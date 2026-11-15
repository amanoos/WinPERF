//! `winperf profile start|stop|status`: the baseline collection mode (PRD FR-010).
//!
//! The monitor always records samples; profiling mode is the marker for "baselines are still being
//! learned", which anomaly detection will honour. `status` also says whether a monitor seems to be
//! running and how trustworthy the baselines are so far.

use crate::commands::baseline::summarize_subjects;
use std::io::Write;
use winperf_core::config::ConfidenceConfig;
use winperf_core::profiler::confidence::Confidence;
use winperf_core::time::{format_span, unix_millis_to_utc_string};
use winperf_storage::Database;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

/// A sample newer than this counts as "a monitor is running" (a few missed ticks are fine).
const RUNNING_WITHIN_MS: i64 = 60_000;

fn at(ms: i64) -> String {
    unix_millis_to_utc_string(ms).map_or_else(|| "unknown time".into(), |s| format!("{s} UTC"))
}

pub fn start(db: &Database, now_ms: i64, out: &mut impl Write) -> Result {
    if db.start_profiling(now_ms)? {
        writeln!(out, "profiling started at {}", at(now_ms))?;
    } else if let Some(since) = db.profile_state()?.started_ms {
        writeln!(
            out,
            "profiling is already active (since {}, {} ago)",
            at(since),
            format_span(now_ms - since)
        )?;
    }
    writeln!(
        out,
        "Samples are only collected while `winperf monitor run` (or the service) is running."
    )?;
    Ok(())
}

pub fn stop(db: &Database, now_ms: i64, out: &mut impl Write) -> Result {
    if db.stop_profiling(now_ms)? {
        writeln!(out, "profiling stopped at {}", at(now_ms))?;
    } else {
        writeln!(out, "profiling was not active")?;
    }
    Ok(())
}

pub fn status(
    db: &Database,
    window_hours: u32,
    cfg: &ConfidenceConfig,
    now_ms: i64,
    out: &mut impl Write,
) -> Result {
    let state = db.profile_state()?;
    match (state.active, state.started_ms, state.stopped_ms) {
        (true, Some(since), _) => writeln!(
            out,
            "profiling: ACTIVE since {} ({} ago)",
            at(since),
            format_span(now_ms - since)
        )?,
        (false, Some(since), Some(until)) => writeln!(
            out,
            "profiling: stopped (last phase {} to {}, {})",
            at(since),
            at(until),
            format_span(until - since)
        )?,
        _ => writeln!(out, "profiling: never started (`winperf profile start`)")?,
    }

    match db.latest_sample_ms()? {
        Some(ts) if now_ms - ts <= RUNNING_WITHIN_MS => writeln!(
            out,
            "monitor: running (last sample {} ago)",
            format_span(now_ms - ts)
        )?,
        Some(ts) => writeln!(
            out,
            "monitor: not running (last sample {} ago)",
            format_span(now_ms - ts)
        )?,
        None => writeln!(out, "monitor: no samples recorded yet")?,
    }

    let subjects = summarize_subjects(&db.list_baselines(window_hours)?, cfg);
    if subjects.is_empty() {
        writeln!(
            out,
            "baselines ({window_hours} h window): none yet (run `winperf baseline update` after collecting for a while)"
        )?;
        return Ok(());
    }
    let count = |level: Confidence| subjects.iter().filter(|s| s.confidence == level).count();
    writeln!(
        out,
        "baselines ({window_hours} h window): {} subjects - {} High, {} Established, {} Preliminary, {} Insufficient data",
        subjects.len(),
        count(Confidence::High),
        count(Confidence::Established),
        count(Confidence::Preliminary),
        count(Confidence::Insufficient),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_709_214_307_000; // 2024-02-29 13:45:07 UTC

    fn text(f: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut out = Vec::new();
        f(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn start_then_status_then_stop() {
        let db = Database::open_in_memory().unwrap();
        let cfg = ConfidenceConfig::default();

        let never = text(|o| status(&db, 24, &cfg, NOW, o).unwrap());
        assert!(never.contains("never started"), "{never}");
        assert!(never.contains("no samples recorded yet"), "{never}");
        assert!(never.contains("none yet"), "{never}");

        let started = text(|o| start(&db, NOW, o).unwrap());
        assert!(
            started.contains("profiling started at 2024-02-29 13:45:07 UTC"),
            "{started}"
        );

        let again = text(|o| start(&db, NOW + 5000, o).unwrap());
        assert!(
            again.contains("already active (since 2024-02-29 13:45:07 UTC, 5s ago)"),
            "{again}"
        );

        let active = text(|o| status(&db, 24, &cfg, NOW + 90_000, o).unwrap());
        assert!(
            active.contains("ACTIVE since 2024-02-29 13:45:07 UTC (1m 30s ago)"),
            "{active}"
        );

        let stopped = text(|o| stop(&db, NOW + 120_000, o).unwrap());
        assert!(stopped.contains("profiling stopped"), "{stopped}");
        let after = text(|o| status(&db, 24, &cfg, NOW + 130_000, o).unwrap());
        assert!(after.contains("stopped (last phase"), "{after}");
        assert!(after.contains("2m 00s"), "{after}");

        let twice = text(|o| stop(&db, NOW + 140_000, o).unwrap());
        assert!(twice.contains("was not active"), "{twice}");
    }

    #[test]
    fn status_reports_whether_a_monitor_is_writing_and_how_trusted_the_baselines_are() {
        let mut db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO executables (path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES ('p', 'P', 'a.exe', 'valid', 'third_party', 1, 1, 't'); \
                 INSERT INTO process_instances (pid, start_time, parent_pid, name, executable_id, \
                 first_seen, last_seen) VALUES (1, 1, 0, 'a.exe', 1, 't', 't');",
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent) \
                 VALUES (1, ?1, 1.0)",
                [NOW - 3000],
            )
            .unwrap();
        db.recompute_baselines(NOW, 24).unwrap();
        let cfg = ConfidenceConfig::default();

        let live = text(|o| status(&db, 24, &cfg, NOW, o).unwrap());
        assert!(
            live.contains("monitor: running (last sample 3s ago)"),
            "{live}"
        );
        assert!(
            live.contains("1 subjects - 0 High, 0 Established, 0 Preliminary, 1 Insufficient data"),
            "{live}"
        );

        let idle = text(|o| status(&db, 24, &cfg, NOW + 600_000, o).unwrap());
        assert!(
            idle.contains("not running (last sample 10m 03s ago)"),
            "{idle}"
        );
    }
}
