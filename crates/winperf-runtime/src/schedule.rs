//! The baseline recompute schedule that runs beside sampling.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use winperf_core::config::RetentionConfig;
use winperf_core::time::unix_millis_now;
use winperf_storage::{Database, Limits};

/// How often the schedule thread looks at the clock and the stop flag.
const POLL: Duration = Duration::from_millis(200);

/// How long to wait before recomputing a window again. Reading a window costs time in proportion
/// to the samples in it (about 0.8 s per hour of samples, measured), so a longer window is
/// refreshed less often: never faster than `base`, and not faster than 2.5 minutes per hour of
/// window (24 h: hourly, 7 d: every 7 hours). A day-old baseline barely moves in a few minutes.
fn refresh_interval(window_hours: u32, base: Duration, per_hour: Duration) -> Duration {
    base.max(per_hour * window_hours)
}

/// Refresh delay added per hour of window (2.5 minutes).
const PER_WINDOW_HOUR: Duration = Duration::from_secs(150);

/// Recompute each window on its own cadence ([`refresh_interval`]) until `stop` is set. Runs on
/// its own thread with its own connection, so it never delays a sampling tick (WAL: readers don't
/// block the writer). Nothing is computed at start-up, when the monitor is busiest: the first
/// recompute of a window comes one interval after the start.
pub fn spawn_schedule(
    db_path: PathBuf,
    windows: Vec<u32>,
    base: Duration,
    raw_days: u32,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    spawn_schedule_with(db_path, windows, base, PER_WINDOW_HOUR, raw_days, stop)
}
fn spawn_schedule_with(
    db_path: PathBuf,
    windows: Vec<u32>,
    base: Duration,
    per_hour: Duration,
    raw_days: u32,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let start = Instant::now();
        let every = |w| refresh_interval(w, base, per_hour);
        let mut due: Vec<(u32, Instant)> = windows.iter().map(|&w| (w, start + every(w))).collect();
        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            let ready: Vec<u32> = due.iter().filter(|d| d.1 <= now).map(|d| d.0).collect();
            if ready.is_empty() {
                thread::sleep(POLL);
                continue;
            }
            for d in due.iter_mut().filter(|d| ready.contains(&d.0)) {
                d.1 = Instant::now() + every(d.0);
            }
            let result = Database::open(&db_path)
                .map_err(Box::<dyn std::error::Error>::from)
                .and_then(|mut db| recompute(&mut db, &ready, raw_days));
            if let Err(e) = result {
                eprintln!("winperf: baseline recompute failed: {e}");
            }
        }
    })
}

/// Recompute the baselines of the given windows. A window longer than the raw samples are kept
/// is computed from the 1-minute rollups, which cover it; shorter ones from the raw ticks.
fn recompute(
    db: &mut Database,
    windows: &[u32],
    raw_days: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = unix_millis_now();
    for &hours in windows {
        let rollup = (hours > raw_days.saturating_mul(24)).then_some(60_000);
        db.recompute_baselines_from(now, hours, rollup)?;
    }
    Ok(())
}

/// How long the maintenance thread waits between passes, and when a pass left work undone.
const MAINTENANCE_EVERY: Duration = Duration::from_secs(60);
const MAINTENANCE_CATCH_UP: Duration = Duration::from_secs(5);
/// Nothing is done in the first moments of a run, when the monitor is busiest.
const MAINTENANCE_FIRST: Duration = Duration::from_secs(60);

/// Build the rollups and delete what has outlived its retention, beside the recorder, on its own
/// connection and in small transactions (see `Database::maintain`). A pass that stopped at its
/// work limit is followed by another after a few seconds, so a big backlog is worked off in
/// pieces; otherwise it runs once a minute. Failures are reported and retried; they never stop
/// the recorder.
pub fn spawn_maintenance(
    db_path: PathBuf,
    retention: RetentionConfig,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut next = Instant::now() + MAINTENANCE_FIRST;
        while !stop.load(Ordering::Relaxed) {
            if Instant::now() < next {
                thread::sleep(POLL);
                continue;
            }
            next = Instant::now() + MAINTENANCE_EVERY;
            let result = Database::open(&db_path)
                .and_then(|mut db| db.maintain(unix_millis_now(), &retention, Limits::default()));
            match result {
                Ok(report) => {
                    if report.did_anything() {
                        eprintln!(
                            "maintenance: {} min and {} quarter hours rolled up; deleted {} raw,                              {} + {} rollup rows, {} anomalies, {} process records",
                            report.minutes_rolled,
                            report.quarters_rolled,
                            report.raw_deleted + report.system_raw_deleted,
                            report.minute_rollups_deleted,
                            report.quarter_rollups_deleted,
                            report.anomalies_deleted,
                            report.instances_deleted
                        );
                    }
                    if report.more {
                        next = Instant::now() + MAINTENANCE_CATCH_UP;
                    }
                }
                Err(e) => eprintln!("winperf: maintenance failed (will retry): {e}"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One executable with one running instance and one CPU/memory sample 1 s before `now_ms`.
    fn seed(db: &mut Database, now_ms: i64) {
        db.conn()
            .execute_batch(
                "INSERT INTO executables (path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES ('p', 'P', 'chrome.exe', 'valid', 'third_party', 1, 1, 't'); \
                 INSERT INTO process_instances (pid, start_time, parent_pid, name, executable_id, \
                 first_seen, last_seen) VALUES (1, 1, 0, 'chrome.exe', 1, 't', 't');",
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, \
                 working_set_bytes) VALUES (1, ?1, 2.5, 209715200)",
                [now_ms - 1000],
            )
            .unwrap();
    }

    #[test]
    fn longer_windows_are_refreshed_less_often() {
        let base = Duration::from_secs(15 * 60);
        let mins = |h| refresh_interval(h, base, PER_WINDOW_HOUR).as_secs() / 60;
        assert_eq!((mins(1), mins(24), mins(168)), (15, 60, 420));
        assert_eq!(
            refresh_interval(1, Duration::from_millis(50), PER_WINDOW_HOUR),
            Duration::from_secs(150)
        );
    }

    #[test]
    fn the_schedule_recomputes_on_its_own_and_stops_on_request() {
        let dir = std::env::temp_dir().join(format!("winperf-cli-baseline-{}", std::process::id()));
        let path = dir.join("b.db");
        {
            let mut db = Database::open(&path).unwrap();
            seed(&mut db, unix_millis_now());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_schedule_with(
            path.clone(),
            vec![1],
            Duration::from_millis(50),
            Duration::ZERO,
            2,
            stop.clone(),
        );

        let reader = Database::open_read_only(&path).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while reader.baseline_count().unwrap() == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        assert!(reader.baseline_count().unwrap() > 0);
        drop(reader);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_maintenance_thread_waits_out_the_start_up_and_stops_on_request() {
        let dir = std::env::temp_dir().join(format!("winperf-cli-maint-{}", std::process::id()));
        let path = dir.join("m.db");
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_maintenance(path, RetentionConfig::default(), stop.clone());
        thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2), "stops promptly");
        // Nothing ran in that time (the first pass comes a minute in), so no file was created.
        assert!(!dir.join("m.db").exists());
    }
}
