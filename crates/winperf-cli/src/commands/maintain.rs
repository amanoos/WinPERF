//! `winperf maintain`: run the retention job once by hand (build the rollups, delete what has
//! outlived its retention) and, on request, compact the database file.
//!
//! The recorder does the same thing by itself every minute; this is for catching up a big
//! database in one go (the first pass after upgrading has two days of raw samples to roll up) and
//! for `--vacuum`, which rewrites the file to give freed space back to the disk.

use std::io::Write;
use std::path::Path;
use winperf_core::config::RetentionConfig;
use winperf_runtime::lock::RecorderLock;
use winperf_storage::{Database, Limits, MaintenanceReport};

pub fn run(
    db_path: &Path,
    retention: &RetentionConfig,
    vacuum: bool,
    now_ms: i64,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    // A vacuum rewrites the whole file and needs it to itself; the ordinary pass is safe beside
    // a recorder (it works in small transactions).
    let _exclusive = if vacuum {
        Some(
            RecorderLock::acquire(db_path)
                .map_err(|e| format!("cannot vacuum while a monitor is recording: {e}"))?,
        )
    } else {
        None
    };
    let mut db = Database::open(db_path)?;
    let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let before = size(db_path);
    let mut passes = 0u32;
    let mut total = MaintenanceReport::default();
    loop {
        let r = db.maintain(now_ms, retention, Limits::unlimited())?;
        passes += 1;
        total.minutes_rolled += r.minutes_rolled;
        total.quarters_rolled += r.quarters_rolled;
        total.raw_deleted += r.raw_deleted;
        total.system_raw_deleted += r.system_raw_deleted;
        total.minute_rollups_deleted += r.minute_rollups_deleted;
        total.quarter_rollups_deleted += r.quarter_rollups_deleted;
        total.anomalies_deleted += r.anomalies_deleted;
        total.instances_deleted += r.instances_deleted;
        if !r.more || passes >= 100 {
            break;
        }
    }
    writeln!(
        out,
        "rolled up {} minutes and {} quarter hours",
        total.minutes_rolled, total.quarters_rolled
    )?;
    writeln!(
        out,
        "deleted {} raw process samples and {} raw system samples (older than {} days, already rolled up)",
        total.raw_deleted, total.system_raw_deleted, retention.raw_samples_days
    )?;
    writeln!(
        out,
        "deleted {} 1-minute rows (older than {} days) and {} 15-minute rows (older than {} days)",
        total.minute_rollups_deleted,
        retention.aggregate_1min_days,
        total.quarter_rollups_deleted,
        retention.aggregate_15min_days
    )?;
    writeln!(
        out,
        "deleted {} resolved anomalies (older than {} days) and {} old process records",
        total.anomalies_deleted, retention.anomaly_days, total.instances_deleted
    )?;
    if vacuum {
        writeln!(out, "compacting the file (this can take a while)...")?;
        db.vacuum()?;
    }
    drop(db);
    let after = size(db_path);
    writeln!(
        out,
        "database file: {:.1} MiB -> {:.1} MiB{}",
        before as f64 / 1_048_576.0,
        after as f64 / 1_048_576.0,
        if vacuum {
            ""
        } else {
            " (freed space is reused by new samples; add --vacuum to shrink the file)"
        }
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_on_an_empty_database_says_so_and_changes_nothing() {
        let dir = std::env::temp_dir().join(format!("winperf-maintain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("m.db");
        let mut out = Vec::new();
        run(
            &path,
            &RetentionConfig::default(),
            false,
            1_700_000_000_000,
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("rolled up 0 minutes"), "{text}");
        assert!(text.contains("deleted 0 raw process samples"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_vacuum_is_refused_while_a_recorder_holds_the_database() {
        let dir =
            std::env::temp_dir().join(format!("winperf-maintain-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("m.db");
        let _recorder = RecorderLock::acquire(&path).unwrap();
        let mut out = Vec::new();
        let err = run(&path, &RetentionConfig::default(), true, 0, &mut out)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot vacuum"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
