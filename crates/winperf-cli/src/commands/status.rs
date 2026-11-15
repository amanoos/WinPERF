//! `winperf monitor status`: is something recording, how fresh is the data, and how continuous has
//! it been. Read-only, so it is safe to run while the service is writing.

use crate::commands::anomalies::at;
use std::io::Write;
use std::path::Path;
use winperf_core::time::format_span;
use winperf_storage::Database;

const DAY_MS: i64 = 24 * 3600 * 1000;

/// Size of the database file plus its write-ahead log, which holds the newest data.
fn database_size(path: &Path) -> u64 {
    let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    size(path) + size(Path::new(&wal))
}

fn megabytes(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// Print the status. `interval_secs` is the configured sampling interval (what "fresh" and
/// "gap" are measured against); `service` is a phrase from the service manager.
pub fn show(
    db: &Database,
    db_path: &Path,
    interval_secs: u64,
    service: &str,
    now_ms: i64,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let interval_ms = interval_secs as i64 * 1000;
    writeln!(out, "Service      {service}")?;
    writeln!(
        out,
        "Database     {} ({})",
        db_path.display(),
        megabytes(database_size(db_path))
    )?;

    // The newest system sample (one is written every tick, so it is the heartbeat).
    let latest: Option<i64> =
        db.conn()
            .query_row("SELECT MAX(ts_ms) FROM system_samples", [], |r| r.get(0))?;
    match latest {
        None => writeln!(out, "Last sample  none yet: nothing has recorded here")?,
        Some(last) => {
            let age = now_ms - last;
            // Three missed intervals in a row is more than a busy moment.
            let verdict = if age <= 3 * interval_ms {
                "recording"
            } else {
                "NOT recording"
            };
            writeln!(
                out,
                "Last sample  {} UTC, {} ago: {verdict}",
                at(last),
                format_span(age)
            )?;
        }
    }

    // Continuity over the last day: a gap is anything over three intervals.
    let since = now_ms - DAY_MS;
    let health = db.sample_health(since, 3 * interval_ms)?;
    if health.samples > 0 {
        // Coverage is judged between the first and last sample, so a new database is not
        // "missing" a day and a stopped monitor shows up in "Last sample", not here.
        let first = health.first_ts_ms.unwrap_or(0);
        let last = health.last_ts_ms.unwrap_or(0);
        let expected = (((last - first) as f64 / interval_ms as f64).round() as i64 + 1).max(1);
        let pct = (health.samples as f64 / expected as f64 * 100.0).min(100.0);
        write!(
            out,
            "Last 24 h    {} samples of about {expected} expected ({pct:.0}%)",
            health.samples
        )?;
        if health.gaps == 0 {
            writeln!(out, ", no gaps")?;
        } else {
            writeln!(
                out,
                ", {} gap{} over {} s, longest {}",
                health.gaps,
                if health.gaps == 1 { "" } else { "s" },
                3 * interval_secs,
                format_span(health.longest_gap_ms)
            )?;
        }
    } else {
        writeln!(out, "Last 24 h    no samples")?;
    }

    writeln!(out, "Anomalies    {} active", db.active_anomaly_count()?)?;
    let profile = db.profile_state()?;
    if profile.active {
        writeln!(
            out,
            "Profiling    on since {} UTC (detection is paused; a running monitor notices within 5 minutes)",
            profile.started_ms.map_or("?".into(), at)
        )?;
    } else {
        writeln!(out, "Profiling    off")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded(samples: &[i64]) -> Database {
        let db = Database::open_in_memory().unwrap();
        for ts in samples {
            db.conn()
                .execute("INSERT INTO system_samples (ts_ms) VALUES (?1)", [ts])
                .unwrap();
        }
        db
    }

    fn render(db: &Database, now: i64) -> String {
        let mut out = Vec::new();
        show(
            db,
            Path::new("no-such.db"),
            5,
            "service running",
            now,
            &mut out,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn fresh_samples_mean_recording() {
        let now = 1_000_000_000;
        let samples: Vec<i64> = (0..=60).map(|i| now - 300_000 + i * 5_000).collect();
        let text = render(&seeded(&samples), now);
        assert!(text.contains("Service      service running"), "{text}");
        assert!(text.contains(": recording"), "{text}");
        assert!(text.contains("no gaps"), "{text}");
        assert!(text.contains("Anomalies    0 active"), "{text}");
        assert!(text.contains("Profiling    off"), "{text}");
    }

    #[test]
    fn old_samples_mean_not_recording_and_gaps_are_reported() {
        let now = 1_000_000_000;
        // Samples, a 10 minute hole, samples, then nothing for 2 minutes.
        let mut samples: Vec<i64> = (0..10).map(|i| now - 1_000_000 + i * 5_000).collect();
        samples.extend((0..10).map(|i| now - 400_000 + i * 5_000));
        let text = render(&seeded(&samples), now);
        assert!(text.contains("NOT recording"), "{text}");
        assert!(text.contains("1 gap over 15 s"), "{text}");
    }

    #[test]
    fn an_empty_database_says_nothing_has_recorded() {
        let text = render(&seeded(&[]), 1_000_000_000);
        assert!(text.contains("nothing has recorded"), "{text}");
        assert!(text.contains("no samples"), "{text}");
    }
}
