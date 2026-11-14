//! `winperf monitor run`: foreground sampling that records into the database until Ctrl+C.

use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use winperf_core::engine::{Engine, MetricsSource, TickStats};
use winperf_core::inventory::ExecutableClassifier;
use winperf_storage::{Database, DbSink};

/// One progress line per tick.
pub fn format_tick(n: u64, s: &TickStats) -> String {
    format!(
        "tick {n}: {} sampled, {} new, {} gone, {} unreadable ({} ms)",
        s.sampled,
        s.new,
        s.gone,
        s.unreadable,
        s.took.as_millis()
    )
}

/// Run the engine against an already-open database. Returns the number of ticks run.
pub fn run_with<M: MetricsSource>(
    metrics: M,
    db: Database,
    classifier: Option<Box<dyn ExecutableClassifier>>,
    interval: Duration,
    max_ticks: Option<u64>,
    stop: &AtomicBool,
    out: &mut impl Write,
) -> Result<u64, Box<dyn std::error::Error>> {
    // Several ticks per transaction (about 6 at the default 5 s): far less disk writing, and at
    // most that much sampling time is lost if the process is killed. A normal stop flushes.
    let mut sink = DbSink::new(db).with_flush_span(winperf_storage::sink::DEFAULT_FLUSH_SPAN);
    if let Some(c) = classifier {
        sink = sink.with_classifier(c);
    }
    let mut engine = Engine::new(metrics, sink);
    let mut write_error: Option<io::Error> = None;
    let ticks = engine.run(interval, max_ticks, stop, |n, stats| {
        if write_error.is_none()
            && let Err(e) = writeln!(out, "{}", format_tick(n, stats))
        {
            write_error = Some(e);
        }
    })?;
    match write_error {
        Some(e) => Err(e.into()),
        None => Ok(ticks),
    }
}

/// Open (creating/migrating) the database at `db_path` and run until `stop` or `max_ticks`.
pub fn run<M: MetricsSource>(
    metrics: M,
    db_path: &Path,
    classifier: Option<Box<dyn ExecutableClassifier>>,
    interval: Duration,
    max_ticks: Option<u64>,
    stop: &AtomicBool,
    out: &mut impl Write,
) -> Result<u64, Box<dyn std::error::Error>> {
    let db = Database::open(db_path)?;
    writeln!(
        out,
        "monitoring every {}s, writing to {} (Ctrl+C to stop){}",
        interval.as_secs(),
        db_path.display(),
        if classifier.is_some() {
            ""
        } else {
            "; signature checks off"
        }
    )?;
    let ticks = run_with(metrics, db, classifier, interval, max_ticks, stop, out)?;
    writeln!(out, "stopped after {ticks} ticks")?;
    Ok(ticks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use winperf_core::inventory::RawProcess;
    use winperf_core::sampling::Observation;

    struct Script(VecDeque<Vec<Observation>>);
    impl MetricsSource for Script {
        fn logical_cpus(&self) -> u32 {
            2
        }
        fn observe(&mut self) -> Vec<Observation> {
            self.0.pop_front().unwrap_or_default()
        }
        fn describe(&mut self, o: &Observation) -> RawProcess {
            RawProcess {
                pid: o.pid,
                name: o.name.clone(),
                start_time: o.start_time,
                ..Default::default()
            }
        }
    }

    fn obs(pid: u32) -> Observation {
        Observation {
            pid,
            name: format!("p{pid}.exe"),
            start_time: Some(1000),
            cpu_time_100ns: Some(0),
            working_set: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn tick_line_reports_the_counts() {
        let s = TickStats {
            sampled: 10,
            unreadable: 3,
            new: 2,
            gone: 1,
            took: Duration::from_millis(42),
        };
        assert_eq!(
            format_tick(7, &s),
            "tick 7: 10 sampled, 2 new, 1 gone, 3 unreadable (42 ms)"
        );
    }

    #[test]
    fn run_records_samples_and_stops_after_the_requested_ticks() {
        let dir = std::env::temp_dir().join(format!("winperf-cli-monitor-{}", std::process::id()));
        let db_path = dir.join("m.db");
        let script = Script(vec![vec![obs(1), obs(2)], vec![obs(1), obs(2)]].into());
        let stop = AtomicBool::new(false);
        let mut out = Vec::new();

        let ticks = run(
            script,
            &db_path,
            None,
            Duration::from_millis(10),
            Some(2),
            &stop,
            &mut out,
        )
        .unwrap();
        assert_eq!(ticks, 2);

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("monitoring every 0s"), "{text}");
        assert!(text.contains("tick 1: 2 sampled, 2 new"), "{text}");
        assert!(text.contains("tick 2: 2 sampled, 0 new"), "{text}");
        assert!(text.contains("stopped after 2 ticks"));

        let db = Database::open(&db_path).unwrap();
        assert_eq!(db.sample_count().unwrap(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
