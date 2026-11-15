//! `winperf monitor run`: foreground sampling that records into the database until Ctrl+C.

use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
use winperf_core::anomaly::{AnomalyEvent, AnomalyKind, Severity, format};
use winperf_core::config::Resource;
use winperf_core::engine::{Engine, MetricsSource, SampleSink, TickStats};
use winperf_core::inventory::ExecutableClassifier;
use winperf_core::time::format_span;
use winperf_storage::{Database, DbSink, DetectSettings, DetectingSink, Notice};

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

/// What a run does besides recording samples.
#[derive(Default)]
pub struct Options {
    /// Verifies the signatures of newly seen executables in the background.
    pub classifier: Option<Box<dyn ExecutableClassifier>>,
    /// Checks every tick for anomalies and stores them.
    pub detect: Option<DetectSettings>,
    /// Ring the terminal bell for serious anomalies (only sensible on a real terminal).
    pub bell: bool,
}

/// Anomaly notices waiting to be printed between tick lines.
struct Announcer {
    rx: Receiver<Notice>,
    bell: bool,
}

fn what(e: &AnomalyEvent) -> &'static str {
    match (e.resource, e.kind) {
        (Resource::Memory, AnomalyKind::MemoryGrowth) => "memory growth",
        (r, _) => r.as_str(),
    }
}

fn describe(e: &AnomalyEvent) -> String {
    format!(
        "{} {} (PID {}): {} vs normal {} for {}",
        what(e),
        e.process_name,
        e.pid,
        format::value(e.resource, e.kind, e.current),
        format::value(e.resource, e.kind, e.baseline),
        format_span(e.duration_ms),
    )
}

/// The line printed when an anomaly is raised, gets worse or ends. Serious ones start with the
/// terminal bell when `bell` is on.
pub fn format_notice(n: &Notice, bell: bool) -> String {
    let ring = |s: Severity| if bell && s >= Severity::High { "" } else { "" };
    match n {
        Notice::Raised { id, event } => format!(
            "{}ANOMALY #{id} [{}] {}",
            ring(event.severity),
            event.severity.label(),
            describe(event)
        ),
        Notice::Worsened { id, event } => format!(
            "{}ANOMALY #{id} worsened to [{}] {}",
            ring(event.severity),
            event.severity.label(),
            describe(event)
        ),
        Notice::Resolved {
            id, process_name, ..
        } => format!("ANOMALY #{id} ({process_name}) resolved"),
    }
}

/// Drive `sink` until `stop` or `max_ticks`, printing a line per tick. Hands the sink back so the
/// caller can report on it.
fn drive<M: MetricsSource, S: SampleSink>(
    metrics: M,
    sink: S,
    announcer: Option<Announcer>,
    interval: Duration,
    max_ticks: Option<u64>,
    stop: &AtomicBool,
    out: &mut impl Write,
) -> Result<(u64, S), Box<dyn std::error::Error>> {
    let mut engine = Engine::new(metrics, sink);
    let mut write_error: Option<io::Error> = None;
    let ticks = engine.run(interval, max_ticks, stop, |n, stats| {
        if write_error.is_none()
            && let Err(e) = writeln!(out, "{}", format_tick(n, stats))
        {
            write_error = Some(e);
        }
        if let Some(a) = &announcer {
            for notice in a.rx.try_iter() {
                if write_error.is_none()
                    && let Err(e) = writeln!(out, "{}", format_notice(&notice, a.bell))
                {
                    write_error = Some(e);
                }
            }
        }
    })?;
    match write_error {
        Some(e) => Err(e.into()),
        None => Ok((ticks, engine.into_parts().1)),
    }
}

/// Run the engine against an already-open database. Returns the number of ticks run. With
/// `detect` set, every tick is also checked for anomalies, which are stored as they are found.
pub fn run_with<M: MetricsSource>(
    metrics: M,
    db: Database,
    options: Options,
    interval: Duration,
    max_ticks: Option<u64>,
    stop: &AtomicBool,
    out: &mut impl Write,
) -> Result<u64, Box<dyn std::error::Error>> {
    // Several ticks per transaction (about 6 at the default 5 s): far less disk writing, and at
    // most that much sampling time is lost if the process is killed. A normal stop flushes.
    let mut sink = DbSink::new(db).with_flush_span(winperf_storage::sink::DEFAULT_FLUSH_SPAN);
    if let Some(c) = options.classifier {
        sink = sink.with_classifier(c);
    }
    let Some(settings) = options.detect else {
        return drive(metrics, sink, None, interval, max_ticks, stop, out).map(|(ticks, _)| ticks);
    };
    let (tx, rx) = mpsc::channel();
    let announcer = Announcer {
        rx,
        bell: options.bell,
    };
    let (ticks, sink) = drive(
        metrics,
        DetectingSink::new(sink, settings).with_notices(tx),
        Some(announcer),
        interval,
        max_ticks,
        stop,
        out,
    )?;
    if sink.raised() > 0 {
        writeln!(out, "{} anomaly event(s) raised", sink.raised())?;
    }
    if let Some(problem) = sink.last_error() {
        writeln!(out, "anomaly detection had a problem: {problem}")?;
    }
    Ok(ticks)
}

/// Open (creating/migrating) the database at `db_path` and run until `stop` or `max_ticks`.
pub fn run<M: MetricsSource>(
    metrics: M,
    db_path: &Path,
    options: Options,
    interval: Duration,
    max_ticks: Option<u64>,
    stop: &AtomicBool,
    out: &mut impl Write,
) -> Result<u64, Box<dyn std::error::Error>> {
    let db = Database::open(db_path)?;
    writeln!(
        out,
        "monitoring every {}s, writing to {} (Ctrl+C to stop){}{}",
        interval.as_secs(),
        db_path.display(),
        if options.classifier.is_some() {
            ""
        } else {
            "; signature checks off"
        },
        if options.detect.is_some() {
            "; anomaly detection on"
        } else {
            ""
        }
    )?;
    let ticks = run_with(metrics, db, options, interval, max_ticks, stop, out)?;
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
        // A folder left by an earlier run with the same process id would add its samples.
        let _ = std::fs::remove_dir_all(&dir);
        let db_path = dir.join("m.db");
        let script = Script(vec![vec![obs(1), obs(2)], vec![obs(1), obs(2)]].into());
        let stop = AtomicBool::new(false);
        let mut out = Vec::new();

        let ticks = run(
            script,
            &db_path,
            Options::default(),
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
        drop(db); // an open file cannot be deleted on Windows
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn event(severity: winperf_core::anomaly::Severity) -> AnomalyEvent {
        AnomalyEvent {
            detected_ts_ms: 1,
            pid: 7,
            start_time: 1,
            process_name: "busy.exe".into(),
            exe_path: r"C:\apps\busy.exe".into(),
            resource: Resource::Cpu,
            kind: AnomalyKind::Deviation,
            current: 72.0,
            baseline: 8.0,
            deviation_pct: 800.0,
            duration_ms: 125_000,
            severity,
            system: Default::default(),
            impact: Default::default(),
            baseline_window_hours: 24,
            baseline_confidence: winperf_core::profiler::confidence::Confidence::Established,
            explanation: String::new(),
        }
    }

    #[test]
    fn notices_read_as_one_line_and_only_serious_ones_ring_the_bell() {
        use winperf_core::anomaly::Severity;
        let raised = |s| Notice::Raised {
            id: 12,
            event: event(s),
        };
        assert_eq!(
            format_notice(&raised(Severity::Warning), true),
            "ANOMALY #12 [Warning] cpu busy.exe (PID 7): 72.0% vs normal 8.0% for 2m 05s"
        );
        assert!(format_notice(&raised(Severity::High), true).starts_with('\x07'));
        assert!(format_notice(&raised(Severity::Critical), true).starts_with('\x07'));
        assert!(
            !format_notice(&raised(Severity::High), false).contains('\x07'),
            "bell off"
        );
        assert!(!format_notice(&raised(Severity::Informational), true).contains('\x07'));

        let worse = Notice::Worsened {
            id: 12,
            event: event(Severity::Critical),
        };
        assert!(format_notice(&worse, false).starts_with("ANOMALY #12 worsened to [Critical] cpu"));
        let done = Notice::Resolved {
            id: 12,
            process_name: "busy.exe".into(),
            ts_ms: 5,
        };
        assert_eq!(
            format_notice(&done, true),
            "ANOMALY #12 (busy.exe) resolved"
        );
    }

    #[test]
    fn a_leak_notice_says_memory_growth_with_a_rate() {
        use winperf_core::anomaly::Severity;
        let mut e = event(Severity::Warning);
        e.resource = Resource::Memory;
        e.kind = AnomalyKind::MemoryGrowth;
        e.current = 180.0 * 1024.0 * 1024.0;
        e.baseline = 0.0;
        let line = format_notice(&Notice::Raised { id: 3, event: e }, false);
        assert!(
            line.contains("memory growth busy.exe") && line.contains("180.0 MiB/h"),
            "{line}"
        );
    }
}
