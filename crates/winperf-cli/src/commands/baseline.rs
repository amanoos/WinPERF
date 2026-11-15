//! `winperf baseline`: recompute and show baseline profiles, plus the recompute schedule that
//! `monitor run` keeps in the background.

use std::cmp::Ordering as Cmp;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use winperf_core::config::ConfidenceConfig;
use winperf_core::profiler::baseline::{BaselineMetric, Scope};
use winperf_core::profiler::confidence::{Confidence, assess};
use winperf_core::time::unix_millis_now;
use winperf_storage::{Database, ListedBaseline};

/// Recompute the baselines of every window and say what was written.
pub fn update(
    db: &mut Database,
    windows: &[u32],
    now_ms: i64,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    for &hours in windows {
        let r = db.recompute_baselines(now_ms, hours)?;
        writeln!(
            out,
            "{hours} h window: {} subjects, {} rows",
            r.subjects, r.rows
        )?;
    }
    Ok(())
}

/// One subject (executable or application) with its baseline reduced to what a person scans:
/// confidence, CPU, memory and growth. Shared by `baseline list`-style views and the TUI explorer.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectSummary {
    pub scope: Scope,
    pub name: String,
    pub confidence: Confidence,
    /// Observations of the best-measured metric.
    pub observations: u64,
    pub first_ts_ms: i64,
    pub last_ts_ms: i64,
    /// `(mean, p95, peak)` of CPU percent.
    pub cpu: Option<(f64, f64, f64)>,
    /// `(mean, peak)` of working set in bytes.
    pub memory: Option<(f64, f64)>,
    /// Private-memory growth in bytes per hour.
    pub growth_per_hour: Option<f64>,
    pub computed_at_ms: i64,
}

/// Group one window's rows by subject. Confidence comes from the subject's best-measured metric
/// and its span. Busiest first (by mean CPU, unmeasured last), then by name.
pub fn summarize_subjects(rows: &[ListedBaseline], cfg: &ConfidenceConfig) -> Vec<SubjectSummary> {
    let mut by_subject: Vec<SubjectSummary> = Vec::new();
    let mut index: HashMap<(Scope, i64), usize> = HashMap::new();
    for l in rows {
        let s = &l.stored;
        let at = *index.entry((s.scope, s.subject_id)).or_insert_with(|| {
            by_subject.push(SubjectSummary {
                scope: s.scope,
                name: l.name.clone(),
                confidence: Confidence::Insufficient,
                observations: 0,
                first_ts_ms: s.first_ts_ms,
                last_ts_ms: s.last_ts_ms,
                cpu: None,
                memory: None,
                growth_per_hour: None,
                computed_at_ms: s.computed_at_ms,
            });
            by_subject.len() - 1
        });
        let subject = &mut by_subject[at];
        subject.observations = subject.observations.max(s.observations);
        match s.metric {
            BaselineMetric::Cpu => subject.cpu = Some((s.mean, s.p95, s.peak)),
            BaselineMetric::Memory => {
                subject.memory = Some((s.mean, s.peak));
                subject.growth_per_hour = s.growth_per_hour;
            }
            _ => {}
        }
    }
    for s in &mut by_subject {
        s.confidence = assess(s.observations, s.last_ts_ms - s.first_ts_ms, cfg);
    }
    by_subject.sort_by(|a, b| {
        let cpu = |s: &SubjectSummary| s.cpu.map(|c| c.0);
        match (cpu(a), cpu(b)) {
            (Some(x), Some(y)) => y.total_cmp(&x),
            (Some(_), None) => Cmp::Less,
            (None, Some(_)) => Cmp::Greater,
            (None, None) => Cmp::Equal,
        }
        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    by_subject
}

/// Print the stored baselines of one window as a table.
pub fn list(
    db: &Database,
    window_hours: u32,
    cfg: &ConfidenceConfig,
    out: &mut impl Write,
) -> io::Result<()> {
    let rows = db.list_baselines(window_hours).map_err(io::Error::other)?;
    if rows.is_empty() {
        return writeln!(
            out,
            "no baselines for the {window_hours} h window yet (run `winperf baseline update`, \
             or let `monitor run` collect for a while)"
        );
    }
    writeln!(
        out,
        "{:<12} {:<36} {:<12} {:<10} {:>7} {:>12} {:>12} {:>12} {:>12}",
        "SCOPE", "NAME", "CONFIDENCE", "METRIC", "OBS", "MEAN", "MEDIAN", "P95", "PEAK"
    )?;
    for l in &rows {
        writeln!(out, "{}", format_row(l, cfg))?;
    }
    Ok(())
}

fn format_row(l: &ListedBaseline, cfg: &ConfidenceConfig) -> String {
    let s = &l.stored;
    let v = |x: f64| format_value(s.metric, x);
    let confidence = assess(s.observations, s.last_ts_ms - s.first_ts_ms, cfg);
    let mut line = format!(
        "{:<12} {:<36} {:<12} {:<10} {:>7} {:>12} {:>12} {:>12} {:>12}",
        s.scope.as_str(),
        truncate(&l.name, 36),
        confidence.label(),
        s.metric.as_str(),
        s.observations,
        v(s.mean),
        v(s.median),
        v(s.p95),
        v(s.peak),
    );
    if let Some(g) = s.growth_per_hour {
        line.push_str(&format!("  growth {}/h", format_bytes(g)));
    }
    line
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max - 1).collect();
        format!("{head}~")
    }
}

fn format_bytes(bytes: f64) -> String {
    let sign = if bytes < 0.0 { "-" } else { "" };
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes.abs();
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{sign}{value:.1} {}", UNITS[unit])
}

fn format_value(metric: BaselineMetric, v: f64) -> String {
    match metric {
        BaselineMetric::Cpu => format!("{v:.2} %"),
        BaselineMetric::Memory => format_bytes(v),
        _ => format!("{}/s", format_bytes(v)),
    }
}

/// How often the schedule thread checks the stop flag while waiting.
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
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    spawn_schedule_with(db_path, windows, base, PER_WINDOW_HOUR, stop)
}
fn spawn_schedule_with(
    db_path: PathBuf,
    windows: Vec<u32>,
    base: Duration,
    per_hour: Duration,
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
                .and_then(|mut db| update(&mut db, &ready, unix_millis_now(), &mut io::sink()));
            if let Err(e) = result {
                eprintln!("winperf: baseline recompute failed: {e}");
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
    fn update_then_list_shows_the_subject_with_readable_units() {
        let now = 10 * 3_600_000;
        let mut db = Database::open_in_memory().unwrap();
        seed(&mut db, now);
        let mut out = Vec::new();
        update(&mut db, &[1, 24], now, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("1 h window: 1 subjects, 2 rows"), "{text}");
        assert!(text.contains("24 h window: 1 subjects, 2 rows"), "{text}");

        let mut out = Vec::new();
        list(&db, 1, &ConfidenceConfig::default(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("chrome.exe"), "{text}");
        assert!(text.contains("2.50 %"), "{text}");
        assert!(text.contains("200.0 MiB"), "{text}");
        assert!(
            text.contains("Insufficient"),
            "one sample is clearly labelled: {text}"
        );
    }

    #[test]
    fn subjects_are_summarized_busiest_first_with_confidence() {
        let now = 10 * 3_600_000;
        let mut db = Database::open_in_memory().unwrap();
        seed(&mut db, now);
        // A second, idle executable with a long history: 60 samples over an hour.
        db.conn()
            .execute_batch(
                "INSERT INTO executables (path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES ('q', 'Q', 'idle.exe', 'valid', 'third_party', 1, 1, 't'); \
                 INSERT INTO process_instances (pid, start_time, parent_pid, name, executable_id, \
                 first_seen, last_seen) VALUES (2, 2, 0, 'idle.exe', 2, 't', 't');",
            )
            .unwrap();
        for i in 0..60 {
            db.conn()
                .execute(
                    "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, \
                     working_set_bytes) VALUES (2, ?1, 0.1, 1048576)",
                    [now - 3_600_000 + i * 60_000],
                )
                .unwrap();
        }
        db.recompute_baselines(now, 2).unwrap();

        let cfg = ConfidenceConfig::default();
        let rows = db.list_baselines(2).unwrap();
        let subjects = summarize_subjects(&rows, &cfg);
        let names: Vec<&str> = subjects.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["chrome.exe", "idle.exe"], "higher mean CPU first");
        assert_eq!(subjects[0].confidence, Confidence::Insufficient);
        assert_eq!(subjects[1].confidence, Confidence::Preliminary);
        assert_eq!(subjects[1].observations, 60);
        assert_eq!(subjects[0].cpu, Some((2.5, 2.5, 2.5)));
        assert_eq!(subjects[0].memory.map(|m| m.0), Some(209_715_200.0));
    }

    #[test]
    fn an_empty_window_explains_itself() {
        let db = Database::open_in_memory().unwrap();
        let mut out = Vec::new();
        list(&db, 1, &ConfidenceConfig::default(), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("no baselines"));
    }

    #[test]
    fn units_scale_and_long_names_are_cut() {
        assert_eq!(format_bytes(512.0), "512.0 B");
        assert_eq!(format_bytes(1536.0), "1.5 KiB");
        assert_eq!(format_bytes(-2048.0), "-2.0 KiB");
        assert_eq!(truncate("short", 36), "short");
        assert_eq!(truncate(&"x".repeat(40), 10).chars().count(), 10);
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
}
