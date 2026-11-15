//! `winperf baseline`: recompute and show baseline profiles, plus the recompute schedule that
//! `monitor run` keeps in the background.

use std::cmp::Ordering as Cmp;
use std::collections::HashMap;
use std::io::{self, Write};
use winperf_core::config::ConfidenceConfig;
use winperf_core::profiler::baseline::{BaselineMetric, Scope};
use winperf_core::profiler::confidence::{Confidence, assess};
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
}
