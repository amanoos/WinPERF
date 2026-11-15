//! `winperf report`: a plain-text summary of the anomalies of the last N hours (PRD FR-027,
//! Phase 4): how many, how serious, and which processes are behind them.
//!
//! The summary is built from the stored events by a pure function ([`build`]) so it can be checked
//! without a database, and drawn by [`render`].

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::Write;
use winperf_core::anomaly::{AnomalyKind, Severity};
use winperf_core::config::Resource;
use winperf_core::time::{format_span, unix_millis_to_utc_string};
use winperf_storage::{AnomalyFilter, Database, StoredAnomaly};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

const MS_PER_HOUR: i64 = 3_600_000;
/// Events read for one report; a day of anomalies is far below this.
const READ_LIMIT: u32 = 10_000;
/// How many individual events the "most serious" section lists.
const SERIOUS_EVENTS: usize = 5;

/// One executable's anomalies in the period.
#[derive(Debug, Clone, PartialEq)]
pub struct Offender {
    pub name: String,
    pub exe_path: String,
    pub events: usize,
    pub worst: Severity,
    /// The resources involved, each once, in a stable order.
    pub resources: Vec<String>,
    /// Time spent in anomalies, summed over its events (overlapping events add up).
    pub total_duration_ms: i64,
    pub peak_impact: Option<f64>,
    /// Whether any of its anomalies is still going on.
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub hours: u32,
    pub from_ms: i64,
    pub to_ms: i64,
    pub total: usize,
    pub active: usize,
    /// Event counts per severity, in [`Severity::ALL`] order.
    pub by_severity: [usize; 4],
    pub offenders: Vec<Offender>,
    /// The most serious individual events, worst first.
    pub serious: Vec<StoredAnomaly>,
}

fn label(e: &StoredAnomaly) -> String {
    match (e.resource, e.kind) {
        (Resource::Memory, AnomalyKind::MemoryGrowth) => "memory growth".to_string(),
        (r, _) => r.as_str().to_string(),
    }
}

/// Rank by how bad it got, then how much it weighed on the system, then how long it lasted.
fn worse_first(a: &Offender, b: &Offender) -> std::cmp::Ordering {
    let score = |o: &Offender| o.peak_impact.unwrap_or(-1.0);
    b.worst
        .cmp(&a.worst)
        .then(score(b).total_cmp(&score(a)))
        .then(b.total_duration_ms.cmp(&a.total_duration_ms))
        .then(b.events.cmp(&a.events))
        .then(a.name.cmp(&b.name))
}

/// Summarize `events` (the anomalies active at some point in the last `hours` hours). `top`
/// limits the offenders listed.
pub fn build(events: &[StoredAnomaly], hours: u32, top: usize, now_ms: i64) -> Report {
    let mut by_severity = [0usize; 4];
    let mut groups: HashMap<String, (Offender, BTreeSet<String>)> = HashMap::new();
    for e in events {
        if let Some(i) = Severity::ALL.iter().position(|s| *s == e.severity) {
            by_severity[i] += 1;
        }
        let (o, resources) = groups.entry(e.exe_path.to_lowercase()).or_insert_with(|| {
            (
                Offender {
                    name: e.process_name.clone(),
                    exe_path: e.exe_path.clone(),
                    events: 0,
                    worst: e.severity,
                    resources: Vec::new(),
                    total_duration_ms: 0,
                    peak_impact: None,
                    active: false,
                },
                BTreeSet::new(),
            )
        });
        o.events += 1;
        o.worst = o.worst.max(e.severity);
        o.total_duration_ms += e.duration_ms;
        o.peak_impact = match (o.peak_impact, e.impact_score) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        o.active |= e.is_active();
        resources.insert(label(e));
    }
    let mut offenders: Vec<Offender> = groups
        .into_values()
        .map(|(mut o, resources)| {
            o.resources = resources.into_iter().collect();
            o
        })
        .collect();
    offenders.sort_by(worse_first);
    offenders.truncate(top);

    let mut serious: Vec<StoredAnomaly> = events.to_vec();
    serious.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(
                b.impact_score
                    .unwrap_or(-1.0)
                    .total_cmp(&a.impact_score.unwrap_or(-1.0)),
            )
            .then(b.detected_ts_ms.cmp(&a.detected_ts_ms))
    });
    serious.truncate(SERIOUS_EVENTS);

    Report {
        hours,
        from_ms: now_ms - i64::from(hours) * MS_PER_HOUR,
        to_ms: now_ms,
        total: events.len(),
        active: events.iter().filter(|e| e.is_active()).count(),
        by_severity,
        offenders,
        serious,
    }
}

fn minutes(ms: i64) -> String {
    // "2026-11-15 05:12:24" -> "2026-11-15 05:12"
    unix_millis_to_utc_string(ms)
        .and_then(|s| s.get(..16).map(str::to_string))
        .unwrap_or_else(|| "unknown time".into())
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let cut: String = s.chars().take(max - 1).collect();
        format!("{cut}~")
    } else {
        s.to_string()
    }
}

pub fn render(r: &Report, out: &mut impl Write) -> Result {
    writeln!(
        out,
        "WinPerf anomaly report: last {} h ({} to {} UTC)",
        r.hours,
        minutes(r.from_ms),
        minutes(r.to_ms)
    )?;
    writeln!(out)?;
    if r.total == 0 {
        writeln!(out, "No anomalies were recorded in this period.")?;
        writeln!(
            out,
            "(Detection needs learned baselines and a running monitor: see `winperf profile status`.)"
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "ANOMALIES  {} in total, {} still active",
        r.total, r.active
    )?;
    let counts: Vec<String> = Severity::ALL
        .iter()
        .enumerate()
        .rev()
        .map(|(i, s)| format!("{} {}", s.label(), r.by_severity[i]))
        .collect();
    writeln!(out, "  {}", counts.join("   "))?;
    writeln!(out)?;

    writeln!(out, "TOP OFFENDERS")?;
    writeln!(
        out,
        "  {:<3} {:<26} {:>6} {:<13} {:<24} {:>9}  STATE",
        "#", "PROCESS", "EVENTS", "WORST", "RESOURCES", "TIME"
    )?;
    for (i, o) in r.offenders.iter().enumerate() {
        writeln!(
            out,
            "  {:<3} {:<26} {:>6} {:<13} {:<24} {:>9}  {}",
            i + 1,
            clip(&o.name, 26),
            o.events,
            o.worst.label(),
            clip(&o.resources.join(", "), 24),
            format_span(o.total_duration_ms),
            if o.active { "active" } else { "resolved" },
        )?;
    }
    writeln!(out)?;

    writeln!(out, "MOST SERIOUS EVENTS")?;
    for e in &r.serious {
        writeln!(
            out,
            "  #{} [{}] {} {} {} (PID {}), lasted {}{}",
            e.id,
            e.severity.label(),
            minutes(e.detected_ts_ms),
            label(e),
            e.process_name,
            e.pid,
            format_span(e.duration_ms),
            if e.is_active() { ", still active" } else { "" },
        )?;
        writeln!(out, "      {}", e.explanation)?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "`winperf anomalies show <id>` has the full detail of any event."
    )?;
    Ok(())
}

/// Read the last `hours` hours of anomalies and print the report.
pub fn run(db: &Database, hours: u32, top: usize, now_ms: i64, out: &mut impl Write) -> Result {
    let filter = AnomalyFilter {
        since_ms: Some(now_ms - i64::from(hours) * MS_PER_HOUR),
        active_only: false,
    };
    let events = db.list_anomalies(&filter, READ_LIMIT)?;
    render(&build(&events, hours, top, now_ms), out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    struct Spec<'a> {
        id: i64,
        name: &'a str,
        resource: Resource,
        kind: AnomalyKind,
        severity: Severity,
        duration_ms: i64,
        score: Option<f64>,
        resolved: bool,
    }

    fn event(s: Spec<'_>) -> StoredAnomaly {
        StoredAnomaly {
            id: s.id,
            detected_ts_ms: NOW - s.id * 60_000,
            process_instance_id: None,
            pid: 100 + s.id as u32,
            process_name: s.name.into(),
            application: None,
            exe_path: format!(r"C:\apps\{}", s.name),
            resource: s.resource,
            kind: s.kind,
            current: 72.0,
            baseline: 8.0,
            deviation_pct: 800.0,
            duration_ms: s.duration_ms,
            severity: s.severity,
            system_cpu_percent: None,
            system_memory_percent: None,
            baseline_window_hours: 24,
            baseline_confidence: "Established".into(),
            explanation: format!("{}: explanation {}.", s.name, s.id),
            resolved_ts_ms: s.resolved.then_some(NOW),
            last_update_ts_ms: NOW,
            system_disk_percent: None,
            pressure_percent: None,
            share_percent: None,
            impact_score: s.score,
        }
    }

    fn cpu(
        id: i64,
        name: &str,
        severity: Severity,
        duration_ms: i64,
        score: Option<f64>,
        resolved: bool,
    ) -> StoredAnomaly {
        event(Spec {
            id,
            name,
            resource: Resource::Cpu,
            kind: AnomalyKind::Deviation,
            severity,
            duration_ms,
            score,
            resolved,
        })
    }

    fn sample() -> Vec<StoredAnomaly> {
        vec![
            cpu(
                1,
                "chrome.exe",
                Severity::Warning,
                600_000,
                Some(10.0),
                true,
            ),
            cpu(
                2,
                "chrome.exe",
                Severity::Warning,
                300_000,
                Some(12.0),
                true,
            ),
            event(Spec {
                id: 3,
                name: "chrome.exe",
                resource: Resource::Memory,
                kind: AnomalyKind::MemoryGrowth,
                severity: Severity::Warning,
                duration_ms: 1_800_000,
                score: None,
                resolved: true,
            }),
            cpu(4, "burner.exe", Severity::High, 180_000, Some(40.0), false),
            cpu(
                5,
                "quiet.exe",
                Severity::Informational,
                120_000,
                Some(1.0),
                true,
            ),
        ]
    }

    #[test]
    fn counts_by_severity_and_how_many_are_active() {
        let r = build(&sample(), 24, 10, NOW);
        assert_eq!(r.total, 5);
        assert_eq!(r.active, 1);
        // Order of Severity::ALL: Informational, Warning, High, Critical.
        assert_eq!(r.by_severity, [1, 3, 1, 0]);
        assert_eq!(r.hours, 24);
        assert_eq!(r.from_ms, NOW - 24 * MS_PER_HOUR);
    }

    #[test]
    fn offenders_are_grouped_per_executable_and_ranked_by_how_bad_it_got() {
        let r = build(&sample(), 24, 10, NOW);
        let names: Vec<&str> = r.offenders.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["burner.exe", "chrome.exe", "quiet.exe"],
            "High first"
        );

        let chrome = &r.offenders[1];
        assert_eq!(chrome.events, 3);
        assert_eq!(chrome.worst, Severity::Warning);
        assert_eq!(chrome.resources, vec!["cpu", "memory growth"]);
        assert_eq!(chrome.total_duration_ms, 2_700_000);
        assert_eq!(chrome.peak_impact, Some(12.0));
        assert!(!chrome.active);
        assert!(r.offenders[0].active, "burner is still going");
    }

    #[test]
    fn the_same_executable_in_a_different_case_is_one_offender() {
        let mut a = cpu(1, "Tool.exe", Severity::Warning, 1000, None, true);
        let mut b = cpu(2, "Tool.exe", Severity::Warning, 1000, None, true);
        a.exe_path = r"C:\Apps\Tool.exe".into();
        b.exe_path = r"c:\apps\tool.EXE".into();
        let r = build(&[a, b], 1, 10, NOW);
        assert_eq!(r.offenders.len(), 1);
        assert_eq!(r.offenders[0].events, 2);
    }

    #[test]
    fn top_limits_the_offenders_and_the_serious_list_is_capped() {
        let many: Vec<StoredAnomaly> = (1..=12)
            .map(|i| {
                cpu(
                    i,
                    &format!("p{i}.exe"),
                    Severity::Warning,
                    1000,
                    Some(i as f64),
                    true,
                )
            })
            .collect();
        let r = build(&many, 24, 3, NOW);
        assert_eq!(r.offenders.len(), 3);
        assert_eq!(
            r.offenders[0].name, "p12.exe",
            "biggest impact first among equals"
        );
        assert_eq!(r.serious.len(), SERIOUS_EVENTS);
        assert_eq!(r.serious[0].process_name, "p12.exe");
    }

    #[test]
    fn the_most_serious_events_come_worst_first() {
        let r = build(&sample(), 24, 10, NOW);
        let ids: Vec<i64> = r.serious.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![4, 2, 1, 3, 5]);
    }

    fn text(r: &Report) -> String {
        let mut out = Vec::new();
        render(r, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_report_reads_top_down_summary_offenders_events() {
        let t = text(&build(&sample(), 24, 10, NOW));
        for expected in [
            "WinPerf anomaly report: last 24 h",
            "ANOMALIES  5 in total, 1 still active",
            "Critical 0   High 1   Warning 3   Informational 1",
            "TOP OFFENDERS",
            "PROCESS",
            "burner.exe",
            "cpu, memory growth",
            "45m 00s",
            "active",
            "resolved",
            "MOST SERIOUS EVENTS",
            "#4 [High]",
            "still active",
            "burner.exe: explanation 4.",
            "`winperf anomalies show <id>`",
        ] {
            assert!(t.contains(expected), "missing {expected:?} in\n{t}");
        }
        let at = |s: &str| t.find(s).unwrap();
        assert!(at("ANOMALIES") < at("TOP OFFENDERS") && at("TOP OFFENDERS") < at("MOST SERIOUS"));
    }

    #[test]
    fn a_quiet_period_says_so_and_points_at_the_setup() {
        let t = text(&build(&[], 6, 10, NOW));
        assert!(t.contains("last 6 h"), "{t}");
        assert!(t.contains("No anomalies were recorded"), "{t}");
        assert!(t.contains("winperf profile status"), "{t}");
        assert!(!t.contains("TOP OFFENDERS"), "{t}");
    }

    #[test]
    fn long_names_are_clipped_to_keep_the_table_aligned() {
        let long = "x".repeat(60);
        let t = text(&build(
            &[cpu(1, &long, Severity::Warning, 1000, None, true)],
            1,
            10,
            NOW,
        ));
        assert!(t.contains(&format!("{}~", "x".repeat(25))), "{t}");
    }

    #[test]
    fn run_reads_the_period_from_the_database() {
        use winperf_core::anomaly::{AnomalyEvent, Impact, SystemHealth};
        use winperf_core::profiler::confidence::Confidence;
        let db = Database::open_in_memory().unwrap();
        let add = |ts: i64, name: &str| {
            db.insert_anomaly(&AnomalyEvent {
                detected_ts_ms: ts,
                pid: 7,
                start_time: 1,
                process_name: name.into(),
                exe_path: format!(r"C:\apps\{name}"),
                resource: Resource::Cpu,
                kind: AnomalyKind::Deviation,
                current: 72.0,
                baseline: 8.0,
                deviation_pct: 800.0,
                duration_ms: 120_000,
                severity: Severity::Warning,
                system: SystemHealth::default(),
                impact: Impact::default(),
                baseline_window_hours: 24,
                baseline_confidence: Confidence::Established,
                explanation: format!("{name} was busy"),
            })
            .unwrap()
        };
        let old = add(NOW - 30 * MS_PER_HOUR, "stale.exe");
        db.resolve_anomaly(old, NOW - 29 * MS_PER_HOUR).unwrap();
        let recent = add(NOW - MS_PER_HOUR, "recent.exe");
        db.resolve_anomaly(recent, NOW - MS_PER_HOUR / 2).unwrap();

        let mut out = Vec::new();
        run(&db, 24, 10, NOW, &mut out).unwrap();
        let t = String::from_utf8(out).unwrap();
        assert!(t.contains("recent.exe") && !t.contains("stale.exe"), "{t}");
        assert!(t.contains("ANOMALIES  1 in total, 0 still active"), "{t}");
    }
}
