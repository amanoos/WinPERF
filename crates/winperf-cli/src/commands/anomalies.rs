//! `winperf anomalies list|show`: the stored anomaly events (PRD FR-018, FR-019).

use std::io::Write;
use winperf_core::anomaly::{AnomalyKind, format};
use winperf_core::config::Resource;
use winperf_core::time::{format_span, unix_millis_to_utc_string};
use winperf_storage::{AnomalyFilter, Database, StoredAnomaly};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

const MS_PER_HOUR: i64 = 3_600_000;

pub(crate) fn at(ms: i64) -> String {
    unix_millis_to_utc_string(ms).unwrap_or_else(|| "unknown time".into())
}

pub(crate) fn value(a: &StoredAnomaly, v: f64) -> String {
    format::value(a.resource, a.kind, v)
}

/// What the event is about: the resource, or "memory growth" for a potential leak.
pub(crate) fn what(a: &StoredAnomaly) -> &'static str {
    match (a.resource, a.kind) {
        (Resource::Memory, AnomalyKind::MemoryGrowth) => "mem-growth",
        (r, _) => r.as_str(),
    }
}

pub(crate) fn deviation(pct: f64) -> String {
    format!("{pct:+.0}%")
}

/// A one-line summary per event, active ones first and then newest first. `hours` limits how far
/// back to look (events that were active in that time), `active_only` shows only the ones still
/// going on.
pub fn list(
    db: &Database,
    hours: Option<u32>,
    active_only: bool,
    limit: u32,
    now_ms: i64,
    out: &mut impl Write,
) -> Result {
    let filter = AnomalyFilter {
        since_ms: hours.map(|h| now_ms - i64::from(h) * MS_PER_HOUR),
        active_only,
    };
    let rows = db.list_anomalies(&filter, limit)?;
    if rows.is_empty() {
        let what = if active_only {
            "active anomalies"
        } else {
            "anomalies"
        };
        match hours {
            Some(h) => writeln!(out, "no {what} in the last {h} h")?,
            None if active_only => writeln!(out, "no active anomalies")?,
            None => writeln!(out, "no anomalies recorded")?,
        }
        return Ok(());
    }
    writeln!(
        out,
        "{:<5} {:<19} {:<13} {:<9} {:<10} {:<28} {:>10} {:>10} {:>7} {:>8}",
        "ID",
        "TIME (UTC)",
        "SEVERITY",
        "STATE",
        "RESOURCE",
        "PROCESS",
        "NOW",
        "NORMAL",
        "OVER",
        "LASTED"
    )?;
    for a in &rows {
        writeln!(out, "{}", format_row(a))?;
    }
    writeln!(
        out,
        "{} event(s); `winperf anomalies show <id>` explains one",
        rows.len()
    )?;
    Ok(())
}

fn format_row(a: &StoredAnomaly) -> String {
    let process = format!("{} ({})", a.process_name, a.pid);
    let process: String = if process.chars().count() > 28 {
        let cut: String = process.chars().take(27).collect();
        format!("{cut}~")
    } else {
        process
    };
    format!(
        "{:<5} {:<19} {:<13} {:<9} {:<10} {:<28} {:>10} {:>10} {:>7} {:>8}",
        a.id,
        at(a.detected_ts_ms),
        a.severity.label(),
        if a.is_active() { "active" } else { "resolved" },
        what(a),
        process,
        value(a, a.current),
        value(a, a.baseline),
        deviation(a.deviation_pct),
        format_span(a.duration_ms),
    )
}

/// Every stored field of one event, with the explanation.
pub fn show(db: &Database, id: i64, out: &mut impl Write) -> Result {
    let Some(a) = db.anomaly(id)? else {
        return Err(format!("no anomaly with id {id}").into());
    };
    writeln!(out, "Anomaly #{} - {}", a.id, a.severity.label())?;
    writeln!(out, "  Detected     {} UTC", at(a.detected_ts_ms))?;
    match a.resolved_ts_ms {
        None => writeln!(
            out,
            "  State        active (last confirmed {} UTC)",
            at(a.last_update_ts_ms)
        )?,
        Some(t) => writeln!(out, "  State        resolved at {} UTC", at(t))?,
    }
    writeln!(out, "  Process      {} (PID {})", a.process_name, a.pid)?;
    if let Some(app) = &a.application {
        writeln!(out, "  Application  {app}")?;
    }
    writeln!(out, "  Path         {}", a.exe_path)?;
    writeln!(out, "  Resource     {}", what(&a))?;
    writeln!(out, "  Measured     {}", value(&a, a.current))?;
    writeln!(
        out,
        "  Baseline     {} ({}; {} h window, {} confidence)",
        value(&a, a.baseline),
        match a.kind {
            AnomalyKind::Deviation => "median",
            AnomalyKind::MemoryGrowth => "usual growth",
        },
        a.baseline_window_hours,
        a.baseline_confidence
    )?;
    writeln!(out, "  Deviation    {}", deviation(a.deviation_pct))?;
    writeln!(out, "  Duration     {}", format_span(a.duration_ms))?;
    let system = match (
        a.system_cpu_percent,
        a.system_memory_percent,
        a.system_disk_percent,
    ) {
        (None, None, None) => "not measured".to_string(),
        (cpu, mem, disk) => format!(
            "CPU {}, memory {}, disk {}",
            cpu.map_or("n/a".into(), |v| format!("{v:.1}%")),
            mem.map_or("n/a".into(), |v| format!("{v:.1}% in use")),
            disk.map_or("n/a".into(), |v| format!("{v:.1}% busy")),
        ),
    };
    writeln!(out, "  System       {system}")?;
    let part = |v: Option<f64>| v.map_or("n/a".to_string(), |v| format!("{v:.0}%"));
    writeln!(
        out,
        "  Impact       {} (system pressure {}, process share {})",
        a.impact_score
            .map_or("not measured".to_string(), |v| format!(
                "score {v:.0} of 100"
            )),
        part(a.pressure_percent),
        part(a.share_percent),
    )?;
    writeln!(out, "  Why          {}", a.explanation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use winperf_core::anomaly::{AnomalyEvent, Impact, Severity, SystemHealth};
    use winperf_core::profiler::confidence::Confidence;

    fn seed(db: &Database, ts: i64, name: &str) -> i64 {
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
            duration_ms: 125_000,
            severity: Severity::Warning,
            system: SystemHealth {
                cpu_percent: Some(91.0),
                memory_percent: Some(75.0),
                disk_percent: None,
            },
            impact: Impact {
                pressure_percent: Some(91.0),
                share_percent: Some(72.0),
                score: Some(65.5),
            },
            baseline_window_hours: 24,
            baseline_confidence: Confidence::Established,
            explanation: format!("{name} was busy"),
        })
        .unwrap()
    }

    fn text(f: impl FnOnce(&mut Vec<u8>) -> Result) -> String {
        let mut out = Vec::new();
        f(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn the_list_shows_one_readable_line_per_event() {
        let db = Database::open_in_memory().unwrap();
        let id = seed(&db, 1_700_000_000_000, "busy.exe");
        let t = text(|o| list(&db, None, false, 50, 1_700_000_100_000, o));

        assert!(t.contains("SEVERITY") && t.contains("LASTED"), "{t}");
        for expected in [
            &id.to_string(),
            "2023-11-14 22:13:20",
            "Warning",
            "cpu",
            "busy.exe (7)",
            "72.0%",
            "8.0%",
            "+800%",
            "2m 05s",
            "1 event(s)",
        ] {
            assert!(t.contains(expected), "missing {expected:?} in\n{t}");
        }
    }

    #[test]
    fn an_empty_list_says_so_and_names_the_time_range() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(
            text(|o| list(&db, None, false, 50, 0, o)).trim(),
            "no anomalies recorded"
        );
        assert_eq!(
            text(|o| list(&db, Some(6), false, 50, 0, o)).trim(),
            "no anomalies in the last 6 h"
        );
    }

    #[test]
    fn hours_limits_how_far_back_the_list_goes() {
        let db = Database::open_in_memory().unwrap();
        let now = 10 * MS_PER_HOUR;
        seed(&db, now - 30 * 60_000, "recent.exe");
        let older = seed(&db, now - 5 * MS_PER_HOUR, "older.exe");
        db.resolve_anomaly(older, now - 4 * MS_PER_HOUR).unwrap();
        let t = text(|o| list(&db, Some(1), false, 50, now, o));
        assert!(t.contains("recent.exe") && !t.contains("older.exe"), "{t}");
    }

    #[test]
    fn a_very_long_process_name_is_cut_to_keep_the_columns() {
        let db = Database::open_in_memory().unwrap();
        seed(&db, 1, &"x".repeat(60));
        let t = text(|o| list(&db, None, false, 50, 2, o));
        let mut lines = t.lines();
        let header = lines.next().unwrap();
        let line = lines.next().unwrap();
        assert!(line.contains('~'), "{line}");
        assert_eq!(line.chars().count(), header.chars().count(), "{line}");
    }

    #[test]
    fn show_prints_every_field_and_the_explanation() {
        let db = Database::open_in_memory().unwrap();
        let id = seed(&db, 1_700_000_000_000, "busy.exe");
        let t = text(|o| show(&db, id, o));
        for expected in [
            "Warning",
            "2023-11-14 22:13:20 UTC",
            "busy.exe (PID 7)",
            r"C:\apps\busy.exe",
            "72.0%",
            "8.0% (median; 24 h window, Established confidence)",
            "+800%",
            "2m 05s",
            "CPU 91.0%, memory 75.0% in use, disk n/a",
            "score 66 of 100 (system pressure 91%, process share 72%)",
            "State        active",
            "busy.exe was busy",
        ] {
            assert!(t.contains(expected), "missing {expected:?} in\n{t}");
        }
    }

    #[test]
    fn showing_an_unknown_id_is_an_error() {
        let db = Database::open_in_memory().unwrap();
        let err = show(&db, 99, &mut Vec::new()).unwrap_err();
        assert_eq!(err.to_string(), "no anomaly with id 99");
    }

    #[test]
    fn the_list_shows_state_and_can_be_limited_to_active_events() {
        let db = Database::open_in_memory().unwrap();
        let done = seed(&db, 1_000, "done.exe");
        seed(&db, 2_000, "going.exe");
        db.resolve_anomaly(done, 5_000).unwrap();

        let all = text(|o| list(&db, None, false, 50, 10_000, o));
        assert!(
            all.contains("STATE") && all.contains("resolved") && all.contains("active"),
            "{all}"
        );
        let going = all.find("going.exe").unwrap();
        assert!(
            going < all.find("done.exe").unwrap(),
            "active first:
{all}"
        );

        let active = text(|o| list(&db, None, true, 50, 10_000, o));
        assert!(
            active.contains("going.exe") && !active.contains("done.exe"),
            "{active}"
        );
        db.resolve_anomaly(2, 6_000).unwrap();
        assert_eq!(
            text(|o| list(&db, None, true, 50, 10_000, o)).trim(),
            "no active anomalies"
        );
    }

    #[test]
    fn show_says_whether_the_event_is_going_on_and_what_it_weighs() {
        let db = Database::open_in_memory().unwrap();
        let id = seed(&db, 1_700_000_000_000, "busy.exe");
        let t = text(|o| show(&db, id, o));
        assert!(
            t.contains("State        active (last confirmed 2023-11-14 22:13:20 UTC)"),
            "{t}"
        );
        db.resolve_anomaly(id, 1_700_000_600_000).unwrap();
        let t = text(|o| show(&db, id, o));
        assert!(
            t.contains("State        resolved at 2023-11-14 22:23:20 UTC"),
            "{t}"
        );
        assert!(t.contains("Impact       score 66 of 100"), "{t}");
    }

    #[test]
    fn a_potential_leak_is_shown_as_a_growth_rate_not_a_level() {
        let db = Database::open_in_memory().unwrap();
        let mib = 1024.0 * 1024.0;
        db.insert_anomaly(&AnomalyEvent {
            detected_ts_ms: 1_700_000_000_000,
            pid: 9,
            start_time: 1,
            process_name: "leaky.exe".into(),
            exe_path: r"C:pps\leaky.exe".into(),
            resource: Resource::Memory,
            kind: AnomalyKind::MemoryGrowth,
            current: 180.0 * mib,
            baseline: 0.0,
            deviation_pct: 17_900.0,
            duration_ms: 1_800_000,
            severity: Severity::Warning,
            system: SystemHealth::default(),
            impact: Impact::default(),
            baseline_window_hours: 24,
            baseline_confidence: Confidence::Established,
            explanation: "Potential memory leak: leaky.exe".into(),
        })
        .unwrap();
        let t = text(|o| list(&db, None, false, 50, 1_700_000_100_000, o));
        assert!(t.contains("mem-growth") && t.contains("180.0 MiB/h"), "{t}");
        let t = text(|o| show(&db, 1, o));
        assert!(t.contains("Resource     mem-growth"), "{t}");
        assert!(t.contains("0 B/h (usual growth; 24 h window"), "{t}");
        assert!(t.contains("Potential memory leak"), "{t}");
    }
}
