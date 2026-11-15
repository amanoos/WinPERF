//! JSON and CSV export of inventory data (PRD Phase 1 deliverable 9).

use clap::ValueEnum;
use serde::Serialize;
use winperf_core::inventory::grouping::associate;
use winperf_core::inventory::{InstalledApp, ProcessInfo};
use winperf_core::time::filetime_to_utc_string;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable fixed-width table
    Table,
    /// Pretty-printed JSON array
    Json,
    /// RFC 4180 CSV with a header row
    Csv,
}

/// Escape one CSV cell. Cells that a spreadsheet could interpret as a formula (leading `=`, `+`,
/// `-`, `@`, tab or CR) get a leading `'` so exported data can't execute when opened in Excel.
pub fn csv_cell(s: &str) -> String {
    let guarded = match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => format!("'{s}"),
        _ => s.to_string(),
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn csv_row(cells: &[String]) -> String {
    let mut line = cells
        .iter()
        .map(|c| csv_cell(c))
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

#[derive(Serialize)]
struct AppRecord<'a> {
    name: &'a str,
    publisher: Option<&'a str>,
    version: Option<&'a str>,
    install_date: Option<&'a str>,
    install_location: Option<&'a str>,
    /// Shown with its secrets hidden (an uninstall command is a command line).
    uninstall_command: Option<String>,
    registry_sources: &'a [String],
    classification: &'static str,
}

fn app_records(apps: &[InstalledApp]) -> Vec<AppRecord<'_>> {
    apps.iter()
        .map(|a| AppRecord {
            name: &a.name,
            publisher: a.publisher.as_deref(),
            version: a.version.as_deref(),
            install_date: a.install_date.as_deref(),
            install_location: a.install_location.as_deref(),
            uninstall_command: a
                .uninstall_command
                .as_deref()
                .map(winperf_core::redact::redact_command_line),
            registry_sources: &a.registry_sources,
            classification: a.classification.as_str(),
        })
        .collect()
}

pub fn apps_json(apps: &[InstalledApp]) -> String {
    serde_json::to_string_pretty(&app_records(apps)).expect("serializing plain records")
}

pub fn apps_csv(apps: &[InstalledApp]) -> String {
    let mut out = csv_row(
        &[
            "name",
            "publisher",
            "version",
            "install_date",
            "install_location",
            "uninstall_command",
            "registry_sources",
            "classification",
        ]
        .map(String::from),
    );
    let opt = |o: Option<&str>| o.unwrap_or("").to_string();
    for a in app_records(apps) {
        out.push_str(&csv_row(&[
            a.name.to_string(),
            opt(a.publisher),
            opt(a.version),
            opt(a.install_date),
            opt(a.install_location),
            opt(a.uninstall_command.as_deref()),
            a.registry_sources.join(";"),
            a.classification.to_string(),
        ]));
    }
    out
}

#[derive(Serialize)]
struct ProcessRecord {
    pid: u32,
    parent_pid: u32,
    name: String,
    /// UTC `YYYY-MM-DD HH:MM:SS`, null when unreadable.
    started_utc: Option<String>,
    exe_path: Option<String>,
    publisher: Option<String>,
    classification: &'static str,
    user: Option<String>,
    session_id: Option<u32>,
    application: String,
    /// True when some core fields could not be read (e.g. access denied).
    partial: bool,
    /// Present only when command lines were requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    command_line: Option<String>,
}

fn process_records(
    procs: &[ProcessInfo],
    apps: &[InstalledApp],
    include_cmdline: bool,
) -> Vec<ProcessRecord> {
    associate(apps, procs)
        .into_iter()
        .zip(procs)
        .map(|(assoc, p)| ProcessRecord {
            pid: p.key.pid,
            parent_pid: p.parent_pid,
            name: p.name.clone(),
            started_utc: p
                .start_time
                .value()
                .and_then(|t| filetime_to_utc_string(*t)),
            exe_path: p.exe_path.value().map(|x| x.to_string_lossy().into_owned()),
            publisher: p.publisher.clone(),
            classification: p.classification.as_str(),
            user: p.user.value().cloned(),
            session_id: p.session_id.value().copied(),
            application: assoc.label,
            partial: p.is_partial(),
            command_line: if include_cmdline {
                p.command_line
                    .value()
                    .map(|c| winperf_core::redact::redact_command_line(c))
            } else {
                None
            },
        })
        .collect()
}

pub fn processes_json(
    procs: &[ProcessInfo],
    apps: &[InstalledApp],
    include_cmdline: bool,
) -> String {
    serde_json::to_string_pretty(&process_records(procs, apps, include_cmdline))
        .expect("serializing plain records")
}

pub fn processes_csv(
    procs: &[ProcessInfo],
    apps: &[InstalledApp],
    include_cmdline: bool,
) -> String {
    let mut header: Vec<String> = [
        "pid",
        "parent_pid",
        "name",
        "started_utc",
        "exe_path",
        "publisher",
        "classification",
        "user",
        "session_id",
        "application",
        "partial",
    ]
    .map(String::from)
    .to_vec();
    if include_cmdline {
        header.push("command_line".into());
    }
    let mut out = csv_row(&header);
    for r in process_records(procs, apps, include_cmdline) {
        let mut cells = vec![
            r.pid.to_string(),
            r.parent_pid.to_string(),
            r.name,
            r.started_utc.unwrap_or_default(),
            r.exe_path.unwrap_or_default(),
            r.publisher.unwrap_or_default(),
            r.classification.to_string(),
            r.user.unwrap_or_default(),
            r.session_id.map(|s| s.to_string()).unwrap_or_default(),
            r.application,
            r.partial.to_string(),
        ];
        if include_cmdline {
            cells.push(r.command_line.unwrap_or_default());
        }
        out.push_str(&csv_row(&cells));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;
    use winperf_core::inventory::SignatureStatus;
    use winperf_core::{Classification, Metric, ProcessKey};

    fn app(name: &str) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            publisher: Some("Acme, Inc.".into()),
            version: Some("1.0".into()),
            install_date: Some("2024-02-29".into()),
            install_location: Some("C:\\Acme".into()),
            uninstall_command: None,
            registry_sources: vec!["HKLM32".into(), "HKLM64".into()],
            classification: Classification::Unknown,
        }
    }

    fn proc(pid: u32, path: Option<&str>, cmd: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            key: ProcessKey::new(pid, 133_000_000_000_000_000),
            parent_pid: 1,
            name: "a.exe".into(),
            start_time: Metric::Available(133_000_000_000_000_000),
            exe_path: path.map_or(Metric::Unavailable, |p| Metric::Available(PathBuf::from(p))),
            user: Metric::Unavailable,
            session_id: Metric::Available(1),
            command_line: cmd.map_or(Metric::Unavailable, |c| Metric::Available(c.into())),
            publisher: None,
            signature: SignatureStatus::NotSigned,
            classification: Classification::Unsigned,
        }
    }

    #[test]
    fn csv_cells_are_quoted_when_needed() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
    }

    #[test]
    fn csv_cells_that_look_like_formulas_are_neutralised() {
        for evil in ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=x"] {
            assert!(csv_cell(evil).starts_with('\''), "{evil}");
        }
        assert_eq!(csv_cell("ok=fine"), "ok=fine");
    }

    #[test]
    fn apps_json_is_valid_and_complete() {
        let v: Value = serde_json::from_str(&apps_json(&[app("Widget")])).unwrap();
        let a = &v[0];
        assert_eq!(a["name"], "Widget");
        assert_eq!(a["publisher"], "Acme, Inc.");
        assert_eq!(a["install_date"], "2024-02-29");
        assert_eq!(a["uninstall_command"], Value::Null);
        assert_eq!(a["registry_sources"][1], "HKLM64");
        assert_eq!(a["classification"], "unknown");
    }

    #[test]
    fn apps_csv_has_header_and_escapes_commas() {
        let csv = apps_csv(&[app("Widget")]);
        let mut lines = csv.split("\r\n");
        assert!(lines.next().unwrap().starts_with("name,publisher,version"));
        let row = lines.next().unwrap();
        assert!(row.contains("\"Acme, Inc.\""), "{row}");
        assert!(row.contains("HKLM32;HKLM64"));
    }

    #[test]
    fn spreadsheet_formula_in_an_app_name_is_defused() {
        let csv = apps_csv(&[app("=HYPERLINK(\"http://evil\")")]);
        let row = csv.split("\r\n").nth(1).unwrap();
        assert!(row.starts_with("\"'=HYPERLINK"), "{row}");
    }

    #[test]
    fn empty_inventory_exports_cleanly() {
        assert_eq!(apps_json(&[]), "[]");
        assert_eq!(apps_csv(&[]).matches("\r\n").count(), 1); // header only
    }

    #[test]
    fn processes_json_includes_application_and_omits_command_line_by_default() {
        let apps = vec![app("Acme Suite")];
        let procs = vec![proc(
            7,
            Some("C:\\Acme\\a.exe"),
            Some("a.exe --token=SECRET"),
        )];
        let off: Value = serde_json::from_str(&processes_json(&procs, &apps, false)).unwrap();
        assert_eq!(off[0]["application"], "Acme Suite");
        assert_eq!(off[0]["pid"], 7);
        assert!(
            off[0].get("command_line").is_none(),
            "must not leak by default"
        );
        assert!(!processes_json(&procs, &apps, false).contains("SECRET"));

        let on: Value = serde_json::from_str(&processes_json(&procs, &apps, true)).unwrap();
        // Asked for, the command line is shown, but its secret is not.
        assert_eq!(on[0]["command_line"], "a.exe --token=***");
        assert!(!processes_json(&procs, &apps, true).contains("SECRET"));
        assert!(!processes_csv(&procs, &apps, true).contains("SECRET"));
    }

    #[test]
    fn unreadable_process_exports_nulls_and_partial_flag() {
        let v: Value =
            serde_json::from_str(&processes_json(&[proc(4, None, None)], &[], false)).unwrap();
        assert_eq!(v[0]["exe_path"], Value::Null);
        assert_eq!(v[0]["user"], Value::Null);
        assert_eq!(v[0]["partial"], true);
        assert_eq!(v[0]["application"], "Unassociated (unknown)");
    }

    #[test]
    fn processes_csv_columns_follow_the_cmdline_option() {
        let procs = vec![proc(7, Some("C:\\x\\a.exe"), Some("a.exe, \"q\""))];
        let without = processes_csv(&procs, &[], false);
        assert!(!without.contains("command_line"));
        let with = processes_csv(&procs, &[], true);
        assert!(with.lines().next().unwrap().ends_with(",command_line"));
        assert!(with.contains("\"a.exe, \"\"q\"\"\""));
    }
}
