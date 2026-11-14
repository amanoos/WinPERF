//! `winperf process list`: running processes with publisher classification.

use crate::export::{Format, processes_csv, processes_json};
use std::io::{self, Write};
use winperf_core::inventory::grouping::associate;
use winperf_core::inventory::{InstalledApp, ProcessInfo, ProcessSource, SignatureVerifier, scan};
use winperf_core::time::filetime_to_utc_string;

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Render processes as a fixed-width table. `*` after the PID marks partial data (some fields
/// could not be read). The command line column is only shown when requested.
pub fn format_table(procs: &[ProcessInfo], applications: &[String], show_cmdline: bool) -> String {
    let mut out = format!(
        "{:>7}  {:>7}  {:<28} {:<11} {:<24} {:<24} {:>4}  {:<19}  {:<30}",
        "PID", "PPID", "NAME", "CLASS", "PUBLISHER", "USER", "SESS", "STARTED (UTC)", "APPLICATION"
    );
    if show_cmdline {
        out.push_str("  COMMAND LINE");
    }
    out.push('\n');

    for (p, application) in procs.iter().zip(applications) {
        let started = p
            .start_time
            .value()
            .and_then(|t| filetime_to_utc_string(*t))
            .unwrap_or_else(|| "-".into());
        let sess = p
            .session_id
            .value()
            .map_or("-".to_string(), |s| s.to_string());
        let pid = format!("{}{}", p.key.pid, if p.is_partial() { "*" } else { "" });
        out.push_str(&format!(
            "{:>7}  {:>7}  {:<28} {:<11} {:<24} {:<24} {:>4}  {:<19}  {:<30}",
            pid,
            p.parent_pid,
            clip(&p.name, 28),
            p.classification,
            clip(p.publisher.as_deref().unwrap_or("-"), 24),
            clip(p.user.value().map_or("-", String::as_str), 24),
            sess,
            started,
            clip(application, 30)
        ));
        if show_cmdline {
            out.push_str(&format!(
                "  {}",
                p.command_line.value().map_or("-", String::as_str)
            ));
        }
        out.push('\n');
    }
    let partial = procs.iter().filter(|p| p.is_partial()).count();
    out.push_str(&format!(
        "\n{} processes ({} with partial data, marked *)\n",
        procs.len(),
        partial
    ));
    out
}

/// Scan, associate each process with an installed application, and write it in `format`.
pub fn list(
    source: &dyn ProcessSource,
    apps: &[InstalledApp],
    verifier: Option<&dyn SignatureVerifier>,
    show_cmdline: bool,
    format: Format,
    out: &mut impl Write,
) -> io::Result<()> {
    let procs = scan(source, verifier);
    let text = match format {
        Format::Table => {
            let labels: Vec<String> = associate(apps, &procs)
                .into_iter()
                .map(|a| a.label)
                .collect();
            format_table(&procs, &labels, show_cmdline)
        }
        Format::Json => processes_json(&procs, apps, show_cmdline),
        Format::Csv => processes_csv(&procs, apps, show_cmdline),
    };
    out.write_all(text.as_bytes())?;
    if format == Format::Json {
        out.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use winperf_core::inventory::{RawProcess, SignatureStatus};
    use winperf_core::{Classification, Metric};

    struct Fixture(Vec<RawProcess>);
    impl ProcessSource for Fixture {
        fn list(&self) -> Vec<RawProcess> {
            self.0.clone()
        }
    }
    struct Always(SignatureStatus);
    impl SignatureVerifier for Always {
        fn verify(&self, _: &std::path::Path) -> SignatureStatus {
            self.0.clone()
        }
    }

    fn labels(procs: &[ProcessInfo]) -> Vec<String> {
        associate(&[], procs).into_iter().map(|a| a.label).collect()
    }

    fn readable() -> RawProcess {
        RawProcess {
            pid: 42,
            parent_pid: 1,
            name: "app.exe".into(),
            start_time: Some((1_709_214_307 + 11_644_473_600) * 10_000_000),
            exe_path: Some(PathBuf::from("C:\\a\\app.exe")),
            user: Some("PC\\me".into()),
            session_id: Some(1),
            command_line: Some("app.exe --flag".into()),
            exited: false,
        }
    }

    #[test]
    fn complete_process_row_has_no_partial_marker() {
        let v = Always(SignatureStatus::Valid {
            signer: "Acme".into(),
        });
        let procs = scan(&Fixture(vec![readable()]), Some(&v));
        let t = format_table(&procs, &labels(&procs), false);
        assert!(t.contains("42  "), "{t}");
        assert!(!t.contains("42*"));
        assert!(t.contains("third_party") && t.contains("Acme") && t.contains("PC\\me"));
        assert!(t.contains("2024-02-29 13:45:07"));
        assert!(t.contains("1 processes (0 with partial data"));
        assert!(!t.contains("COMMAND LINE"));
    }

    #[test]
    fn denied_process_is_marked_partial_with_dashes() {
        let denied = RawProcess {
            pid: 4,
            name: "System".into(),
            ..Default::default()
        };
        let procs = scan(&Fixture(vec![denied]), None);
        let t = format_table(&procs, &labels(&procs), false);
        assert!(t.contains("4*"), "{t}");
        assert!(t.contains("(1 with partial data"));
    }

    #[test]
    fn command_line_column_is_opt_in() {
        let v = Always(SignatureStatus::NotSigned);
        let procs = scan(&Fixture(vec![readable()]), Some(&v));
        let l = labels(&procs);
        assert!(!format_table(&procs, &l, false).contains("--flag"));
        let with = format_table(&procs, &l, true);
        assert!(with.contains("COMMAND LINE") && with.contains("app.exe --flag"));
        assert_eq!(procs[0].classification, Classification::Unsigned);
        assert_eq!(
            procs[0].command_line,
            Metric::Available("app.exe --flag".into())
        );
    }
}
