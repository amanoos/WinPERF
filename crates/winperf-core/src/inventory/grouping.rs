//! Process-to-application association (PRD FR-004).
//!
//! Rules, in order:
//! 1. **Install location**: the executable lives under an installed app's install directory
//!    (most specific directory wins). Overly generic locations (drive root, `Windows`,
//!    `Program Files`, ...) are ignored so one sloppy registry entry can't swallow everything.
//! 2. **Publisher**: the process's signer matches exactly one installed app's publisher. If
//!    several installed apps share a publisher the match is ambiguous and is *not* guessed.
//! 3. Otherwise the process is `Unassociated (<publisher>)`, or `Unassociated (unknown)`.
//!
//! A product-name fallback (version resources) is not implemented: process records don't carry
//! version info yet.

use super::processes::ProcessInfo;
use super::software::InstalledApp;
use crate::ProcessKey;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchRule {
    InstallLocation,
    Publisher,
    None,
}

/// Which application one process belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    /// Index into the installed-apps slice, when matched.
    pub app: Option<usize>,
    /// Application name, or `Unassociated (<publisher>)`.
    pub label: String,
    pub rule: MatchRule,
}

/// All processes of one application (or one unassociated publisher bucket).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppGroup {
    pub label: String,
    pub app: Option<usize>,
    pub processes: Vec<ProcessKey>,
}

/// Lowercase, `/` -> `\`, strip quotes and trailing separators.
fn normalize_path(p: &str) -> String {
    p.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

/// Directories too broad to identify a single application.
fn is_generic_location(norm: &str) -> bool {
    let rest = match norm.split_once(':') {
        Some((drive, rest)) if drive.len() == 1 => rest.trim_start_matches('\\'),
        _ => return norm.is_empty(),
    };
    let parts: Vec<&str> = rest.split('\\').filter(|s| !s.is_empty()).collect();
    match parts.as_slice() {
        [] => true,
        ["windows" | "program files" | "program files (x86)" | "programdata"] => true,
        ["windows", "system32" | "syswow64"] => true,
        ["users", ..] => parts.len() <= 2,
        _ => false,
    }
}

fn is_under(path: &str, dir: &str) -> bool {
    path == dir
        || path
            .strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// Lowercased alphanumeric words with company-suffix noise removed: "Docker Inc." -> "docker".
fn normalize_publisher(p: &str) -> String {
    const NOISE: &[&str] = &[
        "inc",
        "llc",
        "ltd",
        "limited",
        "corp",
        "corporation",
        "co",
        "gmbh",
        "sa",
        "srl",
        "sro",
        "plc",
        "ag",
        "bv",
    ];
    // Drop dots first so "s.r.o." collapses to "sro".
    let cleaned: String = p
        .to_lowercase()
        .chars()
        .filter(|c| *c != '.')
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    cleaned
        .split_whitespace()
        .filter(|w| !NOISE.contains(w))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Associate every process with an application. The result has one entry per input process,
/// in the same order.
pub fn associate(apps: &[InstalledApp], procs: &[ProcessInfo]) -> Vec<Association> {
    // (normalized install dir, app index), skipping missing and generic locations.
    let locations: Vec<(String, usize)> = apps
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            let n = normalize_path(a.install_location.as_deref()?);
            (!n.is_empty() && !is_generic_location(&n)).then_some((n, i))
        })
        .collect();

    // Publisher -> app index, only when that publisher has exactly one installed app.
    let mut by_publisher: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, a) in apps.iter().enumerate() {
        if let Some(p) = a.publisher.as_deref() {
            let n = normalize_publisher(p);
            if !n.is_empty() {
                by_publisher.entry(n).or_default().push(i);
            }
        }
    }

    procs
        .iter()
        .map(|p| {
            // Rule 1: most specific (longest) install directory containing the executable.
            if let Some(path) = p.exe_path.value() {
                let path = normalize_path(&path.to_string_lossy());
                let best = locations
                    .iter()
                    .filter(|(dir, _)| is_under(&path, dir))
                    .max_by_key(|(dir, _)| dir.len());
                if let Some((_, i)) = best {
                    return Association {
                        app: Some(*i),
                        label: apps[*i].name.clone(),
                        rule: MatchRule::InstallLocation,
                    };
                }
            }
            // Rule 2: unambiguous publisher match.
            if let Some(signer) = p.publisher.as_deref()
                && let Some([i]) = by_publisher
                    .get(&normalize_publisher(signer))
                    .map(Vec::as_slice)
            {
                return Association {
                    app: Some(*i),
                    label: apps[*i].name.clone(),
                    rule: MatchRule::Publisher,
                };
            }
            // Rule 3: unassociated bucket named by publisher.
            Association {
                app: None,
                label: format!(
                    "Unassociated ({})",
                    p.publisher.as_deref().unwrap_or("unknown")
                ),
                rule: MatchRule::None,
            }
        })
        .collect()
}

/// Aggregate associations into groups, sorted by label (case-insensitive); each group's
/// processes are sorted by PID.
pub fn group(apps: &[InstalledApp], procs: &[ProcessInfo]) -> Vec<AppGroup> {
    let mut groups: BTreeMap<(String, Option<usize>), Vec<ProcessKey>> = BTreeMap::new();
    for (assoc, p) in associate(apps, procs).into_iter().zip(procs) {
        groups
            .entry((assoc.label, assoc.app))
            .or_default()
            .push(p.key);
    }
    let mut out: Vec<AppGroup> = groups
        .into_iter()
        .map(|((label, app), mut processes)| {
            processes.sort();
            AppGroup {
                label,
                app,
                processes,
            }
        })
        .collect();
    out.sort_by_key(|g| g.label.to_lowercase());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::executable::SignatureStatus;
    use crate::{Classification, Metric};
    use std::path::PathBuf;

    fn app(name: &str, publisher: Option<&str>, location: Option<&str>) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            publisher: publisher.map(Into::into),
            version: None,
            install_date: None,
            install_location: location.map(Into::into),
            uninstall_command: None,
            registry_sources: vec!["HKLM64".into()],
            classification: Classification::Unknown,
        }
    }

    fn proc(pid: u32, path: Option<&str>, signer: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            key: ProcessKey::new(pid, 1000 + pid as u64),
            parent_pid: 1,
            name: "p.exe".into(),
            start_time: Metric::Available(1000 + pid as u64),
            exe_path: path.map_or(Metric::Unavailable, |p| Metric::Available(PathBuf::from(p))),
            user: Metric::Unavailable,
            session_id: Metric::Unavailable,
            command_line: Metric::Unavailable,
            publisher: signer.map(Into::into),
            signature: SignatureStatus::Unreadable,
            classification: Classification::Unknown,
        }
    }

    const CHROME_DIR: &str = "C:\\Program Files\\Google\\Chrome\\Application";

    #[test]
    fn multi_process_browser_groups_into_one_application() {
        let apps = vec![app("Google Chrome", Some("Google LLC"), Some(CHROME_DIR))];
        let chrome = format!("{CHROME_DIR}\\chrome.exe");
        let nested = format!("{CHROME_DIR}\\124.0\\elevation_service.exe");
        let procs = vec![
            proc(1, Some(&chrome), Some("Google LLC")),
            proc(2, Some(&chrome), Some("Google LLC")),
            proc(3, Some(&chrome), Some("Google LLC")),
            proc(4, Some(&nested), None),
        ];
        let groups = group(&apps, &procs);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].label, "Google Chrome");
        assert_eq!(groups[0].app, Some(0));
        assert_eq!(groups[0].processes.len(), 4);
    }

    #[test]
    fn path_matching_ignores_case_quotes_slashes_and_trailing_backslash() {
        let apps = vec![app("Tool", None, Some("\"c:/PROGRAM FILES/Tool/\""))];
        let procs = vec![proc(
            1,
            Some("C:\\Program Files\\Tool\\BIN\\tool.exe"),
            None,
        )];
        assert_eq!(associate(&apps, &procs)[0].app, Some(0));
    }

    #[test]
    fn directory_prefix_must_end_at_a_path_boundary() {
        let apps = vec![app("Foo", None, Some("C:\\Program Files\\Foo"))];
        let procs = vec![proc(1, Some("C:\\Program Files\\FooBar\\x.exe"), None)];
        let a = &associate(&apps, &procs)[0];
        assert_eq!(a.app, None);
        assert_eq!(a.rule, MatchRule::None);
    }

    #[test]
    fn most_specific_install_directory_wins() {
        let apps = vec![
            app("Suite", None, Some("C:\\Tools")),
            app("Suite Plugin", None, Some("C:\\Tools\\Plugin")),
        ];
        let procs = vec![
            proc(1, Some("C:\\Tools\\Plugin\\p.exe"), None),
            proc(2, Some("C:\\Tools\\main.exe"), None),
        ];
        let a = associate(&apps, &procs);
        assert_eq!(a[0].label, "Suite Plugin");
        assert_eq!(a[1].label, "Suite");
    }

    #[test]
    fn generic_install_locations_do_not_swallow_processes() {
        let apps = vec![
            app("Sloppy A", None, Some("C:\\")),
            app("Sloppy B", None, Some("C:\\Windows")),
            app("Sloppy C", None, Some("C:\\Program Files")),
            app("Sloppy D", None, Some("C:\\Windows\\System32")),
            app("Sloppy E", None, Some("C:\\Users\\me")),
        ];
        let procs = vec![
            proc(1, Some("C:\\Windows\\System32\\svchost.exe"), None),
            proc(2, Some("C:\\Program Files\\Other\\o.exe"), None),
            proc(3, Some("C:\\Users\\me\\AppData\\x.exe"), None),
        ];
        assert!(associate(&apps, &procs).iter().all(|a| a.app.is_none()));
    }

    #[test]
    fn publisher_fallback_matches_a_unique_publisher_despite_suffix_noise() {
        let apps = vec![app("Docker Desktop", Some("Docker Inc."), None)];
        let procs = vec![proc(
            1,
            Some("D:\\elsewhere\\docker.exe"),
            Some("Docker Inc"),
        )];
        let a = &associate(&apps, &procs)[0];
        assert_eq!(a.label, "Docker Desktop");
        assert_eq!(a.rule, MatchRule::Publisher);
    }

    #[test]
    fn ambiguous_publisher_is_not_guessed() {
        let apps = vec![
            app("CLion", Some("JetBrains s.r.o."), None),
            app("DataGrip", Some("JetBrains s.r.o."), None),
        ];
        let procs = vec![proc(1, Some("D:\\x\\j.exe"), Some("JetBrains s.r.o."))];
        let a = &associate(&apps, &procs)[0];
        assert_eq!(a.app, None);
        assert_eq!(a.label, "Unassociated (JetBrains s.r.o.)");
    }

    #[test]
    fn install_location_beats_publisher() {
        let apps = vec![
            app("A", Some("Acme"), Some("C:\\A")),
            app("B", Some("Other"), None),
        ];
        let procs = vec![proc(1, Some("C:\\A\\a.exe"), Some("Other"))];
        let a = &associate(&apps, &procs)[0];
        assert_eq!(
            (a.label.as_str(), a.rule),
            ("A", MatchRule::InstallLocation)
        );
    }

    #[test]
    fn unreadable_process_is_unassociated_unknown() {
        let apps = vec![app("A", Some("Acme"), Some("C:\\A"))];
        let a = &associate(&apps, &[proc(4, None, None)])[0];
        assert_eq!(a.label, "Unassociated (unknown)");
    }

    #[test]
    fn unassociated_processes_group_by_publisher() {
        let procs = vec![
            proc(1, Some("C:\\Windows\\a.exe"), Some("Microsoft Windows")),
            proc(2, Some("C:\\Windows\\b.exe"), Some("Microsoft Windows")),
            proc(3, Some("C:\\x\\c.exe"), None),
        ];
        let g = group(&[], &procs);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].label, "Unassociated (Microsoft Windows)");
        assert_eq!(g[0].processes.len(), 2);
        assert_eq!(g[1].label, "Unassociated (unknown)");
    }

    #[test]
    fn grouping_is_deterministic_and_order_independent() {
        let apps = vec![app("A", None, Some("C:\\A")), app("B", None, Some("C:\\B"))];
        let p1 = proc(1, Some("C:\\A\\1.exe"), None);
        let p2 = proc(2, Some("C:\\B\\2.exe"), None);
        let p3 = proc(3, Some("C:\\A\\3.exe"), None);
        let one = group(&apps, &[p1.clone(), p2.clone(), p3.clone()]);
        let two = group(&apps, &[p3, p1, p2]);
        assert_eq!(one, two);
        assert_eq!(one[0].processes[0].pid, 1);
    }

    #[test]
    fn association_vector_matches_input_order_and_length() {
        let apps = vec![app("A", None, Some("C:\\A"))];
        let procs = vec![
            proc(9, Some("C:\\Z\\z.exe"), None),
            proc(1, Some("C:\\A\\a.exe"), None),
        ];
        let a = associate(&apps, &procs);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].app, None);
        assert_eq!(a[1].app, Some(0));
    }
}
