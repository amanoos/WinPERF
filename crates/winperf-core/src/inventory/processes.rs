//! Running-process inventory (PRD FR-003). Pure: the OS is reached through [`ProcessSource`].
//!
//! Processes Windows won't let us inspect, or that exit mid-scan, must never abort a scan.
//! Fields we could not read are `Metric::Unavailable`, never silently empty or zero.

use super::executable::{SignatureStatus, SignatureVerifier};
use crate::{Classification, Metric, ProcessKey};
use std::path::PathBuf;

/// What the operating system layer could read about one process. `None` = could not be read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    /// FILETIME creation time. Without it the instance cannot be told apart from a PID reuse.
    pub start_time: Option<u64>,
    pub exe_path: Option<PathBuf>,
    pub user: Option<String>,
    pub session_id: Option<u32>,
    /// Only populated when the caller opted in (command lines can contain secrets, NFR-003).
    pub command_line: Option<String>,
    /// The process ended between enumeration and inspection.
    pub exited: bool,
}

pub trait ProcessSource {
    fn list(&self) -> Vec<RawProcess>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    /// Instance identity. `start_time` is 0 when it could not be read (see `start_time` field).
    pub key: ProcessKey,
    pub parent_pid: u32,
    pub name: String,
    pub start_time: Metric<u64>,
    pub exe_path: Metric<PathBuf>,
    pub user: Metric<String>,
    pub session_id: Metric<u32>,
    pub command_line: Metric<String>,
    /// Signer display name when the signature is valid.
    pub publisher: Option<String>,
    pub signature: SignatureStatus,
    pub classification: Classification,
}

impl ProcessInfo {
    /// True when a core field could not be read (access denied, etc.). The command line is
    /// opt-in, so its absence does not count.
    pub fn is_partial(&self) -> bool {
        self.start_time.is_unavailable()
            || self.exe_path.is_unavailable()
            || self.user.is_unavailable()
            || self.session_id.is_unavailable()
    }
}

fn metric<T>(v: Option<T>) -> Metric<T> {
    v.map_or(Metric::Unavailable, Metric::Available)
}

/// Enumerate processes, drop ones that exited mid-scan, and classify each by its executable's
/// signature (`verifier = None` skips signature checks: classification stays `Unknown`).
/// Output is sorted by name (case-insensitive) then PID.
pub fn scan(
    source: &dyn ProcessSource,
    verifier: Option<&dyn SignatureVerifier>,
) -> Vec<ProcessInfo> {
    let mut out: Vec<ProcessInfo> = source
        .list()
        .into_iter()
        .filter(|r| !r.exited)
        .map(|r| {
            let signature = match (&r.exe_path, verifier) {
                (Some(path), Some(v)) => v.verify(path),
                _ => SignatureStatus::Unreadable,
            };
            let publisher = match &signature {
                SignatureStatus::Valid { signer } if !signer.is_empty() => Some(signer.clone()),
                _ => None,
            };
            ProcessInfo {
                key: ProcessKey::new(r.pid, r.start_time.unwrap_or(0)),
                parent_pid: r.parent_pid,
                name: r.name,
                start_time: metric(r.start_time),
                exe_path: metric(r.exe_path),
                user: metric(r.user),
                session_id: metric(r.session_id),
                command_line: metric(r.command_line),
                publisher,
                classification: super::executable::classify(&signature),
                signature,
            }
        })
        .collect();
    out.sort_by_key(|p| (p.name.to_lowercase(), p.key.pid));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    struct Fixture(Vec<RawProcess>);
    impl ProcessSource for Fixture {
        fn list(&self) -> Vec<RawProcess> {
            self.0.clone()
        }
    }

    /// Verifier keyed on the path text, so tests control the outcome.
    struct ByPath;
    impl SignatureVerifier for ByPath {
        fn verify(&self, path: &Path) -> SignatureStatus {
            let p = path.to_string_lossy();
            if p.contains("ms") {
                SignatureStatus::Valid {
                    signer: "Microsoft Corporation".into(),
                }
            } else if p.contains("acme") {
                SignatureStatus::Valid {
                    signer: "Acme Inc".into(),
                }
            } else if p.contains("missing") {
                SignatureStatus::Unreadable
            } else {
                SignatureStatus::NotSigned
            }
        }
    }

    fn full(pid: u32, name: &str, path: &str) -> RawProcess {
        RawProcess {
            pid,
            parent_pid: 4,
            name: name.into(),
            start_time: Some(1000 + pid as u64),
            exe_path: Some(PathBuf::from(path)),
            user: Some("PC\\me".into()),
            session_id: Some(1),
            command_line: None,
            exited: false,
        }
    }

    #[test]
    fn fully_readable_process_has_all_fields_and_is_not_partial() {
        let out = scan(
            &Fixture(vec![full(10, "a.exe", "C:\\ms\\a.exe")]),
            Some(&ByPath),
        );
        let p = &out[0];
        assert_eq!(p.key, ProcessKey::new(10, 1010));
        assert_eq!(p.parent_pid, 4);
        assert_eq!(
            p.exe_path,
            Metric::Available(PathBuf::from("C:\\ms\\a.exe"))
        );
        assert_eq!(p.user, Metric::Available("PC\\me".to_string()));
        assert_eq!(p.session_id, Metric::Available(1));
        assert_eq!(p.publisher.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(p.classification, Classification::MicrosoftOfficial);
        assert!(!p.is_partial(), "command line is opt-in and must not count");
    }

    #[test]
    fn access_denied_process_is_kept_as_partial_and_unknown() {
        let denied = RawProcess {
            pid: 4,
            name: "System".into(),
            ..Default::default()
        };
        let out = scan(&Fixture(vec![denied]), Some(&ByPath));
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert!(p.is_partial());
        assert!(p.start_time.is_unavailable() && p.exe_path.is_unavailable());
        assert_eq!(p.key, ProcessKey::new(4, 0));
        assert_eq!(p.classification, Classification::Unknown);
        assert_eq!(p.publisher, None);
    }

    #[test]
    fn processes_that_exited_mid_scan_are_dropped() {
        let gone = RawProcess {
            exited: true,
            ..full(20, "gone.exe", "C:\\x\\gone.exe")
        };
        let out = scan(
            &Fixture(vec![gone, full(21, "stay.exe", "C:\\x\\stay.exe")]),
            Some(&ByPath),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "stay.exe");
    }

    #[test]
    fn missing_executable_file_is_unknown_not_a_crash() {
        let out = scan(
            &Fixture(vec![full(30, "z.exe", "C:\\missing\\z.exe")]),
            Some(&ByPath),
        );
        assert_eq!(out[0].signature, SignatureStatus::Unreadable);
        assert_eq!(out[0].classification, Classification::Unknown);
    }

    #[test]
    fn reused_pid_with_a_new_start_time_is_a_different_instance() {
        let first = scan(&Fixture(vec![full(50, "a.exe", "C:\\x\\a.exe")]), None);
        let mut reborn = full(50, "b.exe", "C:\\x\\b.exe");
        reborn.start_time = Some(99_999);
        let second = scan(&Fixture(vec![reborn]), None);
        assert_eq!(first[0].key.pid, second[0].key.pid);
        assert_ne!(first[0].key, second[0].key);
    }

    #[test]
    fn repeated_scans_of_the_same_state_are_identical() {
        let src = Fixture(vec![
            full(2, "b.exe", "C:\\acme\\b.exe"),
            full(1, "A.exe", "C:\\x\\a.exe"),
        ]);
        assert_eq!(scan(&src, Some(&ByPath)), scan(&src, Some(&ByPath)));
    }

    #[test]
    fn no_verifier_means_unknown_classification() {
        let out = scan(&Fixture(vec![full(1, "a.exe", "C:\\ms\\a.exe")]), None);
        assert_eq!(out[0].classification, Classification::Unknown);
    }

    #[test]
    fn output_is_sorted_by_name_then_pid() {
        let src = Fixture(vec![
            full(9, "zeta.exe", "C:\\x\\z"),
            full(5, "Alpha.exe", "C:\\x\\a"),
            full(3, "alpha.exe", "C:\\x\\a"),
        ]);
        let pids: Vec<u32> = scan(&src, None).iter().map(|p| p.key.pid).collect();
        assert_eq!(pids, vec![3, 5, 9]);
    }

    #[test]
    fn third_party_and_unsigned_are_distinguished() {
        let src = Fixture(vec![
            full(1, "t.exe", "C:\\acme\\t.exe"),
            full(2, "u.exe", "C:\\plain\\u.exe"),
        ]);
        let out = scan(&src, Some(&ByPath));
        assert_eq!(out[0].classification, Classification::ThirdPartyOfficial);
        assert_eq!(out[0].publisher.as_deref(), Some("Acme Inc"));
        assert_eq!(out[1].classification, Classification::Unsigned);
    }
}
