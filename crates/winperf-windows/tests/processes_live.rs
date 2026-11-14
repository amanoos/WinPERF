//! Live process-inventory tests against this machine (T7 acceptance criteria).

use std::process::{Command, Stdio};
use winperf_core::Classification;
use winperf_core::inventory::{CachedVerifier, ProcessSource, scan};
use winperf_windows::{WinTrustVerifier, WindowsProcessSource};

#[test]
fn enumerates_this_process_with_full_details() {
    let me = std::process::id();
    let procs = scan(&WindowsProcessSource::default(), None);
    let p = procs
        .iter()
        .find(|p| p.key.pid == me)
        .expect("own process must be listed");
    assert!(
        p.start_time.value().is_some_and(|t| *t > 0),
        "start time read"
    );
    assert!(p.exe_path.value().is_some(), "own exe path readable");
    assert!(p.session_id.value().is_some());
    assert!(
        p.user.value().is_some_and(|u| u.contains('\\')),
        "{:?}",
        p.user
    );
    assert!(!p.is_partial());
}

#[test]
fn unreadable_processes_are_kept_not_dropped() {
    let raw = WindowsProcessSource::default().list();
    // PID 4 (System) always exists and cannot be opened without elevation: it must still be listed.
    let system = raw.iter().find(|r| r.pid == 4).expect("System listed");
    assert_eq!(system.name, "System");
    assert!(raw.len() > 50, "implausibly few processes: {}", raw.len());
}

#[test]
fn command_line_is_only_collected_on_request() {
    let me = std::process::id();
    let off = WindowsProcessSource::default().list();
    assert!(
        off.iter()
            .find(|r| r.pid == me)
            .unwrap()
            .command_line
            .is_none()
    );

    let on = WindowsProcessSource {
        collect_command_line: true,
    }
    .list();
    let line = on
        .iter()
        .find(|r| r.pid == me)
        .unwrap()
        .command_line
        .clone()
        .expect("own command line readable");
    assert!(line.to_lowercase().contains("processes_live"), "{line}");
}

#[test]
fn consecutive_scans_agree_on_stable_processes() {
    let a = scan(&WindowsProcessSource::default(), None);
    let b = scan(&WindowsProcessSource::default(), None);
    // Short-lived processes differ; long-lived ones (like this test and System) must have equal keys.
    for stable in [std::process::id(), 4] {
        let ka = a.iter().find(|p| p.key.pid == stable).map(|p| p.key);
        let kb = b.iter().find(|p| p.key.pid == stable).map(|p| p.key);
        assert_eq!(ka, kb, "pid {stable}");
    }
}

#[test]
fn a_process_that_exits_is_not_listed_afterwards() {
    let mut child = Command::new("cmd")
        .args(["/C", "ping -n 30 127.0.0.1"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let src = WindowsProcessSource::default();
    assert!(scan(&src, None).iter().any(|p| p.key.pid == pid));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(!scan(&src, None).iter().any(|p| p.key.pid == pid));
}

#[test]
fn system_binaries_classify_as_microsoft_and_this_test_does_not() {
    let verifier = CachedVerifier::new(WinTrustVerifier);
    let procs = scan(&WindowsProcessSource::default(), Some(&verifier));
    let ms = procs
        .iter()
        .filter(|p| p.classification == Classification::MicrosoftOfficial)
        .count();
    assert!(ms > 5, "expected several Microsoft processes, got {ms}");
    // This unsigned test binary must not be Microsoft.
    let me = procs
        .iter()
        .find(|p| p.key.pid == std::process::id())
        .unwrap();
    assert_eq!(me.classification, Classification::Unsigned);
}
