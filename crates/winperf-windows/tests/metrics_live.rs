//! Live checks of the per-tick probe: identity, memory counters, and first-sighting details.

use winperf_core::engine::MetricsSource;
use winperf_core::inventory::scan;
use winperf_core::sampling::Observation;
use winperf_windows::{WindowsMetricsSource, WindowsProcessSource};

fn observe_me(src: &mut WindowsMetricsSource) -> Observation {
    let me = std::process::id();
    src.observe()
        .into_iter()
        .find(|o| o.pid == me)
        .expect("own process observed")
}

#[test]
fn own_process_has_identity_cpu_and_memory() {
    let mut src = WindowsMetricsSource::new();
    let o = observe_me(&mut src);
    assert!(o.start_time.is_some_and(|t| t > 0));
    assert!(o.cpu_time_100ns.is_some_and(|t| t > 0), "{o:?}");
    let ws = o.working_set.expect("working set");
    let peak = o.peak_working_set.expect("peak working set");
    let private = o.private_bytes.expect("private bytes");
    let virt = o.virtual_bytes.expect("virtual size");
    assert!(ws > 0 && private > 0);
    assert!(peak >= ws, "peak {peak} < current {ws}");
    assert!(virt >= private, "virtual {virt} < private {private}");
}

#[test]
fn the_start_time_matches_the_process_inventory() {
    let mut src = WindowsMetricsSource::new();
    let o = observe_me(&mut src);
    let inv = scan(&WindowsProcessSource::default(), None);
    let me = inv
        .iter()
        .find(|p| p.key.pid == std::process::id())
        .unwrap();
    assert_eq!(Some(me.key.start_time), o.start_time);
}

#[test]
fn a_hundred_megabyte_allocation_shows_up_in_private_bytes_and_working_set() {
    let mut src = WindowsMetricsSource::new();
    let before = observe_me(&mut src);

    // Touch every page so it is committed and resident.
    let mut block = vec![0u8; 100 * 1024 * 1024];
    for i in (0..block.len()).step_by(4096) {
        block[i] = 1;
    }
    std::hint::black_box(&block);
    let after = observe_me(&mut src);

    let mb = 1024 * 1024;
    let d_private = after.private_bytes.unwrap() - before.private_bytes.unwrap();
    let d_ws = after.working_set.unwrap() - before.working_set.unwrap();
    assert!(
        d_private >= 90 * mb,
        "private grew only {} MB",
        d_private / mb
    );
    assert!(d_ws >= 90 * mb, "working set grew only {} MB", d_ws / mb);
    drop(block);
}

#[test]
fn protected_processes_are_measured_without_opening_them() {
    let mut src = WindowsMetricsSource::new();
    let all = src.observe();
    assert!(all.len() > 50, "implausibly few processes: {}", all.len());
    let system = all.iter().find(|o| o.pid == 4).expect("System listed");
    assert_eq!(system.name, "System");
    // The all-processes query needs no handle, so even the System process (which OpenProcess
    // refuses without elevation) has identity and counters.
    assert!(system.start_time.is_some_and(|t| t > 0), "{system:?}");
    assert!(system.cpu_time_100ns.is_some() && system.working_set.is_some());
    // Names are parsed from the buffer: every process carries one.
    assert!(
        all.iter().all(|o| !o.name.is_empty()),
        "a process has no name"
    );
}

#[test]
fn describe_fills_in_path_user_and_session_for_a_new_process() {
    let mut src = WindowsMetricsSource::new();
    let o = observe_me(&mut src);
    let raw = src.describe(&o);
    assert_eq!(raw.pid, std::process::id());
    assert_eq!(raw.start_time, o.start_time);
    assert!(raw.exe_path.is_some());
    assert!(raw.user.as_deref().is_some_and(|u| u.contains('\\')));
    assert!(raw.session_id.is_some());
    assert!(
        raw.command_line.is_none(),
        "the monitor never reads command lines"
    );
}

#[test]
fn logical_cpu_count_is_sane() {
    let n = WindowsMetricsSource::new().logical_cpus();
    assert!((1..=4096).contains(&n), "{n}");
}
