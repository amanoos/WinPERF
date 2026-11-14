//! Live checks of the system-wide source (T12): every metric present, and independent of the others.

use std::time::{Duration, Instant};
use winperf_core::Metric;
use winperf_core::system::{SystemSample, SystemSampler};
use winperf_windows::{DiskCounterPaths, WindowsSystemSource};

/// Two readings ~1.2 s apart, converted to a sample (so rates exist).
fn sample_twice(src: &mut WindowsSystemSource) -> SystemSample {
    let mut sampler = SystemSampler::new();
    let t0 = Instant::now();
    sampler.tick(&src.observe(), Duration::ZERO);
    std::thread::sleep(Duration::from_millis(1200));
    let second = src.observe();
    sampler.tick(&second, t0.elapsed())
}

fn bogus() -> String {
    r"\NoSuchObject(_Total)\No Such Counter".to_string()
}

#[test]
fn every_metric_is_reported_on_a_normal_machine() {
    let mut src = WindowsSystemSource::new();
    assert!(
        src.disk_counters_available(),
        "PDH query could not be opened"
    );
    let s = sample_twice(&mut src);

    let Metric::Available(cpu) = s.cpu_percent else {
        panic!("cpu unavailable: {:?}", s.cpu_percent)
    };
    assert!((0.0..=100.0).contains(&cpu), "cpu {cpu}");

    let (Metric::Available(total), Metric::Available(avail)) =
        (s.memory_total_bytes, s.memory_available_bytes)
    else {
        panic!("memory unavailable")
    };
    assert!(total >= 1 << 30, "total memory {total}");
    assert!(avail > 0 && avail <= total, "available {avail} of {total}");

    let (Metric::Available(used), Metric::Available(limit)) =
        (s.commit_used_bytes, s.commit_limit_bytes)
    else {
        panic!("commit unavailable")
    };
    assert!(used > 0 && limit >= used, "commit {used} / {limit}");

    let Metric::Available(util) = s.disk_utilization_percent else {
        panic!("disk utilization unavailable")
    };
    assert!((0.0..=100.0).contains(&util), "disk util {util}");
    assert!(matches!(s.disk_queue_length, Metric::Available(q) if q >= 0.0));
    assert!(matches!(s.disk_read_bytes_per_sec, Metric::Available(v) if v >= 0.0));
    assert!(matches!(s.disk_write_bytes_per_sec, Metric::Available(v) if v >= 0.0));
    assert!(matches!(s.disk_latency_ms, Metric::Available(v) if v >= 0.0));

    assert!(matches!(s.net_rx_bytes_per_sec, Metric::Available(v) if v >= 0.0));
    assert!(matches!(s.net_tx_bytes_per_sec, Metric::Available(v) if v >= 0.0));
}

#[test]
fn a_broken_counter_path_makes_only_that_metric_unavailable() {
    let paths = DiskCounterPaths {
        latency_seconds: bogus(),
        ..DiskCounterPaths::default()
    };
    let mut src = WindowsSystemSource::with_disk_counters(&paths);
    let s = sample_twice(&mut src);

    assert_eq!(s.disk_latency_ms, Metric::Unavailable, "the broken counter");
    // Everything else keeps working.
    assert!(matches!(s.disk_utilization_percent, Metric::Available(_)));
    assert!(matches!(s.disk_queue_length, Metric::Available(_)));
    assert!(matches!(s.disk_read_bytes_per_sec, Metric::Available(_)));
    assert!(matches!(s.cpu_percent, Metric::Available(_)));
    assert!(matches!(s.memory_total_bytes, Metric::Available(_)));
}

#[test]
fn with_every_disk_counter_broken_cpu_memory_and_network_still_work() {
    let paths = DiskCounterPaths {
        idle_time: bogus(),
        queue_length: bogus(),
        read_bytes_per_sec: bogus(),
        write_bytes_per_sec: bogus(),
        latency_seconds: bogus(),
    };
    let mut src = WindowsSystemSource::with_disk_counters(&paths);
    let s = sample_twice(&mut src);

    for m in [
        s.disk_utilization_percent,
        s.disk_queue_length,
        s.disk_read_bytes_per_sec,
        s.disk_write_bytes_per_sec,
        s.disk_latency_ms,
    ] {
        assert_eq!(m, Metric::Unavailable);
    }
    assert!(matches!(s.cpu_percent, Metric::Available(_)));
    assert!(matches!(s.memory_available_bytes, Metric::Available(_)));
    assert!(matches!(s.net_rx_bytes_per_sec, Metric::Available(_)));
    assert!(s.has_any());
}

#[test]
fn network_totals_never_decrease() {
    let mut src = WindowsSystemSource::new();
    let mut last = (0u64, 0u64);
    for _ in 0..4 {
        let o = src.observe();
        let rx = o.net_rx_octets.expect("network counters readable");
        let tx = o.net_tx_octets.expect("network counters readable");
        assert!(
            rx >= last.0 && tx >= last.1,
            "went backwards: {last:?} -> ({rx},{tx})"
        );
        last = (rx, tx);
        std::thread::sleep(Duration::from_millis(100));
    }
}
