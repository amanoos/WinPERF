//! `winperf system now`: one-shot system-wide health (CPU, memory, disk, network).

use std::io::{self, Write};
use std::time::{Duration, Instant};
use winperf_core::Metric;
use winperf_core::system::{SystemObservation, SystemSample, SystemSampler};

const KIB: f64 = 1024.0;
const MIB: f64 = KIB * 1024.0;
const GIB: f64 = MIB * 1024.0;

fn bytes(b: u64) -> String {
    let b = b as f64;
    if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else {
        format!("{:.0} MiB", b / MIB)
    }
}

fn rate(v: f64) -> String {
    if v >= MIB {
        format!("{:.1} MB/s", v / MIB)
    } else if v >= KIB {
        format!("{:.0} KB/s", v / KIB)
    } else {
        format!("{v:.0} B/s")
    }
}

fn or_na<T>(m: &Metric<T>, f: impl Fn(&T) -> String) -> String {
    m.value().map_or_else(|| "n/a".to_string(), f)
}

/// Human-readable report. Unavailable metrics print `n/a`, never a misleading 0.
pub fn format_sample(s: &SystemSample) -> String {
    let memory = match (
        s.memory_total_bytes.value(),
        s.memory_available_bytes.value(),
    ) {
        (Some(total), Some(avail)) if *total > 0 => {
            let used = total.saturating_sub(*avail);
            format!(
                "{} used of {} ({:.0}%), {} available",
                bytes(used),
                bytes(*total),
                used as f64 / *total as f64 * 100.0,
                bytes(*avail)
            )
        }
        _ => "n/a".into(),
    };
    let commit = match (s.commit_used_bytes.value(), s.commit_limit_bytes.value()) {
        (Some(used), Some(limit)) if *limit > 0 => format!(
            "{} of {} ({:.0}%)",
            bytes(*used),
            bytes(*limit),
            *used as f64 / *limit as f64 * 100.0
        ),
        _ => "n/a".into(),
    };
    format!(
        "CPU:      {}\n\
         Memory:   {}\n\
         Commit:   {}\n\
         Disk:     busy {}, queue {}, read {}, write {}, latency {}\n\
         Network:  rx {}, tx {} (physical adapters)\n",
        or_na(&s.cpu_percent, |v| format!("{v:.1}%")),
        memory,
        commit,
        or_na(&s.disk_utilization_percent, |v| format!("{v:.1}%")),
        or_na(&s.disk_queue_length, |v| format!("{v:.1}")),
        or_na(&s.disk_read_bytes_per_sec, |v| rate(*v)),
        or_na(&s.disk_write_bytes_per_sec, |v| rate(*v)),
        or_na(&s.disk_latency_ms, |v| format!("{v:.1} ms")),
        or_na(&s.net_rx_bytes_per_sec, |v| rate(*v)),
        or_na(&s.net_tx_bytes_per_sec, |v| rate(*v)),
    )
}

/// Take two readings `wait` apart (rates need a baseline) and turn them into a sample.
pub fn collect(mut observe: impl FnMut() -> SystemObservation, wait: Duration) -> SystemSample {
    let mut sampler = SystemSampler::new();
    let started = Instant::now();
    sampler.tick(&observe(), Duration::ZERO);
    std::thread::sleep(wait);
    let second = observe();
    sampler.tick(&second, started.elapsed())
}

pub fn now(
    observe: impl FnMut() -> SystemObservation,
    wait: Duration,
    out: &mut impl Write,
) -> io::Result<()> {
    out.write_all(format_sample(&collect(observe, wait)).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> SystemSample {
        SystemSample {
            cpu_percent: Metric::Available(12.34),
            memory_total_bytes: Metric::Available(16 * 1024 * 1024 * 1024),
            memory_available_bytes: Metric::Available(4 * 1024 * 1024 * 1024),
            commit_used_bytes: Metric::Available(10 * 1024 * 1024 * 1024),
            commit_limit_bytes: Metric::Available(40 * 1024 * 1024 * 1024),
            disk_utilization_percent: Metric::Available(7.5),
            disk_queue_length: Metric::Available(1.0),
            disk_read_bytes_per_sec: Metric::Available(2.0 * MIB),
            disk_write_bytes_per_sec: Metric::Available(512.0),
            disk_latency_ms: Metric::Available(0.8),
            net_rx_bytes_per_sec: Metric::Available(150.0 * KIB),
            net_tx_bytes_per_sec: Metric::Available(0.0),
        }
    }

    #[test]
    fn report_shows_every_metric_in_readable_units() {
        let t = format_sample(&full());
        assert!(t.contains("CPU:      12.3%"), "{t}");
        assert!(
            t.contains("12.0 GiB used of 16.0 GiB (75%), 4.0 GiB available"),
            "{t}"
        );
        assert!(t.contains("10.0 GiB of 40.0 GiB (25%)"), "{t}");
        assert!(
            t.contains("busy 7.5%, queue 1.0, read 2.0 MB/s, write 512 B/s, latency 0.8 ms"),
            "{t}"
        );
        assert!(t.contains("rx 150 KB/s, tx 0 B/s"), "{t}");
    }

    #[test]
    fn unavailable_metrics_print_na_not_zero() {
        let mut s = full();
        s.cpu_percent = Metric::Unavailable;
        s.disk_utilization_percent = Metric::Unavailable;
        s.memory_total_bytes = Metric::Unavailable;
        s.net_rx_bytes_per_sec = Metric::Unavailable;
        let t = format_sample(&s);
        assert!(t.contains("CPU:      n/a"), "{t}");
        assert!(t.contains("Memory:   n/a"), "{t}");
        assert!(t.contains("busy n/a, queue 1.0"), "{t}");
        assert!(t.contains("rx n/a, tx 0 B/s"), "{t}");
    }

    #[test]
    fn collect_computes_rates_from_two_readings() {
        let mut calls = 0u64;
        let sample = collect(
            || {
                calls += 1;
                SystemObservation {
                    cpu_idle_100ns: Some(calls * 50),
                    cpu_kernel_100ns: Some(calls * 100),
                    cpu_user_100ns: Some(calls * 100),
                    ..Default::default()
                }
            },
            Duration::from_millis(5),
        );
        // Between readings: idle +50, kernel +100, user +100 => 75% busy.
        assert_eq!(sample.cpu_percent, Metric::Available(75.0));
    }
}
