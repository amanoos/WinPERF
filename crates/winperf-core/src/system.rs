//! System-wide health metrics (PRD FR-009): total CPU, memory and commit, physical disk
//! utilization/queue/latency, and network throughput.
//!
//! Like the per-process sampler this is pure: the OS supplies a [`SystemObservation`], and
//! [`SystemSampler`] turns cumulative counters into rates. Anything the OS couldn't supply is
//! `Metric::Unavailable`; one broken counter never takes the others down (NFR-002).

use crate::Metric;
use crate::sampling::rate_per_sec;
use std::time::Duration;

/// Raw system readings for one tick. `None` = could not be read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SystemObservation {
    // Cumulative CPU time since boot, 100 ns ticks. `kernel` includes `idle`.
    pub cpu_idle_100ns: Option<u64>,
    pub cpu_kernel_100ns: Option<u64>,
    pub cpu_user_100ns: Option<u64>,
    // Cumulative bytes across physical network adapters.
    pub net_rx_octets: Option<u64>,
    pub net_tx_octets: Option<u64>,
    // Instantaneous.
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub commit_used_bytes: Option<u64>,
    pub commit_limit_bytes: Option<u64>,
    /// Physical disk busy percentage (all disks), 0..=100.
    pub disk_utilization_percent: Option<f64>,
    /// Outstanding requests queued on the disks.
    pub disk_queue_length: Option<f64>,
    pub disk_read_bytes_per_sec: Option<f64>,
    pub disk_write_bytes_per_sec: Option<f64>,
    /// Average time per disk transfer, milliseconds.
    pub disk_latency_ms: Option<f64>,
}

/// One tick of system health.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemSample {
    /// Percent of total CPU capacity in use, 0..=100.
    pub cpu_percent: Metric<f64>,
    pub memory_total_bytes: Metric<u64>,
    pub memory_available_bytes: Metric<u64>,
    pub commit_used_bytes: Metric<u64>,
    pub commit_limit_bytes: Metric<u64>,
    pub disk_utilization_percent: Metric<f64>,
    pub disk_queue_length: Metric<f64>,
    pub disk_read_bytes_per_sec: Metric<f64>,
    pub disk_write_bytes_per_sec: Metric<f64>,
    pub disk_latency_ms: Metric<f64>,
    pub net_rx_bytes_per_sec: Metric<f64>,
    pub net_tx_bytes_per_sec: Metric<f64>,
}

impl SystemSample {
    /// True when at least one metric has a value (an all-unavailable sample isn't worth storing).
    pub fn has_any(&self) -> bool {
        !(self.cpu_percent.is_unavailable()
            && self.memory_total_bytes.is_unavailable()
            && self.memory_available_bytes.is_unavailable()
            && self.commit_used_bytes.is_unavailable()
            && self.commit_limit_bytes.is_unavailable()
            && self.disk_utilization_percent.is_unavailable()
            && self.disk_queue_length.is_unavailable()
            && self.disk_read_bytes_per_sec.is_unavailable()
            && self.disk_write_bytes_per_sec.is_unavailable()
            && self.disk_latency_ms.is_unavailable()
            && self.net_rx_bytes_per_sec.is_unavailable()
            && self.net_tx_bytes_per_sec.is_unavailable())
    }
}

fn metric<T>(v: Option<T>) -> Metric<T> {
    v.map_or(Metric::Unavailable, Metric::Available)
}

/// Busy percentage from cumulative idle/kernel/user ticks. `kernel` includes idle time.
fn cpu_busy_percent(prev: &SystemObservation, cur: &SystemObservation) -> Option<f64> {
    let delta = |p: Option<u64>, c: Option<u64>| -> Option<u64> { c?.checked_sub(p?) };
    let idle = delta(prev.cpu_idle_100ns, cur.cpu_idle_100ns)?;
    let kernel = delta(prev.cpu_kernel_100ns, cur.cpu_kernel_100ns)?;
    let user = delta(prev.cpu_user_100ns, cur.cpu_user_100ns)?;
    let total = kernel.checked_add(user)?;
    if total == 0 {
        return None;
    }
    let busy = total.saturating_sub(idle) as f64 / total as f64 * 100.0;
    Some(busy.clamp(0.0, 100.0))
}

pub struct SystemSampler {
    prev: Option<SystemObservation>,
}

impl SystemSampler {
    pub fn new() -> Self {
        Self { prev: None }
    }

    /// Turn one observation into a sample. `elapsed` is the time since the previous observation.
    /// The first call has nothing to compare against, so CPU and network rates are unavailable.
    pub fn tick(&mut self, now: &SystemObservation, elapsed: Duration) -> SystemSample {
        let (cpu, rx, tx) = match &self.prev {
            Some(prev) => (
                cpu_busy_percent(prev, now),
                prev.net_rx_octets
                    .zip(now.net_rx_octets)
                    .and_then(|(p, c)| rate_per_sec(p, c, elapsed)),
                prev.net_tx_octets
                    .zip(now.net_tx_octets)
                    .and_then(|(p, c)| rate_per_sec(p, c, elapsed)),
            ),
            None => (None, None, None),
        };
        self.prev = Some(now.clone());
        SystemSample {
            cpu_percent: metric(cpu),
            memory_total_bytes: metric(now.memory_total_bytes),
            memory_available_bytes: metric(now.memory_available_bytes),
            commit_used_bytes: metric(now.commit_used_bytes),
            commit_limit_bytes: metric(now.commit_limit_bytes),
            disk_utilization_percent: metric(now.disk_utilization_percent),
            disk_queue_length: metric(now.disk_queue_length),
            disk_read_bytes_per_sec: metric(now.disk_read_bytes_per_sec),
            disk_write_bytes_per_sec: metric(now.disk_write_bytes_per_sec),
            disk_latency_ms: metric(now.disk_latency_ms),
            net_rx_bytes_per_sec: metric(rx),
            net_tx_bytes_per_sec: metric(tx),
        }
    }
}

impl Default for SystemSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    fn cpu(idle: u64, kernel: u64, user: u64) -> SystemObservation {
        SystemObservation {
            cpu_idle_100ns: Some(idle),
            cpu_kernel_100ns: Some(kernel),
            cpu_user_100ns: Some(user),
            ..Default::default()
        }
    }

    #[test]
    fn busy_cpu_excludes_idle_time_which_is_part_of_kernel_time() {
        let mut s = SystemSampler::new();
        s.tick(&cpu(1_000, 2_000, 1_000), SEC);
        // +40 idle, +60 kernel (includes the 40 idle), +40 user => total 100, busy 60.
        let out = s.tick(&cpu(1_040, 2_060, 1_040), SEC);
        assert_eq!(out.cpu_percent, Metric::Available(60.0));
    }

    #[test]
    fn a_fully_idle_machine_is_0_percent_and_a_saturated_one_100() {
        let mut s = SystemSampler::new();
        s.tick(&cpu(0, 0, 0), SEC);
        assert_eq!(
            s.tick(&cpu(100, 100, 0), SEC).cpu_percent,
            Metric::Available(0.0)
        );
        assert_eq!(
            s.tick(&cpu(100, 200, 100), SEC).cpu_percent,
            Metric::Available(100.0)
        );
    }

    #[test]
    fn the_first_tick_has_no_cpu_or_network_rate_but_does_report_memory() {
        let mut s = SystemSampler::new();
        let mut o = cpu(1, 2, 3);
        o.net_rx_octets = Some(10);
        o.net_tx_octets = Some(10);
        o.memory_total_bytes = Some(16_000);
        o.memory_available_bytes = Some(4_000);
        let first = s.tick(&o, SEC);
        assert_eq!(first.cpu_percent, Metric::Unavailable);
        assert_eq!(first.net_rx_bytes_per_sec, Metric::Unavailable);
        assert_eq!(first.memory_total_bytes, Metric::Available(16_000));
        assert_eq!(first.memory_available_bytes, Metric::Available(4_000));
    }

    #[test]
    fn network_throughput_is_the_counter_delta_per_second() {
        let mut s = SystemSampler::new();
        let at = |rx, tx| SystemObservation {
            net_rx_octets: Some(rx),
            net_tx_octets: Some(tx),
            ..Default::default()
        };
        s.tick(&at(1_000, 500), Duration::ZERO);
        let out = s.tick(&at(11_000, 2_500), Duration::from_secs(5));
        assert_eq!(out.net_rx_bytes_per_sec, Metric::Available(2_000.0));
        assert_eq!(out.net_tx_bytes_per_sec, Metric::Available(400.0));
    }

    #[test]
    fn counters_that_went_backwards_are_unavailable_not_negative() {
        let mut s = SystemSampler::new();
        let at = |rx| SystemObservation {
            net_rx_octets: Some(rx),
            ..Default::default()
        };
        s.tick(&at(9_000), SEC);
        assert_eq!(
            s.tick(&at(10), SEC).net_rx_bytes_per_sec,
            Metric::Unavailable
        );
        s.tick(&cpu(500, 600, 100), SEC);
        assert_eq!(
            s.tick(&cpu(10, 20, 10), SEC).cpu_percent,
            Metric::Unavailable
        );
    }

    #[test]
    fn instantaneous_disk_and_memory_values_pass_through() {
        let mut s = SystemSampler::new();
        let o = SystemObservation {
            commit_used_bytes: Some(8),
            commit_limit_bytes: Some(32),
            disk_utilization_percent: Some(37.5),
            disk_queue_length: Some(2.0),
            disk_read_bytes_per_sec: Some(1_000.0),
            disk_write_bytes_per_sec: Some(2_000.0),
            disk_latency_ms: Some(4.5),
            ..Default::default()
        };
        let out = s.tick(&o, SEC);
        assert_eq!(out.commit_used_bytes, Metric::Available(8));
        assert_eq!(out.commit_limit_bytes, Metric::Available(32));
        assert_eq!(out.disk_utilization_percent, Metric::Available(37.5));
        assert_eq!(out.disk_queue_length, Metric::Available(2.0));
        assert_eq!(out.disk_read_bytes_per_sec, Metric::Available(1_000.0));
        assert_eq!(out.disk_write_bytes_per_sec, Metric::Available(2_000.0));
        assert_eq!(out.disk_latency_ms, Metric::Available(4.5));
    }

    #[test]
    fn one_missing_metric_does_not_affect_the_others() {
        let mut s = SystemSampler::new();
        let o = SystemObservation {
            memory_total_bytes: Some(100),
            disk_utilization_percent: None, // e.g. the PDH counter is broken
            disk_queue_length: Some(1.0),
            ..Default::default()
        };
        let out = s.tick(&o, SEC);
        assert_eq!(out.disk_utilization_percent, Metric::Unavailable);
        assert_eq!(out.disk_queue_length, Metric::Available(1.0));
        assert_eq!(out.memory_total_bytes, Metric::Available(100));
    }

    #[test]
    fn an_observation_with_nothing_in_it_yields_an_empty_sample() {
        let mut s = SystemSampler::new();
        let out = s.tick(&SystemObservation::default(), SEC);
        assert!(!out.has_any());
        let o = SystemObservation {
            memory_total_bytes: Some(1),
            ..Default::default()
        };
        assert!(s.tick(&o, SEC).has_any());
    }
}
