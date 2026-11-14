//! Turning raw per-process counters into samples (PRD FR-005/FR-006/FR-007), and noticing which
//! process instances appear or disappear between ticks.
//!
//! CPU time and I/O counters are cumulative, so a rate needs two observations. The first
//! observation of an instance therefore has **no** CPU or I/O value (`Unavailable`), never 0 (A6).
//!
//! Process I/O rates come from the per-process I/O counters, which count *all* I/O a process
//! issues (files, pipes, devices, network), not just physical disk traffic. They are reported as
//! `Metric::Partial` so no consumer mistakes them for disk throughput (PRD FR-007).

use crate::{Metric, ProcessKey};
use std::collections::HashMap;
use std::time::Duration;

/// One process as seen by the cheap per-tick probe. `None` = could not be read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observation {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    /// FILETIME creation time; without it the instance has no identity and is not sampled.
    pub start_time: Option<u64>,
    /// Cumulative kernel + user CPU time in 100 ns ticks.
    pub cpu_time_100ns: Option<u64>,
    pub working_set: Option<u64>,
    pub private_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub peak_working_set: Option<u64>,
    /// Cumulative bytes read / written by the process (all I/O kinds, not only disk).
    pub io_read_bytes: Option<u64>,
    pub io_write_bytes: Option<u64>,
    /// Cumulative read / write operations.
    pub io_read_ops: Option<u64>,
    pub io_write_ops: Option<u64>,
    /// Cumulative bytes the process received / sent over the network, from per-process ETW
    /// attribution (needs administrator). `None` whenever attribution isn't running.
    pub net_rx_bytes: Option<u64>,
    pub net_tx_bytes: Option<u64>,
}

impl Observation {
    pub fn key(&self) -> Option<ProcessKey> {
        self.start_time.map(|s| ProcessKey::new(self.pid, s))
    }
}

/// One stored measurement of one process instance.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub key: ProcessKey,
    /// Percent of the whole machine (normalized by logical CPUs), 0..=100.
    pub cpu_percent: Metric<f64>,
    pub working_set: Metric<u64>,
    pub private_bytes: Metric<u64>,
    pub virtual_bytes: Metric<u64>,
    pub peak_working_set: Metric<u64>,
    /// Process-level I/O rates (bytes and operations per second). `Partial` when available:
    /// they include non-disk I/O.
    pub io_read_bytes_per_sec: Metric<f64>,
    pub io_write_bytes_per_sec: Metric<f64>,
    pub io_read_ops_per_sec: Metric<f64>,
    pub io_write_ops_per_sec: Metric<f64>,
    /// Per-process network throughput. Unlike process I/O this is attributed per PID from event
    /// tracing, so it is `Available` when computed; `Unavailable` when attribution isn't running.
    pub net_rx_bytes_per_sec: Metric<f64>,
    pub net_tx_bytes_per_sec: Metric<f64>,
}

fn metric<T>(v: Option<T>) -> Metric<T> {
    v.map_or(Metric::Unavailable, Metric::Available)
}

/// CPU use over an interval as a percentage of *total* machine capacity.
///
/// `None` when it can't be computed: zero interval, zero CPUs, or a counter that went backwards.
/// Timer jitter can briefly push the ratio above 100; the result is capped at 100.
pub fn cpu_percent(
    prev_100ns: u64,
    cur_100ns: u64,
    elapsed: Duration,
    logical_cpus: u32,
) -> Option<f64> {
    if cur_100ns < prev_100ns || elapsed.is_zero() || logical_cpus == 0 {
        return None;
    }
    let wall_ticks = elapsed.as_secs_f64() * 10_000_000.0;
    let pct = (cur_100ns - prev_100ns) as f64 / (wall_ticks * f64::from(logical_cpus)) * 100.0;
    Some(pct.min(100.0))
}

/// Per-second rate of a cumulative counter over `elapsed`. `None` for a zero interval or a
/// counter that went backwards (reset, wrap, or a different process).
pub fn rate_per_sec(prev: u64, cur: u64, elapsed: Duration) -> Option<f64> {
    if cur < prev || elapsed.is_zero() {
        return None;
    }
    Some((cur - prev) as f64 / elapsed.as_secs_f64())
}

/// Rate of a cumulative process-I/O counter, marked `Partial` (it includes non-disk I/O).
fn io_rate(prev: Option<u64>, cur: Option<u64>, elapsed: Duration) -> Metric<f64> {
    match (prev, cur) {
        (Some(p), Some(c)) => {
            rate_per_sec(p, c, elapsed).map_or(Metric::Unavailable, Metric::Partial)
        }
        _ => Metric::Unavailable,
    }
}

/// Rate of a cumulative, reliably attributed counter (network bytes).
fn attributed_rate(prev: Option<u64>, cur: Option<u64>, elapsed: Duration) -> Metric<f64> {
    match (prev, cur) {
        (Some(p), Some(c)) => {
            rate_per_sec(p, c, elapsed).map_or(Metric::Unavailable, Metric::Available)
        }
        _ => Metric::Unavailable,
    }
}

/// What one tick produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TickOutput {
    pub samples: Vec<Sample>,
    /// Instances never seen before by this sampler (first sighting, including after a restart).
    pub new: Vec<Observation>,
    /// Instances seen last tick that are no longer present (sorted).
    pub gone: Vec<ProcessKey>,
    /// Processes skipped because their creation time could not be read (access denied).
    pub unreadable: usize,
}

/// The cumulative counters remembered from the previous tick.
#[derive(Debug, Clone, Copy, Default)]
struct Prev {
    cpu: Option<u64>,
    io_read_bytes: Option<u64>,
    io_write_bytes: Option<u64>,
    io_read_ops: Option<u64>,
    io_write_ops: Option<u64>,
    net_rx: Option<u64>,
    net_tx: Option<u64>,
}

impl Prev {
    fn of(o: &Observation) -> Self {
        Self {
            cpu: o.cpu_time_100ns,
            io_read_bytes: o.io_read_bytes,
            io_write_bytes: o.io_write_bytes,
            io_read_ops: o.io_read_ops,
            io_write_ops: o.io_write_ops,
            net_rx: o.net_rx_bytes,
            net_tx: o.net_tx_bytes,
        }
    }
}

pub struct Sampler {
    logical_cpus: u32,
    /// Instances seen last tick -> their cumulative counters then.
    known: HashMap<ProcessKey, Prev>,
}

impl Sampler {
    pub fn new(logical_cpus: u32) -> Self {
        Self {
            logical_cpus,
            known: HashMap::new(),
        }
    }

    /// Process one round of observations taken `elapsed` after the previous round.
    pub fn tick(&mut self, observations: &[Observation], elapsed: Duration) -> TickOutput {
        let mut out = TickOutput::default();
        let mut current: HashMap<ProcessKey, Prev> = HashMap::with_capacity(observations.len());

        for o in observations {
            let Some(key) = o.key() else {
                out.unreadable += 1;
                continue;
            };
            let prev = self.known.get(&key).copied();
            let before = prev.unwrap_or_default();
            let cpu = match (before.cpu, o.cpu_time_100ns) {
                (Some(p), Some(c)) => cpu_percent(p, c, elapsed, self.logical_cpus),
                _ => None,
            };
            if prev.is_none() {
                out.new.push(o.clone());
            }
            out.samples.push(Sample {
                key,
                cpu_percent: metric(cpu),
                working_set: metric(o.working_set),
                private_bytes: metric(o.private_bytes),
                virtual_bytes: metric(o.virtual_bytes),
                peak_working_set: metric(o.peak_working_set),
                io_read_bytes_per_sec: io_rate(before.io_read_bytes, o.io_read_bytes, elapsed),
                io_write_bytes_per_sec: io_rate(before.io_write_bytes, o.io_write_bytes, elapsed),
                io_read_ops_per_sec: io_rate(before.io_read_ops, o.io_read_ops, elapsed),
                io_write_ops_per_sec: io_rate(before.io_write_ops, o.io_write_ops, elapsed),
                net_rx_bytes_per_sec: attributed_rate(before.net_rx, o.net_rx_bytes, elapsed),
                net_tx_bytes_per_sec: attributed_rate(before.net_tx, o.net_tx_bytes, elapsed),
            });
            current.insert(key, Prev::of(o));
        }

        out.gone = self
            .known
            .keys()
            .filter(|k| !current.contains_key(k))
            .copied()
            .collect();
        out.gone.sort();
        self.known = current;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    fn obs(pid: u32, start: u64, cpu: u64) -> Observation {
        Observation {
            pid,
            start_time: Some(start),
            cpu_time_100ns: Some(cpu),
            working_set: Some(1000),
            private_bytes: Some(2000),
            virtual_bytes: Some(3000),
            peak_working_set: Some(4000),
            ..Default::default()
        }
    }

    fn with_io(mut o: Observation, rb: u64, wb: u64, ro: u64, wo: u64) -> Observation {
        o.io_read_bytes = Some(rb);
        o.io_write_bytes = Some(wb);
        o.io_read_ops = Some(ro);
        o.io_write_ops = Some(wo);
        o
    }

    #[test]
    fn one_second_of_cpu_on_a_4_cpu_machine_is_25_percent() {
        assert_eq!(cpu_percent(0, 10_000_000, SEC, 4), Some(25.0));
    }

    #[test]
    fn half_a_second_of_cpu_over_two_seconds_on_1_cpu_is_25_percent() {
        assert_eq!(
            cpu_percent(5, 5_000_005, Duration::from_secs(2), 1),
            Some(25.0)
        );
    }

    #[test]
    fn jitter_above_100_is_capped() {
        assert_eq!(cpu_percent(0, 10_500_000, SEC, 1), Some(100.0));
    }

    #[test]
    fn impossible_inputs_yield_none() {
        assert_eq!(cpu_percent(10, 5, SEC, 4), None, "counter went backwards");
        assert_eq!(cpu_percent(0, 5, Duration::ZERO, 4), None);
        assert_eq!(cpu_percent(0, 5, SEC, 0), None);
    }

    #[test]
    fn rates_divide_the_delta_by_the_interval() {
        assert_eq!(rate_per_sec(100, 1100, Duration::from_secs(5)), Some(200.0));
        assert_eq!(rate_per_sec(7, 7, SEC), Some(0.0));
        assert_eq!(rate_per_sec(10, 5, SEC), None, "counter went backwards");
        assert_eq!(rate_per_sec(0, 5, Duration::ZERO), None);
    }

    #[test]
    fn first_sample_has_no_cpu_value_not_zero() {
        let mut s = Sampler::new(4);
        let out = s.tick(&[obs(1, 100, 5_000_000)], SEC);
        assert_eq!(out.samples.len(), 1);
        assert_eq!(out.samples[0].cpu_percent, Metric::Unavailable);
        assert_eq!(out.samples[0].working_set, Metric::Available(1000));
        assert_eq!(out.new.len(), 1);
    }

    #[test]
    fn second_sample_computes_cpu_from_the_delta() {
        let mut s = Sampler::new(4);
        s.tick(&[obs(1, 100, 5_000_000)], SEC);
        let out = s.tick(&[obs(1, 100, 15_000_000)], SEC); // +1 s CPU over 1 s on 4 cpus
        assert_eq!(out.samples[0].cpu_percent, Metric::Available(25.0));
        assert!(out.new.is_empty() && out.gone.is_empty());
    }

    #[test]
    fn io_rates_are_partial_and_need_two_observations() {
        let mut s = Sampler::new(4);
        let first = s.tick(&[with_io(obs(1, 100, 0), 1_000, 2_000, 10, 20)], SEC);
        assert_eq!(first.samples[0].io_read_bytes_per_sec, Metric::Unavailable);
        assert_eq!(first.samples[0].io_write_ops_per_sec, Metric::Unavailable);

        let second = s.tick(
            &[with_io(obs(1, 100, 0), 11_000, 7_000, 50, 25)],
            Duration::from_secs(5),
        );
        let m = &second.samples[0];
        // Partial, not Available: process I/O includes non-disk traffic.
        assert_eq!(m.io_read_bytes_per_sec, Metric::Partial(2_000.0));
        assert_eq!(m.io_write_bytes_per_sec, Metric::Partial(1_000.0));
        assert_eq!(m.io_read_ops_per_sec, Metric::Partial(8.0));
        assert_eq!(m.io_write_ops_per_sec, Metric::Partial(1.0));
        assert!(m.io_read_bytes_per_sec.reliable().is_none());
    }

    fn with_net(mut o: Observation, rx: u64, tx: u64) -> Observation {
        o.net_rx_bytes = Some(rx);
        o.net_tx_bytes = Some(tx);
        o
    }

    #[test]
    fn network_rates_are_available_and_need_two_observations() {
        let mut s = Sampler::new(4);
        let first = s.tick(&[with_net(obs(1, 100, 0), 1_000, 500)], SEC);
        assert_eq!(first.samples[0].net_rx_bytes_per_sec, Metric::Unavailable);
        assert_eq!(first.samples[0].net_tx_bytes_per_sec, Metric::Unavailable);

        let second = s.tick(
            &[with_net(obs(1, 100, 0), 11_000, 500)],
            Duration::from_secs(5),
        );
        let m = &second.samples[0];
        // Reliable (per-PID ETW attribution), unlike process I/O which is only Partial.
        assert_eq!(m.net_rx_bytes_per_sec, Metric::Available(2_000.0));
        assert_eq!(m.net_tx_bytes_per_sec, Metric::Available(0.0));
    }

    #[test]
    fn without_attribution_network_rates_are_unavailable_not_zero() {
        let mut s = Sampler::new(4);
        s.tick(&[obs(1, 100, 0)], SEC); // net_* = None: collector not running
        let out = s.tick(&[obs(1, 100, 1)], SEC);
        assert_eq!(out.samples[0].net_rx_bytes_per_sec, Metric::Unavailable);
        assert_eq!(out.samples[0].net_tx_bytes_per_sec, Metric::Unavailable);
    }

    #[test]
    fn a_reused_pid_does_not_inherit_the_old_instances_network_traffic() {
        // PID 7 had 1 GB received. A new process takes the PID; per-PID totals keep counting, but
        // the new instance's first observation carries no rate and later deltas start from its own
        // first observation.
        let mut s = Sampler::new(4);
        s.tick(&[with_net(obs(7, 100, 0), 1_000_000_000, 0)], SEC);
        let reborn = s.tick(&[with_net(obs(7, 200, 0), 1_000_000_500, 0)], SEC);
        assert_eq!(reborn.samples[0].net_rx_bytes_per_sec, Metric::Unavailable);
        let next = s.tick(&[with_net(obs(7, 200, 0), 1_000_001_500, 0)], SEC);
        assert_eq!(
            next.samples[0].net_rx_bytes_per_sec,
            Metric::Available(1_000.0)
        );
    }

    #[test]
    fn an_idle_process_reads_zero_io_not_unavailable() {
        let mut s = Sampler::new(4);
        s.tick(&[with_io(obs(1, 100, 0), 500, 500, 5, 5)], SEC);
        let out = s.tick(&[with_io(obs(1, 100, 0), 500, 500, 5, 5)], SEC);
        assert_eq!(out.samples[0].io_write_bytes_per_sec, Metric::Partial(0.0));
    }

    #[test]
    fn unreadable_io_counters_stay_unavailable() {
        let mut s = Sampler::new(4);
        s.tick(&[obs(1, 100, 0)], SEC); // no io counters at all
        let out = s.tick(&[obs(1, 100, 1)], SEC);
        assert_eq!(out.samples[0].io_read_bytes_per_sec, Metric::Unavailable);
        assert_eq!(out.samples[0].io_write_ops_per_sec, Metric::Unavailable);
    }

    #[test]
    fn a_decreasing_io_counter_yields_unavailable() {
        let mut s = Sampler::new(4);
        s.tick(&[with_io(obs(1, 100, 0), 9_000, 9_000, 9, 9)], SEC);
        let out = s.tick(&[with_io(obs(1, 100, 0), 100, 100, 1, 1)], SEC);
        assert_eq!(out.samples[0].io_read_bytes_per_sec, Metric::Unavailable);
    }

    #[test]
    fn counters_that_cannot_be_read_stay_unavailable() {
        let mut s = Sampler::new(4);
        let mut o = obs(1, 100, 1);
        o.private_bytes = None;
        o.cpu_time_100ns = None;
        let out = s.tick(&[o], SEC);
        assert_eq!(out.samples[0].private_bytes, Metric::Unavailable);
        assert_eq!(out.samples[0].cpu_percent, Metric::Unavailable);
        assert_eq!(out.samples[0].working_set, Metric::Available(1000));
    }

    #[test]
    fn a_reused_pid_is_a_new_instance_and_the_old_one_is_gone() {
        let mut s = Sampler::new(4);
        s.tick(&[with_io(obs(50, 1000, 100), 5, 5, 5, 5)], SEC);
        let out = s.tick(&[with_io(obs(50, 2000, 100), 99, 99, 9, 9)], SEC);
        assert_eq!(out.new.len(), 1);
        assert_eq!(out.new[0].key(), Some(ProcessKey::new(50, 2000)));
        assert_eq!(out.gone, vec![ProcessKey::new(50, 1000)]);
        // The reborn instance starts fresh: no delta against the dead one.
        assert_eq!(out.samples[0].cpu_percent, Metric::Unavailable);
        assert_eq!(out.samples[0].io_read_bytes_per_sec, Metric::Unavailable);
    }

    #[test]
    fn processes_without_a_start_time_are_counted_but_not_sampled() {
        let mut s = Sampler::new(4);
        let denied = Observation {
            pid: 4,
            name: "System".into(),
            ..Default::default()
        };
        let out = s.tick(&[denied, obs(1, 100, 1)], SEC);
        assert_eq!(out.unreadable, 1);
        assert_eq!(out.samples.len(), 1);
    }

    #[test]
    fn disappearing_processes_are_reported_once_and_sorted() {
        let mut s = Sampler::new(4);
        s.tick(&[obs(9, 1, 0), obs(3, 1, 0), obs(5, 1, 0)], SEC);
        let out = s.tick(&[obs(5, 1, 0)], SEC);
        assert_eq!(out.gone, vec![ProcessKey::new(3, 1), ProcessKey::new(9, 1)]);
        assert!(s.tick(&[obs(5, 1, 0)], SEC).gone.is_empty());
    }

    #[test]
    fn cpu_is_not_computed_across_a_gap_in_the_counter() {
        // First sighting had an unreadable CPU counter, second has one: still no delta available.
        let mut s = Sampler::new(2);
        let mut first = obs(1, 100, 0);
        first.cpu_time_100ns = None;
        s.tick(&[first], SEC);
        let out = s.tick(&[obs(1, 100, 10_000_000)], SEC);
        assert_eq!(out.samples[0].cpu_percent, Metric::Unavailable);
        let out = s.tick(&[obs(1, 100, 20_000_000)], SEC);
        assert_eq!(out.samples[0].cpu_percent, Metric::Available(50.0));
    }
}
