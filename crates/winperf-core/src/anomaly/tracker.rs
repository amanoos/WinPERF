//! Turns each tick's batch into anomaly changes: sums each metric per executable (the baseline
//! subject), hands the totals to a level detector per metric, feeds every instance's private
//! memory to the leak detector, weighs what they find against the state of the system, and
//! follows each anomaly through its life (raised, updated while it lasts, resolved when it ends).
//!
//! The tracker only ever sees baselines the caller considers usable (confidence above
//! Insufficient) and can be switched off, which is how profiling mode holds detection back.

use super::leak::{self, LeakDetection, LeakDetector, LeakReading};
use super::level::{self, Detection, LevelDetector, Reading, deviation_percent};
use super::rules::{LeakRule, LevelRule};
use super::severity::assess;
use super::{
    AnomalyChange, AnomalyEvent, AnomalyKind, BaselineSet, Phase, Sensitivities, Severity,
    SystemHealth, resource_of,
};
use crate::ProcessKey;
use crate::config::Resource;
use crate::engine::TickBatch;
use crate::profiler::baseline::BaselineMetric;
use crate::sampling::Sample;
use crate::system::SystemSample;
use std::collections::HashMap;

const METRICS: usize = BaselineMetric::ALL.len();

/// Smallest growth rate (bytes/hour) used as the denominator of a leak's deviation, so a zero
/// baseline growth does not make the figure explode.
const GROWTH_FLOOR_PER_HOUR: f64 = 1024.0 * 1024.0;

/// An anomaly that is going on is re-reported at most this often (sooner if it gets more severe).
const UPDATE_EVERY_MS: i64 = 30_000;

struct ProcInfo {
    /// Lower-cased executable path: matches `executables.path_key` and the baseline subject.
    subject: String,
    name: String,
    exe_path: String,
}

/// What the tracker last reported about an active anomaly.
struct Active {
    last_reported_ms: i64,
    severity: Severity,
}

pub struct AnomalyTracker {
    levels: Vec<LevelDetector>,
    leak: LeakDetector,
    procs: HashMap<ProcessKey, ProcInfo>,
    baselines: BaselineSet,
    enabled: bool,
    active: HashMap<String, Active>,
    last_ts_ms: i64,
}

/// One subject's per-metric totals for a tick.
struct Total<'a> {
    info: &'a ProcInfo,
    sum: [f64; METRICS],
    seen: [bool; METRICS],
    /// The instance contributing the most to each metric, with its contribution.
    top: [(f64, ProcessKey); METRICS],
}

/// The value of `metric` in a sample, if it was measured.
fn value_of(s: &Sample, metric: BaselineMetric) -> Option<f64> {
    match metric {
        BaselineMetric::Cpu => s.cpu_percent.value().copied(),
        BaselineMetric::Memory => s.working_set.value().map(|v| *v as f64),
        BaselineMetric::DiskRead => s.io_read_bytes_per_sec.value().copied(),
        BaselineMetric::DiskWrite => s.io_write_bytes_per_sec.value().copied(),
        BaselineMetric::NetRx => s.net_rx_bytes_per_sec.value().copied(),
        BaselineMetric::NetTx => s.net_tx_bytes_per_sec.value().copied(),
    }
}

impl AnomalyTracker {
    pub fn new(sensitivities: Sensitivities) -> Self {
        let levels = BaselineMetric::ALL
            .iter()
            .map(|m| {
                let s = sensitivities.for_resource(resource_of(*m));
                LevelDetector::new(LevelRule::new(*m, s))
            })
            .collect();
        Self {
            levels,
            leak: LeakDetector::new(LeakRule::new(sensitivities.memory)),
            procs: HashMap::new(),
            baselines: BaselineSet::new(),
            enabled: true,
            active: HashMap::new(),
            last_ts_ms: 0,
        }
    }

    /// Replace the baselines. Callers pass only usable ones.
    pub fn set_baselines(&mut self, baselines: BaselineSet) {
        self.baselines = baselines;
    }

    /// Pause or resume detection. Pausing forgets any episode in progress (so resuming starts
    /// every clock from zero) and resolves the anomalies that were active. Process tracking
    /// continues either way.
    pub fn set_enabled(&mut self, enabled: bool) -> Vec<AnomalyChange> {
        let mut changes = Vec::new();
        if !enabled && self.enabled {
            let mut ended: Vec<String> = Vec::new();
            for d in &mut self.levels {
                ended.extend(d.reset().iter().map(level_key));
            }
            ended.extend(self.leak.reset().iter().map(leak_key));
            for key in ended {
                if self.active.remove(&key).is_some() {
                    changes.push(AnomalyChange::Resolved {
                        key,
                        ts_ms: self.last_ts_ms,
                    });
                }
            }
        }
        self.enabled = enabled;
        changes
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Anomalies currently active.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Subjects with a usable CPU baseline (a rough size of what is being watched).
    pub fn baseline_count(&self) -> usize {
        self.baselines.subjects(BaselineMetric::Cpu)
    }

    pub fn ingest(&mut self, batch: &TickBatch) -> Vec<AnomalyChange> {
        self.last_ts_ms = batch.ts_ms;
        for raw in &batch.new {
            if let (Some(start), Some(path)) = (raw.start_time, raw.exe_path.as_ref()) {
                let exe_path = path.to_string_lossy().into_owned();
                self.procs.insert(
                    ProcessKey::new(raw.pid, start),
                    ProcInfo {
                        subject: exe_path.to_lowercase(),
                        name: raw.name.clone(),
                        exe_path,
                    },
                );
            }
        }

        let mut changes = Vec::new();
        if self.enabled {
            let system = batch.system.as_ref();
            let health = system_health(system);
            for d in self.detect_levels(batch) {
                let make = |held: Severity| level_event(&d, health, system, held);
                self.follow(level_key(&d), d.phase, d.ts_ms, make, &mut changes);
            }
            for d in self.detect_leaks(batch) {
                let make = |held: Severity| leak_event(&d, health, system, held);
                self.follow(leak_key(&d), d.phase, d.ts_ms, make, &mut changes);
            }
        }

        for key in &batch.gone {
            self.procs.remove(key);
        }
        changes
    }

    /// Turn one detection into the right change for its anomaly: a new event, an update (when it
    /// got worse or enough time has passed), or its resolution. `make` builds the event given the
    /// highest severity reached so far, which an active anomaly never drops below.
    fn follow(
        &mut self,
        key: String,
        phase: Phase,
        ts_ms: i64,
        make: impl Fn(Severity) -> AnomalyEvent,
        changes: &mut Vec<AnomalyChange>,
    ) {
        match phase {
            Phase::Started => {
                let event = make(Severity::Informational);
                self.active.insert(
                    key.clone(),
                    Active {
                        last_reported_ms: ts_ms,
                        severity: event.severity,
                    },
                );
                changes.push(AnomalyChange::Raised { key, event });
            }
            Phase::Ongoing => {
                let Some(active) = self.active.get_mut(&key) else {
                    return;
                };
                let event = make(active.severity);
                let worse = event.severity > active.severity;
                if worse || ts_ms - active.last_reported_ms >= UPDATE_EVERY_MS {
                    active.severity = event.severity;
                    active.last_reported_ms = ts_ms;
                    changes.push(AnomalyChange::Updated { key, event });
                }
            }
            Phase::Ended => {
                if self.active.remove(&key).is_some() {
                    changes.push(AnomalyChange::Resolved { key, ts_ms });
                }
            }
        }
    }

    fn detect_levels(&mut self, batch: &TickBatch) -> Vec<Detection> {
        let mut totals: HashMap<&str, Total<'_>> = HashMap::new();
        for s in &batch.samples {
            let Some(info) = self.procs.get(&s.key) else {
                continue;
            };
            let t = totals.entry(info.subject.as_str()).or_insert(Total {
                info,
                sum: [0.0; METRICS],
                seen: [false; METRICS],
                top: [(f64::MIN, s.key); METRICS],
            });
            for (i, metric) in BaselineMetric::ALL.iter().enumerate() {
                let Some(v) = value_of(s, *metric) else {
                    continue;
                };
                t.seen[i] = true;
                t.sum[i] += v;
                if v > t.top[i].0 {
                    t.top[i] = (v, s.key);
                }
            }
        }

        let no_baselines = HashMap::new();
        let mut found = Vec::new();
        for (i, metric) in BaselineMetric::ALL.iter().enumerate() {
            let readings: Vec<Reading<'_>> = totals
                .iter()
                .filter(|(_, t)| t.seen[i])
                .map(|(subject, t)| Reading {
                    subject,
                    value: t.sum[i],
                    top: t.top[i].1,
                    name: &t.info.name,
                    exe_path: &t.info.exe_path,
                })
                .collect();
            let baselines = self.baselines.metric(*metric).unwrap_or(&no_baselines);
            found.extend(self.levels[i].observe_tick(batch.ts_ms, &readings, baselines));
        }
        found
    }

    fn detect_leaks(&mut self, batch: &TickBatch) -> Vec<LeakDetection> {
        let readings: Vec<LeakReading<'_>> = batch
            .samples
            .iter()
            .filter_map(|s| {
                let private = *s.private_bytes.value()? as f64;
                let info = self.procs.get(&s.key)?;
                let baseline = self.baselines.get(BaselineMetric::Memory, &info.subject)?;
                Some(LeakReading {
                    key: s.key,
                    private_bytes: private,
                    name: &info.name,
                    exe_path: &info.exe_path,
                    baseline,
                })
            })
            .collect();
        self.leak.observe_tick(batch.ts_ms, &readings)
    }
}

fn level_key(d: &Detection) -> String {
    format!("level|{}|{}", d.rule.metric.as_str(), d.subject)
}

fn leak_key(d: &LeakDetection) -> String {
    format!("leak|{}", d.key)
}

fn system_health(system: Option<&SystemSample>) -> SystemHealth {
    let Some(s) = system else {
        return SystemHealth::default();
    };
    let memory_percent = match (
        s.memory_total_bytes.value(),
        s.memory_available_bytes.value(),
    ) {
        (Some(&total), Some(&avail)) if total > 0 => {
            Some((1.0 - avail.min(total) as f64 / total as f64) * 100.0)
        }
        _ => None,
    };
    SystemHealth {
        cpu_percent: s.cpu_percent.value().copied(),
        memory_percent,
        disk_percent: s.disk_utilization_percent.value().copied(),
    }
}

/// The process's share of what the whole system is doing with this metric, percent. For CPU that
/// is its own use (already a percent of the machine); for memory, of physical memory; for disk and
/// network, of the system's traffic in the same direction.
fn level_share(metric: BaselineMetric, current: f64, system: Option<&SystemSample>) -> Option<f64> {
    let of = |total: f64| (total > 0.0).then(|| current / total * 100.0);
    let s = system?;
    match metric {
        BaselineMetric::Cpu => Some(current),
        BaselineMetric::Memory => of(*s.memory_total_bytes.value()? as f64),
        BaselineMetric::DiskRead => of(*s.disk_read_bytes_per_sec.value()?),
        BaselineMetric::DiskWrite => of(*s.disk_write_bytes_per_sec.value()?),
        BaselineMetric::NetRx => of(*s.net_rx_bytes_per_sec.value()?),
        BaselineMetric::NetTx => of(*s.net_tx_bytes_per_sec.value()?),
    }
}

/// Append the impact sentence, and note when the severity is held at an earlier, higher level.
fn with_impact(explanation: String, reason: &str, assessed: Severity, held: Severity) -> String {
    if held > assessed {
        format!(
            "{explanation} Impact: {reason} Severity stays at {} because it was that high \
             earlier in this episode.",
            held.label()
        )
    } else {
        format!("{explanation} Impact: {reason}")
    }
}

fn level_event(
    d: &Detection,
    health: SystemHealth,
    system: Option<&SystemSample>,
    held: Severity,
) -> AnomalyEvent {
    let resource = resource_of(d.rule.metric);
    let share = level_share(d.rule.metric, d.current, system);
    let assessed = assess(resource, share, &health);
    AnomalyEvent {
        detected_ts_ms: d.ts_ms,
        pid: d.top.pid,
        start_time: d.top.start_time,
        process_name: d.name.clone(),
        exe_path: d.exe_path.clone(),
        resource,
        kind: AnomalyKind::Deviation,
        current: d.current,
        baseline: d.baseline.median,
        deviation_pct: deviation_percent(d.current, d.baseline.median, d.rule.baseline_floor()),
        duration_ms: d.duration_ms,
        severity: assessed.severity.max(held),
        system: health,
        impact: assessed.impact,
        baseline_window_hours: d.baseline.window_hours,
        baseline_confidence: d.baseline.confidence,
        explanation: with_impact(level::explain(d), &assessed.reason, assessed.severity, held),
    }
}

fn leak_event(
    d: &LeakDetection,
    health: SystemHealth,
    system: Option<&SystemSample>,
    held: Severity,
) -> AnomalyEvent {
    let share = level_share(BaselineMetric::Memory, d.current_bytes, system);
    let assessed = assess(Resource::Memory, share, &health);
    AnomalyEvent {
        detected_ts_ms: d.ts_ms,
        pid: d.key.pid,
        start_time: d.key.start_time,
        process_name: d.name.clone(),
        exe_path: d.exe_path.clone(),
        resource: Resource::Memory,
        kind: AnomalyKind::MemoryGrowth,
        current: d.rate_per_hour,
        baseline: d.usual_rate_per_hour,
        deviation_pct: (d.rate_per_hour / d.usual_rate_per_hour.max(GROWTH_FLOOR_PER_HOUR) - 1.0)
            * 100.0,
        duration_ms: d.span_ms,
        severity: assessed.severity.max(held),
        system: health,
        impact: assessed.impact,
        baseline_window_hours: d.baseline.window_hours,
        baseline_confidence: d.baseline.confidence,
        explanation: with_impact(leak::explain(d), &assessed.reason, assessed.severity, held),
    }
}

#[cfg(test)]
mod tests {
    use super::super::BaselineStats;
    use super::*;
    use crate::Metric;
    use crate::config::Sensitivity;
    use crate::inventory::RawProcess;
    use crate::profiler::confidence::Confidence;
    use std::path::PathBuf;

    const PATH: &str = r"C:\Apps\Busy.exe";
    const MIB: f64 = 1024.0 * 1024.0;

    fn stats(median: f64, mad: f64, p95: f64, growth: Option<f64>) -> BaselineStats {
        BaselineStats {
            median,
            mad,
            p95,
            mean: median,
            growth_per_hour: growth,
            confidence: Confidence::Established,
            window_hours: 24,
        }
    }

    /// Busy.exe is normally ~8% CPU, 100 MiB of memory, quiet on disk and network.
    fn tracker() -> AnomalyTracker {
        let mut t = AnomalyTracker::new(Sensitivities::uniform(Sensitivity::Normal));
        let mut set = BaselineSet::new();
        let s = PATH.to_lowercase();
        set.insert(BaselineMetric::Cpu, s.clone(), stats(8.0, 1.0, 10.0, None));
        set.insert(
            BaselineMetric::Memory,
            s.clone(),
            stats(100.0 * MIB, MIB, 105.0 * MIB, Some(0.0)),
        );
        for m in [
            BaselineMetric::DiskRead,
            BaselineMetric::DiskWrite,
            BaselineMetric::NetRx,
            BaselineMetric::NetTx,
        ] {
            set.insert(m, s.clone(), stats(0.0, 0.0, 0.0, None));
        }
        t.set_baselines(set);
        t
    }

    fn sample(pid: u32, cpu: f64) -> Sample {
        Sample {
            key: ProcessKey::new(pid, 100),
            cpu_percent: Metric::Available(cpu),
            working_set: Metric::Unavailable,
            private_bytes: Metric::Unavailable,
            virtual_bytes: Metric::Unavailable,
            peak_working_set: Metric::Unavailable,
            io_read_bytes_per_sec: Metric::Unavailable,
            io_write_bytes_per_sec: Metric::Unavailable,
            io_read_ops_per_sec: Metric::Unavailable,
            io_write_ops_per_sec: Metric::Unavailable,
            net_rx_bytes_per_sec: Metric::Unavailable,
            net_tx_bytes_per_sec: Metric::Unavailable,
        }
    }

    fn started(pid: u32, path: &str) -> RawProcess {
        RawProcess {
            pid,
            name: "Busy.exe".into(),
            start_time: Some(100),
            exe_path: Some(PathBuf::from(path)),
            ..Default::default()
        }
    }

    fn batch(ts_ms: i64, new: Vec<RawProcess>, samples: Vec<Sample>) -> TickBatch {
        TickBatch {
            ts_ms,
            new,
            samples,
            gone: Vec::new(),
            system: None,
        }
    }

    /// A system sample with the given CPU and memory use and an 8 GiB machine.
    fn system(cpu: f64, memory_used_percent: f64) -> SystemSample {
        let total = 8u64 * 1024 * 1024 * 1024;
        SystemSample {
            cpu_percent: Metric::Available(cpu),
            memory_total_bytes: Metric::Available(total),
            memory_available_bytes: Metric::Available(
                (total as f64 * (1.0 - memory_used_percent / 100.0)) as u64,
            ),
            commit_used_bytes: Metric::Unavailable,
            commit_limit_bytes: Metric::Unavailable,
            disk_utilization_percent: Metric::Unavailable,
            disk_queue_length: Metric::Unavailable,
            disk_read_bytes_per_sec: Metric::Unavailable,
            disk_write_bytes_per_sec: Metric::Unavailable,
            disk_latency_ms: Metric::Unavailable,
            net_rx_bytes_per_sec: Metric::Unavailable,
            net_tx_bytes_per_sec: Metric::Unavailable,
        }
    }

    fn raised(changes: &[AnomalyChange]) -> Vec<AnomalyEvent> {
        changes
            .iter()
            .filter_map(|c| match c {
                AnomalyChange::Raised { event, .. } => Some(event.clone()),
                _ => None,
            })
            .collect()
    }

    /// Ticks 5 s apart; `make` builds each tick's samples. Instances start on the first tick.
    /// Returns every change.
    fn drive_changes(
        t: &mut AnomalyTracker,
        ticks: usize,
        pids: &[u32],
        make: impl Fn(usize, u32) -> Sample,
    ) -> Vec<AnomalyChange> {
        let mut changes = Vec::new();
        for i in 0..ticks {
            let new = if i == 0 {
                pids.iter().map(|p| started(*p, PATH)).collect()
            } else {
                Vec::new()
            };
            let samples = pids.iter().map(|p| make(i, *p)).collect();
            changes.extend(t.ingest(&batch(i as i64 * 5_000, new, samples)));
        }
        changes
    }

    fn drive(
        t: &mut AnomalyTracker,
        ticks: usize,
        pids: &[u32],
        make: impl Fn(usize, u32) -> Sample,
    ) -> Vec<AnomalyEvent> {
        raised(&drive_changes(t, ticks, pids, make))
    }

    fn cpu_only(cpus: &'static [(u32, f64)]) -> impl Fn(usize, u32) -> Sample {
        move |_, pid| {
            let cpu = cpus.iter().find(|(p, _)| *p == pid).unwrap().1;
            sample(pid, cpu)
        }
    }

    /// One process at `cpu`% on a system with the given load, for `ticks` ticks.
    fn burn_on(system_cpu: f64, mem: f64, cpu: f64, ticks: usize) -> Vec<AnomalyChange> {
        burn_with(tracker(), system_cpu, mem, cpu, ticks)
    }

    fn burn_with(
        mut t: AnomalyTracker,
        system_cpu: f64,
        mem: f64,
        cpu: f64,
        ticks: usize,
    ) -> Vec<AnomalyChange> {
        let mut changes = Vec::new();
        for i in 0..ticks {
            let new = if i == 0 {
                vec![started(7, PATH)]
            } else {
                vec![]
            };
            let mut b = batch(i as i64 * 5_000, new, vec![sample(7, cpu)]);
            b.system = Some(system(system_cpu, mem));
            changes.extend(t.ingest(&b));
        }
        changes
    }

    #[test]
    fn a_sustained_burn_becomes_an_event_with_every_field() {
        let changes = burn_on(91.0, 75.0, 72.0, 25);
        let events = raised(&changes);

        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!((e.pid, e.start_time), (7, 100));
        assert_eq!(e.process_name, "Busy.exe");
        assert_eq!(e.exe_path, PATH, "original case is kept for display");
        assert_eq!(
            (e.resource, e.kind),
            (Resource::Cpu, AnomalyKind::Deviation)
        );
        assert_eq!((e.current, e.baseline), (72.0, 8.0));
        assert_eq!(e.deviation_pct, 800.0);
        assert_eq!(e.duration_ms, 120_000);
        assert_eq!(e.detected_ts_ms, 120_000);
        assert_eq!(e.system.cpu_percent, Some(91.0));
        assert!((e.system.memory_percent.unwrap() - 75.0).abs() < 0.01);
        assert_eq!(e.baseline_window_hours, 24);
        assert_eq!(e.baseline_confidence, Confidence::Established);
        assert!(e.explanation.contains("Busy.exe"), "{}", e.explanation);
        assert!(e.explanation.contains("Impact:"), "{}", e.explanation);
        // 91% busy and this process is 72% of it.
        assert_eq!(e.severity, Severity::High);
        assert_eq!(e.impact.share_percent, Some(72.0));
        assert_eq!(e.impact.pressure_percent, Some(91.0));
    }

    #[test]
    fn instances_of_one_executable_are_summed_and_the_busiest_is_reported() {
        // Three processes at 25% each are 75% together: abnormal for a 8% baseline, though no
        // single one looks unusual on its own.
        let mut t = tracker();
        let events = drive(
            &mut t,
            30,
            &[1, 2, 3],
            cpu_only(&[(1, 25.0), (2, 25.0), (3, 25.0)]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].current, 75.0);

        let mut t = tracker();
        let events = drive(&mut t, 30, &[1, 2], cpu_only(&[(1, 5.0), (2, 70.0)]));
        assert_eq!(events[0].pid, 2, "the busiest instance is named");
    }

    #[test]
    fn nothing_is_raised_without_a_baseline() {
        let mut t = tracker();
        t.set_baselines(BaselineSet::new());
        assert!(drive(&mut t, 60, &[1], cpu_only(&[(1, 95.0)])).is_empty());
    }

    #[test]
    fn a_paused_tracker_raises_nothing_and_restarts_its_clocks_on_resume() {
        let mut t = tracker();
        t.set_enabled(false);
        assert!(drive(&mut t, 60, &[1], cpu_only(&[(1, 95.0)])).is_empty());
        assert!(!t.is_enabled());

        t.set_enabled(true);
        // Processes already known keep being tracked while paused, and the clock starts afresh:
        // 20 ticks is 95 s, short of the 120 s.
        let mut changes = Vec::new();
        for i in 0..20 {
            changes.extend(t.ingest(&batch(1_000_000 + i * 5_000, vec![], vec![sample(1, 95.0)])));
        }
        assert!(raised(&changes).is_empty());
        for i in 20..30 {
            changes.extend(t.ingest(&batch(1_000_000 + i * 5_000, vec![], vec![sample(1, 95.0)])));
        }
        assert_eq!(raised(&changes).len(), 1);
    }

    #[test]
    fn samples_of_unidentified_processes_are_ignored() {
        // No exe path (access denied), so there is no subject to judge.
        let mut t = tracker();
        let mut raw = started(1, PATH);
        raw.exe_path = None;
        let mut changes = t.ingest(&batch(0, vec![raw], vec![sample(1, 95.0)]));
        for i in 1..40 {
            changes.extend(t.ingest(&batch(i * 5_000, vec![], vec![sample(1, 95.0)])));
        }
        assert!(changes.is_empty());
    }

    #[test]
    fn unavailable_cpu_is_not_treated_as_zero_or_as_high() {
        let mut t = tracker();
        let mut s = sample(1, 0.0);
        s.cpu_percent = Metric::Unavailable;
        let mut changes = t.ingest(&batch(0, vec![started(1, PATH)], vec![s.clone()]));
        for i in 1..40 {
            changes.extend(t.ingest(&batch(i * 5_000, vec![], vec![s.clone()])));
        }
        assert!(changes.is_empty());
    }

    #[test]
    fn ended_processes_are_forgotten() {
        let mut t = tracker();
        t.ingest(&batch(0, vec![started(1, PATH)], vec![sample(1, 1.0)]));
        let mut gone = batch(5_000, vec![], vec![]);
        gone.gone = vec![ProcessKey::new(1, 100)];
        t.ingest(&gone);
        assert!(t.procs.is_empty());
    }

    // ---- memory, disk, network -----------------------------------------------------------

    #[test]
    fn heavy_memory_use_is_reported_as_a_memory_event() {
        let mut t = tracker();
        let events = drive(&mut t, 80, &[1], |_, pid| {
            let mut s = sample(pid, 1.0);
            s.working_set = Metric::Available((2048.0 * MIB) as u64);
            s
        });
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(
            (e.resource, e.kind),
            (Resource::Memory, AnomalyKind::Deviation)
        );
        assert_eq!(e.current, 2048.0 * MIB);
        assert_eq!(e.baseline, 100.0 * MIB);
        assert_eq!(e.duration_ms, 300_000);
        assert!(e.explanation.contains("2.0 GiB"), "{}", e.explanation);
    }

    #[test]
    fn heavy_disk_writes_and_network_sends_are_separate_events() {
        let mut t = tracker();
        let events = drive(&mut t, 40, &[1], |_, pid| {
            let mut s = sample(pid, 1.0);
            s.io_write_bytes_per_sec = Metric::Partial(90.0 * MIB);
            s.net_tx_bytes_per_sec = Metric::Available(30.0 * MIB);
            s
        });
        let mut kinds: Vec<_> = events.iter().map(|e| e.resource).collect();
        kinds.sort_by_key(|r| r.as_str());
        assert_eq!(kinds, vec![Resource::Disk, Resource::Network]);
        let disk = events
            .iter()
            .find(|e| e.resource == Resource::Disk)
            .unwrap();
        assert!(disk.explanation.contains("writes"), "{}", disk.explanation);
        let net = events
            .iter()
            .find(|e| e.resource == Resource::Network)
            .unwrap();
        assert!(
            net.explanation.contains("sent network data"),
            "{}",
            net.explanation
        );
    }

    #[test]
    fn unattributed_network_is_not_judged_as_zero_or_high() {
        // Network metrics are Unavailable (no collector): nothing to compare, nothing raised.
        let mut t = tracker();
        let events = drive(&mut t, 80, &[1], cpu_only(&[(1, 1.0)]));
        assert!(events.is_empty());
    }

    #[test]
    fn per_resource_sensitivity_is_respected() {
        let mut sens = Sensitivities::uniform(Sensitivity::Normal);
        sens.disk = Sensitivity::Low; // Low floor is 40 MiB/s: 30 MiB/s no longer qualifies.
        let mut t = AnomalyTracker::new(sens);
        let mut set = BaselineSet::new();
        set.insert(
            BaselineMetric::DiskWrite,
            PATH.to_lowercase(),
            stats(0.0, 0.0, 0.0, None),
        );
        t.set_baselines(set);
        let events = drive(&mut t, 200, &[1], |_, pid| {
            let mut s = sample(pid, 1.0);
            s.io_write_bytes_per_sec = Metric::Partial(30.0 * MIB);
            s
        });
        assert!(events.is_empty());
    }

    // ---- potential memory leaks ----------------------------------------------------------

    fn ramp(mib_per_min: f64) -> impl Fn(usize, u32) -> Sample {
        move |i, pid| {
            let mut s = sample(pid, 1.0);
            let minutes = i as f64 * 5.0 / 60.0;
            s.private_bytes = Metric::Available(((200.0 + mib_per_min * minutes) * MIB) as u64);
            s.working_set = Metric::Available((100.0 * MIB) as u64);
            s
        }
    }

    #[test]
    fn a_steady_private_memory_ramp_is_a_potential_leak_event() {
        let mut t = tracker();
        let events = drive(&mut t, 480, &[9], ramp(3.0));
        assert_eq!(events.len(), 1, "{events:#?}");
        let e = &events[0];
        assert_eq!(
            (e.resource, e.kind),
            (Resource::Memory, AnomalyKind::MemoryGrowth)
        );
        assert_eq!(e.pid, 9);
        assert!(
            (e.current / MIB - 180.0).abs() < 5.0,
            "MiB/h: {}",
            e.current / MIB
        );
        assert_eq!(e.baseline, 0.0);
        assert!(e.deviation_pct > 1000.0);
        assert!(
            e.explanation.contains("Potential memory leak"),
            "{}",
            e.explanation
        );
    }

    #[test]
    fn a_leak_needs_a_usable_memory_baseline() {
        let mut t = tracker();
        t.set_baselines(BaselineSet::new());
        assert!(drive(&mut t, 480, &[9], ramp(3.0)).is_empty());
    }

    #[test]
    fn instance_churn_in_one_executable_is_not_a_leak() {
        // Instances come and go, so the executable's total private memory climbs, but no single
        // process is growing: nothing to report.
        let mut t = tracker();
        let mut changes = Vec::new();
        for i in 0..480usize {
            let generation = (i / 12) as u32; // a new process every minute
            let pid = 1000 + generation;
            let new = if i % 12 == 0 {
                vec![RawProcess {
                    pid,
                    name: "Busy.exe".into(),
                    start_time: Some(100),
                    exe_path: Some(PathBuf::from(PATH)),
                    ..Default::default()
                }]
            } else {
                vec![]
            };
            let mut s = sample(pid, 1.0);
            s.private_bytes = Metric::Available((200.0 * MIB) as u64);
            changes.extend(t.ingest(&batch(i as i64 * 5_000, new, vec![s])));
        }
        assert!(changes.is_empty());
    }

    // ---- severity from system pressure ---------------------------------------------------

    #[test]
    fn the_same_fifteen_percent_burn_ranks_by_how_much_the_system_suffers() {
        // A process that normally idles around 2% suddenly uses 15%.
        let severity = |system_cpu: f64| {
            let mut t = tracker();
            let mut set = BaselineSet::new();
            set.insert(
                BaselineMetric::Cpu,
                PATH.to_lowercase(),
                stats(2.0, 0.2, 3.0, None),
            );
            t.set_baselines(set);
            let events = raised(&burn_with(t, system_cpu, 40.0, 15.0, 30));
            assert_eq!(events.len(), 1, "system at {system_cpu}%");
            events[0].severity
        };
        assert_eq!(severity(20.0), Severity::Informational, "idle machine");
        assert_eq!(severity(70.0), Severity::Warning, "busy machine");
        assert_eq!(severity(90.0), Severity::High, "saturated machine");
    }

    #[test]
    fn a_dominant_process_on_a_saturated_machine_is_critical() {
        let events = raised(&burn_on(98.0, 40.0, 60.0, 30));
        assert_eq!(events[0].severity, Severity::Critical);
        assert!(events[0].impact.score.unwrap() > 50.0);
    }

    #[test]
    fn a_memory_hog_is_judged_by_memory_pressure() {
        let mut t = tracker();
        let mut changes = Vec::new();
        for i in 0..80 {
            let new = if i == 0 {
                vec![started(1, PATH)]
            } else {
                vec![]
            };
            let mut s = sample(1, 1.0);
            s.working_set = Metric::Available((2048.0 * MIB) as u64);
            let mut b = batch(i as i64 * 5_000, new, vec![s]);
            b.system = Some(system(10.0, 92.0)); // CPU idle, memory nearly full
            changes.extend(t.ingest(&b));
        }
        let e = &raised(&changes)[0];
        assert_eq!(e.resource, Resource::Memory);
        assert_eq!(e.severity, Severity::High);
        assert_eq!(e.impact.pressure_percent.map(|p| p.round()), Some(92.0));
        assert_eq!(e.impact.share_percent.map(|p| p.round()), Some(25.0));
    }

    // ---- lifecycle -----------------------------------------------------------------------

    fn kinds(changes: &[AnomalyChange]) -> Vec<&'static str> {
        changes
            .iter()
            .map(|c| match c {
                AnomalyChange::Raised { .. } => "raised",
                AnomalyChange::Updated { .. } => "updated",
                AnomalyChange::Resolved { .. } => "resolved",
            })
            .collect()
    }

    #[test]
    fn a_condition_that_goes_on_updates_one_event_instead_of_raising_more() {
        // 10 minutes of the same burn: one event, then occasional updates, never a second event.
        let changes = burn_on(50.0, 40.0, 72.0, 120);
        let k = kinds(&changes);
        assert_eq!(k.iter().filter(|x| **x == "raised").count(), 1, "{k:?}");
        let updates = k.iter().filter(|x| **x == "updated").count();
        assert!(
            (14..=17).contains(&updates),
            "about one update every 30 s for the 8 minutes after the start: {updates}"
        );
        assert!(!k.contains(&"resolved"));
        // The updates carry the growing duration.
        let last = changes
            .iter()
            .rev()
            .find_map(|c| match c {
                AnomalyChange::Updated { event, .. } => Some(event),
                _ => None,
            })
            .unwrap();
        assert!(last.duration_ms > 500_000, "{}", last.duration_ms);
        // All of them name the same condition.
        let keys: std::collections::HashSet<_> = changes
            .iter()
            .map(|c| match c {
                AnomalyChange::Raised { key, .. }
                | AnomalyChange::Updated { key, .. }
                | AnomalyChange::Resolved { key, .. } => key.clone(),
            })
            .collect();
        assert_eq!(keys.len(), 1, "{keys:?}");
    }

    #[test]
    fn the_event_is_resolved_when_the_condition_ends() {
        let mut t = tracker();
        let mut changes = Vec::new();
        for i in 0..40 {
            let new = if i == 0 {
                vec![started(7, PATH)]
            } else {
                vec![]
            };
            let cpu = if i < 30 { 72.0 } else { 3.0 };
            changes.extend(t.ingest(&batch(i as i64 * 5_000, new, vec![sample(7, cpu)])));
        }
        let k = kinds(&changes);
        assert_eq!(k.last(), Some(&"resolved"), "{k:?}");
        assert_eq!(k.iter().filter(|x| **x == "resolved").count(), 1);
        let AnomalyChange::Resolved { ts_ms, .. } = changes.last().unwrap() else {
            unreachable!()
        };
        assert_eq!(*ts_ms, 29 * 5_000, "resolved as of the last elevated tick");
        assert_eq!(t.active_count(), 0);
    }

    #[test]
    fn a_new_episode_after_resolution_is_a_new_event() {
        let mut t = tracker();
        let mut changes = Vec::new();
        for i in 0..100 {
            let new = if i == 0 {
                vec![started(7, PATH)]
            } else {
                vec![]
            };
            let cpu = if (35..45).contains(&i) { 3.0 } else { 72.0 };
            changes.extend(t.ingest(&batch(i as i64 * 5_000, new, vec![sample(7, cpu)])));
        }
        assert_eq!(raised(&changes).len(), 2);
    }

    #[test]
    fn severity_only_goes_up_while_an_event_is_active() {
        // The burn starts on a busy machine (Warning), the system then saturates (High), and
        // later eases: the event keeps its worst severity.
        let mut t = tracker();
        let mut changes = Vec::new();
        for i in 0..160 {
            let new = if i == 0 {
                vec![started(7, PATH)]
            } else {
                vec![]
            };
            let load = match i {
                0..=60 => 70.0,
                61..=100 => 90.0,
                _ => 30.0,
            };
            let mut b = batch(i as i64 * 5_000, new, vec![sample(7, 35.0)]);
            b.system = Some(system(load, 40.0));
            changes.extend(t.ingest(&b));
        }
        let severities: Vec<Severity> = changes
            .iter()
            .filter_map(|c| match c {
                AnomalyChange::Raised { event, .. } | AnomalyChange::Updated { event, .. } => {
                    Some(event.severity)
                }
                _ => None,
            })
            .collect();
        assert_eq!(severities[0], Severity::Warning);
        assert!(severities.contains(&Severity::High), "{severities:?}");
        assert!(
            severities.windows(2).all(|w| w[0] <= w[1]),
            "never drops: {severities:?}"
        );
        let AnomalyChange::Updated { event, .. } = changes
            .iter()
            .rev()
            .find(|c| matches!(c, AnomalyChange::Updated { .. }))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(event.severity, Severity::High);
        assert!(
            event.explanation.contains("Severity stays at High"),
            "{}",
            event.explanation
        );
    }

    #[test]
    fn a_worse_severity_is_reported_at_once() {
        let mut t = tracker();
        let mut changes = Vec::new();
        for i in 0..36 {
            let new = if i == 0 {
                vec![started(7, PATH)]
            } else {
                vec![]
            };
            let load = if i < 30 { 70.0 } else { 90.0 };
            let mut b = batch(i as i64 * 5_000, new, vec![sample(7, 35.0)]);
            b.system = Some(system(load, 40.0));
            changes.extend(t.ingest(&b));
        }
        // Raised at tick 24; the next update is not due for 30 s, but the jump to High at tick
        // 30 is reported straight away.
        let k = kinds(&changes);
        assert_eq!(k, vec!["raised", "updated"], "{k:?}");
        let AnomalyChange::Updated { event, .. } = &changes[1] else {
            unreachable!()
        };
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.detected_ts_ms, 30 * 5_000);
    }

    #[test]
    fn pausing_resolves_the_active_anomalies() {
        let mut t = tracker();
        for i in 0..30 {
            let new = if i == 0 {
                vec![started(7, PATH)]
            } else {
                vec![]
            };
            t.ingest(&batch(i as i64 * 5_000, new, vec![sample(7, 72.0)]));
        }
        assert_eq!(t.active_count(), 1);
        let resolved = t.set_enabled(false);
        assert_eq!(kinds(&resolved), vec!["resolved"]);
        assert_eq!(t.active_count(), 0);
        assert!(t.set_enabled(true).is_empty());
    }

    #[test]
    fn an_exiting_process_resolves_its_anomaly() {
        let mut t = tracker();
        let mut changes = Vec::new();
        for i in 0..30 {
            let new = if i == 0 {
                vec![started(7, PATH)]
            } else {
                vec![]
            };
            changes.extend(t.ingest(&batch(i as i64 * 5_000, new, vec![sample(7, 72.0)])));
        }
        let mut gone = batch(30 * 5_000, vec![], vec![]);
        gone.gone = vec![ProcessKey::new(7, 100)];
        changes.extend(t.ingest(&gone));
        for i in 31..34 {
            changes.extend(t.ingest(&batch(i * 5_000, vec![], vec![])));
        }
        assert_eq!(kinds(&changes).last(), Some(&"resolved"));
    }

    #[test]
    fn a_leak_is_one_event_that_resolves_when_memory_is_given_back() {
        let mut t = tracker();
        let changes = drive_changes(&mut t, 560, &[9], |i, pid| {
            let mut s = ramp(3.0)(i, pid);
            if i as f64 * 5.0 / 60.0 >= 40.0 {
                s.private_bytes = Metric::Available((200.0 * MIB) as u64);
            }
            s
        });
        let k = kinds(&changes);
        assert_eq!(k.iter().filter(|x| **x == "raised").count(), 1, "{k:?}");
        assert!(k.contains(&"updated"));
        assert_eq!(k.last(), Some(&"resolved"));
    }
}
