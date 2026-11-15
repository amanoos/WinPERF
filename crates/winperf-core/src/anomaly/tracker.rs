//! Turns each tick's batch into anomaly events: sums CPU per executable (the baseline subject),
//! hands the totals to the detector, and wraps what it finds in full [`AnomalyEvent`]s.
//!
//! The tracker only ever sees baselines the caller considers usable (confidence above
//! Insufficient) and can be switched off, which is how profiling mode holds detection back.

use super::cpu::{CpuDetector, Detection, Reading, deviation_percent, explain};
use super::rules::CpuRule;
use super::{AnomalyEvent, BaselineStats, Severity, SystemHealth};
use crate::ProcessKey;
use crate::config::Resource;
use crate::engine::TickBatch;
use crate::system::SystemSample;
use std::collections::HashMap;

struct ProcInfo {
    /// Lower-cased executable path: matches `executables.path_key` and the baseline subject.
    subject: String,
    name: String,
    exe_path: String,
}

pub struct AnomalyTracker {
    cpu: CpuDetector,
    procs: HashMap<ProcessKey, ProcInfo>,
    baselines: HashMap<String, BaselineStats>,
    enabled: bool,
}

impl AnomalyTracker {
    pub fn new(cpu_rule: CpuRule) -> Self {
        Self {
            cpu: CpuDetector::new(cpu_rule),
            procs: HashMap::new(),
            baselines: HashMap::new(),
            enabled: true,
        }
    }

    /// Replace the baselines, keyed by lower-cased executable path. Callers pass only usable ones.
    pub fn set_baselines(&mut self, baselines: HashMap<String, BaselineStats>) {
        self.baselines = baselines;
    }

    /// Pause or resume detection. Pausing forgets any episode in progress, so resuming starts
    /// every clock from zero. Process tracking continues either way.
    pub fn set_enabled(&mut self, enabled: bool) {
        if !enabled {
            self.cpu.reset();
        }
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    pub fn ingest(&mut self, batch: &TickBatch) -> Vec<AnomalyEvent> {
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

        let detections = if self.enabled {
            self.detect_cpu(batch)
        } else {
            Vec::new()
        };

        for key in &batch.gone {
            self.procs.remove(key);
        }

        let health = system_health(batch.system.as_ref());
        detections
            .into_iter()
            .map(|d| cpu_event(d, health))
            .collect()
    }

    fn detect_cpu(&mut self, batch: &TickBatch) -> Vec<Detection> {
        struct Total<'a> {
            info: &'a ProcInfo,
            sum: f64,
            top: ProcessKey,
            top_cpu: f64,
        }
        let mut totals: HashMap<&str, Total<'_>> = HashMap::new();
        for s in &batch.samples {
            let (Some(&cpu), Some(info)) = (s.cpu_percent.value(), self.procs.get(&s.key)) else {
                continue;
            };
            let t = totals.entry(info.subject.as_str()).or_insert(Total {
                info,
                sum: 0.0,
                top: s.key,
                top_cpu: f64::MIN,
            });
            t.sum += cpu;
            if cpu > t.top_cpu {
                t.top_cpu = cpu;
                t.top = s.key;
            }
        }
        let readings: Vec<Reading<'_>> = totals
            .iter()
            .map(|(subject, t)| Reading {
                subject,
                cpu_percent: t.sum,
                top: t.top,
                name: &t.info.name,
                exe_path: &t.info.exe_path,
            })
            .collect();
        self.cpu
            .observe_tick(batch.ts_ms, &readings, &self.baselines)
    }
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
    }
}

fn cpu_event(d: Detection, system: SystemHealth) -> AnomalyEvent {
    let explanation = explain(&d);
    AnomalyEvent {
        detected_ts_ms: d.ts_ms,
        pid: d.top.pid,
        start_time: d.top.start_time,
        process_name: d.name,
        exe_path: d.exe_path,
        resource: Resource::Cpu,
        current: d.current,
        baseline: d.baseline.median,
        deviation_pct: deviation_percent(d.current, d.baseline.median),
        duration_ms: d.duration_ms,
        // Every detector event starts as a plain deviation; weighing it against system pressure
        // (High/Critical, or Informational when nothing suffers) is a later step.
        severity: Severity::Warning,
        system,
        baseline_window_hours: d.baseline.window_hours,
        baseline_confidence: d.baseline.confidence,
        explanation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Metric;
    use crate::config::Sensitivity;
    use crate::inventory::RawProcess;
    use crate::profiler::confidence::Confidence;
    use crate::sampling::Sample;
    use std::path::PathBuf;

    const PATH: &str = r"C:\Apps\Busy.exe";

    fn tracker() -> AnomalyTracker {
        let mut t = AnomalyTracker::new(CpuRule::for_sensitivity(Sensitivity::Normal));
        t.set_baselines(HashMap::from([(
            PATH.to_lowercase(),
            BaselineStats {
                median: 8.0,
                mad: 1.0,
                p95: 10.0,
                mean: 8.0,
                confidence: Confidence::Established,
                window_hours: 24,
            },
        )]));
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

    /// Ticks 5 s apart with the given per-instance CPU; instances start on the first tick.
    fn drive(t: &mut AnomalyTracker, ticks: usize, cpus: &[(u32, f64)]) -> Vec<AnomalyEvent> {
        let mut events = Vec::new();
        for i in 0..ticks {
            let new = if i == 0 {
                cpus.iter().map(|(pid, _)| started(*pid, PATH)).collect()
            } else {
                Vec::new()
            };
            let samples = cpus.iter().map(|(pid, c)| sample(*pid, *c)).collect();
            events.extend(t.ingest(&batch(i as i64 * 5_000, new, samples)));
        }
        events
    }

    #[test]
    fn a_sustained_burn_becomes_an_event_with_every_field() {
        let mut t = tracker();
        let mut b = batch(0, vec![started(7, PATH)], vec![sample(7, 72.0)]);
        b.system = Some(SystemSample {
            cpu_percent: Metric::Available(91.0),
            memory_total_bytes: Metric::Available(16_000),
            memory_available_bytes: Metric::Available(4_000),
            commit_used_bytes: Metric::Unavailable,
            commit_limit_bytes: Metric::Unavailable,
            disk_utilization_percent: Metric::Unavailable,
            disk_queue_length: Metric::Unavailable,
            disk_read_bytes_per_sec: Metric::Unavailable,
            disk_write_bytes_per_sec: Metric::Unavailable,
            disk_latency_ms: Metric::Unavailable,
            net_rx_bytes_per_sec: Metric::Unavailable,
            net_tx_bytes_per_sec: Metric::Unavailable,
        });
        assert!(t.ingest(&b).is_empty());
        let mut events = Vec::new();
        for i in 1..=24 {
            let mut next = batch(i * 5_000, vec![], vec![sample(7, 72.0)]);
            next.system = b.system.clone();
            events.extend(t.ingest(&next));
        }

        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!((e.pid, e.start_time), (7, 100));
        assert_eq!(e.process_name, "Busy.exe");
        assert_eq!(e.exe_path, PATH, "original case is kept for display");
        assert_eq!(e.resource, Resource::Cpu);
        assert_eq!((e.current, e.baseline), (72.0, 8.0));
        assert_eq!(e.deviation_pct, 800.0);
        assert_eq!(e.duration_ms, 120_000);
        assert_eq!(e.detected_ts_ms, 120_000);
        assert_eq!(e.severity, Severity::Warning);
        assert_eq!(e.system.cpu_percent, Some(91.0));
        assert_eq!(e.system.memory_percent, Some(75.0));
        assert_eq!(e.baseline_window_hours, 24);
        assert_eq!(e.baseline_confidence, Confidence::Established);
        assert!(e.explanation.contains("Busy.exe"), "{}", e.explanation);
    }

    #[test]
    fn instances_of_one_executable_are_summed_and_the_busiest_is_reported() {
        // Three processes at 25% each are 75% together: abnormal for a 8% baseline, though no
        // single one looks unusual on its own.
        let mut t = tracker();
        let events = drive(&mut t, 30, &[(1, 25.0), (2, 25.0), (3, 25.0)]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].current, 75.0);

        let mut t = tracker();
        let events = drive(&mut t, 30, &[(1, 5.0), (2, 70.0)]);
        assert_eq!(events[0].pid, 2, "the busiest instance is named");
    }

    #[test]
    fn nothing_is_raised_without_a_baseline() {
        let mut t = tracker();
        t.set_baselines(HashMap::new());
        assert!(drive(&mut t, 60, &[(1, 95.0)]).is_empty());
    }

    #[test]
    fn a_paused_tracker_raises_nothing_and_restarts_its_clocks_on_resume() {
        let mut t = tracker();
        t.set_enabled(false);
        assert!(drive(&mut t, 60, &[(1, 95.0)]).is_empty());
        assert!(!t.is_enabled());

        t.set_enabled(true);
        // Processes already known keep being tracked while paused, and the clock starts afresh:
        // 20 ticks is 95 s, short of the 120 s.
        let mut events = Vec::new();
        for i in 0..20 {
            events.extend(t.ingest(&batch(1_000_000 + i * 5_000, vec![], vec![sample(1, 95.0)])));
        }
        assert!(events.is_empty());
        for i in 20..30 {
            events.extend(t.ingest(&batch(1_000_000 + i * 5_000, vec![], vec![sample(1, 95.0)])));
        }
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn samples_of_unidentified_processes_are_ignored() {
        // No exe path (access denied), so there is no subject to judge.
        let mut t = tracker();
        let mut raw = started(1, PATH);
        raw.exe_path = None;
        let mut events = t.ingest(&batch(0, vec![raw], vec![sample(1, 95.0)]));
        for i in 1..40 {
            events.extend(t.ingest(&batch(i * 5_000, vec![], vec![sample(1, 95.0)])));
        }
        assert!(events.is_empty());
    }

    #[test]
    fn unavailable_cpu_is_not_treated_as_zero_or_as_high() {
        let mut t = tracker();
        let mut s = sample(1, 0.0);
        s.cpu_percent = Metric::Unavailable;
        let mut events = t.ingest(&batch(0, vec![started(1, PATH)], vec![s.clone()]));
        for i in 1..40 {
            events.extend(t.ingest(&batch(i * 5_000, vec![], vec![s.clone()])));
        }
        assert!(events.is_empty());
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
}
