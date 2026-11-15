//! Anomaly detection (PRD FR-014..FR-018): explainable statistics against stored baselines.
//!
//! Pure logic. A [`tracker::AnomalyTracker`] watches each tick's samples and runs two kinds of
//! detector: [`level::LevelDetector`] (a resource stays far above its normal level: CPU, memory,
//! disk, network) and [`leak::LeakDetector`] (a process's private memory keeps climbing and is
//! never given back). What they find becomes an [`AnomalyEvent`] carrying every FR-018 field plus
//! a plain-language explanation.

pub mod format;
pub mod leak;
pub mod level;
pub mod rules;
pub mod severity;
pub mod tracker;

pub use severity::Impact;

use crate::config::{DetectionConfig, Resource, Sensitivity};
use crate::profiler::baseline::BaselineMetric;
use crate::profiler::confidence::Confidence;
use std::collections::HashMap;

/// How serious an anomaly is (FR-018). Ordered from least to most serious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Unusual activity without measurable system impact.
    Informational,
    /// Significant deviation from baseline.
    Warning,
    /// Sustained deviation associated with system resource pressure.
    High,
    /// Severe resource consumption associated with substantial system degradation.
    Critical,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::Informational,
        Severity::Warning,
        Severity::High,
        Severity::Critical,
    ];

    /// The stable name stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Informational => "informational",
            Severity::Warning => "warning",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Informational => "Informational",
            Severity::Warning => "Warning",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

/// What an event measures, which decides how its numbers are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnomalyKind {
    /// A resource level far above normal: `current` and `baseline` are levels.
    Deviation,
    /// Private memory growing steadily without reclamation (a *potential* leak): `current` and
    /// `baseline` are growth rates in bytes per hour.
    MemoryGrowth,
}

impl AnomalyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AnomalyKind::Deviation => "deviation",
            AnomalyKind::MemoryGrowth => "memory_growth",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [AnomalyKind::Deviation, AnomalyKind::MemoryGrowth]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// The resource category a baseline metric belongs to.
pub fn resource_of(metric: BaselineMetric) -> Resource {
    match metric {
        BaselineMetric::Cpu => Resource::Cpu,
        BaselineMetric::Memory => Resource::Memory,
        BaselineMetric::DiskRead | BaselineMetric::DiskWrite => Resource::Disk,
        BaselineMetric::NetRx | BaselineMetric::NetTx => Resource::Network,
    }
}

/// What a baseline says is normal for one subject and metric, plus how far it can be trusted.
#[derive(Debug, Clone, PartialEq)]
pub struct BaselineStats {
    pub median: f64,
    /// Median absolute deviation, unscaled (as stored).
    pub mad: f64,
    pub p95: f64,
    pub mean: f64,
    /// Typical private-memory growth in bytes per hour (memory baselines only).
    pub growth_per_hour: Option<f64>,
    pub confidence: Confidence,
    /// The baseline window this came from, in hours.
    pub window_hours: u32,
}

/// The usable baselines (confidence above Insufficient), by metric and then by subject (the
/// lower-cased executable path). A subject without an entry is never judged.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BaselineSet {
    by_metric: HashMap<BaselineMetric, HashMap<String, BaselineStats>>,
}

impl BaselineSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, metric: BaselineMetric, subject: String, stats: BaselineStats) {
        self.by_metric
            .entry(metric)
            .or_default()
            .insert(subject, stats);
    }

    pub fn get(&self, metric: BaselineMetric, subject: &str) -> Option<&BaselineStats> {
        self.by_metric.get(&metric)?.get(subject)
    }

    /// All usable baselines of one metric, by subject.
    pub fn metric(&self, metric: BaselineMetric) -> Option<&HashMap<String, BaselineStats>> {
        self.by_metric.get(&metric)
    }

    /// Subjects that have a usable baseline for `metric`.
    pub fn subjects(&self, metric: BaselineMetric) -> usize {
        self.by_metric.get(&metric).map_or(0, HashMap::len)
    }

    pub fn is_empty(&self) -> bool {
        self.by_metric.values().all(HashMap::is_empty)
    }
}

/// The sensitivity to apply to each resource (config `[detection]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sensitivities {
    pub cpu: Sensitivity,
    pub memory: Sensitivity,
    pub disk: Sensitivity,
    pub network: Sensitivity,
}

impl Sensitivities {
    pub fn uniform(s: Sensitivity) -> Self {
        Self {
            cpu: s,
            memory: s,
            disk: s,
            network: s,
        }
    }

    pub fn from_config(c: &DetectionConfig) -> Self {
        Self {
            cpu: c.for_resource(Resource::Cpu),
            memory: c.for_resource(Resource::Memory),
            disk: c.for_resource(Resource::Disk),
            network: c.for_resource(Resource::Network),
        }
    }

    pub fn for_resource(&self, r: Resource) -> Sensitivity {
        match r {
            Resource::Cpu => self.cpu,
            Resource::Memory => self.memory,
            Resource::Disk => self.disk,
            Resource::Network => self.network,
        }
    }
}

/// System health at the moment an anomaly was detected (FR-018 "system health indicators").
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SystemHealth {
    /// Total CPU in use, percent.
    pub cpu_percent: Option<f64>,
    /// Physical memory in use, percent.
    pub memory_percent: Option<f64>,
    /// Busiest disk, percent of time busy.
    pub disk_percent: Option<f64>,
}

/// One detected anomaly (FR-018).
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyEvent {
    /// Detection time, Unix milliseconds UTC.
    pub detected_ts_ms: i64,
    /// The busiest instance of the subject when the event was raised.
    pub pid: u32,
    /// Creation time of that instance (raw FILETIME), which with `pid` identifies it.
    pub start_time: u64,
    pub process_name: String,
    pub exe_path: String,
    pub resource: Resource,
    pub kind: AnomalyKind,
    /// What was measured (see [`AnomalyKind`] for the unit).
    pub current: f64,
    /// What is normal for this subject: the baseline median, or its usual growth rate.
    pub baseline: f64,
    /// How far above normal, in percent of the baseline.
    pub deviation_pct: f64,
    /// How long the behaviour had lasted when the event was raised.
    pub duration_ms: i64,
    pub severity: Severity,
    pub system: SystemHealth,
    /// How much this weighs on the system (FR-017).
    pub impact: Impact,
    pub baseline_window_hours: u32,
    pub baseline_confidence: Confidence,
    pub explanation: String,
}

/// Where a detector's episode stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The behaviour has just lasted long enough to count.
    Started,
    /// It is still going on.
    Ongoing,
    /// It has stopped (or can no longer be judged).
    Ended,
}

/// What happened to an anomaly this tick. `key` identifies the condition (a process and a
/// resource), so a condition that goes on updates one event instead of raising a new one each time.
#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyChange {
    /// A new event.
    Raised { key: String, event: AnomalyEvent },
    /// The event for `key` has new numbers (it lasted longer, got worse, ...).
    Updated { key: String, event: AnomalyEvent },
    /// The condition ended at `ts_ms`.
    Resolved { key: String, ts_ms: i64 },
}
