//! Anomaly detection (PRD FR-014..FR-018): explainable statistics against stored baselines.
//!
//! Pure logic. A [`tracker::AnomalyTracker`] watches each tick's samples, a detector (so far
//! [`cpu::CpuDetector`]) decides when a subject has been abnormal for long enough, and the result
//! is an [`AnomalyEvent`] carrying every FR-018 field plus a plain-language explanation.

pub mod cpu;
pub mod rules;
pub mod tracker;

use crate::config::Resource;
use crate::profiler::confidence::Confidence;

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

/// What a baseline says is normal for one subject and metric, plus how far it can be trusted.
#[derive(Debug, Clone, PartialEq)]
pub struct BaselineStats {
    pub median: f64,
    /// Median absolute deviation, unscaled (as stored).
    pub mad: f64,
    pub p95: f64,
    pub mean: f64,
    pub confidence: Confidence,
    /// The baseline window this came from, in hours.
    pub window_hours: u32,
}

/// System health at the moment an anomaly was detected (FR-018 "system health indicators").
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct SystemHealth {
    /// Total CPU in use, percent.
    pub cpu_percent: Option<f64>,
    /// Physical memory in use, percent.
    pub memory_percent: Option<f64>,
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
    /// What was measured (the average over the abnormal stretch). Percent for CPU.
    pub current: f64,
    /// What is normal for this subject (the baseline median).
    pub baseline: f64,
    /// How far above normal, in percent of the baseline.
    pub deviation_pct: f64,
    /// How long the behaviour had lasted when the event was raised.
    pub duration_ms: i64,
    pub severity: Severity,
    pub system: SystemHealth,
    pub baseline_window_hours: u32,
    pub baseline_confidence: Confidence,
    pub explanation: String,
}
