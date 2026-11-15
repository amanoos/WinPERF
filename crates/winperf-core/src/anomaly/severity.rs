//! Severity and system impact (PRD FR-017, FR-018): the same deviation matters more when the
//! system is struggling and the process is a big part of why.
//!
//! The rule is deliberately small and explainable. For the resource involved it looks at the
//! system's pressure (how busy that resource is overall) and the process's share (how much of the
//! machine, or of the traffic, the process accounts for):
//!
//! | System pressure | Process share | Severity |
//! |---|---|---|
//! | unknown (e.g. network) | any | Warning |
//! | below 60% | any | Informational |
//! | 60% to 85% | any | Warning |
//! | 85% or more | under 10% | Warning |
//! | 85% or more | 10% or more | High |
//! | 95% or more | 25% or more | Critical |

use super::{Severity, SystemHealth};
use crate::config::Resource;

pub const PRESSURE_ELEVATED: f64 = 60.0;
pub const PRESSURE_SATURATED: f64 = 85.0;
pub const PRESSURE_SEVERE: f64 = 95.0;
pub const SHARE_MEANINGFUL: f64 = 10.0;
pub const SHARE_DOMINANT: f64 = 25.0;

/// How much an anomaly weighs on the system.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Impact {
    /// How busy the resource is system-wide, percent. `None` when it cannot be measured.
    pub pressure_percent: Option<f64>,
    /// The process's share of the resource, percent.
    pub share_percent: Option<f64>,
    /// Share weighted by pressure, 0 to 100: a big share of a saturated resource scores high.
    pub score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub severity: Severity,
    pub impact: Impact,
    /// Why this severity, in one sentence.
    pub reason: String,
}

/// How busy `resource` is across the whole system, percent.
pub fn pressure_of(resource: Resource, system: &SystemHealth) -> Option<f64> {
    match resource {
        Resource::Cpu => system.cpu_percent,
        Resource::Memory => system.memory_percent,
        Resource::Disk => system.disk_percent,
        // There is no known capacity to compare network traffic with.
        Resource::Network => None,
    }
}

fn name(resource: Resource) -> &'static str {
    match resource {
        Resource::Cpu => "CPU",
        Resource::Memory => "memory",
        Resource::Disk => "disk",
        Resource::Network => "network",
    }
}

/// Classify an anomaly on `resource` whose process accounts for `share_percent` of it.
pub fn assess(resource: Resource, share_percent: Option<f64>, system: &SystemHealth) -> Assessment {
    let pressure = pressure_of(resource, system);
    let share = share_percent.map(|s| s.clamp(0.0, 100.0));
    let impact = Impact {
        pressure_percent: pressure,
        share_percent: share,
        score: pressure
            .zip(share)
            .map(|(p, s)| s * p.clamp(0.0, 100.0) / 100.0),
    };
    let what = name(resource);
    let saturated = |p: f64, s: f64| {
        format!(
            "System {what} was saturated ({p:.0}% in use) and this process accounted for {s:.0}% of it."
        )
    };
    let (severity, reason) = match pressure {
        None => (
            Severity::Warning,
            format!(
                "System {what} pressure could not be measured, so the severity rests on the \
                 deviation alone."
            ),
        ),
        Some(p) if p < PRESSURE_ELEVATED => (
            Severity::Informational,
            format!(
                "System {what} was not under pressure ({p:.0}% in use), so there is no \
                 measurable system impact."
            ),
        ),
        Some(p) if p < PRESSURE_SATURATED => (
            Severity::Warning,
            format!("System {what} pressure was elevated ({p:.0}% in use)."),
        ),
        Some(p) => match share {
            Some(s) if s >= SHARE_DOMINANT && p >= PRESSURE_SEVERE => {
                (Severity::Critical, saturated(p, s))
            }
            Some(s) if s >= SHARE_MEANINGFUL => (Severity::High, saturated(p, s)),
            Some(s) => (
                Severity::Warning,
                format!(
                    "System {what} was saturated ({p:.0}% in use) but this process accounted \
                     for only {s:.0}% of it."
                ),
            ),
            None => (
                Severity::Warning,
                format!(
                    "System {what} was saturated ({p:.0}% in use); the process's share could \
                     not be measured."
                ),
            ),
        },
    };
    Assessment {
        severity,
        impact,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(p: f64) -> SystemHealth {
        SystemHealth {
            cpu_percent: Some(p),
            ..Default::default()
        }
    }

    fn sev(resource: Resource, share: Option<f64>, system: &SystemHealth) -> Severity {
        assess(resource, share, system).severity
    }

    #[test]
    fn the_same_process_is_judged_by_how_much_the_system_suffers() {
        // 15% CPU on an idle machine, a busy one and a saturated one.
        assert_eq!(
            sev(Resource::Cpu, Some(15.0), &cpu(20.0)),
            Severity::Informational
        );
        assert_eq!(
            sev(Resource::Cpu, Some(15.0), &cpu(70.0)),
            Severity::Warning
        );
        assert_eq!(sev(Resource::Cpu, Some(15.0), &cpu(90.0)), Severity::High);
    }

    #[test]
    fn critical_needs_a_severe_load_and_a_dominant_process() {
        assert_eq!(
            sev(Resource::Cpu, Some(40.0), &cpu(97.0)),
            Severity::Critical
        );
        assert_eq!(
            sev(Resource::Cpu, Some(40.0), &cpu(90.0)),
            Severity::High,
            "not yet severe"
        );
        assert_eq!(
            sev(Resource::Cpu, Some(15.0), &cpu(99.0)),
            Severity::High,
            "not dominant"
        );
    }

    #[test]
    fn a_saturated_system_is_not_blamed_on_a_bystander() {
        assert_eq!(sev(Resource::Cpu, Some(3.0), &cpu(99.0)), Severity::Warning);
        assert_eq!(sev(Resource::Cpu, None, &cpu(99.0)), Severity::Warning);
    }

    #[test]
    fn unknown_pressure_falls_back_to_warning() {
        assert_eq!(
            sev(Resource::Network, Some(80.0), &cpu(99.0)),
            Severity::Warning
        );
        assert_eq!(
            sev(Resource::Disk, Some(80.0), &cpu(99.0)),
            Severity::Warning,
            "no disk reading"
        );
        let a = assess(Resource::Network, Some(80.0), &SystemHealth::default());
        assert_eq!(a.impact.pressure_percent, None);
        assert_eq!(a.impact.score, None);
        assert!(a.reason.contains("could not be measured"), "{}", a.reason);
    }

    #[test]
    fn each_resource_reads_its_own_pressure() {
        let sys = SystemHealth {
            cpu_percent: Some(10.0),
            memory_percent: Some(92.0),
            disk_percent: Some(40.0),
        };
        assert_eq!(
            sev(Resource::Cpu, Some(50.0), &sys),
            Severity::Informational
        );
        assert_eq!(sev(Resource::Memory, Some(30.0), &sys), Severity::High);
        assert_eq!(
            sev(Resource::Disk, Some(50.0), &sys),
            Severity::Informational
        );
    }

    #[test]
    fn the_impact_score_weighs_share_by_pressure() {
        let a = assess(Resource::Cpu, Some(40.0), &cpu(50.0));
        assert_eq!(a.impact.score, Some(20.0));
        assert_eq!(a.impact.pressure_percent, Some(50.0));
        assert_eq!(a.impact.share_percent, Some(40.0));
        let busier = assess(Resource::Cpu, Some(40.0), &cpu(100.0)).impact.score;
        assert!(busier > a.impact.score);
    }

    #[test]
    fn the_reason_names_the_pressure_and_the_share() {
        let r = assess(Resource::Cpu, Some(15.0), &cpu(90.0)).reason;
        assert!(
            r.contains("saturated") && r.contains("90%") && r.contains("15%"),
            "{r}"
        );
        let r = assess(Resource::Cpu, Some(15.0), &cpu(20.0)).reason;
        assert!(r.contains("no measurable system impact"), "{r}");
    }

    #[test]
    fn out_of_range_shares_are_clamped() {
        let a = assess(Resource::Cpu, Some(250.0), &cpu(100.0));
        assert_eq!(a.impact.share_percent, Some(100.0));
    }
}
