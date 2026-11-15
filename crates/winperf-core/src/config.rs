//! WinPerf configuration (PRD FR-010/FR-011/FR-015, 4.3). Pure: text in, validated settings out;
//! reading the file and deciding where it lives is the front end's job.
//!
//! Every setting is optional in the file; anything omitted takes its default. Unknown keys are
//! rejected so a typo (`intervall_secs`) is an error, not a silently ignored setting.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Anomaly-detection sensitivity (PRD FR-015). Consumed by the detectors in a later phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    /// More conservative: fewer, more certain anomalies.
    Low,
    /// Balanced.
    #[default]
    Normal,
    /// More aggressive: flags smaller or shorter deviations.
    High,
}

/// The resource categories that can have their own sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Cpu,
    Memory,
    Disk,
    Network,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorConfig {
    /// Seconds between samples.
    pub interval_secs: u64,
    /// Verify signatures of newly seen executables (publisher classification).
    pub signatures: bool,
    /// Try to attribute network traffic to processes (ETW; needs administrator rights, and is
    /// skipped with a notice when they are missing).
    pub network: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Database file; `None` means the default location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    pub raw_samples_days: u32,
    pub aggregate_1min_days: u32,
    pub aggregate_15min_days: u32,
    pub anomaly_days: u32,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    /// Sensitivity for every resource without its own override.
    pub sensitivity: Sensitivity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<Sensitivity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Sensitivity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<Sensitivity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Sensitivity>,
}

impl DetectionConfig {
    /// The sensitivity that applies to `resource`: its override, else the global value.
    pub fn for_resource(&self, resource: Resource) -> Sensitivity {
        match resource {
            Resource::Cpu => self.cpu,
            Resource::Memory => self.memory,
            Resource::Disk => self.disk,
            Resource::Network => self.network,
        }
        .unwrap_or(self.sensitivity)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaselineConfig {
    /// Rolling baseline windows in hours (short, medium, long), strictly increasing.
    pub windows_hours: Vec<u32>,
    /// How often a running monitor recomputes the baselines, in minutes.
    pub recompute_minutes: u32,
    pub confidence: ConfidenceConfig,
}

/// How much history a baseline needs before it is trusted. A level is reached when *both* its
/// observation count and its observation span are met; levels must strictly increase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfidenceConfig {
    pub preliminary_observations: u64,
    pub preliminary_minutes: u64,
    pub established_observations: u64,
    pub established_minutes: u64,
    pub high_observations: u64,
    pub high_minutes: u64,
}

impl Default for ConfidenceConfig {
    fn default() -> Self {
        // At the default 5 s interval: 5 minutes, 2 hours and 1 day of continuous sampling.
        Self {
            preliminary_observations: 60,
            preliminary_minutes: 5,
            established_observations: 1_000,
            established_minutes: 120,
            high_observations: 10_000,
            high_minutes: 1_440,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub monitor: MonitorConfig,
    pub storage: StorageConfig,
    pub retention: RetentionConfig,
    pub detection: DetectionConfig,
    pub baseline: BaselineConfig,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval_secs: 5,
            signatures: true,
            network: true,
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        // Deliberately shorter than the PRD's 7 / 30 days for raw / 1-minute data: raw samples
        // cost ~0.95 GB/day at 5 s (measured, T11/T12), so 7 days would be ~6.6 GB. Raw detail
        // is kept for 2 days; history beyond that lives in the rollups (T34).
        Self {
            raw_samples_days: 2,
            aggregate_1min_days: 14,
            aggregate_15min_days: 180,
            anomaly_days: 180,
        }
    }
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            windows_hours: vec![1, 24, 168],
            recompute_minutes: 15,
            confidence: ConfidenceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    /// The text is not valid TOML or has unknown/mistyped keys (message includes line and column).
    Parse(String),
    /// Valid TOML, but one or more settings are out of range.
    Invalid(Vec<String>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(m) => write!(f, "{m}"),
            ConfigError::Invalid(problems) => {
                write!(f, "invalid configuration:")?;
                for p in problems {
                    write!(f, "\n  - {p}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// A commented starting point for `winperf config init`. Kept equal to `Config::default()`
/// (a test enforces it), so the file documents exactly what the defaults are.
pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"# WinPerf configuration.
# Every setting is optional; anything omitted uses the default shown here.

[monitor]
# Seconds between samples (1-3600).
interval_secs = 5
# Verify signatures of newly seen executables in the background (publisher classification).
signatures = true
# Attribute network traffic to processes (needs administrator rights; skipped with a notice otherwise).
network = true

[storage]
# Database file. Default: %ProgramData%\WinPerf\winperf.db (or the WINPERF_DB variable).
# database = 'C:\path\to\winperf.db'

[retention]
# How long data is kept, in days. Raw 5 s samples cost about 1 GB/day, so they are kept briefly and
# history lives in the 1-minute and 15-minute rollups (about 3.8 GB in total at these defaults).
raw_samples_days = 2
aggregate_1min_days = 14
aggregate_15min_days = 180
anomaly_days = 180

[detection]
# low | normal | high
sensitivity = "normal"
# Optional per-resource overrides:
# cpu = "high"
# memory = "normal"
# disk = "low"
# network = "low"

[baseline]
# Rolling baseline windows in hours: short, medium, long (strictly increasing).
windows_hours = [1, 24, 168]
# How often a running `monitor run` recomputes the baselines, in minutes (1 to 1440).
recompute_minutes = 15

[baseline.confidence]
# A baseline reaches a level when it has at least this many observations spread over at least
# this many minutes. Below the first level it is "Insufficient" and anomalies are not raised.
# Levels must strictly increase. Defaults assume the 5 s interval.
preliminary_observations = 60
preliminary_minutes = 5
established_observations = 1000
established_minutes = 120
high_observations = 10000
high_minutes = 1440
"#;

impl Config {
    /// Parse and validate a configuration file's text.
    pub fn from_toml_str(text: &str) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// The effective configuration as TOML text.
    pub fn to_toml_string(&self) -> String {
        toml::to_string_pretty(self).expect("configuration is always serializable")
    }

    /// Check every setting's range, reporting *all* problems at once.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();

        if !(1..=3600).contains(&self.monitor.interval_secs) {
            problems.push(format!(
                "monitor.interval_secs must be between 1 and 3600 (got {})",
                self.monitor.interval_secs
            ));
        }
        for (name, days) in [
            ("raw_samples_days", self.retention.raw_samples_days),
            ("aggregate_1min_days", self.retention.aggregate_1min_days),
            ("aggregate_15min_days", self.retention.aggregate_15min_days),
            ("anomaly_days", self.retention.anomaly_days),
        ] {
            if !(1..=3650).contains(&days) {
                problems.push(format!(
                    "retention.{name} must be between 1 and 3650 days (got {days})"
                ));
            }
        }
        let windows = &self.baseline.windows_hours;
        if windows.is_empty() {
            problems.push("baseline.windows_hours must list at least one window".into());
        } else {
            if windows.contains(&0) {
                problems.push("baseline.windows_hours entries must be at least 1 hour".into());
            }
            if windows.windows(2).any(|w| w[0] >= w[1]) {
                problems.push(format!(
                    "baseline.windows_hours must be strictly increasing (got {windows:?})"
                ));
            }
        }
        if !(1..=1440).contains(&self.baseline.recompute_minutes) {
            problems.push(format!(
                "baseline.recompute_minutes must be between 1 and 1440 (got {})",
                self.baseline.recompute_minutes
            ));
        }
        let c = &self.baseline.confidence;
        let levels = [
            (
                "preliminary",
                c.preliminary_observations,
                c.preliminary_minutes,
            ),
            (
                "established",
                c.established_observations,
                c.established_minutes,
            ),
            ("high", c.high_observations, c.high_minutes),
        ];
        for (name, observations, minutes) in levels {
            if observations == 0 || minutes == 0 {
                problems.push(format!(
                    "baseline.confidence.{name}_observations and {name}_minutes must be at least 1"
                ));
            }
        }
        if levels
            .windows(2)
            .any(|w| w[0].1 >= w[1].1 || w[0].2 >= w[1].2)
        {
            problems.push(
                "baseline.confidence levels must strictly increase (preliminary < established < high) in both observations and minutes"
                    .into(),
            );
        }
        if let Some(db) = &self.storage.database
            && db.as_os_str().is_empty()
        {
            problems.push("storage.database must not be empty (omit it for the default)".into());
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(problems))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_prd_except_the_deliberately_shorter_raw_retention() {
        let c = Config::default();
        assert_eq!(c.monitor.interval_secs, 5);
        assert!(c.monitor.signatures);
        assert!(
            c.monitor.network,
            "network attribution is attempted by default"
        );
        // PRD 4.3 says 7 / 30 days; changed to 2 / 14 after measuring ~0.95 GB/day of raw data.
        assert_eq!(c.retention.raw_samples_days, 2);
        assert_eq!(c.retention.aggregate_1min_days, 14);
        assert_eq!(c.retention.aggregate_15min_days, 180);
        assert_eq!(c.retention.anomaly_days, 180);
        assert_eq!(c.baseline.windows_hours, vec![1, 24, 168]);
        assert_eq!(c.detection.sensitivity, Sensitivity::Normal);
        assert_eq!(c.storage.database, None);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn the_commented_template_is_exactly_the_defaults() {
        assert_eq!(
            Config::from_toml_str(DEFAULT_CONFIG_TEMPLATE).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn an_empty_file_means_all_defaults() {
        assert_eq!(Config::from_toml_str("").unwrap(), Config::default());
        assert_eq!(
            Config::from_toml_str("# nothing\n").unwrap(),
            Config::default()
        );
    }

    #[test]
    fn a_partial_file_overrides_only_what_it_names() {
        let c = Config::from_toml_str("[monitor]\ninterval_secs = 15\n").unwrap();
        assert_eq!(c.monitor.interval_secs, 15);
        assert!(c.monitor.signatures, "untouched keys keep their defaults");
        assert_eq!(c.retention, RetentionConfig::default());
    }

    #[test]
    fn every_setting_can_be_set() {
        let c = Config::from_toml_str(
            r#"
            [monitor]
            interval_secs = 30
            signatures = false
            network = false
            [storage]
            database = 'D:\data\wp.db'
            [retention]
            raw_samples_days = 2
            aggregate_1min_days = 10
            aggregate_15min_days = 90
            anomaly_days = 365
            [detection]
            sensitivity = "high"
            disk = "low"
            [baseline]
            windows_hours = [2, 12, 72]
            "#,
        )
        .unwrap();
        assert_eq!(c.monitor.interval_secs, 30);
        assert!(!c.monitor.signatures);
        assert!(!c.monitor.network);
        assert_eq!(c.storage.database, Some(PathBuf::from(r"D:\data\wp.db")));
        assert_eq!(c.retention.raw_samples_days, 2);
        assert_eq!(c.retention.anomaly_days, 365);
        assert_eq!(c.baseline.windows_hours, vec![2, 12, 72]);
        assert_eq!(c.detection.sensitivity, Sensitivity::High);
    }

    #[test]
    fn per_resource_sensitivity_falls_back_to_the_global_one() {
        let c = Config::from_toml_str(
            "[detection]\nsensitivity = \"low\"\ncpu = \"high\"\nnetwork = \"normal\"\n",
        )
        .unwrap();
        assert_eq!(c.detection.for_resource(Resource::Cpu), Sensitivity::High);
        assert_eq!(
            c.detection.for_resource(Resource::Network),
            Sensitivity::Normal
        );
        assert_eq!(c.detection.for_resource(Resource::Memory), Sensitivity::Low);
        assert_eq!(c.detection.for_resource(Resource::Disk), Sensitivity::Low);
    }

    #[test]
    fn a_typo_in_a_key_is_an_error_not_silently_ignored() {
        let err = Config::from_toml_str("[monitor]\nintervall_secs = 9\n").unwrap_err();
        let ConfigError::Parse(m) = err else {
            panic!("expected a parse error")
        };
        assert!(m.contains("intervall_secs"), "{m}");
        assert!(Config::from_toml_str("[nope]\nx = 1\n").is_err());
    }

    #[test]
    fn wrong_types_and_bad_enum_values_are_parse_errors() {
        assert!(matches!(
            Config::from_toml_str("[monitor]\ninterval_secs = \"fast\"\n"),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::from_toml_str("[detection]\nsensitivity = \"extreme\"\n"),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::from_toml_str("[monitor\n"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn parse_errors_say_where_the_problem_is() {
        let ConfigError::Parse(m) =
            Config::from_toml_str("[monitor]\ninterval_secs = 5\nsignatures = maybe\n")
                .unwrap_err()
        else {
            panic!()
        };
        assert!(m.contains("line 3") || m.contains(":3:"), "{m}");
    }

    #[test]
    fn out_of_range_values_are_rejected_and_all_reported_together() {
        let ConfigError::Invalid(p) = Config::from_toml_str(
            "[monitor]\ninterval_secs = 0\n[retention]\nraw_samples_days = 0\nanomaly_days = 99999\n",
        )
        .unwrap_err() else {
            panic!("expected validation errors")
        };
        assert_eq!(p.len(), 3, "{p:?}");
        assert!(
            p.iter()
                .any(|m| m.contains("interval_secs") && m.contains("got 0"))
        );
        assert!(p.iter().any(|m| m.contains("raw_samples_days")));
        assert!(
            p.iter()
                .any(|m| m.contains("anomaly_days") && m.contains("99999"))
        );
    }

    #[test]
    fn the_interval_boundaries_are_1_and_3600() {
        for ok in [1, 5, 3600] {
            let c = Config {
                monitor: MonitorConfig {
                    interval_secs: ok,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(c.validate().is_ok(), "{ok}");
        }
        for bad in [0, 3601, u64::MAX] {
            let c = Config {
                monitor: MonitorConfig {
                    interval_secs: bad,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(c.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn baseline_windows_must_be_non_empty_positive_and_increasing() {
        for bad in ["[]", "[0, 24]", "[24, 24]", "[24, 1]"] {
            let text = format!("[baseline]\nwindows_hours = {bad}\n");
            assert!(
                matches!(Config::from_toml_str(&text), Err(ConfigError::Invalid(_))),
                "{bad}"
            );
        }
        assert!(Config::from_toml_str("[baseline]\nwindows_hours = [1]\n").is_ok());
    }

    #[test]
    fn confidence_levels_must_be_positive_and_strictly_increasing() {
        for bad in [
            "preliminary_observations = 0",
            "preliminary_minutes = 0",
            "established_observations = 60", // equal to preliminary
            "established_minutes = 5",
            "high_observations = 500", // below established
            "high_minutes = 100",
        ] {
            let text = format!("[baseline.confidence]\n{bad}\n");
            assert!(Config::from_toml_str(&text).is_err(), "{bad}");
        }
        let ok = "[baseline.confidence]\npreliminary_observations = 10\nestablished_observations = 20\n\
                  high_observations = 30\n";
        assert!(Config::from_toml_str(ok).is_ok());
    }

    #[test]
    fn baseline_recompute_interval_is_range_checked() {
        for bad in [0, 1441] {
            let text = format!("[baseline]\nrecompute_minutes = {bad}\n");
            assert!(Config::from_toml_str(&text).is_err(), "{bad}");
        }
        let c = Config::from_toml_str("[baseline]\nrecompute_minutes = 30\n").unwrap();
        assert_eq!(c.baseline.recompute_minutes, 30);
        assert_eq!(Config::default().baseline.recompute_minutes, 15);
    }

    #[test]
    fn an_empty_database_path_is_rejected() {
        assert!(Config::from_toml_str("[storage]\ndatabase = ''\n").is_err());
    }

    #[test]
    fn the_effective_config_round_trips_through_toml() {
        let mut c = Config::default();
        c.monitor.interval_secs = 12;
        c.storage.database = Some(PathBuf::from(r"E:\x\y.db"));
        c.detection.cpu = Some(Sensitivity::High);
        let text = c.to_toml_string();
        assert_eq!(Config::from_toml_str(&text).unwrap(), c);
        assert!(
            !Config::default().to_toml_string().contains("database"),
            "None is omitted"
        );
    }

    #[test]
    fn the_error_message_lists_every_problem() {
        let e = ConfigError::Invalid(vec!["a is bad".into(), "b is bad".into()]);
        let s = e.to_string();
        assert!(
            s.contains("invalid configuration")
                && s.contains("- a is bad")
                && s.contains("- b is bad")
        );
    }
}
