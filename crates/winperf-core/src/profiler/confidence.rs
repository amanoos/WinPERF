//! How far a baseline can be trusted, from how much history is behind it (PRD FR-013).

use crate::config::ConfidenceConfig;

/// Ordered from least to most trusted, so levels compare (`Established > Preliminary`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Too little history to say what is normal. Anomalies are not raised against it.
    Insufficient,
    Preliminary,
    Established,
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Insufficient => "Insufficient",
            Confidence::Preliminary => "Preliminary",
            Confidence::Established => "Established",
            Confidence::High => "High",
        }
    }

    /// Whether detection may use a baseline of this level.
    pub fn is_usable(self) -> bool {
        self > Confidence::Insufficient
    }
}

const MS_PER_MINUTE: i64 = 60_000;

/// The highest level whose observation count and span are both met. `span_ms` is the time from
/// the first to the last observation (a negative span counts as none).
pub fn assess(observations: u64, span_ms: i64, thresholds: &ConfidenceConfig) -> Confidence {
    let minutes = u64::try_from(span_ms.max(0) / MS_PER_MINUTE).unwrap_or(0);
    let reached = |obs: u64, mins: u64| observations >= obs && minutes >= mins;
    if reached(thresholds.high_observations, thresholds.high_minutes) {
        Confidence::High
    } else if reached(
        thresholds.established_observations,
        thresholds.established_minutes,
    ) {
        Confidence::Established
    } else if reached(
        thresholds.preliminary_observations,
        thresholds.preliminary_minutes,
    ) {
        Confidence::Preliminary
    } else {
        Confidence::Insufficient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = MS_PER_MINUTE;

    fn level(observations: u64, span_minutes: i64) -> Confidence {
        assess(
            observations,
            span_minutes * MIN,
            &ConfidenceConfig::default(),
        )
    }

    #[test]
    fn each_boundary_needs_both_count_and_span() {
        use Confidence::*;
        // Defaults: 60 obs / 5 min, 1000 obs / 120 min, 10000 obs / 1440 min.
        let table = [
            (0, 0, Insufficient),
            (59, 5, Insufficient), // one observation short
            (60, 4, Insufficient), // one minute short
            (60, 5, Preliminary),  // exactly on the line
            (999, 500, Preliminary),
            (1000, 119, Preliminary),
            (1000, 120, Established),
            (9999, 5000, Established),
            (10_000, 1439, Established),
            (10_000, 1440, High),
            (1_000_000, 100_000, High),
        ];
        for (obs, mins, expected) in table {
            assert_eq!(
                level(obs, mins),
                expected,
                "{obs} observations over {mins} min"
            );
        }
    }

    #[test]
    fn a_burst_of_samples_in_a_short_span_is_not_trusted() {
        assert_eq!(level(50_000, 2), Confidence::Insufficient);
    }

    #[test]
    fn a_negative_span_counts_as_none_and_partial_minutes_round_down() {
        let c = ConfidenceConfig::default();
        assert_eq!(assess(100, -5 * MIN, &c), Confidence::Insufficient);
        assert_eq!(assess(100, 5 * MIN - 1, &c), Confidence::Insufficient);
        assert_eq!(assess(100, 5 * MIN, &c), Confidence::Preliminary);
    }

    #[test]
    fn thresholds_come_from_the_configuration() {
        let c = ConfidenceConfig {
            preliminary_observations: 2,
            preliminary_minutes: 1,
            established_observations: 3,
            established_minutes: 2,
            high_observations: 4,
            high_minutes: 3,
        };
        assert_eq!(assess(4, 3 * MIN, &c), Confidence::High);
        assert_eq!(assess(2, MIN, &c), Confidence::Preliminary);
    }

    #[test]
    fn levels_order_and_only_insufficient_is_unusable() {
        assert!(Confidence::High > Confidence::Established);
        assert!(Confidence::Established > Confidence::Preliminary);
        assert!(Confidence::Preliminary > Confidence::Insufficient);
        assert!(!Confidence::Insufficient.is_usable());
        assert!(Confidence::Preliminary.is_usable());
        assert_eq!(Confidence::Insufficient.label(), "Insufficient");
    }
}
