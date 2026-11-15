//! Detection thresholds per sensitivity (PRD FR-015). Plain numbers, so the explanation of an
//! event can name exactly what was exceeded.

use super::BaselineStats;
use crate::config::Sensitivity;

/// MAD to standard-deviation factor for normally distributed data.
const MAD_SCALE: f64 = 1.4826;

/// When CPU use counts as abnormal, and for how long it must last.
///
/// A reading is *elevated* when it is above all three of:
/// 1. the absolute floor,
/// 2. `median + z` robust standard deviations (`1.4826 x MAD`, at least `min_spread`), and
/// 3. `p95_factor x p95`, so a process that often runs near its 95th percentile is not flagged
///    for doing so.
///
/// It becomes an anomaly once it has stayed elevated for `sustain_ms`, tolerating
/// `tolerated_dips` consecutive readings below the line (a single quiet tick does not restart the
/// clock).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuRule {
    pub sensitivity: Sensitivity,
    pub floor_percent: f64,
    pub z: f64,
    pub p95_factor: f64,
    /// Smallest spread (percentage points) used for the z test, so a perfectly flat baseline
    /// (MAD = 0) does not make every wobble look extreme.
    pub min_spread: f64,
    pub sustain_ms: i64,
    pub tolerated_dips: u32,
}

impl CpuRule {
    pub fn for_sensitivity(sensitivity: Sensitivity) -> Self {
        let (floor_percent, z, p95_factor, sustain_secs) = match sensitivity {
            Sensitivity::Low => (10.0, 10.0, 2.0, 300),
            Sensitivity::Normal => (5.0, 6.0, 1.5, 120),
            Sensitivity::High => (3.0, 4.0, 1.2, 60),
        };
        Self {
            sensitivity,
            floor_percent,
            z,
            p95_factor,
            min_spread: 0.5,
            sustain_ms: sustain_secs * 1000,
            tolerated_dips: 1,
        }
    }

    /// The CPU level (percent) above which a reading is elevated for this baseline.
    pub fn threshold(&self, baseline: &BaselineStats) -> f64 {
        let spread = (MAD_SCALE * baseline.mad).max(self.min_spread);
        self.floor_percent
            .max(baseline.median + self.z * spread)
            .max(baseline.p95 * self.p95_factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiler::confidence::Confidence;

    pub(crate) fn baseline(median: f64, mad: f64, p95: f64) -> BaselineStats {
        BaselineStats {
            median,
            mad,
            p95,
            mean: median,
            confidence: Confidence::Established,
            window_hours: 24,
        }
    }

    #[test]
    fn stricter_sensitivity_means_a_higher_and_longer_bar() {
        let b = baseline(8.0, 1.0, 10.0);
        let low = CpuRule::for_sensitivity(Sensitivity::Low);
        let normal = CpuRule::for_sensitivity(Sensitivity::Normal);
        let high = CpuRule::for_sensitivity(Sensitivity::High);
        assert!(low.threshold(&b) > normal.threshold(&b));
        assert!(normal.threshold(&b) > high.threshold(&b));
        assert!(low.sustain_ms > normal.sustain_ms && normal.sustain_ms > high.sustain_ms);
    }

    #[test]
    fn a_quiet_process_is_held_to_the_absolute_floor() {
        // Median 0.5%: statistics alone would flag 2%, the 5% floor does not.
        let rule = CpuRule::for_sensitivity(Sensitivity::Normal);
        assert_eq!(rule.threshold(&baseline(0.5, 0.0, 1.0)), 5.0);
    }

    #[test]
    fn a_noisy_process_gets_a_higher_line_than_a_steady_one() {
        let rule = CpuRule::for_sensitivity(Sensitivity::Normal);
        let steady = rule.threshold(&baseline(8.0, 0.2, 9.0));
        let noisy = rule.threshold(&baseline(8.0, 3.0, 9.0));
        assert!(noisy > steady, "{noisy} vs {steady}");
    }

    #[test]
    fn a_process_that_often_runs_near_its_p95_is_not_flagged_for_it() {
        let rule = CpuRule::for_sensitivity(Sensitivity::Normal);
        let t = rule.threshold(&baseline(5.0, 0.1, 40.0));
        assert_eq!(t, 60.0, "1.5 x p95 dominates");
    }

    #[test]
    fn a_flat_baseline_does_not_collapse_the_spread() {
        let rule = CpuRule {
            p95_factor: 1.0, // isolate the spread test
            ..CpuRule::for_sensitivity(Sensitivity::Normal)
        };
        // MAD 0: the spread falls back to 0.5 points, so 20 + 6 x 0.5 = 23.
        assert_eq!(rule.threshold(&baseline(20.0, 0.0, 20.0)), 23.0);
    }
}
