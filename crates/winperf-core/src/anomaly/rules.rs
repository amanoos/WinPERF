//! Detection thresholds per metric and sensitivity (PRD FR-015). Plain numbers, so the explanation
//! of an event can name exactly what was exceeded.

use super::BaselineStats;
use crate::config::Sensitivity;
use crate::profiler::baseline::BaselineMetric;

/// MAD to standard-deviation factor for normally distributed data.
const MAD_SCALE: f64 = 1.4826;

const KIB: f64 = 1024.0;
const MIB: f64 = 1024.0 * 1024.0;

/// When a resource level counts as abnormal, and for how long it must last.
///
/// A reading is *elevated* when it is above all three of:
/// 1. the absolute floor,
/// 2. `median + z` robust standard deviations (`1.4826 x MAD`, at least `min_spread`), and
/// 3. `p95_factor x p95`, so a process that often runs near its 95th percentile is not flagged
///    for doing so, and
/// 4. `min_ratio x median`, so a resource that naturally swings a lot in relative terms (memory)
///    is only flagged when it is a real multiple of normal, not merely a bit above it.
///
/// It becomes an anomaly once it has stayed elevated for `sustain_ms`, tolerating
/// `tolerated_dips` consecutive readings below the line (a single quiet tick does not restart the
/// clock). Units follow the metric: percent for CPU, bytes for memory, bytes per second for I/O.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LevelRule {
    pub metric: BaselineMetric,
    pub sensitivity: Sensitivity,
    pub floor: f64,
    pub z: f64,
    pub p95_factor: f64,
    /// The reading must also be at least this many times the median (1.0 = no extra condition).
    pub min_ratio: f64,
    /// Smallest spread (in the metric's unit) used for the z test, so a perfectly flat baseline
    /// (MAD = 0) does not make every wobble look extreme.
    pub min_spread: f64,
    pub sustain_ms: i64,
    pub tolerated_dips: u32,
}

impl LevelRule {
    pub fn new(metric: BaselineMetric, sensitivity: Sensitivity) -> Self {
        // Normal-sensitivity figures per metric: floor, minimum spread, seconds of persistence.
        let (floor, min_spread, sustain_secs) = match metric {
            BaselineMetric::Cpu => (5.0, 0.5, 120.0),
            BaselineMetric::Memory => (256.0 * MIB, 16.0 * MIB, 300.0),
            BaselineMetric::DiskRead | BaselineMetric::DiskWrite => {
                (20.0 * MIB, 256.0 * KIB, 120.0)
            }
            BaselineMetric::NetRx | BaselineMetric::NetTx => (5.0 * MIB, 64.0 * KIB, 120.0),
        };
        // Low asks for more and waits longer; High asks for less and reacts sooner.
        let (floor_scale, z, p95_factor, sustain_scale) = match sensitivity {
            Sensitivity::Low => (2.0, 10.0, 2.0, 2.5),
            Sensitivity::Normal => (1.0, 6.0, 1.5, 1.0),
            Sensitivity::High => (0.6, 4.0, 1.2, 0.5),
        };
        // Working-set memory legitimately varies by tens of percent (editors, browsers, shells),
        // so it also has to reach a multiple of normal. Other resources rely on the other tests.
        let min_ratio = match (metric, sensitivity) {
            (BaselineMetric::Memory, Sensitivity::Low) => 3.0,
            (BaselineMetric::Memory, Sensitivity::Normal) => 2.0,
            (BaselineMetric::Memory, Sensitivity::High) => 1.5,
            _ => 1.0,
        };
        Self {
            metric,
            sensitivity,
            floor: floor * floor_scale,
            z,
            p95_factor,
            min_ratio,
            min_spread,
            sustain_ms: (sustain_secs * sustain_scale * 1000.0) as i64,
            tolerated_dips: 1,
        }
    }

    /// The level above which a reading is elevated for this baseline.
    pub fn threshold(&self, baseline: &BaselineStats) -> f64 {
        let spread = (MAD_SCALE * baseline.mad).max(self.min_spread);
        self.floor
            .max(baseline.median + self.z * spread)
            .max(baseline.p95 * self.p95_factor)
            .max(baseline.median * self.min_ratio)
    }

    /// The smallest "normal" used as the denominator when saying how many times above normal a
    /// reading is, so a near-zero baseline does not make the ratio explode.
    pub fn baseline_floor(&self) -> f64 {
        self.min_spread / 5.0
    }
}

/// When steadily rising private memory counts as a *potential* leak (FR-016).
///
/// Over the last `window_ms`, all of these must hold: the fitted growth rate reaches
/// `min_rate_per_hour` (and `baseline_factor` times the subject's usual growth); memory rose in at
/// least `min_rising_fraction` of the steps (a single jump is not a leak); and what was given
/// back is at most `max_reclaim_fraction` of what was taken (a sawtooth is garbage collection, not
/// a leak).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LeakRule {
    pub sensitivity: Sensitivity,
    pub window_ms: i64,
    /// One history point is kept per this much time.
    pub point_every_ms: i64,
    pub min_rate_per_hour: f64,
    pub baseline_factor: f64,
    pub min_rising_fraction: f64,
    pub max_reclaim_fraction: f64,
}

impl LeakRule {
    pub fn new(sensitivity: Sensitivity) -> Self {
        let (window_minutes, min_rate_mib) = match sensitivity {
            Sensitivity::Low => (60, 300.0),
            Sensitivity::Normal => (30, 100.0),
            Sensitivity::High => (15, 30.0),
        };
        Self {
            sensitivity,
            window_ms: window_minutes * 60_000,
            point_every_ms: 30_000,
            min_rate_per_hour: min_rate_mib * MIB,
            baseline_factor: 3.0,
            min_rising_fraction: 0.6,
            max_reclaim_fraction: 0.1,
        }
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
            growth_per_hour: None,
            confidence: Confidence::Established,
            window_hours: 24,
        }
    }

    fn cpu(s: Sensitivity) -> LevelRule {
        LevelRule::new(BaselineMetric::Cpu, s)
    }

    #[test]
    fn cpu_presets_keep_their_documented_values() {
        let (low, normal, high) = (
            cpu(Sensitivity::Low),
            cpu(Sensitivity::Normal),
            cpu(Sensitivity::High),
        );
        assert_eq!(
            (low.floor, low.z, low.p95_factor, low.sustain_ms),
            (10.0, 10.0, 2.0, 300_000)
        );
        assert_eq!(
            (normal.floor, normal.z, normal.p95_factor, normal.sustain_ms),
            (5.0, 6.0, 1.5, 120_000)
        );
        assert_eq!(
            (high.floor, high.z, high.p95_factor, high.sustain_ms),
            (3.0, 4.0, 1.2, 60_000)
        );
    }

    #[test]
    fn stricter_sensitivity_means_a_higher_and_longer_bar_for_every_metric() {
        let b = baseline(8.0, 1.0, 10.0);
        for metric in BaselineMetric::ALL {
            let low = LevelRule::new(metric, Sensitivity::Low);
            let normal = LevelRule::new(metric, Sensitivity::Normal);
            let high = LevelRule::new(metric, Sensitivity::High);
            assert!(low.threshold(&b) > normal.threshold(&b), "{metric:?}");
            assert!(normal.threshold(&b) > high.threshold(&b), "{metric:?}");
            assert!(low.sustain_ms > normal.sustain_ms && normal.sustain_ms > high.sustain_ms);
        }
    }

    #[test]
    fn each_resource_has_a_floor_in_its_own_unit() {
        let b = baseline(0.0, 0.0, 0.0);
        let t = |m| LevelRule::new(m, Sensitivity::Normal).threshold(&b);
        assert_eq!(t(BaselineMetric::Cpu), 5.0);
        assert_eq!(t(BaselineMetric::Memory), 256.0 * MIB);
        assert_eq!(t(BaselineMetric::DiskRead), 20.0 * MIB);
        assert_eq!(t(BaselineMetric::DiskWrite), 20.0 * MIB);
        assert_eq!(t(BaselineMetric::NetRx), 5.0 * MIB);
        assert_eq!(t(BaselineMetric::NetTx), 5.0 * MIB);
    }

    #[test]
    fn a_quiet_process_is_held_to_the_absolute_floor() {
        // Median 0.5%: statistics alone would flag 2%, the 5% floor does not.
        assert_eq!(
            cpu(Sensitivity::Normal).threshold(&baseline(0.5, 0.0, 1.0)),
            5.0
        );
    }

    #[test]
    fn a_noisy_process_gets_a_higher_line_than_a_steady_one() {
        let rule = cpu(Sensitivity::Normal);
        let steady = rule.threshold(&baseline(8.0, 0.2, 9.0));
        let noisy = rule.threshold(&baseline(8.0, 3.0, 9.0));
        assert!(noisy > steady, "{noisy} vs {steady}");
    }

    #[test]
    fn a_process_that_often_runs_near_its_p95_is_not_flagged_for_it() {
        let t = cpu(Sensitivity::Normal).threshold(&baseline(5.0, 0.1, 40.0));
        assert_eq!(t, 60.0, "1.5 x p95 dominates");
    }

    #[test]
    fn memory_must_reach_a_multiple_of_normal() {
        // A 1.6 GiB app at 2.4 GiB (+50%) is ordinary growth at normal sensitivity.
        let b = baseline(1.6 * 1024.0 * MIB, 10.0 * MIB, 1.7 * 1024.0 * MIB);
        let normal = LevelRule::new(BaselineMetric::Memory, Sensitivity::Normal);
        assert!((normal.threshold(&b) - 3.2 * 1024.0 * MIB).abs() < MIB);
        let high = LevelRule::new(BaselineMetric::Memory, Sensitivity::High);
        assert!((high.threshold(&b) - 2.4 * 1024.0 * MIB).abs() < MIB);
        // CPU is unaffected by the ratio.
        assert_eq!(cpu(Sensitivity::Normal).min_ratio, 1.0);
    }

    #[test]
    fn a_flat_baseline_does_not_collapse_the_spread() {
        let rule = LevelRule {
            p95_factor: 1.0, // isolate the spread test
            ..cpu(Sensitivity::Normal)
        };
        // MAD 0: the spread falls back to 0.5 points, so 20 + 6 x 0.5 = 23.
        assert_eq!(rule.threshold(&baseline(20.0, 0.0, 20.0)), 23.0);
    }

    #[test]
    fn leak_rules_get_stricter_with_lower_sensitivity() {
        let (low, normal, high) = (
            LeakRule::new(Sensitivity::Low),
            LeakRule::new(Sensitivity::Normal),
            LeakRule::new(Sensitivity::High),
        );
        assert!(low.window_ms > normal.window_ms && normal.window_ms > high.window_ms);
        assert!(low.min_rate_per_hour > normal.min_rate_per_hour);
        assert!(normal.min_rate_per_hour > high.min_rate_per_hour);
        assert_eq!(normal.window_ms, 30 * 60_000);
        assert_eq!(normal.min_rate_per_hour, 100.0 * MIB);
    }
}
