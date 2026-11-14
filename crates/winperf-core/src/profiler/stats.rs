//! Summary statistics and growth rate over a window of values (pure, no I/O).
//!
//! Non-finite inputs (NaN, infinities) are treated as "not measured" and skipped, the same way
//! `Metric::Unavailable` is stored as NULL. Callers that care how many values were dropped can
//! compare `Summary::count` with their input length.

use std::cmp::Ordering;

/// Largest number of points the growth-rate fit looks at. The fit compares every pair of points
/// (quadratic), so longer windows are thinned evenly down to this many.
pub const MAX_GROWTH_POINTS: usize = 256;

/// Summary of one window of values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    /// Number of finite values summarized.
    pub count: usize,
    pub min: f64,
    /// Highest value seen (the peak).
    pub peak: f64,
    pub mean: f64,
    pub median: f64,
    /// Median absolute deviation from the median, unscaled. Robust: one wild spike barely moves it.
    pub mad: f64,
    /// Sample standard deviation (n - 1); 0 for a single value.
    pub stddev: f64,
    /// 95th percentile, linearly interpolated between neighbouring ranks.
    pub p95: f64,
}

/// Summarize `values`. `None` when there is no finite value. Allocates one buffer (sorted once).
pub fn summarize(values: &[f64]) -> Option<Summary> {
    let mut buf: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if buf.is_empty() {
        return None;
    }
    buf.sort_unstable_by(f64::total_cmp);
    let n = buf.len();

    let mean = buf.iter().sum::<f64>() / n as f64;
    let stddev = if n > 1 {
        let ss: f64 = buf.iter().map(|v| (v - mean).powi(2)).sum();
        (ss / (n - 1) as f64).sqrt()
    } else {
        0.0
    };
    let median = median_of_sorted(&buf);
    let p95 = percentile_of_sorted(&buf, 0.95);
    let (min, peak) = (buf[0], buf[n - 1]);

    // Reuse the buffer for the deviations; everything that needs order is already computed.
    for v in &mut buf {
        *v = (*v - median).abs();
    }
    let mad = median_of_unsorted(&mut buf);

    Some(Summary {
        count: n,
        min,
        peak,
        mean,
        median,
        mad,
        stddev,
        p95,
    })
}

/// Growth rate of `(x, y)` points: the Theil-Sen slope (median of all pairwise slopes), in y
/// units per x unit. Robust to outliers: a few spikes do not tilt it. `None` with fewer than two
/// usable points or when every x is the same. Non-finite points are skipped; windows longer than
/// [`MAX_GROWTH_POINTS`] are thinned evenly. Points need not be sorted.
pub fn growth_rate(points: &[(f64, f64)]) -> Option<f64> {
    let usable = || {
        points
            .iter()
            .copied()
            .filter(|(x, y)| x.is_finite() && y.is_finite())
    };
    let total = usable().count();
    if total < 2 {
        return None;
    }
    let kept: Vec<(f64, f64)> = if total <= MAX_GROWTH_POINTS {
        usable().collect()
    } else {
        let all: Vec<(f64, f64)> = usable().collect();
        (0..MAX_GROWTH_POINTS)
            .map(|i| all[i * (total - 1) / (MAX_GROWTH_POINTS - 1)])
            .collect()
    };

    let mut slopes = Vec::with_capacity(kept.len() * (kept.len() - 1) / 2);
    for (i, &(x1, y1)) in kept.iter().enumerate() {
        for &(x2, y2) in &kept[i + 1..] {
            let dx = x2 - x1;
            if dx != 0.0 {
                slopes.push((y2 - y1) / dx);
            }
        }
    }
    if slopes.is_empty() {
        return None;
    }
    Some(median_of_unsorted(&mut slopes))
}

fn median_of_sorted(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// Median without a full sort (partial selection). Reorders `values`. Must be non-empty.
fn median_of_unsorted(values: &mut [f64]) -> f64 {
    let n = values.len();
    let mid = n / 2;
    let (lower, hi, _) = values.select_nth_unstable_by(mid, f64::total_cmp);
    let hi = *hi;
    if n % 2 == 1 {
        hi
    } else {
        let lo = lower
            .iter()
            .copied()
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
            .unwrap_or(hi);
        (lo + hi) / 2.0
    }
}

/// Linear-interpolation percentile (`q` in 0..=1). Always within `[sorted[0], sorted[n-1]]`.
fn percentile_of_sorted(sorted: &[f64], q: f64) -> f64 {
    let rank = q.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let frac = rank - lo as f64;
    let value = sorted[lo] + (sorted[hi] - sorted[lo]) * frac;
    value.clamp(sorted[0], sorted[sorted.len() - 1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn known_answers() {
        struct Case {
            values: &'static [f64],
            mean: f64,
            median: f64,
            mad: f64,
            stddev: f64,
            p95: f64,
            peak: f64,
        }
        let table = [
            Case {
                values: &[1.0, 2.0, 3.0, 4.0, 5.0],
                mean: 3.0,
                median: 3.0,
                mad: 1.0,
                stddev: 2.5f64.sqrt(),
                p95: 4.8,
                peak: 5.0,
            },
            Case {
                values: &[1.0, 2.0, 3.0, 4.0],
                mean: 2.5,
                median: 2.5,
                mad: 1.0,
                stddev: (5.0f64 / 3.0).sqrt(),
                p95: 3.85,
                peak: 4.0,
            },
            Case {
                values: &[5.0, 1.0, 4.0, 2.0, 3.0],
                mean: 3.0,
                median: 3.0,
                mad: 1.0,
                stddev: 2.5f64.sqrt(),
                p95: 4.8,
                peak: 5.0,
            },
            Case {
                values: &[1.0, 1.0, 1.0, 1.0, 100.0],
                mean: 20.8,
                median: 1.0,
                mad: 0.0,
                stddev: 44.28,
                p95: 80.2,
                peak: 100.0,
            },
        ];
        for c in &table {
            let (s, v) = (summarize(c.values).unwrap(), c.values);
            assert_eq!(s.count, v.len());
            assert!(close(s.mean, c.mean), "{v:?} mean {}", s.mean);
            assert!(close(s.median, c.median), "{v:?} median {}", s.median);
            assert!(close(s.mad, c.mad), "{v:?} mad {}", s.mad);
            assert!((s.stddev - c.stddev).abs() < 0.01, "{v:?} sd {}", s.stddev);
            assert!(close(s.p95, c.p95), "{v:?} p95 {}", s.p95);
            assert!(close(s.peak, c.peak), "{v:?} peak {}", s.peak);
        }
    }

    #[test]
    fn empty_and_all_non_finite_have_no_summary() {
        assert_eq!(summarize(&[]), None);
        assert_eq!(
            summarize(&[f64::NAN, f64::INFINITY, f64::NEG_INFINITY]),
            None
        );
    }

    #[test]
    fn a_single_value_summarizes_to_itself() {
        let s = summarize(&[7.5]).unwrap();
        assert_eq!(s.count, 1);
        assert!(
            [s.min, s.peak, s.mean, s.median, s.p95]
                .iter()
                .all(|v| *v == 7.5)
        );
        assert_eq!(s.mad, 0.0);
        assert_eq!(s.stddev, 0.0);
    }

    #[test]
    fn non_finite_values_are_skipped_not_poisoning() {
        let s = summarize(&[1.0, f64::NAN, 3.0, f64::INFINITY]).unwrap();
        assert_eq!(s.count, 2);
        assert!(close(s.mean, 2.0));
        assert!(close(s.peak, 3.0));
    }

    #[test]
    fn a_spike_moves_the_mean_but_not_the_median_or_mad() {
        let calm = summarize(&[10.0, 11.0, 9.0, 10.0, 10.0, 11.0, 9.0]).unwrap();
        let spiky = summarize(&[10.0, 11.0, 9.0, 10.0, 10.0, 11.0, 9.0, 1000.0]).unwrap();
        assert!(spiky.mean > calm.mean * 10.0);
        assert!(spiky.median - calm.median <= 0.5);
        assert!(spiky.mad - calm.mad <= 0.5);
    }

    #[test]
    fn growth_of_a_straight_line_is_its_slope() {
        let pts: Vec<(f64, f64)> = (0..10).map(|i| (i as f64, 2.0 * i as f64 + 1.0)).collect();
        assert!(close(growth_rate(&pts).unwrap(), 2.0));
        let falling: Vec<(f64, f64)> = (0..10).map(|i| (i as f64, 50.0 - 3.0 * i as f64)).collect();
        assert!(close(growth_rate(&falling).unwrap(), -3.0));
        let flat: Vec<(f64, f64)> = (0..10).map(|i| (i as f64, 4.0)).collect();
        assert!(close(growth_rate(&flat).unwrap(), 0.0));
    }

    #[test]
    fn growth_ignores_a_spike() {
        let mut pts: Vec<(f64, f64)> = (0..6).map(|i| (i as f64, 2.0 * i as f64)).collect();
        pts[3].1 = 100.0;
        assert!(close(growth_rate(&pts).unwrap(), 2.0));
    }

    #[test]
    fn growth_needs_two_points_at_different_times() {
        assert_eq!(growth_rate(&[]), None);
        assert_eq!(growth_rate(&[(1.0, 1.0)]), None);
        assert_eq!(growth_rate(&[(1.0, 1.0), (1.0, 5.0)]), None);
        assert_eq!(growth_rate(&[(1.0, 1.0), (f64::NAN, 5.0)]), None);
    }

    #[test]
    fn growth_accepts_unsorted_points_and_thins_long_windows() {
        let pts = [(3.0, 6.0), (0.0, 0.0), (2.0, 4.0), (1.0, 2.0)];
        assert!(close(growth_rate(&pts).unwrap(), 2.0));
        let long: Vec<(f64, f64)> = (0..5000).map(|i| (i as f64, 0.5 * i as f64)).collect();
        assert!(close(growth_rate(&long).unwrap(), 0.5));
    }

    proptest! {
        #[test]
        fn percentile_and_central_values_stay_inside_min_max(
            values in prop::collection::vec(-1.0e6f64..1.0e6, 1..200)
        ) {
            let s = summarize(&values).unwrap();
            for v in [s.p95, s.median, s.mean] {
                prop_assert!(v >= s.min - 1e-6 && v <= s.peak + 1e-6, "{v} outside [{}, {}]", s.min, s.peak);
            }
            prop_assert!(s.p95 >= s.median - 1e-9);
            prop_assert!(s.mad >= 0.0 && s.stddev >= 0.0);
        }

        #[test]
        fn summary_does_not_depend_on_input_order(
            values in prop::collection::vec(-1.0e3f64..1.0e3, 1..100)
        ) {
            let mut reversed = values.clone();
            reversed.reverse();
            let (a, b) = (summarize(&values).unwrap(), summarize(&reversed).unwrap());
            prop_assert_eq!(a.median, b.median);
            prop_assert_eq!(a.mad, b.mad);
            prop_assert_eq!(a.p95, b.p95);
            prop_assert!((a.mean - b.mean).abs() < 1e-6);
        }
    }
}
