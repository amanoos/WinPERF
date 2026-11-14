//! Baseline profile of one subject (an executable or an application) over one window.
//!
//! The subject's usage is first summed across all of its running process instances at each tick
//! (so a browser with 30 processes is one series, not 30), then summarized per metric with the
//! statistics in [`super::stats`]. This module is pure: the storage layer feeds it the per-tick
//! series and persists the result.

use super::stats::{Summary, growth_rate, summarize};

/// What a baseline describes. A process instance is too short-lived to have a baseline of its
/// own, so baselines are kept per executable file and per installed application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Executable,
    Application,
}

impl Scope {
    pub const ALL: [Scope; 2] = [Scope::Executable, Scope::Application];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Executable => "executable",
            Scope::Application => "application",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// The metrics a baseline is kept for (PRD FR-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BaselineMetric {
    /// CPU, percent of the whole machine. Memory growth is stored with `Memory`.
    Cpu,
    /// Working set in bytes.
    Memory,
    DiskRead,
    DiskWrite,
    NetRx,
    NetTx,
}

impl BaselineMetric {
    pub const ALL: [BaselineMetric; 6] = [
        BaselineMetric::Cpu,
        BaselineMetric::Memory,
        BaselineMetric::DiskRead,
        BaselineMetric::DiskWrite,
        BaselineMetric::NetRx,
        BaselineMetric::NetTx,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            BaselineMetric::Cpu => "cpu",
            BaselineMetric::Memory => "memory",
            BaselineMetric::DiskRead => "disk_read",
            BaselineMetric::DiskWrite => "disk_write",
            BaselineMetric::NetRx => "net_rx",
            BaselineMetric::NetTx => "net_tx",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// One tick of a subject's usage, summed over its instances. `None` means no instance of the
/// subject had that metric measured at that tick (never "zero").
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TickPoint {
    pub ts_ms: i64,
    pub cpu: Option<f64>,
    pub working_set: Option<f64>,
    pub private_bytes: Option<f64>,
    pub disk_read: Option<f64>,
    pub disk_write: Option<f64>,
    pub net_rx: Option<f64>,
    pub net_tx: Option<f64>,
}

impl TickPoint {
    fn value(&self, metric: BaselineMetric) -> Option<f64> {
        match metric {
            BaselineMetric::Cpu => self.cpu,
            BaselineMetric::Memory => self.working_set,
            BaselineMetric::DiskRead => self.disk_read,
            BaselineMetric::DiskWrite => self.disk_write,
            BaselineMetric::NetRx => self.net_rx,
            BaselineMetric::NetTx => self.net_tx,
        }
    }
}

/// Statistics of one metric.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricBaseline {
    pub metric: BaselineMetric,
    pub stats: Summary,
    /// Typical growth of private (committed) memory in bytes per hour: the Theil-Sen slope over
    /// the window. Only set on `Memory`, and only when private bytes were measured at two or more
    /// distinct times. Negative means shrinking.
    pub growth_per_hour: Option<f64>,
}

/// A subject's baseline over one window.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectBaseline {
    /// Number of ticks at which the subject was running (any metric).
    pub ticks: usize,
    pub first_ts_ms: i64,
    pub last_ts_ms: i64,
    /// One entry per metric that was measured at least once, in [`BaselineMetric::ALL`] order.
    pub metrics: Vec<MetricBaseline>,
}

const MS_PER_HOUR: f64 = 3_600_000.0;

/// Compute the baseline from a subject's per-tick series. `None` when `points` is empty or no
/// metric was ever measured (nothing to baseline).
pub fn compute_baseline(points: &[TickPoint]) -> Option<SubjectBaseline> {
    let first_ts_ms = points.iter().map(|p| p.ts_ms).min()?;
    let last_ts_ms = points.iter().map(|p| p.ts_ms).max()?;

    let mut metrics = Vec::new();
    let mut values = Vec::with_capacity(points.len());
    for metric in BaselineMetric::ALL {
        values.clear();
        values.extend(points.iter().filter_map(|p| p.value(metric)));
        let Some(stats) = summarize(&values) else {
            continue;
        };
        let growth_per_hour = (metric == BaselineMetric::Memory)
            .then(|| private_growth_per_hour(points))
            .flatten();
        metrics.push(MetricBaseline {
            metric,
            stats,
            growth_per_hour,
        });
    }
    if metrics.is_empty() {
        return None;
    }
    Some(SubjectBaseline {
        ticks: points.len(),
        first_ts_ms,
        last_ts_ms,
        metrics,
    })
}

fn private_growth_per_hour(points: &[TickPoint]) -> Option<f64> {
    let series: Vec<(f64, f64)> = points
        .iter()
        .filter_map(|p| Some((p.ts_ms as f64 / MS_PER_HOUR, p.private_bytes?)))
        .collect();
    growth_rate(&series)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(ts_ms: i64, cpu: Option<f64>, ws: Option<f64>, private: Option<f64>) -> TickPoint {
        TickPoint {
            ts_ms,
            cpu,
            working_set: ws,
            private_bytes: private,
            ..Default::default()
        }
    }

    fn metric(b: &SubjectBaseline, m: BaselineMetric) -> Option<&MetricBaseline> {
        b.metrics.iter().find(|x| x.metric == m)
    }

    #[test]
    fn names_round_trip() {
        for s in Scope::ALL {
            assert_eq!(Scope::parse(s.as_str()), Some(s));
        }
        for m in BaselineMetric::ALL {
            assert_eq!(BaselineMetric::parse(m.as_str()), Some(m));
        }
        assert_eq!(Scope::parse("nope"), None);
        assert_eq!(BaselineMetric::parse(""), None);
    }

    #[test]
    fn no_points_or_nothing_measured_gives_no_baseline() {
        assert_eq!(compute_baseline(&[]), None);
        assert_eq!(compute_baseline(&[point(1000, None, None, None)]), None);
    }

    #[test]
    fn statistics_come_from_the_measured_ticks_only() {
        let points = [
            point(0, None, Some(100.0), Some(100.0)), // first tick: no CPU yet
            point(5000, Some(2.0), Some(100.0), Some(100.0)),
            point(10_000, Some(4.0), Some(100.0), Some(100.0)),
            point(15_000, Some(6.0), Some(100.0), Some(100.0)),
        ];
        let b = compute_baseline(&points).unwrap();
        assert_eq!((b.ticks, b.first_ts_ms, b.last_ts_ms), (4, 0, 15_000));
        let cpu = metric(&b, BaselineMetric::Cpu).unwrap();
        assert_eq!(cpu.stats.count, 3);
        assert_eq!(cpu.stats.mean, 4.0);
        assert_eq!(cpu.stats.peak, 6.0);
        assert_eq!(cpu.growth_per_hour, None, "growth belongs to memory only");
    }

    #[test]
    fn unmeasured_metrics_are_left_out_not_zeroed() {
        let b = compute_baseline(&[point(0, Some(1.0), None, None)]).unwrap();
        assert_eq!(b.metrics.len(), 1);
        assert!(metric(&b, BaselineMetric::Memory).is_none());
        assert!(metric(&b, BaselineMetric::NetRx).is_none());
    }

    #[test]
    fn memory_growth_is_private_bytes_per_hour() {
        // +1 MiB every 5 s = 720 MiB per hour, with a one-off spike that must not matter.
        let mib = 1024.0 * 1024.0;
        let mut points: Vec<TickPoint> = (0..20)
            .map(|i| {
                point(
                    i * 5000,
                    Some(1.0),
                    Some(50.0 * mib),
                    Some(100.0 * mib + i as f64 * mib),
                )
            })
            .collect();
        points[7].private_bytes = Some(5000.0 * mib);
        let b = compute_baseline(&points).unwrap();
        let growth = metric(&b, BaselineMetric::Memory)
            .unwrap()
            .growth_per_hour
            .unwrap();
        assert!((growth - 720.0 * mib).abs() < 1.0, "{growth}");
    }

    #[test]
    fn growth_needs_private_bytes_at_two_times() {
        let b = compute_baseline(&[point(0, None, Some(10.0), Some(10.0))]).unwrap();
        assert_eq!(
            metric(&b, BaselineMetric::Memory).unwrap().growth_per_hour,
            None
        );
        let b = compute_baseline(&[
            point(0, None, Some(10.0), None),
            point(5000, None, Some(12.0), None),
        ])
        .unwrap();
        let m = metric(&b, BaselineMetric::Memory).unwrap();
        assert_eq!(m.stats.mean, 11.0);
        assert_eq!(m.growth_per_hour, None);
    }
}
