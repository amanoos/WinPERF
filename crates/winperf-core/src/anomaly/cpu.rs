//! The CPU detector (PRD FR-015): a reading is elevated when it clears the rule's threshold for
//! its baseline, and an anomaly is raised once a subject has stayed elevated for long enough.
//! One event per episode: it fires once and re-arms only after the subject has calmed down.

use super::BaselineStats;
use super::rules::CpuRule;
use crate::ProcessKey;
use crate::time::format_span;
use std::collections::HashMap;

/// A subject's CPU use at one tick, summed over its running instances.
#[derive(Debug, Clone, Copy)]
pub struct Reading<'a> {
    /// The subject's identity (the lower-cased executable path).
    pub subject: &'a str,
    pub cpu_percent: f64,
    /// The instance using the most CPU right now.
    pub top: ProcessKey,
    pub name: &'a str,
    pub exe_path: &'a str,
}

/// A subject that has been abnormal long enough.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub ts_ms: i64,
    pub name: String,
    pub exe_path: String,
    pub top: ProcessKey,
    /// Mean CPU over the abnormal stretch, percent.
    pub current: f64,
    pub peak: f64,
    pub duration_ms: i64,
    /// The line it had to stay above, percent.
    pub threshold: f64,
    pub baseline: BaselineStats,
    pub rule: CpuRule,
}

struct Episode {
    first_ts_ms: i64,
    sum: f64,
    count: u32,
    peak: f64,
    /// Consecutive readings below the line.
    dips: u32,
    fired: bool,
    last_tick: u64,
}

pub struct CpuDetector {
    rule: CpuRule,
    episodes: HashMap<String, Episode>,
    tick: u64,
}

impl CpuDetector {
    pub fn new(rule: CpuRule) -> Self {
        Self {
            rule,
            episodes: HashMap::new(),
            tick: 0,
        }
    }

    pub fn rule(&self) -> &CpuRule {
        &self.rule
    }

    /// Forget every episode in progress (detection was paused).
    pub fn reset(&mut self) {
        self.episodes.clear();
    }

    /// Feed one tick. `baselines` holds only usable baselines, by subject: a subject without one
    /// is never judged. A subject missing from `readings` counts as quiet for this tick.
    pub fn observe_tick(
        &mut self,
        ts_ms: i64,
        readings: &[Reading<'_>],
        baselines: &HashMap<String, BaselineStats>,
    ) -> Vec<Detection> {
        self.tick += 1;
        let tick = self.tick;
        let mut raised = Vec::new();

        for r in readings {
            let Some(baseline) = baselines.get(r.subject) else {
                self.episodes.remove(r.subject);
                continue;
            };
            let threshold = self.rule.threshold(baseline);
            if r.cpu_percent > threshold {
                let ep = self
                    .episodes
                    .entry(r.subject.to_string())
                    .or_insert_with(|| Episode {
                        first_ts_ms: ts_ms,
                        sum: 0.0,
                        count: 0,
                        peak: 0.0,
                        dips: 0,
                        fired: false,
                        last_tick: tick,
                    });
                ep.dips = 0;
                ep.last_tick = tick;
                ep.sum += r.cpu_percent;
                ep.count += 1;
                ep.peak = ep.peak.max(r.cpu_percent);
                let lasted = ts_ms - ep.first_ts_ms;
                if !ep.fired && lasted >= self.rule.sustain_ms {
                    ep.fired = true;
                    raised.push(Detection {
                        ts_ms,
                        name: r.name.to_string(),
                        exe_path: r.exe_path.to_string(),
                        top: r.top,
                        current: ep.sum / f64::from(ep.count),
                        peak: ep.peak,
                        duration_ms: lasted,
                        threshold,
                        baseline: baseline.clone(),
                        rule: self.rule,
                    });
                }
            } else if let Some(ep) = self.episodes.get_mut(r.subject) {
                ep.dips += 1;
                ep.last_tick = tick;
            }
        }

        // Subjects that were not seen at all this tick (their processes ended) were quiet too.
        let tolerated = self.rule.tolerated_dips;
        self.episodes.retain(|_, ep| {
            if ep.last_tick != tick {
                ep.dips += 1;
            }
            ep.dips <= tolerated
        });
        raised
    }
}

fn window_label(hours: u32) -> String {
    if hours > 24 && hours.is_multiple_of(24) {
        format!("{} d", hours / 24)
    } else {
        format!("{hours} h")
    }
}

/// How far above normal, in percent of the baseline median. A near-zero median is treated as 0.1%
/// so the figure stays finite.
pub fn deviation_percent(current: f64, baseline_median: f64) -> f64 {
    (current / baseline_median.max(0.1) - 1.0) * 100.0
}

/// The plain-language reason an event was raised (FR-018).
pub fn explain(d: &Detection) -> String {
    let b = &d.baseline;
    let times = d.current / b.median.max(0.1);
    format!(
        "{} used {:.1}% CPU on average for {}, against a normal level of {:.1}% (median over the \
         last {}; 95th percentile {:.1}%). That is {:.1}x its usual level and above the {:.1}% \
         alert line for {} sensitivity. Baseline confidence: {}.",
        d.name,
        d.current,
        format_span(d.duration_ms),
        b.median,
        window_label(b.window_hours),
        b.p95,
        times,
        d.threshold,
        match d.rule.sensitivity {
            crate::config::Sensitivity::Low => "low",
            crate::config::Sensitivity::Normal => "normal",
            crate::config::Sensitivity::High => "high",
        },
        b.confidence.label(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Sensitivity;
    use crate::profiler::confidence::Confidence;

    const SUBJECT: &str = r"c:\apps\busy.exe";
    const TICK_MS: i64 = 5_000;

    fn baseline(median: f64, mad: f64, p95: f64) -> HashMap<String, BaselineStats> {
        HashMap::from([(
            SUBJECT.to_string(),
            BaselineStats {
                median,
                mad,
                p95,
                mean: median,
                confidence: Confidence::Established,
                window_hours: 24,
            },
        )])
    }

    fn reading(cpu: f64) -> Reading<'static> {
        Reading {
            subject: SUBJECT,
            cpu_percent: cpu,
            top: ProcessKey::new(42, 7),
            name: "busy.exe",
            exe_path: r"C:\apps\busy.exe",
        }
    }

    /// Feed one reading per 5 s tick; returns every detection with the tick it came at.
    fn run(
        det: &mut CpuDetector,
        b: &HashMap<String, BaselineStats>,
        cpu: &[f64],
    ) -> Vec<(usize, Detection)> {
        let mut out = Vec::new();
        for (i, c) in cpu.iter().enumerate() {
            let ts = i as i64 * TICK_MS;
            for d in det.observe_tick(ts, &[reading(*c)], b) {
                out.push((i, d));
            }
        }
        out
    }

    fn normal() -> CpuDetector {
        CpuDetector::new(CpuRule::for_sensitivity(Sensitivity::Normal))
    }

    #[test]
    fn a_brief_spike_is_not_an_anomaly() {
        let b = baseline(8.0, 1.0, 10.0);
        let mut cpu = vec![8.0; 20];
        cpu.extend([90.0; 6]); // 25 s above the line, far short of two minutes
        cpu.extend([8.0; 20]);
        assert!(run(&mut normal(), &b, &cpu).is_empty());
    }

    #[test]
    fn a_quiet_process_rising_to_two_percent_is_not_an_anomaly() {
        let b = baseline(0.5, 0.1, 1.0);
        let cpu = vec![2.0; 200]; // 4x its normal, but under the 5% floor, for 16 minutes
        assert!(run(&mut normal(), &b, &cpu).is_empty());
    }

    #[test]
    fn eight_to_seventy_two_percent_for_three_minutes_raises_one_event() {
        let b = baseline(8.0, 1.0, 10.0);
        let mut cpu = vec![8.0; 12];
        cpu.extend([72.0; 36]); // 3 minutes
        let hits = run(&mut normal(), &b, &cpu);

        assert_eq!(hits.len(), 1, "one event per episode, not one per tick");
        let (tick, d) = &hits[0];
        assert_eq!(*tick, 12 + 24, "raised once 2 minutes of it have passed");
        assert_eq!(d.duration_ms, 120_000);
        assert_eq!(d.current, 72.0);
        assert_eq!(d.baseline.median, 8.0);
        assert_eq!(d.top, ProcessKey::new(42, 7));
        assert!(d.threshold < 72.0);
    }

    #[test]
    fn it_can_fire_again_after_the_process_has_calmed_down() {
        let b = baseline(8.0, 1.0, 10.0);
        let mut cpu = vec![72.0; 30];
        cpu.extend([8.0; 5]); // calm: well past the tolerated single dip
        cpu.extend([72.0; 30]);
        assert_eq!(run(&mut normal(), &b, &cpu).len(), 2);
    }

    #[test]
    fn one_quiet_tick_does_not_restart_the_clock_but_two_do() {
        let b = baseline(8.0, 1.0, 10.0);

        let mut one_dip = vec![72.0; 10];
        one_dip.push(8.0);
        one_dip.extend([72.0; 20]);
        assert_eq!(run(&mut normal(), &b, &one_dip).len(), 1);

        let mut two_dips = vec![72.0; 10];
        two_dips.extend([8.0, 8.0]);
        two_dips.extend([72.0; 20]); // 100 s since the restart: not enough
        assert!(run(&mut normal(), &b, &two_dips).is_empty());
    }

    #[test]
    fn a_subject_without_a_usable_baseline_is_never_judged() {
        let none = HashMap::new();
        assert!(run(&mut normal(), &none, &[99.0; 100]).is_empty());
    }

    #[test]
    fn losing_the_baseline_mid_episode_drops_the_episode() {
        let b = baseline(8.0, 1.0, 10.0);
        let mut det = normal();
        assert!(run(&mut det, &b, &[72.0; 20]).is_empty());
        assert!(
            det.observe_tick(0, &[reading(72.0)], &HashMap::new())
                .is_empty()
        );
        // The earlier 100 s no longer count: 20 more ticks (100 s) are still short of 120 s.
        assert!(run(&mut det, &b, &[72.0; 20]).is_empty());
    }

    #[test]
    fn a_subject_that_disappears_counts_as_quiet() {
        let b = baseline(8.0, 1.0, 10.0);
        let mut det = normal();
        for i in 0..20 {
            det.observe_tick(i * TICK_MS, &[reading(72.0)], &b);
        }
        // Gone for three ticks, then back: the stretch before it must not be carried over.
        for i in 20..23 {
            det.observe_tick(i * TICK_MS, &[], &b);
        }
        let mut hits = 0;
        for i in 23..43 {
            hits += det.observe_tick(i * TICK_MS, &[reading(72.0)], &b).len();
        }
        assert_eq!(hits, 0, "only 100 s since it came back");
    }

    #[test]
    fn high_sensitivity_reacts_sooner_to_a_smaller_rise() {
        let b = baseline(8.0, 1.0, 10.0);
        let cpu = vec![14.0; 40]; // 14% is under the Normal line, over the High one
        assert!(run(&mut normal(), &b, &cpu).is_empty());
        let mut high = CpuDetector::new(CpuRule::for_sensitivity(Sensitivity::High));
        let hits = run(&mut high, &b, &cpu);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1.duration_ms, 60_000);
    }

    #[test]
    fn instances_of_a_subject_are_judged_together_by_the_caller_summing_them() {
        // The detector sees the summed reading; the busiest instance is only for reporting.
        let b = baseline(8.0, 1.0, 10.0);
        let mut det = normal();
        let mut r = reading(72.0);
        r.top = ProcessKey::new(99, 1);
        let mut found = None;
        for i in 0..40 {
            if let Some(d) = det.observe_tick(i * TICK_MS, &[r], &b).pop() {
                found = Some(d);
            }
        }
        assert_eq!(found.unwrap().top, ProcessKey::new(99, 1));
    }

    #[test]
    fn the_explanation_names_the_numbers_behind_the_event() {
        let b = baseline(8.0, 1.0, 10.0);
        let hits = run(&mut normal(), &b, &[72.0; 30]);
        let text = explain(&hits[0].1);
        for expected in [
            "busy.exe",
            "72.0%",
            "2m 00s",
            "8.0%",
            "24 h",
            "9.0x",
            "normal sensitivity",
            "Established",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
    }

    #[test]
    fn deviation_is_relative_to_the_baseline_and_stays_finite_for_a_zero_baseline() {
        assert_eq!(deviation_percent(72.0, 8.0), 800.0);
        assert!(deviation_percent(10.0, 0.0).is_finite());
        assert_eq!(window_label(168), "7 d");
        assert_eq!(window_label(1), "1 h");
    }
}
