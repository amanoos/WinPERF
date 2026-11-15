//! The potential-memory-leak detector (PRD FR-016): a process whose private memory keeps climbing
//! steadily and is never given back.
//!
//! It works per process instance, because instances starting and ending would otherwise look like
//! growth and reclamation. For each instance it keeps a thinned history of private bytes over the
//! rule's window and, each time a point is added, asks three questions of the whole window:
//! is the fitted growth rate high enough (and well above this subject's usual growth), did memory
//! rise in most steps (one jump is not a leak), and was little of it given back (a sawtooth is
//! garbage collection)? Only when all three say yes does it fire, once per episode. The wording is
//! always "potential": growth alone cannot prove a leak.

use super::BaselineStats;
use super::format::{bytes, window_label};
use super::level::sensitivity_word;
use super::rules::LeakRule;
use crate::ProcessKey;
use crate::profiler::stats::growth_rate;
use crate::time::format_span;
use std::collections::{HashMap, VecDeque};

const MS_PER_HOUR: f64 = 3_600_000.0;

/// One instance's private memory at one tick, with the baseline of the executable it belongs to.
#[derive(Debug, Clone, Copy)]
pub struct LeakReading<'a> {
    pub key: ProcessKey,
    pub private_bytes: f64,
    pub name: &'a str,
    pub exe_path: &'a str,
    pub baseline: &'a BaselineStats,
}

/// An instance that looks like it is leaking.
#[derive(Debug, Clone, PartialEq)]
pub struct LeakDetection {
    pub ts_ms: i64,
    pub key: ProcessKey,
    pub name: String,
    pub exe_path: String,
    /// Private bytes now.
    pub current_bytes: f64,
    /// Bytes gained from the start to the end of the window.
    pub gained_bytes: f64,
    /// The fitted growth rate, bytes per hour.
    pub rate_per_hour: f64,
    /// This subject's usual growth rate (never below zero), bytes per hour.
    pub usual_rate_per_hour: f64,
    pub span_ms: i64,
    /// Share of steps in which memory rose.
    pub rising_fraction: f64,
    /// Bytes given back as a share of bytes taken.
    pub reclaimed_fraction: f64,
    pub baseline: BaselineStats,
    pub rule: LeakRule,
}

struct Track {
    /// (time ms, private bytes), one point per `point_every_ms`, covering about the window.
    points: VecDeque<(i64, f64)>,
    fired: bool,
    last_tick: u64,
}

pub struct LeakDetector {
    rule: LeakRule,
    tracks: HashMap<ProcessKey, Track>,
    tick: u64,
}

struct Verdict {
    rate_per_hour: f64,
    gained: f64,
    rising_fraction: f64,
    reclaimed_fraction: f64,
}

impl LeakDetector {
    pub fn new(rule: LeakRule) -> Self {
        Self {
            rule,
            tracks: HashMap::new(),
            tick: 0,
        }
    }

    pub fn rule(&self) -> &LeakRule {
        &self.rule
    }

    /// Forget every history (detection was paused).
    pub fn reset(&mut self) {
        self.tracks.clear();
    }

    /// Feed one tick. Only instances whose subject has a usable memory baseline belong in
    /// `readings`; an instance that is absent loses its history.
    pub fn observe_tick(&mut self, ts_ms: i64, readings: &[LeakReading<'_>]) -> Vec<LeakDetection> {
        self.tick += 1;
        let tick = self.tick;
        let mut raised = Vec::new();

        for r in readings {
            let track = self.tracks.entry(r.key).or_insert_with(|| Track {
                points: VecDeque::new(),
                fired: false,
                last_tick: tick,
            });
            track.last_tick = tick;
            let due = track
                .points
                .back()
                .is_none_or(|(last, _)| ts_ms - last >= self.rule.point_every_ms);
            if !due {
                continue;
            }
            track.points.push_back((ts_ms, r.private_bytes));
            // Keep one point at or before the start of the window so the span is the full window.
            while track.points.len() >= 2 && track.points[1].0 <= ts_ms - self.rule.window_ms {
                track.points.pop_front();
            }
            let usual = r.baseline.growth_per_hour.unwrap_or(0.0).max(0.0);
            match assess(&track.points, &self.rule, usual) {
                Some(v) if !track.fired => {
                    track.fired = true;
                    raised.push(LeakDetection {
                        ts_ms,
                        key: r.key,
                        name: r.name.to_string(),
                        exe_path: r.exe_path.to_string(),
                        current_bytes: r.private_bytes,
                        gained_bytes: v.gained,
                        rate_per_hour: v.rate_per_hour,
                        usual_rate_per_hour: usual,
                        span_ms: ts_ms - track.points[0].0,
                        rising_fraction: v.rising_fraction,
                        reclaimed_fraction: v.reclaimed_fraction,
                        baseline: r.baseline.clone(),
                        rule: self.rule,
                    });
                }
                Some(_) => {}
                None => track.fired = false, // reclaimed or levelled off: the episode is over
            }
        }

        self.tracks.retain(|_, t| t.last_tick == tick);
        raised
    }
}

/// Judge one window of history. `None` unless it covers the whole window and passes all tests.
fn assess(points: &VecDeque<(i64, f64)>, rule: &LeakRule, usual_rate: f64) -> Option<Verdict> {
    let (first, last) = (points.front()?, points.back()?);
    if last.0 - first.0 < rule.window_ms || points.len() < 3 {
        return None;
    }
    let (mut rising, mut taken, mut given_back) = (0usize, 0.0, 0.0);
    for w in points.iter().zip(points.iter().skip(1)) {
        let step = w.1.1 - w.0.1;
        if step > 0.0 {
            rising += 1;
            taken += step;
        } else {
            given_back -= step;
        }
    }
    let steps = points.len() - 1;
    let rising_fraction = rising as f64 / steps as f64;
    if rising_fraction < rule.min_rising_fraction || given_back > rule.max_reclaim_fraction * taken
    {
        return None;
    }
    let series: Vec<(f64, f64)> = points
        .iter()
        .map(|(t, b)| (*t as f64 / MS_PER_HOUR, *b))
        .collect();
    let rate_per_hour = growth_rate(&series)?;
    if rate_per_hour
        < rule
            .min_rate_per_hour
            .max(rule.baseline_factor * usual_rate)
    {
        return None;
    }
    Some(Verdict {
        rate_per_hour,
        gained: last.1 - first.1,
        rising_fraction,
        reclaimed_fraction: if taken > 0.0 { given_back / taken } else { 0.0 },
    })
}

/// The plain-language reason a leak event was raised (FR-016, FR-018).
pub fn explain(d: &LeakDetection) -> String {
    format!(
        "Potential memory leak: {} (PID {}) grew its private memory by {} over {} (about {}/h, \
         now {}). It rose in {:.0}% of the steps and gave back only {:.0}% of what it took, and \
         its usual growth is {}/h (baseline over the last {}). Growth like this can also be \
         legitimate work, so this is a potential leak, not a confirmed one. Detected at {} \
         sensitivity; baseline confidence: {}.",
        d.name,
        d.key.pid,
        bytes(d.gained_bytes),
        format_span(d.span_ms),
        bytes(d.rate_per_hour),
        bytes(d.current_bytes),
        d.rising_fraction * 100.0,
        d.reclaimed_fraction * 100.0,
        bytes(d.usual_rate_per_hour),
        window_label(d.baseline.window_hours),
        sensitivity_word(d.rule.sensitivity),
        d.baseline.confidence.label(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Sensitivity;
    use crate::profiler::confidence::Confidence;

    const MIB: f64 = 1024.0 * 1024.0;
    const TICK_MS: i64 = 5_000;

    fn baseline(growth: Option<f64>) -> BaselineStats {
        BaselineStats {
            median: 100.0 * MIB,
            mad: MIB,
            p95: 110.0 * MIB,
            mean: 100.0 * MIB,
            growth_per_hour: growth,
            confidence: Confidence::Established,
            window_hours: 24,
        }
    }

    fn detector() -> LeakDetector {
        LeakDetector::new(LeakRule::new(Sensitivity::Normal))
    }

    /// Feed one value per 5 s tick for one instance; returns the ticks at which it fired.
    fn run(
        det: &mut LeakDetector,
        b: &BaselineStats,
        bytes_at: impl Fn(usize) -> f64,
        ticks: usize,
    ) -> Vec<usize> {
        let key = ProcessKey::new(7, 1);
        let mut fired = Vec::new();
        for i in 0..ticks {
            let r = LeakReading {
                key,
                private_bytes: bytes_at(i),
                name: "leaky.exe",
                exe_path: r"C:\apps\leaky.exe",
                baseline: b,
            };
            if !det.observe_tick(i as i64 * TICK_MS, &[r]).is_empty() {
                fired.push(i);
            }
        }
        fired
    }

    fn minutes(i: usize) -> f64 {
        i as f64 * TICK_MS as f64 / 60_000.0
    }

    #[test]
    fn a_steady_ramp_is_a_potential_leak_raised_once_after_a_full_window() {
        // 3 MiB a minute = 180 MiB/h, with a little jitter.
        let ramp = |i: usize| 200.0 * MIB + 3.0 * MIB * minutes(i) + ((i % 3) as f64) * 0.1 * MIB;
        let fired = run(&mut detector(), &baseline(Some(0.0)), ramp, 480); // 40 minutes
        assert_eq!(fired.len(), 1, "one event per episode: {fired:?}");
        let minutes_in = minutes(fired[0]);
        assert!(
            (30.0..31.0).contains(&minutes_in),
            "after the 30 min window: {minutes_in}"
        );
    }

    #[test]
    fn a_sawtooth_from_garbage_collection_is_not_a_leak() {
        // Climbs 200 MiB over 10 minutes, collected back down, again and again.
        let saw = |i: usize| 200.0 * MIB + 20.0 * MIB * (minutes(i) % 10.0);
        assert!(run(&mut detector(), &baseline(Some(0.0)), saw, 1200).is_empty());
    }

    #[test]
    fn a_single_step_increase_is_not_a_leak() {
        let step = |i: usize| {
            if minutes(i) < 10.0 {
                200.0 * MIB
            } else {
                700.0 * MIB
            }
        };
        assert!(run(&mut detector(), &baseline(Some(0.0)), step, 960).is_empty());
    }

    #[test]
    fn growth_below_the_minimum_rate_is_ignored() {
        // 20 MiB/h is steady and unreclaimed, but far below 100 MiB/h.
        let slow = |i: usize| 200.0 * MIB + (20.0 / 60.0) * MIB * minutes(i);
        assert!(run(&mut detector(), &baseline(Some(0.0)), slow, 960).is_empty());
    }

    #[test]
    fn a_subject_that_always_grows_needs_to_grow_much_faster_than_usual() {
        let ramp = |i: usize| 200.0 * MIB + 4.0 * MIB * minutes(i); // 240 MiB/h
        // Usual growth 200 MiB/h: the bar becomes 600 MiB/h, so 240 is normal for it.
        assert!(run(&mut detector(), &baseline(Some(200.0 * MIB)), ramp, 480).is_empty());
        // The same ramp against a quiet baseline is flagged.
        assert_eq!(
            run(&mut detector(), &baseline(Some(1.0 * MIB)), ramp, 480).len(),
            1
        );
    }

    #[test]
    fn it_fires_again_for_a_new_episode_after_memory_is_reclaimed() {
        // Ramp for 40 min, drop back, ramp for another 40 min.
        let two = |i: usize| {
            let m = minutes(i);
            if m < 40.0 {
                200.0 * MIB + 3.0 * MIB * m
            } else if m < 41.0 {
                200.0 * MIB
            } else {
                200.0 * MIB + 3.0 * MIB * (m - 41.0)
            }
        };
        let fired = run(&mut detector(), &baseline(Some(0.0)), two, 1000);
        assert_eq!(fired.len(), 2, "{fired:?}");
    }

    #[test]
    fn a_process_that_disappears_loses_its_history() {
        let b = baseline(Some(0.0));
        let mut det = detector();
        let key = ProcessKey::new(7, 1);
        let at = |bytes: f64| LeakReading {
            key,
            private_bytes: bytes,
            name: "leaky.exe",
            exe_path: "p",
            baseline: &b,
        };
        for i in 0..300 {
            det.observe_tick(
                i as i64 * TICK_MS,
                &[at(200.0 * MIB + 3.0 * MIB * minutes(i))],
            );
        }
        det.observe_tick(300 * TICK_MS, &[]); // gone for one tick
        // Back (same key, say a resumed sample): the 25 minutes before are forgotten.
        let mut fired = 0;
        for i in 301..500 {
            fired += det
                .observe_tick(
                    i as i64 * TICK_MS,
                    &[at(200.0 * MIB + 3.0 * MIB * minutes(i))],
                )
                .len();
        }
        assert_eq!(fired, 0, "only 16 minutes of fresh history");
    }

    #[test]
    fn high_sensitivity_needs_less_growth_and_less_time() {
        let ramp = |i: usize| 200.0 * MIB + 0.8 * MIB * minutes(i); // 48 MiB/h
        assert!(run(&mut detector(), &baseline(Some(0.0)), ramp, 480).is_empty());
        let mut high = LeakDetector::new(LeakRule::new(Sensitivity::High));
        let fired = run(&mut high, &baseline(Some(0.0)), ramp, 480);
        assert_eq!(fired.len(), 1);
        assert!((15.0..16.0).contains(&minutes(fired[0])));
    }

    #[test]
    fn the_explanation_says_potential_and_gives_the_numbers() {
        let b = baseline(Some(0.0));
        let key = ProcessKey::new(7, 1);
        let mut det = detector();
        let mut found = None;
        for i in 0..400 {
            let r = LeakReading {
                key,
                private_bytes: 200.0 * MIB + 3.0 * MIB * minutes(i),
                name: "leaky.exe",
                exe_path: "p",
                baseline: &b,
            };
            if let Some(d) = det.observe_tick(i as i64 * TICK_MS, &[r]).pop() {
                found = Some(d);
            }
        }
        let d = found.expect("a ramp is detected");
        let text = explain(&d);
        for expected in [
            "Potential memory leak",
            "leaky.exe (PID 7)",
            "MiB/h",
            "potential leak, not a confirmed one",
            "normal sensitivity",
            "Established",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        assert!(
            (d.rate_per_hour / MIB - 180.0).abs() < 5.0,
            "{}",
            d.rate_per_hour
        );
    }
}
