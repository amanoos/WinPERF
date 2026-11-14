//! The monitoring engine: one tick = observe processes, compute samples, hand a batch to a sink.
//! It knows nothing about Windows, SQLite or any UI (A1): those arrive through traits, so the
//! terminal app and the Windows service run the exact same loop.

use crate::ProcessKey;
use crate::inventory::RawProcess;
use crate::sampling::{Observation, Sample, Sampler};
use crate::system::{SystemObservation, SystemSample, SystemSampler};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Where raw observations come from (the OS in production, a script in tests).
pub trait MetricsSource {
    /// Logical CPU count used to normalize CPU percentages.
    fn logical_cpus(&self) -> u32;
    /// Cheap probe of every process: identity plus cumulative counters.
    fn observe(&mut self) -> Vec<Observation>;
    /// Fuller details (path, user, session) for a process seen for the first time.
    fn describe(&mut self, observation: &Observation) -> RawProcess;
    /// System-wide readings (CPU, memory, disk, network). The default reports nothing, so sources
    /// that only deal in processes (and test doubles) need not implement it.
    fn observe_system(&mut self) -> SystemObservation {
        SystemObservation::default()
    }
}

/// Everything one tick wants persisted, as one unit.
#[derive(Debug, Clone, PartialEq)]
pub struct TickBatch {
    /// Wall-clock time of the tick, Unix milliseconds UTC.
    pub ts_ms: i64,
    /// Instances first seen this tick, with details.
    pub new: Vec<RawProcess>,
    pub samples: Vec<Sample>,
    /// Instances that were present last tick and are gone now.
    pub gone: Vec<ProcessKey>,
    /// System-wide health for this tick; `None` when the source supplied nothing at all.
    pub system: Option<SystemSample>,
}

/// Where batches go (SQLite in production). A tick's batch should be stored atomically.
pub trait SampleSink {
    type Error: std::error::Error + Send + Sync + 'static;
    fn record(&mut self, batch: &TickBatch) -> Result<(), Self::Error>;
    /// Persist anything still buffered. The engine calls this when a run ends (Ctrl+C, service
    /// stop, tick limit), so a sink that batches several ticks never drops its tail. Sinks that
    /// write every tick need no override.
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickStats {
    pub sampled: usize,
    pub unreadable: usize,
    pub new: usize,
    pub gone: usize,
    /// How long observing + persisting took.
    pub took: Duration,
}

/// Time as the engine sees it. Production uses [`SystemClock`]; tests use a fake one so the
/// schedule (drift, overruns, stop handling) can be checked without real sleeping.
pub trait Clock {
    /// Monotonic time since an arbitrary origin.
    fn now(&self) -> Duration;
    /// Wall-clock time as Unix milliseconds (UTC), used for sample timestamps.
    fn unix_millis(&self) -> i64;
    /// Wait for `d`. The engine only ever asks for short slices so it can notice a stop request.
    fn sleep(&self, d: Duration);
}

/// The real clock.
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
    fn unix_millis(&self) -> i64 {
        crate::time::unix_millis_now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// The longest single sleep, so a stop request (Ctrl+C, service stop) is honoured promptly.
const SLEEP_SLICE: Duration = Duration::from_millis(100);

pub struct Engine<M: MetricsSource, S: SampleSink> {
    metrics: M,
    sink: S,
    sampler: Sampler,
    system_sampler: SystemSampler,
    /// When the previous tick's observation finished (clock time), for rate intervals.
    last_observed: Option<Duration>,
}

impl<M: MetricsSource, S: SampleSink> Engine<M, S> {
    pub fn new(metrics: M, sink: S) -> Self {
        let sampler = Sampler::new(metrics.logical_cpus());
        Self {
            metrics,
            sink,
            sampler,
            system_sampler: SystemSampler::new(),
            last_observed: None,
        }
    }

    /// Run one tick. The interval used for rates is the time between this observation and the
    /// previous one *as measured by `clock`*, which is what the counters actually span (not the
    /// nominal interval).
    pub fn tick_with_clock(&mut self, clock: &dyn Clock) -> Result<TickStats, S::Error> {
        let started = clock.now();
        let observations = self.metrics.observe();
        let system = self.metrics.observe_system();
        let observed_at = clock.now();
        let elapsed = self
            .last_observed
            .map_or(Duration::ZERO, |t| observed_at.saturating_sub(t));
        self.last_observed = Some(observed_at);
        let mut stats = self.finish_tick(clock.unix_millis(), &observations, &system, elapsed)?;
        stats.took = clock.now().saturating_sub(started);
        Ok(stats)
    }

    /// Like [`tick_with_clock`](Self::tick_with_clock) but with a caller-supplied interval
    /// (deterministic tests of the sampling maths).
    pub fn tick_with_elapsed(
        &mut self,
        ts_ms: i64,
        elapsed: Duration,
    ) -> Result<TickStats, S::Error> {
        let started = Instant::now();
        let observations = self.metrics.observe();
        let system = self.metrics.observe_system();
        let mut stats = self.finish_tick(ts_ms, &observations, &system, elapsed)?;
        stats.took = started.elapsed();
        Ok(stats)
    }

    fn finish_tick(
        &mut self,
        ts_ms: i64,
        observations: &[Observation],
        system: &SystemObservation,
        elapsed: Duration,
    ) -> Result<TickStats, S::Error> {
        let out = self.sampler.tick(observations, elapsed);
        let system = self.system_sampler.tick(system, elapsed);
        let new: Vec<RawProcess> = out.new.iter().map(|o| self.metrics.describe(o)).collect();
        let batch = TickBatch {
            ts_ms,
            new,
            samples: out.samples,
            gone: out.gone,
            system: system.has_any().then_some(system),
        };
        self.sink.record(&batch)?;
        Ok(TickStats {
            sampled: batch.samples.len(),
            unreadable: out.unreadable,
            new: batch.new.len(),
            gone: batch.gone.len(),
            took: Duration::ZERO,
        })
    }

    /// Tick every `interval` until `stop` is set or `max_ticks` ticks have run, on the real clock.
    /// Returns the number of ticks run.
    pub fn run(
        &mut self,
        interval: Duration,
        max_ticks: Option<u64>,
        stop: &AtomicBool,
        on_tick: impl FnMut(u64, &TickStats),
    ) -> Result<u64, S::Error> {
        self.run_with_clock(&SystemClock::new(), interval, max_ticks, stop, on_tick)
    }

    /// The scheduling loop. Ticks are anchored to a fixed grid (`start + n * interval`), so a
    /// slow tick never pushes later ticks back (no drift). A tick that is late by less than an
    /// interval runs immediately; whole missed intervals (after a long stall such as
    /// suspend/resume) are skipped, so there is never a burst of catch-up ticks.
    ///
    /// The stop flag is checked before every tick and between short sleep slices. A tick that has
    /// started always finishes (and commits) before the loop exits, so stopping never leaves a
    /// half-written tick.
    pub fn run_with_clock(
        &mut self,
        clock: &dyn Clock,
        interval: Duration,
        max_ticks: Option<u64>,
        stop: &AtomicBool,
        mut on_tick: impl FnMut(u64, &TickStats),
    ) -> Result<u64, S::Error> {
        let mut ticks = 0u64;
        let mut next = clock.now();
        while !stop.load(Ordering::Relaxed) {
            let stats = self.tick_with_clock(clock)?;
            ticks += 1;
            on_tick(ticks, &stats);
            if max_ticks.is_some_and(|m| ticks >= m) {
                break;
            }
            let now = clock.now();
            next += interval;
            // Skip whole intervals that were missed (a long stall such as suspend/resume, or a
            // tick slower than the interval). A tick that is merely late runs immediately.
            while !interval.is_zero() && next + interval <= now {
                next += interval;
            }
            while !stop.load(Ordering::Relaxed) {
                let now = clock.now();
                if now >= next {
                    break;
                }
                clock.sleep((next - now).min(SLEEP_SLICE));
            }
        }
        self.sink.flush()?;
        Ok(ticks)
    }

    /// Read-only access to the sink (e.g. to inspect what was stored).
    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn into_parts(self) -> (M, S) {
        (self.metrics, self.sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Metric;
    use crate::system::SystemObservation;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    /// Plays back a script of observation rounds.
    struct Script {
        rounds: VecDeque<Vec<Observation>>,
        described: Vec<u32>,
    }
    impl Script {
        fn new(rounds: Vec<Vec<Observation>>) -> Self {
            Self {
                rounds: rounds.into(),
                described: vec![],
            }
        }
    }
    impl MetricsSource for Script {
        fn logical_cpus(&self) -> u32 {
            4
        }
        fn observe(&mut self) -> Vec<Observation> {
            self.rounds.pop_front().unwrap_or_default()
        }
        fn describe(&mut self, o: &Observation) -> RawProcess {
            self.described.push(o.pid);
            RawProcess {
                pid: o.pid,
                parent_pid: o.parent_pid,
                name: o.name.clone(),
                start_time: o.start_time,
                user: Some("PC\\me".into()),
                ..Default::default()
            }
        }
    }

    #[derive(Default)]
    struct Collect(Vec<TickBatch>);
    #[derive(Debug)]
    struct Never;
    impl std::fmt::Display for Never {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "never")
        }
    }
    impl std::error::Error for Never {}
    impl SampleSink for Collect {
        type Error = Never;
        fn record(&mut self, b: &TickBatch) -> Result<(), Self::Error> {
            self.0.push(b.clone());
            Ok(())
        }
    }

    fn obs(pid: u32, start: u64, cpu: u64) -> Observation {
        Observation {
            pid,
            name: format!("p{pid}.exe"),
            start_time: Some(start),
            cpu_time_100ns: Some(cpu),
            working_set: Some(10),
            ..Default::default()
        }
    }

    #[test]
    fn new_instances_are_described_once_and_samples_follow_every_tick() {
        let script = Script::new(vec![
            vec![obs(1, 100, 0)],
            vec![obs(1, 100, 10_000_000)],
            vec![obs(1, 100, 20_000_000)],
        ]);
        let mut e = Engine::new(script, Collect::default());
        let s1 = e.tick_with_elapsed(1000, Duration::ZERO).unwrap();
        e.tick_with_elapsed(2000, Duration::from_secs(1)).unwrap();
        e.tick_with_elapsed(3000, Duration::from_secs(1)).unwrap();
        let (metrics, sink) = e.into_parts();

        assert_eq!((s1.sampled, s1.new, s1.gone), (1, 1, 0));
        assert_eq!(
            metrics.described,
            vec![1],
            "described only on first sighting"
        );
        assert_eq!(sink.0.len(), 3);
        assert_eq!(sink.0[0].new[0].user.as_deref(), Some("PC\\me"));
        assert_eq!(sink.0[0].samples[0].cpu_percent, Metric::Unavailable);
        assert_eq!(sink.0[1].samples[0].cpu_percent, Metric::Available(25.0));
        assert_eq!(sink.0[2].ts_ms, 3000);
        assert!(sink.0[1].new.is_empty());
    }

    #[test]
    fn pid_reuse_across_ticks_produces_two_instances() {
        let script = Script::new(vec![vec![obs(50, 1000, 5)], vec![obs(50, 2000, 5)]]);
        let mut e = Engine::new(script, Collect::default());
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        let s = e.tick_with_elapsed(2, Duration::from_secs(1)).unwrap();
        let (_, sink) = e.into_parts();
        assert_eq!((s.new, s.gone), (1, 1));
        assert_eq!(sink.0[1].new[0].start_time, Some(2000));
        assert_eq!(sink.0[1].gone, vec![ProcessKey::new(50, 1000)]);
    }

    #[test]
    fn run_stops_after_max_ticks() {
        let rounds = (0..10).map(|_| vec![obs(1, 1, 0)]).collect();
        let mut e = Engine::new(Script::new(rounds), Collect::default());
        let stop = AtomicBool::new(false);
        let mut seen = vec![];
        let n = e
            .run(Duration::from_millis(5), Some(3), &stop, |i, _| {
                seen.push(i)
            })
            .unwrap();
        assert_eq!(n, 3);
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn run_returns_immediately_when_already_stopped() {
        let mut e = Engine::new(Script::new(vec![]), Collect::default());
        let stop = AtomicBool::new(true);
        assert_eq!(
            e.run(Duration::from_secs(60), None, &stop, |_, _| {})
                .unwrap(),
            0
        );
    }

    #[test]
    fn a_stop_request_interrupts_a_long_sleep() {
        let rounds = (0..5).map(|_| vec![obs(1, 1, 0)]).collect();
        let mut e = Engine::new(Script::new(rounds), Collect::default());
        let stop = AtomicBool::new(false);
        let started = Instant::now();
        let n = e
            .run(Duration::from_secs(60), None, &stop, |_, _| {
                stop.store(true, Ordering::Relaxed); // request stop during the first tick
            })
            .unwrap();
        assert_eq!(n, 1);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "should not sleep 60 s"
        );
    }

    /// A process script that also supplies system readings.
    struct WithSystem {
        inner: Script,
        system: VecDeque<SystemObservation>,
    }
    impl MetricsSource for WithSystem {
        fn logical_cpus(&self) -> u32 {
            self.inner.logical_cpus()
        }
        fn observe(&mut self) -> Vec<Observation> {
            self.inner.observe()
        }
        fn describe(&mut self, o: &Observation) -> RawProcess {
            self.inner.describe(o)
        }
        fn observe_system(&mut self) -> SystemObservation {
            self.system.pop_front().unwrap_or_default()
        }
    }

    #[test]
    fn system_health_rides_along_in_each_batch() {
        let sys = |idle, kernel, user| SystemObservation {
            cpu_idle_100ns: Some(idle),
            cpu_kernel_100ns: Some(kernel),
            cpu_user_100ns: Some(user),
            memory_total_bytes: Some(1_000),
            ..Default::default()
        };
        let source = WithSystem {
            inner: Script::new(vec![vec![obs(1, 1, 0)], vec![obs(1, 1, 0)]]),
            system: vec![sys(0, 0, 0), sys(50, 100, 100)].into(),
        };
        let mut e = Engine::new(source, Collect::default());
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        e.tick_with_elapsed(2, Duration::from_secs(1)).unwrap();
        let (_, sink) = e.into_parts();

        let first = sink.0[0]
            .system
            .as_ref()
            .expect("memory alone is worth storing");
        assert_eq!(
            first.cpu_percent,
            Metric::Unavailable,
            "no CPU rate on the first tick"
        );
        assert_eq!(first.memory_total_bytes, Metric::Available(1_000));
        // total = 100 + 100 = 200, idle 50 => 75% busy
        let second = sink.0[1].system.as_ref().unwrap();
        assert_eq!(second.cpu_percent, Metric::Available(75.0));
    }

    #[test]
    fn a_source_with_no_system_readings_produces_no_system_sample() {
        let mut e = Engine::new(Script::new(vec![vec![obs(1, 1, 0)]]), Collect::default());
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        let (_, sink) = e.into_parts();
        assert!(sink.0[0].system.is_none());
    }

    // ---- schedule, with a fake clock (T13) -------------------------------------------------

    /// A clock the test controls. `sleep` advances time instantly.
    struct FakeClock {
        now: Cell<Duration>,
        slept: RefCell<Vec<Duration>>,
        on_sleep: RefCell<Option<SleepHook>>,
    }
    type SleepHook = Box<dyn FnMut(Duration)>;
    impl FakeClock {
        fn new() -> Rc<Self> {
            Rc::new(Self {
                now: Cell::new(Duration::ZERO),
                slept: RefCell::new(vec![]),
                on_sleep: RefCell::new(None),
            })
        }
        fn advance(&self, d: Duration) {
            self.now.set(self.now.get() + d);
        }
    }
    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.now.get()
        }
        fn unix_millis(&self) -> i64 {
            1_700_000_000_000 + self.now.get().as_millis() as i64
        }
        fn sleep(&self, d: Duration) {
            self.slept.borrow_mut().push(d);
            self.advance(d);
            if let Some(f) = self.on_sleep.borrow_mut().as_mut() {
                f(self.now.get());
            }
        }
    }

    /// Each observation costs `cost` of fake time and records when the tick started.
    struct CostSource {
        clock: Rc<FakeClock>,
        cost: Duration,
        starts: Rc<RefCell<Vec<Duration>>>,
        cpu: u64,
        on_observe: Option<Box<dyn FnMut()>>,
    }
    impl CostSource {
        fn new(clock: &Rc<FakeClock>, cost_ms: u64) -> (Self, Rc<RefCell<Vec<Duration>>>) {
            let starts = Rc::new(RefCell::new(vec![]));
            (
                Self {
                    clock: Rc::clone(clock),
                    cost: Duration::from_millis(cost_ms),
                    starts: Rc::clone(&starts),
                    cpu: 0,
                    on_observe: None,
                },
                starts,
            )
        }
    }
    impl MetricsSource for CostSource {
        fn logical_cpus(&self) -> u32 {
            4
        }
        fn observe(&mut self) -> Vec<Observation> {
            self.starts.borrow_mut().push(self.clock.now());
            if let Some(f) = self.on_observe.as_mut() {
                f();
            }
            self.clock.advance(self.cost);
            self.cpu += 10_000_000; // one CPU-second per tick
            vec![obs(1, 1, self.cpu)]
        }
        fn describe(&mut self, o: &Observation) -> RawProcess {
            RawProcess {
                pid: o.pid,
                start_time: o.start_time,
                ..Default::default()
            }
        }
    }

    fn ms(v: &[Duration]) -> Vec<u128> {
        v.iter().map(Duration::as_millis).collect()
    }

    #[test]
    fn ticks_start_on_a_fixed_grid_regardless_of_tick_cost() {
        let clock = FakeClock::new();
        let (source, starts) = CostSource::new(&clock, 100);
        let mut e = Engine::new(source, Collect::default());
        let stop = AtomicBool::new(false);
        let n = e
            .run_with_clock(&*clock, Duration::from_secs(1), Some(4), &stop, |_, _| {})
            .unwrap();
        assert_eq!(n, 4);
        // Not 0, 1100, 2200, 3300: the 100 ms of work each tick does not accumulate.
        assert_eq!(ms(&starts.borrow()), vec![0, 1000, 2000, 3000]);
    }

    #[test]
    fn batches_are_stamped_with_the_clocks_wall_time() {
        let clock = FakeClock::new();
        let (source, _) = CostSource::new(&clock, 100);
        let mut e = Engine::new(source, Collect::default());
        let stop = AtomicBool::new(false);
        e.run_with_clock(&*clock, Duration::from_secs(1), Some(3), &stop, |_, _| {})
            .unwrap();
        let (_, sink) = e.into_parts();
        let ts: Vec<i64> = sink.0.iter().map(|b| b.ts_ms).collect();
        assert_eq!(
            ts,
            vec![1_700_000_000_100, 1_700_000_001_100, 1_700_000_002_100]
        );
    }

    #[test]
    fn cpu_rates_use_the_measured_interval_between_observations() {
        let clock = FakeClock::new();
        let (source, _) = CostSource::new(&clock, 100);
        let mut e = Engine::new(source, Collect::default());
        let stop = AtomicBool::new(false);
        e.run_with_clock(&*clock, Duration::from_secs(1), Some(3), &stop, |_, _| {})
            .unwrap();
        let (_, sink) = e.into_parts();
        // +1 CPU-second every second on 4 CPUs = 25%.
        assert_eq!(sink.0[0].samples[0].cpu_percent, Metric::Unavailable);
        assert_eq!(sink.0[1].samples[0].cpu_percent, Metric::Available(25.0));
        assert_eq!(sink.0[2].samples[0].cpu_percent, Metric::Available(25.0));
    }

    #[test]
    fn a_tick_slower_than_the_interval_runs_back_to_back_without_a_burst() {
        let clock = FakeClock::new();
        let (source, starts) = CostSource::new(&clock, 2_500);
        let mut e = Engine::new(source, Collect::default());
        let stop = AtomicBool::new(false);
        e.run_with_clock(&*clock, Duration::from_secs(1), Some(3), &stop, |_, _| {})
            .unwrap();
        // Each tick takes 2.5 s, longer than the 1 s interval: the next starts as soon as the last
        // finishes, never earlier and never several at once.
        assert_eq!(ms(&starts.borrow()), vec![0, 2500, 5000]);
    }

    #[test]
    fn a_tick_that_exactly_fills_the_interval_does_not_lose_a_slot() {
        let clock = FakeClock::new();
        let (source, starts) = CostSource::new(&clock, 1_000);
        let mut e = Engine::new(source, Collect::default());
        let stop = AtomicBool::new(false);
        e.run_with_clock(&*clock, Duration::from_secs(1), Some(3), &stop, |_, _| {})
            .unwrap();
        assert_eq!(ms(&starts.borrow()), vec![0, 1000, 2000]);
    }

    #[test]
    fn after_a_long_stall_one_tick_runs_then_the_grid_resumes_with_no_catch_up_burst() {
        // e.g. the laptop was suspended for an hour between ticks.
        let clock = FakeClock::new();
        let (source, starts) = CostSource::new(&clock, 100);
        let mut e = Engine::new(source, Collect::default());
        let stop = AtomicBool::new(false);
        let c = Rc::clone(&clock);
        let n = e
            .run_with_clock(&*clock, Duration::from_secs(1), Some(4), &stop, |i, _| {
                if i == 1 {
                    c.advance(Duration::from_secs(3_600));
                }
            })
            .unwrap();
        assert_eq!(n, 4, "an hour of missed ticks is skipped, not replayed");
        let s = ms(&starts.borrow());
        assert_eq!(s[0], 0);
        assert_eq!(s[1], 3_600_100, "one immediate tick after the stall");
        assert_eq!(s[2] - s[1], 900, "then back on the 1 s grid");
        assert_eq!(s[3] - s[2], 1_000);
    }

    #[test]
    fn sleeps_are_short_slices_and_a_stop_request_cuts_a_long_interval_short() {
        let clock = FakeClock::new();
        let (source, starts) = CostSource::new(&clock, 0);
        let stop = Rc::new(AtomicBool::new(false));
        let flag = Rc::clone(&stop);
        *clock.on_sleep.borrow_mut() = Some(Box::new(move |now| {
            if now >= Duration::from_millis(250) {
                flag.store(true, Ordering::Relaxed);
            }
        }));
        let mut e = Engine::new(source, Collect::default());
        let n = e
            .run_with_clock(&*clock, Duration::from_secs(60), None, &stop, |_, _| {})
            .unwrap();
        assert_eq!(n, 1, "no second tick after the stop request");
        assert_eq!(starts.borrow().len(), 1);
        let slept = clock.slept.borrow();
        assert!(
            slept.iter().all(|d| *d <= Duration::from_millis(100)),
            "{slept:?}"
        );
        assert!(
            clock.now() <= Duration::from_millis(400),
            "slept {:?} of a 60 s interval",
            clock.now()
        );
    }

    #[test]
    fn a_tick_in_progress_when_stop_is_requested_still_completes_and_is_recorded() {
        let clock = FakeClock::new();
        let (mut source, _) = CostSource::new(&clock, 50);
        let stop = Rc::new(AtomicBool::new(false));
        let flag = Rc::clone(&stop);
        source.on_observe = Some(Box::new(move || flag.store(true, Ordering::Relaxed)));
        let mut e = Engine::new(source, Collect::default());
        let n = e
            .run_with_clock(&*clock, Duration::from_secs(1), None, &stop, |_, _| {})
            .unwrap();
        let (_, sink) = e.into_parts();
        assert_eq!(n, 1);
        assert_eq!(sink.0.len(), 1, "the in-flight tick's batch was committed");
    }

    struct FailingSink;
    #[derive(Debug)]
    struct Boom;
    impl std::fmt::Display for Boom {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "boom")
        }
    }
    impl std::error::Error for Boom {}
    impl SampleSink for FailingSink {
        type Error = Boom;
        fn record(&mut self, _: &TickBatch) -> Result<(), Boom> {
            Err(Boom)
        }
    }

    #[test]
    fn sink_errors_propagate() {
        let mut e = Engine::new(Script::new(vec![vec![obs(1, 1, 0)]]), FailingSink);
        assert!(e.tick_with_elapsed(1, Duration::ZERO).is_err());
    }
}
