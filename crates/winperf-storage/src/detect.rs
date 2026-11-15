//! Anomaly detection on the live tick stream: wraps the database sink, feeds every batch to the
//! pure tracker in `winperf-core`, and stores what it raises.
//!
//! Detection never gets in the way of recording. Samples are written first, and a failure to read
//! baselines or write an event is remembered (see [`DetectingSink::last_error`]) instead of
//! stopping the monitor.
//!
//! Baselines are re-read every [`DetectSettings::refresh`] (they change only when the baseline
//! job runs), together with the profiling-mode marker: while profiling is active nothing is raised.

use crate::db::Database;
use crate::error::StorageError;
use crate::sink::DbSink;
use std::time::Duration;
use winperf_core::anomaly::rules::CpuRule;
use winperf_core::anomaly::tracker::AnomalyTracker;
use winperf_core::config::{ConfidenceConfig, Sensitivity};
use winperf_core::engine::{SampleSink, TickBatch};

#[derive(Debug, Clone)]
pub struct DetectSettings {
    pub cpu_sensitivity: Sensitivity,
    /// The baseline windows to trust, in hours (from `[baseline] windows_hours`).
    pub windows_hours: Vec<u32>,
    pub confidence: ConfidenceConfig,
    /// How often baselines and the profiling marker are re-read.
    pub refresh: Duration,
}

impl DetectSettings {
    pub const DEFAULT_REFRESH: Duration = Duration::from_secs(300);

    pub fn new(
        cpu_sensitivity: Sensitivity,
        windows_hours: Vec<u32>,
        confidence: ConfidenceConfig,
    ) -> Self {
        Self {
            cpu_sensitivity,
            windows_hours,
            confidence,
            refresh: Self::DEFAULT_REFRESH,
        }
    }
}

pub struct DetectingSink {
    inner: DbSink,
    tracker: AnomalyTracker,
    settings: DetectSettings,
    last_refresh_ms: Option<i64>,
    raised: u64,
    last_error: Option<String>,
}

impl DetectingSink {
    pub fn new(inner: DbSink, settings: DetectSettings) -> Self {
        let tracker = AnomalyTracker::new(CpuRule::for_sensitivity(settings.cpu_sensitivity));
        Self {
            inner,
            tracker,
            settings,
            last_refresh_ms: None,
            raised: 0,
            last_error: None,
        }
    }

    /// Anomalies raised and stored so far.
    pub fn raised(&self) -> u64 {
        self.raised
    }

    /// The most recent problem reading baselines or storing an event, if any.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn database(&self) -> &Database {
        self.inner.database()
    }

    /// Whether detection is currently running (it is paused while profiling mode is on).
    pub fn is_detecting(&self) -> bool {
        self.tracker.is_enabled()
    }

    pub fn into_database(self) -> Database {
        self.inner.into_database()
    }

    fn refresh_if_due(&mut self, now_ms: i64) {
        let due = match self.last_refresh_ms {
            None => true,
            Some(last) => now_ms - last >= self.settings.refresh.as_millis() as i64,
        };
        if !due {
            return;
        }
        self.last_refresh_ms = Some(now_ms);
        let db = self.inner.database();
        // On failure keep what we had: a database that is briefly busy must not blind detection.
        match db.profile_state() {
            Ok(state) => self.tracker.set_enabled(!state.active),
            Err(e) => self.last_error = Some(format!("reading profiling state: {e}")),
        }
        match db.usable_cpu_baselines(&self.settings.windows_hours, &self.settings.confidence) {
            Ok(baselines) => self.tracker.set_baselines(baselines),
            Err(e) => self.last_error = Some(format!("reading baselines: {e}")),
        }
    }

    fn detect(&mut self, batch: &TickBatch) {
        self.refresh_if_due(batch.ts_ms);
        for event in self.tracker.ingest(batch) {
            match self.inner.database().insert_anomaly(&event) {
                Ok(_) => self.raised += 1,
                Err(e) => self.last_error = Some(format!("storing an anomaly: {e}")),
            }
        }
    }
}

impl SampleSink for DetectingSink {
    type Error = StorageError;

    fn record(&mut self, batch: &TickBatch) -> Result<(), StorageError> {
        self.inner.record(batch)?;
        self.detect(batch);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use std::collections::VecDeque;
    use winperf_core::engine::{Engine, MetricsSource};
    use winperf_core::inventory::RawProcess;
    use winperf_core::sampling::Observation;

    const PATH: &str = r"C:\apps\busy.exe";
    /// 4 logical CPUs and 5 s ticks: this much CPU time per tick is exactly 1% of the machine.
    const ONE_PERCENT_PER_TICK: u64 = 4 * 5 * 10_000_000 / 100;

    struct Script(VecDeque<Vec<Observation>>);
    impl MetricsSource for Script {
        fn logical_cpus(&self) -> u32 {
            4
        }
        fn observe(&mut self) -> Vec<Observation> {
            self.0.pop_front().unwrap_or_default()
        }
        fn describe(&mut self, o: &Observation) -> RawProcess {
            RawProcess {
                pid: o.pid,
                name: o.name.clone(),
                start_time: o.start_time,
                exe_path: Some(PATH.into()),
                ..Default::default()
            }
        }
    }

    /// One process using `percent` of the machine on every tick after the first.
    fn burner(ticks: u64, percent: u64) -> Script {
        Script(
            (0..ticks)
                .map(|i| {
                    vec![Observation {
                        pid: 7,
                        name: "busy.exe".into(),
                        start_time: Some(100),
                        cpu_time_100ns: Some(i * percent * ONE_PERCENT_PER_TICK),
                        working_set: Some(1),
                        ..Default::default()
                    }]
                })
                .collect(),
        )
    }

    /// A database that already knows `busy.exe` and says it normally uses ~8% CPU.
    fn database_with_baseline(observations: i64, span_minutes: i64) -> Database {
        let db = Database::open_in_memory().unwrap();
        db.conn()
            .execute(
                "INSERT INTO executables (id, path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES (1, ?1, ?2, 'busy.exe', 'valid', 'third_party', 1, 1, 't')",
                params![PATH.to_lowercase(), PATH],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO baseline_profiles (scope, subject_id, window_hours, metric, \
                 observations, first_ts_ms, last_ts_ms, mean, median, mad, stddev, p95, peak, \
                 computed_at_ms) VALUES ('executable', 1, 24, 'cpu', ?1, 0, ?2, 8.0, 8.0, 1.0, \
                 1.0, 10.0, 20.0, 0)",
                params![observations, span_minutes * 60_000],
            )
            .unwrap();
        db
    }

    fn run(db: Database, script: Script, ticks: i64) -> DetectingSink {
        let settings = DetectSettings::new(
            Sensitivity::Normal,
            vec![1, 24, 168],
            ConfidenceConfig::default(),
        );
        let mut engine = Engine::new(script, DetectingSink::new(DbSink::new(db), settings));
        for i in 0..ticks {
            engine
                .tick_with_elapsed(i * 5_000, Duration::from_secs(5))
                .unwrap();
        }
        engine.into_parts().1
    }

    #[test]
    fn a_sustained_burn_is_stored_as_an_event() {
        let db = database_with_baseline(5_000, 600);
        let sink = run(db, burner(40, 72), 40);

        assert_eq!(sink.raised(), 1);
        assert_eq!(sink.last_error(), None);
        let events = sink.database().list_anomalies(None, 10).unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!((e.process_name.as_str(), e.pid), ("busy.exe", 7));
        assert_eq!(e.exe_path, PATH);
        assert_eq!(e.current, 72.0);
        assert_eq!(e.baseline, 8.0);
        assert_eq!(e.duration_ms, 120_000);
        assert_eq!(e.baseline_window_hours, 24);
        assert!(
            e.process_instance_id.is_some(),
            "the instance is stored by then"
        );
        assert!(e.explanation.contains("busy.exe"));
    }

    #[test]
    fn normal_use_raises_nothing() {
        let db = database_with_baseline(5_000, 600);
        let sink = run(db, burner(60, 8), 60);
        assert_eq!(sink.raised(), 0);
        assert_eq!(sink.database().anomaly_count().unwrap(), 0);
    }

    #[test]
    fn a_baseline_with_too_little_history_is_not_used() {
        let db = database_with_baseline(10, 1); // Insufficient
        let sink = run(db, burner(60, 90), 60);
        assert_eq!(sink.raised(), 0, "no trusted baseline, no anomaly");
    }

    #[test]
    fn an_unknown_executable_is_never_judged() {
        let sink = run(Database::open_in_memory().unwrap(), burner(60, 90), 60);
        assert_eq!(sink.raised(), 0);
    }

    #[test]
    fn profiling_mode_holds_detection_back() {
        let db = database_with_baseline(5_000, 600);
        db.start_profiling(1).unwrap();
        let sink = run(db, burner(60, 90), 60);
        assert!(!sink.is_detecting());
        assert_eq!(sink.raised(), 0);
    }

    #[test]
    fn samples_are_still_recorded_while_detection_is_held_back() {
        let db = database_with_baseline(5_000, 600);
        db.start_profiling(1).unwrap();
        let sink = run(db, burner(10, 90), 10);
        assert_eq!(sink.database().sample_count().unwrap(), 10);
    }
}
