//! Anomaly detection on the live tick stream: wraps the database sink, feeds every batch to the
//! pure tracker in `winperf-core`, and stores what it raises.
//!
//! Detection never gets in the way of recording. Samples are written first, and a failure to read
//! baselines or write an event is remembered (see [`DetectingSink::last_error`]) instead of
//! stopping the monitor.
//!
//! Each anomaly lives in one row: the first sighting inserts it, later updates refresh it in place,
//! and when the condition ends the row is resolved. Rows a stopped monitor left active are resolved
//! (as of their last update) when the next monitor starts.
//!
//! Baselines are re-read every [`DetectSettings::refresh`] (they change only when the baseline
//! job runs), together with the profiling-mode marker: while profiling is active nothing is raised.

use crate::db::Database;
use crate::error::StorageError;
use crate::sink::DbSink;
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::time::Duration;
use winperf_core::anomaly::tracker::AnomalyTracker;
use winperf_core::anomaly::{AnomalyChange, AnomalyEvent, Sensitivities, Severity};
use winperf_core::config::ConfidenceConfig;
use winperf_core::engine::{SampleSink, TickBatch};

#[derive(Debug, Clone)]
pub struct DetectSettings {
    pub sensitivities: Sensitivities,
    /// The baseline windows to trust, in hours (from `[baseline] windows_hours`).
    pub windows_hours: Vec<u32>,
    pub confidence: ConfidenceConfig,
    /// How often baselines and the profiling marker are re-read.
    pub refresh: Duration,
}

impl DetectSettings {
    pub const DEFAULT_REFRESH: Duration = Duration::from_secs(300);

    pub fn new(
        sensitivities: Sensitivities,
        windows_hours: Vec<u32>,
        confidence: ConfidenceConfig,
    ) -> Self {
        Self {
            sensitivities,
            windows_hours,
            confidence,
            refresh: Self::DEFAULT_REFRESH,
        }
    }
}

/// Something worth telling the person watching, sent as it is stored (see
/// [`DetectingSink::with_notices`]).
#[derive(Debug, Clone, PartialEq)]
pub enum Notice {
    /// A new anomaly, stored as row `id`.
    Raised { id: i64, event: AnomalyEvent },
    /// An active anomaly got more severe.
    Worsened { id: i64, event: AnomalyEvent },
    /// The condition ended.
    Resolved {
        id: i64,
        process_name: String,
        ts_ms: i64,
    },
}

/// What the sink remembers about an active anomaly's row.
struct ActiveRow {
    id: i64,
    severity: Severity,
    process_name: String,
}

pub struct DetectingSink {
    inner: DbSink,
    tracker: AnomalyTracker,
    settings: DetectSettings,
    last_refresh_ms: Option<i64>,
    raised: u64,
    last_error: Option<String>,
    /// The database row of each active anomaly, by the tracker's key for it.
    rows: HashMap<String, ActiveRow>,
    notices: Option<Sender<Notice>>,
}

impl DetectingSink {
    pub fn new(inner: DbSink, settings: DetectSettings) -> Self {
        let tracker = AnomalyTracker::new(settings.sensitivities);
        let mut sink = Self {
            inner,
            tracker,
            settings,
            last_refresh_ms: None,
            raised: 0,
            last_error: None,
            rows: HashMap::new(),
            notices: None,
        };
        // Anything still marked active belongs to a monitor that is no longer running.
        if let Err(e) = sink.inner.database().resolve_stale_anomalies() {
            sink.last_error = Some(format!("closing earlier anomalies: {e}"));
        }
        sink
    }

    /// Send a [`Notice`] for every anomaly that is raised, gets worse or ends. Sending never
    /// blocks, and a receiver that has gone away is ignored.
    pub fn with_notices(mut self, to: Sender<Notice>) -> Self {
        self.notices = Some(to);
        self
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
        // On failure keep what we had: a database that is briefly busy must not blind detection.
        match self.inner.database().profile_state() {
            Ok(state) => {
                let changes = self.tracker.set_enabled(!state.active);
                self.store(changes, now_ms);
            }
            Err(e) => self.last_error = Some(format!("reading profiling state: {e}")),
        }
        match self
            .inner
            .database()
            .usable_baselines(&self.settings.windows_hours, &self.settings.confidence)
        {
            Ok(baselines) => self.tracker.set_baselines(baselines),
            Err(e) => self.last_error = Some(format!("reading baselines: {e}")),
        }
    }

    fn detect(&mut self, batch: &TickBatch) {
        self.refresh_if_due(batch.ts_ms);
        let changes = self.tracker.ingest(batch);
        self.store(changes, batch.ts_ms);
    }

    fn notify(&self, notice: Notice) {
        if let Some(to) = &self.notices {
            let _ = to.send(notice);
        }
    }

    /// Write what changed: new events are inserted, active ones refreshed, finished ones resolved.
    fn store(&mut self, changes: Vec<AnomalyChange>, now_ms: i64) {
        for change in changes {
            let result = match change {
                AnomalyChange::Raised { key, event } => {
                    self.inner.database().insert_anomaly(&event).map(|id| {
                        self.rows.insert(
                            key,
                            ActiveRow {
                                id,
                                severity: event.severity,
                                process_name: event.process_name.clone(),
                            },
                        );
                        self.raised += 1;
                        self.notify(Notice::Raised { id, event });
                    })
                }
                AnomalyChange::Updated { key, event } => match self.rows.get_mut(&key) {
                    Some(row) => {
                        let id = row.id;
                        let worse = event.severity > row.severity;
                        row.severity = row.severity.max(event.severity);
                        let stored = self.inner.database().update_anomaly(id, &event, now_ms);
                        if worse {
                            self.notify(Notice::Worsened { id, event });
                        }
                        stored
                    }
                    None => Ok(()),
                },
                AnomalyChange::Resolved { key, ts_ms } => match self.rows.remove(&key) {
                    Some(row) => {
                        let stored = self.inner.database().resolve_anomaly(row.id, ts_ms);
                        self.notify(Notice::Resolved {
                            id: row.id,
                            process_name: row.process_name,
                            ts_ms,
                        });
                        stored
                    }
                    None => Ok(()),
                },
            };
            if let Err(e) = result {
                self.last_error = Some(format!("storing an anomaly: {e}"));
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
    use crate::repo::AnomalyFilter;
    use rusqlite::params;
    use std::collections::VecDeque;
    use winperf_core::config::Sensitivity;
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
            Sensitivities::uniform(Sensitivity::Normal),
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
        let events = sink
            .database()
            .list_anomalies(&AnomalyFilter::default(), 10)
            .unwrap();
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!((e.process_name.as_str(), e.pid), ("busy.exe", 7));
        assert_eq!(e.exe_path, PATH);
        assert_eq!(e.current, 72.0);
        assert_eq!(e.baseline, 8.0);
        assert_eq!(
            e.detected_ts_ms, 125_000,
            "raised once it had lasted 2 minutes"
        );
        assert!(
            e.duration_ms > 120_000,
            "refreshed as it went on: {}",
            e.duration_ms
        );
        assert!(e.is_active());
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

    /// 72% for `burn` ticks, then idle for the rest of `ticks`.
    fn burn_then_idle(burn: u64, ticks: u64) -> Script {
        Script(
            (0..ticks)
                .map(|i| {
                    let busy = i.min(burn);
                    let idle = i.saturating_sub(burn);
                    vec![Observation {
                        pid: 7,
                        name: "busy.exe".into(),
                        start_time: Some(100),
                        cpu_time_100ns: Some(busy * 72 * ONE_PERCENT_PER_TICK + idle),
                        working_set: Some(1),
                        ..Default::default()
                    }]
                })
                .collect(),
        )
    }

    #[test]
    fn one_row_follows_an_anomaly_from_raised_to_resolved() {
        let db = database_with_baseline(5_000, 600);
        let sink = run(db, burn_then_idle(40, 60), 60);

        let events = sink
            .database()
            .list_anomalies(&AnomalyFilter::default(), 10)
            .unwrap();
        assert_eq!(
            events.len(),
            1,
            "one row for the whole episode: {events:#?}"
        );
        let e = &events[0];
        assert!(!e.is_active(), "the burn ended");
        assert!(e.resolved_ts_ms.is_some());
        assert!(e.duration_ms >= 150_000, "{}", e.duration_ms);
        assert!(e.last_update_ts_ms >= e.detected_ts_ms);
        assert_eq!(sink.database().active_anomaly_count().unwrap(), 0);
        assert_eq!(sink.raised(), 1);
    }

    #[test]
    fn a_new_monitor_closes_what_a_stopped_one_left_active() {
        let db = database_with_baseline(5_000, 600);
        let sink = run(db, burner(40, 72), 40); // stops while the burn is still on
        assert_eq!(sink.database().active_anomaly_count().unwrap(), 1);

        let db = sink.into_database();
        let sink = run(db, burner(2, 1), 2); // the next monitor starts
        assert_eq!(sink.database().active_anomaly_count().unwrap(), 0);
        let e = &sink
            .database()
            .list_anomalies(&AnomalyFilter::default(), 10)
            .unwrap()[0];
        assert_eq!(e.resolved_ts_ms, Some(e.last_update_ts_ms));
    }

    #[test]
    fn profiling_mode_resolves_an_anomaly_that_was_active() {
        let db = database_with_baseline(5_000, 600);
        let settings = DetectSettings {
            refresh: Duration::from_secs(60),
            ..DetectSettings::new(
                Sensitivities::uniform(Sensitivity::Normal),
                vec![1, 24, 168],
                ConfidenceConfig::default(),
            )
        };
        let mut engine = Engine::new(
            burner(60, 72),
            DetectingSink::new(DbSink::new(db), settings),
        );
        for i in 0..60i64 {
            if i == 40 {
                engine.sink().database().start_profiling(1).unwrap();
            }
            engine
                .tick_with_elapsed(i * 5_000, Duration::from_secs(5))
                .unwrap();
        }
        let sink = engine.into_parts().1;
        let e = &sink
            .database()
            .list_anomalies(&AnomalyFilter::default(), 10)
            .unwrap()[0];
        assert!(!e.is_active(), "learning again: nothing is judged any more");
    }

    /// A process whose private memory climbs 3 MiB a minute for 40 minutes (5 s ticks).
    fn leaker() -> Script {
        Script(
            (0..480u64)
                .map(|i| {
                    vec![Observation {
                        pid: 7,
                        name: "busy.exe".into(),
                        start_time: Some(100),
                        cpu_time_100ns: Some(0),
                        working_set: Some(100 * 1024 * 1024),
                        private_bytes: Some(200 * 1024 * 1024 + i * 262_144), // 3 MiB/min
                        ..Default::default()
                    }]
                })
                .collect(),
        )
    }

    #[test]
    fn a_steadily_growing_process_is_stored_as_a_potential_leak() {
        let db = database_with_baseline(5_000, 600);
        db.conn()
            .execute(
                "INSERT INTO baseline_profiles (scope, subject_id, window_hours, metric,                  observations, first_ts_ms, last_ts_ms, mean, median, mad, stddev, p95, peak,                  growth_per_hour, computed_at_ms) VALUES ('executable', 1, 24, 'memory', 5000,                  0, 36000000, 1.0e8, 1.0e8, 1.0e6, 1.0e6, 1.1e8, 1.2e8, 0.0, 0)",
                [],
            )
            .unwrap();
        let sink = run(db, leaker(), 480);

        let events = sink
            .database()
            .list_anomalies(&AnomalyFilter::default(), 10)
            .unwrap();
        assert_eq!(events.len(), 1, "{events:#?}");
        let e = &events[0];
        assert_eq!(e.kind, winperf_core::anomaly::AnomalyKind::MemoryGrowth);
        assert_eq!(e.resource, winperf_core::config::Resource::Memory);
        assert!(
            (e.current / (1024.0 * 1024.0) - 180.0).abs() < 5.0,
            "{}",
            e.current
        );
        assert!(e.explanation.contains("Potential memory leak"));
    }

    #[test]
    fn without_a_memory_baseline_growth_is_not_judged() {
        let db = database_with_baseline(5_000, 600); // CPU baseline only
        let sink = run(db, leaker(), 480);
        assert_eq!(sink.raised(), 0);
    }

    #[test]
    fn notices_announce_raised_and_resolved_anomalies() {
        let db = database_with_baseline(5_000, 600);
        let (tx, rx) = std::sync::mpsc::channel();
        let settings = DetectSettings::new(
            Sensitivities::uniform(Sensitivity::Normal),
            vec![1, 24, 168],
            ConfidenceConfig::default(),
        );
        let mut engine = Engine::new(
            burn_then_idle(40, 60),
            DetectingSink::new(DbSink::new(db), settings).with_notices(tx),
        );
        for i in 0..60i64 {
            engine
                .tick_with_elapsed(i * 5_000, Duration::from_secs(5))
                .unwrap();
        }
        let notices: Vec<Notice> = rx.try_iter().collect();
        assert_eq!(notices.len(), 2, "{notices:#?}");
        let Notice::Raised { id, event } = &notices[0] else {
            panic!("first is the raise: {notices:?}")
        };
        assert_eq!((event.process_name.as_str(), event.pid), ("busy.exe", 7));
        let Notice::Resolved {
            id: resolved,
            process_name,
            ..
        } = &notices[1]
        else {
            panic!("then the resolution: {notices:?}")
        };
        assert_eq!((resolved, process_name.as_str()), (id, "busy.exe"));
    }

    #[test]
    fn a_receiver_that_went_away_does_not_stop_detection() {
        let db = database_with_baseline(5_000, 600);
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let settings = DetectSettings::new(
            Sensitivities::uniform(Sensitivity::Normal),
            vec![1, 24, 168],
            ConfidenceConfig::default(),
        );
        let mut engine = Engine::new(
            burner(40, 72),
            DetectingSink::new(DbSink::new(db), settings).with_notices(tx),
        );
        for i in 0..40i64 {
            engine
                .tick_with_elapsed(i * 5_000, Duration::from_secs(5))
                .unwrap();
        }
        let sink = engine.into_parts().1;
        assert_eq!(sink.raised(), 1);
        assert_eq!(sink.last_error(), None);
    }
}
