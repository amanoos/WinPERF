//! Connects the monitoring engine to SQLite.
//!
//! Each tick's batch is written in ONE transaction (new instances, their samples, and lifecycle
//! updates), so a crash never leaves samples without their instance or half a tick on disk
//! (NFR-002). This is the single writer (A3); other processes only read.
//!
//! Lifecycle: an instance is opened on first sight, its `last_seen` is refreshed every
//! [`TOUCH_EVERY_TICKS`] ticks, and its `end_time` is set when the engine reports it gone. On the first tick of a run, instances
//! left "running" by an earlier run that are no longer present are closed.
//!
//! Classification never runs on the tick: new executables are handed to an
//! [`ExecutableClassifier`] (a worker thread) and linked to their instances in a later tick, once
//! the result is ready. The database doubles as a persistent cache so a restart doesn't re-verify.

use crate::db::Database;
use crate::error::StorageError;
use crate::repo::inventory::{FileIdentity, InstanceRow, upsert_instance};
use crate::repo::samples::{insert_sample_rows, insert_system_sample};
use std::collections::HashMap;
use std::path::PathBuf;
use winperf_core::ProcessKey;
use winperf_core::engine::{SampleSink, TickBatch};
use winperf_core::inventory::ExecutableClassifier;
use winperf_core::time::utc_now_string;

pub struct DbSink {
    db: Database,
    /// Running instances this sink has stored, by identity, so samples attach to their row.
    ids: HashMap<ProcessKey, i64>,
    classifier: Option<Box<dyn ExecutableClassifier>>,
    /// path (lower-cased) -> executable row id and the file identity it was classified at.
    known_exec: HashMap<String, (i64, FileIdentity)>,
    /// path (lower-cased) -> instances waiting for that path's classification.
    waiting: HashMap<String, Vec<i64>>,
    /// Whether the once-per-run sweep of stale "running" instances has happened.
    swept: bool,
    /// Ticks recorded since the survivors' `last_seen` was last refreshed.
    ticks_since_touch: u32,
    touch_every: u32,
    /// Ticks received but not yet written (see [`DbSink::with_flush_span`]).
    pending: Vec<TickBatch>,
    /// Time covered by the buffer at which it is written; zero means every tick.
    flush_span_ms: i64,
    /// Time between the last two ticks seen, to look one tick ahead.
    last_gap_ms: i64,
}

/// Buffer about this much sampling time per database transaction. Each tick adds ~560 small rows
/// that land on as many different index pages, and every dirty page is written to the WAL and
/// later again at checkpoint (measured 3.1 MB written per tick on a populated database, ~53 GB a
/// day). Writing several ticks together dirties each page once per transaction instead of once
/// per tick. The cost: a crash loses at most this much (a clean stop loses nothing).
pub const DEFAULT_FLUSH_SPAN: std::time::Duration = std::time::Duration::from_secs(30);

/// How often (in ticks) `last_seen` is refreshed for every running instance. Refreshing it each
/// tick rewrote a row per live process (~560), and those rows are scattered across many pages once
/// the table has history, which doubled the tick's CPU. At the default 5 s this is every 5 minutes.
pub const TOUCH_EVERY_TICKS: u32 = 60;

impl DbSink {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            ids: HashMap::new(),
            classifier: None,
            known_exec: HashMap::new(),
            waiting: HashMap::new(),
            swept: false,
            ticks_since_touch: 0,
            touch_every: TOUCH_EVERY_TICKS,
            pending: Vec::new(),
            flush_span_ms: 0,
            last_gap_ms: 0,
        }
    }

    /// Write several ticks per transaction: the buffer is flushed once it covers `span` of
    /// sampling time (see [`DEFAULT_FLUSH_SPAN`]). The default is no buffering, every tick is
    /// written immediately. The engine flushes the rest when a run ends.
    pub fn with_flush_span(mut self, span: std::time::Duration) -> Self {
        self.flush_span_ms = span.as_millis() as i64;
        self
    }

    /// Refresh `last_seen` every `ticks` ticks instead of the default (tests use 1).
    pub fn with_touch_every(mut self, ticks: u32) -> Self {
        self.touch_every = ticks.max(1);
        self
    }

    /// Classify executables of newly seen processes in the background and link the results.
    pub fn with_classifier(mut self, classifier: Box<dyn ExecutableClassifier>) -> Self {
        self.classifier = Some(classifier);
        self
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Give the database back, writing any buffered ticks first (best effort).
    pub fn into_database(mut self) -> Database {
        let _ = self.flush();
        self.db
    }

    /// Drain finished classifications, then queue (or link from cache) the executables of
    /// `candidates` = (instance row id, executable path). Own transaction: a failure here never
    /// loses the tick that was already committed.
    fn classify_step(
        &mut self,
        candidates: Vec<(i64, PathBuf)>,
        now: &str,
    ) -> Result<(), StorageError> {
        let result = self.classify_inner(candidates, now);
        if result.is_err() {
            // In-memory state may be ahead of the rolled-back transaction; rebuild from the DB.
            self.known_exec.clear();
            self.waiting.clear();
        }
        result
    }

    fn classify_inner(
        &mut self,
        candidates: Vec<(i64, PathBuf)>,
        now: &str,
    ) -> Result<(), StorageError> {
        let Some(classifier) = self.classifier.as_mut() else {
            return Ok(());
        };
        let tx = self.db.conn_mut().transaction()?;

        for info in classifier.poll() {
            let key = info.path.to_string_lossy().to_lowercase();
            let Some(identity) = FileIdentity::of(&info.path) else {
                self.waiting.remove(&key); // file vanished before we could record it
                continue;
            };
            let exec_id = Database::upsert_executable_row(&tx, &info, identity, now)?;
            self.known_exec.insert(key.clone(), (exec_id, identity));
            for instance in self.waiting.remove(&key).unwrap_or_default() {
                Database::link_instance_executable(&tx, instance, exec_id)?;
            }
        }

        for (instance, path) in candidates {
            let Some(identity) = FileIdentity::of(&path) else {
                continue; // unreadable or missing: nothing to classify
            };
            let key = path.to_string_lossy().to_lowercase();
            if let Some((exec_id, at)) = self.known_exec.get(&key).copied()
                && at == identity
            {
                Database::link_instance_executable(&tx, instance, exec_id)?;
                continue;
            }
            if let Some(exec_id) = Database::executable_id_if_current(&tx, &path, identity)? {
                self.known_exec.insert(key, (exec_id, identity));
                Database::link_instance_executable(&tx, instance, exec_id)?;
                continue;
            }
            self.waiting.entry(key).or_default().push(instance);
            classifier.submit(path);
        }
        tx.commit()?;
        Ok(())
    }
}

impl SampleSink for DbSink {
    type Error = StorageError;

    fn record(&mut self, batch: &TickBatch) -> Result<(), StorageError> {
        self.pending.push(batch.clone());
        if self.should_flush() {
            self.write_pending()
        } else {
            Ok(())
        }
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            self.write_pending()
        }
    }
}

impl DbSink {
    /// Write the buffered ticks now? Always for the first tick of a run (so a new run is visible
    /// at once and the stale-instance sweep isn't delayed), otherwise once the buffer spans
    /// `flush_span`, looking one tick ahead so the buffer never grows past it. With the default
    /// span of zero every tick is written immediately.
    fn should_flush(&self) -> bool {
        if !self.swept {
            return true;
        }
        let (Some(first), Some(last)) = (self.pending.first(), self.pending.last()) else {
            return false;
        };
        let gap = match self.pending.len() {
            0 | 1 => self.last_gap_ms,
            n => last.ts_ms - self.pending[n - 2].ts_ms,
        };
        (last.ts_ms - first.ts_ms) + gap >= self.flush_span_ms
    }

    /// Write every buffered tick in ONE transaction: each tick's new instances, lifecycle changes
    /// and samples, in order. Either all of them are stored or none (and the in-memory view only
    /// changes after the commit).
    fn write_pending(&mut self) -> Result<(), StorageError> {
        let batches = std::mem::take(&mut self.pending);
        if let [.., prev, last] = batches.as_slice() {
            self.last_gap_ms = last.ts_ms - prev.ts_ms;
        }
        let now = utc_now_string();
        // Working copy of the instance ids: later ticks in the buffer see earlier ones' new
        // instances, and processes that end inside the buffer are closed.
        let mut ids = self.ids.clone();
        let mut candidates: Vec<(i64, PathBuf)> = Vec::new();
        let tx = self.db.conn_mut().transaction()?;

        for batch in &batches {
            // Instances first seen this tick. An instance that already exists (e.g. the engine was
            // restarted while the process kept running) is refreshed, not duplicated.
            let mut fresh: HashMap<ProcessKey, i64> = HashMap::new();
            for raw in &batch.new {
                let Some(start_time) = raw.start_time else {
                    continue; // no identity, can't be stored
                };
                let id = upsert_instance(
                    &tx,
                    &InstanceRow {
                        pid: raw.pid,
                        start_time,
                        parent_pid: raw.parent_pid,
                        name: &raw.name,
                        exe_path: raw
                            .exe_path
                            .as_ref()
                            .map(|p| p.to_string_lossy().into_owned()),
                        executable_id: None,
                        application_id: None,
                        user: raw.user.as_deref(),
                        session_id: raw.session_id,
                    },
                    &now,
                )?;
                fresh.insert(ProcessKey::new(raw.pid, start_time), id);
                if let Some(path) = &raw.exe_path {
                    candidates.push((id, path.clone()));
                }
            }
            ids.extend(fresh);

            for key in &batch.gone {
                if let Some(id) = ids.remove(key) {
                    Database::end_instance(&tx, id, &now)?;
                }
            }

            let rows: Vec<(i64, &_)> = batch
                .samples
                .iter()
                .filter_map(|s| ids.get(&s.key).map(|id| (*id, s)))
                .collect();
            insert_sample_rows(&tx, batch.ts_ms, &rows)?;
            if let Some(system) = &batch.system {
                insert_system_sample(&tx, batch.ts_ms, system)?;
            }
        }

        // Survivors get a fresh last_seen, but only every `touch_every` ticks (TOUCH_EVERY_TICKS).
        self.ticks_since_touch += batches.len() as u32;
        let touch = self.ticks_since_touch >= self.touch_every;
        if touch {
            for id in ids.values() {
                Database::touch_instance(&tx, *id, &now)?;
            }
        }
        if !self.swept {
            Database::close_stale_instances(&tx, &now)?;
        }
        tx.commit()?;

        // Only after a successful commit does the in-memory view change.
        if touch {
            self.ticks_since_touch = 0;
        }
        self.ids = ids;
        self.swept = true;

        self.classify_step(candidates, &now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::Path;
    use std::rc::Rc;
    use std::time::Duration;
    use winperf_core::Classification;
    use winperf_core::engine::{Engine, MetricsSource};
    use winperf_core::inventory::{ExecutableInfo, FileVersionInfo, RawProcess, SignatureStatus};
    use winperf_core::sampling::Observation;
    use winperf_core::system::SystemObservation;

    struct Script {
        rounds: VecDeque<Vec<Observation>>,
        paths: HashMap<u32, PathBuf>,
        system: VecDeque<SystemObservation>,
    }
    impl Script {
        fn new(rounds: Vec<Vec<Observation>>) -> Self {
            Self {
                rounds: rounds.into(),
                paths: HashMap::new(),
                system: VecDeque::new(),
            }
        }
        fn with_system(mut self, system: Vec<SystemObservation>) -> Self {
            self.system = system.into();
            self
        }
        fn with_path(mut self, pid: u32, path: &Path) -> Self {
            self.paths.insert(pid, path.to_path_buf());
            self
        }
    }
    impl MetricsSource for Script {
        fn logical_cpus(&self) -> u32 {
            4
        }
        fn observe(&mut self) -> Vec<Observation> {
            self.rounds.pop_front().unwrap_or_default()
        }
        fn observe_system(&mut self) -> SystemObservation {
            self.system.pop_front().unwrap_or_default()
        }
        fn describe(&mut self, o: &Observation) -> RawProcess {
            RawProcess {
                pid: o.pid,
                parent_pid: o.parent_pid,
                name: o.name.clone(),
                start_time: o.start_time,
                exe_path: Some(
                    self.paths
                        .get(&o.pid)
                        .cloned()
                        .unwrap_or_else(|| format!("C:\\apps\\{}", o.name).into()),
                ),
                user: Some("PC\\me".into()),
                session_id: Some(1),
                ..Default::default()
            }
        }
    }

    fn obs(pid: u32, start: u64, cpu: u64, private: u64) -> Observation {
        Observation {
            pid,
            parent_pid: 4,
            name: format!("p{pid}.exe"),
            start_time: Some(start),
            cpu_time_100ns: Some(cpu),
            working_set: Some(private / 2),
            private_bytes: Some(private),
            virtual_bytes: Some(private * 4),
            peak_working_set: Some(private),
            ..Default::default()
        }
    }

    fn count(db: &Database, table: &str) -> i64 {
        db.conn()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    fn instance_id(db: &Database, pid: u32, start: i64) -> i64 {
        db.conn()
            .query_row(
                "SELECT id FROM process_instances WHERE pid = ?1 AND start_time = ?2",
                rusqlite::params![pid, start],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn end_time(db: &Database, pid: u32, start: i64) -> Option<String> {
        db.conn()
            .query_row(
                "SELECT end_time FROM process_instances WHERE pid = ?1 AND start_time = ?2",
                rusqlite::params![pid, start],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn tick(e: &mut Engine<Script, DbSink>, ts: i64) {
        e.tick_with_elapsed(ts, Duration::from_secs(1)).unwrap();
    }

    // ---- samples (T10) -------------------------------------------------------------------

    #[test]
    fn samples_are_stored_with_null_for_the_first_cpu_value() {
        let script = Script::new(vec![
            vec![obs(5, 100, 0, 8_000)],
            vec![obs(5, 100, 10_000_000, 9_000)], // +1 s CPU in 1 s on 4 cpus = 25%
        ]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        e.tick_with_elapsed(1_000, Duration::ZERO).unwrap();
        e.tick_with_elapsed(2_000, Duration::from_secs(1)).unwrap();
        let (_, sink) = e.into_parts();
        let db = sink.database();

        let id = instance_id(db, 5, 100);
        let s = db.samples_for_instance(id).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].cpu_percent, None, "first sample: no CPU, not zero");
        assert_eq!(s[0].private_bytes, Some(8_000));
        assert_eq!(s[1].cpu_percent, Some(25.0));
        assert_eq!(s[1].private_bytes, Some(9_000));
        assert_eq!(s[1].virtual_bytes, Some(36_000));
        assert_eq!((s[0].ts_ms, s[1].ts_ms), (1_000, 2_000));
    }

    #[test]
    fn a_reused_pid_creates_two_instances_and_row_counts_add_up() {
        let script = Script::new(vec![
            vec![obs(5, 100, 0, 1_000)],
            vec![obs(5, 100, 5, 1_000)],
            vec![obs(5, 200, 0, 2_000)], // PID 5 reborn with a new start time
        ]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        for t in 0..3 {
            tick(&mut e, 1_000 * (t + 1));
        }
        let (_, sink) = e.into_parts();
        let db = sink.database();

        assert_eq!(count(db, "process_instances"), 2, "one row per instance");
        assert_eq!(
            db.sample_count().unwrap(),
            3,
            "one row per instance per tick"
        );
        let first = instance_id(db, 5, 100);
        let reborn = instance_id(db, 5, 200);
        assert_ne!(first, reborn);
        assert_eq!(db.samples_for_instance(first).unwrap().len(), 2);
        let r = db.samples_for_instance(reborn).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            r[0].cpu_percent, None,
            "new instance starts without a CPU delta"
        );
    }

    #[test]
    fn instance_details_from_describe_are_stored() {
        let script = Script::new(vec![vec![obs(7, 300, 0, 100)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        let (_, sink) = e.into_parts();
        let (name, path, user, session): (String, String, String, i64) = sink
            .database()
            .conn()
            .query_row(
                "SELECT name, exe_path, user_account, session_id FROM process_instances",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(name, "p7.exe");
        assert_eq!(path, "C:\\apps\\p7.exe");
        assert_eq!(user, "PC\\me");
        assert_eq!(session, 1);
    }

    #[test]
    fn restarting_the_engine_reuses_instances_instead_of_duplicating_them() {
        let dir = TempDir::new("sink-restart");
        let path = dir.path().join("m.db");

        let script = Script::new(vec![vec![obs(9, 500, 0, 100)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open(&path).unwrap()));
        e.tick_with_elapsed(1_000, Duration::ZERO).unwrap();
        drop(e);

        // "Restart": fresh sampler and sink, same database, same still-running process.
        let script = Script::new(vec![vec![obs(9, 500, 50, 120)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open(&path).unwrap()));
        e.tick_with_elapsed(2_000, Duration::from_secs(5)).unwrap();
        let (_, sink) = e.into_parts();
        let db = sink.database();

        assert_eq!(count(db, "process_instances"), 1);
        assert_eq!(db.sample_count().unwrap(), 2);
    }

    #[test]
    fn samples_without_an_identity_are_never_stored() {
        let denied = Observation {
            pid: 4,
            name: "System".into(),
            ..Default::default()
        };
        let script = Script::new(vec![vec![denied, obs(5, 100, 0, 10)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        let stats = e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        let (_, sink) = e.into_parts();
        assert_eq!(stats.unreadable, 1);
        assert_eq!(count(sink.database(), "process_instances"), 1);
        assert_eq!(sink.database().sample_count().unwrap(), 1);
    }

    #[test]
    fn a_failed_batch_leaves_nothing_behind() {
        // Force a failure after the instance insert by dropping the samples table first.
        let script = Script::new(vec![vec![obs(5, 100, 0, 10)]]);
        let db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch("DROP TABLE resource_samples")
            .unwrap();
        let mut e = Engine::new(script, DbSink::new(db));
        assert!(e.tick_with_elapsed(1, Duration::ZERO).is_err());
        let (_, sink) = e.into_parts();
        assert_eq!(
            count(sink.database(), "process_instances"),
            0,
            "rolled back"
        );
    }

    // ---- process I/O and system health (T12) ---------------------------------------------

    #[test]
    fn process_io_rates_are_stored_and_null_until_a_second_observation() {
        let mut first = obs(5, 100, 0, 1_000);
        first.io_read_bytes = Some(1_000);
        first.io_write_bytes = Some(2_000);
        first.io_read_ops = Some(10);
        first.io_write_ops = Some(20);
        let mut second = obs(5, 100, 0, 1_000);
        second.io_read_bytes = Some(11_000); // +10_000 B over 5 s
        second.io_write_bytes = Some(2_000); // idle writer
        second.io_read_ops = Some(60);
        second.io_write_ops = Some(20);

        let script = Script::new(vec![vec![first], vec![second]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        e.tick_with_elapsed(2, Duration::from_secs(5)).unwrap();
        let (_, sink) = e.into_parts();
        let db = sink.database();

        let rows = db.samples_for_instance(instance_id(db, 5, 100)).unwrap();
        assert_eq!(
            rows[0].io_read_bytes_per_sec, None,
            "first sample has no rate"
        );
        assert_eq!(rows[1].io_read_bytes_per_sec, Some(2_000.0));
        assert_eq!(
            rows[1].io_write_bytes_per_sec,
            Some(0.0),
            "idle is 0, not NULL"
        );
        assert_eq!(rows[1].io_read_ops_per_sec, Some(10.0));
        assert_eq!(rows[1].io_write_ops_per_sec, Some(0.0));
    }

    #[test]
    fn per_process_network_rates_are_stored_and_null_without_attribution() {
        let mut first = obs(5, 100, 0, 1_000);
        first.net_rx_bytes = Some(10_000);
        first.net_tx_bytes = Some(0);
        let mut second = obs(5, 100, 0, 1_000);
        second.net_rx_bytes = Some(60_000); // +50_000 B over 5 s
        second.net_tx_bytes = Some(0); // measured: no traffic
        // Process 6 is observed with no attribution at all (collector not running).
        let plain = |start| obs(6, start, 0, 1_000);

        let script = Script::new(vec![vec![first, plain(200)], vec![second, plain(200)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        e.tick_with_elapsed(2, Duration::from_secs(5)).unwrap();
        let (_, sink) = e.into_parts();
        let db = sink.database();

        let measured = db.samples_for_instance(instance_id(db, 5, 100)).unwrap();
        assert_eq!(
            measured[0].net_rx_bytes_per_sec, None,
            "first sample: no rate yet"
        );
        assert_eq!(measured[1].net_rx_bytes_per_sec, Some(10_000.0));
        assert_eq!(
            measured[1].net_tx_bytes_per_sec,
            Some(0.0),
            "measured zero stays 0"
        );

        let unmeasured = db.samples_for_instance(instance_id(db, 6, 200)).unwrap();
        assert!(
            unmeasured
                .iter()
                .all(|r| r.net_rx_bytes_per_sec.is_none() && r.net_tx_bytes_per_sec.is_none()),
            "no attribution => NULL, never 0"
        );
    }

    #[test]
    fn processes_whose_io_cannot_be_read_store_null_rates() {
        let script = Script::new(vec![vec![obs(5, 100, 0, 1)], vec![obs(5, 100, 1, 1)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        e.tick_with_elapsed(2, Duration::from_secs(1)).unwrap();
        let (_, sink) = e.into_parts();
        let db = sink.database();
        let rows = db.samples_for_instance(instance_id(db, 5, 100)).unwrap();
        assert!(rows.iter().all(|r| r.io_write_bytes_per_sec.is_none()));
    }

    #[test]
    fn system_health_is_stored_one_row_per_tick_with_null_for_unavailable_metrics() {
        let sys = |idle, kernel, user, mem| SystemObservation {
            cpu_idle_100ns: Some(idle),
            cpu_kernel_100ns: Some(kernel),
            cpu_user_100ns: Some(user),
            memory_total_bytes: mem,
            disk_queue_length: Some(3.0),
            // disk utilization deliberately missing (a broken counter)
            ..Default::default()
        };
        let script =
            Script::new(vec![vec![obs(1, 100, 0, 10)], vec![obs(1, 100, 1, 10)]]).with_system(
                vec![sys(0, 0, 0, Some(8_000)), sys(50, 100, 100, Some(8_000))],
            );
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        e.tick_with_elapsed(1_000, Duration::ZERO).unwrap();
        e.tick_with_elapsed(2_000, Duration::from_secs(1)).unwrap();
        let (_, sink) = e.into_parts();
        let rows = sink.database().system_samples().unwrap();

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].cpu_percent, None, "no CPU rate on the first tick");
        assert_eq!(rows[0].memory_total_bytes, Some(8_000));
        assert_eq!(rows[1].cpu_percent, Some(75.0));
        assert_eq!(rows[1].disk_queue_length, Some(3.0));
        assert_eq!(
            rows[1].disk_utilization_percent, None,
            "broken counter stored as NULL"
        );
        assert_eq!((rows[0].ts_ms, rows[1].ts_ms), (1_000, 2_000));
    }

    #[test]
    fn no_system_row_is_written_when_the_source_supplies_nothing() {
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        e.tick_with_elapsed(1, Duration::ZERO).unwrap();
        let (_, sink) = e.into_parts();
        assert_eq!(sink.database().system_sample_count().unwrap(), 0);
    }

    // ---- lifecycle (T11) -----------------------------------------------------------------

    #[test]
    fn an_instance_that_disappears_gets_an_end_time_and_survivors_stay_open() {
        let script = Script::new(vec![
            vec![obs(1, 100, 0, 10), obs(2, 100, 0, 10)],
            vec![obs(1, 100, 1, 10)], // pid 2 is gone
        ]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        tick(&mut e, 1);
        tick(&mut e, 2);
        let (_, sink) = e.into_parts();
        let db = sink.database();

        assert!(end_time(db, 2, 100).is_some(), "exited instance is closed");
        assert!(end_time(db, 1, 100).is_none(), "survivor stays open");
        assert_eq!(db.running_instance_count().unwrap(), 1);
    }

    #[test]
    fn pid_reuse_closes_the_old_instance_and_opens_the_new_one() {
        let script = Script::new(vec![vec![obs(5, 100, 0, 10)], vec![obs(5, 200, 0, 10)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        tick(&mut e, 1);
        tick(&mut e, 2);
        let (_, sink) = e.into_parts();
        let db = sink.database();
        assert!(end_time(db, 5, 100).is_some());
        assert!(end_time(db, 5, 200).is_none());
        assert_eq!(count(db, "process_instances"), 2);
    }

    #[test]
    fn last_seen_moves_forward_on_later_ticks() {
        let dir = TempDir::new("last-seen");
        let path = dir.path().join("l.db");
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)], vec![obs(1, 100, 1, 10)]]);
        let sink = DbSink::new(Database::open(&path).unwrap()).with_touch_every(1);
        let mut e = Engine::new(script, sink);
        tick(&mut e, 1);
        // Backdate the stored last_seen (through a second connection), then tick again.
        let other = Database::open(&path).unwrap();
        other
            .conn()
            .execute(
                "UPDATE process_instances SET last_seen = '2000-01-01 00:00:00'",
                [],
            )
            .unwrap();
        tick(&mut e, 2);
        let last: String = other
            .conn()
            .query_row("SELECT last_seen FROM process_instances", [], |r| r.get(0))
            .unwrap();
        assert_ne!(
            last, "2000-01-01 00:00:00",
            "survivor's last_seen refreshed"
        );
        assert!(last.starts_with("20"));
    }

    #[test]
    fn last_seen_is_not_rewritten_every_tick_by_default() {
        let dir = TempDir::new("last-seen-default");
        let path = dir.path().join("d.db");
        let rounds: Vec<_> = (0..3).map(|i| vec![obs(1, 100, i, 10)]).collect();
        let mut e = Engine::new(
            Script::new(rounds),
            DbSink::new(Database::open(&path).unwrap()),
        );
        tick(&mut e, 1);
        let other = Database::open(&path).unwrap();
        other
            .conn()
            .execute(
                "UPDATE process_instances SET last_seen = '2000-01-01 00:00:00'",
                [],
            )
            .unwrap();
        tick(&mut e, 2);
        tick(&mut e, 3);
        let last: String = other
            .conn()
            .query_row("SELECT last_seen FROM process_instances", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            last, "2000-01-01 00:00:00",
            "ticks 2 and 3 must not rewrite last_seen (refresh is every {TOUCH_EVERY_TICKS} ticks)"
        );
    }

    // ---- batching: several ticks per transaction ----------------------------------------

    fn batching_sink(path: &Path) -> DbSink {
        DbSink::new(Database::open(path).unwrap()).with_flush_span(Duration::from_secs(30))
    }

    fn steady_rounds(n: u64) -> Vec<Vec<Observation>> {
        (0..n).map(|i| vec![obs(1, 100, i, 10)]).collect()
    }

    #[test]
    fn buffered_ticks_are_written_together_six_at_a_time() {
        let dir = TempDir::new("batch-six");
        let path = dir.path().join("b.db");
        let mut e = Engine::new(Script::new(steady_rounds(8)), batching_sink(&path));
        let other = Database::open(&path).unwrap();
        let mut seen = Vec::new();
        for i in 0..8 {
            tick(&mut e, i * 5_000); // the default 5 s interval
            seen.push(count(&other, "resource_samples"));
        }
        // The first tick is written at once; then ticks 2-7 go in one transaction.
        assert_eq!(
            seen,
            vec![1, 1, 1, 1, 1, 1, 7, 7],
            "rows visible after each tick"
        );
    }

    #[test]
    fn flushing_writes_the_buffered_tail() {
        let dir = TempDir::new("batch-flush");
        let path = dir.path().join("f.db");
        let mut e = Engine::new(Script::new(steady_rounds(3)), batching_sink(&path));
        for i in 0..3 {
            tick(&mut e, i * 5_000);
        }
        let other = Database::open(&path).unwrap();
        assert_eq!(
            count(&other, "resource_samples"),
            1,
            "ticks 2-3 still buffered"
        );
        let (_, mut sink) = e.into_parts();
        sink.flush().unwrap();
        assert_eq!(count(&other, "resource_samples"), 3);
    }

    #[test]
    fn the_engine_flushes_when_a_run_ends() {
        let dir = TempDir::new("batch-run");
        let path = dir.path().join("r.db");
        let mut e = Engine::new(Script::new(steady_rounds(3)), batching_sink(&path));
        let stop = std::sync::atomic::AtomicBool::new(false);
        e.run(Duration::ZERO, Some(3), &stop, |_, _| {}).unwrap();
        assert_eq!(
            count(&Database::open(&path).unwrap(), "resource_samples"),
            3
        );
    }

    #[test]
    fn a_process_that_starts_and_ends_inside_one_buffer_is_stored_and_closed() {
        let dir = TempDir::new("batch-short-lived");
        let path = dir.path().join("s.db");
        let rounds = vec![
            vec![obs(1, 100, 0, 10)],
            vec![obs(1, 100, 1, 10), obs(2, 200, 0, 10)],
            vec![obs(1, 100, 2, 10)], // pid 2 is gone
            vec![obs(1, 100, 3, 10)],
        ];
        let mut e = Engine::new(Script::new(rounds), batching_sink(&path));
        for i in 0..4 {
            tick(&mut e, i * 5_000);
        }
        let (_, mut sink) = e.into_parts();
        sink.flush().unwrap();
        let db = Database::open(&path).unwrap();
        assert_eq!(count(&db, "resource_samples"), 5);
        assert!(
            end_time(&db, 2, 200).is_some(),
            "short-lived instance closed"
        );
        assert!(end_time(&db, 1, 100).is_none(), "survivor still running");
        let p2_samples: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM resource_samples WHERE process_instance_id = ?1",
                [instance_id(&db, 2, 200)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(p2_samples, 1);
    }

    #[test]
    fn startup_sweep_closes_leftovers_from_an_earlier_run_but_keeps_running_ones() {
        let dir = TempDir::new("sweep");
        let path = dir.path().join("s.db");
        {
            // An earlier run left two instances "running"; one of them is still alive now.
            let db = Database::open(&path).unwrap();
            for (pid, start) in [(99u32, 1i64), (1, 100)] {
                db.conn()
                    .execute(
                        "INSERT INTO process_instances \
                         (pid, start_time, parent_pid, name, first_seen, last_seen) \
                         VALUES (?1, ?2, 0, 'old.exe', '2000-01-01 00:00:00', '2000-01-01 00:00:00')",
                        rusqlite::params![pid, start],
                    )
                    .unwrap();
            }
        }
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open(&path).unwrap()));
        tick(&mut e, 1);
        let (_, sink) = e.into_parts();
        let db = sink.database();

        assert!(end_time(db, 99, 1).is_some(), "leftover closed");
        assert!(
            end_time(db, 1, 100).is_none(),
            "still-running instance reopened"
        );
        assert_eq!(
            count(db, "process_instances"),
            2,
            "no duplicate for the survivor"
        );
    }

    // ---- classification (T11) ------------------------------------------------------------

    /// A classifier the test controls: records submissions, returns whatever is staged.
    #[derive(Clone, Default)]
    struct Fake {
        submitted: Rc<RefCell<Vec<PathBuf>>>,
        ready: Rc<RefCell<Vec<ExecutableInfo>>>,
    }
    impl ExecutableClassifier for Fake {
        fn submit(&mut self, path: PathBuf) {
            self.submitted.borrow_mut().push(path);
        }
        fn poll(&mut self) -> Vec<ExecutableInfo> {
            self.ready.borrow_mut().drain(..).collect()
        }
    }

    fn microsoft_info(path: &Path) -> ExecutableInfo {
        ExecutableInfo {
            path: path.to_path_buf(),
            version: FileVersionInfo::default(),
            signature: SignatureStatus::Valid {
                signer: "Microsoft Corporation".into(),
            },
            classification: Classification::MicrosoftOfficial,
        }
    }

    fn temp_exe(dir: &TempDir, name: &str) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, b"MZ-fake").unwrap();
        p
    }

    fn linked_exec(db: &Database, pid: u32) -> Option<i64> {
        db.conn()
            .query_row(
                "SELECT executable_id FROM process_instances WHERE pid = ?1",
                [pid],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn a_new_executable_is_submitted_without_blocking_and_linked_when_the_result_arrives() {
        let dir = TempDir::new("classify");
        let exe = temp_exe(&dir, "tool.exe");
        let fake = Fake::default();
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)], vec![obs(1, 100, 1, 10)]])
            .with_path(1, &exe);
        let sink = DbSink::new(Database::open_in_memory().unwrap())
            .with_classifier(Box::new(fake.clone()));
        let mut e = Engine::new(script, sink);

        tick(&mut e, 1);
        assert_eq!(*fake.submitted.borrow(), vec![exe.clone()]);
        assert_eq!(
            linked_exec(e_db(&e), 1),
            None,
            "tick did not wait for the verdict"
        );
        assert_eq!(count(e_db(&e), "executables"), 0);

        fake.ready.borrow_mut().push(microsoft_info(&exe)); // the worker finishes
        tick(&mut e, 2);

        let db = e_db(&e);
        let exec_id = linked_exec(db, 1).expect("instance linked once classified");
        let class: String = db
            .conn()
            .query_row(
                "SELECT classification FROM executables WHERE id = ?1",
                [exec_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(class, "microsoft");
        assert_eq!(fake.submitted.borrow().len(), 1, "not resubmitted");
    }

    fn e_db(e: &Engine<Script, DbSink>) -> &Database {
        // `Engine` has no accessor for the sink; tests reach it through a tiny helper below.
        crate::sink::tests_support::sink_db(e)
    }

    #[test]
    fn a_second_instance_of_a_known_executable_links_immediately() {
        let dir = TempDir::new("classify-known");
        let exe = temp_exe(&dir, "tool.exe");
        let fake = Fake::default();
        let script = Script::new(vec![
            vec![obs(1, 100, 0, 10)],
            vec![obs(1, 100, 1, 10), obs(2, 100, 0, 10)],
        ])
        .with_path(1, &exe)
        .with_path(2, &exe);
        let sink = DbSink::new(Database::open_in_memory().unwrap())
            .with_classifier(Box::new(fake.clone()));
        let mut e = Engine::new(script, sink);

        tick(&mut e, 1);
        fake.ready.borrow_mut().push(microsoft_info(&exe));
        tick(&mut e, 2);

        let db = e_db(&e);
        assert_eq!(linked_exec(db, 2), linked_exec(db, 1));
        assert!(linked_exec(db, 2).is_some());
        assert_eq!(fake.submitted.borrow().len(), 1, "path verified only once");
        assert_eq!(count(db, "executables"), 1);
    }

    #[test]
    fn instances_waiting_on_the_same_path_are_all_linked_together() {
        let dir = TempDir::new("classify-waiting");
        let exe = temp_exe(&dir, "tool.exe");
        let fake = Fake::default();
        let script = Script::new(vec![
            vec![obs(1, 100, 0, 10), obs(2, 100, 0, 10)],
            vec![obs(1, 100, 1, 10), obs(2, 100, 1, 10)],
        ])
        .with_path(1, &exe)
        .with_path(2, &exe);
        let sink = DbSink::new(Database::open_in_memory().unwrap())
            .with_classifier(Box::new(fake.clone()));
        let mut e = Engine::new(script, sink);
        tick(&mut e, 1);
        assert_eq!(
            fake.submitted.borrow().len(),
            2,
            "fake doesn't dedupe; real classifier does"
        );
        fake.ready.borrow_mut().push(microsoft_info(&exe));
        tick(&mut e, 2);
        let db = e_db(&e);
        assert!(linked_exec(db, 1).is_some());
        assert_eq!(linked_exec(db, 1), linked_exec(db, 2));
    }

    #[test]
    fn a_restart_links_from_the_persistent_cache_without_reverifying() {
        let dir = TempDir::new("classify-cache");
        let exe = temp_exe(&dir, "tool.exe");
        let db_path = dir.path().join("c.db");

        // Run 1 classifies the executable.
        let fake1 = Fake::default();
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)], vec![obs(1, 100, 1, 10)]])
            .with_path(1, &exe);
        let sink =
            DbSink::new(Database::open(&db_path).unwrap()).with_classifier(Box::new(fake1.clone()));
        let mut e = Engine::new(script, sink);
        tick(&mut e, 1);
        fake1.ready.borrow_mut().push(microsoft_info(&exe));
        tick(&mut e, 2);
        drop(e);

        // Run 2 (restart) sees a new process of the same, unchanged file.
        let fake2 = Fake::default();
        let script = Script::new(vec![vec![obs(2, 200, 0, 10)]]).with_path(2, &exe);
        let sink =
            DbSink::new(Database::open(&db_path).unwrap()).with_classifier(Box::new(fake2.clone()));
        let mut e = Engine::new(script, sink);
        tick(&mut e, 3);

        assert!(
            fake2.submitted.borrow().is_empty(),
            "served from the DB cache"
        );
        assert!(linked_exec(e_db(&e), 2).is_some());
    }

    #[test]
    fn a_changed_executable_is_verified_again() {
        let dir = TempDir::new("classify-changed");
        let exe = temp_exe(&dir, "tool.exe");
        let db_path = dir.path().join("c.db");

        let fake1 = Fake::default();
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)], vec![obs(1, 100, 1, 10)]])
            .with_path(1, &exe);
        let mut e = Engine::new(
            script,
            DbSink::new(Database::open(&db_path).unwrap()).with_classifier(Box::new(fake1.clone())),
        );
        tick(&mut e, 1);
        fake1.ready.borrow_mut().push(microsoft_info(&exe));
        tick(&mut e, 2);
        drop(e);

        std::fs::write(&exe, b"MZ-fake-but-different-and-longer").unwrap(); // new size

        let fake2 = Fake::default();
        let script = Script::new(vec![vec![obs(2, 200, 0, 10)]]).with_path(2, &exe);
        let mut e = Engine::new(
            script,
            DbSink::new(Database::open(&db_path).unwrap()).with_classifier(Box::new(fake2.clone())),
        );
        tick(&mut e, 3);
        assert_eq!(
            fake2.submitted.borrow().len(),
            1,
            "stale cache entry must not be trusted"
        );
    }

    #[test]
    fn processes_with_unreadable_executables_are_not_submitted() {
        let fake = Fake::default();
        // Default describe() path C:\apps\p1.exe doesn't exist, so it can't be stat'ed.
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)]]);
        let sink = DbSink::new(Database::open_in_memory().unwrap())
            .with_classifier(Box::new(fake.clone()));
        let mut e = Engine::new(script, sink);
        tick(&mut e, 1);
        assert!(fake.submitted.borrow().is_empty());
        assert_eq!(linked_exec(e_db(&e), 1), None);
    }

    #[test]
    fn without_a_classifier_nothing_is_linked_and_nothing_breaks() {
        let script = Script::new(vec![vec![obs(1, 100, 0, 10)], vec![obs(1, 100, 1, 10)]]);
        let mut e = Engine::new(script, DbSink::new(Database::open_in_memory().unwrap()));
        tick(&mut e, 1);
        tick(&mut e, 2);
        assert_eq!(count(e_db(&e), "executables"), 0);
    }
}

/// Test-only access to the sink inside an engine.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use winperf_core::engine::{Engine, MetricsSource};

    pub fn sink_db<M: MetricsSource>(e: &Engine<M, DbSink>) -> &Database {
        e.sink().database()
    }
}
