//! Anomaly events (`anomaly_events`) and the baselines the detectors judge against.

use crate::db::Database;
use crate::error::{Result, StorageError};
use rusqlite::{OptionalExtension, params};
use std::collections::HashMap;
use winperf_core::anomaly::{AnomalyEvent, BaselineStats, Severity};
use winperf_core::config::{ConfidenceConfig, Resource};
use winperf_core::profiler::confidence::assess;

/// One stored anomaly event, as read back.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredAnomaly {
    pub id: i64,
    pub detected_ts_ms: i64,
    pub process_instance_id: Option<i64>,
    pub pid: u32,
    pub process_name: String,
    pub application: Option<String>,
    pub exe_path: String,
    pub resource: Resource,
    pub current: f64,
    pub baseline: f64,
    pub deviation_pct: f64,
    pub duration_ms: i64,
    pub severity: Severity,
    pub system_cpu_percent: Option<f64>,
    pub system_memory_percent: Option<f64>,
    pub baseline_window_hours: u32,
    pub baseline_confidence: String,
    pub explanation: String,
}

const COLUMNS: &str = "id, detected_ts_ms, process_instance_id, pid, process_name, application, \
                       exe_path, resource, current_value, baseline_value, deviation_pct, \
                       duration_ms, severity, system_cpu_percent, system_memory_percent, \
                       baseline_window_hours, baseline_confidence, explanation";

fn from_row(r: &rusqlite::Row<'_>) -> Result<StoredAnomaly> {
    let resource: String = r.get(7)?;
    let severity: String = r.get(12)?;
    Ok(StoredAnomaly {
        id: r.get(0)?,
        detected_ts_ms: r.get(1)?,
        process_instance_id: r.get(2)?,
        pid: r.get(3)?,
        process_name: r.get(4)?,
        application: r.get(5)?,
        exe_path: r.get(6)?,
        resource: Resource::parse(&resource)
            .ok_or_else(|| StorageError::Corrupt(format!("anomaly resource {resource:?}")))?,
        current: r.get(8)?,
        baseline: r.get(9)?,
        deviation_pct: r.get(10)?,
        duration_ms: r.get(11)?,
        severity: Severity::parse(&severity)
            .ok_or_else(|| StorageError::Corrupt(format!("anomaly severity {severity:?}")))?,
        system_cpu_percent: r.get(13)?,
        system_memory_percent: r.get(14)?,
        baseline_window_hours: r.get(15)?,
        baseline_confidence: r.get(16)?,
        explanation: r.get(17)?,
    })
}

impl Database {
    /// Store an event and return its id. The instance link and the application name are looked up
    /// here; both stay empty when the instance has not been written yet.
    pub fn insert_anomaly(&self, e: &AnomalyEvent) -> Result<i64> {
        let linked: Option<(i64, Option<String>)> = self
            .conn()
            .query_row(
                "SELECT pi.id, a.name FROM process_instances pi \
                 LEFT JOIN installed_applications a ON a.id = pi.application_id \
                 WHERE pi.pid = ?1 AND pi.start_time = ?2",
                params![e.pid, e.start_time as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (instance_id, application) = match linked {
            Some((id, app)) => (Some(id), app),
            None => (None, None),
        };
        self.conn().execute(
            "INSERT INTO anomaly_events (detected_ts_ms, process_instance_id, pid, process_name, \
             application, exe_path, resource, current_value, baseline_value, deviation_pct, \
             duration_ms, severity, system_cpu_percent, system_memory_percent, \
             baseline_window_hours, baseline_confidence, explanation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                e.detected_ts_ms,
                instance_id,
                e.pid,
                e.process_name,
                application,
                e.exe_path,
                e.resource.as_str(),
                e.current,
                e.baseline,
                e.deviation_pct,
                e.duration_ms,
                e.severity.as_str(),
                e.system.cpu_percent,
                e.system.memory_percent,
                e.baseline_window_hours,
                e.baseline_confidence.label(),
                e.explanation,
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Events newest first, optionally only those detected at or after `since_ms`.
    pub fn list_anomalies(&self, since_ms: Option<i64>, limit: u32) -> Result<Vec<StoredAnomaly>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLUMNS} FROM anomaly_events WHERE detected_ts_ms >= ?1 \
             ORDER BY detected_ts_ms DESC, id DESC LIMIT ?2"
        ))?;
        let mut rows = stmt.query(params![since_ms.unwrap_or(i64::MIN), limit])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(from_row(r)?);
        }
        Ok(out)
    }

    pub fn anomaly(&self, id: i64) -> Result<Option<StoredAnomaly>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLUMNS} FROM anomaly_events WHERE id = ?1"
        ))?;
        let mut rows = stmt.query([id])?;
        match rows.next()? {
            Some(r) => Ok(Some(from_row(r)?)),
            None => Ok(None),
        }
    }

    pub fn anomaly_count(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT COUNT(*) FROM anomaly_events", [], |r| r.get(0))?)
    }

    /// CPU baselines the detector may use, keyed by lower-cased executable path. Only the given
    /// windows count, a subject takes its longest window whose confidence is above Insufficient,
    /// and a subject with no such window is left out (so it is never judged).
    pub fn usable_cpu_baselines(
        &self,
        windows_hours: &[u32],
        confidence: &ConfidenceConfig,
    ) -> Result<HashMap<String, BaselineStats>> {
        let mut stmt = self.conn().prepare(
            "SELECT e.path_key, bp.window_hours, bp.observations, bp.first_ts_ms, bp.last_ts_ms, \
                    bp.mean, bp.median, bp.mad, bp.p95 \
             FROM baseline_profiles bp JOIN executables e ON e.id = bp.subject_id \
             WHERE bp.scope = 'executable' AND bp.metric = 'cpu' \
             ORDER BY bp.window_hours DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out: HashMap<String, BaselineStats> = HashMap::new();
        while let Some(r) = rows.next()? {
            let window_hours: u32 = r.get(1)?;
            if !windows_hours.contains(&window_hours) {
                continue;
            }
            let path_key: String = r.get(0)?;
            if out.contains_key(&path_key) {
                continue; // a longer window already qualified
            }
            let observations = r.get::<_, i64>(2)?.max(0) as u64;
            let span_ms = r.get::<_, i64>(4)? - r.get::<_, i64>(3)?;
            let level = assess(observations, span_ms, confidence);
            if !level.is_usable() {
                continue;
            }
            out.insert(
                path_key,
                BaselineStats {
                    mean: r.get(5)?,
                    median: r.get(6)?,
                    mad: r.get(7)?,
                    p95: r.get(8)?,
                    confidence: level,
                    window_hours,
                },
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winperf_core::anomaly::SystemHealth;
    use winperf_core::profiler::confidence::Confidence;

    fn event(ts: i64, pid: u32, severity: Severity) -> AnomalyEvent {
        AnomalyEvent {
            detected_ts_ms: ts,
            pid,
            start_time: 100,
            process_name: "busy.exe".into(),
            exe_path: r"C:\apps\busy.exe".into(),
            resource: Resource::Cpu,
            current: 72.0,
            baseline: 8.0,
            deviation_pct: 800.0,
            duration_ms: 120_000,
            severity,
            system: SystemHealth {
                cpu_percent: Some(91.0),
                memory_percent: None,
            },
            baseline_window_hours: 24,
            baseline_confidence: Confidence::Established,
            explanation: "busy.exe used 72% CPU".into(),
        }
    }

    #[test]
    fn an_event_round_trips_with_every_field() {
        let db = Database::open_in_memory().unwrap();
        let id = db.insert_anomaly(&event(5_000, 7, Severity::High)).unwrap();
        let back = db.anomaly(id).unwrap().unwrap();

        assert_eq!(back.id, id);
        assert_eq!(back.detected_ts_ms, 5_000);
        assert_eq!(back.pid, 7);
        assert_eq!(back.process_name, "busy.exe");
        assert_eq!(back.exe_path, r"C:\apps\busy.exe");
        assert_eq!(back.resource, Resource::Cpu);
        assert_eq!((back.current, back.baseline), (72.0, 8.0));
        assert_eq!(back.deviation_pct, 800.0);
        assert_eq!(back.duration_ms, 120_000);
        assert_eq!(back.severity, Severity::High);
        assert_eq!(back.system_cpu_percent, Some(91.0));
        assert_eq!(back.system_memory_percent, None, "unmeasured stays NULL");
        assert_eq!(back.baseline_window_hours, 24);
        assert_eq!(back.baseline_confidence, "Established");
        assert_eq!(back.explanation, "busy.exe used 72% CPU");
        assert_eq!(back.process_instance_id, None, "instance was never stored");
        assert_eq!(db.anomaly(id + 1).unwrap(), None);
    }

    #[test]
    fn events_list_newest_first_with_a_time_filter_and_limit() {
        let db = Database::open_in_memory().unwrap();
        for (ts, pid) in [(1_000, 1), (3_000, 3), (2_000, 2)] {
            db.insert_anomaly(&event(ts, pid, Severity::Warning))
                .unwrap();
        }
        let pids = |rows: Vec<StoredAnomaly>| rows.iter().map(|r| r.pid).collect::<Vec<_>>();

        assert_eq!(pids(db.list_anomalies(None, 10).unwrap()), vec![3, 2, 1]);
        assert_eq!(
            pids(db.list_anomalies(Some(2_000), 10).unwrap()),
            vec![3, 2]
        );
        assert_eq!(pids(db.list_anomalies(None, 1).unwrap()), vec![3]);
        assert_eq!(db.anomaly_count().unwrap(), 3);
    }

    #[test]
    fn the_instance_and_its_application_are_linked_when_known() {
        let db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO installed_applications (id, app_key, name, registry_sources, \
                   classification, first_seen, last_seen, scan_seq) \
                 VALUES (1, 'busy|1|x', 'Busy Suite', 'hklm', 'third_party', 't', 't', 1); \
                 INSERT INTO process_instances (id, pid, start_time, parent_pid, name, \
                   application_id, first_seen, last_seen) \
                 VALUES (9, 7, 100, 0, 'busy.exe', 1, 't', 't');",
            )
            .unwrap();
        let id = db.insert_anomaly(&event(1, 7, Severity::Warning)).unwrap();
        let back = db.anomaly(id).unwrap().unwrap();
        assert_eq!(back.process_instance_id, Some(9));
        assert_eq!(back.application.as_deref(), Some("Busy Suite"));
    }

    // ---- usable baselines ----------------------------------------------------------------

    fn add_executable(db: &Database, id: i64, path: &str) {
        db.conn()
            .execute(
                "INSERT INTO executables (id, path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES (?1, ?2, ?3, 'x.exe', 'valid', 'third_party', 1, 1, 't')",
                params![id, path.to_lowercase(), path],
            )
            .unwrap();
    }

    fn add_baseline(db: &Database, subject: i64, window: u32, obs: i64, span_min: i64, med: f64) {
        db.conn()
            .execute(
                "INSERT INTO baseline_profiles (scope, subject_id, window_hours, metric, \
                 observations, first_ts_ms, last_ts_ms, mean, median, mad, stddev, p95, peak, \
                 computed_at_ms) VALUES ('executable', ?1, ?2, 'cpu', ?3, 0, ?4, ?5, ?5, 1.0, \
                 1.0, 10.0, 20.0, 0)",
                params![subject, window, obs, span_min * 60_000, med],
            )
            .unwrap();
    }

    #[test]
    fn only_baselines_above_insufficient_are_usable() {
        let db = Database::open_in_memory().unwrap();
        let cfg = ConfidenceConfig::default();
        add_executable(&db, 1, r"C:\Apps\Old.exe");
        add_executable(&db, 2, r"C:\Apps\New.exe");
        add_baseline(&db, 1, 24, 5_000, 600, 8.0); // plenty of history
        add_baseline(&db, 2, 24, 10, 1, 8.0); // a few seconds' worth

        let usable = db.usable_cpu_baselines(&[1, 24, 168], &cfg).unwrap();
        assert_eq!(usable.len(), 1);
        let b = &usable[r"c:\apps\old.exe"];
        assert_eq!((b.median, b.window_hours), (8.0, 24));
        assert!(b.confidence.is_usable());
    }

    #[test]
    fn a_subject_uses_its_longest_usable_window() {
        let db = Database::open_in_memory().unwrap();
        let cfg = ConfidenceConfig::default();
        add_executable(&db, 1, r"C:\Apps\A.exe");
        add_baseline(&db, 1, 1, 5_000, 600, 1.0);
        add_baseline(&db, 1, 24, 5_000, 600, 2.0);
        add_baseline(&db, 1, 168, 10, 1, 3.0); // longest, but too thin to trust

        let usable = db.usable_cpu_baselines(&[1, 24, 168], &cfg).unwrap();
        assert_eq!(usable[r"c:\apps\a.exe"].window_hours, 24);
        assert_eq!(usable[r"c:\apps\a.exe"].median, 2.0);
    }

    #[test]
    fn windows_that_are_not_configured_are_ignored() {
        let db = Database::open_in_memory().unwrap();
        add_executable(&db, 1, r"C:\Apps\A.exe");
        add_baseline(&db, 1, 168, 5_000, 600, 3.0);
        let usable = db
            .usable_cpu_baselines(&[1, 24], &ConfidenceConfig::default())
            .unwrap();
        assert!(usable.is_empty(), "a stale 168 h row from an old config");
    }
}
