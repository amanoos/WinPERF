//! Anomaly events (`anomaly_events`) and the baselines the detectors judge against.

use crate::db::Database;
use crate::error::{Result, StorageError};
use rusqlite::{OptionalExtension, params};
use winperf_core::anomaly::{AnomalyEvent, AnomalyKind, BaselineSet, BaselineStats, Severity};
use winperf_core::config::{ConfidenceConfig, Resource};
use winperf_core::profiler::baseline::{BaselineMetric, Scope};
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
    pub kind: AnomalyKind,
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
    /// When the condition ended; `None` while the event is active.
    pub resolved_ts_ms: Option<i64>,
    /// When the event was last confirmed or refreshed.
    pub last_update_ts_ms: i64,
    pub system_disk_percent: Option<f64>,
    pub pressure_percent: Option<f64>,
    pub share_percent: Option<f64>,
    pub impact_score: Option<f64>,
}

impl StoredAnomaly {
    pub fn is_active(&self) -> bool {
        self.resolved_ts_ms.is_none()
    }
}

/// Which events to list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnomalyFilter {
    /// Only events that were active at or after this time (still going on, or resolved since).
    pub since_ms: Option<i64>,
    /// Only events that are still going on.
    pub active_only: bool,
}

const COLUMNS: &str = "id, detected_ts_ms, process_instance_id, pid, process_name, application, \
                       exe_path, resource, current_value, baseline_value, deviation_pct, \
                       duration_ms, severity, system_cpu_percent, system_memory_percent, \
                       baseline_window_hours, baseline_confidence, explanation, kind, \
                       resolved_ts_ms, last_update_ts_ms, system_disk_percent, \
                       pressure_percent, share_percent, impact_score";

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
        kind: {
            let kind: String = r.get(18)?;
            AnomalyKind::parse(&kind)
                .ok_or_else(|| StorageError::Corrupt(format!("anomaly kind {kind:?}")))?
        },
        resolved_ts_ms: r.get(19)?,
        last_update_ts_ms: r.get(20)?,
        system_disk_percent: r.get(21)?,
        pressure_percent: r.get(22)?,
        share_percent: r.get(23)?,
        impact_score: r.get(24)?,
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
             baseline_window_hours, baseline_confidence, explanation, kind, last_update_ts_ms, \
             system_disk_percent, pressure_percent, share_percent, impact_score) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
             ?18, ?1, ?19, ?20, ?21, ?22)",
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
                e.kind.as_str(),
                e.system.disk_percent,
                e.impact.pressure_percent,
                e.impact.share_percent,
                e.impact.score,
            ],
        )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Refresh an active event with newer numbers (it lasted longer, got worse, ...). Who the
    /// event is about and when it was detected stay as they were.
    pub fn update_anomaly(&self, id: i64, e: &AnomalyEvent, now_ms: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE anomaly_events SET current_value = ?2, baseline_value = ?3, \
             deviation_pct = ?4, duration_ms = ?5, severity = ?6, system_cpu_percent = ?7, \
             system_memory_percent = ?8, system_disk_percent = ?9, pressure_percent = ?10, \
             share_percent = ?11, impact_score = ?12, explanation = ?13, last_update_ts_ms = ?14 \
             WHERE id = ?1 AND resolved_ts_ms IS NULL",
            params![
                id,
                e.current,
                e.baseline,
                e.deviation_pct,
                e.duration_ms,
                e.severity.as_str(),
                e.system.cpu_percent,
                e.system.memory_percent,
                e.system.disk_percent,
                e.impact.pressure_percent,
                e.impact.share_percent,
                e.impact.score,
                e.explanation,
                now_ms,
            ],
        )?;
        Ok(())
    }

    /// Mark an event's condition as over. Does nothing if it was already resolved.
    pub fn resolve_anomaly(&self, id: i64, ts_ms: i64) -> Result<()> {
        self.conn().execute(
            "UPDATE anomaly_events SET resolved_ts_ms = ?2, \
             last_update_ts_ms = MAX(?2, COALESCE(last_update_ts_ms, 0)) \
             WHERE id = ?1 AND resolved_ts_ms IS NULL",
            params![id, ts_ms],
        )?;
        Ok(())
    }

    /// Resolve events left active by a monitor that stopped, as of their last update. Returns how
    /// many there were.
    pub fn resolve_stale_anomalies(&self) -> Result<usize> {
        Ok(self.conn().execute(
            "UPDATE anomaly_events \
             SET resolved_ts_ms = COALESCE(last_update_ts_ms, detected_ts_ms) \
             WHERE resolved_ts_ms IS NULL",
            [],
        )?)
    }

    /// Number of events still going on.
    pub fn active_anomaly_count(&self) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM anomaly_events WHERE resolved_ts_ms IS NULL",
            [],
            |r| r.get(0),
        )?)
    }

    /// Events, active ones first and then newest first.
    pub fn list_anomalies(&self, filter: &AnomalyFilter, limit: u32) -> Result<Vec<StoredAnomaly>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLUMNS} FROM anomaly_events \
             WHERE (resolved_ts_ms IS NULL OR resolved_ts_ms >= ?1) \
               AND (?2 = 0 OR resolved_ts_ms IS NULL) \
             ORDER BY resolved_ts_ms IS NULL DESC, detected_ts_ms DESC, id DESC LIMIT ?3"
        ))?;
        let mut rows = stmt.query(params![
            filter.since_ms.unwrap_or(i64::MIN),
            i64::from(filter.active_only),
            limit
        ])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(from_row(r)?);
        }
        Ok(out)
    }

    /// Events about one subject (an executable, or an installed application and all its
    /// executables) that were active at or after `since_ms`, active ones first then newest first.
    /// A process counts when its instance is linked to the subject, or its path is one of the
    /// subject's executables.
    pub fn subject_anomalies(
        &self,
        scope: Scope,
        subject_id: i64,
        since_ms: i64,
        limit: u32,
    ) -> Result<Vec<StoredAnomaly>> {
        let (instances, paths) = match scope {
            Scope::Executable => (
                "SELECT id FROM process_instances WHERE executable_id = ?2",
                "SELECT path_key FROM executables WHERE id = ?2",
            ),
            Scope::Application => (
                "SELECT id FROM process_instances WHERE application_id = ?2",
                "SELECT e.path_key FROM executables e WHERE e.id IN                  (SELECT executable_id FROM process_instances WHERE application_id = ?2)",
            ),
        };
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLUMNS} FROM anomaly_events              WHERE (resolved_ts_ms IS NULL OR resolved_ts_ms >= ?1)                AND (process_instance_id IN ({instances}) OR LOWER(exe_path) IN ({paths}))              ORDER BY resolved_ts_ms IS NULL DESC, detected_ts_ms DESC, id DESC LIMIT ?3"
        ))?;
        let mut rows = stmt.query(params![since_ms, subject_id, limit])?;
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

    /// The baselines the detectors may use. Only the given windows count, a subject takes its
    /// longest window whose confidence is above Insufficient (separately for each metric), and a
    /// subject with no such window is left out so it is never judged.
    pub fn usable_baselines(
        &self,
        windows_hours: &[u32],
        confidence: &ConfidenceConfig,
    ) -> Result<BaselineSet> {
        let mut stmt = self.conn().prepare(
            "SELECT e.path_key, bp.metric, bp.window_hours, bp.observations, bp.first_ts_ms, \
                    bp.last_ts_ms, bp.mean, bp.median, bp.mad, bp.p95, bp.growth_per_hour \
             FROM baseline_profiles bp JOIN executables e ON e.id = bp.subject_id \
             WHERE bp.scope = 'executable' \
             ORDER BY bp.window_hours DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = BaselineSet::new();
        while let Some(r) = rows.next()? {
            let window_hours: u32 = r.get(2)?;
            if !windows_hours.contains(&window_hours) {
                continue;
            }
            let metric: String = r.get(1)?;
            let Some(metric) = BaselineMetric::parse(&metric) else {
                continue;
            };
            let path_key: String = r.get(0)?;
            if out.get(metric, &path_key).is_some() {
                continue; // a longer window already qualified
            }
            let observations = r.get::<_, i64>(3)?.max(0) as u64;
            let span_ms = r.get::<_, i64>(5)? - r.get::<_, i64>(4)?;
            let level = assess(observations, span_ms, confidence);
            if !level.is_usable() {
                continue;
            }
            out.insert(
                metric,
                path_key,
                BaselineStats {
                    mean: r.get(6)?,
                    median: r.get(7)?,
                    mad: r.get(8)?,
                    p95: r.get(9)?,
                    growth_per_hour: r.get(10)?,
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
    use winperf_core::anomaly::{Impact, SystemHealth};
    use winperf_core::profiler::confidence::Confidence;

    fn event(ts: i64, pid: u32, severity: Severity) -> AnomalyEvent {
        AnomalyEvent {
            detected_ts_ms: ts,
            pid,
            start_time: 100,
            process_name: "busy.exe".into(),
            exe_path: r"C:\apps\busy.exe".into(),
            resource: Resource::Cpu,
            kind: AnomalyKind::Deviation,
            current: 72.0,
            baseline: 8.0,
            deviation_pct: 800.0,
            duration_ms: 120_000,
            severity,
            system: SystemHealth {
                cpu_percent: Some(91.0),
                memory_percent: None,
                disk_percent: Some(40.0),
            },
            impact: Impact {
                pressure_percent: Some(91.0),
                share_percent: Some(72.0),
                score: Some(65.5),
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
        assert_eq!(back.kind, AnomalyKind::Deviation);
        assert_eq!((back.current, back.baseline), (72.0, 8.0));
        assert_eq!(back.deviation_pct, 800.0);
        assert_eq!(back.duration_ms, 120_000);
        assert_eq!(back.severity, Severity::High);
        assert_eq!(back.system_cpu_percent, Some(91.0));
        assert_eq!(back.system_memory_percent, None, "unmeasured stays NULL");
        assert_eq!(back.baseline_window_hours, 24);
        assert_eq!(back.baseline_confidence, "Established");
        assert_eq!(back.explanation, "busy.exe used 72% CPU");
        assert_eq!(back.system_disk_percent, Some(40.0));
        assert_eq!(back.pressure_percent, Some(91.0));
        assert_eq!(back.share_percent, Some(72.0));
        assert_eq!(back.impact_score, Some(65.5));
        assert!(back.is_active());
        assert_eq!(back.resolved_ts_ms, None);
        assert_eq!(
            back.last_update_ts_ms, 5_000,
            "first seen counts as an update"
        );
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
        let all = AnomalyFilter::default();

        assert_eq!(pids(db.list_anomalies(&all, 10).unwrap()), vec![3, 2, 1]);
        assert_eq!(pids(db.list_anomalies(&all, 1).unwrap()), vec![3]);
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

    #[test]
    fn a_subjects_events_are_found_by_instance_link_or_by_path() {
        let db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO installed_applications (id, app_key, name, registry_sources, \
                   classification, first_seen, last_seen, scan_seq) \
                 VALUES (1, 'busy|1|x', 'Busy Suite', 'hklm', 'third_party', 't', 't', 1); \
                 INSERT INTO executables (id, path_key, file_path, file_name, signature_status, \
                   classification, file_size, file_mtime_ns, verified_at) \
                 VALUES (5, 'c:\\apps\\busy.exe', 'C:\\apps\\Busy.exe', 'busy.exe', 'valid', \
                   'third_party', 1, 1, 't'), \
                        (6, 'c:\\apps\\other.exe', 'C:\\apps\\other.exe', 'other.exe', 'valid', \
                   'third_party', 1, 1, 't'); \
                 INSERT INTO process_instances (id, pid, start_time, parent_pid, name, \
                   executable_id, application_id, first_seen, last_seen) \
                 VALUES (9, 7, 100, 0, 'busy.exe', 5, 1, 't', 't');",
            )
            .unwrap();
        // Linked by instance (pid 7); the second has no instance but the same executable path;
        // the third is someone else.
        db.insert_anomaly(&event(1_000, 7, Severity::Warning))
            .unwrap();
        db.insert_anomaly(&event(2_000, 8, Severity::High)).unwrap();
        let mut other = event(3_000, 9, Severity::Warning);
        other.exe_path = r"C:\apps\other.exe".into();
        db.insert_anomaly(&other).unwrap();

        let pids = |rows: Vec<StoredAnomaly>| rows.iter().map(|r| r.pid).collect::<Vec<_>>();
        assert_eq!(
            pids(db.subject_anomalies(Scope::Executable, 5, 0, 10).unwrap()),
            [8, 7]
        );
        assert_eq!(
            pids(db.subject_anomalies(Scope::Application, 1, 0, 10).unwrap()),
            [8, 7],
            "an application's events include its executables'"
        );
        assert_eq!(
            pids(db.subject_anomalies(Scope::Executable, 6, 0, 10).unwrap()),
            [9]
        );
        assert!(
            db.subject_anomalies(Scope::Executable, 5, 0, 1)
                .unwrap()
                .len()
                == 1
        );
    }

    // ---- lifecycle -----------------------------------------------------------------------

    #[test]
    fn an_active_event_is_refreshed_in_place_and_keeps_its_identity() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .insert_anomaly(&event(1_000, 7, Severity::Warning))
            .unwrap();

        let mut worse = event(1_000, 7, Severity::High);
        worse.current = 90.0;
        worse.duration_ms = 600_000;
        worse.impact.score = Some(80.0);
        worse.explanation = "longer and worse".into();
        worse.pid = 999; // who it is about never changes
        db.update_anomaly(id, &worse, 31_000).unwrap();

        let back = db.anomaly(id).unwrap().unwrap();
        assert_eq!(db.anomaly_count().unwrap(), 1, "updated, not duplicated");
        assert_eq!(
            (back.severity, back.current, back.duration_ms),
            (Severity::High, 90.0, 600_000)
        );
        assert_eq!(back.impact_score, Some(80.0));
        assert_eq!(back.explanation, "longer and worse");
        assert_eq!(back.last_update_ts_ms, 31_000);
        assert_eq!(back.detected_ts_ms, 1_000, "detection time is kept");
        assert_eq!(back.pid, 7);
        assert!(back.is_active());
    }

    #[test]
    fn resolving_ends_an_event_and_freezes_it() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .insert_anomaly(&event(1_000, 7, Severity::Warning))
            .unwrap();
        assert_eq!(db.active_anomaly_count().unwrap(), 1);

        db.resolve_anomaly(id, 50_000).unwrap();
        let back = db.anomaly(id).unwrap().unwrap();
        assert_eq!(back.resolved_ts_ms, Some(50_000));
        assert!(!back.is_active());
        assert_eq!(db.active_anomaly_count().unwrap(), 0);

        // Later updates and resolutions do nothing.
        let mut other = event(1_000, 7, Severity::Critical);
        other.current = 1.0;
        db.update_anomaly(id, &other, 60_000).unwrap();
        db.resolve_anomaly(id, 70_000).unwrap();
        let back = db.anomaly(id).unwrap().unwrap();
        assert_eq!((back.severity, back.current), (Severity::Warning, 72.0));
        assert_eq!(back.resolved_ts_ms, Some(50_000));
    }

    #[test]
    fn events_left_active_by_a_stopped_monitor_are_resolved_as_of_their_last_update() {
        let db = Database::open_in_memory().unwrap();
        let a = db
            .insert_anomaly(&event(1_000, 1, Severity::Warning))
            .unwrap();
        db.update_anomaly(a, &event(1_000, 1, Severity::Warning), 9_000)
            .unwrap();
        let b = db
            .insert_anomaly(&event(2_000, 2, Severity::Warning))
            .unwrap();
        db.resolve_anomaly(b, 3_000).unwrap();

        assert_eq!(
            db.resolve_stale_anomalies().unwrap(),
            1,
            "only the active one"
        );
        assert_eq!(db.anomaly(a).unwrap().unwrap().resolved_ts_ms, Some(9_000));
        assert_eq!(db.anomaly(b).unwrap().unwrap().resolved_ts_ms, Some(3_000));
        assert_eq!(db.resolve_stale_anomalies().unwrap(), 0);
    }

    #[test]
    fn listing_puts_active_events_first_and_can_show_only_them() {
        let db = Database::open_in_memory().unwrap();
        let old = db
            .insert_anomaly(&event(1_000, 1, Severity::Warning))
            .unwrap();
        db.resolve_anomaly(old, 5_000).unwrap();
        db.insert_anomaly(&event(2_000, 2, Severity::Warning))
            .unwrap(); // active, older start
        let newer = db
            .insert_anomaly(&event(3_000, 3, Severity::Warning))
            .unwrap();
        db.resolve_anomaly(newer, 4_000).unwrap();
        let pids = |f: &AnomalyFilter| {
            db.list_anomalies(f, 10)
                .unwrap()
                .iter()
                .map(|r| r.pid)
                .collect::<Vec<_>>()
        };

        assert_eq!(
            pids(&AnomalyFilter::default()),
            vec![2, 3, 1],
            "active first, then newest"
        );
        let active = AnomalyFilter {
            active_only: true,
            ..Default::default()
        };
        assert_eq!(pids(&active), vec![2]);
        // `since` keeps what was active at or after that time: still going, or resolved since.
        let since = AnomalyFilter {
            since_ms: Some(4_500),
            ..Default::default()
        };
        assert_eq!(pids(&since), vec![2, 1]);
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

        let usable = db.usable_baselines(&[1, 24, 168], &cfg).unwrap();
        assert_eq!(usable.subjects(BaselineMetric::Cpu), 1);
        let b = usable.get(BaselineMetric::Cpu, r"c:\apps\old.exe").unwrap();
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

        let usable = db.usable_baselines(&[1, 24, 168], &cfg).unwrap();
        let b = usable.get(BaselineMetric::Cpu, r"c:\apps\a.exe").unwrap();
        assert_eq!((b.window_hours, b.median), (24, 2.0));
    }

    #[test]
    fn windows_that_are_not_configured_are_ignored() {
        let db = Database::open_in_memory().unwrap();
        add_executable(&db, 1, r"C:\Apps\A.exe");
        add_baseline(&db, 1, 168, 5_000, 600, 3.0);
        let usable = db
            .usable_baselines(&[1, 24], &ConfidenceConfig::default())
            .unwrap();
        assert!(usable.is_empty(), "a stale 168 h row from an old config");
    }

    #[test]
    fn every_metric_is_loaded_with_its_own_window_and_memory_growth() {
        let db = Database::open_in_memory().unwrap();
        add_executable(&db, 1, r"C:\Apps\A.exe");
        for (metric, growth) in [
            ("memory", Some(5.0e6)),
            ("disk_write", None),
            ("net_rx", None),
        ] {
            db.conn()
                .execute(
                    "INSERT INTO baseline_profiles (scope, subject_id, window_hours, metric, \
                     observations, first_ts_ms, last_ts_ms, mean, median, mad, stddev, p95, peak, \
                     growth_per_hour, computed_at_ms) VALUES ('executable', 1, 24, ?1, 5000, 0, \
                     36000000, 1.0, 1.0, 0.1, 0.1, 2.0, 3.0, ?2, 0)",
                    params![metric, growth],
                )
                .unwrap();
        }
        let usable = db
            .usable_baselines(&[24], &ConfidenceConfig::default())
            .unwrap();
        let key = r"c:\apps\a.exe";
        assert_eq!(
            usable
                .get(BaselineMetric::Memory, key)
                .unwrap()
                .growth_per_hour,
            Some(5.0e6)
        );
        assert!(usable.get(BaselineMetric::DiskWrite, key).is_some());
        assert!(usable.get(BaselineMetric::NetRx, key).is_some());
        assert!(
            usable.get(BaselineMetric::Cpu, key).is_none(),
            "no cpu row stored"
        );
    }
}
