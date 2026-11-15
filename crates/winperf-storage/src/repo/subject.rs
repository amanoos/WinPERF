//! What the report's detail page shows about one subject: an installed application or one
//! executable. Everything here is read from stored rows; nothing is recomputed (the baselines come
//! from `baseline_profiles` as written by the recorder).

use crate::db::Database;
use crate::error::Result;
use crate::repo::maintenance::HistorySource;
use rusqlite::{OptionalExtension, params};
use winperf_core::profiler::baseline::Scope;

/// The `process_instances` column that links an instance to a subject of this scope.
fn column(scope: Scope) -> &'static str {
    match scope {
        Scope::Executable => "executable_id",
        Scope::Application => "application_id",
    }
}

/// Who the subject is. Fields that do not apply to the scope stay `None`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SubjectInfo {
    pub id: i64,
    pub name: String,
    /// The installed application's publisher.
    pub publisher: Option<String>,
    /// The installed application's version, or the executable's file version.
    pub version: Option<String>,
    /// Install folder (application) or file path (executable).
    pub location: Option<String>,
    /// The executable's product name or file description.
    pub description: Option<String>,
    pub classification: String,
    /// Executables only: `valid`, `not_signed`, `invalid` or `unreadable`.
    pub signature_status: Option<String>,
    pub signer: Option<String>,
    /// Applications only: the install date and when scans first and last saw it.
    pub install_date: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// Executables only: the application it belongs to, when known.
    pub application: Option<(i64, String)>,
}

/// One executable of a subject, with how many of its instances were recorded.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectExecutable {
    pub id: i64,
    pub file_name: String,
    pub file_path: String,
    pub signature_status: String,
    pub signer: Option<String>,
    pub classification: String,
    /// Instances ever recorded, and those not yet marked ended.
    pub instances: i64,
    pub open_instances: i64,
}

/// A subject's usage at one moment (or one bucket): instances summed per tick, then averaged over
/// the ticks of the bucket. A field is `None` when it was never measured there.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectPoint {
    pub ts_ms: i64,
    pub cpu: Option<f64>,
    pub memory: Option<f64>,
    pub disk_read: Option<f64>,
    pub disk_write: Option<f64>,
    pub net_rx: Option<f64>,
    pub net_tx: Option<f64>,
}

/// A subject's history over a period.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectSeries {
    /// Ticks in the period, and how many of them each tick that was read stands for (1 = all
    /// were read; N = every Nth, for long periods, so a program shorter than that can be missed).
    pub ticks: i64,
    pub sampled_every: i64,
    /// 0 for raw samples, else the width of the rollup buckets read (a range past the raw ones).
    pub resolution_ms: i64,
    pub points: Vec<SubjectPoint>,
}

/// The most ticks one history reads.
const MAX_TICKS: usize = 2000;

/// One recorded run of a process of the subject.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectRun {
    pub pid: i64,
    pub name: String,
    pub exe_path: Option<String>,
    pub user_account: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    /// `None` while the instance is believed running.
    pub end_time: Option<String>,
}

impl Database {
    /// The subject's identity and metadata, or `None` when there is no such row.
    pub fn subject_info(&self, scope: Scope, id: i64) -> Result<Option<SubjectInfo>> {
        match scope {
            Scope::Application => Ok(self
                .conn()
                .query_row(
                    "SELECT name, publisher, version, install_location, classification, \
                            install_date, first_seen, last_seen \
                     FROM installed_applications WHERE id = ?1",
                    [id],
                    |r| {
                        Ok(SubjectInfo {
                            id,
                            name: r.get(0)?,
                            publisher: r.get(1)?,
                            version: r.get(2)?,
                            location: r.get(3)?,
                            classification: r.get(4)?,
                            install_date: r.get(5)?,
                            first_seen: r.get(6)?,
                            last_seen: r.get(7)?,
                            ..SubjectInfo::default()
                        })
                    },
                )
                .optional()?),
            Scope::Executable => {
                let found = self
                    .conn()
                    .query_row(
                        "SELECT file_name, file_version, file_path, \
                                COALESCE(product_name, file_description), classification, \
                                signature_status, signer \
                         FROM executables WHERE id = ?1",
                        [id],
                        |r| {
                            Ok(SubjectInfo {
                                id,
                                name: r.get(0)?,
                                version: r.get(1)?,
                                location: r.get(2)?,
                                description: r.get(3)?,
                                classification: r.get(4)?,
                                signature_status: r.get(5)?,
                                signer: r.get(6)?,
                                ..SubjectInfo::default()
                            })
                        },
                    )
                    .optional()?;
                let Some(mut info) = found else {
                    return Ok(None);
                };
                // The most recent application that one of its processes was linked to.
                info.application = self
                    .conn()
                    .query_row(
                        "SELECT a.id, a.name FROM process_instances pi \
                         JOIN installed_applications a ON a.id = pi.application_id \
                         WHERE pi.executable_id = ?1 ORDER BY pi.id DESC LIMIT 1",
                        [id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                Ok(Some(info))
            }
        }
    }

    /// The executables behind the subject (itself, for an executable), most-run first.
    pub fn subject_executables(&self, scope: Scope, id: i64) -> Result<Vec<SubjectExecutable>> {
        let mut stmt = self.conn().prepare(
            "SELECT e.id, e.file_name, e.file_path, e.signature_status, e.signer, \
                    e.classification, COUNT(pi.id), COALESCE(SUM(pi.end_time IS NULL), 0) \
             FROM executables e JOIN process_instances pi ON pi.executable_id = e.id \
             WHERE (?1 = 'executable' AND e.id = ?2) \
                OR (?1 = 'application' AND pi.application_id = ?2) \
             GROUP BY e.id ORDER BY COUNT(pi.id) DESC, e.file_name COLLATE NOCASE",
        )?;
        let rows = stmt.query_map(params![scope.as_str(), id], |r| {
            Ok(SubjectExecutable {
                id: r.get(0)?,
                file_name: r.get(1)?,
                file_path: r.get(2)?,
                signature_status: r.get(3)?,
                signer: r.get(4)?,
                classification: r.get(5)?,
                instances: r.get(6)?,
                open_instances: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The subject's usage over `[from_ms, to_ms]` in buckets of `bucket_ms`. A bucket with no
    /// sample of the subject is absent (it was not running, or recording had stopped), so a chart
    /// shows a gap there. `ts_ms` is the first tick inside the bucket.
    pub fn subject_series(
        &self,
        scope: Scope,
        id: i64,
        from_ms: i64,
        to_ms: i64,
        bucket_ms: i64,
    ) -> Result<SubjectSeries> {
        let col = column(scope);
        let source = self.history_source(from_ms)?;
        let pick = self.pick_ticks(from_ms, to_ms, MAX_TICKS, source)?;
        // Raw samples, or rollup buckets (their averages) for a range older than the raw ones.
        let (table, ts, scope, c) = match source {
            HistorySource::Raw => (
                "resource_samples",
                "ts_ms",
                String::new(),
                [
                    "cpu_percent",
                    "working_set_bytes",
                    "io_read_bytes_per_sec",
                    "io_write_bytes_per_sec",
                    "net_rx_bytes_per_sec",
                    "net_tx_bytes_per_sec",
                ]
                .map(String::from),
            ),
            HistorySource::Rollup(res) => (
                "process_rollups",
                "bucket_ts",
                format!(" AND rs.res_ms = {res}"),
                [
                    "cpu",
                    "working_set",
                    "io_read",
                    "io_write",
                    "net_rx",
                    "net_tx",
                ]
                .map(|stem| format!("{stem}_avg")),
            ),
        };
        let mut stmt = self.conn().prepare(&format!(
            "WITH per_tick AS ( \
                 SELECT rs.{ts} AS ts, SUM(rs.{}) AS cpu, SUM(rs.{}) AS mem, \
                        SUM(rs.{}) AS dr, SUM(rs.{}) AS dw, \
                        SUM(rs.{}) AS rx, SUM(rs.{}) AS tx \
                 FROM {table} rs JOIN process_instances pi ON pi.id = rs.process_instance_id \
                 WHERE pi.{col} = ?1 AND rs.{ts} IN (SELECT value FROM json_each(?3)){scope} \
                 GROUP BY rs.{ts}) \
             SELECT MIN(ts), AVG(cpu), AVG(mem), AVG(dr), AVG(dw), AVG(rx), AVG(tx) \
             FROM per_tick GROUP BY (ts - ?2) / ?4 ORDER BY MIN(ts)",
            c[0], c[1], c[2], c[3], c[4], c[5]
        ))?;
        let rows = stmt.query_map(params![id, from_ms, pick.list, bucket_ms.max(1)], |r| {
            Ok(SubjectPoint {
                ts_ms: r.get(0)?,
                cpu: r.get(1)?,
                memory: r.get(2)?,
                disk_read: r.get(3)?,
                disk_write: r.get(4)?,
                net_rx: r.get(5)?,
                net_tx: r.get(6)?,
            })
        })?;
        Ok(SubjectSeries {
            ticks: pick.total,
            sampled_every: pick.stride,
            resolution_ms: source.resolution_ms(),
            points: rows.collect::<std::result::Result<Vec<_>, _>>()?,
        })
    }

    /// The most recent recorded runs of the subject's processes, newest first.
    pub fn subject_runs(&self, scope: Scope, id: i64, limit: u32) -> Result<Vec<SubjectRun>> {
        let col = column(scope);
        let mut stmt = self.conn().prepare(&format!(
            "SELECT pid, name, exe_path, user_account, first_seen, last_seen, end_time \
             FROM process_instances WHERE {col} = ?1 ORDER BY id DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![id, limit], |r| {
            Ok(SubjectRun {
                pid: r.get(0)?,
                name: r.get(1)?,
                exe_path: r.get(2)?,
                user_account: r.get(3)?,
                first_seen: r.get(4)?,
                last_seen: r.get(5)?,
                end_time: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Application 1 ("Suite") owns executables 1 (two instances) and 2; executable 3 stands alone.
    fn seeded() -> Database {
        let db = Database::open_in_memory().unwrap();
        let sql = |s: &str| db.conn().execute_batch(s).unwrap();
        sql(
            "INSERT INTO installed_applications (id, app_key, name, publisher, version, install_location, \
             registry_sources, classification, first_seen, last_seen, scan_seq) \
             VALUES (1, 'suite', 'Suite', 'Acme', '2.0', 'C:/Suite', 'x', 'third_party', 'a', 'b', 1)",
        );
        for (id, name, status) in [
            (1, "suite.exe", "valid"),
            (2, "helper.exe", "not_signed"),
            (3, "solo.exe", "valid"),
        ] {
            sql(&format!(
                "INSERT INTO executables (id, path_key, file_path, file_name, signature_status, signer, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES ({id}, 'c:/x/{name}', 'C:/x/{name}', '{name}', '{status}', 'Acme', 'third_party', 1, 1, 't')"
            ));
        }
        for (id, pid, exe, app, end) in [
            (1, 10, 1, "1", "NULL"),
            (2, 11, 1, "1", "'e'"),
            (3, 20, 2, "1", "NULL"),
            (4, 30, 3, "NULL", "NULL"),
        ] {
            sql(&format!(
                "INSERT INTO process_instances (id, pid, start_time, parent_pid, name, executable_id, \
                 application_id, first_seen, last_seen, end_time) \
                 VALUES ({id}, {pid}, 100, 0, 'p{pid}', {exe}, {app}, 'f{id}', 'l{id}', {end})"
            ));
        }
        for ts in [1000, 2000, 3000, 4000] {
            sql(&format!("INSERT INTO system_samples (ts_ms) VALUES ({ts})"));
        }
        // Instances 1 and 3 run at 1000 and 2000, instance 2 at 2000 only, instance 1 at 4000.
        for (i, ts, cpu, mem) in [
            (1, 1000, 1.0, 10),
            (3, 1000, 2.0, 20),
            (1, 2000, 3.0, 10),
            (2, 2000, 4.0, 5),
            (3, 2000, 6.0, 20),
            (1, 4000, 8.0, 10),
        ] {
            sql(&format!(
                "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, working_set_bytes) \
                 VALUES ({i}, {ts}, {cpu}, {mem})"
            ));
        }
        db
    }

    #[test]
    fn an_application_has_its_metadata_and_executables() {
        let db = seeded();
        let info = db.subject_info(Scope::Application, 1).unwrap().unwrap();
        assert_eq!(
            (
                info.name.as_str(),
                info.publisher.as_deref(),
                info.version.as_deref()
            ),
            ("Suite", Some("Acme"), Some("2.0"))
        );
        assert_eq!(info.location.as_deref(), Some("C:/Suite"));
        assert!(db.subject_info(Scope::Application, 9).unwrap().is_none());

        let exes = db.subject_executables(Scope::Application, 1).unwrap();
        let shape: Vec<_> = exes
            .iter()
            .map(|e| (e.file_name.as_str(), e.instances, e.open_instances))
            .collect();
        assert_eq!(shape, [("suite.exe", 2, 1), ("helper.exe", 1, 1)]);
    }

    #[test]
    fn an_executable_names_its_application() {
        let db = seeded();
        let info = db.subject_info(Scope::Executable, 2).unwrap().unwrap();
        assert_eq!(info.name, "helper.exe");
        assert_eq!(info.signature_status.as_deref(), Some("not_signed"));
        assert_eq!(info.application, Some((1, "Suite".to_string())));
        let solo = db.subject_info(Scope::Executable, 3).unwrap().unwrap();
        assert_eq!(solo.application, None);
        assert_eq!(
            db.subject_executables(Scope::Executable, 3).unwrap().len(),
            1
        );
    }

    #[test]
    fn the_series_sums_instances_per_tick_then_averages_each_bucket() {
        let db = seeded();
        // One bucket per tick: totals are 3 at 1000 (1+2), 13 at 2000 (3+4+6), 8 at 4000.
        let each = db
            .subject_series(Scope::Application, 1, 1000, 4000, 1000)
            .unwrap();
        assert_eq!((each.ticks, each.sampled_every), (4, 1));
        let each = each.points;
        let cpu: Vec<_> = each.iter().map(|p| (p.ts_ms, p.cpu)).collect();
        assert_eq!(
            cpu,
            [(1000, Some(3.0)), (2000, Some(13.0)), (4000, Some(8.0))]
        );
        assert_eq!(each[1].memory, Some(35.0));
        assert_eq!(each[0].net_rx, None, "never measured stays None, not zero");

        // One bucket for the first two ticks: the mean of 3 and 13; the 3000 gap stays absent.
        let wide = db
            .subject_series(Scope::Application, 1, 1000, 4000, 2000)
            .unwrap()
            .points;
        assert_eq!(wide.len(), 2);
        assert_eq!((wide[0].ts_ms, wide[0].cpu), (1000, Some(8.0)));
        assert_eq!((wide[1].ts_ms, wide[1].cpu), (4000, Some(8.0)));

        // The executable alone sees only its own instances.
        let own = db
            .subject_series(Scope::Executable, 2, 0, 5000, 1000)
            .unwrap()
            .points;
        assert_eq!(
            own.iter().map(|p| p.cpu).collect::<Vec<_>>(),
            [Some(2.0), Some(6.0)]
        );
    }

    #[test]
    fn a_long_period_is_read_from_an_even_subset_that_keeps_the_newest_tick() {
        let db = seeded();
        // 5,000 ticks of 1 s with instance 4 (executable 3) running at every one of them.
        db.conn()
            .execute_batch(
                "WITH RECURSIVE t(n) AS (SELECT 10000 UNION ALL SELECT n + 1000 FROM t WHERE n < 5009000) \
                 INSERT INTO system_samples (ts_ms) SELECT n FROM t; \
                 INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent) \
                 SELECT 4, ts_ms, 2.0 FROM system_samples WHERE ts_ms >= 10000",
            )
            .unwrap();
        let s = db
            .subject_series(Scope::Executable, 3, 0, 6_000_000, 1_000_000)
            .unwrap();
        assert_eq!((s.ticks, s.sampled_every), (5004, 3));
        assert!(s.points.iter().all(|p| p.cpu == Some(2.0)));
        let newest = s.points.last().unwrap().ts_ms;
        assert!(newest > 4_900_000, "the newest bucket is there: {newest}");
    }

    #[test]
    fn runs_are_newest_first_and_limited() {
        let db = seeded();
        let runs = db.subject_runs(Scope::Application, 1, 2).unwrap();
        assert_eq!(runs.iter().map(|r| r.pid).collect::<Vec<_>>(), [20, 11]);
        assert_eq!(runs[1].end_time.as_deref(), Some("e"));
        assert_eq!(runs[0].end_time, None);
        assert_eq!(db.subject_runs(Scope::Executable, 3, 10).unwrap().len(), 1);
    }
}
