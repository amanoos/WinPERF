//! Baseline profile persistence and the recompute job (reads samples, writes `baseline_profiles`).

use crate::db::Database;
use crate::error::Result;
use rusqlite::params;
use winperf_core::profiler::baseline::{
    BaselineMetric, Scope, SubjectBaseline, TickPoint, compute_baseline,
};

const MS_PER_HOUR: i64 = 3_600_000;

/// One stored baseline row, as read back.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredBaseline {
    pub scope: Scope,
    pub subject_id: i64,
    pub window_hours: u32,
    pub metric: BaselineMetric,
    pub observations: u64,
    pub first_ts_ms: i64,
    pub last_ts_ms: i64,
    pub mean: f64,
    pub median: f64,
    pub mad: f64,
    pub stddev: f64,
    pub p95: f64,
    pub peak: f64,
    pub growth_per_hour: Option<f64>,
    pub computed_at_ms: i64,
}

/// A stored baseline plus the name of the executable or application it describes.
#[derive(Debug, Clone, PartialEq)]
pub struct ListedBaseline {
    pub stored: StoredBaseline,
    pub name: String,
}

/// The 13 stored columns, in the order [`stored_from_row`] reads them.
const COLUMNS: &str = "window_hours, metric, observations, first_ts_ms, last_ts_ms, mean, \
                       median, mad, stddev, p95, peak, growth_per_hour, computed_at_ms";

fn stored_from_row(
    r: &rusqlite::Row<'_>,
    scope: Scope,
    subject_id: i64,
) -> rusqlite::Result<StoredBaseline> {
    let metric: String = r.get(1)?;
    Ok(StoredBaseline {
        scope,
        subject_id,
        window_hours: r.get(0)?,
        // The CHECK constraint guarantees a known name.
        metric: BaselineMetric::parse(&metric).unwrap_or(BaselineMetric::Cpu),
        observations: r.get::<_, i64>(2)? as u64,
        first_ts_ms: r.get(3)?,
        last_ts_ms: r.get(4)?,
        mean: r.get(5)?,
        median: r.get(6)?,
        mad: r.get(7)?,
        stddev: r.get(8)?,
        p95: r.get(9)?,
        peak: r.get(10)?,
        growth_per_hour: r.get(11)?,
        computed_at_ms: r.get(12)?,
    })
}

/// What a recompute wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecomputeReport {
    /// Subjects (executables plus applications) that got a baseline.
    pub subjects: usize,
    pub rows: usize,
}

/// The `process_instances` column that identifies a subject of this scope.
fn subject_column(scope: Scope) -> &'static str {
    match scope {
        Scope::Executable => "executable_id",
        Scope::Application => "application_id",
    }
}

impl Database {
    /// Recompute every baseline of one window from the samples in `[now_ms - window, now_ms]`
    /// and replace the stored rows for that window in one transaction. Idempotent: the same
    /// samples and `now_ms` give the same rows. A subject with no samples in the window loses
    /// its row. Sums each subject's instances per tick first (SQL `SUM` ignores NULL, and is NULL
    /// when every instance was unmeasured).
    pub fn recompute_baselines(
        &mut self,
        now_ms: i64,
        window_hours: u32,
    ) -> Result<RecomputeReport> {
        self.recompute_baselines_from(now_ms, window_hours, None)
    }

    /// Like [`Self::recompute_baselines`], but with `Some(res_ms)` the points are the rollup
    /// buckets of that width (the average over each bucket) instead of raw ticks. This is how a
    /// window longer than the raw retention is computed: the raw samples no longer cover it.
    /// Statistics over bucket averages are smoother than over raw ticks (a spike is averaged into
    /// its bucket), which suits the sustained deviations the detectors look for.
    pub fn recompute_baselines_from(
        &mut self,
        now_ms: i64,
        window_hours: u32,
        rollup_res_ms: Option<i64>,
    ) -> Result<RecomputeReport> {
        let since = now_ms - i64::from(window_hours) * MS_PER_HOUR;
        let mut computed: Vec<(Scope, i64, SubjectBaseline)> = Vec::new();

        for scope in Scope::ALL {
            let col = subject_column(scope);
            let mut stmt = match rollup_res_ms {
                None => self.conn().prepare(&format!(
                    "SELECT pi.{col}, rs.ts_ms, SUM(rs.cpu_percent), SUM(rs.working_set_bytes),                      SUM(rs.private_bytes), SUM(rs.io_read_bytes_per_sec),                      SUM(rs.io_write_bytes_per_sec), SUM(rs.net_rx_bytes_per_sec),                      SUM(rs.net_tx_bytes_per_sec)                      FROM resource_samples rs JOIN process_instances pi ON pi.id = rs.process_instance_id                      WHERE rs.ts_ms BETWEEN ?1 AND ?2 AND pi.{col} IS NOT NULL                      GROUP BY pi.{col}, rs.ts_ms ORDER BY pi.{col}, rs.ts_ms"
                ))?,
                Some(res) => self.conn().prepare(&format!(
                    "SELECT pi.{col}, rs.bucket_ts, SUM(rs.cpu_avg), SUM(rs.working_set_avg),                      SUM(rs.private_avg), SUM(rs.io_read_avg), SUM(rs.io_write_avg),                      SUM(rs.net_rx_avg), SUM(rs.net_tx_avg)                      FROM process_rollups rs JOIN process_instances pi ON pi.id = rs.process_instance_id                      WHERE rs.res_ms = {res} AND rs.bucket_ts BETWEEN ?1 AND ?2                        AND pi.{col} IS NOT NULL                      GROUP BY pi.{col}, rs.bucket_ts ORDER BY pi.{col}, rs.bucket_ts"
                ))?,
            };
            let mut rows = stmt.query(params![since, now_ms])?;

            let mut current: Option<i64> = None;
            let mut series: Vec<TickPoint> = Vec::new();
            let mut finish = |subject: Option<i64>, series: &mut Vec<TickPoint>| {
                if let Some(id) = subject
                    && let Some(b) = compute_baseline(series)
                {
                    computed.push((scope, id, b));
                }
                series.clear();
            };
            while let Some(r) = rows.next()? {
                let subject: i64 = r.get(0)?;
                if current != Some(subject) {
                    finish(current, &mut series);
                    current = Some(subject);
                }
                series.push(TickPoint {
                    ts_ms: r.get(1)?,
                    cpu: r.get(2)?,
                    working_set: r.get(3)?,
                    private_bytes: r.get(4)?,
                    disk_read: r.get(5)?,
                    disk_write: r.get(6)?,
                    net_rx: r.get(7)?,
                    net_tx: r.get(8)?,
                });
            }
            finish(current, &mut series);
        }

        let tx = self.conn_mut().transaction()?;
        tx.execute(
            "DELETE FROM baseline_profiles WHERE window_hours = ?1",
            [window_hours],
        )?;
        let mut report = RecomputeReport::default();
        {
            let mut insert = tx.prepare(
                "INSERT INTO baseline_profiles \
                 (scope, subject_id, window_hours, metric, observations, first_ts_ms, last_ts_ms, \
                  mean, median, mad, stddev, p95, peak, growth_per_hour, computed_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            )?;
            for (scope, subject_id, b) in &computed {
                report.subjects += 1;
                for m in &b.metrics {
                    insert.execute(params![
                        scope.as_str(),
                        subject_id,
                        window_hours,
                        m.metric.as_str(),
                        m.stats.count as i64,
                        b.first_ts_ms,
                        b.last_ts_ms,
                        m.stats.mean,
                        m.stats.median,
                        m.stats.mad,
                        m.stats.stddev,
                        m.stats.p95,
                        m.stats.peak,
                        m.growth_per_hour,
                        now_ms,
                    ])?;
                    report.rows += 1;
                }
            }
        }
        tx.commit()?;
        Ok(report)
    }

    /// Every stored baseline row of one subject, shortest window first.
    pub fn baselines_for(&self, scope: Scope, subject_id: i64) -> Result<Vec<StoredBaseline>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLUMNS} FROM baseline_profiles \
             WHERE scope = ?1 AND subject_id = ?2 ORDER BY window_hours, id"
        ))?;
        let rows = stmt.query_map(params![scope.as_str(), subject_id], |r| {
            stored_from_row(r, scope, subject_id)
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All baseline rows of one window with the subject's display name (the executable's file
    /// name or the application's name), ordered by scope, name and metric.
    pub fn list_baselines(&self, window_hours: u32) -> Result<Vec<ListedBaseline>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLUMNS}, scope, subject_id, \
             COALESCE(e.file_name, a.name, '#' || subject_id) AS subject_name \
             FROM baseline_profiles bp \
             LEFT JOIN executables e ON bp.scope = 'executable' AND e.id = bp.subject_id \
             LEFT JOIN installed_applications a ON bp.scope = 'application' AND a.id = bp.subject_id \
             WHERE window_hours = ?1 ORDER BY scope, subject_name COLLATE NOCASE, bp.id"
        ))?;
        let rows = stmt.query_map([window_hours], |r| {
            let scope: String = r.get(13)?;
            let scope = Scope::parse(&scope).unwrap_or(Scope::Executable);
            let subject_id: i64 = r.get(14)?;
            Ok(ListedBaseline {
                stored: stored_from_row(r, scope, subject_id)?,
                name: r.get(15)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn baseline_count(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT COUNT(*) FROM baseline_profiles", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winperf_core::sampling::Sample;
    use winperf_core::{Metric, ProcessKey};

    const HOUR: i64 = MS_PER_HOUR;
    const NOW: i64 = 100 * HOUR;

    fn exe(db: &Database, key: &str) -> i64 {
        db.conn()
            .execute(
                "INSERT INTO executables (path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES (?1, ?1, ?1, 'valid', 'microsoft', 1, 1, 't')",
                [key],
            )
            .unwrap();
        db.conn().last_insert_rowid()
    }

    fn app(db: &Database, key: &str) -> i64 {
        db.conn()
            .execute(
                "INSERT INTO installed_applications (app_key, name, registry_sources, \
                 classification, first_seen, last_seen, scan_seq) \
                 VALUES (?1, ?1, 'x', 'microsoft', 't', 't', 1)",
                [key],
            )
            .unwrap();
        db.conn().last_insert_rowid()
    }

    fn instance(db: &Database, pid: i64, exe: Option<i64>, app: Option<i64>) -> i64 {
        db.conn()
            .execute(
                "INSERT INTO process_instances (pid, start_time, parent_pid, name, executable_id, \
                 application_id, first_seen, last_seen) VALUES (?1, ?1, 0, 'p', ?2, ?3, 't', 't')",
                params![pid, exe, app],
            )
            .unwrap();
        db.conn().last_insert_rowid()
    }

    fn sample(cpu: Option<f64>, ws: u64) -> Sample {
        Sample {
            key: ProcessKey::new(1, 1),
            cpu_percent: cpu.map_or(Metric::Unavailable, Metric::Available),
            working_set: Metric::Available(ws),
            private_bytes: Metric::Unavailable,
            virtual_bytes: Metric::Unavailable,
            peak_working_set: Metric::Unavailable,
            io_read_bytes_per_sec: Metric::Unavailable,
            io_write_bytes_per_sec: Metric::Unavailable,
            io_read_ops_per_sec: Metric::Unavailable,
            io_write_ops_per_sec: Metric::Unavailable,
            net_rx_bytes_per_sec: Metric::Unavailable,
            net_tx_bytes_per_sec: Metric::Unavailable,
        }
    }

    fn put(db: &mut Database, ts_ms: i64, rows: &[(i64, Option<f64>, u64)]) {
        let samples: Vec<Sample> = rows.iter().map(|r| sample(r.1, r.2)).collect();
        let pairs: Vec<(i64, &Sample)> = rows.iter().zip(&samples).map(|(r, s)| (r.0, s)).collect();
        db.insert_samples(ts_ms, &pairs).unwrap();
    }

    fn row(rows: &[StoredBaseline], window: u32, m: BaselineMetric) -> &StoredBaseline {
        rows.iter()
            .find(|r| r.window_hours == window && r.metric == m)
            .unwrap_or_else(|| panic!("no {m:?} row for {window} h in {rows:?}"))
    }

    #[test]
    fn instances_are_summed_per_tick_then_summarized() {
        let mut db = Database::open_in_memory().unwrap();
        let e = exe(&db, "chrome");
        let (a, b) = (
            instance(&db, 1, Some(e), None),
            instance(&db, 2, Some(e), None),
        );
        // Two processes of one executable: per-tick totals are 3, 5, 7 (mean 5, peak 7).
        put(
            &mut db,
            NOW - 3000,
            &[(a, Some(1.0), 10), (b, Some(2.0), 20)],
        );
        put(
            &mut db,
            NOW - 2000,
            &[(a, Some(2.0), 10), (b, Some(3.0), 20)],
        );
        put(
            &mut db,
            NOW - 1000,
            &[(a, Some(3.0), 10), (b, Some(4.0), 20)],
        );

        let report = db.recompute_baselines(NOW, 1).unwrap();
        assert_eq!(
            report.subjects, 1,
            "no application link, so executable scope only"
        );

        let rows = db.baselines_for(Scope::Executable, e).unwrap();
        let cpu = row(&rows, 1, BaselineMetric::Cpu);
        assert_eq!(
            (cpu.observations, cpu.mean, cpu.median, cpu.peak),
            (3, 5.0, 5.0, 7.0)
        );
        let mem = row(&rows, 1, BaselineMetric::Memory);
        assert_eq!((mem.mean, mem.peak), (30.0, 30.0));
        assert_eq!((cpu.first_ts_ms, cpu.last_ts_ms), (NOW - 3000, NOW - 1000));
        assert_eq!(cpu.computed_at_ms, NOW);
        assert!(
            rows.iter().all(|r| r.metric != BaselineMetric::NetRx),
            "unmeasured metrics get no row"
        );
    }

    #[test]
    fn applications_are_baselined_across_their_executables() {
        let mut db = Database::open_in_memory().unwrap();
        let ap = app(&db, "suite");
        let (e1, e2) = (exe(&db, "a.exe"), exe(&db, "b.exe"));
        let (i1, i2) = (
            instance(&db, 1, Some(e1), Some(ap)),
            instance(&db, 2, Some(e2), Some(ap)),
        );
        put(
            &mut db,
            NOW - 2000,
            &[(i1, Some(1.0), 10), (i2, Some(1.0), 10)],
        );
        put(
            &mut db,
            NOW - 1000,
            &[(i1, Some(1.0), 10), (i2, Some(3.0), 10)],
        );

        assert_eq!(db.recompute_baselines(NOW, 1).unwrap().subjects, 3);

        let app_rows = db.baselines_for(Scope::Application, ap).unwrap();
        assert_eq!(row(&app_rows, 1, BaselineMetric::Cpu).mean, 3.0); // (2 + 4) / 2
        let e2_rows = db.baselines_for(Scope::Executable, e2).unwrap();
        assert_eq!(row(&e2_rows, 1, BaselineMetric::Cpu).mean, 2.0); // (1 + 3) / 2
    }

    #[test]
    fn each_window_only_sees_its_own_samples() {
        let mut db = Database::open_in_memory().unwrap();
        let e = exe(&db, "x");
        let i = instance(&db, 1, Some(e), None);
        put(&mut db, NOW - 30 * 60_000, &[(i, Some(10.0), 100)]); // 30 min ago
        put(&mut db, NOW - 5 * HOUR, &[(i, Some(2.0), 100)]); // 5 h ago

        db.recompute_baselines(NOW, 1).unwrap();
        db.recompute_baselines(NOW, 24).unwrap();

        let rows = db.baselines_for(Scope::Executable, e).unwrap();
        assert_eq!(row(&rows, 1, BaselineMetric::Cpu).observations, 1);
        assert_eq!(row(&rows, 1, BaselineMetric::Cpu).mean, 10.0);
        assert_eq!(row(&rows, 24, BaselineMetric::Cpu).observations, 2);
        assert_eq!(row(&rows, 24, BaselineMetric::Cpu).mean, 6.0);
        assert_eq!(rows[0].window_hours, 1, "shortest window first");
    }

    #[test]
    fn recomputing_is_idempotent_and_drops_subjects_that_left_the_window() {
        let mut db = Database::open_in_memory().unwrap();
        let (e1, e2) = (exe(&db, "old"), exe(&db, "new"));
        let (i1, i2) = (
            instance(&db, 1, Some(e1), None),
            instance(&db, 2, Some(e2), None),
        );
        put(&mut db, NOW - 90 * 60_000, &[(i1, Some(1.0), 5)]); // 90 min ago
        put(&mut db, NOW - 1000, &[(i2, Some(1.0), 5)]);

        db.recompute_baselines(NOW, 2).unwrap();
        let first = db.baselines_for(Scope::Executable, e2).unwrap();
        let count = db.baseline_count().unwrap();
        assert_eq!(db.recompute_baselines(NOW, 2).unwrap().subjects, 2);
        assert_eq!(db.baselines_for(Scope::Executable, e2).unwrap(), first);
        assert_eq!(db.baseline_count().unwrap(), count);

        // An hour later the old executable's only sample is outside the 2 h window.
        db.recompute_baselines(NOW + HOUR, 2).unwrap();
        assert!(db.baselines_for(Scope::Executable, e1).unwrap().is_empty());
        assert!(!db.baselines_for(Scope::Executable, e2).unwrap().is_empty());
    }

    #[test]
    fn unlinked_instances_and_other_windows_are_left_alone() {
        let mut db = Database::open_in_memory().unwrap();
        let e = exe(&db, "x");
        let (linked, orphan) = (
            instance(&db, 1, Some(e), None),
            instance(&db, 2, None, None),
        );
        put(
            &mut db,
            NOW - 1000,
            &[(linked, Some(1.0), 5), (orphan, Some(9.0), 5)],
        );

        db.recompute_baselines(NOW, 24).unwrap();
        assert_eq!(
            db.baseline_count().unwrap(),
            2,
            "cpu + memory of the one executable"
        );

        db.recompute_baselines(NOW, 1).unwrap();
        assert_eq!(
            db.baseline_count().unwrap(),
            4,
            "recomputing 1 h keeps the 24 h rows"
        );
    }

    #[test]
    fn listing_names_the_subjects() {
        let mut db = Database::open_in_memory().unwrap();
        let ap = app(&db, "Suite");
        let e = exe(&db, "zed.exe");
        let i = instance(&db, 1, Some(e), Some(ap));
        put(&mut db, NOW - 1000, &[(i, Some(1.0), 5)]);
        db.recompute_baselines(NOW, 1).unwrap();

        let listed = db.list_baselines(1).unwrap();
        let names: Vec<(&str, Scope)> = listed
            .iter()
            .map(|l| (l.name.as_str(), l.stored.scope))
            .collect();
        assert_eq!(
            names,
            [
                ("Suite", Scope::Application),
                ("Suite", Scope::Application),
                ("zed.exe", Scope::Executable),
                ("zed.exe", Scope::Executable),
            ]
        );
        assert!(db.list_baselines(24).unwrap().is_empty());
    }

    #[test]
    fn a_database_without_samples_gives_an_empty_report() {
        let mut db = Database::open_in_memory().unwrap();
        assert_eq!(
            db.recompute_baselines(NOW, 1).unwrap(),
            RecomputeReport::default()
        );
    }
}
