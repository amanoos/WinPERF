//! Who used the most of a resource over a period: the data behind the report's rankings.
//!
//! Instances are summed per tick first (all of Chrome's processes together), then each group is
//! summarised over the period. `average` is the mean over **every** tick of the period, counting
//! ticks where the group was not running as zero, so a ten-minute burst does not outrank something
//! that worked all day; `peak` is the highest per-tick total; `current` is the group's total at the
//! newest tick of the period (`None` when it was not running then).

use crate::db::Database;
use crate::error::Result;
use rusqlite::params;

/// The most ticks one ranking reads.
const MAX_TICKS: usize = 1500;

/// What is ranked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RankMetric {
    /// Percent of the whole machine's CPU.
    Cpu,
    /// Working set in bytes (shared pages are counted in every process that maps them).
    Memory,
    /// Process I/O read rate in bytes per second (all I/O kinds, not just physical disk).
    DiskRead,
    DiskWrite,
    /// Per-process network rates, from the ETW trace (needs administrator rights).
    NetRx,
    NetTx,
}

impl RankMetric {
    pub const ALL: [RankMetric; 6] = [
        Self::Cpu,
        Self::Memory,
        Self::DiskRead,
        Self::DiskWrite,
        Self::NetRx,
        Self::NetTx,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::DiskRead => "disk_read",
            Self::DiskWrite => "disk_write",
            Self::NetRx => "net_rx",
            Self::NetTx => "net_tx",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == text)
    }

    fn column(self) -> &'static str {
        match self {
            Self::Cpu => "cpu_percent",
            Self::Memory => "working_set_bytes",
            Self::DiskRead => "io_read_bytes_per_sec",
            Self::DiskWrite => "io_write_bytes_per_sec",
            Self::NetRx => "net_rx_bytes_per_sec",
            Self::NetTx => "net_tx_bytes_per_sec",
        }
    }
}

/// What a row stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RankGroup {
    /// One executable, all its running instances together.
    Process,
    /// One installed application (all its executables), else the executable on its own.
    Application,
}

impl RankGroup {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "process" => Some(Self::Process),
            "application" => Some(Self::Application),
            _ => None,
        }
    }

    /// SQL for the grouping key and the label of a group (fixed text, never user input).
    fn sql(self) -> (&'static str, &'static str) {
        match self {
            Self::Process => ("COALESCE(LOWER(pi.exe_path), LOWER(pi.name))", "pi.name"),
            Self::Application => (
                "COALESCE('app:' || pi.application_id, LOWER(COALESCE(pi.exe_path, pi.name)))",
                "COALESCE(ia.name, pi.name)",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankRow {
    pub name: String,
    /// The installed application the executable belongs to, when known (process rows).
    pub application: Option<String>,
    /// The executable and installed application behind the row, for linking to its detail page
    /// (a process row spans every instance of one path, so this is that path's executable).
    pub executable_id: Option<i64>,
    pub application_id: Option<i64>,
    pub current: Option<f64>,
    pub average: f64,
    pub peak: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ranking {
    /// False when the metric was never measured in the period (network without administrator
    /// rights, say): then there are no rows, and that is not the same as "nobody used any".
    pub available: bool,
    /// Ticks in the period.
    pub ticks: i64,
    /// 1 when every tick was read; N when only every Nth was (long periods), which makes peaks
    /// the highest of the sampled moments.
    pub sampled_every: i64,
    pub rows: Vec<RankRow>,
}

/// The ticks of a period that a query reads: all of them, or an even subset when there are many.
pub(crate) struct TickPick {
    /// Newest first; the newest tick of the period is always among them.
    pub picked: Vec<i64>,
    /// The same ticks as a JSON array, for `json_each(?)` in SQL.
    pub list: String,
    /// Ticks in the period, and how many of them one picked tick stands for (1 = all read).
    pub total: i64,
    pub stride: i64,
}

impl Database {
    /// The ticks of the period (one system sample each), thinned to at most `max` evenly spaced
    /// ones with the newest always among them: reading every sample of a long period takes many
    /// seconds, while an even subset gives the same averages and is read in a fraction of the time.
    /// (Peaks, and programs shorter than the gap between picked ticks, can be missed.)
    pub(crate) fn pick_ticks(&self, from_ms: i64, to_ms: i64, max: usize) -> Result<TickPick> {
        let all: Vec<i64> = {
            let mut stmt = self.conn().prepare(
                "SELECT ts_ms FROM system_samples WHERE ts_ms BETWEEN ?1 AND ?2 ORDER BY ts_ms",
            )?;
            let rows = stmt.query_map(params![from_ms, to_ms], |r| r.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let stride = all.len().div_ceil(max).max(1);
        // Newest first, so the newest tick is always picked.
        let picked: Vec<i64> = all.iter().rev().step_by(stride).copied().collect();
        let list = format!(
            "[{}]",
            picked
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        Ok(TickPick {
            picked,
            list,
            total: all.len() as i64,
            stride: stride as i64,
        })
    }

    /// The `limit` biggest users of `metric` between `from_ms` and `to_ms`, biggest average first.
    pub fn rankings(
        &self,
        metric: RankMetric,
        group: RankGroup,
        from_ms: i64,
        to_ms: i64,
        limit: u32,
    ) -> Result<Ranking> {
        let col = metric.column();
        let TickPick {
            picked,
            list,
            total,
            stride,
        } = self.pick_ticks(from_ms, to_ms, MAX_TICKS)?;
        let ticks = total.max(1);
        let sampled_every = stride;
        // Measured at any of the ticks that are read? (Cheap, and the same ticks the ranking uses.)
        let available: bool = self.conn().query_row(
            &format!(
                "SELECT EXISTS (SELECT 1 FROM resource_samples \
                 WHERE ts_ms IN (SELECT value FROM json_each(?1)) AND {col} IS NOT NULL)"
            ),
            params![list],
            |r| r.get(0),
        )?;
        let Some(&newest) = picked.first().filter(|_| available) else {
            return Ok(Ranking {
                available,
                ticks,
                sampled_every,
                rows: Vec::new(),
            });
        };
        let (key, label) = group.sql();
        let sql = format!(
            "WITH per_tick AS ( \
                 SELECT {key} AS k, MAX({label}) AS label, MAX(ia.name) AS app, \
                        MAX(pi.executable_id) AS exe_id, MAX(pi.application_id) AS app_id, \
                        rs.ts_ms AS ts, SUM(rs.{col}) AS v \
                 FROM resource_samples rs \
                 JOIN process_instances pi ON pi.id = rs.process_instance_id \
                 LEFT JOIN installed_applications ia ON ia.id = pi.application_id \
                 WHERE rs.ts_ms IN (SELECT value FROM json_each(?1)) AND rs.{col} IS NOT NULL \
                 GROUP BY k, rs.ts_ms) \
             SELECT label, MAX(app), SUM(v), MAX(v), SUM(CASE WHEN ts = ?2 THEN v END), \
                    MAX(exe_id), MAX(app_id) \
             FROM per_tick GROUP BY k ORDER BY SUM(v) DESC, label LIMIT ?3"
        );
        let used = picked.len() as f64;
        let mut stmt = self.conn().prepare(&sql)?;
        let rows = stmt.query_map(params![list, newest, limit], |r| {
            let total: f64 = r.get(2)?;
            Ok(RankRow {
                name: r.get(0)?,
                application: r.get(1)?,
                average: total / used,
                peak: r.get(3)?,
                current: r.get(4)?,
                executable_id: r.get(5)?,
                application_id: r.get(6)?,
            })
        })?;
        Ok(Ranking {
            available,
            ticks,
            sampled_every,
            rows: rows.collect::<std::result::Result<Vec<_>, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Four ticks. Chrome is two instances (pid 10 and 11) plus a helper executable of the same
    /// application; Code is one; `other.exe` has no application and ran in one tick only.
    fn seeded() -> Database {
        let db = Database::open_in_memory().unwrap();
        let sql = |s: &str| db.conn().execute_batch(s).unwrap();
        for ts in [1000, 2000, 3000, 4000] {
            sql(&format!("INSERT INTO system_samples (ts_ms) VALUES ({ts})"));
        }
        sql(
            "INSERT INTO installed_applications (id, app_key, name, registry_sources, classification, first_seen, last_seen, \
             scan_seq) VALUES (1, 'chrome', 'Chrome', '', 't', 't', 't', 1), \
             (2, 'code', 'Code', '', 't', 't', 't', 1)",
        );
        for (id, pid, name, app) in [
            (1, 10, "chrome.exe", "1"),
            (2, 11, "chrome.exe", "1"),
            (3, 20, "code.exe", "2"),
            (4, 30, "other.exe", "NULL"),
            (5, 40, "helper.exe", "1"),
        ] {
            sql(&format!(
                "INSERT INTO process_instances (id, pid, start_time, parent_pid, name, exe_path, \
                 application_id, first_seen, last_seen) \
                 VALUES ({id}, {pid}, 100, 0, '{name}', 'C:/apps/{name}', {app}, 't', 't')"
            ));
        }
        // Only chrome.exe has an executable row (id 7), shared by its two instances.
        sql(
            "INSERT INTO executables (id, path_key, file_path, file_name, signature_status, \
             classification, file_size, file_mtime_ns, verified_at) \
             VALUES (7, 'c:/apps/chrome.exe', 'C:/apps/chrome.exe', 'chrome.exe', 'valid', 't', 1, 1, 't'); \
             UPDATE process_instances SET executable_id = 7 WHERE id IN (1, 2)",
        );
        // (instance, ts, cpu, working set)
        for (i, ts, cpu, mem) in [
            (1, 1000, 10.0, 100),
            (2, 1000, 5.0, 50),
            (3, 1000, 1.0, 10),
            (1, 2000, 20.0, 100),
            (2, 2000, 10.0, 50),
            (3, 2000, 1.0, 10),
            (4, 2000, 50.0, 7),
            (3, 3000, 1.0, 10),
            (1, 4000, 30.0, 100),
            (2, 4000, 0.0, 50),
            (3, 4000, 2.0, 10),
            (5, 4000, 5.0, 25),
        ] {
            sql(&format!(
                "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, \
                 working_set_bytes) VALUES ({i}, {ts}, {cpu}, {mem})"
            ));
        }
        db
    }

    fn names(r: &Ranking) -> Vec<&str> {
        r.rows.iter().map(|x| x.name.as_str()).collect()
    }

    #[test]
    fn processes_are_summed_per_tick_then_averaged_over_every_tick() {
        let db = seeded();
        let r = db
            .rankings(RankMetric::Cpu, RankGroup::Process, 0, 5000, 10)
            .unwrap();
        assert!(r.available);
        assert_eq!(r.ticks, 4);
        assert_eq!(
            names(&r),
            ["chrome.exe", "other.exe", "code.exe", "helper.exe"]
        );
        let chrome = &r.rows[0];
        // Sums per tick: 15, 30, (absent), 30. Total 75 over 4 ticks.
        assert_eq!(chrome.average, 75.0 / 4.0);
        assert_eq!(chrome.peak, 30.0);
        assert_eq!(chrome.current, Some(30.0));
        assert_eq!(chrome.application.as_deref(), Some("Chrome"));
        assert_eq!(
            (chrome.executable_id, chrome.application_id),
            (Some(7), Some(1))
        );
        let other = &r.rows[1];
        assert_eq!((other.executable_id, other.application_id), (None, None));
        assert_eq!((other.average, other.peak), (12.5, 50.0));
        assert_eq!(other.current, None, "not running at the newest tick");
        assert_eq!(other.application, None);
        let code = &r.rows[2];
        assert_eq!(
            (code.average, code.peak, code.current),
            (1.25, 2.0, Some(2.0))
        );
    }

    #[test]
    fn applications_gather_their_executables() {
        let db = seeded();
        let r = db
            .rankings(RankMetric::Cpu, RankGroup::Application, 0, 5000, 10)
            .unwrap();
        assert_eq!(names(&r), ["Chrome", "other.exe", "Code"]);
        let chrome = &r.rows[0];
        // Chrome + its helper: 15, 30, (absent), 35. Total 80.
        assert_eq!(chrome.average, 20.0);
        assert_eq!(chrome.peak, 35.0);
        assert_eq!(chrome.current, Some(35.0));
        assert_eq!(chrome.application_id, Some(1));
    }

    #[test]
    fn the_period_and_the_limit_are_respected() {
        let db = seeded();
        // Only ticks 2000 and 3000: chrome 30 once, other 50 once, code 1 twice.
        let r = db
            .rankings(RankMetric::Cpu, RankGroup::Process, 2000, 3000, 2)
            .unwrap();
        assert_eq!(r.ticks, 2);
        assert_eq!(names(&r), ["other.exe", "chrome.exe"]);
        assert_eq!(r.rows[0].average, 25.0);
        assert_eq!(
            r.rows[0].current, None,
            "not running at the newest tick, 3000"
        );
    }

    #[test]
    fn memory_ranks_by_working_set() {
        let db = seeded();
        let r = db
            .rankings(RankMetric::Memory, RankGroup::Process, 0, 5000, 10)
            .unwrap();
        assert_eq!(names(&r)[0], "chrome.exe");
        assert_eq!(r.rows[0].peak, 150.0);
        assert_eq!(r.rows[0].current, Some(150.0));
    }

    #[test]
    fn a_metric_that_was_never_measured_is_unavailable_not_zero() {
        let db = seeded();
        for m in [RankMetric::NetRx, RankMetric::NetTx, RankMetric::DiskRead] {
            let r = db.rankings(m, RankGroup::Process, 0, 5000, 10).unwrap();
            assert!(!r.available, "{m:?}");
            assert!(r.rows.is_empty());
        }
    }

    #[test]
    fn a_long_period_is_read_from_an_even_subset_that_includes_the_newest_tick() {
        let db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO process_instances (id, pid, start_time, parent_pid, name, exe_path, \
                 first_seen, last_seen) VALUES (1, 1, 1, 0, 'a.exe', 'C:/a.exe', 't', 't')",
            )
            .unwrap();
        // 3001 ticks of 10 ms steps; the process reads 1.0 except at the very last tick (7.0).
        for n in 0..=3000 {
            let ts = 1000 + n * 10;
            let cpu = if n == 3000 { 7.0 } else { 1.0 };
            db.conn()
                .execute_batch(&format!(
                    "INSERT INTO system_samples (ts_ms) VALUES ({ts}); \
                     INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent) \
                     VALUES (1, {ts}, {cpu})"
                ))
                .unwrap();
        }
        let r = db
            .rankings(RankMetric::Cpu, RankGroup::Process, 0, 100_000, 10)
            .unwrap();
        assert_eq!(r.ticks, 3001);
        assert_eq!(r.sampled_every, 3, "3001 ticks, at most 1500 read");
        let row = &r.rows[0];
        assert_eq!(row.current, Some(7.0), "the newest tick is always read");
        assert_eq!(row.peak, 7.0);
        // 1001 ticks read: 1000 at 1.0 and the newest at 7.0.
        assert_eq!(row.average, (1000.0 + 7.0) / 1001.0);

        // A short period is read in full.
        let short = db
            .rankings(RankMetric::Cpu, RankGroup::Process, 1000, 1100, 10)
            .unwrap();
        assert_eq!(short.sampled_every, 1);
    }

    #[test]
    fn names_round_trip() {
        for m in RankMetric::ALL {
            assert_eq!(RankMetric::parse(m.as_str()), Some(m));
        }
        assert_eq!(RankMetric::parse("gpu"), None);
        assert_eq!(
            RankGroup::parse("application"),
            Some(RankGroup::Application)
        );
        assert_eq!(RankGroup::parse("x"), None);
    }
}
