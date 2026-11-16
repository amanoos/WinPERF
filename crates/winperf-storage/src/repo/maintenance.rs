//! Retention: build the 1-minute and 15-minute rollups from the raw samples, then delete what has
//! outlived its retention (T34, PRD 4.3).
//!
//! Everything here works in small transactions so it can run beside the recorder without holding
//! its write lock for long, and every step is safe to repeat or to interrupt:
//!
//! * a rollup is only built for minutes that are complete (with a minute of grace), and rebuilding
//!   a bucket replaces it, so a crash half way loses nothing;
//! * raw samples are only deleted once they are older than the retention **and** already rolled
//!   up, 1-minute rows only once they are rolled into 15-minute rows, and so on, so a stopped
//!   maintenance job never costs history;
//! * deletes go in batches, oldest first, so the freed pages are reused and the file settles at a
//!   steady size.
//!
//! `resource_samples` is indexed by time first (schema v5), and `process_instances` is its parent
//! with ON DELETE CASCADE, so samples are pruned by time and instances afterwards with foreign key
//! enforcement switched off on this connection (otherwise every instance delete scans the table).

use crate::db::Database;
use crate::error::Result;
use crate::repo::samples::StoredSystemSample;
use rusqlite::{OptionalExtension, params};
use winperf_core::config::RetentionConfig;

const MINUTE_MS: i64 = 60_000;
const QUARTER_MS: i64 = 15 * MINUTE_MS;
const DAY_MS: i64 = 24 * 3_600_000;
/// Raw time covered by one 1-minute rollup transaction.
const MINUTE_CHUNK_MS: i64 = 60 * MINUTE_MS;
/// Time covered by one 15-minute rollup transaction.
const QUARTER_CHUNK_MS: i64 = 12 * 3_600_000;
/// Rows deleted per transaction.
const DELETE_BATCH: i64 = 20_000;
/// Rollup rows are deleted this much time at a time.
const DELETE_SLICE_MS: i64 = 6 * 3_600_000;

const KEY_1M: &str = "rolled_1m_until";
const KEY_15M: &str = "rolled_15m_until";

/// The process columns that are rolled up: rollup name, raw column.
const PROCESS_COLUMNS: [(&str, &str); 7] = [
    ("cpu", "cpu_percent"),
    ("working_set", "working_set_bytes"),
    ("private", "private_bytes"),
    ("io_read", "io_read_bytes_per_sec"),
    ("io_write", "io_write_bytes_per_sec"),
    ("net_rx", "net_rx_bytes_per_sec"),
    ("net_tx", "net_tx_bytes_per_sec"),
];

/// The destination columns of the system rollup, in the order the SELECTs below produce them.
const SYSTEM_INSERT: &str = "(res_ms, bucket_ts, n, cpu_avg, cpu_max, memory_total, \
    memory_avail_avg, memory_avail_min, commit_used_avg, commit_limit, disk_util_avg, \
    disk_util_max, disk_queue_avg, disk_read_avg, disk_write_avg, disk_latency_avg, \
    disk_latency_max, net_rx_avg, net_rx_max, net_tx_avg, net_tx_max)";

/// What one maintenance pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MaintenanceReport {
    /// Minutes rolled up into 1-minute rows, and quarter hours into 15-minute rows.
    pub minutes_rolled: u64,
    pub quarters_rolled: u64,
    pub raw_deleted: u64,
    pub system_raw_deleted: u64,
    pub minute_rollups_deleted: u64,
    pub quarter_rollups_deleted: u64,
    pub anomalies_deleted: u64,
    pub instances_deleted: u64,
    /// The pass stopped at its work limit and there is more to do.
    pub more: bool,
}

impl MaintenanceReport {
    pub fn did_anything(&self) -> bool {
        self.minutes_rolled
            + self.quarters_rolled
            + self.raw_deleted
            + self.system_raw_deleted
            + self.minute_rollups_deleted
            + self.quarter_rollups_deleted
            + self.anomalies_deleted
            + self.instances_deleted
            > 0
    }
}

/// How much one pass may do (so a catch-up on a big database is spread over many passes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Transactions that build rollups.
    pub rollup_chunks: u32,
    /// Delete batches per table.
    pub delete_batches: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rollup_chunks: 6,
            delete_batches: 10,
        }
    }
}

impl Limits {
    /// No limit worth speaking of: do everything now (the command-line `maintain`).
    pub fn unlimited() -> Self {
        Self {
            rollup_chunks: u32::MAX,
            delete_batches: u32::MAX,
        }
    }
}

fn state(db: &Database, key: &str) -> Result<Option<i64>> {
    Ok(db
        .conn()
        .query_row(
            "SELECT value FROM maintenance_state WHERE key = ?1",
            [key],
            |r| r.get(0),
        )
        .optional()?)
}

fn set_state(tx: &rusqlite::Transaction<'_>, key: &str, value: i64) -> Result<()> {
    tx.execute(
        "INSERT INTO maintenance_state (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn floor_to(ts: i64, width: i64) -> i64 {
    ts.div_euclid(width) * width
}

/// A weighted average over the minutes that measured the column.
fn weighted(c: &str) -> String {
    format!("SUM({c}_avg * n) / SUM(CASE WHEN {c}_avg IS NOT NULL THEN n END)")
}

/// Where a history query reads from: the raw samples, or the rollups of one bucket width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySource {
    Raw,
    /// 60000 (1-minute rows) or 900000 (15-minute rows).
    Rollup(i64),
}

impl HistorySource {
    /// 0 for raw samples, else the bucket width in milliseconds.
    pub fn resolution_ms(self) -> i64 {
        match self {
            HistorySource::Raw => 0,
            HistorySource::Rollup(r) => r,
        }
    }

    /// The rollup column stem of a raw process column (`cpu_percent` is `cpu`, giving `cpu_avg`
    /// and `cpu_max`).
    pub(crate) fn rollup_stem(raw_column: &str) -> &'static str {
        PROCESS_COLUMNS
            .iter()
            .find(|(_, raw)| *raw == raw_column)
            .map_or("cpu", |(stem, _)| stem)
    }
}

impl Database {
    /// Whether this database has the rollup tables (an older one opened read-only may not).
    pub(crate) fn has_rollups(&self) -> bool {
        self.conn()
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'system_rollups'",
                [],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// Where to read a history that starts at `from_ms`: the raw samples when they reach back that
    /// far (or when no rollup reaches back further), else the finest rollup that does. Rollups
    /// are only chosen when they hold history the raw samples no longer have, so a short history
    /// is never shown at a coarser resolution than it has.
    pub fn history_source(&self, from_ms: i64) -> Result<HistorySource> {
        if !self.has_rollups() {
            return Ok(HistorySource::Raw);
        }
        let raw_floor: Option<i64> =
            self.conn()
                .query_row("SELECT MIN(ts_ms) FROM system_samples", [], |r| r.get(0))?;
        let floor = |res: i64| -> Result<Option<i64>> {
            Ok(self.conn().query_row(
                "SELECT MIN(bucket_ts) FROM system_rollups WHERE res_ms = ?1",
                [res],
                |r| r.get(0),
            )?)
        };
        let (minute, quarter) = (floor(MINUTE_MS)?, floor(QUARTER_MS)?);
        let oldest_rollup = [minute, quarter].into_iter().flatten().min();
        match (raw_floor, oldest_rollup) {
            (Some(raw), Some(old)) if old < raw && from_ms < raw => {}
            (None, Some(_)) => {}
            _ => return Ok(HistorySource::Raw),
        }
        Ok(match (minute, quarter) {
            (Some(m), _) if from_ms >= m => HistorySource::Rollup(MINUTE_MS),
            (_, Some(_)) => HistorySource::Rollup(QUARTER_MS),
            _ => HistorySource::Rollup(MINUTE_MS),
        })
    }

    /// The system history of `[from_ms, to_ms]` from the best source for it (see
    /// [`Self::history_source`]). Rollup rows come back as samples whose values are the bucket
    /// averages, stamped with the bucket start, so a chart reads them like raw samples.
    pub fn system_history_between(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<(HistorySource, Vec<StoredSystemSample>)> {
        let mut out = Vec::new();
        let source = self.system_history_each(from_ms, to_ms, |s| {
            out.push(s);
            true
        })?;
        Ok((source, out))
    }

    /// Like [`Self::system_history_between`] but handing each sample to `each` (which returns
    /// false to stop), so a long raw range need not be held in memory.
    pub fn system_history_each(
        &self,
        from_ms: i64,
        to_ms: i64,
        mut each: impl FnMut(StoredSystemSample) -> bool,
    ) -> Result<HistorySource> {
        let source = self.history_source(from_ms)?;
        let HistorySource::Rollup(res) = source else {
            self.system_samples_each(from_ms, to_ms, each)?;
            return Ok(source);
        };
        let mut stmt = self.conn().prepare(
            "SELECT bucket_ts, cpu_avg, memory_total, memory_avail_avg, commit_used_avg,              commit_limit, disk_util_avg, disk_queue_avg, disk_read_avg, disk_write_avg,              disk_latency_avg, net_rx_avg, net_tx_avg FROM system_rollups              WHERE res_ms = ?1 AND bucket_ts BETWEEN ?2 AND ?3 ORDER BY bucket_ts",
        )?;
        let big = |v: Option<f64>| v.map(|x| x as u64);
        let mut rows = stmt.query(params![res, from_ms, to_ms])?;
        while let Some(r) = rows.next()? {
            let sample = StoredSystemSample {
                ts_ms: r.get(0)?,
                cpu_percent: r.get(1)?,
                memory_total_bytes: r.get::<_, Option<i64>>(2)?.map(|x| x as u64),
                memory_available_bytes: big(r.get(3)?),
                commit_used_bytes: big(r.get(4)?),
                commit_limit_bytes: r.get::<_, Option<i64>>(5)?.map(|x| x as u64),
                disk_utilization_percent: r.get(6)?,
                disk_queue_length: r.get(7)?,
                disk_read_bytes_per_sec: r.get(8)?,
                disk_write_bytes_per_sec: r.get(9)?,
                disk_latency_ms: r.get(10)?,
                net_rx_bytes_per_sec: r.get(11)?,
                net_tx_bytes_per_sec: r.get(12)?,
            };
            if !each(sample) {
                break;
            }
        }
        Ok(source)
    }

    /// How far the 1-minute rollup is built (`None` before the first pass).
    pub fn rolled_up_until(&self) -> Result<Option<i64>> {
        state(self, KEY_1M)
    }

    /// Build 1-minute rollups for every complete minute not yet done, at most
    /// `limits.rollup_chunks` hours of raw data per call. Returns the minutes covered.
    pub fn rollup_minutes(&mut self, now_ms: i64, limits: Limits) -> Result<u64> {
        let end = floor_to(now_ms - MINUTE_MS, MINUTE_MS);
        let mut from = match state(self, KEY_1M)? {
            Some(v) => v,
            None => {
                let first: Option<i64> =
                    self.conn()
                        .query_row("SELECT MIN(ts_ms) FROM system_samples", [], |r| r.get(0))?;
                match first {
                    Some(t) => floor_to(t, MINUTE_MS),
                    None => return Ok(0),
                }
            }
        };
        let process_values: String = PROCESS_COLUMNS
            .iter()
            .map(|(_, raw)| format!(", AVG({raw}), MAX({raw})"))
            .collect();
        let process_names: String = PROCESS_COLUMNS
            .iter()
            .map(|(n, _)| format!(", {n}_avg, {n}_max"))
            .collect();
        let mut minutes = 0u64;
        let mut chunks = limits.rollup_chunks;
        while from < end && chunks > 0 {
            // Skip a stretch with no samples at all (the recorder was off) instead of walking it.
            let next: Option<i64> = self.conn().query_row(
                "SELECT MIN(ts_ms) FROM system_samples WHERE ts_ms >= ?1",
                [from],
                |r| r.get(0),
            )?;
            let Some(next) = next else {
                let tx = self.conn_mut().transaction()?;
                set_state(&tx, KEY_1M, end)?;
                tx.commit()?;
                return Ok(minutes);
            };
            from = from.max(floor_to(next, MINUTE_MS));
            if from >= end {
                break;
            }
            let to = (from + MINUTE_CHUNK_MS).min(end);
            let tx = self.conn_mut().transaction()?;
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO process_rollups \
                     (res_ms, bucket_ts, process_instance_id, n{process_names}) \
                     SELECT {MINUTE_MS}, (ts_ms / {MINUTE_MS}) * {MINUTE_MS}, process_instance_id, \
                            COUNT(*){process_values} \
                     FROM resource_samples WHERE ts_ms >= ?1 AND ts_ms < ?2 \
                     GROUP BY 2, 3"
                ),
                params![from, to],
            )?;
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO system_rollups {SYSTEM_INSERT} \
                     SELECT {MINUTE_MS}, (ts_ms / {MINUTE_MS}) * {MINUTE_MS}, COUNT(*), \
                            AVG(cpu_percent), MAX(cpu_percent), MAX(memory_total_bytes), \
                            AVG(memory_available_bytes), MIN(memory_available_bytes), \
                            AVG(commit_used_bytes), MAX(commit_limit_bytes), \
                            AVG(disk_utilization_percent), MAX(disk_utilization_percent), \
                            AVG(disk_queue_length), AVG(disk_read_bytes_per_sec), \
                            AVG(disk_write_bytes_per_sec), AVG(disk_latency_ms), \
                            MAX(disk_latency_ms), AVG(net_rx_bytes_per_sec), \
                            MAX(net_rx_bytes_per_sec), AVG(net_tx_bytes_per_sec), \
                            MAX(net_tx_bytes_per_sec) \
                     FROM system_samples WHERE ts_ms >= ?1 AND ts_ms < ?2 GROUP BY 2"
                ),
                params![from, to],
            )?;
            set_state(&tx, KEY_1M, to)?;
            tx.commit()?;
            minutes += ((to - from) / MINUTE_MS) as u64;
            from = to;
            chunks -= 1;
        }
        Ok(minutes)
    }

    /// Build 15-minute rollups from the 1-minute ones for every complete quarter hour not yet done.
    /// Returns the quarter hours covered.
    pub fn rollup_quarters(&mut self, limits: Limits) -> Result<u64> {
        let Some(built) = state(self, KEY_1M)? else {
            return Ok(0);
        };
        let end = floor_to(built, QUARTER_MS);
        let mut from = match state(self, KEY_15M)? {
            Some(v) => v,
            None => {
                let first: Option<i64> = self.conn().query_row(
                    "SELECT MIN(bucket_ts) FROM system_rollups WHERE res_ms = ?1",
                    [MINUTE_MS],
                    |r| r.get(0),
                )?;
                match first {
                    Some(t) => floor_to(t, QUARTER_MS),
                    None => return Ok(0),
                }
            }
        };
        let process_values: String = PROCESS_COLUMNS
            .iter()
            .map(|(n, _)| format!(", {}, MAX({n}_max)", weighted(n)))
            .collect();
        let process_names: String = PROCESS_COLUMNS
            .iter()
            .map(|(n, _)| format!(", {n}_avg, {n}_max"))
            .collect();
        let mut quarters = 0u64;
        let mut chunks = limits.rollup_chunks;
        while from < end && chunks > 0 {
            let to = (from + QUARTER_CHUNK_MS).min(end);
            let tx = self.conn_mut().transaction()?;
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO process_rollups \
                     (res_ms, bucket_ts, process_instance_id, n{process_names}) \
                     SELECT {QUARTER_MS}, (bucket_ts / {QUARTER_MS}) * {QUARTER_MS}, \
                            process_instance_id, SUM(n){process_values} \
                     FROM process_rollups \
                     WHERE res_ms = {MINUTE_MS} AND bucket_ts >= ?1 AND bucket_ts < ?2 \
                     GROUP BY 2, 3"
                ),
                params![from, to],
            )?;
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO system_rollups {SYSTEM_INSERT} \
                     SELECT {QUARTER_MS}, (bucket_ts / {QUARTER_MS}) * {QUARTER_MS}, SUM(n), \
                            {cpu}, MAX(cpu_max), MAX(memory_total), {avail}, \
                            MIN(memory_avail_min), {commit}, MAX(commit_limit), {util}, \
                            MAX(disk_util_max), {queue}, {read}, {write}, {lat}, \
                            MAX(disk_latency_max), {rx}, MAX(net_rx_max), {tx}, MAX(net_tx_max) \
                     FROM system_rollups \
                     WHERE res_ms = {MINUTE_MS} AND bucket_ts >= ?1 AND bucket_ts < ?2 \
                     GROUP BY 2",
                    cpu = weighted("cpu"),
                    avail = weighted("memory_avail"),
                    commit = weighted("commit_used"),
                    util = weighted("disk_util"),
                    queue = weighted("disk_queue"),
                    read = weighted("disk_read"),
                    write = weighted("disk_write"),
                    lat = weighted("disk_latency"),
                    rx = weighted("net_rx"),
                    tx = weighted("net_tx"),
                ),
                params![from, to],
            )?;
            set_state(&tx, KEY_15M, to)?;
            tx.commit()?;
            quarters += ((to - from) / QUARTER_MS) as u64;
            from = to;
            chunks -= 1;
        }
        Ok(quarters)
    }

    /// Delete rows by id in batches (through the time index) until none older than `cutoff_ms`
    /// are left or `batches` run out. Returns rows deleted and whether more remain.
    fn delete_old_rows(
        &mut self,
        table: &str,
        cutoff_ms: i64,
        batches: u32,
    ) -> Result<(u64, bool)> {
        let sql = format!(
            "DELETE FROM {table} WHERE id IN \
             (SELECT id FROM {table} WHERE ts_ms < ?1 LIMIT {DELETE_BATCH})"
        );
        let mut total = 0u64;
        let mut left = batches;
        loop {
            if left == 0 {
                return Ok((total, true));
            }
            left -= 1;
            let tx = self.conn_mut().transaction()?;
            let n = tx.execute(&sql, [cutoff_ms])? as u64;
            tx.commit()?;
            total += n;
            if (n as i64) < DELETE_BATCH {
                return Ok((total, false));
            }
        }
    }

    /// Delete rollup rows of one width older than `cutoff_ms`, a time slice at a time.
    fn delete_old_rollups(
        &mut self,
        res_ms: i64,
        cutoff_ms: i64,
        batches: u32,
    ) -> Result<(u64, bool)> {
        let mut total = 0u64;
        let mut left = batches;
        loop {
            let oldest = |table: &str| -> Result<Option<i64>> {
                Ok(self.conn().query_row(
                    &format!("SELECT MIN(bucket_ts) FROM {table} WHERE res_ms = ?1"),
                    [res_ms],
                    |r| r.get(0),
                )?)
            };
            let Some(oldest) = [oldest("system_rollups")?, oldest("process_rollups")?]
                .into_iter()
                .flatten()
                .min()
            else {
                return Ok((total, false));
            };
            if oldest >= cutoff_ms {
                return Ok((total, false));
            }
            if left == 0 {
                return Ok((total, true));
            }
            left -= 1;
            let to = (oldest + DELETE_SLICE_MS).min(cutoff_ms);
            let tx = self.conn_mut().transaction()?;
            total += tx.execute(
                "DELETE FROM process_rollups WHERE res_ms = ?1 AND bucket_ts < ?2",
                params![res_ms, to],
            )? as u64;
            total += tx.execute(
                "DELETE FROM system_rollups WHERE res_ms = ?1 AND bucket_ts < ?2",
                params![res_ms, to],
            )? as u64;
            tx.commit()?;
        }
    }

    /// Delete what has outlived its retention and is safely covered by a coarser rollup (see the
    /// module docs). Returns what was removed.
    pub fn prune(
        &mut self,
        now_ms: i64,
        retention: &RetentionConfig,
        limits: Limits,
    ) -> Result<MaintenanceReport> {
        let mut report = MaintenanceReport::default();
        let rolled_1m = state(self, KEY_1M)?.unwrap_or(i64::MIN);
        let rolled_15m = state(self, KEY_15M)?.unwrap_or(i64::MIN);
        let day = |d: u32| i64::from(d) * DAY_MS;

        // Raw samples: old enough and already in a 1-minute rollup.
        let raw_cutoff = (now_ms - day(retention.raw_samples_days)).min(rolled_1m);
        let (n, more) =
            self.delete_old_rows("resource_samples", raw_cutoff, limits.delete_batches)?;
        report.raw_deleted = n;
        report.more |= more;
        let (n, more) =
            self.delete_old_rows("system_samples", raw_cutoff, limits.delete_batches)?;
        report.system_raw_deleted = n;
        report.more |= more;

        // 1-minute rows: old enough and already in a 15-minute row.
        let minute_cutoff = (now_ms - day(retention.aggregate_1min_days)).min(rolled_15m);
        let (n, more) = self.delete_old_rollups(MINUTE_MS, minute_cutoff, limits.delete_batches)?;
        report.minute_rollups_deleted = n;
        report.more |= more;

        // 15-minute rows: by age alone.
        let quarter_cutoff = now_ms - day(retention.aggregate_15min_days);
        let (n, more) =
            self.delete_old_rollups(QUARTER_MS, quarter_cutoff, limits.delete_batches)?;
        report.quarter_rollups_deleted = n;
        report.more |= more;

        // Anomalies: resolved ones by age.
        let tx = self.conn_mut().transaction()?;
        report.anomalies_deleted = tx.execute(
            "DELETE FROM anomaly_events WHERE resolved_ts_ms IS NOT NULL AND detected_ts_ms < ?1",
            [now_ms - day(retention.anomaly_days)],
        )? as u64;
        tx.commit()?;

        // Process instances that ended before the oldest history kept. Foreign keys are off for
        // this: a cascade check scans the whole samples table for every row deleted.
        self.conn().pragma_update(None, "foreign_keys", false)?;
        let result = self.delete_old_instances(quarter_cutoff, limits.delete_batches);
        self.conn().pragma_update(None, "foreign_keys", true)?;
        report.instances_deleted = result?;

        // Let the WAL be folded back into the database file without blocking anyone.
        let _ = self
            .conn()
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()));
        Ok(report)
    }

    fn delete_old_instances(&mut self, cutoff_ms: i64, batches: u32) -> Result<u64> {
        let mut total = 0u64;
        for _ in 0..batches {
            let tx = self.conn_mut().transaction()?;
            let n = tx.execute(
                "DELETE FROM process_instances WHERE id IN ( \
                   SELECT id FROM process_instances \
                   WHERE end_time IS NOT NULL AND last_seen < datetime(?1 / 1000, 'unixepoch') \
                   LIMIT ?2)",
                params![cutoff_ms, DELETE_BATCH],
            )? as u64;
            tx.commit()?;
            total += n;
            if (n as i64) < DELETE_BATCH {
                break;
            }
        }
        Ok(total)
    }

    /// One full pass: roll up, then prune.
    pub fn maintain(
        &mut self,
        now_ms: i64,
        retention: &RetentionConfig,
        limits: Limits,
    ) -> Result<MaintenanceReport> {
        let minutes = self.rollup_minutes(now_ms, limits)?;
        let quarters = self.rollup_quarters(limits)?;
        let mut report = self.prune(now_ms, retention, limits)?;
        report.minutes_rolled = minutes;
        report.quarters_rolled = quarters;
        // Rollup work remains when the pass stopped at its limit.
        let end = floor_to(now_ms - MINUTE_MS, MINUTE_MS);
        report.more |= state(self, KEY_1M)?.is_some_and(|built| built < end);
        Ok(report)
    }

    /// Compact the file by rewriting it (SQLite `VACUUM`). Slow and needs the database to itself
    /// (no recorder writing), so it is only ever run by hand.
    pub fn vacuum(&self) -> Result<()> {
        self.conn().execute_batch("VACUUM")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_006_400_000; // a multiple of a day (and so of 15 minutes)

    fn retention(raw: u32, m1: u32, m15: u32, anomaly: u32) -> RetentionConfig {
        RetentionConfig {
            raw_samples_days: raw,
            aggregate_1min_days: m1,
            aggregate_15min_days: m15,
            anomaly_days: anomaly,
        }
    }

    fn instance(db: &Database, id: i64, last_seen_ms: i64, ended: bool) {
        db.conn()
            .execute(
                "INSERT INTO process_instances (id, pid, start_time, parent_pid, name, first_seen, \
                 last_seen, end_time) VALUES (?1, ?1, 1, 0, 'p', 't', datetime(?2 / 1000, 'unixepoch'), \
                 CASE WHEN ?3 THEN 'e' END)",
                params![id, last_seen_ms, ended],
            )
            .unwrap();
    }

    fn tick(db: &Database, ts: i64, rows: &[(i64, Option<f64>, i64)]) {
        db.conn()
            .execute(
                "INSERT INTO system_samples (ts_ms, cpu_percent, memory_total_bytes, \
                 memory_available_bytes) VALUES (?1, ?2, 1000, 400)",
                params![ts, rows.first().and_then(|r| r.1)],
            )
            .unwrap();
        for (inst, cpu, ws) in rows {
            db.conn()
                .execute(
                    "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, \
                     working_set_bytes) VALUES (?1, ?2, ?3, ?4)",
                    params![inst, ts, cpu, ws],
                )
                .unwrap();
        }
    }

    fn count(db: &Database, sql: &str) -> i64 {
        db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_minute_becomes_one_row_with_the_average_the_max_and_the_tick_count() {
        let mut db = Database::open_in_memory().unwrap();
        instance(&db, 1, T0, false);
        // Minute 0: cpu 10, 20 and one unmeasured; minute 1: 30 only. Working set 100 each.
        tick(&db, T0, &[(1, Some(10.0), 100)]);
        tick(&db, T0 + 20_000, &[(1, Some(20.0), 100)]);
        tick(&db, T0 + 40_000, &[(1, None, 100)]);
        tick(&db, T0 + 60_000, &[(1, Some(30.0), 100)]);

        // Not before the minute (and its grace) is over: now = T0 + 1 min covers nothing yet.
        assert_eq!(
            db.rollup_minutes(T0 + 60_000, Limits::default()).unwrap(),
            0
        );
        // At T0 + 3 min the minutes 0 and 1 are complete.
        assert_eq!(
            db.rollup_minutes(T0 + 3 * 60_000, Limits::default())
                .unwrap(),
            2
        );

        let row = |bucket: i64| -> (i64, Option<f64>, Option<f64>, Option<f64>) {
            db.conn()
                .query_row(
                    "SELECT n, cpu_avg, cpu_max, working_set_avg FROM process_rollups \
                     WHERE res_ms = 60000 AND bucket_ts = ?1 AND process_instance_id = 1",
                    [bucket],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap()
        };
        assert_eq!(row(T0), (3, Some(15.0), Some(20.0), Some(100.0)));
        assert_eq!(row(T0 + 60_000), (1, Some(30.0), Some(30.0), Some(100.0)));
        let sys: (i64, Option<f64>, Option<i64>, Option<f64>) = db
            .conn()
            .query_row(
                "SELECT n, cpu_avg, memory_total, memory_avail_avg FROM system_rollups \
                 WHERE res_ms = 60000 AND bucket_ts = ?1",
                [T0],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(sys, (3, Some(15.0), Some(1000), Some(400.0)));

        // Running again does nothing and changes nothing.
        assert_eq!(
            db.rollup_minutes(T0 + 3 * 60_000, Limits::default())
                .unwrap(),
            0
        );
        assert_eq!(count(&db, "SELECT COUNT(*) FROM process_rollups"), 2);
    }

    #[test]
    fn fifteen_minutes_are_the_tick_weighted_mean_of_their_minutes() {
        let mut db = Database::open_in_memory().unwrap();
        instance(&db, 1, T0, false);
        // Minute 0: three ticks at cpu 10 (avg 10, n 3). Minute 1: one tick at cpu 50.
        for k in 0..3 {
            tick(&db, T0 + k * 10_000, &[(1, Some(10.0), 100)]);
        }
        tick(&db, T0 + 60_000, &[(1, Some(50.0), 300)]);
        let now = T0 + 20 * 60_000;
        db.rollup_minutes(now, Limits::default()).unwrap();
        assert_eq!(db.rollup_quarters(Limits::default()).unwrap(), 1);
        let (n, avg, max, ws): (i64, f64, f64, f64) = db
            .conn()
            .query_row(
                "SELECT n, cpu_avg, cpu_max, working_set_avg FROM process_rollups \
                 WHERE res_ms = 900000 AND bucket_ts = ?1",
                [T0],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(
            avg,
            (3.0 * 10.0 + 50.0) / 4.0,
            "weighted by ticks, not by minutes"
        );
        assert_eq!(max, 50.0);
        assert_eq!(ws, (3.0 * 100.0 + 300.0) / 4.0);
    }

    #[test]
    fn nothing_is_deleted_before_it_is_safely_rolled_up() {
        let mut db = Database::open_in_memory().unwrap();
        instance(&db, 1, T0, false);
        for k in 0..10 {
            tick(&db, T0 + k * 60_000, &[(1, Some(1.0), 1)]);
        }
        // Raw retention of one day, and it is two days later, but nothing was ever rolled up.
        let later = T0 + 2 * DAY_MS;
        let keep = retention(1, 14, 180, 180);
        let report = db.prune(later, &keep, Limits::default()).unwrap();
        assert_eq!(report.raw_deleted + report.system_raw_deleted, 0);
        assert_eq!(count(&db, "SELECT COUNT(*) FROM resource_samples"), 10);

        // After a rollup the same prune removes them, and the history is still there as rollups.
        db.rollup_minutes(later, Limits::default()).unwrap();
        let report = db.prune(later, &keep, Limits::default()).unwrap();
        assert_eq!((report.raw_deleted, report.system_raw_deleted), (10, 10));
        assert_eq!(count(&db, "SELECT COUNT(*) FROM resource_samples"), 0);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM process_rollups WHERE res_ms = 60000"
            ),
            10
        );
    }

    #[test]
    fn old_resolved_anomalies_and_ended_instances_go_but_active_and_running_stay() {
        let mut db = Database::open_in_memory().unwrap();
        let old = T0;
        let now = T0 + 400 * DAY_MS;
        instance(&db, 1, old, true); // ended long ago
        instance(&db, 2, old, false); // never marked ended: kept
        instance(&db, 3, now - DAY_MS, true); // ended recently: kept
        for (id, resolved) in [(1, Some(old)), (2, None), (3, Some(now - DAY_MS))] {
            db.conn()
                .execute(
                    "INSERT INTO anomaly_events (id, detected_ts_ms, pid, process_name, exe_path, \
                     resource, current_value, baseline_value, deviation_pct, duration_ms, severity, \
                     baseline_window_hours, baseline_confidence, explanation, resolved_ts_ms) \
                     VALUES (?1, ?2, 1, 'p', 'x', 'cpu', 1, 1, 1, 1, 'warning', 1, 'c', 'e', ?3)",
                    params![id, if id == 3 { now - DAY_MS } else { old }, resolved],
                )
                .unwrap();
        }
        let report = db
            .prune(now, &retention(2, 14, 180, 180), Limits::default())
            .unwrap();
        assert_eq!((report.anomalies_deleted, report.instances_deleted), (1, 1));
        let ids = |sql: &str| -> Vec<i64> {
            let mut stmt = db.conn().prepare(sql).unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .map(std::result::Result::unwrap)
                .collect()
        };
        assert_eq!(ids("SELECT id FROM anomaly_events ORDER BY id"), [2, 3]);
        assert_eq!(ids("SELECT id FROM process_instances ORDER BY id"), [2, 3]);
        let fk: i64 = db
            .conn()
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign keys are switched back on");
    }

    /// Three days of a minute per tick: a busy first day (cpu 30), then two quiet ones (cpu 10),
    /// maintained with one day of raw samples kept.
    fn three_days_with_one_raw() -> (Database, i64) {
        let mut db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO executables (id, path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES (1, 'c:/x/a.exe', 'C:/x/a.exe', 'a.exe', 'valid', 't', 1, 1, 't'); \
                 INSERT INTO process_instances (id, pid, start_time, parent_pid, name, exe_path, \
                 executable_id, first_seen, last_seen) \
                 VALUES (1, 1, 1, 0, 'a.exe', 'c:/x/a.exe', 1, 't', 't');",
            )
            .unwrap();
        for minute in 0..3 * 1440i64 {
            let cpu = if minute < 1440 { 30.0 } else { 10.0 };
            tick(&db, T0 + minute * 60_000, &[(1, Some(cpu), 1000)]);
        }
        let now = T0 + 3 * DAY_MS;
        db.maintain(now, &retention(1, 14, 180, 180), Limits::unlimited())
            .unwrap();
        (db, now)
    }

    #[test]
    fn history_older_than_the_raw_samples_is_read_from_the_rollups() {
        let (db, now) = three_days_with_one_raw();
        // The raw samples now start about a day ago; rollups reach back to the start.
        assert_eq!(
            db.history_source(T0).unwrap(),
            HistorySource::Rollup(60_000)
        );
        assert_eq!(
            db.history_source(now - 3_600_000).unwrap(),
            HistorySource::Raw
        );

        let (source, first_day) = db.system_history_between(T0, T0 + DAY_MS - 1).unwrap();
        assert_eq!(source, HistorySource::Rollup(60_000));
        assert_eq!(first_day.len(), 1440);
        assert!(first_day.iter().all(|s| s.cpu_percent == Some(30.0)));
        assert_eq!(first_day[0].memory_total_bytes, Some(1000));
        assert_eq!(first_day[0].memory_available_bytes, Some(400));

        // Rankings over all three days: average (1 x 30 + 2 x 10) / 3, from the rollups.
        let r = db
            .rankings(
                crate::RankMetric::Cpu,
                crate::RankGroup::Process,
                T0,
                now,
                5,
            )
            .unwrap();
        assert_eq!(r.resolution_ms, 60_000);
        let want = (30.0 + 10.0 + 10.0) / 3.0;
        assert!(
            (r.rows[0].average - want).abs() < 0.5,
            "{}",
            r.rows[0].average
        );
        assert_eq!(r.rows[0].peak, 30.0);
        // The same call for the last hour reads raw samples.
        let recent = db
            .rankings(
                crate::RankMetric::Cpu,
                crate::RankGroup::Process,
                now - 3_600_000,
                now,
                5,
            )
            .unwrap();
        assert_eq!((recent.resolution_ms, recent.rows[0].average), (0, 10.0));

        // A subject's history comes from the rollups too, with the first day's level.
        let series = db
            .subject_series(
                winperf_core::profiler::baseline::Scope::Executable,
                1,
                T0,
                now,
                DAY_MS,
            )
            .unwrap();
        assert_eq!(series.resolution_ms, 60_000);
        assert_eq!(series.points[0].cpu, Some(30.0));
        assert_eq!(series.points[0].memory, Some(1000.0));
    }

    #[test]
    fn a_long_baseline_window_is_computed_from_the_rollups() {
        use winperf_core::profiler::baseline::{BaselineMetric, Scope};
        let (mut db, now) = three_days_with_one_raw();
        // 72 h reaches past the one day of raw samples: from rollups it sees all three days.
        db.recompute_baselines_from(now, 72, Some(60_000)).unwrap();
        let rows = db.baselines_for(Scope::Executable, 1).unwrap();
        let cpu = rows
            .iter()
            .find(|r| r.metric == BaselineMetric::Cpu)
            .unwrap();
        // The final minute is still inside its grace period, so it is not rolled up yet.
        assert_eq!(cpu.observations, 3 * 1440 - 1);
        assert_eq!(cpu.median, 10.0);
        let want = (30.0 * 1440.0 + 10.0 * (2.0 * 1440.0 - 1.0)) / (3.0 * 1440.0 - 1.0);
        assert!((cpu.mean - want).abs() < 1e-9, "{}", cpu.mean);
        assert_eq!(cpu.peak, 30.0);
        // From the raw samples alone only the last day is there.
        db.recompute_baselines(now, 72).unwrap();
        let raw = db
            .baselines_for(Scope::Executable, 1)
            .unwrap()
            .into_iter()
            .find(|r| r.metric == BaselineMetric::Cpu)
            .unwrap();
        assert!(raw.observations < 1500, "{}", raw.observations);
    }

    #[test]
    fn a_day_window_uses_the_rollups_only_once_they_are_caught_up() {
        let (db, now) = three_days_with_one_raw();
        // Caught up: a day or more reads the 1-minute rollups, an hour reads raw ticks.
        assert_eq!(db.baseline_rollup(now, 24, 2).unwrap(), Some(60_000));
        assert_eq!(db.baseline_rollup(now, 168, 2).unwrap(), Some(60_000));
        assert_eq!(db.baseline_rollup(now, 1, 2).unwrap(), None);
        // A window beyond the raw retention always needs the rollups.
        assert_eq!(db.baseline_rollup(now, 72, 2).unwrap(), Some(60_000));
        // An hour later with no maintenance pass in between the rollups are behind: raw ticks.
        assert_eq!(db.baseline_rollup(now + 3_600_000, 24, 2).unwrap(), None);
        // No rollup tables at all: raw ticks.
        let old = Database::open_in_memory().unwrap();
        old.conn()
            .execute_batch("DROP TABLE system_rollups; DROP TABLE process_rollups;")
            .unwrap();
        assert_eq!(old.baseline_rollup(now, 24, 2).unwrap(), None);
    }

    #[test]
    fn a_database_without_rollup_tables_is_read_as_raw() {
        let db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch("DROP TABLE system_rollups; DROP TABLE process_rollups;")
            .unwrap();
        assert_eq!(db.history_source(0).unwrap(), HistorySource::Raw);
    }

    /// Ten days of one tick a minute for 10 processes (with some process churn), maintained every
    /// hour with retention of 1 day raw, 2 days of 1-minute rows and 4 days of 15-minute rows.
    /// The row counts and the database size must level off, not grow with time.
    #[test]
    fn the_database_stops_growing_once_retention_is_reached() {
        let mut db = Database::open_in_memory().unwrap();
        let policy = retention(1, 2, 4, 3);
        let mut next_instance = 100;
        for id in 1..=10 {
            instance(&db, id, T0 + 20 * DAY_MS, false); // long-running, never ended
        }
        let mut sizes = Vec::new();
        let mut raw_rows = Vec::new();
        for day in 0..10i64 {
            // Today's short-lived processes: three start and end during the day.
            let churn: Vec<i64> = (0..3)
                .map(|_| {
                    next_instance += 1;
                    instance(&db, next_instance, T0 + day * DAY_MS + DAY_MS / 2, true);
                    next_instance
                })
                .collect();
            for hour in 0..24i64 {
                let base = T0 + day * DAY_MS + hour * 3_600_000;
                for minute in 0..60i64 {
                    let ts = base + minute * 60_000;
                    let mut rows: Vec<(i64, Option<f64>, i64)> = (1..=10)
                        .map(|i| (i, Some((i + minute) as f64), 1000 * i))
                        .collect();
                    if hour < 12 {
                        rows.extend(churn.iter().map(|&c| (c, Some(2.0), 500)));
                    }
                    tick(&db, ts, &rows);
                }
                db.maintain(base + 3_600_000, &policy, Limits::unlimited())
                    .unwrap();
            }
            sizes.push(count(&db, "PRAGMA page_count"));
            raw_rows.push(count(&db, "SELECT COUNT(*) FROM resource_samples"));
        }
        // Raw rows are bounded by the retention plus the hour not yet rolled up, whatever the day.
        let steady = raw_rows[3];
        assert!(
            raw_rows[3..].iter().all(|&r| r <= steady + 600),
            "raw rows keep growing: {raw_rows:?}"
        );
        let per_day = 1440 * 10 + 1440 * 3 / 2;
        assert!(
            steady <= per_day * 2,
            "{steady} raw rows is more than about a day and a half"
        );
        // The file size levels off: the last days are not bigger than the day retention filled up.
        assert!(
            sizes[9] <= sizes[6] + sizes[6] / 20,
            "page count keeps growing: {sizes:?}"
        );
        // Each tier holds about its own retention and no more.
        let minute_rows = count(
            &db,
            "SELECT COUNT(*) FROM process_rollups WHERE res_ms = 60000",
        );
        let quarter_rows = count(
            &db,
            "SELECT COUNT(*) FROM process_rollups WHERE res_ms = 900000",
        );
        assert!(minute_rows <= 3 * 1440 * 13, "{minute_rows}");
        assert!(quarter_rows <= 5 * 96 * 13, "{quarter_rows}");
        // Only the ongoing instances and the last days' churn are left.
        let instances = count(&db, "SELECT COUNT(*) FROM process_instances");
        assert!(instances <= 10 + 3 * 5, "{instances} instances kept");
        // History older than the raw retention is still answerable from rollups.
        let oldest_quarter = count(
            &db,
            "SELECT MIN(bucket_ts) FROM system_rollups WHERE res_ms = 900000",
        );
        assert!(oldest_quarter <= T0 + 9 * DAY_MS - 3 * DAY_MS);
    }
}
