//! Resource-sample and system-sample persistence.

use crate::db::Database;
use crate::error::Result;
use rusqlite::{Connection, params};
use winperf_core::Metric;
use winperf_core::sampling::Sample;
use winperf_core::system::SystemSample;

/// One stored process sample, as read back.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSample {
    pub ts_ms: i64,
    pub cpu_percent: Option<f64>,
    pub working_set_bytes: Option<u64>,
    pub private_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub peak_working_set_bytes: Option<u64>,
    /// Process I/O rates (all I/O kinds, not just physical disk).
    pub io_read_bytes_per_sec: Option<f64>,
    pub io_write_bytes_per_sec: Option<f64>,
    pub io_read_ops_per_sec: Option<f64>,
    pub io_write_ops_per_sec: Option<f64>,
    /// Per-process network throughput (ETW attribution; NULL when not measured).
    pub net_rx_bytes_per_sec: Option<f64>,
    pub net_tx_bytes_per_sec: Option<f64>,
}

/// One stored system-wide sample, as read back.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSystemSample {
    pub ts_ms: i64,
    pub cpu_percent: Option<f64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub commit_used_bytes: Option<u64>,
    pub commit_limit_bytes: Option<u64>,
    pub disk_utilization_percent: Option<f64>,
    pub disk_queue_length: Option<f64>,
    pub disk_read_bytes_per_sec: Option<f64>,
    pub disk_write_bytes_per_sec: Option<f64>,
    pub disk_latency_ms: Option<f64>,
    pub net_rx_bytes_per_sec: Option<f64>,
    pub net_tx_bytes_per_sec: Option<f64>,
}

/// The stored value of a metric: its value whether complete or partial, NULL when unavailable.
fn float(m: &Metric<f64>) -> Option<f64> {
    m.value().copied()
}

fn int(m: &Metric<u64>) -> Option<i64> {
    m.value().map(|v| *v as i64)
}

/// Insert one row per `(instance id, sample)`. Takes a plain `&Connection` so the caller controls
/// the transaction. Unavailable metrics are stored as NULL.
pub(crate) fn insert_sample_rows(
    conn: &Connection,
    ts_ms: i64,
    rows: &[(i64, &Sample)],
) -> Result<usize> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO resource_samples \
         (process_instance_id, ts_ms, cpu_percent, working_set_bytes, private_bytes, \
          virtual_bytes, peak_working_set_bytes, io_read_bytes_per_sec, io_write_bytes_per_sec, \
          io_read_ops_per_sec, io_write_ops_per_sec, net_rx_bytes_per_sec, net_tx_bytes_per_sec) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )?;
    for (instance_id, s) in rows {
        stmt.execute(params![
            instance_id,
            ts_ms,
            float(&s.cpu_percent),
            int(&s.working_set),
            int(&s.private_bytes),
            int(&s.virtual_bytes),
            int(&s.peak_working_set),
            float(&s.io_read_bytes_per_sec),
            float(&s.io_write_bytes_per_sec),
            float(&s.io_read_ops_per_sec),
            float(&s.io_write_ops_per_sec),
            float(&s.net_rx_bytes_per_sec),
            float(&s.net_tx_bytes_per_sec),
        ])?;
    }
    Ok(rows.len())
}

/// Insert one system-wide sample row.
pub(crate) fn insert_system_sample(conn: &Connection, ts_ms: i64, s: &SystemSample) -> Result<()> {
    conn.prepare_cached(
        "INSERT INTO system_samples \
         (ts_ms, cpu_percent, memory_total_bytes, memory_available_bytes, commit_used_bytes, \
          commit_limit_bytes, disk_utilization_percent, disk_queue_length, \
          disk_read_bytes_per_sec, disk_write_bytes_per_sec, disk_latency_ms, \
          net_rx_bytes_per_sec, net_tx_bytes_per_sec) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
    )?
    .execute(params![
        ts_ms,
        float(&s.cpu_percent),
        int(&s.memory_total_bytes),
        int(&s.memory_available_bytes),
        int(&s.commit_used_bytes),
        int(&s.commit_limit_bytes),
        float(&s.disk_utilization_percent),
        float(&s.disk_queue_length),
        float(&s.disk_read_bytes_per_sec),
        float(&s.disk_write_bytes_per_sec),
        float(&s.disk_latency_ms),
        float(&s.net_rx_bytes_per_sec),
        float(&s.net_tx_bytes_per_sec),
    ])?;
    Ok(())
}

impl Database {
    /// Insert a batch of samples in a single transaction.
    pub fn insert_samples(&mut self, ts_ms: i64, rows: &[(i64, &Sample)]) -> Result<usize> {
        let tx = self.conn_mut().transaction()?;
        let n = insert_sample_rows(&tx, ts_ms, rows)?;
        tx.commit()?;
        Ok(n)
    }

    pub fn sample_count(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT COUNT(*) FROM resource_samples", [], |r| r.get(0))?)
    }

    pub fn system_sample_count(&self) -> Result<i64> {
        Ok(self
            .conn()
            .query_row("SELECT COUNT(*) FROM system_samples", [], |r| r.get(0))?)
    }

    /// All samples of one process instance, oldest first.
    ///
    /// Since schema v5 the samples index is time-first, so this reads the whole samples table
    /// and filters (fine for tests and small databases). A caller that has a time range, such as
    /// a chart or the report, needs a windowed variant that uses the `ts_ms` index.
    pub fn samples_for_instance(&self, instance_id: i64) -> Result<Vec<StoredSample>> {
        let mut stmt = self.conn().prepare(
            "SELECT ts_ms, cpu_percent, working_set_bytes, private_bytes, virtual_bytes, \
             peak_working_set_bytes, io_read_bytes_per_sec, io_write_bytes_per_sec, \
             io_read_ops_per_sec, io_write_ops_per_sec, net_rx_bytes_per_sec, \
             net_tx_bytes_per_sec FROM resource_samples \
             WHERE process_instance_id = ?1 ORDER BY ts_ms, id",
        )?;
        let big = |v: Option<i64>| v.map(|x| x as u64);
        let rows = stmt.query_map([instance_id], |r| {
            Ok(StoredSample {
                ts_ms: r.get(0)?,
                cpu_percent: r.get(1)?,
                working_set_bytes: big(r.get(2)?),
                private_bytes: big(r.get(3)?),
                virtual_bytes: big(r.get(4)?),
                peak_working_set_bytes: big(r.get(5)?),
                io_read_bytes_per_sec: r.get(6)?,
                io_write_bytes_per_sec: r.get(7)?,
                io_read_ops_per_sec: r.get(8)?,
                io_write_ops_per_sec: r.get(9)?,
                net_rx_bytes_per_sec: r.get(10)?,
                net_tx_bytes_per_sec: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// One instance's samples with `from_ms <= ts_ms <= to_ms`, oldest first. Uses the time
    /// index, so keep the window short (hours, not days) on a busy database.
    pub fn instance_samples_between(
        &self,
        instance_id: i64,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<StoredSample>> {
        let mut stmt = self.conn().prepare(
            "SELECT ts_ms, cpu_percent, working_set_bytes, private_bytes, virtual_bytes, \
             peak_working_set_bytes, io_read_bytes_per_sec, io_write_bytes_per_sec, \
             io_read_ops_per_sec, io_write_ops_per_sec, net_rx_bytes_per_sec, \
             net_tx_bytes_per_sec FROM resource_samples \
             WHERE ts_ms BETWEEN ?2 AND ?3 AND process_instance_id = ?1 ORDER BY ts_ms, id",
        )?;
        let big = |v: Option<i64>| v.map(|x| x as u64);
        let rows = stmt.query_map(rusqlite::params![instance_id, from_ms, to_ms], |r| {
            Ok(StoredSample {
                ts_ms: r.get(0)?,
                cpu_percent: r.get(1)?,
                working_set_bytes: big(r.get(2)?),
                private_bytes: big(r.get(3)?),
                virtual_bytes: big(r.get(4)?),
                peak_working_set_bytes: big(r.get(5)?),
                io_read_bytes_per_sec: r.get(6)?,
                io_write_bytes_per_sec: r.get(7)?,
                io_read_ops_per_sec: r.get(8)?,
                io_write_ops_per_sec: r.get(9)?,
                net_rx_bytes_per_sec: r.get(10)?,
                net_tx_bytes_per_sec: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// All system-wide samples, oldest first.
    pub fn system_samples(&self) -> Result<Vec<StoredSystemSample>> {
        self.system_samples_between(i64::MIN, i64::MAX)
    }

    /// System-wide samples with `from_ms <= ts_ms <= to_ms`, oldest first.
    pub fn system_samples_between(
        &self,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<StoredSystemSample>> {
        let mut out = Vec::new();
        self.system_samples_each(from_ms, to_ms, |s| {
            out.push(s);
            true
        })?;
        Ok(out)
    }

    /// Hand each system sample of the range to `each`, oldest first, without holding them all in
    /// memory. `each` returns false to stop early (a closed download, say).
    pub fn system_samples_each(
        &self,
        from_ms: i64,
        to_ms: i64,
        mut each: impl FnMut(StoredSystemSample) -> bool,
    ) -> Result<()> {
        let mut stmt = self.conn().prepare(
            "SELECT ts_ms, cpu_percent, memory_total_bytes, memory_available_bytes, \
             commit_used_bytes, commit_limit_bytes, disk_utilization_percent, disk_queue_length, \
             disk_read_bytes_per_sec, disk_write_bytes_per_sec, disk_latency_ms, \
             net_rx_bytes_per_sec, net_tx_bytes_per_sec FROM system_samples \
             WHERE ts_ms BETWEEN ?1 AND ?2 ORDER BY ts_ms, id",
        )?;
        let big = |v: Option<i64>| v.map(|x| x as u64);
        let mut rows = stmt.query([from_ms, to_ms])?;
        while let Some(r) = rows.next()? {
            let sample = StoredSystemSample {
                ts_ms: r.get(0)?,
                cpu_percent: r.get(1)?,
                memory_total_bytes: big(r.get(2)?),
                memory_available_bytes: big(r.get(3)?),
                commit_used_bytes: big(r.get(4)?),
                commit_limit_bytes: big(r.get(5)?),
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
        Ok(())
    }
}

/// One process's reading at the newest tick.
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentProcess {
    pub pid: u32,
    pub name: String,
    pub application: Option<String>,
    pub cpu_percent: Option<f64>,
    pub working_set_bytes: Option<u64>,
    pub private_bytes: Option<u64>,
    pub io_read_bytes_per_sec: Option<f64>,
    pub io_write_bytes_per_sec: Option<f64>,
    pub net_rx_bytes_per_sec: Option<f64>,
    pub net_tx_bytes_per_sec: Option<f64>,
}

/// How continuous the recording has been over a period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleHealth {
    /// System samples in the period.
    pub samples: i64,
    /// Time of the first and last of them.
    pub first_ts_ms: Option<i64>,
    pub last_ts_ms: Option<i64>,
    /// Interruptions: places where consecutive samples are further apart than the allowed gap.
    pub gaps: i64,
    /// The longest such interruption in milliseconds (0 when there were none).
    pub longest_gap_ms: i64,
}

impl Database {
    /// The processes of the newest tick (when any were recorded), busiest CPU first, at most
    /// `limit`. Returns the tick's time with them.
    pub fn current_processes(&self, limit: u32) -> Result<(Option<i64>, Vec<CurrentProcess>)> {
        let ts: Option<i64> =
            self.conn()
                .query_row("SELECT MAX(ts_ms) FROM resource_samples", [], |r| r.get(0))?;
        let Some(ts) = ts else {
            return Ok((None, Vec::new()));
        };
        let mut stmt = self.conn().prepare(
            "SELECT pi.pid, pi.name, ia.name, rs.cpu_percent, rs.working_set_bytes, \
                    rs.private_bytes, rs.io_read_bytes_per_sec, rs.io_write_bytes_per_sec, \
                    rs.net_rx_bytes_per_sec, rs.net_tx_bytes_per_sec \
             FROM resource_samples rs \
             JOIN process_instances pi ON pi.id = rs.process_instance_id \
             LEFT JOIN installed_applications ia ON ia.id = pi.application_id \
             WHERE rs.ts_ms = ?1 \
             ORDER BY rs.cpu_percent IS NULL, rs.cpu_percent DESC, rs.working_set_bytes DESC \
             LIMIT ?2",
        )?;
        let big = |v: Option<i64>| v.map(|x| x as u64);
        let rows = stmt.query_map(params![ts, limit], |r| {
            Ok(CurrentProcess {
                pid: r.get(0)?,
                name: r.get(1)?,
                application: r.get(2)?,
                cpu_percent: r.get(3)?,
                working_set_bytes: big(r.get(4)?),
                private_bytes: big(r.get(5)?),
                io_read_bytes_per_sec: r.get(6)?,
                io_write_bytes_per_sec: r.get(7)?,
                net_rx_bytes_per_sec: r.get(8)?,
                net_tx_bytes_per_sec: r.get(9)?,
            })
        })?;
        Ok((Some(ts), rows.collect::<std::result::Result<Vec<_>, _>>()?))
    }

    /// Continuity of the system samples since `since_ms`: how many, and how many gaps longer than
    /// `gap_ms` (the monitor was stopped, the machine slept, or sampling failed).
    pub fn sample_health(&self, since_ms: i64, gap_ms: i64) -> Result<SampleHealth> {
        let (samples, first, last, gaps, longest): (i64, Option<i64>, Option<i64>, i64, i64) =
            self.conn().query_row(
                "SELECT COUNT(*), MIN(ts_ms), MAX(ts_ms), \
                    COALESCE(SUM(d > ?2), 0), \
                    COALESCE(MAX(CASE WHEN d > ?2 THEN d END), 0) \
             FROM (SELECT ts_ms, ts_ms - LAG(ts_ms) OVER (ORDER BY ts_ms) AS d \
                   FROM system_samples WHERE ts_ms >= ?1)",
                params![since_ms, gap_ms],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        Ok(SampleHealth {
            samples,
            first_ts_ms: first,
            last_ts_ms: last,
            gaps,
            longest_gap_ms: longest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaps_between_samples_are_counted_and_the_longest_reported() {
        let db = Database::open_in_memory().unwrap();
        // 5 s apart, then a 60 s hole, then 5 s apart, then a 20 s hole.
        for ts in [0, 5_000, 10_000, 70_000, 75_000, 95_000] {
            db.conn()
                .execute(
                    "INSERT INTO system_samples (ts_ms) VALUES (?1)",
                    params![ts],
                )
                .unwrap();
        }
        let h = db.sample_health(0, 15_000).unwrap();
        assert_eq!(
            h,
            SampleHealth {
                samples: 6,
                first_ts_ms: Some(0),
                last_ts_ms: Some(95_000),
                gaps: 2,
                longest_gap_ms: 60_000
            }
        );
        // Only the later samples count when the period starts later.
        let later = db.sample_health(70_000, 15_000).unwrap();
        assert_eq!(
            (later.samples, later.gaps, later.longest_gap_ms),
            (3, 1, 20_000)
        );
        let none = db.sample_health(1_000_000, 15_000).unwrap();
        assert_eq!((none.samples, none.gaps), (0, 0));
    }

    #[test]
    fn system_samples_can_be_read_for_a_time_range() {
        let db = Database::open_in_memory().unwrap();
        for ts in [1_000, 2_000, 3_000, 4_000] {
            db.conn()
                .execute(
                    "INSERT INTO system_samples (ts_ms, cpu_percent) VALUES (?1, ?2)",
                    rusqlite::params![ts, ts as f64 / 100.0],
                )
                .unwrap();
        }
        let ts = |rows: Vec<StoredSystemSample>| rows.iter().map(|r| r.ts_ms).collect::<Vec<_>>();
        assert_eq!(
            ts(db.system_samples_between(2_000, 3_000).unwrap()),
            vec![2_000, 3_000]
        );
        assert_eq!(
            ts(db.system_samples_between(5_000, 9_000).unwrap()),
            Vec::<i64>::new()
        );
        assert_eq!(db.system_samples().unwrap().len(), 4);
    }
}
