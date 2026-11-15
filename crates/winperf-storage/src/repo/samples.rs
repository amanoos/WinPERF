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
        let mut stmt = self.conn().prepare(
            "SELECT ts_ms, cpu_percent, memory_total_bytes, memory_available_bytes, \
             commit_used_bytes, commit_limit_bytes, disk_utilization_percent, disk_queue_length, \
             disk_read_bytes_per_sec, disk_write_bytes_per_sec, disk_latency_ms, \
             net_rx_bytes_per_sec, net_tx_bytes_per_sec FROM system_samples \
             WHERE ts_ms BETWEEN ?1 AND ?2 ORDER BY ts_ms, id",
        )?;
        let big = |v: Option<i64>| v.map(|x| x as u64);
        let rows = stmt.query_map([from_ms, to_ms], |r| {
            Ok(StoredSystemSample {
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
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
