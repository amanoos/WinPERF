//! Process-instance lifecycle and executable linking: small SQL helpers used by the sink inside
//! its own transactions (they take a plain `&Connection`).

use crate::db::Database;
use crate::error::Result;
use crate::repo::inventory::FileIdentity;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

impl Database {
    /// Record that an instance was still running at `now`.
    pub(crate) fn touch_instance(conn: &Connection, id: i64, now: &str) -> Result<()> {
        conn.prepare_cached("UPDATE process_instances SET last_seen = ?2 WHERE id = ?1")?
            .execute(params![id, now])?;
        Ok(())
    }

    /// Mark an instance as ended (first end wins; an already-ended instance is left alone).
    pub(crate) fn end_instance(conn: &Connection, id: i64, now: &str) -> Result<()> {
        conn.prepare_cached(
            "UPDATE process_instances SET end_time = ?2 WHERE id = ?1 AND end_time IS NULL",
        )?
        .execute(params![id, now])?;
        Ok(())
    }

    /// Close instances still marked running whose last sighting is older than `now`: leftovers
    /// from an earlier run that ended while nothing was watching. Call it once per start, after
    /// the processes that are running now have been refreshed to `now`.
    pub(crate) fn close_stale_instances(conn: &Connection, now: &str) -> Result<usize> {
        Ok(conn.execute(
            "UPDATE process_instances SET end_time = ?1 \
             WHERE end_time IS NULL AND last_seen < ?1",
            [now],
        )?)
    }

    /// Attach a classified executable to a process instance.
    pub(crate) fn link_instance_executable(
        conn: &Connection,
        instance_id: i64,
        executable_id: i64,
    ) -> Result<()> {
        conn.prepare_cached("UPDATE process_instances SET executable_id = ?2 WHERE id = ?1")?
            .execute(params![instance_id, executable_id])?;
        Ok(())
    }

    /// The executable row for `path`, only if it still describes the file on disk (same size and
    /// modification time). This is the persistent signature cache lookup.
    pub(crate) fn executable_id_if_current(
        conn: &Connection,
        path: &Path,
        identity: FileIdentity,
    ) -> Result<Option<i64>> {
        Ok(conn
            .query_row(
                "SELECT id FROM executables \
                 WHERE path_key = ?1 AND file_size = ?2 AND file_mtime_ns = ?3",
                params![
                    path.to_string_lossy().to_lowercase(),
                    identity.size as i64,
                    identity.mtime_ns
                ],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// How many instances are currently believed to be running.
    pub fn running_instance_count(&self) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT COUNT(*) FROM process_instances WHERE end_time IS NULL",
            [],
            |r| r.get(0),
        )?)
    }
}
