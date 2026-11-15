//! Forward-only schema migrations. The schema version lives in `PRAGMA user_version` and equals
//! the number of migrations applied. Each migration runs in its own transaction, so a failure
//! leaves the database at the previous version.

use crate::error::{Result, StorageError};
use rusqlite::Connection;

/// Ordered `(name, sql)` pairs. Never edit or reorder an applied migration; append a new one.
pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_initial",
        include_str!("../migrations/0001_initial.sql"),
    ),
    (
        "0002_resource_samples",
        include_str!("../migrations/0002_resource_samples.sql"),
    ),
    (
        "0003_system_samples",
        include_str!("../migrations/0003_system_samples.sql"),
    ),
    (
        "0004_process_network",
        include_str!("../migrations/0004_process_network.sql"),
    ),
    (
        "0005_samples_time_index",
        include_str!("../migrations/0005_samples_time_index.sql"),
    ),
    (
        "0006_baseline_profiles",
        include_str!("../migrations/0006_baseline_profiles.sql"),
    ),
    (
        "0007_profile_state",
        include_str!("../migrations/0007_profile_state.sql"),
    ),
];

/// Highest schema version this build understands.
pub fn latest_version() -> u32 {
    MIGRATIONS.len() as u32
}

pub fn current_version(conn: &Connection) -> Result<u32> {
    Ok(conn.pragma_query_value(None, "user_version", |r| r.get(0))?)
}

/// Bring the database up to date. Idempotent. Refuses a database from a newer build.
pub fn migrate(conn: &mut Connection) -> Result<u32> {
    let current = current_version(conn)?;
    if current > latest_version() {
        return Err(StorageError::SchemaTooNew {
            found: current,
            supported: latest_version(),
        });
    }
    for (index, (_name, sql)) in MIGRATIONS.iter().enumerate().skip(current as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (index + 1) as u32)?;
        tx.commit()?;
    }
    Ok(latest_version())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_indexes(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'index' \
                 AND tbl_name = 'resource_samples' AND name LIKE 'ix_%' ORDER BY name",
            )
            .unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn upgrading_from_v4_keeps_samples_and_swaps_the_indexes() {
        let mut conn = Connection::open_in_memory().unwrap();
        // The test inserts bare sample rows; their instances don't exist.
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        for (i, (_name, sql)) in MIGRATIONS.iter().take(4).enumerate() {
            conn.execute_batch(sql).unwrap();
            conn.pragma_update(None, "user_version", (i + 1) as u32)
                .unwrap();
        }
        assert_eq!(
            sample_indexes(&conn),
            ["ix_resource_samples_instance_ts", "ix_resource_samples_ts"]
        );
        conn.execute(
            "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent) \
             VALUES (1, 1000, 2.5), (2, 1000, NULL)",
            [],
        )
        .unwrap();

        assert_eq!(migrate(&mut conn).unwrap(), latest_version());

        assert_eq!(sample_indexes(&conn), ["ix_resource_samples_ts_instance"]);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM resource_samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 2);
        let unmeasured: Option<f64> = conn
            .query_row(
                "SELECT cpu_percent FROM resource_samples WHERE process_instance_id = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unmeasured, None, "NULL (not measured) must stay NULL");
    }

    #[test]
    fn a_time_window_query_is_served_by_the_time_index() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        let mut stmt = conn
            .prepare(
                "EXPLAIN QUERY PLAN SELECT process_instance_id FROM resource_samples \
                 WHERE ts_ms BETWEEN 1 AND 2",
            )
            .unwrap();
        let plan: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            plan.iter()
                .any(|p| p.contains("ix_resource_samples_ts_instance")),
            "{plan:?}"
        );
    }
}
