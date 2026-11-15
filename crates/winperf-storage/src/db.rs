//! Opening and configuring the SQLite database.
//!
//! One writer (the monitoring engine) and many readers (TUI, report service): WAL mode lets
//! readers proceed while a write transaction is open (A3).

use crate::error::Result;
use crate::migrations::{self, current_version};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::time::Duration;

/// How long a connection waits for a lock held by another connection before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Database {
    conn: Connection,
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

impl Database {
    /// Open (creating directories and the file if needed), enable WAL, and migrate to the latest schema.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let mut conn = Connection::open(path)?;
        configure(&conn)?;
        // Switching journal mode returns the resulting mode as a row.
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0))?;
        // NORMAL is safe with WAL (no corruption; at worst the last commit is lost on power failure).
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        migrations::migrate(&mut conn)?;
        Ok(Self { conn })
    }

    /// Open an existing database read-only (for readers that must never write). Does not migrate,
    /// but refuses a database from a newer build.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        configure(&conn)?;
        let found = current_version(&conn)?;
        if found > migrations::latest_version() {
            return Err(crate::error::StorageError::SchemaTooNew {
                found,
                supported: migrations::latest_version(),
            });
        }
        Ok(Self { conn })
    }

    /// A private in-memory database (tests, dry runs).
    pub fn open_in_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        configure(&conn)?;
        migrations::migrate(&mut conn)?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn schema_version(&self) -> Result<u32> {
        current_version(&self.conn)
    }

    pub fn journal_mode(&self) -> Result<String> {
        Ok(self
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StorageError;
    use crate::testutil::TempDir;

    const TABLES: [&str; 5] = [
        "installed_applications",
        "executables",
        "process_instances",
        "resource_samples",
        "system_samples",
    ];

    fn table_exists(db: &Database, name: &str) -> bool {
        db.conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
            == 1
    }

    /// T35: command lines can hold passwords and tokens, so no table may keep them. If a column that
    /// looks like one is ever added, this fails and the change has to be a deliberate, redacted,
    /// opt-in one (see `winperf_core::redact`).
    #[test]
    fn no_table_stores_command_lines() {
        let db = Database::open_in_memory().unwrap();
        let tables: Vec<String> = {
            let mut stmt = db
                .conn()
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .map(|row| row.unwrap())
                .collect()
        };
        assert!(tables.len() > 10);
        for table in tables {
            let mut stmt = db
                .conn()
                .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .unwrap();
            for column in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
                let column = column.unwrap().to_lowercase();
                // The one deliberate exception: the registry's uninstall command, which the
                // inventory stores with its secrets redacted (see `save_installed_apps`).
                if (table.as_str(), column.as_str())
                    == ("installed_applications", "uninstall_command")
                {
                    continue;
                }
                assert!(
                    !["command", "cmdline", "cmd_line", "arguments", "argv"]
                        .iter()
                        .any(|bad| column.contains(bad)),
                    "{table}.{column} looks like a command line column"
                );
            }
        }
    }

    #[test]
    fn open_creates_schema_at_latest_version() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.schema_version().unwrap(), migrations::latest_version());
        for t in TABLES {
            assert!(table_exists(&db, t), "{t}");
        }
    }

    #[test]
    fn file_database_uses_wal_and_creates_missing_directories() {
        let dir = TempDir::new("wal");
        let path = dir.path().join("nested").join("deeper").join("w.db");
        let db = Database::open(&path).unwrap();
        assert_eq!(db.journal_mode().unwrap(), "wal");
        assert!(path.exists());
    }

    #[test]
    fn migrating_twice_is_idempotent_and_keeps_data() {
        let dir = TempDir::new("idem");
        let path = dir.path().join("i.db");
        {
            let db = Database::open(&path).unwrap();
            db.conn()
                .execute(
                    "INSERT INTO executables (path_key, file_path, file_name, signature_status, \
                     classification, file_size, file_mtime_ns, verified_at) \
                     VALUES ('p','P','p','valid','microsoft',1,1,'t')",
                    [],
                )
                .unwrap();
        }
        let mut conn = Connection::open(&path).unwrap();
        assert_eq!(
            migrations::migrate(&mut conn).unwrap(),
            migrations::latest_version()
        );
        assert_eq!(
            migrations::migrate(&mut conn).unwrap(),
            migrations::latest_version()
        );
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM executables", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn reopening_preserves_data() {
        let dir = TempDir::new("reopen");
        let path = dir.path().join("r.db");
        {
            let db = Database::open(&path).unwrap();
            db.conn()
                .execute(
                    "INSERT INTO process_instances (pid, start_time, parent_pid, name, first_seen, last_seen) \
                     VALUES (7, 99, 1, 'a.exe', 't', 't')",
                    [],
                )
                .unwrap();
        }
        let db = Database::open(&path).unwrap();
        let name: String = db
            .conn()
            .query_row(
                "SELECT name FROM process_instances WHERE pid = 7",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(name, "a.exe");
    }

    #[test]
    fn a_database_from_a_newer_build_is_refused() {
        let dir = TempDir::new("newer");
        let path = dir.path().join("n.db");
        Database::open(&path).unwrap();
        Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 99u32)
            .unwrap();
        assert!(matches!(
            Database::open(&path),
            Err(StorageError::SchemaTooNew {
                found: 99,
                supported: _
            })
        ));
        assert!(matches!(
            Database::open_read_only(&path),
            Err(StorageError::SchemaTooNew { .. })
        ));
    }

    #[test]
    fn a_reader_is_not_blocked_by_an_open_write_transaction() {
        let dir = TempDir::new("concurrent");
        let path = dir.path().join("c.db");
        let writer = Database::open(&path).unwrap();
        let reader = Database::open_read_only(&path).unwrap();
        let count = |d: &Database| -> i64 {
            d.conn()
                .query_row("SELECT COUNT(*) FROM executables", [], |r| r.get(0))
                .unwrap()
        };

        writer.conn().execute_batch("BEGIN IMMEDIATE").unwrap();
        writer
            .conn()
            .execute(
                "INSERT INTO executables (path_key, file_path, file_name, signature_status, \
                 classification, file_size, file_mtime_ns, verified_at) \
                 VALUES ('p','P','p','valid','microsoft',1,1,'t')",
                [],
            )
            .unwrap();
        assert_eq!(count(&reader), 0, "reader sees the last committed snapshot");

        writer.conn().execute_batch("COMMIT").unwrap();
        assert_eq!(count(&reader), 1, "reader sees the commit");
    }

    #[test]
    fn read_only_connections_cannot_write() {
        let dir = TempDir::new("ro");
        let path = dir.path().join("ro.db");
        Database::open(&path).unwrap();
        let ro = Database::open_read_only(&path).unwrap();
        assert!(ro.conn().execute("DELETE FROM executables", []).is_err());
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let db = Database::open_in_memory().unwrap();
        let bad = db.conn().execute(
            "INSERT INTO process_instances (pid, start_time, parent_pid, name, executable_id, first_seen, last_seen) \
             VALUES (1, 1, 0, 'x', 12345, 't', 't')",
            [],
        );
        assert!(bad.is_err(), "dangling executable_id must be rejected");
    }
}
