//! Inventory persistence: installed applications, executables (+ signature cache), and process
//! instances.

use crate::db::Database;
use crate::error::{Result, StorageError};
use rusqlite::{OptionalExtension, Row, params};
use std::path::{Path, PathBuf};
use winperf_core::Classification;
use winperf_core::inventory::{
    ExecutableInfo, FileVersionInfo, InstalledApp, ProcessInfo, SignatureStatus, classify,
};

/// What identifies a file's content cheaply: if either changes, a cached signature is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub size: u64,
    pub mtime_ns: i64,
}

impl FileIdentity {
    /// Read from the filesystem; `None` if the file can't be stat'ed.
    pub fn of(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        let mtime = meta.modified().ok()?;
        let ns = mtime
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_nanos()).ok())?;
        Some(Self {
            size: meta.len(),
            mtime_ns: ns,
        })
    }
}

fn app_key(a: &InstalledApp) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        a.name.to_lowercase(),
        a.version.as_deref().unwrap_or(""),
        a.publisher.as_deref().unwrap_or("").to_lowercase()
    )
}

fn parse_classification(s: &str) -> Result<Classification> {
    Classification::parse(s)
        .ok_or_else(|| StorageError::Corrupt(format!("unknown classification {s:?}")))
}

fn signature_columns(s: &SignatureStatus) -> (&'static str, Option<&str>, Option<i64>) {
    match s {
        SignatureStatus::Valid { signer } => ("valid", Some(signer.as_str()), None),
        SignatureStatus::NotSigned => ("not_signed", None, None),
        SignatureStatus::Invalid { code } => ("invalid", None, Some(i64::from(*code))),
        SignatureStatus::Unreadable => ("unreadable", None, None),
    }
}

fn signature_from_columns(
    status: &str,
    signer: Option<String>,
    code: Option<i64>,
) -> Result<SignatureStatus> {
    Ok(match status {
        "valid" => SignatureStatus::Valid {
            signer: signer.unwrap_or_default(),
        },
        "not_signed" => SignatureStatus::NotSigned,
        "invalid" => SignatureStatus::Invalid {
            code: code.and_then(|c| u32::try_from(c).ok()).unwrap_or(0),
        },
        "unreadable" => SignatureStatus::Unreadable,
        other => {
            return Err(StorageError::Corrupt(format!(
                "unknown signature status {other:?}"
            )));
        }
    })
}

fn app_from_row(row: &Row<'_>) -> Result<InstalledApp> {
    let classification: String = row.get("classification")?;
    let sources: String = row.get("registry_sources")?;
    Ok(InstalledApp {
        name: row.get("name")?,
        publisher: row.get("publisher")?,
        version: row.get("version")?,
        install_date: row.get("install_date")?,
        install_location: row.get("install_location")?,
        uninstall_command: row.get("uninstall_command")?,
        registry_sources: sources
            .split(';')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        classification: parse_classification(&classification)?,
    })
}

impl Database {
    /// Replace the installed-application snapshot with `apps`, atomically. Products seen again keep
    /// their row (and id) and `first_seen`; products no longer present are removed (and processes
    /// that referenced them are detached, not deleted). Returns the number of applications saved.
    pub fn save_installed_apps(&mut self, apps: &[InstalledApp], now: &str) -> Result<usize> {
        let tx = self.conn_mut().transaction()?;
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(scan_seq), 0) + 1 FROM installed_applications",
            [],
            |r| r.get(0),
        )?;
        {
            let mut upsert = tx.prepare_cached(
                "INSERT INTO installed_applications \
                 (app_key, name, publisher, version, install_date, install_location, \
                  uninstall_command, registry_sources, classification, first_seen, last_seen, scan_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11) \
                 ON CONFLICT(app_key) DO UPDATE SET \
                   name = excluded.name, publisher = excluded.publisher, version = excluded.version, \
                   install_date = excluded.install_date, install_location = excluded.install_location, \
                   uninstall_command = excluded.uninstall_command, \
                   registry_sources = excluded.registry_sources, \
                   classification = excluded.classification, \
                   last_seen = excluded.last_seen, scan_seq = excluded.scan_seq",
            )?;
            for a in apps {
                upsert.execute(params![
                    app_key(a),
                    a.name,
                    a.publisher,
                    a.version,
                    a.install_date,
                    a.install_location,
                    a.uninstall_command,
                    a.registry_sources.join(";"),
                    a.classification.as_str(),
                    now,
                    seq,
                ])?;
            }
        }
        tx.execute(
            "DELETE FROM installed_applications WHERE scan_seq <> ?1",
            [seq],
        )?;
        let saved: i64 = tx.query_row("SELECT COUNT(*) FROM installed_applications", [], |r| {
            r.get(0)
        })?;
        tx.commit()?;
        Ok(saved as usize)
    }

    /// The stored application snapshot, ordered like `discover` (name, then version).
    pub fn load_installed_apps(&self) -> Result<Vec<InstalledApp>> {
        let mut stmt = self.conn().prepare(
            "SELECT name, publisher, version, install_date, install_location, uninstall_command, \
             registry_sources, classification FROM installed_applications",
        )?;
        let mut rows = stmt.query([])?;
        let mut apps = Vec::new();
        while let Some(row) = rows.next()? {
            apps.push(app_from_row(row)?);
        }
        apps.sort_by_key(|a| (a.name.to_lowercase(), a.version.clone().unwrap_or_default()));
        Ok(apps)
    }

    /// Row id of a stored application, matched by product identity.
    pub fn find_application_id(&self, app: &InstalledApp) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id FROM installed_applications WHERE app_key = ?1",
                [app_key(app)],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Insert or update an executable's metadata and signature result. Returns its row id.
    pub fn upsert_executable(
        &self,
        info: &ExecutableInfo,
        identity: FileIdentity,
        verified_at: &str,
    ) -> Result<i64> {
        Self::upsert_executable_row(self.conn(), info, identity, verified_at)
    }

    /// Connection-level form of [`upsert_executable`](Self::upsert_executable), usable inside a
    /// caller-controlled transaction.
    pub(crate) fn upsert_executable_row(
        conn: &rusqlite::Connection,
        info: &ExecutableInfo,
        identity: FileIdentity,
        verified_at: &str,
    ) -> Result<i64> {
        let path = info.path.to_string_lossy();
        let (status, signer, code) = signature_columns(&info.signature);
        let file_name = info
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(conn.query_row(
            "INSERT INTO executables \
             (path_key, file_path, file_name, product_name, file_description, original_filename, \
              file_version, signature_status, signer, signature_code, classification, \
              file_size, file_mtime_ns, verified_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) \
             ON CONFLICT(path_key) DO UPDATE SET \
               file_path = excluded.file_path, file_name = excluded.file_name, \
               product_name = excluded.product_name, file_description = excluded.file_description, \
               original_filename = excluded.original_filename, file_version = excluded.file_version, \
               signature_status = excluded.signature_status, signer = excluded.signer, \
               signature_code = excluded.signature_code, classification = excluded.classification, \
               file_size = excluded.file_size, file_mtime_ns = excluded.file_mtime_ns, \
               verified_at = excluded.verified_at \
             RETURNING id",
            params![
                path.to_lowercase(),
                path,
                file_name,
                info.version.product_name,
                info.version.file_description,
                info.version.original_filename,
                info.version.file_version,
                status,
                signer,
                code,
                info.classification.as_str(),
                identity.size as i64,
                identity.mtime_ns,
                verified_at,
            ],
            |r| r.get(0),
        )?)
    }

    /// The stored result for `path`, only if the file is unchanged (same size and mtime).
    /// This is the persistent signature cache: a hit avoids re-running WinVerifyTrust.
    pub fn cached_executable(
        &self,
        path: &Path,
        identity: FileIdentity,
    ) -> Result<Option<ExecutableInfo>> {
        let key = path.to_string_lossy().to_lowercase();
        let row = self
            .conn()
            .query_row(
                "SELECT file_path, product_name, file_description, original_filename, file_version, \
                 signature_status, signer, signature_code \
                 FROM executables WHERE path_key = ?1 AND file_size = ?2 AND file_mtime_ns = ?3",
                params![key, identity.size as i64, identity.mtime_ns],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        FileVersionInfo {
                            product_name: r.get(1)?,
                            file_description: r.get(2)?,
                            original_filename: r.get(3)?,
                            file_version: r.get(4)?,
                        },
                        r.get::<_, String>(5)?,
                        r.get::<_, Option<String>>(6)?,
                        r.get::<_, Option<i64>>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((file_path, version, status, signer, code)) = row else {
            return Ok(None);
        };
        let signature = signature_from_columns(&status, signer, code)?;
        Ok(Some(ExecutableInfo {
            path: PathBuf::from(file_path),
            version,
            classification: classify(&signature),
            signature,
        }))
    }

    /// Record a sighting of a process instance, keyed by (pid, start_time). A returning instance
    /// has its `end_time` cleared. Returns the row id.
    pub fn upsert_process_instance(
        &self,
        p: &ProcessInfo,
        executable_id: Option<i64>,
        application_id: Option<i64>,
        now: &str,
    ) -> Result<i64> {
        upsert_instance(
            self.conn(),
            &InstanceRow {
                pid: p.key.pid,
                start_time: p.key.start_time,
                parent_pid: p.parent_pid,
                name: &p.name,
                exe_path: p.exe_path.value().map(|x| x.to_string_lossy().into_owned()),
                executable_id,
                application_id,
                user: p.user.value().map(String::as_str),
                session_id: p.session_id.value().copied(),
            },
            now,
        )
    }
}

/// Everything stored about one process instance when it is (re)sighted.
pub struct InstanceRow<'a> {
    pub pid: u32,
    /// FILETIME; 0 when unknown.
    pub start_time: u64,
    pub parent_pid: u32,
    pub name: &'a str,
    pub exe_path: Option<String>,
    pub executable_id: Option<i64>,
    pub application_id: Option<i64>,
    pub user: Option<&'a str>,
    pub session_id: Option<u32>,
}

/// Insert or refresh a process instance keyed by (pid, start_time); clears `end_time`.
/// Takes a plain `&Connection` so callers can run it inside their own transaction.
pub(crate) fn upsert_instance(
    conn: &rusqlite::Connection,
    row: &InstanceRow<'_>,
    now: &str,
) -> Result<i64> {
    Ok(conn.query_row(
        "INSERT INTO process_instances \
         (pid, start_time, parent_pid, name, exe_path, executable_id, application_id, \
          user_account, session_id, first_seen, last_seen) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10) \
         ON CONFLICT(pid, start_time) DO UPDATE SET \
           parent_pid = excluded.parent_pid, name = excluded.name, \
           exe_path = COALESCE(excluded.exe_path, exe_path), \
           executable_id = COALESCE(excluded.executable_id, executable_id), \
           application_id = COALESCE(excluded.application_id, application_id), \
           user_account = COALESCE(excluded.user_account, user_account), \
           session_id = COALESCE(excluded.session_id, session_id), \
           last_seen = excluded.last_seen, end_time = NULL \
         RETURNING id",
        params![
            row.pid,
            row.start_time as i64,
            row.parent_pid,
            row.name,
            row.exe_path,
            row.executable_id,
            row.application_id,
            row.user,
            row.session_id,
            now,
        ],
        |r| r.get(0),
    )?)
}

/// An executable the monitor has seen, with how many of its processes are running right now.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutableRow {
    pub file_name: String,
    pub file_path: String,
    pub product_name: Option<String>,
    /// The signer's name when the signature is valid.
    pub signer: Option<String>,
    pub classification: Classification,
    pub running_instances: u32,
}

impl Database {
    /// Every executable seen so far, with its running instance count, ordered by name.
    pub fn list_executables(&self) -> Result<Vec<ExecutableRow>> {
        let mut stmt = self.conn().prepare(
            "SELECT e.file_name, e.file_path, e.product_name, e.signer, e.classification,                     (SELECT COUNT(*) FROM process_instances pi                      WHERE pi.executable_id = e.id AND pi.end_time IS NULL) AS running              FROM executables e ORDER BY e.file_name COLLATE NOCASE, e.file_path",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let class: String = r.get(4)?;
            out.push(ExecutableRow {
                file_name: r.get(0)?,
                file_path: r.get(1)?,
                product_name: r.get(2)?,
                signer: r.get(3)?,
                classification: parse_classification(&class)?,
                running_instances: r.get::<_, i64>(5)?.max(0) as u32,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use winperf_core::inventory::SignatureStatus;
    use winperf_core::{Metric, ProcessKey};

    fn app(name: &str, version: &str, publisher: &str) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            publisher: Some(publisher.into()),
            version: Some(version.into()),
            install_date: Some("2024-02-29".into()),
            install_location: Some(format!("C:\\{name}")),
            uninstall_command: Some("C:\\u.exe".into()),
            registry_sources: vec!["HKLM32".into(), "HKLM64".into()],
            classification: Classification::Unknown,
        }
    }

    fn bare_app(name: &str) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            publisher: None,
            version: None,
            install_date: None,
            install_location: None,
            uninstall_command: None,
            registry_sources: vec!["HKCU".into()],
            classification: Classification::Unknown,
        }
    }

    fn exe(sig: SignatureStatus) -> ExecutableInfo {
        ExecutableInfo {
            path: PathBuf::from("C:\\Windows\\System32\\Notepad.exe"),
            version: FileVersionInfo {
                product_name: Some("Windows".into()),
                file_description: Some("Notepad".into()),
                original_filename: None,
                file_version: Some("10.0".into()),
            },
            classification: classify(&sig),
            signature: sig,
        }
    }

    fn proc(pid: u32, start: u64) -> ProcessInfo {
        ProcessInfo {
            key: ProcessKey::new(pid, start),
            parent_pid: 4,
            name: "a.exe".into(),
            start_time: Metric::Available(start),
            exe_path: Metric::Unavailable,
            user: Metric::Available("PC\\me".into()),
            session_id: Metric::Available(1),
            command_line: Metric::Unavailable,
            publisher: None,
            signature: SignatureStatus::NotSigned,
            classification: Classification::Unsigned,
        }
    }

    fn count(db: &Database, table: &str) -> i64 {
        db.conn()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn installed_apps_round_trip_exactly() {
        let mut db = Database::open_in_memory().unwrap();
        let apps = vec![
            app("Alpha", "1.0", "Acme"),
            bare_app("beta"),
            app("Gamma", "2.0", "Other"),
        ];
        assert_eq!(
            db.save_installed_apps(&apps, "2026-01-01 00:00:00")
                .unwrap(),
            3
        );
        assert_eq!(db.load_installed_apps().unwrap(), apps);
    }

    #[test]
    fn saving_the_same_scan_twice_is_idempotent_and_keeps_ids() {
        let mut db = Database::open_in_memory().unwrap();
        let apps = vec![app("Alpha", "1.0", "Acme"), app("Gamma", "2.0", "Other")];
        db.save_installed_apps(&apps, "2026-01-01 00:00:00")
            .unwrap();
        let id = db.find_application_id(&apps[0]).unwrap().unwrap();
        db.save_installed_apps(&apps, "2026-01-02 00:00:00")
            .unwrap();
        assert_eq!(count(&db, "installed_applications"), 2);
        assert_eq!(db.find_application_id(&apps[0]).unwrap(), Some(id));
        let (first, last): (String, String) = db
            .conn()
            .query_row(
                "SELECT first_seen, last_seen FROM installed_applications WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            first, "2026-01-01 00:00:00",
            "first_seen must survive refresh"
        );
        assert_eq!(last, "2026-01-02 00:00:00");
    }

    #[test]
    fn refresh_removes_uninstalled_apps_and_detaches_their_processes() {
        let mut db = Database::open_in_memory().unwrap();
        let keep = app("Keep", "1", "A");
        let gone = app("Gone", "1", "B");
        db.save_installed_apps(&[keep.clone(), gone.clone()], "t1")
            .unwrap();
        let gone_id = db.find_application_id(&gone).unwrap().unwrap();
        let pid_row = db
            .upsert_process_instance(&proc(10, 100), None, Some(gone_id), "t1")
            .unwrap();

        db.save_installed_apps(std::slice::from_ref(&keep), "t2")
            .unwrap();

        assert_eq!(db.load_installed_apps().unwrap(), vec![keep]);
        let app_id: Option<i64> = db
            .conn()
            .query_row(
                "SELECT application_id FROM process_instances WHERE id = ?1",
                [pid_row],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(app_id, None, "process kept, association cleared");
        assert_eq!(count(&db, "process_instances"), 1);
    }

    #[test]
    fn executable_upsert_and_cache_hit() {
        let db = Database::open_in_memory().unwrap();
        let id_a = FileIdentity {
            size: 100,
            mtime_ns: 5,
        };
        let info = exe(SignatureStatus::Valid {
            signer: "Microsoft Windows".into(),
        });
        let row = db.upsert_executable(&info, id_a, "t1").unwrap();

        let hit = db.cached_executable(&info.path, id_a).unwrap().unwrap();
        assert_eq!(hit, info);
        assert_eq!(hit.classification, Classification::MicrosoftOfficial);

        // Path lookup is case-insensitive (Windows paths).
        let upper = Path::new("C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE");
        assert!(db.cached_executable(upper, id_a).unwrap().is_some());

        // Upsert of the same path reuses the row.
        assert_eq!(db.upsert_executable(&info, id_a, "t2").unwrap(), row);
        assert_eq!(count(&db, "executables"), 1);
    }

    #[test]
    fn cache_misses_when_the_file_changed() {
        let db = Database::open_in_memory().unwrap();
        let id = FileIdentity {
            size: 100,
            mtime_ns: 5,
        };
        let info = exe(SignatureStatus::NotSigned);
        db.upsert_executable(&info, id, "t").unwrap();
        let bigger = FileIdentity { size: 101, ..id };
        let newer = FileIdentity { mtime_ns: 6, ..id };
        assert!(db.cached_executable(&info.path, bigger).unwrap().is_none());
        assert!(db.cached_executable(&info.path, newer).unwrap().is_none());
        assert!(
            db.cached_executable(Path::new("C:\\other.exe"), id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn every_signature_status_round_trips() {
        let db = Database::open_in_memory().unwrap();
        let id = FileIdentity {
            size: 1,
            mtime_ns: 1,
        };
        for (i, sig) in [
            SignatureStatus::Valid {
                signer: "Acme".into(),
            },
            SignatureStatus::NotSigned,
            SignatureStatus::Invalid { code: 0x8009_6010 },
            SignatureStatus::Unreadable,
        ]
        .into_iter()
        .enumerate()
        {
            let mut info = exe(sig.clone());
            info.path = PathBuf::from(format!("C:\\x\\{i}.exe"));
            db.upsert_executable(&info, id, "t").unwrap();
            assert_eq!(db.cached_executable(&info.path, id).unwrap().unwrap(), info);
        }
    }

    #[test]
    fn a_reused_pid_is_a_separate_process_instance() {
        let db = Database::open_in_memory().unwrap();
        let first = db
            .upsert_process_instance(&proc(50, 1000), None, None, "t1")
            .unwrap();
        let reborn = db
            .upsert_process_instance(&proc(50, 2000), None, None, "t2")
            .unwrap();
        assert_ne!(first, reborn);
        assert_eq!(count(&db, "process_instances"), 2);
    }

    #[test]
    fn seeing_the_same_instance_again_updates_it_and_clears_end_time() {
        let db = Database::open_in_memory().unwrap();
        let id = db
            .upsert_process_instance(&proc(60, 1000), None, None, "t1")
            .unwrap();
        db.conn()
            .execute(
                "UPDATE process_instances SET end_time = 'tX' WHERE id = ?1",
                [id],
            )
            .unwrap();

        let again = db
            .upsert_process_instance(&proc(60, 1000), None, None, "t3")
            .unwrap();
        assert_eq!(again, id);
        assert_eq!(count(&db, "process_instances"), 1);
        let (first, last, end): (String, String, Option<String>) = db
            .conn()
            .query_row(
                "SELECT first_seen, last_seen, end_time FROM process_instances WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((first.as_str(), last.as_str(), end), ("t1", "t3", None));
    }

    #[test]
    fn process_instance_keeps_a_previously_known_executable_link() {
        let db = Database::open_in_memory().unwrap();
        let id = FileIdentity {
            size: 1,
            mtime_ns: 1,
        };
        let exe_id = db
            .upsert_executable(&exe(SignatureStatus::NotSigned), id, "t")
            .unwrap();
        let p = proc(70, 1000);
        let row = db
            .upsert_process_instance(&p, Some(exe_id), None, "t1")
            .unwrap();
        // A later sighting where the path was unreadable must not drop the link.
        db.upsert_process_instance(&p, None, None, "t2").unwrap();
        let linked: Option<i64> = db
            .conn()
            .query_row(
                "SELECT executable_id FROM process_instances WHERE id = ?1",
                [row],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(linked, Some(exe_id));
    }

    #[test]
    fn saving_data_survives_reopen_on_disk() {
        let dir = crate::testutil::TempDir::new("apps-reopen");
        let path = dir.path().join("a.db");
        let apps = vec![app("Persisted", "9", "Acme")];
        {
            let mut db = Database::open(&path).unwrap();
            db.save_installed_apps(&apps, "t").unwrap();
        }
        let db = Database::open(&path).unwrap();
        assert_eq!(db.load_installed_apps().unwrap(), apps);
    }

    #[test]
    fn executables_are_listed_with_their_running_instance_counts() {
        let db = Database::open_in_memory().unwrap();
        db.conn()
            .execute_batch(
                "INSERT INTO executables (id, path_key, file_path, file_name, product_name,
                   signature_status, signer, classification, file_size, file_mtime_ns, verified_at)
                 VALUES (1, 'c:/b/zed.exe', 'C:/B/Zed.exe', 'Zed.exe', 'Zed', 'valid',
                         'Zed Ltd', 'third_party', 1, 1, 't'),
                        (2, 'c:/a/alpha.exe', 'C:/A/alpha.exe', 'alpha.exe', NULL,
                         'not_signed', NULL, 'unsigned', 1, 1, 't');
                 INSERT INTO process_instances (pid, start_time, parent_pid, name, executable_id,
                   first_seen, last_seen, end_time) VALUES
                   (1, 1, 0, 'Zed.exe', 1, 't', 't', NULL),
                   (2, 2, 0, 'Zed.exe', 1, 't', 't', NULL),
                   (3, 3, 0, 'Zed.exe', 1, 't', 't', 'ended'),
                   (4, 4, 0, 'alpha.exe', 2, 't', 't', 'ended');",
            )
            .unwrap();
        let rows = db.list_executables().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].file_name, "alpha.exe",
            "ordered by name, case-insensitively"
        );
        assert_eq!(rows[0].classification, Classification::Unsigned);
        assert_eq!(
            (rows[0].running_instances, rows[0].signer.clone()),
            (0, None)
        );
        assert_eq!(rows[1].file_name, "Zed.exe");
        assert_eq!(rows[1].running_instances, 2, "ended instances do not count");
        assert_eq!(rows[1].signer.as_deref(), Some("Zed Ltd"));
        assert_eq!(rows[1].product_name.as_deref(), Some("Zed"));
        assert_eq!(rows[1].classification, Classification::ThirdPartyOfficial);
    }
}
