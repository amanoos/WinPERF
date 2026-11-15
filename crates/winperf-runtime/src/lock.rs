//! One recorder per database. The service and `winperf monitor run` both record samples; running
//! two against the same database would interleave their data and double every row. A lock file
//! next to the database is held for as long as a run lasts; Windows releases it when the process
//! ends, however it ends (including being killed), so it cannot go stale.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

/// Held while a run is recording; dropping it (or the process ending) releases it.
#[derive(Debug)]
pub struct RecorderLock {
    _file: File,
}

fn lock_path(db_path: &Path) -> PathBuf {
    let mut name = db_path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

impl RecorderLock {
    /// Take the lock for the database at `db_path`, or say that another recorder has it.
    pub fn acquire(db_path: &Path) -> Result<Self, io::Error> {
        let path = lock_path(db_path);
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(io::Error::other(format!(
                "another WinPerf monitor is already recording to {} (the Windows service, or \
                 another `monitor run`); stop it first, or use `winperf tui` to watch",
                db_path.display()
            ))),
            Err(TryLockError::Error(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_recorder_is_refused_until_the_first_is_gone() {
        let dir = std::env::temp_dir().join(format!("winperf-lock-{}", std::process::id()));
        let db = dir.join("x.db");
        let first = RecorderLock::acquire(&db).unwrap();
        let refused = RecorderLock::acquire(&db).unwrap_err().to_string();
        assert!(refused.contains("already recording"), "{refused}");
        drop(first);
        RecorderLock::acquire(&db).expect("free again once the first run ended");
    }
}
