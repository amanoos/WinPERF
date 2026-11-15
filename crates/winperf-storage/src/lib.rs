//! SQLite storage layer (schema, migrations, repositories).

pub mod db;
pub mod detect;
pub mod error;
pub mod migrations;
pub mod paths;
pub mod repo;
pub mod sink;

pub use db::Database;
pub use detect::{DetectSettings, DetectingSink, Notice};
pub use error::{Result, StorageError};
pub use paths::{
    ConfigLocation, ENV_CONFIG, ENV_DB, config_location, default_db_path, resolve_config_location,
    resolve_db_path,
};
pub use repo::{
    AnomalyFilter, ExecutableRow, FileIdentity, ListedBaseline, ProfileState, RecomputeReport,
    StoredAnomaly, StoredBaseline, StoredSystemSample,
};
pub use sink::DbSink;

/// Crate name, used by front ends for diagnostics.
pub const NAME: &str = "winperf-storage";

#[cfg(test)]
pub(crate) mod testutil {
    //! A self-cleaning unique temp directory (no extra dependency).
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("winperf-storage-{}-{n}-{tag}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(NAME, "winperf-storage");
    }
}
