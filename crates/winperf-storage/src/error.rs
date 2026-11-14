//! Storage errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "database schema version {found} is newer than this build supports ({supported}); \
         upgrade WinPerf instead of opening it with an older build"
    )]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("invalid value in database: {0}")]
    Corrupt(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;
