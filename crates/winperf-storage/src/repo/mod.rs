//! Repositories: typed read/write access to the tables, as methods on [`crate::Database`].

pub mod baselines;
pub mod inventory;
pub mod lifecycle;
pub mod samples;

pub use baselines::{ListedBaseline, RecomputeReport, StoredBaseline};
pub use inventory::FileIdentity;
pub use samples::{StoredSample, StoredSystemSample};
