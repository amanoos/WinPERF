//! Repositories: typed read/write access to the tables, as methods on [`crate::Database`].

pub mod anomalies;
pub mod baselines;
pub mod inventory;
pub mod lifecycle;
pub mod profile;
pub mod samples;

pub use anomalies::{AnomalyFilter, StoredAnomaly};
pub use baselines::{ListedBaseline, RecomputeReport, StoredBaseline};
pub use inventory::FileIdentity;
pub use profile::ProfileState;
pub use samples::{StoredSample, StoredSystemSample};
