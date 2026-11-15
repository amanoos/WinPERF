//! Repositories: typed read/write access to the tables, as methods on [`crate::Database`].

pub mod anomalies;
pub mod baselines;
pub mod inventory;
pub mod lifecycle;
pub mod maintenance;
pub mod profile;
pub mod rankings;
pub mod samples;
pub mod subject;

pub use anomalies::{AnomalyFilter, StoredAnomaly};
pub use baselines::{ListedBaseline, RecomputeReport, StoredBaseline};
pub use inventory::{ExecutableRow, FileIdentity};
pub use maintenance::{HistorySource, Limits, MaintenanceReport};
pub use profile::ProfileState;
pub use rankings::{RankGroup, RankMetric, RankRow, Ranking};
pub use samples::{CurrentProcess, SampleHealth, StoredSample, StoredSystemSample};
pub use subject::{SubjectExecutable, SubjectInfo, SubjectPoint, SubjectRun, SubjectSeries};
