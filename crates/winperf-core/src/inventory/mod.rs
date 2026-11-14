//! System inventory: installed software (T5), executable metadata and processes (later tasks).

pub mod classifier;
pub mod executable;
pub mod grouping;
pub mod processes;
pub mod software;

pub use classifier::{BackgroundClassifier, ExecutableClassifier};
pub use executable::{
    CachedVerifier, ExecutableInfo, FileVersionInfo, SignatureStatus, SignatureVerifier,
    VersionReader, classify, inspect,
};
pub use processes::{ProcessInfo, ProcessSource, RawProcess, scan};
pub use software::{InstalledApp, RawEntry, RegValue, RegistrySource, discover};
