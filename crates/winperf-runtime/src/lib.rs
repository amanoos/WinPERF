//! The monitoring run itself: sampling, detection, baselines, signature checks and network
//! attribution, assembled from the configuration. `winperf monitor run` and the Windows service
//! both call [`run_configured`], so they behave identically.

pub mod lock;
pub mod monitor;
pub mod schedule;

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use winperf_core::anomaly::Sensitivities;
use winperf_core::config::Config;
use winperf_core::inventory::{BackgroundClassifier, ExecutableClassifier};
use winperf_storage::DetectSettings;
use winperf_windows::{
    EtwNetworkCollector, WinTrustVerifier, WindowsMetricsSource, WindowsVersionReader,
};

/// The standard data folder, `%ProgramData%\WinPerf` (where the database, config and service log
/// live unless the user points them elsewhere).
pub fn default_data_dir() -> std::path::PathBuf {
    let base = std::env::var("ProgramData")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| r"C:\ProgramData".to_string());
    std::path::PathBuf::from(base).join("WinPerf")
}

fn same_folder(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| {
        p.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .replace('/', "\\")
            .to_lowercase()
    };
    norm(a) == norm(b)
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn only_the_standard_folder_counts_as_ours_to_restrict() {
        let standard = default_data_dir();
        assert!(same_folder(&standard, &standard));
        assert!(same_folder(
            &standard,
            Path::new(&format!("{}\\", standard.display()).to_uppercase())
        ));
        assert!(!same_folder(&standard, Path::new(r"E:\Workspace\data")));
        // A database somewhere else is left alone, and nothing is created for it.
        let elsewhere = Path::new(r"E:\no-such-winperf-folder\x.db");
        assert_eq!(secure_data_dir(elsewhere).unwrap(), None);
        assert!(!Path::new(r"E:\no-such-winperf-folder").exists());
    }
}

/// Restrict the standard data folder to SYSTEM, Administrators and the current account (T35,
/// NFR-003): the database is a history of everything that ran, so other users should not read it.
/// Only the standard folder is touched: a database the user placed elsewhere is in a folder that is
/// theirs to manage. Returns the folder when it was restricted, `None` when the database is
/// somewhere else. Not called from the service itself, whose account is SYSTEM and would lock out
/// the person who installed it; `winperf service install` does it as that person.
pub fn secure_data_dir(db_path: &Path) -> std::io::Result<Option<std::path::PathBuf>> {
    let Some(dir) = db_path.parent() else {
        return Ok(None);
    };
    if !same_folder(dir, &default_data_dir()) {
        return Ok(None);
    }
    std::fs::create_dir_all(dir)?;
    winperf_windows::acl::restrict_to_admins_and_user(dir)?;
    Ok(Some(dir.to_path_buf()))
}

/// What the caller may change about a run, beyond the configuration file.
#[derive(Debug, Clone, Default)]
pub struct RunSettings {
    /// Sampling interval in seconds; the configured one when `None`.
    pub interval_secs: Option<u64>,
    /// Stop after this many ticks (tests and demos); run until stopped when `None`.
    pub max_ticks: Option<u64>,
    pub no_signatures: bool,
    pub no_network: bool,
    /// Ring the terminal bell for serious anomalies (only on a real terminal).
    pub bell: bool,
}

/// Run until `stop` is set (or `max_ticks`), recording into the database at `db_path`. `note`
/// receives one-line status messages (network attribution state, baseline failures); the sampling
/// lines go to `out`. Returns the number of ticks run. The stop flag is set on return, so helper
/// threads end too.
pub fn run_configured(
    config: &Config,
    db_path: &Path,
    settings: &RunSettings,
    stop: &Arc<AtomicBool>,
    out: &mut impl Write,
    note: &mut dyn FnMut(&str),
) -> Result<u64, Box<dyn std::error::Error>> {
    // Only one recorder may write to a database: the service and a foreground monitor (or two
    // of either) would otherwise interleave their samples. The lock ends with the process.
    let _recorder = lock::RecorderLock::acquire(db_path)?;
    let interval = settings
        .interval_secs
        .unwrap_or(config.monitor.interval_secs);
    let verify_signatures = config.monitor.signatures && !settings.no_signatures;
    // Signature verification runs on its own thread so it can never delay a sampling tick.
    let classifier: Option<Box<dyn ExecutableClassifier>> = verify_signatures.then(|| {
        Box::new(BackgroundClassifier::spawn(
            WinTrustVerifier,
            WindowsVersionReader,
        )) as Box<dyn ExecutableClassifier>
    });
    // Per-process network attribution needs administrator rights. Without them the run carries
    // on and records network as "unavailable"; it never fails because of this.
    let mut metrics = WindowsMetricsSource::new();
    if config.monitor.network && !settings.no_network {
        match EtwNetworkCollector::start() {
            Ok(collector) => {
                metrics = metrics.with_network(collector);
                note("per-process network attribution is active");
            }
            Err(status) => note(&status.describe()),
        }
    }
    // Baselines are recomputed in the background on their own connection.
    let schedule = schedule::spawn_schedule(
        db_path.to_path_buf(),
        config.baseline.windows_hours.clone(),
        Duration::from_secs(u64::from(config.baseline.recompute_minutes) * 60),
        config.retention.raw_samples_days,
        Arc::clone(stop),
    );
    // Rollups and retention run beside it, on their own connection.
    let maintenance = schedule::spawn_maintenance(
        db_path.to_path_buf(),
        config.retention.clone(),
        Arc::clone(stop),
    );
    let detect = DetectSettings::new(
        Sensitivities::from_config(&config.detection),
        config.baseline.windows_hours.clone(),
        config.baseline.confidence.clone(),
    );
    let result = monitor::run(
        metrics,
        db_path,
        monitor::Options {
            classifier,
            detect: Some(detect),
            bell: settings.bell,
        },
        Duration::from_secs(interval),
        settings.max_ticks,
        stop,
        out,
    );
    // A run that ended by itself (max_ticks) never set the flag; stop the schedule too.
    stop.store(true, Ordering::Relaxed);
    let _ = schedule.join();
    let _ = maintenance.join();
    result
}
