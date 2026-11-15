//! The monitoring run itself: sampling, detection, baselines, signature checks and network
//! attribution, assembled from the configuration. `winperf monitor run` and the Windows service
//! both call [`run_configured`], so they behave identically.

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
    result
}
