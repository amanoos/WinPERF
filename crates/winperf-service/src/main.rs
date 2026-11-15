//! `winperf-service`: the Windows service host. It runs exactly the engine `winperf monitor run`
//! runs (`winperf_runtime::run_configured`), but under the Service Control Manager, without a
//! terminal, writing a log file instead of console lines.
//!
//! * `winperf-service` (no arguments) is what the SCM starts.
//! * `winperf-service run` runs the same thing in the foreground until Ctrl+C, for testing.

mod log;

use log::Log;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use winperf_core::config::Config;
use winperf_runtime::{RunSettings, run_configured};
use winperf_storage::{ConfigLocation, resolve_config_location, resolve_db_path};

pub const SERVICE_NAME: &str = "WinPerf";

/// Load the configuration like the command line does: a missing file at the default location
/// means the defaults; a missing or broken file the user named is an error.
fn load_config(location: &ConfigLocation) -> Result<Config, String> {
    match std::fs::read_to_string(&location.path) {
        Ok(text) => {
            Config::from_toml_str(&text).map_err(|e| format!("{}: {e}", location.path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !location.explicit => {
            Ok(Config::default())
        }
        Err(e) => Err(format!(
            "cannot read configuration file {}: {e}",
            location.path.display()
        )),
    }
}

/// Run the engine until `stop` is set. Everything that goes wrong is written to the log, since
/// nobody is watching a console.
fn run_engine(stop: &Arc<AtomicBool>, log: &Log) -> Result<(), String> {
    let location = resolve_config_location(None);
    let config = load_config(&location)?;
    let db_path = resolve_db_path(None, config.storage.database.as_deref());
    log.line(&format!(
        "starting: config {}, database {}, every {} s",
        location.path.display(),
        db_path.display(),
        config.monitor.interval_secs
    ));
    let mut note = |line: &str| log.line(line);
    // Per-tick progress and anomaly lines are for terminals; anomalies are in the database.
    let result = run_configured(
        &config,
        &db_path,
        &RunSettings::default(),
        stop,
        &mut std::io::sink(),
        &mut note,
    );
    match result {
        Ok(ticks) => {
            log.line(&format!("stopped after {ticks} ticks"));
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn log_file() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    PathBuf::from(base)
        .join("WinPerf")
        .join("logs")
        .join("service.log")
}

fn foreground() -> ExitCode {
    let log = Log::open(&log_file());
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    if let Err(e) = ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed)) {
        eprintln!("winperf-service: could not install Ctrl+C handler: {e}");
        return ExitCode::FAILURE;
    }
    match run_engine(&stop, &log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log.line(&format!("failed: {e}"));
            eprintln!("winperf-service: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
mod scm {
    use super::*;
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    pub fn dispatch() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn status(state: ServiceState, exit: u32, wait: Duration) -> ServiceStatus {
        let running = state == ServiceState::Running;
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        }
    }

    fn service_main(_args: Vec<OsString>) {
        let log = Log::open(&log_file());
        if let Err(e) = serve(&log) {
            log.line(&format!("service failed: {e}"));
        }
    }

    fn serve(log: &Log) -> Result<(), String> {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<()>();
        let flag = Arc::clone(&stop);
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                flag.store(true, Ordering::Relaxed);
                let _ = tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let handle = service_control_handler::register(SERVICE_NAME, handler)
            .map_err(|e| format!("cannot register with the service manager: {e}"))?;
        handle
            .set_service_status(status(ServiceState::Running, 0, Duration::ZERO))
            .map_err(|e| e.to_string())?;
        log.line("service started");

        // The engine runs on its own thread so a stop request is answered promptly. If it ends by
        // itself (a configuration error, say) the service stops with a failure code, so the
        // recovery actions of T25 can restart it.
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let engine_log = Log::open(&log_file());
        let engine_stop = Arc::clone(&stop);
        let engine = std::thread::spawn(move || {
            let r = run_engine(&engine_stop, &engine_log);
            let _ = done_tx.send(());
            r
        });
        // Wait for either a stop request or the engine ending.
        loop {
            if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                break;
            }
            if done_rx.try_recv().is_ok() {
                break;
            }
        }
        handle
            .set_service_status(status(
                ServiceState::StopPending,
                0,
                Duration::from_secs(20),
            ))
            .map_err(|e| e.to_string())?;
        stop.store(true, Ordering::Relaxed);
        let result = engine
            .join()
            .unwrap_or_else(|_| Err("the engine thread panicked".into()));
        if let Err(e) = &result {
            log.line(&format!("engine failed: {e}"));
        }
        log.line("service stopped");
        handle
            .set_service_status(status(
                ServiceState::Stopped,
                u32::from(result.is_err()),
                Duration::ZERO,
            ))
            .map_err(|e| e.to_string())?;
        result
    }
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("run") => foreground(),
        Some("--version") => {
            println!("winperf-service {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!(
                "winperf-service: unknown argument {other:?} (use \"run\" to run in the foreground)"
            );
            ExitCode::from(2)
        }
        None => {
            #[cfg(windows)]
            if let Err(e) = scm::dispatch() {
                // Started from a console rather than by the service manager.
                eprintln!(
                    "winperf-service: not started by the service manager ({e}); use \"run\" to run in the foreground"
                );
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}
