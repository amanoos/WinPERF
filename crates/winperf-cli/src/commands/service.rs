//! `winperf service ...`: install, remove, start, stop and inspect the Windows service that runs
//! the monitor without a terminal (the `winperf-service` program).
//!
//! Installing and removing change the machine, so they need an elevated prompt and say so plainly
//! when they do not have one. Both can be repeated safely: installing again updates the existing
//! service, removing a service that is not there is not an error. The database is never touched.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use winperf_windows::is_elevated;

pub const SERVICE_NAME: &str = "WinPerf";
const DISPLAY_NAME: &str = "WinPerf Performance Monitor";
const DESCRIPTION: &str = "Records per-process CPU, memory, disk and network use and detects \
                           anomalies. Part of WinPerf.";
const SERVICE_EXE: &str = "winperf-service.exe";
/// Win32 error: the service does not exist.
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
/// How long to wait for the service to reach a state.
const WAIT: Duration = Duration::from_secs(30);

/// How the service is set up.
#[derive(Debug, Clone, PartialEq)]
pub struct InstallOptions {
    /// Path of `winperf-service.exe`; the one next to this program when `None`.
    pub exe: Option<PathBuf>,
    /// Start a little after boot, once the system has settled, rather than with everything else.
    pub delayed_start: bool,
    /// Start the service now, after installing.
    pub start: bool,
}

/// What Windows is told to do when the service fails: restart after 5 s, then 30 s, then every
/// 60 s; the failure count resets after a day without failures.
pub fn recovery_plan() -> ServiceFailureActions {
    let restart = |secs| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(secs),
    };
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(30), restart(60)]),
    }
}

/// The service definition: runs as LocalSystem (needed for the network trace and to read every
/// process), starts automatically.
pub fn service_info(exe: &Path) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    }
}

/// Find `winperf-service.exe`: the explicit path, else next to the running program.
pub fn locate_service_exe(explicit: Option<&Path>, own_exe: &Path) -> Result<PathBuf, String> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => own_exe
            .parent()
            .map(|dir| dir.join(SERVICE_EXE))
            .ok_or("cannot tell where this program is installed; give --exe")?,
    };
    if path.is_file() {
        std::fs::canonicalize(&path)
            .map(|p| strip_verbatim(&p))
            .map_err(|e| format!("{}: {e}", path.display()))
    } else {
        Err(format!(
            "{} not found; build it (cargo build --release) or give its path with --exe",
            path.display()
        ))
    }
}

/// `canonicalize` returns `\\?\C:\...`, which the service manager does not want.
fn strip_verbatim(p: &Path) -> PathBuf {
    match p.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) => PathBuf::from(rest),
        None => p.to_path_buf(),
    }
}

fn need_admin(action: &str) -> Result<(), String> {
    if is_elevated() {
        Ok(())
    } else {
        Err(format!(
            "{action} needs administrator rights: run this from an elevated prompt (right-click the terminal, Run as administrator)"
        ))
    }
}

fn err(what: &str, e: windows_service::Error) -> String {
    format!("{what}: {e}")
}

fn is_missing(e: &windows_service::Error) -> bool {
    matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST))
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager, String> {
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|e| err("cannot reach the service manager", e))
}

/// Open the service, or `None` when it is not installed.
fn open(manager: &ServiceManager, access: ServiceAccess) -> Result<Option<Service>, String> {
    match manager.open_service(SERVICE_NAME, access) {
        Ok(s) => Ok(Some(s)),
        Err(e) if is_missing(&e) => Ok(None),
        Err(e) => Err(err("cannot open the service", e)),
    }
}

fn state_of(service: &Service) -> Result<ServiceState, String> {
    service
        .query_status()
        .map(|s| s.current_state)
        .map_err(|e| err("cannot read the service state", e))
}

fn wait_for(service: &Service, wanted: ServiceState) -> Result<(), String> {
    let deadline = Instant::now() + WAIT;
    loop {
        let state = state_of(service)?;
        if state == wanted {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the service did not reach {wanted:?} within {} s (it is {state:?}); see the service log in %ProgramData%\\WinPerf\\logs",
                WAIT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn say(out: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(out, "{text}").map_err(|e| e.to_string())
}

/// Install the service, or bring an existing installation up to date.
pub fn install(options: &InstallOptions, out: &mut impl Write) -> Result<(), String> {
    need_admin("installing the service")?;
    let own = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = locate_service_exe(options.exe.as_deref(), &own)?;
    let info = service_info(&exe);
    let access = ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::START;
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let (service, created) = match open(&manager, access)? {
        Some(existing) => {
            existing
                .change_config(&info)
                .map_err(|e| err("cannot update the service", e))?;
            (existing, false)
        }
        None => (
            manager
                .create_service(&info, access)
                .map_err(|e| err("cannot create the service", e))?,
            true,
        ),
    };
    service
        .set_description(DESCRIPTION)
        .map_err(|e| err("cannot set the description", e))?;
    service
        .set_delayed_auto_start(options.delayed_start)
        .map_err(|e| err("cannot set delayed start", e))?;
    service
        .update_failure_actions(recovery_plan())
        .map_err(|e| err("cannot set the recovery actions", e))?;
    // Also restart when the service stops itself with an error code, not only when it crashes.
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| err("cannot set the recovery actions", e))?;
    say(
        out,
        &format!(
            "{} service {SERVICE_NAME} ({}), starts {}, restarts itself after a failure",
            if created { "installed" } else { "updated" },
            exe.display(),
            if options.delayed_start {
                "automatically shortly after boot"
            } else {
                "automatically at boot"
            }
        ),
    )?;
    if options.start {
        start_service(&service, out)
    } else {
        say(out, "start it with: winperf service start")
    }
}

fn start_service(service: &Service, out: &mut impl Write) -> Result<(), String> {
    if state_of(service)? == ServiceState::Running {
        return say(out, "already running");
    }
    service
        .start::<OsString>(&[])
        .map_err(|e| err("cannot start the service", e))?;
    wait_for(service, ServiceState::Running)?;
    say(out, "running")
}

/// Start the installed service.
pub fn start(out: &mut impl Write) -> Result<(), String> {
    need_admin("starting the service")?;
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = open(&manager, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?
        .ok_or("the service is not installed: run winperf service install")?;
    start_service(&service, out)
}

fn stop_service(service: &Service, out: &mut impl Write) -> Result<(), String> {
    let state = state_of(service)?;
    if state == ServiceState::Stopped {
        return say(out, "already stopped");
    }
    if state != ServiceState::StopPending {
        service
            .stop()
            .map_err(|e| err("cannot stop the service", e))?;
    }
    wait_for(service, ServiceState::Stopped)?;
    say(out, "stopped")
}

/// Stop the installed service.
pub fn stop(out: &mut impl Write) -> Result<(), String> {
    need_admin("stopping the service")?;
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = open(&manager, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?
        .ok_or("the service is not installed")?;
    stop_service(&service, out)
}

/// Remove the service (stopping it first). The database and logs stay where they are.
pub fn uninstall(out: &mut impl Write) -> Result<(), String> {
    need_admin("removing the service")?;
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let Some(service) = open(&manager, access)? else {
        return say(out, "the service is not installed; nothing to do");
    };
    stop_service(&service, out)?;
    service
        .delete()
        .map_err(|e| err("cannot remove the service", e))?;
    say(
        out,
        &format!("removed service {SERVICE_NAME}; the database and logs were left in place"),
    )
}

/// Say whether the service is installed and running. Needs no administrator rights.
pub fn status(out: &mut impl Write) -> Result<(), String> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG;
    let Some(service) = open(&manager, access)? else {
        return say(
            out,
            "not installed (winperf service install, as administrator)",
        );
    };
    let state = state_of(&service)?;
    let config = service
        .query_config()
        .map_err(|e| err("cannot read the service settings", e))?;
    say(
        out,
        &format!(
            "{SERVICE_NAME}: {}; start type {:?}; {}",
            describe(state),
            config.start_type,
            config.executable_path.display()
        ),
    )
}

/// What the service is doing, without needing administrator rights: `None` when it is not
/// installed or the service manager cannot be asked.
pub fn current_state() -> Option<ServiceState> {
    let manager = manager(ServiceManagerAccess::CONNECT).ok()?;
    let service = open(&manager, ServiceAccess::QUERY_STATUS).ok()??;
    state_of(&service).ok()
}

/// One phrase for the service's state, for status screens.
pub fn state_phrase(state: Option<ServiceState>) -> &'static str {
    match state {
        None => "service not installed",
        Some(s) => match describe(s) {
            "running" => "service running",
            "stopped" => "service stopped",
            "starting" => "service starting",
            "stopping" => "service stopping",
            "paused" => "service paused",
            _ => "service resuming",
        },
    }
}

fn describe(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Running => "running",
        ServiceState::Stopped => "stopped",
        ServiceState::StartPending => "starting",
        ServiceState::StopPending => "stopping",
        ServiceState::PausePending | ServiceState::Paused => "paused",
        ServiceState::ContinuePending => "resuming",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_starts_automatically_as_its_own_process() {
        let info = service_info(Path::new(r"C:\WinPerf\winperf-service.exe"));
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.name, OsString::from("WinPerf"));
        assert!(info.account_name.is_none(), "LocalSystem");
        assert!(info.launch_arguments.is_empty());
    }

    #[test]
    fn recovery_restarts_with_growing_delays() {
        let plan = recovery_plan();
        let actions = plan.actions.unwrap();
        assert_eq!(actions.len(), 3);
        assert!(
            actions
                .iter()
                .all(|a| a.action_type == ServiceActionType::Restart)
        );
        let delays: Vec<u64> = actions.iter().map(|a| a.delay.as_secs()).collect();
        assert_eq!(delays, [5, 30, 60]);
    }

    #[test]
    fn the_service_program_is_found_next_to_this_one_or_by_path() {
        let dir = std::env::temp_dir().join(format!("winperf-svc-locate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let service = dir.join(SERVICE_EXE);
        std::fs::write(&service, b"x").unwrap();
        let own = dir.join("winperf.exe");

        let found = locate_service_exe(None, &own).unwrap();
        assert!(found.ends_with(SERVICE_EXE));
        assert!(!found.to_string_lossy().starts_with(r"\\?\"));
        assert_eq!(locate_service_exe(Some(&service), &own).unwrap(), found);

        std::fs::remove_file(&service).unwrap();
        let missing = locate_service_exe(None, &own).unwrap_err();
        assert!(
            missing.contains("not found") && missing.contains("--exe"),
            "{missing}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verbatim_prefixes_are_stripped() {
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\C:\a\b.exe")),
            PathBuf::from(r"C:\a\b.exe")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"C:\a\b.exe")),
            PathBuf::from(r"C:\a\b.exe")
        );
    }
}
