//! Per-process network attribution through an ETW kernel session (PRD FR-008, T2/T14).
//!
//! The kernel TCP/IP and UDP/IP providers emit an event for every send and receive, carrying the
//! owning PID and the byte count. We add the bytes up per PID. This needs administrator rights
//! (T2): without them [`EtwNetworkCollector::start`] returns `Err(NetworkStatus::RequiresAdmin)`
//! *without calling ETW at all*, and the monitor simply runs without network attribution.
//!
//! Operational concerns handled here:
//! * The session name embeds our PID (`winperf-network-<pid>`), so two WinPerf processes never
//!   fight over one session.
//! * ETW sessions outlive the process that created them, so a crashed or killed monitor leaves a
//!   session running in the kernel. On start we stop any `winperf-network-*` session whose owning
//!   PID is no longer alive.
//! * Disk attribution via ETW is deliberately not done (kernel disk events carry no usable PID,
//!   see the T2 findings).

use ferrisetw::EventRecord;
use ferrisetw::GUID;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::provider::kernel_providers::{KernelProvider, TCP_IP_PROVIDER};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{KernelTrace, TraceError, stop_trace_by_name};
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Diagnostics::Etw::{EVENT_TRACE_PROPERTIES, QueryAllTracesW};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use winperf_core::network::{NetworkStatus, NetworkTotals, direction_of};

use crate::processes::OwnedHandle;

const SESSION_PREFIX: &str = "winperf-network-";
const STILL_ACTIVE: u32 = 259;
/// `EVENT_TRACE_FLAG_NETWORK_TCPIP`: enables both the TCP/IP and UDP/IP kernel event groups.
const FLAG_NETWORK_TCPIP: u32 = 0x0001_0000;

/// Kernel UDP/IP provider (ferrisetw only predefines the TCP one).
static UDP_IP_PROVIDER: KernelProvider = KernelProvider::new(
    GUID::from_values(
        0xbf3a_50c5,
        0xa9c9,
        0x4988,
        [0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80],
    ),
    FLAG_NETWORK_TCPIP,
);

/// Is this process running with an elevated (administrator) token?
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: current-process pseudo handle; valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: `elevation` is a correctly sized, writable TOKEN_ELEVATION.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .is_ok();
    ok && elevation.TokenIsElevated != 0
}

fn pid_is_alive(pid: u32) -> bool {
    // SAFETY: plain open for limited query; wrapped for closing.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return false;
    };
    let handle = OwnedHandle(handle);
    let mut code = 0u32;
    // SAFETY: live handle, valid out-pointer.
    unsafe { GetExitCodeProcess(handle.0, &mut code) }.is_ok() && code == STILL_ACTIVE
}

/// The PID embedded in one of our session names, or `None` if `name` isn't one of ours.
pub(crate) fn parse_session_pid(name: &str) -> Option<u32> {
    name.strip_prefix(SESSION_PREFIX)?.parse().ok()
}

/// Names of every ETW session currently running on the machine.
fn running_session_names() -> Vec<String> {
    const MAX_SESSIONS: usize = 64;
    const NAME_UNITS: usize = 1024; // UTF-16 units reserved for each of name and log-file name
    let header = size_of::<EVENT_TRACE_PROPERTIES>();
    let stride = header + 2 * NAME_UNITS * 2;
    // u64 backing keeps every EVENT_TRACE_PROPERTIES suitably aligned (`stride` is a multiple of 8).
    let mut backing = vec![0u64; (MAX_SESSIONS * stride).div_ceil(8)];
    let base = backing.as_mut_ptr().cast::<u8>();

    let mut pointers: Vec<*mut EVENT_TRACE_PROPERTIES> = Vec::with_capacity(MAX_SESSIONS);
    for i in 0..MAX_SESSIONS {
        // SAFETY: `i * stride` stays inside `backing`; each slot is initialised before use below.
        let p = unsafe { base.add(i * stride) }.cast::<EVENT_TRACE_PROPERTIES>();
        // SAFETY: `p` points at zeroed storage of at least `stride` bytes owned by `backing`.
        unsafe {
            (*p).Wnode.BufferSize = stride as u32;
            (*p).LoggerNameOffset = header as u32;
            (*p).LogFileNameOffset = (header + NAME_UNITS * 2) as u32;
        }
        pointers.push(p);
    }
    let mut count = 0u32;
    // SAFETY: `pointers` holds MAX_SESSIONS valid, initialised property buffers.
    if unsafe { QueryAllTracesW(&mut pointers, &mut count) }.0 != 0 {
        return Vec::new();
    }
    pointers
        .iter()
        .take((count as usize).min(MAX_SESSIONS))
        .filter_map(|&p| {
            // SAFETY: the system filled the name at `LoggerNameOffset` inside this slot as a
            // NUL-terminated UTF-16 string no longer than the reserved NAME_UNITS.
            let name = unsafe {
                let units = p
                    .cast::<u8>()
                    .add((*p).LoggerNameOffset as usize)
                    .cast::<u16>();
                let slice = std::slice::from_raw_parts(units, NAME_UNITS);
                let len = slice.iter().position(|&c| c == 0)?;
                String::from_utf16_lossy(&slice[..len])
            };
            Some(name)
        })
        .collect()
}

/// Stop `winperf-network-*` sessions whose owning process has died. Returns how many were stopped.
fn stop_stale_sessions() -> usize {
    running_session_names()
        .into_iter()
        .filter(|name| parse_session_pid(name).is_some_and(|pid| !pid_is_alive(pid)))
        .filter(|name| stop_trace_by_name(name).is_ok())
        .count()
}

/// Names of the WinPerf network sessions currently running on the machine (diagnostics, tests).
pub fn list_winperf_sessions() -> Vec<String> {
    running_session_names()
        .into_iter()
        .filter(|name| parse_session_pid(name).is_some())
        .collect()
}

fn classify(error: &TraceError) -> NetworkStatus {
    match error {
        TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist) => {
            NetworkStatus::SessionInUse
        }
        TraceError::EtwNativeError(EvntraceNativeError::IoError(io)) => match io.raw_os_error() {
            Some(5) => NetworkStatus::RequiresAdmin, // ERROR_ACCESS_DENIED
            Some(183) => NetworkStatus::SessionInUse, // ERROR_ALREADY_EXISTS
            _ => NetworkStatus::Failed(io.to_string()),
        },
        other => NetworkStatus::Failed(format!("{other:?}")),
    }
}

/// Event callback: add the bytes of a TCP/UDP send or receive to its PID's totals.
fn callback(
    totals: Arc<Mutex<NetworkTotals>>,
) -> impl Fn(&EventRecord, &SchemaLocator) + Send + Sync + 'static {
    move |record, locator| {
        // Connect, disconnect, retransmit, ... carry no payload and must not be counted.
        let Some(direction) = direction_of(record.opcode()) else {
            return;
        };
        let Ok(schema) = locator.event_schema(record) else {
            return;
        };
        let parser = Parser::create(record, &schema);
        let (Ok(pid), Ok(size)) = (
            parser.try_parse::<u32>("PID"),
            parser.try_parse::<u32>("size"),
        ) else {
            return;
        };
        if let Ok(mut t) = totals.lock() {
            t.record(pid, direction, u64::from(size));
        }
    }
}

/// A running per-process network attribution session. Dropping it stops the session.
pub struct EtwNetworkCollector {
    totals: Arc<Mutex<NetworkTotals>>,
    trace: Option<KernelTrace>,
    session: String,
}

impl EtwNetworkCollector {
    /// Start collecting. `Err` carries the reason attribution is unavailable; it is never fatal.
    pub fn start() -> Result<Self, NetworkStatus> {
        if !is_elevated() {
            return Err(NetworkStatus::RequiresAdmin);
        }
        stop_stale_sessions();

        let session = format!("{SESSION_PREFIX}{}", std::process::id());
        let totals = Arc::new(Mutex::new(NetworkTotals::new()));
        let tcp = Provider::kernel(&TCP_IP_PROVIDER)
            .add_callback(callback(Arc::clone(&totals)))
            .build();
        let udp = Provider::kernel(&UDP_IP_PROVIDER)
            .add_callback(callback(Arc::clone(&totals)))
            .build();
        let trace = KernelTrace::new()
            .named(session.clone())
            .enable(tcp)
            .enable(udp)
            .start_and_process()
            .map_err(|e| classify(&e))?;
        Ok(Self {
            totals,
            trace: Some(trace),
            session,
        })
    }

    /// A copy of the running totals (cheap: only PIDs that have produced traffic).
    pub fn snapshot(&self) -> NetworkTotals {
        self.totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Drop totals for processes that no longer exist.
    pub fn retain_live(&self, live: &HashSet<u32>) {
        self.totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain_live(live);
    }
}

impl Drop for EtwNetworkCollector {
    fn drop(&mut self) {
        if let Some(trace) = self.trace.take() {
            let _ = trace.stop();
        }
        // Belt and braces: make sure the kernel session is gone even if the stop above failed.
        let _ = stop_trace_by_name(&self.session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_own_session_names_parse_to_a_pid() {
        assert_eq!(parse_session_pid("winperf-network-1234"), Some(1234));
        assert_eq!(parse_session_pid("winperf-network-"), None);
        assert_eq!(parse_session_pid("winperf-network-abc"), None);
        assert_eq!(parse_session_pid("winperf-network-12x"), None);
        assert_eq!(parse_session_pid("NT Kernel Logger"), None);
        assert_eq!(parse_session_pid("other-network-1234"), None);
    }

    #[test]
    fn this_process_is_alive_and_an_absurd_pid_is_not() {
        assert!(pid_is_alive(std::process::id()));
        assert!(!pid_is_alive(0xFFFF_FFF0));
    }

    #[test]
    fn enumerating_sessions_works_without_elevation_and_finds_system_sessions() {
        // Listing is allowed for normal users and Windows always runs a few of its own sessions.
        let names = running_session_names();
        assert!(!names.is_empty(), "expected at least one ETW session");
        assert!(names.iter().all(|n| !n.contains('\0')));
    }

    #[test]
    fn errors_are_classified_into_actionable_statuses() {
        let denied = TraceError::EtwNativeError(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(5),
        ));
        assert_eq!(classify(&denied), NetworkStatus::RequiresAdmin);

        let exists = TraceError::EtwNativeError(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(183),
        ));
        assert_eq!(classify(&exists), NetworkStatus::SessionInUse);
        assert_eq!(
            classify(&TraceError::EtwNativeError(
                EvntraceNativeError::AlreadyExist
            )),
            NetworkStatus::SessionInUse
        );

        let other = TraceError::EtwNativeError(EvntraceNativeError::IoError(
            std::io::Error::from_raw_os_error(1450),
        ));
        assert!(matches!(classify(&other), NetworkStatus::Failed(_)));
        assert!(matches!(
            classify(&TraceError::InvalidTraceName),
            NetworkStatus::Failed(_)
        ));
    }
}
