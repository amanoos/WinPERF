//! Per-tick process probe for the monitoring engine: cumulative CPU time plus memory counters.
//!
//! Cheap by design (T2: ~11 ms for ~600 processes): one `OpenProcess`, `GetProcessTimes` and one
//! `NtQueryInformationProcess(ProcessVmCounters)` per process. The expensive details (path,
//! owner) are fetched only for a process seen for the first time, via `describe`.

use crate::processes::{OwnedHandle, WindowsProcessSource, snapshot};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessVmCounters};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::Threading::{
    ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, GetExitCodeProcess, GetProcessIoCounters,
    GetProcessTimes, IO_COUNTERS, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use winperf_core::engine::MetricsSource;
use winperf_core::inventory::RawProcess;
use winperf_core::network::NetworkTotals;
use winperf_core::sampling::Observation;
use winperf_core::system::SystemObservation;

use crate::etw::EtwNetworkCollector;
use crate::system::WindowsSystemSource;

const STILL_ACTIVE: u32 = 259;

/// Mirrors the native `VM_COUNTERS_EX` structure (x64 layout).
#[repr(C)]
#[derive(Default)]
struct VmCountersEx {
    peak_virtual_size: usize,
    virtual_size: usize,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_usage: usize,
}

fn filetime_u64(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

/// `STATUS_INFO_LENGTH_MISMATCH`: the buffer was too small, grow it and ask again.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

// Byte offsets inside one `SYSTEM_PROCESS_INFORMATION` entry (x64). The `windows` crate only
// exposes this struct with reserved placeholder fields, so the stable documented layout (ntexapi.h)
// is read at fixed offsets from the buffer instead.
mod spi {
    pub const NEXT_ENTRY: usize = 0;
    pub const CREATE_TIME: usize = 32;
    pub const USER_TIME: usize = 40;
    pub const KERNEL_TIME: usize = 48;
    pub const NAME_LENGTH: usize = 56; // UNICODE_STRING.Length, in bytes
    pub const NAME_BUFFER: usize = 64; // UNICODE_STRING.Buffer, an address inside the same buffer
    pub const PID: usize = 80;
    pub const PARENT_PID: usize = 88;
    pub const PEAK_VIRTUAL: usize = 112;
    pub const VIRTUAL: usize = 120;
    pub const PEAK_WORKING_SET: usize = 136;
    pub const WORKING_SET: usize = 144;
    pub const PRIVATE_PAGES: usize = 200;
    pub const READ_OPS: usize = 208;
    pub const WRITE_OPS: usize = 216;
    pub const READ_BYTES: usize = 232;
    pub const WRITE_BYTES: usize = 240;
    /// One past the last field read.
    pub const END: usize = 248;
}

fn read_u64(buf: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(buf[at..at + 8].try_into().expect("8 bytes"))
}

/// Turn the buffer filled by `NtQuerySystemInformation(SystemProcessInformation)` into
/// observations. Defensive about a malformed buffer: a bad entry ends the walk, never panics.
fn parse_process_information(buf: &[u8], net: Option<&NetworkTotals>) -> Vec<Observation> {
    let mut out = Vec::with_capacity(512);
    let mut at = 0usize;
    while at + spi::END <= buf.len() {
        let e = &buf[at..];
        let pid = read_u64(e, spi::PID) as u32;
        if pid != 0 {
            let name_len = u16::from_le_bytes([e[spi::NAME_LENGTH], e[spi::NAME_LENGTH + 1]]);
            let name_ptr = read_u64(e, spi::NAME_BUFFER) as usize;
            let name = (name_ptr >= buf.as_ptr() as usize)
                .then(|| name_ptr - buf.as_ptr() as usize)
                .filter(|start| start + name_len as usize <= buf.len())
                .map(|start| {
                    let units: Vec<u16> = buf[start..start + name_len as usize]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_le_bytes(*c))
                        .collect();
                    String::from_utf16_lossy(&units)
                })
                .unwrap_or_default();
            let mut o = Observation {
                pid,
                parent_pid: read_u64(e, spi::PARENT_PID) as u32,
                name,
                ..Default::default()
            };
            let created = read_u64(e, spi::CREATE_TIME);
            if created > 0 {
                o.start_time = Some(created);
                o.cpu_time_100ns =
                    Some(read_u64(e, spi::USER_TIME) + read_u64(e, spi::KERNEL_TIME));
                o.working_set = Some(read_u64(e, spi::WORKING_SET));
                o.peak_working_set = Some(read_u64(e, spi::PEAK_WORKING_SET));
                o.private_bytes = Some(read_u64(e, spi::PRIVATE_PAGES));
                o.virtual_bytes = Some(read_u64(e, spi::VIRTUAL));
                let _ = spi::PEAK_VIRTUAL;
                o.io_read_ops = Some(read_u64(e, spi::READ_OPS));
                o.io_write_ops = Some(read_u64(e, spi::WRITE_OPS));
                o.io_read_bytes = Some(read_u64(e, spi::READ_BYTES));
                o.io_write_bytes = Some(read_u64(e, spi::WRITE_BYTES));
            }
            if let Some(totals) = net {
                let (rx, tx) = totals.get(pid);
                o.net_rx_bytes = Some(rx);
                o.net_tx_bytes = Some(tx);
            }
            out.push(o);
        }
        let next = u32::from_le_bytes(
            e[spi::NEXT_ENTRY..spi::NEXT_ENTRY + 4]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        if next == 0 {
            break;
        }
        at += next;
    }
    out
}

/// One system call for every process: no handles opened, and it also covers the protected
/// processes that `OpenProcess` refuses. `None` if the call fails (the caller falls back).
fn query_all_processes(buf: &mut Vec<u8>) -> Option<usize> {
    if buf.len() < 1 << 20 {
        buf.resize(1 << 20, 0);
    }
    for _ in 0..4 {
        let mut needed = 0u32;
        // SAFETY: `buf` is a writable allocation of the stated length; `needed` is a valid out-pointer.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len() as u32,
                &mut needed,
            )
        };
        if status.0 >= 0 {
            return Some(needed as usize)
                .filter(|n| *n > 0 && *n <= buf.len())
                .or(Some(buf.len()));
        }
        if status.0 == STATUS_INFO_LENGTH_MISMATCH {
            // The process list can grow between the size probe and the next call: add headroom.
            let want = needed as usize + (needed as usize / 4) + 4096;
            buf.resize(want.max(buf.len() * 2), 0);
        } else {
            return None;
        }
    }
    None
}

/// Observes live processes for the engine.
pub struct WindowsMetricsSource {
    inspector: WindowsProcessSource,
    path_buf: Vec<u16>,
    /// Reused buffer for the all-processes query (about 1 MB; grows if needed).
    spi_buf: Vec<u8>,
    users: HashMap<Vec<u8>, Option<String>>,
    system: WindowsSystemSource,
    /// Per-process network attribution (ETW, administrator only); `None` when not running.
    network: Option<EtwNetworkCollector>,
}

impl Default for WindowsMetricsSource {
    fn default() -> Self {
        Self {
            // Command lines are never collected by the monitor (NFR-003).
            inspector: WindowsProcessSource {
                collect_command_line: false,
            },
            path_buf: vec![0u16; 32_768],
            spi_buf: Vec::new(),
            users: HashMap::new(),
            system: WindowsSystemSource::new(),
            network: None,
        }
    }
}

impl WindowsMetricsSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Also report per-process network bytes, from a running ETW collector.
    pub fn with_network(mut self, collector: EtwNetworkCollector) -> Self {
        self.network = Some(collector);
        self
    }

    /// `None` means the process has already exited and must not be reported at all.
    fn observe_one(
        pid: u32,
        parent_pid: u32,
        name: String,
        net: Option<&NetworkTotals>,
    ) -> Option<Observation> {
        let mut obs = Observation {
            pid,
            parent_pid,
            name,
            ..Default::default()
        };
        // SAFETY: plain open for limited query; the result is wrapped for closing.
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            return Some(obs); // access denied or vanished: identity stays unknown
        };
        let handle = OwnedHandle(handle);

        let mut code = 0u32;
        // SAFETY: live handle, valid out-pointer.
        if unsafe { GetExitCodeProcess(handle.0, &mut code) }.is_ok() && code != STILL_ACTIVE {
            return None;
        }

        let (mut created, mut exited, mut kernel, mut user) = Default::default();
        // SAFETY: live handle, valid out-pointers.
        if unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) }
            .is_ok()
        {
            obs.start_time = Some(filetime_u64(created));
            obs.cpu_time_100ns = Some(filetime_u64(kernel) + filetime_u64(user));
        }

        let mut vm = VmCountersEx::default();
        let mut returned = 0u32;
        // SAFETY: `vm` is a correctly sized, writable VM_COUNTERS_EX for this information class.
        let status = unsafe {
            NtQueryInformationProcess(
                handle.0,
                ProcessVmCounters,
                (&mut vm as *mut VmCountersEx).cast::<c_void>(),
                size_of::<VmCountersEx>() as u32,
                &mut returned,
            )
        };
        if status.0 >= 0 {
            obs.working_set = Some(vm.working_set_size as u64);
            obs.peak_working_set = Some(vm.peak_working_set_size as u64);
            obs.private_bytes = Some(vm.private_usage as u64);
            obs.virtual_bytes = Some(vm.virtual_size as u64);
        }

        // Cumulative I/O the process has issued. This counts ALL I/O (files, pipes, devices,
        // network), not just physical disk traffic, so consumers treat it as "process I/O".
        let mut io = IO_COUNTERS::default();
        // SAFETY: live handle, valid out-pointer.
        if unsafe { GetProcessIoCounters(handle.0, &mut io) }.is_ok() {
            obs.io_read_bytes = Some(io.ReadTransferCount);
            obs.io_write_bytes = Some(io.WriteTransferCount);
            obs.io_read_ops = Some(io.ReadOperationCount);
            obs.io_write_ops = Some(io.WriteOperationCount);
        }

        // Network bytes attributed to this PID by event tracing. Only set when attribution is
        // running, so a monitor without administrator rights reports "unavailable", not zero.
        if let Some(totals) = net {
            let (rx, tx) = totals.get(pid);
            obs.net_rx_bytes = Some(rx);
            obs.net_tx_bytes = Some(tx);
        }
        Some(obs)
    }
}

impl MetricsSource for WindowsMetricsSource {
    fn logical_cpus(&self) -> u32 {
        // SAFETY: no pointers; counts active logical processors across all processor groups.
        let n = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        if n > 0 {
            n
        } else {
            std::thread::available_parallelism().map_or(1, |n| n.get() as u32)
        }
    }

    fn observe(&mut self) -> Vec<Observation> {
        let net = self.network.as_ref().map(EtwNetworkCollector::snapshot);
        let observations: Vec<Observation> = match query_all_processes(&mut self.spi_buf) {
            Some(used) => parse_process_information(&self.spi_buf[..used], net.as_ref()),
            // Fallback: a handle per process (slower, and blind to protected processes).
            None => snapshot()
                .into_iter()
                .filter(|(pid, _, _)| *pid != 0)
                .filter_map(|(pid, ppid, name)| Self::observe_one(pid, ppid, name, net.as_ref()))
                .collect(),
        };
        if let Some(collector) = &self.network {
            // Keep the totals map from growing forever with PIDs that have exited.
            let live: HashSet<u32> = observations.iter().map(|o| o.pid).collect();
            collector.retain_live(&live);
        }
        observations
    }

    fn observe_system(&mut self) -> SystemObservation {
        self.system.observe()
    }

    fn describe(&mut self, o: &Observation) -> RawProcess {
        self.inspector.inspect(
            o.pid,
            o.parent_pid,
            o.name.clone(),
            &mut self.path_buf,
            &mut self.users,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: usize = 256;

    fn put(buf: &mut [u8], at: usize, v: u64) {
        buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Two entries, then the UTF-16 names after them. Name pointers are absolute, as in the real call.
    fn sample_buffer() -> Vec<u8> {
        let mut buf = vec![0u8; ENTRY * 2 + 64];
        let base = buf.as_ptr() as usize;
        for (i, (pid, name, created)) in [(4u64, "System", 100u64), (1234, "app.exe", 0)]
            .into_iter()
            .enumerate()
        {
            let at = i * ENTRY;
            let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let name_at = ENTRY * 2 + i * 32;
            buf[name_at..name_at + units.len()].copy_from_slice(&units);
            let e = &mut buf[at..at + ENTRY];
            e[spi::NEXT_ENTRY..spi::NEXT_ENTRY + 4]
                .copy_from_slice(&(if i == 0 { ENTRY as u32 } else { 0 }).to_le_bytes());
            put(e, spi::CREATE_TIME, created);
            put(e, spi::USER_TIME, 30);
            put(e, spi::KERNEL_TIME, 12);
            e[spi::NAME_LENGTH..spi::NAME_LENGTH + 2]
                .copy_from_slice(&(units.len() as u16).to_le_bytes());
            put(e, spi::NAME_BUFFER, (base + name_at) as u64);
            put(e, spi::PID, pid);
            put(e, spi::PARENT_PID, 0);
            put(e, spi::WORKING_SET, 5000);
            put(e, spi::PRIVATE_PAGES, 4000);
            put(e, spi::READ_BYTES, 77);
        }
        buf
    }

    #[test]
    fn parses_identity_counters_and_names() {
        let buf = sample_buffer();
        let obs = parse_process_information(&buf, None);
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].pid, 4);
        assert_eq!(obs[0].name, "System");
        assert_eq!(obs[0].start_time, Some(100));
        assert_eq!(obs[0].cpu_time_100ns, Some(42));
        assert_eq!(obs[0].working_set, Some(5000));
        assert_eq!(obs[0].private_bytes, Some(4000));
        assert_eq!(obs[0].io_read_bytes, Some(77));
        assert!(
            obs[0].net_rx_bytes.is_none(),
            "no collector: network stays unavailable"
        );
    }

    #[test]
    fn a_process_without_a_creation_time_has_no_identity_or_counters() {
        let buf = sample_buffer();
        let obs = parse_process_information(&buf, None);
        assert_eq!(obs[1].name, "app.exe");
        assert!(obs[1].start_time.is_none() && obs[1].cpu_time_100ns.is_none());
        assert!(obs[1].working_set.is_none() && obs[1].io_read_bytes.is_none());
    }

    #[test]
    fn a_truncated_or_corrupt_buffer_never_panics() {
        let mut buf = sample_buffer();
        // Name pointer outside the buffer, and a NextEntryOffset running past the end.
        put(&mut buf, spi::NAME_BUFFER, 8);
        buf[spi::NEXT_ENTRY..spi::NEXT_ENTRY + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let obs = parse_process_information(&buf, None);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].name, "");
        for cut in [0, 10, ENTRY - 1, ENTRY + 100] {
            let _ = parse_process_information(&buf[..cut.min(buf.len())], None);
        }
        assert!(parse_process_information(&[], None).is_empty());
    }
}
