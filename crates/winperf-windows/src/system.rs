//! System-wide readings (PRD FR-009): CPU times, memory/commit, physical disk (PDH) and network
//! adapters (IP Helper).
//!
//! Every metric is independent: if a PDH counter can't be created or read (missing object,
//! disabled counters, localized system), only that metric is unavailable (NFR-002).
//!
//! Disk counters use `PdhAddEnglishCounterW`, so the English counter names work on any language
//! of Windows. Network throughput sums *physical* adapters only (virtual/VPN/Hyper-V adapters
//! would double-count traffic); a newly appearing adapter contributes nothing until its second
//! sighting, so plugging one in never produces a spike.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, IF_TYPE_SOFTWARE_LOOPBACK, MIB_IF_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::System::Performance::{
    PDH_CSTATUS_NEW_DATA, PDH_CSTATUS_VALID_DATA, PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE,
    PDH_HCOUNTER, PDH_HQUERY, PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData,
    PdhGetFormattedCounterValue, PdhOpenQueryW,
};
use windows::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows::Win32::System::Threading::GetSystemTimes;
use windows::core::PCWSTR;
use winperf_core::system::SystemObservation;

/// Full PDH paths of the physical-disk counters (English names).
#[derive(Debug, Clone)]
pub struct DiskCounterPaths {
    /// `% Idle Time`: disk utilization is reported as 100 minus this.
    pub idle_time: String,
    pub queue_length: String,
    pub read_bytes_per_sec: String,
    pub write_bytes_per_sec: String,
    /// Seconds per transfer; reported in milliseconds.
    pub latency_seconds: String,
}

impl Default for DiskCounterPaths {
    fn default() -> Self {
        Self {
            idle_time: r"\PhysicalDisk(_Total)\% Idle Time".into(),
            queue_length: r"\PhysicalDisk(_Total)\Current Disk Queue Length".into(),
            read_bytes_per_sec: r"\PhysicalDisk(_Total)\Disk Read Bytes/sec".into(),
            write_bytes_per_sec: r"\PhysicalDisk(_Total)\Disk Write Bytes/sec".into(),
            latency_seconds: r"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer".into(),
        }
    }
}

struct Pdh {
    query: PDH_HQUERY,
    idle: Option<PDH_HCOUNTER>,
    queue: Option<PDH_HCOUNTER>,
    read: Option<PDH_HCOUNTER>,
    write: Option<PDH_HCOUNTER>,
    latency: Option<PDH_HCOUNTER>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn add_counter(query: PDH_HQUERY, path: &str) -> Option<PDH_HCOUNTER> {
    let path = wide(path);
    let mut counter = PDH_HCOUNTER::default();
    // SAFETY: `query` is open; `path` is NUL-terminated and outlives the call; valid out-pointer.
    let status = unsafe { PdhAddEnglishCounterW(query, PCWSTR(path.as_ptr()), 0, &mut counter) };
    (status == 0).then_some(counter)
}

fn read_counter(counter: Option<PDH_HCOUNTER>) -> Option<f64> {
    let counter = counter?;
    let mut value = PDH_FMT_COUNTERVALUE::default();
    // SAFETY: `counter` belongs to an open query that has been collected; valid out-pointer.
    let status = unsafe { PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, None, &mut value) };
    if status != 0
        || !(value.CStatus == PDH_CSTATUS_VALID_DATA || value.CStatus == PDH_CSTATUS_NEW_DATA)
    {
        return None;
    }
    // SAFETY: the format requested was PDH_FMT_DOUBLE, so `doubleValue` is the active member.
    let v = unsafe { value.Anonymous.doubleValue };
    v.is_finite().then_some(v)
}

impl Pdh {
    fn open(paths: &DiskCounterPaths) -> Option<Self> {
        let mut query = PDH_HQUERY::default();
        // SAFETY: null data source = real-time data; valid out-pointer.
        if unsafe { PdhOpenQueryW(PCWSTR::null(), 0, &mut query) } != 0 {
            return None;
        }
        let pdh = Self {
            query,
            idle: add_counter(query, &paths.idle_time),
            queue: add_counter(query, &paths.queue_length),
            read: add_counter(query, &paths.read_bytes_per_sec),
            write: add_counter(query, &paths.write_bytes_per_sec),
            latency: add_counter(query, &paths.latency_seconds),
        };
        // Rate counters need a baseline collection; the first real read happens a tick later.
        // SAFETY: `query` is open.
        let _ = unsafe { PdhCollectQueryData(query) };
        Some(pdh)
    }

    fn collect(&self) {
        // SAFETY: `self.query` is open for the lifetime of `self`.
        let _ = unsafe { PdhCollectQueryData(self.query) };
    }
}

impl Drop for Pdh {
    fn drop(&mut self) {
        // SAFETY: closes the query opened in `open`, exactly once; its counters die with it.
        let _ = unsafe { PdhCloseQuery(self.query) };
    }
}

/// Accumulates traffic of physical adapters into a monotonic total that is immune to adapters
/// appearing or disappearing.
#[derive(Default)]
struct NetTracker {
    last: HashMap<u64, (u64, u64)>,
    total_rx: u64,
    total_tx: u64,
}

impl NetTracker {
    fn observe(&mut self) -> Option<(u64, u64)> {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        // SAFETY: valid out-pointer; on success the table is freed with FreeMibTable below.
        if unsafe { GetIfTable2(&mut table) }.0 != 0 || table.is_null() {
            return None;
        }
        let mut seen = HashSet::new();
        // SAFETY: GetIfTable2 returned `NumEntries` contiguous rows starting at `Table`; the
        // table stays valid until FreeMibTable.
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        for row in rows {
            let physical = row.InterfaceAndOperStatusFlags._bitfield & 1 != 0; // HardwareInterface
            if row.Type == IF_TYPE_SOFTWARE_LOOPBACK
                || row.OperStatus != IfOperStatusUp
                || !physical
            {
                continue;
            }
            // SAFETY: reading the plain 64-bit view of the LUID union.
            let luid = unsafe { row.InterfaceLuid.Value };
            seen.insert(luid);
            if let Some((prev_rx, prev_tx)) = self.last.get(&luid) {
                self.total_rx += row.InOctets.saturating_sub(*prev_rx);
                self.total_tx += row.OutOctets.saturating_sub(*prev_tx);
            }
            self.last.insert(luid, (row.InOctets, row.OutOctets));
        }
        // SAFETY: `table` came from GetIfTable2 and is freed once; `rows` is not used after this.
        unsafe { FreeMibTable(table as *const c_void) };
        self.last.retain(|luid, _| seen.contains(luid));
        Some((self.total_rx, self.total_tx))
    }
}

fn filetime_u64(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

/// Reads system-wide health from Windows.
pub struct WindowsSystemSource {
    pdh: Option<Pdh>,
    net: NetTracker,
}

impl Default for WindowsSystemSource {
    fn default() -> Self {
        Self::with_disk_counters(&DiskCounterPaths::default())
    }
}

impl WindowsSystemSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Use custom disk counter paths (tests use this to simulate a broken counter).
    pub fn with_disk_counters(paths: &DiskCounterPaths) -> Self {
        Self {
            pdh: Pdh::open(paths),
            net: NetTracker::default(),
        }
    }

    /// Take one reading of everything. Each field is `None` if its source failed.
    pub fn observe(&mut self) -> SystemObservation {
        let mut o = SystemObservation::default();

        let (mut idle, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: valid out-pointers.
        if unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) }.is_ok() {
            o.cpu_idle_100ns = Some(filetime_u64(idle));
            o.cpu_kernel_100ns = Some(filetime_u64(kernel)); // includes idle
            o.cpu_user_100ns = Some(filetime_u64(user));
        }

        let mut pi = PERFORMANCE_INFORMATION {
            cb: size_of::<PERFORMANCE_INFORMATION>() as u32,
            ..Default::default()
        };
        // SAFETY: `pi.cb` is set and `pi` is a valid out-structure.
        if unsafe { GetPerformanceInfo(&mut pi, pi.cb) }.is_ok() {
            let page = pi.PageSize as u64;
            o.memory_total_bytes = Some(pi.PhysicalTotal as u64 * page);
            o.memory_available_bytes = Some(pi.PhysicalAvailable as u64 * page);
            o.commit_used_bytes = Some(pi.CommitTotal as u64 * page);
            o.commit_limit_bytes = Some(pi.CommitLimit as u64 * page);
        }

        if let Some(pdh) = &self.pdh {
            pdh.collect();
            o.disk_utilization_percent =
                read_counter(pdh.idle).map(|i| (100.0 - i).clamp(0.0, 100.0));
            o.disk_queue_length = read_counter(pdh.queue).map(|q| q.max(0.0));
            o.disk_read_bytes_per_sec = read_counter(pdh.read).map(|v| v.max(0.0));
            o.disk_write_bytes_per_sec = read_counter(pdh.write).map(|v| v.max(0.0));
            o.disk_latency_ms = read_counter(pdh.latency).map(|s| (s * 1000.0).max(0.0));
        }

        if let Some((rx, tx)) = self.net.observe() {
            o.net_rx_octets = Some(rx);
            o.net_tx_octets = Some(tx);
        }
        o
    }

    /// Whether the PDH query could be opened at all (individual counters may still be missing).
    pub fn disk_counters_available(&self) -> bool {
        self.pdh.is_some()
    }
}
