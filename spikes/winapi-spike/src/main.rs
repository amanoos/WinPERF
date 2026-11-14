//! T2 spike: throwaway probes of the Windows APIs WinPerf depends on.
//! Usage: winapi-spike <procs|sign <path>|etw [seconds]|overhead [seconds]>
#![allow(clippy::all, unsafe_code)]

use std::ffi::c_void;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::*;
use windows::Win32::Security::WinTrust::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;
use windows::core::PCWSTR;

fn ft_u64(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

#[derive(Default, Debug, Clone)]
struct Probe {
    pid: u32,
    name: String,
    start: u64,
    cpu_100ns: u64,
    working_set: usize,
    private: usize,
    io_read: u64,
    io_write: u64,
}

fn snapshot_pids() -> Vec<(u32, String)> {
    let mut out = vec![];
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
        let mut e = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                let end = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                out.push((e.th32ProcessID, String::from_utf16_lossy(&e.szExeFile[..end])));
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

fn probe(pid: u32, name: &str) -> Result<Probe, String> {
    unsafe {
        // LIMITED_INFORMATION works for most processes without elevation.
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| format!("open: {e}"))?;
        let mut p = Probe { pid, name: name.into(), ..Default::default() };
        let (mut c, mut x, mut k, mut u) = Default::default();
        GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u).map_err(|e| format!("times: {e}"))?;
        p.start = ft_u64(c);
        p.cpu_100ns = ft_u64(k) + ft_u64(u);
        let mut m = PROCESS_MEMORY_COUNTERS_EX::default();
        m.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        if GetProcessMemoryInfo(h, &mut m as *mut _ as *mut PROCESS_MEMORY_COUNTERS, m.cb).is_ok() {
            p.working_set = m.WorkingSetSize;
            p.private = m.PrivateUsage;
        }
        let mut io = IO_COUNTERS::default();
        if GetProcessIoCounters(h, &mut io).is_ok() {
            p.io_read = io.ReadTransferCount;
            p.io_write = io.WriteTransferCount;
        }
        let _ = CloseHandle(h);
        Ok(p)
    }
}

fn cmd_procs() {
    let list = snapshot_pids();
    let t0 = Instant::now();
    let (mut ok, mut denied) = (0, 0);
    let mut denied_names = vec![];
    for (pid, name) in &list {
        if *pid == 0 {
            continue;
        }
        match probe(*pid, name) {
            Ok(_) => ok += 1,
            Err(e) => {
                denied += 1;
                if denied_names.len() < 8 {
                    denied_names.push(format!("{name}({pid}): {e}"));
                }
            }
        }
    }
    println!("processes: {}  readable: {ok}  denied/failed: {denied}", list.len());
    println!("one full pass (open+times+mem+io) took {:?}", t0.elapsed());
    for d in denied_names {
        println!("  denied sample: {d}");
    }
    let before: Vec<Probe> = list.iter().filter_map(|(p, n)| probe(*p, n).ok()).collect();
    std::thread::sleep(Duration::from_secs(2));
    let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;
    let mut rows = vec![];
    for b in &before {
        if let Ok(a) = probe(b.pid, &b.name) {
            if a.start != b.start {
                continue; // PID reused: different instance
            }
            let pct = (a.cpu_100ns - b.cpu_100ns) as f64 / (2.0 * 1e7) / ncpu * 100.0;
            rows.push((pct, a));
        }
    }
    rows.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap());
    println!("top CPU (normalized by {ncpu} logical cpus) over 2s:");
    for (pct, a) in rows.iter().take(5) {
        println!(
            "  {:<24} pid {:<6} cpu {:5.1}%  ws {:>6} MB  priv {:>6} MB  ioR {:>8} MB ioW {:>8} MB",
            a.name, a.pid, pct, a.working_set >> 20, a.private >> 20, a.io_read >> 20, a.io_write >> 20
        );
    }
}

fn verify_file(path: &str) -> i32 {
    unsafe {
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        data.Anonymous.pFile = &mut file;
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let r = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut c_void);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut c_void);
        r
    }
}

fn cmd_sign(path: &str) {
    let t = Instant::now();
    let r = verify_file(path);
    println!("{path}\n  WinVerifyTrust(file, no revocation, cache-only) = 0x{:08X} ({:?})", r as u32, t.elapsed());
    println!("  0 = valid embedded signature; 0x800B0100 = no embedded signature (may still be catalog-signed)");
}

fn cmd_overhead(secs: u64) {
    // Emulates the sampling loop at the PRD default (5s): full pass over all processes.
    let me = std::process::id();
    let t0 = Instant::now();
    let base = probe(me, "self").unwrap();
    let mut passes = 0;
    while t0.elapsed() < Duration::from_secs(secs) {
        for (pid, name) in snapshot_pids() {
            if pid != 0 {
                let _ = probe(pid, &name);
            }
        }
        passes += 1;
        std::thread::sleep(Duration::from_secs(5));
    }
    let end = probe(me, "self").unwrap();
    let wall = t0.elapsed().as_secs_f64();
    let cpu_s = (end.cpu_100ns - base.cpu_100ns) as f64 / 1e7;
    println!(
        "{passes} passes over {wall:.0}s @5s interval: self CPU {cpu_s:.3}s = {:.3}% of one core, WS {} MB",
        cpu_s / wall * 100.0,
        end.working_set >> 20
    );
}

fn cmd_etw(secs: u64) {
    use ferrisetw::EventRecord;
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::{Provider, kernel_providers};
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::{KernelTrace, TraceTrait};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // pid -> (net_bytes, disk_bytes, events)
    let stats: Arc<Mutex<HashMap<u32, (u64, u64, u64)>>> = Default::default();
    let s1 = stats.clone();
    let tcp = move |r: &EventRecord, sl: &SchemaLocator| {
        if let Ok(schema) = sl.event_schema(r) {
            let p = Parser::create(r, &schema);
            let (Ok(pid), Ok(size)) = (p.try_parse::<u32>("PID"), p.try_parse::<u32>("size")) else { return };
            let mut m = s1.lock().unwrap();
            let e = m.entry(pid).or_default();
            e.0 += size as u64;
            e.2 += 1;
        }
    };
    let s2 = stats.clone();
    let disk = move |r: &EventRecord, sl: &SchemaLocator| {
        if let Ok(schema) = sl.event_schema(r) {
            let p = Parser::create(r, &schema);
            let Ok(size) = p.try_parse::<u32>("TransferSize") else { return };
            let mut m = s2.lock().unwrap();
            let e = m.entry(r.process_id()).or_default();
            e.1 += size as u64;
            e.2 += 1;
        }
    };
    let tcp_p = Provider::kernel(&kernel_providers::TCP_IP_PROVIDER).add_callback(tcp).build();
    let disk_p = Provider::kernel(&kernel_providers::DISK_IO_PROVIDER).add_callback(disk).build();
    let trace = KernelTrace::new().named("winperf-spike".into()).enable(tcp_p).enable(disk_p).start_and_process();
    match trace {
        Err(e) => {
            println!("ETW kernel trace FAILED to start: {e:?}");
            println!("(expected without elevation: kernel sessions need admin / SeSystemProfilePrivilege)");
        }
        Ok(t) => {
            println!("ETW kernel trace started; collecting {secs}s. Generate some network + disk activity...");
            std::thread::sleep(Duration::from_secs(secs));
            let _ = t.stop();
            let m = stats.lock().unwrap();
            let names: HashMap<u32, String> = snapshot_pids().into_iter().collect();
            let mut rows: Vec<_> = m.iter().collect();
            rows.sort_by_key(|(_, v)| std::cmp::Reverse(v.0 + v.1));
            println!("{:<26} {:>7} {:>12} {:>12} {:>8}", "process", "pid", "net bytes", "disk bytes", "events");
            for (pid, (n, d, c)) in rows.into_iter().take(10) {
                println!("{:<26} {:>7} {:>12} {:>12} {:>8}", names.get(pid).cloned().unwrap_or("?".into()), pid, n, d, c);
            }
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let n = |i: usize, d: u64| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    match a.get(1).map(String::as_str) {
        Some("procs") => cmd_procs(),
        Some("overhead") => cmd_overhead(n(2, 60)),
        Some("etw") => cmd_etw(n(2, 15)),
        Some("sign") => cmd_sign(a.get(2).expect("path")),
        _ => eprintln!("usage: procs | sign <path> | etw [s] | overhead [s]"),
    }
}
