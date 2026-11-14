//! Live file-write workload (T12 verification): the writing process's I/O rate and the
//! system-wide physical disk counters must both show it.
//!
//! The writer runs until the sampler has taken enough measurements (not for a fixed amount of
//! data), so the test doesn't depend on how fast this machine's disk is.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use winperf_core::Metric;
use winperf_core::engine::MetricsSource;
use winperf_core::sampling::Sampler;
use winperf_core::system::SystemSampler;
use winperf_windows::WindowsMetricsSource;

const MB: f64 = 1024.0 * 1024.0;
const CHUNK: usize = 8 * 1024 * 1024;
/// The scratch file is rewound after this many bytes so it never grows without bound.
const FILE_CAP: u64 = 512 * 1024 * 1024;

#[test]
fn a_file_write_workload_shows_up_in_process_io_and_system_disk_counters() {
    let path = std::env::temp_dir().join(format!("winperf-disk-live-{}.bin", std::process::id()));
    let target = path.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::clone(&stop);

    // Writes continuously, forcing data to disk every 64 MB so physical writes fall inside the
    // sampling window, until the sampler says it is done.
    let writer = std::thread::spawn(move || {
        let mut f = File::create(&target).unwrap();
        let chunk = vec![0xABu8; CHUNK];
        let mut since_sync = 0usize;
        let mut written = 0u64;
        while !writer_stop.load(Ordering::Relaxed) {
            f.write_all(&chunk).unwrap();
            since_sync += CHUNK;
            written += CHUNK as u64;
            if since_sync >= 64 * 1024 * 1024 {
                f.sync_all().unwrap();
                since_sync = 0;
            }
            if written >= FILE_CAP {
                f.seek(SeekFrom::Start(0)).unwrap();
                written = 0;
            }
        }
        f.sync_all().unwrap();
    });

    let mut src = WindowsMetricsSource::new();
    let mut procs = Sampler::new(src.logical_cpus());
    let mut system = SystemSampler::new();
    let me = std::process::id();
    let mine = |all: Vec<winperf_core::sampling::Observation>| {
        all.into_iter().filter(|o| o.pid == me).collect::<Vec<_>>()
    };

    let mut max_proc_write = 0.0f64;
    let mut proc_write_was_partial = false;
    let mut max_sys_write = 0.0f64;
    let mut max_util = 0.0f64;

    // Prime the rate counters, then take several 400 ms measurements while the writer runs.
    procs.tick(&mine(src.observe()), Duration::ZERO);
    system.tick(&src.observe_system(), Duration::ZERO);
    let mut last = Instant::now();
    for _ in 0..6 {
        std::thread::sleep(Duration::from_millis(400));
        let elapsed = last.elapsed();
        last = Instant::now();
        let out = procs.tick(&mine(src.observe()), elapsed);
        let sys = system.tick(&src.observe_system(), elapsed);

        if let Metric::Partial(w) = out.samples[0].io_write_bytes_per_sec {
            proc_write_was_partial = true;
            max_proc_write = max_proc_write.max(w);
        }
        if let Metric::Available(w) = sys.disk_write_bytes_per_sec {
            max_sys_write = max_sys_write.max(w);
        }
        if let Metric::Available(u) = sys.disk_utilization_percent {
            max_util = max_util.max(u);
        }
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        proc_write_was_partial,
        "process I/O must be reported as Partial (it includes non-disk I/O)"
    );
    assert!(
        max_proc_write >= 20.0 * MB,
        "process write rate peaked at only {:.1} MB/s",
        max_proc_write / MB
    );
    assert!(
        max_sys_write >= 10.0 * MB,
        "system disk write rate peaked at only {:.1} MB/s",
        max_sys_write / MB
    );
    assert!(max_util > 0.5, "disk utilization peaked at {max_util:.1}%");
}
