//! Live CPU measurement check (T10 verification). Deliberately the ONLY test in this file: the
//! test harness runs tests of one file in parallel threads of one process, and any other busy
//! test would pollute the CPU reading.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use winperf_core::Metric;
use winperf_core::engine::MetricsSource;
use winperf_core::sampling::{Observation, Sampler};
use winperf_windows::WindowsMetricsSource;

fn observe_me(src: &mut WindowsMetricsSource) -> Observation {
    let me = std::process::id();
    src.observe()
        .into_iter()
        .find(|o| o.pid == me)
        .expect("own process observed")
}

#[test]
fn a_busy_thread_reads_as_one_cores_share_of_the_machine() {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let burner = std::thread::spawn(move || {
        let mut x = 0u64;
        while !flag.load(Ordering::Relaxed) {
            x = x.wrapping_add(1);
            std::hint::black_box(x);
        }
    });

    let mut src = WindowsMetricsSource::new();
    let cpus = src.logical_cpus();
    let mut sampler = Sampler::new(cpus);

    let first = observe_me(&mut src);
    let t0 = Instant::now();
    sampler.tick(&[first], Duration::ZERO);

    std::thread::sleep(Duration::from_secs(3));

    let second = observe_me(&mut src);
    let elapsed = t0.elapsed();
    let out = sampler.tick(&[second], elapsed);

    stop.store(true, Ordering::Relaxed);
    burner.join().unwrap();

    let Metric::Available(pct) = out.samples[0].cpu_percent else {
        panic!("expected a CPU value, got {:?}", out.samples[0].cpu_percent);
    };
    let expected = 100.0 / f64::from(cpus); // one fully busy thread
    assert!(
        pct > expected * 0.7 && pct <= expected * 1.4 || pct >= 99.9,
        "{cpus} cpus: expected ~{expected:.2}%, measured {pct:.2}%"
    );
}
