//! Does the report get in the recorder's way? (T33)
//!
//! Plays the recorder against a COPY of a real database: every tick it writes one system sample and
//! one sample for each of N process instances in a single transaction, as the recorder does, and
//! times each commit. It does that twice, first alone and then while several threads hammer a
//! running `winperf-report` with the heaviest requests the page makes. Prints the write latencies
//! of both phases and the size of the WAL file.
//!
//! ```text
//! cargo run --release -p winperf-report --example interference -- <db copy> <report port> [secs]
//! ```
//!
//! Start the report first, on the same copy: `winperf-report --db <db copy> --port <report port>`.
//! Never point this at a live database: it writes rows.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use winperf_storage::Database;

const TICK: Duration = Duration::from_millis(250);
const PROCESSES: usize = 200;
const LOAD_THREADS: usize = 4;

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// One GET over a fresh connection; returns the status code and the response size.
fn get(port: u16, path: &str) -> Option<(u16, usize)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let code = std::str::from_utf8(buf.get(9..12)?).ok()?.parse().ok()?;
    Some((code, buf.len()))
}

struct Phase {
    name: &'static str,
    latencies_ms: Vec<f64>,
}

fn write_phase(
    db: &mut Database,
    instances: &[i64],
    secs: u64,
    next_ts: &mut i64,
    name: &'static str,
) -> Phase {
    let mut latencies_ms = Vec::new();
    let end = Instant::now() + Duration::from_secs(secs);
    let mut next = Instant::now();
    while Instant::now() < end {
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
        next += TICK;
        *next_ts += 5_000;
        let started = Instant::now();
        let tx = db.conn_mut().transaction().expect("begin");
        tx.execute(
            "INSERT INTO system_samples (ts_ms, cpu_percent) VALUES (?1, 10.0)",
            [*next_ts],
        )
        .expect("system sample");
        {
            let mut insert = tx
                .prepare_cached(
                    "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, \
                     working_set_bytes) VALUES (?1, ?2, 1.5, 1048576)",
                )
                .expect("prepare");
            for id in instances {
                insert.execute([*id, *next_ts]).expect("process sample");
            }
        }
        tx.commit().expect("commit");
        latencies_ms.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    Phase { name, latencies_ms }
}

fn sorted(p: &Phase) -> Vec<f64> {
    let mut v = p.latencies_ms.clone();
    v.sort_by(|a, b| a.total_cmp(b));
    v
}

fn show(p: &Phase) {
    let v = sorted(p);
    println!(
        "{:<12} {:>5} ticks  p50 {:>7.2} ms  p95 {:>7.2} ms  p99 {:>7.2} ms  max {:>7.2} ms",
        p.name,
        v.len(),
        percentile(&v, 0.50),
        percentile(&v, 0.95),
        percentile(&v, 0.99),
        v.last().copied().unwrap_or(0.0),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: interference <db copy> <report port> [secs per phase]");
        std::process::exit(2);
    }
    let path = PathBuf::from(&args[1]);
    let port: u16 = args[2].parse().expect("port");
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(20);

    let mut db = Database::open(&path).expect("open the database copy");
    let instances: Vec<i64> = {
        let mut stmt = db
            .conn()
            .prepare("SELECT id FROM process_instances ORDER BY id DESC LIMIT ?1")
            .unwrap();
        stmt.query_map([PROCESSES as i64], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let newest: i64 = db
        .conn()
        .query_row("SELECT MAX(ts_ms) FROM system_samples", [], |r| r.get(0))
        .unwrap();
    // Write after the newest sample so existing data is untouched; ask for the 24 h before it.
    let mut next_ts = newest;
    let from = newest - 24 * 3_600_000;
    println!(
        "database: {} MiB, {} instances written per tick, reading the 24 h up to {newest} (ms)",
        std::fs::metadata(&path).map_or(0, |m| m.len()) / (1 << 20),
        instances.len(),
    );
    if get(port, "/api/status").is_none() {
        eprintln!("no report is answering on port {port}");
        std::process::exit(1);
    }

    let alone = write_phase(&mut db, &instances, secs, &mut next_ts, "alone");
    show(&alone);

    // The heaviest requests the page makes, repeated as fast as they are answered.
    let to = newest;
    let paths: Arc<Vec<String>> = Arc::new(vec![
        format!("/api/system?from_ms={from}&to_ms={to}&points=600"),
        format!("/api/rankings?metric=cpu&group=process&limit=8&from_ms={from}&to_ms={to}"),
        format!("/api/rankings?metric=memory&group=application&limit=8&from_ms={from}&to_ms={to}"),
        format!("/api/export/history?format=csv&from_ms={from}&to_ms={to}"),
        "/api/anomalies?hours=48&limit=200".to_string(),
        "/api/current?limit=10".to_string(),
    ]);
    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let threads: Vec<_> = (0..LOAD_THREADS)
        .map(|t| {
            let (stop, served, failed, paths) =
                (stop.clone(), served.clone(), failed.clone(), paths.clone());
            std::thread::spawn(move || {
                let mut i = t;
                while !stop.load(Ordering::Relaxed) {
                    match get(port, &paths[i % paths.len()]) {
                        Some((200, _)) => served.fetch_add(1, Ordering::Relaxed),
                        _ => failed.fetch_add(1, Ordering::Relaxed),
                    };
                    i += 1;
                }
            })
        })
        .collect();
    let loaded = write_phase(&mut db, &instances, secs, &mut next_ts, "under load");
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    show(&loaded);
    println!(
        "report answered {} requests ({} failed) from {LOAD_THREADS} threads during the loaded phase",
        served.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed)
    );
    let wal = std::fs::metadata(format!("{}-wal", path.display())).map_or(0, |m| m.len());
    println!("WAL file now {} MiB", wal / (1 << 20));
    let p99 = |p: &Phase| percentile(&sorted(p), 0.99);
    println!(
        "tick budget {} ms; p99 with load is {:.1}x the p99 alone",
        TICK.as_millis(),
        p99(&loaded) / p99(&alone).max(0.01)
    );
}
