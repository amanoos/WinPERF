//! Live checks of per-process network attribution via ETW (T14).
//!
//! Kernel tracing needs administrator rights, so the tests that start a session SKIP (and say so)
//! when run from a normal shell. To run everything, use an elevated PowerShell:
//!
//! ```text
//! cargo test -p winperf-windows --test etw_live -- --nocapture --test-threads=1
//! cargo test -p winperf-windows --test etw_live -- --nocapture --ignored   # overhead report
//! ```
//!
//! `--test-threads=1` matters: the tests compare byte counts for this process, so they must not
//! generate loopback traffic concurrently.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};
use winperf_core::Metric;
use winperf_core::engine::MetricsSource;
use winperf_core::network::NetworkStatus;
use winperf_core::sampling::Sampler;
use winperf_windows::{
    EtwNetworkCollector, WindowsMetricsSource, is_elevated, list_winperf_sessions,
};

const MB: usize = 1024 * 1024;

/// Wait (up to `timeout`) until `done` is true for this process's totals, then return them.
/// ETW delivers events asynchronously, so totals trail the traffic by a short time.
fn totals_when(
    collector: &EtwNetworkCollector,
    timeout: Duration,
    done: impl Fn((u64, u64)) -> bool,
) -> (u64, u64) {
    let me = std::process::id();
    let deadline = Instant::now() + timeout;
    loop {
        let t = collector.snapshot().get(me);
        if done(t) || Instant::now() >= deadline {
            return t;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn skip_unless_elevated(test: &str) -> bool {
    if is_elevated() {
        return false;
    }
    eprintln!("SKIPPED {test}: needs an elevated (administrator) shell");
    true
}

/// Send `bytes` over a loopback TCP connection inside this process and read them all back.
fn tcp_loopback_transfer(bytes: usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0usize;
        while total < bytes {
            let n = conn.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        total
    });
    let mut client = TcpStream::connect(addr).unwrap();
    let chunk = vec![7u8; 64 * 1024];
    let mut sent = 0;
    while sent < bytes {
        let n = chunk.len().min(bytes - sent);
        client.write_all(&chunk[..n]).unwrap();
        sent += n;
    }
    client.flush().unwrap();
    assert_eq!(server.join().unwrap(), bytes, "server received everything");
}

#[test]
fn without_administrator_rights_attribution_is_unavailable_and_nothing_crashes() {
    if is_elevated() {
        eprintln!("SKIPPED non-admin fallback test: this shell is elevated");
        return;
    }
    let started = Instant::now();
    let status = EtwNetworkCollector::start().err().expect("must not start");
    assert_eq!(status, NetworkStatus::RequiresAdmin);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the check must be immediate, not an ETW attempt that times out"
    );
    assert!(status.describe().contains("administrator"));

    // The metrics source works exactly as before, reporting network as *unavailable*, not zero.
    let mut src = WindowsMetricsSource::new();
    let me = std::process::id();
    let own = src.observe().into_iter().find(|o| o.pid == me).unwrap();
    assert_eq!((own.net_rx_bytes, own.net_tx_bytes), (None, None));

    let mut sampler = Sampler::new(src.logical_cpus());
    sampler.tick(&[own], Duration::ZERO);
    let own2 = src.observe().into_iter().find(|o| o.pid == me).unwrap();
    let out = sampler.tick(&[own2], Duration::from_secs(1));
    assert_eq!(out.samples[0].net_rx_bytes_per_sec, Metric::Unavailable);
    assert_eq!(out.samples[0].net_tx_bytes_per_sec, Metric::Unavailable);
}

#[test]
fn a_tcp_transfer_is_attributed_to_this_process() {
    if skip_unless_elevated("a_tcp_transfer_is_attributed_to_this_process") {
        return;
    }
    let collector = EtwNetworkCollector::start().expect("collector starts when elevated");
    let before = collector.snapshot().get(std::process::id());

    tcp_loopback_transfer(8 * MB);
    let want = (8 * MB) as u64 * 95 / 100;
    let (rx, tx) = totals_when(&collector, Duration::from_secs(10), |(rx, tx)| {
        rx - before.0 >= want && tx - before.1 >= want
    });

    // Loopback: this one process both sent and received the 8 MB.
    assert!(tx - before.1 >= want, "sent only {} bytes", tx - before.1);
    assert!(
        rx - before.0 >= want,
        "received only {} bytes",
        rx - before.0
    );
    // ...and it is not wildly over-counted either.
    assert!(
        tx - before.1 < (24 * MB) as u64,
        "tx over-counted: {}",
        tx - before.1
    );
}

#[test]
fn a_udp_transfer_is_attributed_to_this_process() {
    if skip_unless_elevated("a_udp_transfer_is_attributed_to_this_process") {
        return;
    }
    let collector = EtwNetworkCollector::start().expect("collector starts when elevated");
    let before = collector.snapshot().get(std::process::id());

    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let datagram = vec![9u8; 1_000];
    let count = 3_000usize;
    for _ in 0..count {
        sender.send_to(&datagram, target).unwrap();
    }

    let want_tx = (count * datagram.len()) as u64 * 95 / 100;
    let (rx, tx) = totals_when(&collector, Duration::from_secs(10), |(_, tx)| {
        tx - before.1 >= want_tx
    });
    assert!(
        tx - before.1 >= want_tx,
        "UDP/QUIC-style traffic must be counted: sent {} of {} bytes",
        tx - before.1,
        count * datagram.len()
    );
    // The receive side is best-effort on loopback (datagrams can be dropped), but must show up.
    assert!(rx - before.0 > 0, "no UDP receive events seen");
}

#[test]
fn the_metrics_source_turns_network_bytes_into_a_per_process_rate() {
    if skip_unless_elevated("the_metrics_source_turns_network_bytes_into_a_per_process_rate") {
        return;
    }
    let collector = EtwNetworkCollector::start().expect("collector starts when elevated");
    let mut src = WindowsMetricsSource::new().with_network(collector);
    let me = std::process::id();
    let mut sampler = Sampler::new(src.logical_cpus());

    let first = src.observe().into_iter().find(|o| o.pid == me).unwrap();
    assert!(
        first.net_rx_bytes.is_some(),
        "attribution active => counters present"
    );
    sampler.tick(&[first], Duration::ZERO);

    let t0 = Instant::now();
    tcp_loopback_transfer(16 * MB);
    std::thread::sleep(Duration::from_millis(500)); // let the trailing events arrive
    let second = src.observe().into_iter().find(|o| o.pid == me).unwrap();
    let out = sampler.tick(&[second], t0.elapsed());

    let Metric::Available(tx) = out.samples[0].net_tx_bytes_per_sec else {
        panic!(
            "expected an available rate, got {:?}",
            out.samples[0].net_tx_bytes_per_sec
        )
    };
    let expected = 16.0 * MB as f64 / t0.elapsed().as_secs_f64();
    assert!(
        tx > expected * 0.5 && tx < expected * 2.0,
        "tx rate {tx:.0} B/s vs ~{expected:.0} B/s"
    );
}

#[test]
fn the_session_exists_while_running_and_is_gone_after_drop() {
    if skip_unless_elevated("the_session_exists_while_running_and_is_gone_after_drop") {
        return;
    }
    let mine = format!("winperf-network-{}", std::process::id());
    {
        let _collector = EtwNetworkCollector::start().expect("collector starts when elevated");
        assert!(
            list_winperf_sessions().contains(&mine),
            "our session should be listed while running: {:?}",
            list_winperf_sessions()
        );
    }
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !list_winperf_sessions().contains(&mine),
        "dropping the collector must stop its kernel session (sessions otherwise outlive us)"
    );
}

#[test]
fn starting_twice_in_one_process_does_not_break_the_first_collector() {
    if skip_unless_elevated("starting_twice_in_one_process_does_not_break_the_first_collector") {
        return;
    }
    let first = EtwNetworkCollector::start().expect("collector starts when elevated");
    let second = EtwNetworkCollector::start();
    // Same session name in the same process: the second start must fail cleanly, not panic and
    // not silence the first.
    assert!(
        second.is_err(),
        "same-named session cannot be started twice"
    );
    let before = first.snapshot().get(std::process::id());
    tcp_loopback_transfer(2 * MB);
    let want = (2 * MB) as u64 * 9 / 10;
    let (_, tx) = totals_when(&first, Duration::from_secs(10), |(_, tx)| {
        tx - before.1 >= want
    });
    assert!(tx - before.1 >= want, "first collector still counts");
}

/// Not part of the normal run: prints what attribution costs under heavy loopback traffic.
#[test]
#[ignore = "overhead report; run elevated with --ignored --nocapture"]
fn etw_overhead_report() {
    if skip_unless_elevated("etw_overhead_report") {
        return;
    }
    let collector = EtwNetworkCollector::start().expect("collector starts when elevated");
    let me = std::process::id();
    let mut src = WindowsMetricsSource::new();
    let cpu_of = |src: &mut WindowsMetricsSource| {
        src.observe()
            .into_iter()
            .find(|o| o.pid == me)
            .map(|o| (o.cpu_time_100ns.unwrap(), o.working_set.unwrap()))
    };

    let (cpu0, ws0) = cpu_of(&mut src).unwrap();
    let started = Instant::now();
    let mut moved = 0usize;
    while started.elapsed() < Duration::from_secs(10) {
        tcp_loopback_transfer(32 * MB);
        moved += 32 * MB;
    }
    let wall = started.elapsed().as_secs_f64();
    let (cpu1, ws1) = cpu_of(&mut src).unwrap();
    let events_bytes = collector.snapshot().get(me);

    println!(
        "moved {:.0} MB over loopback in {wall:.1} s ({:.0} MB/s)",
        moved as f64 / MB as f64,
        moved as f64 / MB as f64 / wall
    );
    println!(
        "this process CPU during the run: {:.2} s of {wall:.1} s wall (includes the traffic generator itself)",
        (cpu1 - cpu0) as f64 / 1e7
    );
    println!(
        "working set growth: {:.1} MB",
        (ws1 as f64 - ws0 as f64) / MB as f64
    );
    println!(
        "attributed to this pid: rx {} MB, tx {} MB",
        events_bytes.0 as usize / MB,
        events_bytes.1 as usize / MB
    );
}
