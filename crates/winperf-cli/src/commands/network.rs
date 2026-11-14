//! `winperf network now`: which processes are using the network right now (needs administrator).

use std::io::{self, Write};
use std::time::Duration;
use winperf_core::Metric;
use winperf_core::engine::MetricsSource;
use winperf_core::sampling::{Observation, Sample, Sampler};

/// One process's network throughput over the measurement window.
#[derive(Debug, Clone, PartialEq)]
pub struct Talker {
    pub pid: u32,
    pub name: String,
    pub rx_per_sec: f64,
    pub tx_per_sec: f64,
}

impl Talker {
    fn total(&self) -> f64 {
        self.rx_per_sec + self.tx_per_sec
    }
}

/// Join samples with process names and keep the busiest `limit` processes. Processes whose
/// network rate is unavailable (no attribution) or exactly zero are left out.
pub fn top_talkers(observations: &[Observation], samples: &[Sample], limit: usize) -> Vec<Talker> {
    let mut talkers: Vec<Talker> = samples
        .iter()
        .filter_map(|s| {
            let (Metric::Available(rx), Metric::Available(tx)) =
                (s.net_rx_bytes_per_sec, s.net_tx_bytes_per_sec)
            else {
                return None;
            };
            if rx + tx <= 0.0 {
                return None;
            }
            let name = observations
                .iter()
                .find(|o| o.key() == Some(s.key))
                .map_or_else(|| "?".to_string(), |o| o.name.clone());
            Some(Talker {
                pid: s.key.pid,
                name,
                rx_per_sec: rx,
                tx_per_sec: tx,
            })
        })
        .collect();
    talkers.sort_by(|a, b| b.total().total_cmp(&a.total()));
    talkers.truncate(limit);
    talkers
}

fn rate(v: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    if v >= MIB {
        format!("{:.1} MB/s", v / MIB)
    } else if v >= KIB {
        format!("{:.1} KB/s", v / KIB)
    } else {
        format!("{v:.0} B/s")
    }
}

pub fn format_table(talkers: &[Talker], seconds: u64) -> String {
    if talkers.is_empty() {
        return format!("no process used the network during the {seconds} s measurement\n");
    }
    let mut out = format!(
        "{:>7}  {:<30} {:>12} {:>12}\n",
        "PID", "NAME", "RECEIVE", "SEND"
    );
    for t in talkers {
        out.push_str(&format!(
            "{:>7}  {:<30} {:>12} {:>12}\n",
            t.pid,
            t.name.chars().take(30).collect::<String>(),
            rate(t.rx_per_sec),
            rate(t.tx_per_sec)
        ));
    }
    out.push_str(&format!(
        "\naveraged over {seconds} s; includes loopback traffic; TCP and UDP\n"
    ));
    out
}

/// Observe twice, `seconds` apart, and return the busiest processes in between.
pub fn measure(
    source: &mut dyn MetricsSource,
    seconds: u64,
    sleep: impl Fn(Duration),
) -> Vec<Talker> {
    let mut sampler = Sampler::new(source.logical_cpus());
    sampler.tick(&source.observe(), Duration::ZERO);
    sleep(Duration::from_secs(seconds));
    let observations = source.observe();
    let out = sampler.tick(&observations, Duration::from_secs(seconds));
    top_talkers(&observations, &out.samples, 15)
}

pub fn now(source: &mut dyn MetricsSource, seconds: u64, out: &mut impl Write) -> io::Result<()> {
    let talkers = measure(source, seconds, std::thread::sleep);
    out.write_all(format_table(&talkers, seconds).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use winperf_core::ProcessKey;
    use winperf_core::inventory::RawProcess;

    fn obs(pid: u32, name: &str, rx: Option<u64>, tx: Option<u64>) -> Observation {
        Observation {
            pid,
            name: name.into(),
            start_time: Some(1),
            net_rx_bytes: rx,
            net_tx_bytes: tx,
            ..Default::default()
        }
    }

    fn sample(pid: u32, rx: Metric<f64>, tx: Metric<f64>) -> Sample {
        Sample {
            key: ProcessKey::new(pid, 1),
            cpu_percent: Metric::Unavailable,
            working_set: Metric::Unavailable,
            private_bytes: Metric::Unavailable,
            virtual_bytes: Metric::Unavailable,
            peak_working_set: Metric::Unavailable,
            io_read_bytes_per_sec: Metric::Unavailable,
            io_write_bytes_per_sec: Metric::Unavailable,
            io_read_ops_per_sec: Metric::Unavailable,
            io_write_ops_per_sec: Metric::Unavailable,
            net_rx_bytes_per_sec: rx,
            net_tx_bytes_per_sec: tx,
        }
    }

    use Metric::{Available as A, Unavailable as U};

    #[test]
    fn talkers_are_ranked_by_total_throughput_and_named() {
        let o = [
            obs(1, "slow.exe", None, None),
            obs(2, "fast.exe", None, None),
            obs(3, "mid.exe", None, None),
        ];
        let s = [
            sample(1, A(100.0), A(0.0)),
            sample(2, A(5_000.0), A(1_000.0)),
            sample(3, A(0.0), A(2_000.0)),
        ];
        let t = top_talkers(&o, &s, 10);
        assert_eq!(
            t.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            vec!["fast.exe", "mid.exe", "slow.exe"]
        );
        assert_eq!((t[0].rx_per_sec, t[0].tx_per_sec), (5_000.0, 1_000.0));
    }

    #[test]
    fn silent_and_unattributed_processes_are_left_out() {
        let o = [
            obs(1, "idle.exe", None, None),
            obs(2, "blind.exe", None, None),
            obs(3, "busy.exe", None, None),
        ];
        let s = [
            sample(1, A(0.0), A(0.0)), // measured, no traffic
            sample(2, U, U),           // no attribution at all
            sample(3, A(10.0), A(0.0)),
        ];
        let t = top_talkers(&o, &s, 10);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].name, "busy.exe");
    }

    #[test]
    fn the_list_is_capped() {
        let o: Vec<_> = (1..=20).map(|p| obs(p, "p.exe", None, None)).collect();
        let s: Vec<_> = (1..=20)
            .map(|p| sample(p, A(f64::from(p)), A(0.0)))
            .collect();
        let t = top_talkers(&o, &s, 5);
        assert_eq!(t.len(), 5);
        assert_eq!(t[0].pid, 20);
    }

    #[test]
    fn the_table_uses_readable_units_and_a_note_about_scope() {
        let t = vec![Talker {
            pid: 42,
            name: "browser.exe".into(),
            rx_per_sec: 3.0 * 1024.0 * 1024.0,
            tx_per_sec: 512.0,
        }];
        let text = format_table(&t, 5);
        assert!(
            text.contains("browser.exe") && text.contains("3.0 MB/s") && text.contains("512 B/s"),
            "{text}"
        );
        assert!(
            text.contains("averaged over 5 s") && text.contains("loopback"),
            "{text}"
        );
    }

    #[test]
    fn an_empty_result_says_so_instead_of_printing_an_empty_table() {
        assert!(format_table(&[], 5).contains("no process used the network"));
    }

    /// Two scripted rounds with cumulative counters.
    struct Script(Vec<Vec<Observation>>);
    impl MetricsSource for Script {
        fn logical_cpus(&self) -> u32 {
            4
        }
        fn observe(&mut self) -> Vec<Observation> {
            self.0.remove(0)
        }
        fn describe(&mut self, _: &Observation) -> RawProcess {
            RawProcess::default()
        }
    }

    #[test]
    fn measure_turns_two_counter_snapshots_into_rates() {
        let mut src = Script(vec![
            vec![obs(1, "a.exe", Some(0), Some(0))],
            vec![obs(1, "a.exe", Some(10_000), Some(2_000))],
        ]);
        let slept = Cell::new(Duration::ZERO);
        let t = measure(&mut src, 5, |d| slept.set(d));
        assert_eq!(slept.get(), Duration::from_secs(5));
        assert_eq!(
            t,
            vec![Talker {
                pid: 1,
                name: "a.exe".into(),
                rx_per_sec: 2_000.0,
                tx_per_sec: 400.0
            }]
        );
    }

    #[test]
    fn without_attribution_measure_finds_no_talkers() {
        let mut src = Script(vec![
            vec![obs(1, "a.exe", None, None)],
            vec![obs(1, "a.exe", None, None)],
        ]);
        assert!(measure(&mut src, 1, |_| {}).is_empty());
    }
}
