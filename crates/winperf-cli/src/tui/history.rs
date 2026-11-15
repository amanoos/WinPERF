//! The System History screen (PRD FR-020 F): time-series graphs of CPU, memory, disk and network
//! over a selectable range (15 minutes to 24 hours), drawn from the stored system samples. A
//! read-only view of the database; the monitor or service writes the samples.
//!
//! Each graph is a sparkline: the range is cut into as many equal slices as the graph is wide and
//! each slice shows the average of the samples in it. A slice with no samples is left blank, so a
//! gap in monitoring shows as a gap, not as zero.

use crate::tui::baselines::Nav;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Sparkline, Wrap};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use winperf_core::anomaly::format::bytes;
use winperf_core::time::unix_millis_now;
use winperf_storage::{Database, StoredSystemSample};

/// How often the samples are re-read while the screen is open.
const REFRESH: Duration = Duration::from_secs(5);

const MINUTE: i64 = 60_000;

/// The selectable ranges: label and length in milliseconds.
pub const RANGES: [(&str, i64); 4] = [
    ("15 minutes", 15 * MINUTE),
    ("1 hour", 60 * MINUTE),
    ("6 hours", 6 * 60 * MINUTE),
    ("24 hours", 24 * 60 * MINUTE),
];

/// Where the screen reads from.
#[derive(Debug, Clone)]
pub struct HistorySource {
    pub db_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Graph {
    Cpu,
    Memory,
    Disk,
    Network,
}

impl Graph {
    pub const ALL: [Graph; 4] = [Graph::Cpu, Graph::Memory, Graph::Disk, Graph::Network];

    fn name(self) -> &'static str {
        match self {
            Graph::Cpu => "CPU",
            Graph::Memory => "Memory in use",
            Graph::Disk => "Disk I/O",
            Graph::Network => "Network",
        }
    }

    /// Percentages are drawn against a fixed 0 to 100 scale; rates scale to their own peak.
    fn is_percent(self) -> bool {
        matches!(self, Graph::Cpu | Graph::Memory)
    }

    fn color(self) -> Color {
        match self {
            Graph::Cpu => Color::Cyan,
            Graph::Memory => Color::Magenta,
            Graph::Disk => Color::Yellow,
            Graph::Network => Color::Green,
        }
    }

    fn show(self, v: f64) -> String {
        if self.is_percent() {
            format!("{v:.1}%")
        } else {
            format!("{}/s", bytes(v))
        }
    }

    /// This graph's value in one sample, if it was measured: CPU and memory as percent, disk and
    /// network as the two directions added together.
    fn value(self, s: &StoredSystemSample) -> Option<f64> {
        let both = |a: Option<f64>, b: Option<f64>| match (a, b) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0.0) + b.unwrap_or(0.0)),
        };
        match self {
            Graph::Cpu => s.cpu_percent,
            Graph::Memory => match (s.memory_total_bytes, s.memory_available_bytes) {
                (Some(total), Some(avail)) if total > 0 => {
                    Some((1.0 - avail.min(total) as f64 / total as f64) * 100.0)
                }
                _ => None,
            },
            Graph::Disk => both(s.disk_read_bytes_per_sec, s.disk_write_bytes_per_sec),
            Graph::Network => both(s.net_rx_bytes_per_sec, s.net_tx_bytes_per_sec),
        }
    }
}

/// `(time, value)` for every sample in which the graph's value was measured.
pub fn series(samples: &[StoredSystemSample], graph: Graph) -> Vec<(i64, f64)> {
    samples
        .iter()
        .filter_map(|s| graph.value(s).map(|v| (s.ts_ms, v)))
        .collect()
}

/// Cut `[from, to)` into `buckets` equal slices and average the points in each. A slice with no
/// points is `None`. Points outside the range are ignored.
pub fn downsample(
    points: &[(i64, f64)],
    from_ms: i64,
    to_ms: i64,
    buckets: usize,
) -> Vec<Option<f64>> {
    if buckets == 0 || to_ms <= from_ms {
        return Vec::new();
    }
    let span = (to_ms - from_ms) as f64;
    let mut sum = vec![0.0; buckets];
    let mut count = vec![0u32; buckets];
    for (ts, v) in points {
        if *ts < from_ms || *ts >= to_ms {
            continue;
        }
        let slot = (((*ts - from_ms) as f64 / span) * buckets as f64) as usize;
        let slot = slot.min(buckets - 1);
        sum[slot] += v;
        count[slot] += 1;
    }
    sum.iter()
        .zip(&count)
        .map(|(s, c)| (*c > 0).then(|| s / f64::from(*c)))
        .collect()
}

/// The latest, average and peak value of a series.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub now: f64,
    pub avg: f64,
    pub max: f64,
}

pub fn summarize(points: &[(i64, f64)]) -> Option<Summary> {
    let now = points.last()?.1;
    let avg = points.iter().map(|p| p.1).sum::<f64>() / points.len() as f64;
    let max = points.iter().map(|p| p.1).fold(f64::MIN, f64::max);
    Some(Summary { now, avg, max })
}

pub struct HistoryView {
    source: Option<HistorySource>,
    /// Index into [`RANGES`].
    pub range: usize,
    pub samples: Vec<StoredSystemSample>,
    /// Wall clock when the samples were read: the right edge of the graphs.
    pub now_ms: i64,
    pub problem: Option<String>,
    loaded_at: Option<Instant>,
    stale: bool,
}

impl HistoryView {
    pub fn new(source: Option<HistorySource>) -> Self {
        Self {
            source,
            range: 1,
            samples: Vec::new(),
            now_ms: 0,
            problem: None,
            loaded_at: None,
            stale: true,
        }
    }

    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    pub fn range_ms(&self) -> i64 {
        RANGES[self.range].1
    }

    pub fn refresh_if_due(&mut self) -> bool {
        let due = self.stale || self.loaded_at.is_none_or(|t| t.elapsed() >= REFRESH);
        if !due || self.source.is_none() {
            return false;
        }
        self.load();
        true
    }

    fn load(&mut self) {
        self.stale = false;
        self.loaded_at = Some(Instant::now());
        let Some(source) = &self.source else { return };
        let now = unix_millis_now();
        if !source.db_path.exists() {
            self.problem = Some(format!(
                "no database at {} yet. Run `winperf monitor run` first.",
                source.db_path.display()
            ));
            self.set_samples(Vec::new(), now);
            return;
        }
        let from = now - self.range_ms();
        match Database::open_read_only(&source.db_path)
            .and_then(|db| db.system_samples_between(from, now))
        {
            Ok(samples) => {
                self.problem = None;
                self.set_samples(samples, now);
            }
            Err(e) => {
                self.problem = Some(e.to_string());
                self.set_samples(Vec::new(), now);
            }
        }
    }

    pub fn set_samples(&mut self, samples: Vec<StoredSystemSample>, now_ms: i64) {
        self.samples = samples;
        self.now_ms = now_ms;
    }

    fn pick_range(&mut self, index: usize) {
        if index < RANGES.len() && index != self.range {
            self.range = index;
            self.stale = true;
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return Nav::Quit,
            (KeyCode::Char('q'), _) => return Nav::Quit,
            (KeyCode::Esc | KeyCode::Char('h'), _) => return Nav::Back,
            (KeyCode::Right | KeyCode::Tab | KeyCode::Char(']'), _) => {
                self.pick_range((self.range + 1) % RANGES.len());
            }
            (KeyCode::Left | KeyCode::BackTab | KeyCode::Char('['), _) => {
                self.pick_range((self.range + RANGES.len() - 1) % RANGES.len());
            }
            (KeyCode::Char(c @ '1'..='4'), _) => self.pick_range(usize::from(c as u8 - b'1')),
            (KeyCode::Char('l'), _) => self.stale = true,
            _ => {}
        }
        Nav::Stay
    }
}

// ---- drawing -------------------------------------------------------------------------------

fn axis(range_label: &str, width: u16) -> String {
    let left = format!("-{range_label}");
    let right = "now";
    let pad = usize::from(width).saturating_sub(left.chars().count() + right.len() + 2);
    format!(" {left}{}{right}", " ".repeat(pad))
}

pub fn draw(f: &mut Frame, area: Rect, view: &mut HistoryView) {
    let [title, body, axis_area, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);

    let (range_label, range_ms) = RANGES[view.range];
    let ranges: String = RANGES
        .iter()
        .enumerate()
        .map(|(i, (label, _))| {
            if i == view.range {
                format!("[{} {label}]", i + 1)
            } else {
                format!(" {} {label} ", i + 1)
            }
        })
        .collect::<Vec<_>>()
        .join("");
    f.render_widget(
        Paragraph::new(Line::from(vec![
            ratatui::text::Span::styled(" WinPerf ", Style::new().bold().fg(Color::Cyan)),
            ratatui::text::Span::raw(format!("System history  {ranges}")),
        ])),
        title,
    );

    if view.samples.is_empty() {
        let text = view.problem.clone().unwrap_or_else(|| {
            format!(
                "No system samples in the last {range_label}. Samples are written by `winperf \
                 monitor run` (or the service); try a longer range."
            )
        });
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), body);
    } else {
        let panels = Layout::vertical([Constraint::Ratio(1, 4); 4]).split(body);
        let (from, to) = (view.now_ms - range_ms, view.now_ms);
        for (graph, panel) in Graph::ALL.iter().zip(panels.iter()) {
            draw_graph(f, *panel, *graph, &view.samples, from, to);
        }
    }

    f.render_widget(
        Paragraph::new(axis(range_label, axis_area.width)).style(Style::new().fg(Color::DarkGray)),
        axis_area,
    );
    f.render_widget(
        Paragraph::new(" q quit  h back  ←→ or 1-4 range  l reload")
            .style(Style::new().fg(Color::DarkGray)),
        footer,
    );
}

fn draw_graph(
    f: &mut Frame,
    area: Rect,
    graph: Graph,
    samples: &[StoredSystemSample],
    from_ms: i64,
    to_ms: i64,
) {
    let points = series(samples, graph);
    let title = match summarize(&points) {
        Some(s) => format!(
            " {}   now {}   avg {}   max {} ",
            graph.name(),
            graph.show(s.now),
            graph.show(s.avg),
            graph.show(s.max)
        ),
        None => format!(" {}   not measured ", graph.name()),
    };
    let block = Block::bordered().title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);
    if points.is_empty() || inner.width == 0 || inner.height == 0 {
        return;
    }
    let buckets = downsample(&points, from_ms, to_ms, usize::from(inner.width));
    let data: Vec<Option<u64>> = buckets
        .iter()
        .map(|b| b.map(|v| v.round().max(0.0) as u64))
        .collect();
    let mut spark = Sparkline::default()
        .data(data)
        .style(Style::new().fg(graph.color()));
    if graph.is_percent() {
        spark = spark.max(100);
    }
    f.render_widget(spark, inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    const NOW: i64 = 10_000_000;

    fn sample(ts: i64, cpu: Option<f64>) -> StoredSystemSample {
        StoredSystemSample {
            ts_ms: ts,
            cpu_percent: cpu,
            memory_total_bytes: Some(1000),
            memory_available_bytes: Some(400),
            commit_used_bytes: None,
            commit_limit_bytes: None,
            disk_utilization_percent: None,
            disk_queue_length: None,
            disk_read_bytes_per_sec: Some(2.0 * 1024.0 * 1024.0),
            disk_write_bytes_per_sec: Some(1.0 * 1024.0 * 1024.0),
            disk_latency_ms: None,
            net_rx_bytes_per_sec: Some(100.0),
            net_tx_bytes_per_sec: None,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn screen(v: &mut HistoryView, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, f.area(), v)).unwrap();
        let buf = terminal.backend().buffer();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn view_with(samples: Vec<StoredSystemSample>) -> HistoryView {
        let mut v = HistoryView::new(None);
        v.set_samples(samples, NOW);
        v
    }

    // ---- the maths ------------------------------------------------------------------------

    #[test]
    fn each_graph_reads_its_own_value_from_a_sample() {
        let s = sample(1, Some(40.0));
        assert_eq!(Graph::Cpu.value(&s), Some(40.0));
        assert_eq!(Graph::Memory.value(&s), Some(60.0), "600 of 1000 in use");
        assert_eq!(
            Graph::Disk.value(&s),
            Some(3.0 * 1024.0 * 1024.0),
            "read + write"
        );
        assert_eq!(
            Graph::Network.value(&s),
            Some(100.0),
            "one direction measured is enough"
        );
    }

    #[test]
    fn unmeasured_values_are_skipped_not_drawn_as_zero() {
        let mut s = sample(1, None);
        s.net_rx_bytes_per_sec = None;
        s.memory_total_bytes = None;
        s.disk_read_bytes_per_sec = None;
        s.disk_write_bytes_per_sec = None;
        assert_eq!(Graph::Cpu.value(&s), None);
        assert_eq!(Graph::Network.value(&s), None);
        assert_eq!(Graph::Memory.value(&s), None);
        assert_eq!(Graph::Disk.value(&s), None);
        let all = [sample(1, Some(10.0)), sample(2, None)];
        assert_eq!(series(&all, Graph::Cpu), vec![(1, 10.0)]);
    }

    #[test]
    fn downsampling_averages_each_slice_and_leaves_gaps_empty() {
        // 0..100 in 4 slices of 25: values at 5, 10 (slice 0), none in 1, 60 (slice 2), 99 (slice 3).
        let pts = [(5, 10.0), (10, 30.0), (60, 50.0), (99, 80.0)];
        let d = downsample(&pts, 0, 100, 4);
        assert_eq!(d, vec![Some(20.0), None, Some(50.0), Some(80.0)]);
    }

    #[test]
    fn downsampling_ignores_points_outside_the_range_and_handles_edges() {
        let pts = [(-5, 1.0), (0, 2.0), (100, 3.0), (150, 4.0)];
        assert_eq!(downsample(&pts, 0, 100, 2), vec![Some(2.0), None]);
        assert!(downsample(&pts, 0, 100, 0).is_empty());
        assert!(downsample(&pts, 100, 100, 5).is_empty());
        assert_eq!(downsample(&[], 0, 100, 3), vec![None, None, None]);
    }

    #[test]
    fn the_summary_is_latest_average_and_peak() {
        let s = summarize(&[(1, 10.0), (2, 50.0), (3, 30.0)]).unwrap();
        assert_eq!(
            s,
            Summary {
                now: 30.0,
                avg: 30.0,
                max: 50.0
            }
        );
        assert_eq!(summarize(&[]), None);
    }

    // ---- keys -----------------------------------------------------------------------------

    #[test]
    fn it_opens_on_one_hour_and_the_range_can_be_changed() {
        let mut v = HistoryView::new(None);
        assert_eq!(RANGES[v.range].0, "1 hour");
        v.on_key(key(KeyCode::Right));
        assert_eq!(RANGES[v.range].0, "6 hours");
        v.on_key(KeyCode::Char(']').into());
        assert_eq!(RANGES[v.range].0, "24 hours");
        v.on_key(key(KeyCode::Right));
        assert_eq!(RANGES[v.range].0, "15 minutes", "wraps around");
        v.on_key(key(KeyCode::Left));
        assert_eq!(RANGES[v.range].0, "24 hours");
        v.on_key(KeyCode::Char('2').into());
        assert_eq!(RANGES[v.range].0, "1 hour");
        v.on_key(KeyCode::Char('4').into());
        assert_eq!(RANGES[v.range].0, "24 hours");
        assert_eq!(v.range_ms(), 24 * 60 * MINUTE);
    }

    #[test]
    fn changing_the_range_asks_for_a_reload_but_pressing_the_same_one_does_not() {
        let mut v = HistoryView::new(Some(HistorySource {
            db_path: std::env::temp_dir().join("winperf-history-nonexistent.db"),
        }));
        assert!(v.refresh_if_due());
        assert!(!v.refresh_if_due());
        v.on_key(KeyCode::Char('2').into()); // already on 1 hour
        assert!(!v.refresh_if_due());
        v.on_key(KeyCode::Char('1').into());
        assert!(v.refresh_if_due(), "a new range needs new data");
    }

    #[test]
    fn exit_keys() {
        let mut v = HistoryView::new(None);
        assert_eq!(v.on_key(key(KeyCode::Esc)), Nav::Back);
        assert_eq!(v.on_key(KeyCode::Char('h').into()), Nav::Back);
        assert_eq!(v.on_key(KeyCode::Char('q').into()), Nav::Quit);
        assert_eq!(
            v.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Nav::Quit
        );
    }

    // ---- drawing --------------------------------------------------------------------------

    fn steady(n: i64) -> Vec<StoredSystemSample> {
        // One sample a minute over the last `n` minutes, CPU climbing from 10 to 90.
        (0..n)
            .map(|i| {
                sample(
                    NOW - (n - i) * MINUTE,
                    Some(10.0 + 80.0 * i as f64 / (n - 1) as f64),
                )
            })
            .collect()
    }

    #[test]
    fn four_graphs_are_drawn_with_now_average_and_peak() {
        let mut v = view_with(steady(60));
        let s = screen(&mut v, 100, 28);
        for expected in [
            "System history",
            "[2 1 hour]",
            " 1 15 minutes ",
            "CPU",
            "Memory in use",
            "Disk I/O",
            "Network",
            "now 90.0%",
            "max 90.0%",
            "now 60.0%",
            "now 3.0 MiB/s",
            "now 100 B/s",
            "-1 hour",
            "now",
            "range",
        ] {
            assert!(s.contains(expected), "missing {expected:?} in\n{s}");
        }
        // A climbing CPU line draws bars from low to full height.
        assert!(s.contains('▁') || s.contains('▂'), "{s}");
        assert!(s.contains('█'), "{s}");
    }

    #[test]
    fn a_gap_in_monitoring_is_left_blank_not_drawn_as_zero() {
        // Samples only in the first and last quarter of the hour.
        let mut samples = Vec::new();
        for m in 0..15 {
            samples.push(sample(NOW - 60 * MINUTE + m * MINUTE, Some(100.0)));
            samples.push(sample(NOW - 15 * MINUTE + m * MINUTE, Some(100.0)));
        }
        let mut v = view_with(samples);
        let s = screen(&mut v, 82, 28);
        let cpu_row = s
            .lines()
            .find(|l| l.contains('█'))
            .expect("a graph row with full bars");
        assert!(cpu_row.contains('█'), "{cpu_row}");
        // The middle of the graph has no bars at all.
        let inner: Vec<char> = cpu_row.chars().skip(1).collect();
        let middle: String = inner[inner.len() / 3..2 * inner.len() / 3].iter().collect();
        assert!(!middle.contains('█'), "gap should be empty: {cpu_row}");
    }

    #[test]
    fn an_empty_range_explains_itself_and_names_the_range() {
        let mut v = view_with(Vec::new());
        let s = screen(&mut v, 100, 20);
        assert!(s.contains("No system samples in the last 1 hour"), "{s}");
        assert!(s.contains("monitor run"), "{s}");
        v.on_key(KeyCode::Char('1').into());
        assert!(screen(&mut v, 100, 20).contains("last 15 minutes"));
    }

    #[test]
    fn a_metric_that_was_never_measured_says_so() {
        let mut samples = steady(10);
        for s in &mut samples {
            s.net_rx_bytes_per_sec = None;
            s.net_tx_bytes_per_sec = None;
        }
        let mut v = view_with(samples);
        let s = screen(&mut v, 100, 28);
        assert!(s.contains("Network   not measured"), "{s}");
        assert!(
            s.contains("now 90.0%"),
            "the other graphs are unaffected: {s}"
        );
    }

    #[test]
    fn a_missing_database_is_explained() {
        let mut v = HistoryView::new(Some(HistorySource {
            db_path: std::env::temp_dir().join("winperf-no-such-history.db"),
        }));
        assert!(v.refresh_if_due());
        assert!(screen(&mut v, 100, 20).contains("no database at"));
    }

    #[test]
    fn the_graphs_fit_the_smallest_supported_screen() {
        let mut v = view_with(steady(60));
        let s = screen(&mut v, 80, 24);
        assert!(
            s.contains("CPU") && s.contains("Network") && s.contains("-1 hour"),
            "{s}"
        );
    }
}
