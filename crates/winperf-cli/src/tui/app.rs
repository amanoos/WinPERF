//! TUI state and behaviour, independent of drawing and of the terminal: feed it engine batches
//! and key presses, read back what to show. Everything here is unit-tested without a terminal.

use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::widgets::TableState;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::Duration;
use winperf_core::engine::{TickBatch, TickStats};
use winperf_core::network::NetworkStatus;
use winperf_core::sampling::Sample;
use winperf_core::system::SystemSample;
use winperf_core::{Metric, ProcessKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Cpu,
    Memory,
    Io,
    Network,
    Pid,
    Name,
}

impl SortColumn {
    pub fn label(self) -> &'static str {
        match self {
            SortColumn::Cpu => "CPU",
            SortColumn::Memory => "memory",
            SortColumn::Io => "I/O",
            SortColumn::Network => "network",
            SortColumn::Pid => "PID",
            SortColumn::Name => "name",
        }
    }

    /// Text and numbers read naturally ascending; every resource column starts with the biggest.
    fn default_descending(self) -> bool {
        !matches!(self, SortColumn::Pid | SortColumn::Name)
    }

    /// The sortable columns, left to right as they appear in the table.
    pub const DISPLAY_ORDER: [SortColumn; 6] = [
        SortColumn::Pid,
        SortColumn::Name,
        SortColumn::Cpu,
        SortColumn::Memory,
        SortColumn::Io,
        SortColumn::Network,
    ];

    /// The neighbouring column (wrapping around), for ←/→ and Tab.
    pub fn step(self, delta: isize) -> SortColumn {
        let n = Self::DISPLAY_ORDER.len() as isize;
        let at = Self::DISPLAY_ORDER
            .iter()
            .position(|c| *c == self)
            .unwrap_or(0) as isize;
        Self::DISPLAY_ORDER[(at + delta).rem_euclid(n) as usize]
    }
}

/// One process instance as shown in the table.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessRow {
    pub key: ProcessKey,
    pub name: String,
    pub cpu: Metric<f64>,
    /// Private bytes (committed memory the process owns).
    pub memory: Metric<u64>,
    /// Process-level read + write rate. `Partial`: includes non-disk I/O.
    pub io: Metric<f64>,
    /// Network receive + send rate (needs administrator attribution).
    pub network: Metric<f64>,
}

/// Sum two rates, keeping the weaker reliability, and `Unavailable` unless both are known.
fn add(a: Metric<f64>, b: Metric<f64>) -> Metric<f64> {
    match (a, b) {
        (Metric::Available(x), Metric::Available(y)) => Metric::Available(x + y),
        (Metric::Available(x) | Metric::Partial(x), Metric::Available(y) | Metric::Partial(y)) => {
            Metric::Partial(x + y)
        }
        _ => Metric::Unavailable,
    }
}

impl ProcessRow {
    fn from_sample(name: String, s: &Sample) -> Self {
        Self {
            key: s.key,
            name,
            cpu: s.cpu_percent,
            memory: s.private_bytes,
            io: add(s.io_read_bytes_per_sec, s.io_write_bytes_per_sec),
            network: add(s.net_rx_bytes_per_sec, s.net_tx_bytes_per_sec),
        }
    }

    fn sort_value(&self, column: SortColumn) -> Option<f64> {
        match column {
            SortColumn::Cpu => self.cpu.value().copied(),
            SortColumn::Memory => self.memory.value().map(|v| *v as f64),
            SortColumn::Io => self.io.value().copied(),
            SortColumn::Network => self.network.value().copied(),
            SortColumn::Pid => Some(f64::from(self.key.pid)),
            SortColumn::Name => None, // compared as text
        }
    }
}

/// How the monitor is doing, for the status line.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Status {
    pub ticks: u64,
    pub last_took: Duration,
    pub unreadable: usize,
}

pub struct App {
    rows: HashMap<ProcessKey, ProcessRow>,
    pub system: Option<SystemSample>,
    pub status: Status,
    pub interval: Duration,
    pub network: NetworkStatus,
    pub sort: SortColumn,
    pub descending: bool,
    pub table: TableState,
    selected: Option<ProcessKey>,
    /// Rows visible in the table at the last draw; PageUp/PageDown jump by this much.
    pub page_size: usize,
    pub should_quit: bool,
    /// Where each sortable column header was drawn last time: `(column, x_start, x_end)`, plus the
    /// header's screen row. Filled in by the renderer, used to turn mouse clicks into sorting.
    pub header_hits: Vec<(SortColumn, u16, u16)>,
    pub header_y: u16,
}

impl App {
    pub fn new(interval: Duration, network: NetworkStatus) -> Self {
        Self {
            rows: HashMap::new(),
            system: None,
            status: Status::default(),
            interval,
            network,
            sort: SortColumn::Cpu,
            descending: true,
            table: TableState::default(),
            selected: None,
            page_size: 10,
            should_quit: false,
            header_hits: Vec::new(),
            header_y: 0,
        }
    }

    /// Fold one engine tick into the view.
    pub fn apply_batch(&mut self, batch: &TickBatch) {
        let names: HashMap<ProcessKey, &str> = batch
            .new
            .iter()
            .filter_map(|r| {
                r.start_time
                    .map(|s| (ProcessKey::new(r.pid, s), r.name.as_str()))
            })
            .collect();
        for sample in &batch.samples {
            let name = names
                .get(&sample.key)
                .map(|n| (*n).to_string())
                .or_else(|| self.rows.get(&sample.key).map(|r| r.name.clone()))
                .unwrap_or_else(|| "?".to_string());
            self.rows
                .insert(sample.key, ProcessRow::from_sample(name, sample));
        }
        for gone in &batch.gone {
            self.rows.remove(gone);
        }
        if batch.system.is_some() {
            self.system = batch.system.clone();
        }
    }

    pub fn apply_stats(&mut self, stats: &TickStats) {
        self.status.ticks += 1;
        self.status.last_took = stats.took;
        self.status.unreadable = stats.unreadable;
    }

    pub fn process_count(&self) -> usize {
        self.rows.len()
    }

    /// Rows in display order. Rows whose sort value is unavailable always go last, in either
    /// direction, so "n/a" never floats to the top.
    pub fn sorted(&self) -> Vec<&ProcessRow> {
        let mut rows: Vec<&ProcessRow> = self.rows.values().collect();
        let (column, descending) = (self.sort, self.descending);
        rows.sort_by(|a, b| {
            let primary = if column == SortColumn::Name {
                let o = a.name.to_lowercase().cmp(&b.name.to_lowercase());
                if descending { o.reverse() } else { o }
            } else {
                match (a.sort_value(column), b.sort_value(column)) {
                    (Some(x), Some(y)) => {
                        let o = x.total_cmp(&y);
                        if descending { o.reverse() } else { o }
                    }
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                }
            };
            primary
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.key.cmp(&b.key))
        });
        rows
    }

    #[cfg(test)]
    pub fn selected_key(&self) -> Option<ProcessKey> {
        self.selected
    }

    /// Point the table cursor at the selected process (or the first row), so the selection
    /// follows a process as the order changes between ticks.
    pub fn sync_table(&mut self) {
        let keys: Vec<ProcessKey> = self.sorted().iter().map(|r| r.key).collect();
        let index = self
            .selected
            .and_then(|k| keys.iter().position(|x| *x == k))
            .or(if keys.is_empty() { None } else { Some(0) });
        self.selected = index.map(|i| keys[i]);
        self.table.select(index);
    }

    fn move_selection(&mut self, delta: isize) {
        let keys: Vec<ProcessKey> = self.sorted().iter().map(|r| r.key).collect();
        if keys.is_empty() {
            return;
        }
        let current = self
            .selected
            .and_then(|k| keys.iter().position(|x| *x == k))
            .unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, keys.len() as isize - 1) as usize;
        self.selected = Some(keys[next]);
    }

    fn select_edge(&mut self, last: bool) {
        let keys: Vec<ProcessKey> = self.sorted().iter().map(|r| r.key).collect();
        self.selected = if last { keys.last() } else { keys.first() }.copied();
    }

    fn sort_by(&mut self, column: SortColumn) {
        if self.sort == column {
            self.descending = !self.descending;
        } else {
            self.sort = column;
            self.descending = column.default_descending();
        }
    }

    /// Mouse: click a column header to sort by it (click again to flip), click a row to select it,
    /// wheel to scroll the selection.
    pub fn on_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if mouse.row == self.header_y {
                    let hit = self
                        .header_hits
                        .iter()
                        .find(|(_, start, end)| mouse.column >= *start && mouse.column < *end)
                        .map(|(column, _, _)| *column);
                    if let Some(column) = hit {
                        self.sort_by(column);
                    }
                } else if mouse.row > self.header_y {
                    let visible = self.page_size;
                    let line = usize::from(mouse.row - self.header_y - 1);
                    if line < visible {
                        let index = self.table.offset() + line;
                        let keys: Vec<ProcessKey> = self.sorted().iter().map(|r| r.key).collect();
                        if let Some(key) = keys.get(index) {
                            self.selected = Some(*key);
                        }
                    }
                }
            }
            MouseEventKind::ScrollUp => self.move_selection(-3),
            MouseEventKind::ScrollDown => self.move_selection(3),
            _ => {}
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        let page = self.page_size.max(1) as isize;
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => self.should_quit = true,
            (KeyCode::Char('q') | KeyCode::Esc, _) => self.should_quit = true,
            (KeyCode::Up | KeyCode::Char('k'), _) => self.move_selection(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => self.move_selection(1),
            (KeyCode::PageUp, _) => self.move_selection(-page),
            (KeyCode::PageDown, _) => self.move_selection(page),
            (KeyCode::Home | KeyCode::Char('g'), _) => self.select_edge(false),
            (KeyCode::End | KeyCode::Char('G'), _) => self.select_edge(true),
            // Move the sort column across the headers; Enter/Space flips its direction.
            (KeyCode::Right | KeyCode::Tab, _) => self.sort_by(self.sort.step(1)),
            (KeyCode::Left | KeyCode::BackTab, _) => self.sort_by(self.sort.step(-1)),
            (KeyCode::Enter | KeyCode::Char(' '), _) => self.descending = !self.descending,
            (KeyCode::Char('c'), _) => self.sort_by(SortColumn::Cpu),
            (KeyCode::Char('m'), _) => self.sort_by(SortColumn::Memory),
            (KeyCode::Char('i'), _) => self.sort_by(SortColumn::Io),
            (KeyCode::Char('n'), _) => self.sort_by(SortColumn::Network),
            (KeyCode::Char('p'), _) => self.sort_by(SortColumn::Pid),
            (KeyCode::Char('a'), _) => self.sort_by(SortColumn::Name),
            (KeyCode::Char('r'), _) => self.descending = !self.descending,
            _ => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use winperf_core::inventory::RawProcess;

    pub(crate) fn sample(pid: u32, cpu: Metric<f64>, mem: Metric<u64>) -> Sample {
        Sample {
            key: ProcessKey::new(pid, 1),
            cpu_percent: cpu,
            working_set: Metric::Unavailable,
            private_bytes: mem,
            virtual_bytes: Metric::Unavailable,
            peak_working_set: Metric::Unavailable,
            io_read_bytes_per_sec: Metric::Unavailable,
            io_write_bytes_per_sec: Metric::Unavailable,
            io_read_ops_per_sec: Metric::Unavailable,
            io_write_ops_per_sec: Metric::Unavailable,
            net_rx_bytes_per_sec: Metric::Unavailable,
            net_tx_bytes_per_sec: Metric::Unavailable,
        }
    }

    fn raw(pid: u32, name: &str) -> RawProcess {
        RawProcess {
            pid,
            name: name.into(),
            start_time: Some(1),
            ..Default::default()
        }
    }

    pub(crate) fn batch(procs: &[(u32, &str, Metric<f64>, Metric<u64>)]) -> TickBatch {
        TickBatch {
            ts_ms: 0,
            new: procs.iter().map(|(p, n, _, _)| raw(*p, n)).collect(),
            samples: procs
                .iter()
                .map(|(p, _, c, m)| sample(*p, *c, *m))
                .collect(),
            gone: vec![],
            system: None,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    use Metric::{Available as A, Unavailable as U};

    fn app() -> App {
        App::new(Duration::from_secs(2), NetworkStatus::RequiresAdmin)
    }

    fn names(app: &App) -> Vec<String> {
        app.sorted().iter().map(|r| r.name.clone()).collect()
    }

    #[test]
    fn a_batch_creates_named_rows_and_later_batches_update_them() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (1, "a.exe", A(5.0), A(100)),
            (2, "b.exe", A(9.0), A(200)),
        ]));
        assert_eq!(a.process_count(), 2);

        // A later tick has samples only (no `new`): names persist, values update.
        let mut next = batch(&[(1, "a.exe", A(50.0), A(110))]);
        next.new.clear();
        a.apply_batch(&next);
        let r = a.sorted().into_iter().find(|r| r.key.pid == 1).unwrap();
        assert_eq!((r.name.as_str(), r.cpu), ("a.exe", A(50.0)));
        assert_eq!(r.memory, A(110));
    }

    #[test]
    fn exited_processes_disappear() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (1, "a.exe", A(1.0), A(1)),
            (2, "b.exe", A(2.0), A(2)),
        ]));
        let mut b = batch(&[]);
        b.gone = vec![ProcessKey::new(1, 1)];
        a.apply_batch(&b);
        assert_eq!(names(&a), vec!["b.exe"]);
    }

    #[test]
    fn the_default_order_is_cpu_descending() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (1, "low.exe", A(1.0), A(0)),
            (2, "high.exe", A(90.0), A(0)),
            (3, "mid.exe", A(20.0), A(0)),
        ]));
        assert_eq!(names(&a), vec!["high.exe", "mid.exe", "low.exe"]);
    }

    #[test]
    fn unavailable_values_sort_last_in_either_direction() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (1, "blind.exe", U, A(0)),
            (2, "busy.exe", A(50.0), A(0)),
            (3, "idle.exe", A(0.0), A(0)),
        ]));
        assert_eq!(names(&a), vec!["busy.exe", "idle.exe", "blind.exe"]);
        a.on_key(ch('r')); // ascending
        assert_eq!(names(&a), vec!["idle.exe", "busy.exe", "blind.exe"]);
    }

    #[test]
    fn sort_keys_pick_columns_and_a_repeat_flips_the_direction() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (30, "c.exe", A(1.0), A(300)),
            (10, "a.exe", A(3.0), A(100)),
            (20, "B.exe", A(2.0), A(200)),
        ]));
        a.on_key(ch('m'));
        assert_eq!(
            names(&a),
            vec!["c.exe", "B.exe", "a.exe"],
            "memory, biggest first"
        );
        a.on_key(ch('m'));
        assert_eq!(
            names(&a),
            vec!["a.exe", "B.exe", "c.exe"],
            "same key reverses"
        );
        a.on_key(ch('p'));
        assert_eq!(
            names(&a),
            vec!["a.exe", "B.exe", "c.exe"],
            "pid ascending by default"
        );
        a.on_key(ch('a'));
        assert_eq!(
            names(&a),
            vec!["a.exe", "B.exe", "c.exe"],
            "name is case-insensitive"
        );
        a.on_key(ch('a'));
        assert_eq!(names(&a), vec!["c.exe", "B.exe", "a.exe"]);
    }

    #[test]
    fn io_and_network_combine_both_directions_and_keep_reliability() {
        let mut s = sample(1, U, U);
        s.io_read_bytes_per_sec = Metric::Partial(100.0);
        s.io_write_bytes_per_sec = Metric::Partial(50.0);
        s.net_rx_bytes_per_sec = A(10.0);
        s.net_tx_bytes_per_sec = A(5.0);
        let row = ProcessRow::from_sample("x".into(), &s);
        assert_eq!(row.io, Metric::Partial(150.0), "process I/O stays Partial");
        assert_eq!(row.network, A(15.0));

        // One direction unknown => the total is unknown, not half of it.
        s.net_tx_bytes_per_sec = U;
        assert_eq!(ProcessRow::from_sample("x".into(), &s).network, U);
    }

    #[test]
    fn selection_moves_clamps_and_jumps() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (1, "a.exe", A(3.0), A(0)),
            (2, "b.exe", A(2.0), A(0)),
            (3, "c.exe", A(1.0), A(0)),
        ]));
        a.sync_table();
        assert_eq!(a.table.selected(), Some(0));
        a.on_key(key(KeyCode::Down));
        a.on_key(ch('j'));
        a.on_key(key(KeyCode::Down)); // past the end: clamped
        a.sync_table();
        assert_eq!(a.table.selected(), Some(2));
        a.on_key(key(KeyCode::Up));
        a.sync_table();
        assert_eq!(a.table.selected(), Some(1));
        a.on_key(key(KeyCode::Home));
        a.sync_table();
        assert_eq!(a.table.selected(), Some(0));
        a.on_key(key(KeyCode::End));
        a.sync_table();
        assert_eq!(a.table.selected(), Some(2));
        a.page_size = 2;
        a.on_key(key(KeyCode::PageUp));
        a.sync_table();
        assert_eq!(a.table.selected(), Some(0));
    }

    #[test]
    fn the_selection_follows_the_process_when_the_order_changes() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (1, "a.exe", A(9.0), A(0)),
            (2, "b.exe", A(1.0), A(0)),
        ]));
        a.sync_table();
        a.on_key(key(KeyCode::Down)); // select b.exe (row 1)
        a.sync_table();
        assert_eq!(a.selected_key(), Some(ProcessKey::new(2, 1)));

        // b.exe becomes the busiest: it moves to the top and stays selected.
        let mut next = batch(&[(1, "a.exe", A(1.0), A(0)), (2, "b.exe", A(80.0), A(0))]);
        next.new.clear();
        a.apply_batch(&next);
        a.sync_table();
        assert_eq!(a.table.selected(), Some(0));
        assert_eq!(a.selected_key(), Some(ProcessKey::new(2, 1)));
    }

    #[test]
    fn if_the_selected_process_exits_the_cursor_falls_back_to_the_first_row() {
        let mut a = app();
        a.apply_batch(&batch(&[
            (1, "a.exe", A(9.0), A(0)),
            (2, "b.exe", A(1.0), A(0)),
        ]));
        a.sync_table();
        a.on_key(key(KeyCode::Down));
        a.sync_table();
        let mut gone = batch(&[]);
        gone.gone = vec![ProcessKey::new(2, 1)];
        a.apply_batch(&gone);
        a.sync_table();
        assert_eq!(a.selected_key(), Some(ProcessKey::new(1, 1)));
    }

    #[test]
    fn an_empty_table_has_no_selection_and_navigation_is_harmless() {
        let mut a = app();
        a.on_key(key(KeyCode::Down));
        a.on_key(key(KeyCode::End));
        a.sync_table();
        assert_eq!(a.table.selected(), None);
    }

    #[test]
    fn quit_keys() {
        for k in [
            ch('q'),
            key(KeyCode::Esc),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        ] {
            let mut a = app();
            a.on_key(k);
            assert!(a.should_quit, "{k:?}");
        }
        let mut a = app();
        a.on_key(ch('c')); // plain 'c' sorts by CPU, it does not quit
        assert!(!a.should_quit);
    }

    #[test]
    fn ticks_and_system_health_are_remembered() {
        let mut a = app();
        let mut b = batch(&[(1, "a.exe", A(1.0), A(1))]);
        b.system = Some(SystemSample {
            cpu_percent: A(42.0),
            memory_total_bytes: U,
            memory_available_bytes: U,
            commit_used_bytes: U,
            commit_limit_bytes: U,
            disk_utilization_percent: U,
            disk_queue_length: U,
            disk_read_bytes_per_sec: U,
            disk_write_bytes_per_sec: U,
            disk_latency_ms: U,
            net_rx_bytes_per_sec: U,
            net_tx_bytes_per_sec: U,
        });
        a.apply_batch(&b);
        a.apply_stats(&TickStats {
            sampled: 1,
            unreadable: 3,
            new: 1,
            gone: 0,
            took: Duration::from_millis(40),
        });
        assert_eq!(a.system.as_ref().unwrap().cpu_percent, A(42.0));
        assert_eq!(
            a.status,
            Status {
                ticks: 1,
                last_took: Duration::from_millis(40),
                unreadable: 3
            }
        );
    }
}
