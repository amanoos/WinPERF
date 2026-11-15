//! The Anomaly Explorer (PRD FR-020 E): the anomalies the monitor has stored, split into those
//! still going on (Active) and those that have ended (History), filterable by severity and sortable.
//! A read-only view of the database; the monitor or service is the writer.
//!
//! The view also keeps watch while another screen is showing: it re-reads the database every few
//! seconds so the dashboard can show a badge for anomalies that appeared since you last looked, and
//! mark the processes involved.

use crate::commands::anomalies::{at, deviation, value, what};
use crate::tui::baselines::Nav;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use winperf_core::anomaly::Severity;
use winperf_core::time::format_span;
use winperf_storage::{AnomalyFilter, Database, StoredAnomaly};

/// How often the stored anomalies are re-read, on any screen.
const REFRESH: Duration = Duration::from_secs(5);
/// Most events read at a time (newest first).
const LOAD_LIMIT: u32 = 1000;
/// Below this width the impact column is left out so the rest still fits.
const WIDE: u16 = 100;

/// Where the explorer reads from.
#[derive(Debug, Clone)]
pub struct AnomalySource {
    pub db_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Active,
    History,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    /// Most serious first, then the biggest impact, then the newest.
    Severity,
    Newest,
    Impact,
}

impl SortBy {
    fn next(self) -> Self {
        match self {
            SortBy::Severity => SortBy::Newest,
            SortBy::Newest => SortBy::Impact,
            SortBy::Impact => SortBy::Severity,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SortBy::Severity => "severity",
            SortBy::Newest => "newest",
            SortBy::Impact => "impact",
        }
    }
}

/// The severity filter cycles: everything, then only at least Warning, High, Critical.
fn next_filter(f: Option<Severity>) -> Option<Severity> {
    match f {
        None => Some(Severity::Warning),
        Some(Severity::Warning) => Some(Severity::High),
        Some(Severity::High) => Some(Severity::Critical),
        Some(_) => None,
    }
}

/// What the dashboard shows about anomalies that have not been looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Badge {
    /// Events that appeared since the explorer was last opened.
    pub new: usize,
    pub active: usize,
    /// The worst severity among the new events.
    pub worst_new: Severity,
}

pub struct AnomalyView {
    source: Option<AnomalySource>,
    /// Everything loaded, newest first.
    events: Vec<StoredAnomaly>,
    /// What is on screen: the current tab, filter and sort applied to `events`.
    pub rows: Vec<StoredAnomaly>,
    pub tab: Tab,
    pub sort: SortBy,
    pub min_severity: Option<Severity>,
    pub table: TableState,
    /// Why there is nothing to show, when that is not simply "no anomalies".
    pub problem: Option<String>,
    /// Events with an id above this have not been seen. `None` until the first load.
    seen_id: Option<i64>,
    loaded_at: Option<Instant>,
    stale: bool,
    pub page_size: usize,
}

impl AnomalyView {
    pub fn new(source: Option<AnomalySource>) -> Self {
        Self {
            source,
            events: Vec::new(),
            rows: Vec::new(),
            tab: Tab::Active,
            sort: SortBy::Severity,
            min_severity: None,
            table: TableState::default(),
            problem: None,
            seen_id: None,
            loaded_at: None,
            stale: true,
            page_size: 10,
        }
    }

    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    /// Re-read the database when asked to or when the data is old. Returns whether anything
    /// changed, so the caller knows to redraw.
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
        if !source.db_path.exists() {
            self.problem = Some(format!(
                "no database at {} yet. Run `winperf monitor run` first.",
                source.db_path.display()
            ));
            self.set_events(Vec::new());
            return;
        }
        match Database::open_read_only(&source.db_path)
            .and_then(|db| db.list_anomalies(&AnomalyFilter::default(), LOAD_LIMIT))
        {
            Ok(events) => {
                self.problem = None;
                self.set_events(events);
            }
            Err(e) => {
                self.problem = Some(e.to_string());
                self.set_events(Vec::new());
            }
        }
    }

    /// Show these events. Keeps the cursor on the same event if it is still shown. The first load
    /// counts everything as already seen, so only events that appear later badge.
    pub fn set_events(&mut self, events: Vec<StoredAnomaly>) {
        if self.seen_id.is_none() {
            self.seen_id = Some(events.iter().map(|e| e.id).max().unwrap_or(0));
        }
        self.events = events;
        self.rebuild();
    }

    fn rebuild(&mut self) {
        let keep = self.selected().map(|e| e.id);
        let tab = self.tab;
        let min = self.min_severity;
        let mut rows: Vec<StoredAnomaly> = self
            .events
            .iter()
            .filter(|e| match tab {
                Tab::Active => e.is_active(),
                Tab::History => !e.is_active(),
            })
            .filter(|e| min.is_none_or(|m| e.severity >= m))
            .cloned()
            .collect();
        match self.sort {
            SortBy::Severity => rows.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then(cmp_score(b.impact_score, a.impact_score))
                    .then(b.detected_ts_ms.cmp(&a.detected_ts_ms))
            }),
            SortBy::Newest => rows.sort_by(|a, b| {
                b.detected_ts_ms
                    .cmp(&a.detected_ts_ms)
                    .then(b.id.cmp(&a.id))
            }),
            SortBy::Impact => rows.sort_by(|a, b| {
                cmp_score(b.impact_score, a.impact_score)
                    .then(b.severity.cmp(&a.severity))
                    .then(b.detected_ts_ms.cmp(&a.detected_ts_ms))
            }),
        }
        self.rows = rows;
        let index = keep
            .and_then(|id| self.rows.iter().position(|e| e.id == id))
            .or(if self.rows.is_empty() { None } else { Some(0) });
        self.table.select(index);
    }

    pub fn selected(&self) -> Option<&StoredAnomaly> {
        self.rows.get(self.table.selected()?)
    }

    pub fn active_count(&self) -> usize {
        self.events.iter().filter(|e| e.is_active()).count()
    }

    pub fn history_count(&self) -> usize {
        self.events.len() - self.active_count()
    }

    /// Anomalies that appeared since the explorer was last opened, if any.
    pub fn badge(&self) -> Option<Badge> {
        let seen = self.seen_id?;
        let fresh: Vec<&StoredAnomaly> = self.events.iter().filter(|e| e.id > seen).collect();
        let worst_new = fresh.iter().map(|e| e.severity).max()?;
        Some(Badge {
            new: fresh.len(),
            active: self.active_count(),
            worst_new,
        })
    }

    /// Everything loaded counts as seen (the explorer was opened).
    pub fn mark_seen(&mut self) {
        self.seen_id = self.events.iter().map(|e| e.id).max().or(self.seen_id);
    }

    /// The worst severity among the active anomalies of each process id, to mark the processes.
    pub fn active_by_pid(&self) -> HashMap<u32, Severity> {
        let mut map: HashMap<u32, Severity> = HashMap::new();
        for e in self.events.iter().filter(|e| e.is_active()) {
            let slot = map.entry(e.pid).or_insert(e.severity);
            *slot = (*slot).max(e.severity);
        }
        map
    }

    fn move_by(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let at = self.table.selected().unwrap_or(0) as isize;
        let next = (at + delta).clamp(0, self.rows.len() as isize - 1);
        self.table.select(Some(next as usize));
    }

    pub fn scroll(&mut self, delta: isize) {
        self.move_by(delta);
    }

    fn switch_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.table.select(None);
            self.rebuild();
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        let page = self.page_size.max(1) as isize;
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return Nav::Quit,
            (KeyCode::Char('q'), _) => return Nav::Quit,
            (KeyCode::Esc | KeyCode::Char('e'), _) => return Nav::Back,
            (KeyCode::Up | KeyCode::Char('k'), _) => self.move_by(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => self.move_by(1),
            (KeyCode::PageUp, _) => self.move_by(-page),
            (KeyCode::PageDown, _) => self.move_by(page),
            (KeyCode::Home | KeyCode::Char('g'), _) => self.move_by(isize::MIN / 2),
            (KeyCode::End | KeyCode::Char('G'), _) => self.move_by(isize::MAX / 2),
            (KeyCode::Char('1'), _) => self.switch_tab(Tab::Active),
            (KeyCode::Char('2'), _) => self.switch_tab(Tab::History),
            (KeyCode::Left | KeyCode::Right | KeyCode::Tab | KeyCode::BackTab, _) => {
                let to = match self.tab {
                    Tab::Active => Tab::History,
                    Tab::History => Tab::Active,
                };
                self.switch_tab(to);
            }
            (KeyCode::Char('s'), _) => {
                self.min_severity = next_filter(self.min_severity);
                self.rebuild();
            }
            (KeyCode::Char('o'), _) => {
                self.sort = self.sort.next();
                self.rebuild();
            }
            (KeyCode::Char('r'), _) => self.stale = true,
            _ => {}
        }
        Nav::Stay
    }
}

/// Larger scores first when used as `cmp_score(b, a)`; events without a score last.
fn cmp_score(a: Option<f64>, b: Option<f64>) -> std::cmp::Ordering {
    match (a, b) {
        (Some(x), Some(y)) => x.total_cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

// ---- drawing -------------------------------------------------------------------------------

pub fn severity_style(s: Severity) -> Style {
    match s {
        Severity::Informational => Style::new().fg(Color::Cyan),
        Severity::Warning => Style::new().fg(Color::Yellow),
        Severity::High => Style::new().fg(Color::LightRed),
        Severity::Critical => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn filter_label(f: Option<Severity>) -> String {
    f.map_or("all severities".to_string(), |s| {
        format!("{} and above", s.label())
    })
}

fn time_cell(ms: i64) -> String {
    // "2026-11-15 05:12:24" -> "11-15 05:12"
    at(ms).get(5..16).unwrap_or("?").to_string()
}

fn row(e: &StoredAnomaly, wide: bool) -> Row<'static> {
    let mut cells = vec![
        Cell::new(e.severity.label()).style(severity_style(e.severity)),
        Cell::new(time_cell(e.detected_ts_ms)),
        Cell::new(what(e)),
        Cell::new(format!("{} ({})", e.process_name, e.pid)),
        Cell::new(value(e, e.current)),
        Cell::new(value(e, e.baseline)),
        Cell::new(deviation(e.deviation_pct)),
        Cell::new(format_span(e.duration_ms)),
    ];
    if wide {
        cells.push(e.impact_score.map_or_else(
            || Cell::new("n/a").style(Style::new().fg(Color::DarkGray)),
            |s| Cell::new(format!("{s:.0}")),
        ));
    }
    Row::new(cells)
}

fn detail(e: &StoredAnomaly) -> String {
    let state = match e.resolved_ts_ms {
        None => "Active".to_string(),
        Some(t) => format!("Resolved {}", time_cell(t)),
    };
    format!("{state}. {}", e.explanation)
}

pub fn draw(f: &mut Frame, area: Rect, view: &mut AnomalyView) {
    let [title, body, detail_area, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(4),
        Constraint::Length(1),
    ])
    .areas(area);

    let tab = |label: String, on: bool| {
        if on {
            Span::styled(format!("[{label}]"), Style::new().bold().fg(Color::Cyan))
        } else {
            Span::raw(format!(" {label} "))
        }
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" WinPerf ", Style::new().bold().fg(Color::Cyan)),
            Span::raw("Anomalies  "),
            tab(
                format!("1 Active ({})", view.active_count()),
                view.tab == Tab::Active,
            ),
            tab(
                format!("2 History ({})", view.history_count()),
                view.tab == Tab::History,
            ),
            Span::styled(
                format!(
                    "  {} | sorted by {}",
                    filter_label(view.min_severity),
                    view.sort.label()
                ),
                Style::new().fg(Color::DarkGray),
            ),
        ])),
        title,
    );

    if view.rows.is_empty() {
        let text = view.problem.clone().unwrap_or_else(|| {
            let none = match view.tab {
                Tab::Active => "No anomalies are active",
                Tab::History => "No resolved anomalies",
            };
            let filtered = view.min_severity.is_some();
            format!(
                "{none}{}. Anomalies are detected by `winperf monitor run` (or the service) \
                 against learned baselines.{}",
                if filtered { " at this severity" } else { "" },
                if filtered && !view.events.is_empty() {
                    " Press s to widen the filter."
                } else {
                    ""
                }
            )
        });
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), body);
    } else {
        draw_table(f, body, view);
    }

    if let Some(e) = view.selected() {
        f.render_widget(
            Paragraph::new(detail(e))
                .wrap(Wrap { trim: true })
                .style(severity_style(e.severity)),
            detail_area,
        );
    }
    f.render_widget(
        Paragraph::new(" q quit  e back  ↑↓ move  ←→ tab  s severity filter  o sort  r reload")
            .style(Style::new().fg(Color::DarkGray)),
        footer,
    );
}

fn draw_table(f: &mut Frame, area: Rect, view: &mut AnomalyView) {
    let wide = area.width >= WIDE;
    let mut header = vec![
        "SEVERITY", "SINCE", "RESOURCE", "PROCESS", "NOW", "NORMAL", "OVER", "LASTED",
    ];
    let mut widths = vec![
        Constraint::Length(13),
        Constraint::Length(11),
        Constraint::Length(10),
        Constraint::Min(16),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Length(8),
        Constraint::Length(8),
    ];
    if wide {
        header.push("IMPACT");
        widths.push(Constraint::Length(6));
    }
    view.page_size = usize::from(area.height.saturating_sub(1)).max(1);
    let rows: Vec<Row> = view.rows.iter().map(|e| row(e, wide)).collect();
    let table = Table::new(rows, widths)
        .header(Row::new(header).style(Style::new().add_modifier(Modifier::BOLD)))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, area, &mut view.table);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use winperf_core::config::Resource;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    fn event(
        id: i64,
        name: &str,
        severity: Severity,
        ts: i64,
        resolved: Option<i64>,
        score: Option<f64>,
    ) -> StoredAnomaly {
        StoredAnomaly {
            id,
            detected_ts_ms: ts,
            process_instance_id: None,
            pid: 100 + id as u32,
            process_name: name.into(),
            application: None,
            exe_path: format!(r"C:\apps\{name}"),
            resource: Resource::Cpu,
            kind: winperf_core::anomaly::AnomalyKind::Deviation,
            current: 72.0,
            baseline: 8.0,
            deviation_pct: 800.0,
            duration_ms: 180_000,
            severity,
            system_cpu_percent: Some(91.0),
            system_memory_percent: None,
            baseline_window_hours: 24,
            baseline_confidence: "Established".into(),
            explanation: format!("{name} used a lot of CPU."),
            resolved_ts_ms: resolved,
            last_update_ts_ms: ts,
            system_disk_percent: None,
            pressure_percent: Some(91.0),
            share_percent: Some(72.0),
            impact_score: score,
        }
    }

    /// Newest first, as the database lists them.
    fn sample() -> Vec<StoredAnomaly> {
        vec![
            event(
                5,
                "newest.exe",
                Severity::Informational,
                5_000_000,
                None,
                Some(5.0),
            ),
            event(
                4,
                "hot.exe",
                Severity::Critical,
                4_000_000,
                None,
                Some(80.0),
            ),
            event(
                3,
                "done.exe",
                Severity::High,
                3_000_000,
                Some(3_500_000),
                Some(40.0),
            ),
            event(2, "warm.exe", Severity::Warning, 2_000_000, None, None),
            event(
                1,
                "old.exe",
                Severity::Warning,
                1_000_000,
                Some(1_500_000),
                Some(10.0),
            ),
        ]
    }

    fn view() -> AnomalyView {
        let mut v = AnomalyView::new(Some(AnomalySource {
            db_path: std::env::temp_dir().join("winperf-anomalies-nonexistent.db"),
        }));
        v.set_events(sample());
        v
    }

    fn names(v: &AnomalyView) -> Vec<String> {
        v.rows.iter().map(|e| e.process_name.clone()).collect()
    }

    fn render(view: &mut AnomalyView, w: u16, h: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, f.area(), view)).unwrap();
        let buf = terminal.backend().buffer();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect()
    }

    fn screen(view: &mut AnomalyView, w: u16, h: u16) -> String {
        render(view, w, h).join("\n")
    }

    #[test]
    fn active_and_history_are_separate_tabs() {
        let mut v = view();
        assert_eq!(v.tab, Tab::Active);
        assert_eq!(
            names(&v),
            vec!["hot.exe", "warm.exe", "newest.exe"],
            "worst first"
        );
        assert_eq!((v.active_count(), v.history_count()), (3, 2));

        v.on_key(ch('2'));
        assert_eq!(v.tab, Tab::History);
        assert_eq!(names(&v), vec!["done.exe", "old.exe"]);
        v.on_key(key(KeyCode::Tab));
        assert_eq!(v.tab, Tab::Active);
        v.on_key(key(KeyCode::Right));
        assert_eq!(v.tab, Tab::History);
    }

    #[test]
    fn sorting_cycles_severity_newest_impact() {
        let mut v = view();
        assert_eq!(v.sort, SortBy::Severity);
        assert_eq!(names(&v), vec!["hot.exe", "warm.exe", "newest.exe"]);
        v.on_key(ch('o'));
        assert_eq!(v.sort, SortBy::Newest);
        assert_eq!(names(&v), vec!["newest.exe", "hot.exe", "warm.exe"]);
        v.on_key(ch('o'));
        assert_eq!(v.sort, SortBy::Impact);
        assert_eq!(
            names(&v),
            vec!["hot.exe", "newest.exe", "warm.exe"],
            "no score sorts last"
        );
        v.on_key(ch('o'));
        assert_eq!(v.sort, SortBy::Severity);
    }

    #[test]
    fn the_severity_filter_cycles_and_hides_milder_events() {
        let mut v = view();
        v.on_key(ch('s'));
        assert_eq!(v.min_severity, Some(Severity::Warning));
        assert_eq!(
            names(&v),
            vec!["hot.exe", "warm.exe"],
            "Informational hidden"
        );
        v.on_key(ch('s'));
        assert_eq!(v.min_severity, Some(Severity::High));
        assert_eq!(names(&v), vec!["hot.exe"]);
        v.on_key(ch('s'));
        assert_eq!(v.min_severity, Some(Severity::Critical));
        assert_eq!(names(&v), vec!["hot.exe"]);
        v.on_key(ch('s'));
        assert_eq!(v.min_severity, None);
        assert_eq!(v.rows.len(), 3);
    }

    #[test]
    fn the_cursor_follows_the_event_when_the_order_changes() {
        let mut v = view();
        v.on_key(ch('j')); // warm.exe
        assert_eq!(v.selected().unwrap().process_name, "warm.exe");
        v.on_key(ch('o')); // newest first: still on warm.exe
        assert_eq!(v.selected().unwrap().process_name, "warm.exe");
        v.set_events(sample());
        assert_eq!(
            v.selected().unwrap().process_name,
            "warm.exe",
            "survives a reload"
        );
    }

    #[test]
    fn navigation_clamps_and_an_empty_list_is_harmless() {
        let mut v = view();
        for _ in 0..10 {
            v.on_key(ch('j'));
        }
        assert_eq!(v.table.selected(), Some(2));
        v.on_key(ch('g'));
        assert_eq!(v.table.selected(), Some(0));
        v.on_key(ch('G'));
        assert_eq!(v.table.selected(), Some(2));

        let mut empty = AnomalyView::new(None);
        empty.set_events(Vec::new());
        assert_eq!(empty.on_key(ch('j')), Nav::Stay);
        assert!(empty.selected().is_none());
    }

    #[test]
    fn keys_say_whether_to_go_back_or_quit() {
        let mut v = view();
        assert_eq!(v.on_key(key(KeyCode::Esc)), Nav::Back);
        assert_eq!(v.on_key(ch('e')), Nav::Back);
        assert_eq!(v.on_key(ch('q')), Nav::Quit);
        assert_eq!(
            v.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Nav::Quit
        );
    }

    // ---- the badge ------------------------------------------------------------------------

    #[test]
    fn what_was_there_on_the_first_load_is_not_new() {
        let v = view();
        assert_eq!(v.badge(), None);
    }

    #[test]
    fn events_that_appear_later_badge_until_the_explorer_is_opened() {
        let mut v = view();
        let mut more = sample();
        more.insert(
            0,
            event(7, "fresh.exe", Severity::High, 7_000_000, None, Some(50.0)),
        );
        more.insert(
            0,
            event(8, "fresher.exe", Severity::Warning, 8_000_000, None, None),
        );
        v.set_events(more);

        let badge = v.badge().expect("two new events");
        assert_eq!(badge.new, 2);
        assert_eq!(badge.worst_new, Severity::High);
        assert_eq!(badge.active, 5);

        v.mark_seen();
        assert_eq!(v.badge(), None);
    }

    #[test]
    fn active_processes_are_marked_with_their_worst_severity() {
        let mut v = view();
        let mut more = sample();
        let mut again = event(6, "again.exe", Severity::Warning, 6_000_000, None, None);
        again.pid = 104; // same pid as hot.exe (id 4)
        more.push(again);
        v.set_events(more);
        let map = v.active_by_pid();
        assert_eq!(map.get(&104), Some(&Severity::Critical));
        assert_eq!(map.get(&105), Some(&Severity::Informational));
        assert!(!map.contains_key(&103), "resolved events do not mark");
    }

    #[test]
    fn refreshing_without_a_source_does_nothing() {
        let mut v = AnomalyView::new(None);
        assert!(!v.refresh_if_due());
    }

    #[test]
    fn a_missing_database_is_explained_not_an_error() {
        let mut v = AnomalyView::new(Some(AnomalySource {
            db_path: std::env::temp_dir().join("winperf-no-such-anomalies.db"),
        }));
        assert!(v.refresh_if_due());
        assert!(v.problem.as_deref().unwrap().contains("monitor run"));
        let s = screen(&mut v, 100, 14);
        assert!(s.contains("no database at"), "{s}");
        assert!(!v.refresh_if_due(), "and it waits before looking again");
        v.on_key(ch('r'));
        assert!(v.refresh_if_due(), "r reloads");
    }

    // ---- drawing --------------------------------------------------------------------------

    #[test]
    fn the_active_tab_shows_columns_severity_and_the_explanation() {
        let mut v = view();
        let s = screen(&mut v, 120, 16);
        for expected in [
            "Anomalies",
            "[1 Active (3)]",
            "2 History (2)",
            "all severities",
            "sorted by severity",
            "SEVERITY",
            "RESOURCE",
            "IMPACT",
            "Critical",
            "hot.exe (104)",
            "72.0%",
            "+800%",
            "3m 00s",
            "hot.exe used a lot of CPU.",
            "Active.",
        ] {
            assert!(s.contains(expected), "missing {expected:?} in\n{s}");
        }
        assert!(
            !s.contains("done.exe"),
            "resolved events are on the other tab"
        );
    }

    #[test]
    fn the_history_tab_says_when_each_event_was_resolved() {
        let mut v = view();
        v.on_key(ch('2'));
        let s = screen(&mut v, 120, 16);
        assert!(
            s.contains("[2 History (2)]") && s.contains("done.exe (103)"),
            "{s}"
        );
        assert!(s.contains("Resolved "), "{s}");
    }

    #[test]
    fn a_narrow_screen_drops_the_impact_column_but_keeps_the_rest() {
        let mut v = view();
        let s = screen(&mut v, 80, 16);
        assert!(!s.contains("IMPACT"), "{s}");
        assert!(s.contains("hot.exe") && s.contains("LASTED"), "{s}");
    }

    #[test]
    fn empty_states_explain_what_to_do() {
        let mut v = AnomalyView::new(None);
        v.set_events(Vec::new());
        let s = screen(&mut v, 100, 14);
        assert!(s.contains("No anomalies are active"), "{s}");
        assert!(s.contains("monitor run"), "{s}");

        let mut v = view();
        v.on_key(ch('s'));
        v.on_key(ch('s'));
        v.on_key(ch('s')); // Critical only
        v.on_key(ch('2')); // history has no Critical events
        let s = screen(&mut v, 100, 14);
        assert!(s.contains("No resolved anomalies at this severity"), "{s}");
        assert!(s.contains("Press s to widen the filter"), "{s}");
    }

    #[test]
    fn the_footer_lists_the_keys() {
        let mut v = view();
        let s = screen(&mut v, 100, 14);
        assert!(
            s.contains("s severity filter") && s.contains("o sort"),
            "{s}"
        );
    }
}
