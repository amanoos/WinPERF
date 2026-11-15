//! The Baseline Explorer: what is normal for each executable and application, how far to trust it,
//! and when it was last updated. A read-only view of the stored baselines (the monitor or
//! `baseline update` writes them); state and drawing live here, like the process view.

use crate::commands::baseline::{SubjectSummary, summarize_subjects};
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use winperf_core::config::ConfidenceConfig;
use winperf_core::profiler::baseline::Scope;
use winperf_core::profiler::confidence::Confidence;
use winperf_core::time::{format_span, unix_millis_now};
use winperf_storage::{Database, ListedBaseline};

/// How often the stored baselines are re-read while the explorer is open.
const REFRESH: Duration = Duration::from_secs(15);
/// Below this width the growth and updated columns are left out so the rest still fits.
const WIDE: u16 = 104;

/// Where the explorer reads from.
#[derive(Debug, Clone)]
pub struct BaselineSource {
    pub db_path: PathBuf,
    /// Configured baseline windows in hours, shortest first.
    pub windows: Vec<u32>,
    pub confidence: ConfidenceConfig,
}

/// What a key press asks the app to do beyond moving inside the explorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Stay,
    Back,
    Quit,
}

pub struct BaselineView {
    source: Option<BaselineSource>,
    /// Index into the source's windows.
    window: usize,
    pub subjects: Vec<SubjectSummary>,
    pub table: TableState,
    /// Why there is nothing to show, when that is not simply "no baselines yet".
    pub problem: Option<String>,
    loaded_at: Option<Instant>,
    /// Wall clock at the last load, for "updated N ago".
    now_ms: i64,
    stale: bool,
    pub page_size: usize,
}

impl BaselineView {
    pub fn new(source: Option<BaselineSource>) -> Self {
        // Start on the longest window: the most history, so the most trustworthy picture.
        let window = source
            .as_ref()
            .map_or(0, |s| s.windows.len().saturating_sub(1));
        Self {
            source,
            window,
            subjects: Vec::new(),
            table: TableState::default(),
            problem: None,
            loaded_at: None,
            now_ms: 0,
            stale: true,
            page_size: 10,
        }
    }

    pub fn window_hours(&self) -> Option<u32> {
        self.source.as_ref()?.windows.get(self.window).copied()
    }

    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    /// Re-read the database if asked to or if the data is old. Returns whether anything changed
    /// on screen, so the caller knows to redraw.
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
        let (Some(source), Some(hours)) = (&self.source, self.window_hours()) else {
            return;
        };
        let result = if source.db_path.exists() {
            Database::open_read_only(&source.db_path)
                .and_then(|db| db.list_baselines(hours))
                .map_err(|e| e.to_string())
        } else {
            Err(format!(
                "no database at {} yet. Run `winperf monitor run` first.",
                source.db_path.display()
            ))
        };
        match result {
            Ok(rows) => self.set_rows(&rows, unix_millis_now()),
            Err(e) => {
                self.subjects.clear();
                self.problem = Some(e);
                self.table.select(None);
            }
        }
    }

    /// Show these rows (one window's baselines). Keeps the cursor on the same subject if it is
    /// still there, else the first row.
    pub fn set_rows(&mut self, rows: &[ListedBaseline], now_ms: i64) {
        let thresholds = self.thresholds();
        let keep = self.selected().map(|s| (s.scope, s.name.clone()));
        self.subjects = summarize_subjects(rows, &thresholds);
        self.now_ms = now_ms;
        self.problem = None;
        let index = keep
            .and_then(|(scope, name)| {
                self.subjects
                    .iter()
                    .position(|s| s.scope == scope && s.name == name)
            })
            .or(if self.subjects.is_empty() {
                None
            } else {
                Some(0)
            });
        self.table.select(index);
    }

    pub fn selected(&self) -> Option<&SubjectSummary> {
        self.subjects.get(self.table.selected()?)
    }

    fn move_by(&mut self, delta: isize) {
        if self.subjects.is_empty() {
            return;
        }
        let at = self.table.selected().unwrap_or(0) as isize;
        let next = (at + delta).clamp(0, self.subjects.len() as isize - 1);
        self.table.select(Some(next as usize));
    }

    fn change_window(&mut self, delta: isize) {
        let Some(source) = &self.source else { return };
        let n = source.windows.len() as isize;
        if n == 0 {
            return;
        }
        self.window = (self.window as isize + delta).rem_euclid(n) as usize;
        self.table.select(None);
        self.stale = true;
    }

    /// Scroll with the wheel.
    pub fn scroll(&mut self, delta: isize) {
        self.move_by(delta);
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        let page = self.page_size.max(1) as isize;
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return Nav::Quit,
            (KeyCode::Char('q'), _) => return Nav::Quit,
            (KeyCode::Esc | KeyCode::Char('b'), _) => return Nav::Back,
            (KeyCode::Up | KeyCode::Char('k'), _) => self.move_by(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => self.move_by(1),
            (KeyCode::PageUp, _) => self.move_by(-page),
            (KeyCode::PageDown, _) => self.move_by(page),
            (KeyCode::Home | KeyCode::Char('g'), _) => self.move_by(isize::MIN / 2),
            (KeyCode::End | KeyCode::Char('G'), _) => self.move_by(isize::MAX / 2),
            (KeyCode::Left | KeyCode::BackTab, _) => self.change_window(-1),
            (KeyCode::Right | KeyCode::Tab, _) => self.change_window(1),
            (KeyCode::Char('r'), _) => self.stale = true,
            _ => {}
        }
        Nav::Stay
    }

    fn thresholds(&self) -> ConfidenceConfig {
        self.source
            .as_ref()
            .map(|s| s.confidence.clone())
            .unwrap_or_default()
    }
}

// ---- drawing -------------------------------------------------------------------------------

fn fmt_percent(v: f64) -> String {
    format!("{v:.2}%")
}

fn fmt_bytes(b: f64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = b.abs();
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let sign = if b < 0.0 { "-" } else { "" };
    if unit == 0 {
        format!("{sign}{value:.0} B")
    } else {
        format!("{sign}{value:.1} {}", UNITS[unit])
    }
}

fn confidence_style(c: Confidence) -> Style {
    match c {
        Confidence::Insufficient => Style::new().fg(Color::Yellow),
        Confidence::Preliminary => Style::new(),
        Confidence::Established => Style::new().fg(Color::Green),
        Confidence::High => Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
    }
}

fn display_name(s: &SubjectSummary) -> String {
    match s.scope {
        Scope::Executable => s.name.clone(),
        Scope::Application => format!("{} [app]", s.name),
    }
}

fn na() -> Cell<'static> {
    Cell::new("n/a").style(Style::new().fg(Color::DarkGray))
}

fn row(s: &SubjectSummary, wide: bool, now_ms: i64) -> Row<'static> {
    let num = |v: Option<String>| v.map_or_else(na, Cell::new);
    let mut cells = vec![
        Cell::new(display_name(s)),
        Cell::new(s.confidence.label()).style(confidence_style(s.confidence)),
        Cell::new(s.observations.to_string()),
        num(s.cpu.map(|c| fmt_percent(c.0))),
        num(s.cpu.map(|c| fmt_percent(c.1))),
        num(s.cpu.map(|c| fmt_percent(c.2))),
        num(s.memory.map(|m| fmt_bytes(m.0))),
        num(s.memory.map(|m| fmt_bytes(m.1))),
    ];
    if wide {
        cells.push(num(s
            .growth_per_hour
            .map(|g| format!("{}/h", fmt_bytes(g)))));
        cells.push(Cell::new(format!(
            "{} ago",
            format_span(now_ms - s.computed_at_ms)
        )));
    }
    Row::new(cells)
}

/// One line about the selected subject, spelling out why a baseline is not trusted yet.
fn detail_line(s: &SubjectSummary, c: &ConfidenceConfig) -> String {
    let span = format_span(s.last_ts_ms - s.first_ts_ms);
    let have = format!("{} observations over {span}", s.observations);
    match s.confidence {
        Confidence::Insufficient => format!(
            "Insufficient data: {have}; needs at least {} over {} min before it is trusted",
            c.preliminary_observations, c.preliminary_minutes
        ),
        Confidence::Preliminary => format!(
            "Preliminary: {have}; Established needs {} over {} min",
            c.established_observations, c.established_minutes
        ),
        Confidence::Established => format!(
            "Established: {have}; High needs {} over {} min",
            c.high_observations, c.high_minutes
        ),
        Confidence::High => format!("High confidence: {have}"),
    }
}

pub fn draw(f: &mut Frame, area: Rect, view: &mut BaselineView) {
    let [title, body, detail, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);

    let window = view
        .window_hours()
        .map_or("no window".to_string(), |h| format!("{h} h window"));
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" WinPerf ", Style::new().bold().fg(Color::Cyan)),
            Span::raw(format!(
                "Baseline Explorer - {window} - {} subjects",
                view.subjects.len()
            )),
        ])),
        title,
    );

    if view.subjects.is_empty() {
        let text = view.problem.clone().unwrap_or_else(|| {
            format!(
                "No baselines for the {window} yet. They are built from collected samples: run \
                 `winperf monitor run` for a while (it recomputes them in the background), or run \
                 `winperf baseline update`."
            )
        });
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), body);
    } else {
        draw_table(f, body, view);
    }

    let thresholds = view.thresholds();
    if let Some(s) = view.selected() {
        let style = confidence_style(s.confidence);
        f.render_widget(
            Paragraph::new(detail_line(s, &thresholds)).style(style),
            detail,
        );
    }
    f.render_widget(
        Paragraph::new(" q quit  b back  ↑↓ move  ←→ window  r reload")
            .style(Style::new().fg(Color::DarkGray)),
        footer,
    );
}

fn draw_table(f: &mut Frame, area: Rect, view: &mut BaselineView) {
    let wide = area.width >= WIDE;
    let mut header = vec![
        "NAME",
        "CONFIDENCE",
        "OBS",
        "CPU avg",
        "CPU p95",
        "CPU peak",
        "MEM avg",
        "MEM peak",
    ];
    let mut widths = vec![
        Constraint::Min(14),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(9),
        Constraint::Length(9),
    ];
    if wide {
        header.extend(["GROWTH", "UPDATED"]);
        widths.extend([Constraint::Length(11), Constraint::Length(11)]);
    }
    view.page_size = usize::from(area.height.saturating_sub(1)).max(1);
    let now_ms = view.now_ms;
    let rows: Vec<Row> = view.subjects.iter().map(|s| row(s, wide, now_ms)).collect();
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
    use winperf_core::profiler::baseline::BaselineMetric;
    use winperf_storage::StoredBaseline;

    const NOW: i64 = 1_000_000_000;

    fn source() -> BaselineSource {
        BaselineSource {
            db_path: std::env::temp_dir().join("winperf-explorer-nonexistent.db"),
            windows: vec![1, 24],
            confidence: ConfidenceConfig::default(),
        }
    }

    fn stored(
        scope: Scope,
        id: i64,
        metric: BaselineMetric,
        obs: u64,
        span_ms: i64,
        mean: f64,
    ) -> StoredBaseline {
        StoredBaseline {
            scope,
            subject_id: id,
            window_hours: 24,
            metric,
            observations: obs,
            first_ts_ms: NOW - span_ms,
            last_ts_ms: NOW,
            mean,
            median: mean,
            mad: 0.0,
            stddev: 0.0,
            p95: mean * 2.0,
            peak: mean * 3.0,
            growth_per_hour: (metric == BaselineMetric::Memory).then_some(2048.0),
            computed_at_ms: NOW - 90_000,
        }
    }

    fn rows() -> Vec<ListedBaseline> {
        let mut v = Vec::new();
        for (id, name, obs, span, cpu) in [
            (1, "chrome.exe", 20_000, 30 * 3_600_000, 4.0),
            (2, "newcomer.exe", 12, 70_000, 0.5),
        ] {
            for (metric, mean) in [
                (BaselineMetric::Cpu, cpu),
                (BaselineMetric::Memory, 100.0 * 1024.0 * 1024.0),
            ] {
                v.push(ListedBaseline {
                    stored: stored(Scope::Executable, id, metric, obs, span, mean),
                    name: name.into(),
                });
            }
        }
        v
    }

    fn view() -> BaselineView {
        let mut v = BaselineView::new(Some(source()));
        v.set_rows(&rows(), NOW);
        v
    }

    fn render(view: &mut BaselineView, w: u16, h: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, f.area(), view)).unwrap();
        let buf = terminal.backend().buffer();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect())
            .collect()
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn shows_confidence_cpu_memory_and_clearly_labels_insufficient_data() {
        let mut v = view();
        let screen = render(&mut v, 110, 12).join("\n");
        for want in [
            "Baseline Explorer - 24 h window - 2 subjects",
            "chrome.exe",
            "High",
            "newcomer.exe",
            "Insufficient",
            "4.00%",
            "100.0 MB",
            "2.0 KB/h",
            "1m 30s ago",
        ] {
            assert!(screen.contains(want), "missing {want:?} in:\n{screen}");
        }
        // Busiest first: chrome is selected, so its (High) detail shows; move to the newcomer.
        v.on_key(key(KeyCode::Down));
        let screen = render(&mut v, 110, 12).join("\n");
        assert!(
            screen.contains(
                "Insufficient data: 12 observations over 1m 10s; needs at least 60 over 5 min"
            ),
            "{screen}"
        );
    }

    #[test]
    fn an_80_column_screen_drops_growth_and_updated_but_keeps_the_rest() {
        let mut v = view();
        let screen = render(&mut v, 80, 12).join("\n");
        assert!(!screen.contains("GROWTH"), "{screen}");
        assert!(
            screen.contains("CONFIDENCE") && screen.contains("MEM peak"),
            "{screen}"
        );
        assert!(screen.lines().all(|l| l.chars().count() <= 80));
    }

    #[test]
    fn applications_are_tagged() {
        let mut v = BaselineView::new(Some(source()));
        let mut r = rows();
        r[0].stored.scope = Scope::Application;
        r[1].stored.scope = Scope::Application;
        v.set_rows(&r, NOW);
        let screen = render(&mut v, 110, 12).join("\n");
        assert!(screen.contains("chrome.exe [app]"), "{screen}");
    }

    #[test]
    fn an_empty_window_explains_how_to_get_baselines() {
        let mut v = BaselineView::new(Some(source()));
        v.set_rows(&[], NOW);
        let screen = render(&mut v, 200, 12).join("\n");
        assert!(
            screen.contains("No baselines for the 24 h window yet"),
            "{screen}"
        );
        assert!(screen.contains("winperf monitor run"), "{screen}");
    }

    #[test]
    fn a_missing_database_is_reported_not_a_crash() {
        let mut v = BaselineView::new(Some(source()));
        assert!(v.refresh_if_due());
        let screen = render(&mut v, 110, 12).join("\n");
        assert!(screen.contains("no database at"), "{screen}");
        assert!(!v.refresh_if_due(), "not stale again until asked or old");
    }

    #[test]
    fn keys_move_switch_windows_reload_and_leave() {
        let mut v = view();
        assert_eq!(v.table.selected(), Some(0));
        v.on_key(key(KeyCode::Down));
        v.on_key(key(KeyCode::Down)); // clamped
        assert_eq!(v.table.selected(), Some(1));
        v.on_key(key(KeyCode::Home));
        assert_eq!(v.table.selected(), Some(0));
        v.on_key(key(KeyCode::End));
        assert_eq!(v.table.selected(), Some(1));

        assert_eq!(v.window_hours(), Some(24), "starts on the longest window");
        v.on_key(key(KeyCode::Left));
        assert_eq!(v.window_hours(), Some(1));
        v.on_key(key(KeyCode::Left)); // wraps
        assert_eq!(v.window_hours(), Some(24));
        v.on_key(key(KeyCode::Right));
        assert_eq!(v.window_hours(), Some(1));

        assert_eq!(v.on_key(key(KeyCode::Esc)), Nav::Back);
        assert_eq!(v.on_key(key(KeyCode::Char('b'))), Nav::Back);
        assert_eq!(v.on_key(key(KeyCode::Char('q'))), Nav::Quit);
        assert_eq!(
            v.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Nav::Quit
        );
        assert_eq!(v.on_key(key(KeyCode::Char('x'))), Nav::Stay);
    }

    #[test]
    fn the_cursor_stays_on_the_same_subject_across_a_refresh() {
        let mut v = view();
        v.on_key(key(KeyCode::Down));
        assert_eq!(v.selected().unwrap().name, "newcomer.exe");
        v.set_rows(&rows(), NOW + 1000);
        assert_eq!(v.selected().unwrap().name, "newcomer.exe");
    }

    #[test]
    fn without_a_source_nothing_loads_and_navigation_is_harmless() {
        let mut v = BaselineView::new(None);
        assert!(!v.refresh_if_due());
        v.on_key(key(KeyCode::Down));
        v.on_key(key(KeyCode::Left));
        assert_eq!(v.window_hours(), None);
        let screen = render(&mut v, 80, 10).join("\n");
        assert!(screen.contains("No baselines"), "{screen}");
    }

    #[test]
    fn units_and_detail_text() {
        assert_eq!(fmt_bytes(512.0), "512 B");
        assert_eq!(fmt_bytes(1536.0), "1.5 KB");
        assert_eq!(fmt_bytes(-2048.0), "-2.0 KB");
        let v = view();
        let s = &v.subjects[0];
        assert_eq!(
            detail_line(s, &ConfidenceConfig::default()),
            "High confidence: 20000 observations over 1d 06h"
        );
    }
}
