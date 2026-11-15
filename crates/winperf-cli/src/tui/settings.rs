//! The Configuration screen (PRD FR-020 G): view and change the settings in the configuration file
//! from inside the dashboard.
//!
//! Changes are made to a working copy and checked as they are entered (the same validation the
//! file gets when it is loaded), so the copy can never be invalid. `w` saves it: the existing file
//! is edited in place, keeping its comments, and the dashboard applies what it can immediately (the
//! baseline windows and confidence levels of the Baseline Explorer). A running monitor reads the
//! file when it starts, so it picks changes up on its next start.

use crate::tui::baselines::Nav;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use std::path::PathBuf;
use winperf_core::config::{Config, DEFAULT_CONFIG_TEMPLATE, Sensitivity};
use winperf_core::config_edit;

/// What the screen edits: the configuration file and the settings as they were loaded.
#[derive(Debug, Clone)]
pub struct SettingsSource {
    pub path: PathBuf,
    pub config: Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Interval,
    Signatures,
    Network,
    Sensitivity,
    CpuOverride,
    MemoryOverride,
    DiskOverride,
    NetworkOverride,
    Windows,
    Recompute,
    RawDays,
    OneMinuteDays,
    FifteenMinuteDays,
    AnomalyDays,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Number,
    Toggle,
    /// Low / normal / high.
    Level,
    /// Inherit / low / normal / high.
    Override,
    List,
    ReadOnly,
}

impl Field {
    pub const ALL: [Field; 15] = [
        Field::Interval,
        Field::Signatures,
        Field::Network,
        Field::Sensitivity,
        Field::CpuOverride,
        Field::MemoryOverride,
        Field::DiskOverride,
        Field::NetworkOverride,
        Field::Windows,
        Field::Recompute,
        Field::RawDays,
        Field::OneMinuteDays,
        Field::FifteenMinuteDays,
        Field::AnomalyDays,
        Field::Service,
    ];

    fn group(self) -> &'static str {
        match self {
            Field::Interval | Field::Signatures | Field::Network => "Monitoring",
            Field::Sensitivity
            | Field::CpuOverride
            | Field::MemoryOverride
            | Field::DiskOverride
            | Field::NetworkOverride => "Detection sensitivity",
            Field::Windows | Field::Recompute => "Baselines",
            Field::RawDays
            | Field::OneMinuteDays
            | Field::FifteenMinuteDays
            | Field::AnomalyDays => "Data retention (days)",
            Field::Service => "Service",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Field::Interval => "Sampling interval (seconds)",
            Field::Signatures => "Signature checks",
            Field::Network => "Per-process network attribution",
            Field::Sensitivity => "Sensitivity (all resources)",
            Field::CpuOverride => "  CPU override",
            Field::MemoryOverride => "  Memory override",
            Field::DiskOverride => "  Disk override",
            Field::NetworkOverride => "  Network override",
            Field::Windows => "Baseline windows (hours)",
            Field::Recompute => "Baseline refresh (minutes)",
            Field::RawDays => "Raw samples",
            Field::OneMinuteDays => "1-minute rollups",
            Field::FifteenMinuteDays => "15-minute rollups",
            Field::AnomalyDays => "Anomaly events",
            Field::Service => "Windows service",
        }
    }

    fn kind(self) -> Kind {
        match self {
            Field::Interval | Field::Recompute => Kind::Number,
            Field::RawDays
            | Field::OneMinuteDays
            | Field::FifteenMinuteDays
            | Field::AnomalyDays => Kind::Number,
            Field::Signatures | Field::Network => Kind::Toggle,
            Field::Sensitivity => Kind::Level,
            Field::CpuOverride
            | Field::MemoryOverride
            | Field::DiskOverride
            | Field::NetworkOverride => Kind::Override,
            Field::Windows => Kind::List,
            Field::Service => Kind::ReadOnly,
        }
    }

    fn help(self) -> &'static str {
        match self {
            Field::Interval => {
                "Seconds between samples, 1 to 3600. Shorter catches brief spikes but writes more data."
            }
            Field::Signatures => {
                "Verify the signatures of newly seen executables in the background (publisher classification)."
            }
            Field::Network => {
                "Attribute network traffic to processes. Needs administrator rights; skipped with a notice otherwise."
            }
            Field::Sensitivity => {
                "How readily anomalies are raised: low is conservative, high flags smaller or shorter deviations."
            }
            Field::CpuOverride
            | Field::MemoryOverride
            | Field::DiskOverride
            | Field::NetworkOverride => {
                "Overrides the sensitivity for one resource. Inherit uses the setting above."
            }
            Field::Windows => {
                "Rolling baseline windows in hours, shortest first, strictly increasing (for example 1, 24, 168)."
            }
            Field::Recompute => {
                "How often a running monitor recomputes the baselines, 1 to 1440 minutes."
            }
            Field::RawDays => "How long the raw samples are kept (about 1 GB a day at 5 s).",
            Field::OneMinuteDays => "How long the 1-minute rollups are kept.",
            Field::FifteenMinuteDays => "How long the 15-minute rollups are kept.",
            Field::AnomalyDays => "How long anomaly events are kept.",
            Field::Service => {
                "Service settings arrive with the Windows service. Until then run `winperf monitor run`."
            }
        }
    }
}

fn level_text(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Low => "low",
        Sensitivity::Normal => "normal",
        Sensitivity::High => "high",
    }
}

fn override_text(s: Option<Sensitivity>) -> &'static str {
    s.map_or("inherit", level_text)
}

/// A field's value as shown (and as edited, for numbers and lists).
pub fn value_text(c: &Config, f: Field) -> String {
    let onoff = |b: bool| if b { "on" } else { "off" }.to_string();
    match f {
        Field::Interval => c.monitor.interval_secs.to_string(),
        Field::Signatures => onoff(c.monitor.signatures),
        Field::Network => onoff(c.monitor.network),
        Field::Sensitivity => level_text(c.detection.sensitivity).to_string(),
        Field::CpuOverride => override_text(c.detection.cpu).to_string(),
        Field::MemoryOverride => override_text(c.detection.memory).to_string(),
        Field::DiskOverride => override_text(c.detection.disk).to_string(),
        Field::NetworkOverride => override_text(c.detection.network).to_string(),
        Field::Windows => c
            .baseline
            .windows_hours
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        Field::Recompute => c.baseline.recompute_minutes.to_string(),
        Field::RawDays => c.retention.raw_samples_days.to_string(),
        Field::OneMinuteDays => c.retention.aggregate_1min_days.to_string(),
        Field::FifteenMinuteDays => c.retention.aggregate_15min_days.to_string(),
        Field::AnomalyDays => c.retention.anomaly_days.to_string(),
        Field::Service => "not installed".to_string(),
    }
}

const LEVELS: [Sensitivity; 3] = [Sensitivity::Low, Sensitivity::Normal, Sensitivity::High];

fn step_level(s: Sensitivity, delta: isize) -> Sensitivity {
    let i = LEVELS.iter().position(|x| *x == s).unwrap_or(1) as isize;
    LEVELS[(i + delta).rem_euclid(3) as usize]
}

/// Inherit, then low, normal, high.
fn step_override(s: Option<Sensitivity>, delta: isize) -> Option<Sensitivity> {
    let i = match s {
        None => 0,
        Some(l) => 1 + LEVELS.iter().position(|x| *x == l).unwrap_or(1) as isize,
    };
    match (i + delta).rem_euclid(4) {
        0 => None,
        n => Some(LEVELS[(n - 1) as usize]),
    }
}

/// Change a toggle or choice by `delta` steps.
fn step(c: &mut Config, f: Field, delta: isize) {
    match f {
        Field::Signatures => c.monitor.signatures = !c.monitor.signatures,
        Field::Network => c.monitor.network = !c.monitor.network,
        Field::Sensitivity => c.detection.sensitivity = step_level(c.detection.sensitivity, delta),
        Field::CpuOverride => c.detection.cpu = step_override(c.detection.cpu, delta),
        Field::MemoryOverride => c.detection.memory = step_override(c.detection.memory, delta),
        Field::DiskOverride => c.detection.disk = step_override(c.detection.disk, delta),
        Field::NetworkOverride => c.detection.network = step_override(c.detection.network, delta),
        _ => {}
    }
}

/// Set a number or list field from typed text. Errors say what is wrong with the text itself;
/// range problems are caught by validating the whole configuration afterwards.
fn set_text(c: &mut Config, f: Field, text: &str) -> Result<(), String> {
    let number = |t: &str| -> Result<u32, String> {
        t.trim()
            .parse::<u32>()
            .map_err(|_| format!("'{}' is not a whole number", t.trim()))
    };
    match f {
        Field::Interval => c.monitor.interval_secs = u64::from(number(text)?),
        Field::Recompute => c.baseline.recompute_minutes = number(text)?,
        Field::RawDays => c.retention.raw_samples_days = number(text)?,
        Field::OneMinuteDays => c.retention.aggregate_1min_days = number(text)?,
        Field::FifteenMinuteDays => c.retention.aggregate_15min_days = number(text)?,
        Field::AnomalyDays => c.retention.anomaly_days = number(text)?,
        Field::Windows => {
            let list: Result<Vec<u32>, String> = text
                .split([',', ' '])
                .filter(|p| !p.trim().is_empty())
                .map(number)
                .collect();
            c.baseline.windows_hours = list?;
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub text: String,
    pub error: bool,
}

pub struct SettingsView {
    path: Option<PathBuf>,
    saved: Config,
    pub working: Config,
    pub cursor: usize,
    /// The text being typed into a number or list field.
    pub editing: Option<String>,
    pub message: Option<Message>,
    /// The first Esc/q with unsaved changes warns; a second one discards them.
    warned: bool,
    /// A save that the dashboard has not yet applied.
    just_saved: Option<Config>,
    pub table: TableState,
}

impl SettingsView {
    pub fn new(source: Option<SettingsSource>) -> Self {
        let (path, config) = match source {
            Some(s) => (Some(s.path), s.config),
            None => (None, Config::default()),
        };
        let mut view = Self {
            path,
            saved: config.clone(),
            working: config,
            cursor: 0,
            editing: None,
            message: None,
            warned: false,
            just_saved: None,
            table: TableState::default(),
        };
        view.table.select(Some(view.row_of(0)));
        view
    }

    pub fn field(&self) -> Field {
        Field::ALL[self.cursor]
    }

    pub fn unsaved(&self) -> bool {
        self.working != self.saved
    }

    /// The configuration just saved, once, so the dashboard can apply it.
    pub fn take_saved(&mut self) -> Option<Config> {
        self.just_saved.take()
    }

    /// Row of field `i` in the table, counting the group headings above it.
    fn row_of(&self, i: usize) -> usize {
        let mut rows = 0;
        let mut last = "";
        for (n, f) in Field::ALL.iter().enumerate() {
            if f.group() != last {
                rows += 1;
                last = f.group();
            }
            if n == i {
                return rows;
            }
            rows += 1;
        }
        rows
    }

    fn move_cursor(&mut self, delta: isize) {
        let next = (self.cursor as isize + delta).clamp(0, Field::ALL.len() as isize - 1);
        self.cursor = next as usize;
        self.table.select(Some(self.row_of(self.cursor)));
        self.warned = false;
    }

    fn note(&mut self, text: impl Into<String>, error: bool) {
        self.message = Some(Message {
            text: text.into(),
            error,
        });
    }

    /// Check `candidate` and make it the working copy, or say why not.
    fn accept(&mut self, candidate: Config) -> bool {
        match candidate.validate() {
            Ok(()) => {
                self.working = candidate;
                true
            }
            Err(e) => {
                self.note(e.to_string().replace('\n', " "), true);
                false
            }
        }
    }

    fn step_field(&mut self, delta: isize) {
        let f = self.field();
        if matches!(f.kind(), Kind::Toggle | Kind::Level | Kind::Override) {
            let mut candidate = self.working.clone();
            step(&mut candidate, f, delta);
            if self.accept(candidate) {
                self.message = None;
            }
        }
    }

    fn begin_edit(&mut self) {
        let f = self.field();
        match f.kind() {
            Kind::Number | Kind::List => {
                self.editing = Some(value_text(&self.working, f));
                self.message = None;
            }
            Kind::ReadOnly => self.note(f.help(), false),
            _ => self.step_field(1),
        }
    }

    fn commit_edit(&mut self) {
        let Some(text) = self.editing.clone() else {
            return;
        };
        let mut candidate = self.working.clone();
        if let Err(e) = set_text(&mut candidate, self.field(), &text) {
            self.note(e, true);
            return;
        }
        if self.accept(candidate) {
            self.editing = None;
            self.message = None;
        }
    }

    /// Save the working copy into the file, keeping the file's comments.
    pub fn save(&mut self) {
        let Some(path) = self.path.clone() else {
            self.note("There is no configuration file to save to.", true);
            return;
        };
        let existing = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                DEFAULT_CONFIG_TEMPLATE.to_string()
            }
            Err(e) => {
                self.note(format!("Cannot read {}: {e}", path.display()), true);
                return;
            }
        };
        let text = match config_edit::apply(&existing, &self.working) {
            Ok(t) => t,
            Err(e) => {
                self.note(
                    format!("Not saved: {}", e.to_string().replace('\n', " ")),
                    true,
                );
                return;
            }
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            self.note(format!("Cannot create {}: {e}", dir.display()), true);
            return;
        }
        if let Err(e) = std::fs::write(&path, text) {
            self.note(format!("Cannot write {}: {e}", path.display()), true);
            return;
        }
        self.saved = self.working.clone();
        self.just_saved = Some(self.working.clone());
        self.warned = false;
        self.note(
            format!(
                "Saved to {}. The dashboard uses it now; a running monitor reads it when it restarts.",
                path.display()
            ),
            false,
        );
    }

    fn revert(&mut self) {
        self.working = self.saved.clone();
        self.editing = None;
        self.note("Changes discarded.", false);
    }

    /// Leave, unless there are unsaved changes the person has not been warned about.
    fn leave(&mut self, nav: Nav) -> Nav {
        if self.unsaved() && !self.warned {
            self.warned = true;
            self.note(
                "Unsaved changes: w saves them; press the same key again to discard them.",
                true,
            );
            return Nav::Stay;
        }
        if self.unsaved() {
            self.working = self.saved.clone();
        }
        self.warned = false;
        nav
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        if let Some(text) = &mut self.editing {
            match key.code {
                KeyCode::Esc => self.editing = None,
                KeyCode::Enter => self.commit_edit(),
                KeyCode::Backspace => {
                    text.pop();
                }
                KeyCode::Char(c) if c.is_ascii_digit() || c == ',' || c == ' ' => text.push(c),
                _ => {}
            }
            return Nav::Stay;
        }
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return Nav::Quit,
            (KeyCode::Char('s'), m) if m.contains(KeyModifiers::CONTROL) => self.save(),
            (KeyCode::Char('q'), _) => return self.leave(Nav::Quit),
            (KeyCode::Esc | KeyCode::Char('s'), _) => return self.leave(Nav::Back),
            (KeyCode::Up | KeyCode::Char('k'), _) => self.move_cursor(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => self.move_cursor(1),
            (KeyCode::Home | KeyCode::Char('g'), _) => self.move_cursor(isize::MIN / 2),
            (KeyCode::End | KeyCode::Char('G'), _) => self.move_cursor(isize::MAX / 2),
            (KeyCode::Enter | KeyCode::Char(' '), _) => self.begin_edit(),
            (KeyCode::Right, _) => self.step_field(1),
            (KeyCode::Left, _) => self.step_field(-1),
            (KeyCode::Char('w'), _) => self.save(),
            (KeyCode::Char('u'), _) => self.revert(),
            _ => {}
        }
        Nav::Stay
    }
}

// ---- drawing -------------------------------------------------------------------------------

pub fn draw(f: &mut Frame, area: Rect, view: &mut SettingsView) {
    let [title, body, help, message, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(2),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .areas(area);

    let location = view
        .path
        .as_ref()
        .map_or("no configuration file".to_string(), |p| {
            p.display().to_string()
        });
    let mut spans = vec![
        Span::styled(" WinPerf ", Style::new().bold().fg(Color::Cyan)),
        Span::raw(format!("Configuration  {location}")),
    ];
    if view.unsaved() {
        spans.push(Span::styled(
            "  (unsaved changes)",
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), title);

    let mut rows: Vec<Row> = Vec::new();
    let mut last = "";
    for (i, field) in Field::ALL.iter().enumerate() {
        if field.group() != last {
            last = field.group();
            rows.push(Row::new(vec![
                Cell::new(last).style(Style::new().bold().fg(Color::Cyan)),
            ]));
        }
        let editing_here = i == view.cursor && view.editing.is_some();
        let value = if editing_here {
            format!("{}_", view.editing.as_deref().unwrap_or(""))
        } else {
            value_text(&view.working, *field)
        };
        let changed = value_text(&view.saved, *field) != value_text(&view.working, *field);
        let style = if editing_here {
            Style::new().fg(Color::Yellow)
        } else if changed {
            Style::new().fg(Color::Green)
        } else if field.kind() == Kind::ReadOnly {
            Style::new().fg(Color::DarkGray)
        } else {
            Style::new()
        };
        rows.push(Row::new(vec![
            Cell::new(field.label()),
            Cell::new(value).style(style),
            Cell::new(if changed && !editing_here {
                "changed"
            } else {
                ""
            })
            .style(Style::new().fg(Color::Green)),
        ]));
    }
    let table = Table::new(
        rows,
        [
            Constraint::Length(34),
            Constraint::Min(18),
            Constraint::Length(8),
        ],
    )
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    f.render_stateful_widget(table, body, &mut view.table);

    f.render_widget(
        Paragraph::new(view.field().help())
            .wrap(Wrap { trim: true })
            .style(Style::new().fg(Color::DarkGray)),
        help,
    );
    if let Some(m) = &view.message {
        f.render_widget(
            Paragraph::new(m.text.clone())
                .wrap(Wrap { trim: true })
                .style(if m.error {
                    Style::new().fg(Color::Red)
                } else {
                    Style::new().fg(Color::Green)
                }),
            message,
        );
    }
    let hint = if view.editing.is_some() {
        " type a value  Enter accept  Esc cancel"
    } else {
        " q quit  s back  ↑↓ select  Enter edit  ←→ change  w save  u discard"
    };
    f.render_widget(
        Paragraph::new(hint).style(Style::new().fg(Color::DarkGray)),
        footer,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use winperf_core::config::ConfigError;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("winperf-settings-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn file(&self) -> PathBuf {
            self.0.join("config.toml")
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    fn type_text(v: &mut SettingsView, text: &str) {
        for c in text.chars() {
            v.on_key(ch(c));
        }
    }

    fn at(v: &mut SettingsView, f: Field) {
        while v.field() != f {
            v.on_key(ch('j'));
        }
    }

    fn view_at(path: PathBuf, config: Config) -> SettingsView {
        SettingsView::new(Some(SettingsSource { path, config }))
    }

    fn screen(v: &mut SettingsView, w: u16, h: u16) -> String {
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

    // ---- editing --------------------------------------------------------------------------

    #[test]
    fn toggles_and_choices_change_with_enter_and_the_arrows() {
        let mut v = SettingsView::new(None);
        at(&mut v, Field::Signatures);
        v.on_key(key(KeyCode::Enter));
        assert!(!v.working.monitor.signatures);
        v.on_key(ch(' '));
        assert!(v.working.monitor.signatures);

        at(&mut v, Field::Sensitivity);
        v.on_key(key(KeyCode::Right));
        assert_eq!(v.working.detection.sensitivity, Sensitivity::High);
        v.on_key(key(KeyCode::Right));
        assert_eq!(v.working.detection.sensitivity, Sensitivity::Low, "wraps");
        v.on_key(key(KeyCode::Left));
        assert_eq!(v.working.detection.sensitivity, Sensitivity::High);

        at(&mut v, Field::CpuOverride);
        assert_eq!(v.working.detection.cpu, None);
        v.on_key(key(KeyCode::Right));
        assert_eq!(v.working.detection.cpu, Some(Sensitivity::Low));
        v.on_key(key(KeyCode::Left));
        v.on_key(key(KeyCode::Left));
        assert_eq!(
            v.working.detection.cpu,
            Some(Sensitivity::High),
            "inherit wraps to high"
        );
        v.on_key(key(KeyCode::Right));
        assert_eq!(v.working.detection.cpu, None);
    }

    #[test]
    fn a_number_is_typed_and_accepted_with_enter() {
        let mut v = SettingsView::new(None);
        assert_eq!(v.field(), Field::Interval);
        v.on_key(key(KeyCode::Enter));
        assert_eq!(v.editing.as_deref(), Some("5"));
        v.on_key(key(KeyCode::Backspace));
        type_text(&mut v, "30");
        v.on_key(key(KeyCode::Enter));
        assert_eq!(v.editing, None);
        assert_eq!(v.working.monitor.interval_secs, 30);
        assert!(v.unsaved());
    }

    #[test]
    fn an_out_of_range_or_malformed_number_is_refused_with_a_reason() {
        let mut v = SettingsView::new(None);
        v.on_key(key(KeyCode::Enter));
        v.on_key(key(KeyCode::Backspace));
        type_text(&mut v, "0");
        v.on_key(key(KeyCode::Enter));
        assert!(v.editing.is_some(), "stays in edit mode");
        assert_eq!(
            v.working.monitor.interval_secs, 5,
            "the working copy is untouched"
        );
        let m = v.message.clone().unwrap();
        assert!(m.error && m.text.contains("interval_secs"), "{m:?}");

        v.on_key(key(KeyCode::Backspace));
        v.on_key(key(KeyCode::Enter)); // empty text
        assert!(
            v.message
                .clone()
                .unwrap()
                .text
                .contains("not a whole number")
        );
        v.on_key(key(KeyCode::Esc));
        assert_eq!(v.editing, None);
        assert!(!v.unsaved());
    }

    #[test]
    fn only_digits_commas_and_spaces_can_be_typed() {
        let mut v = SettingsView::new(None);
        v.on_key(key(KeyCode::Enter));
        type_text(&mut v, "ab-.9");
        assert_eq!(v.editing.as_deref(), Some("59"));
    }

    #[test]
    fn baseline_windows_are_a_comma_separated_list_that_must_increase() {
        let mut v = SettingsView::new(None);
        at(&mut v, Field::Windows);
        v.on_key(key(KeyCode::Enter));
        assert_eq!(v.editing.as_deref(), Some("1, 24, 168"));
        for _ in 0..10 {
            v.on_key(key(KeyCode::Backspace));
        }
        type_text(&mut v, "2, 12, 72");
        v.on_key(key(KeyCode::Enter));
        assert_eq!(v.working.baseline.windows_hours, vec![2, 12, 72]);

        v.on_key(key(KeyCode::Enter));
        for _ in 0..10 {
            v.on_key(key(KeyCode::Backspace));
        }
        type_text(&mut v, "24, 2");
        v.on_key(key(KeyCode::Enter));
        assert!(v.editing.is_some(), "decreasing windows are refused");
        assert_eq!(v.working.baseline.windows_hours, vec![2, 12, 72]);
    }

    #[test]
    fn the_service_row_is_read_only() {
        let mut v = SettingsView::new(None);
        at(&mut v, Field::Service);
        let before = v.working.clone();
        v.on_key(key(KeyCode::Enter));
        v.on_key(key(KeyCode::Right));
        assert_eq!(v.working, before);
        assert_eq!(v.editing, None);
        assert!(v.message.clone().unwrap().text.contains("Windows service"));
    }

    #[test]
    fn the_cursor_stays_inside_the_fields_and_headings_are_skipped() {
        let mut v = SettingsView::new(None);
        v.on_key(ch('k'));
        assert_eq!(v.cursor, 0);
        v.on_key(ch('G'));
        assert_eq!(v.field(), Field::Service);
        v.on_key(ch('j'));
        assert_eq!(v.field(), Field::Service);
        v.on_key(ch('g'));
        // Row 0 is the "Monitoring" heading, so the first field is on row 1.
        assert_eq!(v.table.selected(), Some(1));
        at(&mut v, Field::Sensitivity);
        assert_eq!(
            v.table.selected(),
            Some(5),
            "after the Monitoring group and a heading"
        );
    }

    // ---- saving ---------------------------------------------------------------------------

    #[test]
    fn saving_edits_the_file_in_place_and_keeps_its_comments() {
        let dir = Scratch::new("save");
        std::fs::write(dir.file(), DEFAULT_CONFIG_TEMPLATE).unwrap();
        let mut v = view_at(dir.file(), Config::default());
        v.on_key(key(KeyCode::Enter));
        v.on_key(key(KeyCode::Backspace));
        type_text(&mut v, "15");
        v.on_key(key(KeyCode::Enter));
        at(&mut v, Field::Network);
        v.on_key(key(KeyCode::Enter));
        at(&mut v, Field::AnomalyDays);
        v.on_key(key(KeyCode::Enter));
        for _ in 0..4 {
            v.on_key(key(KeyCode::Backspace));
        }
        type_text(&mut v, "30");
        v.on_key(key(KeyCode::Enter));
        assert!(v.unsaved());

        v.on_key(ch('w'));
        assert!(!v.unsaved());
        let m = v.message.clone().unwrap();
        assert!(!m.error && m.text.contains("Saved to"), "{m:?}");

        let text = std::fs::read_to_string(dir.file()).unwrap();
        assert!(
            text.contains("# Seconds between samples (1-3600)."),
            "{text}"
        );
        let back = Config::from_toml_str(&text).unwrap();
        assert_eq!(back, v.working);
        assert_eq!(back.monitor.interval_secs, 15);
        assert!(!back.monitor.network);
        assert_eq!(back.retention.anomaly_days, 30);
    }

    #[test]
    fn saving_creates_the_file_when_there_is_none() {
        let dir = Scratch::new("create");
        let path = dir.0.join("nested").join("config.toml");
        let mut v = view_at(path.clone(), Config::default());
        v.on_key(key(KeyCode::Enter));
        v.on_key(key(KeyCode::Backspace));
        type_text(&mut v, "9");
        v.on_key(key(KeyCode::Enter));
        v.on_key(ch('w'));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("# WinPerf configuration."),
            "starts from the commented template: {text}"
        );
        assert_eq!(
            Config::from_toml_str(&text).unwrap().monitor.interval_secs,
            9
        );
    }

    #[test]
    fn a_saved_change_is_handed_to_the_dashboard_once() {
        let dir = Scratch::new("apply");
        let mut v = view_at(dir.file(), Config::default());
        assert_eq!(v.take_saved(), None);
        at(&mut v, Field::Windows);
        v.on_key(key(KeyCode::Enter));
        for _ in 0..12 {
            v.on_key(key(KeyCode::Backspace));
        }
        type_text(&mut v, "1, 12");
        v.on_key(key(KeyCode::Enter));
        v.on_key(ch('w'));
        let applied = v.take_saved().expect("the saved configuration");
        assert_eq!(applied.baseline.windows_hours, vec![1, 12]);
        assert_eq!(v.take_saved(), None);
    }

    #[test]
    fn a_file_that_is_not_valid_toml_is_not_overwritten() {
        let dir = Scratch::new("broken");
        std::fs::write(dir.file(), "[monitor\nbroken").unwrap();
        let mut v = view_at(dir.file(), Config::default());
        v.on_key(key(KeyCode::Enter));
        v.on_key(key(KeyCode::Backspace));
        type_text(&mut v, "9");
        v.on_key(key(KeyCode::Enter));
        v.on_key(ch('w'));
        assert!(v.message.clone().unwrap().error);
        assert!(v.unsaved(), "still unsaved");
        assert_eq!(
            std::fs::read_to_string(dir.file()).unwrap(),
            "[monitor\nbroken"
        );
        assert_eq!(v.take_saved(), None);
    }

    #[test]
    fn without_a_file_saving_says_so() {
        let mut v = SettingsView::new(None);
        v.on_key(ch('w'));
        assert!(v.message.clone().unwrap().error);
    }

    // ---- leaving --------------------------------------------------------------------------

    #[test]
    fn leaving_with_unsaved_changes_warns_once_then_discards() {
        let mut v = SettingsView::new(None);
        at(&mut v, Field::Signatures);
        v.on_key(key(KeyCode::Enter));
        assert!(v.unsaved());
        assert_eq!(v.on_key(key(KeyCode::Esc)), Nav::Stay);
        assert!(v.message.clone().unwrap().text.contains("Unsaved changes"));
        assert_eq!(v.on_key(key(KeyCode::Esc)), Nav::Back);
        assert!(!v.unsaved(), "discarded");
        assert!(v.working.monitor.signatures);
    }

    #[test]
    fn moving_the_cursor_resets_the_warning_and_q_quits_the_same_way() {
        let mut v = SettingsView::new(None);
        at(&mut v, Field::Network);
        v.on_key(key(KeyCode::Enter));
        assert_eq!(v.on_key(ch('q')), Nav::Stay);
        v.on_key(ch('j')); // moving on forgets the warning
        assert_eq!(v.on_key(ch('q')), Nav::Stay);
        assert_eq!(v.on_key(ch('q')), Nav::Quit);
    }

    #[test]
    fn nothing_unsaved_means_leaving_is_immediate() {
        let mut v = SettingsView::new(None);
        assert_eq!(v.on_key(ch('s')), Nav::Back);
        assert_eq!(v.on_key(ch('q')), Nav::Quit);
    }

    #[test]
    fn u_discards_the_changes() {
        let mut v = SettingsView::new(None);
        at(&mut v, Field::Sensitivity);
        v.on_key(key(KeyCode::Right));
        assert!(v.unsaved());
        v.on_key(ch('u'));
        assert!(!v.unsaved());
        assert_eq!(v.working.detection.sensitivity, Sensitivity::Normal);
    }

    #[test]
    fn escape_cancels_an_edit_without_leaving() {
        let mut v = SettingsView::new(None);
        v.on_key(key(KeyCode::Enter));
        type_text(&mut v, "99");
        assert_eq!(v.on_key(key(KeyCode::Esc)), Nav::Stay);
        assert_eq!(v.editing, None);
        assert_eq!(v.working.monitor.interval_secs, 5);
    }

    // ---- the pure helpers -----------------------------------------------------------------

    #[test]
    fn every_value_is_shown_as_text() {
        let mut c = Config::default();
        c.detection.memory = Some(Sensitivity::High);
        let text: Vec<String> = Field::ALL.iter().map(|f| value_text(&c, *f)).collect();
        assert_eq!(
            text,
            vec![
                "5",
                "on",
                "on",
                "normal",
                "inherit",
                "high",
                "inherit",
                "inherit",
                "1, 24, 168",
                "15",
                "2",
                "14",
                "180",
                "180",
                "not installed"
            ]
        );
    }

    #[test]
    fn every_editable_field_round_trips_through_its_text() {
        let mut c = Config::default();
        for f in Field::ALL {
            if matches!(f.kind(), Kind::Number | Kind::List) {
                let text = value_text(&c, f);
                set_text(&mut c, f, &text).unwrap();
            }
        }
        assert_eq!(c, Config::default());
        assert!(matches!(
            {
                let mut bad = Config::default();
                set_text(&mut bad, Field::Interval, "-3").unwrap_err();
                bad.monitor.interval_secs = 0;
                bad.validate()
            },
            Err(ConfigError::Invalid(_))
        ));
    }

    // ---- drawing --------------------------------------------------------------------------

    #[test]
    fn the_screen_lists_every_group_and_setting_with_its_value() {
        let mut v = view_at(
            PathBuf::from(r"C:\ProgramData\WinPerf\config.toml"),
            Config::default(),
        );
        let s = screen(&mut v, 100, 30);
        for expected in [
            "Configuration",
            r"C:\ProgramData\WinPerf\config.toml",
            "Monitoring",
            "Sampling interval (seconds)",
            "Detection sensitivity",
            "CPU override",
            "inherit",
            "Baselines",
            "1, 24, 168",
            "Data retention (days)",
            "Raw samples",
            "Service",
            "Windows service",
            "not installed",
            "w save",
        ] {
            assert!(s.contains(expected), "missing {expected:?} in\n{s}");
        }
    }

    #[test]
    fn changed_settings_are_marked_and_the_title_says_unsaved() {
        let mut v = SettingsView::new(None);
        at(&mut v, Field::Sensitivity);
        v.on_key(key(KeyCode::Right));
        let s = screen(&mut v, 100, 30);
        assert!(s.contains("(unsaved changes)"), "{s}");
        assert!(s.contains("changed"), "{s}");
        assert!(s.contains("high"), "{s}");
    }

    #[test]
    fn editing_shows_the_text_being_typed_and_the_edit_keys() {
        let mut v = SettingsView::new(None);
        v.on_key(key(KeyCode::Enter));
        type_text(&mut v, "7");
        let s = screen(&mut v, 100, 30);
        assert!(s.contains("57_"), "{s}");
        assert!(
            s.contains("Enter accept") && s.contains("Esc cancel"),
            "{s}"
        );
    }

    #[test]
    fn the_selected_settings_help_and_any_message_are_shown() {
        let mut v = SettingsView::new(None);
        let s = screen(&mut v, 100, 30);
        assert!(s.contains("Seconds between samples, 1 to 3600"), "{s}");
        v.on_key(key(KeyCode::Enter));
        v.on_key(key(KeyCode::Backspace));
        type_text(&mut v, "0");
        v.on_key(key(KeyCode::Enter));
        let s = screen(&mut v, 100, 30);
        assert!(
            s.contains("interval_secs must be between 1 and 3600"),
            "{s}"
        );
    }

    #[test]
    fn it_fits_the_smallest_supported_screen() {
        let mut v = SettingsView::new(None);
        let s = screen(&mut v, 80, 24);
        assert!(
            s.contains("Monitoring") && s.contains("Sampling interval") && s.contains("w save"),
            "{s}"
        );
    }
}
