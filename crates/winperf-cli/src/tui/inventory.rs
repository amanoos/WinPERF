//! The Software Inventory screen (PRD FR-020 C): what is installed and what the monitor has seen
//! run, split by publisher class (Microsoft, third-party, unsigned, unknown), with a filter by class
//! and a "running only" switch. A read-only view of the database (installed software comes from
//! `winperf inventory scan --save`, executables from the monitor).

use crate::tui::baselines::Nav;
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use winperf_core::Classification;
use winperf_core::inventory::InstalledApp;
use winperf_storage::{Database, ExecutableRow};

/// How often the stored inventory is re-read while the screen is open.
const REFRESH: Duration = Duration::from_secs(15);
/// Below this width the path/installed column is left out.
const WIDE: u16 = 110;

#[derive(Debug, Clone)]
pub struct InventorySource {
    pub db_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Installed applications (from the registry scan).
    Installed,
    /// Executables the monitor has seen, with how many are running now.
    Executables,
}

fn class_label(c: Classification) -> &'static str {
    match c {
        Classification::MicrosoftOfficial => "Microsoft",
        Classification::ThirdPartyOfficial => "Third-party",
        Classification::Unsigned => "Unsigned",
        Classification::Unknown => "Unknown",
    }
}

const CLASSES: [Classification; 4] = [
    Classification::MicrosoftOfficial,
    Classification::ThirdPartyOfficial,
    Classification::Unsigned,
    Classification::Unknown,
];

fn class_style(c: Classification) -> Style {
    match c {
        Classification::MicrosoftOfficial => Style::new().fg(Color::Cyan),
        Classification::ThirdPartyOfficial => Style::new(),
        Classification::Unsigned => Style::new().fg(Color::Yellow),
        Classification::Unknown => Style::new().fg(Color::DarkGray),
    }
}

/// One line of either list, in the columns the screen shows.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub name: String,
    /// Version (installed) or product (executables).
    pub detail: String,
    /// Publisher (installed) or signer (executables).
    pub publisher: String,
    pub class: Classification,
    /// Running instances; `None` for installed software (not tracked per product).
    pub running: Option<u32>,
    /// Install date (installed) or file path (executables).
    pub extra: String,
}

fn from_app(a: &InstalledApp) -> Item {
    Item {
        name: a.name.clone(),
        detail: a.version.clone().unwrap_or_default(),
        publisher: a.publisher.clone().unwrap_or_default(),
        class: a.classification,
        running: None,
        extra: a.install_date.clone().unwrap_or_default(),
    }
}

fn from_exe(e: &ExecutableRow) -> Item {
    Item {
        name: e.file_name.clone(),
        detail: e.product_name.clone().unwrap_or_default(),
        publisher: e.signer.clone().unwrap_or_default(),
        class: e.classification,
        running: Some(e.running_instances),
        extra: e.file_path.clone(),
    }
}

pub struct InventoryView {
    source: Option<InventorySource>,
    installed: Vec<Item>,
    executables: Vec<Item>,
    pub mode: Mode,
    /// `None` shows every class.
    pub class: Option<Classification>,
    /// Executables only: hide the ones with no running process.
    pub running_only: bool,
    /// What is on screen.
    pub rows: Vec<Item>,
    pub table: TableState,
    pub problem: Option<String>,
    loaded_at: Option<Instant>,
    stale: bool,
    pub page_size: usize,
}

impl InventoryView {
    pub fn new(source: Option<InventorySource>) -> Self {
        Self {
            source,
            installed: Vec::new(),
            executables: Vec::new(),
            mode: Mode::Executables,
            class: None,
            running_only: false,
            rows: Vec::new(),
            table: TableState::default(),
            problem: None,
            loaded_at: None,
            stale: true,
            page_size: 10,
        }
    }

    pub fn mark_stale(&mut self) {
        self.stale = true;
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
        if !source.db_path.exists() {
            self.problem = Some(format!(
                "no database at {} yet. Run `winperf monitor run` first.",
                source.db_path.display()
            ));
            self.set_items(Vec::new(), Vec::new());
            return;
        }
        let loaded = Database::open_read_only(&source.db_path)
            .and_then(|db| Ok((db.load_installed_apps()?, db.list_executables()?)));
        match loaded {
            Ok((apps, exes)) => {
                self.problem = None;
                self.set_items(
                    apps.iter().map(from_app).collect(),
                    exes.iter().map(from_exe).collect(),
                );
            }
            Err(e) => {
                self.problem = Some(e.to_string());
                self.set_items(Vec::new(), Vec::new());
            }
        }
    }

    /// Show these lists. Keeps the cursor on the same entry if it is still shown.
    pub fn set_items(&mut self, installed: Vec<Item>, executables: Vec<Item>) {
        self.installed = installed;
        self.executables = executables;
        self.rebuild();
    }

    fn current(&self) -> &[Item] {
        match self.mode {
            Mode::Installed => &self.installed,
            Mode::Executables => &self.executables,
        }
    }

    /// Whether running-only applies to the list being shown.
    fn hides_idle(&self) -> bool {
        self.running_only && self.mode == Mode::Executables
    }

    /// How many entries of the current list belong to each class (and the total), ignoring the
    /// class filter so the counts stay put while filtering.
    pub fn counts(&self) -> (usize, [usize; 4]) {
        let mut by = [0usize; 4];
        let hide_idle = self.hides_idle();
        let list: Vec<&Item> = self
            .current()
            .iter()
            .filter(|i| !hide_idle || i.running > Some(0))
            .collect();
        for item in &list {
            if let Some(n) = CLASSES.iter().position(|c| *c == item.class) {
                by[n] += 1;
            }
        }
        (list.len(), by)
    }

    fn rebuild(&mut self) {
        let keep = self
            .table
            .selected()
            .and_then(|i| self.rows.get(i))
            .map(|r| (r.name.clone(), r.extra.clone(), r.detail.clone()));
        let class = self.class;
        let hide_idle = self.hides_idle();
        self.rows = self
            .current()
            .iter()
            .filter(|i| class.is_none_or(|c| i.class == c))
            .filter(|i| !hide_idle || i.running > Some(0))
            .cloned()
            .collect();
        let index = keep
            .and_then(|(n, e, d)| {
                self.rows
                    .iter()
                    .position(|r| r.name == n && r.extra == e && r.detail == d)
            })
            .or(if self.rows.is_empty() { None } else { Some(0) });
        self.table.select(index);
    }

    pub fn selected(&self) -> Option<&Item> {
        self.rows.get(self.table.selected()?)
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

    fn set_class(&mut self, class: Option<Classification>) {
        self.class = class;
        self.rebuild();
    }

    fn cycle_class(&mut self) {
        let next = match self.class {
            None => Some(CLASSES[0]),
            Some(c) => CLASSES
                .iter()
                .position(|x| *x == c)
                .and_then(|i| CLASSES.get(i + 1))
                .copied(),
        };
        self.set_class(next);
    }

    fn switch_mode(&mut self) {
        self.mode = match self.mode {
            Mode::Installed => Mode::Executables,
            Mode::Executables => Mode::Installed,
        };
        self.table.select(None);
        self.rebuild();
    }

    pub fn on_key(&mut self, key: KeyEvent) -> Nav {
        let page = self.page_size.max(1) as isize;
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => return Nav::Quit,
            (KeyCode::Char('q'), _) => return Nav::Quit,
            (KeyCode::Esc | KeyCode::Char('w'), _) => return Nav::Back,
            (KeyCode::Up | KeyCode::Char('k'), _) => self.move_by(-1),
            (KeyCode::Down | KeyCode::Char('j'), _) => self.move_by(1),
            (KeyCode::PageUp, _) => self.move_by(-page),
            (KeyCode::PageDown, _) => self.move_by(page),
            (KeyCode::Home | KeyCode::Char('g'), _) => self.move_by(isize::MIN / 2),
            (KeyCode::End | KeyCode::Char('G'), _) => self.move_by(isize::MAX / 2),
            (KeyCode::Tab | KeyCode::BackTab | KeyCode::Left | KeyCode::Right, _) => {
                self.switch_mode()
            }
            (KeyCode::Char('0'), _) => self.set_class(None),
            (KeyCode::Char('1'), _) => self.set_class(Some(CLASSES[0])),
            (KeyCode::Char('2'), _) => self.set_class(Some(CLASSES[1])),
            (KeyCode::Char('3'), _) => self.set_class(Some(CLASSES[2])),
            (KeyCode::Char('4'), _) => self.set_class(Some(CLASSES[3])),
            (KeyCode::Char('c'), _) => self.cycle_class(),
            (KeyCode::Char('r'), _) => {
                self.running_only = !self.running_only;
                self.rebuild();
            }
            (KeyCode::Char('l'), _) => self.stale = true,
            _ => {}
        }
        Nav::Stay
    }
}

// ---- drawing -------------------------------------------------------------------------------

fn row(i: &Item, mode: Mode, wide: bool) -> Row<'static> {
    let mut cells = vec![
        Cell::new(i.name.clone()),
        Cell::new(i.detail.clone()),
        Cell::new(i.publisher.clone()),
        Cell::new(class_label(i.class)).style(class_style(i.class)),
    ];
    if mode == Mode::Executables {
        cells.push(match i.running {
            Some(0) | None => Cell::new("-").style(Style::new().fg(Color::DarkGray)),
            Some(n) => Cell::new(n.to_string()).style(Style::new().fg(Color::Green)),
        });
    }
    if wide {
        cells.push(Cell::new(i.extra.clone()));
    }
    Row::new(cells)
}

pub fn draw(f: &mut Frame, area: Rect, view: &mut InventoryView) {
    let [title, filters, body, detail, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .areas(area);

    let tab = |label: &str, on: bool| {
        if on {
            Span::styled(format!("[{label}]"), Style::new().bold().fg(Color::Cyan))
        } else {
            Span::raw(format!(" {label} "))
        }
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" WinPerf ", Style::new().bold().fg(Color::Cyan)),
            Span::raw("Software  "),
            tab("Seen running", view.mode == Mode::Executables),
            tab("Installed", view.mode == Mode::Installed),
            Span::styled(
                if view.hides_idle() {
                    "  running only"
                } else {
                    ""
                },
                Style::new().fg(Color::Green),
            ),
        ])),
        title,
    );

    // The class filter, with how many of each there are.
    let (total, by) = view.counts();
    let chip = |label: String, on: bool| {
        if on {
            Span::styled(
                format!(" {label} "),
                Style::new().add_modifier(Modifier::REVERSED),
            )
        } else {
            Span::raw(format!(" {label} "))
        }
    };
    let mut chips = vec![chip(format!("0 All {total}"), view.class.is_none())];
    for (n, c) in CLASSES.iter().enumerate() {
        chips.push(chip(
            format!("{} {} {}", n + 1, class_label(*c), by[n]),
            view.class == Some(*c),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(chips)), filters);

    if view.rows.is_empty() {
        let text = view.problem.clone().unwrap_or_else(|| match view.mode {
            Mode::Installed => {
                "No installed software stored yet. Run `winperf inventory scan --save`.".to_string()
            }
            Mode::Executables => "Nothing here yet. Executables appear once `winperf monitor run` \
                 has seen them (and the filters allow them)."
                .to_string(),
        });
        f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), body);
    } else {
        draw_table(f, body, view);
    }

    if let Some(i) = view.selected() {
        let who = |s: &'static str, v: &str| -> String {
            if v.is_empty() {
                s.to_string()
            } else {
                v.to_string()
            }
        };
        let text = match view.mode {
            Mode::Installed => format!(
                "{} {} | {} | installed {}",
                i.name,
                i.detail,
                who("unknown publisher", &i.publisher),
                who("date unknown", &i.extra)
            ),
            Mode::Executables => format!(
                "{}\n{} | {}",
                i.extra,
                who("no valid signature", &i.publisher),
                class_label(i.class)
            ),
        };
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .style(class_style(i.class)),
            detail,
        );
    }
    f.render_widget(
        Paragraph::new(" q quit  w back  ↑↓ move  Tab list  0-4/c class  r running only  l reload")
            .style(Style::new().fg(Color::DarkGray)),
        footer,
    );
}

fn draw_table(f: &mut Frame, area: Rect, view: &mut InventoryView) {
    let wide = area.width >= WIDE;
    let mode = view.mode;
    let (mut header, mut widths): (Vec<&str>, Vec<Constraint>) = match mode {
        Mode::Installed => (
            vec!["NAME", "VERSION", "PUBLISHER", "CLASS"],
            vec![
                Constraint::Min(20),
                Constraint::Length(14),
                Constraint::Length(24),
                Constraint::Length(12),
            ],
        ),
        Mode::Executables => (
            vec!["NAME", "PRODUCT", "SIGNER", "CLASS", "RUN"],
            vec![
                Constraint::Min(18),
                Constraint::Length(20),
                Constraint::Length(22),
                Constraint::Length(12),
                Constraint::Length(4),
            ],
        ),
    };
    if wide {
        header.push(match mode {
            Mode::Installed => "INSTALLED",
            Mode::Executables => "PATH",
        });
        widths.push(match mode {
            Mode::Installed => Constraint::Length(11),
            Mode::Executables => Constraint::Min(20),
        });
    }
    view.page_size = usize::from(area.height.saturating_sub(1)).max(1);
    let rows: Vec<Row> = view.rows.iter().map(|i| row(i, mode, wide)).collect();
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

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    fn exe(name: &str, class: Classification, running: u32) -> Item {
        Item {
            name: name.into(),
            detail: format!("{name} product"),
            publisher: if class == Classification::Unsigned {
                String::new()
            } else {
                format!("{name} Ltd")
            },
            class,
            running: Some(running),
            extra: format!(r"C:\apps\{name}"),
        }
    }

    fn app(name: &str, class: Classification) -> Item {
        Item {
            name: name.into(),
            detail: "1.2.3".into(),
            publisher: "Some Publisher".into(),
            class,
            running: None,
            extra: "2024-02-29".into(),
        }
    }

    fn view() -> InventoryView {
        use Classification::*;
        let mut v = InventoryView::new(Some(InventorySource {
            db_path: std::env::temp_dir().join("winperf-inventory-nonexistent.db"),
        }));
        v.set_items(
            vec![
                app("Office", MicrosoftOfficial),
                app("Chrome", ThirdPartyOfficial),
                app("Mystery", Unknown),
            ],
            vec![
                exe("explorer.exe", MicrosoftOfficial, 1),
                exe("chrome.exe", ThirdPartyOfficial, 12),
                exe("old-tool.exe", ThirdPartyOfficial, 0),
                exe("sketchy.exe", Unsigned, 1),
                exe("who.exe", Unknown, 0),
            ],
        );
        v
    }

    fn names(v: &InventoryView) -> Vec<String> {
        v.rows.iter().map(|r| r.name.clone()).collect()
    }

    fn screen(v: &mut InventoryView, w: u16, h: u16) -> String {
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

    #[test]
    fn it_opens_on_the_executables_the_monitor_has_seen() {
        let v = view();
        assert_eq!(v.mode, Mode::Executables);
        assert_eq!(v.rows.len(), 5);
        assert_eq!(v.class, None);
    }

    #[test]
    fn the_class_filter_narrows_the_list_and_number_keys_pick_a_class() {
        let mut v = view();
        v.on_key(ch('1'));
        assert_eq!(names(&v), vec!["explorer.exe"]);
        v.on_key(ch('2'));
        assert_eq!(names(&v), vec!["chrome.exe", "old-tool.exe"]);
        v.on_key(ch('3'));
        assert_eq!(names(&v), vec!["sketchy.exe"]);
        v.on_key(ch('4'));
        assert_eq!(names(&v), vec!["who.exe"]);
        v.on_key(ch('0'));
        assert_eq!(v.rows.len(), 5);
    }

    #[test]
    fn c_cycles_through_the_classes_and_back_to_all() {
        let mut v = view();
        let mut seen = Vec::new();
        for _ in 0..5 {
            v.on_key(ch('c'));
            seen.push(v.class);
        }
        assert_eq!(
            seen,
            vec![
                Some(Classification::MicrosoftOfficial),
                Some(Classification::ThirdPartyOfficial),
                Some(Classification::Unsigned),
                Some(Classification::Unknown),
                None
            ]
        );
    }

    #[test]
    fn running_only_hides_executables_with_no_process() {
        let mut v = view();
        v.on_key(ch('r'));
        assert_eq!(names(&v), vec!["explorer.exe", "chrome.exe", "sketchy.exe"]);
        v.on_key(ch('2'));
        assert_eq!(names(&v), vec!["chrome.exe"], "filters combine");
        v.on_key(ch('r'));
        assert_eq!(names(&v), vec!["chrome.exe", "old-tool.exe"]);
    }

    #[test]
    fn tab_switches_between_installed_software_and_executables() {
        let mut v = view();
        v.on_key(key(KeyCode::Tab));
        assert_eq!(v.mode, Mode::Installed);
        assert_eq!(names(&v), vec!["Office", "Chrome", "Mystery"]);
        v.on_key(ch('1'));
        assert_eq!(names(&v), vec!["Office"]);
        v.on_key(ch('r'));
        assert_eq!(
            names(&v),
            vec!["Office"],
            "running-only does not apply to installed software"
        );
        v.on_key(key(KeyCode::Left));
        assert_eq!(v.mode, Mode::Executables);
        assert_eq!(
            names(&v),
            vec!["explorer.exe"],
            "the class filter stays (and running-only applies again)"
        );
    }

    #[test]
    fn counts_ignore_the_class_filter_but_follow_running_only() {
        let mut v = view();
        v.on_key(ch('3'));
        assert_eq!(v.counts(), (5, [1, 2, 1, 1]));
        v.on_key(ch('r'));
        assert_eq!(v.counts(), (3, [1, 1, 1, 0]));
    }

    #[test]
    fn the_cursor_follows_the_entry_through_filter_changes() {
        let mut v = view();
        v.on_key(ch('j'));
        v.on_key(ch('j')); // old-tool.exe
        assert_eq!(v.selected().unwrap().name, "old-tool.exe");
        v.on_key(ch('2')); // third-party: chrome, old-tool
        assert_eq!(v.selected().unwrap().name, "old-tool.exe");
        v.on_key(ch('r')); // old-tool disappears: back to the first row
        assert_eq!(v.selected().unwrap().name, "chrome.exe");
    }

    #[test]
    fn navigation_and_exit_keys() {
        let mut v = view();
        for _ in 0..20 {
            v.on_key(ch('j'));
        }
        assert_eq!(v.table.selected(), Some(4));
        v.on_key(ch('g'));
        assert_eq!(v.table.selected(), Some(0));
        assert_eq!(v.on_key(key(KeyCode::Esc)), Nav::Back);
        assert_eq!(v.on_key(ch('w')), Nav::Back);
        assert_eq!(v.on_key(ch('q')), Nav::Quit);

        let mut empty = InventoryView::new(None);
        assert_eq!(empty.on_key(ch('j')), Nav::Stay);
        assert!(!empty.refresh_if_due());
    }

    #[test]
    fn the_screen_shows_columns_class_chips_counts_and_the_selected_path() {
        let mut v = view();
        let s = screen(&mut v, 120, 16);
        for expected in [
            "Software",
            "[Seen running]",
            "Installed",
            "0 All 5",
            "1 Microsoft 1",
            "2 Third-party 2",
            "3 Unsigned 1",
            "4 Unknown 1",
            "NAME",
            "SIGNER",
            "CLASS",
            "RUN",
            "PATH",
            "explorer.exe",
            "chrome.exe",
            "12",
            r"C:\apps\explorer.exe",
        ] {
            assert!(s.contains(expected), "missing {expected:?} in\n{s}");
        }
    }

    #[test]
    fn the_installed_list_shows_versions_publishers_and_dates() {
        let mut v = view();
        v.on_key(key(KeyCode::Tab));
        let s = screen(&mut v, 120, 16);
        for expected in [
            "[Installed]",
            "VERSION",
            "PUBLISHER",
            "INSTALLED",
            "Office",
            "1.2.3",
            "2024-02-29",
        ] {
            assert!(s.contains(expected), "missing {expected:?} in\n{s}");
        }
        assert!(!s.contains("PATH"), "{s}");
    }

    #[test]
    fn a_narrow_screen_drops_the_wide_column() {
        let mut v = view();
        let s = screen(&mut v, 80, 16);
        assert!(!s.contains("PATH") && s.contains("CLASS"), "{s}");
    }

    #[test]
    fn empty_states_explain_what_to_do() {
        let mut v = InventoryView::new(None);
        v.set_items(Vec::new(), Vec::new());
        let s = screen(&mut v, 100, 14);
        assert!(s.contains("monitor run"), "{s}");
        v.on_key(key(KeyCode::Tab));
        let s = screen(&mut v, 100, 14);
        assert!(s.contains("inventory scan --save"), "{s}");
    }

    #[test]
    fn a_missing_database_is_explained() {
        let mut v = InventoryView::new(Some(InventorySource {
            db_path: std::env::temp_dir().join("winperf-no-such-inventory.db"),
        }));
        assert!(v.refresh_if_due());
        assert!(screen(&mut v, 100, 14).contains("no database at"));
        assert!(!v.refresh_if_due());
        v.on_key(ch('l'));
        assert!(v.refresh_if_due());
    }
}
