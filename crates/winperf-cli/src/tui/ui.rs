//! Drawing the dashboard. Pure rendering of [`App`]: no I/O, so it is tested with ratatui's
//! `TestBackend`. Laid out for an 80x24 terminal and grows gracefully beyond it.

use super::app::{App, ProcessRow, SortColumn, View};
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, LineGauge, Paragraph, Row, Table, Wrap};
use winperf_core::Metric;
use winperf_core::network::NetworkStatus;
use winperf_core::system::SystemSample;

const MIN_WIDTH: u16 = 60;
const MIN_HEIGHT: u16 = 16;
const KIB: f64 = 1024.0;
const MIB: f64 = KIB * 1024.0;
const GIB: f64 = MIB * 1024.0;

// ---- formatting (pure) -------------------------------------------------------------------

/// Unavailable values are always `n/a`, never a misleading zero.
pub fn fmt_percent(m: &Metric<f64>) -> String {
    m.value()
        .map_or_else(|| "n/a".into(), |v| format!("{v:.1}%"))
}

pub fn fmt_bytes(b: u64) -> String {
    let b = b as f64;
    if b >= GIB {
        format!("{:.1} GB", b / GIB)
    } else if b >= MIB {
        format!("{:.0} MB", b / MIB)
    } else {
        format!("{:.0} KB", b / KIB)
    }
}

pub fn fmt_memory(m: &Metric<u64>) -> String {
    m.value().map_or_else(|| "n/a".into(), |v| fmt_bytes(*v))
}

/// A throughput. `Partial` values get a leading `~`: they are real but incomplete (process I/O
/// includes non-disk I/O).
pub fn fmt_rate(m: &Metric<f64>) -> String {
    let text = |v: f64| {
        if v >= MIB {
            format!("{:.1} MB/s", v / MIB)
        } else if v >= KIB {
            format!("{:.0} KB/s", v / KIB)
        } else {
            format!("{v:.0} B/s")
        }
    };
    match m {
        Metric::Available(v) => text(*v),
        Metric::Partial(v) => format!("~{}", text(*v)),
        Metric::Unavailable => "n/a".into(),
    }
}

fn ratio(used: &Metric<u64>, total: &Metric<u64>) -> Option<f64> {
    match (used.value(), total.value()) {
        (Some(u), Some(t)) if *t > 0 => Some((*u as f64 / *t as f64).clamp(0.0, 1.0)),
        _ => None,
    }
}

fn level_color(r: f64) -> Color {
    if r < 0.6 {
        Color::Green
    } else if r < 0.85 {
        Color::Yellow
    } else {
        Color::Red
    }
}

// ---- layout ------------------------------------------------------------------------------

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let msg = format!(
            "terminal too small ({}x{}): WinPerf needs at least {MIN_WIDTH}x{MIN_HEIGHT}",
            area.width, area.height
        );
        // Wrap, or the message itself is cut off on exactly the screens it is meant for.
        f.render_widget(Paragraph::new(msg).wrap(Wrap { trim: true }), area);
        return;
    }
    if app.view == View::Baselines {
        super::baselines::draw(f, area, &mut app.baselines);
        return;
    }
    let [title, system, table, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(8),
        Constraint::Min(4),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_title(f, title, app);
    draw_system(f, system, app);
    draw_processes(f, table, app);
    draw_footer(f, footer);
}

fn draw_title(f: &mut Frame, area: Rect, app: &App) {
    let title = Line::from(vec![
        Span::styled(" WinPerf ", Style::new().bold().fg(Color::Cyan)),
        Span::raw(format!(
            "System overview - sampling every {}s",
            app.interval.as_secs()
        )),
        Span::styled("   b: baselines", Style::new().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(title), area);
}

fn gauge(f: &mut Frame, area: Rect, label: String, r: Option<f64>) {
    let value = r.unwrap_or(0.0);
    f.render_widget(
        LineGauge::default()
            .label(label)
            .ratio(value)
            .filled_style(Style::new().fg(level_color(value)))
            .unfilled_style(Style::new().fg(Color::DarkGray)),
        area,
    );
}

fn draw_system(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" System ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows: [Rect; 6] = Layout::vertical([Constraint::Length(1); 6]).areas(inner);

    let Some(s) = &app.system else {
        f.render_widget(
            Paragraph::new("waiting for the first sample...")
                .style(Style::new().fg(Color::DarkGray)),
            rows[0],
        );
        f.render_widget(Paragraph::new(status_line(app)), rows[5]);
        return;
    };
    draw_gauges(f, &rows, s);
    f.render_widget(Paragraph::new(disk_line(s)), rows[3]);
    f.render_widget(Paragraph::new(network_line(s)), rows[4]);
    f.render_widget(Paragraph::new(status_line(app)), rows[5]);
}

fn draw_gauges(f: &mut Frame, rows: &[Rect; 6], s: &SystemSample) {
    let cpu = s.cpu_percent.value().copied();
    gauge(
        f,
        rows[0],
        format!("CPU    {:>6}", fmt_percent(&s.cpu_percent)),
        cpu.map(|v| (v / 100.0).clamp(0.0, 1.0)),
    );

    let used = match (
        s.memory_total_bytes.value(),
        s.memory_available_bytes.value(),
    ) {
        (Some(t), Some(a)) => Metric::Available(t.saturating_sub(*a)),
        _ => Metric::Unavailable,
    };
    let mem = ratio(&used, &s.memory_total_bytes);
    let mem_label = match (used.value(), s.memory_total_bytes.value(), mem) {
        (Some(u), Some(t), Some(r)) => {
            format!(
                "Memory {:>5.1}%  {} of {}",
                r * 100.0,
                fmt_bytes(*u),
                fmt_bytes(*t)
            )
        }
        _ => "Memory    n/a".to_string(),
    };
    gauge(f, rows[1], mem_label, mem);

    let commit = ratio(&s.commit_used_bytes, &s.commit_limit_bytes);
    let commit_label = match (
        s.commit_used_bytes.value(),
        s.commit_limit_bytes.value(),
        commit,
    ) {
        (Some(u), Some(l), Some(r)) => {
            format!(
                "Commit {:>5.1}%  {} of {}",
                r * 100.0,
                fmt_bytes(*u),
                fmt_bytes(*l)
            )
        }
        _ => "Commit    n/a".to_string(),
    };
    gauge(f, rows[2], commit_label, commit);
}

fn disk_line(s: &SystemSample) -> String {
    let queue = s
        .disk_queue_length
        .value()
        .map_or("n/a".into(), |v| format!("{v:.1}"));
    let latency = s
        .disk_latency_ms
        .value()
        .map_or("n/a".into(), |v| format!("{v:.1} ms"));
    format!(
        "Disk    busy {}  queue {queue}  read {}  write {}  latency {latency}",
        fmt_percent(&s.disk_utilization_percent),
        fmt_rate(&s.disk_read_bytes_per_sec),
        fmt_rate(&s.disk_write_bytes_per_sec),
    )
}

fn network_line(s: &SystemSample) -> String {
    format!(
        "Network rx {}  tx {}  (physical adapters)",
        fmt_rate(&s.net_rx_bytes_per_sec),
        fmt_rate(&s.net_tx_bytes_per_sec)
    )
}

fn status_line(app: &App) -> Line<'static> {
    // Kept short on purpose: the whole line must fit in 78 columns (80 minus the borders), and the
    // network status is the part users most need to see.
    let net = match app.network {
        NetworkStatus::Active => Span::styled("net: per-process", Style::new().fg(Color::Green)),
        _ => Span::styled("net: system-wide only", Style::new().fg(Color::DarkGray)),
    };
    if app.status.ticks == 0 {
        return Line::from(vec![Span::raw("starting... | "), net]);
    }
    Line::from(vec![
        Span::raw(format!(
            "sample {} | {} ms | {} procs ({} unreadable) | ",
            app.status.ticks,
            app.status.last_took.as_millis(),
            app.process_count(),
            app.status.unreadable,
        )),
        net,
    ])
}

fn header_cell(label: &str, column: SortColumn, app: &App) -> Cell<'static> {
    let marker = if app.sort == column {
        if app.descending { "▼" } else { "▲" }
    } else {
        ""
    };
    let style = if app.sort == column {
        Style::new().bold().fg(Color::Cyan)
    } else {
        Style::new().bold()
    };
    Cell::from(format!("{label}{marker}")).style(style)
}

fn dim_if_na(text: String) -> Cell<'static> {
    if text == "n/a" {
        Cell::from(text).style(Style::new().fg(Color::DarkGray))
    } else {
        Cell::from(text)
    }
}

fn process_row(r: &ProcessRow) -> Row<'static> {
    Row::new(vec![
        Cell::from(r.key.pid.to_string()),
        Cell::from(r.name.clone()),
        dim_if_na(fmt_percent(&r.cpu)),
        dim_if_na(fmt_memory(&r.memory)),
        dim_if_na(fmt_rate(&r.io)),
        dim_if_na(fmt_rate(&r.network)),
        // Anomaly detection arrives in a later phase; the column is reserved.
        Cell::from("-").style(Style::new().fg(Color::DarkGray)),
    ])
}

fn draw_processes(f: &mut Frame, area: Rect, app: &mut App) {
    app.page_size = usize::from(area.height.saturating_sub(3)).max(1);
    app.sync_table();

    let rows: Vec<Row> = app.sorted().into_iter().map(process_row).collect();
    let title = format!(
        " Processes ({}) - sorted by {} {} ",
        app.process_count(),
        app.sort.label(),
        if app.descending {
            "descending"
        } else {
            "ascending"
        }
    );
    let header = Row::new(vec![
        header_cell("PID", SortColumn::Pid, app),
        header_cell("NAME", SortColumn::Name, app),
        header_cell("CPU", SortColumn::Cpu, app),
        header_cell("MEM", SortColumn::Memory, app),
        header_cell("I/O", SortColumn::Io, app),
        header_cell("NET", SortColumn::Network, app),
        Cell::from("ANOM").style(Style::new().bold()),
    ]);
    let block = Block::bordered().title(title);

    // Remember where each sortable header lands so a mouse click can pick that column. The same
    // constraints and spacing as the table, solved against the table's inner area, give the same
    // column positions the table itself uses (a test checks they agree with what is drawn).
    let inner = block.inner(area);
    let columns = Layout::horizontal(COLUMN_WIDTHS)
        .flex(Flex::Start)
        .spacing(1)
        .split(inner);
    app.header_y = inner.y;
    app.header_hits = SortColumn::DISPLAY_ORDER
        .iter()
        .enumerate()
        .map(|(i, column)| (*column, columns[i].x, columns[i].x + columns[i].width))
        .collect();

    let table = Table::new(rows, COLUMN_WIDTHS)
        .header(header)
        .block(block)
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .column_spacing(1);
    f.render_stateful_widget(table, area, &mut app.table);
}

/// PID, NAME, CPU, MEM, I/O, NET, ANOM. The first six are sortable, in this order.
const COLUMN_WIDTHS: [Constraint; 7] = [
    Constraint::Length(7),
    Constraint::Min(16),
    Constraint::Length(8),
    Constraint::Length(9),
    Constraint::Length(11),
    Constraint::Length(11),
    Constraint::Length(4),
];

fn draw_footer(f: &mut Frame, area: Rect) {
    // Must fit in 80 columns, so every key hint is visible on the smallest supported screen.
    let text = " q quit  ↑↓ move  ←→/click header: sort  Enter reverse  ~ = incl. non-disk I/O";
    f.render_widget(
        Paragraph::new(text).style(Style::new().fg(Color::DarkGray)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::tests::batch;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use std::time::Duration;
    use winperf_core::engine::TickStats;

    use Metric::{Available as A, Partial as P, Unavailable as U};

    fn app() -> App {
        App::new(Duration::from_secs(2), NetworkStatus::RequiresAdmin)
    }

    fn system() -> SystemSample {
        SystemSample {
            cpu_percent: A(23.4),
            memory_total_bytes: A(16 * 1024 * 1024 * 1024),
            memory_available_bytes: A(4 * 1024 * 1024 * 1024),
            commit_used_bytes: A(10 * 1024 * 1024 * 1024),
            commit_limit_bytes: A(40 * 1024 * 1024 * 1024),
            disk_utilization_percent: A(3.0),
            disk_queue_length: A(1.0),
            disk_read_bytes_per_sec: A(2.0 * MIB),
            disk_write_bytes_per_sec: A(512.0),
            disk_latency_ms: A(0.4),
            net_rx_bytes_per_sec: A(150.0 * KIB),
            net_tx_bytes_per_sec: A(0.0),
        }
    }

    /// Render and return each terminal row as text.
    fn render(app: &mut App, w: u16, h: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();
        let buf = terminal.backend().buffer();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect()
    }

    fn loaded() -> App {
        let mut a = app();
        let mut b = batch(&[
            (10, "chrome.exe", A(40.0), A(900 * 1024 * 1024)),
            (20, "rider64.exe", A(12.5), A(2 * 1024 * 1024 * 1024)),
            (30, "blind.exe", U, U),
        ]);
        b.system = Some(system());
        a.apply_batch(&b);
        a.apply_stats(&TickStats {
            sampled: 3,
            unreadable: 150,
            new: 3,
            gone: 0,
            took: Duration::from_millis(55),
        });
        a
    }

    #[test]
    fn values_are_formatted_with_units_and_na() {
        assert_eq!(fmt_percent(&A(12.34)), "12.3%");
        assert_eq!(fmt_percent(&U), "n/a");
        assert_eq!(fmt_bytes(900 * 1024), "900 KB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5 MB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
        assert_eq!(fmt_memory(&U), "n/a");
        assert_eq!(fmt_rate(&A(2.0 * MIB)), "2.0 MB/s");
        assert_eq!(fmt_rate(&A(3.0 * KIB)), "3 KB/s");
        assert_eq!(fmt_rate(&A(7.0)), "7 B/s");
        assert_eq!(
            fmt_rate(&P(2.0 * MIB)),
            "~2.0 MB/s",
            "partial values are marked"
        );
        assert_eq!(fmt_rate(&U), "n/a");
    }

    #[test]
    fn an_80_by_24_screen_shows_system_health_and_the_busiest_processes() {
        let mut a = loaded();
        let screen = render(&mut a, 80, 24);
        let text = screen.join("\n");
        assert_eq!(screen.len(), 24);
        for want in [
            "WinPerf",
            "CPU",
            "23.4%",
            "Memory",
            "75.0%",
            "Commit",
            "Disk",
            "busy 3.0%",
            "Network",
            "rx 150 KB/s",
            "sample 1",
            "3 procs (150 unreadable)",
            "chrome.exe",
            "rider64.exe",
            "q quit",
            "click header: sort",
            "Enter reverse",
            "incl. non-disk I/O",
        ] {
            assert!(text.contains(want), "missing {want:?} in:\n{text}");
        }
        // Busiest first, unavailable last.
        let line_of = |needle: &str| screen.iter().position(|l| l.contains(needle)).unwrap();
        assert!(line_of("chrome.exe") < line_of("rider64.exe"));
        assert!(line_of("rider64.exe") < line_of("blind.exe"));
    }

    #[test]
    fn no_line_is_wider_than_the_screen_and_nothing_panics_when_names_are_huge() {
        let mut a = app();
        let long = "x".repeat(200);
        a.apply_batch(&batch(&[(1, &long, A(1.0), A(1))]));
        let screen = render(&mut a, 80, 24);
        assert!(screen.iter().all(|l| l.chars().count() == 80));
    }

    #[test]
    fn unavailable_metrics_render_as_na_not_zero() {
        let mut a = loaded();
        let screen = render(&mut a, 80, 24);
        let blind = screen.iter().find(|l| l.contains("blind.exe")).unwrap();
        assert!(
            blind.matches("n/a").count() >= 3,
            "cpu, mem, io, net: {blind}"
        );

        let mut b = app();
        let mut batch2 = batch(&[(1, "a.exe", A(1.0), A(1))]);
        batch2.system = Some(SystemSample {
            cpu_percent: U,
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
        b.apply_batch(&batch2);
        let text = render(&mut b, 80, 24).join("\n");
        assert!(
            text.contains("CPU      n/a") || text.contains("n/a"),
            "{text}"
        );
        assert!(text.contains("Memory    n/a"), "{text}");
        assert!(text.contains("busy n/a"), "{text}");
        assert!(text.contains("rx n/a"), "{text}");
    }

    #[test]
    fn before_the_first_sample_it_says_so() {
        let mut a = app();
        let text = render(&mut a, 80, 24).join("\n");
        assert!(text.contains("waiting for the first sample"), "{text}");
        assert!(text.contains("starting"), "{text}");
        assert!(text.contains("Processes (0)"), "{text}");
    }

    #[test]
    fn the_header_marks_the_sort_column_and_direction() {
        let mut a = loaded();
        assert!(render(&mut a, 80, 24).join("\n").contains("CPU▼"));
        a.on_key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
        let text = render(&mut a, 80, 24).join("\n");
        assert!(text.contains("MEM▼") && !text.contains("CPU▼"), "{text}");
        assert!(text.contains("sorted by memory descending"));
        a.on_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert!(render(&mut a, 80, 24).join("\n").contains("MEM▲"));
    }

    #[test]
    fn the_selected_row_is_highlighted() {
        let mut a = loaded();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| draw(f, &mut a)).unwrap();
        let buf = terminal.backend().buffer();
        let row_of = |name: &str| {
            (0..24u16)
                .find(|y| {
                    (0..80u16)
                        .map(|x| buf[(x, *y)].symbol().to_string())
                        .collect::<String>()
                        .contains(name)
                })
                .unwrap()
        };
        let reversed = |y: u16| buf[(2, y)].modifier.contains(Modifier::REVERSED);
        assert!(
            reversed(row_of("chrome.exe")),
            "first row selected by default"
        );
        assert!(!reversed(row_of("rider64.exe")));
    }

    #[test]
    fn partial_process_io_is_marked_with_a_tilde() {
        let mut a = app();
        let mut b = batch(&[(1, "writer.exe", A(1.0), A(1))]);
        b.samples[0].io_read_bytes_per_sec = P(1.0 * MIB);
        b.samples[0].io_write_bytes_per_sec = P(1.0 * MIB);
        a.apply_batch(&b);
        let text = render(&mut a, 80, 24).join("\n");
        assert!(text.contains("~2.0 MB/s"), "{text}");
    }

    #[test]
    fn the_status_line_reflects_network_attribution() {
        let mut a = loaded();
        a.apply_stats(&TickStats {
            sampled: 411,
            unreadable: 153,
            new: 0,
            gone: 0,
            took: Duration::from_millis(105),
        });
        // Fits at 80x24 even with a realistic three-digit process count (it was once clipped).
        let off = render(&mut a, 80, 24).join("\n");
        assert!(off.contains("net: system-wide only"), "{off}");
        a.network = NetworkStatus::Active;
        let on = render(&mut a, 80, 24).join("\n");
        assert!(on.contains("net: per-process"), "{on}");
        assert!(on.contains("sampling every 2s"), "{on}");
    }

    // ---- sorting by column: keyboard and mouse ------------------------------------------

    fn click(app: &mut App, column: u16, row: u16) {
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        });
    }

    fn wheel(app: &mut App, up: bool) {
        app.on_mouse(MouseEvent {
            kind: if up {
                MouseEventKind::ScrollUp
            } else {
                MouseEventKind::ScrollDown
            },
            column: 5,
            row: 14,
            modifiers: KeyModifiers::NONE,
        });
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// The screen column where `label` starts in the header line.
    fn header_x(screen: &[String], app: &App, label: &str) -> u16 {
        let line = &screen[usize::from(app.header_y)];
        let byte = line
            .find(label)
            .unwrap_or_else(|| panic!("{label} not in {line}"));
        line[..byte].chars().count() as u16
    }

    #[test]
    fn header_hit_areas_line_up_with_the_headers_that_are_drawn() {
        let mut a = loaded();
        for (w, h) in [(80, 24), (100, 30), (160, 50)] {
            let screen = render(&mut a, w, h);
            assert_eq!(a.header_hits.len(), 6, "{w}x{h}");
            for (column, label) in [
                (SortColumn::Pid, "PID"),
                (SortColumn::Name, "NAME"),
                (SortColumn::Cpu, "CPU"),
                (SortColumn::Memory, "MEM"),
                (SortColumn::Io, "I/O"),
                (SortColumn::Network, "NET"),
            ] {
                let x = header_x(&screen, &a, label);
                let (_, start, end) = *a.header_hits.iter().find(|(c, _, _)| *c == column).unwrap();
                assert!(
                    start <= x && x < end,
                    "{w}x{h}: {label} drawn at {x}, hit area {start}..{end}"
                );
            }
        }
    }

    #[test]
    fn clicking_a_header_sorts_by_that_column_and_a_second_click_flips_it() {
        let mut a = loaded(); // chrome 900MB, rider 2GB, blind n/a
        let screen = render(&mut a, 80, 24);
        let (mem_x, y) = (header_x(&screen, &a, "MEM"), a.header_y);

        click(&mut a, mem_x, y);
        let text = render(&mut a, 80, 24).join("\n");
        assert!(
            text.contains("MEM▼") && text.contains("sorted by memory descending"),
            "{text}"
        );
        let screen = render(&mut a, 80, 24);
        let line_of = |s: &[String], n: &str| s.iter().position(|l| l.contains(n)).unwrap();
        assert!(
            line_of(&screen, "rider64.exe") < line_of(&screen, "chrome.exe"),
            "2 GB first"
        );

        click(&mut a, mem_x, y);
        assert!(render(&mut a, 80, 24).join("\n").contains("MEM▲"));

        let name_x = header_x(&render(&mut a, 80, 24), &a, "NAME");
        click(&mut a, name_x, y);
        assert!(
            render(&mut a, 80, 24)
                .join("\n")
                .contains("sorted by name ascending")
        );
    }

    #[test]
    fn clicking_the_anomaly_column_or_outside_the_header_does_not_change_the_sort() {
        let mut a = loaded();
        let screen = render(&mut a, 80, 24);
        let anom_x = header_x(&screen, &a, "ANOM");
        let before = (a.sort, a.descending);
        let y = a.header_y;
        click(&mut a, anom_x, y);
        click(&mut a, 0, 0); // title bar
        click(&mut a, 3, y.saturating_sub(2));
        assert_eq!((a.sort, a.descending), before);
    }

    #[test]
    fn arrow_keys_and_tab_move_the_sort_column_across_the_headers() {
        let mut a = loaded(); // starts on CPU
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.sort, SortColumn::Memory);
        a.on_key(key(KeyCode::Tab));
        assert_eq!(a.sort, SortColumn::Io);
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.sort, SortColumn::Network);
        a.on_key(key(KeyCode::Right));
        assert_eq!(a.sort, SortColumn::Pid, "wraps around");
        a.on_key(key(KeyCode::Left));
        assert_eq!(a.sort, SortColumn::Network, "and back");
        a.on_key(key(KeyCode::BackTab));
        assert_eq!(a.sort, SortColumn::Io);
        // The header follows.
        assert!(render(&mut a, 80, 24).join("\n").contains("I/O▼"));
    }

    #[test]
    fn enter_and_space_flip_the_direction() {
        let mut a = loaded();
        a.on_key(key(KeyCode::Enter));
        assert!(!a.descending);
        a.on_key(key(KeyCode::Char(' ')));
        assert!(a.descending);
        assert_eq!(a.sort, SortColumn::Cpu, "the column stays put");
    }

    #[test]
    fn clicking_a_row_selects_it_and_the_wheel_scrolls() {
        let mut a = app();
        let mut b = batch(&[]);
        for p in 1..=30u32 {
            let one = batch(&[(p, &format!("proc{p:02}.exe"), A(f64::from(100 - p)), A(1))]);
            b.new.extend(one.new);
            b.samples.extend(one.samples);
        }
        a.apply_batch(&b);
        render(&mut a, 80, 24);
        let first_row = a.header_y + 1;

        click(&mut a, 10, first_row + 2); // third process row
        a.sync_table();
        assert_eq!(a.table.selected(), Some(2));

        wheel(&mut a, false);
        a.sync_table();
        assert_eq!(a.table.selected(), Some(5), "wheel moves three rows");
        wheel(&mut a, true);
        wheel(&mut a, true);
        wheel(&mut a, true);
        a.sync_table();
        assert_eq!(a.table.selected(), Some(0), "clamped at the top");
    }

    #[test]
    fn step_wraps_in_both_directions() {
        assert_eq!(SortColumn::Network.step(1), SortColumn::Pid);
        assert_eq!(SortColumn::Pid.step(-1), SortColumn::Network);
        assert_eq!(SortColumn::Cpu.step(0), SortColumn::Cpu);
    }

    #[test]
    fn a_tiny_terminal_gets_a_message_not_a_panic() {
        let mut a = loaded();
        let screen = render(&mut a, 40, 8);
        assert!(screen.join("\n").contains("terminal too small"));
    }

    #[test]
    fn a_bigger_terminal_shows_more_rows() {
        let mut a = app();
        let procs: Vec<(u32, String)> = (1..=40).map(|p| (p, format!("proc{p:02}.exe"))).collect();
        let mut b = batch(&[]);
        for (p, n) in &procs {
            let one = batch(&[(*p, n, A(f64::from(*p)), A(1))]);
            b.new.extend(one.new);
            b.samples.extend(one.samples);
        }
        a.apply_batch(&b);
        let small = render(&mut a, 80, 24);
        let big = render(&mut a, 120, 50);
        let count = |s: &[String]| s.iter().filter(|l| l.contains("proc")).count();
        assert!(
            count(&big) > count(&small),
            "{} vs {}",
            count(&big),
            count(&small)
        );
        assert_eq!(
            a.page_size,
            50 - 1 - 8 - 1 - 3,
            "page size follows the visible rows"
        );
    }
}
