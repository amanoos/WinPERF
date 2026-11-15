//! `winperf tui`: the interactive terminal dashboard (Ratatui).
//!
//! The sampling engine runs on its own thread and streams each tick to the UI thread over a
//! channel, so a slow tick never freezes the keyboard. The TUI is a *viewer*: it samples live but
//! does not write the database (the monitor or service is the single writer).

pub mod app;
pub mod baselines;
pub mod ui;

use app::App;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind,
};
use ratatui::crossterm::execute;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::Duration;
use winperf_core::engine::{Engine, MetricsSource, SampleSink, TickBatch, TickStats};
use winperf_core::network::NetworkStatus;

/// What the engine thread sends to the UI.
pub enum Msg {
    /// Whether per-process network attribution started (sent once, first).
    Network(NetworkStatus),
    Batch(Box<TickBatch>),
    Stats(TickStats),
}

/// The UI went away; the engine thread should stop.
#[derive(Debug)]
pub struct FeedClosed;

impl std::fmt::Display for FeedClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the dashboard closed")
    }
}
impl std::error::Error for FeedClosed {}

struct LiveSink(Sender<Msg>);

impl SampleSink for LiveSink {
    type Error = FeedClosed;
    fn record(&mut self, batch: &TickBatch) -> Result<(), FeedClosed> {
        self.0
            .send(Msg::Batch(Box::new(batch.clone())))
            .map_err(|_| FeedClosed)
    }
}

/// A running engine thread and the channel it feeds.
pub struct Feed {
    rx: Receiver<Msg>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Feed {
    /// Start sampling every `interval`. `make` runs *on the engine thread* (OS handles such as
    /// performance counters aren't `Send`) and returns the metrics source plus the network
    /// attribution status to show.
    pub fn spawn<M, F>(make: F, interval: Duration) -> Self
    where
        M: MetricsSource + 'static,
        F: FnOnce() -> (M, NetworkStatus) + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let worker = std::thread::Builder::new()
            .name("winperf-engine".into())
            .spawn(move || {
                let (metrics, network) = make();
                if tx.send(Msg::Network(network)).is_err() {
                    return;
                }
                let stats_tx = tx.clone();
                let mut engine = Engine::new(metrics, LiveSink(tx));
                let _ = engine.run(interval, None, &stop_flag, |_, stats| {
                    let _ = stats_tx.send(Msg::Stats(*stats));
                });
            })
            .expect("failed to spawn the engine thread");
        Self {
            rx,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Feed {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn apply(app: &mut App, msg: Msg) {
    match msg {
        Msg::Network(status) => app.network = status,
        Msg::Batch(batch) => app.apply_batch(&batch),
        Msg::Stats(stats) => app.apply_stats(&stats),
    }
}

/// The interactive dashboard. Restores the terminal on quit, on error and on panic.
///
/// With `mouse`, header clicks sort and the wheel scrolls. Mouse capture means the terminal's own
/// text selection needs Shift held; `--no-mouse` turns it off.
pub fn run_terminal(feed: &Feed, mut app: App, mouse: bool) -> io::Result<()> {
    let mut terminal = ratatui::init(); // raw mode + alternate screen + panic hook that restores
    if mouse {
        let _ = execute!(io::stdout(), EnableMouseCapture);
        // ratatui's panic hook restores the screen but knows nothing about mouse capture; chain
        // ahead of it so a crash can't leave the user's terminal reporting mouse movements.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = execute!(io::stdout(), DisableMouseCapture);
            previous(info);
        }));
    }
    let result = event_loop(&mut terminal, feed, &mut app);
    if mouse {
        let _ = execute!(io::stdout(), DisableMouseCapture);
    }
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    feed: &Feed,
    app: &mut App,
) -> io::Result<()> {
    let mut dirty = true;
    while !app.should_quit {
        if dirty {
            terminal.draw(|f| ui::draw(f, app))?;
            dirty = false;
        }
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    app.on_key(key);
                    dirty = true;
                }
                Event::Mouse(mouse) => {
                    app.on_mouse(mouse);
                    dirty = true;
                }
                Event::Resize(..) => dirty = true,
                _ => {}
            }
        }
        while let Ok(msg) = feed.rx.try_recv() {
            apply(app, msg);
            dirty = true;
        }
        if app.refresh_baselines_if_due() {
            dirty = true;
        }
    }
    Ok(())
}

/// Sample for `batches` ticks, then render one frame of the given size as plain text. Lets the
/// dashboard be checked (and shown in docs) without an interactive terminal.
pub fn snapshot(
    feed: &Feed,
    mut app: App,
    batches: usize,
    width: u16,
    height: u16,
) -> io::Result<String> {
    let mut seen = 0;
    while seen < batches {
        match feed.rx.recv_timeout(Duration::from_secs(60)) {
            Ok(msg) => {
                if matches!(msg, Msg::Batch(_)) {
                    seen += 1;
                }
                apply(&mut app, msg);
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err(io::Error::other("timed out waiting for samples"));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("the sampling thread stopped"));
            }
        }
    }
    // Drain stats that arrived right behind the last batch so the status line is complete.
    while let Ok(msg) = feed.rx.try_recv() {
        apply(&mut app, msg);
    }
    app.refresh_baselines_if_due();
    // The in-memory backend cannot fail (its error type is `Infallible`).
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("in-memory terminal");
    terminal
        .draw(|f| ui::draw(f, &mut app))
        .expect("in-memory draw");
    let buffer = terminal.backend().buffer();
    let lines: Vec<String> = (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect();
    Ok(lines.join("\n") + "\n")
}
