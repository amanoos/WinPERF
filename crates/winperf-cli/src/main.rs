//! `winperf` command-line entry point.

mod commands;
mod export;
mod tui;

use clap::{Parser, Subcommand};
use export::Format;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use winperf_core::anomaly::Sensitivities;
use winperf_core::config::Config;
use winperf_core::inventory::{
    BackgroundClassifier, CachedVerifier, ExecutableClassifier, SignatureVerifier, discover,
};
use winperf_core::network::NetworkStatus;
use winperf_core::time::unix_millis_now;
use winperf_storage::{
    ConfigLocation, Database, DetectSettings, resolve_config_location, resolve_db_path,
};
use winperf_windows::{
    EtwNetworkCollector, WinTrustVerifier, WindowsMetricsSource, WindowsProcessSource,
    WindowsRegistry, WindowsSystemSource, WindowsVersionReader,
};

#[derive(Parser)]
#[command(
    name = "winperf",
    version,
    about = "Windows performance profiler and anomaly monitor"
)]
struct Cli {
    /// Database file (default: storage.database from the config file, else
    /// %ProgramData%\WinPerf\winperf.db; the WINPERF_DB variable also overrides the config file)
    #[arg(long, global = true)]
    db: Option<PathBuf>,
    /// Configuration file (default: %ProgramData%\WinPerf\config.toml, or the WINPERF_CONFIG variable)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Installed software and processes
    Inventory {
        #[command(subcommand)]
        action: InventoryAction,
    },
    /// Running processes
    Process {
        #[command(subcommand)]
        action: ProcessAction,
    },
    /// Resource sampling
    Monitor {
        #[command(subcommand)]
        action: MonitorAction,
    },
    /// System-wide health (CPU, memory, disk, network)
    System {
        #[command(subcommand)]
        action: SystemAction,
    },
    /// Baseline profiles: what is normal for each executable and application
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Baseline collection mode: start or stop learning, and see how far it has got
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Anomalies the monitor has detected
    Anomalies {
        #[command(subcommand)]
        action: AnomaliesAction,
    },
    /// Show or create the configuration file
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Per-process network usage (needs administrator rights)
    Network {
        #[command(subcommand)]
        action: NetworkAction,
    },
    /// Interactive terminal dashboard: system health and a sortable process table
    Tui {
        /// Seconds between samples
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
        interval: u64,
        /// Don't try per-process network attribution (overrides monitor.network)
        #[arg(long)]
        no_network: bool,
        /// Don't capture the mouse (keeps the terminal's own text selection working)
        #[arg(long)]
        no_mouse: bool,
        /// Open on the Baseline Explorer instead of the process table (press b to switch)
        #[arg(long)]
        baselines: bool,
        /// Instead of the interactive screen, sample twice and print one frame as text
        #[arg(long)]
        snapshot: bool,
        /// Frame width for --snapshot
        #[arg(long, default_value_t = 80)]
        width: u16,
        /// Frame height for --snapshot
        #[arg(long, default_value_t = 24)]
        height: u16,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Recompute the baselines from the stored samples now (every configured window)
    Update,
    /// Show the stored baselines of one window
    List {
        /// Window length in hours (default: the shortest configured window)
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        window: Option<u32>,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Enter profiling mode (baselines are being learned; detection holds back)
    Start,
    /// Leave profiling mode
    Stop,
    /// Show the mode, whether a monitor is running, and baseline confidence so far
    Status,
}

#[derive(Subcommand)]
enum AnomaliesAction {
    /// List detected anomalies, newest first
    List {
        /// Only those that were active in the last this many hours
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        hours: Option<u32>,
        /// Only those still going on
        #[arg(long)]
        active: bool,
        /// Most events to show
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=10000))]
        limit: u32,
    },
    /// Show everything about one anomaly, including why it was raised
    Show {
        /// The event id from `anomalies list`
        id: i64,
    },
}

#[derive(Subcommand)]
enum NetworkAction {
    /// Measure for a few seconds and list the processes using the network
    Now {
        /// Measurement length in seconds
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=300))]
        seconds: u64,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the effective configuration (file values plus defaults)
    Show,
    /// Print where the configuration file is and whether it exists
    Path,
    /// Write a commented default configuration file
    Init {
        /// Overwrite an existing file
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum SystemAction {
    /// Take a one-second measurement and print it
    Now,
}

#[derive(Subcommand)]
enum MonitorAction {
    /// Sample all processes in the foreground and record to the database until Ctrl+C
    Run {
        /// Seconds between samples (default: monitor.interval_secs from the config file, else 5)
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
        interval: Option<u64>,
        /// Stop after this many samples (default: run until Ctrl+C)
        #[arg(long)]
        ticks: Option<u64>,
        /// Don't verify signatures of new executables (overrides monitor.signatures)
        #[arg(long)]
        no_signatures: bool,
        /// Don't attribute network traffic to processes (overrides monitor.network)
        #[arg(long)]
        no_network: bool,
    },
}

#[derive(Subcommand)]
enum ProcessAction {
    /// List running processes with publisher classification
    List {
        /// Also read and show each process's command line (may contain secrets)
        #[arg(long)]
        cmdline: bool,
        /// Skip signature verification (faster; classification stays "unknown")
        #[arg(long)]
        no_signatures: bool,
        /// Output format
        #[arg(long, value_enum, default_value = "table")]
        format: Format,
    },
}

#[derive(Subcommand)]
enum InventoryAction {
    /// List installed applications
    Scan {
        /// Output format
        #[arg(long, value_enum, default_value = "table")]
        format: Format,
        /// Also store the result in the database
        #[arg(long)]
        save: bool,
    },
    /// Show signature and version details for one executable
    Exe {
        /// Path to the executable or DLL
        path: PathBuf,
    },
}

fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("winperf: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `config` subcommands run before the configuration is loaded, so `path` and `init` still work
/// when the file is broken (that's exactly when you need them).
fn run_config(action: &ConfigAction, location: &ConfigLocation) -> Result<(), String> {
    let mut out = std::io::stdout().lock();
    match action {
        ConfigAction::Path => commands::config::path(location, &mut out).map_err(|e| e.to_string()),
        ConfigAction::Init { force } => commands::config::init(&location.path, *force, &mut out),
        ConfigAction::Show => {
            let config = commands::config::load(location)?;
            commands::config::show(&config, location, &mut out).map_err(|e| e.to_string())
        }
    }
}

fn run(cli: Cli, config: Config) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    match cli.command {
        Command::Inventory {
            action: InventoryAction::Scan { format, save },
        } => {
            let db_path =
                save.then(|| resolve_db_path(cli.db.clone(), config.storage.database.as_deref()));
            commands::inventory::scan(
                &WindowsRegistry,
                format,
                db_path.as_deref(),
                &mut std::io::stdout().lock(),
            )
            .map_err(io)
        }
        Command::Inventory {
            action: InventoryAction::Exe { path },
        } => commands::inventory::inspect_exe(
            &path,
            &WinTrustVerifier,
            &WindowsVersionReader,
            &mut std::io::stdout().lock(),
        )
        .map_err(io),
        Command::System {
            action: SystemAction::Now,
        } => {
            let mut source = WindowsSystemSource::new();
            commands::system::now(
                || source.observe(),
                Duration::from_secs(1),
                &mut std::io::stdout().lock(),
            )
            .map_err(io)
        }
        Command::Monitor {
            action:
                MonitorAction::Run {
                    interval,
                    ticks,
                    no_signatures,
                    no_network,
                },
        } => {
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))
                .map_err(|e| format!("could not install Ctrl+C handler: {e}"))?;
            let db_path = resolve_db_path(cli.db.clone(), config.storage.database.as_deref());
            // A flag given on the command line beats the config file.
            let interval = interval.unwrap_or(config.monitor.interval_secs);
            let verify_signatures = config.monitor.signatures && !no_signatures;
            // Signature verification runs on its own thread so it can never delay a sampling tick.
            let classifier: Option<Box<dyn ExecutableClassifier>> = verify_signatures.then(|| {
                Box::new(BackgroundClassifier::spawn(
                    WinTrustVerifier,
                    WindowsVersionReader,
                )) as Box<dyn ExecutableClassifier>
            });
            // Per-process network attribution needs administrator rights. Without them the monitor
            // carries on and records network as "unavailable"; it never fails because of this.
            let mut metrics = WindowsMetricsSource::new();
            if config.monitor.network && !no_network {
                match EtwNetworkCollector::start() {
                    Ok(collector) => {
                        metrics = metrics.with_network(collector);
                        eprintln!("winperf: per-process network attribution is active");
                    }
                    Err(status) => eprintln!("winperf: {}", status.describe()),
                }
            }
            // Baselines are recomputed in the background on their own connection.
            let schedule = commands::baseline::spawn_schedule(
                db_path.clone(),
                config.baseline.windows_hours.clone(),
                Duration::from_secs(u64::from(config.baseline.recompute_minutes) * 60),
                Arc::clone(&stop),
            );
            let detect = DetectSettings::new(
                Sensitivities::from_config(&config.detection),
                config.baseline.windows_hours.clone(),
                config.baseline.confidence.clone(),
            );
            let result = commands::monitor::run(
                metrics,
                &db_path,
                commands::monitor::Options {
                    classifier,
                    detect: Some(detect),
                },
                Duration::from_secs(interval),
                ticks,
                &stop,
                &mut std::io::stdout().lock(),
            );
            // A run that ended by itself (--ticks) never set the flag; stop the schedule too.
            stop.store(true, Ordering::Relaxed);
            let _ = schedule.join();
            result.map(|_| ()).map_err(|e| e.to_string())
        }
        Command::Baseline { action } => {
            let db_path = resolve_db_path(cli.db.clone(), config.storage.database.as_deref());
            let windows = &config.baseline.windows_hours;
            let mut out = std::io::stdout().lock();
            match action {
                BaselineAction::Update => {
                    let mut db = Database::open(&db_path).map_err(|e| e.to_string())?;
                    commands::baseline::update(&mut db, windows, unix_millis_now(), &mut out)
                        .map_err(|e| e.to_string())
                }
                BaselineAction::List { window } => {
                    let db = Database::open_read_only(&db_path).map_err(|e| e.to_string())?;
                    let window = window.unwrap_or_else(|| windows.first().copied().unwrap_or(1));
                    commands::baseline::list(&db, window, &config.baseline.confidence, &mut out)
                        .map_err(io)
                }
            }
        }
        Command::Anomalies { action } => {
            let db_path = resolve_db_path(cli.db.clone(), config.storage.database.as_deref());
            let db = Database::open_read_only(&db_path).map_err(|e| e.to_string())?;
            let mut out = std::io::stdout().lock();
            match action {
                AnomaliesAction::List {
                    hours,
                    active,
                    limit,
                } => commands::anomalies::list(
                    &db,
                    hours,
                    active,
                    limit,
                    unix_millis_now(),
                    &mut out,
                )
                .map_err(|e| e.to_string()),
                AnomaliesAction::Show { id } => {
                    commands::anomalies::show(&db, id, &mut out).map_err(|e| e.to_string())
                }
            }
        }
        Command::Profile { action } => {
            let db_path = resolve_db_path(cli.db.clone(), config.storage.database.as_deref());
            let now = unix_millis_now();
            let mut out = std::io::stdout().lock();
            let longest = config.baseline.windows_hours.last().copied().unwrap_or(24);
            match action {
                ProfileAction::Start => {
                    let db = Database::open(&db_path).map_err(|e| e.to_string())?;
                    commands::profile::start(&db, now, &mut out).map_err(|e| e.to_string())
                }
                ProfileAction::Stop => {
                    let db = Database::open(&db_path).map_err(|e| e.to_string())?;
                    commands::profile::stop(&db, now, &mut out).map_err(|e| e.to_string())
                }
                ProfileAction::Status => {
                    let db = Database::open(&db_path).map_err(|e| e.to_string())?;
                    commands::profile::status(
                        &db,
                        longest,
                        &config.baseline.confidence,
                        now,
                        &mut out,
                    )
                    .map_err(|e| e.to_string())
                }
            }
        }
        Command::Process {
            action:
                ProcessAction::List {
                    cmdline,
                    no_signatures,
                    format,
                },
        } => {
            let source = WindowsProcessSource {
                collect_command_line: cmdline,
            };
            let verifier = CachedVerifier::new(WinTrustVerifier);
            let apps = discover(&WindowsRegistry);
            commands::process::list(
                &source,
                &apps,
                (!no_signatures).then_some(&verifier as &dyn SignatureVerifier),
                cmdline,
                format,
                &mut std::io::stdout().lock(),
            )
            .map_err(io)
        }
        Command::Network {
            action: NetworkAction::Now { seconds },
        } => {
            let collector = EtwNetworkCollector::start().map_err(|status| status.describe())?;
            let mut source = WindowsMetricsSource::new().with_network(collector);
            commands::network::now(&mut source, seconds, &mut std::io::stdout().lock()).map_err(io)
        }
        Command::Tui {
            interval,
            no_network,
            no_mouse,
            baselines,
            snapshot,
            width,
            height,
        } => {
            let source = tui::baselines::BaselineSource {
                db_path: resolve_db_path(cli.db.clone(), config.storage.database.as_deref()),
                windows: config.baseline.windows_hours.clone(),
                confidence: config.baseline.confidence.clone(),
            };
            let want_network = config.monitor.network && !no_network;
            let interval = Duration::from_secs(interval);
            // Built on the engine thread (performance-counter handles aren't `Send`).
            let make = move || {
                let mut metrics = WindowsMetricsSource::new();
                let status = if !want_network {
                    NetworkStatus::Failed("turned off".into())
                } else {
                    match EtwNetworkCollector::start() {
                        Ok(collector) => {
                            metrics = metrics.with_network(collector);
                            NetworkStatus::Active
                        }
                        Err(status) => status,
                    }
                };
                (metrics, status)
            };
            let feed = tui::Feed::spawn(make, interval);
            let app = tui::app::App::new(interval, NetworkStatus::RequiresAdmin)
                .with_baselines(source, baselines);
            if snapshot {
                let text = tui::snapshot(&feed, app, 2, width, height).map_err(io)?;
                print!("{text}");
                Ok(())
            } else {
                tui::run_terminal(&feed, app, !no_mouse).map_err(io)
            }
        }
        Command::Config { .. } => unreachable!("handled before the configuration is loaded"),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let location = resolve_config_location(cli.config.clone());

    if let Command::Config { action } = &cli.command {
        return finish(run_config(action, &location));
    }
    match commands::config::load(&location) {
        Ok(config) => finish(run(cli, config)),
        Err(e) => finish(Err(e)),
    }
}
