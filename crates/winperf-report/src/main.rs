//! `winperf-report`: the browser report server.
//!
//! ```text
//! winperf-report [--db FILE] [--config FILE] [--port N]
//! ```
//!
//! Listens on `report.bind`:`report.port` from the configuration file (127.0.0.1:8099 by default),
//! reads the same database the monitor writes, and stops on Ctrl+C.

use std::path::PathBuf;
use std::process::ExitCode;
use winperf_core::config::Config;
use winperf_report::{ReportSettings, app, bind_address};
use winperf_storage::{ConfigLocation, resolve_config_location, resolve_db_path};

struct Args {
    db: Option<PathBuf>,
    config: Option<PathBuf>,
    port: Option<u16>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        db: None,
        config: None,
        port: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--db" => args.db = Some(PathBuf::from(value("--db")?)),
            "--config" => args.config = Some(PathBuf::from(value("--config")?)),
            "--port" => {
                args.port = Some(
                    value("--port")?
                        .parse()
                        .map_err(|_| "--port must be a number from 1 to 65535".to_string())?,
                );
            }
            "--version" => {
                println!("winperf-report {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!(
                    "winperf-report [--db FILE] [--config FILE] [--port N]\n\n\
                     Serves the WinPerf browser report on this machine (default http://127.0.0.1:8099/)."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?} (try --help)")),
        }
    }
    Ok(args)
}

fn load_config(location: &ConfigLocation) -> Result<Config, String> {
    match std::fs::read_to_string(&location.path) {
        Ok(text) => {
            Config::from_toml_str(&text).map_err(|e| format!("{}: {e}", location.path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !location.explicit => {
            Ok(Config::default())
        }
        Err(e) => Err(format!(
            "cannot read configuration file {}: {e}",
            location.path.display()
        )),
    }
}

async fn serve(args: Args) -> Result<(), String> {
    let location = resolve_config_location(args.config);
    let config = load_config(&location)?;
    let addr = bind_address(&config.report, args.port)?;
    let db_path = resolve_db_path(args.db, config.storage.database.as_deref());
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        format!(
            "cannot listen on {addr}: {e}. If the port is taken, choose another with --port or report.port"
        )
    })?;
    let router = app(ReportSettings {
        db_path: db_path.clone(),
        interval_secs: config.monitor.interval_secs,
        token: config.report.token.clone(),
        bind: addr.ip(),
    });
    println!(
        "WinPerf report on http://{addr}/ (reading {})",
        db_path.display()
    );
    if config.report.token.is_some() {
        println!(
            "a token is required: add ?token=... to the address, or send Authorization: Bearer"
        );
    }
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() -> ExitCode {
    match parse_args() {
        Ok(args) => match serve(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("winperf-report: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("winperf-report: {e}");
            ExitCode::from(2)
        }
    }
}
