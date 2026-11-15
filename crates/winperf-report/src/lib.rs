//! The browser report: a small web server that reads the shared database and never writes to it.
//!
//! It listens on the local machine only unless a token is configured (see [`bind_address`]), sends
//! no requests to anything else, and tells the browser not to load anything from elsewhere.

pub mod api;
pub mod guard;

use axum::Router;
use axum::routing::get;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use winperf_core::config::{MIN_TOKEN_LEN, ReportConfig};

/// What the server needs to answer requests.
#[derive(Debug, Clone)]
pub struct ReportSettings {
    /// The database to read (opened read-only for every request).
    pub db_path: PathBuf,
    /// The monitor's sampling interval, to judge whether recording is current.
    pub interval_secs: u64,
    /// When set, every request must carry it.
    pub token: Option<String>,
    /// The address the server listens on (a loopback bind also checks the `Host` header).
    pub bind: IpAddr,
}

pub type Shared = Arc<ReportSettings>;

/// The address to listen on, or why it is refused. Reaching the report from another machine needs
/// an explicit address and a token of a sensible length; the default is this machine only.
pub fn bind_address(config: &ReportConfig, port: Option<u16>) -> Result<SocketAddr, String> {
    let ip = config.bind_ip().ok_or_else(|| {
        format!(
            "report.bind must be an IP address such as 127.0.0.1 (got {:?})",
            config.bind
        )
    })?;
    if !ip.is_loopback() {
        match &config.token {
            None => {
                return Err(format!(
                    "report.bind {ip} is reachable from other machines: set report.token (at least {MIN_TOKEN_LEN} characters) or use 127.0.0.1"
                ));
            }
            Some(t) if t.chars().count() < MIN_TOKEN_LEN => {
                return Err(format!(
                    "report.token must be at least {MIN_TOKEN_LEN} characters"
                ));
            }
            Some(_) => {}
        }
    }
    Ok(SocketAddr::new(ip, port.unwrap_or(config.port)))
}

const HOME: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>WinPerf report</title></head>\
<body><h1>WinPerf report</h1><p>The report server is running. The dashboard arrives in the next task; the data is available now:</p>\
<ul><li><a href=\"/api/status\">/api/status</a></li><li><a href=\"/api/current\">/api/current</a></li>\
<li><a href=\"/api/system\">/api/system</a></li><li><a href=\"/api/anomalies\">/api/anomalies</a></li></ul></body></html>";

async fn home() -> axum::response::Html<&'static str> {
    axum::response::Html(HOME)
}

/// The full application: the API, the guards (host, token, security headers) around it.
pub fn app(settings: ReportSettings) -> Router {
    let shared: Shared = Arc::new(settings);
    Router::new()
        .route("/", get(home))
        .route("/api/status", get(api::status))
        .route("/api/current", get(api::current))
        .route("/api/system", get(api::system))
        .route("/api/anomalies", get(api::anomalies))
        .route("/api/anomalies/{id}", get(api::anomaly))
        .layer(axum::middleware::from_fn_with_state(
            shared.clone(),
            guard::guard,
        ))
        .with_state(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(bind: &str, token: Option<&str>) -> ReportConfig {
        ReportConfig {
            bind: bind.into(),
            port: 8099,
            token: token.map(String::from),
        }
    }

    #[test]
    fn the_default_listens_on_this_machine_only() {
        let addr = bind_address(&ReportConfig::default(), None).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:8099");
        assert_eq!(
            bind_address(&config("::1", None), Some(9000))
                .unwrap()
                .to_string(),
            "[::1]:9000"
        );
    }

    #[test]
    fn another_machine_needs_an_address_and_a_long_enough_token() {
        let refused = bind_address(&config("0.0.0.0", None), None).unwrap_err();
        assert!(refused.contains("report.token"), "{refused}");
        let short = bind_address(&config("192.168.1.5", Some("short")), None).unwrap_err();
        assert!(short.contains("at least 16"), "{short}");
        assert!(bind_address(&config("192.168.1.5", Some("a-long-enough-secret")), None).is_ok());
        assert!(bind_address(&config("not-an-ip", None), None).is_err());
    }
}
