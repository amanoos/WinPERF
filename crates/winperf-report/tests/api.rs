//! The report API against a seeded temporary database, driven in-process (no network).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt;
use winperf_core::anomaly::{AnomalyEvent, AnomalyKind, Impact, Severity, SystemHealth};
use winperf_core::config::Resource;
use winperf_core::profiler::confidence::Confidence;
use winperf_core::time::unix_millis_now;
use winperf_report::{ReportSettings, app};
use winperf_storage::Database;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A scratch folder that disappears with the test.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("winperf-report-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn db(&self) -> PathBuf {
        self.dir.join("report.db")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn event(ts: i64, pid: u32, severity: Severity) -> AnomalyEvent {
    AnomalyEvent {
        detected_ts_ms: ts,
        pid,
        start_time: 100,
        process_name: "busy.exe".into(),
        exe_path: r"C:\apps\busy.exe".into(),
        resource: Resource::Cpu,
        kind: AnomalyKind::Deviation,
        current: 72.0,
        baseline: 8.0,
        deviation_pct: 800.0,
        duration_ms: 120_000,
        severity,
        system: SystemHealth {
            cpu_percent: Some(91.0),
            memory_percent: None,
            disk_percent: Some(40.0),
        },
        impact: Impact {
            pressure_percent: Some(91.0),
            share_percent: Some(72.0),
            score: Some(65.5),
        },
        baseline_window_hours: 24,
        baseline_confidence: Confidence::Established,
        explanation: "busy.exe used 72% CPU for 2 minutes against a normal 8%.".into(),
    }
}

/// 10 minutes of system samples ending now (5 s apart, memory 50% used), two processes in the
/// newest tick, one active and one resolved anomaly.
fn seed(path: &Path) -> (i64, i64) {
    let db = Database::open(path).unwrap();
    let now = unix_millis_now();
    for i in 0..120 {
        let ts = now - i * 5_000;
        db.conn()
            .execute(
                &format!(
                    "INSERT INTO system_samples (ts_ms, cpu_percent, memory_total_bytes, \
                     memory_available_bytes) VALUES ({ts}, 20.0, 1000, 500)"
                ),
                [],
            )
            .unwrap();
    }
    for (id, pid, name, cpu) in [(1, 10, "idle.exe", 1.0), (2, 11, "busy.exe", 60.0)] {
        db.conn()
            .execute(
                &format!(
                    "INSERT INTO process_instances (id, pid, start_time, parent_pid, name, \
                     first_seen, last_seen) VALUES ({id}, {pid}, 100, 0, '{name}', 't', 't')"
                ),
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                &format!(
                    "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, \
                     working_set_bytes) VALUES ({id}, {now}, {cpu}, 1048576)"
                ),
                [],
            )
            .unwrap();
    }
    let active = db
        .insert_anomaly(&event(now - 60_000, 11, Severity::High))
        .unwrap();
    let resolved = db
        .insert_anomaly(&event(now - 3_600_000, 10, Severity::Warning))
        .unwrap();
    db.resolve_anomaly(resolved, now - 3_000_000).unwrap();
    (active, resolved)
}

fn settings(path: PathBuf, token: Option<&str>) -> ReportSettings {
    ReportSettings {
        db_path: path,
        interval_secs: 5,
        token: token.map(String::from),
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

async fn get(
    app: axum::Router,
    uri: &str,
    host: Option<&str>,
    bearer: Option<&str>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut req = Request::builder().uri(uri);
    if let Some(h) = host {
        req = req.header("host", h);
    }
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let response = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, headers)
}

async fn local(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
    let (s, j, _) = get(app.clone(), uri, Some("localhost:8099"), None).await;
    (s, j)
}

#[tokio::test]
async fn status_says_whether_recording_is_current() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    let (code, body) = local(&app, "/api/status").await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["recording"], true);
    assert_eq!(body["active_anomalies"], 1);
    assert_eq!(body["last_24h"]["samples"], 120);
    assert_eq!(body["last_24h"]["gaps"], 0);
    assert_eq!(body["profile"]["active"], false);
    assert!(body["version"].is_string());
}

#[tokio::test]
async fn system_samples_are_reduced_to_the_requested_number_of_points() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    let now = unix_millis_now();
    let uri = format!(
        "/api/system?from_ms={}&to_ms={}&points=10",
        now - 700_000,
        now
    );
    let (code, body) = local(&app, &uri).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["samples"], 120);
    let points = body["points"].as_array().unwrap();
    assert!(
        (8..=12).contains(&points.len()),
        "about 10 points, got {}",
        points.len()
    );
    assert_eq!(points[0]["cpu_percent"], 20.0);
    assert_eq!(points[0]["memory_used_percent"], 50.0);
    assert!(
        points[0]["net_rx_bytes_per_sec"].is_null(),
        "unavailable stays null"
    );

    let (code, body) = local(&app, "/api/system?from_ms=5&to_ms=5").await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("before"));
    let (code, _) = local(&app, "/api/system?from_ms=0&to_ms=99999999999999").await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn current_lists_the_busiest_processes_first() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    let (code, body) = local(&app, "/api/current?limit=5").await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["system"]["cpu_percent"], 20.0);
    let names: Vec<&str> = body["processes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["busy.exe", "idle.exe"]);
    let (_, one) = local(&app, "/api/current?limit=1").await;
    assert_eq!(one["processes"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn anomalies_can_be_filtered_and_fetched_one_by_one() {
    let s = Scratch::new();
    let (active, resolved) = seed(&s.db());
    let app = app(settings(s.db(), None));

    let (_, all) = local(&app, "/api/anomalies?hours=24").await;
    assert_eq!(all["count"], 2);
    assert_eq!(
        all["anomalies"][0]["id"], active,
        "active events come first"
    );
    let (_, only_active) = local(&app, "/api/anomalies?active=true").await;
    assert_eq!(only_active["count"], 1);
    assert_eq!(only_active["anomalies"][0]["state"], "active");
    let (_, recent) = local(&app, "/api/anomalies?hours=1").await;
    assert_eq!(recent["count"], 2, "the resolved one ended within the hour");

    let (code, one) = local(&app, &format!("/api/anomalies/{resolved}")).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(one["state"], "resolved");
    assert_eq!(one["severity"], "warning");
    assert_eq!(one["resource"], "cpu");
    assert_eq!(one["kind"], "deviation");
    assert_eq!(
        one["explanation"],
        "busy.exe used 72% CPU for 2 minutes against a normal 8%."
    );
    assert_eq!(one["impact"]["score"], 65.5);

    let (code, body) = local(&app, "/api/anomalies/9999").await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("9999"));
}

#[tokio::test]
async fn a_missing_database_is_explained_not_a_crash() {
    let s = Scratch::new();
    let app = app(settings(s.dir.join("never-created.db"), None));
    let (code, body) = local(&app, "/api/status").await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body["error"].as_str().unwrap().contains("no database yet"));
}

#[tokio::test]
async fn only_requests_addressed_to_localhost_are_answered() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    for host in [
        Some("evil.example"),
        Some("localhost.evil.example:8099"),
        None,
    ] {
        let (code, _, _) = get(app.clone(), "/api/status", host, None).await;
        assert_eq!(code, StatusCode::FORBIDDEN, "{host:?}");
    }
    for host in ["localhost:8099", "127.0.0.1:8099", "[::1]:8099"] {
        let (code, _, _) = get(app.clone(), "/api/status", Some(host), None).await;
        assert_eq!(code, StatusCode::OK, "{host}");
    }
}

#[tokio::test]
async fn a_configured_token_is_required_for_the_data() {
    let s = Scratch::new();
    seed(&s.db());
    let secret = "a-long-enough-secret";
    let app = app(settings(s.db(), Some(secret)));
    let host = Some("localhost:8099");
    let (code, _, _) = get(app.clone(), "/api/status", host, None).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    let (code, _, _) = get(app.clone(), "/api/status", host, Some("wrong")).await;
    assert_eq!(code, StatusCode::UNAUTHORIZED);
    // The page and its scripts hold no data, so they load without it; the data does not.
    for path in ["/", "/app.js", "/app.css", "/echarts.min.js"] {
        let (code, _, _) = get(app.clone(), path, host, None).await;
        assert_eq!(code, StatusCode::OK, "{path}");
    }
    let (code, _, _) = get(app.clone(), "/api/status", host, Some(secret)).await;
    assert_eq!(code, StatusCode::OK);
    let (code, _, _) = get(
        app.clone(),
        &format!("/api/status?token={secret}"),
        host,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK);
}

#[tokio::test]
async fn every_response_forbids_loading_anything_from_elsewhere() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    let (_, _, headers) = get(app, "/api/status", Some("localhost"), None).await;
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("default-src 'self'"), "{csp}");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["x-content-type-options"], "nosniff");
}
