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

#[tokio::test]
async fn rankings_average_over_the_period_and_flag_what_was_not_measured() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    let now = unix_millis_now();
    let range = format!("from_ms={}&to_ms={}", now - 700_000, now + 1);

    let (code, cpu) = local(&app, &format!("/api/rankings?metric=cpu&{range}")).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(cpu["unit"], "percent");
    assert_eq!(cpu["group"], "process");
    assert_eq!(cpu["available"], true);
    assert_eq!(cpu["ticks"], 120);
    let rows = cpu["rows"].as_array().unwrap();
    assert_eq!(rows[0]["name"], "busy.exe");
    assert_eq!(rows[0]["current"], 60.0);
    assert_eq!(rows[0]["peak"], 60.0);
    assert_eq!(rows[0]["average"], 60.0 / 120.0, "one tick of 120 counts");
    assert_eq!(rows[1]["name"], "idle.exe");

    let (_, mem) = local(
        &app,
        &format!("/api/rankings?metric=memory&group=application&{range}"),
    )
    .await;
    assert_eq!(mem["unit"], "bytes");
    assert_eq!(mem["group"], "application");
    assert_eq!(mem["rows"][0]["peak"], 1_048_576.0);

    let (code, net) = local(&app, &format!("/api/rankings?metric=net_rx&{range}")).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(net["available"], false, "never measured is not zero");
    assert!(net["rows"].as_array().unwrap().is_empty());
    assert!(net["note"].as_str().unwrap().contains("administrator"));

    let (_, one) = local(&app, &format!("/api/rankings?metric=cpu&limit=1&{range}")).await;
    assert_eq!(one["rows"].as_array().unwrap().len(), 1);

    for bad in ["metric=gpu", "group=team", "from_ms=9&to_ms=9"] {
        let (code, _) = local(&app, &format!("/api/rankings?{bad}")).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{bad}");
    }
}

/// Application 1 ("Suite", by Acme) owns suite.exe (executable 5, instance 11, signed) and has
/// run for 10 minutes with a stored 1 h baseline; one anomaly belongs to it, one to someone else.
fn seed_subject(path: &Path) -> i64 {
    use winperf_core::profiler::baseline::Scope;
    let mut db = Database::open(path).unwrap();
    let now = unix_millis_now();
    db.conn()
        .execute_batch(
            "INSERT INTO installed_applications (id, app_key, name, publisher, version, \
               install_location, registry_sources, classification, first_seen, last_seen, scan_seq) \
             VALUES (1, 'suite|2|acme', 'Suite', 'Acme', '2.0', 'C:/Suite', 'x', 'third_party', 'a', 'b', 1); \
             INSERT INTO executables (id, path_key, file_path, file_name, signature_status, signer, \
               classification, file_size, file_mtime_ns, verified_at) \
             VALUES (5, 'c:/apps/busy.exe', 'C:/apps/busy.exe', 'busy.exe', 'valid', 'Acme', \
               'third_party', 1, 1, 't'); \
             INSERT INTO process_instances (id, pid, start_time, parent_pid, name, executable_id, \
               application_id, first_seen, last_seen) VALUES (11, 11, 100, 0, 'busy.exe', 5, 1, 'f', 'l'); \
             INSERT INTO process_instances (id, pid, start_time, parent_pid, name, first_seen, last_seen) \
               VALUES (12, 12, 100, 0, 'stranger.exe', 'f', 'l');",
        )
        .unwrap();
    for i in 0..120 {
        let ts = now - i * 5_000;
        let cpu = 10.0 + (i % 7) as f64;
        db.conn()
            .execute(
                &format!("INSERT INTO system_samples (ts_ms) VALUES ({ts})"),
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                &format!(
                    "INSERT INTO resource_samples (process_instance_id, ts_ms, cpu_percent, \
                     working_set_bytes) VALUES (11, {ts}, {cpu}, 2097152)"
                ),
                [],
            )
            .unwrap();
    }
    db.recompute_baselines(now, 1).unwrap();
    assert!(
        !db.baselines_for(Scope::Application, 1).unwrap().is_empty(),
        "the seed must give the application a baseline"
    );
    db.insert_anomaly(&event(now - 60_000, 11, Severity::High))
        .unwrap();
    let mut stranger = event(now - 30_000, 12, Severity::Warning);
    stranger.process_name = "stranger.exe".into();
    stranger.exe_path = r"C:\elsewhere\stranger.exe".into();
    db.insert_anomaly(&stranger).unwrap();
    now
}

#[tokio::test]
async fn a_subject_page_carries_its_metadata_history_stored_baselines_and_events() {
    use winperf_core::profiler::baseline::Scope;
    let s = Scratch::new();
    let now = seed_subject(&s.db());
    let app = app(settings(s.db(), None));
    let range = format!("from_ms={}&to_ms={}&points=20", now - 700_000, now + 1);

    let (code, page) = local(&app, &format!("/api/subjects/application/1?{range}")).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(page["name"], "Suite");
    assert_eq!(page["publisher"], "Acme");
    assert_eq!(page["version"], "2.0");
    assert_eq!(page["location"], "C:/Suite");
    let exes = page["executables"].as_array().unwrap();
    assert_eq!(exes.len(), 1);
    assert_eq!(exes[0]["file_name"], "busy.exe");
    assert_eq!(exes[0]["signature_status"], "valid");
    assert_eq!(exes[0]["running"], 1);

    // History: bucketed, newest included, values are the summed instance (one here).
    let series = page["series"].as_array().unwrap();
    assert!(!series.is_empty() && series.len() <= 21, "{}", series.len());
    assert_eq!(page["ticks"], 120);
    assert_eq!(
        page["sampled_every_ticks"], 1,
        "a short range reads every tick"
    );
    assert_eq!(series[0]["working_set_bytes"], 2_097_152.0);
    assert!(series[0]["net_rx_bytes_per_sec"].is_null());

    // The baseline rows are exactly what the database holds, nothing recomputed.
    let stored = Database::open_read_only(&s.db())
        .unwrap()
        .baselines_for(Scope::Application, 1)
        .unwrap();
    let shown = page["baselines"].as_array().unwrap();
    assert_eq!(shown.len(), stored.len());
    for (row, db_row) in shown.iter().zip(&stored) {
        assert_eq!(row["metric"], db_row.metric.as_str());
        assert_eq!(row["window_hours"], db_row.window_hours);
        assert_eq!(row["median"], db_row.median);
        assert_eq!(row["mean"], db_row.mean);
        assert_eq!(row["p95"], db_row.p95);
        assert_eq!(row["peak"], db_row.peak);
        assert_eq!(row["mad"], db_row.mad);
        assert_eq!(row["observations"], db_row.observations);
    }

    // Only this application's event; the stranger's is left out.
    let events = page["anomalies"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["process"]["name"], "busy.exe");
    assert_eq!(page["runs"].as_array().unwrap().len(), 1);

    // The executable has its own page, and knows its application.
    let (_, exe) = local(&app, &format!("/api/subjects/executable/5?{range}")).await;
    assert_eq!(exe["name"], "busy.exe");
    assert_eq!(exe["signature"]["signer"], "Acme");
    assert_eq!(exe["application"]["name"], "Suite");
}

#[tokio::test]
async fn an_unknown_subject_or_scope_is_refused_clearly() {
    let s = Scratch::new();
    seed_subject(&s.db());
    let app = app(settings(s.db(), None));
    let (code, body) = local(&app, "/api/subjects/application/99").await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("99"));
    for bad in [
        "/api/subjects/team/1",
        "/api/subjects/application/1?from_ms=9&to_ms=9",
    ] {
        let (code, _) = local(&app, bad).await;
        assert_eq!(code, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn ranking_rows_say_which_detail_page_they_open() {
    let s = Scratch::new();
    let now = seed_subject(&s.db());
    let app = app(settings(s.db(), None));
    let range = format!("from_ms={}&to_ms={}", now - 700_000, now + 1);
    let (_, by_process) = local(&app, &format!("/api/rankings?metric=memory&{range}")).await;
    assert_eq!(by_process["rows"][0]["subject"]["scope"], "executable");
    assert_eq!(by_process["rows"][0]["subject"]["id"], 5);
    let (_, by_app) = local(
        &app,
        &format!("/api/rankings?metric=memory&group=application&{range}"),
    )
    .await;
    assert_eq!(by_app["rows"][0]["subject"]["scope"], "application");
    assert_eq!(by_app["rows"][0]["subject"]["id"], 1);
}

#[tokio::test]
async fn one_event_comes_with_the_process_and_system_around_it() {
    let s = Scratch::new();
    let (active, _) = seed(&s.db());
    let app = app(settings(s.db(), None));

    let (_, one) = local(&app, &format!("/api/anomalies/{active}")).await;
    let ctx = &one["context"];
    let from = ctx["from_ms"].as_i64().unwrap();
    let to = ctx["to_ms"].as_i64().unwrap();
    assert_eq!(
        to - from,
        20 * 60_000,
        "ten minutes either side of an event that has not lasted"
    );
    assert_eq!(ctx["cut"], false);
    let process = ctx["process"].as_array().unwrap();
    assert_eq!(process.len(), 1, "one sample of busy.exe in the window");
    assert_eq!(process[0]["cpu_percent"], 60.0);
    assert!(
        process[0]["net_bytes_per_sec"].is_null(),
        "never measured stays null"
    );
    let system = ctx["system"].as_array().unwrap();
    assert!(!system.is_empty());
    assert_eq!(system[0]["cpu_percent"], 20.0);
}

async fn raw(app: &axum::Router, uri: &str) -> (StatusCode, String, axum::http::HeaderMap) {
    let req = Request::builder()
        .uri(uri)
        .header("host", "localhost:8099")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 26)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap(), headers)
}

#[tokio::test]
async fn the_history_downloads_as_csv_and_json_with_one_row_per_sample() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    let now = unix_millis_now();
    let range = format!("from_ms={}&to_ms={}", now - 700_000, now + 1);

    let (code, csv, headers) = raw(&app, &format!("/api/export/history?{range}")).await;
    assert_eq!(code, StatusCode::OK);
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    assert!(
        headers["content-disposition"]
            .to_str()
            .unwrap()
            .contains("winperf-history.csv")
    );
    let lines: Vec<&str> = csv.trim_end().split("\r\n").collect();
    assert_eq!(lines.len(), 121, "a header and one row per sample");
    assert!(lines[0].starts_with("time_utc_ms,cpu_percent,"));
    let first: Vec<&str> = lines[1].split(',').collect();
    assert_eq!(first.len(), 13);
    assert_eq!(first[1], "20", "cpu as stored");
    assert_eq!(first[6], "", "never measured is empty, not zero");
    // Oldest first.
    let times: Vec<i64> = lines[1..]
        .iter()
        .map(|l| l.split(',').next().unwrap().parse().unwrap())
        .collect();
    assert!(times.windows(2).all(|w| w[0] < w[1]));

    let (_, json, headers) = raw(&app, &format!("/api/export/history?format=json&{range}")).await;
    assert_eq!(headers["content-type"], "application/json");
    let rows: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 120);
    assert_eq!(rows[0]["cpu_percent"], 20.0);
    assert!(rows[0]["disk_latency_ms"].is_null());
    assert_eq!(rows[0]["time_utc_ms"], times[0]);

    // An empty range is still a valid document.
    let (_, empty, _) = raw(&app, "/api/export/history?format=json&from_ms=1&to_ms=2").await;
    assert_eq!(empty, "[]");
    let (code, _, _) = raw(&app, "/api/export/history?format=xml").await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    let (code, _, _) = raw(&app, "/api/export/secrets").await;
    assert_eq!(code, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn exported_text_cannot_run_as_a_spreadsheet_formula() {
    let s = Scratch::new();
    seed(&s.db());
    let db = Database::open(&s.db()).unwrap();
    let now = unix_millis_now();
    let mut nasty = event(now - 30_000, 42, Severity::Warning);
    nasty.process_name = "=cmd|' /C calc'!A0".into();
    nasty.exe_path = "@SUM(1+1),\"x\"".into();
    nasty.explanation = "-2+3 then\nnew line".into();
    db.insert_anomaly(&nasty).unwrap();
    drop(db);
    let app = app(settings(s.db(), None));
    let (_, csv, _) = raw(&app, "/api/export/anomalies?hours=24").await;
    assert!(csv.contains("'=cmd|' /C calc'!A0"), "{csv}");
    assert!(csv.contains("\"'@SUM(1+1),\"\"x\"\"\""), "{csv}");
    assert!(csv.contains("\"'-2+3 then\nnew line\""), "{csv}");
    // No cell of any line starts with a bare formula character.
    let (_, json, _) = raw(&app, "/api/export/anomalies?format=json").await;
    let back: serde_json::Value = serde_json::from_str(&json).unwrap();
    let names: Vec<&str> = back
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["process"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"=cmd|' /C calc'!A0"),
        "JSON keeps the real text"
    );
}

#[tokio::test]
async fn rankings_export_matches_the_ranking_api() {
    let s = Scratch::new();
    seed(&s.db());
    let app = app(settings(s.db(), None));
    let now = unix_millis_now();
    let range = format!("from_ms={}&to_ms={}", now - 700_000, now + 1);
    let (_, api_rows) = local(&app, &format!("/api/rankings?metric=cpu&{range}")).await;
    let (_, csv, _) = raw(&app, &format!("/api/export/rankings?metric=cpu&{range}")).await;
    let lines: Vec<&str> = csv.trim_end().split("\r\n").collect();
    assert_eq!(lines[0], "rank,name,application,current,average,peak");
    let want = api_rows["rows"].as_array().unwrap();
    assert_eq!(lines.len(), want.len() + 1);
    assert!(lines[1].starts_with(&format!("1,{},", want[0]["name"].as_str().unwrap())));
    let (code, _, _) = raw(&app, "/api/export/rankings?metric=gpu").await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
}
