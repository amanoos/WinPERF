//! The read-only JSON API. Every handler opens the database read-only for the request, so nothing
//! here can write, and a database that is busy or missing produces a clear error, not a hang.

use crate::Shared;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use winperf_core::anomaly::AnomalyKind;
use winperf_core::time::unix_millis_now;
use winperf_storage::{AnomalyFilter, Database, StoredAnomaly, StoredSystemSample};

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 24 * HOUR_MS;
/// The longest range one request may ask for (the database never holds more than this).
const MAX_RANGE_MS: i64 = 400 * DAY_MS;

/// An error the browser can read: a status and one sentence.
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}

type ApiResult = Result<Json<Value>, ApiError>;

/// Run `work` against a read-only connection on a blocking thread.
async fn with_db<T, F>(shared: &Shared, work: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T, ApiError> + Send + 'static,
{
    let path = shared.db_path.clone();
    tokio::task::spawn_blocking(move || {
        if !path.exists() {
            return Err(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "there is no database yet: has the monitor or the service run?".into(),
            ));
        }
        let db = Database::open_read_only(&path).map_err(|_| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "the database cannot be opened right now".into(),
            )
        })?;
        work(&db)
    })
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the request failed".into(),
        )
    })?
}

fn read_err(_: impl std::fmt::Debug) -> ApiError {
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "the database could not be read".into(),
    )
}

fn memory_used_percent(s: &StoredSystemSample) -> Option<f64> {
    match (s.memory_total_bytes, s.memory_available_bytes) {
        (Some(total), Some(avail)) if total > 0 => {
            Some((total.saturating_sub(avail)) as f64 / total as f64 * 100.0)
        }
        _ => None,
    }
}

fn system_json(s: &StoredSystemSample) -> Value {
    json!({
        "ts_ms": s.ts_ms,
        "cpu_percent": s.cpu_percent,
        "memory_used_percent": memory_used_percent(s),
        "memory_total_bytes": s.memory_total_bytes,
        "memory_available_bytes": s.memory_available_bytes,
        "commit_used_bytes": s.commit_used_bytes,
        "commit_limit_bytes": s.commit_limit_bytes,
        "disk_busy_percent": s.disk_utilization_percent,
        "disk_queue_length": s.disk_queue_length,
        "disk_read_bytes_per_sec": s.disk_read_bytes_per_sec,
        "disk_write_bytes_per_sec": s.disk_write_bytes_per_sec,
        "disk_latency_ms": s.disk_latency_ms,
        "net_rx_bytes_per_sec": s.net_rx_bytes_per_sec,
        "net_tx_bytes_per_sec": s.net_tx_bytes_per_sec,
    })
}

// ---- /api/status ----------------------------------------------------------------------------

pub async fn status(State(shared): State<Shared>) -> ApiResult {
    let now = unix_millis_now();
    let interval_ms = shared.interval_secs.max(1) as i64 * 1000;
    let path = shared.db_path.clone();
    let body = with_db(&shared, move |db| {
        let latest: Option<i64> = db
            .conn()
            .query_row("SELECT MAX(ts_ms) FROM system_samples", [], |r| r.get(0))
            .map_err(read_err)?;
        let health = db
            .sample_health(now - DAY_MS, 3 * interval_ms)
            .map_err(read_err)?;
        let profile = db.profile_state().map_err(read_err)?;
        Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "now_ms": now,
            "database": {
                "path": path.display().to_string(),
                "size_bytes": std::fs::metadata(&path).map_or(0, |m| m.len()),
            },
            "latest_sample_ms": latest,
            "recording": latest.is_some_and(|t| now - t <= 3 * interval_ms),
            "interval_secs": interval_ms / 1000,
            "last_24h": {
                "samples": health.samples,
                "gaps": health.gaps,
                "longest_gap_ms": health.longest_gap_ms,
            },
            "active_anomalies": db.active_anomaly_count().map_err(read_err)?,
            "profile": {
                "active": profile.active,
                "started_ms": profile.started_ms,
                "stopped_ms": profile.stopped_ms,
            },
        }))
    })
    .await?;
    Ok(Json(body))
}

// ---- /api/current ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CurrentQuery {
    limit: Option<u32>,
}

pub async fn current(State(shared): State<Shared>, Query(q): Query<CurrentQuery>) -> ApiResult {
    let limit = q.limit.unwrap_or(10).clamp(1, 100);
    let body = with_db(&shared, move |db| {
        let latest: Option<i64> = db
            .conn()
            .query_row("SELECT MAX(ts_ms) FROM system_samples", [], |r| r.get(0))
            .map_err(read_err)?;
        let system = match latest {
            Some(ts) => db
                .system_samples_between(ts, ts)
                .map_err(read_err)?
                .first()
                .map(system_json),
            None => None,
        };
        let (process_ts, processes) = db.current_processes(limit).map_err(read_err)?;
        let rows: Vec<Value> = processes
            .iter()
            .map(|p| {
                json!({
                    "pid": p.pid,
                    "name": p.name,
                    "application": p.application,
                    "cpu_percent": p.cpu_percent,
                    "working_set_bytes": p.working_set_bytes,
                    "private_bytes": p.private_bytes,
                    "io_read_bytes_per_sec": p.io_read_bytes_per_sec,
                    "io_write_bytes_per_sec": p.io_write_bytes_per_sec,
                    "net_rx_bytes_per_sec": p.net_rx_bytes_per_sec,
                    "net_tx_bytes_per_sec": p.net_tx_bytes_per_sec,
                })
            })
            .collect();
        Ok(json!({
            "system": system,
            "process_ts_ms": process_ts,
            "processes": rows,
        }))
    })
    .await?;
    Ok(Json(body))
}

// ---- /api/system ----------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SystemQuery {
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    points: Option<u32>,
}

/// Average the readings that fall in one bucket, ignoring the ones that are missing.
#[derive(Default)]
struct Mean {
    sum: f64,
    n: u32,
}

impl Mean {
    fn add(&mut self, v: Option<f64>) {
        if let Some(v) = v.filter(|v| v.is_finite()) {
            self.sum += v;
            self.n += 1;
        }
    }
    fn value(&self) -> Option<f64> {
        (self.n > 0).then(|| self.sum / f64::from(self.n))
    }
}

#[derive(Default)]
struct Bucket {
    cpu: Mean,
    memory: Mean,
    disk_busy: Mean,
    disk_read: Mean,
    disk_write: Mean,
    disk_latency: Mean,
    net_rx: Mean,
    net_tx: Mean,
}

/// Reduce samples to at most `points` evenly spaced buckets over `[from_ms, to_ms]`, averaging
/// within each. Buckets with no samples are left out, so a gap in recording shows as a gap.
pub fn downsample(
    samples: &[StoredSystemSample],
    from_ms: i64,
    to_ms: i64,
    points: u32,
) -> (i64, Vec<Value>) {
    let span = (to_ms - from_ms).max(1);
    let bucket_ms = (span / i64::from(points.max(1)) + 1).max(1);
    let mut buckets: std::collections::BTreeMap<i64, Bucket> = Default::default();
    for s in samples {
        let b = buckets.entry((s.ts_ms - from_ms) / bucket_ms).or_default();
        b.cpu.add(s.cpu_percent);
        b.memory.add(memory_used_percent(s));
        b.disk_busy.add(s.disk_utilization_percent);
        b.disk_read.add(s.disk_read_bytes_per_sec);
        b.disk_write.add(s.disk_write_bytes_per_sec);
        b.disk_latency.add(s.disk_latency_ms);
        b.net_rx.add(s.net_rx_bytes_per_sec);
        b.net_tx.add(s.net_tx_bytes_per_sec);
    }
    let rows = buckets
        .into_iter()
        .map(|(i, b)| {
            json!({
                "ts_ms": from_ms + i * bucket_ms,
                "cpu_percent": b.cpu.value(),
                "memory_used_percent": b.memory.value(),
                "disk_busy_percent": b.disk_busy.value(),
                "disk_read_bytes_per_sec": b.disk_read.value(),
                "disk_write_bytes_per_sec": b.disk_write.value(),
                "disk_latency_ms": b.disk_latency.value(),
                "net_rx_bytes_per_sec": b.net_rx.value(),
                "net_tx_bytes_per_sec": b.net_tx.value(),
            })
        })
        .collect();
    (bucket_ms, rows)
}

pub async fn system(State(shared): State<Shared>, Query(q): Query<SystemQuery>) -> ApiResult {
    let to_ms = q.to_ms.unwrap_or_else(unix_millis_now);
    let from_ms = q.from_ms.unwrap_or(to_ms - HOUR_MS);
    if from_ms >= to_ms {
        return Err(bad("from_ms must be before to_ms"));
    }
    if to_ms - from_ms > MAX_RANGE_MS {
        return Err(bad("the range may be at most 400 days"));
    }
    let points = q.points.unwrap_or(600).clamp(10, 2000);
    let body = with_db(&shared, move |db| {
        let samples = db
            .system_samples_between(from_ms, to_ms)
            .map_err(read_err)?;
        let (bucket_ms, rows) = downsample(&samples, from_ms, to_ms, points);
        Ok(json!({
            "from_ms": from_ms,
            "to_ms": to_ms,
            "samples": samples.len(),
            "bucket_ms": bucket_ms,
            "points": rows,
        }))
    })
    .await?;
    Ok(Json(body))
}

// ---- /api/anomalies -------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AnomalyQuery {
    /// Only events still going on.
    active: Option<bool>,
    /// Events active at some point in the last this many hours (default 24).
    hours: Option<u32>,
    limit: Option<u32>,
}

fn kind_name(kind: AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::Deviation => "deviation",
        AnomalyKind::MemoryGrowth => "memory_growth",
    }
}

pub fn anomaly_json(a: &StoredAnomaly) -> Value {
    json!({
        "id": a.id,
        "state": if a.is_active() { "active" } else { "resolved" },
        "detected_ts_ms": a.detected_ts_ms,
        "resolved_ts_ms": a.resolved_ts_ms,
        "last_update_ts_ms": a.last_update_ts_ms,
        "duration_ms": a.duration_ms,
        "severity": a.severity.as_str(),
        "resource": a.resource.as_str(),
        "kind": kind_name(a.kind),
        "process": {
            "pid": a.pid,
            "name": a.process_name,
            "application": a.application,
            "exe_path": a.exe_path,
        },
        "current": a.current,
        "baseline": a.baseline,
        "deviation_percent": a.deviation_pct,
        "baseline_window_hours": a.baseline_window_hours,
        "baseline_confidence": a.baseline_confidence,
        "system": {
            "cpu_percent": a.system_cpu_percent,
            "memory_percent": a.system_memory_percent,
            "disk_percent": a.system_disk_percent,
        },
        "impact": {
            "pressure_percent": a.pressure_percent,
            "share_percent": a.share_percent,
            "score": a.impact_score,
        },
        "explanation": a.explanation,
    })
}

pub async fn anomalies(State(shared): State<Shared>, Query(q): Query<AnomalyQuery>) -> ApiResult {
    let hours = i64::from(q.hours.unwrap_or(24).clamp(1, 24 * 400));
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let active_only = q.active.unwrap_or(false);
    let since = unix_millis_now() - hours * HOUR_MS;
    let body = with_db(&shared, move |db| {
        let filter = AnomalyFilter {
            since_ms: Some(since),
            active_only,
        };
        let list = db.list_anomalies(&filter, limit).map_err(read_err)?;
        Ok(json!({
            "count": list.len(),
            "anomalies": list.iter().map(anomaly_json).collect::<Vec<_>>(),
        }))
    })
    .await?;
    Ok(Json(body))
}

pub async fn anomaly(State(shared): State<Shared>, Path(id): Path<i64>) -> ApiResult {
    let found = with_db(&shared, move |db| db.anomaly(id).map_err(read_err)).await?;
    match found {
        Some(a) => Ok(Json(anomaly_json(&a))),
        None => Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("there is no anomaly {id}"),
        )),
    }
}
