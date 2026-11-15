//! CSV and JSON downloads of the rankings, the system history and the anomalies.
//!
//! The history can be millions of rows, so it is streamed: a blocking thread reads the database
//! and sends chunks down a small channel, and a download that is closed stops the read. CSV cells
//! that a spreadsheet could take for a formula are neutralised (see [`csv_cell`]).

use crate::Shared;
use crate::api::{ApiError, bad, read_err, with_db};
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use serde::Deserialize;
use std::convert::Infallible;
use tokio_stream::wrappers::ReceiverStream;
use winperf_core::time::unix_millis_now;
use winperf_storage::{AnomalyFilter, Database, RankGroup, RankMetric};

const HOUR_MS: i64 = 3_600_000;
const MAX_RANGE_MS: i64 = 400 * 24 * HOUR_MS;
/// Rows per chunk sent to the download.
const CHUNK_ROWS: usize = 500;
const MAX_ANOMALIES: u32 = 10_000;

/// One value of a row.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Num(f64),
    Text(String),
}

impl Cell {
    pub fn opt(v: Option<f64>) -> Cell {
        v.filter(|v| v.is_finite()).map_or(Cell::Null, Cell::Num)
    }
    pub fn text(v: impl Into<String>) -> Cell {
        Cell::Text(v.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Json,
}

impl Format {
    fn parse(text: Option<&str>) -> Option<Format> {
        match text {
            None | Some("csv") => Some(Format::Csv),
            Some("json") => Some(Format::Json),
            _ => None,
        }
    }
    fn content_type(self) -> &'static str {
        match self {
            Format::Csv => "text/csv; charset=utf-8",
            Format::Json => "application/json",
        }
    }
    fn extension(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Json => "json",
        }
    }
}

/// One CSV cell. Text that starts with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed
/// with an apostrophe so a spreadsheet shows it as text instead of running it as a formula; the
/// cell is quoted when it holds a comma, quote or line break. Numbers are never changed (a
/// negative number is a number, not a formula).
pub fn csv_cell(cell: &Cell) -> String {
    let text = match cell {
        Cell::Null => return String::new(),
        Cell::Int(v) => return v.to_string(),
        Cell::Num(v) => return v.to_string(),
        Cell::Text(t) => t,
    };
    let guarded = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.clone()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn json_value(cell: &Cell) -> serde_json::Value {
    match cell {
        Cell::Null => serde_json::Value::Null,
        Cell::Int(v) => (*v).into(),
        Cell::Num(v) => {
            serde_json::Number::from_f64(*v).map_or(serde_json::Value::Null, Into::into)
        }
        Cell::Text(t) => t.clone().into(),
    }
}

/// Turns rows into the bytes of a CSV or JSON document, a chunk at a time.
pub struct Encoder {
    format: Format,
    columns: Vec<&'static str>,
    /// The document's start has been written.
    started: bool,
    /// At least one row has been written (so JSON needs a comma before the next).
    any_row: bool,
}

impl Encoder {
    pub fn new(format: Format, columns: &[&'static str]) -> Self {
        Self {
            format,
            columns: columns.to_vec(),
            started: false,
            any_row: false,
        }
    }

    fn start(&mut self, out: &mut String) {
        if self.started {
            return;
        }
        self.started = true;
        match self.format {
            Format::Csv => {
                out.push_str(&self.columns.join(","));
                out.push_str("\r\n");
            }
            Format::Json => out.push('['),
        }
    }

    /// The text for these rows (the document start is added to the first call).
    pub fn rows(&mut self, rows: &[Vec<Cell>]) -> String {
        let mut out = String::new();
        self.start(&mut out);
        for row in rows {
            match self.format {
                Format::Csv => {
                    let cells: Vec<String> = row.iter().map(csv_cell).collect();
                    out.push_str(&cells.join(","));
                    out.push_str("\r\n");
                }
                Format::Json => {
                    if self.any_row {
                        out.push(',');
                    }
                    let object: serde_json::Map<String, serde_json::Value> = self
                        .columns
                        .iter()
                        .zip(row)
                        .map(|(k, c)| ((*k).to_string(), json_value(c)))
                        .collect();
                    out.push_str(&serde_json::Value::Object(object).to_string());
                }
            }
            self.any_row = true;
        }
        out
    }

    /// The end of the document (and its start, if no row was ever written).
    pub fn finish(&mut self) -> String {
        let mut out = String::new();
        self.start(&mut out);
        if self.format == Format::Json {
            out.push(']');
        }
        out
    }
}

fn download(format: Format, name: &str, body: Body) -> Response {
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(format.content_type()),
    );
    if let Ok(v) = HeaderValue::from_str(&format!(
        "attachment; filename=\"winperf-{name}.{}\"",
        format.extension()
    )) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    response
}

fn range(from: Option<i64>, to: Option<i64>, default_span: i64) -> Result<(i64, i64), ApiError> {
    let to_ms = to.unwrap_or_else(unix_millis_now);
    let from_ms = from.unwrap_or(to_ms - default_span);
    if from_ms >= to_ms {
        return Err(bad("from_ms must be before to_ms"));
    }
    if to_ms - from_ms > MAX_RANGE_MS {
        return Err(bad("the range may be at most 400 days"));
    }
    Ok((from_ms, to_ms))
}

#[derive(Deserialize)]
pub struct ExportQuery {
    format: Option<String>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    metric: Option<String>,
    group: Option<String>,
    limit: Option<u32>,
}

/// `GET /api/export/{rankings|history|anomalies}?format=csv|json&...`
pub async fn export(
    State(shared): State<Shared>,
    Path(kind): Path<String>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let format =
        Format::parse(q.format.as_deref()).ok_or_else(|| bad("format must be csv or json"))?;
    match kind.as_str() {
        "history" => history(shared, format, q).await,
        "rankings" => rankings(shared, format, q).await,
        "anomalies" => anomalies(shared, format, q).await,
        _ => Err(ApiError(
            StatusCode::NOT_FOUND,
            "export one of rankings, history or anomalies".into(),
        )),
    }
}

const HISTORY_COLUMNS: [&str; 13] = [
    "time_utc_ms",
    "cpu_percent",
    "memory_total_bytes",
    "memory_available_bytes",
    "commit_used_bytes",
    "commit_limit_bytes",
    "disk_busy_percent",
    "disk_queue_length",
    "disk_read_bytes_per_sec",
    "disk_write_bytes_per_sec",
    "disk_latency_ms",
    "net_rx_bytes_per_sec",
    "net_tx_bytes_per_sec",
];

/// The system history, streamed so that a long range never sits in memory.
async fn history(shared: Shared, format: Format, q: ExportQuery) -> Result<Response, ApiError> {
    let (from_ms, to_ms) = range(q.from_ms, q.to_ms, 24 * HOUR_MS)?;
    // Check here so a missing database is a clear error, not an empty download.
    let path = shared.db_path.clone();
    if !path.exists() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "there is no database yet: has the monitor or the service run?".into(),
        ));
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(4);
    tokio::task::spawn_blocking(move || {
        let Ok(db) = Database::open_read_only(&path) else {
            return;
        };
        let mut encoder = Encoder::new(format, &HISTORY_COLUMNS);
        let mut batch: Vec<Vec<Cell>> = Vec::with_capacity(CHUNK_ROWS);
        let mut open = true;
        let read = db.system_samples_each(from_ms, to_ms, |s| {
            let big = |v: Option<u64>| v.map_or(Cell::Null, |x| Cell::Int(x as i64));
            batch.push(vec![
                Cell::Int(s.ts_ms),
                Cell::opt(s.cpu_percent),
                big(s.memory_total_bytes),
                big(s.memory_available_bytes),
                big(s.commit_used_bytes),
                big(s.commit_limit_bytes),
                Cell::opt(s.disk_utilization_percent),
                Cell::opt(s.disk_queue_length),
                Cell::opt(s.disk_read_bytes_per_sec),
                Cell::opt(s.disk_write_bytes_per_sec),
                Cell::opt(s.disk_latency_ms),
                Cell::opt(s.net_rx_bytes_per_sec),
                Cell::opt(s.net_tx_bytes_per_sec),
            ]);
            if batch.len() >= CHUNK_ROWS {
                let text = encoder.rows(&batch);
                batch.clear();
                open = tx.blocking_send(Ok(Bytes::from(text))).is_ok();
            }
            open
        });
        if open && read.is_ok() {
            let mut tail = encoder.rows(&batch);
            tail.push_str(&encoder.finish());
            let _ = tx.blocking_send(Ok(Bytes::from(tail)));
        }
    });
    Ok(download(
        format,
        "history",
        Body::from_stream(ReceiverStream::new(rx)),
    ))
}

async fn rankings(shared: Shared, format: Format, q: ExportQuery) -> Result<Response, ApiError> {
    let metric = RankMetric::parse(q.metric.as_deref().unwrap_or("cpu")).ok_or_else(|| {
        bad("metric must be one of cpu, memory, disk_read, disk_write, net_rx, net_tx")
    })?;
    let group = RankGroup::parse(q.group.as_deref().unwrap_or("process"))
        .ok_or_else(|| bad("group must be process or application"))?;
    let (from_ms, to_ms) = range(q.from_ms, q.to_ms, HOUR_MS)?;
    let limit = q.limit.unwrap_or(50).clamp(1, 1000);
    let text = with_db(&shared, move |db| {
        let ranking = db
            .rankings(metric, group, from_ms, to_ms, limit)
            .map_err(read_err)?;
        let rows: Vec<Vec<Cell>> = ranking
            .rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                vec![
                    Cell::Int(i as i64 + 1),
                    Cell::text(r.name.clone()),
                    r.application.clone().map_or(Cell::Null, Cell::Text),
                    Cell::opt(r.current),
                    Cell::Num(r.average),
                    Cell::Num(r.peak),
                ]
            })
            .collect();
        let mut encoder = Encoder::new(
            format,
            &["rank", "name", "application", "current", "average", "peak"],
        );
        let mut text = encoder.rows(&rows);
        text.push_str(&encoder.finish());
        Ok(text)
    })
    .await?;
    Ok(download(format, "rankings", Body::from(text)))
}

async fn anomalies(shared: Shared, format: Format, q: ExportQuery) -> Result<Response, ApiError> {
    let (from_ms, to_ms) = range(q.from_ms, q.to_ms, 24 * HOUR_MS)?;
    let limit = q.limit.unwrap_or(MAX_ANOMALIES).clamp(1, MAX_ANOMALIES);
    let text = with_db(&shared, move |db| {
        let list = db
            .list_anomalies(
                &AnomalyFilter {
                    since_ms: Some(from_ms),
                    active_only: false,
                },
                limit,
            )
            .map_err(read_err)?;
        let rows: Vec<Vec<Cell>> = list
            .iter()
            .filter(|a| a.detected_ts_ms <= to_ms)
            .map(|a| {
                vec![
                    Cell::Int(a.id),
                    Cell::Int(a.detected_ts_ms),
                    a.resolved_ts_ms.map_or(Cell::Null, Cell::Int),
                    Cell::text(if a.is_active() { "active" } else { "resolved" }),
                    Cell::text(a.severity.as_str()),
                    Cell::text(a.resource.as_str()),
                    Cell::text(a.kind.as_str()),
                    Cell::text(a.process_name.clone()),
                    a.application.clone().map_or(Cell::Null, Cell::Text),
                    Cell::text(a.exe_path.clone()),
                    Cell::Num(a.current),
                    Cell::Num(a.baseline),
                    Cell::Num(a.deviation_pct),
                    Cell::Int(a.duration_ms),
                    Cell::opt(a.system_cpu_percent),
                    Cell::opt(a.system_memory_percent),
                    Cell::opt(a.system_disk_percent),
                    Cell::text(a.explanation.clone()),
                ]
            })
            .collect();
        let mut encoder = Encoder::new(
            format,
            &[
                "id",
                "detected_utc_ms",
                "resolved_utc_ms",
                "state",
                "severity",
                "resource",
                "kind",
                "process",
                "application",
                "exe_path",
                "current",
                "baseline",
                "deviation_percent",
                "duration_ms",
                "system_cpu_percent",
                "system_memory_percent",
                "system_disk_percent",
                "explanation",
            ],
        );
        let mut text = encoder.rows(&rows);
        text.push_str(&encoder.finish());
        Ok(text)
    })
    .await?;
    Ok(download(format, "anomalies", Body::from(text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_that_could_be_a_formula_is_made_harmless() {
        for risky in ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tx", "\rx"] {
            let out = csv_cell(&Cell::text(risky));
            assert!(
                out.trim_matches('"').starts_with('\''),
                "{risky:?} -> {out:?}"
            );
        }
        assert_eq!(
            csv_cell(&Cell::text("=HYPERLINK(\"http://x\",\"a\")")),
            "\"'=HYPERLINK(\"\"http://x\"\",\"\"a\"\")\""
        );
        assert_eq!(csv_cell(&Cell::text("busy.exe")), "busy.exe");
    }

    #[test]
    fn numbers_stay_numbers_and_quoting_follows_the_rules() {
        assert_eq!(csv_cell(&Cell::Num(-2.5)), "-2.5");
        assert_eq!(csv_cell(&Cell::Int(-3)), "-3");
        assert_eq!(csv_cell(&Cell::Null), "");
        assert_eq!(csv_cell(&Cell::text("a,b")), "\"a,b\"");
        assert_eq!(csv_cell(&Cell::text("say \"hi\"")), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell(&Cell::text("two\nlines")), "\"two\nlines\"");
    }

    #[test]
    fn documents_have_a_header_or_brackets_even_when_empty() {
        let mut csv = Encoder::new(Format::Csv, &["a", "b"]);
        assert_eq!(csv.finish(), "a,b\r\n");
        let mut json = Encoder::new(Format::Json, &["a"]);
        assert_eq!(json.finish(), "[]");
    }

    #[test]
    fn chunks_join_into_one_valid_document() {
        let mut json = Encoder::new(Format::Json, &["a", "b"]);
        let mut all = json.rows(&[vec![Cell::Int(1), Cell::text("x")]]);
        all.push_str(&json.rows(&[vec![Cell::Int(2), Cell::Null]]));
        all.push_str(&json.finish());
        let back: serde_json::Value = serde_json::from_str(&all).unwrap();
        assert_eq!(back[0]["b"], "x");
        assert!(back[1]["b"].is_null());
        assert_eq!(back.as_array().unwrap().len(), 2);

        let mut csv = Encoder::new(Format::Csv, &["a", "b"]);
        let mut all = csv.rows(&[vec![Cell::Int(1), Cell::text("x")]]);
        all.push_str(&csv.rows(&[vec![Cell::Int(2), Cell::Null]]));
        all.push_str(&csv.finish());
        assert_eq!(all, "a,b\r\n1,x\r\n2,\r\n");
    }
}
