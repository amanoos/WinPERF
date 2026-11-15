-- Schema v8: anomaly events (PRD 4.2 AnomalyEvents, FR-018).
--
-- One row per detected anomaly. The process is described by value (pid, name, path) as well as
-- by `process_instance_id`, so an event stays readable after the instance rows are pruned; the
-- id is a convenience link with no foreign key and is NULL when the instance had not been
-- written yet at detection time.

CREATE TABLE anomaly_events (
    id                    INTEGER PRIMARY KEY,
    detected_ts_ms        INTEGER NOT NULL,
    process_instance_id   INTEGER,
    pid                   INTEGER NOT NULL,
    process_name          TEXT    NOT NULL,
    application           TEXT,              -- installed application name, when known
    exe_path              TEXT    NOT NULL,
    resource              TEXT    NOT NULL CHECK (resource IN ('cpu', 'memory', 'disk', 'network')),
    current_value         REAL    NOT NULL,  -- percent for cpu
    baseline_value        REAL    NOT NULL,  -- the baseline median, same unit
    deviation_pct         REAL    NOT NULL,
    duration_ms           INTEGER NOT NULL,
    severity              TEXT    NOT NULL
        CHECK (severity IN ('informational', 'warning', 'high', 'critical')),
    system_cpu_percent    REAL,              -- system health at detection; NULL = not measured
    system_memory_percent REAL,
    baseline_window_hours INTEGER NOT NULL,
    baseline_confidence   TEXT    NOT NULL,
    explanation           TEXT    NOT NULL
);

CREATE INDEX ix_anomaly_events_time ON anomaly_events (detected_ts_ms);
