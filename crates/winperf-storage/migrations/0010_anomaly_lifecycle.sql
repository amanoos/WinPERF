-- Schema v10: anomaly lifecycle and system impact (PRD FR-017, FR-018).
--
-- An event is active while `resolved_ts_ms` is NULL. While it lasts the monitor updates it in
-- place (longer duration, worse severity, newer numbers) instead of adding more rows, and
-- `last_update_ts_ms` says when it was last confirmed. Events left active by a monitor that
-- stopped are resolved, as of their last update, when the next one starts.
--
-- `pressure_percent` is how busy the resource was system-wide, `share_percent` the process's part
-- of it, `impact_score` their product (0 to 100). NULL means it could not be measured.

ALTER TABLE anomaly_events ADD COLUMN resolved_ts_ms INTEGER;
ALTER TABLE anomaly_events ADD COLUMN last_update_ts_ms INTEGER;
ALTER TABLE anomaly_events ADD COLUMN system_disk_percent REAL;
ALTER TABLE anomaly_events ADD COLUMN pressure_percent REAL;
ALTER TABLE anomaly_events ADD COLUMN share_percent REAL;
ALTER TABLE anomaly_events ADD COLUMN impact_score REAL;

UPDATE anomaly_events SET last_update_ts_ms = detected_ts_ms;

CREATE INDEX ix_anomaly_events_active ON anomaly_events (id) WHERE resolved_ts_ms IS NULL;
