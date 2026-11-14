-- Schema v6: baseline profiles (PRD 4.2 BaselineProfiles, FR-011).
--
-- One row per (scope, subject, window, metric). `subject_id` is an executables.id or an
-- installed_applications.id depending on `scope`, so it has no foreign key. A subject's usage is
-- summed across its running instances at each tick before the statistics are taken.
-- The whole window is replaced on every recompute, so rows never go stale.

CREATE TABLE baseline_profiles (
    id              INTEGER PRIMARY KEY,
    scope           TEXT    NOT NULL CHECK (scope IN ('executable', 'application')),
    subject_id      INTEGER NOT NULL,
    window_hours    INTEGER NOT NULL CHECK (window_hours > 0),
    metric          TEXT    NOT NULL
        CHECK (metric IN ('cpu', 'memory', 'disk_read', 'disk_write', 'net_rx', 'net_tx')),
    observations    INTEGER NOT NULL,   -- ticks at which this metric was measured
    first_ts_ms     INTEGER NOT NULL,   -- span of the subject's ticks in the window (UTC ms)
    last_ts_ms      INTEGER NOT NULL,
    mean            REAL    NOT NULL,
    median          REAL    NOT NULL,
    mad             REAL    NOT NULL,   -- median absolute deviation, unscaled
    stddev          REAL    NOT NULL,
    p95             REAL    NOT NULL,
    peak            REAL    NOT NULL,
    growth_per_hour REAL,               -- bytes/hour of private memory; 'memory' rows only
    computed_at_ms  INTEGER NOT NULL,
    UNIQUE (scope, subject_id, window_hours, metric)
);
