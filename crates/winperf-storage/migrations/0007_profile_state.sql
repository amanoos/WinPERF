-- Schema v7: baseline collection mode (PRD FR-010, `winperf profile start|stop`).
--
-- A single row. While `active` is 1 the system is in its initial profiling phase: baselines are
-- still being learned, so anomaly detection (T19+) holds back. Sampling itself is unaffected;
-- the monitor always records.

CREATE TABLE profile_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    active     INTEGER NOT NULL CHECK (active IN (0, 1)),
    started_ms INTEGER,   -- when the current or last profiling phase began (UTC ms)
    stopped_ms INTEGER    -- when the last phase ended; NULL while active or never run
);

INSERT INTO profile_state (id, active) VALUES (1, 0);
