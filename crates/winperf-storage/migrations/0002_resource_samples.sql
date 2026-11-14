-- Schema v2: per-process resource samples (PRD 4.2 ResourceSamples; CPU + memory columns).
-- Disk and network columns arrive in later migrations (T12/T14).

-- Where the instance's executable lives, so it can be classified later without re-querying the OS.
ALTER TABLE process_instances ADD COLUMN exe_path TEXT;

-- One row per process instance per tick. A NULL means "could not be measured", never zero:
-- the first sample of an instance has no CPU value because CPU time is cumulative.
CREATE TABLE resource_samples (
    id                     INTEGER PRIMARY KEY,
    process_instance_id    INTEGER NOT NULL
        REFERENCES process_instances (id) ON DELETE CASCADE,
    ts_ms                  INTEGER NOT NULL,   -- Unix milliseconds, UTC
    cpu_percent            REAL,               -- percent of the whole machine (all logical CPUs)
    working_set_bytes      INTEGER,
    private_bytes          INTEGER,
    virtual_bytes          INTEGER,
    peak_working_set_bytes INTEGER
);

CREATE INDEX ix_resource_samples_instance_ts ON resource_samples (process_instance_id, ts_ms);
CREATE INDEX ix_resource_samples_ts ON resource_samples (ts_ms);
