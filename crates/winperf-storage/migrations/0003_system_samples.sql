-- Schema v3: process I/O rates and system-wide health samples (PRD 4.2 SystemSamples).

-- Per-process I/O rates. They come from the process I/O counters, which count ALL I/O a process
-- issues (files, pipes, devices, network), not only physical disk traffic: hence the `io_` prefix
-- and no "disk" in the name. NULL = could not be measured (the first sample of an instance has
-- no rate yet). REAL zeros cost almost nothing on disk, so idle processes stay cheap.
ALTER TABLE resource_samples ADD COLUMN io_read_bytes_per_sec REAL;
ALTER TABLE resource_samples ADD COLUMN io_write_bytes_per_sec REAL;
ALTER TABLE resource_samples ADD COLUMN io_read_ops_per_sec REAL;
ALTER TABLE resource_samples ADD COLUMN io_write_ops_per_sec REAL;

-- One row per tick: machine-wide health. Each metric is independently NULL when unavailable.
CREATE TABLE system_samples (
    id                       INTEGER PRIMARY KEY,
    ts_ms                    INTEGER NOT NULL,   -- Unix milliseconds, UTC
    cpu_percent              REAL,               -- total CPU busy, 0..100
    memory_total_bytes       INTEGER,
    memory_available_bytes   INTEGER,
    commit_used_bytes        INTEGER,
    commit_limit_bytes       INTEGER,
    disk_utilization_percent REAL,               -- physical disks busy, 0..100
    disk_queue_length        REAL,
    disk_read_bytes_per_sec  REAL,               -- physical disk (system-wide), not process I/O
    disk_write_bytes_per_sec REAL,
    disk_latency_ms          REAL,
    net_rx_bytes_per_sec     REAL,               -- physical adapters only
    net_tx_bytes_per_sec     REAL
);

CREATE INDEX ix_system_samples_ts ON system_samples (ts_ms);
