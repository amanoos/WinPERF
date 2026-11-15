-- Schema v11: 1-minute and 15-minute rollups (T34, PRD 4.3).
--
-- Raw samples are kept for a couple of days; older history lives in these tables. `res_ms` is the
-- bucket width (60000 or 900000) and `bucket_ts` the bucket's start (Unix ms, UTC, a multiple of the
-- width). `n` is how many raw ticks the bucket covers (a 15-minute row sums its minutes' `n`).
-- Averages ignore ticks where the value was not measured and are NULL when it never was.
--
-- No foreign key to process_instances: deleting an instance must not scan these tables, and an
-- old rollup row outliving its instance is harmless (the maintenance job removes both by age).

CREATE TABLE process_rollups (
    res_ms              INTEGER NOT NULL,
    bucket_ts           INTEGER NOT NULL,
    process_instance_id INTEGER NOT NULL,
    n                   INTEGER NOT NULL,
    cpu_avg             REAL,
    cpu_max             REAL,
    working_set_avg     REAL,
    working_set_max     REAL,
    private_avg         REAL,
    private_max         REAL,
    io_read_avg         REAL,
    io_read_max         REAL,
    io_write_avg        REAL,
    io_write_max        REAL,
    net_rx_avg          REAL,
    net_rx_max          REAL,
    net_tx_avg          REAL,
    net_tx_max          REAL,
    PRIMARY KEY (res_ms, bucket_ts, process_instance_id)
) WITHOUT ROWID;

CREATE TABLE system_rollups (
    res_ms             INTEGER NOT NULL,
    bucket_ts          INTEGER NOT NULL,
    n                  INTEGER NOT NULL,
    cpu_avg            REAL,
    cpu_max            REAL,
    memory_total       INTEGER,
    memory_avail_avg   REAL,
    memory_avail_min   REAL,
    commit_used_avg    REAL,
    commit_limit       INTEGER,
    disk_util_avg      REAL,
    disk_util_max      REAL,
    disk_queue_avg     REAL,
    disk_read_avg      REAL,
    disk_write_avg     REAL,
    disk_latency_avg   REAL,
    disk_latency_max   REAL,
    net_rx_avg         REAL,
    net_rx_max         REAL,
    net_tx_avg         REAL,
    net_tx_max         REAL,
    PRIMARY KEY (res_ms, bucket_ts)
) WITHOUT ROWID;

-- How far each rollup has been built (Unix ms: everything before it is done).
CREATE TABLE maintenance_state (
    key   TEXT    PRIMARY KEY,
    value INTEGER NOT NULL
) WITHOUT ROWID;
