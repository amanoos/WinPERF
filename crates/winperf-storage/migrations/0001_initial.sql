-- Schema v1: inventory (PRD 4.2: InstalledApplications, Executables, Processes).
-- Timestamps are UTC text `YYYY-MM-DD HH:MM:SS`. FILETIME values are stored as INTEGER ticks.

CREATE TABLE installed_applications (
    id                INTEGER PRIMARY KEY,
    -- lower(name) | version | lower(publisher): the identity of a product across scans
    app_key           TEXT    NOT NULL UNIQUE,
    name              TEXT    NOT NULL,
    publisher         TEXT,
    version           TEXT,
    install_date      TEXT,
    install_location  TEXT,
    uninstall_command TEXT,
    registry_sources  TEXT    NOT NULL,          -- ';'-separated
    classification    TEXT    NOT NULL,
    first_seen        TEXT    NOT NULL,
    last_seen         TEXT    NOT NULL,
    scan_seq          INTEGER NOT NULL           -- which scan last saw it; older rows are pruned
);

-- One row per executable file. Also the persistent signature cache: a row is valid for a file
-- only while (file_size, file_mtime_ns) still match.
CREATE TABLE executables (
    id                INTEGER PRIMARY KEY,
    path_key          TEXT    NOT NULL UNIQUE,   -- lower-cased path
    file_path         TEXT    NOT NULL,
    file_name         TEXT    NOT NULL,
    product_name      TEXT,
    file_description  TEXT,
    original_filename TEXT,
    file_version      TEXT,
    signature_status  TEXT    NOT NULL
        CHECK (signature_status IN ('valid', 'not_signed', 'invalid', 'unreadable')),
    signer            TEXT,                      -- set when valid
    signature_code    INTEGER,                   -- Windows trust result when invalid
    classification    TEXT    NOT NULL,
    file_size         INTEGER NOT NULL,
    file_mtime_ns     INTEGER NOT NULL,
    verified_at       TEXT    NOT NULL
);

-- One row per process *instance*. PIDs are reused, so identity is (pid, start_time).
-- start_time 0 means the creation time could not be read (access denied).
CREATE TABLE process_instances (
    id             INTEGER PRIMARY KEY,
    pid            INTEGER NOT NULL,
    start_time     INTEGER NOT NULL,
    parent_pid     INTEGER NOT NULL,
    name           TEXT    NOT NULL,
    executable_id  INTEGER REFERENCES executables (id),
    application_id INTEGER REFERENCES installed_applications (id) ON DELETE SET NULL,
    user_account   TEXT,
    session_id     INTEGER,
    first_seen     TEXT    NOT NULL,
    last_seen      TEXT    NOT NULL,
    end_time       TEXT,                         -- NULL while the instance is believed running
    UNIQUE (pid, start_time)
);

CREATE INDEX ix_process_instances_running ON process_instances (pid) WHERE end_time IS NULL;
CREATE INDEX ix_process_instances_executable ON process_instances (executable_id);
