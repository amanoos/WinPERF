-- Schema v4: per-process network throughput (PRD FR-008).
--
-- Attributed per PID from ETW TCP/IP + UDP/IP events, which needs administrator rights. NULL means
-- "not measured": attribution wasn't running, or this is the instance's first sample. Zero means a
-- measured absence of traffic. Idle processes therefore cost almost nothing per row.
ALTER TABLE resource_samples ADD COLUMN net_rx_bytes_per_sec REAL;
ALTER TABLE resource_samples ADD COLUMN net_tx_bytes_per_sec REAL;
