-- Schema v5: index resource_samples by time first.
--
-- Every tick inserts one row per live process (~560). With the old (process_instance_id, ts_ms)
-- index each of those rows lands on a different index page, so a tick dirtied hundreds of pages
-- and the monitor wrote ~3 MB to disk per tick on a database with history (measured). With time
-- first, new entries always append at the end of the index: a few pages per tick.
--
-- Readers that ask "all samples in a time window" (baselines, rollups, charts, retention) are
-- served by this index directly. "All samples of one instance" now reads the time window it needs
-- and filters, so callers should give a window.
--
-- ix_resource_samples_ts (ts_ms) is covered by the new index and is dropped as redundant.
--
-- Note for retention (T34): resource_samples.process_instance_id is a foreign key with ON DELETE
-- CASCADE and no longer has its own index, so deleting a process_instances row scans the table.
-- Delete old samples by time first and prune instances with foreign_keys switched off.

DROP INDEX ix_resource_samples_instance_ts;
DROP INDEX ix_resource_samples_ts;
CREATE INDEX ix_resource_samples_ts_instance ON resource_samples (ts_ms, process_instance_id);
