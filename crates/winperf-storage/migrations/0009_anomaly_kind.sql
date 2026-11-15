-- Schema v9: what an anomaly event measures.
--
-- 'deviation'     : a resource level far above normal (current and baseline are levels).
-- 'memory_growth' : private memory climbing without reclamation, a potential leak (current and
--                   baseline are growth rates in bytes per hour).
-- Existing rows are all CPU deviations.

ALTER TABLE anomaly_events
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'deviation'
    CHECK (kind IN ('deviation', 'memory_growth'));
