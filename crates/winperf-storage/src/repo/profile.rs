//! Baseline collection mode: the single `profile_state` row.

use crate::db::Database;
use crate::error::Result;
use rusqlite::params;

/// Whether the system is in its initial profiling phase, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileState {
    pub active: bool,
    pub started_ms: Option<i64>,
    pub stopped_ms: Option<i64>,
}

impl Database {
    pub fn profile_state(&self) -> Result<ProfileState> {
        Ok(self.conn().query_row(
            "SELECT active, started_ms, stopped_ms FROM profile_state WHERE id = 1",
            [],
            |r| {
                Ok(ProfileState {
                    active: r.get::<_, i64>(0)? == 1,
                    started_ms: r.get(1)?,
                    stopped_ms: r.get(2)?,
                })
            },
        )?)
    }

    /// Enter profiling mode. Returns `false` (and changes nothing) if it was already active, so
    /// the original start time is kept.
    pub fn start_profiling(&self, now_ms: i64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE profile_state SET active = 1, started_ms = ?1, stopped_ms = NULL \
             WHERE id = 1 AND active = 0",
            params![now_ms],
        )?;
        Ok(changed == 1)
    }

    /// Leave profiling mode. Returns `false` if it was not active.
    pub fn stop_profiling(&self, now_ms: i64) -> Result<bool> {
        let changed = self.conn().execute(
            "UPDATE profile_state SET active = 0, stopped_ms = ?1 WHERE id = 1 AND active = 1",
            params![now_ms],
        )?;
        Ok(changed == 1)
    }

    /// Timestamp of the newest process sample, if any (is a monitor writing?).
    pub fn latest_sample_ms(&self) -> Result<Option<i64>> {
        Ok(self
            .conn()
            .query_row("SELECT MAX(ts_ms) FROM resource_samples", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_database_is_not_profiling() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(
            db.profile_state().unwrap(),
            ProfileState {
                active: false,
                started_ms: None,
                stopped_ms: None
            }
        );
    }

    #[test]
    fn start_and_stop_record_times_and_repeats_change_nothing() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.start_profiling(1000).unwrap());
        assert!(!db.start_profiling(2000).unwrap(), "already active");
        let s = db.profile_state().unwrap();
        assert_eq!(
            (s.active, s.started_ms, s.stopped_ms),
            (true, Some(1000), None)
        );

        assert!(db.stop_profiling(5000).unwrap());
        assert!(!db.stop_profiling(6000).unwrap(), "already stopped");
        let s = db.profile_state().unwrap();
        assert_eq!(
            (s.active, s.started_ms, s.stopped_ms),
            (false, Some(1000), Some(5000))
        );

        // A second phase starts fresh.
        assert!(db.start_profiling(9000).unwrap());
        let s = db.profile_state().unwrap();
        assert_eq!(
            (s.active, s.started_ms, s.stopped_ms),
            (true, Some(9000), None)
        );
    }

    #[test]
    fn stopping_when_never_started_is_a_no_op() {
        let db = Database::open_in_memory().unwrap();
        assert!(!db.stop_profiling(1).unwrap());
        assert_eq!(db.profile_state().unwrap().stopped_ms, None);
    }

    #[test]
    fn the_state_survives_reopening() {
        let dir = crate::testutil::TempDir::new("profile");
        let path = dir.path().join("p.db");
        Database::open(&path).unwrap().start_profiling(42).unwrap();
        let s = Database::open(&path).unwrap().profile_state().unwrap();
        assert_eq!((s.active, s.started_ms), (true, Some(42)));
    }

    #[test]
    fn latest_sample_is_none_until_something_is_recorded() {
        let db = Database::open_in_memory().unwrap();
        assert_eq!(db.latest_sample_ms().unwrap(), None);
    }
}
