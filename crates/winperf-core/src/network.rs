//! Per-process network attribution state (PRD FR-008).
//!
//! The OS-specific part (an ETW kernel session) lives in `winperf-windows`; this module holds the
//! pure parts: which events count as send or receive, the running per-PID totals, and the status
//! the front end reports when attribution isn't available (it needs administrator rights, T2).

use std::collections::{HashMap, HashSet};

/// Whether per-process network attribution is running, and if not, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkStatus {
    /// Events are flowing; per-process rates are real.
    Active,
    /// Kernel tracing needs an elevated (administrator) process.
    RequiresAdmin,
    /// The tracing session could not be created because the name or the kernel logger is taken.
    SessionInUse,
    /// Any other failure, with the system's message.
    Failed(String),
}

impl NetworkStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, NetworkStatus::Active)
    }

    /// One line a user can act on.
    pub fn describe(&self) -> String {
        match self {
            NetworkStatus::Active => "per-process network attribution is active".into(),
            NetworkStatus::RequiresAdmin => {
                "per-process network attribution is unavailable: it needs administrator rights \
                 (run from an elevated prompt or as the service)"
                    .into()
            }
            NetworkStatus::SessionInUse => {
                "per-process network attribution is unavailable: another tracing session is \
                 using the name or the kernel logger"
                    .into()
            }
            NetworkStatus::Failed(why) => {
                format!("per-process network attribution is unavailable: {why}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Receive,
    Send,
}

/// Direction of a kernel TCP/IP or UDP/IP trace event, from its ETW opcode. `None` for events
/// that don't move payload (connect, disconnect, retransmit, ...), which must not be counted.
pub fn direction_of(opcode: u8) -> Option<Direction> {
    match opcode {
        10 | 26 => Some(Direction::Send),    // Send, SendIPv6
        11 | 27 => Some(Direction::Receive), // Recv, RecvIPv6
        _ => None,
    }
}

/// Cumulative bytes received and sent per process ID since collection started.
///
/// Totals are per PID, not per process instance: PIDs are reused, but the sampler computes rates
/// from the difference between a *given instance's* consecutive observations, so traffic that
/// belonged to an earlier owner of the PID cancels out (an instance's first observation yields no
/// rate).
#[derive(Debug, Default, Clone)]
pub struct NetworkTotals {
    by_pid: HashMap<u32, (u64, u64)>,
}

impl NetworkTotals {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, pid: u32, direction: Direction, bytes: u64) {
        let entry = self.by_pid.entry(pid).or_default();
        match direction {
            Direction::Receive => entry.0 = entry.0.saturating_add(bytes),
            Direction::Send => entry.1 = entry.1.saturating_add(bytes),
        }
    }

    /// `(received, sent)` for a PID; zeros if it has produced no traffic.
    pub fn get(&self, pid: u32) -> (u64, u64) {
        self.by_pid.get(&pid).copied().unwrap_or_default()
    }

    /// Forget PIDs that are no longer running, so the map doesn't grow for the life of the monitor.
    pub fn retain_live(&mut self, live: &HashSet<u32>) {
        self.by_pid.retain(|pid, _| live.contains(pid));
    }

    pub fn len(&self) -> usize {
        self.by_pid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_pid.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_payload_events_have_a_direction() {
        assert_eq!(direction_of(10), Some(Direction::Send));
        assert_eq!(direction_of(26), Some(Direction::Send));
        assert_eq!(direction_of(11), Some(Direction::Receive));
        assert_eq!(direction_of(27), Some(Direction::Receive));
        for other in [0, 12, 13, 14, 15, 16, 17, 18, 28, 255] {
            assert_eq!(direction_of(other), None, "opcode {other} moves no payload");
        }
    }

    #[test]
    fn bytes_accumulate_per_pid_and_direction() {
        let mut t = NetworkTotals::new();
        t.record(100, Direction::Receive, 1_000);
        t.record(100, Direction::Receive, 500);
        t.record(100, Direction::Send, 40);
        t.record(200, Direction::Send, 7);
        assert_eq!(t.get(100), (1_500, 40));
        assert_eq!(t.get(200), (0, 7));
    }

    #[test]
    fn an_unseen_pid_has_zero_totals_not_a_missing_value() {
        assert_eq!(NetworkTotals::new().get(42), (0, 0));
    }

    #[test]
    fn totals_saturate_instead_of_wrapping() {
        let mut t = NetworkTotals::new();
        t.record(1, Direction::Send, u64::MAX);
        t.record(1, Direction::Send, 5);
        assert_eq!(t.get(1).1, u64::MAX);
    }

    #[test]
    fn exited_pids_are_pruned() {
        let mut t = NetworkTotals::new();
        for pid in [1, 2, 3] {
            t.record(pid, Direction::Receive, 10);
        }
        t.retain_live(&HashSet::from([2]));
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(2), (10, 0));
        assert_eq!(t.get(1), (0, 0));
    }

    #[test]
    fn statuses_explain_themselves_and_only_active_is_active() {
        assert!(NetworkStatus::Active.is_active());
        for s in [
            NetworkStatus::RequiresAdmin,
            NetworkStatus::SessionInUse,
            NetworkStatus::Failed("boom".into()),
        ] {
            assert!(!s.is_active());
            assert!(s.describe().contains("unavailable"), "{}", s.describe());
        }
        assert!(
            NetworkStatus::RequiresAdmin
                .describe()
                .contains("administrator")
        );
        assert!(
            NetworkStatus::Failed("boom".into())
                .describe()
                .contains("boom")
        );
    }
}
