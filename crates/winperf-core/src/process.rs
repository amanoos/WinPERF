//! Process identity. Windows reuses PIDs, so a PID alone is never an identifier (PRD 10.1).

use std::fmt;

/// Identifies one *instance* of a process: PID plus its creation time.
///
/// `start_time` is the raw Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as returned by
/// `GetProcessTimes`. Two processes that reuse the same PID have different start times.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time: u64,
}

impl ProcessKey {
    pub fn new(pid: u32, start_time: u64) -> Self {
        Self { pid, start_time }
    }
}

impl fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.pid, self.start_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn same_pid_different_start_is_a_different_instance() {
        let first = ProcessKey::new(1234, 133_000_000_000_000_000);
        let reused = ProcessKey::new(1234, 133_000_000_500_000_000);
        assert_ne!(first, reused);
        let set: HashSet<_> = [first, reused].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn same_pid_and_start_is_the_same_instance() {
        assert_eq!(ProcessKey::new(7, 99), ProcessKey::new(7, 99));
    }

    #[test]
    fn display_includes_both_parts() {
        assert_eq!(ProcessKey::new(7, 99).to_string(), "7@99");
    }
}
