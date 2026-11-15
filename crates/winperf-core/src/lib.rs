//! WinPerf core engine: pure logic with no Windows or UI dependencies.

pub mod anomaly;
pub mod classification;
pub mod config;
pub mod engine;
pub mod inventory;
pub mod metric;
pub mod network;
pub mod process;
pub mod profiler;
pub mod sampling;
pub mod system;
pub mod time;

pub use classification::Classification;
pub use metric::Metric;
pub use process::ProcessKey;

/// Crate name, used by front ends for diagnostics.
pub const NAME: &str = "winperf-core";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(NAME, "winperf-core");
    }
}
