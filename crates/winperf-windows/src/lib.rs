//! Windows-specific collectors and integrations. All `unsafe` FFI is confined to this crate.

pub mod acl;
pub mod etw;
pub mod metrics;
pub mod processes;
pub mod registry;
pub mod signatures;
pub mod system;
pub mod version;

pub use etw::{EtwNetworkCollector, is_elevated, list_winperf_sessions};
pub use metrics::WindowsMetricsSource;
pub use processes::WindowsProcessSource;
pub use registry::WindowsRegistry;
pub use signatures::WinTrustVerifier;
pub use system::{DiskCounterPaths, WindowsSystemSource};
pub use version::WindowsVersionReader;

/// Crate name, used by front ends for diagnostics.
pub const NAME: &str = "winperf-windows";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(NAME, "winperf-windows");
    }
}
