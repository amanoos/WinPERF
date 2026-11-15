//! Human-readable numbers for anomaly events, shared by the explanations written at detection
//! time and by the command-line views.

use super::AnomalyKind;
use crate::config::Resource;

/// Bytes with a binary unit: `512 B`, `1.5 KiB`, `27.4 GiB`.
pub fn bytes(v: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let sign = if v < 0.0 { "-" } else { "" };
    let mut v = v.abs();
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{sign}{v:.0} B")
    } else {
        format!("{sign}{v:.1} {}", UNITS[unit])
    }
}

/// A value of `resource` in the unit its kind of event uses: percent for CPU, bytes for memory
/// levels, bytes per hour for memory growth, bytes per second for disk and network.
pub fn value(resource: Resource, kind: AnomalyKind, v: f64) -> String {
    match (resource, kind) {
        (Resource::Cpu, _) => format!("{v:.1}%"),
        (Resource::Memory, AnomalyKind::MemoryGrowth) => format!("{}/h", bytes(v)),
        (Resource::Memory, AnomalyKind::Deviation) => bytes(v),
        (Resource::Disk | Resource::Network, _) => format!("{}/s", bytes(v)),
    }
}

/// A baseline window as text: `1 h`, `24 h`, `7 d`.
pub fn window_label(hours: u32) -> String {
    if hours > 24 && hours.is_multiple_of(24) {
        format!("{} d", hours / 24)
    } else {
        format!("{hours} h")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_scale_to_a_readable_unit() {
        assert_eq!(bytes(0.0), "0 B");
        assert_eq!(bytes(512.0), "512 B");
        assert_eq!(bytes(1536.0), "1.5 KiB");
        assert_eq!(bytes(100.0 * 1024.0 * 1024.0), "100.0 MiB");
        assert_eq!(bytes(27.4 * 1024.0 * 1024.0 * 1024.0), "27.4 GiB");
        assert_eq!(bytes(-2048.0), "-2.0 KiB");
    }

    #[test]
    fn each_resource_and_kind_gets_its_own_unit() {
        let mib = 1024.0 * 1024.0;
        let dev = AnomalyKind::Deviation;
        assert_eq!(value(Resource::Cpu, dev, 72.0), "72.0%");
        assert_eq!(value(Resource::Memory, dev, 3.0 * mib), "3.0 MiB");
        assert_eq!(
            value(Resource::Memory, AnomalyKind::MemoryGrowth, 3.0 * mib),
            "3.0 MiB/h"
        );
        assert_eq!(value(Resource::Disk, dev, 2.0 * mib), "2.0 MiB/s");
        assert_eq!(value(Resource::Network, dev, 512.0), "512 B/s");
    }

    #[test]
    fn windows_read_naturally() {
        assert_eq!(window_label(1), "1 h");
        assert_eq!(window_label(24), "24 h");
        assert_eq!(window_label(168), "7 d");
    }
}
