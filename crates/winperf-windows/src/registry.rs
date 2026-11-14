//! Reads the Windows `Uninstall` registry keys (PRD FR-001) via the safe `winreg` crate.
//! Missing keys, denied subkeys and odd value types are skipped, never fatal.

use winperf_core::inventory::{RawEntry, RegValue, RegistrySource};
use winreg::RegKey;
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

const STRING_VALUES: &[&str] = &[
    "DisplayName",
    "Publisher",
    "DisplayVersion",
    "InstallLocation",
    "UninstallString",
    "ParentKeyName",
    "ParentDisplayName",
    "ReleaseType",
];

/// Reads installed-software entries from the machine and current-user hives (64- and 32-bit views).
pub struct WindowsRegistry;

fn read_view(label: &str, root: &RegKey, wow_flag: u32, out: &mut Vec<RawEntry>) {
    let Ok(uninstall) = root.open_subkey_with_flags(UNINSTALL, KEY_READ | wow_flag) else {
        return; // hive/view absent or unreadable
    };
    for key_name in uninstall.enum_keys().flatten() {
        let Ok(sub) = uninstall.open_subkey_with_flags(&key_name, KEY_READ) else {
            continue; // access denied or key vanished
        };
        let mut entry = RawEntry {
            source: label.to_string(),
            key_name,
            ..Default::default()
        };
        for name in STRING_VALUES {
            if let Ok(v) = sub.get_value::<String, _>(name) {
                entry.values.insert((*name).to_string(), RegValue::Str(v));
            }
        }
        // InstallDate is usually a string (YYYYMMDD) but some installers write a DWORD.
        if let Ok(v) = sub.get_value::<String, _>("InstallDate") {
            entry.values.insert("InstallDate".into(), RegValue::Str(v));
        } else if let Ok(v) = sub.get_value::<u32, _>("InstallDate") {
            entry
                .values
                .insert("InstallDate".into(), RegValue::Str(v.to_string()));
        }
        if let Ok(v) = sub.get_value::<u32, _>("SystemComponent") {
            entry
                .values
                .insert("SystemComponent".into(), RegValue::Dword(v));
        }
        out.push(entry);
    }
}

impl RegistrySource for WindowsRegistry {
    fn entries(&self) -> Vec<RawEntry> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let mut out = Vec::new();
        read_view("HKLM64", &hklm, KEY_WOW64_64KEY, &mut out);
        read_view("HKLM32", &hklm, KEY_WOW64_32KEY, &mut out);
        // HKCU is not WOW64-redirected, so one default-view read is enough.
        read_view("HKCU", &hkcu, 0, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winperf_core::inventory::discover;

    /// Live smoke test against this machine's registry: should find something and never panic.
    #[test]
    fn live_registry_yields_applications() {
        let apps = discover(&WindowsRegistry);
        assert!(
            !apps.is_empty(),
            "expected at least one installed application"
        );
        assert!(apps.iter().all(|a| !a.name.trim().is_empty()));
    }

    #[test]
    fn repeated_scans_are_consistent() {
        let a = discover(&WindowsRegistry);
        let b = discover(&WindowsRegistry);
        assert_eq!(a, b);
    }
}
