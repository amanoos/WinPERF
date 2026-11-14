//! Installed-software discovery logic (PRD FR-001). Pure: raw registry data comes in through
//! [`RegistrySource`], so the filtering/deduplication rules are testable without Windows.

use crate::Classification;
use std::collections::HashMap;

/// A raw registry value we care about.
#[derive(Debug, Clone, PartialEq)]
pub enum RegValue {
    Str(String),
    Dword(u32),
}

/// One subkey under an `Uninstall` key, with its values.
#[derive(Debug, Clone, Default)]
pub struct RawEntry {
    /// Which hive/view it came from, e.g. `HKLM64`, `HKLM32`, `HKCU`.
    pub source: String,
    /// The subkey name (often a product GUID).
    pub key_name: String,
    pub values: HashMap<String, RegValue>,
}

impl RawEntry {
    fn text(&self, name: &str) -> Option<String> {
        match self.values.get(name) {
            Some(RegValue::Str(s)) => {
                let t = s.trim();
                (!t.is_empty()).then(|| t.to_string())
            }
            _ => None,
        }
    }

    fn dword(&self, name: &str) -> Option<u32> {
        match self.values.get(name) {
            Some(RegValue::Dword(d)) => Some(*d),
            _ => None,
        }
    }
}

/// Supplies raw Uninstall entries. The Windows implementation lives in `winperf-windows`.
pub trait RegistrySource {
    fn entries(&self) -> Vec<RawEntry>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstalledApp {
    pub name: String,
    pub publisher: Option<String>,
    pub version: Option<String>,
    /// ISO date `YYYY-MM-DD` when the registry holds a valid `YYYYMMDD`.
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub uninstall_command: Option<String>,
    /// Every registry location this product was found in (sorted, unique).
    pub registry_sources: Vec<String>,
    /// Publisher-level only; signature-based classification is added later (T6).
    pub classification: Classification,
}

/// `YYYYMMDD` -> `YYYY-MM-DD`, rejecting anything that isn't a plausible date.
fn parse_install_date(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (y, m, d): (u32, u32, u32) = (
        s[0..4].parse().ok()?,
        s[4..6].parse().ok()?,
        s[6..8].parse().ok()?,
    );
    ((1990..=2100).contains(&y) && (1..=12).contains(&m) && (1..=31).contains(&d))
        .then(|| format!("{y:04}-{m:02}-{d:02}"))
}

/// True for entries that are not user-facing products: updates/hotfixes, system components,
/// child entries of another product, or entries with no display name.
fn is_excluded(e: &RawEntry) -> bool {
    if e.text("DisplayName").is_none() {
        return true;
    }
    if e.dword("SystemComponent") == Some(1) {
        return true;
    }
    if e.text("ParentKeyName").is_some() || e.text("ParentDisplayName").is_some() {
        return true;
    }
    if let Some(rt) = e.text("ReleaseType") {
        let rt = rt.to_ascii_lowercase();
        if rt.contains("update") || rt.contains("hotfix") {
            return true;
        }
    }
    false
}

/// Discover installed applications: filter non-products, and merge the same product found in
/// several registry views (same name + version + publisher, case-insensitive).
pub fn discover(source: &dyn RegistrySource) -> Vec<InstalledApp> {
    let mut merged: HashMap<(String, String, String), InstalledApp> = HashMap::new();

    for e in source.entries().iter().filter(|e| !is_excluded(e)) {
        let name = e.text("DisplayName").expect("checked by is_excluded");
        let publisher = e.text("Publisher");
        let version = e.text("DisplayVersion");
        let key = (
            name.to_lowercase(),
            version.clone().unwrap_or_default().to_lowercase(),
            publisher.clone().unwrap_or_default().to_lowercase(),
        );
        let app = merged.entry(key).or_insert_with(|| InstalledApp {
            name,
            publisher,
            version,
            install_date: None,
            install_location: None,
            uninstall_command: None,
            registry_sources: vec![],
            classification: Classification::Unknown,
        });
        // First non-empty value wins; later duplicates only fill gaps.
        app.install_date = app
            .install_date
            .take()
            .or_else(|| e.text("InstallDate").and_then(|d| parse_install_date(&d)));
        app.install_location = app
            .install_location
            .take()
            .or_else(|| e.text("InstallLocation"));
        app.uninstall_command = app
            .uninstall_command
            .take()
            .or_else(|| e.text("UninstallString"));
        if !app.registry_sources.contains(&e.source) {
            app.registry_sources.push(e.source.clone());
        }
    }

    let mut apps: Vec<InstalledApp> = merged.into_values().collect();
    for a in &mut apps {
        a.registry_sources.sort();
    }
    apps.sort_by_key(|a| (a.name.to_lowercase(), a.version.clone().unwrap_or_default()));
    apps
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(Vec<RawEntry>);
    impl RegistrySource for Fixture {
        fn entries(&self) -> Vec<RawEntry> {
            self.0.clone()
        }
    }

    fn entry(source: &str, key: &str, vals: &[(&str, RegValue)]) -> RawEntry {
        RawEntry {
            source: source.into(),
            key_name: key.into(),
            values: vals
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        }
    }
    fn s(v: &str) -> RegValue {
        RegValue::Str(v.into())
    }

    #[test]
    fn reads_all_fr001_fields() {
        let src = Fixture(vec![entry(
            "HKLM64",
            "{A}",
            &[
                ("DisplayName", s("Example App")),
                ("Publisher", s("Example Corp")),
                ("DisplayVersion", s("1.2.3")),
                ("InstallDate", s("20240229")),
                ("InstallLocation", s("C:\\Program Files\\Example")),
                ("UninstallString", s("C:\\u.exe /x")),
            ],
        )]);
        let apps = discover(&src);
        assert_eq!(apps.len(), 1);
        let a = &apps[0];
        assert_eq!(a.name, "Example App");
        assert_eq!(a.publisher.as_deref(), Some("Example Corp"));
        assert_eq!(a.version.as_deref(), Some("1.2.3"));
        assert_eq!(a.install_date.as_deref(), Some("2024-02-29"));
        assert_eq!(
            a.install_location.as_deref(),
            Some("C:\\Program Files\\Example")
        );
        assert_eq!(a.uninstall_command.as_deref(), Some("C:\\u.exe /x"));
        assert_eq!(a.registry_sources, vec!["HKLM64"]);
        assert_eq!(a.classification, Classification::Unknown);
    }

    #[test]
    fn missing_optional_values_are_tolerated() {
        let apps = discover(&Fixture(vec![entry(
            "HKCU",
            "x",
            &[("DisplayName", s("Bare"))],
        )]));
        assert_eq!(apps.len(), 1);
        assert!(
            apps[0].publisher.is_none()
                && apps[0].version.is_none()
                && apps[0].install_date.is_none()
        );
    }

    #[test]
    fn excludes_non_products() {
        let src = Fixture(vec![
            entry("HKLM64", "nodisplay", &[("Publisher", s("X"))]),
            entry("HKLM64", "blank", &[("DisplayName", s("   "))]),
            entry(
                "HKLM64",
                "sys",
                &[
                    ("DisplayName", s("Sys Comp")),
                    ("SystemComponent", RegValue::Dword(1)),
                ],
            ),
            entry(
                "HKLM64",
                "kb",
                &[
                    ("DisplayName", s("Update for X (KB1)")),
                    ("ParentKeyName", s("OperatingSystem")),
                ],
            ),
            entry(
                "HKLM64",
                "hf",
                &[
                    ("DisplayName", s("Hotfix Y")),
                    ("ReleaseType", s("Security Update")),
                ],
            ),
            entry(
                "HKLM64",
                "keep",
                &[
                    ("DisplayName", s("Keep Me")),
                    ("SystemComponent", RegValue::Dword(0)),
                ],
            ),
        ]);
        let names: Vec<_> = discover(&src).into_iter().map(|a| a.name).collect();
        assert_eq!(names, vec!["Keep Me"]);
    }

    #[test]
    fn merges_same_product_across_views() {
        let v = [
            ("DisplayName", s("Tool")),
            ("DisplayVersion", s("2.0")),
            ("Publisher", s("Acme")),
        ];
        let mut with_loc = v.to_vec();
        with_loc.push(("InstallLocation", s("C:\\Tool")));
        let src = Fixture(vec![
            entry("HKLM32", "a", &v),
            entry("HKLM64", "b", &with_loc),
        ]);
        let apps = discover(&src);
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].registry_sources, vec!["HKLM32", "HKLM64"]);
        assert_eq!(apps[0].install_location.as_deref(), Some("C:\\Tool")); // gap filled from second
    }

    #[test]
    fn different_versions_stay_separate() {
        let mk = |ver: &str, key: &str| {
            entry(
                "HKLM64",
                key,
                &[("DisplayName", s("Runtime")), ("DisplayVersion", s(ver))],
            )
        };
        assert_eq!(
            discover(&Fixture(vec![mk("1.0", "a"), mk("2.0", "b")])).len(),
            2
        );
    }

    #[test]
    fn bad_install_dates_are_dropped() {
        for bad in [
            "",
            "2024-02-29",
            "20241399",
            "00000000",
            "2024022",
            "abcdefgh",
        ] {
            assert_eq!(parse_install_date(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_install_date("20231105").as_deref(),
            Some("2023-11-05")
        );
    }

    #[test]
    fn output_is_sorted_case_insensitively() {
        let src = Fixture(vec![
            entry("HKCU", "1", &[("DisplayName", s("zeta"))]),
            entry("HKCU", "2", &[("DisplayName", s("Alpha"))]),
            entry("HKCU", "3", &[("DisplayName", s("beta"))]),
        ]);
        let names: Vec<_> = discover(&src).into_iter().map(|a| a.name).collect();
        assert_eq!(names, vec!["Alpha", "beta", "zeta"]);
    }
}
