//! `winperf inventory scan`: list installed applications.

use crate::export::{Format, apps_csv, apps_json};
use std::io::{self, Write};
use std::path::Path;
use winperf_core::inventory::{
    ExecutableInfo, InstalledApp, RegistrySource, SignatureStatus, SignatureVerifier,
    VersionReader, discover, inspect,
};
use winperf_core::time::utc_now_string;
use winperf_storage::{Database, StorageError};

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Render applications as a fixed-width text table.
pub fn format_table(apps: &[InstalledApp]) -> String {
    let mut out = format!(
        "{:<42} {:<16} {:<30} {:<11} {}\n",
        "NAME", "VERSION", "PUBLISHER", "CLASS", "SOURCE"
    );
    for a in apps {
        out.push_str(&format!(
            "{:<42} {:<16} {:<30} {:<11} {}\n",
            clip(&a.name, 42),
            clip(a.version.as_deref().unwrap_or("-"), 16),
            clip(a.publisher.as_deref().unwrap_or("-"), 30),
            a.classification,
            a.registry_sources.join(",")
        ));
    }
    out.push_str(&format!("\n{} applications\n", apps.len()));
    out
}

/// Render one executable's metadata and classification as `label: value` lines.
pub fn format_executable(info: &ExecutableInfo) -> String {
    let dash = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
    let signature = match &info.signature {
        SignatureStatus::Valid { signer } => format!("valid (signer: {signer})"),
        SignatureStatus::NotSigned => "not signed".into(),
        SignatureStatus::Invalid { code } => format!("invalid signature (0x{code:08X})"),
        SignatureStatus::Unreadable => "could not be read".into(),
    };
    format!(
        "path:             {}\nclassification:   {}\nsignature:        {}\nproduct:          {}\ndescription:      {}\noriginal name:    {}\nfile version:     {}\n",
        info.path.display(),
        info.classification,
        signature,
        dash(&info.version.product_name),
        dash(&info.version.file_description),
        dash(&info.version.original_filename),
        dash(&info.version.file_version),
    )
}

/// Inspect one executable (signature + version resources) and write the result.
pub fn inspect_exe(
    path: &Path,
    verifier: &dyn SignatureVerifier,
    versions: &dyn VersionReader,
    out: &mut impl Write,
) -> io::Result<()> {
    let info = inspect(path, verifier, versions);
    out.write_all(format_executable(&info).as_bytes())
}

/// Persist the application snapshot to the database at `db_path` (created and migrated if needed).
pub fn save_apps(apps: &[InstalledApp], db_path: &Path) -> Result<usize, StorageError> {
    let mut db = Database::open(db_path)?;
    db.save_installed_apps(apps, &utc_now_string())
}

/// Scan using the given registry source and write the result in `format`. With `save_to`, the
/// snapshot is also stored in the database; the confirmation goes to stderr so stdout stays pure
/// table/JSON/CSV.
pub fn scan(
    source: &dyn RegistrySource,
    format: Format,
    save_to: Option<&Path>,
    out: &mut impl Write,
) -> io::Result<()> {
    let apps = discover(source);
    match format {
        Format::Table => out.write_all(format_table(&apps).as_bytes())?,
        Format::Json => {
            out.write_all(apps_json(&apps).as_bytes())?;
            out.write_all(b"\n")?;
        }
        Format::Csv => out.write_all(apps_csv(&apps).as_bytes())?,
    }
    if let Some(path) = save_to {
        let saved = save_apps(&apps, path).map_err(io::Error::other)?;
        eprintln!("saved {saved} applications to {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use winperf_core::Classification;

    fn app(name: &str) -> InstalledApp {
        InstalledApp {
            name: name.into(),
            publisher: Some("Acme".into()),
            version: Some("1.0".into()),
            install_date: None,
            install_location: None,
            uninstall_command: None,
            registry_sources: vec!["HKLM64".into()],
            classification: Classification::Unknown,
        }
    }

    #[test]
    fn table_has_header_rows_and_count() {
        let t = format_table(&[app("One"), app("Two")]);
        assert!(t.starts_with("NAME"));
        assert!(t.contains("One") && t.contains("Two"));
        assert!(t.contains("2 applications"));
    }

    #[test]
    fn long_names_are_clipped() {
        let long = "x".repeat(100);
        let t = format_table(&[app(&long)]);
        assert!(!t.contains(&long));
        assert!(t.contains('…'));
    }

    #[test]
    fn executable_report_shows_classification_and_signer() {
        use std::path::PathBuf;
        use winperf_core::inventory::FileVersionInfo;
        let info = ExecutableInfo {
            path: PathBuf::from("C:\\x\\a.exe"),
            version: FileVersionInfo {
                product_name: Some("Thing".into()),
                ..Default::default()
            },
            signature: SignatureStatus::Valid {
                signer: "Acme".into(),
            },
            classification: Classification::ThirdPartyOfficial,
        };
        let t = format_executable(&info);
        assert!(t.contains("third_party"));
        assert!(t.contains("signer: Acme"));
        assert!(t.contains("Thing"));
        assert!(t.contains("description:      -"));
    }

    #[test]
    fn save_apps_persists_a_snapshot_that_reloads_identically() {
        let dir = std::env::temp_dir().join(format!("winperf-cli-save-{}", std::process::id()));
        let db_path = dir.join("nested").join("t.db");
        let apps = vec![app("Alpha"), app("Beta")];

        assert_eq!(save_apps(&apps, &db_path).unwrap(), 2);
        // A second save of fewer apps replaces the snapshot.
        assert_eq!(save_apps(&apps[..1], &db_path).unwrap(), 1);

        let stored = Database::open(&db_path)
            .unwrap()
            .load_installed_apps()
            .unwrap();
        assert_eq!(stored, apps[..1].to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_fields_show_a_dash() {
        let mut a = app("Bare");
        a.publisher = None;
        a.version = None;
        assert!(format_table(&[a]).contains(" - "));
    }
}
