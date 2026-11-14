//! `winperf config show | path | init`, and loading the configuration for the other commands.

use std::io::{self, Write};
use std::path::Path;
use winperf_core::config::{Config, DEFAULT_CONFIG_TEMPLATE};
use winperf_storage::ConfigLocation;

/// Load the configuration from `location`.
///
/// * File present: parsed and validated; errors name the file and the problem.
/// * File missing at the default location: built-in defaults.
/// * File missing but the user named it (`--config`, `WINPERF_CONFIG`): an error, because silently
///   ignoring a mistyped path would run with settings the user didn't intend.
pub fn load(location: &ConfigLocation) -> Result<Config, String> {
    match std::fs::read_to_string(&location.path) {
        Ok(text) => {
            Config::from_toml_str(&text).map_err(|e| format!("{}: {e}", location.path.display()))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && !location.explicit => {
            Ok(Config::default())
        }
        Err(e) => Err(format!(
            "cannot read configuration file {}: {e}",
            location.path.display()
        )),
    }
}

/// Print the effective configuration, noting where it came from.
pub fn show(config: &Config, location: &ConfigLocation, out: &mut impl Write) -> io::Result<()> {
    let source = if location.path.exists() {
        format!("file {}", location.path.display())
    } else {
        "built-in defaults (no file found)".to_string()
    };
    writeln!(out, "# Effective configuration from {source}")?;
    out.write_all(config.to_toml_string().as_bytes())
}

/// Say where the configuration file is (or would be) and whether it exists.
pub fn path(location: &ConfigLocation, out: &mut impl Write) -> io::Result<()> {
    let state = if location.path.exists() {
        "exists"
    } else {
        "does not exist (defaults apply)"
    };
    writeln!(out, "{} ({state})", location.path.display())
}

/// Write the commented default configuration to `target`, creating folders as needed. An existing
/// file is never overwritten unless `force` is set.
pub fn init(target: &Path, force: bool, out: &mut impl Write) -> Result<(), String> {
    if target.exists() && !force {
        return Err(format!(
            "{} already exists; use --force to overwrite it",
            target.display()
        ));
    }
    if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    std::fs::write(target, DEFAULT_CONFIG_TEMPLATE)
        .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
    writeln!(out, "wrote default configuration to {}", target.display()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("winperf-cli-config-{}-{tag}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn loc(path: PathBuf, explicit: bool) -> ConfigLocation {
        ConfigLocation { path, explicit }
    }

    #[test]
    fn a_missing_default_config_means_defaults() {
        let s = Scratch::new("missing-default");
        let c = load(&loc(s.file("nope.toml"), false)).unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn a_missing_config_that_the_user_named_is_an_error() {
        let s = Scratch::new("missing-explicit");
        let err = load(&loc(s.file("typo.toml"), true)).unwrap_err();
        assert!(
            err.contains("cannot read configuration file") && err.contains("typo.toml"),
            "{err}"
        );
    }

    #[test]
    fn a_valid_file_is_loaded() {
        let s = Scratch::new("valid");
        std::fs::write(s.file("c.toml"), "[monitor]\ninterval_secs = 20\n").unwrap();
        let c = load(&loc(s.file("c.toml"), true)).unwrap();
        assert_eq!(c.monitor.interval_secs, 20);
    }

    #[test]
    fn errors_name_the_file_and_the_problem() {
        let s = Scratch::new("bad");
        std::fs::write(s.file("c.toml"), "[monitor]\ninterval_secs = 0\n").unwrap();
        let err = load(&loc(s.file("c.toml"), false)).unwrap_err();
        assert!(
            err.contains("c.toml") && err.contains("interval_secs"),
            "{err}"
        );

        std::fs::write(s.file("t.toml"), "[monitor]\nintervall = 5\n").unwrap();
        let err = load(&loc(s.file("t.toml"), false)).unwrap_err();
        assert!(err.contains("t.toml") && err.contains("intervall"), "{err}");
    }

    #[test]
    fn init_writes_the_commented_defaults_and_they_load_back_as_the_defaults() {
        let s = Scratch::new("init");
        let target = s.file("nested").join("config.toml");
        let mut out = Vec::new();
        init(&target, false, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("wrote default configuration")
        );

        let text = std::fs::read_to_string(&target).unwrap();
        assert!(
            text.contains("# Seconds between samples"),
            "comments are kept"
        );
        assert_eq!(load(&loc(target, true)).unwrap(), Config::default());
    }

    #[test]
    fn init_never_overwrites_without_force() {
        let s = Scratch::new("init-force");
        let target = s.file("config.toml");
        std::fs::write(&target, "[monitor]\ninterval_secs = 42\n").unwrap();

        let err = init(&target, false, &mut Vec::new()).unwrap_err();
        assert!(
            err.contains("already exists") && err.contains("--force"),
            "{err}"
        );
        assert!(
            std::fs::read_to_string(&target).unwrap().contains("42"),
            "file untouched"
        );

        init(&target, true, &mut Vec::new()).unwrap();
        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains("interval_secs = 5")
        );
    }

    #[test]
    fn show_reports_the_source_and_the_effective_values() {
        let s = Scratch::new("show");
        let file = s.file("c.toml");
        std::fs::write(&file, "[monitor]\ninterval_secs = 9\n").unwrap();
        let location = loc(file, true);
        let config = load(&location).unwrap();
        let mut out = Vec::new();
        show(&config, &location, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.starts_with("# Effective configuration from file"),
            "{text}"
        );
        assert!(text.contains("interval_secs = 9"), "{text}");
        assert!(
            text.contains("raw_samples_days = 2"),
            "defaults are filled in: {text}"
        );

        let mut out = Vec::new();
        show(
            &Config::default(),
            &loc(s.file("none.toml"), false),
            &mut out,
        )
        .unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("built-in defaults")
        );
    }

    #[test]
    fn path_says_whether_the_file_exists() {
        let s = Scratch::new("path");
        let mut out = Vec::new();
        path(&loc(s.file("a.toml"), false), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("does not exist"));

        std::fs::write(s.file("a.toml"), "").unwrap();
        let mut out = Vec::new();
        path(&loc(s.file("a.toml"), false), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("(exists)"));
    }
}
