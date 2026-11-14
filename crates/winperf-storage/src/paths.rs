//! Where the database and the configuration file live.
//!
//! Defaults are machine-wide (`%ProgramData%\WinPerf\...`) so the LocalSystem service and
//! interactive users share one database and one config. Precedence, highest first:
//!
//! * database: `--db` flag, then the `WINPERF_DB` variable, then `storage.database` from the
//!   configuration file, then `%ProgramData%\WinPerf\winperf.db`;
//! * config file: `--config` flag, then the `WINPERF_CONFIG` variable, then
//!   `%ProgramData%\WinPerf\config.toml`.
//!
//! (Restricting access to these files is a hardening task, T35.)

use std::path::{Path, PathBuf};

pub const ENV_DB: &str = "WINPERF_DB";
pub const ENV_CONFIG: &str = "WINPERF_CONFIG";

fn program_data_dir(get_env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    let base = get_env("ProgramData")
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("WinPerf")
}

fn non_empty(get_env: &dyn Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get_env(key).filter(|v| !v.trim().is_empty())
}

/// The database path from the environment and the config file (no command-line flag).
/// `WINPERF_DB` beats the config file, which beats the default location.
pub fn default_db_path(
    get_env: &dyn Fn(&str) -> Option<String>,
    config_db: Option<&Path>,
) -> PathBuf {
    if let Some(explicit) = non_empty(get_env, ENV_DB) {
        return PathBuf::from(explicit);
    }
    if let Some(from_config) = config_db {
        return from_config.to_path_buf();
    }
    program_data_dir(get_env).join("winperf.db")
}

/// An explicit command-line path wins; otherwise the environment, config file and default apply.
pub fn resolve_db_path(cli_override: Option<PathBuf>, config_db: Option<&Path>) -> PathBuf {
    cli_override.unwrap_or_else(|| default_db_path(&|k| std::env::var(k).ok(), config_db))
}

/// Where the configuration file is, and whether the user chose that location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLocation {
    pub path: PathBuf,
    /// True when named via `--config` or `WINPERF_CONFIG`: a missing file is then an error.
    /// False for the default location, where a missing file just means "use the defaults".
    pub explicit: bool,
}

pub fn config_location(
    cli_override: Option<PathBuf>,
    get_env: &dyn Fn(&str) -> Option<String>,
) -> ConfigLocation {
    if let Some(path) = cli_override {
        return ConfigLocation {
            path,
            explicit: true,
        };
    }
    if let Some(from_env) = non_empty(get_env, ENV_CONFIG) {
        return ConfigLocation {
            path: PathBuf::from(from_env),
            explicit: true,
        };
    }
    ConfigLocation {
        path: program_data_dir(get_env).join("config.toml"),
        explicit: false,
    }
}

/// [`config_location`] using the real environment.
pub fn resolve_config_location(cli_override: Option<PathBuf>) -> ConfigLocation {
    config_location(cli_override, &|k| std::env::var(k).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn explicit_env_var_wins() {
        let e = env(&[(ENV_DB, r"D:\data\x.db"), ("ProgramData", r"C:\PD")]);
        assert_eq!(default_db_path(&e, None), PathBuf::from(r"D:\data\x.db"));
    }

    #[test]
    fn defaults_to_program_data() {
        let e = env(&[("ProgramData", r"C:\PD")]);
        assert_eq!(
            default_db_path(&e, None),
            PathBuf::from(r"C:\PD").join("WinPerf").join("winperf.db")
        );
    }

    #[test]
    fn blank_values_are_ignored_and_a_fallback_is_used() {
        let e = env(&[(ENV_DB, "  "), ("ProgramData", "")]);
        assert_eq!(
            default_db_path(&e, None),
            PathBuf::from(r"C:\ProgramData")
                .join("WinPerf")
                .join("winperf.db")
        );
    }

    #[test]
    fn the_config_file_sits_between_the_environment_and_the_default() {
        let from_config = Path::new(r"E:\cfg\wp.db");
        let plain = env(&[("ProgramData", r"C:\PD")]);
        assert_eq!(
            default_db_path(&plain, Some(from_config)),
            PathBuf::from(r"E:\cfg\wp.db"),
            "config beats the default"
        );
        let with_env = env(&[(ENV_DB, r"D:\env.db"), ("ProgramData", r"C:\PD")]);
        assert_eq!(
            default_db_path(&with_env, Some(from_config)),
            PathBuf::from(r"D:\env.db"),
            "environment beats config"
        );
    }

    #[test]
    fn cli_override_beats_everything() {
        assert_eq!(
            resolve_db_path(
                Some(PathBuf::from(r"E:\mine.db")),
                Some(Path::new(r"E:\cfg.db"))
            ),
            PathBuf::from(r"E:\mine.db")
        );
    }

    #[test]
    fn the_config_file_defaults_to_program_data_and_is_not_explicit() {
        let loc = config_location(None, &env(&[("ProgramData", r"C:\PD")]));
        assert_eq!(
            loc.path,
            PathBuf::from(r"C:\PD").join("WinPerf").join("config.toml")
        );
        assert!(
            !loc.explicit,
            "a missing default config just means defaults"
        );
    }

    #[test]
    fn a_config_named_by_flag_or_variable_is_explicit_and_the_flag_wins() {
        let e = env(&[(ENV_CONFIG, r"D:\env.toml")]);
        let from_env = config_location(None, &e);
        assert_eq!(
            (from_env.path, from_env.explicit),
            (PathBuf::from(r"D:\env.toml"), true)
        );

        let from_flag = config_location(Some(PathBuf::from(r"E:\flag.toml")), &e);
        assert_eq!(
            (from_flag.path, from_flag.explicit),
            (PathBuf::from(r"E:\flag.toml"), true)
        );
    }

    #[test]
    fn a_blank_config_variable_is_ignored() {
        let loc = config_location(None, &env(&[(ENV_CONFIG, " "), ("ProgramData", r"C:\PD")]));
        assert!(!loc.explicit);
    }
}
