//! Saving a changed [`Config`] into an existing configuration file without destroying it.
//!
//! Serialising a `Config` from scratch would throw away the comments (and any commented-out
//! settings) that make the file self-explanatory. Instead the existing text is parsed as an editable
//! document, every setting that differs is updated in place, settings that are no longer set are
//! removed, and everything else (comments, order, spacing) is left as it was.

use crate::config::{Config, ConfigError};
use toml_edit::{DocumentMut, Item, Table, Value};

/// `existing` with its settings changed to match `config`. `existing` must be valid TOML (it may
/// be empty); the result parses back to exactly `config`.
pub fn apply(existing: &str, config: &Config) -> Result<String, ConfigError> {
    config.validate()?;
    let mut doc: DocumentMut = existing
        .parse()
        .map_err(|e: toml_edit::TomlError| ConfigError::Parse(e.to_string()))?;
    let wanted: DocumentMut = config
        .to_toml_string()
        .parse()
        .map_err(|e: toml_edit::TomlError| ConfigError::Parse(e.to_string()))?;
    sync(doc.as_table_mut(), wanted.as_table());
    Ok(doc.to_string())
}

/// Whether two values say the same thing, ignoring how they are laid out (an array written on one
/// line equals the same array written over several).
fn same_value(a: &Value, b: &Value) -> bool {
    match (a.as_array(), b.as_array()) {
        (Some(x), Some(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y.iter())
                    .all(|(p, q)| p.to_string().trim() == q.to_string().trim())
        }
        _ => a.to_string().trim() == b.to_string().trim(),
    }
}

/// Make `have` hold exactly the settings of `want`, keeping what already matches untouched.
fn sync(have: &mut Table, want: &Table) {
    // Settings that are no longer set (an optional override that was cleared).
    let stale: Vec<String> = have
        .iter()
        .map(|(k, _)| k.to_string())
        .filter(|k| !want.contains_key(k))
        .collect();
    for key in stale {
        have.remove(&key);
    }
    for (key, wanted) in want.iter() {
        match wanted {
            Item::Table(wanted_table) => {
                if !matches!(have.get(key), Some(Item::Table(_))) {
                    let mut created = Table::new();
                    created.set_implicit(false);
                    have.insert(key, Item::Table(created));
                }
                if let Some(Item::Table(t)) = have.get_mut(key) {
                    sync(t, wanted_table);
                }
            }
            Item::Value(new) => {
                let same = have
                    .get(key)
                    .and_then(Item::as_value)
                    .is_some_and(|old| same_value(old, new));
                if !same {
                    // Keep the key's own comments and, when the key existed, its trailing comment.
                    let trailing = have
                        .get(key)
                        .and_then(Item::as_value)
                        .and_then(|v| v.decor().suffix().cloned());
                    let mut value = new.clone();
                    if let Some(array) = value.as_array_mut() {
                        array.fmt(); // one line, like `[1, 24, 168]`
                    }
                    value.decor_mut().clear();
                    if let Some(suffix) = trailing {
                        value.decor_mut().set_suffix(suffix);
                    }
                    match have.get_mut(key) {
                        // Replacing the item in place keeps the comments written above the key.
                        Some(item) => *item = Item::Value(value),
                        None => {
                            have.insert(key, Item::Value(value));
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_CONFIG_TEMPLATE, Sensitivity};

    fn edited(f: impl FnOnce(&mut Config)) -> (Config, String) {
        let mut config = Config::default();
        f(&mut config);
        let text = apply(DEFAULT_CONFIG_TEMPLATE, &config).unwrap();
        (config, text)
    }

    #[test]
    fn the_result_parses_back_to_exactly_the_edited_config() {
        let (config, text) = edited(|c| {
            c.monitor.interval_secs = 10;
            c.monitor.network = false;
            c.baseline.windows_hours = vec![2, 12, 72];
            c.retention.raw_samples_days = 3;
            c.detection.sensitivity = Sensitivity::High;
            c.detection.cpu = Some(Sensitivity::Low);
            c.baseline.confidence.high_minutes = 2000;
        });
        assert_eq!(Config::from_toml_str(&text).unwrap(), config, "{text}");
    }

    #[test]
    fn comments_and_untouched_settings_survive() {
        let (_, text) = edited(|c| c.monitor.interval_secs = 10);
        assert!(text.contains("interval_secs = 10"), "{text}");
        assert!(
            text.contains("# Seconds between samples (1-3600)."),
            "{text}"
        );
        assert!(text.contains("# WinPerf configuration."), "{text}");
        assert!(
            text.contains("# cpu = \"high\""),
            "commented example kept: {text}"
        );
        assert!(text.contains("signatures = true"), "{text}");
        assert!(text.contains("[baseline.confidence]"), "{text}");
    }

    #[test]
    fn an_unchanged_config_leaves_the_file_byte_for_byte_the_same() {
        let text = apply(DEFAULT_CONFIG_TEMPLATE, &Config::default()).unwrap();
        assert_eq!(text, DEFAULT_CONFIG_TEMPLATE);
    }

    #[test]
    fn a_trailing_comment_on_a_changed_setting_is_kept() {
        let existing = "[monitor]\ninterval_secs = 5 # how often\n";
        let mut c = Config::default();
        c.monitor.interval_secs = 9;
        let text = apply(existing, &c).unwrap();
        assert!(text.contains("interval_secs = 9 # how often"), "{text}");
        assert_eq!(
            Config::from_toml_str(&text).unwrap().monitor.interval_secs,
            9
        );
    }

    #[test]
    fn a_cleared_override_is_removed_and_a_new_one_added() {
        let existing = "[detection]\nsensitivity = \"normal\"\ncpu = \"high\"\n";
        let mut c = Config::from_toml_str(existing).unwrap();
        c.detection.cpu = None;
        c.detection.disk = Some(Sensitivity::Low);
        let text = apply(existing, &c).unwrap();
        assert!(!text.contains("cpu"), "{text}");
        assert!(text.contains("disk = \"low\""), "{text}");
        assert_eq!(Config::from_toml_str(&text).unwrap(), c);
    }

    #[test]
    fn an_empty_or_partial_file_gains_the_settings_that_differ() {
        let mut c = Config::default();
        c.monitor.interval_secs = 7;
        let text = apply("", &c).unwrap();
        assert_eq!(Config::from_toml_str(&text).unwrap(), c, "{text}");

        let partial = "[retention]\nanomaly_days = 30\n";
        let mut c = Config::from_toml_str(partial).unwrap();
        c.retention.anomaly_days = 60;
        c.monitor.interval_secs = 8;
        let text = apply(partial, &c).unwrap();
        assert_eq!(Config::from_toml_str(&text).unwrap(), c, "{text}");
        assert!(text.contains("anomaly_days = 60"), "{text}");
    }

    #[test]
    fn a_database_path_round_trips() {
        let mut c = Config::default();
        c.storage.database = Some(r"D:\data\winperf.db".into());
        let text = apply(DEFAULT_CONFIG_TEMPLATE, &c).unwrap();
        assert_eq!(Config::from_toml_str(&text).unwrap(), c, "{text}");
        c.storage.database = None;
        let again = apply(&text, &c).unwrap();
        assert_eq!(Config::from_toml_str(&again).unwrap(), c, "{again}");
    }

    #[test]
    fn an_invalid_config_is_refused_and_broken_text_is_a_parse_error() {
        let mut bad = Config::default();
        bad.monitor.interval_secs = 0;
        assert!(matches!(
            apply(DEFAULT_CONFIG_TEMPLATE, &bad),
            Err(ConfigError::Invalid(_))
        ));
        assert!(matches!(
            apply("[monitor\nbroken", &Config::default()),
            Err(ConfigError::Parse(_))
        ));
    }
}
