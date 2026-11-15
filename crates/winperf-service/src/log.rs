//! A small append-only log file for the service. One line per event, time-stamped in UTC. The
//! file is moved aside to `<name>.old` when it passes 5 MiB, so it never grows without bound.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use winperf_core::time::unix_millis_now;

const MAX_BYTES: u64 = 5 * 1024 * 1024;

pub struct Log {
    file: Mutex<Option<File>>,
}

impl Log {
    /// Open (creating the folder) the log at `path`. A log that cannot be opened is not fatal:
    /// the service still runs, it just says nothing.
    pub fn open(path: &Path) -> Self {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        if fs::metadata(path).is_ok_and(|m| m.len() > MAX_BYTES) {
            let _ = fs::rename(path, path.with_extension("log.old"));
        }
        let file = OpenOptions::new().create(true).append(true).open(path).ok();
        Self {
            file: Mutex::new(file),
        }
    }

    pub fn line(&self, text: &str) {
        if let Ok(mut guard) = self.file.lock()
            && let Some(f) = guard.as_mut()
        {
            let _ = writeln!(f, "{} {text}", stamp(unix_millis_now()));
        }
    }
}

/// `YYYY-MM-DD HH:MM:SS` in UTC.
fn stamp(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("winperf-svc-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn timestamps_are_utc_dates() {
        assert_eq!(stamp(0), "1970-01-01 00:00:00");
        assert_eq!(stamp(1_700_000_000_000), "2023-11-14 22:13:20");
        assert_eq!(stamp(951_782_400_000), "2000-02-29 00:00:00");
    }

    #[test]
    fn lines_are_appended_with_a_timestamp_and_the_folder_is_created() {
        let dir = temp_dir("log");
        let path = dir.join("logs").join("service.log");
        let log = Log::open(&path);
        log.line("first");
        log.line("second");
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("first") && lines[1].ends_with("second"));
        assert!(lines[0].starts_with("20"), "{}", lines[0]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_big_log_is_moved_aside_on_open() {
        let dir = temp_dir("rotate");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("service.log");
        fs::write(&path, vec![0u8; (MAX_BYTES + 1) as usize]).unwrap();
        let log = Log::open(&path);
        log.line("fresh");
        assert!(dir.join("service.log.old").exists());
        assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
