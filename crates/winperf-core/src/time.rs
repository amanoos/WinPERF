//! Minimal time helpers (no external date crate needed yet).

const FILETIME_TO_UNIX_SECS: u64 = 11_644_473_600; // 1601-01-01 -> 1970-01-01
const TICKS_PER_SEC: u64 = 10_000_000; // FILETIME ticks are 100 ns

/// Days since 1970-01-01 -> (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Windows FILETIME (100 ns ticks since 1601-01-01 UTC) -> `YYYY-MM-DD HH:MM:SS` in UTC.
/// Returns `None` for values before the Unix epoch (including 0, i.e. "unknown").
pub fn filetime_to_utc_string(ft: u64) -> Option<String> {
    let secs = (ft / TICKS_PER_SEC).checked_sub(FILETIME_TO_UNIX_SECS)?;
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    Some(format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Unix milliseconds -> `YYYY-MM-DD HH:MM:SS` in UTC. `None` for negative values.
pub fn unix_millis_to_utc_string(ms: i64) -> Option<String> {
    let secs = u64::try_from(ms).ok()? / 1000;
    filetime_to_utc_string((secs + FILETIME_TO_UNIX_SECS) * TICKS_PER_SEC)
}

/// A span as a short human string: `42s`, `5m 03s`, `2h 05m`, `3d 04h`. Negative spans read `0s`.
pub fn format_span(ms: i64) -> String {
    let s = (ms / 1000).max(0);
    let (d, h, m, sec) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60, s % 60);
    if d > 0 {
        format!("{d}d {h:02}h")
    } else if h > 0 {
        format!("{h}h {m:02}m")
    } else if m > 0 {
        format!("{m}m {sec:02}s")
    } else {
        format!("{sec}s")
    }
}

/// Current time as Unix milliseconds (UTC).
pub fn unix_millis_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// Current time as `YYYY-MM-DD HH:MM:SS` in UTC.
pub fn utc_now_string() -> String {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    filetime_to_utc_string((unix + FILETIME_TO_UNIX_SECS) * TICKS_PER_SEC)
        .expect("current time is after 1970")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_well_formed_and_recent() {
        let s = utc_now_string();
        assert_eq!(s.len(), 19, "{s}");
        assert!(s.starts_with("20"), "{s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], " ");
    }

    #[test]
    fn unix_millis_convert_to_utc_text() {
        assert_eq!(
            unix_millis_to_utc_string(1_709_214_307_999).as_deref(),
            Some("2024-02-29 13:45:07")
        );
        assert_eq!(
            unix_millis_to_utc_string(0).as_deref(),
            Some("1970-01-01 00:00:00")
        );
        assert_eq!(unix_millis_to_utc_string(-1), None);
    }

    #[test]
    fn spans_read_naturally() {
        assert_eq!(format_span(-5), "0s");
        assert_eq!(format_span(42_000), "42s");
        assert_eq!(format_span(303_000), "5m 03s");
        assert_eq!(format_span(7_500_000), "2h 05m");
        assert_eq!(format_span(3 * 86_400_000 + 4 * 3_600_000), "3d 04h");
    }

    #[test]
    fn unix_epoch() {
        assert_eq!(
            filetime_to_utc_string(116_444_736_000_000_000).as_deref(),
            Some("1970-01-01 00:00:00")
        );
    }

    #[test]
    fn known_date_with_time() {
        // 2024-02-29 13:45:07 UTC = unix 1_709_214_307
        let ft = (1_709_214_307 + FILETIME_TO_UNIX_SECS) * TICKS_PER_SEC;
        assert_eq!(
            filetime_to_utc_string(ft).as_deref(),
            Some("2024-02-29 13:45:07")
        );
    }

    #[test]
    fn year_end_rollover() {
        let ft = (1_704_067_199 + FILETIME_TO_UNIX_SECS) * TICKS_PER_SEC; // 2023-12-31 23:59:59
        assert_eq!(
            filetime_to_utc_string(ft).as_deref(),
            Some("2023-12-31 23:59:59")
        );
    }

    #[test]
    fn zero_and_pre_epoch_are_none() {
        assert_eq!(filetime_to_utc_string(0), None);
        assert_eq!(filetime_to_utc_string(1_000), None);
    }
}
