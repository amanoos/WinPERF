//! Hiding secrets in process command lines (T35, NFR-003).
//!
//! Programs are often started with a password or token on the command line, and anyone who can
//! read the process list can read it. WinPerf never stores command lines; where it shows one (the
//! `process list --cmdline` output) the secret parts are replaced with `***` first.
//!
//! What is recognised: an option or `key=value` whose name says it is secret (`--password x`,
//! `--password=x`, `/pwd:x`, `DB_PASSWORD=x`, `?token=x&...`), a value after `Bearer` or an
//! `Authorization:` header, and the password in `scheme://user:password@host`. A name counts when
//! it is, or ends with, one of a short list of secret words; the list is deliberately about the
//! name, never about guessing which values look like secrets.

/// What replaces a secret.
pub const MASK: &str = "***";

/// Names that are secrets when they are the whole name (`pwd`, `auth`).
const EXACT: [&str; 6] = ["pwd", "pass", "auth", "cred", "creds", "sig"];
/// Names that are secrets when the name ends with them (`db-password`, `GITHUB_TOKEN`).
const SUFFIXES: [&str; 12] = [
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "credential",
    "credentials",
    "authorization",
    "sessionid",
];

/// The name without dashes, slashes, underscores, dots and quotes, in lower case: `--API_Key` is
/// `apikey`.
fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | '/' | '"' | '\''))
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_secret_name(name: &str) -> bool {
    let n = normalize(name);
    !n.is_empty() && (EXACT.contains(&n.as_str()) || SUFFIXES.iter().any(|s| n.ends_with(s)))
}

/// Split a command line into runs of blanks and runs of non-blanks (blanks inside double quotes do
/// not split), keeping everything so the line can be put back together exactly.
fn split(line: &str) -> Vec<(bool, String)> {
    let mut out: Vec<(bool, String)> = Vec::new(); // (is_blank_run, text)
    let mut quoted = false;
    for c in line.chars() {
        if c == '"' {
            quoted = !quoted;
        }
        let blank = c.is_whitespace() && !quoted;
        match out.last_mut() {
            Some((b, text)) if *b == blank => text.push(c),
            _ => out.push((blank, c.to_string())),
        }
    }
    out
}

/// Mask the value of one `name<sep>value` token when the name is secret. `None` when it is not.
fn mask_assignment(token: &str) -> Option<String> {
    let at = token.find(['=', ':'])?;
    let (name, rest) = token.split_at(at);
    // `http://host` and `C:\path` are not assignments.
    if rest.starts_with(":/") || rest.starts_with(":\\") || name.len() <= 1 {
        return None;
    }
    if rest.len() > 1 && is_secret_name(name) {
        Some(format!("{name}{}{MASK}", &rest[..1]))
    } else {
        None
    }
}

/// Mask the password of `scheme://user:password@host`.
fn mask_url_password(token: &str) -> Option<String> {
    let scheme_end = token.find("://")? + 3;
    let rest = &token[scheme_end..];
    let at = rest.find('@')?;
    let userinfo = &rest[..at];
    let colon = userinfo.find(':')?;
    if userinfo.contains('/') {
        return None;
    }
    Some(format!(
        "{}{}:{MASK}{}",
        &token[..scheme_end],
        &userinfo[..colon],
        &rest[at..]
    ))
}

/// Mask `?key=value&key2=value2` pairs inside a token whose name is secret.
fn mask_query(token: &str) -> Option<String> {
    let q = token.find('?')?;
    let (head, query) = token.split_at(q + 1);
    let mut changed = false;
    let parts: Vec<String> = query
        .split('&')
        .map(|pair| match mask_assignment(pair) {
            Some(masked) => {
                changed = true;
                masked
            }
            None => pair.to_string(),
        })
        .collect();
    changed.then(|| format!("{head}{}", parts.join("&")))
}

/// The command line with its secrets replaced by `***`.
pub fn redact_command_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    // How many of the next non-blank tokens are still to be hidden.
    let mut hide_next = 0u8;
    for (blank, text) in split(line) {
        if blank {
            out.push_str(&text);
            continue;
        }
        if hide_next > 0 {
            hide_next -= 1;
            // A scheme word between a header name and its value stays: `Authorization: Bearer x`.
            if hide_next > 0 && matches!(normalize(&text).as_str(), "bearer" | "basic") {
                out.push_str(&text);
            } else {
                hide_next = 0;
                out.push_str(MASK);
            }
            continue;
        }
        let bare = text.trim_end_matches([':', '=']);
        let word = normalize(&text);
        if let Some(masked) = mask_assignment(&text)
            .or_else(|| mask_url_password(&text))
            .or_else(|| mask_query(&text))
        {
            out.push_str(&masked);
        } else if word == "bearer" || word == "basic" {
            out.push_str(&text);
            hide_next = 1;
        } else if (text.starts_with('-') || text.starts_with('/') || text.ends_with(':'))
            && is_secret_name(bare)
        {
            // `--password secret`, `/pwd secret`, `Authorization: Bearer secret`.
            out.push_str(&text);
            hide_next = if normalize(bare).ends_with("authorization") {
                2
            } else {
                1
            };
        } else {
            out.push_str(&text);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> String {
        redact_command_line(s)
    }

    #[test]
    fn secret_options_lose_their_values_in_every_spelling() {
        assert_eq!(
            r("app.exe --password hunter2 --verbose"),
            "app.exe --password *** --verbose"
        );
        assert_eq!(r("app.exe --password=hunter2"), "app.exe --password=***");
        assert_eq!(r(r"app.exe /pwd:hunter2 /q"), r"app.exe /pwd:*** /q");
        assert_eq!(r("tool --api-key abc123 run"), "tool --api-key *** run");
        assert_eq!(r("tool --API_KEY=abc123"), "tool --API_KEY=***");
        assert_eq!(
            r("DB_PASSWORD=x node server.js"),
            "DB_PASSWORD=*** node server.js"
        );
        assert_eq!(r("gh --github-token=ghp_abc"), "gh --github-token=***");
        assert_eq!(
            r("x --client-secret s3cr3t --id 5"),
            "x --client-secret *** --id 5"
        );
    }

    #[test]
    fn quoted_secrets_with_spaces_are_hidden_whole() {
        assert_eq!(
            r(r#"app.exe --password "two words" --user bob"#),
            "app.exe --password *** --user bob"
        );
        assert_eq!(r(r#"app.exe --token="a b c" ok"#), "app.exe --token=*** ok");
    }

    #[test]
    fn headers_urls_and_query_strings_are_handled() {
        assert_eq!(
            r("curl -H Authorization: Bearer abc.def.ghi https://x"),
            "curl -H Authorization: Bearer *** https://x"
        );
        assert_eq!(r("curl Bearer abc"), "curl Bearer ***");
        assert_eq!(
            r("git clone https://bob:hunter2@host/repo.git"),
            "git clone https://bob:***@host/repo.git"
        );
        assert_eq!(
            r("curl https://h/x?id=5&token=abc&mode=1"),
            "curl https://h/x?id=5&token=***&mode=1"
        );
    }

    #[test]
    fn ordinary_command_lines_are_not_touched() {
        for line in [
            r#""C:\Program Files\App\app.exe" --config C:\x\a.toml --port 8080"#,
            "chrome.exe --type=renderer --user-data-dir=C:\\Users\\a\\b",
            "node server.js --keyboard layout",
            "git commit -m \"fix the password dialog\"",
            "https://example.com/path?page=2",
            "",
        ] {
            assert_eq!(r(line), line, "{line}");
        }
    }

    #[test]
    fn spacing_and_quotes_survive() {
        assert_eq!(r("a   --pass   x   b"), "a   --pass   ***   b");
        assert_eq!(r("  lead  trail  "), "  lead  trail  ");
    }
}
