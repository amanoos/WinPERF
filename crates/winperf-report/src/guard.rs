//! Checks every request before it reaches a handler, and adds the security headers to every
//! response.
//!
//! * **Host check** (loopback binds): only `localhost`, `127.0.0.1` and `[::1]` are accepted as the
//!   `Host`, so a web page on another site cannot reach the report through a DNS name that points
//!   at 127.0.0.1 (DNS rebinding).
//! * **Token**: when configured, every data request (`/api`) must send it, as `Authorization: Bearer <token>` or
//!   a `token` query parameter. The comparison takes the same time whatever the guess.
//! * **Headers**: no caching, no sniffing, no framing, and a policy that allows nothing but this
//!   server's own files, so the page can never pull in anything from elsewhere.

use crate::Shared;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Compare without stopping at the first difference.
fn same_token(given: &str, wanted: &str) -> bool {
    let (a, b) = (given.as_bytes(), wanted.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// The host name of a `Host` header value, without the port: `localhost:8099` is `localhost`,
/// `[::1]:8099` is `[::1]`.
fn host_name(value: &str) -> &str {
    let value = value.trim();
    if value.starts_with('[') {
        value.find(']').map_or(value, |end| &value[..=end])
    } else {
        value.split(':').next().unwrap_or(value)
    }
}

fn local_host(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "[::1]"
    )
}

/// The `token` parameter of a query string, if present.
fn query_token(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
}

fn refuse(status: StatusCode, why: &'static str) -> Response {
    (status, why).into_response()
}

fn with_headers(mut response: Response) -> Response {
    let h = response.headers_mut();
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; frame-ancestors 'none'",
        ),
    ] {
        h.insert(name, HeaderValue::from_static(value));
    }
    response
}

pub async fn guard(State(shared): State<Shared>, request: Request<Body>, next: Next) -> Response {
    if shared.bind.is_loopback() {
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(host_name);
        if !host.is_some_and(local_host) {
            return with_headers(refuse(
                StatusCode::FORBIDDEN,
                "this report only answers requests addressed to localhost",
            ));
        }
    }
    if let Some(wanted) = shared
        .token
        .as_ref()
        .filter(|_| !crate::is_page_asset(request.uri().path()))
    {
        let from_header = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let given = from_header.or_else(|| query_token(request.uri().query()));
        if !given.is_some_and(|g| same_token(g, wanted)) {
            return with_headers(refuse(
                StatusCode::UNAUTHORIZED,
                "a token is required (Authorization: Bearer ..., or ?token=...)",
            ));
        }
    }
    with_headers(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names_lose_their_port() {
        assert_eq!(host_name("localhost:8099"), "localhost");
        assert_eq!(host_name("127.0.0.1:80"), "127.0.0.1");
        assert_eq!(host_name("[::1]:8099"), "[::1]");
        assert_eq!(host_name("evil.example"), "evil.example");
    }

    #[test]
    fn only_this_machine_counts_as_local() {
        assert!(local_host("LocalHost"));
        assert!(local_host("127.0.0.1"));
        assert!(local_host("[::1]"));
        assert!(!local_host("localhost.evil.example"));
        assert!(!local_host("192.168.1.5"));
    }

    #[test]
    fn tokens_compare_exactly() {
        assert!(same_token("abc", "abc"));
        assert!(!same_token("abc", "abd"));
        assert!(!same_token("abc", "abcd"));
        assert!(!same_token("", "abc"));
        assert_eq!(query_token(Some("a=1&token=xyz&b=2")), Some("xyz"));
        assert_eq!(query_token(Some("a=1")), None);
        assert_eq!(query_token(None), None);
    }
}
