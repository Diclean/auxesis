//! Host and `Origin` validation for the local API.
//!
//! The API binds loopback only and every route needs the bearer token, so a
//! DNS-rebinding page cannot read a response today (it can neither set
//! `Authorization` nor, for a WebSocket, any custom header). This layer is
//! defence in depth for the day a token travels in a URL/query/cookie or a
//! browser front talks to the loopback port: a request whose `Host` is not a
//! loopback name, or whose browser `Origin` is cross-site, is refused before
//! auth and before any handler runs.
//!
//! Native clients (URLSession, reqwest, a CLI) send no `Origin` and a
//! loopback `Host`; both stay accepted.

use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::error;

/// Reject non-loopback `Host` and cross-origin browser requests.
///
/// A duplicated `Host`/`Origin` header is refused outright:
/// hyper answers from the first value while a downstream proxy or a browser
/// may read the last, so "first one is loopback" is not a decision this layer
/// can make. An absent header stays the caller's business.
pub async fn validate_host_origin(request: Request, next: Next) -> Response {
    if !sole_header(request.headers(), header::HOST) {
        return error::error_response(
            StatusCode::FORBIDDEN,
            "forbidden_host",
            "duplicate Host headers are not accepted by the local API",
            None,
        );
    }
    if !sole_header(request.headers(), header::ORIGIN) {
        return error::error_response(
            StatusCode::FORBIDDEN,
            "forbidden_origin",
            "duplicate Origin headers are not accepted by the local API",
            None,
        );
    }
    if let Some(host) = request.headers().get(header::HOST) {
        if !host.to_str().map(host_is_loopback).unwrap_or(false) {
            return error::error_response(
                StatusCode::FORBIDDEN,
                "forbidden_host",
                "Host must be a loopback name (127.0.0.1, localhost or [::1])",
                None,
            );
        }
    }
    if let Some(origin) = request.headers().get(header::ORIGIN) {
        if !origin.to_str().map(origin_is_loopback).unwrap_or(false) {
            return error::error_response(
                StatusCode::FORBIDDEN,
                "forbidden_origin",
                "cross-origin requests are not accepted by the local API",
                None,
            );
        }
    }
    next.run(request).await
}

/// At most one value for `name`: a duplicate must never be resolved to either
/// the first or the last value.
fn sole_header(headers: &HeaderMap, name: HeaderName) -> bool {
    headers.get_all(name).iter().count() <= 1
}

/// True for `127.0.0.1[:port]`, `localhost[:port]`, `[::1][:port]` and a
/// bare loopback IP. A missing `Host` is the caller's business (HTTP/1.1
/// always carries one); a present one must be loopback.
pub fn host_is_loopback(host: &str) -> bool {
    let host = host.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        // `[::1]` / `[::1]:2893`.
        let Some((inside, after)) = rest.split_once(']') else {
            return false;
        };
        if !after.is_empty() && !port_suffix_ok(after) {
            return false;
        }
        inside
    } else if host.matches(':').count() > 1 {
        // Bare IPv6 without brackets (no port can be appended).
        host
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        name
    } else {
        host
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// `:2893` after a bracketed host; rejected when it is anything else.
fn port_suffix_ok(after: &str) -> bool {
    after
        .strip_prefix(':')
        .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

/// True for an `Origin` whose authority is loopback (`http://localhost:2893`,
/// `https://127.0.0.1`). The scheme is not part of the trust decision; the
/// opaque `null` origin and any cross-site host are refused.
pub fn origin_is_loopback(origin: &str) -> bool {
    let origin = origin.trim();
    let Some((_scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority
        .rsplit_once('@')
        .map(|(_userinfo, host)| host)
        .unwrap_or(authority);
    host_is_loopback(authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_host_or_origin_headers_are_refused() {
        // Round-1 P3-9: hyper answers from the first value, so
        // `Host: 127.0.0.1` + `Host: evil.example` used to pass. Neither
        // value may decide; a duplicate is refused.
        let mut host = HeaderMap::new();
        host.append(header::HOST, "127.0.0.1".parse().unwrap());
        assert!(sole_header(&host, header::HOST), "one value is fine");
        host.append(header::HOST, "evil.example".parse().unwrap());
        assert!(
            !sole_header(&host, header::HOST),
            "a loopback first value must not launder a duplicate"
        );

        let mut origin = HeaderMap::new();
        origin.append(header::ORIGIN, "http://localhost:1".parse().unwrap());
        origin.append(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(!sole_header(&origin, header::ORIGIN));

        assert!(sole_header(&HeaderMap::new(), header::HOST));
        assert!(sole_header(&HeaderMap::new(), header::ORIGIN));
    }

    #[test]
    fn loopback_hosts_are_accepted() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:2893",
            "127.0.0.2:2893",
            "localhost",
            "localhost:2893",
            "LOCALHOST:2893",
            "[::1]",
            "[::1]:2893",
            "::1",
        ] {
            assert!(host_is_loopback(host), "{host} should be loopback");
        }
    }

    #[test]
    fn rebinding_shaped_hosts_are_rejected() {
        for host in [
            "evil.example",
            "localhost.evil.com",
            "127.0.0.1.nip.io",
            "localhost:bad",
            "localhost:",
            "[::1]evil",
            "[fe80::1]:2893",
        ] {
            assert!(!host_is_loopback(host), "{host} must be rejected");
        }
    }

    #[test]
    fn origins_follow_the_same_loopback_rule() {
        for origin in [
            "http://localhost:2893",
            "https://127.0.0.1",
            "http://[::1]:2893",
            "http://user:pass@localhost:2893",
        ] {
            assert!(origin_is_loopback(origin), "{origin} should be accepted");
        }
        for origin in [
            "http://evil.example",
            "https://localhost.evil.com",
            "http://127.0.0.1.nip.io",
            "null",
            "chrome-extension://abcdef",
            "http://evil.example:2893",
        ] {
            assert!(!origin_is_loopback(origin), "{origin} must be rejected");
        }
    }
}
