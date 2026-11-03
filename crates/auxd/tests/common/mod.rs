//! Shared helpers for the `auxd` API integration tests: a tiny blocking
//! HTTP/1.1 client over `std::net::TcpStream` (no extra client dependency).
//!
//! Every call sends `Connection: close`, writes the request on a separate
//! thread (so a server that answers early — body-limit 413s — cannot lose
//! the response to a reset), and reads until EOF.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::Value;

/// One shared wait budget for every condition poll in the auxd integration
/// tests. The happy path is milliseconds; a saturated runner (several cargo
/// jobs at once) made the old fixed 5 s/10 s deadlines fail on unrelated PRs
/// and pass on rerun, so every wait gets the same generous budget.
pub const LOADED_RUNNER_WAIT: Duration = Duration::from_secs(30);

/// Build a `Command` for a spawned Auxesis binary inside a test sandbox.
///
/// Every integration helper that spawns `auxd` (or `aux`) must use this: it
/// pins `HOME` and `AUXESIS_HOME` to the temp dir, marks the child as
/// sandboxed (`AUXESIS_SANDBOX=1`, the H-03 tripwire in `aux-core`), pins the
/// API to an explicit ephemeral port (`AUXESIS_API_PORT=0`, so a sandbox can
/// never bind or probe the real daemon's 2893) and asserts the home is
/// literally under that temp dir — a shell/`$HOME` expansion mistake can then
/// never point a daemon at the real `~/.auxesis`.
pub fn sandbox_command(binary: &str, dir: &Path, home: &Path) -> Command {
    assert!(
        home.starts_with(dir),
        "refusing to spawn {binary}: AUXESIS_HOME {} is not under the temp dir {}",
        home.display(),
        dir.display()
    );
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null());
    command
}

/// A spawned [`Child`] that is killed and reaped when the guard is dropped.
///
/// `std::process::Child` does not kill its process on drop, so a test that
/// panics before an explicit shutdown would leave the child running after its
/// `TempDir` home is gone. Wrap every child a test spawns in this guard; the
/// nominal path is unchanged, because a child already killed and reaped makes
/// `kill`/`wait` no-ops whose errors are ignored.
pub struct KillOnDrop {
    child: Child,
}

impl KillOnDrop {
    /// Take ownership of a spawned child and arm the kill-on-drop guard.
    pub fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Deref for KillOnDrop {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for KillOnDrop {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        // A child that already exited (and was reaped) makes both calls
        // return an error; there is nothing left to clean up.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One HTTP response, decoded as UTF-8 (lossy).
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Raw body text.
    pub body: String,
}

impl HttpResponse {
    /// Parse the body as JSON, panicking with the body on failure.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {}", self.body))
    }
}

/// Perform one HTTP request against `addr`.
pub fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> HttpResponse {
    http_with_headers(addr, method, path, token, body, &[])
}

/// Perform one HTTP request against `addr` with extra header lines.
///
/// A caller-supplied `Host` replaces the default `Host: {addr}` (used by the
/// F-17 rebinding tests).
pub fn http_with_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> HttpResponse {
    build_and_send(
        addr,
        method,
        path,
        token,
        body,
        extra_headers,
        Duration::from_secs(10),
    )
}

/// Perform one HTTP request with an explicit socket read timeout.
///
/// The default 10 s read fits a server that answers promptly; a test whose
/// server must first run to a long deadline (a turn timeout) outwaits that
/// deadline here instead of failing the client's read.
pub fn http_with_read_timeout(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
    read_timeout: Duration,
) -> HttpResponse {
    build_and_send(addr, method, path, token, body, &[], read_timeout)
}

/// Frame and send one request with the read timeout the caller needs.
fn build_and_send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
    extra_headers: &[(&str, &str)],
    read_timeout: Duration,
) -> HttpResponse {
    let body = body.unwrap_or("");
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    let has_host = extra_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"));
    if !has_host {
        request.push_str(&format!("Host: {addr}\r\n"));
    }
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        request.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);

    send_raw(addr, request.into_bytes(), read_timeout)
}

/// Write one already-framed request and decode the response.
fn send_raw(addr: SocketAddr, request: Vec<u8>, read_timeout: Duration) -> HttpResponse {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .unwrap_or_else(|err| panic!("connecting to {addr}: {err}"));
    stream.set_read_timeout(Some(read_timeout)).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut writer = stream.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = writer.write_all(&request);
        let _ = writer.flush();
    });

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let _ = writer.join();

    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no HTTP header terminator in {text:?}"));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {head:?}"));

    HttpResponse {
        status,
        body: decode_body(head, body),
    }
}

/// Decode a (possibly chunked) HTTP body.
fn decode_body(head: &str, body: &str) -> String {
    let chunked = head.lines().any(|line| {
        line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
    });
    if !chunked {
        return body.to_string();
    }
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        if after.len() < size {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
    out
}

/// GET with an optional token.
pub fn get(addr: SocketAddr, path: &str, token: Option<&str>) -> HttpResponse {
    http(addr, "GET", path, token, None)
}

/// POST a JSON body with an optional token.
pub fn post(addr: SocketAddr, path: &str, token: Option<&str>, body: &str) -> HttpResponse {
    http(addr, "POST", path, token, Some(body))
}

/// Assert an error response has the uniform shape and the expected code.
pub fn assert_error(response: &HttpResponse, status: u16, code: &str) {
    assert_eq!(
        response.status, status,
        "expected HTTP {status}, body: {}",
        response.body
    );
    let value = response.json();
    assert_eq!(
        value["error"]["code"], code,
        "unexpected error code: {}",
        response.body
    );
    assert!(
        value["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "error message must be a non-empty string: {}",
        response.body
    );
}
