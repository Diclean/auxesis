//! Bearer-token auth for the local API.
//!
//! The token is created on first use and stored at `<home>/api.token` with
//! mode `0600`. It is never logged: the process only ever compares it in
//! constant time against the `Authorization: Bearer <token>` header, and the
//! surrounding [`crate::api::ApiState`] redacts it from `Debug`.
//!
//! Every route — including `GET /v1/health` and the WebSocket upgrade — goes
//! through [`require_token`]; there is no unauthenticated endpoint and no
//! CORS surface, because the API binds loopback only and is consumed by a
//! native desktop app, not a browser.

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::error;
use super::ApiState;

/// File name of the API token inside the Auxesis home.
pub const TOKEN_FILE: &str = "api.token";

/// Entropy of a fresh token, in bytes (rendered as lowercase hex).
const TOKEN_BYTES: usize = 32;

/// Longest token file we are willing to read, so a FIFO-like path can never
/// hang or exhaust the daemon.
const MAX_TOKEN_FILE_BYTES: u64 = 4 * 1024;

/// Longest accepted token string (a hand-written token, not our hex one).
const MAX_TOKEN_CHARS: usize = 256;

/// The API bearer token.
///
/// `Debug` is intentionally opaque so the value can never leak into a log
/// line through a derived formatter.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken(String);

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiToken(<redacted>)")
    }
}

impl ApiToken {
    /// Wrap a token value, registering it with the exact-value scrubber so
    /// the daemon's own bearer token can never survive on a scrub surface.
    fn register(value: String) -> Self {
        kernel_broker::scrub::register_known_secret(&value);
        Self(value)
    }

    /// The raw token bytes, used only as the per-installation key for one-way
    /// confirmation bindings. Never for display, logging or equality.
    pub(crate) fn confirmation_key(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Load the token at `<home>/api.token`, creating it when missing.
    ///
    /// A pre-existing regular file wins (the app and the daemon must agree);
    /// an empty, unreadable or non-regular file is an error rather than a
    /// silent regeneration, so a corrupt home is never papered over. Newly
    /// created tokens are private (`0600`), and an existing file with wider
    /// permissions is tightened back to `0600` before use.
    pub fn load_or_create(home: &Path) -> std::io::Result<Self> {
        kernel_core::ensure_home(home)?;
        let path = token_path(home);
        match read_token(&path)? {
            Some(token) => {
                set_private(&path)?;
                Ok(Self::register(token))
            }
            None if path.exists() => {
                // Corrupt (empty / non-UTF-8 / oversized) regular file: rewrite
                // it in place through the verified home handle (J-02 write
                // gateway), keeping the path's ownership and mode.
                write_fresh_via(home, false)?;
                let token = read_token(&path)?.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "token file could not be rewritten",
                    )
                })?;
                set_private(&path)?;
                Ok(Self::register(token))
            }
            None => match write_fresh_via(home, true) {
                Ok(()) => {
                    let token = read_token(&path)?.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "token file could not be read back",
                        )
                    })?;
                    set_private(&path)?;
                    Ok(Self::register(token))
                }
                // Another process won the creation race: use its token.
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let token = read_token(&path)?.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "concurrent token file is not readable yet",
                        )
                    })?;
                    set_private(&path)?;
                    Ok(Self::register(token))
                }
                Err(err) => Err(err),
            },
        }
    }

    /// Constant-time comparison against a candidate header value.
    pub fn matches(&self, candidate: &str) -> bool {
        constant_time_eq(&self.0, candidate)
    }
}

/// Path of the API token inside `home`.
pub fn token_path(home: &Path) -> PathBuf {
    home.join(TOKEN_FILE)
}

/// Extract the token from an `Authorization: Bearer <token>` header.
///
/// The scheme is matched case-insensitively; anything else (no header, a
/// different scheme, an empty token) yields `None`.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Reject every request without the expected bearer token.
///
/// Runs before the WebSocket upgrade as well: a bad token never reaches a
/// route handler.
pub async fn require_token(
    State(state): State<std::sync::Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(token) = bearer_token(request.headers()) {
        if state.token.matches(token) {
            return next.run(request).await;
        }
    }
    error::error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "missing or invalid bearer token",
        None,
    )
}

/// Read and validate the token file, if it exists.
///
/// F-17 (audit C P3-3): the path is checked and opened with `O_NOFOLLOW`, so
/// a symlink placed at `api.token` is an error, never something the daemon
/// reads through or rewrites. The open handle is `fchmod`'ed to `0600` and
/// the mode is verified before the value is used.
fn read_token(path: &Path) -> std::io::Result<Option<String>> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is a symlink; refusing to follow it", path.display()),
        ));
    }
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if meta.len() > MAX_TOKEN_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is unexpectedly large", path.display()),
        ));
    }

    let mut file = open_token_file(path)?;
    tighten_open_file(&file, path)?;

    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let token = text.trim();
    if token.is_empty() || token.chars().count() > MAX_TOKEN_CHARS {
        return Ok(None);
    }
    if !token.chars().all(|c| c.is_ascii_graphic()) {
        return Ok(None);
    }
    Ok(Some(token.to_string()))
}

/// Open the token file read-only with `O_NOFOLLOW`.
///
/// Split out so the TOCTOU defence itself is testable: `read_token`'s
/// `symlink_metadata` pre-check can be raced, and this open is what refuses
/// the swapped-in symlink (M04).
fn open_token_file(path: &Path) -> std::io::Result<std::fs::File> {
    // SANDBOX-GATEWAY-EXEMPT: cfg(test)-only path-based token helper, kept to test the symlink refusal.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // TOCTOU defence: even if the path is swapped for a symlink between
        // the caller's check and this open, the open fails instead of
        // following it.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// `fchmod` an already-open token handle to `0600` and verify no group or
/// other access remains (F-17).
fn tighten_open_file(file: &std::fs::File, path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{} is not private (mode {mode:o})", path.display()),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (file, path);
    }
    Ok(())
}

/// Write a fresh random token through the verified sandbox home handle
/// (J-02 write gateway), optionally with `create_new` (race-safe).
///
/// The handle resolves `api.token` relative to the verified home directory
/// fd, so a symlink swapped at the home root after `ensure_home` cannot
/// redirect the write; `O_NOFOLLOW` refuses a symlink at the token name.
fn write_fresh_via(home: &Path, create_new: bool) -> std::io::Result<()> {
    let token = random_token()?;
    let handle = kernel_core::SandboxHome::open(home)?;
    let data = format!("{token}\n");
    let written = if create_new {
        handle.write_new(Path::new(TOKEN_FILE), data.as_bytes(), 0o600)?
    } else {
        handle.write(Path::new(TOKEN_FILE), data.as_bytes(), 0o600)?;
        true
    };
    if !written {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "token file exists",
        ));
    }
    Ok(())
}

/// Write a fresh random token by path, optionally with `create_new`.
///
/// Kept for the unit tests that exercise the path-based refusal of a symlink
/// planted at the token name.
#[cfg(test)]
fn write_fresh(path: &Path, create_new: bool) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{} is a symlink; refusing to write through it",
                    path.display()
                ),
            ));
        }
    }
    let token = random_token()?;
    // SANDBOX-GATEWAY-EXEMPT: cfg(test)-only path-based token helper, kept to test the symlink refusal.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    if create_new {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    // The `0600` mode above only applies to newly created files on unix; an
    // overwritten corrupt file keeps its old mode until the caller tightens
    // it, which `load_or_create` always does.
    writeln!(file, "{token}")?;
    file.sync_all()
}

/// 32 random bytes from the OS, rendered as lowercase hex.
///
/// `/dev/urandom` exists on every platform this daemon targets (macOS,
/// Linux CI); the error path is loud rather than falling back to a weak
/// seed.
fn random_token() -> std::io::Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut out = String::with_capacity(TOKEN_BYTES * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

/// Compare two strings without an early exit on the first differing byte.
fn constant_time_eq(expected: &str, candidate: &str) -> bool {
    let (expected, candidate) = (expected.as_bytes(), candidate.as_bytes());
    if expected.len() != candidate.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(candidate) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Tighten an existing token file to `0600` (no-op off unix).
fn set_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn creates_a_private_token_on_first_use_and_stays_stable() {
        let dir = tempdir().unwrap();
        let first = ApiToken::load_or_create(dir.path()).unwrap();
        let path = token_path(dir.path());
        assert!(path.is_file());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "token file must be private");
        }

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim().len(), TOKEN_BYTES * 2, "hex token length");
        assert!(text.trim().chars().all(|c| c.is_ascii_hexdigit()));

        let second = ApiToken::load_or_create(dir.path()).unwrap();
        assert_eq!(first, second, "second load reuses the same token");
    }

    #[test]
    fn widens_back_to_private_when_the_file_was_loose() {
        let dir = tempdir().unwrap();
        let _ = ApiToken::load_or_create(dir.path()).unwrap();
        let path = token_path(dir.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let _ = ApiToken::load_or_create(dir.path()).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn an_empty_file_is_regenerated_not_accepted() {
        let dir = tempdir().unwrap();
        let path = token_path(dir.path());
        std::fs::write(&path, "").unwrap();

        let token = ApiToken::load_or_create(dir.path()).unwrap();
        assert!(!token.matches(""));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim().len(), TOKEN_BYTES * 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_token_path_is_an_error_not_a_hang() {
        let dir = tempdir().unwrap();
        let path = token_path(dir.path());
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let err = ApiToken::load_or_create(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_token_path_is_refused_and_the_target_is_untouched() {
        // F-17/C P3-3: a symlink at `api.token` used to be rewritten through,
        // truncating an arbitrary same-uid file (and chmod'ing it 0600).
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("rcfile.sh");
        let contents = "export FOO=bar\nexport PATH=/custom/bin:$PATH\n";
        std::fs::write(&target, contents).unwrap();
        let path = token_path(dir.path());
        symlink(&target, &path).unwrap();

        let err = ApiToken::load_or_create(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            contents,
            "the symlink target must never be rewritten"
        );
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must be left alone"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_token_refuses_a_symlink_directly() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("rcfile.sh");
        std::fs::write(&target, "line one\nline two\n").unwrap();
        let path = dir.path().join("api.token");
        symlink(&target, &path).unwrap();

        let err = read_token(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    }

    /// M04 (DAEMON-HARDEN-1 security-review round 1): the pre-check above is not the
    /// TOCTOU defence — it cannot see a symlink swapped in between the check
    /// and the open. This calls the exact open helper `read_token` uses, with
    /// the pre-check bypassed, and requires `O_NOFOLLOW` to refuse the link.
    #[cfg(unix)]
    #[test]
    fn the_token_open_itself_refuses_a_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("rcfile.sh");
        std::fs::write(&target, "export FOO=bar\n").unwrap();
        let path = dir.path().join("api.token");
        symlink(&target, &path).unwrap();

        let err = open_token_file(&path).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "the open must fail with ELOOP, not follow the link: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "export FOO=bar\n",
            "the symlink target must be untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_fresh_refuses_a_symlink_directly() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("rcfile.sh");
        let contents = "export FOO=bar\n";
        std::fs::write(&target, contents).unwrap();
        let path = dir.path().join("api.token");
        symlink(&target, &path).unwrap();

        let err = write_fresh(&path, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), contents);
    }

    #[test]
    fn bearer_parsing_accepts_only_the_bearer_scheme() {
        use axum::http::HeaderValue;

        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer abc"),
        );
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("BEARER  abc "),
        );
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer"));
        assert_eq!(bearer_token(&headers), None);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer   "));
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn constant_time_compare_is_exact() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
