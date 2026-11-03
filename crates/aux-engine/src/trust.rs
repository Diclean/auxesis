//! Owner-presence proof for clearing a workspace's taint mark (WS-C fix
//! rounds 4–5).
//!
//! # WS-C alone provides no owner-presence guarantee
//!
//! What follows is a speed bump on the delivery channel, not a security
//! boundary. The code is displayed on the owner's screen; any same-user
//! process that can read that screen's inputs (the macOS notification
//! database, a keylogger, the process table before round 5's stdin fix) or
//! write the store file can defeat or bypass the proof entirely. WS-D's
//! sandbox (token unreadable, network off, notification store and process
//! info out of reach) is the layer that turns this into a guarantee; WS-C is
//! designed to be correct only together with it.
//!
//! The one promise this module keeps on its own: no tool or model can make
//! the code reach a program of *its* choosing. The notifier executes a
//! verified, root-owned absolute system binary (`/usr/bin/osascript`, never
//! a `PATH` lookup), with a cleared environment, and the notification text —
//! code included — travels on stdin, never on a command line.
//!
//! The sticky workspace mark is only ever cleared by an owner action. That
//! claim was broken because `aux workspace trust <path>` was an ordinary
//! owner CLI: the `shell` tool runs owner commands, so one approved command
//! (or none, under `allow shell`) could disarm the whole mechanism, and its
//! audit row was byte-identical to a hand-run clear (security-review round 3, P1).
//!
//! The fix splits the clear into two steps.
//!
//! 1. **Request.** `aux workspace trust <path>` (CLI) and
//!    `POST /v1/workspaces/trust` (API) create a *pending trust request*
//!    bound to the canonical workspace path. A random one-time code (8
//!    digits, >= 6 as required) is generated and delivered **only** through
//!    the owner's local notification channel ([`aux_notify::Notifier`] —
//!    `osascript` in production). The store keeps a salted, iterated
//!    PBKDF2-HMAC-SHA256 hash of the code plus a random salt; the code itself
//!    is never returned to any caller, never written to a store row, an audit
//!    row, a log or a file, so a tool that can run the CLI or `curl` the API
//!    (owner token included) has nothing to replay. Requests are
//!    rate-limited (one notification per 30 s per workspace, a limit the
//!    attempt cap no longer resets), expire after 120 s and are single-use.
//! 2. **Complete.** The owner enters the code from the notification: at the
//!    CLI, re-running `aux workspace trust <path>` prompts for it without
//!    echo (`--code -` reads stdin; `--code <code>` is legacy and warns), or
//!    the API's `code` field. A wrong code counts an attempt (max 3, after
//!    which the request is spent but its cooldown watermark remains); an
//!    expired, exhausted, replaced or already-used code fails. Only a
//!    correct code consumes the request, clears the mark and writes
//!    `workspace.trusted` — all in one store transaction, so a failed audit
//!    can never leave the mark cleared unrecorded.
//!
//! The audit trail records `workspace.trust_requested`, `workspace.trusted`
//! and `workspace.trust_failed` (who/how, request id, attempt counts) but
//! never the code — the store methods take no code parameter at all, which
//! makes the leak structurally impossible.
//!
//! # Threat model / WS-D
//!
//! The code travels through a channel the model cannot read (a macOS
//! notification; the app's Inbox has no trust surface in this tree). A tool
//! that obtains the owner token, reads the store, or brute-forces its KDF
//! hash offline still cannot *read the notification*; online guessing is
//! capped at 3 attempts inside a 120 s window (and the cooldown that bounds
//! request/guess cycles survives an exhausted request). The KDF is a speed
//! bump, not the boundary: a stolen store copy is a ~60-core-day job, and
//! WS-D's sandbox is the layer that keeps the store (and the notification
//! database) out of a tool's reach.

use std::io::Read as _;

use aux_notify::{Notification, Notifier};
use aux_store::{NewTrustRequest, PutTrustOutcome, Store, StoreError};

/// Digits in a one-time trust code (the brief's floor is 6; 8 keeps the
/// offline brute force of a stolen store hash expensive).
pub const TRUST_CODE_DIGITS: usize = 8;

/// How long a code stays valid.
pub const TRUST_CODE_TTL_SECS: i64 = 120;

/// Wrong codes accepted before the request is deleted.
pub const TRUST_MAX_ATTEMPTS: i64 = 3;

/// Minimum seconds between two notifications for the same workspace.
pub const TRUST_REQUEST_COOLDOWN_SECS: i64 = 30;

/// PBKDF2 iterations. Measured at ~54 ms per candidate on a current release
/// build, so brute-forcing one code out of the 10^8 space from a stolen
/// store hash is ≈ 5.4e6 CPU-seconds ≈ **62 core-days** (single core; a
/// 10-core host brings it to about a week). The per-request random salt
/// keeps rainbow tables reusable across requests at zero. This is a speed
/// bump, not the boundary — WS-D's sandbox is the boundary.
const KDF_ITERATIONS: u32 = 500_000;

/// Notification title; the body is built by [`notification_body`].
pub const TRUST_NOTIFICATION_TITLE: &str = "Auxesis: workspace trust request";

/// A pending trust request was created and the code delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRequested {
    /// Public id correlating the request's audit rows (not a secret).
    pub request_id: String,
    /// Unix seconds after which the code no longer works.
    pub expires_at: i64,
}

/// A trust request was completed: the mark was cleared and audited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustCompleted {
    /// Public id of the consumed request.
    pub request_id: String,
    /// Whether a workspace mark actually existed.
    pub changed: bool,
}

/// Why a trust request or completion failed.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    /// A request was made too recently; no new notification was sent.
    #[error("a trust request was already sent; try again in {retry_after_secs} s")]
    RateLimited {
        /// Seconds until a new request is accepted.
        retry_after_secs: i64,
    },
    /// The notification could not be delivered, so the request was removed.
    /// `detail` is redacted: it can never echo the code.
    #[error("the trust notification could not be delivered: {detail}")]
    Notification {
        /// Sanitized, code-redacted transport error.
        detail: String,
    },
    /// No pending request for this workspace (never made, expired, replaced,
    /// exhausted or already used).
    #[error("no pending trust request for this workspace; run `aux workspace trust <path>` first")]
    NoRequest,
    /// The code's 120 s lifetime elapsed; the request was swept.
    #[error("the trust request expired; run `aux workspace trust <path>` again")]
    Expired,
    /// The submitted code did not match.
    #[error(
        "wrong code ({attempts_left} attempt(s) left): use the code from the owner notification"
    )]
    WrongCode {
        /// Attempts remaining before the request is deleted.
        attempts_left: i64,
    },
    /// The attempt cap was reached; this code is spent. The cooldown still
    /// applies before a fresh request, so the cap cannot be used to reset it.
    #[error(
        "too many wrong codes; this code is spent — run `aux workspace trust <path>` again after the cooldown"
    )]
    AttemptsExhausted,
    /// The loaded `[shell]` config can run the shell unsandboxed, so clearing
    /// the workspace mark would not constrain anything. No code is issued or
    /// consumed; the refusal is audited as `workspace.trust_refused`.
    #[error(
        "the shell can run unsandboxed (`shell.allow_unsandboxed = true` with the sandbox disabled or \
         unavailable), so trusting a workspace is refused; restore the sandbox in config.toml first"
    )]
    UnsandboxedShell,
    /// The store failed.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// The OS randomness source was unavailable.
    #[error("could not read OS randomness: {0}")]
    Random(#[source] std::io::Error),
}

/// Refuse a trust action while the loaded `[shell]` config can run the shell
/// unsandboxed (WS-C round 7).
///
/// The owner-presence proof exists to clear the workspace taint mark. While
/// the shell can run unsandboxed, that mark is not the boundary — the shell
/// can already do anything — so the promise is to refuse the clear rather
/// than let the owner believe it constrains a command-capable model. The
/// refusal is audited as `workspace.trust_refused`, and **no code is issued
/// or consumed**: callers run this before [`request_trust`] and before
/// [`complete_trust`].
pub fn refuse_when_unsandboxed_shell(
    store: &Store,
    workspace: &str,
    by: &str,
    shell: &kernel_core::ShellConfig,
) -> Result<(), TrustError> {
    if !crate::config::shell_sandbox(shell).will_run_unsandboxed() {
        return Ok(());
    }
    let payload = serde_json::json!({
        "workspace": workspace,
        "by": by,
        "reason": "unsandboxed_shell",
    })
    .to_string();
    store.log_event("workspace.trust_refused", &payload)?;
    Err(TrustError::UnsandboxedShell)
}

/// Create a pending trust request for `workspace` and deliver the code
/// through `notifier`.
///
/// `by` labels the audit rows (`owner-cli`, `owner-api`). The code is never
/// part of the return value, an audit row or the store; the caller must not
/// echo it either. A failed notification deletes the request so the owner
/// can retry immediately.
pub fn request_trust(
    store: &Store,
    workspace: &str,
    by: &str,
    notifier: &dyn Notifier,
) -> Result<TrustRequested, TrustError> {
    let code = generate_code()?;
    let salt = random_bytes::<16>()?;
    let hash = derive_code_hash(&code, &salt, KDF_ITERATIONS);
    let request_id = random_request_id()?;
    let now = unix_now();
    let request = NewTrustRequest {
        request_id: request_id.clone(),
        code_hash: hash.to_vec(),
        salt: salt.to_vec(),
    };
    match store.put_trust_request(workspace, &request, now, TRUST_REQUEST_COOLDOWN_SECS, by)? {
        PutTrustOutcome::RateLimited { retry_after_secs } => {
            return Err(TrustError::RateLimited { retry_after_secs })
        }
        PutTrustOutcome::Stored => {}
    }
    let notification = Notification::new(
        TRUST_NOTIFICATION_TITLE,
        notification_body(workspace, &code, by),
    );
    if let Err(err) = notifier.notify(&notification) {
        // No code reached the owner: do not leave a pending request that
        // blocks the next attempt until the cooldown.
        let _ = store.delete_trust_request(workspace, &request_id, "notification_failed", by);
        return Err(TrustError::Notification {
            detail: redact_code(&err.to_string(), &code),
        });
    }
    Ok(TrustRequested {
        request_id,
        expires_at: now + TRUST_CODE_TTL_SECS,
    })
}

/// Complete the pending trust request of `workspace` with the owner-typed
/// `code`: consume it, clear the mark and audit, all atomically.
pub fn complete_trust(
    store: &Store,
    workspace: &str,
    code: &str,
    by: &str,
) -> Result<TrustCompleted, TrustError> {
    let Some(pending) = store.trust_request(workspace)? else {
        store.log_trust_no_request(workspace, by)?;
        return Err(TrustError::NoRequest);
    };
    let now = unix_now();
    if now - pending.created_at > TRUST_CODE_TTL_SECS {
        let _ = store.delete_trust_request(workspace, &pending.request_id, "expired", by);
        return Err(TrustError::Expired);
    }
    if pending.attempts >= TRUST_MAX_ATTEMPTS {
        // The attempt cap already spent this request. The row stays until
        // the cooldown/TTL so the request rate limit cannot be reset by
        // burning the cap (security-review round 4, P2-1); no code can revive it.
        store.log_trust_no_request(workspace, by)?;
        return Err(TrustError::NoRequest);
    }
    let matches = match normalize_code(code) {
        Some(candidate) => {
            let candidate_hash = derive_code_hash(&candidate, &pending.salt, KDF_ITERATIONS);
            constant_time_eq(&candidate_hash, &pending.code_hash)
        }
        None => false,
    };
    if !matches {
        return match store.bump_trust_attempts(
            workspace,
            &pending.request_id,
            TRUST_MAX_ATTEMPTS,
            by,
        )? {
            None => {
                store.log_trust_no_request(workspace, by)?;
                Err(TrustError::NoRequest)
            }
            Some(attempts) if attempts >= TRUST_MAX_ATTEMPTS => Err(TrustError::AttemptsExhausted),
            Some(attempts) => Err(TrustError::WrongCode {
                attempts_left: TRUST_MAX_ATTEMPTS - attempts,
            }),
        };
    }
    match store.complete_trust_request(workspace, &pending.request_id, TRUST_MAX_ATTEMPTS, by)? {
        Some(changed) => Ok(TrustCompleted {
            request_id: pending.request_id,
            changed,
        }),
        // The request was consumed between the read and the transaction
        // (another process, or a replay): treat it as absent.
        None => {
            store.log_trust_no_request(workspace, by)?;
            Err(TrustError::NoRequest)
        }
    }
}

/// Unix seconds, for the request/expiry policy.
fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Eight random decimal digits (zero-padded).
fn generate_code() -> Result<String, TrustError> {
    let value = u64::from_le_bytes(random_bytes::<8>()?) % 100_000_000;
    Ok(format!("{value:08}"))
}

/// A random public request id (never a secret).
fn random_request_id() -> Result<String, TrustError> {
    let bytes = random_bytes::<16>()?;
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// `count` bytes from the OS; no fallback to a weak seed.
fn random_bytes<const N: usize>() -> Result<[u8; N], TrustError> {
    let mut buf = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buf))
        .map_err(TrustError::Random)?;
    Ok(buf)
}

/// PBKDF2-HMAC-SHA256 (one 32-byte block) of `code` with `salt`.
///
/// The stored verifier is the hash; recovering the code from it requires
/// brute-forcing the code space through all `iterations` HMACs per candidate.
fn derive_code_hash(code: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, code.as_bytes());
    let mut u = {
        let mut ctx = ring::hmac::Context::with_key(&key);
        ctx.update(salt);
        ctx.update(&1u32.to_be_bytes());
        ctx.sign()
    };
    let mut t: [u8; 32] = u
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 output is 32 bytes");
    for _ in 1..iterations {
        u = ring::hmac::sign(&key, u.as_ref());
        for (acc, byte) in t.iter_mut().zip(u.as_ref()) {
            *acc ^= *byte;
        }
    }
    t
}

/// Byte-wise comparison without an early exit on the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Strip grouping (spaces/hyphens) an owner may type; require exactly
/// [`TRUST_CODE_DIGITS`] ASCII digits.
fn normalize_code(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if cleaned.len() == TRUST_CODE_DIGITS && cleaned.bytes().all(|b| b.is_ascii_digit()) {
        Some(cleaned)
    } else {
        None
    }
}

/// `1234 5678` for display in the notification.
fn display_code(code: &str) -> String {
    let (head, tail) = code.split_at(code.len() / 2);
    format!("{head} {tail}")
}

/// The notification body: the code plus enough context for the owner to
/// decide, and an explicit note that a model can trigger the request — the
/// owner must not confuse a tool-initiated notification with their own
/// action. Never logged by this crate.
fn notification_body(workspace: &str, code: &str, by: &str) -> String {
    let source = match by {
        "owner-cli" => "the aux CLI",
        "owner-api" => "the aux API",
        _ => "aux",
    };
    format!(
        "A trust request for {workspace} came from {source}.\n\
         Code: {} (expires in {} minutes)\n\
         A model or tool can trigger this request — enter the code only if you started it.",
        display_code(code),
        TRUST_CODE_TTL_SECS / 60,
    )
}

/// Ensure a transport error can never carry the code back to a tool.
fn redact_code(text: &str, code: &str) -> String {
    text.replace(code, "[redacted]")
        .replace(&display_code(code), "[redacted]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_notify::{FakeNotifier, NotifyError};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tempfile::{tempdir, TempDir};

    /// A notifier that captures the code it was given, then fails with it in
    /// the error text — to prove the error path redacts it.
    struct CodeEchoNotifier {
        seen: Mutex<Vec<String>>,
    }

    impl CodeEchoNotifier {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
            })
        }

        fn codes(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Notifier for CodeEchoNotifier {
        fn notify(&self, notification: &Notification) -> Result<(), NotifyError> {
            let code = code_from_body(&notification.body).expect("notification carries a code");
            self.seen.lock().unwrap().push(code.clone());
            Err(NotifyError::Osascript {
                status: "1".to_string(),
                stderr: format!("failed to show {code}"),
            })
        }
    }

    fn code_from_body(body: &str) -> Option<String> {
        let line = body.lines().find(|line| line.starts_with("Code: "))?;
        let after = line.trim_start_matches("Code: ");
        let end = after.find(" (expires").unwrap_or(after.len());
        normalize_code(&after[..end])
    }

    fn code_of(notifier: &FakeNotifier) -> String {
        code_from_body(&notifier.last().unwrap().body).unwrap()
    }

    /// A real file store so tests can read/modify the raw rows (expiry,
    /// audit payloads) through a second connection, exactly like the shell
    /// could.
    fn store_with_tainted() -> (TempDir, PathBuf, Store) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        store.mark_workspace_tainted("/ws/main", "shell").unwrap();
        (dir, path, store)
    }

    fn event_payloads(path: &Path, kind: &str) -> Vec<String> {
        let conn = aux_store::open_keyed(path).unwrap();
        let mut stmt = conn
            .prepare("SELECT payload FROM events WHERE kind = ?1 ORDER BY id")
            .unwrap();
        let payloads = stmt
            .query_map([kind], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        payloads
    }

    fn backdate(path: &Path, workspace: &str, seconds: i64) {
        let conn = aux_store::open_keyed(path).unwrap();
        conn.execute(
            "UPDATE trust_requests SET created_at = created_at - ?1 WHERE workspace = ?2",
            rusqlite::params![seconds, workspace],
        )
        .unwrap();
    }

    #[test]
    fn the_notification_is_the_only_carrier_of_the_code() {
        let (_dir, path, store) = store_with_tainted();
        let notifier = FakeNotifier::new();
        let requested = request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        assert_eq!(notifier.count(), 1);
        let code = code_of(&notifier);

        // The request row holds a hash, not the code.
        let pending = store.trust_request("/ws/main").unwrap().unwrap();
        assert_eq!(pending.request_id, requested.request_id);
        assert_ne!(pending.code_hash, code.as_bytes());
        assert!(
            !format!("{pending:?}").contains(&code),
            "the code must not be derivable from the stored row's rendering"
        );
        // …and neither does the audit trail.
        for payload in event_payloads(&path, "workspace.trust_requested") {
            assert!(
                !payload.contains(&code),
                "the code appeared in an audit row: {payload}"
            );
        }
    }

    #[test]
    fn a_wrong_code_counts_an_attempt_and_the_cap_spends_the_request() {
        let (_dir, _path, store) = store_with_tainted();
        let notifier = FakeNotifier::new();
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        let code = code_of(&notifier);
        let wrong = if code == "00000000" {
            "11111111"
        } else {
            "00000000"
        };

        for expected_left in (1..TRUST_MAX_ATTEMPTS).rev() {
            let err = complete_trust(&store, "/ws/main", wrong, "owner-cli").unwrap_err();
            assert!(matches!(
                err,
                TrustError::WrongCode { attempts_left } if attempts_left == expected_left
            ));
        }
        assert!(matches!(
            complete_trust(&store, "/ws/main", wrong, "owner-cli").unwrap_err(),
            TrustError::AttemptsExhausted
        ));
        // The spent row stays as the cooldown watermark (P2-1)…
        assert_eq!(
            store.trust_request("/ws/main").unwrap().unwrap().attempts,
            TRUST_MAX_ATTEMPTS
        );
        // …and even the real code cannot revive it.
        assert!(matches!(
            complete_trust(&store, "/ws/main", &code, "owner-cli").unwrap_err(),
            TrustError::NoRequest
        ));
        assert!(
            store.workspace_taint("/ws/main").unwrap().is_some(),
            "the mark must survive every failure path"
        );
        assert_eq!(
            store.event_count("workspace.trust_failed").unwrap(),
            4,
            "three wrong codes plus the late attempt"
        );
    }

    #[test]
    fn exhausting_the_cap_does_not_reset_the_request_cooldown() {
        // P2 regression (security-review round 4, P2-1): three wrong codes used to
        // delete the only cooldown record, so the next request was accepted
        // immediately and every cycle delivered another owner notification.
        // With the spent row kept in place, the request step stays limited
        // for the remainder of the 30 s window.
        let (_dir, path, store) = store_with_tainted();
        let notifier = FakeNotifier::new();
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        let code = code_of(&notifier);
        let wrong = if code == "00000000" {
            "11111111"
        } else {
            "00000000"
        };
        for _ in 0..TRUST_MAX_ATTEMPTS {
            assert!(complete_trust(&store, "/ws/main", wrong, "owner-cli").is_err());
        }

        // Immediately after the cap: refused, no second notification.
        assert!(matches!(
            request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap_err(),
            TrustError::RateLimited { .. }
        ));
        assert_eq!(notifier.count(), 1, "no second notification may be shown");
        assert_eq!(store.event_count("workspace.trust_requested").unwrap(), 1);

        // After the cooldown the owner gets a fresh code.
        backdate(&path, "/ws/main", TRUST_REQUEST_COOLDOWN_SECS + 1);
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        assert_eq!(notifier.count(), 2);
        assert_eq!(
            store.trust_request("/ws/main").unwrap().unwrap().attempts,
            0
        );
    }

    #[test]
    fn the_code_is_single_use_and_grouping_is_accepted() {
        let (_dir, _path, store) = store_with_tainted();
        let notifier = FakeNotifier::new();
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        let code = code_of(&notifier);
        let typed = display_code(&code);

        let completed = complete_trust(&store, "/ws/main", &typed, "owner-cli").unwrap();
        assert!(completed.changed);
        assert!(store.workspace_taint("/ws/main").unwrap().is_none());
        assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);

        // Replay of the same (correct) code: the request is gone, and the
        // failed attempt is audited.
        assert!(matches!(
            complete_trust(&store, "/ws/main", &code, "owner-cli").unwrap_err(),
            TrustError::NoRequest
        ));
        assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);
        assert_eq!(store.event_count("workspace.trust_failed").unwrap(), 1);
    }

    #[test]
    fn an_expired_code_is_refused_and_swept() {
        let (_dir, path, store) = store_with_tainted();
        let notifier = FakeNotifier::new();
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        let code = code_of(&notifier);
        // The owner waits too long.
        backdate(&path, "/ws/main", TRUST_CODE_TTL_SECS + 1);

        assert!(matches!(
            complete_trust(&store, "/ws/main", &code, "owner-cli").unwrap_err(),
            TrustError::Expired
        ));
        assert!(store.trust_request("/ws/main").unwrap().is_none());
        assert!(store.workspace_taint("/ws/main").unwrap().is_some());
        let payloads = event_payloads(&path, "workspace.trust_failed");
        assert!(
            payloads
                .iter()
                .any(|payload| payload.contains(r#""reason":"expired""#)),
            "{payloads:?}"
        );
    }

    #[test]
    fn a_request_is_bound_to_its_workspace() {
        let (_dir, _path, store) = store_with_tainted();
        store.mark_workspace_tainted("/ws/other", "shell").unwrap();
        let notifier = FakeNotifier::new();
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        let code = code_of(&notifier);

        assert!(matches!(
            complete_trust(&store, "/ws/other", &code, "owner-cli").unwrap_err(),
            TrustError::NoRequest
        ));
        assert!(store.workspace_taint("/ws/main").unwrap().is_some());
        assert!(store.workspace_taint("/ws/other").unwrap().is_some());
        // The right workspace still completes.
        assert!(complete_trust(&store, "/ws/main", &code, "owner-cli").is_ok());
        assert!(store.workspace_taint("/ws/main").unwrap().is_none());
    }

    #[test]
    fn requests_are_rate_limited() {
        let (_dir, path, store) = store_with_tainted();
        let notifier = FakeNotifier::new();
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        let err = request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap_err();
        assert!(matches!(err, TrustError::RateLimited { .. }), "{err:?}");
        assert_eq!(notifier.count(), 1, "no second notification may be sent");

        // After the cooldown a fresh request replaces the pending one.
        backdate(&path, "/ws/main", TRUST_REQUEST_COOLDOWN_SECS + 1);
        request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap();
        assert_eq!(notifier.count(), 2);
    }

    #[test]
    fn a_notification_failure_removes_the_request_and_redacts_the_code() {
        let (_dir, _path, store) = store_with_tainted();
        let notifier = CodeEchoNotifier::new();
        let err = request_trust(&store, "/ws/main", "owner-cli", &notifier).unwrap_err();
        let code = notifier.codes().pop().expect("the notifier saw a code");
        let text = err.to_string();
        assert!(text.contains("could not be delivered"), "{text}");
        assert!(
            !text.contains(&code),
            "the transport error must be redacted: {text}"
        );
        assert!(
            store.trust_request("/ws/main").unwrap().is_none(),
            "a failed notification must not leave a pending request"
        );
        assert!(store.workspace_taint("/ws/main").unwrap().is_some());
        assert_eq!(store.event_count("workspace.trust_failed").unwrap(), 1);
    }

    #[test]
    fn a_symlinked_alias_keys_the_same_request() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("agents/main/workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let alias = dir.path().join("alias");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&workspace, &alias).unwrap();
        #[cfg(not(unix))]
        std::fs::create_dir_all(&alias).unwrap();

        let key = crate::workspace::workspace_key(&workspace);
        let store = Store::open_in_memory().unwrap();
        store.mark_workspace_tainted(&key, "shell").unwrap();
        let notifier = FakeNotifier::new();
        let aliased = crate::workspace::workspace_key(&alias);
        request_trust(&store, &aliased, "owner-cli", &notifier).unwrap();
        let code = code_of(&notifier);
        assert!(complete_trust(&store, &key, &code, "owner-cli").is_ok());
        assert!(store.workspace_taint(&key).unwrap().is_none());
    }

    #[test]
    fn trust_is_refused_while_the_shell_can_run_unsandboxed() {
        // WS-C round 7: with the escape hatch on, clearing the mark would not
        // constrain the shell, so the trust action is refused and audited —
        // and the refusal path never reaches the code generation.
        let (_dir, path, store) = store_with_tainted();
        let notifier = FakeNotifier::new();
        let unsandboxed = kernel_core::ShellConfig {
            sandbox: false,
            network: false,
            allow_unsandboxed: true,
            ..kernel_core::ShellConfig::default()
        };

        let err = refuse_when_unsandboxed_shell(&store, "/ws/main", "owner-cli", &unsandboxed)
            .unwrap_err();
        assert!(matches!(err, TrustError::UnsandboxedShell), "{err:?}");
        assert!(
            err.to_string().contains("unsandboxed"),
            "the error must name the reason: {err}"
        );
        assert_eq!(store.event_count("workspace.trust_refused").unwrap(), 1);
        assert!(
            store.workspace_taint("/ws/main").unwrap().is_some(),
            "the mark must survive the refusal"
        );
        // The caller returns before `request_trust`: no request row, no code.
        assert!(store.trust_request("/ws/main").unwrap().is_none());
        assert_eq!(notifier.count(), 0, "no code may be issued");

        let payloads = event_payloads(&path, "workspace.trust_refused");
        assert_eq!(payloads.len(), 1);
        assert!(
            payloads[0].contains("\"reason\":\"unsandboxed_shell\""),
            "{}",
            payloads[0]
        );
        assert!(
            payloads[0].contains("\"workspace\":\"/ws/main\""),
            "{}",
            payloads[0]
        );
    }

    #[test]
    fn trust_is_allowed_with_the_sandboxed_profile() {
        let (_dir, _path, store) = store_with_tainted();
        assert!(
            refuse_when_unsandboxed_shell(
                &store,
                "/ws/main",
                "owner-cli",
                &kernel_core::ShellConfig::default()
            )
            .is_ok(),
            "the safe default must not refuse trust"
        );
        assert_eq!(store.event_count("workspace.trust_refused").unwrap(), 0);
    }
}
