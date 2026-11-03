//! IMAP connection lifecycle: dial, log in, log out.
//!
//! [`crate::dial::Dialer`] has already consumed the greeting and the
//! CAPABILITY response, so this module hands the stream straight to
//! `async_imap::Client::new` and never reads a greeting. The whole login is
//! bounded by [`crate::limits::Limits::call_timeout`].
//!
//! # Log hygiene
//!
//! `async_imap` logs the encoded `LOGIN` command — the password included — at
//! `TRACE`. This crate cannot silence another crate's target, so the daemon's
//! tracing filter forces `async_imap=off` (see the `P2-3` note in
//! `crates/auxd/src/main.rs`). Never add a subscriber here that lets
//! `async_imap` reach `trace` while a login is in flight.

use std::time::Duration;

use async_imap::Session;

use crate::config::ImapSettings;
use crate::dial::{BoxedStream, Dialer};
use crate::error::MailError;
use crate::limits::Limits;
use crate::presets::Endpoint;

/// Log in to `settings`, bounding the whole exchange — dial included — by
/// `limits.call_timeout`.
///
/// A login carries the password, so a `plain` endpoint is refused **before any
/// socket is opened**: implicit TLS and a completed STARTTLS upgrade both
/// arrive here already encrypted, leaving `plain` as the only case where the
/// password would cross the wire in the clear.
pub async fn login(
    settings: &ImapSettings,
    username: &str,
    password: &str,
    dialer: &Dialer,
    limits: &Limits,
) -> Result<Session<BoxedStream>, MailError> {
    let ceiling = limits
        .max_message_bytes
        .saturating_add(crate::guard::READ_GUARD_OVERHEAD);
    login_with_caps(
        settings, username, password, dialer, limits, ceiling, ceiling,
    )
    .await
}

/// [`login`] with explicit guard ceilings: `total_limit` bounds the connection
/// and `literal_limit` the largest `{N}` it accepts. MA3's attachment fetch
/// uses this to arm the guard from the attachment budgets rather than the
/// message cap.
#[allow(clippy::too_many_arguments)]
pub async fn login_with_caps(
    settings: &ImapSettings,
    username: &str,
    password: &str,
    dialer: &Dialer,
    limits: &Limits,
    total_limit: usize,
    literal_limit: usize,
) -> Result<Session<BoxedStream>, MailError> {
    let endpoint = Endpoint {
        host: settings.host.clone(),
        port: settings.port,
        security: settings.security,
    };
    if !endpoint.security.is_encrypted() {
        return Err(MailError::InsecurePassword {
            host: endpoint.host,
            port: endpoint.port,
        });
    }

    // A `ca_file` pins exactly that certificate and is loopback-only; both the
    // host check and the file read happen before any socket is opened. Without
    // it the caller's dialer (the webpki-roots production path) is unchanged.
    let pinned;
    let dialer = match settings.ca_file.as_deref() {
        Some(ca_file) => {
            crate::tlsutil::ensure_loopback_ca(&endpoint.host)?;
            pinned = Dialer::with_ca_file(std::path::Path::new(ca_file), dialer.connect_timeout())?;
            &pinned
        }
        None => dialer,
    };

    let outcome = tokio::time::timeout(limits.call_timeout, async {
        let stream = dialer
            .connect_guarded_caps(&endpoint, total_limit, literal_limit)
            .await?;
        let client = async_imap::Client::new(stream);
        client
            .login(username, password)
            .await
            .map_err(|(error, _client)| map_login_error(error))
    })
    .await;
    match outcome {
        Err(_) => Err(MailError::Timeout {
            budget: limits.call_timeout,
        }),
        Ok(result) => result,
    }
}

/// Log out cleanly, bounded by `budget`.
pub async fn logout(mut session: Session<BoxedStream>, budget: Duration) -> Result<(), MailError> {
    match tokio::time::timeout(budget, session.logout()).await {
        Err(_) => Err(MailError::Timeout { budget }),
        Ok(Err(_)) => Err(MailError::Protocol),
        Ok(Ok(())) => Ok(()),
    }
}

/// Collapse an `async_imap` failure to a text-free [`MailError`].
///
/// The `async_imap` error kinds are not credential-free: `No`/`Bad` carry the
/// server's reason, and a malformed response makes `imap-proto` embed the raw
/// line (via `imap_stream`'s `io::Error`) in the error's `Display`/`Debug`.
/// A hostile server echoes the `LOGIN` command — password included — in any of
/// them, so the login phase keeps only the kind: [`MailError::Auth`] for a
/// refused login, [`MailError::Protocol`] for everything else. No original
/// error is stored, so no `source()` chain can carry the text either.
fn map_login_error(error: async_imap::error::Error) -> MailError {
    match error {
        async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_) => MailError::Auth,
        _ => MailError::Protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Lang;

    /// A hostile `async_imap` error can carry the raw LOGIN line — password
    /// included — in its `Display`/`Debug`; the mapping must drop it entirely.
    #[test]
    fn login_errors_never_keep_library_text() {
        const CANARY: &str = "canary-password-abc123";
        let errors = [
            async_imap::error::Error::No(CANARY.to_string()),
            async_imap::error::Error::Bad(CANARY.to_string()),
            async_imap::error::Error::Io(std::io::Error::other(format!(
                "during parsing of \"{CANARY}\""
            ))),
            async_imap::error::Error::ConnectionLost,
        ];
        for error in errors {
            let mapped = map_login_error(error);
            assert!(
                matches!(mapped, MailError::Auth | MailError::Protocol),
                "{mapped:?}"
            );
            assert_no_canary(&mapped, CANARY);
        }
    }

    fn assert_no_canary(error: &MailError, canary: &str) {
        let en = error.user_message(Lang::En);
        let fr = error.user_message(Lang::Fr);
        let mut texts = vec![
            format!("{error}"),
            format!("{error:?}"),
            format!("{} {} {}", en.title, en.cause, en.action),
            format!("{} {} {}", fr.title, fr.cause, fr.action),
        ];
        let mut source = std::error::Error::source(error);
        while let Some(next) = source {
            texts.push(format!("{next}"));
            texts.push(format!("{next:?}"));
            source = next.source();
        }
        for text in texts {
            assert!(!text.contains(canary), "leaked the canary: {text}");
        }
    }
}
