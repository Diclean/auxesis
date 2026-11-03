//! Typed errors for the Auxesis MCP client (internal crate `kernel-mcp`).
//!
//! Every failure mode the envelope, the bounds and the transport seam can
//! report is enumerated here, so callers never string-match on a message.
//! The `Display` strings stay protocol-neutral on purpose: if one ever
//! reaches the owner it must not leak an internal product name.
//!
//! # Untrusted text never reaches `Display`/`Debug` raw
//!
//! Every server- or peer-supplied string is copied through [`Sanitized`]
//! before storage. Protocol errors never display the message text: `Display`
//! shows its byte length and short hash, while callers that need the bounded
//! content can inspect the typed field. The sanitiser bounds and cleans, but
//! does not redact, so the message must still not be logged directly.

use std::fmt;
use std::io;
use std::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Convenience alias used across the crate.
pub type McpResult<T> = Result<T, McpError>;

/// JSON-RPC "parse error": the frame could not be decoded at all.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC "invalid request".
pub const INVALID_REQUEST: i64 = -32600;
/// JSON-RPC "method not found".
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC internal error.
pub const INTERNAL_ERROR: i64 = -32603;

/// Byte cap applied to every untrusted server/peer string that can reach a
/// `Display`/`Debug` implementation.
pub const MAX_UNTRUSTED_BYTES: usize = 256;

/// Remove control characters, newlines and ANSI escape sequences from `raw`,
/// neutralise any forged Auxesis wrapper marker, then truncate to at most
/// `max_bytes` without splitting a UTF-8 character.
///
/// This is **not a redactor**: a token such as `sk-live-...` survives. It only
/// bounds and cleans, so a caller must never log the raw body as well. The
/// wrapper neutralisation is shared with [`crate::descriptor`] so a server that
/// puts a copy of the provenance tag into a JSON-RPC error message cannot make
/// it look like Auxesis' own line (Step 5).
pub fn sanitize_untrusted(raw: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        // Drop a whole ANSI escape sequence, not just its ESC byte.
        if c == '\u{1b}' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    // CSI: parameters/intermediates, then a final byte 0x40..=0x7e.
                    for f in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&f) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    // OSC: run to BEL or the string terminator.
                    for f in chars.by_ref() {
                        if f == '\u{7}' || f == '\u{1b}' {
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if c.is_control() {
            continue;
        }
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    crate::descriptor::neutralise_server_text(&out)
}

/// A bounded, control-character-free copy of an untrusted string.
///
/// The only constructors run [`sanitize_untrusted`], so a raw server payload
/// cannot reach a `Display`/`Debug` implementation through this type. It is
/// **not** a redactor (see the module docs).
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Sanitized(String);

impl fmt::Debug for Sanitized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the text itself: even sanitised, it can carry a secret or an
        // injected instruction. A short hash keeps two distinct strings
        // distinguishable in a log without revealing either one.
        f.debug_struct("Sanitized")
            .field("bytes", &self.0.len())
            .field("hash", &crate::naming::short_hash(&self.0))
            .finish()
    }
}

impl Sanitized {
    /// Sanitise with the default [`MAX_UNTRUSTED_BYTES`] cap.
    pub fn new(raw: &str) -> Self {
        Self::with_cap(raw, MAX_UNTRUSTED_BYTES)
    }

    /// Sanitise with an explicit byte cap.
    pub fn with_cap(raw: &str, max_bytes: usize) -> Self {
        Self(sanitize_untrusted(raw, max_bytes))
    }

    /// The sanitised text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the sanitised `String`.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Whether the sanitised text is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Sanitized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for Sanitized {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Sanitized {
    fn from(raw: &str) -> Self {
        Self::new(raw)
    }
}

impl From<String> for Sanitized {
    fn from(raw: String) -> Self {
        Self::new(&raw)
    }
}

impl PartialEq<str> for Sanitized {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Sanitized {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl Serialize for Sanitized {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sanitized {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SanitizedVisitor;

        impl serde::de::Visitor<'_> for SanitizedVisitor {
            type Value = Sanitized;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Sanitized, E> {
                Ok(Sanitized::new(value))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Sanitized, E> {
                Ok(Sanitized::new(&value))
            }
        }

        deserializer.deserialize_str(SanitizedVisitor)
    }
}

/// A single bounded failure from the transport/client.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum McpError {
    /// A frame (response body or SSE line) crossed its configured hard bound.
    ///
    /// This is **terminal for the connection**: the reader stopped at an
    /// unknown offset, so the connection must be dropped and never resumed.
    /// See [`McpError::requires_connection_close`].
    #[error("frame exceeds the size bound: limit {limit} bytes, saw at least {seen}")]
    FrameTooLarge { limit: usize, seen: usize },
    /// The operation exceeded its per-call budget.
    #[error("operation timed out")]
    Timeout,
    /// The server answered with a non-success status.
    #[error("unexpected HTTP status {status}")]
    Http { status: u16 },
    /// A JSON-RPC error object returned by the server.
    #[error("protocol error {code} (server message {message:?})")]
    Protocol { code: i64, message: Sanitized },
    /// The byte stream failed. Only the [`io::ErrorKind`] is kept; a raw
    /// `io::Error` string can embed filesystem paths or secrets.
    #[error("i/o error: {kind:?}")]
    Io { kind: io::ErrorKind },
    /// The server did not hand back the session id this endpoint requires.
    #[error("server did not provide a session id")]
    NoSessionId,
    /// A request resolved to an origin other than the pinned one.
    #[error("origin mismatch: expected {expected}, got {got}")]
    OriginRefused { expected: Sanitized, got: Sanitized },
    /// The endpoint host shape or a resolved address was refused by the SSRF
    /// guard (`localhost`, `*.localhost`, a trailing dot, `.lan`/`.local`/
    /// `.internal`, or a private/tailnet resolution).
    #[error("endpoint address refused by the network guard")]
    AddressRefused,
    /// `tools/call` named a tool the server does not expose.
    #[error("tool not found: {0}")]
    ToolNotFound(Sanitized),
    /// A [`crate::Limits`] value was zero or outside the accepted range.
    #[error("invalid limit {field}={value}")]
    InvalidLimit { field: &'static str, value: usize },
    /// A per-request timeout or an aggregate deadline was zero or absurd.
    #[error("invalid timeout {field}={millis}ms")]
    InvalidTimeout { field: &'static str, millis: u128 },
    /// A stdio server's accumulated stdout crossed its session bound.
    ///
    /// This is **terminal for the connection** (see
    /// [`McpError::requires_connection_close`]): the reader stopped at an
    /// unknown offset, so the process must be killed, never resumed.
    #[error(
        "server output exceeds the accumulated bound: limit {limit} bytes, saw at least {seen}"
    )]
    OutputTooLarge { limit: usize, seen: usize },
    /// More requests were in flight than the configured cap allows.
    ///
    /// Terminal: the stdio transport stops the process rather than queueing an
    /// unbounded backlog.
    #[error("too many in-flight requests: limit {limit}")]
    TooManyInflight { limit: usize },
    /// The stdio server process is gone (exited, killed, or never started).
    #[error("mcp server process is not running")]
    ProcessGone,
    /// The pinned stdio command configuration is invalid.
    ///
    /// The reason is a fixed, secret-free label: an environment key or an
    /// argument value must never be echoed into an error or a log.
    #[error("invalid mcp stdio command: {reason}")]
    InvalidCommand { reason: &'static str },
}

impl McpError {
    /// Build a protocol error, sanitising the (untrusted) message.
    pub fn protocol(code: i64, message: &str) -> Self {
        Self::Protocol {
            code,
            message: Sanitized::new(message),
        }
    }

    /// A stable, content-free classification for logs, status and cards.
    ///
    /// Unlike [`Display`](std::fmt::Display) this never embeds a server-supplied
    /// string, so a caller may log it without leaking untrusted content.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::FrameTooLarge { .. } => "frame_too_large",
            Self::Timeout => "timeout",
            Self::Http { .. } => "http",
            Self::Protocol { .. } => "protocol",
            Self::Io { .. } => "io",
            Self::NoSessionId => "no_session_id",
            Self::OriginRefused { .. } => "origin_refused",
            Self::AddressRefused => "address_refused",
            Self::ToolNotFound(_) => "tool_not_found",
            Self::InvalidLimit { .. } => "invalid_limit",
            Self::InvalidTimeout { .. } => "invalid_timeout",
            Self::OutputTooLarge { .. } => "output_too_large",
            Self::TooManyInflight { .. } => "too_many_inflight",
            Self::ProcessGone => "process_gone",
            Self::InvalidCommand { .. } => "invalid_command",
        }
    }

    /// Whether the connection that produced this error must be dropped rather
    /// than reused.
    ///
    /// True for [`McpError::FrameTooLarge`] and
    /// [`McpError::OutputTooLarge`] (the reader stopped at an unknown offset),
    /// for [`McpError::TooManyInflight`] (the process is stopped as the bound's
    /// remedy) and for [`McpError::ProcessGone`]. Resuming any of them would
    /// parse the tail of an oversized frame or talk to a dead pipe.
    pub fn requires_connection_close(&self) -> bool {
        matches!(
            self,
            Self::FrameTooLarge { .. }
                | Self::OutputTooLarge { .. }
                | Self::TooManyInflight { .. }
                | Self::ProcessGone
        )
    }
}

#[cfg(test)]
mod sanitized_debug_tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_text() {
        let canary = "sk-live-CANARY_IGNORE_PRIOR_INSTRUCTIONS";
        let sanitized = Sanitized::new(canary);
        let debug = format!("{sanitized:?}");
        assert!(!debug.contains(canary), "{debug}");
        assert!(!debug.contains("CANARY"), "{debug}");
        assert!(!debug.contains("sk-live"), "{debug}");
        // The metadata stays useful: byte count plus a short, stable hash.
        assert!(debug.contains("bytes"), "{debug}");
        assert!(debug.contains("hash"), "{debug}");

        // A `Protocol` error embeds a `Sanitized`; its derived `Debug` must
        // inherit the masking.
        let error = McpError::protocol(-32000, canary);
        assert!(!format!("{error:?}").contains(canary));
    }

    #[test]
    fn debug_hash_is_stable_and_distinguishes_values() {
        assert_eq!(
            format!("{:?}", Sanitized::new("abc")),
            format!("{:?}", Sanitized::new("abc"))
        );
        assert_ne!(
            format!("{:?}", Sanitized::new("abc")),
            format!("{:?}", Sanitized::new("abd"))
        );
    }

    #[test]
    fn protocol_display_only_reports_code_and_message_metadata() {
        let canary = "SERVER_TEXT_CANARY_ignore_rules";
        let error = McpError::protocol(-32000, canary);
        let display = error.to_string();
        assert!(display.contains("-32000"), "{display}");
        assert!(display.contains("bytes"), "{display}");
        assert!(display.contains("hash"), "{display}");
        assert!(!display.contains(canary), "{display}");
    }

    #[test]
    fn protocol_message_neutralises_a_forged_provenance_tag() {
        // Same variant set the descriptor path defends against; a server error
        // message must not be able to smuggle a second provenance line.
        let forged = format!(
            "server said {}",
            crate::tools::UNTRUSTED_MCP_TAG.to_ascii_uppercase()
        );
        let error = McpError::protocol(-32000, &forged);
        match error {
            McpError::Protocol { message, .. } => {
                assert!(
                    message
                        .as_str()
                        .contains(crate::descriptor::FORGED_PROVENANCE_MARKER),
                    "{message}"
                );
                assert!(!message.as_str().contains("UNTRUSTED MCP"), "{message}");
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
        // The plain sanitiser applies the same neutralisation, including the
        // Cyrillic-homoglyph variant.
        let homoglyph = crate::tools::UNTRUSTED_MCP_TAG.replace('e', "\u{0435}");
        let cleaned = sanitize_untrusted(&homoglyph, MAX_UNTRUSTED_BYTES);
        assert!(!cleaned.contains("untrusted MCP"), "{cleaned}");
    }
}
