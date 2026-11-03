//! Every hard bound the mail connector enforces, in one place.
//!
//! The hard-bounds table lives here. A bound is **always** enforced in code:
//! a tool schema's "≤ 200" description is a hint to the model, never the
//! enforcement. Tools pass a *requested* value through the `clamp_*` helpers,
//! so a hostile or confused caller can only ever ask for less than the hard
//! bound — never more.
//!
//! [`Limits::default`] is the documented v1 posture; [`Limits::tight`]
//! is the deliberately tiny variant tests use (a 300 ms call budget, five
//! messages, 64 KiB per message) so an offline fixture exercises the caps
//! instead of the happy path.

use std::time::Duration;

/// Bytes per message before parsing (2 MiB).
///
/// A bigger message is **skipped with a marker**, never truncated silently.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// Bytes per tool call across all fetched messages (32 MiB).
pub const DEFAULT_MAX_CALL_BYTES: usize = 32 * 1024 * 1024;

/// Messages per call (200).
pub const DEFAULT_MAX_MESSAGES: usize = 200;

/// Attachment bytes a caller may be granted per attachment (25 MiB).
///
/// MA3 enabled attachment download into the local evidence registry. The value
/// is a **ceiling**: a tool request may ask for less, never more, and the blob
/// never leaves this process (it is hashed and stored under `<home>/evidence`).
pub const DEFAULT_MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Attachment bytes one call may download across every part (50 MiB).
pub const DEFAULT_MAX_CALL_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;

/// Wall clock for one whole operation (20 s).
pub const DEFAULT_CALL_TIMEOUT_SECS: u64 = 20;

/// Connect plus TLS handshake budget (8 s).
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 8;

/// Server-side search window (90 days).
pub const DEFAULT_MAX_SEARCH_DAYS: u32 = 90;

/// Concurrent mail calls per agent (2).
pub const DEFAULT_MAX_INFLIGHT_PER_AGENT: usize = 2;

/// Result bytes handed to the model by `mail_list` / `mail_search`
/// (32 KiB, below the engine's 128 KiB cap).
pub const LIST_RESULT_BYTES: usize = 32 * 1024;

/// Result bytes handed to the model by `mail_read` (64 KiB).
pub const READ_RESULT_BYTES: usize = 64 * 1024;

/// The effective hard bounds for one mail operation.
///
/// Built from [`crate::config::MailLimits`] for production, or directly from
/// [`Limits::tight`] in tests. Every field is a **ceiling**: callers may ask
/// for less, never more.
///
/// The two attachment budgets are private and set only by [`Limits::new`] and
/// [`Limits::with_attachments`], so a `Limits` built anywhere in Rust starts at
/// the documented 25 MiB / 50 MiB posture and only the config can lower it.
/// Read them through [`Limits::max_attachment_bytes`] and
/// [`Limits::max_call_attachment_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Largest single message we will parse, in bytes.
    pub max_message_bytes: usize,
    /// Largest total fetched across one call, in bytes.
    pub max_call_bytes: usize,
    /// Largest number of messages one call may return.
    pub max_messages: usize,
    /// Largest single attachment we will download, in bytes.
    max_attachment_bytes: usize,
    /// Largest total attachment bytes downloaded across one call.
    max_call_attachment_bytes: usize,
    /// Wall clock for the whole operation.
    pub call_timeout: Duration,
    /// Connect and TLS-handshake budget.
    pub connect_timeout: Duration,
    /// Newest search window, in days.
    pub max_search_days: u32,
    /// Concurrent mail calls allowed per agent.
    pub max_inflight_per_agent: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_MESSAGE_BYTES,
            DEFAULT_MAX_CALL_BYTES,
            DEFAULT_MAX_MESSAGES,
            Duration::from_secs(DEFAULT_CALL_TIMEOUT_SECS),
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            DEFAULT_MAX_SEARCH_DAYS,
            DEFAULT_MAX_INFLIGHT_PER_AGENT,
        )
    }
}

impl Limits {
    /// Build the message bounds with the documented attachment posture.
    ///
    /// The attachment budgets are not parameters: they start at
    /// [`DEFAULT_MAX_ATTACHMENT_BYTES`] and [`DEFAULT_MAX_CALL_ATTACHMENT_BYTES`]
    /// and a caller that has a config lowers them through
    /// [`Limits::with_attachments`].
    pub fn new(
        max_message_bytes: usize,
        max_call_bytes: usize,
        max_messages: usize,
        call_timeout: Duration,
        connect_timeout: Duration,
        max_search_days: u32,
        max_inflight_per_agent: usize,
    ) -> Self {
        Self {
            max_message_bytes,
            max_call_bytes,
            max_messages,
            max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
            max_call_attachment_bytes: DEFAULT_MAX_CALL_ATTACHMENT_BYTES,
            call_timeout,
            connect_timeout,
            max_search_days,
            max_inflight_per_agent,
        }
    }

    /// Lower (never raise) the two attachment budgets from a config.
    pub fn with_attachments(mut self, per_attachment: usize, per_call: usize) -> Self {
        self.max_attachment_bytes = per_attachment.min(DEFAULT_MAX_ATTACHMENT_BYTES);
        self.max_call_attachment_bytes = per_call.min(DEFAULT_MAX_CALL_ATTACHMENT_BYTES);
        self
    }

    /// The tiny bounds tests use: 64 KiB/message, 512 KiB/call, five messages,
    /// a 300 ms call budget, a 100 ms connect budget, one search day, one
    /// in-flight call, and small attachment budgets (64 KiB per attachment,
    /// 128 KiB per call) so an offline fixture can exercise the attachment
    /// caps rather than the happy path.
    pub fn tight() -> Self {
        Self::new(
            64 * 1024,
            512 * 1024,
            5,
            Duration::from_millis(300),
            Duration::from_millis(100),
            1,
            1,
        )
        .with_attachments(64 * 1024, 128 * 1024)
    }

    /// The per-attachment ceiling (25 MiB by default).
    pub fn max_attachment_bytes(&self) -> usize {
        self.max_attachment_bytes
    }

    /// The per-call attachment ceiling (50 MiB by default).
    pub fn max_call_attachment_bytes(&self) -> usize {
        self.max_call_attachment_bytes
    }

    /// Clamp a requested message count. `0` means "unset": use the hard bound.
    pub fn clamp_messages(&self, requested: usize) -> usize {
        if requested == 0 {
            self.max_messages
        } else {
            requested.min(self.max_messages)
        }
    }

    /// Clamp a requested search window. `0` means "unset": use the hard bound.
    pub fn clamp_search_days(&self, requested: u32) -> u32 {
        if requested == 0 {
            self.max_search_days
        } else {
            requested.min(self.max_search_days)
        }
    }

    /// Clamp a requested per-message byte budget to [`Self::max_message_bytes`].
    pub fn clamp_message_bytes(&self, requested: usize) -> usize {
        requested.min(self.max_message_bytes)
    }

    /// Clamp a requested attachment budget to [`Self::max_attachment_bytes`].
    ///
    /// `0` means "unset": use the ceiling, which is
    /// [`DEFAULT_MAX_ATTACHMENT_BYTES`] (25 MiB) unless a config lowered it.
    pub fn clamp_attachment_bytes(&self, requested: usize) -> usize {
        if requested == 0 {
            self.max_attachment_bytes
        } else {
            requested.min(self.max_attachment_bytes)
        }
    }

    /// Clamp a requested per-call attachment budget to
    /// [`Self::max_call_attachment_bytes`]. `0` means "unset".
    pub fn clamp_attachment_call_bytes(&self, requested: usize) -> usize {
        if requested == 0 {
            self.max_call_attachment_bytes
        } else {
            requested.min(self.max_call_attachment_bytes)
        }
    }

    /// Clamp requested result bytes to the tool's own cap. `0` means "unset":
    /// use `hard`, which itself must be one of [`LIST_RESULT_BYTES`] or
    /// [`READ_RESULT_BYTES`].
    pub fn clamp_result_bytes(&self, requested: usize, hard: usize) -> usize {
        if requested == 0 {
            hard
        } else {
            requested.min(hard)
        }
    }
}
