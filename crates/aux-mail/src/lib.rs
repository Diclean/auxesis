//! `aux-mail` — native IMAP + SMTP mailbox Connector.
//!
//! This crate owns the mailbox half of Auxesis' connector layer. It never
//! borrows the broker's logic, and shares only the workspace's `Tool` trait
//! with the rest of the connector family.
//!
//! # The one rule: mail content is data, never instructions
//!
//! Mail is the highest-volume indirect prompt-injection surface in the
//! product. Every string that came out of a mailbox — body, subject, display
//! name, folder name — is **untrusted**. It is sanitised, capped and wrapped
//! in an untrusted banner before it can reach a model, and no string that
//! came out of a mailbox can cause a mailbox write without a human saying yes.
//! The broker is the wall; the taint guard overrides any `allow` rule while
//! mail content is in context; a mail write is skill-only and approved each
//! run.
//!
//! # TLS: rustls only, one stack
//!
//! `async-imap` ships no TLS at all, so [`dial::Dialer`] wraps its stream in
//! the workspace's existing `tokio-rustls` (`ring` provider, the same family
//! `reqwest` uses). `lettre` runs with `default-features = false` because its
//! default set pulls `native-tls`/OpenSSL. There is deliberately no
//! "ignore the certificate" switch; the one production `ClientConfig` is built
//! once from `webpki-roots` in [`tlsutil`].
//!
//! # Offline first
//!
//! No test in this crate opens a socket to a real mail server, and the real
//! macOS Keychain is never touched. A hand-rolled in-process fake IMAP + fake
//! SMTP pair, bound to `127.0.0.1:0`, covers the wire protocol; it now lives in
//! the `aux-fakemail` crate, which this crate's dev-dependencies link.
//!
//! # Slice status
//!
//! M1 + M1b + M2 + M2b (presets, error vocabulary, dial/TLS, the fakes) landed
//! first. M3 + M4 (the read path, `folders`/`parse`/`sanitize`) land here too:
//! [`MailService`] lists, searches, threads and reads, and every returned
//! string is sanitised and banner-wrapped before a model can see it. The tools
//! and the SMTP path land in later slices, each behind its own work order.

pub mod config;
pub mod dial;
pub mod direction;
pub mod discover;
pub mod error;
pub mod folders;
mod guard;
pub mod ics;
mod imap_query;
pub mod imap_read;
pub mod limits;
pub mod mailbox;
pub mod parse;
pub mod presets;
pub mod sanitize;
pub mod send;
pub mod smtp;
pub mod tlsutil;
pub mod tools;

mod b64;

pub use config::{
    is_account_slug, FolderMap, ImapSettings, MailAccount, MailConfig, MailLimits, Security,
    SmtpSettings,
};
pub use dial::{AsyncReadWrite, BoxedStream, Dialer};
pub use direction::{mail_direction, EnvelopeDirection, MailDirection};
pub use error::{Lang, MailError, UserMessage};
pub use folders::{canonical_name, Folder};
pub use ics::{build_request_ics, IcsError, Invite};
pub use imap_read::{
    attachment_mime_allowed, days_ago_date, Credentials, DownloadedAttachment, EnvCredentials,
    EnvelopeItem, FetchedAttachments, ListQuery, MailService, RawMail, SearchQuery,
    SkippedAttachment, MAX_HEADER_SCAN,
};
pub use limits::{
    Limits, DEFAULT_CALL_TIMEOUT_SECS, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_MAX_ATTACHMENT_BYTES,
    DEFAULT_MAX_CALL_ATTACHMENT_BYTES, DEFAULT_MAX_CALL_BYTES, DEFAULT_MAX_INFLIGHT_PER_AGENT,
    DEFAULT_MAX_MESSAGES, DEFAULT_MAX_MESSAGE_BYTES, DEFAULT_MAX_SEARCH_DAYS, LIST_RESULT_BYTES,
    READ_RESULT_BYTES,
};
pub use parse::{parse_message, AttachmentMeta, MailItem};
pub use presets::{all_presets, preset, Endpoint, Preset};
pub use sanitize::{fence_quoted, render_envelopes, render_untrusted, UNTRUSTED_MAIL_TAG};
pub use send::{compose, validate as validate_mail, OutgoingMail, SendOutcome};
pub use tools::{
    Draft, DraftSink, EvidenceAttachment, EvidenceRef, EvidenceSink, MailApi, MailToolset,
};
