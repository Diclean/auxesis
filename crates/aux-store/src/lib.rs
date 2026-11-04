//! Persistence layer for Auxesis: the SQLite store and its migrations.
//!
//! The schema is versioned and built by additive, idempotent migrations:
//! v1 is the M0 baseline (`meta` + `events`), v2 adds chat `sessions` and
//! their `messages`, v3 adds scheduled `jobs` and their `runs`, and v4 adds
//! the `usage` meter that backs the per-agent budgets. v5 adds the atomic
//! spend `usage_reservations` (check-and-reserve in one `BEGIN IMMEDIATE`
//! transaction) and a day index on `usage`. v6 adds `budget_stops`, the
//! per-agent/day fail-closed latch written when a completed call reaches a cap
//! (so a provider that ignores its completion cap cannot cause unbounded
//! further spend). v7 adds the `sessions.kind` column and backfills historical
//! `job <name>` transcripts. v8 records `sessions_kind_legacy_max_id`, the
//! highest session id that existed when the durable `kind` column became the
//! authority: sessions at or below it may still need the legacy `job <name>`
//! title heuristic, sessions created after it never do (RV2-05). v9 records
//! WS-C taint marks: `workspace_taint` is the sticky workspace-level mark
//! (written before an untrusted-class call runs, cleared only by the owner)
//! and `session_taint` is the per-conversation write-ahead mark that makes a
//! cancelled or crashed turn resume tainted. v10 repairs stores that recorded
//! the amended v9 (which was edited in place during the WS-C redesign, so a
//! `ws-c-1`/`ws-c-2`-shaped store at version 9 never got `session_taint`) and
//! adds `trust_requests`: the pending owner-presence proof behind
//! `aux workspace trust` — a hashed one-time code, never the code itself.
//! Migrations are additive: a v1 database walks up through v2…v10 in one
//! `open()`.

use kernel_core::budget::{
    warning_threshold, AuditSink, BudgetCaps, BudgetError, Denial, DenialReason, Reservation,
    ReservationLedger, ReserveOutcome, UsageActual, UsageKind, UsageLedger, UsageTotals,
    ESTIMATED_UNIT, RESERVATION_TTL,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

mod audit;
mod channels;
mod contacts;
mod delegation;
mod document_fields;
mod drafts;
mod encryption;
mod evidence;
mod jobs;
mod mcp;
mod memory;
mod migrations;
mod parties;
mod sessions;
mod taint;
mod usage;
mod usage_calls;

#[cfg(test)]
mod testutil;

pub use contacts::{contacts_snapshot_at, contacts_version_at, ContactRecord, ContactsSnapshot};
pub use delegation::{Delegation, DelegationState, DelegationStep};
pub use document_fields::{
    erased_document_texts, evidence_lifecycle_lock, scrub_erased_echo, ClaimedDocument,
    DocumentEraseResult, DocumentExtraction, DocumentListRow, DocumentRef, ExportDocument,
    NewDocumentFields, StoredDocumentText, UnlinkedDocument, UnprocessedDocument,
    DOCUMENT_EXTRACTORS, DOCUMENT_EXTRACT_STATES, DOCUMENT_FIELD_KINDS, DOCUMENT_STATUSES,
    DOCUMENT_TEXT_MAX_BYTES, DOCUMENT_UNAVAILABLE_TEXT, EXTRACT_CLAIM_TIMEOUT_SECS,
    EXTRACT_MAX_ATTEMPTS,
};
pub use drafts::StoredDraft;
pub use encryption::{
    evidence_key, open_evidence, open_keyed, open_keyed_readonly, seal_evidence, store_key,
    vault_key, Key,
};
pub use sessions::not_ever_private_session;
pub use usage_calls::{UsageCall, UsageCallTotals};

/// Current schema version. Bump when adding migrations.
pub const SCHEMA_VERSION: i64 = 37;

/// Maximum bytes in a memory item title (UTF-8 encoded).
pub const MEMORY_TITLE_MAX_BYTES: usize = 1024;
/// Maximum bytes in a memory item body (UTF-8 encoded).
pub const MEMORY_BODY_MAX_BYTES: usize = 16 * 1024;
/// Maximum bytes in per-item provenance and key metadata.
pub const MEMORY_METADATA_MAX_BYTES: usize = 1024;
/// Maximum agent identifier size accepted by memory operations.
pub const MEMORY_AGENT_MAX_BYTES: usize = 128;
/// Maximum active and inactive memory rows per agent.
pub const MEMORY_ITEMS_PER_AGENT_MAX: i64 = 10_000;
/// Maximum stored title/body bytes per agent.
pub const MEMORY_BYTES_PER_AGENT_MAX: i64 = 50 * 1024 * 1024;
/// Maximum title/body bytes returned by one memory read or search.
pub const MEMORY_RESPONSE_MAX_BYTES: usize = 64 * 1024;
/// Maximum pending memory suggestions per agent.
pub const MEMORY_SUGGESTIONS_PER_AGENT_MAX: usize = 6;
/// The `source` prefix an accepted suggestion from outside content carries,
/// followed by `:` and the suggestion's `source_ref` (MEM-SUGGEST-TRUST).
/// The daemon renders it as its own label and keeps the ref on the item.
pub const ACCEPTED_OUTSIDE_SUGGESTION: &str = "accepted_outside_suggestion";

/// Maximum bytes in a CRM party display name.
pub const PARTY_NAME_MAX_BYTES: usize = 512;
/// Maximum entries in one party JSON list (variants, e-mails, phones, addresses, tags).
pub const PARTY_LIST_MAX: usize = 256;
/// Maximum bytes in CRM party notes.
pub const PARTY_NOTES_MAX_BYTES: usize = 16 * 1024;
/// Maximum bytes in an interaction summary.
pub const INTERACTION_SUMMARY_MAX_BYTES: usize = 500;

/// Most jobs one [`Store::claim_due_jobs`] call claims (F-17).
///
/// The scheduler tick runs every 30 s and fire-and-forgets one blocking task
/// per claimed job; an unbounded claim would start one engine turn per due
/// row at once (provider calls, tool executions). Each claimed job's lease
/// moves its `next_run_at` forward, so the next tick picks up the remainder.
pub const CLAIM_BATCH_LIMIT: i64 = 32;

/// Run status while a job is executing.
pub const RUN_RUNNING: &str = "running";
/// Run status for a job that finished successfully.
pub const RUN_OK: &str = "ok";
/// Run status for a job whose runner reported a failure.
pub const RUN_FAILED: &str = "failed";
/// Run status for a run that was still `running` when the daemon restarted.
pub const RUN_INTERRUPTED: &str = "interrupted";

/// Maximum bytes of an MCP tool/server/toolkit **name** accepted by
/// [`Store::upsert_mcp_tools`] (server, remote name, wire name, toolkit).
pub const MCP_TOOL_NAME_MAX_BYTES: usize = 128;

/// Maximum bytes of a cached MCP tool description.
pub const MCP_TOOL_DESCRIPTION_MAX_BYTES: usize = 512;

/// Maximum bytes of a cached MCP tool JSON schema.
pub const MCP_TOOL_SCHEMA_MAX_BYTES: usize = 16 * 1024;

/// Maximum bytes of the canonical descriptor JSON and its tags blob.
pub const MCP_TOOL_DESCRIPTOR_MAX_BYTES: usize = 24 * 1024;
/// Maximum bytes of the compact tags JSON.
pub const MCP_TOOL_TAGS_MAX_BYTES: usize = 4 * 1024;

/// Maximum cached tool rows for one server (a refresh replaces a server's
/// whole tool set; this bounds a runaway one).
pub const MCP_TOOLS_PER_SERVER_MAX: i64 = 500;

/// Maximum cached tool rows across the whole table.
pub const MCP_TOOLS_TOTAL_MAX: i64 = 5000;

/// Largest accepted cache TTL (one year, in seconds).
pub const MCP_TOOL_TTL_MAX_SECONDS: i64 = 365 * 24 * 60 * 60;

/// How far `fetched_at` may lead the store's clock before
/// [`Store::upsert_mcp_tools`] refuses it. A cache row stamped in the future
/// would never satisfy the TTL prune (`fetched_at + ttl` stays ahead of
/// `now`), so the cap could never free it; five minutes absorbs ordinary clock
/// skew between the fetcher and the store.
pub const MCP_TOOL_FUTURE_SKEW_SECONDS: i64 = 5 * 60;

/// Maximum provider-legal MCP tool wire name length.
const MCP_TOOL_WIRE_NAME_MAX_BYTES: usize = 64;

/// Errors returned by the store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Underlying SQLite error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Filesystem error (creating the parent directory).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The store was written by a newer Auxesis build: never downgrade it.
    #[error("store schema v{found} is newer than supported v{supported}")]
    SchemaTooNew {
        /// Version found on disk.
        found: i64,
        /// Version this build supports.
        supported: i64,
    },
    /// A job id did not resolve to a row.
    #[error("job {id} not found")]
    JobNotFound {
        /// Requested job id.
        id: i64,
    },
    /// A run id did not resolve to a row.
    #[error("run {id} not found")]
    RunNotFound {
        /// Requested run id.
        id: i64,
    },
    /// A usage record failed validation before it was written.
    #[error("invalid usage record: {reason}")]
    InvalidUsage {
        /// What was wrong.
        reason: String,
    },
    /// A cached MCP tool descriptor was refused (oversize, missing field or a
    /// row cap) before anything was written.
    #[error("mcp tool cache rejected the write: {reason}")]
    McpToolRejected {
        /// What was wrong.
        reason: String,
    },
    /// A memory item was rejected before any bytes were committed.
    #[error("memory item rejected: {reason}")]
    MemoryRejected { reason: String },
    /// An agent already has the maximum number of pending memory suggestions.
    #[error("memory suggestion limit reached")]
    MemorySuggestionLimitReached,
    /// A CRM row was rejected before any bytes were written.
    #[error("crm row rejected: {reason}")]
    CrmRejected {
        /// What was wrong.
        reason: String,
    },
    /// An evidence-registry append was rejected before any row was written.
    #[error("evidence rejected: {reason}")]
    EvidenceRejected {
        /// What was wrong.
        reason: String,
    },
    /// A delegation id did not resolve to a row.
    #[error("delegation {id} not found")]
    DelegationNotFound {
        /// Requested delegation id.
        id: String,
    },
    /// A `document_fields` write or queue transition was rejected before any
    /// row changed (C2b).
    #[error("document fields rejected: {reason}")]
    DocumentFieldsRejected {
        /// What was wrong.
        reason: String,
    },
    /// The store is encrypted but its `master.key` is gone.
    #[error("the store's master key is missing; the encrypted store cannot be opened")]
    KeyMissing,
    /// `master.key` (or a legacy key file) is a symlink, is not a regular file,
    /// or is readable by others. Nothing is followed or tightened: the owner
    /// fixes it.
    #[error("store key material is not private (symlink, not a regular file, or readable by others); refusing to open the store")]
    KeyFilesUnsafe,
    /// The store directory is a symlink, is not owned by this user, or can be written
    /// by others. Nothing is followed or tightened: the owner fixes it.
    #[error("store directory is unsafe (symlink, another owner, or writable by others); refusing to open the store")]
    StoreDirUnsafe,
    /// The key files do not unlock the store (wrong, damaged or swapped keys).
    #[error("store key does not unlock the store; refusing to open it")]
    KeyRejected,
    /// A read-only opener met a plaintext store. Only `Store::open` migrates.
    #[error("store is not encrypted yet; start the daemon once to migrate it")]
    NotEncrypted,
    /// The one-time plaintext to encrypted migration was refused or failed
    /// verification. The plaintext store is left in place.
    #[error("store migration refused: {reason}")]
    StoreMigration { reason: String },
}

/// Data for a new memory row. `agent` is passed separately to every method;
/// trust and taint are stamped by the trusted engine/store caller.
#[derive(Debug, Clone, PartialEq)]
pub struct NewMemoryItem<'a> {
    pub kind: &'a str,
    pub title: &'a str,
    pub body: &'a str,
    pub fact_key: Option<&'a str>,
    pub confidence: Option<f64>,
    pub source: &'a str,
    pub trust: &'a str,
    pub tainted: bool,
    pub state: &'a str,
    pub supersedes_id: Option<i64>,
    pub valid_from: Option<&'a str>,
    pub valid_to: Option<&'a str>,
}

/// A memory item returned by the store.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryItem {
    pub id: i64,
    pub agent: String,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub fact_key: Option<String>,
    pub confidence: Option<f64>,
    pub source: String,
    pub trust: String,
    pub tainted: bool,
    pub supersedes_id: Option<i64>,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub content_hash: String,
}

/// A pending or decided suggestion derived from outside content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySuggestion {
    pub id: i64,
    pub body: String,
    pub fact_key: Option<String>,
    pub trust: String,
    pub created_at: String,
    /// Where the proposal came from (a run identity, or a tool-supplied ref).
    pub source_ref: String,
}

/// A chat session between the user and one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Row id.
    pub id: i64,
    /// Agent this session belongs to.
    pub agent: String,
    /// Optional human-readable title.
    pub title: Option<String>,
    /// Creation timestamp (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub created_at: String,
    /// Last-activity timestamp, bumped by [`Store::append_message`].
    pub updated_at: String,
}

/// One persisted chat message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Row id; also the ordering key inside a session.
    pub id: i64,
    /// Session this message belongs to.
    pub session_id: i64,
    /// Chat role (`system`, `user`, `assistant`, `tool`, …).
    pub role: String,
    /// Message body.
    pub content: String,
    /// Creation timestamp (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub created_at: String,
    /// Optional JSON metadata (tool call id, token usage, …).
    pub meta: Option<String>,
}

/// A scheduled job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Row id.
    pub id: i64,
    /// Agent that owns the job.
    pub agent: String,
    /// Human-readable name.
    pub name: String,
    /// Raw schedule string (`every 15m`, `daily 08:30`, …), parsed by the
    /// scheduler via `kernel_core::job::Schedule`.
    pub schedule: String,
    /// JSON payload handed to the runner.
    pub payload: String,
    /// Whether the scheduler may claim this job.
    pub enabled: bool,
    /// Creation timestamp (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub created_at: String,
    /// Last time a run was scheduled for this job.
    pub last_run_at: Option<String>,
    /// Next time the job becomes due; `NULL` means "due immediately".
    pub next_run_at: Option<String>,
}

/// One execution of a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// Row id.
    pub id: i64,
    /// Job that was run.
    pub job_id: i64,
    /// Start timestamp (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub started_at: String,
    /// Finish timestamp; `None` while the run is still `running`.
    pub finished_at: Option<String>,
    /// One of [`RUN_RUNNING`], [`RUN_OK`], [`RUN_FAILED`], [`RUN_INTERRUPTED`].
    pub status: String,
    /// Short outcome text (runner summary, error message, …).
    pub summary: Option<String>,
}

/// One recorded usage amount for an agent (provider call, run, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRecord {
    /// Row id.
    pub id: i64,
    /// Agent that spent the resource.
    pub agent: String,
    /// Local timestamp (`YYYY-MM-DD HH:MM:SS`).
    pub at: String,
    /// Resource dimension, as [`UsageKind::as_str`].
    pub kind: String,
    /// Amount spent (tokens or cents).
    pub amount: i64,
    /// Unit of `amount` (`tokens`, `cents`, `tokens_est`, …).
    pub unit: String,
}

/// One conversation's write-ahead taint mark (v9).
///
/// Written *before* an untrusted-class tool call runs, so a cancelled,
/// killed, timed-out or crashed turn still resumes tainted. The first mark
/// for a session is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTaint {
    /// Tool whose dispatch marked the conversation.
    pub tool: String,
    /// Origin detail (URL, host, …), when known.
    pub detail: Option<String>,
}

/// A pending owner trust request (v10).
///
/// This is the store half of the owner-presence proof behind
/// `aux workspace trust`: it never contains the one-time code, only the salt
/// and hash the verifier compares against. The code itself travels only
/// through the owner's local notification channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRequest {
    /// Public id correlating the request's audit rows (not a secret).
    pub request_id: String,
    /// Salted KDF hash of the one-time code (never the code).
    pub code_hash: Vec<u8>,
    /// Random per-request salt.
    pub salt: Vec<u8>,
    /// Unix seconds when the request was created.
    pub created_at: i64,
    /// How many wrong codes have been submitted for this request.
    pub attempts: i64,
}

/// The verifier half of a pending owner trust request (v10).
///
/// Carries the public request id, the salted KDF hash and the salt — never
/// the one-time code, which only travels through the owner's notification
/// channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTrustRequest {
    /// Public id correlating the request's audit rows (not a secret).
    pub request_id: String,
    /// Salted KDF hash of the one-time code (never the code).
    pub code_hash: Vec<u8>,
    /// Random per-request salt.
    pub salt: Vec<u8>,
}

/// Outcome of [`Store::put_trust_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutTrustOutcome {
    /// A pending request is in place (created or refreshed).
    Stored,
    /// Another request was made too recently; no new request was stored.
    RateLimited {
        /// Seconds until a new request is accepted.
        retry_after_secs: i64,
    },
}

/// One cached MCP tool descriptor (v15).
///
/// This is **plain descriptor data** — server, remote/wire names, toolkit,
/// description, schema, tags, the canonical descriptor JSON, risk and cache
/// lifetime. There is deliberately no field for an API key, token or other
/// credential: the store never persists one, and S2b exposes no method that
/// could receive one. Sizes are enforced by [`Store::upsert_mcp_tools`].
///
/// **Read-side contract.** The `*_json` fields are stored verbatim after only
/// a JSON *syntax* check at upsert (plus the byte caps); the store never
/// re-validates them on read. Callers — the S3 adapter — must parse and
/// sanitise `schema_json`, `descriptor_json` and `tags_json` before any of it
/// reaches the model or a broker, and must treat the parsed shapes as
/// untrusted. The cache is also not the spend authority: the row caps here and
/// the `connector_calls` cap are enforced from S3 only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolRecord {
    /// MCP server this descriptor belongs to (its server id).
    pub server: String,
    /// Upstream tool name (the stable key inside `server`).
    pub remote_name: String,
    /// Auxesis wire name (`mcp__…`) the adapter dispatches under. On reads this
    /// is the store-derived canonical name; [`Store::upsert_mcp_tools`] ignores
    /// the caller's value and rejects identities that collide after naming.
    pub wire_name: String,
    /// Toolkit slug the descriptor was classified into (`crm`, `elevenlabs`…).
    pub toolkit: String,
    /// Sanitised, display-safe description.
    pub description: String,
    /// The tool's JSON schema, serialized. Stored verbatim; **not**
    /// re-validated on read — S3 must parse and sanitise it before use.
    pub schema_json: String,
    /// Risk tags, serialized (`descriptor` JSON array or `[]`). Stored
    /// verbatim; **not** re-validated on read.
    pub tags_json: String,
    /// The canonical descriptor JSON (the exact bytes S2 produced). Stored
    /// verbatim; **not** re-validated on read — S3 must parse and sanitise it
    /// before use.
    pub descriptor_json: String,
    /// Risk class (`low`, `medium`, `high`).
    pub risk: String,
    /// Why that risk was assigned (tag table / untagged).
    pub risk_basis: String,
    /// When the descriptor was fetched upstream (`YYYY-MM-DD HH:MM:SS`).
    /// Round-trip validated at upsert, and refused when it leads the store's
    /// clock by more than [`MCP_TOOL_FUTURE_SKEW_SECONDS`].
    pub fetched_at: String,
    /// Cache lifetime in seconds (`> 0`, at most [`MCP_TOOL_TTL_MAX_SECONDS`]).
    pub ttl_seconds: i64,
}

/// `meta` key prefix for senders the owner declined to add as prospects.
const IGNORED_SENDER_PREFIX: &str = "prospect-ignored:";
/// Most ignored senders kept.
const IGNORED_SENDERS_MAX: i64 = 10_000;

/// v8: the legacy-session watermark (RV2-05).
///
/// The `job <name>` title heuristic exists only for sessions that predate the
/// durable `kind` column; a session created after that column became the
/// authority always has an explicit kind and must never be hidden by a title
/// collision. `meta.sessions_kind_legacy_max_id` stores the highest session id
/// present when this migration ran, so the cutoff is clock-free (two rows
/// created in the same second are still ordered). Idempotent: applied only
/// when the key is absent, inside the same `IMMEDIATE` transaction as v7.
pub const META_SESSION_LEGACY_MAX_ID: &str = "sessions_kind_legacy_max_id";

/// NEW-CHAT-1: `meta` key prefix (`chat_new:<agent>`): the session the last `/new` started.
pub const META_CHAT_NEW_PREFIX: &str = "chat_new:";

/// AGENT-HISTORY-BLEED: the `channel_sessions` channel that binds a delegated
/// agent's thread to the chief thread that asked (`<chief session>:<agent>`).
pub const DELEGATE_CHANNEL: &str = "delegate";

/// Remove the v29/v30 document additions when an upgrade test forges an older
/// schema version from a fresh store. Real old stores never contain these
/// triggers or tables; leaving them behind makes SQLite reject dropped text
/// columns before the historical migration path can run.
#[cfg(test)]
pub(crate) fn remove_document_text_additions_for_legacy_fixture(
    conn: &Connection,
) -> rusqlite::Result<()> {
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS document_fields_text_flag_insert;
         DROP TRIGGER IF EXISTS document_fields_text_flag_update;
         DROP TRIGGER IF EXISTS documents_delete_requires_erasure;
         DROP TRIGGER IF EXISTS proofs_append_only_delete;
         DROP TRIGGER IF EXISTS corrections_append_only_delete;
         DROP TRIGGER IF EXISTS evidence_source_append_only_delete;
         DROP INDEX IF EXISTS document_fields_nonempty_text;
         DROP TABLE IF EXISTS document_text_backfill;
         DROP TABLE IF EXISTS evidence_erase_tombstones;
         ALTER TABLE document_fields DROP COLUMN has_extracted_text;
         ALTER TABLE document_fields DROP COLUMN extracted_text;",
    )
}

/// Most `(token, value)` pairs one session keeps; later ones are not stored.
pub const MAX_SESSION_TOKENS: i64 = 4_096;

/// The source tag the CRM writes its parties under in the `contacts` table.
/// The union of the enabled sources mounts it like any other contact list, so
/// a party write is tokenised in the next provider call.
pub const CRM_CONTACT_SOURCE: &str = "crm";

/// One original to append to the evidence registry.
///
/// The bytes themselves live outside SQLite under `<home>/evidence/<sha256>`;
/// this struct carries only what the `documents` row stores. `content_hash` is
/// the lowercase SHA-256 hex the caller already computed from the bytes.
pub struct NewEvidenceDocument<'a> {
    /// Lowercase SHA-256 hex of the original bytes.
    pub content_hash: &'a str,
    /// Relative blob path (`evidence/<sha256>`), frozen by trigger.
    pub storage_path: &'a str,
    /// Original size in bytes.
    pub size_bytes: i64,
    /// Declared MIME type.
    pub mime_type: &'a str,
    /// Sender-declared file name.
    pub original_name: &'a str,
    /// Account the original came from.
    pub account_id: &'a str,
    /// When it was captured (RFC 3339 or SQLite datetime).
    pub captured_at: &'a str,
}

/// The result of one [`Store::append_evidence`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceAppend {
    /// `documents.id` of the original (new or already known).
    pub document_id: i64,
    /// True when the hash was already registered: no second document row.
    pub duplicate: bool,
}

/// The kind of a CRM party (`party.kind`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PartyKind {
    /// A natural person, whose names feed the contacts index.
    #[default]
    Person,
    /// A company; its name is still a known name (a supplier, a client).
    Company,
}

impl PartyKind {
    /// The stored spelling (`person` / `company`).
    pub fn as_str(self) -> &'static str {
        match self {
            PartyKind::Person => "person",
            PartyKind::Company => "company",
        }
    }

    /// Parse a stored spelling.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "person" => Some(PartyKind::Person),
            "company" => Some(PartyKind::Company),
            _ => None,
        }
    }
}

/// The fields of a new CRM party. `id`, `created_at` and `updated_at` are the
/// store's; `archived` starts false.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewParty {
    /// Person or company.
    pub kind: PartyKind,
    /// The name shown on the card.
    pub display_name: String,
    /// Every other spelling the contacts index must tokenise.
    pub name_variants: Vec<String>,
    /// E-mail addresses, lower-case.
    pub emails: Vec<String>,
    /// Phone numbers in E.164 (`+` and digits).
    pub phones: Vec<String>,
    /// Postal addresses, as written by the owner.
    pub addresses: Vec<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Owner notes; never a mail body.
    pub notes: String,
    /// The client's IANA time zone (`Europe/Paris`), when the card carries one.
    /// It is not inferred: a vCard `TZ:` or the owner sets it.
    pub time_zone: Option<String>,
    /// Where the party came from (`owner`, `contacts:<source>`, `mail:<account>`).
    pub origin: String,
}

/// A stored CRM party.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Party {
    /// Row id.
    pub id: i64,
    /// Person or company.
    pub kind: PartyKind,
    /// The name shown on the card.
    pub display_name: String,
    /// Every other spelling the contacts index tokenises.
    pub name_variants: Vec<String>,
    /// E-mail addresses, lower-case.
    pub emails: Vec<String>,
    /// Phone numbers in E.164.
    pub phones: Vec<String>,
    /// Postal addresses.
    pub addresses: Vec<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Owner notes.
    pub notes: String,
    /// The client's IANA time zone, when the card carries one.
    pub time_zone: Option<String>,
    /// Where the party came from.
    pub origin: String,
    /// Creation timestamp (UTC).
    pub created_at: String,
    /// Last-write timestamp (UTC).
    pub updated_at: String,
    /// An archived party keeps its rows but leaves the contacts index.
    pub archived: bool,
}

impl From<&Party> for NewParty {
    fn from(party: &Party) -> Self {
        Self {
            kind: party.kind,
            display_name: party.display_name.clone(),
            name_variants: party.name_variants.clone(),
            emails: party.emails.clone(),
            phones: party.phones.clone(),
            addresses: party.addresses.clone(),
            tags: party.tags.clone(),
            notes: party.notes.clone(),
            time_zone: party.time_zone.clone(),
            origin: party.origin.clone(),
        }
    }
}

/// One timeline row (`interaction`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interaction {
    /// Row id.
    pub id: i64,
    /// The party the interaction belongs to.
    pub party_id: i64,
    /// `mail`, `meeting`, `call`, `note` or `document`.
    pub kind: String,
    /// When it happened (UTC).
    pub at: String,
    /// JSON source reference (IMAP mailbox/uid, EventKit id, document hash).
    pub source_ref: String,
    /// A short summary written locally; never a mail body.
    pub summary: String,
    /// The skill reference or `owner`.
    pub provenance: String,
    /// Mail direction: `in` (from the client) or `out` (from the owner).
    /// `None` for non-mail rows.
    pub direction: Option<String>,
    /// Written from outside content while the turn was tainted. The card may
    /// show it to the owner, marked; the model gets a neutral placeholder.
    pub tainted: bool,
}

/// One follow-up row (`followup`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Followup {
    /// Row id.
    pub id: i64,
    /// The party the follow-up belongs to.
    pub party_id: i64,
    /// Due date or timestamp.
    pub due: String,
    /// Why it is due.
    pub reason: String,
    /// The skill reference or `owner`.
    pub created_by: String,
    /// `open`, `done` or `dropped`.
    pub status: String,
}

/// One open follow-up with the party it belongs to (B4): the shape the
/// `brief` skill's "follow-ups due" section needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueFollowup {
    /// The party the follow-up belongs to.
    pub party_id: i64,
    /// The live party's display name.
    pub display_name: String,
    /// The follow-up row.
    pub followup: Followup,
}

/// One relationship row (`relationship`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    /// Row id.
    pub id: i64,
    /// The party on the near side.
    pub from_party: i64,
    /// The party on the far side.
    pub to_party: i64,
    /// `works_at`, `reports_to`, `invoices` or `other`.
    pub kind: String,
    /// Start date, if any.
    pub since: Option<String>,
    /// End date, if any.
    pub until: Option<String>,
    /// A short note.
    pub note: String,
}

/// A JSON array of strings, as it is stored in a party list column.
fn json_list(values: &[String]) -> String {
    serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string())
}

/// Read one party list column; a malformed blob is a conversion error, never a panic.
fn crm_from_json(raw: String, column: usize) -> rusqlite::Result<Vec<String>> {
    serde_json::from_str(&raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(err),
        )
    })
}

/// Read one `party` row.
fn read_party(row: &rusqlite::Row<'_>) -> rusqlite::Result<Party> {
    let kind = PartyKind::parse(&row.get::<_, String>(1)?).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other("unknown party kind")),
        )
    })?;
    Ok(Party {
        id: row.get(0)?,
        kind,
        display_name: row.get(2)?,
        name_variants: crm_from_json(row.get(3)?, 3)?,
        emails: crm_from_json(row.get(4)?, 4)?,
        phones: crm_from_json(row.get(5)?, 5)?,
        addresses: crm_from_json(row.get(6)?, 6)?,
        tags: crm_from_json(row.get(7)?, 7)?,
        notes: row.get(8)?,
        time_zone: row.get(13)?,
        origin: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        archived: row.get::<_, i64>(12)? != 0,
    })
}

/// Append every value of `source` that `target` does not hold yet.
fn extend_unique(target: &mut Vec<String>, source: &[String]) {
    for value in source {
        if !target.iter().any(|existing| existing == value) {
            target.push(value.clone());
        }
    }
}

/// The `contacts` row the index reads for one party: the display name and every
/// variant are names, the e-mails and E.164 phones are identifiers. The variants
/// go in `nicknames` because [`super::contacts`] keeps every nickname as its own
/// known form, and the union mount indexes it without a second CRM path.
fn party_contacts(party: &Party) -> ContactRecord {
    let mut names: Vec<String> = Vec::with_capacity(party.name_variants.len() + 1);
    names.push(party.display_name.clone());
    extend_unique(&mut names, &party.name_variants);
    ContactRecord {
        source: CRM_CONTACT_SOURCE.to_string(),
        display_name: Some(party.display_name.clone()),
        given: Vec::new(),
        family: Vec::new(),
        nicknames: names,
        emails: party.emails.clone(),
        phones: party.phones.clone(),
        time_zone: party.time_zone.clone(),
    }
}

/// The live (non-archived) parties, read through an open transaction.
fn read_live_parties(tx: &Transaction<'_>) -> Result<Vec<Party>, StoreError> {
    let mut statement = tx.prepare(
        "SELECT id, kind, display_name, name_variants, emails, phones, addresses,
                tags, notes, origin, created_at, updated_at, archived, time_zone
           FROM party WHERE archived = 0 ORDER BY id",
    )?;
    let rows = statement.query_map([], read_party)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Rebuild the `crm` contacts source inside `tx`, so a party write and the
/// index the kernel mounts commit or roll back together. Every store party
/// write calls this; the store cannot be bypassed by a direct caller.
fn sync_crm_contacts_in_tx(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let records: Vec<ContactRecord> = read_live_parties(tx)?.iter().map(party_contacts).collect();
    crate::contacts::replace_source_contacts_in_tx(tx, CRM_CONTACT_SOURCE, &records)
}

/// Whether `raw` is an E.164 number: `+`, 8 to 15 digits, no leading zero.
fn is_e164(raw: &str) -> bool {
    let Some(digits) = raw.strip_prefix('+') else {
        return false;
    };
    (8..=15).contains(&digits.len())
        && !digits.starts_with('0')
        && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Validate one new party before any row is written.
fn validate_party(party: &NewParty) -> Result<(), StoreError> {
    if party.display_name.trim().is_empty() || party.display_name.len() > PARTY_NAME_MAX_BYTES {
        return Err(StoreError::CrmRejected {
            reason: "invalid display name size".into(),
        });
    }
    if party.origin.trim().is_empty() {
        return Err(StoreError::CrmRejected {
            reason: "origin is empty".into(),
        });
    }
    for (label, values) in [
        ("name variants", &party.name_variants),
        ("emails", &party.emails),
        ("phones", &party.phones),
        ("addresses", &party.addresses),
        ("tags", &party.tags),
    ] {
        if values.len() > PARTY_LIST_MAX {
            return Err(StoreError::CrmRejected {
                reason: format!("{label} list over {PARTY_LIST_MAX} entries"),
            });
        }
    }
    if party.notes.len() > PARTY_NOTES_MAX_BYTES {
        return Err(StoreError::CrmRejected {
            reason: "notes over the size cap".into(),
        });
    }
    if party.time_zone.as_ref().is_some_and(|zone| zone.len() > 64) {
        return Err(StoreError::CrmRejected {
            reason: "time zone over the size cap".into(),
        });
    }
    for phone in &party.phones {
        if !is_e164(phone) {
            return Err(StoreError::CrmRejected {
                reason: "a phone is not E.164".into(),
            });
        }
    }
    Ok(())
}

/// Validate an interaction before it is written.
fn validate_interaction(kind: &str, summary: &str) -> Result<(), StoreError> {
    if !matches!(kind, "mail" | "meeting" | "call" | "note" | "document") {
        return Err(StoreError::CrmRejected {
            reason: "unknown interaction kind".into(),
        });
    }
    if summary.len() > INTERACTION_SUMMARY_MAX_BYTES {
        return Err(StoreError::CrmRejected {
            reason: "interaction summary over the size cap".into(),
        });
    }
    Ok(())
}

/// The Auxesis store.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    /// The verified home the store lives in (`<home>/export/` is written
    /// there by the v19 invoice export). `None` for in-memory stores.
    export_home: Option<PathBuf>,
}

/// A store handle the broker/engine can own or borrow (E-18).
///
/// `Borrowed` keeps the CLI, scheduled jobs and tests zero-cost; `Shared`
/// lets the daemon hand the turn an `Arc<Mutex<Store>>` it owns, so a future
/// holds a shareable handle instead of a borrow of the caller's store.
#[derive(Clone)]
pub enum StoreHandle<'a> {
    /// Borrow a store owned by the caller (CLI, job runner, tests).
    Borrowed(&'a Store),
    /// Share an owned store (the daemon's turn runner).
    Shared(Arc<Mutex<Store>>),
}

impl StoreHandle<'_> {
    /// Run `f` with the store. A poisoned shared lock is recovered (logged),
    /// never allowed to panic the daemon.
    pub fn with<R>(&self, f: impl FnOnce(&Store) -> R) -> R {
        match self {
            Self::Borrowed(store) => f(store),
            Self::Shared(store) => {
                let guard = kernel_core::sync::lock_recover(store);
                f(&guard)
            }
        }
    }

    /// The audit sink the broker writes its decisions through. Only a shared
    /// store can back it: the kernel's sink is `Send + Sync`, and a borrowed
    /// store is neither, so a borrowed handle has no sink (`None`).
    pub fn audit_sink(&self) -> Option<Arc<dyn kernel_broker::AuditSink>> {
        match self {
            Self::Borrowed(_) => None,
            Self::Shared(store) => Some(Arc::new(SharedStoreSink(Arc::clone(store)))),
        }
    }
}

/// The broker's audit trail over a shared store: one `events` row per decision.
pub struct SharedStoreSink(Arc<Mutex<Store>>);

impl kernel_broker::AuditSink for SharedStoreSink {
    fn log_event(
        &self,
        kind: &str,
        payload: &serde_json::Value,
    ) -> Result<i64, kernel_broker::AuditError> {
        let store = kernel_core::sync::lock_recover(&self.0);
        store
            .log_event_id(kind, &payload.to_string())
            .map_err(|err| kernel_broker::AuditError::backend(err.to_string()))
    }
}

impl Store {
    /// Open (or create) the store at `path` and run migrations.
    ///
    /// The file is SQLCipher-encrypted at rest: the key handling and the
    /// one-time migration of a plaintext store live in [`encryption`].
    ///
    /// F-05: the file is switched to `journal_mode = WAL` with
    /// `synchronous = NORMAL`, so a same-uid reader (a `sqlite3` shell, the
    /// CLI, the 1 Hz WS poller) can hold a read transaction while the daemon
    /// writes instead of wedging every write for 5 s. On a filesystem
    /// without WAL support (or on `:memory:`) SQLite keeps its rollback
    /// journal and the open still succeeds — availability first.
    ///
    /// # Backups and disk guard
    ///
    /// A WAL store is **three files**: `store.db`, `store.db-wal` (the
    /// durable tail until the next checkpoint) and `store.db-shm` (the
    /// shared-memory index). A backup that copies only `store.db` silently
    /// loses the tail of the journal, and the disk guard must count all
    /// three. The sidecars are tightened to `0600` like the main file.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // The store directory is checked, then created private, before any file in it.
        encryption::prepare_store_dir(path)?;
        // P3-4: create (0600) or tighten the main file *before* SQLite opens
        // it, so the first bytes are never group/other readable.
        prepare_store_file(path)?;
        // Held until the schema is current, so concurrent first opens cannot
        // race the key files or the one-time migration.
        let _open_lock = encryption::lock_for_open(path)?;
        let conn = encryption::open_encrypted(path)?;
        let store = Self::from_connection(conn, path.parent().map(Path::to_path_buf))?;
        set_private_permissions_with_sidecars(path)?;
        Ok(store)
    }

    /// Open the store through the process's verified home (J-02 round 4).
    ///
    /// Re-verifies the home identity, builds the database path from the held
    /// fd's real path (`F_GETPATH`/`/proc/self/fd`), and proves after the
    /// open that the file at that path is the same inode reachable through
    /// the verified directory fd. A home renamed or swapped after the guard
    /// therefore cannot redirect SQLite onto a decoy (GLM-P1-1).
    pub fn open_verified(home: &kernel_core::SandboxHome) -> Result<Self, StoreError> {
        let real_home = home.real_path()?;
        let db = real_home.join("store.db");
        let store = Self::open(&db)?;
        home.verify_file_inode(Path::new("store.db"), &db)?;
        Ok(store)
    }

    /// Open an in-memory store (used by tests and dry runs). It never touches
    /// disk, so it is not encrypted: there is nothing at rest to protect.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?, None)
    }

    /// Open an existing store read-only, without migrating it: a reader writes nothing.
    pub fn open_readonly(path: &Path) -> Result<Self, StoreError> {
        let conn = encryption::open_keyed_snapshot(path)?;
        Ok(Self {
            conn,
            export_home: path.parent().map(Path::to_path_buf),
        })
    }

    fn from_connection(conn: Connection, export_home: Option<PathBuf>) -> Result<Self, StoreError> {
        let mut store = Self { conn, export_home };
        store.configure_journal_mode()?;
        store.migrate()?;
        Ok(store)
    }

    /// F-05: ask SQLite for WAL and, once it actually switched, use
    /// `synchronous = NORMAL`.
    ///
    /// With WAL, `NORMAL` is crash-safe (a process crash loses nothing; a
    /// power cut can lose only the last commits) and avoids one fsync per
    /// commit. When WAL is unavailable — `:memory:`, a read-only or network
    /// filesystem — the pragma reports the mode that stuck (or errors) and
    /// the store keeps its rollback journal instead of failing the open.
    fn configure_journal_mode(&self) -> Result<(), StoreError> {
        match self
            .conn
            .query_row::<String, _, _>("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
                self.conn.pragma_update(None, "synchronous", "NORMAL")?;
            }
            Ok(_fallback) => {}
            Err(_unsupported) => {}
        }
        Ok(())
    }
}

/// Agents and units are stored as-is but kept to a small, boring charset so a
/// stray control character can never end up in an audit payload.
fn validate_usage_agent(agent: &str) -> Result<(), StoreError> {
    let count = agent.chars().count();
    if count == 0 || count > 64 {
        return Err(StoreError::InvalidUsage {
            reason: "agent must be 1-64 characters".to_string(),
        });
    }
    Ok(())
}

/// Ledger unit for an amount: provider-reported or estimated.
fn unit_for(estimated: bool) -> &'static str {
    if estimated {
        ESTIMATED_UNIT
    } else {
        "tokens"
    }
}

/// Recorded day totals for `agent`, read inside an already-open transaction so
/// the check-and-reserve (and settle-and-latch) decision is atomic.
fn day_totals_tx(
    tx: &Transaction<'_>,
    agent: &str,
    day: &str,
) -> rusqlite::Result<(i64, i64, i64)> {
    tx.query_row(
        "SELECT
             COALESCE(SUM(CASE WHEN kind = 'tokens_in'  THEN amount END), 0),
             COALESCE(SUM(CASE WHEN kind = 'tokens_out' THEN amount END), 0),
             COALESCE(SUM(CASE WHEN kind = 'usd_cents'  THEN amount END), 0)
         FROM usage
         WHERE agent = ?1 AND at >= ?2 AND at < date(?2, '+1 day')",
        rusqlite::params![agent, day],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
}

fn validate_usage_unit(unit: &str) -> Result<(), StoreError> {
    let count = unit.chars().count();
    let allowed = !unit.is_empty()
        && count <= 32
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !allowed {
        return Err(StoreError::InvalidUsage {
            reason: format!("unit `{unit}` must be 1-32 ASCII letters, digits, `_` or `-`"),
        });
    }
    Ok(())
}

/// True when SQLite parses `value` as a date/time and the date prefix
/// round-trips (SQLite *normalizes* impossible dates, so parse alone is not
/// enough). Shared by `validate_usage_at` and the v15 timestamp checks.
fn sqlite_date_matches(conn: &Connection, value: &str) -> Result<bool, StoreError> {
    let matches: i64 = conn.query_row(
        "SELECT COALESCE(date(?1) = substr(?1, 1, 10), 0)",
        [value],
        |row| row.get(0),
    )?;
    Ok(matches == 1)
}

/// Refuse a descriptor JSON field that does not parse. Only a syntax check:
/// the byte caps are enforced immediately before this, so the parse is
/// bounded, and the store makes no claim about the shape (only S3, the
/// read-side consumer, may).
fn validate_mcp_json(field: &str, value: &str) -> Result<(), StoreError> {
    if serde_json::from_str::<serde_json::Value>(value).is_err() {
        return Err(StoreError::McpToolRejected {
            reason: format!("{field} is not valid JSON"),
        });
    }
    Ok(())
}

/// Bound one text field of an [`McpToolRecord`], refusing an oversize (or,
/// when `required`, an empty) value. Sizes count UTF-8 bytes, the unit the
/// column cap is defined in.
fn bound_mcp_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    required: bool,
) -> Result<(), StoreError> {
    if required && value.is_empty() {
        return Err(StoreError::McpToolRejected {
            reason: format!("{field} must not be empty"),
        });
    }
    if value.len() > max_bytes {
        return Err(StoreError::McpToolRejected {
            reason: format!(
                "{field} is {} bytes; the maximum is {max_bytes}",
                value.len()
            ),
        });
    }
    Ok(())
}

/// Validate one descriptor row before it can reach the `mcp_tools` table.
fn validate_mcp_tool(tool: &McpToolRecord) -> Result<(), StoreError> {
    bound_mcp_text("server", &tool.server, MCP_TOOL_NAME_MAX_BYTES, true)?;
    bound_mcp_text(
        "remote_name",
        &tool.remote_name,
        MCP_TOOL_NAME_MAX_BYTES,
        true,
    )?;
    // `wire_name` has already been derived by `canonical_mcp_tool_wire_name`;
    // callers cannot supply, forge, or inflate this dispatch key.
    bound_mcp_text("toolkit", &tool.toolkit, MCP_TOOL_NAME_MAX_BYTES, true)?;
    bound_mcp_text(
        "description",
        &tool.description,
        MCP_TOOL_DESCRIPTION_MAX_BYTES,
        false,
    )?;
    bound_mcp_text(
        "schema_json",
        &tool.schema_json,
        MCP_TOOL_SCHEMA_MAX_BYTES,
        true,
    )?;
    bound_mcp_text("tags_json", &tool.tags_json, MCP_TOOL_TAGS_MAX_BYTES, false)?;
    bound_mcp_text(
        "descriptor_json",
        &tool.descriptor_json,
        MCP_TOOL_DESCRIPTOR_MAX_BYTES,
        true,
    )?;
    // Parse only after the byte caps, so a hostile `*_json` cannot make the
    // upsert spend unbounded work.
    validate_mcp_json("schema_json", &tool.schema_json)?;
    validate_mcp_json("tags_json", &tool.tags_json)?;
    validate_mcp_json("descriptor_json", &tool.descriptor_json)?;
    bound_mcp_text("risk", &tool.risk, MCP_TOOL_NAME_MAX_BYTES, true)?;
    bound_mcp_text(
        "risk_basis",
        &tool.risk_basis,
        MCP_TOOL_DESCRIPTION_MAX_BYTES,
        false,
    )?;
    bound_mcp_text("fetched_at", &tool.fetched_at, 64, true)?;
    if tool.ttl_seconds <= 0 || tool.ttl_seconds > MCP_TOOL_TTL_MAX_SECONDS {
        return Err(StoreError::McpToolRejected {
            reason: format!(
                "ttl_seconds {} must be 1..={MCP_TOOL_TTL_MAX_SECONDS}",
                tool.ttl_seconds
            ),
        });
    }
    Ok(())
}

/// Derive the sole persisted MCP wire name for an identity.
///
/// This follows aux-mcp's `mcp__<server>__<tool>` naming rules: non-provider
/// characters become `_`, and names longer than 64 bytes retain a stable
/// six-hex-character BLAKE3 suffix. The store uses this function for every
/// incoming row rather than trusting `McpToolRecord::wire_name`.
fn canonical_mcp_tool_wire_name(server: &str, remote_name: &str) -> String {
    fn sanitize(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    }

    let full = format!("mcp__{}__{}", sanitize(server), sanitize(remote_name));
    if full.len() <= MCP_TOOL_WIRE_NAME_MAX_BYTES {
        return full;
    }
    let digest = blake3::hash(full.as_bytes());
    let suffix = format!(
        "{:02x}{:02x}{:02x}",
        digest.as_bytes()[0],
        digest.as_bytes()[1],
        digest.as_bytes()[2]
    );
    format!(
        "{}{}",
        &full[..MCP_TOOL_WIRE_NAME_MAX_BYTES - suffix.len()],
        suffix
    )
}

/// Validate one descriptor's `fetched_at` against SQLite: it must round-trip as
/// a calendar date/time, and it must not lead the store clock by more than
/// [`MCP_TOOL_FUTURE_SKEW_SECONDS`] (a future stamp could never expire).
fn validate_mcp_fetched_at(conn: &Connection, tool: &McpToolRecord) -> Result<(), StoreError> {
    if !sqlite_date_matches(conn, &tool.fetched_at)? {
        return Err(StoreError::McpToolRejected {
            reason: format!(
                "fetched_at `{}` is not a valid calendar date/time",
                tool.fetched_at
            ),
        });
    }
    let future: i64 = conn.query_row(
        "SELECT COALESCE(datetime(?1) > datetime('now', printf('%+d seconds', ?2)), 0)",
        rusqlite::params![tool.fetched_at, MCP_TOOL_FUTURE_SKEW_SECONDS],
        |row| row.get(0),
    )?;
    if future == 1 {
        return Err(StoreError::McpToolRejected {
            reason: format!(
                "fetched_at `{}` is more than {MCP_TOOL_FUTURE_SKEW_SECONDS}s in the future",
                tool.fetched_at
            ),
        });
    }
    Ok(())
}

/// The store-generated `synced_at` for one upsert batch, round-trip validated
/// with the same rule as the input timestamps. It is generated by SQLite
/// (`datetime('now')`, UTC) and validated once per batch rather than per row.
fn validated_synced_at(conn: &Connection) -> Result<String, StoreError> {
    let synced_at: String = conn.query_row("SELECT datetime('now')", [], |row| row.get(0))?;
    if !sqlite_date_matches(conn, &synced_at)? {
        return Err(StoreError::McpToolRejected {
            reason: format!("synced_at `{synced_at}` is not a valid calendar date/time"),
        });
    }
    Ok(synced_at)
}

/// Read one `mcp_tools` row (column order is the SELECT list above).
fn row_to_mcp_tool(row: &rusqlite::Row<'_>) -> rusqlite::Result<McpToolRecord> {
    Ok(McpToolRecord {
        server: row.get(0)?,
        remote_name: row.get(1)?,
        wire_name: row.get(2)?,
        toolkit: row.get(3)?,
        description: row.get(4)?,
        schema_json: row.get(5)?,
        tags_json: row.get(6)?,
        descriptor_json: row.get(7)?,
        risk: row.get(8)?,
        risk_basis: row.get(9)?,
        fetched_at: row.get(10)?,
        ttl_seconds: row.get(11)?,
    })
}

impl UsageLedger for Store {
    fn day_totals(&self, agent: &str, day: &str) -> Result<UsageTotals, BudgetError> {
        self.usage_totals(agent, day)
            .map_err(|err| BudgetError::Ledger(err.to_string()))
    }
}

impl ReservationLedger for Store {
    fn try_reserve(
        &self,
        agent: &str,
        day: &str,
        caps: &BudgetCaps,
        estimate: &UsageTotals,
    ) -> Result<ReserveOutcome, BudgetError> {
        Store::try_reserve(self, agent, day, caps, estimate)
            .map_err(|err| BudgetError::Ledger(err.to_string()))
    }

    fn settle(&self, reservation: &Reservation, actual: &UsageActual) -> Result<(), BudgetError> {
        self.settle_reservation(reservation, actual)
            .map_err(|err| BudgetError::Ledger(err.to_string()))
    }

    fn release(&self, reservation: &Reservation) -> Result<(), BudgetError> {
        self.release_reservation(reservation)
            .map_err(|err| BudgetError::Ledger(err.to_string()))
    }
}

impl AuditSink for Store {
    fn audit(&self, kind: &str, payload: &str) -> Result<(), BudgetError> {
        self.log_event(kind, payload)
            .map_err(|err| BudgetError::Audit(err.to_string()))
    }
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        id: row.get(0)?,
        agent: row.get(1)?,
        // A legacy row may predate title scrubbing. Clean on every read too,
        // so an old e-mail, IBAN or card never reaches a sidebar or API view.
        title: row
            .get::<_, Option<String>>(2)?
            .map(|title| kernel_broker::scrub_title(&title)),
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn row_to_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<Message> {
    Ok(Message {
        id: row.get(0)?,
        session_id: row.get(1)?,
        role: row.get(2)?,
        content: row.get(3)?,
        created_at: row.get(4)?,
        meta: row.get(5)?,
    })
}

fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<Job> {
    Ok(Job {
        id: row.get(0)?,
        agent: row.get(1)?,
        name: row.get(2)?,
        schedule: row.get(3)?,
        payload: row.get(4)?,
        enabled: row.get(5)?,
        created_at: row.get(6)?,
        last_run_at: row.get(7)?,
        next_run_at: row.get(8)?,
    })
}

fn row_to_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<Run> {
    Ok(Run {
        id: row.get(0)?,
        job_id: row.get(1)?,
        started_at: row.get(2)?,
        finished_at: row.get(3)?,
        status: row.get(4)?,
        summary: row.get(5)?,
    })
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Create the store file with `0600`, before SQLite ever opens it (P3-4).
///
/// Kept separate from [`prepare_store_file`] so the create mode is
/// observable and tested: the `0600` has to be set *here*, at creation —
/// SQLite copies the mode to the WAL sidecars when it materialises them,
/// and a loose first mode is a window no later `chmod` can close in time.
fn create_store_file(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    drop(options.open(path)?);
    Ok(())
}

/// Create the store file with `0600` when missing, before SQLite opens it
/// (P3-4); an existing regular file is tightened after a successful open,
/// exactly as before.
///
/// A symlink or a special file (FIFO, device) is refused before any open can
/// follow it or block on it.
fn prepare_store_file(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            create_store_file(path)?;
            set_private_permissions(path)
        }
        Err(err) => Err(err),
    }
}

/// Tighten `path` and the WAL sidecars SQLite keeps next to it, so the
/// journal tail is exactly as private as the main file (F-05).
fn set_private_permissions_with_sidecars(path: &Path) -> std::io::Result<()> {
    set_private_permissions(path)?;
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.is_file() {
            set_private_permissions(&sidecar)?;
        }
    }
    Ok(())
}

fn validate_memory_item(item: &NewMemoryItem<'_>) -> Result<(), StoreError> {
    let reject = |reason: &str| StoreError::MemoryRejected {
        reason: reason.into(),
    };
    if !matches!(item.kind, "fact" | "episode" | "note") {
        return Err(reject("invalid kind"));
    }
    if !matches!(item.state, "active" | "quarantined" | "superseded") {
        return Err(reject("invalid state"));
    }
    if item.tainted && item.state != "quarantined" {
        return Err(reject("tainted items must remain quarantined"));
    }
    if item.title.len() > MEMORY_TITLE_MAX_BYTES {
        return Err(reject("title byte limit exceeded"));
    }
    if item.body.len() > MEMORY_BODY_MAX_BYTES {
        return Err(reject("body byte limit exceeded"));
    }
    if item.source.len() > MEMORY_METADATA_MAX_BYTES
        || item.trust.len() > MEMORY_METADATA_MAX_BYTES
        || item
            .fact_key
            .is_some_and(|value| value.len() > MEMORY_METADATA_MAX_BYTES)
        || item
            .valid_from
            .is_some_and(|value| value.len() > MEMORY_METADATA_MAX_BYTES)
        || item
            .valid_to
            .is_some_and(|value| value.len() > MEMORY_METADATA_MAX_BYTES)
    {
        return Err(reject("metadata byte limit exceeded"));
    }
    if item
        .confidence
        .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
    {
        return Err(reject("confidence must be between 0 and 1"));
    }
    Ok(())
}

fn memory_content_hash(title: &str, body: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(title.len() as u64).to_le_bytes());
    hasher.update(title.as_bytes());
    hasher.update(body.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn tokenize_memory_query(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut current = String::new();
    for character in query.chars() {
        if character.is_alphanumeric() {
            current.push(character);
        } else if !current.is_empty() {
            terms.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        terms.push(current);
    }
    terms
}

fn memory_item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryItem> {
    Ok(MemoryItem {
        id: row.get(0)?,
        agent: row.get(1)?,
        kind: row.get(2)?,
        title: row.get(3)?,
        body: row.get(4)?,
        fact_key: row.get(5)?,
        confidence: row.get(6)?,
        source: row.get(7)?,
        trust: row.get(8)?,
        tainted: row.get(9)?,
        supersedes_id: row.get(10)?,
        state: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        valid_from: row.get(14)?,
        valid_to: row.get(15)?,
        content_hash: row.get(16)?,
    })
}

fn memory_suggestion_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemorySuggestion> {
    Ok(MemorySuggestion {
        id: row.get(0)?,
        body: row.get(1)?,
        fact_key: row.get(2)?,
        trust: row.get(3)?,
        created_at: row.get(4)?,
        source_ref: row.get(5)?,
    })
}

fn sanitized_memory_text(text: &str) -> Result<(String, String), StoreError> {
    let body = kernel_broker::sanitize_text(text).trim().to_owned();
    if body.is_empty() || body.len() > MEMORY_BODY_MAX_BYTES {
        return Err(StoreError::MemoryRejected {
            reason: "invalid memory text".into(),
        });
    }
    let title = body
        .lines()
        .next()
        .unwrap_or("Memory")
        .chars()
        .take(120)
        .collect();
    Ok((title, body))
}

fn memory_response_bytes(item: &MemoryItem) -> usize {
    item.title.len()
        + item.body.len()
        + item.fact_key.as_deref().unwrap_or("").len()
        + item.agent.len()
        + item.kind.len()
        + item.source.len()
        + item.trust.len()
        + item.state.len()
        + item.created_at.len()
        + item.updated_at.len()
        + item.valid_from.as_deref().unwrap_or("").len()
        + item.valid_to.as_deref().unwrap_or("").len()
        + item.content_hash.len()
}

fn check_memory_response(item: Option<&MemoryItem>) -> Result<(), StoreError> {
    if item.is_some_and(|item| memory_response_bytes(item) > MEMORY_RESPONSE_MAX_BYTES) {
        return Err(StoreError::MemoryRejected {
            reason: "response byte limit exceeded".into(),
        });
    }
    Ok(())
}

fn check_memory_response_many(items: &[MemoryItem]) -> Result<(), StoreError> {
    let bytes = items
        .iter()
        .map(memory_response_bytes)
        .fold(0usize, usize::saturating_add);
    if bytes > MEMORY_RESPONSE_MAX_BYTES {
        return Err(StoreError::MemoryRejected {
            reason: "response byte limit exceeded".into(),
        });
    }
    Ok(())
}

fn map_memory_constraint(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            StoreError::MemoryRejected {
                reason: "unique or schema constraint rejected the item".into(),
            }
        }
        other => StoreError::Sqlite(other),
    }
}

/// Bound one evidence append before it can touch a row.
///
/// `content_hash` is the SHA-256 of the bytes, so it must be 64 lowercase hex
/// characters; the rest are the registry's own bounds. `source_json` is the
/// provenance JSON: a non-empty object under a small cap.
fn validate_evidence(
    document: &NewEvidenceDocument<'_>,
    source_json: &str,
    seen_at: &str,
) -> Result<(), StoreError> {
    let reject = |reason: &str| StoreError::EvidenceRejected {
        reason: reason.to_string(),
    };
    let hash = document.content_hash;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(reject("content_hash is not a lowercase SHA-256 hex digest"));
    }
    if document.storage_path.is_empty()
        || document.storage_path.len() > 512
        || document.storage_path.chars().any(char::is_control)
    {
        return Err(reject(
            "storage_path is empty, oversized or carries controls",
        ));
    }
    if document.size_bytes < 0 {
        return Err(reject("size_bytes must not be negative"));
    }
    if document.mime_type.is_empty()
        || document.mime_type.len() > 255
        || document.mime_type.chars().any(char::is_control)
    {
        return Err(reject("mime_type is empty, oversized or carries controls"));
    }
    if document.original_name.len() > 512 || document.original_name.chars().any(char::is_control) {
        return Err(reject("original_name is oversized or carries controls"));
    }
    if document.account_id.len() > 128 || document.account_id.chars().any(char::is_control) {
        return Err(reject("account_id is oversized or carries controls"));
    }
    if source_json.is_empty() || source_json.len() > 8 * 1024 {
        return Err(reject("source reference is empty or oversized"));
    }
    if source_json.parse::<serde_json::Value>().is_err() {
        return Err(reject("source reference is not JSON"));
    }
    if seen_at.is_empty() || seen_at.len() > 64 || seen_at.chars().any(char::is_control) {
        return Err(reject("seen_at is empty, oversized or carries controls"));
    }
    Ok(())
}

/// The v17 invoice tables as JSON, one array per table, plus the UTC stamp
/// that names the export file. `None` when every table is empty.
fn invoice_ledger_export(
    tx: &rusqlite::Transaction<'_>,
) -> Result<Option<(String, serde_json::Value)>, StoreError> {
    const TABLES: [&str; 4] = ["documents", "proofs", "corrections", "evidence_guard"];
    let mut any = false;
    let mut tables = serde_json::Map::new();
    for table in TABLES {
        let rows = table_rows_json(tx, table)?;
        any |= !rows.is_empty();
        tables.insert(table.to_string(), serde_json::Value::Array(rows));
    }
    if !any {
        return Ok(None);
    }
    let stamp: String = tx.query_row("SELECT strftime('%Y%m%dT%H%M%SZ', 'now')", [], |row| {
        row.get(0)
    })?;
    Ok(Some((stamp, serde_json::Value::Object(tables))))
}

/// Every row of one fixed table as a JSON object, in rowid order.
fn table_rows_json(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
) -> Result<Vec<serde_json::Value>, StoreError> {
    use rusqlite::types::ValueRef;
    use serde_json::Value;
    let present: i64 = tx.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    if present == 0 {
        // A store without the table has no rows to keep.
        return Ok(Vec::new());
    }
    let mut statement = tx.prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))?;
    let names: Vec<String> = statement.column_names().map(str::to_owned).collect();
    let rows = statement.query_map([], |row| {
        let mut object = serde_json::Map::new();
        for (index, name) in names.iter().enumerate() {
            let value = match row.get_ref(index)? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(number) => Value::from(number),
                ValueRef::Real(number) => {
                    serde_json::Number::from_f64(number).map_or(Value::Null, Value::Number)
                }
                ValueRef::Text(text) => Value::String(String::from_utf8_lossy(text).into_owned()),
                ValueRef::Blob(bytes) => {
                    Value::String(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
                }
            };
            object.insert(name.clone(), value);
        }
        Ok(Value::Object(object))
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Write the invoice export under `<home>/export/` through the kernel
/// gateway: the folder is `0700`, the file `0600`, and an existing file is
/// never overwritten.
fn write_invoice_export(
    home: &Path,
    stamp: &str,
    export: &serde_json::Value,
) -> Result<(), StoreError> {
    let handle = kernel_core::SandboxHome::open(home)?;
    handle.create_dir_all(Path::new("export"))?;
    let rel = PathBuf::from("export").join(format!("invoices-v17-{stamp}.json"));
    let mut bytes = serde_json::to_vec_pretty(export)
        .map_err(|err| StoreError::Io(std::io::Error::other(err)))?;
    bytes.push(b'\n');
    if !handle.write_new(&rel, &bytes, 0o600)? {
        return Err(StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", rel.display()),
        )));
    }
    Ok(())
}

/// Pre-WO-07 spelling of an event kind: `agent.created` was `dot.created`.
/// Historical rows keep the old kind, so kind lookups match both spellings.
pub fn legacy_event_kind(kind: &str) -> String {
    match kind.strip_prefix("agent.") {
        Some(rest) => format!("dot.{rest}"),
        None => kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use tempfile::tempdir;

    #[test]
    fn store_persists_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store.log_event("boot", "{}").unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.event_count("boot").unwrap(), 1);
    }

    // ---- foreign keys and deletion ----

    #[test]
    fn foreign_keys_are_enabled_on_the_connection() {
        let store = Store::open_in_memory().unwrap();
        let enabled: i64 = store
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(enabled, 1);
    }

    #[test]
    fn store_open_switches_to_wal_with_normal_synchronous() {
        // F-05: the rollback journal made any same-uid reader wedge every
        // write for the 5 s busy timeout.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        // A write materializes the sidecars (a fresh WAL store has none yet).
        store.log_event("wal.probe", "{}").unwrap();

        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        let synchronous: i64 = store
            .conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 1, "synchronous must be NORMAL under WAL");
        // WA-MSG-0 item 10: the text listener opens its own `Store` on the
        // same file as `auxd`, so it must carry the same busy timeout; the
        // shared constructor is what makes that true by construction.
        let busy_timeout: i64 = store
            .conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy_timeout, 5_000, "same busy_timeout as auxd");
    }

    #[test]
    fn session_tokens_wait_out_another_connections_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        let session = store.create_session("mail", None).unwrap().id;
        // The chief's connection holds the write lock, then commits.
        let other = Store::open(&path).unwrap();
        other.conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
        other.log_event("delegation.step", "{}").unwrap();
        let pairs = vec![("⟦CARD_1⟧".to_string(), "4111".to_string())];
        let writer = std::thread::spawn(move || store.record_session_tokens(session, &pairs));
        std::thread::sleep(std::time::Duration::from_millis(200));
        other.conn.execute_batch("COMMIT;").unwrap();
        assert_eq!(writer.join().unwrap().unwrap(), 0);
        assert_eq!(other.session_tokens(session).unwrap().len(), 1);
    }

    #[test]
    fn wal_lets_a_reader_hold_the_store_while_the_writer_commits() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        store.log_event("seed", "{}").unwrap();

        // A second connection (the CLI, a sqlite3 shell) holds a read
        // transaction open across the write.
        let reader = open_keyed_readonly(&path).unwrap();
        reader.execute_batch("BEGIN;").unwrap();
        let _: i64 = reader
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .unwrap();

        // Under a rollback journal this waits out the 5 s busy timeout and
        // then fails; under WAL it commits immediately.
        let started = std::time::Instant::now();
        store.log_event("while_reading", "{}").unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "writer blocked for {:?}",
            started.elapsed()
        );
        reader.execute_batch("ROLLBACK;").unwrap();
    }

    #[test]
    fn an_existing_rollback_journal_store_migrates_to_wal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let conn = Connection::open(&path).unwrap();
            let mode: String = conn
                .query_row("PRAGMA journal_mode = delete", [], |row| row.get(0))
                .unwrap();
            assert_eq!(mode.to_ascii_lowercase(), "delete");
            conn.execute_batch(
                "CREATE TABLE legacy (id INTEGER PRIMARY KEY, note TEXT);
                 INSERT INTO legacy(note) VALUES ('kept');",
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let mode: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        let note: String = store
            .conn
            .query_row("SELECT note FROM legacy", [], |row| row.get(0))
            .unwrap();
        assert_eq!(note, "kept", "the migration must preserve the data");
    }

    #[test]
    fn a_read_only_guest_reads_a_wal_store() {
        // The 1 Hz WS poller and every snapshot reader open the store
        // `SQLITE_OPEN_READ_ONLY`; WAL must not break them.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        store.log_event("guest", "{}").unwrap();

        let guest = open_keyed_readonly(&path).unwrap();
        let count: i64 = guest
            .query_row(
                "SELECT COUNT(*) FROM events WHERE kind = 'guest'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn wal_sidecars_are_private_like_the_store() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        store.log_event("perms", "{}").unwrap();

        for suffix in ["", "-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            assert!(sidecar.is_file(), "{} is missing", sidecar.display());
            let mode = std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be 0600", sidecar.display());
        }
    }

    /// M09 (DAEMON-HARDEN-1 security-review round 1): a fresh store is born `0600`,
    /// so its sidecars inherit `0600` and the test above cannot tell whether
    /// the explicit sidecar pass runs. A store that was already loose when
    /// SQLite materialised `-wal`/`-shm` can: they inherit the loose mode,
    /// and only the sidecar pass (not the umask, not the main-file `chmod`)
    /// makes them private.
    #[cfg(unix)]
    #[test]
    fn sidecars_of_a_loose_store_are_tightened_too() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v1_database(&path);
        // Simulate an older build / a manual copy that left the store 0644
        // before this daemon opened (and migrated) it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let store = Store::open(&path).unwrap();
        store.log_event("perms", "{}").unwrap();

        for suffix in ["-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            assert!(sidecar.is_file(), "{} is missing", sidecar.display());
            let mode = std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} must be 0600", sidecar.display());
        }
    }

    /// WA-MSG-0 round-4 P1: `open_verified` opens the store under the
    /// verified-home handle (the live text listener's path).
    #[test]
    fn store_open_verified_uses_the_verified_home() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("h");
        std::fs::create_dir_all(&home).unwrap();
        let handle = kernel_core::ensure_home(&home).expect("verified home");
        let store = Store::open_verified(&handle).unwrap();
        store.log_event("probe", "{}").unwrap();
        assert!(home.join("store.db").exists());
        assert_eq!(store.event_count("probe").unwrap(), 1);
    }

    #[test]
    fn corrupted_store_is_reported() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        std::fs::write(&path, b"this is definitely not a sqlite database").unwrap();

        let result = Store::open(&path);
        assert!(result.is_err(), "corrupted store must not open cleanly");
    }

    #[cfg(unix)]
    #[test]
    fn store_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let _store = Store::open(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "store must be 0600");
    }

    /// M15 (DAEMON-HARDEN-1 security-review round 1): `store_file_is_private` only
    /// observes the *final* mode, so it passes even when the `0600` creation
    /// mode is dropped and `set_private_permissions` does all the work. This
    /// asserts the create step itself, before any tightening can run.
    #[cfg(unix)]
    #[test]
    fn a_missing_store_is_created_private_not_tightened_after() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        create_store_file(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "store must be born 0600");
    }
}
