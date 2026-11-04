//! App-facing JSON frames for live turn events (B-API v2).
//!
//! The shapes mirror the daemon's live contract, decoded by the SwiftUI
//! reference client in `apps/auxesis-mac`. One
//! frame is never larger than [`MAX_WS_FRAME_BYTES`]: oversized frames are
//! dropped with a warning, never truncated mid-JSON.
//!
//! Everything that leaves here is sanitized, and tool arguments/results,
//! message content and approval previews are additionally scrubbed of the
//! Auxesis home path and every documented secret shape (see
//! [`error::scrub_preview`]). Every message role gets the same scrub as a
//! `tool.end` preview, so the live frame and the REST history can never
//! disagree about a secret: both go through
//! [`snapshot::message_json_scrubbed`].
//!
//! User and assistant content stay verbatim by design (RV2-04, tracked): the
//! user may ask about a credential on purpose, and redacting the model's own
//! answer can mangle legitimate text. That channel is therefore **not**
//! guaranteed credential-free at the daemon. The transient `message.delta`
//! frames are the one exception on the assistant side: streamed text is
//! scrubbed before it is emitted (the completed `message.new` still carries
//! the model's verbatim answer). The app adds a best-effort
//! **render-time** mask (known vendor prefixes, bare three-segment JWTs,
//! secret-shaped or long opaque values after `Bearer`, and secret-shaped
//! values after `Basic`/curl flags/sensitive key identifiers) on a
//! percent-decoded and Unicode-whitespace-normalized view; it covers those
//! known shapes, not any possible secret. A key identifier is split on
//! `_`/`-`/`.` into segments, each matched whole and split again at case
//! transitions (`secretAccessKey` → `secret`/`access`/`key`, `dbPassword` →
//! `db`/`password`, `sEcReT_aCcEsS_kEy` → `secret`/`access`/`key`); all-caps
//! or digit-bearing glued segments also match a sensitive term as a suffix
//! (`PGPASSWORD`, `REDISPASSWORD`, `MYSQLPWD`, `SECRETACCESSKEY`). A key's
//! value may follow `=`/`:` or the next whitespace-separated run
//! (`aws configure set secretAccessKey <value>`); it is masked to the end of
//! its run when its prefix up to the first shape-bad byte is secret-shaped
//! (`PASSWORD=MyDogHasFleas123!`), and a quoted value is masked whole when it
//! is shaped or carries any shape-bad byte (`PASSWORD="correct horse battery
//! staple"`), unless it already contains the mask (idempotency). Lowercase
//! words (`monkey`, `keyboard`, `keynote`, `oauth`, `compass`, `bypass`,
//! `passport`, a lone `pass`) and `scheme://` URLs as values
//! (`auth_uri=https://…`) stay readable; `PASS`, `DB_PASS` and `db_pass`
//! mask. Known out-of-claim residuals
//! stay best-effort: connection-string URLs, webhook URLs, PEM bodies, cookie
//! `session=` ids, presigned-URL signatures, separator-free all-lowercase
//! compounds (`postgrespassword`) and values whose shape-clean prefix is under
//! 16 bytes (`PASSWORD=Sup3rS3cret!`) may render. Scrubbing daemon-verbatim
//! user/assistant text remains the tracked residual.
//!
//! **The daemon side is the contract** (B2-10): the API response body —
//! `curl`, a script, `aux activity --json`, the app's own HTTP client — is
//! scrubbed by the shared pattern redactor in `aux-tools`. The app's
//! render-time `sanitize::redact` is defence in depth for anything that
//! reaches a view without the daemon's mask; its known pattern-only
//! residuals (separator-free lowercase compounds, shape-clean prefixes under
//! 16 bytes, some connection-string/webhook URL spellings) are not part of
//! this API's contract, which is the daemon scrubber itself.
//!
//! # Frame size vs message size
//!
//! One frame is never larger than [`MAX_WS_FRAME_BYTES`] (1 MiB): an
//! oversized frame is dropped with a warning, never truncated mid-JSON. In
//! practice that drop path is unreachable for message content, because
//! [`snapshot::message_json`] already caps a message body at
//! [`snapshot::MESSAGE_MAX_BYTES`] (64 KiB, with a truncation marker) before
//! this module frames it; tool/approval previews are 4–8 KiB. Clients should
//! expect a truncated `message.new` (marker included), not a dropped one.

//! A `message.delta` frame carries transient streamed text coalesced to one
//! frame per ~40 ms (see [`super::deltas`]); its `message_id` is a transient
//! draft id (`draft-<thread>-<round>`), and the persisted `message.new` that
//! follows it is authoritative. Deltas are scrubbed of the home path and
//! key-shaped strings even when a secret is split across two deltas.

use std::path::Path;

use aux_providers::ToolCall;
use aux_store::Message;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use super::display::Rehydrated;
use super::error;
use super::snapshot;

/// Receipt schema used by the REST and WebSocket contracts.
pub use super::receipt::Receipt;

#[derive(Debug, Clone, serde::Serialize)]
#[allow(dead_code)] // The event journal combines these same fields with its generic WS envelope.
pub struct RunFinishedFrame {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub at: String,
    pub receipt: Receipt,
}

#[allow(dead_code)] // Kept as the typed wire constructor; journal fan-out attaches the receipt to WsMessage.
pub fn run_finished(receipt: Receipt) -> RunFinishedFrame {
    RunFinishedFrame {
        kind: "run.finished",
        at: stamp(),
        receipt,
    }
}

/// Hard cap for one WS frame (serialized bytes).
pub const MAX_WS_FRAME_BYTES: usize = 1024 * 1024;

/// Cap of a tool-arguments preview. It is also the cap of one approval card:
/// a card never shows less than the action will do, so an action too big for
/// a card is refused instead of being shortened.
pub const MAX_TOOL_ARGS_BYTES: usize = 4 * 1024;

/// Cap of a mail's arguments and of the card that shows it.
///
/// A mail body is shown whole and scrolls in the app, so the cap is a mail's
/// size, not a preview's.
pub const MAX_MAIL_ARGS_BYTES: usize = 256 * 1024;

/// Cap of a tool-result preview.
pub const MAX_TOOL_RESULT_BYTES: usize = 8 * 1024;

/// A `message.new` frame for one persisted message.
///
/// Content comes from [`snapshot::message_json_scrubbed`]: every role is
/// scrubbed exactly like a `tool.end` preview (home path → `<home>`, every
/// documented secret shape redacted), matching the REST history byte for
/// byte.
pub fn message_new(home: &Path, agent: &str, message: &Message) -> Value {
    let clean = snapshot::message_json_scrubbed(home, message);
    message_frame(agent, &clean, &clean.content)
}

/// The `message.new` frame for the loopback channel: the same frame, with the
/// scrubbed content rehydrated by `rehydrate`. A reference that stayed masked
/// sets `rehydration_unavailable` on the message.
pub fn message_new_rehydrated(
    home: &Path,
    agent: &str,
    message: &Message,
    rehydrate: impl Fn(&str) -> Rehydrated,
) -> Value {
    let clean = snapshot::message_json_scrubbed(home, message);
    let shown = rehydrate(&clean.content);
    let mut frame = message_frame(agent, &clean, &shown.text);
    // The sidebar preview is display text, so it follows the rehydrated text
    // too: the detector runs here, on the owner's real values, never in Swift.
    frame["message"]["preview"] = json!(snapshot::message_preview(home, &shown.text));
    if shown.unavailable {
        frame["message"]["rehydration_unavailable"] = Value::Bool(true);
    }
    frame
}

/// A `message.new` frame carrying `text` as the message's only text block.
fn message_frame(agent: &str, clean: &snapshot::MessageJson, text: &str) -> Value {
    let author = match clean.role.as_str() {
        "user" => json!({ "kind": "you" }),
        "assistant" => json!({ "kind": "agent", "id": snapshot::clean_field(agent) }),
        // Tool results are not sentences: the app folds this into the run's
        // tool card instead of a `System context` disclosure (UMF-05).
        "tool" => json!({ "kind": "tool" }),
        _ => json!({ "kind": "system" }),
    };
    json!({
        "type": "message.new",
        "at": stamp(),
        "agent": snapshot::clean_field(agent),
        "message": {
            "id": clean.id.to_string(),
            "thread_id": clean.thread_id.to_string(),
            "author": author,
            "ts": unix_ms(&clean.at),
            "blocks": [{ "kind": "text", "text": text }],
            "preview": clean.preview,
            "streaming": false,
            "pending": false,
            // DELEGATION-SOURCE-1: the same field the stored row carries.
            "source": clean.source,
        },
    })
}

/// A `message.delta` frame: transient text for the draft `message_id`, before
/// the assistant message is persisted.
///
/// The frame text is already scrubbed by the caller (coalescer). `seq` is the
/// engine ordinal of the newest delta folded into this frame; it is monotonic
/// within one draft, and a client that misses a frame can detect the gap — the
/// persisted `message.new`/snapshot stays authoritative.
pub fn message_delta(agent: &str, thread_id: i64, message_id: &str, seq: u64, text: &str) -> Value {
    json!({
        "type": "message.delta",
        "at": stamp(),
        "agent": snapshot::clean_field(agent),
        "thread_id": thread_id.to_string(),
        "message_id": snapshot::clean_field(message_id),
        "seq": seq,
        "text": text,
    })
}

/// A `message.done` frame: the completion of `message_id` ended.
pub fn message_done(agent: &str, thread_id: i64, message_id: i64) -> Value {
    json!({
        "type": "message.done",
        "at": stamp(),
        "agent": snapshot::clean_field(agent),
        "thread_id": thread_id.to_string(),
        "message_id": message_id.to_string(),
    })
}

/// A `tool.start` frame: the call has not been decided yet (`ok` is null).
pub fn tool_start(
    home: &Path,
    agent: &str,
    thread_id: i64,
    message_id: i64,
    call: &ToolCall,
) -> Value {
    json!({
        "type": "tool.start",
        "at": stamp(),
        "agent": snapshot::clean_field(agent),
        "thread_id": thread_id.to_string(),
        "message_id": message_id.to_string(),
        "call": tool_call(home, call, None, None),
    })
}

/// A `tool.end` frame with the outcome and a scrub of the result.
#[allow(clippy::too_many_arguments)]
pub fn tool_end(
    home: &Path,
    agent: &str,
    thread_id: i64,
    message_id: i64,
    index: usize,
    call: &ToolCall,
    status: &str,
    result: &str,
    error_kind: Option<&str>,
) -> Value {
    let preview = error::scrub_preview(home, result, MAX_TOOL_RESULT_BYTES);
    let mut frame = json!({
        "type": "tool.end",
        "at": stamp(),
        "agent": snapshot::clean_field(agent),
        "thread_id": thread_id.to_string(),
        "message_id": message_id.to_string(),
        "index": index,
        "call": tool_call(home, call, Some(status == "ok"), Some(preview)),
        "tokens": 0,
        "cost_cents": 0.0,
    });
    if let Some(kind) = error_kind {
        frame["error_kind"] = json!(kind);
    }
    frame
}

/// A `agent.state` frame carrying the app's state enum (`thinking`, `working`,
/// `idle`).
pub fn agent_state(agent: &str, state: &str) -> Value {
    json!({
        "type": "agent.state",
        "at": stamp(),
        "agent": snapshot::clean_field(agent),
        "state": state,
    })
}

/// The app's `Approval` shape (`model.rs`), field for field.
///
/// `audit_id` is always present because the app's model requires a `u64`
/// (RV2-03). It is the id of the `approval.pending` journal row, or `0` when
/// that row could not be written (unwritable store): `0` is not a real event
/// id (SQLite ids start at 1) and the app only ever displays it, so the
/// degraded frame is both decodable and honest.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApprovalFrame {
    /// API approval id.
    pub id: String,
    /// Id of the `approval.pending` audit row; `0` = not recorded.
    pub audit_id: u64,
    /// Agent that asked.
    pub agent: String,
    /// Session the approval belongs to.
    pub thread_id: String,
    /// Creation time (unix milliseconds).
    pub ts: i64,
    /// What the agent wants to do (`run shell`).
    pub action: String,
    /// Mono headline.
    pub headline: String,
    /// One-line arguments preview (already scrubbed).
    pub preview: Option<String>,
    /// Full draft/diff; not produced by B-API v2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_preview: Option<String>,
    /// Bounded editable JSON when the display preview uses a purpose-built
    /// representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edit_preview: Option<String>,
    /// Extra mono lines.
    pub detail: Vec<String>,
    /// Why the approval is needed.
    pub why: String,
    /// Verifier verdict (not produced yet).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<Value>,
    /// Untrusted-taint marker (`None` = clean).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<String>,
    /// True when the call will run unsandboxed (the `[shell]` escape hatch):
    /// the card must show it and refuse "always allow".
    pub unsandboxed: bool,
    /// Provenance note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clean_note: Option<String>,
    /// Tool the scope picker offers.
    pub scope_tool: String,
    /// Resource the scope picker offers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_resource: Option<String>,
    /// Human-readable current rule.
    pub scope_rule: String,
    /// Preview + arming delay required.
    pub destructive: bool,
    /// Current state.
    pub state: ApprovalStateFrame,
}

/// The app's `ApprovalState` (internally tagged `state`, `model.rs`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ApprovalStateFrame {
    /// Waiting for an answer.
    Pending,
    /// Answered yes.
    Allowed {
        /// Who answered.
        by: String,
        /// Applies to future matching calls.
        always: bool,
    },
    /// Answered no.
    Denied {
        /// Who answered.
        by: String,
    },
    /// Answered later: nothing ran, and the card may be reopened within
    /// the undo window.
    Deferred {
        /// Who deferred it.
        by: String,
    },
    /// Nobody answered in time (fail-closed deny).
    Expired,
}

/// An `approval.new` frame.
pub fn approval_new(approval: &ApprovalFrame) -> Value {
    json!({
        "type": "approval.new",
        "at": stamp(),
        "agent": approval.agent,
        "approval": approval,
    })
}

/// An `approval.resolved` frame.
pub fn approval_resolved(id: &str, state: ApprovalStateFrame) -> Value {
    json!({
        "type": "approval.resolved",
        "at": stamp(),
        "id": id,
        "state": state,
    })
}

/// An `approval.updated` frame: the same id and state every view re-renders
/// from, emitted alongside `approval.resolved` so a client that only follows
/// `approval.updated` still converges.
pub fn approval_updated(id: &str, state: ApprovalStateFrame) -> Value {
    json!({
        "type": "approval.updated",
        "at": stamp(),
        "id": id,
        "state": state,
    })
}

// ---------------------------------------------------------------------------
// provider setup + first run (B-API v4)
// ---------------------------------------------------------------------------

/// `POST /v1/providers` body.
///
/// `api_key` is used and forgotten: it is written only to `<home>/.env` (via
/// [`aux_providers::set_in_env_file`]) and never appears in `config.toml`, a
/// log line, an audit row or any response.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct CreateProviderRequest {
    /// Provider id, also the `[[providers]]` key and the `AUX_KEY_<ID>` stem.
    pub name: Option<String>,
    /// `openai-compat` (default), `fake` or `acp`.
    pub kind: Option<String>,
    /// API root.
    pub base_url: Option<String>,
    /// Default model for this provider.
    pub model: Option<String>,
    /// Secret to store in `<home>/.env`; never echoed back.
    pub api_key: Option<String>,
}

/// `POST /v1/providers` response. `key_present` says whether a key was stored;
/// the value itself never leaves the daemon.
#[derive(Debug, serde::Serialize)]
pub struct ProviderSavedJson {
    /// Saved provider id.
    pub name: String,
    /// True when a non-empty `api_key` was written to `<home>/.env`.
    pub key_present: bool,
}

/// One provider as the settings screen reads it.
#[derive(Debug, serde::Serialize)]
pub struct ProviderJson {
    /// Stable provider id (`[[providers]].id`).
    pub id: String,
    /// Display name (the id: config has no separate name field).
    pub name: String,
    /// API root.
    pub base_url: String,
    /// Model configured for this entry.
    pub model: String,
    /// Adapter (`openai-compat` / `fake` / `acp`).
    pub kind: &'static str,
    /// Roles this entry serves (v1: chat).
    pub roles: Vec<&'static str>,
    /// Where the key lives, when one is configured (`keychain` / `env` /
    /// `none`).
    pub key_location: &'static str,
    /// The app's `ProviderStatus` shape, always untested here.
    pub status: ProviderStatusJson,
    /// Human summary of the last test (none persisted yet: `""`).
    pub last_test: String,
    /// `Some(true/false)`; `None` when the lookup itself failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_present: Option<bool>,
    /// True when a non-empty key is needed for this entry to work.
    pub key_required: bool,
    /// Sanitized lookup failure, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_error: Option<String>,
}

/// The app's internally-tagged `ProviderStatus` (no test has run yet).
#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderStatusJson {
    /// Never tested.
    Untested,
}

/// The `POST /v1/providers/test` result. Field names the app already knows
/// (`ok`, `latency_ms`, `models`, `error`) plus the honest extra facts and a
/// machine-readable `reason` for the guided first-run flow.
#[derive(Debug, serde::Serialize)]
pub struct ProviderTestJson {
    /// Config valid, key available (or not needed), and not proven
    /// unreachable.
    pub ok: bool,
    /// Plain-language bucket: `ok`, `bad_key`, `unreachable`,
    /// `model_not_found`, `invalid_config` or `unknown`. `model_not_found` is
    /// reserved for a future live check: this route never sends a completion.
    pub reason: &'static str,
    /// TCP connect time when a probe ran and succeeded.
    pub latency_ms: Option<u32>,
    /// Model ids: never listed without a live call, so always empty.
    pub models: Vec<String>,
    /// Plain-language reason when `ok` is false.
    pub error: Option<String>,
    /// `Some(true/false)`; `None` when the lookup itself failed.
    pub key_present: Option<bool>,
    /// True when a non-empty key is needed for this entry to work.
    pub key_required: bool,
    /// `Some(true/false)` when the policy allowed a probe; `None` when the
    /// address is not probeable under the fetch policy.
    pub reachable: Option<bool>,
    /// One plain sentence about anything that was skipped or verified.
    pub note: Option<String>,
}

/// `GET /v1/first-run` response: the guided flow's step states.
#[derive(Debug, serde::Serialize)]
pub struct FirstRunStatusJson {
    /// The health gate: true until a provider is saved **and** an agent
    /// exists.
    pub first_run: bool,
    /// At least one `[[providers]]` entry exists.
    pub provider_saved: bool,
    /// A saved provider passed `POST /v1/providers/{name}/test`.
    pub provider_tested: bool,
    /// At least one agent exists.
    pub agent_created: bool,
    /// What the app should ask for next: `provider`, `test`, `agent` or
    /// `done`.
    pub next_step: &'static str,
    /// The saved provider the flow is about, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The default agent, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

/// `POST /v1/first-run/complete` body. Every field is optional: the daemon
/// picks the saved (or tested) provider and its model when they are omitted.
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FirstRunCompleteRequest {
    /// Provider id to attach; defaults to the tested or only saved provider.
    pub provider: Option<String>,
    /// Model override; defaults to the provider's configured model.
    pub model: Option<String>,
    /// Instructions written to the agent's `soul.md`.
    pub role: Option<String>,
    /// Alias for `role`.
    pub instructions: Option<String>,
}

/// `POST /v1/first-run/complete` response.
#[derive(Debug, serde::Serialize)]
pub struct FirstRunCompleteJson {
    /// Always false on success: the gate is cleared.
    pub first_run: bool,
    /// True when this call created the default agent.
    pub created: bool,
    /// Provider attached to the default agent.
    pub provider: String,
    /// The agent as `POST /v1/agents` answers it.
    pub agent: Value,
}

/// The placeholder that stands in for the owner's own words in a live frame.
const MEMORY_TEXT_PLACEHOLDER: &str = "[memory text]";

/// The tools whose arguments are the owner's own words. The shared scrubber
/// removes secrets, not e-mail or health details, so the live event of these
/// tools is built from an allowlist instead of the model's arguments.
const MEMORY_TEXT_TOOLS: &[&str] = &["remember", "suggest_memory"];

/// The memory kinds a frame may show; any other `kind` value is free text.
const MEMORY_KINDS: &[&str] = &[
    "fact",
    "episode",
    "note",
    "about_you",
    "people",
    "rules",
    "other",
];

fn tool_call(
    home: &Path,
    call: &ToolCall,
    ok: Option<bool>,
    result_preview: Option<String>,
) -> Value {
    let shown = if MEMORY_TEXT_TOOLS.contains(&call.name.as_str()) {
        memory_frame_args(&call.arguments)
    } else {
        // Scrub each argument string *before* serializing: a JSON-escaped `\n`
        // would otherwise glue two key/value shapes into one unparseable value
        // (B2-01's second-line assignment).
        scrub_json(home, &call.arguments, 0)
    };
    let raw = serde_json::to_string(&shown).unwrap_or_else(|_| "null".to_string());
    let raw = error::scrub_preview(home, &raw, MAX_TOOL_ARGS_BYTES);
    json!({
        "tool": snapshot::clean_field(&call.name),
        "args": raw,
        "ok": ok,
        "result_preview": result_preview,
    })
}

/// The memory tools' frame arguments, built from scratch: a known `kind`, a
/// placeholder for `text` and a count of `source_refs`. Every other field, a
/// non-object call, and any value of the wrong shape is dropped or replaced.
fn memory_frame_args(args: &Value) -> Value {
    let Some(map) = args.as_object() else {
        return Value::String(MEMORY_TEXT_PLACEHOLDER.to_string());
    };
    let mut shown = serde_json::Map::new();
    if let Some(kind) = map.get("kind") {
        let known = kind.as_str().filter(|kind| MEMORY_KINDS.contains(kind));
        shown.insert(
            "kind".to_string(),
            Value::String(known.unwrap_or(MEMORY_TEXT_PLACEHOLDER).to_string()),
        );
    }
    if map.contains_key("text") {
        shown.insert(
            "text".to_string(),
            Value::String(MEMORY_TEXT_PLACEHOLDER.to_string()),
        );
    }
    if let Some(refs) = map.get("source_refs").and_then(Value::as_array) {
        shown.insert("source_refs".to_string(), json!(refs.len()));
    }
    Value::Object(shown)
}

/// Recursively scrub the string values and keys of one tool-arguments tree,
/// with depth and item bounds so a hostile argument object cannot balloon.
fn scrub_json(home: &Path, value: &Value, depth: usize) -> Value {
    if depth > 8 {
        return Value::Null;
    }
    match value {
        Value::String(text) => Value::String(error::scrub_preview(home, text, MAX_TOOL_ARGS_BYTES)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(100)
                .map(|item| scrub_json(home, item, depth + 1))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .take(100)
                .map(|(key, item)| {
                    (
                        error::scrub_preview(home, key, 128),
                        scrub_json(home, item, depth + 1),
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Serialize and publish one frame; over-limit frames are dropped, not cut.
///
/// Returns `false` when the frame was too large (or unserializable).
pub fn send_bounded(events: &broadcast::Sender<String>, value: &Value) -> bool {
    let Ok(text) = serde_json::to_string(value) else {
        return false;
    };
    if text.len() > MAX_WS_FRAME_BYTES {
        tracing::warn!(
            bytes = text.len(),
            "dropping oversize live-event frame (cap {MAX_WS_FRAME_BYTES})"
        );
        return false;
    }
    let _ = events.send(text);
    true
}

/// `YYYY-MM-DD HH:MM:SS` for generated frames.
fn stamp() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Store timestamp → unix milliseconds (0 when unparseable).
fn unix_ms(at: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(at, "%Y-%m-%d %H:%M:%S")
        .map(|naive| naive.and_utc().timestamp_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_store::Message;

    fn message(id: i64, session_id: i64, role: &str, content: &str) -> Message {
        Message {
            id,
            session_id,
            role: role.to_string(),
            content: content.to_string(),
            created_at: "2026-10-04 09:30:00".to_string(),
            meta: None,
        }
    }

    #[test]
    fn a_row_meta_with_reasoning_never_reaches_a_client_frame() {
        let dir = tempfile::tempdir().unwrap();
        let mut row = message(7, 3, "assistant", "calling a tool");
        row.meta = Some(r#"{"tool_calls":[],"reasoning_content":"SECRET-REASONING"}"#.to_string());
        let live = message_new(dir.path(), "main", &row).to_string();
        let loopback = message_new_rehydrated(dir.path(), "main", &row, |text| Rehydrated {
            text: text.to_string(),
            unavailable: false,
        })
        .to_string();
        let page =
            serde_json::to_string(&snapshot::message_json_scrubbed(dir.path(), &row)).unwrap();
        for shown in [live, loopback, page] {
            assert!(!shown.contains("SECRET-REASONING"), "{shown}");
            assert!(!shown.contains("reasoning_content"), "{shown}");
        }
    }

    #[test]
    fn message_new_matches_the_app_shape() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let value = message_new(
            home,
            "main",
            &message(7, 3, "assistant", "a\u{1b}[31m hi\u{200b}"),
        );
        assert_eq!(value["type"], "message.new");
        assert_eq!(value["agent"], "main");
        let msg = &value["message"];
        assert_eq!(msg["id"], "7");
        assert_eq!(msg["thread_id"], "3");
        assert_eq!(msg["author"], json!({ "kind": "agent", "id": "main" }));
        assert_eq!(msg["blocks"][0], json!({ "kind": "text", "text": "a hi" }));
        assert_eq!(msg["streaming"], false);
        assert_eq!(msg["pending"], false);
        // 2026-10-04 09:30:00 UTC
        assert_eq!(msg["ts"], 1_791_106_200_000i64);

        let user = message_new(home, "main", &message(8, 3, "user", "hello"));
        assert_eq!(user["message"]["author"], json!({ "kind": "you" }));
        let tool = message_new(home, "main", &message(9, 3, "tool", "result"));
        // UMF-05: a tool result is its own author — never a `System context` line.
        assert_eq!(tool["message"]["author"], json!({ "kind": "tool" }));
    }

    #[test]
    fn message_new_scrubs_every_role_content_like_tool_end() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = "top secret: sk-live-SECRET0123456789\nfrom /Users/secret/.auxesis/agents";
        // P2-5: every role is display-scrubbed; the stored row stays raw.
        for role in ["tool", "user", "assistant"] {
            let frame = message_new(home, "main", &message(9, 3, role, raw));
            let text = frame["message"]["blocks"][0]["text"].as_str().unwrap();
            assert!(
                !text.contains("sk-live-SECRET0123456789"),
                "role {role}: {text}"
            );
            assert!(text.contains("<redacted>"), "role {role}: {text}");
            assert!(
                !text.contains("/Users/secret/.auxesis"),
                "role {role}: {text}"
            );
            assert!(text.contains("<home>/agents"), "role {role}: {text}");
        }
    }

    #[test]
    fn every_canary_is_scrubbed_from_live_frames() {
        let home = Path::new("/Users/secret/.auxesis");
        for (raw, secret) in crate::api::canary::all_canaries() {
            for role in ["tool", "user", "assistant"] {
                let frame = message_new(home, "main", &message(1, 1, role, &raw));
                let encoded = serde_json::to_string(&frame).unwrap();
                assert!(
                    !encoded.contains(&secret),
                    "message.new leaked {secret:?} for role {role}"
                );
            }
            let call = aux_providers::ToolCall::new(
                "call-1",
                "shell",
                serde_json::json!({ "command": raw }),
            );
            let frame = tool_end(home, "main", 1, 1, 0, &call, "ok", &raw, None);
            let encoded = serde_json::to_string(&frame).unwrap();
            assert!(!encoded.contains(&secret), "tool.end leaked {secret:?}");
        }
    }

    #[test]
    fn tool_frames_match_the_app_shape_and_scrub_secrets() {
        let home = Path::new("/Users/secret/.auxesis");
        let call = ToolCall::new(
            "call_1",
            "shell",
            json!({ "command": format!("cat {}/.env; echo sk-live-abcdef", home.display()) }),
        );

        let start = tool_start(home, "main", 3, 42, &call);
        assert_eq!(start["type"], "tool.start");
        assert_eq!(start["thread_id"], "3");
        assert_eq!(start["message_id"], "42");
        assert_eq!(start["call"]["tool"], "shell");
        assert_eq!(start["call"]["ok"], Value::Null);
        let args = start["call"]["args"].as_str().unwrap();
        assert!(!args.contains("/Users/secret/.auxesis"), "{args}");
        assert!(args.contains("<home>/.env"), "{args}");
        assert!(!args.contains("sk-live-abcdef"), "{args}");

        let end = tool_end(home, "main", 3, 42, 0, &call, "ok", "exit 0", None);
        assert_eq!(end["type"], "tool.end");
        assert_eq!(end["index"], 0);
        assert_eq!(end["call"]["ok"], true);
        assert_eq!(end["call"]["result_preview"], "exit 0");
        assert_eq!(end["tokens"], 0);
        assert_eq!(end["cost_cents"], 0.0);

        let denied = tool_end(home, "main", 3, 42, 0, &call, "denied", "denied: ask", None);
        assert_eq!(denied["call"]["ok"], false);
    }

    #[test]
    fn memory_tool_frames_carry_a_placeholder_instead_of_the_text() {
        // The shared scrubber removes secrets, not e-mail or health details, so
        // the memory-writing tools get their free text replaced before the
        // frame is built. The other arguments stay.
        let home = Path::new("/Users/secret/.auxesis");
        let text = "Nico's e-mail is nico@example.com and he has diabetes";
        for (tool, args, kept) in [
            (
                "remember",
                json!({"kind":"fact","text":text,"source_refs":["note-1"]}),
                "fact",
            ),
            (
                "suggest_memory",
                json!({"kind":"people","text":text}),
                "people",
            ),
        ] {
            let call = ToolCall::new("call-1", tool, args);
            for frame in [
                tool_start(home, "main", 3, 42, &call),
                tool_end(home, "main", 3, 42, 0, &call, "ok", "stored", None),
            ] {
                let shown = frame["call"]["args"].as_str().unwrap();
                assert!(!shown.contains("nico@example.com"), "{tool}: {shown}");
                assert!(!shown.contains("diabetes"), "{tool}: {shown}");
                assert!(shown.contains("[memory text]"), "{tool}: {shown}");
                assert!(shown.contains(kept), "{tool}: {shown}");
            }
        }
    }

    #[test]
    fn malformed_memory_tool_frames_show_only_allowlisted_fields() {
        // The model controls the argument shape: nested text, extra fields,
        // arrays and non-string text must not carry owner words to the frame.
        let home = Path::new("/Users/secret/.auxesis");
        let secret = "lea@example.test FR7630006000011234567890189 diabetes";
        for tool in ["remember", "suggest_memory"] {
            for args in [
                json!({"kind":"fact","text":{"text":secret}}),
                json!({"kind":"people","text":"ok","note":secret}),
                json!({"kind":"rules","text":[secret, {"text": secret}]}),
                json!({"kind":"other","text":42,"extra":{"text":secret}}),
                json!({"kind":secret,"text":"ok"}),
                json!({"kind":"fact","text":"ok","source_refs":[secret]}),
                json!({"kind":"fact","text":"ok", secret: "value"}),
                json!([{"kind":"fact","text":secret}]),
                json!(secret),
            ] {
                let call = ToolCall::new("call-1", tool, args.clone());
                for frame in [
                    tool_start(home, "main", 3, 42, &call),
                    tool_end(home, "main", 3, 42, 0, &call, "error", "bad", None),
                ] {
                    let shown = frame["call"]["args"].as_str().unwrap();
                    for word in [
                        "lea@example.test",
                        "FR7630006000011234567890189",
                        "diabetes",
                    ] {
                        assert!(!shown.contains(word), "{tool} {args}: {shown}");
                    }
                }
            }
        }
    }

    #[test]
    fn message_done_and_agent_state_carry_string_ids() {
        let done = message_done("main", 3, 42);
        assert_eq!(done["type"], "message.done");
        assert_eq!(done["thread_id"], "3");
        assert_eq!(done["message_id"], "42");

        let state = agent_state("main", "thinking");
        assert_eq!(state["type"], "agent.state");
        assert_eq!(state["state"], "thinking");
    }

    #[test]
    fn run_finished_frame_carries_the_receipt() {
        let receipt =
            super::super::receipt::build_receipt(&[super::super::receipt::ReceiptEvent::Run {
                run_id: "job-1".into(),
                agent: "main".into(),
                started: Some("2026-10-07 09:00:00".into()),
                finished: Some("2026-10-07 09:00:01".into()),
            }]);
        let frame = serde_json::to_value(run_finished(receipt)).unwrap();
        assert_eq!(frame["type"], "run.finished");
        assert_eq!(frame["receipt"]["run_id"], "job-1");
    }

    #[test]
    fn message_delta_carries_the_draft_id_seq_and_text() {
        let frame = message_delta("main", 3, "draft-3-1", 7, "streamed text");
        assert_eq!(frame["type"], "message.delta");
        assert_eq!(frame["agent"], "main");
        assert_eq!(frame["thread_id"], "3");
        assert_eq!(frame["message_id"], "draft-3-1");
        assert_eq!(frame["seq"], 7);
        assert_eq!(frame["text"], "streamed text");
    }

    #[test]
    fn send_bounded_drops_frames_above_the_cap() {
        let (sender, mut receiver) = broadcast::channel(8);
        assert!(send_bounded(
            &sender,
            &json!({"type": "message.new", "message": "ok"})
        ));
        assert!(receiver.try_recv().is_ok());

        let huge = json!({ "type": "message.new", "blob": "x".repeat(MAX_WS_FRAME_BYTES) });
        assert!(!send_bounded(&sender, &huge), "oversize frame must drop");
        assert!(receiver.try_recv().is_err(), "nothing was sent");
    }

    #[test]
    fn unix_millis_are_zero_for_junk_timestamps() {
        assert_eq!(unix_ms("not a date"), 0);
        assert!(unix_ms("2026-10-04 09:30:00") > 0);
    }
}
