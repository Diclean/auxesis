//! `document_fields`: the extracted fields of one evidence document and the
//! durable bridge queue (Wave C / C2b).
//!
//! The schema is `MIGRATION_V23` in [`crate`]. This module owns every SQL
//! statement against it: the extractor chain in `aux-docs` reads a blob,
//! parses it, and hands the typed result here; the local API in `auxd` only
//! moves bytes and JSON. Amounts are integer minor units, never floats.
//!
//! Queue rules (binding, from the C2b work order):
//!
//! * A document without a `document_fields` row is unprocessed.
//! * A claim older than ten minutes ([`EXTRACT_CLAIM_TIMEOUT_SECS`]) is
//!   re-queued; after [`EXTRACT_MAX_ATTEMPTS`] claims it is `failed` and
//!   `to_check` with empty fields.
//! * The blob is served only while its row is `claimed` and fresh.

use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::{Store, StoreError};

/// A claim older than this many seconds is stale and re-queued.
pub const EXTRACT_CLAIM_TIMEOUT_SECS: i64 = 600;
/// Claims after which a stale document is `failed`, not re-queued.
pub const EXTRACT_MAX_ATTEMPTS: i64 = 3;
pub const DOCUMENT_TEXT_MAX_BYTES: usize = 1_048_576;
const DOCUMENT_TEXT_SCAN_MAX_DOCS: usize = 256;
const DOCUMENT_TEXT_SCAN_MAX_BYTES: usize = 16 * 1024 * 1024;
/// The plain sentence a scrubbed document result carries. It is owner-facing
/// text: never a bracketed internal marker the model could mistake for an
/// instruction or relay to the owner verbatim.
pub const DOCUMENT_UNAVAILABLE_TEXT: &str =
    "This document's content is not available — it was removed or could not be read.";

static EVIDENCE_LIFECYCLE_LOCKS: OnceLock<Mutex<HashMap<String, Weak<Mutex<()>>>>> =
    OnceLock::new();

/// The process-wide lifecycle lock shared by evidence append, erase and tool-result persistence.
pub fn evidence_lifecycle_lock(content_hash: &str) -> Arc<Mutex<()>> {
    let locks = EVIDENCE_LIFECYCLE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = kernel_core::lock_recover(locks);
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(content_hash).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(content_hash.to_string(), Arc::downgrade(&lock));
    lock
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct DocumentTarget {
    document_id: Option<i64>,
    content_hash: Option<String>,
}

#[derive(Default)]
struct ErasedDocumentTargets {
    ids: HashSet<i64>,
    hashes: HashSet<String>,
}

fn payload_value(content: &str) -> Option<(usize, serde_json::Value)> {
    if let Some(body) = content.find('\n').map(|at| at + 1) {
        if let Ok(value) = serde_json::from_str(&content[body..]) {
            return Some((body, value));
        }
    }
    serde_json::from_str(content).ok().map(|value| (0, value))
}

fn object_target(object: &serde_json::Map<String, serde_json::Value>) -> DocumentTarget {
    let document_id = object
        .get("document_id")
        .and_then(serde_json::Value::as_i64)
        .filter(|id| *id > 0);
    let content_hash = ["content_hash", "document_hash", "sha256", "hash"]
        .iter()
        .filter_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
        .find(|hash| is_sha256(hash))
        .map(str::to_string);
    DocumentTarget {
        document_id,
        content_hash,
    }
}

fn collect_targets(value: &serde_json::Value, targets: &mut HashSet<DocumentTarget>) {
    match value {
        serde_json::Value::Object(object) => {
            let target = object_target(object);
            if target.document_id.is_some() || target.content_hash.is_some() {
                targets.insert(target);
            }
            for child in object.values() {
                collect_targets(child, targets);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_targets(child, targets);
            }
        }
        _ => {}
    }
}

fn has_unattributed_excerpt(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            let target = object_target(object);
            let identified = target.document_id.is_some() || target.content_hash.is_some();
            (object.contains_key("excerpt") && !identified)
                || object.values().any(has_unattributed_excerpt)
        }
        serde_json::Value::Array(items) => items.iter().any(has_unattributed_excerpt),
        _ => false,
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn matches_target(
    object: &serde_json::Map<String, serde_json::Value>,
    ids: &HashSet<i64>,
    hashes: &HashSet<String>,
) -> bool {
    let target = object_target(object);
    target.document_id.is_some_and(|id| ids.contains(&id))
        || target
            .content_hash
            .is_some_and(|hash| hashes.contains(&hash))
}

fn scrub_payload_value(value: &mut serde_json::Value, erased: &ErasedDocumentTargets) -> bool {
    if let serde_json::Value::Object(object) = value {
        if matches_target(object, &erased.ids, &erased.hashes) {
            *value = serde_json::Value::String(DOCUMENT_UNAVAILABLE_TEXT.into());
            return true;
        }
    }
    match value {
        serde_json::Value::Object(object) => {
            let mut changed = false;
            for child in object.values_mut() {
                changed |= scrub_payload_value(child, erased);
            }
            changed
        }
        serde_json::Value::Array(items) => {
            let mut changed = false;
            for child in items {
                changed |= scrub_payload_value(child, erased);
            }
            changed
        }
        _ => false,
    }
}

fn scrub_document_payload(content: &str, erased: &ErasedDocumentTargets) -> Option<String> {
    let Some((body, mut value)) = payload_value(content) else {
        return Some(DOCUMENT_UNAVAILABLE_TEXT.into());
    };
    let mut targets = HashSet::new();
    collect_targets(&value, &mut targets);
    if has_unattributed_excerpt(&value) {
        return Some(DOCUMENT_UNAVAILABLE_TEXT.into());
    }
    if targets.is_empty() {
        // A search that matched nothing, or a read that found nothing, carries
        // no document text to erase. Marking it would tell the model that a
        // document was erased when none was, so the empty result stays intact.
        return (!is_empty_document_result(&value)).then(|| DOCUMENT_UNAVAILABLE_TEXT.into());
    }
    if let serde_json::Value::Object(object) = &value {
        if matches_target(object, &erased.ids, &erased.hashes) {
            return Some(DOCUMENT_UNAVAILABLE_TEXT.into());
        }
    }
    if !scrub_payload_value(&mut value, erased) {
        return None;
    }
    Some(format!("{}{}", &content[..body], value))
}

/// The exact keys a canonical empty search result may carry. Anything else is
/// document text the scrub cannot attribute, so it is erased (fail closed).
const EMPTY_SEARCH_RESULT_KEYS: [&str; 8] = [
    "matches",
    "total",
    "truncated",
    "query_truncated",
    "searched_documents",
    "available_documents",
    "scanned_bytes",
    "search_scope",
];

/// A docs result envelope that carries no document text: a search with no
/// match, or a read that found nothing. Only the canonical shapes the docs
/// tools emit are accepted; any unknown or nested field is treated as text and
/// erased, because it cannot be attributed to a live document.
fn is_empty_document_result(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.contains_key("matches") {
        if !object
            .get("matches")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            return false;
        }
        if !object
            .keys()
            .all(|key| EMPTY_SEARCH_RESULT_KEYS.contains(&key.as_str()))
        {
            return false;
        }
        let count = |key: &str| object.get(key).and_then(serde_json::Value::as_u64);
        let (Some(total), Some(searched), Some(available), Some(_scanned)) = (
            count("total"),
            count("searched_documents"),
            count("available_documents"),
            count("scanned_bytes"),
        ) else {
            return false;
        };
        if total != 0 || searched > available {
            return false;
        }
        if !["truncated", "query_truncated"]
            .iter()
            .all(|key| object.get(*key).is_some_and(serde_json::Value::is_boolean))
        {
            return false;
        }
        let scope = if searched < available {
            format!("searched newest {searched} of {available} documents")
        } else {
            format!("searched all {available} documents")
        };
        return object
            .get("search_scope")
            .and_then(serde_json::Value::as_str)
            == Some(scope.as_str());
    }
    object.len() == 1 && object.get("found").and_then(serde_json::Value::as_bool) == Some(false)
}

/// Shortest verbatim text an erase also removes from the assistant's own
/// replies. Shorter strings (a date, a currency code, a short label) occur in
/// too many replies to attribute to one document.
pub const ERASED_ECHO_MIN_CHARS: usize = 24;

fn collect_string_leaves<'a>(value: &'a serde_json::Value, out: &mut HashSet<&'a str>) {
    match value {
        serde_json::Value::String(text) => {
            out.insert(text.as_str());
        }
        serde_json::Value::Object(object) => {
            for child in object.values() {
                collect_string_leaves(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_string_leaves(child, out);
            }
        }
        _ => {}
    }
}

/// The string values a scrub removed from one document result: present in
/// `before`, absent from `after`, at least [`ERASED_ECHO_MIN_CHARS`] long.
/// They are the texts the model may have echoed verbatim in a later reply.
/// Both texts are the stored representation (the tokenised copy in a Private
/// thread), so a match on them runs on what the provider actually saw.
pub fn erased_document_texts(before: &str, after: &str) -> Vec<String> {
    let Some((_, old)) = payload_value(before) else {
        return Vec::new();
    };
    let mut kept = HashSet::new();
    let new = payload_value(after).map(|(_, value)| value);
    if let Some(new) = &new {
        collect_string_leaves(new, &mut kept);
    }
    let mut removed = HashSet::new();
    collect_string_leaves(&old, &mut removed);
    let mut texts: Vec<String> = removed
        .into_iter()
        .filter(|text| text.chars().count() >= ERASED_ECHO_MIN_CHARS && !kept.contains(text))
        .map(str::to_string)
        .collect();
    // Longest first, so a text that contains another is replaced whole.
    texts.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    texts
}

/// Replace every verbatim occurrence of an erased text in `content` with the
/// unavailable sentence. `None` when nothing matched.
pub fn scrub_erased_echo(content: &str, texts: &[String]) -> Option<String> {
    let mut scrubbed = content.to_string();
    for text in texts {
        if scrubbed.contains(text.as_str()) {
            scrubbed = scrubbed.replace(text.as_str(), DOCUMENT_UNAVAILABLE_TEXT);
        }
    }
    (scrubbed != content).then_some(scrubbed)
}

/// JSON writers escape a newline, a double quote and a backslash inside a
/// string, so a raw replace misses a quoted excerpt in `meta`. Tool-call
/// arguments are one JSON-encoded string layer; the cap keeps a hostile value
/// with thousands of nested layers from exhausting the stack.
const META_ECHO_MAX_DEPTH: usize = 64;

/// The text as it appears inside a JSON string, without the quotes.
fn json_escaped_body(text: &str) -> Option<String> {
    let quoted = serde_json::to_string(text).ok()?;
    quoted
        .strip_prefix('"')?
        .strip_suffix('"')
        .map(str::to_string)
}

/// The strict superset fallback for a `meta` that is not valid JSON: the old
/// raw replace, plus the JSON-escaped form of every echo. Parsing is
/// impossible, so the scrub must never do less than it did before.
fn scrub_escaped_echo(content: &str, echoes: &[String]) -> Option<String> {
    let mut scrubbed = content.to_string();
    for text in echoes {
        if scrubbed.contains(text.as_str()) {
            scrubbed = scrubbed.replace(text.as_str(), DOCUMENT_UNAVAILABLE_TEXT);
        }
        if let Some(escaped) = json_escaped_body(text) {
            if escaped.as_str() != text.as_str() && scrubbed.contains(&escaped) {
                scrubbed = scrubbed.replace(&escaped, DOCUMENT_UNAVAILABLE_TEXT);
            }
        }
    }
    (scrubbed != content).then_some(scrubbed)
}

/// Replace every echo in a JSON value's string leaves. A leaf that is itself
/// JSON (a tool call's `arguments` is stored as a JSON-encoded string) is
/// parsed, scrubbed and re-encoded, so escaped excerpts are reached too.
fn scrub_meta_value(value: &mut serde_json::Value, echoes: &[String], depth: usize) -> bool {
    match value {
        serde_json::Value::String(text) => {
            // Decode first: replacing inside the encoded text could hit a
            // JSON escape (`\n`, `\"`) and leave a broken document behind.
            if depth > 0 {
                if let Ok(mut nested) = serde_json::from_str::<serde_json::Value>(text) {
                    if scrub_meta_value(&mut nested, echoes, depth - 1) {
                        if let Ok(encoded) = serde_json::to_string(&nested) {
                            *text = encoded;
                            return true;
                        }
                    }
                }
            }
            match scrub_erased_echo(text, echoes) {
                Some(scrubbed) => {
                    *text = scrubbed;
                    true
                }
                None => false,
            }
        }
        serde_json::Value::Object(object) => {
            if depth == 0 {
                return false;
            }
            let mut changed = false;
            for child in object.values_mut() {
                changed |= scrub_meta_value(child, echoes, depth - 1);
            }
            changed
        }
        serde_json::Value::Array(items) => {
            if depth == 0 {
                return false;
            }
            let mut changed = false;
            for child in items {
                changed |= scrub_meta_value(child, echoes, depth - 1);
            }
            changed
        }
        _ => false,
    }
}

/// Rewrite an assistant row's `meta` without breaking it: valid JSON is walked
/// leaf by leaf; malformed JSON takes the raw-plus-escaped fallback. `None`
/// when nothing matched.
fn scrub_meta_echo(meta: &str, echoes: &[String]) -> Option<String> {
    match serde_json::from_str::<serde_json::Value>(meta) {
        Ok(mut value) => {
            if !scrub_meta_value(&mut value, echoes, META_ECHO_MAX_DEPTH) {
                return None;
            }
            serde_json::to_string(&value)
                .ok()
                .or_else(|| scrub_escaped_echo(meta, echoes))
        }
        Err(_) => scrub_escaped_echo(meta, echoes),
    }
}

fn scrub_document_tool_messages(
    tx: &Transaction<'_>,
    document_id: i64,
    content_hash: &str,
) -> Result<(), StoreError> {
    let messages: Vec<(i64, i64, String)> = {
        let mut statement = tx.prepare(
            "SELECT id, session_id, content FROM messages
              WHERE role = 'tool'
                AND CASE WHEN json_valid(meta) THEN json_extract(meta, '$.tool') END GLOB 'docs_*'",
        )?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    let erased = ErasedDocumentTargets {
        ids: [document_id].into_iter().collect(),
        hashes: [content_hash.to_string()].into_iter().collect(),
    };
    let mut sessions = BTreeSet::new();
    let mut echoes = BTreeSet::new();
    for (message_id, session_id, content) in messages {
        if let Some(scrubbed) = scrub_document_payload(&content, &erased) {
            tx.execute(
                "UPDATE messages SET content = ?1 WHERE id = ?2",
                params![scrubbed, message_id],
            )?;
            sessions.insert(session_id);
            echoes.extend(erased_document_texts(&content, &scrubbed));
        }
    }
    // The model may have quoted the erased text in its own replies (or in a
    // tool call's arguments) in the threads that read this document. Exact
    // text only: a paraphrase cannot be told from the model's own words.
    let echoes: Vec<String> = echoes.into_iter().collect();
    if echoes.is_empty() {
        return Ok(());
    }
    for session_id in sessions {
        let replies: Vec<(i64, String, Option<String>)> = {
            let mut statement = tx.prepare(
                "SELECT id, content, meta FROM messages
                  WHERE session_id = ?1 AND role = 'assistant'",
            )?;
            let rows = statement.query_map([session_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
            rows.collect::<Result<_, _>>()?
        };
        for (message_id, content, meta) in replies {
            let content = scrub_erased_echo(&content, &echoes);
            let meta = meta
                .as_deref()
                .and_then(|meta| scrub_meta_echo(meta, &echoes));
            if content.is_none() && meta.is_none() {
                continue;
            }
            tx.execute(
                "UPDATE messages
                    SET content = COALESCE(?1, content), meta = COALESCE(?2, meta)
                  WHERE id = ?3",
                params![content, meta, message_id],
            )?;
        }
    }
    Ok(())
}

/// The statuses the contract allows.
pub const DOCUMENT_FIELD_KINDS: &[&str] = &["invoice", "receipt", "other"];
/// The extractors the contract allows.
pub const DOCUMENT_EXTRACTORS: &[&str] = &["xml", "pdf_text", "ocr", "none"];
/// The review statuses the contract allows.
pub const DOCUMENT_STATUSES: &[&str] = &["to_check", "filed", "ignored"];
/// The durable queue states.
pub const DOCUMENT_EXTRACT_STATES: &[&str] = &["pending", "claimed", "done", "failed"];

/// One row to insert into `document_fields`.
///
/// `Default` is a blank row: the store's own guard refuses it (the kind, the
/// extractor and the status must be one of the allowed values), so it is a
/// convenience for a test that fills the fields it cares about.
#[derive(Debug, Clone, Default)]
pub struct NewDocumentFields<'a> {
    /// `documents.id`.
    pub document_id: i64,
    /// `invoice` | `receipt` | `other`.
    pub kind: &'a str,
    /// `xml` | `pdf_text` | `ocr` | `none`.
    pub extractor: &'a str,
    /// Seller name, when known.
    pub issuer: Option<&'a str>,
    /// Buyer name, when known.
    pub recipient: Option<&'a str>,
    /// ISO `YYYY-MM-DD`, when known.
    pub issued_on: Option<&'a str>,
    /// ISO 4217 code, when known.
    pub currency: Option<&'a str>,
    /// Total including VAT, in minor units.
    pub total_minor: Option<i64>,
    /// VAT amount, in minor units.
    pub vat_minor: Option<i64>,
    /// Human invoice/receipt number, when known.
    pub number: Option<&'a str>,
    /// The full field set as JSON.
    pub fields_json: &'a str,
    pub extracted_text: &'a str,
    /// The checks as JSON.
    pub checks_json: &'a str,
    /// Matched CRM party, when the party check passes.
    pub party_id: Option<i64>,
    /// JSON array of tags.
    pub tags: &'a str,
    /// `to_check` | `filed` | `ignored`.
    pub status: &'a str,
    /// RFC 3339 UTC write time.
    pub updated_at: &'a str,
    /// `pending` | `claimed` | `done` | `failed`.
    pub extract_state: &'a str,
    /// RFC 3339 UTC claim time, when claimed.
    pub claimed_at: Option<&'a str>,
    /// Claims so far.
    pub attempts: i64,
}

/// One document that has no `document_fields` row yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnprocessedDocument {
    /// `documents.id`.
    pub document_id: i64,
    /// Lowercase SHA-256 of the original.
    pub content_hash: String,
    /// Relative blob path (`evidence/<sha256>`).
    pub storage_path: String,
    /// Declared MIME type (dispatch uses the bytes, never this).
    pub mime_type: String,
    /// Original size in bytes.
    pub size_bytes: i64,
}

/// One claimed document, joined to its `documents` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedDocument {
    /// `documents.id`.
    pub document_id: i64,
    /// Lowercase SHA-256 of the original.
    pub content_hash: String,
    /// Declared MIME type.
    pub mime_type: String,
    /// Original size in bytes.
    pub size_bytes: i64,
}

/// One extracted document for the accountant export (M5-2): the
/// `document_fields` columns it needs plus the blob hash, MIME type and
/// attachment name of its `documents` row. Never a body or OCR text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportDocument {
    pub content_hash: String,
    pub mime_type: String,
    pub original_name: Option<String>,
    pub issued_on: String,
    pub number: Option<String>,
    pub issuer: Option<String>,
    pub currency: Option<String>,
    pub total_minor: Option<i64>,
    pub vat_minor: Option<i64>,
    pub checks_json: String,
    pub party_id: Option<i64>,
}

/// The parsed result of one extraction, written when the row is `claimed`.
#[derive(Debug, Clone)]
pub struct DocumentExtraction<'a> {
    /// `invoice` | `receipt` | `other`.
    pub kind: &'a str,
    /// `xml` | `pdf_text` | `ocr` | `none`.
    pub extractor: &'a str,
    /// Seller name, when known.
    pub issuer: Option<&'a str>,
    /// Buyer name, when known.
    pub recipient: Option<&'a str>,
    /// ISO `YYYY-MM-DD`, when known.
    pub issued_on: Option<&'a str>,
    /// ISO 4217 code, when known.
    pub currency: Option<&'a str>,
    /// Total including VAT, in minor units.
    pub total_minor: Option<i64>,
    /// VAT amount, in minor units.
    pub vat_minor: Option<i64>,
    /// Human invoice/receipt number, when known.
    pub number: Option<&'a str>,
    /// The full field set as JSON.
    pub fields_json: &'a str,
    /// The checks as JSON.
    pub checks_json: &'a str,
    /// Matched CRM party, when the party check passes.
    pub party_id: Option<i64>,
    /// `to_check` | `filed` | `ignored`.
    pub status: &'a str,
    /// RFC 3339 UTC write time.
    pub updated_at: &'a str,
    pub extracted_text: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocumentText {
    pub document_id: i64,
    pub original_name: Option<String>,
    pub kind: String,
    pub text: String,
}

/// The bounded local scan used by Documents search, with its true horizon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentTextScan {
    pub documents: Vec<StoredDocumentText>,
    pub available_documents: usize,
    pub scanned_bytes: usize,
}

fn one_of(value: &str, allowed: &[&str]) -> bool {
    allowed.contains(&value)
}

fn validate_row(row: &NewDocumentFields<'_>) -> Result<(), StoreError> {
    let reject = |reason: &str| StoreError::DocumentFieldsRejected {
        reason: reason.to_string(),
    };
    if row.document_id <= 0 {
        return Err(reject("document_id must be positive"));
    }
    if !one_of(row.kind, DOCUMENT_FIELD_KINDS) {
        return Err(reject("kind is not invoice/receipt/other"));
    }
    if !one_of(row.extractor, DOCUMENT_EXTRACTORS) {
        return Err(reject("extractor is not xml/pdf_text/ocr/none"));
    }
    if !one_of(row.status, DOCUMENT_STATUSES) {
        return Err(reject("status is not to_check/filed/ignored"));
    }
    if !one_of(row.extract_state, DOCUMENT_EXTRACT_STATES) {
        return Err(reject("extract_state is not pending/claimed/done/failed"));
    }
    if row.attempts < 0 {
        return Err(reject("attempts must not be negative"));
    }
    if row.extracted_text.len() > DOCUMENT_TEXT_MAX_BYTES {
        return Err(reject("extracted text exceeds the local storage limit"));
    }
    Ok(())
}

fn validate_extraction(update: &DocumentExtraction<'_>) -> Result<(), StoreError> {
    let reject = |reason: &str| StoreError::DocumentFieldsRejected {
        reason: reason.to_string(),
    };
    if !one_of(update.kind, DOCUMENT_FIELD_KINDS) {
        return Err(reject("kind is not invoice/receipt/other"));
    }
    if !one_of(update.extractor, DOCUMENT_EXTRACTORS) {
        return Err(reject("extractor is not xml/pdf_text/ocr/none"));
    }
    if !one_of(update.status, DOCUMENT_STATUSES) {
        return Err(reject("status is not to_check/filed/ignored"));
    }
    if update.extracted_text.len() > DOCUMENT_TEXT_MAX_BYTES {
        return Err(reject("extracted text exceeds the local storage limit"));
    }
    Ok(())
}

impl Store {
    /// Insert one `document_fields` row. Returns `false` when a row for the
    /// document already exists (a racing sweep lost the race; the winner's row
    /// stands).
    pub fn insert_document_fields(&self, row: &NewDocumentFields<'_>) -> Result<bool, StoreError> {
        validate_row(row)?;
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO document_fields(
                 document_id, kind, extractor, issuer, recipient, issued_on, currency,
                 total_minor, vat_minor, number, fields_json, checks_json, party_id, tags,
                 status, updated_at, extract_state, claimed_at, attempts, extracted_text)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19, ?20)",
            params![
                row.document_id,
                row.kind,
                row.extractor,
                row.issuer,
                row.recipient,
                row.issued_on,
                row.currency,
                row.total_minor,
                row.vat_minor,
                row.number,
                row.fields_json,
                row.checks_json,
                row.party_id,
                row.tags,
                row.status,
                row.updated_at,
                row.extract_state,
                row.claimed_at,
                row.attempts,
                row.extracted_text,
            ],
        )?;
        Ok(inserted == 1)
    }

    /// Documents with no `document_fields` row, oldest first.
    pub fn unprocessed_documents(
        &self,
        limit: usize,
    ) -> Result<Vec<UnprocessedDocument>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT d.id, d.content_hash, d.storage_path, d.mime_type, d.size_bytes
               FROM documents AS d
               LEFT JOIN document_fields AS f ON f.document_id = d.id
              WHERE f.document_id IS NULL
              ORDER BY d.id
              LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(UnprocessedDocument {
                document_id: row.get(0)?,
                content_hash: row.get(1)?,
                storage_path: row.get(2)?,
                mime_type: row.get(3)?,
                size_bytes: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Re-queue or fail every claim older than `cutoff` (an RFC 3339 UTC
    /// instant). A stale claim under the attempt cap goes back to `pending`;
    /// the cap makes it `failed` with empty fields and `to_check`.
    pub fn expire_document_claims(&self, cutoff: &str) -> Result<u64, StoreError> {
        let changed = self.conn.execute(
            "UPDATE document_fields
                SET extract_state = CASE WHEN attempts >= ?1 THEN 'failed' ELSE 'pending' END,
                    kind        = CASE WHEN attempts >= ?1 THEN 'other' ELSE kind END,
                    extractor   = CASE WHEN attempts >= ?1 THEN 'none' ELSE extractor END,
                    issuer      = CASE WHEN attempts >= ?1 THEN NULL ELSE issuer END,
                    recipient   = CASE WHEN attempts >= ?1 THEN NULL ELSE recipient END,
                    issued_on   = CASE WHEN attempts >= ?1 THEN NULL ELSE issued_on END,
                    currency    = CASE WHEN attempts >= ?1 THEN NULL ELSE currency END,
                    total_minor = CASE WHEN attempts >= ?1 THEN NULL ELSE total_minor END,
                    vat_minor   = CASE WHEN attempts >= ?1 THEN NULL ELSE vat_minor END,
                    number      = CASE WHEN attempts >= ?1 THEN NULL ELSE number END,
                    fields_json = CASE WHEN attempts >= ?1 THEN '{}' ELSE fields_json END,
                    checks_json = CASE WHEN attempts >= ?1 THEN '[]' ELSE checks_json END,
                    party_id    = CASE WHEN attempts >= ?1 THEN NULL ELSE party_id END,
                    status      = CASE WHEN attempts >= ?1 THEN 'to_check' ELSE status END,
                    claimed_at  = NULL
              WHERE extract_state = 'claimed'
                AND claimed_at IS NOT NULL
                AND claimed_at < ?2",
            params![EXTRACT_MAX_ATTEMPTS, cutoff],
        )?;
        Ok(changed as u64)
    }

    /// Claim up to `limit` pending documents for the bridge. Each claim stamps
    /// `claimed_at = now` and increments `attempts`.
    pub fn claim_document_fields(
        &self,
        now: &str,
        limit: usize,
    ) -> Result<Vec<ClaimedDocument>, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let ids: Vec<i64> = {
            let mut statement = tx.prepare(
                "SELECT document_id FROM document_fields
                  WHERE extract_state = 'pending'
                  ORDER BY document_id
                  LIMIT ?1",
            )?;
            let rows = statement.query_map([limit as i64], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut claimed = Vec::with_capacity(ids.len());
        for id in ids {
            let changed = tx.execute(
                "UPDATE document_fields
                    SET extract_state = 'claimed', claimed_at = ?1, attempts = attempts + 1
                  WHERE document_id = ?2 AND extract_state = 'pending'",
                params![now, id],
            )?;
            if changed == 0 {
                continue;
            }
            let doc = tx
                .query_row(
                    "SELECT d.id, d.content_hash, d.mime_type, d.size_bytes
                       FROM documents AS d
                       JOIN document_fields AS f ON f.document_id = d.id
                      WHERE d.id = ?1 AND f.extract_state = 'claimed'",
                    [id],
                    |row| {
                        Ok(ClaimedDocument {
                            document_id: row.get(0)?,
                            content_hash: row.get(1)?,
                            mime_type: row.get(2)?,
                            size_bytes: row.get(3)?,
                        })
                    },
                )
                .optional()?;
            if let Some(doc) = doc {
                claimed.push(doc);
            }
        }
        tx.commit()?;
        Ok(claimed)
    }

    /// The claimed document with this hash, when its claim is still fresh
    /// (`claimed_at >= cutoff`). A stale claim answers `None` and the caller
    /// must not serve the blob.
    pub fn claimed_document(
        &self,
        content_hash: &str,
        cutoff: &str,
    ) -> Result<Option<ClaimedDocument>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT d.id, d.content_hash, d.mime_type, d.size_bytes
                   FROM documents AS d
                   JOIN document_fields AS f ON f.document_id = d.id
                  WHERE d.content_hash = ?1
                    AND f.extract_state = 'claimed'
                    AND f.claimed_at IS NOT NULL
                    AND f.claimed_at >= ?2",
                params![content_hash, cutoff],
                |row| {
                    Ok(ClaimedDocument {
                        document_id: row.get(0)?,
                        content_hash: row.get(1)?,
                        mime_type: row.get(2)?,
                        size_bytes: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Claim completed documents whose text alone needs backfilling. Their
    /// extraction state and all owner-reviewed fields remain unchanged.
    pub fn claim_document_text_backfills(
        &self,
        now: &str,
        cutoff: &str,
        limit: usize,
    ) -> Result<Vec<ClaimedDocument>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let ids: Vec<i64> = {
            let mut statement = tx.prepare(
                "SELECT b.document_id
                   FROM document_text_backfill AS b
                   JOIN document_fields AS f ON f.document_id = b.document_id
                  WHERE (b.claimed_at IS NULL OR b.claimed_at < ?1)
                    AND f.extract_state = 'done'
                    AND f.has_extracted_text = 0
                    AND f.extracted_text = ''
                  ORDER BY b.document_id
                  LIMIT ?2",
            )?;
            let rows = statement
                .query_map(params![cutoff, limit as i64], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            rows
        };
        let mut claimed = Vec::with_capacity(ids.len());
        for id in ids {
            if tx.execute(
                "UPDATE document_text_backfill SET claimed_at = ?1
                  WHERE document_id = ?2 AND (claimed_at IS NULL OR claimed_at < ?3)",
                params![now, id, cutoff],
            )? == 0
            {
                continue;
            }
            if let Some(doc) = tx
                .query_row(
                    "SELECT d.id, d.content_hash, d.mime_type, d.size_bytes
                       FROM documents AS d
                       JOIN document_fields AS f ON f.document_id = d.id
                       JOIN document_text_backfill AS b ON b.document_id = d.id
                      WHERE d.id = ?1 AND f.extract_state = 'done'
                        AND f.has_extracted_text = 0 AND f.extracted_text = ''
                        AND b.claimed_at = ?2",
                    params![id, now],
                    |row| {
                        Ok(ClaimedDocument {
                            document_id: row.get(0)?,
                            content_hash: row.get(1)?,
                            mime_type: row.get(2)?,
                            size_bytes: row.get(3)?,
                        })
                    },
                )
                .optional()?
            {
                claimed.push(doc);
            }
        }
        tx.commit()?;
        Ok(claimed)
    }

    /// A fresh text-only claim for `content_hash`, when one exists.
    pub fn claimed_document_text_backfill(
        &self,
        content_hash: &str,
        cutoff: &str,
    ) -> Result<Option<ClaimedDocument>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT d.id, d.content_hash, d.mime_type, d.size_bytes
                   FROM documents AS d
                   JOIN document_fields AS f ON f.document_id = d.id
                   JOIN document_text_backfill AS b ON b.document_id = d.id
                  WHERE d.content_hash = ?1 AND b.claimed_at >= ?2
                    AND f.extract_state = 'done'
                    AND f.has_extracted_text = 0 AND f.extracted_text = ''",
                params![content_hash, cutoff],
                |row| {
                    Ok(ClaimedDocument {
                        document_id: row.get(0)?,
                        content_hash: row.get(1)?,
                        mime_type: row.get(2)?,
                        size_bytes: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Persist only extracted text for a fresh backfill claim. Non-empty text
    /// and rows cleared by a party-forget operation are never restored.
    pub fn complete_document_text_backfill(
        &self,
        document_id: i64,
        text: &str,
        cutoff: &str,
    ) -> Result<bool, StoreError> {
        if text.len() > DOCUMENT_TEXT_MAX_BYTES {
            return Err(StoreError::DocumentFieldsRejected {
                reason: "extracted text exceeds the local storage limit".into(),
            });
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let claimed: bool = tx.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM document_text_backfill AS b
                 JOIN document_fields AS f ON f.document_id = b.document_id
                WHERE b.document_id = ?1 AND b.claimed_at >= ?2
                  AND f.extract_state = 'done'
            )",
            params![document_id, cutoff],
            |row| row.get(0),
        )?;
        if !claimed {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "UPDATE document_fields
                SET extracted_text = ?2
              WHERE document_id = ?1 AND extract_state = 'done'
                AND has_extracted_text = 0 AND extracted_text = ''",
            params![document_id, text],
        )?;
        tx.execute(
            "DELETE FROM document_text_backfill WHERE document_id = ?1",
            [document_id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Finish the extraction of a claimed document. Returns `false` when the
    /// row is not claimed (the claim expired or the document is unknown).
    pub fn complete_document_fields(
        &self,
        document_id: i64,
        update: &DocumentExtraction<'_>,
    ) -> Result<bool, StoreError> {
        validate_extraction(update)?;
        let changed = self.conn.execute(
            "UPDATE document_fields
                SET kind = ?2, extractor = ?3, issuer = ?4, recipient = ?5, issued_on = ?6,
                    currency = ?7, total_minor = ?8, vat_minor = ?9, number = ?10,
                    fields_json = ?11, checks_json = ?12, party_id = ?13, status = ?14,
                    updated_at = ?15, extract_state = 'done', claimed_at = NULL,
                    extracted_text = ?16
              WHERE document_id = ?1 AND extract_state = 'claimed'",
            params![
                document_id,
                update.kind,
                update.extractor,
                update.issuer,
                update.recipient,
                update.issued_on,
                update.currency,
                update.total_minor,
                update.vat_minor,
                update.number,
                update.fields_json,
                update.checks_json,
                update.party_id,
                update.status,
                update.updated_at,
                update.extracted_text,
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn document_text_scan(&self) -> Result<DocumentTextScan, StoreError> {
        let available_documents: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM document_fields WHERE has_extracted_text = 1",
            [],
            |row| row.get(0),
        )?;
        let mut statement = self.conn.prepare(
            "SELECT d.id, d.original_name, f.kind, f.extracted_text
               FROM documents AS d
               JOIN document_fields AS f ON f.document_id = d.id
              WHERE f.has_extracted_text = 1
              ORDER BY d.id DESC LIMIT ?1",
        )?;
        let mut rows = statement.query([DOCUMENT_TEXT_SCAN_MAX_DOCS as i64])?;
        let mut documents = Vec::new();
        let mut total_bytes = 0usize;
        while let Some(row) = rows.next()? {
            let text: String = row.get(3)?;
            if total_bytes.saturating_add(text.len()) > DOCUMENT_TEXT_SCAN_MAX_BYTES {
                break;
            }
            total_bytes += text.len();
            documents.push(StoredDocumentText {
                document_id: row.get(0)?,
                original_name: row.get(1)?,
                kind: row.get(2)?,
                text,
            });
        }
        Ok(DocumentTextScan {
            documents,
            available_documents: available_documents.max(0) as usize,
            scanned_bytes: total_bytes,
        })
    }

    /// All extracted text for one document id; unlike search, this is not
    /// limited to the newest-document scan window.
    pub fn document_text(
        &self,
        document_id: i64,
    ) -> Result<Option<StoredDocumentText>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT d.id, d.original_name, f.kind, f.extracted_text
               FROM documents AS d
               JOIN document_fields AS f ON f.document_id = d.id
              WHERE d.id = ?1 AND f.has_extracted_text = 1",
                [document_id],
                |row| {
                    Ok(StoredDocumentText {
                        document_id: row.get(0)?,
                        original_name: row.get(1)?,
                        kind: row.get(2)?,
                        text: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn recent_document_texts(&self) -> Result<Vec<StoredDocumentText>, StoreError> {
        Ok(self.document_text_scan()?.documents)
    }

    /// The `documents.content_hash` of another document with the same issuer
    /// and number, when one exists. `documents.content_hash` is `UNIQUE`, so a
    /// second row for the same SHA-256 is impossible: the number is the only
    /// duplicate signal the registry can add.
    pub fn duplicate_document_number(
        &self,
        document_id: i64,
        issuer: &str,
        number: &str,
    ) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT d.content_hash
                   FROM document_fields AS f
                   JOIN documents AS d ON d.id = f.document_id
                  WHERE f.document_id != ?1
                    AND f.issuer = ?2
                    AND f.number = ?3
                  ORDER BY f.document_id
                  LIMIT 1",
                params![document_id, issuer, number],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Extracted invoices and receipts issued in `[from, to]` (ISO dates,
    /// inclusive), optionally of one party, oldest first, at most `limit`.
    /// Ignored documents and failed or unfinished extractions are left out.
    pub fn export_documents(
        &self,
        from: &str,
        to: &str,
        party_id: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ExportDocument>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT d.content_hash, d.mime_type, d.original_name, f.issued_on, f.number,
                    f.issuer, f.currency, f.total_minor, f.vat_minor, f.checks_json, f.party_id
               FROM document_fields AS f
               JOIN documents AS d ON d.id = f.document_id
              WHERE f.extract_state = 'done'
                AND f.kind IN ('invoice', 'receipt')
                AND f.status != 'ignored'
                AND f.issued_on IS NOT NULL
                AND f.issued_on BETWEEN ?1 AND ?2
                AND (?3 IS NULL OR f.party_id = ?3)
              ORDER BY f.issued_on, d.id
              LIMIT ?4",
        )?;
        let rows = statement.query_map(params![from, to, party_id, limit as i64], |row| {
            Ok(ExportDocument {
                content_hash: row.get(0)?,
                mime_type: row.get(1)?,
                original_name: row.get(2)?,
                issued_on: row.get(3)?,
                number: row.get(4)?,
                issuer: row.get(5)?,
                currency: row.get(6)?,
                total_minor: row.get(7)?,
                vat_minor: row.get(8)?,
                checks_json: row.get(9)?,
                party_id: row.get(10)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// One row of the owner's document list (M5-1): `document_fields` columns
/// (`None` before the first sweep) and the party's current name, no free text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentListRow {
    pub content_hash: String,
    pub extract_state: Option<String>,
    pub kind: Option<String>,
    pub issued_on: Option<String>,
    pub number: Option<String>,
    pub currency: Option<String>,
    pub total_minor: Option<i64>,
    pub vat_minor: Option<i64>,
    pub party_id: Option<i64>,
    pub party_name: Option<String>,
    pub party_archived: bool,
    pub checks_json: Option<String>,
}

impl Store {
    /// The newest `limit` documents, joined to their fields and party: only
    /// those linked to `party` when set, only unlinked ones when `unlinked`.
    pub fn document_list(
        &self,
        party: Option<i64>,
        unlinked: bool,
        limit: usize,
    ) -> Result<Vec<DocumentListRow>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT d.content_hash, f.extract_state, f.kind, f.issued_on, f.number, f.currency,
                    f.total_minor, f.vat_minor, f.party_id, p.display_name,
                    COALESCE(p.archived, 0), f.checks_json
               FROM documents AS d
               LEFT JOIN document_fields AS f ON f.document_id = d.id
               LEFT JOIN party AS p ON p.id = f.party_id
              WHERE (?2 IS NULL OR f.party_id = ?2) AND (?3 = 0 OR f.party_id IS NULL)
              ORDER BY d.id DESC
              LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64, party, unlinked], |row| {
            Ok(DocumentListRow {
                content_hash: row.get(0)?,
                extract_state: row.get(1)?,
                kind: row.get(2)?,
                issued_on: row.get(3)?,
                number: row.get(4)?,
                currency: row.get(5)?,
                total_minor: row.get(6)?,
                vat_minor: row.get(7)?,
                party_id: row.get(8)?,
                party_name: row.get(9)?,
                party_archived: row.get::<_, i64>(10)? != 0,
                checks_json: row.get(11)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// A document found by hash prefix, for the owner's link and unlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentRef {
    /// `documents.id`.
    pub document_id: i64,
    /// Lowercase SHA-256 of the original.
    pub content_hash: String,
    /// The queue state; `None` before the first sweep.
    pub extract_state: Option<String>,
    /// The checks as JSON.
    pub checks_json: Option<String>,
}

/// Result of scheduling an explicit owner erase. Blob removal is retried from
/// `evidence_erase_tombstones` at startup if the process stops after commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentEraseResult {
    /// Registry rows were deleted and this sealed blob must be removed.
    Erased(String),
    /// No document has this prefix.
    NotFound,
    /// More than one document has this prefix.
    Ambiguous,
    /// Prefixes must be 8–64 lowercase hexadecimal characters.
    InvalidPrefix,
}

impl Store {
    /// Up to two documents whose hash starts with `prefix`. The caller
    /// validates `prefix` as lowercase hex, so it carries no `LIKE` wildcard.
    pub fn documents_by_hash_prefix(&self, prefix: &str) -> Result<Vec<DocumentRef>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT d.id, d.content_hash, f.extract_state, f.checks_json
               FROM documents AS d
               LEFT JOIN document_fields AS f ON f.document_id = d.id
              WHERE d.content_hash LIKE ?1 || '%'
              ORDER BY d.id
              LIMIT 2",
        )?;
        let rows = statement.query_map([prefix], |row| {
            Ok(DocumentRef {
                document_id: row.get(0)?,
                content_hash: row.get(1)?,
                extract_state: row.get(2)?,
                checks_json: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Delete every local registry row for one unambiguous owner-selected hash
    /// prefix and commit a blob-deletion tombstone in the same transaction.
    pub fn erase_document_by_hash_prefix(
        &self,
        prefix: &str,
    ) -> Result<DocumentEraseResult, StoreError> {
        if !(8..=64).contains(&prefix.len())
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(DocumentEraseResult::InvalidPrefix);
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let matches: Vec<(i64, String)> = {
            let mut statement = tx.prepare(
                "SELECT id, content_hash FROM documents
                  WHERE content_hash LIKE ?1 || '%' ORDER BY id LIMIT 2",
            )?;
            let rows = statement
                .query_map([prefix], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<_, _>>()?;
            rows
        };
        if matches.is_empty() {
            tx.commit()?;
            return Ok(DocumentEraseResult::NotFound);
        }
        if matches.len() > 1 {
            tx.commit()?;
            return Ok(DocumentEraseResult::Ambiguous);
        }
        let (document_id, content_hash) = matches.into_iter().next().expect("one matching row");
        tx.execute(
            "INSERT INTO evidence_erase_tombstones(document_id, content_hash)
             VALUES (?1, ?2)",
            params![document_id, content_hash],
        )?;
        scrub_document_tool_messages(&tx, document_id, &content_hash)?;
        tx.execute("DELETE FROM proofs WHERE document_id = ?1", [document_id])?;
        tx.execute(
            "DELETE FROM corrections WHERE document_id = ?1",
            [document_id],
        )?;
        tx.execute(
            "DELETE FROM evidence_source WHERE document_id = ?1",
            [document_id],
        )?;
        tx.execute(
            "DELETE FROM document_text_backfill WHERE document_id = ?1",
            [document_id],
        )?;
        tx.execute(
            "DELETE FROM document_fields WHERE document_id = ?1",
            [document_id],
        )?;
        tx.execute(
            "DELETE FROM documents WHERE id = ?1 AND content_hash = ?2",
            params![document_id, content_hash],
        )?;
        tx.commit()?;
        Ok(DocumentEraseResult::Erased(content_hash))
    }

    /// The per-hash locks a `docs_ingest` result must hold from its erasure
    /// re-check through persistence. IDs and hashes are read from every nested
    /// object, including search `matches[]` entries.
    pub fn document_result_lifecycle_locks(
        &self,
        content: &str,
    ) -> Result<Vec<Arc<Mutex<()>>>, StoreError> {
        let Some((_, value)) = payload_value(content) else {
            return Ok(Vec::new());
        };
        let mut targets = HashSet::new();
        collect_targets(&value, &mut targets);
        let mut hashes = BTreeSet::new();
        for target in targets {
            if let Some(hash) = target.content_hash.filter(|hash| is_sha256(hash)) {
                hashes.insert(hash);
            }
            if let Some(document_id) = target.document_id {
                let live: Option<String> = self
                    .conn
                    .query_row(
                        "SELECT content_hash FROM documents WHERE id = ?1",
                        [document_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let pending: Option<String> = if live.is_none() {
                    self.conn
                        .query_row(
                            "SELECT content_hash FROM evidence_erase_tombstones WHERE document_id = ?1",
                            [document_id],
                            |row| row.get(0),
                        )
                        .optional()?
                } else {
                    None
                };
                if let Some(hash) = live.or(pending).filter(|hash| is_sha256(hash)) {
                    hashes.insert(hash);
                }
            }
        }
        Ok(hashes
            .iter()
            .map(|hash| evidence_lifecycle_lock(hash))
            .collect())
    }

    /// Re-check every document in a saved tool payload after its lifecycle
    /// locks are held. Erased hits become the plain unavailable sentence; live
    /// search hits and empty results stay intact.
    pub fn scrub_erased_document_result(&self, content: &str) -> Result<String, StoreError> {
        let Some((_, value)) = payload_value(content) else {
            return Ok(DOCUMENT_UNAVAILABLE_TEXT.into());
        };
        let mut targets = HashSet::new();
        collect_targets(&value, &mut targets);
        let mut erased = ErasedDocumentTargets::default();
        for target in targets {
            if self.document_target_is_live(&target)? {
                continue;
            }
            if let Some(id) = target.document_id {
                erased.ids.insert(id);
            }
            if let Some(hash) = target.content_hash {
                erased.hashes.insert(hash);
            }
        }
        Ok(scrub_document_payload(content, &erased).unwrap_or_else(|| content.to_string()))
    }

    fn document_target_is_live(&self, target: &DocumentTarget) -> Result<bool, StoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM documents d
              WHERE (?1 IS NULL OR d.id = ?1) AND (?2 IS NULL OR d.content_hash = ?2)
                AND NOT EXISTS (SELECT 1 FROM evidence_erase_tombstones e
                                WHERE e.document_id = d.id OR e.content_hash = d.content_hash))",
            params![target.document_id, target.content_hash.as_deref()],
            |row| row.get(0),
        )?)
    }

    /// Blob hashes whose owner-erasure transaction committed but whose file
    /// cleanup has not yet been acknowledged.
    pub fn pending_evidence_erases(&self) -> Result<Vec<String>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT content_hash FROM evidence_erase_tombstones ORDER BY created_at, content_hash",
        )?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Clear the durable tombstone only after the matching blob is absent.
    pub fn finish_evidence_erasure(&self, content_hash: &str) -> Result<bool, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM evidence_erase_tombstones WHERE content_hash = ?1",
            [content_hash],
        )? == 1)
    }

    /// The owner links (`Some`) or unlinks (`None`) a read document. Unlink is
    /// only a link change; OCR and evidence require explicit erase or forget.
    /// Returns `false` when no such row exists.
    pub fn set_document_party(
        &self,
        document_id: i64,
        party_id: Option<i64>,
        checks_json: &str,
        updated_at: &str,
    ) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE document_fields
                SET party_id = ?2, checks_json = ?3, updated_at = ?4
              WHERE document_id = ?1 AND extract_state IN ('done', 'failed')",
            params![document_id, party_id, checks_json, updated_at],
        )?;
        Ok(changed == 1)
    }
}

/// Move every document linked to party `from` to `to` inside the caller's
/// transaction: `Some(to)` for a CRM merge, `None` for a forget. A merge keeps
/// the extracted text; a forget clears it and cancels queued backfill so OCR
/// cannot outlive the forgotten client link. The receipt and checks remain,
/// and the `party_match` check follows the link. A row whose `checks_json` is
/// not a readable array keeps its checks as they are, so a corrupted row never
/// blocks the owner's right to forget.
pub(crate) fn relink_party_documents_in_tx(
    tx: &Transaction<'_>,
    from: i64,
    to: Option<i64>,
) -> Result<(), StoreError> {
    let rows: Vec<(i64, String)> = {
        let mut stmt =
            tx.prepare("SELECT document_id, checks_json FROM document_fields WHERE party_id = ?1")?;
        let rows = stmt
            .query_map([from], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        rows
    };
    if to.is_none() {
        tx.execute(
            "DELETE FROM document_text_backfill WHERE document_id IN (
                 SELECT document_id FROM document_fields WHERE party_id = ?1
             )",
            [from],
        )?;
    }
    let mut update = tx.prepare(
        "UPDATE document_fields SET party_id = ?1, checks_json = ?2,
               extracted_text = CASE WHEN ?1 IS NULL THEN '' ELSE extracted_text END
          WHERE document_id = ?3",
    )?;
    for (document_id, checks_json) in rows {
        let checks = relinked_checks(&checks_json, to).unwrap_or(checks_json);
        update.execute(params![to, checks, document_id])?;
    }
    Ok(())
}

/// The `party_match` check rewritten for the new link: on a forget it no
/// longer passes (`unknown`, "client forgotten"); on a merge a passing check
/// names the target. `None` when the JSON is not an array of checks.
fn relinked_checks(checks_json: &str, to: Option<i64>) -> Option<String> {
    let mut checks: serde_json::Value = serde_json::from_str(checks_json).ok()?;
    for check in checks.as_array_mut()? {
        let Some(check) = check.as_object_mut() else {
            continue;
        };
        if check.get("name").and_then(|name| name.as_str()) != Some("party_match") {
            continue;
        }
        match to {
            None => {
                check.insert("state".to_string(), "unknown".into());
                check.insert("reason".to_string(), "client forgotten".into());
            }
            Some(to) if check.get("state").and_then(|state| state.as_str()) == Some("pass") => {
                check.insert(
                    "reason".to_string(),
                    format!("matched CRM party {to}").into(),
                );
            }
            Some(_) => {}
        }
    }
    serde_json::to_string(&checks).ok()
}

/// A read document linked to no client, with the names the matcher reads
/// (DOCS-RELINK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkedDocument {
    /// `documents.id`.
    pub document_id: i64,
    /// The extracted issuer, when kept (open mode).
    pub issuer: Option<String>,
    /// The extracted recipient, when kept (open mode).
    pub recipient: Option<String>,
    /// The checks as JSON.
    pub checks_json: String,
}

impl Store {
    /// Up to `limit` read (`done`) documents with no client and an issuer or
    /// recipient, newest first: the ones a new client may match.
    pub fn unlinked_read_documents(
        &self,
        limit: usize,
    ) -> Result<Vec<UnlinkedDocument>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT document_id, issuer, recipient, checks_json FROM document_fields
              WHERE extract_state = 'done' AND party_id IS NULL
                AND (issuer IS NOT NULL OR recipient IS NOT NULL)
              ORDER BY document_id DESC
              LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(UnlinkedDocument {
                document_id: row.get(0)?,
                issuer: row.get(1)?,
                recipient: row.get(2)?,
                checks_json: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Link an unlinked document only if nothing changed since it was read
    /// (still unlinked, same checks), so a re-match never overwrites the
    /// owner's link or unlink made in between. True when the row changed.
    pub fn link_if_unchanged(
        &self,
        document_id: i64,
        party_id: i64,
        read_checks: &str,
        checks_json: &str,
        updated_at: &str,
    ) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE document_fields
                SET party_id = ?2, checks_json = ?4, updated_at = ?5
              WHERE document_id = ?1 AND extract_state = 'done' AND party_id IS NULL
                AND checks_json = ?3",
            params![document_id, party_id, read_checks, checks_json, updated_at],
        )?;
        Ok(changed == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remove_document_text_additions_for_legacy_fixture;
    use crate::testutil::*;
    use crate::{NewEvidenceDocument, SCHEMA_VERSION};
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn fresh_store_has_the_document_fields_schema() {
        let store = Store::open_in_memory().unwrap();
        let columns = table_columns(&store, "document_fields");
        for column in [
            "document_id",
            "kind",
            "extractor",
            "issuer",
            "recipient",
            "issued_on",
            "currency",
            "total_minor",
            "vat_minor",
            "number",
            "fields_json",
            "checks_json",
            "party_id",
            "tags",
            "status",
            "updated_at",
            "extract_state",
            "claimed_at",
            "attempts",
            "extracted_text",
            "has_extracted_text",
        ] {
            assert!(columns.contains(&column.to_string()), "missing {column}");
        }
        // v24–v38 add delegation usage, private tokens, CRM direction,
        // extracted text and its backfill/search/erasure indexes, timeline
        // taint, the seeded note counter, the sticky per-session Private
        // mark, the usage provider cleanup, the mail draft claim states, the
        // client's own time zone and the money a reservation holds.
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 38);
    }

    #[test]
    fn only_canonical_empty_document_results_stay_unscrubbed() {
        let store = Store::open_in_memory().unwrap();
        for empty in [
            r#"{"found":false}"#,
            r#"{"matches":[],"total":0,"truncated":false,"query_truncated":false,"searched_documents":0,"available_documents":0,"scanned_bytes":0,"search_scope":"searched all 0 documents"}"#,
            r#"{"matches":[],"total":0,"truncated":true,"query_truncated":false,"searched_documents":256,"available_documents":300,"scanned_bytes":1024,"search_scope":"searched newest 256 of 300 documents"}"#,
        ] {
            assert_eq!(
                store.scrub_erased_document_result(empty).unwrap(),
                empty,
                "a canonical empty result carries no document text"
            );
        }
        for crafted in [
            r#"{"matches":[],"text":"ERASE-PROBE-CANARY"}"#,
            r#"{"found":false,"title":"ERASE-PROBE-CANARY"}"#,
            r#"{"found":false,"fields":{"title":"ERASE-PROBE-CANARY"}}"#,
            r#"{"matches":[],"fields":{"title":"ERASE-PROBE-CANARY"}}"#,
            r#"{"matches":[],"results":["ERASE-PROBE-CANARY"]}"#,
            r#"{"matches":[],"notes":["ERASE-PROBE-CANARY"]}"#,
            r#"{"matches":[],"total":0,"truncated":false,"query_truncated":false,"searched_documents":0,"available_documents":0,"scanned_bytes":0,"search_scope":"ERASE-PROBE-CANARY"}"#,
            r#"{"matches":[]}"#,
        ] {
            assert_eq!(
                store.scrub_erased_document_result(crafted).unwrap(),
                DOCUMENT_UNAVAILABLE_TEXT,
                "a non-canonical empty envelope must be erased: {crafted}"
            );
        }
    }

    /// ERASE-ASSISTANT-ECHO: an erase also rewrites the assistant's own
    /// replies that quoted the erased excerpt verbatim, in the threads that
    /// read the document. Other documents' quotes and other threads stay.
    #[test]
    fn an_erase_rewrites_assistant_replies_that_quoted_the_document_verbatim() {
        const ERASED: &str = "The tenant pays 1 250 EUR on the first of each month.";
        const KEPT: &str = "Delivery is due within thirty days of signature.";
        let store = Store::open_in_memory().unwrap();
        let insert = |hash: &str| {
            store.conn.execute("INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source, original_name)
                 VALUES (?1, ?2, 1, 'text/plain', 'test', 'doc.txt')",
                rusqlite::params![hash, format!("evidence/{hash}")]).unwrap();
            store.conn.last_insert_rowid()
        };
        let hash = "a".repeat(64);
        let erased_id = insert(&hash);
        let kept_id = insert(&"b".repeat(64));
        let thread = store.create_session("main", None).unwrap().id;
        let other = store.create_session("main", None).unwrap().id;
        let result = format!(
            "[untrusted document content]\n{}",
            serde_json::json!({"matches":[
                {"document_id":erased_id,"excerpt":ERASED,"page":"2"},
                {"document_id":kept_id,"excerpt":KEPT}
            ]})
        );
        store
            .append_message(thread, "tool", &result, Some(r#"{"tool":"docs_search"}"#))
            .unwrap();
        let echo = format!("The lease says: {ERASED} The other contract says: {KEPT}");
        let meta = serde_json::json!({"tool_calls":[{"id":"c1","name":"delegate",
            "arguments":{"brief":ERASED}}]})
        .to_string();
        store
            .append_message(thread, "assistant", &echo, Some(&meta))
            .unwrap();
        store
            .append_message(other, "assistant", &echo, None)
            .unwrap();
        store.append_message(thread, "user", &echo, None).unwrap();

        store.erase_document_by_hash_prefix(&hash[..12]).unwrap();

        let rows = store.list_messages(thread).unwrap();
        let row = rows.iter().find(|row| row.role == "assistant").unwrap();
        assert!(!row.content.contains(ERASED), "{}", row.content);
        assert_eq!(
            row.content,
            format!("The lease says: {DOCUMENT_UNAVAILABLE_TEXT} The other contract says: {KEPT}")
        );
        let meta: serde_json::Value = serde_json::from_str(row.meta.as_deref().unwrap()).unwrap();
        assert_eq!(
            meta["tool_calls"][0]["arguments"]["brief"], DOCUMENT_UNAVAILABLE_TEXT,
            "a tool call that carried the excerpt is rewritten too"
        );
        assert_eq!(
            store.list_messages(other).unwrap()[0].content,
            echo,
            "a thread that never read the document is untouched"
        );
        assert_eq!(
            rows.iter().find(|row| row.role == "user").unwrap().content,
            echo,
            "the owner's own words are not rewritten"
        );
        // A short leaf ("2") is never an echo: it would hit ordinary text.
        assert!(erased_document_texts(&result, DOCUMENT_UNAVAILABLE_TEXT)
            .iter()
            .all(|text| text.chars().count() >= ERASED_ECHO_MIN_CHARS));
    }

    /// ERASE-ECHO-ESCAPED: a stored tool call keeps its `arguments` as a
    /// JSON-encoded string, so a quote with a newline or a double quote is
    /// escaped inside `meta`. The erase must reach it, and the rewritten meta
    /// must stay valid JSON with the call replayable.
    #[test]
    fn an_erase_rewrites_escaped_quotes_in_stored_tool_call_arguments() {
        const ERASED: &str = "Clause 4:\nThe tenant pays \"1 250 EUR\" on the first of each month.";
        const KEPT: &str = "Delivery is due within thirty days of signature.";
        let store = Store::open_in_memory().unwrap();
        let insert = |hash: &str| {
            store.conn.execute("INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source, original_name)
                 VALUES (?1, ?2, 1, 'text/plain', 'test', 'doc.txt')",
                rusqlite::params![hash, format!("evidence/{hash}")]).unwrap();
            store.conn.last_insert_rowid()
        };
        let hash = "c".repeat(64);
        let erased_id = insert(&hash);
        let kept_id = insert(&"d".repeat(64));
        let thread = store.create_session("main", None).unwrap().id;
        let result = format!(
            "[untrusted document content]\n{}",
            serde_json::json!({"matches":[
                {"document_id":erased_id,"excerpt":ERASED},
                {"document_id":kept_id,"excerpt":KEPT}
            ]})
        );
        store
            .append_message(thread, "tool", &result, Some(r#"{"tool":"docs_search"}"#))
            .unwrap();
        let echo = format!("The lease says: {ERASED} The delivery note says: {KEPT}");
        // The shape the engine writes: `arguments` is a JSON string, so the
        // excerpt's newline and quotes are escaped a second time.
        let arguments =
            serde_json::json!({"brief": ERASED, "note": KEPT, "quotes": [KEPT, ERASED]})
                .to_string();
        let meta = serde_json::json!({"tool_calls":[{
            "id":"call_1","type":"function",
            "function":{"name":"delegate","arguments":arguments}
        }]})
        .to_string();
        assert!(
            !meta.contains(ERASED),
            "the fixture must be escaped in meta"
        );
        store
            .append_message(thread, "assistant", &echo, Some(&meta))
            .unwrap();

        store.erase_document_by_hash_prefix(&hash[..12]).unwrap();

        let rows = store.list_messages(thread).unwrap();
        let row = rows.iter().find(|row| row.role == "assistant").unwrap();
        let meta = row.meta.as_deref().expect("the row keeps its meta");
        let escaped = serde_json::to_string(ERASED).unwrap();
        let escaped = escaped
            .strip_prefix('"')
            .and_then(|body| body.strip_suffix('"'))
            .unwrap();
        for leaked in [ERASED, escaped] {
            assert!(!row.content.contains(leaked), "content: {}", row.content);
            assert!(!meta.contains(leaked), "meta: {meta}");
        }
        assert!(row.content.contains(DOCUMENT_UNAVAILABLE_TEXT));
        assert!(row.content.contains(KEPT));
        let parsed: serde_json::Value =
            serde_json::from_str(meta).expect("the scrubbed meta is still valid JSON");
        assert_eq!(parsed["tool_calls"][0]["id"], "call_1");
        assert_eq!(parsed["tool_calls"][0]["function"]["name"], "delegate");
        let arguments = parsed["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments stay a JSON-encoded string");
        let arguments: serde_json::Value =
            serde_json::from_str(arguments).expect("the scrubbed arguments still parse");
        assert_eq!(arguments["brief"], DOCUMENT_UNAVAILABLE_TEXT);
        assert_eq!(arguments["note"], KEPT, "the other excerpt stays");
        assert_eq!(
            arguments["quotes"],
            serde_json::json!([KEPT, DOCUMENT_UNAVAILABLE_TEXT]),
            "array leaves are walked too"
        );
    }

    /// The fallback is a strict superset of the old raw replace: a malformed
    /// meta still loses the escaped excerpt, not only the plain one.
    #[test]
    fn a_malformed_meta_still_loses_the_raw_and_escaped_excerpt() {
        const ERASED: &str = "Clause 4:\nThe tenant pays \"1 250 EUR\".";
        let echoes = vec![ERASED.to_string()];
        let escaped = json_escaped_body(ERASED).unwrap();
        let raw = format!("note {ERASED}");
        assert_eq!(
            scrub_meta_echo(&raw, &echoes).unwrap(),
            format!("note {DOCUMENT_UNAVAILABLE_TEXT}")
        );
        let broken = format!("{{\"note\":\"{escaped}\"");
        let scrubbed = scrub_meta_echo(&broken, &echoes).expect("the fallback scrubs");
        assert!(!scrubbed.contains(&escaped), "{scrubbed}");
        assert!(!scrubbed.contains(ERASED), "{scrubbed}");
        assert!(scrubbed.contains(DOCUMENT_UNAVAILABLE_TEXT), "{scrubbed}");
    }

    #[test]
    fn local_document_text_is_stored_for_search_and_excerpt_reads() {
        let store = Store::open_in_memory().unwrap();
        let hash = "d".repeat(64);
        store.conn.execute("INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source, original_name)
             VALUES (?1, ?2, 1, 'application/pdf', 'test', 'invoice.pdf')",
            rusqlite::params![hash, format!("evidence/{hash}")]).unwrap();
        let id = store.conn.last_insert_rowid();
        store.conn.execute("INSERT INTO document_fields(document_id, kind, extractor, fields_json, checks_json,
             status, updated_at, extract_state, attempts, extracted_text)
             VALUES (?1, 'invoice', 'pdf_text', '{}', '[]', 'to_check', '2026-10-25T00:00:00Z', 'done', 1, 'INV-26-044')",
            [id]).unwrap();
        let stored = store.recent_document_texts().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].document_id, id);
        assert_eq!(stored[0].original_name.as_deref(), Some("invoice.pdf"));
        assert_eq!(stored[0].text, "INV-26-044");
    }

    #[test]
    fn v28_upgrade_preserves_owner_fields_and_backfills_only_nonforgotten_text() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v28.db");
        let (party_id, [linked_id, unlinked_id, forgotten_id]) = write_v28_document_store(&path);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let row = |id| {
            store
                .conn
                .query_row(
                    "SELECT extract_state, status, party_id, fields_json, extracted_text
                       FROM document_fields WHERE document_id = ?1",
                    [id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    },
                )
                .unwrap()
        };
        assert_eq!(
            row(linked_id),
            (
                "done".into(),
                "filed".into(),
                Some(party_id),
                r#"{"owner_note":"keep me"}"#.into(),
                String::new()
            )
        );
        assert_eq!(row(unlinked_id).0, "done");
        assert_eq!(row(unlinked_id).1, "ignored");
        assert_eq!(row(forgotten_id).0, "done");
        assert_eq!(row(forgotten_id).1, "filed");
        assert!(store
            .claim_document_fields("2026-10-26T00:00:00Z", 10)
            .unwrap()
            .is_empty());

        let backfills: Vec<i64> = store
            .conn
            .prepare("SELECT document_id FROM document_text_backfill ORDER BY document_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(backfills, vec![linked_id, unlinked_id]);

        let claimed = store
            .claim_document_text_backfills("2026-10-26T00:00:00Z", "2026-10-25T23:50:00Z", 10)
            .unwrap();
        assert_eq!(
            claimed
                .iter()
                .map(|document| document.document_id)
                .collect::<Vec<_>>(),
            vec![linked_id, unlinked_id]
        );
        assert!(store
            .complete_document_text_backfill(
                linked_id,
                "recovered local OCR",
                "2026-10-25T23:50:00Z",
            )
            .unwrap());
        assert_eq!(
            row(linked_id),
            (
                "done".into(),
                "filed".into(),
                Some(party_id),
                r#"{"owner_note":"keep me"}"#.into(),
                "recovered local OCR".into()
            )
        );
        let searchable = store.document_text_scan().unwrap();
        assert_eq!(searchable.available_documents, 1);
        assert_eq!(searchable.documents[0].document_id, linked_id);
        assert!(!searchable
            .documents
            .iter()
            .any(|document| document.document_id == forgotten_id));
    }

    #[test]
    fn text_backfill_changes_only_empty_text_and_preserves_owner_fields() {
        let store = Store::open_in_memory().unwrap();
        let party_id = store.insert_party(&camille_party()).unwrap();
        let hash = "b".repeat(64);
        let document_id = store
            .append_evidence(
                &NewEvidenceDocument {
                    content_hash: &hash,
                    storage_path: &format!("evidence/{hash}"),
                    size_bytes: 4,
                    mime_type: "application/pdf",
                    original_name: "backfill.pdf",
                    account_id: "personal",
                    captured_at: "2026-10-25T00:00:00Z",
                },
                "{}",
                "2026-10-25T00:00:00Z",
            )
            .unwrap()
            .document_id;
        store
            .insert_document_fields(&NewDocumentFields {
                document_id,
                kind: "invoice",
                extractor: "pdf_text",
                issuer: Some("Northwind"),
                recipient: None,
                issued_on: None,
                currency: Some("EUR"),
                total_minor: Some(12_000),
                vat_minor: None,
                number: Some("NW-28"),
                fields_json: r#"{"owner_note":"keep me"}"#,
                extracted_text: "",
                checks_json: "[]",
                party_id: Some(party_id),
                tags: "[]",
                status: "filed",
                updated_at: "2026-10-25T00:00:00Z",
                extract_state: "done",
                claimed_at: None,
                attempts: 2,
            })
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO document_text_backfill(document_id) VALUES (?1)",
                [document_id],
            )
            .unwrap();

        let claimed = store
            .claim_document_text_backfills("2026-10-26T00:00:00Z", "2026-10-25T23:50:00Z", 1)
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert!(store
            .complete_document_text_backfill(document_id, "new OCR text", "2026-10-25T23:50:00Z",)
            .unwrap());

        let row: (String, i64, String, i64, String, i64) = store
            .conn
            .query_row(
                "SELECT status, party_id, fields_json, total_minor,
                        extracted_text, has_extracted_text
                   FROM document_fields WHERE document_id = ?1",
                [document_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "filed".into(),
                party_id,
                r#"{"owner_note":"keep me"}"#.into(),
                12_000,
                "new OCR text".into(),
                1
            )
        );
        assert_eq!(
            store
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM document_text_backfill WHERE document_id = ?1",
                    [document_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn document_search_reports_its_bounded_horizon_and_id_read_is_unbounded() {
        let store = Store::open_in_memory().unwrap();
        let mut oldest = 0;
        for n in 0..300 {
            let hash = format!("{:064x}", n + 1);
            store.conn.execute(
                "INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source)
                 VALUES (?1, ?2, 1, 'application/pdf', 'test')",
                rusqlite::params![hash, format!("evidence/{hash}")],
            ).unwrap();
            let id = store.conn.last_insert_rowid();
            if n == 0 {
                oldest = id;
            }
            store.conn.execute(
                "INSERT INTO document_fields(document_id, kind, extractor, fields_json, checks_json,
                 status, updated_at, extract_state, attempts, extracted_text)
                 VALUES (?1, 'other', 'pdf_text', '{}', '[]', 'to_check',
                         '2026-10-25T00:00:00Z', 'done', 1, ?2)",
                rusqlite::params![id, format!("document {n}")],
            ).unwrap();
        }

        let scan = store.document_text_scan().unwrap();
        assert_eq!(scan.documents.len(), 256);
        assert_eq!(scan.available_documents, 300);
        assert!(scan.documents.iter().all(|doc| doc.document_id != oldest));
        let count_plan: Vec<String> = store
            .conn
            .prepare(
                "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM document_fields
                  WHERE has_extracted_text = 1",
            )
            .unwrap()
            .query_map([], |row| row.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            count_plan
                .iter()
                .any(|step| step.contains("document_fields_nonempty_text")),
            "the count must use the partial non-empty-text index: {count_plan:?}"
        );
        let old = store
            .document_text(oldest)
            .unwrap()
            .expect("old id is readable");
        assert_eq!(old.text, "document 0");
    }

    #[test]
    fn document_search_reports_the_byte_limited_horizon() {
        let store = Store::open_in_memory().unwrap();
        let text = "x".repeat(DOCUMENT_TEXT_MAX_BYTES);
        for n in 0..17 {
            let hash = format!("{:064x}", n + 10_000);
            store.conn.execute(
                "INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source)
                 VALUES (?1, ?2, 1, 'application/pdf', 'test')",
                rusqlite::params![hash, format!("evidence/{hash}")],
            ).unwrap();
            let id = store.conn.last_insert_rowid();
            store.conn.execute(
                "INSERT INTO document_fields(document_id, kind, extractor, fields_json, checks_json,
                 status, updated_at, extract_state, attempts, extracted_text)
                 VALUES (?1, 'other', 'ocr', '{}', '[]', 'to_check',
                         '2026-10-25T00:00:00Z', 'done', 1, ?2)",
                rusqlite::params![id, text],
            ).unwrap();
        }

        let scan = store.document_text_scan().unwrap();
        assert_eq!(scan.documents.len(), 16);
        assert_eq!(scan.available_documents, 17);
        assert_eq!(scan.scanned_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn unlinking_a_document_keeps_its_stored_ocr_text() {
        let store = Store::open_in_memory().unwrap();
        let hash = "e".repeat(64);
        store
            .conn
            .execute(
                "INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source)
             VALUES (?1, ?2, 1, 'application/pdf', 'test')",
                rusqlite::params![hash, format!("evidence/{hash}")],
            )
            .unwrap();
        let id = store.conn.last_insert_rowid();
        store.conn.execute(
            "INSERT INTO document_fields(document_id, kind, extractor, fields_json, checks_json,
             status, updated_at, extract_state, attempts, extracted_text)
             VALUES (?1, 'other', 'ocr', '{}', '[]', 'to_check', '2026-10-25T00:00:00Z', 'done', 1,
                     'OCR extracted confidential source text')",
            [id],
        ).unwrap();

        assert!(store
            .set_document_party(id, None, "[]", "2026-10-26T00:00:00Z")
            .unwrap());
        let retained: String = store
            .conn
            .query_row(
                "SELECT extracted_text FROM document_fields WHERE document_id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, "OCR extracted confidential source text");
        assert_eq!(store.recent_document_texts().unwrap().len(), 1);
    }

    /// A v28 store has document fields but no extracted-text or text-backfill
    /// columns. The inserted rows model a filed owner-linked invoice, an
    /// owner-unlinked row, and a forgotten party row.
    fn write_v28_document_store(path: &Path) -> (i64, [i64; 3]) {
        let store = Store::open(path).unwrap();
        let party_id = store.insert_party(&camille_party()).unwrap();
        let checks = [
            r#"[{"name":"party_match","state":"pass","reason":"matched"}]"#,
            r#"[{"name":"party_match","state":"unknown","reason":"unlinked by the owner"}]"#,
            r#"[{"name":"party_match","state":"unknown","reason":"client forgotten"}]"#,
        ];
        let statuses = ["filed", "ignored", "filed"];
        let parties = [Some(party_id), None, None];
        let mut ids = [0; 3];
        for index in 0..3 {
            let hash = format!("{:064x}", index + 1);
            let append = store
                .append_evidence(
                    &NewEvidenceDocument {
                        content_hash: &hash,
                        storage_path: &format!("evidence/{hash}"),
                        size_bytes: 4,
                        mime_type: "application/pdf",
                        original_name: "v28.pdf",
                        account_id: "personal",
                        captured_at: "2026-10-25T00:00:00Z",
                    },
                    "{}",
                    "2026-10-25T00:00:00Z",
                )
                .unwrap();
            store
                .conn
                .execute(
                    "INSERT INTO document_fields(
                         document_id, kind, extractor, issuer, number, fields_json,
                         checks_json, party_id, tags, status, updated_at, extract_state,
                         claimed_at, attempts, extracted_text)
                     VALUES (?1, 'invoice', 'pdf_text', 'Northwind', 'NW-28',
                         '{\"owner_note\":\"keep me\"}', ?2, ?3, '[]', ?4,
                         '2026-10-25T00:00:00Z', 'done', NULL, 2, '')",
                    rusqlite::params![
                        append.document_id,
                        checks[index],
                        parties[index],
                        statuses[index]
                    ],
                )
                .unwrap();
            ids[index] = append.document_id;
        }

        remove_document_text_additions_for_legacy_fixture(&store.conn).unwrap();
        store
            .conn
            .execute_batch("UPDATE meta SET value = '28' WHERE key = 'schema_version';")
            .unwrap();
        drop(store);
        (party_id, ids)
    }
}
