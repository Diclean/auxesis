//! The extractor chain over the registry and the durable bridge queue.
//!
//! [`sweep_and_claim`] is the one entry point the local API calls: it runs the
//! chain over every document that has no `document_fields` row yet, then
//! claims up to `limit` bridge documents. XML is parsed here in Rust; anything
//! else waits for the Mac bridge (`pdf_text`, then `ocr`), which posts its text
//! back through [`store_text_extraction`]. Nothing here logs a body, a file
//! name or a field value.

use std::path::Path;

use serde::Serialize;

use crate::extract::{self, Check, CheckState, Extracted, Extractor, Fields, PartyRef};
use aux_store::{
    DocumentExtraction, NewDocumentFields, Store, StoreError, EXTRACT_CLAIM_TIMEOUT_SECS,
};

/// The largest text the bridge may post after extraction (1 MiB).
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// How many unprocessed documents one sweep looks at.
const SWEEP_LIMIT: usize = 256;

/// A failure of the queue or the extractor chain.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// The store refused a read or write.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// A registered document has no readable blob.
    #[error("the evidence blob for a registered document is unreadable")]
    Blob,
    /// The document is not currently claimed by the bridge.
    #[error("the document is not claimed")]
    NotClaimed,
    /// The posted text is over the 1 MiB ceiling.
    #[error("the text exceeds the 1 MiB limit")]
    TextTooLarge,
    /// The extractor name is not `pdf_text`, `ocr` or `none`.
    #[error("unknown extractor")]
    UnknownExtractor,
}

/// One document handed to the bridge. It deliberately carries no name and no
/// body: the bridge fetches the bytes through the blob route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingDocument {
    /// Lowercase SHA-256 of the original.
    pub hash: String,
    /// Declared MIME type.
    pub mime: String,
    /// Original size in bytes.
    pub size: i64,
}

/// One blob to serve to the bridge, with its declared MIME type.
#[derive(Debug, Clone)]
pub struct ClaimedBlob {
    /// The original bytes.
    pub bytes: Vec<u8>,
    /// Declared MIME type.
    pub mime: String,
}

/// The result of one text extraction.
#[derive(Debug, Clone)]
pub struct StoredExtraction {
    /// `documents.id`.
    pub document_id: i64,
    /// The checks, as stored.
    pub checks: Vec<Check>,
}

/// The RFC 3339 UTC instant `now - timeout`, the freshness cutoff for claims.
pub fn claim_cutoff(now: chrono::DateTime<chrono::Utc>) -> String {
    (now - chrono::Duration::seconds(EXTRACT_CLAIM_TIMEOUT_SECS))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The clock and privacy mode one queue pass runs under. `now` and `cutoff`
/// are RFC 3339 UTC strings so tests can drive the clock; `private` keeps only
/// metadata at rest.
#[derive(Debug, Clone, Copy)]
pub struct ExtractWindow<'a> {
    /// RFC 3339 UTC "now".
    pub now: &'a str,
    /// RFC 3339 UTC instant `now - timeout`.
    pub cutoff: &'a str,
    /// Private metadata is reduced; local text returns through the chat session's Gate.
    pub private: bool,
}

/// Ensure every unprocessed document has a `document_fields` row, then claim
/// up to `limit` pending documents for the bridge.
///
/// XML is parsed in Rust and lands `done`; every other format lands `pending`.
/// A claim older than the timeout is re-queued, or `failed` after the attempt
/// cap.
pub fn sweep_and_claim(
    store: &Store,
    home: &Path,
    window: ExtractWindow<'_>,
    limit: usize,
) -> Result<Vec<PendingDocument>, QueueError> {
    sweep_unprocessed(store, home, window)?;
    store.expire_document_claims(window.cutoff)?;
    let mut claimed = store.claim_document_fields(window.now, limit)?;
    let remaining = limit.saturating_sub(claimed.len());
    claimed.extend(store.claim_document_text_backfills(window.now, window.cutoff, remaining)?);
    Ok(claimed
        .into_iter()
        .map(|doc| PendingDocument {
            hash: doc.content_hash,
            mime: doc.mime_type,
            size: doc.size_bytes,
        })
        .collect())
}

/// Give every document without a `document_fields` row its first row: XML is
/// parsed now, everything else becomes `pending` for the bridge. A document
/// whose hash is malformed or whose blob is unreadable is recorded `failed`
/// and `to_check`, so it leaves the unprocessed set and cannot starve the
/// queue behind the sweep limit.
pub fn sweep_unprocessed(
    store: &Store,
    home: &Path,
    window: ExtractWindow<'_>,
) -> Result<usize, QueueError> {
    relink_unlinked(store, window.now)?;
    let documents = store.unprocessed_documents(SWEEP_LIMIT)?;
    if documents.is_empty() {
        return Ok(0);
    }
    let parties = party_refs(store)?;
    let mut processed = 0;
    for document in documents {
        if !extract::is_lowercase_sha256(&document.content_hash) {
            insert_failed(store, document.document_id, window.now)?;
            processed += 1;
            continue;
        }
        let Ok(bytes) = crate::evidence::read_blob(home, &document.content_hash) else {
            insert_failed(store, document.document_id, window.now)?;
            processed += 1;
            continue;
        };
        if extract::is_xml(&bytes) {
            match extract::extract_xml(&bytes) {
                Ok(extracted) => {
                    let source_text = std::str::from_utf8(&bytes).unwrap_or_default();
                    insert_extracted(
                        store,
                        document.document_id,
                        &extracted,
                        &parties,
                        capped_document_text(source_text),
                        window,
                    )?;
                    processed += 1;
                    continue;
                }
                Err(_) => {
                    // XML, but not a supported e-invoice: never send it to the
                    // bridge, which only understands PDFs and images.
                    insert_failed(store, document.document_id, window.now)?;
                    processed += 1;
                    continue;
                }
            }
        }
        store.insert_document_fields(&pending_row(document.document_id, window.now))?;
        processed += 1;
    }
    Ok(processed)
}

/// How many unlinked documents one sweep re-matches.
const RELINK_LIMIT: usize = 500;
/// The `party_match` reason of the owner's unlink, which a re-match never undoes.
const OWNER_UNLINKED: &str = "unlinked by the owner";

/// Re-match the read, unlinked documents against the live
/// clients, so a receipt read before its client existed is linked once the
/// client is created. Same exact rule as extraction ([`extract::party_match`]):
/// one matching client links, several or none link nothing, and the owner's
/// unlink stands. Private mode keeps no issuer, so it relinks nothing. Returns
/// how many documents were linked.
fn relink_unlinked(store: &Store, now: &str) -> Result<usize, QueueError> {
    let documents = store.unlinked_read_documents(RELINK_LIMIT)?;
    if documents.is_empty() {
        return Ok(0);
    }
    let parties = party_refs(store)?;
    let mut linked = 0;
    for document in documents {
        let mut checks: Vec<Check> =
            serde_json::from_str(&document.checks_json).unwrap_or_default();
        let owner_unlinked =
            |check: &Check| check.name == "party_match" && check.reason == OWNER_UNLINKED;
        if checks.iter().any(owner_unlinked) {
            continue;
        }
        let fields = Fields {
            issuer: document.issuer,
            recipient: document.recipient,
            ..Fields::default()
        };
        let matched = extract::party_match(&fields, &parties);
        let Some(party_id) = matched.party_id else {
            continue;
        };
        checks.retain(|check| check.name != "party_match");
        checks.push(matched.check);
        let json = serde_json::to_string(&checks).unwrap_or_else(|_| "[]".to_string());
        let read = &document.checks_json;
        if store.link_if_unchanged(document.document_id, party_id, read, &json, now)? {
            linked += 1;
        }
    }
    Ok(linked)
}

/// Build the `pending` row a bridge document starts with.
fn pending_row(document_id: i64, now: &str) -> NewDocumentFields<'_> {
    NewDocumentFields {
        document_id,
        kind: "other",
        extractor: "none",
        issuer: None,
        recipient: None,
        issued_on: None,
        currency: None,
        total_minor: None,
        vat_minor: None,
        number: None,
        fields_json: "{\"kind\":\"other\",\"extractor\":\"none\"}",
        extracted_text: "",
        checks_json: "[]",
        party_id: None,
        tags: "[]",
        status: "to_check",
        updated_at: now,
        extract_state: "pending",
        claimed_at: None,
        attempts: 0,
    }
}

/// Record a document the chain cannot extract as failed and `to_check`: XML
/// that is not a supported e-invoice, a malformed hash, or a missing blob.
/// It is never claimed by the bridge.
fn insert_failed(store: &Store, document_id: i64, now: &str) -> Result<(), QueueError> {
    store.insert_document_fields(&NewDocumentFields {
        document_id,
        kind: "other",
        extractor: "none",
        issuer: None,
        recipient: None,
        issued_on: None,
        currency: None,
        total_minor: None,
        vat_minor: None,
        number: None,
        fields_json: "{}",
        extracted_text: "",
        checks_json: "[]",
        party_id: None,
        tags: "[]",
        status: "to_check",
        updated_at: now,
        extract_state: "failed",
        claimed_at: None,
        attempts: 0,
    })?;
    Ok(())
}

/// The CRM parties as the matcher sees them. `Store::parties` is the party
/// list that `aux-crm::Crm::list` exposes.
fn party_refs(store: &Store) -> Result<Vec<PartyRef>, StoreError> {
    let parties = store.parties()?;
    Ok(parties
        .into_iter()
        .map(|party| {
            let mut names = vec![party.display_name];
            names.extend(party.name_variants);
            PartyRef {
                id: party.id,
                names,
                emails: party.emails,
            }
        })
        .collect())
}

/// Append the store-backed `duplicate` and `party_match` checks and write the
/// row as `done`.
fn insert_extracted(
    store: &Store,
    document_id: i64,
    extracted: &Extracted,
    parties: &[PartyRef],
    extracted_text: &str,
    window: ExtractWindow<'_>,
) -> Result<Vec<Check>, QueueError> {
    let (checks, party_id) = with_store_checks(store, document_id, extracted, parties)?;
    let fields = if window.private {
        extracted.fields.metadata_only()
    } else {
        extracted.fields.clone()
    };
    let fields_json = serde_json::to_string(&fields).unwrap_or_else(|_| "{}".to_string());
    let checks_json = serde_json::to_string(&checks).unwrap_or_else(|_| "[]".to_string());
    store.insert_document_fields(&NewDocumentFields {
        document_id,
        kind: fields.kind.stored(),
        extractor: fields.extractor.as_str(),
        issuer: fields.issuer.as_deref(),
        recipient: fields.recipient.as_deref(),
        issued_on: fields.issued_on.as_deref(),
        currency: fields.currency.as_deref(),
        total_minor: fields.total_minor,
        vat_minor: fields.vat_minor,
        number: fields.number.as_deref(),
        fields_json: &fields_json,
        extracted_text,
        checks_json: &checks_json,
        party_id,
        tags: "[]",
        status: "to_check",
        updated_at: window.now,
        extract_state: "done",
        claimed_at: None,
        attempts: 0,
    })?;
    Ok(checks)
}

fn capped_document_text(text: &str) -> &str {
    let mut end = text.len().min(aux_store::DOCUMENT_TEXT_MAX_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Add `duplicate` and `party_match` to the pure checks.
fn with_store_checks(
    store: &Store,
    document_id: i64,
    extracted: &Extracted,
    parties: &[PartyRef],
) -> Result<(Vec<Check>, Option<i64>), QueueError> {
    let mut checks = extracted.checks.clone();
    let duplicate = match (&extracted.fields.issuer, &extracted.fields.number) {
        (Some(issuer), Some(number)) => {
            store.duplicate_document_number(document_id, issuer, number)?
        }
        _ => None,
    };
    checks.push(match duplicate {
        Some(hash) => Check {
            name: "duplicate".to_string(),
            state: CheckState::Fail,
            reason: format!(
                "same issuer and number as {}",
                hash.get(..8).unwrap_or(&hash)
            ),
        },
        None => Check {
            name: "duplicate".to_string(),
            state: CheckState::Pass,
            reason: "no other document has this issuer and number".to_string(),
        },
    });
    let matched = extract::party_match(&extracted.fields, parties);
    let party_id = matched.party_id;
    checks.push(matched.check);
    Ok((checks, party_id))
}

/// The bytes of a claimed document, only while the claim is fresh.
pub fn claimed_blob(
    store: &Store,
    home: &Path,
    content_hash: &str,
    cutoff: &str,
) -> Result<Option<ClaimedBlob>, QueueError> {
    if !extract::is_lowercase_sha256(content_hash) {
        return Ok(None);
    }
    let document = store
        .claimed_document(content_hash, cutoff)?
        .or(store.claimed_document_text_backfill(content_hash, cutoff)?);
    let Some(document) = document else {
        return Ok(None);
    };
    let bytes =
        crate::evidence::read_blob(home, &document.content_hash).map_err(|_| QueueError::Blob)?;
    Ok(Some(ClaimedBlob {
        bytes,
        mime: document.mime_type,
    }))
}

/// Parse the bridge's text deterministically and finish the claimed document.
///
/// `extractor` is `pdf_text`, `ocr` or `none`; text over 1 MiB is refused
/// before anything is parsed. No model is ever called. In private mode the
pub fn store_text_extraction(
    store: &Store,
    content_hash: &str,
    extractor: Extractor,
    text: &str,
    pages: Option<u32>,
    window: ExtractWindow<'_>,
) -> Result<StoredExtraction, QueueError> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(QueueError::TextTooLarge);
    }
    if let Some(document) = store.claimed_document_text_backfill(content_hash, window.cutoff)? {
        let text = if extractor == Extractor::None {
            ""
        } else {
            capped_document_text(text)
        };
        if !store.complete_document_text_backfill(document.document_id, text, window.cutoff)? {
            return Err(QueueError::NotClaimed);
        }
        return Ok(StoredExtraction {
            document_id: document.document_id,
            checks: Vec::new(),
        });
    }
    let Some(document) = store.claimed_document(content_hash, window.cutoff)? else {
        return Err(QueueError::NotClaimed);
    };
    let extracted = if extractor == Extractor::None {
        empty_extraction(extractor)
    } else {
        extract::extract_text(text, pages, extractor)
    };
    let parties = party_refs(store)?;
    let (checks, party_id) = with_store_checks(store, document.document_id, &extracted, &parties)?;
    let fields = if window.private {
        extracted.fields.metadata_only()
    } else {
        extracted.fields.clone()
    };
    let fields_json = serde_json::to_string(&fields).unwrap_or_else(|_| "{}".to_string());
    let checks_json = serde_json::to_string(&checks).unwrap_or_else(|_| "[]".to_string());
    let completed = store.complete_document_fields(
        document.document_id,
        &DocumentExtraction {
            kind: fields.kind.stored(),
            extractor: fields.extractor.as_str(),
            issuer: fields.issuer.as_deref(),
            recipient: fields.recipient.as_deref(),
            issued_on: fields.issued_on.as_deref(),
            currency: fields.currency.as_deref(),
            total_minor: fields.total_minor,
            vat_minor: fields.vat_minor,
            number: fields.number.as_deref(),
            fields_json: &fields_json,
            checks_json: &checks_json,
            party_id,
            status: "to_check",
            updated_at: window.now,
            extracted_text: if extractor == Extractor::None {
                ""
            } else {
                text
            },
        },
    )?;
    if !completed {
        return Err(QueueError::NotClaimed);
    }
    Ok(StoredExtraction {
        document_id: document.document_id,
        checks,
    })
}

/// The empty field set the `none` extractor stores.
fn empty_extraction(extractor: Extractor) -> Extracted {
    let fields = Fields {
        extractor,
        ..Fields::default()
    };
    let checks = vec![
        Check {
            name: "totals".to_string(),
            state: CheckState::Unknown,
            reason: "no text was extracted".to_string(),
        },
        Check {
            name: "vat".to_string(),
            state: CheckState::Unknown,
            reason: "no text was extracted".to_string(),
        },
    ];
    Extracted { fields, checks }
}

/// Why the owner's link or unlink was refused. Nothing was written.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The store refused a read or write.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The prefix is not 8 to 64 lowercase hex characters.
    #[error("a document hash prefix is 8 to 64 hex characters")]
    BadPrefix,
    /// No document starts with the prefix.
    #[error("no document has that hash")]
    UnknownDocument,
    /// Several documents start with the prefix.
    #[error("several documents start with that hash: give more characters")]
    AmbiguousPrefix,
    /// The document is still waiting for the bridge.
    #[error("the document is still waiting to be read")]
    NotRead,
    /// The party is unknown or archived.
    #[error("no live client has that id")]
    UnknownParty,
}

/// Link the document whose hash starts with `prefix` to `party_id`, or unlink
/// it (`None`). The `party_match` check records the owner's choice. Returns
/// the full hash.
pub fn link_document(
    store: &Store,
    prefix: &str,
    party_id: Option<i64>,
    now: &str,
) -> Result<String, LinkError> {
    let hex = prefix
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !(8..=64).contains(&prefix.len()) || !hex {
        return Err(LinkError::BadPrefix);
    }
    let mut found = store.documents_by_hash_prefix(prefix)?;
    if found.len() > 1 {
        return Err(LinkError::AmbiguousPrefix);
    }
    let document = found.pop().ok_or(LinkError::UnknownDocument)?;
    if !matches!(document.extract_state.as_deref(), Some("done" | "failed")) {
        return Err(LinkError::NotRead);
    }
    if let Some(id) = party_id {
        if !store.party(id)?.is_some_and(|party| !party.archived) {
            return Err(LinkError::UnknownParty);
        }
    }
    let mut checks: Vec<Check> = document
        .checks_json
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default();
    checks.retain(|check| check.name != "party_match");
    checks.push(match party_id {
        Some(id) => Check {
            name: "party_match".to_string(),
            state: CheckState::Pass,
            reason: format!("linked to CRM party {id} by the owner"),
        },
        None => Check {
            name: "party_match".to_string(),
            state: CheckState::Unknown,
            reason: OWNER_UNLINKED.to_string(),
        },
    });
    let checks_json = serde_json::to_string(&checks).unwrap_or_else(|_| "[]".to_string());
    if !store.set_document_party(document.document_id, party_id, &checks_json, now)? {
        return Err(LinkError::NotRead);
    }
    Ok(document.content_hash)
}
