//! Documents extraction routes (path B25, `docs/phase1.md` §2).
//!
//! The Mac app is the bridge. It polls the queue, downloads the original
//! through the blob route, runs PDFKit (native text) and then Vision (OCR) on
//! the device, and posts the text back. These routes are behind the shared
//! bearer-token middleware, so nothing here is reachable without the local
//! token.
//!
//! Privacy: the pending route returns only `{hash, mime, size}`, never a name

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::error;
use super::ApiState;
use aux_docs::{Check, Extractor};

/// Default number of documents one queue poll claims.
const DEFAULT_LIMIT: usize = 32;
/// Hard cap on one queue poll.
const MAX_LIMIT: usize = 256;
/// Default and cap of one `GET /v1/docs`.
const LIST_DEFAULT: usize = 50;
const LIST_MAX: usize = 500;
/// The extraction body is the JSON envelope around a 1 MiB text.
const EXTRACTION_BODY_BYTES: usize = aux_docs::MAX_TEXT_BYTES + 64 * 1024;

/// The docs routes, merged into the authenticated router.
pub fn routes() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/v1/docs/extract/pending", get(pending))
        .route("/v1/docs/{hash}/blob", get(blob))
        .route("/v1/docs", get(list))
        .route("/v1/docs/{hash}", delete(erase))
        .route("/v1/docs/{hash}/party", post(link))
        .route(
            "/v1/docs/{hash}/extraction",
            post(extraction).layer(DefaultBodyLimit::max(EXTRACTION_BODY_BYTES)),
        )
}

#[derive(Debug, Deserialize)]
struct PendingQuery {
    #[serde(default)]
    limit: Option<usize>,
}

/// `GET /v1/docs/extract/pending?limit=N` — sweep the chain, then claim up to
/// `N` bridge documents. Returns `[{hash, mime, size}]`.
async fn pending(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<PendingQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let private = crate::privacy_wiring::private_now(&state.home);
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let now = chrono::Utc::now();
        let now_text = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let cutoff = aux_docs::claim_cutoff(now);
        let window = aux_docs::ExtractWindow {
            now: &now_text,
            cutoff: &cutoff,
            private,
        };
        let store = aux_store::Store::open(&db_path)?;
        aux_docs::sweep_and_claim(&store, &home, window, limit)
    })
    .await;
    match result {
        Ok(Ok(documents)) => Json(documents).into_response(),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the documents queue could not be swept");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_pending_failed",
                "the document queue could not be read",
                None,
            )
        }
        Err(err) => {
            tracing::error!(error = %err, "the documents queue task failed");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_pending_failed",
                "the document queue could not be read",
                None,
            )
        }
    }
}

/// `GET /v1/docs/{hash}/blob` — the original bytes, only while claimed.
async fn blob(State(state): State<Arc<ApiState>>, Path(hash): Path<String>) -> Response {
    if !aux_docs::is_lowercase_sha256(&hash) {
        return not_found();
    }
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let now = chrono::Utc::now();
        let cutoff = aux_docs::claim_cutoff(now);
        let store = aux_store::Store::open(&db_path)?;
        aux_docs::claimed_blob(&store, &home, &hash, &cutoff)
    })
    .await;
    match result {
        Ok(Ok(Some(blob))) => {
            let mime = HeaderValue::from_str(&blob.mime)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            ([(header::CONTENT_TYPE, mime)], blob.bytes).into_response()
        }
        Ok(Ok(None)) => not_found(),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the claimed document blob could not be served");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_blob_failed",
                "the document blob could not be read",
                None,
            )
        }
        Err(err) => {
            tracing::error!(error = %err, "the document blob task failed");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_blob_failed",
                "the document blob could not be read",
                None,
            )
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtractionRequest {
    extractor: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    pages: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ExtractionResponse {
    document_id: i64,
    checks: Vec<Check>,
}

/// `POST /v1/docs/{hash}/extraction` — the bridge's extracted text.
async fn extraction(
    State(state): State<Arc<ApiState>>,
    Path(hash): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => return too_large("the extraction body is too large"),
    };
    if !aux_docs::is_lowercase_sha256(&hash) {
        return not_found();
    }
    let request: ExtractionRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return bad_request("invalid extraction body"),
    };
    let Some(extractor) = Extractor::parse(&request.extractor) else {
        return bad_request("unknown extractor");
    };
    if extractor == Extractor::Xml {
        return bad_request("the bridge may not post xml");
    }
    if request.text.len() > aux_docs::MAX_TEXT_BYTES {
        return too_large("the text exceeds the 1 MiB limit");
    }
    let text = request.text;
    let pages = request.pages;
    let private = crate::privacy_wiring::private_now(&state.home);
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let now = chrono::Utc::now();
        let now_text = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let cutoff = aux_docs::claim_cutoff(now);
        let window = aux_docs::ExtractWindow {
            now: &now_text,
            cutoff: &cutoff,
            private,
        };
        let store = aux_store::Store::open(&db_path)?;
        aux_docs::store_text_extraction(&store, &hash, extractor, &text, pages, window)
    })
    .await;
    match result {
        Ok(Ok(stored)) => Json(ExtractionResponse {
            document_id: stored.document_id,
            checks: stored.checks,
        })
        .into_response(),
        Ok(Err(aux_docs::QueueError::TextTooLarge)) => {
            too_large("the text exceeds the 1 MiB limit")
        }
        Ok(Err(aux_docs::QueueError::NotClaimed)) => error::error_response(
            StatusCode::CONFLICT,
            "docs_not_claimed",
            "the document is not claimed",
            None,
        ),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the document extraction could not be stored");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_extraction_failed",
                "the extraction could not be stored",
                None,
            )
        }
        Err(err) => {
            tracing::error!(error = %err, "the document extraction task failed");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_extraction_failed",
                "the extraction could not be stored",
                None,
            )
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ListQuery {
    client: Option<i64>,
    unlinked: bool,
    limit: Option<usize>,
}

/// `GET /v1/docs?client=ID|unlinked=true&limit=N`: fields, client and check
/// states only, never a body, a file name or OCR text. Unread XML is parsed
/// first, so the list does not wait for the Mac bridge.
async fn list(State(state): State<Arc<ApiState>>, Query(query): Query<ListQuery>) -> Response {
    if query.client.is_some() && query.unlinked {
        return bad_request("choose a client or unlinked, not both");
    }
    let limit = query.limit.unwrap_or(LIST_DEFAULT).clamp(1, LIST_MAX);
    let private = crate::privacy_wiring::private_now(&state.home);
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let now = chrono::Utc::now();
        let now_text = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let cutoff = aux_docs::claim_cutoff(now);
        let window = aux_docs::ExtractWindow {
            now: &now_text,
            cutoff: &cutoff,
            private,
        };
        let store = aux_store::Store::open(&db_path)?;
        aux_docs::sweep_unprocessed(&store, &home, window)?;
        Ok::<_, aux_docs::QueueError>(store.document_list(query.client, query.unlinked, limit)?)
    })
    .await;
    match result {
        Ok(Ok(rows)) => Json(rows.iter().map(list_row).collect::<Vec<_>>()).into_response(),
        Ok(Err(err)) => list_failed(&err),
        Err(err) => list_failed(&err),
    }
}

fn list_failed(err: &dyn std::fmt::Display) -> Response {
    tracing::warn!(error = %err, "the documents list could not be read");
    error::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "docs_list_failed",
        "the documents could not be read",
        None,
    )
}

/// One list row as JSON: whitelisted fields only.
fn list_row(row: &aux_store::DocumentListRow) -> serde_json::Value {
    let checks: Vec<Check> = row
        .checks_json
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default();
    let status = match row.extract_state.as_deref() {
        Some("done") => "read",
        Some("failed") => "could not be read",
        _ => "waiting for reading",
    };
    serde_json::json!({
        "hash": row.content_hash.get(..12).unwrap_or(&row.content_hash),
        "kind": row.kind,
        "issued_on": row.issued_on,
        "number": row.number,
        "total": money(row.total_minor, row.currency.as_deref()),
        "vat": money(row.vat_minor, row.currency.as_deref()),
        "client": row.party_id.map(|id| serde_json::json!({
            "id": id,
            "name": row.party_name,
            "archived": row.party_archived,
        })),
        "checks": checks
            .iter()
            .map(|check| serde_json::json!({"name": check.name, "state": check.state}))
            .collect::<Vec<_>>(),
        "status": status,
    })
}

/// Minor units as a two-decimal amount with its currency (`-12.05 EUR`).
fn money(minor: Option<i64>, currency: Option<&str>) -> Option<String> {
    let (sign, abs) = (if minor? < 0 { "-" } else { "" }, minor?.unsigned_abs());
    let amount = format!(
        "{sign}{}.{:02} {}",
        abs / 100,
        abs % 100,
        currency.unwrap_or("")
    );
    Some(amount.trim_end().to_string())
}

#[derive(Debug, Deserialize)]
struct LinkQuery {
    /// A party id, or `none` to unlink.
    party: String,
}

/// `POST /v1/docs/{hash-prefix}/party?party=ID|none` — the owner links a
/// document to a live client, or unlinks it. A refusal writes nothing.
async fn link(
    State(state): State<Arc<ApiState>>,
    Path(prefix): Path<String>,
    Query(query): Query<LinkQuery>,
) -> Response {
    use aux_docs::LinkError;
    let party = match query.party.as_str() {
        "none" => None,
        raw => match raw.parse::<i64>() {
            Ok(id) => Some(id),
            Err(_) => return bad_request("party is a client id or none"),
        },
    };
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let store = aux_store::Store::open(&db_path).map_err(LinkError::Store)?;
        aux_docs::link_document(&store, &prefix, party, &now)
    })
    .await;
    let refused = |status, err: LinkError| {
        error::error_response(status, "docs_link_refused", err.to_string(), None)
    };
    match result {
        Ok(Ok(hash)) => Json(serde_json::json!({"hash": hash, "party_id": party})).into_response(),
        Ok(Err(err @ LinkError::BadPrefix)) => refused(StatusCode::BAD_REQUEST, err),
        Ok(Err(err @ (LinkError::UnknownDocument | LinkError::UnknownParty))) => {
            refused(StatusCode::NOT_FOUND, err)
        }
        Ok(Err(err @ (LinkError::AmbiguousPrefix | LinkError::NotRead))) => {
            refused(StatusCode::CONFLICT, err)
        }
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the document link could not be stored");
            link_failed()
        }
        Err(err) => {
            tracing::error!(error = %err, "the document link task failed");
            link_failed()
        }
    }
}

/// `DELETE /v1/docs/{hash-prefix}` — explicit owner erase. The registry rows
/// are deleted transactionally before the sealed source blob is removed.
async fn erase(State(state): State<Arc<ApiState>>, Path(prefix): Path<String>) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let store = aux_store::Store::open(&db_path).map_err(aux_docs::EraseError::Store)?;
        aux_docs::erase_document(&store, &home, &prefix)
    })
    .await;
    match result {
        Ok(Ok(_)) => Json(serde_json::json!({"erased": true})).into_response(),
        Ok(Err(err @ aux_docs::EraseError::BadPrefix)) => error::error_response(
            StatusCode::BAD_REQUEST,
            "docs_erase_refused",
            err.to_string(),
            None,
        ),
        Ok(Err(err @ aux_docs::EraseError::UnknownDocument)) => error::error_response(
            StatusCode::NOT_FOUND,
            "docs_erase_refused",
            err.to_string(),
            None,
        ),
        Ok(Err(err @ aux_docs::EraseError::AmbiguousPrefix)) => error::error_response(
            StatusCode::CONFLICT,
            "docs_erase_refused",
            err.to_string(),
            None,
        ),
        Ok(Err(err)) => {
            tracing::warn!(error = %err, "the owner document erase did not finish");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_erase_failed",
                "the document erase could not be completed",
                None,
            )
        }
        Err(err) => {
            tracing::error!(error = %err, "the document erase task failed");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "docs_erase_failed",
                "the document erase could not be completed",
                None,
            )
        }
    }
}

fn link_failed() -> Response {
    error::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "docs_link_failed",
        "the link could not be stored",
        None,
    )
}

fn not_found() -> Response {
    error::error_response(
        StatusCode::NOT_FOUND,
        "docs_not_found",
        "no claimed document has that hash",
        None,
    )
}

fn bad_request(message: &'static str) -> Response {
    error::error_response(StatusCode::BAD_REQUEST, "docs_bad_request", message, None)
}

fn too_large(message: &'static str) -> Response {
    error::error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "docs_too_large",
        message,
        None,
    )
}
