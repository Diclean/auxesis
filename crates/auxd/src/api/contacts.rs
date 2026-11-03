//! Import clients from a contacts file (WO-CRMIO-1).
//!
//! | Method | Path | Answer |
//! |---|---|---|
//! | POST | `/v1/contacts/import` | preview (`dry_run`) or import of a vCard / CSV file on this Mac |
//!
//! The daemon reads the file where it is and never copies it; the parse and import
//! core is `aux_runtime::contacts_import`, the one `aux contacts import` runs. The
//! answer, the logs and the audit event carry counts and CSV column names only: no
//! name, address or number, and not the path. Behind the shared bearer-token middleware.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::error;
use super::ApiState;
use aux_runtime::contacts_import::{import_file, preview_file, Summary};

/// The contacts routes, merged into the authenticated router.
pub fn routes() -> Router<Arc<ApiState>> {
    Router::new().route("/v1/contacts/import", post(import))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportRequest {
    /// Absolute path of the file on this Mac.
    path: PathBuf,
    /// Required, so an import is never one missing field away from a preview.
    dry_run: bool,
    /// `client` or `partner`, put on every party the file creates or matches.
    #[serde(default)]
    tag: Option<String>,
    /// ISO 3166-1 country of national-format numbers; without it they are skipped.
    #[serde(default)]
    country: Option<String>,
}

/// One CSV column the import read, and as what.
#[derive(Debug, Serialize)]
struct MappedColumn {
    column: String,
    #[serde(rename = "as")]
    role: &'static str,
}

/// Rows that did not import, by reason. Counts only.
#[derive(Debug, Serialize)]
struct Skipped {
    no_name_or_contact: usize,
    repeated_in_file: usize,
    phone_needs_country: usize,
    phone_invalid: usize,
    refused_charset: usize,
    undecodable_fields: usize,
    over_size_cap: usize,
}

#[derive(Debug, Serialize)]
struct ImportAnswer {
    dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mapped_columns: Option<Vec<MappedColumn>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unmapped_columns: Option<Vec<String>>,
    /// Contacts the file yields, after merging its repeats.
    contacts: usize,
    emails: usize,
    phones: usize,
    parties_created: usize,
    parties_updated: usize,
    parties_refused: usize,
    /// Card values that differ from the one the card holds: the old one was kept.
    conflicts: usize,
    skipped: Skipped,
}

impl ImportAnswer {
    fn new(dry_run: bool, summary: &Summary) -> Self {
        Self {
            dry_run,
            format: None,
            mapped_columns: None,
            unmapped_columns: None,
            contacts: summary.stored,
            emails: summary.emails,
            phones: summary.phones,
            parties_created: summary.parties_created,
            parties_updated: summary.parties_updated,
            parties_refused: summary.parties_refused,
            conflicts: summary.conflicts,
            skipped: Skipped {
                no_name_or_contact: summary.skipped,
                repeated_in_file: summary.merged,
                phone_needs_country: summary.no_country,
                phone_invalid: summary.invalid,
                refused_charset: summary.refused_charset,
                undecodable_fields: summary.encoded_fields,
                over_size_cap: summary.capped,
            },
        }
    }
}

fn invalid(message: impl Into<String>) -> Response {
    error::error_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "contacts_import_invalid",
        message,
        None,
    )
}

/// `POST /v1/contacts/import`.
async fn import(
    State(state): State<Arc<ApiState>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Ok(body) = body else {
        return invalid("the request body could not be read");
    };
    let Ok(request) = serde_json::from_slice::<ImportRequest>(&body) else {
        return invalid(
            "expected {\"path\": \"<absolute path>\", \"dry_run\": bool, \"tag\": \"client\"|\"partner\"|null}",
        );
    };
    if !matches!(request.tag.as_deref(), None | Some("client" | "partner")) {
        return invalid("tag must be \"client\", \"partner\" or null");
    }
    if !request.path.is_absolute() {
        return invalid("path must be absolute");
    }
    // The file itself is opened once by the importer, without following a final
    // link and without blocking on a pipe; every check runs on that handle.
    let db_path = state.db_path.clone();
    let dry_run = request.dry_run;
    let result = tokio::task::spawn_blocking(move || {
        let store = aux_store::Store::open(&db_path).map_err(|_| Failure::Store)?;
        let country = request.country.as_deref();
        if dry_run {
            let preview = preview_file(&store, &request.path, country).map_err(Failure::Refused)?;
            let mut answer = ImportAnswer::new(true, &preview.summary);
            answer.parties_created = preview.would_create;
            answer.parties_updated = preview.would_update;
            answer.parties_refused = preview.would_refuse;
            answer.conflicts = preview.conflicts;
            answer.format = Some(preview.format);
            if let Some(csv) = preview.csv {
                answer.mapped_columns = Some(
                    csv.mapped
                        .into_iter()
                        .map(|(column, role)| MappedColumn { column, role })
                        .collect(),
                );
                answer.unmapped_columns = Some(csv.unmapped);
            }
            return Ok(answer);
        }
        let summary = import_file(&store, &request.path, country, request.tag.as_deref())
            .map_err(Failure::Refused)?;
        let audit = format!(
            "{{\"contacts\":{},\"created\":{},\"updated\":{}}}",
            summary.stored, summary.parties_created, summary.parties_updated
        );
        store
            .log_event("contacts.imported", &audit)
            .map_err(|_| Failure::Store)?;
        Ok(ImportAnswer::new(false, &summary))
    })
    .await;
    match result {
        Ok(Ok(answer)) => Json(answer).into_response(),
        // The refusal text names no one: counts, a country code, an error kind.
        Ok(Err(Failure::Refused(message))) => invalid(message),
        Ok(Err(Failure::Store)) | Err(_) => {
            tracing::error!("a contacts import failed in the store");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "contacts_import_failed",
                "the contacts could not be imported",
                None,
            )
        }
    }
}

enum Failure {
    Refused(String),
    Store,
}
