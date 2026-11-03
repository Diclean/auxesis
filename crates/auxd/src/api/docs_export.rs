//! `POST /v1/docs/export?from=&to=&client=&out=` (M5-2): the owner's receipts
//! of a period to a CSV plus the originals, in a folder he names. Behind the
//! bearer-token router. No model is called; no log line carries a path, a file
//! name or a value.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use super::error;
use super::ApiState;
use aux_docs::export::{export_receipts, ExportError, ExportOutcome, ExportRequest};

/// The export route, merged into the authenticated router.
pub fn routes() -> Router<Arc<ApiState>> {
    Router::new().route("/v1/docs/export", post(export))
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    from: String,
    to: String,
    client: Option<i64>,
    out: std::path::PathBuf,
}

async fn export(State(state): State<Arc<ApiState>>, Query(query): Query<ExportQuery>) -> Response {
    let (home, db_path) = (state.home.clone(), state.db_path.clone());
    let result = tokio::task::spawn_blocking(move || {
        let store = aux_store::Store::open(&db_path)?;
        let (from, to, client, out) = (&query.from, &query.to, query.client, &query.out);
        export_receipts(
            &store,
            &home,
            &ExportRequest {
                from,
                to,
                client,
                out,
            },
        )
    })
    .await
    .unwrap_or_else(|_| Err(ExportError::Failed("the export task stopped".into())));
    let (status, code) = match &result {
        Ok(ExportOutcome::Empty { message }) => {
            return Json(serde_json::json!({ "status": "empty", "message": message }))
                .into_response()
        }
        Ok(ExportOutcome::Written {
            folder,
            rows,
            missing,
        }) => {
            let folder = folder.to_string_lossy();
            let reply = serde_json::json!({ "status": "written", "folder": folder, "rows": rows, "missing": missing });
            return Json(reply).into_response();
        }
        Err(ExportError::Refused(_)) => (StatusCode::BAD_REQUEST, "docs_export_refused"),
        Err(ExportError::Exists(_)) => (StatusCode::CONFLICT, "docs_export_exists"),
        Err(ExportError::Failed(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "docs_export_failed"),
    };
    tracing::warn!(code, "the receipts export did not run");
    let message = result.err().map(|err| err.to_string()).unwrap_or_default();
    error::error_response(status, code, message, None)
}
