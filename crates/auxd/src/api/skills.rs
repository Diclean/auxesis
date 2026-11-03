//! Read-only discovery API for owner-authored local instruction skills.
use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{error, ApiState};

/// `GET /v1/skills` — names, descriptions, byte sizes and validation status.
pub async fn list(State(state): State<Arc<ApiState>>) -> Response {
    match tokio::task::spawn_blocking(move || aux_engine::skills::list(&state.home)).await {
        Ok(skills) => Json(skills).into_response(),
        Err(_) => error::error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "skills_unavailable",
            "skills could not be listed",
            None,
        ),
    }
}
