//! Local OAuth 2.0 (PKCE) for extensions (E5).
//!
//! Three authenticated routes:
//!
//! * `POST /v1/extensions/{id}/oauth/start` binds the one-shot loopback
//!   listener, generates `state` and the PKCE verifier with the OS CSPRNG and
//!   answers the authorization URL for the app to open. The daemon then waits
//!   for the callback and stores the tokens; the app never sees them.
//! * `GET /v1/extensions/{id}/oauth/status` reports a boolean only.
//! * `DELETE /v1/extensions/{id}/oauth` forgets the stored tokens.
//!
//! The callback itself is the random loopback port, not a route here: a
//! browser redirect cannot carry the local bearer token.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use aux_runtime::extensions::install::load_installed;
use aux_runtime::extensions::oauth::{loopback_endpoints_allowed, oauth_endpoints, FileTokenStore};
use aux_runtime::extensions::{TokenStore, OAUTH_TIMEOUT};

use super::error;
use super::ApiState;

/// The one active flow slot per extension.
fn active_flows() -> &'static Mutex<BTreeSet<String>> {
    static SLOT: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(BTreeSet::new()))
}

fn release_flow(id: &str) {
    let mut flows = active_flows()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    flows.remove(id);
}

/// The one body the status and disconnect routes answer with.
#[derive(Debug, Serialize)]
struct OAuthStatus {
    /// Whether this Mac stores a live authorization for the extension.
    connected: bool,
}

/// `POST /v1/extensions/{id}/oauth/start`.
pub async fn start(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    if !aux_runtime::extensions::valid_name(&id) {
        return error::error_response(
            StatusCode::NOT_FOUND,
            "extension_not_found",
            "unknown extension",
            None,
        );
    }
    let Some(installed) = load_installed(&state.home, &id) else {
        return error::error_response(
            StatusCode::NOT_FOUND,
            "extension_not_found",
            "unknown extension",
            None,
        );
    };
    let Some(config) = installed.entry.oauth.as_ref() else {
        return error::error_response(
            StatusCode::CONFLICT,
            "oauth_not_configured",
            "this extension has no OAuth configuration",
            None,
        );
    };
    let endpoints = match oauth_endpoints(config, &id, &state.home, loopback_endpoints_allowed()) {
        Ok(endpoints) => endpoints,
        Err(err) => {
            tracing::warn!(extension = %id, reason = %err, "extension OAuth refused");
            return error::error_response(
                StatusCode::CONFLICT,
                "oauth_endpoint_refused",
                "the OAuth endpoints are not secure https URLs",
                None,
            );
        }
    };
    {
        let mut flows = active_flows()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !flows.insert(id.clone()) {
            return error::error_response(
                StatusCode::CONFLICT,
                "oauth_flow_running",
                "an OAuth flow is already running for this extension",
                None,
            );
        }
    }

    let flow = match endpoints.begin().await {
        Ok(flow) => flow,
        Err(err) => {
            release_flow(&id);
            tracing::warn!(extension = %id, reason = %err, "extension OAuth could not start");
            return error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "oauth_start_failed",
                "the local callback listener could not start",
                None,
            );
        }
    };
    let authorize_url = flow.authorize_url().to_string();
    let home = state.home.clone();
    let name = id.clone();
    tokio::spawn(async move {
        let store = FileTokenStore::new(&home);
        match flow.complete().await {
            Ok(tokens) => {
                if store.save(&name, &tokens).is_err() {
                    tracing::warn!(extension = %name, "extension OAuth token could not be stored");
                } else {
                    tracing::info!(extension = %name, "extension OAuth connected");
                }
            }
            Err(err) => tracing::warn!(extension = %name, reason = %err, "extension OAuth failed"),
        }
        release_flow(&name);
    });

    Json(serde_json::json!({
        "authorize_url": authorize_url,
        "expires_in": OAUTH_TIMEOUT.as_secs(),
    }))
    .into_response()
}

/// `GET /v1/extensions/{id}/oauth/status`.
pub async fn status(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let connected = FileTokenStore::new(&state.home)
        .load(&id)
        .map(|tokens| tokens.is_some())
        .unwrap_or(false);
    Json(OAuthStatus { connected }).into_response()
}

/// `DELETE /v1/extensions/{id}/oauth`.
pub async fn disconnect(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let store = FileTokenStore::new(&state.home);
    if store.clear(&id).is_err() {
        return error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "oauth_disconnect_failed",
            "the stored authorization could not be removed",
            None,
        );
    }
    Json(OAuthStatus { connected: false }).into_response()
}
