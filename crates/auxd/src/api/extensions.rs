//! Local OAuth 2.0 (PKCE) for extensions.
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
use std::path::Path as FsPath;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use aux_runtime::extensions::install::{load_installed, InstalledExtension};
use aux_runtime::extensions::mount::{require_approval, MountError};
use aux_runtime::extensions::oauth::{loopback_endpoints_allowed, oauth_endpoints, FileTokenStore};
use aux_runtime::extensions::{TokenStore, OAUTH_TIMEOUT};

use super::error;
use super::ApiState;

/// The one active flow slot per extension.
fn active_flows() -> &'static Mutex<BTreeSet<String>> {
    static SLOT: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// Per-extension disconnect count. A flow saves its token only if no
/// disconnect happened since it started; the check and the save run under
/// this lock, as does the disconnect, so a revoke is never undone.
fn generations() -> &'static Mutex<std::collections::BTreeMap<String, u64>> {
    static SLOT: OnceLock<Mutex<std::collections::BTreeMap<String, u64>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
}

fn generation(map: &std::collections::BTreeMap<String, u64>, id: &str) -> u64 {
    map.get(id).copied().unwrap_or(0)
}

/// The install the flow started from is still the approved one: same
/// version and same entry (endpoints included), and its pin still holds.
fn same_approved_install(home: &FsPath, id: &str, started: &InstalledExtension) -> bool {
    let Ok(now) = approved_install(home, id) else {
        return false;
    };
    now.version == started.version && now.entry == started.entry
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

/// The one 404 body the start and disconnect routes answer with.
fn extension_not_found() -> Response {
    error::error_response(
        StatusCode::NOT_FOUND,
        "extension_not_found",
        "unknown extension",
        None,
    )
}

// Check before resolving OAuth secrets or starting a flow (the route that goes
// out to the network). A missing pin is a refusal too. Status and disconnect
// stay open for any valid name: they are local, and the owner must always be
// able to revoke a token.
fn approved_install(home: &FsPath, id: &str) -> Result<InstalledExtension, Box<Response>> {
    let installed = aux_runtime::extensions::valid_name(id)
        .then(|| load_installed(home, id))
        .flatten()
        .ok_or_else(|| Box::new(extension_not_found()))?;
    let state = require_approval(home, &installed).map_err(|err| {
        // The exact re-trust command, changed field names included; a missing
        // or unreadable pin has none and keeps the generic hint.
        let message = match err {
            MountError::ApprovalRequired { fix, .. } => {
                format!("the installed extension must be approved before using OAuth: run `{fix}`")
            }
            _ => "the installed extension must be approved before using OAuth".to_owned(),
        };
        Box::new(error::error_response(
            StatusCode::CONFLICT,
            "approval_required",
            message,
            Some("reinstall or run aux ext verify --accept for this extension"),
        ))
    })?;
    // EXT-ANCHOR-11: a frozen row (tool drift, or a pin saved before its start)
    // is no yes either: nothing goes out until the owner re-accepts it.
    if state.frozen {
        let fix = aux_runtime::extensions::mount::accept_command(&state, &installed);
        return Err(Box::new(error::error_response(
            StatusCode::CONFLICT,
            "approval_required",
            format!(
                "the extension is frozen and must be re-approved before using OAuth: run `{fix}`"
            ),
            Some("run aux ext verify --accept for this extension"),
        )));
    }
    Ok(installed)
}

/// `POST /v1/extensions/{id}/oauth/start`.
pub async fn start(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let installed = match approved_install(&state.home, &id) {
        Ok(installed) => installed,
        Err(response) => return *response,
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
    let started_gen = {
        let map = generations().lock().unwrap_or_else(|p| p.into_inner());
        generation(&map, &id)
    };
    tokio::spawn(async move {
        let store = FileTokenStore::new(&home);
        // An upgrade or a disconnect while the browser is open ends the
        // flow before the code exchange and before any save.
        let unchanged = || {
            let map = generations().lock().unwrap_or_else(|p| p.into_inner());
            generation(&map, &name) == started_gen
                && same_approved_install(&home, &name, &installed)
        };
        match flow.complete_if(OAUTH_TIMEOUT, unchanged).await {
            Ok(tokens) => {
                let map = generations().lock().unwrap_or_else(|p| p.into_inner());
                let still_ok = generation(&map, &name) == started_gen
                    && same_approved_install(&home, &name, &installed);
                if !still_ok {
                    tracing::warn!(extension = %name, "extension OAuth dropped: changed during the flow");
                } else if store.save(&name, &tokens).is_err() {
                    tracing::warn!(extension = %name, "extension OAuth token could not be stored");
                } else if !same_approved_install(&home, &name, &installed) {
                    // `aux ext install` runs in another process and does not take
                    // this lock, so an install can land
                    // between the check and the save. Check again after the
                    // save and take the token back: a kept token was saved
                    // while the approved install was still in place.
                    let _ = store.clear(&name);
                    tracing::warn!(extension = %name, "extension OAuth dropped: changed during the save");
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
    // No install can carry this name, so it must not grow the generation map
    // (keyed by the raw URL id). The 404 matches the start route. Any valid
    // name still revokes, installed or not.
    if !aux_runtime::extensions::valid_name(&id) {
        return extension_not_found();
    }
    let store = FileTokenStore::new(&state.home);
    let mut map = generations().lock().unwrap_or_else(|p| p.into_inner());
    let next = generation(&map, &id).wrapping_add(1);
    map.insert(id.clone(), next);
    let cleared = store.clear(&id);
    drop(map);
    if cleared.is_err() {
        return error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "oauth_disconnect_failed",
            "the stored authorization could not be removed",
            None,
        );
    }
    Json(OAuthStatus { connected: false }).into_response()
}
