//! The owner's Google connection routes (G4).
//!
//! * `POST /v1/google/connect` starts the installed-app consent flow **only**
//!   when the app asks for it, on an owner click. The browser opens from the
//!   daemon exactly here and nowhere else; startup, the scheduler and a tool
//!   call can never reach an opener.
//! * `POST /v1/google/disconnect` revokes the stored authorization and deletes
//!   it.
//!
//! Answers carry booleans only: never a token, never an email, never the
//! client id or secret. Connection and update state come from `GET /v1/health`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use aux_google::browser::SystemBrowser;
use aux_google::{MacConnection, CONNECT_SCOPES};
use kernel_core::{Lang, Message};

use super::error;
use super::ApiState;

/// At most one owner-started consent flow at a time.
///
/// A second click while the first flow waits for the browser must not open a
/// second tab or bind a second callback listener.
#[derive(Default)]
pub(crate) struct FlowGuard(AtomicBool);

impl FlowGuard {
    /// Claim the single flow slot. `false` when one is already in flight.
    fn begin(&self) -> bool {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn end(&self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The one body these routes answer with.
#[derive(Debug, Serialize)]
struct GoogleJson {
    /// Whether this Mac holds a Google authorization right now.
    connected: bool,
    /// True when a grant exists but needs the current Google permissions.
    reconnect_needed: bool,
    /// True when this call started a consent flow that is still in flight.
    started: bool,
}

/// `POST /v1/google/connect`.
pub async fn connect(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    let home = state.home.clone();
    let connection = MacConnection::at(&home);
    let reconnect_needed = connection.connected() && connection.needs_reconsent();
    if connection.connected() && !reconnect_needed {
        return Json(GoogleJson {
            connected: true,
            reconnect_needed: false,
            started: false,
        })
        .into_response();
    }
    start_consent_flow(state, home, reconnect_needed, lang).await
}

/// `POST /v1/google/reconnect`: owner-clicked renewal for a stored old grant.
pub async fn reconnect(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    let home = state.home.clone();
    let connection = MacConnection::at(&home);
    if !connection.connected() {
        return error::error_response(
            StatusCode::CONFLICT,
            "google_reconnect_not_needed",
            "aucune autorisation Google à mettre à jour",
            None,
        );
    }
    if !connection.needs_reconsent() {
        return Json(GoogleJson {
            connected: true,
            reconnect_needed: false,
            started: false,
        })
        .into_response();
    }
    start_consent_flow(state, home, true, lang).await
}

async fn start_consent_flow(
    state: Arc<ApiState>,
    home: std::path::PathBuf,
    reconnect_needed: bool,
    lang: Lang,
) -> Response {
    if !state.google_flow.begin() {
        return error::error_response(
            StatusCode::CONFLICT,
            "google_flow_running",
            kernel_core::i18n::text(Message::GoogleFlowRunning, lang),
            Some(kernel_core::i18n::text(Message::GoogleFlowHint, lang)),
        );
    }
    let flow = Arc::clone(&state.google_flow);
    tokio::spawn(async move {
        let result = MacConnection::at(&home)
            .connect_with_lang(&SystemBrowser, &CONNECT_SCOPES, lang)
            .await;
        match result {
            Ok(_) => tracing::info!("Google connection established"),
            Err(error) => tracing::warn!(error = %error, "Google connection failed"),
        }
        flow.end();
    });
    Json(GoogleJson {
        connected: false,
        reconnect_needed,
        started: true,
    })
    .into_response()
}

/// `POST /v1/google/disconnect`.
pub async fn disconnect(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let lang = request_lang(&headers);
    let connection = MacConnection::at(&state.home);
    let result = connection.disconnect().await;
    // The local authorization is what this Mac controls: once the grant file is
    // gone, the owner is disconnected here whatever Google answered.
    let connected = connection.connected();
    if let Err(error) = result {
        tracing::warn!(%error, connected, "Google disconnect did not revoke cleanly");
    }
    if connected {
        return error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "google_disconnect_failed",
            kernel_core::i18n::text(Message::GoogleDisconnectFailed, lang),
            None,
        );
    }
    Json(GoogleJson {
        connected: false,
        reconnect_needed: false,
        started: false,
    })
    .into_response()
}

fn request_lang(headers: &HeaderMap) -> Lang {
    headers
        .get("X-Auxesis-Lang")
        .and_then(|value| value.to_str().ok())
        .and_then(Lang::parse)
        .unwrap_or(Lang::En)
}

#[cfg(test)]
mod i18n_tests {
    use super::*;

    #[test]
    fn invalid_or_absent_language_header_falls_back_to_english() {
        assert_eq!(request_lang(&HeaderMap::new()), Lang::En);
        let mut headers = HeaderMap::new();
        headers.insert("X-Auxesis-Lang", "de".parse().unwrap());
        assert_eq!(request_lang(&headers), Lang::En);
        headers.insert("X-Auxesis-Lang", "fr".parse().unwrap());
        assert_eq!(request_lang(&headers), Lang::Fr);
    }
}
