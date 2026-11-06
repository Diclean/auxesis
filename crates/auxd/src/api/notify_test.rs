//! `POST /v1/notify/test` — one fixed, content-free test text from auxd.
//!
//! macOS asks for Automation → Messages only when auxd itself sends while
//! the owner is at the screen. This route lets the owner trigger that send:
//! the text is a constant, the recipient and channel are the morning brief's
//! own (the notify router's brief lane), and the request takes no body. The
//! answer carries labels only, never message text.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kernel_core::Lang;

use crate::gateway::router::{BriefOutcome, BRIEF_REPORT_WAIT};

use super::error;
use super::ApiState;

/// The test text, English.
pub const TEST_TEXT_EN: &str =
    "Auxesis test: if you can read this, the morning brief can reach you.";
/// The test text, French.
pub const TEST_TEXT_FR: &str =
    "Test Auxesis : si vous lisez ceci, le brief du matin peut vous joindre.";

/// At most one test send per this window.
const MIN_INTERVAL: Duration = Duration::from_secs(60);

fn test_text(lang: Lang) -> &'static str {
    match lang {
        Lang::Fr => TEST_TEXT_FR,
        Lang::En => TEST_TEXT_EN,
    }
}

/// `delivered` and the closed cause label (the brief's `SendCause` strings,
/// plus the router outcomes that carry no transport cause).
fn outcome_labels(outcome: BriefOutcome) -> (bool, Option<&'static str>) {
    match outcome {
        BriefOutcome::Sent | BriefOutcome::NoticeSent => (true, None),
        BriefOutcome::Failed(Some(cause)) => (false, Some(cause.as_str())),
        BriefOutcome::Failed(None) => (false, Some("not_delivered")),
        BriefOutcome::Unconfirmed => (false, Some("not_confirmed")),
        BriefOutcome::Held => (false, Some("held")),
        BriefOutcome::Quiet => (false, Some("quiet_hours")),
        BriefOutcome::Queued => (false, Some("queued")),
    }
}

/// `POST /v1/notify/test` — send the fixed test text now.
pub async fn run(State(state): State<Arc<ApiState>>, body: Bytes) -> Response {
    if !body.is_empty() {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "body_not_allowed",
            "this route takes no request body",
            None,
        );
    }
    if aux_engine::marker_engaged(&state.home) {
        return error::error_response(
            StatusCode::CONFLICT,
            "stopped",
            "the kill switch is engaged; resume before sending a test",
            None,
        );
    }
    let Some(router) = state.notify_router.clone() else {
        return error::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "notify_unavailable",
            "the daemon has no notification channel",
            None,
        );
    };
    {
        let mut last = kernel_core::lock_recover(&state.notify_test_last);
        if last.is_some_and(|at| at.elapsed() < MIN_INTERVAL) {
            return error::error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "one test send a minute; try again shortly",
                None,
            );
        }
        *last = Some(Instant::now());
    }
    let home = state.home.clone();
    let sent = tokio::task::spawn_blocking(move || {
        let lang = super::load_config_verified(&home)
            .map(|config| config.ui.language)
            .unwrap_or_default();
        let (delivered, cause) =
            outcome_labels(router.test_reported(test_text(lang), BRIEF_REPORT_WAIT));
        // Audit: labels only. A failed write never fails the send.
        let row = serde_json::json!({ "delivered": delivered, "cause": cause }).to_string();
        let logged = aux_store::Store::open(&kernel_core::store_path(&home))
            .map(|store| store.log_event("notify.test", &row));
        if !matches!(logged, Ok(Ok(()))) {
            tracing::warn!("notify test not recorded");
        }
        (delivered, cause)
    })
    .await;
    match sent {
        Ok((delivered, cause)) => {
            Json(serde_json::json!({ "delivered": delivered, "cause": cause })).into_response()
        }
        Err(join) => {
            tracing::error!(error = %join, "notify test runner failed");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the daemon could not complete this request",
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::SendCause;

    #[test]
    fn every_outcome_maps_to_a_closed_label() {
        assert_eq!(outcome_labels(BriefOutcome::Sent), (true, None));
        assert_eq!(
            outcome_labels(BriefOutcome::Failed(Some(SendCause::NotAuthorized))),
            (false, Some("not_authorized"))
        );
        assert_eq!(
            outcome_labels(BriefOutcome::Unconfirmed),
            (false, Some("not_confirmed"))
        );
        assert_eq!(test_text(Lang::Fr), TEST_TEXT_FR);
    }
}
