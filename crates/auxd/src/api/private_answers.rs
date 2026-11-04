//! Private-mode iMessage answers, held in memory only.
//!
//! | Method | Path | Answer |
//! |---|---|---|
//! | GET | `/v1/private/answers` | the held answers, newest first |
//! | POST | `/v1/private/answers/{id}/dismiss` | removes one (204) |
//!
//! Private mode writes no chat rows, so an answer to an owner text that
//! came over Messages waits here for the app. It is never written to disk, a
//! log, the ledger or the store; a restart, or any read after Private mode is
//! switched off, drops it. The inbound text is not kept. The routes sit behind
//! the shared bearer-token middleware and answer the owner's app on loopback.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use kernel_core::privacy::{admit_call, Destination, PathId, PrivacyMode};
use serde::Serialize;

use super::error;
use super::ApiState;

/// Most answers held; the oldest is dropped past this.
pub const MAX_HELD: usize = 20;

/// One held answer: the rehydrated local text, nothing of the inbound text.
#[derive(Clone, Serialize)]
pub struct HeldAnswer {
    pub id: String,
    /// RFC 3339, UTC.
    pub received_at: String,
    pub answer: String,
}

/// The bounded in-memory ring. No `Debug`: it holds real names.
#[derive(Default)]
pub struct PrivateAnswers {
    next: Mutex<(u64, VecDeque<HeldAnswer>)>,
}

impl PrivateAnswers {
    /// Rehydrate the gated `answer` of session `thread_id` with that session's
    /// own tokens, then hold it. The real values live only in this ring.
    pub fn hold_local(&self, home: &std::path::Path, thread_id: i64, answer: &str) {
        self.hold(super::display::rehydrate_text(home, thread_id, answer));
        // The session is over: its token table goes, so the values live only here.
        super::display::live_tokens().forget(thread_id);
    }

    /// Hold `answer`, dropping the oldest past [`MAX_HELD`].
    pub fn hold(&self, answer: String) {
        let mut guard = kernel_core::lock_recover(&self.next);
        guard.0 += 1;
        let id = guard.0.to_string();
        guard.1.push_back(HeldAnswer {
            id,
            received_at: chrono::Utc::now().to_rfc3339(),
            answer,
        });
        while guard.1.len() > MAX_HELD {
            guard.1.pop_front();
        }
    }

    /// The held answers, newest first.
    pub fn list(&self) -> Vec<HeldAnswer> {
        let guard = kernel_core::lock_recover(&self.next);
        guard.1.iter().rev().cloned().collect()
    }

    /// Remove one answer; whether it was held.
    pub fn dismiss(&self, id: &str) -> bool {
        let mut guard = kernel_core::lock_recover(&self.next);
        let before = guard.1.len();
        guard.1.retain(|held| held.id != id);
        guard.1.len() != before
    }

    /// Drop every answer.
    pub fn clear(&self) {
        kernel_core::lock_recover(&self.next).1.clear();
    }
}

pub fn routes() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/v1/private/answers", get(list))
        .route("/v1/private/answers/{id}/dismiss", post(dismiss))
}

/// Whether the owner's app may be shown the answers now: Private mode only
/// (anything else drops them), through the local-display row C12.
fn displayable(state: &ApiState) -> bool {
    let mode = crate::privacy_wiring::current_mode(&state.home);
    if mode == PrivacyMode::Private
        && admit_call(PathId::C12, mode, Destination::LocalDisplay).is_ok()
    {
        return true;
    }
    state.private_answers.clear();
    false
}

async fn list(State(state): State<Arc<ApiState>>) -> Response {
    if !displayable(&state) {
        return Json(Vec::<HeldAnswer>::new()).into_response();
    }
    Json(state.private_answers.list()).into_response()
}

async fn dismiss(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    if displayable(&state) && state.private_answers.dismiss(&id) {
        return StatusCode::NO_CONTENT.into_response();
    }
    error::error_response(StatusCode::NOT_FOUND, "not_found", "no such answer", None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hold_local_rehydrates_with_the_sessions_own_tokens_then_forgets_them() {
        let home = std::path::Path::new("/nonexistent-home");
        let pair = (
            "PERSON_1A2B3C4D5E6F".to_string(),
            "Camille Durand".to_string(),
        );
        super::super::display::live_tokens().record(7_001, &[pair]);
        let held = PrivateAnswers::default();
        let text = "Noted: \u{27e6}PERSON_1A2B3C4D5E6F\u{27e7}.";
        held.hold_local(home, 7_001, text);
        assert_eq!(held.list()[0].answer, "Noted: Camille Durand.");
        held.hold_local(home, 7_001, text);
        assert!(
            !held.list()[0].answer.contains("Camille"),
            "tokens forgotten"
        );
    }
}
