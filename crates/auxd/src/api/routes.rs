//! HTTP routes of the local API (B-API v1).
//!
//! Surface:
//!
//! | Method | Path | Status |
//! |---|---|---|
//! | GET | `/v1/health` | `{ok, version, pid, first_run}` |
//! | GET | `/v1/agents` · `/v1/agents/{id}` | agent list / detail with live state + `thread_id` |
//! | GET | `/v1/agents/{id}/soul` | the agent's personality, whole (editor read) |
//! | POST | `/v1/agents` | create an agent (name, instructions, provider/model, tools) |
//! | PUT/PATCH | `/v1/agents/{id}` | update an agent (role/provider/model/tools) |
//! | POST | `/v1/agents/{id}/pause` · `/resume` · `/kill` | per-agent stop markers |
//! | POST | `/v1/stop-all` | engage the one kill switch (audited) |
//! | GET/POST | `/v1/threads/{id}/messages` | read page / run one engine turn (append) |
//! | POST | `/v1/threads/{id}/new` · `/select` | start a fresh chat / make `{"session"}` the agent's current one |
//! | GET | `/v1/conversations` | Aux's past chats: id, title, last activity (newest first, 50) |
//! | GET | `/v1/activity?since=&agent=&limit=` | `aux activity` semantics |
//! | GET | `/v1/receipts?agent=&limit=` | run receipts, newest first |
//! | GET | `/v1/usage?agent=&period=day&day=` | `aux usage` semantics + caps |
//! | GET | `/v1/jobs` | scheduled jobs + `next_run_at` |
//! | POST | `/v1/jobs` | create a routine `{agent, name, schedule, prompt}` (audited) |
//! | PATCH/DELETE | `/v1/jobs/{id}` | pause/resume (`{enabled}`) or delete a routine (audited; system jobs `403`) |
//! | POST | `/v1/brief/run` | run the morning brief once, now |
//! | POST | `/v1/notify/test` | send one fixed test text on the brief's channel; `{delivered, cause}` |
//! | GET | `/v1/brief/today` | today's stored brief (`DailyBrief` shape) or `404 no_brief` |
//! | GET | `/v1/brief/status` | did today's brief run: time, trigger, sections, delivery; no content |
//! | POST | `/v1/brief/prospects/add`, `/ignore` | add a suggested sender as a `prospect` party, or never suggest it again |
//! | GET | `/v1/providers` | configured providers/models + key presence (never values) |
//! | GET | `/v1/skills` | owner-authored local instruction skills |
//! | POST | `/v1/extensions/{id}/oauth/start` | local PKCE flow; answers the authorize URL |
//! | GET | `/v1/extensions/{id}/oauth/status` | whether an authorization is stored (boolean only) |
//! | DELETE | `/v1/extensions/{id}/oauth` | forget the stored extension authorization |
//! | POST | `/v1/providers` | save a provider; secret to `<home>/.env` only (audited) |
//! | PUT | `/v1/providers/{name}/key` | set the key of an existing provider (audited) |
//! | POST | `/v1/providers/test` · `/v1/providers/{id}/test` | cheap spend-free check |
//! | GET/PUT | `/v1/settings` | read or update UI language and memory suggestions |
//! | GET | `/v1/first-run` | guided-setup step states (`provider_saved`, …) |
//! | POST | `/v1/first-run/complete` | idempotently create the default `main` agent |
//! | POST | `/v1/google/connect` | start the Google sign-in (owner click only) |
//! | POST | `/v1/google/reconnect` | renew missing Google permissions (owner click only) |
//! | POST | `/v1/google/disconnect` | revoke + delete this Mac's Google grant |
//! | POST | `/v1/workspaces/trust` | owner trust: request a code / complete with it (audited) |
//! | GET | `/v1/approvals?state=pending` | pending approvals (in-memory) |
//! | POST | `/v1/approvals/{id}` | answer: deny / allow_once / allow_always / edit |
//! | POST | `/v1/apple-eventkit/snapshot` | the app publishes its calendar and reminders snapshot |
//! | GET | `/v1/apple-eventkit/status` | the calendar copy's age: `{shared, updated_at, covers_from, covers_to, fresh}`; no event |
//! | POST | `/v1/bridge/{id}` | the app's answer to one pending bridge call |
//! | GET/PUT | `/v1/clients` · `/v1/clients/{id}` | client list / card; PUT edits the party (E3) |
//! | DELETE | `/v1/clients/{id}/memory/{item}` | forget one memory line of a client card |
//! | POST | `/v1/contacts/import` | preview (`dry_run`) or import a vCard / CSV contacts file on this Mac; counts only |
//! | POST | `/v1/stop` · `/v1/resume` | STOP marker write/remove |
//! | GET | `/v1/events` | WebSocket live channel |
//!
//! Deferred routes (mode, screen, audit, agent delete) answer
//! `501 not_implemented` with a machine-readable body, so the app can gate
//! cleanly.
//!
//! # Thread ids
//!
//! `{id}` in `/v1/threads/{id}/messages` is either a **store session id**
//! (pure digits), a **agent name** (resolved to the agent's current session, i.e.
//! the newest session with messages), or an agent name without a session yet
//! (POST creates one, lazily). Sends **append**: a session keeps exactly one
//! system prompt for its whole life. Unknown explicit ids are a clean `404`;
//! they never silently create a session.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{middleware, Json, Router};
use serde::{Deserialize, Serialize};

use super::auth;
use super::display;
use super::error;
use super::events;
use super::first_run;
#[cfg(feature = "google")]
use super::google;
use super::providers;
use super::refusal;
use super::security;
use super::snapshot::{self, ActivityQuery, ThreadError, ThreadTarget};
use super::turn::TurnError;
use super::wire::{self, ApprovalStateFrame};
use super::{
    agents, ApiState, DEFAULT_PAGE_LIMIT, MAX_CONTENT_BYTES, MAX_PAGE_LIMIT, MAX_REQUEST_BODY_BYTES,
};

/// The G4 Google connection routes. Compiled out without the `google` feature,
/// so the default daemon exposes no Google endpoint at all.
fn consent_routes() -> Router<Arc<ApiState>> {
    let router = Router::new();
    #[cfg(feature = "google")]
    let router = router
        .route("/v1/google/connect", post(google::connect))
        .route("/v1/google/reconnect", post(google::reconnect))
        .route("/v1/google/disconnect", post(google::disconnect));
    router
}

/// Build the authenticated router.
pub fn router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/agents", get(agents_list).post(agents::create))
        .route(
            "/v1/agents/{id}",
            get(agent_show)
                .put(agents::update)
                .patch(agents::update)
                .delete(agents_write_not_implemented),
        )
        .route("/v1/agents/{id}/soul", get(agents::soul_show))
        .route("/v1/agents/{id}/pause", post(agents::pause))
        .route("/v1/agents/{id}/resume", post(agents::resume))
        .route("/v1/agents/{id}/kill", post(agents::kill))
        .route(
            "/v1/agents/{id}/grants",
            get(crate::agents::grants_show).put(crate::agents::grants_update),
        )
        .route("/v1/agents/{id}/memory", get(crate::agents::memory_list))
        .route(
            "/v1/agents/{id}/memory/view",
            get(crate::agents::memory_view_list),
        )
        .route(
            "/v1/agents/{id}/memory/{item}",
            delete(crate::agents::memory_forget)
                .patch(crate::agents::memory_edit)
                .layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/v1/agents/{id}/memory/suggestions/{sid}/{decision}",
            post(crate::agents::memory_suggestion_decide).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route("/v1/stop-all", post(agents::stop_all))
        .route(
            "/v1/threads/{id}/messages",
            get(thread_messages).post(send_message),
        )
        .route("/v1/threads/{id}/new", post(new_thread))
        .route("/v1/threads/{id}/select", post(select_thread))
        .route(
            "/v1/threads/{id}/read",
            post(crate::delegation::thread_read),
        )
        .route("/v1/conversations", get(conversations))
        .route("/v1/activity", get(activity))
        .route("/v1/receipts", get(receipts))
        .route("/v1/usage", get(usage))
        .route("/v1/jobs", get(jobs).post(super::jobs::create))
        .route(
            "/v1/jobs/{id}",
            patch(super::jobs::update).delete(super::jobs::delete),
        )
        .route("/v1/brief/run", post(super::brief::run))
        .route("/v1/notify/test", post(super::notify_test::run))
        .route("/v1/brief/today", get(super::brief::today))
        .route("/v1/brief/status", get(super::brief::status))
        .route("/v1/brief/prospects/add", post(super::brief::prospect_add))
        .route(
            "/v1/brief/prospects/ignore",
            post(super::brief::prospect_ignore),
        )
        .route("/v1/skills", get(super::skills::list))
        .route(
            "/v1/extensions/{id}/oauth/start",
            post(super::extensions::start),
        )
        .route(
            "/v1/extensions/{id}/oauth/status",
            get(super::extensions::status),
        )
        .route(
            "/v1/extensions/{id}/oauth",
            delete(super::extensions::disconnect),
        )
        .route("/v1/mcp/catalog", get(super::mcp_plugins::catalog))
        .route("/v1/mcp/packs", get(super::mcp_plugins::packs))
        .route(
            "/v1/mcp/packs/{pack}/enable",
            post(super::mcp_plugins::enable_pack),
        )
        .route(
            "/v1/mcp/servers/test",
            post(super::mcp_plugins::test_server),
        )
        .route(
            "/v1/mcp/servers/import",
            post(super::mcp_plugins::import_servers),
        )
        .route(
            "/v1/mcp/servers",
            get(super::mcp_plugins::servers).post(super::mcp_plugins::add_server),
        )
        .route(
            "/v1/mcp/servers/{id}",
            put(super::mcp_plugins::set_server).delete(super::mcp_plugins::delete_server),
        )
        .route(
            "/v1/mcp/servers/{id}/agents/{agent}",
            put(super::mcp_plugins::set_agent_tools),
        )
        .route(
            "/v1/mcp/servers/{id}/confirmation",
            get(super::mcp_plugins::confirmation_preview)
                .delete(super::mcp_plugins::revoke_confirmation),
        )
        .route(
            "/v1/mcp/servers/{id}/confirm",
            post(super::mcp_plugins::confirm_server),
        )
        .route(
            "/v1/mcp/servers/{id}/approval",
            get(super::mcp_plugins::server_approval),
        )
        .route(
            "/v1/mcp/servers/{id}/approve",
            post(super::mcp_plugins::approve_server),
        )
        .route("/v1/workspaces/trust", post(trust_workspace))
        .route(
            "/v1/stop",
            get(crate::delegation::stop_status).post(engage_stop),
        )
        .route("/v1/resume", post(release_stop))
        .route("/v1/delegations", get(crate::delegation::list))
        .route("/v1/delegations/{id}", get(crate::delegation::show))
        .route("/v1/delegations/{id}/stop", post(crate::delegation::stop))
        .route(
            "/v1/delegations/{id}/resume",
            post(crate::delegation::resume),
        )
        .route("/v1/events", get(events::events_socket))
        .route("/v1/approvals", get(approvals_list))
        .route("/v1/privacy/coverage", get(super::coverage::show))
        .route("/v1/approvals/{id}", post(resolve_approval))
        .route("/v1/approvals/{id}/undo", post(undo_approval))
        // Features deferred past B-API v2.
        .route(
            "/v1/mode",
            get(mode_not_implemented).put(mode_not_implemented),
        )
        .route("/v1/settings", get(settings_show).put(settings_update))
        .route(
            "/v1/providers",
            get(providers::list).post(providers::create),
        )
        .route("/v1/providers/test", post(providers::test))
        .route("/v1/providers/{id}/test", post(providers::test_by_id))
        .route("/v1/providers/{name}/key", put(providers::update_key))
        .route("/v1/first-run", get(first_run::status))
        .route("/v1/first-run/complete", post(first_run::complete))
        // G4: the owner's Google connection, compiled out without the feature.
        .merge(consent_routes())
        .route("/v1/apple-eventkit/snapshot", post(apple_eventkit_snapshot))
        .route("/v1/apple-eventkit/status", get(apple_eventkit_status))
        // The Mac app answers a bridge request here. Route-level body limit:
        // an OCR result can exceed the 128 KiB global cap.
        .route(
            "/v1/bridge/{id}",
            post(bridge_answer).layer(DefaultBodyLimit::max(crate::bridge::MAX_BRIDGE_BODY_BYTES)),
        )
        // C2b: the document extractor queue the Mac bridge polls (path B25).
        .merge(super::docs_api::routes())
        // M5-2: the owner's receipts of a period to a CSV and the originals.
        .merge(super::docs_export::routes())
        // E3: the Clients destination (list, card, edit, forget a memory line).
        .merge(super::clients::routes())
        // Private-mode iMessage answers held in memory (PRIV-IMSG).
        .merge(super::private_answers::routes())
        // Import clients from a contacts file (WO-CRMIO-1).
        .merge(super::contacts::routes())
        .route("/v1/screen", get(screen_not_implemented))
        .route("/v1/audit/{id}", get(audit_not_implemented))
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_token,
        ))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        // Outermost: a non-loopback Host or a cross-origin browser request
        // is refused before auth and before any route (F-17/C P3-2).
        .layer(middleware::from_fn(security::validate_host_origin))
        .with_state(state)
}

async fn apple_eventkit_snapshot(State(state): State<Arc<ApiState>>, body: Bytes) -> Response {
    if body.len() > 128 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "snapshot too large").into_response();
    }
    let Some(mut snapshot) = crate::apple_eventkit::parse_published(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid EventKit snapshot").into_response();
    };
    // A revoked/disabled authorization purges the stored snapshot and never
    // needs the item validation (its items are dropped, not served).
    if snapshot.authorized && crate::apple_eventkit::validate_snapshot(&mut snapshot).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid EventKit snapshot").into_response();
    }
    match crate::apple_eventkit::save_snapshot(&state.home, &snapshot) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "could not save snapshot").into_response(),
    }
}

/// How fresh the calendar copy is (CAL-SNAPSHOT-STALE): the capture facts the
/// app wrote into it, never an event. `shared` is false with no stored copy.
async fn apple_eventkit_status(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let snapshot = tokio::task::spawn_blocking(move || crate::apple_eventkit::read_snapshot(&home))
        .await
        .ok()
        .flatten()
        .filter(|snapshot| snapshot.authorized);
    let Some(snapshot) = snapshot else {
        return Json(serde_json::json!({
            "shared": false,
            "updated_at": null,
            "covers_from": null,
            "covers_to": null,
            "fresh": false,
        }))
        .into_response();
    };
    let age = crate::apple_eventkit::snapshot_age(&snapshot, chrono::Utc::now());
    let utc = |at: Option<chrono::DateTime<chrono::Utc>>| {
        at.map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    };
    Json(serde_json::json!({
        "shared": true,
        "updated_at": utc(age.updated_at),
        "covers_from": utc(age.covers_from),
        "covers_to": utc(age.covers_to),
        "fresh": age.fresh,
    }))
    .into_response()
}

/// One app answer to a bridge request (`docs/phase1.md` §3).
///
/// Unknown fields are refused so a future field cannot be silently ignored;
/// exactly one of `result` / `error`+`message` is required.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeAnswerRequest {
    ok: bool,
    #[serde(default)]
    result: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

/// `POST /v1/bridge/{id}` — the app's answer to one pending bridge call.
///
/// The route is behind the shared bearer-token middleware, so a missing or
/// wrong token is a `401` that never touches the pending call. The first
/// answer wins (`200`); a replay within 10 minutes is a `409`, an id that was
/// never sent is a `404`.
async fn bridge_answer(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_bridge_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: BridgeAnswerRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "the answer must be an object `{ok:true,result}` or `{ok:false,error,message}`",
                None,
            )
        }
    };
    let answer = if request.ok {
        if request.error.is_some() || request.message.is_some() {
            return invalid_bridge_answer("`ok:true` must not carry `error` or `message`");
        }
        match request.result.filter(serde_json::Value::is_object) {
            Some(result) => crate::bridge::BridgeAnswer::Result(result),
            None => return invalid_bridge_answer("`ok:true` needs a `result` object"),
        }
    } else {
        if request.result.is_some() {
            return invalid_bridge_answer("`ok:false` must not carry `result`");
        }
        match (request.error, request.message) {
            (Some(code), Some(message)) => crate::bridge::BridgeAnswer::Error { code, message },
            _ => return invalid_bridge_answer("`ok:false` needs `error` and `message` strings"),
        }
    };
    match state.bridge.answer(&id, answer) {
        crate::bridge::AnswerOutcome::Accepted => {
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        crate::bridge::AnswerOutcome::Conflict => error::error_response(
            StatusCode::CONFLICT,
            "bridge_already_answered",
            "this bridge request was already answered",
            None,
        ),
        crate::bridge::AnswerOutcome::Unknown => error::error_response(
            StatusCode::NOT_FOUND,
            "bridge_unknown",
            "no such bridge request",
            None,
        ),
    }
}

/// Read one bridge answer body, reporting the bridge's own 1 MiB cap.
#[allow(clippy::result_large_err)]
fn read_bridge_body(body: Result<Bytes, BytesRejection>) -> Result<Bytes, Response> {
    match body {
        Ok(bytes) => Ok(bytes),
        Err(rejection) => {
            let status = rejection.into_response().status();
            if status == StatusCode::PAYLOAD_TOO_LARGE {
                Err(error::error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!(
                        "the request body is too large (max {} KiB)",
                        crate::bridge::MAX_BRIDGE_BODY_BYTES / 1024
                    ),
                    None,
                ))
            } else {
                Err(error::error_response(
                    status,
                    "invalid_body",
                    "the request body could not be read",
                    None,
                ))
            }
        }
    }
}

fn invalid_bridge_answer(message: &'static str) -> Response {
    error::error_response(StatusCode::BAD_REQUEST, "invalid_answer", message, None)
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct HealthJson {
    ok: bool,
    version: &'static str,
    pid: u32,
    /// True until at least one provider is configured **and** one agent
    /// exists: the first-run wizard's gate (B-API v3). Honest by
    /// construction: it reads `config.toml` and `<home>/agents` per request.
    first_run: bool,
    /// True when this Mac holds a Google authorization right now (G4). A
    /// boolean only: never a token, never an email, never a client id.
    google_connected: bool,
    /// True when the existing grant lacks a permission Auxesis now needs.
    google_reconnect_needed: bool,
}

async fn health(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let (first_run, google_connected, google_reconnect_needed) =
        tokio::task::spawn_blocking(move || {
            #[cfg(feature = "google")]
            {
                let google = aux_google::MacConnection::at(&home);
                (
                    snapshot::first_run(&home),
                    google.connected(),
                    google.needs_reconsent(),
                )
            }
            #[cfg(not(feature = "google"))]
            {
                let _ = &home;
                (snapshot::first_run(&home), false, false)
            }
        })
        .await
        .unwrap_or((true, false, false));
    Json(HealthJson {
        ok: true,
        version: kernel_core::VERSION,
        pid: std::process::id(),
        first_run,
        google_connected,
        google_reconnect_needed,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------------

async fn agents_list(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || snapshot::agents_snapshot(&home)).await {
        Ok(Ok(mut agents)) => {
            // D33: open approvals per agent. The store snapshot cannot see
            // the in-memory registry, so the handler overlays the count.
            let mut counts: std::collections::HashMap<String, u32> =
                std::collections::HashMap::new();
            for pending in state.approvals.list_pending() {
                *counts.entry(pending.agent).or_default() += 1;
            }
            for agent in &mut agents {
                agent.waiting = counts.get(&agent.name).copied().unwrap_or(0);
            }
            Json(agents).into_response()
        }
        Ok(Err(err)) => internal_error("listing agents", &err),
        Err(err) => internal_error("joining the agent reader", &anyhow::Error::from(err)),
    }
}

async fn agent_show(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    if let Err(err) = aux_engine::validate_agent(&id) {
        return invalid_agent(&id, &err.to_string());
    }
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || snapshot::agent_detail(&home, &id)).await {
        Ok(Ok(Some(detail))) => Json(detail).into_response(),
        Ok(Ok(None)) => error::error_response(
            StatusCode::NOT_FOUND,
            "agent_not_found",
            "no such agent",
            None,
        ),
        Ok(Err(err)) => internal_error("reading an agent", &err),
        Err(err) => internal_error("joining the agent reader", &anyhow::Error::from(err)),
    }
}

// ---------------------------------------------------------------------------
// threads / messages
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct MessagesQuery {
    before: Option<String>,
    limit: Option<String>,
}

async fn thread_messages(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Response {
    let limit = match parse_limit(query.limit.as_deref()) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let before = match parse_before(query.before.as_deref()) {
        Ok(before) => before,
        Err(response) => return response,
    };

    let home = state.home.clone();
    let resolved = tokio::task::spawn_blocking(move || snapshot::resolve_thread(&home, &id)).await;
    let target = match resolved {
        Ok(Ok(Some(target))) => target,
        Ok(Ok(None)) => {
            return error::error_response(
                StatusCode::NOT_FOUND,
                "thread_not_found",
                "no such thread",
                None,
            )
        }
        Ok(Err(ThreadError::InvalidAgent { agent, reason })) => {
            return invalid_agent(&agent, &reason)
        }
        Ok(Err(err)) => return internal_error("resolving a thread", &err.into()),
        Err(err) => return internal_error("joining the thread reader", &anyhow::Error::from(err)),
    };

    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || {
        snapshot::thread_messages(&home, &target, before, limit).map(|mut page| {
            // The loopback page shows values; the stored rows stay tokenised.
            display::rehydrate_messages(&home, &mut page.messages);
            page
        })
    })
    .await
    {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(err)) => internal_error("reading a message page", &err),
        Err(err) => internal_error("joining the message reader", &anyhow::Error::from(err)),
    }
}

/// NEW-CHAT-1: a fresh chat session for the thread's agent; the old one stays stored.
async fn new_thread(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let home = state.home.clone();
    let created = tokio::task::spawn_blocking(move || {
        let agent = match snapshot::resolve_thread(&home, &id)? {
            Some(target) => target.agent_name().to_string(),
            None => return Ok(None),
        };
        let session = aux_store::Store::open(&kernel_core::store_path(&home))
            .and_then(|store| store.start_chat_session(&agent))
            .map_err(|err| ThreadError::from(anyhow::Error::from(err)))?;
        Ok(Some(snapshot::session_json(&home, &session)))
    })
    .await;
    match created {
        Ok(Ok(Some(session))) => {
            state.runner.forget_thread(&session.agent);
            Json(session).into_response()
        }
        Ok(Ok(None)) => error::error_response(
            StatusCode::NOT_FOUND,
            "thread_not_found",
            "no such thread",
            None,
        ),
        Ok(Err(ThreadError::InvalidAgent { agent, reason })) => invalid_agent(&agent, &reason),
        Ok(Err(err)) => internal_error("starting a new thread", &err.into()),
        Err(err) => internal_error("joining the thread writer", &anyhow::Error::from(err)),
    }
}

#[derive(Debug, Deserialize)]
struct SelectRequest {
    /// A store session id, as a string or a number.
    session: serde_json::Value,
}

/// THREAD-RESTORE-1: make an existing chat session the agent's current one (persisted like
/// `/new`'s mark). Unknown agent or session, or one of another agent: `404`, nothing changes.
async fn select_thread(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let session_id = serde_json::from_slice::<SelectRequest>(&body)
        .ok()
        .and_then(|request| match request.session {
            serde_json::Value::String(text) => text.parse::<i64>().ok(),
            serde_json::Value::Number(number) => number.as_i64(),
            _ => None,
        });
    let Some(session_id) = session_id else {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "the request body must be a JSON object with a `session` id",
            None,
        );
    };
    let home = state.home.clone();
    let selected = tokio::task::spawn_blocking(move || {
        let agent = match snapshot::resolve_thread(&home, &id)? {
            Some(target) => target.agent_name().to_string(),
            None => return Ok(None),
        };
        let session = aux_store::Store::open(&kernel_core::store_path(&home))
            .and_then(|store| store.select_chat_session(&agent, session_id))
            .map_err(|err| ThreadError::from(anyhow::Error::from(err)))?;
        Ok(session.map(|session| snapshot::session_json(&home, &session)))
    })
    .await;
    match selected {
        Ok(Ok(Some(session))) => {
            state.runner.forget_thread(&session.agent);
            Json(session).into_response()
        }
        Ok(Ok(None)) => error::error_response(
            StatusCode::NOT_FOUND,
            "thread_not_found",
            "no such thread",
            None,
        ),
        Ok(Err(ThreadError::InvalidAgent { agent, reason })) => invalid_agent(&agent, &reason),
        Ok(Err(err)) => internal_error("selecting a thread", &err.into()),
        Err(err) => internal_error("joining the thread writer", &anyhow::Error::from(err)),
    }
}

async fn conversations(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || snapshot::read_conversations(&home)).await {
        Ok(Ok(list)) => Json(list).into_response(),
        Ok(Err(err)) => internal_error("reading conversations", &err),
        Err(err) => internal_error("joining the conversation reader", &anyhow::Error::from(err)),
    }
}

#[derive(Debug, Deserialize)]
struct SendRequest {
    content: Option<String>,
}

#[derive(Debug, Serialize)]
struct SendResponse {
    thread: snapshot::SessionJson,
    messages: Vec<snapshot::MessageJson>,
    rounds: usize,
    capped: bool,
    /// The turn's run: the app clears this run's streamed drafts only.
    run_id: String,
}

async fn send_message(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let request: SendRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "the request body must be a JSON object with a `content` string",
                None,
            )
        }
    };
    let Some(content) = request.content.as_deref() else {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "missing_content",
            "`content` is required",
            None,
        );
    };
    let content = content.trim();
    if content.is_empty() {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "empty_content",
            "`content` must not be empty",
            None,
        );
    }
    if content.len() > MAX_CONTENT_BYTES {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "content_too_large",
            format!("`content` must be at most {MAX_CONTENT_BYTES} bytes"),
            None,
        );
    }

    let home = state.home.clone();
    let thread_id = id.clone();
    let resolved =
        tokio::task::spawn_blocking(move || snapshot::resolve_thread(&home, &thread_id)).await;
    let target: ThreadTarget = match resolved {
        Ok(Ok(Some(target))) => target,
        Ok(Ok(None)) => {
            return error::error_response(
                StatusCode::NOT_FOUND,
                "thread_not_found",
                "no such thread",
                None,
            )
        }
        Ok(Err(ThreadError::InvalidAgent { agent, reason })) => {
            return invalid_agent(&agent, &reason)
        }
        Ok(Err(err)) => return internal_error("resolving a thread", &err.into()),
        Err(err) => return internal_error("joining the thread reader", &anyhow::Error::from(err)),
    };

    let agent = target.agent_name().to_string();
    let session_id = match &target {
        ThreadTarget::Session(session) => Some(session.id),
        ThreadTarget::Agent { latest, .. } => latest.as_ref().map(|session| session.id),
    };
    let content = content.to_string();

    // CANCEL-AT-CARD: a bare refusal withdraws the waiting card at once,
    // through the Deny button's own path, instead of queuing behind it.
    if let Some(session_id) = session_id.filter(|_| refusal::is_bare_refusal(&content)) {
        if let Some(response) = withdraw_waiting_card(&state, session_id, &content).await {
            return response;
        }
    }

    // The turn is live: phase transitions around it. The sink refines these
    // (`working`/`thinking` around tool calls); `idle` is unconditional so a
    // failed turn can never leave the agent stuck.
    // TURN2-HANG: a turn queued behind a running one leaves the agent's
    // state to that turn (it may be waiting on a card, not thinking).
    let queued = state.turn_cancels.in_flight(&agent);
    if !queued {
        let _ = wire::send_bounded(&state.events, &wire::agent_state(&agent, "thinking"));
    }
    let runner = Arc::clone(&state.runner);
    let turn_agent = agent.clone();
    // B-API v3 × E-18: the token is registered under the agent so a per-agent
    // pause/kill (or stop-all) fires it immediately — the engine aborts the
    // in-flight provider/tool await, the shell tool reaps its process tree,
    // and the runner retires the turn's pending approvals.
    let registration = state.turn_cancels.register(&agent);
    let cancel = registration.token();
    // E-18: a dropped handler future (client disconnect) fires the token, so
    // the turn stops at its next step boundary instead of spending to
    // completion. E-14: the route also caps the whole request with the
    // configured turn timeout.
    let _cancel_on_drop = CancelOnDrop(Arc::clone(&cancel));
    let timeout = state.turn_timeout;
    let handle = tokio::task::spawn_blocking({
        let cancel = Arc::clone(&cancel);
        move || runner.run_turn(&turn_agent, session_id, &content, Some(cancel))
    });
    let record = match tokio::time::timeout(timeout, handle).await {
        Ok(record) => record,
        Err(_elapsed) => {
            cancel.cancel();
            // A queued turn that times out leaves the state to the turn ahead.
            if !queued {
                let _ = wire::send_bounded(&state.events, &wire::agent_state(&agent, "idle"));
            }
            return error::error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "turn_timeout",
                format!(
                    "the turn exceeded its {} s limit and was cancelled",
                    timeout.as_secs()
                ),
                Some("the agent is idle again; retry when the provider responds"),
            );
        }
    };
    if !matches!(record, Ok(Err(TurnError::Busy))) {
        let _ = wire::send_bounded(&state.events, &wire::agent_state(&agent, "idle"));
    }
    match record {
        Ok(Ok(record)) => {
            let mut messages: Vec<snapshot::MessageJson> = record
                .messages
                .iter()
                .map(|message| snapshot::message_json_scrubbed(&state.home, message))
                .collect();
            display::rehydrate_messages(&state.home, &mut messages);
            Json(SendResponse {
                thread: snapshot::session_json(&state.home, &record.thread),
                messages,
                rounds: record.rounds,
                capped: record.capped,
                run_id: record.run_id,
            })
            .into_response()
        }
        Ok(Err(err)) => turn_error_response(&state, err),
        Err(err) => internal_error("joining the turn runner", &anyhow::Error::from(err)),
    }
}

/// CANCEL-AT-CARD: withdraw the newest card holding `session_id`'s turn
/// exactly as its Deny button would, store the owner's words and a plain confirmation,
/// and answer. `None` when no card could be claimed.
async fn withdraw_waiting_card(
    state: &ApiState,
    session_id: i64,
    content: &str,
) -> Option<Response> {
    // CARD-NEVER-BLOCKS r1: one refusal withdraws the newest card only;
    // another turn's older card keeps waiting (list_pending is oldest first).
    let holding = |card: &super::approval::PendingApproval| {
        card.thread_id == session_id || card.root_thread == Some(session_id)
    };
    let mut claimed = Vec::new();
    for card in state
        .approvals
        .list_pending()
        .iter()
        .rev()
        .filter(|c| holding(c))
    {
        if let Some(claim) = state.approvals.claim(&card.id) {
            if card.tool == "agent.grants" {
                crate::agents::drop_proposal(&card.id);
            }
            claimed.push(claim);
            break;
        }
    }
    let tool = claimed.first()?.pending().tool.clone();
    let others = state
        .approvals
        .list_pending()
        .iter()
        .filter(|c| holding(c))
        .count();
    let name = tool.strip_prefix("skill__").unwrap_or(&tool);
    let reply = match (display::language_of(&state.home), others) {
        (kernel_core::Lang::Fr, 0) => "Annulé — rien n'a été envoyé.".to_string(),
        (kernel_core::Lang::En, 0) => "Cancelled — nothing was sent.".to_string(),
        (kernel_core::Lang::Fr, 1) => {
            format!("Retiré : {name}. 1 autre demande vous attend encore.")
        }
        (kernel_core::Lang::Fr, n) => {
            format!("Retiré : {name}. {n} autres demandes vous attendent encore.")
        }
        (kernel_core::Lang::En, 1) => {
            format!("Withdrawn: {name}. 1 other request still waits for you.")
        }
        (kernel_core::Lang::En, n) => {
            format!("Withdrawn: {name}. {n} other requests still wait for you.")
        }
    };
    let db_path = state.db_path.clone();
    let events = state.events.clone();
    let content = content.to_string();
    let stored = tokio::task::spawn_blocking(move || {
        for claim in claimed {
            let id = claim.pending().id.clone();
            let frame = ApprovalStateFrame::Denied {
                by: "you".to_string(),
            };
            let _ = claim.complete_with(super::approval::Resolution::deny(), || {
                audit_answered_sync(&db_path, &id, "deny", false, None);
                let _ = wire::send_bounded(&events, &wire::approval_resolved(&id, frame.clone()));
                let _ = wire::send_bounded(&events, &wire::approval_updated(&id, frame));
            });
        }
        let store = aux_store::Store::open(&db_path)?;
        let rows = store.append_messages_atomic(
            session_id,
            &[
                ("user", content.as_str(), None),
                ("assistant", reply.as_str(), None),
            ],
        )?;
        let session = store
            .session(session_id)?
            .ok_or_else(|| anyhow::anyhow!("session {session_id} disappeared"))?;
        Ok::<_, anyhow::Error>((session, rows))
    })
    .await;
    let (session, rows) = match stored {
        Ok(Ok(stored)) => stored,
        Ok(Err(err)) => return Some(internal_error("storing the cancellation", &err)),
        Err(err) => {
            return Some(internal_error(
                "joining the card writer",
                &anyhow::Error::from(err),
            ))
        }
    };
    let messages: Vec<snapshot::MessageJson> = rows
        .iter()
        .map(|message| snapshot::message_json_scrubbed(&state.home, message))
        .collect();
    Some(
        Json(SendResponse {
            thread: snapshot::session_json(&state.home, &session),
            messages,
            rounds: 0,
            capped: false,
            run_id: String::new(),
        })
        .into_response(),
    )
}

/// Fires a turn's cancellation token when dropped before the turn completes
/// (client disconnect). The engine stops at its next step boundary.
struct CancelOnDrop(Arc<aux_engine::TurnCancel>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Map a turn failure to a sanitized HTTP response.
fn turn_error_response(state: &ApiState, err: TurnError) -> Response {
    let detail = |text: &str| error::sanitize_detail(&state.home, text);
    match err {
        TurnError::Stopped => error::error_response(
            StatusCode::CONFLICT,
            "stopped",
            "the kill switch is engaged; resume before sending a message",
            None,
        ),
        TurnError::Inactive { agent, reason } => error::error_response_with_detail(
            StatusCode::CONFLICT,
            "agent_inactive",
            format!(
                "agent `{}` cannot run right now",
                error::sanitize_detail(&state.home, &agent)
            ),
            detail(&reason),
        ),
        TurnError::Cancelled => error::error_response(
            StatusCode::from_u16(499).unwrap_or(StatusCode::REQUEST_TIMEOUT),
            "turn_cancelled",
            "the turn was cancelled (client disconnected or the request timed out)",
            None,
        ),
        TurnError::Busy => error::error_response(
            StatusCode::CONFLICT,
            "thread_busy",
            "the previous message of this conversation waits for your answer on an approval card",
            Some("answer the card, then send again"),
        ),
        TurnError::ThreadMissing { id } => error::error_response(
            StatusCode::NOT_FOUND,
            "thread_not_found",
            format!("no thread with id {id}"),
            None,
        ),
        TurnError::InvalidAgent { agent, reason } => invalid_agent(&agent, &reason),
        TurnError::NoProvider { detail: text } => error::error_response_with_detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_provider",
            "no usable provider is configured",
            detail(&text),
        ),
        TurnError::ProviderConfig { detail: text } => error::error_response_with_detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "provider_config",
            "the provider configuration could not be loaded",
            detail(&text),
        ),
        TurnError::AgentConfig { detail: text } => error::error_response_with_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "agent_config",
            "the agent configuration could not be read",
            detail(&text),
        ),
        TurnError::Provider { detail: text } => error::error_response_with_detail(
            StatusCode::BAD_GATEWAY,
            "provider_error",
            "the provider call failed",
            detail(&text),
        ),
        TurnError::PrivacyDisabled { detail: text } => error::error_response_with_detail(
            StatusCode::FORBIDDEN,
            "privacy_disabled",
            "disabled in private mode",
            detail(&text),
        ),
        TurnError::BudgetDenied { detail: text } => error::error_response_with_detail(
            StatusCode::TOO_MANY_REQUESTS,
            "budget_denied",
            "the agent's daily budget denied this turn",
            detail(&text),
        ),
        TurnError::PrivacyWithheld { detail: text } => error::error_response_with_detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "privacy_withheld",
            "the privacy check kept this message on this Mac; nothing was sent",
            detail(&text),
        ),
        TurnError::Store { detail: text } => {
            tracing::error!(error = %text, "turn store failure");
            error::error_response_with_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "store_error",
                "the daemon could not read its store",
                detail(&text),
            )
        }
        TurnError::Internal { detail: text } => {
            tracing::error!(error = %text, "turn internal failure");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the daemon could not complete this request",
                None,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// activity / usage / jobs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ActivityParams {
    since: Option<String>,
    agent: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReceiptParams {
    agent: Option<String>,
    limit: Option<String>,
}

async fn receipts(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<ReceiptParams>,
) -> Response {
    if let Some(agent) = &params.agent {
        if let Err(err) = aux_engine::validate_agent(agent) {
            return invalid_agent(agent, &err.to_string());
        }
    }
    let limit = match parse_limit(params.limit.as_deref()) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    let db_path = state.db_path.clone();
    let agent = params.agent;
    match tokio::task::spawn_blocking(move || {
        super::receipt::read_receipts(&db_path, agent.as_deref(), limit)
    })
    .await
    {
        Ok(Ok(receipts)) => Json(receipts).into_response(),
        Ok(Err(err)) => internal_error("reading receipts", &err),
        Err(err) => internal_error("joining the receipt reader", &anyhow::Error::from(err)),
    }
}

async fn activity(
    State(state): State<Arc<ApiState>>,
    Query(params): Query<ActivityParams>,
) -> Response {
    let limit = match parse_limit(params.limit.as_deref()) {
        Ok(limit) => limit,
        Err(response) => return response,
    };
    if let Some(agent) = &params.agent {
        if let Err(err) = aux_engine::validate_agent(agent) {
            return invalid_agent(agent, &err.to_string());
        }
    }
    let home = state.home.clone();
    let agent = params.agent;
    let since = params.since;
    let result = tokio::task::spawn_blocking(move || {
        snapshot::read_activity(
            &home,
            ActivityQuery {
                agent: agent.as_deref(),
                since: since.as_deref(),
                limit,
            },
        )
    })
    .await;
    match result {
        Ok(Ok(entries)) => Json(entries).into_response(),
        Ok(Err(snapshot::ActivityReadError::Since { input })) => error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_since",
            format!(
                "invalid `since` value `{}`",
                error::sanitize_detail(&state.home, &input)
            ),
            Some("expected YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, or 30m/2h/7d"),
        ),
        Ok(Err(err)) => internal_error("reading activity", &err.into()),
        Err(err) => internal_error("joining the activity reader", &anyhow::Error::from(err)),
    }
}

#[derive(Debug, Deserialize)]
struct UsageParams {
    agent: Option<String>,
    period: Option<String>,
    day: Option<String>,
}

async fn usage(State(state): State<Arc<ApiState>>, Query(params): Query<UsageParams>) -> Response {
    match params.period.as_deref() {
        None | Some("day") => {}
        Some(other) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_period",
                format!(
                    "unsupported period `{}`; v1 supports only `day`",
                    error::sanitize_detail(&state.home, other)
                ),
                None,
            )
        }
    }
    if let Some(agent) = &params.agent {
        if let Err(err) = aux_engine::validate_agent(agent) {
            return invalid_agent(agent, &err.to_string());
        }
    }
    let home = state.home.clone();
    let agent = params.agent;
    let day = params.day;
    let result = tokio::task::spawn_blocking(move || {
        snapshot::usage_snapshot(&home, agent.as_deref(), day.as_deref())
    })
    .await;
    match result {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(snapshot::UsageReadError::InvalidDay { day })) => error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_day",
            format!(
                "invalid `day` value `{}`",
                error::sanitize_detail(&state.home, &day)
            ),
            Some("expected YYYY-MM-DD"),
        ),
        Ok(Err(err)) => internal_error("reading usage", &err.into()),
        Err(err) => internal_error("joining the usage reader", &anyhow::Error::from(err)),
    }
}

async fn jobs(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || snapshot::jobs_snapshot(&home)).await {
        Ok(Ok(jobs)) => Json(jobs).into_response(),
        Ok(Err(err)) => internal_error("listing jobs", &err),
        Err(err) => internal_error("joining the job reader", &anyhow::Error::from(err)),
    }
}

// ---------------------------------------------------------------------------
// workspace trust
// ---------------------------------------------------------------------------

/// Largest accepted workspace path (bytes).
const MAX_WORKSPACE_PATH_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
struct TrustWorkspaceRequest {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Serialize)]
struct TrustWorkspaceResponse {
    workspace: String,
    trusted: bool,
    changed: bool,
    requested: bool,
}

/// `POST /v1/workspaces/trust` — the two-step owner action that clears a
/// workspace's taint mark.
///
/// Without `code` this creates a pending trust request and sends a one-time
/// code **only** through the owner's local notification channel (the code is
/// never in this response, any other response, an audit row or the store).
/// With `code` it completes the request: the code is verified against the
/// salted KDF hash, consumed (single use), and the mark cleared and audited in
/// one transaction. The bearer token (route layer) stays required, but it is
/// not sufficient: a tool that steals it cannot read the notification, so it
/// cannot complete a trust request (security-review round 3, P1). WS-D's sandbox is
/// the second layer — see `aux_engine::trust`.
async fn trust_workspace(
    State(state): State<Arc<ApiState>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let request: TrustWorkspaceRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "the request body must be a JSON object with a `path` string",
                None,
            )
        }
    };
    let Some(path) = request.path else {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "missing_path",
            "`path` is required",
            None,
        );
    };
    if path.len() > MAX_WORKSPACE_PATH_BYTES {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_workspace",
            "the workspace path is too long",
            None,
        );
    }
    if request
        .code
        .as_deref()
        .is_some_and(|code| code.len() > MAX_TRUST_CODE_BYTES)
    {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_code",
            "the code is too long",
            None,
        );
    }

    let home = state.home.clone();
    let resolved =
        tokio::task::spawn_blocking(move || aux_engine::resolve_agent_workspace(&home, &path))
            .await;
    let workspace = match resolved {
        Ok(Ok(workspace)) => workspace,
        Ok(Err(err)) => return invalid_workspace(&state, &err.to_string()),
        Err(err) => {
            return internal_error("joining the workspace reader", &anyhow::Error::from(err))
        }
    };

    let home = state.home.clone();
    let key = workspace.clone();
    let code = request.code;
    let notifier = Arc::clone(&state.notifier);
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<TrustOutcome> {
        let store = aux_store::Store::open(&kernel_core::store_path(&home))?;
        // WS-C round 7: while the loaded `[shell]` config can run the shell
        // unsandboxed the mark is not the boundary, so the trust action is
        // refused and audited (`workspace.trust_refused`) before any code is
        // issued or consumed. A config that cannot be loaded fails closed the
        // same way the turn path does.
        let config = crate::api::load_config_verified(&home)?;
        aux_engine::refuse_when_unsandboxed_shell(&store, &key, "owner-api", &config.shell)?;
        match code {
            // Completion: the owner typed the code from the notification.
            Some(code) => {
                let completed = aux_engine::complete_trust(&store, &key, &code, "owner-api")?;
                Ok(TrustOutcome::Completed {
                    changed: completed.changed,
                })
            }
            // Request: create the pending request and deliver the code
            // through the owner's notification channel only.
            None => {
                aux_engine::request_trust(&store, &key, "owner-api", notifier.as_ref())?;
                Ok(TrustOutcome::Requested)
            }
        }
    })
    .await;
    match result {
        Ok(Ok(TrustOutcome::Requested)) => Json(TrustWorkspaceResponse {
            workspace,
            trusted: false,
            changed: false,
            requested: true,
        })
        .into_response(),
        Ok(Ok(TrustOutcome::Completed { changed })) => Json(TrustWorkspaceResponse {
            workspace,
            trusted: true,
            changed,
            requested: false,
        })
        .into_response(),
        Ok(Err(err)) => match err.downcast::<aux_engine::TrustError>() {
            Ok(trust_err) => trust_error(&state, trust_err),
            Err(err) => internal_error("trusting a workspace", &err),
        },
        Err(err) => internal_error("joining the workspace writer", &anyhow::Error::from(err)),
    }
}

/// Largest accepted submitted code (bytes); anything longer is junk, not a
/// wrong code.
const MAX_TRUST_CODE_BYTES: usize = 64;

enum TrustOutcome {
    Requested,
    Completed { changed: bool },
}

/// Map a trust failure to a sanitized HTTP response. No path can echo the
/// code: `TrustError` never carries it (the notification error detail is
/// redacted by `aux_engine::trust`).
fn trust_error(state: &ApiState, err: aux_engine::TrustError) -> Response {
    use aux_engine::TrustError;
    match err {
        TrustError::RateLimited { retry_after_secs } => error::error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "trust_rate_limited",
            format!("a trust request was already sent; try again in {retry_after_secs} s"),
            None,
        ),
        TrustError::Notification { detail } => error::error_response_with_detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "trust_notification_failed",
            "the trust code could not be delivered to your notifications",
            error::sanitize_detail(&state.home, &detail),
        ),
        TrustError::NoRequest => error::error_response(
            StatusCode::NOT_FOUND,
            "trust_request_missing",
            "no pending trust request for this workspace; request one first",
            None,
        ),
        TrustError::Expired => error::error_response(
            StatusCode::BAD_REQUEST,
            "trust_request_expired",
            "the trust code expired; request a new one",
            None,
        ),
        TrustError::WrongCode { attempts_left } => error::error_response(
            StatusCode::BAD_REQUEST,
            "trust_code_invalid",
            format!("wrong code ({attempts_left} attempt(s) left)"),
            None,
        ),
        TrustError::AttemptsExhausted => error::error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "trust_attempts_exhausted",
            "too many wrong codes; the request was cancelled — request a new one",
            None,
        ),
        TrustError::UnsandboxedShell => error::error_response(
            StatusCode::CONFLICT,
            "unsandboxed_shell",
            "the shell can run unsandboxed (`shell.allow_unsandboxed` with the sandbox disabled or unavailable), so trusting a workspace is refused; restore the sandbox in config.toml first",
            None,
        ),
        TrustError::Store(err) => internal_error("trusting a workspace", &anyhow::Error::from(err)),
        TrustError::Random(err) => {
            internal_error("drawing a trust code", &anyhow::Error::from(err))
        }
    }
}

fn invalid_workspace(state: &ApiState, reason: &str) -> Response {
    error::error_response_with_detail(
        StatusCode::BAD_REQUEST,
        "invalid_workspace",
        "the path is not an agent workspace of this Auxesis home",
        error::sanitize_detail(&state.home, reason),
    )
}

// ---------------------------------------------------------------------------
// stop / resume
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct StopResponse {
    stop: bool,
    changed: bool,
}

async fn engage_stop(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let result = tokio::task::spawn_blocking(move || {
        let was_stopped = kernel_core::killswitch::is_stopped(&home);
        kernel_core::killswitch::engage(&home).map(|()| !was_stopped)
    })
    .await;
    match result {
        Ok(Ok(changed)) => {
            state
                .stop_cancelled
                .store(0, std::sync::atomic::Ordering::Relaxed);
            let _ = wire::send_bounded(
                &state.events,
                &crate::delegation::stop_changed_frame(true, None, 0),
            );
            Json(StopResponse {
                stop: true,
                changed,
            })
            .into_response()
        }
        Ok(Err(err)) => internal_error("engaging the kill switch", &anyhow::Error::from(err)),
        Err(err) => internal_error("joining the stop writer", &anyhow::Error::from(err)),
    }
}

async fn release_stop(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
        let changed = kernel_core::killswitch::release(&home)?;
        // RESUME-AFTER-STOP: the next turn must read that the stop is lifted.
        if changed {
            if let Err(err) = record_resume_note(&home, &db_path) {
                tracing::warn!(error = %err, "could not record the resume line");
            }
        }
        Ok(changed)
    })
    .await;
    match result {
        Ok(Ok(changed)) => {
            state
                .stop_cancelled
                .store(0, std::sync::atomic::Ordering::Relaxed);
            let _ = wire::send_bounded(
                &state.events,
                &crate::delegation::stop_changed_frame(false, None, 0),
            );
            Json(StopResponse {
                stop: false,
                changed,
            })
            .into_response()
        }
        Ok(Err(err)) => internal_error("releasing the kill switch", &anyhow::Error::from(err)),
        Err(err) => internal_error("joining the resume writer", &anyhow::Error::from(err)),
    }
}

/// Append the one system line that tells the next turn the stop is over; a
/// failed write never fails the already-released switch.
fn record_resume_note(home: &std::path::Path, db_path: &std::path::Path) -> Result<(), String> {
    let french = matches!(
        crate::api::load_config_verified(home).map(|config| config.ui.language),
        Ok(kernel_core::Lang::Fr)
    );
    let text = if french {
        "Vous avez tout repris. L’arrêt est levé ; rien n’a été rejoué."
    } else {
        "You resumed all agents. The stop is lifted; nothing was replayed."
    };
    let store = aux_store::Store::open(db_path).map_err(|err| err.to_string())?;
    let mut agents = std::collections::HashSet::new();
    for session in store.list_sessions().map_err(|err| err.to_string())? {
        if !agents.insert(session.agent.clone()) {
            continue;
        }
        let Ok(Some(current)) = store.current_chat_session(&session.agent) else {
            continue;
        };
        if store.session_ever_private(current.id).unwrap_or(true) {
            continue;
        }
        if let Err(err) = store.append_message(
            current.id,
            "system",
            text,
            Some(r#"{"kind":"state","state":"resume"}"#),
        ) {
            tracing::warn!(error = %err, agent = %session.agent, "could not record the resume line");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ApprovalsQuery {
    state: Option<String>,
}

async fn approvals_list(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<ApprovalsQuery>,
) -> Response {
    match query.state.as_deref() {
        None | Some("pending") => {}
        Some(other) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_state",
                format!(
                    "unsupported state `{}`; only `pending` lives in memory",
                    error::sanitize_detail(&state.home, other)
                ),
                None,
            )
        }
    }
    let pending: Vec<wire::ApprovalFrame> = state
        .approvals
        .list_pending()
        .iter()
        .map(super::approval::PendingApproval::frame)
        .collect();
    Json(pending).into_response()
}

/// The persistent-allow part of an answer. A skill card's answer is always
/// one-time: a scope on it is ignored and no `skill__<name>` rule is written.
/// Any other ask keeps the pinned scope rule.
#[allow(clippy::result_large_err)]
fn allow_scope(
    pending: &super::approval::PendingApproval,
    scope: Option<&ScopeJson>,
) -> Result<(bool, Option<kernel_broker::Rule>), Response> {
    if pending.tool.starts_with("skill__") {
        return Ok((false, None));
    }
    match scope {
        Some(scope) => pinned_scope_rule(pending, scope).map(|rule| (true, Some(rule))),
        None => Ok((false, None)),
    }
}

/// The `scope` of an allow-always answer (a subset of the app's `PolicyRule`).
#[derive(Debug, Deserialize)]
struct ScopeJson {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    resource: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResolveRequest {
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    scope: Option<ScopeJson>,
    #[serde(default)]
    text: Option<String>,
}

async fn resolve_approval(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: ResolveRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "the request body must be a JSON object with a `decision` string",
                None,
            )
        }
    };
    let Some(decision) = request.decision.as_deref() else {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "missing_decision",
            "`decision` is required",
            None,
        );
    };

    // A grants change is a one-shot approval: only `allow_once`, `deny` or
    // `later` are meaningful, and it applies only through this exact id.
    let grants_approval = state
        .approvals
        .get(&id)
        .is_some_and(|pending| pending.tool == "agent.grants");
    if grants_approval && !matches!(decision, "allow_once" | "deny" | "later") {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "grants_one_shot",
            "a grants change is approved once (`allow_once`), denied or deferred",
            None,
        );
    }

    let (resolution, state_frame, rule) = match decision {
        "deny" => (
            super::approval::Resolution::deny(),
            ApprovalStateFrame::Denied {
                by: "you".to_string(),
            },
            None,
        ),
        "allow_once" => (
            super::approval::Resolution::allow_once(),
            ApprovalStateFrame::Allowed {
                by: "you".to_string(),
                always: false,
            },
            None,
        ),
        "allow_always" => {
            let Some(pending) = state.approvals.get(&id) else {
                // P2-1: a turn that was cancelled/timed out retires its
                // pending approvals; an answer for one is a `410`, never a
                // silent 404 that could hide a real bug.
                if state.approvals.is_abandoned(&id) {
                    return reject_abandoned(
                        &state,
                        &id,
                        "allow_always",
                        request.scope.is_some(),
                        None,
                    )
                    .await;
                }
                return approval_not_found();
            };
            // Taint cannot be widened: a conversation holding untrusted
            // content may never persist an allow rule for the ask it
            // displayed. The app greys the button; the server refuses it.
            if pending.is_tainted() {
                return error::error_response(
                    StatusCode::CONFLICT,
                    "tainted_approval",
                    "this conversation is tainted by untrusted content; `allow_always` is refused — answer `allow_once` or `deny`",
                    None,
                );
            }
            // WS-C round 7: an unsandboxed call can never be widened to a
            // persistent allow either — it must ask every time, first call
            // included. Same refusal shape as the tainted ask.
            if pending.unsandboxed {
                return error::error_response(
                    StatusCode::CONFLICT,
                    "unsandboxed_approval",
                    "this call will run unsandboxed (`shell.allow_unsandboxed` with the sandbox disabled or unavailable); `allow_always` is refused — answer `allow_once` or `deny`",
                    None,
                );
            }
            // SHELL-NETWORK-ASK: a shell with `[shell] network = true` opens
            // every socket, so it takes the same bar: a persistent allow is
            // refused and every call asks again, first call included.
            if pending.networked {
                return error::error_response(
                    StatusCode::CONFLICT,
                    "networked_approval",
                    "this call will run with the shell's network enabled (`[shell] network = true`, all sockets open); `allow_always` is refused — answer `allow_once` or `deny`",
                    None,
                );
            }
            // "Always" persists an allow rule for exactly the ask that was
            // displayed. Validate the scope *before* claiming: a rejected
            // scope is a 400 that leaves the approval pending. Without a
            // scope the answer counts for this call only.
            let (always, rule) = match allow_scope(&pending, request.scope.as_ref()) {
                Ok(pair) => pair,
                Err(response) => return response,
            };
            (
                super::approval::Resolution {
                    allow: true,
                    always,
                    by: "you".to_string(),
                    edited: None,
                },
                ApprovalStateFrame::Allowed {
                    by: "you".to_string(),
                    always,
                },
                rule,
            )
        }
        "edit" => {
            // An edited draft is a decision, not a shortcut: the broker
            // authorizes the *substituted* arguments under the same rule set,
            // taint and execution mode as the ask, and the engine re-runs its
            // own argument-dependent gates on them before they run. Editing
            // can never widen a rule (it is allow-once only) and never grows
            // the payload past the same 4 KiB cap as a tool preview.
            //
            // Expiry wins over payload shape: an edit for an ask that is no
            // longer pending (or whose turn is gone) is the same clean
            // 404/410 as allow/deny, whatever `text` holds.
            if state.approvals.get(&id).is_none() {
                if state.approvals.is_abandoned(&id) {
                    return reject_abandoned(&state, &id, "edit", false, None).await;
                }
                return approval_not_found();
            }
            let Some(text) = request.text.as_deref() else {
                return error::error_response(
                    StatusCode::BAD_REQUEST,
                    "missing_edit_text",
                    "decision `edit` requires a `text` field with the edited arguments as JSON",
                    None,
                );
            };
            if text.is_empty() {
                return error::error_response(
                    StatusCode::BAD_REQUEST,
                    "empty_edit_text",
                    "the edited draft must not be empty; the arguments are required",
                    None,
                );
            }
            if text.len() > wire::MAX_TOOL_ARGS_BYTES {
                return error::error_response(
                    StatusCode::BAD_REQUEST,
                    "edit_too_large",
                    format!(
                        "the edited draft must be at most {} bytes",
                        wire::MAX_TOOL_ARGS_BYTES
                    ),
                    None,
                );
            }
            // Reject a draft that is not JSON *before* claiming the ask, so a
            // malformed edit leaves the card pending and runs nothing.
            let edited: serde_json::Value = match serde_json::from_str(text) {
                Ok(value) => value,
                Err(_) => {
                    return error::error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_edit_text",
                        "the edited draft must be a JSON value (the tool arguments)",
                        None,
                    )
                }
            };
            // The edited payload is what the owner wrote: it must be showable
            // on a card, whole. A value that would be shown redacted while it
            // leaves raw is refused here, never run. A skill run's edit keeps
            // the run's calls and tools (SEND-REAL-ARGS-1).
            let (tool, original) = state
                .approvals
                .get(&id)
                .map(|pending| {
                    let original = serde_json::from_str(&pending.edit_args).unwrap_or_default();
                    (pending.tool, original)
                })
                .unwrap_or_default();
            let accounts = super::approval::mail_accounts(&state.home);
            let home = state.home.clone();
            let shown = super::approval::approval_preview::build_edit_checked(
                &tool,
                &original,
                &edited,
                &accounts,
                &|text| error::scrub_preview(&home, text, usize::MAX),
            );
            if let Err(reason) = shown {
                return error::error_response(
                    StatusCode::CONFLICT,
                    "edited_card_unshowable",
                    format!("the edited arguments cannot be shown for approval: {reason}"),
                    None,
                );
            }
            tracing::info!(
                approval = %id,
                text_bytes = text.len(),
                "the draft was edited; the substituted arguments will be authorized"
            );
            (
                super::approval::Resolution::edited_once(edited),
                ApprovalStateFrame::Allowed {
                    by: "you".to_string(),
                    always: false,
                },
                None,
            )
        }
        "later" => {
            // `later` is a fail-closed no: nothing runs, and the answer is
            // remembered for the bounded undo window so the same id can be
            // re-opened in every view.
            let Some(pending) = state.approvals.defer(&id) else {
                if state.approvals.is_abandoned(&id) {
                    return reject_abandoned(&state, &id, "later", false, None).await;
                }
                return approval_not_found();
            };
            let _ = pending;
            (
                super::approval::Resolution::deny(),
                ApprovalStateFrame::Deferred {
                    by: "you".to_string(),
                },
                None,
            )
        }
        other => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_decision",
                format!(
                    "unknown decision `{}`; expected deny, allow_once, allow_always or edit",
                    error::sanitize_detail(&state.home, other)
                ),
                None,
            )
        }
    };

    // The edited draft is kept for the `approval.answered` row only. It is
    // scrubbed (home path + secret shapes) and byte-capped exactly like a tool
    // preview, so a secret pasted into a draft never reaches the journal.
    let edited_text = if decision == "edit" {
        Some(error::scrub_preview(
            &state.home,
            request.text.as_deref().unwrap_or_default(),
            wire::MAX_TOOL_ARGS_BYTES,
        ))
    } else {
        None
    };

    // Atomically claim the pending *before* any side effect. Exactly one
    // answer can win; a late or duplicate answer is a clean 404 that writes
    // nothing (this closes the old get → write → resolve fail-open window).
    let Some(claimed) = state.approvals.claim(&id) else {
        // The turn is gone and the answer is late: reject it loudly (410,
        // audited, no rule write, no execution) instead of a bare 404.
        if state.approvals.is_abandoned(&id) {
            return reject_abandoned(
                &state,
                &id,
                decision,
                state_frame_always(&state_frame),
                edited_text.as_deref(),
            )
            .await;
        }
        return approval_not_found();
    };

    // RV2-06: the rule write is a read → fsync → rename → fsync under the
    // process-wide append lock. Never run it on a tokio worker: one slow disk
    // would pin the worker (and the lock serializes every answer anyway).
    if let Some(rule) = rule {
        let config = kernel_core::config_path(&state.home);
        let home = state.home.clone();
        let config_write = Arc::clone(&state.config_write);
        let write = tokio::task::spawn_blocking(move || {
            // `append_rule` is a read-modify-write of `config.toml`; it takes
            // the same shared lock so it cannot be lost to a concurrent
            // settings rewrite (P2, #133), and the `<home>/.config.lock` file
            // lock extends that to writers in other processes (security review P2).
            let _guard = config_write
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            kernel_core::with_config_lock(&home, || aux_engine::append_rule(&config, &rule))
                .map_err(|err| err.to_string())?
                .map_err(|err| err.to_string())
        })
        .await;
        let failure = match write {
            Ok(Ok(())) => None,
            Ok(Err(err)) => Some(err.to_string()),
            Err(err) => Some(err.to_string()),
        };
        if let Some(err) = failure {
            tracing::error!(error = %err, "allow-always rule could not be written");
            // The ask is already claimed; fail closed rather than run the
            // tool under an approval whose rule was not persisted. The audit
            // and the `denied` frame stay before the wake (and off the async
            // runtime, RV2-06).
            let deny = ApprovalStateFrame::Denied {
                by: "error".to_string(),
            };
            let db_path = state.db_path.clone();
            let events = state.events.clone();
            let id_for_effects = id.clone();
            let _ = tokio::task::spawn_blocking(move || {
                audit_answered_sync(
                    &db_path,
                    &id_for_effects,
                    "allow_always_rule_write_failed",
                    false,
                    None,
                );
                claimed.complete_with(super::approval::Resolution::deny(), || {
                    let _ = wire::send_bounded(
                        &events,
                        &wire::approval_resolved(&id_for_effects, deny),
                    );
                })
            })
            .await;
            return error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "rule_write_failed",
                "the allow-always rule could not be saved; the approval was denied",
                None,
            );
        }
    }

    // Finish on a blocking thread, under the registry lock: the audit row and
    // the `approval.resolved` frame are out *before* the turn wakes, so
    // `resolved` always precedes `tool.end`/`message.done`. `complete_with`
    // returns `Abandoned` when the turn already gave up (the timeout grace
    // expired); then nothing is broadcast and the answer is reported as
    // expired instead of `allowed` (RV2-01).
    let db_path = state.db_path.clone();
    let events = state.events.clone();
    let id_for_effects = id.clone();
    let decision_owned = decision.to_string();
    let always = state_frame_always(&state_frame);
    let frame = state_frame.clone();
    let frame_updated = state_frame.clone();
    let edited = edited_text.clone();
    let completion = tokio::task::spawn_blocking(move || {
        claimed.complete_with(resolution, || {
            audit_answered_sync(
                &db_path,
                &id_for_effects,
                &decision_owned,
                always,
                edited.as_deref(),
            );
            let _ = wire::send_bounded(&events, &wire::approval_resolved(&id_for_effects, frame));
            let _ = wire::send_bounded(
                &events,
                &wire::approval_updated(&id_for_effects, frame_updated),
            );
        })
    })
    .await;

    match completion {
        Ok(super::approval::Completion::Delivered) => {
            if grants_approval {
                match decision {
                    "allow_once" => {
                        if let Some(crate::agents::GrantsProposal { agent, grants, .. }) =
                            crate::agents::take_proposal(&id)
                        {
                            let home = state.home.clone();
                            let write = tokio::task::spawn_blocking(move || {
                                crate::agents::write_grants(&home, &agent, &grants)
                            })
                            .await;
                            let failed = match write {
                                Ok(Ok(())) => false,
                                Ok(Err(err)) => {
                                    tracing::warn!(error = %err, "applying an approved grants change failed");
                                    true
                                }
                                Err(err) => {
                                    tracing::warn!(error = %err, "joining the grants writer");
                                    true
                                }
                            };
                            if failed {
                                return error::error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "grants_write_failed",
                                    "the approved grants change could not be saved; nothing was applied",
                                    None,
                                );
                            }
                        }
                    }
                    "deny" => crate::agents::drop_proposal(&id),
                    _ => {}
                }
            }
            Json(serde_json::json!({ "state": state_frame })).into_response()
        }
        Ok(super::approval::Completion::Abandoned) => {
            // The answer claimed the ask in time, but its rule write finished
            // after the turn was denied. The rule (when one was requested) is
            // already persisted; this call was not allowed. Say so.
            tracing::warn!(
                approval = %id,
                "approval answered after the turn was already denied"
            );
            let db_path = state.db_path.clone();
            let id_for_audit = id.clone();
            let answer = decision.to_string();
            let edited = edited_text.clone();
            let _ = tokio::task::spawn_blocking(move || {
                audit_answered_late_sync(
                    &db_path,
                    &id_for_audit,
                    &answer,
                    always,
                    edited.as_deref(),
                )
            })
            .await;
            Json(serde_json::json!({ "state": ApprovalStateFrame::Expired })).into_response()
        }
        Err(err) => {
            tracing::error!(error = %err, "joining the approval completion");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the daemon could not complete this request",
                None,
            )
        }
    }
}

/// Internal channel entry point for Telegram's two-button approval card.
/// It deliberately reuses the HTTP route implementation so callback answers
/// get exactly the same single-claim, audit and broadcast behavior as the app.
pub(super) async fn resolve_telegram_approval(state: Arc<ApiState>, id: &str, allow: bool) -> bool {
    let decision = if allow { "allow_once" } else { "deny" };
    let body = Bytes::from(serde_json::json!({"decision": decision}).to_string());
    resolve_approval(State(state), Path(id.to_string()), Ok(body))
        .await
        .status()
        .is_success()
}

/// `POST /v1/approvals/{id}/undo`: re-open a `later` answer inside the
/// 10 s window. The same id becomes pending again in every view; the turn
/// that already stopped is not resurrected (nothing ran).
async fn undo_approval(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    match state.approvals.undo(&id) {
        Some(pending) => {
            let frame = ApprovalStateFrame::Pending;
            let _ = wire::send_bounded(
                &state.events,
                &wire::approval_updated(&pending.id, frame.clone()),
            );
            Json(serde_json::json!({ "state": frame, "approval": pending.frame() })).into_response()
        }
        None => error::error_response(
            StatusCode::CONFLICT,
            "undo_window_closed",
            "this approval was not deferred, or its undo window has closed",
            None,
        ),
    }
}

fn state_frame_always(state: &ApprovalStateFrame) -> bool {
    matches!(state, ApprovalStateFrame::Allowed { always: true, .. })
}

/// Validate an `allow_always` scope against the pending ask and return the
/// rule it is allowed to persist.
///
/// The scope can only ever restate the ask that was shown: a wildcard or any
/// other tool/agent is a `400 invalid_scope` with no write. Empty fields mean
/// "the pending one", so a scope-less payload is still pinned.
#[allow(clippy::result_large_err)]
fn pinned_scope_rule(
    pending: &super::approval::PendingApproval,
    scope: &ScopeJson,
) -> Result<kernel_broker::Rule, Response> {
    let raw_agent = scope.agent.as_deref().unwrap_or("").trim();
    let agent = if raw_agent.is_empty() {
        pending.agent.as_str()
    } else {
        raw_agent
    };
    // The agent validator runs first so wildcards and paths keep answering the
    // documented `invalid_agent`; a valid foreign agent is `invalid_scope`.
    aux_engine::validate_agent(agent).map_err(|err| invalid_agent(agent, &err.to_string()))?;
    if agent != pending.agent {
        return Err(invalid_scope(
            "scope `agent` must match the pending approval's agent",
        ));
    }

    let raw_tool = scope.tool.as_deref().unwrap_or("").trim();
    let tool = if raw_tool.is_empty() {
        pending.tool.as_str()
    } else {
        raw_tool
    };
    if tool.chars().count() > 64 {
        return Err(invalid_scope("scope `tool` must be at most 64 characters"));
    }
    if tool == kernel_broker::ANY || tool != pending.tool {
        return Err(invalid_scope(
            "scope `tool` must match the pending approval's tool exactly (no wildcards)",
        ));
    }
    // Reached only when scope.tool == pending.tool and scope.agent == pending.agent.
    let _ = &scope.resource; // B-API v2 rules have no resource dimension
    Ok(kernel_broker::Rule::new(
        pending.agent.clone(),
        pending.tool.clone(),
        kernel_broker::Action::Allow,
    ))
}

fn invalid_scope(message: &'static str) -> Response {
    error::error_response(StatusCode::BAD_REQUEST, "invalid_scope", message, None)
}

/// Blocking `approval.answered` audit write. Callers run it on a blocking
/// thread (`spawn_blocking`), never directly on a tokio worker (RV2-06).
///
/// `edited_text` is `Some` only for an `edit` decision: the scrubbed draft is
/// stored with the answer so the journal shows exactly what the owner sent.
fn audit_answered_sync(
    db_path: &std::path::Path,
    id: &str,
    decision: &str,
    always: bool,
    edited_text: Option<&str>,
) {
    let mut payload = serde_json::json!({
        "id": id,
        "decision": decision,
        "by": "you",
        "always": always,
    });
    if let Some(text) = edited_text {
        payload["edited_text"] = serde_json::Value::String(text.to_string());
    }
    let payload = payload.to_string();
    if let Err(err) = aux_store::Store::open(db_path)
        .and_then(|store| store.log_event("approval.answered", &payload))
    {
        tracing::warn!(error = %err, "approval answer audit failed");
    }
}

/// Audit an answer that arrived after the turn had already been denied
/// (RV2-01). `decision` says what the client asked, `always` whether its rule
/// was persisted; the frame it would have carried was never broadcast.
fn audit_answered_late_sync(
    db_path: &std::path::Path,
    id: &str,
    answer: &str,
    always: bool,
    edited_text: Option<&str>,
) {
    let mut payload = serde_json::json!({
        "id": id,
        "decision": "late_after_timeout",
        "answer": answer,
        "by": "you",
        "always": always,
        "late": true,
    });
    if let Some(text) = edited_text {
        payload["edited_text"] = serde_json::Value::String(text.to_string());
    }
    let payload = payload.to_string();
    if let Err(err) = aux_store::Store::open(db_path)
        .and_then(|store| store.log_event("approval.answered", &payload))
    {
        tracing::warn!(error = %err, "late approval answer audit failed");
    }
}

/// Audit an answer for an approval whose turn was already abandoned (P2-1):
/// the answer is rejected with `410`, nothing was written and nothing ran.
fn audit_answered_abandoned_sync(
    db_path: &std::path::Path,
    id: &str,
    answer: &str,
    always: bool,
    edited_text: Option<&str>,
) {
    let mut payload = serde_json::json!({
        "id": id,
        "decision": "late_after_abandon",
        "answer": answer,
        "by": "you",
        "always": always,
        "late": true,
    });
    if let Some(text) = edited_text {
        payload["edited_text"] = serde_json::Value::String(text.to_string());
    }
    let payload = payload.to_string();
    if let Err(err) = aux_store::Store::open(db_path)
        .and_then(|store| store.log_event("approval.answered", &payload))
    {
        tracing::warn!(error = %err, "abandoned approval answer audit failed");
    }
}

/// Reject an answer for an approval of a turn that is gone: audit the late
/// attempt and answer `410 Gone`. No rule write, no execution.
async fn reject_abandoned(
    state: &ApiState,
    id: &str,
    answer: &str,
    always: bool,
    edited_text: Option<&str>,
) -> Response {
    let db_path = state.db_path.clone();
    let id_for_audit = id.to_string();
    let answer = answer.to_string();
    let edited_text = edited_text.map(str::to_string);
    let _ = tokio::task::spawn_blocking(move || {
        audit_answered_abandoned_sync(
            &db_path,
            &id_for_audit,
            &answer,
            always,
            edited_text.as_deref(),
        )
    })
    .await;
    approval_abandoned()
}

fn approval_abandoned() -> Response {
    error::error_response(
        StatusCode::GONE,
        "approval_abandoned",
        "the turn that asked for this approval is gone (cancelled or timed out); the answer was not applied",
        Some("the tool did not run — send a new message to ask again"),
    )
}

fn approval_not_found() -> Response {
    error::error_response(
        StatusCode::NOT_FOUND,
        "approval_not_found",
        "no pending approval with this id",
        None,
    )
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Read a bounded POST body, mapping axum's rejection to the error envelope.
#[allow(clippy::result_large_err)]
pub(super) fn read_body(body: Result<Bytes, BytesRejection>) -> Result<Bytes, Response> {
    match body {
        Ok(bytes) => Ok(bytes),
        Err(rejection) => {
            let status = rejection.into_response().status();
            let (code, message) = if status == StatusCode::PAYLOAD_TOO_LARGE {
                (
                    "payload_too_large",
                    format!(
                        "the request body is too large (max {} KiB)",
                        MAX_REQUEST_BODY_BYTES / 1024
                    ),
                )
            } else {
                (
                    "invalid_body",
                    "the request body could not be read".to_string(),
                )
            };
            Err(error::error_response(status, code, message, None))
        }
    }
}

/// Parse and bound a `limit` query value (1..=[`MAX_PAGE_LIMIT`]).
///
/// The `Err` is a ready-made HTTP response; boxing it would only add noise.
#[allow(clippy::result_large_err)]
fn parse_limit(raw: Option<&str>) -> Result<i64, Response> {
    match raw {
        None => Ok(DEFAULT_PAGE_LIMIT),
        Some(raw) => match raw.trim().parse::<i64>() {
            Ok(limit) if (1..=MAX_PAGE_LIMIT).contains(&limit) => Ok(limit),
            _ => Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_limit",
                format!("limit must be between 1 and {MAX_PAGE_LIMIT}"),
                None,
            )),
        },
    }
}

/// Parse a `before` message id (a positive integer).
#[allow(clippy::result_large_err)]
fn parse_before(raw: Option<&str>) -> Result<Option<i64>, Response> {
    match raw {
        None => Ok(None),
        Some(raw) => match raw.trim().parse::<i64>() {
            Ok(before) if before > 0 => Ok(Some(before)),
            _ => Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_before",
                "before must be a positive message id",
                None,
            )),
        },
    }
}

pub(super) fn invalid_agent(agent: &str, reason: &str) -> Response {
    error::error_response_with_detail(
        StatusCode::BAD_REQUEST,
        "invalid_agent",
        format!(
            "invalid agent `{}`",
            error::sanitize_detail(std::path::Path::new(""), agent)
        ),
        error::sanitize_detail(std::path::Path::new(""), reason),
    )
}

fn internal_error(what: &str, err: &anyhow::Error) -> Response {
    tracing::error!(error = %err, task = what, "local API failure");
    error::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "the daemon could not complete this request",
        None,
    )
}

// Deferred features: a clear 501 beats a random 404 for the app.

async fn mode_not_implemented() -> Response {
    error::not_implemented("mode (Engaged/Away)")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemorySettingsRequest {
    #[serde(default)]
    suggestions: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsRequest {
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    memory: Option<MemorySettingsRequest>,
}

/// `GET /v1/settings` exposes owner-controlled settings without provider keys.
async fn settings_show(State(state): State<Arc<ApiState>>) -> Response {
    match crate::api::load_config_verified(&state.home) {
        Ok(config) => Json(serde_json::json!({
            "language": config.ui.language.code(),
            "memory": {"suggestions": config.memory.suggestions},
        }))
        .into_response(),
        Err(err) => internal_error("reading settings", &anyhow::Error::from(err)),
    }
}

/// `PUT /v1/settings` updates language and/or memory suggestions, preserving
/// provider settings and other extension keys in config.toml.
async fn settings_update(State(state): State<Arc<ApiState>>, body: Bytes) -> Response {
    let request: SettingsRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_settings",
                "expected language and/or memory.suggestions settings",
                None,
            )
        }
    };
    let language = match request.language.as_deref() {
        Some(raw) => match kernel_core::Lang::parse(raw) {
            Some(language) => Some(language),
            None => {
                return error::error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_language",
                    "language must be en or fr",
                    None,
                )
            }
        },
        None => None,
    };
    let suggestions = request.memory.and_then(|memory| memory.suggestions);
    if language.is_none() && suggestions.is_none() {
        return error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_settings",
            "expected language and/or memory.suggestions settings",
            None,
        );
    }
    let home = state.home.clone();
    let config_write = Arc::clone(&state.config_write);
    let result = tokio::task::spawn_blocking(move || {
        // The whole read-modify-write runs under the one shared config writer
        // lock, so a concurrent provider append cannot be silently dropped by
        // this atomic replacement (P2, #133).
        let _guard = config_write
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The file lock extends that serialization across processes (a CLI or
        // another writer in a different process): the read below must happen
        // inside it, never on a stale snapshot (security review P2).
        kernel_core::with_config_lock(&home, || {
            crate::api::load_config_verified(&home).map_err(|err| err.to_string())?;
            let handle = kernel_core::SandboxHome::open(&home).map_err(|err| err.to_string())?;
            let real = handle.real_path().map_err(|err| err.to_string())?;
            let path = real.join("config.toml");
            let original = std::fs::read_to_string(&path).map_err(|err| err.to_string())?;
            let mut value: toml::Value = toml::from_str(&original).map_err(|err| {
                kernel_core::redact_toml_error(&err, "config.toml", &original)
                    .message()
                    .to_string()
            })?;
            let root = value
                .as_table_mut()
                .ok_or_else(|| "config root must be a table".to_string())?;
            if let Some(language) = language {
                let ui = root
                    .entry("ui")
                    .or_insert_with(|| toml::Value::Table(Default::default()));
                ui.as_table_mut()
                    .ok_or_else(|| "ui must be a table".to_string())?
                    .insert(
                        "language".to_string(),
                        toml::Value::String(language.code().to_string()),
                    );
            }
            if let Some(suggestions) = suggestions {
                let memory = root
                    .entry("memory")
                    .or_insert_with(|| toml::Value::Table(Default::default()));
                memory
                    .as_table_mut()
                    .ok_or_else(|| "memory must be a table".to_string())?
                    .insert("suggestions".to_string(), toml::Value::Boolean(suggestions));
            }
            let updated = toml::to_string_pretty(&value).map_err(|err| err.to_string())?;
            let config: kernel_core::Config =
                toml::from_str(&updated).map_err(|err| err.to_string())?;
            handle
                .write_atomic(
                    std::path::Path::new("config.toml"),
                    updated.as_bytes(),
                    0o600,
                )
                .map_err(|err| err.to_string())?;
            Ok::<_, String>(config)
        })
        .map_err(|err| format!("acquiring the configuration lock: {err}"))?
    })
    .await;
    match result {
        Ok(Ok(config)) => Json(serde_json::json!({
            "language": config.ui.language.code(),
            "memory": {"suggestions": config.memory.suggestions},
        }))
        .into_response(),
        Ok(Err(err)) => internal_error("updating settings", &anyhow::anyhow!(err)),
        Err(err) => internal_error("joining the settings writer", &anyhow::Error::from(err)),
    }
}

async fn screen_not_implemented() -> Response {
    error::not_implemented("screen")
}

async fn audit_not_implemented() -> Response {
    error::not_implemented("audit replay")
}

async fn agents_write_not_implemented() -> Response {
    error::not_implemented("agent deletion")
}

#[cfg(test)]
mod skill_scope_tests {
    use super::*;
    use serde_json::json;

    fn pending(tool: &str) -> crate::api::PendingApproval {
        crate::api::PendingApproval {
            id: "ap-1".to_string(),
            audit_id: 1,
            agent: "assistant".to_string(),
            thread_id: 1,
            root_thread: None,
            tool: tool.to_string(),
            risk: kernel_broker::Risk::High,
            card_title: tool.to_string(),
            card_body: String::new(),
            card_detail: Vec::new(),
            edit_args: String::new(),
            taint: None,
            unsandboxed: false,
            networked: false,
            created_ms: 0,
        }
    }

    /// N7: a scoped answer to a skill card writes no `skill__<name>` rule; it is
    /// a one-time approval. A scoped answer to a plain tool still persists one.
    #[test]
    fn a_skill_card_answer_is_one_time_and_writes_no_rule() {
        let scope: ScopeJson = serde_json::from_value(json!({ "agent": "assistant" })).unwrap();
        let (always, rule) = allow_scope(&pending("skill__send-invite"), Some(&scope)).unwrap();
        assert!(!always, "a skill card is never always-allowed");
        assert!(rule.is_none(), "no skill allow rule is written");

        let (always, rule) = allow_scope(&pending("read_file"), Some(&scope)).unwrap();
        assert!(always);
        assert!(rule.is_some());
    }
}
