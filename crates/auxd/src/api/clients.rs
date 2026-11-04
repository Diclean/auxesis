//! The Clients destination.
//!
//! | Method | Path | Answer |
//! |---|---|---|
//! | GET | `/v1/clients` | the live parties, one summary row each |
//! | GET | `/v1/clients/{id}` | the card: identity, timeline, follow-ups, memory |
//! | PUT | `/v1/clients/{id}` | overwrite the party's identity; answers the card |
//! | DELETE | `/v1/clients/{id}/memory/{item}` | forget one memory line of the card |
//!
//! Every write goes through [`aux_crm::Crm`], whose store write refreshes the
//! `crm` contacts source in the same transaction, so an edited name or address
//! is tokenised in the next provider call (`docs/phase1.md` §2). These routes
//! sit behind the shared bearer-token middleware; they answer the owner's own
//! app on loopback, so the card carries real values. Nothing here logs a name,
//! an address or a number: refusals log the error kind only.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use super::error;
use super::ApiState;
use aux_crm::{Crm, CrmError, NewParty, Party, PartyKind};

/// The card shows the last 20 interactions (`docs/phase1.md` §5, `crm.get`).
const TIMELINE_LIMIT: usize = 20;

/// The clients routes, merged into the authenticated router.
pub fn routes() -> Router<Arc<ApiState>> {
    Router::new()
        .route("/v1/clients", get(list))
        .route("/v1/clients/{id}", get(card).put(update))
        .route("/v1/clients/{id}/memory/{item}", delete(forget_memory))
}

/// One row of the client list.
#[derive(Debug, Serialize)]
struct ClientRow {
    id: i64,
    kind: &'static str,
    display_name: String,
    emails: Vec<String>,
    phones: Vec<String>,
    tags: Vec<String>,
    updated_at: String,
    /// The earliest open follow-up, if any.
    next_followup: Option<FollowupView>,
    /// When the newest interaction happened, if any.
    last_interaction_at: Option<String>,
}

/// A party's identity as the card shows and edits it.
#[derive(Debug, Serialize)]
struct PartyView {
    id: i64,
    kind: &'static str,
    display_name: String,
    name_variants: Vec<String>,
    emails: Vec<String>,
    phones: Vec<String>,
    addresses: Vec<String>,
    tags: Vec<String>,
    notes: String,
    /// The client's own IANA zone, when the card carries one.
    time_zone: Option<String>,
    origin: String,
    created_at: String,
    updated_at: String,
}

/// One timeline row. The source reference stays in the store: it names
/// mailboxes and message ids the card has no use for.
#[derive(Debug, Serialize)]
struct InteractionView {
    id: i64,
    kind: String,
    at: String,
    summary: String,
    provenance: String,
    /// `in` or `out` for a mail row, `null` otherwise.
    direction: Option<String>,
    /// Written from outside content: the app shows the owner the real text,
    /// marked, while the model only ever sees a neutral placeholder.
    tainted: bool,
}

#[derive(Debug, Clone, Serialize)]
struct FollowupView {
    id: i64,
    due: String,
    reason: String,
    created_by: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct MemoryView {
    id: i64,
    title: String,
    body: String,
    source: String,
    updated_at: String,
}

/// `GET /v1/clients/{id}`.
#[derive(Debug, Serialize)]
struct ClientCard {
    party: PartyView,
    /// Newest first, at most [`TIMELINE_LIMIT`].
    timeline: Vec<InteractionView>,
    /// Open follow-ups, earliest due first.
    followups: Vec<FollowupView>,
    memory: Vec<MemoryView>,
}

/// `PUT /v1/clients/{id}`: the editable identity. The origin is the audit
/// trail of where a party came from, so an edit keeps it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    #[serde(default)]
    kind: Option<String>,
    display_name: String,
    #[serde(default)]
    name_variants: Vec<String>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    phones: Vec<String>,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    notes: String,
    /// Absent keeps the card's stored zone; an empty string clears it.
    #[serde(default)]
    time_zone: Option<String>,
}

/// Why a clients call failed, mapped to one HTTP answer.
enum Failure {
    NotFound,
    Invalid(String),
    Store,
}

impl From<CrmError> for Failure {
    fn from(err: CrmError) -> Self {
        match err {
            CrmError::PartyNotFound { .. } => Failure::NotFound,
            CrmError::Store(err) => err.into(),
            // The message names the value the owner typed; it goes back to
            // the owner's own app and is never logged.
            other => Failure::Invalid(other.to_string()),
        }
    }
}

impl From<aux_store::StoreError> for Failure {
    fn from(err: aux_store::StoreError) -> Self {
        tracing::warn!(error = %err, "a clients call failed in the store");
        Failure::Store
    }
}

impl Failure {
    fn response(self, code: &'static str) -> Response {
        match self {
            Failure::NotFound => error::error_response(
                StatusCode::NOT_FOUND,
                "client_not_found",
                "no client with this id",
                None,
            ),
            Failure::Invalid(message) => error::error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "client_invalid",
                message,
                None,
            ),
            Failure::Store => error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                code,
                "the client list could not be read or written",
                None,
            ),
        }
    }
}

/// Run `work` on the blocking pool over a freshly opened store and answer
/// its value as JSON, or the failure as an error body.
async fn with_store<T, F>(state: &ApiState, code: &'static str, work: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce(&aux_store::Store) -> Result<T, Failure> + Send + 'static,
{
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        let store = aux_store::Store::open(&db_path)?;
        work(&store)
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(failure)) => failure.response(code),
        Err(_) => {
            tracing::error!(code, "a clients task failed");
            Failure::Store.response(code)
        }
    }
}

/// `GET /v1/clients`: the live parties, by name.
async fn list(State(state): State<Arc<ApiState>>) -> Response {
    with_store(&state, "clients_list_failed", |store| {
        let mut parties = Crm::new(store).list()?;
        parties.sort_by_key(|party| party.display_name.to_lowercase());
        parties
            .into_iter()
            .map(|party| {
                let next_followup = open_followups(store, party.id)?.into_iter().next();
                let interactions = store.interactions_for_party(party.id)?;
                // An old row's `at` may be model text: a non-time becomes the
                // store's clock before it reaches the app (CRM-TAINT-AT).
                let last_interaction_at = aux_crm::latest_contact_at(&interactions)
                    .map(|at| aux_crm::safe_interaction_at(store, &at));
                Ok(ClientRow {
                    id: party.id,
                    kind: party.kind.as_str(),
                    display_name: party.display_name,
                    emails: party.emails,
                    phones: party.phones,
                    tags: party.tags,
                    updated_at: party.updated_at,
                    next_followup,
                    last_interaction_at,
                })
            })
            .collect::<Result<Vec<_>, Failure>>()
    })
    .await
}

/// `GET /v1/clients/{id}`: one live party's card.
async fn card(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return Failure::NotFound.response("clients_card_failed");
    };
    with_store(&state, "clients_card_failed", move |store| {
        let party = live_party(store, id)?;
        build_card(store, party)
    })
    .await
}

/// `PUT /v1/clients/{id}`: overwrite the identity of a live party.
async fn update(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(id) = parse_id(&id) else {
        return Failure::NotFound.response("clients_update_failed");
    };
    let Ok(body) = body else {
        return invalid_body();
    };
    let Ok(request) = serde_json::from_slice::<UpdateRequest>(&body) else {
        return invalid_body();
    };
    let kind = match request.kind.as_deref() {
        None => None,
        Some(raw) => match PartyKind::parse(raw) {
            Some(kind) => Some(kind),
            None => return invalid_body(),
        },
    };
    with_store(&state, "clients_update_failed", move |store| {
        let crm = Crm::new(store);
        let current = live_party(store, id)?;
        // The editor does not show the zone: an absent field keeps the card's,
        // and an explicit empty string clears it.
        let time_zone = match request.time_zone {
            None => current.time_zone.clone(),
            Some(raw) if raw.trim().is_empty() => None,
            Some(raw) => Some(raw),
        };
        let draft = NewParty {
            kind: kind.unwrap_or(current.kind),
            display_name: request.display_name,
            name_variants: request.name_variants,
            emails: request.emails,
            phones: request.phones,
            addresses: request.addresses,
            tags: request.tags,
            notes: request.notes,
            time_zone,
            origin: current.origin,
        };
        let party = crm.update(id, draft)?;
        store.log_event(
            "crm.party_updated",
            &format!("{{\"id\":{id},\"by\":\"owner\"}}"),
        )?;
        build_card(store, party)
    })
    .await
}

/// `DELETE /v1/clients/{id}/memory/{item}`: forget one memory line.
async fn forget_memory(
    State(state): State<Arc<ApiState>>,
    Path((id, item)): Path<(String, String)>,
) -> Response {
    let (Some(id), Some(item)) = (parse_id(&id), parse_id(&item)) else {
        return Failure::NotFound.response("clients_forget_failed");
    };
    with_store(&state, "clients_forget_failed", move |store| {
        live_party(store, id)?;
        if store.forget_party_memory_item(id, item)? {
            Ok(serde_json::json!({ "forgotten": true }))
        } else {
            Err(Failure::NotFound)
        }
    })
    .await
}

fn parse_id(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|id| *id > 0)
}

fn invalid_body() -> Response {
    error::error_response(
        StatusCode::BAD_REQUEST,
        "invalid_body",
        "expected {display_name, name_variants, emails, phones, addresses, tags, notes, time_zone}",
        None,
    )
}

/// A live party, or not found. An archived party has no card.
fn live_party(store: &aux_store::Store, id: i64) -> Result<Party, Failure> {
    match Crm::new(store).get(id)? {
        Some(party) if !party.archived => Ok(party),
        _ => Err(Failure::NotFound),
    }
}

fn open_followups(store: &aux_store::Store, id: i64) -> Result<Vec<FollowupView>, Failure> {
    Ok(store
        .followups_for_party(id)?
        .into_iter()
        .filter(|followup| followup.status == "open")
        .map(|followup| FollowupView {
            id: followup.id,
            due: followup.due,
            reason: followup.reason,
            created_by: followup.created_by,
            status: followup.status,
        })
        .collect())
}

fn build_card(store: &aux_store::Store, party: Party) -> Result<ClientCard, Failure> {
    let mut timeline: Vec<InteractionView> = store
        .interactions_for_party(party.id)?
        .into_iter()
        .map(|interaction| InteractionView {
            id: interaction.id,
            kind: interaction.kind,
            at: aux_crm::safe_interaction_at(store, &interaction.at),
            summary: interaction.summary,
            provenance: interaction.provenance,
            direction: interaction.direction,
            tainted: interaction.tainted,
        })
        .collect();
    timeline.reverse();
    timeline.truncate(TIMELINE_LIMIT);
    let followups = open_followups(store, party.id)?;
    let memory = store
        .memory_items_for_party_card(party.id)?
        .into_iter()
        .map(|item| MemoryView {
            id: item.id,
            title: item.title,
            body: item.body,
            source: item.source,
            updated_at: item.updated_at,
        })
        .collect();
    Ok(ClientCard {
        party: PartyView {
            id: party.id,
            kind: party.kind.as_str(),
            display_name: party.display_name,
            name_variants: party.name_variants,
            emails: party.emails,
            phones: party.phones,
            addresses: party.addresses,
            tags: party.tags,
            notes: party.notes,
            time_zone: party
                .time_zone
                .and_then(|zone| aux_crm::valid_time_zone(&zone)),
            origin: party.origin,
            created_at: party.created_at,
            updated_at: party.updated_at,
        },
        timeline,
        followups,
        memory,
    })
}
