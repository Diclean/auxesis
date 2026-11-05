//! Agent writes: create, update, pause/resume/kill and stop-all (B-API v3).
//!
//! Every handler is a real write over the same artifacts the engine reads:
//! the agent directory, `soul.md` (the instructions the system prompt embeds),
//! the `agent.toml` sidecar (provider/model/tools ceiling) and the
//! `PAUSED`/`KILLED` markers. Nothing here can grant a right the config did
//! not already have: provider/model are chosen among the `[[providers]]`
//! entries, the tools list can only *restrict* (the turn path denies every
//! registered tool it omits), and the shell stays governed by `[shell]`.
//!
//! `soul.md` is the owner's trusted text and has exactly one writer,
//! [`agent::write_soul`] — the atomic, fd-relative, `O_NOFOLLOW` gateway used
//! by both create and update. No model and no tool can reach it here; the only
//! read that exposes it whole is `GET /v1/agents/{id}/soul`, bounded by
//! [`MAX_SOUL_BYTES`].
//!
//! Every successful write is audited (`agent.created`, `agent.updated`,
//! `agent.paused`, `agent.resumed`, `agent.killed`, `daemon.stop_all`), which also
//! publishes it on the WebSocket through the journal poller. Payloads carry
//! field names and ids only — never instructions or key material.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use aux_engine::MAX_SOUL_BYTES;
use aux_providers::{provider_name_is_key_shaped, shown_id_plain, KEY_SHAPED_PROVIDER_NAME};
use kernel_core::{config_path, killswitch};

use super::error;
use super::routes::read_body;
use super::ApiState;
use crate::agent::{self, AgentConfig, AgentState};

/// Longest accepted model id.
const MAX_MODEL_CHARS: usize = 200;

/// Most tools one agent may list.
const MAX_TOOLS: usize = 24;

/// How long a create waits for the winner of a same-name race to finish
/// writing its files before answering "already exists".
const RACE_READ_TIMEOUT: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// request / response shapes
// ---------------------------------------------------------------------------

/// One entry of the `tools` allowlist: a bare name, or the app's grant shape
/// (`{tool, granted}`; `granted: false` leaves the tool out).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ToolEntry {
    /// `"read_file"`.
    Name(String),
    /// `{"tool":"read_file","granted":true,...}`.
    Grant {
        /// Tool name.
        tool: String,
        /// Whether the owner granted it (default true).
        #[serde(default = "default_true")]
        granted: bool,
    },
}

fn default_true() -> bool {
    true
}

/// `POST /v1/agents` body. `role`, `instructions` and `soul_md` are aliases.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CreateAgentRequest {
    /// Template id (`mail`, `calendar`, `clients`, `documents`); the agent
    /// takes the template's id, grants and shipped files.
    pub template: Option<String>,
    /// Agent name (also its identity and directory name).
    pub name: Option<String>,
    /// Instructions written to `soul.md`.
    pub role: Option<String>,
    /// Alias for `role`.
    pub instructions: Option<String>,
    /// Alias for `role` (the app's soul editor field).
    pub soul_md: Option<String>,
    /// Provider id from `[[providers]]`.
    pub provider: Option<String>,
    /// Model id for that provider.
    pub model: Option<String>,
    /// Tools this agent may use (empty list = none).
    pub tools: Option<Vec<ToolEntry>>,
}

/// `PUT`/`PATCH /v1/agents/{id}` body. Absent fields are unchanged; an explicit
/// `null` (or empty string) clears `provider`/`model`/`tools`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct UpdateAgentRequest {
    /// Must equal the path id when present: agents are not renamed.
    pub name: Option<String>,
    /// New instructions; empty resets to the daemon default.
    pub role: Option<String>,
    /// Alias for `role`.
    pub instructions: Option<String>,
    /// Alias for `role`.
    pub soul_md: Option<String>,
    /// New provider id; `null` clears it.
    #[serde(default, deserialize_with = "double_option")]
    pub provider: Option<Option<String>>,
    /// New model; `null` clears it.
    #[serde(default, deserialize_with = "double_option")]
    pub model: Option<Option<String>>,
    /// New tools allowlist; `null` clears it.
    #[serde(default, deserialize_with = "double_option")]
    pub tools: Option<Option<Vec<ToolEntry>>>,
    /// Local instruction skills selected for this agent.
    pub skills: Option<Vec<String>>,
}

/// Distinguish an absent field (`None`) from an explicit `null`
/// (`Some(None)`) — serde alone maps both to `None`.
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// One agent as the write endpoints answer it.
#[derive(Debug, Serialize)]
pub struct AgentJson {
    /// Agent name.
    pub name: String,
    /// Provider id, when one is set.
    pub provider: Option<String>,
    /// Model override, when one is set.
    pub model: Option<String>,
    /// Tools allowlist; `null` = global rules apply.
    pub tools: Option<Vec<String>>,
    /// Local instruction skills selected for this agent.
    pub skills: Vec<String>,
    /// `PAUSED` marker present.
    pub paused: bool,
    /// `KILLED` marker present.
    pub killed: bool,
}

impl AgentJson {
    pub(crate) fn of(home: &Path, name: &str, config: &AgentConfig) -> Self {
        let state = agent::state(home, name);
        Self {
            name: name.to_string(),
            provider: config
                .provider
                .clone()
                .filter(|provider| !provider_name_is_key_shaped(provider)),
            model: config.model.clone(),
            tools: config.tools.clone(),
            skills: config.skills.clone(),
            paused: matches!(state, AgentState::Paused | AgentState::Killed),
            killed: matches!(state, AgentState::Killed),
        }
    }
}

/// A pause/resume/kill answer.
#[derive(Debug, Serialize)]
pub struct ControlJson {
    /// Agent name.
    pub name: String,
    /// `PAUSED` marker present after the call.
    pub paused: bool,
    /// `KILLED` marker present after the call.
    pub killed: bool,
    /// Whether this call changed the marker state.
    pub changed: bool,
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

/// `GET /v1/agent-templates`: the starter agents the owner can create, with
/// the grants each would get and whether it already exists.
pub async fn templates(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let list = tokio::task::spawn_blocking(move || {
        let ids = aux_runtime::grants::DOMAIN_AGENTS;
        let json = |def: crate::agents::AgentDef| {
            serde_json::json!({
                "id": def.id,
                "name": def.name,
                "glyph": def.glyph,
                "grants": crate::agents::grants_json(&def.grants),
                "created": agent::exists(&home, &def.id),
            })
        };
        ids.iter()
            .filter_map(|id| crate::agents::template(id))
            .map(json)
            .collect::<Vec<_>>()
    })
    .await;
    match list {
        Ok(items) => Json(serde_json::json!({ "templates": items })).into_response(),
        Err(_) => internal_error(),
    }
}

/// `POST /v1/agents`.
#[allow(clippy::result_large_err)]
pub async fn create(
    State(state): State<Arc<ApiState>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: CreateAgentRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "the request body must be a JSON object with a `name` string",
                None,
            )
        }
    };
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    match tokio::task::spawn_blocking(move || create_sync(&home, &db_path, request)).await {
        Ok(Ok((status, json))) => (status, Json(json)).into_response(),
        Ok(Err(response)) => response,
        Err(_) => internal_error(),
    }
}

/// `PUT`/`PATCH /v1/agents/{id}`.
#[allow(clippy::result_large_err)]
pub async fn update(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: UpdateAgentRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "the request body must be a JSON object with the fields to change",
                None,
            )
        }
    };
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    match tokio::task::spawn_blocking(move || update_sync(&home, &db_path, &id, request)).await {
        Ok(Ok(json)) => Json(json).into_response(),
        Ok(Err(response)) => response,
        Err(_) => internal_error(),
    }
}

/// `GET /v1/agents/{id}/soul`.
///
/// The owner's own trusted text, whole: this is the read the personality
/// editor round-trips, so it is deliberately **not** the scrubbed/capped
/// `instructions` preview that `GET /v1/agents/{id}` shows. Authenticated like
/// every other route (bearer token + loopback Host/Origin middleware) and
/// bounded by [`MAX_SOUL_BYTES`]; it only ever reads the caller's own home.
#[allow(clippy::result_large_err)]
pub async fn soul_show(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || soul_sync(&home, &id)).await {
        Ok(Ok(json)) => Json(json).into_response(),
        Ok(Err(response)) => response,
        Err(_) => internal_error(),
    }
}

/// Read one agent's personality for its editor.
///
/// `is_default` is true when no file exists yet (the engine would then use
/// its built-in default): the app shows that text and an explicit save writes
/// the first real file. A present-but-unusable file is refused (see
/// [`agent::read_soul_for_edit`]) so a truncated soul is never shown, and
/// therefore never saved over the original.
#[allow(clippy::result_large_err)]
pub(crate) fn soul_sync(home: &Path, id: &str) -> Result<serde_json::Value, Response> {
    if let Err(err) = aux_engine::validate_agent(id) {
        return Err(super::routes::invalid_agent(id, &err.to_string()));
    }
    if !agent::exists(home, id) {
        return Err(agent_not_found(home, id));
    }
    let (text, is_default) = match agent::read_soul_for_edit(home, id) {
        Ok(Some(text)) => (text, false),
        Ok(None) => (agent::default_instructions(id), true),
        Err(err) => {
            tracing::warn!(agent = %id, error = %err, "reading an agent personality failed");
            return Err(error::error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "soul_unreadable",
                "this agent's personality file cannot be read",
                Some("fix or remove the agent's personality file, then try again"),
            ));
        }
    };
    Ok(serde_json::json!({
        "soul_md": text,
        "max_bytes": MAX_SOUL_BYTES,
        "is_default": is_default,
    }))
}

/// `POST /v1/agents/{id}/pause`.
pub async fn pause(State(state): State<Arc<ApiState>>, AxumPath(id): AxumPath<String>) -> Response {
    control(&state, &id, ControlAction::Pause).await
}

/// `POST /v1/agents/{id}/resume` (clears `PAUSED` and `KILLED`).
pub async fn resume(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    control(&state, &id, ControlAction::Resume).await
}

/// `POST /v1/agents/{id}/kill`.
pub async fn kill(State(state): State<Arc<ApiState>>, AxumPath(id): AxumPath<String>) -> Response {
    control(&state, &id, ControlAction::Kill).await
}

/// `POST /v1/stop-all`: engage the one kill switch every turn and job honors.
pub async fn stop_all(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let turn_cancels = Arc::clone(&state.turn_cancels);
    let delegation_cancels = Arc::clone(&state.delegation_cancels);
    let pending_sends = state.approvals.pending().len();
    let result = tokio::task::spawn_blocking(move || -> Result<(bool, usize), String> {
        let was_stopped = killswitch::is_stopped(&home);
        killswitch::engage(&home).map_err(|err| err.to_string())?;
        // B-API v3 × E-18: stop-all also fires the cancellation tokens of
        // every in-flight turn, so they abort now (the shell tool reaps its
        // process tree, pending approvals are retired) instead of waiting for
        // the next engine step boundary.
        turn_cancels.cancel_all();
        // D33: Stop all also aborts every running child turn, keeping each
        // task's partial steps so its row can offer Resume.
        delegation_cancels.cancel_all();
        // partial steps so its row can offer Resume.
        let stopped_delegations = match aux_store::Store::open(&db_path) {
            Ok(store) => store.stop_open_delegations().unwrap_or(0),
            Err(_) => 0,
        };
        let changed = !was_stopped;
        if changed {
            audit(
                &db_path,
                "daemon.stop_all",
                serde_json::json!({
                    "by": "owner-api",
                    "changed": changed,
                    "stopped_delegations": stopped_delegations,
                }),
            );
        }
        Ok((changed, stopped_delegations))
    })
    .await;
    match result {
        Ok(Ok((changed, stopped_delegations))) => {
            let cancelled = stopped_delegations + pending_sends;
            state
                .stop_cancelled
                .store(cancelled, std::sync::atomic::Ordering::Relaxed);
            let _ = crate::api::wire::send_bounded(
                &state.events,
                &crate::delegation::stop_changed_frame(true, None, cancelled),
            );
            Json(serde_json::json!({
                "stop": true,
                "changed": changed,
                "cancelled_sends": cancelled,
            }))
            .into_response()
        }
        Ok(Err(err)) => {
            tracing::error!(error = %err, "engaging the kill switch failed");
            internal_error()
        }
        Err(_) => internal_error(),
    }
}

// ---------------------------------------------------------------------------
// create / update
// ---------------------------------------------------------------------------

#[allow(clippy::result_large_err)]
pub(crate) fn create_sync(
    home: &Path,
    db_path: &Path,
    mut request: CreateAgentRequest,
) -> Result<(StatusCode, serde_json::Value), Response> {
    let _guard = kernel_core::lock_recover(crate::agents::grants_lock());
    let template = request.template.take();
    if let Some(id) = &template {
        let refuse =
            |code, message| error::error_response(StatusCode::BAD_REQUEST, code, message, None);
        let def = crate::agents::template(id)
            .ok_or_else(|| refuse("unknown_template", "there is no such agent template"))?;
        if request.name.as_deref().is_some_and(|name| name != def.id) {
            return Err(refuse(
                "invalid_name",
                "an agent made from a template keeps its id",
            ));
        }
        crate::agents::validate_grants(home, &def.id, &def.grants).map_err(|err| match err {
            crate::agents::RegistryError::ExceedsChief => crate::agents::exceeds_chief(),
            _ => internal_error(),
        })?;
        // Its shipped `agent.md` lists tools: the same ceiling as a request.
        validate_tool_ceiling(home, &def.id, &crate::agents::shipped_tools(&def.id))?;
        request.name = Some(def.id);
    }
    let validated = validate_create(home, request)?;
    let name = &validated.name;
    // A template's id without `template` (any case) still gets the template's
    // grants from the registry, so it passes the same ceiling check.
    if template.is_none() {
        if let Some(def) = crate::agents::template(&name.to_ascii_lowercase()) {
            crate::agents::validate_grants(home, &def.id, &def.grants).map_err(
                |err| match err {
                    crate::agents::RegistryError::ExceedsChief => crate::agents::exceeds_chief(),
                    _ => internal_error(),
                },
            )?;
            validate_tool_ceiling(home, &def.id, &crate::agents::shipped_tools(&def.id))?;
        }
    }
    let requested = validated.config.tools.as_deref().unwrap_or_default();
    validate_tool_ceiling(home, name, requested)?;
    let expected_soul = validated
        .instructions
        .clone()
        .unwrap_or_else(|| agent::default_instructions(name));

    if agent::claim_dir(home, name).map_err(|err| agent_write_failed(&err.to_string()))? {
        // We created the directory: write the real artifacts. A failure
        // leaves nothing behind (the directory is abandoned).
        let write = agent::write_soul(home, name, &expected_soul)
            .and_then(|()| agent::write_config(home, name, &validated.config));
        // A template agent and the chief get their shipped files (skills).
        let shipped = template.is_some() || name == aux_runtime::grants::CHIEF_AGENT;
        let write = write.and_then(|()| {
            if !shipped {
                return Ok(());
            }
            crate::agents::install_shipped_files_for(home, Some(name))
                .map(drop)
                .map_err(|err| agent::AgentError::Io(err.to_string()))
        });
        if let Err(err) = write {
            agent::abandon_dir(home, name);
            return Err(agent_write_failed(&err.to_string()));
        }
        audit(
            db_path,
            "agent.created",
            serde_json::json!({
                "agent": name,
                "provider": validated.config.provider.as_deref().map(shown_id_plain),
                "model": validated.config.model.as_deref().map(shown_id_plain),
                "tools": &validated.config.tools,
                "by": "owner-api",
            }),
        );
        let json = AgentJson::of(home, name, &validated.config);
        return Ok((
            StatusCode::CREATED,
            serde_json::json!({ "agent": json, "created": true }),
        ));
    }

    // The name is taken: identical request → idempotent success; anything
    // else is a conflict. Wait briefly so the winner of a concurrent create
    // can finish writing before we compare.
    let deadline = std::time::Instant::now() + RACE_READ_TIMEOUT;
    loop {
        // A corrupt sidecar or a non-directory entry is never papered over.
        let existing_config = match agent::config(home, name) {
            Ok(config) if agent::exists(home, name) => config,
            _ => {
                return Err(error::error_response(
                    StatusCode::CONFLICT,
                    "agent_exists",
                    format!(
                        "an agent called `{}` already exists",
                        error::sanitize_detail(home, name)
                    ),
                    Some("choose another name, or update the existing agent"),
                ));
            }
        };
        let existing_soul =
            agent::read_soul(home, name).unwrap_or_else(|| agent::default_instructions(name));
        if existing_config == validated.config && existing_soul == expected_soul {
            let json = AgentJson::of(home, name, &existing_config);
            return Ok((
                StatusCode::OK,
                serde_json::json!({ "agent": json, "created": false }),
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(error::error_response(
                StatusCode::CONFLICT,
                "agent_exists",
                format!(
                    "an agent called `{}` already exists",
                    error::sanitize_detail(home, name)
                ),
                Some("choose another name, or update the existing agent"),
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[allow(clippy::result_large_err)]
fn update_sync(
    home: &Path,
    db_path: &Path,
    id: &str,
    request: UpdateAgentRequest,
) -> Result<serde_json::Value, Response> {
    if let Err(err) = aux_engine::validate_agent(id) {
        return Err(super::routes::invalid_agent(id, &err.to_string()));
    }
    if let Some(name) = request.name.as_deref() {
        if name != id {
            return Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_name",
                "an agent cannot be renamed: its name is its identity",
                Some("create a new agent instead"),
            ));
        }
    }
    if !agent::exists(home, id) {
        return Err(agent_not_found(home, id));
    }

    let instructions = instructions_of(
        request.role.as_deref(),
        request.instructions.as_deref(),
        request.soul_md.as_deref(),
    )?;
    // The ceiling check and the write it allows, as one step (as a create).
    let _guard = kernel_core::lock_recover(crate::agents::grants_lock());
    let mut config = agent::config(home, id).map_err(|err| agent_write_failed(&err.to_string()))?;
    let mut fields: Vec<&str> = Vec::new();

    // Provider / model: absent = keep, null or empty = clear.
    if let Some(provider) = request.provider {
        let next = provider
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if let Some(id) = &next {
            if let Some(response) = key_shaped_provider(id) {
                return Err(response);
            }
            let configured = load_configured(home)?;
            if !configured.iter().any(|entry| entry.id == *id) {
                return Err(unknown_provider(home, id, &configured));
            }
        }
        if next != config.provider {
            fields.push("provider");
            config.provider = next;
        }
    }
    if let Some(model) = request.model {
        let next = model
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if let Some(model) = &next {
            if model.chars().count() > MAX_MODEL_CHARS {
                return Err(invalid_model(home));
            }
        }
        if next != config.model {
            fields.push("model");
            config.model = next;
        }
    }
    if let Some(tools) = request.tools {
        let next = match tools {
            None => None,
            Some(entries) => Some(validate_tools(home, entries)?),
        };
        if next != config.tools {
            fields.push("tools");
            config.tools = next;
        }
    }
    if let Some(skills) = request.skills {
        let next = validate_skills(home, skills)?;
        if next != config.skills {
            fields.push("skills");
            config.skills = next;
        }
    }
    validate_effective_selection(home, &config)?;
    validate_tool_ceiling(home, id, config.tools.as_deref().unwrap_or_default())?;

    if let Some(instructions) = &instructions {
        let text = if instructions.trim().is_empty() {
            agent::default_instructions(id)
        } else {
            instructions.clone()
        };
        agent::write_soul(home, id, &text).map_err(|err| agent_write_failed(&err.to_string()))?;
        fields.push("role");
    }
    if !fields.is_empty()
        && (fields.contains(&"provider")
            || fields.contains(&"model")
            || fields.contains(&"tools")
            || fields.contains(&"skills"))
    {
        agent::write_config(home, id, &config)
            .map_err(|err| agent_write_failed(&err.to_string()))?;
    }
    if fields.is_empty() {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "empty_update",
            "nothing to update",
            Some("send at least one of `role`, `provider`, `model`, `tools` or `skills`"),
        ));
    }
    audit(
        db_path,
        "agent.updated",
        serde_json::json!({ "agent": id, "fields": fields, "by": "owner-api" }),
    );
    Ok(serde_json::json!({
        "agent": AgentJson::of(home, id, &config),
        "changed": true,
    }))
}

/// Validate a create request and normalize it.
struct ValidatedCreate {
    name: String,
    instructions: Option<String>,
    config: AgentConfig,
}

#[allow(clippy::result_large_err)]
fn validate_create(home: &Path, request: CreateAgentRequest) -> Result<ValidatedCreate, Response> {
    let raw_name = request.name.as_deref().unwrap_or("").trim();
    if raw_name.is_empty() {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "missing_name",
            "`name` is required",
            Some("letters, digits, `-`, `_` and `.` (max 64 characters)"),
        ));
    }
    if let Err(err) = aux_engine::validate_agent(raw_name) {
        return Err(error::error_response_with_detail(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "this agent name cannot be used",
            error::sanitize_detail(home, &err.to_string()),
        ));
    }
    let instructions = instructions_of(
        request.role.as_deref(),
        request.instructions.as_deref(),
        request.soul_md.as_deref(),
    )?;
    let config = validate_selection(home, request.provider, request.model, request.tools)?;
    Ok(ValidatedCreate {
        name: raw_name.to_string(),
        instructions,
        config,
    })
}

/// Merge and validate provider/model/tools against the configured entries
/// and the registered tools.
#[allow(clippy::result_large_err)]
fn validate_selection(
    home: &Path,
    provider: Option<String>,
    model: Option<String>,
    tools: Option<Vec<ToolEntry>>,
) -> Result<AgentConfig, Response> {
    let provider = provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if let Some(id) = &provider {
        if let Some(response) = key_shaped_provider(id) {
            return Err(response);
        }
        let configured = load_configured(home)?;
        if !configured.iter().any(|entry| entry.id == *id) {
            return Err(unknown_provider(home, id, &configured));
        }
    }
    let model = model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    if let Some(model) = &model {
        if model.chars().count() > MAX_MODEL_CHARS {
            return Err(invalid_model(home));
        }
    }
    let config = AgentConfig {
        provider,
        model,
        tools: match tools {
            Some(entries) => Some(validate_tools(home, entries)?),
            None => None,
        },
        skills: Vec::new(),
    };
    validate_effective_selection(home, &config)?;
    Ok(config)
}

/// A tools list names only tools the chief may use (its
/// grants, its own tools list, the config rules that deny it). The run-time
/// ceiling enforces the same every turn; this refuses early with a clear
/// error. The chief is the one this home runs: on an older install an added
/// agent stays under `aux` as well as under `main` ([`crate::agents::ceilings`]).
#[allow(clippy::result_large_err)]
fn validate_tool_ceiling(home: &Path, id: &str, tools: &[String]) -> Result<(), Response> {
    let caps = crate::agents::ceilings(home, id);
    if caps.is_empty() || tools.is_empty() {
        return Ok(());
    }
    let agents = crate::agents::registry(home).map_err(|_| internal_error())?;
    let path = config_path(home);
    let rules = if path.exists() {
        aux_engine::config::load_rules(&path).map_err(|_| internal_error())?
    } else {
        Vec::new()
    };
    for cap in caps {
        let chief = crate::agents::ceiling_grants(&agents, cap);
        agent::config(home, cap).map_err(|_| internal_error())?;
        // Both of the chief's lists, as the run-time ceiling reads them.
        let chief_lists = super::turn::tool_lists(home, cap);
        let refused = tools.iter().any(|tool| {
            // An agent file names `mail.send`; rules and grants see `mail_send`.
            let wire = aux_runtime::skills::tool_map::wire_name(tool);
            let tool = wire.as_deref().unwrap_or(tool);
            // Every rule, matched as the broker matches it: an `agent = "*"`
            // rule is the chief's too, and the last match wins.
            let denied = kernel_broker::matching_rule(&rules, cap, tool, false)
                .is_some_and(|(_, rule)| rule.action == kernel_broker::Action::Deny);
            denied
                || chief.check_tool(cap, tool).is_err()
                || !chief_lists
                    .iter()
                    .all(|list| super::turn::listed(list, tool))
        });
        if refused {
            return Err(crate::agents::exceeds_chief());
        }
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_skills(home: &Path, names: Vec<String>) -> Result<Vec<String>, Response> {
    if names.len() > 32 {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "too_many_skills",
            "too many skills are selected",
            Some("choose up to 32 skills"),
        ));
    }
    let mut unique = Vec::new();
    for name in names {
        if let Err(reason) = aux_engine::skills::validate_name(&name) {
            return Err(error::error_response_with_detail(
                StatusCode::BAD_REQUEST,
                "invalid_skill_name",
                "this skill name cannot be used",
                error::sanitize_detail(home, &reason),
            ));
        }
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    if let Err(reason) = aux_engine::load_active_skills(home, &unique) {
        return Err(error::error_response_with_detail(
            StatusCode::BAD_REQUEST,
            "invalid_skills",
            "one or more skills cannot be activated",
            error::sanitize_detail(home, &reason),
        ));
    }
    Ok(unique)
}

/// A model with no provider only makes sense when the daemon has exactly one
/// provider to fall back on; say so at write time instead of failing a turn.
#[allow(clippy::result_large_err)]
fn validate_effective_selection(home: &Path, config: &AgentConfig) -> Result<(), Response> {
    if config.model.is_none() || config.provider.is_some() {
        return Ok(());
    }
    let configured = load_configured(home)?;
    if configured.len() == 1 {
        return Ok(());
    }
    Err(error::error_response(
        StatusCode::BAD_REQUEST,
        "ambiguous_provider",
        if configured.is_empty() {
            "no AI service is configured yet, so a model cannot be attached"
        } else {
            "several AI services are configured; choose one with `provider`"
        },
        Some("see GET /v1/providers for the configured services"),
    ))
}

#[allow(clippy::result_large_err)]
fn load_configured(home: &Path) -> Result<Vec<aux_providers::ProviderConfig>, Response> {
    let config_file = config_path(home);
    if !config_file.exists() {
        return Ok(Vec::new());
    }
    aux_providers::load_providers(&config_file).map_err(|err| {
        error::error_response_with_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_invalid",
            "the provider configuration could not be read",
            error::sanitize_detail(home, &err.to_string()),
        )
    })
}

/// Normalize the tools allowlist: names only, deduplicated in order, every
/// name a tool this daemon actually has.
#[allow(clippy::result_large_err)]
fn validate_tools(home: &Path, entries: Vec<ToolEntry>) -> Result<Vec<String>, Response> {
    if entries.len() > MAX_TOOLS {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_tools",
            format!("at most {MAX_TOOLS} tools may be listed"),
            None,
        ));
    }
    let names: Vec<String> = match crate::api::load_config_verified(home) {
        Ok(config) => aux_engine::registry_from_config(&config)
            .names()
            .into_iter()
            .map(str::to_string)
            .collect(),
        Err(err) => {
            return Err(error::error_response_with_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "config_invalid",
                "the tool configuration could not be read",
                error::sanitize_detail(home, &err.to_string()),
            ));
        }
    };
    let available: Vec<&str> = names.iter().map(String::as_str).collect();
    let mut tools: Vec<String> = Vec::new();
    for entry in entries {
        let (name, granted) = match entry {
            ToolEntry::Name(name) => (name, true),
            ToolEntry::Grant { tool, granted } => (tool, granted),
        };
        let name = name.trim();
        if !granted {
            continue;
        }
        if name.is_empty() {
            return Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_tools",
                "a tool name cannot be empty",
                None,
            ));
        }
        if !available.contains(&name) {
            return Err(error::error_response_with_detail(
                StatusCode::BAD_REQUEST,
                "unknown_tool",
                format!(
                    "`{}` is not a tool of this daemon",
                    error::sanitize_detail(home, name)
                ),
                format!(
                    "available: {}",
                    error::sanitize_detail(home, &available.join(", "))
                ),
            ));
        }
        if !tools.iter().any(|known| known == name) {
            tools.push(name.to_string());
        }
    }
    Ok(tools)
}

/// Resolve the three instructions aliases: at most one value, empty means
/// "not provided" on create and "reset to default" on update.
#[allow(clippy::result_large_err)]
fn instructions_of(
    role: Option<&str>,
    instructions: Option<&str>,
    soul_md: Option<&str>,
) -> Result<Option<String>, Response> {
    let provided: Vec<&str> = [role, instructions, soul_md]
        .into_iter()
        .flatten()
        .collect();
    if provided.is_empty() {
        return Ok(None);
    }
    let first = provided[0];
    if provided[1..].iter().any(|other| *other != first) {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "conflicting_fields",
            "`role`, `instructions` and `soul_md` are aliases; send only one of them",
            None,
        ));
    }
    Ok(Some(first.to_string()))
}

/// Refuse a provider id that reads as a key: provider ids are names, never
/// credentials. The refusal never echoes the id.
fn key_shaped_provider(id: &str) -> Option<Response> {
    provider_name_is_key_shaped(id).then(|| {
        error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_provider",
            KEY_SHAPED_PROVIDER_NAME,
            None,
        )
    })
}

fn unknown_provider(
    home: &Path,
    id: &str,
    configured: &[aux_providers::ProviderConfig],
) -> Response {
    let available = if configured.is_empty() {
        "none".to_string()
    } else {
        configured
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    error::error_response_with_detail(
        StatusCode::BAD_REQUEST,
        "unknown_provider",
        format!(
            "there is no AI service called `{}` configured",
            error::sanitize_detail(home, id)
        ),
        format!("available: {available}"),
    )
}

fn invalid_model(_home: &Path) -> Response {
    error::error_response(
        StatusCode::BAD_REQUEST,
        "invalid_model",
        format!("the model id is too long (max {MAX_MODEL_CHARS} characters)"),
        None,
    )
}

fn agent_not_found(home: &Path, id: &str) -> Response {
    error::error_response(
        StatusCode::NOT_FOUND,
        "agent_not_found",
        format!("no agent called `{}`", error::sanitize_detail(home, id)),
        Some("see GET /v1/agents"),
    )
}

// ---------------------------------------------------------------------------
// pause / resume / kill
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum ControlAction {
    Pause,
    Resume,
    Kill,
}

#[allow(clippy::result_large_err)]
async fn control(state: &Arc<ApiState>, id: &str, action: ControlAction) -> Response {
    if let Err(err) = aux_engine::validate_agent(id) {
        return super::routes::invalid_agent(id, &err.to_string());
    }
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let turn_cancels = Arc::clone(&state.turn_cancels);
    let id = id.to_string();
    let result = tokio::task::spawn_blocking(move || -> Result<ControlJson, Response> {
        if !agent::exists(&home, &id) {
            return Err(agent_not_found(&home, &id));
        }
        let before = agent::state(&home, &id);
        let changed = match action {
            ControlAction::Pause => {
                if before == AgentState::Killed {
                    return Err(error::error_response(
                        StatusCode::CONFLICT,
                        "agent_killed",
                        "this agent is stopped; resume it before pausing",
                        None,
                    ));
                }
                agent::set_marker(&home, &id, agent::PAUSED_MARKER)
                    .map_err(|err| agent_write_failed(&err.to_string()))?
            }
            ControlAction::Kill => agent::set_marker(&home, &id, agent::KILLED_MARKER)
                .map_err(|err| agent_write_failed(&err.to_string()))?,
            ControlAction::Resume => {
                let unpaused = agent::clear_marker(&home, &id, agent::PAUSED_MARKER)
                    .map_err(|err| agent_write_failed(&err.to_string()))?;
                let unkilled = agent::clear_marker(&home, &id, agent::KILLED_MARKER)
                    .map_err(|err| agent_write_failed(&err.to_string()))?;
                unpaused || unkilled
            }
        };
        let state = agent::state(&home, &id);
        let changed = changed || before != state;
        // B-API v3 × E-18: a pause/kill also fires the cancellation tokens of
        // this agent's in-flight turns, so they abort now (the engine aborts its
        // provider/tool await, the shell tool reaps its process tree, and the
        // runner retires pending approvals) instead of waiting for the next
        // engine step boundary.
        if matches!(action, ControlAction::Pause | ControlAction::Kill) {
            turn_cancels.cancel_agent(&id);
        }
        if changed {
            let kind = match action {
                ControlAction::Pause => "agent.paused",
                ControlAction::Resume => "agent.resumed",
                ControlAction::Kill => "agent.killed",
            };
            audit(
                &db_path,
                kind,
                serde_json::json!({ "agent": &id, "by": "owner-api" }),
            );
        }
        Ok(ControlJson {
            name: id,
            paused: matches!(state, AgentState::Paused | AgentState::Killed),
            killed: matches!(state, AgentState::Killed),
            changed,
        })
    })
    .await;
    match result {
        Ok(Ok(json)) => Json(json).into_response(),
        Ok(Err(response)) => response,
        Err(_) => internal_error(),
    }
}

// ---------------------------------------------------------------------------
// audit / helpers
// ---------------------------------------------------------------------------

/// Append one audit/journal row. The row is also what the WebSocket poller
/// publishes as `agent.created`/`agent.updated`/… — never instructions or keys.
pub(crate) fn audit(_db_path: &Path, kind: &str, payload: serde_json::Value) {
    let text = payload.to_string();
    // J-02 round 4: re-open through the verified home, never the raw path.
    let home_path = _db_path.parent().unwrap_or(_db_path);
    let result = kernel_core::verified_home_or_verify(home_path)
        .map_err(aux_store::StoreError::from)
        .and_then(|home| aux_store::Store::open_verified(&home))
        .and_then(|store| store.log_event(kind, &text));
    if let Err(err) = result {
        tracing::warn!(kind, error = %err, "agent write audit failed");
    }
}

fn agent_write_failed(detail: &str) -> Response {
    tracing::error!(error = %detail, "agent write failed");
    error::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "agent_write_failed",
        "the change could not be saved",
        None,
    )
}

fn internal_error() -> Response {
    error::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "the daemon could not complete this request",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn home_with_config(text: &str) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        std::fs::write(config_path(dir.path()), text).unwrap();
        dir
    }

    async fn assert_refused(response: Response) {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(!body.to_lowercase().contains("canary"), "{body}");
        assert!(body.contains("looks like a key"), "{body}");
    }

    const CONFIG: &str = r#"
version = 1
default_agent = "main"

[[providers]]
id = "deepseek"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
kind = "openai-compat"

[[providers]]
id = "local"
base_url = "http://127.0.0.1:1234/v1"
model = "local-model"
kind = "openai-compat"
"#;

    #[test]
    fn create_writes_soul_sidecar_and_audits() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let (status, value) = create_sync(
            home,
            &db,
            CreateAgentRequest {
                name: Some("scout".to_string()),
                role: Some("# scout\nwatch the news".to_string()),
                provider: Some("deepseek".to_string()),
                model: Some("deepseek-chat".to_string()),
                tools: Some(vec![ToolEntry::Name("read_file".to_string())]),
                ..CreateAgentRequest::default()
            },
        )
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(value["created"], true);
        assert_eq!(value["agent"]["provider"], "deepseek");
        assert_eq!(value["agent"]["tools"][0], "read_file");
        assert_eq!(value["agent"]["paused"], false);
        assert_eq!(
            agent::read_soul(home, "scout").as_deref(),
            Some("# scout\nwatch the news")
        );
        let config = agent::config(home, "scout").unwrap();
        assert_eq!(config.provider.as_deref(), Some("deepseek"));
        let events = aux_store::Store::open(&db).unwrap();
        assert_eq!(events.event_count("agent.created").unwrap(), 1);
    }

    /// On an older install the chief is `aux`, which may not read mail: a
    /// tools list naming `mail_read` is refused when an agent is created or
    /// changed, for an added agent and for `main` (not the chief there). Mail,
    /// which `aux` hands work to, keeps it; a `main` home is as before.
    #[test]
    fn a_tools_list_is_held_to_the_chief_this_home_runs() {
        let reader = vec!["mail_read".to_string()];
        let dir = home_with_config("version = 1\ndefault_agent = \"aux\"\n");
        let home = dir.path();
        for id in ["scout", "main"] {
            let refused = validate_tool_ceiling(home, id, &reader).unwrap_err();
            assert_eq!(refused.status(), StatusCode::CONFLICT, "{id}");
        }
        assert!(validate_tool_ceiling(home, "aux", &reader).is_ok());
        assert!(validate_tool_ceiling(home, "mail", &reader).is_ok());

        let dir = home_with_config("version = 1\ndefault_agent = \"main\"\n");
        assert!(validate_tool_ceiling(dir.path(), "scout", &reader).is_ok());
    }

    /// A template's shipped tools list is held to the chief like a requested
    /// one: with `main` denied `mail_send`, Mail is refused and leaves no
    /// folder, Documents still fits, and the chief is never held to itself.
    #[test]
    fn a_template_tools_list_is_held_to_the_chief() {
        let deny = "\n[[rules]]\nagent = \"main\"\ntool = \"mail_send\"\naction = \"deny\"\n";
        let dir = home_with_config(&format!("{CONFIG}{deny}"));
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let template = |id: &str| CreateAgentRequest {
            template: Some(id.to_string()),
            ..CreateAgentRequest::default()
        };
        let refused = create_sync(home, &db, template("mail")).unwrap_err();
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert!(!agent::exists(home, "mail"));
        let (status, _) = create_sync(home, &db, template("documents")).unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let wide = vec!["mail_send".to_string(), "shell".to_string()];
        assert!(validate_tool_ceiling(home, "main", &wide).is_ok());
    }

    /// An `agent = "*"` rule denies the chief as an exact one does, in the
    /// broker's order. `mail_send` denied to every agent, then allowed to
    /// Mail: the chief is denied it, so the Mail template and a list naming
    /// it are refused. The reverse order is refused too. An allow for the
    /// chief after the wildcard lets both through again.
    #[test]
    fn a_wildcard_deny_of_the_chief_refuses_a_tools_list() {
        let rule = |agent: &str, action: &str| {
            format!(
                "\n[[rules]]\nagent = \"{agent}\"\ntool = \"mail_send\"\naction = \"{action}\"\n"
            )
        };
        let (every, mail, chief) = (
            rule("*", "deny"),
            rule("mail", "allow"),
            rule("main", "allow"),
        );
        for (rules, refused) in [
            (format!("{every}{mail}"), true),
            (format!("{mail}{every}"), true),
            (format!("{every}{chief}{mail}"), false),
        ] {
            let dir = home_with_config(&format!("{CONFIG}{rules}"));
            let home = dir.path();
            let sends = vec!["mail.send".to_string()];
            let listed = validate_tool_ceiling(home, "scout", &sends);
            assert_eq!(listed.is_err(), refused, "{rules}");
            let db = home.join("store.db");
            aux_store::Store::open(&db).unwrap();
            let template = CreateAgentRequest {
                template: Some("mail".to_string()),
                ..CreateAgentRequest::default()
            };
            let status = match create_sync(home, &db, template) {
                Ok((status, _)) => status,
                Err(response) => response.status(),
            };
            let expected = if refused {
                StatusCode::CONFLICT
            } else {
                StatusCode::CREATED
            };
            assert_eq!(status, expected, "{rules}");
            assert_eq!(agent::exists(home, "mail"), !refused, "{rules}");
        }
    }

    #[test]
    fn identical_create_is_idempotent_and_a_different_one_conflicts() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let request = || CreateAgentRequest {
            name: Some("scout".to_string()),
            role: Some("watch".to_string()),
            provider: Some("deepseek".to_string()),
            ..CreateAgentRequest::default()
        };
        let (status, _) = create_sync(home, &db, request()).unwrap();
        assert_eq!(status, StatusCode::CREATED);

        let (status, value) = create_sync(home, &db, request()).unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["created"], false);

        let mut different = request();
        different.role = Some("other".to_string());
        let err = create_sync(home, &db, different).unwrap_err();
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn key_shaped_provider_is_refused_on_create_and_update() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let key = "sk-proj-canary-7f3k9q"; // gitleaks:allow
        let request = |provider: &str| CreateAgentRequest {
            name: Some("scout".to_string()),
            provider: Some(provider.to_string()),
            ..CreateAgentRequest::default()
        };

        let err = create_sync(home, &db, request(key)).unwrap_err();
        assert_refused(err).await;

        create_sync(home, &db, request("deepseek")).unwrap();
        let err = update_sync(
            home,
            &db,
            "scout",
            UpdateAgentRequest {
                provider: Some(Some(key.to_string())),
                ..UpdateAgentRequest::default()
            },
        )
        .unwrap_err();
        assert_refused(err).await;
    }

    #[test]
    fn a_legacy_key_shaped_provider_is_not_exposed_or_rewritten() {
        // One provider: clearing the bad value falls back unambiguously.
        let dir = home_with_config(
            r#"
version = 1
[[providers]]
id = "deepseek"
base_url = "https://api.deepseek.com/v1"
model = "deepseek-chat"
kind = "openai-compat"
"#,
        );
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let key = "sk-proj-canary-7f3k9q"; // gitleaks:allow
        let agent_dir = home.join("agents/scout");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(
            agent_dir.join("agent.toml"),
            format!("provider = \"{key}\"\nmodel = \"old\"\n"),
        )
        .unwrap();

        let loaded = agent::config(home, "scout").unwrap();
        assert_eq!(loaded.provider, None);
        assert!(AgentJson::of(home, "scout", &loaded).provider.is_none());
        // Defense in depth: even a raw config passed directly is filtered.
        let raw = AgentConfig {
            provider: Some(key.to_string()),
            ..loaded
        };
        assert!(AgentJson::of(home, "scout", &raw).provider.is_none());

        // A model-only update writes the cleared provider back, never the raw one.
        update_sync(
            home,
            &db,
            "scout",
            UpdateAgentRequest {
                model: Some(Some("new".to_string())),
                ..UpdateAgentRequest::default()
            },
        )
        .unwrap();
        let text = std::fs::read_to_string(agent_dir.join("agent.toml")).unwrap();
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(!text.contains("provider"), "{text}");
        assert!(text.contains("model = \"new\""), "{text}");
    }

    #[test]
    fn unknown_provider_and_tool_are_plain_errors() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        let mut request = CreateAgentRequest {
            name: Some("scout".to_string()),
            provider: Some("nope".to_string()),
            ..CreateAgentRequest::default()
        };
        let err = create_sync(home, &db, request.clone()).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);

        request.provider = None;
        request.tools = Some(vec![ToolEntry::Name("not-a-tool".to_string())]);
        let err = create_sync(home, &db, request).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert!(!agent::exists(home, "scout"), "no half-created agent");
    }

    #[test]
    fn tools_grant_shape_respects_granted_false() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let names = validate_tools(
            home,
            vec![
                ToolEntry::Grant {
                    tool: "read_file".to_string(),
                    granted: false,
                },
                ToolEntry::Grant {
                    tool: "shell".to_string(),
                    granted: true,
                },
            ],
        )
        .unwrap();
        assert_eq!(names, vec!["shell".to_string()]);
    }

    #[test]
    fn update_merges_and_clears_fields() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        create_sync(
            home,
            &db,
            CreateAgentRequest {
                name: Some("scout".to_string()),
                role: Some("old role".to_string()),
                provider: Some("deepseek".to_string()),
                model: Some("deepseek-chat".to_string()),
                ..CreateAgentRequest::default()
            },
        )
        .unwrap();

        let value = update_sync(
            home,
            &db,
            "scout",
            UpdateAgentRequest {
                role: Some("new role".to_string()),
                provider: Some(Some("local".to_string())),
                model: Some(None),
                ..UpdateAgentRequest::default()
            },
        )
        .unwrap();
        assert_eq!(value["agent"]["provider"], "local");
        assert!(value["agent"]["model"].is_null());
        assert_eq!(agent::read_soul(home, "scout").as_deref(), Some("new role"));

        // Explicit null clears the provider too; an empty update is refused.
        let value = update_sync(
            home,
            &db,
            "scout",
            UpdateAgentRequest {
                provider: Some(None),
                ..UpdateAgentRequest::default()
            },
        )
        .unwrap();
        assert!(value["agent"]["provider"].is_null());
        let err = update_sync(home, &db, "scout", UpdateAgentRequest::default()).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn control_marks_pause_kill_and_resume() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        create_sync(
            home,
            &db,
            CreateAgentRequest {
                name: Some("scout".to_string()),
                ..CreateAgentRequest::default()
            },
        )
        .unwrap();

        assert!(agent::set_marker(home, "scout", agent::PAUSED_MARKER).unwrap());
        assert_eq!(agent::state(home, "scout"), AgentState::Paused);
        assert!(agent::set_marker(home, "scout", agent::KILLED_MARKER).unwrap());
        assert_eq!(agent::state(home, "scout"), AgentState::Killed);
        assert!(agent::clear_marker(home, "scout", agent::KILLED_MARKER).unwrap());
        assert!(agent::clear_marker(home, "scout", agent::PAUSED_MARKER).unwrap());
        assert_eq!(agent::state(home, "scout"), AgentState::Active);
    }

    #[test]
    fn create_requires_a_name_and_a_clean_one() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let err =
            create_sync(home, &home.join("store.db"), CreateAgentRequest::default()).unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let err = create_sync(
            home,
            &home.join("store.db"),
            CreateAgentRequest {
                name: Some("../escape".to_string()),
                ..CreateAgentRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn soul_read_and_update_round_trip_through_the_api() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        create_sync(
            home,
            &db,
            CreateAgentRequest {
                name: Some("scout".to_string()),
                role: Some("# scout\nwatch the news".to_string()),
                ..CreateAgentRequest::default()
            },
        )
        .unwrap();

        // Read: whole text, the 1 MiB ceiling advertised, not the default.
        let read = soul_sync(home, "scout").unwrap();
        assert_eq!(read["soul_md"], "# scout\nwatch the news");
        assert_eq!(read["max_bytes"], MAX_SOUL_BYTES);
        assert_eq!(read["is_default"], false);

        // Update through the same `soul_md` field the app sends.
        update_sync(
            home,
            &db,
            "scout",
            UpdateAgentRequest {
                soul_md: Some("# scout\nbe terse".to_string()),
                ..UpdateAgentRequest::default()
            },
        )
        .unwrap();
        assert_eq!(
            soul_sync(home, "scout").unwrap()["soul_md"],
            "# scout\nbe terse"
        );
        assert_eq!(
            agent::read_soul(home, "scout").as_deref(),
            Some("# scout\nbe terse")
        );

        // An empty update still refuses to clear the personality silently.
        let value = update_sync(
            home,
            &db,
            "scout",
            UpdateAgentRequest {
                soul_md: Some(String::new()),
                ..UpdateAgentRequest::default()
            },
        )
        .unwrap();
        assert_eq!(value["changed"], true);
        assert_eq!(
            soul_sync(home, "scout").unwrap()["soul_md"],
            agent::default_instructions("scout")
        );
    }

    #[test]
    fn a_missing_soul_reads_as_the_built_in_default() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        create_sync(
            home,
            &db,
            CreateAgentRequest {
                name: Some("scout".to_string()),
                ..CreateAgentRequest::default()
            },
        )
        .unwrap();
        std::fs::remove_file(aux_engine::soul_path(home, "scout")).unwrap();

        let read = soul_sync(home, "scout").unwrap();
        assert_eq!(read["soul_md"], agent::default_instructions("scout"));
        assert_eq!(read["is_default"], true);
    }

    #[test]
    fn soul_read_is_scoped_to_its_own_agent() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        for (name, role) in [("axis", "axis soul"), ("bolt", "bolt soul")] {
            create_sync(
                home,
                &db,
                CreateAgentRequest {
                    name: Some(name.to_string()),
                    role: Some(role.to_string()),
                    ..CreateAgentRequest::default()
                },
            )
            .unwrap();
        }

        assert_eq!(soul_sync(home, "axis").unwrap()["soul_md"], "axis soul");
        assert_eq!(soul_sync(home, "bolt").unwrap()["soul_md"], "bolt soul");

        let missing = soul_sync(home, "ghost").unwrap_err();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let bad_name = soul_sync(home, "../escape").unwrap_err();
        assert_eq!(bad_name.status(), StatusCode::BAD_REQUEST);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_soul_is_refused_for_reading_and_never_followed_on_write() {
        let dir = home_with_config(CONFIG);
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        create_sync(
            home,
            &db,
            CreateAgentRequest {
                name: Some("scout".to_string()),
                role: Some("original".to_string()),
                ..CreateAgentRequest::default()
            },
        )
        .unwrap();

        let target = home.join("outside-secret.txt");
        std::fs::write(&target, "not a soul").unwrap();
        let soul = aux_engine::soul_path(home, "scout");
        std::fs::remove_file(&soul).unwrap();
        std::os::unix::fs::symlink(&target, &soul).unwrap();

        // The editor read refuses the link instead of showing the other file.
        let err = soul_sync(home, "scout").unwrap_err();
        assert_eq!(err.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // The update writes through the one secure path, which never follows
        // the link. With the sandbox armed a pre-planted symlink makes it
        // refuse the home outright (500); without it the atomic rename
        // replaces the link itself. Either way the pointed-to file is intact
        // and its content is never the soul.
        let outcome = update_sync(
            home,
            &db,
            "scout",
            UpdateAgentRequest {
                soul_md: Some("rewritten".to_string()),
                ..UpdateAgentRequest::default()
            },
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "not a soul");
        match outcome {
            Ok(_) => {
                assert!(!std::fs::symlink_metadata(&soul)
                    .unwrap()
                    .file_type()
                    .is_symlink());
                assert_eq!(
                    agent::read_soul(home, "scout").as_deref(),
                    Some("rewritten")
                );
            }
            Err(response) => {
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
                assert!(std::fs::symlink_metadata(&soul)
                    .unwrap()
                    .file_type()
                    .is_symlink());
            }
        }
    }
}
