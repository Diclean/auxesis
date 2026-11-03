//! `GET /v1/first-run` and `POST /v1/first-run/complete` (B-API v4, gap 2).
//!
//! The guided flow the Swift app renders: save a provider, test it, create the
//! default `main` agent. This module owns the step state and the idempotent
//! "create the default agent" write; the provider write itself lives in
//! [`super::providers`] and the per-id test in the same module.
//!
//! State is derived from real artifacts, never cached: `config.toml` for
//! `provider_saved`, a `provider.tested` journal row for `provider_tested`,
//! and `<home>/agents` for `agent_created`. A failed test is an honest `false`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use aux_providers::{provider_name_is_key_shaped, ProviderConfig, KEY_SHAPED_PROVIDER_NAME};

use super::agents::{self, AgentJson, CreateAgentRequest};
use super::error;
use super::routes::read_body;
use super::wire::{FirstRunCompleteJson, FirstRunCompleteRequest, FirstRunStatusJson};
use super::ApiState;

/// The default agent the first-run flow creates.
pub const DEFAULT_AGENT: &str = "main";

/// `GET /v1/first-run`.
pub async fn status(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    match tokio::task::spawn_blocking(move || status_sync(&home)).await {
        Ok(Ok(json)) => Json(json).into_response(),
        Ok(Err(err)) => error::error_response_with_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_invalid",
            "the first-run state could not be read",
            error::sanitize_detail(&state.home, &err),
        ),
        Err(_) => internal_error(),
    }
}

fn status_sync(home: &Path) -> Result<FirstRunStatusJson, String> {
    let providers = configured(home)?;
    let provider_saved = !providers.is_empty();
    let tested = tested_provider(home);
    let provider_tested = tested
        .as_deref()
        .is_some_and(|id| providers.iter().any(|provider| provider.id == id));
    let agent = first_agent(home);
    let agent_created = agent.is_some();
    let next_step = if !provider_saved {
        "provider"
    } else if !provider_tested {
        "test"
    } else if !agent_created {
        "agent"
    } else {
        "done"
    };
    let provider = tested
        .filter(|id| {
            providers
                .iter()
                .any(|provider| provider.id.as_str() == id.as_str())
        })
        .or_else(|| providers.first().map(|provider| provider.id.clone()));
    Ok(FirstRunStatusJson {
        first_run: !(provider_saved && agent_created),
        provider_saved,
        provider_tested,
        agent_created,
        next_step,
        provider,
        agent,
    })
}

/// `POST /v1/first-run/complete`.
#[allow(clippy::result_large_err)]
pub async fn complete(
    State(state): State<Arc<ApiState>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: FirstRunCompleteRequest = if body.is_empty() {
        FirstRunCompleteRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => {
                return error::error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    "the request body must be a JSON object",
                    None,
                )
            }
        }
    };
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    match tokio::task::spawn_blocking(move || complete_sync(&home, &db_path, request)).await {
        Ok(Ok((status, json))) => (status, Json(json)).into_response(),
        Ok(Err(response)) => response,
        Err(_) => internal_error(),
    }
}

#[allow(clippy::result_large_err)]
fn complete_sync(
    home: &Path,
    db_path: &Path,
    request: FirstRunCompleteRequest,
) -> Result<(StatusCode, FirstRunCompleteJson), Response> {
    if request
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .is_some_and(provider_name_is_key_shaped)
    {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_provider",
            KEY_SHAPED_PROVIDER_NAME,
            None,
        ));
    }
    let providers = configured(home).map_err(|err| {
        error::error_response_with_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_invalid",
            "the provider configuration could not be read",
            error::sanitize_detail(home, &err),
        )
    })?;
    if providers.is_empty() {
        return Err(error::error_response(
            StatusCode::CONFLICT,
            "no_provider",
            "no AI service is saved yet",
            Some("save one with POST /v1/providers first"),
        ));
    }

    // Pick the provider the flow used: the request's, else the last tested,
    // else the only configured one. Several untested providers are ambiguous.
    let chosen = match request
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(id) => providers
            .iter()
            .find(|provider| provider.id == id)
            .cloned()
            .ok_or_else(|| {
                error::error_response(
                    StatusCode::BAD_REQUEST,
                    "unknown_provider",
                    format!(
                        "there is no AI service called `{}`",
                        error::sanitize_detail(home, id)
                    ),
                    Some("see GET /v1/providers"),
                )
            })?,
        None => {
            let tested = tested_provider(home);
            let tested_match = tested
                .as_deref()
                .and_then(|id| providers.iter().find(|provider| provider.id == id));
            match (tested_match, providers.as_slice()) {
                (Some(provider), _) => provider.clone(),
                (None, [only]) => only.clone(),
                (None, _) => {
                    return Err(error::error_response(
                        StatusCode::BAD_REQUEST,
                        "ambiguous_provider",
                        "several AI services are saved; choose one with `provider`",
                        Some("see GET /v1/providers"),
                    ))
                }
            }
        }
    };

    // Idempotent: an existing default agent is reported as-is, never
    // reconfigured or refused.
    if crate::agent::exists(home, DEFAULT_AGENT) {
        let config = crate::agent::config(home, DEFAULT_AGENT).unwrap_or_default();
        return Ok((
            StatusCode::OK,
            FirstRunCompleteJson {
                first_run: false,
                created: false,
                provider: chosen.id,
                agent: serde_json::to_value(AgentJson::of(home, DEFAULT_AGENT, &config))
                    .unwrap_or(serde_json::Value::Null),
            },
        ));
    }

    let model = request
        .model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_string)
        .or_else(|| (!chosen.model.is_empty()).then(|| chosen.model.clone()));
    let instructions = request
        .role
        .as_deref()
        .or(request.instructions.as_deref())
        .map(str::to_string);
    let create = CreateAgentRequest {
        name: Some(DEFAULT_AGENT.to_string()),
        role: instructions,
        provider: Some(chosen.id.clone()),
        model,
        ..CreateAgentRequest::default()
    };
    let (status, value) = agents::create_sync(home, db_path, create)?;
    let agent = value
        .get("agent")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    agents::audit(
        db_path,
        "first_run.completed",
        serde_json::json!({
            "agent": DEFAULT_AGENT,
            "provider": chosen.id,
            "by": "owner-api",
        }),
    );
    Ok((
        status,
        FirstRunCompleteJson {
            first_run: false,
            created: true,
            provider: chosen.id,
            agent,
        },
    ))
}

/// `[[providers]]` entries; a missing config file is an empty list.
fn configured(home: &Path) -> Result<Vec<ProviderConfig>, String> {
    let config_file = kernel_core::config_path(home);
    if !config_file.exists() {
        return Ok(Vec::new());
    }
    aux_providers::load_providers(&config_file).map_err(|err| err.to_string())
}

/// The provider id of the newest successful `provider.tested` row, if any.
fn tested_provider(home: &Path) -> Option<String> {
    let path = kernel_core::store_path(home);
    if !path.exists() {
        return None;
    }
    let conn = aux_store::open_keyed_readonly(&path).ok()?;
    let _ = conn.busy_timeout(Duration::from_secs(2));
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE kind = 'provider.tested' ORDER BY id DESC")
        .ok()?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0)).ok()?;
    for payload in rows.flatten() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&payload) else {
            continue;
        };
        if value["ok"] == serde_json::Value::Bool(true) {
            if let Some(provider) = value["provider"].as_str() {
                return Some(provider.to_string());
            }
        }
    }
    None
}

/// The default agent's name when it exists, else any agent, else `None`.
fn first_agent(home: &Path) -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir(home.join("agents"))
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| aux_engine::validate_agent(name).is_ok())
        .collect();
    names.sort();
    if names.iter().any(|name| name == DEFAULT_AGENT) {
        Some(DEFAULT_AGENT.to_string())
    } else {
        names.into_iter().next()
    }
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

    #[tokio::test]
    async fn complete_refuses_a_key_shaped_provider_name_without_echoing_it() {
        let err = complete_sync(
            Path::new("/tmp/aux-first-run-test"),
            Path::new("/tmp/aux-first-run-test.db"),
            FirstRunCompleteRequest {
                provider: Some("sk-proj-canary-7f3k9q".to_string()),
                ..FirstRunCompleteRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(err.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(!body.to_lowercase().contains("canary"), "{body}");
        assert!(body.contains("looks like a key"), "{body}");
    }
}
