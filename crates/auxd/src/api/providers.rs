//! `GET`/`POST /v1/providers` and `POST /v1/providers/test` (B-API v3/v4).
//!
//! The provider list is the settings screen's truth: every `[[providers]]`
//! entry from `config.toml`, its configured model and a **boolean** answer to
//! "is a key present?". Key material itself never crosses this module:
//! [`key_info`] resolves a key only to drop it, and no field, log line or
//! error body carries a value (the `api_key` of a test request is used and
//! forgotten).
//!
//! `POST /v1/providers` is the in-app setup write (gap 2): the non-secret part
//! (`id`, `base_url`, `model`, `key_user`, `kind`) is appended atomically to
//! `config.toml` under the loader's own validation, and a non-empty `api_key`
//! goes **only** to `<home>/.env` (`0600`, atomic, via
//! [`aux_providers::set_in_env_file`]). The key is never written to
//! `config.toml`, never logged, never echoed and never carried by an error
//! body; the response reports `key_present` only.
//!
//! `PUT /v1/providers/{name}/key` fixes the one dead end of that write: a
//! service that is already configured but has no key (or whose key lookup
//! failed) can now receive one. It never touches `config.toml`, refuses a name
//! that is not configured (`404`), refuses kinds that take no key and applies
//! the same shape checks, rate limit and `AUX_KEY_*` collision policy as the
//! create route.
//!
//! `POST /v1/providers/test` is a deliberately cheap, spend-free check:
//!
//! 1. the entry validates (id, model, HTTP(S) base URL as `auxproviders`
//!    would use it);
//! 2. a key is present when the entry needs one (the request's `api_key`
//!    counts and is never stored);
//! 3. the base URL is probed with a plain TCP connect **only** when every
//!    resolved address is public — the same SSRF policy the fetch tools run
//!    under. Behind a loopback/private address the probe is skipped and
//!    reported as "not checked", never as a failure.
//!
//! No chat completion is ever sent: the test can never spend tokens. The
//! result carries a machine-readable `reason` (`ok` / `bad_key` /
//! `unreachable` / `model_not_found` / `invalid_config`) so the guided flow
//! can show one plain sentence per case without parsing prose.

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use aux_providers::key::{
    env_var_name, set_in_env_file, AgentEnvStore, KeychainStore, SecretStore, KEYCHAIN_SERVICE,
};
use aux_providers::{
    chat_completions_url, load_providers, parse_providers, provider_name_is_key_shaped,
    shown_base_url, shown_id_plain, ProviderConfig, ProviderKind, FAKE_PROVIDER_SUPPORTED,
    KEY_SHAPED_PROVIDER_NAME,
};
use kernel_core::privacy::{admit_call, Destination, PathId};

use super::error;
use super::routes::read_body;
use super::wire::{
    CreateProviderRequest, ProviderJson, ProviderSavedJson, ProviderStatusJson, ProviderTestJson,
};
use super::ApiState;

/// How long a reachability probe may take before it is reported unreachable.
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest accepted provider name (the agent validator's own bound).
const MAX_PROVIDER_NAME_CHARS: usize = 64;

/// Largest accepted base URL.
const MAX_BASE_URL_BYTES: usize = 2048;

/// Largest accepted model id (same bound `POST /v1/agents` uses).
const MAX_MODEL_CHARS: usize = 200;

/// Largest accepted API key.
const MAX_API_KEY_BYTES: usize = 8192;

/// Key writes allowed per rolling minute: saving a provider key is a rare
/// owner action, never a hot path.
const MAX_KEY_WRITES_PER_MINUTE: usize = 60;

/// Timestamps of recent key writes, for the rate limit.
static KEY_WRITES: Mutex<Vec<Instant>> = Mutex::new(Vec::new());

/// GET `/v1/providers`.
pub async fn list(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let result = tokio::task::spawn_blocking(move || providers_snapshot(&home)).await;
    match result {
        Ok(Ok(providers)) => Json(providers).into_response(),
        Ok(Err(err)) => error::error_response_with_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_invalid",
            "the provider configuration could not be read",
            error::sanitize_detail(&state.home, &err),
        ),
        Err(_) => error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the daemon could not complete this request",
            None,
        ),
    }
}

/// Read `config.toml`, degrade to an empty list when there is no file yet.
fn providers_snapshot(home: &Path) -> Result<Vec<ProviderJson>, String> {
    let config_file = kernel_core::config_path(home);
    if !config_file.exists() {
        return Ok(Vec::new());
    }
    let providers = load_providers(&config_file).map_err(|err| err.to_string())?;
    Ok(providers
        .iter()
        .map(|provider| {
            let key = key_info(home, provider);
            ProviderJson {
                id: provider.id.clone(),
                name: provider.id.clone(),
                base_url: if provider.base_url.is_empty() {
                    String::new()
                } else {
                    shown_base_url(&provider.base_url)
                },
                model: provider.model.clone(),
                kind: provider.kind.as_str(),
                roles: vec!["chat"],
                key_location: key.location,
                status: ProviderStatusJson::Untested,
                last_test: String::new(),
                key_present: key.present,
                key_required: key.required,
                key_error: key.error.map(|text| error::sanitize_detail(home, &text)),
            }
        })
        .collect())
}

/// `POST /v1/providers`.
#[allow(clippy::result_large_err)]
pub async fn create(
    State(state): State<Arc<ApiState>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: CreateProviderRequest = match serde_json::from_slice(&body) {
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
    let config_write = Arc::clone(&state.config_write);
    match tokio::task::spawn_blocking(move || create_sync(&config_write, &home, &db_path, request))
        .await
    {
        Ok(Ok(json)) => (StatusCode::CREATED, Json(json)).into_response(),
        Ok(Err(response)) => response,
        Err(_) => internal_error(),
    }
}

/// Validate, store the secret, append the config entry and audit.
///
/// `config_write` is the daemon's one `config.toml` writer lock; the existing
/// entries are re-read and the new one appended while holding it.
#[allow(clippy::result_large_err)]
fn create_sync(
    config_write: &Mutex<()>,
    home: &Path,
    db_path: &Path,
    request: CreateProviderRequest,
) -> Result<ProviderSavedJson, Response> {
    let name = request
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            error::error_response(
                StatusCode::BAD_REQUEST,
                "missing_name",
                "`name` is required",
                Some("letters, digits, `-`, `_` and `.` (max 64 characters)"),
            )
        })?;
    if name.chars().count() > MAX_PROVIDER_NAME_CHARS {
        return Err(invalid_name(home, "the name is longer than 64 characters"));
    }
    if provider_name_is_key_shaped(name) {
        return Err(invalid_name(home, KEY_SHAPED_PROVIDER_NAME));
    }
    if let Err(err) = aux_engine::validate_agent(name) {
        return Err(invalid_name(home, &err.to_string()));
    }

    let kind = parse_kind(home, request.kind.as_deref())?;

    let api_key = request
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty());
    if let Some(key) = api_key {
        if key.len() > MAX_API_KEY_BYTES {
            return Err(invalid_key(home, "the key is too long"));
        }
        if key.contains(['\n', '\r', '\0']) {
            return Err(invalid_key(home, "the key must be a single line"));
        }
    }
    if api_key.is_some() {
        match kind {
            ProviderKind::OpenAiCompat => {}
            ProviderKind::Acp => {
                return Err(error::error_response(
                    StatusCode::BAD_REQUEST,
                    "key_not_allowed",
                    "an ACP provider uses its CLI's own login and cannot carry an API key",
                    None,
                ))
            }
            ProviderKind::Fake => {
                return Err(error::error_response(
                    StatusCode::BAD_REQUEST,
                    "key_not_allowed",
                    "a fake provider does not use an API key",
                    None,
                ))
            }
        }
    }

    let base_url = request
        .base_url
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if base_url.len() > MAX_BASE_URL_BYTES {
        return Err(invalid_provider(home, "the base URL is too long"));
    }
    let model = request
        .model
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if model.chars().count() > MAX_MODEL_CHARS {
        return Err(invalid_model());
    }

    let provider = ProviderConfig {
        disable_thinking: false,
        id: name.to_string(),
        base_url,
        model,
        key_user: match kind {
            ProviderKind::OpenAiCompat if api_key.is_some() => Some(name.to_string()),
            _ => None,
        },
        kind,
    };
    if let Err(err) = provider.validate() {
        return Err(invalid_provider(home, &err.to_string()));
    }
    if let Err(message) = check_base_url_policy(&provider) {
        return Err(invalid_provider(home, &message));
    }

    // The rate limit guards key material only.
    if api_key.is_some() && !key_write_allowed(Instant::now()) {
        return Err(error::error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("too many key writes; at most {MAX_KEY_WRITES_PER_MINUTE} per minute"),
            Some("wait a minute and try again"),
        ));
    }

    let _guard = config_write
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Re-read under the lock so a concurrent save cannot be lost.
    let existing = load_configured(home)?;
    if existing.iter().any(|entry| entry.id == provider.id) {
        return Err(error::error_response(
            StatusCode::CONFLICT,
            "provider_exists",
            format!(
                "an AI service called `{}` already exists",
                error::sanitize_detail(home, name)
            ),
            Some("choose another name"),
        ));
    }
    // Distinct ids that differ only by case or by `-`/`_`/`.` share one
    // `AUX_KEY_*` slot, so saving a key for one would silently overwrite the
    // other's secret (and both would report `key_present`). Refuse the pair.
    if let Some(other) = env_var_collision(&existing, &provider.id) {
        return Err(error::error_response(
            StatusCode::CONFLICT,
            "provider_key_conflict",
            format!(
                "`{}` is already using the key slot of `{}`; names that differ only by case or by `-`, `_` or `.` share the same secret",
                error::sanitize_detail(home, name),
                error::sanitize_detail(home, &other.id),
            ),
            Some("choose a name that is not a case or punctuation variant"),
        ));
    }

    // Secret first: a key that cannot be stored must not leave a config entry
    // pointing at a missing key.
    if let Some(key) = api_key {
        set_in_env_file(home, name, key).map_err(|err| {
            tracing::error!(error = %err, "provider key could not be written");
            error::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key_write_failed",
                "the key could not be saved",
                None,
            )
        })?;
    }

    if let Err(message) = append_provider_config(home, &provider) {
        tracing::error!(error = %message, "provider config could not be written");
        return Err(error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "provider_write_failed",
            "the AI service could not be saved",
            None,
        ));
    }

    super::agents::audit(
        db_path,
        "provider.created",
        serde_json::json!({
            "provider": shown_id_plain(&provider.id),
            "kind": provider.kind.as_str(),
            "base_url": if provider.base_url.is_empty() {
                String::new()
            } else {
                shown_base_url(&provider.base_url)
            },
            "model": shown_id_plain(&provider.model),
            "key_present": api_key.is_some(),
            "by": "owner-api",
        }),
    );

    Ok(ProviderSavedJson {
        name: provider.id.clone(),
        key_present: api_key.is_some(),
    })
}

/// `PUT /v1/providers/{name}/key` body. The key is used and forgotten exactly
/// like the create route's: it only reaches `<home>/.env`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UpdateProviderKeyRequest {
    /// Secret to store in `<home>/.env`; never echoed back.
    pub api_key: Option<String>,
}

/// `PUT /v1/providers/{name}/key`.
#[allow(clippy::result_large_err)]
pub async fn update_key(
    State(state): State<Arc<ApiState>>,
    AxumPath(name): AxumPath<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match read_body(body) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: UpdateProviderKeyRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return error::error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "the request body must be a JSON object with an `api_key` string",
                None,
            )
        }
    };
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let config_write = Arc::clone(&state.config_write);
    match tokio::task::spawn_blocking(move || {
        update_key_sync(&config_write, &home, &db_path, &name, request)
    })
    .await
    {
        Ok(Ok(json)) => Json(json).into_response(),
        Ok(Err(response)) => response,
        Err(_) => internal_error(),
    }
}

/// Store one key for an **existing** provider, without touching `config.toml`.
///
/// The name must already be configured (`404` otherwise); a kind that takes no
/// key is refused; the key is shape-checked, rate-limited and written to
/// `<home>/.env` through the same safe writer as the create route. A config
/// that duplicates the `AUX_KEY_*` slot is refused rather than overwritten.
#[allow(clippy::result_large_err)]
fn update_key_sync(
    config_write: &Mutex<()>,
    home: &Path,
    db_path: &Path,
    name: &str,
    request: UpdateProviderKeyRequest,
) -> Result<ProviderSavedJson, Response> {
    let name = name.trim();
    if name.is_empty() {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "missing_name",
            "`name` is required",
            Some("letters, digits, `-`, `_` and `.` (max 64 characters)"),
        ));
    }
    if name.chars().count() > MAX_PROVIDER_NAME_CHARS {
        return Err(invalid_name(home, "the name is longer than 64 characters"));
    }
    if provider_name_is_key_shaped(name) {
        return Err(invalid_name(home, KEY_SHAPED_PROVIDER_NAME));
    }
    if let Err(err) = aux_engine::validate_agent(name) {
        return Err(invalid_name(home, &err.to_string()));
    }

    let key = request
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| {
            error::error_response(
                StatusCode::BAD_REQUEST,
                "missing_key",
                "`api_key` is required",
                Some("send the key the service gave you"),
            )
        })?;
    if key.len() > MAX_API_KEY_BYTES {
        return Err(invalid_key(home, "the key is too long"));
    }
    if key.contains(['\n', '\r', '\0']) {
        return Err(invalid_key(home, "the key must be a single line"));
    }

    let _guard = config_write
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Re-read under the lock: the entry must exist, and a hand-edited config
    // that duplicated the key slot must be refused, not silently overwritten.
    let existing = load_configured(home)?;
    let Some(provider) = existing.iter().find(|entry| entry.id == name) else {
        return Err(error::error_response(
            StatusCode::NOT_FOUND,
            "provider_not_found",
            format!(
                "no AI service called `{}` is configured",
                error::sanitize_detail(home, name)
            ),
            Some("check GET /v1/providers"),
        ));
    };
    match provider.kind {
        ProviderKind::OpenAiCompat => {}
        ProviderKind::Acp => {
            return Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "key_not_allowed",
                "an ACP provider uses its CLI's own login and cannot carry an API key",
                None,
            ))
        }
        ProviderKind::Fake => {
            return Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "key_not_allowed",
                "a fake provider does not use an API key",
                None,
            ))
        }
    }
    if let Some(other) = env_var_collision(&existing, &provider.id) {
        return Err(error::error_response(
            StatusCode::CONFLICT,
            "provider_key_conflict",
            format!(
                "`{}` is already using the key slot of `{}`; names that differ only by case or by `-`, `_` or `.` share the same secret",
                error::sanitize_detail(home, name),
                error::sanitize_detail(home, &other.id),
            ),
            Some("choose a name that is not a case or punctuation variant"),
        ));
    }

    if !key_write_allowed(Instant::now()) {
        return Err(error::error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("too many key writes; at most {MAX_KEY_WRITES_PER_MINUTE} per minute"),
            Some("wait a minute and try again"),
        ));
    }

    set_in_env_file(home, name, key).map_err(|err| {
        tracing::error!(error = %err, "provider key could not be written");
        error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_write_failed",
            "the key could not be saved",
            None,
        )
    })?;

    super::agents::audit(
        db_path,
        "provider.key_updated",
        serde_json::json!({
            "provider": shown_id_plain(&provider.id),
            "key_present": true,
            "by": "owner-api",
        }),
    );

    Ok(ProviderSavedJson {
        name: provider.id.clone(),
        key_present: true,
    })
}

/// Load `[[providers]]`, degrading to an empty list when the file is absent.
#[allow(clippy::result_large_err)]
fn load_configured(home: &Path) -> Result<Vec<ProviderConfig>, Response> {
    let config_file = kernel_core::config_path(home);
    if !config_file.exists() {
        return Ok(Vec::new());
    }
    load_providers(&config_file).map_err(|err| {
        error::error_response_with_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "config_invalid",
            "the provider configuration could not be read",
            error::sanitize_detail(home, &err.to_string()),
        )
    })
}

/// The first configured provider whose id maps to the same `AUX_KEY_*`
/// variable as `id`, when that provider has a *different* id.
///
/// Two ids that differ only by case (`Acme` / `acme`) or by `-`/`_`/`.`
/// (`a-b` / `a_b`) share one secret slot; the caller refuses the pair.
fn env_var_collision<'a>(existing: &'a [ProviderConfig], id: &str) -> Option<&'a ProviderConfig> {
    let var = env_var_name(id);
    existing
        .iter()
        .find(|entry| entry.id != id && env_var_name(&entry.id) == var)
}

/// Refuse `kind = "fake"` in a build that has no fake adapter.
///
/// The fake provider is test/sandbox support (`aux-providers`'s off-by-default
/// `test-fake` feature). A release daemon refuses the write here rather than
/// saving a provider every turn would then fail to build.
fn fake_kind_disabled() -> Response {
    error::error_response(
        StatusCode::BAD_REQUEST,
        "fake_provider_disabled",
        "the fake provider is a test aid and this build does not include it",
        Some("use a real AI service, or a test build with the `test-fake` feature"),
    )
}

/// Parse the request's `kind`, accepting both spellings of `openai-compat`.
#[allow(clippy::result_large_err)]
fn parse_kind(home: &Path, raw: Option<&str>) -> Result<ProviderKind, Response> {
    match raw.map(str::trim) {
        None | Some("") | Some("openai-compat") | Some("openai_compat") => {
            Ok(ProviderKind::OpenAiCompat)
        }
        Some("fake") if FAKE_PROVIDER_SUPPORTED => Ok(ProviderKind::Fake),
        Some("fake") => Err(fake_kind_disabled()),
        Some("acp") => Ok(ProviderKind::Acp),
        Some(other) => Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_kind",
            format!(
                "unknown provider kind `{}`; expected `openai_compat`, `fake` or `acp`",
                error::sanitize_detail(home, other)
            ),
            None,
        )),
    }
}

/// Extra policy on top of [`ProviderConfig::validate`]: a literal IP base URL
/// must be public or loopback; a private-network address is refused unless
/// the adapter is the local `fake` one.
fn check_base_url_policy(provider: &ProviderConfig) -> Result<(), String> {
    let Some((host, _port)) = host_port(&provider.base_url) else {
        return Ok(());
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let Ok(ip) = host.parse::<IpAddr>() else {
        return Ok(()); // a name: resolved at call time under the fetch policy
    };
    if ip.is_loopback() || kernel_net::is_public_address(ip) || kind_is_local(provider.kind) {
        return Ok(());
    }
    Err(format!(
        "base_url `{}` points at a private-network address; use a public https host or a loopback endpoint",
        shown_base_url(&provider.base_url)
    ))
}

/// The one existing kind that never talks to the network.
fn kind_is_local(kind: ProviderKind) -> bool {
    matches!(kind, ProviderKind::Fake)
}

/// Append one `[[providers]]` block to `config.toml` atomically.
///
/// The exact bytes are re-validated before the rename: the whole config must
/// still parse and the provider section must satisfy the loader. The whole
/// read-modify-write runs under the shared `<home>/.config.lock` file lock so
/// a CLI or settings writer in another process cannot be lost to a stale
/// read.
fn append_provider_config(home: &Path, provider: &ProviderConfig) -> Result<(), String> {
    kernel_core::with_config_lock(home, || {
        // Create the default config first so a fresh home has a valid file.
        crate::api::load_config_verified(home).map_err(|err| err.to_string())?;
        let handle = kernel_core::SandboxHome::open(home).map_err(|err| err.to_string())?;
        // Read through the handle that writes: never a symlink nor a FIFO.
        let mut text =
            aux_engine::config::read_config_text(&handle).map_err(|err| err.to_string())?;
        if !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str("\n[[providers]]\n");
        let block = toml::to_string(provider).map_err(|err| err.to_string())?;
        text.push_str(&block);
        if !text.ends_with('\n') {
            text.push('\n');
        }

        let _: kernel_core::Config = toml::from_str(&text).map_err(|err| {
            let err = kernel_core::redact_toml_error(&err, "config.toml", &text);
            format!("the combined config would not parse: {}", err.message())
        })?;
        parse_providers(&text).map_err(|err| err.to_string())?;

        handle
            .write_atomic(Path::new("config.toml"), text.as_bytes(), 0o600)
            .map_err(|err| err.to_string())
    })
    .map_err(|err| format!("acquiring the configuration lock: {err}"))?
}

/// Whether another key write is allowed under the rolling-minute limit.
fn key_write_allowed(now: Instant) -> bool {
    let mut writes = KEY_WRITES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    writes.retain(|at| now.duration_since(*at) < Duration::from_secs(60));
    if writes.len() >= MAX_KEY_WRITES_PER_MINUTE {
        return false;
    }
    writes.push(now);
    true
}

fn invalid_name(home: &Path, reason: &str) -> Response {
    error::error_response_with_detail(
        StatusCode::BAD_REQUEST,
        "invalid_name",
        "this AI service name cannot be used",
        error::sanitize_detail(home, reason),
    )
}

fn invalid_key(home: &Path, reason: &str) -> Response {
    error::error_response_with_detail(
        StatusCode::BAD_REQUEST,
        "invalid_key",
        "the API key cannot be used",
        error::sanitize_detail(home, reason),
    )
}

fn invalid_provider(home: &Path, reason: &str) -> Response {
    error::error_response_with_detail(
        StatusCode::BAD_REQUEST,
        "invalid_provider",
        "this AI service cannot be used",
        error::sanitize_detail(home, reason),
    )
}

fn invalid_model() -> Response {
    error::error_response(
        StatusCode::BAD_REQUEST,
        "invalid_model",
        format!("the model id is too long (max {MAX_MODEL_CHARS} characters)"),
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

/// A test request: either an existing configured provider (by `id`/`name`)
/// or an inline entry. Unknown fields (the app's drafts carry a few) are
/// ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct TestRequest {
    /// Provider id; `name` is accepted as an alias.
    pub id: Option<String>,
    /// Alias for `id`.
    pub name: Option<String>,
    /// API root; required when `id` does not name a configured provider.
    pub base_url: Option<String>,
    /// Model override.
    pub model: Option<String>,
    /// Key to check for this test only. Used, never stored, never echoed.
    pub api_key: Option<String>,
    /// Keychain account, when testing an inline entry.
    pub key_user: Option<String>,
    /// `openai-compat` (default) or `fake`.
    pub kind: Option<String>,
}

/// POST `/v1/providers/test`.
pub async fn test(
    State(state): State<Arc<ApiState>>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    run_test(&state, None, body).await
}

/// POST `/v1/providers/{id}/test` (the app's per-row test button).
pub async fn test_by_id(
    State(state): State<Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    run_test(&state, Some(id), body).await
}

#[allow(clippy::result_large_err)]
async fn run_test(
    state: &Arc<ApiState>,
    path_id: Option<String>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    // The body is optional on the per-id route: `{}` and an empty body both
    // test the named configured provider.
    let bytes = match read_body(body) {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let request: TestRequest = if bytes.is_empty() {
        TestRequest::default()
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(request) => request,
            Err(_) => {
                return error::error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    "the request body must be a JSON object",
                    None,
                );
            }
        }
    };
    let id = path_id
        .or_else(|| request.id.clone())
        .or_else(|| request.name.clone())
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty());

    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let id_for_audit = id.clone();
    let result =
        tokio::task::spawn_blocking(move || test_provider(&home, id.as_deref(), request)).await;
    match result {
        Ok(Ok(json)) => {
            // First-run reads this journal row back (never a key).
            if let Some(name) = id_for_audit.as_deref() {
                audit_test(&db_path, name, &json);
            }
            Json(json).into_response()
        }
        Ok(Err(response)) => response,
        Err(_) => error::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the daemon could not complete this request",
            None,
        ),
    }
}

/// Journal one test outcome. The payload carries the verdict and booleans
/// only — never the key, the request body or the base URL's userinfo.
///
/// The provider id stays as it is: the first-run flow reads this row back to
/// name the service it tested (see `first_run::tested_provider`).
fn audit_test(db_path: &Path, provider: &str, json: &ProviderTestJson) {
    super::agents::audit(
        db_path,
        "provider.tested",
        serde_json::json!({
            "provider": provider,
            "ok": json.ok,
            "reason": json.reason,
            "key_present": json.key_present,
            "by": "owner-api",
        }),
    );
}

/// The `POST /v1/providers/test` result is [`ProviderTestJson`] (wire.rs).
#[allow(clippy::result_large_err)]
fn test_provider(
    home: &Path,
    id: Option<&str>,
    request: TestRequest,
) -> Result<ProviderTestJson, Response> {
    if id.is_some_and(provider_name_is_key_shaped) {
        return Err(error::error_response(
            StatusCode::BAD_REQUEST,
            "invalid_provider",
            KEY_SHAPED_PROVIDER_NAME,
            None,
        ));
    }
    let config_file = kernel_core::config_path(home);
    let configured = match (config_file.exists(), id) {
        (true, _) => match load_providers(&config_file) {
            Ok(providers) => providers,
            Err(err) => {
                return Err(error::error_response_with_detail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "config_invalid",
                    "the provider configuration could not be read",
                    error::sanitize_detail(home, &err.to_string()),
                ));
            }
        },
        (false, _) => Vec::new(),
    };

    // Resolve the entry under test: a configured one by id wins; otherwise
    // the request must carry enough to build one inline.
    let from_config = id.and_then(|id| configured.iter().find(|provider| provider.id == id));
    let provider = if let Some(provider) = from_config {
        let mut provider = provider.clone();
        if let Some(model) = request
            .model
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty())
        {
            provider.model = model.to_string();
        }
        provider
    } else {
        let Some(id) = id else {
            return Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "missing_name",
                "`name` (the AI service id) is required",
                Some("use an id from GET /v1/providers, or set `name` and `base_url`"),
            ));
        };
        let Some(base_url) = request
            .base_url
            .as_deref()
            .map(str::trim)
            .filter(|url| !url.is_empty())
        else {
            return Err(error::error_response(
                StatusCode::NOT_FOUND,
                "provider_not_found",
                format!(
                    "no AI service called `{}` is configured, and no `base_url` was given",
                    error::sanitize_detail(home, id)
                ),
                Some("check GET /v1/providers, or send `base_url` for a new service"),
            ));
        };
        let kind = match request.kind.as_deref().map(str::trim) {
            None | Some("") | Some("openai-compat") | Some("openai_compat") => {
                ProviderKind::OpenAiCompat
            }
            Some("fake") if FAKE_PROVIDER_SUPPORTED => ProviderKind::Fake,
            Some("fake") => return Err(fake_kind_disabled()),
            Some(other) => {
                return Err(error::error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_kind",
                    format!(
                        "unknown provider kind `{}`; expected `openai-compat` or `fake`",
                        error::sanitize_detail(home, other)
                    ),
                    None,
                ));
            }
        };
        let model = request
            .model
            .as_deref()
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .unwrap_or(if matches!(kind, ProviderKind::Fake) {
                "fake-model"
            } else {
                ""
            })
            .to_string();
        if model.is_empty() {
            return Err(error::error_response(
                StatusCode::BAD_REQUEST,
                "missing_model",
                "`model` is required when testing a service that is not configured",
                Some("send the model id, e.g. `deepseek-chat`"),
            ));
        }
        ProviderConfig {
            disable_thinking: false,
            id: id.to_string(),
            base_url: base_url.to_string(),
            model,
            key_user: request
                .key_user
                .as_deref()
                .map(str::trim)
                .filter(|user| !user.is_empty())
                .map(str::to_string),
            kind,
        }
    };

    // 1. Configuration validity, with the exact error the provider layer
    //    would raise at turn time.
    if let Err(err) = provider.validate() {
        return Ok(ProviderTestJson {
            ok: false,
            reason: "invalid_config",
            latency_ms: None,
            models: Vec::new(),
            error: Some(error::sanitize_detail(home, &err.to_string())),
            key_present: None,
            key_required: false,
            reachable: None,
            note: None,
        });
    }
    let endpoint = match chat_completions_url(&provider.base_url) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            return Ok(ProviderTestJson {
                ok: false,
                reason: "invalid_config",
                latency_ms: None,
                models: Vec::new(),
                error: Some(error::sanitize_detail(home, &err.to_string())),
                key_present: None,
                key_required: false,
                reachable: None,
                note: None,
            });
        }
    };

    // 2. Key presence: the request's key, else the real sources.
    let has_inline_key = request
        .api_key
        .as_deref()
        .is_some_and(|key| !key.is_empty());
    let key = if has_inline_key {
        KeyInfo {
            present: Some(true),
            required: key_required(&provider),
            location: "request",
            error: None,
        }
    } else {
        key_info(home, &provider)
    };
    let key_ok = !key.required || key.present == Some(true);

    // 3. Reachability, only behind the fetch policy. Private mode (A3): the
    // endpoint is not contacted at all, not even a bare TCP connect.
    let privacy_config = crate::api::load_config_verified(home);
    let probe = match admit_call(
        PathId::A3,
        crate::privacy_wiring::mode_of(&privacy_config),
        Destination::Vendor(provider.id.clone()),
    ) {
        Ok(_grant) => probe_base_url(&endpoint),
        Err(refused) => Reachability::NotChecked {
            reason: refused.text(
                privacy_config
                    .as_ref()
                    .map(|config| config.ui.language)
                    .unwrap_or_default(),
            ),
        },
    };
    let reachable = match &probe {
        Reachability::Reachable { .. } => Some(true),
        Reachability::Unreachable { .. } => Some(false),
        Reachability::NotChecked { .. } => None,
    };
    let mut note = match &probe {
        Reachability::Reachable { addr, .. } => Some(format!("reachable at {addr}")),
        Reachability::Unreachable { .. } => None,
        Reachability::NotChecked { reason } => Some(reason.clone()),
    };
    if key.required && key.present.is_none() {
        note = Some(match note {
            Some(note) => format!("{note}; the key could not be checked"),
            None => "the key could not be checked".to_string(),
        });
    }
    let error = if !key_ok {
        Some(match key.present {
            Some(false) => "no API key found for this service".to_string(),
            _ => key
                .error
                .clone()
                .unwrap_or_else(|| "the API key could not be checked".to_string()),
        })
    } else {
        match &probe {
            Reachability::Unreachable { error: text } => Some(text.clone()),
            _ => None,
        }
    };
    let ok = key_ok && !matches!(probe, Reachability::Unreachable { .. });
    let reason = test_reason(
        ok,
        key_ok,
        matches!(probe, Reachability::Unreachable { .. }),
        error.as_deref(),
    );
    Ok(ProviderTestJson {
        ok,
        reason,
        latency_ms: match &probe {
            Reachability::Reachable { latency_ms, .. } => Some(*latency_ms),
            _ => None,
        },
        models: Vec::new(),
        error: error.map(|text| error::sanitize_detail(home, &text)),
        key_present: key.present,
        key_required: key.required,
        reachable,
        note,
    })
}

/// One machine-readable bucket for the guided flow.
///
/// `model_not_found` is reserved for a future live check: this route never
/// sends a completion, so it can only ever be inferred from an error that
/// names the model.
fn test_reason(ok: bool, key_ok: bool, unreachable: bool, error: Option<&str>) -> &'static str {
    if ok {
        "ok"
    } else if !key_ok {
        "bad_key"
    } else if unreachable {
        "unreachable"
    } else if error.is_some_and(|text| text.to_ascii_lowercase().contains("model")) {
        "model_not_found"
    } else {
        "unknown"
    }
}

/// What a key lookup found (never the key itself).
struct KeyInfo {
    present: Option<bool>,
    required: bool,
    location: &'static str,
    error: Option<String>,
}

/// Whether this entry needs a key to work: a key_user is configured and the
/// adapter is a remote HTTP one.
fn key_required(provider: &ProviderConfig) -> bool {
    matches!(provider.kind, ProviderKind::OpenAiCompat)
        && provider
            .key_user
            .as_deref()
            .is_some_and(|user| !user.trim().is_empty())
}

/// Resolve presence (not the value) through the real stores, in the same
/// order the provider adapter uses: Keychain → `<home>/.env` → process env.
fn key_info(home: &Path, provider: &ProviderConfig) -> KeyInfo {
    if !key_required(provider) {
        return KeyInfo {
            present: Some(false),
            required: false,
            location: "none",
            error: None,
        };
    }
    let account = provider
        .key_user
        .as_deref()
        .map(str::trim)
        .filter(|user| !user.is_empty());
    let env_file = match AgentEnvStore::load(&home.join(aux_providers::key::ENV_FILE)) {
        Ok(store) => store,
        Err(err) => {
            return KeyInfo {
                present: None,
                required: true,
                location: "none",
                error: Some(err.to_string()),
            };
        }
    };

    let mut keychain_error: Option<String> = None;
    if let Some(account) = account {
        match KeychainStore::new().get(KEYCHAIN_SERVICE, account) {
            Ok(Some(secret)) if !secret.is_empty() => {
                // Whatever key this process resolves is registered
                // with the exact-value scrubber (the value is never logged).
                kernel_broker::scrub::register_known_secret(&secret);
                return KeyInfo {
                    present: Some(true),
                    required: true,
                    location: "keychain",
                    error: None,
                };
            }
            Ok(_) => {}
            Err(err) => keychain_error = Some(err.to_string()),
        }
    }
    let var = env_var_name(&provider.id);
    if let Some(value) = env_file.get_var(&var).filter(|value| !value.is_empty()) {
        kernel_broker::scrub::register_known_secret(value);
        return KeyInfo {
            present: Some(true),
            required: true,
            location: "env",
            error: None,
        };
    }
    if let Ok(value) = std::env::var(&var) {
        if !value.is_empty() {
            kernel_broker::scrub::register_known_secret(&value);
            return KeyInfo {
                present: Some(true),
                required: true,
                location: "env",
                error: None,
            };
        }
    }
    match keychain_error {
        Some(error) => KeyInfo {
            present: None,
            required: true,
            location: "none",
            error: Some(error),
        },
        None => KeyInfo {
            present: Some(false),
            required: true,
            location: "none",
            error: None,
        },
    }
}

/// What the reachability probe concluded.
enum Reachability {
    /// A TCP connection succeeded.
    Reachable { addr: SocketAddr, latency_ms: u32 },
    /// The policy allowed the probe and the connection failed.
    Unreachable { error: String },
    /// The probe was skipped because the fetch policy blocks the address.
    NotChecked { reason: String },
}

/// Probe the base URL with a bounded TCP connect, only when every resolved
/// address is public (the fetch tools' SSRF policy).
fn probe_base_url(endpoint: &str) -> Reachability {
    let Some((host, port)) = host_port(endpoint) else {
        return Reachability::NotChecked {
            reason: "the base URL has no host to probe".to_string(),
        };
    };
    let mut addresses = match (host.as_str(), port).to_socket_addrs() {
        Ok(addresses) => addresses.collect::<Vec<_>>(),
        Err(err) => {
            return Reachability::Unreachable {
                error: format!("could not resolve `{host}`: {err}"),
            };
        }
    };
    if addresses.is_empty() {
        return Reachability::Unreachable {
            error: format!("`{host}` did not resolve to any address"),
        };
    }
    if !addresses.iter().all(|addr| is_public_probe(addr.ip())) {
        return Reachability::NotChecked {
            reason: "not checked: the fetch policy blocks this address (private or loopback)"
                .to_string(),
        };
    }
    // Deterministic order: probe the first validated address.
    addresses.sort_by_key(|addr| addr.ip());
    let addr = addresses[0];
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, REACHABILITY_TIMEOUT) {
        Ok(_) => Reachability::Reachable {
            addr,
            latency_ms: started.elapsed().as_millis().min(u32::MAX as u128) as u32,
        },
        Err(err) => Reachability::Unreachable {
            error: format!("could not reach `{host}`: {err}"),
        },
    }
}

fn is_public_probe(ip: IpAddr) -> bool {
    kernel_net::is_public_address(ip)
}

/// Extract `(host, port)` from an HTTP(S) URL without pulling in a URL crate:
/// base URLs are validated by the provider layer before this runs.
fn host_port(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?; // drop userinfo
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|value| value.parse().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Some((host.to_string(), port.parse().ok()?))
        }
        _ => Some((authority.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A fresh writer lock for a single-threaded unit test: the production
    /// daemon shares one instance across every writer, and these tests call
    /// one writer at a time.
    fn test_config_write() -> Mutex<()> {
        Mutex::new(())
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

    fn provider(id: &str, key_user: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            disable_thinking: false,
            id: id.to_string(),
            base_url: "https://api.example.com/v1".to_string(),
            model: "model-x".to_string(),
            key_user: key_user.map(str::to_string),
            kind: ProviderKind::OpenAiCompat,
        }
    }

    #[test]
    fn no_key_user_means_no_key_required() {
        let dir = tempdir().unwrap();
        let info = key_info(dir.path(), &provider("local", None));
        assert!(!info.required);
        assert_eq!(info.present, Some(false));
        assert_eq!(info.location, "none");
    }

    #[test]
    fn a_fake_provider_never_needs_a_key() {
        let dir = tempdir().unwrap();
        let mut entry = provider("fakey", Some("fakey"));
        entry.kind = ProviderKind::Fake;
        let info = key_info(dir.path(), &entry);
        assert!(!info.required);
    }

    #[test]
    fn home_env_file_supplies_the_key() {
        let dir = tempdir().unwrap();
        // A unique account guarantees the lookup falls through to the home
        // `.env` even on a developer machine with a real Keychain entry for
        // the usual provider ids.
        std::fs::write(
            dir.path().join(".env"),
            "AUX_KEY_BAPI3KEYTEST=sk-test-value\n",
        )
        .unwrap();
        let info = key_info(
            dir.path(),
            &provider("bapi3keytest", Some("bapi3-unit-test-account")),
        );
        assert_eq!(info.present, Some(true));
        assert_eq!(info.location, "env");
    }

    #[test]
    fn a_missing_key_is_reported_missing_not_unknown() {
        let dir = tempdir().unwrap();
        let info = key_info(dir.path(), &provider("nope", None));
        assert_eq!(info.present, Some(false));
        assert!(!info.required);
    }

    #[test]
    fn host_port_parses_common_forms() {
        assert_eq!(
            host_port("https://api.deepseek.com/v1/chat/completions"),
            Some(("api.deepseek.com".to_string(), 443))
        );
        assert_eq!(
            host_port("http://127.0.0.1:1234/v1"),
            Some(("127.0.0.1".to_string(), 1234))
        );
        assert_eq!(
            host_port("https://user:pass@example.com:8443/v1"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(host_port("http://[::1]:9/v1"), Some(("::1".to_string(), 9)));
        assert_eq!(host_port("nonsense"), None);
    }

    #[test]
    fn loopback_probes_are_skipped_by_policy() {
        let probe = probe_base_url("http://127.0.0.1:9/v1/chat/completions");
        assert!(matches!(probe, Reachability::NotChecked { .. }));
    }

    #[test]
    fn invalid_base_url_is_a_validation_error_not_a_panic() {
        let result = test_provider(
            Path::new("/nonexistent-home"),
            Some("inline"),
            TestRequest {
                name: Some("inline".to_string()),
                base_url: Some("ftp://example.com".to_string()),
                model: Some("m".to_string()),
                ..TestRequest::default()
            },
        )
        .unwrap();
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert_eq!(result.key_present, None);
    }

    #[test]
    fn invalid_base_url_error_detail_redacts_url_credentials() {
        // B2-11: the validation error echoes the `base_url`; a credential in
        // its userinfo must not travel back in the error body.
        let result = test_provider(
            Path::new("/nonexistent-home"),
            Some("inline"),
            TestRequest {
                name: Some("inline".to_string()),
                base_url: Some(format!("http://{}@[", "CANARYE2EERR13")),
                model: Some("m".to_string()),
                ..TestRequest::default()
            },
        )
        .unwrap();
        assert!(!result.ok);
        let error = result.error.unwrap();
        assert!(!error.contains("CANARYE2EERR13"), "{error}");
        // An unparsable URL is not shown at all, only why.
        assert!(error.contains("base_url is not a valid URL"), "{error}");
    }

    #[test]
    fn test_reason_maps_each_bucket() {
        assert_eq!(test_reason(true, true, false, None), "ok");
        assert_eq!(
            test_reason(false, false, false, Some("no API key")),
            "bad_key"
        );
        assert_eq!(
            test_reason(false, true, true, Some("could not reach `x`")),
            "unreachable"
        );
        assert_eq!(
            test_reason(false, true, false, Some("model `x` was not found")),
            "model_not_found"
        );
        assert_eq!(test_reason(false, true, false, Some("weird")), "unknown");
    }

    #[test]
    fn parse_kind_accepts_both_spellings_and_rejects_junk() {
        let home = Path::new("/nonexistent-home");
        assert_eq!(parse_kind(home, None).unwrap(), ProviderKind::OpenAiCompat);
        assert_eq!(
            parse_kind(home, Some("openai_compat")).unwrap(),
            ProviderKind::OpenAiCompat
        );
        assert_eq!(parse_kind(home, Some("fake")).unwrap(), ProviderKind::Fake);
        assert_eq!(parse_kind(home, Some("acp")).unwrap(), ProviderKind::Acp);
        assert!(parse_kind(home, Some("grpc")).is_err());
    }

    #[test]
    fn private_network_base_url_is_refused_unless_local() {
        let openai = |url: &str| ProviderConfig {
            disable_thinking: false,
            id: "x".to_string(),
            base_url: url.to_string(),
            model: "m".to_string(),
            key_user: None,
            kind: ProviderKind::OpenAiCompat,
        };
        assert!(check_base_url_policy(&openai("https://192.168.1.10/v1")).is_err());
        assert!(check_base_url_policy(&openai("https://10.0.0.5/v1")).is_err());
        assert!(check_base_url_policy(&openai("https://172.16.5.5/v1")).is_err());
        assert!(check_base_url_policy(&openai("http://127.0.0.1:1234/v1")).is_ok());
        assert!(check_base_url_policy(&openai("https://api.deepseek.com/v1")).is_ok());

        let mut fake = openai("https://10.0.0.5/v1");
        fake.kind = ProviderKind::Fake;
        assert!(check_base_url_policy(&fake).is_ok());
    }

    #[test]
    fn a_key_in_a_private_base_url_is_redacted_in_the_policy_error() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let provider = ProviderConfig {
            disable_thinking: false,
            id: "x".to_string(),
            base_url: format!("https://10.0.0.5/v1/{key}"),
            model: "m".to_string(),
            key_user: None,
            kind: ProviderKind::OpenAiCompat,
        };
        let err = check_base_url_policy(&provider).unwrap_err();
        assert!(!err.to_lowercase().contains("canary"), "{err}");
        assert!(err.contains("<redacted>"), "{err}");
    }

    #[tokio::test]
    async fn provider_api_refuses_a_key_shaped_name_without_echoing_it() {
        let home = Path::new("/tmp/aux-provider-api-test");
        let db = Path::new("/tmp/aux-provider-api-test.db");
        let key = "sk-proj-canary-7f3k9q";

        let err = create_sync(
            &test_config_write(),
            home,
            db,
            CreateProviderRequest {
                name: Some(key.to_string()),
                kind: Some("fake".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some("m".to_string()),
                api_key: None,
            },
        )
        .unwrap_err();
        assert_refused(err).await;

        let err = update_key_sync(
            &test_config_write(),
            home,
            db,
            key,
            UpdateProviderKeyRequest {
                api_key: Some("sk-test-value".to_string()),
            },
        )
        .unwrap_err();
        assert_refused(err).await;

        let err = test_provider(home, Some(key), TestRequest::default()).unwrap_err();
        assert_refused(err).await;
    }

    #[test]
    fn create_sync_validates_stores_and_never_puts_the_key_in_config() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let canary = "sk-canary-unit-0123456789abcdef";

        let saved = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("acme".to_string()),
                kind: Some("openai_compat".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some("acme-1".to_string()),
                api_key: Some(canary.to_string()),
            },
        )
        .unwrap();
        assert_eq!(saved.name, "acme");
        assert!(saved.key_present);

        let config = std::fs::read_to_string(kernel_core::config_path(home)).unwrap();
        assert!(config.contains("[[providers]]"), "{config}");
        assert!(config.contains("id = \"acme\""), "{config}");
        assert!(
            !config.contains(canary),
            "the key leaked into config: {config}"
        );
        let env = std::fs::read_to_string(home.join(".env")).unwrap();
        assert!(env.contains(&format!("AUX_KEY_ACME={canary}")), "{env}");
        assert_eq!(
            aux_store::Store::open(&db)
                .unwrap()
                .event_count("provider.created")
                .unwrap(),
            1
        );

        // Duplicate, invalid scheme and private-network inputs are refused.
        let duplicate = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("acme".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some("acme-1".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
        let cleartext = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("bad".to_string()),
                base_url: Some("http://api.example.com/v1".to_string()),
                model: Some("m".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(cleartext.status(), StatusCode::BAD_REQUEST);
        let private = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("priv".to_string()),
                base_url: Some("https://10.1.2.3/v1".to_string()),
                model: Some("m".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(private.status(), StatusCode::BAD_REQUEST);
    }

    /// BRAINCONFIG-DEBUG: the audit row of a created provider names the
    /// provider and its model through the helpers, so a key pasted as the
    /// model never reaches the journal.
    #[test]
    fn the_provider_audit_row_never_shows_a_key_shaped_model() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let model = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();

        create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("acme".to_string()),
                kind: Some("openai_compat".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some(model.clone()),
                api_key: None,
            },
        )
        .unwrap();

        let payloads = aux_store::Store::open(&db)
            .unwrap()
            .event_payloads("provider.created")
            .unwrap();
        let payload = payloads.join("\n");
        assert!(!payload.to_lowercase().contains("canary"), "{payload}");
        // The row still names the provider: a hidden value is not an empty row.
        assert!(payload.contains("acme"), "{payload}");
    }

    #[test]
    fn create_sync_refuses_key_slot_collisions_without_overwriting() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();

        let first = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("Acme".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some("m".to_string()),
                api_key: Some("sk-first-secret".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap();
        assert!(first.key_present);

        // A case variant maps to the same AUX_KEY_* slot.
        let case = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("acme".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some("m".to_string()),
                api_key: Some("sk-second-secret".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(case.status(), StatusCode::CONFLICT);

        // A `-` vs `_` variant collides too.
        let dash = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("a-b".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some("m".to_string()),
                api_key: Some("sk-dash-secret".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap();
        assert!(dash.key_present);
        let underscore = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("a_b".to_string()),
                base_url: Some("https://api.example.com/v1".to_string()),
                model: Some("m".to_string()),
                api_key: Some("sk-underscore-secret".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(underscore.status(), StatusCode::CONFLICT);

        // The refused saves wrote nothing: the first secret survives and one
        // line remains per slot.
        let env = std::fs::read_to_string(home.join(".env")).unwrap();
        assert!(env.contains("AUX_KEY_ACME=sk-first-secret"), "{env}");
        assert!(!env.contains("sk-second-secret"), "{env}");
        assert!(env.contains("AUX_KEY_A_B=sk-dash-secret"), "{env}");
        assert!(!env.contains("sk-underscore-secret"), "{env}");
        assert_eq!(env.matches("AUX_KEY_ACME=").count(), 1, "{env}");
        assert_eq!(env.matches("AUX_KEY_A_B=").count(), 1, "{env}");
    }

    #[test]
    fn create_sync_refuses_a_key_for_a_fake_provider_without_writing_it() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let canary = "sk-fake-canary-0123456789abcdef";

        let refused = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("fakey".to_string()),
                kind: Some("fake".to_string()),
                base_url: Some("http://127.0.0.1:9/v1".to_string()),
                model: Some("fake-model".to_string()),
                api_key: Some(canary.to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(
            !home.join(".env").exists(),
            "a refused key must not leave an orphan .env"
        );
        assert!(
            !home.join("config.toml").exists(),
            "a refused provider must not be configured"
        );

        // Without a key the same entry saves and reports `key_present: false`.
        let saved = create_sync(
            &test_config_write(),
            home,
            &db,
            CreateProviderRequest {
                name: Some("fakey".to_string()),
                kind: Some("fake".to_string()),
                base_url: Some("http://127.0.0.1:9/v1".to_string()),
                model: Some("fake-model".to_string()),
                ..CreateProviderRequest::default()
            },
        )
        .unwrap();
        assert!(!saved.key_present);
        let snapshot = providers_snapshot(home).unwrap();
        let entry = snapshot.iter().find(|p| p.id == "fakey").unwrap();
        assert_eq!(entry.key_present, Some(false));
        assert!(!entry.key_required);
    }

    #[test]
    fn update_key_sync_stores_a_late_key_only_for_an_existing_provider() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();
        let canary = "sk-canary-unit-late-0123456789abcdef";

        // The provider is configured with a key_user but no key: the dead
        // end the update route fixes.
        std::fs::write(
            kernel_core::config_path(home),
            "version = 1\ndefault_agent = \"main\"\n\n\
             [[providers]]\nid = \"late\"\nbase_url = \"https://api.example.com/v1\"\n\
             model = \"m\"\nkey_user = \"late\"\nkind = \"openai-compat\"\n\n\
             [[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
             model = \"fake-model\"\nkind = \"fake\"\n",
        )
        .unwrap();
        let snapshot = providers_snapshot(home).unwrap();
        let entry = snapshot.iter().find(|p| p.id == "late").unwrap();
        assert_eq!(entry.key_present, Some(false));
        assert!(
            entry.key_required,
            "an openai-compat entry with key_user needs a key"
        );

        let saved = update_key_sync(
            &test_config_write(),
            home,
            &db,
            "late",
            UpdateProviderKeyRequest {
                api_key: Some(canary.to_string()),
            },
        )
        .unwrap();
        assert_eq!(saved.name, "late");
        assert!(saved.key_present);

        // The key is in `.env` only; config.toml is untouched.
        let env = std::fs::read_to_string(home.join(".env")).unwrap();
        assert!(env.contains(&format!("AUX_KEY_LATE={canary}")), "{env}");
        let config = std::fs::read_to_string(kernel_core::config_path(home)).unwrap();
        assert_eq!(config.matches("[[providers]]").count(), 2, "{config}");
        assert!(
            !config.contains(canary),
            "the key leaked into config: {config}"
        );
        assert_eq!(
            aux_store::Store::open(&db)
                .unwrap()
                .event_count("provider.key_updated")
                .unwrap(),
            1
        );

        // Unknown provider: 404, and nothing new is written.
        let ghost = update_key_sync(
            &test_config_write(),
            home,
            &db,
            "ghost",
            UpdateProviderKeyRequest {
                api_key: Some(canary.to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(ghost.status(), StatusCode::NOT_FOUND);

        // A missing / blank key is a clean 400.
        let blank = update_key_sync(
            &test_config_write(),
            home,
            &db,
            "late",
            UpdateProviderKeyRequest {
                api_key: Some("   ".to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(blank.status(), StatusCode::BAD_REQUEST);

        // A kind that takes no key is refused, and its secret never lands.
        let fake = update_key_sync(
            &test_config_write(),
            home,
            &db,
            "fakey",
            UpdateProviderKeyRequest {
                api_key: Some(canary.to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(fake.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn update_key_sync_refuses_a_key_slot_collision_without_overwriting() {
        let dir = tempdir().unwrap();
        let home = dir.path();
        let db = home.join("store.db");
        aux_store::Store::open(&db).unwrap();

        // A hand-edited config can hold two ids that share one AUX_KEY_* slot;
        // the loader accepts it, so the update route must refuse the pair.
        std::fs::write(
            kernel_core::config_path(home),
            "version = 1\ndefault_agent = \"main\"\n\n\
             [[providers]]\nid = \"Acme\"\nbase_url = \"https://api.example.com/v1\"\n\
             model = \"m\"\nkind = \"openai-compat\"\n\n\
             [[providers]]\nid = \"acme\"\nbase_url = \"https://api.example.com/v1\"\n\
             model = \"m\"\nkind = \"openai-compat\"\n",
        )
        .unwrap();

        let refused = update_key_sync(
            &test_config_write(),
            home,
            &db,
            "acme",
            UpdateProviderKeyRequest {
                api_key: Some("sk-canary-unit-collision-0123456789abcdef".to_string()),
            },
        )
        .unwrap_err();
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        assert!(
            !home.join(".env").exists(),
            "a refused key write must leave no orphan .env"
        );
    }
}
