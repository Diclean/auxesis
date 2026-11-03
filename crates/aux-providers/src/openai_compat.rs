//! OpenAI-compatible chat adapter.
//!
//! Covers every endpoint that speaks the OpenAI `chat/completions` wire:
//! DeepSeek, LM Studio, OpenRouter, Ollama, … `.complete` is
//! the plain one-body call; `.complete_streaming` uses SSE with a transparent
//! fallback to the plain path when the endpoint signals streaming is
//! unsupported. The streaming path is bounded by two timeouts, not one:
//! `DEFAULT_TIMEOUT` is the connect and idle-read budget (H-10), while one
//! request is still capped overall at [`STREAM_TOTAL_TIMEOUT_FACTOR`] × that
//! (F-08). The fallback is chosen from structured error fields only, never
//! from a substring of the body (F-11).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::config::{chat_completions_url, shown_base_url, shown_id_plain, ProviderConfig};
use crate::error::{redact_upstream, ProviderError};
use crate::key;
use crate::preset::OLLAMA_PROVIDER_ID;
use crate::provider::{report_response, ChatProvider};
use crate::types::{
    assembled_arguments, ChatDelta, ChatMessage, ChatRequest, ChatResponse, ChatRole, SafeMessage,
    SafeToolSpec, ToolCall, Usage,
};

/// Default request timeout for chat completions.
///
/// For a non-streaming call this bounds the whole request. For a streaming
/// call it is the *idle* timeout: the time allowed between two reads (H-10),
/// so a long answer is never cut mid-stream just because it takes longer
/// than this in total. One stream is still bounded overall by
/// [`STREAM_TOTAL_TIMEOUT_FACTOR`] × this: a server that keeps dribbling
/// bytes inside the idle window cannot hold the turn forever (F-08).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Overall deadline for one streamed completion, as a multiple of the
/// configured connect/idle timeout: `read_timeout` resets on every read, so
/// on its own it cannot bound a server that dribbles one byte at a time. The
/// streaming request therefore also carries `timeout × this` as a total
/// budget (F-08). With the default [`DEFAULT_TIMEOUT`] that is 20 minutes —
/// generous for a long answer and still finite.
pub const STREAM_TOTAL_TIMEOUT_FACTOR: u32 = 10;

/// Hard ceiling for the bytes buffered for one stream body (F-09): at most
/// this many bytes may sit in `pending` (one newline-less SSE line, F-05)
/// and the same cap bounds the pre-choice recovery copy in `raw` (F-06).
/// One named ceiling for both buffers, bounded well above any legitimate
/// chat delta.
const MAX_STREAM_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Stable error-code prefix used whenever a stream cap refuses the body: the
/// caller sees `stream_too_large` instead of a silently truncated answer
/// (F-06, UNB-01). Every stream ceiling shares this one code so a caller can
/// tell a hostile/looping endpoint from a genuine parse failure.
const STREAM_TOO_LARGE: &str = "stream_too_large";

/// Hard ceiling on the assistant text assembled for one streamed turn
/// (UNB-01). `raw` is freed after the first choice (F-05) and the per-line cap
/// is 4 MiB, so without this a hostile or looping endpoint could grow
/// `content` without bound for the whole stream budget (20 min by default).
/// 1 MiB is far above any legitimate answer; crossing it ends the stream with
/// `stream_too_large`.
const MAX_STREAM_CONTENT_BYTES: usize = 1024 * 1024;

/// Hard ceiling on the argument bytes assembled for one streamed tool call
/// (UNB-01). Arguments are a JSON document split across deltas; 256 KiB is
/// already implausible for a real call. Crossing it ends the stream with
/// `stream_too_large` *before* `finish`, so no partial call is emitted.
const MAX_STREAM_TOOL_ARGUMENT_BYTES: usize = 256 * 1024;

/// Hard ceiling on the number of distinct tool calls in one streamed message
/// (UNB-01). Every new `delta.tool_calls[].index` used to insert an entry in
/// `tool_calls`; 64 distinct calls is well above any legitimate model turn.
const MAX_STREAM_TOOL_CALLS: usize = 64;

/// Hard ceiling on the function-name bytes assembled for one streamed tool
/// call (UNB-01, same unbounded-growth class as the arguments). Names are
/// identifiers; 4 KiB is generous. Crossing it ends the stream with
/// `stream_too_large`.
const MAX_STREAM_TOOL_NAME_BYTES: usize = 4 * 1024;

/// Adapter for OpenAI-compatible `/chat/completions` endpoints.
///
/// The API key is resolved at construction time (Keychain first, environment
/// fallback) and never written anywhere. `Debug` redacts it.
pub struct OpenAiCompat {
    id: String,
    endpoint: String,
    model: String,
    api_key: Option<String>,
    /// Client for one-body calls: the configured timeout bounds the whole
    /// request.
    http: Client,
    /// Client for SSE calls: connect timeout plus an *idle* read timeout, no
    /// client-wide total timeout, so an answer longer than `DEFAULT_TIMEOUT`
    /// keeps streaming while a stalled socket still fails (H-10). The
    /// per-request overall deadline `stream_total_timeout` is applied on the
    /// request itself instead.
    http_stream: Client,
    /// Overall deadline per streamed request (F-08).
    stream_total_timeout: Duration,
    /// Send DeepSeek's thinking toggle (`ProviderConfig::disable_thinking`).
    disable_thinking: bool,
    /// The endpoint once refused a tool-call row without `reasoning_content`
    /// (DeepSeek thinking mode): later requests send the empty field at once.
    backfills_reasoning: AtomicBool,
    /// Built from a local runtime entry (the `ollama` kind); see
    /// [`ChatProvider::on_this_mac`].
    local_runtime: bool,
    /// Both clients were built with no proxy (loopback endpoint).
    direct: bool,
}

impl OpenAiCompat {
    /// Mark the adapter as a local runtime (the `ollama` kind).
    pub fn local_runtime(mut self) -> Self {
        self.local_runtime = true;
        self
    }

    /// Build the adapter for a config entry, resolving the API key from the
    /// Keychain or `AUX_KEY_<UPPER_ID>`.
    pub fn new(config: &ProviderConfig) -> Result<Self, ProviderError> {
        let api_key = key::resolve_key(&config.id, config.key_user.as_deref())?;
        Self::with_key_and_timeout(config, api_key, DEFAULT_TIMEOUT)
    }

    /// Build the adapter with an explicit API key (tests, key onboarding).
    pub fn with_key(
        config: &ProviderConfig,
        api_key: Option<String>,
    ) -> Result<Self, ProviderError> {
        Self::with_key_and_timeout(config, api_key, DEFAULT_TIMEOUT)
    }

    /// Build the adapter with an explicit API key and request timeout.
    ///
    /// `timeout` bounds a non-streaming request in total. The streaming path
    /// gets a separate client where `timeout` is the connection and idle-read
    /// budget only: a long answer must not be cut mid-stream (H-10). Each
    /// streamed request still carries `timeout × STREAM_TOTAL_TIMEOUT_FACTOR`
    /// as an overall deadline, so a trickling keep-alive endpoint is bounded
    /// as well (F-08).
    pub fn with_key_and_timeout(
        config: &ProviderConfig,
        api_key: Option<String>,
        timeout: Duration,
    ) -> Result<Self, ProviderError> {
        config.validate()?;
        // H-04/L-1: every key this process resolves (Keychain, `.env`,
        // process environment) joins the exact-value scrubber, so a key
        // that later reaches a log line, a tool argument or a preview is
        // redacted without needing a credential-shaped name next to it.
        // The value is never logged; registration is idempotent.
        if let Some(key) = &api_key {
            kernel_broker::scrub::register_known_secret(key);
        }
        let endpoint = chat_completions_url(&config.base_url)?;
        // security-review round 2, P2: never follow a redirect. A 3xx from the
        // configured origin would otherwise forward the key and the prompt to
        // another host; the response is surfaced as a provider error instead.
        // A loopback endpoint is reached directly, never through a system or
        // `*_PROXY` proxy that could forward the prompt off this Mac.
        let direct = crate::config::is_loopback_url(&config.base_url);
        let builder = || match direct {
            true => Client::builder().no_proxy(),
            false => Client::builder(),
        };
        let http = builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(client_error)?;
        let http_stream = builder()
            .connect_timeout(timeout)
            .read_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(client_error)?;
        Ok(Self {
            id: config.id.clone(),
            disable_thinking: config.disable_thinking,
            backfills_reasoning: AtomicBool::new(false),
            local_runtime: false,
            direct,
            endpoint,
            model: config.model.clone(),
            api_key,
            http,
            http_stream,
            stream_total_timeout: timeout.saturating_mul(STREAM_TOTAL_TIMEOUT_FACTOR),
        })
    }

    /// Full URL called for chat completions.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// `req` with its reasoning backfilled, once this endpoint has asked for it.
    fn known_backfill(&self, req: &ChatRequest) -> Option<ChatRequest> {
        if self.backfills_reasoning.load(Ordering::Relaxed) {
            backfill_reasoning(&self.id, req)
        } else {
            None
        }
    }

    /// FOLLOWUP-REASONING-400: the request to re-send when the endpoint refused
    /// `req` for a tool-call row without `reasoning_content` (DeepSeek thinking
    /// mode), and that row can be backfilled. The endpoint gets the empty field
    /// from then on. `None` otherwise, so a refusal is re-sent at most once.
    fn refused_backfill(
        &self,
        req: &ChatRequest,
        status: reqwest::StatusCode,
        body: &str,
    ) -> Option<ChatRequest> {
        if status != reqwest::StatusCode::BAD_REQUEST || !body.contains("reasoning_content") {
            return None;
        }
        let filled = backfill_reasoning(&self.id, req)?;
        self.backfills_reasoning.store(true, Ordering::Relaxed);
        tracing::info!(
            provider = %shown_id_plain(&self.id),
            status = status.as_u16(),
            "a tool call without reasoning was refused; sending an empty reasoning"
        );
        Some(filled)
    }
}

/// `req` with an empty reasoning from `provider` on each assistant tool-call
/// row since the last user message that carries none for it: DeepSeek thinking
/// mode refuses those rows without the field, and the engine writes some itself
/// (FOLLOWUP-READ-FIRST's pre-read). Earlier turns are left as they are. `None`
/// when no row needs it.
fn backfill_reasoning(provider: &str, req: &ChatRequest) -> Option<ChatRequest> {
    let turn = req
        .messages
        .iter()
        .rposition(|message| message.role() == ChatRole::User)
        .map_or(0, |index| index + 1);
    let mut messages = req.messages.as_ref().clone();
    let mut filled = false;
    for message in &mut messages[turn..] {
        if let Some(backfilled) = message.with_empty_reasoning_for(provider) {
            *message = backfilled;
            filled = true;
        }
    }
    filled.then(|| ChatRequest {
        messages: std::sync::Arc::new(messages),
        ..req.clone()
    })
}

impl fmt::Debug for OpenAiCompat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiCompat")
            .field("id", &shown_id_plain(&self.id))
            .field("endpoint", &shown_base_url(&self.endpoint))
            .field("model", &shown_id_plain(&self.model))
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[async_trait]
impl ChatProvider for OpenAiCompat {
    fn on_this_mac(&self) -> bool {
        // Ollama serves `*:cloud` / `*-cloud` models through localhost: any
        // `cloud` in the model name means the prompt may leave.
        self.local_runtime && self.direct && !self.model.to_ascii_lowercase().contains("cloud")
    }

    fn endpoint_host(&self) -> Option<String> {
        reqwest::Url::parse(&self.endpoint)
            .ok()?
            .host_str()
            .map(str::to_string)
    }

    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let filled = self.known_backfill(req);
        let req = filled.as_ref().unwrap_or(req);
        let payload = WireRequest {
            model: req
                .model
                .as_ref()
                .map_or(self.model.as_str(), |model| model.as_str()),
            messages: &messages_for(&self.id, req.messages.as_slice()),
            temperature: req.temperature,
            max_tokens: req.max_tokens,
            tools: (!req.tools.is_empty()).then_some(req.tools.as_slice()),
            tool_choice: wire_tool_choice(req),
            thinking: wire_thinking(self.disable_thinking),
        };

        let response = self
            .send_request(&self.http, &payload, &self.id)?
            .send()
            .await
            .map_err(|err| request_error(&self.id, err))?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(parse_retry_after);
        let body = response
            .text()
            .await
            .map_err(|err| request_error(&self.id, err))?;

        if !status.is_success() {
            if let Some(filled) = self.refused_backfill(req, status, &body) {
                return self.complete(&filled).await;
            }
            if let Some(next) = tool_choice_downgrade(req, status, &body) {
                log_tool_choice_downgrade(&self.id, status, &next);
                let mut plain = req.clone();
                plain.tool_choice = Some(next);
                return self.complete(&plain).await;
            }
            return Err(status_error(
                &self.id,
                status,
                retry_after,
                &body,
                self.api_key.as_deref(),
            ));
        }

        parse_response(&self.id, &body)
    }

    async fn complete_streaming(
        &self,
        req: &ChatRequest,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        let filled = self.known_backfill(req);
        let req = filled.as_ref().unwrap_or(req);
        let payload = WireStreamRequest {
            model: req
                .model
                .as_ref()
                .map_or(self.model.as_str(), |model| model.as_str()),
            messages: &messages_for(&self.id, req.messages.as_slice()),
            temperature: req.temperature,
            max_tokens: req.max_tokens,
            tools: (!req.tools.is_empty()).then_some(req.tools.as_slice()),
            tool_choice: wire_tool_choice(req),
            thinking: wire_thinking(self.disable_thinking),
            stream: true,
            // Ask OpenAI-compatible gateways that support it for a `usage`
            // object in the final chunk; gateways that reject the field make
            // the request fail before any delta, and the non-streaming
            // fallback below re-runs it without streaming.
            stream_options: Some(StreamOptions {
                include_usage: true,
            }),
        };

        let mut response = self
            .send_request(&self.http_stream, &payload, &self.id)?
            // The client has no total timeout (H-10); the request carries
            // the larger overall deadline itself, so a byte-dribbling
            // keep-alive endpoint is still cut off (F-08).
            .timeout(self.stream_total_timeout)
            .send()
            .await
            .map_err(|err| request_error(&self.id, err))?;
        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(parse_retry_after);
            let body = response
                .text()
                .await
                .map_err(|err| request_error(&self.id, err))?;
            if let Some(filled) = self.refused_backfill(req, status, &body) {
                return self.complete_streaming(&filled, sink).await;
            }
            if let Some(next) = tool_choice_downgrade(req, status, &body) {
                log_tool_choice_downgrade(&self.id, status, &next);
                let mut plain = req.clone();
                plain.tool_choice = Some(next);
                return self.complete_streaming(&plain, sink).await;
            }
            if stream_unsupported(status, &body) {
                // The endpoint itself refused streaming — a refusal status
                // whose *parsed* body names the `stream`/`stream_options`
                // parameter (F-11/F-14), not a genuine request error. The
                // response body has not been read as SSE yet, so no delta can
                // have been shown: the honest fallback is the plain path and
                // no re-send can ever happen after a visible delta. The
                // fallback stays inside this one `complete_streaming` call:
                // the caller's budget reservation for the round is settled
                // exactly once whether the answer came from SSE or from the
                // plain re-send (H-10).
                tracing::info!(
                    provider = %shown_id_plain(&self.id),
                    status = status.as_u16(),
                    "streaming refused; falling back to a non-streaming completion"
                );
                let response = self.complete(req).await?;
                report_response(&response, sink);
                return Ok(response);
            }
            return Err(status_error(
                &self.id,
                status,
                retry_after,
                &body,
                self.api_key.as_deref(),
            ));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if content_type.contains("application/json") {
            // The server ignored `stream: true` and answered with one JSON
            // body: parse it as the non-streaming response.
            let body = response
                .text()
                .await
                .map_err(|err| request_error(&self.id, err))?;
            return parse_response(&self.id, &body);
        }

        let mut assembler = StreamAssembler::new(&self.id);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| request_error(&self.id, err))?
        {
            assembler.push(&chunk, sink)?;
            if assembler.saw_done() {
                // `[DONE]` closes the stream: stop reading now. A keep-alive
                // endpoint that holds the socket open after the terminator
                // must not make the turn wait out the idle timeout and throw
                // away an already complete answer (F-08).
                break;
            }
        }
        assembler.finish(sink)
    }

    fn name(&self) -> &str {
        &self.id
    }

    fn model(&self) -> Option<&str> {
        Some(&self.model)
    }
}

impl OpenAiCompat {
    /// Build a POST request with the adapter's auth header applied, or a
    /// config error when the configured key cannot be a header value.
    fn send_request<T: Serialize>(
        &self,
        client: &Client,
        payload: &T,
        provider: &str,
    ) -> Result<reqwest::RequestBuilder, ProviderError> {
        let mut builder = client.post(&self.endpoint).json(payload);
        if let Some(api_key) = &self.api_key {
            let value = HeaderValue::from_str(&format!("Bearer {api_key}")).map_err(|_| {
                ProviderError::Config(crate::config::ConfigError::Invalid(format!(
                    "provider `{}`: API key is not a valid HTTP header value",
                    shown_id_plain(provider)
                )))
            })?;
            builder = builder.header(AUTHORIZATION, value);
        }
        Ok(builder)
    }
}

/// Map a client-construction failure to a config error.
fn client_error(err: reqwest::Error) -> ProviderError {
    ProviderError::Config(crate::config::ConfigError::Invalid(format!(
        "building HTTP client: {}",
        err.without_url()
    )))
}

#[derive(Serialize)]
struct WireRequest<'a> {
    model: &'a str,
    messages: &'a [SafeMessage],
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<&'a [SafeToolSpec]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<serde_json::Value>,
}

/// The wire `tool_choice` of a request that asks for one and offers tools:
/// the named-function object, or the string `required` or `auto`.
fn wire_tool_choice(req: &ChatRequest) -> Option<serde_json::Value> {
    if req.tools.is_empty() {
        return None;
    }
    req.tool_choice.as_ref().map(|choice| match choice {
        crate::types::ToolChoice::Function(name) => {
            serde_json::json!({ "type": "function", "function": { "name": name } })
        }
        crate::types::ToolChoice::Required => serde_json::json!("required"),
        crate::types::ToolChoice::Auto => serde_json::json!("auto"),
    })
}

/// DeepSeek's documented thinking toggle, sent only when the provider config
/// asks for it (https://api-docs.deepseek.com/api/create-chat-completion).
fn wire_thinking(disable: bool) -> Option<serde_json::Value> {
    if disable {
        Some(serde_json::json!({ "type": "disabled" }))
    } else {
        None
    }
}

#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    choices: Vec<WireChoice>,
    /// OpenAI-compatible endpoints return `{"prompt_tokens": …,
    /// "completion_tokens": …}` here; some omit it entirely.
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct WireChoice {
    message: WireMessage,
}

#[derive(Deserialize)]
struct WireMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ToolCall>,
    /// DeepSeek thinking mode: the reasoning text, to be sent back.
    #[serde(default)]
    reasoning_content: Option<String>,
}

#[derive(Serialize)]
struct WireStreamRequest<'a> {
    model: &'a str,
    messages: &'a [SafeMessage],
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<&'a [SafeToolSpec]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<serde_json::Value>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<StreamOptions>,
}

/// OpenAI's `stream_options` object.
#[derive(Serialize)]
struct StreamOptions {
    include_usage: bool,
}

/// One `data:` payload of an SSE chunk.
#[derive(Deserialize, Default)]
struct StreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct StreamChoice {
    #[serde(default)]
    delta: StreamDelta,
}

#[derive(Deserialize, Default)]
struct StreamDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<StreamToolCall>,
}

#[derive(Deserialize)]
struct StreamToolCall {
    #[serde(default)]
    index: usize,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<StreamFunction>,
}

#[derive(Deserialize)]
struct StreamFunction {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

/// A tool call being assembled from `delta.tool_calls` fragments.
#[derive(Default)]
struct PartialToolCall {
    id: Option<String>,
    name: String,
    arguments: String,
}

/// True for HTTP statuses that can carry a "this endpoint does not serve
/// SSE" refusal rather than a real request error.
const STREAM_REFUSAL_STATUSES: [u16; 6] = [400, 404, 405, 415, 422, 501];

/// `error.code` / `error.type` values that mean "the provider rejected a
/// request parameter". Documented allowlist (F-11): every entry must mean a
/// parameter was not accepted, never a generic bad request, and it is only
/// trusted together with a message that names the stream field as an
/// identifier (or a structured `param`/`loc`, which is a signal on its own).
/// Adding an entry here widens what can trigger the fallback, so keep it
/// short.
const PARAMETER_REFUSAL_CODES: [&str; 4] = [
    "unsupported_parameter",
    "unknown_parameter",
    "unsupported_parameter_value",
    "unknown_field",
];

/// Short, exact provider messages that are themselves a stream refusal.
/// Matched case-insensitively after trimming, and only as a *whole* message:
/// a long body that merely mentions streaming (an HTML page, an `upstream`
/// error) must not match (F-11). `not implemented` recovers the canonical
/// `501 Not Implemented` shape (F-14).
const KNOWN_STREAM_REFUSALS: [&str; 10] = [
    "not implemented",
    "sse is not supported",
    "sse not supported",
    "stream is not supported",
    "stream not enabled",
    "stream not supported",
    "stream unsupported",
    "streaming is not supported",
    "streaming not enabled",
    "streaming not supported",
];

/// Narrow parameter-refusal phrasings (F-16) trusted only together with a
/// token-level mention of `stream`/`stream_options`: "Unknown name
/// \"stream_options\": Cannot find field.", "Extra inputs are not permitted:
/// stream_options", "messages: unexpected keyword argument \"stream\"",
/// "Invalid value for 'stream': must be a boolean". Deliberately not generic
/// error words (`invalid`, `unknown` alone), so the F-11 negatives — e.g.
/// `Invalid api key: 'stream'` — stay genuine errors.
const PARAMETER_REFUSAL_PHRASES: [&str; 5] = [
    "cannot find field",
    "extra inputs are not permitted",
    "invalid value for",
    "unexpected keyword argument",
    "unknown name",
];

/// A whole-message statement that the *stream capability* is unsupported
/// (vLLM: "This model does not support streaming"). Unlike the parameter
/// phrasings this names streaming itself, so no separate token test is
/// needed; it cannot appear in an error that merely mentions streaming.
const STREAM_CAPABILITY_REFUSALS: [&str; 1] = ["does not support streaming"];

/// True when a failed streaming request was refused *because the endpoint
/// does not speak SSE*, not because the request itself is invalid.
///
/// The status alone cannot tell those apart: `400` and `422` are ordinary
/// request-error codes, so the error body must name the stream parameter in
/// a *structured* way (F-11/F-14). The decision never uses
/// `body.contains("stream")`:
///
/// - a JSON body is parsed; the stream parameter must appear as OpenAI's
///   `error.param`, a FastAPI `detail[].loc` entry, or the whole message must
///   be one of [`KNOWN_STREAM_REFUSALS`];
/// - an allowlisted [`PARAMETER_REFUSAL_CODES`] `code`/`type` counts only
///   when the message names `stream`/`stream_options` as an identifier
///   (`unknown parameter: stream_options`);
/// - a non-JSON body counts only when it *is* one of the known refusals;
/// - `upstream`/`downstream` prose, a quoted `"stream"` key in an unrelated
///   JSON document and HTML error pages never match.
///
/// A genuine `400` ("model not found") surfaces untouched and is never
/// re-sent, so one turn never bills two attempts (H-10).
fn stream_unsupported(status: reqwest::StatusCode, body: &str) -> bool {
    STREAM_REFUSAL_STATUSES.contains(&status.as_u16()) && stream_refusal_signal(body)
}

/// The less specific `tool_choice` an endpoint that refused this request accepts
/// instead: a `400` whose body names `tool_choice`, on a request that asked for
/// one. `None` when the request asked for no choice, or `auto` was refused.
fn tool_choice_downgrade(
    req: &ChatRequest,
    status: reqwest::StatusCode,
    body: &str,
) -> Option<crate::types::ToolChoice> {
    let current = req.tool_choice.as_ref()?;
    if status != reqwest::StatusCode::BAD_REQUEST || !body.contains("tool_choice") {
        return None;
    }
    current.step_down()
}

/// Log one step of a refused `tool_choice`: the first refusal of a named tool is
/// a warning; a later step is informational.
fn log_tool_choice_downgrade(
    provider: &str,
    status: reqwest::StatusCode,
    next: &crate::types::ToolChoice,
) {
    let provider = shown_id_plain(provider);
    if *next == crate::types::ToolChoice::Required {
        tracing::warn!(
            provider = %provider,
            status = status.as_u16(),
            "the named tool_choice was refused; sending required"
        );
    } else {
        tracing::info!(
            provider = %provider,
            status = status.as_u16(),
            "the tool_choice was refused; sending auto"
        );
    }
}

/// Extract the structured stream refusal from a body, if any.
fn stream_refusal_signal(body: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(value) => json_stream_refusal(&value),
        Err(_) => known_stream_refusal(body),
    }
}

fn json_stream_refusal(value: &serde_json::Value) -> bool {
    let error = value.get("error");

    // OpenAI names the rejected field in `error.param`; FastAPI names it in
    // `detail[].loc`. Either is a signal on its own.
    if let Some(param) = error
        .and_then(|error| error.get("param"))
        .and_then(serde_json::Value::as_str)
    {
        if names_stream_parameter(param) {
            return true;
        }
    }
    if let Some(detail) = value.get("detail") {
        if detail_loc_names_stream_parameter(detail) {
            return true;
        }
    }

    // Message candidates across the parse shapes: OpenAI `error.message`, an
    // Anthropic-style `error.message`, a plain `error` string, a top-level
    // `message`, or a FastAPI string `detail`.
    let message = match error {
        Some(serde_json::Value::Object(object)) => object
            .get("message")
            .and_then(serde_json::Value::as_str)
            .or_else(|| value.get("message").and_then(serde_json::Value::as_str)),
        Some(serde_json::Value::String(text)) => Some(text.as_str()),
        _ => value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .or_else(|| value.get("detail").and_then(serde_json::Value::as_str)),
    };

    // A canonical short refusal is a signal by itself.
    if message.is_some_and(known_stream_refusal) {
        return true;
    }

    // An allowlisted parameter-refusal code/type is trusted only when the
    // message names the stream field as an identifier (`unknown parameter
    // stream_options`), never on prose.
    let code = error
        .and_then(|error| error.get("code"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            error
                .and_then(|error| error.get("type"))
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| value.get("code").and_then(serde_json::Value::as_str))
        .or_else(|| value.get("type").and_then(serde_json::Value::as_str));
    if let Some(code) = code {
        if PARAMETER_REFUSAL_CODES.contains(&code.to_ascii_lowercase().as_str())
            && message.is_some_and(message_names_stream_parameter)
        {
            return true;
        }
    }

    // F-16: realistic parameter refusals are often phrased without a
    // structured `param`/`loc` or an allowlisted code. The message must both
    // name the stream field as an identifier and state a narrow
    // parameter-refusal phrase; `Invalid api key: 'stream'` and prose that
    // merely mentions streaming stay untouched (F-11).
    if let Some(message) = message {
        let lowered = message.to_ascii_lowercase();
        if message_names_stream_parameter(message)
            && PARAMETER_REFUSAL_PHRASES
                .iter()
                .any(|phrase| lowered.contains(phrase))
        {
            return true;
        }
        if STREAM_CAPABILITY_REFUSALS
            .iter()
            .any(|phrase| lowered.contains(phrase))
        {
            return true;
        }
    }

    false
}

/// True when a structured `param` or FastAPI `loc` value names the request's
/// stream field: exactly `stream`, or any `stream_*` parameter
/// (`stream_options`). Exact names keep `upstream`, `downstream` and
/// `streaming_model_v2` out (F-11).
fn names_stream_parameter(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value == "stream" || value.starts_with("stream_")
}

/// True when a message names the stream field as a *token*, e.g.
/// `unknown parameter: stream_options`. Token equality — never a `contains`
/// test — is what keeps `upstream`/`downstream` prose out (F-11).
fn message_names_stream_parameter(message: &str) -> bool {
    message
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(names_stream_parameter)
}

/// True only when the message *is* one of the known short stream refusals,
/// not when it merely mentions streaming somewhere (F-11).
fn known_stream_refusal(message: &str) -> bool {
    let message = message.trim().to_ascii_lowercase();
    KNOWN_STREAM_REFUSALS.contains(&message.as_str())
}

/// True when a FastAPI validation `detail` payload names the stream field in
/// any `loc` entry. `detail` is normally an array of error items but some
/// proxies return a single object; both are handled.
fn detail_loc_names_stream_parameter(detail: &serde_json::Value) -> bool {
    match detail {
        serde_json::Value::Array(items) => items.iter().any(loc_names_stream_parameter),
        item => loc_names_stream_parameter(item),
    }
}

fn loc_names_stream_parameter(item: &serde_json::Value) -> bool {
    item.get("loc")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|loc| {
            loc.iter()
                .any(|entry| entry.as_str().is_some_and(names_stream_parameter))
        })
}

/// Strip leading transport noise from one SSE line: any number of UTF-8 BOMs
/// (a gateway may double one, F-12) interleaved with ASCII spaces/tabs (a
/// gateway may pad the field name: `\u{FEFF} data: …`). Only the line head is
/// touched; the payload keeps its bytes.
fn trim_line_noise(mut line: &[u8]) -> &[u8] {
    loop {
        if let Some(rest) = line.strip_prefix(b"\xEF\xBB\xBF") {
            line = rest;
        } else if let Some(rest) = line.strip_prefix(b" ").or_else(|| line.strip_prefix(b"\t")) {
            line = rest;
        } else {
            return line;
        }
    }
}

/// True when one line is the `[DONE]` terminator, whatever cosmetic noise it
/// carries: any BOM/padding, any casing, surrounding whitespace, and a
/// trailing CR. Used both for newline-terminated lines and for the final
/// unterminated line, so `data: [DONE]` with no line terminator still ends
/// the read loop instead of stalling out the idle timeout (F-15).
fn done_line(line: &[u8]) -> bool {
    let line = trim_line_noise(line);
    let Some(payload) = line.strip_prefix(b"data:") else {
        return false;
    };
    let payload = payload.strip_prefix(b" ").unwrap_or(payload);
    payload.trim_ascii().eq_ignore_ascii_case(b"[DONE]")
}

/// Refuse an over-cap stream body with the stable `stream_too_large` code
/// instead of truncating it silently (F-06/F-09).
fn stream_too_large(provider: &str, detail: impl fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse {
        provider: shown_id_plain(provider),
        message: format!("{STREAM_TOO_LARGE}: {detail}"),
    }
}

/// Incremental SSE assembler for OpenAI-compatible streams.
///
/// Reads raw bytes chunk by chunk (a UTF-8 character or a `data:` line may be
/// split anywhere), keeps only complete lines, and reassembles the final
/// [`ChatResponse`] from the deltas. Text deltas are reported as they are
/// parsed; tool calls and usage once the stream ends.
struct StreamAssembler {
    provider: String,
    /// Bytes not yet terminated by `\n` (may include a partial line).
    pending: Vec<u8>,
    /// Raw bytes seen before the first choice, for the "server ignored
    /// `stream:true`" recovery; dropped once a choice arrives (F-05) and
    /// capped at [`MAX_STREAM_BODY_BYTES`] while it is still live (F-06).
    raw: Vec<u8>,
    content: String,
    /// Reasoning text, kept to send back; never emitted to the sink.
    reasoning: String,
    /// A delta carried `reasoning_content` (even `""`): the reply has a
    /// reasoning to send back, empty or not.
    saw_reasoning: bool,
    tool_calls: BTreeMap<usize, PartialToolCall>,
    usage: Option<Usage>,
    saw_choice: bool,
    saw_done: bool,
}

impl StreamAssembler {
    fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            pending: Vec::new(),
            raw: Vec::new(),
            content: String::new(),
            reasoning: String::new(),
            saw_reasoning: false,
            tool_calls: BTreeMap::new(),
            usage: None,
            saw_choice: false,
            saw_done: false,
        }
    }

    /// Feed one body chunk, emitting text deltas as lines complete.
    fn push(
        &mut self,
        bytes: &[u8],
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<(), ProviderError> {
        if self.saw_done {
            // `[DONE]` closes the event stream; everything after it is inert
            // and is not even copied, so a post-`[DONE]` flood cannot grow
            // the buffers (mutation survivors m2/m5).
            return Ok(());
        }
        // `raw` exists only for the "server ignored `stream: true`" recovery
        // in `finish`; once a choice has been seen that path is unreachable,
        // so the whole-body copy must not keep growing (F-05). While it is
        // live it is capped like `pending`: a hostile endpoint can send many
        // short *complete* lines that never grow `pending` and would
        // otherwise retain the whole body here (F-06). Crossing the cap is
        // refused outright — a silently truncated copy would later surface
        // as a confusing parse error (F-06/F-09).
        if !self.saw_choice {
            let room = MAX_STREAM_BODY_BYTES.saturating_sub(self.raw.len());
            if bytes.len() > room {
                return Err(stream_too_large(
                    &self.provider,
                    format!(
                        "pre-choice body exceeds {MAX_STREAM_BODY_BYTES} bytes before any completion data"
                    ),
                ));
            }
            self.raw.extend_from_slice(bytes);
        }
        self.pending.extend_from_slice(bytes);
        // SSE (spec §"Parsing the event stream") terminates a line on CR, LF
        // or CRLF; `push` used to split on LF only, so a CR-only framed body
        // Parse every complete line in one forward pass and shift the buffer
        // once: draining per line made one large body chunk quadratic in the
        // number of events (R9: 91k tiny events in a 4 MiB push took >5 s).
        // Take the buffer so the lines are parsed in place without a copy:
        // the per-line `to_vec` left the release wall allocation-bound (R10).
        let buffer = std::mem::take(&mut self.pending);
        let mut consumed = 0usize;
        while let Some(position) = buffer[consumed..]
            .iter()
            .position(|byte| *byte == b'\n' || *byte == b'\r')
            .map(|offset| consumed + offset)
        {
            // A CR at the end of the buffer may still be the first half of a
            // CRLF split across chunks: wait for the next byte instead of
            // terminating the line early. A body-ending CR is flushed by
            // `finish`, and a CR-terminated `[DONE]` still latches below.
            if buffer[position] == b'\r' && position + 1 == buffer.len() {
                break;
            }
            let next = if buffer[position] == b'\r' && buffer.get(position + 1) == Some(&b'\n') {
                position + 2
            } else {
                position + 1
            };
            let line = &buffer[consumed..position];
            consumed = next;
            self.line(line, sink)?;
            if self.saw_done {
                // The terminator ends the body even if more bytes follow in
                // this chunk: drop the partial line and ignore the rest.
                return Ok(());
            }
        }
        if consumed < buffer.len() {
            // One copy of the unconsumed tail back into the buffer.
            self.pending.extend_from_slice(&buffer[consumed..]);
        }
        if self.pending.len() > MAX_STREAM_BODY_BYTES {
            // One line this long is hostile or broken; refusing it keeps the
            // buffer bounded instead of buffering the rest of the body, and
            // `stream_too_large` tells the caller why (F-06/F-09).
            return Err(stream_too_large(
                &self.provider,
                format!("stream line exceeds {MAX_STREAM_BODY_BYTES} bytes without a newline"),
            ));
        }
        // F-15: `[DONE]` may arrive as the final, unterminated line (a
        // gateway that ends the body without a trailing newline on a
        // keep-alive socket). Treat it as terminal here, so `complete_streaming`
        // breaks the read loop instead of waiting out the idle timeout and
        // discarding a complete answer.
        if !self.pending.is_empty() && done_line(&self.pending) {
            self.saw_done = true;
            self.pending.clear();
            return Ok(());
        }
        Ok(())
    }

    /// True once `data: [DONE]` has been seen: the caller stops reading the
    /// body then, so a keep-alive endpoint cannot hold a finished answer
    /// hostage until a timeout (F-08).
    fn saw_done(&self) -> bool {
        self.saw_done
    }

    fn line(
        &mut self,
        line: &[u8],
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<(), ProviderError> {
        if self.saw_done {
            return Ok(());
        }
        // A UTF-8 BOM glued to the head of a line is a transport artifact,
        // not an SSE field: gateways prepend one (sometimes two) to the body
        // and may pad the field name, and without this strip the first
        // `data:` line looks like an unknown field and its delta is silently
        // dropped (F-07/F-12). The strip is per line, so noise split across
        // reads — or placed after an earlier chunk — is reassembled first.
        let line = trim_line_noise(line);
        if line.is_empty() || line.starts_with(b":") {
            return Ok(());
        }
        // A terminator without its line terminator is handled at the end of
        // `push`; here the line is complete.
        if done_line(line) {
            self.saw_done = true;
            return Ok(());
        }
        let Some(payload) = line.strip_prefix(b"data:") else {
            // `event:`, `id:`, `retry:` — not part of the completion body.
            return Ok(());
        };
        let payload = payload.strip_prefix(b" ").unwrap_or(payload);
        // A spec-legal heartbeat (`data:` with an empty or whitespace-only
        // payload) carries no event; skipping it keeps a completion alive
        // instead of failing it on a JSON parse (GLM-P3).
        if payload.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Ok(());
        }
        let invalid = |message: String| ProviderError::InvalidResponse {
            provider: shown_id_plain(&self.provider),
            message,
        };
        let text = std::str::from_utf8(payload)
            .map_err(|_| invalid("stream chunk is not valid UTF-8".to_string()))?;
        let chunk: StreamChunk = serde_json::from_str(text)
            .map_err(|err| invalid(format!("invalid stream chunk: {err}")))?;
        self.apply(chunk, sink)?;
        Ok(())
    }

    /// Apply one parsed chunk, enforcing the per-turn growth caps (UNB-01).
    ///
    /// Any cap crossing returns `stream_too_large` immediately. The caller
    /// (`complete_streaming`) propagates it out of the read loop before
    /// `finish`, so no tool call is ever emitted for a capped stream: the sink
    /// has only the text deltas that fit, and the assembled `ChatResponse` is
    /// never built.
    fn apply(
        &mut self,
        chunk: StreamChunk,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<(), ProviderError> {
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
        }
        for choice in chunk.choices {
            if !self.saw_choice {
                self.saw_choice = true;
                // The plain-body recovery copy in `finish` is unreachable
                // from here on; free it instead of retaining dead weight.
                self.raw = Vec::new();
            }
            if let Some(text) = choice.delta.content {
                if !text.is_empty() {
                    if self.content.len() + text.len() > MAX_STREAM_CONTENT_BYTES {
                        // Check before pushing and before emitting: the delta
                        // that would cross the ceiling is refused whole.
                        return Err(stream_too_large(
                            &self.provider,
                            format!(
                                "assistant text exceeds {MAX_STREAM_CONTENT_BYTES} bytes for one turn"
                            ),
                        ));
                    }
                    self.content.push_str(&text);
                    sink(ChatDelta::Text(text));
                }
            }
            if let Some(text) = choice.delta.reasoning_content {
                if self.reasoning.len() + text.len() > MAX_STREAM_CONTENT_BYTES {
                    return Err(stream_too_large(
                        &self.provider,
                        format!(
                            "reasoning text exceeds {MAX_STREAM_CONTENT_BYTES} bytes for one turn"
                        ),
                    ));
                }
                self.reasoning.push_str(&text);
                self.saw_reasoning = true;
            }
            for fragment in choice.delta.tool_calls {
                // A repeated index is a fragment of an existing call, not a
                // new one; only a genuinely new index counts against the cap.
                if !self.tool_calls.contains_key(&fragment.index)
                    && self.tool_calls.len() >= MAX_STREAM_TOOL_CALLS
                {
                    return Err(stream_too_large(
                        &self.provider,
                        format!("stream carries more than {MAX_STREAM_TOOL_CALLS} tool calls"),
                    ));
                }
                let call = self.tool_calls.entry(fragment.index).or_default();
                if let Some(id) = fragment.id {
                    call.id = Some(id);
                }
                if let Some(function) = fragment.function {
                    if let Some(name) = function.name {
                        if call.name.len() + name.len() > MAX_STREAM_TOOL_NAME_BYTES {
                            return Err(stream_too_large(
                                &self.provider,
                                format!(
                                    "tool call name exceeds {MAX_STREAM_TOOL_NAME_BYTES} bytes"
                                ),
                            ));
                        }
                        call.name.push_str(&name);
                    }
                    if let Some(arguments) = function.arguments {
                        if call.arguments.len() + arguments.len() > MAX_STREAM_TOOL_ARGUMENT_BYTES {
                            return Err(stream_too_large(
                                &self.provider,
                                format!(
                                    "tool call arguments exceed {MAX_STREAM_TOOL_ARGUMENT_BYTES} bytes"
                                ),
                            ));
                        }
                        call.arguments.push_str(&arguments);
                    }
                }
            }
        }
        Ok(())
    }

    /// Flush any unterminated final line, then assemble the response.
    fn finish(
        mut self,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            let line = line.strip_suffix(b"\r").unwrap_or(&line).to_vec();
            self.line(&line, sink)?;
        }
        let provider = self.provider.clone();
        if !self.saw_choice {
            // The server may have ignored `stream: true` (some proxies answer
            // 200 text/plain with a normal JSON body): recover the plain
            // response rather than failing the turn.
            if let Ok(body) = std::str::from_utf8(&self.raw) {
                if let Ok(response) = parse_response(&provider, body) {
                    return Ok(response);
                }
            }
            return Err(ProviderError::InvalidResponse {
                provider: shown_id_plain(&provider),
                message: "stream contained no completion data".to_string(),
            });
        }

        let mut tool_calls = Vec::new();
        for (_, partial) in self.tool_calls {
            if partial.name.is_empty() {
                return Err(ProviderError::InvalidResponse {
                    provider: shown_id_plain(&provider),
                    message: "streamed tool call had no function name".to_string(),
                });
            }
            tool_calls.push(ToolCall {
                id: partial.id.unwrap_or_default(),
                name: partial.name,
                arguments: assembled_arguments(&partial.arguments),
            });
        }

        let message = ChatMessage {
            role: ChatRole::Assistant,
            content: self.content.clone(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            reasoning_content: None,
            reasoning_provider: None,
        }
        .with_reasoning_content(
            self.saw_reasoning
                .then(|| std::mem::take(&mut self.reasoning)),
        );
        let message = stamp_reasoning_provider(message, &provider);
        let mut response = ChatResponse::new(message);
        response.message.tool_calls = tool_calls;
        response.usage = self.usage;

        // Emit the assembled pieces after the text: the return value is the
        // contract, the sink is the live view.
        for call in &response.message.tool_calls {
            sink(ChatDelta::ToolCall(call.clone()));
        }
        if let Some(usage) = response.usage {
            sink(ChatDelta::Usage(usage));
        }
        Ok(response)
    }
}

/// The messages one request carries to `provider`: reasoning another provider
/// produced is dropped, so a switch or a fallback never forwards it.
fn messages_for<'a>(
    provider: &str,
    messages: &'a [SafeMessage],
) -> std::borrow::Cow<'a, [SafeMessage]> {
    if messages
        .iter()
        .any(|message| message.withholds_reasoning_from(provider))
    {
        std::borrow::Cow::Owned(
            messages
                .iter()
                .map(|message| message.for_provider(provider))
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(messages)
    }
}

/// Record which provider produced the reasoning a reply carries.
fn stamp_reasoning_provider(message: ChatMessage, provider: &str) -> ChatMessage {
    if message.reasoning_content.is_some() {
        message.with_reasoning_provider(provider)
    } else {
        message
    }
}

fn parse_response(provider: &str, body: &str) -> Result<ChatResponse, ProviderError> {
    let parsed: WireResponse =
        serde_json::from_str(body).map_err(|err| ProviderError::InvalidResponse {
            provider: shown_id_plain(provider),
            message: format!("not a chat completion: {err}"),
        })?;
    let choice =
        parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| ProviderError::InvalidResponse {
                provider: shown_id_plain(provider),
                message: "response contained no choices".to_string(),
            })?;

    let message = ChatMessage {
        role: ChatRole::Assistant,
        content: choice.message.content.unwrap_or_default(),
        tool_calls: choice.message.tool_calls,
        tool_call_id: None,
        reasoning_content: None,
        reasoning_provider: None,
    }
    .with_reasoning_content(choice.message.reasoning_content);
    let message = stamp_reasoning_provider(message, provider);
    let mut response = ChatResponse::new(message);
    response.usage = parsed.usage;
    Ok(response)
}

fn request_error(provider: &str, err: reqwest::Error) -> ProviderError {
    let provider = shown_id_plain(provider);
    if err.is_timeout() {
        ProviderError::Timeout { provider }
    } else if err.is_connect() && provider == OLLAMA_PROVIDER_ID {
        // The Ollama preset's id: a refused connection means the local server
        // is down, which the owner can fix by starting it.
        ProviderError::OllamaNotRunning { provider }
    } else {
        ProviderError::Request {
            provider,
            // reqwest's Display embeds the URL, which may carry a key.
            source: err.without_url(),
        }
    }
}

fn status_error(
    provider: &str,
    status: reqwest::StatusCode,
    retry_after: Option<Duration>,
    body: &str,
    key: Option<&str>,
) -> ProviderError {
    let provider = shown_id_plain(provider);
    match status.as_u16() {
        401 => ProviderError::Unauthorized { provider },
        429 => ProviderError::RateLimited {
            provider,
            retry_after,
        },
        code if status.is_server_error() => ProviderError::Server {
            provider,
            status: code,
        },
        code => ProviderError::Client {
            provider,
            status: code,
            // The upstream body may echo the key (P2 security-review round 1):
            // redact before extracting, so a truncated message can never hold
            // a partial key either.
            message: error_message(&redact_upstream(body, key)),
        },
    }
}

/// Extract `{"error": {"message": "…"}}` (or a plain `{"error": "…"}`) from
/// an error body, falling back to the raw body. Kept short so logs stay
/// readable.
fn error_message(body: &str) -> String {
    #[derive(Deserialize)]
    struct ErrorObject {
        #[serde(default)]
        message: Option<String>,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ErrorDetail {
        Object(ErrorObject),
        Text(String),
    }
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        error: Option<ErrorDetail>,
        #[serde(default)]
        message: Option<String>,
    }

    let message = match serde_json::from_str::<ErrorBody>(body) {
        Ok(parsed) => match parsed.error {
            Some(ErrorDetail::Object(error)) => error.message.unwrap_or_else(|| body.to_string()),
            Some(ErrorDetail::Text(text)) => text,
            None => parsed.message.unwrap_or_else(|| body.to_string()),
        },
        Err(_) => body.to_string(),
    };
    truncate(&message, 300)
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let kept: String = text.chars().take(max_chars).collect();
        format!("{kept}…")
    }
}

fn parse_retry_after(value: &HeaderValue) -> Option<Duration> {
    value
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {

    /// A gate that tokenises: C9 is the one covered row private mode allows.
    fn tokenising_gate(key: [u8; 32]) -> kernel_privacy::safetext::Gate {
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        kernel_privacy::safetext::Gate::for_tests(&grant, key, crate::test_gate::names_checked())
    }
    use super::*;
    use crate::config::ProviderConfig;
    use crate::config::ProviderKind;
    use crate::types::{ChatMessage, SafeMessage};
    use serde_json::json;

    fn config() -> ProviderConfig {
        ProviderConfig {
            disable_thinking: false,
            id: "deepseek".to_string(),
            base_url: "http://127.0.0.1:9/v1".to_string(),
            model: "deepseek-chat".to_string(),
            key_user: None,
            kind: ProviderKind::OpenAiCompat,
        }
    }

    #[test]
    fn endpoint_appends_chat_completions() {
        let provider = OpenAiCompat::with_key(&config(), None).unwrap();
        assert_eq!(
            provider.endpoint(),
            "http://127.0.0.1:9/v1/chat/completions"
        );
        assert_eq!(provider.name(), "deepseek");
    }

    #[test]
    fn only_a_local_runtime_on_loopback_with_a_local_model_runs_on_this_mac() {
        let brain = |base: &str, model: &str, local: bool| {
            let config = ProviderConfig {
                base_url: base.into(),
                model: model.into(),
                ..config()
            };
            let provider = OpenAiCompat::with_key(&config, None).unwrap();
            if local {
                provider.local_runtime()
            } else {
                provider
            }
            .on_this_mac()
        };
        assert!(brain("http://127.0.0.1:11434/v1", "llama3.2", true));
        assert!(!brain(
            "http://127.0.0.1:11434/v1",
            "gpt-oss:120b-cloud",
            true
        ));
        assert!(!brain("http://127.0.0.1:11434/v1", "kimi-k2:cloud", true));
        assert!(!brain("http://127.0.0.1:11434/v1", "llama3.2", false));
        assert!(!brain("https://ollama.example/v1", "llama3.2", true));
    }

    #[test]
    fn debug_redacts_the_api_key() {
        let provider = OpenAiCompat::with_key(&config(), Some("super-secret".to_string())).unwrap();
        let text = format!("{provider:?}");
        assert!(
            !text.contains("super-secret"),
            "debug leaked the key: {text}"
        );
        assert!(text.contains("REDACTED"));
    }

    #[test]
    fn debug_never_shows_a_key_in_the_endpoint_or_id() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let config = ProviderConfig {
            base_url: format!("https://api.example.com/v1/{key}"),
            ..config()
        };
        let mut provider = OpenAiCompat::with_key(&config, None).unwrap();
        // A validated config cannot carry a key-shaped id; Debug still hides one.
        provider.id = key.clone();
        let text = format!("{provider:?}");
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[tokio::test]
    async fn a_request_error_never_carries_the_url() {
        // reqwest's own Display embeds the URL; the provider error must strip
        // it before the key in a path can reach a log or the owner.
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let provider = OpenAiCompat::with_key(&config(), None).unwrap();
        let source = provider
            .http
            .get(format!("http://127.0.0.1:9/{key}"))
            .send()
            .await
            .unwrap_err();
        let err = request_error("p", source);
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        for out in [&shown, &debug] {
            assert!(!out.to_lowercase().contains("canary"), "{out}");
        }
    }

    #[test]
    fn an_error_never_shows_a_key_shaped_provider_id() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let err = status_error(&key, reqwest::StatusCode::UNAUTHORIZED, None, "", None);
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        for out in [&shown, &debug] {
            assert!(!out.to_lowercase().contains("canary"), "{out}");
        }
        assert!(shown.contains("<id>"), "{shown}");
    }

    #[tokio::test]
    async fn invalid_header_characters_in_key_are_rejected() {
        let provider = OpenAiCompat::with_key(&config(), Some("bad\nkey".to_string())).unwrap();
        let hi =
            SafeMessage::issue(&mut tokenising_gate([1u8; 32]), &ChatMessage::user("hi")).unwrap();
        let err = provider
            .complete(&ChatRequest::new(vec![hi]))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ProviderError::Config(crate::config::ConfigError::Invalid(_))
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn error_message_extracts_json_error() {
        assert_eq!(
            error_message(r#"{"error":{"message":"bad model","type":"invalid_request"}}"#),
            "bad model"
        );
    }

    #[test]
    fn error_message_falls_back_to_raw_body() {
        assert_eq!(error_message("<html>oops</html>"), "<html>oops</html>");
        assert_eq!(error_message(r#"{"error":"plain text"}"#), "plain text");
    }

    #[test]
    fn error_message_truncates_long_bodies() {
        let long = "x".repeat(1000);
        let message = error_message(&long);
        assert_eq!(message.chars().count(), 301);
        assert!(message.ends_with('…'));
    }

    #[test]
    fn parse_response_rejects_empty_choices() {
        let err = parse_response("deepseek", r#"{"choices":[]}"#).unwrap_err();
        assert!(
            matches!(&err, ProviderError::InvalidResponse { message, .. } if message.contains("no choices")),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_response_rejects_malformed_json() {
        let err = parse_response("deepseek", "not json").unwrap_err();
        assert!(matches!(err, ProviderError::InvalidResponse { .. }));
    }

    #[test]
    fn parse_response_reads_text_and_tool_calls() {
        let response = parse_response(
            "deepseek",
            &json!({
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": { "name": "shell", "arguments": "{\"cmd\":\"ls\"}" }
                        }]
                    }
                }]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(response.content(), "");
        assert_eq!(response.message.role, ChatRole::Assistant);
        assert_eq!(response.tool_calls().len(), 1);
        assert_eq!(response.tool_calls()[0].arguments, json!({ "cmd": "ls" }));
        assert_eq!(response.usage, None, "no usage object in the body");
    }

    #[test]
    fn parse_response_reads_usage_when_present() {
        let response = parse_response(
            "deepseek",
            &json!({
                "choices": [{ "message": { "role": "assistant", "content": "hi" } }],
                "usage": { "prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13 }
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            response.usage,
            Some(Usage {
                prompt_tokens: 9,
                completion_tokens: 4,
                cost_usd: None,
                cached_prompt_tokens: None,
            })
        );
    }

    #[test]
    fn parse_response_reads_cached_prompt_tokens() {
        // api.deepseek.com, 2026-10-21 (second identical call): both spellings.
        let deepseek = json!({ "prompt_tokens": 637, "completion_tokens": 10,
            "prompt_tokens_details": { "cached_tokens": 384 },
            "prompt_cache_hit_tokens": 384, "prompt_cache_miss_tokens": 253 });
        let hit_only = json!({ "prompt_tokens": 50, "prompt_cache_hit_tokens": 7 });
        let plain = json!({ "prompt_tokens": 50, "completion_tokens": 1 });
        let junk = json!({ "prompt_tokens_details": "x", "prompt_cache_hit_tokens": -1 });
        for (usage, cached) in [
            (deepseek, Some(384)),
            (hit_only, Some(7)),
            (plain, None),
            (junk, None),
        ] {
            let body = json!({ "choices": [{ "message": { "content": "ok" } }], "usage": usage });
            let usage = parse_response("deepseek", &body.to_string()).unwrap().usage;
            assert_eq!(usage.unwrap().cached_prompt_tokens, cached, "{body}");
        }
    }

    #[test]
    fn parse_response_reads_a_provider_reported_cost() {
        // OpenRouter-style `usage.cost` in dollars; recorded as USD.
        let response = parse_response(
            "openrouter",
            &json!({
                "choices": [{ "message": { "role": "assistant", "content": "hi" } }],
                "usage": { "prompt_tokens": 9, "completion_tokens": 4, "cost": 0.0123 }
            })
            .to_string(),
        )
        .unwrap();
        let usage = response.usage.expect("usage");
        assert_eq!(usage.prompt_tokens, 9);
        assert_eq!(usage.cost_usd, Some(0.0123));
    }

    #[test]
    fn parse_response_reads_null_usage_as_absent() {
        let response = parse_response(
            "deepseek",
            &json!({
                "choices": [{ "message": { "content": "ok" } }],
                "usage": null
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(response.usage, None);
    }

    #[test]
    fn parse_response_tolerates_null_usage_fields() {
        let response = parse_response(
            "deepseek",
            &json!({
                "choices": [{ "message": { "content": "ok" } }],
                "usage": { "prompt_tokens": null, "completion_tokens": 5 }
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            response.usage,
            Some(Usage {
                prompt_tokens: 0,
                completion_tokens: 5,
                cost_usd: None,
                cached_prompt_tokens: None,
            })
        );
    }

    // ---- streaming (WS-F1) ----

    fn collect(deltas: &std::sync::Mutex<Vec<ChatDelta>>) -> Vec<ChatDelta> {
        deltas.lock().unwrap().clone()
    }

    /// Feed `sse` in `step`-byte pieces, splitting lines and UTF-8 chars.
    fn assemble(
        provider: &str,
        sse: &str,
        step: usize,
    ) -> (Result<ChatResponse, ProviderError>, Vec<ChatDelta>) {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new(provider);
        let bytes = sse.as_bytes();
        let mut result = Ok(ChatResponse::assistant("unset"));
        for piece in bytes.chunks(step) {
            if let Err(err) = assembler.push(piece, &sink) {
                result = Err(err);
                break;
            }
        }
        if result.is_ok() {
            result = assembler.finish(&sink);
        }
        (result, collect(&deltas))
    }

    #[test]
    fn stream_assembler_reads_cached_tokens_from_the_last_chunk() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":637,\"completion_tokens\":2,",
            "\"prompt_tokens_details\":{\"cached_tokens\":384}}}\n",
            "data: [DONE]\n",
        );
        let (result, _) = assemble("deepseek", sse, 5);
        let usage = result.unwrap().usage.unwrap();
        assert_eq!(
            (usage.prompt_tokens, usage.cached_prompt_tokens),
            (637, Some(384))
        );
    }

    #[test]
    fn stream_assembler_rebuilds_text_across_split_lines() {
        let sse = concat!(
            ": keep-alive\n",
            "event: message\n",
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n",
            "\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo \"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"wörld\"}}]}\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":4}}\n",
            "data: [DONE]\n",
        );

        for step in [1, 3, 7, 4096] {
            let (result, deltas) = assemble("deepseek", sse, step);
            let response = result.unwrap_or_else(|err| panic!("step {step}: {err:?}"));
            assert_eq!(response.content(), "Hello wörld", "step {step}");
            assert_eq!(
                response.usage,
                Some(Usage {
                    prompt_tokens: 9,
                    completion_tokens: 4,
                    cost_usd: None,
                    cached_prompt_tokens: None,
                }),
                "step {step}"
            );
            let texts: Vec<String> = deltas
                .iter()
                .filter_map(|delta| match delta {
                    ChatDelta::Text(text) => Some(text.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(texts.concat(), "Hello wörld", "step {step}");
            assert_eq!(texts.len(), 3, "step {step}");
        }
    }

    #[test]
    fn stream_assembler_assembles_tool_calls_from_fragments() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",",
            "\"function\":{\"name\":\"shell\",\"arguments\":\"{\\\"cmd\\\":\"}}]}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,",
            "\"function\":{\"arguments\":\"\\\"ls\\\"}\"}}]}}]}\n",
            "data: [DONE]\n",
        );

        let (result, deltas) = assemble("deepseek", sse, 5);
        let response = result.unwrap();
        assert_eq!(response.content(), "");
        assert_eq!(response.tool_calls().len(), 1);
        assert_eq!(response.tool_calls()[0].id, "call_9");
        assert_eq!(response.tool_calls()[0].name, "shell");
        assert_eq!(response.tool_calls()[0].arguments, json!({ "cmd": "ls" }));
        assert!(
            matches!(deltas.first(), Some(ChatDelta::ToolCall(call)) if call.name == "shell"),
            "the assembled call is reported to the sink: {deltas:?}"
        );
    }

    #[test]
    fn stream_assembler_keeps_malformed_arguments_as_text() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",",
            "\"function\":{\"name\":\"shell\",\"arguments\":\"{not json\"}}]}}]}\n",
            "data: [DONE]\n",
        );
        let (result, _) = assemble("deepseek", sse, 4096);
        let response = result.unwrap();
        assert_eq!(response.tool_calls()[0].arguments, json!("{not json"));
    }

    #[test]
    fn stream_assembler_recovers_a_plain_json_body() {
        // A proxy that ignores `stream: true` and answers one JSON document.
        let body = json!({
            "choices": [{ "message": { "role": "assistant", "content": "plain" } }],
            "usage": { "prompt_tokens": 2, "completion_tokens": 1 }
        })
        .to_string();
        let (result, deltas) = assemble("proxy", &body, 8);
        let response = result.unwrap();
        assert_eq!(response.content(), "plain");
        assert_eq!(response.usage.unwrap().prompt_tokens, 2);
        assert!(deltas.is_empty(), "a recovered plain body emits no deltas");
    }

    #[test]
    fn stream_assembler_rejects_garbage() {
        let (result, _) = assemble("deepseek", "data: {not json}\n", 4096);
        assert!(
            matches!(&result, Err(ProviderError::InvalidResponse { provider, message })
                if provider == "deepseek" && message.contains("invalid stream chunk")),
            "got {result:?}"
        );

        let (empty, _) = assemble("deepseek", "event: ping\n\ndata: [DONE]\n", 4096);
        assert!(matches!(empty, Err(ProviderError::InvalidResponse { .. })));

        let (bad_name, _) = assemble(
            "deepseek",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{}\"}}]}}]}\n",
            4096,
        );
        assert!(
            matches!(&bad_name, Err(ProviderError::InvalidResponse { message, .. })
                if message.contains("no function name")),
            "got {bad_name:?}"
        );
    }

    #[test]
    fn stream_assembler_accepts_every_done_variant() {
        let content = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n",
        );
        let variants = [
            "data: [DONE]\n",
            "data:[DONE]\n",
            "data:  [DONE]\n",                     // an extra space after `data:`
            "data: [DONE] \n",                     // trailing space
            "data: [done]\n",                      // lowercase
            "data: [Done]",                        // no trailing newline
            "data:\t[DONE]\n",                     // tab after the colon
            "data:  [DONE]\n\ndata: {not json}\n", // junk after the terminator
        ];
        for done in variants {
            for step in [1, 5, 4096] {
                let sse = format!("{content}{done}");
                let (result, deltas) = assemble("deepseek", &sse, step);
                let response =
                    result.unwrap_or_else(|err| panic!("done={done:?} step={step}: {err:?}"));
                assert_eq!(response.content(), "Hello", "done={done:?} step={step}");
                let texts: String = deltas
                    .iter()
                    .filter_map(|delta| match delta {
                        ChatDelta::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(texts, "Hello", "done={done:?} step={step}");
            }
        }
    }

    /// F-15 (B5-2): the SSE spec accepts a lone CR as a line terminator. A
    /// CR-only framed body must yield its deltas, and a trailing
    /// `data: [DONE]\r` must end the read loop even if the socket is held
    /// open (no stall).
    #[test]
    fn b5f15_cr_only_framing() {
        let first = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\r";
        let second = "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\r";
        let done = "data: [DONE]\r";
        // Body-ends form: every event CR-terminated, fed at every byte split
        // (each CR is at a chunk end, so the CRLF wait is exercised too).
        for step in [1, 2, 3, 5, 4096] {
            let sse = format!("{first}{second}{done}");
            let (result, deltas) = assemble("deepseek", &sse, step);
            let response = result.unwrap_or_else(|err| panic!("step {step}: {err:?}"));
            assert_eq!(response.content(), "Hello", "step {step}");
            let texts: String = deltas
                .iter()
                .filter_map(|delta| match delta {
                    ChatDelta::Text(text) => Some(text.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(texts, "Hello", "step {step}");
        }
        // Held-socket form: the CR-terminated `[DONE]` must latch without
        // another byte ever arriving.
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler
            .push(format!("{first}{second}{done}").as_bytes(), &sink)
            .unwrap();
        assert!(
            assembler.saw_done(),
            "a CR-terminated [DONE] must end the body"
        );
        let texts: String = collect(&deltas)
            .iter()
            .filter_map(|delta| match delta {
                ChatDelta::Text(text) => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, "Hello");
    }

    /// F-15 (B5-2) multi-event table: every CR/CRLF composition and framing
    /// artifact, split at every byte, yields both deltas and completes.
    #[test]
    fn b5f15_cr_only_multi_event_table() {
        let a = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}";
        let b = "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}";
        let done = "data: [DONE]";
        let shapes = [
            // pure CR, last event also CR-terminated (held socket)
            format!("{a}\r{b}\r{done}\r"),
            // pure CR, body ends on `[DONE]` without a terminator
            format!("{a}\r{b}\r{done}"),
            // mixed: CRLF first two, CR terminator on the terminator
            format!("{a}\r\n{b}\r\n{done}\r"),
            // mixed: CR on the events, CRLF on the terminator
            format!("{a}\r{b}\r{done}\r\n"),
            // a keep-alive comment line and a blank CR line up front
            format!(": ping\r\r{a}\r{b}\r{done}\r"),
            // lowercase/space noise on the terminator, CR-terminated
            format!("{a}\r{b}\rdata:  [done] \r"),
        ];
        for sse in shapes {
            for step in [1, 2, 3, 4, 7, 4096] {
                let (result, deltas) = assemble("deepseek", &sse, step);
                let response =
                    result.unwrap_or_else(|err| panic!("step {step} body {sse:?}: {err:?}"));
                assert_eq!(response.content(), "Hello", "step {step} body {sse:?}");
                let texts: String = deltas
                    .iter()
                    .filter_map(|delta| match delta {
                        ChatDelta::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(texts, "Hello", "step {step} body {sse:?}");
            }
        }
    }

    /// A UTF-8 BOM at the head of the body is a transport artifact: it must
    /// not turn the first `data:` line into an unknown field (F-07).
    #[test]
    fn stream_assembler_strips_a_utf8_bom() {
        const BOM: &str = "\u{FEFF}";
        let content = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n",
        );
        let heads = [
            // BOM glued to the first `data:` line (LF terminated).
            format!("{BOM}data: {{\"choices\":[{{\"delta\":{{\"content\":\"Hel\"}}}}]}}\n\
                    data: {{\"choices\":[{{\"delta\":{{\"content\":\"lo\"}}}}]}}\ndata: [DONE]\n"),
            // BOM alone on its first line, CRLF terminated.
            format!("{BOM}\r\ndata: {{\"choices\":[{{\"delta\":{{\"content\":\"Hel\"}}}}]}}\r\n\
                    data: {{\"choices\":[{{\"delta\":{{\"content\":\"lo\"}}}}]}}\r\ndata: [DONE]\r\n"),
            // BOM after one good chunk still only affects its own line.
            format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"Hel\"}}}}]}}\n\
                    {BOM}data: {{\"choices\":[{{\"delta\":{{\"content\":\"lo\"}}}}]}}\ndata: [DONE]\n"),
            // BOM glued to the terminator is harmless.
            format!("{content}data: [DONE]\n"),
            format!("{content}{BOM}data: [DONE]\n"),
        ];
        for sse in heads {
            for step in [1, 2, 3, 4096] {
                let (result, deltas) = assemble("deepseek", &sse, step);
                let response = result.unwrap_or_else(|err| panic!("step {step}: {err:?}"));
                assert_eq!(response.content(), "Hello", "step {step} body {sse:?}");
                let texts: String = deltas
                    .iter()
                    .filter_map(|delta| match delta {
                        ChatDelta::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(texts, "Hello", "step {step} body {sse:?}");
            }
        }
    }

    /// F-12: a doubled BOM and a BOM followed by spacing used to slip past
    /// the single `strip_prefix`, silently dropping the first `data:` line
    /// (`Ok("lo")` instead of `Ok("Hello")`).
    #[test]
    fn stream_assembler_strips_double_bom_and_bom_padding() {
        const BOM: &str = "\u{FEFF}";
        let content = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n",
            "data: [DONE]\n",
        );
        let first = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n";
        let heads = [
            format!("{BOM}{BOM}{first}"),   // two BOMs
            format!("{BOM} {first}"),       // BOM then a space
            format!("{BOM}{BOM} {first}"),  // two BOMs then a space
            format!("  {BOM}{BOM}{first}"), // padding before the BOMs
        ];
        for head in heads {
            let sse = format!("{head}{content}");
            for step in [1, 2, 3, 4096] {
                let (result, deltas) = assemble("deepseek", &sse, step);
                let response = result.unwrap_or_else(|err| panic!("step {step}: {err:?}"));
                assert_eq!(response.content(), "Hello", "step {step} body {sse:?}");
                let texts: String = deltas
                    .iter()
                    .filter_map(|delta| match delta {
                        ChatDelta::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(texts, "Hello", "step {step} body {sse:?}");
            }
        }
    }

    /// F-06/F-09: one named ceiling bounds both the pre-choice recovery copy
    /// and `pending`, and crossing it is an explicit `stream_too_large`
    /// error, never a silently truncated answer. Many short complete lines
    /// drain `pending` after every newline, so only the `raw` cap can see
    /// this body.
    #[test]
    fn stream_assembler_refuses_a_pre_choice_body_over_the_ceiling() {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        let mut batch = Vec::new();
        for _ in 0..64 {
            batch.extend_from_slice(b": keep-alive padding padding padding padding padding\n");
            batch.extend_from_slice(b"data: {\"usage\":{\"prompt_tokens\":1}}\n");
        }
        // Push several MiB of complete, newline-terminated lines.
        let mut error = None;
        for _ in 0..(MAX_STREAM_BODY_BYTES / batch.len() + 2) {
            if let Err(err) = assembler.push(&batch, &sink) {
                error = Some(err);
                break;
            }
        }
        let err = error.expect("a body over the ceiling must be refused at push time");
        assert!(
            matches!(&err, ProviderError::InvalidResponse { message, .. }
                if message.starts_with("stream_too_large")),
            "got {err:?}"
        );
        assert!(
            assembler.raw.len() <= MAX_STREAM_BODY_BYTES,
            "the pre-choice recovery copy must stay bounded: {} bytes",
            assembler.raw.len()
        );
        assert!(
            assembler.pending.is_empty(),
            "complete lines drain `pending`, so the line cap cannot help here"
        );
    }

    /// R9: one 4 MiB body chunk carrying ~89k tiny complete events must stay
    /// fast. The parser used to drain `pending` per line, shifting the rest
    /// of the chunk on every event (O(lines x chunk)); the budget below is
    /// asserted in release, where the pre-fix code took >5 s.
    #[test]
    fn a_four_mib_single_chunk_with_tiny_events_is_not_quadratic() {
        let mut assembler = StreamAssembler::new("deepseek");
        let sink = |_delta: ChatDelta| {};
        let event = b"data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n";
        let mut body = Vec::with_capacity(4 * 1024 * 1024);
        while body.len() + event.len() <= 4 * 1024 * 1024 {
            body.extend_from_slice(event);
        }
        let events = body.len() / event.len();
        let start = std::time::Instant::now();
        assembler.push(&body, &sink).expect("the body parses");
        let elapsed = start.elapsed();
        assert!(
            events > 80_000,
            "the probe must carry many events: {events}"
        );
        if cfg!(debug_assertions) {
            // Debug builds are much slower; only a sanity bound here.
            assert!(
                elapsed < std::time::Duration::from_secs(10),
                "a 4 MiB single push with {events} events took {elapsed:?}"
            );
        } else {
            assert!(
                elapsed < std::time::Duration::from_secs_f64(1.0),
                "a 4 MiB single push with {events} events took {elapsed:?}"
            );
        }
    }

    /// F-09/F-13(m1): the ceiling is one named constant and both sides of it
    /// are pinned. A plain body just under the cap is recovered whole; one
    /// over it fails closed with `stream_too_large`. A tighter cap (m1)
    /// breaks the first half, a silent truncation (F-06) breaks the second.
    #[test]
    fn stream_assembler_recovers_a_plain_body_up_to_the_named_ceiling() {
        assert_eq!(
            MAX_STREAM_BODY_BYTES,
            4 * 1024 * 1024,
            "the named body ceiling is 4 MiB (F-09)"
        );
        let under_content = MAX_STREAM_BODY_BYTES - 4096;
        let under = json!({
            "choices": [{ "message": { "content": "x".repeat(under_content) } }]
        })
        .to_string();
        assert!(under.len() <= MAX_STREAM_BODY_BYTES, "{}", under.len());
        let (result, deltas) = assemble("proxy", &under, 1 << 20);
        let response = result.unwrap_or_else(|err| panic!("under-cap body must recover: {err:?}"));
        assert_eq!(response.content().len(), under_content);
        assert!(deltas.is_empty(), "a recovered plain body emits no deltas");

        let over = json!({
            "choices": [{ "message": { "content": "x".repeat(MAX_STREAM_BODY_BYTES) } }]
        })
        .to_string();
        assert!(over.len() > MAX_STREAM_BODY_BYTES, "{}", over.len());
        let (result, _) = assemble("proxy", &over, 1 << 20);
        assert!(
            matches!(&result, Err(ProviderError::InvalidResponse { message, .. })
                if message.starts_with("stream_too_large")),
            "an over-cap body must fail closed with `stream_too_large`, got {result:?}"
        );
    }

    // ---- UNB-01: per-turn content, tool-argument, name and tool-count caps ----

    /// Build an SSE body that streams `total` bytes of assistant text in
    /// `chunk`-byte deltas, then terminates.
    fn text_sse(total: usize, chunk: usize) -> String {
        let mut sse = String::new();
        let mut sent = 0;
        while sent < total {
            let n = chunk.min(total - sent);
            let piece = "x".repeat(n);
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{piece}\"}}}}]}}\n"
            ));
            sent += n;
        }
        sse.push_str("data: [DONE]\n");
        sse
    }

    fn shown_text(deltas: &[ChatDelta]) -> usize {
        deltas
            .iter()
            .filter_map(|delta| match delta {
                ChatDelta::Text(text) => Some(text.len()),
                _ => None,
            })
            .sum()
    }

    /// A cap crossing is a `stream_too_large` error and the stream never
    /// reaches `finish`, so no (partial) assembled tool call is emitted.
    fn assert_capped(result: &Result<ChatResponse, ProviderError>, deltas: &[ChatDelta]) {
        assert!(
            matches!(result, Err(ProviderError::InvalidResponse { message, .. })
                if message.starts_with("stream_too_large")),
            "a cap crossing must fail closed with `stream_too_large`, got {result:?}"
        );
        assert!(
            !deltas
                .iter()
                .any(|delta| matches!(delta, ChatDelta::ToolCall(_))),
            "no partial tool call may reach the sink: {deltas:?}"
        );
    }

    /// UNB-01: assistant text over one turn's cap ends the stream; only the
    /// text that fit is shown, and nothing beyond the cap is retained.
    #[test]
    fn stream_assembler_refuses_content_over_the_turn_cap() {
        assert_eq!(
            MAX_STREAM_CONTENT_BYTES,
            1024 * 1024,
            "the named per-turn text ceiling is 1 MiB (UNB-01)"
        );
        let sse = text_sse(MAX_STREAM_CONTENT_BYTES + 1, 64 * 1024);
        let (result, deltas) = assemble("deepseek", &sse, 1 << 16);
        assert_capped(&result, &deltas);
        assert_eq!(
            shown_text(&deltas),
            MAX_STREAM_CONTENT_BYTES,
            "the crossing delta must be refused whole"
        );
    }

    /// UNB-01: exactly at the text cap is accepted; the ceiling is `>`, not
    /// `>=`, so a legitimate long answer is never cut one byte early.
    #[test]
    fn stream_assembler_accepts_content_at_the_exact_cap() {
        let sse = text_sse(MAX_STREAM_CONTENT_BYTES, 64 * 1024);
        let (result, deltas) = assemble("deepseek", &sse, 1 << 16);
        let response =
            result.unwrap_or_else(|err| panic!("an exact-cap turn must succeed: {err:?}"));
        assert_eq!(response.content().len(), MAX_STREAM_CONTENT_BYTES);
        assert_eq!(shown_text(&deltas), MAX_STREAM_CONTENT_BYTES);
    }

    /// UNB-01: one tool call's assembled arguments over the cap ends the
    /// stream before `finish`; no partial call reaches the sink.
    #[test]
    fn stream_assembler_refuses_tool_arguments_over_the_cap() {
        assert_eq!(
            MAX_STREAM_TOOL_ARGUMENT_BYTES,
            256 * 1024,
            "the named per-call argument ceiling is 256 KiB (UNB-01)"
        );
        let mut sse = String::from(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\
             \"function\":{\"name\":\"shell\"}}]}}]}\n",
        );
        let fragment = "a".repeat(32 * 1024);
        let mut sent = 0;
        while sent <= MAX_STREAM_TOOL_ARGUMENT_BYTES {
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\
                 \"function\":{{\"arguments\":\"{fragment}\"}}}}]}}}}]}}\n"
            ));
            sent += fragment.len();
        }
        sse.push_str("data: [DONE]\n");
        let (result, deltas) = assemble("deepseek", &sse, 1 << 16);
        assert_capped(&result, &deltas);
    }

    /// UNB-01: an over-cap tool-call name is refused too (same unbounded
    /// growth class as the arguments).
    #[test]
    fn stream_assembler_refuses_a_tool_name_over_the_cap() {
        let fragment = "n".repeat(MAX_STREAM_TOOL_NAME_BYTES + 1);
        let sse = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\
             \"function\":{{\"name\":\"{fragment}\"}}}}]}}}}]}}\n"
        );
        let (result, deltas) = assemble("deepseek", &sse, 1 << 16);
        assert_capped(&result, &deltas);
    }

    /// UNB-01: more than `MAX_STREAM_TOOL_CALLS` distinct indices end the
    /// stream; a repeated index is a fragment and must not count.
    #[test]
    fn stream_assembler_refuses_too_many_tool_calls() {
        assert_eq!(
            MAX_STREAM_TOOL_CALLS, 64,
            "the named tool-call ceiling is 64 (UNB-01)"
        );
        let mut sse = String::new();
        for index in 0..=MAX_STREAM_TOOL_CALLS {
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":{index},\
                 \"id\":\"c{index}\",\"function\":{{\"name\":\"f\",\"arguments\":\"{{}}\"}}}}]}}}}]}}\n"
            ));
        }
        sse.push_str("data: [DONE]\n");
        let (result, deltas) = assemble("deepseek", &sse, 4096);
        assert_capped(&result, &deltas);
    }

    /// UNB-01: a normal stream under every cap is unchanged — text, several
    /// tool calls, and their assembled deltas all still arrive.
    #[test]
    fn stream_assembler_normal_stream_under_the_caps_is_unchanged() {
        let mut sse = String::from("data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n");
        for index in 0..3 {
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":{index},\
                 \"id\":\"c{index}\",\"function\":{{\"name\":\"f\",\"arguments\":\"{{}}\"}}}}]}}}}]}}\n"
            ));
        }
        sse.push_str("data: [DONE]\n");
        let (result, deltas) = assemble("deepseek", &sse, 4096);
        let response = result.unwrap();
        assert_eq!(response.content(), "hello ");
        assert_eq!(response.tool_calls().len(), 3);
        assert_eq!(
            deltas
                .iter()
                .filter(|delta| matches!(delta, ChatDelta::ToolCall(_)))
                .count(),
            3
        );
    }

    /// UNB-01: a call fragmented into many small argument deltas under the
    /// cap still reassembles exactly (the cap must not break fragmentation).
    #[test]
    fn stream_assembler_accepts_fragmented_arguments_under_the_cap() {
        let mut sse = String::from(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\
             \"function\":{\"name\":\"shell\"}}]}}]}\n",
        );
        let mut expected = String::new();
        for _ in 0..16 {
            let fragment = "b".repeat(4 * 1024);
            expected.push_str(&fragment);
            sse.push_str(&format!(
                "data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{{\"index\":0,\
                 \"function\":{{\"arguments\":\"{fragment}\"}}}}]}}}}]}}\n"
            ));
        }
        sse.push_str("data: [DONE]\n");
        let (result, _) = assemble("deepseek", &sse, 4096);
        let response = result.unwrap();
        assert_eq!(response.tool_calls().len(), 1);
        assert_eq!(
            response.tool_calls()[0].arguments,
            serde_json::json!(expected)
        );
    }

    /// Mutation kill (m2): the early return after `[DONE]` is what keeps a
    /// post-terminator flood out of the buffers, not the line cap.
    #[test]
    fn stream_assembler_drops_everything_after_the_terminator() {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler
            .push(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n",
                &sink,
            )
            .unwrap();
        assembler.push(b"data: [DONE]\n", &sink).unwrap();
        let tail = vec![b'x'; 2 * 1024 * 1024];
        assembler.push(&tail, &sink).unwrap();
        assert!(
            assembler.pending.is_empty(),
            "post-[DONE] bytes must not be buffered: {}",
            assembler.pending.len()
        );
        assert!(
            assembler.raw.is_empty(),
            "post-[DONE] bytes must not be retained: {}",
            assembler.raw.len()
        );
        let response = assembler.finish(&sink).unwrap();
        assert_eq!(response.content(), "Hello");
    }

    /// Mutation kill (m5): `[DONE]` ends the body even when more bytes follow
    /// it inside the same chunk.
    #[test]
    fn stream_assembler_terminator_drops_the_rest_of_the_chunk() {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        let mut body = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n".to_vec();
        body.extend_from_slice(b"data: [DONE]\n");
        body.extend_from_slice(&vec![b'y'; 1024 * 1024]);
        assembler.push(&body, &sink).unwrap();
        assert!(
            assembler.pending.is_empty(),
            "the keep-alive tail after [DONE] must be dropped: {}",
            assembler.pending.len()
        );
        let response = assembler.finish(&sink).unwrap();
        assert_eq!(response.content(), "Hello");
    }

    /// F-15: a terminator that arrives as the final, unterminated line ends
    /// the stream immediately (no line terminator needed), for every padded/
    /// cased/BOM/no-space spelling; a partial `[DO` tail is not terminal.
    #[test]
    fn stream_assembler_terminator_without_a_line_terminator_ends_the_stream() {
        let terminators: [&[u8]; 7] = [
            b"data: [DONE]",
            b"data: [DONE]\r",
            b"data: [DONE]   ",
            b"data:[DONE]",
            b"data: [done]",
            b"\xEF\xBB\xBFdata: [DONE]",
            b"\xEF\xBB\xBF data: [DONE]\r",
        ];
        for terminator in terminators {
            let deltas = std::sync::Mutex::new(Vec::new());
            let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
            let mut assembler = StreamAssembler::new("deepseek");
            assembler
                .push(
                    b"data: {\"choices\":[{\"delta\":{\"content\":\"done\"}}]}\n",
                    &sink,
                )
                .unwrap();
            assembler.push(terminator, &sink).unwrap();
            assert!(
                assembler.saw_done(),
                "terminator {terminator:?} must end the stream without a newline"
            );
            assert!(
                assembler.pending.is_empty(),
                "the terminator tail must not stay buffered: {terminator:?}"
            );
            // A post-terminator flood is inert.
            assembler.push(&vec![b'x'; 4096], &sink).unwrap();
            assert!(assembler.pending.is_empty());
            let response = assembler.finish(&sink).unwrap();
            assert_eq!(response.content(), "done", "terminator {terminator:?}");
        }

        // A partial terminator must NOT end the stream: it may complete in
        // the very next chunk.
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler
            .push(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"done\"}}]}\n",
                &sink,
            )
            .unwrap();
        assembler.push(b"data: [DO", &sink).unwrap();
        assert!(
            !assembler.saw_done(),
            "a partial terminator is not terminal"
        );
        assembler.push(b"NE]", &sink).unwrap();
        assert!(assembler.saw_done(), "the completed terminator is terminal");
        assert_eq!(assembler.finish(&sink).unwrap().content(), "done");
    }

    /// F-19: both named ceilings are exact — a body/line of exactly
    /// `MAX_STREAM_BODY_BYTES` is accepted, only `+1` is refused. The reject
    /// side alone let `>` silently tighten to `>=`.
    #[test]
    fn stream_assembler_ceiling_is_exact_on_the_accept_side() {
        // The pre-choice recovery copy: a plain JSON body of exactly the cap.
        let overhead = json!({ "choices": [{ "message": { "content": "" } }] })
            .to_string()
            .len();
        let content = "x".repeat(MAX_STREAM_BODY_BYTES - overhead);
        let body = json!({ "choices": [{ "message": { "content": content } }] }).to_string();
        assert_eq!(body.len(), MAX_STREAM_BODY_BYTES);
        let (result, deltas) = assemble("proxy", &body, 4096);
        let response =
            result.unwrap_or_else(|err| panic!("an exact-cap body must recover: {err:?}"));
        assert_eq!(response.content().len(), MAX_STREAM_BODY_BYTES - overhead);
        assert!(deltas.is_empty(), "a recovered plain body emits no deltas");

        // The endless-line cap: a pending line of exactly the cap is fine.
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler
            .push(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n",
                &sink,
            )
            .unwrap();
        let prefix = b"data: ";
        assembler.push(prefix, &sink).unwrap();
        assembler
            .push(&vec![b'A'; MAX_STREAM_BODY_BYTES - prefix.len()], &sink)
            .unwrap();
        assert_eq!(
            assembler.pending.len(),
            MAX_STREAM_BODY_BYTES,
            "an exact-cap line must be buffered, not refused"
        );
        let err = assembler
            .push(b"A", &sink)
            .expect_err("one byte over the cap must be refused");
        assert!(
            matches!(&err, ProviderError::InvalidResponse { message, .. }
                if message.starts_with("stream_too_large")),
            "got {err:?}"
        );
    }

    /// Mutation kill (m4): the recovery copy is freed the moment a choice
    /// arrives, it does not merely stop growing.
    #[test]
    fn stream_assembler_frees_the_recovery_copy_when_a_choice_arrives() {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler
            .push(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n",
                &sink,
            )
            .unwrap();
        assert!(
            assembler.raw.is_empty(),
            "raw must be freed on the first choice: {} bytes retained",
            assembler.raw.len()
        );
        let response = assembler.finish(&sink).unwrap();
        assert_eq!(response.content(), "hi");
    }

    /// Mutation kill (m6): after a choice `raw` is empty and never grows
    /// again, so the endless-line cap must be checked on `pending` itself.
    #[test]
    fn stream_assembler_rejects_an_overlong_line_after_a_choice() {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler
            .push(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n",
                &sink,
            )
            .unwrap();
        assembler.push(b"data: [", &sink).unwrap();
        let piece = vec![b'A'; 1024 * 1024];
        let mut error = None;
        for _ in 0..(MAX_STREAM_BODY_BYTES / piece.len() + 2) {
            if let Err(err) = assembler.push(&piece, &sink) {
                error = Some(err);
                break;
            }
        }
        let err = error.expect("an endless line after a choice must still be refused");
        assert!(
            matches!(&err, ProviderError::InvalidResponse { message, .. }
                if message.starts_with("stream_too_large") && message.contains("without a newline")),
            "got {err:?}"
        );
    }

    #[test]
    fn stream_assembler_stops_retaining_the_body_after_a_choice() {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler
            .push(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n",
                &sink,
            )
            .unwrap();
        // Body bytes that arrive after a choice can never be read again: the
        // `raw` recovery copy must not keep growing (F-05).
        let junk = vec![b'x'; 128 * 1024];
        assembler.push(&junk, &sink).unwrap();
        assert!(
            assembler.raw.len() < junk.len() / 2,
            "raw must not retain post-choice body bytes: {}",
            assembler.raw.len()
        );
        let response = assembler.finish(&sink).unwrap();
        assert_eq!(response.content(), "hi");
    }

    #[test]
    fn stream_assembler_rejects_an_overlong_unterminated_line() {
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let mut assembler = StreamAssembler::new("deepseek");
        assembler.push(b"data: [", &sink).unwrap();
        let piece = vec![b'A'; 1024 * 1024];
        let mut error = None;
        for _ in 0..(MAX_STREAM_BODY_BYTES / piece.len() + 2) {
            if let Err(err) = assembler.push(&piece, &sink) {
                error = Some(err);
                break;
            }
        }
        let err = error.expect("an endless line must be refused, not buffered forever");
        // Before any choice the `raw` cap can fire first, so either cap is
        // acceptable here; both must say `stream_too_large` rather than
        // silently truncating (F-06/F-09).
        assert!(
            matches!(&err, ProviderError::InvalidResponse { message, .. }
                if message.starts_with("stream_too_large")),
            "got {err:?}"
        );
    }

    /// F-11/F-14: the fallback decision is structured. A refusal status must
    /// name the stream parameter in a parsed field (OpenAI `param`, FastAPI
    /// `loc`, an allowlisted parameter-refusal code plus the field named in
    /// the message), or be one of the short exact known refusals.
    #[test]
    fn stream_refusals_fall_back_only_on_structured_stream_signals() {
        let positives = [
            // OpenAI `param`.
            r#"{"error":{"message":"unrecognized argument","param":"stream","code":"unsupported_parameter"}}"#,
            r#"{"error":{"param":"stream_options"}}"#,
            // FastAPI validation.
            r#"{"detail":[{"loc":["body","stream"],"msg":"extra fields not permitted"}]}"#,
            r#"{"detail":{"loc":["body","stream_options"],"msg":"extra fields not permitted"}}"#,
            // Allowlisted parameter-refusal code + the field named in the message.
            r#"{"error":{"message":"unknown parameter: stream_options","code":"unknown_parameter"}}"#,
            r#"{"error":{"message":"unknown parameter: stream_options","type":"unsupported_parameter"}}"#,
            // F-18: every allowlisted code is pinned; dropping this one loses
            // a real provider refusal silently.
            r#"{"error":{"message":"unsupported value for stream_options","code":"unsupported_parameter_value"}}"#,
            // F-16: realistic refusals phrased without `param`/`loc` or an
            // allowlisted code — a token-level mention of the field plus a
            // narrow parameter-refusal phrase (or a stream-capability
            // statement) is a signal.
            r#"{"error":{"code":400,"message":"Unknown name \"stream_options\": Cannot find field.","status":"INVALID_ARGUMENT"}}"#,
            r#"{"error":{"message":"litellm.BadRequestError: Extra inputs are not permitted: stream_options","type":"invalid_request_error"}}"#,
            r#"{"object":"error","message":"This model does not support streaming","type":"BadRequestError","code":400}"#,
            r#"{"type":"error","error":{"type":"invalid_request_error","message":"messages: unexpected keyword argument \"stream\""}}"#,
            r#"{"error":{"message":"Invalid value for 'stream': must be a boolean","type":"invalid_request_error"}}"#,
            // Canonical short messages.
            r#"{"error":{"message":"stream not supported"}}"#,
            r#"{"error":{"message":"Not Implemented"}}"#,
            "Not Implemented",
            "stream not supported",
        ];
        for body in positives {
            assert!(
                stream_unsupported(reqwest::StatusCode::BAD_REQUEST, body),
                "a structured stream refusal must fall back: {body:?}"
            );
        }
        for refusal_status in [400, 404, 405, 415, 422, 501] {
            assert!(
                stream_unsupported(
                    reqwest::StatusCode::from_u16(refusal_status).unwrap(),
                    r#"{"error":{"param":"stream"}}"#
                ),
                "status {refusal_status} with a stream param must fall back"
            );
        }

        // F-13(m3): prose words like `model`/`upstream` do not disable a
        // structured signal.
        assert!(stream_unsupported(
            reqwest::StatusCode::BAD_REQUEST,
            r#"{"error":{"message":"model deepseek-chat rejects upstream stream_options","param":"stream_options","code":"unsupported_parameter"}}"#
        ));
    }

    /// F-11: prose is never a signal. `upstream` alone used to be enough to
    /// re-send a genuine 400 through `complete()` (doubling the bill).
    #[test]
    fn genuine_errors_are_not_structured_stream_refusals() {
        let negatives = [
            r#"{"error":{"message":"upstream connect error"}}"#,
            r#"{"error":{"message":"no healthy upstream"}}"#,
            r#"{"error":{"message":"downstream timeout"}}"#,
            r#"{"error":{"message":"Invalid api key: 'stream'"}}"#,
            r#"{"error":{"message":"streaming is disabled for this upstream"}}"#,
            r#"{"detail":"bad body: {\"model\":\"x\",\"stream\":true}"}"#,
            "<html><body><!-- streaming not enabled --></body></html>",
            r#"{"error":"unknown field: streaming_model_v2"}"#,
            r#"{"stream":true,"error":{"message":"invalid temperature"}}"#,
            r#"{"model":"stream","error":{"message":"bad request"}}"#,
            r#"{"error":{"code":"invalid_request_error","message":"stream is broken"}}"#,
            r#"{"error":{"message":"Model Not Exist"}}"#,
            "upstream connect error",
            "invalid request: temperature out of range",
            "",
        ];
        for body in negatives {
            assert!(
                !stream_unsupported(reqwest::StatusCode::BAD_REQUEST, body),
                "a genuine error must never be treated as a stream refusal: {body:?}"
            );
            assert!(
                !stream_unsupported(reqwest::StatusCode::UNPROCESSABLE_ENTITY, body),
                "a genuine 422 must never be treated as a stream refusal: {body:?}"
            );
        }
        // Refusal statuses are required too: auth errors, 429 and 5xx never
        // fall back even when the body names the stream parameter.
        for status in [401, 403, 429, 500, 503] {
            assert!(
                !stream_unsupported(
                    reqwest::StatusCode::from_u16(status).unwrap(),
                    r#"{"error":{"param":"stream"}}"#
                ),
                "status {status} must never fall back"
            );
        }
    }

    fn user_message() -> crate::types::SafeMessage {
        let mut gate = tokenising_gate([7u8; 32]);
        crate::types::SafeMessage::from_text(
            crate::types::ChatRole::User,
            gate.text("Invite Camille.").expect("the text passes").0,
        )
    }

    /// A request that forces its skill, built the way the engine builds one.
    fn forced_request() -> ChatRequest {
        let mut gate = tokenising_gate([7u8; 32]);
        let spec = crate::types::ToolSpec::new(
            "skill__send-invite",
            "Send the invitation",
            json!({ "type": "object" }),
        );
        let tool = crate::types::SafeToolSpec::issue(&mut gate, &spec).expect("the spec issues");
        ChatRequest::new(vec![user_message()])
            .with_tools(vec![tool])
            .with_forced_tool("skill__send-invite")
    }

    fn ok_response(content: &str) -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "role": "assistant", "content": content } }]
        }))
    }

    /// An endpoint that refuses every body containing one of `refused` with a
    /// 400 that names `tool_choice`, and answers every other body with "done".
    /// The refusals are mounted first: wiremock answers with the first match.
    async fn refusing_provider(refused: &[&str]) -> (wiremock::MockServer, OpenAiCompat) {
        let server = wiremock::MockServer::start().await;
        for needle in refused {
            wiremock::Mock::given(wiremock::matchers::body_string_contains(*needle))
                .respond_with(wiremock::ResponseTemplate::new(400).set_body_json(json!({
                    "error": { "message": "Thinking mode does not support this tool_choice" }
                })))
                .mount(&server)
                .await;
        }
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(ok_response("done"))
            .mount(&server)
            .await;
        let mut config = config();
        config.base_url = format!("{}/v1", server.uri());
        let provider = OpenAiCompat::with_key_and_timeout(&config, None, Duration::from_secs(30))
            .expect("the adapter builds");
        (server, provider)
    }

    const NAMED: &str = r#""tool_choice":{"type":"function""#;
    const REQUIRED: &str = r#""tool_choice":"required""#;
    const AUTO: &str = r#""tool_choice":"auto""#;

    /// The documented toggle (`thinking: {"type": "disabled"}`) is sent only when
    /// the provider config asks for it.
    #[tokio::test]
    async fn disable_thinking_sends_the_documented_toggle_and_only_then() {
        for disable in [true, false] {
            let server = wiremock::MockServer::start().await;
            wiremock::Mock::given(wiremock::matchers::any())
                .respond_with(ok_response("done"))
                .mount(&server)
                .await;
            let mut config = config();
            config.base_url = format!("{}/v1", server.uri());
            config.disable_thinking = disable;
            let provider =
                OpenAiCompat::with_key_and_timeout(&config, None, Duration::from_secs(30))
                    .expect("the adapter builds");
            let request = ChatRequest::new(vec![user_message()]);
            provider
                .complete(&request)
                .await
                .expect("the request completes");
            provider
                .complete_streaming(&request, &|_| {})
                .await
                .expect("the streamed request completes");

            let sent = server
                .received_requests()
                .await
                .expect("requests are recorded");
            assert_eq!(sent.len(), 2, "one plain and one streamed request");
            for request in sent {
                let body: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("a JSON body");
                if disable {
                    assert_eq!(body["thinking"], json!({ "type": "disabled" }), "{body}");
                } else {
                    assert!(body.get("thinking").is_none(), "{body}");
                }
            }
        }
    }

    /// DeepSeek thinking mode's rule, as its API applies it: an assistant
    /// tool-call row after the last user message without `reasoning_content`.
    struct MissingReasoning;

    impl wiremock::Match for MissingReasoning {
        fn matches(&self, request: &wiremock::Request) -> bool {
            let Ok(body) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
                return false;
            };
            let messages = body["messages"].as_array().cloned().unwrap_or_default();
            let turn = messages
                .iter()
                .rposition(|message| message["role"] == "user")
                .map_or(0, |index| index + 1);
            messages[turn..].iter().any(|message| {
                message["role"] == "assistant"
                    && message.get("tool_calls").is_some()
                    && message.get("reasoning_content").is_none()
            })
        }
    }

    const REASONING_REFUSAL: &str =
        "The `reasoning_content` in the thinking mode must be passed back to the API.";

    /// An endpoint that refuses with DeepSeek's 400 every body `refused` matches,
    /// and answers every other body with "done".
    async fn thinking_provider(
        refused: impl wiremock::Match + 'static,
    ) -> (wiremock::MockServer, OpenAiCompat) {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(refused)
            .respond_with(wiremock::ResponseTemplate::new(400).set_body_json(json!({
                "error": { "message": REASONING_REFUSAL, "type": "invalid_request_error" }
            })))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(ok_response("done"))
            .mount(&server)
            .await;
        let mut config = config();
        config.base_url = format!("{}/v1", server.uri());
        let provider = OpenAiCompat::with_key_and_timeout(&config, None, Duration::from_secs(30))
            .expect("the adapter builds");
        (server, provider)
    }

    /// An earlier turn's tool call, the user's message, then a tool call the
    /// engine wrote itself (no reasoning) and its result, as FOLLOWUP-READ-FIRST
    /// sends them.
    fn pre_read_request() -> ChatRequest {
        let mut gate = tokenising_gate([7u8; 32]);
        let mut issue = |message: ChatMessage| {
            SafeMessage::issue(&mut gate, &message).expect("the message issues")
        };
        let call = |id: &str| ToolCall::new(id, "mail_search", json!({ "query": "zork" }));
        ChatRequest::new(vec![
            issue(ChatMessage::assistant_with_tool_calls(
                "",
                vec![call("old_1")],
            )),
            issue(ChatMessage::tool_result("old_1", "no mail")),
            user_message(),
            issue(ChatMessage::assistant_with_tool_calls(
                "",
                vec![call("pre_read_0_search")],
            )),
            issue(ChatMessage::tool_result("pre_read_0_search", "no mail")),
        ])
    }

    /// FOLLOWUP-REASONING-400: a thinking-mode endpoint refuses this turn's tool
    /// call without reasoning. It is re-sent once with `reasoning_content: ""`
    /// on that row only; the adapter then sends the field at once (the streamed
    /// call goes out filled).
    #[tokio::test]
    async fn a_tool_call_without_reasoning_is_resent_with_an_empty_one() {
        let (server, provider) = thinking_provider(MissingReasoning).await;
        let request = pre_read_request();
        let reply = provider
            .complete(&request)
            .await
            .expect("the re-send passes");
        assert_eq!(reply.message.content, "done");
        provider
            .complete_streaming(&request, &|_| {})
            .await
            .expect("the streamed request passes at once");

        let sent = server.received_requests().await.expect("recorded");
        assert_eq!(
            sent.len(),
            3,
            "one refusal, one re-send, one streamed request"
        );
        for request in &sent[1..] {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["messages"][3]["reasoning_content"], "", "{body}");
            assert!(
                body["messages"][0].get("reasoning_content").is_none(),
                "{body}"
            );
        }
    }

    /// An endpoint that never asks for reasoning never receives the field.
    #[tokio::test]
    async fn an_endpoint_that_never_asks_gets_no_reasoning_field() {
        let (server, provider) = refusing_provider(&[]).await;
        provider
            .complete(&pre_read_request())
            .await
            .expect("the request completes");
        let sent = server.received_requests().await.expect("recorded");
        assert_eq!(sent.len(), 1);
        let body = String::from_utf8_lossy(&sent[0].body);
        assert!(!body.contains("reasoning_content"), "{body}");
    }

    /// A refusal that stays after the backfill surfaces: one re-send, no loop.
    #[tokio::test]
    async fn a_reasoning_refusal_is_resent_at_most_once() {
        let (server, provider) = thinking_provider(wiremock::matchers::any()).await;
        let err = provider
            .complete(&pre_read_request())
            .await
            .expect_err("the refusal surfaces");
        assert!(err.to_string().contains("400"), "{err}");
        let sent = server.received_requests().await.expect("recorded");
        assert_eq!(sent.len(), 2, "the refusal and one re-send");
    }

    /// A thinking-mode endpoint refuses the named `tool_choice`, then `required`
    /// (both are 400 there). The request steps down to `auto` and stops: three
    /// requests per call at most, on the plain and the streaming path alike.
    #[tokio::test]
    async fn a_refused_tool_choice_steps_down_to_auto_and_no_further() {
        let (server, provider) = refusing_provider(&[NAMED, REQUIRED]).await;
        let request = forced_request();

        let plain = provider
            .complete(&request)
            .await
            .expect("the plain path steps down to auto");
        assert_eq!(plain.message.content, "done");
        let streamed = provider
            .complete_streaming(&request, &|_| {})
            .await
            .expect("the streaming path steps down to auto");
        assert_eq!(streamed.message.content, "done");
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("requests are recorded")
                .len(),
            6,
            "named, required and auto, once per call"
        );
    }

    /// When `auto` is refused too there is nothing left to step down to: the
    /// refusal is the error, after exactly three requests.
    #[tokio::test]
    async fn a_refused_auto_is_the_error_after_three_requests() {
        let (server, provider) = refusing_provider(&[NAMED, REQUIRED, AUTO]).await;

        let err = provider
            .complete(&forced_request())
            .await
            .expect_err("every step refused");

        assert!(format!("{err:?}").contains("400"), "{err:?}");
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("requests are recorded")
                .len(),
            3
        );
    }

    /// P2 (security-review round 1): a provider that echoes the key in a 400 body
    /// must not have it copied into the error, its Display or its Debug.
    #[tokio::test]
    async fn a_key_echoed_in_an_error_body_is_redacted() {
        const KEY: &str = "sk-a4-redact-openai-0001";
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/chat/completions"))
            .respond_with(wiremock::ResponseTemplate::new(400).set_body_json(json!({
                "error": { "message": format!("bad key {KEY}") }
            })))
            .mount(&server)
            .await;
        let mut config = config();
        config.base_url = format!("{}/v1", server.uri());
        let provider = OpenAiCompat::with_key_and_timeout(
            &config,
            Some(KEY.to_string()),
            Duration::from_secs(30),
        )
        .unwrap();

        let err = provider
            .complete(&ChatRequest::new(vec![user_message()]))
            .await
            .expect_err("a 400 is an error");

        assert!(
            matches!(err, ProviderError::Client { status: 400, .. }),
            "got {err:?}"
        );
        let display = err.to_string();
        assert!(
            !display.contains(KEY),
            "the key leaked into Display: {display}"
        );
        let debug = format!("{err:?}");
        assert!(!debug.contains(KEY), "the key leaked into Debug: {debug}");
        if let ProviderError::Client { message, .. } = &err {
            assert!(message.contains("[REDACTED]"), "message: {message}");
            assert!(!message.contains(KEY));
        }
    }
}
