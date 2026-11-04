//! Anthropic `v1/messages` chat adapter (`docs/providers.md` §5.1).
//!
//! The key travels only in the `x-api-key` header: never in a URL, never in a
//! body, never in a log. Forced `tool_choice` is never sent — an endpoint that
//! rejects `any`/`tool` gets `auto` with the one skill tool offered and a
//! system line telling the model to call it. `stop_reason: "refusal"` is a
//! typed [`ProviderError::Refused`], not a fallback trigger.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderValue, RETRY_AFTER};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::{shown_base_url, shown_id_plain};
use crate::error::{redact_upstream, ProviderError};
use crate::provider::ChatProvider;
use crate::providers_toml::{anthropic_messages_url, resolve_entry_key, Effort, ProviderEntry};
use crate::types::{
    assembled_arguments, ChatDelta, ChatMessage, ChatRequest, ChatResponse, ChatRole, ToolCall,
    ToolChoice, Usage,
};

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// Non-streaming `max_tokens`.
pub const DEFAULT_MAX_TOKENS: u32 = 16_000;

/// `anthropic-version` header value.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Streaming `max_tokens`.
pub const STREAMING_MAX_TOKENS: u32 = 64_000;

/// Overall deadline for one streamed request, as a multiple of the configured
/// connect/idle timeout: `read_timeout` resets on every read, so on its own it
/// cannot bound a server that dribbles one byte at a time.
const STREAM_TOTAL_TIMEOUT_FACTOR: u32 = 10;

/// Hard ceilings for one streamed response (bounded everything).
const MAX_STREAM_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_STREAM_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_STREAM_TOOL_ARGUMENT_BYTES: usize = 256 * 1024;
const MAX_STREAM_TOOL_CALLS: usize = 64;
const STREAM_TOO_LARGE: &str = "stream_too_large";

/// Adapter for the Anthropic `v1/messages` wire.
pub struct AnthropicCompat {
    id: String,
    endpoint: String,
    model: String,
    effort: Effort,
    api_key: Option<String>,
    /// Client for one-body calls: the configured timeout bounds the request.
    http: Client,
    /// Client for SSE calls: connect plus idle-read timeout, no total timeout;
    /// the per-request deadline is applied on the request itself.
    http_stream: Client,
    /// Overall deadline per streamed request.
    stream_total_timeout: Duration,
}

impl AnthropicCompat {
    /// Build the adapter for an entry, resolving the key from the entry's
    /// `env:` reference (process environment, then `~/.auxesis/.env`).
    pub fn new(entry: &ProviderEntry, model: &str, home: &Path) -> Result<Self, ProviderError> {
        let key = resolve_entry_key(entry, home)?;
        Self::with_key(entry, model, key)
    }

    /// Build the adapter with an explicit API key (tests, key onboarding).
    pub fn with_key(
        entry: &ProviderEntry,
        model: &str,
        api_key: Option<String>,
    ) -> Result<Self, ProviderError> {
        Self::with_key_and_timeout(entry, model, api_key, DEFAULT_TIMEOUT)
    }

    /// Build the adapter with an explicit API key and request timeout.
    pub fn with_key_and_timeout(
        entry: &ProviderEntry,
        model: &str,
        api_key: Option<String>,
        timeout: Duration,
    ) -> Result<Self, ProviderError> {
        entry.validate()?;
        let base = entry
            .base_url
            .as_deref()
            .expect("validate requires a base_url");
        let endpoint = anthropic_messages_url(base)?;
        if let Some(key) = &api_key {
            // H-04/L-1: the exact value joins the scrubber so it is redacted
            // if it ever reaches a log or a preview. Never logged directly.
            kernel_broker::scrub::register_known_secret(key);
        }
        // security-review round 2, P2: never follow a redirect. A 3xx from the
        // configured origin would otherwise forward the key and the prompt to
        // another host; the response is surfaced as a provider error instead.
        let http = Client::builder()
            .connect_timeout(timeout)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(client_error)?;
        let http_stream = Client::builder()
            .connect_timeout(timeout)
            .read_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(client_error)?;
        Ok(Self {
            id: entry.id.clone(),
            endpoint,
            model: model.to_string(),
            effort: entry.effort.unwrap_or(Effort::Medium),
            api_key,
            http,
            http_stream,
            stream_total_timeout: timeout.saturating_mul(STREAM_TOTAL_TIMEOUT_FACTOR),
        })
    }

    /// Full URL called for messages.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Build a POST with the Anthropic auth headers applied.
    fn send(
        &self,
        client: &Client,
        body: &Value,
    ) -> Result<reqwest::RequestBuilder, ProviderError> {
        let mut builder = client.post(&self.endpoint).json(body);
        if let Some(key) = &self.api_key {
            let value = HeaderValue::from_str(key).map_err(|_| {
                ProviderError::Config(crate::config::ConfigError::Invalid(format!(
                    "provider `{}`: API key is not a valid HTTP header value",
                    shown_id_plain(&self.id)
                )))
            })?;
            builder = builder
                .header("x-api-key", value)
                .header("anthropic-version", ANTHROPIC_VERSION);
        }
        Ok(builder)
    }

    /// The request body; `stream` switches `max_tokens` and adds `stream: true`.
    fn request_body(&self, req: &ChatRequest, stream: bool) -> Value {
        let (mut system, messages) = to_anthropic_messages(req);
        let (tools, tool_choice, forced_line) = anthropic_tools(req);
        if let Some(line) = forced_line {
            system = Some(match system {
                Some(existing) => format!("{existing}\n{line}"),
                None => line,
            });
        }
        let model = req
            .model
            .as_ref()
            .map_or(self.model.as_str(), |model| model.as_str());
        let max_tokens = if stream {
            STREAMING_MAX_TOKENS
        } else {
            DEFAULT_MAX_TOKENS
        };
        let mut body = json!({
            "model": model,
            "max_tokens": max_tokens,
            "messages": messages,
            "output_config": { "effort": self.effort.as_str() },
        });
        if stream {
            body["stream"] = json!(true);
        }
        if let Some(system) = system {
            body["system"] = json!(system);
        }
        if let Some(tools) = tools {
            body["tools"] = json!(tools);
        }
        if let Some(choice) = tool_choice {
            body["tool_choice"] = choice;
        }
        body
    }
}

impl fmt::Debug for AnthropicCompat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicCompat")
            .field("id", &shown_id_plain(&self.id))
            .field("endpoint", &shown_base_url(&self.endpoint))
            .field("model", &shown_id_plain(&self.model))
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[async_trait]
impl ChatProvider for AnthropicCompat {
    fn endpoint_host(&self) -> Option<String> {
        reqwest::Url::parse(&self.endpoint)
            .ok()?
            .host_str()
            .map(str::to_string)
    }

    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let body = self.request_body(req, false);
        let response = self
            .send(&self.http, &body)?
            .send()
            .await
            .map_err(|err| request_error(&self.id, err))?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(parse_retry_after);
        let text = response
            .text()
            .await
            .map_err(|err| request_error(&self.id, err))?;
        if !status.is_success() {
            return Err(status_error(
                &self.id,
                status,
                retry_after,
                &text,
                self.api_key.as_deref(),
            ));
        }
        parse_response(&self.id, &text)
    }

    async fn complete_streaming(
        &self,
        req: &ChatRequest,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        let body = self.request_body(req, true);
        let mut response = self
            .send(&self.http_stream, &body)?
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
            let text = response
                .text()
                .await
                .map_err(|err| request_error(&self.id, err))?;
            return Err(status_error(
                &self.id,
                status,
                retry_after,
                &text,
                self.api_key.as_deref(),
            ));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if content_type.contains("application/json") {
            // The server ignored `stream: true` and answered one JSON body.
            let text = response
                .text()
                .await
                .map_err(|err| request_error(&self.id, err))?;
            return parse_response(&self.id, &text);
        }
        let mut assembler = AnthropicStream::new(&self.id, self.api_key.clone());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| request_error(&self.id, err))?
        {
            assembler.push(&chunk, sink)?;
            if assembler.saw_message_stop() {
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

/// One streamed tool call being assembled from `input_json_delta` fragments.
#[derive(Default)]
struct PartialTool {
    id: String,
    name: String,
    arguments: String,
}

/// Assembles an Anthropic SSE stream into one [`ChatResponse`].
struct AnthropicStream {
    provider: String,
    /// The resolved key, redacted from any upstream-supplied stream error.
    key: Option<String>,
    pending: String,
    content: String,
    tool_calls: Vec<ToolCall>,
    partials: std::collections::BTreeMap<u64, PartialTool>,
    stop_reason: Option<String>,
    input_tokens: u64,
    cached_input_tokens: Option<u64>,
    output_tokens: u64,
    saw_stop: bool,
}

impl AnthropicStream {
    fn new(provider: &str, key: Option<String>) -> Self {
        Self {
            provider: provider.to_string(),
            key,
            pending: String::new(),
            content: String::new(),
            tool_calls: Vec::new(),
            partials: std::collections::BTreeMap::new(),
            stop_reason: None,
            input_tokens: 0,
            cached_input_tokens: None,
            output_tokens: 0,
            saw_stop: false,
        }
    }

    fn saw_message_stop(&self) -> bool {
        self.saw_stop
    }

    fn push(
        &mut self,
        chunk: &[u8],
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<(), ProviderError> {
        self.pending.push_str(&String::from_utf8_lossy(chunk));
        if self.pending.len() > MAX_STREAM_BODY_BYTES {
            return Err(self.too_large("body"));
        }
        while let Some(index) = self.pending.find('\n') {
            let line = self.pending[..index].to_string();
            self.pending.drain(..=index);
            self.line(line.trim_end_matches('\r'), sink)?;
        }
        Ok(())
    }

    fn line(
        &mut self,
        line: &str,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<(), ProviderError> {
        let Some(data) = line.strip_prefix("data:") else {
            return Ok(());
        };
        let data = data.trim();
        if data.is_empty() {
            return Ok(());
        }
        let value: Value = serde_json::from_str(data)
            .map_err(|err| self.invalid(format!("stream event is not JSON: {err}")))?;
        self.event(&value, sink)
    }

    fn event(
        &mut self,
        value: &Value,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<(), ProviderError> {
        match value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "message_start" => {
                let count = |field| value.pointer(field).and_then(Value::as_u64);
                self.cached_input_tokens = count("/message/usage/cache_read_input_tokens");
                // Anthropic's `input_tokens` excludes cache reads; ours includes them.
                self.input_tokens = count("/message/usage/input_tokens")
                    .unwrap_or(0)
                    .saturating_add(self.cached_input_tokens.unwrap_or(0));
            }
            "content_block_start" => {
                let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
                if value.pointer("/content_block/type").and_then(Value::as_str) == Some("tool_use")
                {
                    if self.partials.len() + self.tool_calls.len() >= MAX_STREAM_TOOL_CALLS {
                        return Err(self.too_large("tool calls"));
                    }
                    let id = value
                        .pointer("/content_block/id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let name = value
                        .pointer("/content_block/name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    self.partials.insert(
                        index,
                        PartialTool {
                            id,
                            name,
                            arguments: String::new(),
                        },
                    );
                }
            }
            "content_block_delta" => {
                let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
                match value
                    .pointer("/delta/type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                {
                    "text_delta" => {
                        if let Some(text) = value.pointer("/delta/text").and_then(Value::as_str) {
                            if self.content.len() + text.len() > MAX_STREAM_CONTENT_BYTES {
                                return Err(self.too_large("content"));
                            }
                            self.content.push_str(text);
                            sink(ChatDelta::Text(text.to_string()));
                        }
                    }
                    "input_json_delta" => {
                        if let (Some(partial), Some(fragment)) = (
                            self.partials.get_mut(&index),
                            value.pointer("/delta/partial_json").and_then(Value::as_str),
                        ) {
                            if partial.arguments.len() + fragment.len()
                                > MAX_STREAM_TOOL_ARGUMENT_BYTES
                            {
                                return Err(self.too_large("tool arguments"));
                            }
                            partial.arguments.push_str(fragment);
                        }
                    }
                    _ => {}
                }
            }
            "content_block_stop" => {
                let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
                if let Some(partial) = self.partials.remove(&index) {
                    if partial.name.is_empty() {
                        return Err(self.invalid("streamed tool_use block has an empty name"));
                    }
                    let call = ToolCall::new(
                        partial.id,
                        partial.name,
                        assembled_arguments(&partial.arguments),
                    );
                    self.tool_calls.push(call.clone());
                    sink(ChatDelta::ToolCall(call));
                }
            }
            "message_delta" => {
                if let Some(reason) = value.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    self.stop_reason = Some(reason.to_string());
                }
                if let Some(out) = value
                    .pointer("/usage/output_tokens")
                    .and_then(Value::as_u64)
                {
                    self.output_tokens = out;
                }
            }
            "message_stop" => self.saw_stop = true,
            "error" => {
                let message = value
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("stream error");
                let message = redact_upstream(message, self.key.as_deref());
                return Err(self.invalid(format!("provider stream error: {message}")));
            }
            _ => {}
        }
        Ok(())
    }

    fn finish(
        &self,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        if self.stop_reason.as_deref() == Some("refusal") {
            return Err(ProviderError::Refused {
                provider: shown_id_plain(&self.provider),
                category: "refusal".to_string(),
            });
        }
        if self.stop_reason.as_deref() == Some("max_tokens") && !self.tool_calls.is_empty() {
            return Err(
                self.invalid("max_tokens cut a tool call; the partial call was not executed")
            );
        }
        let usage = if self.input_tokens > 0 || self.output_tokens > 0 {
            Some(Usage {
                prompt_tokens: self.input_tokens,
                completion_tokens: self.output_tokens,
                cost_usd: None,
                cached_prompt_tokens: self.cached_input_tokens,
            })
        } else {
            None
        };
        if let Some(usage) = usage {
            sink(ChatDelta::Usage(usage));
        }
        let message = if self.tool_calls.is_empty() {
            ChatMessage::assistant(self.content.clone())
        } else {
            ChatMessage::assistant_with_tool_calls(self.content.clone(), self.tool_calls.clone())
        };
        Ok(ChatResponse { message, usage })
    }

    fn too_large(&self, what: &str) -> ProviderError {
        self.invalid(format!("{STREAM_TOO_LARGE}: streamed {what} over the cap"))
    }

    fn invalid(&self, message: impl Into<String>) -> ProviderError {
        ProviderError::InvalidResponse {
            provider: shown_id_plain(&self.provider),
            message: message.into(),
        }
    }
}

/// Convert gated messages into `(system, messages)` on the Anthropic wire.
///
/// System messages are joined into one `system` string. Assistant tool calls
/// become `tool_use` blocks; consecutive tool results become `tool_result`
/// blocks in one user message.
pub(crate) fn to_anthropic_messages(req: &ChatRequest) -> (Option<String>, Vec<Value>) {
    let mut system_parts: Vec<String> = Vec::new();
    let mut messages: Vec<Value> = Vec::new();
    let mut pending_results: Vec<Value> = Vec::new();

    for message in req.messages.iter() {
        match message.role() {
            ChatRole::System => system_parts.push(message.content().as_str().to_string()),
            ChatRole::User => {
                flush_tool_results(&mut messages, &mut pending_results);
                messages.push(json!({
                    "role": "user",
                    "content": message.content().as_str(),
                }));
            }
            ChatRole::Assistant => {
                flush_tool_results(&mut messages, &mut pending_results);
                let calls = message.tool_calls();
                if calls.is_empty() {
                    messages.push(json!({
                        "role": "assistant",
                        "content": message.content().as_str(),
                    }));
                } else {
                    let mut blocks: Vec<Value> = Vec::new();
                    if !message.content().as_str().is_empty() {
                        blocks.push(json!({ "type": "text", "text": message.content().as_str() }));
                    }
                    for call in calls {
                        blocks.push(json!({
                            "type": "tool_use",
                            "id": call.id().as_str(),
                            "name": call.name().as_str(),
                            "input": call.arguments().as_value(),
                        }));
                    }
                    messages.push(json!({ "role": "assistant", "content": blocks }));
                }
            }
            ChatRole::Tool => {
                pending_results.push(json!({
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id().map(|id| id.as_str()).unwrap_or(""),
                    "content": message.content().as_str(),
                }));
            }
        }
    }
    flush_tool_results(&mut messages, &mut pending_results);

    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    (system, messages)
}

fn flush_tool_results(messages: &mut Vec<Value>, pending: &mut Vec<Value>) {
    if !pending.is_empty() {
        let results = std::mem::take(pending);
        messages.push(json!({ "role": "user", "content": results }));
    }
}

/// `(tools, tool_choice, extra system line)` for a request.
///
/// A forced `skill__<name>` is never sent as a forced `tool_choice`: only that
/// tool is offered, with `strict: true`, `tool_choice: auto`, plus one system
/// line.
pub(crate) fn anthropic_tools(
    req: &ChatRequest,
) -> (Option<Vec<Value>>, Option<Value>, Option<String>) {
    if req.tools.is_empty() {
        return (None, None, None);
    }
    if let Some(ToolChoice::Function(name)) = &req.tool_choice {
        if let Some(spec) = req.tools.iter().find(|spec| spec.name().as_str() == name) {
            let tool = json!({
                "name": spec.name().as_str(),
                "description": spec.description().as_str(),
                "input_schema": spec.parameters().as_value(),
                "strict": true,
            });
            let line = format!("Call the tool {name} exactly once. Do not answer in text.");
            return (
                Some(vec![tool]),
                Some(json!({ "type": "auto" })),
                Some(line),
            );
        }
    }
    let tools: Vec<Value> = req
        .tools
        .iter()
        .map(|spec| {
            json!({
                "name": spec.name().as_str(),
                "description": spec.description().as_str(),
                "input_schema": spec.parameters().as_value(),
            })
        })
        .collect();
    (Some(tools), Some(json!({ "type": "auto" })), None)
}

#[derive(Debug, Deserialize)]
struct WireResponse {
    #[serde(default)]
    content: Vec<WireBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
    #[serde(default)]
    usage: Option<WireUsage>,
}

#[derive(Debug, Deserialize)]
struct WireBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    input: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: Option<u64>,
}

/// Parse one `v1/messages` response body.
pub(crate) fn parse_response(provider: &str, body: &str) -> Result<ChatResponse, ProviderError> {
    let wire: WireResponse =
        serde_json::from_str(body).map_err(|err| ProviderError::InvalidResponse {
            provider: shown_id_plain(provider),
            message: format!("messages response is not JSON: {err}"),
        })?;

    if wire.stop_reason.as_deref() == Some("refusal") {
        return Err(ProviderError::Refused {
            provider: shown_id_plain(provider),
            category: "refusal".to_string(),
        });
    }

    let mut content = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    for block in &wire.content {
        match block.kind.as_str() {
            "text" => {
                if let Some(text) = &block.text {
                    content.push_str(text);
                }
            }
            "tool_use" => {
                let name = block
                    .name
                    .clone()
                    .ok_or_else(|| ProviderError::InvalidResponse {
                        provider: shown_id_plain(provider),
                        message: "tool_use block has no name".to_string(),
                    })?;
                if name.is_empty() {
                    return Err(ProviderError::InvalidResponse {
                        provider: shown_id_plain(provider),
                        message: "tool_use block has an empty name".to_string(),
                    });
                }
                tool_calls.push(ToolCall::new(
                    block.id.clone().unwrap_or_default(),
                    name,
                    block.input.clone().unwrap_or(Value::Null),
                ));
            }
            _ => {}
        }
    }

    if wire.stop_reason.as_deref() == Some("max_tokens") && !tool_calls.is_empty() {
        return Err(ProviderError::InvalidResponse {
            provider: shown_id_plain(provider),
            message: "max_tokens cut a tool call; the partial call was not executed".to_string(),
        });
    }

    let message = if tool_calls.is_empty() {
        ChatMessage::assistant(content)
    } else {
        ChatMessage::assistant_with_tool_calls(content, tool_calls)
    };
    let usage = wire.usage.map(|usage| Usage {
        prompt_tokens: (usage.input_tokens)
            .saturating_add(usage.cache_read_input_tokens.unwrap_or(0)),
        completion_tokens: usage.output_tokens,
        cost_usd: None,
        cached_prompt_tokens: usage.cache_read_input_tokens,
    });
    Ok(ChatResponse { message, usage })
}

fn client_error(err: reqwest::Error) -> ProviderError {
    ProviderError::Config(crate::config::ConfigError::Invalid(format!(
        "building HTTP client: {}",
        err.without_url()
    )))
}

fn request_error(provider: &str, err: reqwest::Error) -> ProviderError {
    let provider = shown_id_plain(provider);
    if err.is_timeout() {
        ProviderError::Timeout { provider }
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
        code if (500..=599).contains(&code) => ProviderError::Server {
            provider,
            status: code,
        },
        code => ProviderError::Client {
            provider,
            status: code,
            // The upstream body may echo the key.
            message: error_message(&redact_upstream(body, key)),
        },
    }
}

fn error_message(body: &str) -> String {
    let parsed = serde_json::from_str::<Value>(body).ok();
    let from_json = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/message"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|value| value.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    let message = from_json.unwrap_or_else(|| body.trim().to_string());
    let mut truncated: String = message.chars().take(300).collect();
    if message.chars().count() > 300 {
        truncated.push('…');
    }
    truncated
}

fn parse_retry_after(value: &HeaderValue) -> Option<Duration> {
    value
        .to_str()
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers_toml::parse_providers_toml;
    use crate::types::SafeMessage;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn tokenising_gate(key: [u8; 32]) -> kernel_privacy::safetext::Gate {
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        kernel_privacy::safetext::Gate::for_tests(&grant, key, crate::test_gate::names_checked())
    }

    fn entry(server: &str) -> ProviderEntry {
        let text = format!(
            r#"
[[provider]]
id = "anthropic"
kind = "anthropic"
base_url = "{server}"
key = "env:AUX_KEY_ANTHROPIC"
effort = "high"
"#
        );
        parse_providers_toml(&text).unwrap().providers.remove(0)
    }

    fn request(messages: Vec<SafeMessage>) -> ChatRequest {
        ChatRequest::new(messages)
    }

    #[test]
    fn debug_never_shows_a_key_in_the_endpoint_or_id() {
        let key = ["sk", "-proj-", "CANARY-", "7f3k9q"].concat();
        let mut entry = entry("https://api.example.com/v1");
        entry.base_url = Some(format!("https://api.example.com/v1/{key}"));
        let mut provider = AnthropicCompat::with_key(&entry, "m", Some("k".into())).unwrap();
        // A validated entry cannot carry a key-shaped id; Debug still hides one.
        provider.id = key.clone();
        let text = format!("{provider:?}");
        assert!(!text.to_lowercase().contains("canary"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(text.contains("<id>"), "{text}");
    }

    #[test]
    fn cache_reads_count_as_cached_prompt_tokens() {
        let usage =
            json!({ "input_tokens": 20, "cache_read_input_tokens": 80, "output_tokens": 3 });
        let body = json!({ "content": [], "usage": usage }).to_string();
        let usage = parse_response("anthropic", &body).unwrap().usage.unwrap();
        assert_eq!(
            (usage.prompt_tokens, usage.cached_prompt_tokens),
            (100, Some(80))
        );
    }

    #[tokio::test]
    async fn complete_sends_the_anthropic_wire_and_reads_text_and_usage() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [{ "type": "text", "text": "bonjour" }],
                "stop_reason": "end_turn",
                "usage": { "input_tokens": 11, "output_tokens": 3 }
            })))
            .mount(&server)
            .await;

        let entry = entry(&server.uri());
        let provider =
            AnthropicCompat::with_key(&entry, "claude-opus-5-5", Some("sk-secret-value".into()))
                .unwrap();
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("salut")).unwrap();
        let response = provider.complete(&request(vec![message])).await.unwrap();

        assert_eq!(response.content(), "bonjour");
        assert_eq!(response.usage.unwrap().prompt_tokens, 11);
        assert_eq!(provider.effort, Effort::High);

        let requests = server.received_requests().await.unwrap();
        let body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert_eq!(
            requests[0].headers["x-api-key"].to_str().unwrap(),
            "sk-secret-value"
        );
        assert_eq!(
            requests[0].headers["anthropic-version"].to_str().unwrap(),
            ANTHROPIC_VERSION
        );
        assert!(
            !body.contains("sk-secret-value"),
            "key leaked into the body: {body}"
        );
        assert!(!requests[0].url.as_str().contains("sk-secret-value"));
        assert!(
            !body.contains("temperature"),
            "temperature must not be sent"
        );
        assert_eq!(requests[0].url.path(), "/v1/messages");
        let value: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["max_tokens"], json!(DEFAULT_MAX_TOKENS));
        assert_eq!(value["output_config"]["effort"], "high");
    }

    #[tokio::test]
    async fn a_forced_tool_is_offered_alone_with_auto_and_a_system_line() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{ "type": "tool_use", "id": "t1", "name": "skill__invite", "input": { "to": "x" } }],
                "stop_reason": "tool_use"
            })))
            .mount(&server)
            .await;

        let entry = entry(&server.uri());
        let provider =
            AnthropicCompat::with_key(&entry, "claude-opus-5-5", Some("k".into())).unwrap();
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("invite")).unwrap();
        let spec = crate::types::ToolSpec::new(
            "skill__invite",
            "send an invite",
            json!({ "type": "object" }),
        );
        let primary = crate::types::SafeToolSpec::issue(&mut gate, &spec).unwrap();
        let other = crate::types::SafeToolSpec::issue(
            &mut gate,
            &crate::types::ToolSpec::new("other", "another", json!({ "type": "object" })),
        )
        .unwrap();
        let request = request(vec![message])
            .with_tools(vec![primary, other])
            .with_forced_tool("skill__invite");

        let response = provider.complete(&request).await.unwrap();
        assert_eq!(response.tool_calls().len(), 1);
        assert_eq!(response.tool_calls()[0].name, "skill__invite");

        let requests = server.received_requests().await.unwrap();
        let value: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(value["tool_choice"], json!({ "type": "auto" }));
        assert_eq!(value["tools"].as_array().unwrap().len(), 1);
        assert_eq!(value["tools"][0]["name"], "skill__invite");
        assert_eq!(value["tools"][0]["strict"], true);
        assert!(
            value["system"].as_str().unwrap().contains("exactly once"),
            "missing forced-tool system line: {}",
            value["system"]
        );
    }

    #[tokio::test]
    async fn a_refusal_is_a_typed_error_and_never_a_text_answer() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{ "type": "text", "text": "I cannot help" }],
                "stop_reason": "refusal"
            })))
            .mount(&server)
            .await;
        let entry = entry(&server.uri());
        let provider = AnthropicCompat::with_key(&entry, "m", Some("k".into())).unwrap();
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("x")).unwrap();
        let err = provider
            .complete(&request(vec![message]))
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Refused { .. }), "got {err:?}");
        assert!(!crate::fallback::is_fallback_eligible(&err));
    }

    #[tokio::test]
    async fn max_tokens_with_a_partial_tool_call_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{ "type": "tool_use", "id": "t1", "name": "skill__invite", "input": {} }],
                "stop_reason": "max_tokens"
            })))
            .mount(&server)
            .await;
        let entry = entry(&server.uri());
        let provider = AnthropicCompat::with_key(&entry, "m", Some("k".into())).unwrap();
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("x")).unwrap();
        let err = provider
            .complete(&request(vec![message]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::InvalidResponse { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn tool_results_are_grouped_into_one_user_message() {
        let mut gate = tokenising_gate([7u8; 32]);
        let assistant = ChatMessage::assistant_with_tool_calls(
            "",
            vec![ToolCall::new("t1", "skill__invite", json!({ "to": "x" }))],
        );
        let a = SafeMessage::issue(&mut gate, &assistant).unwrap();
        let r1 = SafeMessage::issue(&mut gate, &ChatMessage::tool_result("t1", "ok")).unwrap();
        let r2 = SafeMessage::issue(&mut gate, &ChatMessage::tool_result("t2", "ok")).unwrap();
        let (_system, messages) = to_anthropic_messages(&request(vec![a, r1, r2]));
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "assistant");
        assert_eq!(messages[0]["content"][0]["type"], "tool_use");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"].as_array().unwrap().len(), 2);
        assert_eq!(messages[1]["content"][0]["type"], "tool_result");
    }

    #[tokio::test]
    async fn a_5xx_is_a_server_error_that_may_hop_and_a_400_is_not() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!({
                "error": { "message": "overloaded" }
            })))
            .mount(&server)
            .await;
        let entry = entry(&server.uri());
        let provider = AnthropicCompat::with_key(&entry, "m", Some("k".into())).unwrap();
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("x")).unwrap();
        let err = provider
            .complete(&request(vec![message]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::Server { status: 503, .. }),
            "got {err:?}"
        );
        assert!(crate::fallback::is_fallback_eligible(&err));
    }

    /// Render events as an Anthropic SSE body.
    fn sse(events: &[Value]) -> String {
        events
            .iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect()
    }

    async fn streaming_provider(server: &MockServer, body: String) -> AnthropicCompat {
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
            .mount(server)
            .await;
        let entry = entry(&server.uri());
        AnthropicCompat::with_key(&entry, "claude-opus-5-5", Some("k".into())).unwrap()
    }

    #[tokio::test]
    async fn streaming_text_deltas_are_reported_in_order_with_usage() {
        let server = MockServer::start().await;
        let body = sse(&[
            json!({"type": "message_start", "message": {"usage": {"input_tokens": 5}}}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "bon"}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "jour"}}),
            json!({"type": "content_block_stop", "index": 0}),
            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}),
            json!({"type": "message_stop"}),
        ]);
        let provider = streaming_provider(&server, body).await;

        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("salut")).unwrap();
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let response = provider
            .complete_streaming(&request(vec![message]), &sink)
            .await
            .unwrap();

        assert_eq!(response.content(), "bonjour");
        let usage = response.usage.unwrap();
        assert_eq!((usage.prompt_tokens, usage.completion_tokens), (5, 2));
        {
            let seen = deltas.lock().unwrap();
            assert_eq!(seen.len(), 3, "two text deltas then one usage");
            assert_eq!(seen[0], ChatDelta::Text("bon".into()));
            assert_eq!(seen[1], ChatDelta::Text("jour".into()));
            assert!(matches!(seen[2], ChatDelta::Usage(_)));
        }

        let requests = server.received_requests().await.unwrap();
        let value: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(value["stream"], true);
        assert_eq!(value["max_tokens"], json!(STREAMING_MAX_TOKENS));
    }

    #[tokio::test]
    async fn streaming_tool_input_is_assembled_from_fragments() {
        let server = MockServer::start().await;
        let body = sse(&[
            json!({"type": "message_start", "message": {"usage": {"input_tokens": 1}}}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "t1", "name": "skill__invite"}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{\"to\":"}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "\"elise\"}"}}),
            json!({"type": "content_block_stop", "index": 0}),
            json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 3}}),
            json!({"type": "message_stop"}),
        ]);
        let provider = streaming_provider(&server, body).await;

        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("invite")).unwrap();
        let deltas = std::sync::Mutex::new(Vec::new());
        let sink = |delta: ChatDelta| deltas.lock().unwrap().push(delta);
        let response = provider
            .complete_streaming(&request(vec![message]), &sink)
            .await
            .unwrap();

        assert_eq!(response.tool_calls().len(), 1);
        assert_eq!(response.tool_calls()[0].name, "skill__invite");
        assert_eq!(response.tool_calls()[0].arguments["to"], "elise");
        let seen = deltas.lock().unwrap();
        assert!(
            seen.iter()
                .any(|delta| matches!(delta, ChatDelta::ToolCall(_))),
            "the assembled tool call must be emitted to the sink"
        );
    }

    /// P2 (security-review round 1): an SSE `error` event that echoes the key must
    /// not have it copied into the InvalidResponse message, Display or Debug.
    #[tokio::test]
    async fn a_key_echoed_in_an_sse_error_event_is_redacted() {
        const KEY: &str = "sk-a4-redact-anthropic-0001";
        let server = MockServer::start().await;
        let body = sse(&[json!({
            "type": "error",
            "error": { "message": format!("bad key {KEY}") }
        })]);
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
            .mount(&server)
            .await;
        let entry = entry(&server.uri());
        let provider = AnthropicCompat::with_key(&entry, "m", Some(KEY.to_string())).unwrap();
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("x")).unwrap();

        let err = provider
            .complete_streaming(&request(vec![message]), &|_: ChatDelta| {})
            .await
            .unwrap_err();

        assert!(
            matches!(err, ProviderError::InvalidResponse { .. }),
            "got {err:?}"
        );
        let display = err.to_string();
        assert!(!display.contains(KEY), "key leaked into Display: {display}");
        let debug = format!("{err:?}");
        assert!(!debug.contains(KEY), "key leaked into Debug: {debug}");
        if let ProviderError::InvalidResponse { message, .. } = &err {
            assert!(message.contains("[REDACTED]"), "message: {message}");
            assert!(!message.contains(KEY));
        }
    }

    /// Security-review round 2, P2: a 3xx is surfaced as a provider error and the
    /// redirect target receives nothing.
    #[tokio::test]
    async fn a_redirect_is_not_followed_and_the_target_gets_nothing() {
        let target = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{ "type": "text", "text": "must not run" }],
                "stop_reason": "end_turn"
            })))
            .mount(&target)
            .await;

        let redirect = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/v1/messages", target.uri())),
            )
            .mount(&redirect)
            .await;

        let entry = entry(&redirect.uri());
        let provider =
            AnthropicCompat::with_key(&entry, "m", Some("sk-redirect-secret".into())).unwrap();
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("x")).unwrap();
        let err = provider
            .complete(&request(vec![message]))
            .await
            .expect_err("a 3xx is a provider error");

        assert!(
            matches!(err, ProviderError::Client { status, .. } if (300..400).contains(&status)),
            "got {err:?}"
        );
        assert!(
            target.received_requests().await.unwrap().is_empty(),
            "the redirect target must receive nothing"
        );
    }
}
