//! Chat request/response types shared by every provider adapter.
//!
//! The shapes mirror the OpenAI `chat/completions` wire closely enough that
//! no adapter needs its own translation layer, while staying independent of
//! any particular HTTP stack.

use kernel_core::privacy::GrantPolicy;
use kernel_privacy::safetext::{DetectionReport, Gate, GateError, SafeText, SafeValue};
use kernel_privacy::{EntityKind, Registry};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Who authored a chat message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    /// Instructions the model should always follow.
    System,
    /// Input from the user.
    User,
    /// Output from the model.
    Assistant,
    /// Result of a tool call, fed back to the model.
    Tool,
}

/// One message in a chat conversation.
///
/// `tool_calls` is only meaningful for assistant messages and `tool_call_id`
/// only for tool results; both are omitted from the wire when empty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Author of the message.
    pub role: ChatRole,
    /// Text content (empty for an assistant message that only calls tools).
    pub content: String,
    /// Tool calls requested by the assistant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// Id of the tool call this message answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// The model's reasoning text, for providers that return it with a reply
    /// (DeepSeek thinking mode). It is model output: it goes back only to the
    /// provider that produced it, within the turn, and is never shown or
    /// stored. `None` for every provider that does not send it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_content: Option<String>,
    /// Id of the provider that produced `reasoning_content`. The reasoning is
    /// sent back only to that same provider; without an id it goes nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_provider: Option<String>,
}

impl ChatMessage {
    /// A system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::plain(ChatRole::System, content)
    }

    /// A user message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::plain(ChatRole::User, content)
    }

    /// An assistant text message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::plain(ChatRole::Assistant, content)
    }

    /// An assistant message that requests one or more tool calls.
    pub fn assistant_with_tool_calls(
        content: impl Into<String>,
        tool_calls: Vec<ToolCall>,
    ) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.into(),
            tool_calls,
            tool_call_id: None,
            reasoning_content: None,
            reasoning_provider: None,
        }
    }

    /// Attach the reasoning text the provider returned with this message. An
    /// empty text is kept: a thinking-mode DeepSeek may return `""` with a tool
    /// call and still refuses the next request if the field is missing.
    pub fn with_reasoning_content(mut self, reasoning: Option<String>) -> Self {
        self.reasoning_content = reasoning;
        self
    }

    /// Name the provider that produced this message's reasoning.
    pub fn with_reasoning_provider(mut self, provider: impl Into<String>) -> Self {
        self.reasoning_provider = Some(provider.into());
        self
    }

    /// A tool result message, answering the tool call `tool_call_id`.
    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: ChatRole::Tool,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: Some(tool_call_id.into()),
            reasoning_content: None,
            reasoning_provider: None,
        }
    }

    fn plain(role: ChatRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            reasoning_content: None,
            reasoning_provider: None,
        }
    }
}

/// A tool (function) call requested by the model.
///
/// On the wire, OpenAI-compatible providers encode `arguments` as a JSON
/// *string*. Internally it is a [`Value`] so the tool loop can validate it
/// directly. If the model emits malformed JSON, the raw text is preserved as
/// a string value instead of failing the whole completion.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    /// Provider-assigned call id, echoed back with the tool result.
    pub id: String,
    /// Name of the tool to run.
    pub name: String,
    /// Parsed arguments.
    pub arguments: Value,
}

impl ToolCall {
    /// Build a tool call.
    pub fn new(id: impl Into<String>, name: impl Into<String>, arguments: Value) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments,
        }
    }
}

impl Serialize for ToolCall {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Function<'a> {
            name: &'a str,
            arguments: String,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            #[serde(rename = "type")]
            kind: &'static str,
            function: Function<'a>,
        }

        Wire {
            id: &self.id,
            kind: "function",
            function: Function {
                name: &self.name,
                arguments: serde_json::to_string(&self.arguments)
                    .unwrap_or_else(|_| "null".to_string()),
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ToolCall {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Function {
            name: String,
            #[serde(default)]
            arguments: Option<Value>,
        }
        #[derive(Deserialize)]
        struct Wire {
            #[serde(default)]
            id: String,
            function: Function,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.function.name.is_empty() {
            return Err(D::Error::custom("tool call function name is empty"));
        }
        Ok(Self {
            id: wire.id,
            name: wire.function.name,
            arguments: arguments_value(wire.function.arguments),
        })
    }
}

/// A tool the model may call, advertised in [`ChatRequest::tools`].
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    /// Tool name.
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// JSON Schema for the arguments.
    pub parameters: Value,
}

impl ToolSpec {
    /// Build a tool spec.
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }
}

impl Serialize for ToolSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Function<'a> {
            name: &'a str,
            description: &'a str,
            parameters: &'a Value,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(rename = "type")]
            kind: &'static str,
            function: Function<'a>,
        }

        Wire {
            kind: "function",
            function: Function {
                name: &self.name,
                description: &self.description,
                parameters: &self.parameters,
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ToolSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Function {
            name: String,
            #[serde(default)]
            description: String,
            #[serde(default)]
            parameters: Value,
        }
        #[derive(Deserialize)]
        struct Wire {
            function: Function,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            name: wire.function.name,
            description: wire.function.description,
            parameters: wire.function.parameters,
        })
    }
}

/// One outbound message. Every text field is a [`SafeText`] that the privacy
/// gate issued, so no raw `String` can reach a provider request body.
///
/// Built from a local [`ChatMessage`] with [`SafeMessage::issue`]; the raw
/// message stays local.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SafeMessage {
    role: ChatRole,
    content: SafeText,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_calls: Vec<SafeToolCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<SafeText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_content: Option<SafeText>,
    /// Who produced `reasoning_content`; never on the wire.
    #[serde(skip)]
    reasoning_provider: Option<String>,
    /// Kinds and counts the open-mode gate removed (or would have masked) in
    /// this message. Always empty under a tokenising gate, whose tokens are
    /// the receipt's evidence instead. Never a value.
    #[serde(skip)]
    detected: BTreeMap<EntityKind, usize>,
}

impl SafeMessage {
    /// Gate one local message. Fails closed: the gate's error keeps the
    /// message local.
    pub fn issue(gate: &mut Gate, message: &ChatMessage) -> Result<Self, GateError> {
        // Only a passthrough gate removes a value without minting a token; its
        // detection report is the only category evidence the receipt can use.
        let passthrough = gate.policy() == GrantPolicy::Passthrough;
        let mut detected = BTreeMap::new();
        let (content, report) = gate.text(&message.content)?;
        if passthrough {
            merge_report(&mut detected, &report);
        }
        let mut tool_calls = Vec::with_capacity(message.tool_calls.len());
        for call in &message.tool_calls {
            let (call, call_detected) = SafeToolCall::issue_reported(gate, call)?;
            if passthrough {
                merge_counts(&mut detected, call_detected);
            }
            tool_calls.push(call);
        }
        let tool_call_id = match message.tool_call_id.as_deref() {
            Some(id) => {
                let (issued, report) = gate.text(id)?;
                if passthrough {
                    merge_report(&mut detected, &report);
                }
                Some(issued)
            }
            None => None,
        };
        let reasoning_content = match message.reasoning_content.as_deref() {
            Some(text) => {
                let (issued, report) = gate.text(text)?;
                if passthrough {
                    merge_report(&mut detected, &report);
                }
                Some(issued)
            }
            None => None,
        };
        Ok(Self {
            role: message.role,
            content,
            tool_calls,
            tool_call_id,
            reasoning_content,
            reasoning_provider: message.reasoning_provider.clone(),
            detected,
        })
    }

    /// A message whose text is composed from parts that were already issued
    /// (the system prompt: application text plus gated owner text). It carries
    /// no tool calls and no tool-call id.
    pub fn from_text(role: ChatRole, content: SafeText) -> Self {
        Self {
            role,
            content,
            tool_calls: Vec::new(),
            tool_call_id: None,
            reasoning_content: None,
            reasoning_provider: None,
            detected: BTreeMap::new(),
        }
    }

    /// The kinds and counts the open-mode gate removed (or would have masked)
    /// in this message. Empty under a tokenising gate. Categories only: the
    /// values never enter this map.
    pub fn detected(&self) -> impl Iterator<Item = (EntityKind, usize)> + '_ {
        self.detected.iter().map(|(kind, count)| (*kind, *count))
    }

    /// Who authored the message.
    pub fn role(&self) -> ChatRole {
        self.role
    }

    /// The masked text content.
    pub fn content(&self) -> &SafeText {
        &self.content
    }

    /// The tool calls the assistant requested, masked.
    pub fn tool_calls(&self) -> &[SafeToolCall] {
        &self.tool_calls
    }

    /// The masked id of the tool call this message answers, if any.
    pub fn tool_call_id(&self) -> Option<&SafeText> {
        self.tool_call_id.as_ref()
    }

    /// The masked reasoning text the provider returned with this message.
    pub fn reasoning_content(&self) -> Option<&SafeText> {
        self.reasoning_content.as_ref()
    }

    /// Id of the provider that produced this message's reasoning, if known.
    pub fn reasoning_provider(&self) -> Option<&str> {
        self.reasoning_provider.as_deref()
    }

    /// This message as `provider` may receive it: the reasoning stays only
    /// when `provider` is the one that produced it, else it is dropped.
    pub fn for_provider(&self, provider: &str) -> Self {
        let mut message = self.clone();
        if message.reasoning_provider.as_deref() != Some(provider) {
            message.reasoning_content = None;
        }
        message
    }

    /// This assistant tool-call message with an empty reasoning stamped as
    /// `provider`'s, when it carries none `provider` may receive (a row the
    /// engine wrote itself, or reasoning another provider produced). `None`
    /// for every other message. The empty text carries no data.
    pub(crate) fn with_empty_reasoning_for(&self, provider: &str) -> Option<Self> {
        if self.role != ChatRole::Assistant
            || self.tool_calls.is_empty()
            || (self.reasoning_content.is_some()
                && self.reasoning_provider.as_deref() == Some(provider))
        {
            return None;
        }
        let mut message = self.clone();
        message.reasoning_content = Some(SafeText::join(std::iter::empty()));
        message.reasoning_provider = Some(provider.to_string());
        Some(message)
    }

    /// True when `provider` may not receive this message's reasoning.
    pub fn withholds_reasoning_from(&self, provider: &str) -> bool {
        self.reasoning_content.is_some() && self.reasoning_provider.as_deref() != Some(provider)
    }
}

/// A tool call inside an outbound assistant message. Serializes like
/// [`ToolCall`]: the arguments travel as a JSON string.
#[derive(Debug, Clone, PartialEq)]
pub struct SafeToolCall {
    id: SafeText,
    name: SafeText,
    arguments: SafeValue,
}

impl SafeToolCall {
    /// Gate one local tool call.
    pub fn issue(gate: &mut Gate, call: &ToolCall) -> Result<Self, GateError> {
        Ok(Self::issue_reported(gate, call)?.0)
    }

    /// Gate one local tool call, keeping the gate's kind/count report.
    fn issue_reported(
        gate: &mut Gate,
        call: &ToolCall,
    ) -> Result<(Self, BTreeMap<EntityKind, usize>), GateError> {
        let mut detected = BTreeMap::new();
        let (id, report) = gate.text(&call.id)?;
        merge_report(&mut detected, &report);
        let (name, report) = gate.text(&call.name)?;
        merge_report(&mut detected, &report);
        let (arguments, report) = gate.value(&call.arguments)?;
        merge_report(&mut detected, &report);
        Ok((
            Self {
                id,
                name,
                arguments,
            },
            detected,
        ))
    }

    /// The masked arguments.
    pub fn arguments(&self) -> &SafeValue {
        &self.arguments
    }

    /// The masked call id, echoed back with the tool result.
    pub fn id(&self) -> &SafeText {
        &self.id
    }

    /// The masked tool name.
    pub fn name(&self) -> &SafeText {
        &self.name
    }
}

/// Fold one gate report into a `kind -> count` map. Counts only; a report
/// never holds a value.
fn merge_report(counts: &mut BTreeMap<EntityKind, usize>, report: &DetectionReport) {
    for (kind, count) in report.counts() {
        *counts.entry(kind).or_default() += count;
    }
}

/// Fold one already-counted map into another.
fn merge_counts(counts: &mut BTreeMap<EntityKind, usize>, other: BTreeMap<EntityKind, usize>) {
    for (kind, count) in other {
        *counts.entry(kind).or_default() += count;
    }
}

impl Serialize for SafeToolCall {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Function<'a> {
            name: &'a str,
            arguments: String,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            id: &'a str,
            #[serde(rename = "type")]
            kind: &'static str,
            function: Function<'a>,
        }

        Wire {
            id: self.id.as_str(),
            kind: "function",
            function: Function {
                name: self.name.as_str(),
                arguments: serde_json::to_string(self.arguments.as_value())
                    .unwrap_or_else(|_| "null".to_string()),
            },
        }
        .serialize(serializer)
    }
}

/// A tool advertised to the model, masked. Built from a [`ToolSpec`] with
/// [`SafeToolSpec::issue`].
#[derive(Debug, Clone, PartialEq)]
pub struct SafeToolSpec {
    name: SafeText,
    description: SafeText,
    parameters: SafeValue,
}

impl SafeToolSpec {
    /// Gate one local tool spec, including its JSON schema.
    pub fn issue(gate: &mut Gate, spec: &ToolSpec) -> Result<Self, GateError> {
        Ok(Self {
            name: gate.text(&spec.name)?.0,
            description: gate.text(&spec.description)?.0,
            parameters: gate.value(&spec.parameters)?.0,
        })
    }

    /// A tool spec whose parts are already issued: an application declaration
    /// is built from application text the caller gated, and anything else goes through
    /// [`SafeToolSpec::issue`].
    pub fn from_parts(name: SafeText, description: SafeText, parameters: SafeValue) -> Self {
        Self {
            name,
            description,
            parameters,
        }
    }

    /// The masked tool name.
    pub fn name(&self) -> &SafeText {
        &self.name
    }

    /// The masked description.
    pub fn description(&self) -> &SafeText {
        &self.description
    }

    /// The masked JSON schema.
    pub fn parameters(&self) -> &SafeValue {
        &self.parameters
    }
}

impl Serialize for SafeToolSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Function<'a> {
            name: &'a SafeText,
            description: &'a SafeText,
            parameters: &'a SafeValue,
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            #[serde(rename = "type")]
            kind: &'static str,
            function: Function<'a>,
        }

        Wire {
            kind: "function",
            function: Function {
                name: &self.name,
                description: &self.description,
                parameters: &self.parameters,
            },
        }
        .serialize(serializer)
    }
}

/// Why a model id was refused. Messages never echo the id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModelIdError {
    /// The id is empty.
    #[error("model id is empty")]
    Empty,
    /// The id is longer than 96 bytes.
    #[error("model id is longer than 96 bytes")]
    TooLong,
    /// The id has a character outside `[A-Za-z0-9._:/-]`.
    #[error("model id has a character outside [A-Za-z0-9._:/-]")]
    Charset,
    /// The id reads as a personal identifier (an address, a phone number, ...).
    #[error("model id reads as a personal identifier")]
    PersonalData,
}

/// A model id that may go into a provider body: validated on construction, and
/// never a personal identifier.
///
/// The only constructor is [`ModelId::from_config`]. Allowed characters are
/// `[A-Za-z0-9._:/-]` (`deepseek-chat`, `llama3.1:8b`, `org/model`), at most 96
/// bytes. No space and no `@` pass, and neither does any value the privacy
/// recognisers read as an address, a phone number or another personal identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ModelId(String);

impl ModelId {
    /// Validate a model id read from configuration. Nothing else builds one.
    pub fn from_config(raw: &str) -> Result<Self, ModelIdError> {
        if raw.is_empty() {
            return Err(ModelIdError::Empty);
        }
        if raw.len() > 96 {
            return Err(ModelIdError::TooLong);
        }
        let allowed = |byte: u8| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        };
        if !raw.bytes().all(allowed) {
            return Err(ModelIdError::Charset);
        }
        // Fail toward refusing: a value that reads as personal data never leaves.
        if !Registry::new().analyze(raw).is_empty() {
            return Err(ModelIdError::PersonalData);
        }
        Ok(Self(raw.to_string()))
    }

    /// The id, read-only.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A chat completion request.
///
/// `model`, `temperature`, `max_tokens` and `tools` are optional: adapters
/// fill the model from their configuration when it is absent and omit the
/// other fields from the wire when unset.
///
/// Every message and tool is a gated `Safe*` value, so the request has no
/// `String` payload a provider could send. The type has no `Deserialize`:
/// nothing may build a request from wire text without the gate.
///
/// `messages` is an [`Arc`] so a multi-round turn can share one conversation
/// buffer instead of deep-copying it for every provider call (E-13).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChatRequest {
    /// Conversation so far, oldest first.
    pub messages: Arc<Vec<SafeMessage>>,
    /// Per-request model override; falls back to the provider's configured model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelId>,
    /// Sampling temperature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Maximum number of tokens to generate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Tools the model may call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<SafeToolSpec>,
    /// What the model must do with the offered tools. A forced `/command` asks
    /// for its skill on the first round; an adapter steps the choice down when
    /// the endpoint refuses it (see [`ToolChoice::step_down`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
}

/// A `tool_choice` the request can ask for, most specific first. Thinking-mode
/// DeepSeek refuses the first two with a 400 and accepts only `auto`
/// (https://api-docs.deepseek.com/api/create-chat-completion).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ToolChoice {
    /// Call this tool.
    Function(String),
    /// Call some offered tool.
    Required,
    /// Call a tool or answer in text.
    Auto,
}

impl ToolChoice {
    /// The next, less specific choice an endpoint that refused this one accepts
    /// instead; `None` when `auto` itself was refused.
    pub fn step_down(&self) -> Option<Self> {
        match self {
            ToolChoice::Function(_) => Some(ToolChoice::Required),
            ToolChoice::Required => Some(ToolChoice::Auto),
            ToolChoice::Auto => None,
        }
    }
}

impl ChatRequest {
    /// A request with the given conversation.
    pub fn new(messages: Vec<SafeMessage>) -> Self {
        Self::shared(Arc::new(messages))
    }

    /// A request sharing an existing conversation buffer (no deep copy).
    pub fn shared(messages: Arc<Vec<SafeMessage>>) -> Self {
        Self {
            messages,
            model: None,
            temperature: None,
            max_tokens: None,
            tools: Vec::new(),
            tool_choice: None,
        }
    }

    /// Override the provider's configured model.
    pub fn with_model(mut self, model: ModelId) -> Self {
        self.model = Some(model);
        self
    }

    /// Set the sampling temperature.
    pub fn with_temperature(mut self, temperature: f64) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set the generation cap.
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Advertise tools to the model.
    pub fn with_tools(mut self, tools: Vec<SafeToolSpec>) -> Self {
        self.tools = tools;
        self
    }

    /// Require the model to call `tool` on this request.
    pub fn with_forced_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool_choice = Some(ToolChoice::Function(tool.into()));
        self
    }
}

/// Provider-reported token usage for one completion.
///
/// Mirrors the OpenAI `usage` object. Both counts default to zero so a
/// partial object (or a provider that omits — or nulls — one field) still
/// parses; the engine treats zero as "not reported".
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(from = "WireUsage")]
pub struct Usage {
    /// Tokens in the prompt (input).
    pub prompt_tokens: u64,
    /// Tokens generated (output).
    pub completion_tokens: u64,
    /// Provider-reported cost in **USD**, when the gateway sends one
    /// (OpenRouter-style `usage.cost`). `None` = not reported; the engine
    /// then prices the call from `[prices]`.
    #[serde(default, rename = "cost", skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// Of `prompt_tokens`, how many the provider served from its prompt
    /// cache. `None` = not reported; never guessed as zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_prompt_tokens: Option<u64>,
}

/// The wire `usage`: cached input is `prompt_tokens_details.cached_tokens` or
/// `prompt_cache_hit_tokens` (api.deepseek.com sends both); junk = not reported.
#[derive(Deserialize)]
struct WireUsage {
    #[serde(default, deserialize_with = "null_as_zero")]
    prompt_tokens: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    completion_tokens: u64,
    cost: Option<f64>,
    cached_prompt_tokens: Option<Value>,
    prompt_tokens_details: Option<Value>,
    prompt_cache_hit_tokens: Option<Value>,
}

impl From<WireUsage> for Usage {
    fn from(wire: WireUsage) -> Self {
        let details = wire.prompt_tokens_details.as_ref();
        let cached = [
            wire.cached_prompt_tokens.as_ref(),
            details.and_then(|details| details.get("cached_tokens")),
            wire.prompt_cache_hit_tokens.as_ref(),
        ]
        .into_iter()
        .find_map(|count| count?.as_u64());
        Self {
            prompt_tokens: wire.prompt_tokens,
            completion_tokens: wire.completion_tokens,
            cost_usd: wire.cost,
            cached_prompt_tokens: cached,
        }
    }
}

/// `null` and a missing field both mean zero: a sloppy `usage` object must
/// never fail an otherwise valid completion.
fn null_as_zero<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    Ok(Option::<u64>::deserialize(deserializer)?.unwrap_or(0))
}

/// One event of a streaming completion.
///
/// The sink passed to
/// [`ChatProvider::complete_streaming`](crate::ChatProvider::complete_streaming)
/// receives text as the model generates it; the assembled tool calls and the
/// provider-reported usage are emitted once, when the stream ends. The
/// returned [`ChatResponse`] is always the complete result, so a caller that
/// ignores the sink behaves exactly like a non-streaming call.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatDelta {
    /// Generated text, in generation order. Concatenating every `Text` delta
    /// of one completion yields the response's `message.content`.
    Text(String),
    /// One tool call requested by the model, fully assembled from its
    /// fragments and emitted at the end of the stream.
    ToolCall(ToolCall),
    /// Provider-reported usage for the streamed completion, when the provider
    /// sends one (usually in the final chunk).
    Usage(Usage),
}

/// A chat completion response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatResponse {
    /// The assistant message (text and/or tool calls).
    pub message: ChatMessage,
    /// Provider-reported usage, when the provider returns a `usage` object;
    /// `None` means "not reported" and callers fall back to their own estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

impl ChatResponse {
    /// Wrap an assistant message (no usage reported).
    pub fn new(message: ChatMessage) -> Self {
        Self {
            message,
            usage: None,
        }
    }

    /// A plain assistant text response.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(ChatMessage::assistant(content))
    }

    /// Attach provider-reported usage.
    pub fn with_usage(mut self, usage: Usage) -> Self {
        self.usage = Some(usage);
        self
    }

    /// Text content of the assistant message.
    pub fn content(&self) -> &str {
        &self.message.content
    }

    /// Tool calls requested by the assistant.
    pub fn tool_calls(&self) -> &[ToolCall] {
        &self.message.tool_calls
    }
}

fn arguments_value(raw: Option<Value>) -> Value {
    match raw {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Value::Null
            } else {
                serde_json::from_str(trimmed).unwrap_or_else(|_| Value::String(trimmed.to_string()))
            }
        }
        Some(other) => other,
    }
}

/// Parse an OpenAI-wire `arguments` fragment into a [`ToolCall`] argument
/// value: a JSON object when it parses, the raw trimmed string otherwise
/// (malformed arguments must never fail the whole completion).
pub(crate) fn assembled_arguments(raw: &str) -> Value {
    arguments_value(Some(Value::String(raw.to_string())))
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

    /// [`tokenising_gate`] over an injected detector, for failure-path tests.
    fn tokenising_gate_with(
        key: [u8; 32],
        detector: std::sync::Arc<dyn kernel_privacy::safetext::Detector>,
    ) -> kernel_privacy::safetext::Gate {
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Private,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered in private mode");
        kernel_privacy::safetext::Gate::for_tests(
            &grant,
            key,
            crate::test_gate::names_claimed(detector),
        )
    }
    use super::*;
    use kernel_privacy::safetext::{DetectError, Detector};
    use kernel_privacy::Span;
    use serde_json::json;
    use std::sync::Arc;

    const MAIL: &str = "elise.vautrin@example.invalid";

    /// A gate whose detector always fails: nothing may be issued.
    struct Broken;

    impl Detector for Broken {
        fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
            Err(DetectError::Panicked)
        }
    }

    #[test]
    fn tool_results_and_calls_are_masked_before_they_go_out() {
        let mut gate = tokenising_gate([3u8; 32]);
        let call = ToolCall::new("call_1", "send_mail", json!({ "to": MAIL }));
        let assistant = ChatMessage::assistant_with_tool_calls("", vec![call]);
        let result = ChatMessage::tool_result("call_1", format!("sent to {MAIL}"));

        let assistant = SafeMessage::issue(&mut gate, &assistant).unwrap();
        let result = SafeMessage::issue(&mut gate, &result).unwrap();

        let wire = serde_json::to_string(&(assistant, result)).unwrap();
        assert!(!wire.contains(MAIL), "raw address on the wire: {wire}");
        assert!(wire.contains("⟦EMAIL_"));
    }

    #[test]
    fn a_refused_message_issues_nothing() {
        let mut gate = tokenising_gate_with([3u8; 32], Arc::new(Broken));
        let err = SafeMessage::issue(&mut gate, &ChatMessage::user("hello")).unwrap_err();
        assert_eq!(err, GateError::Detect(DetectError::Panicked));
    }

    #[test]
    fn assistant_text_message_omits_optional_fields() {
        let message = ChatMessage::assistant("hello");
        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(value, json!({ "role": "assistant", "content": "hello" }));
    }

    #[test]
    fn tool_call_serializes_arguments_as_a_json_string() {
        let call = ToolCall::new("call_1", "shell", json!({ "cmd": "ls" }));
        let value = serde_json::to_value(&call).unwrap();
        assert_eq!(
            value,
            json!({
                "id": "call_1",
                "type": "function",
                "function": { "name": "shell", "arguments": "{\"cmd\":\"ls\"}" }
            })
        );
    }

    #[test]
    fn tool_call_deserializes_string_arguments() {
        let call: ToolCall = serde_json::from_value(json!({
            "id": "call_1",
            "type": "function",
            "function": { "name": "shell", "arguments": "{\"cmd\":\"ls\"}" }
        }))
        .unwrap();
        assert_eq!(call.id, "call_1");
        assert_eq!(call.name, "shell");
        assert_eq!(call.arguments, json!({ "cmd": "ls" }));
    }

    #[test]
    fn tool_call_deserializes_object_arguments_and_missing_id() {
        let call: ToolCall = serde_json::from_value(json!({
            "function": { "name": "shell", "arguments": { "cmd": "pwd" } }
        }))
        .unwrap();
        assert_eq!(call.id, "");
        assert_eq!(call.arguments, json!({ "cmd": "pwd" }));
    }

    #[test]
    fn tool_call_preserves_malformed_arguments_as_text() {
        let call: ToolCall = serde_json::from_value(json!({
            "id": "call_1",
            "function": { "name": "shell", "arguments": "{not json" }
        }))
        .unwrap();
        assert_eq!(call.arguments, json!("{not json"));
    }

    #[test]
    fn tool_call_empty_arguments_become_null() {
        let call: ToolCall = serde_json::from_value(json!({
            "id": "call_1",
            "function": { "name": "shell", "arguments": "" }
        }))
        .unwrap();
        assert_eq!(call.arguments, Value::Null);
    }

    #[test]
    fn tool_spec_serializes_function_envelope() {
        let spec = ToolSpec::new("shell", "run a command", json!({ "type": "object" }));
        let value = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            value,
            json!({
                "type": "function",
                "function": {
                    "name": "shell",
                    "description": "run a command",
                    "parameters": { "type": "object" }
                }
            })
        );
    }

    #[test]
    fn assistant_tool_call_message_round_trips() {
        let message = ChatMessage::assistant_with_tool_calls(
            "",
            vec![ToolCall::new("call_1", "shell", json!({ "cmd": "ls" }))],
        );
        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(
            value,
            json!({
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "shell", "arguments": "{\"cmd\":\"ls\"}" }
                }]
            })
        );
        let back: ChatMessage = serde_json::from_value(value).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn tool_result_message_includes_call_id() {
        let message = ChatMessage::tool_result("call_1", "total 0");
        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(
            value,
            json!({ "role": "tool", "content": "total 0", "tool_call_id": "call_1" })
        );
    }

    #[test]
    fn chat_response_accessors() {
        let response = ChatResponse::assistant("hi");
        assert_eq!(response.content(), "hi");
        assert!(response.tool_calls().is_empty());
    }

    #[test]
    fn chat_response_carries_optional_usage() {
        let response = ChatResponse::assistant("hi");
        assert_eq!(response.usage, None, "no usage unless the provider says so");
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({ "message": { "role": "assistant", "content": "hi" } }),
            "absent usage must not reach the wire"
        );

        let usage = Usage {
            prompt_tokens: 12,
            completion_tokens: 34,
            cost_usd: None,
            cached_prompt_tokens: None,
        };
        let response = response.with_usage(usage);
        assert_eq!(response.usage, Some(usage));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["usage"],
            json!({ "prompt_tokens": 12, "completion_tokens": 34 })
        );
        let back: ChatResponse = serde_json::from_value(value).unwrap();
        assert_eq!(back, response);
    }

    #[test]
    fn usage_defaults_missing_fields_to_zero() {
        let usage: Usage = serde_json::from_value(json!({ "completion_tokens": 7 })).unwrap();
        assert_eq!(usage.prompt_tokens, 0);
        assert_eq!(usage.completion_tokens, 7);
    }

    #[test]
    fn usage_treats_null_fields_as_zero() {
        let usage: Usage =
            serde_json::from_value(json!({ "prompt_tokens": null, "completion_tokens": 7 }))
                .unwrap();
        assert_eq!(usage.prompt_tokens, 0);
        assert_eq!(usage.completion_tokens, 7);
    }

    #[test]
    fn a_configured_model_id_is_accepted() {
        for id in [
            "deepseek-chat",
            "llama3.1:8b",
            "org/model-7b",
            "gpt-4o_mini",
        ] {
            assert_eq!(ModelId::from_config(id).unwrap().as_str(), id);
        }
    }

    #[test]
    fn a_model_id_outside_the_charset_is_refused() {
        assert_eq!(ModelId::from_config(""), Err(ModelIdError::Empty));
        assert_eq!(
            ModelId::from_config("deepseek chat"),
            Err(ModelIdError::Charset)
        );
        assert_eq!(
            ModelId::from_config("model#max"),
            Err(ModelIdError::Charset)
        );
        assert_eq!(
            ModelId::from_config("elise@example.invalid"),
            Err(ModelIdError::Charset)
        );
    }

    #[test]
    fn a_model_id_over_the_length_cap_is_refused() {
        let long = "a".repeat(97);
        assert_eq!(ModelId::from_config(&long), Err(ModelIdError::TooLong));
        assert!(ModelId::from_config(&"a".repeat(96)).is_ok());
    }

    #[test]
    fn a_model_id_that_reads_as_personal_data_is_refused() {
        // A phone number needs no `+` or spaces to be one: the recognisers decide.
        assert_eq!(
            ModelId::from_config("0612345678"),
            Err(ModelIdError::PersonalData)
        );
    }

    #[test]
    fn a_model_override_serialises_as_its_plain_id() {
        let request =
            ChatRequest::new(Vec::new()).with_model(ModelId::from_config("deepseek-chat").unwrap());
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["model"], "deepseek-chat");
    }
}
