//! Wire types for ACP v1 over JSON-RPC 2.0 (newline-delimited JSON).
//!
//! The ACP spec (protocolVersion 1) is deliberately parsed into a small,
//! permissive subset: unknown fields and unknown update kinds are preserved
//! as data (never an error), and every parse failure returns a typed
//! [`Incoming`] so the read loop can answer with a JSON-RPC error instead of
//! panicking. See <https://agentclientprotocol.com/protocol/v1/overview>.

use serde_json::{json, Value};

/// JSON-RPC error codes we emit or describe.
pub mod code {
    /// Invalid JSON.
    pub const PARSE_ERROR: i64 = -32700;
    /// Not a valid JSON-RPC request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// Unknown method.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Parameters do not match the method.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal error on our side.
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// Numeric code.
    pub code: i64,
    /// Short, human-readable message (never carries secrets).
    pub message: String,
    /// Optional structured detail.
    pub data: Option<Value>,
}

impl RpcError {
    /// Build an error without structured data.
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Serialize into the JSON-RPC `error` member.
    pub fn to_value(&self) -> Value {
        let mut value = json!({ "code": self.code, "message": self.message });
        if let Some(data) = &self.data {
            value["data"] = data.clone();
        }
        value
    }

    /// Parse an `error` member; tolerant of missing/oddly typed fields.
    pub fn from_value(value: &Value) -> Self {
        Self {
            code: value.get("code").and_then(Value::as_i64).unwrap_or(-32603),
            message: value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("(no message)")
                .to_string(),
            data: value.get("data").cloned(),
        }
    }
}

/// Canonical identity of a JSON-RPC request id.
///
/// JSON-RPC ids may be integers or strings, and `1` is **not** the same id as
/// `"1"`; the canonical form keeps the type so a mismatched response is never
/// routed to the wrong pending request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IdKey {
    /// Integer id.
    Num(i64),
    /// String id.
    Str(String),
}

impl IdKey {
    /// Canonical key for a JSON value, `None` when the id has an invalid type.
    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Number(number) => number.as_i64().map(Self::Num),
            Value::String(text) => Some(Self::Str(text.clone())),
            _ => None,
        }
    }

    /// The JSON form of this id.
    pub fn to_value(&self) -> Value {
        match self {
            Self::Num(number) => json!(number),
            Self::Str(text) => json!(text),
        }
    }
}

impl std::fmt::Display for IdKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Num(number) => write!(formatter, "{number}"),
            Self::Str(text) => write!(formatter, "{text:?}"),
        }
    }
}

/// One classified inbound JSON-RPC frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A request from the agent (must be answered).
    Request {
        /// Parsed id.
        id: IdKey,
        /// Raw id value to echo in the response.
        id_value: Value,
        /// Method name.
        method: String,
        /// Parameters (may be absent; normalized to `null`).
        params: Value,
    },
    /// A notification (no response).
    Notification {
        /// Method name.
        method: String,
        /// Parameters (may be absent; normalized to `null`).
        params: Value,
    },
    /// A response to one of our requests.
    Response {
        /// Id this response answers.
        id: IdKey,
        /// Result or error.
        result: Result<Value, RpcError>,
    },
    /// Not a valid JSON-RPC 2.0 message; answer with an error (id echoed when
    /// the value carried a usable one, `null` otherwise).
    Malformed {
        /// Raw id, when one was present.
        id: Option<Value>,
        /// The error to answer with.
        error: RpcError,
    },
}

/// Classify one parsed JSON value as a JSON-RPC 2.0 message.
///
/// Never fails: anything that is not a valid request/notification/response is
/// [`Incoming::Malformed`], so the caller always has a well-formed error to
/// send back.
pub fn classify(value: &Value) -> Incoming {
    let Some(object) = value.as_object() else {
        return Incoming::Malformed {
            id: None,
            error: RpcError::new(code::INVALID_REQUEST, "message must be an object"),
        };
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Incoming::Malformed {
            id: object.get("id").cloned().filter(|id| !id.is_null()),
            error: RpcError::new(code::INVALID_REQUEST, "jsonrpc must be \"2.0\""),
        };
    }
    let id = object.get("id");
    let method = object.get("method");
    match method {
        Some(Value::String(method)) => {
            let params = object.get("params").cloned().unwrap_or(Value::Null);
            match id {
                None => Incoming::Notification {
                    method: method.clone(),
                    params,
                },
                Some(value) => match IdKey::from_value(value) {
                    Some(id) => Incoming::Request {
                        id,
                        id_value: value.clone(),
                        method: method.clone(),
                        params,
                    },
                    None => Incoming::Malformed {
                        id: Some(Value::Null),
                        error: RpcError::new(
                            code::INVALID_REQUEST,
                            "request id must be a number or a string",
                        ),
                    },
                },
            }
        }
        Some(_) => Incoming::Malformed {
            id: id.cloned().filter(|id| !id.is_null()),
            error: RpcError::new(code::INVALID_REQUEST, "method must be a string"),
        },
        None => match id {
            Some(id_value) => match IdKey::from_value(id_value) {
                Some(id) => {
                    let result = object.get("result");
                    let error = object.get("error");
                    match (result, error) {
                        (Some(result), None) => Incoming::Response {
                            id,
                            result: Ok(result.clone()),
                        },
                        (None, Some(error)) => Incoming::Response {
                            id,
                            result: Err(RpcError::from_value(error)),
                        },
                        (Some(_), Some(_)) => Incoming::Malformed {
                            id: Some(id_value.clone()),
                            error: RpcError::new(
                                code::INVALID_REQUEST,
                                "response must not carry both result and error",
                            ),
                        },
                        (None, None) => Incoming::Malformed {
                            id: Some(id_value.clone()),
                            error: RpcError::new(
                                code::INVALID_REQUEST,
                                "response must carry result or error",
                            ),
                        },
                    }
                }
                None => Incoming::Malformed {
                    id: Some(id_value.clone()),
                    error: RpcError::new(code::INVALID_REQUEST, "invalid response id"),
                },
            },
            None => Incoming::Malformed {
                id: None,
                error: RpcError::new(
                    code::INVALID_REQUEST,
                    "message is neither a request, a notification nor a response",
                ),
            },
        },
    }
}

/// ACP client→agent requests this client uses.
pub mod method {
    /// Handshake.
    pub const INITIALIZE: &str = "initialize";
    /// Open a session.
    pub const SESSION_NEW: &str = "session/new";
    /// Send one prompt and stream updates until the stop reason.
    pub const SESSION_PROMPT: &str = "session/prompt";
    /// Ask the agent to stop the in-flight prompt (notification).
    pub const SESSION_CANCEL: &str = "session/cancel";
    /// Agent asks the client to run a terminal command.
    pub const FS_READ_TEXT_FILE: &str = "fs/read_text_file";
    /// Agent asks the client to write a file.
    pub const FS_WRITE_TEXT_FILE: &str = "fs/write_text_file";
    /// Agent asks for a permission decision.
    pub const SESSION_REQUEST_PERMISSION: &str = "session/request_permission";
    /// Terminal methods.
    pub const TERMINAL_CREATE: &str = "terminal/create";
    /// Read accumulated terminal output.
    pub const TERMINAL_OUTPUT: &str = "terminal/output";
    /// Wait for a terminal command to exit.
    pub const TERMINAL_WAIT_FOR_EXIT: &str = "terminal/wait_for_exit";
    /// Kill a terminal command.
    pub const TERMINAL_KILL: &str = "terminal/kill";
    /// Release a terminal.
    pub const TERMINAL_RELEASE: &str = "terminal/release";
    /// Session update notification.
    pub const SESSION_UPDATE: &str = "session/update";
}

/// Text extracted from one ACP ContentBlock (or an array of blocks).
pub fn content_text(content: &Value) -> Option<String> {
    match content {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("text") {
                object
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            } else {
                None
            }
        }
        Value::Array(blocks) => {
            let mut text = String::new();
            for block in blocks {
                if let Some(part) = content_text(block) {
                    text.push_str(&part);
                }
            }
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

/// A `tool_call` / `tool_call_update` payload, with every optional field kept
/// as data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolCallUpdate {
    /// Stable call id (`toolCallId`).
    pub id: String,
    /// Human title.
    pub title: Option<String>,
    /// Kind (`read`, `edit`, `execute`, ...).
    pub kind: Option<String>,
    /// Status (`pending`, `in_progress`, `completed`, `failed`).
    pub status: Option<String>,
    /// Raw input the agent used.
    pub raw_input: Option<Value>,
    /// Raw output the agent got.
    pub raw_output: Option<Value>,
    /// Content blocks (text/diffs/terminals) as raw data.
    pub content: Vec<Value>,
    /// File locations touched.
    pub locations: Vec<Value>,
}

impl ToolCallUpdate {
    fn from_value(value: &Value) -> Self {
        let object = value.as_object();
        let get_str = |key: &str| {
            object
                .and_then(|object| object.get(key))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        Self {
            id: get_str("toolCallId").unwrap_or_default(),
            title: get_str("title"),
            kind: get_str("kind"),
            status: get_str("status"),
            raw_input: object
                .and_then(|object| object.get("rawInput"))
                .cloned()
                .filter(|value| !value.is_null()),
            raw_output: object
                .and_then(|object| object.get("rawOutput"))
                .cloned()
                .filter(|value| !value.is_null()),
            content: object
                .and_then(|object| object.get("content"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            locations: object
                .and_then(|object| object.get("locations"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        }
    }
}

/// One plan entry (`plan` update).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    /// What the entry says.
    pub content: String,
    /// Priority label, when the agent reports one.
    pub priority: Option<String>,
    /// Status label, when the agent reports one.
    pub status: Option<String>,
}

/// Best-effort usage reported by `usage_update`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UsageUpdate {
    /// Context tokens currently used.
    pub used: Option<u64>,
    /// Context size (tokens).
    pub size: Option<u64>,
    /// Optional cost amount.
    pub cost_amount: Option<f64>,
    /// Optional cost currency.
    pub cost_currency: Option<String>,
}

/// One `session/update` notification payload.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionUpdate {
    /// Streaming assistant text.
    AgentMessageChunk {
        /// The chunk text.
        text: String,
    },
    /// Streaming internal reasoning.
    AgentThoughtChunk {
        /// The chunk text.
        text: String,
    },
    /// Echo of a user message the agent decided to persist.
    UserMessageChunk {
        /// The chunk text.
        text: String,
    },
    /// A tool call appeared.
    ToolCall {
        /// The call payload.
        tool_call: ToolCallUpdate,
    },
    /// A tool call changed state.
    ToolCallUpdate {
        /// The call payload.
        tool_call: ToolCallUpdate,
    },
    /// The agent published a plan.
    Plan {
        /// The plan entries.
        entries: Vec<PlanEntry>,
    },
    /// Best-effort usage numbers.
    UsageUpdate {
        /// The reported usage.
        usage: UsageUpdate,
    },
    /// A recognized-but-uninteresting update kind (mode/commands/config...).
    Other {
        /// The `sessionUpdate` discriminator.
        kind: String,
    },
    /// An unrecognized update kind: preserved, never an error.
    Unknown {
        /// The `sessionUpdate` discriminator, when present.
        kind: String,
    },
}

/// Extract the update kind and payload from a `session/update` notification.
///
/// Tolerates a missing or oddly shaped `update` member: the result is
/// [`SessionUpdate::Unknown`] rather than an error, so a protocol-shaped
/// agent can never crash the client.
pub fn parse_session_update(params: &Value) -> (Option<String>, SessionUpdate) {
    let session_id = params
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let update = params.get("update").cloned().unwrap_or(Value::Null);
    let kind = update
        .get("sessionUpdate")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let parsed = match kind.as_str() {
        "agent_message_chunk" => update
            .get("content")
            .and_then(content_text)
            .map(|text| SessionUpdate::AgentMessageChunk { text })
            .unwrap_or(SessionUpdate::Unknown { kind: kind.clone() }),
        "agent_thought_chunk" => update
            .get("content")
            .and_then(content_text)
            .map(|text| SessionUpdate::AgentThoughtChunk { text })
            .unwrap_or(SessionUpdate::Unknown { kind: kind.clone() }),
        "user_message_chunk" => update
            .get("content")
            .and_then(content_text)
            .map(|text| SessionUpdate::UserMessageChunk { text })
            .unwrap_or(SessionUpdate::Unknown { kind: kind.clone() }),
        "tool_call" => SessionUpdate::ToolCall {
            tool_call: ToolCallUpdate::from_value(&update),
        },
        "tool_call_update" => SessionUpdate::ToolCallUpdate {
            tool_call: ToolCallUpdate::from_value(&update),
        },
        "plan" => {
            let entries = update
                .get("entries")
                .and_then(Value::as_array)
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| {
                            let content = entry.get("content").and_then(Value::as_str)?;
                            Some(PlanEntry {
                                content: content.to_string(),
                                priority: entry
                                    .get("priority")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                status: entry
                                    .get("status")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            SessionUpdate::Plan { entries }
        }
        "usage_update" => SessionUpdate::UsageUpdate {
            usage: UsageUpdate {
                used: update.get("used").and_then(Value::as_u64),
                size: update.get("size").and_then(Value::as_u64),
                cost_amount: update
                    .get("cost")
                    .and_then(|cost| cost.get("amount"))
                    .and_then(Value::as_f64),
                cost_currency: update
                    .get("cost")
                    .and_then(|cost| cost.get("currency"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            },
        },
        "" => SessionUpdate::Unknown {
            kind: String::new(),
        },
        "available_commands_update"
        | "current_mode_update"
        | "config_option_update"
        | "session_info_update"
        | "mode_update" => SessionUpdate::Other { kind },
        _ => SessionUpdate::Unknown { kind },
    };
    (session_id, parsed)
}

/// The `stopReason` of a finished `session/prompt`.
pub fn stop_reason(result: &Value) -> Option<String> {
    result
        .get("stopReason")
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_requests_notifications_and_responses() {
        let request = classify(&json!({"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}));
        assert!(matches!(
            request,
            Incoming::Request {
                id: IdKey::Num(7),
                ..
            }
        ));
        let notification =
            classify(&json!({"jsonrpc":"2.0","method":"session/cancel","params":{}}));
        assert!(matches!(notification, Incoming::Notification { .. }));
        let response = classify(&json!({"jsonrpc":"2.0","id":"a","result":{"ok":true}}));
        match response {
            Incoming::Response { id, result } => {
                assert_eq!(id, IdKey::Str("a".into()));
                assert!(result.is_ok());
            }
            other => panic!("expected a response, got {other:?}"),
        }
        let error = classify(&json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"nope"}}));
        match error {
            Incoming::Response {
                result: Err(err), ..
            } => {
                assert_eq!(err.code, -1);
                assert_eq!(err.message, "nope");
            }
            other => panic!("expected an error response, got {other:?}"),
        }
    }

    #[test]
    fn malformed_frames_never_panic_and_carry_an_error() {
        for value in [
            json!("just a string"),
            json!([]),
            json!({}),
            json!({"jsonrpc":"1.0","id":1,"method":"x"}),
            json!({"jsonrpc":"2.0","id":1.5,"method":"x"}),
            json!({"jsonrpc":"2.0","id":null,"method":"x"}),
            json!({"jsonrpc":"2.0","method":42}),
            json!({"jsonrpc":"2.0","id":3}),
            json!({"jsonrpc":"2.0","id":3,"result":1,"error":{"code":1,"message":"x"}}),
        ] {
            match classify(&value) {
                Incoming::Malformed { error, .. } => {
                    assert_eq!(error.code, code::INVALID_REQUEST)
                }
                other => panic!("expected malformed for {value}, got {other:?}"),
            }
        }
    }

    #[test]
    fn ids_are_type_sensitive() {
        assert_ne!(IdKey::Num(1), IdKey::Str("1".to_string()));
        assert_eq!(IdKey::from_value(&json!(1)), Some(IdKey::Num(1)));
        assert_eq!(IdKey::from_value(&json!("1")), Some(IdKey::Str("1".into())));
        assert_eq!(IdKey::from_value(&json!(null)), None);
    }

    #[test]
    fn parses_the_session_update_kinds() {
        let (session, update) = parse_session_update(&json!({
            "sessionId": "s1",
            "update": {"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}
        }));
        assert_eq!(session.as_deref(), Some("s1"));
        assert_eq!(
            update,
            SessionUpdate::AgentMessageChunk { text: "hi".into() }
        );

        let (_, update) = parse_session_update(&json!({
            "update": {"sessionUpdate":"tool_call_update","toolCallId":"t1","status":"completed","title":"Run"}
        }));
        match update {
            SessionUpdate::ToolCallUpdate { tool_call } => {
                assert_eq!(tool_call.id, "t1");
                assert_eq!(tool_call.status.as_deref(), Some("completed"));
            }
            other => panic!("expected tool call update, got {other:?}"),
        }

        let (_, update) = parse_session_update(&json!({
            "update": {"sessionUpdate":"usage_update","used":10,"size":100}
        }));
        assert_eq!(
            update,
            SessionUpdate::UsageUpdate {
                usage: UsageUpdate {
                    used: Some(10),
                    size: Some(100),
                    cost_amount: None,
                    cost_currency: None,
                }
            }
        );

        // Unknown kinds and missing payloads are data, never errors.
        let (_, update) =
            parse_session_update(&json!({"update": {"sessionUpdate":"future_thing"}}));
        assert!(matches!(update, SessionUpdate::Unknown { kind } if kind == "future_thing"));
        let (_, update) = parse_session_update(&json!({"update": "garbage"}));
        assert!(matches!(update, SessionUpdate::Unknown { .. }));
    }

    #[test]
    fn extracts_text_from_content_blocks() {
        assert_eq!(
            content_text(&json!({"type":"text","text":"a"})).as_deref(),
            Some("a")
        );
        assert_eq!(
            content_text(
                &json!([{"type":"text","text":"a"},{"type":"image"},{"type":"text","text":"b"}])
            )
            .as_deref(),
            Some("ab")
        );
        assert_eq!(content_text(&json!({"type":"image"})), None);
    }
}
