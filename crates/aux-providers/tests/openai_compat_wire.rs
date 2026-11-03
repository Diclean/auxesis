//! Wire-level tests for the OpenAI-compatible adapter, against a local
//! wiremock server. No real network, no real keys.

use std::io::{Read, Write};
use std::time::Duration;

use aux_providers::config::{ProviderConfig, ProviderKind};
use aux_providers::error::ProviderError;
use aux_providers::openai_compat::OpenAiCompat;
use aux_providers::provider::ChatProvider;
use aux_providers::types::{
    ChatMessage, ChatRequest, ModelId, SafeMessage, SafeToolSpec, ToolCall, ToolSpec, Usage,
};
use kernel_privacy::safetext::Gate;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A gate that tokenises: C9 is the one covered row private mode allows.
fn tokenising_gate(key: [u8; 32]) -> Gate {
    let grant = kernel_core::privacy::admit_call(
        kernel_core::privacy::PathId::C9,
        kernel_core::privacy::PrivacyMode::Private,
        kernel_core::privacy::Destination::LocalDisplay,
    )
    .expect("C9 is covered in private mode");
    Gate::for_tests(&grant, key, aux_providers::test_gate::names_checked())
}

/// Gate local messages into a request, as the engine does, so every test
/// sends a `SafeText` payload.
fn gated(messages: Vec<ChatMessage>) -> ChatRequest {
    let mut gate = tokenising_gate([8u8; 32]);
    ChatRequest::new(
        messages
            .iter()
            .map(|message| SafeMessage::issue(&mut gate, message).unwrap())
            .collect(),
    )
}

/// A gated tool spec, as the engine advertises tools.
fn gated_tool(name: &str, description: &str, parameters: Value) -> SafeToolSpec {
    let mut gate = tokenising_gate([8u8; 32]);
    SafeToolSpec::issue(&mut gate, &ToolSpec::new(name, description, parameters)).unwrap()
}

fn config(base_url: &str) -> ProviderConfig {
    ProviderConfig {
        disable_thinking: false,
        id: "deepseek".to_string(),
        base_url: base_url.to_string(),
        model: "deepseek-chat".to_string(),
        key_user: Some("deepseek".to_string()),
        kind: ProviderKind::OpenAiCompat,
    }
}

fn provider(server: &MockServer, key: Option<&str>) -> OpenAiCompat {
    OpenAiCompat::with_key(
        &config(&format!("{}/v1", server.uri())),
        key.map(str::to_string),
    )
    .expect("provider builds")
}

async fn mount_json(server: &MockServer, status: u16, body: Value) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn request_shape_matches_openai_wire() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "role": "assistant", "content": "ok" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let request = gated(vec![
        ChatMessage::system("be brief"),
        ChatMessage::user("hello"),
    ])
    .with_temperature(0.2)
    .with_max_tokens(64)
    .with_tools(vec![gated_tool(
        "shell",
        "run a command",
        json!({ "type": "object" }),
    )]);

    provider.complete(&request).await.unwrap();

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let request = &received[0];

    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), "/v1/chat/completions");
    assert_eq!(
        request
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer test-key"
    );
    let content_type = request
        .headers
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.starts_with("application/json"),
        "got content-type {content_type}"
    );

    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(
        body,
        json!({
            "model": "deepseek-chat",
            "messages": [
                { "role": "system", "content": "be brief" },
                { "role": "user", "content": "hello" }
            ],
            "temperature": 0.2,
            "max_tokens": 64,
            "tools": [{
                "type": "function",
                "function": {
                    "name": "shell",
                    "description": "run a command",
                    "parameters": { "type": "object" }
                }
            }]
        })
    );
}

#[tokio::test]
async fn request_omits_unset_optional_fields() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "content": "ok" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap();

    let received = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    let object = body.as_object().unwrap();
    // Field *set* is the contract, not object key order (JSON objects are
    // unordered; `serde_json`'s `preserve_order` keeps the struct's field
    // order in the body).
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["messages", "model"], "unexpected fields in {body}");
}

#[tokio::test]
async fn per_request_model_overrides_the_configured_model() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "content": "ok" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let request = gated(vec![ChatMessage::user("hello")])
        .with_model(ModelId::from_config("deepseek-reasoner").unwrap());
    provider.complete(&request).await.unwrap();

    let received = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(body["model"], "deepseek-reasoner");
}

#[tokio::test]
async fn tool_call_and_tool_result_messages_serialize() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "content": "done" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let call = ToolCall::new("call_1", "shell", json!({ "cmd": "ls" }));
    let request = gated(vec![
        ChatMessage::user("list files"),
        ChatMessage::assistant_with_tool_calls("", vec![call]),
        ChatMessage::tool_result("call_1", "file.txt"),
    ]);

    provider.complete(&request).await.unwrap();

    let received = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(
        body["messages"],
        json!([
            { "role": "user", "content": "list files" },
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "shell", "arguments": "{\"cmd\":\"ls\"}" }
                }]
            },
            { "role": "tool", "content": "file.txt", "tool_call_id": "call_1" }
        ])
    );
}

#[tokio::test]
async fn no_key_means_no_authorization_header() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "content": "ok" } }] }),
    )
    .await;
    let provider = provider(&server, None);

    provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap();

    let received = server.received_requests().await.unwrap();
    assert!(received[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn parses_text_response() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "role": "assistant", "content": "bonjour" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let response = provider
        .complete(&gated(vec![ChatMessage::user("salut")]))
        .await
        .unwrap();
    assert_eq!(response.content(), "bonjour");
    assert!(response.tool_calls().is_empty());
    assert_eq!(response.usage, None, "no usage object in the body");
}

#[tokio::test]
async fn parses_usage_when_the_provider_reports_it() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({
            "choices": [{ "message": { "role": "assistant", "content": "bonjour" } }],
            "usage": { "prompt_tokens": 123, "completion_tokens": 45, "total_tokens": 168 }
        }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let response = provider
        .complete(&gated(vec![ChatMessage::user("salut")]))
        .await
        .unwrap();
    assert_eq!(
        response.usage,
        Some(Usage {
            prompt_tokens: 123,
            completion_tokens: 45,
            cost_usd: None,
            cached_prompt_tokens: None,
        })
    );
}

#[tokio::test]
async fn parses_tool_call_response() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "shell", "arguments": "{\"cmd\":\"pwd\"}" }
                    }]
                }
            }]
        }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let response = provider
        .complete(&gated(vec![ChatMessage::user("where am i")]))
        .await
        .unwrap();
    assert_eq!(response.content(), "");
    assert_eq!(response.tool_calls().len(), 1);
    let call = &response.tool_calls()[0];
    assert_eq!(call.id, "call_1");
    assert_eq!(call.name, "shell");
    assert_eq!(call.arguments, json!({ "cmd": "pwd" }));
}

#[tokio::test]
async fn empty_choices_is_an_invalid_response() {
    let server = MockServer::start().await;
    mount_json(&server, 200, json!({ "choices": [] })).await;
    let provider = provider(&server, Some("test-key"));

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ProviderError::InvalidResponse { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn unauthorized_is_mapped_to_unauthorized() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        401,
        json!({ "error": { "message": "Authentication Fails" } }),
    )
    .await;
    let provider = provider(&server, Some("bad-key"));

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ProviderError::Unauthorized { provider } if provider == "deepseek"),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rate_limited_is_mapped_with_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "2")
                .set_body_json(json!({ "error": { "message": "slow down" } })),
        )
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            ProviderError::RateLimited { provider, retry_after }
                if provider == "deepseek" && *retry_after == Some(Duration::from_secs(2))
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn server_error_is_mapped_to_server() {
    let server = MockServer::start().await;
    mount_json(&server, 500, json!({ "error": { "message": "internal" } })).await;
    let provider = provider(&server, Some("test-key"));

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ProviderError::Server { provider, status } if provider == "deepseek" && *status == 500),
        "got {err:?}"
    );
}

#[tokio::test]
async fn other_client_errors_include_the_provider_message() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        400,
        json!({ "error": { "message": "Model Not Exist" } }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            ProviderError::Client { provider, status: 400, message }
                if provider == "deepseek" && message == "Model Not Exist"
        ),
        "got {err:?}"
    );
}

#[tokio::test]
async fn timeout_is_mapped_to_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .set_body_json(json!({ "choices": [{ "message": { "content": "late" } }] })),
        )
        .mount(&server)
        .await;
    let provider = OpenAiCompat::with_key_and_timeout(
        &config(&format!("{}/v1", server.uri())),
        Some("test-key".to_string()),
        Duration::from_millis(200),
    )
    .unwrap();

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ProviderError::Timeout { provider } if provider == "deepseek"),
        "got {err:?}"
    );
}

#[tokio::test]
async fn connection_refused_is_mapped_to_request_error() {
    // Port 1 is privileged and nothing listens on it in CI: refused, no bind race.
    let provider = OpenAiCompat::with_key(
        &config("http://127.0.0.1:1/v1"),
        Some("test-key".to_string()),
    )
    .unwrap();

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Request { .. }), "got {err:?}");
}

// ---------------------------------------------------------------------------
// streaming (WS-F1)
// ---------------------------------------------------------------------------

/// Collects the sink's deltas in order.
/// The follow-up request of a tool round: the user's question, the assistant
/// message the provider just returned (with its tool call), and the result.
fn follow_up(first: &aux_providers::ChatResponse) -> ChatRequest {
    gated(vec![
        ChatMessage::user("weather in Budapest?"),
        first.message.clone(),
        ChatMessage::tool_result("call_1", "sunny"),
    ])
}

const THINKING_TOOL_CALL: &str =
    r#"{"id":"call_1","type":"function","function":{"name":"weather","arguments":"{}"}}"#;

#[tokio::test]
async fn reasoning_content_is_sent_back_on_the_next_round() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": {
            "content": "",
            "reasoning_content": "I should call the weather tool.",
            "tool_calls": [serde_json::from_str::<Value>(THINKING_TOOL_CALL).unwrap()]
        } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let first = provider
        .complete(&gated(vec![ChatMessage::user("weather in Budapest?")]))
        .await
        .unwrap();
    assert_eq!(
        first.message.reasoning_content.as_deref(),
        Some("I should call the weather tool.")
    );
    provider.complete(&follow_up(&first)).await.unwrap();

    let received = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&received[1].body).unwrap();
    assert_eq!(
        body["messages"][1]["reasoning_content"],
        "I should call the weather tool."
    );
    assert!(body["messages"][1]["tool_calls"].is_array());
    let first_body: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert!(first_body["messages"][0].get("reasoning_content").is_none());
}

#[tokio::test]
async fn streamed_reasoning_content_is_sent_back_and_never_shown() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"I should \"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"call it.\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",",
        "\"function\":{\"name\":\"weather\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: [DONE]\n\n",
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));
    let (log, sink) = delta_log();

    let first = provider
        .complete_streaming(
            &gated(vec![ChatMessage::user("weather in Budapest?")]),
            &sink,
        )
        .await
        .unwrap();
    assert_eq!(
        first.message.reasoning_content.as_deref(),
        Some("I should call it.")
    );
    assert!(
        !log.lock().unwrap().iter().any(|delta| matches!(
            delta,
            aux_providers::ChatDelta::Text(text) if text.contains("call it")
        )),
        "reasoning is never streamed to the owner"
    );
    provider
        .complete_streaming(&follow_up(&first), &sink)
        .await
        .unwrap();

    let received = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&received[1].body).unwrap();
    assert_eq!(
        body["messages"][1]["reasoning_content"],
        "I should call it."
    );
}

/// Stream one tool call whose first delta carries `reasoning` (raw JSON, or
/// no field at all), then the follow-up; returns the follow-up's assistant
/// message as sent.
async fn streamed_tool_call_then_follow_up(reasoning: Option<&str>) -> Value {
    let server = MockServer::start().await;
    let field = reasoning.map_or(String::new(), |raw| format!(",\"reasoning_content\":{raw}"));
    let sse = format!(
        "data: {{\"choices\":[{{\"delta\":{{\"role\":\"assistant\",\"content\":\"\"{field}}}}}]}}\n\n\
         data: {{\"choices\":[{{\"delta\":{{\"tool_calls\":[{THINKING_TOOL_CALL_DELTA}]}}}}]}}\n\n\
         data: [DONE]\n\n"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));
    let (_log, sink) = delta_log();
    let first = provider
        .complete_streaming(
            &gated(vec![ChatMessage::user("weather in Budapest?")]),
            &sink,
        )
        .await
        .unwrap();
    provider
        .complete_streaming(&follow_up(&first), &sink)
        .await
        .unwrap();
    let received = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&received[1].body).unwrap();
    body["messages"][1].clone()
}

const THINKING_TOOL_CALL_DELTA: &str =
    r#"{"index":0,"id":"call_1","function":{"name":"weather","arguments":"{}"}}"#;

#[tokio::test]
async fn an_empty_streamed_reasoning_is_sent_back_empty() {
    // DeepSeek in thinking mode may stream `""` then nulls with a tool call;
    // the next request must still carry the field, or it is a 400.
    let sent = streamed_tool_call_then_follow_up(Some("\"\"")).await;
    assert_eq!(sent["reasoning_content"], "", "{sent}");
}

#[tokio::test]
async fn a_stream_without_reasoning_sends_none_back() {
    for reasoning in [None, Some("null")] {
        let sent = streamed_tool_call_then_follow_up(reasoning).await;
        assert!(sent["tool_calls"].is_array(), "{sent}");
        assert!(sent.get("reasoning_content").is_none(), "{sent}");
    }
}

#[tokio::test]
async fn an_empty_reasoning_in_a_json_reply_is_kept() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": {
            "content": "",
            "reasoning_content": "",
            "tool_calls": [serde_json::from_str::<Value>(THINKING_TOOL_CALL).unwrap()]
        } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));
    let first = provider
        .complete(&gated(vec![ChatMessage::user("weather in Budapest?")]))
        .await
        .unwrap();
    assert_eq!(first.message.reasoning_content.as_deref(), Some(""));
    provider.complete(&follow_up(&first)).await.unwrap();
    let received = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&received[1].body).unwrap();
    assert_eq!(body["messages"][1]["reasoning_content"], "");
}

/// A thinking-mode DeepSeek: it rejects a thread whose assistant tool-call
/// message has no `reasoning_content`.
struct RejectsMissingReasoning;

impl wiremock::Respond for RejectsMissingReasoning {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let missing = body["messages"].as_array().unwrap().iter().any(|message| {
            message.get("tool_calls").is_some() && message.get("reasoning_content").is_none()
        });
        if missing {
            ResponseTemplate::new(400).set_body_json(json!({ "error": { "message":
                "The `reasoning_content` in the thinking mode must be passed back to the API." } }))
        } else {
            ResponseTemplate::new(200)
                .set_body_json(json!({ "choices": [{ "message": { "content": "ok" } }] }))
        }
    }
}

#[tokio::test]
async fn a_rebuilt_thread_passes_a_provider_that_demands_reasoning_back() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(RejectsMissingReasoning)
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));
    let call = ToolCall::new("call_1", "weather", json!({}));
    let thread = |reasoning: Option<&str>| {
        gated(vec![
            ChatMessage::user("weather?"),
            ChatMessage::assistant_with_tool_calls("", vec![call.clone()])
                .with_reasoning_content(reasoning.map(str::to_string))
                .with_reasoning_provider("deepseek"),
            ChatMessage::tool_result("call_1", "sunny"),
            ChatMessage::user("thanks"),
        ])
    };

    let err = provider.complete(&thread(None)).await.unwrap_err();
    assert!(err.to_string().contains("reasoning_content"), "{err}");
    provider
        .complete(&thread(Some("restored from the store")))
        .await
        .unwrap();
}

fn provider_named(server: &MockServer, id: &str) -> OpenAiCompat {
    let mut config = config(&format!("{}/v1", server.uri()));
    config.id = id.to_string();
    OpenAiCompat::with_key(&config, Some("test-key".to_string())).expect("provider builds")
}

async fn reasoned_first_reply(server: &MockServer) -> aux_providers::ChatResponse {
    mount_json(
        server,
        200,
        json!({ "choices": [{ "message": {
            "content": "",
            "reasoning_content": "private thoughts",
            "tool_calls": [serde_json::from_str::<Value>(THINKING_TOOL_CALL).unwrap()]
        } }] }),
    )
    .await;
    provider(server, Some("test-key"))
        .complete(&gated(vec![ChatMessage::user("weather in Budapest?")]))
        .await
        .unwrap()
}

#[tokio::test]
async fn the_reply_names_the_provider_that_produced_the_reasoning() {
    let server = MockServer::start().await;
    let first = reasoned_first_reply(&server).await;
    assert_eq!(
        first.message.reasoning_provider.as_deref(),
        Some("deepseek")
    );
}

#[tokio::test]
async fn reasoning_is_not_sent_to_another_provider_after_a_switch() {
    let origin = MockServer::start().await;
    let first = reasoned_first_reply(&origin).await;
    let other = MockServer::start().await;
    mount_json(
        &other,
        200,
        json!({ "choices": [{ "message": { "content": "ok" } }] }),
    )
    .await;

    provider_named(&other, "other-vendor")
        .complete(&follow_up(&first))
        .await
        .unwrap();
    provider(&origin, Some("test-key"))
        .complete(&follow_up(&first))
        .await
        .unwrap();

    let to_other = other.received_requests().await.unwrap();
    assert!(!String::from_utf8_lossy(&to_other[0].body).contains("private thoughts"));
    assert!(String::from_utf8_lossy(&to_other[0].body).contains("tool_calls"));
    let to_origin = origin.received_requests().await.unwrap();
    assert!(String::from_utf8_lossy(&to_origin[1].body).contains("private thoughts"));
}

#[tokio::test]
async fn reasoning_is_not_sent_to_a_fallback_provider_but_the_primary_keeps_it() {
    let origin = MockServer::start().await;
    let first = reasoned_first_reply(&origin).await;
    let down = MockServer::start().await;
    mount_json(&down, 503, json!({ "error": { "message": "down" } })).await;
    let backup = MockServer::start().await;
    mount_json(
        &backup,
        200,
        json!({ "choices": [{ "message": { "content": "ok" } }] }),
    )
    .await;
    // Primary is the producer and is down; the fallback is another vendor.
    let chain = aux_providers::FallbackProvider::new(vec![
        Box::new(provider_named(&down, "deepseek")),
        Box::new(provider_named(&backup, "backup-vendor")),
    ]);

    chain.complete(&follow_up(&first)).await.unwrap();

    let to_primary = down.received_requests().await.unwrap();
    assert!(String::from_utf8_lossy(&to_primary[0].body).contains("private thoughts"));
    let to_backup = backup.received_requests().await.unwrap();
    assert!(!String::from_utf8_lossy(&to_backup[0].body).contains("private thoughts"));
}

#[tokio::test]
async fn a_provider_without_reasoning_content_sees_unchanged_requests() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": {
            "content": "",
            "tool_calls": [serde_json::from_str::<Value>(THINKING_TOOL_CALL).unwrap()]
        } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));

    let first = provider
        .complete(&gated(vec![ChatMessage::user("weather in Budapest?")]))
        .await
        .unwrap();
    assert_eq!(first.message.reasoning_content, None);
    provider.complete(&follow_up(&first)).await.unwrap();

    let received = server.received_requests().await.unwrap();
    assert!(!String::from_utf8_lossy(&received[1].body).contains("reasoning_content"));
}

#[tokio::test]
async fn reasoning_content_goes_through_the_privacy_gate() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "content": "ok" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));
    let request = gated(vec![
        ChatMessage::user("hi"),
        ChatMessage::assistant_with_tool_calls("", vec![])
            .with_reasoning_content(Some("mail marie.durand@example.com first".to_string()))
            .with_reasoning_provider("deepseek"),
    ]);

    provider.complete(&request).await.unwrap();

    let received = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&received[0].body);
    assert!(body.contains("reasoning_content"));
    assert!(
        !body.contains("marie.durand@example.com"),
        "reasoning text is masked like any other outbound text: {body}"
    );
}

fn delta_log() -> (
    std::sync::Arc<std::sync::Mutex<Vec<aux_providers::ChatDelta>>>,
    impl Fn(aux_providers::ChatDelta) + Send + Sync,
) {
    let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink_log = std::sync::Arc::clone(&log);
    let sink = move |delta: aux_providers::ChatDelta| sink_log.lock().unwrap().push(delta);
    (log, sink)
}

#[tokio::test]
async fn streaming_request_uses_sse_and_assembles_the_answer() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\n",
        "data: [DONE]\n\n",
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));
    let (log, sink) = delta_log();

    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap();

    assert_eq!(response.content(), "Hello world");
    assert_eq!(
        response.usage,
        Some(Usage {
            prompt_tokens: 7,
            completion_tokens: 2,
            cost_usd: None,
            cached_prompt_tokens: None,
        })
    );
    let deltas = log.lock().unwrap().clone();
    let texts: Vec<String> = deltas
        .iter()
        .filter_map(|delta| match delta {
            aux_providers::ChatDelta::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec!["Hello ", "world"]);
    assert!(matches!(
        deltas.last(),
        Some(aux_providers::ChatDelta::Usage(_))
    ));

    // The wire request asked for SSE and for usage in the final chunk.
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(body["stream"], true);
    assert_eq!(body["stream_options"]["include_usage"], true);
    assert_eq!(body["model"], "deepseek-chat");
}

#[tokio::test]
async fn streaming_refusal_falls_back_to_the_non_streaming_path() {
    let server = MockServer::start().await;
    // The stream-specific refusal is registered first (wiremock picks the
    // first matching mock); the generic JSON reply catches the fallback.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(wiremock::matchers::body_string_contains("\"stream\":true"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({ "error": { "message": "stream not supported" } })),
        )
        .mount(&server)
        .await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "role": "assistant", "content": "plain answer" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));
    let (log, sink) = delta_log();

    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap();

    assert_eq!(response.content(), "plain answer");
    assert_eq!(
        log.lock().unwrap().len(),
        1,
        "the fallback reports the whole answer as one delta"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "one refused stream attempt, one non-streaming fallback"
    );
}

#[tokio::test]
async fn a_stream_request_answered_with_json_is_parsed_plainly() {
    // Some proxies ignore `stream: true` but answer 200 application/json.
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({
            "choices": [{ "message": { "role": "assistant", "content": "not streamed" } }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 2 }
        }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));
    let (log, sink) = delta_log();

    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap();

    assert_eq!(response.content(), "not streamed");
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn streaming_client_errors_other_than_refusals_surface_untouched() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({ "error": { "message": "slow down" } })),
        )
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));
    let (_, sink) = delta_log();

    let err = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ProviderError::RateLimited { provider, .. } if provider == "deepseek"),
        "got {err:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "a rate limit must not be retried as a fallback"
    );
}

#[tokio::test]
async fn a_genuine_400_is_never_re_sent_as_a_fallback() {
    // H-10: a 400 that never mentions streaming is a real request error. It
    // must surface untouched and never be re-sent through `complete()`.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": { "message": "Model Not Exist", "type": "invalid_request_error" }
        })))
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));
    let (_, sink) = delta_log();

    let err = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            ProviderError::Client { provider, status: 400, message }
                if provider == "deepseek" && message == "Model Not Exist"
        ),
        "got {err:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "a genuine 400 must not be doubled by a fallback re-send"
    );
}

#[tokio::test]
async fn streaming_decodes_a_utf8_bom_at_the_head() {
    // F-07: the most common gateway BOM is glued to the first `data:` line;
    // without a strip the first delta is silently dropped.
    let server = MockServer::start().await;
    let sse = format!(
        "{}\n\ndata: [DONE]\n\n",
        "\u{FEFF}data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}"
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    let provider = provider(&server, None);
    let (log, sink) = delta_log();

    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap();

    assert_eq!(response.content(), "Hello");
    let deltas = log.lock().unwrap().clone();
    let texts: Vec<String> = deltas
        .iter()
        .filter_map(|delta| match delta {
            aux_providers::ChatDelta::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec!["Hello"]);
}

/// Drain one HTTP request head + body from `socket` so a later close sends a
/// clean FIN rather than a RST. Returns false when the peer went away.
fn drain_request(socket: &mut std::net::TcpStream) -> bool {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match socket.read(&mut byte) {
            Ok(0) | Err(_) => return false,
            Ok(_) => head.push(byte[0]),
        }
    }
    let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let content_length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; content_length];
    let mut filled = 0;
    while filled < content_length {
        match socket.read(&mut body[filled..]) {
            Ok(0) | Err(_) => return false,
            Ok(read) => filled += read,
        }
    }
    if content_length == 0 {
        // No content-length (chunked): drain whatever is already buffered.
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok();
        let mut scratch = [0u8; 1024];
        while let Ok(read) = socket.read(&mut scratch) {
            if read == 0 {
                break;
            }
        }
    }
    true
}

/// A minimal SSE endpoint on loopback: accepts one connection, drains the
/// request, answers `200 text/event-stream` with `connection: close`, writes
/// each event verbatim with `gap` in between, then closes. Returns the port.
/// The server thread is detached; it finishes on its own.
fn sse_server(events: Vec<String>, gap: Duration) -> u16 {
    sse_server_with_hold(events, gap, Duration::ZERO)
}

/// Like [`sse_server`], but keeps the socket open for `hold` after the last
/// event: a keep-alive endpoint that never closes after `[DONE]` (F-08).
fn sse_server_with_hold(events: Vec<String>, gap: Duration, hold: Duration) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        if !drain_request(&mut socket) {
            return;
        }
        let response =
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
        if socket.write_all(response).is_err() {
            return;
        }
        for event in events {
            if socket.write_all(event.as_bytes()).is_err() || socket.flush().is_err() {
                return;
            }
            std::thread::sleep(gap);
        }
        if !hold.is_zero() {
            std::thread::sleep(hold);
        }
        // Dropping the socket ends the body (no content-length + close).
    });
    port
}

/// A keep-alive endpoint that dribbles one byte inside every idle window and
/// never closes: `read_timeout` alone can never fire, only the overall
/// deadline can (F-08).
fn trickle_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        if !drain_request(&mut socket) {
            return;
        }
        let response = b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n";
        if socket.write_all(response).is_err() {
            return;
        }
        loop {
            if socket.write_all(b"x").is_err() || socket.flush().is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    port
}

fn sse_content_event(text: &str) -> String {
    format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"{text}\"}}}}]}}\n\n")
}

#[tokio::test]
async fn empty_data_heartbeats_are_skipped_not_failed() {
    // GLM-P3: `data:` with an empty or whitespace-only payload is a
    // spec-legal heartbeat/keep-alive (servers send these between chunks);
    // it must be skipped, not parsed as JSON and failed.
    let events = vec![
        "data:\n\n".to_string(),
        sse_content_event("Hello"),
        "data:   \n\n".to_string(),
        "data: \t\n\n".to_string(),
        sse_content_event(" world"),
        "data: [DONE]\n\n".to_string(),
    ];
    let port = sse_server(events, Duration::from_millis(10));
    let provider =
        OpenAiCompat::with_key(&config(&format!("http://127.0.0.1:{port}/v1")), None).unwrap();
    let (log, sink) = delta_log();

    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap();

    assert_eq!(response.content(), "Hello world");
    let texts: String = log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|delta| match delta {
            aux_providers::ChatDelta::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, "Hello world");
}

#[tokio::test]
async fn a_stream_longer_than_the_request_timeout_keeps_streaming() {
    // H-10: `DEFAULT_TIMEOUT` (here 1 s) must be an *idle* timeout on the
    // streaming path. Eight events 200 ms apart run for ~1.8 s, well past
    // the old total timeout, while no single gap comes near the idle budget.
    let timeout = Duration::from_secs(1);
    let mut events: Vec<String> = ["a", "b", "c", "d", "e", "f", "g", "h"]
        .iter()
        .map(|text| sse_content_event(text))
        .collect();
    events.push("data: [DONE]\n\n".to_string());
    let port = sse_server(events, Duration::from_millis(200));

    let provider = OpenAiCompat::with_key_and_timeout(
        &config(&format!("http://127.0.0.1:{port}/v1")),
        None,
        timeout,
    )
    .unwrap();
    let (log, sink) = delta_log();

    let started = std::time::Instant::now();
    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(response.content(), "abcdefgh");
    assert!(
        elapsed > timeout,
        "the answer must outlive the request timeout, took {elapsed:?}"
    );
    let texts: String = log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|delta| match delta {
            aux_providers::ChatDelta::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, "abcdefgh");
}

#[tokio::test]
async fn a_stalled_stream_fails_when_the_idle_timeout_expires() {
    // H-10 keeps the failure direction too: no total timeout does not mean no
    // bound at all. One event, then silence longer than the idle budget.
    let timeout = Duration::from_millis(300);
    let port = sse_server(
        vec![sse_content_event("hi"), "data: [DONE]\n\n".to_string()],
        Duration::from_secs(3),
    );
    let provider = OpenAiCompat::with_key_and_timeout(
        &config(&format!("http://127.0.0.1:{port}/v1")),
        None,
        timeout,
    )
    .unwrap();
    let (_, sink) = delta_log();

    let started = std::time::Instant::now();
    let err = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap_err();

    assert!(
        matches!(&err, ProviderError::Timeout { provider } if provider == "deepseek"),
        "got {err:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the idle timeout must fire promptly, took {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// F-08: [DONE] ends the read loop; a trickle is bounded overall
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_terminator_returns_without_waiting_for_the_socket_to_close() {
    // F-08/F-15: a keep-alive endpoint holds the connection open after
    // `[DONE]`. The complete answer must return immediately, not wait out
    // the idle timeout and then be discarded — for every terminator shape,
    // including one that arrives as the final line with no line terminator
    // and one split across two body chunks. The idle timeout is well above a
    // loaded CI host's connect latency and well below the 3 s hold, so a pass
    // still proves the answer did not wait for the socket to close.
    let timeout = Duration::from_millis(1500);
    let terminators = [
        "data: [DONE]\n\n",
        "data: [DONE]\n",
        "data: [DONE]\r\n",
        // F-15: no trailing line terminator, CR only, trailing spaces, BOM.
        "data: [DONE]",
        "data: [DONE]\r",
        "data: [DONE]   ",
        "\u{FEFF}data: [DONE]",
        "data:[DONE]",
        "data: [done]",
    ];
    for terminator in terminators {
        let port = sse_server_with_hold(
            vec![sse_content_event("done"), terminator.to_string()],
            Duration::ZERO,
            Duration::from_secs(3),
        );
        let provider = OpenAiCompat::with_key_and_timeout(
            &config(&format!("http://127.0.0.1:{port}/v1")),
            None,
            timeout,
        )
        .unwrap();
        let (log, sink) = delta_log();

        let started = std::time::Instant::now();
        let response = provider
            .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
            .await
            .unwrap_or_else(|err| panic!("terminator {terminator:?}: {err:?}"));
        let elapsed = started.elapsed();

        assert_eq!(response.content(), "done", "terminator {terminator:?}");
        assert!(
            elapsed < timeout,
            "terminator {terminator:?} must return before the idle timeout, took {elapsed:?}"
        );
        let texts: String = log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|delta| match delta {
                aux_providers::ChatDelta::Text(text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, "done", "terminator {terminator:?}");
    }

    // The terminator split across two body chunks (and with a gap between
    // them) is still terminal once its tail arrives.
    let port = sse_server_with_hold(
        vec![
            sse_content_event("done"),
            "data: [DO".to_string(),
            "NE]".to_string(),
        ],
        Duration::from_millis(20),
        Duration::from_secs(3),
    );
    let provider = OpenAiCompat::with_key_and_timeout(
        &config(&format!("http://127.0.0.1:{port}/v1")),
        None,
        timeout,
    )
    .unwrap();
    let (log, sink) = delta_log();
    let started = std::time::Instant::now();
    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(response.content(), "done");
    assert!(
        elapsed < timeout,
        "a split terminator must return before the idle timeout, took {elapsed:?}"
    );
    let texts: String = log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|delta| match delta {
            aux_providers::ChatDelta::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, "done");
}

#[tokio::test]
async fn a_trickling_stream_is_bounded_by_the_overall_deadline() {
    // F-08: `read_timeout` resets on every byte, so a server dribbling inside
    // the idle window used to hold the turn forever. Each request carries
    // `timeout × STREAM_TOTAL_TIMEOUT_FACTOR` as an overall budget.
    let timeout = Duration::from_millis(100);
    let port = trickle_server();
    let provider = OpenAiCompat::with_key_and_timeout(
        &config(&format!("http://127.0.0.1:{port}/v1")),
        None,
        timeout,
    )
    .unwrap();
    let (_, sink) = delta_log();

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        provider.complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink),
    )
    .await
    .expect("the trickle must be cut by the overall deadline, not hang forever");
    let err = result.unwrap_err();
    assert!(
        matches!(&err, ProviderError::Timeout { provider } if provider == "deepseek"),
        "got {err:?}"
    );
    let deadline = timeout * aux_providers::openai_compat::STREAM_TOTAL_TIMEOUT_FACTOR;
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the overall deadline ({deadline:?}) must fire well before the 5 s guard, took {:?}",
        started.elapsed()
    );
}

// ---------------------------------------------------------------------------
// F-11/F-14: the fallback decision is structured
// ---------------------------------------------------------------------------

#[tokio::test]
async fn genuine_errors_are_never_re_sent_as_a_fallback() {
    // F-11: every one of these used to be doubled by `contains("stream")`.
    let bodies = [
        r#"{"error":{"message":"upstream connect error"}}"#,
        r#"{"error":{"message":"Invalid api key: 'stream'"}}"#,
        r#"{"detail":"bad body: {\"model\":\"x\",\"stream\":true}"}"#,
        "<html><body><!-- streaming not enabled --></body></html>",
        r#"{"error":"unknown field: streaming_model_v2"}"#,
        r#"{"error":{"message":"downstream timeout"}}"#,
    ];
    for body in bodies {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(400).set_body_string(body))
            .mount(&server)
            .await;
        let provider = provider(&server, Some("test-key"));
        let (log, sink) = delta_log();

        let err = provider
            .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProviderError::Client { status: 400, .. }),
            "body {body:?}: got {err:?}"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "a genuine error must not be re-sent: {body:?}"
        );
        assert!(
            log.lock().unwrap().is_empty(),
            "a genuine error emitted a delta: {body:?}"
        );
    }
}

#[tokio::test]
async fn rate_limits_and_server_errors_never_fall_back_even_naming_stream() {
    for status in [429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(status).set_body_string(r#"{"error":{"param":"stream"}}"#),
            )
            .mount(&server)
            .await;
        let provider = provider(&server, Some("test-key"));
        let (_, sink) = delta_log();

        let err = provider
            .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                ProviderError::RateLimited { .. } | ProviderError::Server { .. }
            ),
            "status {status}: got {err:?}"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "status {status} must not be retried as a fallback"
        );
    }
}

#[tokio::test]
async fn structured_stream_refusals_still_fall_back() {
    let refusals: [(u16, &str); 6] = [
        (400, r#"{"error":{"param":"stream"}}"#),
        (
            422,
            r#"{"detail":[{"loc":["body","stream_options"],"msg":"extra fields not permitted"}]}"#,
        ),
        (501, r#"{"error":{"message":"Not Implemented"}}"#),
        (
            400,
            r#"{"error":{"code":"unknown_parameter","message":"unknown parameter stream_options"}}"#,
        ),
        (400, r#"{"error":{"message":"stream not supported"}}"#),
        (405, "stream not supported"),
    ];
    for (status, refusal) in refusals {
        let server = MockServer::start().await;
        // The stream-specific refusal is registered first (wiremock picks the
        // first matching mock); the generic JSON reply catches the fallback.
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(wiremock::matchers::body_string_contains("\"stream\":true"))
            .respond_with(ResponseTemplate::new(status).set_body_string(refusal))
            .mount(&server)
            .await;
        mount_json(
            &server,
            200,
            json!({ "choices": [{ "message": { "role": "assistant", "content": "plain answer" } }] }),
        )
        .await;
        let provider = provider(&server, Some("test-key"));
        let (log, sink) = delta_log();

        let response = provider
            .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
            .await
            .unwrap_or_else(|err| panic!("refusal {refusal:?} must fall back: {err:?}"));

        assert_eq!(response.content(), "plain answer", "refusal {refusal:?}");
        assert_eq!(
            log.lock().unwrap().len(),
            1,
            "refusal {refusal:?} must report the fallback as one delta"
        );
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            2,
            "refusal {refusal:?}: one refused stream attempt plus one fallback"
        );
    }
}

#[tokio::test]
async fn a_stream_error_after_a_delta_is_never_re_sent() {
    // Once a delta has been shown, a mid-stream failure must surface — not
    // silently re-run the whole request (budget would settle twice).
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n",
        "data: {not json}\n\n",
    );
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(sse),
        )
        .mount(&server)
        .await;
    let provider = provider(&server, Some("test-key"));
    let (log, sink) = delta_log();

    let err = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, ProviderError::InvalidResponse { message, .. }
            if message.contains("invalid stream chunk")),
        "got {err:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "a failure after a delta must not trigger a re-send"
    );
    let texts: Vec<String> = log
        .lock()
        .unwrap()
        .iter()
        .filter_map(|delta| match delta {
            aux_providers::ChatDelta::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec!["partial"]);
}

/// A FAKE address, the kind of value the privacy gate must never let through.
const FAKE_MAIL: &str = "mara.ellison@example.invalid";

#[tokio::test]
async fn gated_canary_never_reaches_the_wire_on_either_path() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        200,
        json!({ "choices": [{ "message": { "content": "ok" } }] }),
    )
    .await;
    let provider = provider(&server, Some("test-key"));
    let request = gated(vec![ChatMessage::user(format!("écris à {FAKE_MAIL}"))]);

    provider.complete(&request).await.unwrap();
    provider
        .complete_streaming(&request, &|_| {})
        .await
        .unwrap();

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2, "one request per path");
    for request in &received {
        let body = String::from_utf8(request.body.clone()).unwrap();
        assert!(!body.contains(FAKE_MAIL), "raw canary on the wire: {body}");
        assert!(body.contains("⟦EMAIL_"), "no token on the wire: {body}");
    }
}

/// Security-review round 2, P2: a 3xx from the configured origin is surfaced as a
/// provider error and the redirect target receives nothing.
#[tokio::test]
async fn a_redirect_is_not_followed_and_the_target_gets_nothing() {
    let target = MockServer::start().await;
    mount_json(
        &target,
        200,
        json!({"choices":[{"message":{"role":"assistant","content":"must not run"}}]}),
    )
    .await;

    let redirect = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/v1/chat/completions", target.uri())),
        )
        .mount(&redirect)
        .await;

    let provider = provider(&redirect, Some("sk-redirect-secret"));
    let err = provider
        .complete(&gated(vec![ChatMessage::user("hello")]))
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
