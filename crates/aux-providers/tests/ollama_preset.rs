//! The `ollama` preset against a local wiremock server standing in for
//! Ollama's `/v1` endpoint. No real Ollama, no real network, no keys.

use std::sync::{Arc, Mutex};

use aux_providers::config::{parse_providers, parse_providers_with_env};
use aux_providers::error::ProviderError;
use aux_providers::provider::ChatProvider;
use aux_providers::types::{
    ChatDelta, ChatMessage, ChatRequest, SafeMessage, SafeToolSpec, ToolCall, ToolSpec,
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

fn gated(messages: Vec<ChatMessage>) -> ChatRequest {
    let mut gate = tokenising_gate([9u8; 32]);
    ChatRequest::new(
        messages
            .iter()
            .map(|message| SafeMessage::issue(&mut gate, message).unwrap())
            .collect(),
    )
}

fn gated_tool(name: &str, parameters: Value) -> SafeToolSpec {
    let mut gate = tokenising_gate([9u8; 32]);
    SafeToolSpec::issue(&mut gate, &ToolSpec::new(name, "test tool", parameters)).unwrap()
}

/// Build the `ollama` preset from `[brain]` TOML, pointed at `base_url`.
/// Loopback, so the preset accepts it without `allow_remote_base_url`.
fn ollama_at(base_url: &str) -> Box<dyn ChatProvider> {
    let text = format!(
        "[brain]\npreset = \"ollama\"\nmodel = \"granite3.3:2b\"\nbase_url = \"{base_url}\"\n"
    );
    // `None`: a runner's AUXESIS_OLLAMA_MODEL must not change the model under test.
    let mut providers = parse_providers_with_env(&text, None).expect("preset parses");
    assert_eq!(providers.len(), 1);
    providers
        .remove(0)
        .build_provider_with_key(None)
        .expect("provider builds without a key")
}

/// Ollama's OpenAI-compatible tool-call reply: content empty, `arguments` as
/// a JSON string, the call id present.
fn ollama_tool_call_body() -> Value {
    json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "granite3.3:2b",
        "system_fingerprint": "fp_ollama",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call_0",
                    "type": "function",
                    "function": {
                        "index": 0,
                        "name": "calendar.create_event",
                        "arguments": "{\"title\":\"Call Camille\",\"start\":\"2026-10-11T10:00\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": { "prompt_tokens": 40, "completion_tokens": 12, "total_tokens": 52 }
    })
}

/// Bodies the mock server received, parsed as JSON, in arrival order.
async fn received_bodies(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|request| serde_json::from_slice(&request.body).expect("request body is JSON"))
        .collect()
}

#[tokio::test]
async fn tool_call_round_trip_non_streaming() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ollama_tool_call_body()))
        .mount(&server)
        .await;
    let provider = ollama_at(&format!("{}/v1", server.uri()));
    let tool = gated_tool(
        "calendar.create_event",
        json!({ "type": "object", "properties": { "title": { "type": "string" } } }),
    );

    let first = provider
        .complete(&gated(vec![ChatMessage::user("invite Camille")]).with_tools(vec![tool]))
        .await
        .expect("tool call comes back");
    let call = &first.tool_calls()[0];
    assert_eq!(call.id, "call_0");
    assert_eq!(call.name, "calendar.create_event");
    assert_eq!(
        call.arguments,
        json!({ "title": "Call Camille", "start": "2026-10-11T10:00" })
    );

    // The tool result goes back on the wire in OpenAI format: an assistant
    // message with its tool_calls, then a `tool` message with the same id.
    let answered = gated(vec![
        ChatMessage::user("invite Camille"),
        ChatMessage::assistant_with_tool_calls(
            "",
            vec![ToolCall::new(
                "call_0",
                "calendar.create_event",
                json!({ "title": "Call Camille" }),
            )],
        ),
        ChatMessage::tool_result("call_0", "{\"ok\":true}"),
    ]);
    provider.complete(&answered).await.expect("second turn");

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 2);
    let tools = &bodies[0]["tools"];
    assert_eq!(tools[0]["type"], "function");
    assert_eq!(tools[0]["function"]["name"], "calendar.create_event");
    let messages = bodies[1]["messages"].as_array().unwrap();
    let assistant = &messages[1];
    assert_eq!(assistant["role"], "assistant");
    assert_eq!(assistant["tool_calls"][0]["id"], "call_0");
    assert_eq!(
        assistant["tool_calls"][0]["function"]["name"],
        "calendar.create_event"
    );
    let tool_result = &messages[2];
    assert_eq!(tool_result["role"], "tool");
    assert_eq!(tool_result["tool_call_id"], "call_0");
    assert_eq!(bodies[1]["model"], "granite3.3:2b");
}

#[tokio::test]
async fn tool_call_round_trip_streaming() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_0\",\"type\":\"function\",",
        "\"function\":{\"name\":\"calendar.create_event\",\"arguments\":\"{\\\"title\\\":\\\"Call \"}}]}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,",
        "\"function\":{\"arguments\":\"Camille\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
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
    let provider = ollama_at(&format!("{}/v1", server.uri()));

    let deltas = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&deltas);
    let sink = move |delta: ChatDelta| log.lock().unwrap().push(delta);
    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("invite Camille")]), &sink)
        .await
        .expect("streamed tool call");

    let call = &response.tool_calls()[0];
    assert_eq!(call.id, "call_0");
    assert_eq!(call.name, "calendar.create_event");
    assert_eq!(call.arguments, json!({ "title": "Call Camille" }));
    let tool_deltas = deltas
        .lock()
        .unwrap()
        .iter()
        .filter(|delta| matches!(delta, ChatDelta::ToolCall(_)))
        .count();
    assert_eq!(tool_deltas, 1, "the assembled call is reported once");

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies[0]["stream"], true);
}

#[tokio::test]
async fn streamed_text_arrives_in_order_and_matches_the_answer() {
    let server = MockServer::start().await;
    let sse = concat!(
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"Bonjour \"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"!\"}}]}\n\n",
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
    let provider = ollama_at(&format!("{}/v1", server.uri()));

    let texts = Arc::new(Mutex::new(String::new()));
    let log = Arc::clone(&texts);
    let sink = move |delta: ChatDelta| {
        if let ChatDelta::Text(text) = delta {
            log.lock().unwrap().push_str(&text);
        }
    };
    let response = provider
        .complete_streaming(&gated(vec![ChatMessage::user("salut")]), &sink)
        .await
        .unwrap();

    assert_eq!(response.content(), "Bonjour !");
    assert_eq!(*texts.lock().unwrap(), "Bonjour !");
}

#[tokio::test]
async fn non_streaming_text_answer() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "Hello" },
                "finish_reason": "stop"
            }]
        })))
        .mount(&server)
        .await;
    let provider = ollama_at(&format!("{}/v1", server.uri()));

    let response = provider
        .complete(&gated(vec![ChatMessage::user("hi")]))
        .await
        .unwrap();

    assert_eq!(response.content(), "Hello");
    assert!(response.tool_calls().is_empty());
}

#[tokio::test]
async fn no_authorization_header_is_sent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "role": "assistant", "content": "ok" } }]
        })))
        .mount(&server)
        .await;
    let provider = ollama_at(&format!("{}/v1", server.uri()));

    provider
        .complete(&gated(vec![ChatMessage::user("hi")]))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert!(requests[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn ollama_down_is_reported_in_english_and_french() {
    // Port 1 is privileged and nothing listens on it in CI, so the connection
    // is refused. A bind-then-drop port could be taken by a parallel server.
    let provider = ollama_at("http://127.0.0.1:1/v1");

    let err = provider
        .complete(&gated(vec![ChatMessage::user("hi")]))
        .await
        .unwrap_err();

    assert!(
        matches!(err, ProviderError::OllamaNotRunning { .. }),
        "got {err:?}"
    );
    let message = err.to_string();
    assert!(message.contains("Ollama is not running"), "{message}");
    assert!(message.contains("n'est pas lancé"), "{message}");
    assert!(
        !message.contains("127.0.0.1"),
        "no endpoint in the message: {message}"
    );
}

#[tokio::test]
async fn ollama_down_while_streaming_is_reported_the_same_way() {
    // Port 1, as above: refused without a bind race.
    let provider = ollama_at("http://127.0.0.1:1/v1");
    let sink = |_: ChatDelta| {};

    let err = provider
        .complete_streaming(&gated(vec![ChatMessage::user("hi")]), &sink)
        .await
        .unwrap_err();

    assert!(
        matches!(err, ProviderError::OllamaNotRunning { .. }),
        "got {err:?}"
    );
}

#[test]
fn remote_endpoint_is_refused_for_the_preset() {
    let text = "[brain]\npreset = \"ollama\"\nbase_url = \"https://ollama.example.com/v1\"\n";
    let err = parse_providers(text).unwrap_err();
    assert!(err.to_string().contains("allow_remote_base_url"), "{err}");

    let allowed = format!("{text}allow_remote_base_url = true\n");
    let providers = parse_providers(&allowed).expect("explicit opt-in is honoured");
    assert_eq!(providers[0].base_url, "https://ollama.example.com/v1");
}

#[test]
fn preset_defaults_to_loopback_without_a_key() {
    let providers = parse_providers("[brain]\npreset = \"ollama\"\n").unwrap();
    assert_eq!(providers[0].id, "ollama");
    assert_eq!(providers[0].base_url, "http://127.0.0.1:11434/v1");
    assert_eq!(providers[0].key_user, None);
}
