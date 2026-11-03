//! End-to-end provider-layer tests over fake HTTP upstreams.
//!
//! Every brain is a loopback `wiremock` server, never a real cloud API. The
//! tests prove the items that live in this crate: the three
//! cloud legs round-trip a tool call, a key value never reaches a body or a
//! URL, a 503 hops once and a 400 does not, and a tools-less brain is refused
//! with `chat only` before any request.

use std::path::Path;
use std::sync::Arc;
use std::sync::Once;

use aux_providers::brain::{build_chain, build_entry, ResolvedBrain};
use aux_providers::catalog::Catalog;
use aux_providers::fallback::RecordingLedger;
use aux_providers::providers_toml::{parse_providers_toml, ProviderEntry, ProvidersFile};
use aux_providers::types::{ChatMessage, ChatRequest, SafeMessage, SafeToolSpec, ToolSpec};
use kernel_core::privacy::{admit_call, Destination, PathId, PrivacyMode};
use kernel_privacy::safetext::Gate;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY_DEEPSEEK: &str = "sk-a4-canary-deepseek-0001";
const KEY_ANTHROPIC: &str = "sk-a4-canary-anthropic-0002";
const KEY_OLLAMA: &str = "sk-a4-canary-ollama-0003";

static ENV: Once = Once::new();

/// Install the sentinel keys once. The values are never mutated, so parallel
/// reads are safe.
fn install_env() {
    ENV.call_once(|| {
        std::env::set_var("AUX_KEY_A4_DEEPSEEK", KEY_DEEPSEEK);
        std::env::set_var("AUX_KEY_A4_ANTHROPIC", KEY_ANTHROPIC);
        std::env::set_var("AUX_KEY_A4_OLLAMA", KEY_OLLAMA);
    });
}

fn gate() -> Gate {
    let grant = admit_call(PathId::C9, PrivacyMode::Private, Destination::LocalDisplay)
        .expect("C9 is covered in private mode");
    Gate::for_tests(&grant, [9u8; 32], aux_providers::test_gate::names_checked())
}

fn chat_request(gate: &mut Gate, text: &str) -> ChatRequest {
    let message = SafeMessage::issue(gate, &ChatMessage::user(text)).unwrap();
    ChatRequest::new(vec![message])
}

fn tool_request(gate: &mut Gate) -> ChatRequest {
    let message = SafeMessage::issue(gate, &ChatMessage::user("invite")).unwrap();
    let spec = ToolSpec::new(
        "skill__invite",
        "send an invite",
        json!({ "type": "object" }),
    );
    let spec = SafeToolSpec::issue(gate, &spec).unwrap();
    ChatRequest::new(vec![message])
        .with_tools(vec![spec])
        .with_forced_tool("skill__invite")
}

fn providers(deepseek: &MockServer, anthropic: &MockServer, ollama: &MockServer) -> ProvidersFile {
    let text = format!(
        r#"
[[provider]]
id = "deepseek"
kind = "openai"
base_url = "{deepseek}/v1"
key = "env:AUX_KEY_A4_DEEPSEEK"
models = ["deepseek-chat"]
disable_thinking = true

[[provider]]
id = "anthropic"
kind = "anthropic"
base_url = "{anthropic}"
key = "env:AUX_KEY_A4_ANTHROPIC"
models = ["claude-haiku-5-5"]

[[provider]]
id = "ollama-cloud"
kind = "openai"
base_url = "{ollama}/v1"
key = "env:AUX_KEY_A4_OLLAMA"
models = ["gpt-oss:120b-cloud"]

[brain]
default = "deepseek/deepseek-chat"
fallback = ["anthropic/claude-haiku-5-5"]
"#,
        deepseek = deepseek.uri(),
        anthropic = anthropic.uri(),
        ollama = ollama.uri(),
    );
    parse_providers_toml(&text).unwrap()
}

const OPENAI_TOOL_CALL: &str = r#"{
  "choices": [{
    "message": {
      "role": "assistant",
      "content": "",
      "tool_calls": [{
        "id": "call_1",
        "type": "function",
        "function": { "name": "skill__invite", "arguments": "{\"to\":\"elise\"}" }
      }]
    },
    "finish_reason": "tool_use"
  }]
}"#;

async fn mount_openai_tool_call(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(OPENAI_TOOL_CALL, "application/json"))
        .mount(server)
        .await;
}

async fn mount_anthropic_tool_call(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{ "type": "tool_use", "id": "t1", "name": "skill__invite", "input": { "to": "elise" } }],
            "stop_reason": "tool_use"
        })))
        .mount(server)
        .await;
}

fn all_bodies(requests: &[wiremock::Request]) -> Vec<String> {
    requests
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).to_string())
        .collect()
}

#[tokio::test]
async fn a_key_value_never_reaches_a_body_or_a_url() {
    install_env();
    let deepseek = MockServer::start().await;
    let anthropic = MockServer::start().await;
    let ollama = MockServer::start().await;
    for server in [&deepseek, &ollama] {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{ "message": { "role": "assistant", "content": "ok" } }]
            })))
            .mount(server)
            .await;
    }
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{ "type": "text", "text": "ok" }],
            "stop_reason": "end_turn"
        })))
        .mount(&anthropic)
        .await;

    let file = providers(&deepseek, &anthropic, &ollama);
    let mut gate = gate();
    for id in ["deepseek", "anthropic", "ollama-cloud"] {
        let entry = aux_providers::brain::find_entry(&file, id).unwrap();
        let model = entry.first_model().unwrap().to_string();
        let provider = build_entry(entry, &model, Path::new("/nonexistent")).unwrap();
        let response = provider
            .complete(&chat_request(&mut gate, "hello"))
            .await
            .unwrap();
        assert_eq!(response.content(), "ok");
    }

    let mut requests = Vec::new();
    for server in [&deepseek, &anthropic, &ollama] {
        requests.extend(server.received_requests().await.unwrap());
    }
    assert_eq!(requests.len(), 3, "each provider was called once");
    for body in all_bodies(&requests) {
        for needle in [KEY_DEEPSEEK, KEY_ANTHROPIC, KEY_OLLAMA] {
            assert!(!body.contains(needle), "a key leaked into a body: {body}");
        }
    }
    for request in &requests {
        for needle in [KEY_DEEPSEEK, KEY_ANTHROPIC, KEY_OLLAMA] {
            assert!(
                !request.url.as_str().contains(needle),
                "a key leaked into a URL: {}",
                request.url
            );
        }
    }
    // The key only travels in the auth header.
    let deepseek_requests = deepseek.received_requests().await.unwrap();
    assert_eq!(
        deepseek_requests[0].headers["authorization"]
            .to_str()
            .unwrap(),
        format!("Bearer {KEY_DEEPSEEK}")
    );
    let anthropic_requests = anthropic.received_requests().await.unwrap();
    assert_eq!(
        anthropic_requests[0].headers["x-api-key"].to_str().unwrap(),
        KEY_ANTHROPIC
    );
    assert!(!anthropic_requests[0].headers.contains_key("authorization"));
    let ollama_requests = ollama.received_requests().await.unwrap();
    assert_eq!(
        ollama_requests[0].headers["authorization"]
            .to_str()
            .unwrap(),
        format!("Bearer {KEY_OLLAMA}")
    );
}

#[tokio::test]
async fn the_three_cloud_legs_round_trip_a_forced_tool_call() {
    install_env();
    let deepseek = MockServer::start().await;
    let anthropic = MockServer::start().await;
    let ollama = MockServer::start().await;
    mount_openai_tool_call(&deepseek).await;
    mount_anthropic_tool_call(&anthropic).await;
    mount_openai_tool_call(&ollama).await;

    let file = providers(&deepseek, &anthropic, &ollama);
    let mut gate = gate();
    for id in ["deepseek", "anthropic", "ollama-cloud"] {
        let entry = aux_providers::brain::find_entry(&file, id).unwrap();
        let model = entry.first_model().unwrap().to_string();
        let provider = build_entry(entry, &model, Path::new("/nonexistent")).unwrap();
        let response = provider.complete(&tool_request(&mut gate)).await.unwrap();
        let calls = response.tool_calls();
        assert_eq!(calls.len(), 1, "{id} did not return a tool call");
        assert_eq!(calls[0].name, "skill__invite");
        assert_eq!(calls[0].arguments["to"], "elise");
    }
}

#[tokio::test]
async fn a_503_from_the_first_provider_hops_once_and_a_400_does_not() {
    install_env();
    let deepseek = MockServer::start().await;
    let anthropic = MockServer::start().await;
    let ollama = MockServer::start().await;

    // First provider is down with a 5xx; second answers.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": { "message": "overloaded" }
        })))
        .mount(&deepseek)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{ "type": "text", "text": "from anthropic" }],
            "stop_reason": "end_turn"
        })))
        .mount(&anthropic)
        .await;

    let file = providers(&deepseek, &anthropic, &ollama);
    let catalog = Catalog::bundled();
    let ledger = Arc::new(RecordingLedger::default());
    let chain = build_chain(
        &file,
        &catalog,
        Path::new("/nonexistent"),
        ledger.clone(),
        None,
        None,
        None,
        true,
    )
    .unwrap()
    .expect("a chain");
    let mut gate = gate();
    let response = chain
        .complete(&chat_request(&mut gate, "hello"))
        .await
        .unwrap();
    assert_eq!(response.content(), "from anthropic");
    let hops = ledger.hops();
    assert_eq!(hops.len(), 1);
    assert_eq!(
        (hops[0].from.as_str(), hops[0].to.as_str()),
        ("deepseek", "anthropic")
    );
    assert_eq!(hops[0].reason, "server_error");
    // The hop row carries no content.
    assert!(!hops[0].reason.contains("hello"));

    // A 400 does not hop.
    let deepseek2 = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": { "message": "bad request" }
        })))
        .mount(&deepseek2)
        .await;
    let file2 = providers(&deepseek2, &anthropic, &ollama);
    let ledger2 = Arc::new(RecordingLedger::default());
    let chain2 = build_chain(
        &file2,
        &catalog,
        Path::new("/nonexistent"),
        ledger2.clone(),
        None,
        None,
        None,
        true,
    )
    .unwrap()
    .expect("a chain");
    let err = chain2
        .complete(&chat_request(&mut gate, "hello"))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        aux_providers::ProviderError::Client { status: 400, .. }
    ));
    assert!(ledger2.hops().is_empty());
}

#[tokio::test]
async fn the_local_ollama_kind_posts_to_v1_chat_completions_and_sends_no_key() {
    install_env();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "role": "assistant", "content": "local" } }]
        })))
        .mount(&server)
        .await;

    let text = format!(
        r#"
[[provider]]
id = "ollama-local"
kind = "ollama"
base_url = "{server}"
models = ["granite3.3:2b"]
"#,
        server = server.uri()
    );
    let file = parse_providers_toml(&text).unwrap();
    let entry: &ProviderEntry = &file.providers[0];
    let provider = build_entry(entry, "granite3.3:2b", Path::new("/nonexistent")).unwrap();
    let mut gate = gate();
    let response = provider
        .complete(&chat_request(&mut gate, "salut"))
        .await
        .unwrap();
    assert_eq!(response.content(), "local");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests[0].url.path(), "/v1/chat/completions");
    assert!(!requests[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn a_tools_less_brain_is_refused_with_chat_only_before_any_request() {
    install_env();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "role": "assistant", "content": "should not run" } }]
        })))
        .mount(&server)
        .await;

    let text = format!(
        r#"
[[provider]]
id = "chatty"
kind = "openai"
base_url = "{server}/v1"
models = ["no-tools-model"]

[brain]
default = "chatty/no-tools-model"
"#,
        server = server.uri()
    );
    let file = parse_providers_toml(&text).unwrap();
    let catalog = Catalog::parse(
        r#"
[[model]]
provider = "chatty"
id = "no-tools-model"
tools = false
"#,
    )
    .unwrap();
    let err = build_chain(
        &file,
        &catalog,
        Path::new("/nonexistent"),
        Arc::new(RecordingLedger::default()),
        None,
        None,
        None,
        true,
    );
    let Err(err) = err else {
        panic!("expected a chat-only refusal");
    };
    assert!(err.to_string().contains("cannot use tools"), "got {err}");
    assert_eq!(aux_providers::ChatOnly::LABEL, "chat only");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "the gate must run before any request"
    );

    // The same brain is fine for a skill with no tools.
    let provider = build_chain(
        &file,
        &catalog,
        Path::new("/nonexistent"),
        Arc::new(RecordingLedger::default()),
        None,
        None,
        None,
        false,
    )
    .unwrap()
    .expect("a chain");
    let mut gate = gate();
    assert_eq!(
        provider
            .complete(&chat_request(&mut gate, "hi"))
            .await
            .unwrap()
            .content(),
        "should not run"
    );
}

#[tokio::test]
async fn resolution_writes_the_answering_provider_for_a_fake_brain() {
    install_env();
    let text = r#"
[[provider]]
id = "sandbox"
kind = "fake"
models = ["fake-model"]

[brain]
default = "sandbox/fake-model"
"#;
    let file = parse_providers_toml(text).unwrap();
    let catalog = Catalog::bundled();
    let provider = build_chain(
        &file,
        &catalog,
        Path::new("/nonexistent"),
        Arc::new(RecordingLedger::default()),
        None,
        None,
        Some("none"),
        false,
    )
    .unwrap();
    assert!(provider.is_none(), "brain: none runs without a model");

    assert_eq!(
        aux_providers::brain::resolve_brain(&file, &catalog, None, None).unwrap(),
        ResolvedBrain::Model {
            provider: "sandbox".into(),
            model: "fake-model".into()
        }
    );

    let provider = build_chain(
        &file,
        &catalog,
        Path::new("/nonexistent"),
        Arc::new(RecordingLedger::default()),
        None,
        None,
        None,
        false,
    )
    .unwrap()
    .expect("the fake provider");
    let mut gate = gate();
    let response = provider
        .complete(&chat_request(&mut gate, "ping"))
        .await
        .unwrap();
    assert_eq!(response.content(), "[fake:sandbox] ping");
}
