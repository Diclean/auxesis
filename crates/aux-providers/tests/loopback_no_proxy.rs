//! DELEG-WHERE-1: a loopback brain is reached directly, never through a proxy
//! from the environment, so `on_this_mac` is never claimed for a prompt a
//! proxy could forward. Its own test binary: the proxy variables are
//! process-wide and must not reach any other test.

use aux_providers::config::{ProviderConfig, ProviderKind};
use aux_providers::openai_compat::OpenAiCompat;
use aux_providers::provider::ChatProvider;
use aux_providers::types::{ChatMessage, ChatRequest, SafeMessage};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn a_loopback_runtime_ignores_proxy_variables_and_stays_on_this_mac() {
    // An unroutable proxy (TEST-NET-1): any request sent through it fails.
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "all_proxy",
    ] {
        std::env::set_var(name, "http://192.0.2.1:9");
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({ "choices": [{ "message": { "role": "assistant", "content": "ok" } }] }),
        ))
        .mount(&server)
        .await;
    let config = ProviderConfig {
        disable_thinking: false,
        id: "ollama".into(),
        base_url: format!("{}/v1", server.uri()),
        model: "llama3.2".into(),
        key_user: None,
        kind: ProviderKind::OpenAiCompat,
    };
    let timeout = std::time::Duration::from_secs(3);
    let brain = OpenAiCompat::with_key_and_timeout(&config, None, timeout)
        .unwrap()
        .local_runtime();
    let grant = kernel_core::privacy::admit_call(
        kernel_core::privacy::PathId::C9,
        kernel_core::privacy::PrivacyMode::Open,
        kernel_core::privacy::Destination::LocalDisplay,
    )
    .unwrap();
    let mut gate = kernel_privacy::safetext::Gate::for_tests(
        &grant,
        [8u8; 32],
        std::sync::Arc::new(kernel_privacy::Registry::new()),
    );
    let message = SafeMessage::issue(&mut gate, &ChatMessage::user("hello")).unwrap();
    let request = ChatRequest::new(vec![message]);
    let answer = brain.complete(&request).await.expect("reached directly");
    assert_eq!(answer.message.content, "ok");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert!(brain.on_this_mac());
}
