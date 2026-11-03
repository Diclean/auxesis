//! P2 acceptance: a declared secret is injected by name and never leaks.
//!
//! Offline only: the `fake_mcp_server` fixture echoes its own environment in
//! the `diagnostics` mode, so a test can prove the value reached the child
//! while it stayed out of the command's `Debug` and every error.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use kernel_mcp::{JsonRpcRequest, StdioCommand, StdioLimits, StdioTransport, Transport};

/// The canary is not a real secret; it only has to be recognisable.
const CANARY: &str = "sk-live-CANARY-not-a-real-key";

fn fixture(mode: &str) -> StdioCommand {
    StdioCommand::new(env!("CARGO_BIN_EXE_fake_mcp_server"))
        .expect("fixture path")
        .arg("--mode")
        .arg(mode)
}

#[tokio::test]
async fn a_declared_secret_reaches_the_child_and_not_the_debug_output() {
    let command = fixture("diagnostics")
        .env_declared("DATAGOUV_KEY", CANARY)
        .expect("declared key accepted");

    let debug = format!("{command:?}");
    assert!(
        !debug.contains(CANARY),
        "the value must never reach a log: {debug}"
    );
    assert!(
        debug.contains("DATAGOUV_KEY"),
        "the name is safe and useful: {debug}"
    );

    let transport = Arc::new(
        StdioTransport::new_for_tests(command, StdioLimits::default()).expect("transport"),
    );
    let request = JsonRpcRequest::new(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "auxesis", "version": "0"},
        }),
    );
    let value = transport
        .round_trip(request, Duration::from_secs(5))
        .await
        .expect("round trip")
        .into_result()
        .expect("initialize result");
    let env = value
        .get("fixtureDiagnostics")
        .and_then(|diagnostics| diagnostics.get("env"))
        .and_then(serde_json::Value::as_object)
        .expect("fixture diagnostics");
    assert_eq!(
        env.get("DATAGOUV_KEY").and_then(serde_json::Value::as_str),
        Some(CANARY)
    );
    // The Auxesis-reserved store is never inherited or injectable.
    assert!(env.get("AUX_KEY_OPENAI").is_none());
}

#[test]
fn a_reserved_or_malformed_env_name_is_refused_without_echoing_the_value() {
    for name in ["AUX_KEY_OPENAI", "AUXESIS_HOME", "AUX_TELEGRAM_BOT_TOKEN"] {
        let err = fixture("handshake")
            .env_declared(name, CANARY)
            .expect_err("reserved name must be refused");
        let text = format!("{err} {err:?}");
        assert!(!text.contains(CANARY), "{text}");
        assert!(!text.contains(name), "even the name stays out: {text}");
    }
    for name in ["1BAD", "with space", ""] {
        assert!(fixture("handshake").env_declared(name, CANARY).is_err());
    }
}
