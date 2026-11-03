//! P2/P4 acceptance: startup discovery, per-agent mounting and isolation.
//!
//! Offline only: the `stdio` cases run the on-disk `fake_mcp_server` fixture,
//! the `http` case runs a loopback axum mock. No external host, no secret.

use std::collections::BTreeMap;

use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};

use kernel_broker::{ToolClassExt, ToolRegistry};
use kernel_mcp::{
    McpConfig, McpRuntime, McpServerConfig, McpServerState, McpStartOptions, McpTransport,
};

/// The key every test confirmation is minted with.
///
/// `confirmation_secret: None` now refuses every `stdio` launch (item 6), so a
/// test that wants to spawn the fixture must supply a key **and** a matching
/// `stdio_confirmation`. A test never uses the real daemon token.
const TEST_SECRET: &[u8] = b"aux-mcp-test-key";

/// The options a library test needs: no SSRF guard (loopback mock) and a
/// confirmation key, because no key means no confirmed `stdio` launch. The
/// `stdio` sandbox is deliberately **not** an option: the launch path attaches
/// it whenever the platform has one.
fn permissive_options() -> McpStartOptions {
    McpStartOptions {
        network_guard: false,
        confirmation_secret: Some(TEST_SECRET.to_vec()),
    }
}

/// A `stdio` server entry pinned to the fixture binary and confirmed for the
/// test key.
fn stdio_server(id: &str, agents: &[(&str, &[&str])], env: Vec<String>) -> McpServerConfig {
    let mut server = McpServerConfig {
        id: id.to_string(),
        catalog_id: None,
        data_class: kernel_mcp::McpDataClass::Sensitive,
        stdio_confirmed: true,
        stdio_confirmation: None,
        approval: None,
        network: false,
        transport: McpTransport::Stdio,
        url: None,
        command: Some(env!("CARGO_BIN_EXE_fake_mcp_server").to_string()),
        args: vec!["--mode".to_owned(), "handshake".to_owned()],
        env,
        enabled: true,
        agents: agents
            .iter()
            .map(|(agent, tools)| {
                (
                    (*agent).to_owned(),
                    tools.iter().map(|tool| (*tool).to_owned()).collect(),
                )
            })
            .collect(),
    };
    server.stdio_confirmation = server.confirmation_binding(TEST_SECRET);
    server
}

fn config(servers: Vec<McpServerConfig>) -> McpConfig {
    McpConfig::from_servers(servers)
}

#[tokio::test]
async fn a_agent_sees_only_its_listed_and_discovered_tools() {
    let runtime = McpRuntime::start_with(
        config(vec![stdio_server(
            "srv",
            &[("main", &["FAKE_TOOL"])],
            vec![],
        )]),
        &BTreeMap::new(),
        permissive_options(),
        &|_| Ok(()),
    )
    .await;

    let statuses = runtime.statuses();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].state, McpServerState::Ready);
    assert_eq!(statuses[0].tool_count, 1);

    let mut main = ToolRegistry::new();
    assert_eq!(runtime.register_for_agent("main", &mut main), 1);
    assert_eq!(main.names(), vec!["mcp__srv__FAKE_TOOL"]);

    let mut other = ToolRegistry::new();
    assert_eq!(
        runtime.register_for_agent("other", &mut other),
        0,
        "an agent without a [server.agents] entry sees nothing"
    );
    assert!(other.is_empty());
}

#[tokio::test]
async fn an_mcp_tool_is_untrusted_and_needs_an_explicit_rule_when_not_read_only() {
    let runtime = McpRuntime::start_with(
        config(vec![stdio_server(
            "srv",
            &[("main", &["FAKE_TOOL"])],
            vec![],
        )]),
        &BTreeMap::new(),
        permissive_options(),
        &|_| Ok(()),
    )
    .await;
    let mut registry = ToolRegistry::new();
    runtime.register_for_agent("main", &mut registry);

    let tool = registry.get("mcp__srv__FAKE_TOOL").expect("registered");
    // No annotations on the fixture tool => conservative high risk.
    assert_eq!(tool.risk(), kernel_broker::Risk::High);
    assert!(
        tool.requires_explicit_rule(),
        "a non-read-only MCP tool must refuse a wildcard allow"
    );
    assert!(
        registry.is_untrusted_output("mcp__srv__FAKE_TOOL"),
        "MCP output must taint the conversation"
    );
    assert!(
        !registry.is_read_only("mcp__srv__FAKE_TOOL"),
        "an unannotated tool is consequential"
    );
    assert!(
        tool.arguments_leave_machine(),
        "MCP arguments go to a third-party server and must be screened"
    );
}

#[tokio::test]
async fn a_listed_but_absent_tool_is_ignored_not_fallback() {
    let runtime = McpRuntime::start_with(
        config(vec![stdio_server("srv", &[("main", &["NOPE"])], vec![])]),
        &BTreeMap::new(),
        permissive_options(),
        &|_| Ok(()),
    )
    .await;
    assert_eq!(runtime.statuses()[0].state, McpServerState::Ready);
    let mut registry = ToolRegistry::new();
    assert_eq!(runtime.register_for_agent("main", &mut registry), 0);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn a_broken_server_does_not_stop_the_others() {
    let mut broken = stdio_server("broken", &[("main", &["FAKE_TOOL"])], vec![]);
    broken.command = Some("/nonexistent/mcp-does-not-exist".to_owned());
    let runtime = McpRuntime::start_with(
        config(vec![
            broken,
            stdio_server("srv", &[("main", &["FAKE_TOOL"])], vec![]),
        ]),
        &BTreeMap::new(),
        permissive_options(),
        &|_| Ok(()),
    )
    .await;

    let states: Vec<McpServerState> = runtime.statuses().iter().map(|s| s.state).collect();
    assert_eq!(
        states,
        vec![McpServerState::Failed, McpServerState::Ready],
        "one failing server must be isolated"
    );
    assert_eq!(runtime.tool_count(), 1);

    let mut registry = ToolRegistry::new();
    assert_eq!(runtime.register_for_agent("main", &mut registry), 1);
}

#[tokio::test]
async fn a_missing_declared_secret_isolates_only_that_server() {
    let with_secret = stdio_server(
        "srv",
        &[("main", &["FAKE_TOOL"])],
        vec!["DATAGOUV_KEY".into()],
    );
    let runtime = McpRuntime::start_with(
        config(vec![with_secret]),
        &BTreeMap::new(),
        permissive_options(),
        &|_| Ok(()),
    )
    .await;
    assert_eq!(runtime.statuses()[0].state, McpServerState::Failed);
    assert_eq!(runtime.tool_count(), 0);

    let mut present = stdio_server(
        "srv",
        &[("main", &["FAKE_TOOL"])],
        vec!["DATAGOUV_KEY".into()],
    );
    present.enabled = true;
    let mut secrets = BTreeMap::new();
    secrets.insert("DATAGOUV_KEY".to_owned(), "not-a-real-key".to_owned());
    let runtime = McpRuntime::start_with(
        config(vec![present]),
        &secrets,
        permissive_options(),
        &|_| Ok(()),
    )
    .await;
    assert_eq!(runtime.statuses()[0].state, McpServerState::Ready);
    assert_eq!(runtime.tool_count(), 1);
}

/// A loopback HTTP MCP server: `initialize` + one `tools/list` read-only tool.
async fn spawn_http_mock() -> (u16, tokio::task::JoinHandle<()>) {
    // The mock echoes the request id; the transport rejects a wrong id.
    async fn echo(body: axum::body::Bytes) -> axum::response::Response {
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock", "version": "1"}
            }),
            "tools/list" => json!({
                "tools": [{
                    "name": "HTTP_TOOL",
                    "description": "a tool",
                    "inputSchema": {"type": "object",
                        "properties": {"q": {"type": "string"}}},
                    "annotations": {"readOnlyHint": true}
                }]
            }),
            // A JSON-RPC notification gets no body, only an accepted status.
            _ => return axum::http::StatusCode::ACCEPTED.into_response(),
        };
        axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let port = listener.local_addr().expect("addr").port();
    let app = Router::new().route("/mcp", post(echo));
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (port, handle)
}

#[tokio::test]
async fn a_loopback_http_server_is_discovered_and_mounted() {
    let (port, handle) = spawn_http_mock().await;
    let server = McpServerConfig {
        id: "web".to_owned(),
        catalog_id: Some("web-tools".to_owned()),
        data_class: kernel_mcp::McpDataClass::Sensitive,
        stdio_confirmed: false,
        stdio_confirmation: None,
        approval: None,
        network: false,
        transport: McpTransport::Http,
        url: Some(format!("http://127.0.0.1:{port}/mcp")),
        command: None,
        args: Vec::new(),
        env: Vec::new(),
        enabled: true,
        agents: [("main".to_owned(), vec!["HTTP_TOOL".to_owned()])]
            .into_iter()
            .collect(),
    };
    let runtime = McpRuntime::start_with(
        config(vec![server]),
        &BTreeMap::new(),
        permissive_options(),
        &|_| Ok(()),
    )
    .await;
    assert_eq!(runtime.statuses()[0].state, McpServerState::Ready);
    assert_eq!(runtime.tool_count(), 1);

    let mut registry = ToolRegistry::new();
    assert_eq!(runtime.register_for_agent("main", &mut registry), 1);
    let tool = registry.get("mcp__web__HTTP_TOOL").expect("registered");
    assert_eq!(
        tool.risk(),
        kernel_broker::Risk::Low,
        "readOnlyHint is low risk"
    );
    assert!(
        tool.requires_explicit_rule(),
        "a server readOnlyHint is not corroborated: no wildcard allow for MCP"
    );
    assert!(
        !registry.is_read_only("mcp__web__HTTP_TOOL"),
        "a server readOnlyHint is not the by-construction read-only class"
    );
    handle.abort();
}
