//! E0 acceptance: the agents runtime (D33).
//!
//! A real server on an ephemeral loopback port with a scripted provider, a
//! scripted delegation executor and a fake domain tool. No network, no
//! Keychain, no real `~/.auxesis`.
//!
//! The four acceptance items:
//! 1. the chief delegates, `delegation.*` frames stream, the result comes back
//!    and the chief's context never holds the agent's raw data (the hero test);
//! 2. Mail calling a Documents-only tool is refused before the tool runs;
//! 3. one approval answered by id resolves everywhere, with `approval.updated`;
//! 4. Stop leaves partial work and offers Resume (store-level unit tests in
//!    `crates/aux-store/src/delegation.rs` cover the record; `GET /v1/stop`
//!    and Stop all are covered here).

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{ChatMessage, ChatResponse, FakeProvider};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions, ToolRegistryHook};
use auxd::delegation::{DelegationExecutor, DelegationRun};
use common::{get, http, post, HttpResponse};
use futures_util::StreamExt;
use kernel_broker::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, Trust};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "aux"
approvals = "ask"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"

[[rules]]
agent = "aux"
tool = "delegate"
action = "allow"

[[rules]]
agent = "mail"
tool = "mail_send"
action = "allow"

[[rules]]
agent = "mail"
tool = "read_file"
action = "allow"
"#;

/// The raw text the fake Mail agent "sees"; it must never reach the chief.
const RAW_MAIL: &str = "PRIVATE-MAIL-BODY-Camille-Exemple";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct TestApi {
    _dir: tempfile::TempDir,
    addr: SocketAddr,
    token: String,
    home: std::path::PathBuf,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start(options: ApiOptions) -> Self {
        Self::start_with(options, CONFIG).await
    }

    async fn start_with(options: ApiOptions, config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), config).unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        let handle = api::spawn(&home, options).unwrap();
        let addr = handle.addr();
        Self {
            _dir: dir,
            addr,
            token: TOKEN.to_string(),
            home,
            handle: Some(handle),
        }
    }

    fn get(&self, path: &str) -> HttpResponse {
        get(self.addr, path, Some(&self.token))
    }

    fn post(&self, path: &str, body: &str) -> HttpResponse {
        post(self.addr, path, Some(&self.token), body)
    }

    fn put(&self, path: &str, body: &str) -> HttpResponse {
        http(self.addr, "PUT", path, Some(&self.token), Some(body))
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

fn options(provider: Arc<dyn aux_providers::ChatProvider>) -> ApiOptions {
    ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(provider),
        approval_timeout: Some(Duration::from_secs(30)),
        ..ApiOptions::default()
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(addr: SocketAddr, token: &str) -> Ws {
    let mut request = format!("ws://{addr}/v1/events")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    tokio_tungstenite::connect_async(request).await.unwrap().0
}

async fn wait_ws<F: Fn(&Value) -> bool>(
    ws: &mut Ws,
    timeout: Duration,
    predicate: F,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let slice = Duration::from_millis(500).min(deadline - tokio::time::Instant::now());
        let Ok(Some(Ok(message))) = tokio::time::timeout(slice, ws.next()).await else {
            continue;
        };
        let WsMessage::Text(text) = message else {
            continue;
        };
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            if predicate(&value) {
                return Some(value);
            }
        }
    }
    None
}

/// Collect `delegation.*` frames until `message.done` (or the timeout).
async fn delegation_frames(ws: &mut Ws, timeout: Duration) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut frames = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let slice = Duration::from_millis(500).min(deadline - tokio::time::Instant::now());
        let Ok(Some(Ok(message))) = tokio::time::timeout(slice, ws.next()).await else {
            continue;
        };
        let WsMessage::Text(text) = message else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let kind = value["type"].as_str().unwrap_or("");
        if kind == "message.done" {
            break;
        }
        if kind.starts_with("delegation.") || kind == "approval.updated" {
            frames.push(value);
        }
    }
    frames
}

// ---------------------------------------------------------------------------
// 1. hero: Aux delegates to Mail; the chief sees only the result
// ---------------------------------------------------------------------------

struct ScriptedMail {
    raw: String,
}

#[async_trait]
impl DelegationExecutor for ScriptedMail {
    async fn execute(&self, run: DelegationRun) -> Result<String, String> {
        run.step("read the owner's thread", "working");
        run.step(&format!("saw {}", self.raw), "working");
        run.step("drafted a reply", "working");
        Ok("Mail sent the reply.".to_string())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hero_chief_delegates_and_only_the_result_comes_back() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![aux_providers::ToolCall::new(
                    "call_1",
                    "delegate",
                    json!({ "agent": "mail", "task": "summarise Camille's last thread" }),
                )],
            )),
            ChatResponse::assistant("Done."),
        ],
    ));
    let executor: Arc<dyn DelegationExecutor> = Arc::new(ScriptedMail {
        raw: RAW_MAIL.to_string(),
    });
    let mut t = TestApi::start(ApiOptions {
        delegations: Some(executor),
        ..options(provider)
    })
    .await;
    let mut ws = ws_connect(t.addr, &t.token).await;

    let sent = t.post(
        "/v1/threads/aux/messages",
        &json!({ "content": "ask Mail" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);

    let frames = delegation_frames(&mut ws, Duration::from_secs(10)).await;
    let kinds: Vec<&str> = frames.iter().filter_map(|f| f["type"].as_str()).collect();
    assert!(kinds.contains(&"delegation.new"), "frames: {kinds:?}");
    assert!(kinds.contains(&"delegation.result"), "frames: {kinds:?}");
    assert!(
        kinds
            .iter()
            .filter(|kind| **kind == "delegation.step")
            .count()
            >= 2,
        "steps must stream: {kinds:?}"
    );
    let result = frames
        .iter()
        .find(|frame| frame["type"] == "delegation.result")
        .unwrap();
    assert_eq!(result["result"], "Mail sent the reply.");

    // The chief's stored context holds the short result, never the raw mail.
    let page = t.get("/v1/threads/aux/messages");
    assert_eq!(page.status, 200, "body: {}", page.body);
    let text = page.body.clone();
    assert!(
        text.contains("Mail sent the reply."),
        "chief must see the result"
    );
    assert!(
        !text.contains(RAW_MAIL),
        "the chief must never see the agent's raw data"
    );

    // The delegation is recorded and finished, with the raw data only in the
    // steps the owner sees (not in the chief's context).
    let list = t.get("/v1/delegations?thread=aux");
    assert_eq!(list.status, 200, "body: {}", list.body);
    let delegations = list.json();
    let first = &delegations[0];
    assert_eq!(first["state"], "done");
    assert_eq!(first["result"], "Mail sent the reply.");
    assert_eq!(first["agent"], "mail");
    assert!(
        first["steps"].as_array().unwrap().len() >= 3,
        "partial steps are kept: {first}"
    );

    // Stop keeps the partial work and Resume re-runs the same id.
    let id = first["id"].as_str().unwrap().to_string();
    let stopped = t.post(&format!("/v1/delegations/{id}/stop"), "{}");
    assert_eq!(stopped.status, 200, "body: {}", stopped.body);
    assert_eq!(stopped.json()["state"], "stopped");
    assert!(
        stopped.json()["steps"].as_array().unwrap().len() >= 3,
        "Stop must keep the partial steps: {}",
        stopped.body
    );
    let resumed = t.post(&format!("/v1/delegations/{id}/resume"), "{}");
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    assert_eq!(resumed.json()["state"], "queued");
    // Resuming a live delegation is a conflict.
    let again = t.post(&format!("/v1/delegations/{id}/resume"), "{}");
    assert_eq!(again.status, 409, "body: {}", again.body);

    t.stop();
}

// ---------------------------------------------------------------------------
// 2. Mail calling a Documents-only tool is refused before it runs
// ---------------------------------------------------------------------------

struct DocumentsOnly {
    ran: Arc<AtomicBool>,
}

impl NativeTool for DocumentsOnly {
    fn native_name(&self) -> &'static str {
        "documents.read"
    }
    fn native_description(&self) -> &'static str {
        "Read a filed document (Documents domain only)."
    }
    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| json!({"type":"object","properties":{}}));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for DocumentsOnly {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B3
    }
    fn name(&self) -> &str {
        self.native_name()
    }
    fn schema(&self) -> Value {
        self.native_schema().clone()
    }
    async fn run(&self, _args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        self.ran.store(true, Ordering::SeqCst);
        Ok(ToolOutput::ok("a document"))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn class(&self) -> ToolClass {
        ToolClass {
            output_trust: Trust::Trusted,
            ..ToolClass::default()
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mail_calling_a_documents_only_tool_is_refused_by_the_broker() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![aux_providers::ToolCall::new(
                    "call_1",
                    "documents.read",
                    json!({}),
                )],
            )),
            ChatResponse::assistant("Done."),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(DocumentsOnly {
            ran: Arc::clone(&flag),
        }));
        registry.mark_read_only("documents.read");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;

    let sent = t.post(
        "/v1/threads/mail/messages",
        &json!({ "content": "file this" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !ran.load(Ordering::SeqCst),
        "the Documents-only tool must never run for Mail"
    );

    // The refusal is on the Ledger and in the model's tool result.
    let activity = t.get("/v1/activity?agent=mail");
    assert_eq!(activity.status, 200, "body: {}", activity.body);
    let entries = activity.json();
    assert!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["kind"] == "tool.decision"),
        "the refusal must leave a tool.decision Ledger row: {entries}"
    );
    let messages = t.get("/v1/threads/mail/messages").body;
    assert!(
        messages.contains("denied"),
        "the model must get the refusal: {messages}"
    );

    t.stop();
}

// ---------------------------------------------------------------------------
// 3. one approval, keyed by id, with approval.updated and a bounded Undo
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_approval_resolves_everywhere_and_later_can_be_undone() {
    // `write_file` is not allowed by the config, so it asks.
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![aux_providers::ToolCall::new(
                    "call_1",
                    "write_file",
                    json!({ "path": "note.txt", "content": "hi" }),
                )],
            )),
            ChatResponse::assistant("Done."),
        ],
    ));
    let mut t = TestApi::start(options(provider)).await;
    let mut ws = ws_connect(t.addr, &t.token).await;

    // The turn blocks on the approval, so send it on a blocking task.
    let addr = t.addr;
    let token = t.token.clone();
    let send = tokio::task::spawn_blocking(move || {
        post(
            addr,
            "/v1/threads/aux/messages",
            Some(&token),
            &json!({ "content": "write a note" }).to_string(),
        )
    });

    // Wait for the pending approval, then defer it.
    let pending = wait_for_pending(&t, Duration::from_secs(10)).await;
    let id = pending["id"].as_str().unwrap().to_string();
    let deferred = t.post(
        &format!("/v1/approvals/{id}"),
        &json!({ "decision": "later" }).to_string(),
    );
    assert_eq!(deferred.status, 200, "body: {}", deferred.body);
    assert_eq!(deferred.json()["state"]["state"], "deferred");
    let updated = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "approval.updated"
            && value["id"] == id.as_str()
            && value["state"]["state"] == "deferred"
    })
    .await
    .expect("approval.updated must stream the deferred state");
    assert_eq!(updated["state"]["state"], "deferred");

    // `later` is a fail-closed no: the turn ends on it. Wait for that end
    // before the undo, or the turn's own clean-up (P2-1) can retire the
    // re-opened id between the undo and the next step.
    let sent = tokio::time::timeout(Duration::from_secs(10), send)
        .await
        .expect("the turn ends after `later`")
        .unwrap();
    assert_eq!(sent.status, 200, "body: {}", sent.body);

    // Undo re-opens the same id in every view.
    let undone = t.post(&format!("/v1/approvals/{id}/undo"), "{}");
    assert_eq!(undone.status, 200, "body: {}", undone.body);
    assert_eq!(undone.json()["state"]["state"], "pending");
    let listed = t.get("/v1/approvals?state=pending");
    assert!(
        listed
            .json()
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["id"] == id.as_str()),
        "the reopened id is pending again: {}",
        listed.body
    );

    // The re-opened id can still be answered.
    let denied = t.post(
        &format!("/v1/approvals/{id}"),
        &json!({ "decision": "deny" }).to_string(),
    );
    assert_eq!(denied.status, 200, "body: {}", denied.body);

    t.stop();
}

async fn wait_for_pending(t: &TestApi, timeout: Duration) -> Value {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let response = t.get("/v1/approvals?state=pending");
        let value = response.json();
        if let Some(first) = value.as_array().and_then(|list| list.first()) {
            return first.clone();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no pending approval appeared");
}

// ---------------------------------------------------------------------------
// 4. Stop all pauses the team and reports through GET /v1/stop
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_all_is_visible_through_get_stop() {
    let provider = Arc::new(FakeProvider::scripted("fakey", vec![]));
    let mut t = TestApi::start(options(provider)).await;

    let before = t.get("/v1/stop");
    assert_eq!(before.status, 200, "body: {}", before.body);
    assert_eq!(before.json()["stopped"], false);

    let stopped = t.post("/v1/stop-all", "{}");
    assert_eq!(stopped.status, 200, "body: {}", stopped.body);

    let after = t.get("/v1/stop");
    assert_eq!(after.status, 200, "body: {}", after.body);
    let value = after.json();
    assert_eq!(value["stopped"], true);
    assert!(value["cancelled_sends"].is_u64());

    let resumed = t.post("/v1/resume", "{}");
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    assert_eq!(t.get("/v1/stop").json()["stopped"], false);

    t.stop();
}

// ---------------------------------------------------------------------------
// security-review round 1: the six findings each get a regression test.
// ---------------------------------------------------------------------------

/// A configurable test tool: flags when it ran (and when it started/completed),
/// can block, and returns a fixed string.
struct TestTool {
    name: &'static str,
    result: String,
    ran: Arc<AtomicBool>,
    started: Option<Arc<AtomicBool>>,
    completed: Option<Arc<AtomicBool>>,
    block_for: Option<Duration>,
}

impl TestTool {
    fn simple(name: &'static str, result: &str, ran: Arc<AtomicBool>) -> Self {
        Self {
            name,
            result: result.to_string(),
            ran,
            started: None,
            completed: None,
            block_for: None,
        }
    }
}

impl NativeTool for TestTool {
    fn native_name(&self) -> &'static str {
        self.name
    }
    fn native_description(&self) -> &'static str {
        "A test tool."
    }
    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
            || json!({"type":"object","properties":{},"additionalProperties":false}),
        );
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for TestTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B3
    }
    fn name(&self) -> &str {
        self.name
    }
    fn schema(&self) -> Value {
        self.native_schema().clone()
    }
    async fn run(&self, _args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        if let Some(started) = &self.started {
            started.store(true, Ordering::SeqCst);
        }
        if let Some(block_for) = self.block_for {
            tokio::time::sleep(block_for).await;
        }
        if let Some(completed) = &self.completed {
            completed.store(true, Ordering::SeqCst);
        }
        self.ran.store(true, Ordering::SeqCst);
        Ok(ToolOutput::ok(self.result.clone()))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn class(&self) -> ToolClass {
        ToolClass {
            output_trust: Trust::Trusted,
            ..ToolClass::default()
        }
    }
}

fn tool_call(name: &str, arguments: Value) -> ChatResponse {
    ChatResponse::new(ChatMessage::assistant_with_tool_calls(
        "",
        vec![aux_providers::ToolCall::new("call_1", name, arguments)],
    ))
}

async fn wait_for_delegation(t: &TestApi, timeout: Duration) -> Value {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let response = t.get("/v1/delegations?thread=aux");
        if let Some(first) = response.json().as_array().and_then(|list| list.first()) {
            return first.clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no delegation appeared");
}

/// #1: the chief cannot reach a domain tool by its bare name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chief_cannot_call_a_domain_tool_directly() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("mail_read", json!({"account":"personal","uid":1})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "mail_read",
            "PRIVATE-MAIL-BODY",
            Arc::clone(&flag),
        )));
        registry.mark_read_only("mail_read");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;
    let sent = t.post(
        "/v1/threads/aux/messages",
        &json!({ "content": "read my mail" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !ran.load(Ordering::SeqCst),
        "the chief must not call a domain tool directly"
    );
    t.stop();
}

/// #2: an unregistered agent gets no implicit domain access.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unregistered_agent_cannot_reach_a_domain_tool() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("documents.read", json!({})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "documents.read",
            "a document",
            Arc::clone(&flag),
        )));
        registry.mark_read_only("documents.read");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;
    let sent = t.post(
        "/v1/threads/ghost/messages",
        &json!({ "content": "read a document" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !ran.load(Ordering::SeqCst),
        "an unregistered agent must not reach a scoped tool"
    );
    t.stop();
}

/// #4: the child turn's own content never reaches the chief's channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_turn_content_never_reaches_the_chief_channel() {
    const CANARY: &str = "CHILD-TURN-CANARY-Camille-Exemple";
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call(
                "delegate",
                json!({"agent":"mail","task":"summarise the thread"}),
            ),
            tool_call("mail_read", json!({"account":"personal","uid":1})),
            ChatResponse::assistant("safe result"),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "mail_read",
            CANARY,
            Arc::clone(&flag),
        )));
        registry.mark_read_only("mail_read");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;
    let mut ws = ws_connect(t.addr, &t.token).await;

    let sent = t.post(
        "/v1/threads/aux/messages",
        &json!({ "content": "ask Mail" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(ran.load(Ordering::SeqCst), "the child turn must run");

    let frames = delegation_frames(&mut ws, Duration::from_secs(10)).await;
    let encoded = serde_json::to_string(&frames).unwrap();
    assert!(
        !encoded.contains(CANARY),
        "the child's content leaked onto the chief's channel: {encoded}"
    );
    assert!(
        frames
            .iter()
            .any(|frame| frame["type"] == "delegation.result" && frame["result"] == "safe result"),
        "the safe result must still come back: {frames:?}"
    );
    t.stop();
}

/// #3: task Stop cancels the in-flight child and never becomes `done`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn task_stop_cancels_the_in_flight_child_and_stays_stopped() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("delegate", json!({"agent":"mail","task":"read the thread"})),
            tool_call("mail_read", json!({"account":"personal","uid":1})),
            ChatResponse::assistant("safe result"),
            ChatResponse::assistant("done"),
        ],
    ));
    let started = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let start_flag = Arc::clone(&started);
    let done_flag = Arc::clone(&completed);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool {
            name: "mail_read",
            result: "PRIVATE-MAIL-BODY".to_string(),
            ran: Arc::clone(&flag),
            started: Some(Arc::clone(&start_flag)),
            completed: Some(Arc::clone(&done_flag)),
            block_for: Some(Duration::from_secs(30)),
        }));
        registry.mark_read_only("mail_read");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;

    let addr = t.addr;
    let token = t.token.clone();
    let send = tokio::task::spawn_blocking(move || {
        post(
            addr,
            "/v1/threads/aux/messages",
            Some(&token),
            &json!({ "content": "ask Mail" }).to_string(),
        )
    });

    // Wait until the child's tool is genuinely in flight.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !started.load(Ordering::SeqCst) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        started.load(Ordering::SeqCst),
        "the child tool never started"
    );
    let delegation = wait_for_delegation(&t, Duration::from_secs(5)).await;
    let id = delegation["id"].as_str().unwrap().to_string();

    let stopped = t.post(&format!("/v1/delegations/{id}/stop"), "{}");
    assert_eq!(stopped.status, 200, "body: {}", stopped.body);
    let _ = tokio::time::timeout(Duration::from_secs(20), send).await;

    assert!(
        !completed.load(Ordering::SeqCst),
        "the cancelled child tool must not complete its side effect"
    );
    let final_state = t.get(&format!("/v1/delegations/{id}")).json();
    assert_eq!(
        final_state["state"], "stopped",
        "a stopped task must never be overwritten with done: {final_state}"
    );
    t.stop();
}

/// #5: an `ask` grant forces approval even when a global rule allows the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ask_grant_requires_an_approval_despite_a_global_allow() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("mail_send", json!({"to":"camille@exemple.test"})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "mail_send",
            "sent",
            Arc::clone(&flag),
        )));
        registry.mark_read_only("mail_send");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;

    let addr = t.addr;
    let token = t.token.clone();
    let send = tokio::task::spawn_blocking(move || {
        post(
            addr,
            "/v1/threads/mail/messages",
            Some(&token),
            &json!({ "content": "send it" }).to_string(),
        )
    });

    let pending = wait_for_pending(&t, Duration::from_secs(10)).await;
    assert_eq!(
        pending["scope_tool"], "mail_send",
        "an ask grant must force an approval despite the global allow"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the tool must not run before the owner answers"
    );
    let id = pending["id"].as_str().unwrap().to_string();
    let denied = t.post(
        &format!("/v1/approvals/{id}"),
        &json!({ "decision": "deny" }).to_string(),
    );
    assert_eq!(denied.status, 200, "body: {}", denied.body);
    let _ = tokio::time::timeout(Duration::from_secs(10), send).await;
    assert!(!ran.load(Ordering::SeqCst));
    t.stop();
}

/// A grants approval that went stale (the chief lost the access while the
/// card waited) is refused, and the stream never shows it allowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_grants_approval_is_refused_and_never_streams_allowed() {
    let provider = Arc::new(FakeProvider::scripted("fakey", vec![]));
    let config = CONFIG.replace("default_agent = \"aux\"", "default_agent = \"main\"");
    let mut t = TestApi::start_with(options(provider), &config).await;
    // The chief has no blanket MCP access; the owner grants it explicitly.
    let mut chief = auxd::agents::grants(&t.home, "main").unwrap();
    chief.can_do.push(aux_runtime::grants::DoGrant {
        skill: "mcp.access".to_string(),
        level: aux_runtime::grants::ActionLevel::Auto,
    });
    auxd::agents::write_grants(&t.home, "main", &chief).unwrap();
    let mut ws = ws_connect(t.addr, &t.token).await;
    let before = t.get("/v1/agents/mail/grants").json();
    let mut wider = before.clone();
    let more = json!({"skill": "mcp.access", "level": "auto"});
    wider["do"].as_array_mut().unwrap().push(more);
    let put = t.put("/v1/agents/mail/grants", &wider.to_string());
    assert_eq!(put.status, 200, "body: {}", put.body);
    let id = put.json()["approval_id"].as_str().unwrap().to_string();
    let mut chief = auxd::agents::grants(&t.home, "main").unwrap();
    chief.can_do.retain(|grant| grant.skill != "mcp.access");
    auxd::agents::write_grants(&t.home, "main", &chief).unwrap();

    let answer = t.post(
        &format!("/v1/approvals/{id}"),
        r#"{"decision":"allow_once"}"#,
    );
    assert_eq!(answer.status, 409, "body: {}", answer.body);
    assert!(
        answer.body.contains("grant_exceeds_chief"),
        "{}",
        answer.body
    );
    assert_eq!(t.get("/v1/agents/mail/grants").json(), before);
    // The answer streams `resolved` then `updated`; both must say denied.
    for kind in ["approval.resolved", "approval.updated"] {
        let frame = wait_ws(&mut ws, Duration::from_secs(5), |value| {
            value["type"] == kind && value["id"] == id.as_str()
        })
        .await
        .unwrap_or_else(|| panic!("{kind} must stream"));
        assert_eq!(frame["state"]["state"], "denied", "{frame}");
    }
    t.stop();
}

/// An older grants card approved after a newer one is refused: the newer set
/// stays, the answer is `409 grants_changed`, and the stream says denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_grants_approval_never_overwrites_a_newer_set() {
    let provider = Arc::new(FakeProvider::scripted("fakey", vec![]));
    let config = CONFIG.replace("default_agent = \"aux\"", "default_agent = \"main\"");
    let mut t = TestApi::start_with(options(provider), &config).await;
    std::fs::create_dir_all(t.home.join("agents/mail")).unwrap();
    let mut ws = ws_connect(t.addr, &t.token).await;
    let before = t.get("/v1/agents/mail/grants").json();
    let propose = |note: &str| {
        let mut next = before.clone();
        next["egress_note"] = json!(note);
        next
    };
    let (older, newer) = (propose("older proposal"), propose("newer proposal"));
    let put = |t: &TestApi, body: &serde_json::Value| {
        let put = t.put("/v1/agents/mail/grants", &body.to_string());
        assert_eq!(put.status, 200, "body: {}", put.body);
        put.json()["approval_id"].as_str().unwrap().to_string()
    };
    let (old_id, new_id) = (put(&t, &older), put(&t, &newer));
    let allow = r#"{"decision":"allow_once"}"#;
    let answer = t.post(&format!("/v1/approvals/{new_id}"), allow);
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    assert_eq!(t.get("/v1/agents/mail/grants").json(), newer);

    let answer = t.post(&format!("/v1/approvals/{old_id}"), allow);
    assert_eq!(answer.status, 409, "body: {}", answer.body);
    assert!(answer.body.contains("grants_changed"), "{}", answer.body);
    assert_eq!(t.get("/v1/agents/mail/grants").json(), newer);
    for kind in ["approval.resolved", "approval.updated"] {
        let frame = wait_ws(&mut ws, Duration::from_secs(5), |value| {
            value["type"] == kind && value["id"] == old_id.as_str()
        })
        .await
        .unwrap_or_else(|| panic!("{kind} must stream"));
        assert_eq!(frame["state"]["state"], "denied", "{frame}");
    }
    t.stop();
}

/// #6: a grants change applies only through the approval it created.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grants_change_requires_its_own_approved_approval() {
    let provider = Arc::new(FakeProvider::scripted("fakey", vec![]));
    let mut t = TestApi::start(options(provider)).await;

    let before = t.get("/v1/agents/mail/grants").json();
    let proposed = json!({
        "see": [],
        "do": [{"skill": "mail.send", "level": "auto"}],
        "never": [],
        "egress_note": "changed by the owner"
    });
    let put = t.put("/v1/agents/mail/grants", &proposed.to_string());
    assert_eq!(put.status, 200, "body: {}", put.body);
    let body = put.json();
    assert_eq!(body["state"], "pending");
    let id = body["approval_id"].as_str().unwrap().to_string();
    assert!(body["hash"].as_str().is_some_and(|hash| !hash.is_empty()));

    // The card is built by the shared builder: a human title, the fields of
    // the proposal, and an edit payload that is valid JSON.
    let cards = t.get("/v1/approvals?state=pending").json();
    let card = &cards[0];
    assert_eq!(card["headline"], "Agent grants", "{card}");
    assert!(
        card["preview"]
            .as_str()
            .unwrap_or_default()
            .contains("agent: mail"),
        "{card}"
    );
    let edit: serde_json::Value =
        serde_json::from_str(card["edit_preview"].as_str().unwrap()).expect("valid JSON");
    assert_eq!(edit["agent"], "mail", "{card}");

    // Nothing is written until the owner approves this exact id.
    assert_eq!(
        t.get("/v1/agents/mail/grants").json()["egress_note"],
        before["egress_note"],
        "the PUT must not write before approval"
    );

    let answered = t.post(
        &format!("/v1/approvals/{id}"),
        &json!({ "decision": "allow_once" }).to_string(),
    );
    assert_eq!(answered.status, 200, "body: {}", answered.body);
    assert_eq!(
        t.get("/v1/agents/mail/grants").json()["egress_note"],
        "changed by the owner"
    );

    // Replay is refused: the change applies once.
    let replay = t.post(
        &format!("/v1/approvals/{id}"),
        &json!({ "decision": "allow_once" }).to_string(),
    );
    assert_eq!(replay.status, 404, "body: {}", replay.body);

    // `allow_always` is refused for a one-shot grants change.
    let second = t.put(
        "/v1/agents/mail/grants",
        &json!({"see":[],"do":[],"never":[],"egress_note":"again"}).to_string(),
    );
    let second_id = second.json()["approval_id"].as_str().unwrap().to_string();
    let always = t.post(
        &format!("/v1/approvals/{second_id}"),
        &json!({ "decision": "allow_always" }).to_string(),
    );
    assert_eq!(always.status, 400, "body: {}", always.body);
    assert_eq!(
        t.get("/v1/agents/mail/grants").json()["egress_note"],
        "changed by the owner",
        "a refused decision must not apply the proposal"
    );

    t.stop();
}

/// #P2 (round 2): a connector tool that does not name a known scope is denied
/// because it is not a builtin, whatever its name looks like.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connector_tool_with_an_unknown_name_is_refused() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("notion_export_records", json!({})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "notion_export_records",
            "notion data",
            Arc::clone(&flag),
        )));
        // Read-only, so an unfixed build would run it: only the origin deny
        // rule stops it.
        registry.mark_read_only("notion_export_records");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;
    let sent = t.post(
        "/v1/threads/mail/messages",
        &json!({ "content": "export" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !ran.load(Ordering::SeqCst),
        "a non-builtin tool with no resolvable scope must be denied"
    );
    t.stop();
}

/// #P2 (round 2): a hyphenated `google-export` is not matched by the `google_`
/// prefix, so the registered origin must deny it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connector_tool_named_google_export_is_refused() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("google-export", json!({})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "google-export",
            "google data",
            Arc::clone(&flag),
        )));
        registry.mark_read_only("google-export");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        ..options(provider)
    })
    .await;
    let sent = t.post(
        "/v1/threads/mail/messages",
        &json!({ "content": "export" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !ran.load(Ordering::SeqCst),
        "a name the scope table does not match must still be denied"
    );
    t.stop();
}

/// #P2 (round 2): a builtin tool is untouched by the origin check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_builtin_tool_still_runs() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("read_file", json!({"path":"note.txt"})),
            ChatResponse::assistant("done"),
        ],
    ));
    let mut t = TestApi::start(options(provider)).await;
    let home = t._dir.path().join("home");
    let workspace = aux_engine::workspace_dir(&home, "mail");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("note.txt"), "builtin works").unwrap();

    let sent = t.post(
        "/v1/threads/mail/messages",
        &json!({ "content": "read it" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    let messages = t.get("/v1/threads/mail/messages").body;
    assert!(
        messages.contains("builtin works"),
        "a builtin tool must still run: {messages}"
    );
    t.stop();
}

/// CHIEF-BASE-1: what the chief is denied, an agent is denied too, at run
/// time and when the agent is created, whatever the agent's own rules say.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chief_deny_caps_every_agent_at_run_time_and_creation() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("read_file", json!({"path":"note.txt"})),
            ChatResponse::assistant("done"),
        ],
    ));
    let config = CONFIG.replace("default_agent = \"aux\"", "default_agent = \"main\"")
        + "\n[[rules]]\nagent = \"main\"\ntool = \"read_file\"\naction = \"deny\"\n";
    let mut t = TestApi::start_with(options(provider), &config).await;
    let workspace = aux_engine::workspace_dir(&t.home, "mail");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("note.txt"), "builtin works").unwrap();
    let sent = t.post("/v1/threads/mail/messages", r#"{"content":"read it"}"#);
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    let messages = t.get("/v1/threads/mail/messages").body;
    assert!(!messages.contains("builtin works"), "{messages}");
    assert!(messages.contains("denied"), "{messages}");

    let scout = json!({"name": "scout", "tools": ["read_file"]});
    let created = t.post("/v1/agents", &scout.to_string());
    assert_eq!(created.status, 409, "body: {}", created.body);
    assert!(
        created.body.contains("grant_exceeds_chief"),
        "{}",
        created.body
    );
    assert!(!t.home.join("agents/scout").exists());
    t.stop();
}

/// ACT-FREE still binds the chief: with every access and `approvals = auto`,
/// a send still waits for a card and runs nothing before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chief_send_still_creates_a_card_in_auto_mode() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("mail_send", json!({"to": "nobody@example.test"})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        let tool = TestTool::simple("mail_send", "sent", Arc::clone(&flag));
        registry.register_native(Box::new(tool));
    });
    let config = CONFIG
        .replace("default_agent = \"aux\"", "default_agent = \"main\"")
        .replace("approvals = \"ask\"", "approvals = \"auto\"");
    let options = ApiOptions {
        tools: Some(tools),
        ..options(provider)
    };
    let mut t = TestApi::start_with(options, &config).await;
    let (addr, token) = (t.addr, t.token.clone());
    let mut send = tokio::task::spawn_blocking(move || {
        let body = json!({"content": "send it"}).to_string();
        post(addr, "/v1/threads/main/messages", Some(&token), &body)
    });
    let pending = tokio::select! {
        pending = wait_for_pending(&t, Duration::from_secs(10)) => pending,
        sent = &mut send => panic!("the turn ended before a card: {:?}", sent.unwrap().status),
    };
    assert_eq!(pending["scope_tool"], "mail_send");
    assert!(!ran.load(Ordering::SeqCst));
    let id = pending["id"].as_str().unwrap();
    let denied = t.post(&format!("/v1/approvals/{id}"), r#"{"decision":"deny"}"#);
    assert_eq!(denied.status, 200, "body: {}", denied.body);
    let _ = tokio::time::timeout(Duration::from_secs(10), send).await;
    assert!(!ran.load(Ordering::SeqCst));
    t.stop();
}

/// #P2 (round 3): an `Unknown`-origin tool is refused for Mail even when its
/// name resolves to the granted `mail` scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_origin_tool_named_mail_read_is_refused_for_mail() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("mail_read", json!({"account":"personal","uid":1})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "mail_read",
            "PRIVATE-MAIL-BODY",
            Arc::clone(&flag),
        )));
        registry.mark_read_only("mail_read");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        tool_origins: vec![(
            "mail_read".to_string(),
            aux_runtime::grants::ToolOrigin::Unknown,
        )],
        ..options(provider)
    })
    .await;
    let sent = t.post(
        "/v1/threads/mail/messages",
        &json!({ "content": "read" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !ran.load(Ordering::SeqCst),
        "an Unknown-origin tool must be denied for Mail even when its name resolves to a granted scope"
    );
    t.stop();
}

/// #P2 (round 4): an Unknown-origin tool is denied for the chief too, even
/// when the chief holds the matching Auto grant; the builtin `delegate` keeps
/// working (the hero test above).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_origin_tool_is_refused_for_the_chief_even_with_a_grant() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call("mail_read", json!({"account":"personal","uid":1})),
            ChatResponse::assistant("done"),
        ],
    ));
    let ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "mail_read",
            "PRIVATE-MAIL-BODY",
            Arc::clone(&flag),
        )));
        registry.mark_read_only("mail_read");
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        tool_origins: vec![(
            "mail_read".to_string(),
            aux_runtime::grants::ToolOrigin::Unknown,
        )],
        ..options(provider)
    })
    .await;
    // The chief holds an Auto `mail.read` grant, so only the origin rule can
    // stop the call.
    let home = t._dir.path().join("home");
    let mut grants = aux_runtime::grants::default_grants("aux").unwrap();
    grants.can_do.push(aux_runtime::grants::DoGrant {
        skill: "mail.read".to_string(),
        level: aux_runtime::grants::ActionLevel::Auto,
    });
    auxd::agents::write_grants(&home, "aux", &grants).unwrap();

    let sent = t.post(
        "/v1/threads/aux/messages",
        &json!({ "content": "read my mail" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !ran.load(Ordering::SeqCst),
        "an Unknown-origin tool must be denied for the chief even with a grant"
    );
    t.stop();
}

/// #P2 (round 5): a hook tool named `delegate` does not stale the builtin
/// origin. The builtin `DelegateTool` replaces it and must take the Builtin
/// origin, so the chief can still delegate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hook_delegate_does_not_stale_the_builtin_origin() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            tool_call(
                "delegate",
                json!({"agent":"mail","task":"summarise the thread"}),
            ),
            ChatResponse::assistant("done"),
        ],
    ));
    let hook_ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&hook_ran);
    let tools: ToolRegistryHook = Arc::new(move |registry| {
        registry.register_native(Box::new(TestTool::simple(
            "delegate",
            "a shadow",
            Arc::clone(&flag),
        )));
    });
    let executor: Arc<dyn DelegationExecutor> = Arc::new(ScriptedMail {
        raw: RAW_MAIL.to_string(),
    });
    let mut t = TestApi::start(ApiOptions {
        tools: Some(tools),
        delegations: Some(executor),
        ..options(provider)
    })
    .await;
    let sent = t.post(
        "/v1/threads/aux/messages",
        &json!({ "content": "ask Mail" }).to_string(),
    );
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert!(
        !hook_ran.load(Ordering::SeqCst),
        "the builtin delegate must replace the hook tool"
    );
    let list = t.get("/v1/delegations?thread=aux");
    assert_eq!(list.status, 200, "body: {}", list.body);
    assert_eq!(
        list.json()[0]["state"],
        "done",
        "the builtin delegate must still work: {}",
        list.body
    );
    t.stop();
}
