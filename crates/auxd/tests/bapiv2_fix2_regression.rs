//! B-API v2 residual-fix regressions (carry list from the reverify #2 CLEAR
//! verdict, 2026-10-04).
//!
//! Covered findings:
//! - **RV2-01**: a stalled `allow_always` rule write past the 500 ms grace
//!   must not answer `200 allowed` after the turn was denied; the expired
//!   resolution must precede `tool.end`/`message.done`.
//! - **RV2-02**: `GET /v1/threads/{id}/messages` (and the POST result) scrubs
//!   tool-role content exactly like the live `message.new`; the store row
//!   stays raw.
//! - **RV2-03**: a degraded audit still emits a numeric `audit_id` (0 = not
//!   recorded) so the app's required `u64` frame keeps decoding.
//! - **RV2-05**: the legacy `job <name>` title heuristic only applies to
//!   sessions at or below the v8 watermark.
//! - **RV2-06**: a stalled rule write (fsync under the process-wide lock)
//!   never pins a tokio worker; the API keeps serving.
//!
//! Everything is in-process: ephemeral 127.0.0.1 port, temp home, fake
//! providers, no network, no Keychain, no real `~/.auxesis`.

mod common;

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A fixed 64-hex-char API token shared by every test API in this binary.
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, FakeProvider, ProviderError,
    ToolCall as ProviderToolCall,
};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use kernel_core::{config_path, store_path};

use common::{http, HttpResponse};

const FAKE_CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "main"
approvals = "ask"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;

const SECRET: &str = "sk-live-SECRET0123456789";

// ---------------------------------------------------------------------------
// app wire contract (copied from the app's model.rs/protocol.rs)
// ---------------------------------------------------------------------------

mod app_wire {
    use serde::Deserialize;

    /// `model.rs::Approval` — `audit_id` is a required `u64` (RV2-03).
    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    pub struct Approval {
        pub id: String,
        pub audit_id: u64,
        pub agent: String,
        pub thread_id: String,
        pub ts: i64,
        pub action: String,
        pub headline: String,
        #[serde(default)]
        pub scope_tool: String,
        #[serde(default)]
        pub scope_rule: String,
        #[serde(default)]
        pub state: ApprovalState,
    }

    #[derive(Debug, PartialEq, Default, Deserialize)]
    #[serde(tag = "state", rename_all = "snake_case")]
    pub enum ApprovalState {
        #[default]
        Pending,
        Allowed {
            by: String,
            always: bool,
        },
        Denied {
            by: String,
        },
        Expired,
    }
}

// ---------------------------------------------------------------------------
// sandbox
// ---------------------------------------------------------------------------

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start_with(provider: Option<Arc<dyn ChatProvider>>, timeout: Duration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        // One fixed token for every test: the daemon registers it with the
        // exact-value scrubber, and a fresh random token per test would make
        // the process-global registry accumulate one encoding closure per test.
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
        let handle = api::spawn(
            &home,
            ApiOptions {
                port: 0,
                event_poll: Duration::from_millis(25),
                provider,
                approval_timeout: Some(timeout),
                ..ApiOptions::default()
            },
        )
        .unwrap();
        let addr = handle.addr();
        let token = std::fs::read_to_string(api::token_path(&home))
            .unwrap()
            .trim()
            .to_string();
        Self {
            _dir: dir,
            home,
            addr,
            token,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }

    fn store(&self) -> Store {
        Store::open(&store_path(&self.home)).unwrap()
    }

    fn rules_or_error(&self) -> Result<Vec<kernel_broker::Rule>, String> {
        aux_engine::load_rules(&kernel_core::config_path(&self.home)).map_err(|err| err.to_string())
    }
}

/// Scripted provider whose one tool call is **effectful** (`write_file`), so
/// with no matching rule it still asks (H-02 leaves that protection intact).
fn ask_provider() -> Arc<dyn ChatProvider> {
    Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "write_file",
                    serde_json::json!({ "path": "out.txt", "content": "written" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ))
}

/// Sleeps before its first response (so the store can be made unreadable at a
/// controlled moment), then answers "done".
struct DelayedToolProvider {
    delay: Duration,
    calls: AtomicUsize,
    path: String,
}

#[async_trait]
impl ChatProvider for DelayedToolProvider {
    async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            tokio::time::sleep(self.delay).await;
            Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "write_file",
                    serde_json::json!({ "path": self.path, "content": "written" }),
                )],
            )))
        } else {
            Ok(ChatResponse::assistant("done"))
        }
    }

    fn name(&self) -> &str {
        "delayed-tool"
    }
}

// ---------------------------------------------------------------------------
// HTTP / WS helpers
// ---------------------------------------------------------------------------

async fn call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> HttpResponse {
    let method = method.to_string();
    let path = path.to_string();
    let token = token.map(str::to_string);
    let body = body.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        http(addr, &method, &path, token.as_deref(), body.as_deref())
    })
    .await
    .unwrap()
}

async fn get_auth(t: &TestApi, path: &str) -> HttpResponse {
    call(t.addr, "GET", path, Some(&t.token), None).await
}

async fn post_auth(t: &TestApi, path: &str, body: &str) -> HttpResponse {
    call(t.addr, "POST", path, Some(&t.token), Some(body)).await
}

fn send_async(
    t: &TestApi,
    path: &'static str,
    content: &'static str,
) -> tokio::task::JoinHandle<HttpResponse> {
    let addr = t.addr;
    let token = t.token.clone();
    tokio::spawn(async move { call(addr, "POST", path, Some(&token), Some(content)).await })
}

fn messages_with_role(response: &HttpResponse, role: &str) -> Vec<String> {
    response.json()["messages"]
        .as_array()
        .map(|messages| {
            messages
                .iter()
                .filter(|m| m["role"] == role)
                .map(|m| m["content"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Typed pending wait (requires the app `Approval` to decode).
async fn wait_for_pending(t: &TestApi, timeout: Duration) -> Vec<app_wire::Approval> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let response = get_auth(t, "/v1/approvals?state=pending").await;
        assert_eq!(response.status, 200, "body: {}", response.body);
        let approvals: Vec<app_wire::Approval> = serde_json::from_value(response.json()).unwrap();
        if !approvals.is_empty() {
            return approvals;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no pending approval appeared within {timeout:?}");
}

/// Blocking pending wait (the plain-`#[test]` sandbox has no tokio runtime of
/// its own to await on).
fn wait_for_pending_blocking(t: &TestApi, timeout: Duration) -> Vec<app_wire::Approval> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let response = http(
            t.addr,
            "GET",
            "/v1/approvals?state=pending",
            Some(&t.token),
            None,
        );
        assert_eq!(response.status, 200, "body: {}", response.body);
        let approvals: Vec<app_wire::Approval> = serde_json::from_value(response.json()).unwrap();
        if !approvals.is_empty() {
            return approvals;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no pending approval appeared within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(addr: SocketAddr, token: &str) -> Ws {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{addr}/v1/events")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    tokio_tungstenite::connect_async(request).await.unwrap().0
}

async fn drain_ws(ws: &mut Ws, window: Duration) -> Vec<serde_json::Value> {
    use futures_util::StreamExt;
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) => {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                    frames.push(value);
                }
            }
            Ok(Some(Ok(_))) => {}
            Ok(None) | Ok(Some(Err(_))) => break,
            Err(_) => break,
        }
    }
    frames
}

fn index_of(frames: &[serde_json::Value], kind: &str) -> Option<usize> {
    frames
        .iter()
        .position(|value| value["type"].as_str() == Some(kind))
}

fn audit_payloads(home: &std::path::Path, kind: &str) -> Vec<serde_json::Value> {
    let conn = aux_store::open_keyed_readonly(&store_path(home)).unwrap();
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE kind = ?1 ORDER BY id ASC")
        .unwrap();
    let rows = stmt
        .query_map([kind], |row| row.get::<_, String>(0))
        .unwrap();
    rows.filter_map(|row| {
        row.ok()
            .and_then(|payload| serde_json::from_str::<serde_json::Value>(&payload).ok())
    })
    .collect()
}

// ---------------------------------------------------------------------------
// FIFO stall (deterministic hold of the process-wide append-rule lock)
// ---------------------------------------------------------------------------

/// Writing to a FIFO blocks until a reader opens it; the holder thread is that
/// reader.
fn fifo_write(path: &std::path::Path) {
    if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) {
        let _ = file.write_all(b"version = 1\nprivacy.mode = \"open\"\n");
    }
}

fn make_fifo(dir: &std::path::Path) -> PathBuf {
    let fifo = dir.join("stall.toml");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    fifo
}

// ===========================================================================
// RV2-01 — the grace-window late answer tells the truth
// ===========================================================================

/// An `allow_always` answer that claims just before the approval deadline but
/// whose rule write is stalled past the 500 ms grace must not answer
/// `200 {"allowed"}` after the turn was denied, and the expired resolution
/// must precede `tool.end`/`message.done`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_grace_window_answer_reports_expired_and_stays_ordered() {
    let fifo_dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(fifo_dir.path());
    {
        let wd = fifo.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(8));
            fifo_write(&wd);
            std::thread::sleep(Duration::from_millis(200));
            fifo_write(&wd);
        });
    }

    // Hold the process-wide append lock: append_rule(fifo) blocks in
    // read_to_string until a writer appears.
    let holder_fifo = fifo.clone();
    let holder = std::thread::spawn(move || {
        aux_engine::append_rule(
            &holder_fifo,
            &kernel_broker::Rule::new("main", "read_file", kernel_broker::Action::Allow),
        )
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut t = TestApi::start_with(Some(ask_provider()), Duration::from_millis(1000)).await;
    let mut ws = ws_connect(t.addr, &t.token).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"write"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let id = pending[0].id.clone();

    // The answer claims immediately, then blocks on the stalled rule write.
    let answer = {
        let addr = t.addr;
        let token = t.token.clone();
        tokio::spawn(async move {
            call(
                addr,
                "POST",
                &format!("/v1/approvals/{id}"),
                Some(&token),
                Some(r#"{"decision":"allow_always","scope":{"tool":"write_file"}}"#),
            )
            .await
        })
    };

    let turn = tokio::time::timeout(Duration::from_secs(6), send).await;
    // Release the stall (first write: the initial read; second: the backup copy).
    let fifo2 = fifo.clone();
    tokio::task::spawn_blocking(move || {
        fifo_write(&fifo2);
        std::thread::sleep(Duration::from_millis(300));
        fifo_write(&fifo2);
    })
    .await
    .unwrap();

    let response = turn
        .expect("timed-out turn never finished even after the stall released")
        .unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert!(
        messages_with_role(&response, "tool")
            .iter()
            .any(|content| content.contains("denied")),
        "the tool must be denied when the rule write missed the grace: {:?}",
        messages_with_role(&response, "tool")
    );

    let answer = answer.await.unwrap();
    let holder = holder.join().unwrap();
    assert!(holder.is_ok(), "holder append failed: {holder:?}");

    // The late answer reports the real outcome, never `allowed`.
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    assert_eq!(
        answer.json()["state"],
        serde_json::json!({ "state": "expired" }),
        "the answer claimed allowed for a call the daemon denied"
    );

    let frames = drain_ws(&mut ws, Duration::from_millis(1500)).await;
    let kinds: Vec<&str> = frames
        .iter()
        .map(|frame| frame["type"].as_str().unwrap())
        .collect();
    let resolved = index_of(&frames, "approval.resolved").expect("approval.resolved");
    let done = index_of(&frames, "message.done").expect("message.done");
    assert_eq!(
        frames[resolved]["state"],
        serde_json::json!({ "state": "expired" }),
        "the only resolution frame must be the fail-closed timeout: {kinds:?}"
    );
    assert!(
        resolved < done,
        "approval.resolved ({resolved}) trails message.done ({done}): {kinds:?}"
    );
    assert!(
        !frames.iter().any(|frame| {
            frame["type"] == "approval.resolved"
                && frame["state"]["state"].as_str() == Some("allowed")
        }),
        "a late answer broadcast `allowed` after the deny: {kinds:?}"
    );

    // The rule itself was persisted by the stalled write; the audit records
    // the late answer honestly instead of pretending it was applied in time.
    assert_eq!(
        t.rules_or_error().map(|rules| rules.len()),
        Ok(1),
        "the stalled rule write should still have persisted its rule"
    );
    let answered = audit_payloads(&t.home, "approval.answered");
    assert!(
        answered
            .iter()
            .any(|row| row["decision"] == "late_after_timeout" && row["always"] == true),
        "no late-answer audit row: {answered:?}"
    );
    assert!(
        answered
            .iter()
            .any(|row| row["decision"] == "timeout" && row["late_claim"] == true),
        "the grace-expiry timeout row is not marked: {answered:?}"
    );
    t.stop();
}

// ===========================================================================
// RV2-02 — REST history scrubs tool-role content like the live frame
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_reload_scrubs_tool_results_like_the_live_frame() {
    // H-02: `read_file` is read-only, so this read runs without an approval
    // card (no pending ask is expected); the scrubbing contract is unchanged.
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "read_file",
                    serde_json::json!({ "path": "note.txt" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ));
    let mut t = TestApi::start_with(Some(provider), Duration::from_secs(10)).await;
    let workspace = t.home.join("agents").join("main").join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(
        workspace.join("note.txt"),
        format!("top secret: {SECRET}\n"),
    )
    .unwrap();

    let mut ws = ws_connect(t.addr, &t.token).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"read"}"#);
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    // The read-only default allowed the call without a card.
    assert!(
        get_auth(&t, "/v1/approvals?state=pending")
            .await
            .json()
            .as_array()
            .unwrap()
            .is_empty(),
        "a read-only tool must not raise an approval card"
    );
    let thread_id = response.json()["thread"]["id"].as_i64().unwrap();

    // The live frame is scrubbed (pre-existing behaviour, kept as a guard).
    // UMF-05: a tool-role message carries its own `tool` author kind.
    let frames = drain_ws(&mut ws, Duration::from_millis(1200)).await;
    let live_tool = frames
        .iter()
        .filter(|f| f["type"] == "message.new")
        .find(|f| f["message"]["author"]["kind"] == "tool")
        .and_then(|f| f["message"]["blocks"][0]["text"].as_str())
        .expect("tool-role message.new");
    assert!(!live_tool.contains(SECRET), "{live_tool}");

    // The POST result already hides it…
    let post_tool = messages_with_role(&response, "tool");
    assert!(
        !post_tool.iter().any(|content| content.contains(SECRET)),
        "the POST result leaked the tool result: {post_tool:?}"
    );

    // …and the reload path must agree (RV2-02).
    let page = get_auth(&t, &format!("/v1/threads/{thread_id}/messages")).await;
    assert_eq!(page.status, 200, "body: {}", page.body);
    let tool = messages_with_role(&page, "tool");
    assert!(
        !tool.iter().any(|content| content.contains(SECRET)),
        "GET /v1/threads/{{id}}/messages returned the raw tool result: {tool:?}"
    );
    assert!(
        tool.iter().any(|content| content.contains("<redacted>")),
        "the reloaded tool result is not the live scrub: {tool:?}"
    );

    // The persisted row stays raw: the model's resume history needs it.
    let stored = t
        .store()
        .list_messages(thread_id)
        .unwrap()
        .into_iter()
        .find(|message| message.role == "tool")
        .expect("a persisted tool row");
    assert!(
        stored.content.contains(SECRET),
        "the store row must not be redacted: {}",
        stored.content
    );
    t.stop();
}

// ===========================================================================
// RV2-03 — the degraded audit keeps the app's required numeric `audit_id`
// ===========================================================================

/// Budget for one step of the degraded-audit test on a saturated CI runner.
/// The happy path is about 1.3 s (the provider's own delay); 5 s produced
/// "no pending appeared" on #227, #228 and #235 while other jobs shared the
/// runner, and passed on every rerun (LEDGER "CI flake").
const LOADED_RUNNER_WAIT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn degraded_audit_still_emits_a_numeric_audit_id() {
    let provider = Arc::new(DelayedToolProvider {
        delay: Duration::from_millis(1200),
        calls: AtomicUsize::new(0),
        path: "note.txt".to_string(),
    });
    let mut t = TestApi::start_with(
        Some(Arc::clone(&provider) as Arc<dyn ChatProvider>),
        Duration::from_secs(10),
    )
    .await;
    let mut ws = ws_connect(t.addr, &t.token).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"read"}"#);

    // Wait until the runner has opened the store and is inside the provider's
    // delayed first call, then make the store unreadable: the audit write in
    // the approver fails, the turn's own connection stays valid. A fixed sleep
    // here raced the runner on a loaded CI host.
    let deadline = tokio::time::Instant::now() + LOADED_RUNNER_WAIT;
    while provider.calls.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the provider was never called"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let store_file = store_path(&t.home);
    std::fs::set_permissions(&store_file, std::fs::Permissions::from_mode(0o000)).unwrap();

    let pending = {
        let deadline = tokio::time::Instant::now() + LOADED_RUNNER_WAIT;
        loop {
            let response = get_auth(&t, "/v1/approvals?state=pending").await;
            let approvals = response.json();
            if approvals.as_array().is_some_and(|a| !a.is_empty()) {
                break approvals.as_array().unwrap()[0].clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no pending appeared"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };

    // The honest sentinel: a numeric 0, never an omission (the app's
    // `Approval.audit_id` is a required `u64`).
    assert_eq!(
        pending["audit_id"], 0,
        "degraded frame must carry the numeric sentinel: {pending}"
    );
    let decoded: app_wire::Approval = serde_json::from_value(pending.clone())
        .unwrap_or_else(|err| panic!("app `Approval` rejected the frame: {err}: {pending}"));
    assert_eq!(decoded.audit_id, 0);

    let frames = drain_ws(&mut ws, Duration::from_millis(600)).await;
    let approval_new = frames
        .iter()
        .find(|frame| frame["type"] == "approval.new")
        .expect("approval.new frame");
    assert_eq!(
        approval_new["approval"]["audit_id"], 0,
        "the live degraded frame must match the REST shape: {approval_new}"
    );
    serde_json::from_value::<app_wire::Approval>(approval_new["approval"].clone())
        .unwrap_or_else(|err| panic!("app `Approval` rejected the live frame: {err}"));

    // Finish the turn and restore permissions.
    let _ = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending["id"].as_str().unwrap()),
        r#"{"decision":"deny"}"#,
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), send).await;
    std::fs::set_permissions(&store_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    t.stop();
}

// ===========================================================================
// RV2-05 — the legacy title heuristic stops at the v8 watermark
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chat_titled_like_a_job_stays_the_agent_thread() {
    let mut t = TestApi::start_with(
        Some(Arc::new(FakeProvider::echo("fakey"))),
        Duration::from_secs(10),
    )
    .await;

    let store = t.store();
    store
        .create_job(
            "main",
            "morning",
            "every 15m",
            r#"{"kind":"agent","prompt":"x"}"#,
            None,
        )
        .unwrap();
    // A genuine post-v8 chat whose first message happens to be `job morning`.
    let chat = store.create_session("main", Some("job morning")).unwrap();
    store
        .append_message(chat.id, "system", "You are main", None)
        .unwrap();
    store
        .append_message(chat.id, "user", "job morning", None)
        .unwrap();
    store
        .append_message(chat.id, "assistant", "good morning to you", None)
        .unwrap();
    drop(store);

    let agents = get_auth(&t, "/v1/agents").await.json();
    let main = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "main")
        .unwrap();
    assert_eq!(
        main["thread_id"],
        chat.id.to_string(),
        "a chat session titled like an existing job is hidden from the agent thread"
    );

    let page = get_auth(&t, "/v1/threads/main/messages").await.json();
    assert_eq!(page["thread"]["id"], chat.id);

    // The next send appends to the same conversation instead of forking.
    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"next"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert_eq!(sent.json()["thread"]["id"], chat.id);
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_legacy_job_titled_session_is_still_hidden() {
    let mut t = TestApi::start_with(
        Some(Arc::new(FakeProvider::echo("fakey"))),
        Duration::from_secs(10),
    )
    .await;
    let home = t.home.clone();

    // Simulate a pre-v8 row: it exists at the watermark, so the legacy title
    // heuristic still protects the thread from it.
    let legacy_id = {
        let conn = aux_store::open_keyed(&store_path(&home)).unwrap();
        conn.execute(
            "INSERT INTO sessions(agent, title, kind) VALUES ('main', 'job morning', 'chat')",
            [],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO messages(session_id, role, content) VALUES (?1, 'user', 'job prompt')",
            [id],
        )
        .unwrap();
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'sessions_kind_legacy_max_id'",
            [id.to_string()],
        )
        .unwrap();
        id
    };
    let store = t.store();
    store
        .create_job(
            "main",
            "morning",
            "every 15m",
            r#"{"kind":"agent","prompt":"x"}"#,
            None,
        )
        .unwrap();
    drop(store);

    let agents = get_auth(&t, "/v1/agents").await.json();
    let main = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "main")
        .unwrap();
    assert!(
        main["thread_id"].is_null(),
        "a legacy job transcript became the agent thread: {main}"
    );

    // A new chat is a new session and is not touched by the heuristic.
    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hello"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    let chat_id = sent.json()["thread"]["id"].as_i64().unwrap();
    assert_ne!(chat_id, legacy_id);
    assert_eq!(t.store().list_messages(legacy_id).unwrap().len(), 1);

    let agents = get_auth(&t, "/v1/agents").await.json();
    let main = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "main")
        .unwrap();
    assert_eq!(main["thread_id"], chat_id.to_string());
    t.stop();
}

// ===========================================================================
// RV2-06 — the stalled fsync never pins a tokio worker
// ===========================================================================

/// A one-worker runtime turns "the rule write runs on the async runtime" into
/// a deterministic observation: pre-fix the stalled `append_rule` owns the
/// only worker, so `/v1/health` cannot be served; post-fix (spawn_blocking)
/// the API stays responsive while the rule write waits on the lock.
#[test]
fn a_stalled_rule_write_does_not_pin_the_api_runtime() {
    let fifo_dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(fifo_dir.path());
    {
        let wd = fifo.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(10));
            fifo_write(&wd);
            std::thread::sleep(Duration::from_millis(200));
            fifo_write(&wd);
        });
    }

    let holder_fifo = fifo.clone();
    let holder = std::thread::spawn(move || {
        aux_engine::append_rule(
            &holder_fifo,
            &kernel_broker::Rule::new("main", "read_file", kernel_broker::Action::Allow),
        )
    });
    std::thread::sleep(Duration::from_millis(150));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let mut t = runtime.block_on(TestApi::start_with(
        Some(ask_provider()),
        Duration::from_secs(20),
    ));

    // One turn reaches its pending ask.
    let turn = {
        let addr = t.addr;
        let token = t.token.clone();
        std::thread::spawn(move || {
            http(
                addr,
                "POST",
                "/v1/threads/main/messages",
                Some(&token),
                Some(r#"{"content":"read"}"#),
            )
        })
    };
    let pending = wait_for_pending_blocking(&t, Duration::from_secs(5));

    // Answer allow_always: it claims, then blocks on the process-wide lock.
    let answer = {
        let addr = t.addr;
        let token = t.token.clone();
        let id = pending[0].id.clone();
        std::thread::spawn(move || {
            http(
                addr,
                "POST",
                &format!("/v1/approvals/{id}"),
                Some(&token),
                Some(r#"{"decision":"allow_always","scope":{"tool":"write_file"}}"#),
            )
        })
    };
    std::thread::sleep(Duration::from_millis(400));

    // While the rule write is stalled, the API must keep serving.
    let health = health_with_timeout(t.addr, &t.token, Duration::from_millis(1200));

    // Release the stall and let everything finish.
    fifo_write(&fifo);
    std::thread::sleep(Duration::from_millis(200));
    fifo_write(&fifo);
    let holder = holder.join().unwrap();
    let turn = turn.join().unwrap();
    let answer = answer.join().unwrap();
    t.stop();
    drop(runtime);

    assert!(holder.is_ok(), "holder append failed: {holder:?}");
    assert_eq!(turn.status, 200, "body: {}", turn.body);
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    assert_eq!(
        health,
        Some(200),
        "the API runtime was pinned by the stalled rule write \
         (spawn_blocking must keep the worker free)"
    );
}

/// A minimal blocking GET with a short read timeout; `None` on any timeout.
fn health_with_timeout(addr: SocketAddr, token: &str, timeout: Duration) -> Option<u16> {
    use std::io::Read;
    let mut stream = std::net::TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let request = format!(
        "GET /v1/health HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
}
