//! Regression tests for the v2 API.
//!
//! The file uses only stable public APIs, so it also compiles against an
//! archive of the previous commit.
//!
//! Everything runs in-process on ephemeral loopback ports with temp homes and
//! the fake provider: no network, no Keychain, no real `~/.auxesis`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A fixed 64-hex-char API token shared by every test API in this binary.
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, FakeProvider, ProviderError,
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

    fn config_text(&self) -> String {
        std::fs::read_to_string(config_path(&self.home)).unwrap_or_default()
    }

    fn rules_or_error(&self) -> Result<Vec<kernel_broker::Rule>, String> {
        aux_engine::load_rules(&config_path(&self.home)).map_err(|err| err.to_string())
    }
}

/// Scripted provider whose one tool call is **effectful** (`write_file`), so
/// with no matching rule it still asks (H-02 leaves that protection intact).
async fn ask_provider() -> Arc<FakeProvider> {
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

/// The app's `Approval` shape, copied from `protocol.rs`/`model.rs`.
#[derive(Debug, serde::Deserialize)]
struct PendingApproval {
    id: String,
    agent: String,
    scope_tool: String,
}

#[derive(Debug, PartialEq, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ApprovalState {
    Pending,
    Allowed { by: String, always: bool },
    Denied { by: String },
    Expired,
}

async fn pending_now(t: &TestApi) -> Vec<PendingApproval> {
    let response = get_auth(t, "/v1/approvals?state=pending").await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    serde_json::from_value(response.json()).unwrap()
}

async fn wait_for_pending(t: &TestApi, timeout: Duration) -> Vec<PendingApproval> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let pending = pending_now(t).await;
        if !pending.is_empty() {
            return pending;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no pending approval appeared within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn state_of(value: &serde_json::Value) -> ApprovalState {
    serde_json::from_value(value["state"].clone()).unwrap()
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

fn user_contents(response: &HttpResponse) -> Vec<String> {
    response.json()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            format!(
                "{}:{}",
                m["role"].as_str().unwrap(),
                m["content"].as_str().unwrap()
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The scope of an allow-always answer is pinned to the pending ask
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allow_always_scope_is_pinned_to_the_pending_ask() {
    // `write_file` is effectful, so with no rule it asks (H-02 keeps this).
    let provider = Arc::new(FakeProvider::scripted(
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
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_2",
                    "shell",
                    serde_json::json!({ "command": "echo attacked" }),
                )],
            )),
            ChatResponse::assistant("ran"),
        ],
    ));
    let mut t = TestApi::start_with(Some(provider), Duration::from_secs(10)).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"write"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending[0].scope_tool, "write_file");
    assert_eq!(pending[0].agent, "main");
    let before = t.config_text();
    let id = pending[0].id.clone();

    // Every widening attempt is a clean 400 with no write and the ask intact.
    let bad = [
        r#"{"decision":"allow_always","scope":{"tool":"*"}}"#,
        r#"{"decision":"allow_always","scope":{"tool":"shell"}}"#,
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"axis"}}"#,
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"*"}}"#,
    ];
    for body in bad {
        let answer = post_auth(&t, &format!("/v1/approvals/{id}"), body).await;
        assert!(
            answer.status == 400,
            "scope {body} must be rejected, got {} {}",
            answer.status,
            answer.body
        );
        assert_eq!(t.config_text(), before, "rejected scope wrote a rule");
        assert_eq!(
            pending_now(&t).await.len(),
            1,
            "ask consumed by a rejected scope"
        );
    }

    // The exact pending scope is accepted and pins tool + agent.
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{id}"),
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"main"}}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    assert_eq!(
        state_of(&answer.json()),
        ApprovalState::Allowed {
            by: "you".to_string(),
            always: true
        }
    );
    let rules = t.rules_or_error().expect("config stays parseable");
    assert_eq!(rules.len(), 1, "exactly the pinned rule: {rules:?}");
    assert_eq!(rules[0].agent, "main");
    assert_eq!(rules[0].tool, "write_file");
    assert_eq!(rules[0].action, kernel_broker::Action::Allow);

    let first = send.await.unwrap();
    assert_eq!(first.status, 200, "body: {}", first.body);

    // A different tool still asks: the rule cannot cover `shell`.
    let second = send_async(
        &t,
        "/v1/threads/main/messages",
        r#"{"content":"now shell"}"#,
    );
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending[0].scope_tool, "shell", "shell must still ask");
    let deny = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"deny"}"#,
    )
    .await;
    assert_eq!(deny.status, 200, "body: {}", deny.body);
    let second = second.await.unwrap();
    assert_eq!(second.status, 200, "body: {}", second.body);
    assert!(
        user_contents(&second).iter().any(|m| m.contains("denied")),
        "the shell call was denied: {:?}",
        user_contents(&second)
    );
    t.stop();
}

// ---------------------------------------------------------------------------
// Concurrent answers — one winner, truthful effects, parseable file
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_allow_always_answers_are_serialized_and_truthful() {
    let mut t = TestApi::start_with(Some(ask_provider().await), Duration::from_secs(10)).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"write"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let id = pending[0].id.clone();

    // Six identical valid allow-always answers, all at once. Pre-fix each
    // handler could append a rule before losing the `resolve` race, so this
    // reproduces lost/duplicated rules; post-fix exactly one claim wins and
    // writes exactly one rule.
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let addr = t.addr;
        let token = t.token.clone();
        let id = id.clone();
        tasks.push(tokio::spawn(async move {
            call(
                addr,
                "POST",
                &format!("/v1/approvals/{id}"),
                Some(&token),
                Some(r#"{"decision":"allow_always","scope":{"tool":"write_file"}}"#),
            )
            .await
        }));
    }

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut always_won = false;
    for task in tasks {
        let response = task.await.unwrap();
        match response.status {
            200 => {
                accepted += 1;
                always_won = matches!(
                    state_of(&response.json()),
                    ApprovalState::Allowed { always: true, .. }
                );
            }
            404 => rejected += 1,
            other => panic!("unexpected status {other}: {}", response.body),
        }
    }
    assert_eq!(accepted, 1, "exactly one answer may win the claim");
    assert_eq!(rejected, 5, "every loser is a clean 404");
    assert!(always_won, "the winner is an allow-always answer");

    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);

    // The file survived and the accepted answer persisted truthfully.
    let rules = t
        .rules_or_error()
        .unwrap_or_else(|err| panic!("concurrent answers left config.toml unparseable: {err}"));
    assert_eq!(
        rules.len(),
        1,
        "the winning allow-always wrote exactly one rule: {rules:?}"
    );
    assert_eq!(rules[0].tool, "write_file");
    assert_eq!(rules[0].agent, "main");
    assert!(pending_now(&t).await.is_empty(), "the ask was consumed");
    t.stop();
}

// ---------------------------------------------------------------------------
// Concurrent first sends share one session
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_first_sends_create_exactly_one_session() {
    let provider = Arc::new(FakeProvider::echo("fakey"));
    let mut t = TestApi::start_with(Some(provider), Duration::from_secs(5)).await;

    let mut sends = Vec::new();
    for index in 0..8 {
        let body = format!(r#"{{"content":"msg-{index}"}}"#);
        let addr = t.addr;
        let token = t.token.clone();
        sends.push(tokio::spawn(async move {
            let body = body;
            call(
                addr,
                "POST",
                "/v1/threads/main/messages",
                Some(&token),
                Some(&body),
            )
            .await
        }));
    }
    let mut thread_ids = Vec::new();
    for send in sends {
        let response = send.await.unwrap();
        assert_eq!(response.status, 200, "body: {}", response.body);
        thread_ids.push(response.json()["thread"]["id"].as_i64().unwrap());
    }
    assert!(
        thread_ids.windows(2).all(|pair| pair[0] == pair[1]),
        "concurrent first sends must share one session, got {thread_ids:?}"
    );

    let sessions = t.store().list_sessions().unwrap();
    assert_eq!(
        sessions.len(),
        1,
        "the agent forked into {} sessions",
        sessions.len()
    );
    let messages = t.store().list_messages(sessions[0].id).unwrap();
    let users = messages.iter().filter(|m| m.role == "user").count();
    assert_eq!(users, 8, "all eight prompts landed in the one session");

    let agents = get_auth(&t, "/v1/agents").await.json();
    let main = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "main")
        .unwrap();
    assert_eq!(
        main["thread_id"],
        thread_ids[0].to_string(),
        "the agent advertises the single session"
    );
    t.stop();
}

// ---------------------------------------------------------------------------
// Concurrent turns on one session serialize and keep their own rows
// ---------------------------------------------------------------------------

/// Provider that records overlap and answers with a marker derived from the
/// last user message (no rendezvous: a serialized turn must never deadlock).
#[derive(Default)]
struct SlowProvider {
    active: AtomicUsize,
    max_active: AtomicUsize,
    requests: Mutex<Vec<Vec<(String, String)>>>,
}

impl SlowProvider {
    fn max_active(&self) -> usize {
        self.max_active.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<Vec<(String, String)>> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl ChatProvider for SlowProvider {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(now, Ordering::SeqCst);
        self.requests.lock().unwrap().push(
            req.messages
                .iter()
                .map(|m| (format!("{:?}", m.role()), m.content().as_str().to_string()))
                .collect(),
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        let last_user = req
            .messages
            .iter()
            .rev()
            .find(|m| m.role() == ChatRole::User)
            .map(|m| m.content().as_str().to_string())
            .unwrap_or_default();
        Ok(ChatResponse::assistant(format!("answer:{last_user}")))
    }

    fn name(&self) -> &str {
        "slow"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_turns_on_one_session_do_not_merge_responses() {
    let provider = Arc::new(SlowProvider::default());
    let mut t = TestApi::start_with(
        Some(Arc::clone(&provider) as Arc<dyn ChatProvider>),
        Duration::from_secs(5),
    )
    .await;

    let warm = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"warm"}"#).await;
    assert_eq!(warm.status, 200, "body: {}", warm.body);
    let thread_id = warm.json()["thread"]["id"].as_i64().unwrap();
    let path = format!("/v1/threads/{thread_id}/messages");

    let first = {
        let addr = t.addr;
        let token = t.token.clone();
        let path = path.clone();
        tokio::spawn(async move {
            call(
                addr,
                "POST",
                &path,
                Some(&token),
                Some(r#"{"content":"alpha"}"#),
            )
            .await
        })
    };
    let second = {
        let addr = t.addr;
        let token = t.token.clone();
        let path = path.clone();
        tokio::spawn(async move {
            call(
                addr,
                "POST",
                &path,
                Some(&token),
                Some(r#"{"content":"beta"}"#),
            )
            .await
        })
    };
    let (first, second) = (first.await.unwrap(), second.await.unwrap());
    assert_eq!(first.status, 200, "body: {}", first.body);
    assert_eq!(second.status, 200, "body: {}", second.body);

    assert_eq!(
        provider.max_active(),
        1,
        "two turns ran on one session at the same time"
    );

    let first_bodies = user_contents(&first);
    let second_bodies = user_contents(&second);
    let has_alpha = |bodies: &[String]| bodies.iter().any(|m| m.contains("alpha"));
    let has_beta = |bodies: &[String]| bodies.iter().any(|m| m.contains("beta"));
    assert!(
        !(has_alpha(&first_bodies) && has_beta(&first_bodies))
            && !(has_alpha(&second_bodies) && has_beta(&second_bodies)),
        "a response mixed both concurrent prompts: {first_bodies:?} / {second_bodies:?}"
    );
    // Each response holds exactly its own two rows.
    assert_eq!(first_bodies.len(), 2, "{first_bodies:?}");
    assert_eq!(second_bodies.len(), 2, "{second_bodies:?}");

    // Context intact: the turn that ran second saw the first turn in full.
    let requests = provider.requests();
    let last = requests.last().expect("the two real turns made requests");
    let joined: Vec<String> = last.iter().map(|(_, content)| content.clone()).collect();
    assert!(
        joined.iter().any(|c| c == "alpha") && joined.iter().any(|c| c == "beta"),
        "the second turn did not see the first turn's prompt: {joined:?}"
    );
    let first_answer = joined
        .iter()
        .find(|c| c.starts_with("answer:alpha") || c.starts_with("answer:beta"))
        .expect("the second turn saw the first turn's answer");
    assert!(
        first_answer.starts_with("answer:"),
        "unexpected answer: {first_answer}"
    );
    t.stop();
}

// ---------------------------------------------------------------------------
// A job transcript never becomes the agent's chat thread
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_job_transcript_never_becomes_the_agent_thread() {
    let provider = Arc::new(FakeProvider::echo("fakey"));
    let mut t = TestApi::start_with(
        Some(provider as Arc<dyn ChatProvider>),
        Duration::from_secs(5),
    )
    .await;
    let home = t.home.clone();

    // Seed what a scheduled run used to leave behind before v7: a legacy
    // `job <name>` session with a transcript, plus the job it belongs to.
    let store = Store::open(&store_path(&home)).unwrap();
    store
        .create_job(
            "main",
            "morning",
            "every 15m",
            r#"{"kind":"agent","prompt":"x"}"#,
            None,
        )
        .unwrap();
    // The row predates the v8 watermark, so the title heuristic still
    // protects it. (A session created today has an explicit kind and is only
    // distinguished by the watermark.)
    let job_session_id = {
        let conn = aux_store::open_keyed(&store_path(&home)).unwrap();
        conn.execute(
            "INSERT INTO sessions(agent, title, kind) VALUES ('main', 'job morning', 'chat')",
            [],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO messages(session_id, role, content) VALUES (?1, 'system', 'You are main')",
            [id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(session_id, role, content) VALUES (?1, 'user', 'job prompt')",
            [id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(session_id, role, content) VALUES (?1, 'assistant', 'job answer')",
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
    let job_session = store.session(job_session_id).unwrap().unwrap();
    drop(store);

    let agents = get_auth(&t, "/v1/agents").await.json();
    let main = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "main")
        .unwrap();
    assert!(
        main["thread_id"].is_null(),
        "a job transcript became the agent thread: {main}"
    );
    let page = get_auth(&t, "/v1/threads/main/messages").await.json();
    assert!(
        page["thread"].is_null(),
        "job transcript leaked into the chat page"
    );
    assert!(page["messages"].as_array().unwrap().is_empty());

    // The next chat message opens a real chat session, and the job transcript
    // is untouched.
    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hello"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    let chat_id = sent.json()["thread"]["id"].as_i64().unwrap();
    assert_ne!(
        chat_id, job_session.id,
        "the chat appended to the job session"
    );
    let store = t.store();
    assert_eq!(store.list_messages(job_session.id).unwrap().len(), 3);
    let agents = get_auth(&t, "/v1/agents").await.json();
    let main = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "main")
        .unwrap();
    assert_eq!(main["thread_id"], chat_id.to_string());
    t.stop();
}

// ---------------------------------------------------------------------------
// Recovery: a broken config is a clear error, never a crash
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_config_reports_a_clear_error() {
    let mut t = TestApi::start_with(None, Duration::from_secs(5)).await;
    std::fs::write(config_path(&t.home), "[[[ not toml\n").unwrap();

    let response = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hi"}"#).await;
    assert_eq!(
        response.status, 503,
        "a broken config must be a clear 503: {}",
        response.body
    );
    assert_eq!(response.json()["error"]["code"], "provider_config");
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_allow_always_answer_to_a_broken_config_fails_closed() {
    let mut t = TestApi::start_with(Some(ask_provider().await), Duration::from_secs(10)).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"write"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;

    // The config becomes unwritable/broken while the ask is pending.
    std::fs::write(config_path(&t.home), "[[[ not toml\n").unwrap();
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"allow_always","scope":{"tool":"write_file"}}"#,
    )
    .await;
    assert_eq!(
        answer.status, 500,
        "an unpersistable rule must be an honest error: {}",
        answer.body
    );
    assert_eq!(answer.json()["error"]["code"], "rule_write_failed");

    // The turn did not run the tool under an approval that was not persisted.
    // An unreadable config reads as private (fail toward masking), so the turn
    // stops with privacy_disabled before the tool is dispatched.
    let response = send.await.unwrap();
    assert_eq!(response.status, 403, "body: {}", response.body);
    assert_eq!(response.json()["error"]["code"], "privacy_disabled");
    // The broken file was not appended to (still exactly the broken text).
    assert_eq!(
        t.config_text(),
        "[[[ not toml\n",
        "a failed rule write must not touch the file"
    );
    t.stop();
}

// ---------------------------------------------------------------------------
// Event order and tool-content scrubbing
// ---------------------------------------------------------------------------
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approval_resolved_precedes_the_tool_it_authorized() {
    let mut t = TestApi::start_with(Some(ask_provider().await), Duration::from_secs(10)).await;
    let mut ws = ws_connect(t.addr, &t.token).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"allow_once"}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);

    let frames = drain_ws(&mut ws, Duration::from_millis(1200)).await;
    let resolved = index_of(&frames, "approval.resolved").expect("approval.resolved");
    let tool_end = index_of(&frames, "tool.end").expect("tool.end");
    let done = index_of(&frames, "message.done").expect("message.done");
    assert!(
        resolved < tool_end,
        "approval.resolved (index {resolved}) trails tool.end (index {tool_end})"
    );
    assert!(
        resolved < done,
        "approval.resolved (index {resolved}) trails message.done (index {done})"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tool_role_message_new_is_scrubbed_like_tool_end() {
    // H-02: `read_file` is read-only, so it runs without an approval card;
    // the scrubbing contract is unchanged.
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
    // The workspace file read by `read_file` carries a key-shaped secret.
    let workspace = t.home.join("agents").join("main").join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(
        workspace.join("note.txt"),
        format!("top secret: {SECRET}\n"),
    )
    .unwrap();

    let mut ws = ws_connect(t.addr, &t.token).await;
    let send = send_async(&t, "/v1/threads/main/messages", r#"{"content":"read it"}"#);
    let _ = send.await.unwrap();
    assert!(
        get_auth(&t, "/v1/approvals?state=pending")
            .await
            .json()
            .as_array()
            .unwrap()
            .is_empty(),
        "a read-only tool must not raise an approval card"
    );

    let frames = drain_ws(&mut ws, Duration::from_millis(1200)).await;
    let preview = frames
        .iter()
        .find(|value| value["type"] == "tool.end")
        .and_then(|value| value["call"]["result_preview"].as_str())
        .expect("tool.end result preview")
        .to_string();
    let tool_text = frames
        .iter()
        .filter(|value| value["type"] == "message.new")
        // Tool-role messages carry their own author kind.
        .find(|value| value["message"]["author"]["kind"] == "tool")
        .and_then(|value| value["message"]["blocks"][0]["text"].as_str())
        .expect("tool-role message.new")
        .to_string();

    assert!(
        !preview.contains(SECRET),
        "tool.end leaked the key: {preview}"
    );
    assert!(
        !tool_text.contains(SECRET),
        "message.new leaked the raw tool result: {tool_text}"
    );
    assert!(
        tool_text.contains("<redacted>"),
        "scrub marker: {tool_text}"
    );
    t.stop();
}

// ---------------------------------------------------------------------------
// Error envelopes never echo key-shaped caller input
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_messages_do_not_echo_key_shaped_input() {
    let mut t = TestApi::start_with(None, Duration::from_secs(5)).await;
    let key = "sk-live-ECHO1234567890";

    for path in [
        format!("/v1/approvals?state={key}"),
        format!("/v1/usage?period={key}"),
        format!("/v1/activity?agent=ab%20{key}"),
        format!("/v1/activity?since={key}"),
    ] {
        let response = get_auth(&t, &path).await;
        assert!(
            !response.body.contains(key),
            "{path} echoed the key: {}",
            response.body
        );
    }
    t.stop();
}
