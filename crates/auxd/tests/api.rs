//! End-to-end tests of the `auxd` local API (B-API v1).
//!
//! Every test starts a **real server on an ephemeral loopback port in
//! process** (`auxd::api::spawn`), speaks real HTTP/1.1 over a socket, and
//! uses temp homes + the deterministic fake provider. No network, no
//! Keychain, no real `~/.auxesis`.

mod common;

use kernel_broker::ToolClass;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aux_notify::{FakeNotifier, Notifier};
use aux_providers::ToolCall as ProviderToolCall;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, FakeProvider, ProviderError, Usage,
};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions, FailingTurnRunner, ToolRegistryHook};
use common::{assert_error, http, HttpResponse};
use futures_util::StreamExt;
use kernel_broker::{Risk, Tool, ToolCtx, ToolError, ToolOutput};
use kernel_core::{config_path, killswitch, store_path, UsageKind};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

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

#[cfg(feature = "l1-fetch")]
/// `FAKE_CONFIG` plus a `[web]` policy that asks on every read and hard-denies
/// one host, so an edit can be pointed at a URL the policy never allowed.
const WEB_FAKE_CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "main"
approvals = "ask"

[web]
mode = "always_ask"
deny_domains = ["blocked.example"]

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;

/// A sandbox: temp home, real server, its bearer token.
struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start() -> Self {
        Self::start_with(|_| fast_options()).await
    }

    async fn start_with(build: impl FnOnce(&Path) -> ApiOptions) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();
        // Every test home shares one API token: the daemon registers the
        // token with the exact-value scrubber, and a fresh random token per
        // test made the process-global registry grow one full encoding
        // closure per test (quadratic automaton rebuilds in parallel runs).
        let shared_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(api::token_path(&home), format!("{shared_token}\n")).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        let handle = api::spawn(&home, build(&home)).unwrap();
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

    /// A sandbox whose owner notification channel is a recording fake, so
    /// trust codes never reach a real macOS notification.
    async fn start_with_notifier(notifier: Arc<FakeNotifier>) -> Self {
        let notifier: Arc<dyn Notifier> = notifier;
        Self::start_with(move |_| ApiOptions {
            notifier: Some(notifier),
            ..fast_options()
        })
        .await
    }

    fn store(&self) -> Store {
        Store::open(&store_path(&self.home)).unwrap()
    }

    /// Stop the server, keeping the home (and its temp dir) alive.
    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

fn fast_options() -> ApiOptions {
    ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        runner: None,
        provider: None,
        ..ApiOptions::default()
    }
}

/// `FAKE_CONFIG` with an explicit turn timeout. The key must precede the
/// `[[providers]]` array of tables to stay a top-level TOML key.
fn config_with_turn_timeout(secs: u64) -> String {
    format!(
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\napprovals = \"ask\"\nturn_timeout_secs = {secs}\n\n\
         [[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
         model = \"fake-model\"\nkind = \"fake\"\n"
    )
}

/// Blocking HTTP on the blocking pool, so the test runtime stays free.
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

async fn call_auth(t: &TestApi, method: &str, path: &str, body: Option<&str>) -> HttpResponse {
    call(t.addr, method, path, Some(&t.token), body).await
}

async fn get_auth(t: &TestApi, path: &str) -> HttpResponse {
    call_auth(t, "GET", path, None).await
}

/// Authenticated request with extra header lines (F-17 Host/Origin tests).
async fn call_with_headers(
    t: &TestApi,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let addr = t.addr;
    let token = t.token.clone();
    let method = method.to_string();
    let path = path.to_string();
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    tokio::task::spawn_blocking(move || {
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        common::http_with_headers(addr, &method, &path, Some(&token), None, &refs)
    })
    .await
    .unwrap()
}

async fn post_auth(t: &TestApi, path: &str, body: &str) -> HttpResponse {
    call_auth(t, "POST", path, Some(body)).await
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(addr: SocketAddr, token: Option<&str>) -> Result<Ws, String> {
    let mut request = format!("ws://{addr}/v1/events")
        .into_client_request()
        .map_err(|err| err.to_string())?;
    if let Some(token) = token {
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {token}")
                .parse()
                .map_err(|err| format!("{err:?}"))?,
        );
    }
    tokio_tungstenite::connect_async(request)
        .await
        .map(|(socket, _)| socket)
        .map_err(|err| err.to_string())
}

async fn next_ws_json(ws: &mut Ws, timeout: Duration) -> Option<Value> {
    loop {
        let message = tokio::time::timeout(timeout, ws.next()).await.ok()??;
        match message.ok()? {
            WsMessage::Text(text) => return serde_json::from_str(&text).ok(),
            WsMessage::Close(_) => return None,
            _ => continue,
        }
    }
}

async fn wait_ws<F: Fn(&Value) -> bool>(
    ws: &mut Ws,
    timeout: Duration,
    predicate: F,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let slice = Duration::from_millis(500).min(deadline - tokio::time::Instant::now());
        if let Some(value) = next_ws_json(ws, slice).await {
            if predicate(&value) {
                return Some(value);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_requires_a_valid_bearer_token() {
    let mut t = TestApi::start().await;

    let missing = call(t.addr, "GET", "/v1/health", None, None).await;
    assert_error(&missing, 401, "unauthorized");
    assert!(
        !missing.body.contains(&t.token),
        "the expected token must never be echoed"
    );

    let wrong = call(t.addr, "GET", "/v1/health", Some("not-the-token"), None).await;
    assert_error(&wrong, 401, "unauthorized");

    let malformed = call(t.addr, "GET", "/v1/health", Some("Basic abc"), None).await;
    assert_error(&malformed, 401, "unauthorized");

    let ok = call(t.addr, "GET", "/v1/health", Some(&t.token), None).await;
    assert_eq!(ok.status, 200, "body: {}", ok.body);
    let value = ok.json();
    assert_eq!(value["ok"], true);
    assert_eq!(value["version"], kernel_core::VERSION);
    assert!(value["pid"].as_u64().unwrap() > 0);

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_route_rejects_a_missing_or_wrong_token() {
    let mut t = TestApi::start().await;
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("GET", "/v1/health", None),
        ("GET", "/v1/agents", None),
        ("GET", "/v1/agents/main", None),
        ("POST", "/v1/agents", Some("{}")),
        ("POST", "/v1/agents/main/pause", None),
        ("POST", "/v1/agents/main/kill", None),
        ("GET", "/v1/threads/main/messages", None),
        (
            "POST",
            "/v1/threads/main/messages",
            Some(r#"{"content":"hi"}"#),
        ),
        ("GET", "/v1/activity", None),
        ("GET", "/v1/usage", None),
        ("GET", "/v1/jobs", None),
        ("GET", "/v1/privacy/coverage", None),
        ("POST", "/v1/stop", None),
        ("POST", "/v1/resume", None),
        ("GET", "/v1/approvals", None),
        ("POST", "/v1/approvals/1", Some("{}")),
        ("GET", "/v1/mode", None),
        ("PUT", "/v1/mode", Some("{}")),
        ("GET", "/v1/settings", None),
        ("GET", "/v1/providers", None),
        ("POST", "/v1/providers/fakey/test", None),
        ("GET", "/v1/screen", None),
        ("GET", "/v1/audit/1", None),
        ("POST", "/v1/stop-all", None),
        ("GET", "/v1/nope", None),
    ];
    for (method, path, body) in cases {
        let missing = call(t.addr, method, path, None, *body).await;
        assert_error(&missing, 401, "unauthorized");
        let wrong = call(t.addr, method, path, Some("wrong"), *body).await;
        assert_error(&wrong, 401, "unauthorized");
    }

    // The WebSocket upgrade is authenticated by the same middleware.
    assert!(ws_connect(t.addr, None).await.is_err());
    assert!(ws_connect(t.addr, Some("wrong")).await.is_err());
    assert!(ws_connect(t.addr, Some(&t.token)).await.is_ok());

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn host_and_origin_validation_blocks_dns_rebinding() {
    let mut t = TestApi::start().await;

    // F-17/C P3-2: a rebinding page presents its own Host.
    for host in ["evil.example", "localhost.evil.com", "127.0.0.1.nip.io"] {
        let response = call_with_headers(&t, "GET", "/v1/health", &[("Host", host)]).await;
        assert_error(&response, 403, "forbidden_host");
    }
    // A browser cross-origin request is refused on REST...
    for origin in ["http://evil.example", "https://localhost.evil.com"] {
        let response = call_with_headers(&t, "GET", "/v1/health", &[("Origin", origin)]).await;
        assert_error(&response, 403, "forbidden_origin");
    }
    // Round-1 P3-9: a duplicated Host/Origin is refused outright — the first
    // value must not launder the last for whatever reads it next.
    for headers in [
        [("Host", "127.0.0.1"), ("Host", "evil.example")],
        [("Host", "evil.example"), ("Host", "127.0.0.1")],
    ] {
        let response = call_with_headers(&t, "GET", "/v1/health", &headers).await;
        assert_error(&response, 403, "forbidden_host");
    }
    let response = call_with_headers(
        &t,
        "GET",
        "/v1/health",
        &[
            ("Origin", "http://localhost:1"),
            ("Origin", "http://evil.example"),
        ],
    )
    .await;
    assert_error(&response, 403, "forbidden_origin");
    // ...and on the WebSocket upgrade, before the protocol switch.
    let mut request = format!("ws://{}/v1/events", t.addr)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", t.token).parse().unwrap(),
    );
    request
        .headers_mut()
        .insert("origin", "http://evil.example".parse().unwrap());
    assert!(
        tokio_tungstenite::connect_async(request).await.is_err(),
        "a cross-origin WS upgrade must be refused"
    );

    // A native client sends no Origin, and a loopback Host/Origin passes.
    let native = get_auth(&t, "/v1/health").await;
    assert_eq!(native.status, 200, "body: {}", native.body);
    let loopback_origin = format!("http://localhost:{}", t.addr.port());
    let cors = call_with_headers(
        &t,
        "GET",
        "/v1/health",
        &[("Origin", loopback_origin.as_str())],
    )
    .await;
    assert_eq!(cors.status, 200, "body: {}", cors.body);

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_bind_and_private_token_file() {
    let mut t = TestApi::start().await;
    assert!(t.addr.ip().is_loopback(), "must serve only 127.0.0.1");
    assert_eq!(t.addr.ip(), std::net::Ipv4Addr::LOCALHOST);

    let path = api::token_path(&t.home);
    let raw = std::fs::read_to_string(&path).unwrap();
    assert_eq!(raw.trim().len(), 64, "32 random bytes as hex");
    assert!(raw.trim().chars().all(|c| c.is_ascii_hexdigit()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "api.token must be private");
    }

    // Restarting on the same home reuses the token but a fresh port.
    let old_port = t.addr.port();
    let old_token = t.token.clone();
    let home = t.home.clone();
    t.stop();
    let handle = api::spawn(&home, fast_options()).unwrap();
    assert_ne!(handle.addr().port(), old_port);
    let token = std::fs::read_to_string(api::token_path(&home))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(token, old_token);
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_taken_port_is_an_error_not_a_silent_rebind() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();

    let options = ApiOptions {
        port,
        event_poll: Duration::from_millis(25),
        runner: None,
        provider: None,
        ..ApiOptions::default()
    };
    let err = match api::spawn(&home, options) {
        Ok(_) => panic!("spawning on a taken port must fail"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_features_answer_501_with_the_error_envelope() {
    let mut t = TestApi::start().await;
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("GET", "/v1/mode", None),
        ("PUT", "/v1/mode", Some("{}")),
        // `POST /v1/providers` and the `/v1/first-run` routes are implemented
        // by B-API v4 (gap 2); they are no longer 501.
        ("GET", "/v1/screen", None),
        ("GET", "/v1/audit/7", None),
        ("DELETE", "/v1/agents/main", None),
    ];
    for (method, path, body) in cases {
        let response = call_auth(&t, method, path, *body).await;
        assert_error(&response, 501, "not_implemented");
        assert!(
            response.json()["error"]["hint"].is_string(),
            "501 bodies carry a hint: {}",
            response.body
        );
    }

    let unknown = get_auth(&t, "/v1/nope").await;
    assert_error(&unknown, 404, "not_found");

    let wrong_method = call_auth(&t, "DELETE", "/v1/health", None).await;
    assert_error(&wrong_method, 405, "method_not_allowed");

    t.stop();
}

// ---------------------------------------------------------------------------
// agents
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_endpoint_reports_live_state_and_threads() {
    let mut t = TestApi::start().await;
    let store = t.store();
    let main = store.create_session("main", Some("hello")).unwrap();
    store.append_message(main.id, "user", "hi", None).unwrap();
    let job = store
        .create_job(
            "axis",
            "veille",
            "every 15m",
            "{}",
            Some("2026-10-03 12:00:00"),
        )
        .unwrap();
    store.start_run(job.id, "2026-10-03 11:45:00").unwrap();
    store
        .record_usage_at(
            "main",
            UsageKind::TokensIn,
            12,
            "tokens",
            &format!("{} 08:00:00", store.local_day().unwrap()),
        )
        .unwrap();

    let list = get_auth(&t, "/v1/agents").await;
    assert_eq!(list.status, 200, "body: {}", list.body);
    let agents = list.json();
    let names: Vec<&str> = agents
        .as_array()
        .unwrap()
        .iter()
        .map(|agent| agent["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "aux",
            "axis",
            "calendar",
            "clients",
            "documents",
            "mail",
            "main"
        ]
    );

    let main_agent = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "main")
        .unwrap();
    assert_eq!(main_agent["enabled"], true);
    assert_eq!(main_agent["jobs_total"], 0);
    assert_eq!(main_agent["usage_today"]["tokens_in"], 12);
    assert_eq!(main_agent["stop"], false);
    assert_eq!(main_agent["last_activity"]["summary"], "hi");
    assert_eq!(
        main_agent["thread_id"],
        main.id.to_string(),
        "/v1/agents publishes the current session"
    );

    let axis = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "axis")
        .unwrap();
    assert_eq!(axis["jobs_total"], 1);
    assert_eq!(axis["running_job"], "veille");
    assert_eq!(axis["enabled"], true);
    assert_eq!(axis["thread_id"], Value::Null, "no session yet");

    let detail = get_auth(&t, "/v1/agents/main").await;
    assert_eq!(detail.status, 200);
    let detail = detail.json();
    assert_eq!(detail["name"], "main");
    assert_eq!(detail["sessions"][0]["id"], main.id);
    assert_eq!(detail["sessions"][0]["title"], "hello");
    assert_eq!(detail["sessions"][0]["agent"], "main");

    let missing = get_auth(&t, "/v1/agents/ghost").await;
    assert_error(&missing, 404, "agent_not_found");

    let invalid = get_auth(&t, "/v1/agents/a%20b").await;
    assert_error(&invalid, 400, "invalid_agent");

    // STOP is reflected in every agent's live state.
    let stopped = post_auth(&t, "/v1/stop", "").await;
    assert_eq!(stopped.status, 200);
    let list = get_auth(&t, "/v1/agents").await;
    assert!(list
        .json()
        .as_array()
        .unwrap()
        .iter()
        .all(|agent| agent["stop"] == true));

    t.stop();
}

// ---------------------------------------------------------------------------
// messages / turns
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn message_pages_are_capped_and_cursor_bounded() {
    let mut t = TestApi::start().await;
    let store = t.store();
    let session = store.create_session("main", None).unwrap();
    for index in 0..5 {
        store
            .append_message(session.id, "user", &format!("m{index}"), None)
            .unwrap();
    }

    let first = get_auth(&t, &format!("/v1/threads/{}/messages?limit=2", session.id)).await;
    assert_eq!(first.status, 200, "body: {}", first.body);
    let page = first.json();
    let contents: Vec<&str> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["content"].as_str().unwrap())
        .collect();
    assert_eq!(contents, vec!["m3", "m4"]);
    assert_eq!(page["thread"]["id"], session.id);
    assert_eq!(page["has_more"], true);
    let cursor = page["oldest_id"].as_i64().unwrap();
    assert_eq!(page["messages"][0]["id"], cursor);

    let second = get_auth(
        &t,
        &format!(
            "/v1/threads/{}/messages?limit=2&before={cursor}",
            session.id
        ),
    )
    .await;
    let page = second.json();
    let contents: Vec<&str> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["content"].as_str().unwrap())
        .collect();
    assert_eq!(contents, vec!["m1", "m2"]);
    assert_eq!(page["has_more"], true);

    let cursor = page["oldest_id"].as_i64().unwrap();
    let third = get_auth(
        &t,
        &format!("/v1/threads/{}/messages?before={cursor}", session.id),
    )
    .await;
    let page = third.json();
    assert_eq!(page["messages"].as_array().unwrap().len(), 1);
    assert_eq!(page["messages"][0]["content"], "m0");
    assert_eq!(page["has_more"], false);

    // Caps and malformed values are 400s with a stable code.
    for query in ["limit=0", "limit=201", "limit=-1", "limit=abc"] {
        let response = get_auth(&t, &format!("/v1/threads/{}/messages?{query}", session.id)).await;
        assert_error(&response, 400, "invalid_limit");
    }
    for query in ["before=0", "before=-1", "before=abc"] {
        let response = get_auth(&t, &format!("/v1/threads/{}/messages?{query}", session.id)).await;
        assert_error(&response, 400, "invalid_before");
    }

    // Unknown session id → 404; unknown agent → 200 with a null thread.
    let missing = get_auth(&t, "/v1/threads/999/messages").await;
    assert_error(&missing, 404, "thread_not_found");
    let empty = get_auth(&t, "/v1/threads/ghost/messages").await;
    assert_eq!(empty.status, 200);
    assert_eq!(empty.json()["thread"], Value::Null);
    assert_eq!(empty.json()["messages"].as_array().unwrap().len(), 0);

    let invalid = get_auth(&t, "/v1/threads/a%20b/messages").await;
    assert_error(&invalid, 400, "invalid_agent");

    t.stop();
}

/// Private mode with no contacts: names are not checked, but the turn runs
/// with its pattern values tokenised (owner, 2026-10-14: the filter tokenises,
/// it never blocks). The store keeps the rows (G1) but no title.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_mode_without_contacts_answers_and_stores_no_title() {
    let mut t = TestApi::start_with(|home| {
        let config = std::fs::read_to_string(config_path(home))
            .unwrap()
            .replace("privacy.mode = \"open\"", "privacy.mode = \"private\"");
        std::fs::write(config_path(home), config).unwrap();
        fast_options()
    })
    .await;

    let response = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"ping"}"#).await;
    assert_eq!(response.status, 200, "body: {}", response.body);

    // A private turn stores its rows (G1, PRIVATE-TRANSCRIPT) but no title.
    for session in t.store().list_sessions().unwrap() {
        assert!(session.title.is_none(), "{session:?}");
        let roles: Vec<String> = t
            .store()
            .list_messages(session.id)
            .unwrap()
            .into_iter()
            .map(|row| row.role)
            .collect();
        assert_eq!(roles, ["user", "assistant"]);
    }
    t.stop();
}

/// CONV-SIDEBAR-1: a Private-mode Aux chat persists as a `chat` row (G1) but
/// must never be listed, and its fallback title must not leak either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conversations_never_list_a_private_aux_chat() {
    let mut t = TestApi::start_with(|home| {
        let config = std::fs::read_to_string(config_path(home))
            .unwrap()
            .replace("privacy.mode = \"open\"", "privacy.mode = \"private\"");
        std::fs::write(config_path(home), config).unwrap();
        fast_options()
    })
    .await;

    let response = post_auth(
        &t,
        "/v1/threads/aux/messages",
        r#"{"content":"Aurora kickoff alex@example.test"}"#,
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let store = t.store();
    assert!(
        store
            .list_sessions()
            .unwrap()
            .iter()
            .any(|session| session.agent == "aux" && session.title.is_none()),
        "the private chat is stored"
    );

    let list = get_auth(&t, "/v1/conversations").await;
    assert_eq!(list.status, 200, "body: {}", list.body);
    assert_eq!(list.json(), json!([]));
    assert!(!list.body.contains("Aurora"), "{}", list.body);
    t.stop();
}

/// The owner switches Aux to `mode` (the app writes the config).
fn set_privacy(home: &Path, mode: &str) {
    let config = std::fs::read_to_string(config_path(home)).unwrap();
    let mut lines: Vec<String> = config
        .lines()
        .map(|line| {
            if line.starts_with("privacy.mode") {
                format!("privacy.mode = \"{mode}\"")
            } else {
                line.to_string()
            }
        })
        .collect();
    lines.push(String::new());
    std::fs::write(config_path(home), lines.join("\n")).unwrap();
}

/// One owner turn on Aux; returns the chat it landed in.
async fn aux_turn(t: &TestApi, content: &str) -> i64 {
    let response = post_auth(
        t,
        "/v1/threads/aux/messages",
        &json!({ "content": content }).to_string(),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    response.json()["thread"]["id"].as_i64().unwrap()
}

/// A chat that ran in Private mode: the gated row the provider saw, the token
/// table that resolves it, and the sticky mark (CONV-PRIVATE-MIX).
fn private_chat(home: &Path) -> i64 {
    let store = Store::open(&store_path(home)).unwrap();
    let session = store.create_session("aux", Some("Atlas planning")).unwrap();
    store
        .append_message(session.id, "user", "mail from ⟦EMAIL_0A1B2C3D4E5F⟧", None)
        .unwrap();
    store
        .record_session_tokens(
            session.id,
            &[(
                "EMAIL_0A1B2C3D4E5F".to_string(),
                "mara@example.invalid".to_string(),
            )],
        )
        .unwrap();
    store.mark_session_ever_private(session.id).unwrap();
    session.id
}

/// CONV-PRIVATE-MIX: the agent's CURRENT session is exempt from the Private
/// filter for the transcript read, so a live Private chat survives the app's
/// reload on launch. Once the owner starts a new chat, the old Private one
/// is no longer current: it is gone from the transcript read and refused by
/// id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_private_chat_survives_a_reload() {
    let mut t = TestApi::start_with(|_| fast_options()).await;
    let chat = private_chat(&t.home);

    // The live Private chat is the agent's current session: the reload finds
    // it, and its row is rehydrated as before.
    let live = get_auth(&t, "/v1/threads/aux/messages").await;
    assert_eq!(live.status, 200, "body: {}", live.body);
    assert!(
        live.body.contains("mara@example.invalid"),
        "the live private chat vanished: {}",
        live.body
    );

    // A new chat makes the old one non-current: it is gone everywhere.
    let fresh = post_auth(&t, "/v1/threads/aux/new", "").await;
    assert_eq!(fresh.status, 200, "body: {}", fresh.body);

    let after = get_auth(&t, "/v1/threads/aux/messages").await;
    assert_eq!(after.status, 200, "body: {}", after.body);
    assert!(
        !after.body.contains("mara@example.invalid"),
        "the old private chat is still read back: {}",
        after.body
    );
    let by_id = get_auth(&t, &format!("/v1/threads/{chat}/messages")).await;
    assert_eq!(by_id.status, 404, "body: {}", by_id.body);
    assert!(
        !by_id.body.contains("mara@example.invalid"),
        "{}",
        by_id.body
    );
    t.stop();
}

/// CONV-PRIVATE-MIX: a chat that ran in Private mode is not in the activity:
/// its rows are left out entirely, never rehydrated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_chat_is_not_in_the_activity() {
    let mut t = TestApi::start_with(|_| fast_options()).await;
    private_chat(&t.home);

    let activity = get_auth(&t, "/v1/activity?agent=aux").await;
    assert_eq!(activity.status, 200, "body: {}", activity.body);
    assert!(
        !activity.body.contains("mara@example.invalid"),
        "the private row was rehydrated: {}",
        activity.body
    );
    assert!(
        !activity.body.contains("EMAIL_0A1B2C3D4E5F"),
        "the gated row is in the activity: {}",
        activity.body
    );
    t.stop();
}

/// CONV-PRIVATE-MIX: a chat that ran in Private mode cannot be reopened: the
/// select refuses it, as it refuses an unknown thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_chat_cannot_be_selected() {
    let mut t = TestApi::start_with(|_| fast_options()).await;
    let chat = private_chat(&t.home);

    let response = post_auth(
        &t,
        "/v1/threads/aux/select",
        &json!({ "session": chat.to_string() }).to_string(),
    )
    .await;
    assert_eq!(response.status, 404, "body: {}", response.body);
    assert!(
        !response.body.contains("Atlas planning"),
        "{}",
        response.body
    );
    t.stop();
}

/// CONV-PRIVATE-MIX: a chat that ran in Private mode does not drive the
/// agents snapshot's unread flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_chat_does_not_drive_unread() {
    let mut t = TestApi::start_with(|_| fast_options()).await;
    private_chat(&t.home);

    let agents = get_auth(&t, "/v1/agents").await;
    assert_eq!(agents.status, 200, "body: {}", agents.body);
    let aux = agents
        .json()
        .as_array()
        .unwrap_or_else(|| panic!("an array: {}", agents.body))
        .iter()
        .find(|agent| agent["name"] == "aux")
        .expect("the aux agent")
        .clone();
    assert_eq!(
        aux["unread"],
        json!(false),
        "the private chat drove unread: {aux}"
    );
    t.stop();
}

/// The ids of the chats the sidebar lists, and the raw answer.
async fn listed(t: &TestApi) -> (Vec<i64>, String) {
    let list = get_auth(t, "/v1/conversations").await;
    assert_eq!(list.status, 200, "body: {}", list.body);
    let rows = list.json();
    let ids = rows
        .as_array()
        .unwrap_or_else(|| panic!("an array: {rows}"))
        .iter()
        .map(|row| row["id"].as_i64().expect("a chat id"))
        .collect();
    (ids, list.body)
}

/// CONV-PRIVATE-MIX: a chat that ever ran in Private mode is never listed,
/// whichever order the two modes come in.
///
/// The Private turns here say nothing the gate would tokenise, so the stored
/// rows carry no private marker: the sticky mark alone must drop the chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chat_that_was_ever_private_is_never_listed() {
    // Open, then Private: the chat leaves the list.
    let mut t = TestApi::start_with(|_| fast_options()).await;
    let chat = aux_turn(&t, "Plan the Q4 workshop").await;
    let (ids, body) = listed(&t).await;
    assert_eq!(ids, vec![chat], "the Open chat is listed: {body}");
    assert!(body.contains("Plan the Q4 workshop"), "{body}");

    set_privacy(&t.home, "private");
    let same = aux_turn(&t, "And the budget").await;
    assert_eq!(same, chat, "the Private turn stays in the same chat");
    assert!(
        listed(&t).await.0.is_empty(),
        "a chat that was ever Private is never listed"
    );
    t.stop();

    // Private, then Open: the chat never comes back, though the Open turn
    // gives it a system row.
    let mut t = TestApi::start_with(|home| {
        let config = std::fs::read_to_string(config_path(home))
            .unwrap()
            .replace("privacy.mode = \"open\"", "privacy.mode = \"private\"");
        std::fs::write(config_path(home), config).unwrap();
        fast_options()
    })
    .await;
    let chat = aux_turn(&t, "Plan the Q4 workshop").await;
    assert!(
        listed(&t).await.0.is_empty(),
        "a Private chat is not listed"
    );
    set_privacy(&t.home, "open");
    let same = aux_turn(&t, "And the budget").await;
    assert_eq!(same, chat, "the Open turn stays in the same chat");
    assert!(
        listed(&t).await.0.is_empty(),
        "a chat that was ever Private is never listed"
    );
    t.stop();
}

/// CONV-PRIVATE-MIX: a chat written before the mark existed cannot be
/// proven Open — a Private turn that detected nothing leaves no marker — so
/// the migration marks every old chat and the reader leaves them out. The
/// markerless mixed chat (an Open system row and title, then a Private turn)
/// is the case that must not be listed and must not be reopenable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_written_before_the_mark_never_lists() {
    let mut t = TestApi::start_with(|_| fast_options()).await;
    // A store as it stood before the mark: no `ever_private` column at all.
    let conn = aux_store::open_keyed(&store_path(&t.home)).unwrap();
    conn.execute_batch(
        "ALTER TABLE sessions DROP COLUMN ever_private;
         UPDATE meta SET value = '32' WHERE key = 'schema_version';
         INSERT INTO sessions(id, agent, title, kind, updated_at) VALUES
           (1, 'aux', 'Atlas planning', 'chat', '2026-02-01 00:00:00'),
           (2, 'aux', 'Mixed chat', 'chat', '2026-02-01 00:00:01');
         INSERT INTO messages(session_id, role, content) VALUES
           (1, 'system', 'You are Aux'),
           (1, 'user', 'Plan the trip'),
           (2, 'system', 'You are Aux'),
           (2, 'user', 'keep this note');",
    )
    .unwrap();
    drop(conn);

    // An unmigrated store proves nothing: no chat is listed (fail closed).
    let (ids, body) = listed(&t).await;
    assert!(ids.is_empty(), "no pre-v32 chat is listed: {body}");
    assert!(!body.contains("Atlas planning"), "{body}");
    assert!(!body.contains("Mixed chat"), "{body}");

    // The migration marks every old chat, and rewrites nothing else.
    let _ = t.store();
    let conn = aux_store::open_keyed(&store_path(&t.home)).unwrap();
    let marked: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE kind = 'chat' AND ever_private = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marked, 2, "every chat that existed before v32 is marked");
    drop(conn);

    let (ids, body) = listed(&t).await;
    assert!(ids.is_empty(), "no pre-v32 chat is listed: {body}");
    assert!(!body.contains("Atlas planning"), "{body}");
    assert!(
        !body.contains("Mixed chat"),
        "the markerless mixed chat is listed: {body}"
    );
    t.stop();
}

/// CONV-PRIVATE-MIX: the agent's threads leave out a chat that ran in
/// Private mode, title included (the follow-up finding on `/v1/agents`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_agent_threads_leave_out_a_private_chat() {
    let mut t = TestApi::start_with(|_| fast_options()).await;
    let store = t.store();
    let open = store.create_session("aux", Some("Open chat")).unwrap();
    store
        .append_message(open.id, "system", "You are Aux", None)
        .unwrap();
    let private = store.create_session("aux", Some("Atlas planning")).unwrap();
    store
        .append_message(private.id, "system", "You are Aux", None)
        .unwrap();
    store.mark_session_ever_private(private.id).unwrap();
    drop(store);

    let detail = get_auth(&t, "/v1/agents/aux").await;
    assert_eq!(detail.status, 200, "body: {}", detail.body);
    let titles: Vec<String> = detail.json()["sessions"]
        .as_array()
        .unwrap_or_else(|| panic!("sessions: {}", detail.body))
        .iter()
        .map(|row| row["title"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(titles.contains(&"Open chat".to_string()), "{titles:?}");
    assert!(
        !titles.contains(&"Atlas planning".to_string()),
        "the private chat is listed: {titles:?}"
    );
    assert!(!detail.body.contains("Atlas planning"), "{}", detail.body);
    t.stop();
}

/// CONV-PRIVATE-MIX: the marker is the kernel's own token shape: a stored
/// gated copy excludes the chat, while a literal `⟦` in an Open message is
/// not a token and the chat stays listed. The kernel's collision suffix
/// (`_1` to `_9` and a longer digit run) is part of that shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_real_token_marker_excludes_an_open_chat() {
    let mut t = TestApi::start_with(|_| fast_options()).await;
    let store = t.store();
    let literal = store.create_session("aux", Some("Bracket chat")).unwrap();
    store
        .append_message(literal.id, "system", "You are Aux", None)
        .unwrap();
    store
        .append_message(literal.id, "user", "the bracket ⟦ is odd", None)
        .unwrap();
    let gated = store.create_session("aux", Some("Gated chat")).unwrap();
    store
        .append_message(gated.id, "system", "You are Aux", None)
        .unwrap();
    store
        .append_message(gated.id, "user", "mail from ⟦EMAIL_0A1B2C3D4E5F⟧", None)
        .unwrap();
    let collided = store.create_session("aux", Some("Collided chat")).unwrap();
    store
        .append_message(collided.id, "system", "You are Aux", None)
        .unwrap();
    store
        .append_message(
            collided.id,
            "user",
            "mail from ⟦EMAIL_0A1B2C3D4E5F_7⟧",
            None,
        )
        .unwrap();
    let longer = store.create_session("aux", Some("Longer run")).unwrap();
    store
        .append_message(longer.id, "system", "You are Aux", None)
        .unwrap();
    store
        .append_message(
            longer.id,
            "user",
            "mail from ⟦EMAIL_0A1B2C3D4E5F_123⟧",
            None,
        )
        .unwrap();
    drop(store);

    let (ids, body) = listed(&t).await;
    assert_eq!(
        ids,
        vec![literal.id],
        "the literal bracket stays Open, the gated copies do not: {body}"
    );
    t.stop();
}

const E2E_EMAIL: &str = "synthetic.person@example.test";
const E2E_PHONE: &str = "+1 202-555-0123";
const E2E_IBAN: &str = "GB82 WEST 1234 5698 7654 32";
const E2E_HEALTH: &str = "my type 2 diabetes";

fn copy_model_tree(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_model_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

async fn private_egress_e2e(deep: bool) {
    let provider = Arc::new(FakeProvider::echo("fakey"));
    let selected = Arc::clone(&provider);
    let mut t = TestApi::start_with(move |home| {
        let config = FAKE_CONFIG.replace("privacy.mode = \"open\"", "privacy.mode = \"private\"");
        std::fs::write(config_path(home), config).unwrap();
        if deep {
            let source = std::env::var_os("AUX_E2E_MODEL_DIR")
                .expect("AUX_E2E_MODEL_DIR is required for the Deep variant");
            copy_model_tree(Path::new(&source), &home.join("models/gliner2-pii"));
            let model =
                kernel_privacy::load_vetted_local_model(home, &home.join("models/gliner2-pii"))
                    .expect("the supplied local Deep model loads in the sandbox");
            aux_engine::install_deep_detector(Arc::new(model));
        }
        ApiOptions {
            provider: Some(selected as Arc<dyn aux_providers::ChatProvider>),
            ..fast_options()
        }
    })
    .await;

    let input = format!(
        "Check these synthetic details: email {E2E_EMAIL}; phone {E2E_PHONE}; IBAN {E2E_IBAN}; health phrase {E2E_HEALTH}."
    );
    let response = post_auth(
        &t,
        "/v1/threads/main/messages",
        &serde_json::json!({"content": input}).to_string(),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let turn = response.json();
    let request = provider
        .requests()
        .into_iter()
        .next()
        .expect("provider request");
    let received = serde_json::to_string(&request).unwrap();
    for (label, value) in [
        ("email", E2E_EMAIL),
        ("phone", E2E_PHONE),
        ("IBAN", E2E_IBAN),
        ("health", E2E_HEALTH),
    ] {
        assert!(
            !received.contains(value),
            "{label} reached the fake provider without tokenization"
        );
    }
    for kind in ["EMAIL_", "PHONE_", "IBAN_", "HEALTH"] {
        assert!(received.contains(kind), "provider body lacks {kind} token");
    }

    let reply = turn["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "assistant")
        .and_then(|message| message["content"].as_str())
        .expect("owner-visible assistant reply");
    for value in [E2E_EMAIL, E2E_PHONE, E2E_IBAN, E2E_HEALTH] {
        assert!(reply.contains(value), "owner reply was not rehydrated");
    }

    let receipts = get_auth(&t, "/v1/receipts?agent=main&limit=10").await;
    assert_eq!(receipts.status, 200, "body: {}", receipts.body);
    let receipts = receipts.json();
    let receipt = receipts
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| receipt["run_id"] == turn["run_id"])
        .expect("receipt for the completed turn");
    for kind in ["email", "phone", "iban", "health"] {
        assert_eq!(
            receipt["replaced_values"][kind].as_u64(),
            Some(1),
            "receipt has an unexpected {kind} replacement count: {receipt}"
        );
    }
    assert_eq!(
        receipt["replaced_values"].as_object().unwrap().len(),
        4,
        "receipt should contain exactly the four replaced kinds: {receipt}"
    );
    let receipt_json = serde_json::to_string(receipt).unwrap();
    for value in [E2E_EMAIL, E2E_PHONE, E2E_IBAN, E2E_HEALTH] {
        assert!(
            !receipt_json.contains(value),
            "receipt retained a source value"
        );
    }
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_api_turn_masks_each_value_before_the_fake_provider() {
    private_egress_e2e(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires AUX_E2E_MODEL_DIR with the public Deep model files"]
async fn private_api_turn_masks_values_with_the_deep_model() {
    private_egress_e2e(true).await;
}

/// IBAN-RECEIPT: an open-mode chief turn replaces a pasted IBAN with its
/// class marker and still records that class in the run receipt. The receipt
/// keeps the kind and count only, never the value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_chief_turn_records_a_pasted_iban_in_the_receipt() {
    let provider = Arc::new(FakeProvider::echo("fakey"));
    let selected = Arc::clone(&provider);
    let mut t = TestApi::start_with(move |home| {
        let config = FAKE_CONFIG.replace("default_agent = \"main\"", "default_agent = \"aux\"");
        std::fs::write(config_path(home), config).unwrap();
        ApiOptions {
            provider: Some(selected as Arc<dyn aux_providers::ChatProvider>),
            ..fast_options()
        }
    })
    .await;

    let iban = "FR76 3000 6000 0112 3456 7890 189";
    let content = format!(
        "Bonjour Aux,\n\nVoici le recap du virement :\n\
         IBAN : {iban}\n\
         BIC : AGRIFRPPXXX\n\n\
         Merci de verifier ce virement.\n"
    );
    let response = post_auth(
        &t,
        "/v1/threads/aux/messages",
        &serde_json::json!({"content": content}).to_string(),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let turn = response.json();

    let sent = serde_json::to_string(&provider.requests()).unwrap();
    assert!(
        !sent.contains(iban),
        "the IBAN reached the provider: {sent}"
    );
    assert!(
        sent.contains("[iban removed]"),
        "open mode did not replace the pasted IBAN with its class marker: {sent}"
    );

    let receipts = get_auth(&t, "/v1/receipts?agent=aux&limit=10").await;
    assert_eq!(receipts.status, 200, "body: {}", receipts.body);
    let receipts = receipts.json();
    let receipt = receipts
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| receipt["run_id"] == turn["run_id"])
        .expect("receipt for the completed chief turn");
    assert_eq!(
        receipt["replaced_values"]["iban"].as_u64(),
        Some(1),
        "receipt did not record the removed IBAN class: {receipt}"
    );
    assert!(
        !serde_json::to_string(receipt).unwrap().contains(iban),
        "receipt retained the IBAN value"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_turn_runs_the_engine_with_the_fake_provider() {
    let mut t = TestApi::start().await;
    let response = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"ping"}"#).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let value = response.json();
    assert_eq!(value["rounds"], 1);
    assert_eq!(value["capped"], false);
    assert_eq!(value["thread"]["agent"], "main");
    assert_eq!(value["thread"]["title"], "ping");
    let thread_id = value["thread"]["id"].as_i64().unwrap();
    assert!(thread_id > 0);

    let roles: Vec<&str> = value["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, vec!["user", "assistant"]);
    assert_eq!(value["messages"][0]["content"], "ping");
    assert_eq!(value["messages"][1]["content"], "[fake:fakey] ping");

    // The persisted turn is readable back through the thread endpoints.
    let page = get_auth(&t, &format!("/v1/threads/{thread_id}/messages")).await;
    let page = page.json();
    assert_eq!(page["messages"].as_array().unwrap().len(), 3);
    assert_eq!(page["messages"][2]["content"], "[fake:fakey] ping");

    let by_agent = get_auth(&t, "/v1/threads/main/messages").await;
    assert_eq!(by_agent.json()["thread"]["id"], thread_id);

    // A second send to the agent name appends to the same session: one system
    // prompt, continuous history, no silent new thread.
    let second = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"pong"}"#).await;
    assert_eq!(second.status, 200, "body: {}", second.body);
    let second = second.json();
    assert_eq!(second["thread"]["id"], thread_id, "same thread");
    assert_eq!(second["messages"][0]["content"], "pong");
    assert_eq!(second["messages"][1]["content"], "[fake:fakey] pong");

    let page = get_auth(&t, &format!("/v1/threads/{thread_id}/messages")).await;
    let page = page.json();
    let contents: Vec<&str> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["content"].as_str().unwrap())
        .collect();
    assert_eq!(
        contents.len(),
        5,
        "one system prompt + two user/assistant turns: {contents:?}"
    );
    assert_eq!(
        &contents[1..],
        ["ping", "[fake:fakey] ping", "pong", "[fake:fakey] pong"]
    );
    let systems = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "system")
        .count();
    assert_eq!(systems, 1, "exactly one system prompt per session");

    // `/v1/agents` publishes the current session as `thread_id`.
    let agents = get_auth(&t, "/v1/agents").await.json();
    let main = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "main")
        .unwrap();
    assert_eq!(main["thread_id"], thread_id.to_string());

    // An explicit session id appends there too.
    let explicit = post_auth(
        &t,
        &format!("/v1/threads/{thread_id}/messages"),
        r#"{"content":"direct"}"#,
    )
    .await;
    assert_eq!(explicit.status, 200, "body: {}", explicit.body);
    assert_eq!(explicit.json()["thread"]["id"], thread_id);

    // Unknown explicit ids are a clean 404, never a silent new session.
    let missing = get_auth(&t, "/v1/threads/999999/messages").await;
    assert_error(&missing, 404, "thread_not_found");
    let missing = post_auth(&t, "/v1/threads/999999/messages", r#"{"content":"ghost"}"#).await;
    assert_error(&missing, 404, "thread_not_found");
    assert_eq!(
        t.store().list_sessions().unwrap().len(),
        1,
        "a 404 must not create a session"
    );

    // Validation and caps.
    let empty = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"   "}"#).await;
    assert_error(&empty, 400, "empty_content");

    let missing = post_auth(&t, "/v1/threads/main/messages", "{}").await;
    assert_error(&missing, 400, "missing_content");

    let bad_json = post_auth(&t, "/v1/threads/main/messages", "not json").await;
    assert_error(&bad_json, 400, "invalid_json");

    let too_big = post_auth(
        &t,
        "/v1/threads/main/messages",
        &json!({ "content": "x".repeat(api::MAX_CONTENT_BYTES + 1) }).to_string(),
    )
    .await;
    assert_error(&too_big, 400, "content_too_large");

    let huge = post_auth(
        &t,
        "/v1/threads/main/messages",
        &json!({ "content": "x".repeat(api::MAX_REQUEST_BODY_BYTES + 1024) }).to_string(),
    )
    .await;
    assert_error(&huge, 413, "payload_too_large");

    t.stop();
}

// ---------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------

/// Scripted provider: one `write_file` call, then a final answer.
///
/// `write_file` is effectful (not read-only), so with no matching rule it
/// still asks — the approval-flow tests below exercise exactly the kept
/// protection (H-02 leaves it untouched).
fn approval_provider() -> Arc<FakeProvider> {
    Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "write_file",
                    json!({ "path": "out.txt", "content": "written" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ))
}

/// Starts a server with `provider` and a workspace file; `FAKE_CONFIG` has no
/// rules, so `write_file` always asks.
async fn start_approval_api_with(
    provider: Arc<dyn aux_providers::ChatProvider>,
    timeout: Duration,
) -> TestApi {
    TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            approval_timeout: Some(timeout),
            ..ApiOptions::default()
        }
    })
    .await
}

/// The default two-response script.
async fn start_approval_api(timeout: Duration) -> TestApi {
    start_approval_api_with(approval_provider(), timeout).await
}

#[cfg(feature = "l1-fetch")]
/// Scripted provider: one `http_fetch` to a normal (non-denied) host, then a
/// final answer. The fetch card appears because `WEB_FAKE_CONFIG` always asks.
fn fetch_provider() -> Arc<FakeProvider> {
    Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "http_fetch",
                    json!({ "url": "https://example.invalid/page" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ))
}

#[cfg(feature = "l1-fetch")]
/// Starts a server from an explicit config with `provider` and a workspace
/// file, for tests that need a `[web]` (or other) section `FAKE_CONFIG` lacks.
async fn start_approval_api_with_config(
    config: &str,
    provider: Arc<dyn aux_providers::ChatProvider>,
    timeout: Duration,
) -> TestApi {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), config).unwrap();
    let workspace = aux_engine::workspace_dir(&home, "main");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
    // One shared token across the binary: a fresh random token per test makes
    // the process-global scrubber accumulate one encoding closure per test.
    let shared_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    std::fs::write(api::token_path(&home), format!("{shared_token}\n")).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
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
    TestApi {
        _dir: dir,
        home,
        addr,
        token,
        handle: Some(handle),
    }
}

/// Payloads of every journal row of `kind`, oldest first.
fn event_payloads(home: &Path, kind: &str) -> Vec<String> {
    let conn = aux_store::open_keyed_readonly(&store_path(home)).unwrap();
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE kind = ?1 ORDER BY id")
        .unwrap();
    stmt.query_map([kind], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// Polls `GET /v1/approvals?state=pending` until one entry appears.
async fn wait_for_pending(t: &TestApi, timeout: Duration) -> Vec<app_wire::Approval> {
    wait_for_pending_with_send(t, timeout, None).await
}

/// Polls for a pending approval, and on timeout reports why one never
/// appeared: the blocked `send_async` request's HTTP status and body, plus the
/// daemon's view of the agent, the activity journal, the thread and the
/// approval journal. A missing approval means the turn never reached the ask —
/// this turns an opaque timeout into the exact failure mode.
async fn wait_for_pending_with_send(
    t: &TestApi,
    timeout: Duration,
    send: Option<&mut tokio::task::JoinHandle<HttpResponse>>,
) -> Vec<app_wire::Approval> {
    // The suite runs many tests in parallel, each with its own runtime; a
    // 5 s budget is load-sensitive, so give the approval task at least 15 s.
    let timeout = timeout.max(Duration::from_secs(15));
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
    let diagnostics = match send {
        Some(send) => approval_timeout_diagnostics(t, send).await,
        None => String::new(),
    };
    if !diagnostics.is_empty() {
        // The engine installs the kernel's payload-free panic hook: a panic
        // prints `file:line` and nothing else, so a diagnostic in the panic
        // message never reaches the CI log. Write the report straight to
        // stderr (the hook's own sink, not libtest's captured buffer) before
        // panicking.
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "{diagnostics}");
    }
    panic!("no pending approval appeared within {timeout:?}{diagnostics}");
}

/// Bound one diagnostic body so a huge response cannot drown the panic.
fn clip_body(body: &str, max: usize) -> String {
    if body.len() <= max {
        return body.to_string();
    }
    let mut end = max;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… ({} bytes total)", &body[..end], body.len())
}

/// What the daemon knows when an approval never showed up: the blocked turn
/// request's own response (or that it is still blocked), the agent state, the
/// recent activity, the thread rows and the approval journal.
async fn approval_timeout_diagnostics(
    t: &TestApi,
    send: &mut tokio::task::JoinHandle<HttpResponse>,
) -> String {
    let mut report = String::new();
    // The request that should have produced the approval: bound the wait so a
    // wedged client cannot hold the failure report hostage, then abort.
    match tokio::time::timeout(Duration::from_secs(5), std::pin::Pin::new(&mut *send)).await {
        Ok(Ok(response)) => report.push_str(&format!(
            "turn request: HTTP {} body: {}\n",
            response.status,
            clip_body(&response.body, 2000)
        )),
        Ok(Err(err)) => report.push_str(&format!(
            "turn request: task ended without a response: {err}\n"
        )),
        Err(_) => {
            send.abort();
            report.push_str("turn request: still blocked after 5s (aborted)\n");
        }
    }
    for (label, path) in [
        ("agent state", "/v1/agents/main"),
        ("activity", "/v1/activity?agent=main&limit=10"),
        ("thread messages", "/v1/threads/main/messages?limit=10"),
        ("pending approvals", "/v1/approvals?state=pending"),
    ] {
        let response = get_auth(t, path).await;
        report.push_str(&format!(
            "{label}: HTTP {} {}\n",
            response.status,
            clip_body(&response.body, 2000)
        ));
    }
    for kind in ["approval.pending", "approval.answered", "tool.decision"] {
        report.push_str(&format!(
            "{kind} journal: {:?}\n",
            event_payloads(&t.home, kind)
        ));
    }
    report
}

fn send_async(t: &TestApi, content: &'static str) -> tokio::task::JoinHandle<HttpResponse> {
    let addr = t.addr;
    let token = t.token.clone();
    tokio::spawn(async move {
        call(
            addr,
            "POST",
            "/v1/threads/main/messages",
            Some(&token),
            Some(content),
        )
        .await
    })
}

/// Like [`send_async`], but the blocking client outwaits a server that is
/// deliberately held open until its own turn timeout (the `504`), instead of
/// the default 10 s read the client would otherwise enforce.
fn send_async_with_read_timeout(
    t: &TestApi,
    content: &'static str,
    read_timeout: Duration,
) -> tokio::task::JoinHandle<HttpResponse> {
    let addr = t.addr;
    let token = t.token.clone();
    tokio::spawn(async move {
        tokio::task::spawn_blocking(move || {
            common::http_with_read_timeout(
                addr,
                "POST",
                "/v1/threads/main/messages",
                Some(&token),
                Some(content),
                read_timeout,
            )
        })
        .await
        .unwrap()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allow_once_approval_runs_the_tool_and_events_flow() {
    let mut t = start_approval_api(Duration::from_secs(10)).await;
    let mut ws = ws_connect(t.addr, Some(&t.token)).await.unwrap();

    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending.len(), 1);
    let approval = &pending[0];
    assert_eq!(approval.agent, "main");
    assert_eq!(approval.scope_tool, "write_file");
    assert_eq!(approval.state, app_wire::ApprovalState::Pending);
    assert!(approval.audit_id > 0, "the ask is audited");
    assert!(approval.ts > 0);
    // The card shows a title and a body a person can read: never the
    // arguments, never raw JSON.
    assert_eq!(approval.headline, "Write file");
    let preview = approval.preview.clone().unwrap_or_default();
    assert!(!preview.contains("{\""), "preview: {preview}");
    assert!(!preview.contains("skill_hash"), "preview: {preview}");
    assert!(preview.contains("content:"), "preview: {preview}");

    // `approval.new` arrives over the WS with the app shape.
    let frame = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "approval.new"
    })
    .await
    .expect("no approval.new frame");
    let parsed: app_wire::Frame = serde_json::from_value(frame).unwrap();
    match parsed {
        app_wire::Frame::ApprovalNew { approval: pushed } => {
            assert_eq!(pushed.id, approval.id);
            assert_eq!(pushed.state, app_wire::ApprovalState::Pending);
        }
        other => panic!("expected approval.new, got {other:?}"),
    }

    // Answer allow-once; the blocked turn resumes and the tool runs.
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{}", approval.id),
        r#"{"decision":"allow_once"}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    assert_eq!(
        answer.json()["state"],
        json!({ "state": "allowed", "by": "you", "always": false })
    );

    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let value = response.json();
    let tool_message = value["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("a tool result was persisted");
    assert!(
        tool_message["content"].as_str().unwrap().contains("wrote"),
        "the tool ran: {}",
        tool_message["content"]
    );

    // The pending list is empty and the resolution event was delivered.
    let empty: Vec<app_wire::Approval> =
        serde_json::from_value(get_auth(&t, "/v1/approvals?state=pending").await.json()).unwrap();
    assert!(empty.is_empty());
    let frame = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "approval.resolved" && value["id"] == json!(approval.id)
    })
    .await
    .expect("no approval.resolved frame");
    let parsed: app_wire::Frame = serde_json::from_value(frame).unwrap();
    match parsed {
        app_wire::Frame::ApprovalResolved { state, .. } => {
            assert_eq!(
                state,
                app_wire::ApprovalState::Allowed {
                    by: "you".to_string(),
                    always: false
                }
            );
        }
        other => panic!("expected approval.resolved, got {other:?}"),
    }

    // Both decisions are audited: ask (`approval.pending`) and answer.
    let store = t.store();
    assert_eq!(store.event_count("approval.pending").unwrap(), 1);
    assert_eq!(store.event_count("approval.answered").unwrap(), 1);

    t.stop();
}

/// The `edit` decision is a first-class answer, not a bypass: the broker
/// authorizes the **edited** arguments and the engine runs those, the answer
/// carries the same `allowed` response, the draft is stored — scrubbed — on
/// the `approval.answered` row, and the `tool.decision` row names both the
/// An edit whose payload would be shown redacted is refused: the owner never
/// approves a redacted copy of what runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_edit_that_would_be_shown_redacted_is_refused() {
    let t = start_approval_api(Duration::from_secs(10)).await;
    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let id = pending[0].id.clone();

    // The owner edits the arguments to something the card would show
    // redacted: the edit is refused and nothing runs.
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{id}"),
        &json!({
            "decision": "edit",
            "text": r#"{"path":"out.txt","content":"password=Fict1onal-Pw-42"}"#
        })
        .to_string(),
    )
    .await;
    assert_eq!(answer.status, 409, "body: {}", answer.body);
    assert!(
        answer.body.contains("cannot be shown for approval"),
        "the refusal says why: {}",
        answer.body
    );
    // The ask is still pending: the owner can edit it again or refuse it.
    let pending = get_auth(&t, "/v1/approvals?state=pending").await.json();
    assert_eq!(pending[0]["id"], id.as_str(), "{pending}");
    let _ = tokio::time::timeout(Duration::from_secs(2), send).await;
}

/// A `mail_send` the daemon can ask about: the card is built from the tool's
/// arguments, and the SMTP path is not reached in this test.
struct FakeMailSend;

#[async_trait]
impl Tool for FakeMailSend {
    fn class(&self) -> ToolClass {
        ToolClass::default()
    }

    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B20
    }

    fn name(&self) -> &str {
        "mail_send"
    }

    fn risk(&self) -> Risk {
        Risk::High
    }

    fn schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "to": { "type": "array", "items": { "type": "string" } },
                "subject": { "type": "string" },
                "body": { "type": "string" }
            },
            "additionalProperties": false
        })
    }

    async fn run(
        &self,
        _args: &serde_json::Value,
        _ctx: &ToolCtx,
    ) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("sent"))
    }
}

/// The owner edits a mail send and adds a `bcc`: the SMTP path never sends
/// one, so the card could promise a hidden recipient that no message
/// carries. The edit is refused with the reason and the ask stays pending
/// (SEND-REAL-ARGS-1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_edit_that_adds_a_bcc_to_a_mail_send_is_refused() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "mail_send",
                    json!({
                        "to": ["camille@example.test"], "subject": "Hi", "body": "B"
                    }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ));
    let tools: ToolRegistryHook = Arc::new(|registry| {
        registry.register(Box::new(FakeMailSend));
    });
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            tools: Some(tools),
            approval_timeout: Some(Duration::from_secs(10)),
            ..ApiOptions::default()
        }
    })
    .await;
    let mut send = {
        let addr = t.addr;
        let token = t.token.clone();
        tokio::spawn(async move {
            call(
                addr,
                "POST",
                "/v1/threads/mail/messages",
                Some(&token),
                Some(r#"{"content":"send it"}"#),
            )
            .await
        })
    };
    let pending = wait_for_pending_with_send(&t, Duration::from_secs(5), Some(&mut send)).await;
    let id = pending[0].id.clone();

    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{id}"),
        &json!({
            "decision": "edit",
            "text": r#"{"to":["camille@example.test"],"subject":"Hi","body":"B","bcc":["hidden@example.test"]}"#
        })
        .to_string(),
    )
    .await;
    assert_eq!(answer.status, 409, "body: {}", answer.body);
    assert_eq!(answer.json()["error"]["code"], "edited_card_unshowable");
    assert!(
        answer.body.contains("bcc is not supported for mail_send"),
        "the refusal says why: {}",
        answer.body
    );
    // The ask is still pending: the owner can edit it again or refuse it.
    let pending = get_auth(&t, "/v1/approvals?state=pending").await.json();
    assert_eq!(pending[0]["id"], id.as_str(), "{pending}");
    let _ = tokio::time::timeout(Duration::from_secs(2), send).await;
    t.stop();
}

/// requested and the executed payload by SHA-256.
/// The owner edits the arguments: the edit answers like an allow-once.
async fn edit_once(t: &TestApi, id: &str, text: &str) -> HttpResponse {
    let edit = post_auth(
        t,
        &format!("/v1/approvals/{id}"),
        &json!({ "decision": "edit", "text": text }).to_string(),
    )
    .await;
    assert_eq!(edit.status, 200, "body: {}", edit.body);
    edit
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_approval_runs_the_edited_draft_and_audits_both_hashes() {
    let mut t = start_approval_api(Duration::from_secs(10)).await;
    let mut ws = ws_connect(t.addr, Some(&t.token)).await.unwrap();

    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let id = pending[0].id.clone();

    // The model asked to write `out.txt` with "written"; the owner edits the
    // draft to write a different file with different content.
    let edit_text = r#"{"path":"edited.txt","content":"edited draft body"}"#;
    // The edit rebuilds the card: the owner confirms what they wrote.
    let refreshed = get_auth(&t, "/v1/approvals?state=pending").await.json();
    let answer = edit_once(&t, &id, edit_text).await;
    assert_eq!(
        answer.json()["state"],
        json!({ "state": "allowed", "by": "you", "always": false }),
        "edit answers exactly like allow_once"
    );
    let _ = refreshed;

    // The blocked turn resumes and the ask runs under the broker.
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);

    // The edited draft is what executed: the new file exists with the new
    // content, and the file the model originally asked for was never written.
    let workspace = aux_engine::workspace_dir(&t.home, "main");
    assert_eq!(
        std::fs::read_to_string(workspace.join("edited.txt")).unwrap(),
        "edited draft body",
        "the edited arguments must be what runs"
    );
    assert!(
        !workspace.join("out.txt").exists(),
        "the original arguments must not run"
    );

    // `approval.resolved` says allowed, like allow-once.
    let frame = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "approval.resolved" && value["id"] == json!(id)
    })
    .await
    .expect("no approval.resolved frame");
    assert_eq!(
        frame["state"],
        json!({ "state": "allowed", "by": "you", "always": false })
    );

    // Exactly one answer row, marked `edit`, carrying the edited draft.
    let answered = event_payloads(&t.home, "approval.answered");
    assert_eq!(answered.len(), 1, "one answer row: {answered:?}");
    let row: Value = serde_json::from_str(&answered[0]).unwrap();
    assert_eq!(row["decision"], "edit");
    assert_eq!(row["by"], "you");
    assert_eq!(row["always"], json!(false));
    assert_eq!(row["edited_text"], edit_text);

    assert_eq!(t.store().event_count("approval.pending").unwrap(), 1);

    // The broker's decision names both payloads by SHA-256 and stores neither.
    let decisions = event_payloads(&t.home, "tool.decision");
    assert_eq!(decisions.len(), 1, "one broker row: {decisions:?}");
    let decision: Value = serde_json::from_str(&decisions[0]).unwrap();
    assert_eq!(decision["outcome"], "allowed");
    let original_hash = decision["original_args_sha256"]
        .as_str()
        .expect("the requested payload hash");
    let executed_hash = decision["executed_args_sha256"]
        .as_str()
        .expect("the executed payload hash");
    assert_eq!(original_hash.len(), 64, "SHA-256 hex: {original_hash}");
    assert_eq!(executed_hash.len(), 64, "SHA-256 hex: {executed_hash}");
    assert_ne!(
        original_hash, executed_hash,
        "the requested and executed payloads differ"
    );
    assert!(
        !decisions[0].contains("edited draft body") && !decisions[0].contains("out.txt"),
        "the decision row must not store either payload: {}",
        decisions[0]
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_edited_draft_does_not_echo_its_path_in_the_tool_error() {
    let provider = approval_provider();
    let mut t = start_approval_api_with(provider.clone(), Duration::from_secs(10)).await;
    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let id = pending[0].id.clone();

    let answer = edit_once(
        &t,
        &id,
        r#"{"path":"../DRAFTMARK9271","content":"edited draft body"}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);

    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let response_value = response.json();
    let tool_message = response_value["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("a failed tool result was persisted");
    let tool_content = tool_message["content"].as_str().unwrap();
    assert!(tool_content.contains("L'outil n'a pas pu utiliser le brouillon modifié."));
    assert!(!tool_content.contains("DRAFTMARK9271"), "{tool_content}");

    let requests = provider.requests();
    assert_eq!(
        requests.len(),
        2,
        "the model was asked for its next response"
    );
    let next_request = serde_json::to_string(&requests[1]).unwrap();
    assert!(
        !next_request.contains("DRAFTMARK9271"),
        "the edited path must not enter the next model request: {next_request}"
    );

    let receipts = event_payloads(&t.home, "run.finished");
    assert_eq!(receipts.len(), 1);
    let receipt: Value = serde_json::from_str(&receipts[0]).unwrap();
    let tool_failure = receipt["could_not_verify"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .find(|entry| entry.contains("outside_workspace"))
        .expect("owner receipt retains the typed, value-free tool error kind");
    assert!(!tool_failure.contains("DRAFTMARK9271"), "{tool_failure}");

    t.stop();
}

#[tokio::test]
async fn a_failed_later_round_keeps_the_run_evidence_in_its_receipt() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![ChatResponse::new(ChatMessage::assistant_with_tool_calls(
            "",
            vec![
                ProviderToolCall::new("call_1", "read_file", json!({"path":"note.txt"})),
                ProviderToolCall::new("call_2", "skill__brief", json!({})),
            ],
        ))],
    ));
    let scripted = Arc::clone(&provider);
    let mut t = TestApi::start_with(move |home| {
        let config = FAKE_CONFIG.replace("privacy.mode = \"open\"", "privacy.mode = \"private\"");
        std::fs::write(config_path(home), config).unwrap();
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            workspace.join("note.txt"),
            "Camille Exemple can be reached at camille@exemple.fr.",
        )
        .unwrap();
        let mut contacts = kernel_privacy::ContactIndex::new();
        assert!(contacts
            .add_from_header("Camille Exemple", "camille@exemple.fr")
            .is_some());
        let (events, _receiver) = tokio::sync::broadcast::channel(16);
        let runner = auxd::api::EngineTurnRunner::new(home)
            .with_provider(Arc::clone(&scripted) as Arc<dyn aux_providers::ChatProvider>)
            .with_contacts(Arc::new(contacts))
            .with_events(events);
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            runner: Some(Arc::new(runner)),
            ..ApiOptions::default()
        }
    })
    .await;

    let failed = post_auth(
        &t,
        "/v1/threads/main/messages",
        r#"{"content":"Read the contact note and tell me who it names."}"#,
    )
    .await;
    assert_error(&failed, 502, "provider_error");
    assert_eq!(
        provider.request_count(),
        2,
        "one response, then a failed round"
    );
    assert!(
        serde_json::to_string(&provider.requests())
            .unwrap()
            .contains("EMAIL_"),
        "provider did not receive the e-mail token"
    );

    let raw = event_payloads(&t.home, "run.finished");
    assert_eq!(raw.len(), 1);
    let receipt: Value = serde_json::from_str(&raw[0]).unwrap();
    assert_eq!(receipt["status"], "failed");
    assert_eq!(receipt["agent"], "main");
    assert!(
        receipt["skills"]
            .as_array()
            .unwrap()
            .iter()
            .any(|skill| skill == "brief"),
        "{receipt}"
    );
    let replacements = receipt["replaced_values"].as_object().unwrap();
    assert!(
        replacements.values().all(|count| count.as_u64().is_some()),
        "{receipt}"
    );
    assert!(!raw[0].contains("camille@exemple.fr"), "{raw:?}");

    t.stop();
}

#[cfg(feature = "l1-fetch")]
/// `[web]` stays at its default `open_read`, where an unseen host is silent
/// unless the turn carries private data or untrusted content. Both EventKit
/// tools and `http_fetch` have explicit allow rules, so only the egress rule
/// can raise the fetch to a card.
const EVENTKIT_FETCH_CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "main"
approvals = "ask"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"

[[rules]]
agent = "main"
tool = "apple_calendar_list_events"
action = "allow"

[[rules]]
agent = "main"
tool = "http_fetch"
action = "allow"
"#;

/// An EventKit calendar read sets the conversation's private-data mark, so a
/// later fetch to an unseen host asks despite its allow rule. The read output
/// is untrusted too, so the card has two possible causes; the `web.fetch`
/// audit row checks the private-data mark on its own.
#[cfg(feature = "l1-fetch")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_eventkit_read_marks_the_turn_private_before_an_unseen_fetch() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "apple_calendar_list_events",
                    json!({}),
                )],
            )),
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_2",
                    "http_fetch",
                    json!({ "url": "https://example.invalid/page" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ));
    let mut t =
        start_approval_api_with_config(EVENTKIT_FETCH_CONFIG, provider, Duration::from_secs(10))
            .await;
    // Fake snapshot only: one calendar entry with a marker title.
    let snapshot = auxd::apple_eventkit::EventKitSnapshot {
        authorized: true,
        events: vec![auxd::apple_eventkit::EventItem {
            id: None,
            attendees: None,
            calendar_id: None,
            recurring: None,
            title: "EVENTKIT-FAKE-7312".into(),
            start: "2026-10-10T09:00:00Z".into(),
            end: "2026-10-10T10:00:00Z".into(),
            all_day: None,
            calendar: "Fake".into(),
            location: None,
        }],
        reminders: vec![],
        ..Default::default()
    };
    auxd::apple_eventkit::save_snapshot(&t.home, &snapshot).unwrap();

    let send = send_async(&t, r#"{"content":"read my calendar, then fetch the page"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0].scope_tool, "http_fetch", "{pending:?}");
    let id = pending[0].id.clone();
    let answer = post_auth(&t, &format!("/v1/approvals/{id}"), r#"{"decision":"deny"}"#).await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);

    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let body = response.json();
    let tool_outputs: Vec<String> = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "tool")
        .map(|message| message["content"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        tool_outputs
            .iter()
            .any(|output| output.contains("EVENTKIT-FAKE-7312")),
        "the calendar read ran under its allow rule: {tool_outputs:?}"
    );

    // The private-data mark is on the fetch's audit row: the host is the
    // unseen one, and `carries_private_data` is set by the calendar read.
    let fetches = event_payloads(&t.home, "web.fetch");
    assert!(
        fetches
            .iter()
            .any(|row| row.contains("example.invalid")
                && row.contains("\"carries_private_data\":true")),
        "the calendar read must set the private-data mark: {fetches:?}"
    );
    t.stop();
}

/// An edit can never widen the argument-dependent policy: the substituted URL
/// is re-checked by the web egress gate before any socket, and a host the
/// policy hard-denies is refused and traced.
#[cfg(feature = "l1-fetch")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_to_a_denied_url_is_refused() {
    let mut t =
        start_approval_api_with_config(WEB_FAKE_CONFIG, fetch_provider(), Duration::from_secs(10))
            .await;
    let send = send_async(&t, r#"{"content":"fetch it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let id = pending[0].id.clone();

    // The card asked about `example.invalid`; the owner edits it to a host
    // the config denies outright.
    let answer = edit_once(&t, &id, r#"{"url":"https://blocked.example/page"}"#).await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);

    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let tool_message = response.json()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .cloned()
        .expect("a tool result was persisted");
    assert!(
        tool_message["content"]
            .as_str()
            .unwrap()
            .contains("web egress policy"),
        "the denied URL must be refused by policy: {}",
        tool_message["content"]
    );

    // The refusal is traced: a `web.fetch` row names the blocked host.
    let fetches = event_payloads(&t.home, "web.fetch");
    assert!(
        fetches
            .iter()
            .any(|row| row.contains("blocked.example") && row.contains("deny:")),
        "the denied fetch must be audited: {fetches:?}"
    );
    t.stop();
}

/// Expiry stays a refusal for `edit` exactly as for allow/deny: once the
/// bounded wait drops the pending, a late edit is a clean `404` and no `edit`
/// answer is audited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edit_on_an_expired_approval_is_refused() {
    let mut t = start_approval_api(Duration::from_secs(1)).await;
    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let id = pending[0].id.clone();

    // Nobody answers: the turn completes with a denied tool and the pending
    // is dropped by the fail-closed expiry.
    let response = tokio::time::timeout(Duration::from_secs(10), send)
        .await
        .expect("the turn must not hang")
        .unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);

    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{id}"),
        r#"{"decision":"edit","text":"too late"}"#,
    )
    .await;
    assert_error(&answer, 404, "approval_not_found");
    assert!(
        !event_payloads(&t.home, "approval.answered")
            .iter()
            .any(|row| row.contains("\"decision\":\"edit\"")),
        "a refused edit must not be audited as an answer"
    );
    assert_eq!(
        get_auth(&t, "/v1/approvals?state=pending").await.json(),
        json!([])
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_blocks_the_tool_but_the_turn_finishes() {
    let mut t = start_approval_api(Duration::from_secs(10)).await;
    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;

    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"deny"}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    assert_eq!(
        answer.json()["state"],
        json!({ "state": "denied", "by": "you" })
    );

    let response = send.await.unwrap();
    assert_eq!(
        response.status, 200,
        "a denied tool is reported to the model"
    );
    let value = response.json();
    let tool_message = value["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("a tool result was persisted");
    let content = tool_message["content"].as_str().unwrap();
    assert!(content.contains("denied"), "blocked: {content}");

    // The broker audited the denial.
    let payloads = event_payloads(&t.home, "tool.decision");
    assert_eq!(payloads.len(), 1);
    assert!(
        payloads[0].contains("\"outcome\":\"denied\""),
        "{}",
        payloads[0]
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unanswered_approval_times_out_fail_closed() {
    let mut t = start_approval_api(Duration::from_millis(150)).await;
    let mut ws = ws_connect(t.addr, Some(&t.token)).await.unwrap();

    let send = send_async(&t, r#"{"content":"write it"}"#);
    // Nobody answers: the turn must come back with a denied tool.
    let response = tokio::time::timeout(Duration::from_secs(10), send)
        .await
        .expect("the turn must not hang")
        .unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let value = response.json();
    let tool_message = value["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("a tool result was persisted");
    assert!(
        tool_message["content"].as_str().unwrap().contains("denied"),
        "timeout is a deny"
    );

    let empty: Vec<app_wire::Approval> =
        serde_json::from_value(get_auth(&t, "/v1/approvals?state=pending").await.json()).unwrap();
    assert!(empty.is_empty(), "the pending entry was dropped");

    let frame = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "approval.resolved"
    })
    .await
    .expect("no approval.resolved frame");
    assert_eq!(frame["state"], json!({ "state": "expired" }));

    // The timeout is audited as an answered decision.
    let payloads = event_payloads(&t.home, "approval.answered");
    assert_eq!(payloads.len(), 1);
    assert!(
        payloads[0].contains("\"decision\":\"timeout\""),
        "{}",
        payloads[0]
    );
    assert_eq!(event_payloads(&t.home, "approval.pending").len(), 1);

    t.stop();
}

/// H-04: `[approval] timeout_secs` from `config.toml` reaches the approval
/// registry (no `ApiOptions` pin), and expiry stays DENY. The turn timeout is
/// pinned well above it so the approval's own expiry wins, not the 504.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_approval_timeout_comes_from_config_and_expiry_stays_deny() {
    let provider = approval_provider();
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        // Turn timeout large; approval timeout tiny. Both un-pinned in
        // ApiOptions, so both must come from the file.
        let mut config = std::fs::read_to_string(config_path(home)).unwrap();
        config.push_str("\nturn_timeout_secs = 600\n\n[approval]\ntimeout_secs = 1\n");
        std::fs::write(config_path(home), config).unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            approval_timeout: None,
            turn_timeout: None,
            ..ApiOptions::default()
        }
    })
    .await;

    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending[0].scope_tool, "write_file");

    // Nobody answers: the 1 s configured wait must fire and deny; the turn
    // keeps running to its final answer (no 504).
    let response = tokio::time::timeout(Duration::from_secs(10), send)
        .await
        .expect("the turn must finish after the approval expiry")
        .unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let tool_message = response.json()["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .cloned()
        .expect("a tool result was persisted");
    assert!(
        tool_message["content"].as_str().unwrap().contains("denied"),
        "expiry stays DENY: {}",
        tool_message["content"]
    );
    let answered = event_payloads(&t.home, "approval.answered");
    assert!(
        answered
            .iter()
            .any(|row| row.contains("\"decision\":\"timeout\"")),
        "the configured expiry is audited: {answered:?}"
    );

    // The approval card is gone and the tool never ran.
    assert!(!aux_engine::workspace_dir(&t.home, "main")
        .join("out.txt")
        .exists());
    assert!(get_auth(&t, "/v1/approvals?state=pending")
        .await
        .json()
        .as_array()
        .unwrap()
        .is_empty());
    t.stop();
}

/// H-04: a hand-edited `[approval] timeout_secs` at or above the turn timeout
/// is clamped strictly below it, so the failure is the approval expiry (deny),
/// never a generic turn-timeout cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_approval_timeout_at_the_turn_timeout_is_clamped_below_it() {
    let provider = approval_provider();
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut config = std::fs::read_to_string(config_path(home)).unwrap();
        // Deliberately bad: the approval wait equals the turn timeout.
        config.push_str("\nturn_timeout_secs = 4\n\n[approval]\ntimeout_secs = 4\n");
        std::fs::write(config_path(home), config).unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            approval_timeout: None,
            turn_timeout: None,
            ..ApiOptions::default()
        }
    })
    .await;

    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending[0].scope_tool, "write_file");

    // The clamped 3 s approval expiry must deny the tool and the turn must
    // answer 200 (not 504): the turn's own timeout never fires first.
    let response = tokio::time::timeout(Duration::from_secs(10), send)
        .await
        .expect("the turn must finish after the approval expiry")
        .unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let answered = event_payloads(&t.home, "approval.answered");
    assert!(
        answered
            .iter()
            .any(|row| row.contains("\"decision\":\"timeout\"")),
        "the clamped expiry is audited: {answered:?}"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn allow_always_persists_a_rule_for_the_next_turn() {
    // Four responses: two turns × (tool call + final answer). `write_file` is
    // effectful, so with no rule it asks — the kept protection H-02 leaves
    // untouched.
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "write_file",
                    json!({ "path": "out.txt", "content": "first" }),
                )],
            )),
            ChatResponse::assistant("done"),
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_2",
                    "write_file",
                    json!({ "path": "out.txt", "content": "second" }),
                )],
            )),
            ChatResponse::assistant("done again"),
        ],
    ));
    let mut t = start_approval_api_with(provider.clone(), Duration::from_secs(10)).await;
    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;

    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"main"}}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    assert_eq!(
        answer.json()["state"],
        json!({ "state": "allowed", "by": "you", "always": true })
    );
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);

    // The rule is in config.toml, last, and the next turn skips the ask.
    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert!(config.contains("[[rules]]"), "{config}");
    assert!(config.contains("tool = \"write_file\""), "{config}");
    let rules = aux_engine::load_rules(&config_path(&t.home)).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].action, kernel_broker::Action::Allow);

    let second = send_async(&t, r#"{"content":"write again"}"#);
    let response = tokio::time::timeout(Duration::from_secs(10), second)
        .await
        .expect("the second turn must not wait for a human")
        .unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(provider.request_count(), 4, "both turns completed");
    let value = response.json();
    let tool_message = value["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("the auto-allowed tool ran");
    assert!(
        tool_message["content"].as_str().unwrap().contains("wrote"),
        "the tool ran: {}",
        tool_message["content"]
    );
    let pending: Vec<app_wire::Approval> =
        serde_json::from_value(get_auth(&t, "/v1/approvals?state=pending").await.json()).unwrap();
    assert!(pending.is_empty(), "the allow rule skipped the ask");

    t.stop();
}

/// Provider script: one `write_file` call, then a final answer.
fn tainted_write_provider() -> Arc<FakeProvider> {
    Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "write_file",
                    json!({ "path": "out.txt", "content": "hi" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tainted_conversation_refuses_allow_always() {
    let mut t = start_approval_api_with(tainted_write_provider(), Duration::from_secs(10)).await;
    // Seed the workspace mark directly: W1 correctly rejects localhost URLs
    // before broker authorization, so using a loopback http_fetch here would
    // no longer create taint or an approval card. This keeps the test
    // deterministic and offline while exercising the tainted approval path.
    let (_workspace, key) = agent_workspace(&t, "main");
    t.store()
        .mark_workspace_tainted(&key, "http_fetch: https://example.invalid/")
        .unwrap();
    let send = send_async(&t, r#"{"content":"write after untrusted content"}"#);

    // The workspace is already tainted, so write_file must ask even though
    // there is no matching rule.
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    let write = &pending[0];
    assert_eq!(write.scope_tool, "write_file");
    assert_eq!(
        write.taint.as_deref(),
        Some("workspace: http_fetch: https://example.invalid/"),
        "the approval card shows the persisted taint source"
    );

    // "Always allow" is refused server-side (the app greys the button too).
    let refused = post_auth(
        &t,
        &format!("/v1/approvals/{}", write.id),
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"main"}}"#,
    )
    .await;
    assert_error(&refused, 409, "tainted_approval");
    let still: Vec<app_wire::Approval> =
        serde_json::from_value(get_auth(&t, "/v1/approvals?state=pending").await.json()).unwrap();
    assert_eq!(
        still.len(),
        1,
        "a refused answer must leave the ask pending"
    );

    // A one-shot approval still works, and no allow rule is written.
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{}", write.id),
        r#"{"decision":"allow_once"}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "body: {}", answer.body);
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert!(
        !config.contains("write_file"),
        "taint wrote no rule: {config}"
    );

    // Approval audit rows record the taint state and the source.
    let payloads = event_payloads(&t.home, "approval.pending");
    assert_eq!(payloads.len(), 1);
    assert!(payloads[0].contains("\"tainted\":true"), "{}", payloads[0]);
    assert!(payloads[0].contains("http_fetch"), "{}", payloads[0]);

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unsandboxed_shell_asks_first_and_refuses_allow_always() {
    // P1 regression (security-review round 5): `[shell] sandbox = false` +
    // `allow_unsandboxed = true` with an `allow shell` rule. The first call
    // must ask (no taint mark is involved), the card must carry
    // `unsandboxed: true`, and `allow_always` must be refused with the same
    // 409 shape as a tainted ask.
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "shell",
                    json!({ "command": "touch ran.txt" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ));
    let provider_for_options = Arc::clone(&provider);
    let mut t = TestApi::start_with(move |home| {
        let mut config = std::fs::read_to_string(config_path(home)).unwrap();
        config.push_str(
            "\n[[rules]]\ndot = \"main\"\ntool = \"shell\"\naction = \"allow\"\n\
             \n[shell]\nsandbox = false\nallow_unsandboxed = true\n",
        );
        std::fs::write(config_path(home), config).unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider_for_options),
            approval_timeout: Some(Duration::from_secs(10)),
            ..ApiOptions::default()
        }
    })
    .await;

    let send = send_async(&t, r#"{"content":"run it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending.len(), 1, "the allow rule must not skip the ask");
    assert_eq!(pending[0].scope_tool, "shell");

    // The raw card carries the unsandboxed marker and says so in prose.
    let listed = get_auth(&t, "/v1/approvals?state=pending").await;
    let frame = &listed.json()[0];
    assert_eq!(frame["unsandboxed"], json!(true), "frame: {frame}");
    assert!(
        frame["why"].as_str().unwrap().contains("unsandboxed"),
        "frame: {frame}"
    );

    // `allow_always` is refused server-side, exactly like a tainted ask.
    let refused = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"allow_always","scope":{"tool":"shell","agent":"main"}}"#,
    )
    .await;
    assert_error(&refused, 409, "unsandboxed_approval");
    let still: Vec<app_wire::Approval> =
        serde_json::from_value(get_auth(&t, "/v1/approvals?state=pending").await.json()).unwrap();
    assert_eq!(still.len(), 1, "a refused answer leaves the ask pending");

    // Deny it: the command must never run, and no rule is written.
    let denied = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"deny"}"#,
    )
    .await;
    assert_eq!(denied.status, 200, "body: {}", denied.body);
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert!(
        !aux_engine::workspace_dir(&t.home, "main")
            .join("ran.txt")
            .exists(),
        "the denied unsandboxed command must not run"
    );
    let rules = aux_engine::load_rules(&config_path(&t.home)).unwrap();
    assert_eq!(rules.len(), 1, "only the pre-existing rule stays");
    assert_eq!(rules[0].tool, "shell");

    // The pending audit row says the ask was unsandboxed.
    let payloads = event_payloads(&t.home, "approval.pending");
    assert_eq!(payloads.len(), 1);
    assert!(
        payloads[0].contains("\"unsandboxed\":true"),
        "{}",
        payloads[0]
    );

    t.stop();
}

/// H-02 end-to-end: a read-only tool with no rule runs without a card (audit
/// row only), while an effectful tool and a tainted turn still ask.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_only_tools_run_free_while_effectful_and_tainted_calls_still_ask() {
    // Round 1: `read_file` (read-only) — no rule anywhere.
    let read_provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "read_file",
                    json!({ "path": "note.txt" }),
                )],
            )),
            ChatResponse::assistant("read done"),
        ],
    ));
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(read_provider),
            approval_timeout: Some(Duration::from_secs(10)),
            ..ApiOptions::default()
        }
    })
    .await;

    let response = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"read it"}"#).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    // No card was raised for the read.
    assert!(
        get_auth(&t, "/v1/approvals?state=pending")
            .await
            .json()
            .as_array()
            .unwrap()
            .is_empty(),
        "a read-only tool must run without an approval card"
    );
    assert_eq!(
        event_payloads(&t.home, "approval.pending").len(),
        0,
        "no approval.pending row for a read"
    );
    // The decision is audited as an allow.
    let decisions = event_payloads(&t.home, "tool.decision");
    assert_eq!(decisions.len(), 1, "{decisions:?}");
    assert!(
        decisions[0].contains("\"tool\":\"read_file\"")
            && decisions[0].contains("\"outcome\":\"allowed\""),
        "the read must be audited as allowed: {}",
        decisions[0]
    );
    t.stop();

    // The effectful half stays as before: `write_file` with no rule asks.
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "write_file",
                    json!({ "path": "out.txt", "content": "written" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ));
    let mut t = start_approval_api_with(provider, Duration::from_secs(10)).await;
    let send = send_async(&t, r#"{"content":"write it"}"#);
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending[0].scope_tool, "write_file");
    let deny = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"deny"}"#,
    )
    .await;
    assert_eq!(deny.status, 200, "body: {}", deny.body);
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    t.stop();
}

/// H-02: taint is never weakened by the read-only default — a tainted turn
/// forces `ask` for the declared read-only `read_file` too, raises an
/// allow-ruled `write_file` to an ask, and refuses `allow_always`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tainted_turn_raises_effectful_and_read_only_calls() {
    // The tainted workspace is seeded directly (below): W1 refuses a loopback
    // `http_fetch` before broker authorization, so it can no longer be the
    // taint source. The `read_file` (read-only, no rule) must still ask while
    // tainted, and the allow-ruled `write_file` must be raised to an ask that
    // refuses "always allow".
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "read_file",
                    json!({ "path": "note.txt" }),
                )],
            )),
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_2",
                    "write_file",
                    json!({ "path": "out.txt", "content": "written" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ));
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
        // The effectful write carries an explicit allow rule: while tainted
        // it must still be raised to an ask (the taint protection).
        let mut config = std::fs::read_to_string(config_path(home)).unwrap();
        config.push_str("\n[[rules]]\ndot = \"main\"\ntool = \"write_file\"\naction = \"allow\"\n");
        std::fs::write(config_path(home), config).unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            approval_timeout: Some(Duration::from_secs(10)),
            ..ApiOptions::default()
        }
    })
    .await;

    // Seed the workspace mark directly: W1 rejects loopback URLs before
    // broker authorization, so a loopback `http_fetch` would create neither a
    // card nor taint. This keeps the test deterministic and offline.
    let (_workspace, key) = agent_workspace(&t, "main");
    t.store()
        .mark_workspace_tainted(&key, "http_fetch: https://example.invalid/")
        .unwrap();
    let send = send_async(&t, r#"{"content":"act while tainted"}"#);

    // The read-only `read_file` has no rule; taint must still force a card.
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending[0].scope_tool, "read_file");
    assert_eq!(
        pending[0].taint.as_deref(),
        Some("workspace: http_fetch: https://example.invalid/"),
        "the read card must name the taint source"
    );
    let read = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"allow_once"}"#,
    )
    .await;
    assert_eq!(read.status, 200, "body: {}", read.body);

    // The tainted, allow-ruled write is raised to an ask.
    let pending = wait_for_pending(&t, Duration::from_secs(5)).await;
    assert_eq!(pending[0].scope_tool, "write_file");
    assert_eq!(
        pending[0].taint.as_deref(),
        Some("workspace: http_fetch: https://example.invalid/"),
        "the write card must name the taint source"
    );

    // "Always allow" is refused on the tainted ask.
    let refused = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"main"}}"#,
    )
    .await;
    assert_error(&refused, 409, "tainted_approval");

    // Allow once: the turn runs to completion; the tainted read and the
    // tainted write both asked (exactly two cards: read, write).
    let allow = post_auth(
        &t,
        &format!("/v1/approvals/{}", pending[0].id),
        r#"{"decision":"allow_once"}"#,
    )
    .await;
    assert_eq!(allow.status, 200, "body: {}", allow.body);
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(
        event_payloads(&t.home, "approval.pending").len(),
        2,
        "the tainted read and the tainted write each asked"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approvals_invalid_requests_are_clean_errors() {
    let mut t = start_approval_api(Duration::from_secs(10)).await;

    let missing = post_auth(&t, "/v1/approvals/ap-nope", "{}").await;
    assert_error(&missing, 400, "missing_decision");
    let unknown = post_auth(&t, "/v1/approvals/ap-nope", r#"{"decision":"allow_once"}"#).await;
    assert_error(&unknown, 404, "approval_not_found");
    let bad = post_auth(&t, "/v1/approvals/ap-nope", r#"{"decision":"maybe"}"#).await;
    assert_error(&bad, 400, "invalid_decision");
    // `edit` is a real decision now, so an unknown id is the same clean 404
    // as any other answer — never a 501.
    let edit = post_auth(
        &t,
        "/v1/approvals/ap-nope",
        r#"{"decision":"edit","text":"safer"}"#,
    )
    .await;
    assert_error(&edit, 404, "approval_not_found");
    let invalid_state = get_auth(&t, "/v1/approvals?state=all").await;
    assert_error(&invalid_state, 400, "invalid_state");

    // Unknown ids never invent a pending entry.
    assert!(get_auth(&t, "/v1/approvals?state=pending")
        .await
        .json()
        .as_array()
        .unwrap()
        .is_empty());

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_drops_pending_with_an_audit_line() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();
    let store = Store::open(&store_path(&home)).unwrap();
    // Two orphaned asks: one never answered, one already answered (must be
    // left alone).
    store
        .log_event(
            "approval.pending",
            r#"{"id":"ap-orphan","agent":"main","tool":"shell","thread_id":1}"#,
        )
        .unwrap();
    store
        .log_event(
            "approval.pending",
            r#"{"id":"ap-answered","agent":"main","tool":"shell","thread_id":1}"#,
        )
        .unwrap();
    store
        .log_event(
            "approval.answered",
            r#"{"id":"ap-answered","decision":"allow_once","by":"you"}"#,
        )
        .unwrap();
    drop(store);

    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let addr = handle.addr();
    let token = std::fs::read_to_string(api::token_path(&home))
        .unwrap()
        .trim()
        .to_string();

    let dropped = event_payloads(&home, "approval.dropped");
    assert_eq!(dropped.len(), 1, "one audit line per orphan");
    assert!(dropped[0].contains("ap-orphan"), "{}", dropped[0]);

    let response = call(
        addr,
        "GET",
        "/v1/approvals?state=pending",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json(), json!([]));

    handle.shutdown();
}

// ---------------------------------------------------------------------------
// stop / resume
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_and_resume_round_trip_including_a_dangling_symlink() {
    let mut t = TestApi::start().await;

    let stop = post_auth(&t, "/v1/stop", "").await;
    assert_eq!(stop.status, 200, "body: {}", stop.body);
    assert_eq!(stop.json(), json!({ "stop": true, "changed": true }));
    assert!(killswitch::is_stopped(&t.home));

    let again = post_auth(&t, "/v1/stop", "").await;
    assert_eq!(again.json(), json!({ "stop": true, "changed": false }));

    // Sending while stopped is a 409 and persists nothing.
    let blocked = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hi"}"#).await;
    assert_error(&blocked, 409, "stopped");
    assert!(t.store().list_sessions().unwrap().is_empty());

    // A dangling symlink occupies the marker path: STILL stopped (fail
    // safe), STOP is idempotent, and RESUME removes the link itself.
    #[cfg(unix)]
    {
        std::fs::remove_file(killswitch::stop_path(&t.home)).unwrap();
        std::os::unix::fs::symlink(
            t.home.join("missing-target"),
            killswitch::stop_path(&t.home),
        )
        .unwrap();
        let stop = post_auth(&t, "/v1/stop", "").await;
        assert_eq!(stop.json(), json!({ "stop": true, "changed": false }));

        let resume = post_auth(&t, "/v1/resume", "").await;
        assert_eq!(resume.json(), json!({ "stop": false, "changed": true }));
        assert!(
            !killswitch::stop_path(&t.home).exists(),
            "resume removes the link, never creates the target"
        );
    }

    let resume = post_auth(&t, "/v1/resume", "").await;
    assert_eq!(resume.json(), json!({ "stop": false, "changed": false }));
    assert!(!killswitch::is_stopped(&t.home));

    // Once resumed, the turn runs.
    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hi"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);

    t.stop();
}

// ---------------------------------------------------------------------------
// activity / usage / jobs
// ---------------------------------------------------------------------------

/// E2 Ledger: a `skill.*` event carries its skill and pinned hash; a hash that
/// is not a plain digest is dropped, and plain rows carry neither field.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activity_rows_carry_the_skill_hash() {
    let mut t = TestApi::start().await;
    let store = t.store();
    store
        .log_event(
            "skill.run",
            r#"{"agent":"main","skill_name":"follow-up-email","skill_hash":"sha256:9f2c41ab","outcome":"done"}"#,
        )
        .unwrap();
    store
        .log_event(
            "skill.action",
            r#"{"agent":"main","skill_name":"slot-reply","skill_hash":"not a <hash>","tool":"mail.send"}"#,
        )
        .unwrap();
    store
        .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
        .unwrap();

    let response = get_auth(&t, "/v1/activity?limit=10").await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let rows = response.json();
    let rows = rows.as_array().unwrap();
    let run = rows.iter().find(|row| row["kind"] == "skill.run").unwrap();
    assert_eq!(run["skill"], "follow-up-email");
    assert_eq!(run["skill_hash"], "sha256:9f2c41ab");
    let action = rows
        .iter()
        .find(|row| row["kind"] == "skill.action")
        .unwrap();
    assert_eq!(action["skill"], "slot-reply");
    assert!(
        action.get("skill_hash").is_none(),
        "a non-digest hash is dropped"
    );
    let started = rows
        .iter()
        .find(|row| row["kind"] == "daemon.started")
        .unwrap();
    assert!(started.get("skill").is_none() && started.get("skill_hash").is_none());

    t.stop();
}

/// E2 Coverage: one row per `PathId::ALL` entry, read through the API.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn coverage_lists_every_privacy_path() {
    let mut t = TestApi::start().await;
    let response = get_auth(&t, "/v1/privacy/coverage").await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let body = response.json();
    let paths = body["paths"].as_array().unwrap();
    assert_eq!(paths.len(), kernel_core::privacy::PathId::ALL.len());
    assert_eq!(paths[0]["id"], "A1");
    assert_eq!(paths[0]["state"], "covered");
    for path in paths {
        let state = path["state"].as_str().unwrap();
        assert!(["covered", "partial", "missed"].contains(&state), "{path}");
        assert!(!path["label"].as_str().unwrap().is_empty(), "{path}");
    }
    let missed = paths
        .iter()
        .filter(|path| path["state"] == "missed")
        .count();
    assert_eq!(body["missed"].as_u64().unwrap() as usize, missed);

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activity_usage_and_jobs_mirror_the_cli() {
    let mut t = TestApi::start().await;
    let store = t.store();
    let session = store.create_session("main", None).unwrap();
    store
        .append_message(session.id, "user", "hello world", None)
        .unwrap();
    store
        .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
        .unwrap();
    store
        .create_job(
            "main",
            "veille",
            "daily 08:30",
            "{}",
            Some("2026-10-04 08:30:00"),
        )
        .unwrap();
    store
        .record_usage_at(
            "main",
            UsageKind::TokensIn,
            5,
            "tokens",
            &format!("{} 08:00:00", store.local_day().unwrap()),
        )
        .unwrap();

    let all = get_auth(&t, "/v1/activity?limit=10").await;
    assert_eq!(all.status, 200, "body: {}", all.body);
    let all_value = all.json();
    let all_kinds: Vec<String> = all_value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["kind"].as_str().unwrap().to_string())
        .collect();
    assert!(
        all_kinds.iter().any(|kind| kind == "daemon.started"),
        "dotless events survive an unfiltered read: {all_kinds:?}"
    );

    let activity = get_auth(&t, "/v1/activity?agent=main&limit=10").await;
    assert_eq!(activity.status, 200, "body: {}", activity.body);
    let entries = activity.json();
    let kinds: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"message.user"));
    let times: Vec<&str> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["at"].as_str().unwrap())
        .collect();
    let mut sorted = times.clone();
    sorted.sort_unstable();
    assert_eq!(times, sorted, "the timeline is ascending");

    let bad_since = get_auth(&t, "/v1/activity?since=yesterday").await;
    assert_error(&bad_since, 400, "invalid_since");
    for query in ["limit=0", "limit=201"] {
        let response = get_auth(&t, &format!("/v1/activity?{query}")).await;
        assert_error(&response, 400, "invalid_limit");
    }

    let usage = get_auth(&t, "/v1/usage?agent=main&period=day").await;
    assert_eq!(usage.status, 200, "body: {}", usage.body);
    let usage = usage.json();
    assert_eq!(usage["period"], "day");
    assert_eq!(usage["agents"][0]["agent"], "main");
    assert_eq!(usage["agents"][0]["totals"]["tokens_in"], 5);
    assert_eq!(usage["total"]["tokens_in"], 5);

    let bad_period = get_auth(&t, "/v1/usage?period=week").await;
    assert_error(&bad_period, 400, "invalid_period");
    let bad_day = get_auth(&t, "/v1/usage?day=2026-02-30").await;
    assert_error(&bad_day, 400, "invalid_day");

    let jobs = get_auth(&t, "/v1/jobs").await;
    assert_eq!(jobs.status, 200);
    let jobs = jobs.json();
    assert_eq!(jobs[0]["agent"], "main");
    assert_eq!(jobs[0]["name"], "veille");
    assert_eq!(jobs[0]["schedule"], "daily 08:30");
    assert_eq!(jobs[0]["enabled"], true);
    assert_eq!(jobs[0]["next_run_at"], "2026-10-04 08:30:00");

    t.stop();
}

// ---------------------------------------------------------------------------
// sanitized errors
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_bodies_never_leak_paths_tokens_or_keys() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();

    let planted = format!(
        "boom at {}/store.db AUX_KEY_FAKE=sk-canary-123456 and sk-ant-9xyz",
        home.display()
    );
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            runner: Some(Arc::new(FailingTurnRunner::new(planted))),
            provider: None,
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let addr = handle.addr();
    let token = std::fs::read_to_string(api::token_path(&home))
        .unwrap()
        .trim()
        .to_string();

    let failed = call(
        addr,
        "POST",
        "/v1/threads/main/messages",
        Some(&token),
        Some(r#"{"content":"hi"}"#),
    )
    .await;
    assert_error(&failed, 502, "provider_error");
    let home_text = home.display().to_string();
    assert!(
        !failed.body.contains(&home_text),
        "path leaked: {}",
        failed.body
    );
    assert!(
        !failed.body.contains("sk-canary-123456"),
        "key leaked: {}",
        failed.body
    );
    assert!(
        failed.body.contains("AUX_KEY_FAKE=<redacted>"),
        "env value must be redacted while the key stays readable: {}",
        failed.body
    );
    assert!(
        failed.body.contains("<home>"),
        "the path is replaced, not dropped: {}",
        failed.body
    );

    let unauthorized = call(addr, "GET", "/v1/agents", None, None).await;
    assert_error(&unauthorized, 401, "unauthorized");
    assert!(!unauthorized.body.contains(&token));

    let unknown = call(addr, "GET", "/v1/nope", Some(&token), None).await;
    assert_error(&unknown, 404, "not_found");
    assert!(!unknown.body.contains(&home_text));

    handle.shutdown();
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/// The app-facing `WireEvent`/`Message`/`ToolCall` shapes (the live contract
/// the SwiftUI client in `apps/auxesis-mac` decodes).
#[allow(dead_code)] // every field is part of the copied contract
mod app_wire {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(tag = "type")]
    pub enum Frame {
        #[serde(rename = "agent.state")]
        AgentState {
            agent: String,
            state: AgentState,
            #[serde(default)]
            status: Option<String>,
            #[serde(default)]
            status_short: Option<String>,
            #[serde(default)]
            waiting: Option<u32>,
            #[serde(default)]
            budget_used: Option<f32>,
            #[serde(default)]
            budget_hit: Option<bool>,
        },
        #[serde(rename = "message.new")]
        MessageNew { message: Message },
        #[serde(rename = "message.done")]
        MessageDone {
            thread_id: String,
            message_id: String,
        },
        #[serde(rename = "tool.start")]
        ToolStart {
            thread_id: String,
            message_id: String,
            call: ToolCall,
        },
        #[serde(rename = "tool.end")]
        ToolEnd {
            thread_id: String,
            message_id: String,
            index: usize,
            call: ToolCall,
            #[serde(default)]
            tokens: u32,
            #[serde(default)]
            cost_cents: f32,
        },
        #[serde(rename = "approval.new")]
        ApprovalNew { approval: Approval },
        #[serde(rename = "approval.resolved")]
        ApprovalResolved { id: String, state: ApprovalState },
    }

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum AgentState {
        Idle,
        Thinking,
        Working,
        NeedsYou,
        Paused,
        Killed,
    }

    #[derive(Debug, Deserialize)]
    pub struct Message {
        pub id: String,
        pub thread_id: String,
        pub author: Author,
        pub ts: i64,
        pub blocks: Vec<Block>,
        #[serde(default)]
        pub streaming: bool,
        #[serde(default)]
        pub pending: bool,
    }

    #[derive(Debug, PartialEq, Deserialize)]
    #[serde(tag = "kind", content = "id", rename_all = "snake_case")]
    pub enum Author {
        You,
        Agent(String),
        System,
        /// UMF-05: a tool-role result has its own author, never `system`.
        Tool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum Block {
        Text { text: String },
    }

    #[derive(Debug, Deserialize)]
    pub struct ToolCall {
        pub tool: String,
        pub args: String,
        #[serde(default)]
        pub duration_ms: Option<u32>,
        #[serde(default)]
        pub result_preview: Option<String>,
        #[serde(default)]
        pub audit_id: Option<u64>,
        #[serde(default)]
        pub ok: Option<bool>,
    }

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
        pub preview: Option<String>,
        #[serde(default)]
        pub detail: Vec<String>,
        pub why: String,
        pub scope_tool: String,
        pub scope_rule: String,
        #[serde(default)]
        pub taint: Option<String>,
        #[serde(default)]
        pub destructive: bool,
        #[serde(default)]
        pub state: ApprovalState,
    }

    #[derive(Debug, Default, PartialEq, Deserialize)]
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

/// Config with the read_file rule allowed, so the tool loop runs without an
/// approval.
const LIVE_CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "main"
approvals = "ask"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"

[[rules]]
agent = "main"
tool = "read_file"
action = "allow"
"#;

/// Collects the app-shaped live frames of one turn, in arrival order, until
/// `message.done` and the trailing `agent.state idle` are seen.
async fn collect_turn_frames(ws: &mut Ws, timeout: Duration) -> Vec<Value> {
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut saw_done = false;
    while tokio::time::Instant::now() < deadline {
        let Some(value) = next_ws_json(ws, Duration::from_millis(500)).await else {
            continue;
        };
        let kind = value["type"].as_str().unwrap_or_default();
        let turn_frame = matches!(
            kind,
            "message.new" | "message.done" | "tool.start" | "tool.end"
        ) || (kind == "agent.state" && value["state"].is_string());
        if !turn_frame {
            continue;
        }
        saw_done |= kind == "message.done";
        let idle = kind == "agent.state" && value["state"] == "idle";
        frames.push(value);
        if saw_done && idle {
            break;
        }
    }
    frames
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_streams_the_ordered_live_turn_events_with_app_shapes() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "read_file",
                    json!({ "path": "note.txt" }),
                )],
            )),
            ChatResponse::assistant("all done"),
        ],
    ));
    let scripted = Arc::clone(&provider);
    let mut t = TestApi::start_with(move |home| {
        std::fs::write(config_path(home), LIVE_CONFIG).unwrap();
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            runner: None,
            provider: Some(scripted),
            ..ApiOptions::default()
        }
    })
    .await;

    let mut ws = ws_connect(t.addr, Some(&t.token)).await.unwrap();
    // Drain the connect-time agent snapshots so the turn stream starts clean.
    tokio::time::sleep(Duration::from_millis(150)).await;
    while next_ws_json(&mut ws, Duration::from_millis(30))
        .await
        .is_some()
    {}

    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"read it"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert_eq!(provider.request_count(), 2, "tool round + final answer");

    let frames = collect_turn_frames(&mut ws, Duration::from_secs(10)).await;
    let kinds: Vec<String> = frames
        .iter()
        .map(|frame| frame["type"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        kinds,
        vec![
            "agent.state", // thinking
            "message.new", // user echo
            "message.new", // assistant with the tool call
            "tool.start",
            "agent.state", // working
            "tool.end",
            "agent.state", // thinking
            "message.new", // tool result
            "message.new", // final assistant
            "message.done",
            "agent.state", // idle
        ],
        "frames: {frames:#?}"
    );
    assert_eq!(frames[0]["state"], "thinking");
    assert_eq!(frames[4]["state"], "working");
    assert_eq!(frames[6]["state"], "thinking");
    assert_eq!(frames[10]["state"], "idle");

    // Every frame deserializes with the app's exact serde shapes.
    let parsed: Vec<app_wire::Frame> = frames
        .iter()
        .map(|frame| serde_json::from_value(frame.clone()).expect("app shape"))
        .collect();
    match &parsed[0] {
        app_wire::Frame::AgentState { state, agent, .. } => {
            assert_eq!(agent, "main");
            assert_eq!(state, &app_wire::AgentState::Thinking);
        }
        other => panic!("expected agent.state, got {other:?}"),
    }
    let thread_id = match &parsed[1] {
        app_wire::Frame::MessageNew { message } => {
            assert_eq!(message.author, app_wire::Author::You);
            assert!(message.ts > 0, "unix ms timestamps");
            match &message.blocks[0] {
                app_wire::Block::Text { text } => assert_eq!(text, "read it"),
            }
            message.thread_id.clone()
        }
        other => panic!("expected message.new, got {other:?}"),
    };
    match &parsed[2] {
        app_wire::Frame::MessageNew { message } => {
            assert_eq!(message.author, app_wire::Author::Agent("main".to_string()));
            assert_eq!(message.thread_id, thread_id);
        }
        other => panic!("expected message.new, got {other:?}"),
    }
    match &parsed[3] {
        app_wire::Frame::ToolStart {
            thread_id: thread,
            call,
            ..
        } => {
            assert_eq!(thread, &thread_id);
            assert_eq!(call.tool, "read_file");
            assert!(call.args.contains("note.txt"), "args: {}", call.args);
            assert_eq!(call.ok, None, "ok is unknown before the decision");
        }
        other => panic!("expected tool.start, got {other:?}"),
    }
    match &parsed[5] {
        app_wire::Frame::ToolEnd {
            call,
            index,
            tokens,
            ..
        } => {
            assert_eq!(*index, 0);
            assert_eq!(call.tool, "read_file");
            assert_eq!(call.ok, Some(true));
            assert_eq!(call.result_preview.as_deref(), Some("hello note"));
            assert_eq!(*tokens, 0);
        }
        other => panic!("expected tool.end, got {other:?}"),
    }
    // UMF-05: the tool-role result is its own author — the app folds it into
    // the run instead of a `System context` line.
    match &parsed[7] {
        app_wire::Frame::MessageNew { message } => {
            assert_eq!(message.author, app_wire::Author::Tool);
        }
        other => panic!("expected the tool result message.new, got {other:?}"),
    }
    match &parsed[9] {
        app_wire::Frame::MessageDone {
            thread_id: thread,
            message_id,
        } => {
            assert_eq!(thread, &thread_id);
            let final_id = match &parsed[8] {
                app_wire::Frame::MessageNew { message } => message.id.clone(),
                other => panic!("expected the final message.new, got {other:?}"),
            };
            assert_eq!(message_id, &final_id);
        }
        other => panic!("expected message.done, got {other:?}"),
    }

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_carries_agent_state_and_journal_events() {
    let mut t = TestApi::start().await;
    let store = t.store();
    let mut ws = ws_connect(t.addr, Some(&t.token)).await.unwrap();

    // On connect the server sends the current snapshot of every agent.
    let initial = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "agent.state" && value["agent"] == "main"
    })
    .await
    .expect("no initial agent.state for main");
    assert_eq!(initial["state"]["name"], "main");
    assert_eq!(initial["state"]["stop"], false);

    // A journal row is carried with kind, agent, seq, summary and payload, and
    // the same row changes the agent's last activity. The two messages can be
    // observed in either order (separate read connections), so collect both.
    store
        .log_event(
            "budget.denied",
            r#"{"agent":"main","reason":"daily cap reached"}"#,
        )
        .unwrap();
    let mut journal = None;
    let mut changed = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while (journal.is_none() || changed.is_none()) && tokio::time::Instant::now() < deadline {
        let slice = Duration::from_millis(500).min(deadline - tokio::time::Instant::now());
        let Some(value) = next_ws_json(&mut ws, slice).await else {
            continue;
        };
        let kind = value["type"].as_str().unwrap_or("").to_string();
        if kind == "budget.denied" {
            journal = Some(value);
        } else if kind == "agent.state"
            && value["state"]["last_activity"]["kind"] == "budget.denied"
        {
            changed = Some(value);
        }
    }
    let journal = journal.expect("no budget.denied event");
    assert_eq!(journal["agent"], "main");
    assert_eq!(journal["summary"], "daily cap reached");
    assert_eq!(journal["payload"]["reason"], "daily cap reached");
    assert!(journal["seq"].as_i64().unwrap() > 0);

    let changed = changed.expect("no agent.state with the new last activity");
    assert_eq!(
        changed["state"]["last_activity"]["summary"],
        "daily cap reached"
    );

    // STOP toggles surface as agent.state too.
    let stopped = post_auth(&t, "/v1/stop", "").await;
    assert_eq!(stopped.status, 200);
    let state = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "agent.state" && value["agent"] == "main" && value["state"]["stop"] == true
    })
    .await
    .expect("no agent.state with stop engaged");
    assert_eq!(state["agent"], "main");

    t.stop();
}

// ---------------------------------------------------------------------------
// F-03: activity + WS scrub the secrets the messages view hides
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activity_and_ws_scrub_secrets_like_the_messages_view() {
    let mut t = TestApi::start().await;
    let store = t.store();
    let session = store.create_session("main", None).unwrap();
    let message = format!(
        "cat {}/agents/main/notes.txt && export KEY=ghp_0123456789abcdefghijklmnopqrstuvwx",
        t.home.display()
    );
    store
        .append_message(session.id, "user", &message, None)
        .unwrap();

    // Connect first: the WS only streams journal rows written after the
    // subscription exists (no replay).
    let mut ws = ws_connect(t.addr, Some(&t.token)).await.unwrap();

    // The initial agent.state carries the message as `last_activity`.
    let initial = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "agent.state" && value["agent"] == "main"
    })
    .await
    .expect("no initial agent.state for main");
    let encoded = initial.to_string();
    assert!(
        !encoded.contains("ghp_0123456789abcdefghijklmnopqrstuvwx"),
        "last_activity leaked the canary: {encoded}"
    );
    assert!(
        !encoded.contains(&t.home.display().to_string()),
        "last_activity leaked the home path: {encoded}"
    );

    store
        .log_event(
            "tool.end",
            &json!({
                "agent": "main",
                "summary": "answer used password=hunter2swordfish",
                "detail": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYW5hcnkifQ.abcdefghijklmnop",
            })
            .to_string(),
        )
        .unwrap();

    let journal = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "tool.end"
    })
    .await
    .expect("no tool.end frame");
    let encoded = journal.to_string();
    assert!(!encoded.contains("hunter2swordfish"), "{encoded}");
    assert!(
        !encoded.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        "{encoded}"
    );
    assert!(encoded.contains("<redacted>"), "{encoded}");

    let activity = get_auth(&t, "/v1/activity").await;
    assert_eq!(activity.status, 200);
    assert!(
        !activity
            .body
            .contains("ghp_0123456789abcdefghijklmnopqrstuvwx"),
        "{}",
        activity.body
    );
    assert!(
        !activity.body.contains("hunter2swordfish"),
        "{}",
        activity.body
    );
    assert!(
        !activity.body.contains(&t.home.display().to_string()),
        "activity leaked the home path: {}",
        activity.body
    );
    assert!(activity.body.contains("<redacted>"), "{}", activity.body);

    t.stop();
}

// ---------------------------------------------------------------------------
// workspace trust (WS-C fix round 4: owner-presence proof)
// ---------------------------------------------------------------------------

/// Create `<home>/agents/<agent>/workspace` and return its path + canonical key.
fn agent_workspace(t: &TestApi, agent: &str) -> (PathBuf, String) {
    let workspace = t.home.join(format!("agents/{agent}/workspace"));
    std::fs::create_dir_all(&workspace).unwrap();
    let key = workspace
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    (workspace, key)
}

fn trust_body(path: &Path, code: Option<&str>) -> String {
    match code {
        Some(code) => json!({
            "path": path.to_string_lossy(),
            "code": code,
        })
        .to_string(),
        None => json!({ "path": path.to_string_lossy() }).to_string(),
    }
}

/// The one-time code exactly as delivered to the owner's notifications.
fn notified_code(fake: &FakeNotifier) -> String {
    let body = fake.last().unwrap().body;
    let line = body
        .lines()
        .find(|line| line.starts_with("Code: "))
        .unwrap();
    let after = &line["Code: ".len()..];
    let end = after.find(" (expires").unwrap_or(after.len());
    let digits: String = after[..end]
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    assert_eq!(digits.len(), 8, "notification body: {body}");
    digits
}

fn workspace_event_payloads(home: &Path) -> Vec<String> {
    let conn = aux_store::open_keyed(&store_path(home)).unwrap();
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE kind LIKE 'workspace.%' ORDER BY id")
        .unwrap();
    let payloads = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    payloads
}

fn backdate_trust_request(home: &Path, workspace: &str, seconds: i64) {
    let conn = aux_store::open_keyed(&store_path(home)).unwrap();
    conn.execute(
        "UPDATE trust_requests SET created_at = created_at - ?1 WHERE workspace = ?2",
        rusqlite::params![seconds, workspace],
    )
    .unwrap();
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_trust_requires_the_owner_token_and_the_notified_code() {
    // P1 regression (security-review round 3): the owner token alone (the shell can
    // read `api.token`) must not disarm the taint. The route is a two-step
    // owner-presence proof: request a code (delivered only to the owner's
    // notification), complete with the code.
    let fake = Arc::new(FakeNotifier::new());
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    let (workspace, key) = agent_workspace(&t, "main");
    t.store().mark_workspace_tainted(&key, "shell").unwrap();

    // Without the bearer token neither step is reachable.
    let unauth = call(
        t.addr,
        "POST",
        "/v1/workspaces/trust",
        None,
        Some(&trust_body(&workspace, None)),
    )
    .await;
    assert_error(&unauth, 401, "unauthorized");
    assert_eq!(
        t.store().workspace_taint(&key).unwrap().as_deref(),
        Some("shell"),
        "an unauthorized request must not change the mark"
    );

    // Request step: pending, mark unchanged, notification sent, no code in
    // the response.
    let response = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    let value = response.json();
    assert_eq!(value["requested"].as_bool(), Some(true));
    assert_eq!(value["trusted"].as_bool(), Some(false));
    assert_eq!(value["changed"].as_bool(), Some(false));
    assert_eq!(value["workspace"].as_str(), Some(key.as_str()));
    assert_eq!(fake.count(), 1, "exactly one notification");
    let code = notified_code(&fake);
    assert!(
        !response.body.contains(&code),
        "the request response must never carry the code"
    );
    assert_eq!(
        t.store().workspace_taint(&key).unwrap().as_deref(),
        Some("shell"),
        "a bare request must not clear the mark"
    );
    assert_eq!(
        t.store().event_count("workspace.trust_requested").unwrap(),
        1
    );

    // Completion without the token is refused too.
    let unauth = call(
        t.addr,
        "POST",
        "/v1/workspaces/trust",
        None,
        Some(&trust_body(&workspace, Some(&code))),
    )
    .await;
    assert_error(&unauth, 401, "unauthorized");
    assert!(t.store().workspace_taint(&key).unwrap().is_some());

    // A wrong code (what a tool could guess) is audited and changes nothing.
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    let bad = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(wrong)),
    )
    .await;
    assert_error(&bad, 400, "trust_code_invalid");
    assert!(t.store().workspace_taint(&key).unwrap().is_some());
    assert_eq!(t.store().event_count("workspace.trust_failed").unwrap(), 1);

    // The notified code completes: mark cleared and audited.
    let done = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    assert_eq!(done.status, 200, "body: {}", done.body);
    let value = done.json();
    assert_eq!(value["trusted"].as_bool(), Some(true));
    assert_eq!(value["changed"].as_bool(), Some(true));
    assert_eq!(value["requested"].as_bool(), Some(false));
    assert!(
        !done.body.contains(&code),
        "the completion response must never carry the code"
    );
    let store = t.store();
    assert_eq!(store.workspace_taint(&key).unwrap(), None);
    assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);
    assert!(store.trust_request(&key).unwrap().is_none(), "single use");

    // Replay of the same code: the request is gone.
    let replay = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    assert_error(&replay, 404, "trust_request_missing");
    assert_eq!(t.store().event_count("workspace.trusted").unwrap(), 1);

    // Paths outside the agent layout are still refused, with or without code.
    let elsewhere = t.home.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    for body in [
        trust_body(&elsewhere, None),
        trust_body(&elsewhere, Some(&code)),
    ] {
        let bad = post_auth(&t, "/v1/workspaces/trust", &body).await;
        assert_error(&bad, 400, "invalid_workspace");
    }

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_trust_is_refused_while_the_shell_can_run_unsandboxed() {
    // P1 regression (security-review round 5): with the escape hatch on, the trust
    // action is refused and audited (`workspace.trust_refused`); no code is
    // issued or consumed. Tightening the config re-enables the action, and
    // the seeded code still completes.
    let fake = Arc::new(FakeNotifier::new());
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    {
        let mut config = std::fs::read_to_string(config_path(&t.home)).unwrap();
        config.push_str("\n[shell]\nsandbox = false\nallow_unsandboxed = true\n");
        std::fs::write(config_path(&t.home), config).unwrap();
    }
    let (workspace, key) = agent_workspace(&t, "main");
    t.store().mark_workspace_tainted(&key, "shell").unwrap();

    // Request step refused: no notification, no pending row, audited.
    let requested = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_error(&requested, 409, "unsandboxed_shell");
    assert_eq!(fake.count(), 0, "no code may be issued");
    assert!(t.store().trust_request(&key).unwrap().is_none());
    assert_eq!(t.store().event_count("workspace.trust_refused").unwrap(), 1);
    assert!(
        t.store().workspace_taint(&key).unwrap().is_some(),
        "the mark must survive the refusal"
    );

    // A pending request seeded out of band (the owner could have requested
    // it before tightening the sandbox) cannot be completed while the shell
    // can run unsandboxed: the code stays unconsumed.
    let store = t.store();
    aux_engine::request_trust(&store, &key, "owner-api", fake.as_ref()).unwrap();
    let code = notified_code(&fake);
    let completed = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    assert_error(&completed, 409, "unsandboxed_shell");
    assert!(
        store.workspace_taint(&key).unwrap().is_some(),
        "the mark must survive the refused completion"
    );
    assert!(
        store.trust_request(&key).unwrap().is_some(),
        "the code must not be consumed"
    );
    assert_eq!(t.store().event_count("workspace.trust_refused").unwrap(), 2);

    // Tightening `[shell]` back re-enables the owner action; the same code
    // still completes.
    {
        let config = std::fs::read_to_string(config_path(&t.home))
            .unwrap()
            .replace("sandbox = false", "sandbox = true")
            .replace("allow_unsandboxed = true", "allow_unsandboxed = false");
        std::fs::write(config_path(&t.home), config).unwrap();
    }
    let done = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    assert_eq!(done.status, 200, "body: {}", done.body);
    assert_eq!(t.store().workspace_taint(&key).unwrap(), None);
    assert_eq!(t.store().event_count("workspace.trusted").unwrap(), 1);

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_trust_code_never_appears_in_api_responses_audits_or_the_store() {
    let fake = Arc::new(FakeNotifier::new());
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    let (workspace, key) = agent_workspace(&t, "main");
    t.store().mark_workspace_tainted(&key, "shell").unwrap();

    let mut bodies = Vec::new();
    let requested = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    bodies.push(requested.body.clone());
    let code = notified_code(&fake);
    let spaced = format!("{} {}", &code[..4], &code[4..]);

    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    let bad = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(wrong)),
    )
    .await;
    bodies.push(bad.body.clone());
    let done = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    bodies.push(done.body.clone());
    let replay = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    bodies.push(replay.body.clone());

    for body in &bodies {
        assert!(
            !body.contains(&code) && !body.contains(&spaced),
            "an API response carried the code: {body}"
        );
    }
    let payloads = workspace_event_payloads(&t.home);
    assert!(!payloads.is_empty(), "trust actions must be audited");
    for payload in &payloads {
        assert!(
            !payload.contains(&code) && !payload.contains(&spaced),
            "an audit row carried the code: {payload}"
        );
    }
    let bytes = std::fs::read(store_path(&t.home)).unwrap();
    assert!(
        !contains_bytes(&bytes, code.as_bytes()) && !contains_bytes(&bytes, spaced.as_bytes()),
        "the store file carried the code"
    );
    // And the wrong guess itself is not echoed either.
    assert!(
        !bodies.iter().any(|body| body.contains(wrong)),
        "a rejected guess must not be echoed: {bodies:?}"
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_trust_code_expiry_is_enforced() {
    let fake = Arc::new(FakeNotifier::new());
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    let (workspace, key) = agent_workspace(&t, "main");
    t.store().mark_workspace_tainted(&key, "shell").unwrap();
    let requested = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_eq!(requested.status, 200);
    let code = notified_code(&fake);

    // The owner waits longer than the 120 s TTL.
    backdate_trust_request(&t.home, &key, aux_engine::TRUST_CODE_TTL_SECS + 1);

    let expired = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    assert_error(&expired, 400, "trust_request_expired");
    assert!(t.store().workspace_taint(&key).unwrap().is_some());
    assert!(t.store().trust_request(&key).unwrap().is_none(), "swept");
    assert_eq!(t.store().event_count("workspace.trust_failed").unwrap(), 1);

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_trust_attempt_cap_cancels_the_request() {
    let fake = Arc::new(FakeNotifier::new());
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    let (workspace, key) = agent_workspace(&t, "main");
    t.store().mark_workspace_tainted(&key, "shell").unwrap();
    let requested = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_eq!(requested.status, 200);
    let code = notified_code(&fake);
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };

    let first = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(wrong)),
    )
    .await;
    assert_error(&first, 400, "trust_code_invalid");
    assert!(first.body.contains("2 attempt(s) left"), "{}", first.body);
    let second = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(wrong)),
    )
    .await;
    assert_error(&second, 400, "trust_code_invalid");
    let third = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(wrong)),
    )
    .await;
    assert_error(&third, 429, "trust_attempts_exhausted");
    let spent = t
        .store()
        .trust_request(&key)
        .unwrap()
        .expect("the spent row must survive as the cooldown watermark (P2-1)");
    assert_eq!(spent.attempts, 3);
    assert!(t.store().workspace_taint(&key).unwrap().is_some());

    // P2-1 regression (security-review round 4): burning the attempt cap must not
    // reset the cooldown, so an immediate new request is refused and no
    // second notification is shown.
    let flooded = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_error(&flooded, 429, "trust_rate_limited");
    assert_eq!(fake.count(), 1, "no second notification may be shown");

    // Even the notified code cannot revive the spent request.
    let late = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&workspace, Some(&code)),
    )
    .await;
    assert_error(&late, 404, "trust_request_missing");
    assert!(t.store().workspace_taint(&key).unwrap().is_some());
    assert_eq!(
        t.store().event_count("workspace.trust_failed").unwrap(),
        4,
        "three wrong codes plus the late attempt"
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_trust_code_is_bound_to_its_workspace() {
    let fake = Arc::new(FakeNotifier::new());
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    let (main_ws, main_key) = agent_workspace(&t, "main");
    let (other_ws, other_key) = agent_workspace(&t, "other");
    t.store()
        .mark_workspace_tainted(&main_key, "shell")
        .unwrap();
    t.store()
        .mark_workspace_tainted(&other_key, "shell")
        .unwrap();

    let requested = post_auth(&t, "/v1/workspaces/trust", &trust_body(&main_ws, None)).await;
    assert_eq!(requested.status, 200);
    let code = notified_code(&fake);

    // Another workspace cannot be completed with main's code.
    let cross = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&other_ws, Some(&code)),
    )
    .await;
    assert_error(&cross, 404, "trust_request_missing");
    assert!(t.store().workspace_taint(&main_key).unwrap().is_some());
    assert!(t.store().workspace_taint(&other_key).unwrap().is_some());

    // The owning workspace still completes.
    let done = post_auth(
        &t,
        "/v1/workspaces/trust",
        &trust_body(&main_ws, Some(&code)),
    )
    .await;
    assert_eq!(done.status, 200, "body: {}", done.body);
    assert!(t.store().workspace_taint(&main_key).unwrap().is_none());
    assert!(t.store().workspace_taint(&other_key).unwrap().is_some());

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_trust_reports_notification_failure_without_leaving_state() {
    // A failing transport must not leave a pending request whose code nobody
    // saw, and the response must stay a clean 503.
    let fake = Arc::new(FakeNotifier::failing("script editor said no"));
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    let (workspace, key) = agent_workspace(&t, "main");
    t.store().mark_workspace_tainted(&key, "shell").unwrap();

    let failed = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_error(&failed, 503, "trust_notification_failed");
    assert!(t.store().workspace_taint(&key).unwrap().is_some());
    assert!(t.store().trust_request(&key).unwrap().is_none());

    // The owner can immediately try again (no cooldown was consumed).
    let retry = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_error(&retry, 503, "trust_notification_failed");
    assert_eq!(
        fake.count(),
        2,
        "both attempts were delivered to the transport"
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_trust_requests_are_rate_limited() {
    let fake = Arc::new(FakeNotifier::new());
    let mut t = TestApi::start_with_notifier(Arc::clone(&fake)).await;
    let (workspace, key) = agent_workspace(&t, "main");
    t.store().mark_workspace_tainted(&key, "shell").unwrap();

    let first = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_eq!(first.status, 200);
    let second = post_auth(&t, "/v1/workspaces/trust", &trust_body(&workspace, None)).await;
    assert_error(&second, 429, "trust_rate_limited");
    assert_eq!(fake.count(), 1, "no second notification may be shown");
    assert!(t.store().workspace_taint(&key).unwrap().is_some());

    t.stop();
}

/// A turn runner that only stops when its cancellation token fires.
struct SleepingRunner {
    saw_cancel: Arc<std::sync::atomic::AtomicBool>,
    completed: Arc<std::sync::atomic::AtomicBool>,
}

impl auxd::api::TurnRunner for SleepingRunner {
    fn run_turn(
        &self,
        _agent: &str,
        _session_id: Option<i64>,
        _content: &str,
        cancel: Option<Arc<aux_engine::TurnCancel>>,
    ) -> Result<auxd::api::TurnRecord, auxd::api::TurnError> {
        for _ in 0..1000 {
            if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
                self.saw_cancel
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(auxd::api::TurnError::Cancelled);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.completed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Err(auxd::api::TurnError::Internal {
            detail: "never cancelled".to_string(),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_turn_over_the_configured_timeout_answers_504_and_cancels() {
    // E-14 regression: `POST .../messages` is bounded by the configured turn
    // timeout; on expiry the client gets `504 turn_timeout` and the turn's
    // cancellation token is fired (the old route awaited forever).
    let saw_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runner: Arc<dyn auxd::api::TurnRunner> = Arc::new(SleepingRunner {
        saw_cancel: Arc::clone(&saw_cancel),
        completed: Arc::clone(&completed),
    });
    let mut t = TestApi::start_with(move |_| ApiOptions {
        runner: Some(runner),
        turn_timeout: Some(Duration::from_millis(50)),
        ..fast_options()
    })
    .await;

    let response = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"ping"}"#).await;
    assert_error(&response, 504, "turn_timeout");

    // The token really reached the runner: it stops early instead of running
    // its full loop.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !saw_cancel.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the runner never saw the cancellation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !completed.load(std::sync::atomic::Ordering::SeqCst),
        "the runner must not run to completion"
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_turn_timeout_comes_from_config_when_options_are_default() {
    // M8c: with `ApiOptions::turn_timeout = None`, the daemon must read
    // `turn_timeout_secs` from `config.toml`. An ignored config would leave
    // the default 1800 s (H-05) and this POST would not answer 504 in time.
    let saw_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runner: Arc<dyn auxd::api::TurnRunner> = Arc::new(SleepingRunner {
        saw_cancel: Arc::clone(&saw_cancel),
        completed: Arc::clone(&completed),
    });
    let mut t = TestApi::start_with(move |home| {
        std::fs::write(config_path(home), config_with_turn_timeout(1)).unwrap();
        ApiOptions {
            runner: Some(runner),
            turn_timeout: None,
            ..fast_options()
        }
    })
    .await;

    let started = std::time::Instant::now();
    let response = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"ping"}"#).await;
    assert_error(&response, 504, "turn_timeout");
    assert!(
        response.body.contains("1 s"),
        "the 504 must report the configured seconds: {}",
        response.body
    );
    assert!(
        started.elapsed() < Duration::from_secs(9),
        "the configured 1 s timeout must fire well before the runner's 10 s loop"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !saw_cancel.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            std::time::Instant::now() < deadline,
            "the runner never saw the cancellation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    t.stop();
}

/// P2-1 end-to-end: a turn cancelled while an approval is pending abandons
/// that approval. A late `allow_always` answer is a `410` that writes no
/// rule, and the session lock is released for the next turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_turn_abandons_its_approval_and_late_answers_are_410() {
    let provider = approval_provider();
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
        // The turn timeout is this test's cancellation source *and* the
        // budget the engine's whole cold start shares: the blocking-pool
        // hand-off, the SQLCipher store opens, config/rules/provider load and
        // the fake provider round all run before the broker can raise the
        // ask. A saturated runner made even 8 s too tight: the route cancelled
        // the turn before the ask, the approval was never created, and a
        // longer `wait_for_pending` cannot see what never existed. Thirty
        // seconds leaves the ask a wide pending window; the request that must
        // outwait the timeout uses a read timeout above it, not the client's
        // 10 s default.
        std::fs::write(config_path(home), config_with_turn_timeout(30)).unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            // Above the 30 s turn timeout, so an approval timeout never races
            // it: only the turn's own cancellation may retire the card.
            approval_timeout: Some(Duration::from_secs(120)),
            ..ApiOptions::default()
        }
    })
    .await;

    let mut send = send_async_with_read_timeout(
        &t,
        r#"{"content":"write it"}"#,
        // Outwait the 30 s turn timeout with room for the response to arrive.
        Duration::from_secs(90),
    );
    // On timeout this reports the blocked send's response and the daemon's
    // view of the turn, instead of just "no approval appeared".
    let pending = wait_for_pending_with_send(&t, common::LOADED_RUNNER_WAIT, Some(&mut send)).await;
    let id = pending[0].id.clone();
    let response = send.await.unwrap();
    assert_error(&response, 504, "turn_timeout");

    // The cancelled turn retires its approval: the card disappears.
    let deadline = tokio::time::Instant::now() + common::LOADED_RUNNER_WAIT;
    loop {
        let pending: Vec<app_wire::Approval> =
            serde_json::from_value(get_auth(&t, "/v1/approvals?state=pending").await.json())
                .unwrap();
        if pending.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the cancelled turn never retired its approval"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A late allow_always is rejected with 410, writes no rule, and is
    // audited as such.
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{id}"),
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"main"}}"#,
    )
    .await;
    assert_error(&answer, 410, "approval_abandoned");
    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert!(
        !config.contains("[[rules]]"),
        "a dead turn must not persist an allow rule: {config}"
    );
    let answered = event_payloads(&t.home, "approval.answered");
    assert!(
        answered
            .iter()
            .any(|row| row.contains("\"decision\":\"late_after_abandon\"")),
        "the late answer must be audited: {answered:?}"
    );

    // The first turn's batch was closed with a synthetic cancelled result and
    // the per-session lock was released: the next turn runs.
    let store = t.store();
    let session = store
        .list_sessions()
        .unwrap()
        .into_iter()
        .find(|session| session.agent == "main")
        .expect("the cancelled turn created the session");
    let rows = store.list_messages(session.id).unwrap();
    let tool_row = rows
        .iter()
        .find(|message| message.role == "tool")
        .expect("the cancelled batch is closed with a tool result");
    assert!(
        tool_row
            .meta
            .as_deref()
            .unwrap()
            .contains("\"status\":\"cancelled\""),
        "{:?}",
        tool_row.meta
    );

    let second = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"carry on"}"#).await;
    assert_eq!(
        second.status, 200,
        "the lock must be released for the next turn: {}",
        second.body
    );

    t.stop();
}

/// Deterministic, portable stand-in for the production sandboxed `shell`.
///
/// The real `ShellTool` needs macOS Seatbelt: where `sandbox-exec` is
/// unavailable (Linux CI) it fails closed, so the kill-lifecycle regression
/// cannot depend on it. Registered under the name `shell`, this fake keeps
/// the contract the test needs: it spawns a real `sh -c` child in its own
/// process group, records the child's pid in the workspace, and — like
/// `ShellTool`'s `TreeReaper` — observes `ToolCtx::cancel` and SIGKILLs the
/// child's whole process group before the engine's cleanup grace expires.
/// A future dropped mid-run (turn teardown, a panicking test) still reaps.
struct PortableFakeShell;

/// Best-effort whole-group kill of the fake shell's child, armed until the
/// run finishes normally (mirrors `ShellTool`'s `TreeReaper`).
struct GroupKill {
    pid: i32,
    armed: bool,
}

impl GroupKill {
    fn sweep(&mut self) {
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
            libc::kill(self.pid, libc::SIGKILL);
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for GroupKill {
    fn drop(&mut self) {
        if self.armed {
            self.sweep();
        }
    }
}

#[async_trait]
impl Tool for PortableFakeShell {
    fn class(&self) -> ToolClass {
        ToolClass::default()
    }

    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B5
    }
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
            "additionalProperties": false
        })
    }

    async fn run(&self, args: &serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let command = args
            .get("command")
            .and_then(|value| value.as_str())
            .unwrap_or("sleep 30");
        use std::os::unix::process::CommandExt;
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(&ctx.workspace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Own process group: the sweep takes the whole tree even when
            // `sh` forks instead of exec'ing `sleep`.
            .process_group(0)
            .spawn()?;
        // The pid the test polls: the direct child, and the group leader.
        std::fs::write(ctx.workspace.join("shell.pid"), child.id().to_string())?;
        let mut reaper = GroupKill {
            pid: child.id() as i32,
            armed: true,
        };
        let cancelled = async {
            match &ctx.cancel {
                Some(token) => token.cancelled().await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(cancelled);
        loop {
            if let Some(status) = child.try_wait()? {
                reaper.disarm();
                return Ok(ToolOutput::ok(format!("[exited: {status}]")));
            }
            tokio::select! {
                biased;
                _ = &mut cancelled => {
                    reaper.sweep();
                    let _ = child.wait();
                    reaper.disarm();
                    return Ok(ToolOutput::error("[cancelled: the turn was cancelled]"));
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    fn risk(&self) -> Risk {
        // Same class as the real shell: a process runner.
        Risk::High
    }
}

/// A killed in-flight turn may report either abort status: the cancellation
/// token (`499 turn_cancelled`) or the agent's stop marker (`409 stopped`),
/// depending on which check the engine reaches first. Both mean the turn
/// aborted; the caller's cleanup assertions prove the rest.
fn assert_turn_aborted(response: &HttpResponse) {
    match response.status {
        499 => assert_error(response, 499, "turn_cancelled"),
        409 => assert_error(response, 409, "stopped"),
        status => panic!(
            "a killed turn must abort (499 turn_cancelled or 409 stopped), got HTTP {status}: {}",
            response.body
        ),
    }
}

/// B-API v3 × E-18: a per-agent kill during an in-flight turn must end the
/// turn now, with the same cleanup a client-disconnect cancellation gets.
///
/// Phase one: the scripted `write_file` call (effectful, no rule ⇒ asks) is
/// waiting on its approval when the kill lands — the approval is retired (a
/// late answer is a `410`, no rule is written).
/// Phase two: the turn is running a long command when the kill lands — the
/// running child's process group is reaped, the turn never reaches the next
/// provider round, and the completed provider spend settles exactly once.
///
/// The command runs through [`PortableFakeShell`] (registered as `shell`),
/// not the real `ShellTool`: the real sandbox needs macOS Seatbelt and fails
/// closed on Linux CI, which made this regression host-bound. The macOS-only
/// half — the real sandboxed shell tree — is pinned by the test after this
/// one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killing_an_agent_aborts_its_turn_retires_the_approval_and_reaps_the_shell_tree() {
    // Every completed provider round reports the same usage, so the daily
    // totals below prove exactly how many settles the two killed turns made.
    let settled_usage = || Usage {
        prompt_tokens: 1_000,
        completion_tokens: 20,
        cost_usd: Some(0.10),
        cached_prompt_tokens: None,
    };
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            // Phase one: one write_file call (FAKE_CONFIG has no rules, so it
            // asks; a cancelled ask leaves the session untainted), then a
            // final answer that is never reached.
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "write_file",
                    json!({ "path": "out.txt", "content": "phase one" }),
                )],
            ))
            .with_usage(settled_usage()),
            // Phase two: one long command (allowed by the rule below and run
            // by the portable fake shell), then a final answer never reached.
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_2",
                    "shell",
                    json!({ "command": "sleep 30" }),
                )],
            ))
            .with_usage(settled_usage()),
            ChatResponse::assistant("done"),
        ],
    ));
    let scripted = Arc::clone(&provider);
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "hello note").unwrap();
        std::fs::write(
            config_path(home),
            "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\napprovals = \"ask\"\n\n\
             [[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
             model = \"fake-model\"\nkind = \"fake\"\n\n\
             [[rules]]\ndot = \"main\"\ntool = \"shell\"\naction = \"allow\"\n",
        )
        .unwrap();
        // Replace the host-bound sandboxed `shell` with the portable
        // stand-in, so this lifecycle test runs on Linux CI too.
        let tools: ToolRegistryHook = Arc::new(|registry| {
            registry.register(Box::new(PortableFakeShell));
        });
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            tools: Some(tools),
            approval_timeout: Some(Duration::from_secs(30)),
            ..ApiOptions::default()
        }
    })
    .await;

    // Phase one: the turn blocks on an approval; the kill ends it and
    // retires the approval.
    let mut send = send_async(&t, r#"{"content":"write it"}"#);
    // On timeout this reports the blocked send's response and the daemon's
    // view of the turn, instead of just "no approval appeared".
    let pending = wait_for_pending_with_send(&t, common::LOADED_RUNNER_WAIT, Some(&mut send)).await;
    assert_eq!(pending[0].scope_tool, "write_file");
    let approval_id = pending[0].id.clone();

    let killed = post_auth(&t, "/v1/agents/main/kill", "{}").await;
    assert_eq!(killed.status, 200, "body: {}", killed.body);
    assert_eq!(killed.json()["killed"], true);

    let response = send.await.unwrap();
    assert_turn_aborted(&response);

    let deadline = tokio::time::Instant::now() + common::LOADED_RUNNER_WAIT;
    loop {
        let pending: Vec<app_wire::Approval> =
            serde_json::from_value(get_auth(&t, "/v1/approvals?state=pending").await.json())
                .unwrap();
        if pending.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the killed turn never retired its approval"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let answer = post_auth(
        &t,
        &format!("/v1/approvals/{approval_id}"),
        r#"{"decision":"allow_always","scope":{"tool":"write_file","agent":"main"}}"#,
    )
    .await;
    assert_error(&answer, 410, "approval_abandoned");
    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert!(
        !config.contains("tool = \"write_file\""),
        "a killed turn must not persist an allow rule: {config}"
    );

    // Phase two: resume, then kill while a long command is running: the
    // portable shell observes the fired token and sweeps the child's process
    // group.
    let resumed = post_auth(&t, "/v1/agents/main/resume", "{}").await;
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    assert_eq!(resumed.json()["killed"], false);

    let send = send_async(&t, r#"{"content":"run the long command"}"#);
    let pid_file = aux_engine::workspace_dir(&t.home, "main").join("shell.pid");
    let deadline = tokio::time::Instant::now() + common::LOADED_RUNNER_WAIT;
    let child_pid = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                break pid;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the portable shell never started its child"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let killed = post_auth(&t, "/v1/agents/main/kill", "{}").await;
    assert_eq!(killed.status, 200, "body: {}", killed.body);
    let response = send.await.unwrap();
    assert_turn_aborted(&response);

    // The killed turn's child (and its process group) must be gone.
    let deadline = tokio::time::Instant::now() + common::LOADED_RUNNER_WAIT;
    loop {
        if unsafe { libc::kill(child_pid, 0) } != 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the shell child {child_pid} survived the per-agent kill"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The kill aborted the turn before the next round: the third scripted
    // response (round 1 = read_file, round 2 = shell) was never requested.
    assert_eq!(
        scripted.request_count(),
        2,
        "a killed turn must not reach the next provider round"
    );

    // Budget: exactly one settle per completed provider round (two here), a
    // killed turn neither settles twice nor releases a completed call, and no
    // reservation is left behind.
    let store = t.store();
    let day = store.local_day().unwrap();
    let totals = store.usage_totals("main", &day).unwrap();
    assert_eq!(totals.tokens_in, 2_000, "one settle per completed round");
    assert_eq!(totals.tokens_out, 40, "one settle per completed round");
    assert_eq!(totals.usd_cents, 20, "one settle per completed round");
    assert_eq!(
        store.reservation_count().unwrap(),
        0,
        "a killed turn must not leave a spend reservation behind"
    );

    t.stop();
}

/// The macOS half of the same B-API v3 × E-18 contract: with the real,
/// Seatbelt-sandboxed `shell`, a per-agent kill must fire the tool's
/// cancellation token and reap the sandboxed command's whole process tree.
/// Sandboxed shells exist only on macOS (`sandbox-exec`); the
/// platform-independent lifecycle runs in the test above through
/// [`PortableFakeShell`].
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killing_an_agent_reaps_a_real_sandboxed_shell_tree_on_macos() {
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ProviderToolCall::new(
                    "call_1",
                    "shell",
                    json!({ "command": "echo $$ > shell.pid; sleep 60" }),
                )],
            )),
            ChatResponse::assistant("done"),
        ],
    ));
    let mut t = TestApi::start_with(move |home| {
        let workspace = aux_engine::workspace_dir(home, "main");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(
            config_path(home),
            "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n\n\
             [[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
             model = \"fake-model\"\nkind = \"fake\"\n\n\
             [[rules]]\ndot = \"main\"\ntool = \"shell\"\naction = \"allow\"\n",
        )
        .unwrap();
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(provider),
            approval_timeout: Some(Duration::from_secs(30)),
            ..ApiOptions::default()
        }
    })
    .await;

    // Kill while the sandboxed `sleep 60` is running: the shell tool
    // observes the fired token and sweeps its process tree.
    let send = send_async(&t, r#"{"content":"run the long command"}"#);
    let pid_file = aux_engine::workspace_dir(&t.home, "main").join("shell.pid");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let child_pid = loop {
        if let Ok(text) = std::fs::read_to_string(&pid_file) {
            if let Ok(pid) = text.trim().parse::<i32>() {
                break pid;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the sandboxed shell command never started"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let killed = post_auth(&t, "/v1/agents/main/kill", "{}").await;
    assert_eq!(killed.status, 200, "body: {}", killed.body);
    let response = send.await.unwrap();
    assert_turn_aborted(&response);

    // The killed turn's shell child must be gone (the whole tree sweep).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if unsafe { libc::kill(child_pid, 0) } != 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the shell child {child_pid} survived the per-agent kill"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    t.stop();
}

// ---------------------------------------------------------------------------
// connection timeouts (API-TIMEOUT-1)
// ---------------------------------------------------------------------------

/// How long the timeout tests let the server read a request head. Short
/// enough that every case finishes well under two seconds.
const SLOW_CLIENT_TIMEOUT: Duration = Duration::from_millis(200);

/// Generous wait for a connection the server should have closed: the timeout
/// above plus slack for a loaded runner.
const CLOSE_MARGIN: Duration = Duration::from_millis(500);

fn timeout_options() -> ApiOptions {
    ApiOptions {
        header_read_timeout: SLOW_CLIENT_TIMEOUT,
        ..fast_options()
    }
}

/// Read until the peer closes (FIN or reset). A server that keeps the socket
/// open past `budget` is a failure, not a hang.
async fn drain_until_closed(
    stream: &mut tokio::net::TcpStream,
    budget: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection stayed open",
            ));
        }
        match tokio::time::timeout(left, stream.read(&mut buf)).await {
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection stayed open",
                ))
            }
            // A reset is a disconnect too.
            Ok(Err(_)) | Ok(Ok(0)) => return Ok(out),
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
        }
    }
}

/// Read one complete HTTP/1.1 response (head and `Content-Length` body).
async fn read_one_response(stream: &mut tokio::net::TcpStream) -> (String, String) {
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout(CLOSE_MARGIN, stream.read(&mut chunk))
            .await
            .expect("the response head never arrived")
            .expect("the connection closed before the response head");
        assert!(n > 0, "the connection closed before the response head");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .expect("every response carries a Content-Length");
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 1024];
        let n = tokio::time::timeout(CLOSE_MARGIN, stream.read(&mut chunk))
            .await
            .expect("the response body never arrived")
            .expect("the connection closed before the response body");
        assert!(n > 0, "the connection closed before the response body");
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    (
        head,
        String::from_utf8(body).expect("the API answers UTF-8"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partial_request_head_is_disconnected_after_the_header_timeout() {
    let mut t = TestApi::start_with(|_| timeout_options()).await;
    let mut stream = tokio::net::TcpStream::connect(t.addr).await.unwrap();
    stream
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let started = tokio::time::Instant::now();
    let bytes = drain_until_closed(&mut stream, CLOSE_MARGIN)
        .await
        .expect("a slow-loris connection must be disconnected at the header timeout");
    assert!(
        !bytes.starts_with(b"HTTP/1.1 200"),
        "an incomplete request must never be answered: {:?}",
        String::from_utf8_lossy(&bytes)
    );
    assert!(started.elapsed() <= SLOW_CLIENT_TIMEOUT + CLOSE_MARGIN);

    t.stop();
}

/// The regression behind round 2: hyper-util's `auto` builder waited for the
/// protocol-sniff byte before arming the header timer, so a socket that sent
/// nothing held its connection slot until the daemon restarted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_socket_is_disconnected_after_the_header_timeout() {
    let mut t = TestApi::start_with(|_| timeout_options()).await;
    let mut stream = tokio::net::TcpStream::connect(t.addr).await.unwrap();

    let started = tokio::time::Instant::now();
    let bytes = drain_until_closed(&mut stream, SLOW_CLIENT_TIMEOUT + CLOSE_MARGIN)
        .await
        .expect("a socket that never sends a byte must be closed at the header timeout");
    assert!(
        bytes.is_empty(),
        "a silent socket must not be answered: {:?}",
        String::from_utf8_lossy(&bytes)
    );
    // Allow for the server having armed its timer a few milliseconds before
    // this test's clock started; an immediate close is still a failure.
    assert!(
        started.elapsed() >= SLOW_CLIENT_TIMEOUT.saturating_sub(Duration::from_millis(50)),
        "the silent socket was closed before the header timeout: {:?}",
        started.elapsed()
    );
    assert!(started.elapsed() <= SLOW_CLIENT_TIMEOUT + CLOSE_MARGIN);

    t.stop();
}

/// Every connection slot filled by a peer that never sends a byte, then one
/// real authorized request. The real request is queued behind the silent ones
/// and is answered once they time out. Before the HTTP/1-only builder, the
/// silent sockets never timed out and this request hung forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_house_of_silent_sockets_does_not_lock_out_a_real_request() {
    let header_timeout = SLOW_CLIENT_TIMEOUT * 2;
    let mut t = TestApi::start_with(move |_| ApiOptions {
        header_read_timeout: header_timeout,
        ..fast_options()
    })
    .await;

    let mut silent = Vec::with_capacity(api::MAX_CONNECTIONS);
    for _ in 0..api::MAX_CONNECTIONS {
        silent.push(tokio::net::TcpStream::connect(t.addr).await.unwrap());
    }
    // Give the accept loop time to take the slots. Even if it has not, these
    // connects were queued before the real request, so it still waits.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = tokio::time::Instant::now();
    let response = tokio::task::spawn_blocking({
        let addr = t.addr;
        let token = t.token.clone();
        move || {
            common::http_with_read_timeout(
                addr,
                "GET",
                "/v1/health",
                Some(&token),
                None,
                header_timeout + Duration::from_secs(2),
            )
        }
    })
    .await
    .expect("the real request must not hang");
    let elapsed = started.elapsed();

    assert_eq!(response.status, 200, "body: {}", response.body);
    assert!(
        response.body.contains("\"ok\":true"),
        "body: {}",
        response.body
    );
    // All 64 slots were taken when it arrived, so it cannot have been
    // answered before at least one of them timed out.
    assert!(
        elapsed >= header_timeout / 2,
        "the real request was answered before a slot could free: {elapsed:?}"
    );
    assert!(
        elapsed <= header_timeout + Duration::from_secs(2),
        "the real request waited too long: {elapsed:?}"
    );

    drop(silent);
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_keep_alive_connection_is_closed_after_the_header_timeout() {
    let mut t = TestApi::start_with(|_| timeout_options()).await;
    let mut stream = tokio::net::TcpStream::connect(t.addr).await.unwrap();
    let request = format!(
        "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nConnection: keep-alive\r\n\r\n",
        t.token
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let (head, body) = read_one_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    assert!(body.contains("\"ok\":true"), "body: {body}");

    // The socket must survive the response (it is keep-alive), then the idle
    // timer — not an immediate close — must end it.
    let mut probe = [0u8; 1];
    let early = tokio::time::timeout(Duration::from_millis(30), stream.read(&mut probe)).await;
    assert!(
        early.is_err(),
        "the keep-alive socket closed before its idle timeout"
    );

    let started = tokio::time::Instant::now();
    drain_until_closed(&mut stream, CLOSE_MARGIN)
        .await
        .expect("an idle keep-alive connection must be closed at the header timeout");
    assert!(started.elapsed() <= SLOW_CLIENT_TIMEOUT + CLOSE_MARGIN);

    t.stop();
}

/// Answers only after a delay longer than the server's header timeout, so a
/// response that is still being produced proves the timer stopped with the
/// request head.
struct SlowTurnProvider {
    delay: Duration,
}

#[async_trait]
impl ChatProvider for SlowTurnProvider {
    async fn complete(&self, _request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        tokio::time::sleep(self.delay).await;
        Ok(ChatResponse::assistant("slow but whole"))
    }

    fn name(&self) -> &str {
        "slow-turn"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_turn_and_the_events_socket_outlive_the_header_timeout() {
    let provider = Arc::new(SlowTurnProvider {
        delay: SLOW_CLIENT_TIMEOUT * 2,
    });
    let mut t = TestApi::start_with(move |_| ApiOptions {
        provider: Some(Arc::clone(&provider) as Arc<dyn ChatProvider>),
        ..timeout_options()
    })
    .await;

    // A normal authenticated request still works.
    let health = get_auth(&t, "/v1/health").await;
    assert_eq!(health.status, 200, "body: {}", health.body);

    // A WebSocket upgraded before the timeout must stay open while idle past
    // it, then still carry a live turn's frames.
    let mut ws = ws_connect(t.addr, Some(&t.token)).await.unwrap();
    tokio::time::sleep(SLOW_CLIENT_TIMEOUT + Duration::from_millis(100)).await;
    let send = send_async(&t, r#"{"content":"slow"}"#);
    let frame = wait_ws(&mut ws, Duration::from_secs(5), |value| {
        value["type"] == "message.done"
    })
    .await;
    assert!(
        frame.is_some(),
        "the events socket was cut while idle longer than the header timeout"
    );

    // A turn that runs longer than the header timeout is answered whole.
    let response = send.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(
        response.json()["messages"][1]["content"],
        "slow but whole",
        "a long turn must not be cut by the header timeout"
    );

    t.stop();
}
