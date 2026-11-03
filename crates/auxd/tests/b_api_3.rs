//! End-to-end tests of the B-API v3 write surface (providers, agents,
//! stop-all, first-run).
//!
//! Real server on an ephemeral loopback port, temp homes, the deterministic
//! fake provider — no network, no real `~/.auxesis`, no real Keychain (the
//! key lookups exercised here resolve through the home's `.env` with
//! accounts that do not exist in the Keychain).

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// A fixed 64-hex-char API token shared by every test API in this binary.
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{assert_error, http, HttpResponse};
use futures_util::StreamExt;
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const FAKE_CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "main"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;

/// A unique Keychain account: the lookup falls through to the home `.env`.
const TEST_ACCOUNT: &str = "bapi3-integration-account-not-in-keychain";

/// The canary key value that must never appear in any response or audit row.
const CANARY_KEY: &str = "sk-canary-bapi3-0123456789abcdef";

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start() -> Self {
        Self::start_with_config(FAKE_CONFIG).await
    }

    async fn start_with_config(config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), config).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            ..ApiOptions::default()
        };
        // One fixed token for every test: the daemon registers it with the
        // exact-value scrubber, and a fresh random token per test would make
        // the process-global registry accumulate one encoding closure per test.
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
        let handle = api::spawn(&home, options).unwrap();
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

async fn call_auth(t: &TestApi, method: &str, path: &str, body: Option<&str>) -> HttpResponse {
    call(t.addr, method, path, Some(&t.token), body).await
}

async fn get_auth(t: &TestApi, path: &str) -> HttpResponse {
    call_auth(t, "GET", path, None).await
}

async fn post_auth(t: &TestApi, path: &str, body: &str) -> HttpResponse {
    call_auth(t, "POST", path, Some(body)).await
}

async fn put_auth(t: &TestApi, path: &str, body: &str) -> HttpResponse {
    call_auth(t, "PUT", path, Some(body)).await
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

/// How long a test waits for one event on the socket. The happy path takes
/// milliseconds; the budget is for a saturated CI runner (several cargo jobs
/// at once), where 5 s produced a false red on a docs-only PR (run 38174639151).
const WS_WAIT: Duration = Duration::from_secs(30);

async fn wait_ws<F: Fn(&Value) -> bool>(
    ws: &mut Ws,
    timeout: Duration,
    predicate: F,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let slice = Duration::from_millis(300).min(deadline - tokio::time::Instant::now());
        let Ok(message) = tokio::time::timeout(slice, ws.next()).await else {
            continue;
        };
        match message {
            Some(Ok(WsMessage::Text(text))) => {
                if let Ok(value) = serde_json::from_str::<Value>(&text) {
                    if predicate(&value) {
                        return Some(value);
                    }
                }
            }
            Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => return None,
            _ => {}
        }
    }
    None
}

fn find<'a>(value: &'a Value, id: &str) -> &'a Value {
    value
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap_or_else(|| panic!("no provider `{id}` in {value}"))
}

/// A loopback "AI service" that counts every connection it accepts. It
/// answers a valid completion so a build that did burn one cannot hang.
struct CountingEndpoint {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl CountingEndpoint {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::clone(&connections);
        let stopped = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                        let mut buffer = [0u8; 4096];
                        let _ = stream.read(&mut buffer);
                        let body = r#"{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            connections,
            stop,
            handle: Some(handle),
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_routes_reject_missing_or_wrong_tokens() {
    let mut t = TestApi::start().await;
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("GET", "/v1/providers", None),
        ("POST", "/v1/providers/test", Some("{}")),
        ("POST", "/v1/providers/fakey/test", Some("{}")),
        ("POST", "/v1/agents", Some("{}")),
        ("PUT", "/v1/agents/main", Some("{}")),
        ("PATCH", "/v1/agents/main", Some("{}")),
        ("GET", "/v1/agents/main/soul", None),
        ("POST", "/v1/agents/main/pause", None),
        ("POST", "/v1/agents/main/resume", None),
        ("POST", "/v1/agents/main/kill", None),
        ("POST", "/v1/stop-all", None),
    ];
    for (method, path, body) in cases {
        let missing = call(t.addr, method, path, None, *body).await;
        assert_error(&missing, 401, "unauthorized");
        let wrong = call(t.addr, method, path, Some("wrong"), *body).await;
        assert_error(&wrong, 401, "unauthorized");
    }
    t.stop();
}

// ---------------------------------------------------------------------------
// providers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn providers_list_reports_key_presence_never_the_key() {
    let config = format!(
        "{FAKE_CONFIG}\n\
         [[providers]]\nid = \"bapi3cloud\"\nbase_url = \"https://127.0.0.1:9/v1\"\n\
         model = \"cloud-model\"\nkey_user = \"{TEST_ACCOUNT}\"\nkind = \"openai-compat\"\n"
    );
    let mut t = TestApi::start_with_config(&config).await;
    std::fs::write(
        t.home.join(".env"),
        format!("AUX_KEY_BAPI3CLOUD={CANARY_KEY}\n"),
    )
    .unwrap();

    let response = get_auth(&t, "/v1/providers").await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert!(
        !response.body.contains(CANARY_KEY),
        "the key value must never appear: {}",
        response.body
    );
    let body = response.json();
    assert_eq!(body.as_array().unwrap().len(), 2);

    let cloud = find(&body, "bapi3cloud");
    assert_eq!(cloud["model"], "cloud-model");
    assert_eq!(cloud["key_required"], true);
    assert_eq!(cloud["key_present"], true);
    assert_eq!(cloud["key_location"], "env");
    assert!(cloud.get("key").is_none(), "no raw key field");

    let fake = find(&body, "fakey");
    assert_eq!(fake["key_required"], false);
    assert_eq!(fake["kind"], "fake");
    assert!(fake.get("key").is_none());
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn providers_test_is_cheap_spend_free_and_never_echoes_a_key() {
    let config = format!(
        "{FAKE_CONFIG}\n\
         [[providers]]\nid = \"bapi3local\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
         model = \"local-model\"\nkind = \"openai-compat\"\n"
    );
    let mut t = TestApi::start_with_config(&config).await;

    // A configured loopback provider: config valid, no key needed, probe
    // skipped by the fetch policy (never reported as a failure).
    let ok = post_auth(&t, "/v1/providers/test", r#"{"name":"bapi3local"}"#).await;
    assert_eq!(ok.status, 200, "body: {}", ok.body);
    let value = ok.json();
    assert_eq!(value["ok"], true);
    assert_eq!(value["key_required"], false);
    assert_eq!(value["reachable"], Value::Null);
    assert!(value["note"].as_str().unwrap().contains("fetch policy"));
    assert_eq!(value["models"].as_array().unwrap().len(), 0, "no live call");

    // The per-id route works with an empty body too.
    let by_id = post_auth(&t, "/v1/providers/bapi3local/test", "{}").await;
    assert_eq!(by_id.status, 200, "body: {}", by_id.body);
    assert_eq!(by_id.json()["ok"], true);

    // An inline entry with a canary key: the key is used for the check and
    // never echoed anywhere.
    let inline = post_auth(
        &t,
        "/v1/providers/test",
        &json!({
            "name": "inline",
            "base_url": "http://127.0.0.1:9/v1",
            "model": "inline-model",
            "api_key": CANARY_KEY,
        })
        .to_string(),
    )
    .await;
    assert_eq!(inline.status, 200, "body: {}", inline.body);
    assert!(!inline.body.contains(CANARY_KEY), "{}", inline.body);
    let inline = inline.json();
    assert_eq!(inline["ok"], true);
    assert_eq!(inline["key_present"], true);
    assert_eq!(inline["reachable"], Value::Null);

    // Validation errors are plain-language codes.
    let missing = post_auth(&t, "/v1/providers/test", "{}").await;
    assert_error(&missing, 400, "missing_name");
    let unknown = post_auth(&t, "/v1/providers/test", r#"{"name":"ghost"}"#).await;
    assert_error(&unknown, 404, "provider_not_found");
    let kind = post_auth(
        &t,
        "/v1/providers/test",
        r#"{"name":"x","base_url":"http://127.0.0.1:9/v1","model":"m","kind":"grpc"}"#,
    )
    .await;
    assert_error(&kind, 400, "invalid_kind");
    let bad_url = post_auth(
        &t,
        "/v1/providers/test",
        r#"{"name":"x","base_url":"ftp://example.com","model":"m"}"#,
    )
    .await;
    assert_eq!(bad_url.status, 200, "body: {}", bad_url.body);
    assert_eq!(bad_url.json()["ok"], false);
    assert!(bad_url.json()["error"].is_string());
    let bad_json = post_auth(&t, "/v1/providers/test", "not json").await;
    assert_error(&bad_json, 400, "invalid_json");

    // Nothing in the audit log carries the canary either.
    for kind in ["agent.created", "agent.updated", "daemon.stop_all"] {
        for payload in event_payloads(&t.home, kind) {
            assert!(!payload.contains(CANARY_KEY), "{kind}: {payload}");
        }
    }
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn providers_test_never_contacts_the_configured_service() {
    // M12: the cheap check must stay spend-free. The configured provider
    // points at a counting loopback endpoint: if the route built a provider
    // and sent a completion, the endpoint sees a connection.
    let mut endpoint = CountingEndpoint::start();
    let config = format!(
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n\n\
         [[providers]]\nid = \"counted\"\nbase_url = \"http://{}/v1\"\n\
         model = \"counting-model\"\nkind = \"openai-compat\"\n",
        endpoint.addr
    );
    let mut t = TestApi::start_with_config(&config).await;

    let by_name = post_auth(&t, "/v1/providers/test", r#"{"name":"counted"}"#).await;
    assert_eq!(by_name.status, 200, "body: {}", by_name.body);
    assert_eq!(by_name.json()["ok"], true);
    assert_eq!(
        by_name.json()["reachable"],
        Value::Null,
        "loopback is skipped"
    );
    assert_eq!(by_name.json()["models"].as_array().unwrap().len(), 0);

    let by_id = post_auth(&t, "/v1/providers/counted/test", "{}").await;
    assert_eq!(by_id.status, 200, "body: {}", by_id.body);
    assert_eq!(by_id.json()["ok"], true);

    // A queued connection from a mutated build would still be accepted by
    // the (non-blocking) counter before this assert.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        endpoint.connections(),
        0,
        "POST /v1/providers/test must never send a completion"
    );
    endpoint.stop();
    t.stop();
}

// ---------------------------------------------------------------------------
// agents: create / update
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_agent_writes_real_artifacts_is_idempotent_and_audited() {
    let mut t = TestApi::start().await;
    let config_before = std::fs::read_to_string(config_path(&t.home)).unwrap();
    let body = json!({
        "name": "scout",
        "role": "# scout\nwatch the news",
        "provider": "fakey",
        "tools": ["read_file"],
    })
    .to_string();

    let created = post_auth(&t, "/v1/agents", &body).await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let value = created.json();
    assert_eq!(value["created"], true);
    assert_eq!(value["agent"]["name"], "scout");
    assert_eq!(value["agent"]["provider"], "fakey");
    assert_eq!(value["agent"]["tools"][0], "read_file");
    assert_eq!(value["agent"]["paused"], false);
    assert_eq!(value["agent"]["killed"], false);
    assert!(
        !created.body.contains(t.home.to_str().unwrap()),
        "no home path"
    );

    let dir = t.home.join("agents").join("scout");
    assert!(dir.is_dir());
    assert_eq!(
        std::fs::read_to_string(dir.join("soul.md")).unwrap(),
        "# scout\nwatch the news"
    );
    let sidecar = std::fs::read_to_string(dir.join("agent.toml")).unwrap();
    assert!(sidecar.contains("provider = \"fakey\""));
    assert!(sidecar.contains("read_file"));

    // The agent is visible through the read endpoints with its config.
    let list = get_auth(&t, "/v1/agents").await.json();
    let scout = list
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "scout")
        .unwrap();
    assert_eq!(scout["paused"], false);
    assert_eq!(scout["killed"], false);
    let detail = get_auth(&t, "/v1/agents/scout").await.json();
    assert_eq!(detail["agent"]["provider"], "fakey");
    assert_eq!(detail["agent"]["tools"][0], "read_file");
    assert_eq!(detail["agent"]["instructions"], "# scout\nwatch the news");

    // Identical create → idempotent 200; different content → 409.
    let again = post_auth(&t, "/v1/agents", &body).await;
    assert_eq!(again.status, 200, "body: {}", again.body);
    assert_eq!(again.json()["created"], false);
    let different = post_auth(
        &t,
        "/v1/agents",
        r#"{"name":"scout","role":"something else"}"#,
    )
    .await;
    assert_error(&different, 409, "agent_exists");

    // Exactly one creation was audited.
    let created_rows = event_payloads(&t.home, "agent.created");
    assert_eq!(created_rows.len(), 1, "{created_rows:?}");
    assert!(created_rows[0].contains("\"agent\":\"scout\""));

    // Validation with plain-language errors.
    let missing = post_auth(&t, "/v1/agents", "{}").await;
    assert_error(&missing, 400, "missing_name");
    let escape = post_auth(&t, "/v1/agents", r#"{"name":"../escape"}"#).await;
    assert_error(&escape, 400, "invalid_name");
    let provider = post_auth(&t, "/v1/agents", r#"{"name":"a","provider":"ghost"}"#).await;
    assert_error(&provider, 400, "unknown_provider");
    let tool = post_auth(&t, "/v1/agents", r#"{"name":"a","tools":["not-a-tool"]}"#).await;
    assert_error(&tool, 400, "unknown_tool");
    let bad_json = post_auth(&t, "/v1/agents", "not json").await;
    assert_error(&bad_json, 400, "invalid_json");
    assert!(
        !t.home.join("agents").join("a").exists(),
        "no half-created agent"
    );
    // An agent write never touches the global config: no rule, no sandbox
    // exception, nothing that could widen another agent's rights.
    assert_eq!(
        std::fs::read_to_string(config_path(&t.home)).unwrap(),
        config_before
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_instructions_are_scrubbed_in_the_api_view_only() {
    // B3-02: the detail view goes through the same sanitize + scrub as
    // messages/tool content; the stored `soul.md` stays raw.
    let mut t = TestApi::start().await;
    let hostile = format!(
        "\u{1b}[31mred\u{0}end {}/agents/main AUX_KEY_X=sk-live-abcdef12345 sk-ant-9xyz",
        t.home.display()
    );
    let created = post_auth(
        &t,
        "/v1/agents",
        &json!({ "name": "souly", "role": hostile }).to_string(),
    )
    .await;
    assert_eq!(created.status, 201, "body: {}", created.body);

    let stored = std::fs::read_to_string(t.home.join("agents/souly/soul.md")).unwrap();
    assert_eq!(stored, hostile, "storage stays raw");

    let detail = get_auth(&t, "/v1/agents/souly").await;
    assert_eq!(detail.status, 200, "body: {}", detail.body);
    let value = detail.json();
    let instructions = value["agent"]["instructions"].as_str().unwrap();
    assert!(!instructions.contains('\u{1b}'), "{instructions:?}");
    assert!(!instructions.contains('\u{0}'), "{instructions:?}");
    assert!(
        !instructions.contains(t.home.to_str().unwrap()),
        "the real home path must not cross the API: {instructions:?}"
    );
    assert!(!instructions.contains("abcdef12345"), "{instructions:?}");
    assert!(instructions.contains("sk-<redacted>"), "{instructions:?}");
    assert!(
        instructions.contains("AUX_KEY_X=<redacted>"),
        "{instructions:?}"
    );
    assert!(
        instructions.contains("<home>/agents/main"),
        "{instructions:?}"
    );
    assert!(instructions.contains("redend"), "{instructions:?}");
    assert_eq!(value["agent"]["truncated"], false);

    // The agent list carries no instructions at all, so no raw soul either.
    let list = get_auth(&t, "/v1/agents").await;
    assert!(!list.body.contains("abcdef12345"), "{}", list.body);
    assert!(!list.body.contains('\u{1b}'), "{}", list.body);
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_request_body_limit_is_the_one_instructions_cap() {
    // B3-03: the old 1 MiB `invalid_role` check was unreachable behind the
    // 128 KiB body limit. The body limit is now the single, tested cap, with
    // a plain-language message; the API view still caps at MESSAGE_MAX_BYTES
    // and flags the cut.
    let mut t = TestApi::start().await;

    let big = "x".repeat(api::MAX_REQUEST_BODY_BYTES - 4096);
    let created = post_auth(
        &t,
        "/v1/agents",
        &json!({ "name": "big", "role": big }).to_string(),
    )
    .await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    assert_eq!(
        std::fs::metadata(t.home.join("agents/big/soul.md"))
            .unwrap()
            .len(),
        big.len() as u64,
        "the whole instruction is stored under the limit"
    );
    let detail = get_auth(&t, "/v1/agents/big").await.json();
    let view = detail["agent"]["instructions"].as_str().unwrap();
    assert_eq!(detail["agent"]["truncated"], true);
    assert!(
        view.len() <= api::MESSAGE_MAX_BYTES + 256,
        "the API view is capped, got {} bytes",
        view.len()
    );
    assert!(view.contains("[truncated"), "the cut is marked");

    // Over the body limit: a clean 413 naming the limit, on both write verbs.
    let huge = "x".repeat(api::MAX_REQUEST_BODY_BYTES + 1024);
    let rejected = post_auth(
        &t,
        "/v1/agents",
        &json!({ "name": "huge", "role": huge }).to_string(),
    )
    .await;
    assert_error(&rejected, 413, "payload_too_large");
    assert!(
        rejected.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("128 KiB"),
        "plain-language limit: {}",
        rejected.body
    );
    assert!(
        !t.home.join("agents/huge").exists(),
        "no half-created agent"
    );

    let huge = "x".repeat(api::MAX_REQUEST_BODY_BYTES + 1024);
    let rejected = put_auth(&t, "/v1/agents/big", &json!({ "role": huge }).to_string()).await;
    assert_error(&rejected, 413, "payload_too_large");
    assert_eq!(
        std::fs::metadata(t.home.join("agents/big/soul.md"))
            .unwrap()
            .len(),
        big.len() as u64,
        "a rejected update changes nothing"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_personality_is_readable_and_writable_through_the_soul_route() {
    let mut t = TestApi::start().await;

    let created = post_auth(
        &t,
        "/v1/agents",
        r#"{"name":"scout","role":"watch the news"}"#,
    )
    .await;
    assert_eq!(created.status, 201, "body: {}", created.body);

    // GET /v1/agents/{id}/soul: the whole raw text plus the 1 MiB ceiling the
    // app's editor counts against.
    let read = get_auth(&t, "/v1/agents/scout/soul").await;
    assert_eq!(read.status, 200, "body: {}", read.body);
    let value = read.json();
    assert_eq!(value["soul_md"], "watch the news");
    assert_eq!(value["max_bytes"], aux_engine::MAX_SOUL_BYTES);
    assert_eq!(value["is_default"], false);

    // PUT with the app's `soul_md` field updates the same file through the one
    // secure write path.
    let updated = put_auth(&t, "/v1/agents/scout", r#"{"soul_md":"be terse"}"#).await;
    assert_eq!(updated.status, 200, "body: {}", updated.body);
    assert_eq!(
        std::fs::read_to_string(t.home.join("agents/scout/soul.md")).unwrap(),
        "be terse"
    );
    assert_eq!(
        get_auth(&t, "/v1/agents/scout/soul").await.json()["soul_md"],
        "be terse"
    );

    // Another agent's soul is never visible: distinct text, unknown name 404,
    // a path-escaping name 400.
    post_auth(&t, "/v1/agents", r#"{"name":"bolt","role":"bolt only"}"#).await;
    assert_eq!(
        get_auth(&t, "/v1/agents/bolt/soul").await.json()["soul_md"],
        "bolt only"
    );
    let missing = get_auth(&t, "/v1/agents/ghost/soul").await;
    assert_error(&missing, 404, "agent_not_found");
    let escape = get_auth(&t, "/v1/agents/..%2Fescape/soul").await;
    assert_eq!(escape.status, 400, "body: {}", escape.body);

    // Over the body limit: refused with the one honest 413, and the previous
    // personality stays in place.
    let huge = "x".repeat(api::MAX_REQUEST_BODY_BYTES + 1024);
    let rejected = put_auth(
        &t,
        "/v1/agents/scout",
        &json!({ "soul_md": huge }).to_string(),
    )
    .await;
    assert_error(&rejected, 413, "payload_too_large");
    assert_eq!(
        get_auth(&t, "/v1/agents/scout/soul").await.json()["soul_md"],
        "be terse",
        "a refused save changes nothing"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_identical_creates_leave_exactly_one_agent() {
    let mut t = TestApi::start().await;
    let body = json!({
        "name": "racer",
        "role": "same everywhere",
        "provider": "fakey",
    })
    .to_string();

    let mut handles = Vec::new();
    for _ in 0..6 {
        let addr = t.addr;
        let token = t.token.clone();
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            call(addr, "POST", "/v1/agents", Some(&token), Some(&body)).await
        }));
    }
    let mut statuses = Vec::new();
    for handle in handles {
        statuses.push(handle.await.unwrap().status);
    }
    statuses.sort();
    assert_eq!(
        statuses.iter().filter(|status| **status == 201).count(),
        1,
        "exactly one create: {statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .all(|status| *status == 201 || *status == 200),
        "identical concurrent creates must be idempotent: {statuses:?}"
    );
    assert_eq!(event_payloads(&t.home, "agent.created").len(), 1);
    let sidecar = std::fs::read_to_string(t.home.join("agents/racer/agent.toml")).unwrap();
    assert!(sidecar.contains("provider = \"fakey\""));
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_conflicting_creates_leave_one_winner() {
    let mut t = TestApi::start().await;
    let mut handles = Vec::new();
    for index in 0..4 {
        let addr = t.addr;
        let token = t.token.clone();
        handles.push(tokio::spawn(async move {
            let body = json!({ "name": "racer", "role": format!("role {index}") }).to_string();
            call(addr, "POST", "/v1/agents", Some(&token), Some(&body)).await
        }));
    }
    let mut statuses = Vec::new();
    for handle in handles {
        statuses.push(handle.await.unwrap().status);
    }
    assert_eq!(
        statuses.iter().filter(|status| **status == 201).count(),
        1,
        "exactly one winner: {statuses:?}"
    );
    assert!(
        statuses.iter().filter(|status| **status == 409).count() == 3,
        "losers conflict: {statuses:?}"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_agent_merges_fields_and_audits() {
    let mut t = TestApi::start().await;
    let created = post_auth(
        &t,
        "/v1/agents",
        r#"{"name":"scout","role":"old","provider":"fakey","model":"m1"}"#,
    )
    .await;
    assert_eq!(created.status, 201, "body: {}", created.body);

    let updated = put_auth(
        &t,
        "/v1/agents/scout",
        r#"{"role":"new role","provider":null,"tools":["read_file","shell"]}"#,
    )
    .await;
    assert_eq!(updated.status, 200, "body: {}", updated.body);
    let value = updated.json();
    assert_eq!(value["agent"]["provider"], Value::Null);
    assert_eq!(value["agent"]["model"], "m1", "model untouched");
    assert_eq!(value["agent"]["tools"][1], "shell");
    assert_eq!(
        std::fs::read_to_string(t.home.join("agents/scout/soul.md")).unwrap(),
        "new role"
    );

    // PATCH is the app's verb and behaves the same.
    let patched = call_auth(&t, "PATCH", "/v1/agents/scout", Some(r#"{"model":"m2"}"#)).await;
    assert_eq!(patched.status, 200, "body: {}", patched.body);
    assert_eq!(patched.json()["agent"]["model"], "m2");

    let payloads = event_payloads(&t.home, "agent.updated");
    assert_eq!(payloads.len(), 2, "{payloads:?}");
    assert!(payloads[0].contains("\"fields\""));
    assert!(
        !payloads[0].contains("new role"),
        "instructions stay out of audit"
    );

    let unknown = put_auth(&t, "/v1/agents/ghost", r#"{"role":"x"}"#).await;
    assert_error(&unknown, 404, "agent_not_found");
    let rename = put_auth(&t, "/v1/agents/scout", r#"{"name":"other"}"#).await;
    assert_error(&rename, 400, "invalid_name");
    let empty = put_auth(&t, "/v1/agents/scout", "{}").await;
    assert_error(&empty, 400, "empty_update");
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn skills_list_and_agent_update_are_authenticated_and_bounded() {
    let mut t = TestApi::start().await;
    let skill_dir = t.home.join("skills/writing");
    std::fs::create_dir_all(&skill_dir).unwrap();
    std::fs::write(
        skill_dir.join("SKILL.md"),
        "---\nname: writing\ndescription: Write clearly\n---\nUse short sentences.\n",
    )
    .unwrap();
    let extra_dir = t.home.join("skills/extra");
    std::fs::create_dir_all(&extra_dir).unwrap();
    std::fs::write(extra_dir.join("SKILL.md"), "instructions").unwrap();
    std::fs::write(extra_dir.join("run.sh"), "must never execute").unwrap();

    let unauthenticated = call(t.addr, "GET", "/v1/skills", None, None).await;
    assert_error(&unauthenticated, 401, "unauthorized");
    let listed = call_auth(&t, "GET", "/v1/skills", None).await;
    assert_eq!(listed.status, 200, "body: {}", listed.body);
    let skills = listed.json();
    assert_eq!(skills[0]["name"], "extra");
    assert_eq!(skills[0]["status"]["state"], "valid");
    assert_eq!(
        skills[0]["status"]["warning"],
        "other files are present and ignored"
    );
    assert_eq!(skills[1]["name"], "writing");
    assert_eq!(skills[1]["description"], "Write clearly");

    let created = post_auth(&t, "/v1/agents", r#"{"name":"scout"}"#).await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let updated = put_auth(&t, "/v1/agents/scout", r#"{"skills":["writing"]}"#).await;
    assert_eq!(updated.status, 200, "body: {}", updated.body);
    assert_eq!(updated.json()["agent"]["skills"][0], "writing");
    let detail = call_auth(&t, "GET", "/v1/agents/scout", None).await;
    assert_eq!(detail.json()["agent"]["skills"][0], "writing");

    let unknown = put_auth(&t, "/v1/agents/scout", r#"{"skills":["missing"]}"#).await;
    assert_error(&unknown, 400, "invalid_skills");
    let invalid = put_auth(&t, "/v1/agents/scout", r#"{"skills":["../outside"]}"#).await;
    assert_error(&invalid, 400, "invalid_skill_name");
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_with_an_unconfigured_provider_is_a_clean_4xx() {
    // B3-05 / mutation M17: `POST /v1/agents` already validated the provider;
    // `PUT` must too, or an agent ends up pointed at a service that does not
    // exist and only fails later, at turn time.
    let mut t = TestApi::start().await;
    let created = post_auth(&t, "/v1/agents", r#"{"name":"scout","provider":"fakey"}"#).await;
    assert_eq!(created.status, 201, "body: {}", created.body);

    let put = put_auth(&t, "/v1/agents/scout", r#"{"provider":"ghost"}"#).await;
    assert_error(&put, 400, "unknown_provider");
    let body = put.body.clone();
    assert!(
        body.contains("fakey"),
        "the hint lists what is available: {body}"
    );

    // The sidecar is untouched: still `fakey`, no `ghost` write.
    let sidecar = std::fs::read_to_string(t.home.join("agents/scout/agent.toml")).unwrap();
    assert!(sidecar.contains("provider = \"fakey\""), "{sidecar}");
    assert!(!sidecar.contains("ghost"), "{sidecar}");
    t.stop();
}

// ---------------------------------------------------------------------------
// agents: pause / resume / kill, stop-all
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_kill_and_resume_really_stop_and_restart_turns() {
    let mut t = TestApi::start().await;
    let created = post_auth(&t, "/v1/agents", r#"{"name":"scout"}"#).await;
    assert_eq!(created.status, 201, "body: {}", created.body);

    // Pause: turns are refused, idempotently marked, and audited.
    let paused = post_auth(&t, "/v1/agents/scout/pause", "{}").await;
    assert_eq!(paused.status, 200, "body: {}", paused.body);
    let value = paused.json();
    assert_eq!(value["paused"], true);
    assert_eq!(value["changed"], true);
    let again = post_auth(&t, "/v1/agents/scout/pause", "{}").await;
    assert_eq!(again.json()["changed"], false);

    let refused = post_auth(&t, "/v1/threads/scout/messages", r#"{"content":"hello"}"#).await;
    assert_error(&refused, 409, "agent_inactive");
    assert!(
        refused.json()["error"]["detail"]
            .as_str()
            .unwrap()
            .contains("paused"),
        "{}",
        refused.body
    );

    // Resume: the same turn now runs through the fake provider.
    let resumed = post_auth(&t, "/v1/agents/scout/resume", "{}").await;
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    assert_eq!(resumed.json()["paused"], false);
    assert_eq!(resumed.json()["changed"], true);
    let sent = post_auth(&t, "/v1/threads/scout/messages", r#"{"content":"hello"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    assert_eq!(sent.json()["messages"][1]["content"], "[fake:fakey] hello");

    // Kill: sticky stop; pause is refused while killed; resume clears it.
    let killed = post_auth(&t, "/v1/agents/scout/kill", "{}").await;
    assert_eq!(killed.status, 200, "body: {}", killed.body);
    assert_eq!(killed.json()["killed"], true);
    let killed_send = post_auth(&t, "/v1/threads/scout/messages", r#"{"content":"again"}"#).await;
    assert_error(&killed_send, 409, "agent_inactive");
    let pause_killed = post_auth(&t, "/v1/agents/scout/pause", "{}").await;
    assert_error(&pause_killed, 409, "agent_killed");
    let resumed = post_auth(&t, "/v1/agents/scout/resume", "{}").await;
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    assert_eq!(resumed.json()["killed"], false);
    let sent = post_auth(&t, "/v1/threads/scout/messages", r#"{"content":"back"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);

    // The list reflects the markers too.
    let list = get_auth(&t, "/v1/agents").await.json();
    let scout = list
        .as_array()
        .unwrap()
        .iter()
        .find(|agent| agent["name"] == "scout")
        .unwrap();
    assert_eq!(scout["paused"], false);

    for kind in ["agent.paused", "agent.killed"] {
        assert_eq!(event_payloads(&t.home, kind).len(), 1, "{kind}");
    }
    assert_eq!(
        event_payloads(&t.home, "agent.resumed").len(),
        2,
        "paused then killed"
    );
    let unknown = post_auth(&t, "/v1/agents/ghost/pause", "{}").await;
    assert_error(&unknown, 404, "agent_not_found");
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stop_all_engages_the_kill_switch_is_idempotent_and_audited() {
    let mut t = TestApi::start().await;
    let opening = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hello"}"#).await;
    assert_eq!(opening.status, 200, "body: {}", opening.body);

    let first = post_auth(&t, "/v1/stop-all", "{}").await;
    assert_eq!(first.status, 200, "body: {}", first.body);
    assert_eq!(first.json()["stop"], true);
    assert_eq!(first.json()["changed"], true);

    let second = post_auth(&t, "/v1/stop-all", "{}").await;
    assert_eq!(second.json()["changed"], false, "idempotent");

    // Stop with no resume still refuses a new turn.
    let refused = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hi"}"#).await;
    assert_error(&refused, 409, "stopped");

    assert_eq!(event_payloads(&t.home, "daemon.stop_all").len(), 1);
    let release = post_auth(&t, "/v1/resume", "{}").await;
    assert_eq!(release.status, 200, "body: {}", release.body);
    assert_eq!(release.json()["stop"], false);

    // RESUME-AFTER-STOP: Resume leaves the lifted stop as the last row.
    let page = get_auth(&t, "/v1/threads/main/messages").await.json();
    let last = page["messages"]
        .as_array()
        .expect("messages")
        .last()
        .expect("a row");
    assert_eq!(last["role"], "system");
    assert!(
        last["content"]
            .as_str()
            .is_some_and(|text| text.contains("You resumed all agents")),
        "Resume leaves the lifted stop as the last thing the next turn reads: {last}"
    );

    // The very next turn runs and answers normally. A released switch must
    // not leave the refusal behind for new work.
    let resumed = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"hi"}"#).await;
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    let body = resumed.json();
    let reply = body["messages"]
        .as_array()
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| message["role"] == "assistant")
        })
        .and_then(|message| message["content"].as_str())
        .expect("the resumed turn stores an assistant reply");
    assert_eq!(reply, "[fake:fakey] hi");
    assert!(
        !reply.contains("Stopped"),
        "the resumed turn must not repeat the stop reply: {reply:?}"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_records_the_lifted_stop_only_in_chats_that_never_ran_private() {
    let mut t = TestApi::start().await;
    let store = Store::open(&store_path(&t.home)).unwrap();
    let open = store.create_session("main", None).unwrap();
    store
        .append_message(open.id, "user", "hello", None)
        .unwrap();
    let private = store.create_session("scout", None).unwrap();
    store
        .append_message(private.id, "user", "hello", None)
        .unwrap();
    store.mark_session_ever_private(private.id).unwrap();
    drop(store);

    let stopped = post_auth(&t, "/v1/stop-all", "{}").await;
    assert_eq!(stopped.status, 200, "body: {}", stopped.body);
    let resumed = post_auth(&t, "/v1/resume", "{}").await;
    assert_eq!(resumed.status, 200, "body: {}", resumed.body);
    assert_eq!(resumed.json()["changed"], true);

    let store = Store::open(&store_path(&t.home)).unwrap();
    let notes = |session: i64| {
        store
            .list_messages(session)
            .unwrap()
            .into_iter()
            .filter(|message| {
                message.role == "system" && message.content.contains("You resumed all agents")
            })
            .count()
    };
    assert_eq!(
        notes(open.id),
        1,
        "the open chat reads that the stop is over"
    );
    assert_eq!(
        notes(private.id),
        0,
        "a chat that ever ran Private never stores the resume line"
    );
    t.stop();
}

// ---------------------------------------------------------------------------
// first_run
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_run_is_true_until_a_provider_and_an_agent_both_exist() {
    // A fresh home with a provider but no agent: still first run.
    let mut t = TestApi::start().await;
    let health = get_auth(&t, "/v1/health").await.json();
    assert_eq!(health["first_run"], true);
    assert_eq!(health["ok"], true);

    let created = post_auth(&t, "/v1/agents", r#"{"name":"scout"}"#).await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let health = get_auth(&t, "/v1/health").await.json();
    assert_eq!(health["first_run"], false, "provider + agent: done");
    t.stop();

    // An agent without a provider is still a first run.
    let mut t = TestApi::start_with_config(
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"main\"\n",
    )
    .await;
    let created = post_auth(&t, "/v1/agents", r#"{"name":"scout"}"#).await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let health = get_auth(&t, "/v1/health").await.json();
    assert_eq!(health["first_run"], true, "no provider configured yet");
    t.stop();
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_publishes_agent_write_events_in_the_journal_shape() {
    let mut t = TestApi::start().await;
    let mut ws = ws_connect(t.addr, &t.token).await;

    let created = post_auth(
        &t,
        "/v1/agents",
        r#"{"name":"scout","role":"watch","provider":"fakey"}"#,
    )
    .await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let event = wait_ws(&mut ws, WS_WAIT, |value| {
        value["type"] == "agent.created" && value["agent"] == "scout"
    })
    .await
    .expect("agent.created must reach the socket");
    assert!(event["seq"].as_i64().unwrap() > 0);
    assert_eq!(event["payload"]["provider"], "fakey");

    let paused = post_auth(&t, "/v1/agents/scout/pause", "{}").await;
    assert_eq!(paused.status, 200, "body: {}", paused.body);
    wait_ws(&mut ws, WS_WAIT, |value| {
        value["type"] == "agent.paused" && value["agent"] == "scout"
    })
    .await
    .expect("agent.paused must reach the socket");

    let stopped = post_auth(&t, "/v1/stop-all", "{}").await;
    assert_eq!(stopped.status, 200, "body: {}", stopped.body);
    wait_ws(&mut ws, WS_WAIT, |value| value["type"] == "daemon.stop_all")
        .await
        .expect("daemon.stop_all must reach the socket");
    t.stop();
}

// ---------------------------------------------------------------------------
// real binary: the key never reaches stdout/stderr either
// ---------------------------------------------------------------------------

/// Spawn the real `auxd` with both streams piped and collected.
fn spawn_daemon(dir: &Path, home: &Path) -> (Child, mpsc::Receiver<u16>, Arc<Mutex<Vec<String>>>) {
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir, home)
        .env("AUXESIS_API_PORT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (sender, receiver) = mpsc::channel();
    let collected = Arc::new(Mutex::new(Vec::new()));
    for stream in [
        child
            .stdout
            .take()
            .map(|out| Box::new(out) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|err| Box::new(err) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sender = sender.clone();
        let collected = Arc::clone(&collected);
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if let Some(rest) = line.strip_prefix("auxd api on http://127.0.0.1:") {
                    if let Ok(port) = rest.trim().parse::<u16>() {
                        let _ = sender.send(port);
                    }
                }
                collected.lock().unwrap().push(line);
            }
        });
    }
    (child, receiver, collected)
}

#[test]
fn the_daemon_never_logs_the_key_it_resolves() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        config_path(&home),
        format!(
            "{FAKE_CONFIG}\n\
             [[providers]]\nid = \"bapi3cloud\"\nbase_url = \"https://127.0.0.1:9/v1\"\n\
             model = \"cloud-model\"\nkey_user = \"{TEST_ACCOUNT}\"\nkind = \"openai-compat\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        home.join(".env"),
        format!("AUX_KEY_BAPI3CLOUD={CANARY_KEY}\n"),
    )
    .unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();

    let (mut child, ports, collected) = spawn_daemon(dir.path(), &home);
    let port = ports
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| {
            let _ = child.kill();
            panic!("the daemon never announced the local API")
        });
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let token = std::fs::read_to_string(api::token_path(&home))
        .unwrap()
        .trim()
        .to_string();

    // Exercise every path that touches a key.
    let listed = http(addr, "GET", "/v1/providers", Some(&token), None);
    assert_eq!(listed.status, 200, "body: {}", listed.body);
    assert!(!listed.body.contains(CANARY_KEY), "{}", listed.body);
    let tested = http(
        addr,
        "POST",
        "/v1/providers/test",
        Some(&token),
        Some(r#"{"name":"bapi3cloud"}"#),
    );
    assert_eq!(tested.status, 200, "body: {}", tested.body);
    assert!(!tested.body.contains(CANARY_KEY), "{}", tested.body);
    let inline = http(
        addr,
        "POST",
        "/v1/providers/test",
        Some(&token),
        Some(
            &json!({
                "name": "inline",
                "base_url": "http://127.0.0.1:9/v1",
                "model": "m",
                "api_key": CANARY_KEY,
            })
            .to_string(),
        ),
    );
    assert_eq!(inline.status, 200, "body: {}", inline.body);
    assert!(!inline.body.contains(CANARY_KEY), "{}", inline.body);

    // SIGTERM → clean exit, then scan every captured line.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = std::time::Instant::now() + WS_WAIT;
    let mut exited = false;
    while std::time::Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !exited {
        let _ = child.kill();
    }
    let _ = child.wait();
    // Give the reader threads a moment to drain the pipes.
    std::thread::sleep(Duration::from_millis(100));
    let lines = collected.lock().unwrap().clone();
    assert!(
        !lines.iter().any(|line| line.contains(CANARY_KEY)),
        "the key leaked into stdout/stderr: {lines:?}"
    );
}
