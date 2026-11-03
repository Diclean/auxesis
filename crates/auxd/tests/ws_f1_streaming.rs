//! WS-F1 streaming integration tests: `message.delta` end to end.
//!
//! Everything runs in-process on an ephemeral loopback port with temp homes
//! and fake providers: no network, no Keychain, no real `~/.auxesis`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// A fixed 64-hex-char API token shared by every test API in this binary.
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

use async_trait::async_trait;
use aux_providers::{
    ChatDelta, ChatProvider, ChatRequest, ChatResponse, FakeProvider, ProviderError,
};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use kernel_core::{config_path, store_path};

use common::{http, HttpResponse};

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

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start(provider: Arc<dyn ChatProvider>, turn_timeout: Option<Duration>) -> Self {
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
                provider: Some(provider),
                turn_timeout,
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

async fn post_auth(t: &TestApi, path: &str, body: &str) -> HttpResponse {
    call(t.addr, "POST", path, Some(&t.token), Some(body)).await
}

async fn get_snapshot(t: &TestApi) -> serde_json::Value {
    let response = call(
        t.addr,
        "GET",
        "/v1/threads/main/messages?limit=50",
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    response.json()
}

fn send_async(t: &TestApi, body: &'static str) -> tokio::task::JoinHandle<HttpResponse> {
    let addr = t.addr;
    let token = t.token.clone();
    tokio::spawn(async move {
        call(
            addr,
            "POST",
            "/v1/threads/main/messages",
            Some(&token),
            Some(body),
        )
        .await
    })
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_connect(t: &TestApi) -> Ws {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{}/v1/events", t.addr)
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", t.token).parse().unwrap(),
    );
    tokio_tungstenite::connect_async(request).await.unwrap().0
}

async fn next_ws_json(ws: &mut Ws, timeout: Duration) -> Option<serde_json::Value> {
    use futures_util::StreamExt;
    loop {
        let message = tokio::time::timeout(timeout, ws.next()).await.ok()??;
        match message.ok()? {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                return serde_json::from_str(&text).ok();
            }
            tokio_tungstenite::tungstenite::Message::Close(_) => return None,
            _ => continue,
        }
    }
}

/// Drain the connect-time snapshots so a test starts on a clean stream.
async fn drain_initial(ws: &mut Ws) {
    tokio::time::sleep(Duration::from_millis(120)).await;
    while next_ws_json(ws, Duration::from_millis(30)).await.is_some() {}
}

/// Every frame until `message.done` (or the deadline).
async fn collect_until_done(ws: &mut Ws, timeout: Duration) -> Vec<serde_json::Value> {
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let Some(value) = next_ws_json(ws, Duration::from_millis(500)).await else {
            continue;
        };
        let done = value["type"] == "message.done";
        frames.push(value);
        if done {
            break;
        }
    }
    frames
}

fn of_type<'a>(frames: &'a [serde_json::Value], kind: &str) -> Vec<&'a serde_json::Value> {
    frames
        .iter()
        .filter(|frame| frame["type"] == kind)
        .collect()
}

fn joined_deltas(frames: &[serde_json::Value]) -> String {
    of_type(frames, "message.delta")
        .iter()
        .map(|frame| frame["text"].as_str().unwrap())
        .collect()
}

/// A provider that reports fixed chunks with a configurable delay, and whose
/// non-streaming answer is the chunks' concatenation.
struct ChunkedProvider {
    inner: FakeProvider,
    chunks: Vec<String>,
    delay: Duration,
}

impl ChunkedProvider {
    fn new(name: &str, full: &str, chunks: &[&str], delay: Duration) -> Self {
        assert_eq!(
            chunks.concat(),
            full,
            "the chunks must concatenate to the full answer"
        );
        Self {
            inner: FakeProvider::repeating(name, ChatResponse::assistant(full)),
            chunks: chunks.iter().map(|chunk| chunk.to_string()).collect(),
            delay,
        }
    }
}

#[async_trait]
impl ChatProvider for ChunkedProvider {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        self.inner.complete(req).await
    }

    async fn complete_streaming(
        &self,
        req: &ChatRequest,
        sink: &(dyn Fn(ChatDelta) + Send + Sync),
    ) -> Result<ChatResponse, ProviderError> {
        let response = self.inner.complete(req).await?;
        for chunk in &self.chunks {
            sink(ChatDelta::Text(chunk.clone()));
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
        }
        Ok(response)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

// ---------------------------------------------------------------------------
// ordering + coalescing
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deltas_stream_in_order_and_coalesce_before_the_persisted_message() {
    let text = "Le streaming fonctionne, token par token.";
    let provider = Arc::new(
        FakeProvider::repeating("fakey", ChatResponse::assistant(text)).with_stream_chunks(2),
    );
    let mut t = TestApi::start(provider, None).await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"go"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    let frames = collect_until_done(&mut ws, Duration::from_secs(10)).await;

    let deltas = of_type(&frames, "message.delta");
    assert!(!deltas.is_empty(), "frames: {frames:#?}");
    assert!(
        deltas.len() < text.chars().count() / 2,
        "deltas must coalesce: {} frames for ~{} chunks",
        deltas.len(),
        text.chars().count() / 2
    );

    // Every delta is a partial of one draft, with a monotonic seq.
    for frame in &deltas {
        assert_eq!(frame["agent"], "main");
        let id = frame["message_id"].as_str().unwrap();
        assert!(id.starts_with("draft-"), "draft id: {id}");
        let seq = frame["seq"].as_u64().unwrap();
        assert!(seq > 0);
    }
    let seqs: Vec<u64> = deltas
        .iter()
        .map(|frame| frame["seq"].as_u64().unwrap())
        .collect();
    assert!(
        seqs.windows(2).all(|pair| pair[0] < pair[1]),
        "seq must increase: {seqs:?}"
    );
    assert_eq!(joined_deltas(&frames), text);

    // The persisted assistant message arrives last and is authoritative.
    let assistants: Vec<&serde_json::Value> = of_type(&frames, "message.new")
        .into_iter()
        .filter(|frame| frame["message"]["author"]["kind"] == "agent")
        .collect();
    assert_eq!(assistants.len(), 1, "frames: {frames:#?}");
    assert_eq!(
        assistants[0]["message"]["blocks"][0]["text"], text,
        "the completed message carries the full answer"
    );
    assert_eq!(assistants[0]["message"]["streaming"], false);
    let last_delta = frames
        .iter()
        .rposition(|frame| frame["type"] == "message.delta")
        .unwrap();
    let assistant = frames
        .iter()
        .position(|frame| {
            frame["type"] == "message.new" && frame["message"]["author"]["kind"] == "agent"
        })
        .unwrap();
    assert!(
        last_delta < assistant,
        "every delta precedes the persisted message: {frames:#?}"
    );
    assert!(!of_type(&frames, "message.done").is_empty());

    t.stop();
}

// ---------------------------------------------------------------------------
// secret safety across split deltas
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_split_across_two_deltas_never_reaches_a_delta_frame() {
    const SECRET: &str = "sk-live-SECRET0123456789";
    let full = format!("before {SECRET} after");
    let provider = Arc::new(ChunkedProvider::new(
        "fakey",
        &full,
        &["before sk-live-", "SECRET0123456789 after"],
        Duration::ZERO,
    ));
    let mut t = TestApi::start(provider, None).await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"go"}"#).await;
    assert_eq!(sent.status, 200, "body: {}", sent.body);
    let frames = collect_until_done(&mut ws, Duration::from_secs(10)).await;

    let deltas = of_type(&frames, "message.delta");
    assert!(!deltas.is_empty(), "frames: {frames:#?}");
    for frame in &deltas {
        let text = frame["text"].as_str().unwrap();
        assert!(!text.contains(SECRET), "delta leaked the secret: {text}");
        assert!(!text.contains("sk-live-"), "delta leaked the key: {text}");
    }
    let streamed = joined_deltas(&frames);
    assert!(
        streamed.contains("sk-<redacted>"),
        "the split secret must be redacted: {streamed}"
    );

    // The daemon-side scrub is the contract (B2-10): the persisted message
    // frame carries the same scrub as the transient channel, even though the
    // store row itself keeps the model's verbatim answer (RV2-04).
    let assistants = of_type(&frames, "message.new");
    let assistant = assistants
        .iter()
        .find(|frame| frame["message"]["author"]["kind"] == "agent")
        .expect("assistant message");
    let persisted = assistant["message"]["blocks"][0]["text"].as_str().unwrap();
    assert!(
        !persisted.contains(SECRET),
        "message.new leaked the key: {persisted}"
    );
    assert!(persisted.contains("<redacted>"), "{persisted}");

    t.stop();
}

// ---------------------------------------------------------------------------
// cancellation mid-stream
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turn_cancelled_mid_stream_persists_no_assistant_message() {
    let provider = Arc::new(ChunkedProvider::new(
        "fakey",
        "partial answer",
        &["partial ", "answer"],
        Duration::from_secs(60),
    ));
    let mut t = TestApi::start(provider, Some(Duration::from_millis(300))).await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let started = tokio::time::Instant::now();
    let sent = post_auth(&t, "/v1/threads/main/messages", r#"{"content":"go"}"#).await;
    assert_eq!(sent.status, 504, "body: {}", sent.body);
    assert_eq!(sent.json()["error"]["code"], "turn_timeout");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the cancel must abort the stream promptly"
    );

    // The user echo may arrive; no assistant message and no completion frame.
    let frames = collect_until_done(&mut ws, Duration::from_millis(500)).await;
    let assistant = frames.iter().find(|frame| {
        frame["type"] == "message.new" && frame["message"]["author"]["kind"] == "agent"
    });
    assert!(assistant.is_none(), "frames: {frames:#?}");
    assert!(of_type(&frames, "message.done").is_empty());

    // The 504 is sent at the timeout, but the cancelled turn finishes on its
    // blocking thread afterwards: it stores the user row and settles the
    // reservation then. Wait for both, bounded, before reading the state.
    let deadline = tokio::time::Instant::now() + common::LOADED_RUNNER_WAIT;
    let (snapshot, roles, reserved) = loop {
        let snapshot = get_snapshot(&t).await;
        let roles: Vec<String> = snapshot["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| message["role"].as_str().unwrap().to_string())
            .collect();
        let reserved = t.store().reservation_count().unwrap();
        let settled = roles == ["system", "user"] && reserved == 0;
        if settled || tokio::time::Instant::now() >= deadline {
            break (snapshot, roles, reserved);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(roles, vec!["system", "user"], "snapshot: {snapshot}");
    assert_eq!(reserved, 0, "the cancelled call releases its reservation");

    t.stop();
}

// ---------------------------------------------------------------------------
// slow client + reconnect + snapshot consistency
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_client_and_a_reconnect_agree_on_the_snapshot() {
    let full = "alpha beta gamma delta epsilon";
    let provider = Arc::new(ChunkedProvider::new(
        "fakey",
        full,
        &["alpha ", "beta ", "gamma ", "delta ", "epsilon"],
        Duration::from_millis(60),
    ));
    let mut t = TestApi::start(provider, None).await;

    // A client that connects but never reads: it cannot slow the producer
    // down, and its missed frames do not matter.
    let _muted = ws_connect(&t).await;

    let sent = send_async(&t, r#"{"content":"go"}"#);
    tokio::time::sleep(Duration::from_millis(80)).await;
    // A second client attaches mid-stream and follows the tail.
    let mut mid = ws_connect(&t).await;
    let frames = collect_until_done(&mut mid, Duration::from_secs(15)).await;
    let response = sent.await.unwrap();
    assert_eq!(response.status, 200, "body: {}", response.body);

    let seen = joined_deltas(&frames);
    assert!(
        full.ends_with(&seen),
        "a late subscriber sees a suffix of the answer: {seen:?}"
    );

    // Reconnect after completion: the persisted snapshot is authoritative and
    // complete.
    let mut late = ws_connect(&t).await;
    drain_initial(&mut late).await;
    let snapshot = get_snapshot(&t).await;
    let assistant = snapshot["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "assistant")
        .expect("assistant message");
    assert_eq!(assistant["content"], full);

    t.stop();
}
