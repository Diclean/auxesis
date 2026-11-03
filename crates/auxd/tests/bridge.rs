//! Mac bridge integration tests (work order A2b-d, `docs/phase1.md` §3).
//!
//! Everything runs in-process on an ephemeral loopback port with a temp home:
//! no network, no Keychain, no real `~/.auxesis`. The fake app is a real
//! `tokio-tungstenite` client on `WS /v1/events` that answers with a real
//! `POST /v1/bridge/{id}`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use auxd::bridge::{Bridge, BridgeError, BridgeOp};
use kernel_core::{config_path, store_path};

use common::{http, HttpResponse};

/// A fixed 64-hex-char API token shared by every test API in this binary.
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const FAKE_CONFIG: &str = r#"
version = 1
privacy.mode = "open"
default_agent = "main"
"#;

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    bridge: Arc<Bridge>,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
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
        let bridge = handle.bridge();
        let token = std::fs::read_to_string(api::token_path(&home))
            .unwrap()
            .trim()
            .to_string();
        Self {
            _dir: dir,
            home,
            addr,
            token,
            bridge,
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

/// The next `bridge.request` frame, skipping agent/journal frames.
///
/// The store broadcaster re-emits each journal row with its kind as `type`, so
/// a `bridge.request` ledger row also arrives as a `type:"bridge.request"`
/// message — but with its fields nested under `payload`. Only the real frame
/// carries a top-level `id`.
async fn find_bridge_frame(ws: &mut Ws, budget: Duration) -> Option<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        let Some(value) = next_ws_json(ws, Duration::from_millis(200)).await else {
            continue;
        };
        if value["type"] == "bridge.request" && value["id"].is_string() {
            return Some(value);
        }
    }
    None
}

fn spawn_call(
    bridge: Arc<Bridge>,
    op: BridgeOp,
    args: serde_json::Value,
) -> tokio::task::JoinHandle<Result<serde_json::Value, BridgeError>> {
    tokio::spawn(async move { bridge.call(op, args).await })
}

fn valid_args() -> serde_json::Value {
    serde_json::json!({
        "title": "Dinner",
        "start": "2030-01-01T19:00:00Z",
        "end": "2030-01-01T20:00:00Z",
    })
}

async fn call_raw(
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
    call_raw(t.addr, "POST", path, Some(&t.token), Some(body)).await
}

// ---------------------------------------------------------------------------
// happy path + journal
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_event_round_trips_and_the_journal_keeps_no_values() {
    let mut t = TestApi::start().await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let args = serde_json::json!({
        "calendar": "Home",
        "title": "Dentist CANARY_TITLE",
        "start": "2030-03-04T09:00:00Z",
        "end": "2030-03-04T09:30:00Z",
        "notes": "CANARY_NOTES",
        "url": "https://example.test/visit",
    });
    let call = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::EventkitCreateEvent,
        args.clone(),
    );
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(5))
        .await
        .expect("the app must receive one bridge.request frame");
    assert_eq!(frame["type"], "bridge.request");
    assert_eq!(frame["op"], "eventkit.create_event");
    assert_eq!(frame["args"], args);
    let id = frame["id"].as_str().expect("an id").to_string();

    let posted = post_auth(
        &t,
        &format!("/v1/bridge/{id}"),
        r#"{"ok":true,"result":{"event_id":"evt-1","calendar":"Home"}}"#,
    )
    .await;
    assert_eq!(posted.status, 200, "body: {}", posted.body);

    let result = call.await.unwrap().unwrap();
    assert_eq!(
        result,
        serde_json::json!({"event_id": "evt-1", "calendar": "Home"})
    );

    let store = t.store();
    let requests = store.event_payloads("bridge.request").unwrap();
    let results = store.event_payloads("bridge.result").unwrap();
    assert_eq!(requests.len(), 1, "one request row: {requests:?}");
    assert_eq!(results.len(), 1, "one result row: {results:?}");
    assert!(
        requests[0].contains("eventkit.create_event"),
        "{requests:?}"
    );
    assert!(results[0].contains("\"outcome\":\"ok\""), "{results:?}");
    for payload in requests.iter().chain(results.iter()) {
        assert!(!payload.contains("CANARY_TITLE"), "{payload}");
        assert!(!payload.contains("CANARY_NOTES"), "{payload}");
        assert!(
            !payload.contains("evt-1"),
            "a result value leaked: {payload}"
        );
    }

    t.stop();
}

// ---------------------------------------------------------------------------
// app error
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_app_error_answer_is_a_typed_error() {
    let mut t = TestApi::start().await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let call = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::EventkitCreateEvent,
        valid_args(),
    );
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(5))
        .await
        .unwrap();
    let id = frame["id"].as_str().unwrap().to_string();
    let posted = post_auth(
        &t,
        &format!("/v1/bridge/{id}"),
        r#"{"ok":false,"error":"denied","message":"no EventKit access"}"#,
    )
    .await;
    assert_eq!(posted.status, 200, "body: {}", posted.body);

    match call.await.unwrap().unwrap_err() {
        BridgeError::App { code, message } => {
            assert_eq!(code, "denied");
            assert_eq!(message, "no EventKit access");
        }
        other => panic!("expected an app error, got {other:?}"),
    }

    let results = t.store().event_payloads("bridge.result").unwrap();
    assert_eq!(results.len(), 1, "{results:?}");
    assert!(
        results[0].contains("\"outcome\":\"app_error\""),
        "{results:?}"
    );

    t.stop();
}

// ---------------------------------------------------------------------------
// unavailable / timeout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_connected_app_is_unavailable_at_once() {
    let mut t = TestApi::start().await;
    let started = std::time::Instant::now();
    let error = t
        .bridge
        .call(BridgeOp::EventkitCreateEvent, valid_args())
        .await
        .unwrap_err();
    assert_eq!(error, BridgeError::Unavailable);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "no socket must not wait for the 30 s deadline: {:?}",
        started.elapsed()
    );
    // P3-5a: even a no-app call pairs its request and result rows.
    let requests = t.store().event_payloads("bridge.request").unwrap();
    let results = t.store().event_payloads("bridge.result").unwrap();
    assert_eq!(requests.len(), 1, "one request row: {requests:?}");
    assert_eq!(results.len(), 1, "one result row: {results:?}");
    assert!(
        results[0].contains("\"outcome\":\"unavailable\""),
        "{results:?}"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_timed_out_call_is_unavailable_and_a_late_answer_is_conflict() {
    let mut t = TestApi::start().await;
    t.bridge
        .set_timeouts(Duration::from_millis(150), Duration::from_millis(150));
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let call = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::EventkitCreateEvent,
        valid_args(),
    );
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(5))
        .await
        .unwrap();
    let id = frame["id"].as_str().unwrap().to_string();
    assert_eq!(call.await.unwrap().unwrap_err(), BridgeError::Unavailable);

    let late = post_auth(
        &t,
        &format!("/v1/bridge/{id}"),
        r#"{"ok":true,"result":{}}"#,
    )
    .await;
    assert_eq!(late.status, 409, "body: {}", late.body);

    let results = t.store().event_payloads("bridge.result").unwrap();
    assert!(
        results[0].contains("\"outcome\":\"timeout\""),
        "{results:?}"
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aborted_call_retires_its_id() {
    let mut t = TestApi::start().await;
    // Long deadlines: the only way the id leaves pending is the drop guard.
    t.bridge
        .set_timeouts(Duration::from_secs(30), Duration::from_secs(30));
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let call = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::EventkitCreateEvent,
        valid_args(),
    );
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(5))
        .await
        .unwrap();
    let id = frame["id"].as_str().unwrap().to_string();

    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());

    // P2-2: the dropped caller's entry is retired, so the app's answer is a
    // 409 rather than a 200 into a channel nobody reads (which would lose the
    // result and let an event retry create a duplicate).
    let posted = post_auth(
        &t,
        &format!("/v1/bridge/{id}"),
        r#"{"ok":true,"result":{}}"#,
    )
    .await;
    assert_eq!(posted.status, 409, "body: {}", posted.body);

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_op_timeouts_are_mapped_by_op() {
    let mut t = TestApi::start().await;
    // Very different values for the two classes, so a swapped mapping cannot
    // pass (P3-6). The long fixture is deliberately far above the short one:
    // the test waits for the short class to time out instead of sleeping, so
    // the long class only has to still be pending at that point, whatever the
    // runner's scheduling jitter does to the answer's HTTP hop.
    t.bridge
        .set_timeouts(Duration::from_millis(100), Duration::from_secs(60));
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    // The OCR class carries the long deadline. Start it first and answer it
    // only once the call class has proved its own (short) deadline fired.
    let ocr = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::VisionOcr,
        serde_json::json!({ "sha256": "a".repeat(64) }),
    );
    // Every wait here is generous (>=15 s): the frame's HTTP hop, the ws pump
    // and the test task all share the runner, and a saturated runner used to
    // blow the old 5 s budget and return `None` before the request frame
    // arrived. The bound only has to exceed one local hop, never a product
    // deadline.
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(15))
        .await
        .unwrap();
    let ocr_id = frame["id"].as_str().unwrap().to_string();

    // The event call carries the short deadline: it must hit it on its own.
    let event = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::EventkitCreateEvent,
        valid_args(),
    );
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(15))
        .await
        .unwrap();
    let event_id = frame["id"].as_str().unwrap().to_string();
    let event_started = tokio::time::Instant::now();
    // A watchdog, not a deadline: the call class must report after its own
    // 100 ms deadline, and a swapped mapping would leave it pending on the
    // 60 s long timeout, so 15 s still separates the two.
    let event_outcome = tokio::time::timeout(Duration::from_secs(15), event)
        .await
        .unwrap_or_else(|_| {
            panic!("the call class never hit its short deadline; the mapping may be swapped")
        });
    assert_eq!(
        event_outcome.unwrap().unwrap_err(),
        BridgeError::Unavailable,
        "the call class must time out on the short deadline (after {:?})",
        event_started.elapsed()
    );

    // The OCR call survived the call class's whole deadline: it is on the long
    // deadline, not the short one. A swapped mapping would already have
    // retired it, so this answer would be a 409 instead of a 200.
    assert!(
        !ocr.is_finished(),
        "the OCR class must still be pending after the call class timed out"
    );
    let answered = post_auth(
        &t,
        &format!("/v1/bridge/{ocr_id}"),
        r#"{"ok":true,"result":{"pages":1}}"#,
    )
    .await;
    assert_eq!(
        answered.status, 200,
        "the OCR answer must land before the long deadline: {}",
        answered.body
    );
    assert_eq!(ocr.await.unwrap().unwrap()["pages"], 1);

    // The short-deadline id stays finished: a late answer is a 409.
    let late = post_auth(
        &t,
        &format!("/v1/bridge/{event_id}"),
        r#"{"ok":true,"result":{}}"#,
    )
    .await;
    assert_eq!(late.status, 409, "body: {}", late.body);

    t.stop();
}

// ---------------------------------------------------------------------------
// replay / unknown
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_answer_is_conflict() {
    let mut t = TestApi::start().await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let call = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::EventkitCreateEvent,
        valid_args(),
    );
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(5))
        .await
        .unwrap();
    let id = frame["id"].as_str().unwrap().to_string();
    let body = r#"{"ok":true,"result":{"event_id":"evt-2"}}"#;

    let first = post_auth(&t, &format!("/v1/bridge/{id}"), body).await;
    assert_eq!(first.status, 200, "body: {}", first.body);
    let second = post_auth(&t, &format!("/v1/bridge/{id}"), body).await;
    assert_eq!(second.status, 409, "body: {}", second.body);
    assert!(call.await.unwrap().is_ok());

    t.stop();
}

#[tokio::test]
async fn an_unknown_id_is_not_found() {
    let mut t = TestApi::start().await;
    let response = post_auth(
        &t,
        "/v1/bridge/00000000-0000-4000-8000-000000000000",
        r#"{"ok":true,"result":{}}"#,
    )
    .await;
    assert_eq!(response.status, 404, "body: {}", response.body);
    t.stop();
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_token_is_unauthorized_and_leaves_the_call_pending() {
    let mut t = TestApi::start().await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    let call = spawn_call(
        Arc::clone(&t.bridge),
        BridgeOp::EventkitCreateEvent,
        valid_args(),
    );
    let frame = find_bridge_frame(&mut ws, Duration::from_secs(5))
        .await
        .unwrap();
    let id = frame["id"].as_str().unwrap().to_string();
    let path = format!("/v1/bridge/{id}");
    let body = r#"{"ok":true,"result":{"event_id":"evt-late"}}"#;

    let missing = call_raw(t.addr, "POST", &path, None, Some(body)).await;
    assert_eq!(missing.status, 401, "body: {}", missing.body);
    let wrong = call_raw(t.addr, "POST", &path, Some("not-the-token"), Some(body)).await;
    assert_eq!(wrong.status, 401, "body: {}", wrong.body);

    // Neither 401 touched the pending call: the correct answer still lands.
    let right = post_auth(&t, &path, body).await;
    assert_eq!(right.status, 200, "body: {}", right.body);
    assert_eq!(call.await.unwrap().unwrap()["event_id"], "evt-late");

    t.stop();
}

// ---------------------------------------------------------------------------
// validation / body cap
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_create_event_args_never_reach_the_socket() {
    let mut t = TestApi::start().await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    for args in [
        serde_json::json!({
            "title": "x",
            "start": "2030-01-01T20:00:00Z",
            "end": "2030-01-01T19:00:00Z",
        }),
        serde_json::json!({
            "title": "x",
            "start": "2030-01-01T19:00:00Z",
            "end": "2030-01-01T20:00:00Z",
            "attendees": ["someone@example.test"],
        }),
        serde_json::json!({
            "title": "x",
            "start": "2030-01-01T19:00:00Z",
            "end": "2030-01-01T20:00:00Z",
            "notes": "n".repeat(8 * 1024 + 1),
        }),
    ] {
        let error = t
            .bridge
            .call(BridgeOp::EventkitCreateEvent, args)
            .await
            .unwrap_err();
        assert!(
            matches!(error, BridgeError::InvalidArgs(_)),
            "expected InvalidArgs, got {error:?}"
        );
    }

    assert!(
        find_bridge_frame(&mut ws, Duration::from_millis(400))
            .await
            .is_none(),
        "an invalid call must never publish a bridge.request frame"
    );
    assert!(
        t.store()
            .event_payloads("bridge.request")
            .unwrap()
            .is_empty(),
        "an invalid call must not journal a request"
    );

    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_ocr_and_update_args_never_reach_the_socket() {
    let mut t = TestApi::start().await;
    let mut ws = ws_connect(&t).await;
    drain_initial(&mut ws).await;

    for (op, args) in [
        (
            BridgeOp::VisionOcr,
            serde_json::json!({ "sha256": "A".repeat(64) }),
        ),
        (
            BridgeOp::VisionOcr,
            serde_json::json!({ "sha256": "a".repeat(63) }),
        ),
        (
            BridgeOp::VisionOcr,
            serde_json::json!({ "sha256": "a".repeat(64), "extra": true }),
        ),
        (
            BridgeOp::EventkitUpdateEvent,
            serde_json::json!({ "title": "x" }),
        ),
        (
            BridgeOp::EventkitUpdateEvent,
            serde_json::json!({ "event_id": "e", "attendees": ["a@example.test"] }),
        ),
        (
            BridgeOp::EventkitUpdateEvent,
            serde_json::json!({
                "event_id": "e",
                "start": "2030-01-01T20:00:00Z",
                "end": "2030-01-01T19:00:00Z",
            }),
        ),
    ] {
        let error = t.bridge.call(op, args).await.unwrap_err();
        assert!(
            matches!(error, BridgeError::InvalidArgs(_)),
            "expected InvalidArgs, got {error:?}"
        );
    }
    assert!(
        find_bridge_frame(&mut ws, Duration::from_millis(400))
            .await
            .is_none(),
        "an invalid call must never publish a bridge.request frame"
    );
    assert!(
        t.store()
            .event_payloads("bridge.request")
            .unwrap()
            .is_empty(),
        "an invalid call must not journal a request"
    );

    t.stop();
}

#[tokio::test]
async fn the_answer_body_cap_is_one_mib() {
    let mut t = TestApi::start().await;
    // Just over the 128 KiB global cap but under 1 MiB: the route's own cap
    // wins, so the body parses and reaches the unknown-id 404.
    let big = format!(
        r#"{{"ok":true,"result":{{"pad":"{}"}}}}"#,
        "x".repeat(300 * 1024)
    );
    let unknown = post_auth(&t, "/v1/bridge/never-sent", &big).await;
    assert_eq!(unknown.status, 404, "body: {}", unknown.body);

    // Over 1 MiB: rejected before parsing.
    let huge = format!(
        r#"{{"ok":true,"result":{{"pad":"{}"}}}}"#,
        "x".repeat(2 * 1024 * 1024)
    );
    let rejected = post_auth(&t, "/v1/bridge/never-sent", &huge).await;
    assert_eq!(rejected.status, 413, "body: {}", rejected.body);

    t.stop();
}
