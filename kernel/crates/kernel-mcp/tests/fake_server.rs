//! S1 acceptance: the Streamable HTTP transport and `McpClient` against a local
//! axum mock server. **Offline only** — every socket is on `127.0.0.1`, there is
//! no real key, no Keychain and no external host.
//!
//! The mock deliberately serves hostile routes: an oversize JSON body, a 4 MiB
//! SSE line bomb, a 500-then-200 endpoint, a redirect to a second origin, a
//! missing `Mcp-Session-Id`, a `tools/list_changed` notification, a pagination
//! server that never ends, a connection flap, a slow endpoint, and response
//! bodies whose id does not match the request.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use futures_util::stream;
use serde_json::{json, Map, Value};

use kernel_mcp::{HttpTransport, Limits, McpError, ServerInfo};

/// The grant-bound arguments every `tools/call` in this file sends: the HTTP
/// path accepts only a `SafeValue`, so the test admits the call first.
fn safe_args(args: &Value) -> kernel_privacy::SafeValue {
    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
    let ctx = Context {
        destination: Destination::Vendor("mock".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::B13, PrivacyMode::Open, &ctx) else {
        panic!("B13 is admitted in open mode");
    };
    let mut gate = kernel_privacy::Gate::for_grant(&grant, [7u8; 32]);
    gate.value(args).expect("arguments are admitted").0
}

/// Tests run on several threads; the memory-bound test reads process resident
/// size, so every test in this file takes the lock to keep allocations serial.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL.lock().await
}

/// Shared counters so a test can prove how many requests actually went out.
#[derive(Default)]
struct MockState {
    init_hits: AtomicUsize,
    list_hits: AtomicUsize,
    call_hits: AtomicUsize,
    list_with_session: AtomicUsize,
    list_with_protocol_header: AtomicUsize,
    notification_hits: AtomicUsize,
    notification_with_id: AtomicUsize,
    flaky_hits: AtomicUsize,
    evil_hits: AtomicUsize,
    evil_key_hits: AtomicUsize,
    evil_port: AtomicUsize,
    flap_init: AtomicUsize,
    flap_list: AtomicUsize,
    flap_call: AtomicUsize,
    slow_hits: AtomicUsize,
}

struct Mock {
    port: u16,
    state: Arc<MockState>,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Mock {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

async fn spawn() -> Mock {
    let evil_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind evil");
    let evil_port = evil_listener.local_addr().expect("evil addr").port();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let port = listener.local_addr().expect("mock addr").port();

    let state = Arc::new(MockState {
        evil_port: AtomicUsize::new(usize::from(evil_port)),
        ..MockState::default()
    });

    let app = Router::new()
        .route("/mcp", post(main_handler))
        .route("/mcp/no-session", post(main_handler))
        .route("/mcp/session", post(session_handler))
        .route("/mcp/session-error", post(session_error_handler))
        .route("/mcp/session-long", post(session_long_handler))
        .route("/mcp/500", post(flaky_handler))
        .route("/mcp/redirect", post(redirect_handler))
        .route("/mcp/big", post(big_handler))
        .route("/mcp/sse", post(sse_handler))
        .route("/mcp/sse-lf", post(sse_lf_handler))
        .route("/mcp/sse-crlf", post(sse_crlf_handler))
        .route("/mcp/sse-cr", post(sse_cr_handler))
        .route("/mcp/sse-no-id", post(sse_no_id_handler))
        .route("/mcp/sse-wrong-id", post(sse_wrong_id_handler))
        .route("/mcp/sse-bomb", post(sse_bomb_handler))
        .route("/mcp/no-id", post(no_id_handler))
        .route("/mcp/wrong-id", post(wrong_id_handler))
        .route("/mcp/spin-empty", post(spin_empty_handler))
        .route("/mcp/spin-tools", post(spin_tools_handler))
        .route("/mcp/repeat-cursor", post(repeat_cursor_handler))
        .route("/mcp/empty-tail", post(empty_tail_handler))
        .route("/mcp/huge-cursor", post(huge_cursor_handler))
        .route("/mcp/mutating-cursor", post(mutating_cursor_handler))
        .route(
            "/mcp/mutating-big-cursor",
            post(mutating_big_cursor_handler),
        )
        .route("/mcp/slow-paginate", post(slow_paginate_handler))
        .route("/mcp/bad-version", post(bad_version_handler))
        .route("/mcp/old-version", post(old_version_handler))
        .route("/mcp/evil-info", post(evil_info_handler))
        .route("/mcp/sse-bom", post(sse_bom_handler))
        .route("/mcp/sse-evil-id", post(sse_evil_id_handler))
        .route("/mcp/flap", post(flap_handler))
        .route("/mcp/slow", post(slow_handler))
        .route("/mcp/oversize-tools", post(oversize_tools_handler))
        .with_state(state.clone());
    let evil = Router::new()
        .fallback(evil_handler)
        .with_state(state.clone());

    let main_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let evil_handle = tokio::spawn(async move {
        let _ = axum::serve(evil_listener, evil).await;
    });

    Mock {
        port,
        state,
        _handles: vec![main_handle, evil_handle],
    }
}

async fn main_handler(
    State(state): State<Arc<MockState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    respond(&state, &headers, &body, false)
}

async fn session_handler(
    State(state): State<Arc<MockState>>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    respond(&state, &headers, &body, true)
}

/// Sets a session header on a 500: it must never be remembered.
async fn session_error_handler() -> Response {
    let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
    response
        .headers_mut()
        .insert("mcp-session-id", HeaderValue::from_static("sess_err"));
    response
}

/// Answers `initialize` successfully with a hostile-length session header.
async fn session_long_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64);
    let mut response = json_result(
        id,
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "serverInfo": { "name": "long-session", "version": "0.1.0" }
        }),
        false,
    );
    let long = "s".repeat(4096);
    response.headers_mut().insert(
        "mcp-session-id",
        HeaderValue::from_str(&long).expect("session header"),
    );
    response
}

async fn flaky_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    state.flaky_hits.fetch_add(1, Ordering::SeqCst);
    if state.flaky_hits.load(Ordering::SeqCst) == 1 {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    } else {
        respond(&state, &HeaderMap::new(), &body, false)
    }
}

async fn redirect_handler(State(state): State<Arc<MockState>>) -> Response {
    let location = format!(
        "http://127.0.0.1:{}/steal",
        state.evil_port.load(Ordering::SeqCst)
    );
    (
        [(header::LOCATION, location)],
        StatusCode::TEMPORARY_REDIRECT,
    )
        .into_response()
}

async fn big_handler() -> Response {
    let text = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "pad": "x".repeat(200) }
    })
    .to_string();
    ([(header::CONTENT_TYPE, "application/json")], text).into_response()
}

async fn sse_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    let text = format!(
        "event: message\ndata: {}\n\nid: evt-42\ndata: {}\n\n",
        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [tool("SSE_TOOL")], "nextCursor": Value::Null}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

/// A complete SSE stream with an interleaved notification, using `term` as the
/// line terminator.
fn eol_sse_body(term: &str, id: u64) -> String {
    let notif = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}).to_string();
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"tools": [tool("EOL_TOOL")], "nextCursor": Value::Null}
    })
    .to_string();
    format!("event: message{term}data: {notif}{term}{term}id: evt-9{term}data: {resp}{term}{term}")
}

async fn sse_lf_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        eol_sse_body("\n", id),
    )
        .into_response()
}

async fn sse_crlf_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        eol_sse_body("\r\n", id),
    )
        .into_response()
}

async fn sse_cr_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        eol_sse_body("\r", id),
    )
        .into_response()
}

async fn sse_no_id_handler(axum::Json(_body): axum::Json<Value>) -> Response {
    let text = format!(
        "data: {}\n\n",
        json!({"jsonrpc": "2.0", "result": {"tools": []}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

async fn sse_wrong_id_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0) + 1;
    let text = format!(
        "data: {}\n\n",
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

async fn sse_bomb_handler(axum::Json(body): axum::Json<Value>) -> Response {
    // The first `initialize` is answered normally so the test can warm the
    // connection and measure only the bomb; the notification is a 202.
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "initialize" {
        return json_result(
            body.get("id").and_then(Value::as_u64),
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": { "name": "bomb-server", "version": "0.1.0" }
            }),
            false,
        );
    }
    if method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }

    // One SSE line of ~4 MiB, streamed in 64 KiB chunks so the server itself
    // never holds the explosion in memory.
    let head = Bytes::from_static(b"data: ");
    let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
    let mut items: Vec<Result<Bytes, Infallible>> = Vec::with_capacity(1 + 64);
    items.push(Ok(head));
    for _ in 0..64 {
        items.push(Ok(chunk.clone()));
    }
    let body = Body::from_stream(stream::iter(items));
    ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response()
}

async fn no_id_handler(axum::Json(_body): axum::Json<Value>) -> Response {
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    envelope.insert("result".to_owned(), json!({ "tools": [] }));
    respond_with(Value::Object(envelope), false)
}

async fn wrong_id_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0) + 1;
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    envelope.insert("id".to_owned(), json!(id));
    envelope.insert("result".to_owned(), json!({ "tools": [] }));
    respond_with(Value::Object(envelope), false)
}

/// Every page is empty and carries a fresh cursor: the empty-page guard must
/// stop the client on page two.
async fn spin_empty_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [], "nextCursor": format!("spin{n}") }),
        false,
    )
}

/// Every page has one tool and a fresh cursor, and never reaches `max_tools`:
/// the hard page bound must stop the client.
async fn spin_tools_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool(&format!("SPIN_{n}"))], "nextCursor": format!("spin{n}") }),
        false,
    )
}

/// Every page advertises the same cursor.
async fn repeat_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool("REPEAT")], "nextCursor": "loop" }),
        false,
    )
}

/// Page one is non-empty; page two is empty but still carries a cursor.
async fn empty_tail_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    if n == 0 {
        json_result(
            id,
            json!({ "tools": [tool("FIRST")], "nextCursor": "e1" }),
            false,
        )
    } else {
        json_result(id, json!({ "tools": [], "nextCursor": "e2" }), false)
    }
}

/// Shared preamble for the hostile discovery routes: answer `initialize`
/// normally and accept the completion notification, so a test can warm the
/// connection without polluting the `tools/list` hit counter.
fn discovery_preamble(body: &Value) -> Option<Response> {
    match body.get("method").and_then(Value::as_str).unwrap_or("") {
        "initialize" => Some(json_result(
            body.get("id").and_then(Value::as_u64),
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": { "name": "cursor-mock", "version": "0.1.0" }
            }),
            false,
        )),
        method if method.starts_with("notifications/") => {
            Some(StatusCode::ACCEPTED.into_response())
        }
        _ => None,
    }
}

/// NP-1: a page advertises a ~500 KiB cursor, far above the 4 KiB cap.
async fn huge_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool("HUGE")], "nextCursor": "H".repeat(500 * 1024) }),
        false,
    )
}

/// A distinct cursor where one character mutates per page.
fn one_char_mutation(n: usize) -> String {
    let mut bytes = vec![b'a'; 64];
    bytes[n % 64] = b'A' + (n % 26) as u8;
    String::from_utf8(bytes).expect("ascii cursor")
}

/// NP-1: every page mints a cursor that differs from the previous one by a
/// single character, so a text-based seen-set would keep growing.
async fn mutating_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({ "tools": [tool(&format!("M{n}"))], "nextCursor": one_char_mutation(n) }),
        false,
    )
}

/// NP-1: as above, but each distinct cursor sits just under the byte cap, so a
/// client that retained the text of every cursor would hold ~80 KiB of cursors.
async fn mutating_big_cursor_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    let id = body.get("id").and_then(Value::as_u64);
    let mut cursor = "c".repeat(4000);
    cursor.replace_range(n % 100..n % 100 + 1, "Z");
    json_result(
        id,
        json!({ "tools": [tool(&format!("B{n}"))], "nextCursor": cursor }),
        false,
    )
}

/// NP-3: answers each `tools/list` after a delay, always with a fresh cursor,
/// so only an aggregate deadline can stop the pagination.
async fn slow_paginate_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    if let Some(response) = discovery_preamble(&body) {
        return response;
    }
    let id = body.get("id").and_then(Value::as_u64);
    let n = state.list_hits.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(60)).await;
    json_result(
        id,
        json!({ "tools": [tool(&format!("S{n}"))], "nextCursor": format!("sp{n}") }),
        false,
    )
}

/// NP-5: the server negotiates a revision that is not date-shaped.
async fn bad_version_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({
            "protocolVersion": "not-a-date",
            "capabilities": {},
            "serverInfo": { "name": "bad-version", "version": "0.1.0" }
        }),
        false,
    )
}

/// NP-5: a date-shaped revision this build does not know is still accepted.
async fn old_version_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": { "name": "old-version", "version": "0.1.0" }
        }),
        false,
    )
}

/// NP-4: name/version/instructions carry control characters and cross the caps.
async fn evil_info_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "serverInfo": {
                "name": format!("\u{1b}[31m{}", "n".repeat(600)),
                "version": format!("v\u{7}{}", "e".repeat(400))
            },
            "instructions": "i".repeat(5000)
        }),
        false,
    )
}

/// NP-6: the stream begins with a UTF-8 BOM before the first `data:` line.
async fn sse_bom_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    let text = format!(
        "\u{feff}data: {}\n\n",
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [tool("BOM_TOOL")], "nextCursor": Value::Null}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

/// NP-9: the SSE `id:` carries ANSI escapes and crosses the byte cap.
async fn sse_evil_id_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64).unwrap_or(0);
    let evil = format!("\u{1b}[31m{}", "z".repeat(600));
    let text = format!(
        "id: {evil}\ndata: {}\n\n",
        json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [tool("EVIL_ID")], "nextCursor": Value::Null}})
    );
    ([(header::CONTENT_TYPE, "text/event-stream")], text).into_response()
}

/// The first hit for each method drops the connection without a response; the
/// retry (if any) succeeds.
async fn flap_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let id = body.get("id").and_then(Value::as_u64);
    match method {
        "initialize" => {
            let seen = state.flap_init.fetch_add(1, Ordering::SeqCst);
            assert_ne!(
                seen, 0,
                "flap: connection dropped before initialize response"
            );
            json_result(
                id,
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "serverInfo": { "name": "mock-server", "version": "0.1.0" }
                }),
                false,
            )
        }
        "tools/list" => {
            let seen = state.flap_list.fetch_add(1, Ordering::SeqCst);
            assert_ne!(
                seen, 0,
                "flap: connection dropped before tools/list response"
            );
            json_result(
                id,
                json!({ "tools": [tool("FLAP")], "nextCursor": Value::Null }),
                false,
            )
        }
        "tools/call" => {
            let seen = state.flap_call.fetch_add(1, Ordering::SeqCst);
            assert_ne!(
                seen, 0,
                "flap: connection dropped before tools/call response"
            );
            json_result(
                id,
                json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false }),
                false,
            )
        }
        _ => StatusCode::ACCEPTED.into_response(),
    }
}

/// Answers, but only after the client's budget has expired.
async fn slow_handler(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    state.slow_hits.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    respond(&state, &HeaderMap::new(), &body, false)
}

/// One good tool plus entries that cross each descriptor cap, plus one that
/// cannot be decoded at all.
async fn oversize_tools_handler(axum::Json(body): axum::Json<Value>) -> Response {
    let id = body.get("id").and_then(Value::as_u64);
    json_result(
        id,
        json!({
            "tools": [
                tool("GOOD"),
                { "name": "N".repeat(200), "description": "ok", "inputSchema": { "type": "object" } },
                { "name": "DESC", "description": "D".repeat(600), "inputSchema": { "type": "object" } },
                { "name": "SCHEMA", "description": "ok", "inputSchema": { "type": "object", "pad": "x".repeat(20 * 1024) } },
                { "description": "no name at all" }
            ],
            "nextCursor": Value::Null
        }),
        false,
    )
}

async fn evil_handler(State(state): State<Arc<MockState>>, headers: HeaderMap) -> Response {
    state.evil_hits.fetch_add(1, Ordering::SeqCst);
    if headers.contains_key("x-api-key") {
        state.evil_key_hits.fetch_add(1, Ordering::SeqCst);
    }
    (StatusCode::OK, "stolen").into_response()
}

fn respond(state: &MockState, headers: &HeaderMap, body: &Value, with_session: bool) -> Response {
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let id = body.get("id").and_then(Value::as_u64);
    match method {
        "initialize" => {
            state.init_hits.fetch_add(1, Ordering::SeqCst);
            json_result(
                id,
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": { "tools": { "listChanged": true } },
                    "serverInfo": { "name": "mock-server", "version": "0.1.0" },
                    "instructions": "mock"
                }),
                with_session,
            )
        }
        "notifications/initialized" => {
            state.notification_hits.fetch_add(1, Ordering::SeqCst);
            if body.get("id").is_some() {
                state.notification_with_id.fetch_add(1, Ordering::SeqCst);
            }
            StatusCode::ACCEPTED.into_response()
        }
        "tools/list" => {
            state.list_hits.fetch_add(1, Ordering::SeqCst);
            if headers.contains_key("mcp-session-id") {
                state.list_with_session.fetch_add(1, Ordering::SeqCst);
            }
            if headers
                .get("mcp-protocol-version")
                .and_then(|value| value.to_str().ok())
                == Some("2025-11-25")
            {
                state
                    .list_with_protocol_header
                    .fetch_add(1, Ordering::SeqCst);
            }
            let cursor = body
                .get("params")
                .and_then(|params| params.get("cursor"))
                .and_then(Value::as_str);
            let (tools, next) = match cursor {
                None => (json!([tool("A"), tool("B")]), Some("p2")),
                Some("p2") => (json!([tool("C")]), Some("p3")),
                Some(_) => (json!([tool("D"), tool("E")]), None),
            };
            json_result(
                id,
                json!({ "tools": tools, "nextCursor": next }),
                with_session,
            )
        }
        "tools/call" => {
            state.call_hits.fetch_add(1, Ordering::SeqCst);
            let name = body
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            match name {
                "MISSING" => json_error(id, -32602, "unknown tool: MISSING"),
                "BADARGS" => json_error(id, -32602, "invalid arguments for tool BADARGS"),
                "FAILS" => json_result(
                    id,
                    json!({ "content": [{ "type": "text", "text": "boom" }], "isError": true }),
                    false,
                ),
                _ => json_result(
                    id,
                    json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false }),
                    false,
                ),
            }
        }
        other => json_error(id, -32601, &format!("unknown method: {other}")),
    }
}

fn tool(name: &str) -> Value {
    json!({ "name": name, "description": format!("tool {name}"), "inputSchema": { "type": "object" } })
}

fn json_result(id: Option<u64>, result: Value, with_session: bool) -> Response {
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    if let Some(id) = id {
        envelope.insert("id".to_owned(), json!(id));
    }
    envelope.insert("result".to_owned(), result);
    respond_with(Value::Object(envelope), with_session)
}

fn json_error(id: Option<u64>, code: i64, message: &str) -> Response {
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), json!("2.0"));
    if let Some(id) = id {
        envelope.insert("id".to_owned(), json!(id));
    }
    envelope.insert(
        "error".to_owned(),
        json!({ "code": code, "message": message }),
    );
    respond_with(Value::Object(envelope), false)
}

fn respond_with(envelope: Value, with_session: bool) -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "application/json")],
        envelope.to_string(),
    )
        .into_response();
    if with_session {
        response
            .headers_mut()
            .insert("mcp-session-id", HeaderValue::from_static("sess_mock_1"));
    }
    response
}

fn transport(mock: &Mock, path: &str, headers: HeaderMap, limits: Limits) -> Arc<HttpTransport> {
    Arc::new(HttpTransport::new(&mock.url(path), headers, limits).expect("build transport"))
}

#[tokio::test]
async fn initialize_negotiates_and_tolerates_absent_session() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    let info = client.initialize().await.expect("initialize");
    assert_eq!(info.name, "mock-server");
    assert_eq!(info.version, "0.1.0");
    assert_eq!(info.protocol_version, "2025-11-25");
    assert_eq!(info.max_tools, 500);
    assert!(transport.session_id().is_none());
    assert_eq!(mock.state.init_hits.load(Ordering::SeqCst), 1);

    // Stateless follow-up: no session header, and the server is fine with it.
    let page = client.list_tools(None).await.expect("list tools");
    assert_eq!(page.tools.len(), 5);
    assert!(page.next_cursor.is_none());
    assert_eq!(page.dropped, 0);
    assert_eq!(mock.state.list_with_session.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn session_id_is_reused_when_present() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/session", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    client.initialize().await.expect("initialize");
    assert_eq!(transport.session_id().as_deref(), Some("sess_mock_1"));

    client.list_tools(None).await.expect("list tools");
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 3);
    assert_eq!(mock.state.list_with_session.load(Ordering::SeqCst), 3);
}

/// P3: a session id is remembered only from a 2xx response and is capped.
#[tokio::test]
async fn session_id_is_captured_only_on_2xx_and_is_capped() {
    let _guard = serial().await;

    let mock = spawn().await;
    let transport_err = transport(
        &mock,
        "/mcp/session-error",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport_err.clone(), ServerInfo::default());
    let err = client.initialize().await.unwrap_err();
    assert!(matches!(err, McpError::Http { status: 500 }), "got {err:?}");
    assert!(
        transport_err.session_id().is_none(),
        "a session id on a 500 was remembered"
    );

    let mock = spawn().await;
    let transport_long = transport(
        &mock,
        "/mcp/session-long",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport_long.clone(), ServerInfo::default());
    client.initialize().await.expect("initialize");
    let session = transport_long.session_id().expect("session id");
    assert_eq!(session.len(), 256, "session id was not capped");
}

#[tokio::test]
async fn tools_list_paginates_and_stops_at_max_tools() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let info = ServerInfo {
        max_tools: 3,
        ..ServerInfo::default()
    };
    let client = kernel_mcp::client(transport, info);

    let page = client.list_tools(None).await.expect("list tools");
    let names: Vec<&str> = page.tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(names, ["A", "B", "C"]);
    assert_eq!(page.next_cursor.as_deref(), Some("p3"));
    // The third page was never requested: discovery stopped at the bound.
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 2);
}

/// P3-4: an entry the local `max_tools` bound cuts mid-page is counted, not
/// silently discarded while the page is marked complete.
#[tokio::test]
async fn tools_list_counts_entries_cut_at_max_tools() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let info = ServerInfo {
        max_tools: 4,
        ..ServerInfo::default()
    };
    let client = kernel_mcp::client(transport, info);

    let page = client.list_tools(None).await.expect("list tools");
    let names: Vec<&str> = page.tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(names, ["A", "B", "C", "D"]);
    assert!(page.truncated);
    assert_eq!(page.dropped, 1, "the cut entry must be counted");
    assert_eq!(page.next_cursor, None);
}

/// P3: the negotiated version rides every request after `initialize`.
#[tokio::test]
async fn protocol_version_header_is_sent_after_initialize() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    client.initialize().await.expect("initialize");
    client.list_tools(None).await.expect("list tools");
    let list_hits = mock.state.list_hits.load(Ordering::SeqCst);
    assert_eq!(list_hits, 3);
    assert_eq!(
        mock.state.list_with_protocol_header.load(Ordering::SeqCst),
        list_hits,
        "every post-initialize request must carry MCP-Protocol-Version"
    );
}

/// P3: a JSON-RPC notification must not carry an `id` member.
#[tokio::test]
async fn notifications_are_sent_without_an_id_member() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    client.initialize().await.expect("initialize");
    assert_eq!(mock.state.notification_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.state.notification_with_id.load(Ordering::SeqCst),
        0,
        "the initialized notification carried an id"
    );
}

/// P1 / NP-2: a server that never finishes paginating is stopped by the page
/// bound and the entries gathered so far are returned with the resume cursor.
#[tokio::test]
async fn tools_list_page_bound_returns_partial_with_resume_cursor() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/spin-tools",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client
        .list_tools(None)
        .await
        .expect("partial at the page bound");
    assert!(page.truncated, "a page-bound stop must be marked partial");
    assert_eq!(page.tools.len(), 20, "one tool per page for the page bound");
    assert_eq!(
        page.next_cursor.as_deref(),
        Some("spin19"),
        "the resume cursor must be the page after the last fetched one"
    );
    let hits = mock.state.list_hits.load(Ordering::SeqCst);
    assert_eq!(hits, 20, "pagination was not capped at the page bound");
}

/// P1: an echoed cursor is terminal, not another request.
#[tokio::test]
async fn tools_list_repeated_cursor_is_refused() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/repeat-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => {
            assert!(
                message.as_str().contains("repeated a cursor"),
                "got {message}"
            )
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 2);
}

/// P1: an empty page that still carries a cursor cannot make progress.
#[tokio::test]
async fn tools_list_empty_page_with_cursor_is_refused() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport1 = transport(
        &mock,
        "/mcp/empty-tail",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport1, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => assert!(
            message.as_str().contains("empty but carried a cursor"),
            "got {message}"
        ),
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 2);

    // A genuinely empty first page with a cursor is tolerated: the guard only
    // fires after the first page.
    let mock2 = spawn().await;
    let transport2 = transport(
        &mock2,
        "/mcp/spin-empty",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport2, ServerInfo::default());
    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => assert!(
            message.as_str().contains("empty but carried a cursor"),
            "got {message}"
        ),
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(mock2.state.list_hits.load(Ordering::SeqCst), 2);
}

/// P2: the plain-JSON path must require the response id to match.
#[tokio::test]
async fn json_response_id_must_match_the_request() {
    let _guard = serial().await;
    for path in ["/mcp/no-id", "/mcp/wrong-id"] {
        let mock = spawn().await;
        let transport = transport(&mock, path, HeaderMap::new(), Limits::default());
        let client = kernel_mcp::client(transport, ServerInfo::default());
        let err = client.list_tools(None).await.unwrap_err();
        match err {
            McpError::Protocol { message, .. } => {
                assert!(message.as_str().contains("id"), "{path}: {message}")
            }
            other => panic!("{path}: expected Protocol, got {other:?}"),
        }
    }
}

/// P2: the SSE path must require the response id to match too.
#[tokio::test]
async fn sse_response_id_must_match_the_request() {
    let _guard = serial().await;
    for path in ["/mcp/sse-no-id", "/mcp/sse-wrong-id"] {
        let mock = spawn().await;
        let transport = transport(&mock, path, HeaderMap::new(), Limits::default());
        let client = kernel_mcp::client(transport, ServerInfo::default());
        let err = client.list_tools(None).await.unwrap_err();
        match err {
            McpError::Protocol { message, .. } => {
                assert!(message.as_str().contains("id"), "{path}: {message}")
            }
            other => panic!("{path}: expected Protocol, got {other:?}"),
        }
    }
}

/// P3: the SSE parser accepts LF, CRLF and bare CR terminators.
#[tokio::test]
async fn sse_accepts_lf_crlf_and_cr_terminators() {
    let _guard = serial().await;
    for path in ["/mcp/sse-lf", "/mcp/sse-crlf", "/mcp/sse-cr"] {
        let mock = spawn().await;
        let transport = transport(&mock, path, HeaderMap::new(), Limits::default());
        let client = kernel_mcp::client(transport, ServerInfo::default());
        let page = client.list_tools(None).await.expect(path);
        assert_eq!(page.tools.len(), 1, "{path}");
        assert_eq!(page.tools[0].name, "EOL_TOOL", "{path}");
    }
}

/// P3: descriptor caps drop and count oversize/malformed entries.
#[tokio::test]
async fn descriptor_caps_drop_and_count_oversize_entries() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/oversize-tools",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client.list_tools(None).await.expect("list tools");
    let names: Vec<&str> = page.tools.iter().map(|tool| tool.name.as_str()).collect();
    assert_eq!(names, ["GOOD"]);
    assert_eq!(page.dropped, 4, "oversize entries must not be silent");
}

#[tokio::test]
async fn oversize_body_is_frame_too_large() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/big", HeaderMap::new(), Limits::tiny());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.initialize().await.unwrap_err();
    assert!(
        matches!(err, McpError::FrameTooLarge { limit: 64, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn sse_notification_is_ignored_and_response_returned() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/sse", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    let page = client.list_tools(None).await.expect("list tools");
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "SSE_TOOL");
    assert_eq!(transport.last_event_id().as_deref(), Some("evt-42"));
}

#[tokio::test]
async fn redirect_is_not_followed_and_key_is_not_forwarded() {
    let _guard = serial().await;
    let mock = spawn().await;
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("test-key-not-real"));
    let transport = transport(&mock, "/mcp/redirect", headers, Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.initialize().await.unwrap_err();
    assert!(
        matches!(err, McpError::Http { status } if (300..400).contains(&status)),
        "got {err:?}"
    );
    assert_eq!(mock.state.evil_hits.load(Ordering::SeqCst), 0);
    assert_eq!(mock.state.evil_key_hits.load(Ordering::SeqCst), 0);
}

/// P2: plaintext HTTP is refused off loopback; https and loopback are fine.
#[test]
fn plaintext_public_origin_is_refused() {
    let err = HttpTransport::new(
        "http://example.com/mcp",
        HeaderMap::new(),
        Limits::default(),
    )
    .err()
    .expect("plaintext public origin must be refused");
    assert!(matches!(err, McpError::OriginRefused { .. }), "got {err:?}");

    for origin in [
        "http://127.0.0.1:8080/mcp",
        "http://localhost:8080/mcp",
        "http://[::1]:8080/mcp",
        "https://mcp.example.com/mcp",
    ] {
        assert!(
            HttpTransport::new(origin, HeaderMap::new(), Limits::default()).is_ok(),
            "{origin} should be allowed"
        );
    }

    // S0's validated-limits surface is enforced at construction.
    let invalid = Limits {
        max_frame_bytes: 0,
        ..Limits::default()
    };
    let zero = HttpTransport::new("https://example.com/mcp", HeaderMap::new(), invalid)
        .err()
        .expect("invalid limits must be refused");
    assert!(
        matches!(zero, McpError::InvalidLimit { .. }),
        "got {zero:?}"
    );
}

#[tokio::test]
async fn five_hundred_is_typed_and_not_retried_on_list() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/500", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    assert!(matches!(err, McpError::Http { status: 500 }), "got {err:?}");
    // Exactly one request went out for the failed call: no retry on a status.
    assert_eq!(mock.state.flaky_hits.load(Ordering::SeqCst), 1);
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 0);

    // The route now answers 200, so a second explicit call succeeds. It walks
    // all three pages, so the flaky route sees three more requests.
    let page = client.list_tools(None).await.expect("second list");
    assert_eq!(page.tools.len(), 5);
    assert_eq!(mock.state.flaky_hits.load(Ordering::SeqCst), 4);
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 3);
}

/// P2/P3: the configured budget caps a per-call budget, and a timeout never
/// retries.
#[tokio::test]
async fn configured_timeout_is_effective_and_timeouts_do_not_retry() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = Arc::new(
        HttpTransport::new(&mock.url("/mcp/slow"), HeaderMap::new(), Limits::default())
            .expect("build transport")
            .with_timeout(Duration::from_millis(150))
            .expect("valid timeout"),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let started = Instant::now();
    let err = client.initialize().await.unwrap_err();
    assert_eq!(err, McpError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the configured timeout was not effective: {:?}",
        started.elapsed()
    );
    assert_eq!(
        mock.state.slow_hits.load(Ordering::SeqCst),
        1,
        "a timeout must never be retried"
    );
}

/// P3: a dropped connection retries initialize/tools-list once, never a call.
#[tokio::test]
async fn connect_flap_retries_discovery_but_not_tools_call() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/flap", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let info = client.initialize().await.expect("initialize after flap");
    assert_eq!(info.name, "mock-server");
    assert_eq!(mock.state.flap_init.load(Ordering::SeqCst), 2);

    let page = client.list_tools(None).await.expect("list after flap");
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "FLAP");
    assert_eq!(mock.state.flap_list.load(Ordering::SeqCst), 2);

    let err = client
        .call_tool("TOOL", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(err, McpError::Protocol { .. }), "got {err:?}");
    assert_eq!(
        mock.state.flap_call.load(Ordering::SeqCst),
        1,
        "tools/call is never retried"
    );
}

#[tokio::test]
async fn tools_call_is_never_retried() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());
    client.initialize().await.expect("initialize");

    let outcome = client
        .call_tool(
            "ELEVENLABS_TEXT_TO_SPEECH",
            &safe_args(&json!({})),
            Duration::from_secs(5),
        )
        .await
        .expect("call");
    assert!(!outcome.is_error);
    assert_eq!(
        outcome.text().marked(),
        format!("{}\nok", kernel_mcp::UNTRUSTED_MCP_TAG)
    );
    assert!(outcome.bytes > 0);
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 1);

    let missing = client
        .call_tool("MISSING", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(missing, McpError::ToolNotFound("MISSING".into()));
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 2);

    // P3: `-32602` is shared with a bad argument set and must not map blindly.
    let bad_args = client
        .call_tool("BADARGS", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(
        matches!(bad_args, McpError::Protocol { code: -32602, .. }),
        "got {bad_args:?}"
    );
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 3);

    let failing = client
        .call_tool("FAILS", &safe_args(&json!({})), Duration::from_secs(5))
        .await
        .expect("call");
    assert!(failing.is_error);
    assert_eq!(mock.state.call_hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn sse_line_bomb_is_bounded() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/sse-bomb", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    // Warm the connection first so this checks the streaming bound after normal
    // client/hyper setup has completed.
    client.initialize().await.expect("warm initialize");

    let err = client.list_tools(None).await.unwrap_err();

    let (limit, seen) = match err {
        McpError::FrameTooLarge { limit, seen } => (limit, seen),
        other => panic!("expected FrameTooLarge, got {other:?}"),
    };
    assert_eq!(limit, 1024 * 1024);
    // The parser stops within one read chunk of the line bound, never at 4 MiB.
    assert!(
        seen < limit + 1024 * 1024,
        "buffered {seen} bytes past a {limit} byte line"
    );
}

/// NP-1: an over-cap `nextCursor` is a typed protocol error, never truncated,
/// and it is refused before the next (unbounded) request body is built.
#[tokio::test]
async fn tools_list_oversize_cursor_is_rejected() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport1 = transport(
        &mock,
        "/mcp/huge-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport1, ServerInfo::default());

    let err = client.list_tools(None).await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => {
            assert!(message.as_str().contains("cursor"), "got {message}")
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
    assert_eq!(
        mock.state.list_hits.load(Ordering::SeqCst),
        1,
        "the over-cap cursor was echoed into another request body"
    );

    // An over-cap resume cursor is refused before any request goes out.
    let mock2 = spawn().await;
    let transport2 = transport(
        &mock2,
        "/mcp/huge-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client2 = kernel_mcp::client(transport2, ServerInfo::default());
    let huge = "s".repeat(500 * 1024);
    let err = client2.list_tools(Some(&huge)).await.unwrap_err();
    assert!(matches!(err, McpError::Protocol { .. }), "got {err:?}");
    assert_eq!(mock2.state.list_hits.load(Ordering::SeqCst), 0);
}

/// NP-1: one-character-mutating cursors are still bounded by the page cap, and
/// only a short hash of each cursor is retained.
#[tokio::test]
async fn tools_list_mutating_cursors_are_bounded_by_the_page_cap() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/mutating-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client
        .list_tools(None)
        .await
        .expect("partial at the page cap");
    assert!(page.truncated);
    assert_eq!(page.tools.len(), 20);
    assert!(page.next_cursor.is_some());
    assert_eq!(mock.state.list_hits.load(Ordering::SeqCst), 20);
}

/// NP-1: a server that mints a fresh (near-cap) cursor per page cannot grow the
/// client's memory without bound.
#[tokio::test]
async fn tools_list_pagination_memory_is_bounded() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/mutating-big-cursor",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport, ServerInfo::default());
    client.initialize().await.expect("warm initialize");

    let page = client
        .list_tools(None)
        .await
        .expect("partial at the page cap");

    assert!(page.truncated);
    assert_eq!(page.tools.len(), 20);
    assert!(page.next_cursor.is_some());
    assert_eq!(
        mock.state.list_hits.load(Ordering::SeqCst),
        20,
        "pagination fetched past the page cap"
    );
}

/// NP-3: the aggregate deadline stops a server that answers every page just
/// inside the per-page budget, with a typed Timeout.
#[tokio::test]
async fn tools_list_aggregate_deadline_is_enforced() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/slow-paginate",
        HeaderMap::new(),
        Limits::default(),
    );
    let info = ServerInfo {
        list_tools_deadline: Duration::from_millis(150),
        ..ServerInfo::default()
    };
    let client = kernel_mcp::client(transport, info);
    client.initialize().await.expect("initialize");

    let started = Instant::now();
    let err = client.list_tools(None).await.unwrap_err();
    assert_eq!(err, McpError::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the aggregate deadline was not effective: {:?}",
        started.elapsed()
    );
    let hits = mock.state.list_hits.load(Ordering::SeqCst);
    assert!(
        hits < 20,
        "the page cap, not the deadline, stopped pagination ({hits} pages)"
    );
}

/// NP-4: server info strings are sanitised (no control characters/ANSI) and
/// capped.
#[tokio::test]
async fn server_info_strings_are_sanitised_and_capped() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/evil-info", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let info = client.initialize().await.expect("initialize");
    assert!(
        info.name.len() <= 256,
        "name not capped: {}",
        info.name.len()
    );
    assert!(
        !info.name.chars().any(char::is_control),
        "name has control characters: {:?}",
        info.name
    );
    assert!(info.version.len() <= 256, "version not capped");
    assert!(!info.version.chars().any(char::is_control));
    let instructions = info.instructions.expect("instructions present");
    assert!(
        instructions.len() <= 4 * 1024,
        "instructions not capped: {}",
        instructions.len()
    );
    assert!(!instructions.chars().any(char::is_control));
}

/// NP-5: a non-date-shaped negotiated revision is a typed protocol error, while
/// a date-shaped one this build predates is accepted.
#[tokio::test]
async fn negotiated_protocol_version_is_validated() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport1 = transport(
        &mock,
        "/mcp/bad-version",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport1, ServerInfo::default());
    let err = client.initialize().await.unwrap_err();
    match &err {
        McpError::Protocol { message, .. } => assert!(
            message.as_str().contains("protocol version"),
            "got {message}"
        ),
        other => panic!("expected Protocol, got {other:?}"),
    }

    let mock2 = spawn().await;
    let transport2 = transport(
        &mock2,
        "/mcp/old-version",
        HeaderMap::new(),
        Limits::default(),
    );
    let client2 = kernel_mcp::client(transport2, ServerInfo::default());
    let info = client2.initialize().await.expect("old but date-shaped");
    assert_eq!(info.protocol_version, "2024-11-05");
}

/// NP-6: a leading UTF-8 BOM does not hide the first SSE `data:` line.
#[tokio::test]
async fn sse_leading_bom_is_stripped() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp/sse-bom", HeaderMap::new(), Limits::default());
    let client = kernel_mcp::client(transport, ServerInfo::default());

    let page = client.list_tools(None).await.expect("BOM-prefixed stream");
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "BOM_TOOL");
}

/// NP-7: a zero or absurd per-request budget is a typed config error.
#[test]
fn with_timeout_rejects_zero_and_absurd() {
    for bad in [Duration::ZERO, Duration::from_secs(24 * 60 * 60 + 1)] {
        let err = HttpTransport::new(
            "http://127.0.0.1:9/mcp",
            HeaderMap::new(),
            Limits::default(),
        )
        .expect("build transport")
        .with_timeout(bad)
        .err()
        .expect("bad timeout must be refused");
        assert!(
            matches!(err, McpError::InvalidTimeout { .. }),
            "got {err:?}"
        );
    }
    assert!(HttpTransport::new(
        "http://127.0.0.1:9/mcp",
        HeaderMap::new(),
        Limits::default()
    )
    .expect("build transport")
    .with_timeout(Duration::from_secs(5))
    .is_ok());
}

/// NP-8: `ServerInfo::max_tools` outside `1..=2000` is a typed config error.
#[tokio::test]
async fn server_info_max_tools_is_validated() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(&mock, "/mcp", HeaderMap::new(), Limits::default());

    for bad in [0usize, 2001] {
        let client = kernel_mcp::client(
            transport.clone(),
            ServerInfo {
                max_tools: bad,
                ..ServerInfo::default()
            },
        );
        let err = client.list_tools(None).await.unwrap_err();
        assert!(
            matches!(
                err,
                McpError::InvalidLimit {
                    field: "max_tools",
                    ..
                }
            ),
            "max_tools={bad}: got {err:?}"
        );
    }

    let client = kernel_mcp::client(
        transport,
        ServerInfo {
            max_tools: 2000,
            ..ServerInfo::default()
        },
    );
    assert!(
        client.list_tools(None).await.is_ok(),
        "2000 must be accepted"
    );
}

/// NP-9: the SSE `id:` is sanitised and capped before it is retained.
#[tokio::test]
async fn last_event_id_is_sanitised() {
    let _guard = serial().await;
    let mock = spawn().await;
    let transport = transport(
        &mock,
        "/mcp/sse-evil-id",
        HeaderMap::new(),
        Limits::default(),
    );
    let client = kernel_mcp::client(transport.clone(), ServerInfo::default());

    let page = client.list_tools(None).await.expect("stream");
    assert_eq!(page.tools.len(), 1);
    let id = transport.last_event_id().expect("event id retained");
    assert!(id.len() <= 256, "event id was not capped: {}", id.len());
    assert!(
        !id.chars().any(char::is_control),
        "event id has control characters: {id:?}"
    );
}
