//! S0 acceptance: envelope shape, id monotonicity, hard bounds, timeout seam,
//! and the security-review R1 hardening (sanitised errors, pinned response version,
//! typed response ids, validated limits).
//!
//! Offline only: the `Transport` here is a local stub, no socket is opened.

use std::io::{self, Read};
use std::time::{Duration, Instant};

use kernel_mcp::limits::{read_frame, read_sse_line};
use kernel_mcp::{
    sanitize_untrusted, IdGenerator, JsonRpcError, JsonRpcRequest, JsonRpcResponse, Limits,
    McpError, Method, ResponseId, Transport, JSONRPC_VERSION, MAX_UNTRUSTED_BYTES,
};

/// A transport that never answers: it burns exactly the budget, then reports.
struct NeverAnswers;

#[async_trait::async_trait]
impl Transport for NeverAnswers {
    async fn round_trip(
        &self,
        _req: JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, McpError> {
        tokio::time::sleep(timeout).await;
        Err(McpError::Timeout)
    }
}

/// A reader whose I/O error payload embeds a path and a secret.
struct LeakyFailingReader;

impl Read for LeakyFailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret: /home/alice/key.pem",
        ))
    }
}

#[test]
fn request_serde_round_trips() {
    let req = JsonRpcRequest::new(7, Method::ToolsList.as_str(), serde_json::json!({}));
    let text = serde_json::to_string(&req).expect("serialize");
    let parsed: JsonRpcRequest = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(parsed, req);
    assert_eq!(parsed.jsonrpc, JSONRPC_VERSION);

    let value: serde_json::Value = serde_json::from_str(&text).expect("to value");
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["id"], 7);
    assert_eq!(value["method"], "tools/list");
}

#[test]
fn success_response_round_trips() {
    let resp = JsonRpcResponse::success(1, serde_json::json!({"tools": []}));
    let text = serde_json::to_string(&resp).expect("serialize");
    let parsed: JsonRpcResponse = serde_json::from_str(&text).expect("deserialize");
    assert_eq!(parsed, resp);
    assert_eq!(
        parsed.into_result().expect("result"),
        serde_json::json!({"tools": []})
    );
}

#[test]
fn error_response_is_a_typed_protocol_error() {
    let resp = JsonRpcResponse::failure(
        1,
        JsonRpcError {
            code: -32601,
            message: "no such method".into(),
            data: None,
        },
    );
    match resp.into_result() {
        Err(McpError::Protocol { code, message }) => {
            assert_eq!(code, -32601);
            assert_eq!(message, "no such method");
        }
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn unknown_method_is_a_typed_error() {
    assert_eq!(
        Method::parse("tools/call").expect("known"),
        Method::ToolsCall
    );
    match Method::parse("tools/delete_everything") {
        Err(McpError::Protocol { code, .. }) => assert_eq!(code, -32601),
        other => panic!("expected Protocol, got {other:?}"),
    }
}

#[test]
fn request_ids_are_monotonic() {
    let ids = IdGenerator::new();
    let seen: Vec<u64> = (0..5).map(|_| ids.next_id().expect("id")).collect();
    assert!(
        seen.windows(2).all(|w| w[0] < w[1]),
        "not monotonic: {seen:?}"
    );
}

#[test]
fn default_limits_are_pinned() {
    let limits = Limits::default();
    assert_eq!(limits.max_frame_bytes, 8 * 1024 * 1024);
    assert_eq!(limits.max_sse_line_bytes, 1024 * 1024);
    assert_eq!(limits.max_tools, 500);
    assert_eq!(limits.max_inflight, 8);
}

#[test]
fn frame_at_the_limit_is_accepted() {
    let body = vec![b'a'; 64];
    let mut reader: &[u8] = &body;
    let out = read_frame(&mut reader, 64).expect("exactly the limit is fine");
    assert_eq!(out.len(), 64);
}

#[test]
fn oversize_frame_is_refused_while_streaming() {
    let body = vec![b'a'; 65];
    let mut reader: &[u8] = &body;
    let err = read_frame(&mut reader, 64).unwrap_err();
    assert_eq!(
        err,
        McpError::FrameTooLarge {
            limit: 64,
            seen: 65
        }
    );
}

#[test]
fn sse_line_is_bounded() {
    let line: Vec<u8> = b"data: ".iter().chain([b'x'; 40].iter()).copied().collect();
    let mut reader: &[u8] = &line;
    let err = read_sse_line(&mut reader, 32).unwrap_err();
    assert!(
        matches!(err, McpError::FrameTooLarge { limit: 32, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn timeout_is_reported_after_the_budget() {
    let budget = Duration::from_millis(50);
    let started = Instant::now();
    let err = NeverAnswers
        .round_trip(
            JsonRpcRequest::new(1, "initialize", serde_json::json!({})),
            budget,
        )
        .await
        .unwrap_err();
    assert_eq!(err, McpError::Timeout);
    let elapsed = started.elapsed();
    assert!(
        elapsed < budget + Duration::from_secs(1),
        "timeout drifted: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// security-review R1 fixes
// ---------------------------------------------------------------------------

/// FB-4: an I/O failure carries only the `ErrorKind`, never the raw payload.
#[test]
fn io_error_never_leaks_the_raw_message() {
    let mut reader = LeakyFailingReader;
    let err = read_frame(&mut reader, 64).unwrap_err();
    assert_eq!(
        err,
        McpError::Io {
            kind: io::ErrorKind::PermissionDenied
        }
    );
    let shown = err.to_string();
    assert!(!shown.contains("secret"), "leaked the payload: {shown}");
    assert!(!shown.contains("/home"), "leaked a path: {shown}");
    assert!(!shown.contains("key.pem"), "leaked a path: {shown}");
}

/// FB-13: untrusted protocol text is bounded and stripped of control
/// characters, newlines and ANSI escapes (it is not redacted).
#[test]
fn untrusted_protocol_text_is_bounded_and_cleaned() {
    let big = "x".repeat(10_000);
    match Method::parse(&big) {
        Err(McpError::Protocol { message, .. }) => {
            assert!(message.len() <= 256, "message was {} bytes", message.len());
        }
        other => panic!("expected Protocol, got {other:?}"),
    }

    let hostile = "bad\u{1b}[31mred\nNUL\u{0}end\t";
    match Method::parse(hostile) {
        Err(McpError::Protocol { message, .. }) => {
            let text = message.as_str();
            assert!(
                !text.chars().any(char::is_control),
                "control chars survived: {text:?}"
            );
            assert!(!text.contains('\u{1b}'), "ESC survived: {text:?}");
            assert!(text.contains("badred"), "ANSI not stripped: {text:?}");
        }
        other => panic!("expected Protocol, got {other:?}"),
    }

    // Bounds and cleans, but does not redact: the secret survives on purpose.
    let secret = sanitize_untrusted("token sk-live-abc123", MAX_UNTRUSTED_BYTES);
    assert!(
        secret.contains("sk-live-abc123"),
        "secret was redacted: {secret}"
    );

    // The cap is UTF-8 boundary safe: 200 two-byte chars cap at 256 bytes.
    let multibyte = "é".repeat(200);
    let capped = sanitize_untrusted(&multibyte, 256);
    assert_eq!(capped.len(), 256);
    assert_eq!(capped.chars().count(), 128);
}

/// FB-3: the response side pins `jsonrpc` to "2.0" exactly like the request.
#[test]
fn response_version_is_pinned() {
    let ok: JsonRpcResponse =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).expect("2.0 decodes");
    assert_eq!(ok.jsonrpc, JSONRPC_VERSION);

    let bad = serde_json::from_str::<JsonRpcResponse>(r#"{"jsonrpc":"1.0","id":1,"result":{}}"#);
    assert!(bad.is_err(), "accepted a non-2.0 response version");

    let huge = serde_json::json!({
        "jsonrpc": "x".repeat(10_000),
        "id": 1,
        "result": {}
    })
    .to_string();
    assert!(
        serde_json::from_str::<JsonRpcResponse>(&huge).is_err(),
        "accepted a 10 KB version string"
    );
}

/// FB-7: string ids and `id: null` decode; `u64::MAX` stays exact; negative,
/// fractional and out-of-range ids are typed errors, not panics.
#[test]
fn response_id_accepts_string_null_and_u64_max() {
    let string_id: JsonRpcResponse =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":"abc","result":{}}"#).expect("string id");
    assert_eq!(string_id.id.as_str(), Some("abc"));

    let null_id: JsonRpcResponse =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":null,"result":{}}"#).expect("null id");
    assert!(null_id.id.is_null());

    let absent: JsonRpcResponse =
        serde_json::from_str(r#"{"jsonrpc":"2.0","result":{}}"#).expect("absent id");
    assert!(absent.id.is_null());

    let max_json = format!(r#"{{"jsonrpc":"2.0","id":{},"result":{{}}}}"#, u64::MAX);
    let max_id: JsonRpcResponse = serde_json::from_str(&max_json).expect("u64::MAX id");
    assert_eq!(max_id.id, ResponseId::Number(u64::MAX));

    let negative =
        serde_json::from_str::<JsonRpcResponse>(r#"{"jsonrpc":"2.0","id":-1,"result":{}}"#);
    assert!(negative.is_err(), "accepted a negative id");

    let fractional =
        serde_json::from_str::<JsonRpcResponse>(r#"{"jsonrpc":"2.0","id":1.5,"result":{}}"#);
    assert!(fractional.is_err(), "accepted a fractional id");

    let out_of_range = serde_json::from_str::<JsonRpcResponse>(
        r#"{"jsonrpc":"2.0","id":18446744073709551616,"result":{}}"#,
    );
    assert!(out_of_range.is_err(), "accepted an out-of-range id");
}

/// FB-1/FB-2: `FrameTooLarge` is terminal for the connection, never resumed.
#[test]
fn frame_too_large_is_terminal_for_the_connection() {
    let too_large = McpError::FrameTooLarge { limit: 8, seen: 9 };
    assert!(too_large.requires_connection_close());

    let protocol = McpError::protocol(-32700, "bad json");
    assert!(!protocol.requires_connection_close());

    let line: Vec<u8> = b"data: ".iter().chain([b'x'; 40].iter()).copied().collect();
    let mut reader: &[u8] = &line;
    let err = read_sse_line(&mut reader, 8).unwrap_err();
    assert!(
        err.requires_connection_close(),
        "over-limit SSE line was not terminal: {err:?}"
    );
}

/// FB-14: `Limits::validate` rejects zero and absurd bounds.
#[test]
fn limits_reject_zero_and_absurd_values() {
    assert!(Limits::default().validate().is_ok());
    assert!(Limits::tiny().validate().is_ok());

    let zero = Limits {
        max_frame_bytes: 0,
        ..Limits::default()
    };
    assert!(matches!(
        zero.validate(),
        Err(McpError::InvalidLimit {
            field: "max_frame_bytes",
            ..
        })
    ));

    let absurd = Limits {
        max_inflight: 1_000_000,
        ..Limits::default()
    };
    assert!(matches!(
        absurd.validate(),
        Err(McpError::InvalidLimit {
            field: "max_inflight",
            ..
        })
    ));

    assert!(Limits::new(64, 32, 3, 1).is_ok());
    assert!(Limits::new(0, 32, 3, 1).is_err());
}

/// P3: the id allocator never wraps to 0 or repeats an id.
#[test]
fn id_generator_never_wraps_or_returns_zero() {
    let ids = IdGenerator::new();
    assert_eq!(ids.next_id(), Some(1));

    let tail = IdGenerator::starting_at(u64::MAX - 1);
    assert_eq!(tail.next_id(), Some(u64::MAX - 1));
    assert_eq!(tail.next_id(), None, "exhaustion must not repeat an id");
    assert_eq!(tail.next_id(), None, "exhaustion must stay exhausted");

    assert_eq!(
        IdGenerator::starting_at(0).next_id(),
        Some(1),
        "0 is reserved"
    );
}
