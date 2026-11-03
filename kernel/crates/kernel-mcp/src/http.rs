//! Streamable HTTP transport for one MCP endpoint.
//!
//! # What this module is responsible for
//!
//! * **Origin pinning.** The transport stores the exact origin the session
//!   handed us and refuses to send the pinned headers anywhere else. With
//!   [`reqwest::redirect::Policy::none`], a `3xx` is returned as
//!   [`McpError::Http`] and never followed, so an `x-api-key` cannot leak to a
//!   redirect target.
//! * **Plaintext refusal.** A request that would carry the pinned headers over
//!   a non-`https` origin is refused unless the host is loopback
//!   (`127.0.0.1` / `::1` / `localhost`), which is what the offline fake server
//!   needs. `x-api-key` therefore never rides a bare `http://` connection to a
//!   public host.
//! * **Bounded frames.** A JSON body is read in a streaming loop and cut at
//!   [`Limits::max_frame_bytes`]; an SSE line is cut at
//!   [`Limits::max_sse_line_bytes`]. Crossing a bound is
//!   [`McpError::FrameTooLarge`], never a truncated parse.
//! * **A hard concurrency cap.** A semaphore of [`Limits::max_inflight`]
//!   permits gates every send.
//! * **Id correlation.** A response body must echo the exact request id
//!   (numeric) on **both** the JSON and the SSE path; an absent, string or
//!   different id is a typed protocol error, never accepted as an answer.
//! * **Negotiated version header.** After `initialize`, the negotiated
//!   `protocolVersion` is sent as the MCP `MCP-Protocol-Version` header on every
//!   later request.
//!
//! # Retries
//!
//! `initialize` and `tools/list` may be retried **once**, and only when the
//! connection itself failed — a refused connect or a connection dropped before
//! any response. A **timeout is terminal** and never retried, an HTTP status is
//! a typed [`McpError::Http`], and `tools/call` is **never retried**: a retried
//! mutation is a double send, and the engine cannot tell a duplicate render or
//! CRM write from the intended one.
//!
//! # Resumption
//!
//! The last SSE `id:` field is kept in memory for a future `Last-Event-ID`
//! resume. It is unused for now — no caller reads it back onto the wire.
//!
//! # SSE line terminators
//!
//! The single transport parser accepts CR, LF and CRLF terminators, including a
//! CRLF split across two read chunks, and drops a leading UTF-8 BOM (split or
//! whole). `limits::read_sse_line` is retained only as the S0 bounded-line
//! helper its tests exercise; the transport never uses it.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use reqwest::{Response, Url};
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::client::is_valid_protocol_version;
use crate::error::{McpError, Sanitized, INTERNAL_ERROR, INVALID_REQUEST, PARSE_ERROR};
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::limits::{check_timeout, Limits};
use crate::Transport;

/// How long a connect may take before it is abandoned.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default request budget when a caller does not override it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Backoff before the single `initialize`/`tools/list` retry.
const RETRY_BACKOFF: Duration = Duration::from_millis(250);
/// Header carrying the negotiated MCP protocol revision (MCP spec).
const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
/// Header carrying the server session id.
const SESSION_ID_HEADER: &str = "mcp-session-id";
/// Largest accepted `Mcp-Session-Id`, in bytes.
const MAX_SESSION_ID_BYTES: usize = 256;
/// Largest accepted SSE `id:` value, in bytes.
const MAX_EVENT_ID_BYTES: usize = 256;
/// The UTF-8 byte-order mark that may prefix an SSE stream.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// The exact origin a transport is pinned to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    fn of(url: &Url) -> Option<Self> {
        Some(Self {
            scheme: url.scheme().to_owned(),
            host: url.host_str()?.to_ascii_lowercase(),
            port: url.port_or_known_default()?,
        })
    }

    fn describe(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }

    /// Whether `host` is a loopback name/address that may use plaintext HTTP.
    fn is_loopback(host: &str) -> bool {
        matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
    }

    /// Whether the transport may carry its pinned headers to this origin.
    ///
    /// `https` always; plaintext `http` only on loopback, so a public host can
    /// never receive `x-api-key` over an unencrypted connection.
    fn accepts_credentials(&self) -> bool {
        self.scheme == "https" || (self.scheme == "http" && Self::is_loopback(&self.host))
    }
}

/// A failure plus whether the caller may safely try once more.
///
/// Only a connection-level failure is retryable; an HTTP status, a frame bound,
/// a timeout or a protocol error is not. This is internal to the transport so
/// the S0 [`McpError`] surface does not have to grow.
struct AttemptError {
    mcp: McpError,
    retryable: bool,
}

impl AttemptError {
    fn fatal(mcp: McpError) -> Self {
        Self {
            mcp,
            retryable: false,
        }
    }

    fn retryable(mcp: McpError) -> Self {
        Self {
            mcp,
            retryable: true,
        }
    }
}

/// One MCP Streamable HTTP endpoint.
pub struct HttpTransport {
    /// The pinned endpoint; every request goes here, verbatim.
    base_url: Url,
    /// The origin `x-api-key` and friends are allowed to reach.
    origin: Origin,
    /// Headers attached to every request (the session credential lives here).
    headers: HeaderMap,
    /// The single shared client for this endpoint.
    client: reqwest::Client,
    /// Hard bounds for one connection.
    limits: Limits,
    /// Default request budget, overridable with [`HttpTransport::with_timeout`].
    timeout: Duration,
    /// The negotiated protocol revision, sent after `initialize`.
    protocol_version: Mutex<Option<String>>,
    /// `Mcp-Session-Id` handed back by the server, if any (memory only).
    session_id: Mutex<Option<String>>,
    /// Last SSE event id, kept for a future resumption. Unused for now.
    last_event_id: Mutex<Option<String>>,
    /// At most `Limits::max_inflight` requests against this endpoint.
    inflight: Semaphore,
}

impl HttpTransport {
    /// Build a transport pinned to `url`.
    ///
    /// The URL must be absolute with a host; the origin it resolves to becomes
    /// the only origin this transport will ever send [`headers`](Self::headers)
    /// to. A non-`https` origin is refused unless its host is loopback, and
    /// `limits` is validated before the transport is built.
    pub fn new(url: &str, headers: HeaderMap, limits: Limits) -> Result<Self, McpError> {
        limits.validate()?;
        let base_url = Url::parse(url)
            .map_err(|_| McpError::protocol(INVALID_REQUEST, "invalid endpoint url"))?;
        let origin = Origin::of(&base_url)
            .ok_or_else(|| McpError::protocol(INVALID_REQUEST, "endpoint url has no origin"))?;
        if !origin.accepts_credentials() {
            return Err(McpError::OriginRefused {
                expected: Sanitized::new("https (or http on loopback)"),
                got: Sanitized::new(&origin.describe()),
            });
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .no_proxy()
            .build()
            .map_err(|_| McpError::protocol(INTERNAL_ERROR, "http client unavailable"))?;
        let inflight = Semaphore::new(limits.max_inflight.max(1));
        Ok(Self {
            base_url,
            origin,
            headers,
            client,
            limits,
            timeout: REQUEST_TIMEOUT,
            protocol_version: Mutex::new(None),
            session_id: Mutex::new(None),
            last_event_id: Mutex::new(None),
            inflight,
        })
    }

    /// Override the default request budget.
    ///
    /// The budget actually used for one call is `min(per_call, configured)`, so
    /// lowering it here tightens every operation without letting a caller
    /// exceed it. It is therefore effective, not a dead knob. A zero or absurd
    /// value is a typed config error rather than a silently useless budget.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, McpError> {
        check_timeout("timeout", timeout)?;
        self.timeout = timeout;
        Ok(self)
    }

    /// Build a transport pinned to `url`, enforcing the shared SSRF guard.
    ///
    /// This is the runtime counterpart of the management API's `test_server`:
    /// the host shape is refused (`localhost`, `*.localhost`, a trailing dot,
    /// `.lan`/`.local`/`.internal`) and **every** DNS answer is checked for a
    /// private/tailnet address. The one address that passed is then pinned with
    /// `reqwest::ClientBuilder::resolve`, so the connection cannot be rebound
    /// to another address between the check and the connect.
    pub async fn new_checked(
        url: &str,
        headers: HeaderMap,
        limits: Limits,
    ) -> Result<Self, McpError> {
        let mut transport = Self::new(url, headers, limits)?;
        let (host, ip) = kernel_net::resolve_public_url(&transport.base_url)
            .await
            .map_err(|_| McpError::AddressRefused)?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .no_proxy();
        if host.parse::<std::net::IpAddr>().is_err() {
            builder = builder.resolve(&host, std::net::SocketAddr::new(ip, 0));
        }
        transport.client = builder
            .build()
            .map_err(|_| McpError::protocol(INTERNAL_ERROR, "http client unavailable"))?;
        Ok(transport)
    }

    /// The `Mcp-Session-Id` the server handed back, if any.
    pub fn session_id(&self) -> Option<String> {
        lock(&self.session_id).clone()
    }

    /// The last SSE event id seen. Kept for resumption; unused for now.
    pub fn last_event_id(&self) -> Option<String> {
        lock(&self.last_event_id).clone()
    }

    /// The negotiated MCP protocol revision, if `initialize` has run.
    pub fn protocol_version(&self) -> Option<String> {
        lock(&self.protocol_version).clone()
    }

    /// Refuse to act on a URL whose origin differs from the pinned one.
    fn check_origin(&self, url: &Url) -> Result<(), McpError> {
        let resolved = Origin::of(url).ok_or_else(|| McpError::OriginRefused {
            expected: Sanitized::new(&self.origin.describe()),
            got: Sanitized::new("<invalid>"),
        })?;
        if resolved != self.origin {
            return Err(McpError::OriginRefused {
                expected: Sanitized::new(&self.origin.describe()),
                got: Sanitized::new(&resolved.describe()),
            });
        }
        Ok(())
    }

    async fn send_once(
        &self,
        req: &JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, AttemptError> {
        match tokio::time::timeout(timeout, self.send_inner(req, timeout)).await {
            Ok(result) => result,
            Err(_) => Err(AttemptError::fatal(McpError::Timeout)),
        }
    }

    async fn send_inner(
        &self,
        req: &JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, AttemptError> {
        let _permit = match tokio::time::timeout(timeout, self.inflight.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(AttemptError::fatal(McpError::protocol(
                    INTERNAL_ERROR,
                    "connection closed",
                )))
            }
            Err(_) => return Err(AttemptError::fatal(McpError::Timeout)),
        };

        self.check_origin(&self.base_url)
            .map_err(AttemptError::fatal)?;

        let is_notification = req.method.starts_with("notifications/");
        let body = if is_notification {
            // JSON-RPC 2.0 notifications MUST NOT carry an `id` member.
            let mut envelope = serde_json::Map::new();
            envelope.insert("jsonrpc".to_owned(), Value::String(req.jsonrpc.to_owned()));
            envelope.insert("method".to_owned(), Value::String(req.method.clone()));
            if req
                .params
                .as_object()
                .is_none_or(|params| !params.is_empty())
            {
                envelope.insert("params".to_owned(), req.params.clone());
            }
            serde_json::to_vec(&Value::Object(envelope))
        } else {
            serde_json::to_vec(req)
        }
        .map_err(|_| {
            AttemptError::fatal(McpError::protocol(
                INVALID_REQUEST,
                "could not encode request",
            ))
        })?;

        let mut builder = self
            .client
            .post(self.base_url.clone())
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .headers(self.headers.clone())
            .body(body);
        // The negotiated revision rides every request *after* initialize.
        let version = if is_notification {
            None
        } else {
            lock(&self.protocol_version).clone()
        };
        if let Some(version) = version {
            builder = builder.header(PROTOCOL_VERSION_HEADER, version);
        }
        if let Some(session) = lock(&self.session_id).clone() {
            builder = builder.header(SESSION_ID_HEADER, session);
        }

        let response = builder.send().await.map_err(send_error)?;

        let status = response.status();
        if status.is_success() {
            // Capture the session id only from a successful response, bounded
            // and stripped of control characters (it is a peer-supplied header).
            if let Some(value) = response
                .headers()
                .get(SESSION_ID_HEADER)
                .and_then(|value| value.to_str().ok())
            {
                *lock(&self.session_id) =
                    Some(Sanitized::with_cap(value, MAX_SESSION_ID_BYTES).into_string());
            }
        }
        if status.is_redirection() || !status.is_success() {
            // A 3xx is reported, never followed (policy is `none`).
            return Err(AttemptError::fatal(McpError::Http {
                status: status.as_u16(),
            }));
        }

        // Notifications are fire-and-forget: a 2xx is the whole answer.
        if is_notification {
            return Ok(JsonRpcResponse::success(req.id, Value::Null));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let envelope = if content_type.contains("text/event-stream") {
            read_sse_bounded(
                response,
                req.id,
                self.limits.max_sse_line_bytes,
                self.limits.max_frame_bytes,
                &self.last_event_id,
            )
            .await
            .map_err(AttemptError::fatal)?
        } else {
            let bytes = read_body_bounded(response, self.limits.max_frame_bytes)
                .await
                .map_err(AttemptError::fatal)?;
            serde_json::from_slice::<JsonRpcResponse>(&bytes).map_err(|_| {
                AttemptError::fatal(McpError::protocol(PARSE_ERROR, "invalid JSON response"))
            })?
        };
        let envelope = correlate(envelope, req.id)?;
        if req.method == "initialize" {
            // Only a date-shaped revision is remembered and echoed back on the
            // `MCP-Protocol-Version` header; the client independently refuses an
            // invalid one, this is defence in depth.
            if let Some(version) = envelope
                .result
                .as_ref()
                .and_then(|result| result.get("protocolVersion"))
                .and_then(Value::as_str)
                .filter(|version| is_valid_protocol_version(version))
            {
                *lock(&self.protocol_version) =
                    Some(Sanitized::with_cap(version, MAX_SESSION_ID_BYTES).into_string());
            }
        }
        Ok(envelope)
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn round_trip(
        &self,
        req: JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, McpError> {
        // The effective budget never exceeds the configured one.
        let budget = timeout.min(self.timeout);
        // One retry only for the two idempotent discovery calls; never for a
        // `tools/call`.
        let attempts = if matches!(req.method.as_str(), "initialize" | "tools/list") {
            2
        } else {
            1
        };
        let mut last = None;
        for attempt in 0..attempts {
            match self.send_once(&req, budget).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    let can_retry = error.retryable && attempt + 1 < attempts;
                    last = Some(error.mcp);
                    if !can_retry {
                        break;
                    }
                    tokio::time::sleep(RETRY_BACKOFF).await;
                }
            }
        }
        Err(last.unwrap_or(McpError::Timeout))
    }
}

/// Classify a `reqwest` send failure.
///
/// Only a connection-level failure may be retried; a timeout never is (it may
/// already have reached the server).
fn send_error(err: reqwest::Error) -> AttemptError {
    if err.is_timeout() {
        AttemptError::fatal(McpError::Timeout)
    } else if err.is_connect() || err.is_request() {
        AttemptError::retryable(McpError::protocol(INTERNAL_ERROR, "connection failed"))
    } else {
        AttemptError::fatal(McpError::protocol(INTERNAL_ERROR, "request failed"))
    }
}

/// Require the response id to equal the request id.
///
/// A JSON body path has exactly one response, so an absent, string or different
/// id is a protocol error rather than a value we might misattribute.
fn correlate(response: JsonRpcResponse, expected_id: u64) -> Result<JsonRpcResponse, AttemptError> {
    if response.id.as_number() == Some(expected_id) {
        Ok(response)
    } else {
        Err(AttemptError::fatal(McpError::protocol(
            INVALID_REQUEST,
            "response id did not match the request id",
        )))
    }
}

/// Read a whole JSON body, cutting it at `max` while streaming.
async fn read_body_bounded(mut response: Response, max: usize) -> Result<Vec<u8>, McpError> {
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(body_error)? {
        if out.len() + chunk.len() > max {
            return Err(McpError::FrameTooLarge {
                limit: max,
                seen: out.len() + chunk.len(),
            });
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Read an SSE stream until the JSON-RPC response for `expected_id` arrives.
///
/// The last `id:` seen is written back to `last_event_id` before returning, win
/// or lose, so a caller could resume with `Last-Event-ID` later (unused today).
async fn read_sse_bounded(
    mut response: Response,
    expected_id: u64,
    max_line: usize,
    max_frame: usize,
    last_event_id: &Mutex<Option<String>>,
) -> Result<JsonRpcResponse, McpError> {
    let mut parser = SseParser::new(expected_id, max_line, max_frame);
    let outcome = loop {
        match response.chunk().await {
            Ok(Some(chunk)) => match parser.push(&chunk) {
                Ok(Some(found)) => break Ok(found),
                Ok(None) => {}
                Err(err) => break Err(err),
            },
            Ok(None) => break parser.finish(),
            Err(err) => break Err(body_error(err)),
        }
    };
    if let Some(id) = parser.last_event_id.take() {
        *lock(last_event_id) = Some(id);
    }
    outcome
}

/// A bounded SSE parser.
///
/// The current line never grows past `max_line`, the accumulated `data:`
/// payload never past `max_frame`, and the parser returns the instant a `data:`
/// line is the complete response for `expected_id` — it does not need to see the
/// terminating blank line, which is what keeps a hostile flood bounded.
///
/// Line terminators may be LF, CR or CRLF, including a CRLF split across two
/// chunks (a trailing CR is held back until the next chunk proves whether an LF
/// follows). A UTF-8 BOM that begins the stream is dropped, even when it is
/// split across two read chunks.
struct SseParser {
    pending: Vec<u8>,
    event_data: Vec<u8>,
    max_line: usize,
    max_frame: usize,
    expected_id: u64,
    last_event_id: Option<String>,
    /// A CR ended the previous chunk; swallow a leading LF from the next one.
    skip_lf: bool,
    /// Bytes held back at the very start of the stream so a split BOM is
    /// detected before any of it is parsed as field content.
    lead: Vec<u8>,
    /// Whether the leading-BOM check has completed.
    lead_checked: bool,
}

impl SseParser {
    fn new(expected_id: u64, max_line: usize, max_frame: usize) -> Self {
        Self {
            pending: Vec::new(),
            event_data: Vec::new(),
            max_line,
            max_frame,
            expected_id,
            last_event_id: None,
            skip_lf: false,
            lead: Vec::new(),
            lead_checked: false,
        }
    }

    /// Feed bytes, returning the response as soon as it is complete.
    fn push(&mut self, bytes: &[u8]) -> Result<Option<JsonRpcResponse>, McpError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        if self.lead_checked {
            return self.push_checked(bytes);
        }
        // Drop a UTF-8 BOM that starts the stream. Until three bytes are
        // available a possible BOM prefix is held back, so a BOM split across
        // chunks is never mistaken for the start of a `data:` line.
        self.lead.extend_from_slice(bytes);
        if self.lead.len() < UTF8_BOM.len() && UTF8_BOM.starts_with(self.lead.as_slice()) {
            return Ok(None);
        }
        self.lead_checked = true;
        if self.lead.starts_with(&UTF8_BOM) {
            self.lead.drain(..UTF8_BOM.len());
        }
        let owned = std::mem::take(&mut self.lead);
        if owned.is_empty() {
            return Ok(None);
        }
        self.push_checked(&owned)
    }

    /// Parse bytes whose leading BOM has already been handled.
    fn push_checked(&mut self, bytes: &[u8]) -> Result<Option<JsonRpcResponse>, McpError> {
        let mut start = 0;
        if self.skip_lf {
            self.skip_lf = false;
            if bytes[0] == b'\n' {
                start = 1;
            }
        }
        let mut i = start;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'\r' || byte == b'\n' {
                self.append(&bytes[start..i])?;
                let mut next = i + 1;
                if byte == b'\r' {
                    if next < bytes.len() {
                        if bytes[next] == b'\n' {
                            next += 1;
                        }
                    } else {
                        // A CR that ends the chunk may be half of a CRLF.
                        self.skip_lf = true;
                    }
                }
                let line = std::mem::take(&mut self.pending);
                if let Some(found) = self.line(&line)? {
                    return Ok(Some(found));
                }
                start = next;
                i = next;
                continue;
            }
            i += 1;
        }
        self.append(&bytes[start..])?;
        Ok(None)
    }

    /// Finish the stream: flush the trailing partial line and event.
    fn finish(&mut self) -> Result<JsonRpcResponse, McpError> {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            if let Some(found) = self.line(&pending)? {
                return Ok(found);
            }
        }
        if let Some(found) = self.dispatch_event()? {
            return Ok(found);
        }
        Err(McpError::protocol(
            INVALID_REQUEST,
            "stream ended without a response",
        ))
    }

    /// Append to the current line, enforcing the per-line bound.
    fn append(&mut self, piece: &[u8]) -> Result<Option<JsonRpcResponse>, McpError> {
        if self.pending.len() + piece.len() > self.max_line {
            return Err(McpError::FrameTooLarge {
                limit: self.max_line,
                seen: self.pending.len() + piece.len(),
            });
        }
        self.pending.extend_from_slice(piece);
        Ok(None)
    }

    /// Handle one complete SSE line (terminator already removed).
    fn line(&mut self, raw: &[u8]) -> Result<Option<JsonRpcResponse>, McpError> {
        if raw.is_empty() {
            return self.dispatch_event();
        }
        if raw.starts_with(b":") {
            return Ok(None); // comment / keep-alive
        }
        let (field, value) = match raw.iter().position(|&b| b == b':') {
            Some(pos) => (&raw[..pos], strip_one_space(&raw[pos + 1..])),
            None => (raw, &b""[..]),
        };
        match field {
            b"data" => {
                // Fast path: MCP sends one complete JSON-RPC message per data
                // line. Return it before reading any further bytes.
                if let Ok(text) = std::str::from_utf8(value) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(text.trim()) {
                        return self.resolve(parsed);
                    }
                }
                if !self.event_data.is_empty() {
                    self.event_data.push(b'\n');
                }
                if self.event_data.len() + value.len() > self.max_frame {
                    return Err(McpError::FrameTooLarge {
                        limit: self.max_frame,
                        seen: self.event_data.len() + value.len(),
                    });
                }
                self.event_data.extend_from_slice(value);
                Ok(None)
            }
            b"id" => {
                // The event id is untrusted: bound it and strip control
                // characters/ANSI before it is retained for a future resume.
                let text = String::from_utf8_lossy(value);
                self.last_event_id =
                    Some(Sanitized::with_cap(&text, MAX_EVENT_ID_BYTES).into_string());
                Ok(None)
            }
            // `event:` and every other field are ignored on purpose.
            _ => Ok(None),
        }
    }

    /// A blank line (or the fast path) resolves one parsed JSON-RPC message.
    ///
    /// A server notification or request (top-level `method`) is ignored, never
    /// acted on. A response whose id is not the request's is a typed protocol
    /// error: it can only be a misattributed answer.
    fn resolve(&self, value: Value) -> Result<Option<JsonRpcResponse>, McpError> {
        if value.get("method").is_some() {
            return Ok(None);
        }
        let response: JsonRpcResponse = match serde_json::from_value(value) {
            Ok(response) => response,
            // Not a response envelope we understand; ignore other traffic.
            Err(_) => return Ok(None),
        };
        if response.id.as_number() == Some(self.expected_id) {
            return Ok(Some(response));
        }
        Err(McpError::protocol(
            INVALID_REQUEST,
            "sse response id did not match the request id",
        ))
    }

    /// A blank line dispatches the accumulated multi-line `data:` payload.
    fn dispatch_event(&mut self) -> Result<Option<JsonRpcResponse>, McpError> {
        let data = std::mem::take(&mut self.event_data);
        if data.is_empty() {
            return Ok(None);
        }
        match serde_json::from_slice::<Value>(&data) {
            Ok(value) => self.resolve(value),
            // Unparseable events are not fatal.
            Err(_) => Ok(None),
        }
    }
}

/// Remove a single leading space from an SSE field value (`data: x`).
fn strip_one_space(value: &[u8]) -> &[u8] {
    if value.first() == Some(&b' ') {
        &value[1..]
    } else {
        value
    }
}

/// Map a body-read failure to a secret-free typed error (never the URL).
fn body_error(_: reqwest::Error) -> McpError {
    McpError::protocol(INTERNAL_ERROR, "response body failed")
}

/// Lock without letting a poisoned mutex poison the transport.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[tokio::test]
    async fn checked_transport_refuses_local_internal_and_trailing_dot_hosts() {
        for url in [
            "https://localhost/mcp",
            "https://foo.localhost/mcp",
            "https://service.internal/mcp",
            "https://printer.lan/mcp",
            "https://localhost./mcp",
            "https://127.0.0.1/mcp",
            "https://10.0.0.1/mcp",
            "https://169.254.169.254/mcp",
            "https://100.64.0.1/mcp",
        ] {
            let result = HttpTransport::new_checked(url, HeaderMap::new(), Limits::default()).await;
            assert!(result.is_err(), "{url} must be refused");
            assert_eq!(
                result.err().map(|err| err.kind()),
                Some("address_refused"),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn checked_transport_accepts_a_public_literal_and_pins_it() {
        let transport =
            HttpTransport::new_checked("https://8.8.8.8/mcp", HeaderMap::new(), Limits::default())
                .await
                .expect("public literal accepted");
        assert_eq!(transport.origin.host, "8.8.8.8");
    }
}
