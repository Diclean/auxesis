//! NDJSON JSON-RPC 2.0 connection over a child's stdio.
//!
//! One reader task parses newline-delimited frames under hard caps, routes
//! responses to their pending request, answers agent requests through a
//! [`RequestHandler`], and forwards `session/update` notifications on a
//! bounded queue. One writer task owns the child's stdin. Nothing in this
//! module panics on malformed input: every failure path becomes a typed error,
//! a JSON-RPC error response, or a closed connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;

use crate::error::AcpError;
use crate::protocol::{self, code, IdKey, Incoming, RpcError, SessionUpdate};

/// Default per-frame (line) cap: 1 MiB. ACP frames are small; a bigger line is
/// either a bug or a memory bomb.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Default cap on in-flight client→agent requests.
pub const DEFAULT_MAX_PENDING: usize = 32;

/// Default outbound queue depth (frames waiting for the writer task).
pub const DEFAULT_OUTBOUND_QUEUE: usize = 64;

/// Default inbound `session/update` queue depth. When it is full the update is
/// dropped and counted; the reader never blocks on the backend.
pub const DEFAULT_UPDATE_QUEUE: usize = 256;

/// Default cap on concurrent agent→client request handlers.
pub const DEFAULT_MAX_HANDLERS: usize = 4;

/// Default cap on the total bytes of inbound frames per connection (16 MiB).
pub const DEFAULT_MAX_TOTAL_INBOUND: u64 = 16 * 1024 * 1024;

/// Hard caps for one connection.
#[derive(Debug, Clone, Copy)]
pub struct RpcLimits {
    /// Largest single frame (line), in bytes.
    pub max_frame_bytes: usize,
    /// Largest number of in-flight client→agent requests.
    pub max_pending_requests: usize,
    /// Outbound queue depth.
    pub outbound_queue: usize,
    /// Inbound update queue depth.
    pub update_queue: usize,
    /// Concurrent agent-request handlers.
    pub max_handlers: usize,
    /// Total inbound bytes before the connection is considered abusive.
    pub max_total_inbound_bytes: u64,
}

impl Default for RpcLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_pending_requests: DEFAULT_MAX_PENDING,
            outbound_queue: DEFAULT_OUTBOUND_QUEUE,
            update_queue: DEFAULT_UPDATE_QUEUE,
            max_handlers: DEFAULT_MAX_HANDLERS,
            max_total_inbound_bytes: DEFAULT_MAX_TOTAL_INBOUND,
        }
    }
}

/// Answers one agent→client JSON-RPC request.
///
/// Returning `Ok(value)` sends `result`; returning `Err` sends `error`. The
/// handler must map every failure to a JSON-RPC error — an unanswered request
/// hangs the agent, so the dispatcher answers even when the handler panics.
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle `method` with `params`.
    async fn handle(&self, method: &str, params: &Value) -> Result<Value, RpcError>;
}

/// One `session/update` notification, already classified.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateEvent {
    /// The session the update belongs to, when reported.
    pub session_id: Option<String>,
    /// The classified update.
    pub update: SessionUpdate,
}

struct Pending {
    senders: HashMap<IdKey, oneshot::Sender<Result<Value, RpcError>>>,
}

struct Inner {
    out_tx: mpsc::Sender<String>,
    pending: Mutex<Pending>,
    next_id: AtomicI64,
    closed: AtomicBool,
    limits: RpcLimits,
    dropped_updates: AtomicU64,
    inbound_bytes: AtomicU64,
    /// Responses that could not be delivered as built (a fallback error was
    /// sent instead, or the connection was closed).
    failed_responses: AtomicU64,
    /// Abort handle of the writer task: dropping the writer closes the
    /// child's stdin, so an undeliverable response can never leave the agent
    /// hanging.
    writer_abort: Mutex<Option<tokio::task::AbortHandle>>,
}

/// Cheap, cloneable client half of a connection.
#[derive(Clone)]
pub struct RpcClient {
    inner: Arc<Inner>,
}

impl RpcClient {
    fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }

    /// True once the transport is closed (EOF, write failure, or shutdown).
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Number of requests awaiting a response.
    pub fn pending_count(&self) -> usize {
        lock_pending(&self.inner.pending).senders.len()
    }

    /// Update events dropped because the consumer fell behind.
    pub fn dropped_updates(&self) -> u64 {
        self.inner.dropped_updates.load(Ordering::Relaxed)
    }

    /// Responses that could not be delivered as built (a fallback error was
    /// sent, or the transport was closed instead of leaving the request
    /// unanswered).
    pub fn failed_responses(&self) -> u64 {
        self.inner.failed_responses.load(Ordering::Relaxed)
    }

    /// Total inbound bytes observed (caps enforcement).
    pub fn inbound_bytes(&self) -> u64 {
        self.inner.inbound_bytes.load(Ordering::Relaxed)
    }

    /// Send a request and await its response, bounded by `timeout`.
    pub async fn request(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, AcpError> {
        if self.is_closed() {
            return Err(AcpError::Disconnected);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let key = IdKey::Num(id);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = lock_pending(&self.inner.pending);
            if pending.senders.len() >= self.inner.limits.max_pending_requests {
                return Err(AcpError::TooManyPending(
                    self.inner.limits.max_pending_requests,
                ));
            }
            pending.senders.insert(key.clone(), tx);
        }
        if let Err(err) = self.send_frame(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })) {
            lock_pending(&self.inner.pending).senders.remove(&key);
            return Err(err);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(value))) => Ok(value),
            Ok(Ok(Err(rpc))) => {
                if self.is_closed() {
                    // The connection failed while we were waiting: the
                    // sentinel error from `fail_all_pending` becomes the
                    // transport error.
                    Err(AcpError::Disconnected)
                } else {
                    Err(AcpError::Rpc {
                        method: method.to_string(),
                        code: rpc.code,
                        message: rpc.message,
                    })
                }
            }
            // The sender side was dropped: the connection failed.
            Ok(Err(_)) => Err(AcpError::Disconnected),
            Err(_) => {
                lock_pending(&self.inner.pending).senders.remove(&key);
                Err(AcpError::Timeout {
                    method: method.to_string(),
                    secs: timeout.as_secs(),
                })
            }
        }
    }

    /// Send a notification (no response expected).
    pub fn notify(&self, method: &str, params: Value) -> Result<(), AcpError> {
        self.send_frame(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
    }

    fn send_frame(&self, frame: &Value) -> Result<(), AcpError> {
        if self.is_closed() {
            return Err(AcpError::Disconnected);
        }
        let mut line = serde_json::to_string(frame)
            .map_err(|err| AcpError::Protocol(format!("serializing a frame: {err}")))?;
        if line.len() > self.inner.limits.max_frame_bytes {
            return Err(AcpError::Protocol(format!(
                "outbound frame of {} bytes exceeds the {} byte cap",
                line.len(),
                self.inner.limits.max_frame_bytes
            )));
        }
        // JSON strings cannot contain a raw newline, but a custom value could
        // still smuggle one through; NDJSON framing requires none.
        if line.contains('\n') || line.contains('\r') {
            return Err(AcpError::Protocol(
                "frame contains an embedded newline".to_string(),
            ));
        }
        line.push('\n');
        self.inner.out_tx.try_send(line).map_err(|_| {
            if self.is_closed() {
                AcpError::Disconnected
            } else {
                AcpError::QueueFull(self.inner.limits.outbound_queue)
            }
        })
    }

    fn respond(&self, id: Value, result: Result<Value, RpcError>) {
        let frame = match result {
            Ok(value) => json!({"jsonrpc": "2.0", "id": id, "result": value}),
            Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error.to_value()}),
        };
        if self.send_frame(&frame).is_ok() {
            return;
        }
        // The response could not be delivered (frame cap, queue full, ...):
        // never leave the agent's request pending. Count the failure, send a
        // minimal error frame, and if even that cannot go out, close the
        // transport so the agent sees EOF instead of hanging.
        self.inner.failed_responses.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            cap = self.inner.limits.max_frame_bytes,
            "acp: could not deliver a response; sending a minimal error"
        );
        let fallback = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code::INTERNAL_ERROR,
                "message": "the response could not be delivered",
            },
        });
        if self.send_frame(&fallback).is_err() {
            self.inner.failed_responses.fetch_add(1, Ordering::Relaxed);
            tracing::error!("acp: closing the connection after an undeliverable response");
            self.inner.closed.store(true, Ordering::SeqCst);
            fail_all_pending(&self.inner);
            // Dropping the writer closes the child's stdin: the agent cannot
            // keep waiting for a reply that will never come.
            if let Some(abort) = lock_writer_abort(&self.inner).take() {
                abort.abort();
            }
        }
    }

    fn respond_parse_error(&self) {
        self.respond(
            Value::Null,
            Err(RpcError::new(code::PARSE_ERROR, "invalid JSON frame")),
        );
    }

    fn respond_frame_too_large(&self) {
        self.respond(
            Value::Null,
            Err(RpcError::new(
                code::INVALID_REQUEST,
                "frame exceeds the line-size cap",
            )),
        );
    }
}

fn lock_pending(pending: &Mutex<Pending>) -> std::sync::MutexGuard<'_, Pending> {
    // A poisoned lock means a panic elsewhere; the map itself is still
    // consistent (every mutation happens under the same lock).
    pending.lock().unwrap_or_else(|err| err.into_inner())
}

fn lock_writer_abort(inner: &Inner) -> std::sync::MutexGuard<'_, Option<tokio::task::AbortHandle>> {
    inner
        .writer_abort
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

fn fail_all_pending(inner: &Inner) {
    let mut pending = lock_pending(&inner.pending);
    for (_, sender) in pending.senders.drain() {
        let _ = sender.send(Err(RpcError::new(
            code::INTERNAL_ERROR,
            "connection closed",
        )));
    }
}

/// One live connection: the [`RpcClient`] plus its tasks and update stream.
pub struct Connection {
    client: RpcClient,
    updates: mpsc::Receiver<UpdateEvent>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Connection {
    /// Start the reader/writer tasks over an established transport.
    pub fn spawn<R, W>(
        reader: R,
        writer: W,
        handler: Arc<dyn RequestHandler>,
        limits: RpcLimits,
    ) -> Self
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (out_tx, out_rx) = mpsc::channel(limits.outbound_queue);
        let (updates_tx, updates) = mpsc::channel(limits.update_queue);
        let inner = Arc::new(Inner {
            out_tx,
            pending: Mutex::new(Pending {
                senders: HashMap::new(),
            }),
            next_id: AtomicI64::new(1),
            closed: AtomicBool::new(false),
            limits,
            dropped_updates: AtomicU64::new(0),
            inbound_bytes: AtomicU64::new(0),
            failed_responses: AtomicU64::new(0),
            writer_abort: Mutex::new(None),
        });
        let client = RpcClient::new(Arc::clone(&inner));
        let writer_task = {
            let inner = Arc::clone(&inner);
            tokio::spawn(writer_loop(writer, out_rx, inner))
        };
        *lock_writer_abort(&inner) = Some(writer_task.abort_handle());
        let reader_task = {
            let inner = Arc::clone(&inner);
            let client = client.clone();
            tokio::spawn(reader_loop(
                BufReader::new(reader),
                updates_tx,
                handler,
                client,
                inner,
            ))
        };
        Self {
            client,
            updates,
            reader: reader_task,
            writer: writer_task,
        }
    }

    /// The client half.
    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    /// Take the next update event (never blocks the transport).
    pub async fn next_update(&mut self) -> Option<UpdateEvent> {
        self.updates.recv().await
    }

    /// Try to take a queued update without waiting.
    pub fn try_update(&mut self) -> Option<UpdateEvent> {
        self.updates.try_recv().ok()
    }

    /// Stop both tasks. Dropping the readers also closes the child's stdio.
    pub fn shutdown(self) {
        self.client.inner.closed.store(true, Ordering::SeqCst);
        fail_all_pending(&self.client.inner);
        self.reader.abort();
        self.writer.abort();
    }
}

async fn writer_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<String>,
    inner: Arc<Inner>,
) {
    while let Some(frame) = rx.recv().await {
        if let Err(err) = writer.write_all(frame.as_bytes()).await {
            tracing::debug!(error = %err, "acp: writing to the agent failed");
            break;
        }
        if let Err(err) = writer.flush().await {
            tracing::debug!(error = %err, "acp: flushing the agent's stdin failed");
            break;
        }
    }
    inner.closed.store(true, Ordering::SeqCst);
    fail_all_pending(&inner);
}

enum Frame {
    Line,
    Eof,
    TooLarge,
    /// The connection's total inbound budget ran out mid-frame; the caller
    /// must close the connection (oversized frames are charged, too).
    OverBudget,
}

/// Bounded line reader: never buffers more than `max` bytes of a line, and
/// discards the remainder of an over-cap line so memory stays bounded.
///
/// Every byte consumed — accumulated, discarded from an oversized line, or
/// discarded to the end of the stream — is charged against `inbound_cap`, so
/// oversized/over-budget output cannot bypass the connection budget.
async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
    scratch: &mut Vec<u8>,
    inbound: &AtomicU64,
    inbound_cap: u64,
) -> std::io::Result<Frame> {
    scratch.clear();
    let charge = |bytes: u64| -> bool {
        let total = inbound.fetch_add(bytes, Ordering::Relaxed) + bytes;
        total > inbound_cap
    };
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(if scratch.is_empty() {
                Frame::Eof
            } else {
                // A final frame without a trailing newline is still a frame.
                Frame::Line
            });
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(position) => {
                if scratch.len().saturating_add(position) > max {
                    reader.consume(position + 1);
                    scratch.clear();
                    return Ok(if charge(position as u64 + 1) {
                        Frame::OverBudget
                    } else {
                        Frame::TooLarge
                    });
                }
                scratch.extend_from_slice(&available[..position]);
                reader.consume(position + 1);
                return Ok(if charge(position as u64 + 1) {
                    Frame::OverBudget
                } else {
                    Frame::Line
                });
            }
            None => {
                if scratch.len().saturating_add(available.len()) > max {
                    // Discard the rest of the oversized line without
                    // allocating for it; the discarded bytes still count.
                    let length = available.len();
                    reader.consume(length);
                    scratch.clear();
                    if charge(length as u64) {
                        return Ok(Frame::OverBudget);
                    }
                    loop {
                        let available = reader.fill_buf().await?;
                        if available.is_empty() {
                            return Ok(Frame::TooLarge);
                        }
                        match available.iter().position(|byte| *byte == b'\n') {
                            Some(position) => {
                                reader.consume(position + 1);
                                return Ok(if charge(position as u64 + 1) {
                                    Frame::OverBudget
                                } else {
                                    Frame::TooLarge
                                });
                            }
                            None => {
                                let length = available.len();
                                reader.consume(length);
                                if charge(length as u64) {
                                    return Ok(Frame::OverBudget);
                                }
                            }
                        }
                    }
                }
                scratch.extend_from_slice(available);
                let length = available.len();
                reader.consume(length);
                if charge(length as u64) {
                    return Ok(Frame::OverBudget);
                }
            }
        }
    }
}

async fn reader_loop<R: AsyncBufRead + Unpin>(
    mut reader: R,
    updates_tx: mpsc::Sender<UpdateEvent>,
    handler: Arc<dyn RequestHandler>,
    client: RpcClient,
    inner: Arc<Inner>,
) {
    let handlers = Arc::new(Semaphore::new(inner.limits.max_handlers));
    let mut scratch = Vec::new();
    loop {
        match read_frame(
            &mut reader,
            inner.limits.max_frame_bytes,
            &mut scratch,
            &inner.inbound_bytes,
            inner.limits.max_total_inbound_bytes,
        )
        .await
        {
            Ok(Frame::Eof) => break,
            Ok(Frame::OverBudget) => {
                tracing::error!(
                    total = inner.inbound_bytes.load(Ordering::Relaxed),
                    cap = inner.limits.max_total_inbound_bytes,
                    "acp: inbound byte cap exceeded; closing the connection"
                );
                break;
            }
            Ok(Frame::TooLarge) => {
                tracing::warn!(
                    cap = inner.limits.max_frame_bytes,
                    "acp: agent sent an oversized frame; dropping it"
                );
                client.respond_frame_too_large();
                continue;
            }
            Ok(Frame::Line) => {
                let bytes = scratch.clone();
                let value: Value = match serde_json::from_slice(&bytes) {
                    Ok(value) => value,
                    Err(_) => {
                        client.respond_parse_error();
                        continue;
                    }
                };
                match protocol::classify(&value) {
                    Incoming::Response { id, result } => {
                        let sender = lock_pending(&inner.pending).senders.remove(&id);
                        match sender {
                            Some(sender) => {
                                let _ = sender.send(result);
                            }
                            None => tracing::debug!(id = %id, "acp: response to an unknown id"),
                        }
                    }
                    Incoming::Request {
                        id_value,
                        method,
                        params,
                        ..
                    } => {
                        let Ok(permit) = Arc::clone(&handlers).try_acquire_owned() else {
                            client.respond(
                                id_value,
                                Err(RpcError::new(
                                    code::INTERNAL_ERROR,
                                    "too many concurrent requests",
                                )),
                            );
                            continue;
                        };
                        let handler = Arc::clone(&handler);
                        let client = client.clone();
                        tokio::spawn(async move {
                            let result = handler.handle(&method, &params).await;
                            client.respond(id_value, result);
                            drop(permit);
                        });
                    }
                    Incoming::Notification { method, params } => {
                        if method == protocol::method::SESSION_UPDATE {
                            let (session_id, update) = protocol::parse_session_update(&params);
                            let event = UpdateEvent { session_id, update };
                            if updates_tx.try_send(event).is_err() {
                                inner.dropped_updates.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            tracing::debug!(method = %method, "acp: ignoring a notification");
                        }
                    }
                    Incoming::Malformed { id, error } => {
                        client.respond(id.unwrap_or(Value::Null), Err(error));
                    }
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, "acp: reading from the agent failed");
                break;
            }
        }
    }
    inner.closed.store(true, Ordering::SeqCst);
    fail_all_pending(&inner);
}

/// A handler for tests and the smoke path that refuses every request.
#[derive(Debug, Default)]
pub struct DenyAllHandler;

#[async_trait]
impl RequestHandler for DenyAllHandler {
    async fn handle(&self, method: &str, _params: &Value) -> Result<Value, RpcError> {
        Err(RpcError::new(
            code::METHOD_NOT_FOUND,
            format!("method `{method}` is not supported by this client"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    struct EchoHandler;

    #[async_trait]
    impl RequestHandler for EchoHandler {
        async fn handle(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
            if method == "client/echo" {
                Ok(params.clone())
            } else {
                Err(RpcError::new(code::METHOD_NOT_FOUND, "unknown method"))
            }
        }
    }

    #[tokio::test]
    async fn routes_responses_and_answers_requests() {
        let (client_read, agent_write) = tokio::io::duplex(64 * 1024);
        let (agent_read, client_write) = tokio::io::duplex(64 * 1024);
        let mut connection = Connection::spawn(
            BufReader::new(client_read),
            client_write,
            Arc::new(EchoHandler),
            RpcLimits::default(),
        );
        let client = connection.client().clone();
        let mut agent_read = BufReader::new(agent_read);
        let agent = tokio::spawn(async move {
            // Answer the client's request.
            let mut line = String::new();
            agent_read.read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let id = request["id"].clone();
            let mut agent_write = agent_write;
            agent_write
                .write_all(
                    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"ok\":true}}}}\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            // Send a request of its own.
            agent_write
                .write_all(
                    b"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"client/echo\",\"params\":{\"x\":1}}\n",
                )
                .await
                .unwrap();
            // And a session/update notification.
            agent_write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"sessionId\":\"s\",\"update\":{\"sessionUpdate\":\"agent_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"hi\"}}}}\n")
                .await
                .unwrap();
            // Read the response to its own request.
            let mut line = String::new();
            agent_read.read_line(&mut line).await.unwrap();
            let response: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(response["id"], 99);
            assert_eq!(response["result"]["x"], 1);
            agent_write
        });
        let response = client
            .request("initialize", json!({}), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response["ok"], true);
        let update = connection.next_update().await.unwrap();
        assert_eq!(
            update.update,
            SessionUpdate::AgentMessageChunk { text: "hi".into() }
        );
        let _agent_write = agent.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_and_oversized_frames_do_not_kill_the_connection() {
        let (client_read, mut agent_write) = tokio::io::duplex(64 * 1024);
        let (agent_read, client_write) = tokio::io::duplex(64 * 1024);
        let connection = Connection::spawn(
            BufReader::new(client_read),
            client_write,
            Arc::new(DenyAllHandler),
            RpcLimits {
                // Small enough to exercise the inbound cap, large enough for
                // the error responses the reader sends back.
                max_frame_bytes: 256,
                ..RpcLimits::default()
            },
        );
        let client = connection.client().clone();
        let mut agent_read = BufReader::new(agent_read);
        let agent = tokio::spawn(async move {
            agent_write.write_all(b"not json at all\n").await.unwrap();
            let oversized = format!(
                "{{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":\"{}\"}}\n",
                "x".repeat(1024)
            );
            agent_write.write_all(oversized.as_bytes()).await.unwrap();
            // The reader must answer both bad frames with JSON-RPC errors.
            // The ping may interleave, so read frames until the errors were
            // seen and the ping was answered.
            let mut errors = 0;
            let mut ping: Option<Value> = None;
            while errors < 2 || ping.is_none() {
                let mut line = String::new();
                agent_read.read_line(&mut line).await.unwrap();
                let value: Value = serde_json::from_str(&line).unwrap();
                if let Some(code) = value.get("error").and_then(|e| e.get("code")) {
                    errors += 1;
                    assert!(
                        code == &json!(code::PARSE_ERROR) || code == &json!(code::INVALID_REQUEST)
                    );
                    continue;
                }
                if value["method"] == "ping" {
                    ping = Some(value);
                    continue;
                }
                panic!("unexpected frame: {value}");
            }
            let ping = ping.expect("the ping request");
            assert_eq!(errors, 2, "both bad frames must have been answered");
            agent_write
                .write_all(
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"pong\":true}}}}\n",
                        ping["id"]
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let pong = client
            .request("ping", json!({}), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(pong["pong"], true);
        agent.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_line_is_discarded_without_allocating_it() {
        let (client_read, agent_write) = tokio::io::duplex(64 * 1024);
        let mut client_read = BufReader::new(client_read);
        // Feed a 4 KiB line into the reader with a 64-byte cap.
        let mut writer = agent_write;
        tokio::spawn(async move {
            writer.write_all(&vec![b'x'; 4096]).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            writer
                .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{}}\n")
                .await
                .unwrap();
            futures_write_close(writer).await;
        });
        let mut scratch = Vec::new();
        let inbound = std::sync::atomic::AtomicU64::new(0);
        let frame = read_frame(&mut client_read, 64, &mut scratch, &inbound, u64::MAX)
            .await
            .unwrap();
        assert!(matches!(frame, Frame::TooLarge));
        let frame = read_frame(&mut client_read, 64, &mut scratch, &inbound, u64::MAX)
            .await
            .unwrap();
        assert!(matches!(frame, Frame::Line));
        assert!(scratch.len() <= 64);
    }

    #[tokio::test]
    async fn oversized_frames_count_toward_the_inbound_cap_and_close_the_connection() {
        let (client_read, mut agent_write) = tokio::io::duplex(64 * 1024);
        let connection = Connection::spawn(
            BufReader::new(client_read),
            tokio::io::sink(),
            Arc::new(DenyAllHandler),
            RpcLimits {
                // Small frame cap, tiny total budget: eight oversized lines
                // are well past the budget.
                max_frame_bytes: 256,
                max_total_inbound_bytes: 1024,
                ..RpcLimits::default()
            },
        );
        let client = connection.client().clone();
        let writer = tokio::spawn(async move {
            for _ in 0..8 {
                let mut line = vec![b'x'; 1024];
                line.extend_from_slice(b"\n");
                if agent_write.write_all(&line).await.is_err() {
                    return;
                }
            }
            // Keep the stream open so the reader cannot claim EOF instead.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut closed = false;
        for _ in 0..200 {
            if client.is_closed() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        writer.abort();
        assert!(
            client.inbound_bytes() >= 1024,
            "oversized frames must be charged to the inbound counter (got {})",
            client.inbound_bytes()
        );
        assert!(
            closed,
            "exceeding the inbound budget on oversized frames must close the connection"
        );
    }

    async fn futures_write_close(mut stream: tokio::io::DuplexStream) {
        let _ = stream.shutdown().await;
    }

    #[test]
    fn limits_have_safe_defaults() {
        let limits = RpcLimits::default();
        assert_eq!(limits.max_frame_bytes, 1024 * 1024);
        assert_eq!(limits.max_pending_requests, 32);
        assert_eq!(limits.max_handlers, 4);
        assert!(limits.update_queue >= 64);
    }

    /// A handler whose result cannot fit the configured outbound cap.
    struct HugeHandler;

    #[async_trait]
    impl RequestHandler for HugeHandler {
        async fn handle(&self, _method: &str, _params: &Value) -> Result<Value, RpcError> {
            Ok(json!({"blob": "x".repeat(64 * 1024)}))
        }
    }

    #[tokio::test]
    async fn an_undeliverable_response_is_answered_with_an_error() {
        let (client_read, agent_write) = tokio::io::duplex(64 * 1024);
        let (agent_read, client_write) = tokio::io::duplex(64 * 1024);
        let connection = Connection::spawn(
            BufReader::new(client_read),
            client_write,
            Arc::new(HugeHandler),
            RpcLimits {
                max_frame_bytes: 1024,
                ..RpcLimits::default()
            },
        );
        let client = connection.client().clone();
        let mut agent_read = BufReader::new(agent_read);
        let mut agent_write = agent_write;
        agent_write
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"x\",\"params\":{}}\n")
            .await
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(3), agent_read.read_line(&mut line))
            .await
            .expect("an undeliverable response must still be answered")
            .unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["error"]["code"], code::INTERNAL_ERROR);
        assert!(
            client.failed_responses() >= 1,
            "the undeliverable response must be counted"
        );
    }
}

#[cfg(test)]
mod proptests {
    //! Property tests for the NDJSON/JSON-RPC parser fed by the agent process.
    //!
    //! The agent is a third party: `read_frame` bounds and buffers its bytes,
    //! then `serde_json` + [`protocol::classify`] turn them into messages.
    //! These tests assert the reader never panics, never buffers past its cap,
    //! never charges more bytes than it consumed, and round-trips valid frames.

    use super::*;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn read_one(bytes: &[u8], max: usize, cap: u64) -> (Frame, Vec<u8>, u64) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a current-thread runtime");
        let mut reader = BufReader::new(std::io::Cursor::new(bytes.to_vec()));
        let mut scratch = Vec::new();
        let inbound = AtomicU64::new(0);
        let frame = runtime
            .block_on(read_frame(&mut reader, max, &mut scratch, &inbound, cap))
            .expect("in-memory reads cannot fail");
        let charged = inbound.load(Ordering::Relaxed);
        (frame, scratch, charged)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Arbitrary bytes under a tiny frame cap and a tiny byte budget: the
        /// reader returns a frame instead of panicking, buffers at most `max`
        /// bytes, and charges at most the bytes it was given.
        #[test]
        fn read_frame_is_bounded_and_never_panics(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096),
            max in 0usize..512,
            cap in 0u64..1024,
        ) {
            let (_frame, scratch, charged) = read_one(&bytes, max, cap);
            prop_assert!(scratch.len() <= max);
            prop_assert!(charged <= bytes.len() as u64);
        }

        /// A line longer than the cap is discarded whole (`TooLarge` with a
        /// generous budget), and nothing past `max` is buffered.
        #[test]
        fn oversized_line_is_discarded(
            length in 1usize..8192,
            max in 0usize..256,
        ) {
            let mut bytes = vec![b'x'; length];
            bytes.push(b'\n');
            let (frame, scratch, charged) = read_one(&bytes, max, u64::MAX);
            if length > max {
                prop_assert!(matches!(frame, Frame::TooLarge));
            }
            prop_assert!(scratch.len() <= max);
            prop_assert!(charged <= bytes.len() as u64);
        }

        /// A valid request frame survives the reader and classifies back to
        /// exactly the request it encoded (round trip).
        #[test]
        fn valid_frames_round_trip(
            id in 0i64..1_000_000,
            method in "[a-z/]{1,32}",
            params in "[a-zA-Z0-9 ]{0,32}",
        ) {
            let request = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{method:?},\
                 \"params\":{{\"text\":{params:?}}}}}\n"
            );
            let (frame, scratch, _charged) = read_one(request.as_bytes(), 4096, u64::MAX);
            prop_assert!(matches!(frame, Frame::Line));
            let value: Value = serde_json::from_slice(&scratch).expect("valid JSON frame");
            match protocol::classify(&value) {
                Incoming::Request {
                    id: parsed_id,
                    method: parsed_method,
                    ..
                } => {
                    prop_assert_eq!(parsed_id, IdKey::Num(id));
                    prop_assert_eq!(parsed_method, method);
                }
                other => prop_assert!(false, "expected a request, got {other:?}"),
            }
        }

        /// Arbitrary bytes that happen to parse as JSON must classify without
        /// panic, and a non-object value is always a clean `Malformed`.
        #[test]
        fn classify_never_panics(raw in proptest::collection::vec(any::<u8>(), 0..4096)) {
            if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
                let incoming = protocol::classify(&value);
                if value.as_object().is_none() {
                    let malformed = matches!(incoming, Incoming::Malformed { .. });
                    prop_assert!(malformed, "a non-object JSON value must be malformed");
                }
            }
        }
    }
}
