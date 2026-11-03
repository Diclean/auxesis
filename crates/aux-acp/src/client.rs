//! The ACP v1 client: handshake, session, prompt streaming, cancellation.
//!
//! One [`AcpClient`] owns one agent process and one JSON-RPC connection. The
//! per-turn prompt loop races three things: the agent's `session/prompt`
//! response, the stream of `session/update` notifications, and the turn's
//! cancellation token. Cancellation sends `session/cancel` (which makes every
//! pending broker handler answer `cancelled`) and then kills the process tree.
//!
//! A0 note: the streaming `message.delta` adapter lands with PR #22; until
//! then the client accumulates `agent_message_chunk` text and the backend
//! emits one final assistant message (`TODO(streaming-1)` in `backend.rs`).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use kernel_broker::Approver;
use kernel_privacy::SafeText;

use crate::config::AcpLimits;
use crate::error::AcpError;
use crate::handlers::{BrokerHandlers, HandlerLimits, TurnState};
use crate::jsonrpc::{Connection, RpcClient};
use crate::protocol::{self, method, PlanEntry, SessionUpdate, ToolCallUpdate, UsageUpdate};
use crate::scrub::{scrub_agent_text, scrub_plan, scrub_tool_call};
use crate::supervisor::{AgentProcess, SupervisorSpec};

/// Client capabilities advertised in `initialize`.
///
/// Only the methods we implement through the broker are advertised; fs and
/// terminal are answered by [`BrokerHandlers`], never by raw host access.
pub fn client_capabilities() -> Value {
    json!({
        "fs": {"readTextFile": true, "writeTextFile": true},
        "terminal": true,
    })
}

/// The protocol version this client speaks.
pub const ACP_PROTOCOL_VERSION: i64 = 1;

/// Handshake / session-creation timeout.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Observer for streamed updates (the engine adapter implements this).
pub trait TurnObserver: Send {
    /// A chunk of the final assistant message.
    fn message_chunk(&mut self, _chunk: &str) {}
    /// A chunk of internal reasoning (never part of the final answer).
    fn thought_chunk(&mut self, _chunk: &str) {}
    /// A tool call was created or updated.
    fn tool_call(&mut self, _call: &ToolCallUpdate) {}
    /// The agent published a plan.
    fn plan(&mut self, _entries: &[PlanEntry]) {}
    /// Best-effort usage numbers.
    fn usage(&mut self, _usage: &UsageUpdate) {}
}

/// A [`TurnObserver`] that discards everything.
#[derive(Debug, Default)]
pub struct NullObserver;

impl TurnObserver for NullObserver {}

/// Counters for one prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TurnStats {
    /// `agent_message_chunk` notifications.
    pub chunks: u64,
    /// `agent_thought_chunk` notifications.
    pub thoughts: u64,
    /// `tool_call`/`tool_call_update` notifications.
    pub tool_calls: u64,
    /// `plan` notifications.
    pub plans: u64,
    /// Unrecognized update kinds.
    pub unknown: u64,
    /// Updates dropped because the queue was full.
    pub dropped: u64,
    /// True when the output cap clipped the answer.
    pub truncated: bool,
    /// Output bytes accumulated.
    pub output_bytes: u64,
}

/// The result of one `session/prompt`.
#[derive(Debug, Clone, PartialEq)]
pub struct PromptOutcome {
    /// Accumulated assistant text (capped).
    pub text: String,
    /// The agent's `stopReason`.
    pub stop_reason: Option<String>,
    /// Best-effort usage from `usage_update`.
    pub usage: UsageUpdate,
    /// Stream counters.
    pub stats: TurnStats,
}

/// One live ACP agent connection.
pub struct AcpClient {
    connection: Option<Connection>,
    process: AgentProcess,
    state: Arc<TurnState>,
    session_id: String,
    output_cap: usize,
    turn_timeout: Duration,
}

impl AcpClient {
    /// Spawn the agent and complete the handshake + `session/new`.
    pub async fn start(
        spec: &SupervisorSpec,
        agent: &str,
        limits: &AcpLimits,
        approver: Arc<dyn Approver>,
        handler_limits: HandlerLimits,
        state: Arc<TurnState>,
        read_only: bool,
    ) -> Result<Self, AcpError> {
        let workspace = spec.workspace.clone();
        let mut process = AgentProcess::spawn(spec).await?;
        let (stdin, stdout) = process.take_stdio()?;
        let handlers = Arc::new(
            BrokerHandlers::new(
                spec.host_workspace
                    .clone()
                    .unwrap_or_else(|| workspace.clone()),
                agent.to_string(),
                approver,
                Arc::clone(&state),
                handler_limits,
            )?
            .with_read_only(read_only),
        );
        let connection = Connection::spawn(
            tokio::io::BufReader::new(stdout),
            stdin,
            handlers,
            limits.rpc,
        );
        let client = connection.client().clone();

        // initialize
        let init = setup_request(
            &client,
            &process,
            method::INITIALIZE,
            json!({
                "protocolVersion": ACP_PROTOCOL_VERSION,
                "clientCapabilities": client_capabilities(),
            }),
        )
        .await?;
        match init.get("protocolVersion").and_then(Value::as_i64) {
            Some(1) => {}
            Some(other) => {
                return Err(AcpError::Protocol(format!(
                    "agent speaks protocolVersion {other}; this client only supports v1"
                )));
            }
            None => {
                return Err(AcpError::Protocol(
                    "the initialize response has no protocolVersion".to_string(),
                ));
            }
        }
        if let Some(methods) = init.get("authMethods").and_then(Value::as_array) {
            if !methods.is_empty() {
                // CLI-login agents authenticate inside their own process; we
                // never call `authenticate` with credentials.
                tracing::debug!(
                    count = methods.len(),
                    "acp: agent advertises auth methods; CLI login is used as-is"
                );
            }
        }

        // session/new
        let cwd = workspace
            .canonicalize()
            .map_err(|err| AcpError::Sandbox(err.to_string()))?;
        let new_session = setup_request(
            &client,
            &process,
            method::SESSION_NEW,
            json!({
                "cwd": cwd.display().to_string(),
                "mcpServers": [],
            }),
        )
        .await?;
        let session_id = new_session
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| AcpError::Protocol("session/new returned no sessionId".to_string()))?
            .to_string();

        Ok(Self {
            connection: Some(connection),
            process,
            state,
            session_id,
            output_cap: limits.max_output_bytes,
            turn_timeout: limits.turn_timeout,
        })
    }

    /// The agent session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The agent process id (also its process-group id).
    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    /// The shared turn state (taint/cancel flags).
    pub fn state(&self) -> &Arc<TurnState> {
        &self.state
    }

    /// The scrubbed stderr snapshot.
    pub fn stderr_lines(&self) -> Vec<String> {
        self.process.stderr_lines()
    }

    /// Send one prompt and pump updates until the stop reason.
    ///
    /// The prompt is a [`SafeText`]: the agent only ever receives text a privacy
    /// gate issued, never a raw string.
    ///
    /// Never blocks past `turn_timeout` plus reply slack: the caller's outer
    /// wall-clock cap wins, and on cancellation this sends `session/cancel`
    /// and returns [`AcpError::Cancelled`] (the caller shuts the process
    /// down).
    pub async fn prompt(
        &mut self,
        text: &SafeText,
        cancel: Option<Arc<kernel_broker::CancelToken>>,
        observer: &mut dyn TurnObserver,
    ) -> Result<PromptOutcome, AcpError> {
        if self.state.is_cancelled() {
            return Err(AcpError::Cancelled);
        }
        let rpc = self.client()?;
        let state = Arc::clone(&self.state);
        let session_id = self.session_id.clone();
        let output_cap = self.output_cap;
        let request_timeout = self.turn_timeout.saturating_add(Duration::from_secs(30));
        let prompt = rpc.request(
            method::SESSION_PROMPT,
            json!({
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": text.as_str()}],
            }),
            request_timeout,
        );
        tokio::pin!(prompt);

        let mut prompt_state = PromptState::new();
        let result = loop {
            tokio::select! {
                biased;
                _ = wait_cancelled(&cancel, &state) => {
                    // The agent must learn the turn is over and every pending
                    // broker handler must answer `cancelled`.
                    state.cancel();
                    let _ = rpc.notify(
                        method::SESSION_CANCEL,
                        json!({"sessionId": session_id}),
                    );
                    // P2-1: a final burst that raced the cancel is still
                    // observed before the turn is reported over.
                    self.drain_queued_updates(&state, &mut prompt_state, output_cap, observer);
                    return Err(AcpError::Cancelled);
                }
                response = &mut prompt => break response,
                update = next_update(&mut self.connection) => {
                    match update {
                        Some(event) => {
                            apply_update(&state, &mut prompt_state, output_cap, event, observer)
                        }
                        // The transport is gone (agent crash): surface it,
                        // after observing whatever was already queued.
                        None => {
                            self.drain_queued_updates(&state, &mut prompt_state, output_cap, observer);
                            return Err(AcpError::Disconnected);
                        }
                    }
                }
            }
        };
        let response = result?;
        // A fast agent writes the last chunks and the prompt response
        // back-to-back; `biased` select can win with the response while
        // updates are still queued, so drain the queue before finishing.
        if let Some(connection) = self.connection.as_mut() {
            while let Some(event) = connection.try_update() {
                apply_update(&state, &mut prompt_state, output_cap, event, observer);
            }
        }
        prompt_state.finish(observer);
        let mut outcome = prompt_state.outcome;
        outcome.stop_reason = protocol::stop_reason(&response);
        outcome.stats.dropped = rpc.dropped_updates();
        if outcome.stop_reason.as_deref() == Some("cancelled") {
            // The agent acknowledged the cancel; the caller still needs the
            // tree swept.
            return Err(AcpError::Cancelled);
        }
        Ok(outcome)
    }

    /// Send `session/cancel` and mark the turn cancelled so pending handlers
    /// answer `cancelled`.
    pub async fn cancel(&mut self) {
        self.state.cancel();
        if let Some(connection) = &self.connection {
            let _ = connection.client().notify(
                method::SESSION_CANCEL,
                json!({"sessionId": self.session_id}),
            );
        }
    }

    /// Shut the connection down and reap the process tree.
    pub async fn shutdown(&mut self) {
        self.state.cancel();
        if let Some(connection) = self.connection.take() {
            connection.shutdown();
        }
        self.process.shutdown().await;
    }

    /// True when the agent process is still alive.
    pub fn is_running(&mut self) -> bool {
        self.process.is_running()
    }

    fn client(&self) -> Result<RpcClient, AcpError> {
        self.connection
            .as_ref()
            .map(|connection| connection.client().clone())
            .ok_or(AcpError::Disconnected)
    }

    /// Apply every update the reader already queued, before an early return
    /// (cancel or disconnect), so a final burst racing the end is observed.
    fn drain_queued_updates(
        &mut self,
        state: &TurnState,
        prompt_state: &mut PromptState,
        output_cap: usize,
        observer: &mut dyn TurnObserver,
    ) {
        if let Some(connection) = self.connection.as_mut() {
            while let Some(event) = connection.try_update() {
                apply_update(state, prompt_state, output_cap, event, observer);
            }
        }
    }
}

/// One handshake request. On failure, attach the **scrubbed** stderr tail
/// (already redacted by the supervisor) so a setup failure is diagnosable
/// without retrying a live turn.
async fn setup_request(
    client: &RpcClient,
    process: &AgentProcess,
    method_name: &str,
    params: Value,
) -> Result<Value, AcpError> {
    match client.request(method_name, params, SETUP_TIMEOUT).await {
        Ok(value) => Ok(value),
        Err(err) => {
            // Give the stderr reader a beat to drain what the agent wrote
            // before exiting.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let stderr = process.stderr_lines().join(" | ");
            Err(AcpError::Protocol(format!(
                "{method_name} failed: {err}{}",
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!("; agent stderr: {stderr}")
                }
            )))
        }
    }
}

/// A streaming scrubber over one text stream, mirroring the daemon's
/// `deltas::DeltaStream::emit_live` state machine: keep the whole
/// accumulated raw text, publish only the prefix outside the fixed trailing
/// window, and on a registry divergence re-anchor at the raw offset the
/// **published** output accounts for and keep publishing the scrub of the
/// remaining suffix. The streamed output is therefore
/// `published prefix ++ scrub(raw[published_raw..])`: no drop, no duplicate,
/// and — while the registry is stable — the final flush equals the
/// whole-buffer scrub.
struct StreamScrubber {
    /// Every raw byte received (never trimmed).
    raw: String,
    /// The output published so far; `emitted[..anchor_out]` is frozen.
    emitted: String,
    /// Raw offset the published output accounts for.
    emitted_raw: usize,
    /// Raw offset at which the live segment begins (moves on re-anchor).
    live_start_raw: usize,
    /// Output offset in `emitted` at which the live segment begins.
    anchor_out: usize,
    /// After a stalled attempt, try again once the buffer reaches this length.
    retry_at: Option<usize>,
    /// The saturation placeholder was already published.
    masked_whole: bool,
    /// Registry pin epoch, so LRU eviction cannot un-register a value this
    /// live stream still relies on.
    pin: Option<u64>,
}

/// Smallest amount of new text between two whole-buffer scrub attempts.
const MIN_ATTEMPT_STEP: usize = 4 * 1024;
/// Largest attempt step (mirrors the daemon's delta stream).
const MAX_ATTEMPT_STEP: usize = 64 * 1024;
/// How many times a drain moves the cut back before stalling.
const MAX_BACKOFF_ATTEMPTS: usize = 6;
/// The visible placeholder published when the known-secret registry cannot
/// prove every spelling covered (fail closed).
const SATURATED_PLACEHOLDER: &str = "<redacted>";

fn attempt_step(n: usize) -> usize {
    (n / 16).clamp(MIN_ATTEMPT_STEP, MAX_ATTEMPT_STEP)
}

/// True for the token bytes the scrubber treats as one opaque run.
fn is_run_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+')
}

/// If `cut` splits a run, move it to the run's first byte: a token, a vendor
/// key or a JWT is only recognisable whole (or from its own start), so no
/// stream boundary may fall inside one.
fn run_start(text: &str, cut: usize) -> usize {
    if cut == 0 || cut >= text.len() {
        return cut;
    }
    let bytes = text.as_bytes();
    if !is_run_byte(bytes[cut - 1]) || !is_run_byte(bytes[cut]) {
        return cut;
    }
    let mut start = cut;
    while start > 0 && is_run_byte(bytes[start - 1]) {
        start -= 1;
    }
    start
}

/// Floor `at` onto a UTF-8 char boundary of `text`.
fn floor_char_boundary(text: &str, at: usize) -> usize {
    let bytes = text.as_bytes();
    let mut at = at.min(bytes.len());
    while at > 0 && at < bytes.len() && (bytes[at] & 0xC0) == 0x80 {
        at -= 1;
    }
    at
}

/// Length of the common byte prefix of two slices.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .take_while(|(left, right)| left == right)
        .count()
}

impl StreamScrubber {
    fn new() -> Self {
        Self {
            raw: String::new(),
            emitted: String::new(),
            emitted_raw: 0,
            live_start_raw: 0,
            anchor_out: 0,
            retry_at: None,
            masked_whole: false,
            pin: Some(kernel_broker::scrub::pin_known_secrets()),
        }
    }

    /// Append `text`; return the newly published scrubbed output (empty while
    /// the trailing window still covers it).
    fn push(&mut self, text: &str) -> String {
        self.raw.push_str(text);
        let mut out = String::new();
        self.emit(false, &mut out);
        out
    }

    /// Flush everything pending (the whole-buffer remainder).
    fn finish(&mut self) -> String {
        let mut out = String::new();
        self.emit(true, &mut out);
        out
    }

    /// Mirror of `deltas::DeltaStream::emit_live` (minus the event sink).
    fn emit(&mut self, finish: bool, out: &mut String) {
        if self.raw.is_empty() {
            return;
        }
        if kernel_broker::scrub::registry_saturated() || kernel_broker::scrub::registry_oversized()
        {
            if !self.masked_whole {
                self.masked_whole = true;
                out.push_str(SATURATED_PLACEHOLDER);
                self.emitted.push_str(SATURATED_PLACEHOLDER);
                tracing::warn!(
                    "known-secret registry cannot cover every spelling; the ACP stream failed closed with a placeholder"
                );
            }
            self.emitted_raw = self.raw.len();
            return;
        }
        if let Some(retry_at) = self.retry_at {
            if !finish && self.raw.len() < retry_at {
                return;
            }
        }
        let window = kernel_broker::scrub::streaming_hold_bytes();
        let n = self.raw.len();
        if !finish && n.saturating_sub(self.emitted_raw) < window.saturating_add(attempt_step(n)) {
            return;
        }
        let mut attempts = 0usize;
        let mut reanchors = 0usize;
        loop {
            let context = window.min(self.live_start_raw);
            let seg_start = self.live_start_raw - context;
            let live_len = self.emitted.len() - self.anchor_out;
            let (seg_scrub, compare_from) = {
                let seg = &self.raw[seg_start..];
                let seg_scrub = scrub_agent_text(seg);
                let head = if context == 0 {
                    String::new()
                } else {
                    scrub_agent_text(&seg[..context])
                };
                let compare_from = if seg_scrub.starts_with(head.as_str()) {
                    head.len()
                } else {
                    common_prefix_len(seg_scrub.as_bytes(), head.as_bytes())
                };
                (seg_scrub, compare_from)
            };
            if !seg_scrub[compare_from..].starts_with(&self.emitted[self.anchor_out..]) {
                // A registry write changed the verdict of an already
                // published region. Re-anchor at the raw offset the published
                // output accounts for and continue with the scrub of the
                // remaining raw suffix; nothing is dropped or duplicated.
                self.live_start_raw = self.emitted_raw;
                self.anchor_out = self.emitted.len();
                reanchors += 1;
                if reanchors > 4 {
                    return;
                }
                continue;
            }
            if finish {
                let from = compare_from + live_len;
                if seg_scrub.len() > from {
                    out.push_str(&seg_scrub[from..]);
                    self.emitted.push_str(&seg_scrub[from..]);
                }
                self.emitted_raw = self.raw.len();
                return;
            }
            let seg = &self.raw[seg_start..];
            let mut cut = run_start(
                seg,
                floor_char_boundary(seg, seg.len().saturating_sub(window)),
            );
            if cut <= context || seg_start + cut <= self.emitted_raw {
                self.stall();
                return;
            }
            if seg_scrub == seg {
                // Identity scrub: the raw cut maps 1:1.
                let from = compare_from + live_len;
                if cut > from {
                    out.push_str(&seg[from..cut]);
                    self.emitted.push_str(&seg[from..cut]);
                }
                self.emitted_raw = seg_start + cut;
                self.retry_at = None;
                return;
            }
            loop {
                let prefix = scrub_agent_text(&self.raw[seg_start..seg_start + cut]);
                if seg_scrub.starts_with(prefix.as_str()) {
                    // Every mask in the prefix is complete: publish it.
                    let from = compare_from + live_len;
                    if prefix.len() > from {
                        out.push_str(&seg_scrub[from..prefix.len()]);
                        self.emitted.push_str(&seg_scrub[from..prefix.len()]);
                    }
                    self.emitted_raw = seg_start + cut;
                    self.retry_at = None;
                    return;
                }
                // A mask straddles the cut: move it back before that region.
                let divergence = common_prefix_len(seg_scrub.as_bytes(), prefix.as_bytes());
                let back = prefix.len().saturating_sub(divergence).max(1);
                let next = run_start(seg, floor_char_boundary(seg, cut.saturating_sub(back)));
                attempts += 1;
                if next >= cut || next <= context || attempts >= MAX_BACKOFF_ATTEMPTS {
                    self.stall();
                    return;
                }
                cut = next;
            }
        }
    }

    /// Try again only after enough new text: a stalled construct must not
    /// cause a scrub per push.
    fn stall(&mut self) {
        let pending = self.raw.len().saturating_sub(self.emitted_raw);
        let step = attempt_step(self.raw.len()).max(pending / 4);
        self.retry_at = Some(self.raw.len().saturating_add(step));
    }
}

impl Drop for StreamScrubber {
    fn drop(&mut self) {
        if let Some(epoch) = self.pin.take() {
            kernel_broker::scrub::unpin_known_secrets(epoch);
        }
    }
}

/// Per-prompt state: the outcome plus the streaming scrubbers and the
/// one-frame delay used to catch secrets split across tool/plan frames.
struct PromptState {
    outcome: PromptOutcome,
    /// Raw accumulated message text; scrubbed and tagged once at the end.
    raw_text: String,
    message: StreamScrubber,
    thought: StreamScrubber,
    first_message_chunk: bool,
    /// Last tool/plan frame, held until the next one arrives (or the end) so
    /// a secret spanning the boundary can be detected and redacted.
    pending_tool: Option<ToolCallUpdate>,
    pending_plan: Option<Vec<PlanEntry>>,
}

impl PromptState {
    fn new() -> Self {
        Self {
            outcome: PromptOutcome {
                text: String::new(),
                stop_reason: None,
                usage: UsageUpdate::default(),
                stats: TurnStats::default(),
            },
            raw_text: String::new(),
            message: StreamScrubber::new(),
            thought: StreamScrubber::new(),
            first_message_chunk: true,
            pending_tool: None,
            pending_plan: None,
        }
    }

    /// Flush every held-back scrubber/frame to the observer, then finalise
    /// the accumulated answer (scrubbed and tagged).
    fn finish(&mut self, observer: &mut dyn TurnObserver) {
        let tail = self.message.finish();
        if !tail.is_empty() {
            if self.first_message_chunk {
                observer.message_chunk(&format!("{}\n{tail}", crate::ACP_UNTRUSTED_TAG));
                self.first_message_chunk = false;
            } else {
                observer.message_chunk(&tail);
            }
        }
        let thought_tail = self.thought.finish();
        if !thought_tail.is_empty() {
            observer.thought_chunk(&thought_tail);
        }
        if let Some(tool) = self.pending_tool.take() {
            observer.tool_call(&tool);
        }
        if let Some(plan) = self.pending_plan.take() {
            observer.plan(&plan);
        }
        // Scrub the **concatenated** raw text: per-chunk scrubbing cannot see
        // a known secret split across two chunks.
        self.outcome.text = crate::scrub::tagged_agent_text(&scrub_agent_text(&self.raw_text));
        self.outcome.stats.output_bytes = self.outcome.text.len() as u64;
    }
}

/// One tool frame's agent-controlled text, joined for cross-frame split
/// detection. JSON strings contribute their raw content (no quotes), so a
/// secret split across frames reconstructs exactly.
fn tool_frame_text(call: &ToolCallUpdate) -> String {
    fn value_text(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        }
    }
    let mut parts = Vec::new();
    if let Some(title) = &call.title {
        parts.push(title.clone());
    }
    if let Some(value) = &call.raw_input {
        parts.push(value_text(value));
    }
    if let Some(value) = &call.raw_output {
        parts.push(value_text(value));
    }
    for value in &call.content {
        parts.push(value_text(value));
    }
    for value in &call.locations {
        parts.push(value_text(value));
    }
    parts.join("\n")
}

fn redact_tool_call(call: &mut ToolCallUpdate) {
    call.title = Some("<redacted>".to_string());
    call.raw_input = call
        .raw_input
        .as_ref()
        .map(|_| serde_json::json!("<redacted>"));
    call.raw_output = call
        .raw_output
        .as_ref()
        .map(|_| serde_json::json!("<redacted>"));
    call.content = if call.content.is_empty() {
        Vec::new()
    } else {
        vec![serde_json::json!("<redacted>")]
    };
    call.locations = Vec::new();
}

fn plan_frame_text(entries: &[PlanEntry]) -> String {
    entries
        .iter()
        .map(|entry| entry.content.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_plan(entries: &mut [PlanEntry]) {
    for entry in entries {
        entry.content = "<redacted>".to_string();
    }
}

/// Forward one tool update, holding the previous one back: if the two
/// individually-clean frames only become a secret when concatenated, both are
/// over-redacted instead of leaking half each.
fn forward_tool_frame(
    state: &mut PromptState,
    call: ToolCallUpdate,
    observer: &mut dyn TurnObserver,
) {
    let Some(mut prev) = state.pending_tool.take() else {
        state.pending_tool = Some(call);
        return;
    };
    let prev_text = tool_frame_text(&prev);
    let next_text = tool_frame_text(&call);
    let combined = format!("{prev_text}\n{next_text}");
    let split_secret = scrub_agent_text(&prev_text) == prev_text
        && scrub_agent_text(&next_text) == next_text
        && scrub_agent_text(&combined) != combined;
    if split_secret {
        let mut call = call;
        redact_tool_call(&mut prev);
        redact_tool_call(&mut call);
        observer.tool_call(&prev);
        observer.tool_call(&call);
    } else {
        observer.tool_call(&prev);
        state.pending_tool = Some(call);
    }
}

/// Plan frames get the same one-frame split detection.
fn forward_plan_frame(
    state: &mut PromptState,
    entries: Vec<PlanEntry>,
    observer: &mut dyn TurnObserver,
) {
    let Some(mut prev) = state.pending_plan.take() else {
        state.pending_plan = Some(entries);
        return;
    };
    let prev_text = plan_frame_text(&prev);
    let next_text = plan_frame_text(&entries);
    let combined = format!("{prev_text}\n{next_text}");
    let split_secret = scrub_agent_text(&prev_text) == prev_text
        && scrub_agent_text(&next_text) == next_text
        && scrub_agent_text(&combined) != combined;
    if split_secret {
        let mut entries = entries;
        redact_plan(&mut prev);
        redact_plan(&mut entries);
        observer.plan(&prev);
        observer.plan(&entries);
    } else {
        observer.plan(&prev);
        state.pending_plan = Some(entries);
    }
}

/// Fold one update into the turn's accumulated output and counters.
fn apply_update(
    turn_state: &TurnState,
    state: &mut PromptState,
    output_cap: usize,
    event: crate::jsonrpc::UpdateEvent,
    observer: &mut dyn TurnObserver,
) {
    match event.update {
        SessionUpdate::AgentMessageChunk { text } => {
            turn_state.mark_tainted();
            state.outcome.stats.chunks += 1;
            let outcome = &mut state.outcome;
            if !outcome.stats.truncated {
                let room = output_cap.saturating_sub(state.raw_text.len());
                if text.len() <= room {
                    state.raw_text.push_str(&text);
                } else {
                    let mut end = room;
                    while end > 0 && !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    state.raw_text.push_str(&text[..end]);
                    outcome.stats.truncated = true;
                }
                outcome.stats.output_bytes = state.raw_text.len() as u64;
            }
            let emit = state.message.push(&text);
            if !emit.is_empty() {
                if state.first_message_chunk {
                    observer.message_chunk(&format!("{}\n{emit}", crate::ACP_UNTRUSTED_TAG));
                    state.first_message_chunk = false;
                } else {
                    observer.message_chunk(&emit);
                }
            }
        }
        SessionUpdate::AgentThoughtChunk { text } => {
            turn_state.mark_tainted();
            state.outcome.stats.thoughts += 1;
            let emit = state.thought.push(&text);
            if !emit.is_empty() {
                observer.thought_chunk(&emit);
            }
        }
        SessionUpdate::UserMessageChunk { .. } => {}
        SessionUpdate::ToolCall { mut tool_call }
        | SessionUpdate::ToolCallUpdate { mut tool_call } => {
            turn_state.mark_tainted();
            scrub_tool_call(&mut tool_call);
            state.outcome.stats.tool_calls += 1;
            forward_tool_frame(state, tool_call, observer);
        }
        SessionUpdate::Plan { mut entries } => {
            turn_state.mark_tainted();
            scrub_plan(&mut entries);
            state.outcome.stats.plans += 1;
            forward_plan_frame(state, entries, observer);
        }
        SessionUpdate::UsageUpdate { usage } => {
            state.outcome.usage = usage.clone();
            observer.usage(&usage);
        }
        SessionUpdate::Other { kind } => {
            tracing::debug!(kind = %kind, "acp: session update");
        }
        SessionUpdate::Unknown { kind } => {
            state.outcome.stats.unknown += 1;
            tracing::debug!(kind = %kind, "acp: unknown session update kind");
        }
    }
}

impl Drop for AcpClient {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.shutdown();
        }
        self.process.kill_now();
    }
}

async fn next_update(connection: &mut Option<Connection>) -> Option<crate::jsonrpc::UpdateEvent> {
    match connection {
        Some(connection) => connection.next_update().await,
        None => None,
    }
}

/// Resolve when the caller's token fires or the shared turn state is
/// cancelled; never, when neither can fire.
async fn wait_cancelled(token: &Option<Arc<kernel_broker::CancelToken>>, state: &TurnState) {
    match token {
        Some(token) => {
            tokio::select! {
                biased;
                _ = token.cancelled() => {}
                _ = state.wait_cancelled() => {}
            }
        }
        None => state.wait_cancelled().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_advertise_only_the_broker_methods() {
        let capabilities = client_capabilities();
        assert_eq!(capabilities["fs"]["readTextFile"], true);
        assert_eq!(capabilities["fs"]["writeTextFile"], true);
        assert_eq!(capabilities["terminal"], true);
    }

    #[derive(Default)]
    struct RecordingObserver {
        chunks: Vec<String>,
        thoughts: Vec<String>,
        tools: Vec<ToolCallUpdate>,
        plans: Vec<Vec<PlanEntry>>,
    }

    impl TurnObserver for RecordingObserver {
        fn message_chunk(&mut self, chunk: &str) {
            self.chunks.push(chunk.to_string());
        }

        fn thought_chunk(&mut self, chunk: &str) {
            self.thoughts.push(chunk.to_string());
        }

        fn tool_call(&mut self, call: &ToolCallUpdate) {
            self.tools.push(call.clone());
        }

        fn plan(&mut self, entries: &[PlanEntry]) {
            self.plans.push(entries.to_vec());
        }
    }

    const SPLIT_CANARY: &str = "CANARY_ACP_STREAM_0123456789abcdef";

    #[test]
    fn stream_scrubber_holds_back_a_split_known_secret() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret(SPLIT_CANARY);
        let mut scrubber = StreamScrubber::new();
        let first = scrubber.push("CANARY_ACP_STREAM_0123");
        assert!(
            first.is_empty(),
            "a secret prefix must be held back: {first}"
        );
        let second = scrubber.push("456789abcdef");
        let tail = scrubber.finish();
        kernel_broker::scrub::clear_known_secrets();
        let joined = format!("{first}{second}{tail}");
        assert!(!joined.contains(SPLIT_CANARY), "{joined}");
        assert!(joined.contains("<redacted>"), "{joined}");
    }

    #[test]
    fn split_secret_across_tool_frames_is_redacted() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret(SPLIT_CANARY);
        let mut state = PromptState::new();
        let mut observer = RecordingObserver::default();
        let mut first = ToolCallUpdate {
            id: "t1".to_string(),
            title: Some("split".to_string()),
            raw_output: Some(serde_json::json!("CANARY_ACP_STREAM_0123")),
            ..ToolCallUpdate::default()
        };
        let mut second = ToolCallUpdate {
            id: "t1".to_string(),
            raw_output: Some(serde_json::json!("456789abcdef")),
            ..ToolCallUpdate::default()
        };
        scrub_tool_call(&mut first);
        scrub_tool_call(&mut second);
        forward_tool_frame(&mut state, first, &mut observer);
        forward_tool_frame(&mut state, second, &mut observer);
        state.finish(&mut observer);
        kernel_broker::scrub::clear_known_secrets();
        assert_eq!(observer.tools.len(), 2);
        let joined = observer
            .tools
            .iter()
            .map(|call| format!("{call:?}"))
            .collect::<String>();
        assert!(!joined.contains(SPLIT_CANARY), "{joined}");
        assert!(joined.contains("<redacted>"), "{joined}");
    }

    #[test]
    fn split_secret_across_plan_frames_is_redacted() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret(SPLIT_CANARY);
        let mut state = PromptState::new();
        let mut observer = RecordingObserver::default();
        let mut first = vec![PlanEntry {
            content: "CANARY_ACP_STREAM_0123".to_string(),
            priority: None,
            status: None,
        }];
        let mut second = vec![PlanEntry {
            content: "456789abcdef".to_string(),
            priority: None,
            status: None,
        }];
        scrub_plan(&mut first);
        scrub_plan(&mut second);
        forward_plan_frame(&mut state, first, &mut observer);
        forward_plan_frame(&mut state, second, &mut observer);
        state.finish(&mut observer);
        kernel_broker::scrub::clear_known_secrets();
        let joined = observer
            .plans
            .iter()
            .flat_map(|entries| entries.iter().map(|entry| entry.content.clone()))
            .collect::<String>();
        assert!(!joined.contains(SPLIT_CANARY), "{joined}");
        assert!(joined.contains("<redacted>"), "{joined}");
    }

    #[test]
    fn clean_tool_frames_forward_unchanged() {
        let mut state = PromptState::new();
        let mut observer = RecordingObserver::default();
        let first = ToolCallUpdate {
            id: "t1".to_string(),
            title: Some("build".to_string()),
            ..ToolCallUpdate::default()
        };
        let second = ToolCallUpdate {
            id: "t1".to_string(),
            status: Some("completed".to_string()),
            ..ToolCallUpdate::default()
        };
        forward_tool_frame(&mut state, first, &mut observer);
        forward_tool_frame(&mut state, second, &mut observer);
        state.finish(&mut observer);
        assert_eq!(observer.tools.len(), 2);
        assert_eq!(observer.tools[0].title.as_deref(), Some("build"));
        assert_eq!(observer.tools[1].status.as_deref(), Some("completed"));
    }

    #[test]
    fn final_text_scrubs_a_secret_split_across_chunks() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret(SPLIT_CANARY);
        let mut state = PromptState::new();
        let mut observer = RecordingObserver::default();
        let turn_state = TurnState::default();
        for text in ["CANARY_ACP_STREAM_0123", "456789abcdef"] {
            apply_update(
                &turn_state,
                &mut state,
                256 * 1024,
                crate::jsonrpc::UpdateEvent {
                    session_id: None,
                    update: SessionUpdate::AgentMessageChunk {
                        text: text.to_string(),
                    },
                },
                &mut observer,
            );
        }
        state.finish(&mut observer);
        kernel_broker::scrub::clear_known_secrets();
        assert!(
            !state.outcome.text.contains(SPLIT_CANARY),
            "{}",
            state.outcome.text
        );
        assert!(state.outcome.text.contains("<redacted>"));
        assert!(turn_state.is_tainted());
    }

    /// The streaming port contract (WF-1): for every split of the registered
    /// canary — raw, hex, percent-encoded and zero-width-interleaved — the
    /// concatenation of the emitted prefixes and the final flush is exactly
    /// the whole-buffer scrub of the accumulated text.
    #[test]
    fn streamed_prefix_plus_finish_equals_the_whole_buffer_scrub() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret(SPLIT_CANARY);
        let filler = "The quick brown fox jumps over the lazy dog. ".repeat(24);
        let hex: String = SPLIT_CANARY
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let percent: String = SPLIT_CANARY
            .bytes()
            .map(|byte| format!("%{byte:02X}"))
            .collect();
        let zero_width: String = SPLIT_CANARY
            .chars()
            .flat_map(|ch| [ch, '\u{200b}'])
            .collect();
        for (label, spelling) in [
            ("raw", SPLIT_CANARY.to_string()),
            ("hex", hex),
            ("percent", percent),
            ("zero-width", zero_width),
        ] {
            for split in 1..spelling.len() {
                if !spelling.is_char_boundary(split) {
                    continue;
                }
                let mut scrubber = StreamScrubber::new();
                let mut out = String::new();
                out.push_str(&scrubber.push(&filler));
                out.push_str(&scrubber.push(&spelling[..split]));
                out.push_str(&scrubber.push(&spelling[split..]));
                out.push_str(&scrubber.push(&filler));
                out.push_str(&scrubber.finish());
                let raw = format!("{filler}{spelling}{filler}");
                let whole = scrub_agent_text(&raw);
                assert_eq!(
                    out, whole,
                    "{label} split {split}: the stream is not the whole-buffer scrub"
                );
                assert!(
                    !out.contains(SPLIT_CANARY),
                    "{label} split {split}: the canary leaked: {out}"
                );
            }
        }
        kernel_broker::scrub::clear_known_secrets();
    }

    /// GLM round-5 F-1 regression: a key registered mid-stream diverges the
    /// already-published band; the stream must re-anchor at the raw offset
    /// the **published** output accounts for and keep publishing the suffix
    /// scrub — `published ++ scrub(raw[published_raw..])`, no drop and no
    /// duplication.
    #[test]
    fn late_registration_reanchors_without_drop_or_duplication() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        let mut scrubber = StreamScrubber::new();
        let filler = "The quick brown fox jumps over the lazy dog. ".repeat(400);
        let mut published = scrubber.push(&filler);
        published.push_str(&scrubber.push(SPLIT_CANARY));
        published.push_str(&scrubber.push(&filler));
        assert!(!published.is_empty(), "a prefix must be published first");
        assert!(
            published.contains(SPLIT_CANARY),
            "the canary is inside the published band"
        );
        let published_raw = scrubber.emitted_raw;
        assert!(published_raw > 0);

        // Key re-resolve: the canary becomes known *after* it was published
        // (the inherent, documented limit — the bytes cannot be recalled).
        kernel_broker::scrub::register_known_secret(SPLIT_CANARY);

        let mut out = String::new();
        out.push_str(&scrubber.push("prose a "));
        out.push_str(&scrubber.push("prose b "));
        out.push_str(&scrubber.finish());
        let raw = scrubber.raw.clone();
        kernel_broker::scrub::clear_known_secrets();

        let total = format!("{published}{out}");
        assert!(
            total.starts_with(&published),
            "the published band must not be recalled"
        );
        let expected_tail = scrub_agent_text(&raw[published_raw..]);
        assert_eq!(
            out, expected_tail,
            "the suffix from published_raw must stream exactly once"
        );
        assert!(
            out.ends_with("prose a prose b "),
            "the prose must end the stream: {out:?}"
        );
        assert_eq!(out.matches("prose a ").count(), 1, "{out:?}");
        assert_eq!(out.matches("prose b ").count(), 1, "{out:?}");
    }

    /// The same divergence through the public update pipeline: the observer
    /// stream equals `published ++ scrub(raw[published_raw..])` and the
    /// persisted/returned text is the whole-buffer scrub.
    #[test]
    fn late_registration_through_the_update_pipeline_reanchors() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        let mut state = PromptState::new();
        let mut observer = RecordingObserver::default();
        let turn_state = TurnState::default();
        let filler = "The quick brown fox jumps over the lazy dog. ".repeat(400);
        for text in [filler.clone(), SPLIT_CANARY.to_string(), filler.clone()] {
            apply_update(
                &turn_state,
                &mut state,
                256 * 1024,
                crate::jsonrpc::UpdateEvent {
                    session_id: None,
                    update: SessionUpdate::AgentMessageChunk { text },
                },
                &mut observer,
            );
        }
        let published = observer.chunks.join("");
        assert!(published.contains(SPLIT_CANARY), "{published:?}");
        let published_raw = state.message.emitted_raw;
        assert!(published_raw > 0);

        kernel_broker::scrub::register_known_secret(SPLIT_CANARY);
        for text in ["prose a ", "prose b "] {
            apply_update(
                &turn_state,
                &mut state,
                256 * 1024,
                crate::jsonrpc::UpdateEvent {
                    session_id: None,
                    update: SessionUpdate::AgentMessageChunk {
                        text: text.to_string(),
                    },
                },
                &mut observer,
            );
        }
        state.finish(&mut observer);
        kernel_broker::scrub::clear_known_secrets();

        let streamed = observer.chunks.join("");
        assert!(streamed.starts_with(&published), "{streamed:?}");
        let raw = state.message.raw.clone();
        let expected_tail = scrub_agent_text(&raw[published_raw..]);
        assert_eq!(&streamed[published.len()..], expected_tail, "{streamed:?}");
        assert!(streamed.ends_with("prose a prose b "), "{streamed:?}");
        assert!(
            !state.outcome.text.contains(SPLIT_CANARY),
            "{}",
            state.outcome.text
        );
        assert!(state.outcome.text.contains("<redacted>"));
    }
}
