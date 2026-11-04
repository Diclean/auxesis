//! Coalesced, secret-scrubbed `message.delta` frames.
//!
//! The engine reports transient assistant text token by token while the
//! provider streams. Forwarding every fragment as its own WebSocket frame
//! would flood a front-end, so this module batches one stream's text into at
//! most one frame per [`DELTA_TICK`], or earlier when the pending buffer
//! crosses [`FLUSH_THRESHOLD_BYTES`] — text is never dropped to keep up; a
//! slow *client* falls back to the authoritative snapshot instead
//! (`GET /v1/threads/{id}/messages`), and the final `message.new`/`message.done`
//! frames close the message.
//!
//! # Secret safety (WF-1 redesign)
//!
//! The streamed text must be **byte-identical to the whole-buffer scrub of
//! the same text** ([`kernel_broker::scrub_external_preview`], the same function
//! every other surface and the persisted `message.new` use), for every split
//! point. Six security-review rounds showed that holding back *spellings* — teaching
//! the hold about `:`, `%NN`, `0x`, base64 padding, … — kept missing families
//! (round 5 colon hexdump, round 6 percent escapes and a dropped base64 tail),
//! so this module no longer recognises any spelling:
//!
//! - The full accumulated raw text is kept per message ([`State::raw`]).
//! - The whole text is scrubbed with the shared entry point; the emitted
//!   output is always a prefix of that whole-buffer scrub
//!   ([`State::emitted`]).
//! - A fixed trailing window `W` ([`kernel_broker::scrub::streaming_hold_bytes`],
//!   or the Auxesis home path when that is longer) is withheld: the cut is
//!   `len - W`, floored to a UTF-8 char boundary and moved out of any token
//!   run. The scrub of the raw prefix ending at the cut must be a prefix of
//!   the whole scrub; if a mask straddles the cut, the cut moves back to
//!   before the decisively masked region, and if no safe cut exists nothing
//!   is emitted until more text (or `finish`) resolves it. A mask is
//!   therefore either fully emitted or fully withheld — never bisected.
//! - `finish` emits the whole-buffer scrub's remainder, so the concatenation
//!   of all deltas equals the scrub exactly.
//!
//! # Registry changes after emission (R7-1)
//!
//! The exact-value registry can change while a stream is live: the daemon
//! re-resolves keys (`providers.rs`), the LRU cap evicts, or a sibling
//! stream registers. Bytes already published cannot be recalled, so the
//! invariant is redefined, not forced: the concatenated output is the
//! emitted prefix plus the scrub of the raw suffix from the consumed offset
//! ([`State::emitted_raw`]), computed with up to one window of raw left
//! context for mask detection only. For a registry-stable stream that is
//! exactly the whole-buffer scrub; after a change that invalidates the
//! emitted prefix the stream re-anchors at the consumed raw offset and
//! continues with the remaining raw suffix — never a panic, never duplicated
//! or dropped text, never a fresh leak past the re-anchor point. A secret
//! registered only *after* it was streamed cannot be recalled from frames
//! the client already holds (the documented inherent limit); live streams
//! pin the values registered at their start so LRU eviction cannot
//! un-register them mid-stream ([`kernel_broker::scrub::pin_known_secrets`]).
//!
//! A registered value whose spelling is longer than the window cap (a
//! 4096-byte value in colon-hex is 8191 bytes) cannot be covered by the
//! fixed window; the stream holds that construct until `finish`, which still
//! emits the whole-buffer scrub exactly. Nothing is dropped; only latency
//! grows.
//!
//! If the registry reaches its hard ceiling with every value pinned
//! ([`kernel_broker::scrub::registry_saturated`]), a new secret can no longer be
//! registered: the stream then fails closed, replacing the whole remaining
//! message with one visible [`SATURATED_PLACEHOLDER`] instead of publishing
//! text that cannot be proven scrubbed.
//!
//! Text is never dropped: a construct that cannot be resolved yet is held,
//! not suppressed. Full scrubs are bounded by a step that grows with the
//! stream ([`attempt_step`]): an emit is attempted only after enough new
//! bytes accumulated, so a stream of many small deltas costs one bounded pass
//! per step instead of one full scrub per push.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use kernel_core::Lang;
use tokio::sync::broadcast;

use super::display::{live_tokens, DisplayFeed, Rehydrator};
use super::wire;

/// Coalescing tick: a pending delta is flushed at least this often.
pub const DELTA_TICK: Duration = Duration::from_millis(40);

/// Pending bytes that force an early flush (never a drop).
pub const FLUSH_THRESHOLD_BYTES: usize = 32 * 1024;

/// Most text bytes one frame carries. Kept far below the scrubber's own cap
/// so the scrubber's head/tail truncation can never bisect a pattern.
const MAX_RELEASE_BYTES: usize = 32 * 1024;

/// Smallest amount of new text between two whole-buffer scrub attempts. A
/// rescan costs `O(pending)`, so the step keeps the total bounded; it grows
/// with the stream so a long message converges in `O(n)` scans.
const MIN_ATTEMPT_STEP: usize = 4 * 1024;

/// Largest step: the live output lags the stream by at most this many bytes
/// on top of the hold window.
const MAX_ATTEMPT_STEP: usize = 64 * 1024;

/// How many times a drain moves the cut back before giving up for this
/// attempt (the next attempt happens after more text arrives).
const MAX_BACKOFF_ATTEMPTS: usize = 6;

/// Upper bound on the withheld window, mirroring
/// [`kernel_broker::scrub::streaming_hold_bytes`]'s own clamp.
const MAX_WINDOW_BYTES: usize = 4096;

/// The visible placeholder a stream emits when the known-secret registry is
/// saturated (at its hard ceiling with every value pinned): unscrubbed text
/// must not be published, so the whole remaining message fails closed (R8).
const SATURATED_PLACEHOLDER: &str = "<redacted>";

/// Mutable state of one stream.
#[derive(Default)]
struct State {
    /// The full text received so far (never trimmed, so every emit can be
    /// checked against the authoritative whole-buffer scrub).
    raw: String,
    /// The output already published. It is the concatenation of the frames
    /// sent so far; [`State::emitted_raw`] maps its end back to a raw offset.
    emitted: String,
    /// How many bytes of `raw` the published output accounts for.
    emitted_raw: usize,
    /// Raw offset at which the current live segment begins. It is 0 while no
    /// registry change has invalidated the emitted prefix; after one it is
    /// the consumed raw offset (the emitted bytes cannot be recalled).
    live_start_raw: usize,
    /// Output offset in [`State::emitted`] at which the live segment's output
    /// begins.
    anchor_out: usize,
    /// The engine seq of the newest delta folded into the buffer (the seq a
    /// frame reports).
    last_seq: u64,
    /// `finish` ran; every further push is ignored.
    finished: bool,
    /// After a stalled drain (a construct reaching the end cannot be
    /// resolved), the raw length at which to try again.
    retry_at: Option<usize>,
    /// The last whole-buffer scrub, keyed by `(raw length, registry
    /// generation)`. `finish` reuses it when neither changed, so the final
    /// flush costs no extra pass over the whole message.
    cached: Option<(usize, u64, String)>,
    /// The pin epoch this stream holds on the secrets that were registered
    /// when it started (released by `finish` or `Drop`), so LRU eviction
    /// cannot un-register a value a live stream still relies on.
    pin: Option<u64>,
    /// A registry write changed the verdict of an already emitted region at
    /// least once (the inherent, documented limit).
    diverged: bool,
    /// The registry was saturated when this stream emitted: the whole
    /// remaining message was replaced by a visible placeholder (R8).
    masked_whole: bool,
}

/// Where one stream's frames go, and how its references read.
#[derive(Clone)]
pub struct StreamSinks {
    /// The loopback channel, read by the Mac app. It gets the rehydrated
    /// text (`display`), never tokens only.
    pub loopback: broadcast::Sender<String>,
    /// The remote channel, for tailnet and mobile listeners. It gets the
    /// tokenised text only. `None` while no remote listener exists.
    pub remote: Option<broadcast::Sender<String>>,
    /// The owner's UI language, for the `[name hidden]` marker.
    pub lang: Lang,
}

impl StreamSinks {
    /// Loopback only, in English: the sinks a stream has without a remote
    /// listener.
    pub fn loopback(events: broadcast::Sender<String>) -> Self {
        Self {
            loopback: events,
            remote: None,
            lang: Lang::En,
        }
    }

    /// The same sinks, with the unknown-reference marker in `lang`.
    pub fn in_language(mut self, lang: Lang) -> Self {
        self.lang = lang;
        self
    }
}

/// One coalesced delta stream for one assistant draft.
pub struct DeltaStream {
    events: broadcast::Sender<String>,
    remote: Option<broadcast::Sender<String>>,
    home: PathBuf,
    agent: String,
    thread_id: i64,
    message_id: String,
    state: Mutex<State>,
    /// The loopback rehydration of the released text. Locked only inside
    /// `emit_text` and `finish`, always after `state`.
    display: Mutex<DisplayFeed>,
    /// The coalescing ticker, aborted on `finish` so a completed turn leaves
    /// no live task behind.
    ticker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DeltaStream {
    /// Start a stream that publishes under `message_id` (the transient draft
    /// id; the persisted message is authoritative), and spawn its coalescing
    /// ticker when a tokio runtime is present. `thread_id` is the session the
    /// stream's references belong to.
    pub fn new(
        sinks: StreamSinks,
        home: PathBuf,
        agent: impl Into<String>,
        thread_id: i64,
        message_id: impl Into<String>,
    ) -> Arc<Self> {
        let pin = kernel_broker::scrub::pin_known_secrets();
        let rehydrator = Rehydrator::new(live_tokens(), thread_id, sinks.lang);
        let stream = Arc::new(Self {
            events: sinks.loopback,
            remote: sinks.remote,
            home,
            agent: agent.into(),
            thread_id,
            message_id: message_id.into(),
            state: Mutex::new(State {
                pin: Some(pin),
                ..State::default()
            }),
            display: Mutex::new(DisplayFeed::new(rehydrator)),
            ticker: Mutex::new(None),
        });
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&stream);
            let ticker = handle.spawn(async move {
                loop {
                    tokio::time::sleep(DELTA_TICK).await;
                    let Some(stream) = weak.upgrade() else {
                        break;
                    };
                    stream.flush();
                    if stream.is_finished() {
                        break;
                    }
                }
            });
            *kernel_core::lock_recover(&stream.ticker) = Some(ticker);
        }
        stream
    }

    /// Fold one engine delta into the buffer, flushing early when the pending
    /// buffer grows past [`FLUSH_THRESHOLD_BYTES`].
    pub fn push(&self, text: &str, seq: u64) {
        let mut state = kernel_core::lock_recover(&self.state);
        if state.finished {
            return;
        }
        state.last_seq = state.last_seq.max(seq);
        state.raw.push_str(text);
        if state.raw.len().saturating_sub(state.emitted_raw) >= FLUSH_THRESHOLD_BYTES {
            self.emit_live(&mut state, false);
        }
    }

    /// Flush everything pending; the stream is done and further pushes are
    /// ignored. Called when the assistant message is persisted (or the turn
    /// ends), so the final text is never left in the buffer.
    pub fn finish(&self) {
        if let Some(ticker) = kernel_core::lock_recover(&self.ticker).take() {
            ticker.abort();
        }
        let mut state = kernel_core::lock_recover(&self.state);
        if state.finished {
            return;
        }
        state.finished = true;
        self.emit_live(&mut state, true);
        self.flush_display(state.last_seq);
        // The stream is done: release the pin on the values it started with,
        // so the registry can be trimmed back to its cap.
        if let Some(epoch) = state.pin.take() {
            kernel_broker::scrub::unpin_known_secrets(epoch);
        }
    }

    /// Ticker entry point; also lets the process-isolated perf tests flush
    /// deterministically.
    #[doc(hidden)]
    pub fn flush(&self) {
        let mut state = kernel_core::lock_recover(&self.state);
        if state.finished {
            return;
        }
        self.emit_live(&mut state, false);
    }

    fn is_finished(&self) -> bool {
        kernel_core::lock_recover(&self.state).finished
    }

    /// The fixed window this stream withholds from the end of its buffer.
    fn window(&self) -> usize {
        let home = self.home.as_os_str().len().saturating_add(1);
        kernel_broker::scrub::streaming_hold_bytes()
            .max(home)
            .min(MAX_WINDOW_BYTES)
    }

    /// Emit as much of the buffer as is provably stable.
    ///
    /// The streamed output is always `emitted` ++ a prefix of the scrub of
    /// the raw suffix starting at [`State::live_start_raw`] (with up to one
    /// window of left context, used only for mask detection and never
    /// re-emitted). While the registry is unchanged that prefix is also a
    /// prefix of the whole-buffer scrub of the full text. If a registry
    /// write (key re-resolution, LRU eviction, a sibling stream) changes the
    /// verdict of an *already emitted* region, those bytes cannot be
    /// recalled: the live segment is re-anchored at the consumed raw offset
    /// and the remaining raw suffix is scrubbed and emitted from there —
    /// well-formed, no duplication, no dropped text, and no fresh leak past
    /// the re-anchor point.
    fn emit_live(&self, state: &mut State, finish: bool) {
        if state.raw.is_empty() {
            return;
        }
        if kernel_broker::scrub::registry_saturated() || kernel_broker::scrub::registry_oversized()
        {
            // The registry cannot prove every spelling covered: it is at its
            // hard ceiling with every value pinned (R8), or a value's variant
            // closure exceeded its budget (R10). Fail closed with one visible
            // placeholder instead of leaking.
            if !state.masked_whole {
                state.masked_whole = true;
                self.emit_text(state.last_seq, SATURATED_PLACEHOLDER);
                state.emitted.push_str(SATURATED_PLACEHOLDER);
                tracing::warn!(
                    thread_id = self.thread_id,
                    "known-secret registry cannot cover every spelling; the delta stream failed closed with a placeholder"
                );
            }
            state.emitted_raw = state.raw.len();
            return;
        }
        if let Some(retry_at) = state.retry_at {
            if !finish && state.raw.len() < retry_at {
                return;
            }
        }
        let n = state.raw.len();
        if !finish
            && n.saturating_sub(state.emitted_raw) < self.window().saturating_add(attempt_step(n))
        {
            return;
        }
        let window = self.window();
        let generation = kernel_broker::scrub::registry_generation();
        let mut attempts = 0usize;
        let mut reanchors = 0usize;
        loop {
            let context = window.min(state.live_start_raw);
            let seg_start = state.live_start_raw - context;
            let seg = &state.raw[seg_start..];
            // In prefix mode `finish` may reuse the last whole-buffer scrub.
            let seg_scrub = if finish && seg_start == 0 && state.anchor_out == 0 {
                match state.cached.take() {
                    Some((len, cached_generation, text))
                        if len == state.raw.len() && cached_generation == generation =>
                    {
                        text
                    }
                    _ => scrub(&self.home, seg),
                }
            } else {
                scrub(&self.home, seg)
            };
            let head = if context == 0 {
                String::new()
            } else {
                scrub(&self.home, &seg[..context])
            };
            // Output position in `seg_scrub` at which the live segment
            // starts: the scrub of the context alone, or the first
            // divergence when a mask now covers the live start (the token is
            // then part of the live output).
            let compare_from = if seg_scrub.starts_with(head.as_str()) {
                head.len()
            } else {
                common_prefix_len(seg_scrub.as_bytes(), head.as_bytes())
            };
            let live_len = state.emitted.len() - state.anchor_out;
            if !seg_scrub[compare_from..].starts_with(&state.emitted[state.anchor_out..]) {
                // A registry write changed the verdict of an already emitted
                // region. Re-anchor at the consumed raw offset and continue
                // with the scrub of the remaining raw suffix; the emitted
                // bytes are never re-emitted.
                state.live_start_raw = state.emitted_raw;
                state.anchor_out = state.emitted.len();
                if !state.diverged {
                    state.diverged = true;
                    tracing::warn!(
                        thread_id = self.thread_id,
                        "delta stream diverged from the whole-buffer scrub after a registry change; the remaining raw suffix is scrubbed from the emitted offset"
                    );
                }
                reanchors += 1;
                if reanchors > 4 {
                    return;
                }
                continue;
            }
            if finish {
                let from = compare_from + live_len;
                if seg_scrub.len() > from {
                    self.emit_text(state.last_seq, &seg_scrub[from..]);
                    state.emitted.push_str(&seg_scrub[from..]);
                }
                state.emitted_raw = state.raw.len();
                return;
            }
            // Candidate cut: the end minus the window, floored to a char
            // boundary and moved out of any token run.
            let mut cut = run_start(
                seg,
                floor_char_boundary(seg, seg.len().saturating_sub(window)),
            );
            if cut <= context || seg_start + cut <= state.emitted_raw {
                self.stall(state);
                return;
            }
            if seg_scrub == seg {
                // Identity scrub: the raw cut maps 1:1, no prefix scrub.
                let from = compare_from + live_len;
                if cut > from {
                    self.emit_text(state.last_seq, &seg[from..cut]);
                    state.emitted.push_str(&seg[from..cut]);
                }
                state.emitted_raw = seg_start + cut;
                state.retry_at = None;
                self.remember(state, seg_start, generation, seg_scrub);
                return;
            }
            loop {
                let prefix = scrub(&self.home, &seg[..cut]);
                if seg_scrub.starts_with(prefix.as_str()) {
                    // The prefix scrub is the tail of the live scrub: every
                    // mask in it is complete, so it can be published.
                    let from = compare_from + live_len;
                    if prefix.len() > from {
                        self.emit_text(state.last_seq, &seg_scrub[from..prefix.len()]);
                        state.emitted.push_str(&seg_scrub[from..prefix.len()]);
                    }
                    state.emitted_raw = seg_start + cut;
                    state.retry_at = None;
                    self.remember(state, seg_start, generation, seg_scrub);
                    return;
                }
                // A mask straddles the cut: move it back before that region.
                let divergence = common_prefix_len(seg_scrub.as_bytes(), prefix.as_bytes());
                let back = prefix.len().saturating_sub(divergence).max(1);
                let next = run_start(seg, floor_char_boundary(seg, cut.saturating_sub(back)));
                attempts += 1;
                if next >= cut || next <= context || attempts >= MAX_BACKOFF_ATTEMPTS {
                    self.stall(state);
                    return;
                }
                cut = next;
            }
        }
    }

    /// Cache the live scrub for `finish` when it is the whole buffer.
    fn remember(&self, state: &mut State, seg_start: usize, generation: u64, text: String) {
        if seg_start == 0 && state.anchor_out == 0 {
            state.cached = Some((state.raw.len(), generation, text));
        }
    }

    /// Try again only after enough new text; a stalled construct (a run or a
    /// mask that reaches the end) must not cause a scrub per push.
    fn stall(&self, state: &mut State) {
        let pending = state.raw.len().saturating_sub(state.emitted_raw);
        let step = attempt_step(state.raw.len()).max(pending / 4);
        state.retry_at = Some(state.raw.len().saturating_add(step));
    }

    /// Publish one scrubbed chunk. The tokenised text goes to the remote
    /// channel at once, when one is attached. The loopback channel gets the
    /// rehydrated text, and `DisplayFeed` holds back a reference still open
    /// at the end of the chunk.
    fn emit_text(&self, seq: u64, text: &str) {
        if let Some(remote) = &self.remote {
            self.send_frames(remote, seq, text, false);
        }
        let released = kernel_core::lock_recover(&self.display).push(text);
        self.send_frames(&self.events, seq, &released.text, released.unavailable);
    }

    /// Release the loopback text that `DisplayFeed` still holds, at the end of the stream.
    fn flush_display(&self, seq: u64) {
        let released = kernel_core::lock_recover(&self.display).finish();
        self.send_frames(&self.events, seq, &released.text, released.unavailable);
    }

    /// Send `text` as one or more `message.delta` frames on `channel`. A
    /// frame carries `rehydration_unavailable` when a reference stayed masked.
    fn send_frames(
        &self,
        channel: &broadcast::Sender<String>,
        seq: u64,
        text: &str,
        unavailable: bool,
    ) {
        let mut rest = text;
        while !rest.is_empty() {
            let cut = floor_char_boundary(rest, MAX_RELEASE_BYTES).max(1);
            let (head, tail) = rest.split_at(cut);
            let mut frame =
                wire::message_delta(&self.agent, self.thread_id, &self.message_id, seq, head);
            if unavailable {
                frame["rehydration_unavailable"] = serde_json::Value::Bool(true);
            }
            wire::send_bounded(channel, &frame);
            rest = tail;
        }
    }
}

impl Drop for DeltaStream {
    fn drop(&mut self) {
        // A stream that never reached `finish` (an aborted turn) still
        // releases its pin, so the registry can be trimmed.
        let pin = kernel_core::lock_recover(&self.state).pin.take();
        if let Some(epoch) = pin {
            kernel_broker::scrub::unpin_known_secrets(epoch);
        }
    }
}

/// Scrub text through the shared entry point.
///
/// No size cap is requested: the whole accumulated buffer may span several
/// frames, and passing the shared scrubber's head/tail cap would silently
/// drop the middle (security review H-02); the release is chunked here instead.
fn scrub(home: &Path, text: &str) -> String {
    kernel_broker::scrub_external_preview(home, text, usize::MAX)
}

/// True for the token bytes the scrubber treats as one opaque run.
fn is_run_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+')
}

/// If `cut` splits a run, move it to the run's first byte: a token, a vendor
/// key or a JWT is only recognisable whole (or from its own start), so no
/// frame boundary may fall inside one.
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

/// Length of the common byte prefix of two strings.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .take_while(|(left, right)| left == right)
        .count()
}

/// How much new text must accumulate between two whole-buffer scans.
fn attempt_step(n: usize) -> usize {
    (n / 16).clamp(MIN_ATTEMPT_STEP, MAX_ATTEMPT_STEP)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    #[test]
    fn shared_secret_redaction_canaries_are_scrubbed_in_deltas() {
        redaction_canaries::assert_no_canaries(|text| {
            scrub(Path::new("/tmp/auxesis-canary-home"), text)
        });
    }
    use serde_json::Value;

    const HOME: &str = "/Users/secret/.auxesis";

    /// The marker the shared scrubber writes for one redacted value.
    const MASK_MARKER: &str = "<redacted>";

    fn stream() -> (Arc<DeltaStream>, broadcast::Receiver<String>) {
        let (sender, receiver) = broadcast::channel(128);
        let stream = DeltaStream::new(
            StreamSinks::loopback(sender),
            PathBuf::from(HOME),
            "main",
            3,
            "draft-3-1",
        );
        (stream, receiver)
    }

    fn drained(receiver: &mut broadcast::Receiver<String>) -> Vec<Value> {
        let mut frames = Vec::new();
        while let Ok(text) = receiver.try_recv() {
            frames.push(serde_json::from_str(&text).unwrap());
        }
        frames
    }

    fn joined(frames: &[Value]) -> String {
        frames
            .iter()
            .map(|frame| frame["text"].as_str().unwrap())
            .collect()
    }

    fn whole(text: &str) -> String {
        scrub(Path::new(HOME), text)
    }

    /// Any window of `needle` at least 8 bytes long that appears in `text`
    /// (the exact-value layer's minimum secret length). A shorter partial
    /// cannot be a complete credential and is the documented residual.
    fn leaked_window(text: &str, needle: &str) -> Option<String> {
        let bytes = needle.as_bytes();
        if bytes.len() < 8 {
            return None;
        }
        for i in 0..=bytes.len() - 8 {
            let window = &needle[i..i + 8];
            if text.contains(window) {
                return Some(window.to_string());
            }
        }
        None
    }

    /// Stream `text` with a real flush after each cut, then finish. Returns
    /// all frame text — which must equal the whole-buffer scrub exactly.
    fn streamed_with_cuts(text: &str, cuts: &[usize]) -> String {
        let (stream, mut receiver) = stream();
        let mut cuts: Vec<usize> = cuts
            .iter()
            .copied()
            .filter(|cut| *cut > 0 && *cut < text.len() && text.is_char_boundary(*cut))
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        let mut start = 0;
        for cut in cuts {
            stream.push(&text[start..cut], 1);
            stream.flush();
            start = cut;
        }
        stream.push(&text[start..], 2);
        stream.finish();
        joined(&drained(&mut receiver))
    }

    /// Split `text` at one position, let one flush happen in between (the
    /// ticker's drain, synchronously), then finish.
    fn split_with_a_flush(text: &str, position: usize) -> String {
        streamed_with_cuts(text, &[position])
    }

    /// Every combination of `k` interior cut positions; `stride` thins the
    /// first index for the (expensive) 4-way sweep.
    fn cut_combinations(boundaries: &[usize], k: usize, stride: usize) -> Vec<Vec<usize>> {
        let interior = &boundaries[1..boundaries.len().saturating_sub(1)];
        let mut out = Vec::new();
        let mut combo = Vec::with_capacity(k);
        collect_combinations(interior, k, stride, 0, &mut combo, &mut out);
        out
    }

    fn collect_combinations(
        interior: &[usize],
        k: usize,
        stride: usize,
        start: usize,
        combo: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if combo.len() == k {
            out.push(combo.clone());
            return;
        }
        for index in start..interior.len() {
            if combo.is_empty() && index % stride != 0 {
                continue;
            }
            if let Some(last) = combo.last() {
                if interior[index] <= *last {
                    continue;
                }
            }
            combo.push(interior[index]);
            collect_combinations(interior, k, stride, index + 1, combo, out);
            combo.pop();
        }
    }

    /// Every documented secret shape around `canary`; all are unregistered,
    /// so only the heuristic layers can save them.
    fn shape_texts(canary: &str) -> Vec<String> {
        vec![
            format!("key {}{} end", "sk-", canary),
            format!("token {}{} end", "ghp_", canary),
            format!("aws {}{} end", "AKIA", canary.to_uppercase()),
            format!("slack xoxb-{canary} end"),
            format!("here password={canary} end"),
            format!("needs {{\"password\":\"{canary}\"}} changing"),
            format!("Authorization: Bearer {canary}"),
            format!("send Bearer {canary} now"),
            format!("env AUX_KEY_DEEPSEEK={canary} end"),
        ]
    }

    fn hex_bytes(text: &str) -> String {
        text.bytes().map(|byte| format!("{byte:02x}")).collect()
    }

    fn percent_bytes(text: &str, upper: bool) -> String {
        text.bytes()
            .map(|byte| {
                if upper {
                    format!("%{byte:02X}")
                } else {
                    format!("%{byte:02x}")
                }
            })
            .collect()
    }

    /// Standard base64 (RFC 4648, padded) without pulling in a dependency.
    fn base64_bytes(text: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let trio = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((trio >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((trio >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((trio >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(trio & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    /// URL-safe base64 (RFC 4648 §5, still padded).
    fn base64url_bytes(text: &str) -> String {
        base64_bytes(text).replace('+', "-").replace('/', "_")
    }

    /// RFC 4648 base32, padded.
    fn base32_bytes(text: &str) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(5) {
            let mut buffer = [0u8; 5];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let symbols = (chunk.len() * 8).div_ceil(5);
            for index in 0..symbols {
                let mut symbol = 0u8;
                for bit in 0..5 {
                    let position = index * 5 + bit;
                    let byte = buffer[position / 8];
                    let bit_value = (byte >> (7 - position % 8)) & 1;
                    symbol = (symbol << 1) | bit_value;
                }
                out.push(ALPHABET[symbol as usize] as char);
            }
        }
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
        out
    }

    /// The required spelling families around a registered canary.
    fn spelling_texts(canary: &str) -> Vec<(&'static str, String)> {
        let pairs: Vec<String> = canary.bytes().map(|byte| format!("{byte:02x}")).collect();
        let upper_pairs: Vec<String> = canary.bytes().map(|byte| format!("{byte:02X}")).collect();
        let mut texts: Vec<(&'static str, String)> = Vec::new();
        for (label, separator) in [
            ("colon", ":"),
            ("dash", "-"),
            ("comma", ","),
            ("agent", "."),
            ("underscore", "_"),
            ("pipe", "|"),
        ] {
            texts.push((label, format!("dump {} done", pairs.join(separator))));
        }
        texts.push((
            "zero-x",
            format!(
                "dump {} done",
                pairs
                    .iter()
                    .map(|pair| format!("0x{pair}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ));
        texts.push((
            "backslash-x",
            format!(
                "dump {} done",
                pairs
                    .iter()
                    .map(|pair| format!("\\x{pair}"))
                    .collect::<String>()
            ),
        ));
        texts.push(("hex", format!("dump {} done", pairs.concat())));
        texts.push(("hex-upper", format!("dump {} done", upper_pairs.concat())));
        texts.push(("base64", format!("dump {} done", base64_bytes(canary))));
        texts.push((
            "base64url",
            format!("dump {} done", base64url_bytes(canary)),
        ));
        texts.push(("base32", format!("dump {} done", base32_bytes(canary))));
        texts.push((
            "percent",
            format!("dump {} done", percent_bytes(canary, true)),
        ));
        texts.push((
            "percent-lower",
            format!("dump {} done", percent_bytes(canary, false)),
        ));
        texts
    }

    /// The UTF-16 surrogate pair of a non-BMP code point (test-side copy).
    fn surrogate_pair(code: u32) -> (u32, u32) {
        let offset = code - 0x1_0000;
        (0xD800 + (offset >> 10), 0xDC00 + (offset & 0x3FF))
    }

    /// Minimal percent encoding: only the characters that break URL/query
    /// parsing.
    fn percent_minimal_bytes(text: &str) -> String {
        let mut out = String::new();
        for c in text.chars() {
            if matches!(
                c,
                '%' | '+' | '&' | '=' | '?' | '#' | ';' | ' ' | '"' | '\'' | '<' | '>' | '`'
            ) {
                out.push_str(&format!("%{:02X}", c as u32));
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Every byte as `%NN`.
    fn percent_all_bytes(text: &str) -> String {
        text.bytes().map(|b| format!("%{b:02X}")).collect()
    }

    /// HTML entities, one per character (`&#x43;`).
    fn html_entities_bytes(text: &str) -> String {
        text.chars()
            .map(|c| format!("&#x{:X};", c as u32))
            .collect()
    }

    /// JSON `\uNNNN` escapes, one per character (surrogate pairs beyond the
    /// BMP).
    fn json_escapes_bytes(text: &str) -> String {
        text.chars()
            .map(|c| {
                let code = c as u32;
                if code > 0xFFFF {
                    let (high, low) = surrogate_pair(code);
                    format!("\\u{high:04X}\\u{low:04X}")
                } else {
                    format!("\\u{code:04X}")
                }
            })
            .collect()
    }

    /// Deterministic 64-bit LCG for the random-chunking property tests.
    fn next_random(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state >> 33
    }

    #[test]
    fn frames_carry_the_app_shape() {
        let (stream, mut receiver) = stream();
        stream.push("hello ", 1);
        stream.push("world", 2);
        stream.push(" sk-live-SECRET0123456789", 3);
        stream.finish();

        let frames = drained(&mut receiver);
        assert_eq!(
            frames.len(),
            1,
            "the final flush emits the whole buffer: {frames:?}"
        );
        let text = joined(&frames);
        assert_eq!(frames[0]["type"], "message.delta");
        assert_eq!(frames[0]["agent"], "main");
        assert_eq!(frames[0]["thread_id"], "3");
        assert_eq!(frames[0]["message_id"], "draft-3-1");
        assert_eq!(frames[0]["seq"], 3, "the newest engine delta's seq");
        assert!(text.starts_with("hello world "), "{text}");
        assert!(text.ends_with("sk-<redacted>"), "{text}");
        assert!(!text.contains("SECRET0123456789"), "{text}");
        assert_eq!(text, whole("hello world sk-live-SECRET0123456789"));
    }

    #[test]
    fn a_secret_split_across_two_deltas_is_never_emitted() {
        let (stream, mut receiver) = stream();
        stream.push("key: sk-live-", 1);
        stream.push("SECRET0123456789 done", 2);
        stream.finish();

        let text = joined(&drained(&mut receiver));
        assert!(!text.contains("SECRET0123456789"), "{text}");
        assert!(!text.contains("sk-live"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert_eq!(text, whole("key: sk-live-SECRET0123456789 done"));
    }

    /// Push `left`, let the real coalescing ticker run, then push `right` and
    /// finish. Returns the joined frames; the tail of `left` held across the
    /// flush must never surface (the prefix before it may), and the whole
    /// joined output must equal the whole-buffer scrub.
    async fn split_across_a_ticker_flush(left: &str, right: &str, held: &str) -> String {
        let (stream, mut receiver) = stream();
        stream.push(left, 1);
        tokio::time::sleep(DELTA_TICK * 4).await;
        let early = joined(&drained(&mut receiver));
        assert!(
            !early.contains(held),
            "a partial pattern leaked across the ticker flush: {early:?}"
        );
        stream.push(right, 2);
        stream.finish();
        let all = format!("{early}{}", joined(&drained(&mut receiver)));
        assert_eq!(all, whole(&format!("{left}{right}")));
        all
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_secret_split_across_a_real_ticker_flush_is_never_emitted() {
        // Canaries and the key prefix are assembled at runtime so no
        // key-shaped literal is committed.
        let canary = format!("CANARY{}", 123_456_789u64);
        let key_prefix = format!("{}live-", "sk-");

        let secret = split_across_a_ticker_flush(
            &format!("key: {key_prefix}"),
            &format!("{canary} done"),
            "sk-",
        )
        .await;
        assert!(!secret.contains(&canary), "the canary leaked: {secret}");
        assert!(secret.contains("<redacted>"), "{secret}");

        let home =
            split_across_a_ticker_flush("path: /Users/sec", "ret/.auxesis/agents", "/Users").await;
        assert!(!home.contains(HOME), "the home path leaked: {home}");
        assert!(home.contains("<home>"), "{home}");

        let env = split_across_a_ticker_flush(
            "env: AUX_KEY_DEEPSEEK=",
            &format!("{key_prefix}{canary} end"),
            "AUX_KEY",
        )
        .await;
        assert!(!env.contains(&canary), "the canary leaked: {env}");
        assert!(env.contains("<redacted>"), "{env}");
    }

    /// An endless adversarial run cannot be resolved until it ends, so the
    /// stream holds it (never suppresses it) and `finish` emits the
    /// whole-buffer scrub: exact bytes, no drop, no leak. The buffer itself
    /// stays linear in the text by design.
    #[test]
    fn an_overlong_open_run_is_redacted_wholesale_by_finish() {
        let (stream, mut receiver) = stream();
        stream.push(&format!("{}live-", "sk-"), 1);
        let piece = "A".repeat(4096);
        for _ in 0..64 {
            stream.push(&piece, 2);
        }
        let mut frames = drained(&mut receiver);
        stream.finish();
        frames.extend(drained(&mut receiver));
        let text = joined(&frames);
        assert!(
            text.contains("sk-<redacted>"),
            "the run was not redacted: {text}"
        );
        assert!(!text.contains(&piece), "raw run bytes leaked: {text}");
        for frame in &frames {
            let text = frame["text"].as_str().unwrap();
            assert!(
                text.len() <= MAX_RELEASE_BYTES,
                "a frame exceeded MAX_RELEASE_BYTES: {}",
                text.len()
            );
        }
        let expected = whole(&format!("sk-live-{}{}", piece.repeat(64), ""));
        assert_eq!(text, expected, "the joined deltas diverged from the scrub");
    }

    #[test]
    fn a_secret_split_at_the_flush_boundary_is_never_emitted() {
        let (stream, mut receiver) = stream();
        // Fill past the early-flush threshold, ending mid-secret: the flush
        // must hold the partial pattern instead of emitting it.
        let prefix = "x".repeat(FLUSH_THRESHOLD_BYTES - 8);
        stream.push(&format!("{prefix} sk-"), 1);
        let early = drained(&mut receiver);
        assert!(
            !joined(&early).contains("sk-"),
            "a partial pattern must not be flushed: {early:?}"
        );

        stream.push("live-SECRET0123456789 end", 2);
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(!text.contains("SECRET0123456789"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert_eq!(
            text,
            whole(&format!("{prefix} sk-live-SECRET0123456789 end"))
        );
    }

    #[test]
    fn a_secret_ending_exactly_at_a_frame_boundary_is_avoided() {
        let (stream, mut receiver) = stream();
        // More than one frame's worth of text, then a separated secret, so
        // the frame boundary lands inside the pending buffer unless the cut
        // is adjusted.
        let prefix = "a".repeat(MAX_RELEASE_BYTES + 100);
        stream.push(&format!("{prefix} sk-live-SECRET0123456789 tail"), 1);
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(!text.contains("SECRET0123456789"), "{text}");
        assert!(!text.contains("sk-live"), "{text}");
        assert_eq!(
            text,
            whole(&format!("{prefix} sk-live-SECRET0123456789 tail"))
        );
    }

    #[test]
    fn an_env_assignment_split_across_deltas_is_redacted() {
        let (stream, mut receiver) = stream();
        stream.push("env: AUX_KEY_", 1);
        stream.push("DEEPSEEK=sk-", 2);
        stream.push("live-abcdef123 end", 3);
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(!text.contains("live-abcdef123"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert_eq!(text, whole("env: AUX_KEY_DEEPSEEK=sk-live-abcdef123 end"));
    }

    #[test]
    fn an_overlong_secret_run_is_redacted_wholesale_without_dropping() {
        let (stream, mut receiver) = stream();
        let huge = "A".repeat(4 * 1024);
        let body = format!("before sk-{huge}CONTINUATION-STILL-SECRET after");
        stream.push(&format!("before sk-{huge}"), 1);
        stream.push("CONTINUATION-STILL-SECRET after", 2);
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(text.contains("before sk-<redacted>"), "{text}");
        assert!(!text.contains(&huge), "the long run must be redacted");
        assert!(
            !text.contains("CONTINUATION"),
            "the run continuation is part of the mask"
        );
        assert!(text.contains("after"), "text after the run resumes: {text}");
        assert_eq!(text, whole(&body));
    }

    #[test]
    fn a_masked_pair_continuation_is_masked_not_dropped() {
        let (stream, mut receiver) = stream();
        // The first flush cannot resolve the open pair; the next delta
        // continues the same (unknown) value without a separator. Nothing is
        // emitted bare and nothing is dropped: the final output is the
        // whole-buffer scrub.
        let body = "the password=SECRET0123456789MORE-STILL-SECRET done";
        stream.push("the password=SECRET0123456789", 1);
        stream.flush();
        stream.push("MORE-STILL-SECRET done", 2);
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(!text.contains("SECRET0123456789"), "{text}");
        assert!(!text.contains("MORE"), "{text}");
        assert!(
            text.contains(" done"),
            "text after the value resumes: {text}"
        );
        assert_eq!(text, whole(body));
    }

    #[test]
    fn the_home_path_is_scrubbed_even_split_across_deltas() {
        let (stream, mut receiver) = stream();
        stream.push("path: /Users/sec", 1);
        stream.push("ret/.auxesis/agents", 2);
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(!text.contains("/Users/secret/.auxesis"), "{text}");
        assert!(
            text.contains("<home>/agents") || text.contains("<home>"),
            "{text}"
        );
        assert_eq!(text, whole("path: /Users/secret/.auxesis/agents"));
    }

    #[test]
    fn push_past_the_threshold_flushes_early_without_dropping_text() {
        let (stream, mut receiver) = stream();
        let big = "lorem ipsum ".repeat(FLUSH_THRESHOLD_BYTES / 6);
        stream.push(&big, 1);
        let frames = drained(&mut receiver);
        assert!(!frames.is_empty(), "the early flush must emit");
        assert!(
            joined(&frames).starts_with("lorem ipsum"),
            "frame text is preserved"
        );
        stream.finish();
        let all = format!("{}{}", joined(&frames), joined(&drained(&mut receiver)));
        assert_eq!(all.len(), big.len(), "no byte is dropped or duplicated");
        assert_eq!(all, whole(&big));
    }

    #[tokio::test]
    async fn the_ticker_coalesces_deltas_into_few_frames() {
        let (stream, mut receiver) = stream();
        for seq in 1..=20 {
            stream.push("tok ", seq);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        stream.finish();
        let frames = drained(&mut receiver);
        assert!(
            frames.len() < 20,
            "20 deltas must coalesce: {} frames",
            frames.len()
        );
        assert_eq!(joined(&frames), "tok ".repeat(20));
        assert_eq!(frames.last().unwrap()["seq"], 20);
    }

    #[test]
    fn pushes_after_finish_are_ignored() {
        let (stream, mut receiver) = stream();
        stream.push("done", 1);
        stream.finish();
        stream.push("late", 2);
        let frames = drained(&mut receiver);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["seq"], 1);
    }

    /// H-02 (P1 gate): every documented secret shape, split at **every** char
    /// boundary with a real flush in between, must never surface a window of
    /// the value on the WS and must reproduce the whole-buffer scrub exactly.
    #[test]
    fn every_shape_split_at_every_position_matches_the_whole_buffer() {
        // Runtime-assembled canaries: no key-shaped literal is committed.
        let canary = format!("CNR7H02{}", 987_654_321u64);
        for text in shape_texts(&canary) {
            let expected = whole(&text);
            let boundaries = text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()]);
            for position in boundaries {
                let all = split_with_a_flush(&text, position);
                if let Some(window) = leaked_window(&all, &canary) {
                    panic!("shape {text:?} split at {position} leaked {window:?}: {all}");
                }
                assert_eq!(all, expected, "shape {text:?} split at {position}");
            }
        }
    }

    /// A registered key is held in every spelling the shared scrubber knows:
    /// raw, hex and base64, split at every position across a flush.
    #[test]
    fn a_registered_key_split_at_every_position_is_held_in_every_spelling() {
        let canary = format!("CNR7KNOWN{}", 5_678_901_234u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let hex = hex_bytes(&canary);
        let b64 = base64_bytes(&canary);
        for (text, needle) in [
            (canary.clone(), canary.clone()),
            (format!("value: {hex} end"), hex.clone()),
            (format!("blob {b64} done"), b64.clone()),
            (format!("password={canary}"), canary.clone()),
        ] {
            let expected = whole(&text);
            let boundaries = text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()]);
            for position in boundaries {
                let all = split_with_a_flush(&text, position);
                if let Some(window) = leaked_window(&all, &needle) {
                    panic!("{needle:?} split at {position} leaked {window:?}: {all}");
                }
                assert_eq!(all, expected, "{needle:?} split at {position}");
            }
        }
    }

    /// Property test over random chunkings: any chunk boundary (including one
    /// in the middle of a name, keyword, separator or value) with a flush at
    /// every chunk must still never leak — and the joined frames must equal
    /// the whole-buffer scrub exactly.
    #[test]
    fn random_chunkings_of_every_shape_never_leak() {
        let canary = format!("CNR7PROP{}", 1_234_567_890u64);
        let texts = shape_texts(&canary);
        let mut rng = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..32 {
            for text in &texts {
                let (stream, mut receiver) = stream();
                let mut position = 0;
                while position < text.len() {
                    let step = 1 + (next_random(&mut rng) % 9) as usize;
                    let mut end = (position + step).min(text.len());
                    end = floor_char_boundary(text, end);
                    if end == position {
                        end = text.len();
                    }
                    stream.push(&text[position..end], 1);
                    if next_random(&mut rng).is_multiple_of(3) {
                        stream.flush();
                    }
                    position = end;
                }
                stream.finish();
                let all = joined(&drained(&mut receiver));
                if let Some(window) = leaked_window(&all, &canary) {
                    panic!("shape {text:?} leaked {window:?}: {all}");
                }
                assert_eq!(all, whole(text), "shape {text:?} diverged from the scrub");
            }
        }
    }

    /// The equality contract over random splits of both plain Unicode prose
    /// and registered spellings: concatenated deltas == whole-buffer scrub.
    #[test]
    fn random_splits_match_the_whole_buffer_exactly() {
        let canary = format!("CNR7RND{}", 314_159_265u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let mut texts: Vec<String> = shape_texts(&canary);
        texts.extend(spelling_texts(&canary).into_iter().map(|(_, text)| text));
        texts.push("emoji 😀 ünïcode 中 \u{2066}isolate\u{2067} \u{2068}done\u{2069}".to_string());
        texts.push("lorem ipsum dolor sit amet, consectetur adipiscing elit.".to_string());
        let mut rng = 0xC0FF_EE00_1234_5678u64;
        for _ in 0..32 {
            for text in &texts {
                let (stream, mut receiver) = stream();
                let mut position = 0;
                while position < text.len() {
                    let step = 1 + (next_random(&mut rng) % 11) as usize;
                    let mut end = (position + step).min(text.len());
                    end = floor_char_boundary(text, end);
                    if end == position {
                        end = text.len();
                    }
                    stream.push(&text[position..end], 1);
                    if next_random(&mut rng).is_multiple_of(3) {
                        stream.flush();
                    }
                    position = end;
                }
                stream.finish();
                let all = joined(&drained(&mut receiver));
                assert_eq!(all, whole(text), "random split of {text:?} diverged");
            }
        }
    }

    /// A registry hold that starts *inside* a run must not move the cut into
    /// that run: the head alone can fail a whole-run shape gate (`AKIA…`
    /// needs 16 trailing bytes) while the rest of the run leaks on the next
    /// flush.
    #[test]
    fn a_hold_inside_a_run_never_splits_a_run_shaped_secret() {
        let collide = format!("87654321HOLD{}", 123_456_789u64);
        assert!(kernel_broker::scrub::register_known_secret(&collide));
        let canary = "CNR7H02987654321";
        let text = format!("aws {}{} end", "AKIA", canary);
        let expected = whole(&text);
        let boundaries = text
            .char_indices()
            .map(|(index, _)| index)
            .chain([text.len()]);
        for position in boundaries {
            let all = split_with_a_flush(&text, position);
            if let Some(window) = leaked_window(&all, canary) {
                panic!("split at {position} leaked {window:?}: {all}");
            }
            assert_eq!(all, expected, "split at {position}");
        }
    }

    /// A bare, non-secret endless run must stream without dropping or
    /// duplicating a byte: an open run is held (bounded steps) and `finish`
    /// emits the whole-buffer scrub exactly.
    #[test]
    fn a_bare_endless_run_keeps_its_bytes_without_dropping() {
        let (stream, mut receiver) = stream();
        let piece = "b".repeat(4096);
        for _ in 0..64 {
            stream.push(&piece, 1);
        }
        let early = joined(&drained(&mut receiver));
        stream.finish();
        let all = format!("{early}{}", joined(&drained(&mut receiver)));
        let body = piece.repeat(64);
        assert_eq!(all, body, "text was dropped, duplicated or masked");
        assert_eq!(all, whole(&body));
    }

    /// Multi-byte characters must never make a cut panic, including a 4-byte
    /// emoji straddling `MAX_RELEASE_BYTES`.
    #[test]
    fn multi_byte_characters_never_make_a_cut_panic() {
        let (stream, mut receiver) = stream();
        let prefix = "a".repeat(MAX_RELEASE_BYTES - 1);
        let body = format!("{prefix}😀 password=SECRET0123456789 done");
        stream.push(&body, 1);
        stream.flush();
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(!text.contains("SECRET0123456789"), "{text}");
        assert!(text.contains("<redacted>") || text.contains("😀"), "{text}");
        assert_eq!(text, whole(&body));
    }

    /// `[DONE]`-style behaviour: a partial word is only flushed at `finish`.
    #[test]
    fn the_held_tail_is_flushed_on_finish_not_before() {
        let (stream, mut receiver) = stream();
        stream.push("onl", 1);
        stream.flush();
        let early = drained(&mut receiver);
        assert!(
            early.is_empty() || !joined(&early).contains("onl"),
            "a partial word must be held: {early:?}"
        );
        stream.finish();
        let text = joined(&drained(&mut receiver));
        assert!(text.contains("onl"), "the held tail is flushed: {text}");
    }

    /// B5-1 regression: a registered key in a separator-joined hex-dump
    /// spelling must never surface when the dump is split across deltas. The
    /// streamed output is identical to the whole-buffer scrub at every split
    /// point because it is emitted from that scrub.
    #[test]
    fn b5_dump_hex_split_leak_hunt() {
        let canary = format!("CNR7B51{}", 8_765_432_109u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let pairs: Vec<String> = canary.bytes().map(|byte| format!("{byte:02x}")).collect();
        let contiguous: String = pairs.concat();
        let mut spellings = Vec::new();
        for separator in [":", "-", ",", ".", "_", "|", " "] {
            spellings.push(pairs.join(separator));
        }
        spellings.push(
            pairs
                .iter()
                .map(|pair| format!("0x{pair}"))
                .collect::<Vec<_>>()
                .join(" "),
        );
        spellings.push(pairs.iter().map(|pair| format!("\\x{pair}")).collect());
        for spelling in spellings {
            let text = format!("dump {spelling} done");
            let whole = scrub(Path::new(HOME), &text);
            assert!(
                whole.contains(MASK_MARKER),
                "the whole-buffer pass did not mask {spelling:?}: {whole:?}"
            );
            for position in text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()])
            {
                let all = split_with_a_flush(&text, position);
                assert_eq!(
                    all, whole,
                    "split at {position} changed the output for {spelling:?}"
                );
                assert!(
                    !all.contains(&contiguous),
                    "the dump spelling leaked at {position}: {all:?}"
                );
            }
        }
    }

    /// Security review R6-1 (B6-1): the all-byte `%NN` spelling of a *registered* secret
    /// streams raw at 55/59 split boundaries under the old hold. The output
    /// must equal the whole-buffer scrub at every boundary, including the
    /// report's `[1, 25]` cuts and the `x…x` probe with a flush after five
    /// bytes.
    #[test]
    fn b6_suppress_drop_depth_and_pct_leak() {
        let canary = "CNR6MIX!8619432705+";
        assert!(kernel_broker::scrub::register_known_secret(canary));
        let pct = percent_bytes(canary, true);
        let text = format!("percent-all {pct} end");
        let expected = whole(&text);
        assert!(expected.contains(MASK_MARKER), "{expected:?}");
        assert!(!expected.contains(&pct), "{expected:?}");
        assert_eq!(
            streamed_with_cuts(&text, &[1, 25]),
            expected,
            "the report's [1, 25] cuts diverged"
        );
        // glm B6-1: `x…x` with a flush after the first five bytes.
        let probe = format!("x{pct}x");
        let expected = whole(&probe);
        assert_eq!(streamed_with_cuts(&probe, &[5]), expected);
        assert!(
            !streamed_with_cuts(&probe, &[5]).contains("%43%4E"),
            "the percent spelling leaked"
        );
        // And every split boundary of the probe.
        for position in probe
            .char_indices()
            .map(|(index, _)| index)
            .chain([probe.len()])
        {
            let all = split_with_a_flush(&probe, position);
            assert!(
                !all.contains(&pct),
                "the spelling leaked at {position}: {all}"
            );
            assert_eq!(all, expected, "split at {position}");
        }
    }

    /// B6-2: a flush inside the `==`-padding tail of a base64 secret must
    /// not drop the rest of the answer's run. The old `drain` tail-masked
    /// branch swallowed the remainder's leading run bytes (`200 z`); the
    /// redesign holds the construct and reproduces the whole-buffer scrub
    /// byte for byte at every flush position.
    #[test]
    fn b6_b64_pad_drop_depth() {
        let canary = format!("{}{}", "CNR6B64PADDEPTH", "0123456789abcdef");
        assert_eq!(canary.len(), 31, "the `==` padding tail needs 31 bytes");
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let b64 = base64_bytes(&canary);
        assert!(b64.ends_with("=="), "the probe needs a padded tail: {b64}");
        let text = format!("dump {b64}{}", "z".repeat(200));
        let expected = whole(&text);
        assert_eq!(
            expected,
            format!("dump {MASK_MARKER}{}", "z".repeat(200)),
            "the whole-buffer baseline changed"
        );
        // The report's padding-tail range plus every other boundary.
        for position in 34..=55usize {
            let all = split_with_a_flush(&text, position);
            assert_eq!(
                all, expected,
                "a flush at {position} changed the output (padding tail)"
            );
        }
        for position in text
            .char_indices()
            .map(|(index, _)| index)
            .chain([text.len()])
        {
            let all = split_with_a_flush(&text, position);
            assert_eq!(all, expected, "a flush at {position} changed the output");
        }
    }

    /// The required spelling families — colon, dash, comma, agent, underscore,
    /// pipe, `0x`, `\x`, hex (both cases), base64, base64url, base32 and
    /// percent — at every split boundary and with 2, 3 and 4 deltas.
    #[test]
    fn every_spelling_split_at_every_boundary_matches_the_whole_buffer() {
        let canary = format!("CNR7E{}", 246_810_121u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        for (label, text) in spelling_texts(&canary) {
            let expected = whole(&text);
            let boundaries: Vec<usize> = text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()])
                .collect();
            // Every single boundary and every 3-way split; 4-way splits are
            // thinned by a stride to keep the sweep linear.
            for position in &boundaries {
                let all = split_with_a_flush(&text, *position);
                assert_eq!(all, expected, "{label} split at {position}");
            }
            for (k, stride) in [(3usize, 1usize), (4usize, 2usize)] {
                for combo in cut_combinations(&boundaries, k - 1, stride) {
                    let all = streamed_with_cuts(&text, &combo);
                    assert_eq!(all, expected, "{label} {k}-way split at {combo:?}");
                }
            }
        }
    }

    /// Mixed separator spellings, including the `;` family the whole-buffer
    /// hex decoder does not join: whatever the whole-buffer scrub returns
    /// (mask or verbatim), the stream must return the same bytes.
    #[test]
    fn mixed_separators_including_semicolon_match_the_whole_buffer() {
        let canary = format!("CNR7MIX{}", 864_209_753u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let pairs: Vec<String> = canary.bytes().map(|byte| format!("{byte:02x}")).collect();
        let cycle = [":", "-", ",", ".", "_", "|", ";", " "];
        let cycled: String = pairs
            .iter()
            .enumerate()
            .map(|(index, pair)| format!("{pair}{}", cycle[index % cycle.len()]))
            .collect();
        let semicolon_escaped: String = pairs.iter().map(|pair| format!("\\x{pair};")).collect();
        let semicolon_zero_x: String = pairs.iter().map(|pair| format!("0x{pair};")).collect();
        let semicolon_percent: String =
            canary.bytes().map(|byte| format!("%{byte:02x};")).collect();
        let texts = [
            ("cycled", format!("dump {cycled} done")),
            (
                "backslash-x-semicolon",
                format!("dump {semicolon_escaped} done"),
            ),
            ("zero-x-semicolon", format!("dump {semicolon_zero_x} done")),
            (
                "percent-semicolon",
                format!("dump {semicolon_percent} done"),
            ),
        ];
        for (label, text) in texts {
            let expected = whole(&text);
            let boundaries: Vec<usize> = text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()])
                .collect();
            for position in &boundaries {
                let all = split_with_a_flush(&text, *position);
                assert_eq!(all, expected, "{label} split at {position}");
            }
            for combo in cut_combinations(&boundaries, 3, 1) {
                let all = streamed_with_cuts(&text, &combo);
                assert_eq!(all, expected, "{label} 4-way split at {combo:?}");
            }
        }
    }

    /// UTF-8 multibyte characters and bidi isolates: secret-free text must
    /// survive byte for byte, and a registered value stuffed with isolates
    /// must be masked whole, at every split boundary.
    #[test]
    fn utf8_multibyte_and_bidi_splits_match_the_whole_buffer() {
        let prose = "ünïcode 😀 中 🚀 \u{2066}bidi\u{2067} \u{2068}isolates\u{2069} done";
        let expected = whole(prose);
        assert_eq!(expected, prose);
        for position in prose
            .char_indices()
            .map(|(index, _)| index)
            .chain([prose.len()])
        {
            let all = split_with_a_flush(prose, position);
            assert_eq!(all, expected, "split at {position} changed the bytes");
        }

        let canary = format!("CNR7BIDI2{}", 2_718_281_828u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let hidden: String = canary.chars().map(|c| format!("\u{2066}{c}")).collect();
        let text = format!("token={hidden} end");
        let expected = whole(&text);
        assert!(
            !expected.contains(&canary),
            "the hidden value leaked: {expected:?}"
        );
        assert!(expected.contains(MASK_MARKER), "{expected:?}");
        for position in text
            .char_indices()
            .map(|(index, _)| index)
            .chain([text.len()])
        {
            let all = split_with_a_flush(&text, position);
            assert!(
                !all.contains(&canary),
                "the hidden value leaked at {position}"
            );
            assert_eq!(all, expected, "split at {position}");
        }
    }

    /// dh-1 SB6-02 at the stream layer: a flush between deltas that lands on
    /// a multi-byte character must never panic or change the emitted bytes.
    #[test]
    fn a_multibyte_split_keeps_the_bytes_identical() {
        let text = "emoji 😀 ünïcode 中 🚀 done";
        for (position, _) in text.char_indices().skip(1) {
            let all = split_with_a_flush(text, position);
            assert_eq!(all, text, "split at {position} changed the bytes");
        }
    }

    /// dh-1 fidelity note: secret-free text keeps its bidi isolate controls
    /// through the stream; an isolate stuffed into a registered value is
    /// still consumed by the mask.
    #[test]
    fn bidi_isolates_survive_secret_free_text_but_not_a_hidden_secret() {
        let prose = "مرحبا \u{2066}mixed\u{2067} \u{2068}text\u{2069} done";
        let (plain, mut receiver) = stream();
        plain.push(prose, 1);
        plain.finish();
        assert_eq!(joined(&drained(&mut receiver)), prose);

        let canary = format!("CNR7BIDI{}", 1_357_924_680u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let hidden: String = canary.chars().map(|c| format!("\u{2066}{c}")).collect();
        let hidden_text = format!("token={hidden} end");
        let (secretly, mut receiver) = stream();
        secretly.push(&hidden_text, 1);
        secretly.finish();
        let all = joined(&drained(&mut receiver));
        assert!(!all.contains(&canary), "the hidden value leaked: {all:?}");
        assert!(all.contains(MASK_MARKER), "{all:?}");
        assert_eq!(all, whole(&hidden_text));
    }

    /// The documented continuation after a registry change invalidates the
    /// emitted prefix: the already-emitted bytes plus the scrub of the raw
    /// suffix from the consumed offset, with one window of left context used
    /// only for mask detection. A test-side restatement of the contract.
    fn expected_continuation(raw: &str, live_start: usize, window: usize) -> String {
        let context = window.min(live_start);
        let seg_start = live_start - context;
        let seg = &raw[seg_start..];
        let seg_scrub = scrub(Path::new(HOME), seg);
        let head = scrub(Path::new(HOME), &seg[..context]);
        let from = if seg_scrub.starts_with(head.as_str()) {
            head.len()
        } else {
            common_prefix_len(seg_scrub.as_bytes(), head.as_bytes())
        };
        seg_scrub[from..].to_string()
    }

    /// R7-1 (a security review): a secret registered *after* its raw bytes were already
    /// emitted must not panic and must not garble, duplicate or drop text:
    /// the stream continues with the scrub of the remaining raw suffix. The
    /// already-published prefix cannot be recalled — the documented inherent
    /// limit — and no fresh leak appears past the re-anchor point.
    #[test]
    fn r7_late_registration_after_emitted_raw_no_panic() {
        let canary = format!("CNR7LATE_{}", 6_024_198_357u64);
        let text = format!("before {canary} after {}", "x".repeat(8000));
        let (stream, mut receiver) = stream();
        stream.push(&text, 1);
        stream.flush();
        let early = joined(&drained(&mut receiver));
        let cut = kernel_core::lock_recover(&stream.state).emitted_raw;
        assert!(
            early.contains(&canary),
            "the pre-registration prefix streams raw (the inherent limit)"
        );
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        stream.push(" tail", 2);
        stream.flush();
        stream.finish();
        let rest = joined(&drained(&mut receiver));
        let all = format!("{early}{rest}");
        let body = format!("{text} tail");
        assert_eq!(
            all,
            format!(
                "{}{}",
                &body[..cut],
                expected_continuation(&body, cut, stream.window())
            ),
            "the post-change continuation must be the documented suffix scrub"
        );
        assert_eq!(all, format!("{}{}", &body[..cut], whole(&body[cut..])));
        assert!(
            !rest.contains(&canary),
            "a fresh leak appeared past the re-anchor point: {rest:?}"
        );
        assert!(
            leaked_window(&rest, &canary).is_none(),
            "a window of the canary leaked past the re-anchor point"
        );
    }

    /// R7-1 (GLM): the same for a run-heavy body (the first flush cut is
    /// moved to the run start), with the registration in the middle of the
    /// stream.
    #[test]
    fn r7_late_registration_mid_stream_no_panic() {
        let canary = format!("CNR7GLM_{}", 314_159_265u64);
        let text = format!("{canary} leaked-before {}", "z".repeat(6000));
        let (stream, mut receiver) = stream();
        stream.push(&text, 1);
        stream.flush();
        let early = joined(&drained(&mut receiver));
        let cut = kernel_core::lock_recover(&stream.state).emitted_raw;
        assert!(early.contains(&canary), "{early:?}");
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        stream.push(" more", 2);
        stream.flush();
        stream.finish();
        let rest = joined(&drained(&mut receiver));
        let all = format!("{early}{rest}");
        let body = format!("{text} more");
        assert_eq!(all, format!("{}{}", &body[..cut], whole(&body[cut..])));
        assert_eq!(
            rest,
            expected_continuation(&body, cut, stream.window()),
            "the continuation diverged from the contract"
        );
        assert!(!rest.contains(&canary), "{rest:?}");
    }

    /// R7-1 (sibling stream): a value registered by *another* stream while
    /// this one is live takes the same deterministic path.
    #[test]
    fn r7_sibling_stream_registration_after_emission_is_well_formed() {
        let canary = format!("CNR7SIB_{}", 271_828_182u64);
        let text = format!("before {canary} after {}", "y".repeat(6000));
        let (main_stream, mut receiver) = stream();
        main_stream.push(&text, 1);
        main_stream.flush();
        let early = joined(&drained(&mut receiver));
        let cut = kernel_core::lock_recover(&main_stream.state).emitted_raw;
        // A sibling stream is live and registers the value.
        let (sibling, mut sibling_receiver) = stream();
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        main_stream.push(" tail", 2);
        main_stream.finish();
        sibling.finish();
        let _ = drained(&mut sibling_receiver);
        let rest = joined(&drained(&mut receiver));
        let all = format!("{early}{rest}");
        let body = format!("{text} tail");
        assert_eq!(
            rest,
            expected_continuation(&body, cut, main_stream.window()),
            "the sibling-triggered continuation diverged"
        );
        assert_eq!(all, format!("{}{}", &body[..cut], whole(&body[cut..])));
        assert!(!rest.contains(&canary), "{rest:?}");
    }

    /// R7-1 (encoded spelling): the flush cut lands *inside* a colon-hex
    /// spelling of a value that is registered afterwards. The already
    /// emitted part is raw (the inherent limit), the remaining spelling is
    /// covered by one mask token, and the continuation matches the
    /// documented suffix scrub exactly.
    #[test]
    fn r7_encoded_spelling_straddling_the_emitted_offset() {
        let canary = format!("CNR7ENC_{}", 112_358_813u64);
        let spelling: String = canary
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        // Filler, then the spelling, then a spaced tail: with the fixed
        // window and the rescan step the first flush cut lands inside the
        // spelling (the pending gate needs at least W + 4 KiB of text).
        let text = format!(
            "{}dump {} {}",
            "f ".repeat(2050),
            spelling,
            "t ".repeat(700)
        );
        let spelling_start = text.find(&spelling).expect("spelling present");
        let (stream, mut receiver) = stream();
        stream.push(&text, 1);
        stream.flush();
        let early = joined(&drained(&mut receiver));
        let cut = kernel_core::lock_recover(&stream.state).emitted_raw;
        assert!(
            cut > spelling_start && cut < spelling_start + spelling.len(),
            "the cut must land inside the spelling for this probe: {cut}"
        );
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        stream.finish();
        let rest = joined(&drained(&mut receiver));
        let all = format!("{early}{rest}");
        assert_eq!(
            rest,
            expected_continuation(&text, cut, stream.window()),
            "the straddling-spelling continuation diverged"
        );
        assert!(rest.contains(MASK_MARKER), "{rest:?}");
        assert!(
            !rest.contains(&spelling[spelling.len() / 2..]),
            "the remaining spelling leaked: {rest:?}"
        );
        assert!(
            all.starts_with(&early),
            "the emitted prefix was not preserved"
        );
    }

    /// R7-4: the `\uNNNN` / `\UNNNNNNNN` / `\u{…}` spelling of a registered
    /// value is masked by the whole-buffer scrub, and the stream matches that
    /// scrub at every split boundary (contiguous and separated forms).
    #[test]
    fn r7_unicode_escaped_spelling_matches_the_whole_buffer_at_every_split() {
        let canary = format!("CNR7UESC{}", 640_128_256u64);
        assert!(kernel_broker::scrub::register_known_secret(&canary));
        let bytes: Vec<u8> = canary.bytes().collect();
        let mut spellings: Vec<String> = vec![
            bytes.iter().map(|b| format!("\\u{b:04x}")).collect(),
            bytes.iter().map(|b| format!("\\U{b:08x}")).collect(),
            bytes.iter().map(|b| format!("\\u{{{b:02x}}}")).collect(),
            bytes.iter().map(|b| format!("\\u{{{b:04x}}}")).collect(),
        ];
        spellings.push(
            bytes
                .iter()
                .map(|b| format!("\\u{b:04x}"))
                .collect::<Vec<_>>()
                .join(" "),
        );
        spellings.push(
            bytes
                .iter()
                .map(|b| format!("\\u{{{b:02x}}}"))
                .collect::<Vec<_>>()
                .join(":"),
        );
        for spelling in spellings {
            let text = format!("dump {spelling} done");
            let expected = whole(&text);
            assert!(
                expected.contains(MASK_MARKER),
                "the whole-buffer scrub missed {spelling:?}: {expected:?}"
            );
            assert!(!expected.contains(&spelling), "{expected:?}");
            for position in text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()])
            {
                let all = split_with_a_flush(&text, position);
                assert_eq!(all, expected, "split at {position} for {spelling:?}");
                assert!(!all.contains(&spelling), "leaked at {position}");
            }
        }
    }

    /// R8 (1): NFKC-compatibility spellings of registered values — ligatures,
    /// fullwidth, superscripts, decomposed combining sequences — must match
    /// the whole-buffer scrub at every split.
    #[test]
    fn r8_nfkc_spelling_matches_the_whole_buffer_at_every_split() {
        let fullwidth = |value: &str| -> String {
            value
                .chars()
                .map(|c| {
                    let cp = c as u32;
                    if (0x21..=0x7E).contains(&cp) {
                        char::from_u32(cp + 0xFEE0).unwrap_or(c)
                    } else {
                        c
                    }
                })
                .collect()
        };
        let pairs: Vec<(&str, String)> = vec![
            ("officeCNR8alpha987", "of\u{FB01}ceCNR8alpha987".to_string()),
            ("flavorCNR8beta987", "\u{FB02}avorCNR8beta987".to_string()),
            ("officeCNR8gamma987", "o\u{FB03}ceCNR8gamma987".to_string()),
            ("officeCNR8delta987", fullwidth("officeCNR8delta987")),
            ("office2CNR8eps987", "office\u{B2}CNR8eps987".to_string()),
            ("caf\u{E9}CNR8eta987", "cafe\u{301}CNR8eta987".to_string()),
        ];
        for (registered, spelled) in pairs {
            assert!(kernel_broker::scrub::register_known_secret(registered));
            let text = format!("free text {spelled} end");
            let expected = whole(&text);
            assert!(
                expected.contains(MASK_MARKER),
                "the whole-buffer scrub missed {spelled:?}: {expected:?}"
            );
            assert!(!expected.contains(&spelled), "{expected:?}");
            for position in text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()])
            {
                let all = split_with_a_flush(&text, position);
                assert_eq!(all, expected, "split at {position} for {spelled:?}");
                assert!(!all.contains(spelled.as_str()), "leaked at {position}");
            }
        }
    }

    /// R8 (2): JSON surrogate-pair escapes of a non-BMP character in a
    /// registered value must match the whole-buffer scrub at every split.
    #[test]
    fn r8_surrogate_pair_spelling_matches_the_whole_buffer_at_every_split() {
        let secret = format!("CNR8{}Surrogate987", '\u{1F600}');
        assert!(kernel_broker::scrub::register_known_secret(&secret));
        let all_escaped: String = secret
            .chars()
            .map(|c| {
                let code = c as u32;
                if code > 0xFFFF {
                    let (high, low) = surrogate_pair(code);
                    format!("\\u{high:04X}\\u{low:04X}")
                } else {
                    format!("\\u{code:04X}")
                }
            })
            .collect();
        let all_escaped_lower: String = secret
            .chars()
            .map(|c| {
                let code = c as u32;
                if code > 0xFFFF {
                    let (high, low) = surrogate_pair(code);
                    format!("\\u{high:04x}\\u{low:04x}")
                } else {
                    format!("\\u{code:04x}")
                }
            })
            .collect();
        let spellings = [
            "CNR8\\uD83D\\uDE00Surrogate987".to_string(),
            "CNR8\\ud83d\\ude00Surrogate987".to_string(),
            "CNR8\\U0001F600Surrogate987".to_string(),
            "CNR8\\u{1F600}Surrogate987".to_string(),
            all_escaped,
            all_escaped_lower,
        ];
        for spelling in spellings {
            let text = format!("dump {spelling} done");
            let expected = whole(&text);
            assert!(
                expected.contains(MASK_MARKER),
                "the whole-buffer scrub missed {spelling:?}: {expected:?}"
            );
            assert!(!expected.contains(&spelling), "{expected:?}");
            for position in text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()])
            {
                let all = split_with_a_flush(&text, position);
                assert_eq!(all, expected, "split at {position} for {spelling:?}");
                assert!(!all.contains(&spelling), "leaked at {position}");
            }
        }
    }

    /// R9 (1): full canonical NFKC — Hangul Jamo composition and canonically
    /// reordered combining marks — must match the whole-buffer scrub at every
    /// split.
    #[test]
    fn r9_nfkc_canonical_reordering_and_hangul_match_at_every_split() {
        let pairs = [
            (
                "\u{D55C}\u{AE00}CNR9KoreanSecret987",
                "\u{1112}\u{1161}\u{11AB}\u{1100}\u{1173}\u{11AF}CNR9KoreanSecret987",
            ),
            (
                "\u{C5}\u{0315}CNR9ZalgoSecret987",
                "A\u{0315}\u{030A}CNR9ZalgoSecret987",
            ),
            (
                "Vi\u{1EC7}tCNR9VietA987",
                "Vie\u{0302}\u{0323}tCNR9VietA987",
            ),
            (
                "Vi\u{1EC7}tCNR9VietB987",
                "Vie\u{0323}\u{0302}tCNR9VietB987",
            ),
        ];
        for (registered, spelled) in pairs {
            assert!(kernel_broker::scrub::register_known_secret(registered));
            let text = format!("public {spelled} end");
            let expected = whole(&text);
            assert!(
                expected.contains(MASK_MARKER),
                "the whole-buffer scrub missed {spelled:?}: {expected:?}"
            );
            for position in text
                .char_indices()
                .map(|(index, _)| index)
                .chain([text.len()])
            {
                let all = split_with_a_flush(&text, position);
                assert_eq!(all, expected, "split at {position} for {spelled:?}");
                assert!(!all.contains(spelled), "leaked at {position}");
            }
        }
    }

    /// R9 (2): every pair of transforms composed on a registered value must
    /// match the whole-buffer scrub at every split (base64-of-hex,
    /// hex-of-base64, percent-of-base64, percent-of-hex, HTML-of-…, …).
    #[test]
    fn r9_composed_transform_pairs_match_at_every_split() {
        let canary = "CNR9~Pair~987";
        assert!(kernel_broker::scrub::register_known_secret(canary));
        type TransformFn = fn(&str) -> String;
        let transforms: Vec<(&str, TransformFn)> = vec![
            ("base64", base64_bytes),
            ("base64url", base64url_bytes),
            ("base32", base32_bytes),
            ("hex", hex_bytes),
            ("escaped-hex", |s| {
                s.bytes().map(|b| format!("\\x{b:02x}")).collect()
            }),
            ("zero-x", |s| {
                s.bytes()
                    .map(|b| format!("0x{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            ("percent", |s| percent_bytes(s, true)),
            ("percent-minimal", percent_minimal_bytes),
            ("percent-all", percent_all_bytes),
            ("html", html_entities_bytes),
            ("json", json_escapes_bytes),
        ];
        let mut checked = 0usize;
        for (first_name, first) in &transforms {
            let step1 = first(canary);
            for (second_name, second) in &transforms {
                let step2 = second(&step1);
                if step2.len() < 8 || step2.len() > 4096 || step2 == canary {
                    // >4096: the registration cap drops ultra-long composed
                    // spellings (see `MAX_VARIANT_LEN` in the scrubber).
                    continue;
                }
                checked += 1;
                let text = format!("dump {step2} done");
                let expected = whole(&text);
                for position in text
                    .char_indices()
                    .map(|(index, _)| index)
                    .chain([text.len()])
                {
                    let all = split_with_a_flush(&text, position);
                    assert_eq!(
                        all, expected,
                        "{first_name}-of-{second_name} split at {position}"
                    );
                    assert!(
                        !all.contains(&step2),
                        "{first_name}-of-{second_name} leaked at {position}"
                    );
                }
            }
        }
        assert!(
            checked > 80,
            "the pair sweep must cover many pairs: {checked}"
        );
    }

    /// A session no other test uses, so its live table is this test's alone.
    const DISPLAY_SESSION: i64 = 4_100_101;
    const EMAIL_TOKEN: &str = "EMAIL_0123456789AB";
    const EMAIL_VALUE: &str = "anne.dupont@example.org";

    /// The loopback and remote receivers of one stream whose session holds
    /// [`EMAIL_TOKEN`] → [`EMAIL_VALUE`].
    fn split_stream() -> (
        Arc<DeltaStream>,
        broadcast::Receiver<String>,
        broadcast::Receiver<String>,
    ) {
        super::super::display::live_tokens().record(
            DISPLAY_SESSION,
            &[(EMAIL_TOKEN.to_string(), EMAIL_VALUE.to_string())],
        );
        let (loopback, loopback_rx) = broadcast::channel(128);
        let (remote, remote_rx) = broadcast::channel(128);
        let sinks = StreamSinks {
            loopback,
            remote: Some(remote),
            lang: Lang::En,
        };
        let stream = DeltaStream::new(
            sinks,
            PathBuf::from(HOME),
            "main",
            DISPLAY_SESSION,
            "draft-display",
        );
        (stream, loopback_rx, remote_rx)
    }

    #[test]
    fn loopback_shows_the_value_and_the_remote_channel_only_tokens() {
        let (stream, mut loopback, mut remote) = split_stream();
        stream.push(&format!("Écrire à ⟦{EMAIL_TOKEN}⟧ demain"), 1);
        stream.finish();

        let shown = joined(&drained(&mut loopback));
        assert_eq!(shown, format!("Écrire à {EMAIL_VALUE} demain"));
        let remote_frames = drained(&mut remote);
        let tokens = joined(&remote_frames);
        assert_eq!(tokens, format!("Écrire à ⟦{EMAIL_TOKEN}⟧ demain"));
        assert!(!format!("{remote_frames:?}").contains(EMAIL_VALUE));
    }

    #[test]
    fn a_token_split_across_deltas_is_never_shown_half_raw() {
        let (stream, mut loopback, mut remote) = split_stream();
        stream.push("Bonjour ⟦EMAIL_01234", 1);
        stream.push("56789AB⟧ merci", 2);
        stream.finish();

        let frames = drained(&mut loopback);
        assert!(frames
            .iter()
            .all(|frame| !frame["text"].as_str().unwrap().contains('⟦')));
        assert_eq!(
            joined(&frames),
            format!("Bonjour {EMAIL_VALUE} merci"),
            "the screen equals the whole-buffer rehydration"
        );
        assert_eq!(
            joined(&drained(&mut remote)),
            "Bonjour ⟦EMAIL_0123456789AB⟧ merci"
        );
    }

    #[test]
    fn an_invented_reference_shows_the_marker_on_screen() {
        let (stream, mut loopback, _remote) = split_stream();
        stream.push("a ⟦EMAIL_FFFFFFFFFFFF⟧ b", 1);
        stream.finish();

        assert_eq!(joined(&drained(&mut loopback)), "a [name hidden] b");
    }
}
