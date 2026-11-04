//! The Mac bridge, daemon side (`docs/phase1.md` §3, work order A2b-d).
//!
//! `auxd` cannot call EventKit or Vision; the bundled Mac app can. One bridge
//! call publishes exactly one `bridge.request` frame on the **existing**
//! authenticated loopback WebSocket (`WS /v1/events`), then waits — bounded —
//! for the app's `POST /v1/bridge/{id}` answer. An unanswered call, or one
//! made while no app socket is connected, is a typed
//! [`BridgeError::Unavailable`].
//!
//! Nothing registers this on a tool surface yet: the tool and its kernel path
//! row B21 land with the kernel pin bump. The type is exercised end to end by
//! `crates/auxd/tests/bridge.rs` so the wiring does not rot.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kernel_core::Lang;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{broadcast, oneshot};
use tokio::time::timeout;

/// Frame `type` the app matches on.
pub const BRIDGE_REQUEST_TYPE: &str = "bridge.request";

/// Largest accepted answer body (1 MiB): an OCR line set can be large.
pub const MAX_BRIDGE_BODY_BYTES: usize = 1024 * 1024;

/// Longest `eventkit.create_event` title, in characters.
const MAX_TITLE_CHARS: usize = 200;

/// Longest `eventkit.update_event` event id, in characters.
const MAX_EVENT_ID_CHARS: usize = 256;

/// Longest `eventkit.create_event` notes, in bytes (8 KiB).
const MAX_NOTES_BYTES: usize = 8 * 1024;

/// How long a finished request id keeps answering `409` instead of `404`.
const FINISHED_TTL: Duration = Duration::from_secs(600);

/// Error code and user text of a bridge that has no app to answer it.
pub const BRIDGE_UNAVAILABLE_CODE: &str = "bridge_unavailable";
/// English text for [`BridgeError::Unavailable`].
pub const BRIDGE_UNAVAILABLE_EN: &str = "Open the Auxesis app on this Mac";
/// French text for [`BridgeError::Unavailable`].
pub const BRIDGE_UNAVAILABLE_FR: &str = "Ouvrez l'app Auxesis sur ce Mac";

/// Ops the app knows how to run for `auxd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeOp {
    /// Create one EventKit event.
    EventkitCreateEvent,
    /// Update one existing EventKit event.
    EventkitUpdateEvent,
    /// Run Vision text recognition on a registry document.
    VisionOcr,
}

impl BridgeOp {
    /// Wire name of the op (the app switches on it).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EventkitCreateEvent => "eventkit.create_event",
            Self::EventkitUpdateEvent => "eventkit.update_event",
            Self::VisionOcr => "vision.ocr",
        }
    }
}

/// Why a bridge call did not produce an app result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// No app socket, or no answer before the deadline.
    Unavailable,
    /// The arguments are malformed; nothing was sent.
    InvalidArgs(String),
    /// The app ran the op and reported a failure.
    App {
        /// Machine-readable code from the app.
        code: String,
        /// Short owner-facing message from the app.
        message: String,
    },
}

impl BridgeError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable => BRIDGE_UNAVAILABLE_CODE,
            Self::InvalidArgs(_) => "invalid_args",
            Self::App { .. } => "app_error",
        }
    }

    /// Owner-facing text in the configured UI language.
    pub fn user_message(&self, lang: Lang) -> String {
        match self {
            Self::Unavailable => match lang {
                Lang::En => BRIDGE_UNAVAILABLE_EN.to_string(),
                Lang::Fr => BRIDGE_UNAVAILABLE_FR.to_string(),
            },
            Self::InvalidArgs(message) | Self::App { message, .. } => message.clone(),
        }
    }
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str(BRIDGE_UNAVAILABLE_EN),
            Self::InvalidArgs(message) => f.write_str(message),
            Self::App { code, message } => write!(f, "the app refused ({code}): {message}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// The app's answer to one request, as the answer route decoded it.
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeAnswer {
    /// `{"ok":true,"result":{…}}`.
    Result(Value),
    /// `{"ok":false,"error":"<code>","message":"…"}`.
    Error {
        /// Machine-readable code from the app.
        code: String,
        /// Short owner-facing message from the app.
        message: String,
    },
}

/// What [`Bridge::answer`] found for an id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerOutcome {
    /// The pending call was woken.
    Accepted,
    /// The id was already answered or timed out (within the retention window).
    Conflict,
    /// No such id.
    Unknown,
}

/// Per-op deadlines; tests pin short ones through [`Bridge::set_timeouts`].
#[derive(Debug, Clone, Copy)]
struct BridgeTimeouts {
    call: Duration,
    ocr: Duration,
}

impl Default for BridgeTimeouts {
    fn default() -> Self {
        Self {
            call: Duration::from_secs(30),
            ocr: Duration::from_secs(60),
        }
    }
}

/// One in-flight request: the waiter that the answer route wakes.
struct Pending {
    answer: oneshot::Sender<BridgeAnswer>,
}

#[derive(Default)]
struct BridgeInner {
    pending: HashMap<String, Pending>,
    /// Ids answered or timed out, kept for [`FINISHED_TTL`] so a replay is a
    /// `409` rather than a silent `404`.
    finished: HashMap<String, Instant>,
}

/// What retiring a fired deadline found in the pending table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimeoutOutcome {
    /// The entry was still pending: the deadline won and retired it.
    TimedOut,
    /// The entry was already gone: the answer route removed it (and sent its
    /// answer) while holding this same lock.
    Answered,
}

impl BridgeInner {
    fn prune_finished(&mut self, now: Instant) {
        self.finished
            .retain(|_, at| now.saturating_duration_since(*at) < FINISHED_TTL);
    }

    /// Retire one id when its deadline fired. The decision is a pure function
    /// of whether the entry is still pending: if it is, the timeout
    /// wins; if not, the answer route won the race under this lock.
    fn retire_on_timeout(&mut self, id: &str) -> TimeoutOutcome {
        match self.pending.remove(id) {
            Some(_) => {
                self.finished.insert(id.to_string(), Instant::now());
                TimeoutOutcome::TimedOut
            }
            None => TimeoutOutcome::Answered,
        }
    }
}

/// Requests to the Mac app over the live events socket.
///
/// "App connected" means at least one authenticated `/v1/events` socket is
/// open. A call publishes its request frame on the shared events broadcast, so
/// the frame reaches **every** authenticated events socket; every app socket
/// is in the same loopback + local-token trust domain. Routing a request to
/// one specific app is separate work, not this one.
pub struct Bridge {
    home: PathBuf,
    events: broadcast::Sender<String>,
    timeouts: Mutex<BridgeTimeouts>,
    inner: Mutex<BridgeInner>,
}

impl Bridge {
    /// Build the bridge on an existing events broadcast sender.
    pub fn new(home: PathBuf, events: broadcast::Sender<String>) -> Self {
        Self {
            home,
            events,
            timeouts: Mutex::new(BridgeTimeouts::default()),
            inner: Mutex::new(BridgeInner::default()),
        }
    }

    /// Override the per-op deadlines (tests pin short ones).
    pub fn set_timeouts(&self, call: Duration, ocr: Duration) {
        *kernel_core::lock_recover(&self.timeouts) = BridgeTimeouts { call, ocr };
    }

    /// Publish one request and wait for the app's answer.
    ///
    /// Validation runs first: a malformed call never reaches the socket and
    /// writes no journal row. No connected app (or no answer before the
    /// deadline) is [`BridgeError::Unavailable`]; an app error is
    /// [`BridgeError::App`].
    pub async fn call(&self, op: BridgeOp, args: Value) -> Result<Value, BridgeError> {
        if let Err(message) = validate_op(op, &args) {
            return Err(BridgeError::InvalidArgs(message));
        }
        let started = Instant::now();
        let id = mint_id();
        // The request row lands first on every path, so request and result
        // rows always pair.
        self.journal_request(op, &id).await;

        if self.events.receiver_count() == 0 {
            self.journal_result(op, &id, "unavailable", started.elapsed())
                .await;
            return Err(BridgeError::Unavailable);
        }

        let (sender, mut receiver) = oneshot::channel();
        {
            let mut inner = kernel_core::lock_recover(&self.inner);
            inner.prune_finished(Instant::now());
            inner.pending.insert(id.clone(), Pending { answer: sender });
        }
        // Retires the id on every exit path below, including a caller whose
        // future is dropped mid-wait.
        let _pending = PendingGuard {
            bridge: self,
            id: id.clone(),
            op,
            started,
        };

        let frame = serde_json::json!({
            "type": BRIDGE_REQUEST_TYPE,
            "id": id,
            "op": op.as_str(),
            "args": args,
        });
        if !send_frame(&self.events, &frame) {
            self.finish(&id);
            self.journal_result(op, &id, "unavailable", started.elapsed())
                .await;
            return Err(BridgeError::Unavailable);
        }

        let deadline = self.deadline(op);
        // `&mut receiver`: the deadline must not drop the channel, so a late
        // answer that raced the timer can still be read.
        let waited = match timeout(deadline, &mut receiver).await {
            Ok(Ok(answer)) => Some(answer),
            // The deadline fired, or the waiter's sender was dropped without
            // an answer. Resolve the race under the pending lock.
            Ok(Err(_)) | Err(_) => self.resolve_timeout(&id, &mut receiver),
        };

        match waited {
            Some(BridgeAnswer::Result(result)) => {
                self.finish(&id);
                self.journal_result(op, &id, "ok", started.elapsed()).await;
                Ok(result)
            }
            Some(BridgeAnswer::Error { code, message }) => {
                self.finish(&id);
                self.journal_result(op, &id, "app_error", started.elapsed())
                    .await;
                Err(BridgeError::App {
                    code: scrub(&self.home, &code, 128),
                    message: scrub(&self.home, &message, 4096),
                })
            }
            None => {
                // `resolve_timeout` already retired the id as timed out.
                self.journal_result(op, &id, "timeout", started.elapsed())
                    .await;
                Err(BridgeError::Unavailable)
            }
        }
    }

    /// Resolve a fired deadline against the pending table.
    ///
    /// If the entry is still pending the timeout wins and `None` is returned.
    /// If it is gone, the answer route removed it while holding the same lock
    /// and already sent its value, so that answer is returned instead of being
    /// lost to the dropped receiver.
    fn resolve_timeout(
        &self,
        id: &str,
        receiver: &mut oneshot::Receiver<BridgeAnswer>,
    ) -> Option<BridgeAnswer> {
        let outcome = {
            let mut inner = kernel_core::lock_recover(&self.inner);
            inner.prune_finished(Instant::now());
            inner.retire_on_timeout(id)
        };
        match outcome {
            TimeoutOutcome::TimedOut => None,
            TimeoutOutcome::Answered => receiver.try_recv().ok(),
        }
    }

    /// Answer one pending request. Exactly one answer wins.
    pub fn answer(&self, id: &str, answer: BridgeAnswer) -> AnswerOutcome {
        let now = Instant::now();
        let mut inner = kernel_core::lock_recover(&self.inner);
        inner.prune_finished(now);
        let Some(pending) = inner.pending.remove(id) else {
            return if inner.finished.contains_key(id) {
                AnswerOutcome::Conflict
            } else {
                AnswerOutcome::Unknown
            };
        };
        inner.finished.insert(id.to_string(), now);
        // The send happens while the lock is held, so a timeout that later
        // finds the entry gone is guaranteed to find the value waiting.
        let _ = pending.answer.send(answer);
        AnswerOutcome::Accepted
    }

    /// Retire one id: no longer pending, and `409` for the retention window.
    fn finish(&self, id: &str) {
        let mut inner = kernel_core::lock_recover(&self.inner);
        inner.pending.remove(id);
        inner.finished.insert(id.to_string(), Instant::now());
    }

    fn deadline(&self, op: BridgeOp) -> Duration {
        let timeouts = *kernel_core::lock_recover(&self.timeouts);
        match op {
            BridgeOp::VisionOcr => timeouts.ocr,
            BridgeOp::EventkitCreateEvent | BridgeOp::EventkitUpdateEvent => timeouts.call,
        }
    }

    /// One `bridge.request` row: the op and id only, never an argument.
    async fn journal_request(&self, op: BridgeOp, id: &str) {
        self.journal(
            "bridge.request",
            serde_json::json!({ "op": op.as_str(), "id": id }),
        )
        .await;
    }

    /// One `bridge.result` row: outcome, op, id and duration only.
    async fn journal_result(&self, op: BridgeOp, id: &str, outcome: &str, elapsed: Duration) {
        self.journal("bridge.result", result_payload(op, id, outcome, elapsed))
            .await;
    }

    /// Append one audit row with the verified-home writer the other auxd
    /// modules use. The store open is blocking, so it runs on the blocking
    /// pool. A failed write is a warning: the call's outcome does not
    /// depend on the audit.
    async fn journal(&self, kind: &str, payload: Value) {
        let (home, kind, text) = (self.home.clone(), kind.to_string(), payload.to_string());
        let result = tokio::task::spawn_blocking(move || write_journal(&home, &kind, &text)).await;
        if let Err(err) = result {
            tracing::warn!(error = %err, "bridge journal task failed");
        }
    }

    /// Best-effort audit for a caller dropped mid-wait, where there is no
    /// await point left to block on. Uses the blocking pool when a runtime is
    /// present, and falls back to a direct write otherwise.
    fn journal_detached(&self, kind: &str, payload: Value) {
        let (home, kind, text) = (self.home.clone(), kind.to_string(), payload.to_string());
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                drop(handle.spawn_blocking(move || write_journal(&home, &kind, &text)));
            }
            Err(_) => write_journal(&self.home, &kind, &text),
        }
    }
}

/// The `bridge.result` payload: outcome, op, id and duration only. An argument
/// value is never included.
fn result_payload(op: BridgeOp, id: &str, outcome: &str, elapsed: Duration) -> Value {
    serde_json::json!({
        "op": op.as_str(),
        "id": id,
        "outcome": outcome,
        "duration_ms": elapsed.as_millis() as u64,
    })
}

/// Test-only: the thread that last ran [`write_journal`], so a unit test can
/// prove the blocking store open is not run on the async worker.
#[cfg(test)]
static JOURNAL_THREAD: Mutex<Option<std::thread::ThreadId>> = Mutex::new(None);

/// The blocking body of one audit write. A failed write is a warning: it never
/// fails the call.
fn write_journal(home: &std::path::Path, kind: &str, text: &str) {
    #[cfg(test)]
    {
        *kernel_core::lock_recover(&JOURNAL_THREAD) = Some(std::thread::current().id());
    }
    let result = kernel_core::verified_home_or_verify(home)
        .map_err(aux_store::StoreError::from)
        .and_then(|home| aux_store::Store::open_verified(&home))
        .and_then(|store| store.log_event(kind, text));
    if let Err(err) = result {
        tracing::warn!(kind, error = %err, "bridge journal write failed");
    }
}

/// Retires one request id on every exit path, including a dropped caller.
/// The guard is armed while the id is pending; a normal exit retires
/// the id first, so the drop finds nothing left to do.
struct PendingGuard<'a> {
    bridge: &'a Bridge,
    id: String,
    op: BridgeOp,
    started: Instant,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let retired = {
            let mut inner = kernel_core::lock_recover(&self.bridge.inner);
            match inner.pending.remove(&self.id) {
                Some(_) => {
                    inner.finished.insert(self.id.clone(), Instant::now());
                    true
                }
                None => false,
            }
        };
        if retired {
            // The caller's future was dropped without a result.
            self.bridge.journal_detached(
                "bridge.result",
                result_payload(self.op, &self.id, "cancelled", self.started.elapsed()),
            );
        }
    }
}

/// Publish one JSON frame; an unserializable frame (or a closed channel) is a
/// failed send.
fn send_frame(events: &broadcast::Sender<String>, value: &Value) -> bool {
    match serde_json::to_string(value) {
        Ok(text) => events.send(text).is_ok(),
        Err(_) => false,
    }
}

/// Scrub one app-supplied string before it can reach a log or a model.
fn scrub(home: &std::path::Path, text: &str, max_bytes: usize) -> String {
    kernel_broker::scrub_external_preview(home, text, max_bytes)
}

/// Validate one op's args before anything is sent or journaled.
///
/// Each op has its own closed argument shape; an unknown field or a malformed
/// value is refused and writes neither journal row.
fn validate_op(op: BridgeOp, args: &Value) -> Result<(), String> {
    match op {
        BridgeOp::EventkitCreateEvent => validate_create_event(args),
        BridgeOp::EventkitUpdateEvent => validate_update_event(args),
        BridgeOp::VisionOcr => validate_ocr(args),
    }
}

/// `eventkit.create_event` args, exactly as `phase1.md` §3 lists them.
///
/// `deny_unknown_fields` needs the whole allowlist to refuse an `attendees`
/// key; only title, notes and the two times are validated.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEventArgs {
    #[serde(default)]
    calendar: Option<String>,
    title: String,
    start: String,
    end: String,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// Validate one `eventkit.create_event` argument object.
///
/// Denying unknown fields is what keeps attendees out: EventKit cannot add
/// them, so an invite goes by mail instead (`docs/mail.md` §5).
fn validate_create_event(args: &Value) -> Result<(), String> {
    let parsed: CreateEventArgs =
        serde_json::from_value(args.clone()).map_err(|_| "invalid event arguments".to_string())?;
    if parsed.title.chars().count() > MAX_TITLE_CHARS {
        return Err(format!(
            "event title is longer than {MAX_TITLE_CHARS} characters"
        ));
    }
    if let Some(notes) = &parsed.notes {
        if notes.len() > MAX_NOTES_BYTES {
            return Err("event notes are longer than 8 KiB".to_string());
        }
    }
    let start = chrono::DateTime::parse_from_rfc3339(&parsed.start)
        .map_err(|_| "event start is not an RFC 3339 time".to_string())?;
    let end = chrono::DateTime::parse_from_rfc3339(&parsed.end)
        .map_err(|_| "event end is not an RFC 3339 time".to_string())?;
    if end <= start {
        return Err("event end must be after its start".to_string());
    }
    Ok(())
}

/// `eventkit.update_event` args: an `event_id` plus the same optional fields as
/// create. Everything but `event_id` is optional; unknown fields are refused.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateEventArgs {
    event_id: String,
    #[serde(default)]
    calendar: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    url: Option<String>,
    /// The calendar the event must still sit on. The app
    /// refuses the write when the live event is on another calendar.
    #[serde(default)]
    expected_calendar_id: Option<String>,
    /// The guest count the event must still have.
    #[serde(default)]
    expected_attendees: Option<usize>,
}

/// Validate one `eventkit.update_event` argument object.
fn validate_update_event(args: &Value) -> Result<(), String> {
    let parsed: UpdateEventArgs =
        serde_json::from_value(args.clone()).map_err(|_| "invalid event arguments".to_string())?;
    if parsed.event_id.is_empty() || parsed.event_id.chars().count() > MAX_EVENT_ID_CHARS {
        return Err(format!(
            "event id must be 1 to {MAX_EVENT_ID_CHARS} characters"
        ));
    }
    if let Some(title) = &parsed.title {
        if title.chars().count() > MAX_TITLE_CHARS {
            return Err(format!(
                "event title is longer than {MAX_TITLE_CHARS} characters"
            ));
        }
    }
    if let Some(notes) = &parsed.notes {
        if notes.len() > MAX_NOTES_BYTES {
            return Err("event notes are longer than 8 KiB".to_string());
        }
    }
    let start = match &parsed.start {
        Some(text) => Some(
            chrono::DateTime::parse_from_rfc3339(text)
                .map_err(|_| "event start is not an RFC 3339 time".to_string())?,
        ),
        None => None,
    };
    let end = match &parsed.end {
        Some(text) => Some(
            chrono::DateTime::parse_from_rfc3339(text)
                .map_err(|_| "event end is not an RFC 3339 time".to_string())?,
        ),
        None => None,
    };
    if let (Some(start), Some(end)) = (start, end) {
        if end <= start {
            return Err("event end must be after its start".to_string());
        }
    }
    // The expected facts are names and a count: both bounded.
    if parsed.expected_calendar_id.is_some() != parsed.expected_attendees.is_some() {
        return Err("the expected facts must travel as a pair".to_string());
    }
    if let Some(calendar_id) = &parsed.expected_calendar_id {
        if calendar_id.is_empty() || calendar_id.chars().count() > MAX_EVENT_ID_CHARS {
            return Err("the expected calendar id is not a usable id".to_string());
        }
    }
    if parsed
        .expected_attendees
        .is_some_and(|count| count > crate::apple_eventkit::MAX_ATTENDEES)
    {
        return Err("the expected guest count is too large".to_string());
    }
    Ok(())
}

/// `vision.ocr` args: exactly one lowercase-hex `sha256`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OcrArgs {
    sha256: String,
}

/// Validate one `vision.ocr` argument object: exactly `{sha256}` with 64
/// lowercase hex characters.
fn validate_ocr(args: &Value) -> Result<(), String> {
    let parsed: OcrArgs =
        serde_json::from_value(args.clone()).map_err(|_| "invalid OCR arguments".to_string())?;
    let hash = &parsed.sha256;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("sha256 must be 64 lowercase hex characters".to_string());
    }
    Ok(())
}

/// Counter only used by the practically unreachable `/dev/urandom` fallback.
static ID_FALLBACK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Mint one UUID v4 (RFC 4122) from the OS CSPRNG, with a time+counter
/// fallback so a missing `/dev/urandom` cannot abort a bridge call.
fn mint_id() -> String {
    let mut bytes = [0u8; 16];
    let random = std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_ok();
    if !random {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let seq = u128::from(ID_FALLBACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        bytes.copy_from_slice(&(now ^ (seq << 64)).to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> Value {
        serde_json::json!({
            "title": "Dinner",
            "start": "2030-01-01T19:00:00Z",
            "end": "2030-01-01T20:00:00Z",
        })
    }

    #[test]
    fn op_names_match_the_contract() {
        assert_eq!(
            BridgeOp::EventkitCreateEvent.as_str(),
            "eventkit.create_event"
        );
        assert_eq!(
            BridgeOp::EventkitUpdateEvent.as_str(),
            "eventkit.update_event"
        );
        assert_eq!(BridgeOp::VisionOcr.as_str(), "vision.ocr");
    }

    #[test]
    fn unavailable_text_is_localised() {
        let error = BridgeError::Unavailable;
        assert_eq!(error.code(), "bridge_unavailable");
        assert_eq!(
            error.user_message(Lang::En),
            "Open the Auxesis app on this Mac"
        );
        assert_eq!(
            error.user_message(Lang::Fr),
            "Ouvrez l'app Auxesis sur ce Mac"
        );
    }

    #[test]
    fn create_event_validation_accepts_the_listed_shape() {
        assert!(validate_create_event(&valid_args()).is_ok());
        for (label, args) in [
            (
                "end before start",
                serde_json::json!({
                    "title": "x",
                    "start": "2030-01-01T20:00:00Z",
                    "end": "2030-01-01T19:00:00Z",
                }),
            ),
            (
                "attendees are refused",
                serde_json::json!({
                    "title": "x",
                    "start": "2030-01-01T19:00:00Z",
                    "end": "2030-01-01T20:00:00Z",
                    "attendees": ["a@example.com"],
                }),
            ),
            (
                "missing end",
                serde_json::json!({ "title": "x", "start": "2030-01-01T19:00:00Z" }),
            ),
            (
                "title too long",
                serde_json::json!({
                    "title": "t".repeat(201),
                    "start": "2030-01-01T19:00:00Z",
                    "end": "2030-01-01T20:00:00Z",
                }),
            ),
            (
                "notes too long",
                serde_json::json!({
                    "title": "x",
                    "start": "2030-01-01T19:00:00Z",
                    "end": "2030-01-01T20:00:00Z",
                    "notes": "n".repeat(8 * 1024 + 1),
                }),
            ),
        ] {
            assert!(
                validate_create_event(&args).is_err(),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn minted_ids_are_uuid_v4_shaped_and_unique() {
        let first = mint_id();
        let second = mint_id();
        assert_ne!(first, second);
        assert_eq!(first.len(), 36);
        let fields: Vec<&str> = first.split('-').collect();
        assert_eq!(
            fields.iter().map(|field| field.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(first.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert_eq!(&first[14..15], "4", "version nibble");
        assert!(
            matches!(&first[19..20], "8" | "9" | "a" | "b"),
            "variant nibble: {first}"
        );
    }

    fn test_bridge() -> (tempfile::TempDir, Bridge) {
        let dir = tempfile::tempdir().unwrap();
        let (events, _frames) = broadcast::channel(4);
        let bridge = Bridge::new(dir.path().to_path_buf(), events);
        (dir, bridge)
    }

    #[test]
    fn update_event_validation_needs_an_id_and_ordered_times() {
        assert!(validate_op(
            BridgeOp::EventkitUpdateEvent,
            &serde_json::json!({ "event_id": "evt-1", "title": "Dinner" })
        )
        .is_ok());
        assert!(validate_op(
            BridgeOp::EventkitUpdateEvent,
            &serde_json::json!({
                "event_id": "evt-1",
                "start": "2030-01-01T19:00:00Z",
                "end": "2030-01-01T20:00:00Z",
            })
        )
        .is_ok());
        for (label, args) in [
            ("missing event_id", serde_json::json!({ "title": "x" })),
            ("empty event_id", serde_json::json!({ "event_id": "" })),
            (
                "event_id too long",
                serde_json::json!({ "event_id": "e".repeat(257) }),
            ),
            (
                "unknown field",
                serde_json::json!({ "event_id": "e", "attendees": [] }),
            ),
            (
                "title too long",
                serde_json::json!({ "event_id": "e", "title": "t".repeat(201) }),
            ),
            (
                "notes too long",
                serde_json::json!({ "event_id": "e", "notes": "n".repeat(8 * 1024 + 1) }),
            ),
            (
                "end before start",
                serde_json::json!({
                    "event_id": "e",
                    "start": "2030-01-01T20:00:00Z",
                    "end": "2030-01-01T19:00:00Z",
                }),
            ),
            (
                "bad start",
                serde_json::json!({ "event_id": "e", "start": "yesterday" }),
            ),
        ] {
            assert!(
                validate_op(BridgeOp::EventkitUpdateEvent, &args).is_err(),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn ocr_validation_wants_one_lowercase_sha256() {
        assert!(validate_op(
            BridgeOp::VisionOcr,
            &serde_json::json!({ "sha256": "a".repeat(64) })
        )
        .is_ok());
        for (label, args) in [
            ("missing", serde_json::json!({})),
            ("uppercase", serde_json::json!({ "sha256": "A".repeat(64) })),
            ("too short", serde_json::json!({ "sha256": "a".repeat(63) })),
            ("non hex", serde_json::json!({ "sha256": "g".repeat(64) })),
            (
                "unknown field",
                serde_json::json!({ "sha256": "a".repeat(64), "path": "/etc/passwd" }),
            ),
        ] {
            assert!(
                validate_op(BridgeOp::VisionOcr, &args).is_err(),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn a_timeout_retires_pending_or_recovers_an_answered_race() {
        let (_dir, bridge) = test_bridge();
        let id = "race-id";

        // Still pending: the deadline wins and retires the id.
        let (sender, mut receiver) = oneshot::channel();
        {
            let mut inner = kernel_core::lock_recover(&bridge.inner);
            inner
                .pending
                .insert(id.to_string(), Pending { answer: sender });
        }
        assert_eq!(bridge.resolve_timeout(id, &mut receiver), None);
        {
            let inner = kernel_core::lock_recover(&bridge.inner);
            assert!(!inner.pending.contains_key(id));
            assert!(inner.finished.contains_key(id));
        }

        // The answer route removed the entry first: its value is recovered
        // rather than lost to the timeout.
        let answer = BridgeAnswer::Result(serde_json::json!({ "event_id": "evt-race" }));
        let (sender, mut receiver) = oneshot::channel();
        {
            let mut inner = kernel_core::lock_recover(&bridge.inner);
            inner
                .pending
                .insert(id.to_string(), Pending { answer: sender });
        }
        assert_eq!(bridge.answer(id, answer.clone()), AnswerOutcome::Accepted);
        assert_eq!(bridge.resolve_timeout(id, &mut receiver), Some(answer));
    }

    #[test]
    fn a_dropped_guard_retires_its_pending_id() {
        let (_dir, bridge) = test_bridge();
        let id = "abandoned-id";
        let (sender, _receiver) = oneshot::channel();
        {
            let mut inner = kernel_core::lock_recover(&bridge.inner);
            inner
                .pending
                .insert(id.to_string(), Pending { answer: sender });
        }
        {
            let _guard = PendingGuard {
                bridge: &bridge,
                id: id.to_string(),
                op: BridgeOp::EventkitCreateEvent,
                started: Instant::now(),
            };
        }
        let inner = kernel_core::lock_recover(&bridge.inner);
        assert!(
            !inner.pending.contains_key(id),
            "the guard must retire the id"
        );
        assert!(
            inner.finished.contains_key(id),
            "a retired id answers 409, not 404"
        );
    }

    #[tokio::test]
    async fn the_journal_write_runs_off_the_async_worker() {
        let (_dir, bridge) = test_bridge();
        *kernel_core::lock_recover(&JOURNAL_THREAD) = None;
        bridge
            .journal("bridge.result", serde_json::json!({ "outcome": "ok" }))
            .await;
        let worker = std::thread::current().id();
        let writer = *kernel_core::lock_recover(&JOURNAL_THREAD);
        assert!(writer.is_some(), "the journal write must run");
        assert_ne!(
            writer.unwrap(),
            worker,
            "the blocking store open must not run on the async worker"
        );
    }
}
