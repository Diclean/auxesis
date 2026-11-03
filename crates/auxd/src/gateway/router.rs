//! The daemon's outbound router (D34, G1): every daemon-originated message
//! goes through the notify policy first, and the admitted value is delivered
//! through the [`Gateway`] trait.
//!
//! The job runners are synchronous, so the policy decision is synchronous and
//! the delivery is queued through a bounded [`GatewaySink`] to an async worker
//! ([`run_worker`]). The worker delivers to every paired gateway, and falls
//! back to the local display when none is paired. Tests inject a recording
//! sink, so no clock, runtime or network is needed. The policy state is a small
//! mode-0600 JSON file under the verified home (lighter than a new store
//! table), so a restart keeps the daily counter and the dropped list; a corrupt
//! file is quarantined and the policy fails closed.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_notify::{Notification, Notifier, NotifyError};
use kernel_core::privacy::ModeFn;
use kernel_core::SandboxHome;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::policy::{Action, Level, Notice, NotifyPolicy, PolicyState};
use super::{imessage, ApprovalBody, ApprovalCard, Gateway, GatewayError, OutboundText, SendCause};

/// Low-priority lane capacity: info/normal drop the oldest past it.
pub const OUTBOUND_QUEUE_CAPACITY: usize = 256;
/// High-priority lane capacity: urgent, briefs and cards wait, never drop.
pub const OUTBOUND_URGENT_CAPACITY: usize = 64;
/// How many dropped notices the brief lists; the count stays exact.
pub const MAX_SINK_DROPS: usize = 64;
/// Maximum bytes retained in each queued text field.
pub const MAX_PENDING_TEXT_BYTES: usize = 16 * 1024;
/// How long a brief run waits for the worker's delivery report: under the
/// CLI's 30 s request timeout. A slower send reads as unconfirmed.
pub const BRIEF_REPORT_WAIT: Duration = Duration::from_secs(20);

/// What became of a brief; across channels the greatest wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BriefOutcome {
    /// The mode held it and no channel carried a notice.
    Held,
    /// A send failed (with the transport's cause when it gave one), nothing
    /// was queued, or the worker stopped first.
    Failed(Option<SendCause>),
    /// The mode held it; a channel carried [`imessage::BRIEF_NOTICE`].
    NoticeSent,
    /// The full brief reached a channel.
    Sent,
    /// Quiet hours hold it until a later flush.
    Quiet,
    /// No report within the wait.
    Unconfirmed,
    /// Queued on a sink that cannot report delivery (tests).
    Queued,
}

/// The high-priority lane was full and the caller could not await.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

impl std::fmt::Display for QueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("outbound urgent queue is full")
    }
}

impl std::error::Error for QueueFull {}

/// Local wall clock for the policy, injected so tests are deterministic.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch, shifted by the local UTC offset, so
    /// `secs.rem_euclid(86_400)` is the local time of day and `secs.div_euclid(86_400)`
    /// is the local day.
    fn now_local_secs(&self) -> i64;
}

/// The production clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_local_secs(&self) -> i64 {
        let now = chrono::Local::now();
        now.timestamp() + i64::from(now.offset().local_minus_utc())
    }
}

/// One admitted outbound message waiting for the gateway worker.
#[derive(Debug, Clone)]
pub enum Pending {
    /// A text alert at `level`.
    Alert {
        /// The notice level.
        level: Level,
        /// The message text.
        text: String,
    },
    /// The daily brief.
    Brief {
        /// The brief body, dropped notices included.
        text: String,
    },
    /// An approval card.
    Approval(ApprovalBody),
}

impl Pending {
    /// Info and normal notices are the ones a full queue may drop.
    fn is_low_priority(&self) -> bool {
        matches!(
            self,
            Pending::Alert {
                level: Level::Info | Level::Normal,
                ..
            }
        )
    }

    /// The notice a dropped pending message reports in the next brief.
    // TODO(NOTIFY-2 P3): an approval headline folds into a later brief if `NotifyRouter::approval` ever gets a caller.
    fn into_notice(self) -> Notice {
        match self {
            Pending::Alert { level, text } => Notice { level, text },
            Pending::Brief { text } => Notice {
                level: Level::Info,
                text,
            },
            Pending::Approval(body) => Notice {
                level: Level::Urgent,
                text: body.headline,
            },
        }
    }

    fn bounded(self) -> Self {
        match self {
            Pending::Alert { level, text } => Pending::Alert {
                level,
                text: truncate_utf8(&text, MAX_PENDING_TEXT_BYTES),
            },
            Pending::Brief { text } => Pending::Brief {
                text: truncate_utf8(&text, MAX_PENDING_TEXT_BYTES),
            },
            Pending::Approval(mut body) => {
                body.headline = truncate_utf8(&body.headline, MAX_PENDING_TEXT_BYTES);
                body.approve_label = truncate_utf8(&body.approve_label, MAX_PENDING_TEXT_BYTES);
                body.deny_label = truncate_utf8(&body.deny_label, MAX_PENDING_TEXT_BYTES);
                body.approve_data = truncate_utf8(&body.approve_data, MAX_PENDING_TEXT_BYTES);
                body.deny_data = truncate_utf8(&body.deny_data, MAX_PENDING_TEXT_BYTES);
                Pending::Approval(body)
            }
        }
    }
}

fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Notices a full queue dropped, for the next brief.
#[derive(Debug, Default, Clone)]
pub struct Drops {
    /// Exact number dropped (the list below is capped).
    pub count: usize,
    /// Up to [`MAX_SINK_DROPS`] dropped notices, for the brief text.
    pub notices: Vec<Notice>,
}

/// Where the router queues a message. The job runners are synchronous, so
/// [`Sink::try_enqueue`] never waits; an async caller uses [`Sink::enqueue`],
/// which applies backpressure on the high-priority lane with no time limit.
#[async_trait]
pub trait Sink: Send + Sync {
    /// Queue without waiting. Low-priority notices never fail; `Err` means the
    /// high-priority lane is full and this caller could not await. The notice
    /// is counted in the next brief.
    fn try_enqueue(&self, pending: Pending) -> Result<(), QueueFull>;

    /// Queue with backpressure: waits for room in the high-priority lane.
    /// Low-priority notices never wait (they drop the oldest).
    async fn enqueue(&self, pending: Pending) {
        let _ = self.try_enqueue(pending);
    }

    /// Reserve an urgent slot BEFORE policy admission, so a caller cancelled
    /// while waiting for room has not been counted. Cancellation-safe: the
    /// reservation is taken without an await after it is recorded.
    async fn reserve_urgent(&self) {}

    /// Complete a reserved urgent enqueue; never waits.
    fn enqueue_reserved(&self, pending: Pending) {
        let _ = self.try_enqueue(pending);
    }

    /// Stop accepting new work; the worker drains what is already queued.
    fn close(&self) {}

    /// The notices a full queue dropped since the last call.
    fn take_drops(&self) -> Drops {
        Drops::default()
    }

    /// Queue a brief without waiting. `Some(n)`: the worker reports on brief
    /// `n` ([`Sink::wait_brief`]); `None`: this sink cannot report.
    fn enqueue_brief(&self, text: String) -> Result<Option<u64>, QueueFull> {
        self.try_enqueue(Pending::Brief { text }).map(|()| None)
    }

    /// Wait up to `timeout` for the worker's report on brief `ticket`;
    /// `None` when none came in time.
    fn wait_brief(&self, _ticket: u64, _timeout: Duration) -> Option<BriefOutcome> {
        None
    }
}

/// The shared state of the bounded outbound queue.
struct Shared {
    state: Mutex<QueueState>,
    notify: Notify,
    high_space: Notify,
    /// Wakes a brief run waiting for the worker's report.
    reported: Condvar,
}

#[derive(Default)]
struct QueueState {
    low: VecDeque<Pending>,
    high: VecDeque<Pending>,
    /// Urgent slots reserved by a caller that has not enqueued yet.
    high_reserved: usize,
    drops: Drops,
    closed: bool,
    /// One worker drains the urgent lane in order, so report `n` is brief `n`.
    briefs_queued: u64,
    briefs_reported: u64,
    last_brief: Option<BriefOutcome>,
    receiver_gone: bool,
}

/// The production sink: two bounded lanes drained by [`run_worker`].
pub struct GatewaySink {
    shared: Arc<Shared>,
}

/// The worker's end of the bounded queue.
pub struct GatewayReceiver {
    shared: Arc<Shared>,
}

impl GatewaySink {
    /// A sink and the queue its worker drains.
    pub fn channel() -> (Self, GatewayReceiver) {
        let shared = Arc::new(Shared {
            state: Mutex::new(QueueState::default()),
            notify: Notify::new(),
            high_space: Notify::new(),
            reported: Condvar::new(),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            GatewayReceiver { shared },
        )
    }

    /// How many messages are queued right now (tests and diagnostics).
    pub fn queued_len(&self) -> usize {
        let state = self.lock();
        state.low.len() + state.high.len() + state.high_reserved
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn push_low(shared: &Shared, state: &mut QueueState, pending: Pending) {
        while state.low.len() >= OUTBOUND_QUEUE_CAPACITY {
            match state.low.pop_front() {
                Some(evicted) => record_drop(&mut state.drops, evicted),
                None => break,
            }
        }
        state.low.push_back(pending);
        shared.notify.notify_one();
    }

    fn push_high(shared: &Shared, state: &mut QueueState, pending: Pending) {
        if matches!(pending, Pending::Brief { .. }) {
            state.briefs_queued += 1;
        }
        state.high.push_back(pending);
        shared.notify.notify_one();
    }
}

#[async_trait]
impl Sink for GatewaySink {
    fn try_enqueue(&self, pending: Pending) -> Result<(), QueueFull> {
        let pending = pending.bounded();
        let mut state = self.lock();
        if state.closed {
            return Ok(());
        }
        if pending.is_low_priority() {
            Self::push_low(&self.shared, &mut state, pending);
            return Ok(());
        }
        if state.high.len() + state.high_reserved < OUTBOUND_URGENT_CAPACITY {
            Self::push_high(&self.shared, &mut state, pending);
            return Ok(());
        }
        record_drop(&mut state.drops, pending);
        Err(QueueFull)
    }

    async fn enqueue(&self, pending: Pending) {
        let pending = pending.bounded();
        if pending.is_low_priority() {
            let mut state = self.lock();
            if !state.closed {
                Self::push_low(&self.shared, &mut state, pending);
            }
            return;
        }
        loop {
            // Register the waiter BEFORE re-checking capacity: a drain that
            // frees a slot between the check and the await must not be lost.
            let notified = self.shared.high_space.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock();
                if state.closed {
                    return;
                }
                if state.high.len() + state.high_reserved < OUTBOUND_URGENT_CAPACITY {
                    Self::push_high(&self.shared, &mut state, pending);
                    return;
                }
            }
            notified.await;
        }
    }

    async fn reserve_urgent(&self) {
        loop {
            let notified = self.shared.high_space.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock();
                if state.closed {
                    return;
                }
                if state.high.len() + state.high_reserved < OUTBOUND_URGENT_CAPACITY {
                    state.high_reserved += 1;
                    return;
                }
            }
            notified.await;
        }
    }

    fn enqueue_reserved(&self, pending: Pending) {
        let pending = pending.bounded();
        let mut state = self.lock();
        state.high_reserved = state.high_reserved.saturating_sub(1);
        if state.closed {
            return;
        }
        Self::push_high(&self.shared, &mut state, pending);
    }

    fn close(&self) {
        self.lock().closed = true;
        self.shared.notify.notify_waiters();
        self.shared.high_space.notify_waiters();
    }

    fn take_drops(&self) -> Drops {
        let mut state = self.lock();
        std::mem::take(&mut state.drops)
    }

    fn enqueue_brief(&self, text: String) -> Result<Option<u64>, QueueFull> {
        let pending = Pending::Brief { text }.bounded();
        let mut state = self.lock();
        // A closed sink queues nothing either.
        if state.closed {
            return Err(QueueFull);
        }
        if state.high.len() + state.high_reserved < OUTBOUND_URGENT_CAPACITY {
            Self::push_high(&self.shared, &mut state, pending);
            return Ok(Some(state.briefs_queued));
        }
        record_drop(&mut state.drops, pending);
        Err(QueueFull)
    }

    fn wait_brief(&self, ticket: u64, timeout: Duration) -> Option<BriefOutcome> {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        loop {
            // A later brief already overwrote this report: unconfirmed.
            if state.briefs_reported >= ticket {
                return state.last_brief.filter(|_| state.briefs_reported == ticket);
            }
            if state.receiver_gone {
                // The worker is gone and the brief was never delivered.
                return Some(BriefOutcome::Failed(None));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            state = match self.shared.reported.wait_timeout(state, left) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }
}

impl Drop for GatewaySink {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        self.shared.notify.notify_waiters();
        self.shared.high_space.notify_waiters();
    }
}

impl Drop for GatewayReceiver {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        state.receiver_gone = true;
        self.shared.notify.notify_waiters();
        self.shared.high_space.notify_waiters();
        self.shared.reported.notify_all();
    }
}

impl GatewayReceiver {
    /// The next queued message (high-priority lane first), or `None` once the
    /// sink is dropped and the queue is drained.
    pub async fn recv(&self) -> Option<Pending> {
        loop {
            {
                let mut state = self
                    .shared
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(pending) = state.high.pop_front() {
                    self.shared.high_space.notify_waiters();
                    return Some(pending);
                }
                if let Some(pending) = state.low.pop_front() {
                    return Some(pending);
                }
                if state.closed {
                    return None;
                }
            }
            self.shared.notify.notified().await;
        }
    }

    /// Report what the worker did with the next brief, in queue order.
    fn report_brief(&self, outcome: BriefOutcome) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.briefs_reported += 1;
        state.last_brief = Some(outcome);
        self.shared.reported.notify_all();
    }
}

fn record_drop(drops: &mut Drops, pending: Pending) {
    drops.count = drops.count.saturating_add(1);
    if drops.notices.len() < MAX_SINK_DROPS {
        drops.notices.push(pending.into_notice());
    }
}

/// Admit every queued message on the delivering gateway's egress path and
/// deliver it. Every paired remote gets the message; when none is paired, the
/// local display is the fallback. The live mode is read per message, so a
/// switch to private holds the rest.
pub async fn run_worker(
    remotes: Vec<Arc<dyn Gateway>>,
    local: Arc<dyn Gateway>,
    mode: ModeFn,
    rx: GatewayReceiver,
) {
    while let Some(pending) = rx.recv().await {
        let brief = matches!(pending, Pending::Brief { .. });
        let outcome = deliver(pending, &remotes, &local, &mode).await;
        if brief {
            rx.report_brief(outcome);
        }
    }
}

/// Deliver one message; the outcome is what a brief run reports.
async fn deliver(
    pending: Pending,
    remotes: &[Arc<dyn Gateway>],
    local: &Arc<dyn Gateway>,
    mode: &ModeFn,
) -> BriefOutcome {
    let paired: Vec<&Arc<dyn Gateway>> = remotes
        .iter()
        .filter(|gateway| gateway.is_paired())
        .collect();
    if let Pending::Approval(body) = pending {
        if paired.is_empty() {
            tracing::info!("approval card dropped: no paired gateway");
            return BriefOutcome::Held;
        }
        for gateway in paired {
            let mode_now = mode();
            match ApprovalCard::admitted_at(
                gateway.egress_path(),
                mode_now,
                gateway.destination(),
                body.clone(),
            ) {
                Ok(card) => {
                    if let Err(err) = gateway.deliver_approval(&card).await {
                        tracing::warn!(cause = %err.cause(), "approval card not delivered");
                    }
                }
                Err(refused) => {
                    tracing::info!(
                        path = refused.path.as_str(),
                        "approval card held in this mode"
                    )
                }
            }
        }
        return BriefOutcome::Held;
    }
    if paired.is_empty() {
        return deliver_one(local, pending, mode).await;
    }
    let mut best = BriefOutcome::Held;
    for gateway in paired {
        best = best.max(deliver_one(gateway, pending.clone(), mode).await);
    }
    best
}

async fn deliver_one(gateway: &Arc<dyn Gateway>, pending: Pending, mode: &ModeFn) -> BriefOutcome {
    let mode_now = mode();
    match pending {
        Pending::Alert { level, text } => {
            match OutboundText::admitted_at(
                gateway.egress_path(),
                mode_now,
                gateway.destination(),
                level,
                text,
            ) {
                Ok(outbound) => {
                    if let Err(err) = gateway.send(&outbound).await {
                        tracing::warn!(cause = %err.cause(), "gateway alert not delivered");
                    }
                }
                Err(refused) => {
                    tracing::info!(path = refused.path.as_str(), "alert held in this mode")
                }
            }
            BriefOutcome::Held
        }
        Pending::Brief { text } => {
            let admitted = |path, text| {
                OutboundText::admitted_at(path, mode_now, gateway.destination(), Level::Info, text)
            };
            // When the mode holds the brief, a channel that opts in carries the
            // fixed notice instead, on its own narrow row, in the same mode.
            let (brief, outcome) = match admitted(gateway.egress_path(), text) {
                Ok(brief) => (brief, BriefOutcome::Sent),
                Err(refused) => {
                    tracing::info!(path = refused.path.as_str(), "brief held in this mode");
                    let notice = gateway
                        .brief_notice_path()
                        .map(|path| admitted(path, imessage::BRIEF_NOTICE.to_string()));
                    match notice {
                        Some(Ok(notice)) => (notice, BriefOutcome::NoticeSent),
                        _ => return BriefOutcome::Held,
                    }
                }
            };
            match gateway.deliver_brief(&brief).await {
                Ok(()) => outcome,
                Err(err) => {
                    tracing::warn!(cause = %err.cause(), "gateway brief not delivered");
                    BriefOutcome::Failed(match err {
                        GatewayError::Send(cause) => Some(cause),
                        _ => None,
                    })
                }
            }
        }
        Pending::Approval(_) => BriefOutcome::Held,
    }
}

/// The state file, relative to the verified home.
const STATE_FILE: &str = "notify_policy.json";

/// The persisted router state: the policy counters plus a brief held by quiet
/// hours.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RouterState {
    policy: PolicyState,
    pending_brief: Option<String>,
}

impl RouterState {
    /// Load the state. A missing file is a fresh state; a corrupt or
    /// unreadable file fails closed (the day's cap is spent) and is
    /// quarantined.
    fn load(home: &SandboxHome, now: i64, cap: u32) -> Self {
        let path = home.path().join(STATE_FILE);
        match std::fs::read(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(err) => {
                tracing::warn!(error = %err, "notify policy state is unreadable; failing closed");
                Self::failing_closed(now, cap)
            }
            Ok(bytes) => match serde_json::from_slice::<RouterState>(&bytes) {
                Ok(state) => state,
                Err(_) => {
                    tracing::warn!(
                        "notify policy state is corrupt; quarantining it and failing closed"
                    );
                    quarantine(home, now, &bytes);
                    Self::failing_closed(now, cap)
                }
            },
        }
    }

    fn failing_closed(now: i64, cap: u32) -> Self {
        Self {
            policy: PolicyState::cap_reached(now, cap),
            pending_brief: None,
        }
    }

    /// Persist through the verified-home gateway, mode 0600.
    fn save(&self, home: &SandboxHome) -> std::io::Result<()> {
        let raw = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        home.write(Path::new(STATE_FILE), &raw, 0o600)
    }
}

/// Move a corrupt state aside as `<file>.corrupt-<ts>`, then remove the
/// original. Never logs the file contents.
fn quarantine(home: &SandboxHome, now: i64, bytes: &[u8]) {
    let name = format!("{STATE_FILE}.corrupt-{now}");
    if let Err(err) = home.write(Path::new(&name), bytes, 0o600) {
        tracing::warn!(error = %err, "could not quarantine the corrupt notify policy state");
        return;
    }
    if let Err(err) = home.remove_file(Path::new(STATE_FILE)) {
        tracing::warn!(error = %err, "could not remove the corrupt notify policy state");
    }
}

/// The daemon's single outbound path: policy first, gateway second.
pub struct NotifyRouter {
    sink: Arc<dyn Sink>,
    policy: NotifyPolicy,
    state: Mutex<RouterState>,
    home: SandboxHome,
    clock: Arc<dyn Clock>,
}

impl NotifyRouter {
    /// Build a router, restoring the state under `home` (missing reads as a
    /// fresh state; corrupt or unreadable fails closed).
    pub fn new(
        sink: Arc<dyn Sink>,
        policy: NotifyPolicy,
        home: SandboxHome,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let now = clock.now_local_secs();
        let cap = policy.config().daily_cap;
        let state = RouterState::load(&home, now, cap);
        Self {
            sink,
            policy,
            state: Mutex::new(state),
            home,
            clock,
        }
    }

    /// The file the policy state is persisted to.
    pub fn state_path(&self) -> PathBuf {
        self.home.path().join(STATE_FILE)
    }

    /// Stop accepting new outbound work; the worker drains what is queued.
    pub fn close(&self) {
        self.sink.close();
    }

    /// Offer an alert. `SendNow` (urgent) messages await the bounded urgent
    /// lane, so backpressure never parks them in the brief. Info/normal are
    /// batched; quiet hours hold them; the daily cap drops the overflow.
    pub async fn alert(&self, level: Level, text: &str) -> Action {
        if level == Level::Urgent {
            // Reserve before admission: a cancellation while waiting for a
            // slot must not leave a counted but undelivered alert.
            self.sink.reserve_urgent().await;
            let action = self.offer(level, text);
            self.sink.enqueue_reserved(Pending::Alert {
                level,
                text: text.to_string(),
            });
            return action;
        }
        self.offer(level, text)
    }

    /// Offer an info/normal alert without queueing: those are batched by the
    /// policy and leave on a later [`NotifyRouter::flush`].
    pub fn alert_batched(&self, text: &str) -> Action {
        self.offer(Level::Normal, text)
    }

    /// Decide the policy action and persist; never queues.
    fn offer(&self, level: Level, text: &str) -> Action {
        let now = self.clock.now_local_secs();
        let action = {
            let mut state = self.lock_state();
            self.policy
                .offer(&mut state.policy, now, Notice::new(level, text))
        };
        self.persist();
        action
    }

    /// Deliver the brief now, or hold it until quiet hours end. Notices the
    /// daily cap or a full outbound queue dropped are folded into the brief.
    pub fn brief(&self, text: &str) -> Action {
        self.queue_brief(text).0
    }

    /// [`NotifyRouter::brief`], then wait up to `wait` for what the worker
    /// did with it, so a run records the truth. Quiet hours and the cap
    /// behave exactly as for `brief`.
    pub fn brief_reported(&self, text: &str, wait: Duration) -> BriefOutcome {
        match self.queue_brief(text).1 {
            None => BriefOutcome::Quiet,
            Some(Ok(Some(ticket))) => self
                .sink
                .wait_brief(ticket, wait)
                .unwrap_or(BriefOutcome::Unconfirmed),
            Some(Ok(None)) => BriefOutcome::Queued,
            Some(Err(QueueFull)) => BriefOutcome::Failed(None),
        }
    }

    /// Send one fixed owner test text through the brief's lane, worker and
    /// channel, then wait up to `wait` for the report. The policy is skipped
    /// on purpose: no dropped notices are folded in, the cap is not spent and
    /// a brief held by quiet hours is left alone. `'static` keeps it a constant.
    pub fn test_reported(&self, text: &'static str, wait: Duration) -> BriefOutcome {
        match self.sink.enqueue_brief(text.to_string()) {
            Ok(Some(ticket)) => self
                .sink
                .wait_brief(ticket, wait)
                .unwrap_or(BriefOutcome::Unconfirmed),
            Ok(None) => BriefOutcome::Queued,
            Err(QueueFull) => BriefOutcome::Failed(None),
        }
    }

    /// The policy action and, unless quiet hours hold it, the queue result.
    fn queue_brief(&self, text: &str) -> (Action, Option<Result<Option<u64>, QueueFull>>) {
        let now = self.clock.now_local_secs();
        let (action, deliver) = {
            let mut state = self.lock_state();
            let mut body = truncate_utf8(text, MAX_PENDING_TEXT_BYTES);
            let cap_drops = self.policy.take_dropped(&mut state.policy);
            let queue_drops = self.sink.take_drops();
            let total = cap_drops.len() + queue_drops.count;
            if total > 0 {
                body.push_str("\n\n");
                body.push_str(&format!("{total} notification(s) not delivered:\n"));
                for notice in cap_drops.iter().chain(queue_drops.notices.iter()) {
                    body.push_str("- ");
                    body.push_str(&notice.text);
                    body.push('\n');
                }
            }
            if self.policy.is_quiet(now) {
                state.pending_brief = Some(body);
                (Action::Quiet, None)
            } else {
                (Action::SendNow, Some(body))
            }
        };
        self.persist();
        let ticket = deliver.map(|body| self.sink.enqueue_brief(body));
        if ticket == Some(Err(QueueFull)) {
            tracing::warn!(
                "outbound urgent queue is full; the brief is counted for the next brief"
            );
        }
        (action, ticket)
    }

    /// Queue an approval card. A card is urgent: never batched, never dropped,
    /// and it passes quiet hours. This awaits the high-priority lane, so a
    /// stalled gateway backpressures the caller without losing the card.
    pub async fn approval(&self, body: ApprovalBody) -> Action {
        self.sink.reserve_urgent().await;
        let action = self.offer(Level::Urgent, &body.headline);
        self.sink.enqueue_reserved(Pending::Approval(body));
        action
    }

    /// Emit anything the policy holds: a brief waiting for quiet hours to end,
    /// then the batch for the elapsed window. Returns the alert batch, if one
    /// left.
    pub fn flush(&self) -> Option<Notice> {
        let now = self.clock.now_local_secs();
        let (brief, batch) = {
            let mut state = self.lock_state();
            let brief = if self.policy.is_quiet(now) {
                None
            } else {
                state.pending_brief.take()
            };
            let batch = self.policy.flush(&mut state.policy, now);
            (brief, batch)
        };
        self.persist();
        if let Some(text) = brief {
            if self.sink.try_enqueue(Pending::Brief { text }).is_err() {
                tracing::warn!(
                    "outbound urgent queue is full; the brief is counted for the next brief"
                );
            }
        }
        if let Some(batch) = batch {
            let _ = self.sink.try_enqueue(Pending::Alert {
                level: batch.level,
                text: batch.text.clone(),
            });
            return Some(batch);
        }
        None
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, RouterState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn persist(&self) {
        let state = self.lock_state();
        if let Err(err) = state.save(&self.home) {
            tracing::warn!(error = %err, "notify policy state not persisted");
        }
    }
}

impl Notifier for NotifyRouter {
    fn notify(&self, notification: &Notification) -> Result<(), NotifyError> {
        let text = format!("{}\n{}", notification.title, notification.body);
        self.offer(Level::Normal, &text);
        Ok(())
    }
}
