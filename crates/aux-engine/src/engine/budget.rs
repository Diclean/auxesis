//! Budgets and usage: reserving the estimated spend before a call,
//! settling it after, and recording what the turn actually cost.

use super::{ChatError, ChatSession, DEFAULT_OUTPUT_RESERVE, ESTIMATED_UNIT};
use aux_providers::{ChatDelta, ChatMessage, ChatProvider, ChatRequest, ChatResponse, SafeMessage};
use aux_store::{Store, StoreError, StoreHandle};
use kernel_core::budget::{
    audit_denial, BudgetCaps, Denial, DenialReason, PriceTable, Reservation, ReserveOutcome,
    UsageActual, UsageKind, UsageTotals,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Arc, Condvar, LazyLock, Mutex, OnceLock, PoisonError, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

fn unit_for(estimated: bool) -> &'static str {
    if estimated {
        ESTIMATED_UNIT
    } else {
        "tokens"
    }
}

/// Text and provider usage captured from a streaming sink.
///
/// A call that fails, times out, is cancelled or overflows the stream body
/// cap after deltas have already gone out has no `ChatResponse` to settle
/// from. The sink records what actually streamed, so [`settle_streamed`] can
/// settle the same estimate the success path would use when the provider
/// reports no usage (I-01).
#[derive(Default)]
pub(super) struct StreamCapture {
    text: std::sync::Mutex<String>,
    usage: std::sync::Mutex<Option<aux_providers::Usage>>,
}

impl StreamCapture {
    pub(super) fn record(&self, delta: &ChatDelta) {
        match delta {
            ChatDelta::Text(text) => kernel_core::lock_recover(&self.text).push_str(text),
            ChatDelta::Usage(usage) => *kernel_core::lock_recover(&self.usage) = Some(*usage),
            ChatDelta::ToolCall(_) => {}
        }
    }

    pub(super) fn text(&self) -> String {
        kernel_core::lock_recover(&self.text).clone()
    }

    pub(super) fn usage(&self) -> Option<aux_providers::Usage> {
        *kernel_core::lock_recover(&self.usage)
    }
}

/// What a streaming call is known to have used: the counts the provider
/// reported, else the estimates of its prompt and of the text that streamed.
pub(super) fn streamed_actual(
    request: &ChatRequest,
    capture: &StreamCapture,
    provider: &dyn ChatProvider,
    prices: &PriceTable,
) -> UsageActual {
    let mut response = ChatResponse::assistant(capture.text());
    response.usage = capture.usage();
    usage_actual(request, &response, request_model(provider, request), prices)
}

pub(super) fn settle_streamed<S: SettleStore>(
    held: HeldReservation<'_, S>,
    request: &ChatRequest,
    capture: &StreamCapture,
    provider: &dyn ChatProvider,
    prices: &PriceTable,
) {
    let id = held.reservation().id;
    if let Err(err) = held.settle(&streamed_actual(request, capture, provider, prices)) {
        tracing::warn!(
            reservation = id,
            error = %err,
            "could not settle a failed streaming call's estimated usage"
        );
    }
}

/// The store a [`HeldReservation`] settles in: a turn's own handle, or a
/// shared store (one a future that must be `Send` can hold). Sealed, so a
/// guard's drop runs no code from outside this crate but its own callback.
pub trait SettleStore: sealed::Sealed {
    /// Settle `reservation` at `actual`. The store settles a reservation once.
    fn settle(&self, reservation: &Reservation, actual: &UsageActual) -> Result<(), StoreError>;
    /// The shared store the settlement worker can retry in; a borrowed one
    /// has none, and its row stays held for the daemon's reconcile.
    fn shared(&self) -> Option<&Arc<Mutex<Store>>>;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for aux_store::StoreHandle<'_> {}
    impl Sealed for std::sync::Arc<std::sync::Mutex<aux_store::Store>> {}
}

impl SettleStore for StoreHandle<'_> {
    fn settle(&self, reservation: &Reservation, actual: &UsageActual) -> Result<(), StoreError> {
        self.with(|store| store.settle_reservation(reservation, actual))
    }

    fn shared(&self) -> Option<&Arc<Mutex<Store>>> {
        match self {
            StoreHandle::Shared(store) => Some(store),
            StoreHandle::Borrowed(_) => None,
        }
    }
}

impl SettleStore for Arc<Mutex<Store>> {
    fn settle(&self, reservation: &Reservation, actual: &UsageActual) -> Result<(), StoreError> {
        kernel_core::lock_recover(self).settle_reservation(reservation, actual)
    }

    fn shared(&self) -> Option<&Arc<Mutex<Store>>> {
        Some(self)
    }
}

/// What the settlement worker is handed.
enum Work {
    /// A settle it owes until it succeeds.
    Settle(Box<SettleJob>),
    /// A store whose abandoned held rows it settles, now and every minute.
    Watch(Weak<Mutex<Store>>),
    /// Nothing to do: wakes the worker so it sees the stop flag.
    Wake,
}

struct SettleJob {
    store: Arc<Mutex<Store>>,
    reservation: Reservation,
    actual: UsageActual,
}

/// A failed try is retried after `FIRST_RETRY`, then twice as long each
/// time up to `RETRY_CAP`, and never given up. Tests run the same schedule
/// faster.
const FIRST_RETRY: Duration = Duration::from_millis(if cfg!(test) { 1 } else { 500 });
const RETRY_CAP: Duration = Duration::from_millis(if cfg!(test) { 4 } else { 60_000 });
/// After a stop, how long the worker records what its owed jobs are known to
/// have spent; one write each, cut off once it passes. With a store lock
/// wait before the first write and the store's busy timeout (5 s) in it, a
/// stop call may take longer: the next one opens a new window.
const RECORD_WINDOW: Duration = Duration::from_millis(if cfg!(test) { 250 } else { 1000 });

const RECONCILE_EVERY: Duration = Duration::from_millis(if cfg!(test) { 20 } else { 60_000 });

/// The settlement worker, started by the first guard: one thread on an
/// unbounded queue, so no drop waits on the store's lock or on SQLite and
/// no job is ever turned away. Each job keeps its row held until it
/// settles, and the store refuses new reservations past a bound on held
/// rows, so a store that stops settling cannot grow this queue without end.
struct Settler {
    work: mpsc::Sender<Work>,
    worker: Mutex<Option<Running>>,
}

/// The worker thread, and the signal it sends as it ends.
struct Running {
    thread: JoinHandle<()>,
    done: mpsc::Receiver<()>,
}

impl Settler {
    /// Start the worker, unless `budget` is already stopped: none runs then.
    fn start(budget: &'static Budget) -> Self {
        let (work, queue) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let spawned = if budget.stopped() {
            Err(std::io::Error::other("the budget settlement is stopped"))
        } else {
            std::thread::Builder::new()
                .name("budget-settle".to_string())
                .spawn(move || {
                    settle_jobs(&queue, budget);
                    let _ = done_tx.send(());
                })
        };
        let worker = match spawned {
            Ok(thread) => Some(Running { thread, done }),
            Err(err) if budget.stopped() => {
                tracing::debug!(error = %err, "no settlement worker after a stop");
                None
            }
            Err(err) => {
                tracing::error!(error = %err, "no settlement worker: dropped calls stay held");
                None
            }
        };
        Self {
            work,
            worker: Mutex::new(worker),
        }
    }

    /// Hand `work` to the worker: no SQL, no store lock, no wait on the
    /// worker. Once it ended, or with no worker, the row stays held: it counts against the caps until its TTL
    /// passes, and the next start's reconcile then settles it. Nothing here
    /// runs SQL; the row may already be raised to what was recorded.
    fn send(&self, work: Work) {
        if self.work.send(work).is_err() {
            tracing::warn!("no settlement worker: the call stays held for a reconcile");
        }
    }

    /// Tell the worker to stop, and wait up to `bound` for it to end. True
    /// once it has ended: no statement of its is then in flight. False when
    /// it is still blocked (on the store's lock or a busy database): it runs
    /// no statement it has not already started, so a second call, which waits
    /// again, ends with it. On the way out it records what each job it owes
    /// is known to have spent ([`RECORD_WINDOW`]), and the row stays held.
    fn stop(&self, bound: Duration) -> bool {
        self.send_quietly(Work::Wake);
        let mut worker = kernel_core::lock_recover(&self.worker);
        let Some(running) = worker.take() else {
            return true;
        };
        match running.done.recv_timeout(bound) {
            Err(mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!("the settlement worker is still mid-statement; not waited for");
                *worker = Some(running);
                false
            }
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = running.thread.join();
                true
            }
        }
    }

    fn send_quietly(&self, work: Work) {
        let _ = self.work.send(work);
    }
}

/// The stop gate (when the last stop was asked, and inline settles and
/// handovers in flight), apart from the worker, so a stop before it holds.
#[derive(Default)]
struct Gate {
    stop: Option<Instant>,
    in_flight: usize,
}

/// One budget's settling: the process has one, a test its own.
#[derive(Default)]
pub(super) struct Budget {
    gate: Mutex<Gate>,
    changed: Condvar,
    settler: OnceLock<Settler>,
}

static PROCESS: LazyLock<Budget> = LazyLock::new(Budget::default);

impl Budget {
    fn settler(&'static self) -> &'static Settler {
        self.settler.get_or_init(|| Settler::start(self))
    }

    /// See [`stop_settle_worker`]. The flag first: a settler started now has no worker.
    fn stop(&'static self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        kernel_core::lock_recover(&self.gate).stop = Some(Instant::now());
        let settler = self.settler();
        let mut gate = kernel_core::lock_recover(&self.gate);
        while gate.in_flight > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                tracing::warn!("an inline budget settle is still mid-statement");
                return false;
            }
            let waited = self.changed.wait_timeout(gate, left);
            gate = waited.unwrap_or_else(PoisonError::into_inner).0;
        }
        gate.stop = Some(Instant::now()); // the window counts from here
        drop(gate);
        self.changed.notify_all();
        settler.stop(deadline.saturating_duration_since(Instant::now()))
    }

    /// Run `write`, a usage write outside settling, past the stop gate: counted
    /// in flight, so a stop waits for it; refused once a stop is asked, so none
    /// starts after it. The refusal is an error the caller handles as any
    /// failed write, never a silent drop.
    fn gated<T>(&self, write: impl FnOnce() -> Result<T, StoreError>) -> Result<T, StoreError> {
        let (_in_flight, open) = self.enter();
        if !open {
            return Err(stopped_error());
        }
        write()
    }

    fn stopped(&self) -> bool {
        kernel_core::lock_recover(&self.gate).stop.is_some()
    }

    fn window_closed(&self) -> bool {
        let stop = kernel_core::lock_recover(&self.gate).stop;
        stop.is_some_and(|at| at.elapsed() >= RECORD_WINDOW)
    }

    /// Count an inline settle or a handover in flight, under the gate's lock,
    /// until it is done; and whether a settle may start (no stop asked).
    fn enter(&self) -> (InFlight<'_>, bool) {
        let mut gate = kernel_core::lock_recover(&self.gate);
        gate.in_flight += 1;
        (InFlight(self), gate.stop.is_none())
    }
}

fn stopped_error() -> StoreError {
    StoreError::Io(std::io::Error::other("the budget settlement is stopped"))
}

/// One counted in flight; its drop lets a stop and the worker see it done.
struct InFlight<'b>(&'b Budget);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        kernel_core::lock_recover(&self.0.gate).in_flight -= 1;
        self.0.changed.notify_all();
    }
}

/// Run `write`, a usage write outside settling, on `store` past the
/// process-wide stop gate (see [`Budget::gated`]).
pub(crate) fn usage_write<T>(
    store: &StoreHandle<'_>,
    write: impl FnOnce(&Store) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    LazyLock::force(&PROCESS).gated(|| store.with(write))
}

/// Hand `work` to the process-wide worker, started on first use.
fn hand_over(work: Work) {
    LazyLock::force(&PROCESS).settler().send(work);
}

/// Stop the process-wide budget settlement before the process exits, and
/// wait up to `bound` for it: a retry mid-statement when SQLCipher's exit hook
/// frees its memory is a use-after-free. True once no settle statement is in
/// flight, the worker's or an inline one's (also when none started), and
/// none starts after it: the usage writes outside settling
/// (`record_usage_call`, `record_usage_for`, `try_reserve_for`) pass the same
/// gate, so one in flight is waited for and a later one is refused with an
/// error its caller handles (a refused reservation denies the call). False
/// means a statement may still be: call this again, which waits again and
/// opens a new [`RECORD_WINDOW`]. Later settles are refused and handed to the
/// worker, which raises their rows while it runs. Residual: a handover (a
/// guard dropped unsettled) after the worker's last check is dropped, even
/// when this returned true; it runs no SQL, and its row stays held at what was
/// last recorded until the next start's reconcile.
pub fn stop_settle_worker(bound: Duration) -> bool {
    LazyLock::force(&PROCESS).stop(bound)
}

/// Settle, now and every minute while this process runs, the held
/// reservations in `store` past their TTL (those a stopped process left), each
/// at the most its call is known to have spent. The daemon watches its store.
pub fn watch_held_reservations(store: &Arc<Mutex<Store>>) {
    hand_over(Work::Watch(Arc::downgrade(store)));
}

/// A job the worker owes: when it is next due, and the wait after that.
type Owed = (SettleJob, Instant, Duration);

fn settle_jobs(queue: &mpsc::Receiver<Work>, budget: &Budget) {
    let stopped = || budget.stopped();
    let mut owed: Vec<Owed> = Vec::new();
    let mut watched: Vec<Weak<Mutex<Store>>> = Vec::new();
    let mut reconcile_at = Instant::now();
    loop {
        let due = owed.iter().map(|(_, at, _)| *at);
        let next = due
            .chain((!watched.is_empty()).then_some(reconcile_at))
            .min();
        // Nothing due: wait for the next work, however long that takes.
        let wait = next.map_or(Duration::MAX, |at| {
            at.saturating_duration_since(Instant::now())
        });
        match queue.recv_timeout(wait) {
            Ok(Work::Settle(job)) => owed.push((*job, Instant::now(), FIRST_RETRY)),
            Ok(Work::Watch(store)) => {
                watched.push(store);
                reconcile_at = Instant::now();
            }
            Ok(Work::Wake) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        // Checked after every wait and before every try, so no settle
        // starts once a stop is asked for.
        if stopped() {
            return record_owed(queue, owed, budget);
        }
        let now = Instant::now();
        owed.retain_mut(|(job, at, wait)| {
            if *at > now || stopped() {
                return true;
            }
            if try_settle(job, &stopped) {
                return false;
            }
            *at = now + *wait;
            *wait = (*wait * 2).min(RETRY_CAP);
            true
        });
        if stopped() {
            return record_owed(queue, owed, budget);
        }
        if !watched.is_empty() && now >= reconcile_at {
            watched.retain(|store| match store.upgrade() {
                Some(store) => {
                    reconcile(&store, &owed, &stopped);
                    true
                }
                None => false, // the store is gone (a test's)
            });
            reconcile_at = now + RECONCILE_EVERY;
        }
    }
}

/// On a stop: record what each job the worker owes (those still in the queue
/// too, and those handed over while one is in flight) is known to have spent,
/// in its held row, so the next start's reconcile counts that and not just the
/// reserve. A write starts only within [`RECORD_WINDOW`] of the latest stop
/// call (checked after the store's lock, whose wait may be long); a job past
/// it waits for the next call's window. Ends once nothing is owed or in flight.
fn record_owed(queue: &mpsc::Receiver<Work>, mut owed: Vec<Owed>, budget: &Budget) {
    loop {
        owed.retain(|(job, ..)| {
            let store = kernel_core::lock_recover(&job.store);
            if budget.window_closed() {
                return true;
            }
            let raise = || store.raise_held_reservation(job.reservation.id, &job.actual);
            if let Ok(Err(err)) = catch_unwind(AssertUnwindSafe(raise)) {
                let id = job.reservation.id;
                tracing::warn!(reservation = id, error = %err, "could not record its amount");
            }
            false
        });
        let gate = kernel_core::lock_recover(&budget.gate);
        while let Ok(work) = queue.try_recv() {
            if let Work::Settle(job) = work {
                owed.push((*job, Instant::now(), FIRST_RETRY));
            }
        }
        if owed.is_empty() && gate.in_flight == 0 {
            return;
        }
        let open = (gate.stop).is_some_and(|at| at.elapsed() < RECORD_WINDOW);
        if owed.is_empty() || !open {
            // A handover in flight, or the next stop call's window.
            drop(budget.changed.wait(gate));
        }
    }
}

/// One try at `job`: raise its held row to the job's amount first, so the
/// most its call is known to have spent outlives this process, then settle.
/// A stop is asked after the store's lock is taken and between the two
/// statements; the settle itself may wait on a busy database, which a stop
/// does not cut short.
fn try_settle(job: &SettleJob, stopped: &dyn Fn() -> bool) -> bool {
    let (store, reservation) = (kernel_core::lock_recover(&job.store), &job.reservation);
    if stopped() {
        return false;
    }
    let tried = catch_unwind(AssertUnwindSafe(|| {
        // A raise that fails leaves the settle to fail or succeed on its own.
        let _ = store.raise_held_reservation(reservation.id, &job.actual);
        if stopped() {
            return Ok(false);
        }
        store
            .settle_reservation(reservation, &job.actual)
            .map(|()| true)
    }));
    match tried {
        Ok(Ok(settled)) => settled,
        Ok(Err(err)) => {
            tracing::warn!(reservation = reservation.id, error = %err, "settle failed; retried");
            false
        }
        Err(_) => {
            tracing::error!(reservation = reservation.id, "settle panicked; retried");
            false
        }
    }
}

/// Settle `store`'s abandoned held rows, but those a job here still owes: it
/// records its own amount. A settle this cannot see (a job still in the
/// channel, a direct one) may find its row claimed here; the store then
/// records what it tops the claim by, once, so the live amount still wins.
fn reconcile(store: &Arc<Mutex<Store>>, owed: &[Owed], stopped: &dyn Fn() -> bool) {
    let skip: Vec<i64> = (owed.iter())
        .filter(|(job, ..)| Arc::ptr_eq(&job.store, store))
        .map(|(job, ..)| job.reservation.id)
        .collect();
    let store = kernel_core::lock_recover(store);
    if stopped() {
        return;
    }
    let settle = || store.settle_abandoned_reservations_until(&skip, stopped);
    match catch_unwind(AssertUnwindSafe(settle)) {
        Ok(Ok((0, 0))) => {}
        outcome => tracing::warn!(?outcome, "settled held reservations a stopped process left"),
    }
}

/// A reservation whose call the provider may already bill, held from the
/// reserve until it is settled: every reservation a call takes comes as one.
///
/// [`HeldReservation::settle`] records what the call cost. Dropped
/// unsettled (the future making the call was cancelled after the request
/// went out), it hands the settlement worker the reserved estimate, or what
/// [`HeldReservation::or_known`] reports where that is more, so the spend is
/// never handed back as headroom. The drop takes no store lock, waits only
/// on the gate's short mutex, and never panics; the store row stays held (counted, never swept) until a
/// settle deletes it, so the reservation settles once.
pub struct HeldReservation<'k, S: SettleStore> {
    budget: &'static Budget,
    store: S,
    reservation: Reservation,
    settled: bool,
    known: Option<Box<dyn Fn() -> UsageActual + Send + 'k>>,
}

impl<'k, S: SettleStore> HeldReservation<'k, S> {
    /// Hold `reservation`, taken in `store`, until it is settled.
    pub fn new(store: S, reservation: Reservation) -> Self {
        Self::new_in(LazyLock::force(&PROCESS), store, reservation)
    }

    fn new_in(budget: &'static Budget, store: S, reservation: Reservation) -> Self {
        budget.settler(); // started now, so no drop waits for it
        Self {
            budget,
            store,
            reservation,
            settled: false,
            known: None,
        }
    }

    /// What the call is known to have used so far, read only if this drops
    /// unsettled: the drop then settles the larger of it and the reserved
    /// estimate in each direction, never less than the reservation.
    pub fn or_known(mut self, known: impl Fn() -> UsageActual + Send + 'k) -> Self {
        self.known = Some(Box::new(known));
        self
    }

    /// The reservation held: its estimate (the output clamped to the
    /// headroom left) and the caps it was admitted under.
    pub fn reservation(&self) -> &Reservation {
        &self.reservation
    }

    /// Settle what the call cost. The guard is spent whatever the outcome;
    /// a settle that fails goes to the settlement worker to retry.
    pub fn settle(mut self, actual: &UsageActual) -> Result<(), StoreError> {
        self.settled = true;
        // Past a stop no statement starts: the job goes to the worker's drain.
        let (_in_flight, open) = self.budget.enter();
        if !open {
            self.settle_later(*actual);
            return Err(stopped_error());
        }
        let settled = self.store.settle(&self.reservation, actual);
        if settled.is_err() {
            self.settle_later(*actual);
        }
        settled
    }

    /// Hand the settle at `actual` to the settlement worker.
    fn settle_later(&self, actual: UsageActual) {
        let _handing = self.budget.enter();
        if let Some(store) = self.store.shared() {
            self.budget.settler().send(Work::Settle(Box::new(SettleJob {
                store: Arc::clone(store),
                reservation: self.reservation.clone(),
                actual,
            })));
        }
    }
}

impl<S: SettleStore> Drop for HeldReservation<'_, S> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // The callback is the caller's code: if it panics, the reserve
        // stands in for it, and nothing unwinds out of a drop.
        let known =
            (self.known.as_ref()).and_then(|known| catch_unwind(AssertUnwindSafe(known)).ok());
        let actual = at_least(known.unwrap_or_default(), &self.reservation.estimate);
        self.settle_later(actual);
    }
}

/// `known`, raised to `reserved` in each direction it falls short in; a
/// raised amount is an estimate.
fn at_least(known: UsageActual, reserved: &UsageTotals) -> UsageActual {
    UsageActual {
        tokens_in: known.tokens_in.max(reserved.tokens_in),
        tokens_in_estimated: known.tokens_in_estimated || known.tokens_in < reserved.tokens_in,
        tokens_out: known.tokens_out.max(reserved.tokens_out),
        tokens_out_estimated: known.tokens_out_estimated || known.tokens_out < reserved.tokens_out,
        usd_cents: known.usd_cents.max(reserved.usd_cents),
    }
}

pub(crate) fn usage_actual(
    request: &ChatRequest,
    response: &ChatResponse,
    model: Option<&str>,
    prices: &PriceTable,
) -> UsageActual {
    let usage = response.usage;
    let (tokens_in, tokens_in_estimated) =
        match usage.map(|usage| usage.prompt_tokens).filter(|n| *n > 0) {
            Some(tokens) => (tokens, false),
            None => (estimate_request_tokens(request), true),
        };
    let (tokens_out, tokens_out_estimated) = match usage
        .map(|usage| usage.completion_tokens)
        .filter(|n| *n > 0)
    {
        Some(tokens) => (tokens, false),
        None => (estimate_response_tokens(response), true),
    };
    let usd_cents = provider_cost_cents(usage)
        .unwrap_or_else(|| priced_cents(prices, model, tokens_in, tokens_out));
    UsageActual {
        tokens_in,
        tokens_in_estimated,
        tokens_out,
        tokens_out_estimated,
        usd_cents,
    }
}

fn reservation_estimate(
    request: &ChatRequest,
    model: Option<&str>,
    prices: &PriceTable,
) -> UsageTotals {
    call_estimate(request, model, prices, DEFAULT_OUTPUT_RESERVE)
}

pub(crate) fn request_model<'r>(
    provider: &'r dyn ChatProvider,
    request: &'r ChatRequest,
) -> Option<&'r str> {
    request
        .model
        .as_ref()
        .map(|model| model.as_str())
        .or_else(|| provider.model())
}

/// Models already warned about as unpriced, keyed by model and UTC day: one
/// warning per model per day, not one per process.
static UNPRICED_MODEL_NOTICES: std::sync::Mutex<Vec<(String, u64)>> =
    std::sync::Mutex::new(Vec::new());

fn notice_unpriced_model(model: Option<&str>) {
    let model = model.unwrap_or("<unreported>");
    let day = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / 86_400);
    let mut seen = kernel_core::lock_recover(&UNPRICED_MODEL_NOTICES);
    seen.retain(|(_, seen_day)| *seen_day == day);
    if seen.iter().any(|(seen_model, _)| seen_model == model) {
        return;
    }
    seen.push((model.to_string(), day));
    tracing::warn!(
        model,
        "no price for this model in [prices] or the bundled catalog: the daily usd_cents \
         cap cannot be checked, so calls to it are refused while a money cap applies \
         (add [prices.models.<model>] to config.toml)"
    );
}

/// The bundled catalog's list prices, in whole cents per million tokens
/// rounded up, for every model id that carries both prices. When two
/// providers list the same id, the higher price wins.
fn catalog_prices() -> &'static PriceTable {
    static PRICES: std::sync::OnceLock<PriceTable> = std::sync::OnceLock::new();
    PRICES.get_or_init(|| {
        let mut table = PriceTable {
            models: Default::default(),
        };
        let cents = |usd: f64| (usd * 100.0 - 1e-6).ceil().max(0.0) as u64;
        for row in aux_providers::Catalog::bundled().rows() {
            let (Some(input), Some(output)) = (row.input_usd_mtok, row.output_usd_mtok) else {
                continue;
            };
            let entry = table.models.entry(row.id.clone()).or_default();
            entry.input_cents_per_million = entry.input_cents_per_million.max(cents(input));
            entry.output_cents_per_million = entry.output_cents_per_million.max(cents(output));
        }
        table
    })
}

/// The price of `model`. A price the owner set in `[prices]` wins; otherwise
/// the higher of the built-in default and the catalog list price, so a stale
/// built-in can never undercount the money cap. `None` means unpriced.
fn model_price(
    prices: &PriceTable,
    model: Option<&str>,
) -> Option<kernel_core::budget::ModelPrice> {
    static BUILT_IN: std::sync::OnceLock<PriceTable> = std::sync::OnceLock::new();
    let model = model?;
    let configured = prices.price(model).copied();
    let built_in = BUILT_IN
        .get_or_init(PriceTable::default)
        .price(model)
        .copied();
    match (configured, catalog_prices().price(model).copied()) {
        (Some(owner), _) if configured != built_in => Some(owner),
        (Some(a), Some(b)) => Some(kernel_core::budget::ModelPrice {
            input_cents_per_million: a.input_cents_per_million.max(b.input_cents_per_million),
            output_cents_per_million: a.output_cents_per_million.max(b.output_cents_per_million),
        }),
        (configured, catalog) => configured.or(catalog),
    }
}

/// Cents for one call, rounded up; `0` when the model is unpriced (an
/// unpriced call is refused before it starts while a money cap applies).
fn priced_cents(prices: &PriceTable, model: Option<&str>, tokens_in: u64, tokens_out: u64) -> u64 {
    let Some(price) = model_price(prices, model) else {
        return 0;
    };
    let numerator = tokens_in as u128 * price.input_cents_per_million as u128
        + tokens_out as u128 * price.output_cents_per_million as u128;
    numerator.div_ceil(1_000_000).min(u64::MAX as u128) as u64
}

/// The provider-reported cost in cents. A missing, zero, negative or
/// non-finite cost is treated as "not reported", so the price table decides:
/// a gateway that reports `0` must not make the money cap inert.
fn provider_cost_cents(usage: Option<aux_providers::Usage>) -> Option<u64> {
    let cost = usage?.cost_usd?;
    if !cost.is_finite() || cost <= 0.0 {
        return None;
    }
    Some((cost * 100.0).ceil().min(u64::MAX as f64) as u64)
}

/// True when the bundled catalog marks `model` as billed by subscription.
fn catalog_subscription(model: &str) -> bool {
    aux_providers::Catalog::bundled()
        .rows()
        .iter()
        .any(|row| row.id == model && row.billing == Some(aux_providers::Billing::Subscription))
}

/// A call whose model has no price cannot be checked against the money cap:
/// it would reserve 0 cents, so concurrent calls could all pass the cap. While
/// a money cap applies (every capped agent has one), such a call is refused,
/// on a loopback endpoint too (a local forwarder can reach a paid service).
///
/// Two calls run unpriced: a model the catalog marks as billed by
/// subscription, sent to the trusted subscription backend itself (0 cents
/// per call); and an in-process adapter that names neither a model nor an
/// endpoint host (every network adapter names both).
fn unpriced_under_money_cap(
    caps: &kernel_core::budget::BudgetCaps,
    prices: &PriceTable,
    provider: &dyn ChatProvider,
    model: Option<&str>,
) -> Option<String> {
    if caps.limit(UsageKind::UsdCents).is_none() || model_price(prices, model).is_some() {
        return None;
    }
    let in_process = model.is_none() && provider.endpoint_hosts().is_empty();
    let subscription = provider.subscription_billed() && model.is_some_and(catalog_subscription);
    if in_process || subscription {
        return None;
    }
    notice_unpriced_model(model);
    let model = model.unwrap_or("<unreported>");
    Some(format!(
        "model {model} has no price; add [prices.models.\"{model}\"] with \
         input_cents_per_million and output_cents_per_million to config.toml \
         (0 and 0 if this model really runs on this Mac)"
    ))
}

pub(super) fn estimate_tokens(text: &str) -> u64 {
    let mut weighted: u64 = 0;
    for character in text.chars() {
        weighted += if character.is_ascii() { 1 } else { 3 };
    }
    weighted.div_ceil(4)
}

fn estimate_message_tokens(message: &ChatMessage) -> u64 {
    let calls: u64 = message
        .tool_calls
        .iter()
        .map(|call| estimate_tokens(&call.arguments.to_string()))
        .sum();
    let reasoning = message
        .reasoning_content
        .as_deref()
        .map_or(0, estimate_tokens);
    estimate_tokens(&message.content) + calls + reasoning
}

fn estimate_safe_message_tokens(message: &SafeMessage) -> u64 {
    let calls: u64 = message
        .tool_calls()
        .iter()
        .map(|call| estimate_tokens(&call.arguments().as_value().to_string()))
        .sum();
    let reasoning = message
        .reasoning_content()
        .map_or(0, |text| estimate_tokens(text.as_str()));
    estimate_tokens(message.content().as_str()) + calls + reasoning
}

pub(super) fn estimate_request_tokens(request: &ChatRequest) -> u64 {
    let messages: u64 = request
        .messages
        .iter()
        .map(estimate_safe_message_tokens)
        .sum();
    let tools: u64 = request
        .tools
        .iter()
        .map(|tool| {
            estimate_tokens(tool.name().as_str())
                + estimate_tokens(tool.description().as_str())
                + estimate_tokens(&tool.parameters().as_value().to_string())
        })
        .sum();
    messages + tools
}

fn estimate_response_tokens(response: &ChatResponse) -> u64 {
    estimate_message_tokens(&response.message)
}

/// The one atomic admission every paid call goes through: a chat round and
/// the shell judge (WO-BUD-1). The reservation is taken inside the store
/// transaction that checks the caps; a denial, or a ledger that cannot
/// answer, is audited as `budget.denied` and refuses the call.
pub(crate) fn admit(
    store: &StoreHandle<'_>,
    run_id: Option<&str>,
    agent: &str,
    day: &str,
    caps: &BudgetCaps,
    estimate: &UsageTotals,
) -> Result<Reservation, ChatError> {
    admit_in(
        LazyLock::force(&PROCESS),
        store,
        run_id,
        agent,
        day,
        caps,
        estimate,
    )
}

/// [`admit`] past `budget`'s stop gate: once a stop is asked, no reservation
/// is taken, and the call is denied as a ledger that cannot answer.
fn admit_in(
    budget: &Budget,
    store: &StoreHandle<'_>,
    run_id: Option<&str>,
    agent: &str,
    day: &str,
    caps: &BudgetCaps,
    estimate: &UsageTotals,
) -> Result<Reservation, ChatError> {
    let reserve = || store.with(|store| store.try_reserve_for(run_id, agent, day, caps, estimate));
    let denial = match budget.gated(reserve) {
        Ok(ReserveOutcome::Reserved(reservation)) => return Ok(reservation),
        Ok(ReserveOutcome::Denied(denial)) => denial,
        Err(err) => ledger_down(agent, day, err),
    };
    Err(refuse(store, denial))
}

/// Fail closed when the budget day cannot be read, with an audit trail.
pub(crate) fn day_denied(store: &StoreHandle<'_>, agent: &str, err: StoreError) -> ChatError {
    refuse(store, ledger_down(agent, "unknown", err))
}

fn ledger_down(agent: &str, day: &str, err: StoreError) -> Denial {
    Denial {
        agent: agent.to_string(),
        day: day.to_string(),
        reason: DenialReason::LedgerUnavailable {
            message: err.to_string(),
        },
        audit_error: None,
    }
}

/// Audit `denial` as `budget.denied` and turn it into the call's error.
fn refuse(store: &StoreHandle<'_>, denial: Denial) -> ChatError {
    let denial = store.with(|store| audit_denial(store, denial));
    ChatError::BudgetDenied {
        reason: denial.reason_text(),
    }
}

/// The estimate one call reserves: its prompt, `tokens_out` of answer.
pub(crate) fn call_estimate(
    request: &ChatRequest,
    model: Option<&str>,
    prices: &PriceTable,
    tokens_out: u64,
) -> UsageTotals {
    let tokens_in = estimate_request_tokens(request).max(1);
    UsageTotals {
        tokens_in,
        tokens_out,
        usd_cents: priced_cents(prices, model, tokens_in, tokens_out),
    }
}

impl<'a> ChatSession<'a> {
    /// The budget whose stop gate this session's usage writes pass.
    fn budget(&self) -> &'static Budget {
        #[cfg(test)]
        if let Some(budget) = self.budget {
            return budget;
        }
        LazyLock::force(&PROCESS)
    }

    /// A usage write outside settling, past this session's stop gate.
    fn usage_write<T>(
        &self,
        write: impl FnOnce(&Store) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.budget().gated(|| self.store.with(write))
    }

    /// Reserve the estimated spend for one provider call, or fail the turn
    /// when a daily cap is reached. The reservation is taken atomically with
    /// the cap check, the caller's own reserve included, so concurrent turns
    /// cannot spend the same headroom; denials are audited as `budget.denied`
    /// before returning.
    ///
    /// A capped output direction is clamped to the remaining headroom (the
    /// caller passes the clamped reservation to the provider as `max_tokens`);
    /// a capped input direction that does not fit is denied. A day latched
    /// closed by an earlier crossing settle is denied with
    /// [`kernel_core::budget::DenialReason::FailClosed`].
    ///
    /// Returns `None` only for an explicit `unlimited = true` (or an empty
    /// per-agent cap set): usage is still recorded after the call. A fresh
    /// config no longer takes this path; it carries the conservative
    /// defaults. The reservation comes held: a turn dropped before it settles
    /// it still settles the reserved estimate.
    pub(super) fn reserve_budget<'k>(
        &self,
        request: &ChatRequest,
    ) -> Result<Option<HeldReservation<'k, StoreHandle<'a>>>, ChatError> {
        let caps = self.budgets.caps_for(&self.agent);
        if caps.is_unlimited() {
            if caps.unlimited {
                tracing::warn!(
                    agent = %self.agent,
                    "budgets.unlimited = true: no daily cap is enforced for this agent"
                );
            }
            return Ok(None);
        }
        let model = request_model(self.provider, request);
        if let Some(message) = unpriced_under_money_cap(&caps, self.prices, self.provider, model) {
            let denial = Denial {
                agent: self.agent.clone(),
                day: self.current_day()?,
                reason: DenialReason::LedgerUnavailable { message },
                audit_error: None,
            };
            let denial = self.store.with(|store| audit_denial(store, denial));
            return Err(ChatError::BudgetDenied {
                reason: denial.reason_text(),
            });
        }

        // The budget day is the Mac's local day at *check* time, not at
        // session start: a turn that crosses midnight starts enforcing the
        // new day on its next provider call.
        let day = self.current_day()?;
        let estimate =
            reservation_estimate(request, request_model(self.provider, request), self.prices);
        admit_in(
            self.budget(),
            &self.store,
            self.run_id.as_deref(),
            &self.agent,
            &day,
            &caps,
            &estimate,
        )
        .map(|reservation| Some(HeldReservation::new(self.store.clone(), reservation)))
    }

    /// Test seam: replace the budget day source for one session.
    #[cfg(test)]
    fn set_day_source(&mut self, source: Box<dyn Fn() -> Result<String, StoreError> + Send>) {
        self.day_source = Some(source);
    }

    /// The local day the next budget check applies to.
    fn current_day(&self) -> Result<String, ChatError> {
        #[cfg(test)]
        if let Some(source) = &self.day_source {
            return source().map_err(|err| self.day_error(err));
        }
        self.store
            .with(|store| store.local_day())
            .map_err(|err| self.day_error(err))
    }

    /// Fail closed when the day itself cannot be read, with an audit trail.
    fn day_error(&self, err: StoreError) -> ChatError {
        day_denied(&self.store, &self.agent, err)
    }

    /// Record the provider call's usage when no cap required a reservation.
    ///
    /// Provider-reported `prompt_tokens`/`completion_tokens` are recorded
    /// verbatim with the `tokens` unit. A direction the provider did not
    /// report (absent `usage`, a missing field, or a zero count) falls back
    /// to the length estimate tagged with [`ESTIMATED_UNIT`], so budgets
    /// stay conservative on providers that report nothing. `usd_cents` is
    /// recorded from the provider-reported cost when the gateway sends one,
    /// otherwise from the configured per-model price table.
    pub(super) fn record_usage(
        &self,
        request: &ChatRequest,
        response: &ChatResponse,
    ) -> Result<(), ChatError> {
        let actual = usage_actual(
            request,
            response,
            request_model(self.provider, request),
            self.prices,
        );
        if actual.tokens_in > 0 {
            self.record_usage_row(
                UsageKind::TokensIn,
                actual.tokens_in,
                unit_for(actual.tokens_in_estimated),
            )?;
        }
        if actual.tokens_out > 0 {
            self.record_usage_row(
                UsageKind::TokensOut,
                actual.tokens_out,
                unit_for(actual.tokens_out_estimated),
            )?;
        }
        if actual.usd_cents > 0 {
            self.record_usage_row(UsageKind::UsdCents, actual.usd_cents, "cents")?;
        }
        Ok(())
    }

    /// INFER-COST-1: one row per brain call with the provider-reported counts.
    /// A failed write is logged, never fatal: budgets use the usage rows.
    pub(super) fn record_usage_call(
        &self,
        request: &ChatRequest,
        response: &ChatResponse,
        round: usize,
    ) {
        let usage = response.usage;
        let call = aux_store::UsageCall {
            run_id: self.run_id.as_deref(),
            agent: &self.agent,
            provider: self.provider.name(),
            model: request_model(self.provider, request),
            call_index: u32::try_from(round).unwrap_or(u32::MAX),
            prompt_tokens: usage.map(|usage| usage.prompt_tokens),
            cached_tokens: usage.and_then(|usage| usage.cached_prompt_tokens),
            completion_tokens: usage.map(|usage| usage.completion_tokens),
        };
        if let Err(err) = self.usage_write(|store| store.record_usage_call(&call)) {
            tracing::warn!(error = %err, "could not record a brain call's token counts");
        }
    }

    /// Insert one usage row, stamped with this turn's identity when it has one.
    fn record_usage_row(&self, kind: UsageKind, amount: u64, unit: &str) -> Result<(), ChatError> {
        let recorded = self.usage_write(|store| match self.run_id.as_deref() {
            Some(run_id) => store.record_usage_for(run_id, &self.agent, kind, amount, unit),
            None => store.record_usage(&self.agent, kind, amount, unit),
        });
        recorded?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testsupport::*;
    use super::super::ChatError;
    use super::*;
    use crate::cancel::TurnCancel;
    use async_trait::async_trait;
    use aux_providers::{
        ChatDelta, ChatMessage, ChatProvider, ChatRequest, ChatResponse, FakeProvider,
        ProviderError, SafeMessage, SafeToolSpec, ToolCall, ToolSpec, Usage,
    };
    use kernel_core::budget::{Budgets, PriceTable, UsageKind};
    use kernel_privacy::safetext::Gate;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    // ---- streaming ----

    /// Provider whose stream emits one delta, then hangs: cancellation must
    /// abort it promptly and settle nothing.
    struct HangingStreamProvider {
        inner: FakeProvider,
        started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl ChatProvider for HangingStreamProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.inner.complete(req).await
        }

        async fn complete_streaming(
            &self,
            req: &ChatRequest,
            sink: &(dyn Fn(ChatDelta) + Send + Sync),
        ) -> Result<ChatResponse, ProviderError> {
            let response = self.inner.complete(req).await?;
            sink(ChatDelta::Text("partial ".to_string()));
            self.started.notify_one();
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(response)
        }

        fn name(&self) -> &str {
            self.inner.name()
        }
    }

    #[tokio::test]
    async fn streaming_cancellation_aborts_mid_stream_and_settles_the_streamed_estimate() {
        let harness = Harness::new();
        let cancel = TurnCancel::new();
        let provider = HangingStreamProvider {
            inner: FakeProvider::echo("fake"),
            started: Arc::new(tokio::sync::Notify::new()),
        };
        let events = RecordingEvents::new();
        let mut session = harness.start_cancellable_with_events(
            &provider,
            vec![],
            RecordingApprover::new(false),
            cancel.clone(),
            events.clone(),
        );
        let session_id = session.session.id;

        let started = Arc::clone(&provider.started);
        let canceller = tokio::spawn(async move {
            started.notified().await;
            cancel.cancel();
        });

        let err = session.send("hello").await.unwrap_err();
        canceller.await.unwrap();

        assert!(matches!(err, ChatError::Cancelled), "got {err:?}");
        assert_eq!(
            harness.roles(session_id),
            vec!["system", "user"],
            "a cancelled stream persists no partial assistant row"
        );
        // I-01: the tokens the provider was already fed (and the partial
        // answer it already generated) are settled, not released at zero.
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert!(
            totals.tokens_in > 0,
            "the request's input estimate must be settled: {totals:?}"
        );
        assert_eq!(
            totals.tokens_out,
            estimate_tokens("partial "),
            "the streamed text is settled as output: {totals:?}"
        );
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "the reservation is settled, never left open"
        );
        let recorded = deltas(&events.calls());
        assert_eq!(
            recorded.len(),
            1,
            "the delta emitted before the cancel reached the sink"
        );
        assert_eq!(recorded[0].2, "partial ");
    }

    /// A provider that emits one delta and then fails the way a real stream
    /// can: a mid-stream protocol error, an idle timeout, or the body
    /// ceiling. All three must settle the streamed estimate (I-01).
    struct DeltaThenFail {
        kind: FailKind,
        started: Arc<tokio::sync::Notify>,
    }

    #[derive(Debug, Clone, Copy)]
    enum FailKind {
        Error,
        Timeout,
        TooLarge,
    }

    impl FailKind {
        fn error(self) -> ProviderError {
            match self {
                Self::Error => ProviderError::InvalidResponse {
                    provider: "fake".to_string(),
                    message: "upstream reset mid-stream".to_string(),
                },
                Self::Timeout => ProviderError::Timeout {
                    provider: "fake".to_string(),
                },
                Self::TooLarge => ProviderError::InvalidResponse {
                    provider: "fake".to_string(),
                    message: format!(
                        "stream_too_large: stream line exceeds {} bytes without a newline",
                        4 * 1024 * 1024
                    ),
                },
            }
        }
    }

    #[async_trait]
    impl ChatProvider for DeltaThenFail {
        async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            Err(self.kind.error())
        }

        async fn complete_streaming(
            &self,
            _req: &ChatRequest,
            sink: &(dyn Fn(ChatDelta) + Send + Sync),
        ) -> Result<ChatResponse, ProviderError> {
            sink(ChatDelta::Text("partial answer ".to_string()));
            self.started.notify_one();
            tokio::task::yield_now().await;
            Err(self.kind.error())
        }

        fn name(&self) -> &str {
            "fake"
        }
    }

    #[tokio::test]
    async fn a_stream_that_fails_mid_answer_settles_the_streamed_estimate() {
        for kind in [FailKind::Error, FailKind::Timeout, FailKind::TooLarge] {
            let harness = Harness::new();
            let provider = DeltaThenFail {
                kind,
                started: Arc::new(tokio::sync::Notify::new()),
            };
            let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
            let session_id = session.session.id;

            let err = session.send("hello").await.unwrap_err();
            assert!(
                matches!(err, ChatError::Provider(_)),
                "{kind:?}: got {err:?}"
            );
            assert_eq!(
                harness.roles(session_id),
                vec!["system", "user"],
                "{kind:?}: a failed stream persists no partial row"
            );
            let day = harness.store().local_day().unwrap();
            let totals = harness.store().usage_totals("main", &day).unwrap();
            assert!(
                totals.tokens_in > 0,
                "{kind:?}: the input estimate must be settled: {totals:?}"
            );
            assert_eq!(
                totals.tokens_out,
                estimate_tokens("partial answer "),
                "{kind:?}: the streamed text is settled as output: {totals:?}"
            );
            assert_eq!(
                harness.store().reservation_count().unwrap(),
                0,
                "{kind:?}: the reservation is settled exactly once"
            );
        }
    }

    /// I-02: the reservation TTL must outlive the longest stream one call can
    /// run, or a concurrent turn could reserve the same headroom while the
    /// provider is still generating (and billing).
    #[test]
    fn reservation_ttl_covers_the_maximum_stream_life() {
        let max_stream = aux_providers::openai_compat::DEFAULT_TIMEOUT
            * aux_providers::openai_compat::STREAM_TOTAL_TIMEOUT_FACTOR;
        assert!(
            kernel_core::budget::RESERVATION_TTL > max_stream,
            "RESERVATION_TTL ({:?}) must exceed the maximum stream life ({max_stream:?})",
            kernel_core::budget::RESERVATION_TTL
        );
    }

    #[tokio::test]
    async fn streaming_settles_the_budget_once_with_provider_reported_usage() {
        let harness = Harness::new();
        let usage = Usage {
            prompt_tokens: 11,
            completion_tokens: 7,
            cost_usd: None,
            cached_prompt_tokens: None,
        };
        let provider = FakeProvider::scripted(
            "fake",
            vec![ChatResponse::assistant("done").with_usage(usage)],
        )
        .with_stream_chunks(2);
        let events = RecordingEvents::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(10_000);
        let mut session = harness.start_cancellable_with_events_and_budget(
            &provider,
            vec![],
            RecordingApprover::new(false),
            &budgets,
            TurnCancel::new(),
            events.clone(),
        );
        let session_id = session.session.id;

        session.send("hello").await.unwrap();

        let day = harness.store().local_day().unwrap();
        assert_eq!(
            harness.store().usage_totals("main", &day).unwrap(),
            kernel_core::UsageTotals {
                tokens_in: 11,
                tokens_out: 7,
                usd_cents: 0,
            },
            "the streamed usage settles the reservation exactly once"
        );
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "the reservation is settled, never left open"
        );
        assert_eq!(
            harness.roles(session_id),
            vec!["system", "user", "assistant"]
        );
        let streamed: String = deltas(&events.calls())
            .iter()
            .map(|(_, _, text)| text.as_str())
            .collect();
        assert_eq!(streamed, "done");
    }

    // ---- budgets & usage ----

    /// Provider that never reports usage: exercises the estimate fallback.
    struct NoUsageProvider {
        requests: Mutex<Vec<ChatRequest>>,
        response: ChatResponse,
    }

    impl NoUsageProvider {
        fn new(response: ChatResponse) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                response,
            }
        }

        fn requests(&self) -> Vec<ChatRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ChatProvider for NoUsageProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.requests.lock().unwrap().push(req.clone());
            Ok(self.response.clone())
        }

        fn name(&self) -> &str {
            "no-usage"
        }
    }

    #[tokio::test]
    async fn usage_is_recorded_after_each_provider_call() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        // The fake reports one token per character (not the chars/4 estimate).
        let request = &provider.requests()[0];
        let expected_in: u64 = request
            .messages
            .iter()
            .map(|message| message.content().as_str().chars().count() as u64)
            .sum();
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_in, expected_in, "got {totals:?}");
        assert_eq!(totals.tokens_out, 2, "`hi` is two characters: {totals:?}");
        assert_ne!(
            totals.tokens_in,
            estimate_request_tokens(request),
            "reported usage must not be the estimate"
        );
        assert_eq!(totals.usd_cents, 0, "no pricing data: usd_cents unrecorded");
        // A single completion records both directions for this agent only.
        assert_eq!(
            harness.store().usage_totals("axis", &day).unwrap(),
            kernel_core::UsageTotals::default()
        );
    }

    #[tokio::test]
    async fn each_brain_call_of_a_turn_records_its_own_counts() {
        let harness = Harness::new();
        let usage = |cached| Usage {
            prompt_tokens: 100,
            completion_tokens: 5,
            cost_usd: None,
            cached_prompt_tokens: cached,
        };
        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![write_file_call("call_1", "note.txt", "hello from aux")],
                ))
                .with_usage(usage(None)),
                ChatResponse::assistant("done").with_usage(usage(Some(80))),
            ],
        );
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(true));

        assert_eq!(session.send("write a note").await.unwrap().rounds, 2);

        let day = harness.store().local_day().unwrap();
        let c = harness
            .store()
            .usage_call_totals(Some("main"), &day)
            .unwrap();
        let counts = (c.calls, c.max_call_index, c.prompt_tokens, c.cached_tokens);
        assert_eq!(counts, (2, 2, 200, 80), "{c:?}");
        assert_eq!(
            c.cache_hit_percent(),
            Some(80.0),
            "unreported call left out"
        );
    }

    #[tokio::test]
    async fn provider_reported_usage_lands_in_usage_totals() {
        let harness = Harness::new();
        let response = ChatResponse::assistant("done").with_usage(Usage {
            prompt_tokens: 1_234,
            completion_tokens: 567,
            cost_usd: None,
            cached_prompt_tokens: None,
        });
        let provider = FakeProvider::repeating("fake", response);
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(
            totals,
            kernel_core::UsageTotals {
                tokens_in: 1_234,
                tokens_out: 567,
                usd_cents: 0,
            },
            "real numbers land verbatim; usd_cents stays unrecorded"
        );
    }

    #[tokio::test]
    async fn missing_usage_falls_back_to_the_estimate() {
        let harness = Harness::new();
        let provider = NoUsageProvider::new(ChatResponse::assistant("hi"));
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        let request = &provider.requests()[0];
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_in, estimate_request_tokens(request));
        assert_eq!(
            totals.tokens_out,
            estimate_response_tokens(&ChatResponse::assistant("hi"))
        );
        assert!(totals.tokens_in > 0 && totals.tokens_out > 0);
    }

    #[tokio::test]
    async fn zero_usage_field_falls_back_per_direction() {
        let harness = Harness::new();
        // Prompt missing (0) but completion reported: directions are
        // independent, the missing one falls back to the estimate.
        let response = ChatResponse::assistant("hi").with_usage(Usage {
            prompt_tokens: 0,
            completion_tokens: 77,
            cost_usd: None,
            cached_prompt_tokens: None,
        });
        let provider = NoUsageProvider::new(response);
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        session.send("hello").await.unwrap();

        let request = &provider.requests()[0];
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_in, estimate_request_tokens(request));
        assert_eq!(totals.tokens_out, 77);
    }

    #[tokio::test]
    async fn a_agent_over_its_daily_cap_is_denied_before_any_provider_call() {
        let harness = Harness::new();
        let day = harness.store().local_day().unwrap();
        harness
            .store()
            .record_usage_at("main", UsageKind::TokensIn, 5, "tokens", &day)
            .unwrap();
        let mut budgets = Budgets::default();
        budgets.default.tokens_in = Some(5);

        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("never"));
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let session_id = session.session.id;

        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(
            err.to_string().contains("tokens_in"),
            "reason should name the cap: {err}"
        );
        assert_eq!(provider.request_count(), 0, "no provider call may happen");
        assert_eq!(harness.roles(session_id), vec!["system", "user"]);
        assert_eq!(
            harness.store().event_count("budget.denied").unwrap(),
            1,
            "the denial is audited"
        );
    }

    #[tokio::test]
    async fn a_turn_that_reaches_the_cap_blocks_the_next_one() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("hi"));

        // The engine's input estimate is internal, and admission now requires
        // the caller's own reserve to fit under the cap (B-01R). So run the
        // first turn with a generous cap, then pin the cap to exactly what it
        // recorded: the next turn's reserve can never fit again.
        let mut generous = Budgets::default();
        generous.default.tokens_in = Some(1_000_000);
        let first = {
            let mut session =
                harness.start_with(&provider, vec![], RecordingApprover::new(false), &generous);
            session.send("hello").await.unwrap()
        };
        assert_eq!(first.text, "hi");
        let day = harness.store().local_day().unwrap();
        let recorded = harness
            .store()
            .usage_totals("main", &day)
            .unwrap()
            .tokens_in;
        assert!(recorded >= 1);
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "the reservation was replaced by the real rows"
        );

        let mut exact = Budgets::default();
        exact.default.tokens_in = Some(recorded);
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &exact);
        let err = session.send("again").await.unwrap_err();
        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert_eq!(provider.request_count(), 1, "the second call is blocked");
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
    }

    #[tokio::test]
    async fn budget_day_is_recomputed_at_every_check() {
        let harness = Harness::new();
        // The output cap is already spent on the *next* local day; a session
        // that pinned its day at start would keep checking the old one.
        harness
            .store()
            .record_usage_at("main", UsageKind::TokensOut, 10, "tokens", "2026-10-04")
            .unwrap();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(10);

        let provider = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![write_file_call("call_1", "note.txt", "content")],
                )),
                ChatResponse::assistant("done"),
            ],
        );
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let calls = Arc::new(AtomicUsize::new(0));
        let day_calls = Arc::clone(&calls);
        session.set_day_source(Box::new(move || {
            let index = day_calls.fetch_add(1, Ordering::SeqCst);
            Ok(if index == 0 {
                "2026-10-03"
            } else {
                "2026-10-04"
            }
            .to_string())
        }));

        let err = session.send("write a note").await.unwrap_err();

        let reason = match err {
            ChatError::BudgetDenied { reason } => reason,
            other => panic!("expected a budget denial, got {other:?}"),
        };
        assert!(
            reason.contains("2026-10-04"),
            "the denial must name the recomputed day: {reason}"
        );
        assert_eq!(provider.request_count(), 1, "the second call is denied");
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "the day is read again for every provider call"
        );
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
    }

    #[tokio::test]
    async fn default_budgets_deny_a_turn_once_the_day_is_spent() {
        // `Budgets::default()` carries the conservative daily caps, so a fresh
        // config enforces them before any provider call.
        let harness = Harness::new();
        harness
            .store()
            .record_usage(
                "main",
                UsageKind::TokensIn,
                kernel_core::budget::DEFAULT_DAILY_TOKENS_IN,
                "tokens",
            )
            .unwrap();
        let provider = FakeProvider::echo("fake");
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert_eq!(
            provider.request_count(),
            0,
            "the cap must be enforced before the provider is called"
        );
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "a denied call leaves no reservation behind"
        );
    }

    #[tokio::test]
    async fn explicit_unlimited_is_the_only_uncapped_path() {
        let harness = Harness::new();
        harness
            .store()
            .record_usage(
                "main",
                UsageKind::TokensIn,
                kernel_core::budget::DEFAULT_DAILY_TOKENS_IN,
                "tokens",
            )
            .unwrap();
        let mut budgets = Budgets::default();
        budgets.default.unlimited = true;
        let provider = FakeProvider::echo("fake");
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        // The day is over the (ignored) default cap; an explicit opt-out
        // still runs, and usage is recorded rather than reserved.
        session.send("hello").await.unwrap();
        assert_eq!(provider.request_count(), 1);
        assert_eq!(harness.store().reservation_count().unwrap(), 0);
    }

    // ---- B-01R: concurrency bound and fail-closed latch ----

    /// Provider that holds every call at a rendezvous until `parties` calls
    /// are in flight, so all reservations are taken before any settle, then
    /// either honors `max_tokens` (compliant) or ignores it and returns a
    /// huge completion.
    struct BatchProvider {
        parties: usize,
        ignore_max_tokens: bool,
        arrived: AtomicUsize,
        requests: Mutex<Vec<ChatRequest>>,
    }

    impl BatchProvider {
        fn new(parties: usize, ignore_max_tokens: bool) -> Self {
            Self {
                parties,
                ignore_max_tokens,
                arrived: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<ChatRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn max_tokens_seen(&self) -> Vec<u32> {
            self.requests()
                .iter()
                .map(|request| {
                    request
                        .max_tokens
                        .expect("a capped agent passes max_tokens")
                })
                .collect()
        }
    }

    #[async_trait]
    impl ChatProvider for BatchProvider {
        async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.requests.lock().unwrap().push(req.clone());
            self.arrived.fetch_add(1, Ordering::SeqCst);
            while self.arrived.load(Ordering::SeqCst) < self.parties {
                tokio::task::yield_now().await;
            }
            let completion = if self.ignore_max_tokens {
                100_000
            } else {
                u64::from(req.max_tokens.unwrap_or(0))
            };
            let text = "x".repeat(completion as usize);
            Ok(ChatResponse::assistant(text).with_usage(Usage {
                prompt_tokens: 1,
                completion_tokens: completion,
                cost_usd: None,
                cached_prompt_tokens: None,
            }))
        }

        fn name(&self) -> &str {
            "batch"
        }
    }

    #[tokio::test]
    async fn two_concurrent_turns_cannot_overshoot_a_compliant_cap() {
        // The B-01R reproducer: cap_out = 5 000, two ordinary turns. Both
        // reserve before either settles (the provider rendezvous); with a
        // provider that honors `max_tokens`, the day settles at the cap.
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(5_000);
        let provider = BatchProvider::new(2, false);

        let mut first =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut second =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let (first, second) = tokio::join!(first.send("one"), second.send("two"));
        first.unwrap();
        second.unwrap();

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(
            totals.tokens_out, 5_000,
            "both calls settle their clamped reserves, never past the cap: {totals:?}"
        );
        assert_eq!(
            provider.max_tokens_seen(),
            vec![4_096, 904],
            "the first call reserves 4096, the second gets the 904 left"
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);

        // The day is at its cap: a third call is denied before any provider
        // call (the second settle latched it closed).
        let mut third =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let err = third.send("three").await.unwrap_err();
        let reason = match err {
            ChatError::BudgetDenied { reason } => reason,
            other => panic!("expected a budget denial, got {other:?}"),
        };
        assert!(reason.contains("failing closed"), "{reason}");
        assert_eq!(provider.requests().len(), 2, "no third provider call");
    }

    #[tokio::test]
    async fn eight_concurrent_turns_cannot_overshoot_a_compliant_cap() {
        // Same race, 8-way: every admitted reservation fits under the cap, so
        // the compliant day settles at 8 × 4096 <= 50 000.
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(50_000);
        let provider = BatchProvider::new(8, false);

        let mut s1 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s2 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s3 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s4 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s5 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s6 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s7 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut s8 = harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let results = tokio::join!(
            s1.send("1"),
            s2.send("2"),
            s3.send("3"),
            s4.send("4"),
            s5.send("5"),
            s6.send("6"),
            s7.send("7"),
            s8.send("8"),
        );
        for result in [
            results.0, results.1, results.2, results.3, results.4, results.5, results.6, results.7,
        ] {
            result.unwrap();
        }

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_out, 8 * 4_096);
        assert!(
            totals.tokens_out <= 50_000,
            "compliant output stays under the cap: {totals:?}"
        );
        assert_eq!(
            provider.max_tokens_seen(),
            vec![4_096; 8],
            "each of the 8 calls reserved the default output budget"
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn concurrent_non_compliant_calls_settle_then_the_day_latches() {
        // A provider that ignores `max_tokens` can only overshoot with the
        // calls already in flight; once a settle reaches the cap, the day is
        // latched and no further call starts.
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(5_000);
        let provider = BatchProvider::new(2, true);

        let mut first =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let mut second =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let (first, second) = tokio::join!(first.send("one"), second.send("two"));
        first.unwrap();
        second.unwrap();

        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert_eq!(
            totals.tokens_out, 200_000,
            "the two in-flight calls are recorded honestly"
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);

        let mut third =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let err = third.send("three").await.unwrap_err();
        let reason = match err {
            ChatError::BudgetDenied { reason } => reason,
            other => panic!("expected a budget denial, got {other:?}"),
        };
        assert!(reason.contains("failing closed"), "{reason}");
        assert!(
            reason.contains("tokens_out budget"),
            "the latch names the crossed cap: {reason}"
        );
        assert_eq!(
            provider.requests().len(),
            2,
            "the latched day admits no third call"
        );
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
        // The latch itself is audited once, before any denial.
        assert_eq!(harness.store().event_count("budget.latched").unwrap(), 1);
    }

    #[tokio::test]
    async fn a_provider_that_ignores_max_tokens_is_latched_closed() {
        let harness = Harness::new();
        let mut budgets = Budgets::default();
        budgets.default.tokens_out = Some(5_000);
        let provider = BatchProvider::new(1, true);

        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        session.send("hello").await.unwrap();

        // The provider was asked for at most 4096 output tokens and returned
        // 100 000; the ledger records that honestly.
        assert_eq!(provider.max_tokens_seen(), vec![4_096]);
        let day = harness.store().local_day().unwrap();
        assert_eq!(
            harness
                .store()
                .usage_totals("main", &day)
                .unwrap()
                .tokens_out,
            100_000
        );
        assert_eq!(harness.store().reservation_count().unwrap(), 0);

        let err = session.send("again").await.unwrap_err();
        match err {
            ChatError::BudgetDenied { reason } => assert!(
                reason.contains("failing closed")
                    && reason.contains("tokens_out budget (100000/5000)"),
                "{reason}"
            ),
            other => panic!("expected a budget denial, got {other:?}"),
        }
        assert_eq!(provider.requests().len(), 1);

        // The audit trail shows the refusal and the closure.
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
        assert_eq!(harness.store().event_count("budget.latched").unwrap(), 1);
    }

    #[test]
    fn token_estimates_round_up() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
    }

    #[test]
    fn token_estimates_weight_non_ascii_three_times() {
        // 5 emoji: (5 × 3).div_ceil(4) = 4, versus 2 for the old chars/4.
        assert_eq!(estimate_tokens("😀😀😀😀😀"), 4);
        // 4 CJK characters: (4 × 3).div_ceil(4) = 3.
        assert_eq!(estimate_tokens("你好世界"), 3);
        // Mixed text weights only the non-ASCII characters.
        assert_eq!(estimate_tokens("abcd你好"), (4u64 + 6).div_ceil(4));
        // ASCII-only estimates are unchanged.
        assert_eq!(estimate_tokens("hello world"), 3);
    }

    #[test]
    fn token_estimates_cover_requests_and_responses() {
        let mut gate = tokenising_gate([6u8; 32]);
        let issue =
            |gate: &mut Gate, message: ChatMessage| SafeMessage::issue(gate, &message).unwrap();
        let request = ChatRequest::new(vec![issue(&mut gate, ChatMessage::user("hello"))]);
        assert_eq!(estimate_request_tokens(&request), 2);

        let call = ToolCall::new("call_1", "shell", json!({ "cmd": "ls" }));
        let tool = ToolSpec::new("shell", "run a command", json!({ "type": "object" }));
        let request = ChatRequest::new(vec![issue(
            &mut gate,
            ChatMessage::assistant_with_tool_calls("", vec![call]),
        )])
        .with_tools(vec![SafeToolSpec::issue(&mut gate, &tool).unwrap()]);
        assert!(
            estimate_request_tokens(&request) > 0,
            "tool payloads count toward input usage"
        );

        assert_eq!(
            estimate_response_tokens(&ChatResponse::assistant("done")),
            1
        );
    }

    struct HangingProvider;

    #[async_trait]
    impl ChatProvider for HangingProvider {
        async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Err(ProviderError::Unauthorized {
                provider: "hanging".to_string(),
            })
        }

        fn name(&self) -> &str {
            "hanging"
        }
    }

    #[tokio::test]
    async fn cancelling_a_provider_call_settles_the_input_estimate_once() {
        // I-01: the provider-phase path no longer releases at zero. A
        // cancelled call settles the request's input estimate (the prompt was
        // sent) with zero output (nothing streamed), exactly once — a
        // repeated cancel cannot settle twice (the store deletes the
        // reservation on the first settle).
        let harness = Harness::new();
        let provider = HangingProvider;
        let cancel = TurnCancel::new();
        let mut session = harness.start_cancellable(
            &provider,
            vec![],
            RecordingApprover::new(false),
            Arc::clone(&cancel),
        );

        let mut turn = Box::pin(session.send("go"));
        let cancel_when_reserved = async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while harness.store().reservation_count().unwrap() != 1 {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the reservation never appeared"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            cancel.cancel();
            // A second cancel must be a no-op, not a second settle.
            cancel.cancel();
        };
        let joined = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(&mut turn, cancel_when_reserved)
        })
        .await
        .expect("cancellation must end the turn promptly");
        assert!(matches!(joined.0.unwrap_err(), ChatError::Cancelled));

        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "a cancelled provider call settles its reservation, never leaves it open"
        );
        let day = harness.store().local_day().unwrap();
        let totals = harness.store().usage_totals("main", &day).unwrap();
        assert!(
            totals.tokens_in > 0,
            "the cancelled request's input estimate is settled: {totals:?}"
        );
        assert_eq!(
            totals.tokens_out, 0,
            "nothing streamed before the cancel: {totals:?}"
        );
    }

    /// A provider that takes the request, streams `before`, then never answers.
    struct AcceptsThenHangs {
        before: Vec<ChatDelta>,
        sent: tokio::sync::Notify,
    }

    #[async_trait]
    impl ChatProvider for AcceptsThenHangs {
        async fn complete(&self, _req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
            self.sent.notify_one();
            std::future::pending().await
        }

        async fn complete_streaming(
            &self,
            _req: &ChatRequest,
            sink: &(dyn Fn(ChatDelta) + Send + Sync),
        ) -> Result<ChatResponse, ProviderError> {
            for delta in &self.before {
                sink(delta.clone());
            }
            self.sent.notify_one();
            std::future::pending().await
        }

        fn name(&self) -> &str {
            "hangs"
        }
    }

    /// One turn whose future is dropped once its provider has the request
    /// (and streamed `before`): `main`'s totals today, reservations still held.
    async fn dropped_after_dispatch(before: Vec<ChatDelta>) -> (UsageTotals, usize) {
        let harness = Harness::new();
        let provider = AcceptsThenHangs {
            before,
            sent: tokio::sync::Notify::new(),
        };
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
        tokio::select! {
            _ = session.send("hello") => panic!("the provider never answers"),
            () = provider.sent.notified() => {}
        }
        settled(&harness.store);
        let store = harness.store();
        let day = store.local_day().unwrap();
        let totals = store.usage_totals("main", &day).unwrap();
        (totals, store.reservation_count().unwrap())
    }

    #[tokio::test]
    async fn a_turn_dropped_after_dispatch_still_charges_its_reserve() {
        let partial = ChatDelta::Text("partial ".to_string());
        for before in [vec![], vec![partial]] {
            let (totals, held) = dropped_after_dispatch(before).await;
            assert_eq!(held, 0, "settled, not left to expire");
            assert!(totals.tokens_in > 0, "{totals:?}");
            assert_eq!(
                totals.tokens_out, DEFAULT_OUTPUT_RESERVE,
                "never less than the reserve: {totals:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_dropped_turn_charges_what_streamed_when_it_tops_the_reserve() {
        let usage = Usage {
            prompt_tokens: 90_000,
            completion_tokens: 5_000,
            ..Default::default()
        };
        let (totals, held) = dropped_after_dispatch(vec![ChatDelta::Usage(usage)]).await;
        assert_eq!(held, 0, "settled once");
        assert_eq!((totals.tokens_in, totals.tokens_out), (90_000, 5_000));
    }

    /// Waits (10 s at most) for the settlement worker to settle all of
    /// `store`, then reads the day's totals for "main".
    fn settled(store: &Mutex<Store>) -> UsageTotals {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let store = kernel_core::lock_recover(store);
            if store.reservation_count().unwrap() == 0 {
                return store
                    .usage_totals("main", &store.local_day().unwrap())
                    .unwrap();
            }
            drop(store);
            assert!(std::time::Instant::now() < deadline, "never settled");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// `tokens_in` in, 9 out, for "main" under a 100-token input cap.
    fn reserve(store: &Mutex<Store>, tokens_in: u64) -> ReserveOutcome {
        let store = kernel_core::lock_recover(store);
        let caps = BudgetCaps {
            tokens_in: Some(100),
            ..Default::default()
        };
        let estimate = UsageTotals {
            tokens_in,
            tokens_out: 9,
            usd_cents: 0,
        };
        let day = store.local_day().unwrap();
        store
            .try_reserve_for(None, "main", &day, &caps, &estimate)
            .unwrap()
    }

    const EXPIRE: &str = "UPDATE usage_reservations SET expires_at = '2000-01-01 00:00:00'";

    #[test]
    fn a_call_above_its_reserve_outlives_failed_settles_and_records_its_actual_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
        let ReserveOutcome::Reserved(reservation) = reserve(&store, 60) else {
            panic!("admitted");
        };
        // Each try is counted (its raise is an update), and the store refuses
        // settles, as a busy one would, while `hold` has a row.
        let raw = aux_store::open_keyed(&path).unwrap();
        raw.execute_batch(
            "CREATE TABLE tries(n); CREATE TABLE hold(n); INSERT INTO hold VALUES (1);
             CREATE TRIGGER tried AFTER UPDATE ON usage_reservations
             BEGIN INSERT INTO tries VALUES (1); END;
             CREATE TRIGGER busy BEFORE DELETE ON usage_reservations
             WHEN EXISTS (SELECT 1 FROM hold) BEGIN SELECT RAISE(ABORT, 'database is busy'); END;",
        )
        .unwrap();
        // Dropped knowing more than it reserved: its job is the only copy.
        let known = UsageActual {
            tokens_in: 90,
            tokens_out: 20,
            ..UsageActual::default()
        };
        drop(HeldReservation::new(Arc::clone(&store), reservation).or_known(move || known));
        let tries = || raw.query_row("SELECT COUNT(*) FROM tries", [], |row| row.get::<_, i64>(0));
        let deadline = Instant::now() + Duration::from_secs(30);
        while tries().unwrap() < 200 {
            assert!(Instant::now() < deadline, "the retries stopped");
            std::thread::sleep(Duration::from_millis(5));
        }
        // Past 150 failures and its TTL, the row holds the actual: 20 more
        // would fit beside the reserve (60 + 20), not beside it (90 + 20).
        raw.execute_batch(EXPIRE).unwrap();
        assert!(matches!(reserve(&store, 20), ReserveOutcome::Denied(_)));
        raw.execute_batch("DELETE FROM hold").unwrap();
        let totals = settled(&store);
        assert_eq!(
            (totals.tokens_in, totals.tokens_out),
            (90, 20),
            "the actual, once"
        );
    }

    /// A store that refuses every settle, counting the updates run on its
    /// reservations (a try's raise), and a job owing its one held row at 90.
    fn refusing_store() -> (tempfile::TempDir, SettleJob) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
        let ReserveOutcome::Reserved(reservation) = reserve(&store, 60) else {
            panic!("admitted");
        };
        aux_store::open_keyed(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE tries(n);
                 CREATE TRIGGER tried AFTER UPDATE ON usage_reservations
                 BEGIN INSERT INTO tries VALUES (1); END;
                 CREATE TRIGGER refuse BEFORE DELETE ON usage_reservations
                 BEGIN SELECT RAISE(ABORT, 'refused'); END;",
            )
            .unwrap();
        let actual = UsageActual {
            tokens_in: 90,
            ..UsageActual::default()
        };
        (
            dir,
            SettleJob {
                store,
                reservation,
                actual,
            },
        )
    }

    fn count(dir: &tempfile::TempDir, sql: &str) -> i64 {
        let raw = aux_store::open_keyed(&dir.path().join("store.db")).unwrap();
        raw.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    const TRIES: &str = "SELECT COUNT(*) FROM tries";
    const HELD: &str = "SELECT COUNT(*) FROM usage_reservations";
    const HELD_IN: &str = "SELECT tokens_in FROM usage_reservations";

    /// A budget of its own: the process-wide one must outlive the other tests.
    fn budget() -> &'static Budget {
        Box::leak(Box::<Budget>::default())
    }

    /// A worker of its own (the process-wide one must outlive the other
    /// tests), retrying a job against a store that refuses every settle.
    #[test]
    fn stop_ends_a_worker_mid_retry_runs_no_more_sql_and_keeps_the_row_held() {
        let (dir, job) = refusing_store();
        let budget = budget();
        budget.settler().send(Work::Settle(Box::new(job)));
        let deadline = Instant::now() + Duration::from_secs(30);
        while count(&dir, TRIES) < 5 {
            assert!(Instant::now() < deadline, "the worker never retried");
            std::thread::sleep(Duration::from_millis(2));
        }
        let asked = Instant::now();
        assert!(budget.stop(Duration::from_secs(2)), "the worker ended");
        assert!(asked.elapsed() < Duration::from_secs(2), "within the bound");
        let after_stop = count(&dir, TRIES);
        std::thread::sleep(Duration::from_millis(100)); // 25+ retries' worth
        assert_eq!(count(&dir, TRIES), after_stop, "no SQL runs after stop");
        assert_eq!(count(&dir, HELD), 1, "the row is still held");
        assert_eq!(count(&dir, HELD_IN), 90, "raised to its amount");
    }

    /// The first stop times out on the store's lock, past its record window;
    /// the retry opens a new one, so the owed actual is still recorded.
    #[test]
    fn a_second_stop_after_a_timed_out_one_records_the_owed_actual() {
        let (dir, job) = refusing_store();
        let budget = budget();
        let store = Arc::clone(&job.store);
        let held = store.lock().unwrap();
        budget.settler().send(Work::Settle(Box::new(job)));
        assert!(!budget.stop(Duration::from_millis(50)), "still blocked");
        std::thread::sleep(RECORD_WINDOW * 2);
        drop(held); // the worker finds the window closed, and keeps the job
        assert_eq!(count(&dir, HELD_IN), 60, "nothing written past the window");
        assert!(budget.stop(Duration::from_secs(10)), "a new window");
        assert_eq!(count(&dir, TRIES), 1, "one raise, no settle");
        assert_eq!(count(&dir, HELD_IN), 90, "the owed actual, recorded");
    }

    /// An inline settle past the gate, blocked on the store's lock: the stop
    /// says false while it runs, and a settle it refuses meanwhile is handed
    /// over. Both rows are raised to their actual; no SQL runs after a true.
    #[test]
    fn a_stop_waits_for_an_inline_settle_and_records_a_refused_one() {
        let (dir, job) = refusing_store();
        let ReserveOutcome::Reserved(second) = reserve(&job.store, 20) else {
            panic!("admitted");
        };
        let budget = budget();
        let locked = job.store.lock().unwrap();
        let held = HeldReservation::new_in(budget, Arc::clone(&job.store), job.reservation);
        let settling = std::thread::spawn(move || held.settle(&job.actual));
        while kernel_core::lock_recover(&budget.gate).in_flight == 0 {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!budget.stop(Duration::from_millis(50)), "still running");
        let refused = HeldReservation::new_in(budget, Arc::clone(&job.store), second);
        assert!(refused.settle(&job.actual).is_err(), "refused at the gate");
        drop(locked);
        assert!(budget.stop(Duration::from_secs(10)), "done once it is");
        let tries = count(&dir, TRIES);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(count(&dir, TRIES), tries, "no SQL runs after stop");
        assert!(settling.join().unwrap().is_err(), "refused by the store");
        let least = "SELECT MIN(tokens_in) FROM usage_reservations";
        assert_eq!(count(&dir, least), 90, "both actuals, recorded");
    }

    /// A stop before the worker exists still holds: a later settle is
    /// refused, and no worker starts.
    #[test]
    fn a_stop_before_the_worker_exists_refuses_settles_and_starts_none() {
        let budget = budget();
        assert!(budget.stop(Duration::from_secs(2)));
        let (dir, job) = refusing_store();
        let held = HeldReservation::new_in(budget, job.store, job.reservation);
        let worker = &budget.settler.get().unwrap().worker;
        assert!(kernel_core::lock_recover(worker).is_none(), "none started");
        assert!(held.settle(&job.actual).is_err(), "refused");
        assert_eq!(count(&dir, TRIES), 0, "no statement ran");
    }

    /// Usage writes outside settling meet the settle gate: one in flight when
    /// the stop is asked is waited for, and every one attempted after it is
    /// refused, so nothing lands once the stop has returned true.
    #[test]
    fn usage_writes_are_waited_for_or_refused_and_none_lands_after_a_stop() {
        let harness = Harness::new();
        let provider = FakeProvider::echo("fake");
        let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));
        let budget = budget();
        session.budget = Some(budget);
        let mut gate = tokenising_gate([7u8; 32]);
        let message = SafeMessage::issue(&mut gate, &ChatMessage::user("hello")).unwrap();
        let request = ChatRequest::new(vec![message]);
        let response = ChatResponse::assistant("done");
        let day = harness.store().local_day().unwrap();
        let rows = || {
            let store = harness.store();
            let totals = store.usage_totals("main", &day).unwrap();
            let calls = store.usage_call_totals(None, &day).unwrap().calls;
            (totals.tokens_in, calls, store.reservation_count().unwrap())
        };

        // A write in flight when the stop is asked: the stop waits for it.
        let stopper = std::sync::OnceLock::new();
        session
            .usage_write(|store| {
                let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let flag = Arc::clone(&done);
                stopper.get_or_init(|| {
                    std::thread::spawn(move || {
                        let ended = budget.stop(Duration::from_secs(10));
                        flag.store(true, Ordering::SeqCst);
                        ended
                    })
                });
                while !budget.stopped() {
                    std::thread::sleep(Duration::from_millis(2));
                }
                std::thread::sleep(Duration::from_millis(100));
                assert!(!done.load(Ordering::SeqCst), "the stop waits for a write");
                store.record_usage("main", UsageKind::TokensIn, 5, "tokens")
            })
            .unwrap();
        assert!(stopper.into_inner().unwrap().join().unwrap(), "then ends");
        let landed = rows();
        assert_eq!(landed.0, 5, "the write in flight landed before the stop");

        // Each write attempted after the stop is refused, not lost silently.
        session.record_usage_call(&request, &response, 1);
        assert!(session.record_usage(&request, &response).is_err());
        assert!(session.reserve_budget(&request).is_err());
        assert_eq!(
            rows(),
            landed,
            "nothing landed after the stop returned true"
        );
    }

    /// Owed jobs the worker never got to try (still queued) have their amount
    /// recorded in the held row on the way out.
    #[test]
    fn a_stop_records_what_an_owed_job_is_known_to_have_used() {
        let (dir, job) = refusing_store();
        let (work, queue) = mpsc::channel();
        work.send(Work::Settle(Box::new(job))).unwrap();
        let budget = budget();
        kernel_core::lock_recover(&budget.gate).stop = Some(Instant::now());
        record_owed(&queue, Vec::new(), budget);
        assert_eq!(count(&dir, HELD_IN), 90, "raised from the 60 reserved");
        assert_eq!(count(&dir, HELD), 1, "and still held");
    }

    #[test]
    fn stop_wakes_an_idle_worker_and_a_second_stop_returns_at_once() {
        let budget = budget();
        budget.settler();
        let asked = Instant::now();
        assert!(budget.stop(Duration::from_secs(2)));
        assert!(asked.elapsed() < Duration::from_secs(2));
        assert!(budget.stop(Duration::from_secs(2)));
    }

    #[test]
    fn a_watched_store_settles_an_abandoned_held_row_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
        watch_held_reservations(&store);
        // A row a stopped process left: held, with no guard, past its TTL.
        assert!(matches!(reserve(&store, 60), ReserveOutcome::Reserved(_)));
        aux_store::open_keyed(&path)
            .unwrap()
            .execute_batch(EXPIRE)
            .unwrap();
        let totals = settled(&store);
        assert_eq!((totals.tokens_in, totals.tokens_out), (60, 9));
    }

    /// The race a minute reconcile can win: a live job still in the channel
    /// while the reconcile claims its expired row. A worker of its own, its
    /// queue filled before it starts, fixes that order without a sleep.
    #[test]
    fn a_job_still_queued_when_the_reconcile_claims_its_row_records_its_actual_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
        let ReserveOutcome::Reserved(reservation) = reserve(&store, 60) else {
            panic!("admitted");
        };
        let raw = aux_store::open_keyed(&path).unwrap();
        raw.execute_batch(EXPIRE).unwrap();
        let actual = UsageActual {
            tokens_in: 90,
            tokens_out: 20,
            ..UsageActual::default()
        };
        let job = || {
            let store = Arc::clone(&store);
            let reservation = reservation.clone();
            Work::Settle(Box::new(SettleJob {
                store,
                reservation,
                actual,
            }))
        };
        let (work, queue) = mpsc::channel();
        // The reconcile runs on the first message, the job and its retry wait.
        work.send(Work::Watch(Arc::downgrade(&store))).unwrap();
        work.send(job()).unwrap();
        work.send(job()).unwrap();
        drop(work);
        std::thread::spawn(move || settle_jobs(&queue, budget()))
            .join()
            .unwrap();
        let claim = "SELECT tokens_in, tokens_out, consumed_at IS NOT NULL
            FROM usage_reconciled WHERE reservation_id = ?1";
        let claimed: (i64, i64, bool) = raw
            .query_row(claim, [reservation.id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(
            claimed,
            (60, 9, true),
            "the reconcile claimed it at the reserve, the job topped and consumed it"
        );
        let totals = settled(&store);
        assert_eq!(
            (totals.tokens_in, totals.tokens_out),
            (90, 20),
            "the actual, once"
        );
    }

    #[test]
    fn a_drop_takes_no_lock_and_outlives_a_callback_that_panics_while_unwinding() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let ReserveOutcome::Reserved(reservation) = reserve(&store, 60) else {
            panic!("admitted");
        };
        let held =
            HeldReservation::new(Arc::clone(&store), reservation).or_known(|| panic!("boom"));
        // Dropped while this thread holds the store's lock and is unwinding: a
        // drop that locked would deadlock, a panic out of it would abort.
        let locked = kernel_core::lock_recover(&store);
        let unwound = catch_unwind(AssertUnwindSafe(move || {
            let _held = held;
            panic!("the turn fails");
        }));
        assert!(unwound.is_err());
        drop(locked);
        let totals = settled(&store);
        assert_eq!((totals.tokens_in, totals.tokens_out), (60, 9));
    }

    #[tokio::test]
    async fn an_upgraded_config_with_an_empty_budgets_table_is_still_capped() {
        // The exact bytes an older install carries must enforce the
        // conservative defaults before any provider call; the empty table is
        // still capped.
        let harness = Harness::new();
        let day = harness.store().local_day().unwrap();
        harness
            .store()
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                kernel_core::budget::DEFAULT_DAILY_TOKENS_IN,
                "tokens",
                &day,
            )
            .unwrap();
        let budgets: Budgets = toml::from_str("[default]\n").unwrap();

        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("never"));
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);
        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(err.to_string().contains("tokens_in"), "{err}");
        assert_eq!(provider.request_count(), 0, "no provider call may happen");
    }

    fn wide_token_caps(usd_cents: u64) -> Budgets {
        let mut budgets = Budgets::default();
        budgets.default.tokens_in = Some(10_000_000);
        budgets.default.tokens_out = Some(10_000_000);
        budgets.default.usd_cents = Some(usd_cents);
        budgets
    }

    fn reported(prompt: u64, completion: u64, cost_usd: Option<f64>) -> ChatResponse {
        ChatResponse::assistant("done").with_usage(aux_providers::Usage {
            prompt_tokens: prompt,
            completion_tokens: completion,
            cost_usd,
            cached_prompt_tokens: None,
        })
    }

    fn usd_spent(harness: &Harness) -> u64 {
        let day = harness.store().local_day().unwrap();
        harness
            .store()
            .usage_totals("main", &day)
            .unwrap()
            .usd_cents
    }

    #[tokio::test]
    async fn a_zero_reported_cost_still_charges_from_the_price_table() {
        let mut harness = Harness::new();
        harness.prices.models.insert(
            "priced-model".to_string(),
            kernel_core::budget::ModelPrice {
                input_cents_per_million: 100,
                output_cents_per_million: 100,
            },
        );
        let provider = FakeProvider::repeating("fake", reported(399_600, 400, Some(0.0)))
            .with_model("priced-model");
        let budgets = wide_token_caps(1_000);
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        session.send("hello").await.unwrap();

        assert_eq!(
            usd_spent(&harness),
            40,
            "a reported 0 falls back to [prices]"
        );
    }

    #[tokio::test]
    async fn deepseek_chat_settles_its_catalog_price() {
        // No [prices] entry: the bundled catalog lists deepseek-chat at
        // 0.27 / 1.10 USD per million tokens.
        let harness = Harness::new();
        assert!(harness.prices.price("deepseek-chat").is_none());
        let provider = FakeProvider::repeating("fake", reported(1_000_000, 1_000_000, None))
            .with_model("deepseek-chat");
        let budgets = wide_token_caps(10_000);
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        session.send("hello").await.unwrap();

        assert_eq!(usd_spent(&harness), 27 + 110);
    }

    #[tokio::test]
    async fn minimax_flash_settles_its_catalog_price() {
        // No [prices] entry: the bundled catalog lists minimax-m3.1-flash at
        // 0.15 / 0.60 USD per million tokens.
        let harness = Harness::new();
        assert!(harness.prices.price("minimax-m3.1-flash").is_none());
        let provider = FakeProvider::repeating("fake", reported(1_000_000, 1_000_000, None))
            .with_model("minimax-m3.1-flash");
        let budgets = wide_token_caps(10_000);
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        session.send("hello").await.unwrap();

        assert_eq!(usd_spent(&harness), 15 + 60);
    }

    #[tokio::test]
    async fn an_unpriced_model_under_a_money_only_cap_is_refused() {
        let harness = Harness::new();
        let budgets: Budgets = toml::from_str("[default]\nusd_cents = 100\n").unwrap();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("never"))
            .with_model("unpriced-model");
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(err.to_string().contains("unpriced-model"), "{err}");
        assert_eq!(provider.request_count(), 0, "no provider call may happen");
        assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
    }

    #[tokio::test]
    async fn an_unpriced_model_is_refused_even_when_token_caps_also_bind() {
        let harness = Harness::new();
        let provider = FakeProvider::repeating("fake", ChatResponse::assistant("never"))
            .with_model("unpriced-model");
        let budgets = wide_token_caps(100);
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        let err = session.send("hello").await.unwrap_err();

        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(
            err.to_string()
                .contains("[prices.models.\"unpriced-model\"]"),
            "{err}"
        );
        assert_eq!(provider.request_count(), 0, "no provider call may happen");
        assert_eq!(
            harness.store().reservation_count().unwrap(),
            0,
            "nothing reserved"
        );
        assert_eq!(usd_spent(&harness), 0);
    }

    #[test]
    fn every_bundled_catalog_model_is_priced_or_billed_by_subscription() {
        // A new catalog row without either would be refused under the money cap.
        for row in aux_providers::Catalog::bundled().rows() {
            assert!(
                catalog_prices().price(&row.id).is_some() || catalog_subscription(&row.id),
                "{}/{} has no price and no billing = \"subscription\"",
                row.provider,
                row.id
            );
        }
    }

    #[test]
    fn the_catalog_price_wins_over_a_stale_built_in_but_not_over_the_owner() {
        let flash = |prices: &PriceTable| model_price(prices, Some("deepseek-flash")).unwrap();
        let shipped = flash(&PriceTable::default());
        assert!(shipped.input_cents_per_million >= 30, "{shipped:?}");
        assert!(shipped.output_cents_per_million >= 120, "{shipped:?}");
        let mut owner = PriceTable::default();
        let set = kernel_core::budget::ModelPrice {
            input_cents_per_million: 10,
            output_cents_per_million: 10,
        };
        owner.models.insert("deepseek-flash".to_string(), set);
        assert_eq!(flash(&owner), set, "an explicit [prices] entry wins");
    }

    #[tokio::test]
    async fn deepseek_flash_runs_under_the_default_money_cap() {
        // The owner's brain with the default caps, with the shipped [prices]
        // and with an owner table that left it out: the catalog price binds.
        for prices in [
            PriceTable::default(),
            PriceTable {
                models: Default::default(),
            },
        ] {
            let mut harness = Harness::new();
            harness.prices = prices;
            let provider = FakeProvider::repeating("fake", reported(1_000_000, 1_000_000, None))
                .with_model("deepseek-flash");
            let mut session = harness.start(&provider, vec![], RecordingApprover::new(false));

            session.send("hello").await.unwrap();

            assert_eq!(provider.request_count(), 1);
            assert_eq!(usd_spent(&harness), 30 + 120);
        }
    }

    /// An OpenAI-compatible brain at `base` sending `model`; never called.
    fn wire(base: &str, model: &str, local: bool) -> aux_providers::OpenAiCompat {
        let config = aux_providers::ProviderConfig {
            disable_thinking: false,
            id: "brain".to_string(),
            base_url: base.to_string(),
            model: model.to_string(),
            key_user: None,
            kind: aux_providers::ProviderKind::OpenAiCompat,
        };
        let provider = aux_providers::OpenAiCompat::with_key(&config, None).unwrap();
        if local {
            provider.local_runtime()
        } else {
            provider
        }
    }

    #[tokio::test]
    async fn an_unpriced_call_is_refused_on_a_paid_endpoint_and_on_loopback() {
        // A paid endpoint sending a subscription model id, and a loopback
        // forwarder serving an unpriced model: both refused before any call.
        for provider in [
            wire("https://paid.example/v1", "gpt-oss:120b-cloud", false),
            wire("http://127.0.0.1:9/v1", "llama3.2", true),
        ] {
            let harness = Harness::new();
            let budgets: Budgets = toml::from_str("[default]\nusd_cents = 100\n").unwrap();
            let mut session =
                harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

            let err = session.send("hello").await.unwrap_err();

            assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
            assert!(err.to_string().contains("[prices.models."), "{err}");
            assert_eq!(harness.store().reservation_count().unwrap(), 0);
            assert_eq!(harness.store().event_count("budget.denied").unwrap(), 1);
        }
    }

    #[test]
    fn a_subscription_model_passes_only_on_the_subscription_backend() {
        let caps = kernel_core::budget::BudgetCaps::conservative_default();
        let prices = PriceTable::default();
        let check = |provider: &dyn ChatProvider| {
            unpriced_under_money_cap(&caps, &prices, provider, provider.model())
        };
        assert_eq!(
            check(&wire("https://ollama.com/v1", "gpt-oss:120b-cloud", false)),
            None
        );
        assert!(check(&wire("https://ollama.com/v1", "not-in-catalog", false)).is_some());
        assert!(check(&wire(
            "https://paid.example/v1",
            "gpt-oss:120b-cloud",
            false
        ))
        .is_some());
    }

    #[tokio::test]
    async fn the_daily_usd_cap_binds_from_the_price_table() {
        // Token counts priced by `[prices]` become recorded usd_cents, so the
        // money cap can latch the day and warn at 80 %.
        let mut harness = Harness::new();
        let mut prices = PriceTable::default();
        prices.models.insert(
            "priced-model".to_string(),
            kernel_core::budget::ModelPrice {
                input_cents_per_million: 100,
                output_cents_per_million: 100,
            },
        );
        harness.prices = prices;
        let mut budgets = Budgets::default();
        budgets.default.tokens_in = Some(10_000_000);
        budgets.default.tokens_out = Some(10_000_000);
        budgets.default.usd_cents = Some(50);

        let response = ChatResponse::assistant("done").with_usage(aux_providers::Usage {
            prompt_tokens: 399_600,
            completion_tokens: 400,
            cost_usd: None,
            cached_prompt_tokens: None,
        });
        let provider = FakeProvider::repeating("fake", response).with_model("priced-model");
        let mut session =
            harness.start_with(&provider, vec![], RecordingApprover::new(false), &budgets);

        session.send("hello").await.unwrap();

        let day = harness.store().local_day().unwrap();
        assert_eq!(
            harness
                .store()
                .usage_totals("main", &day)
                .unwrap()
                .usd_cents,
            40,
            "400k tokens at 100 cents/M = 40 cents"
        );
        assert_eq!(
            harness.store().event_count("budget.warning").unwrap(),
            1,
            "landing exactly on 80 % of the money cap warns"
        );

        // A second call crosses the cap: the settle latches the day.
        session.send("again").await.unwrap();
        assert_eq!(
            harness
                .store()
                .usage_totals("main", &day)
                .unwrap()
                .usd_cents,
            80
        );

        // The latched day denies the next call pre-flight.
        let err = session.send("once more").await.unwrap_err();
        assert!(matches!(err, ChatError::BudgetDenied { .. }), "got {err:?}");
        assert!(
            err.to_string().contains("usd_cents"),
            "the latch names the money cap: {err}"
        );
        assert_eq!(provider.request_count(), 2, "the third call is blocked");
    }
}
