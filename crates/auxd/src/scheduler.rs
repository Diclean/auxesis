//! The job scheduler.
//!
//! Every tick, the scheduler claims the jobs that are due, runs each one
//! through a [`JobRunner`], records the outcome in the `runs` table and
//! moves `next_run_at` to the next occurrence of the job's schedule.
//!
//! Claims are leases: a due job's `next_run_at` is moved to `now + lease`
//! before it runs, so a crash mid-run cannot lose the job (it becomes due
//! again when the lease expires) and cannot double-run it either. While a
//! run is executing, a [`LeaseRenewer`] keeps pushing `next_run_at` forward
//! every `lease / 3`, so a run longer than the lease is never re-claimable.
//! Missed occurrences collapse: the next occurrence is always computed from
//! *now*, never by replaying the missed ones.
//!
//! Each claimed job executes on its **own store connection** (see
//! [`FileStoreOpener`]), never while the shared store mutex is held: scheduler
//! ticks, STOP checks and daemon shutdown stay responsive even when a turn
//! blocks for minutes.
//!
//! While the `STOP` kill-switch marker exists (see [`StopSwitch`]), ticks
//! return before claiming anything; the loop logs the pause once and resumes
//! normally when the marker is removed.
//!
//! The current time is passed in as a [`NowFn`], so tests are deterministic.

use crate::api::jobs::RoutineSchedule;
use aux_store::{Job, Store, StoreError, RUN_FAILED, RUN_OK};
use chrono::{DateTime, Duration, Utc};
use kernel_core::killswitch;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};

/// How often the daemon checks for due jobs.
pub const TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a claimed job stays reserved before it becomes due again.
/// Must exceed the longest expected run; on crash, the job waits out the
/// lease and is then retried.
pub const CLAIM_LEASE: std::time::Duration = std::time::Duration::from_secs(600);

/// Kill-switch gate for the scheduler.
///
/// Wraps the Auxesis home and answers through [`kernel_core::killswitch`], so
/// the daemon and `aux stop`/`aux resume` agree on the exact same marker.
#[derive(Debug, Clone)]
pub struct StopSwitch {
    home: PathBuf,
}

impl StopSwitch {
    /// A switch reading `<home>/STOP`.
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    /// The home whose per-agent markers live beside the global switch.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// True while the `STOP` marker exists.
    pub fn is_engaged(&self) -> bool {
        killswitch::is_stopped(&self.home)
    }
}

/// Longest run summary stored (bytes); protects the store from a runaway
/// runner or a giant error message.
const MAX_SUMMARY_BYTES: usize = 4_096;

/// Reads the current UTC instant. Production passes `Utc::now`; tests pass a
/// closure over a fixed or movable instant.
pub type NowFn = dyn Fn() -> DateTime<Utc> + Send + Sync;

/// Where a [`FileStoreOpener`] opens its connections.
#[derive(Debug, Clone)]
enum StoreLocation {
    /// The process's verified home; every open re-checks it.
    Verified(kernel_core::SandboxHome),
    /// A direct path, for unit tests that build a temporary database.
    #[cfg(test)]
    Path(PathBuf),
}

/// Opens independent connections to the daemon's store.
///
/// Jobs run on their own connection so a blocking turn never holds the
/// shared store mutex. Production holds the **verified home handle** and every
/// re-open goes through [`Store::open_verified`] (re-verify + fd-real path +
/// post-open inode check); unit tests can point it at a temporary database.
#[derive(Debug, Clone)]
pub struct FileStoreOpener {
    location: StoreLocation,
}

impl FileStoreOpener {
    /// Open connections to the store at `path` (tests only).
    #[cfg(test)]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            location: StoreLocation::Path(path.into()),
        }
    }

    /// Open connections through the process's verified home (production).
    pub fn from_verified(home: kernel_core::SandboxHome) -> Self {
        Self {
            location: StoreLocation::Verified(home),
        }
    }

    /// Open a fresh connection (same database, same busy timeout).
    pub fn open(&self) -> Result<Store, StoreError> {
        match &self.location {
            StoreLocation::Verified(home) => Store::open_verified(home),
            #[cfg(test)]
            StoreLocation::Path(path) => Store::open(path),
        }
    }
}

/// Executes one job. `Ok(summary)` marks the run `ok`; `Err(message)` marks
/// it `failed`. Either way the job is rescheduled at its next occurrence.
///
/// The runner is synchronous on purpose: it may block (engine runs use a
/// current-thread runtime), so the scheduler executes it on a blocking
/// thread. The scheduler's store is handed to the runner so scheduled work
/// persists into the same database (`sessions`, `messages`, `usage`, audit).
/// Panics are caught and recorded as a failed run, so one bad job never
/// takes the scheduler down.
pub trait JobRunner: Send + Sync + 'static {
    /// Run `job` against `store` and return a short summary or an error
    /// message. The store is the job's own connection, shared so a runner can
    /// hand it to a chat turn's audit trail. The scheduler holds no lock while
    /// the runner runs: a runner locks only around its own store calls.
    fn run(&self, store: &Arc<Mutex<Store>>, job: &Job) -> Result<String, String>;

    /// Optionally provide a one-off next occurrence for deferred jobs.
    fn reschedule_at(&self, _job: &Job, _now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        None
    }
}

impl<T: JobRunner + ?Sized> JobRunner for Arc<T> {
    fn run(&self, store: &Arc<Mutex<Store>>, job: &Job) -> Result<String, String> {
        (**self).run(store, job)
    }

    fn reschedule_at(&self, job: &Job, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        (**self).reschedule_at(job, now)
    }
}

/// What one scheduler tick did.
///
/// Used by the synchronous, test-facing [`tick`]; the production loop claims
/// and dispatches per job instead.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Number of jobs claimed this tick.
    pub claimed: usize,
    /// Claimed jobs whose runner succeeded.
    pub succeeded: usize,
    /// Claimed jobs whose runner failed, panicked or had a bad schedule.
    pub failed: usize,
    /// True when the tick did nothing because the kill switch is engaged.
    pub stopped: bool,
}

/// Run one scheduler tick: check the kill switch, then claim the due jobs,
/// execute them, record their runs and reschedule them.
///
/// While the `STOP` marker is engaged the tick returns immediately: nothing
/// is claimed, leased, executed or rescheduled, so releasing the switch
/// resumes with exactly the jobs that were due.
///
/// Only store failures reach the caller (as [`StoreError`]); one job's
/// failure is recorded in its run and counted in [`TickReport`].
///
/// The production loop uses [`run_claimed_job`] per job instead, so a long
/// run never blocks the next tick.
#[cfg(test)]
pub fn tick(
    store: &Arc<Mutex<Store>>,
    now: &dyn Fn() -> DateTime<Utc>,
    runner: &dyn JobRunner,
    lease: std::time::Duration,
    stop: &StopSwitch,
) -> Result<TickReport, StoreError> {
    if stop.is_engaged() {
        return Ok(TickReport {
            stopped: true,
            ..TickReport::default()
        });
    }

    let now_utc = now();
    let lease_until = now_utc + lease_delta(lease);
    let claimed =
        locked(store).claim_due_jobs(&format_timestamp(now_utc), &format_timestamp(lease_until))?;

    let mut report = TickReport {
        claimed: claimed.len(),
        ..TickReport::default()
    };
    for job in claimed {
        // A paused/killed agent's job is claimed but not run: the claim
        // already moved `next_run_at` forward, so it stays scheduled and
        // runs when the agent resumes.
        if crate::agent::state(stop.home(), &job.agent).blocks_work() {
            continue;
        }
        match execute(store, now, runner, &job, None) {
            Ok(true) => report.succeeded += 1,
            Ok(false) => report.failed += 1,
            Err(error) => {
                tracing::error!(job_id = job.id, error = %error, "scheduler: recording a run failed");
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

/// Run one claimed job on its own store connection, renewing its lease while
/// it executes.
///
/// This is what the production [`run_loop`] calls per claimed job: the job
/// no longer shares the scheduler's store connection (or its mutex), so a
/// long or blocked runner cannot stall ticks, STOP evaluation or shutdown.
pub fn run_claimed_job(
    opener: &FileStoreOpener,
    now: Arc<NowFn>,
    runner: &dyn JobRunner,
    lease: std::time::Duration,
    job: &Job,
) -> Result<bool, StoreError> {
    run_claimed_job_with_interval(opener, now, runner, lease, renewal_interval(lease), job)
}

/// [`run_claimed_job`] with an explicit renewal cadence (tests use a short
/// one; production derives `lease / 3`).
fn run_claimed_job_with_interval(
    opener: &FileStoreOpener,
    now: Arc<NowFn>,
    runner: &dyn JobRunner,
    lease: std::time::Duration,
    renewal_every: std::time::Duration,
    job: &Job,
) -> Result<bool, StoreError> {
    let store = Arc::new(Mutex::new(opener.open()?));
    let renewer = match LeaseRenewer::start(opener, job.id, lease, renewal_every, Arc::clone(&now))
    {
        Ok(renewer) => Some(renewer),
        Err(error) => {
            // Without a renewer a run longer than the lease could be claimed
            // again; log it and run anyway rather than dropping the job.
            tracing::warn!(job_id = job.id, error = %error, "scheduler: lease renewal unavailable");
            None
        }
    };
    execute(&store, now.as_ref(), runner, job, renewer)
}

/// Run the tick loop until the task is aborted. The first tick fires
/// immediately, so jobs that came due while the daemon was down are caught
/// up at startup.
///
/// Claiming takes the shared store mutex only for the claim itself; each
/// claimed job is then handed to a blocking task that opens its **own**
/// connection. Long jobs therefore never block later ticks, STOP checks or
/// the daemon's shutdown path.
///
/// The kill switch is checked every tick. While it is engaged the loop logs
/// the pause exactly once (no per-tick spam) and resumes with the normal log
/// flow when the marker disappears.
pub async fn run_loop<R>(
    store: Arc<Mutex<Store>>,
    opener: Arc<FileStoreOpener>,
    now: Arc<NowFn>,
    runner: R,
    tick_every: std::time::Duration,
    lease: std::time::Duration,
    stop: StopSwitch,
) -> !
where
    R: JobRunner,
{
    // The time source and the runner are shared with the blocking tasks that
    // execute each job: engine turns block, so they must never run on an
    // async worker.
    let runner: Arc<dyn JobRunner> = Arc::new(runner);
    let mut ticker = tokio::time::interval(tick_every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut paused_logged = false;
    loop {
        ticker.tick().await;
        if stop.is_engaged() {
            if !paused_logged {
                tracing::info!("kill switch engaged: scheduler paused, no job will be claimed");
                paused_logged = true;
            }
            continue;
        }
        if paused_logged {
            tracing::info!("kill switch released: scheduler resumed");
            paused_logged = false;
        }

        // Claim with the shared connection, then release the mutex; the
        // claim is a single short transaction and never runs a job.
        let now_utc = now();
        let now_str = format_timestamp(now_utc);
        let lease_until = format_timestamp(now_utc + lease_delta(lease));
        let claim_store = Arc::clone(&store);
        let claimed = match tokio::task::spawn_blocking(move || {
            let mut store = kernel_core::lock_recover(&claim_store);
            store.claim_due_jobs(&now_str, &lease_until)
        })
        .await
        {
            Ok(Ok(claimed)) => claimed,
            Ok(Err(error)) => {
                tracing::error!(error = %error, "scheduler tick failed");
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "scheduler tick task failed");
                continue;
            }
        };
        if claimed.is_empty() {
            continue;
        }
        tracing::info!(claimed = claimed.len(), "scheduler tick");
        for job in claimed {
            // A paused/killed agent's job is not executed. The
            // claim lease already pushed `next_run_at`, so it stays
            // scheduled and runs after a resume — no failed-run noise.
            if crate::agent::state(stop.home(), &job.agent).blocks_work() {
                continue;
            }
            let opener = Arc::clone(&opener);
            let now = Arc::clone(&now);
            let runner = Arc::clone(&runner);
            // Fire and forget: awaiting the job here would pause ticks for
            // its whole duration. Each task owns its connection and renews
            // its own lease.
            tokio::task::spawn_blocking(move || {
                match run_claimed_job(opener.as_ref(), now, runner.as_ref(), lease, &job) {
                    Ok(succeeded) => {
                        tracing::debug!(job_id = job.id, succeeded, "scheduler: run finished")
                    }
                    Err(error) => {
                        tracing::error!(job_id = job.id, error = %error, "scheduler: run failed")
                    }
                }
            });
        }
    }
}

/// Renews a running job's claim lease every `lease / 3` until dropped.
///
/// The renewer owns its own store connection and thread: it must stay
/// independent of the connection the runner is blocking on.
struct LeaseRenewer {
    stop: mpsc::Sender<()>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl LeaseRenewer {
    /// Open a connection and start renewing `job_id`'s lease every
    /// `interval`.
    fn start(
        opener: &FileStoreOpener,
        job_id: i64,
        lease: std::time::Duration,
        interval: std::time::Duration,
        now: Arc<NowFn>,
    ) -> Result<Self, StoreError> {
        let store = opener.open()?;
        let (stop, wait) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || loop {
            match wait.recv_timeout(interval) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let lease_until = format_timestamp(now() + lease_delta(lease));
                    match store.renew_lease(job_id, &lease_until) {
                        Ok(true) => tracing::debug!(
                            job_id,
                            lease_until = %lease_until,
                            "scheduler: lease renewed"
                        ),
                        // The job was deleted: nothing left to keep claimed.
                        Ok(false) => break,
                        Err(error) => {
                            tracing::warn!(job_id, error = %error, "scheduler: lease renewal failed")
                        }
                    }
                }
            }
        });
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }

    /// Stop renewing and wait for the renewal thread to exit.
    fn shutdown(&mut self) {
        let _ = self.stop.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LeaseRenewer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Renew well before the lease can expire: three chances per lease window.
fn renewal_interval(lease: std::time::Duration) -> std::time::Duration {
    (lease / 3).max(std::time::Duration::from_millis(50))
}

/// A `YYYY-MM-DD HH:MM:SS` UTC timestamp, the format used by the store.
pub fn format_timestamp(instant: DateTime<Utc>) -> String {
    instant.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Mark runs left `running` by a previous process as interrupted. Call once
/// at daemon startup, before the first tick.
pub fn recover_interrupted_runs(
    store: &Store,
    now: &dyn Fn() -> DateTime<Utc>,
) -> Result<usize, StoreError> {
    store.interrupt_running_runs(&format_timestamp(now()))
}

/// Execute one claimed job. Returns `Ok(true)` on success, `Ok(false)` on a
/// recorded failure; only store errors propagate.
/// The job's connection, locked for one store call. A poisoned lock is
/// recovered: the connection itself is still usable.
fn locked(store: &Arc<Mutex<Store>>) -> std::sync::MutexGuard<'_, Store> {
    kernel_core::sync::lock_recover(store)
}

fn execute(
    store: &Arc<Mutex<Store>>,
    now: &dyn Fn() -> DateTime<Utc>,
    runner: &dyn JobRunner,
    job: &Job,
    renewer: Option<LeaseRenewer>,
) -> Result<bool, StoreError> {
    let started = now();
    let started_at = format_timestamp(started);
    let run = locked(store).start_run(job.id, &started_at)?;

    let schedule = match RoutineSchedule::parse(&job.schedule) {
        Ok(schedule) => schedule,
        Err(error) => {
            // Unparseable schedules can never run: record the failure and
            // disable the job so it does not fail on every tick.
            let finished_at = format_timestamp(now());
            let summary = cap_summary(&format!("invalid schedule: {error}"));
            let store_guard = locked(store);
            store_guard.finish_run(run.id, &finished_at, RUN_FAILED, Some(&summary))?;
            persist_run_receipt(
                &store_guard,
                run.id,
                &job.agent,
                &started_at,
                &finished_at,
                crate::api::receipt::ReceiptStatus::Failed,
            );
            store_guard.set_job_enabled(job.id, false)?;
            drop(store_guard);
            tracing::warn!(job_id = job.id, schedule = %job.schedule, "scheduler: job disabled (invalid schedule)");
            return Ok(false);
        }
    };

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runner.run(store, job)))
        .unwrap_or_else(|_| Err("runner panicked".to_string()));
    let (status, summary, succeeded) = match outcome {
        Ok(summary) => (RUN_OK, summary, true),
        Err(message) => (RUN_FAILED, message, false),
    };

    let finished_at = format_timestamp(now());
    let store_guard = locked(store);
    store_guard.finish_run(run.id, &finished_at, status, Some(&cap_summary(&summary)))?;
    let receipt_status = if status == RUN_OK {
        crate::api::receipt::ReceiptStatus::Done
    } else if summary.to_ascii_lowercase().contains("budget")
        || summary.to_ascii_lowercase().contains("capped")
    {
        crate::api::receipt::ReceiptStatus::StoppedBudget
    } else {
        crate::api::receipt::ReceiptStatus::Failed
    };
    persist_run_receipt(
        &store_guard,
        run.id,
        &job.agent,
        &started_at,
        &finished_at,
        receipt_status,
    );
    drop(store_guard);

    // The lease renewer must stop before the real next occurrence is
    // written, or a late renewal could overwrite it with a lease deadline.
    drop(renewer);

    // Next occurrence from *now*: missed occurrences collapse into this
    // single catch-up run. A deleted job simply fails to reschedule.
    let finished = now();
    let next = runner
        .reschedule_at(job, finished)
        .unwrap_or_else(|| schedule.next_after_run(started, finished));
    locked(store).reschedule_job(job.id, Some(&started_at), Some(&format_timestamp(next)))?;
    Ok(succeeded)
}

fn persist_run_receipt(
    store: &Store,
    run_id: i64,
    agent: &str,
    started: &str,
    finished: &str,
    status: crate::api::receipt::ReceiptStatus,
) {
    use crate::api::receipt::{build_receipt, ReceiptEvent};
    let receipt_run_id = format!("job-{run_id}");
    let receipt = build_receipt(&[
        ReceiptEvent::Run {
            run_id: receipt_run_id.clone(),
            agent: agent.to_string(),
            started: Some(started.to_string()),
            finished: Some(finished.to_string()),
        },
        ReceiptEvent::Status(status),
        ReceiptEvent::Trigger("schedule".into()),
        ReceiptEvent::CouldNotVerify(
            "per-run usage, tool outcomes, files, and external destinations are not fully recorded"
                .into(),
        ),
    ]);
    if let Ok(payload) = serde_json::to_string(&receipt) {
        match store.log_run_finished_once(&receipt_run_id, &payload) {
            Ok(_) => crate::api::receipt::prune_receipts(store),
            Err(err) => tracing::warn!(run_id, error = %err, "could not persist run receipt"),
        }
    }
}

fn lease_delta(lease: std::time::Duration) -> Duration {
    let milliseconds = i64::try_from(lease.as_millis()).unwrap_or(i64::MAX);
    Duration::milliseconds(milliseconds)
}

fn cap_summary(summary: &str) -> String {
    if summary.len() <= MAX_SUMMARY_BYTES {
        return summary.to_string();
    }
    let mut end = MAX_SUMMARY_BYTES;
    while !summary.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated]", &summary[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_store::RUN_INTERRUPTED;
    use chrono::{Local, NaiveTime, TimeZone};
    use tempfile::tempdir;

    /// The instant the tests control; read it through `now_utc`.
    struct FakeClock(Mutex<DateTime<Utc>>);

    impl FakeClock {
        fn new(now: DateTime<Utc>) -> Self {
            Self(Mutex::new(now))
        }

        fn set(&self, now: DateTime<Utc>) {
            *self.0.lock().unwrap() = now;
        }

        fn now_utc(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }

        /// A time source that follows this clock, for the shared-time APIs.
        fn reader(self: &Arc<Self>) -> Arc<NowFn> {
            let clock = Arc::clone(self);
            Arc::new(move || clock.now_utc())
        }
    }

    /// Runner that always succeeds and records its calls.
    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<String>>,
        summary: String,
    }

    impl RecordingRunner {
        fn with_summary(summary: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                summary: summary.to_string(),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl JobRunner for RecordingRunner {
        fn run(&self, _store: &Arc<Mutex<Store>>, job: &Job) -> Result<String, String> {
            self.calls.lock().unwrap().push(job.name.clone());
            Ok(self.summary.clone())
        }
    }

    /// Runner that always fails.
    struct FailingRunner;

    impl JobRunner for FailingRunner {
        fn run(&self, _store: &Arc<Mutex<Store>>, _job: &Job) -> Result<String, String> {
            Err("boom".to_string())
        }
    }

    /// Runner that panics.
    struct PanickingRunner;

    impl JobRunner for PanickingRunner {
        fn run(&self, _store: &Arc<Mutex<Store>>, _job: &Job) -> Result<String, String> {
            panic!("runner exploded");
        }
    }

    fn utc(y: i32, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, hh, mm, ss).unwrap()
    }

    /// Local wall-clock instant, converted to UTC for the clock.
    fn local(y: i32, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> DateTime<Utc> {
        Local
            .with_ymd_and_hms(y, m, d, hh, mm, ss)
            .single()
            .expect("test instant must exist in the local timezone")
            .to_utc()
    }

    const LEASE: std::time::Duration = std::time::Duration::from_secs(600);

    /// Switch for tests that do not exercise the kill switch. Its home is a
    /// path no test ever creates, so the `STOP` marker is never present.
    fn switch_off() -> StopSwitch {
        StopSwitch::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("never-created-by-tests"))
    }

    #[test]
    fn tick_without_due_jobs_is_a_noop() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "future",
                "every 15m",
                "{}",
                Some("2026-10-03 09:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::default();

        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report, TickReport::default());
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn tick_runs_a_due_job_and_schedules_the_next_occurrence() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "axis",
                "heartbeat",
                "every 15m",
                r#"{"k":"v"}"#,
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::with_summary("beep");

        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(
            report,
            TickReport {
                claimed: 1,
                succeeded: 1,
                failed: 0,
                stopped: false,
            }
        );
        assert_eq!(runner.calls(), vec!["heartbeat".to_string()]);

        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, RUN_OK);
        assert_eq!(runs[0].started_at, "2026-10-03 08:00:00");
        assert_eq!(runs[0].finished_at.as_deref(), Some("2026-10-03 08:00:00"));
        assert_eq!(runs[0].summary.as_deref(), Some("beep"));

        let stored = store.lock().unwrap().job_by_id(job.id).unwrap().unwrap();
        assert_eq!(stored.last_run_at.as_deref(), Some("2026-10-03 08:00:00"));
        assert_eq!(stored.next_run_at.as_deref(), Some("2026-10-03 08:15:00"));
    }

    #[test]
    fn persist_run_receipt_is_idempotent_per_job_run() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("store.sqlite");
        let store = Arc::new(Mutex::new(Store::open(&db_path).unwrap()));

        // A retry (the write took effect but its ack was lost) must not
        // append a second row for the same job run.
        for _ in 0..2 {
            persist_run_receipt(
                &store.lock().unwrap(),
                7,
                "main",
                "2026-10-03 08:00:00",
                "2026-10-03 08:00:01",
                crate::api::receipt::ReceiptStatus::Done,
            );
        }
        persist_run_receipt(
            &store.lock().unwrap(),
            8,
            "main",
            "2026-10-03 08:01:00",
            "2026-10-03 08:01:01",
            crate::api::receipt::ReceiptStatus::Done,
        );

        assert_eq!(
            store.lock().unwrap().event_count("run.finished").unwrap(),
            2,
            "the retry must be a no-op and a different run must still write"
        );
        let receipts = crate::api::receipt::read_receipts(&db_path, None, 10).unwrap();
        let ids: Vec<&str> = receipts.iter().map(|r| r.run_id.as_str()).collect();
        assert_eq!(
            ids.iter().filter(|id| **id == "job-7").count(),
            1,
            "the scheduler receipt must be keyed by `job-{{run_id}}`"
        );
        assert!(ids.contains(&"job-8"));
    }

    #[test]
    fn a_job_is_not_run_again_before_its_next_occurrence() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "tick",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::default();

        tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 1);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:15:00")
        );

        // 5 minutes later: still leased / not due.
        clock.set(utc(2026, 10, 3, 8, 5, 0));
        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.claimed, 0);
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 1);

        // 15 minutes later: due again.
        clock.set(utc(2026, 10, 3, 8, 15, 0));
        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.claimed, 1);
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 2);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:30:00")
        );
    }

    #[test]
    fn missed_interval_runs_collapse_into_one_catch_up() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "sleepy",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        // The daemon was down for a full hour: four occurrences were missed.
        let clock = FakeClock::new(utc(2026, 10, 3, 9, 0, 0));
        let runner = RecordingRunner::default();

        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.claimed, 1);
        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs.len(), 1, "missed occurrences must not replay");
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 09:15:00"),
            "next occurrence is computed from now"
        );
    }

    #[test]
    fn missed_daily_runs_collapse_into_one_catch_up() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "digest",
                "daily 08:30",
                "{}",
                Some("2026-10-01 06:30:00"),
            )
            .unwrap();
        // It is 10:00 local: today's 08:30 was missed, plus two full days.
        let clock = FakeClock::new(local(2026, 10, 3, 10, 0, 0));
        let runner = RecordingRunner::default();

        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.claimed, 1);
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 1);

        // Next run: tomorrow 08:30 local.
        let next = store
            .lock()
            .unwrap()
            .job_by_id(job.id)
            .unwrap()
            .unwrap()
            .next_run_at
            .unwrap();
        let next_local = DateTime::parse_from_str(&format!("{next} +0000"), "%Y-%m-%d %H:%M:%S %z")
            .unwrap()
            .with_timezone(&Local);
        assert_eq!(
            next_local.time(),
            NaiveTime::from_hms_opt(8, 30, 0).unwrap()
        );
        assert_eq!(next_local.date_naive().to_string(), "2026-10-04");
    }

    #[test]
    fn daily_job_runs_at_its_local_wall_clock_time() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let now = local(2026, 10, 3, 8, 0, 0);
        let job = store
            .lock()
            .unwrap()
            .create_job("main", "digest", "daily 08:30", "{}", None)
            .unwrap();
        let clock = FakeClock::new(now);
        let runner = RecordingRunner::default();

        tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();

        let next = store
            .lock()
            .unwrap()
            .job_by_id(job.id)
            .unwrap()
            .unwrap()
            .next_run_at
            .unwrap();
        let next_local = DateTime::parse_from_str(&format!("{next} +0000"), "%Y-%m-%d %H:%M:%S %z")
            .unwrap()
            .with_timezone(&Local);
        assert_eq!(
            next_local.time(),
            NaiveTime::from_hms_opt(8, 30, 0).unwrap()
        );
        assert_eq!(next_local.date_naive().to_string(), "2026-10-03");
    }

    #[test]
    fn a_weekly_routine_runs_and_is_rescheduled_not_disabled() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "digest",
                "weekly mon 09:00",
                "{}",
                Some("2026-10-05 07:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 5, 8, 0, 0));
        let runner = RecordingRunner::default();

        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!((report.claimed, report.failed), (1, 0));

        let stored = store.lock().unwrap().job_by_id(job.id).unwrap().unwrap();
        assert!(
            stored.enabled,
            "a routine schedule is valid for the scheduler"
        );
        let next = stored.next_run_at.unwrap();
        assert!(
            next.as_str() > "2026-10-05 08:00:00" && next.as_str() < "2026-10-13",
            "{next}"
        );
    }

    #[test]
    fn runner_failure_is_recorded_and_the_job_is_rescheduled() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "flaky",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));

        let report = tick(
            &store,
            &|| clock.now_utc(),
            &FailingRunner,
            LEASE,
            &switch_off(),
        )
        .unwrap();
        assert_eq!(report.claimed, 1);
        assert_eq!(report.failed, 1);

        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs[0].status, RUN_FAILED);
        assert_eq!(runs[0].summary.as_deref(), Some("boom"));
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:15:00")
        );
    }

    #[test]
    fn runner_panic_is_contained_and_recorded() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "explosive",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));

        let report = tick(
            &store,
            &|| clock.now_utc(),
            &PanickingRunner,
            LEASE,
            &switch_off(),
        )
        .unwrap();
        assert_eq!(report.failed, 1);

        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs[0].status, RUN_FAILED);
        assert_eq!(runs[0].summary.as_deref(), Some("runner panicked"));
        // The scheduler survived and the job was rescheduled.
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:15:00")
        );
    }

    #[test]
    fn invalid_schedule_disables_the_job_and_records_a_failure() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "broken",
                "every fortnight",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::default();

        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.failed, 1);
        assert!(runner.calls().is_empty(), "an unparseable job must not run");

        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs[0].status, RUN_FAILED);
        assert!(runs[0]
            .summary
            .as_deref()
            .unwrap()
            .contains("invalid schedule"));

        let stored = store.lock().unwrap().job_by_id(job.id).unwrap().unwrap();
        assert!(!stored.enabled, "job must be disabled so it stops failing");

        // Next tick: nothing to claim.
        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.claimed, 0);
    }

    #[test]
    fn claim_lease_retries_a_job_after_a_crash() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "crashy",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        // Simulate a daemon that claimed the job, then died before finishing.
        let claimed = store
            .lock()
            .unwrap()
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();
        assert_eq!(claimed.len(), 1);

        let clock = FakeClock::new(utc(2026, 10, 3, 8, 5, 0));
        let runner = RecordingRunner::default();
        // The lease still holds: no duplicate run.
        assert_eq!(
            tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off())
                .unwrap()
                .claimed,
            0
        );
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 0);

        // Once the lease expires, the job comes back and runs.
        clock.set(utc(2026, 10, 3, 8, 10, 0));
        assert_eq!(
            tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off())
                .unwrap()
                .claimed,
            1
        );
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 1);
    }

    #[test]
    fn a_live_run_is_not_reclaimed_when_the_lease_is_backdated() {
        // The lease is not the last line of defence. A clock jump
        // that back-dates `next_run_at` while run #1 is still `running` must
        // not produce a second run for the same job.
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "slow",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let claimed = store
            .lock()
            .unwrap()
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();
        assert_eq!(claimed.len(), 1);
        store
            .lock()
            .unwrap()
            .start_run(job.id, "2026-10-03 08:00:00")
            .unwrap();

        // Models the back-dated lease from the report.
        store
            .lock()
            .unwrap()
            .renew_lease(job.id, "2026-10-03 07:59:00")
            .unwrap();

        let clock = FakeClock::new(utc(2026, 10, 3, 8, 5, 0));
        let runner = RecordingRunner::default();
        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.claimed, 0);
        assert!(runner.calls().is_empty(), "no second run may start");
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 1);

        // Crash recovery still works: the startup sweep marks the leftover
        // run `interrupted`, and the job is re-claimable afterwards.
        assert_eq!(
            recover_interrupted_runs(&store.lock().unwrap(), &|| clock.now_utc()).unwrap(),
            1
        );
        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();
        assert_eq!(report.claimed, 1);
        assert_eq!(runner.calls(), vec!["slow".to_string()]);
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 2);
    }

    #[test]
    fn jobs_and_run_history_persist_across_restarts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::default();

        let job_id = {
            let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
            let job = store
                .lock()
                .unwrap()
                .create_job(
                    "main",
                    "persisted",
                    "every 15m",
                    "{}",
                    Some("2026-10-03 08:00:00"),
                )
                .unwrap();
            assert_eq!(
                tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off())
                    .unwrap()
                    .claimed,
                1
            );
            job.id
        };

        // Restart at the same instant: the lease persisted, no double run.
        {
            let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
            assert_eq!(
                tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off())
                    .unwrap()
                    .claimed,
                0
            );
            assert_eq!(store.lock().unwrap().runs_for_job(job_id).unwrap().len(), 1);

            // …and the next occurrence still fires after the restart.
            clock.set(utc(2026, 10, 3, 8, 15, 0));
            assert_eq!(
                tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off())
                    .unwrap()
                    .claimed,
                1
            );
            assert_eq!(store.lock().unwrap().runs_for_job(job_id).unwrap().len(), 2);
        }

        let store = Arc::new(Mutex::new(Store::open(&path).unwrap()));
        assert_eq!(store.lock().unwrap().runs_for_job(job_id).unwrap().len(), 2);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job_id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:30:00")
        );
    }

    #[test]
    fn startup_recovery_marks_crashed_runs_interrupted() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job("main", "j", "every 15m", "{}", None)
            .unwrap();
        store
            .lock()
            .unwrap()
            .start_run(job.id, "2026-10-03 08:00:00")
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 30, 0));

        assert_eq!(
            recover_interrupted_runs(&store.lock().unwrap(), &|| clock.now_utc()).unwrap(),
            1
        );

        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs[0].status, RUN_INTERRUPTED);
        assert_eq!(runs[0].finished_at.as_deref(), Some("2026-10-03 08:30:00"));
    }

    #[test]
    fn run_summaries_are_capped() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job("main", "loud", "every 15m", "{}", None)
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::with_summary(&"x".repeat(50_000));

        tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off()).unwrap();

        let summary = store.lock().unwrap().runs_for_job(job.id).unwrap()[0]
            .summary
            .clone()
            .unwrap();
        assert!(
            summary.len() < 5_000,
            "summary must be capped, got {} bytes",
            summary.len()
        );
        assert!(summary.ends_with("[truncated]"));
    }

    #[test]
    fn run_summaries_are_capped_on_char_boundaries() {
        // A multi-byte character straddling the cap must not be split.
        let summary = format!("{}é", "a".repeat(MAX_SUMMARY_BYTES - 1));
        assert!(summary.len() > MAX_SUMMARY_BYTES);

        let capped = cap_summary(&summary);
        assert!(capped.ends_with("[truncated]"));
        // The `é` straddles the cap, so the cut happens one byte earlier.
        assert_eq!(capped.len(), MAX_SUMMARY_BYTES - 1 + "… [truncated]".len());
        assert!(capped.starts_with(&"a".repeat(MAX_SUMMARY_BYTES - 1)));
    }

    #[test]
    fn disabled_jobs_are_not_claimed() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "paused",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .set_job_enabled(job.id, false)
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::default();

        assert_eq!(
            tick(&store, &|| clock.now_utc(), &runner, LEASE, &switch_off())
                .unwrap()
                .claimed,
            0
        );
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn paused_agents_jobs_are_claimed_but_not_run() {
        // A paused agent's due job is leased (so it is not lost)
        // but never executed; no run row, no notification.
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("agents").join("scout")).unwrap();
        crate::agent::set_marker(&home, "scout", crate::agent::PAUSED_MARKER).unwrap();

        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "scout",
                "paused-job",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 0, 0));
        let runner = RecordingRunner::with_summary("must not run");

        let report = tick(
            &store,
            &|| clock.now_utc(),
            &runner,
            LEASE,
            &StopSwitch::new(&home),
        )
        .unwrap();
        assert_eq!(report.claimed, 1);
        assert!(runner.calls().is_empty(), "a paused agent must not run");
        assert_eq!(store.lock().unwrap().runs_for_job(job.id).unwrap().len(), 0);
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:10:00"),
            "the claim lease keeps the job scheduled"
        );

        // Kill behaves the same way.
        crate::agent::set_marker(&home, "scout", crate::agent::KILLED_MARKER).unwrap();
        clock.set(utc(2026, 10, 3, 8, 20, 0));
        let report = tick(
            &store,
            &|| clock.now_utc(),
            &runner,
            LEASE,
            &StopSwitch::new(&home),
        )
        .unwrap();
        assert_eq!(report.claimed, 1);
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn engaged_kill_switch_skips_claims_execution_and_rescheduling() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        kernel_core::killswitch::engage(&home).unwrap();

        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "blocked",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        // Long past due: the job would run if it were claimed.
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 30, 0));
        let runner = RecordingRunner::default();
        let stop = StopSwitch::new(&home);

        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &stop).unwrap();

        assert!(report.stopped, "the tick must report the pause");
        assert_eq!(report.claimed, 0);
        assert!(
            runner.calls().is_empty(),
            "no job may run while STOP is engaged"
        );
        assert_eq!(
            store.lock().unwrap().runs_for_job(job.id).unwrap().len(),
            0,
            "no run may be recorded"
        );
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:00:00"),
            "the job stays due and untouched"
        );
    }

    #[test]
    fn releasing_the_kill_switch_resumes_the_due_jobs() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        kernel_core::killswitch::engage(&home).unwrap();

        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let job = store
            .lock()
            .unwrap()
            .create_job(
                "axis",
                "waiter",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let clock = FakeClock::new(utc(2026, 10, 3, 8, 30, 0));
        let runner = RecordingRunner::with_summary("late but done");
        let stop = StopSwitch::new(&home);

        // Engaged: nothing happens, the job's due time is preserved.
        assert!(
            tick(&store, &|| clock.now_utc(), &runner, LEASE, &stop)
                .unwrap()
                .stopped
        );
        assert!(runner.calls().is_empty());

        assert!(kernel_core::killswitch::release(&home).unwrap());

        // Released: the next tick catches the job up immediately.
        let report = tick(&store, &|| clock.now_utc(), &runner, LEASE, &stop).unwrap();
        assert!(!report.stopped);
        assert_eq!(report.claimed, 1);
        assert_eq!(report.succeeded, 1);
        assert_eq!(runner.calls(), vec!["waiter".to_string()]);

        let runs = store.lock().unwrap().runs_for_job(job.id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, RUN_OK);
        assert_eq!(runs[0].summary.as_deref(), Some("late but done"));
        // Missed occurrences collapse: next occurrence is computed from now.
        assert_eq!(
            store
                .lock()
                .unwrap()
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:45:00")
        );
    }

    /// Shared store + opener over one file-backed database.
    fn file_store(dir: &tempfile::TempDir) -> (Arc<Mutex<Store>>, Arc<FileStoreOpener>) {
        let path = dir.path().join("store.db");
        (
            Arc::new(Mutex::new(Store::open(&path).unwrap())),
            Arc::new(FileStoreOpener::new(path)),
        )
    }

    /// Wait until `job_id` has at least `expected` finished runs.
    ///
    /// Events fire inside the runner, before `finish_run` commits on the
    /// job's own connection, so tests must not assert run rows right after an
    /// event.
    fn wait_for_finished_runs(
        store: &Arc<Mutex<Store>>,
        job_id: i64,
        expected: usize,
        timeout: std::time::Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let finished = store
                .lock()
                .unwrap()
                .runs_for_job(job_id)
                .map(|runs| {
                    runs.len() >= expected
                        && runs.iter().all(|run| run.status != aux_store::RUN_RUNNING)
                })
                .unwrap_or(false);
            if finished {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[tokio::test]
    async fn run_loop_pauses_on_stop_and_resumes_on_release() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        kernel_core::killswitch::engage(&home).unwrap();

        // Every job now runs on its own connection, so the loop needs a
        // real file-backed store.
        let (store, opener) = file_store(&dir);
        let job = store
            .lock()
            .unwrap()
            .create_job("main", "waiter", "every 15m", "{}", None)
            .unwrap();
        let job_id = job.id;
        let clock = Arc::new(FakeClock::new(utc(2026, 10, 3, 8, 0, 0)));
        let runner = Arc::new(RecordingRunner::default());

        let handle = tokio::spawn(run_loop(
            Arc::clone(&store),
            Arc::clone(&opener),
            clock.reader(),
            Arc::clone(&runner),
            std::time::Duration::from_millis(10),
            LEASE,
            StopSwitch::new(&home),
        ));

        // Several ticks elapse while STOP is engaged: nothing may be claimed.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            runner.calls().is_empty(),
            "no job may run while STOP is engaged"
        );
        assert_eq!(store.lock().unwrap().runs_for_job(job_id).unwrap().len(), 0);

        // Release: the loop picks the due job up on an upcoming tick.
        assert!(kernel_core::killswitch::release(&home).unwrap());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while runner.calls().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            wait_for_finished_runs(&store, job_id, 1, std::time::Duration::from_secs(5)),
            "the run must be recorded"
        );
        handle.abort();

        assert_eq!(runner.calls(), vec!["waiter".to_string()]);
        let store = store.lock().unwrap();
        let runs = store.runs_for_job(job_id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, RUN_OK);
    }

    #[tokio::test]
    async fn run_loop_ticks_immediately_and_can_be_aborted() {
        let dir = tempdir().unwrap();
        let (store, opener) = file_store(&dir);
        store
            .lock()
            .unwrap()
            .create_job("main", "boot", "every 15m", "{}", None)
            .unwrap();
        let clock = Arc::new(FakeClock::new(utc(2026, 10, 3, 8, 0, 0)));
        let runner = Arc::new(RecordingRunner::default());

        let handle = tokio::spawn(run_loop(
            Arc::clone(&store),
            Arc::clone(&opener),
            clock.reader(),
            Arc::clone(&runner),
            std::time::Duration::from_millis(10),
            LEASE,
            switch_off(),
        ));

        // The first tick fires immediately: wait (bounded) for the run.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while runner.calls().is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            wait_for_finished_runs(&store, 1, 1, std::time::Duration::from_secs(5)),
            "the run must be recorded"
        );
        handle.abort();

        assert_eq!(runner.calls(), vec!["boot".to_string()]);
        let store = store.lock().unwrap();
        assert_eq!(store.list_jobs().unwrap().len(), 1);
        let runs = store.runs_for_job(1).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, RUN_OK);
    }

    /// Runner that moves a shared fake clock forward when it starts, signals
    /// the test, then sleeps to model a long turn.
    struct ClockAdvancingRunner {
        clock: Arc<FakeClock>,
        advanced_to: DateTime<Utc>,
        started: mpsc::Sender<()>,
        hold: std::time::Duration,
        calls: Mutex<usize>,
    }

    impl JobRunner for ClockAdvancingRunner {
        fn run(&self, _store: &Arc<Mutex<Store>>, _job: &Job) -> Result<String, String> {
            *self.calls.lock().unwrap() += 1;
            self.clock.set(self.advanced_to);
            let _ = self.started.send(());
            std::thread::sleep(self.hold);
            Ok("slow job finished".to_string())
        }
    }

    #[test]
    fn renewal_interval_is_a_third_of_the_lease_with_a_floor() {
        assert_eq!(
            renewal_interval(std::time::Duration::from_secs(600)),
            std::time::Duration::from_secs(200)
        );
        assert_eq!(
            renewal_interval(std::time::Duration::from_millis(30)),
            std::time::Duration::from_millis(50)
        );
    }

    #[test]
    fn lease_renewal_keeps_a_long_running_job_claimed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let mut claimed_store = Store::open(&path).unwrap();
        let opener = FileStoreOpener::new(&path);
        let job = claimed_store
            .create_job(
                "main",
                "slow",
                "every 15m",
                "{}",
                Some("2000-01-01 00:00:00"),
            )
            .unwrap();

        let lease = std::time::Duration::from_secs(600);
        let t0 = utc(2026, 10, 3, 8, 0, 0);
        let clock = Arc::new(FakeClock::new(t0));
        // Simulate the scheduler's claim: the lease runs out at 08:10.
        let claimed = claimed_store
            .claim_due_jobs(
                &format_timestamp(t0),
                &format_timestamp(t0 + lease_delta(lease)),
            )
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(
            claimed_store
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:10:00")
        );

        let (started_tx, started_rx) = mpsc::channel();
        let runner = Arc::new(ClockAdvancingRunner {
            clock: Arc::clone(&clock),
            advanced_to: t0 + Duration::seconds(10),
            started: started_tx,
            hold: std::time::Duration::from_millis(1_200),
            calls: Mutex::new(0),
        });
        let clock_dyn = clock.reader();
        let job_clone = claimed[0].clone();
        let runner_thread = Arc::clone(&runner);
        let handle = std::thread::spawn(move || {
            run_claimed_job_with_interval(
                &opener,
                clock_dyn,
                runner_thread.as_ref(),
                lease,
                std::time::Duration::from_millis(100),
                &job_clone,
            )
        });

        // The runner rewinds the fake clock to 08:00:10; give the renewal
        // thread time to push the lease to 08:10:10.
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the runner must start");
        std::thread::sleep(std::time::Duration::from_millis(450));

        // At fake 08:10:05 the *original* lease would have expired; with the
        // renewal in place the job is leased until 08:10:10 and stays out.
        let mut intruder = Store::open(&path).unwrap();
        let now = t0 + Duration::seconds(605);
        let stolen = intruder
            .claim_due_jobs(
                &format_timestamp(now),
                &format_timestamp(now + lease_delta(lease)),
            )
            .unwrap();
        assert!(
            stolen.is_empty(),
            "a renewed lease must keep a running job out of another claim"
        );

        let succeeded = handle.join().unwrap().unwrap();
        assert!(succeeded);
        assert_eq!(*runner.calls.lock().unwrap(), 1);
        // After the run, the true next occurrence is written — never the
        // lease deadline.
        let stored = claimed_store.job_by_id(job.id).unwrap().unwrap();
        assert_eq!(stored.last_run_at.as_deref(), Some("2026-10-03 08:00:00"));
        assert_eq!(
            stored.next_run_at.as_deref(),
            Some("2026-10-03 08:15:10"),
            "next occurrence comes from the clock at finish, not from the lease"
        );
    }

    /// Runner that records begin/end events and can sleep to model a slow job.
    struct TrackingRunner {
        events: Arc<Mutex<Vec<String>>>,
        slow_for: std::time::Duration,
    }

    impl JobRunner for TrackingRunner {
        fn run(&self, _store: &Arc<Mutex<Store>>, job: &Job) -> Result<String, String> {
            self.events
                .lock()
                .unwrap()
                .push(format!("begin:{}", job.name));
            if job.name == "slow" {
                std::thread::sleep(self.slow_for);
            }
            self.events
                .lock()
                .unwrap()
                .push(format!("end:{}", job.name));
            Ok(format!("{} done", job.name))
        }
    }

    fn contains_event(events: &Arc<Mutex<Vec<String>>>, wanted: &str) -> bool {
        events.lock().unwrap().iter().any(|event| event == wanted)
    }

    #[tokio::test]
    async fn ticks_keep_claiming_while_a_slow_job_runs() {
        // A-03: a running job owns its own store connection, so later ticks
        // still claim and run other due work.
        let dir = tempdir().unwrap();
        let (store, opener) = file_store(&dir);
        store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "slow",
                "every 1h",
                "{}",
                Some("2000-01-01 00:00:00"),
            )
            .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let runner = Arc::new(TrackingRunner {
            events: Arc::clone(&events),
            slow_for: std::time::Duration::from_millis(800),
        });

        let handle = tokio::spawn(run_loop(
            Arc::clone(&store),
            Arc::clone(&opener),
            Arc::new(Utc::now),
            Arc::clone(&runner),
            std::time::Duration::from_millis(25),
            std::time::Duration::from_secs(60),
            switch_off(),
        ));

        // Wait for the slow job to start.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while !contains_event(&events, "begin:slow") && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            contains_event(&events, "begin:slow"),
            "the slow job must start"
        );

        // A new due job appears while the slow one still runs.
        store
            .lock()
            .unwrap()
            .create_job(
                "main",
                "fast",
                "every 1h",
                "{}",
                Some("2000-01-01 00:00:00"),
            )
            .unwrap();

        // It must be claimed and finish well before the slow job ends.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        while !contains_event(&events, "end:fast") && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let snapshot = events.lock().unwrap().clone();
        assert!(
            snapshot.contains(&"end:fast".to_string()),
            "ticks must keep going during a slow job: {snapshot:?}"
        );
        assert!(
            !snapshot.contains(&"end:slow".to_string()),
            "the slow job should still be running: {snapshot:?}"
        );

        // Let the slow job finish, then stop the loop. Both runs are
        // recorded on their own connections: wait for the commits.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while !contains_event(&events, "end:slow") && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            wait_for_finished_runs(&store, 1, 1, std::time::Duration::from_secs(3)),
            "the slow run must be recorded"
        );
        assert!(
            wait_for_finished_runs(&store, 2, 1, std::time::Duration::from_secs(3)),
            "the fast run must be recorded"
        );
        handle.abort();
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "begin:slow".to_string(),
                "begin:fast".to_string(),
                "end:fast".to_string(),
                "end:slow".to_string(),
            ]
        );
        let store = store.lock().unwrap();
        assert_eq!(store.runs_for_job(1).unwrap()[0].status, RUN_OK);
        assert_eq!(store.runs_for_job(2).unwrap()[0].status, RUN_OK);
    }
}
