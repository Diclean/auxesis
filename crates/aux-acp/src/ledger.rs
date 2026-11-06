//! The ACP turn's store integration: conservative budget reservation,
//! write-ahead taint, one persisted assistant message, best-effort usage.
//!
//! ACP providers are flat-rate subscriptions (OpenCode Go) or not metered per
//! token, so the daily money cap can only bind through a **fixed per-turn
//! reserve**: the turn is admitted against `[acp] turn_cost_estimate_cents`
//! and settled at the same amount, never at the agent-reported cost. A
//! `usage_update` is observed best-effort for the log and never authorises
//! spend.
//!
//! An `unlimited` agent takes no store reservation, but its turn still knows its
//! fixed estimate: settle records that cost directly (the engine's unlimited
//! path), stamped with the turn's `run_id`, so an unlimited ACP turn is not
//! missing from its receipt.

use std::sync::{Arc, Mutex};

use aux_engine::{HeldReservation, TurnEvents};
use aux_store::{Message, Store};
use kernel_core::budget::{Budgets, ReserveOutcome, UsageActual, UsageKind, UsageTotals};

use crate::error::AcpError;
use crate::protocol::UsageUpdate;

/// One turn's admission reservation (fixed conservative estimate).
pub struct TurnReservation {
    /// Store row to settle. A turn dropped before its settle (its future
    /// cancelled while the agent had the prompt) settles the fixed estimate.
    pub(crate) inner: HeldReservation<'static, Arc<Mutex<Store>>>,
    /// The fixed cents reserved for this turn.
    pub cost_cents: u64,
}

/// Everything the backend needs from the engine/daemon.
///
/// Implementations own their store handle; the backend only calls these
/// methods between steps, never while streaming updates.
pub trait TurnHost: Send {
    /// Reserve the fixed per-turn estimate, or deny the turn.
    fn reserve_turn(&mut self, cost_cents: u64) -> Result<Option<TurnReservation>, AcpError>;

    /// Settle the reservation conservatively (the fixed estimate), logging
    /// the observed `usage_update` numbers best-effort.
    fn settle_turn(
        &mut self,
        reservation: Option<TurnReservation>,
        observed: &UsageUpdate,
    ) -> Result<(), AcpError>;

    /// Persist the final assistant message **once**.
    fn persist_assistant(&mut self, text: &str, meta: &str) -> Result<Message, AcpError>;

    /// Emit a persisted message through the turn's event sink.
    fn emit_message(&mut self, message: &Message);

    /// Emit the turn's `done` event.
    fn emit_done(&mut self, message_id: i64);

    /// Write the conversation's taint mark (write-ahead, before agent text is
    /// persisted, so a crash cannot launder it).
    ///
    /// Fatal when it cannot be written: the caller must not store the answer.
    fn taint_session(&mut self, source: &str) -> Result<(), AcpError>;
}

/// A [`TurnHost`] over the daemon's store, events and budgets.
pub struct StoreTurnHost {
    store: Arc<Mutex<Store>>,
    agent: String,
    session_id: i64,
    budgets: Budgets,
    events: Option<Arc<dyn TurnEvents>>,
    /// Identity of the turn whose fixed reservation this host settles, so the
    /// usage rows land under the turn that owns them. `None` keeps the
    /// legacy (unstamped) rows.
    run_id: Option<String>,
    /// The fixed per-turn estimate offered by [`TurnHost::reserve_turn`],
    /// retained even when the agent is `unlimited` and no store reservation
    /// exists. Settle records it as this turn's known spend, stamped with
    /// `run_id`. Taking it on the first settle makes a second settle a no-op.
    pending_cost_cents: Option<u64>,
    /// Private mode (G1): the answer is a memory-only row, never a store row.
    ephemeral: bool,
}

/// A row that exists only in memory: a private turn's message as the owner's
/// screen sees it. Ids are negative and unique in the process, so they never
/// collide with a store row.
pub fn local_row(session_id: i64, role: &str, content: &str, meta: Option<&str>) -> Message {
    static NEXT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    Message {
        id: NEXT.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) - 1,
        session_id,
        role: role.to_string(),
        content: content.to_string(),
        created_at: String::new(),
        meta: meta.map(str::to_string),
    }
}

impl StoreTurnHost {
    /// Build the host for one session.
    pub fn new(
        store: Arc<Mutex<Store>>,
        agent: String,
        session_id: i64,
        budgets: Budgets,
        events: Option<Arc<dyn TurnEvents>>,
    ) -> Self {
        Self {
            store,
            agent,
            session_id,
            budgets,
            events,
            run_id: None,
            pending_cost_cents: None,
            ephemeral: false,
        }
    }

    /// Keep the answer in memory only (private mode, G1).
    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }

    /// Attribute every row this host settles to `run_id`.
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    /// Record a failed settle under this turn's run identity, so the
    /// receipt can mark usage as unverifiable instead of implying it settled.
    ///
    /// Best-effort: the settle error is still returned (and logged by the
    /// caller), so failing to record the marker must never mask it.
    fn note_settle_failure(&self, reason: &str) {
        let Some(run_id) = self.run_id.as_deref() else {
            return;
        };
        let payload = serde_json::json!({
            "run_id": run_id,
            "agent": self.agent.as_str(),
            "reason": crate::scrub::scrub_agent_text(reason),
        });
        // Past the stop gate: after a stop the marker is dropped, not written.
        let marked = aux_engine::gated_usage_write(|| {
            lock_store(&self.store).log_event("usage.settle_failed", &payload.to_string())
        });
        if let Err(err) = marked {
            tracing::warn!(error = %err, "acp: could not record the failed settle marker");
        }
    }
}

fn lock_store(store: &Mutex<Store>) -> std::sync::MutexGuard<'_, Store> {
    kernel_core::lock_recover(store)
}

impl TurnHost for StoreTurnHost {
    fn reserve_turn(&mut self, cost_cents: u64) -> Result<Option<TurnReservation>, AcpError> {
        // A fresh admit clears any estimate a previous admission left behind.
        self.pending_cost_cents = None;
        let caps = self.budgets.caps_for(&self.agent);
        // After the stop no paid call starts, capped or not: its spend could
        // no longer be recorded. The reservation below passes the gate too.
        if aux_engine::gated_usage_write(|| Ok(())).is_err() {
            return Err(AcpError::BudgetDenied {
                reason: "the daemon is stopping: no new model call".to_string(),
            });
        }
        if caps.is_unlimited() {
            tracing::warn!(
                agent = %self.agent,
                "acp: budgets.unlimited = true; no daily cap is enforced for this agent"
            );
            // No reservation to settle, but the fixed estimate is still this
            // turn's known spend: retain it for settle to record directly.
            self.pending_cost_cents = Some(cost_cents);
            return Ok(None);
        }
        let estimate = UsageTotals {
            tokens_in: 0,
            tokens_out: 0,
            usd_cents: cost_cents,
        };
        // Past the stop gate, from the first store access: after a stop there
        // is no reservation, so the turn makes no model call (fail closed).
        // The lock is released inside it: a held reservation settles through it.
        let outcome = aux_engine::gated_usage_write(|| {
            let store = lock_store(&self.store);
            let day = store.local_day()?;
            store.try_reserve_for(self.run_id.as_deref(), &self.agent, &day, &caps, &estimate)
        })
        // A stop between the probe above and this write is the same refusal.
        .map_err(|err| {
            if aux_engine::is_stop_refusal(&err) {
                AcpError::BudgetDenied {
                    reason: "the daemon is stopping: no new model call".to_string(),
                }
            } else {
                AcpError::Store(err)
            }
        })?;
        match outcome {
            ReserveOutcome::Reserved(inner) => Ok(Some(TurnReservation {
                inner: HeldReservation::new(Arc::clone(&self.store), inner),
                cost_cents,
            })),
            ReserveOutcome::Denied(denial) => Err(AcpError::BudgetDenied {
                reason: denial.reason_text(),
            }),
        }
    }

    fn settle_turn(
        &mut self,
        reservation: Option<TurnReservation>,
        observed: &UsageUpdate,
    ) -> Result<(), AcpError> {
        if observed.used.is_some() || observed.size.is_some() || observed.cost_amount.is_some() {
            // Observability only: these numbers are snapshots from the agent
            // and are never used to authorise (or reduce) spend.
            tracing::info!(
                used = ?observed.used,
                size = ?observed.size,
                cost_amount = ?observed.cost_amount,
                cost_currency = ?observed.cost_currency,
                "acp: usage_update observed (best effort)"
            );
        }
        let outcome = match reservation {
            Some(reservation) => {
                let actual = UsageActual {
                    tokens_in: 0,
                    tokens_in_estimated: true,
                    tokens_out: 0,
                    tokens_out_estimated: true,
                    usd_cents: reservation.cost_cents,
                };
                reservation.inner.settle(&actual)
            }
            None => {
                // Unlimited budgets take no store reservation, but the fixed
                // estimate is still this turn's known spend. Record it
                // directly — the engine's unlimited path — stamped with the
                // turn's identity, so its receipt carries the cost. Taking the
                // pending estimate makes a second settle record nothing more.
                if let Some(cost_cents) = self.pending_cost_cents.take() {
                    aux_engine::gated_usage_write(|| {
                        let store = lock_store(&self.store);
                        match self.run_id.as_deref() {
                            Some(run_id) => store
                                .record_usage_for(
                                    run_id,
                                    &self.agent,
                                    UsageKind::UsdCents,
                                    cost_cents,
                                    "cents",
                                )
                                .map(|_| ()),
                            None => store
                                .record_usage(&self.agent, UsageKind::UsdCents, cost_cents, "cents")
                                .map(|_| ()),
                        }
                    })
                } else {
                    Ok(())
                }
            }
        };
        if let Err(err) = &outcome {
            // The caller keeps logging the returned error; record it under
            // the run too, so the receipt marks usage as unverifiable instead
            // of implying the fixed estimate settled at zero.
            self.note_settle_failure(&err.to_string());
        }
        outcome?;
        Ok(())
    }

    fn persist_assistant(&mut self, text: &str, meta: &str) -> Result<Message, AcpError> {
        if self.ephemeral {
            return Ok(local_row(self.session_id, "assistant", text, Some(meta)));
        }
        // Past the stop gate: a paid turn's answer cannot be saved after the
        // stop. Fail the turn, loudly; the text itself is not logged.
        aux_engine::gated_store_write(|| {
            lock_store(&self.store).append_message(self.session_id, "assistant", text, Some(meta))
        })
        .map_err(|err| write_failed(err, "the answer", self.session_id))
    }

    fn emit_message(&mut self, message: &Message) {
        if let Some(events) = &self.events {
            events.message(message);
        }
    }

    fn emit_done(&mut self, message_id: i64) {
        if let Some(events) = &self.events {
            events.done(self.session_id, message_id);
        }
    }

    fn taint_session(&mut self, source: &str) -> Result<(), AcpError> {
        // Past the stop gate. A mark that cannot be written is fatal for the
        // turn, whatever the reason: the answer must never land in a session
        // that is not marked. The message metadata still records the taint.
        aux_engine::gated_store_write(|| {
            lock_store(&self.store).mark_session_tainted(self.session_id, "acp", Some(source))
        })
        .map_err(|err| write_failed(err, "the session taint mark", self.session_id))
    }
}

/// A store write of the turn failed. Only the stop gate's refusal is "the
/// daemon is stopping" (an I/O stop); any other store error stays a store error.
fn write_failed(err: aux_store::StoreError, what: &str, session_id: i64) -> AcpError {
    if aux_engine::is_stop_refusal(&err) {
        tracing::error!(
            session = session_id,
            what,
            "acp: a paid turn's write was NOT saved: the daemon is stopping"
        );
        AcpError::Io(std::io::Error::other(format!(
            "the answer was not saved: {err}"
        )))
    } else {
        tracing::error!(error = %err, session = session_id, what, "acp: a store write failed");
        AcpError::Store(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_store::Store;
    use kernel_core::budget::UsageKind;

    fn host(budgets: Budgets) -> (StoreTurnHost, Arc<Mutex<Store>>) {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let session = lock_store(&store)
            .create_session("main", Some("acp test"))
            .unwrap();
        let host = StoreTurnHost::new(
            Arc::clone(&store),
            "main".to_string(),
            session.id,
            budgets,
            None,
        );
        (host, store)
    }

    fn capped_budgets(usd_cents: u64) -> Budgets {
        let mut budgets = Budgets::default();
        budgets.default.usd_cents = Some(usd_cents);
        budgets
    }

    fn unlimited_budgets() -> Budgets {
        let mut budgets = Budgets::default();
        budgets.default.unlimited = true;
        budgets
    }

    #[test]
    fn reserves_and_settles_the_fixed_estimate() {
        let (mut host, store) = host(capped_budgets(50));
        let reservation = host.reserve_turn(10).unwrap().unwrap();
        assert_eq!(reservation.cost_cents, 10);
        host.settle_turn(Some(reservation), &UsageUpdate::default())
            .unwrap();
        let day = lock_store(&store).local_day().unwrap();
        let totals = lock_store(&store).usage_totals("main", &day).unwrap();
        assert_eq!(totals.usd_cents, 10);
    }

    #[test]
    fn unlimited_budgets_still_record_the_fixed_estimate_under_the_run_id() {
        // An unlimited agent takes no reservation, but dropping the fixed
        // estimate there loses the turn's cost from its receipt entirely.
        let (host, store) = host(unlimited_budgets());
        let run_id = "turn-unlimited-1";
        let mut host = host.with_run_id(run_id);
        let reservation = host.reserve_turn(10).unwrap();
        assert!(
            reservation.is_none(),
            "unlimited budgets take no store reservation"
        );
        host.settle_turn(None, &UsageUpdate::default()).unwrap();
        let day = lock_store(&store).local_day().unwrap();
        let daily = lock_store(&store).usage_totals("main", &day).unwrap();
        assert_eq!(daily.usd_cents, 10, "the fixed cost counts in the day");
        let per_run = lock_store(&store).usage_totals_for_run(run_id).unwrap();
        assert_eq!(
            per_run.usd_cents, 10,
            "the receipt's identity view carries the cost"
        );
        // ACP reports no billable token counts; tokens are honestly zero
        // (same as the capped settle), never the observed context snapshot.
        assert_eq!((per_run.tokens_in, per_run.tokens_out), (0, 0));
    }

    #[test]
    fn capped_budgets_keep_their_existing_accounting() {
        // The capped path is untouched: a reservation is taken, the fixed
        // estimate is settled through it, and a later reserve sees the spend.
        let (host, store) = host(capped_budgets(50));
        let mut host = host.with_run_id("turn-capped-1");
        let reservation = host.reserve_turn(10).unwrap().unwrap();
        host.settle_turn(Some(reservation), &UsageUpdate::default())
            .unwrap();
        let day = lock_store(&store).local_day().unwrap();
        assert_eq!(
            lock_store(&store)
                .usage_totals("main", &day)
                .unwrap()
                .usd_cents,
            10
        );
        assert_eq!(
            lock_store(&store)
                .usage_totals_for_run("turn-capped-1")
                .unwrap()
                .usd_cents,
            10
        );
        assert_eq!(
            lock_store(&store).reservation_count().unwrap(),
            0,
            "the reservation is settled, not left held"
        );
    }

    #[test]
    fn a_second_unlimited_settle_records_nothing_more() {
        let (host, store) = host(unlimited_budgets());
        let mut host = host.with_run_id("turn-unlimited-2");
        host.reserve_turn(10).unwrap();
        host.settle_turn(None, &UsageUpdate::default()).unwrap();
        host.settle_turn(None, &UsageUpdate::default()).unwrap();
        let day = lock_store(&store).local_day().unwrap();
        assert_eq!(
            lock_store(&store)
                .usage_totals("main", &day)
                .unwrap()
                .usd_cents,
            10,
            "a double settle must record the estimate once"
        );
    }

    #[test]
    fn denies_when_the_daily_money_cap_is_exhausted() {
        let (mut host, _store) = host(capped_budgets(5));
        let first = host.reserve_turn(10);
        assert!(matches!(first, Err(AcpError::BudgetDenied { .. })));
    }

    #[test]
    fn a_failed_settle_records_a_marker_for_the_run() {
        // A settle that cannot write its usage row fails. The failure must
        // be recorded under the run for the receipt to mark usage unverified.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("store.db");
        let store = Arc::new(Mutex::new(Store::open(&db).unwrap()));
        let session = lock_store(&store)
            .create_session("main", Some("acp test"))
            .unwrap();
        let mut host = StoreTurnHost::new(
            Arc::clone(&store),
            "main".to_string(),
            session.id,
            capped_budgets(50),
            None,
        )
        .with_run_id("turn-settle-refused");
        let reservation = host.reserve_turn(10).unwrap().unwrap();
        // The store refuses every new usage row: the settle fails.
        aux_store::open_keyed(&db)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER refuse_usage BEFORE INSERT ON usage
                 BEGIN SELECT RAISE(ABORT, 'usage refused'); END;",
            )
            .unwrap();
        assert!(host
            .settle_turn(Some(reservation), &UsageUpdate::default())
            .is_err());
        assert_eq!(
            lock_store(&store)
                .event_count("usage.settle_failed")
                .unwrap(),
            1,
            "the failed settle must leave one marker for this run"
        );
        // The failed settle handed its held row to the process-wide settlement
        // worker, which retries it for as long as the refusal stands. Lift the
        // refusal and wait for that retry to land: a worker still running SQL
        // when this process exits races SQLCipher's exit hook, which frees its
        // state under the running statement (a SIGSEGV after the test passed).
        aux_store::open_keyed(&db)
            .unwrap()
            .execute_batch("DROP TRIGGER refuse_usage;")
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while lock_store(&store).reservation_count().unwrap() != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker never settled the held row"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn a_second_settle_of_a_recorded_estimate_leaves_no_failure_marker() {
        let (host, store) = host(unlimited_budgets());
        let mut host = host.with_run_id("turn-clean-settle");
        host.reserve_turn(10).unwrap();
        host.settle_turn(None, &UsageUpdate::default()).unwrap();
        // A second settle records nothing (the estimate was already taken) and
        // is not a failure, so no marker is written.
        host.settle_turn(None, &UsageUpdate::default()).unwrap();
        assert_eq!(
            lock_store(&store)
                .event_count("usage.settle_failed")
                .unwrap(),
            0
        );
    }

    #[test]
    fn persist_once_and_taint_write_ahead() {
        let (mut host, store) = host(Budgets::default());
        host.taint_session("turn 1").unwrap();
        let message = host.persist_assistant("answer", r#"{"acp":true}"#).unwrap();
        assert_eq!(message.role, "assistant");
        let taint = lock_store(&store)
            .session_taint(message.session_id)
            .unwrap();
        assert_eq!(taint.unwrap().tool, "acp");
        // One message, not two.
        let rows = lock_store(&store)
            .list_messages(message.session_id)
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn observed_usage_is_logged_but_never_settles_above_the_estimate() {
        let (mut host, store) = host(capped_budgets(50));
        let reservation = host.reserve_turn(10).unwrap().unwrap();
        let observed = UsageUpdate {
            used: Some(123_456),
            size: Some(200_000),
            cost_amount: Some(99.99),
            cost_currency: Some("USD".to_string()),
        };
        host.settle_turn(Some(reservation), &observed).unwrap();
        let day = lock_store(&store).local_day().unwrap();
        let totals = lock_store(&store).usage_totals("main", &day).unwrap();
        assert_eq!(
            totals.usd_cents, 10,
            "the reported cost must never raise the settled amount"
        );
        assert_eq!(totals.get(UsageKind::TokensIn), 0);
    }
}
