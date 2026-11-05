//! The spend meter: usage rows, reservations and the per-day budget stop.
//!
//! A reservation holds budget before a call runs, the usage row written
//! afterwards settles it, and a day that reaches its cap is latched so no
//! further spend can slip through.

use super::*;

/// The most reservations a store holds unsettled at once (see
/// [`Store::try_reserve_for`]); a daemon's calls hold a handful.
const MAX_HELD_RESERVATIONS: i64 = 10_000;

/// How long a *consumed* reconcile claim (`usage_reconciled`) is kept, in
/// days from its `consumed_at`, before a prune deletes it.
///
/// A claim not yet consumed is never pruned: it exists only for a stale held
/// row the reconcile settled, so such claims stay rare, and keeping them
/// means a live settle that comes late always finds its claim and records
/// only what tops it. A consumed claim only turns a retry of that settle into
/// a no-op; past this retention a retry finds neither row nor claim and
/// records nothing all the same. A retry comes within the worker's backoff
/// (at most a minute apart); a week is far past that, and past a Mac asleep
/// over a long weekend.
///
/// `claimed_at` and `consumed_at` come from the store's own clock (UTC),
/// never from a caller, and no charge reads them: a clock set back only
/// delays a prune.
const RECONCILED_RETENTION_DAYS: u64 = 7;

/// The most claims one prune deletes, so a pass stays short.
pub(crate) const PRUNE_BATCH: i64 = 1000;

impl Store {
    /// Close one agent's existing daily budget latch and audit it atomically.
    /// This reuses the v6 `budget_stops` table; it does not add a migration.
    pub fn latch_budget_stop(
        &self,
        agent: &str,
        day: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        validate_usage_agent(agent)?;
        if !self.valid_day(day)? {
            return Err(StoreError::InvalidUsage {
                reason: format!("day `{day}` is not a valid calendar date"),
            });
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT INTO budget_stops(agent, day, reason) VALUES (?1, ?2, ?3)
             ON CONFLICT(agent, day) DO NOTHING",
            rusqlite::params![agent, day, reason],
        )?;
        if inserted > 0 {
            tx.execute(
                "INSERT INTO events(kind, payload) VALUES ('budget.latched', ?1)",
                [serde_json::json!({ "agent": agent, "day": day, "reason": reason }).to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Read the budget-stop reason, if the agent/day has been latched.
    pub fn budget_stop_reason(&self, agent: &str, day: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row(
                "SELECT reason FROM budget_stops WHERE agent = ?1 AND day = ?2",
                rusqlite::params![agent, day],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    // ---- usage meter ----

    /// Record a usage amount for `agent`, timestamped now (local time).
    pub fn record_usage(
        &self,
        agent: &str,
        kind: UsageKind,
        amount: u64,
        unit: &str,
    ) -> Result<UsageRecord, StoreError> {
        self.insert_usage(agent, kind, amount, unit, None, None)
    }

    /// Record a usage amount for `agent`, stamped with the identity of the turn
    /// that spent it.
    ///
    /// The receipt for that turn sums `usage` rows by `run_id` alone, so two
    /// overlapping turns of the same agent can never claim each other's spend.
    pub fn record_usage_for(
        &self,
        run_id: &str,
        agent: &str,
        kind: UsageKind,
        amount: u64,
        unit: &str,
    ) -> Result<UsageRecord, StoreError> {
        self.insert_usage(agent, kind, amount, unit, None, Some(run_id))
    }

    /// Atomically enforce an optional per-agent daily cap and record one usage
    /// row. `Some(used)` means the cap was already reached and no row was
    /// written; `None` means the call was charged. An immediate transaction
    /// makes this safe across concurrent daemon processes sharing the store.
    pub fn record_usage_if_under_daily_cap(
        &self,
        agent: &str,
        kind: UsageKind,
        unit: &str,
        cap: Option<u64>,
        run_id: Option<&str>,
    ) -> Result<Option<u64>, StoreError> {
        validate_usage_agent(agent)?;
        validate_usage_unit(unit)?;

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let at: String =
            tx.query_row("SELECT datetime('now', 'localtime')", [], |row| row.get(0))?;
        if let Some(cap) = cap {
            let used = {
                let mut statement = tx.prepare(
                    "SELECT amount FROM usage
                     WHERE agent = ?1 AND kind = ?2
                       AND at >= date(?3)
                       AND at < date(?3, '+1 day')",
                )?;
                let rows = statement
                    .query_map(rusqlite::params![agent, kind.as_str(), at], |row| {
                        row.get::<_, i64>(0)
                    })?;
                let mut total = 0u64;
                for row in rows {
                    total = total.saturating_add(row?.max(0) as u64);
                }
                total
            };
            if used >= cap {
                drop(tx);
                return Ok(Some(used));
            }
        }

        tx.execute(
            "INSERT INTO usage(agent, at, kind, amount, unit, run_id)
             VALUES (?1, ?2, ?3, 1, ?4, ?5)",
            rusqlite::params![agent, at, kind.as_str(), unit, run_id],
        )?;
        tx.commit()?;
        Ok(None)
    }

    /// Record a usage amount for `agent` at an explicit local timestamp.
    ///
    /// `at` must be something SQLite can parse (`YYYY-MM-DD HH:MM:SS`,
    /// `YYYY-MM-DD`, …). Exists so tests and backfills can pin the day.
    pub fn record_usage_at(
        &self,
        agent: &str,
        kind: UsageKind,
        amount: u64,
        unit: &str,
        at: &str,
    ) -> Result<UsageRecord, StoreError> {
        self.insert_usage(agent, kind, amount, unit, Some(at), None)
    }

    fn insert_usage(
        &self,
        agent: &str,
        kind: UsageKind,
        amount: u64,
        unit: &str,
        at: Option<&str>,
        run_id: Option<&str>,
    ) -> Result<UsageRecord, StoreError> {
        validate_usage_agent(agent)?;
        validate_usage_unit(unit)?;
        let amount = i64::try_from(amount).map_err(|_| StoreError::InvalidUsage {
            reason: format!("amount {amount} does not fit in i64"),
        })?;
        let id = match at {
            Some(at) => {
                self.validate_usage_at(at)?;
                self.conn.execute(
                    "INSERT INTO usage(agent, at, kind, amount, unit, run_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![agent, at, kind.as_str(), amount, unit, run_id],
                )?;
                self.conn.last_insert_rowid()
            }
            None => {
                self.conn.execute(
                    "INSERT INTO usage(agent, kind, amount, unit, run_id)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![agent, kind.as_str(), amount, unit, run_id],
                )?;
                self.conn.last_insert_rowid()
            }
        };
        self.usage_record(id)
    }

    /// Validate a timestamp the same way SQLite will read it back.
    ///
    /// SQLite *normalizes* impossible calendar dates (`2026-02-30` becomes
    /// `2026-03-02`), so the check round-trips: the parsed date must equal
    /// the date prefix of the input, not merely parse. This keeps
    /// `record_usage_at` consistent with the CLI's `valid_day` and prevents
    /// rows from landing in a bucket that can never be queried.
    fn validate_usage_at(&self, at: &str) -> Result<(), StoreError> {
        if sqlite_date_matches(&self.conn, at)? {
            return Ok(());
        }
        Err(StoreError::InvalidUsage {
            reason: format!("timestamp `{at}` is not a valid calendar date/time"),
        })
    }

    /// Spend totals for `agent` on the local day `day` (`YYYY-MM-DD`).
    ///
    /// Rows are matched by a half-open range on their local timestamp
    /// (`at >= day AND at < day + 1`), which uses `idx_usage_agent_day`
    /// instead of scanning the agent's whole history; unknown kinds (only
    /// possible in hand-edited databases) are ignored.
    pub fn usage_totals(&self, agent: &str, day: &str) -> Result<UsageTotals, StoreError> {
        let (tokens_in, tokens_out, usd_cents): (i64, i64, i64) = self.conn.query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN kind = 'tokens_in'  THEN amount END), 0),
                 COALESCE(SUM(CASE WHEN kind = 'tokens_out' THEN amount END), 0),
                 COALESCE(SUM(CASE WHEN kind = 'usd_cents'  THEN amount END), 0)
             FROM usage
             WHERE agent = ?1 AND at >= ?2 AND at < date(?2, '+1 day')",
            rusqlite::params![agent, day],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(UsageTotals {
            tokens_in: tokens_in.max(0) as u64,
            tokens_out: tokens_out.max(0) as u64,
            usd_cents: usd_cents.max(0) as u64,
        })
    }

    /// Spend totals for one turn identity: every `usage` row stamped with
    /// `run_id`, regardless of agent or day.
    ///
    /// This is the identity-based counterpart to [`Store::usage_totals`], used
    /// by a run receipt so two overlapping turns of the same agent can never
    /// claim each other's spend.
    pub fn usage_totals_for_run(&self, run_id: &str) -> Result<UsageTotals, StoreError> {
        let (tokens_in, tokens_out, usd_cents): (i64, i64, i64) = self.conn.query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN kind = 'tokens_in'  THEN amount END), 0),
                 COALESCE(SUM(CASE WHEN kind = 'tokens_out' THEN amount END), 0),
                 COALESCE(SUM(CASE WHEN kind = 'usd_cents'  THEN amount END), 0)
             FROM usage
             WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(UsageTotals {
            tokens_in: tokens_in.max(0) as u64,
            tokens_out: tokens_out.max(0) as u64,
            usd_cents: usd_cents.max(0) as u64,
        })
    }

    /// Agents that recorded any usage on the local day `day`, sorted.
    pub fn usage_agents(&self, day: &str) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT agent FROM usage
             WHERE at >= ?1 AND at < date(?1, '+1 day')
             ORDER BY agent ASC",
        )?;
        let rows = stmt.query_map([day], |row| row.get::<_, String>(0))?;
        let agents = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(agents)
    }

    /// Sum one usage kind for `agent` over the half-open local-time window
    /// `[from, until)`.
    ///
    /// The kind-generic counterpart to [`Store::usage_totals`]: it serves
    /// dimensions the provider tuple does not carry, notably
    /// [`UsageKind::ConnectorCalls`]. `from`/`until` are SQLite-parsable
    /// timestamps; malformed ones simply match nothing.
    ///
    /// The sum is **saturating**: SQLite's integer `SUM` would raise
    /// `integer overflow` once the window's total passed `i64::MAX`, which
    /// would make the meter unqueryable; here each non-negative row is added
    /// with `u64::saturating_add`, so a pathological amount pins the total at
    /// `u64::MAX` instead of erroring. Negative amounts (only possible in a
    /// hand-edited database) are treated as `0`, matching
    /// [`Store::usage_totals`].
    pub fn usage_total_between(
        &self,
        agent: &str,
        kind: UsageKind,
        from: &str,
        until: &str,
    ) -> Result<u64, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT amount FROM usage
             WHERE agent = ?1 AND kind = ?2 AND at >= ?3 AND at < ?4",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![agent, kind.as_str(), from, until],
            |row| row.get::<_, i64>(0),
        )?;
        let mut total: u64 = 0;
        for row in rows {
            total = total.saturating_add(row?.max(0) as u64);
        }
        Ok(total)
    }

    /// Sum one usage kind for `agent` over the calendar month `month`
    /// (`YYYY-MM`).
    ///
    /// The upper bound is `date(first_of_month, '+1 month')`, so a call made
    /// on the last day of one month never leaks into the next month's total
    /// and vice versa — the basis for the connector meter's monthly cap.
    /// Delegates to the saturating [`Store::usage_total_between`], so an
    /// oversized month cannot make the meter error.
    pub fn usage_total_for_month(
        &self,
        agent: &str,
        kind: UsageKind,
        month: &str,
    ) -> Result<u64, StoreError> {
        let first = format!("{month}-01");
        if !self.valid_day(&first)? {
            return Err(StoreError::InvalidUsage {
                reason: format!("month `{month}` is not a valid `YYYY-MM`"),
            });
        }
        let until: String =
            self.conn
                .query_row("SELECT date(?1, '+1 month')", [&first], |row| row.get(0))?;
        self.usage_total_between(agent, kind, &first, &until)
    }

    /// Today's date in local time (`YYYY-MM-DD`).
    ///
    /// Budgets are daily in the Mac's own timezone; the store is the single
    /// place that answers "which day is it".
    pub fn local_day(&self) -> Result<String, StoreError> {
        let day: String = self
            .conn
            .query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))?;
        Ok(day)
    }

    /// True when `day` is a date SQLite recognizes (`YYYY-MM-DD`).
    ///
    /// SQLite *normalizes* overflowing dates (`2026-02-30` becomes
    /// `2026-03-02`), so the check round-trips: the parsed date must equal
    /// the input, not merely parse.
    pub fn valid_day(&self, day: &str) -> Result<bool, StoreError> {
        let matches: i64 =
            self.conn
                .query_row("SELECT COALESCE(date(?1) = ?1, 0)", [day], |row| row.get(0))?;
        Ok(matches == 1)
    }

    // ---- atomic spend reservations (v5) ----

    /// Atomically enforce `caps` for `agent`/`day` and reserve `estimate`.
    ///
    /// The recorded totals and the active reservations are read, the caps
    /// enforced and the reservation inserted inside one `BEGIN IMMEDIATE`
    /// transaction, so two connections racing for the last of a cap can
    /// never both win. Expired reservations (a crashed caller) are ignored
    /// and swept in the same transaction.
    ///
    /// The caller's **own reserve is part of the admission test**:
    /// `recorded + reserved + own <= cap` for every capped kind. A capped
    /// `tokens_out` request that would cross the remaining headroom is
    /// *clamped* to it instead (the returned [`Reservation::estimate`] holds
    /// the effective value, which the caller passes to the provider as
    /// `max_tokens`); a capped `tokens_in`/`usd_cents` request that does not
    /// fit is denied. When nothing is left at all (`remaining == 0`) the call
    /// is denied, so no capped direction is ever admitted uncovered.
    ///
    /// A day latched closed by [`Store::settle_reservation`] after a
    /// completed call reached a cap is denied outright
    /// ([`DenialReason::FailClosed`]).
    pub fn try_reserve(
        &self,
        agent: &str,
        day: &str,
        caps: &BudgetCaps,
        estimate: &UsageTotals,
    ) -> Result<ReserveOutcome, StoreError> {
        self.try_reserve_for(None, agent, day, caps, estimate)
    }

    /// Like [`Store::try_reserve`], but stamps every usage row the resulting
    /// reservation later settles with the identity of the turn that owns it.
    pub fn try_reserve_for(
        &self,
        run_id: Option<&str>,
        agent: &str,
        day: &str,
        caps: &BudgetCaps,
        estimate: &UsageTotals,
    ) -> Result<ReserveOutcome, StoreError> {
        validate_usage_agent(agent)?;
        if !self.valid_day(day)? {
            return Err(StoreError::InvalidUsage {
                reason: format!("day `{day}` is not a valid calendar date"),
            });
        }
        let tokens_in =
            i64::try_from(estimate.tokens_in).map_err(|_| StoreError::InvalidUsage {
                reason: format!("reserved amount {} does not fit in i64", estimate.tokens_in),
            })?;
        let mut tokens_out =
            i64::try_from(estimate.tokens_out).map_err(|_| StoreError::InvalidUsage {
                reason: format!(
                    "reserved amount {} does not fit in i64",
                    estimate.tokens_out
                ),
            })?;
        let usd_cents =
            i64::try_from(estimate.usd_cents).map_err(|_| StoreError::InvalidUsage {
                reason: format!("reserved amount {} does not fit in i64", estimate.usd_cents),
            })?;

        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        // A day latched closed by a completed call that reached a cap admits
        // nothing further (B-01R). Read inside the transaction so a concurrent
        // settle cannot slip a call past the latch.
        if let Some(message) = tx
            .query_row(
                "SELECT reason FROM budget_stops WHERE agent = ?1 AND day = ?2",
                rusqlite::params![agent, day],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            drop(tx); // rollback: nothing was reserved
            return Ok(ReserveOutcome::Denied(Denial {
                agent: agent.to_string(),
                day: day.to_string(),
                reason: DenialReason::FailClosed { message },
                audit_error: None,
            }));
        }
        // Each settle a daemon still owes waits in its memory and keeps its
        // row held: a store that takes reservations but stops settling them
        // refuses new ones here, so that queue cannot grow without bound.
        let held: i64 = tx.query_row(
            "SELECT COUNT(*) FROM usage_reservations WHERE unsettled IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        if held >= MAX_HELD_RESERVATIONS {
            drop(tx); // rollback: nothing was reserved
            let message =
                format!("{held} reserved calls are still unsettled, the most a store holds");
            return Ok(ReserveOutcome::Denied(Denial {
                agent: agent.to_string(),
                day: day.to_string(),
                reason: DenialReason::LedgerUnavailable { message },
                audit_error: None,
            }));
        }
        // An older plain reservation of a process that died mid-call is
        // ignored below and swept here past its TTL. A held one (`unsettled`)
        // never expires: its call may be billed, so it counts until settled.
        tx.execute(
            "DELETE FROM usage_reservations
             WHERE agent = ?1 AND expires_at <= datetime('now', 'localtime')
               AND unsettled IS NULL",
            [agent],
        )?;
        let (recorded_in, recorded_out, recorded_usd) = day_totals_tx(&tx, agent, day)?;
        // Money is held like tokens: a call in flight keeps its estimated
        // cents out of everyone else's headroom until it settles.
        let (reserved_in, reserved_out, reserved_usd): (i64, i64, i64) = tx.query_row(
            "SELECT COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0),
                    COALESCE(SUM(usd_cents), 0)
             FROM usage_reservations
             WHERE agent = ?1 AND at >= ?2 AND at < date(?2, '+1 day')
               AND (expires_at > datetime('now', 'localtime') OR unsettled IS NOT NULL)",
            rusqlite::params![agent, day],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let recorded = [
            recorded_in.max(0) as u64,
            recorded_out.max(0) as u64,
            recorded_usd.max(0) as u64,
        ];
        let reserved = [
            reserved_in.max(0) as u64,
            reserved_out.max(0) as u64,
            reserved_usd.max(0) as u64,
        ];
        let mut effective = *estimate;
        // Provider dimensions only: connector calls are metered separately and
        // must never be able to deny a provider reservation (S2b).
        for (index, kind) in UsageKind::PROVIDER.into_iter().enumerate() {
            let Some(limit) = caps.limit(kind) else {
                continue;
            };
            let spent = recorded[index];
            let held = reserved[index];
            let remaining = limit.saturating_sub(spent.saturating_add(held));
            let own = estimate.get(kind);
            if remaining == 0 {
                drop(tx); // rollback: nothing was reserved
                return Ok(ReserveOutcome::Denied(Denial {
                    agent: agent.to_string(),
                    day: day.to_string(),
                    reason: DenialReason::CapExceeded {
                        kind,
                        spent,
                        reserved: held,
                        limit,
                    },
                    audit_error: None,
                }));
            }
            if own > remaining {
                if kind != UsageKind::TokensOut {
                    drop(tx); // rollback: nothing was reserved
                    return Ok(ReserveOutcome::Denied(Denial {
                        agent: agent.to_string(),
                        day: day.to_string(),
                        reason: DenialReason::CapExceeded {
                            kind,
                            spent,
                            reserved: held,
                            limit,
                        },
                        audit_error: None,
                    }));
                }
                // Output: reserve only what is left and let the caller cap
                // the provider at that value.
                effective.tokens_out = remaining;
                tokens_out = i64::try_from(remaining).map_err(|_| StoreError::InvalidUsage {
                    reason: format!("reserved amount {remaining} does not fit in i64"),
                })?;
            }
        }

        let ttl = format!("+{} seconds", RESERVATION_TTL.as_secs());
        // Held from the start, with what settling it needs once this process
        // is gone (see `settle_abandoned_reservations`).
        let unsettled =
            serde_json::json!({ "caps": caps, "run_id": run_id, "usd": estimate.usd_cents });
        tx.execute(
            "INSERT INTO usage_reservations(agent, at, expires_at, tokens_in, tokens_out, usd_cents,
                 unsettled)
             VALUES (?1, ?2, datetime('now', 'localtime', ?3), ?4, ?5, ?6, ?7)",
            rusqlite::params![agent, day, ttl, tokens_in, tokens_out, usd_cents, unsettled.to_string()],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(ReserveOutcome::Reserved(Reservation {
            id,
            agent: agent.to_string(),
            day: day.to_string(),
            estimate: effective,
            caps: *caps,
            run_id: run_id.map(str::to_string),
        }))
    }

    /// Replace a reservation with the call's actual usage: delete + insert
    /// in one transaction. A zero amount inserts no row for that direction.
    ///
    /// **Settle once** (I-02): the `DELETE` row count decides whether this is
    /// the settling call. When the reservation row is already gone — an
    /// earlier settle recorded this call, or a TTL sweep dropped it — the
    /// store records nothing further and returns `Ok`, so a double settle can
    /// never bill the daily cap twice. The spend of a call whose reservation
    /// was swept *before* its first settle is therefore not recorded; the
    /// `RESERVATION_TTL` is sized to keep that case out of the stream path.
    /// A held row a reconcile claimed first is the exception: the claim
    /// recorded the row's amount and kept it (`usage_reconciled`), so this
    /// records what `actual` tops it by in each direction and marks the
    /// claim consumed: the live amount wins, and is still recorded once; a
    /// retry that finds the claim consumed records nothing.
    ///
    /// When the recorded totals reach or cross a cap of `reservation.caps`,
    /// the same transaction writes a `budget_stops` latch for the agent and the
    /// local day the usage landed on: every later `try_reserve` for that
    /// agent/day is denied with [`DenialReason::FailClosed`]. A provider that
    /// ignores its completion cap can therefore overshoot with the calls
    /// already in flight, but never with a call that has not started.
    pub fn settle_reservation(
        &self,
        reservation: &Reservation,
        actual: &UsageActual,
    ) -> Result<(), StoreError> {
        self.settle_held(reservation, actual, false)
    }

    /// [`Store::settle_reservation`], or with `claim` a reconcile's: that
    /// records only a row it deletes itself, and keeps what it recorded.
    fn settle_held(
        &self,
        reservation: &Reservation,
        actual: &UsageActual,
        claim: bool,
    ) -> Result<(), StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let deleted = tx.execute(
            "DELETE FROM usage_reservations WHERE id = ?1",
            [reservation.id],
        )?;
        let mut record = *actual;
        if deleted == 0 {
            // Already settled (or swept after its TTL): settle once, record
            // nothing a second time, but what a live settle tops a claim by.
            let claimed = if claim {
                None
            } else {
                // Consumed once, by the first live settle: a retry finds
                // no unconsumed claim and records nothing.
                tx.query_row(
                    "UPDATE usage_reconciled SET consumed_at = datetime('now')
                     WHERE reservation_id = ?1 AND consumed_at IS NULL
                     RETURNING tokens_in, tokens_out, usd_cents",
                    [reservation.id],
                    |row| Ok([row.get::<_, u64>(0)?, row.get(1)?, row.get(2)?]),
                )
                .optional()?
            };
            let rest = claimed.map(|[tokens_in, tokens_out, usd_cents]| UsageActual {
                tokens_in: actual.tokens_in.saturating_sub(tokens_in),
                tokens_out: actual.tokens_out.saturating_sub(tokens_out),
                usd_cents: actual.usd_cents.saturating_sub(usd_cents),
                ..*actual
            });
            match rest {
                Some(rest) if [rest.tokens_in, rest.tokens_out, rest.usd_cents] != [0; 3] => {
                    record = rest;
                }
                _ => {
                    tx.commit()?;
                    return Ok(());
                }
            }
        }
        if claim {
            // The claim keeps what it recorded until a live settle consumes
            // it (see `prune_reconciled_claims`).
            tx.execute(
                "INSERT INTO usage_reconciled(reservation_id, tokens_in, tokens_out, usd_cents,
                     claimed_at)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))
                 ON CONFLICT(reservation_id) DO UPDATE SET
                   tokens_in = MAX(tokens_in, excluded.tokens_in),
                   tokens_out = MAX(tokens_out, excluded.tokens_out),
                   usd_cents = MAX(usd_cents, excluded.usd_cents)",
                rusqlite::params![
                    reservation.id,
                    actual.tokens_in,
                    actual.tokens_out,
                    actual.usd_cents
                ],
            )?;
        }
        let actual = &record;
        if actual.tokens_in > 0 {
            tx.execute(
                "INSERT INTO usage(agent, at, kind, amount, unit, run_id)
                 VALUES (?1, datetime('now', 'localtime'), 'tokens_in', ?2, ?3, ?4)",
                rusqlite::params![
                    reservation.agent,
                    actual.tokens_in,
                    unit_for(actual.tokens_in_estimated),
                    reservation.run_id
                ],
            )?;
        }
        if actual.tokens_out > 0 {
            tx.execute(
                "INSERT INTO usage(agent, at, kind, amount, unit, run_id)
                 VALUES (?1, datetime('now', 'localtime'), 'tokens_out', ?2, ?3, ?4)",
                rusqlite::params![
                    reservation.agent,
                    actual.tokens_out,
                    unit_for(actual.tokens_out_estimated),
                    reservation.run_id
                ],
            )?;
        }
        if actual.usd_cents > 0 {
            // Money actually spent: the provider-reported cost or the
            // per-model price table. Without this row the daily
            // `usd_cents` cap could never bind nor warn.
            tx.execute(
                "INSERT INTO usage(agent, at, kind, amount, unit, run_id)
                 VALUES (?1, datetime('now', 'localtime'), 'usd_cents', ?2, 'cents', ?3)",
                rusqlite::params![reservation.agent, actual.usd_cents, reservation.run_id],
            )?;
        }

        // Fail closed for the rest of the local day when this call reached a
        // cap of the caps it was admitted under (B-01R). Written in the same
        // transaction as the usage rows, so a racing `try_reserve` either
        // sees the latch or the usage total, never neither.
        let day: String = tx.query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))?;
        let (recorded_in, recorded_out, recorded_usd) =
            day_totals_tx(&tx, &reservation.agent, &day)?;
        let recorded = [
            recorded_in.max(0) as u64,
            recorded_out.max(0) as u64,
            recorded_usd.max(0) as u64,
        ];
        let actuals = [actual.tokens_in, actual.tokens_out, actual.usd_cents];
        // Provider dimensions only; see `try_reserve`.
        for (index, kind) in UsageKind::PROVIDER.into_iter().enumerate() {
            let Some(limit) = reservation.caps.limit(kind) else {
                continue;
            };
            let spent = recorded[index];
            if spent >= limit {
                let reason =
                    format!("a completed call reached the daily {kind} budget ({spent}/{limit})");
                let inserted = tx.execute(
                    "INSERT INTO budget_stops(agent, day, reason) VALUES (?1, ?2, ?3)
                     ON CONFLICT(agent, day) DO NOTHING",
                    rusqlite::params![reservation.agent, day, reason],
                )?;
                if inserted > 0 {
                    // The day closure is itself auditable, even when no later
                    // call is ever attempted.
                    tx.execute(
                        "INSERT INTO events(kind, payload) VALUES ('budget.latched', ?1)",
                        [serde_json::json!({
                            "agent": reservation.agent,
                            "day": day,
                            "reason": reason,
                        })
                        .to_string()],
                    )?;
                }
                break;
            }
            // 80 % warning (E-17): emitted once, when a settle first crosses
            // the line, so the app can warn before the cap latches.
            let line = warning_threshold(limit);
            let before = spent.saturating_sub(actuals[index]);
            if line > 0 && before < line && spent >= line {
                tx.execute(
                    "INSERT INTO events(kind, payload) VALUES ('budget.warning', ?1)",
                    [serde_json::json!({
                        "agent": reservation.agent,
                        "day": day,
                        "kind": kind.as_str(),
                        "spent": spent,
                        "limit": limit,
                    })
                    .to_string()],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Raise held reservation `id` to `actual` where that is more, so the caps
    /// count (money as well as tokens), and a later settle of the row records,
    /// the most its call is known to have spent, even once this process is
    /// gone. A lower amount never lowers what the row holds.
    pub fn raise_held_reservation(&self, id: i64, actual: &UsageActual) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE usage_reservations SET tokens_in = MAX(tokens_in, ?2),
                 tokens_out = MAX(tokens_out, ?3), usd_cents = MAX(usd_cents, ?4),
                 unsettled = json_set(unsettled, '$.usd',
                     MAX(COALESCE(json_extract(unsettled, '$.usd'), 0), ?4))
             WHERE id = ?1 AND unsettled IS NOT NULL",
            rusqlite::params![id, actual.tokens_in, actual.tokens_out, actual.usd_cents],
        )?;
        Ok(())
    }

    /// Settle the held reservations a stopped process left: rows past their
    /// TTL (a live call settles well within it) and not in `skip`, each at the
    /// most its call is known to have spent (its reserve, or more once
    /// raised), once. Each is claimed: deleted, recorded and kept in one
    /// transaction, so a live settle that still comes records only what tops
    /// it (see [`Store::settle_reservation`]). The daemon runs it at start
    /// and every minute; each pass then prunes old claims. Returns how many
    /// settled and how many failed; a failed one stays held for the next
    /// pass.
    pub fn settle_abandoned_reservations(
        &self,
        skip: &[i64],
    ) -> Result<(usize, usize), StoreError> {
        let mut rows = self
            .conn
            .prepare(
                "SELECT id, agent, at, tokens_in, tokens_out, unsettled FROM usage_reservations
                 WHERE unsettled IS NOT NULL AND expires_at <= datetime('now', 'localtime')",
            )?
            .query_map([], |row| {
                let amounts = (row.get(3)?, row.get(4)?);
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, amounts, row.get(5)?))
            })?
            .collect::<Result<Vec<(i64, String, String, (u64, u64), String)>, _>>()?;
        rows.retain(|row| !skip.contains(&row.0));
        let mut failed = 0;
        for (id, agent, day, (tokens_in, tokens_out), held) in rows.iter().cloned() {
            let held: serde_json::Value = serde_json::from_str(&held).unwrap_or_default();
            let usd_cents = held["usd"].as_u64().unwrap_or(0);
            let reservation = Reservation {
                id,
                agent,
                day,
                estimate: UsageTotals {
                    tokens_in,
                    tokens_out,
                    usd_cents,
                },
                caps: serde_json::from_value(held["caps"].clone()).unwrap_or_default(),
                run_id: held["run_id"].as_str().map(str::to_string),
            };
            let actual = UsageActual {
                tokens_in,
                tokens_in_estimated: true,
                tokens_out,
                tokens_out_estimated: true,
                usd_cents,
            };
            failed += usize::from(self.settle_held(&reservation, &actual, true).is_err());
        }
        // A prune that fails keeps its claims for the next pass; it never
        // costs a settle.
        let _ = self.prune_reconciled_claims();
        Ok((rows.len() - failed, failed))
    }

    /// Delete up to [`PRUNE_BATCH`] consumed reconcile claims, consumed at
    /// least [`RECONCILED_RETENTION_DAYS`] ago by the store's clock. A claim
    /// not consumed is never deleted. Returns how many it deleted.
    pub fn prune_reconciled_claims(&self) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            PRUNE_RECONCILED_SQL,
            rusqlite::params![retention_ago(), PRUNE_BATCH],
        )?)
    }

    /// Drop a reservation without recording usage.
    pub fn release_reservation(&self, reservation: &Reservation) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM usage_reservations WHERE id = ?1",
            [reservation.id],
        )?;
        Ok(())
    }

    /// Number of spend reservations held (regardless of expiry). Exposed for
    /// tests and diagnostics.
    pub fn reservation_count(&self) -> Result<usize, StoreError> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM usage_reservations", [], |row| {
                    row.get(0)
                })?;
        Ok(count.max(0) as usize)
    }

    /// Fetch one usage row by id.
    fn usage_record(&self, id: i64) -> Result<UsageRecord, StoreError> {
        let record = self.conn.query_row(
            "SELECT id, agent, at, kind, amount, unit FROM usage WHERE id = ?1",
            [id],
            |row| {
                Ok(UsageRecord {
                    id: row.get(0)?,
                    agent: row.get(1)?,
                    at: row.get(2)?,
                    kind: row.get(3)?,
                    amount: row.get(4)?,
                    unit: row.get(5)?,
                })
            },
        )?;
        Ok(record)
    }
}

/// The prune of consumed reconcile claims; `?1` = [`retention_ago`], `?2` =
/// [`PRUNE_BATCH`]. Shared with the v42 index test so it plans the real query.
pub(crate) const PRUNE_RECONCILED_SQL: &str =
    "DELETE FROM usage_reconciled WHERE reservation_id IN (
                 SELECT reservation_id FROM usage_reconciled
                 WHERE consumed_at IS NOT NULL
                   AND consumed_at <= datetime('now', ?1)
                 LIMIT ?2)";

/// The SQLite modifier for [`RECONCILED_RETENTION_DAYS`] ago.
pub(crate) fn retention_ago() -> String {
    format!("-{RECONCILED_RETENTION_DAYS} days")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use tempfile::tempdir;

    #[test]
    fn connector_calls_accounting_sums_a_calendar_month_across_its_boundary() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::ConnectorCalls,
                2,
                "calls",
                "2026-09-30 23:59:59",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::ConnectorCalls,
                3,
                "calls",
                "2026-10-01 00:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::ConnectorCalls,
                4,
                "calls",
                "2026-10-31 23:59:59",
            )
            .unwrap();
        // A different kind in the same window must never leak in.
        store
            .record_usage_at("main", UsageKind::TokensIn, 99, "tokens", "2026-10-15")
            .unwrap();

        assert_eq!(
            store
                .usage_total_for_month("main", UsageKind::ConnectorCalls, "2026-09")
                .unwrap(),
            2
        );
        assert_eq!(
            store
                .usage_total_for_month("main", UsageKind::ConnectorCalls, "2026-10")
                .unwrap(),
            7,
            "both sides of the month boundary are counted, and no further"
        );
        assert_eq!(
            store
                .usage_total_for_month("main", UsageKind::ConnectorCalls, "2026-11")
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .usage_total_between(
                    "main",
                    UsageKind::ConnectorCalls,
                    "2026-09-30",
                    "2026-10-01"
                )
                .unwrap(),
            2
        );
        assert!(matches!(
            store.usage_total_for_month("main", UsageKind::ConnectorCalls, "2026-13"),
            Err(StoreError::InvalidUsage { .. })
        ));
    }

    #[test]
    fn usage_totals_saturate_instead_of_overflowing() {
        let store = Store::open_in_memory().unwrap();
        let huge = i64::MAX as u64;
        store
            .record_usage_at(
                "main",
                UsageKind::ConnectorCalls,
                huge,
                "calls",
                "2026-10-15 08:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::ConnectorCalls,
                huge,
                "calls",
                "2026-10-15 09:00:00",
            )
            .unwrap();

        // SQLite's integer `SUM` overflows past `i64::MAX`; the meter must not.
        let two = (i64::MAX as u64) * 2;
        assert_eq!(
            store
                .usage_total_between(
                    "main",
                    UsageKind::ConnectorCalls,
                    "2026-10-01",
                    "2026-11-01"
                )
                .unwrap(),
            two,
            "two i64::MAX rows must not make the meter error"
        );
        assert_eq!(
            store
                .usage_total_for_month("main", UsageKind::ConnectorCalls, "2026-10")
                .unwrap(),
            two
        );

        // A third row pushes past u64::MAX: the total pins instead of erroring.
        store
            .record_usage_at(
                "main",
                UsageKind::ConnectorCalls,
                huge,
                "calls",
                "2026-10-15 10:00:00",
            )
            .unwrap();
        assert_eq!(
            store
                .usage_total_between(
                    "main",
                    UsageKind::ConnectorCalls,
                    "2026-10-01",
                    "2026-11-01"
                )
                .unwrap(),
            u64::MAX,
            "the sum saturates at u64::MAX"
        );
    }

    #[test]
    fn connector_accounting_does_not_change_existing_budget_invariants() {
        // S2b adds a fourth dimension without touching the provider spend path:
        // an exhausted connector cap must not deny a provider reservation, and
        // the provider day-latch must still fire exactly at the provider cap.
        let store = Store::open_in_memory().unwrap();
        // Settle stamps usage and the latch with the *current* local day, so the
        // reservation must be taken on that same day (the fixed-day tests use
        // `record_usage_at`/`try_reserve` explicitly; here we want the real
        // latch path).
        let day = store.local_day().unwrap();
        let caps = BudgetCaps {
            tokens_in: Some(10),
            connector_calls: Some(1),
            ..BudgetCaps::default()
        };
        for _ in 0..5 {
            store
                .record_usage("main", UsageKind::ConnectorCalls, 1, "calls")
                .unwrap();
        }
        assert!(
            store
                .usage_total_for_month("main", UsageKind::ConnectorCalls, &day[..7])
                .unwrap()
                > caps.limit(UsageKind::ConnectorCalls).unwrap(),
            "the connector cap really is exhausted"
        );

        match store
            .try_reserve("main", &day, &caps, &estimate(10, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => {
                store
                    .settle_reservation(
                        &reservation,
                        &UsageActual {
                            tokens_in: 10,
                            ..UsageActual::default()
                        },
                    )
                    .unwrap();
            }
            other => panic!("provider reservation must still be admitted: {other:?}"),
        }
        assert!(
            matches!(
                store
                    .try_reserve("main", &day, &caps, &estimate(1, 0))
                    .unwrap(),
                ReserveOutcome::Denied(_)
            ),
            "the provider cap still latches the day closed"
        );
        let totals = store.usage_totals("main", &day).unwrap();
        assert_eq!(totals.tokens_in, 10, "provider totals are unchanged");
        assert_eq!(totals.usd_cents, 0);
    }

    // ---- usage meter (v4) ----

    #[test]
    fn usage_round_trips_its_fields() {
        let store = Store::open_in_memory().unwrap();
        let record = store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                1234,
                "tokens_est",
                "2026-10-03 09:15:00",
            )
            .unwrap();

        assert!(record.id > 0);
        assert_eq!(record.agent, "main");
        assert_eq!(record.at, "2026-10-03 09:15:00");
        assert_eq!(record.kind, "tokens_in");
        assert_eq!(record.amount, 1234);
        assert_eq!(record.unit, "tokens_est");
    }

    #[test]
    fn record_usage_defaults_to_the_local_day() {
        let store = Store::open_in_memory().unwrap();
        let record = store
            .record_usage("main", UsageKind::UsdCents, 42, "cents")
            .unwrap();

        let day = store.local_day().unwrap();
        assert_eq!(
            day,
            record.at[..10],
            "recorded at `{}`, day `{day}`",
            record.at
        );
        assert_eq!(store.usage_totals("main", &day).unwrap().usd_cents, 42);
    }

    #[test]
    fn run_stamped_rows_with_no_receipt_still_count_toward_the_daily_totals() {
        // P2-B: a panic or `kill -9` mid-turn can leave usage rows stamped
        // with a `run_id` but no `run.finished` receipt. The daily budget must
        // still count them, so the cap cannot be evaded by dying.
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        store
            .record_usage_for("turn-no-receipt", "main", UsageKind::TokensIn, 12, "tokens")
            .unwrap();
        store
            .record_usage_for("turn-no-receipt", "main", UsageKind::UsdCents, 7, "cents")
            .unwrap();

        let daily = store.usage_totals("main", &day).unwrap();
        assert_eq!(daily.tokens_in, 12);
        assert_eq!(daily.usd_cents, 7, "an unreceipted turn still spends");
        // The turnover view stays exact and no receipt row is required.
        let per_run = store.usage_totals_for_run("turn-no-receipt").unwrap();
        assert_eq!((per_run.tokens_in, per_run.usd_cents), (12, 7));
        assert_eq!(store.event_count("run.finished").unwrap(), 0);
    }

    #[test]
    fn local_day_looks_like_a_date() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        assert_eq!(day.len(), 10);
        assert_eq!(&day[4..5], "-");
        assert_eq!(&day[7..8], "-");
        assert!(day.chars().filter(char::is_ascii_digit).count() == 8);
    }

    #[test]
    fn valid_day_rejects_impossible_dates() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.valid_day("2026-10-03").unwrap());
        assert!(store.valid_day("2024-02-29").unwrap(), "leap day is real");
        assert!(!store.valid_day("2026-02-30").unwrap());
        assert!(!store.valid_day("2026-13-01").unwrap());
        assert!(!store.valid_day("not a date").unwrap());
    }

    #[test]
    fn totals_sum_each_kind_for_one_agent_and_day_only() {
        let store = Store::open_in_memory().unwrap();
        let day = "2026-10-03";
        let other_day = "2026-10-04";

        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                100,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                50,
                "tokens",
                "2026-10-03 23:59:59",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensOut,
                7,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::UsdCents,
                3,
                "cents",
                "2026-10-03 08:00:00",
            )
            .unwrap();
        // Same agent, other day — must not leak into `day`.
        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                999,
                "tokens",
                "2026-10-04 00:00:01",
            )
            .unwrap();
        // Other agent, same day — must not leak into `main`.
        store
            .record_usage_at(
                "axis",
                UsageKind::TokensIn,
                777,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();

        assert_eq!(
            store.usage_totals("main", day).unwrap(),
            UsageTotals {
                tokens_in: 150,
                tokens_out: 7,
                usd_cents: 3,
            }
        );
        assert_eq!(
            store.usage_totals("main", other_day).unwrap().tokens_in,
            999
        );
        assert_eq!(store.usage_totals("axis", day).unwrap().tokens_in, 777);
        assert_eq!(
            store.usage_totals("nobody", day).unwrap(),
            UsageTotals::default()
        );
    }

    #[test]
    fn usage_agents_lists_each_agent_once_per_day() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                1,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensOut,
                1,
                "tokens",
                "2026-10-03 09:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "axis",
                UsageKind::TokensIn,
                1,
                "tokens",
                "2026-10-03 10:00:00",
            )
            .unwrap();
        store
            .record_usage_at(
                "zzz",
                UsageKind::TokensIn,
                1,
                "tokens",
                "2026-10-02 10:00:00",
            )
            .unwrap();

        assert_eq!(
            store.usage_agents("2026-10-03").unwrap(),
            vec!["axis".to_string(), "main".to_string()]
        );
        assert!(store.usage_agents("2026-10-05").unwrap().is_empty());
    }

    #[test]
    fn usage_rejects_junk_before_writing() {
        let store = Store::open_in_memory().unwrap();

        assert!(matches!(
            store.record_usage("", UsageKind::TokensIn, 1, "tokens"),
            Err(StoreError::InvalidUsage { .. })
        ));
        assert!(matches!(
            store.record_usage("main", UsageKind::TokensIn, 1, "bad unit!"),
            Err(StoreError::InvalidUsage { .. })
        ));
        assert!(matches!(
            store.record_usage_at("main", UsageKind::TokensIn, 1, "tokens", "not a time"),
            Err(StoreError::InvalidUsage { .. })
        ));
        assert!(matches!(
            store.record_usage_at(
                "main",
                UsageKind::TokensIn,
                1,
                "tokens",
                "2026-13-45 99:99:99"
            ),
            Err(StoreError::InvalidUsage { .. })
        ));
        assert_eq!(
            store.usage_totals("main", "2026-10-03").unwrap(),
            UsageTotals::default()
        );
    }

    #[test]
    fn record_usage_at_rejects_normalized_calendar_dates() {
        let store = Store::open_in_memory().unwrap();

        for bad in ["2026-02-30", "2026-02-29", "2026-04-31", "2026-13-01"] {
            assert!(
                matches!(
                    store.record_usage_at("main", UsageKind::TokensIn, 1, "tokens", bad),
                    Err(StoreError::InvalidUsage { .. })
                ),
                "`{bad}` must be rejected instead of normalized"
            );
        }
        assert_eq!(
            store.usage_totals("main", "2026-03-02").unwrap(),
            UsageTotals::default(),
            "no row may land in the normalized bucket"
        );

        // Real dates and explicit timestamps keep working.
        store
            .record_usage_at("main", UsageKind::TokensIn, 1, "tokens", "2024-02-29")
            .unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                2,
                "tokens",
                "2026-10-03 12:34:56",
            )
            .unwrap();
        assert_eq!(
            store.usage_totals("main", "2024-02-29").unwrap().tokens_in,
            1
        );
        assert_eq!(
            store.usage_totals("main", "2026-10-03").unwrap().tokens_in,
            2
        );
    }

    #[test]
    fn negative_rows_never_reduce_a_days_total() {
        let store = Store::open_in_memory().unwrap();
        // The API takes u64; if a hand-edited database ever holds a negative
        // row, the totals must clamp it instead of crediting spend back.
        store
            .conn
            .execute(
                "INSERT INTO usage(agent, kind, amount, unit) VALUES ('main', 'tokens_in', -5, 'tokens')",
                [],
            )
            .unwrap();
        let day = store.local_day().unwrap();
        assert_eq!(store.usage_totals("main", &day).unwrap().tokens_in, 0);
    }

    #[test]
    fn usage_persists_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let record_id = {
            let store = Store::open(&path).unwrap();
            store
                .record_usage_at(
                    "main",
                    UsageKind::TokensIn,
                    11,
                    "tokens",
                    "2026-10-03 12:00:00",
                )
                .unwrap()
                .id
        };

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            store.usage_totals("main", "2026-10-03").unwrap().tokens_in,
            11
        );
        let stored: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM usage WHERE id = ?1",
                [record_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, 1);
    }

    #[test]
    fn store_implements_the_budget_guard_seams() {
        use kernel_core::budget::{AuditSink, UsageLedger};

        let store = Store::open_in_memory().unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                9,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();

        let totals = UsageLedger::day_totals(&store, "main", "2026-10-03").unwrap();
        assert_eq!(totals.tokens_in, 9);

        AuditSink::audit(&store, "budget.denied", r#"{"agent":"main"}"#).unwrap();
        assert_eq!(store.event_count("budget.denied").unwrap(), 1);
    }

    #[test]
    fn reserve_holds_the_cap_across_connections() {
        // The B-01 scenario: two independent connections (two processes /
        // turns) both want the same headroom. The first reserves, the second
        // must be denied instead of both spending the cap.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store_a = Store::open(&path).unwrap();
        let store_b = Store::open(&path).unwrap();
        let caps = caps(Some(100), None);
        let estimate = estimate(100, 0);

        let first = store_a
            .try_reserve("main", "2026-10-03", &caps, &estimate)
            .unwrap();
        assert!(
            matches!(first, ReserveOutcome::Reserved(_)),
            "the first connection reserves: {first:?}"
        );

        let second = store_b
            .try_reserve("main", "2026-10-03", &caps, &estimate)
            .unwrap();
        match second {
            ReserveOutcome::Denied(denial) => assert_eq!(
                denial.reason,
                DenialReason::CapExceeded {
                    kind: UsageKind::TokensIn,
                    spent: 0,
                    reserved: 100,
                    limit: 100,
                }
            ),
            other => panic!("the second connection must be denied, got {other:?}"),
        }
        assert_eq!(store_a.reservation_count().unwrap(), 1);
    }

    #[test]
    fn simultaneous_reservations_from_two_connections_cannot_both_win() {
        // The real race: two connections hit the same cap at the same
        // instant. `BEGIN IMMEDIATE` serializes them, so exactly one wins.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        Store::open(&path).unwrap();
        let caps = caps(Some(100), None);
        let barrier = std::sync::Barrier::new(2);

        let outcomes: Vec<Result<ReserveOutcome, StoreError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let path = &path;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let store = Store::open(path).unwrap();
                        barrier.wait();
                        store.try_reserve("main", "2026-10-03", &caps, &estimate(100, 0))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });

        let reserved = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ReserveOutcome::Reserved(_))))
            .count();
        let denied = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ReserveOutcome::Denied(_))))
            .count();
        assert_eq!(
            (reserved, denied),
            (1, 1),
            "exactly one connection may reserve: {outcomes:?}"
        );
    }

    #[test]
    fn concurrent_money_reservations_never_overshoot_the_money_cap() {
        // Eight connections race for a 100-cent cap with 30 cents each:
        // at most three may hold money at once, never four (120 > 100).
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        Store::open(&path).unwrap();
        let mut caps = caps(Some(1_000_000), Some(1_000_000));
        caps.usd_cents = Some(100);
        let barrier = std::sync::Barrier::new(8);

        let outcomes: Vec<ReserveOutcome> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let (path, barrier, caps) = (&path, &barrier, &caps);
                    scope.spawn(move || {
                        let store = Store::open(path).unwrap();
                        let mut money = estimate(1, 1);
                        money.usd_cents = 30;
                        barrier.wait();
                        store
                            .try_reserve("main", "2026-10-03", caps, &money)
                            .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        let held: u64 = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                ReserveOutcome::Reserved(reservation) => Some(reservation.estimate.usd_cents),
                ReserveOutcome::Denied(_) => None,
            })
            .sum();
        assert_eq!(held, 90, "exactly three 30-cent holds fit: {outcomes:?}");
        let store = Store::open(&path).unwrap();
        assert_eq!(store.reservation_count().unwrap(), 3);
    }

    #[test]
    fn reserve_denies_an_already_reached_cap() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        store
            .record_usage_at("main", UsageKind::TokensIn, 100, "tokens", &day)
            .unwrap();

        let outcome = store
            .try_reserve("main", &day, &caps(Some(100), None), &estimate(10, 0))
            .unwrap();

        match outcome {
            ReserveOutcome::Denied(denial) => assert_eq!(
                denial.reason,
                DenialReason::CapExceeded {
                    kind: UsageKind::TokensIn,
                    spent: 100,
                    reserved: 0,
                    limit: 100,
                }
            ),
            other => panic!("expected a denial, got {other:?}"),
        }
        assert_eq!(store.reservation_count().unwrap(), 0);
    }

    #[test]
    fn reserve_allows_headroom_left_by_another_reservation() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(100), None);

        assert!(matches!(
            store
                .try_reserve("main", &day, &caps, &estimate(40, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        // 0 recorded + 40 reserved + 40 own <= 100: the second call fits.
        assert!(matches!(
            store
                .try_reserve("main", &day, &caps, &estimate(40, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        // 0 + 80 + 40 > 100: the caller's own reserve is part of the
        // admission test, so a third call must not start (B-01R).
        assert!(matches!(
            store
                .try_reserve("main", &day, &caps, &estimate(40, 0))
                .unwrap(),
            ReserveOutcome::Denied(_)
        ));
        // 0 + 80 + 20 <= 100: exactly the remaining headroom still fits.
        assert!(matches!(
            store
                .try_reserve("main", &day, &caps, &estimate(20, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        assert_eq!(store.reservation_count().unwrap(), 3);
    }

    #[test]
    fn reserve_clamps_a_capped_output_to_the_remaining_headroom() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(None, Some(100));

        // The requested 4096-token output reserve does not fit in the 100
        // token cap: it is clamped, never denied while headroom remains.
        let first = match store
            .try_reserve("main", &day, &caps, &estimate(10, 4096))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        assert_eq!(first.estimate.tokens_out, 100, "clamped to the cap");
        assert_eq!(first.caps, caps, "the admitted caps travel with it");

        // 0 recorded + 100 reserved + any own > 100: no headroom left.
        match store
            .try_reserve("main", &day, &caps, &estimate(10, 4096))
            .unwrap()
        {
            ReserveOutcome::Denied(denial) => assert_eq!(
                denial.reason,
                DenialReason::CapExceeded {
                    kind: UsageKind::TokensOut,
                    spent: 0,
                    reserved: 100,
                    limit: 100,
                }
            ),
            other => panic!("the cap is fully reserved, got {other:?}"),
        }

        // Settlement below the cap keeps the day open and frees the room.
        store
            .settle_reservation(
                &first,
                &UsageActual {
                    tokens_in: 10,
                    tokens_in_estimated: false,
                    tokens_out: 40,
                    tokens_out_estimated: false,
                    usd_cents: 0,
                },
            )
            .unwrap();
        let second = match store
            .try_reserve("main", &day, &caps, &estimate(10, 4096))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("headroom must be reusable, got {other:?}"),
        };
        assert_eq!(second.estimate.tokens_out, 60, "remaining headroom");
        assert_eq!(store.reservation_count().unwrap(), 1);
    }

    #[test]
    fn reservations_are_per_agent() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let main_caps = caps(Some(100), None);
        let axis_caps = caps(Some(100), None);

        assert!(matches!(
            store
                .try_reserve("main", &day, &main_caps, &estimate(100, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        assert!(
            matches!(
                store
                    .try_reserve("axis", &day, &axis_caps, &estimate(100, 0))
                    .unwrap(),
                ReserveOutcome::Reserved(_)
            ),
            "a reservation for one agent must not block another"
        );
    }

    #[test]
    fn settle_replaces_the_reservation_with_real_usage() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(100), Some(100));

        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(50, 50))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        assert_eq!(store.reservation_count().unwrap(), 1);

        store
            .settle_reservation(
                &reservation,
                &UsageActual {
                    tokens_in: 10,
                    tokens_in_estimated: false,
                    tokens_out: 5,
                    tokens_out_estimated: true,
                    usd_cents: 0,
                },
            )
            .unwrap();

        assert_eq!(store.reservation_count().unwrap(), 0);
        assert_eq!(
            store.usage_totals("main", &day).unwrap(),
            estimate(10, 5),
            "the real usage replaces the reservation"
        );
        let stored = store
            .conn
            .query_row(
                "SELECT unit FROM usage WHERE agent = 'main' AND kind = 'tokens_out'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(stored, ESTIMATED_UNIT);
        // The reservation no longer counts; the recorded 10 does.
        assert!(matches!(
            store
                .try_reserve("main", &day, &caps, &estimate(50, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
    }

    #[test]
    fn settling_the_same_reservation_twice_records_the_usage_once() {
        // I-02: settle once. The reservation row is the token: the first
        // settle deletes it, the second sees zero deleted rows and records
        // nothing, so an accidental double settle cannot bill the cap twice.
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(100), Some(100));
        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(50, 40))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        let actual = UsageActual {
            tokens_in: 10,
            tokens_in_estimated: false,
            tokens_out: 5,
            tokens_out_estimated: true,
            usd_cents: 7,
        };
        store.settle_reservation(&reservation, &actual).unwrap();
        assert_eq!(
            store.usage_totals("main", &day).unwrap(),
            UsageTotals {
                tokens_in: 10,
                tokens_out: 5,
                usd_cents: 7,
            }
        );

        store.settle_reservation(&reservation, &actual).unwrap();
        assert_eq!(
            store.usage_totals("main", &day).unwrap(),
            UsageTotals {
                tokens_in: 10,
                tokens_out: 5,
                usd_cents: 7,
            },
            "the second settle must be a no-op"
        );
        assert_eq!(store.reservation_count().unwrap(), 0);
    }

    #[test]
    fn settling_beyond_the_estimate_still_blocks_the_next_call() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(100), None);

        // The reservation fills the cap exactly: 0 recorded + 0 reserved +
        // 100 own == 100.
        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(100, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        store
            .settle_reservation(
                &reservation,
                &UsageActual {
                    tokens_in: 150,
                    tokens_in_estimated: false,
                    ..UsageActual::default()
                },
            )
            .unwrap();

        // The single-call overshoot is *only* the input-estimate error: the
        // reservation guessed 100, the provider reported 150, and the day
        // ended at 150 = cap + (actual - estimate).
        let recorded = store.usage_totals("main", &day).unwrap().tokens_in;
        assert_eq!(recorded, 150);
        assert_eq!(
            recorded - 100,
            150 - reservation.estimate.tokens_in,
            "overshoot must equal the input-estimate error, nothing more"
        );
        // The crossing settle also latches the day closed (B-01R): the next
        // call is denied for the fail-closed reason, not merely by arithmetic.
        match store
            .try_reserve("main", &day, &caps, &estimate(1, 0))
            .unwrap()
        {
            ReserveOutcome::Denied(denial) => {
                assert!(
                    matches!(denial.reason, DenialReason::FailClosed { .. }),
                    "expected the fail-closed latch, got {:?}",
                    denial.reason
                );
                assert!(
                    denial.reason_text().contains("tokens_in budget (150/100)"),
                    "{}",
                    denial.reason_text()
                );
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        assert_eq!(store.reservation_count().unwrap(), 0);
        // The closure is auditable once, exactly when the latch is written.
        assert_eq!(store.event_count("budget.latched").unwrap(), 1);
    }

    #[test]
    fn settling_exactly_onto_the_cap_latches_the_day() {
        // The test audit's MUT-01 boundary: `spent >= limit`, not `>`.
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(100), None);

        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(100, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        store
            .settle_reservation(
                &reservation,
                &UsageActual {
                    tokens_in: 100,
                    ..UsageActual::default()
                },
            )
            .unwrap();

        assert_eq!(store.usage_totals("main", &day).unwrap().tokens_in, 100);
        // Exactly at the cap: the day is latched (a `>` comparison would let
        // one more call through).
        match store
            .try_reserve("main", &day, &caps, &estimate(1, 0))
            .unwrap()
        {
            ReserveOutcome::Denied(denial) => assert!(
                matches!(denial.reason, DenialReason::FailClosed { .. }),
                "expected the fail-closed latch, got {:?}",
                denial.reason
            ),
            other => panic!("expected a denial, got {other:?}"),
        }
        assert_eq!(store.event_count("budget.latched").unwrap(), 1);
        // The settle itself never warns on the latch path.
        assert_eq!(store.event_count("budget.warning").unwrap(), 0);
    }

    #[test]
    fn crossing_eighty_percent_emits_one_warning_event() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(1000), None);

        let settle = |store: &Store, estimate_in: u64, actual_in: u64| {
            let reservation = match store
                .try_reserve("main", &day, &caps, &estimate(estimate_in, 0))
                .unwrap()
            {
                ReserveOutcome::Reserved(reservation) => reservation,
                other => panic!("expected a reservation, got {other:?}"),
            };
            store
                .settle_reservation(
                    &reservation,
                    &UsageActual {
                        tokens_in: actual_in,
                        ..UsageActual::default()
                    },
                )
                .unwrap();
        };

        settle(&store, 700, 700);
        assert_eq!(
            store.event_count("budget.warning").unwrap(),
            0,
            "below the line: no warning"
        );

        settle(&store, 100, 150);
        assert_eq!(
            store.event_count("budget.warning").unwrap(),
            1,
            "crossing 800/1000 warns once"
        );

        settle(&store, 10, 10);
        assert_eq!(
            store.event_count("budget.warning").unwrap(),
            1,
            "no repeat warning once above the line"
        );

        let payload: String = store
            .conn
            .query_row(
                "SELECT payload FROM events WHERE kind = 'budget.warning' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(payload.contains(r#""spent":850"#), "{payload}");
        assert!(payload.contains(r#""limit":1000"#), "{payload}");
    }

    #[test]
    fn settling_exactly_onto_eighty_percent_warns() {
        // M3b: the warning line is inclusive (`spent >= line`). Landing
        // exactly on 80 % of the cap must warn; a `>` mutation must not hide
        // it.
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(1000), None);
        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(800, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };

        store
            .settle_reservation(
                &reservation,
                &UsageActual {
                    tokens_in: 800,
                    ..UsageActual::default()
                },
            )
            .unwrap();

        assert_eq!(
            store.event_count("budget.warning").unwrap(),
            1,
            "exactly on the line must warn"
        );
    }

    #[test]
    fn settling_usd_records_the_spend_and_warns_exactly_on_the_line() {
        // P2-3: `usd_cents` usage is now recorded on settle, so the money cap
        // can bind and its 80 % warning is reachable — including exactly on
        // the line.
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let mut caps = caps(Some(1_000_000), None);
        caps.usd_cents = Some(100);
        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(1, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };

        store
            .settle_reservation(
                &reservation,
                &UsageActual {
                    usd_cents: 80,
                    ..UsageActual::default()
                },
            )
            .unwrap();

        assert_eq!(
            store.usage_totals("main", &day).unwrap().usd_cents,
            80,
            "the settled money is recorded in the ledger"
        );
        assert_eq!(store.event_count("budget.warning").unwrap(), 1);
        let payload: String = store
            .conn
            .query_row(
                "SELECT payload FROM events WHERE kind = 'budget.warning' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(payload.contains(r#""kind":"usd_cents""#), "{payload}");
    }

    #[test]
    fn settling_usd_onto_the_cap_latches_the_day_fail_closed() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let mut caps = caps(Some(1_000_000), None);
        caps.usd_cents = Some(100);
        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(1, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        store
            .settle_reservation(
                &reservation,
                &UsageActual {
                    usd_cents: 100,
                    ..UsageActual::default()
                },
            )
            .unwrap();

        match store
            .try_reserve("main", &day, &caps, &estimate(1, 0))
            .unwrap()
        {
            ReserveOutcome::Denied(denial) => {
                assert!(
                    matches!(denial.reason, DenialReason::FailClosed { .. }),
                    "expected the fail-closed latch, got {:?}",
                    denial.reason
                );
                assert!(denial.reason_text().contains("usd_cents"));
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        assert_eq!(store.event_count("budget.latched").unwrap(), 1);
    }

    #[test]
    fn a_fail_closed_latch_is_per_agent_and_per_day() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(100), None);

        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(50, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        store
            .settle_reservation(
                &reservation,
                &UsageActual {
                    tokens_in: 150,
                    tokens_in_estimated: false,
                    ..UsageActual::default()
                },
            )
            .unwrap();

        assert!(matches!(
            store
                .try_reserve("main", &day, &caps, &estimate(1, 0))
                .unwrap(),
            ReserveOutcome::Denied(_)
        ));
        // Another agent is untouched…
        assert!(matches!(
            store
                .try_reserve("axis", &day, &caps, &estimate(50, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        // …and a different day starts fresh. The day key is deliberately
        // unrelated to `local_day()`: a hardcoded "next day" breaks the test
        // when the suite runs exactly on it.
        assert!(matches!(
            store
                .try_reserve("main", "2000-01-01", &caps, &estimate(50, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
    }

    #[test]
    fn release_drops_the_reservation_without_recording_usage() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();

        let reservation = match store
            .try_reserve("main", &day, &caps(Some(100), None), &estimate(100, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        store.release_reservation(&reservation).unwrap();

        assert_eq!(store.reservation_count().unwrap(), 0);
        assert_eq!(
            store.usage_totals("main", &day).unwrap(),
            UsageTotals::default()
        );
    }

    #[test]
    fn expired_reservations_are_ignored_and_swept() {
        // A process that crashes mid-call leaves a reservation behind; after
        // its TTL it must not block the agent's cap forever.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store_a = Store::open(&path).unwrap();
        let store_b = Store::open(&path).unwrap();
        let caps = caps(Some(100), None);
        let estimate = estimate(100, 0);

        assert!(matches!(
            store_a
                .try_reserve("main", "2026-10-03", &caps, &estimate)
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
        assert!(matches!(
            store_b
                .try_reserve("main", "2026-10-03", &caps, &estimate)
                .unwrap(),
            ReserveOutcome::Denied(_)
        ));

        // Backdate the stale reservation past its TTL, as a row from before v39.
        store_a
            .conn
            .execute(
                "UPDATE usage_reservations SET expires_at = '2000-01-01 00:00:00', unsettled = NULL",
                [],
            )
            .unwrap();

        assert!(
            matches!(
                store_b
                    .try_reserve("main", "2026-10-03", &caps, &estimate)
                    .unwrap(),
                ReserveOutcome::Reserved(_)
            ),
            "an expired reservation must not block the cap"
        );
        assert_eq!(
            store_b.reservation_count().unwrap(),
            1,
            "the expired row was swept, only the new reservation remains"
        );
    }

    #[test]
    fn a_held_reservation_outlives_its_ttl_until_a_start_settles_it_once_at_its_most() {
        let store = Store::open_in_memory().unwrap();
        let (caps, day) = (caps(Some(100), None), store.local_day().unwrap());
        let reserved = store.try_reserve_for(Some("run-1"), "main", &day, &caps, &estimate(60, 0));
        let ReserveOutcome::Reserved(held) = reserved.unwrap() else {
            panic!("admitted");
        };
        // The call is known to have spent more than it reserved; its process
        // dies and the TTL passes: still held at that amount, so 20 more no
        // longer fit (60 + 20 would).
        let known = UsageActual {
            tokens_in: 90,
            tokens_out: 7,
            usd_cents: 3,
            ..UsageActual::default()
        };
        store.raise_held_reservation(held.id, &known).unwrap();
        let expire = "UPDATE usage_reservations SET expires_at = '2000-01-01 00:00:00'";
        store.conn.execute(expire, []).unwrap();
        let next = store.try_reserve("main", &day, &caps, &estimate(20, 0));
        assert!(matches!(next.unwrap(), ReserveOutcome::Denied(_)));
        // A row a job here still owes is left; a start charges the rest at
        // the most known, once.
        assert_eq!(
            store.settle_abandoned_reservations(&[held.id]).unwrap(),
            (0, 0)
        );
        assert_eq!(store.settle_abandoned_reservations(&[]).unwrap(), (1, 0));
        assert_eq!(store.settle_abandoned_reservations(&[]).unwrap(), (0, 0));
        assert_eq!(store.reservation_count().unwrap(), 0);
        let totals = store.usage_totals("main", &day).unwrap();
        assert_eq!(
            (totals.tokens_in, totals.tokens_out, totals.usd_cents),
            (90, 7, 3)
        );
    }

    #[test]
    fn a_raised_held_reservation_holds_its_raised_money_until_it_settles() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let mut caps = caps(None, None);
        caps.usd_cents = Some(100);
        let mut money = estimate(1, 1);
        money.usd_cents = 30;
        let reserved = store.try_reserve("main", &day, &caps, &money);
        let ReserveOutcome::Reserved(held) = reserved.unwrap() else {
            panic!("admitted");
        };
        let denied = || match store.try_reserve("main", &day, &caps, &money).unwrap() {
            ReserveOutcome::Denied(denial) => denial.reason,
            other => panic!("30 more cents must not fit, got {other:?}"),
        };
        let money_cap = |spent, reserved| DenialReason::CapExceeded {
            kind: UsageKind::UsdCents,
            spent,
            reserved,
            limit: 100,
        };
        // The call is known to have spent 80 cents, more than the 30 it
        // reserved: before it settles the cap holds the 80, so 30 more no
        // longer fit (beside the 30 they would).
        let known = UsageActual {
            tokens_in: 1,
            tokens_out: 1,
            usd_cents: 80,
            ..UsageActual::default()
        };
        store.raise_held_reservation(held.id, &known).unwrap();
        assert_eq!(denied(), money_cap(0, 80));
        // A lower amount never lowers what the row holds.
        let lower = UsageActual {
            usd_cents: 10,
            ..known
        };
        store.raise_held_reservation(held.id, &lower).unwrap();
        assert_eq!(denied(), money_cap(0, 80));
        // The settle moves the 80 from held to spent, once.
        store.settle_reservation(&held, &known).unwrap();
        assert_eq!(denied(), money_cap(80, 0));
    }

    #[test]
    fn a_live_settle_after_the_reconcile_claimed_its_row_records_only_what_tops_it() {
        let store = Store::open_in_memory().unwrap();
        let (caps, day) = (caps(Some(1000), None), store.local_day().unwrap());
        let reserved = store.try_reserve("main", &day, &caps, &estimate(60, 9));
        let ReserveOutcome::Reserved(held) = reserved.unwrap() else {
            panic!("admitted");
        };
        let expire = "UPDATE usage_reservations SET expires_at = '2000-01-01 00:00:00'";
        store.conn.execute(expire, []).unwrap();
        // The reconcile claims the row at its reserve before the live settle
        // lands: that tops it in and in money, not out; a retry adds nothing.
        assert_eq!(store.settle_abandoned_reservations(&[]).unwrap(), (1, 0));
        let live = UsageActual {
            tokens_in: 90,
            tokens_out: 4,
            usd_cents: 3,
            ..UsageActual::default()
        };
        store.settle_reservation(&held, &live).unwrap();
        assert_eq!(consumed(&store), 1, "the settle consumed its claim");
        store.settle_reservation(&held, &live).unwrap();
        let totals = store.usage_totals("main", &day).unwrap();
        let sum = |t: UsageTotals| (t.tokens_in, t.tokens_out, t.usd_cents);
        assert_eq!(sum(totals), (90, 9, 3));
        // The other order: a claim that finds its row settled records nothing.
        let reserved = store.try_reserve("main", &day, &caps, &estimate(5, 5));
        let ReserveOutcome::Reserved(other) = reserved.unwrap() else {
            panic!("admitted");
        };
        store.settle_reservation(&other, &live).unwrap();
        store
            .settle_held(&other, &UsageActual::default(), true)
            .unwrap();
        store.settle_reservation(&other, &live).unwrap();
        assert_eq!(sum(store.usage_totals("main", &day).unwrap()), (180, 13, 6));
    }

    fn claims(store: &Store) -> i64 {
        let count = "SELECT COUNT(*) FROM usage_reconciled";
        store.conn.query_row(count, [], |row| row.get(0)).unwrap()
    }

    fn consumed(store: &Store) -> i64 {
        let count = "SELECT COUNT(*) FROM usage_reconciled WHERE consumed_at IS NOT NULL";
        store.conn.query_row(count, [], |row| row.get(0)).unwrap()
    }

    /// Reserve 60 in / 9 out on `day`, expire it and let the reconcile claim it.
    fn claimed(store: &Store, day: &str) -> Reservation {
        let caps = caps(Some(1000), None);
        let reserved = store.try_reserve("main", day, &caps, &estimate(60, 9));
        let ReserveOutcome::Reserved(held) = reserved.unwrap() else {
            panic!("admitted");
        };
        let expire = "UPDATE usage_reservations SET expires_at = '2000-01-01 00:00:00'";
        store.conn.execute(expire, []).unwrap();
        assert_eq!(store.settle_abandoned_reservations(&[]).unwrap(), (1, 0));
        held
    }

    /// The live settle that tops a 60 / 9 claim by 30 in and 3 cents.
    const LIVE: UsageActual = UsageActual {
        tokens_in: 90,
        tokens_in_estimated: false,
        tokens_out: 4,
        tokens_out_estimated: false,
        usd_cents: 3,
    };

    fn today_sum(store: &Store) -> (u64, u64, u64) {
        let t = store
            .usage_totals("main", &store.local_day().unwrap())
            .unwrap();
        (t.tokens_in, t.tokens_out, t.usd_cents)
    }

    #[test]
    fn a_retry_after_its_claim_was_consumed_records_nothing_even_with_an_old_day() {
        let store = Store::open_in_memory().unwrap();
        let held = claimed(&store, "2000-01-01");
        store.settle_reservation(&held, &LIVE).unwrap();
        assert_eq!(today_sum(&store), (90, 9, 3));
        assert_eq!(consumed(&store), 1);
        // A retry, whatever day it carries, records nothing.
        let old = Reservation {
            day: "1999-12-31".to_string(),
            ..held.clone()
        };
        store.settle_reservation(&old, &LIVE).unwrap();
        store.settle_reservation(&held, &LIVE).unwrap();
        assert_eq!(today_sum(&store), (90, 9, 3));
        // Nor once its marker is pruned: neither row nor claim, as before.
        let age = "UPDATE usage_reconciled SET consumed_at = datetime('now', '-8 days')";
        store.conn.execute(age, []).unwrap();
        assert_eq!(store.prune_reconciled_claims().unwrap(), 1);
        store.settle_reservation(&old, &LIVE).unwrap();
        assert_eq!(today_sum(&store), (90, 9, 3));
    }

    #[test]
    fn an_unconsumed_claim_is_never_pruned_even_if_very_old() {
        let store = Store::open_in_memory().unwrap();
        let held = claimed(&store, &store.local_day().unwrap());
        let ancient = "UPDATE usage_reconciled SET claimed_at = '2000-01-01 00:00:00'";
        store.conn.execute(ancient, []).unwrap();
        assert_eq!(store.prune_reconciled_claims().unwrap(), 0);
        assert_eq!(store.settle_abandoned_reservations(&[]).unwrap(), (0, 0));
        assert_eq!(claims(&store), 1);
        // The late settle still finds it and records only what tops it.
        store.settle_reservation(&held, &LIVE).unwrap();
        assert_eq!(today_sum(&store), (90, 9, 3));
    }

    #[test]
    fn a_consumed_claim_is_pruned_after_its_retention_and_a_fresh_one_kept() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let (old, fresh) = (claimed(&store, &day), claimed(&store, &day));
        store.settle_reservation(&old, &LIVE).unwrap();
        store.settle_reservation(&fresh, &LIVE).unwrap();
        let age = "UPDATE usage_reconciled SET consumed_at = datetime('now', ?2)
            WHERE reservation_id = ?1";
        store.conn.execute(age, (old.id, "-8 days")).unwrap();
        store.conn.execute(age, (fresh.id, "-6 days")).unwrap();
        // The reconcile's own pass prunes.
        assert_eq!(store.settle_abandoned_reservations(&[]).unwrap(), (0, 0));
        let left: i64 = store
            .conn
            .query_row("SELECT reservation_id FROM usage_reconciled", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((claims(&store), left), (1, fresh.id));
    }

    #[test]
    fn one_prune_deletes_at_most_a_batch_of_consumed_claims() {
        let store = Store::open_in_memory().unwrap();
        store
            .conn
            .execute_batch(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 1001)
                 INSERT INTO usage_reconciled
                 SELECT i, 1, 1, 0, '2000-01-01 00:00:00', '2000-01-01 00:00:00' FROM n;
                 INSERT INTO usage_reconciled VALUES (5000, 1, 1, 0, '2000-01-01 00:00:00', NULL);",
            )
            .unwrap();
        assert_eq!(store.prune_reconciled_claims().unwrap(), 1000);
        assert_eq!(store.prune_reconciled_claims().unwrap(), 1);
        assert_eq!(store.prune_reconciled_claims().unwrap(), 0);
        assert_eq!(claims(&store), 1, "the unconsumed one stays");
    }

    #[test]
    fn a_clock_set_back_changes_no_charge() {
        let store = Store::open_in_memory().unwrap();
        let held = claimed(&store, &store.local_day().unwrap());
        // Claimed "in the future": the clock was set back since.
        let ahead = "UPDATE usage_reconciled SET claimed_at = '2999-01-01 00:00:00'";
        store.conn.execute(ahead, []).unwrap();
        store.settle_reservation(&held, &LIVE).unwrap();
        assert_eq!(today_sum(&store), (90, 9, 3));
        // Consumed "in the future": the prune only waits, a retry still adds
        // nothing.
        let ahead = "UPDATE usage_reconciled SET consumed_at = '2999-01-01 00:00:00'";
        store.conn.execute(ahead, []).unwrap();
        assert_eq!(store.prune_reconciled_claims().unwrap(), 0);
        store.settle_reservation(&held, &LIVE).unwrap();
        assert_eq!(today_sum(&store), (90, 9, 3));
    }

    #[test]
    fn past_ten_thousand_held_reservations_a_new_one_waits_for_a_settle() {
        let store = Store::open_in_memory().unwrap();
        let (caps, day) = (caps(Some(100), None), store.local_day().unwrap());
        // Another agent's calls, held by a store that stopped settling.
        store
            .conn
            .execute(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
                 INSERT INTO usage_reservations(agent, at, expires_at, unsettled)
                 SELECT 'other', ?1, '2999-01-01 00:00:00', '{}' FROM n",
                [&day],
            )
            .unwrap();
        let next = store.try_reserve("main", &day, &caps, &estimate(1, 0));
        let ReserveOutcome::Denied(denial) = next.unwrap() else {
            panic!("refused");
        };
        let reason = denial.reason_text();
        assert!(
            reason.contains("10000 reserved calls are still unsettled"),
            "{reason}"
        );
        let settle_one = "DELETE FROM usage_reservations WHERE id = 1";
        store.conn.execute(settle_one, []).unwrap();
        let next = store.try_reserve("main", &day, &caps, &estimate(1, 0));
        assert!(matches!(next.unwrap(), ReserveOutcome::Reserved(_)));
    }

    #[test]
    fn try_reserve_rejects_junk_before_writing() {
        let store = Store::open_in_memory().unwrap();
        let caps = caps(Some(100), None);

        assert!(matches!(
            store.try_reserve("", "2026-10-03", &caps, &estimate(1, 0)),
            Err(StoreError::InvalidUsage { .. })
        ));
        assert!(matches!(
            store.try_reserve("main", "2026-02-30", &caps, &estimate(1, 0)),
            Err(StoreError::InvalidUsage { .. })
        ));
        assert!(matches!(
            store.try_reserve("main", "2026-10-03", &caps, &estimate(u64::MAX, 0)),
            Err(StoreError::InvalidUsage { .. })
        ));
        assert_eq!(store.reservation_count().unwrap(), 0);
    }

    #[test]
    fn reservation_ledger_seam_round_trips() {
        let store = Store::open_in_memory().unwrap();
        let day = store.local_day().unwrap();
        let caps = caps(Some(100), None);

        let reservation = match store
            .try_reserve("main", &day, &caps, &estimate(10, 0))
            .unwrap()
        {
            ReserveOutcome::Reserved(reservation) => reservation,
            other => panic!("expected a reservation, got {other:?}"),
        };
        store.release(&reservation).unwrap();
        assert_eq!(store.reservation_count().unwrap(), 0);
    }

    #[test]
    fn usage_totals_query_uses_the_agent_day_index() {
        // B-03: the day filter must be a range on `at`, so SQLite can use
        // `idx_usage_agent_day` instead of scanning the agent's whole history.
        let store = Store::open_in_memory().unwrap();
        store
            .record_usage_at(
                "main",
                UsageKind::TokensIn,
                1,
                "tokens",
                "2026-10-03 08:00:00",
            )
            .unwrap();

        let mut stmt = store
            .conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT COALESCE(SUM(amount), 0) FROM usage
                 WHERE agent = ?1 AND at >= ?2 AND at < date(?2, '+1 day')",
            )
            .unwrap();
        let plan: Vec<String> = stmt
            .query_map(rusqlite::params!["main", "2026-10-03"], |row| row.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let plan = plan.join("\n");
        assert!(plan.contains("idx_usage_agent_day"), "plan: {plan}");
        assert!(!plan.contains("SCAN usage"), "plan: {plan}");
    }
}
