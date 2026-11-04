//! Taint marks and the trust requests that clear them.
//!
//! A tainted workspace or session is one that handled untrusted content;
//! a trust request is the owner-presence proof that lets it be marked
//! clean again.

use super::*;

impl Store {
    // ---- taint marks (v9) ----

    /// Record that `workspace` has been touched by an untrusted-class call.
    ///
    /// The mark is sticky: every conversation that starts in a touched
    /// workspace is tainted until an explicit owner action consumes a pending
    /// trust request ([`Self::complete_trust_request`]). The latest source
    /// wins.
    pub fn mark_workspace_tainted(&self, workspace: &str, source: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO workspace_taint(workspace, reason) VALUES (?1, ?2)
             ON CONFLICT(workspace) DO UPDATE SET
                 reason = excluded.reason,
                 at = datetime('now')",
            rusqlite::params![workspace, source],
        )?;
        Ok(())
    }

    /// The source that touched `workspace`, or `None` when it is clean.
    pub fn workspace_taint(&self, workspace: &str) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row(
                "SELECT reason FROM workspace_taint WHERE workspace = ?1",
                [workspace],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Record a conversation's taint *before* its untrusted call runs.
    ///
    /// The first source is kept; later marks cannot change what was seen
    /// first. The row survives a cancelled or crashed turn, so the session
    /// resumes tainted even though no result was ever persisted.
    pub fn mark_session_tainted(
        &self,
        session_id: i64,
        tool: &str,
        detail: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO session_taint(session_id, tool, detail) VALUES (?1, ?2, ?3)
             ON CONFLICT(session_id) DO NOTHING",
            rusqlite::params![session_id, tool, detail],
        )?;
        Ok(())
    }

    /// The conversation's write-ahead taint mark, or `None` when it has none.
    pub fn session_taint(&self, session_id: i64) -> Result<Option<SessionTaint>, StoreError> {
        self.conn
            .query_row(
                "SELECT tool, detail FROM session_taint WHERE session_id = ?1",
                [session_id],
                |row| {
                    Ok(SessionTaint {
                        tool: row.get(0)?,
                        detail: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Record that `session_id` read private owner data (mail, calendar,
    /// memory or notes) **before** the read runs.
    ///
    /// The first source is kept; later reads cannot change it. The row makes
    /// the egress rule sticky across turns of the same thread: a `ChatSession`
    /// rebuilt for the next inbound turn of the same conversation restores
    /// the flag from here, so no private-data read followed by turn 2 of the
    /// same `session_id` can fetch silently again. A read the owner refused
    /// never writes this row.
    pub fn mark_session_private_data(&self, session_id: i64, tool: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO session_private_data(session_id, tool) VALUES (?1, ?2)
             ON CONFLICT(session_id) DO NOTHING",
            rusqlite::params![session_id, tool],
        )?;
        Ok(())
    }

    /// The first tool that read private owner data in this conversation, or
    /// `None` when none did.
    pub fn session_private_data(&self, session_id: i64) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row(
                "SELECT tool FROM session_private_data WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    // ---- owner trust requests (v10) ----

    /// Create (or replace) the pending owner trust request for `workspace`.
    ///
    /// Rate-limited: while a request younger than `cooldown_secs` exists the
    /// call returns [`PutTrustOutcome::RateLimited`] and writes nothing, so a
    /// shell loop cannot flood the owner's notifications. The
    /// `workspace.trust_requested` audit row is written in the same
    /// transaction as the request, and the row stores only the hash — this
    /// method (and every method in this section) has no code parameter at
    /// all, so no code can reach a store row or an audit row through it.
    pub fn put_trust_request(
        &self,
        workspace: &str,
        request: &NewTrustRequest,
        now: i64,
        cooldown_secs: i64,
        by: &str,
    ) -> Result<PutTrustOutcome, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT created_at FROM trust_requests WHERE workspace = ?1",
                [workspace],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(created_at) = existing {
            // A clock that went backwards counts as "just requested": the
            // cooldown is a floor on notification frequency, never a bypass.
            let elapsed = (now - created_at).max(0);
            if elapsed < cooldown_secs {
                drop(tx); // rollback: nothing was stored
                return Ok(PutTrustOutcome::RateLimited {
                    retry_after_secs: cooldown_secs - elapsed,
                });
            }
        }
        tx.execute(
            "INSERT INTO trust_requests(workspace, request_id, code_hash, salt, created_at, attempts)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)
             ON CONFLICT(workspace) DO UPDATE SET
                 request_id = excluded.request_id,
                 code_hash  = excluded.code_hash,
                 salt       = excluded.salt,
                 created_at = excluded.created_at,
                 attempts   = 0",
            rusqlite::params![
                workspace,
                request.request_id,
                request.code_hash,
                request.salt,
                now
            ],
        )?;
        let payload = serde_json::json!({
            "workspace": workspace,
            "request_id": request.request_id,
            "cooldown_secs": cooldown_secs,
            "by": by,
        })
        .to_string();
        tx.execute(
            "INSERT INTO events(kind, payload) VALUES ('workspace.trust_requested', ?1)",
            [payload],
        )?;
        tx.commit()?;
        Ok(PutTrustOutcome::Stored)
    }

    /// The pending trust request of `workspace`, or `None`.
    pub fn trust_request(&self, workspace: &str) -> Result<Option<TrustRequest>, StoreError> {
        self.conn
            .query_row(
                "SELECT request_id, code_hash, salt, created_at, attempts
                   FROM trust_requests WHERE workspace = ?1",
                [workspace],
                |row| {
                    Ok(TrustRequest {
                        request_id: row.get(0)?,
                        code_hash: row.get(1)?,
                        salt: row.get(2)?,
                        created_at: row.get(3)?,
                        attempts: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Count one wrong code against `workspace`'s pending request.
    ///
    /// Returns the new attempt count, or `None` when the matching request no
    /// longer exists (completed, expired or replaced). At `max_attempts` the
    /// request is **spent in place**: the row is kept (attempts stay at the
    /// cap, the code can never match again, [`Self::complete_trust_request`]
    /// refuses it), because the row's `created_at` is also the cooldown
    /// watermark — deleting it let three wrong codes reset the rate limit
    /// A fresh request replaces the spent row once
    /// the cooldown has passed. The `workspace.trust_failed` row is written
    /// atomically and never contains a code.
    pub fn bump_trust_attempts(
        &self,
        workspace: &str,
        request_id: &str,
        max_attempts: i64,
        by: &str,
    ) -> Result<Option<i64>, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let updated = tx.execute(
            "UPDATE trust_requests SET attempts = attempts + 1
              WHERE workspace = ?1 AND request_id = ?2",
            rusqlite::params![workspace, request_id],
        )?;
        if updated == 0 {
            drop(tx);
            return Ok(None);
        }
        let attempts: i64 = tx.query_row(
            "SELECT attempts FROM trust_requests WHERE workspace = ?1",
            [workspace],
            |row| row.get(0),
        )?;
        let exhausted = attempts >= max_attempts;
        let payload = serde_json::json!({
            "workspace": workspace,
            "request_id": request_id,
            "reason": "wrong_code",
            "attempts": attempts,
            "attempts_exhausted": exhausted,
            "by": by,
        })
        .to_string();
        tx.execute(
            "INSERT INTO events(kind, payload) VALUES ('workspace.trust_failed', ?1)",
            [payload],
        )?;
        tx.commit()?;
        Ok(Some(attempts))
    }

    /// Audit a completion attempt that found no pending request (never
    /// requested, replayed after use, expired-and-swept, or cancelled by the
    /// attempt cap). Never carries a code; callers do not distinguish the
    /// cases, so a repeated wrong invocation cannot be mistaken for a real
    /// attempt count.
    pub fn log_trust_no_request(&self, workspace: &str, by: &str) -> Result<(), StoreError> {
        let payload = serde_json::json!({
            "workspace": workspace,
            "reason": "no_pending_request",
            "by": by,
        })
        .to_string();
        self.log_event("workspace.trust_failed", &payload)
    }

    /// Drop a pending request that can no longer be completed and audit it
    /// atomically (`reason` is `notification_failed` or `expired`).
    ///
    /// Returns true when the request existed.
    pub fn delete_trust_request(
        &self,
        workspace: &str,
        request_id: &str,
        reason: &str,
        by: &str,
    ) -> Result<bool, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let deleted = tx.execute(
            "DELETE FROM trust_requests WHERE workspace = ?1 AND request_id = ?2",
            rusqlite::params![workspace, request_id],
        )?;
        if deleted == 0 {
            drop(tx);
            return Ok(false);
        }
        let payload = serde_json::json!({
            "workspace": workspace,
            "request_id": request_id,
            "reason": reason,
            "by": by,
        })
        .to_string();
        tx.execute(
            "INSERT INTO events(kind, payload) VALUES ('workspace.trust_failed', ?1)",
            [payload],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Complete a pending owner trust request: consume it (single use), clear
    /// the workspace mark and write the `workspace.trusted` audit row in one
    /// transaction.
    ///
    /// Returns `None` when no request matches (already used, replaced, swept
    /// after expiry, never made, or spent by the attempt cap: a row whose
    /// `attempts` reached `max_attempts` is kept as the cooldown watermark
    /// and can never complete). `Some(changed)` means the request was
    /// consumed and the mark cleared; `changed` says whether a mark existed.
    /// A failing audit insert rolls the *clear* back too: the mark can never
    /// be cleared without its record.
    pub fn complete_trust_request(
        &self,
        workspace: &str,
        request_id: &str,
        max_attempts: i64,
        by: &str,
    ) -> Result<Option<bool>, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let consumed = tx.execute(
            "DELETE FROM trust_requests
              WHERE workspace = ?1 AND request_id = ?2 AND attempts < ?3",
            rusqlite::params![workspace, request_id, max_attempts],
        )?;
        if consumed == 0 {
            drop(tx);
            return Ok(None);
        }
        let changed = tx.execute(
            "DELETE FROM workspace_taint WHERE workspace = ?1",
            [workspace],
        )? > 0;
        let payload = serde_json::json!({
            "workspace": workspace,
            "changed": changed,
            "request_id": request_id,
            "by": by,
        })
        .to_string();
        tx.execute(
            "INSERT INTO events(kind, payload) VALUES ('workspace.trusted', ?1)",
            [payload],
        )?;
        tx.commit()?;
        Ok(Some(changed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn workspace_and_session_taint_round_trip_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let session_id;
        {
            let store = Store::open(&path).unwrap();
            session_id = store.create_session("main", None).unwrap().id;
            store
                .mark_session_tainted(session_id, "shell", Some("curl http://x"))
                .unwrap();
            // The first source is kept.
            store
                .mark_session_tainted(session_id, "http_fetch", None)
                .unwrap();
            store.mark_workspace_tainted("/ws/axis", "shell").unwrap();
            // The latest source wins.
            store
                .mark_workspace_tainted("/ws/axis", "http_fetch: https://a.example")
                .unwrap();
            assert_eq!(store.workspace_taint("/ws/main").unwrap(), None);
            // The private-data marker is written before the read and keeps
            // the first source, exactly like taint.
            store
                .mark_session_private_data(session_id, "notes_read")
                .unwrap();
            store
                .mark_session_private_data(session_id, "mail_read")
                .unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.workspace_taint("/ws/axis").unwrap().as_deref(),
            Some("http_fetch: https://a.example")
        );
        assert_eq!(store.workspace_taint("/ws/nobody").unwrap(), None);
        assert_eq!(
            store.session_taint(session_id).unwrap(),
            Some(SessionTaint {
                tool: "shell".to_string(),
                detail: Some("curl http://x".to_string()),
            })
        );
        assert!(store.session_taint(999).unwrap().is_none());

        // The private-data marker survives the reopen, so a later turn of
        // the same session still raises the ask rule on an unseen host.
        assert_eq!(
            store.session_private_data(session_id).unwrap().as_deref(),
            Some("notes_read"),
            "the first tool that read private data is kept"
        );
        assert!(store.session_private_data(999).unwrap().is_none());

        // Clearing is an owner action: it consumes a pending trust request
        // (there is no bare store call that clears the mark any more).
        store
            .put_trust_request("/ws/axis", &new_trust_request("req-1", 0, 0), 0, 0, "test")
            .unwrap();
        assert_eq!(
            store
                .complete_trust_request("/ws/axis", "req-1", 3, "test")
                .unwrap(),
            Some(true)
        );
        assert_eq!(store.workspace_taint("/ws/axis").unwrap(), None);
    }

    #[test]
    fn deleting_a_session_cascades_to_its_taint_mark() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();
        store
            .mark_session_tainted(session.id, "shell", None)
            .unwrap();
        assert!(store.session_taint(session.id).unwrap().is_some());

        assert!(store.delete_session(session.id).unwrap());
        assert!(store.session_taint(session.id).unwrap().is_none());
    }

    #[test]
    fn trust_requests_are_rate_limited_and_refresh_after_the_cooldown() {
        let store = Store::open_in_memory().unwrap();
        let first = store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-1", 7, 1),
                1_000,
                30,
                "owner-cli",
            )
            .unwrap();
        assert_eq!(first, PutTrustOutcome::Stored);
        assert_eq!(store.event_count("workspace.trust_requested").unwrap(), 1);

        // Inside the cooldown nothing is written and nothing is audited.
        let limited = store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-2", 7, 2),
                1_010,
                30,
                "owner-cli",
            )
            .unwrap();
        assert_eq!(
            limited,
            PutTrustOutcome::RateLimited {
                retry_after_secs: 20
            }
        );
        assert_eq!(
            store.trust_request("/ws/main").unwrap().unwrap().request_id,
            "req-1"
        );
        assert_eq!(store.event_count("workspace.trust_requested").unwrap(), 1);

        // After the cooldown the request is replaced (hash, salt, attempts).
        let refreshed = store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-2", 7, 2),
                1_031,
                30,
                "owner-api",
            )
            .unwrap();
        assert_eq!(refreshed, PutTrustOutcome::Stored);
        let pending = store.trust_request("/ws/main").unwrap().unwrap();
        assert_eq!(pending.request_id, "req-2");
        assert_eq!(pending.salt, vec![2u8; 16]);
        assert_eq!(pending.attempts, 0);
        assert_eq!(store.event_count("workspace.trust_requested").unwrap(), 2);
    }

    #[test]
    fn trust_completion_consumes_the_request_clears_the_mark_and_audits_atomically() {
        let store = Store::open_in_memory().unwrap();
        store.mark_workspace_tainted("/ws/main", "shell").unwrap();
        store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-1", 9, 3),
                1_000,
                30,
                "owner-cli",
            )
            .unwrap();

        // One wrong code counts an attempt and audits the failure.
        let attempts = store
            .bump_trust_attempts("/ws/main", "req-1", 3, "owner-cli")
            .unwrap();
        assert_eq!(attempts, Some(1));
        assert_eq!(store.event_count("workspace.trust_failed").unwrap(), 1);
        assert!(store.workspace_taint("/ws/main").unwrap().is_some());

        // Completion consumes the request and clears the mark in one step.
        let changed = store
            .complete_trust_request("/ws/main", "req-1", 3, "owner-cli")
            .unwrap();
        assert_eq!(changed, Some(true));
        assert!(store.trust_request("/ws/main").unwrap().is_none());
        assert!(store.workspace_taint("/ws/main").unwrap().is_none());
        assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);

        // Replay: the request is gone, and a stale request id is refused.
        assert_eq!(
            store
                .complete_trust_request("/ws/main", "req-1", 3, "owner-cli")
                .unwrap(),
            None
        );
        assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);
    }

    #[test]
    fn trust_attempt_cap_spends_the_request_but_keeps_the_cooldown() {
        // The cap used to DELETE the
        // request row, which was also the only record of the cooldown, so
        // three wrong codes bought unlimited notifications and guesses. The
        // spent row now stays as the rate-limit watermark.
        let store = Store::open_in_memory().unwrap();
        store.mark_workspace_tainted("/ws/main", "shell").unwrap();
        store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-1", 9, 3),
                1_000,
                30,
                "owner-cli",
            )
            .unwrap();

        for expected in 1..=3 {
            let attempts = store
                .bump_trust_attempts("/ws/main", "req-1", 3, "owner-cli")
                .unwrap();
            assert_eq!(attempts, Some(expected));
        }
        let spent = store
            .trust_request("/ws/main")
            .unwrap()
            .expect("the cooldown watermark must survive the cap");
        assert_eq!(spent.attempts, 3);
        assert_eq!(store.event_count("workspace.trust_failed").unwrap(), 3);
        // Even the right request id cannot complete an exhausted request.
        assert_eq!(
            store
                .complete_trust_request("/ws/main", "req-1", 3, "owner-cli")
                .unwrap(),
            None
        );
        assert!(store.workspace_taint("/ws/main").unwrap().is_some());

        // Inside the cooldown, a fresh request is refused and nothing is
        // screened on the owner's screen.
        let limited = store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-2", 9, 3),
                1_010,
                30,
                "owner-cli",
            )
            .unwrap();
        assert_eq!(
            limited,
            PutTrustOutcome::RateLimited {
                retry_after_secs: 20
            }
        );
        assert_eq!(store.event_count("workspace.trust_requested").unwrap(), 1);
        assert_eq!(
            store.trust_request("/ws/main").unwrap().unwrap().request_id,
            "req-1"
        );

        // After the cooldown a fresh request replaces the spent row.
        let refreshed = store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-2", 9, 3),
                1_031,
                30,
                "owner-cli",
            )
            .unwrap();
        assert_eq!(refreshed, PutTrustOutcome::Stored);
        let pending = store.trust_request("/ws/main").unwrap().unwrap();
        assert_eq!(pending.request_id, "req-2");
        assert_eq!(pending.attempts, 0);
    }

    #[test]
    fn trust_audit_failure_rolls_the_clear_back() {
        // The old owner action cleared the
        // mark first and only then tried to write the audit row, so a failing
        // audit insert left the workspace cleared with no record. Completion
        // is one transaction: if the audit cannot be written, nothing is.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        store.mark_workspace_tainted("/ws/main", "shell").unwrap();
        store
            .put_trust_request(
                "/ws/main",
                &new_trust_request("req-1", 9, 3),
                1_000,
                30,
                "owner-cli",
            )
            .unwrap();
        let trigger = open_keyed(&path).unwrap();
        trigger
            .execute_batch(
                "CREATE TRIGGER block_trusted BEFORE INSERT ON events
                 WHEN NEW.kind = 'workspace.trusted'
                 BEGIN SELECT RAISE(ABORT, 'audit is read-only'); END;",
            )
            .unwrap();

        assert!(store
            .complete_trust_request("/ws/main", "req-1", 3, "owner-cli")
            .is_err());
        assert!(
            store.workspace_taint("/ws/main").unwrap().is_some(),
            "a failed audit must not leave the mark cleared"
        );
        assert!(
            store.trust_request("/ws/main").unwrap().is_some(),
            "a failed completion must not consume the request"
        );
        assert_eq!(store.event_count("workspace.trusted").unwrap(), 0);
    }

    /// A verifier half for a pending trust request, for store tests.
    fn new_trust_request(request_id: &str, hash: u8, salt: u8) -> NewTrustRequest {
        NewTrustRequest {
            request_id: request_id.to_string(),
            code_hash: vec![hash; 32],
            salt: vec![salt; 16],
        }
    }
}
