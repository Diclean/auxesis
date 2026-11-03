//! The channel ledger: the chats the store relays and the turns it sent.
//!
//! A channel session binds one external chat to a session id; the message
//! ledger records the turns that were accepted, so a retry cannot send
//! the same turn twice.

use super::*;

impl Store {
    // ---- channel bindings and message ledger (v11, WA-MSG-0) ----
    //
    // Everything here is keyed by a salted hash (`chat_key`, `message_key`):
    // the store never sees a phone number or message content.

    /// The Auxesis session bound to one external chat, if any.
    pub fn channel_session(
        &self,
        channel: &str,
        chat_key: &str,
    ) -> Result<Option<i64>, StoreError> {
        self.conn
            .query_row(
                "SELECT session_id FROM channel_sessions WHERE channel = ?1 AND chat_key = ?2",
                rusqlite::params![channel, chat_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Bind `chat_key` to `session_id` once and return the **effective**
    /// binding. Two listeners that race (both saw no mapping, both created a
    /// session) end up on the same thread: the loser re-reads the winner's
    /// row and can safely delete its orphan session. The `(channel,
    /// chat_key)` primary key is the UNIQUE constraint that makes this safe.
    pub fn bind_channel_session(
        &self,
        channel: &str,
        chat_key: &str,
        session_id: i64,
    ) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO channel_sessions(channel, chat_key, session_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(channel, chat_key) DO NOTHING",
            rusqlite::params![channel, chat_key, session_id],
        )?;
        self.channel_session(channel, chat_key)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
            .map_err(StoreError::from)
    }

    /// Record an inbound message id as **seen**, before any turn runs.
    ///
    /// Returns `true` for a first sighting and for the single allowed retry
    /// of a message whose turn failed (`channel_message_failed`); `false`
    /// for any other redelivery (dedupe: drop silently).
    pub fn channel_message_seen(
        &self,
        channel: &str,
        message_key: &str,
    ) -> Result<bool, StoreError> {
        let inserted = self.conn.execute(
            "INSERT INTO channel_messages(channel, message_key) VALUES (?1, ?2)
             ON CONFLICT(channel, message_key) DO NOTHING",
            rusqlite::params![channel, message_key],
        )?;
        if inserted == 1 {
            return Ok(true);
        }
        // Redelivery of a failed turn: retry exactly once.
        let retried = self.conn.execute(
            "UPDATE channel_messages SET retries = retries + 1, failed = 0
              WHERE channel = ?1 AND message_key = ?2 AND failed = 1 AND retries < 1",
            rusqlite::params![channel, message_key],
        )?;
        Ok(retried == 1)
    }

    /// Atomically reserve one slot in the rolling rate window **and** mark
    /// this message answered. The count and the write share one
    /// `BEGIN IMMEDIATE` transaction, so two listeners (or two processes)
    /// with distinct message ids cannot both pass the last slot. Returns
    /// `false` when the window is full (nothing is written).
    pub fn channel_try_accept(
        &self,
        channel: &str,
        message_key: &str,
        window_start_unix: i64,
        cap: u32,
    ) -> Result<bool, StoreError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| -> Result<bool, StoreError> {
            let count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM channel_messages
                  WHERE channel = ?1 AND accepted = 1 AND at_unix >= ?2",
                rusqlite::params![channel, window_start_unix],
                |row| row.get(0),
            )?;
            let admitted = count < i64::from(cap);
            if admitted {
                self.conn.execute(
                    "UPDATE channel_messages
                        SET accepted = 1, failed = 0, at_unix = unixepoch()
                      WHERE channel = ?1 AND message_key = ?2",
                    rusqlite::params![channel, message_key],
                )?;
            }
            Ok(admitted)
        })();
        match result {
            Ok(admitted) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(admitted)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    /// Mark a message's turn as failed: release its rate slot and allow one
    /// redelivery retry (the `seen` check admits the next duplicate).
    pub fn channel_message_failed(
        &self,
        channel: &str,
        message_key: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE channel_messages SET accepted = 0, failed = 1
              WHERE channel = ?1 AND message_key = ?2",
            rusqlite::params![channel, message_key],
        )?;
        Ok(())
    }

    /// How many messages were answered at or after `since_unix` (the rate
    /// window count).
    pub fn channel_count_accepted_since(
        &self,
        channel: &str,
        since_unix: i64,
    ) -> Result<i64, StoreError> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM channel_messages
                  WHERE channel = ?1 AND accepted = 1 AND at_unix >= ?2",
                rusqlite::params![channel, since_unix],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    /// Drop ledger rows older than `before_unix`; returns how many.
    pub fn prune_channel_messages(
        &self,
        channel: &str,
        before_unix: i64,
    ) -> Result<usize, StoreError> {
        Ok(self.conn.execute(
            "DELETE FROM channel_messages WHERE channel = ?1 AND at_unix < ?2",
            rusqlite::params![channel, before_unix],
        )?)
    }

    /// Retention for the text channel's threads: for every session bound to
    /// `channel`, drop messages older than `max_age_days` and keep at most
    /// `max_messages` newest rows. Returns how many rows were deleted.
    /// The session rows themselves stay (the binding is the thread's
    /// identity), and the ledger is pruned separately.
    pub fn prune_channel_sessions(
        &self,
        channel: &str,
        max_messages: i64,
        max_age_days: i64,
    ) -> Result<usize, StoreError> {
        let mut deleted = self.conn.execute(
            "DELETE FROM messages
              WHERE created_at < datetime('now', ?1)
                AND session_id IN (SELECT session_id FROM channel_sessions WHERE channel = ?2)",
            rusqlite::params![format!("-{max_age_days} days"), channel],
        )?;
        let session_ids: Vec<i64> = {
            let mut statement = self
                .conn
                .prepare("SELECT session_id FROM channel_sessions WHERE channel = ?1")?;
            let rows = statement.query_map([channel], |row| row.get(0))?;
            rows.collect::<Result<Vec<i64>, _>>()?
        };
        for session_id in session_ids {
            // The id of the `max_messages`-th newest row; when fewer rows
            // exist the subquery is NULL and `id < NULL` deletes nothing.
            deleted += self.conn.execute(
                "DELETE FROM messages
                  WHERE session_id = ?1
                    AND id < (SELECT id FROM messages WHERE session_id = ?1
                               ORDER BY id DESC LIMIT 1 OFFSET ?2)",
                rusqlite::params![session_id, max_messages - 1],
            )?;
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn channel_bindings_and_message_ledger_survive_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let session_id = {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
            let session = store
                .create_session_of_kind("main", Some("wa"), "chat")
                .unwrap();
            assert!(store
                .channel_session("whatsapp_text", "peer#0badcafe")
                .unwrap()
                .is_none());
            assert_eq!(
                store
                    .bind_channel_session("whatsapp_text", "peer#0badcafe", session.id)
                    .unwrap(),
                session.id
            );
            // A second bind (restart / race) never moves the thread: the
            // caller gets the effective binding back, so the loser reuses
            // the winner's session instead of orphaning its own.
            let other = store.create_session("main", None).unwrap();
            assert_eq!(
                store
                    .bind_channel_session("whatsapp_text", "peer#0badcafe", other.id)
                    .unwrap(),
                session.id
            );
            assert_eq!(
                store
                    .channel_session("whatsapp_text", "peer#0badcafe")
                    .unwrap(),
                Some(session.id)
            );
            assert!(store.delete_session(other.id).unwrap(), "orphan removed");

            // First sighting inserts; a redelivery does not.
            assert!(store
                .channel_message_seen("whatsapp_text", "msg#1")
                .unwrap());
            assert!(!store
                .channel_message_seen("whatsapp_text", "msg#1")
                .unwrap());
            assert_eq!(
                store
                    .channel_count_accepted_since("whatsapp_text", 0)
                    .unwrap(),
                0
            );
            assert!(store
                .channel_try_accept("whatsapp_text", "msg#1", 0, 30)
                .unwrap());
            assert_eq!(
                store
                    .channel_count_accepted_since("whatsapp_text", 0)
                    .unwrap(),
                1
            );
            assert_eq!(
                store
                    .channel_count_accepted_since("whatsapp_text", i64::MAX)
                    .unwrap(),
                0
            );
            session.id
        };

        // Reopen: binding and ledger are durable (restart idempotency).
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store
                .channel_session("whatsapp_text", "peer#0badcafe")
                .unwrap(),
            Some(session_id)
        );
        assert!(!store
            .channel_message_seen("whatsapp_text", "msg#1")
            .unwrap());
        assert_eq!(
            store
                .channel_count_accepted_since("whatsapp_text", 0)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .prune_channel_messages("whatsapp_text", i64::MAX)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .channel_count_accepted_since("whatsapp_text", 0)
                .unwrap(),
            0
        );
    }

    /// WA-MSG-0 P2 fix: a failed turn releases its slot and admits exactly
    /// one retry on redelivery.
    #[test]
    fn channel_failed_turn_is_retried_once() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.channel_message_seen("c", "m").unwrap());
        assert!(store.channel_try_accept("c", "m", 0, 1).unwrap());
        store.channel_message_failed("c", "m").unwrap();
        assert_eq!(store.channel_count_accepted_since("c", 0).unwrap(), 0);
        // First redelivery: retried (and its slot is free again).
        assert!(store.channel_message_seen("c", "m").unwrap());
        assert!(store.channel_try_accept("c", "m", 0, 1).unwrap());
        // Second redelivery: dedupe wins, even after another failure.
        store.channel_message_failed("c", "m").unwrap();
        assert!(!store.channel_message_seen("c", "m").unwrap());
    }

    /// WA-MSG-0 P2 fix: the cap is checked and the slot written in one
    /// `BEGIN IMMEDIATE` transaction, so two connections racing for the last
    /// slot admit exactly one.
    #[test]
    fn concurrent_channel_try_accept_admits_exactly_one() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        // Each thread owns its own connection (a `Connection` is Send but not
        // Sync), and a barrier lines them up so both messages exist before
        // the race. Only SQLite's `BEGIN IMMEDIATE` can decide the winner.
        let barrier = std::sync::Barrier::new(2);
        let (a, b) = std::thread::scope(|scope| {
            let one = scope.spawn(|| {
                let store = Store::open(&path).unwrap();
                store.channel_message_seen("c", "m1").unwrap();
                barrier.wait();
                store.channel_try_accept("c", "m1", 0, 1).unwrap()
            });
            let two = scope.spawn(|| {
                let store = Store::open(&path).unwrap();
                store.channel_message_seen("c", "m2").unwrap();
                barrier.wait();
                store.channel_try_accept("c", "m2", 0, 1).unwrap()
            });
            (one.join().unwrap(), two.join().unwrap())
        });
        assert!(a ^ b, "exactly one of the two connections may pass");
        let store = Store::open(&path).unwrap();
        assert_eq!(store.channel_count_accepted_since("c", 0).unwrap(), 1);
    }

    /// WA-MSG-0 P2 fix: retention keeps at most `max_messages` newest rows
    /// per bound thread and drops anything older than the age cap.
    #[test]
    fn channel_retention_prunes_count_and_age() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", Some("wa")).unwrap();
        store
            .bind_channel_session("whatsapp_text", "chat", session.id)
            .unwrap();
        for index in 0..600 {
            store
                .append_message(session.id, "user", &format!("row {index}"), None)
                .unwrap();
        }
        // One old row (beyond the age cap) and one unbound session that must
        // never be touched.
        store
            .conn
            .execute(
                "INSERT INTO messages(session_id, role, content, created_at)
                 VALUES (?1, 'user', 'old', datetime('now', '-40 days'))",
                [session.id],
            )
            .unwrap();
        let other = store.create_session("main", None).unwrap();
        store
            .append_message(other.id, "user", "not a channel", None)
            .unwrap();

        let deleted = store
            .prune_channel_sessions("whatsapp_text", 500, 30)
            .unwrap();
        assert_eq!(deleted, 101, "100 over the cap + 1 over the age");
        assert_eq!(
            store.list_messages(session.id).unwrap().len(),
            500,
            "the newest 500 stay"
        );
        assert_eq!(store.list_messages(other.id).unwrap().len(), 1);
    }
}
