//! Chat sessions and the messages inside them.
//!
//! A session is one conversation with one agent; its messages are the
//! turns of that conversation, kept in the order they were written.

use super::*;

/// SQL predicate: the session aliased `alias` never ran a Private turn
/// (CONV-PRIVATE-MIX): the sticky `ever_private` mark is clear.
///
/// **The one helper every read path uses**, so no path can drift. The mark is
/// written the moment a Private turn starts on that session and is never
/// cleared, so a chat that was ever Private is never listed, reopened, read
/// back or in the activity.
///
/// The readers open the store read-only, without migrating it, so a store
/// that has no `ever_private` column yet proves nothing: the predicate
/// excludes every session (fail closed) until the store is migrated.
pub fn not_ever_private_session(conn: &Connection, alias: &str) -> rusqlite::Result<String> {
    let has_flag: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'ever_private'",
        [],
        |row| row.get(0),
    )?;
    Ok(if has_flag > 0 {
        format!("COALESCE({alias}.ever_private, 0) = 0")
    } else {
        "0 = 1".to_string()
    })
}

impl Store {
    /// Create a session for `agent` and return the stored row.
    ///
    /// `title` is optional; pass `None` for an untitled session. The session
    /// is a `chat` session (see [`Self::create_session_of_kind`]).
    pub fn create_session(&self, agent: &str, title: Option<&str>) -> Result<Session, StoreError> {
        self.create_session_of_kind(agent, title, "chat")
    }

    /// Create a session of `kind`: `chat` for conversations, `job` for a
    /// scheduled-run transcript. A job transcript is its own session, durably
    /// marked `job`: only `chat` sessions can become an agent's current
    /// thread, so a job run never hijacks the chat.
    pub fn create_session_of_kind(
        &self,
        agent: &str,
        title: Option<&str>,
        kind: &str,
    ) -> Result<Session, StoreError> {
        // The title is derived from the owner's first message, so it gets the
        // kernel's full detector before it is stored: an e-mail, IBAN or card
        // typed as a first line is never a durable title.
        let title = title.map(kernel_broker::scrub_title);
        self.conn.execute(
            "INSERT INTO sessions(agent, title, kind) VALUES (?1, ?2, ?3)",
            rusqlite::params![agent, title.as_deref(), kind],
        )?;
        self.session_row(self.conn.last_insert_rowid())
    }

    /// The session `agent`'s last `/new` started ([`META_CHAT_NEW_PREFIX`]), if any.
    pub fn chat_new_session(&self, agent: &str) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
                [format!("{META_CHAT_NEW_PREFIX}{agent}")],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Start a fresh `chat` session for `agent` and mark it current; older ones are kept.
    /// A marked session with no message yet is reused, so `/new` twice adds one row.
    pub fn start_chat_session(&self, agent: &str) -> Result<Session, StoreError> {
        if let Some(id) = self.chat_new_session(agent)? {
            if self.session(id)?.is_some() && self.list_messages(id)?.is_empty() {
                return self.session_row(id);
            }
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO sessions(agent, title, kind) VALUES (?1, NULL, 'chat')",
            [agent],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![format!("{META_CHAT_NEW_PREFIX}{agent}"), id.to_string()],
        )?;
        tx.commit()?;
        self.session_row(id)
    }

    /// Make an existing `chat` session of `agent` its current one, the same durable mark `/new`
    /// writes. `None` (nothing changed) when the session is unknown, another agent's, a job, or a
    /// chat that ran in Private mode (CONV-PRIVATE-MIX: it cannot be reopened).
    pub fn select_chat_session(
        &self,
        agent: &str,
        session_id: i64,
    ) -> Result<Option<Session>, StoreError> {
        let Some(session) = self.session(session_id)? else {
            return Ok(None);
        };
        if session.agent != agent || self.session_kind(session_id)?.as_deref() != Some("chat") {
            return Ok(None);
        }
        // CONV-PRIVATE-MIX: a chat that ran in Private mode is never made
        // current again — its rows are the gated copy the provider saw.
        let open = not_ever_private_session(&self.conn, "sessions")?;
        let readable: i64 = self.conn.query_row(
            &format!("SELECT COUNT(*) FROM sessions WHERE id = ?1 AND {open}"),
            [session_id],
            |row| row.get(0),
        )?;
        if readable == 0 {
            return Ok(None);
        }
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![
                format!("{META_CHAT_NEW_PREFIX}{agent}"),
                session_id.to_string()
            ],
        )?;
        Ok(Some(session))
    }

    /// Kind of a session (`chat`, `job`, …), or `None` when the id is
    /// unknown.
    pub fn session_kind(&self, id: i64) -> Result<Option<String>, StoreError> {
        let kind = self
            .conn
            .query_row("SELECT kind FROM sessions WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(kind)
    }

    /// Mark `session_id` as a chat that ran in Private mode (CONV-PRIVATE-MIX).
    ///
    /// The mark is **sticky**: it is set the moment a Private turn starts and
    /// is never cleared, so a chat that was ever private stays private for the
    /// reader whatever the mode does later. `true` when this call set it.
    pub fn mark_session_ever_private(&self, session_id: i64) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE sessions SET ever_private = 1 WHERE id = ?1 AND ever_private = 0",
            [session_id],
        )?;
        Ok(changed > 0)
    }

    /// True when `session_id` ever ran a Private turn; a missing session reads
    /// as private (fail closed), so a caller never writes an unmarked thread.
    pub fn session_ever_private(&self, session_id: i64) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT COALESCE(ever_private, 0) FROM sessions WHERE id = ?1",
                [session_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(1)
            != 0)
    }

    /// List sessions ordered by most recent activity first (newest id breaks
    /// ties between rows touched within the same second).
    pub fn list_sessions(&self) -> Result<Vec<Session>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent, title, created_at, updated_at
             FROM sessions
             ORDER BY updated_at DESC, id DESC",
        )?;
        let rows = stmt.query_map([], row_to_session)?;
        let sessions = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(sessions)
    }

    /// Return the agent's durable current chat session, including an empty
    /// session explicitly started with `/new`. Daemon restarts must continue
    /// this session instead of creating a new transcript for the same chat.
    pub fn current_chat_session(&self, agent: &str) -> Result<Option<Session>, StoreError> {
        let marked_key = format!("{META_CHAT_NEW_PREFIX}{agent}");
        let session = self
            .conn
            .query_row(
                "SELECT s.id, s.agent, s.title, s.created_at, s.updated_at
             FROM sessions s
             WHERE s.agent = ?1 AND s.kind = 'chat'
               AND (EXISTS (SELECT 1 FROM messages m WHERE m.session_id = s.id)
                    OR s.id = (SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?2))
               AND (s.id > COALESCE((SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?3), 0)
                    OR NOT EXISTS (SELECT 1 FROM jobs j
                                   WHERE j.agent = s.agent
                                     AND s.title = 'job ' || j.name))
             ORDER BY (s.id = (SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?2)) DESC,
                      s.updated_at DESC, s.id DESC
             LIMIT 1",
                rusqlite::params![agent, marked_key, META_SESSION_LEGACY_MAX_ID],
                row_to_session,
            )
            .optional()?;
        Ok(session)
    }

    /// Append a message to a session and return the stored row.
    ///
    /// Fails with a `Sqlite` error when `session_id` does not exist. The
    /// insert and the session's `updated_at` bump commit atomically.
    pub fn append_message(
        &self,
        session_id: i64,
        role: &str,
        content: &str,
        meta: Option<&str>,
    ) -> Result<Message, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO messages(session_id, role, content, meta) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![session_id, role, content, meta],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE sessions SET updated_at = datetime('now') WHERE id = ?1",
            [session_id],
        )?;
        tx.commit()?;
        self.message(id)
    }

    /// Append one morning brief to the newest chat session for `agent`, once
    /// per local day. The marker lives in message metadata, so this uses the
    /// existing schema. An IMMEDIATE transaction makes the check-and-insert
    /// safe across daemon restarts and concurrent manual triggers.
    ///
    /// `parts` is the brief's structured form (events, mail, notes) kept in
    /// the same metadata so `GET /v1/brief/today` can answer without parsing
    /// the text.
    ///
    /// Returns `None` when a brief for `day` already exists in any chat
    /// session for the agent.
    pub fn append_daily_brief_once(
        &self,
        agent: &str,
        day: &str,
        content: &str,
        parts: &serde_json::Value,
    ) -> Result<Option<Message>, StoreError> {
        let marker = serde_json::json!({
            "brief_day": day,
            "source": "morning-brief",
            "brief": parts
        })
        .to_string();
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        // Every json_extract sits behind json_valid: a row with malformed or
        // NULL metadata is skipped, never an error for the whole write.
        let existing: Option<i64> = tx
            .query_row(
                "SELECT m.id FROM messages m
                 JOIN sessions s ON s.id = m.session_id
                 WHERE s.agent = ?1 AND s.kind = 'chat' AND m.role = 'assistant'
                   AND CASE WHEN json_valid(m.meta) THEN json_extract(m.meta, '$.brief_day') END = ?2
                   AND CASE WHEN json_valid(m.meta) THEN json_extract(m.meta, '$.source') END = 'morning-brief'
                 LIMIT 1",
                rusqlite::params![agent, day],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            drop(tx);
            return Ok(None);
        }
        let session_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM sessions WHERE agent = ?1 AND kind = 'chat'
                 ORDER BY updated_at DESC, id DESC LIMIT 1",
                [agent],
                |row| row.get(0),
            )
            .optional()?;
        let session_id = match session_id {
            Some(id) => id,
            None => {
                tx.execute(
                    "INSERT INTO sessions(agent, title, kind) VALUES (?1, ?1, 'chat')",
                    [agent],
                )?;
                tx.last_insert_rowid()
            }
        };
        tx.execute(
            "INSERT INTO messages(session_id, role, content, meta) VALUES (?1, 'assistant', ?2, ?3)",
            rusqlite::params![session_id, content, marker],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE sessions SET updated_at = datetime('now') WHERE id = ?1",
            [session_id],
        )?;
        tx.commit()?;
        self.message(id).map(Some)
    }

    /// The newest morning brief stored for `day`, if any, with its metadata.
    pub fn daily_brief(&self, agent: &str, day: &str) -> Result<Option<Message>, StoreError> {
        let id: Option<i64> = self
            .conn
            .query_row(
                "SELECT m.id FROM messages m
                 JOIN sessions s ON s.id = m.session_id
                 WHERE s.agent = ?1 AND s.kind = 'chat' AND m.role = 'assistant'
                   AND CASE WHEN json_valid(m.meta) THEN json_extract(m.meta, '$.brief_day') END = ?2
                   AND CASE WHEN json_valid(m.meta) THEN json_extract(m.meta, '$.source') END = 'morning-brief'
                 ORDER BY m.id DESC LIMIT 1",
                rusqlite::params![agent, day],
                |row| row.get(0),
            )
            .optional()?;
        id.map(|id| self.message(id)).transpose()
    }

    /// Append several messages to a session **atomically** and return the
    /// stored rows in insertion order.
    ///
    /// Used to close a tool batch the turn will never answer: either
    /// every synthetic tool result is written, or none is — a partial repair
    /// would still leave the assistant `tool_calls` row dangling.
    pub fn append_messages_atomic(
        &self,
        session_id: i64,
        messages: &[(&str, &str, Option<&str>)],
    ) -> Result<Vec<Message>, StoreError> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        let tx = self.conn.unchecked_transaction()?;
        let mut ids = Vec::with_capacity(messages.len());
        for (role, content, meta) in messages {
            tx.execute(
                "INSERT INTO messages(session_id, role, content, meta) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![session_id, role, content, meta],
            )?;
            ids.push(tx.last_insert_rowid());
        }
        tx.execute(
            "UPDATE sessions SET updated_at = datetime('now') WHERE id = ?1",
            [session_id],
        )?;
        tx.commit()?;
        ids.into_iter().map(|id| self.message(id)).collect()
    }

    /// List messages of a session in insertion order.
    ///
    /// Unknown sessions yield an empty list.
    pub fn list_messages(&self, session_id: i64) -> Result<Vec<Message>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, role, content, created_at, meta
             FROM messages
             WHERE session_id = ?1
             ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([session_id], row_to_message)?;
        let messages = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
    }

    /// Newest `limit` messages with `id < before` (all when `before` is
    /// `None`), returned in ascending conversation order, plus whether older
    /// rows exist.
    ///
    /// The bounded read behind the engine's context window (E-13): a resumed
    /// session no longer loads its whole history.
    pub fn list_messages_limited(
        &self,
        session_id: i64,
        before: Option<i64>,
        limit: usize,
    ) -> Result<(Vec<Message>, bool), StoreError> {
        let limit = limit.max(1);
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, role, content, created_at, meta
             FROM messages
             WHERE session_id = ?1 AND (?2 IS NULL OR id < ?2)
             ORDER BY id DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![session_id, before, (limit + 1) as i64],
            row_to_message,
        )?;
        let mut messages = rows.collect::<Result<Vec<_>, _>>()?;
        let has_more = messages.len() > limit;
        if has_more {
            messages.truncate(limit);
        }
        messages.reverse();
        Ok((messages, has_more))
    }

    /// The session's system-prompt row, if it has one.
    ///
    /// Loaded separately from the context window so a long session keeps its
    /// prompt even when the window starts after it (E-13).
    pub fn session_system_message(&self, session_id: i64) -> Result<Option<Message>, StoreError> {
        self.conn
            .query_row(
                "SELECT id, session_id, role, content, created_at, meta
                 FROM messages
                 WHERE session_id = ?1 AND role = 'system'
                 ORDER BY id ASC
                 LIMIT 1",
                [session_id],
                row_to_message,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Every `tool` row of a session, oldest first, **without content**.
    ///
    /// Taint reconstruction only reads `meta` (E-13): bounding the context
    /// window must never let an old untrusted tool call be laundered out of
    /// the taint state. `content` is empty by construction.
    pub fn list_tool_rows(&self, session_id: i64) -> Result<Vec<Message>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, role, '', created_at, meta
             FROM messages
             WHERE session_id = ?1 AND role = 'tool'
             ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([session_id], row_to_message)?;
        let messages = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(messages)
    }

    /// Delete a session and — via `ON DELETE CASCADE` — all of its messages.
    ///
    /// Returns `true` when a session was deleted and `false` when `session_id`
    /// did not exist, so callers can tell a missing session apart from an
    /// empty one. Deleting the same session twice is safe.
    /// The agents' threads it delegated to go with it (AGENT-HISTORY-BLEED).
    pub fn delete_session(&self, session_id: i64) -> Result<bool, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM sessions WHERE id IN (SELECT session_id FROM channel_sessions
              WHERE channel = ?1 AND chat_key LIKE ?2)",
            rusqlite::params![DELEGATE_CHANNEL, format!("{session_id}:%")],
        )?;
        let deleted = tx.execute("DELETE FROM sessions WHERE id = ?1", [session_id])?;
        tx.commit()?;
        Ok(deleted > 0)
    }

    /// The thread `agent` works in for the chief thread `parent`
    /// (AGENT-HISTORY-BLEED): the same chief thread continues it, any other
    /// starts it fresh. With no chief thread (a resumed task) the agent always
    /// starts fresh, so an unbound thread never bleeds into another.
    pub fn delegate_session(&self, parent: Option<i64>, agent: &str) -> Result<i64, StoreError> {
        let Some(parent) = parent else {
            return Ok(self.create_session(agent, None)?.id);
        };
        let key = format!("{parent}:{agent}");
        if let Some(id) = self.channel_session(DELEGATE_CHANNEL, &key)? {
            return Ok(id);
        }
        let created = self.create_session(agent, None)?.id;
        let effective = self.bind_channel_session(DELEGATE_CHANNEL, &key, created)?;
        if effective != created {
            self.delete_session(created)?;
        }
        Ok(effective)
    }

    /// Keep `pairs` in `session_id`'s token table. The first value seen for a
    /// token is kept, and a session holds at most [`MAX_SESSION_TOKENS`].
    /// Returns how many new pairs the cap left out.
    pub fn record_session_tokens(
        &self,
        session_id: i64,
        pairs: &[(String, String)],
    ) -> Result<usize, StoreError> {
        if pairs.is_empty() {
            return Ok(0);
        }
        // FLAKY-PROBE-1: the write lock is taken first. A deferred transaction
        // reads, then upgrades; a commit by another connection in between
        // (the chief's while a delegated turn runs) fails the upgrade with
        // SQLITE_BUSY at once, past the busy timeout.
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let mut dropped = 0usize;
        for (token, value) in pairs {
            // TODO(PRIVATE-TRANSCRIPT P3a): past the cap the newest pair is not
            // stored, while the in-memory display table drops the oldest; after
            // a restart such a token shows the marker. Nothing leaks either way.
            let known: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM session_tokens WHERE session_id = ?1 AND token = ?2)",
                rusqlite::params![session_id, token],
                |row| row.get(0),
            )?;
            let added = tx.execute(
                "INSERT INTO session_tokens(session_id, token, value)
                 SELECT ?1, ?2, ?3
                 WHERE (SELECT COUNT(*) FROM session_tokens WHERE session_id = ?1) < ?4
                 ON CONFLICT(session_id, token) DO NOTHING",
                rusqlite::params![session_id, token, value, MAX_SESSION_TOKENS],
            )?;
            if added == 0 && !known {
                dropped += 1;
            }
        }
        tx.commit()?;
        Ok(dropped)
    }

    /// Every `(token, value)` pair of `session_id`'s token table. Values are the
    /// owner's data: never log them.
    pub fn session_tokens(&self, session_id: i64) -> Result<Vec<(String, String)>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT token, value FROM session_tokens WHERE session_id = ?1")?;
        let pairs = statement
            .query_map([session_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<(String, String)>, _>>()?;
        Ok(pairs)
    }

    /// Fetch one session by id.
    fn session_row(&self, id: i64) -> Result<Session, StoreError> {
        let session = self.conn.query_row(
            "SELECT id, agent, title, created_at, updated_at FROM sessions WHERE id = ?1",
            [id],
            row_to_session,
        )?;
        Ok(session)
    }

    /// Fetch one session by id; `None` when the id does not exist.
    pub fn session(&self, id: i64) -> Result<Option<Session>, StoreError> {
        self.conn
            .query_row(
                "SELECT id, agent, title, created_at, updated_at FROM sessions WHERE id = ?1",
                [id],
                row_to_session,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Fetch one message by id.
    fn message(&self, id: i64) -> Result<Message, StoreError> {
        let message = self.conn.query_row(
            "SELECT id, session_id, role, content, created_at, meta FROM messages WHERE id = ?1",
            [id],
            row_to_message,
        )?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn daily_brief_guard_skips_malformed_and_null_metadata() {
        let store = Store::open_in_memory().unwrap();
        let chat = store.create_session("aux", Some("Aux")).unwrap();
        // Unrelated assistant rows whose metadata is not JSON, or is NULL,
        // sit in front of the brief and must not make json_extract raise.
        store
            .append_message(chat.id, "assistant", "old reply", Some("not json"))
            .unwrap();
        store
            .append_message(chat.id, "assistant", "old reply", None)
            .unwrap();

        let parts = serde_json::json!({ "events": [] });
        let brief = store
            .append_daily_brief_once("aux", "2026-10-13", "Brief", &parts)
            .unwrap();
        assert!(brief.is_some(), "the brief lands past malformed rows");

        // A malformed row written after the brief must not hide it on read.
        store
            .append_message(chat.id, "assistant", "later reply", Some("{broken"))
            .unwrap();

        assert!(
            store
                .append_daily_brief_once("aux", "2026-10-13", "Brief again", &parts)
                .unwrap()
                .is_none(),
            "a second write for the same day stays idempotent"
        );
        let read = store
            .daily_brief("aux", "2026-10-13")
            .unwrap()
            .expect("the Today read returns the brief");
        assert_eq!(read.content, "Brief");
        assert!(store.daily_brief("aux", "2026-10-14").unwrap().is_none());
    }

    #[test]
    fn daily_brief_with_only_malformed_rows_reads_none() {
        let store = Store::open_in_memory().unwrap();
        let chat = store.create_session("aux", None).unwrap();
        store
            .append_message(chat.id, "assistant", "x", Some("{broken"))
            .unwrap();
        store
            .append_message(chat.id, "assistant", "y", None)
            .unwrap();

        assert!(store.daily_brief("aux", "2026-10-13").unwrap().is_none());
        let parts = serde_json::json!({});
        assert!(store
            .append_daily_brief_once("aux", "2026-10-13", "Brief", &parts)
            .unwrap()
            .is_some());
    }

    // ---- sessions ----

    #[test]
    fn create_session_round_trips_its_fields() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("axis", Some("morning chat")).unwrap();

        assert!(session.id > 0);
        assert_eq!(session.agent, "axis");
        assert_eq!(session.title.as_deref(), Some("morning chat"));
        assert!(!session.created_at.is_empty());
        assert!(!session.updated_at.is_empty());
        assert_eq!(store.list_sessions().unwrap(), vec![session]);
    }

    #[test]
    fn session_title_is_optional() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();
        assert_eq!(session.title, None);
    }

    #[test]
    fn sessions_record_their_kind() {
        let store = Store::open_in_memory().unwrap();
        let chat = store.create_session("main", Some("hello")).unwrap();
        let job = store
            .create_session_of_kind("main", Some("job morning"), "job")
            .unwrap();

        assert_eq!(
            store.session_kind(chat.id).unwrap().as_deref(),
            Some("chat")
        );
        assert_eq!(store.session_kind(job.id).unwrap().as_deref(), Some("job"));
        assert_eq!(store.session_kind(4242).unwrap(), None);
    }

    #[test]
    fn a_fresh_store_has_no_legacy_sessions() {
        let store = Store::open_in_memory().unwrap();
        let watermark: String = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'sessions_kind_legacy_max_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(watermark, "0", "every fresh session is explicit");
    }

    #[test]
    fn list_sessions_orders_most_recently_active_first() {
        let store = Store::open_in_memory().unwrap();
        let older = store.create_session("main", Some("older")).unwrap();
        let newer = store.create_session("main", Some("newer")).unwrap();

        // Both rows are created within the same second: pin deterministic
        // timestamps so the ordering assertion cannot flake.
        store
            .conn
            .execute(
                "UPDATE sessions SET updated_at = '2000-01-01 08:00:00' WHERE id = ?1",
                [older.id],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE sessions SET updated_at = '2000-01-01 09:00:00' WHERE id = ?1",
                [newer.id],
            )
            .unwrap();
        assert_eq!(session_ids(&store), vec![newer.id, older.id]);

        // Activity on the older session moves it to the top.
        store
            .append_message(older.id, "user", "wake", None)
            .unwrap();
        assert_eq!(session_ids(&store), vec![older.id, newer.id]);
    }

    #[test]
    fn session_lookup_returns_none_for_unknown_ids() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", Some("hello")).unwrap();
        assert_eq!(store.session(session.id).unwrap(), Some(session));
        assert_eq!(store.session(4242).unwrap(), None);
    }

    #[test]
    fn appending_a_message_bumps_updated_at() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();
        store
            .conn
            .execute(
                "UPDATE sessions SET updated_at = '2000-01-01 00:00:00' WHERE id = ?1",
                [session.id],
            )
            .unwrap();

        store
            .append_message(session.id, "user", "ping", None)
            .unwrap();

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_ne!(sessions[0].updated_at, "2000-01-01 00:00:00");
    }

    // ---- messages ----

    #[test]
    fn messages_are_listed_in_insertion_order() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();

        let system = store
            .append_message(session.id, "system", "soul", Some(r#"{"v":1}"#))
            .unwrap();
        let user = store
            .append_message(session.id, "user", "hello", None)
            .unwrap();
        let assistant = store
            .append_message(session.id, "assistant", "hi!", None)
            .unwrap();

        let messages = store.list_messages(session.id).unwrap();
        assert_eq!(messages, vec![system, user, assistant]);
        assert!(messages[0].id < messages[1].id && messages[1].id < messages[2].id);
        assert_eq!(messages[0].role, "system");
        assert_eq!(messages[0].meta.as_deref(), Some(r#"{"v":1}"#));
        assert_eq!(messages[1].meta, None);
        assert!(messages.iter().all(|m| m.session_id == session.id));
        assert!(messages.iter().all(|m| !m.created_at.is_empty()));
    }

    #[test]
    fn message_order_follows_insertion_not_timestamps() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();
        let first = store
            .append_message(session.id, "user", "first", None)
            .unwrap();
        let second = store
            .append_message(session.id, "user", "second", None)
            .unwrap();

        // Invert the timestamps: ordering must still follow row ids, so
        // messages never jump around when two rows share a second.
        store
            .conn
            .execute(
                "UPDATE messages SET created_at = '2030-01-01 00:00:00' WHERE id = ?1",
                [first.id],
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE messages SET created_at = '2020-01-01 00:00:00' WHERE id = ?1",
                [second.id],
            )
            .unwrap();

        let messages = store.list_messages(session.id).unwrap();
        assert_eq!(messages[0].id, first.id);
        assert_eq!(messages[1].id, second.id);
    }

    #[test]
    fn messages_are_scoped_to_their_session() {
        let store = Store::open_in_memory().unwrap();
        let first = store.create_session("main", None).unwrap();
        let second = store.create_session("main", None).unwrap();

        let first_a = store.append_message(first.id, "user", "a", None).unwrap();
        let second_a = store.append_message(second.id, "user", "b", None).unwrap();
        let first_b = store.append_message(first.id, "user", "c", None).unwrap();

        assert_ne!(first_b.id, second_a.id);
        assert_eq!(
            store.list_messages(first.id).unwrap(),
            vec![first_a, first_b]
        );
        assert_eq!(store.list_messages(second.id).unwrap().len(), 1);
    }

    #[test]
    fn bounded_message_page_returns_the_newest_rows_oldest_first() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();
        for index in 0..10 {
            store
                .append_message(session.id, "user", &format!("m{index}"), None)
                .unwrap();
        }

        // The newest three, in ascending conversation order.
        let (page, has_more) = store.list_messages_limited(session.id, None, 3).unwrap();
        assert!(has_more, "older rows exist");
        let contents: Vec<&str> = page.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(contents, vec!["m7", "m8", "m9"]);

        // Cursor: everything strictly before the oldest id of that page.
        let before = page.first().unwrap().id;
        let (page, has_more) = store
            .list_messages_limited(session.id, Some(before), 3)
            .unwrap();
        let contents: Vec<&str> = page.iter().map(|m| m.content.as_str()).collect();
        assert_eq!(contents, vec!["m4", "m5", "m6"]);
        assert!(has_more);

        // Walking to the head terminates with `has_more == false`.
        let (page, has_more) = store.list_messages_limited(session.id, None, 10).unwrap();
        assert_eq!(page.len(), 10);
        assert!(!has_more);
    }

    #[test]
    fn system_prompt_and_tool_rows_load_without_the_rest_of_the_history() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();
        store
            .append_message(session.id, "system", "be nice", Some("{}"))
            .unwrap();
        store
            .append_message(session.id, "user", "hello", None)
            .unwrap();
        store
            .append_message(
                session.id,
                "tool",
                "SECRET-CONTENT",
                Some(r#"{"tool":"http_fetch","tainted":true}"#),
            )
            .unwrap();

        let system = store.session_system_message(session.id).unwrap().unwrap();
        assert_eq!(system.role, "system");
        assert_eq!(system.content, "be nice");

        let tools = store.list_tool_rows(session.id).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].role, "tool");
        assert_eq!(tools[0].content, "", "tool content is not loaded");
        assert!(tools[0]
            .meta
            .as_deref()
            .unwrap()
            .contains(r#""tainted":true"#));

        // Empty sessions answer empty, not an error.
        let other = store.create_session("main", None).unwrap();
        assert!(store.session_system_message(other.id).unwrap().is_none());
        assert!(store.list_tool_rows(other.id).unwrap().is_empty());
    }

    #[test]
    fn messages_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let (session_id, message_id) = {
            let store = Store::open(&path).unwrap();
            let session = store.create_session("main", Some("persisted")).unwrap();
            let message = store
                .append_message(session.id, "user", "still here", Some(r#"{"k":"v"}"#))
                .unwrap();
            (session.id, message.id)
        };

        let store = Store::open(&path).unwrap();
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, session_id);
        assert_eq!(sessions[0].title.as_deref(), Some("persisted"));

        let messages = store.list_messages(session_id).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, message_id);
        assert_eq!(messages[0].role, "user");
        assert_eq!(messages[0].content, "still here");
        assert_eq!(messages[0].meta.as_deref(), Some(r#"{"k":"v"}"#));
    }

    #[test]
    fn append_to_missing_session_is_rejected() {
        let store = Store::open_in_memory().unwrap();
        let error = store
            .append_message(4242, "user", "orphan", None)
            .unwrap_err();
        assert!(matches!(error, StoreError::Sqlite(_)));
        assert!(store.list_messages(4242).unwrap().is_empty());
    }

    #[test]
    fn delete_session_cascades_to_its_messages_only() {
        let store = Store::open_in_memory().unwrap();
        let doomed = store.create_session("main", Some("doomed")).unwrap();
        let kept = store.create_session("main", Some("kept")).unwrap();
        store
            .append_message(doomed.id, "user", "one", None)
            .unwrap();
        store
            .append_message(doomed.id, "assistant", "two", None)
            .unwrap();
        store
            .append_message(kept.id, "user", "keep me", None)
            .unwrap();

        assert!(store.delete_session(doomed.id).unwrap());
        assert!(store.list_messages(doomed.id).unwrap().is_empty());
        assert_eq!(store.list_messages(kept.id).unwrap().len(), 1);
        assert_eq!(session_ids(&store), vec![kept.id]);

        // The cascade really deleted the rows; no orphans were left behind.
        let remaining: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn a_delegated_thread_is_the_chief_threads_own_and_goes_with_it() {
        let store = Store::open_in_memory().unwrap();
        let a = store.create_session("aux", None).unwrap().id;
        let b = store.create_session("aux", None).unwrap().id;
        let mail_a = store.delegate_session(Some(a), "mail").unwrap();
        assert_eq!(store.delegate_session(Some(a), "mail").unwrap(), mail_a);
        let mail_b = store.delegate_session(Some(b), "mail").unwrap();
        let calendar_a = store.delegate_session(Some(a), "calendar").unwrap();
        assert_ne!(mail_b, mail_a);
        assert_ne!(calendar_a, mail_a);
        // No chief thread: always a fresh one.
        let loose = store.delegate_session(None, "mail").unwrap();
        assert_ne!(loose, mail_a);
        assert_ne!(store.delegate_session(None, "mail").unwrap(), loose);

        // Deleting chief thread A deletes its agents' threads, not B's.
        assert!(store.delete_session(a).unwrap());
        assert!(store.session(mail_a).unwrap().is_none());
        assert!(store.session(calendar_a).unwrap().is_none());
        assert!(store.session(mail_b).unwrap().is_some());
        assert_eq!(store.delegate_session(Some(b), "mail").unwrap(), mail_b);
    }

    #[test]
    fn a_session_token_table_keeps_the_first_value_and_goes_with_its_session() {
        let store = Store::open_in_memory().unwrap();
        let doomed = store.create_session("main", None).unwrap();
        let kept = store.create_session("main", None).unwrap();
        let pair = |t: &str, v: &str| (t.to_string(), v.to_string());
        let first = [pair("EMAIL_AAAAAAAAAAAA", "a@exemple.test")];
        store.record_session_tokens(doomed.id, &first).unwrap();
        let again = [pair("EMAIL_AAAAAAAAAAAA", "b@exemple.test")];
        store.record_session_tokens(doomed.id, &again).unwrap();
        store
            .record_session_tokens(kept.id, &[pair("IBAN_BBBBBBBBBBBB", "FR76…")])
            .unwrap();
        assert_eq!(store.session_tokens(doomed.id).unwrap(), first);

        assert!(store.delete_session(doomed.id).unwrap());
        assert!(store.session_tokens(doomed.id).unwrap().is_empty());
        let remaining: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM session_tokens", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 1, "only the kept session's pair is left");
    }

    #[test]
    fn delete_session_reports_whether_a_row_was_deleted() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();

        assert!(store.delete_session(session.id).unwrap());
        assert!(!store.delete_session(session.id).unwrap());
        assert!(!store.delete_session(999).unwrap());
    }

    #[test]
    fn thousand_messages_stay_fast() {
        let store = Store::open_in_memory().unwrap();
        let session = store.create_session("main", None).unwrap();
        let started = std::time::Instant::now();
        for index in 0..1000 {
            store
                .append_message(session.id, "user", &format!("message {index}"), None)
                .unwrap();
        }
        let messages = store.list_messages(session.id).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(messages.len(), 1000);
        assert!(
            elapsed.as_millis() < 5_000,
            "1000 insert+list took {elapsed:?}"
        );
    }

    /// A first line, its neutral label and the value that must never survive.
    /// Every value is invented.
    const TITLE_PII: [(&str, &str, &str); 7] = [
        (
            "mail lena.ortiz@example.org now",
            "[e-mail]",
            "lena.ortiz@example.org",
        ),
        ("call +44 20 7946 0958", "[phone]", "+44 20 7946 0958"),
        (
            "IBAN FR76 3000 6000 0112 3456 7890 189",
            "[IBAN]",
            "FR76 3000 6000 0112 3456 7890 189",
        ),
        ("card 4111 1111 1111 1111", "[card]", "4111 1111 1111 1111"),
        ("NI QQ 12 34 56 C", "[ID]", "QQ 12 34 56 C"),
        ("type 2 diabetes", "[health]", "diabetes"),
        ("api_key: Fk3jQ9xZ2mP7vB4n", "[secret]", "Fk3jQ9xZ2mP7vB4n"), // gitleaks:allow
    ];

    #[test]
    fn session_titles_are_scrubbed_on_write() {
        let store = Store::open_in_memory().unwrap();
        for (line, label, value) in TITLE_PII {
            let title = store
                .create_session("aux", Some(line))
                .unwrap()
                .title
                .expect("a titled session");
            assert!(title.contains(label), "{line:?} -> {title:?}");
            assert!(!title.contains(value), "{line:?} -> {title:?}");
        }
    }

    #[test]
    fn a_legacy_session_title_is_scrubbed_on_read() {
        let store = Store::open_in_memory().unwrap();
        for (line, label, value) in TITLE_PII {
            let session = store.create_session("aux", Some("draft")).unwrap();
            // A row written before titles were scrubbed, by an old build.
            store
                .conn
                .execute(
                    "UPDATE sessions SET title = ?1 WHERE id = ?2",
                    rusqlite::params![line, session.id],
                )
                .unwrap();
            let title = store
                .session(session.id)
                .unwrap()
                .and_then(|session| session.title)
                .expect("the legacy title");
            assert!(title.contains(label), "{line:?} -> {title:?}");
            assert!(!title.contains(value), "{line:?} -> {title:?}");
        }
    }

    #[test]
    fn a_plain_or_named_first_line_stays_visible() {
        let store = Store::open_in_memory().unwrap();
        for line in ["Plan the week", "Camille Exemple"] {
            let title = store
                .create_session("aux", Some(line))
                .unwrap()
                .title
                .expect("a titled session");
            assert_eq!(title, line);
        }
    }

    /// Ids of `list_sessions`, in returned order.
    fn session_ids(store: &Store) -> Vec<i64> {
        store
            .list_sessions()
            .unwrap()
            .iter()
            .map(|session| session.id)
            .collect()
    }
}
