//! The agent memory: facts, episodes, notes and the suggestions for them.
//!
//! A memory item is one thing the agent knows; a suggestion is one the
//! agent proposed, which the owner accepts or rejects before it counts.

use super::*;

impl Store {
    /// Insert one bounded memory item for `agent`, not linked to a party. All
    /// validation and quota checks happen inside the same immediate transaction
    /// as the insert.
    pub fn create_memory_item(
        &self,
        agent: &str,
        item: &NewMemoryItem<'_>,
    ) -> Result<MemoryItem, StoreError> {
        self.insert_memory_item(agent, item, None)
    }

    /// Insert one bounded memory item for `agent` and link it to `party_id`
    /// (`docs/phase1.md` §2). The same validation and quota checks as
    /// [`Store::create_memory_item`], in the same immediate transaction, so a
    /// party-linked item can never be half written.
    pub fn create_memory_item_for_party(
        &self,
        agent: &str,
        item: &NewMemoryItem<'_>,
        party_id: i64,
    ) -> Result<MemoryItem, StoreError> {
        self.insert_memory_item(agent, item, Some(party_id))
    }

    /// The shared body of the two memory inserts: `party_id` is `None` for a
    /// plain item and `Some` for a party-linked one.
    fn insert_memory_item(
        &self,
        agent: &str,
        item: &NewMemoryItem<'_>,
        party_id: Option<i64>,
    ) -> Result<MemoryItem, StoreError> {
        if agent.is_empty() || agent.len() > MEMORY_AGENT_MAX_BYTES {
            return Err(StoreError::MemoryRejected {
                reason: "invalid agent identifier size".into(),
            });
        }
        validate_memory_item(item)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let created = Self::insert_memory_item_tx(&tx, agent, item, party_id)?;
        tx.commit()?;
        Ok(created)
    }

    fn insert_memory_item_tx(
        tx: &Transaction<'_>,
        agent: &str,
        item: &NewMemoryItem<'_>,
        party_id: Option<i64>,
    ) -> Result<MemoryItem, StoreError> {
        validate_memory_item(item)?;
        let content_hash = memory_content_hash(item.title, item.body);
        let (count, bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(
                length(CAST(agent AS BLOB)) + length(CAST(kind AS BLOB)) +
                length(CAST(title AS BLOB)) + length(CAST(body AS BLOB)) +
                length(CAST(COALESCE(fact_key, '') AS BLOB)) +
                length(CAST(source AS BLOB)) + length(CAST(trust AS BLOB)) +
                length(CAST(state AS BLOB)) + length(CAST(created_at AS BLOB)) +
                length(CAST(updated_at AS BLOB)) + length(CAST(COALESCE(valid_from, '') AS BLOB)) +
                length(CAST(COALESCE(valid_to, '') AS BLOB)) + length(CAST(content_hash AS BLOB))
             ), 0) FROM memory_items WHERE agent = ?1",
            [agent],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let new_bytes = [
            agent.len(),
            item.kind.len(),
            item.title.len(),
            item.body.len(),
            item.fact_key.unwrap_or("").len(),
            item.source.len(),
            item.trust.len(),
            item.state.len(),
            item.valid_from.unwrap_or("").len(),
            item.valid_to.unwrap_or("").len(),
            64usize,
        ]
        .into_iter()
        .fold(0usize, usize::saturating_add);
        let new_bytes = i64::try_from(new_bytes).unwrap_or(i64::MAX);
        if count >= MEMORY_ITEMS_PER_AGENT_MAX {
            return Err(StoreError::MemoryRejected {
                reason: "per-agent record limit exceeded".into(),
            });
        }
        if bytes.saturating_add(new_bytes) > MEMORY_BYTES_PER_AGENT_MAX {
            return Err(StoreError::MemoryRejected {
                reason: "per-agent byte limit exceeded".into(),
            });
        }
        if let Some(id) = item.supersedes_id {
            let belongs: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM memory_items WHERE agent = ?1 AND id = ?2)",
                rusqlite::params![agent, id],
                |row| row.get(0),
            )?;
            if !belongs {
                return Err(StoreError::MemoryRejected {
                    reason: "superseded item does not belong to agent".into(),
                });
            }
        }
        tx.execute(
            "INSERT INTO memory_items(agent, kind, title, body, fact_key, confidence, source, trust, tainted, supersedes_id, state, valid_from, valid_to, content_hash, party_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![agent, item.kind, item.title, item.body, item.fact_key, item.confidence,
                item.source, item.trust, item.tainted, item.supersedes_id, item.state,
                item.valid_from, item.valid_to, content_hash, party_id],
        ).map_err(map_memory_constraint)?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO memory_sources(item_id,agent,source_ref,trust) VALUES (?1,?2,?3,?4)",
            rusqlite::params![
                id,
                agent,
                item.source,
                if item.tainted { "tainted" } else { "owner" }
            ],
        )?;
        match item.kind {
            "fact" => {
                tx.execute(
                    "INSERT INTO profile_facts(item_id,agent,fact_key,value) VALUES (?1,?2,?3,?4)",
                    rusqlite::params![id, agent, item.fact_key, item.body],
                )?;
            }
            "episode" => {
                tx.execute(
                    "INSERT INTO memory_episodes(item_id,agent,occurred_at) VALUES (?1,?2,?3)",
                    rusqlite::params![id, agent, item.valid_from],
                )?;
            }
            "note" => {
                tx.execute(
                    "INSERT INTO memory_notes(item_id,agent) VALUES (?1,?2)",
                    rusqlite::params![id, agent],
                )?;
            }
            _ => unreachable!("validated memory kind"),
        }
        let created = tx.query_row(
            "SELECT id, agent, kind, title, body, fact_key, confidence, source, trust, tainted, supersedes_id, state, created_at, updated_at, valid_from, valid_to, content_hash FROM memory_items WHERE agent = ?1 AND id = ?2",
            rusqlite::params![agent, id], memory_item_from_row,
        )?;
        Ok(created)
    }

    /// Replace an active item while retaining its history and unique fact key.
    pub fn edit_memory_item(
        &self,
        agent: &str,
        id: i64,
        text: &str,
    ) -> Result<Option<MemoryItem>, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let old = tx
            .query_row(
                "SELECT id,agent,kind,title,body,fact_key,confidence,source,trust,tainted,supersedes_id,state,created_at,updated_at,valid_from,valid_to,content_hash,party_id FROM memory_items WHERE agent=?1 AND id=?2 AND state='active'",
                rusqlite::params![agent, id],
                |row| Ok((memory_item_from_row(row)?, row.get::<_, Option<i64>>(17)?)),
            )
            .optional()?;
        let Some((old, party_id)) = old else {
            return Ok(None);
        };
        let (_, body) = sanitized_memory_text(text)?;
        tx.execute(
            "UPDATE memory_items SET state='superseded',updated_at=datetime('now') WHERE agent=?1 AND id=?2 AND state='active'",
            rusqlite::params![agent, id],
        )?;
        let item = NewMemoryItem {
            kind: &old.kind,
            title: &old.title,
            body: &body,
            fact_key: old.fact_key.as_deref(),
            confidence: old.confidence,
            source: "owner_edit",
            trust: "owner",
            tainted: false,
            state: "active",
            supersedes_id: Some(id),
            valid_from: old.valid_from.as_deref(),
            valid_to: old.valid_to.as_deref(),
        };
        let edited = Self::insert_memory_item_tx(&tx, agent, &item, party_id)?;
        tx.commit()?;
        Ok(Some(edited))
    }

    /// Read an item by both its owning agent and id. A guessed foreign id is
    /// indistinguishable from a missing row.
    pub fn memory_item(&self, agent: &str, id: i64) -> Result<Option<MemoryItem>, StoreError> {
        let item = self.conn.query_row(
            "SELECT id, agent, kind, title, body, fact_key, confidence, source, trust, tainted, supersedes_id, state, created_at, updated_at, valid_from, valid_to, content_hash FROM memory_items WHERE agent = ?1 AND id = ?2",
            rusqlite::params![agent, id], memory_item_from_row,
        ).optional()?;
        check_memory_response(item.as_ref())?;
        Ok(item)
    }

    /// The active memory items linked to one CRM party, newest first
    /// (`docs/phase1.md` §2). Scoped to the owning agent like every read, so a
    /// guessed party never leaks another agent's memory.
    pub fn memory_items_for_party(
        &self,
        agent: &str,
        party_id: i64,
        limit: usize,
    ) -> Result<Vec<MemoryItem>, StoreError> {
        let limit = i64::try_from(limit.min(MEMORY_ITEMS_PER_AGENT_MAX as usize))
            .unwrap_or(MEMORY_ITEMS_PER_AGENT_MAX);
        let mut statement = self.conn.prepare(
            "SELECT id, agent, kind, title, body, fact_key, confidence, source, trust, tainted, supersedes_id, state, created_at, updated_at, valid_from, valid_to, content_hash
               FROM memory_items WHERE agent = ?1 AND party_id = ?2 AND state = 'active'
              ORDER BY updated_at DESC, id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            rusqlite::params![agent, party_id, limit],
            memory_item_from_row,
        )?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;
        check_memory_response_many(&items)?;
        Ok(items)
    }

    /// Attach caller-supplied provenance references as tainted metadata only.
    pub fn add_memory_source_refs(
        &self,
        agent: &str,
        id: i64,
        refs: &[String],
    ) -> Result<(), StoreError> {
        if refs.len() > 8 || refs.iter().any(|s| s.is_empty() || s.len() > 128) {
            return Err(StoreError::MemoryRejected {
                reason: "invalid memory source references".into(),
            });
        }
        let tx = self.conn.unchecked_transaction()?;
        for source_ref in refs {
            tx.execute("INSERT OR IGNORE INTO memory_sources(item_id,agent,source_ref,trust) SELECT id,agent,?3,'tainted' FROM memory_items WHERE agent=?1 AND id=?2", rusqlite::params![agent,id,source_ref])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// FTS search. User text is reduced to Unicode alphanumeric tokens and
    /// every token is quoted, so raw FTS operators and column syntax cannot
    /// reach SQLite's MATCH parser.
    pub fn search_memory(
        &self,
        agent: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemoryItem>, StoreError> {
        let terms = tokenize_memory_query(query);
        if terms.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let match_query = terms
            .iter()
            .map(|term| format!("\"{term}\""))
            .collect::<Vec<_>>()
            .join(" AND ");
        let limit = i64::try_from(limit.min(MEMORY_ITEMS_PER_AGENT_MAX as usize))
            .unwrap_or(MEMORY_ITEMS_PER_AGENT_MAX);
        let mut stmt = self.conn.prepare(
            "SELECT i.id, i.agent, i.kind, i.title, i.body, i.fact_key, i.confidence, i.source, i.trust, i.tainted, i.supersedes_id, i.state, i.created_at, i.updated_at, i.valid_from, i.valid_to, i.content_hash
             FROM memory_items_fts f JOIN memory_items i ON i.id = f.rowid
             WHERE memory_items_fts MATCH ?1 AND i.agent = ?2 AND i.state = 'active'
             ORDER BY bm25(memory_items_fts), i.id LIMIT ?3"
        )?;
        let rows = stmt.query_map(
            rusqlite::params![match_query, agent, limit],
            memory_item_from_row,
        )?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;
        check_memory_response_many(&items)?;
        Ok(items)
    }

    /// The active, untainted `owner.*` facts of `agent`, as `(key, value)`,
    /// oldest first. A quarantined or tainted fact is never returned.
    pub fn owner_facts(&self, agent: &str) -> Result<Vec<(String, String)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT fact_key, body FROM memory_items
             WHERE agent = ?1 AND kind = 'fact' AND state = 'active' AND tainted = 0
               AND trust = 'owner' AND fact_key LIKE 'owner.%' ORDER BY id",
        )?;
        let rows = stmt.query_map([agent], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Change lifecycle state for an item owned by `agent`.
    pub fn set_memory_item_state(
        &self,
        agent: &str,
        id: i64,
        state: &str,
    ) -> Result<bool, StoreError> {
        if !matches!(state, "active" | "quarantined" | "superseded") {
            return Err(StoreError::MemoryRejected {
                reason: "invalid state".into(),
            });
        }
        self.conn
            .execute(
                "UPDATE memory_items SET state = ?1, updated_at = datetime('now')
             WHERE agent = ?2 AND id = ?3 AND NOT (state = 'quarantined' AND ?1 = 'active')",
                rusqlite::params![state, agent, id],
            )
            .map_err(map_memory_constraint)
            .map(|changed| changed != 0)
    }

    /// Delete an item owned by `agent`; the FTS delete trigger runs in the same
    /// SQLite statement/transaction.
    pub fn delete_memory_item(&self, agent: &str, id: i64) -> Result<bool, StoreError> {
        self.conn
            .execute(
                "DELETE FROM memory_items WHERE agent = ?1 AND id = ?2",
                rusqlite::params![agent, id],
            )
            .map(|changed| changed != 0)
            .map_err(StoreError::from)
    }

    /// Link an item owned by `agent` to a CRM party (`docs/phase1.md` §2). False
    /// when the item or the party does not exist.
    pub fn set_memory_item_party(
        &self,
        agent: &str,
        id: i64,
        party_id: i64,
    ) -> Result<bool, StoreError> {
        self.conn
            .execute(
                "UPDATE memory_items SET party_id = ?3
                  WHERE agent = ?1 AND id = ?2 AND EXISTS (SELECT 1 FROM party WHERE id = ?3)",
                rusqlite::params![agent, id, party_id],
            )
            .map(|changed| changed != 0)
            .map_err(StoreError::from)
    }

    /// The active memory items linked to one party, oldest first, for the
    /// client card. Bounded like every other memory read. Distinct from the
    /// agent-scoped `memory_items_for_party` (B4).
    pub fn memory_items_for_party_card(
        &self,
        party_id: i64,
    ) -> Result<Vec<MemoryItem>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id,agent,kind,title,body,fact_key,confidence,source,trust,tainted,supersedes_id,state,created_at,updated_at,valid_from,valid_to,content_hash FROM memory_items WHERE party_id=?1 AND state='active' ORDER BY updated_at,id LIMIT 100")?;
        let rows = stmt.query_map([party_id], memory_item_from_row)?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;
        check_memory_response_many(&items)?;
        Ok(items)
    }

    /// Delete one memory item linked to `party_id` (Forget on the client
    /// card). An item linked to another party is a miss. The audit event
    /// carries ids only.
    pub fn forget_party_memory_item(&self, party_id: i64, id: i64) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "DELETE FROM memory_items WHERE party_id = ?1 AND id = ?2",
            rusqlite::params![party_id, id],
        )?;
        if changed != 0 {
            self.log_event(
                "crm.memory_forgotten",
                &format!("{{\"party\":{party_id},\"item\":{id}}}"),
            )?;
        }
        Ok(changed != 0)
    }

    /// Bounded metadata-only view of quarantined rows for the owner CLI.
    pub fn list_quarantined_memory(
        &self,
        agent: &str,
        limit: usize,
    ) -> Result<Vec<(i64, String, String)>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id,kind,substr(title,1,80) FROM memory_items WHERE agent=?1 AND state='quarantined' ORDER BY created_at DESC,id DESC LIMIT ?2")?;
        let rows = stmt.query_map(rusqlite::params![agent, limit.min(100) as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn memory_mirror_hash(&self, agent: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT generated_hash FROM memory_mirrors WHERE agent=?1",
                [agent],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn active_memory_notes(
        &self,
        agent: &str,
        limit: usize,
    ) -> Result<Vec<MemoryItem>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id,agent,kind,title,body,fact_key,confidence,source,trust,tainted,supersedes_id,state,created_at,updated_at,valid_from,valid_to,content_hash FROM memory_items WHERE agent=?1 AND kind='note' AND state='active' ORDER BY updated_at,id LIMIT ?2")?;
        let rows = stmt.query_map(
            rusqlite::params![agent, limit.min(100) as i64],
            memory_item_from_row,
        )?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;
        check_memory_response_many(&items)?;
        Ok(items)
    }

    /// The memory list of `agent`: every active or quarantined item, oldest
    /// first, as `remember` wrote it.
    pub fn memory_items_for_agent(
        &self,
        agent: &str,
        limit: usize,
    ) -> Result<Vec<MemoryItem>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id,agent,kind,title,body,fact_key,confidence,source,trust,tainted,supersedes_id,state,created_at,updated_at,valid_from,valid_to,content_hash FROM memory_items WHERE agent=?1 AND state IN ('active','quarantined') ORDER BY created_at,id LIMIT ?2")?;
        let rows = stmt.query_map(
            rusqlite::params![agent, limit.min(100) as i64],
            memory_item_from_row,
        )?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;
        check_memory_response_many(&items)?;
        Ok(items)
    }

    /// Active-only owner view, independently bounded from runtime recall.
    pub fn active_memory_items_for_agent(
        &self,
        agent: &str,
        limit: usize,
    ) -> Result<Vec<MemoryItem>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id,agent,kind,title,body,fact_key,confidence,source,trust,tainted,supersedes_id,state,created_at,updated_at,valid_from,valid_to,content_hash FROM memory_items WHERE agent=?1 AND state='active' ORDER BY created_at,id LIMIT ?2")?;
        let rows = stmt.query_map(
            rusqlite::params![agent, limit.min(200) as i64],
            memory_item_from_row,
        )?;
        let items = rows.collect::<Result<Vec<_>, _>>()?;
        check_memory_response_many(&items)?;
        Ok(items)
    }

    /// Add one sanitized suggestion. A content hash is unique per agent for its
    /// full lifetime, so accepted and rejected suggestions cannot reappear.
    pub fn add_memory_suggestion(
        &self,
        agent: &str,
        body: &str,
        fact_key: Option<&str>,
        source_ref: &str,
        trust: &str,
    ) -> Result<Option<i64>, StoreError> {
        if agent.is_empty()
            || agent.len() > MEMORY_AGENT_MAX_BYTES
            || !matches!(trust, "owner" | "untrusted" | "tainted")
            || source_ref.is_empty()
            || source_ref.len() > MEMORY_METADATA_MAX_BYTES
            || fact_key.is_some_and(|key| key.len() > MEMORY_METADATA_MAX_BYTES)
        {
            return Err(StoreError::MemoryRejected {
                reason: "invalid memory suggestion metadata".into(),
            });
        }
        let (title, body) = sanitized_memory_text(body)?;
        let content_hash = memory_content_hash(&title, &body);
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let already_active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM memory_items WHERE agent=?1 AND state='active' AND content_hash=?2)",
            rusqlite::params![agent, content_hash],
            |row| row.get(0),
        )?;
        if already_active {
            tx.commit()?;
            return Ok(None);
        }
        let already_suggested: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM memory_suggestions WHERE dot=?1 AND content_hash=?2)",
            rusqlite::params![agent, content_hash],
            |row| row.get(0),
        )?;
        if already_suggested {
            tx.commit()?;
            return Ok(None);
        }
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM memory_suggestions WHERE dot=?1 AND state='pending'",
            [agent],
            |row| row.get(0),
        )?;
        if pending >= MEMORY_SUGGESTIONS_PER_AGENT_MAX as i64 {
            return Err(StoreError::MemorySuggestionLimitReached);
        }
        tx.execute(
            "INSERT OR IGNORE INTO memory_suggestions(dot,body,fact_key,source_ref,trust,content_hash,state) VALUES (?1,?2,?3,?4,?5,?6,'pending')",
            rusqlite::params![agent, body, fact_key, source_ref, trust, content_hash],
        )?;
        let inserted = tx.changes() != 0;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(inserted.then_some(id))
    }

    /// List the oldest pending suggestions, capped at the API's maximum.
    pub fn pending_memory_suggestions(
        &self,
        agent: &str,
        limit: usize,
    ) -> Result<Vec<MemorySuggestion>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id,body,fact_key,trust,created_at,source_ref FROM memory_suggestions WHERE dot=?1 AND state='pending' ORDER BY created_at,id LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![agent, limit.min(MEMORY_SUGGESTIONS_PER_AGENT_MAX) as i64],
            memory_suggestion_from_row,
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Accept a pending suggestion the owner kept and materialize it as an
    /// active memory fact, atomically.
    ///
    /// Acceptance is the owner's decision only: the sole caller is the owner's
    /// API route (`POST /v1/agents/{id}/memory/suggestions/{sid}/accept`),
    /// never a model tool. The owner read the text and said yes, so the row is
    /// an active owner memory whatever trust the proposal carried. A proposal
    /// that came from outside content keeps that provenance: its `source`
    /// names the outside suggestion and carries the suggestion's `source_ref`,
    /// so the memory item still says where it came from.
    pub fn accept_memory_suggestion(
        &self,
        agent: &str,
        id: i64,
    ) -> Result<Option<MemoryItem>, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let suggestion = tx
            .query_row(
                "SELECT id,body,fact_key,trust,created_at,source_ref FROM memory_suggestions WHERE dot=?1 AND id=?2 AND state='pending'",
                rusqlite::params![agent, id],
                memory_suggestion_from_row,
            )
            .optional()?;
        let Some(suggestion) = suggestion else {
            return Ok(None);
        };
        let (title, body) = sanitized_memory_text(&suggestion.body)?;
        let supersedes_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM memory_items WHERE agent=?1 AND state='active' AND ((?2 IS NOT NULL AND fact_key=?2) OR content_hash=?3) ORDER BY id DESC LIMIT 1",
                rusqlite::params![agent, suggestion.fact_key, memory_content_hash(&title, &body)],
                |row| row.get(0),
            )
            .optional()?;
        tx.execute(
            "UPDATE memory_items SET state='superseded',updated_at=datetime('now') WHERE agent=?1 AND state='active' AND ((?2 IS NOT NULL AND fact_key=?2) OR content_hash=?3)",
            rusqlite::params![agent, suggestion.fact_key, memory_content_hash(&title, &body)],
        )?;
        // The owner read and approved the proposal: it becomes an active
        // owner memory, never a quarantined one. A proposal that came from
        // outside content keeps that provenance (label plus the proposing
        // run) instead of looking like something the owner volunteered.
        let source = if suggestion.trust == "owner" {
            "accepted_suggestion".to_string()
        } else {
            accepted_outside_suggestion(&suggestion.source_ref)
        };
        let item = NewMemoryItem {
            kind: "fact",
            title: &title,
            body: &body,
            fact_key: suggestion.fact_key.as_deref(),
            confidence: None,
            source: &source,
            trust: "owner",
            tainted: false,
            state: "active",
            supersedes_id,
            valid_from: None,
            valid_to: None,
        };
        let accepted = Self::insert_memory_item_tx(&tx, agent, &item, None)?;
        let changed = tx.execute(
            "UPDATE memory_suggestions SET state='accepted' WHERE dot=?1 AND id=?2 AND state='pending'",
            rusqlite::params![agent, id],
        )?;
        if changed != 1 {
            return Ok(None);
        }
        tx.commit()?;
        Ok(Some(accepted))
    }

    /// Reject one pending suggestion. Decided and foreign ids are indistinguishable.
    pub fn reject_memory_suggestion(&self, agent: &str, id: i64) -> Result<bool, StoreError> {
        self.conn
            .execute(
                "UPDATE memory_suggestions SET state='rejected' WHERE dot=?1 AND id=?2 AND state='pending'",
                rusqlite::params![agent, id],
            )
            .map(|changed| changed == 1)
            .map_err(StoreError::from)
    }

    pub fn set_memory_mirror_hash(&self, agent: &str, hash: &str) -> Result<(), StoreError> {
        self.conn.execute("INSERT INTO memory_mirrors(agent,generated_hash,updated_at) VALUES (?1,?2,datetime('now')) ON CONFLICT(agent) DO UPDATE SET generated_hash=excluded.generated_hash,updated_at=excluded.updated_at", rusqlite::params![agent,hash])?;
        Ok(())
    }
}

/// The `source` of a memory item the owner accepted from an outside proposal:
/// the fixed prefix the daemon labels, a colon, and the proposing run's ref.
/// A caller-supplied ref longer than the item metadata budget is cut at a
/// character boundary, never rejected: an accepted suggestion must land.
fn accepted_outside_suggestion(source_ref: &str) -> String {
    let mut source = String::from(ACCEPTED_OUTSIDE_SUGGESTION);
    source.push(':');
    let room = MEMORY_METADATA_MAX_BYTES.saturating_sub(source.len());
    let mut used = 0;
    for character in source_ref.chars() {
        if used + character.len_utf8() > room {
            break;
        }
        source.push(character);
        used += character.len_utf8();
    }
    source
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use tempfile::tempdir;

    #[test]
    fn a_refresh_never_overwrites_a_note_the_owner_logged_on_the_same_mail() {
        let store = Store::open_in_memory().unwrap();
        let party = store.insert_party(&camille_party()).unwrap();
        let key = r#"{"imap":{"message_id":"<world-99@example.invalid>"}}"#;
        store
            .insert_interaction(
                party,
                "mail",
                "2026-10-01T09:00:00Z",
                key,
                "manual: owner note",
                "skill:log-interaction",
            )
            .unwrap();
        store
            .upsert_mail_interaction(
                party,
                "2026-10-19T09:00:00Z",
                key,
                "received: Re: update",
                "in",
            )
            .unwrap();
        let rows = store.interactions_for_party(party).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].summary, "manual: owner note");
        assert_eq!(rows[0].at, "2026-10-01T09:00:00Z");
    }

    #[test]
    fn memory_can_be_linked_to_a_party_and_read_back() {
        let store = Store::open_in_memory().unwrap();
        let party = store.insert_party(&camille_party()).unwrap();
        let linked = store
            .create_memory_item_for_party("main", &memory("Note", "linked body", None), party)
            .unwrap();
        let plain = store
            .create_memory_item("main", &memory("Other", "plain body", None))
            .unwrap();

        let linked_rows = store.memory_items_for_party("main", party, 10).unwrap();
        assert_eq!(linked_rows.len(), 1);
        assert_eq!(linked_rows[0].id, linked.id);
        assert_eq!(linked_rows[0].body, "linked body");

        // The plain item is not linked; another agent and another party see
        // nothing, so the read can never cross an ownership boundary.
        assert!(store
            .memory_items_for_party("main", party + 999, 10)
            .unwrap()
            .is_empty());
        assert!(store
            .memory_items_for_party("other", party, 10)
            .unwrap()
            .is_empty());
        assert_ne!(linked.id, plain.id);
    }

    #[test]
    fn v17_store_migrates_additive_memory_tables_idempotently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v17.db");
        let store = Store::open(&path).unwrap();
        let item = store
            .create_memory_item("dot-v17", &memory("Fact", "preserve me", None))
            .unwrap();
        restore_dot_columns(&store.conn);
        remove_document_text_additions_for_legacy_fixture(&store.conn).unwrap();
        store
            .conn
            .execute("UPDATE meta SET value='17' WHERE key='schema_version'", [])
            .unwrap();
        store.conn.execute_batch("DROP TRIGGER IF EXISTS memory_quarantine_immutable; DROP TABLE IF EXISTS memory_sources; DROP TABLE IF EXISTS profile_facts; DROP TABLE IF EXISTS memory_episodes; DROP TABLE IF EXISTS memory_notes; DROP TABLE IF EXISTS memory_mirrors;").unwrap();
        drop(store);
        let migrated = Store::open(&path).unwrap();
        assert_eq!(migrated.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            migrated
                .memory_item("dot-v17", item.id)
                .unwrap()
                .unwrap()
                .body,
            "preserve me"
        );
        assert_eq!(
            migrated
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM profile_facts WHERE item_id=?1",
                    [item.id],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        drop(migrated);
        assert_eq!(
            Store::open(&path).unwrap().schema_version().unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn memory_api_isolation_includes_guessed_ids_for_all_mutations_and_fts() {
        let store = Store::open_in_memory().unwrap();
        let a = store
            .create_memory_item("agent-a", &memory("Private", "secretword", Some("k")))
            .unwrap();
        let b = store
            .create_memory_item("agent-b", &memory("Other", "publicword", Some("k")))
            .unwrap();
        assert!(store.memory_item("agent-b", a.id).unwrap().is_none());
        assert!(store
            .search_memory("agent-b", "secretword", 8)
            .unwrap()
            .is_empty());
        assert!(store
            .search_memory("agent-a", "publicword", 8)
            .unwrap()
            .is_empty());
        assert!(!store
            .set_memory_item_state("agent-b", a.id, "superseded")
            .unwrap());
        assert!(!store.delete_memory_item("agent-b", a.id).unwrap());
        assert_eq!(
            store.memory_item("agent-a", a.id).unwrap().unwrap().state,
            "active"
        );
        assert!(store.memory_item("agent-b", b.id).unwrap().is_some());
    }

    #[test]
    fn fts_hostile_syntax_is_tokenized_and_never_executes_as_fts() {
        let store = Store::open_in_memory().unwrap();
        store
            .create_memory_item("agent", &memory("Memory", "alpha hidden", None))
            .unwrap();
        let hostile = store
            .search_memory("agent", "alpha OR hidden\" NEAR(secret) title:alpha", 8)
            .unwrap();
        let tokenized = store
            .search_memory("agent", "alpha OR hidden NEAR secret title alpha", 8)
            .unwrap();
        assert_eq!(hostile, tokenized);
        assert!(store
            .search_memory("agent", "\" OR ) NEAR :", 8)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn fts_trigger_tracks_text_updates_and_deletes() {
        let store = Store::open_in_memory().unwrap();
        let item = store
            .create_memory_item("agent", &memory("Before", "oldterm", None))
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE memory_items SET title = 'After', body = 'newterm' WHERE agent = ?1 AND id = ?2",
                rusqlite::params!["agent", item.id],
            )
            .unwrap();
        assert!(store
            .search_memory("agent", "oldterm", 8)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.search_memory("agent", "newterm", 8).unwrap()[0].id,
            item.id
        );
        assert!(store.delete_memory_item("agent", item.id).unwrap());
        assert!(store
            .search_memory("agent", "newterm", 8)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn memory_enforces_utf8_byte_caps_active_uniqueness_and_fts_delete() {
        let store = Store::open_in_memory().unwrap();
        let oversize = "é".repeat(MEMORY_TITLE_MAX_BYTES / 2 + 1);
        assert!(matches!(
            store.create_memory_item("agent", &memory(&oversize, "body", None)),
            Err(StoreError::MemoryRejected { .. })
        ));
        let first = store
            .create_memory_item("agent", &memory("Fact", "unique content", Some("favorite")))
            .unwrap();
        assert!(matches!(
            store.create_memory_item("agent", &memory("Another", "different", Some("favorite"))),
            Err(StoreError::MemoryRejected { .. })
        ));
        let duplicate_hash = memory("Fact", "unique content", Some("another-key"));
        assert!(matches!(
            store.create_memory_item("agent", &duplicate_hash),
            Err(StoreError::MemoryRejected { .. })
        ));
        assert!(store.delete_memory_item("agent", first.id).unwrap());
        assert!(store
            .search_memory("agent", "unique content", 8)
            .unwrap()
            .is_empty());
        assert!(store
            .create_memory_item("agent", &memory("Fact", "unique content", Some("favorite")))
            .is_ok());
    }

    #[test]
    fn tainted_memory_is_quarantined_and_cannot_be_promoted() {
        let store = Store::open_in_memory().unwrap();
        let mut tainted = memory("Tainted", "untrusted content", None);
        tainted.tainted = true;
        tainted.state = "quarantined";
        let item = store.create_memory_item("agent", &tainted).unwrap();
        assert!(item.tainted);
        assert_eq!(item.state, "quarantined");
        assert!(store
            .search_memory("agent", "untrusted", 8)
            .unwrap()
            .is_empty());
        assert!(!store
            .set_memory_item_state("agent", item.id, "active")
            .unwrap());
        assert!(store
            .conn
            .execute(
                "UPDATE memory_items SET state='active' WHERE agent='agent' AND id=?1",
                [item.id],
            )
            .is_err());

        let invalid = NewMemoryItem {
            state: "active",
            ..tainted
        };
        assert!(matches!(
            store.create_memory_item("agent", &invalid),
            Err(StoreError::MemoryRejected { .. })
        ));
    }

    #[test]
    fn memory_search_refuses_results_over_the_response_byte_cap() {
        let store = Store::open_in_memory().unwrap();
        for index in 0..5 {
            let body = format!("lots {index} {}", "x".repeat(MEMORY_BODY_MAX_BYTES - 12));
            let row = NewMemoryItem {
                kind: "note",
                title: "large",
                body: &body,
                fact_key: None,
                confidence: None,
                source: "test",
                trust: "owner",
                tainted: false,
                state: "active",
                supersedes_id: None,
                valid_from: None,
                valid_to: None,
            };
            store.create_memory_item("agent", &row).unwrap();
        }
        assert!(matches!(
            store.search_memory("agent", "lots", 8),
            Err(StoreError::MemoryRejected { .. })
        ));
    }

    #[test]
    fn edit_supersedes_and_recall_returns_the_new_fact() {
        let s = Store::open_in_memory().unwrap();
        let old = s
            .create_memory_item(
                "agent",
                &memory("Name", "Name is Rowan", Some("owner.name")),
            )
            .unwrap();
        let new = s
            .edit_memory_item("agent", old.id, "Name is Rowan Vale")
            .unwrap()
            .unwrap();
        assert_eq!(
            s.memory_item("agent", old.id).unwrap().unwrap().state,
            "superseded"
        );
        assert_eq!(
            (
                new.fact_key.as_deref(),
                new.supersedes_id,
                new.source.as_str()
            ),
            (Some("owner.name"), Some(old.id), "owner_edit")
        );
        assert_eq!(
            s.search_memory("agent", "Rowan Vale", 8).unwrap()[0].body,
            "Name is Rowan Vale"
        );
    }

    #[test]
    fn suggestions_are_bounded_idempotent_and_decide_once() {
        let s = Store::open_in_memory().unwrap();
        let id = s
            .add_memory_suggestion(
                "agent",
                "Nico likes quotes",
                Some("rule.quotes"),
                "mail-1",
                "untrusted",
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            s.add_memory_suggestion(
                "agent",
                "Nico likes quotes",
                Some("rule.quotes"),
                "mail-2",
                "untrusted"
            )
            .unwrap(),
            None
        );
        assert_eq!(
            s.pending_memory_suggestions("agent", 20).unwrap()[0].source_ref,
            "mail-1"
        );
        let accepted = s.accept_memory_suggestion("agent", id).unwrap().unwrap();
        assert_eq!(
            (
                accepted.source.as_str(),
                accepted.trust.as_str(),
                accepted.state.as_str()
            ),
            ("accepted_outside_suggestion:mail-1", "owner", "active")
        );
        assert!(s.accept_memory_suggestion("agent", id).unwrap().is_none());
        let id = s
            .add_memory_suggestion("agent", "Never suggest twice", None, "mail-3", "tainted")
            .unwrap()
            .unwrap();
        assert!(s.reject_memory_suggestion("agent", id).unwrap());
        assert!(!s.reject_memory_suggestion("agent", id).unwrap());
        // Rejecting writes no memory row and recalls nothing.
        assert!(s
            .search_memory("agent", "Never suggest twice", 8)
            .unwrap()
            .is_empty());
        assert!(!s
            .memory_items_for_agent("agent", 20)
            .unwrap()
            .iter()
            .any(|item| item.body == "Never suggest twice"));
        assert_eq!(
            s.add_memory_suggestion("agent", "Never suggest twice", None, "mail-4", "tainted")
                .unwrap(),
            None
        );
        s.add_memory_suggestion("agent", "First", None, "mail-5", "owner")
            .unwrap();
        s.add_memory_suggestion("agent", "Second", None, "mail-6", "owner")
            .unwrap();
        assert_eq!(s.pending_memory_suggestions("agent", 1).unwrap().len(), 1);
    }

    /// The owner's acceptance is what makes a suggestion a memory. A proposal
    /// the model made from tainted content becomes an active owner memory the
    /// model recalls, and it keeps the provenance that it came from an
    /// outside suggestion, with the proposing run's ref.
    #[test]
    fn an_accepted_outside_suggestion_becomes_an_active_owner_memory() {
        let s = Store::open_in_memory().unwrap();
        let tainted = s
            .add_memory_suggestion(
                "agent",
                "Nico prefers tea on Tuesdays",
                Some("owner.tea"),
                "mail-1",
                "tainted",
            )
            .unwrap()
            .unwrap();
        let accepted = s
            .accept_memory_suggestion("agent", tainted)
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                accepted.source.as_str(),
                accepted.trust.as_str(),
                accepted.tainted,
                accepted.state.as_str()
            ),
            (
                "accepted_outside_suggestion:mail-1",
                "owner",
                false,
                "active"
            )
        );
        // The owner's yes is what counts: the memory is recalled and it is an
        // owner fact.
        assert_eq!(
            s.search_memory("agent", "Nico prefers tea on Tuesdays", 8)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            s.owner_facts("agent").unwrap(),
            [(
                "owner.tea".to_string(),
                "Nico prefers tea on Tuesdays".to_string()
            )]
        );

        let owner = s
            .add_memory_suggestion(
                "agent",
                "Rowan prefers coffee on Fridays",
                Some("owner.coffee"),
                "run-1",
                "owner",
            )
            .unwrap()
            .unwrap();
        let accepted = s.accept_memory_suggestion("agent", owner).unwrap().unwrap();
        assert_eq!(
            (
                accepted.source.as_str(),
                accepted.trust.as_str(),
                accepted.tainted,
                accepted.state.as_str()
            ),
            ("accepted_suggestion", "owner", false, "active")
        );
        assert_eq!(
            s.search_memory("agent", "Rowan prefers coffee on Fridays", 8)
                .unwrap()
                .len(),
            1
        );
    }

    fn memory<'a>(title: &'a str, body: &'a str, fact_key: Option<&'a str>) -> NewMemoryItem<'a> {
        NewMemoryItem {
            kind: "fact",
            title,
            body,
            fact_key,
            confidence: Some(0.9),
            source: "test",
            trust: "owner",
            tainted: false,
            state: "active",
            supersedes_id: None,
            valid_from: None,
            valid_to: None,
        }
    }
}
