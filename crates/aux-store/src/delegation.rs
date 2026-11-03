//! Delegations (D33, WO E0): one chief handing one task to one domain agent.
//!
//! A delegation is a durable record — task, agent, state, steps, result — so
//! the chief's thread can show it live and the owner can resume it after a
//! stop. The migration is additive: two new tables and nothing else, so a
//! populated store upgrades in place.
//!
//! The steps are stored as one JSON array string rather than a second table:
//! they are append-only, always read whole, and bounded by the executor, so a
//! child table would buy nothing but a join. The `task`, `result` and step
//! `text` columns hold the **already-sanitized** text the API built (the same
//! convention as `messages.content`): the SQLCipher store is local, and the
//! API layer is the one that tokenises or redacts before writing.

use kernel_core::privacy::PrivacyMode;

use crate::{Store, StoreError};

/// Current state of one delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState {
    /// Created, not started.
    Queued,
    /// The agent is working.
    Working,
    /// The agent waits on an approval.
    Waiting,
    /// Finished: `result` holds the short answer.
    Done,
    /// Stopped by the owner; partial steps are kept.
    Stopped,
    /// The agent could not finish.
    Failed,
}

impl DelegationState {
    /// The stored lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            DelegationState::Queued => "queued",
            DelegationState::Working => "working",
            DelegationState::Waiting => "waiting",
            DelegationState::Done => "done",
            DelegationState::Stopped => "stopped",
            DelegationState::Failed => "failed",
        }
    }

    /// Parse a stored label; an unknown label fails closed as `Failed`.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "queued" => DelegationState::Queued,
            "working" => DelegationState::Working,
            "waiting" => DelegationState::Waiting,
            "done" => DelegationState::Done,
            "stopped" => DelegationState::Stopped,
            _ => DelegationState::Failed,
        }
    }

    /// Whether the delegation is still live (work may still arrive).
    pub fn is_open(self) -> bool {
        matches!(
            self,
            DelegationState::Queued | DelegationState::Working | DelegationState::Waiting
        )
    }
}

/// One live step of a delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationStep {
    /// Short, already-sanitized step text.
    pub text: String,
    /// UTC timestamp (`YYYY-MM-DD HH:MM:SS`).
    pub at: String,
    /// Step state (`working`, `done`, `waiting`, …).
    pub state: String,
    /// Where the step ran (`local`/`out`), from the egress record; `None`
    /// when unrecorded, as in every row older than the field.
    pub where_ran: Option<String>,
}

/// One delegation as the store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// Stable id (`dl-<millis>-<seq>`).
    pub id: String,
    /// Thread the work was asked in (the chief's agent name).
    pub parent_thread: String,
    /// Domain agent doing the work.
    pub agent: String,
    /// The task text.
    pub task: String,
    /// Current state.
    pub state: DelegationState,
    /// Append-only steps.
    pub steps: Vec<DelegationStep>,
    /// Short result, once `Done`.
    pub result: Option<String>,
    /// Brain the agent used (`provider/model`).
    pub brain: Option<String>,
    /// Approval the agent waits on, when `Waiting`.
    pub approval_id: Option<String>,
    /// Finished steps so far (`n` of `of`).
    pub progress_n: Option<i64>,
    pub progress_of: Option<i64>,
    /// Wall time the delegation took, once finished.
    pub took_ms: Option<i64>,
    /// Creation timestamp (UTC).
    pub created_at: String,
    /// Last-update timestamp (UTC).
    pub updated_at: String,
    /// The caller's mode at handoff: a resumed run is never looser. A row
    /// from before v25, or with any other label, reads as Private.
    pub caller_mode: PrivacyMode,
}

/// v24: the `delegations` and `thread_reads` tables (D33, WO E0).
///
/// B1 holds v22 and C2b holds v23, so the daemon's delegation work is v24. Both tables are purely additive
/// `CREATE TABLE IF NOT EXISTS`; `state` is constrained to the six documented
/// values, and the rest is free text the API layer already sanitized.
/// `apply_migration_with_version` records v23 in the same transaction.
pub(crate) const MIGRATION_V24: &str = r#"
CREATE TABLE IF NOT EXISTS delegations (
    id            TEXT PRIMARY KEY,
    parent_thread TEXT NOT NULL,
    agent         TEXT NOT NULL,
    task          TEXT NOT NULL,
    state         TEXT NOT NULL
                  CHECK (state IN ('queued', 'working', 'waiting', 'done', 'stopped', 'failed')),
    steps         TEXT NOT NULL DEFAULT '[]',
    result        TEXT,
    brain         TEXT,
    approval_id   TEXT,
    progress_n    INTEGER,
    progress_of   INTEGER,
    took_ms       INTEGER,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_delegations_parent ON delegations(parent_thread, id);
CREATE INDEX IF NOT EXISTS idx_delegations_agent ON delegations(agent, id);
CREATE INDEX IF NOT EXISTS idx_delegations_state ON delegations(state);

-- The team sidebar's unread bold. One row per thread the owner opened; a
-- thread with no row (or a row older than its newest message) is unread.
CREATE TABLE IF NOT EXISTS thread_reads (
    thread_id INTEGER PRIMARY KEY,
    read_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

/// v25: the caller's mode at handoff, so a resumed delegation keeps it.
///
/// `ALTER TABLE … ADD COLUMN` is not idempotent, so [`apply_v25`] checks for
/// the column under the write lock (the v22 pattern). Old rows keep NULL,
/// which reads as Private.
pub(crate) const MIGRATION_V25: &str = "ALTER TABLE delegations ADD COLUMN caller_mode TEXT \
     CHECK (caller_mode IS NULL OR caller_mode IN ('private', 'open'));";

/// Apply v25 and stamp it in one `IMMEDIATE` transaction; a concurrent open
/// that lost the race finds the column and only stamps the version.
pub(crate) fn apply_v25(conn: &mut rusqlite::Connection) -> Result<(), StoreError> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let has_column: i64 = tx.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('delegations') WHERE name = 'caller_mode'",
        [],
        |row| row.get(0),
    )?;
    if has_column == 0 {
        tx.execute_batch(MIGRATION_V25)?;
    }
    tx.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [25_i64.to_string()],
    )?;
    tx.commit()?;
    Ok(())
}

fn mode_label(mode: PrivacyMode) -> &'static str {
    match mode {
        PrivacyMode::Open => "open",
        PrivacyMode::Private => "private",
    }
}

/// Only a stored `open` is Open: NULL (a legacy row) fails closed.
fn parse_mode(raw: Option<String>) -> PrivacyMode {
    match raw.as_deref() {
        Some("open") => PrivacyMode::Open,
        _ => PrivacyMode::Private,
    }
}

fn row_to_delegation(row: &rusqlite::Row<'_>) -> rusqlite::Result<Delegation> {
    let state: String = row.get(4)?;
    let steps: String = row.get(5)?;
    Ok(Delegation {
        id: row.get(0)?,
        parent_thread: row.get(1)?,
        agent: row.get(2)?,
        task: row.get(3)?,
        state: DelegationState::parse(&state),
        steps: parse_steps(&steps),
        result: row.get(6)?,
        brain: row.get(7)?,
        approval_id: row.get(8)?,
        progress_n: row.get(9)?,
        progress_of: row.get(10)?,
        took_ms: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        caller_mode: parse_mode(row.get(14)?),
    })
}

/// Parse the stored steps JSON. A corrupt array degrades to empty rather than
/// failing the whole read: the record is still useful.
fn parse_steps(raw: &str) -> Vec<DelegationStep> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            Some(DelegationStep {
                text: item.get("text")?.as_str()?.to_string(),
                at: item.get("at")?.as_str()?.to_string(),
                state: item
                    .get("state")
                    .and_then(|value| value.as_str())
                    .unwrap_or("working")
                    .to_string(),
                where_ran: item
                    .get("where")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
            })
        })
        .collect()
}

fn steps_json(steps: &[DelegationStep]) -> String {
    let items: Vec<serde_json::Value> = steps
        .iter()
        .map(|s| serde_json::json!({ "text": s.text, "at": s.at, "state": s.state, "where": s.where_ran }))
        .collect();
    serde_json::Value::Array(items).to_string()
}

const SELECT_COLUMNS: &str = "id, parent_thread, agent, task, state, steps, result, brain, \
     approval_id, progress_n, progress_of, took_ms, created_at, updated_at, caller_mode";

impl Store {
    /// Insert one delegation in `queued`, with the caller's mode at handoff,
    /// and return it.
    pub fn create_delegation(
        &self,
        id: &str,
        parent_thread: &str,
        agent: &str,
        task: &str,
        brain: Option<&str>,
        caller_mode: PrivacyMode,
    ) -> Result<Delegation, StoreError> {
        self.conn.execute(
            "INSERT INTO delegations(id, parent_thread, agent, task, state, brain, caller_mode)
             VALUES (?1, ?2, ?3, ?4, 'queued', ?5, ?6)",
            rusqlite::params![
                id,
                parent_thread,
                agent,
                task,
                brain,
                mode_label(caller_mode)
            ],
        )?;
        self.delegation(id)?
            .ok_or_else(|| StoreError::DelegationNotFound { id: id.to_string() })
    }

    /// One delegation by id.
    pub fn delegation(&self, id: &str) -> Result<Option<Delegation>, StoreError> {
        let sql = format!("SELECT {SELECT_COLUMNS} FROM delegations WHERE id = ?1");
        match self.conn.query_row(&sql, [id], row_to_delegation) {
            Ok(delegation) => Ok(Some(delegation)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Delegations, newest first, optionally filtered to one parent thread.
    pub fn list_delegations(
        &self,
        parent_thread: Option<&str>,
    ) -> Result<Vec<Delegation>, StoreError> {
        let mut rows = Vec::new();
        match parent_thread {
            Some(parent) => {
                let sql = format!(
                    "SELECT {SELECT_COLUMNS} FROM delegations WHERE parent_thread = ?1 ORDER BY id DESC"
                );
                let mut stmt = self.conn.prepare(&sql)?;
                let mapped = stmt.query_map([parent], row_to_delegation)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
            None => {
                let sql = format!("SELECT {SELECT_COLUMNS} FROM delegations ORDER BY id DESC");
                let mut stmt = self.conn.prepare(&sql)?;
                let mapped = stmt.query_map([], row_to_delegation)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
        }
        Ok(rows)
    }

    /// Set a delegation's state; `false` when no such row.
    pub fn set_delegation_state(
        &self,
        id: &str,
        state: DelegationState,
    ) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE delegations SET state = ?2, updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![id, state.as_str()],
        )?;
        Ok(changed > 0)
    }

    /// Append one step and return the updated record; `None` when no such row.
    pub fn append_delegation_step(
        &self,
        id: &str,
        step: &DelegationStep,
    ) -> Result<Option<Delegation>, StoreError> {
        let Some(mut delegation) = self.delegation(id)? else {
            return Ok(None);
        };
        delegation.steps.push(step.clone());
        self.conn.execute(
            "UPDATE delegations SET steps = ?2, updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![id, steps_json(&delegation.steps)],
        )?;
        Ok(Some(delegation))
    }

    /// Record where step `index` ran; `false` when the row or step is absent.
    pub fn set_delegation_step_where(
        &self,
        id: &str,
        index: usize,
        place: &str,
    ) -> Result<bool, StoreError> {
        let Some(mut delegation) = self.delegation(id)? else {
            return Ok(false);
        };
        let Some(step) = delegation.steps.get_mut(index) else {
            return Ok(false);
        };
        step.where_ran = Some(place.to_string());
        self.conn.execute(
            "UPDATE delegations SET steps = ?2, updated_at = datetime('now') WHERE id = ?1",
            rusqlite::params![id, steps_json(&delegation.steps)],
        )?;
        Ok(true)
    }

    /// Store the short result and finish the delegation; `false` when absent.
    pub fn set_delegation_result(
        &self,
        id: &str,
        result: &str,
        took_ms: i64,
    ) -> Result<bool, StoreError> {
        // Conditional completion: a `stopped` (or failed) record is never
        // overwritten with `done`, so a Stop that landed while the executor
        // ran keeps the partial work and the stopped state.
        let changed = self.conn.execute(
            "UPDATE delegations
             SET state = 'done', result = ?2, took_ms = ?3, updated_at = datetime('now')
             WHERE id = ?1 AND state IN ('queued', 'working', 'waiting')",
            rusqlite::params![id, result, took_ms],
        )?;
        Ok(changed > 0)
    }

    /// Record finished-step progress.
    pub fn set_delegation_progress(&self, id: &str, n: i64, of: i64) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE delegations
             SET progress_n = ?2, progress_of = ?3, updated_at = datetime('now')
             WHERE id = ?1",
            rusqlite::params![id, n, of],
        )?;
        Ok(changed > 0)
    }

    /// Record the approval the delegation waits on.
    pub fn set_delegation_approval(&self, id: &str, approval_id: &str) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE delegations
             SET approval_id = ?2, state = 'waiting', updated_at = datetime('now')
             WHERE id = ?1",
            rusqlite::params![id, approval_id],
        )?;
        Ok(changed > 0)
    }

    /// Stop every open delegation; returns how many changed. Used by Stop all.
    pub fn stop_open_delegations(&self) -> Result<usize, StoreError> {
        let changed = self.conn.execute(
            "UPDATE delegations
             SET state = 'stopped', updated_at = datetime('now')
             WHERE state IN ('queued', 'working', 'waiting')",
            [],
        )?;
        Ok(changed)
    }

    /// Mark a thread read (upsert).
    pub fn mark_thread_read(&self, thread_id: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO thread_reads(thread_id, read_at) VALUES (?1, datetime('now'))
             ON CONFLICT(thread_id) DO UPDATE SET read_at = excluded.read_at",
            [thread_id],
        )?;
        Ok(())
    }

    /// When this thread was last read, or `None`.
    pub fn thread_read_at(&self, thread_id: i64) -> Result<Option<String>, StoreError> {
        match self.conn.query_row(
            "SELECT read_at FROM thread_reads WHERE thread_id = ?1",
            [thread_id],
            |row| row.get(0),
        ) {
            Ok(stamp) => Ok(Some(stamp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn a_created_delegation_starts_queued_and_empty() {
        let store = store();
        let delegation = store
            .create_delegation(
                "dl-1",
                "aux",
                "mail",
                "summarise the last thread",
                Some("deepseek/x"),
                PrivacyMode::Open,
            )
            .unwrap();
        assert_eq!(delegation.state, DelegationState::Queued);
        assert_eq!(delegation.agent, "mail");
        assert!(delegation.steps.is_empty());
        assert_eq!(delegation.result, None);
        assert_eq!(delegation.brain.as_deref(), Some("deepseek/x"));
        assert_eq!(delegation.caller_mode, PrivacyMode::Open);
    }

    /// A v24 row has no stored mode: after the upgrade it reads as Private.
    #[test]
    fn a_v24_row_upgrades_and_resumes_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let store = Store::open(&path).unwrap();
        crate::remove_document_text_additions_for_legacy_fixture(&store.conn).unwrap();
        store
            .conn
            .execute_batch(&format!(
                "DROP TABLE delegations; {MIGRATION_V24}
                 INSERT INTO delegations(id, parent_thread, agent, task, state)
                 VALUES ('dl-old', 'aux', 'mail', 'task', 'working');
                 UPDATE meta SET value = '24' WHERE key = 'schema_version';"
            ))
            .unwrap();
        drop(store);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), crate::SCHEMA_VERSION);
        let old = store.delegation("dl-old").unwrap().unwrap();
        assert_eq!(old.caller_mode, PrivacyMode::Private);
    }

    #[test]
    fn steps_append_in_order_and_survive_a_reopen() {
        let store = store();
        store
            .create_delegation("dl-1", "aux", "mail", "task", None, PrivacyMode::Private)
            .unwrap();
        for text in ["read", "draft", "send"] {
            let step = DelegationStep {
                text: text.to_string(),
                at: "2026-10-12 08:00:00".to_string(),
                state: "done".to_string(),
                where_ran: None,
            };
            let updated = store
                .append_delegation_step("dl-1", &step)
                .unwrap()
                .unwrap();
            assert_eq!(updated.steps.last().unwrap().text, text);
        }
        let again = store.delegation("dl-1").unwrap().unwrap();
        assert_eq!(again.steps.len(), 3);
        assert_eq!(again.steps[2].state, "done");
    }

    #[test]
    fn a_result_finishes_the_delegation_and_keeps_the_steps() {
        let store = store();
        store
            .create_delegation("dl-1", "aux", "mail", "task", None, PrivacyMode::Private)
            .unwrap();
        store
            .append_delegation_step(
                "dl-1",
                &DelegationStep {
                    text: "sent".to_string(),
                    at: "now".to_string(),
                    state: "done".to_string(),
                    where_ran: None,
                },
            )
            .unwrap();
        assert!(store
            .set_delegation_result("dl-1", "Mail sent it.", 48_000)
            .unwrap());
        let done = store.delegation("dl-1").unwrap().unwrap();
        assert_eq!(done.state, DelegationState::Done);
        assert_eq!(done.result.as_deref(), Some("Mail sent it."));
        assert_eq!(done.took_ms, Some(48_000));
        assert_eq!(done.steps.len(), 1);
    }

    #[test]
    fn list_filters_by_parent_and_is_newest_first() {
        let store = store();
        store
            .create_delegation("dl-1", "aux", "mail", "a", None, PrivacyMode::Private)
            .unwrap();
        store
            .create_delegation("dl-2", "aux", "calendar", "b", None, PrivacyMode::Private)
            .unwrap();
        store
            .create_delegation("dl-3", "main", "documents", "c", None, PrivacyMode::Private)
            .unwrap();
        let aux = store.list_delegations(Some("aux")).unwrap();
        assert_eq!(aux.len(), 2);
        assert_eq!(aux[0].id, "dl-2");
        assert_eq!(store.list_delegations(None).unwrap().len(), 3);
    }

    #[test]
    fn stopping_open_delegations_leaves_finished_ones_alone() {
        let store = store();
        store
            .create_delegation("dl-1", "aux", "mail", "a", None, PrivacyMode::Private)
            .unwrap();
        store
            .create_delegation("dl-2", "aux", "mail", "b", None, PrivacyMode::Private)
            .unwrap();
        store.set_delegation_result("dl-2", "done", 1).unwrap();
        assert_eq!(store.stop_open_delegations().unwrap(), 1);
        assert_eq!(
            store.delegation("dl-1").unwrap().unwrap().state,
            DelegationState::Stopped
        );
        assert_eq!(
            store.delegation("dl-2").unwrap().unwrap().state,
            DelegationState::Done
        );
    }

    #[test]
    fn a_stopped_delegation_cannot_be_overwritten_with_done() {
        let store = store();
        store
            .create_delegation("dl-1", "aux", "mail", "a", None, PrivacyMode::Private)
            .unwrap();
        store
            .set_delegation_state("dl-1", DelegationState::Stopped)
            .unwrap();
        assert!(!store.set_delegation_result("dl-1", "late", 1).unwrap());
        let record = store.delegation("dl-1").unwrap().unwrap();
        assert_eq!(record.state, DelegationState::Stopped);
        assert_eq!(record.result, None);
        // An open delegation still finishes normally.
        store
            .create_delegation("dl-2", "aux", "mail", "b", None, PrivacyMode::Private)
            .unwrap();
        assert!(store.set_delegation_result("dl-2", "done", 1).unwrap());
    }

    #[test]
    fn thread_reads_upsert_and_read_back() {
        let store = store();
        assert_eq!(store.thread_read_at(7).unwrap(), None);
        store.mark_thread_read(7).unwrap();
        assert!(store.thread_read_at(7).unwrap().is_some());
        store.mark_thread_read(7).unwrap();
        assert!(store.thread_read_at(7).unwrap().is_some());
    }

    fn table_exists(store: &Store, name: &str) -> bool {
        store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            > 0
    }

    #[test]
    fn a_fresh_store_reaches_v24_with_both_migrations() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), crate::SCHEMA_VERSION);
        assert!(table_exists(&store, "document_fields"), "C2b v23 table");
        assert!(table_exists(&store, "delegations"), "E0 v24 table");
        assert!(table_exists(&store, "thread_reads"), "E0 v24 table");
    }

    #[test]
    fn a_v22_store_upgrades_through_v23_to_v24() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            crate::remove_document_text_additions_for_legacy_fixture(&store.conn).unwrap();
            store
                .conn
                .execute_batch(
                    "UPDATE meta SET value = '22' WHERE key = 'schema_version';
                     DROP TABLE IF EXISTS document_fields;
                     DROP TABLE IF EXISTS delegations;
                     DROP TABLE IF EXISTS thread_reads;",
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), crate::SCHEMA_VERSION);
        assert!(table_exists(&store, "document_fields"));
        assert!(table_exists(&store, "delegations"));
    }

    #[test]
    fn a_v23_store_with_document_fields_upgrades_to_v24() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            crate::remove_document_text_additions_for_legacy_fixture(&store.conn).unwrap();
            store
                .conn
                .execute_batch(
                    "UPDATE meta SET value = '23' WHERE key = 'schema_version';
                     DROP TABLE IF EXISTS delegations;
                     DROP TABLE IF EXISTS thread_reads;",
                )
                .unwrap();
            assert!(table_exists(&store, "document_fields"));
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), crate::SCHEMA_VERSION);
        assert!(table_exists(&store, "document_fields"));
        assert!(table_exists(&store, "delegations"));
    }
}
