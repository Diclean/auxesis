//! The event log: what happened, in order, and only once.
//!
//! Every decision the store records about a run is written as an event
//! row, so the trail can be read back and pruned by count or by age.

use super::*;

impl Store {
    /// Append an audit event. Payloads are JSON strings by convention.
    pub fn log_event(&self, kind: &str, payload: &str) -> Result<(), StoreError> {
        self.log_event_id(kind, payload).map(|_| ())
    }

    /// Append an audit event and return its row id.
    pub fn log_event_id(&self, kind: &str, payload: &str) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO events(kind, payload) VALUES (?1, ?2)",
            (kind, payload),
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The payloads of the newest `limit` events of `kind`, newest first.
    /// Payloads are returned as stored: a caller parses them and skips a row
    /// it cannot read.
    pub fn recent_event_payloads(
        &self,
        kind: &str,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload FROM events WHERE kind = ?1 ORDER BY id DESC LIMIT ?2")?;
        let rows = stmt.query_map(rusqlite::params![kind, limit as i64], |row| row.get(0))?;
        Ok(rows.collect::<Result<Vec<String>, _>>()?)
    }

    /// Append a `run.finished` receipt at most once per `run_id`.
    ///
    /// A plain insert can duplicate a receipt when the writer's insert took
    /// effect but its acknowledgement was lost: the retry then appends a
    /// second row for the same run. This is one conditional
    /// `INSERT ... SELECT ... WHERE NOT EXISTS` over the same journal, so a
    /// retry, a double write and a fallback after a full write are all no-ops
    /// once the run has a receipt. Returns the new row id, or `None` when the
    /// run already had one (at most one `run.finished` row per `run_id`).
    ///
    /// The `json_valid` guard is what keeps a single malformed-JSON
    /// `run.finished` row from making `json_extract` raise inside the
    /// `NOT EXISTS`, which would otherwise poison every later receipt write.
    pub fn log_run_finished_once(
        &self,
        run_id: &str,
        payload: &str,
    ) -> Result<Option<i64>, StoreError> {
        let inserted = self.conn.execute(
            "INSERT INTO events(kind, payload)
             SELECT 'run.finished', ?1
              WHERE NOT EXISTS (
                    SELECT 1 FROM events
                     WHERE kind = 'run.finished'
                       AND json_valid(payload)
                       AND json_extract(payload, '$.run_id') = ?2
              )",
            rusqlite::params![payload, run_id],
        )?;
        if inserted == 0 {
            return Ok(None);
        }
        Ok(Some(self.conn.last_insert_rowid()))
    }

    /// Count events of a given kind.
    pub fn event_count(&self, kind: &str) -> Result<i64, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind = ?1 OR kind = ?2",
            rusqlite::params![kind, legacy_event_kind(kind)],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// The payloads of every event of a given kind, oldest first (tests and
    /// diagnostics: the audit rows' content, not just their count).
    pub fn event_payloads(&self, kind: &str) -> Result<Vec<String>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT payload FROM events WHERE (kind = ?1 OR kind = ?2) ORDER BY id")?;
        let payloads = statement
            .query_map(rusqlite::params![kind, legacy_event_kind(kind)], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(payloads)
    }

    /// Bound the `run.finished` receipt journal.
    ///
    /// Keeps only rows that are both within the newest `keep` **per agent**
    /// (`json_extract(payload, '$.agent')`) **and** newer than `days`; each is
    /// a ceiling, so the smaller retained set wins. Partitioning by agent stops
    /// a burst from one agent evicting another agent's recent receipts.
    /// `events.created_at` is UTC, so the age bound is too. Returns the number
    /// of rows removed.
    pub fn prune_run_receipts(&self, keep: i64, days: i64) -> Result<usize, StoreError> {
        let removed = self.conn.execute(
            "DELETE FROM events
              WHERE kind = 'run.finished'
                AND (
                    id NOT IN (
                        SELECT id FROM (
                            SELECT id,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY COALESCE(json_extract(payload, '$.agent'), json_extract(payload, '$.dot'))
                                       ORDER BY id DESC
                                   ) AS rn
                              FROM events
                             WHERE kind = 'run.finished'
                        )
                         WHERE rn <= ?1
                    )
                    OR created_at < datetime('now', ?2)
                )",
            rusqlite::params![keep.max(0), format!("-{} days", days.max(0))],
        )?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_recorded_and_counted() {
        let store = Store::open_in_memory().unwrap();
        store.log_event("test", r#"{"hello":true}"#).unwrap();
        let id = store.log_event_id("test", "{}").unwrap();
        store.log_event("other", "{}").unwrap();

        assert_eq!(store.event_count("test").unwrap(), 2);
        assert_eq!(store.event_count("other").unwrap(), 1);
        assert_eq!(store.event_count("missing").unwrap(), 0);
        let ids: Vec<i64> = store
            .conn
            .prepare("SELECT id FROM events WHERE kind = 'test' ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(ids, vec![id - 1, id], "row ids are returned in order");
    }

    #[test]
    fn run_receipt_is_written_at_most_once_per_run_id() {
        let store = Store::open_in_memory().unwrap();
        let first = store
            .log_run_finished_once("turn-1", r#"{"run_id":"turn-1","n":1}"#)
            .unwrap();
        assert!(first.is_some(), "the first write inserts a row");
        assert_eq!(store.event_count("run.finished").unwrap(), 1);

        // A retry, a duplicate write and a later payload for the same run are
        // all no-ops; a different run still writes.
        assert!(
            store
                .log_run_finished_once("turn-1", r#"{"run_id":"turn-1","n":2}"#)
                .unwrap()
                .is_none(),
            "a second write for the same run is skipped"
        );
        assert_eq!(store.event_count("run.finished").unwrap(), 1);
        assert!(store
            .log_run_finished_once("turn-2", r#"{"run_id":"turn-2"}"#)
            .unwrap()
            .is_some());
        assert_eq!(store.event_count("run.finished").unwrap(), 2);

        // The original row survives, not the skipped payload.
        let payload: String = store
            .conn
            .query_row(
                "SELECT payload FROM events
                  WHERE kind = 'run.finished'
                    AND json_extract(payload, '$.run_id') = 'turn-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(payload, r#"{"run_id":"turn-1","n":1}"#);
    }

    #[test]
    fn run_receipt_write_survives_a_malformed_row() {
        let store = Store::open_in_memory().unwrap();
        // A malformed row (for example a truncated write from an older
        // process) must not make `json_extract` raise and poison the dedupe.
        store.log_event("run.finished", "not json").unwrap();

        let inserted = store
            .log_run_finished_once("turn-1", r#"{"run_id":"turn-1"}"#)
            .unwrap();
        assert!(
            inserted.is_some(),
            "a clean write must still land past a malformed row"
        );
        assert_eq!(store.event_count("run.finished").unwrap(), 2);

        // And the dedupe still works for the run that was just written.
        assert!(store
            .log_run_finished_once("turn-1", r#"{"run_id":"turn-1","n":2}"#)
            .unwrap()
            .is_none());
        assert_eq!(store.event_count("run.finished").unwrap(), 2);
    }

    #[test]
    fn run_receipts_prune_by_count() {
        let store = Store::open_in_memory().unwrap();
        for n in 0..5 {
            store
                .log_event("run.finished", &format!("{{\"n\":{n}}}"))
                .unwrap();
        }
        assert_eq!(store.event_count("run.finished").unwrap(), 5);

        let removed = store.prune_run_receipts(2, 90).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(store.event_count("run.finished").unwrap(), 2);
        let kept: Vec<String> = store
            .conn
            .prepare("SELECT payload FROM events WHERE kind = 'run.finished' ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(kept, vec!["{\"n\":3}".to_string(), "{\"n\":4}".to_string()]);
    }

    #[test]
    fn run_receipts_prune_per_agent_not_globally() {
        let store = Store::open_in_memory().unwrap();
        // A burst from agent `a` must not evict agent `b`'s recent receipts.
        for n in 0..4 {
            store
                .log_event("run.finished", &format!(r#"{{"agent":"a","n":{n}}}"#))
                .unwrap();
        }
        for n in 0..2 {
            store
                .log_event("run.finished", &format!(r#"{{"agent":"b","n":{n}}}"#))
                .unwrap();
        }

        let removed = store.prune_run_receipts(2, 90).unwrap();
        assert_eq!(removed, 2, "only agent a's two oldest rows are dropped");
        let kept: Vec<String> = store
            .conn
            .prepare("SELECT payload FROM events WHERE kind = 'run.finished' ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            kept,
            vec![
                r#"{"agent":"a","n":2}"#.to_string(),
                r#"{"agent":"a","n":3}"#.to_string(),
                r#"{"agent":"b","n":0}"#.to_string(),
                r#"{"agent":"b","n":1}"#.to_string(),
            ]
        );
    }

    #[test]
    fn run_receipts_prune_by_age_even_under_the_row_cap() {
        let store = Store::open_in_memory().unwrap();
        store
            .log_event("run.finished", r#"{"recent":true}"#)
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO events(created_at, kind, payload)
                 VALUES (datetime('now', '-400 days'), 'run.finished', '{\"old\":true}')",
                [],
            )
            .unwrap();
        store.log_event("other", "{}").unwrap();
        assert_eq!(store.event_count("run.finished").unwrap(), 2);

        let removed = store.prune_run_receipts(100, 90).unwrap();
        assert_eq!(removed, 1, "only the out-of-window row is dropped");
        assert_eq!(store.event_count("run.finished").unwrap(), 1);
        assert_eq!(store.event_count("other").unwrap(), 1, "other kinds stay");
    }

    #[test]
    fn events_have_a_composite_kind_created_index() {
        let store = Store::open_in_memory().unwrap();
        let indexes: Vec<String> = store
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'events'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(indexes.iter().any(|name| name == "idx_events_kind_created"));
    }

    #[test]
    fn historical_dot_event_kinds_and_payloads_are_found_under_agent_names() {
        let store = Store::open_in_memory().unwrap();
        store.log_event("dot.created", r#"{"dot":"main"}"#).unwrap();
        store
            .log_event("agent.created", r#"{"agent":"scout"}"#)
            .unwrap();

        assert_eq!(store.event_count("agent.created").unwrap(), 2);
        assert_eq!(store.event_count("dot.created").unwrap(), 1);
        let payloads = store.event_payloads("agent.created").unwrap();
        assert_eq!(payloads, vec![r#"{"dot":"main"}"#, r#"{"agent":"scout"}"#]);
    }
}
