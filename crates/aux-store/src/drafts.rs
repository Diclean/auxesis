//! The local `mail.draft` rows and their single-use send state.
//!
//! A draft is one `mail.draft` event; its id is the event id. A send claims it
//! in `mail_draft_claim` before any socket, so a replay or a second approval
//! cannot send the same draft twice. A failed send releases the claim and the
//! draft stays retryable; a successful one marks it `sent`.

use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use crate::{Store, StoreError};

/// One stored draft, as `mail_draft` wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDraft {
    /// The `mail.draft` event id.
    pub id: i64,
    /// The resolved recipient addresses.
    pub to: Vec<String>,
    /// One human line per address, e.g. `Northwind <camille@northwind.example>`.
    pub to_display: Vec<String>,
    pub subject: String,
    pub body: String,
}

/// Parse one `mail.draft` payload. Anything malformed is not a draft.
fn parse_draft(id: i64, payload: &str) -> Option<StoredDraft> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    let list = |field: &str| -> Vec<String> {
        value
            .get(field)
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(StoredDraft {
        id,
        to: list("to"),
        to_display: list("to_display"),
        subject: value.get("subject")?.as_str()?.to_string(),
        body: value.get("body")?.as_str()?.to_string(),
    })
}

impl Store {
    /// The draft `id` when it exists and no send has claimed it: the value
    /// loaded before the card, never after.
    pub fn mail_draft_for_send(&self, id: i64) -> Result<Option<StoredDraft>, StoreError> {
        let payload: Option<String> = self
            .conn
            .query_row(
                "SELECT payload FROM events AS e
                  WHERE e.id = ?1 AND e.kind = 'mail.draft'
                    AND NOT EXISTS (SELECT 1 FROM mail_draft_claim AS c WHERE c.draft_id = e.id)",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload.and_then(|payload| parse_draft(id, &payload)))
    }

    /// Claim the draft for one send. Atomic: two callers cannot both get it.
    /// `None` means unknown, malformed, already claimed or already sent.
    pub fn claim_mail_draft(&self, id: i64) -> Result<Option<StoredDraft>, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let payload: Option<String> = tx
            .query_row(
                "SELECT payload FROM events WHERE id = ?1 AND kind = 'mail.draft'",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let Some(draft) = parse_draft(id, &payload) else {
            return Ok(None);
        };
        let claimed: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mail_draft_claim WHERE draft_id = ?1",
            [id],
            |row| row.get(0),
        )?;
        if claimed > 0 {
            return Ok(None);
        }
        tx.execute(
            "INSERT INTO mail_draft_claim(draft_id, state) VALUES (?1, 'claimed')",
            params![id],
        )?;
        tx.commit()?;
        Ok(Some(draft))
    }

    /// The one accepted send is done: the draft can never be sent again.
    pub fn mark_mail_draft_sent(&self, id: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE mail_draft_claim SET state = 'sent', sent_at = datetime('now')
              WHERE draft_id = ?1 AND state = 'claimed'",
            params![id],
        )?;
        Ok(())
    }

    /// The server may have accepted the message: the draft can never be sent
    /// as this row again.
    pub fn mark_mail_draft_uncertain(&self, id: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE mail_draft_claim SET state = 'uncertain'
              WHERE draft_id = ?1 AND state = 'claimed'",
            params![id],
        )?;
        Ok(())
    }

    /// A failed send gives the draft back, unsent and retryable.
    pub fn release_mail_draft(&self, id: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM mail_draft_claim WHERE draft_id = ?1 AND state = 'claimed'",
            params![id],
        )?;
        Ok(())
    }

    /// Test seam: rewrite one stored draft in place, for the race where the
    /// row changes between the card and the approve. Debug builds only.
    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn rewrite_mail_draft_for_test(&self, id: i64, payload: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE events SET payload = ?1 WHERE id = ?2 AND kind = 'mail.draft'",
            params![payload, id],
        )?;
        Ok(())
    }

    /// A daemon start adopts every claim left by a dead process as
    /// `uncertain`: a crash after the claim must never look sendable again.
    /// Run once, before the daemon serves a turn (never on a per-turn open,
    /// where another lane's live claim would be misread).
    pub fn recover_mail_draft_claims(&self) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE mail_draft_claim SET state = 'uncertain' WHERE state = 'claimed'",
            [],
        )?;
        Ok(())
    }

    /// `claimed`, `sent` or `uncertain` for a draft; `None` when never claimed.
    pub fn mail_draft_state(&self, id: i64) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT state FROM mail_draft_claim WHERE draft_id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?)
    }
}
