//! The evidence registry: the documents the store has seen.
//!
//! A document is registered once, by the SHA-256 of its bytes; the
//! registry keeps one row per document and appends each source it
//! arrived from.

use super::*;

impl Store {
    /// The `documents.id` already registered for `content_hash`, if any.
    pub fn evidence_document_id(&self, content_hash: &str) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM documents WHERE content_hash = ?1",
                [content_hash],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Whether a prior owner erase is still removing this hash's blob.
    pub fn evidence_erasure_pending(&self, content_hash: &str) -> Result<bool, StoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM evidence_erase_tombstones WHERE content_hash = ?1)",
            [content_hash],
            |row| row.get(0),
        )?)
    }

    /// Append one original to the evidence registry.
    ///
    /// A known `content_hash` is not stored twice: this returns the existing
    /// `documents.id` with `duplicate = true`. Otherwise a new `documents` row
    /// is inserted with `source = 'imap'` and `state = 'unverified'`. Either
    /// way one `evidence_source` row is inserted (ignored when the same
    /// `(document_id, source)` pair already exists), so a known hash fetched
    /// from a second message gains a source without a second blob.
    ///
    /// The write runs under one `IMMEDIATE` transaction, so the read-then-insert
    /// in [`Self::append_evidence`] cannot race another writer. The blob file
    /// is written by the caller **before** this call; if the hash is already
    /// known the caller skips the write, and if this call fails the orphan blob
    /// is inert.
    pub fn append_evidence(
        &self,
        document: &NewEvidenceDocument<'_>,
        source_json: &str,
        seen_at: &str,
    ) -> Result<EvidenceAppend, StoreError> {
        validate_evidence(document, source_json, seen_at)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let erasure_pending: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM evidence_erase_tombstones WHERE content_hash = ?1)",
            [document.content_hash],
            |row| row.get(0),
        )?;
        if erasure_pending {
            return Err(StoreError::EvidenceRejected {
                reason: "owner erase is still removing this document".into(),
            });
        }
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM documents WHERE content_hash = ?1",
                [document.content_hash],
                |row| row.get(0),
            )
            .optional()?;
        let (document_id, duplicate) = match existing {
            Some(id) => (id, true),
            None => {
                tx.execute(
                    "INSERT INTO documents(
                         content_hash, storage_path, size_bytes, mime_type, kind, source,
                         account_id, original_name, captured_at, state)
                     VALUES (?1, ?2, ?3, ?4, NULL, 'imap', ?5, ?6, ?7, 'unverified')",
                    rusqlite::params![
                        document.content_hash,
                        document.storage_path,
                        document.size_bytes,
                        document.mime_type,
                        document.account_id,
                        document.original_name,
                        document.captured_at,
                    ],
                )?;
                (tx.last_insert_rowid(), false)
            }
        };
        // The contract is idempotent: the same provenance is never stored
        // twice. The check runs inside the IMMEDIATE transaction, so the no-op
        // is race-free; the insert guards would also refuse a REPLACE.
        let already: Option<i64> = tx
            .query_row(
                "SELECT id FROM evidence_source WHERE document_id = ?1 AND source = ?2",
                rusqlite::params![document_id, source_json],
                |row| row.get(0),
            )
            .optional()?;
        if already.is_none() {
            tx.execute(
                "INSERT OR IGNORE INTO evidence_source(document_id, source, seen_at)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![document_id, source_json, seen_at],
            )?;
        }
        tx.commit()?;
        Ok(EvidenceAppend {
            document_id,
            duplicate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_registry_dedupes_by_hash_and_adds_a_second_source() {
        let store = Store::open_in_memory().unwrap();
        let hash = "a".repeat(64);
        let document = NewEvidenceDocument {
            content_hash: &hash,
            storage_path: "evidence/aaa",
            size_bytes: 12,
            mime_type: "application/pdf",
            original_name: "invoice.pdf",
            account_id: "personal",
            captured_at: "2026-10-11T09:00:00Z",
        };
        let first = store
            .append_evidence(&document, &imap_source(42), "2026-10-11T09:00:00Z")
            .unwrap();
        assert!(!first.duplicate);
        assert_eq!(
            store.evidence_document_id(&hash).unwrap(),
            Some(first.document_id)
        );

        // The same hash from a second message: no second document, a new source.
        let second = store
            .append_evidence(&document, &imap_source(43), "2026-10-11T09:05:00Z")
            .unwrap();
        assert!(second.duplicate);
        assert_eq!(second.document_id, first.document_id);

        let documents: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(documents, 1, "one row for one hash");
        let sources: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM evidence_source", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sources, 2, "each provenance is one append-only row");
        let state: String = store
            .conn
            .query_row("SELECT state FROM documents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "unverified");
    }

    #[test]
    fn evidence_source_is_append_only_against_update_delete_and_replace() {
        let store = Store::open_in_memory().unwrap();
        let hash = "b".repeat(64);
        let document = NewEvidenceDocument {
            content_hash: &hash,
            storage_path: "evidence/bbb",
            size_bytes: 3,
            mime_type: "image/png",
            original_name: "scan.png",
            account_id: "personal",
            captured_at: "2026-10-11T09:00:00Z",
        };
        store
            .append_evidence(&document, &imap_source(7), "2026-10-11T09:00:00Z")
            .unwrap();

        assert!(
            store
                .conn
                .execute("UPDATE evidence_source SET seen_at = 'rewritten'", [])
                .is_err(),
            "UPDATE must abort"
        );
        assert!(
            store
                .conn
                .execute("DELETE FROM evidence_source", [])
                .is_err(),
            "DELETE must abort"
        );
        assert!(
            store
                .conn
                .execute(
                    "INSERT OR REPLACE INTO evidence_source(id, document_id, source, seen_at)
                     VALUES (1, 1, '{}', 'rewritten')",
                    [],
                )
                .is_err(),
            "REPLACE must abort before the existing row is deleted"
        );
        assert!(
            store
                .conn
                .execute("UPDATE documents SET content_hash = 'c' WHERE id = 1", [],)
                .is_err(),
            "a document's hash is immutable"
        );
    }

    #[test]
    fn evidence_source_replace_without_an_id_is_refused_and_keeps_the_row() {
        let store = Store::open_in_memory().unwrap();
        let hash = "f".repeat(64);
        let document = NewEvidenceDocument {
            content_hash: &hash,
            storage_path: "evidence/fff",
            size_bytes: 4,
            mime_type: "application/pdf",
            original_name: "f.pdf",
            account_id: "personal",
            captured_at: "2026-10-11T09:00:00Z",
        };
        let source = imap_source(9);
        let first = store
            .append_evidence(&document, &source, "2026-10-11T09:00:00Z")
            .unwrap();
        // The same provenance is an idempotent no-op, not a second row.
        let again = store
            .append_evidence(&document, &source, "2026-10-11T09:05:00Z")
            .unwrap();
        assert_eq!(again.document_id, first.document_id);
        assert!(again.duplicate);
        let rows: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM evidence_source", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "one row for one (document_id, source) pair");

        let row = |store: &Store| -> (i64, i64, String, String) {
            store
                .conn
                .query_row(
                    "SELECT id, document_id, source, seen_at FROM evidence_source",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap()
        };
        let before = row(&store);
        // A REPLACE with no id gets a fresh rowid, so the id guard cannot fire;
        // the (document_id, source) guard must refuse it before SQLite deletes
        // the original row.
        assert!(
            store
                .conn
                .execute(
                    "INSERT OR REPLACE INTO evidence_source(document_id, source, seen_at)
                     VALUES (1, ?1, 'rewritten')",
                    rusqlite::params![source],
                )
                .is_err(),
            "a no-id REPLACE on the same source must abort"
        );
        assert_eq!(before, row(&store), "the original row must be unchanged");
    }

    #[test]
    fn evidence_rejects_a_non_sha256_hash_and_a_bad_source() {
        let store = Store::open_in_memory().unwrap();
        let document = NewEvidenceDocument {
            content_hash: "not-a-hash",
            storage_path: "evidence/x",
            size_bytes: 1,
            mime_type: "application/pdf",
            original_name: "x.pdf",
            account_id: "personal",
            captured_at: "2026-10-11T09:00:00Z",
        };
        assert!(matches!(
            store.append_evidence(&document, &imap_source(1), "2026-10-11T09:00:00Z"),
            Err(StoreError::EvidenceRejected { .. })
        ));
        let hash = "d".repeat(64);
        let document = NewEvidenceDocument {
            content_hash: &hash,
            ..document
        };
        assert!(matches!(
            store.append_evidence(&document, "not json", "2026-10-11T09:00:00Z"),
            Err(StoreError::EvidenceRejected { .. })
        ));
    }

    /// One evidence source JSON, as `mail.fetch_attachments` writes it.
    fn imap_source(uid: u32) -> String {
        format!(
            "{{\"imap\":{{\"account\":\"personal\",\"folder\":\"INBOX\",\"uid\":{uid},\
             \"message_id\":\"<{uid}@fixture.example>\",\"part\":\"2\",\"file_name\":\"invoice.pdf\"}}}}"
        )
    }
}
