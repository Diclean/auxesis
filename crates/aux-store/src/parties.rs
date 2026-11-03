//! The CRM: the people and companies, and what is owed to them.
//!
//! A party is one person or company in the address book; the
//! interactions, the follow-ups and the relationships all point at one.

use super::*;

impl Store {
    /// Insert one CRM party, stamped by the store. The party row and the `crm`
    /// contacts source commit in one transaction, so the next provider call
    /// tokenises the party's names with no other step. Returns the new row id.
    pub fn insert_party(&self, party: &NewParty) -> Result<i64, StoreError> {
        validate_party(party)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO party(kind, display_name, name_variants, emails, phones,
                               addresses, tags, notes, time_zone, origin, created_at, updated_at,
                               archived)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, datetime('now'), datetime('now'), 0)",
            rusqlite::params![
                party.kind.as_str(),
                party.display_name,
                json_list(&party.name_variants),
                json_list(&party.emails),
                json_list(&party.phones),
                json_list(&party.addresses),
                json_list(&party.tags),
                party.notes,
                party.time_zone,
                party.origin,
            ],
        )?;
        let id = tx.last_insert_rowid();
        sync_crm_contacts_in_tx(&tx)?;
        tx.commit()?;
        Ok(id)
    }

    /// One party by id, archived or not.
    pub fn party(&self, id: i64) -> Result<Option<Party>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, kind, display_name, name_variants, emails, phones, addresses,
                        tags, notes, origin, created_at, updated_at, archived, time_zone
                   FROM party WHERE id = ?1",
                [id],
                read_party,
            )
            .optional()?)
    }

    /// The live (non-archived) parties, oldest first.
    pub fn parties(&self) -> Result<Vec<Party>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT id, kind, display_name, name_variants, emails, phones, addresses,
                    tags, notes, origin, created_at, updated_at, archived, time_zone
               FROM party WHERE archived = 0 ORDER BY id",
        )?;
        let rows = statement.query_map([], read_party)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Remember that the owner declined to add this sender, so the brief never
    /// suggests the address again. Kept in `meta`, local to this store; bounded.
    pub fn ignore_sender(&self, email: &str) -> Result<(), StoreError> {
        let key = format!(
            "{IGNORED_SENDER_PREFIX}{}",
            email.trim().to_ascii_lowercase()
        );
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM meta WHERE key LIKE ?1",
            [format!("{IGNORED_SENDER_PREFIX}%")],
            |row| row.get(0),
        )?;
        if count < IGNORED_SENDERS_MAX {
            self.conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES (?1, '1')",
                [key],
            )?;
        }
        Ok(())
    }

    /// The addresses [`Store::ignore_sender`] recorded, lower-case.
    pub fn ignored_senders(&self) -> Result<std::collections::HashSet<String>, StoreError> {
        let mut statement = self
            .conn
            .prepare("SELECT key FROM meta WHERE key LIKE ?1")?;
        let rows = statement.query_map([format!("{IGNORED_SENDER_PREFIX}%")], |row| {
            row.get::<_, String>(0)
        })?;
        Ok(rows
            .filter_map(Result::ok)
            .filter_map(|key| key.strip_prefix(IGNORED_SENDER_PREFIX).map(str::to_string))
            .collect())
    }

    /// Allocate the next value of a named store-local counter, starting at 1.
    ///
    /// The counter is one `meta` row, bumped in one statement, so it survives a
    /// restart and two processes cannot read the same value. Readable ids that
    /// must never collide across runs are built from it (CRM-NOTE-P3).
    pub fn next_counter(&self, name: &str) -> Result<u64, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES (?1, '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(meta.value AS INTEGER) + 1 AS TEXT)",
            [name],
        )?;
        let value: i64 = tx.query_row(
            "SELECT CAST(value AS INTEGER) FROM meta WHERE key = ?1",
            [name],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(value.max(0) as u64)
    }

    /// The store's own UTC clock, as a strict RFC 3339 timestamp
    /// (`YYYY-MM-DDTHH:MM:SSZ`). A CRM write that cannot trust a
    /// model-supplied time stamps the row from here (CRM-TAINT-AT).
    pub fn now_rfc3339(&self) -> Result<String, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", [], |row| {
                row.get(0)
            })?)
    }

    /// Overwrite the mutable fields of a live party and refresh the `crm`
    /// contacts source in the same transaction. False when no live row has this
    /// id; an archived party is not edited by this call.
    pub fn update_party(&self, id: i64, party: &NewParty) -> Result<bool, StoreError> {
        validate_party(party)?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE party
                SET kind = ?1, display_name = ?2, name_variants = ?3, emails = ?4,
                    phones = ?5, addresses = ?6, tags = ?7, notes = ?8, time_zone = ?9,
                    origin = ?10, updated_at = datetime('now')
              WHERE id = ?11 AND archived = 0",
            rusqlite::params![
                party.kind.as_str(),
                party.display_name,
                json_list(&party.name_variants),
                json_list(&party.emails),
                json_list(&party.phones),
                json_list(&party.addresses),
                json_list(&party.tags),
                party.notes,
                party.time_zone,
                party.origin,
                id,
            ],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        sync_crm_contacts_in_tx(&tx)?;
        tx.commit()?;
        Ok(true)
    }

    /// Archive a live party: its rows stay, its names leave the contacts index.
    /// The archive and the refreshed `crm` source commit together. False when no
    /// live row has this id.
    pub fn archive_party(&self, id: i64) -> Result<bool, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE party SET archived = 1, updated_at = datetime('now')
              WHERE id = ?1 AND archived = 0",
            [id],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        sync_crm_contacts_in_tx(&tx)?;
        tx.commit()?;
        Ok(true)
    }

    /// Hard-delete a party and everything that points at it (the audited
    /// `aux crm forget <id>`): interactions, follow-ups, relationships, and its
    /// linked memory items. A surviving memory body would otherwise be recalled
    /// with the party's name unmasked, so the items go, not their `party_id`.
    /// Linked receipts stay, unlinked: they are the owner's documents, not the
    /// client's data. The FTS delete trigger keeps the search index clean. The
    /// refreshed `crm` contacts source commits with the delete. Returns false
    /// when the id is unknown. The audit row carries the id only, never a name.
    pub fn forget_party(&self, id: i64) -> Result<bool, StoreError> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM party WHERE id = ?1)",
            [id],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(false);
        }
        tx.execute("DELETE FROM interaction WHERE party_id = ?1", [id])?;
        tx.execute("DELETE FROM followup WHERE party_id = ?1", [id])?;
        tx.execute(
            "DELETE FROM relationship WHERE from_party = ?1 OR to_party = ?1",
            [id],
        )?;
        tx.execute("DELETE FROM memory_items WHERE party_id = ?1", [id])?;
        document_fields::relink_party_documents_in_tx(&tx, id, None)?;
        tx.execute("DELETE FROM party WHERE id = ?1", [id])?;
        tx.execute(
            "INSERT INTO events(kind, payload) VALUES ('crm.party_forgotten', ?1)",
            [format!("{{\"id\":{id}}}")],
        )?;
        sync_crm_contacts_in_tx(&tx)?;
        tx.commit()?;
        Ok(true)
    }

    /// Merge `from` into `to`: the source's timeline, follow-ups, memory,
    /// relationships and linked receipts move to the target, its names and
    /// addresses are absorbed, and the source is archived. A colliding interaction (the unique
    /// `(party_id, kind, source_ref)` key) is dropped, because the target
    /// already holds that event. False when either id is not a live party or
    /// they are the same.
    pub fn merge_parties(&self, from: i64, to: i64) -> Result<bool, StoreError> {
        if from == to {
            return Ok(false);
        }
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let target: Option<Party> = tx
            .query_row(
                "SELECT id, kind, display_name, name_variants, emails, phones, addresses,
                        tags, notes, origin, created_at, updated_at, archived, time_zone
                   FROM party WHERE id = ?1 AND archived = 0",
                [to],
                read_party,
            )
            .optional()?;
        let source: Option<Party> = tx
            .query_row(
                "SELECT id, kind, display_name, name_variants, emails, phones, addresses,
                        tags, notes, origin, created_at, updated_at, archived, time_zone
                   FROM party WHERE id = ?1 AND archived = 0",
                [from],
                read_party,
            )
            .optional()?;
        let (Some(mut target), Some(source)) = (target, source) else {
            return Ok(false);
        };
        tx.execute(
            "UPDATE OR IGNORE interaction SET party_id = ?1 WHERE party_id = ?2",
            [to, from],
        )?;
        tx.execute("DELETE FROM interaction WHERE party_id = ?1", [from])?;
        tx.execute(
            "UPDATE followup SET party_id = ?1 WHERE party_id = ?2",
            [to, from],
        )?;
        tx.execute(
            "UPDATE memory_items SET party_id = ?1 WHERE party_id = ?2",
            [to, from],
        )?;
        document_fields::relink_party_documents_in_tx(&tx, from, Some(to))?;
        tx.execute(
            "UPDATE relationship SET from_party = ?1 WHERE from_party = ?2 AND to_party <> ?1",
            [to, from],
        )?;
        tx.execute(
            "UPDATE relationship SET to_party = ?1 WHERE to_party = ?2 AND from_party <> ?1",
            [to, from],
        )?;
        tx.execute("DELETE FROM relationship WHERE from_party = to_party", [])?;
        tx.execute(
            "DELETE FROM relationship WHERE from_party = ?1 OR to_party = ?1",
            [from],
        )?;
        target.name_variants.push(target.display_name.clone());
        target.name_variants.push(source.display_name.clone());
        extend_unique(&mut target.name_variants, &source.name_variants);
        extend_unique(&mut target.emails, &source.emails);
        extend_unique(&mut target.phones, &source.phones);
        extend_unique(&mut target.addresses, &source.addresses);
        extend_unique(&mut target.tags, &source.tags);
        // The target's own zone wins; the source's fills a card that has none.
        if target.time_zone.is_none() {
            target.time_zone = source.time_zone.clone();
        }
        tx.execute(
            "UPDATE party
                SET name_variants = ?1, emails = ?2, phones = ?3, addresses = ?4,
                    tags = ?5, time_zone = ?6, updated_at = datetime('now')
              WHERE id = ?7",
            rusqlite::params![
                json_list(&target.name_variants),
                json_list(&target.emails),
                json_list(&target.phones),
                json_list(&target.addresses),
                json_list(&target.tags),
                target.time_zone,
                to,
            ],
        )?;
        tx.execute(
            "UPDATE party SET archived = 1, updated_at = datetime('now') WHERE id = ?1",
            [from],
        )?;
        sync_crm_contacts_in_tx(&tx)?;
        tx.commit()?;
        Ok(true)
    }

    /// Rebuild the `crm` source of the `contacts` table from the live parties.
    /// The kernel mounts the union of the enabled sources, so this is what makes
    /// the next provider call tokenise a party's names and addresses. Every
    /// party write already calls the in-transaction sync; this is the importer's
    /// entry point when many rows are written before one refresh.
    pub fn sync_crm_contacts(&self) -> Result<(), StoreError> {
        let records: Vec<ContactRecord> = self.parties()?.iter().map(party_contacts).collect();
        self.replace_source_contacts(CRM_CONTACT_SOURCE, &records)
    }

    /// Insert one interaction. The unique `(party_id, kind, source_ref)` key
    /// makes a re-seen mail or event idempotent: a duplicate returns `None`.
    pub fn insert_interaction(
        &self,
        party_id: i64,
        kind: &str,
        at: &str,
        source_ref: &str,
        summary: &str,
        provenance: &str,
    ) -> Result<Option<i64>, StoreError> {
        self.insert_interaction_marked(party_id, kind, at, source_ref, summary, provenance, false)
    }

    /// [`Store::insert_interaction`] with the row's taint flag. A tainted row's
    /// summary is not returned to the model (CRM-NOTE-P3).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_interaction_marked(
        &self,
        party_id: i64,
        kind: &str,
        at: &str,
        source_ref: &str,
        summary: &str,
        provenance: &str,
        tainted: bool,
    ) -> Result<Option<i64>, StoreError> {
        validate_interaction(kind, summary)?;
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO interaction(party_id, kind, at, source_ref, summary, provenance, tainted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                party_id,
                kind,
                at,
                source_ref,
                summary,
                provenance,
                i64::from(tainted)
            ],
        )?;
        if changed == 1 {
            Ok(Some(self.conn.last_insert_rowid()))
        } else {
            Ok(None)
        }
    }

    /// Insert one mail thread row, or refresh the row it already has when this
    /// view is as new or newer (`at`, summary, direction). Some(id) = new row.
    /// A row the owner logged by hand with the same key is never overwritten.
    pub fn upsert_mail_interaction(
        &self,
        party_id: i64,
        at: &str,
        source_ref: &str,
        summary: &str,
        direction: &str,
    ) -> Result<Option<i64>, StoreError> {
        validate_interaction("mail", summary)?;
        let before = self.conn.last_insert_rowid();
        self.conn.execute(
            "INSERT INTO interaction(party_id, kind, at, source_ref, summary, provenance, direction)
             VALUES (?1, 'mail', ?2, ?3, ?4, 'timeline.imap', ?5)
             ON CONFLICT(party_id, kind, source_ref) DO UPDATE SET at = excluded.at,
               summary = excluded.summary, direction = excluded.direction
             WHERE excluded.at >= interaction.at AND interaction.provenance = 'timeline.imap'",
            rusqlite::params![party_id, at, source_ref, summary, direction],
        )?;
        let id = self.conn.last_insert_rowid();
        Ok((id != before).then_some(id))
    }

    /// The interactions of one party, oldest first.
    pub fn interactions_for_party(&self, party_id: i64) -> Result<Vec<Interaction>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT id, party_id, kind, at, source_ref, summary, provenance, direction, tainted
               FROM interaction WHERE party_id = ?1 ORDER BY at, id",
        )?;
        let rows = statement.query_map([party_id], |row| {
            Ok(Interaction {
                id: row.get(0)?,
                party_id: row.get(1)?,
                kind: row.get(2)?,
                at: row.get(3)?,
                source_ref: row.get(4)?,
                summary: row.get(5)?,
                provenance: row.get(6)?,
                direction: row.get(7)?,
                tainted: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Insert one follow-up. Returns the new row id.
    pub fn insert_followup(
        &self,
        party_id: i64,
        due: &str,
        reason: &str,
        created_by: &str,
        status: &str,
    ) -> Result<i64, StoreError> {
        if !matches!(status, "open" | "done" | "dropped") {
            return Err(StoreError::CrmRejected {
                reason: "unknown follow-up status".into(),
            });
        }
        self.conn.execute(
            "INSERT INTO followup(party_id, due, reason, created_by, status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![party_id, due, reason, created_by, status],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The follow-ups of one party, earliest due first.
    pub fn followups_for_party(&self, party_id: i64) -> Result<Vec<Followup>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT id, party_id, due, reason, created_by, status
               FROM followup WHERE party_id = ?1 ORDER BY due, id",
        )?;
        let rows = statement.query_map([party_id], |row| {
            Ok(Followup {
                id: row.get(0)?,
                party_id: row.get(1)?,
                due: row.get(2)?,
                reason: row.get(3)?,
                created_by: row.get(4)?,
                status: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The open follow-ups of live parties whose `due` date is on or before
    /// `on_or_before` (a `YYYY-MM-DD` day), earliest due first (B4). The stored
    /// `due` may carry a time, so only its first ten characters are compared; a
    /// value that is not a date sorts by its text.
    pub fn open_followups_due(
        &self,
        on_or_before: &str,
        limit: usize,
    ) -> Result<Vec<DueFollowup>, StoreError> {
        let limit = i64::try_from(limit.min(500)).unwrap_or(500);
        let mut statement = self.conn.prepare(
            "SELECT f.id, f.party_id, f.due, f.reason, f.created_by, f.status, p.display_name
               FROM followup f JOIN party p ON p.id = f.party_id
              WHERE f.status = 'open' AND p.archived = 0
                AND substr(f.due, 1, 10) <= ?1
              ORDER BY f.due, f.id LIMIT ?2",
        )?;
        let rows = statement.query_map(rusqlite::params![on_or_before, limit], |row| {
            Ok(DueFollowup {
                party_id: row.get(1)?,
                display_name: row.get(6)?,
                followup: Followup {
                    id: row.get(0)?,
                    party_id: row.get(1)?,
                    due: row.get(2)?,
                    reason: row.get(3)?,
                    created_by: row.get(4)?,
                    status: row.get(5)?,
                },
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Insert one relationship. Returns the new row id.
    pub fn insert_relationship(
        &self,
        from_party: i64,
        to_party: i64,
        kind: &str,
        since: Option<&str>,
        until: Option<&str>,
        note: &str,
    ) -> Result<i64, StoreError> {
        if !matches!(kind, "works_at" | "reports_to" | "invoices" | "other") {
            return Err(StoreError::CrmRejected {
                reason: "unknown relationship kind".into(),
            });
        }
        self.conn.execute(
            "INSERT INTO relationship(from_party, to_party, kind, since, until, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![from_party, to_party, kind, since, until, note],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// The relationships touching one party, oldest first.
    pub fn relationships_for_party(&self, party_id: i64) -> Result<Vec<Relationship>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT id, from_party, to_party, kind, since, until, note
               FROM relationship WHERE from_party = ?1 OR to_party = ?1 ORDER BY id",
        )?;
        let rows = statement.query_map([party_id], |row| {
            Ok(Relationship {
                id: row.get(0)?,
                from_party: row.get(1)?,
                to_party: row.get(2)?,
                kind: row.get(3)?,
                since: row.get(4)?,
                until: row.get(5)?,
                note: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn open_followups_due_lists_live_open_rows_on_or_before_the_day() {
        let store = Store::open_in_memory().unwrap();
        let a = store.insert_party(&camille_party()).unwrap();
        let b = store
            .insert_party(&NewParty {
                display_name: "Jonas Weber".to_string(),
                origin: "owner".to_string(),
                ..NewParty::default()
            })
            .unwrap();
        store
            .insert_followup(a, "2026-10-04", "past", "owner", "open")
            .unwrap();
        store
            .insert_followup(a, "2026-10-05T09:00:00Z", "today", "owner", "open")
            .unwrap();
        store
            .insert_followup(b, "2026-10-06", "future", "owner", "open")
            .unwrap();
        store
            .insert_followup(b, "2026-10-01", "done", "owner", "done")
            .unwrap();

        let due = store.open_followups_due("2026-10-05", 10).unwrap();
        assert_eq!(due.len(), 2, "{due:?}");
        assert_eq!(due[0].followup.reason, "past");
        assert_eq!(due[0].display_name, "Camille Exemple");
        assert_eq!(due[1].followup.reason, "today");
        assert_eq!(due[1].party_id, a);

        // An archived party drops out even when its follow-up is due.
        store.archive_party(b).unwrap();
        assert_eq!(store.open_followups_due("2026-10-06", 10).unwrap().len(), 2);
    }

    #[test]
    fn fresh_store_has_the_crm_schema() {
        let store = Store::open_in_memory().unwrap();
        for table in ["party", "relationship", "interaction", "followup"] {
            assert!(
                !table_columns(&store, table).is_empty(),
                "{table} must exist at v22"
            );
        }
        assert!(table_columns(&store, "memory_items").contains(&"party_id".to_string()));
    }

    #[test]
    fn a_party_round_trips_and_updates() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_party(&camille_party()).unwrap();
        let stored = store.party(id).unwrap().unwrap();
        assert_eq!(stored.kind, PartyKind::Person);
        assert_eq!(stored.display_name, "Camille Exemple");
        assert_eq!(stored.name_variants, vec!["Camille", "Exemple"]);
        assert_eq!(stored.emails, vec!["camille.exemple@exemple.test"]);
        assert!(!stored.archived);
        assert!(!stored.created_at.is_empty());

        let mut updated = camille_party();
        updated.display_name = "Camille Exemple-Weber".to_string();
        updated.tags = vec!["client".to_string()];
        assert!(store.update_party(id, &updated).unwrap());
        let stored = store.party(id).unwrap().unwrap();
        assert_eq!(stored.display_name, "Camille Exemple-Weber");
        assert_eq!(stored.tags, vec!["client"]);
        assert!(!store.update_party(id + 1, &updated).unwrap());
    }

    #[test]
    fn a_phone_that_is_not_e164_is_refused_and_nothing_is_written() {
        let store = Store::open_in_memory().unwrap();
        let mut party = camille_party();
        party.phones = vec!["06 12 34 56 78".to_string()];
        assert!(matches!(
            store.insert_party(&party),
            Err(StoreError::CrmRejected { .. })
        ));
        assert!(store.parties().unwrap().is_empty());
    }

    #[test]
    fn sync_puts_the_live_parties_in_the_contacts_source() {
        let store = Store::open_in_memory().unwrap();
        store.sync_crm_contacts().unwrap();
        assert!(store.contacts().unwrap().is_empty());

        let id = store.insert_party(&camille_party()).unwrap();
        store.sync_crm_contacts().unwrap();
        let crm: Vec<ContactRecord> = store
            .contacts()
            .unwrap()
            .into_iter()
            .filter(|record| record.source == CRM_CONTACT_SOURCE)
            .collect();
        assert_eq!(crm.len(), 1);
        assert_eq!(crm[0].display_name.as_deref(), Some("Camille Exemple"));
        assert!(crm[0].nicknames.contains(&"Camille".to_string()));
        assert_eq!(crm[0].emails, vec!["camille.exemple@exemple.test"]);
        assert_eq!(crm[0].phones, vec!["+33612345678"]);

        // Archiving removes the party from the next sync, and the version moves.
        let before = store.contacts_version().unwrap();
        store.archive_party(id).unwrap();
        store.sync_crm_contacts().unwrap();
        assert!(store
            .contacts()
            .unwrap()
            .iter()
            .all(|record| record.source != CRM_CONTACT_SOURCE));
        assert!(store.contacts_version().unwrap() > before);
    }

    #[test]
    fn every_store_party_write_refreshes_the_index_by_itself() {
        let store = Store::open_in_memory().unwrap();
        let names = |store: &Store| -> Vec<String> {
            store
                .contacts()
                .unwrap()
                .into_iter()
                .filter(|record| record.source == CRM_CONTACT_SOURCE)
                .flat_map(|record| record.nicknames)
                .collect()
        };

        // Create.
        let a = store.insert_party(&camille_party()).unwrap();
        assert!(names(&store).contains(&"Camille".to_string()));

        // Update: the new variant is in, the old one is gone.
        let mut edited = camille_party();
        edited.display_name = "Camille Exemple-Weber".to_string();
        edited.name_variants = vec!["Camille Exemple-Weber".to_string()];
        assert!(store.update_party(a, &edited).unwrap());
        assert!(names(&store).contains(&"Camille Exemple-Weber".to_string()));
        assert!(!names(&store).contains(&"Camille".to_string()));

        // Merge: the target absorbs the source's names and the source leaves.
        let b = store
            .insert_party(&NewParty {
                display_name: "Jonas Weber".to_string(),
                name_variants: vec!["Jonas".to_string()],
                origin: "owner".to_string(),
                ..NewParty::default()
            })
            .unwrap();
        assert!(store.merge_parties(a, b).unwrap());
        let merged = names(&store);
        assert!(merged.contains(&"Camille Exemple-Weber".to_string()));
        assert!(merged.contains(&"Jonas".to_string()));

        // Archive.
        let c = store.insert_party(&camille_party()).unwrap();
        assert!(names(&store).contains(&"Camille".to_string()));
        assert!(store.archive_party(c).unwrap());
        assert!(!names(&store).contains(&"Camille".to_string()));

        // Forget.
        assert!(store.forget_party(b).unwrap());
        assert!(names(&store).is_empty());
    }

    #[test]
    fn forgetting_a_party_removes_everything_that_points_at_it() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_party(&camille_party()).unwrap();
        let other = store
            .insert_party(&NewParty {
                display_name: "Jonas Weber".to_string(),
                origin: "owner".to_string(),
                ..NewParty::default()
            })
            .unwrap();
        let _ = store
            .insert_interaction(
                id,
                "mail",
                "2026-10-01T10:00:00Z",
                "{\"imap\":1}",
                "Re: devis",
                "owner",
            )
            .unwrap();
        store
            .insert_followup(id, "2026-10-05", "relancer", "owner", "open")
            .unwrap();
        store
            .insert_relationship(id, other, "invoices", None, None, "")
            .unwrap();
        // A memory item tied to the party is deleted with it: a surviving body
        // would be recalled with the party's name unmasked.
        let item = store
            .create_memory_item(
                "main",
                &NewMemoryItem {
                    kind: "fact",
                    title: "t",
                    body: "b",
                    fact_key: None,
                    confidence: None,
                    source: "owner",
                    trust: "owner",
                    tainted: false,
                    state: "active",
                    supersedes_id: None,
                    valid_from: None,
                    valid_to: None,
                },
            )
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE memory_items SET party_id = ?1 WHERE id = ?2",
                rusqlite::params![id, item.id],
            )
            .unwrap();
        assert_eq!(store.search_memory("main", "b", 8).unwrap().len(), 1);

        assert!(store.forget_party(id).unwrap());
        assert!(store.party(id).unwrap().is_none());
        assert!(store.interactions_for_party(id).unwrap().is_empty());
        assert!(store.followups_for_party(id).unwrap().is_empty());
        assert!(store.relationships_for_party(other).unwrap().is_empty());
        // The linked memory item is gone, not unlinked: no body survives to be
        // recalled, and the FTS index drops it with the row.
        let survivors: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM memory_items WHERE party_id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(survivors, 0, "linked memory items are deleted");
        assert!(store.memory_item("main", item.id).unwrap().is_none());
        assert_eq!(
            store.search_memory("main", "b", 8).unwrap().len(),
            0,
            "the FTS index no longer returns the deleted body"
        );
        // The audit row carries the id only, never a name.
        assert_eq!(store.event_count("crm.party_forgotten").unwrap(), 1);
        let payloads = store.event_payloads("crm.party_forgotten").unwrap();
        assert_eq!(payloads, vec![format!("{{\"id\":{id}}}")]);
        assert!(!store.forget_party(id).unwrap());
    }

    #[test]
    fn forgetting_a_party_keeps_its_linked_receipt_and_unlinks_it() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_party(&camille_party()).unwrap();
        let receipt = link_receipt(&store, &"a".repeat(64), id);
        store
            .conn
            .execute(
                "UPDATE document_fields SET extracted_text = 'OCR text retained before forget'
              WHERE document_id = ?1",
                [receipt],
            )
            .unwrap();

        assert!(store.forget_party(id).unwrap());
        assert!(store.party(id).unwrap().is_none());
        // The receipt is the owner's: its row and fields stay, only the link goes.
        let (party_id, checks, fields) = receipt_link(&store, receipt);
        assert_eq!(party_id, None);
        assert_eq!(fields, "{\"issuer\":\"Camille Exemple\"}");
        let check = party_check(&checks);
        assert_eq!(check["state"], "unknown");
        assert_eq!(check["reason"], "client forgotten");
        assert!(
            store.recent_document_texts().unwrap().is_empty(),
            "forgetting a party retained linked document OCR text"
        );
        // The other checks are untouched.
        assert!(checks.contains("\"reason\":\"totals add up\""));
    }

    #[test]
    fn forgetting_a_party_with_no_receipts_leaves_other_receipts_alone() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_party(&camille_party()).unwrap();
        let other = store
            .insert_party(&NewParty {
                display_name: "Jonas Weber".to_string(),
                origin: "owner".to_string(),
                ..NewParty::default()
            })
            .unwrap();
        let receipt = link_receipt(&store, &"b".repeat(64), other);
        let before = receipt_link(&store, receipt);

        assert!(store.forget_party(id).unwrap());
        assert_eq!(receipt_link(&store, receipt), before);
    }

    #[test]
    fn a_receipt_with_unreadable_checks_does_not_block_forgetting() {
        let store = Store::open_in_memory().unwrap();
        let id = store.insert_party(&camille_party()).unwrap();
        let receipt = link_receipt(&store, &"c".repeat(64), id);
        store
            .conn
            .execute(
                "UPDATE document_fields SET checks_json = 'not json' WHERE document_id = ?1",
                [receipt],
            )
            .unwrap();

        assert!(store.forget_party(id).unwrap());
        let (party_id, checks, _) = receipt_link(&store, receipt);
        assert_eq!((party_id, checks.as_str()), (None, "not json"));
    }

    #[test]
    fn merging_parties_moves_their_receipts_to_the_target() {
        let store = Store::open_in_memory().unwrap();
        let from = store.insert_party(&camille_party()).unwrap();
        let to = store
            .insert_party(&NewParty {
                display_name: "Camille Exemple SARL".to_string(),
                origin: "owner".to_string(),
                ..NewParty::default()
            })
            .unwrap();
        let receipt = link_receipt(&store, &"d".repeat(64), from);

        assert!(store.merge_parties(from, to).unwrap());
        let (party_id, checks, _) = receipt_link(&store, receipt);
        assert_eq!(party_id, Some(to));
        let check = party_check(&checks);
        assert_eq!(check["state"], "pass");
        assert_eq!(check["reason"], format!("matched CRM party {to}"));
        // The target can now be forgotten without a foreign-key error.
        assert!(store.forget_party(to).unwrap());
        assert_eq!(receipt_link(&store, receipt).0, None);
    }

    #[test]
    fn a_failed_forget_or_merge_leaves_the_receipt_link_as_it_was() {
        let store = Store::open_in_memory().unwrap();
        let from = store.insert_party(&camille_party()).unwrap();
        let to = store
            .insert_party(&NewParty {
                display_name: "Jonas Weber".to_string(),
                origin: "owner".to_string(),
                ..NewParty::default()
            })
            .unwrap();
        let receipt = link_receipt(&store, &"e".repeat(64), from);
        let before = receipt_link(&store, receipt);
        // The last step of each write fails after the receipt was rewritten.
        store
            .conn
            .execute_batch(
                "CREATE TEMP TRIGGER fail_party_delete BEFORE DELETE ON party
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;
                 CREATE TEMP TRIGGER fail_party_archive BEFORE UPDATE OF archived ON party
                 BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .unwrap();

        assert!(store.forget_party(from).is_err());
        assert_eq!(receipt_link(&store, receipt), before);
        assert!(store.merge_parties(from, to).is_err());
        assert_eq!(receipt_link(&store, receipt), before);
    }

    #[test]
    fn merging_parties_moves_rows_and_archives_the_source() {
        let store = Store::open_in_memory().unwrap();
        let a = store.insert_party(&camille_party()).unwrap();
        let b = store
            .insert_party(&NewParty {
                kind: PartyKind::Person,
                display_name: "C. Exemple".to_string(),
                name_variants: vec!["Camille E.".to_string()],
                emails: vec!["c@exemple.test".to_string()],
                origin: "owner".to_string(),
                ..NewParty::default()
            })
            .unwrap();
        let _ = store
            .insert_interaction(
                a,
                "note",
                "2026-10-01T10:00:00Z",
                "{\"imap\":{\"uid\":1}}",
                "a",
                "owner",
            )
            .unwrap();
        // A second interaction on `a` that collides with `b`'s own event: the
        // unique `(party_id, kind, source_ref)` key drops it on the merge.
        let _ = store
            .insert_interaction(
                a,
                "mail",
                "2026-10-01T11:00:00Z",
                "{\"imap\":{\"uid\":2}}",
                "dup",
                "owner",
            )
            .unwrap();
        let _ = store
            .insert_interaction(
                b,
                "mail",
                "2026-10-02T10:00:00Z",
                "{\"imap\":{\"uid\":2}}",
                "b",
                "owner",
            )
            .unwrap();
        store
            .insert_followup(a, "2026-10-05", "r", "owner", "open")
            .unwrap();

        assert!(store.merge_parties(a, b).unwrap());
        assert!(store.party(a).unwrap().unwrap().archived);
        assert_eq!(store.interactions_for_party(b).unwrap().len(), 2);
        assert_eq!(store.followups_for_party(b).unwrap().len(), 1);
        let target = store.party(b).unwrap().unwrap();
        assert!(target
            .emails
            .contains(&"camille.exemple@exemple.test".to_string()));
        assert!(target
            .name_variants
            .contains(&"Camille Exemple".to_string()));
        assert!(
            !store.merge_parties(a, b).unwrap(),
            "an archived source is not merged twice"
        );
        assert!(!store.merge_parties(b, b).unwrap());
    }

    /// A receipt auto-linked to `party` the way `aux-docs` files it: a passing
    /// `party_match` check next to a `totals` check. Returns its document id.
    fn link_receipt(store: &Store, hash: &str, party: i64) -> i64 {
        store
            .conn
            .execute(
                "INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source)
                 VALUES (?1, ?2, 3, 'application/pdf', 'imap')",
                rusqlite::params![hash, format!("evidence/{hash}")],
            )
            .unwrap();
        let document_id = store.conn.last_insert_rowid();
        let checks = format!(
            "[{{\"name\":\"totals\",\"state\":\"pass\",\"reason\":\"totals add up\"}},\
             {{\"name\":\"party_match\",\"state\":\"pass\",\"reason\":\"matched CRM party {party}\"}}]"
        );
        assert!(store
            .insert_document_fields(&NewDocumentFields {
                document_id,
                kind: "receipt",
                extractor: "pdf_text",
                issuer: Some("Camille Exemple"),
                recipient: None,
                issued_on: Some("2026-10-01"),
                currency: Some("EUR"),
                total_minor: Some(1200),
                vat_minor: Some(200),
                number: Some("R-1"),
                fields_json: "{\"issuer\":\"Camille Exemple\"}",
                extracted_text: "",
                checks_json: &checks,
                party_id: Some(party),
                tags: "[]",
                status: "filed",
                updated_at: "2026-10-01T10:00:00Z",
                extract_state: "done",
                claimed_at: None,
                attempts: 1,
            })
            .unwrap());
        document_id
    }

    fn party_check(checks_json: &str) -> serde_json::Value {
        let checks: serde_json::Value = serde_json::from_str(checks_json).unwrap();
        checks
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["name"] == "party_match")
            .unwrap()
            .clone()
    }

    /// `(party_id, checks_json, fields_json)` of one `document_fields` row.
    fn receipt_link(store: &Store, document_id: i64) -> (Option<i64>, String, String) {
        store
            .conn
            .query_row(
                "SELECT party_id, checks_json, fields_json FROM document_fields
                  WHERE document_id = ?1",
                [document_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
    }
}
