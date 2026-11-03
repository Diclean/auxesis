//! The owner's contacts in the encrypted store (`contacts` table, schema v20).
//!
//! A contact is personal data. It lives only in `store.db`, which is
//! SQLCipher-encrypted at rest like every other table, and it leaves the store
//! only as the names dictionary of the privacy gate. The import replaces the
//! whole list in one transaction, so a re-import, a removal and a clear are the
//! same operation.

use std::fmt;
use std::path::Path;

use rusqlite::types::Type;
use rusqlite::{params, Connection, OptionalExtension};

use crate::{Store, StoreError};

/// v20: the `contacts` table. The version lives in the `meta` table under
/// `contacts_version`, so a reader can tell a new import from an old one.
/// Lists are JSON arrays, so one row is one person. `source` tags the row with
/// the source it came from, so one source is replaced without the others.
pub(crate) const MIGRATION_V20: &str = r#"
CREATE TABLE IF NOT EXISTS contacts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    display_name TEXT,
    given        TEXT NOT NULL,
    family       TEXT NOT NULL,
    nicknames    TEXT NOT NULL,
    emails       TEXT NOT NULL,
    phones       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS contacts_by_source ON contacts(source);
"#;

const VERSION_KEY: &str = "contacts_version";

/// One person: names, e-mail addresses and phone numbers (E.164).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ContactRecord {
    /// The source the contact came from, as a tag such as `file:contacts.vcf`.
    /// A replace of one source leaves every other source's contacts alone.
    pub source: String,
    /// The display name, as the file wrote it.
    pub display_name: Option<String>,
    /// Given names, one entry per word.
    pub given: Vec<String>,
    /// Family names, one entry per word.
    pub family: Vec<String>,
    /// Known short forms.
    pub nicknames: Vec<String>,
    /// E-mail addresses, lower-case.
    pub emails: Vec<String>,
    /// Phone numbers in E.164 (`+` and digits).
    pub phones: Vec<String>,
    /// The contact's IANA time zone (`Europe/Paris`), when the card carried
    /// one. A vCard `TZ:` offset is not a zone and is left unset.
    pub time_zone: Option<String>,
}

impl fmt::Debug for ContactRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only: a contact is personal data and must not reach a log.
        f.debug_struct("ContactRecord")
            .field(
                "names",
                &(self.given.len() + self.family.len() + self.nicknames.len()),
            )
            .field("emails", &self.emails.len())
            .field("phones", &self.phones.len())
            .finish()
    }
}

/// The contacts at one version of the store, read without migrating it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ContactsSnapshot {
    /// Bumped on every replace; zero before the first import.
    pub version: i64,
    /// Every contact, in the order they were stored.
    pub records: Vec<ContactRecord>,
}

impl Store {
    /// Every stored contact, in the order they were stored.
    pub fn contacts(&self) -> Result<Vec<ContactRecord>, StoreError> {
        read_contacts(&self.conn)
    }

    /// The contacts version: zero before the first import, then bumped by each replace.
    pub fn contacts_version(&self) -> Result<i64, StoreError> {
        read_version(&self.conn)
    }

    /// Replace the contacts of one `source` with `records`, in one transaction.
    /// Each record is stored under `source`; the other sources are kept.
    pub fn replace_source_contacts(
        &self,
        source: &str,
        records: &[ContactRecord],
    ) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        replace_source_contacts_in_tx(&tx, source, records)?;
        tx.commit()?;
        Ok(())
    }

    /// Replace every stored contact with `records`, in one transaction. Each
    /// record keeps its own `source`.
    pub fn replace_contacts(&self, records: &[ContactRecord]) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM contacts", [])?;
        insert_records(&tx, None, records)?;
        bump_version(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

/// Replace the contacts of one `source` inside an already-open transaction.
/// The CRM write methods (`aux-store`'s v22 party API) use this so the party row
/// and the contacts index it feeds commit or roll back together.
pub(crate) fn replace_source_contacts_in_tx(
    tx: &rusqlite::Transaction<'_>,
    source: &str,
    records: &[ContactRecord],
) -> Result<(), StoreError> {
    tx.execute("DELETE FROM contacts WHERE source = ?1", [source])?;
    insert_records(tx, Some(source), records)?;
    bump_version(tx)?;
    Ok(())
}

/// Insert `records`, under `source` when given, otherwise under each record's own.
fn insert_records(
    tx: &rusqlite::Transaction<'_>,
    source: Option<&str>,
    records: &[ContactRecord],
) -> Result<(), StoreError> {
    let mut insert = tx.prepare(
        "INSERT INTO contacts (source, display_name, given, family, nicknames, emails, phones,
                               time_zone)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for record in records {
        insert.execute(params![
            source.unwrap_or(&record.source),
            record.display_name,
            to_json(&record.given),
            to_json(&record.family),
            to_json(&record.nicknames),
            to_json(&record.emails),
            to_json(&record.phones),
            record.time_zone,
        ])?;
    }
    Ok(())
}

fn bump_version(tx: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO meta(key, value) VALUES (?1, '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(meta.value AS INTEGER) + 1 AS TEXT)",
        [VERSION_KEY],
    )?;
    Ok(())
}

/// The contacts of the store at `path`, read through a read-only connection:
/// nothing is created or migrated. A store without the table has no contacts.
pub fn contacts_snapshot_at(path: &Path) -> Result<ContactsSnapshot, StoreError> {
    if !path.exists() {
        return Ok(ContactsSnapshot::default());
    }
    let conn = crate::open_keyed_readonly(path)?;
    let has_table: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'contacts'",
        [],
        |row| row.get(0),
    )?;
    if has_table == 0 {
        return Ok(ContactsSnapshot::default());
    }
    Ok(ContactsSnapshot {
        version: read_version(&conn)?,
        records: read_contacts(&conn)?,
    })
}

/// The contacts version of the store at `path`, read on its own: zero when there is no
/// store or no table. A mount checks it on every turn without decoding the contacts.
pub fn contacts_version_at(path: &Path) -> Result<i64, StoreError> {
    if !path.exists() {
        return Ok(0);
    }
    let conn = crate::open_keyed_readonly(path)?;
    let has_table: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'contacts'",
        [],
        |row| row.get(0),
    )?;
    if has_table == 0 {
        return Ok(0);
    }
    read_version(&conn)
}

fn read_contacts(conn: &Connection) -> Result<Vec<ContactRecord>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT source, display_name, given, family, nicknames, emails, phones, time_zone
         FROM contacts ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ContactRecord {
            source: row.get(0)?,
            display_name: row.get(1)?,
            given: from_json(row.get(2)?, 2)?,
            family: from_json(row.get(3)?, 3)?,
            nicknames: from_json(row.get(4)?, 4)?,
            emails: from_json(row.get(5)?, 5)?,
            phones: from_json(row.get(6)?, 6)?,
            time_zone: row.get(7)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn read_version(conn: &Connection) -> Result<i64, StoreError> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [VERSION_KEY],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.and_then(|v| v.parse().ok()).unwrap_or(0))
}

fn to_json(values: &[String]) -> String {
    // A list of strings always serialises.
    serde_json::to_string(values).unwrap_or_else(|_| "[]".to_string())
}

fn from_json(raw: String, column: usize) -> rusqlite::Result<Vec<String>> {
    serde_json::from_str(&raw)
        .map_err(|err| rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(err)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn camille() -> ContactRecord {
        ContactRecord {
            source: "file:contacts.vcf".to_string(),
            display_name: Some("Camille Exemple".to_string()),
            given: vec!["Camille".to_string()],
            family: vec!["Exemple".to_string()],
            nicknames: vec!["Cam".to_string()],
            emails: vec!["camille.exemple@example.invalid".to_string()],
            phones: vec!["+33612345678".to_string()],
            time_zone: Some("Europe/Paris".to_string()),
        }
    }

    fn anna() -> ContactRecord {
        ContactRecord {
            source: "file:contacts.vcf".to_string(),
            display_name: Some("Kovács Anna".to_string()),
            given: vec!["Anna".to_string()],
            family: vec!["Kovács".to_string()],
            phones: vec!["+36201234567".to_string(), "+38640123456".to_string()],
            ..ContactRecord::default()
        }
    }

    #[test]
    fn replacing_one_source_leaves_the_other_sources_alone() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        let from = |source: &str, record: ContactRecord| ContactRecord {
            source: source.to_string(),
            ..record
        };
        store
            .replace_source_contacts("file:a.vcf", &[from("file:a.vcf", camille())])
            .unwrap();
        store
            .replace_source_contacts("file:b.csv", &[from("file:b.csv", anna())])
            .unwrap();
        assert_eq!(store.contacts().unwrap().len(), 2);

        store.replace_source_contacts("file:a.vcf", &[]).unwrap();

        let left = store.contacts().unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].source, "file:b.csv");
        assert_eq!(left[0].display_name.as_deref(), Some("Kovács Anna"));
    }

    #[test]
    fn a_replace_round_trips_every_field_in_order() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        assert!(store.contacts().unwrap().is_empty());

        store.replace_contacts(&[camille(), anna()]).unwrap();

        assert_eq!(store.contacts().unwrap(), vec![camille(), anna()]);
    }

    #[test]
    fn the_version_moves_on_every_replace() {
        let dir = tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        assert_eq!(store.contacts_version().unwrap(), 0);

        store.replace_contacts(&[camille()]).unwrap();
        let first = store.contacts_version().unwrap();
        assert!(first > 0);

        store.replace_contacts(&[camille(), anna()]).unwrap();
        assert!(store.contacts_version().unwrap() > first);
    }

    #[test]
    fn the_contact_rows_are_encrypted_at_rest() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store.replace_contacts(&[camille(), anna()]).unwrap();
            // The rows are really there, so the byte checks below are not vacuous.
            assert_eq!(store.contacts().unwrap().len(), 2);
        }
        // Every file of the store, including the WAL tail, holds no clear name or address.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            for needle in ["Camille", "camille.exemple", "Kovács", "+3361234"] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                    "a clear `{needle}` reached the disk"
                );
            }
        }
        // And a plain SQLite reader cannot open the store at all.
        let plain = rusqlite::Connection::open(&path).unwrap();
        assert!(plain
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row
                .get::<_, i64>(0))
            .is_err());
    }

    #[test]
    fn the_snapshot_reads_without_migrating_or_writing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store.replace_contacts(&[camille()]).unwrap();
        }
        let snapshot = contacts_snapshot_at(&path).unwrap();
        assert_eq!(snapshot.records, vec![camille()]);
        assert!(snapshot.version > 0);
        assert!(contacts_snapshot_at(&dir.path().join("absent.db"))
            .unwrap()
            .records
            .is_empty());
    }

    #[test]
    fn the_version_alone_matches_the_snapshot_and_moves_with_a_replace() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store
                .replace_source_contacts("file:a.vcf", &[camille()])
                .unwrap();
        }
        let version = contacts_version_at(&path).unwrap();
        assert_eq!(version, contacts_snapshot_at(&path).unwrap().version);
        assert!(version > 0);
        Store::open(&path)
            .unwrap()
            .replace_source_contacts("file:a.vcf", &[])
            .unwrap();
        assert!(contacts_version_at(&path).unwrap() > version);
        assert_eq!(
            contacts_version_at(&dir.path().join("absent.db")).unwrap(),
            0
        );
    }

    #[test]
    fn debug_shows_counts_and_never_a_name() {
        let shown = format!("{:?}", camille());
        assert!(!shown.contains("Camille"), "{shown}");
        assert!(!shown.contains("camille.exemple"), "{shown}");
    }
}
