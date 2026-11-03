//! The read-only `chat.db` reader (G2).
//!
//! The connection is opened `SQLITE_OPEN_READ_ONLY` through a
//! `file:…?mode=ro&immutable=0` URI, and `PRAGMA query_only` is set as well.
//! The query is **locked**: the pinned chat GUID, the ROWID cursor, every owner
//! handle and the limit are bound parameters. The owner handles are the only
//! `IN (…)` entries, and the placeholder text is built from the count, never
//! from a value. No row from another chat or another handle can be returned.
//!
//! Inbound content prefers `text`; when it is NULL (or whitespace) the
//! [`crate::attributed`] decoder reads `attributedBody`. A row whose content
//! cannot be decoded is skipped and counted, never logged as content.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};

use crate::attributed::decode_attributed_body;
use crate::config::{same_handle, MAX_HANDLE_LEN, MAX_OWNER_HANDLES};

/// Hard ceiling for any chat history batch, including callers outside auxd.
pub const MAX_READ_BATCH: usize = 20;

/// Why a read failed. Carries no message content or handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReaderError {
    /// The `chat.db` path cannot be expressed as a safe read-only URI.
    #[error("the chat.db path is not usable")]
    BadPath,
    /// The owner/channel binding is empty or malformed.
    #[error("the owner/channel binding is invalid")]
    BadSpec,
    /// The database could not be opened read-only.
    #[error("the chat.db could not be opened read-only")]
    Open,
    /// The query itself failed.
    #[error("the chat.db query failed")]
    Query,
    /// The persisted cursor could not be read.
    #[error("the chat.db cursor is unreadable")]
    Cursor,
}

/// The exact slice of `chat.db` this reader is allowed to see: one pinned chat
/// and a closed set of owner handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatSpec {
    owner_handles: Vec<String>,
    chat_guid: String,
}

impl ChatSpec {
    /// Build a spec, trimming the handles. Refuses an empty or oversized set,
    /// a control byte, or an empty GUID.
    pub fn new(
        owner_handles: Vec<String>,
        chat_guid: impl Into<String>,
    ) -> Result<Self, ReaderError> {
        let chat_guid = chat_guid.into().trim().to_string();
        let handles: Vec<String> = owner_handles
            .into_iter()
            .map(|handle| handle.trim().to_string())
            .collect();
        if handles.is_empty() || handles.len() > MAX_OWNER_HANDLES {
            return Err(ReaderError::BadSpec);
        }
        if handles.iter().any(|handle| !valid_text(handle)) {
            return Err(ReaderError::BadSpec);
        }
        if !valid_text(&chat_guid) {
            return Err(ReaderError::BadSpec);
        }
        Ok(Self {
            owner_handles: handles,
            chat_guid,
        })
    }

    /// The owner handles this spec accepts.
    pub fn owner_handles(&self) -> &[String] {
        &self.owner_handles
    }

    /// The one pinned chat.
    pub fn chat_guid(&self) -> &str {
        &self.chat_guid
    }

    /// Whether `handle` is one of the pinned owner handles.
    pub fn is_owner(&self, handle: &str) -> bool {
        self.owner_handles
            .iter()
            .any(|owner| same_handle(owner, handle))
    }
}

/// One inbound message from the owner. Local-only; never logged with content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundMessage {
    /// `message.ROWID`.
    pub rowid: i64,
    /// The sender handle (already proven to be an owner handle).
    pub sender: String,
    /// The pinned chat the row is attached to.
    pub chat_guid: String,
    /// The decoded content.
    pub text: String,
    /// Apple's `message.date` (epoch is not normalized here).
    pub date: i64,
}

/// The result of one `read_since` call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundBatch {
    /// The decodable inbound messages.
    pub messages: Vec<InboundMessage>,
    /// Rows whose content could not be decoded, counted only.
    pub skipped: usize,
    /// The highest ROWID examined, skipped rows included: persist this so a
    /// skipped row is not re-read forever.
    pub max_seen_rowid: i64,
}

/// A read receipt for one of the agent's own outgoing messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReceipt {
    /// `message.ROWID` of the outgoing message.
    pub rowid: i64,
    /// `message.is_read`; NULL reads as `false` (unread).
    pub is_read: bool,
    /// `message.date_read`; NULL reads as `0`.
    pub date_read: i64,
}

impl ReadReceipt {
    /// True when the owner has not read the message.
    pub fn is_unread(&self) -> bool {
        !self.is_read
    }
}

/// The reader seam the daemon and its tests share.
pub trait InboundSource: Send + Sync {
    /// Inbound rows newer than `cursor`, locked to `spec`.
    fn read_since(
        &self,
        spec: &ChatSpec,
        cursor: i64,
        limit: usize,
    ) -> Result<InboundBatch, ReaderError>;

    /// Read receipts for the agent's own outgoing rows newer than `cursor`.
    fn read_receipts_since(
        &self,
        spec: &ChatSpec,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<ReadReceipt>, ReaderError>;

    /// The current `MAX(message.ROWID)`, or 0.
    fn max_rowid(&self) -> Result<i64, ReaderError>;
}

/// A read-only handle on one `chat.db`.
pub struct ChatDbReader {
    conn: Mutex<Connection>,
}

impl ChatDbReader {
    /// Open `path` read-only. A missing file, a permission error or a path that
    /// cannot be safely expressed as a URI is an error, never a new file.
    pub fn open_read_only(path: &Path) -> Result<Self, ReaderError> {
        let path = path.to_str().ok_or(ReaderError::BadPath)?;
        if path.is_empty()
            || path.contains('\0')
            || path.contains('?')
            || path.contains('#')
            || path.contains('%')
        {
            return Err(ReaderError::BadPath);
        }
        let uri = format!("file:{path}?mode=ro&immutable=0");
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(&uri, flags).map_err(|_| ReaderError::Open)?;
        conn.busy_timeout(Duration::from_millis(500))
            .map_err(|_| ReaderError::Open)?;
        // Belt and braces on top of the read-only flag and `mode=ro`.
        conn.execute_batch("PRAGMA query_only = ON;")
            .map_err(|_| ReaderError::Open)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Inbound rows newer than `cursor`, locked to `spec`. See
    /// [`InboundSource::read_since`].
    pub fn read_since(
        &self,
        spec: &ChatSpec,
        cursor: i64,
        limit: usize,
    ) -> Result<InboundBatch, ReaderError> {
        let conn = self.lock();
        let limit = limit.clamp(1, MAX_READ_BATCH) as i64;
        let mut sql = String::from(
            // The owner is the configured `owner_handles` list and nothing
            // else: `COLLATE NOCASE` makes an email address match whatever
            // case the sender's device spells it in. The agent's own identity
            // is never inferred from `message.account` or `is_from_me` history.
            "SELECT m.ROWID, h.id, c.guid, m.text, m.attributedBody, m.date \
             FROM message m \
             JOIN chat_message_join cmj ON cmj.message_id = m.ROWID \
             JOIN chat c ON c.ROWID = cmj.chat_id \
             JOIN handle h ON h.ROWID = m.handle_id \
             WHERE c.guid = ?1 AND m.is_from_me = 0 AND m.ROWID > ?2 AND h.id COLLATE NOCASE IN (",
        );
        let mut params: Vec<Value> =
            vec![Value::Text(spec.chat_guid.clone()), Value::Integer(cursor)];
        for (index, handle) in spec.owner_handles.iter().enumerate() {
            if index > 0 {
                sql.push_str(", ");
            }
            // The placeholder is the parameter's number, drawn from the count.
            sql.push('?');
            sql.push_str(&(index + 3).to_string());
            params.push(Value::Text(handle.clone()));
        }
        sql.push_str(") ORDER BY m.ROWID ASC LIMIT ?");
        sql.push_str(&(spec.owner_handles.len() + 3).to_string());
        params.push(Value::Integer(limit));

        let mut stmt = conn.prepare(&sql).map_err(|_| ReaderError::Query)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), |row| {
                let text: Option<String> = row.get(3)?;
                let body: Option<Vec<u8>> = row.get(4)?;
                let content = match text {
                    Some(value) if !value.trim().is_empty() => Some(value),
                    _ => match body {
                        Some(blob) => decode_attributed_body(&blob).ok(),
                        None => None,
                    },
                };
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(5)?.unwrap_or(0),
                    content,
                ))
            })
            .map_err(|_| ReaderError::Query)?;

        let mut batch = InboundBatch {
            max_seen_rowid: cursor,
            ..InboundBatch::default()
        };
        for row in rows {
            let (rowid, sender, chat_guid, date, content) = row.map_err(|_| ReaderError::Query)?;
            batch.max_seen_rowid = batch.max_seen_rowid.max(rowid);
            match content {
                Some(text) if !text.trim().is_empty() => batch.messages.push(InboundMessage {
                    rowid,
                    sender,
                    chat_guid,
                    text,
                    date,
                }),
                _ => batch.skipped = batch.skipped.saturating_add(1),
            }
        }
        Ok(batch)
    }

    /// Read receipts for the agent's own outgoing rows. See
    /// [`InboundSource::read_receipts_since`].
    pub fn read_receipts_since(
        &self,
        spec: &ChatSpec,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<ReadReceipt>, ReaderError> {
        let conn = self.lock();
        let limit = limit.clamp(1, MAX_READ_BATCH) as i64;
        let mut stmt = conn
            .prepare(
                "SELECT m.ROWID, m.is_read, m.date_read \
                 FROM message m \
                 JOIN chat_message_join cmj ON cmj.message_id = m.ROWID \
                 JOIN chat c ON c.ROWID = cmj.chat_id \
                 WHERE c.guid = ?1 AND m.is_from_me = 1 AND m.ROWID > ?2 \
                 ORDER BY m.ROWID ASC LIMIT ?3",
            )
            .map_err(|_| ReaderError::Query)?;
        let rows = stmt
            .query_map(rusqlite::params![spec.chat_guid, cursor, limit], |row| {
                Ok(ReadReceipt {
                    rowid: row.get(0)?,
                    is_read: row.get::<_, Option<i64>>(1)?.unwrap_or(0) != 0,
                    date_read: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                })
            })
            .map_err(|_| ReaderError::Query)?;
        let mut receipts = Vec::new();
        for row in rows {
            receipts.push(row.map_err(|_| ReaderError::Query)?);
        }
        Ok(receipts)
    }

    /// The current `MAX(message.ROWID)`, or 0 on an empty table.
    pub fn max_rowid(&self) -> Result<i64, ReaderError> {
        let conn = self.lock();
        conn.query_row("SELECT COALESCE(MAX(ROWID), 0) FROM message", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| ReaderError::Query)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl InboundSource for ChatDbReader {
    fn read_since(
        &self,
        spec: &ChatSpec,
        cursor: i64,
        limit: usize,
    ) -> Result<InboundBatch, ReaderError> {
        Self::read_since(self, spec, cursor, limit)
    }

    fn read_receipts_since(
        &self,
        spec: &ChatSpec,
        cursor: i64,
        limit: usize,
    ) -> Result<Vec<ReadReceipt>, ReaderError> {
        Self::read_receipts_since(self, spec, cursor, limit)
    }

    fn max_rowid(&self) -> Result<i64, ReaderError> {
        Self::max_rowid(self)
    }
}

/// Non-empty, within the length bound, and free of control bytes.
fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_HANDLE_LEN && !value.chars().any(|c| c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rusqlite::params;

    /// Create the real schema subset and return the temp dir (kept alive) and
    /// the database path.
    fn fake_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL, service TEXT); \
             CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT NOT NULL, chat_identifier TEXT); \
             CREATE TABLE message ( \
                 ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT, attributedBody BLOB, \
                 handle_id INTEGER, is_from_me INTEGER DEFAULT 0, is_read INTEGER, \
                 date INTEGER, date_read INTEGER); \
             CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER); \
             CREATE TABLE chat_handle_join (chat_id INTEGER, handle_id INTEGER);",
        )
        .unwrap();
        (dir, path)
    }

    fn add_handle(conn: &Connection, rowid: i64, id: &str) {
        conn.execute(
            "INSERT INTO handle (ROWID, id, service) VALUES (?1, ?2, 'iMessage')",
            params![rowid, id],
        )
        .unwrap();
    }

    fn add_chat(conn: &Connection, rowid: i64, guid: &str) {
        conn.execute(
            "INSERT INTO chat (ROWID, guid, chat_identifier) VALUES (?1, ?2, ?2)",
            params![rowid, guid],
        )
        .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn add_message(
        conn: &Connection,
        rowid: i64,
        chat_id: i64,
        handle_id: i64,
        text: Option<&str>,
        body: Option<&[u8]>,
        is_from_me: bool,
        is_read: Option<i64>,
        date: i64,
    ) {
        conn.execute(
            "INSERT INTO message (ROWID, text, attributedBody, handle_id, is_from_me, is_read, date, date_read) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
            params![rowid, text, body, handle_id, i64::from(is_from_me), is_read, date],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_message_join (chat_id, message_id) VALUES (?1, ?2)",
            params![chat_id, rowid],
        )
        .unwrap();
    }

    fn spec() -> ChatSpec {
        ChatSpec::new(vec!["+33600000001".to_string()], "iMessage;-;+33600000001").unwrap()
    }

    fn insert_standard(conn: &Connection) {
        add_handle(conn, 1, "+33600000001");
        add_handle(conn, 2, "+33600000002");
        add_handle(conn, 3, "agent@example.test");
        add_chat(conn, 7, "iMessage;-;+33600000001");
        add_chat(conn, 8, "iMessage;-;+33600000002");
    }

    fn sample_body(text: &str) -> Vec<u8> {
        let mut blob = vec![0x04, 0x0b];
        blob.extend_from_slice(b"streamtyped");
        blob.extend_from_slice(b"\x81\xe8\x03\x84\x01\x40\x84\x84\x84\x12NSAttributedString\x00");
        blob.extend_from_slice(b"\x84\x84NSObject\x00\x85\x92\x84\x84\x84\x08NSString");
        blob.extend_from_slice(&[0x01, 0x2b]);
        let bytes = text.as_bytes();
        blob.push(bytes.len() as u8);
        blob.extend_from_slice(bytes);
        blob.extend_from_slice(b"\x86\x84");
        blob
    }

    #[test]
    fn a_foreign_chat_is_never_returned() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            add_message(&conn, 10, 7, 1, Some("mine"), None, false, None, 1);
            add_message(&conn, 11, 8, 1, Some("other chat"), None, false, None, 2);
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let batch = reader.read_since(&spec(), 0, 100).unwrap();
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].text, "mine");
        assert_eq!(batch.messages[0].chat_guid, "iMessage;-;+33600000001");
    }

    #[test]
    fn oversized_limits_are_capped_before_binding_to_sqlite() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            for rowid in 1..=25 {
                add_message(&conn, rowid, 7, 1, Some("owner"), None, false, None, rowid);
            }
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let batch = reader.read_since(&spec(), 0, usize::MAX).unwrap();
        assert_eq!(batch.messages.len(), MAX_READ_BATCH);
        assert_eq!(batch.max_seen_rowid, MAX_READ_BATCH as i64);
        assert!(
            reader
                .read_receipts_since(&spec(), 0, usize::MAX)
                .unwrap()
                .len()
                <= MAX_READ_BATCH
        );
    }

    #[test]
    fn a_foreign_handle_is_never_returned() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            add_message(&conn, 10, 7, 1, Some("owner"), None, false, None, 1);
            add_message(&conn, 11, 7, 2, Some("stranger"), None, false, None, 2);
            add_message(&conn, 12, 7, 3, Some("agent echo"), None, false, None, 3);
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let batch = reader.read_since(&spec(), 0, 100).unwrap();
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].text, "owner");
    }

    /// Owner identity is the configured list alone: a phone and an email are
    /// both the owner, the email matches whatever case the sender used, and a
    /// third handle is ignored. No row's `account` or history is consulted.
    #[test]
    fn either_owner_handle_is_accepted_and_a_third_is_ignored() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            add_handle(&conn, 1, "+33600000001");
            add_handle(&conn, 2, "Owner@Example.test");
            add_handle(&conn, 3, "stranger@example.test");
            add_chat(&conn, 7, "iMessage;-;+33600000001");
            add_message(
                &conn,
                10,
                7,
                1,
                Some("from the phone"),
                None,
                false,
                None,
                1,
            );
            add_message(
                &conn,
                11,
                7,
                2,
                Some("from the email"),
                None,
                false,
                None,
                2,
            );
            add_message(
                &conn,
                12,
                7,
                3,
                Some("from the stranger"),
                None,
                false,
                None,
                3,
            );
        }
        let spec = ChatSpec::new(
            vec!["+33600000001".to_string(), "owner@example.test".to_string()],
            "iMessage;-;+33600000001",
        )
        .unwrap();
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let batch = reader.read_since(&spec, 0, 100).unwrap();
        assert_eq!(
            batch.messages.len(),
            2,
            "both owner handles are the owner, the third is not"
        );
        assert!(batch.messages.iter().any(|m| m.text == "from the phone"));
        assert!(batch.messages.iter().any(|m| m.text == "from the email"));
        assert!(batch.messages.iter().all(|m| spec.is_owner(&m.sender)));
    }

    #[test]
    fn an_outgoing_row_is_never_inbound() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            add_message(&conn, 10, 7, 1, Some("out"), None, true, Some(1), 1);
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        assert!(reader
            .read_since(&spec(), 0, 100)
            .unwrap()
            .messages
            .is_empty());
    }

    #[test]
    fn only_rows_after_the_cursor_are_returned() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            add_message(&conn, 10, 7, 1, Some("old"), None, false, None, 1);
            add_message(&conn, 20, 7, 1, Some("new"), None, false, None, 2);
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let batch = reader.read_since(&spec(), 15, 100).unwrap();
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].rowid, 20);
        assert_eq!(batch.max_seen_rowid, 20);
    }

    #[test]
    fn a_null_text_decodes_from_attributed_body() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            let body = sample_body("Bonjour depuis le blob");
            add_message(&conn, 10, 7, 1, None, Some(&body), false, None, 1);
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let batch = reader.read_since(&spec(), 0, 100).unwrap();
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].text, "Bonjour depuis le blob");
        assert_eq!(batch.skipped, 0);
    }

    #[test]
    fn a_garbage_attributed_body_is_skipped_and_counted() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
            add_message(&conn, 10, 7, 1, None, Some(&garbage), false, None, 1);
            add_message(
                &conn,
                11,
                7,
                1,
                Some("after the garbage"),
                None,
                false,
                None,
                2,
            );
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let batch = reader.read_since(&spec(), 0, 100).unwrap();
        assert_eq!(batch.skipped, 1);
        assert_eq!(batch.messages.len(), 1);
        assert_eq!(batch.messages[0].text, "after the garbage");
        assert_eq!(batch.max_seen_rowid, 11);
    }

    #[test]
    fn read_receipts_come_from_is_read() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            add_message(&conn, 10, 7, 1, Some("seen"), None, true, Some(1), 1);
            add_message(&conn, 11, 7, 1, Some("not seen"), None, true, Some(0), 2);
            add_message(&conn, 12, 8, 1, Some("other chat"), None, true, Some(1), 3);
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let receipts = reader.read_receipts_since(&spec(), 0, 100).unwrap();
        assert_eq!(receipts.len(), 2);
        assert!(receipts[0].is_read);
        assert_eq!(receipts[0].rowid, 10);
        assert!(receipts[1].is_unread());
        assert_eq!(receipts[1].rowid, 11);
    }

    #[test]
    fn an_unread_urgent_item_is_reported_unread() {
        let (_dir, path) = fake_db();
        {
            let conn = Connection::open(&path).unwrap();
            insert_standard(&conn);
            add_message(
                &conn,
                10,
                7,
                1,
                Some("urgent question"),
                None,
                true,
                Some(0),
                1,
            );
        }
        let reader = ChatDbReader::open_read_only(&path).unwrap();
        let receipts = reader.read_receipts_since(&spec(), 0, 100).unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].is_unread(), "the urgent item must be unread");
    }

    #[test]
    fn the_reader_refuses_a_read_write_path_spelling() {
        // A path with a `?` cannot be turned into a safe read-only URI.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chat?db");
        assert!(matches!(
            ChatDbReader::open_read_only(&path),
            Err(ReaderError::BadPath)
        ));
    }

    #[test]
    fn opening_a_missing_database_fails_instead_of_creating_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.db");
        assert!(ChatDbReader::open_read_only(&path).is_err());
        assert!(!path.exists(), "the reader must never create chat.db");
    }

    #[test]
    fn a_spec_needs_an_owner_handle_and_a_guid() {
        assert_eq!(
            ChatSpec::new(vec![], "iMessage;-;+33600000001").unwrap_err(),
            ReaderError::BadSpec
        );
        assert_eq!(
            ChatSpec::new(vec!["+33600000001".to_string()], "  ").unwrap_err(),
            ReaderError::BadSpec
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// With random chats, handles and directions in the table, the reader
        /// returns exactly the rows for the pinned chat and the configured
        /// owner-handle list.
        #[test]
        fn no_row_from_another_chat_or_handle(
            chats in proptest::collection::vec("[a-zA-Z0-9;+\\-]{1,24}", 1..6),
            handles in proptest::collection::vec("[+0-9a-z@.]{3,24}", 2..6),
            rows in proptest::collection::vec(
                (0usize..6, 0usize..6, any::<bool>(), "[ -~]{1,20}"),
                0..30,
            ),
        ) {
            let (_dir, path) = fake_db();
            let owner_chat = chats[0].clone();
            let owner_handles = vec![handles[0].clone(), handles[1].clone()];
            {
                let conn = Connection::open(&path).unwrap();
                for (index, chat) in chats.iter().enumerate() {
                    add_chat(&conn, index as i64 + 1, chat);
                }
                for (index, handle) in handles.iter().enumerate() {
                    add_handle(&conn, index as i64 + 100, handle);
                }
                for (index, (chat_index, handle_index, is_from_me, text)) in rows.iter().enumerate() {
                    let chat_id = (*chat_index % chats.len()) as i64 + 1;
                    let handle_id = (*handle_index % handles.len()) as i64 + 100;
                    add_message(
                        &conn,
                        index as i64 + 1000,
                        chat_id,
                        handle_id,
                        Some(text.as_str()),
                        None,
                        *is_from_me,
                        None,
                        1,
                    );
                }
            }

            let spec = ChatSpec::new(owner_handles.clone(), owner_chat.clone()).unwrap();
            let reader = ChatDbReader::open_read_only(&path).unwrap();
            let batch = reader.read_since(&spec, 0, 1000).unwrap();

            let expected = rows
                .iter()
                .filter(|(chat_index, handle_index, is_from_me, text)| {
                    !*is_from_me
                        && chats[*chat_index % chats.len()].as_str() == owner_chat.as_str()
                        && owner_handles
                            .iter()
                            .any(|owner| owner == &handles[*handle_index % handles.len()])
                        && !text.trim().is_empty()
                })
                .count();
            prop_assert_eq!(batch.messages.len(), expected);
            let all_locked = batch.messages.iter().all(|message| {
                message.chat_guid == owner_chat
                    && spec.is_owner(&message.sender)
                    && !message.text.trim().is_empty()
            });
            prop_assert!(all_locked);
        }
    }
}
