//! The schema of the store and the migrations that build it.
//!
//! Every migration is additive and idempotent, so a store walks up from v1
//! to the current version one step at a time, and an interrupted upgrade
//! is simply retried the next time the store is opened.

use super::*;

/// v1 baseline: version bookkeeping and the audit event log.
pub(crate) const MIGRATION_V1: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    kind       TEXT NOT NULL,
    payload    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
"#;

/// v2: chat sessions and their messages.
///
/// `messages.session_id` cascades on delete so `Store::delete_session` never
/// leaves orphaned messages behind.
pub(crate) const MIGRATION_V2: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    dot        TEXT NOT NULL,
    title      TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_dot ON sessions(dot);
CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    content    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    meta       TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, id);
"#;

/// v3: scheduled jobs and their execution history.
///
/// `runs.job_id` cascades on delete so removing a job also removes its runs;
/// `jobs.next_run_at IS NULL` means "due immediately", which lets a claimed
/// job recover from a crash after the scheduler lease expires.
pub(crate) const MIGRATION_V3: &str = r#"
CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dot         TEXT NOT NULL,
    name        TEXT NOT NULL,
    schedule    TEXT NOT NULL,
    payload     TEXT NOT NULL DEFAULT '{}',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_run_at TEXT,
    next_run_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_due ON jobs(enabled, next_run_at);
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    status      TEXT NOT NULL,
    summary     TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_job ON runs(job_id, id);
"#;

/// v4: the usage meter behind the per-agent daily budgets.
///
/// Additive and independent of v3: a database that already carries the
/// scheduler tables updates straight to v4 without touching jobs or runs.
pub(crate) const MIGRATION_V4: &str = r#"
CREATE TABLE IF NOT EXISTS usage (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    dot    TEXT NOT NULL,
    at     TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    kind   TEXT NOT NULL,
    amount INTEGER NOT NULL,
    unit   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_dot_day ON usage(dot, at);
"#;

/// v5: atomic spend reservations + an index for day-bounded usage reads.
///
/// A reservation is a short-lived claim against an agent's daily cap, written
/// and checked in the same `BEGIN IMMEDIATE` transaction as the recorded
/// totals. `expires_at` bounds a crashed process's reservation: expired rows
/// are ignored (and swept) so a dead reservation can never block a cap
/// forever.
pub(crate) const MIGRATION_V5: &str = r#"
CREATE TABLE IF NOT EXISTS usage_reservations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    dot        TEXT NOT NULL,
    at         TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    expires_at TEXT NOT NULL,
    tokens_in  INTEGER NOT NULL DEFAULT 0,
    tokens_out INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_usage_reservations_dot ON usage_reservations(dot, expires_at);
CREATE INDEX IF NOT EXISTS idx_usage_day ON usage(at);
"#;

/// v6: the per-agent/day fail-closed latch (B-01R).
///
/// A completed call whose real usage reaches or crosses a daily cap writes
/// one row here (in the same transaction as its usage rows). While the row
/// exists, every `try_reserve` for that agent/day is denied: a provider that
/// ignores its completion cap can overshoot with the calls already in
/// flight, but not with any call that has not started yet.
pub(crate) const MIGRATION_V6: &str = r#"
CREATE TABLE IF NOT EXISTS budget_stops (
    dot    TEXT NOT NULL,
    day    TEXT NOT NULL,
    reason TEXT NOT NULL,
    at     TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    PRIMARY KEY (dot, day)
);
"#;

/// v7: session kind.
///
/// `chat` is a conversation; `job` is a scheduled-run transcript. The agent's
/// advertised `thread_id` and the agent-name POST/GET only ever resolve to
/// `chat` sessions, so a job run can never hijack the conversation. Sessions
/// from before the migration are backfilled by the same title convention the
/// scheduler has always used (`job <name>`), so historical job transcripts
/// are excluded too.
///
/// The `ALTER` is the only non-idempotent migration, so it is applied under
/// an `IMMEDIATE` transaction that re-checks the recorded version and the
/// column itself (two processes may open a fresh store at the same moment).
pub(crate) const MIGRATION_V7_ADD_KIND: &str =
    "ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'chat';";

/// Backfill of v7 (idempotent on its own).
pub(crate) const MIGRATION_V7_BACKFILL: &str = r#"
UPDATE sessions SET kind = 'job'
 WHERE kind <> 'job'
   AND EXISTS (
     SELECT 1 FROM jobs j
     WHERE j.dot = sessions.dot AND sessions.title = 'job ' || j.name
   );
"#;

/// v9: taint marks.
///
/// `workspace_taint` is the sticky, workspace-level mark: dispatching an
/// untrusted-class tool in a workspace records that outside content touched
/// it, and every conversation that starts there — new, resumed or
/// job-triggered — is tainted until the owner clears the mark. The key is
/// the canonical workspace path, so one store can hold several agents' marks.
/// `session_taint` records a conversation's taint *before* its untrusted
/// call runs: a turn that is cancelled, killed or crashes before producing a
/// result row still resumes tainted. The v9 tables replace the old per-file
/// snapshot ledger; `file_taint` is dropped.
///
/// An earlier v9 created `file_taint` + `workspace_taint`, and another
/// created `workspace_taint` + `session_taint`. Stores that recorded the
/// first never ran the `session_taint` creation; v10 repairs them.
pub(crate) const MIGRATION_V9: &str = r#"
CREATE TABLE IF NOT EXISTS workspace_taint (
    workspace TEXT PRIMARY KEY,
    reason    TEXT NOT NULL,
    at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS session_taint (
    session_id INTEGER PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    tool       TEXT NOT NULL,
    detail     TEXT,
    at         TEXT NOT NULL DEFAULT (datetime('now'))
);
DROP TABLE IF EXISTS file_taint;
"#;

/// v10: repair the amended-in-place v9 and add the owner trust ledger.
///
/// A store that recorded an earlier schema version 9 considers itself up to
/// date and never gets `session_taint`; every chat then fails with `no such
/// table: session_taint`. The `CREATE TABLE IF NOT EXISTS` below is the
/// repair, and `file_taint` (the old per-file ledger) is
/// dropped for stores that still carry it. `trust_requests` backs the
/// owner-presence proof for `aux workspace trust`: one pending request per
/// canonical workspace path, holding a salted KDF hash of the one-time code —
/// never the code itself, which only ever travels through the owner's local
/// notification. `attempts`/`created_at` enforce the single-use, 120 s,
/// 3-attempt policy. Every migration here is idempotent.
pub(crate) const MIGRATION_V10: &str = r#"
CREATE TABLE IF NOT EXISTS session_taint (
    session_id INTEGER PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    tool       TEXT NOT NULL,
    detail     TEXT,
    at         TEXT NOT NULL DEFAULT (datetime('now'))
);
DROP TABLE IF EXISTS file_taint;
CREATE TABLE IF NOT EXISTS trust_requests (
    workspace  TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    code_hash  BLOB NOT NULL,
    salt       BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0
);
"#;

/// v11: per-channel session bindings and message ledger (WA-MSG-0).
///
/// The WhatsApp text channel maps one external chat to one Auxesis thread
/// (a `sessions` row) and must survive restarts without answering the same
/// inbound message twice. Both tables hold **log-safe keys only** — a
/// salted hash of the chat identity and a salted hash of the transport
/// message id — never a phone number and never message content.
///
/// `channel_messages.accepted` separates "seen" (dedupe, written before the
/// turn starts) from "answered" (written after a reply was handed to the
/// transport), so the inbound rate limit counts answered traffic, not
/// redeliveries or drops.
pub(crate) const MIGRATION_V11: &str = r#"
CREATE TABLE IF NOT EXISTS channel_sessions (
    channel    TEXT NOT NULL,
    chat_key   TEXT NOT NULL,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (channel, chat_key)
);
CREATE TABLE IF NOT EXISTS channel_messages (
    channel     TEXT NOT NULL,
    message_key TEXT NOT NULL,
    accepted    INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0,
    retries     INTEGER NOT NULL DEFAULT 0,
    at_unix     INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (channel, message_key)
);
CREATE INDEX IF NOT EXISTS idx_channel_messages_window
    ON channel_messages(channel, accepted, at_unix);
"#;

/// v12: a composite `(kind, created_at)` index for the event journal.
///
/// Receipt reads and retention both filter `kind` and then range over
/// `created_at`; the v1 single-column `idx_events_kind` cannot serve the
/// range, while `(kind, created_at)` serves both. The v1 index is left in
/// place: [`MIGRATION_V1`] re-creates it on every open, so dropping it here
/// would not stick. Idempotent.
pub(crate) const MIGRATION_V12: &str = r#"
CREATE INDEX IF NOT EXISTS idx_events_kind_created ON events(kind, created_at);
"#;

/// v13: run-scoped usage attribution.
///
/// A receipt must attribute spend to **its own turn**, never to a shared
/// row-id window over `usage`: two overlapping turns of the same agent both
/// land rows in any such window and each receipt would claim the other's
/// spend. `run_id` is stamped on the row at insert time from the turn's own
/// identity, so `sum(usage WHERE run_id = ?)` is exact.
///
/// The `ALTER` is the only non-idempotent migration, so it runs under the same
/// guarded `IMMEDIATE` transaction pattern as v7: the recorded version and the
/// column itself are re-checked under the write lock. Existing rows keep
/// `run_id = NULL` and remain visible to the day/agent budget totals.
pub(crate) const MIGRATION_V13_ADD_RUN_ID: &str = "ALTER TABLE usage ADD COLUMN run_id TEXT;";

pub(crate) const MIGRATION_V13_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_usage_run ON usage(run_id);";

/// v14: the per-session private-data egress marker (web hardening).
///
/// Reading mail, calendar, memory or notes is silent, but it flips the
/// egress rule **sticky, like taint**: while (and after) such a read, every
/// fetch whose URL the model composed asks — including an unseen host, which
/// is refused or asked but can never be silent. The flag used to live only
/// in `ChatSession` and reset on every inbound turn of the same thread, so a
/// notes read in turn 1 followed by an `http_fetch` in turn 2 was silently
/// allowed to carry private text in its query. The row holds the first tool
/// that read private owner data, `ON CONFLICT DO NOTHING` like
/// `session_taint`, and survives cancelled or crashed turns the same way.
///
/// Numbered after the receipt work's v12/v13 (merge of `origin/main`): the
/// table is additive and independent of both, so it takes the next version
/// rather than renumbering either side's migration.
pub(crate) const MIGRATION_V14: &str = r#"
CREATE TABLE IF NOT EXISTS session_private_data (
    session_id INTEGER PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    tool       TEXT NOT NULL,
    at         TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

/// v15: the MCP connector-tool descriptor cache.
///
/// One row per `(server, remote_name)`: the wire allowlist name the adapter
/// dispatches under, the toolkit the descriptor belongs to, and the **plain
/// descriptor data** (description, JSON schema, tags, the canonical descriptor
/// JSON) plus its risk classification and cache lifetime. The table is
/// additive and independent of every earlier migration, so it takes the next
/// version after main's v14 rather than renumbering either side.
///
/// It deliberately has **no secret column**: an API key or OAuth token
/// is never passed to (or storable by) any method in this section — the rows
/// are descriptors only. Sizes are bounded in [`Store::upsert_mcp_tools`].
///
/// `wire_name` carries a **unique** index: [`Store::mcp_tool_by_wire`] is the
/// dispatch key the S3 adapter gates calls by, so two servers must never hold
/// the same wire name (one would shadow the other's risk class and schema).
/// The upsert enforces the same invariant with a typed refusal.
///
/// `fetched_at` is when the upstream descriptor was fetched; `synced_at` is
/// when this row was written (generated by SQLite as `datetime('now')`, so it
/// is always a valid UTC timestamp); `ttl_seconds` bounds the cache lifetime
/// and drives [`Store::prune_expired_mcp_tools`]. Every statement is idempotent.
pub(crate) const MIGRATION_V15: &str = r#"
CREATE TABLE IF NOT EXISTS mcp_tools (
    server          TEXT NOT NULL,
    remote_name     TEXT NOT NULL,
    wire_name       TEXT NOT NULL,
    toolkit         TEXT NOT NULL,
    description     TEXT NOT NULL,
    schema_json     TEXT NOT NULL,
    tags_json       TEXT NOT NULL,
    descriptor_json TEXT NOT NULL,
    risk            TEXT NOT NULL,
    risk_basis      TEXT NOT NULL,
    fetched_at      TEXT NOT NULL,
    ttl_seconds     INTEGER NOT NULL,
    synced_at       TEXT NOT NULL,
    PRIMARY KEY (server, remote_name)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_tools_wire ON mcp_tools(wire_name);
CREATE INDEX IF NOT EXISTS idx_mcp_tools_server ON mcp_tools(server);
"#;

/// v16: bounded per-agent memory rows and an external-content FTS index.
pub(crate) const MIGRATION_V16: &str = r#"
CREATE TABLE IF NOT EXISTS memory_items (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    dot           TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('fact', 'episode', 'note')),
    title         TEXT NOT NULL,
    body          TEXT NOT NULL,
    fact_key      TEXT,
    confidence    REAL CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    source        TEXT NOT NULL,
    trust         TEXT NOT NULL,
    tainted       INTEGER NOT NULL CHECK (tainted IN (0, 1)),
    supersedes_id INTEGER,
    state         TEXT NOT NULL CHECK (state IN ('active', 'quarantined', 'superseded')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    valid_from    TEXT,
    valid_to      TEXT,
    content_hash  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_dot_state ON memory_items(dot, state);
CREATE INDEX IF NOT EXISTS idx_memory_dot_kind ON memory_items(dot, kind);
CREATE INDEX IF NOT EXISTS idx_memory_dot_updated ON memory_items(dot, updated_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_active_fact_key
    ON memory_items(dot, fact_key) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_active_hash
    ON memory_items(dot, content_hash) WHERE state = 'active';
CREATE VIRTUAL TABLE IF NOT EXISTS memory_items_fts USING fts5(
    title, body, content='memory_items', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS memory_items_ai AFTER INSERT ON memory_items BEGIN
    INSERT INTO memory_items_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
END;
CREATE TRIGGER IF NOT EXISTS memory_items_ad AFTER DELETE ON memory_items BEGIN
    INSERT INTO memory_items_fts(memory_items_fts, rowid, title, body)
    VALUES ('delete', old.id, old.title, old.body);
END;
CREATE TRIGGER IF NOT EXISTS memory_items_au AFTER UPDATE OF title, body ON memory_items BEGIN
    INSERT INTO memory_items_fts(memory_items_fts, rowid, title, body)
    VALUES ('delete', old.id, old.title, old.body);
    INSERT INTO memory_items_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
END;
"#;

/// v18: typed projections and generated note mirror bookkeeping.
pub(crate) const MIGRATION_V18: &str = r#"
CREATE TABLE IF NOT EXISTS memory_sources (
    item_id INTEGER NOT NULL REFERENCES memory_items(id) ON DELETE CASCADE,
    dot TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    trust TEXT NOT NULL CHECK (trust IN ('owner', 'untrusted', 'tainted')),
    PRIMARY KEY (item_id, source_ref)
);
CREATE INDEX IF NOT EXISTS idx_memory_sources_dot ON memory_sources(dot, item_id);
CREATE TABLE IF NOT EXISTS profile_facts (
    item_id INTEGER PRIMARY KEY REFERENCES memory_items(id) ON DELETE CASCADE,
    dot TEXT NOT NULL,
    fact_key TEXT,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profile_facts_dot ON profile_facts(dot, fact_key);
CREATE TABLE IF NOT EXISTS memory_episodes (
    item_id INTEGER PRIMARY KEY REFERENCES memory_items(id) ON DELETE CASCADE,
    dot TEXT NOT NULL,
    occurred_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_memory_episodes_dot ON memory_episodes(dot, occurred_at);
CREATE TABLE IF NOT EXISTS memory_notes (
    item_id INTEGER PRIMARY KEY REFERENCES memory_items(id) ON DELETE CASCADE,
    dot TEXT NOT NULL,
    mirror_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_memory_notes_dot ON memory_notes(dot);
INSERT OR IGNORE INTO memory_sources(item_id,dot,source_ref,trust)
    SELECT id,dot,source,CASE WHEN tainted=1 THEN 'tainted' ELSE 'owner' END FROM memory_items;
INSERT OR IGNORE INTO profile_facts(item_id,dot,fact_key,value)
    SELECT id,dot,fact_key,body FROM memory_items WHERE kind='fact';
INSERT OR IGNORE INTO memory_episodes(item_id,dot,occurred_at)
    SELECT id,dot,valid_from FROM memory_items WHERE kind='episode';
INSERT OR IGNORE INTO memory_notes(item_id,dot)
    SELECT id,dot FROM memory_items WHERE kind='note';
CREATE TABLE IF NOT EXISTS memory_mirrors (
    dot TEXT PRIMARY KEY,
    generated_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TRIGGER IF NOT EXISTS memory_quarantine_immutable
BEFORE UPDATE OF state ON memory_items
WHEN old.state = 'quarantined' AND new.state <> 'quarantined'
BEGIN SELECT RAISE(ABORT, 'quarantined memory is immutable'); END;
"#;

/// v17: the invoices/tickets evidence ledger.
///
/// Three new tables and nothing else: a migration added here never alters or
/// drops an existing table or row, so a populated v15/v16 store upgrades in
/// place. `documents` is one row per captured original, keyed by its SHA-256
/// (`content_hash` is `UNIQUE`, so a repeated hash is the *same* document, not
/// a second one). The original bytes themselves live outside SQLite, named by
/// the hash under `invoices/originals/` in the verified home; this row only
/// points at that blob.
///
/// `proofs` (the "preuves" ledger) and `corrections` are append-only. Their
/// `BEFORE UPDATE`/`BEFORE DELETE` triggers `RAISE(ABORT, …)`, and a
/// `BEFORE INSERT` guard rejects an insert whose row already exists, so a bug,
/// a migration, or an operator cannot rewrite or erase prior evidence: a
/// correction or a proof is only ever *added*, and hashes detect later edits
/// (they are not external notarization).
///
/// The insert guard is what stops `INSERT OR REPLACE` / `REPLACE INTO` and an
/// upsert: their conflict is resolved *after* `BEFORE INSERT` fires, and the
/// row they implicitly `DELETE` is invisible to `BEFORE DELETE` while
/// `recursive_triggers` is off. The guard raises an ordinary `CHECK` failure
/// rather than `RAISE(ABORT)` on purpose: SQLite's `IGNORE` clause swallows a
/// plain constraint failure, so `INSERT OR IGNORE` stays a benign no-op,
/// while `REPLACE` / `DO UPDATE` still abort before the conflicting row is
/// touched. `documents` itself stays mutable because its state (`unverified`
/// by default) and classification are reviewable; only its `content_hash` and
/// `storage_path` are frozen, so a document can never be silently repointed or
/// replaced.
///
/// `retention_years` defaults to 10 years and `retention_until` is
/// filled from it when the caller does not supply an explicit date. Nothing
/// here deletes: no retention timer runs in SQL, and an owner deletion is a
/// later audited event, not an `ON DELETE` cascade.
pub(crate) const MIGRATION_V17: &str = r#"
CREATE TABLE IF NOT EXISTS documents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash    TEXT NOT NULL UNIQUE,
    storage_path    TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL CHECK (size_bytes >= 0),
    mime_type       TEXT NOT NULL,
    kind            TEXT CHECK (kind IS NULL OR kind IN ('invoice', 'ticket')),
    source          TEXT NOT NULL,
    account_id      TEXT,
    channel_id      TEXT,
    original_name   TEXT,
    captured_at     TEXT,
    imported_at     TEXT NOT NULL DEFAULT (datetime('now')),
    jurisdiction    TEXT,
    currency        TEXT,
    state           TEXT NOT NULL DEFAULT 'unverified'
                    CHECK (state IN ('unverified', 'verified', 'quarantined')),
    retention_years INTEGER NOT NULL DEFAULT 10 CHECK (retention_years > 0),
    retention_until TEXT,
    recovered       INTEGER NOT NULL DEFAULT 0 CHECK (recovered IN (0, 1)),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_documents_source ON documents(source);
CREATE INDEX IF NOT EXISTS idx_documents_imported ON documents(imported_at);
CREATE INDEX IF NOT EXISTS idx_documents_state ON documents(state);

CREATE TABLE IF NOT EXISTS proofs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    field_key   TEXT,
    proof_ref   TEXT NOT NULL,
    author      TEXT NOT NULL,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_proofs_document ON proofs(document_id, id);

CREATE TABLE IF NOT EXISTS corrections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    field_key   TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT NOT NULL,
    author      TEXT NOT NULL,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_corrections_document ON corrections(document_id, id);

CREATE TRIGGER IF NOT EXISTS proofs_append_only_update
BEFORE UPDATE ON proofs
BEGIN
    SELECT RAISE(ABORT, 'proofs are append-only');
END;
CREATE TRIGGER IF NOT EXISTS proofs_append_only_delete
BEFORE DELETE ON proofs
BEGIN
    SELECT RAISE(ABORT, 'proofs are append-only');
END;
CREATE TRIGGER IF NOT EXISTS corrections_append_only_update
BEFORE UPDATE ON corrections
BEGIN
    SELECT RAISE(ABORT, 'corrections are append-only');
END;
CREATE TRIGGER IF NOT EXISTS corrections_append_only_delete
BEFORE DELETE ON corrections
BEGIN
    SELECT RAISE(ABORT, 'corrections are append-only');
END;

-- A conflicting INSERT is rejected here, before SQLite resolves the conflict,
-- so `INSERT OR REPLACE` / `REPLACE INTO` (whose implicit DELETE never reaches
-- the `BEFORE DELETE` triggers above while `recursive_triggers` is off) and an
-- upsert cannot silently swap an existing row. The failure is a plain CHECK
-- violation, not `RAISE(ABORT)`, because SQLite's IGNORE clause swallows it:
-- `INSERT OR IGNORE` stays a no-op while REPLACE and DO UPDATE abort.
CREATE TABLE IF NOT EXISTS evidence_guard (
    conflict INTEGER NOT NULL CONSTRAINT append_only CHECK (conflict = 0)
);
CREATE TRIGGER IF NOT EXISTS proofs_append_only_insert
BEFORE INSERT ON proofs
WHEN EXISTS (SELECT 1 FROM proofs WHERE id = NEW.id)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
CREATE TRIGGER IF NOT EXISTS corrections_append_only_insert
BEFORE INSERT ON corrections
WHEN EXISTS (SELECT 1 FROM corrections WHERE id = NEW.id)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
CREATE TRIGGER IF NOT EXISTS documents_no_replace_insert
BEFORE INSERT ON documents
WHEN EXISTS (
    SELECT 1 FROM documents WHERE id = NEW.id OR content_hash = NEW.content_hash
)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
CREATE TRIGGER IF NOT EXISTS documents_immutable_update
BEFORE UPDATE OF content_hash, storage_path ON documents
BEGIN
    SELECT RAISE(ABORT, 'a documents hash and path are immutable');
END;
"#;

/// v19: the `dot` → `agent` rename, and the removal of the v17 invoice ledger.
///
/// Columns are renamed in place, so every row and every index survives; the
/// index names follow their columns. The four invoice tables are dropped
/// children first (`proofs` and `corrections` before `documents`), which
/// drops their append-only triggers with them. Nothing else is touched.
pub(crate) const MIGRATION_V19: &str = r#"
ALTER TABLE sessions RENAME COLUMN dot TO agent;
ALTER TABLE jobs RENAME COLUMN dot TO agent;
ALTER TABLE usage RENAME COLUMN dot TO agent;
ALTER TABLE usage_reservations RENAME COLUMN dot TO agent;
ALTER TABLE budget_stops RENAME COLUMN dot TO agent;
ALTER TABLE memory_items RENAME COLUMN dot TO agent;
ALTER TABLE memory_sources RENAME COLUMN dot TO agent;
ALTER TABLE profile_facts RENAME COLUMN dot TO agent;
ALTER TABLE memory_episodes RENAME COLUMN dot TO agent;
ALTER TABLE memory_notes RENAME COLUMN dot TO agent;
ALTER TABLE memory_mirrors RENAME COLUMN dot TO agent;
DROP INDEX IF EXISTS idx_sessions_dot;
CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent);
DROP INDEX IF EXISTS idx_usage_dot_day;
CREATE INDEX IF NOT EXISTS idx_usage_agent_day ON usage(agent, at);
DROP INDEX IF EXISTS idx_usage_reservations_dot;
CREATE INDEX IF NOT EXISTS idx_usage_reservations_agent ON usage_reservations(agent, expires_at);
DROP INDEX IF EXISTS idx_memory_dot_state;
CREATE INDEX IF NOT EXISTS idx_memory_agent_state ON memory_items(agent, state);
DROP INDEX IF EXISTS idx_memory_dot_kind;
CREATE INDEX IF NOT EXISTS idx_memory_agent_kind ON memory_items(agent, kind);
DROP INDEX IF EXISTS idx_memory_dot_updated;
CREATE INDEX IF NOT EXISTS idx_memory_agent_updated ON memory_items(agent, updated_at);
DROP INDEX IF EXISTS idx_memory_sources_dot;
CREATE INDEX IF NOT EXISTS idx_memory_sources_agent ON memory_sources(agent, item_id);
DROP INDEX IF EXISTS idx_profile_facts_dot;
CREATE INDEX IF NOT EXISTS idx_profile_facts_agent ON profile_facts(agent, fact_key);
DROP INDEX IF EXISTS idx_memory_episodes_dot;
CREATE INDEX IF NOT EXISTS idx_memory_episodes_agent ON memory_episodes(agent, occurred_at);
DROP INDEX IF EXISTS idx_memory_notes_dot;
CREATE INDEX IF NOT EXISTS idx_memory_notes_agent ON memory_notes(agent);
DROP INDEX IF EXISTS idx_memory_active_fact_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_active_agent_fact_key
    ON memory_items(agent, fact_key) WHERE state = 'active';
DROP INDEX IF EXISTS idx_memory_active_hash;
CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_active_agent_content_hash
    ON memory_items(agent, content_hash) WHERE state = 'active';
DROP TABLE IF EXISTS corrections;
DROP TABLE IF EXISTS proofs;
DROP TABLE IF EXISTS evidence_guard;
DROP TABLE IF EXISTS documents;
"#;

/// v21: the evidence registry MA3 first writes.
///
/// v19 removed the v17 invoice ledger when invoices left the app (#200). MA3
/// brings the registry back, deliberately and with the same append-only
/// discipline, because attachments now land in it: `documents` (one row per
/// original, `content_hash` SHA-256 `UNIQUE`), the append-only `proofs` and
/// `corrections` ledgers, and the `evidence_guard` helper the insert guards
/// raise through. It adds one table, `evidence_source`, an append-only
/// provenance row (`source` is JSON) so a known hash can gain a new source
/// without a second document or blob.
///
/// The DDL is the v17 text, verbatim, followed by `evidence_source`. Nothing
/// here deletes or rewrites an existing row, so a populated store upgrades in
/// place; `apply_migration_with_version` records v21 in the same transaction.
pub(crate) const MIGRATION_V21: &str = r#"
CREATE TABLE IF NOT EXISTS documents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    content_hash    TEXT NOT NULL UNIQUE,
    storage_path    TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL CHECK (size_bytes >= 0),
    mime_type       TEXT NOT NULL,
    kind            TEXT CHECK (kind IS NULL OR kind IN ('invoice', 'ticket')),
    source          TEXT NOT NULL,
    account_id      TEXT,
    channel_id      TEXT,
    original_name   TEXT,
    captured_at     TEXT,
    imported_at     TEXT NOT NULL DEFAULT (datetime('now')),
    jurisdiction    TEXT,
    currency        TEXT,
    state           TEXT NOT NULL DEFAULT 'unverified'
                    CHECK (state IN ('unverified', 'verified', 'quarantined')),
    retention_years INTEGER NOT NULL DEFAULT 10 CHECK (retention_years > 0),
    retention_until TEXT,
    recovered       INTEGER NOT NULL DEFAULT 0 CHECK (recovered IN (0, 1)),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_documents_source ON documents(source);
CREATE INDEX IF NOT EXISTS idx_documents_imported ON documents(imported_at);
CREATE INDEX IF NOT EXISTS idx_documents_state ON documents(state);

CREATE TABLE IF NOT EXISTS proofs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    field_key   TEXT,
    proof_ref   TEXT NOT NULL,
    author      TEXT NOT NULL,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_proofs_document ON proofs(document_id, id);

CREATE TABLE IF NOT EXISTS corrections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    field_key   TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT NOT NULL,
    author      TEXT NOT NULL,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_corrections_document ON corrections(document_id, id);

CREATE TRIGGER IF NOT EXISTS proofs_append_only_update
BEFORE UPDATE ON proofs
BEGIN
    SELECT RAISE(ABORT, 'proofs are append-only');
END;
CREATE TRIGGER IF NOT EXISTS proofs_append_only_delete
BEFORE DELETE ON proofs
BEGIN
    SELECT RAISE(ABORT, 'proofs are append-only');
END;
CREATE TRIGGER IF NOT EXISTS corrections_append_only_update
BEFORE UPDATE ON corrections
BEGIN
    SELECT RAISE(ABORT, 'corrections are append-only');
END;
CREATE TRIGGER IF NOT EXISTS corrections_append_only_delete
BEFORE DELETE ON corrections
BEGIN
    SELECT RAISE(ABORT, 'corrections are append-only');
END;

-- A conflicting INSERT is rejected here, before SQLite resolves the conflict,
-- so `INSERT OR REPLACE` / `REPLACE INTO` and an upsert cannot silently swap an
-- existing row. The failure is a plain CHECK violation, not `RAISE(ABORT)`, so
-- `INSERT OR IGNORE` stays a benign no-op while REPLACE and DO UPDATE abort.
CREATE TABLE IF NOT EXISTS evidence_guard (
    conflict INTEGER NOT NULL CONSTRAINT append_only CHECK (conflict = 0)
);
CREATE TRIGGER IF NOT EXISTS proofs_append_only_insert
BEFORE INSERT ON proofs
WHEN EXISTS (SELECT 1 FROM proofs WHERE id = NEW.id)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
CREATE TRIGGER IF NOT EXISTS corrections_append_only_insert
BEFORE INSERT ON corrections
WHEN EXISTS (SELECT 1 FROM corrections WHERE id = NEW.id)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
CREATE TRIGGER IF NOT EXISTS documents_no_replace_insert
BEFORE INSERT ON documents
WHEN EXISTS (
    SELECT 1 FROM documents WHERE id = NEW.id OR content_hash = NEW.content_hash
)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
CREATE TRIGGER IF NOT EXISTS documents_immutable_update
BEFORE UPDATE OF content_hash, storage_path ON documents
BEGIN
    SELECT RAISE(ABORT, 'a documents hash and path are immutable');
END;

-- v21's one new table: where one document came from. `source`
-- is JSON (`{"imap":{account,folder,uid,message_id,part,file_name}}` today).
-- Append-only like `proofs`: a re-download of a known hash adds a source row,
-- never a second document or blob.
-- The documents contract moved out of this repository (see `docs/README.md`);
-- the row this table serves is G5 in `docs/phase1.md`.
CREATE TABLE IF NOT EXISTS evidence_source (
    id          INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    source      TEXT NOT NULL,
    seen_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (document_id, source)
);
CREATE INDEX IF NOT EXISTS idx_evidence_source_document ON evidence_source(document_id, id);
CREATE TRIGGER IF NOT EXISTS evidence_source_append_only_update
BEFORE UPDATE ON evidence_source
BEGIN
    SELECT RAISE(ABORT, 'evidence sources are append-only');
END;
CREATE TRIGGER IF NOT EXISTS evidence_source_append_only_delete
BEFORE DELETE ON evidence_source
BEGIN
    SELECT RAISE(ABORT, 'evidence sources are append-only');
END;
CREATE TRIGGER IF NOT EXISTS evidence_source_append_only_insert
BEFORE INSERT ON evidence_source
WHEN EXISTS (SELECT 1 FROM evidence_source WHERE id = NEW.id)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
-- An `INSERT OR REPLACE` (or upsert) that reuses a `(document_id, source)` pair
-- with a fresh rowid does not match the id guard above, and SQLite would delete
-- the original row to satisfy UNIQUE. This guard runs before any conflict is
-- resolved and refuses the write, so provenance is never rewritten; the plain
-- CHECK failure keeps `INSERT OR IGNORE` a benign no-op.
CREATE TRIGGER IF NOT EXISTS evidence_source_no_duplicate_insert
BEFORE INSERT ON evidence_source
WHEN EXISTS (
    SELECT 1 FROM evidence_source
    WHERE document_id = NEW.document_id AND source = NEW.source
)
BEGIN
    INSERT INTO evidence_guard(conflict) VALUES (1);
END;
"#;

/// v22: the CRM tables, additive. `party` is the client or company, with
/// every name variant the contacts index must tokenise; `relationship`,
/// `interaction` and `followup` carry the graph, the timeline and the tasks.
/// No mail body is ever stored: `interaction.summary` is a short summary
/// written by a skill or the owner.
///
/// The contract's last line, `ALTER TABLE memory_items ADD COLUMN party_id`,
/// is not idempotent, so it is not in this batch: `apply_v22` adds the column
/// under a pragma check inside the same write lock and transaction.
pub(crate) const MIGRATION_V22: &str = r#"
CREATE TABLE IF NOT EXISTS party (
    id            INTEGER PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('person','company')),
    display_name  TEXT NOT NULL,
    name_variants TEXT NOT NULL DEFAULT '[]',
    emails        TEXT NOT NULL DEFAULT '[]',
    phones        TEXT NOT NULL DEFAULT '[]',
    addresses     TEXT NOT NULL DEFAULT '[]',
    tags          TEXT NOT NULL DEFAULT '[]',
    notes         TEXT NOT NULL DEFAULT '',
    origin        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    archived      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS party_by_archived ON party(archived, id);

CREATE TABLE IF NOT EXISTS relationship (
    id       INTEGER PRIMARY KEY,
    from_party INTEGER NOT NULL REFERENCES party(id),
    to_party   INTEGER NOT NULL REFERENCES party(id),
    kind     TEXT NOT NULL CHECK (kind IN ('works_at','reports_to','invoices','other')),
    since    TEXT,
    until    TEXT,
    note     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS relationship_by_from ON relationship(from_party, id);
CREATE INDEX IF NOT EXISTS relationship_by_to ON relationship(to_party, id);

CREATE TABLE IF NOT EXISTS interaction (
    id          INTEGER PRIMARY KEY,
    party_id    INTEGER NOT NULL REFERENCES party(id),
    kind        TEXT NOT NULL CHECK (kind IN ('mail','meeting','call','note','document')),
    at          TEXT NOT NULL,
    source_ref  TEXT NOT NULL,
    summary     TEXT NOT NULL,
    provenance  TEXT NOT NULL,
    UNIQUE (party_id, kind, source_ref)
);
CREATE INDEX IF NOT EXISTS interaction_by_party ON interaction(party_id, at, id);

CREATE TABLE IF NOT EXISTS followup (
    id         INTEGER PRIMARY KEY,
    party_id   INTEGER NOT NULL REFERENCES party(id),
    due        TEXT NOT NULL,
    reason     TEXT NOT NULL,
    created_by TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('open','done','dropped'))
);
CREATE INDEX IF NOT EXISTS followup_by_party ON followup(party_id, status, due);
"#;

/// v23: `document_fields`, the extracted fields and checks of one evidence
/// document (Wave C / C2b). One row per `documents` row,
/// written by the extractor chain: XML in Rust through `aux-invoices`, then the
/// Mac bridge (`pdf_text` / `ocr`), then `none`.
///
/// Beyond the contract's columns this adds the durable bridge queue:
/// `extract_state` (`pending` | `claimed` | `done` | `failed`), `claimed_at`
/// (a claim older than ten minutes is re-queued) and `attempts` (after three
/// the document is `failed` and `to_check` with empty fields). Amounts are
/// integer minor units, never floats. The table is mutable by design (status,
/// tags and corrected fields are edited), so it carries no append-only trigger.
pub(crate) const MIGRATION_V23: &str = r#"
CREATE TABLE IF NOT EXISTS document_fields (
    document_id INTEGER PRIMARY KEY REFERENCES documents(id),
    kind        TEXT NOT NULL CHECK (kind IN ('invoice','receipt','other')),
    extractor   TEXT NOT NULL CHECK (extractor IN ('xml','pdf_text','ocr','none')),
    issuer      TEXT,
    recipient   TEXT,
    issued_on   TEXT,
    currency    TEXT,
    total_minor INTEGER,
    vat_minor   INTEGER,
    number      TEXT,
    fields_json TEXT NOT NULL,
    checks_json TEXT NOT NULL,
    party_id    INTEGER REFERENCES party(id),
    tags        TEXT NOT NULL DEFAULT '[]',
    status      TEXT NOT NULL CHECK (status IN ('to_check','filed','ignored')),
    updated_at  TEXT NOT NULL,
    extract_state TEXT NOT NULL DEFAULT 'pending'
                  CHECK (extract_state IN ('pending','claimed','done','failed')),
    claimed_at  TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
CREATE INDEX IF NOT EXISTS document_fields_by_queue
    ON document_fields(extract_state, claimed_at, document_id);
CREATE INDEX IF NOT EXISTS document_fields_by_number
    ON document_fields(issuer, number);
"#;

/// v26 (PRIVATE-TRANSCRIPT): the token table of each private session. Its
/// rows hold the tokenised copy the provider saw; this table maps each token
/// back to its value, locally, for the owner's screen and for a resume after a
/// restart. Deleting the session deletes its pairs.
pub(crate) const MIGRATION_V26: &str = r#"
CREATE TABLE IF NOT EXISTS session_tokens (
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token      TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (session_id, token)
);
"#;

pub(crate) const MIGRATION_V29: &str = r#"
ALTER TABLE document_fields ADD COLUMN extracted_text TEXT NOT NULL DEFAULT ''
    CHECK (length(CAST(extracted_text AS BLOB)) <= 1048576);
"#;

/// v30: a separate text-only backfill queue, an indexed non-empty-text flag,
/// and durable owner-erasure tombstones. Existing extraction state, review
/// status, links and fields are never reset by this migration.
pub(crate) const MIGRATION_V30: &str = r#"
ALTER TABLE document_fields ADD COLUMN has_extracted_text INTEGER NOT NULL DEFAULT 0
    CHECK (has_extracted_text IN (0, 1));
UPDATE document_fields
   SET has_extracted_text = CASE WHEN extracted_text = '' THEN 0 ELSE 1 END;

CREATE INDEX document_fields_nonempty_text
    ON document_fields(document_id) WHERE has_extracted_text = 1;
CREATE TABLE document_text_backfill (
    document_id INTEGER PRIMARY KEY REFERENCES document_fields(document_id) ON DELETE CASCADE,
    claimed_at TEXT
);
INSERT INTO document_text_backfill(document_id)
SELECT f.document_id
  FROM document_fields AS f
 WHERE f.extract_state = 'done'
   AND f.has_extracted_text = 0
   AND NOT EXISTS (
       SELECT 1 FROM json_each(
           CASE WHEN json_valid(f.checks_json) THEN f.checks_json ELSE '[]' END
       ) AS check_row
        WHERE json_extract(check_row.value, '$.name') = 'party_match'
          AND json_extract(check_row.value, '$.reason') = 'client forgotten'
   );

CREATE TABLE evidence_erase_tombstones (
    document_id INTEGER NOT NULL,
    content_hash TEXT PRIMARY KEY NOT NULL
        CHECK (length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER document_fields_text_flag_insert
AFTER INSERT ON document_fields
WHEN NEW.has_extracted_text != CASE WHEN NEW.extracted_text = '' THEN 0 ELSE 1 END
BEGIN
    UPDATE document_fields
       SET has_extracted_text = CASE WHEN NEW.extracted_text = '' THEN 0 ELSE 1 END
     WHERE document_id = NEW.document_id;
END;
CREATE TRIGGER document_fields_text_flag_update
AFTER UPDATE OF extracted_text ON document_fields
WHEN NEW.has_extracted_text != CASE WHEN NEW.extracted_text = '' THEN 0 ELSE 1 END
BEGIN
    UPDATE document_fields
       SET has_extracted_text = CASE WHEN NEW.extracted_text = '' THEN 0 ELSE 1 END
     WHERE document_id = NEW.document_id;
END;

DROP TRIGGER IF EXISTS documents_delete_requires_erasure;
CREATE TRIGGER documents_delete_requires_erasure
BEFORE DELETE ON documents
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_erase_tombstones
     WHERE document_id = OLD.id AND content_hash = OLD.content_hash
)
BEGIN
    SELECT RAISE(ABORT, 'documents may only be deleted by owner erasure');
END;
DROP TRIGGER IF EXISTS proofs_append_only_delete;
CREATE TRIGGER proofs_append_only_delete
BEFORE DELETE ON proofs
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_erase_tombstones WHERE document_id = OLD.document_id
)
BEGIN
    SELECT RAISE(ABORT, 'proofs are append-only');
END;
DROP TRIGGER IF EXISTS corrections_append_only_delete;
CREATE TRIGGER corrections_append_only_delete
BEFORE DELETE ON corrections
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_erase_tombstones WHERE document_id = OLD.document_id
)
BEGIN
    SELECT RAISE(ABORT, 'corrections are append-only');
END;
DROP TRIGGER IF EXISTS evidence_source_append_only_delete;
CREATE TRIGGER evidence_source_append_only_delete
BEFORE DELETE ON evidence_source
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_erase_tombstones WHERE document_id = OLD.document_id
)
BEGIN
    SELECT RAISE(ABORT, 'evidence sources are append-only');
END;
"#;

/// v31: durable owner-reviewable memory suggestions.
pub(crate) const MIGRATION_V31: &str = r#"
CREATE TABLE IF NOT EXISTS memory_suggestions (
    id INTEGER PRIMARY KEY,
    dot TEXT NOT NULL,
    body TEXT NOT NULL,
    fact_key TEXT,
    source_ref TEXT NOT NULL,
    trust TEXT NOT NULL CHECK (trust IN ('owner','untrusted','tainted')),
    content_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','accepted','rejected')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_suggestions_dot_hash
    ON memory_suggestions(dot, content_hash);
CREATE INDEX IF NOT EXISTS idx_memory_suggestions_pending
    ON memory_suggestions(dot, state, created_at, id);
"#;

/// v33: the sticky per-session "this chat ran in Private mode" mark.
///
/// A chat that ever ran a Private turn is never listed in
/// Conversations. The old rule — a Private turn writes no system row, so a
/// chat without one is private — fails both ways: an Open chat that later
/// takes a Private turn keeps its system row and stays listed, and a Private
/// chat that later takes an Open turn gets its system row back. This column
/// is the durable mark, written the moment a Private turn starts, so a
/// cancelled or crashed Private turn still hides the chat.
///
/// Additive: `NOT NULL DEFAULT 0`, so the column adds a fact and rewrites
/// no row's meaning. The `ALTER` is not idempotent, so it runs under the
/// guarded `IMMEDIATE` transaction of the v7/v13 pattern.
pub(crate) const MIGRATION_V33_ADD_EVER_PRIVATE: &str =
    "ALTER TABLE sessions ADD COLUMN ever_private INTEGER NOT NULL DEFAULT 0;";

/// The fail-safe of v33: every chat session that existed before it is marked.
///
/// We cannot prove an old chat was never Private: a Private turn that
/// detected nothing leaves no marker in the stored rows, so an ambiguous
/// pre-v33 chat could hide a Private transcript. The ruling is to fail
/// closed — every old chat is treated as Private. Losing an old chat from
/// the sidebar is acceptable; showing a Private one is not.
pub(crate) const MIGRATION_V33_MARK_OLD_CHATS: &str =
    "UPDATE sessions SET ever_private = 1 WHERE kind = 'chat';";

/// The same fail-safe for a store whose `sessions` table predates the `kind`
/// column (v7): there is no job row to leave out, so every row is marked.
pub(crate) const MIGRATION_V33_MARK_OLD_CHATS_NO_KIND: &str =
    "UPDATE sessions SET ever_private = 1;";

/// v35: a `mail.draft` may be sent once. The claim row is written before the
/// socket and becomes `sent` after it; a failed send deletes it so the draft
/// stays retryable.
pub(crate) const MIGRATION_V35: &str = r#"
CREATE TABLE IF NOT EXISTS mail_draft_claim (
    draft_id   INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    state      TEXT NOT NULL CHECK (state IN ('claimed', 'sent')),
    claimed_at TEXT NOT NULL DEFAULT (datetime('now')),
    sent_at    TEXT
);
"#;

/// v36: a claim may also be `uncertain`, the state of a send whose server may
/// have accepted the message. The old table's CHECK must be rebuilt.
pub(crate) const MIGRATION_V36: &str = r#"
CREATE TABLE IF NOT EXISTS mail_draft_claim_v36 (
    draft_id   INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    state      TEXT NOT NULL CHECK (state IN ('claimed', 'sent', 'uncertain')),
    claimed_at TEXT NOT NULL DEFAULT (datetime('now')),
    sent_at    TEXT
);
INSERT OR IGNORE INTO mail_draft_claim_v36(draft_id, state, claimed_at, sent_at)
SELECT draft_id, state, claimed_at, sent_at FROM mail_draft_claim;
DROP TABLE mail_draft_claim;
ALTER TABLE mail_draft_claim_v36 RENAME TO mail_draft_claim;
"#;

/// v37: the client's own IANA time zone. `contacts` carries it from a vCard
/// `TZ:` so a re-import of the same source keeps it; `party` carries it to the
/// client card and to the invite runtime. Both `ALTER`s are non-idempotent, so
/// `apply_v37` re-checks the columns under one write lock (the v7/v13 pattern).
pub(crate) const MIGRATION_V37_CONTACTS_TIME_ZONE: &str =
    "ALTER TABLE contacts ADD COLUMN time_zone TEXT;";
pub(crate) const MIGRATION_V37_PARTY_TIME_ZONE: &str =
    "ALTER TABLE party ADD COLUMN time_zone TEXT;";
/// A reservation also holds the money it may spend, so concurrent calls
/// cannot each fit under the daily money cap and together cross it. Rows
/// written before this column existed hold no money.
pub(crate) const MIGRATION_V38_RESERVED_USD: &str =
    "ALTER TABLE usage_reservations ADD COLUMN usd_cents INTEGER NOT NULL DEFAULT 0;";

/// v39: a reservation is held until settled. `unsettled` carries what a
/// settle needs once its process is gone; a held row never expires (a daemon
/// start settles those a dead process left). Older rows still expire.
pub(crate) const MIGRATION_V39_UNSETTLED: &str =
    "ALTER TABLE usage_reservations ADD COLUMN unsettled TEXT;";

/// Enforce the v15 wire-name uniqueness invariant on an existing store.
///
/// A store created by this build has a unique `idx_mcp_tools_wire` and this is
/// a cheap pragma read. A store written by the pre-release v15 draft may have
/// the old **non-unique** index and duplicate wire names; in that case the
/// duplicates are dropped deterministically (the newest parseable
/// `fetched_at` survives, then the lowest `(server, remote_name)` breaks ties)
/// and the index is rebuilt as unique. Runs under an
/// `IMMEDIATE` transaction so two concurrent opens cannot race the rebuild.
fn ensure_mcp_wire_unique(conn: &Connection) -> Result<(), StoreError> {
    let table: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'mcp_tools'",
        [],
        |row| row.get(0),
    )?;
    if table == 0 {
        return Ok(());
    }
    let mut unique = false;
    {
        let mut stmt = conn.prepare("PRAGMA index_list(mcp_tools)")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == "idx_mcp_tools_wire" {
                unique = row.get::<_, i64>(2)? == 1;
            }
        }
    }
    if unique {
        return Ok(());
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    // Keep the newest timestamp per wire name; ties (including two invalid
    // legacy timestamps) go to the lowest `(server, remote_name)` key.
    tx.execute(
        "DELETE FROM mcp_tools
          WHERE EXISTS (
              SELECT 1 FROM mcp_tools AS other
              WHERE other.wire_name = mcp_tools.wire_name
                AND (COALESCE(julianday(other.fetched_at), -1.0e99)
                       > COALESCE(julianday(mcp_tools.fetched_at), -1.0e99)
                     OR (COALESCE(julianday(other.fetched_at), -1.0e99)
                           = COALESCE(julianday(mcp_tools.fetched_at), -1.0e99)
                         AND (other.server < mcp_tools.server
                              OR (other.server = mcp_tools.server
                                  AND other.remote_name < mcp_tools.remote_name))))
          )",
        [],
    )?;
    tx.execute("DROP INDEX IF EXISTS idx_mcp_tools_wire", [])?;
    tx.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_tools_wire ON mcp_tools(wire_name)",
        [],
    )?;
    tx.commit()?;
    Ok(())
}

/// Record the legacy-session watermark if it is not there yet.
fn apply_v8_legacy_watermark(tx: &Transaction<'_>) -> Result<(), StoreError> {
    let present: i64 = tx.query_row(
        "SELECT COUNT(*) FROM meta WHERE key = ?1",
        [META_SESSION_LEGACY_MAX_ID],
        |row| row.get(0),
    )?;
    if present == 0 {
        tx.execute(
            "INSERT INTO meta(key, value)
             SELECT ?1, COALESCE(MAX(id), 0) FROM sessions",
            [META_SESSION_LEGACY_MAX_ID],
        )?;
    }
    Ok(())
}

/// True when the error is SQLite's `SQLITE_BUSY` (another writer holds the
/// lock and a deferred transaction could not wait for it).
fn is_database_busy(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if code.code == rusqlite::ErrorCode::DatabaseBusy
    )
}

impl Store {
    /// Bring the schema up to [`SCHEMA_VERSION`], one additive migration at
    /// a time. Each migration is idempotent, so an interrupted upgrade can
    /// simply be retried by reopening the store.
    ///
    /// Concurrent opens (the daemon and a CLI starting together, or the
    /// concurrency test) contend on SQLite's write lock. The busy timeout
    /// covers a *wait* for the lock, but a deferred transaction's lock
    /// upgrade answers `SQLITE_BUSY` immediately; because every migration is
    /// idempotent, the whole sequence is retried on a busy error.
    pub(crate) fn migrate(&mut self) -> Result<(), StoreError> {
        const ATTEMPTS: usize = 40;
        for attempt in 1..=ATTEMPTS {
            match self.migrate_once() {
                Ok(()) => return Ok(()),
                Err(err) if is_database_busy(&err) && attempt < ATTEMPTS => {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(err) => return Err(err),
            }
        }
        unreachable!("the retry loop returns on the last attempt")
    }

    /// One pass of the migration ladder; see [`Self::migrate`].
    fn migrate_once(&mut self) -> Result<(), StoreError> {
        // Foreign keys are a per-connection setting and must be enabled
        // outside of any transaction. A busy timeout keeps two connections
        // to the same store (daemon + CLI, tests) from failing on a
        // momentary write lock.
        self.conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        self.conn
            .busy_timeout(std::time::Duration::from_millis(5_000))?;

        // v1 predates version tracking in some databases and its DDL is
        // fully idempotent, so ensure it before reading the recorded version.
        self.conn.execute_batch(MIGRATION_V1)?;

        let version = self.recorded_schema_version()?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::SchemaTooNew {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        if version < 2 {
            self.apply_migration(MIGRATION_V2)?;
        }
        if version < 3 {
            self.apply_migration(MIGRATION_V3)?;
        }
        if version < 4 {
            self.apply_migration(MIGRATION_V4)?;
        }
        if version < 5 {
            self.apply_migration(MIGRATION_V5)?;
        }
        if version < 6 {
            self.apply_migration(MIGRATION_V6)?;
        }
        if version < 7 {
            // Serialize with any other process opening this store (the v7
            // ALTER is not idempotent) and re-check the real state inside the
            // write lock.
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: i64 = tx.query_row(
                "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
                [],
                |row| row.get(0),
            )?;
            if current < 7 {
                let has_kind: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'kind'",
                    [],
                    |row| row.get(0),
                )?;
                if has_kind == 0 {
                    tx.execute_batch(MIGRATION_V7_ADD_KIND)?;
                }
                tx.execute_batch(MIGRATION_V7_BACKFILL)?;
            }
            // v8 rides the same write lock: the watermark is what makes the
            // legacy title heuristic safe after this point.
            apply_v8_legacy_watermark(&tx)?;
            tx.commit()?;
        } else if version < 8 {
            // A store already at v7: take the write lock, re-check, and record
            // the watermark. Idempotent when another process raced us.
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: i64 = tx.query_row(
                "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
                [],
                |row| row.get(0),
            )?;
            if current < 8 {
                apply_v8_legacy_watermark(&tx)?;
            }
            tx.commit()?;
        }
        if version < 9 {
            self.apply_migration(MIGRATION_V9)?;
        }
        if version < 10 {
            self.apply_migration(MIGRATION_V10)?;
        }
        if version < 11 {
            self.apply_migration(MIGRATION_V11)?;
        }
        if version < 12 {
            self.apply_migration(MIGRATION_V12)?;
        }
        if version < 13 {
            // The v13 `ALTER` is not idempotent; serialize concurrent opens
            // and re-check both the recorded version and the column itself
            // under the write lock (the v7 pattern).
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: i64 = tx.query_row(
                "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
                [],
                |row| row.get(0),
            )?;
            if current < 13 {
                let has_run_id: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('usage') WHERE name = 'run_id'",
                    [],
                    |row| row.get(0),
                )?;
                if has_run_id == 0 {
                    tx.execute_batch(MIGRATION_V13_ADD_RUN_ID)?;
                }
                tx.execute_batch(MIGRATION_V13_INDEX)?;
            }
            tx.commit()?;
        }
        if version < 14 {
            self.apply_migration(MIGRATION_V14)?;
        }
        if version < 15 {
            self.apply_migration(MIGRATION_V15)?;
        }
        if version < 16 {
            self.apply_migration_with_version(MIGRATION_V16, 16)?;
        }
        if version < 17 {
            // Purely additive DDL (three new tables, their indexes and their
            // append-only triggers), so the idempotent `CREATE … IF NOT
            // EXISTS` batch can run under the plain `IMMEDIATE` transaction.
            self.apply_migration_with_version(MIGRATION_V17, 17)?;
        }
        if version < 18 {
            self.apply_migration_with_version(MIGRATION_V18, 18)?;
        }
        if version < 19 {
            self.apply_v19()?;
        }
        if version < 20 {
            // Purely additive: the contacts table (see `contacts`).
            self.apply_migration_with_version(contacts::MIGRATION_V20, 20)?;
        }
        if version < 21 {
            // Purely additive: the evidence registry (`documents`, `proofs`,
            // `corrections`, `evidence_guard`) and its new `evidence_source`
            // provenance table (MA3).
            self.apply_migration_with_version(MIGRATION_V21, 21)?;
        }
        if version < 22 {
            // The CRM tables. The `ALTER TABLE memory_items` is not idempotent,
            // so the pragma check and the DDL run under one write lock; a
            // concurrent open that lost the race re-checks and stamps v22
            // without touching the column again.
            self.apply_v22()?;
        }
        if version < 23 {
            // The extracted document fields and the durable bridge queue.
            // Purely additive DDL.
            self.apply_migration_with_version(MIGRATION_V23, 23)?;
        }
        if version < 24 {
            // The delegation record and the thread-read marker.
            self.apply_migration_with_version(delegation::MIGRATION_V24, 24)?;
        }
        if version < 25 {
            // The caller's mode at handoff on each delegation.
            delegation::apply_v25(&mut self.conn)?;
        }
        if version < 26 {
            // Each private session's token table.
            self.apply_migration_with_version(MIGRATION_V26, 26)?;
        }
        if version < 27 {
            // Direction column on interaction.
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: i64 = tx.query_row(
                "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
                [],
                |row| row.get(0),
            )?;
            if current < 27 {
                let has_direction: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('interaction') WHERE name = 'direction'",
                    [],
                    |row| row.get(0),
                )?;
                if has_direction == 0 {
                    tx.execute_batch("ALTER TABLE interaction ADD COLUMN direction TEXT;")?;
                }
                // Old mail rows: direction from the `sent:` summary prefix, and
                // the thread key reduced to the root Message-ID (TIMELINE-1).
                tx.execute_batch(
                    "UPDATE interaction SET direction = CASE WHEN summary LIKE 'sent:%'
                       THEN 'out' ELSE 'in' END WHERE kind = 'mail' AND provenance = 'timeline.imap'
                       AND direction IS NULL;
                     UPDATE OR IGNORE interaction SET source_ref = json_object('imap',
                       json_object('message_id', json_extract(source_ref, '$.imap.message_id')))
                      WHERE kind = 'mail' AND provenance = 'timeline.imap'
                        AND CASE WHEN json_valid(source_ref) THEN
                          json_type(source_ref, '$.imap.message_id') = 'text'
                          AND json_type(source_ref, '$.imap.uid') IS NOT NULL ELSE 0 END;",
                )?;
                tx.execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [27_i64.to_string()],
                )?;
            }
            tx.commit()?;
        }
        if version < 28 {
            // INFER-COST-1: per-call brain usage. Purely additive DDL.
            self.apply_migration_with_version(usage_calls::MIGRATION_V28, 28)?;
        }
        if version < 29 {
            self.apply_migration_with_version(MIGRATION_V29, 29)?;
        }
        if version < 30 {
            self.apply_migration_with_version(MIGRATION_V30, 30)?;
        }
        if version < 31 {
            self.apply_migration_with_version(MIGRATION_V31, 31)?;
        }
        if version < 32 {
            self.apply_v32()?;
        }
        if version < 33 {
            // CONV-PRIVATE-MIX: the sticky per-session Private mark. The
            // `ALTER` is not idempotent, so serialize concurrent opens and
            // re-check the version and the column under the write lock (the
            // v7/v13 pattern).
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let (current, has_flag, has_kind): (i64, i64, i64) = tx.query_row(
                "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1),
                        (SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'ever_private'),
                        (SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'kind')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            if current < 33 {
                if has_flag == 0 {
                    tx.execute_batch(MIGRATION_V33_ADD_EVER_PRIVATE)?;
                    // The fail-safe: every chat that existed before this
                    // migration is marked, because we cannot prove an old
                    // chat was never Private. Same transaction, so the
                    // column and the marking land together.
                    tx.execute_batch(if has_kind > 0 {
                        MIGRATION_V33_MARK_OLD_CHATS
                    } else {
                        MIGRATION_V33_MARK_OLD_CHATS_NO_KIND
                    })?;
                }
                tx.execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [33_i64.to_string()],
                )?;
            }
            tx.commit()?;
        }
        if version < 34 {
            self.apply_v34()?;
        }
        if version < 35 {
            self.apply_migration_with_version(MIGRATION_V35, 35)?;
        }
        if version < 36 {
            self.apply_migration_with_version(MIGRATION_V36, 36)?;
        }
        if version < 37 {
            // The client's own zone, on the contacts index and on the card.
            self.apply_v37()?;
        }
        if version < 38 {
            self.apply_v38()?;
        }
        if version < 39 {
            self.apply_v39()?;
        }
        // v15 is unreleased, but a store written by a pre-release draft may
        // already exist with the old non-unique wire index and duplicate wire
        // names. Repair it in place (idempotent: the fast path is a pragma
        // read once the index is unique).
        ensure_mcp_wire_unique(&self.conn)?;

        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }

    /// Apply one idempotent migration under an `IMMEDIATE` transaction.
    ///
    /// The write lock is taken at `BEGIN`, where the busy timeout applies; a
    /// deferred transaction that upgrades later would answer `SQLITE_BUSY`
    /// immediately instead of waiting.
    fn apply_migration(&mut self, sql: &str) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        tx.commit()?;
        Ok(())
    }

    /// Apply the final migration and record its version atomically.
    /// Apply v19 in one transaction. When the v17 invoice ledger holds rows,
    /// they are exported first to `<home>/export/invoices-v17-<UTC>.json`; if
    /// that export fails the transaction is dropped and the store stays v18.
    fn apply_v19(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stamp, export)) = invoice_ledger_export(&tx)? {
            let home = self.export_home.as_deref().ok_or_else(|| {
                StoreError::Io(std::io::Error::other(
                    "the invoice ledger has rows but the store has no home to export them to",
                ))
            })?;
            write_invoice_export(home, &stamp, &export)?;
        }
        tx.execute_batch(MIGRATION_V19)?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [19_i64.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn apply_migration_with_version(&mut self, sql: &str, version: i64) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [version.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// v32 (CRM-NOTE-P3): mark a timeline row written from outside content,
    /// and seed the note counter above every legacy per-process `seq` so the
    /// first new note cannot reuse an old `(party, kind, source_ref)` key.
    /// One transaction, re-checked under the write lock because the `ALTER`
    /// is not idempotent.
    fn apply_v32(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
            [],
            |row| row.get(0),
        )?;
        if current < 32 {
            let has_tainted: i64 = tx.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('interaction') WHERE name = 'tainted'",
                [],
                |row| row.get(0),
            )?;
            if has_tainted == 0 {
                tx.execute_batch(
                    "ALTER TABLE interaction ADD COLUMN tainted INTEGER NOT NULL DEFAULT 0;",
                )?;
            }
            // Legacy note refs are `{"note":"<second>","seq":N}` from a
            // per-process counter. Take the highest N as the seed; the next
            // allocation is N+1, never a key already in the table.
            tx.execute(
                "INSERT INTO meta(key, value)
                 SELECT 'crm.note', COALESCE(MAX(CASE WHEN json_valid(source_ref) THEN
                   CASE WHEN json_type(source_ref, '$.seq') IN ('integer','real')
                        THEN CAST(json_extract(source_ref, '$.seq') AS INTEGER) ELSE 0 END
                   ELSE 0 END), 0)
                   FROM interaction WHERE kind = 'note'
                 ON CONFLICT(key) DO UPDATE SET value = CAST(MAX(
                   CAST(meta.value AS INTEGER), CAST(excluded.value AS INTEGER)) AS TEXT)",
                [],
            )?;
        }
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [32_i64.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// v34: replace key-shaped provider names already stored in
    /// `usage_calls` by older versions. The shared classifier runs in Rust
    /// (SQL cannot peel the percent-encoded copies); the version stamp is
    /// recorded in the same transaction.
    fn apply_v34(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
            [],
            |row| row.get(0),
        )?;
        if current < 34 {
            crate::usage_calls::hide_key_shaped_providers(&tx)?;
        }
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [34_i64.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Apply v37 in one transaction: the contacts index and the party card
    /// each gain the optional `time_zone`. Both `ALTER`s are guarded by a
    /// pragma read under the write lock, so a concurrent open cannot run one
    /// twice (the v7/v13 pattern).
    fn apply_v37(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
            [],
            |row| row.get(0),
        )?;
        if current < 37 {
            for (table, sql) in [
                ("contacts", MIGRATION_V37_CONTACTS_TIME_ZONE),
                ("party", MIGRATION_V37_PARTY_TIME_ZONE),
            ] {
                let has: i64 = tx.query_row(
                    &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = 'time_zone'"),
                    [],
                    |row| row.get(0),
                )?;
                if has == 0 {
                    tx.execute_batch(sql)?;
                }
            }
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [37_i64.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Apply v38: reservations gain `usd_cents`. The `ALTER` is guarded by a
    /// pragma read under the write lock, so a concurrent open cannot run it
    /// twice (the v7/v13 pattern).
    fn apply_v38(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has: i64 = tx.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('usage_reservations') WHERE name = 'usd_cents'",
            [],
            |row| row.get(0),
        )?;
        if has == 0 {
            tx.execute_batch(MIGRATION_V38_RESERVED_USD)?;
        }
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [38_i64.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Apply v39: reservations gain `unsettled`. The `ALTER` is guarded by a
    /// pragma read under the write lock (the v7/v13 pattern).
    fn apply_v39(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has: i64 = tx.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('usage_reservations') WHERE name = 'unsettled'",
            [],
            |row| row.get(0),
        )?;
        if has == 0 {
            tx.execute_batch(MIGRATION_V39_UNSETTLED)?;
        }
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [39_i64.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Apply v22 in one transaction: the CRM tables, then the `memory_items`
    /// `party_id` column when it is not there yet, then the version stamp. The
    /// re-check under the write lock is what keeps a concurrent open from
    /// running the non-idempotent `ALTER` twice (the v7/v13 pattern).
    fn apply_v22(&mut self) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT COALESCE(CAST((SELECT value FROM meta WHERE key = 'schema_version') AS INTEGER), -1)",
            [],
            |row| row.get(0),
        )?;
        if current < 22 {
            tx.execute_batch(MIGRATION_V22)?;
            let has_party_id: i64 = tx.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('memory_items') WHERE name = 'party_id'",
                [],
                |row| row.get(0),
            )?;
            if has_party_id == 0 {
                tx.execute_batch(
                    "ALTER TABLE memory_items ADD COLUMN party_id INTEGER REFERENCES party(id);",
                )?;
            }
            tx.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [22_i64.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Schema version recorded in `meta`, or `-1` when absent or unreadable.
    fn recorded_schema_version(&self) -> Result<i64, StoreError> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(raw.and_then(|value| value.parse().ok()).unwrap_or(-1))
    }

    /// Read the schema version recorded in the store.
    /// Names of every user table, sorted. The privacy enumeration test uses
    /// this to check that each table has a coverage-matrix row
    /// (`docs/phase1.md` §2, the path rows).
    pub fn table_names(&self) -> Result<Vec<String>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let names = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }

    /// The row count of every user table (names come from `sqlite_master`).
    /// Tests use it to prove a path wrote nothing.
    pub fn table_row_counts(&self) -> Result<std::collections::BTreeMap<String, i64>, StoreError> {
        let mut counts = std::collections::BTreeMap::new();
        for name in self.table_names()? {
            let count =
                self.conn
                    .query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |row| {
                        row.get(0)
                    })?;
            counts.insert(name, count);
        }
        Ok(counts)
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        let raw: String = self.conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )?;
        Ok(raw.parse().unwrap_or(-1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{
        MIGRATION_V1, MIGRATION_V10, MIGRATION_V11, MIGRATION_V12, MIGRATION_V13_ADD_RUN_ID,
        MIGRATION_V13_INDEX, MIGRATION_V14, MIGRATION_V15, MIGRATION_V16, MIGRATION_V17,
        MIGRATION_V18, MIGRATION_V2, MIGRATION_V3, MIGRATION_V4, MIGRATION_V5, MIGRATION_V6,
        MIGRATION_V7_ADD_KIND, MIGRATION_V7_BACKFILL, MIGRATION_V9,
    };
    use crate::testutil::*;
    use tempfile::tempdir;

    #[test]
    fn v15_migration_preserves_data_and_reopens_idempotently() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store.create_session("dot-a", Some("preserved")).unwrap();
            restore_dot_columns(&store.conn);
            remove_document_text_additions_for_legacy_fixture(&store.conn).unwrap();
            store
                .conn
                .execute_batch(
                    "DROP TABLE memory_items_fts; DROP TABLE memory_items;
                     UPDATE meta SET value = '15' WHERE key = 'schema_version';",
                )
                .unwrap();
        }
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
            assert_eq!(
                store.list_sessions().unwrap()[0].title.as_deref(),
                Some("preserved")
            );
            assert_eq!(
                store
                    .conn
                    .query_row("SELECT COUNT(*) FROM memory_items", [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn fresh_store_has_current_schema() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    /// v33 adds the sticky per-session Private mark
    /// without rewriting a row's meaning: every session the migration found
    /// keeps its fields, and every chat that existed before it is marked,
    /// because we cannot prove an old chat was never Private.
    #[test]
    fn v33_migration_adds_the_private_mark_and_keeps_the_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store.create_session("aux", Some("kept")).unwrap();
            store
                .conn
                .execute_batch(
                    "ALTER TABLE sessions DROP COLUMN ever_private;
                     UPDATE meta SET value = '32' WHERE key = 'schema_version';",
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].title.as_deref(), Some("kept"));
        let marked: i64 = store
            .conn
            .query_row(
                "SELECT ever_private FROM sessions WHERE id = ?1",
                [sessions[0].id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(marked, 1, "every chat that existed before v32 is marked");
        // Reopening is idempotent: the column is not added twice.
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(reopened.list_sessions().unwrap().len(), 1);
    }

    #[test]
    fn v32_marks_taint_and_seeds_the_note_counter_above_legacy_seqs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let party_id;
        {
            let store = Store::open(&path).unwrap();
            party_id = store.insert_party(&camille_party()).unwrap();
            store
                .insert_interaction(
                    party_id,
                    "note",
                    "2026-10-30T14:00:00Z",
                    "{\"note\":\"2026-10-30T14:00:00Z\",\"seq\":7}",
                    "legacy",
                    "test",
                )
                .unwrap();
            // The store a pre-v32 process left: no taint column, version 31.
            store
                .conn
                .execute_batch(
                    "ALTER TABLE interaction DROP COLUMN tainted;
                     UPDATE meta SET value = '31' WHERE key = 'schema_version';",
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // The first new note takes 8, never the legacy 7 that is already there.
        assert_eq!(store.next_counter("crm.note").unwrap(), 8);
        assert!(!store.interactions_for_party(party_id).unwrap()[0].tainted);
        store
            .insert_interaction_marked(
                party_id,
                "note",
                "2026-10-30T14:00:01Z",
                "{\"tainted\":true}",
                "outside text",
                "test",
                true,
            )
            .unwrap();
        assert!(store.interactions_for_party(party_id).unwrap()[1].tainted);
    }

    #[test]
    fn v34_hides_key_shaped_usage_providers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            // Seed the rows a pre-v34 process wrote. `record_usage_call`
            // itself now stores the placeholder, so bypass it.
            for provider in [
                "sk-proj-canary-7f3k9q",
                "deepseek",
                "%25252573k-proj-canary-7f3k9q",
            ] {
                store
                    .conn
                    .execute(
                        "INSERT INTO usage_calls(agent, provider, call_index)
                         VALUES ('main', ?1, 1)",
                        [provider],
                    )
                    .unwrap();
            }
            store
                .conn
                .execute(
                    "UPDATE meta SET value = '33' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let providers: Vec<String> = {
            let mut stmt = store
                .conn
                .prepare("SELECT provider FROM usage_calls ORDER BY id")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(providers, ["[hidden]", "deepseek", "[hidden]"]);
        assert!(!providers
            .iter()
            .any(|p| p.to_lowercase().contains("canary")));
    }

    /// WO CLIENT-TZ-FIELD: a v36 store (before the client's zone) walks up to
    /// v37 with both new columns, keeping its contact and its party, and the
    /// new column reads back once it is written.
    #[test]
    fn v36_store_upgrades_to_v37_and_keeps_contacts_and_parties() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store.insert_party(&camille_party()).unwrap();
            store
                .replace_contacts(&[ContactRecord {
                    source: "file:old.vcf".to_string(),
                    display_name: Some("Old Contact".to_string()),
                    given: vec!["Old".to_string()],
                    ..ContactRecord::default()
                }])
                .unwrap();
            // The store a pre-v37 process left: neither column yet.
            store
                .conn
                .execute_batch(
                    "ALTER TABLE contacts DROP COLUMN time_zone;
                     ALTER TABLE party DROP COLUMN time_zone;
                     UPDATE meta SET value = '36' WHERE key = 'schema_version';",
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(table_columns(&store, "contacts").contains(&"time_zone".to_string()));
        assert!(table_columns(&store, "party").contains(&"time_zone".to_string()));
        // Nothing was lost, and an old row has no zone rather than a guess.
        let contacts = store.contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].display_name.as_deref(), Some("Old Contact"));
        assert_eq!(contacts[0].time_zone, None);
        let parties = store.parties().unwrap();
        assert_eq!(parties.len(), 1);
        assert_eq!(parties[0].display_name, "Camille Exemple");
        assert_eq!(parties[0].time_zone, None);
        // Reopening is idempotent: no ALTER runs twice.
        drop(store);
        assert_eq!(
            Store::open(&path).unwrap().schema_version().unwrap(),
            SCHEMA_VERSION
        );
    }

    #[test]
    fn v37_store_upgrades_to_v38_and_keeps_its_reservations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            // The store a pre-v38 process left: a live reservation and no
            // money column yet.
            store
                .conn
                .execute_batch(
                    "ALTER TABLE usage_reservations DROP COLUMN usd_cents;
                     INSERT INTO usage_reservations(agent, at, expires_at, tokens_in, tokens_out)
                     VALUES ('main', '2026-10-03', '2999-01-01 00:00:00', 7, 9);
                     UPDATE meta SET value = '37' WHERE key = 'schema_version';",
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let row: (String, i64, i64, i64) = store
            .conn
            .query_row(
                "SELECT agent, tokens_in, tokens_out, usd_cents FROM usage_reservations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            ("main".to_string(), 7, 9, 0),
            "the old row holds no money"
        );
        drop(store);
        assert_eq!(
            Store::open(&path).unwrap().schema_version().unwrap(),
            SCHEMA_VERSION,
            "reopening is idempotent: the ALTER does not run twice"
        );
    }

    #[test]
    fn v21_store_upgrades_to_v22_and_keeps_its_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(write_v21_database(&path));

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(table_columns(&store, "memory_items").contains(&"party_id".to_string()));
        // The pre-v22 memory row survives, and its new column is NULL.
        let hits = store.search_memory("main", "v21body", 8).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "v21 title");
        let party_id: Option<i64> = store
            .conn
            .query_row(
                "SELECT party_id FROM memory_items WHERE id = ?1",
                [hits[0].id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(party_id, None);
        drop(store);

        // A second open at v22 re-checks but runs no DDL twice.
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn v22_store_upgrades_through_v23_to_v24_and_keeps_its_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(write_v22_database(&path));

        let store = Store::open(&path).unwrap();
        // A v22 (B1) store upgrades through v23 (C2b) and v24 (E0) to v26.
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(!table_columns(&store, "session_tokens").is_empty());
        assert!(!table_columns(&store, "document_fields").is_empty());
        assert!(table_columns(&store, "document_fields").contains(&"extract_state".to_string()));
        // The pre-v23 party and original survive; the new table is empty.
        assert_eq!(store.parties().unwrap().len(), 1);
        assert_eq!(
            store.parties().unwrap()[0].display_name,
            "Camille Exemple SARL"
        );
        let documents: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))
            .unwrap();
        let fields: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM document_fields", [], |row| row.get(0))
            .unwrap();
        assert_eq!((documents, fields), (1, 0));

        // A second open at v23 runs no DDL twice.
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn concurrent_first_opens_migrate_the_same_store_safely() {
        use std::sync::{Arc, Barrier};

        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let store = Store::open(&path)?;
                store.schema_version()
            }));
        }
        for handle in handles {
            assert_eq!(
                handle.join().unwrap().unwrap(),
                SCHEMA_VERSION,
                "every concurrent open must land on the current schema"
            );
        }
        // The store is fully usable afterwards (sessions carry their kind).
        let store = Store::open(&path).unwrap();
        let chat = store.create_session("main", Some("after race")).unwrap();
        assert_eq!(
            store.session_kind(chat.id).unwrap().as_deref(),
            Some("chat")
        );
    }

    // ---- migrations ----

    #[test]
    fn v1_database_migrates_to_current_schema_in_place() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v1_database(&path);

        let store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // v1 data survived the upgrade and v1 methods still work.
        assert_eq!(store.event_count("legacy.boot").unwrap(), 1);
        store.log_event("post.upgrade", "{}").unwrap();
        assert_eq!(store.event_count("post.upgrade").unwrap(), 1);
        // v2 tables are usable right after the upgrade.
        let session = store.create_session("main", Some("after upgrade")).unwrap();
        let message = store
            .append_message(session.id, "user", "migrated", None)
            .unwrap();
        assert_eq!(store.list_messages(session.id).unwrap(), vec![message]);
        // …and so are the v3 job tables.
        let job = store
            .create_job("main", "heartbeat", "every 15m", "{}", None)
            .unwrap();
        assert!(job.enabled);
        // …the v4 usage meter…
        let usage = store
            .record_usage("main", UsageKind::TokensIn, 7, "tokens")
            .unwrap();
        assert_eq!(usage.amount, 7);
        let day = store.local_day().unwrap();
        assert_eq!(store.usage_totals("main", &day).unwrap().tokens_in, 7);
        // …and the v5 atomic reservations.
        assert!(matches!(
            store
                .try_reserve("main", &day, &caps(Some(100), None), &estimate(10, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
    }

    #[test]
    fn v2_database_migrates_to_current_schema_in_place() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v2_database(&path);

        let store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // v1 and v2 data survived.
        assert_eq!(store.event_count("legacy.boot").unwrap(), 1);
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].title.as_deref(), Some("legacy session"));
        let messages = store.list_messages(sessions[0].id).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].content, "legacy message");
        // The v3 job tables are created by the same upgrade…
        let job = store
            .create_job(
                "main",
                "digest",
                "daily 08:30",
                r#"{"n":1}"#,
                Some("2026-10-04 06:30:00"),
            )
            .unwrap();
        let run = store.start_run(job.id, "2026-10-04 06:30:00").unwrap();
        assert_eq!(run.job_id, job.id);
        // …and so is the v4 usage meter.
        let usage = store
            .record_usage("main", UsageKind::TokensIn, 7, "tokens")
            .unwrap();
        assert_eq!(usage.amount, 7);
        let day = store.local_day().unwrap();
        assert_eq!(store.usage_totals("main", &day).unwrap().tokens_in, 7);
        // …including the v5 reservations.
        assert!(store.reservation_count().unwrap() == 0);
        assert!(matches!(
            store
                .try_reserve("main", &day, &caps(Some(100), None), &estimate(10, 0))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
    }

    #[test]
    fn v12_database_with_usage_gains_run_id_and_keeps_old_rows_counting() {
        // P3: a populated v12 store upgrades to v13 in place. The added
        // `run_id` column is NULL for every pre-existing row (which keep
        // counting in the day/agent totals), the identity index exists, and a
        // reopen is idempotent.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v12_database(&path);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // Old rows survived with a NULL run_id...
        let null_rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM usage WHERE run_id IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(null_rows, 2, "pre-v13 rows must keep run_id NULL");
        // ...and still count in the recorded day totals.
        assert_eq!(
            store.usage_totals("main", "2026-10-03").unwrap(),
            UsageTotals {
                tokens_in: 11,
                tokens_out: 0,
                usd_cents: 9,
            }
        );
        // The identity index exists and the column accepts new stamped rows.
        assert_eq!(usage_run_index_count(&store), 1, "idx_usage_run must exist");
        store
            .record_usage_for("turn-v13", "main", UsageKind::TokensOut, 4, "tokens")
            .unwrap();
        assert_eq!(
            store.usage_totals_for_run("turn-v13").unwrap().tokens_out,
            4
        );
        drop(store);

        // Reopening is idempotent: same version, rows, and index.
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let null_rows: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM usage WHERE run_id IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(null_rows, 2);
        assert_eq!(
            store.usage_totals("main", "2026-10-03").unwrap().usd_cents,
            9
        );
        assert_eq!(usage_run_index_count(&store), 1);
        // The v14 web-hardening table is appended after main's v13, so it must
        // also fire for a populated store recorded at `schema_version = 12`.
        let private_table: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'session_private_data'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(private_table, 1, "v14 must run on a populated v12 store");
    }

    #[test]
    fn old_rusqlite_v10_store_opens_reads_and_writes() {
        // DEPS-1 moved the workspace from rusqlite 0.31 (bundled SQLite
        // 3.45.0) to rusqlite 0.39 (bundled SQLite 3.50.x). Existing users
        // own store files written by the old version; this fixture was
        // generated through the exact v1..v10 ladder by the old stack (see
        // tests/fixtures/README.md). Opening it must run the migration ladder
        // (a no-op at v10), read every table family and keep writing.
        const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/store-v10-rusqlite031.sqlite");

        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        std::fs::write(&path, FIXTURE).unwrap();

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // The fixture is genuine, not rebuilt by the current SQLite.
        let marker: String = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'deps1_fixture'", // gitleaks:allow
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(marker, "rusqlite 0.31.0 / libsqlite3-sys 0.28.0");

        // Every table family reads back through the public API.
        assert_eq!(store.event_count("legacy.boot").unwrap(), 1);
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        let legacy_id = sessions[0].id;
        assert_eq!(sessions[0].title.as_deref(), Some("legacy session"));
        assert_eq!(
            store.session_kind(legacy_id).unwrap().as_deref(),
            Some("chat")
        );
        let messages = store.list_messages(legacy_id).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, "legacy message");
        assert_eq!(messages[1].meta.as_deref(), Some(r#"{"tokens":5}"#));
        let job = store.job_by_id(1).unwrap().unwrap();
        assert_eq!(job.name, "digest");
        assert_eq!(job.next_run_at.as_deref(), Some("2026-10-05 08:30:00"));
        let runs = store.runs_for_job(1).unwrap();
        assert_eq!(runs[0].summary.as_deref(), Some("legacy run"));
        let totals = store.usage_totals("main", "2026-10-04").unwrap();
        assert_eq!(totals.tokens_in, 42);
        assert_eq!(totals.tokens_out, 7);
        assert_eq!(
            store.workspace_taint("/tmp/legacy-ws").unwrap().as_deref(),
            Some("fetch https://example.test/x")
        );
        let taint = store.session_taint(legacy_id).unwrap().unwrap();
        assert_eq!(taint.tool, "fetch");
        let trust = store.trust_request("/tmp/legacy-ws").unwrap().unwrap();
        assert_eq!(trust.request_id, "req-legacy");
        assert_eq!(trust.code_hash, vec![1, 2, 3, 4]);
        assert_eq!(trust.salt, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(trust.attempts, 1);

        // New writes land in the same old file...
        store.log_event("post.upgrade", "{}").unwrap();
        let fresh = store.create_session("main", Some("after deps-1")).unwrap();
        store
            .append_message(fresh.id, "user", "still writable", None)
            .unwrap();
        store
            .append_message(legacy_id, "assistant", "appended to legacy", None)
            .unwrap();
        drop(store);

        // ...and reopening it is idempotent and still reads clean.
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.event_count("legacy.boot").unwrap(), 1);
        assert_eq!(store.list_messages(legacy_id).unwrap().len(), 3);
        let integrity: String = store
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
    }

    #[test]
    fn migration_is_idempotent_across_reopens() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v1_database(&path);

        {
            let store = Store::open(&path).unwrap();
            store.create_session("main", Some("kept")).unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.event_count("legacy.boot").unwrap(), 1);
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].title.as_deref(), Some("kept"));
    }

    #[test]
    fn database_without_version_record_is_upgraded() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            // M0-era tables but no `schema_version` row.
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    kind       TEXT NOT NULL,
                    payload    TEXT NOT NULL
                );
                "#,
            )
            .unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(store.create_session("main", None).is_ok());
        assert!(store
            .create_job("main", "j", "every 15m", "{}", None)
            .is_ok());
        assert!(store
            .record_usage("main", UsageKind::TokensIn, 1, "tokens")
            .is_ok());
    }

    #[test]
    fn v3_database_keeps_jobs_and_gains_the_usage_meter() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v3_database(&path);

        let store = Store::open(&path).unwrap();

        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // The v3 world is untouched: sessions and scheduler data survive.
        assert_eq!(
            store.list_sessions().unwrap()[0].title.as_deref(),
            Some("from v3")
        );
        let job = store.job_by_id(1).unwrap().unwrap();
        assert_eq!(job.name, "v3 job");
        assert_eq!(job.payload, r#"{"kept":true}"#);
        assert_eq!(job.next_run_at.as_deref(), Some("2026-10-04 06:30:00"));
        let runs = store.runs_for_job(1).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, RUN_OK);
        assert_eq!(runs[0].summary.as_deref(), Some("from v3"));
        // …and v4 is ready…
        store
            .record_usage("main", UsageKind::TokensOut, 3, "tokens")
            .unwrap();
        let day = store.local_day().unwrap();
        assert_eq!(store.usage_totals("main", &day).unwrap().tokens_out, 3);
        // …plus the v5 reservations.
        assert!(matches!(
            store
                .try_reserve("main", &day, &caps(Some(100), Some(100)), &estimate(3, 1))
                .unwrap(),
            ReserveOutcome::Reserved(_)
        ));
    }

    #[test]
    fn v14_database_with_data_gains_mcp_tools_and_keeps_rows() {
        // A populated store of the **previous** version upgrades in place:
        // v15 appends `mcp_tools`, v16 appends memory and v17 appends the
        // invoice evidence ledger, none of them touching a single pre-existing
        // row; reopening is idempotent.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v14_database(&path);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // Pre-v15 data is intact.
        assert_eq!(store.event_count("v14.boot").unwrap(), 1);
        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].title.as_deref(), Some("from v14"));
        assert_eq!(
            store.list_messages(sessions[0].id).unwrap()[0].content,
            "kept"
        );
        assert_eq!(
            store.usage_totals("main", "2026-10-01").unwrap().tokens_in,
            12
        );
        // v15 is present and usable.
        let table: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'mcp_tools'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table, 1, "v15 must create mcp_tools");
        let index: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'idx_mcp_tools_wire'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index, 1, "v15 must create idx_mcp_tools_wire");
        store
            .upsert_mcp_tools(&[mcp_tool("server-1", "ACME_CRM_LIST")])
            .unwrap();
        assert_eq!(store.mcp_tool_count().unwrap(), 1);
        drop(store);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(store.event_count("v14.boot").unwrap(), 1);
        assert_eq!(
            store.mcp_tools_for_server("server-1").unwrap().len(),
            1,
            "the v15 rows survive the reopen"
        );
    }

    #[test]
    fn a_newer_store_is_refused_by_an_older_binary() {
        // Simulate an older binary: the recorded version is one newer
        // than the schema this build understands. The existing `SchemaTooNew`
        // gate must fail closed instead of downgrading the file in place.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
            store
                .conn
                .execute(
                    "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                    [(SCHEMA_VERSION + 1).to_string()],
                )
                .unwrap();
        }

        let err = Store::open(&path).unwrap_err();
        assert!(matches!(
            err,
            StoreError::SchemaTooNew { found, supported }
                if found == SCHEMA_VERSION + 1 && supported == SCHEMA_VERSION
        ));
    }

    #[test]
    fn v15_fixture_upgrades_through_v16_to_v17_and_preserves_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v15_database(&path);
        // Sanity: the derived fixture really is a genuine v10 store walked up
        // to v15 (its own marker and rows are still there).
        {
            let conn = Connection::open(&path).unwrap();
            let recorded: String = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(recorded, "15");
            let marker: String = conn
                .query_row(
                    "SELECT value FROM meta WHERE key = 'deps1_fixture'", // gitleaks:allow
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(marker, "rusqlite 0.31.0 / libsqlite3-sys 0.28.0");
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // Rows the genuine fixture carried are intact after v18.
        assert_eq!(store.event_count("legacy.boot").unwrap(), 1);
        assert_eq!(store.event_count("v15.boot").unwrap(), 1);
        assert_eq!(
            store.list_sessions().unwrap()[0].title.as_deref(),
            Some("legacy session")
        );
        // v19 drops the v17 invoice ledger's rows; v21 re-establishes the
        // evidence registry (empty) so MA3's attachments have a home.
        for name in [
            "documents",
            "proofs",
            "corrections",
            "evidence_guard",
            "evidence_source",
            "proofs_append_only_update",
            "proofs_append_only_delete",
            "proofs_append_only_insert",
            "corrections_append_only_update",
            "corrections_append_only_delete",
            "corrections_append_only_insert",
            "documents_no_replace_insert",
            "documents_immutable_update",
            "evidence_source_append_only_update",
            "evidence_source_append_only_delete",
            "evidence_source_append_only_insert",
        ] {
            let count: i64 = store
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                    [name],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{name} must exist after v21");
        }
        for table in ["documents", "proofs", "corrections", "evidence_source"] {
            let rows: i64 = store
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table} must be empty after the v19 invoice drop");
        }
        drop(store);

        // Reopening at v18 is idempotent and preserves the v15 data.
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(reopened.event_count("legacy.boot").unwrap(), 1);
        assert_eq!(reopened.event_count("v15.boot").unwrap(), 1);
    }

    #[test]
    fn v16_fixture_gains_v17_and_v18_without_touching_memory_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v16_database(&path);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // v16 memory survives and still answers through the FTS-backed API.
        let hits = store.search_memory("main", "v16body", 8).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "v16 title");
        // The v15 table is untouched by the migrations that follow it.
        let mcp: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'mcp_tools'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mcp, 1);
        drop(store);

        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(
            reopened.search_memory("main", "v16body", 8).unwrap().len(),
            1
        );
    }

    #[test]
    fn v18_store_renames_dot_columns_to_agent_and_drops_invoice_tables() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v18.db");
        {
            // The v18 schema, built from the historical DDL in ladder order.
            let conn = Connection::open(&path).unwrap();
            for sql in [
                MIGRATION_V1,
                MIGRATION_V2,
                MIGRATION_V3,
                MIGRATION_V4,
                MIGRATION_V5,
                MIGRATION_V6,
                MIGRATION_V7_ADD_KIND,
                MIGRATION_V7_BACKFILL,
                MIGRATION_V9,
                MIGRATION_V10,
                MIGRATION_V11,
                MIGRATION_V12,
                MIGRATION_V13_ADD_RUN_ID,
                MIGRATION_V13_INDEX,
                MIGRATION_V14,
                MIGRATION_V15,
                MIGRATION_V16,
                MIGRATION_V17,
                MIGRATION_V18,
            ] {
                conn.execute_batch(sql).unwrap();
            }
            conn.execute_batch(
                "INSERT INTO meta(key, value) VALUES ('schema_version', '18')
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                 INSERT INTO sessions(dot, title) VALUES ('main', 'v18 session');
                 INSERT INTO usage(dot, kind, amount, unit) VALUES ('main', 'tokens', 7, 'tok');",
            )
            .unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // Rows survive under the renamed column.
        let title: String = store
            .conn
            .query_row("SELECT title FROM sessions WHERE agent = 'main'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(title, "v18 session");
        let spent: i64 = store
            .conn
            .query_row(
                "SELECT SUM(amount) FROM usage WHERE agent = 'main'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(spent, 7);
        // v19 discarded the v17 invoice rows; v21 re-establishes an empty
        // evidence registry for MA3, so only the rows tell the story.
        for table in ["documents", "proofs", "corrections", "evidence_source"] {
            let rows: i64 = store
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(rows, 0, "{table} carries no invoice row");
        }
        drop(store);

        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn v18_store_exports_invoice_rows_before_dropping_them() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let conn = write_v18_fixture(&path);
        conn.execute_batch(
            "INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source)
               VALUES ('abc123', 'invoices/originals/abc123', 42, 'application/pdf', 'mail');
             INSERT INTO proofs(document_id, proof_ref, author)
               VALUES (1, 'proof-1', 'owner');
             INSERT INTO corrections(document_id, field_key, new_value, author)
               VALUES (1, 'total', '12.00', 'owner');",
        )
        .unwrap();
        drop(conn);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // The export ran, then v19 dropped the invoice rows; v21 re-created the
        // registry empty, so the rows are gone even though the tables exist.
        let leftovers: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(leftovers, 0);
        let proofs: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM proofs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(proofs, 0);
        drop(store);

        let files = export_files(dir.path());
        assert_eq!(files.len(), 1, "{files:?}");
        let name = files[0].file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("invoices-v17-") && name.ends_with(".json"),
            "{name}"
        );
        let exported: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&files[0]).unwrap()).unwrap();
        assert_eq!(exported["documents"][0]["content_hash"], "abc123");
        assert_eq!(exported["documents"][0]["size_bytes"], 42);
        assert_eq!(exported["proofs"][0]["proof_ref"], "proof-1");
        assert_eq!(exported["corrections"][0]["new_value"], "12.00");
        assert_eq!(exported["evidence_guard"], serde_json::json!([]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&files[0]).unwrap().permissions().mode();
            assert_eq!(file_mode & 0o777, 0o600);
            let dir_mode = std::fs::metadata(dir.path().join("export"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
    }

    #[test]
    fn v18_store_with_empty_invoice_tables_writes_no_export() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        drop(write_v18_fixture(&path));

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        drop(store);
        assert!(export_files(dir.path()).is_empty());
        assert!(!dir.path().join("export").exists());
    }

    #[test]
    fn v18_store_stays_at_v18_when_the_invoice_export_cannot_be_written() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let conn = write_v18_fixture(&path);
        conn.execute_batch(
            "INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source)
               VALUES ('def456', 'invoices/originals/def456', 7, 'application/pdf', 'mail');",
        )
        .unwrap();
        drop(conn);
        // A regular file where the export folder must go: the export cannot run.
        std::fs::write(dir.path().join("export"), "not a folder").unwrap();

        assert!(Store::open(&path).is_err());
        let raw = encryption::open_encrypted(&path).unwrap();
        let recorded: String = raw
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recorded, "18");
        let documents: i64 = raw
            .query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))
            .unwrap();
        assert_eq!(documents, 1, "the invoice rows survive the failed upgrade");
    }

    #[test]
    fn v6_database_gains_session_kinds_and_backfills_job_sessions() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        write_v3_database(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(MIGRATION_V4).unwrap();
            conn.execute_batch(MIGRATION_V5).unwrap();
            conn.execute_batch(MIGRATION_V6).unwrap();
            conn.execute_batch(
                "INSERT INTO sessions(dot, title) VALUES ('main', 'job v3 job');
                 INSERT INTO sessions(dot, title) VALUES ('main', 'a real chat');
                 UPDATE meta SET value = '6' WHERE key = 'schema_version';",
            )
            .unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);

        let kind_of = |title: &str| -> String {
            store
                .conn
                .query_row(
                    "SELECT kind FROM sessions WHERE title = ?1",
                    [title],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(
            kind_of("job v3 job"),
            "job",
            "a historical `job <name>` session is backfilled"
        );
        assert_eq!(kind_of("a real chat"), "chat");
        // The v3 data is untouched.
        assert_eq!(store.job_by_id(1).unwrap().unwrap().name, "v3 job");
        // The v8 watermark pins every row that existed at migration time:
        // ids 1..=3, including the two fresh sessions this fixture added.
        let watermark: String = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'sessions_kind_legacy_max_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(watermark, "3", "pre-migration rows are legacy by id");

        // A session created after the migration is unambiguously post-v8.
        let after = store.create_session("main", Some("fresh")).unwrap();
        let watermark_after: String = store
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'sessions_kind_legacy_max_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(watermark_after, "3");
        assert!(after.id > 3, "new ids stay above the watermark");
    }

    #[test]
    fn a_v7_database_records_its_legacy_watermark_once() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        // A v7 store: the kind column exists, two sessions predate the v8
        // watermark, and the recorded version says v7. The watermark key is
        // removed because a genuine v7 store never saw the v8 migration (the
        // first `open` above ran it with an empty table).
        {
            let store = Store::open(&path).unwrap();
            store.create_session("main", Some("one")).unwrap();
            store.create_session("main", Some("two")).unwrap();
            store
                .conn
                .execute(
                    "DELETE FROM meta WHERE key = ?1",
                    [META_SESSION_LEGACY_MAX_ID],
                )
                .unwrap();
            restore_dot_columns(&store.conn);
            remove_document_text_additions_for_legacy_fixture(&store.conn).unwrap();
            store
                .conn
                .execute(
                    "UPDATE meta SET value = '7' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }

        let store = Store::open(&path).unwrap();
        let watermark = |store: &Store| -> String {
            store
                .conn
                .query_row(
                    "SELECT value FROM meta WHERE key = 'sessions_kind_legacy_max_id'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(watermark(&store), "2");
        // Reopening must not move the watermark, even after new sessions.
        let fresh = store.create_session("main", Some("three")).unwrap();
        assert!(fresh.id > 2);
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(watermark(&store), "2");
    }

    #[test]
    fn a_store_that_recorded_the_amended_v9_is_repaired_by_v10() {
        // P2 regression (security-review round 3): v9 was edited in place, so a
        // store that recorded a ws-c-1/ws-c-2-shaped version 9 skipped the
        // `session_taint` creation and every chat failed with `no such
        // table`. v10 must repair it on the next open.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            let session = store.create_session("main", None).unwrap();
            store
                .mark_session_tainted(session.id, "shell", None)
                .unwrap();
        }
        // Forge the ws-c-2 shape: file_taint present, session_taint absent,
        // version pinned back to 9.
        let raw = open_keyed(&path).unwrap();
        restore_dot_columns(&raw);
        remove_document_text_additions_for_legacy_fixture(&raw).unwrap();
        raw.execute_batch(
            "DROP TABLE session_taint;
             CREATE TABLE file_taint (path TEXT PRIMARY KEY, stamp TEXT NOT NULL);
             DROP TABLE trust_requests;
             UPDATE meta SET value = '9' WHERE key = 'schema_version';",
        )
        .unwrap();
        drop(raw);

        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        let session = store.create_session("main", Some("repaired")).unwrap();
        store
            .mark_session_tainted(session.id, "shell", Some("repaired"))
            .unwrap();
        assert!(store.session_taint(session.id).unwrap().is_some());
        let stale: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'file_taint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stale, 0, "the round-1 ledger must be dropped");
        let trust: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'trust_requests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(trust, 1, "the trust ledger must exist");
    }

    // ---- M0 regression tests (security-review findings) ----

    #[test]
    fn newer_schema_is_refused_not_downgraded() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let store = Store::open(&path).unwrap();
            store
                .conn
                .execute(
                    "UPDATE meta SET value = '99' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }

        let err = Store::open(&path).unwrap_err();
        assert!(matches!(
            err,
            StoreError::SchemaTooNew {
                found: 99,
                supported: SCHEMA_VERSION
            }
        ));
    }

    fn export_files(home: &Path) -> Vec<PathBuf> {
        match std::fs::read_dir(home.join("export")) {
            Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn usage_run_index_count(store: &Store) -> i64 {
        store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index' AND name = 'idx_usage_run'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    /// Create a store in the shape v12 leaves behind: the full pre-v13 schema,
    /// two existing `usage` rows (the `run_id` column does not exist yet), and
    /// a recorded version of 12.
    fn write_v12_database(path: &Path) {
        let conn = Connection::open(path).unwrap();
        for migration in [
            MIGRATION_V1,
            MIGRATION_V2,
            MIGRATION_V3,
            MIGRATION_V4,
            MIGRATION_V5,
            MIGRATION_V6,
            MIGRATION_V7_ADD_KIND,
            MIGRATION_V7_BACKFILL,
            MIGRATION_V9,
            MIGRATION_V10,
            MIGRATION_V11,
            MIGRATION_V12,
        ] {
            conn.execute_batch(migration).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO meta(key, value) VALUES ('schema_version', '12')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage(dot, at, kind, amount, unit)
             VALUES ('main', '2026-10-03 08:00:00', 'tokens_in', 11, 'tokens')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage(dot, at, kind, amount, unit)
             VALUES ('main', '2026-10-03 08:00:00', 'usd_cents', 9, 'cents')",
            [],
        )
        .unwrap();
    }

    /// Create a store in the shape v14 leaves behind: the full pre-v15
    /// schema, one event, one session with a message, one usage row, and a
    /// recorded version of 14.
    fn write_v14_database(path: &Path) {
        let conn = Connection::open(path).unwrap();
        for migration in [
            MIGRATION_V1,
            MIGRATION_V2,
            MIGRATION_V3,
            MIGRATION_V4,
            MIGRATION_V5,
            MIGRATION_V6,
            MIGRATION_V7_ADD_KIND,
            MIGRATION_V7_BACKFILL,
            MIGRATION_V9,
            MIGRATION_V10,
            MIGRATION_V11,
            MIGRATION_V12,
            MIGRATION_V13_ADD_RUN_ID,
            MIGRATION_V13_INDEX,
            MIGRATION_V14,
        ] {
            conn.execute_batch(migration).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO meta(key, value) VALUES ('schema_version', '14')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;
             INSERT INTO meta(key, value) VALUES ('sessions_kind_legacy_max_id', '1')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events(kind, payload) VALUES ('v14.boot', '{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions(dot, title) VALUES ('main', 'from v14')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(session_id, role, content) VALUES (1, 'user', 'kept')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO usage(dot, at, kind, amount, unit)
             VALUES ('main', '2026-10-01 08:00:00', 'tokens_in', 12, 'tokens')",
            [],
        )
        .unwrap();
    }

    /// Create a store in the shape v15 leaves behind.
    ///
    /// Derived from the genuine `store-v10` fixture
    /// (written by the old rusqlite 0.31 stack) by walking the v11..v15 ladder
    /// against it, then stamping version 15 and appending one v15-era event so
    /// the v15→v16→v17 upgrade can prove it survives.
    fn write_v15_database(path: &Path) {
        const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/store-v10-rusqlite031.sqlite");
        std::fs::write(path, FIXTURE).unwrap();
        let conn = Connection::open(path).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        for migration in [
            MIGRATION_V11,
            MIGRATION_V12,
            MIGRATION_V13_ADD_RUN_ID,
            MIGRATION_V13_INDEX,
            MIGRATION_V14,
            MIGRATION_V15,
        ] {
            conn.execute_batch(migration).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO meta(key, value) VALUES ('schema_version', '15')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;
             INSERT INTO events(kind, payload) VALUES ('v15.boot', '{}');",
        )
        .unwrap();
    }

    /// v15 plus the v16 memory table, holding one v16-era memory row.
    fn write_v16_database(path: &Path) {
        write_v15_database(path);
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(MIGRATION_V16).unwrap();
        conn.execute_batch(
            "INSERT INTO meta(key, value) VALUES ('schema_version', '16')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;
             INSERT INTO memory_items(dot, kind, title, body, source, trust, tainted, state, content_hash)
             VALUES ('main', 'fact', 'v16 title', 'v16body', 'test', 'owner', 0, 'active', 'v16hash');",
        )
        .unwrap();
    }

    /// The v18 schema from the historical DDL, in ladder order, at `path`.
    fn write_v18_fixture(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        for sql in [
            MIGRATION_V1,
            MIGRATION_V2,
            MIGRATION_V3,
            MIGRATION_V4,
            MIGRATION_V5,
            MIGRATION_V6,
            MIGRATION_V7_ADD_KIND,
            MIGRATION_V7_BACKFILL,
            MIGRATION_V9,
            MIGRATION_V10,
            MIGRATION_V11,
            MIGRATION_V12,
            MIGRATION_V13_ADD_RUN_ID,
            MIGRATION_V13_INDEX,
            MIGRATION_V14,
            MIGRATION_V15,
            MIGRATION_V16,
            MIGRATION_V17,
            MIGRATION_V18,
        ] {
            conn.execute_batch(sql).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO meta(key, value) VALUES ('schema_version', '18')
               ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        )
        .unwrap();
        conn
    }

    /// A store in the shape v21 leaves behind, with one memory row to preserve.
    fn write_v21_database(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        for sql in [
            MIGRATION_V1,
            MIGRATION_V2,
            MIGRATION_V3,
            MIGRATION_V4,
            MIGRATION_V5,
            MIGRATION_V6,
            MIGRATION_V7_ADD_KIND,
            MIGRATION_V7_BACKFILL,
            MIGRATION_V9,
            MIGRATION_V10,
            MIGRATION_V11,
            MIGRATION_V12,
            MIGRATION_V13_ADD_RUN_ID,
            MIGRATION_V13_INDEX,
            MIGRATION_V14,
            MIGRATION_V15,
            MIGRATION_V16,
            MIGRATION_V17,
            MIGRATION_V18,
            MIGRATION_V19,
            crate::contacts::MIGRATION_V20,
            MIGRATION_V21,
        ] {
            conn.execute_batch(sql).unwrap();
        }
        conn.execute_batch(
            "INSERT INTO meta(key, value) VALUES ('schema_version', '21')
               ON CONFLICT(key) DO UPDATE SET value = excluded.value;
             INSERT INTO memory_items(agent, kind, title, body, source, trust, tainted, state, content_hash)
             VALUES ('main', 'fact', 'v21 title', 'v21body', 'test', 'owner', 0, 'active', 'v21hash');",
        )
        .unwrap();
        conn
    }

    /// A v22 store: the v21 evidence registry, the CRM tables and the
    /// `memory_items.party_id` column, with one party and one original.
    fn write_v22_database(path: &Path) -> Connection {
        let conn = write_v21_database(path);
        conn.execute_batch(&format!(
            "{MIGRATION_V22}
             ALTER TABLE memory_items ADD COLUMN party_id INTEGER REFERENCES party(id);
             INSERT INTO party(kind, display_name, name_variants, emails, phones, addresses,
                               tags, notes, origin, created_at, updated_at, archived)
             VALUES ('company', 'Camille Exemple SARL', '[]', '[]', '[]', '[]', '[]', '',
                     'owner', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', 0);
             INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source, state)
             VALUES ('{hash}', 'evidence/{hash}', 4, 'application/pdf', 'imap', 'unverified');
             INSERT INTO meta(key, value) VALUES ('schema_version', '22')
               ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            hash = "a".repeat(64),
        ))
        .unwrap();
        conn
    }

    /// Create a store file in the exact v2 shape (M1 code, before v3).
    fn write_v2_database(path: &Path) {
        write_v1_database(path);
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                dot        TEXT NOT NULL,
                title      TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                role       TEXT NOT NULL,
                content    TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                meta       TEXT
            );
            INSERT INTO sessions(dot, title) VALUES ('main', 'legacy session');
            INSERT INTO messages(session_id, role, content)
                VALUES (1, 'user', 'legacy message');
            UPDATE meta SET value = '2' WHERE key = 'schema_version';
            "#,
        )
        .unwrap();
    }

    /// Create a store in the shape the scheduler slice (v3) leaves behind:
    /// the v2 tables plus the v3 `jobs`/`runs` tables, one job and one run,
    /// and a recorded version of 3 — but no `usage` table yet.
    fn write_v3_database(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute_batch(MIGRATION_V2).unwrap();
        conn.execute_batch(MIGRATION_V3).unwrap();
        conn.execute_batch(
            "INSERT INTO meta(key, value) VALUES ('schema_version', '3')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions(dot, title) VALUES ('main', 'from v3')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO jobs(dot, name, schedule, payload, enabled, next_run_at)
             VALUES ('main', 'v3 job', 'every 15m', '{\"kept\":true}', 1, '2026-10-04 06:30:00')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO runs(job_id, started_at, finished_at, status, summary)
             VALUES (1, '2026-10-03 08:00:00', '2026-10-03 08:00:01', 'ok', 'from v3')",
            [],
        )
        .unwrap();
    }
}
