//! Shared helpers for the store's tests.
//!
//! The fixtures that more than one topic's tests need: the old
//! database shapes, the party builder, and the small helpers that
//! read a table back.

use super::*;

/// A person party with a display name, two variants, an address and a phone.
pub(crate) fn camille_party() -> NewParty {
    NewParty {
        kind: PartyKind::Person,
        display_name: "Camille Exemple".to_string(),
        name_variants: vec!["Camille".to_string(), "Exemple".to_string()],
        emails: vec!["camille.exemple@exemple.test".to_string()],
        phones: vec!["+33612345678".to_string()],
        origin: "owner".to_string(),
        ..NewParty::default()
    }
}

// ---- spend reservations (v5) ----

pub(crate) fn caps(tokens_in: Option<u64>, tokens_out: Option<u64>) -> BudgetCaps {
    BudgetCaps {
        tokens_in,
        tokens_out,
        usd_cents: None,
        connector_calls: None,
        unlimited: false,
    }
}

pub(crate) fn estimate(tokens_in: u64, tokens_out: u64) -> UsageTotals {
    UsageTotals {
        tokens_in,
        tokens_out,
        usd_cents: 0,
    }
}

pub(crate) fn mcp_tool(server: &str, remote: &str) -> McpToolRecord {
    McpToolRecord {
        server: server.to_string(),
        remote_name: remote.to_string(),
        wire_name: canonical_mcp_tool_wire_name(server, remote),
        toolkit: "crm".to_string(),
        description: "list records".to_string(),
        schema_json: r#"{"type":"object","properties":{}}"#.to_string(),
        tags_json: "[]".to_string(),
        descriptor_json: r#"{"name":"ACME_CRM_LIST"}"#.to_string(),
        risk: "low".to_string(),
        risk_basis: "tag:read".to_string(),
        fetched_at: "2026-10-01 08:00:00".to_string(),
        ttl_seconds: 3600,
    }
}

/// Put the v19 column renames back, so a test can walk a current store down
/// to the v18 shape that the older migrations expect.
pub(crate) fn restore_dot_columns(conn: &Connection) {
    conn.execute_batch(
        "ALTER TABLE sessions RENAME COLUMN agent TO dot;
     ALTER TABLE jobs RENAME COLUMN agent TO dot;
     ALTER TABLE usage RENAME COLUMN agent TO dot;
     ALTER TABLE usage_reservations RENAME COLUMN agent TO dot;
     ALTER TABLE budget_stops RENAME COLUMN agent TO dot;
     ALTER TABLE memory_items RENAME COLUMN agent TO dot;
     ALTER TABLE memory_sources RENAME COLUMN agent TO dot;
     ALTER TABLE profile_facts RENAME COLUMN agent TO dot;
     ALTER TABLE memory_episodes RENAME COLUMN agent TO dot;
     ALTER TABLE memory_notes RENAME COLUMN agent TO dot;
     ALTER TABLE memory_mirrors RENAME COLUMN agent TO dot;",
    )
    .unwrap();
}

/// The columns of one table (empty when the table does not exist).
pub(crate) fn table_columns(store: &Store, table: &str) -> Vec<String> {
    let mut statement = store
        .conn
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
        .unwrap();
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// Create a store file in the exact v1 shape.
pub(crate) fn write_v1_database(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
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
        INSERT INTO meta(key, value) VALUES ('schema_version', '1');
        INSERT INTO events(kind, payload) VALUES ('legacy.boot', '{"m0":true}');
        "#,
    )
    .unwrap();
}
