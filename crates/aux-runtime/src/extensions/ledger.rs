//! The `ext.*` Ledger rows.
//!
//! Rows go on the existing `events` table with the same plain-string `kind`
//! the rest of the app uses. A row never carries a secret value; the payload
//! is `name`/`version`/`sha256` and a content-free `reason` when refused.
//!
//! Logging is best-effort from the CLI path: the operation itself is the
//! source of truth and a store that cannot open must not turn a successful
//! mount into a failure. The daemon passes its own store when it has one.

use std::path::Path;

use serde_json::Value;

/// Row kinds this module writes.
pub const INSTALL: &str = "ext.install";
/// See [`INSTALL`].
pub const REMOVE: &str = "ext.remove";
/// See [`INSTALL`].
pub const MOUNT: &str = "ext.mount";
/// See [`INSTALL`].
pub const UNMOUNT: &str = "ext.unmount";
/// See [`INSTALL`].
pub const FROZEN: &str = "ext.frozen";
/// See [`INSTALL`].
pub const VERIFY: &str = "ext.verify";
/// See [`INSTALL`].
pub const CATALOG_REFUSED: &str = "ext.catalog_refused";
/// The owner approved one MCP install preview. The payload is the server
/// id, the agent and the binding hash — never a secret or a tool argument.
pub const MCP_APPROVE: &str = "mcp.approve";

/// Write one row through an already-open store.
pub fn log_with(store: &aux_store::Store, kind: &str, payload: &Value) -> Result<(), String> {
    store
        .log_event(kind, &payload.to_string())
        .map_err(|err| err.to_string())
}

/// Write one row to `home/store.db`, best-effort.
///
/// The CLI has no long-lived store handle, so it opens the verified home's
/// store for the row. A store that cannot open is logged at debug level and
/// never fails the caller.
pub fn log(home: &Path, kind: &str, payload: &Value) {
    let path = home.join("store.db");
    match aux_store::Store::open(&path) {
        Ok(store) => {
            let _ = log_with(&store, kind, payload);
        }
        Err(err) => {
            tracing::debug!(kind, reason = %err, "extension ledger row not written");
        }
    }
}

/// How many rows of `kind` are recorded in `home/store.db`.
pub fn count(home: &Path, kind: &str) -> i64 {
    let path = home.join("store.db");
    aux_store::Store::open(&path)
        .ok()
        .and_then(|store| store.event_count(kind).ok())
        .unwrap_or(0)
}

/// The payloads of `kind` recorded in `home/store.db`.
pub fn payloads(home: &Path, kind: &str) -> Vec<String> {
    let path = home.join("store.db");
    aux_store::Store::open(&path)
        .ok()
        .and_then(|store| store.event_payloads(kind).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_is_written_to_the_home_store() {
        let home = tempfile::tempdir().unwrap();
        log(
            home.path(),
            MOUNT,
            &serde_json::json!({"name": "demo", "agent": "alice"}),
        );
        assert_eq!(count(home.path(), MOUNT), 1);
        let rows = payloads(home.path(), MOUNT);
        assert!(rows[0].contains("demo"));
    }
}
