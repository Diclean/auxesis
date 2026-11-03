//! The cache of MCP tool descriptors.
//!
//! The store keeps the tool lists the MCP servers publish, so a tool
//! name resolves to its schema without asking the server again.

use super::*;

impl Store {
    // ---- mcp tool cache (v15) ----

    /// Insert or replace a batch of MCP tool descriptors by
    /// `(server, remote_name)`; returns how many rows were written.
    ///
    /// Every field is checked **before** any write: names ≤ 128 bytes,
    /// description ≤ 512, schema ≤ 16 KiB, descriptor ≤ 24 KiB, tags ≤ 4 KiB,
    /// positive TTL ≤ one year; `schema_json`, `tags_json` and
    /// `descriptor_json` must each parse as JSON (a syntax check only — see
    /// [`McpToolRecord`]); and `fetched_at` is round-trip validated against
    /// SQLite and refused when it leads the store clock by more than
    /// [`MCP_TOOL_FUTURE_SKEW_SECONDS`]. The supplied `wire_name` is ignored:
    /// the store derives it from `(server, remote_name)` using
    /// [`canonical_mcp_tool_wire_name`]. The resulting `wire_name` is
    /// **globally unique**: a row that would take a wire name already held by a different
    /// `(server, remote_name)` is refused, so [`Store::mcp_tool_by_wire`]
    /// can never let one server shadow another's descriptor.
    ///
    /// The row caps (≤ 500 per server, ≤ 5000 total) are checked inside the
    /// same `IMMEDIATE` transaction. A violation rolls the whole batch back and
    /// returns [`StoreError::McpToolRejected`]; no partial server refresh is
    /// ever left behind. Re-running an identical batch is idempotent (the
    /// primary key replaces).
    ///
    /// The records are descriptors only: this method has no parameter that
    /// could carry an API key or OAuth token.
    pub fn upsert_mcp_tools(&self, tools: &[McpToolRecord]) -> Result<usize, StoreError> {
        // Canonicalize before validating uniqueness or writing. Sorting by the
        // primary key and then the full payload gives duplicate keys a stable
        // winner (the lexicographically lowest payload), independent of batch
        // order. The cache stores one row per `(server, remote_name)`.
        let mut canonicalized: Vec<McpToolRecord> = tools
            .iter()
            .cloned()
            .map(|mut tool| {
                tool.wire_name = canonical_mcp_tool_wire_name(&tool.server, &tool.remote_name);
                tool
            })
            .collect();
        canonicalized.sort_by(|a, b| {
            (
                &a.server,
                &a.remote_name,
                &a.toolkit,
                &a.description,
                &a.schema_json,
                &a.tags_json,
                &a.descriptor_json,
                &a.risk,
                &a.risk_basis,
                &a.fetched_at,
                a.ttl_seconds,
            )
                .cmp(&(
                    &b.server,
                    &b.remote_name,
                    &b.toolkit,
                    &b.description,
                    &b.schema_json,
                    &b.tags_json,
                    &b.descriptor_json,
                    &b.risk,
                    &b.risk_basis,
                    &b.fetched_at,
                    b.ttl_seconds,
                ))
        });
        canonicalized.dedup_by(|a, b| a.server == b.server && a.remote_name == b.remote_name);

        for tool in &canonicalized {
            validate_mcp_tool(tool)?;
            validate_mcp_fetched_at(&self.conn, tool)?;
        }
        let synced_at = if canonicalized.is_empty() {
            String::new()
        } else {
            validated_synced_at(&self.conn)?
        };
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let mut written = 0usize;
        for tool in &canonicalized {
            // A wire name is the dispatch key the S3 adapter gates a call by,
            // so two servers must never hold it. Reject a row that would take
            // a wire name already held by a different `(server, remote_name)`;
            // the same tuple replacing itself (including a rename of its own
            // wire name) stays allowed. The unique index is the backstop.
            if let Some((holder_server, holder_remote)) = tx
                .query_row(
                    "SELECT server, remote_name FROM mcp_tools WHERE wire_name = ?1",
                    [tool.wire_name.as_str()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
            {
                if holder_server != tool.server || holder_remote != tool.remote_name {
                    return Err(StoreError::McpToolRejected {
                        reason: format!(
                            "wire_name `{}` is already held by server `{holder_server}` \
                             remote `{holder_remote}`",
                            tool.wire_name
                        ),
                    });
                }
            }
            written += tx.execute(
                "INSERT INTO mcp_tools(
                     server, remote_name, wire_name, toolkit, description,
                     schema_json, tags_json, descriptor_json, risk, risk_basis,
                     fetched_at, ttl_seconds, synced_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT(server, remote_name) DO UPDATE SET
                     wire_name       = excluded.wire_name,
                     toolkit         = excluded.toolkit,
                     description     = excluded.description,
                     schema_json     = excluded.schema_json,
                     tags_json       = excluded.tags_json,
                     descriptor_json = excluded.descriptor_json,
                     risk            = excluded.risk,
                     risk_basis      = excluded.risk_basis,
                     fetched_at      = excluded.fetched_at,
                     ttl_seconds     = excluded.ttl_seconds,
                     synced_at       = excluded.synced_at",
                rusqlite::params![
                    tool.server,
                    tool.remote_name,
                    tool.wire_name,
                    tool.toolkit,
                    tool.description,
                    tool.schema_json,
                    tool.tags_json,
                    tool.descriptor_json,
                    tool.risk,
                    tool.risk_basis,
                    tool.fetched_at,
                    tool.ttl_seconds,
                    synced_at,
                ],
            )?;
        }
        // Row caps, read after the upserts inside the same write transaction,
        // so a concurrent writer cannot slip a row past them between a check
        // and an insert. `ORDER BY server` keeps the refused server name
        // deterministic when several are over the cap at once.
        if let Some((server, count)) = tx
            .query_row(
                "SELECT server, COUNT(*) FROM mcp_tools
                 GROUP BY server HAVING COUNT(*) > ?1
                 ORDER BY server ASC LIMIT 1",
                [MCP_TOOLS_PER_SERVER_MAX],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            return Err(StoreError::McpToolRejected {
                reason: format!(
                    "server `{server}` would hold {count} tool rows (max \
                     {MCP_TOOLS_PER_SERVER_MAX}); delete or prune this server's \
                     cached tools first"
                ),
            });
        }
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM mcp_tools", [], |row| row.get(0))?;
        if total > MCP_TOOLS_TOTAL_MAX {
            return Err(StoreError::McpToolRejected {
                reason: format!(
                    "tool cache would hold {total} rows (max {MCP_TOOLS_TOTAL_MAX}); \
                     prune expired tools or delete a server's rows first"
                ),
            });
        }
        tx.commit()?;
        Ok(written)
    }

    /// Every cached MCP tool descriptor, ordered by `(server, remote_name)`.
    pub fn mcp_tools(&self) -> Result<Vec<McpToolRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT server, remote_name, wire_name, toolkit, description,
                    schema_json, tags_json, descriptor_json, risk, risk_basis,
                    fetched_at, ttl_seconds
             FROM mcp_tools ORDER BY server ASC, remote_name ASC",
        )?;
        let rows = stmt.query_map([], row_to_mcp_tool)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Cached descriptors for one server, ordered by remote name.
    pub fn mcp_tools_for_server(&self, server: &str) -> Result<Vec<McpToolRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT server, remote_name, wire_name, toolkit, description,
                    schema_json, tags_json, descriptor_json, risk, risk_basis,
                    fetched_at, ttl_seconds
             FROM mcp_tools WHERE server = ?1 ORDER BY remote_name ASC",
        )?;
        let rows = stmt.query_map([server], row_to_mcp_tool)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Resolve one cached descriptor by its Auxesis **wire** name.
    ///
    /// Wire names are globally unique: the v15 unique index and the upsert
    /// refusal together guarantee at most one row can match, so this lookup is
    /// unambiguous and cannot be shadowed by a second server.
    pub fn mcp_tool_by_wire(&self, wire_name: &str) -> Result<Option<McpToolRecord>, StoreError> {
        self.conn
            .query_row(
                "SELECT server, remote_name, wire_name, toolkit, description,
                        schema_json, tags_json, descriptor_json, risk, risk_basis,
                        fetched_at, ttl_seconds
                 FROM mcp_tools WHERE wire_name = ?1",
                [wire_name],
                row_to_mcp_tool,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Drop every cached descriptor for `server`; returns how many rows.
    pub fn delete_mcp_tools_for_server(&self, server: &str) -> Result<usize, StoreError> {
        Ok(self
            .conn
            .execute("DELETE FROM mcp_tools WHERE server = ?1", [server])?)
    }

    /// Drop cached descriptors whose `fetched_at + ttl_seconds` is at or before
    /// `now`; returns how many rows.
    ///
    /// `now` must be a valid calendar date/time (round-trip validated like
    /// [`Store::record_usage_at`]); garbage returns
    /// [`StoreError::McpToolRejected`] rather than silently deleting nothing.
    /// A row whose `fetched_at` is `NULL` or unparsable can never satisfy the
    /// TTL comparison, so it is treated as expired and removed — legacy rows
    /// written before this validation self-heal instead of wedging the table
    /// at its cap.
    pub fn prune_expired_mcp_tools(&self, now: &str) -> Result<usize, StoreError> {
        if !sqlite_date_matches(&self.conn, now)? {
            return Err(StoreError::McpToolRejected {
                reason: format!("now `{now}` is not a valid calendar date/time"),
            });
        }
        // Convert `now` once for this operation, then do the age arithmetic in
        // Rust with saturation. SQLite's date modifiers return NULL when a
        // timestamp addition overflows its supported calendar range; treating
        // that as expired would incorrectly evict a far-future legacy row.
        let now_epoch_millis: i64 = self.conn.query_row(
            "SELECT CAST((julianday(?1) - 2440587.5) * 86400000 AS INTEGER)",
            [now],
            |row| row.get(0),
        )?;
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        let expired: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT server, remote_name,
                        CAST((julianday(fetched_at) - 2440587.5) * 86400000 AS INTEGER),
                        ttl_seconds
                 FROM mcp_tools",
            )?;
            let mut rows = stmt.query([])?;
            let mut expired = Vec::new();
            while let Some(row) = rows.next()? {
                let server: String = row.get(0)?;
                let remote_name: String = row.get(1)?;
                let fetched_epoch: Option<i64> = row.get(2)?;
                let ttl_seconds: i64 = row.get(3)?;
                if fetched_epoch
                    .map(|fetched| {
                        fetched.saturating_add(ttl_seconds.saturating_mul(1000)) <= now_epoch_millis
                    })
                    .unwrap_or(true)
                {
                    expired.push((server, remote_name));
                }
            }
            expired
        };
        for (server, remote_name) in &expired {
            tx.execute(
                "DELETE FROM mcp_tools WHERE server = ?1 AND remote_name = ?2",
                rusqlite::params![server, remote_name],
            )?;
        }
        tx.commit()?;
        Ok(expired.len())
    }

    /// Number of cached MCP tool rows.
    pub fn mcp_tool_count(&self) -> Result<i64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM mcp_tools", [], |row| row.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{
        MIGRATION_V1, MIGRATION_V2, MIGRATION_V3, MIGRATION_V4, MIGRATION_V5, MIGRATION_V6,
    };
    use crate::testutil::*;
    use tempfile::tempdir;

    #[test]
    fn mcp_tools_upsert_replaces_by_primary_key() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.upsert_mcp_tools(&[mcp_tool("s1", "A")]).unwrap(), 1);
        assert_eq!(store.upsert_mcp_tools(&[]).unwrap(), 0);

        let mut updated = mcp_tool("s1", "A");
        updated.description = "updated".to_string();
        updated.wire_name = "caller-forged-name".to_string();
        updated.ttl_seconds = 7200;
        assert_eq!(store.upsert_mcp_tools(&[updated.clone()]).unwrap(), 1);
        updated.wire_name = canonical_mcp_tool_wire_name("s1", "A");

        let rows = store.mcp_tools().unwrap();
        assert_eq!(
            rows.len(),
            1,
            "the primary key replaces, it does not append"
        );
        assert_eq!(rows[0], updated);
        assert_eq!(
            store.mcp_tool_by_wire(&updated.wire_name).unwrap(),
            Some(updated)
        );
        assert_eq!(store.mcp_tool_by_wire("mcp__missing").unwrap(), None);
    }

    #[test]
    fn mcp_tools_batch_result_is_independent_of_input_order() {
        let mut first = mcp_tool("server", "FIRST");
        first.description = "z payload".to_string();
        let mut duplicate = first.clone();
        duplicate.description = "a payload".to_string();
        let second = mcp_tool("server", "SECOND");
        let forward_store = Store::open_in_memory().unwrap();
        let reverse_store = Store::open_in_memory().unwrap();

        forward_store
            .upsert_mcp_tools(&[first.clone(), second.clone(), duplicate.clone()])
            .unwrap();
        reverse_store
            .upsert_mcp_tools(&[duplicate, second, first])
            .unwrap();

        let forward = forward_store.mcp_tools().unwrap();
        let reverse = reverse_store.mcp_tools().unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(
            forward
                .iter()
                .find(|row| row.remote_name == "FIRST")
                .unwrap()
                .description,
            "a payload",
            "duplicate identities use the lexicographically lowest payload"
        );
    }

    #[test]
    fn mcp_tool_wire_name_is_canonical_and_ignores_the_caller_value() {
        let store = Store::open_in_memory().unwrap();
        let mut tool = mcp_tool("Server / 1", "ACME CRM.LIST");
        tool.wire_name = "mcp__attacker__chosen".to_string();
        store.upsert_mcp_tools(&[tool]).unwrap();

        let expected = canonical_mcp_tool_wire_name("Server / 1", "ACME CRM.LIST");
        let stored = store.mcp_tool_by_wire(&expected).unwrap().unwrap();
        assert_eq!(stored.wire_name, expected);
        assert_eq!(expected, "mcp__Server___1__ACME_CRM_LIST");

        let long = canonical_mcp_tool_wire_name("s", &"x".repeat(128));
        assert_eq!(long.len(), MCP_TOOL_WIRE_NAME_MAX_BYTES);
        assert!(long.ends_with(&format!(
            "{:02x}{:02x}{:02x}",
            blake3::hash(format!("mcp__s__{}", "x".repeat(128)).as_bytes()).as_bytes()[0],
            blake3::hash(format!("mcp__s__{}", "x".repeat(128)).as_bytes()).as_bytes()[1],
            blake3::hash(format!("mcp__s__{}", "x".repeat(128)).as_bytes()).as_bytes()[2]
        )));
    }

    #[test]
    fn mcp_tools_refuse_oversize_fields_without_writing() {
        let store = Store::open_in_memory().unwrap();
        let big = |n: usize| "x".repeat(n);

        let mut name = mcp_tool("s", "A");
        name.server = big(MCP_TOOL_NAME_MAX_BYTES + 1);
        let mut remote = mcp_tool("s", "A");
        remote.remote_name = big(MCP_TOOL_NAME_MAX_BYTES + 1);
        let mut toolkit = mcp_tool("s", "A");
        toolkit.toolkit = big(MCP_TOOL_NAME_MAX_BYTES + 1);
        let mut description = mcp_tool("s", "A");
        description.description = big(MCP_TOOL_DESCRIPTION_MAX_BYTES + 1);
        let mut schema = mcp_tool("s", "A");
        schema.schema_json = big(MCP_TOOL_SCHEMA_MAX_BYTES + 1);
        let mut descriptor = mcp_tool("s", "A");
        descriptor.descriptor_json = big(MCP_TOOL_DESCRIPTOR_MAX_BYTES + 1);
        let mut tags = mcp_tool("s", "A");
        tags.tags_json = big(MCP_TOOL_TAGS_MAX_BYTES + 1);
        let mut bad_ttl = mcp_tool("s", "A");
        bad_ttl.ttl_seconds = 0;
        let mut huge_ttl = mcp_tool("s", "A");
        huge_ttl.ttl_seconds = MCP_TOOL_TTL_MAX_SECONDS + 1;

        for (what, tool) in [
            ("server", name),
            ("remote_name", remote),
            ("toolkit", toolkit),
            ("description", description),
            ("schema", schema),
            ("descriptor", descriptor),
            ("tags", tags),
            ("ttl=0", bad_ttl),
            ("ttl>max", huge_ttl),
        ] {
            let err = store.upsert_mcp_tools(&[tool]).unwrap_err();
            assert!(
                matches!(err, StoreError::McpToolRejected { .. }),
                "{what} must be refused, got {err:?}"
            );
        }
        assert_eq!(store.mcp_tool_count().unwrap(), 0, "nothing was written");

        // Validation is per batch: one bad row rejects the whole batch.
        let good = mcp_tool("s", "GOOD");
        let mut bad = mcp_tool("s", "A");
        bad.server = big(MCP_TOOL_NAME_MAX_BYTES + 1);
        assert!(matches!(
            store.upsert_mcp_tools(&[good, bad]),
            Err(StoreError::McpToolRejected { .. })
        ));
        assert_eq!(store.mcp_tool_count().unwrap(), 0);
    }

    #[test]
    fn mcp_tools_row_caps_are_enforced_atomically() {
        let store = Store::open_in_memory().unwrap();

        // One over the per-server cap: the whole batch rolls back.
        let over_server: Vec<_> = (0..=MCP_TOOLS_PER_SERVER_MAX)
            .map(|i| mcp_tool("s-cap", &format!("TOOL_{i}")))
            .collect();
        assert!(matches!(
            store.upsert_mcp_tools(&over_server),
            Err(StoreError::McpToolRejected { .. })
        ));
        assert_eq!(store.mcp_tool_count().unwrap(), 0, "batch rolled back");

        // Exactly the per-server cap is accepted.
        let at_server: Vec<_> = (0..MCP_TOOLS_PER_SERVER_MAX)
            .map(|i| mcp_tool("s-cap", &format!("TOOL_{i}")))
            .collect();
        store.upsert_mcp_tools(&at_server).unwrap();
        assert_eq!(
            store.mcp_tools_for_server("s-cap").unwrap().len() as i64,
            MCP_TOOLS_PER_SERVER_MAX
        );
        assert_eq!(
            store.delete_mcp_tools_for_server("s-cap").unwrap() as i64,
            MCP_TOOLS_PER_SERVER_MAX
        );

        // The table-total cap: fill to exactly the limit, then one more is
        // refused and that batch leaves the table at the limit.
        for server in 0..10 {
            let batch: Vec<_> = (0..MCP_TOOLS_PER_SERVER_MAX)
                .map(|i| mcp_tool(&format!("s-{server}"), &format!("TOOL_{i}")))
                .collect();
            store.upsert_mcp_tools(&batch).unwrap();
        }
        assert_eq!(store.mcp_tool_count().unwrap(), MCP_TOOLS_TOTAL_MAX);
        assert!(matches!(
            store.upsert_mcp_tools(&[mcp_tool("s-overflow", "TOOL_0")]),
            Err(StoreError::McpToolRejected { .. })
        ));
        assert_eq!(store.mcp_tool_count().unwrap(), MCP_TOOLS_TOTAL_MAX);
    }

    #[test]
    fn mcp_tools_prune_expired_by_ttl_and_delete_by_server() {
        let store = Store::open_in_memory().unwrap();
        let mut old = mcp_tool("s1", "OLD");
        old.fetched_at = "2026-01-01 00:00:00".to_string();
        old.ttl_seconds = 60;
        let mut fresh = mcp_tool("s1", "FRESH");
        fresh.fetched_at = "2026-10-06 00:00:00".to_string();
        fresh.ttl_seconds = MCP_TOOL_TTL_MAX_SECONDS;
        store.upsert_mcp_tools(&[old, fresh]).unwrap();

        assert_eq!(
            store
                .prune_expired_mcp_tools("2026-10-07 00:00:00")
                .unwrap(),
            1,
            "only the expired row is dropped"
        );
        let rows = store.mcp_tools_for_server("s1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].remote_name, "FRESH");
        assert_eq!(store.delete_mcp_tools_for_server("s1").unwrap(), 1);
        assert!(store.mcp_tools().unwrap().is_empty());
    }

    #[test]
    fn mcp_tool_prune_uses_one_now_and_saturates_far_future_expiry() {
        let store = Store::open_in_memory().unwrap();
        // Legacy rows may have timestamps outside SQLite's date-modifier range.
        // Their TTL addition must not become NULL and cause premature eviction.
        store
            .conn
            .execute(
                "INSERT INTO mcp_tools(
                     server, remote_name, wire_name, toolkit, description,
                     schema_json, tags_json, descriptor_json, risk, risk_basis,
                     fetched_at, ttl_seconds, synced_at)
                 VALUES ('legacy', 'far', 'legacy-wire', 't', 'd', '{}', '[]',
                         '{}', 'low', '', '9999-12-31 23:59:00', 31536000,
                         '9999-12-31 23:59:00')",
                [],
            )
            .unwrap();
        let mut boundary = mcp_tool("s", "BOUNDARY");
        boundary.fetched_at = "2026-10-07 00:00:00".to_string();
        boundary.ttl_seconds = 60;
        let mut recent = boundary.clone();
        recent.remote_name = "RECENT".to_string();
        recent.fetched_at = "2026-10-07 00:00:01".to_string();
        let mut subsecond = boundary.clone();
        subsecond.remote_name = "SUBSECOND".to_string();
        subsecond.fetched_at = "2026-10-07 00:00:00.900".to_string();
        store
            .upsert_mcp_tools(&[boundary, recent, subsecond])
            .unwrap();

        assert_eq!(
            store
                .prune_expired_mcp_tools("2026-10-07 00:01:00.500")
                .unwrap(),
            1
        );
        assert!(store
            .mcp_tools()
            .unwrap()
            .iter()
            .any(|row| row.remote_name == "RECENT"));
        assert!(store
            .mcp_tools()
            .unwrap()
            .iter()
            .any(|row| row.remote_name == "SUBSECOND"));
        assert!(store.mcp_tool_by_wire("legacy-wire").unwrap().is_some());
    }

    #[test]
    fn mcp_tools_refuse_a_wire_name_held_by_another_server() {
        let store = Store::open_in_memory().unwrap();
        let first = mcp_tool("s 1", "A");
        store
            .upsert_mcp_tools(std::slice::from_ref(&first))
            .unwrap();

        // A different `(server, remote_name)` may not take the wire name: S3
        // gates a call by it. These distinct identities sanitize to the same
        // canonical wire name, so the store rejects the alias.
        let forged = mcp_tool("s_1", "A");
        assert!(matches!(
            store.upsert_mcp_tools(std::slice::from_ref(&forged)),
            Err(StoreError::McpToolRejected { .. })
        ));
        assert_eq!(
            store.mcp_tool_by_wire(&first.wire_name).unwrap(),
            Some(first.clone()),
            "the first server's descriptor is intact"
        );
        assert_eq!(store.mcp_tool_count().unwrap(), 1);

        // Atomic batch: a valid new row alongside the forged one writes nothing.
        let fresh = mcp_tool("s2", "FRESH");
        assert!(matches!(
            store.upsert_mcp_tools(&[fresh, forged.clone()]),
            Err(StoreError::McpToolRejected { .. })
        ));
        assert_eq!(store.mcp_tool_count().unwrap(), 1, "the batch rolled back");
        assert_eq!(
            store
                .mcp_tool_by_wire(&canonical_mcp_tool_wire_name("s2", "FRESH"))
                .unwrap(),
            None
        );

        // The same row may re-upsert its own wire name (idempotent replace).
        assert_eq!(
            store
                .upsert_mcp_tools(std::slice::from_ref(&first))
                .unwrap(),
            1
        );

        // A caller supplied name is discarded and the identity formula wins.
        let mut second = mcp_tool("s2", "B");
        second.wire_name = first.wire_name.clone();
        let mut expected_second = second.clone();
        expected_second.wire_name = canonical_mcp_tool_wire_name("s2", "B");
        store.upsert_mcp_tools(&[second]).unwrap();
        assert_eq!(
            store
                .mcp_tool_by_wire(&expected_second.wire_name)
                .unwrap()
                .unwrap(),
            expected_second
        );

        // Deleting a server frees its names too.
        assert_eq!(store.delete_mcp_tools_for_server("s 1").unwrap(), 1);
        assert_eq!(store.mcp_tool_by_wire(&first.wire_name).unwrap(), None);
        store
            .upsert_mcp_tools(std::slice::from_ref(&forged))
            .unwrap();
        assert_eq!(store.mcp_tool_count().unwrap(), 2);
    }

    #[test]
    fn mcp_tools_validate_fetched_at_and_self_heal_bad_rows() {
        let store = Store::open_in_memory().unwrap();

        let mut bad = mcp_tool("s1", "BAD");
        bad.fetched_at = "not-a-date".to_string();
        assert!(matches!(
            store.upsert_mcp_tools(&[bad]),
            Err(StoreError::McpToolRejected { .. })
        ));

        // SQLite *normalizes* impossible dates; the round-trip refuses them.
        let mut impossible = mcp_tool("s1", "FEB30");
        impossible.fetched_at = "2026-02-30 00:00:00".to_string();
        assert!(matches!(
            store.upsert_mcp_tools(&[impossible]),
            Err(StoreError::McpToolRejected { .. })
        ));

        // A stamp beyond the small clock-skew allowance is refused: such a row
        // could never expire from the cache.
        let mut future = mcp_tool("s1", "FUTURE");
        future.fetched_at = "2999-01-01 00:00:00".to_string();
        assert!(matches!(
            store.upsert_mcp_tools(&[future]),
            Err(StoreError::McpToolRejected { .. })
        ));
        assert_eq!(store.mcp_tool_count().unwrap(), 0, "nothing was written");

        // A hand-inserted legacy row with an unparsable timestamp can never
        // satisfy the TTL compare; prune treats it as expired and removes it.
        store.upsert_mcp_tools(&[mcp_tool("s1", "GOOD")]).unwrap();
        store
            .conn
            .execute(
                "UPDATE mcp_tools SET fetched_at = 'garbage' WHERE remote_name = 'GOOD'",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .prune_expired_mcp_tools("2026-10-07 00:00:00")
                .unwrap(),
            1,
            "an unparsable fetched_at is pruned, not wedged forever"
        );
        assert_eq!(store.mcp_tool_count().unwrap(), 0);

        // A garbage `now` is a typed error, never a silent `Ok(0)`.
        assert!(matches!(
            store.prune_expired_mcp_tools("not-a-date"),
            Err(StoreError::McpToolRejected { .. })
        ));
    }

    #[test]
    fn mcp_tools_refuse_non_json_payloads_without_writing() {
        let store = Store::open_in_memory().unwrap();
        let mut schema = mcp_tool("s", "A");
        schema.schema_json = "{\"type\":\"object\"".to_string();
        let mut tags = mcp_tool("s", "A");
        tags.tags_json = "read,write".to_string();
        let mut descriptor = mcp_tool("s", "A");
        descriptor.descriptor_json = "NaN".to_string();

        for (what, tool) in [
            ("schema", schema),
            ("tags", tags),
            ("descriptor", descriptor),
        ] {
            let err = store.upsert_mcp_tools(&[tool]).unwrap_err();
            assert!(
                matches!(err, StoreError::McpToolRejected { .. }),
                "{what} must be refused, got {err:?}"
            );
        }
        assert_eq!(store.mcp_tool_count().unwrap(), 0, "nothing was written");
    }

    #[test]
    fn mcp_tools_legacy_v15_wire_duplicates_are_repaired() {
        // A store that a pre-release v15 draft left behind: the old
        // **non-unique** wire index and duplicate wire names across servers.
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(MIGRATION_V1).unwrap();
            // v19 renames the v2..v6 `dot` columns, so the v15 draft needs them too.
            for sql in [
                MIGRATION_V2,
                MIGRATION_V3,
                MIGRATION_V4,
                MIGRATION_V5,
                MIGRATION_V6,
            ] {
                conn.execute_batch(sql).unwrap();
            }
            conn.execute_batch(
                "CREATE TABLE mcp_tools (
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
                 CREATE INDEX idx_mcp_tools_wire ON mcp_tools(wire_name);",
            )
            .unwrap();
            conn.execute_batch(
                "INSERT INTO meta(key, value) VALUES ('schema_version', '15')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            )
            .unwrap();
            for (server, remote, wire, fetched_at) in [
                ("b", "B", "dup-wire", "2026-10-03 08:00:00"),
                ("a", "A", "dup-wire", "2026-10-01 08:00:00"),
                ("c", "C", "dup-wire", "2026-10-02 08:00:00"),
                ("a", "TIE", "tie-wire", "2026-10-02 08:00:00"),
                ("z", "TIE", "tie-wire", "2026-10-02 08:00:00"),
                ("a", "KEEP", "keep-wire", "2026-10-01 08:00:00"),
            ] {
                conn.execute(
                    "INSERT INTO mcp_tools(
                         server, remote_name, wire_name, toolkit, description,
                         schema_json, tags_json, descriptor_json, risk, risk_basis,
                         fetched_at, ttl_seconds, synced_at)
                     VALUES (?1, ?2, ?3, 'crm', 'd', '{}', '[]', '{}', 'low',
                             'tag:read', ?4, 3600,
                             '2026-10-01 08:00:00')",
                    rusqlite::params![server, remote, wire, fetched_at],
                )
                .unwrap();
            }
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.mcp_tool_count().unwrap(),
            3,
            "duplicates de-duplicated"
        );
        let survivor = store.mcp_tool_by_wire("dup-wire").unwrap().unwrap();
        assert_eq!(
            (survivor.server.as_str(), survivor.remote_name.as_str()),
            ("b", "B"),
            "the newest fetched_at survives"
        );
        let tie_survivor = store.mcp_tool_by_wire("tie-wire").unwrap().unwrap();
        assert_eq!(
            (
                tie_survivor.server.as_str(),
                tie_survivor.remote_name.as_str()
            ),
            ("a", "TIE"),
            "equal timestamps use the lowest (server, remote_name) key"
        );
        assert_eq!(
            store
                .mcp_tool_by_wire("keep-wire")
                .unwrap()
                .unwrap()
                .remote_name,
            "KEEP",
            "a non-duplicate wire is untouched"
        );
        let unique: i64 = store
            .conn
            .query_row(
                "SELECT \"unique\" FROM pragma_index_list('mcp_tools') \
                 WHERE name = 'idx_mcp_tools_wire'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unique, 1, "the wire index is rebuilt as unique");
        drop(store);

        // Reopening is idempotent: no further rewrite.
        let store = Store::open(&path).unwrap();
        assert_eq!(store.mcp_tool_count().unwrap(), 3);
        assert_eq!(
            store.mcp_tool_by_wire("dup-wire").unwrap().unwrap().server,
            "b"
        );
    }

    #[test]
    fn mcp_tools_table_has_no_secret_bearing_column() {
        // "No secrets ever stored": the cache is descriptors only. The DDL has
        // no credential column, and [`McpToolRecord`] has no credential field —
        // there is no method in this section that could receive an API key
        // or OAuth token.
        let store = Store::open_in_memory().unwrap();
        let mut stmt = store.conn.prepare("PRAGMA table_info(mcp_tools)").unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(names.len(), 13, "one column per descriptor field");
        for name in &names {
            let lower = name.to_lowercase();
            for forbidden in [
                "secret",
                "token",
                "key",
                "password",
                "credential",
                "apikey",
                "api_key",
                "auth",
            ] {
                assert!(
                    !lower.contains(forbidden),
                    "column `{name}` looks secret-bearing"
                );
            }
        }
        assert!(names.contains(&"descriptor_json".to_string()));
    }

    #[test]
    fn mcp_tools_two_writers_merge_without_losing_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        Store::open(&path).unwrap();
        let barrier = std::sync::Barrier::new(2);

        std::thread::scope(|scope| {
            let handles: Vec<_> = ["writer-a", "writer-b"]
                .iter()
                .map(|server| {
                    let path = &path;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let store = Store::open(path).unwrap();
                        let batch: Vec<_> = (0..25)
                            .map(|i| mcp_tool(server, &format!("TOOL_{i}")))
                            .collect();
                        barrier.wait();
                        store.upsert_mcp_tools(&batch).unwrap();
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
        });

        let store = Store::open(&path).unwrap();
        assert_eq!(store.mcp_tool_count().unwrap(), 50);
        assert_eq!(store.mcp_tools_for_server("writer-a").unwrap().len(), 25);
        assert_eq!(store.mcp_tools_for_server("writer-b").unwrap().len(), 25);
    }
}
