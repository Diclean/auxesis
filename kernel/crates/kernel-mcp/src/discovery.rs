//! Tool catalogs and the in-memory discovery cache.
//!
//! [`ToolCatalog`] is the deduped, stably ordered set of descriptors. Duplicate
//! remote names are collapsed by a deterministic rule (higher risk first, then
//! smallest canonical annotations/title/schema/description) rather than by
//! arrival order, and descriptors are exposed in wire-name order so a prompt, an
//! approval card and a UI always render the same list.
//!
//! [`ToolCatalog::from_remote_tools`] **merges** a server's tools (additive);
//! [`ToolCatalog::replace_server_tools`] **replaces** them, so a refresh removes
//! the entries the server no longer advertises (no ghost descriptors) and frees
//! their wire names deterministically. Wire names are a pure function of the
//! sorted `(server, remote)` set, so the allocation never depends on the order
//! servers are registered.
//!
//! [`DiscoveryCache`] keeps a catalog in memory with a TTL and explicit
//! invalidation. The durable SQL store is a separate slice (S2b); this type is
//! the live process cache the caller refreshes on `tools/list_changed` or
//! `aux connect sync`.
//!
//! # Per-agent cap
//!
//! Only an agent's explicit allowlist reaches its registry. [`ToolCatalog::for_agent`]
//! intersects the requested wire names with the catalog, truncates the result to
//! [`PER_AGENT_TOOL_CAP`], and reports the overflow **by name** (bounded) plus
//! the unknown names — the caller contract is that an agent's connector tools never
//! exceed the cap.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use kernel_broker::Risk;
use serde_json::Value;

use crate::descriptor::{risk_from_tags, sanitize_schema, McpTag, McpToolDescriptor};
use crate::naming::{valid_wire_component, WireNames};
use crate::tools::RemoteTool;

/// Most connector tools any single agent/agent may hold.
pub const PER_AGENT_TOOL_CAP: usize = 24;
/// Most withheld wire names [`AgentTools::over_cap`] will list.
pub const MAX_NAMED_OVER_CAP: usize = 32;

/// What one catalog mutation did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscoveryStats {
    /// Entries handed in.
    pub received: usize,
    /// Descriptors stored for the server after the pass (new or refreshed).
    pub registered: usize,
    /// Entries collapsed because the remote name repeated.
    pub duplicates_dropped: usize,
    /// Entries refused because the name was unusable.
    pub invalid_dropped: usize,
    /// Entries removed because a replace-refresh no longer advertised them.
    pub removed: usize,
}

/// One server's deduped representative tools, keyed by remote name.
#[derive(Debug, Clone, Default)]
struct ServerState {
    toolkit: String,
    tools: BTreeMap<String, RemoteTool>,
}

/// The descriptors of one or more servers, keyed by a stable wire name.
#[derive(Clone, Default)]
pub struct ToolCatalog {
    servers: BTreeMap<String, ServerState>,
    by_wire: BTreeMap<String, McpToolDescriptor>,
    names: WireNames,
}

impl fmt::Debug for ToolCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let server_keys: Vec<_> = self
            .servers
            .keys()
            .map(|key| (key.len(), crate::naming::short_hash(key)))
            .collect();
        f.debug_struct("ToolCatalog")
            .field("server_keys", &server_keys)
            .field("tool_count", &self.by_wire.len())
            .finish()
    }
}

impl ToolCatalog {
    /// An empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// **Merge** `tools` into `server`'s set, dedupe by remote name, rebuild.
    ///
    /// Additive: tools registered for `server` by an earlier pass and absent
    /// from `tools` stay registered. Use [`ToolCatalog::replace_server_tools`]
    /// when `tools` is the server's complete current list and vanished entries
    /// must disappear.
    ///
    /// Duplicate remote names are collapsed deterministically; the higher-risk
    /// copy always wins and ties fall back to a canonical
    /// `(annotations, title, schema, description)` rank, so the winner never
    /// depends on the order the server sent.
    pub fn from_remote_tools(
        &mut self,
        server: &str,
        toolkit: &str,
        tools: &[RemoteTool],
    ) -> DiscoveryStats {
        self.merge_tools(server, toolkit, tools)
    }

    /// **Replace** `server`'s tools with `tools`, dropping vanished entries.
    ///
    /// Any remote name previously registered for `server` but absent from
    /// `tools` is removed and its wire name freed (the remaining set is
    /// reallocated deterministically). This is the refresh path for
    /// `tools/list_changed` / re-discovery, so a stale tool can never be
    /// resolved from the catalog.
    pub fn replace_server_tools(
        &mut self,
        server: &str,
        toolkit: &str,
        tools: &[RemoteTool],
    ) -> DiscoveryStats {
        let removed = match self.servers.get(server) {
            Some(state) => {
                let kept: BTreeSet<&str> = tools
                    .iter()
                    .filter(|tool| {
                        valid_wire_component(server)
                            && McpToolDescriptor::name_is_valid(&tool.name)
                            && sanitize_schema(&tool.input_schema).is_some()
                    })
                    .map(|tool| tool.name.as_str())
                    .collect();
                state
                    .tools
                    .keys()
                    .filter(|name| !kept.contains(name.as_str()))
                    .count()
            }
            None => 0,
        };
        self.servers.remove(server);
        let mut stats = self.merge_tools(server, toolkit, tools);
        stats.removed = removed;
        stats
    }

    fn merge_tools(&mut self, server: &str, toolkit: &str, tools: &[RemoteTool]) -> DiscoveryStats {
        let mut stats = DiscoveryStats {
            received: tools.len(),
            ..DiscoveryStats::default()
        };
        {
            let state = self.servers.entry(server.to_owned()).or_default();
            if !toolkit.is_empty() {
                state.toolkit = toolkit.to_owned();
            }
            for tool in tools {
                if !valid_wire_component(server)
                    || !McpToolDescriptor::name_is_valid(&tool.name)
                    || sanitize_schema(&tool.input_schema).is_none()
                {
                    stats.invalid_dropped += 1;
                    continue;
                }
                match state.tools.entry(tool.name.clone()) {
                    Entry::Vacant(slot) => {
                        slot.insert(tool.clone());
                    }
                    Entry::Occupied(mut slot) => {
                        stats.duplicates_dropped += 1;
                        if canonical_rank(tool) < canonical_rank(slot.get()) {
                            slot.insert(tool.clone());
                        }
                    }
                }
            }
        }
        self.rebuild();
        stats.registered = self
            .by_wire
            .values()
            .filter(|descriptor| descriptor.server == server)
            .count();
        stats
    }

    /// Reallocate every wire name (sorted) and rebuild the descriptor map.
    fn rebuild(&mut self) {
        let mut identities: Vec<(String, String)> = Vec::new();
        for (server, state) in &self.servers {
            for remote in state.tools.keys() {
                identities.push((server.clone(), remote.clone()));
            }
        }
        self.names.register_all(&identities);
        self.by_wire.clear();
        for (server, remote) in &identities {
            let Some(state) = self.servers.get(server) else {
                continue;
            };
            let Some(tool) = state.tools.get(remote) else {
                continue;
            };
            let Some(wire) = self.names.wire_for(server, remote) else {
                continue;
            };
            if let Some(descriptor) =
                McpToolDescriptor::from_remote(server, &state.toolkit, wire.to_owned(), tool)
            {
                self.by_wire
                    .insert(descriptor.wire_name.clone(), descriptor);
            }
        }
    }

    /// Look a descriptor up by its wire name.
    pub fn resolve(&self, wire_name: &str) -> Option<&McpToolDescriptor> {
        self.by_wire.get(wire_name)
    }

    /// The wire name allocated for `(server, remote)`, if registered.
    pub fn wire_for(&self, server: &str, remote: &str) -> Option<&str> {
        self.names.wire_for(server, remote)
    }

    /// Every descriptor in stable wire-name order.
    pub fn descriptors(&self) -> impl Iterator<Item = &McpToolDescriptor> {
        self.by_wire.values()
    }

    /// Number of descriptors.
    pub fn len(&self) -> usize {
        self.by_wire.len()
    }

    /// Whether the catalog holds no descriptors.
    pub fn is_empty(&self) -> bool {
        self.by_wire.is_empty()
    }

    /// Select one agent's tools from its explicit wire-name allowlist.
    ///
    /// Unknown names are reported, not silently dropped, and the result is
    /// truncated to [`PER_AGENT_TOOL_CAP`] in stable wire-name order. The
    /// withheld wire names are reported by name (bounded by
    /// [`MAX_NAMED_OVER_CAP`]) with their true total, so an operator can see
    /// exactly which tools the cap hid. The returned list is a snapshot; the
    /// catalog stays owned by its cache.
    pub fn for_agent(&self, wire_names: &[String]) -> AgentTools {
        let mut tools = Vec::new();
        let mut missing = Vec::new();
        let mut seen = BTreeSet::new();
        for wire in wire_names {
            if !seen.insert(wire.as_str()) {
                continue;
            }
            match self.by_wire.get(wire) {
                Some(descriptor) => tools.push(descriptor.clone()),
                None => missing.push(wire.clone()),
            }
        }
        tools.sort_by(|a, b| a.wire_name.cmp(&b.wire_name));
        let over_cap_total = tools.len().saturating_sub(PER_AGENT_TOOL_CAP);
        let over_cap: Vec<String> = tools
            .iter()
            .skip(PER_AGENT_TOOL_CAP)
            .take(MAX_NAMED_OVER_CAP)
            .map(|descriptor| descriptor.wire_name.clone())
            .collect();
        tools.truncate(PER_AGENT_TOOL_CAP);
        missing.sort();
        missing.dedup();
        AgentTools {
            tools,
            over_cap,
            over_cap_total,
            missing,
        }
    }
}

/// One agent's selected connector tools.
#[derive(Clone, PartialEq)]
pub struct AgentTools {
    /// The allowed descriptors, capped at [`PER_AGENT_TOOL_CAP`] and in stable
    /// wire-name order.
    pub tools: Vec<McpToolDescriptor>,
    /// The wire names withheld by the per-agent cap, in stable order and
    /// bounded by [`MAX_NAMED_OVER_CAP`].
    pub over_cap: Vec<String>,
    /// The true number of tools withheld by the per-agent cap (may exceed
    /// `over_cap.len()`).
    pub over_cap_total: usize,
    /// Allowlisted wire names the catalog does not know (fail-closed signal).
    pub missing: Vec<String>,
}

impl fmt::Debug for AgentTools {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = |values: &[String]| {
            values
                .iter()
                .map(|name| (name.len(), crate::naming::short_hash(name)))
                .collect::<Vec<_>>()
        };
        f.debug_struct("AgentTools")
            .field("tools", &self.tools)
            .field("over_cap", &names(&self.over_cap))
            .field("over_cap_total", &self.over_cap_total)
            .field("missing", &names(&self.missing))
            .finish()
    }
}

impl AgentTools {
    /// Whether the allowlist was served completely.
    pub fn is_complete(&self) -> bool {
        self.over_cap_total == 0 && self.missing.is_empty()
    }
}

/// A total order used to pick one representative for a repeated remote name.
///
/// Higher risk always wins (the inverted-risk component is smallest for
/// `Risk::High`); among equal-risk copies the lexicographically smallest
/// canonical `(annotations, title, schema, description)` wins, so the result
/// never depends on the order the server sent.
fn canonical_rank(tool: &RemoteTool) -> (u8, String, String, String, String) {
    let inverted_risk = match risk_from_tags(&McpTag::from_annotations(tool.annotations.as_ref())) {
        Risk::High => 0,
        Risk::Medium => 1,
        Risk::Low => 2,
    };
    (
        inverted_risk,
        canonical_json(tool.annotations.as_ref()),
        tool.title.clone().unwrap_or_default(),
        canonical_value_string(tool.input_schema.as_value()),
        tool.description
            .as_ref()
            .map(|text| text.raw().to_owned())
            .unwrap_or_default(),
    )
}

/// Serialise a value with object keys sorted, so two servers that send the same
/// annotations/schema in a different key order rank identically.
fn canonical_json(value: Option<&Value>) -> String {
    value.map(canonical_value_string).unwrap_or_default()
}

fn canonical_value_string(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                out.push_str(
                    &map.get(*key)
                        .map(canonical_value_string)
                        .unwrap_or_default(),
                );
            }
            out.push('}');
            out
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_value_string(item));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Monotonic clock seam for the cache TTL; injectable in tests.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

struct CacheEntry {
    catalog: Arc<ToolCatalog>,
    stored_at: Instant,
}

/// A process-local [`ToolCatalog`] cache with a TTL and explicit invalidation.
pub struct DiscoveryCache {
    ttl: Duration,
    clock: Clock,
    entries: RwLock<HashMap<String, CacheEntry>>,
}

impl DiscoveryCache {
    /// A cache whose entries live for `ttl` on the system clock.
    pub fn new(ttl: Duration) -> Self {
        Self::with_clock(ttl, Arc::new(Instant::now))
    }

    /// A cache with an injectable clock (tests advance time without sleeping).
    pub fn with_clock(ttl: Duration, clock: Clock) -> Self {
        Self {
            ttl,
            clock,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// The configured time-to-live.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The catalog for `server`, or `None` when absent or expired.
    ///
    /// An expired entry is evicted on read.
    pub fn get(&self, server: &str) -> Option<Arc<ToolCatalog>> {
        let now = (self.clock)();
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get(server)?;
        if now.saturating_duration_since(entry.stored_at) < self.ttl {
            Some(Arc::clone(&entry.catalog))
        } else {
            entries.remove(server);
            None
        }
    }

    /// Store (or refresh) the catalog for `server`, returning the shared handle.
    pub fn put(&self, server: &str, catalog: ToolCatalog) -> Arc<ToolCatalog> {
        let shared = Arc::new(catalog);
        let now = (self.clock)();
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        entries.insert(
            server.to_owned(),
            CacheEntry {
                catalog: Arc::clone(&shared),
                stored_at: now,
            },
        );
        shared
    }

    /// Drop one server's entry; `true` when something was removed.
    pub fn invalidate(&self, server: &str) -> bool {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(server)
            .is_some()
    }

    /// Drop every entry.
    pub fn invalidate_all(&self) {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// The servers currently cached, in stable order.
    pub fn servers(&self) -> Vec<String> {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let mut servers: Vec<String> = entries.keys().cloned().collect();
        servers.sort();
        servers
    }

    /// Number of cached entries (including an entry that has not been read past
    /// its TTL yet).
    pub fn len(&self) -> usize {
        self.entries.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
