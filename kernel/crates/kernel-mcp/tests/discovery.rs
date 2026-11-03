//! S2 discovery tests: deterministic dedupe, stable ordering, the per-agent cap
//! and the in-memory TTL cache with explicit invalidation.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kernel_broker::Risk;
use kernel_mcp::discovery::{DiscoveryCache, ToolCatalog, PER_AGENT_TOOL_CAP};
use kernel_mcp::{RemoteTool, ToolSchema};
use serde_json::{json, Value};

fn object_schema() -> ToolSchema {
    ToolSchema::try_from(json!({"type": "object"})).expect("valid schema")
}

fn remote(name: &str, description: &str) -> RemoteTool {
    RemoteTool {
        name: name.to_owned(),
        title: None,
        description: Some(description.to_owned().into()),
        input_schema: object_schema(),
        annotations: Some(json!({"readOnlyHint": true})),
    }
}

fn remote_with(name: &str, description: &str, annotations: Value) -> RemoteTool {
    RemoteTool {
        name: name.to_owned(),
        title: None,
        description: Some(description.to_owned().into()),
        input_schema: object_schema(),
        annotations: Some(annotations),
    }
}

fn catalog_with(names: &[&str]) -> ToolCatalog {
    let tools: Vec<RemoteTool> = names.iter().map(|name| remote(name, "d")).collect();
    let mut catalog = ToolCatalog::new();
    catalog.from_remote_tools("fakeserv", "zoho", &tools);
    catalog
}

#[test]
fn duplicate_remote_names_are_deduped_deterministically() {
    let mut catalog = ToolCatalog::new();
    let stats = catalog.from_remote_tools(
        "fakeserv",
        "zoho",
        &[
            remote("SEARCH", "first"),
            remote("SEARCH", "second"),
            remote("OTHER", "x"),
        ],
    );
    assert_eq!(stats.received, 3);
    assert_eq!(stats.duplicates_dropped, 1);
    assert_eq!(catalog.len(), 2);
    // Deterministic winner: smallest canonical (schema, description) rank.
    let search = catalog
        .resolve("mcp__fakeserv__SEARCH")
        .expect("registered");
    assert_eq!(search.description, "first");
}

#[test]
fn descriptors_are_ordered_by_wire_name() {
    let catalog = catalog_with(&["ZED", "ALPHA", "MID"]);
    let wires: Vec<&str> = catalog
        .descriptors()
        .map(|descriptor| descriptor.wire_name.as_str())
        .collect();
    assert_eq!(
        wires,
        vec![
            "mcp__fakeserv__ALPHA",
            "mcp__fakeserv__MID",
            "mcp__fakeserv__ZED",
        ]
    );
}

#[test]
fn per_agent_selection_is_capped_at_24() {
    let remote_names: Vec<String> = (0..30).map(|i| format!("TOOL_{i:02}")).collect();
    let refs: Vec<&str> = remote_names.iter().map(String::as_str).collect();
    let catalog = catalog_with(&refs);
    let wires: Vec<String> = remote_names
        .iter()
        .map(|name| kernel_mcp::wire_name("fakeserv", name))
        .collect();

    let selection = catalog.for_agent(&wires);
    assert_eq!(selection.tools.len(), PER_AGENT_TOOL_CAP);
    assert_eq!(selection.over_cap_total, 30 - PER_AGENT_TOOL_CAP);
    assert_eq!(selection.over_cap.len(), 30 - PER_AGENT_TOOL_CAP);
    assert!(
        selection
            .over_cap
            .iter()
            .all(|wire| wire.starts_with("mcp__fakeserv__TOOL_")),
        "over_cap must name the withheld tools: {:?}",
        selection.over_cap
    );
    assert!(selection.missing.is_empty());
    assert!(!selection.is_complete());

    let mut sorted = selection.tools.clone();
    sorted.sort_by(|a, b| a.wire_name.cmp(&b.wire_name));
    assert_eq!(selection.tools, sorted);

    // Unknown allowlisted names are reported, never silently dropped.
    let unknown = catalog.for_agent(&["mcp__fakeserv__NOPE".to_owned()]);
    assert!(unknown.tools.is_empty());
    assert_eq!(unknown.missing, vec!["mcp__fakeserv__NOPE".to_owned()]);

    // A fully-served allowlist is complete.
    let complete = catalog.for_agent(&wires[..PER_AGENT_TOOL_CAP]);
    assert!(complete.is_complete());
}

#[test]
fn cache_expires_after_ttl() {
    let now = Arc::new(Mutex::new(Instant::now()));
    let clock = Arc::clone(&now);
    let cache = DiscoveryCache::with_clock(
        Duration::from_secs(60),
        Arc::new(move || *clock.lock().expect("clock")),
    );
    cache.put("fakeserv", catalog_with(&["A"]));
    assert!(cache.get("fakeserv").is_some());

    *now.lock().expect("clock") += Duration::from_secs(59);
    assert!(cache.get("fakeserv").is_some());

    // Exactly the TTL is expired.
    *now.lock().expect("clock") += Duration::from_secs(1);
    assert!(cache.get("fakeserv").is_none());
    assert!(cache.is_empty());
}

#[test]
fn explicit_invalidation_evicts_on_demand() {
    let cache = DiscoveryCache::new(Duration::from_secs(3600));
    cache.put("fakeserv", catalog_with(&["A"]));
    cache.put("other", catalog_with(&["B"]));
    assert_eq!(cache.len(), 2);

    assert!(cache.invalidate("fakeserv"));
    assert!(cache.get("fakeserv").is_none());
    assert!(!cache.invalidate("fakeserv"));
    assert_eq!(cache.servers(), vec!["other".to_owned()]);

    cache.invalidate_all();
    assert!(cache.is_empty());
}

#[test]
fn duplicate_dedupe_is_order_independent_and_keeps_the_higher_risk_copy() {
    let low = remote_with("SEARCH", "low", json!({"readOnlyHint": true}));
    let high = remote_with("SEARCH", "high", json!({}));

    let mut forward = ToolCatalog::new();
    forward.from_remote_tools("fakeserv", "zoho", &[low.clone(), high.clone()]);
    let mut reverse = ToolCatalog::new();
    reverse.from_remote_tools("fakeserv", "zoho", &[high, low]);

    let a = forward
        .resolve("mcp__fakeserv__SEARCH")
        .expect("registered forward");
    let b = reverse
        .resolve("mcp__fakeserv__SEARCH")
        .expect("registered reverse");
    assert_eq!(a.risk(), Risk::High);
    assert_eq!(a.description, "high");
    assert_eq!(a, b, "server order must not flip the winner");
}

#[test]
fn dedupe_tie_breaks_on_canonical_annotations_regardless_of_key_order() {
    let first = remote_with(
        "SEARCH",
        "alpha",
        json!({"readOnlyHint": true, "openWorldHint": true}),
    );
    let reordered = remote_with(
        "SEARCH",
        "beta",
        json!({"openWorldHint": true, "readOnlyHint": true}),
    );

    let mut forward = ToolCatalog::new();
    forward.from_remote_tools("fakeserv", "zoho", &[first.clone(), reordered.clone()]);
    let mut reverse = ToolCatalog::new();
    reverse.from_remote_tools("fakeserv", "zoho", &[reordered, first]);

    let a = forward
        .resolve("mcp__fakeserv__SEARCH")
        .expect("registered forward");
    let b = reverse
        .resolve("mcp__fakeserv__SEARCH")
        .expect("registered reverse");
    assert_eq!(a.risk(), Risk::Low);
    assert_eq!(a.description, "alpha");
    assert_eq!(a, b);
}

#[test]
fn replace_refresh_removes_vanished_tools() {
    let mut catalog = ToolCatalog::new();
    catalog.from_remote_tools("fakeserv", "zoho", &[remote("A", "a"), remote("B", "b")]);
    let wire_b = catalog.wire_for("fakeserv", "B").expect("B").to_owned();
    assert!(catalog.resolve(&wire_b).is_some());

    let stats = catalog.replace_server_tools("fakeserv", "zoho", &[remote("A", "a")]);
    assert_eq!(stats.removed, 1);
    assert_eq!(catalog.len(), 1);
    assert!(catalog.wire_for("fakeserv", "B").is_none());
    assert!(
        catalog.resolve(&wire_b).is_none(),
        "a ghost descriptor survived the refresh"
    );
    assert_eq!(catalog.wire_for("fakeserv", "A"), Some("mcp__fakeserv__A"));
}

#[test]
fn from_remote_tools_merges_and_replace_does_not() {
    let mut catalog = ToolCatalog::new();
    catalog.from_remote_tools("fakeserv", "zoho", &[remote("A", "a")]);
    catalog.from_remote_tools("fakeserv", "zoho", &[remote("B", "b")]);
    assert_eq!(catalog.len(), 2, "merge must keep earlier tools");
    assert!(catalog.wire_for("fakeserv", "A").is_some());

    let stats = catalog.replace_server_tools("fakeserv", "zoho", &[remote("C", "c")]);
    assert_eq!(stats.removed, 2);
    assert_eq!(catalog.len(), 1);
    assert!(catalog.wire_for("fakeserv", "C").is_some());
    assert!(catalog.wire_for("fakeserv", "A").is_none());
}

#[test]
fn generated_wire_name_collisions_reject_every_participant() {
    let mut forward = ToolCatalog::new();
    forward.from_remote_tools("a__b", "t", &[remote("c", "x")]);
    forward.from_remote_tools("a", "t", &[remote("b__c", "y")]);
    let mut reverse = ToolCatalog::new();
    reverse.from_remote_tools("a", "t", &[remote("b__c", "y")]);
    reverse.from_remote_tools("a__b", "t", &[remote("c", "x")]);

    // `mcp__a__b__c` can also be formed from server `a` and remote `b__c`;
    // all participants in a collision are rejected, independent of order.
    for catalog in [&forward, &reverse] {
        assert_eq!(catalog.wire_for("a__b", "c"), None);
        assert_eq!(catalog.wire_for("a", "b__c"), None);
        assert!(catalog.is_empty());
    }
}
