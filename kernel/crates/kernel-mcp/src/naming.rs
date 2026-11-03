//! Stable wire names for connector tools.
//!
//! The model-visible name is exactly `mcp__<server_id>__<remote_name>`. Both
//! components must already be legal ASCII; neither is rewritten or truncated.
//! Duplicate generated names are rejected by [`WireNames`]. The dotted form
//! `mcp.<server>.<tool>` remains the human/display name ([`display_name`]).
//!
//! # Determinism
//!
//! [`wire_name`] is pure and stable across processes. Overlong names and any
//! collision are refused; they are never truncated, sanitised or disambiguated.
//! A compliant but suggestive remote name remains an accepted P3 residual,
//! mitigated by per-tool activation and approval.
//!
//! A wire name is derived, not durable: persisted state keys by
//! `(server, remote)` and resolves through [`WireNames`], so a rebuild after a
//! tool vanishes can never silently point a saved rule at a different tool.
//!
//! # User-visible wording
//!
//! Nothing in this module is shown to the owner. The protocol-neutral
//! `mcp__…` form is the internal wire name only.

use std::collections::BTreeMap;

/// Hard cap on a wire name, in bytes (the OpenAI function-name bound).
pub const MAX_WIRE_NAME_BYTES: usize = 64;
/// Namespace prefix shared by every connector wire name.
pub const WIRE_NAMESPACE: &str = "mcp";
const SHORT_HASH_CHARS: usize = 6;

/// Replace every character outside `[A-Za-z0-9_-]` with `_` for display-only
/// and logical names. This is never used to construct model-visible wire names.
pub fn sanitize_wire_component(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The provider-legal wire name for one remote tool.
///
/// Pure and deterministic: `wire_name(server, remote)` is exactly
/// `mcp__<server>__<tool>`. Callers reject invalid components, generated names
/// over [`MAX_WIRE_NAME_BYTES`], and collisions.
pub fn wire_name(server: &str, remote: &str) -> String {
    format!("{WIRE_NAMESPACE}__{server}__{remote}")
}

pub(crate) fn valid_wire_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// The human/display name `mcp.<server>.<tool>` (the dotted form).
///
/// Human-facing only: OpenAI-compatible providers reject the dots, so this is
/// never sent as the function name.
pub fn display_name(server: &str, remote: &str) -> String {
    format!(
        "{WIRE_NAMESPACE}.{}.{}",
        sanitize_wire_component(server),
        sanitize_wire_component(remote)
    )
}

/// The logical name `<server>.<toolkit>.<tool>` used by audit rows,
/// approval cards and config rules.
pub fn logical_name(server: &str, toolkit: &str, remote: &str) -> String {
    format!(
        "{}.{}.{}",
        sanitize_wire_component(server),
        sanitize_wire_component(toolkit),
        sanitize_wire_component(remote)
    )
}

/// The first six hex characters of the `blake3` digest.
pub(crate) fn short_hash(input: &str) -> String {
    let hash = blake3::hash(input.as_bytes());
    let bytes = hash.as_bytes();
    let mut out = String::with_capacity(SHORT_HASH_CHARS);
    for byte in bytes.iter().take(SHORT_HASH_CHARS / 2) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The bidirectional `(server, remote) <-> wire_name` map.
///
/// Allocation is a pure function of the **identity set**: identities are sorted
/// for stable processing. Every identity participating in a duplicate generated
/// name is refused; neither collision winner is privileged.
///
/// A wire name is a *derived* value, not a durable key: durable state (broker
/// rules, persisted allowlists) keys by `(server, remote)` and resolves through
/// this map. Rebuilding the map after a tool vanishes or appears can therefore
/// reassign the bytes, which is why `(server, remote)` is the persisted key.
#[derive(Debug, Clone, Default)]
pub struct WireNames {
    by_wire: BTreeMap<String, (String, String)>,
    by_identity: BTreeMap<(String, String), String>,
}

impl WireNames {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate (or reuse) the wire name for `(server, remote)`.
    ///
    /// Adding an identity recomputes the whole map in sorted order. Invalid,
    /// overlong and colliding names are refused with `None`.
    pub fn register(&mut self, server: &str, remote: &str) -> Option<String> {
        let identity = (server.to_owned(), remote.to_owned());
        if let Some(existing) = self.by_identity.get(&identity) {
            return Some(existing.clone());
        }
        let mut identities: Vec<(String, String)> = self.by_identity.keys().cloned().collect();
        identities.push(identity.clone());
        self.register_all(&identities);
        self.by_identity.get(&identity).cloned()
    }

    /// Rebuild the whole map from `identities`, allocating in sorted order.
    ///
    /// Previous allocations are discarded, so a caller that removes a server's
    /// tools frees their wire names deterministically: the remaining set is
    /// reallocated exactly as if it had been the only set all along.
    pub fn register_all(&mut self, identities: &[(String, String)]) {
        let mut sorted: Vec<(String, String)> = identities.to_vec();
        sorted.sort();
        sorted.dedup();
        self.by_wire.clear();
        self.by_identity.clear();
        let mut counts = BTreeMap::<String, usize>::new();
        for (server, remote) in &sorted {
            if !valid_wire_component(server) || !valid_wire_component(remote) || remote.len() > 48 {
                continue;
            }
            let name = wire_name(server, remote);
            if name.len() <= MAX_WIRE_NAME_BYTES {
                *counts.entry(name).or_default() += 1;
            }
        }
        for (server, remote) in &sorted {
            if !valid_wire_component(server) || !valid_wire_component(remote) || remote.len() > 48 {
                continue;
            }
            let identity = (server.clone(), remote.clone());
            let wire = wire_name(server, remote);
            if wire.len() > MAX_WIRE_NAME_BYTES || counts.get(&wire) != Some(&1) {
                continue;
            }
            self.by_wire.insert(wire.clone(), identity.clone());
            self.by_identity.insert(identity, wire);
        }
    }

    /// The `(server, remote)` behind a wire name, for a round-trip lookup.
    pub fn resolve(&self, wire: &str) -> Option<(&str, &str)> {
        self.by_wire
            .get(wire)
            .map(|(server, remote)| (server.as_str(), remote.as_str()))
    }

    /// The wire name already allocated for `(server, remote)`, if any.
    pub fn wire_for(&self, server: &str, remote: &str) -> Option<&str> {
        self.by_identity
            .get(&(server.to_owned(), remote.to_owned()))
            .map(String::as_str)
    }

    /// Number of allocated wire names.
    pub fn len(&self) -> usize {
        self.by_wire.len()
    }

    /// Whether no wire name has been allocated yet.
    pub fn is_empty(&self) -> bool {
        self.by_wire.is_empty()
    }
}
