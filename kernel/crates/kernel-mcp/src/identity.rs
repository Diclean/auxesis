//! Tool identity pinning for extensions.
//!
//! At install time every tool an extension advertises is reduced to a 32-byte
//! BLAKE3 identity over its name, its canonical `inputSchema` and its
//! description. The identity is recorded ([`PinnedTools::pin`]) and compared
//! against the live `tools/list` at every launch ([`PinnedTools::verify`]).
//! Any added, removed or changed tool is drift: the extension freezes
//! (unmounted everywhere, Ledger row `ext.frozen`) until the owner re-approves
//! it. A changed description is therefore as much a change as a changed
//! schema — the description is model-visible text and a server can hide an
//! instruction in it.
//!
//! Canonical JSON sorts object keys and emits no whitespace, so two servers
//! that send the same schema in a different key order pin to the same
//! identity. Array order is significant: it is part of the schema.

use crate::tools::RemoteTool;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// The pinned identity of one tool:
/// `blake3(name ‖ 0x00 ‖ canonical-JSON(schema) ‖ 0x00 ‖ description)`.
///
/// The NUL separators keep the three fields from running into each other: a
/// name/schema/description split that moves a byte across a boundary changes
/// the digest.
pub fn tool_identity(name: &str, schema: &Value, description: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(name.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(canonical_json(schema).as_bytes());
    hasher.update(&[0x00]);
    hasher.update(description.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The identity of one live [`RemoteTool`]: its name, `inputSchema` and
/// description (the empty string when the server sent none).
fn identity_of(tool: &RemoteTool) -> [u8; 32] {
    let description = tool
        .description
        .as_ref()
        .map(|text| text.as_str())
        .unwrap_or("");
    tool_identity(&tool.name, tool.input_schema.as_value(), description)
}

/// Canonical JSON: object keys sorted, no whitespace.
///
/// Mirrors the ranking serialiser in [`crate::discovery`] so a schema is
/// spelled the same way wherever the crate compares one.
fn canonical_json(value: &Value) -> String {
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
                out.push_str(&map.get(*key).map(canonical_json).unwrap_or_default());
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
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// The identities recorded at install, keyed by remote tool name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinnedTools {
    identities: BTreeMap<String, [u8; 32]>,
}

impl PinnedTools {
    /// Record the identity of every tool in `tools`.
    ///
    /// A server that repeats a name pins its last entry, matching the wire
    /// decoder's dedupe order.
    pub fn pin(tools: &[RemoteTool]) -> Self {
        let mut identities = BTreeMap::new();
        for tool in tools {
            identities.insert(tool.name.clone(), identity_of(tool));
        }
        Self { identities }
    }

    /// The identity recorded for `name`, or `None` when it was never pinned.
    pub fn identity(&self, name: &str) -> Option<[u8; 32]> {
        self.identities.get(name).copied()
    }

    /// Number of pinned tools.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// True when nothing is pinned.
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Compare the live tool list against the pinned identities.
    ///
    /// `Ok(())` only when every pinned tool is still live with the same
    /// identity and no live tool is new. Otherwise [`IdentityDrift`] names
    /// every added, removed and changed tool (each list sorted by name).
    pub fn verify(&self, live_tools: &[RemoteTool]) -> Result<(), IdentityDrift> {
        let mut live: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        for tool in live_tools {
            live.insert(tool.name.clone(), identity_of(tool));
        }

        let added = live
            .keys()
            .filter(|name| !self.identities.contains_key(*name))
            .cloned()
            .collect();
        let removed = self
            .identities
            .keys()
            .filter(|name| !live.contains_key(*name))
            .cloned()
            .collect();
        let changed = live
            .iter()
            .filter(|(name, identity)| {
                matches!(self.identities.get(*name), Some(pinned) if pinned != *identity)
            })
            .map(|(name, _)| name.clone())
            .collect();

        let drift = IdentityDrift {
            added,
            removed,
            changed,
        };
        if drift.is_empty() {
            Ok(())
        } else {
            Err(drift)
        }
    }
}

/// What changed between the pinned tool list and a live one.
///
/// A non-empty drift freezes the extension; the three lists are sorted by
/// name so the Ledger row and the owner's re-approval diff are deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityDrift {
    /// Live tools that were never pinned.
    pub added: Vec<String>,
    /// Pinned tools the live list no longer advertises.
    pub removed: Vec<String>,
    /// Pinned tools whose live identity differs (schema or description).
    pub changed: Vec<String>,
}

impl IdentityDrift {
    /// True when nothing drifted.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

impl fmt::Display for IdentityDrift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tool identity drift (added: {}, removed: {}, changed: {})",
            self.added.len(),
            self.removed.len(),
            self.changed.len()
        )
    }
}

impl std::error::Error for IdentityDrift {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identity_separates_fields_and_ignores_key_order() {
        let one = tool_identity(
            "search",
            &json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            "Search",
        );
        let reordered = tool_identity(
            "search",
            &json!({"properties": {"q": {"type": "string"}}, "type": "object"}),
            "Search",
        );
        assert_eq!(one, reordered, "key order must not change the identity");

        // Moving a byte across a field boundary must change the digest.
        let other = tool_identity(
            "searc",
            &json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            "hSearch",
        );
        assert_ne!(one, other);
    }

    #[test]
    fn canonical_json_is_compact_and_sorted() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": [true, null]})),
            "{\"a\":[true,null],\"b\":1}"
        );
    }
}
