//! Reading named values from the protected `~/.auxesis/.env`.
//!
//! `.env` holds provider keys (`AUX_KEY_*`) and, for MCP servers, declared
//! vendor keys (`env = ["DATAGOUV_KEY"]` in `mcp.toml`). Only the names a
//! caller asks for are returned; a missing or unusable file yields an empty
//! map, so a caller can fail closed per consumer instead of aborting. Values
//! are never logged here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Refuse to read a `.env` larger than this (runaway write, device file).
pub const MAX_ENV_FILE_BYTES: u64 = 256 * 1024;

/// Read the requested values from `<home>/.env`.
pub fn read_values(home: &Path, names: &BTreeSet<String>) -> BTreeMap<String, String> {
    if names.is_empty() {
        return BTreeMap::new();
    }
    let path = home.join(".env");
    let Ok(meta) = std::fs::metadata(&path) else {
        return BTreeMap::new();
    };
    if !meta.is_file() || meta.len() > MAX_ENV_FILE_BYTES {
        return BTreeMap::new();
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return BTreeMap::new();
    };
    parse(&text, names)
}

/// Parse `NAME = value` lines, keeping only `names`.
///
/// Accepts `#` comments, blank lines, an optional `export ` prefix and
/// optional matching single/double quotes. A duplicated name keeps the last
/// value, matching the shell's assignment order.
pub fn parse(text: &str, names: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !names.contains(key) {
            continue;
        }
        values.insert(key.to_owned(), strip_quotes(value.trim()).to_owned());
    }
    values
}

fn strip_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_requested_names_are_kept_and_quotes_are_stripped() {
        let names: BTreeSet<String> = ["DATAGOUV_KEY", "OTHER"]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let text = "\
# comment
DATAGOUV_KEY=plain-value
export OTHER = \"quoted value\"
UNREQUESTED=leak
";
        let values = parse(text, &names);
        assert_eq!(
            values.get("DATAGOUV_KEY").map(String::as_str),
            Some("plain-value")
        );
        assert_eq!(
            values.get("OTHER").map(String::as_str),
            Some("quoted value")
        );
        assert!(!values.contains_key("UNREQUESTED"));
    }

    #[test]
    fn a_missing_file_yields_no_value() {
        let dir = tempfile::tempdir().unwrap();
        let names: BTreeSet<String> = ["DATAGOUV_KEY".to_owned()].into_iter().collect();
        assert!(read_values(dir.path(), &names).is_empty());
    }

    #[test]
    fn an_oversize_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut text = String::from("DATAGOUV_KEY=secret\n");
        text.push_str(&"#".repeat(MAX_ENV_FILE_BYTES as usize));
        std::fs::write(dir.path().join(".env"), text).unwrap();
        let names: BTreeSet<String> = ["DATAGOUV_KEY".to_owned()].into_iter().collect();
        assert!(read_values(dir.path(), &names).is_empty());
    }
}
