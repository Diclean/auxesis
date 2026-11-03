//! The macOS `security` binary may only be spawned from the one allowlisted
//! module that checks `keychain_allowed()`.
//!
//! This test walks the workspace sources with comments stripped and fails on:
//!
//! * a `Command::new(...)` whose argument names the `security` binary —
//!   inline (`Command::new("security")`, `Command::new("/usr/bin/security")`)
//!   or aliased through a `security` string literal in the same file (a
//!   spawn via a constant or a variable);
//! * the allowlisted module losing its `keychain_allowed()` check.
//!
//! Together with the default-deny opt-in (`AUXESIS_ALLOW_KEYCHAIN=1`), no
//! test, builder or breaker can reach the owner's real Keychain (KC-01).

use std::path::{Path, PathBuf};

/// The single module allowed to name the binary.
const ALLOWED: &str = "crates/kernel-core/src/keychain.rs";

/// This checker itself, excluded so its own needle assembly is not a hit.
const SELF: &str = "crates/kernel-core/tests/keychain_single_spawn.rs";

fn workspace_root() -> PathBuf {
    // <root>/crates/kernel-core -> <root>/crates -> <root>
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

/// Remove `//` and `/* */` comments while keeping string literals intact
/// (the literal `security` must stay visible to the scan).
fn strip_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '"' {
            out.push(c);
            i += 1;
            while i < bytes.len() {
                let b = bytes[i] as char;
                out.push(b);
                if b == '\\' && i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                i += 1;
                if b == '"' {
                    break;
                }
            }
        } else if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// A `Command::new(` whose argument names the binary within a short window.
fn spawns_security(code: &str) -> bool {
    let mut rest = code;
    while let Some(at) = rest.find("Command::new(") {
        let after = &rest[at + "Command::new(".len()..];
        let window = &after[..after.len().min(200)];
        if window.contains("security") {
            return true;
        }
        rest = after;
    }
    false
}

/// A `security` string literal in a file that also spawns something: the
/// binary may be reached through a constant or a variable.
fn security_literal_with_spawn(code: &str) -> bool {
    (code.contains("\"security\"") || code.contains("\"/usr/bin/security\""))
        && code.contains("Command::new(")
}

#[test]
fn security_is_spawned_only_from_the_allowlisted_module() {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root.join("crates"), &mut files);
    assert!(
        files.len() > 50,
        "the source walk found too few files: {}",
        files.len()
    );

    let mut offenders = Vec::new();
    let mut allowed_checks_guard = false;
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let code = strip_comments(&text);
        if !(spawns_security(&code) || security_literal_with_spawn(&code)) {
            continue;
        }
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if relative == SELF {
            continue;
        }
        if relative == ALLOWED {
            allowed_checks_guard = code.contains("keychain_allowed");
            continue;
        }
        offenders.push(relative);
    }
    assert!(
        offenders.is_empty(),
        "the security binary is spawned outside {ALLOWED}: {offenders:?}"
    );
    assert!(
        allowed_checks_guard,
        "{ALLOWED} must check keychain_allowed() before spawning"
    );
}
