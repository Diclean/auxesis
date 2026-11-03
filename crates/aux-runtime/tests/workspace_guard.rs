//! Item (C) + K-01 + GLM-P1-2: every workspace **binary target** must call the
//! one shared sandbox guard, `kernel_core::ensure_sandbox_guard`, before it reads
//! or creates anything.
//!
//! The target list comes from `cargo metadata` (every package, every `bin`
//! target, including `src/bin/<name>/main.rs` auto-discovery and `[[bin]]`
//! with a custom path), never from directory scanning — a new unguarded
//! binary fails this test.
//!
//! The exemptions are exact `(package, target path)` pairs for **test-only**
//! JSON-RPC fixtures with no home access: the ACP stdio fake agent (K-01, #28)
//! and the MCP stdio fake server (#111). Matching is on package + path, so
//! another package cannot inherit an exception by name.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Exact `(package name, workspace-relative target source path)`.
const EXEMPT_TEST_ONLY_BINS: &[(&str, &str)] = &[
    ("aux-acp", "crates/aux-acp/src/bin/acp_fake_agent.rs"),
    ("aux-mcp", "crates/aux-mcp/tests/support/fake_mcp_server.rs"),
    // The vendored kernel's own test-only fixture; kernel-core's guard covers it.
    (
        "kernel-mcp",
        "kernel/crates/kernel-mcp/tests/support/fake_mcp_server.rs",
    ),
];

/// The exact set of guarded workspace binaries, as `package: path`. A binary
/// that vanishes or a new one fails the test until it is listed here.
const EXPECTED_GUARDED_BINS: &[&str] = &[
    "aux-cli: crates/aux-cli/src/main.rs",
    "aux-fakemail: crates/aux-fakemail/src/bin/aux-fakemail.rs",
    "aux-imessage: crates/aux-imessage/src/bin/aux-imessage.rs",
    "auxd: crates/auxd/src/main.rs",
    "privacy-eval: kernel/qa/privacy-eval/src/main.rs",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/aux-core is two levels under the workspace root")
        .to_path_buf()
}

/// Strip Rust comments and string literals (a textual check that cannot be
/// satisfied by a comment or a string containing the guard's name).
fn strip_comments_and_strings(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else if c == '"' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else if c == 'r' {
            // Raw string: r"..." / r#"..."# / r##"..."##
            let mut j = i + 1;
            let mut hashes = 0;
            while j < bytes.len() && bytes[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                let closer: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                while j + closer.len() <= bytes.len()
                    && &bytes[j..j + closer.len()] != closer.as_slice()
                {
                    j += 1;
                }
                i = (j + closer.len()).min(bytes.len());
            } else {
                out.push(c);
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// A real call expression: `ensure_sandbox_guard` followed by `(` (after
/// whitespace).
fn calls_guard(code: &str) -> bool {
    let mut rest = code;
    while let Some(at) = rest.find("ensure_sandbox_guard") {
        let after = &rest[at + "ensure_sandbox_guard".len()..];
        if after.trim_start().starts_with('(') {
            return true;
        }
        rest = after;
    }
    false
}

/// Workspace-relative, forward-slashed path for a cargo-metadata `src_path`.
fn workspace_relative(source: &Path, root: &Path) -> String {
    source
        .strip_prefix(root)
        .unwrap_or(source)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Exact `(package, workspace-relative path)` exemption match: equality, not
/// a suffix. A second bin named `.../src/bin/acp_fake_agent.rs` under another
/// directory (or in another package) is NOT exempt (security review round-4 P2).
fn is_exempt_bin(package: &str, workspace_relative_path: &str) -> bool {
    EXEMPT_TEST_ONLY_BINS
        .iter()
        .any(|(pkg, path)| *pkg == package && workspace_relative_path == *path)
}

#[test]
fn every_workspace_binary_calls_the_shared_sandbox_guard() {
    let root = workspace_root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .expect("running cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata JSON");
    let packages = metadata["packages"].as_array().expect("packages array");

    let mut checked: Vec<String> = Vec::new();
    let mut missing = Vec::new();
    let mut exempted: Vec<(String, String)> = Vec::new();
    for package in packages {
        let name = package["name"].as_str().unwrap_or_default();
        for target in package["targets"].as_array().cloned().unwrap_or_default() {
            let is_bin = target["kind"]
                .as_array()
                .map(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")))
                .unwrap_or(false);
            if !is_bin {
                continue;
            }
            let source = PathBuf::from(target["src_path"].as_str().expect("target src_path"));
            let relative = workspace_relative(&source, &root);
            if is_exempt_bin(name, &relative) {
                exempted.push((name.to_string(), relative));
                continue;
            }
            checked.push(format!("{name}: {relative}"));
            let text = std::fs::read_to_string(&source)
                .unwrap_or_else(|err| panic!("reading {}: {err}", source.display()));
            // A comment or string mentioning the guard must not satisfy the
            // check: strip both, then require a real call expression.
            if !calls_guard(&strip_comments_and_strings(&text)) {
                missing.push(format!("{name}: {relative}"));
            }
        }
    }

    checked.sort();
    assert_eq!(
        checked, EXPECTED_GUARDED_BINS,
        "the guarded workspace binaries changed; update EXPECTED_GUARDED_BINS"
    );
    assert!(
        missing.is_empty(),
        "binary targets that do not call kernel_core::ensure_sandbox_guard: {missing:?}"
    );
    assert!(
        exempted.iter().all(|(pkg, path)| is_exempt_bin(pkg, path)),
        "unexpected test-only exemptions: {exempted:?}"
    );
}

/// The exemption must match the **exact** package and workspace-relative
/// path. A synthetic second target with the same file-name suffix in another
/// directory (or the same path in another package) must not be skipped.
#[test]
fn the_fake_agent_exemption_is_exact_package_and_path() {
    let root = Path::new("/workspace");

    // The real pair, normalised from an absolute cargo-metadata src_path.
    let real = workspace_relative(
        Path::new("/workspace/crates/aux-acp/src/bin/acp_fake_agent.rs"),
        root,
    );
    assert_eq!(real, "crates/aux-acp/src/bin/acp_fake_agent.rs");
    assert!(is_exempt_bin("aux-acp", &real));

    // Same package, same file name, different directory: NOT exempt.
    let fixture = workspace_relative(
        Path::new("/workspace/qa/fixture/src/bin/acp_fake_agent.rs"),
        root,
    );
    assert_eq!(fixture, "qa/fixture/src/bin/acp_fake_agent.rs");
    assert!(
        !is_exempt_bin("aux-acp", &fixture),
        "a suffix match must not be exempt"
    );
    assert!(!is_exempt_bin(
        "aux-acp",
        "crates/aux-acp/qa/src/bin/acp_fake_agent.rs"
    ));

    // Another package with the exact path: NOT exempt.
    assert!(!is_exempt_bin("aux-other", &real));

    // A crate-relative path is NOT the workspace-relative exemption.
    assert!(!is_exempt_bin("aux-acp", "src/bin/acp_fake_agent.rs"));
}
