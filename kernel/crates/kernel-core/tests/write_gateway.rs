//! J-02 round 4, item (B): the sandbox-home invariant is enforced
//! structurally, not by a "does this file mention home" heuristic.
//!
//! Outside `kernel-core` (the single source of truth), workspace code must not:
//!
//! * read `AUXESIS_HOME` or `HOME` itself, or call `dirs::home_dir` — the
//!   home path comes from `kernel_core::ensure_home`/`verified_home`;
//! * use `tokio::fs`;
//! * make raw mutating filesystem calls in non-test code (`fs::write`,
//!   `fs::create_dir*`, `fs::remove_*`, `fs::rename`, `File::create`,
//!   `OpenOptions::new`) — those go through the `SandboxHome` gateway.
//!
//! Every hit must be listed in `qa/sandbox-gateway-allowlist.txt` with a
//! justification (`relative/path.rs | api-pattern | why`). The list is the
//! reviewed debt; an unlisted call fails CI.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const BANNED: &[&str] = &[
    "AUXESIS_HOME\"",
    "dirs::home_dir",
    "\"HOME\"",
    "tokio::fs::",
    "fs::write(",
    "fs::create_dir(",
    "fs::create_dir_all(",
    "fs::remove_file(",
    "fs::remove_dir(",
    "fs::remove_dir_all(",
    "fs::rename(",
    "fs::copy(",
    "fs::hard_link(",
    "File::create(",
    "File::options(",
    "OpenOptions::new(",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/kernel-core is two levels under the workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `path | api-pattern | justification` entries, `#` comments allowed.
fn allowlist(root: &Path) -> Vec<(String, String, String)> {
    let text = std::fs::read_to_string(root.join("qa/sandbox-gateway-allowlist.txt"))
        .expect("qa/sandbox-gateway-allowlist.txt must exist");
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut parts = line.split('|').map(str::trim);
            (
                parts.next().unwrap_or_default().to_string(),
                parts.next().unwrap_or_default().to_string(),
                parts.next().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[test]
fn home_access_and_raw_fs_calls_are_gateway_routed_or_allowlisted() {
    let root = workspace_root();
    let entries = allowlist(&root);
    let mut sources = Vec::new();
    for member in std::fs::read_dir(root.join("crates")).unwrap().flatten() {
        rust_sources(&member.path().join("src"), &mut sources);
    }
    sources.sort();

    let mut hits: BTreeSet<String> = BTreeSet::new();
    let mut used_entries: BTreeSet<String> = BTreeSet::new();
    for path in &sources {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        // kernel-core is the single source of truth: it *owns* the env reads,
        // the guard and the gateway.
        if relative.starts_with("crates/kernel-core/") {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
        // Only non-test code is in scope: cut at the LAST test module (a
        // doc comment mentioning `mod tests` must not truncate the scan).
        let cut = text.rfind("mod tests").unwrap_or(text.len());
        let body = &text[..cut];
        for (index, line) in body.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            for pattern in BANNED {
                if !line.contains(pattern) {
                    continue;
                }
                let allowed = entries.iter().any(|(file, api, _)| {
                    let matches =
                        relative.ends_with(file.as_str()) && pattern.contains(api.as_str());
                    if matches {
                        used_entries.insert(format!("{file}|{api}"));
                    }
                    matches
                });
                if !allowed {
                    hits.insert(format!("{relative}:{}: {} [{pattern}]", index + 1, trimmed));
                }
            }
        }
    }

    // Every allowlist entry must be used by a current hit and carry a
    // justification: stale entries are debt that must be cleared.
    for (file, api, justification) in &entries {
        assert!(
            !justification.is_empty(),
            "allowlist entry {file} | {api} has no justification"
        );
        let file_path = root.join(file);
        assert!(
            file_path.exists(),
            "stale allowlist entry: {file} does not exist"
        );
        let used = used_entries.contains(&format!("{file}|{api}"));
        assert!(
            used,
            "stale allowlist entry (no matching hit): {file} | {api}"
        );
    }

    assert!(
        hits.is_empty(),
        "home access / raw fs calls outside the kernel-core gateway, not in \
         qa/sandbox-gateway-allowlist.txt:\n{}",
        hits.into_iter().collect::<Vec<_>>().join("\n")
    );
}
