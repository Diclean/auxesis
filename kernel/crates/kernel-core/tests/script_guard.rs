//! J-02 round 7: shell scripts must not touch the real home in a
//! contradictory sandbox environment.
//!
//! * Every script under `scripts/` or `apps/*/scripts/` that mentions
//!   `$HOME`, `~/Library` or `.auxesis` must source `scripts/lib/guard.sh`
//!   (or be explicitly allowlisted with a reason).
//! * `guard.sh` refuses `AUXESIS_SANDBOX=1` with a HOME resolving to the
//!   real home, and the macOS launcher additionally refuses a `TMPDIR`,
//!   `HOME` or `AUXESIS_HOME` resolving into the real home.
//!
//! All behaviour tests use fake paths via the `AUXESIS_GUARD_REAL_HOME` seam
//! (which can only make the guard stricter), never the real home.

use std::path::{Path, PathBuf};

/// `(relative path, reason)` scripts that mention a home but do not need the
/// guard.
const ALLOWLIST: &[(&str, &str)] = &[];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/aux-core is two levels under the workspace root")
        .to_path_buf()
}

fn shell_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            shell_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "sh") {
            out.push(path);
        }
    }
}

fn mentions_home(text: &str) -> bool {
    ["$HOME", "${HOME", "~/Library", "~/.auxesis", ".auxesis"]
        .iter()
        .any(|needle| text.contains(needle))
}

#[test]
fn home_touching_scripts_source_the_shared_guard() {
    let root = workspace_root();
    let mut sources = Vec::new();
    shell_sources(&root.join("scripts"), &mut sources);
    if let Ok(apps) = std::fs::read_dir(root.join("apps")) {
        for app in apps.flatten() {
            shell_sources(&app.path().join("scripts"), &mut sources);
        }
    }
    sources.sort();

    let mut missing = Vec::new();
    for path in &sources {
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "scripts/lib/guard.sh" {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
        if !mentions_home(&text) {
            continue;
        }
        let allowed = ALLOWLIST.iter().any(|(file, reason)| {
            assert!(!reason.is_empty(), "allowlist entry {file} has no reason");
            relative == *file
        });
        if !allowed && !text.contains("lib/guard.sh") {
            missing.push(relative);
        }
    }
    assert!(
        missing.is_empty(),
        "scripts touching a home must source scripts/lib/guard.sh (or be allowlisted): {missing:?}"
    );
}
