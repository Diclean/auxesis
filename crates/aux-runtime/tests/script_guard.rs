//! Shell scripts must not touch the real home in a contradictory sandbox
//! environment.
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
use std::process::{Command, Output};

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

fn run_script(script: &Path, env: &[(&str, &str)], root: &Path) -> Output {
    let mut command = Command::new("bash");
    command
        .arg(script)
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().expect("run script")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn guard_refuses_and_allows_the_right_environments() {
    let root = workspace_root();
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("fake-real");
    let sandbox = dir.path().join("fake-sandbox");
    std::fs::create_dir_all(real.join(".auxesis")).unwrap();
    std::fs::create_dir_all(&sandbox).unwrap();
    let guard = root.join("scripts/lib/guard.sh");
    let probe = format!(". {}; echo reached", guard.display());

    // Contradictory: sandbox flag + HOME is the real home → refuse.
    let refused = Command::new("bash")
        .args(["-c", &probe])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_GUARD_REAL_HOME", &real)
        .env("HOME", &real)
        .output()
        .unwrap();
    assert!(!refused.status.success(), "{}", text(&refused));
    assert!(!text(&refused).contains("reached"));
    assert!(
        stderr(&refused).contains("refusing"),
        "{}",
        stderr(&refused)
    );

    // HOME inside the real `.auxesis` → refuse.
    let nested = Command::new("bash")
        .args(["-c", &probe])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_GUARD_REAL_HOME", &real)
        .env("HOME", real.join(".auxesis"))
        .output()
        .unwrap();
    assert!(!nested.status.success(), "{}", text(&nested));

    // A literal sandbox HOME → allowed.
    let allowed = Command::new("bash")
        .args(["-c", &probe])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_GUARD_REAL_HOME", &real)
        .env("HOME", &sandbox)
        .output()
        .unwrap();
    assert!(allowed.status.success(), "{}", text(&allowed));
    assert!(text(&allowed).contains("reached"));

    // Inert without the sandbox flag (normal launchd/developer runs).
    let inert = Command::new("bash")
        .args(["-c", &probe])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("AUXESIS_GUARD_REAL_HOME", &real)
        .env("HOME", &real)
        .output()
        .unwrap();
    assert!(inert.status.success(), "{}", text(&inert));
    assert!(text(&inert).contains("reached"));
}

/// `TMPDIR=<real home>` must make the macOS launcher refuse before it creates
/// anything or builds Swift.
#[test]
fn mac_launcher_refuses_real_home_inputs() {
    let root = workspace_root();
    let launcher = root.join("apps/auxesis-mac/scripts/run-auxesis-mac.sh");
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("fake-real");
    let sandbox = dir.path().join("fake-sandbox");
    std::fs::create_dir_all(real.join(".auxesis")).unwrap();
    std::fs::create_dir_all(&sandbox).unwrap();

    for (label, env) in [
        (
            "TMPDIR into .auxesis",
            vec![("TMPDIR", real.join(".auxesis"))],
        ),
        (
            "TMPDIR equal to the real home",
            vec![("TMPDIR", real.clone())],
        ),
        (
            "AUXESIS_HOME into .auxesis",
            vec![("AUXESIS_HOME", real.join(".auxesis"))],
        ),
        (
            "HOME inside .auxesis",
            vec![("HOME", real.join(".auxesis"))],
        ),
        (
            "HOME equals the real home with AUXESIS_HOME set",
            vec![
                ("HOME", real.clone()),
                ("AUXESIS_HOME", sandbox.join(".auxesis")),
            ],
        ),
    ] {
        // Base env first; the case's variables win on conflict (a case may
        // deliberately override HOME).
        let mut pairs: Vec<(&str, String)> = vec![
            ("AUXESIS_GUARD_REAL_HOME", real.display().to_string()),
            ("HOME", sandbox.display().to_string()),
        ];
        for (key, value) in &env {
            pairs.push((key, value.display().to_string()));
        }
        let output = run_script(
            &launcher,
            &pairs
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect::<Vec<_>>(),
            &root,
        );
        assert!(!output.status.success(), "{label}: {}", text(&output));
        assert!(
            stderr(&output).contains("refusing"),
            "{label}: {}",
            stderr(&output)
        );
        assert!(
            !text(&output).contains("building"),
            "{label} must refuse before any build: {}",
            text(&output)
        );
    }
}
