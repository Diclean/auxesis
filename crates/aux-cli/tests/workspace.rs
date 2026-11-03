//! End-to-end tests of `aux workspace trust`: clearing the workspace taint
//! mark is an explicit two-step owner action — request a one-time code, then
//! complete with it — restricted to agent workspaces, and audited. Everything
//! runs in a throwaway Auxesis home.
//!
//! No real macOS notification is ever shown: a pending request is seeded
//! through the library with a recording notifier, so the tests can exercise
//! the real binary (the tool path) without an owner's screen.

use aux_notify::FakeNotifier;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::{tempdir, TempDir};

mod common;
use common::sandbox_command;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

fn run(home: &Path, path: &Path, code: Option<&str>) -> std::process::Output {
    run_with_stdin(home, path, code, None, None)
}

/// Run the real binary, optionally with a `--code` value and/or data piped
/// on stdin. `stdin` is always a pipe (closed immediately when `None`), so
/// the no-flag prompt path runs with a non-terminal stdin.
fn run_with_stdin(
    home: &Path,
    path: &Path,
    code: Option<&str>,
    stdin_data: Option<&str>,
    extra_env: Option<(&str, &str)>,
) -> std::process::Output {
    let dir = home.parent().expect("home sits in the temp dir");
    let mut command = sandbox_command(aux_bin(), dir, home);
    command
        .args(["workspace", "trust"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(code) = code {
        command.arg("--code").arg(code);
    }
    if let Some((name, value)) = extra_env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("run aux workspace trust");
    if let Some(data) = stdin_data {
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(data.as_bytes())
            .expect("write stdin");
    }
    drop(child.stdin.take());
    child
        .wait_with_output()
        .expect("wait for aux workspace trust")
}

struct Sandbox {
    _dir: TempDir,
    home: PathBuf,
    workspace: PathBuf,
    key: String,
}

fn sandbox() -> Sandbox {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let workspace = home.join("agents/main/workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
    let key = workspace
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    store.mark_workspace_tainted(&key, "shell").unwrap();
    Sandbox {
        _dir: dir,
        home,
        workspace,
        key,
    }
}

/// Create a pending request exactly like the CLI's request step, with a fake
/// notification channel, and return the delivered code.
fn seed_request(s: &Sandbox) -> String {
    let store = aux_store::Store::open(&kernel_core::store_path(&s.home)).unwrap();
    let fake = FakeNotifier::new();
    aux_engine::request_trust(&store, &s.key, "owner-cli", &fake).unwrap();
    let body = fake.last().unwrap().body;
    let line = body
        .lines()
        .find(|line| line.starts_with("Code: "))
        .unwrap();
    let after = &line["Code: ".len()..];
    let end = after.find(" (expires").unwrap_or(after.len());
    let digits: String = after[..end]
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    assert_eq!(digits.len(), 8, "notification body: {body}");
    digits
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn the_real_binary_cannot_complete_trust_without_the_notified_code() {
    // P1 regression (security-review round 3): the `shell` tool runs owner commands,
    // and `aux` is on the owner's PATH. Running the real binary must not
    // clear the mark: without the code it only repeats the pending request
    // (here rate-limited), wrong guesses fail, and only the code from the
    // notification completes.
    let s = sandbox();
    let code = seed_request(&s);

    // A tool invocation with no code cannot clear the mark: with a pending
    // request the CLI would prompt for the code, but its stdin is a pipe
    // (not a terminal), so it refuses without consuming anything and
    // without sending a second notification.
    let bare = run(&s.home, &s.workspace, None);
    let bare_out = String::from_utf8_lossy(&bare.stdout).into_owned();
    let bare_err = String::from_utf8_lossy(&bare.stderr).into_owned();
    assert!(!bare.status.success(), "stdout: {bare_out}");
    assert!(
        !bare_out.contains(&code) && !bare_err.contains(&code),
        "the binary's output must never carry the code"
    );

    // A tool-producible guess fails and leaves the mark alone.
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    let bad = run(&s.home, &s.workspace, Some(wrong));
    let bad_out = String::from_utf8_lossy(&bad.stdout).into_owned();
    let bad_err = String::from_utf8_lossy(&bad.stderr).into_owned();
    assert!(!bad.status.success());
    assert!(
        !bad_out.contains(&code) && !bad_err.contains(&code),
        "the binary's output must never carry the code"
    );

    let store = aux_store::Store::open(&kernel_core::store_path(&s.home)).unwrap();
    assert!(store.workspace_taint(&s.key).unwrap().is_some());
    assert!(store.trust_request(&s.key).unwrap().is_some());
    assert_eq!(store.event_count("workspace.trust_failed").unwrap(), 1);

    // The owner runs the same binary with the notified code: it completes.
    let done = run(&s.home, &s.workspace, Some(&code));
    let stdout = String::from_utf8_lossy(&done.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&done.stderr).into_owned();
    assert!(done.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("workspace trusted"), "stdout: {stdout}");
    assert!(stdout.contains(&s.key), "stdout: {stdout}");
    assert!(!stdout.contains(&code) && !stderr.contains(&code));
    assert_eq!(store.workspace_taint(&s.key).unwrap(), None);
    assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);
    assert!(store.trust_request(&s.key).unwrap().is_none(), "single use");

    // Replay of the same code through the real binary: refused.
    let replay = run(&s.home, &s.workspace, Some(&code));
    assert!(!replay.status.success());
    assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);

    // Nothing a tool can read (its own output, the audit rows, the store
    // file) ever carries the code.
    let spaced = format!("{} {}", &code[..4], &code[4..]);
    let conn = aux_store::open_keyed(&kernel_core::store_path(&s.home)).unwrap();
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE kind LIKE 'workspace.%'")
        .unwrap();
    let payloads: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!payloads.is_empty());
    for payload in payloads {
        assert!(
            !payload.contains(&code) && !payload.contains(&spaced),
            "audit carried the code: {payload}"
        );
    }
    let bytes = std::fs::read(kernel_core::store_path(&s.home)).unwrap();
    assert!(
        !contains_bytes(&bytes, code.as_bytes()) && !contains_bytes(&bytes, spaced.as_bytes()),
        "the store file carried the code"
    );
}

#[test]
fn trust_refuses_paths_that_are_not_agent_workspaces() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    // A directory outside the Auxesis home (no code, but path validation
    // fails before any request or notification).
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let output = run(&home, &elsewhere, None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("not an agent workspace"),
        "stderr:\n{stderr}"
    );

    // A missing workspace path.
    let output = run(&home, &home.join("agents/main/workspace"), None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("does not exist"), "stderr:\n{stderr}");

    // A path that exists but is a file.
    let file = home.join("agents/main/soul.md");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, "soul").unwrap();
    let output = run(&home, &file, None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("not a directory"), "stderr:\n{stderr}");
}

#[test]
fn the_cli_accepts_the_code_on_stdin_without_echoing_it() {
    // P1 regression (security-review round 4): the code is never a command-line
    // argument. `--code -` reads it from the pipe, and the binary echoes
    // neither the code nor a prompt into stdout/stderr.
    let s = sandbox();
    let code = seed_request(&s);

    let output = run_with_stdin(
        &s.home,
        &s.workspace,
        Some("-"),
        Some(&format!("{code}\n")),
        None,
    );
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("workspace trusted"), "stdout: {stdout}");
    assert!(
        !stdout.contains(&code) && !stderr.contains(&code),
        "the code must never be echoed"
    );
    assert!(
        !stderr.contains("deprecated"),
        "--code - is the supported form, not the legacy one: {stderr}"
    );

    let store = aux_store::Store::open(&kernel_core::store_path(&s.home)).unwrap();
    assert_eq!(store.workspace_taint(&s.key).unwrap(), None);
    assert!(store.trust_request(&s.key).unwrap().is_none(), "single use");
}

#[test]
fn the_no_flag_path_refuses_a_pipe_instead_of_prompting() {
    // No flag + a pending request means "type the code at a hidden prompt";
    // a non-terminal stdin must fail closed instead of consuming pipe data.
    let s = sandbox();
    let code = seed_request(&s);

    let output = run(&s.home, &s.workspace, None);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success());
    assert!(
        stderr.contains("--code -"),
        "the error must point at the explicit stdin form: {stderr}"
    );
    assert!(!stdout.contains(&code) && !stderr.contains(&code));

    let store = aux_store::Store::open(&kernel_core::store_path(&s.home)).unwrap();
    assert!(store.workspace_taint(&s.key).unwrap().is_some());
    assert!(store.trust_request(&s.key).unwrap().is_some());
}

#[test]
fn the_legacy_literal_prints_a_warning_and_still_completes() {
    let s = sandbox();
    let code = seed_request(&s);

    let output = run(&s.home, &s.workspace, Some(&code));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("workspace trusted"), "stdout: {stdout}");
    assert!(
        stderr.contains("deprecated"),
        "the legacy form must warn: {stderr}"
    );
    assert!(
        !stdout.contains(&code) && !stderr.contains(&code),
        "the warning must not echo the code"
    );

    let store = aux_store::Store::open(&kernel_core::store_path(&s.home)).unwrap();
    assert_eq!(store.workspace_taint(&s.key).unwrap(), None);
}

#[test]
fn trust_is_refused_while_the_shell_can_run_unsandboxed() {
    // P1 regression (security-review round 5): with `[shell] sandbox = false` +
    // `allow_unsandboxed = true`, the CLI must refuse the trust action,
    // audit `workspace.trust_refused`, and never issue a code. Tightening
    // the sandbox re-enables the owner action.
    let s = sandbox();
    std::fs::write(
        s.home.join("config.toml"),
        "version = 1\n\n[shell]\nsandbox = false\nallow_unsandboxed = true\n",
    )
    .unwrap();

    let refused = run(&s.home, &s.workspace, None);
    let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(!refused.status.success(), "stderr: {stderr}");
    assert!(
        stderr.contains("unsandboxed"),
        "the error must name the reason: {stderr}"
    );

    let store = aux_store::Store::open(&kernel_core::store_path(&s.home)).unwrap();
    assert_eq!(store.event_count("workspace.trust_refused").unwrap(), 1);
    assert!(store.workspace_taint(&s.key).unwrap().is_some());
    assert!(
        store.trust_request(&s.key).unwrap().is_none(),
        "no code row"
    );
    assert_eq!(
        store.event_count("workspace.trust_requested").unwrap(),
        0,
        "the request step must never run"
    );

    // A code the owner already received cannot be completed either.
    std::fs::write(
        s.home.join("config.toml"),
        "version = 1\n\n[shell]\nsandbox = true\nallow_unsandboxed = false\n",
    )
    .unwrap();
    let code = seed_request(&s);
    // Turn the escape hatch back on for the completion attempt.
    std::fs::write(
        s.home.join("config.toml"),
        "version = 1\n\n[shell]\nsandbox = false\nallow_unsandboxed = true\n",
    )
    .unwrap();
    let refused = run(&s.home, &s.workspace, Some(&code));
    let stderr = String::from_utf8_lossy(&refused.stderr).into_owned();
    assert!(!refused.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("unsandboxed"), "stderr: {stderr}");
    assert!(
        store.trust_request(&s.key).unwrap().is_some(),
        "the code must not be consumed"
    );
    assert!(store.workspace_taint(&s.key).unwrap().is_some());

    // Tighten the sandbox: the same code completes.
    std::fs::write(
        s.home.join("config.toml"),
        "version = 1\n\n[shell]\nsandbox = true\nallow_unsandboxed = false\n",
    )
    .unwrap();
    let done = run(&s.home, &s.workspace, Some(&code));
    let stdout = String::from_utf8_lossy(&done.stdout).into_owned();
    assert!(done.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("workspace trusted"), "stdout: {stdout}");
    assert_eq!(store.workspace_taint(&s.key).unwrap(), None);
    assert_eq!(store.event_count("workspace.trusted").unwrap(), 1);
}

#[test]
fn a_planted_osascript_in_path_is_never_executed_by_the_cli() {
    // P1 regression (security-review round 4): a fake `osascript` placed first on
    // PATH must never run as part of the trust flow. The code is piped on
    // stdin and completes normally while the plant stays untouched.
    let s = sandbox();
    let code = seed_request(&s);

    let dir = tempdir().unwrap();
    let fake_bin = dir.path().join("bin");
    std::fs::create_dir_all(&fake_bin).unwrap();
    let marker = dir.path().join("executed");
    let shim = fake_bin.join("osascript");
    std::fs::write(&shim, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = run_with_stdin(
        &s.home,
        &s.workspace,
        Some("-"),
        Some(&format!("{code}\n")),
        Some(("PATH", &path)),
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        !marker.exists(),
        "the planted osascript must never be executed"
    );

    let store = aux_store::Store::open(&kernel_core::store_path(&s.home)).unwrap();
    assert_eq!(store.workspace_taint(&s.key).unwrap(), None);
}
