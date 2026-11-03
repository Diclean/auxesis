//! End-to-end tests of `aux activity` in a throwaway Auxesis home.
//!
//! The command is read-only by contract: these tests also prove that a fresh
//! home is left untouched.

use std::process::Stdio;
use tempfile::tempdir;

mod common;
use common::sandbox_command;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

fn run_activity(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    let dir = home.parent().expect("home sits in the temp dir");
    sandbox_command(aux_bin(), dir, home)
        .arg("activity")
        .args(args)
        .output()
        .expect("run aux activity")
}

#[test]
fn fresh_home_is_empty_and_never_created() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("missing");

    let output = run_activity(&home, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "activity failed:\n{stdout}");
    assert_eq!(stdout, "(no activity)\n");
    assert!(!home.exists(), "activity must not create the home");

    let output = run_activity(&home, &["--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "activity --json failed:\n{stdout}");
    assert_eq!(stdout, "[]\n");
    assert!(!home.exists(), "activity --json must not create the home");
}

#[test]
fn timeline_shows_messages_and_events_with_filters_and_json() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let store = aux_store::Store::open(&home.join("store.db")).unwrap();

    let main = store.create_session("main", None).unwrap();
    store
        .append_message(main.id, "user", "from main", None)
        .unwrap();
    let axis = store.create_session("axis", None).unwrap();
    store
        .append_message(axis.id, "user", "from axis", None)
        .unwrap();
    store
        .log_event(
            "tool.decision",
            r#"{"agent":"main","tool":"shell","outcome":"allowed","reason":"rule 0: allow"}"#,
        )
        .unwrap();
    store
        .log_event("daemon.started", r#"{"version":"0.1.0"}"#)
        .unwrap();

    // Full table: header plus every entry.
    let output = run_activity(&home, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "activity failed:\n{stdout}");
    assert!(stdout.starts_with("TIME"), "unexpected output:\n{stdout}");
    assert!(stdout.contains("message.user"));
    assert!(stdout.contains("from main"));
    assert!(stdout.contains("from axis"));
    assert!(stdout.contains("tool.decision"));
    assert!(stdout.contains("daemon.started"));

    // --agent keeps only main's message and main's event.
    let output = run_activity(&home, &["--agent", "main"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("from main"), "unexpected output:\n{stdout}");
    assert!(
        !stdout.contains("from axis"),
        "agent filter leaked:\n{stdout}"
    );
    assert!(
        !stdout.contains("daemon.started"),
        "dotless event leaked:\n{stdout}"
    );

    // --since relative to now: everything is fresh.
    let output = run_activity(&home, &["--since", "1h", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 4, "stdout: {stdout}");

    // --since in the future filters everything out without failing.
    let output = run_activity(&home, &["--since", "2999-01-01"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "activity failed:\n{stdout}");
    assert_eq!(stdout, "(no activity)\n");

    // --limit keeps the most recent entries only.
    let output = run_activity(&home, &["--limit", "1", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value.as_array().unwrap().len(), 1, "stdout: {stdout}");

    // --json shape: stable keys, nullable agent, agent attribution.
    let output = run_activity(&home, &["--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let entries = value.as_array().unwrap();
    assert_eq!(entries.len(), 4, "stdout: {stdout}");
    for entry in entries {
        let object = entry.as_object().unwrap();
        assert!(object.contains_key("at"));
        assert!(object.contains_key("kind"));
        assert!(object.contains_key("agent"));
        assert!(object.contains_key("summary"));
    }
    let decision = entries
        .iter()
        .find(|entry| entry["kind"] == "tool.decision")
        .unwrap();
    assert_eq!(decision["agent"], "main");
    assert_eq!(decision["summary"], "shell allowed — rule 0: allow");
    let daemon = entries
        .iter()
        .find(|entry| entry["kind"] == "daemon.started")
        .unwrap();
    assert!(daemon["agent"].is_null());
    assert_eq!(daemon["summary"], "v0.1.0");
}

#[test]
fn invalid_since_fails_with_a_clear_message() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");

    let output = run_activity(&home, &["--since", "yesterday"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "should have failed");
    assert!(
        stderr.contains("invalid --since"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn activity_survives_closed_stdout() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("missing");

    let mut child = sandbox_command(aux_bin(), dir.path(), &home)
        .arg("activity")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn aux activity");
    drop(child.stdout.take());

    let status = child.wait().expect("wait for activity");
    assert!(
        status.success(),
        "must not panic on a broken pipe: {status:?}"
    );
}
