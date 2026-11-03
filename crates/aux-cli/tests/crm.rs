//! `aux crm timeline refresh` end to end against the real `aux` binary, in a
//! sandbox home.
//!
//! The refresh logic itself is tested with a fixture mailbox and fixture
//! EventKit events in `aux-mail/tests/timeline.rs`; this proves the command is
//! wired and that an empty home is a calm success, not a crash.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn aux(dir: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aux"))
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn aux")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A sandbox home with an open config and no mailbox.
fn empty_home(dir: &Path) -> PathBuf {
    let home = dir.join(".auxesis");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    home
}

#[test]
fn timeline_refresh_on_an_empty_home_is_a_calm_success() {
    let dir = tempfile::tempdir().unwrap();
    let home = empty_home(dir.path());
    let output = aux(dir.path(), &home, &["crm", "timeline", "refresh"]);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        text(&output.stdout),
        text(&output.stderr)
    );
    let stdout = text(&output.stdout);
    assert!(
        stdout.contains("timeline refresh: 0 mail, 0 meetings"),
        "unexpected output: {stdout}"
    );
}
