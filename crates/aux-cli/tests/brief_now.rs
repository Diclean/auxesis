//! `aux brief now` still writes the offline fixture brief
//! with `--offline`, and refuses cleanly with the exact message when no
//! daemon answers.
//!
//! Sandbox only (rule 4): a temp `HOME`/`AUXESIS_HOME`, `AUXESIS_SANDBOX=1`
//! and an explicit loopback port (`0` = no endpoint, or a closed port). The
//! real home and the real daemon port are never touched.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::tempdir;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

fn run(dir: &Path, home: &Path, port: &str, args: &[&str]) -> Output {
    Command::new(aux_bin())
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", port)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .output()
        .expect("run aux brief")
}

/// An open home whose quiet window is disabled (`start == end`), so a run
/// always writes whatever the test hour.
fn home_open(dir: &Path) -> std::path::PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version = 1\ndefault_agent = \"main\"\n\n[privacy]\nmode = \"open\"\n\n[quiet]\nstart = \"00:00\"\nend = \"00:00\"\n\n[ui]\nlanguage = \"en\"\n",
    )
    .unwrap();
    home
}

/// A closed loopback port: bind, learn the port, drop the listener.
fn closed_port() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port.to_string()
}

#[test]
fn offline_still_writes_the_fixture_brief_in_a_sandbox_home() {
    let dir = tempdir().unwrap();
    let home = home_open(dir.path());

    let output = run(dir.path(), &home, "0", &["brief", "now", "--offline"]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Point d’équipe"), "{stdout}");
}

#[test]
fn without_a_daemon_the_command_says_so_and_exits_one() {
    let dir = tempdir().unwrap();
    let home = home_open(dir.path());
    let port = closed_port();

    let output = run(dir.path(), &home, &port, &["brief", "now"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.trim(),
        "aux brief: auxd is not running (start it, or use --offline)",
        "{stderr}"
    );
}
