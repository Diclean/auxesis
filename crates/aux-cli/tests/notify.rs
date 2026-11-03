//! End-to-end checks of `aux notify` that never run `osascript`.
//!
//! The old tests planted a fake `osascript` first on `PATH`; since fix round
//! 5 the transport executes the fixed absolute `/usr/bin/osascript` with a
//! cleared environment, so a fake on `PATH` can never stand in for it (and
//! actually running it from a test would show a real notification, which is
//! forbidden). The delivery payload and the transport error mapping are
//! covered with the recording fake in `src/notify.rs`; what remains here is
//! the `STOP` marker, which suppresses delivery before any spawn.
//!
//! macOS-only: on other platforms `MacNotifier` returns `Unsupported`
//! instead of spawning anything, which is covered in the aux-notify crate.

#![cfg(target_os = "macos")]

use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::tempdir;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

fn run_notify(dir: &Path, home: &Path, title: &str, body: &str) -> Output {
    Command::new(aux_bin())
        .args(["notify", title, body])
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .output()
        .expect("run aux notify")
}

/// A home whose config sets `mode`, so a test can pick which check refuses.
fn home_with_mode(dir: &Path, mode: &str) -> std::path::PathBuf {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        format!("version = 1\ndefault_agent = \"main\"\n\n[privacy]\nmode = \"{mode}\"\n"),
    )
    .unwrap();
    home
}

#[test]
fn notify_is_suppressed_by_the_stop_marker() {
    // Open mode, so the STOP marker is the check that refuses.
    let dir = tempdir().unwrap();
    let home = home_with_mode(dir.path(), "open");
    std::fs::write(home.join("STOP"), b"").unwrap();

    let output = run_notify(dir.path(), &home, "Title", "Body");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("STOP"), "{stderr}");
}

#[test]
fn notify_is_refused_in_private_mode() {
    let dir = tempdir().unwrap();
    let home = home_with_mode(dir.path(), "private");

    let output = run_notify(dir.path(), &home, "Title", "Body");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("private mode"), "{stderr}");
}

#[test]
fn notify_test_prints_the_daemon_cause_and_the_allow_hint() {
    use std::io::{Read, Write};
    let dir = tempdir().unwrap();
    let home = home_with_mode(dir.path(), "open");
    let token = "0123456789abcdef0123456789abcdef"; // gitleaks:allow
    std::fs::write(home.join("api.token"), format!("{token}\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(home.join("api.token"), mode).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // One canned daemon reply on loopback; the request is kept for checks.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = vec![0; 4096];
        let read = stream.read(&mut request).unwrap();
        let body = r#"{"delivered":false,"cause":"timeout"}"#;
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(reply.as_bytes()).unwrap();
        String::from_utf8_lossy(&request[..read]).to_string()
    });

    let output = Command::new(aux_bin())
        .args(["notify", "--test"])
        .env_clear()
        .env("HOME", dir.path())
        .env("AUXESIS_HOME", &home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", port.to_string())
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .output()
        .expect("run aux notify --test");

    let request = server.join().unwrap();
    assert!(request.starts_with("POST /v1/notify/test "), "{request}");
    assert!(request.contains(&format!("Bearer {token}")), "token sent");
    assert!(!output.status.success(), "a timeout is not delivered");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("(timeout)"), "{stdout}");
    assert!(
        stdout.contains(
            "macOS may be showing an Allow pop-up for auxd: click OK, then run this again."
        ),
        "{stdout}"
    );
}
