//! `aux mail` end to end against the real `aux` binary, in a sandbox home.
//!
//! No test opens a socket to a real server. The login test points at a bound
//! loopback listener and proves the daemon-side refusal happens **before** any
//! connection: the sealed read path never sends a password over plaintext.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn aux(dir: &Path, home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aux"));
    command
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn aux");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for aux")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A sandbox home with a `plain` mail account pointed at `port`.
fn home_with_plain_account(dir: &Path, port: u16) -> PathBuf {
    let home = dir.join(".auxesis");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        format!(
            "version = 1\n\n[privacy]\nmode = \"open\"\n\n\
             [connectors.mail]\n\
             [[connectors.mail.accounts]]\n\
             id = \"personal\"\n\
             email = \"me@example.org\"\n\
             only_folders = [\"INBOX\"]\n\
             [connectors.mail.accounts.imap]\n\
             host = \"127.0.0.1\"\n\
             port = {port}\n\
             security = \"plain\"\n"
        ),
    )
    .unwrap();
    std::fs::write(home.join(".env"), "AUX_MAIL_PERSONAL=secret\n").unwrap();
    home
}

#[test]
fn mail_add_stores_the_choice_and_the_password_offline() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".auxesis");
    std::fs::create_dir_all(&home).unwrap();
    // A preset domain: discovery needs no network.
    let added = aux(
        dir.path(),
        &home,
        &["mail", "add", "camille@gmail.com"],
        Some("1\nmon-mot-de-passe\n"),
    );
    assert!(added.status.success(), "{}", text(&added.stderr));

    let env = std::fs::read_to_string(home.join(".env")).unwrap();
    assert!(env.contains("AUX_MAIL_CAMILLE=mon-mot-de-passe"), "{env}");
    let config = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(config.contains("imap.gmail.com"), "{config}");
    assert!(config.contains("id = \"camille\""), "{config}");
    // The password never appears on stdout.
    assert!(!text(&added.stdout).contains("mon-mot-de-passe"));
}

#[test]
fn mail_test_refuses_a_plaintext_login_before_any_socket() {
    // Bind a loopback port so a connection would be visible, but never accept.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let home = home_with_plain_account(dir.path(), port);

    let tested = aux(dir.path(), &home, &["mail", "test"], None);
    assert!(
        !tested.status.success(),
        "a plaintext login must be refused: {}",
        text(&tested.stdout)
    );
    assert!(
        text(&tested.stderr).contains("aux mail:"),
        "{}",
        text(&tested.stderr)
    );
    // The refusal happens before the dialer runs: nothing connected.
    assert!(
        listener.accept().is_err(),
        "a plaintext account must not open a socket"
    );
}
