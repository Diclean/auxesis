//! The EventKit snapshot route against the real `auxd` binary.
//!
//! Both modes keep the snapshot encrypted at rest and never a plaintext copy;
//! a legacy plaintext file is removed in either. The sandbox home holds only a config and the
//! store, and the API port is ephemeral.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use aux_store::Store;
use common::{post, KillOnDrop};
use kernel_core::{config_path, store_path};

const CANARY_TITLE: &str = "EVENTKIT-CANARY-dentist";
const CANARY_PHONE: &str = "+33 6 12 34 56 78";

fn config(mode: &str) -> String {
    format!(
        r#"version = 1
default_agent = "main"

[privacy]
mode = "{mode}"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#
    )
}

fn snapshot_body() -> String {
    serde_json::json!({
        "authorized": true,
        "events": [{
            "title": CANARY_TITLE,
            "start": "2026-10-10T09:00:00Z",
            "end": "2026-10-10T10:00:00Z",
            "calendar": "Work",
            "location": CANARY_PHONE,
        }],
        "reminders": [],
    })
    .to_string()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Every file under `home` that an EventKit snapshot could occupy.
fn eventkit_files(home: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(home)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("apple-eventkit"))
        })
        .collect()
}

/// Start the daemon on `home` and return it with its API address and token.
fn start_daemon(dir: &Path, home: &Path) -> (KillOnDrop, SocketAddr, String) {
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir, home)
        .env("AUXESIS_API_PORT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let port = wait_for_api_port(&mut child, Duration::from_secs(10))
        .expect("the daemon announces its local API");
    let daemon = KillOnDrop::new(child);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let token = std::fs::read_to_string(auxd::api::token_path(home))
        .unwrap()
        .trim()
        .to_string();
    (daemon, addr, token)
}

fn wait_for_api_port(child: &mut Child, timeout: Duration) -> Option<u16> {
    let stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let Ok(line) = receiver.recv_timeout(Duration::from_millis(200)) else {
            continue;
        };
        if let Some(rest) = line.strip_prefix("auxd api on http://127.0.0.1:") {
            if let Ok(port) = rest.trim().parse::<u16>() {
                return Some(port);
            }
        }
    }
    None
}

/// A home with `mode` in its config and its store created.
fn home_with(mode: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), config(mode)).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    (dir, home)
}

#[test]
fn private_mode_stores_the_snapshot_encrypted_and_writes_no_plaintext() {
    let (dir, home) = home_with("private");
    // A plaintext copy from an older build is already on disk.
    std::fs::write(home.join("apple-eventkit.json"), snapshot_body()).unwrap();

    let (_daemon, addr, token) = start_daemon(dir.path(), &home);
    let response = post(
        addr,
        "/v1/apple-eventkit/snapshot",
        Some(&token),
        &snapshot_body(),
    );

    assert_eq!(response.status, 204, "body: {}", response.body);
    assert!(
        home.join("apple-eventkit.db").exists(),
        "the snapshot is stored"
    );
    assert!(
        !home.join("apple-eventkit.json").exists(),
        "no plaintext file"
    );
    for path in eventkit_files(&home) {
        let bytes = std::fs::read(&path).unwrap();
        assert!(!contains(&bytes, CANARY_TITLE), "{path:?} holds the title");
        assert!(!contains(&bytes, CANARY_PHONE), "{path:?} holds the phone");
    }
}

#[test]
fn open_mode_keeps_the_snapshot_encrypted_on_disk() {
    let (dir, home) = home_with("open");

    let (_daemon, addr, token) = start_daemon(dir.path(), &home);
    let response = post(
        addr,
        "/v1/apple-eventkit/snapshot",
        Some(&token),
        &snapshot_body(),
    );

    assert_eq!(response.status, 204, "body: {}", response.body);
    let files = eventkit_files(&home);
    assert!(!files.is_empty(), "the snapshot is stored");
    for path in files {
        let bytes = std::fs::read(&path).unwrap();
        assert!(!contains(&bytes, CANARY_TITLE), "{path:?} holds the title");
        assert!(!contains(&bytes, CANARY_PHONE), "{path:?} holds the phone");
    }
}

#[test]
fn a_private_start_removes_a_legacy_plaintext_snapshot() {
    let (dir, home) = home_with("private");
    std::fs::write(home.join("apple-eventkit.json"), snapshot_body()).unwrap();

    // The daemon announces its API only after its start-up sweep, so the file
    // is already gone when `start_daemon` returns.
    let (_daemon, _addr, _token) = start_daemon(dir.path(), &home);

    assert!(
        !home.join("apple-eventkit.json").exists(),
        "a legacy plaintext snapshot must not survive a private start"
    );
}

#[test]
fn an_open_to_private_switch_keeps_the_encrypted_snapshot() {
    let (dir, home) = home_with("open");
    let (_daemon, addr, token) = start_daemon(dir.path(), &home);
    let response = post(
        addr,
        "/v1/apple-eventkit/snapshot",
        Some(&token),
        &snapshot_body(),
    );
    assert_eq!(response.status, 204, "body: {}", response.body);
    assert!(
        home.join("apple-eventkit.db").exists(),
        "the snapshot is stored before the switch"
    );

    // The owner switches the home to private while the daemon runs.
    std::fs::write(config_path(&home), config("private")).unwrap();

    // Let several watch ticks pass: the encrypted snapshot must survive them.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        home.join("apple-eventkit.db").exists(),
        "the encrypted snapshot survives the switch to private: {:?}",
        eventkit_files(&home)
    );
    assert!(!home.join("apple-eventkit.json").exists());
}
