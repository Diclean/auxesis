//! End-to-end test of the real `auxd` binary: it boots, announces the local
//! API on an ephemeral loopback port, serves the token-guarded API, and
//! shuts down cleanly on SIGTERM.
//!
//! No network, no Keychain: the sandbox home carries a fake provider and the
//! API port is `0` (ephemeral), so parallel tests never collide.

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use aux_store::Store;
use common::get;
use kernel_core::{config_path, store_path};

const CONFIG: &str = r#"
version = 1
default_agent = "main"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;

fn spawn_daemon(dir: &std::path::Path, home: &std::path::Path) -> Child {
    common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir, home)
        .env("AUXESIS_API_PORT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
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

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    None
}

#[test]
fn the_daemon_serves_the_api_and_stops_on_sigterm() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), CONFIG).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();

    let mut child = spawn_daemon(dir.path(), &home);
    let port = match wait_for_api_port(&mut child, Duration::from_secs(10)) {
        Some(port) => port,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon never announced the local API");
        }
    };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // The token file exists, is private, and authenticates /v1/health.
    let token_path = auxd::api::token_path(&home);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let token = std::fs::read_to_string(&token_path)
        .unwrap()
        .trim()
        .to_string();

    let unauthorized = get(addr, "/v1/health", None);
    assert_eq!(unauthorized.status, 401, "body: {}", unauthorized.body);
    assert_eq!(unauthorized.json()["error"]["code"], "unauthorized");

    let health = get(addr, "/v1/health", Some(&token));
    assert_eq!(health.status, 200, "body: {}", health.body);
    let health = health.json();
    assert_eq!(health["ok"], true);
    assert_eq!(health["pid"].as_u64().unwrap() as u32, child.id());

    // SIGTERM → clean exit.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let status = match wait_for_exit(&mut child, Duration::from_secs(5)) {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon did not exit after SIGTERM");
        }
    };
    assert!(status.success(), "SIGTERM exit status: {status}");
}
