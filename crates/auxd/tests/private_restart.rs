//! A private transcript across a real process restart: the real `auxd` binary is
//! spawned on a throwaway home, stopped, and spawned again on the same home.
//! A private thread is stored as the provider saw it, so the turn after the
//! restart re-sends the tokens, never a value the gate could no longer classify
//! (a password, a passport number), in text or in tool arguments; the owner's
//! page still shows the values.
//!
//! Sandbox only: temp home, loopback provider, fictional values.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{get, post, KillOnDrop};
use kernel_core::config_path;
use serde_json::Value;

const PASSWORD: &str = "velvet-cactus-lantern";
const PASSPORT: &str = "12AB3456";

/// A loopback OpenAI-compatible server that keeps every request body and
/// answers by request number: echo the owner's tokens, call `read_file` with
/// the passport's token in its path, close the call, then a plain line.
fn start_provider() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&bodies);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let body = read_body(&mut stream);
            let owner = last_owner_text(&body);
            let n = {
                let mut bodies = kept.lock().unwrap();
                bodies.push(body);
                bodies.len()
            };
            let message = match n {
                1 => {
                    serde_json::json!({"role": "assistant", "content": format!("Noted: {}", tokens_of(&owner).join(" "))})
                }
                2 => serde_json::json!({"role": "assistant", "content": "", "tool_calls": [{
                "id": "call_1", "type": "function", "function": {
                    "name": "read_file",
                    "arguments": serde_json::json!({ "path": format!("{}.txt", tokens_of(&owner).join("")) }).to_string(),
                }}]}),
                3 => serde_json::json!({"role": "assistant", "content": "Filed."}),
                _ => {
                    serde_json::json!({"role": "assistant", "content": "You told me your password first."})
                }
            };
            let json = serde_json::json!({ "choices": [{ "message": message }] }).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{json}",
                json.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (uri, bodies)
}

fn read_body(stream: &mut std::net::TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut data = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(split) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..split]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while data.len() < split + 4 + length {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => data.extend_from_slice(&chunk[..n]),
                }
            }
            return String::from_utf8_lossy(&data[split + 4..]).into_owned();
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return String::new(),
            Ok(n) => data.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The content of the last `user` message of a request body.
fn last_owner_text(body: &str) -> String {
    let json: Value = serde_json::from_str(body).unwrap_or_default();
    json["messages"]
        .as_array()
        .and_then(|messages| messages.iter().rev().find(|m| m["role"] == "user"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// Every distinct `⟦…⟧` token in `text`, in order.
fn tokens_of(text: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('⟦') {
        let Some(len) = rest[start..].find('⟧') else {
            break;
        };
        let end = start + len + '⟧'.len_utf8();
        if !tokens.iter().any(|t| t == &rest[start..end]) {
            tokens.push(rest[start..end].to_string());
        }
        rest = &rest[end..];
    }
    tokens
}

/// Spawn the real daemon on `home`; its address and API token.
fn start_daemon(dir: &Path, home: &Path) -> (KillOnDrop, SocketAddr, String) {
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir, home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let daemon = KillOnDrop::new(child);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = sender.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let port = loop {
        assert!(
            Instant::now() < deadline,
            "the daemon never announced its API"
        );
        let Ok(line) = receiver.recv_timeout(Duration::from_millis(200)) else {
            continue;
        };
        if let Some(rest) = line.strip_prefix("auxd api on http://127.0.0.1:") {
            break rest.trim().parse::<u16>().unwrap();
        }
    };
    let token = std::fs::read_to_string(auxd::api::token_path(home)).unwrap();
    (
        daemon,
        format!("127.0.0.1:{port}").parse().unwrap(),
        token.trim().to_string(),
    )
}

fn send(addr: SocketAddr, token: &str, content: &str) {
    let body = serde_json::json!({ "content": content }).to_string();
    let response = post(addr, "/v1/threads/main/messages", Some(token), &body);
    assert_eq!(response.status, 200, "{}", response.body);
}

fn home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    (dir, home)
}

#[test]
fn a_private_thread_resumed_by_a_new_process_resends_tokens_never_values() {
    let (uri, bodies) = start_provider();
    let (dir, home) = home();
    let config = format!(
        "version = 1\ndefault_agent = \"main\"\n\n[privacy]\nmode = \"private\"\n\n\
         [[providers]]\nid = \"local\"\nbase_url = \"{uri}/v1\"\nmodel = \"test-model\"\nkind = \"openai-compat\"\n\n[prices.models.\"test-model\"]\ninput_cents_per_million = 1\noutput_cents_per_million = 1\n"
    );
    std::fs::write(config_path(&home), config).unwrap();

    let (daemon, addr, token) = start_daemon(dir.path(), &home);
    send(addr, &token, &format!("my password is {PASSWORD}"));
    send(addr, &token, &format!("file my passport {PASSPORT} please"));
    drop(daemon);

    let (_daemon, addr, token) = start_daemon(dir.path(), &home);
    send(addr, &token, "What did I tell you first?");

    let bodies = bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 4, "echo, tool call, close, after restart");
    let secret = tokens_of(&last_owner_text(&bodies[0]));
    assert!(
        !secret.is_empty(),
        "the password was not tokenised: {}",
        bodies[0]
    );
    let id = tokens_of(&last_owner_text(&bodies[1]));
    assert!(
        !id.is_empty(),
        "the passport was not tokenised: {}",
        bodies[1]
    );
    // No value reaches the provider, before or after the restart.
    for body in &bodies {
        assert!(
            !body.contains(PASSWORD),
            "the password left the Mac: {body}"
        );
        assert!(
            !body.contains(PASSPORT),
            "the passport left the Mac: {body}"
        );
    }
    // The resumed thread is the one the model read: its answer and its tool
    // call come back with the same tokens.
    let resumed = &bodies[3];
    assert!(
        resumed.contains(&format!("Noted: {}", secret[0])),
        "{resumed}"
    );
    // The tool call's arguments keep the passport's token.
    let arguments = format!("{}.txt", id.join(""));
    let encoded = serde_json::to_string(&arguments).unwrap();
    let encoded = encoded.trim_matches('"');
    assert!(
        resumed.contains(encoded),
        "tool arguments changed: {resumed}"
    );

    // The owner's page shows the values, never a token.
    let page = get(addr, "/v1/threads/main/messages", Some(&token));
    assert_eq!(page.status, 200, "{}", page.body);
    let rows: Value = page.json();
    let shown: Vec<&str> = rows["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["content"].as_str())
        .collect();
    assert!(shown.iter().all(|text| !text.contains('⟦')), "{shown:?}");
    let owner_rows = shown.iter().filter(|text| text.contains(PASSWORD)).count();
    assert_eq!(
        owner_rows, 2,
        "the owner row and the echo show the value: {shown:?}"
    );
    assert!(
        shown.iter().any(|text| text.contains(PASSPORT)),
        "{shown:?}"
    );
}
