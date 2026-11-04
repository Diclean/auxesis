//! TURN2-HANG: a chief turn queued behind a running turn of the same thread
//! never parks silently.
//!
//! - Turn 1 delegates to Clients, whose call waits on a card nobody answers:
//!   turn 2 runs beside it and answers at once, and the card still waits
//!   (CARD-NEVER-BLOCKS). Before TURN2-HANG it parked on the thread lock until
//!   turn 1 ended; before CARD-NEVER-BLOCKS it failed `409 thread_busy`.
//! - Turn 1 is slow but healthy (no card): turn 2 waits for it and answers.
//!
//! A real server and a loopback OpenAI-compatible upstream; no network or
//! real home.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use auxd::api::{self, ApiHandle, ApiOptions};
use common::{get, http_with_read_timeout, post};
use kernel_core::config_path;
use serde_json::Value;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TURN_TIMEOUT: Duration = Duration::from_secs(20);
/// A slow but healthy brain answer; stands in for a long owner turn.
const SLOW: Duration = Duration::from_secs(4);

fn sse(event: String) -> String {
    let body = format!("data: {event}\n\ndata: [DONE]\n\n");
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The chief delegates when the owner's message names clients; the Clients
/// agent calls `forget` (always a card); a tool result or anything else is
/// answered in text.
fn answer(request: &str) -> String {
    let body = request.find("\r\n\r\n").map_or("", |at| &request[at + 4..]);
    let value: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let last = value["messages"].as_array().and_then(|m| m.last()).cloned();
    let last = last.unwrap_or(Value::Null);
    let asks_clients = last["content"]
        .as_str()
        .is_some_and(|t| t.contains("clients"));
    let call = |name: &str, args: &str| {
        sse(format!(
            r#"{{"choices":[{{"index":0,"delta":{{"role":"assistant","tool_calls":[{{"index":0,"id":"call_1","type":"function","function":{{"name":"{name}","arguments":"{args}"}}}}]}},"finish_reason":"tool_calls"}}]}}"#
        ))
    };
    if last["role"] == "tool" {
        sse(r#"{"choices":[{"index":0,"delta":{"role":"assistant","content":"Done."},"finish_reason":"stop"}]}"#.into())
    } else if request.contains("\"name\":\"delegate\"") && asks_clients {
        call(
            "delegate",
            r#"{\"agent\":\"clients\",\"task\":\"List the owner's clients.\"}"#,
        )
    } else if request.contains("\"name\":\"crm_list\"") {
        call("forget", "{}")
    } else {
        sse(r#"{"choices":[{"index":0,"delta":{"role":"assistant","content":"No tool."},"finish_reason":"stop"}]}"#.into())
    }
}

/// A loopback upstream answering [`answer`]. A request whose text says
/// "slowly" is signalled on `slow`, then answered after [`SLOW`].
fn upstream(slow: mpsc::Sender<()>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            while let Ok(n @ 1..) = stream.read(&mut chunk) {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf);
                let Some(head) = text.find("\r\n\r\n") else {
                    continue;
                };
                let len = text[..head]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= head + 4 + len {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf);
            if request.contains("slowly") {
                let _ = slow.send(());
                std::thread::sleep(SLOW);
            }
            let _ = stream.write_all(answer(&request).as_bytes());
        }
    });
    base
}

struct Rig {
    _dir: tempfile::TempDir,
    handle: ApiHandle,
}

/// An open-mode home on the loopback brain; `slow` hears each slow request.
fn rig(slow: mpsc::Sender<()>) -> Rig {
    let base = upstream(slow);
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"open\"\n";
    std::fs::write(config_path(&home), config).unwrap();
    aux_engine::config::load_or_create(&config_path(&home)).unwrap();
    let providers = format!(
        "[[provider]]\nid = \"deepseek\"\nkind = \"openai\"\nbase_url = \"{base}/v1\"\n\
         models = [\"deepseek-flash\"]\nkey = \"env:AUX_KEY_TURN2\"\n\n\
         [brain]\ndefault = \"deepseek/deepseek-flash\"\n"
    );
    std::fs::write(home.join("providers.toml"), providers).unwrap();
    std::fs::write(home.join(".env"), "AUX_KEY_TURN2=sk-fake-not-a-key\n").unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        approval_timeout: Some(Duration::from_secs(60)),
        turn_timeout: Some(TURN_TIMEOUT),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    Rig { _dir: dir, handle }
}

impl Rig {
    fn send(&self, content: &str) -> (u16, Value, Duration) {
        let started = Instant::now();
        let body = serde_json::json!({ "content": content }).to_string();
        let addr = self.handle.addr();
        let path = "/v1/threads/aux/messages";
        let response = http_with_read_timeout(
            addr,
            "POST",
            path,
            Some(TOKEN),
            Some(&body),
            TURN_TIMEOUT * 2,
        );
        let body = serde_json::from_str(&response.body).unwrap_or(Value::Null);
        (response.status, body, started.elapsed())
    }

    /// The first card listed within [`TURN_TIMEOUT`].
    fn card(&self) -> Option<Value> {
        let started = Instant::now();
        while started.elapsed() < TURN_TIMEOUT {
            let response = get(self.handle.addr(), "/v1/approvals", Some(TOKEN));
            let cards = serde_json::from_str::<Vec<Value>>(&response.body).unwrap_or_default();
            if let Some(card) = cards.into_iter().next() {
                return Some(card);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// Send `first` in the background after a "Hello" opened the thread.
    fn start(
        self: &Arc<Self>,
        first: &'static str,
    ) -> std::thread::JoinHandle<(u16, Value, Duration)> {
        let (status, body, _) = self.send("Hello");
        assert_eq!(status, 200, "{body}");
        let rig = Arc::clone(self);
        std::thread::spawn(move || rig.send(first))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turn_sent_while_a_delegate_waits_on_its_card_answers_at_once() {
    tokio::task::block_in_place(|| {
        let rig = Arc::new(rig(mpsc::channel().0));
        let first = rig.start("List my clients");
        let pending = rig.card().expect("the delegate's call waits on a card");
        assert_eq!(pending["agent"], "clients", "{pending}");
        let (status, body, took) = rig.send("Thanks, and what's the weather like?");
        assert!(
            took < Duration::from_secs(3),
            "turn 2 waited {took:?} behind turn 1's card: {status} {body}"
        );
        assert_eq!(status, 200, "{body}");
        assert!(body.to_string().contains("No tool."), "{body}");
        let id = rig.card().expect("turn 1's card is untouched")["id"]
            .as_str()
            .unwrap()
            .to_string();
        let path = format!("/v1/approvals/{id}");
        post(
            rig.handle.addr(),
            &path,
            Some(TOKEN),
            r#"{"decision":"deny"}"#,
        );
        let (status, body, _) = first.join().unwrap();
        assert_eq!(status, 200, "turn 1 ends once its card is answered: {body}");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turn_sent_while_a_slow_turn_works_waits_and_answers() {
    tokio::task::block_in_place(|| {
        let (slow, reached) = mpsc::channel();
        let rig = Arc::new(rig(slow));
        let first = rig.start("Think slowly about my week");
        reached
            .recv_timeout(TURN_TIMEOUT)
            .expect("turn 1 reaches its brain");
        let (status, body, took) = rig.send("And tomorrow?");
        assert_eq!(status, 200, "turn 2 after {took:?}: {body}");
        assert!(
            took >= SLOW / 2,
            "turn 2 did not queue behind turn 1: {took:?}"
        );
        let (status, body, _) = first.join().unwrap();
        assert_eq!(status, 200, "turn 1: {body}");
    });
}
