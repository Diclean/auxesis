//! In thinking mode DeepSeek refuses a request
//! whose assistant tool-call message lacks `reasoning_content` (HTTP 400),
//! even when the reasoning it streamed was empty (`""` in the first delta).
//! The reasoning, empty or not, goes back to the provider that produced it.
//!
//! A real server and a loopback DeepSeek double that answers like the real
//! one: one streamed tool call with an empty reasoning, then text once a tool
//! result is in the request, and the exact 400 when the rule is broken. The
//! turn is driven on the Mail agent's own thread (2 rounds) and through the
//! chief's `delegate` (the chief and the child each send a tool call back).
//! A mailbox never dialled. No network or real home.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use auxd::api::{self, ApiHandle, ApiOptions};
use common::http_with_read_timeout;
use kernel_core::config_path;
use serde_json::Value;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TURN_TIMEOUT: Duration = Duration::from_secs(20);
const ANSWER: &str = "You have 3 unread mails.";
const REJECTION: &str =
    "The `reasoning_content` in the thinking mode must be passed back to the API.";

/// True when an assistant message with tool calls has no `reasoning_content`
/// (absent or null): what DeepSeek refuses in thinking mode.
fn breaks_the_rule(body: &Value) -> bool {
    body["messages"].as_array().into_iter().flatten().any(|m| {
        m["role"] == "assistant"
            && m["tool_calls"].as_array().is_some_and(|c| !c.is_empty())
            && !m["reasoning_content"].is_string()
    })
}

/// One answer: the 400 when the rule is broken; text once a tool result is
/// in; else a tool call (`delegate` when offered, else `mail_list`) streamed
/// with an empty reasoning, as DeepSeek does on a short tool-call reply.
fn answer(body: &Value) -> (u16, String) {
    if breaks_the_rule(body) {
        let error = serde_json::json!({"error": {"message": REJECTION, "type": "invalid_request_error", "param": null, "code": "invalid_request_error"}});
        return (400, error.to_string());
    }
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let delta = if messages.last().is_some_and(|m| m["role"] == "tool") {
        serde_json::json!({"role": "assistant", "content": ANSWER})
    } else {
        let offered = |name: &str| {
            body["tools"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|t| t["function"]["name"] == name)
        };
        let (name, args) = if offered("delegate") {
            (
                "delegate",
                r#"{"agent":"mail","task":"Count the unread mails."}"#,
            )
        } else {
            ("mail_list", "{}")
        };
        serde_json::json!({"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
            "function": {"name": name, "arguments": args}}]})
    };
    let first = serde_json::json!({"choices": [{"index": 0,
        "delta": {"role": "assistant", "content": "", "reasoning_content": ""}}]});
    let last = serde_json::json!({"choices": [{"index": 0, "delta": delta,
        "finish_reason": "stop"}]});
    let body = format!("data: {first}\n\ndata: {last}\n\ndata: [DONE]\n\n");
    (200, body)
}

/// A loopback DeepSeek double; counts the requests and the 400s it sent.
struct DeepSeek {
    base: String,
    requests: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
}

fn deepseek() -> DeepSeek {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicUsize::new(0));
    let (seen, refused) = (Arc::clone(&requests), Arc::clone(&rejected));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            let mut head = 0;
            while let Ok(n @ 1..) = stream.read(&mut chunk) {
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf);
                let Some(end) = text.find("\r\n\r\n") else {
                    continue;
                };
                head = end + 4;
                let len = text[..end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= head + len {
                    break;
                }
            }
            seen.fetch_add(1, Ordering::SeqCst);
            let body = serde_json::from_slice(&buf[head.min(buf.len())..]).unwrap_or(Value::Null);
            let (status, text) = answer(&body);
            let kind = if status == 200 {
                "text/event-stream"
            } else {
                refused.fetch_add(1, Ordering::SeqCst);
                "application/json"
            };
            let reason = if status == 200 { "OK" } else { "Bad Request" };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\n\
                     connection: close\r\n\r\n{text}",
                    text.len()
                )
                .as_bytes(),
            );
        }
    });
    DeepSeek {
        base,
        requests,
        rejected,
    }
}

struct Rig {
    _dir: tempfile::TempDir,
    _home: PathBuf,
    handle: ApiHandle,
    deepseek: DeepSeek,
}

/// A home in `mode` whose every agent runs on the DeepSeek double.
fn rig(mode: &str) -> Rig {
    let deepseek = deepseek();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = format!(
        "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"{mode}\"\n\n\
         [[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"\n"
    );
    std::fs::write(config_path(&home), config).unwrap();
    kernel_core::Config::load_or_create(&config_path(&home)).unwrap();
    let mail = "\n[connectors.mail]\n\n[[connectors.mail.accounts]]\nid = \"sim\"\n\
                email = \"owner@mailsim.test\"\n\n[connectors.mail.accounts.imap]\n\
                host = \"127.0.0.1\"\nport = 9\nsecurity = \"tls\"\n";
    let text = std::fs::read_to_string(config_path(&home)).unwrap() + mail;
    std::fs::write(config_path(&home), text).unwrap();
    let providers = format!(
        "[[provider]]\nid = \"deepseek\"\nkind = \"openai\"\nbase_url = \"{}/v1\"\n\
         models = [\"deepseek-flash\"]\nkey = \"env:AUX_KEY_DSR\"\n\n\
         [brain]\ndefault = \"deepseek/deepseek-flash\"\n",
        deepseek.base
    );
    std::fs::write(home.join("providers.toml"), providers).unwrap();
    std::fs::write(home.join(".env"), "AUX_KEY_DSR=sk-fake-not-a-key\n").unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        approval_timeout: Some(TURN_TIMEOUT),
        turn_timeout: Some(TURN_TIMEOUT),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    Rig {
        _dir: dir,
        _home: home,
        handle,
        deepseek,
    }
}

impl Rig {
    /// One app turn of `agent`: the status and the body.
    fn send(&self, agent: &str, content: &str) -> (u16, Value) {
        let response = http_with_read_timeout(
            self.handle.addr(),
            "POST",
            &format!("/v1/threads/{agent}/messages"),
            Some(TOKEN),
            Some(&serde_json::json!({ "content": content }).to_string()),
            TURN_TIMEOUT * 2,
        );
        let body = serde_json::from_str(&response.body).unwrap_or(Value::Null);
        (response.status, body)
    }

    fn requests(&self) -> usize {
        self.deepseek.requests.load(Ordering::SeqCst)
    }

    fn rejected(&self) -> usize {
        self.deepseek.rejected.load(Ordering::SeqCst)
    }
}

fn a_tool_turn_sends_the_empty_reasoning_back(mode: &str) {
    let rig = rig(mode);
    let (status, body) = rig.send("mail", "How many unread mails do I have?");
    assert_eq!(rig.rejected(), 0, "DeepSeek refused a request: {body}");
    assert_eq!(status, 200, "{body}");
    assert!(body.to_string().contains(ANSWER), "{body}");
    assert_eq!(rig.requests(), 2, "one tool round, then the answer");
}

fn a_delegated_turn_sends_both_reasonings_back(mode: &str) {
    let rig = rig(mode);
    let (status, body) = rig.send("aux", "How many unread mails do I have?");
    assert_eq!(rig.rejected(), 0, "DeepSeek refused a request: {body}");
    assert_eq!(status, 200, "{body}");
    assert!(body.to_string().contains(ANSWER), "{body}");
    assert_eq!(
        rig.requests(),
        4,
        "the chief's two rounds around the child's two"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_a_tool_turn_sends_the_empty_reasoning_back() {
    tokio::task::block_in_place(|| a_tool_turn_sends_the_empty_reasoning_back("open"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_a_tool_turn_sends_the_empty_reasoning_back() {
    tokio::task::block_in_place(|| a_tool_turn_sends_the_empty_reasoning_back("private"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_a_delegated_turn_sends_both_reasonings_back() {
    tokio::task::block_in_place(|| a_delegated_turn_sends_both_reasonings_back("open"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_a_delegated_turn_sends_both_reasonings_back() {
    tokio::task::block_in_place(|| a_delegated_turn_sends_both_reasonings_back("private"));
}
