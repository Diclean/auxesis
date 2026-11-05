//! TOOL-HANG acceptance: a Private turn whose model calls a tool never waits
//! on anything the owner cannot see or end.
//!
//! - A clean calendar turn runs its tool and answers. Once the calendar
//!   workspace is tainted (its first read) and the owner asks for its reads
//!   (an own read runs free after taint since READ-AFTER-TAINT), the next
//!   read waits on its card and on nothing else: answered, the turn ends.
//! - A chief turn that ends while its delegate waits (here the route's turn
//!   timeout) stops the agent's own turn: its card is retired and the
//!   delegation record is closed, not left "working".
//! - A channel turn, which no HTTP route wraps, ends at the turn timeout.
//!
//! A real server, a loopback OpenAI-compatible upstream (one streamed tool
//! call, then an answer), a mailbox never dialled. No network or real home.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use aux_store::{DelegationState, Store};
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{get, http_with_read_timeout, post};
use kernel_core::{config_path, store_path};
use serde_json::Value;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TURN_TIMEOUT: Duration = Duration::from_secs(4);
/// Far above the turn timeout: a wait that only ends here is the bug.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
const CALENDAR: &str = "apple_calendar_list_events";

/// One SSE answer: `delegate` when offered, else the calendar read, then text
/// once a tool result follows the owner's last message (a private thread keeps
/// the earlier turns in context).
fn answer(request: &str) -> String {
    let last_user = request.rfind("\"role\":\"user\"").unwrap_or(0);
    let events: Vec<String> = if request[last_user..].contains("\"role\":\"tool\"") {
        vec![r#"{"choices":[{"index":0,"delta":{"role":"assistant","content":"No events."},"finish_reason":"stop"}]}"#.into()]
    } else {
        let (name, args) = if request.contains("\"name\":\"delegate\"") {
            (
                "delegate",
                r#"{\"agent\":\"calendar\",\"task\":\"Count tomorrow's events.\"}"#,
            )
        } else {
            (CALENDAR, "{}")
        };
        vec![
            r#"{"choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"Use the tool."}}]}"#.into(),
            format!(
                r#"{{"choices":[{{"index":0,"delta":{{"tool_calls":[{{"index":0,"id":"call_1","type":"function","function":{{"name":"{name}","arguments":"{args}"}}}}]}},"finish_reason":"tool_calls"}}]}}"#
            ),
        ]
    };
    let mut body: String = events.iter().map(|e| format!("data: {e}\n\n")).collect();
    body.push_str("data: [DONE]\n\n");
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A loopback OpenAI-compatible upstream answering [`answer`].
fn upstream() -> String {
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
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if buf.len() >= head + 4 + len {
                    break;
                }
            }
            let _ = stream.write_all(answer(&String::from_utf8_lossy(&buf)).as_bytes());
        }
    });
    base
}

struct Rig {
    _dir: tempfile::TempDir,
    home: PathBuf,
    handle: ApiHandle,
}

/// A Private home whose default agent is `agent`, on the loopback brain.
fn rig(agent: &str) -> Rig {
    let base = upstream();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = format!(
        "version = 1\ndefault_agent = \"{agent}\"\n\n[privacy]\nmode = \"private\"\n\n\
         [[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"\n"
    );
    std::fs::write(config_path(&home), config).unwrap();
    // The agent the rig talks to exists, as if made from its template.
    std::fs::create_dir_all(home.join("agents").join(agent)).unwrap();
    aux_engine::config::load_or_create(&config_path(&home)).unwrap();
    let mail = "\n[connectors.mail]\n\n[[connectors.mail.accounts]]\nid = \"sim\"\n\
                email = \"owner@mailsim.test\"\n\n[connectors.mail.accounts.imap]\n\
                host = \"127.0.0.1\"\nport = 9\nsecurity = \"tls\"\n";
    let text = std::fs::read_to_string(config_path(&home)).unwrap() + mail;
    std::fs::write(config_path(&home), text).unwrap();
    let providers = format!(
        "[[provider]]\nid = \"deepseek\"\nkind = \"openai\"\nbase_url = \"{base}/v1\"\n\
         models = [\"deepseek-flash\"]\nkey = \"env:AUX_KEY_TOOL_HANG\"\n\n\
         [brain]\ndefault = \"deepseek/deepseek-flash\"\n"
    );
    std::fs::write(home.join("providers.toml"), providers).unwrap();
    std::fs::write(home.join(".env"), "AUX_KEY_TOOL_HANG=sk-fake-not-a-key\n").unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        approval_timeout: Some(APPROVAL_TIMEOUT),
        turn_timeout: Some(TURN_TIMEOUT),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    Rig {
        _dir: dir,
        home,
        handle,
    }
}

impl Rig {
    /// One app turn of `agent`: the status, the body and how long it took.
    fn send(&self, agent: &str, content: &str) -> (u16, Value, Duration) {
        let started = Instant::now();
        let response = http_with_read_timeout(
            self.handle.addr(),
            "POST",
            &format!("/v1/threads/{agent}/messages"),
            Some(TOKEN),
            Some(&serde_json::json!({ "content": content }).to_string()),
            APPROVAL_TIMEOUT * 2,
        );
        let body = serde_json::from_str(&response.body).unwrap_or(Value::Null);
        (response.status, body, started.elapsed())
    }

    fn approvals(&self) -> Vec<Value> {
        let response = get(self.handle.addr(), "/v1/approvals", Some(TOKEN));
        serde_json::from_str::<Vec<Value>>(&response.body).unwrap()
    }

    /// Wait up to `limit` for `done`.
    fn until(&self, limit: Duration, done: impl Fn(&Self) -> bool) -> bool {
        let started = Instant::now();
        while !done(self) && started.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(100));
        }
        done(self)
    }

    fn delegation_states(&self) -> Vec<DelegationState> {
        let store = Store::open(&store_path(&self.home)).unwrap();
        let rows = store.list_delegations(None).unwrap();
        rows.into_iter().map(|row| row.state).collect()
    }

    /// The calendar's first read: it runs, and taints the calendar workspace.
    /// Then the owner asks for its reads, so the next one waits on a card.
    fn taint_calendar(&self) {
        let (status, body, took) = self.send("calendar", "How many events do I have tomorrow?");
        assert_eq!(status, 200, "{body}");
        assert!(took < TURN_TIMEOUT, "a clean tool turn took {took:?}");
        assert!(body.to_string().contains("Access not granted"), "{body}");
        let rule =
            format!("\n[[rules]]\nagent = \"calendar\"\ntool = \"{CALENDAR}\"\naction = \"ask\"\n");
        let text = std::fs::read_to_string(config_path(&self.home)).unwrap() + &rule;
        std::fs::write(config_path(&self.home), text).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tool_turn_completes_and_a_tainted_read_waits_only_on_its_card() {
    let rig = rig("aux");
    tokio::task::block_in_place(|| {
        rig.taint_calendar();
        let addr = rig.handle.addr();
        let owner = std::thread::spawn(move || {
            let started = Instant::now();
            while started.elapsed() < TURN_TIMEOUT {
                let response = get(addr, "/v1/approvals", Some(TOKEN));
                let list: Vec<Value> = serde_json::from_str(&response.body).unwrap();
                if let Some(card) = list.first() {
                    let path = format!("/v1/approvals/{}", card["id"].as_str().unwrap());
                    let answer = post(addr, &path, Some(TOKEN), r#"{"decision":"allow_once"}"#);
                    return answer.status;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            0
        });
        let (status, body, took) = rig.send("calendar", "And the day after?");
        assert_eq!(
            owner.join().unwrap(),
            200,
            "the card was listed and answered"
        );
        assert_eq!(status, 200, "{body}");
        assert!(
            took < TURN_TIMEOUT,
            "an answered card still waited {took:?}"
        );
        assert!(body.to_string().contains("Access not granted"), "{body}");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_chief_turn_stops_its_delegate_and_closes_the_record() {
    let rig = rig("aux");
    tokio::task::block_in_place(|| {
        rig.taint_calendar();
        let (status, body, _) = rig.send("aux", "How many events do I have tomorrow?");
        assert_eq!(status, 504, "the chief's turn hit its timeout: {body}");
        assert!(
            rig.until(Duration::from_secs(5), |rig| rig.approvals().is_empty()),
            "the delegate's card outlived the chief's turn: {:?}",
            rig.approvals()
        );
        assert!(
            rig.until(Duration::from_secs(5), |rig| matches!(
                rig.delegation_states()[..],
                [DelegationState::Failed | DelegationState::Stopped]
            )),
            "the delegation stayed open: {:?}",
            rig.delegation_states()
        );
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_turn_ends_at_the_turn_timeout() {
    let rig = rig("calendar");
    tokio::task::block_in_place(|| {
        rig.taint_calendar();
        let session = Store::open(&store_path(&rig.home))
            .unwrap()
            .create_session_of_kind("calendar", Some("iMessage"), "chat")
            .unwrap();
        let started = Instant::now();
        let outcome = rig
            .handle
            .channel_access()
            .run_turn(session.id, "How many events tomorrow?");
        let took = started.elapsed();
        assert!(outcome.is_err(), "the unanswered card cannot be allowed");
        assert!(
            took < TURN_TIMEOUT + Duration::from_secs(5),
            "a channel turn waited {took:?}"
        );
        assert!(rig.approvals().is_empty(), "the card outlived its turn");
    });
}
