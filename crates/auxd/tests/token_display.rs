//! TOKEN-DISPLAY acceptance: a token minted while masking a TOOL RESULT is shown
//! to the owner as its real value on every display, never as `⟦…⟧`.
//!
//! A real API server on loopback, the fictional demo mailbox (`aux-fakemail`),
//! and a scripted brain that lists the mail, then answers with the first token
//! of the result. It records every body: they hold tokens, never the value.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_fakemail::{serve, write_demo, SimConfig};
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{get, post};
use kernel_core::{config_path, store_path};
use serde_json::Value;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OPEN: char = '⟦';
const CLOSE: char = '⟧';

const IBAN: &str = "FR7630006000011234567890189";

/// The first `⟦<kind>…⟧` reference of `text`.
fn first_token(text: &str, kind: &str) -> Option<String> {
    let start = text.find(&format!("{OPEN}{kind}"))?;
    let end = start + text[start..].find(CLOSE)? + CLOSE.len_utf8();
    Some(text[start..end].to_string())
}

/// Lists the mail, then names the newest sender and address with the tool
/// result's first tokens (Open: in clear), and repeats a token of the owner's
/// last message. Keeps every request body and every answer it gave.
#[derive(Default)]
struct EchoToolToken {
    bodies: StdMutex<Vec<String>>,
    echoed: StdMutex<Vec<String>>,
}

#[async_trait]
impl ChatProvider for EchoToolToken {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let body = serde_json::to_string(&request.messages).unwrap();
        self.bodies.lock().unwrap().push(body);
        let text_of = |role| -> Vec<String> {
            let of_role = request.messages.iter().filter(|m| m.role() == role);
            of_role.map(|m| m.content().as_str().to_string()).collect()
        };
        let tool_text = text_of(aux_providers::ChatRole::Tool).concat();
        if tool_text.is_empty() {
            return Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new("call_1", "mail_list", serde_json::json!({}))],
            )));
        }
        let from = tool_text.split("from: ").nth(1).unwrap_or_default();
        let (name, address) = from.split_once(" <").unwrap_or_default();
        let person = first_token(&tool_text, "PERSON_").unwrap_or(name.to_string());
        let email = first_token(&tool_text, "EMAIL_");
        let email = email.unwrap_or(address.split('>').next().unwrap().to_string());
        let mut answer = format!("Your newest mail is from {person} <{email}>.");
        let last_user = text_of(aux_providers::ChatRole::User)
            .pop()
            .unwrap_or_default();
        if let Some(token) = first_token(&last_user, "") {
            answer.push_str(&format!(" Noted {token}."));
        }
        self.echoed.lock().unwrap().push(answer.clone());
        Ok(ChatResponse::assistant(answer))
    }

    fn name(&self) -> &str {
        "echo-tool-token"
    }
}

/// The demo mailbox on its own runtime, alive for the test process.
fn start_mailbox(dir: &Path) -> (u16, PathBuf) {
    let sim_dir = dir.join("sim");
    std::fs::create_dir_all(&sim_dir).unwrap();
    write_demo(&sim_dir, false).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let server = runtime
            .block_on(serve(SimConfig {
                dir: sim_dir,
                imap_port: 0,
                smtp_port: 0,
            }))
            .unwrap();
        tx.send((server.imap_port, server.ca_file.clone())).unwrap();
        loop {
            std::thread::park();
        }
    });
    rx.recv_timeout(Duration::from_secs(30)).unwrap()
}

struct Rig {
    dir: tempfile::TempDir,
    home: PathBuf,
    brain: Arc<EchoToolToken>,
    handle: ApiHandle,
}

impl Rig {
    fn start(mode: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let (port, ca_file) = start_mailbox(dir.path());
        std::fs::write(
            config_path(&home),
            format!(
                "version = 1\ndefault_agent = \"main\"\n\n[privacy]\nmode = \"{mode}\"\n\n\
                 [ui]\nlanguage = \"en\"\n\n\
                 [connectors.mail]\n\n[[connectors.mail.accounts]]\nid = \"mailsim\"\n\
                 email = \"owner@mailsim.test\"\n\n[connectors.mail.accounts.imap]\n\
                 host = \"127.0.0.1\"\nport = {port}\nsecurity = \"tls\"\nca_file = \"{}\"\n\n\
                 [[rules]]\ndot = \"main\"\ntool = \"mail_list\"\naction = \"allow\"\n",
                ca_file.display()
            ),
        )
        .unwrap();
        let env = home.join(".env");
        std::fs::write(&env, "AUX_MAIL_MAILSIM=fictional-password\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
        let agent = home.join("agents/main");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(agent.join("agent.toml"), "tools = [\"mail_list\"]\n").unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        let brain = Arc::new(EchoToolToken::default());
        let handle = api::spawn(
            &home,
            ApiOptions {
                port: 0,
                event_poll: Duration::from_millis(25),
                provider: Some(Arc::clone(&brain) as Arc<dyn ChatProvider>),
                approval_timeout: Some(Duration::from_secs(30)),
                ..ApiOptions::default()
            },
        )
        .unwrap();
        Self {
            dir,
            home,
            brain,
            handle,
        }
    }

    /// The sender name and address the shown answer names, each checked to be
    /// a real value of the fictional mailbox, never a token or the marker.
    fn shown_value(&self, shown: &str) -> (String, String) {
        assert!(!shown.contains(OPEN), "a raw token was shown: {shown}");
        assert!(!shown.contains("[name hidden]"), "token lost: {shown}");
        let rest = shown.split("Your newest mail is from ").nth(1);
        let rest = rest.unwrap_or_else(|| panic!("not the scripted answer: {shown}"));
        let (name, address) = if let Some((name, rest)) = rest.rsplit_once(" [") {
            let (address, suffix) = rest.split_once("](mailto:[hidden]).").unwrap();
            assert!(
                suffix.is_empty() || suffix.starts_with(" Noted "),
                "unexpected text after e-mail: {shown}"
            );
            (name, address)
        } else {
            let (name, rest) = rest.split_once(" <").unwrap();
            (name, rest.split_once(">.").unwrap().0)
        };
        let mailbox = std::fs::read_to_string(self.dir.path().join("sim/mailbox.json"));
        let mailbox = mailbox.unwrap();
        for value in [name, address] {
            assert!(mailbox.contains(value), "{value:?} is not a mailbox value");
        }
        (name.to_string(), address.to_string())
    }

    /// A chat session for the owner's Messages thread.
    fn imessage_session(&self) -> i64 {
        let store = Store::open(&store_path(&self.home)).unwrap();
        let session = store.create_session_of_kind("main", Some("iMessage"), "chat");
        session.unwrap().id
    }

    /// Every body the brain got holds tokens, never `value`.
    fn assert_masked_outbound(&self, value: &str) {
        let bodies = self.brain.bodies.lock().unwrap();
        assert!(bodies.len() >= 2, "two rounds per turn");
        for body in bodies.iter() {
            assert!(!body.contains(value), "{value:?} left the Mac: {body}");
        }
        // The model's own reference goes back to it whole, never `⟦⟦` (literal text).
        assert!(bodies.iter().any(|body| body.contains(OPEN)));
        assert!(!bodies.iter().any(|body| body.contains("⟦⟦")));
    }
}

/// The last assistant text of a channel turn: what the daemon replies or holds.
fn last_answer(record: &api::TurnRecord) -> String {
    let mut answers = record
        .messages
        .iter()
        .rev()
        .filter(|m| m.role == "assistant");
    answers.next().unwrap().content.clone()
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The app's live feed, `/v1/events`.
async fn events(rig: &Rig) -> Ws {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{}/v1/events", rig.handle.addr())
        .into_client_request()
        .unwrap();
    let bearer = format!("Bearer {TOKEN}").parse().unwrap();
    request.headers_mut().insert("authorization", bearer);
    tokio_tungstenite::connect_async(request).await.unwrap().0
}

/// Every text frame until `message.done` (or five quiet seconds), one per line.
async fn feed(ws: &mut Ws) -> String {
    use futures_util::StreamExt;
    let mut feed = String::new();
    while !feed.contains("\"message.done\"") {
        let next = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
        let Ok(Some(Ok(message))) = next else { break };
        feed.push_str(message.to_text().unwrap_or(""));
        feed.push('\n');
    }
    feed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_owner_display_shows_the_value_of_a_token_from_a_tool_result() {
    let rig = Rig::start("private");
    let addr = rig.handle.addr();
    let mut ws = events(&rig).await;
    let send = |content: &str| {
        let body = serde_json::json!({ "content": content }).to_string();
        let response = tokio::task::block_in_place(|| {
            post(addr, "/v1/threads/main/messages", Some(TOKEN), &body)
        });
        assert_eq!(response.status, 200, "{}", response.body);
        let json: Value = response.json();
        json
    };
    let answer_of = |body: &Value| {
        let last = body["messages"].as_array().unwrap().last().unwrap();
        last["content"].as_str().unwrap().to_string()
    };

    // The app: the turn's answer, then the live feed it streamed. The owner's
    // IBAN is a token on the way out and shown back as written.
    let body = send(&format!("Who sent my newest mail? I pay them on {IBAN}."));
    let answer = answer_of(&body);
    let (name, address) = rig.shown_value(&answer);
    assert!(answer.ends_with(&format!(" Noted {IBAN}.")), "{answer}");
    let feed = feed(&mut ws).await;
    assert!(feed.contains("message.done"), "{feed}");
    assert!(!feed.contains(OPEN), "a raw token on the live feed: {feed}");
    assert!(feed.contains(&answer), "{feed}");

    // The thread snapshot the app reloads.
    let page = tokio::task::block_in_place(|| {
        get(addr, "/v1/threads/main/messages?limit=50", Some(TOKEN))
    });
    assert!(!page.body.contains(OPEN), "{}", page.body);

    // `aux chat`, single shot and REPL: the model's answer through the session's table.
    let thread = body["thread"]["id"].as_i64().unwrap();
    let raw = rig.brain.echoed.lock().unwrap()[0].clone();
    assert_eq!(auxd::privacy_wiring::rehydrate_local(thread, &raw), answer);

    // A second turn of the same session resends the repaired answer as history:
    // the model gets its own tokens back, never values and never `⟦⟦`.
    let channel = rig.handle.channel_access();
    let again = tokio::task::block_in_place(|| channel.run_turn(thread, "And before?")).unwrap();
    let shown = auxd::privacy_wiring::rehydrate_local(thread, &last_answer(&again));
    assert_eq!(rig.shown_value(&shown), (name.clone(), address.clone()));
    let history = rig.brain.bodies.lock().unwrap().last().unwrap().clone();
    let resent = serde_json::to_string(&raw).unwrap();
    assert!(history.contains(resent.trim_matches('"')), "{history}");

    // A Private text over Messages: answered quietly, held for the app (C12).
    let session = rig.imessage_session();
    let record =
        tokio::task::block_in_place(|| channel.run_turn_quiet(session, "Who wrote last?")).unwrap();
    let held = channel.private_answers();
    held.hold_local(&rig.home, session, &last_answer(&record));
    let held = tokio::task::block_in_place(|| get(addr, "/v1/private/answers", Some(TOKEN)));
    let held: Value = held.json();
    rig.shown_value(held[0]["answer"].as_str().unwrap());

    // Nothing that leaves the Mac or stays at rest holds a value. A name is no
    // hidden value.
    let store = Store::open(&store_path(&rig.home)).unwrap();
    for value in [address.as_str(), IBAN] {
        rig.assert_masked_outbound(value);
        for id in [thread, session] {
            let rows = store.list_messages(id).unwrap();
            assert!(rows.iter().all(|row| !row.content.contains(value)));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_text_over_messages_is_answered_with_no_token() {
    let rig = Rig::start("open");
    let (channel, session) = (rig.handle.channel_access(), rig.imessage_session());
    let record =
        tokio::task::block_in_place(|| channel.run_turn(session, "Who wrote last?")).unwrap();
    // This text is what the daemon sends back over Messages in Open mode.
    rig.shown_value(&last_answer(&record));
}
