//! NEW-CHAT-1: `POST /v1/threads/{agent}/new` starts a fresh chat session; the old one
//! stays stored, and in private mode nothing of it is restored or sent.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{ChatProvider, ChatRequest, ChatResponse, ProviderError};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{get, post};
use kernel_core::{config_path, store_path};
use serde_json::Value;
use tempfile::TempDir;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EMAIL: &str = "camille@exemple.test";

/// Echoes the email token of the last owner message and keeps every request body.
#[derive(Default)]
struct Recorder {
    bodies: StdMutex<Vec<String>>,
}

#[async_trait]
impl ChatProvider for Recorder {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let body = serde_json::to_string(&request.messages).unwrap();
        self.bodies.lock().unwrap().push(body.clone());
        let last = &body[body.rfind("\"role\":\"user\"").unwrap_or(0)..];
        Ok(ChatResponse::assistant(match email_token(last) {
            Some(token) => format!("Noted, I will write to {token}."),
            None => "ok.".to_string(),
        }))
    }

    fn name(&self) -> &str {
        "recorder"
    }
}

fn email_token(text: &str) -> Option<String> {
    let start = text.find("⟦EMAIL_")?;
    let end = start + text[start..].find('⟧')? + '⟧'.len_utf8();
    Some(text[start..end].to_string())
}

type Setup = (TempDir, PathBuf, Arc<Recorder>, ApiHandle);

fn setup(mode: &str) -> Setup {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = format!("version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"{mode}\"\n");
    std::fs::write(config_path(&home), config).unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    let brain = Arc::new(Recorder::default());
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::clone(&brain) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(30)),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    (dir, home, brain, handle)
}

/// One turn on `thread` (an agent's current one, or a session id): `(thread id, body)`.
fn send_to(handle: &ApiHandle, thread: &str, content: &str) -> (i64, Value) {
    let body = serde_json::json!({ "content": content }).to_string();
    let path = format!("/v1/threads/{thread}/messages");
    let response = post(handle.addr(), &path, Some(TOKEN), &body);
    assert_eq!(response.status, 200, "{}", response.body);
    let json: Value = response.json();
    (json["thread"]["id"].as_i64().unwrap(), json)
}

fn send(handle: &ApiHandle, content: &str) -> (i64, Value) {
    send_to(handle, "aux", content)
}

fn new_chat(handle: &ApiHandle) -> i64 {
    let response = post(handle.addr(), "/v1/threads/aux/new", Some(TOKEN), "");
    assert_eq!(response.status, 200, "{}", response.body);
    let json: Value = response.json();
    assert_eq!(json["agent"], "aux", "{json}");
    json["id"].as_i64().unwrap()
}

fn page(handle: &ApiHandle, thread: &str) -> Value {
    let path = format!("/v1/threads/{thread}/messages");
    let response = get(handle.addr(), &path, Some(TOKEN));
    assert_eq!(response.status, 200, "{}", response.body);
    response.json()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_starts_a_fresh_thread_and_keeps_the_old_one_stored() {
    let (_dir, home, _brain, handle) = setup("open");
    let (old, _) = tokio::task::block_in_place(|| send(&handle, "first question"));
    let (again, _) = tokio::task::block_in_place(|| send(&handle, "second question"));
    assert_eq!(old, again);

    let fresh = tokio::task::block_in_place(|| new_chat(&handle));
    assert_ne!(fresh, old);
    // `/new` twice reuses the empty session: one row, same id.
    let store = Store::open(&store_path(&home)).unwrap();
    let before = store.list_sessions().unwrap().len();
    assert_eq!(tokio::task::block_in_place(|| new_chat(&handle)), fresh);
    assert_eq!(store.list_sessions().unwrap().len(), before);
    // A late turn on the old session (CLI, card, iMessage) keeps the new one current.
    std::thread::sleep(Duration::from_millis(1100));
    tokio::task::block_in_place(|| send_to(&handle, &old.to_string(), "late"));
    // Before any turn the current thread is the new, empty one.
    let empty = tokio::task::block_in_place(|| page(&handle, "aux"));
    assert_eq!(empty["thread"]["id"].as_i64(), Some(fresh), "{empty}");
    assert_eq!(empty["messages"].as_array().unwrap().len(), 0, "{empty}");

    let (thread, _) = tokio::task::block_in_place(|| send(&handle, "third question"));
    assert_eq!(thread, fresh, "the turn did not land on the new thread");
    let json = tokio::task::block_in_place(|| page(&handle, "aux"));
    let shown = json["messages"].to_string();
    assert!(shown.contains("third question"), "{json}");
    // The check is about this thread's own conversation. The system prompt is
    // the engine's text (it names things like "the late invoices" as an
    // example of a vague request), not something written in this thread, so
    // it is not part of what the new thread must not show.
    let conversation = json["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["role"] != "system")
        .map(|row| row.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !conversation.contains("second question") && !conversation.contains("late"),
        "{json}"
    );

    // The old session is still there, readable by its id.
    let kept = store.list_messages(old).unwrap();
    let owner_rows = kept.iter().filter(|row| row.role == "user").count();
    assert_eq!(owner_rows, 3, "{kept:?}");
    let by_id = tokio::task::block_in_place(|| page(&handle, &old.to_string()));
    assert!(by_id.to_string().contains("second question"), "{by_id}");
    // An unknown session id has no thread to renew.
    let unknown = tokio::task::block_in_place(|| {
        post(handle.addr(), "/v1/threads/987654/new", Some(TOKEN), "")
    });
    assert_eq!(unknown.status, 404, "{}", unknown.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_restart_keeps_the_agents_open_chat_thread() {
    let (_dir, home, brain, handle) = setup("open");
    let (first_thread, _) = tokio::task::block_in_place(|| send(&handle, "first turn"));
    handle.shutdown();
    drop(handle);

    let restarted = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(brain as Arc<dyn ChatProvider>),
            approval_timeout: Some(Duration::from_secs(30)),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let (second_thread, _) = tokio::task::block_in_place(|| send(&restarted, "second turn"));

    assert_eq!(
        second_thread, first_thread,
        "restart forked the chat thread"
    );
    let messages = tokio::task::block_in_place(|| page(&restarted, "aux"));
    let contents = messages["messages"].to_string();
    assert!(contents.contains("first turn"), "{messages}");
    assert!(contents.contains("second turn"), "{messages}");
    assert_eq!(
        messages["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "user")
            .count(),
        2,
        "both turns must be in the current thread: {messages}"
    );
    restarted.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_private_token_of_the_old_session_never_restores_in_the_new_one() {
    let (_dir, home, brain, handle) = setup("private");
    let first = format!("My client is Camille Exemple, {EMAIL}.");
    let (old, _) = tokio::task::block_in_place(|| send(&handle, &first));
    let old_token = email_token(&brain.bodies.lock().unwrap()[0]).expect("turn 1 was tokenised");

    let fresh = tokio::task::block_in_place(|| new_chat(&handle));
    assert_ne!(fresh, old);
    // The owner pastes the old token into the new chat: it is plain text here.
    let pasted = format!("Write to {old_token} and to her again.");
    let (thread, json) = tokio::task::block_in_place(|| send(&handle, &pasted));
    assert_eq!(thread, fresh);
    let (_, plain) = tokio::task::block_in_place(|| send(&handle, "What is her email?"));

    let bodies = brain.bodies.lock().unwrap().clone();
    for body in &bodies[1..] {
        assert!(!body.contains(EMAIL), "old value sent: {body}");
        assert!(!body.contains("My client is"), "old turn sent: {body}");
    }
    for answer in [&json, &plain, &page(&handle, "aux")] {
        assert!(!answer.to_string().contains(EMAIL), "restored: {answer}");
    }
    let store = Store::open(&store_path(&home)).unwrap();
    let has_email = |id| {
        store
            .session_tokens(id)
            .unwrap()
            .iter()
            .any(|(_, v)| v == EMAIL)
    };
    assert!(!has_email(fresh), "copied table");
    assert!(has_email(old));
}
