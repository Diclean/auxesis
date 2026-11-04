//! In Private mode a message sent with no thread id continues
//! the agent's current thread, as in Open mode. Turn 2 reaches the model with
//! turn 1's masked exchange, under the same session and the same tokens.

mod common;

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{ChatProvider, ChatRequest, ChatResponse, ProviderError};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::post;
use kernel_core::{config_path, store_path};
use serde_json::Value;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EMAIL: &str = "camille@exemple.test";

/// Answers every turn with one fixed line and keeps every request body.
#[derive(Default)]
struct Recorder {
    bodies: StdMutex<Vec<String>>,
}

#[async_trait]
impl ChatProvider for Recorder {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let body = serde_json::to_string(&request.messages).unwrap();
        self.bodies.lock().unwrap().push(body);
        Ok(ChatResponse::assistant("ok, i keep it in mind."))
    }

    fn name(&self) -> &str {
        "recorder"
    }
}

fn spawn(home: &std::path::Path, brain: &Arc<Recorder>) -> ApiHandle {
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::clone(brain) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(30)),
        ..ApiOptions::default()
    };
    api::spawn(home, options).unwrap()
}

fn send(handle: &ApiHandle, content: &str) -> i64 {
    let body = serde_json::json!({ "content": content }).to_string();
    let response = post(
        handle.addr(),
        "/v1/threads/aux/messages",
        Some(TOKEN),
        &body,
    );
    assert_eq!(response.status, 200, "{}", response.body);
    let json: Value = response.json();
    json["thread"]["id"].as_i64().unwrap()
}

/// The `⟦EMAIL_…⟧` token of `text`.
fn email_token(text: &str) -> String {
    let start = text
        .find("⟦EMAIL_")
        .unwrap_or_else(|| panic!("no token: {text}"));
    let end = start + text[start..].find('⟧').unwrap() + '⟧'.len_utf8();
    text[start..end].to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_private_second_message_without_a_thread_id_keeps_the_first_in_context() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"private\"\n";
    std::fs::write(config_path(&home), config).unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    let brain = Arc::new(Recorder::default());
    let handle = spawn(&home, &brain);

    let first = format!("My client is Camille Exemple, {EMAIL}.");
    let thread_1 = tokio::task::block_in_place(|| send(&handle, &first));
    let thread_2 = tokio::task::block_in_place(|| send(&handle, "What is her email again?"));
    assert_eq!(thread_1, thread_2, "turn 2 opened a new thread");

    let bodies = brain.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 2, "one model call per turn");
    let token = email_token(&bodies[0]);
    // Turn 2's exchange, past the system prompt.
    let second = &bodies[1][bodies[1].find("\"role\":\"user\"").unwrap_or(0)..];
    assert!(second.contains("My client is"), "turn 1 missing: {second}");
    assert!(second.contains("ok, i keep it in mind."), "{second}");
    assert!(
        second.contains(&token),
        "turn 2 re-minted the token: {second}"
    );
    for body in &bodies {
        assert!(!body.contains(EMAIL), "the value left the Mac: {body}");
    }

    // The store keeps the private exchange as the model read it, tokens and
    // all, and the token's value in the session's table.
    let store = Store::open(&store_path(&home)).unwrap();
    let stored = store.list_messages(thread_1).unwrap();
    assert_eq!(stored.len(), 4, "{stored:?}");
    assert!(stored[0].content.contains(&token), "{stored:?}");
    assert!(stored.iter().all(|row| !row.content.contains(EMAIL)));
    let pairs = store.session_tokens(thread_1).unwrap();
    assert!(pairs
        .iter()
        .any(|(t, v)| token.contains(t.as_str()) && v == EMAIL));

    // A pinned private turn (the iMessage gateway's throwaway session, deleted
    // after its turn) does not move the agent's current thread.
    let pinned = store
        .create_session_of_kind("aux", None, "chat")
        .unwrap()
        .id;
    let channel = handle.channel_access();
    tokio::task::block_in_place(|| channel.run_turn_quiet(pinned, "ping")).unwrap();
    store.delete_session(pinned).unwrap();
    let thread_4 = tokio::task::block_in_place(|| send(&handle, "And her company?"));
    assert_eq!(thread_4, thread_1, "a pinned turn moved the current thread");

    // A restart keeps the thread: the next message continues turn 1.
    drop(handle);
    let restarted = spawn(&home, &brain);
    let thread_3 = tokio::task::block_in_place(|| send(&restarted, "And her phone?"));
    assert_eq!(thread_3, thread_1, "a restart lost the private thread");
}
