//! A Private conversation is kept in the local store, so the
//! owner's page shows it after a refresh and an API restart in one process (the
//! fresh-process restart is `private_restart.rs`).
//! What reaches the model is unchanged: tokens, never the value.

mod common;

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{ChatProvider, ChatRequest, ChatResponse, ProviderError};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{get, post};
use kernel_core::{config_path, store_path};
use serde_json::Value;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EMAIL: &str = "camille@exemple.test";

/// Echoes the email token of the last owner message, fails on `boom`, and
/// keeps every request body.
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
        if last.contains("boom") {
            return Err(ProviderError::Server {
                provider: "recorder".into(),
                status: 503,
            });
        }
        Ok(ChatResponse::assistant(match token_in(last) {
            Some(token) => format!("Noted, I will write to {token}."),
            None => "Here is what you said first.".to_string(),
        }))
    }

    fn name(&self) -> &str {
        "recorder"
    }
}

fn token_in(text: &str) -> Option<String> {
    let start = text.find("⟦EMAIL_")?;
    let end = start + text[start..].find('⟧')? + '⟧'.len_utf8();
    Some(text[start..end].to_string())
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

fn send(handle: &ApiHandle, content: &str) -> (u16, Value) {
    let body = serde_json::json!({ "content": content }).to_string();
    let response = post(
        handle.addr(),
        "/v1/threads/aux/messages",
        Some(TOKEN),
        &body,
    );
    (response.status, response.json())
}

/// `(role, content)` of every row of the page at `path`.
fn page(handle: &ApiHandle, path: &str) -> Vec<(String, String)> {
    let response = get(handle.addr(), path, Some(TOKEN));
    assert_eq!(response.status, 200, "{}", response.body);
    let json: Value = response.json();
    json["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let content = row["content"].as_str().unwrap().to_string();
            assert!(
                !content.contains('⟦'),
                "a marker reached the page: {content}"
            );
            (row["role"].as_str().unwrap().to_string(), content)
        })
        .collect()
}

fn write_mode(home: &std::path::Path, mode: &str) {
    let config = format!("version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"{mode}\"\n");
    std::fs::write(config_path(home), config).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_private_conversation_is_shown_after_a_refresh_and_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    write_mode(&home, "private");
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    let brain = Arc::new(Recorder::default());
    let handle = spawn(&home, &brain);

    let first = format!("My client is Camille Exemple, {EMAIL}.");
    let (status, json) = tokio::task::block_in_place(|| send(&handle, &first));
    assert_eq!(status, 200, "{json}");
    let thread = json["thread"]["id"].as_i64().unwrap();
    // The agent list's last activity and the activity feed leave the marked
    // chat out: they carry neither the token nor the
    // value. The transcript read below is the current session's, and it does
    // show the values to their owner.
    for path in ["/v1/agents", "/v1/activity"] {
        let response = tokio::task::block_in_place(|| get(handle.addr(), path, Some(TOKEN)));
        assert_eq!(response.status, 200, "{path}: {}", response.body);
        assert!(!response.body.contains('⟦'), "{path}: {}", response.body);
        assert!(!response.body.contains(EMAIL), "{path}: {}", response.body);
    }
    let (status, _) = tokio::task::block_in_place(|| send(&handle, "Thanks."));
    assert_eq!(status, 200);

    // A refresh: by agent and by session id, user and assistant rows, in clear.
    let by_agent = tokio::task::block_in_place(|| page(&handle, "/v1/threads/aux/messages"));
    let roles: Vec<&str> = by_agent.iter().map(|(role, _)| role.as_str()).collect();
    assert_eq!(
        roles,
        ["user", "assistant", "user", "assistant"],
        "{by_agent:?}"
    );
    assert!(by_agent[0].1.contains(EMAIL), "{by_agent:?}");
    assert!(
        by_agent[1].1.contains(EMAIL),
        "the answer is not rehydrated: {by_agent:?}"
    );
    // The numeric read of a marked session stays refused:
    // only the current session is exempt, and only for the agent-name read.
    let by_id = tokio::task::block_in_place(|| {
        get(
            handle.addr(),
            &format!("/v1/threads/{thread}/messages"),
            Some(TOKEN),
        )
    });
    assert_eq!(by_id.status, 404, "{}", by_id.body);

    // A turn that fails keeps its owner row and writes no half answer.
    let (status, _) = tokio::task::block_in_place(|| send(&handle, "boom"));
    assert_ne!(status, 200);
    let after_error = tokio::task::block_in_place(|| page(&handle, "/v1/threads/aux/messages"));
    assert_eq!(after_error.len(), 5, "{after_error:?}");
    assert_eq!(after_error[4], ("user".to_string(), "boom".to_string()));

    // A restart: the same rows, and the next message continues the thread with
    // turn 1 in its context, still masked.
    drop(handle);
    let restarted = spawn(&home, &brain);
    let again = tokio::task::block_in_place(|| page(&restarted, "/v1/threads/aux/messages"));
    assert_eq!(again, after_error, "a restart lost the conversation");
    let (status, json) =
        tokio::task::block_in_place(|| send(&restarted, "What did I ask you first?"));
    assert_eq!(status, 200, "{json}");
    assert_eq!(
        json["thread"]["id"].as_i64(),
        Some(thread),
        "a restart opened a new thread"
    );
    let bodies = brain.bodies.lock().unwrap().clone();
    let last = bodies.last().unwrap();
    assert!(
        last.contains("My client is"),
        "turn 1 missing after restart: {last}"
    );
    for body in &bodies {
        assert!(!body.contains(EMAIL), "the value left the Mac: {body}");
    }

    // Private to Open mid-thread: the same thread goes on; its private rows
    // are re-sent as the model first read them, tokens and all.
    write_mode(&home, "open");
    let (status, json) = tokio::task::block_in_place(|| send(&restarted, "And now?"));
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["thread"]["id"].as_i64(), Some(thread));
    let last = brain.bodies.lock().unwrap().last().unwrap().clone();
    assert!(last.contains("My client is"), "{last}");
    assert!(
        !last.contains(EMAIL),
        "a private value went out in open mode: {last}"
    );
    // Open mode adds its system row to a session that has none, as before.
    let open = tokio::task::block_in_place(|| page(&restarted, "/v1/threads/aux/messages"));
    let shown: Vec<_> = open.iter().filter(|(role, _)| role != "system").collect();
    assert_eq!(shown.len(), 9, "{open:?}");
    assert!(shown.iter().copied().take(5).eq(again.iter()), "{open:?}");
}
