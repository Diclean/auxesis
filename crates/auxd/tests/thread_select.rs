//! `POST /v1/threads/{agent}/select` makes an existing chat session the
//! agent's current one; the choice survives a daemon restart; a bad target changes nothing.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{ChatProvider, ChatRequest, ChatResponse, ProviderError};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{get, post};
use kernel_core::{config_path, store_path};
use tempfile::TempDir;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fake;

#[async_trait]
impl ChatProvider for Fake {
    async fn complete(&self, _request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        Ok(ChatResponse::assistant("ok.".to_string()))
    }

    fn name(&self) -> &str {
        "fake"
    }
}

fn spawn(home: &std::path::Path) -> ApiHandle {
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::new(Fake) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(30)),
        ..ApiOptions::default()
    };
    api::spawn(home, options).unwrap()
}

fn send(handle: &ApiHandle, thread: &str, content: &str) -> i64 {
    let body = serde_json::json!({ "content": content }).to_string();
    let path = format!("/v1/threads/{thread}/messages");
    let response = post(handle.addr(), &path, Some(TOKEN), &body);
    assert_eq!(response.status, 200, "{}", response.body);
    response.json()["thread"]["id"].as_i64().unwrap()
}

fn new_chat(handle: &ApiHandle) -> i64 {
    let response = post(handle.addr(), "/v1/threads/aux/new", Some(TOKEN), "");
    assert_eq!(response.status, 200, "{}", response.body);
    response.json()["id"].as_i64().unwrap()
}

fn select(handle: &ApiHandle, agent: &str, session: &str) -> common::HttpResponse {
    let body = format!(r#"{{"session":"{session}"}}"#);
    let path = format!("/v1/threads/{agent}/select");
    post(handle.addr(), &path, Some(TOKEN), &body)
}

fn current(handle: &ApiHandle) -> i64 {
    let response = get(
        handle.addr(),
        "/v1/threads/aux/messages?limit=1",
        Some(TOKEN),
    );
    assert_eq!(response.status, 200, "{}", response.body);
    response.json()["thread"]["id"].as_i64().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn select_restores_an_older_session_and_survives_a_restart() {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        config_path(&home),
        "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    let handle = spawn(&home);

    // A: the owner's own chat. B: a test chat started after it, with its own message.
    let a = tokio::task::block_in_place(|| send(&handle, "aux", "owner question"));
    let b = tokio::task::block_in_place(|| {
        let b = new_chat(&handle);
        assert_eq!(send(&handle, "aux", "check question"), b);
        b
    });
    assert_ne!(a, b);
    assert_eq!(tokio::task::block_in_place(|| current(&handle)), b);

    let selected = tokio::task::block_in_place(|| select(&handle, "aux", &a.to_string()));
    assert_eq!(selected.status, 200, "{}", selected.body);
    assert_eq!(selected.json()["id"].as_i64(), Some(a));
    assert_eq!(tokio::task::block_in_place(|| current(&handle)), a);

    // Unknown session, another agent, a bad body: 404/400 and the current thread is unchanged.
    let missing = tokio::task::block_in_place(|| select(&handle, "aux", "987654"));
    assert_eq!(missing.status, 404, "{}", missing.body);
    let other_agent = tokio::task::block_in_place(|| select(&handle, "mail", &b.to_string()));
    assert_eq!(other_agent.status, 404, "{}", other_agent.body);
    let bad = tokio::task::block_in_place(|| {
        post(handle.addr(), "/v1/threads/aux/select", Some(TOKEN), "{}")
    });
    assert_eq!(bad.status, 400, "{}", bad.body);
    assert_eq!(tokio::task::block_in_place(|| current(&handle)), a);

    // A late turn on B does not steal the current thread back.
    std::thread::sleep(Duration::from_millis(1100));
    tokio::task::block_in_place(|| send(&handle, &b.to_string(), "late"));
    assert_eq!(tokio::task::block_in_place(|| current(&handle)), a);

    handle.shutdown();
    drop(handle);
    let restarted = spawn(&home);
    assert_eq!(tokio::task::block_in_place(|| current(&restarted)), a);
    // The next turn to the agent lands in the restored session.
    assert_eq!(
        tokio::task::block_in_place(|| send(&restarted, "aux", "back")),
        a
    );
    restarted.shutdown();
}

/// Aux's chats only, newest first, capped, titles only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conversations_are_aux_chats_newest_first_and_titles_only() {
    let dir = TempDir::new().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        config_path(&home),
        "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();
    let conn = aux_store::open_keyed(&store_path(&home)).unwrap();
    conn.execute_batch(
        "WITH RECURSIVE n(x) AS (SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<54)
         INSERT INTO sessions(id, agent, title, kind, updated_at)
           SELECT x+1, 'aux', 'conversation '||x, 'chat',
                  printf('2026-02-01 00:00:%02d', x) FROM n;
         UPDATE sessions SET title = 'Stored title' WHERE id = 54;
         UPDATE sessions SET title = NULL WHERE id = 55;
         INSERT INTO messages(session_id, role, content)
           SELECT id, 'system', 'You are Aux' FROM sessions WHERE agent = 'aux';
         INSERT INTO messages(session_id, role, content)
           SELECT id, 'user', CASE id
             WHEN 55 THEN '  Plan the Q4 workshop  \nwith the team'
             WHEN 54 THEN 'Second owner line'
             ELSE 'Question '||(id-1) END
           FROM sessions WHERE agent = 'aux';
         INSERT INTO sessions(id, agent, kind, updated_at) VALUES
           (56, 'mail', 'chat', '2026-03-01 00:00:00'),
           (57, 'aux', 'job', '2026-03-01 00:00:01'),
           (58, 'aux', 'imessage-private', '2026-03-01 00:00:02'),
           (59, 'aux', 'chat', '2026-03-01 00:00:03');
         INSERT INTO messages(session_id, role, content) VALUES
           (56, 'user', 'Mail body'), (57, 'user', 'job body'), (58, 'user', 'private body');",
    )
    .unwrap();
    drop(conn);

    let handle = spawn(&home);
    let response = get(handle.addr(), "/v1/conversations", Some(TOKEN));
    assert_eq!(response.status, 200, "{}", response.body);
    let body = response.json();
    let rows = body
        .as_array()
        .unwrap_or_else(|| panic!("expected an array: {body}"));
    assert_eq!(rows.len(), 50, "{body}");
    assert_eq!(
        rows[0]["title"], "Plan the Q4 workshop",
        "first owner line, newest first"
    );
    assert_eq!(rows[1]["title"], "Stored title");
    assert_eq!(rows[2]["title"], "conversation 52");
    let raw = body.to_string();
    for secret in [
        "with the team",
        "Second owner line",
        "Mail body",
        "job body",
        "private body",
    ] {
        assert!(!raw.contains(secret), "{secret} leaked: {raw}");
    }
    handle.shutdown();
}
