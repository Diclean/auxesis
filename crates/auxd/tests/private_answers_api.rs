//! The in-memory Private-mode answers and their two routes.

mod common;

use std::path::{Path, PathBuf};

use auxd::api::{self, ApiHandle, ApiOptions, MAX_HELD};
use serde_json::Value;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn set_mode(home: &Path, mode: &str) {
    let config = format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n");
    std::fs::write(kernel_core::config_path(home), config).unwrap();
}

fn start() -> (tempfile::TempDir, PathBuf, ApiHandle) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    set_mode(&home, "private");
    std::fs::write(api::token_path(&home), TOKEN).unwrap();
    let options = ApiOptions {
        port: 0,
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    (dir, home, handle)
}

async fn call(handle: &ApiHandle, method: &str, path: &str, token: Option<&str>) -> (u16, Value) {
    let (addr, method, path) = (handle.addr(), method.to_string(), path.to_string());
    let token = token.map(str::to_string);
    let reply = tokio::task::spawn_blocking(move || {
        common::http(addr, &method, &path, token.as_deref(), None)
    })
    .await
    .unwrap();
    (
        reply.status,
        serde_json::from_str(&reply.body).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn answers_list_newest_first_cap_at_twenty_and_dismiss() {
    let (_dir, _home, handle) = start();
    let held = handle.channel_access().private_answers();
    for n in 0..MAX_HELD + 3 {
        held.hold(format!("answer {n}"));
    }
    let (status, list) = call(&handle, "GET", "/v1/private/answers", Some(TOKEN)).await;
    let items = list.as_array().unwrap();
    assert_eq!((status, items.len()), (200, MAX_HELD));
    assert_eq!(items[0]["answer"], format!("answer {}", MAX_HELD + 2));
    assert_eq!(items[MAX_HELD - 1]["answer"], "answer 3");
    let path = format!(
        "/v1/private/answers/{}/dismiss",
        items[0]["id"].as_str().unwrap()
    );
    assert_eq!(call(&handle, "POST", &path, Some(TOKEN)).await.0, 204);
    assert_eq!(call(&handle, "POST", &path, Some(TOKEN)).await.0, 404);
    assert_eq!(held.list().len(), MAX_HELD - 1);
}

#[tokio::test]
async fn an_unauthenticated_request_is_refused() {
    let (_dir, _home, handle) = start();
    handle
        .channel_access()
        .private_answers()
        .hold("secret".into());
    for token in [None, Some("wrong")] {
        let (status, body) = call(&handle, "GET", "/v1/private/answers", token).await;
        assert_eq!(status, 401, "{body}");
        assert!(!body.to_string().contains("secret"));
    }
}

#[tokio::test]
async fn leaving_private_mode_drops_the_answers_and_a_restart_starts_empty() {
    let (_dir, home, handle) = start();
    let held = handle.channel_access().private_answers();
    held.hold("answer".into());
    set_mode(&home, "open");
    let (_, list) = call(&handle, "GET", "/v1/private/answers", Some(TOKEN)).await;
    assert!(list.as_array().unwrap().is_empty() && held.list().is_empty());
    set_mode(&home, "private");
    let (_, list) = call(&handle, "GET", "/v1/private/answers", Some(TOKEN)).await;
    assert!(list.as_array().unwrap().is_empty(), "dropped, not migrated");

    held.hold("again".into());
    let (_dir2, _home2, restarted) = start();
    let (_, list) = call(&restarted, "GET", "/v1/private/answers", Some(TOKEN)).await;
    assert!(list.as_array().unwrap().is_empty());
}
