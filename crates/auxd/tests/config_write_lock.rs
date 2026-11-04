//! The one shared `config.toml` writer lock.
//!
//! `PUT /v1/settings` rewrites the whole file while `POST /v1/providers`
//! appends to it. Without a single lock over both read-modify-write
//! sequences, an atomic whole-file replacement silently erases a provider
//! created concurrently (and a concurrent append can erase the chosen UI
//! language). This test runs the two writers against one live daemon for
//! [`ITERATIONS`] rounds and asserts the final config still holds every
//! provider and the last language sent.
//!
//! Real server on an ephemeral loopback port, temp home, no network, no real
//! `~/.auxesis`.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::http;
use kernel_core::{config_path, store_path};
use serde_json::json;

/// The fixed 64-hex-char token the other `auxd` integration binaries use: the
/// daemon registers it with the exact-value scrubber once per process.
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Rounds per writer: enough to interleave the two read-modify-write windows
/// many times over.
const ITERATIONS: usize = 200;

/// A config with no provider and no `[ui]` section yet.
const BASE_CONFIG: &str = "version = 1\ndefault_agent = \"main\"\n";

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), BASE_CONFIG).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            ..ApiOptions::default()
        };
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
        let handle = api::spawn(&home, options).unwrap();
        let addr = handle.addr();
        Self {
            _dir: dir,
            home,
            addr,
            handle: Some(handle),
        }
    }
}

impl Drop for TestApi {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

async fn call(
    addr: SocketAddr,
    token: String,
    method: &'static str,
    path: &'static str,
    body: String,
) -> (u16, String) {
    tokio::task::spawn_blocking(move || {
        let response = http(addr, method, path, Some(&token), Some(&body));
        (response.status, response.body)
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_settings_and_provider_writes_never_lose_each_other() {
    let t = TestApi::start().await;
    let addr = t.addr;

    let settings = tokio::spawn({
        let token = TEST_TOKEN.to_string();
        async move {
            for index in 0..ITERATIONS {
                let language = if index % 2 == 0 { "en" } else { "fr" };
                let body = json!({ "language": language }).to_string();
                let (status, response) =
                    call(addr, token.clone(), "PUT", "/v1/settings", body).await;
                assert_eq!(status, 200, "settings round {index}: {response}");
            }
        }
    });

    let providers = tokio::spawn({
        let token = TEST_TOKEN.to_string();
        async move {
            for index in 0..ITERATIONS {
                let name = format!("p{index:03}");
                let body = json!({
                    "name": name,
                    "kind": "openai_compat",
                    "base_url": "https://api.example.com/v1",
                    "model": "m",
                })
                .to_string();
                let (status, response) =
                    call(addr, token.clone(), "POST", "/v1/providers", body).await;
                assert_eq!(status, 201, "provider {name}: {response}");
            }
        }
    });

    settings.await.unwrap();
    providers.await.unwrap();

    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    let parsed: toml::Value = toml::from_str(&config).unwrap();
    let providers = parsed
        .get("providers")
        .and_then(toml::Value::as_array)
        .expect("the config must keep a [[providers]] array");
    assert_eq!(
        providers.len(),
        ITERATIONS,
        "the atomic settings rewrite erased provider entries"
    );
    for index in 0..ITERATIONS {
        let id = format!("p{index:03}");
        assert!(
            providers
                .iter()
                .any(|entry| entry.get("id").and_then(toml::Value::as_str) == Some(id.as_str())),
            "provider {id} was erased: {config}"
        );
    }
    assert_eq!(
        parsed
            .get("ui")
            .and_then(|ui| ui.get("language"))
            .and_then(toml::Value::as_str),
        Some("fr"),
        "the last chosen UI language was erased: {config}"
    );
}
