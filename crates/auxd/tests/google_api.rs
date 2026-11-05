//! The owner's Google connection surface (G4), end to end on a temp home.
//!
//! Real server on an ephemeral loopback port, no network: the connect route is
//! only asked about the *already connected* case, which must never open a
//! browser. The status flag carries a boolean and nothing else.
//!
//! Every test runs with a temp home and `AUXESIS_SANDBOX=1` (set by
//! the private ops repo), and none of them reaches Google.

// The Google connect routes exist only with the `google` feature.
#![cfg(feature = "google")]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{http, HttpResponse};
use kernel_core::{config_path, store_path};
use serde_json::json;

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CLIENT_ID: &str = "desktop-client-id.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "client-secret-canary";
const EMAIL: &str = "alex@example.test";

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    handle: Option<ApiHandle>,
}

impl TestApi {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(
            config_path(&home),
            "version = 1\ndefault_agent = \"main\"\n",
        )
        .unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        std::fs::write(
            home.join(".env"),
            format!(
                "AUXESIS_GOOGLE_CLIENT_ID={CLIENT_ID}\nAUXESIS_GOOGLE_CLIENT_SECRET={CLIENT_SECRET}\n"
            ),
        )
        .unwrap();
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
            token: TEST_TOKEN.to_string(),
            handle: Some(handle),
        }
    }

    /// Pretend the consent flow already stored the grant for `client_id`.
    fn connect(&self, client_id: &str, scopes: &[&str]) {
        let key = aux_google::mac_account_key(client_id);
        let path = self.home.join(format!("google-auth-{key}.json"));
        std::fs::write(
            &path,
            serde_json::json!({
                "version": 1,
                "account_hash": key,
                "refresh_token": "test-refresh-token",
                "scopes": scopes,
            })
            .to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

/// One HTTP call, off the runtime's worker so the server can answer while the
/// test thread waits.
async fn call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> HttpResponse {
    let method = method.to_string();
    let path = path.to_string();
    let token = token.map(str::to_string);
    let body = body.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        http(addr, &method, &path, token.as_deref(), body.as_deref())
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_reports_google_connected_only_when_a_grant_exists_and_never_leaks_a_secret() {
    let mut api = TestApi::start();

    let health = call(api.addr, "GET", "/v1/health", Some(&api.token), None).await;
    assert_eq!(health.status, 200, "body: {}", health.body);
    assert_eq!(health.json()["google_connected"], json!(false));
    assert_eq!(health.json()["google_reconnect_needed"], json!(false));

    api.connect(CLIENT_ID, &["gmail_readonly", "calendar_events_readonly"]);
    let health = call(api.addr, "GET", "/v1/health", Some(&api.token), None).await;
    assert_eq!(health.json()["google_connected"], json!(true));
    assert_eq!(health.json()["google_reconnect_needed"], json!(true));
    for canary in [
        CLIENT_ID,
        CLIENT_SECRET,
        EMAIL,
        "apps.googleusercontent.com",
    ] {
        assert!(
            !health.body.contains(canary),
            "the status response leaked `{canary}`: {}",
            health.body
        );
    }

    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_for_another_client_id_reads_as_disconnected() {
    let mut api = TestApi::start();
    api.connect(
        "another-client-id.apps.googleusercontent.com",
        &[
            "gmail_readonly",
            "calendar_events_readonly",
            "gmail_compose",
        ],
    );

    let health = call(api.addr, "GET", "/v1/health", Some(&api.token), None).await;
    assert_eq!(health.json()["google_connected"], json!(false));

    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_is_a_no_op_when_google_is_already_connected() {
    let mut api = TestApi::start();
    api.connect(
        CLIENT_ID,
        &[
            "gmail_readonly",
            "calendar_events_readonly",
            "gmail_compose",
        ],
    );

    // The one path that must never open a browser: nothing to do.
    let response = call(
        api.addr,
        "POST",
        "/v1/google/connect",
        Some(&api.token),
        Some("{}"),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(response.json()["connected"], json!(true));
    assert_eq!(response.json()["started"], json!(false));
    assert!(!response.body.contains(CLIENT_SECRET));

    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_is_a_no_op_when_the_grant_already_has_every_permission() {
    let mut api = TestApi::start();
    api.connect(
        CLIENT_ID,
        &[
            "gmail_readonly",
            "calendar_events_readonly",
            "gmail_compose",
        ],
    );
    let response = call(
        api.addr,
        "POST",
        "/v1/google/reconnect",
        Some(&api.token),
        Some("{}"),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(response.json()["connected"], json!(true));
    assert_eq!(response.json()["started"], json!(false));
    assert!(!response.body.contains(CLIENT_SECRET));
    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_without_a_grant_is_an_honest_no_op() {
    let mut api = TestApi::start();

    let response = call(
        api.addr,
        "POST",
        "/v1/google/disconnect",
        Some(&api.token),
        Some("{}"),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(response.json()["connected"], json!(false));
    assert_eq!(response.json()["started"], json!(false));

    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_google_routes_require_the_local_access_key() {
    let mut api = TestApi::start();
    for path in [
        "/v1/google/connect",
        "/v1/google/reconnect",
        "/v1/google/disconnect",
    ] {
        let response = call(api.addr, "POST", path, None, Some("{}")).await;
        assert_eq!(response.status, 401, "{path}: {}", response.body);
    }
    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_settings_route_updates_the_background_language() {
    let mut api = TestApi::start();
    let response = call(
        api.addr,
        "PUT",
        "/v1/settings",
        Some(&api.token),
        Some(r#"{"language":"fr"}"#),
    )
    .await;
    assert_eq!(response.status, 200, "body: {}", response.body);
    assert_eq!(response.json()["language"], "fr");
    let config = aux_engine::config::load_or_create(&config_path(&api.home)).unwrap();
    assert_eq!(config.ui.language, kernel_core::Lang::Fr);

    let unauthenticated = call(
        api.addr,
        "PUT",
        "/v1/settings",
        None,
        Some(r#"{"language":"en"}"#),
    )
    .await;
    assert_eq!(unauthenticated.status, 401);

    // The error codes the app switches on are stable, whatever the language.
    let invalid_language = call(
        api.addr,
        "PUT",
        "/v1/settings",
        Some(&api.token),
        Some(r#"{"language":"de"}"#),
    )
    .await;
    assert_eq!(
        invalid_language.status, 400,
        "body: {}",
        invalid_language.body
    );
    assert_eq!(invalid_language.json()["error"]["code"], "invalid_language");

    let invalid_settings = call(
        api.addr,
        "PUT",
        "/v1/settings",
        Some(&api.token),
        Some(r#"{"nope":true}"#),
    )
    .await;
    assert_eq!(
        invalid_settings.status, 400,
        "body: {}",
        invalid_settings.body
    );
    assert_eq!(invalid_settings.json()["error"]["code"], "invalid_settings");
    api.stop();
}
