//! The local extension OAuth surface (E5), end to end on a temp home.
//!
//! A real auxd server on an ephemeral loopback port talks to a fake
//! authorization server on loopback (the test-only seam). The full
//! authorization-code + PKCE round trip runs, the token is stored in the
//! protected `.env`, and no API response ever carries it.

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use aux_runtime::extensions::install::{install, load_installed, InstallOptions};
use aux_runtime::extensions::mount::{network_pins, store_state, ExtensionState};
use aux_runtime::extensions::session::accept_current;
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{http, HttpResponse};
use kernel_core::{config_path, store_path};
use reqwest::Url;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EXTENSION: &str = "demo";
const ACCESS_CANARY: &str = "access-token-canary-7f3a";
const REFRESH_CANARY: &str = "refresh-token-canary-2b9c";

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    handle: Option<ApiHandle>,
}

impl TestApi {
    fn start(server: &MockServer) -> Self {
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
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
        install_oauth_entry(&home, server);
        let installed = load_installed(&home, EXTENSION).unwrap();
        store_state(
            &home,
            &ExtensionState {
                name: EXTENSION.to_string(),
                version: installed.version.clone(),
                kind: "mcp".to_string(),
                frozen: false,
                tools: Default::default(),
                network: network_pins(&installed.entry),
                secrets: installed.entry.secret_names(),
                oauth: installed.entry.oauth.clone(),
            },
        )
        .unwrap();
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            ..ApiOptions::default()
        };
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

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

fn install_oauth_entry(home: &std::path::Path, server: &MockServer) {
    let dir = home.join("extensions").join(format!("{EXTENSION}@1.0.0"));
    std::fs::create_dir_all(&dir).unwrap();
    let entry = format!(
        r#"name = "{EXTENSION}"
kind = "mcp"
version = "1.0.0"
licence = "MIT"
reviewed = true
sensitivity = "public"
summary_en = "demo"
summary_fr = "demo"
[source]
type = "binary"
package = "server"
sha256 = "{hash}"
[run]
transport = "stdio"
command = "server"
[[tools]]
name = "ping"
description = "Ping"
network = []
secrets = []
auth = "oauth2"
fs = []
[oauth]
authorization_url = "{uri}/authorize"
token_url = "{uri}/token"
client_id = "test-client"
scopes = ["read"]
"#,
        hash = "a".repeat(64),
        uri = server.uri(),
    );
    std::fs::write(dir.join("entry.toml"), entry).unwrap();
}

/// Send one real HTTP call off the runtime's worker so the server can answer
/// while the test thread waits.
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

/// Play the browser: hit the one-shot loopback callback with the code.
async fn hit_callback(authorize_url: &Url, state: &str) -> String {
    let redirect = authorize_url
        .query_pairs()
        .find(|(name, _)| name == "redirect_uri")
        .map(|(_, value)| value.into_owned())
        .expect("the authorization URL carries a redirect_uri");
    let redirect = Url::parse(&redirect).unwrap();
    let host = redirect.host_str().unwrap().to_owned();
    let port = redirect.port().unwrap();
    let target = format!(
        "{}?state={state}&code=the-authorization-code",
        redirect.path()
    );
    let mut stream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .unwrap();
    let request =
        format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

async fn status(api: &TestApi) -> HttpResponse {
    call(
        api.addr,
        "GET",
        &format!("/v1/extensions/{EXTENSION}/oauth/status"),
        Some(&api.token),
        None,
    )
    .await
}

async fn wait_connected(api: &TestApi) -> bool {
    for _ in 0..100 {
        if status(api).await.json()["connected"] == json!(true) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_full_flow_connects_stores_the_token_and_never_echoes_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=the-authorization-code"))
        .and(body_string_contains("code_verifier="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_CANARY,
            "refresh_token": REFRESH_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut api = TestApi::start(&server);

    let start = call(
        api.addr,
        "POST",
        &format!("/v1/extensions/{EXTENSION}/oauth/start"),
        Some(&api.token),
        Some("{}"),
    )
    .await;
    assert_eq!(start.status, 200, "body: {}", start.body);
    let authorize_url = Url::parse(start.json()["authorize_url"].as_str().unwrap()).unwrap();
    assert_eq!(
        authorize_url
            .query_pairs()
            .find(|(name, _)| name == "code_challenge_method")
            .map(|(_, value)| value.into_owned())
            .as_deref(),
        Some("S256")
    );
    let state = authorize_url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .unwrap();
    assert!(
        !start.body.contains("code_verifier"),
        "the response must not carry the PKCE verifier: {}",
        start.body
    );

    let callback = hit_callback(&authorize_url, &state).await;
    assert!(callback.contains("200 OK"), "{callback}");

    assert!(wait_connected(&api).await, "the flow did not finish");
    let connected = status(&api).await;
    assert_eq!(connected.status, 200);
    assert_eq!(connected.json()["connected"], json!(true));

    // The token lives in the protected file, nowhere in an API response.
    let env = std::fs::read_to_string(api.home.join(".env")).unwrap();
    assert!(
        env.contains("EXT_DEMO__OAUTH_TOKENS="),
        "the token was not stored: {env}"
    );
    assert!(env.contains(ACCESS_CANARY));
    assert!(env.contains(REFRESH_CANARY));
    for body in [&start.body, &connected.body, &callback] {
        assert!(
            !body.contains(ACCESS_CANARY) && !body.contains(REFRESH_CANARY),
            "a token leaked: {body}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(api.home.join(".env"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the token store must be 0600");
    }

    // Disconnect deletes the local authorization.
    let deleted = call(
        api.addr,
        "DELETE",
        &format!("/v1/extensions/{EXTENSION}/oauth"),
        Some(&api.token),
        None,
    )
    .await;
    assert_eq!(deleted.status, 200, "body: {}", deleted.body);
    assert_eq!(deleted.json()["connected"], json!(false));
    assert_eq!(status(&api).await.json()["connected"], json!(false));
    let env = std::fs::read_to_string(api.home.join(".env")).unwrap_or_default();
    assert!(
        !env.contains(ACCESS_CANARY) && !env.contains(REFRESH_CANARY),
        "disconnect left the token at rest: {env}"
    );

    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_oauth_routes_require_the_local_access_key() {
    let server = MockServer::start().await;
    let mut api = TestApi::start(&server);

    for (method, path) in [
        ("POST", format!("/v1/extensions/{EXTENSION}/oauth/start")),
        ("GET", format!("/v1/extensions/{EXTENSION}/oauth/status")),
        ("DELETE", format!("/v1/extensions/{EXTENSION}/oauth")),
    ] {
        let response = call(api.addr, method, &path, None, Some("{}")).await;
        assert_eq!(response.status, 401, "{method} {path}: {}", response.body);
    }

    api.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_extension_without_oauth_is_refused() {
    let server = MockServer::start().await;
    let mut api = TestApi::start(&server);
    let response = call(
        api.addr,
        "POST",
        "/v1/extensions/no-such-extension/oauth/start",
        Some(&api.token),
        Some("{}"),
    )
    .await;
    assert_eq!(response.status, 404, "body: {}", response.body);
    api.stop();
}

// The disconnect generation map is keyed by the raw URL id, so a name no
// install can carry must be refused before it touches the map. The 404
// matches the start route, and any valid name still revokes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_refuses_an_invalid_name_and_revokes_any_valid_one() {
    let server = MockServer::start().await;
    let mut api = TestApi::start(&server);

    let invalid = call(
        api.addr,
        "DELETE",
        "/v1/extensions/BAD..NAME/oauth",
        Some(&api.token),
        None,
    )
    .await;
    assert_eq!(invalid.status, 404, "body: {}", invalid.body);
    assert_eq!(invalid.json()["error"]["code"], "extension_not_found");

    // An installed name and an uninstalled one both revoke: the owner can
    // always take a token back.
    for name in [EXTENSION, "no-such-extension"] {
        let revoked = call(
            api.addr,
            "DELETE",
            &format!("/v1/extensions/{name}/oauth"),
            Some(&api.token),
            None,
        )
        .await;
        assert_eq!(revoked.status, 200, "{name}: {}", revoked.body);
        assert_eq!(revoked.json()["connected"], json!(false));
    }
    api.stop();
}

// A file-backed MCP fixture: real install, pin and accept, with no external service.
const MCP_FIXTURE: &str = r##"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      id=${line#*\"id\":}; id=${id%%,*}
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1.0.0"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      id=${line#*\"id\":}; id=${id%%,*}
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"ping","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
  esac
done
"##;
const MCP_FIXTURE_SHA256: &str = "5dcd732bf0b64d496b06b941cce72a2c077b5a95fb1d88633ec163dbc8077b66";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_refuses_unapproved_upgrades_before_reading_tokens_or_starting_a_flow() {
    const NAME: &str = "upgrade";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_CANARY, "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut api = TestApi::start(&server);
    let artifact = api.home.join("fixture-server");
    std::fs::write(&artifact, MCP_FIXTURE).unwrap();
    let mut entry = load_installed(&api.home, EXTENSION).unwrap().entry;
    entry.name = NAME.to_string();
    entry.source.package = artifact.to_string_lossy().into_owned();
    entry.source.sha256 = MCP_FIXTURE_SHA256.to_string();
    install(
        &api.home,
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: true,
        },
    )
    .await
    .expect("v1 installs and pins its MCP identity");
    let v1_pin = aux_runtime::extensions::mount::load_state(&api.home, NAME).unwrap();
    assert_eq!(v1_pin.version, "1.0.0");
    assert!(v1_pin.network.is_empty());

    entry.version = "2.0.0".to_string();
    entry.tools[0].network.push("new.example:443".to_string());
    install(
        &api.home,
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: false,
        },
    )
    .await
    .expect("v2 installs without changing the v1 pin");
    let start_path = format!("/v1/extensions/{NAME}/oauth/start");
    let status_path = format!("/v1/extensions/{NAME}/oauth/status");
    let disconnect_path = format!("/v1/extensions/{NAME}/oauth");
    // Revoking stays open for an unapproved upgrade; only the flow is gated.
    let revoked = call(api.addr, "DELETE", &disconnect_path, Some(&api.token), None).await;
    assert_eq!(
        revoked.status, 200,
        "revoke must stay open: {}",
        revoked.body
    );
    let local = call(api.addr, "GET", &status_path, Some(&api.token), None).await;
    assert_eq!(local.json()["connected"], json!(false), "{}", local.body);
    for (method, path) in [("POST", &start_path)] {
        let response = call(api.addr, method, path, Some(&api.token), None).await;
        // On old code, complete the returned flow so the fake records the unwanted request.
        if method == "POST" && response.status == 200 {
            let url = Url::parse(response.json()["authorize_url"].as_str().unwrap()).unwrap();
            let state = url
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1
                .into_owned();
            hit_callback(&url, &state).await;
        }
        assert_eq!(response.status, 409, "{method}: {}", response.body);
        assert_eq!(response.json()["error"]["code"], "approval_required");
    }

    // Isolate version, host, and secret mismatches from one another.
    let mut pin = v1_pin.clone();
    pin.network = network_pins(&entry);
    store_state(&api.home, &pin).unwrap();
    let response = call(api.addr, "POST", &start_path, Some(&api.token), None).await;
    assert_eq!(response.status, 409, "new version alone: {}", response.body);
    assert_eq!(response.json()["error"]["code"], "approval_required");
    pin.network.clear();
    pin.version = entry.version.clone();
    store_state(&api.home, &pin).unwrap();
    let response = call(api.addr, "POST", &start_path, Some(&api.token), None).await;
    assert_eq!(response.status, 409, "new host alone: {}", response.body);
    assert_eq!(response.json()["error"]["code"], "approval_required");
    pin.network = network_pins(&entry);
    store_state(&api.home, &pin).unwrap();
    entry.tools[0].secrets.push("EXT_UPGRADE__NEW".to_string());
    let entry_path = api.home.join("extensions/upgrade@2.0.0/entry.toml");
    std::fs::write(&entry_path, toml::to_string(&entry).unwrap()).unwrap();
    let response = call(api.addr, "POST", &start_path, Some(&api.token), None).await;
    assert_eq!(response.status, 409, "new secret alone: {}", response.body);
    assert_eq!(response.json()["error"]["code"], "approval_required");

    let state_path = api.home.join("extensions/state/upgrade.json");
    std::fs::remove_file(&state_path).unwrap();
    {
        let (method, path) = ("POST", &start_path);
        let response = call(api.addr, method, path, Some(&api.token), None).await;
        assert_eq!(
            response.status, 409,
            "missing pin {method}: {}",
            response.body
        );
        assert_eq!(response.json()["error"]["code"], "approval_required");
    }
    std::fs::write(&state_path, "invalid state").unwrap();
    let response = call(api.addr, "POST", &start_path, Some(&api.token), None).await;
    assert_eq!(response.status, 409, "unreadable pin: {}", response.body);
    assert_eq!(response.json()["error"]["code"], "approval_required");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "unapproved flow reached the fake endpoint"
    );
    assert!(
        !api.home.join(".env").exists(),
        "unapproved flow wrote a token"
    );

    // The real owner-accept path re-pins the installed v2 before OAuth proceeds.
    store_state(&api.home, &v1_pin).unwrap();
    accept_current(&api.home, NAME, true)
        .await
        .expect("accept v2");
    let response = call(api.addr, "POST", &start_path, Some(&api.token), None).await;
    assert_eq!(response.status, 200, "accepted flow: {}", response.body);
    let url = Url::parse(response.json()["authorize_url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    assert!(hit_callback(&url, &state).await.contains("200 OK"));
    // Status observes completion, ensuring the background flow finishes before teardown.
    let connected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = call(api.addr, "GET", &status_path, Some(&api.token), None).await;
            if status.json()["connected"] == json!(true) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(connected.is_ok(), "accepted flow did not store its token");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    api.stop();
}

fn flow_state(response: &HttpResponse) -> (Url, String) {
    let url = Url::parse(response.json()["authorize_url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .unwrap()
        .1
        .into_owned();
    (url, state)
}

// A flow started while approved must not exchange its code or save a
// token when the extension is upgraded, or disconnected, before the browser
// comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pending_flow_dies_on_upgrade_or_disconnect() {
    const NAME: &str = "racer";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_CANARY, "token_type": "Bearer"
        })))
        .expect(0)
        .mount(&server)
        .await;
    let mut api = TestApi::start(&server);

    let artifact = api.home.join("fixture-server");
    std::fs::write(&artifact, MCP_FIXTURE).unwrap();
    let mut entry = load_installed(&api.home, EXTENSION).unwrap().entry;
    entry.name = NAME.to_string();
    entry.source.package = artifact.to_string_lossy().into_owned();
    entry.source.sha256 = MCP_FIXTURE_SHA256.to_string();
    let opts = |pin| InstallOptions {
        allow_loopback: true,
        pin,
    };
    install(&api.home, &entry, &opts(true))
        .await
        .expect("v1 pinned");
    // Disconnect while the browser is open: the revoke is never undone.
    let start = format!("/v1/extensions/{NAME}/oauth/start");
    let started = call(api.addr, "POST", &start, Some(&api.token), None).await;
    assert_eq!(started.status, 200, "{}", started.body);
    let (url, state) = flow_state(&started);
    let gone = call(
        api.addr,
        "DELETE",
        &format!("/v1/extensions/{NAME}/oauth"),
        Some(&api.token),
        None,
    )
    .await;
    assert_eq!(gone.status, 200, "{}", gone.body);
    hit_callback(&url, &state).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Upgrade while the browser is open: no exchange, no token.
    let start = format!("/v1/extensions/{NAME}/oauth/start");
    let started = call(api.addr, "POST", &start, Some(&api.token), None).await;
    assert_eq!(started.status, 200, "{}", started.body);
    let (url, state) = flow_state(&started);
    entry.version = "2.0.0".to_string();
    entry.tools[0].network.push("new.example:443".to_string());
    install(&api.home, &entry, &opts(false))
        .await
        .expect("v2 unpinned");
    hit_callback(&url, &state).await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "a changed flow reached the token endpoint"
    );
    let status_path = format!("/v1/extensions/{NAME}/oauth/status");
    let status = call(api.addr, "GET", &status_path, Some(&api.token), None).await;
    assert_eq!(status.json()["connected"], json!(false), "{}", status.body);
    api.stop();
}

// WO EXT-OAUTH-ENDPOINT-PIN (#528): the pin covered the version, the tool
// network hosts and the secret names, but not `[oauth]`. A same-version
// reinstall that moves only the token URL must be refused before the
// authorization code (and a possible client secret) reaches the moved endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_same_version_oauth_endpoint_change_needs_approval_before_any_code_is_sent() {
    const NAME: &str = "moved";
    let approved = MockServer::start().await;
    let moved = MockServer::start().await;
    // The moved token endpoint must see nothing while the install is unapproved.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": ACCESS_CANARY, "token_type": "Bearer"
        })))
        .expect(0)
        .mount(&moved)
        .await;
    let mut api = TestApi::start(&approved);

    let artifact = api.home.join("fixture-server");
    std::fs::write(&artifact, MCP_FIXTURE).unwrap();
    let mut entry = load_installed(&api.home, EXTENSION).unwrap().entry;
    entry.name = NAME.to_string();
    entry.source.package = artifact.to_string_lossy().into_owned();
    entry.source.sha256 = MCP_FIXTURE_SHA256.to_string();
    let opts = |pin| InstallOptions {
        allow_loopback: true,
        pin,
    };
    install(&api.home, &entry, &opts(true))
        .await
        .expect("v1 installs and pins its OAuth table");
    let v1_pin = aux_runtime::extensions::mount::load_state(&api.home, NAME).unwrap();
    assert_eq!(
        v1_pin.oauth.as_ref().map(|oauth| oauth.token_url.clone()),
        Some(format!("{}/token", approved.uri())),
        "the install pin records the approved token URL"
    );

    // The same version and the same artefact: only `[oauth].token_url` moves.
    entry.oauth.as_mut().unwrap().token_url = format!("{}/token", moved.uri());
    install(&api.home, &entry, &opts(false))
        .await
        .expect("the same version reinstalls without touching the pin");

    let start_path = format!("/v1/extensions/{NAME}/oauth/start");
    let status_path = format!("/v1/extensions/{NAME}/oauth/status");
    let response = call(api.addr, "POST", &start_path, Some(&api.token), None).await;
    // On the old code the flow starts: complete it so the moved endpoint sees
    // the request this test forbids, instead of racing the assertion.
    if response.status == 200 {
        let (url, state) = flow_state(&response);
        hit_callback(&url, &state).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = call(api.addr, "GET", &status_path, Some(&api.token), None).await;
                if status.json()["connected"] == json!(true) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
    }
    assert_eq!(response.status, 409, "moved token URL: {}", response.body);
    assert_eq!(response.json()["error"]["code"], "approval_required");
    assert!(
        moved.received_requests().await.unwrap().is_empty(),
        "the authorization code reached the moved token endpoint"
    );

    // The owner's one-time accept records the current table; then it starts.
    accept_current(&api.home, NAME, true)
        .await
        .expect("accept the moved endpoint");
    let accepted = aux_runtime::extensions::mount::load_state(&api.home, NAME).unwrap();
    assert_eq!(
        accepted.oauth.as_ref().map(|oauth| oauth.token_url.clone()),
        Some(format!("{}/token", moved.uri()))
    );
    let response = call(api.addr, "POST", &start_path, Some(&api.token), None).await;
    assert_eq!(response.status, 200, "accepted start: {}", response.body);
    let _ = flow_state(&response);
    api.stop();
}
