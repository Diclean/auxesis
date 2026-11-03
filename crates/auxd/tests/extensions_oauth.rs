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
