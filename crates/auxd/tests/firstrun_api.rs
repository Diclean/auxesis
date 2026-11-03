//! End-to-end tests of the in-app provider setup + first-run flow (gap 2).
//!
//! Real server on an ephemeral loopback port, temp homes, the deterministic
//! fake provider — no network, no real `~/.auxesis`, no real Keychain. The
//! key lookups here resolve through the home's `.env` with accounts that do
//! not exist in the Keychain.

mod common;

use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// A fixed 64-hex-char API token shared by every test API in this binary.
const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The canary key value that must never appear outside `<home>/.env`.
///
/// Hyphenated on purpose: it is not shaped like a real vendor key, so the
/// repo's secret scanner does not flag this synthetic fixture.
const CANARY_KEY: &str = "sk-canary-firstrun-0123456789abcdef";

use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions};
use common::{assert_error, http, HttpResponse};
use kernel_core::{config_path, store_path};
use serde_json::json;

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    handle: Option<ApiHandle>,
}

impl TestApi {
    async fn start() -> Self {
        Self::start_with_config("version = 1\ndefault_agent = \"main\"\n").await
    }

    async fn start_with_config(config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), config).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            ..ApiOptions::default()
        };
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
        let handle = api::spawn(&home, options).unwrap();
        let addr = handle.addr();
        let token = std::fs::read_to_string(api::token_path(&home))
            .unwrap()
            .trim()
            .to_string();
        Self {
            _dir: dir,
            home,
            addr,
            token,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown();
        }
    }
}

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

async fn call_auth(t: &TestApi, method: &str, path: &str, body: Option<&str>) -> HttpResponse {
    call(t.addr, method, path, Some(&t.token), body).await
}

async fn get_auth(t: &TestApi, path: &str) -> HttpResponse {
    call_auth(t, "GET", path, None).await
}

async fn post_auth(t: &TestApi, path: &str, body: &str) -> HttpResponse {
    call_auth(t, "POST", path, Some(body)).await
}

async fn put_auth(t: &TestApi, path: &str, body: &str) -> HttpResponse {
    call_auth(t, "PUT", path, Some(body)).await
}

/// Payloads of every journal row of `kind`, oldest first.
fn event_payloads(home: &Path, kind: &str) -> Vec<String> {
    let conn = aux_store::open_keyed_readonly(&store_path(home)).unwrap();
    let mut stmt = conn
        .prepare("SELECT payload FROM events WHERE kind = ?1 ORDER BY id")
        .unwrap();
    stmt.query_map([kind], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// Every regular file under `root` whose bytes contain `needle`.
fn files_containing(root: &Path, needle: &str) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() {
                if let Ok(mut file) = std::fs::File::open(&path) {
                    let mut bytes = Vec::new();
                    if file.read_to_end(&mut bytes).is_ok()
                        && String::from_utf8_lossy(&bytes).contains(needle)
                    {
                        hits.push(path);
                    }
                }
            }
        }
    }
    hits
}

fn provider_body(name: &str, base_url: &str, model: &str, key: Option<&str>) -> String {
    json!({
        "name": name,
        "kind": "openai_compat",
        "base_url": base_url,
        "model": model,
        "api_key": key,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// provider save: the secret path
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_save_stores_the_key_only_in_dotenv_and_never_echoes_it() {
    let mut t = TestApi::start().await;
    let saved = post_auth(
        &t,
        "/v1/providers",
        &provider_body(
            "acme",
            "https://api.example.com/v1",
            "acme-1",
            Some(CANARY_KEY),
        ),
    )
    .await;
    assert_eq!(saved.status, 201, "body: {}", saved.body);
    assert!(
        !saved.body.contains(CANARY_KEY),
        "the key must never be echoed: {}",
        saved.body
    );
    let value = saved.json();
    assert_eq!(value["name"], "acme");
    assert_eq!(value["key_present"], true);

    // The non-secret part is in config.toml; the key is not.
    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert!(config.contains("[[providers]]"), "{config}");
    assert!(config.contains("id = \"acme\""), "{config}");
    assert!(config.contains("key_user = \"acme\""), "{config}");
    assert!(!config.contains(CANARY_KEY), "key in config.toml: {config}");

    // The secret is in `<home>/.env`, private and whole.
    let env_path = t.home.join(".env");
    let env = std::fs::read_to_string(&env_path).unwrap();
    assert!(env.contains(&format!("AUX_KEY_ACME={CANARY_KEY}")), "{env}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the .env must be 0600");
    }

    // Grep the whole home: only `.env` may carry the key.
    let hits = files_containing(&t.home, CANARY_KEY);
    assert_eq!(
        hits,
        vec![env_path.clone()],
        "unexpected key locations: {hits:?}"
    );

    // No audit row carries it either.
    for kind in ["provider.created", "provider.tested"] {
        for payload in event_payloads(&t.home, kind) {
            assert!(!payload.contains(CANARY_KEY), "{kind}: {payload}");
        }
    }
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_provider_saves_are_atomic_and_lose_nothing() {
    let mut t = TestApi::start().await;
    let bodies: Vec<String> = (0..8)
        .map(|index| {
            let name = format!("svc{index}");
            let key = format!("sk-canary-firstrun-concurrent-{index}-0123456789");
            provider_body(
                &name,
                &format!("https://api{index}.example.com/v1"),
                "m",
                Some(&key),
            )
        })
        .collect();
    let futures: Vec<_> = bodies
        .iter()
        .map(|body| post_auth(&t, "/v1/providers", body))
        .collect();
    let responses = futures_util::future::join_all(futures).await;
    for (index, response) in responses.iter().enumerate() {
        assert_eq!(response.status, 201, "svc{index}: {}", response.body);
    }

    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert_eq!(config.matches("[[providers]]").count(), 8, "{config}");
    for index in 0..8 {
        assert!(
            config.contains(&format!("id = \"svc{index}\"")),
            "missing svc{index}: {config}"
        );
    }

    let env = std::fs::read_to_string(t.home.join(".env")).unwrap();
    for index in 0..8 {
        let line = format!("AUX_KEY_SVC{index}=");
        assert_eq!(
            env.matches(&line).count(),
            1,
            "{line} must appear exactly once: {env}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(t.home.join(".env"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    t.stop();
}

// ---------------------------------------------------------------------------
// provider key update: the "exists but has no key" dead end
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_key_update_stores_a_late_key_for_an_existing_service() {
    let config = r#"
version = 1
default_agent = "main"

[[providers]]
id = "latekey"
base_url = "http://127.0.0.1:9/v1"
model = "late-model"
key_user = "latekey"
kind = "openai-compat"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;
    let mut t = TestApi::start_with_config(config).await;

    // The service exists but has no key: the app can paste one now.
    let listed = get_auth(&t, "/v1/providers").await.json();
    let entry = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["id"] == "latekey")
        .unwrap();
    assert_eq!(entry["key_present"], false);
    assert_eq!(entry["key_required"], true);
    // The list returns the id as the app's lookup handle, not a placeholder.
    let handle = entry["id"].as_str().expect("the provider id");
    assert_eq!(handle, "latekey");

    let updated = put_auth(
        &t,
        "/v1/providers/latekey/key",
        &json!({ "api_key": CANARY_KEY }).to_string(),
    )
    .await;
    assert_eq!(updated.status, 200, "body: {}", updated.body);
    assert!(
        !updated.body.contains(CANARY_KEY),
        "the key must never be echoed: {}",
        updated.body
    );
    let value = updated.json();
    assert_eq!(value["name"], "latekey");
    assert_eq!(value["key_present"], true);

    // The key is in `.env` (0600) and nowhere else; config.toml is untouched.
    let env_path = t.home.join(".env");
    let env = std::fs::read_to_string(&env_path).unwrap();
    assert!(
        env.contains(&format!("AUX_KEY_LATEKEY={CANARY_KEY}")),
        "{env}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the .env must be 0600");
    }
    let hits = files_containing(&t.home, CANARY_KEY);
    assert_eq!(
        hits,
        vec![env_path.clone()],
        "unexpected key locations: {hits:?}"
    );
    let config_after = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert_eq!(
        config_after.matches("[[providers]]").count(),
        2,
        "{config_after}"
    );
    assert!(!config_after.contains(CANARY_KEY), "{config_after}");

    // The stored key now resolves without an inline key, so the test succeeds.
    let tested = post_auth(&t, &format!("/v1/providers/{handle}/test"), "{}").await;
    assert_eq!(tested.status, 200, "body: {}", tested.body);
    let tested = tested.json();
    assert_eq!(tested["key_present"], true);
    assert_eq!(tested["reason"], "ok");
    assert_eq!(event_payloads(&t.home, "provider.key_updated").len(), 1);

    // Unknown provider: clean 404. A keyless kind refuses the key. Neither
    // echoes the secret.
    let ghost = put_auth(
        &t,
        "/v1/providers/ghost/key",
        &json!({ "api_key": CANARY_KEY }).to_string(),
    )
    .await;
    assert_error(&ghost, 404, "provider_not_found");
    assert!(!ghost.body.contains(CANARY_KEY), "{}", ghost.body);

    let fake_key = put_auth(
        &t,
        "/v1/providers/fakey/key",
        &json!({ "api_key": CANARY_KEY }).to_string(),
    )
    .await;
    assert_error(&fake_key, 400, "key_not_allowed");
    assert!(!fake_key.body.contains(CANARY_KEY), "{}", fake_key.body);

    let blank = put_auth(
        &t,
        "/v1/providers/latekey/key",
        &json!({ "api_key": "   " }).to_string(),
    )
    .await;
    assert_error(&blank, 400, "missing_key");
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_key_update_refuses_a_key_slot_collision() {
    let config = r#"
version = 1
default_agent = "main"

[[providers]]
id = "Acme"
base_url = "https://api.example.com/v1"
model = "m"
kind = "openai-compat"

[[providers]]
id = "acme"
base_url = "https://api.example.com/v1"
model = "m"
kind = "openai-compat"
"#;
    let mut t = TestApi::start_with_config(config).await;

    let refused = put_auth(
        &t,
        "/v1/providers/acme/key",
        &json!({ "api_key": CANARY_KEY }).to_string(),
    )
    .await;
    assert_error(&refused, 409, "provider_key_conflict");
    assert!(
        !refused.body.contains(CANARY_KEY),
        "the key must not leak: {}",
        refused.body
    );
    assert!(
        !t.home.join(".env").exists(),
        "a refused key write must leave no orphan .env"
    );
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_and_invalid_inputs_are_rejected() {
    let mut t = TestApi::start().await;
    let first = post_auth(
        &t,
        "/v1/providers",
        &provider_body("acme", "https://api.example.com/v1", "acme-1", None),
    )
    .await;
    assert_eq!(first.status, 201, "body: {}", first.body);

    let duplicate = post_auth(
        &t,
        "/v1/providers",
        &provider_body("acme", "https://api.example.com/v1", "acme-1", None),
    )
    .await;
    assert_error(&duplicate, 409, "provider_exists");

    let bad_name = post_auth(
        &t,
        "/v1/providers",
        &provider_body("../escape", "https://api.example.com/v1", "m", None),
    )
    .await;
    assert_error(&bad_name, 400, "invalid_name");

    let cleartext = post_auth(
        &t,
        "/v1/providers",
        &provider_body("bad", "http://api.example.com/v1", "m", None),
    )
    .await;
    assert_error(&cleartext, 400, "invalid_provider");

    let private = post_auth(
        &t,
        "/v1/providers",
        &provider_body("priv", "https://10.1.2.3/v1", "m", None),
    )
    .await;
    assert_error(&private, 400, "invalid_provider");

    let bad_kind = post_auth(
        &t,
        "/v1/providers",
        &json!({
            "name": "grpc",
            "kind": "grpc",
            "base_url": "https://api.example.com/v1",
            "model": "m",
        })
        .to_string(),
    )
    .await;
    assert_error(&bad_kind, 400, "invalid_kind");

    let missing_name = post_auth(
        &t,
        "/v1/providers",
        &json!({ "base_url": "https://api.example.com/v1", "model": "m" }).to_string(),
    )
    .await;
    assert_error(&missing_name, 400, "missing_name");

    let long_url = post_auth(
        &t,
        "/v1/providers",
        &provider_body(
            "long",
            &format!("https://api.example.com/{}", "a".repeat(4096)),
            "m",
            None,
        ),
    )
    .await;
    assert_error(&long_url, 400, "invalid_provider");

    let acp_with_key = post_auth(
        &t,
        "/v1/providers",
        &json!({
            "name": "opencode-go",
            "kind": "acp",
            "api_key": CANARY_KEY,
        })
        .to_string(),
    )
    .await;
    assert_error(&acp_with_key, 400, "key_not_allowed");
    assert!(
        !acp_with_key.body.contains(CANARY_KEY),
        "{}",
        acp_with_key.body
    );

    // Exactly one provider survived every rejection.
    let config = std::fs::read_to_string(config_path(&t.home)).unwrap();
    assert_eq!(config.matches("[[providers]]").count(), 1, "{config}");
    assert!(config.contains("id = \"acme\""), "{config}");
    t.stop();
}

// ---------------------------------------------------------------------------
// provider test: plain-language reasons
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_test_maps_reasons_and_never_leaks_the_key() {
    // `nokey` has a key_user but no stored key: the honest "bad key" case.
    let config = r#"
version = 1
default_agent = "main"

[[providers]]
id = "good"
base_url = "http://127.0.0.1:9/v1"
model = "good-model"
key_user = "good"
kind = "openai-compat"

[[providers]]
id = "nokey"
base_url = "http://127.0.0.1:9/v1"
model = "nokey-model"
key_user = "definitely-not-in-keychain"
kind = "openai-compat"
"#;
    let mut t = TestApi::start_with_config(config).await;
    std::fs::write(t.home.join(".env"), format!("AUX_KEY_GOOD={CANARY_KEY}\n")).unwrap();

    let good = post_auth(&t, "/v1/providers/good/test", "{}").await;
    assert_eq!(good.status, 200, "body: {}", good.body);
    assert!(!good.body.contains(CANARY_KEY), "{}", good.body);
    assert_eq!(good.json()["ok"], true);
    assert_eq!(good.json()["reason"], "ok");

    let bad_key = post_auth(&t, "/v1/providers/nokey/test", "{}").await;
    assert_eq!(bad_key.status, 200, "body: {}", bad_key.body);
    let bad_key = bad_key.json();
    assert_eq!(bad_key["ok"], false);
    assert_eq!(bad_key["reason"], "bad_key");
    assert_eq!(bad_key["key_required"], true);
    assert_eq!(bad_key["key_present"], false);

    // Inline validation failure: invalid scheme maps to `invalid_config`.
    let inline = post_auth(
        &t,
        "/v1/providers/test",
        &json!({ "name": "inline", "base_url": "ftp://example.com", "model": "m" }).to_string(),
    )
    .await;
    assert_eq!(inline.status, 200, "body: {}", inline.body);
    assert_eq!(inline.json()["ok"], false);
    assert_eq!(inline.json()["reason"], "invalid_config");

    let unknown = post_auth(&t, "/v1/providers/ghost/test", "{}").await;
    assert_error(&unknown, 404, "provider_not_found");
    let missing = post_auth(&t, "/v1/providers/test", "{}").await;
    assert_error(&missing, 400, "missing_name");

    // A successful test is what flips the first-run step.
    let status = get_auth(&t, "/v1/first-run").await.json();
    assert_eq!(status["provider_tested"], true);
    assert_eq!(status["next_step"], "agent");
    assert_eq!(
        event_payloads(&t.home, "provider.tested").len(),
        3,
        "good + nokey + inline"
    );
    for payload in event_payloads(&t.home, "provider.tested") {
        assert!(!payload.contains(CANARY_KEY), "{payload}");
    }
    t.stop();
}

// ---------------------------------------------------------------------------
// first-run status + complete
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_run_status_and_complete_are_idempotent() {
    let mut t = TestApi::start().await;

    let empty = get_auth(&t, "/v1/first-run").await;
    assert_eq!(empty.status, 200, "body: {}", empty.body);
    let empty = empty.json();
    assert_eq!(empty["first_run"], true);
    assert_eq!(empty["provider_saved"], false);
    assert_eq!(empty["provider_tested"], false);
    assert_eq!(empty["agent_created"], false);
    assert_eq!(empty["next_step"], "provider");

    let saved = post_auth(
        &t,
        "/v1/providers",
        &provider_body("acme", "http://127.0.0.1:9/v1", "acme-1", Some(CANARY_KEY)),
    )
    .await;
    assert_eq!(saved.status, 201, "body: {}", saved.body);
    let after_save = get_auth(&t, "/v1/first-run").await.json();
    assert_eq!(after_save["provider_saved"], true);
    assert_eq!(after_save["provider_tested"], false);
    assert_eq!(after_save["next_step"], "test");

    let tested = post_auth(&t, "/v1/providers/acme/test", "{}").await;
    assert_eq!(tested.status, 200, "body: {}", tested.body);
    let after_test = get_auth(&t, "/v1/first-run").await.json();
    assert_eq!(after_test["provider_tested"], true);
    assert_eq!(after_test["agent_created"], false);
    assert_eq!(after_test["next_step"], "agent");
    assert_eq!(after_test["provider"], "acme");

    let created = post_auth(&t, "/v1/first-run/complete", "{}").await;
    assert_eq!(created.status, 201, "body: {}", created.body);
    let created = created.json();
    assert_eq!(created["first_run"], false);
    assert_eq!(created["created"], true);
    assert_eq!(created["provider"], "acme");
    assert_eq!(created["agent"]["name"], "main");
    assert_eq!(created["agent"]["provider"], "acme");
    assert!(t.home.join("agents/main").is_dir());

    let done = get_auth(&t, "/v1/first-run").await.json();
    assert_eq!(done["first_run"], false);
    assert_eq!(done["agent_created"], true);
    assert_eq!(done["next_step"], "done");
    assert_eq!(get_auth(&t, "/v1/health").await.json()["first_run"], false);

    // Idempotent: the second call reports the existing agent, creates nothing.
    let again = post_auth(&t, "/v1/first-run/complete", "{}").await;
    assert_eq!(again.status, 200, "body: {}", again.body);
    let again = again.json();
    assert_eq!(again["created"], false);
    assert_eq!(again["agent"]["name"], "main");

    assert_eq!(event_payloads(&t.home, "agent.created").len(), 1);
    assert_eq!(event_payloads(&t.home, "first_run.completed").len(), 1);
    t.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_run_complete_without_a_provider_is_a_clean_conflict() {
    let mut t = TestApi::start().await;
    let response = post_auth(&t, "/v1/first-run/complete", "{}").await;
    assert_error(&response, 409, "no_provider");
    assert!(!t.home.join("agents/main").exists());
    t.stop();
}

// ---------------------------------------------------------------------------
// auth + host/origin
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_routes_require_the_token_and_a_loopback_host() {
    let mut t = TestApi::start().await;
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("GET", "/v1/first-run", None),
        ("POST", "/v1/first-run/complete", Some("{}")),
        ("POST", "/v1/providers", Some("{}")),
        ("PUT", "/v1/providers/latekey/key", Some("{}")),
    ];
    for (method, path, body) in cases {
        let missing = call(t.addr, method, path, None, *body).await;
        assert_error(&missing, 401, "unauthorized");
        let wrong = call(t.addr, method, path, Some("wrong"), *body).await;
        assert_error(&wrong, 401, "unauthorized");
    }

    // A cross-origin browser request is refused before auth (F-17).
    let cross_origin = tokio::task::spawn_blocking({
        let addr = t.addr;
        let body = "{}".to_string();
        move || {
            common::http_with_headers(
                addr,
                "POST",
                "/v1/providers",
                Some(TEST_TOKEN),
                Some(&body),
                &[("Origin", "http://evil.example")],
            )
        }
    })
    .await
    .unwrap();
    assert_error(&cross_origin, 403, "forbidden_origin");
    t.stop();
}

// ---------------------------------------------------------------------------
// real binary: a saved key never reaches stdout/stderr
// ---------------------------------------------------------------------------

/// Spawn the real `auxd` with both streams piped and collected.
fn spawn_daemon(dir: &Path, home: &Path) -> (Child, mpsc::Receiver<u16>, Arc<Mutex<Vec<String>>>) {
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir, home)
        .env("AUXESIS_API_PORT", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (sender, receiver) = mpsc::channel();
    let collected = Arc::new(Mutex::new(Vec::new()));
    for stream in [
        child
            .stdout
            .take()
            .map(|out| Box::new(out) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|err| Box::new(err) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sender = sender.clone();
        let collected = Arc::clone(&collected);
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if let Some(rest) = line.strip_prefix("auxd api on http://127.0.0.1:") {
                    if let Ok(port) = rest.trim().parse::<u16>() {
                        let _ = sender.send(port);
                    }
                }
                collected.lock().unwrap().push(line);
            }
        });
    }
    (child, receiver, collected)
}

#[test]
fn the_daemon_never_logs_a_key_saved_through_the_api() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        config_path(&home),
        "version = 1\ndefault_agent = \"main\"\n",
    )
    .unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();

    let (mut child, ports, collected) = spawn_daemon(dir.path(), &home);
    let port = ports
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| {
            let _ = child.kill();
            panic!("the daemon never announced the local API")
        });
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let token = std::fs::read_to_string(api::token_path(&home))
        .unwrap()
        .trim()
        .to_string();

    let body = provider_body(
        "logged",
        "http://127.0.0.1:9/v1",
        "logged-model",
        Some(CANARY_KEY),
    );
    let saved = http(addr, "POST", "/v1/providers", Some(&token), Some(&body));
    assert_eq!(saved.status, 201, "body: {}", saved.body);
    assert!(!saved.body.contains(CANARY_KEY), "{}", saved.body);
    let tested = http(
        addr,
        "POST",
        "/v1/providers/logged/test",
        Some(&token),
        Some("{}"),
    );
    assert_eq!(tested.status, 200, "body: {}", tested.body);
    assert!(!tested.body.contains(CANARY_KEY), "{}", tested.body);

    // SIGTERM → clean exit, then scan every captured line.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut exited = false;
    while std::time::Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    if !exited {
        let _ = child.kill();
    }
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(100));
    let lines = collected.lock().unwrap().clone();
    assert!(
        !lines.iter().any(|line| line.contains(CANARY_KEY)),
        "the key leaked into stdout/stderr: {lines:?}"
    );
}

#[test]
fn a_provider_config_parse_error_names_the_line_and_never_quotes_it() {
    // CONFIG-ERR-ECHO-1: toml quotes the offending line in its error. A value
    // with no secret shape on that line must still never leave the daemon.
    const CANARY: &str = "CANARY-echo-1234567890abcdef";
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = format!(
        "version = 1\n[[providers]]\nid = \"x\"\nkind = \"openai-compat\"\n\
         base_url = \"http://127.0.0.1:9/v1\"\nmodel = [\"{CANARY}\"]\n"
    );
    std::fs::write(config_path(&home), config).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();

    let (mut child, ports, collected) = spawn_daemon(dir.path(), &home);
    let port = ports
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| {
            let _ = child.kill();
            panic!("the daemon never announced the local API")
        });
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let token = std::fs::read_to_string(api::token_path(&home)).unwrap();
    let listed = http(addr, "GET", "/v1/providers", Some(token.trim()), None);
    let _ = child.kill();
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(100));

    assert_error(&listed, 500, "config_invalid");
    assert!(!listed.body.contains("CANARY"), "{}", listed.body);
    assert!(
        listed.body.contains("config.toml, line 6"),
        "{}",
        listed.body
    );
    let lines = collected.lock().unwrap().clone();
    assert!(
        !lines.iter().any(|line| line.contains("CANARY")),
        "the value leaked into stdout/stderr: {lines:?}"
    );
}
