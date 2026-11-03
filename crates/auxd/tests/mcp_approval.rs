//! M6-2 acceptance: one approval installs an MCP server.
//!
//! The fixture is a local shebang stdio server that writes one line per spawn
//! into its sandbox temp dir. No real MCP server, no network: the daemon runs
//! in a temp home and the only traffic is the fixture's JSON-RPC handshake.

mod common;
use auxd::api::{self, ApiOptions};
use common::{http, HttpResponse, LOADED_RUNNER_WAIT};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `TMPDIR` and the catalog seam are process-wide, so this file's tests run
/// one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn call(a: SocketAddr, t: &str, m: &str, p: &str, b: Option<String>) -> HttpResponse {
    let (a, t, m, p) = (a, t.to_owned(), m.to_owned(), p.to_owned());
    tokio::task::spawn_blocking(move || http(a, &m, &p, Some(&t), b.as_deref()))
        .await
        .unwrap()
}

/// A base dir captured before any test points `TMPDIR` elsewhere.
fn temp_base() -> PathBuf {
    static BASE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BASE.get_or_init(std::env::temp_dir).clone()
}

/// Set an env var for one serialized test, restoring it on drop.
struct EnvVar(&'static str, Option<std::ffi::OsString>);

impl EnvVar {
    fn set(key: &'static str, value: &Path) -> Self {
        let prior = std::env::var_os(key);
        std::env::set_var(key, value);
        Self(key, prior)
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        match self.1.take() {
            Some(value) => std::env::set_var(self.0, value),
            None => std::env::remove_var(self.0),
        }
    }
}

fn write_home(dir: &Path) -> (PathBuf, &'static str) {
    let home = dir.join(".auxesis");
    std::fs::create_dir_all(home.join("agents/main")).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version=1\nprivacy.mode=\"open\"\ndefault_agent=\"main\"\n",
    )
    .unwrap();
    let token = "mcp-approval-token-0123456789";
    std::fs::write(api::token_path(&home), token).unwrap();
    (home, token)
}

fn fixture_script(path: &Path) {
    let script = r#"dir="${TMPDIR:-$1}"
mkdir -p "$dir"
printf 'spawn\n' >> "$dir/spawns"
while IFS= read -r line; do
  id=$(printf '%s' "$line"|/usr/bin/sed -n 's/.*"id":[ ]*\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id";;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"FAKE_TOOL","inputSchema":{"type":"object"}}],"nextCursor":null}}\n' "$id";;
  esac
done"#;
    std::fs::write(path, format!("#!/bin/sh\n{script}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Every `spawns` line a child wrote, directly in `dir` or in its own
/// `aux-mcp-*` sandbox temp dir.
fn spawn_count(dir: &Path) -> usize {
    let subdirs = std::fs::read_dir(dir).into_iter().flatten().flatten();
    std::iter::once(dir.to_path_buf())
        .chain(subdirs.map(|entry| entry.path()))
        .filter_map(|path| std::fs::read_to_string(path.join("spawns")).ok())
        .map(|text| text.lines().filter(|line| !line.is_empty()).count())
        .sum()
}

async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(LOADED_RUNNER_WAIT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn catalog_entry(id: &str, script: &Path, sha256: &str) -> String {
    format!(
        "[[server]]\nid = \"{id}\"\ndata_class = \"public\"\nname = \"{id}\"\nregion = \"fr\"\n\
         category = \"other\"\nstatus = \"community\"\ntransport = \"stdio\"\nauth = \"none\"\n\
         access = \"read-only\"\ntier = \"candidate\"\nversion = \"1.0.0\"\nsha256 = \"{sha256}\"\n\
         command = \"{}\"\nargs = []\n\
         permissions = {{ tools = [\"FAKE_TOOL\"], network = false, env = [] }}\n",
        script.display()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_approval_starts_exactly_one_child_and_a_replay_is_refused() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, token) = write_home(dir.path());
    let reports = dir.path().join("reports");
    std::fs::create_dir(&reports).unwrap();
    // The sandbox gives the child a temp dir under this; the script records
    // every spawn there so the test never needs to read outside its temp dir.
    let _tmp = EnvVar::set("TMPDIR", &reports);
    let script = dir.path().join("fixture-server.sh");
    fixture_script(&script);
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();
    let add = serde_json::json!({
        "id": "fixture",
        "transport": "stdio",
        "command": script,
        "args": [reports],
        "agent": "main",
        "tools": ["FAKE_TOOL"],
    });

    let added = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers",
        Some(add.to_string()),
    )
    .await;
    assert_eq!(added.status, 200, "{}", added.body);
    let added = added.json();
    let hash = added["hash"]
        .as_str()
        .expect("add returns the binding hash")
        .to_owned();
    assert_eq!(hash.len(), 64, "binding hash is a blake3 digest");
    assert_eq!(added["enabled"], false);
    assert_eq!(added["warning"], "mcp_install_approval");
    assert_eq!(added["tools"][0]["name"], "FAKE_TOOL");
    assert_eq!(added["tools"][0]["risk"], "high");
    assert_eq!(spawn_count(&reports), 0, "no child before approve");

    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let listed = listed.json();
    assert_eq!(listed["servers"][0]["state"], "disabled");
    assert_eq!(spawn_count(&reports), 0);

    let approved = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/fixture/approve",
        Some(serde_json::json!({"hash": hash, "agent": "main"}).to_string()),
    )
    .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    wait_for("the approved child to spawn", || spawn_count(&reports) == 1).await;
    wait_for("discovery to mount the approved tool", || {
        let Ok(text) = std::fs::read_to_string(home.join("mcp.toml")) else {
            return false;
        };
        text.contains("approval = \"") && text.contains("FAKE_TOOL")
    })
    .await;

    // A second approve of the same binding is idempotent: no second child.
    let again = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/fixture/approve",
        Some(serde_json::json!({"hash": hash, "agent": "main"}).to_string()),
    )
    .await;
    assert_eq!(again.status, 200, "{}", again.body);
    assert_eq!(spawn_count(&reports), 1, "no double start");

    // The old hash is stale once the launch changes.
    let current = std::fs::read_to_string(home.join("mcp.toml")).unwrap();
    std::fs::write(
        home.join("mcp.toml"),
        current.replace("network = false", "network = true"),
    )
    .unwrap();
    let stale = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/fixture/approve",
        Some(serde_json::json!({"hash": hash, "agent": "main"}).to_string()),
    )
    .await;
    assert_eq!(stale.status, 409, "{}", stale.body);
    assert!(stale.body.contains("stale_confirmation"), "{}", stale.body);

    assert_eq!(
        aux_runtime::extensions::ledger::count(&home, "mcp.approve"),
        1,
        "one approval writes one ledger row"
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hand_edited_enabled_http_server_waits_for_approval() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, token) = write_home(dir.path());
    std::fs::write(
        home.join("mcp.toml"),
        "[[server]]\nid = \"hand-edited\"\ntransport = \"http\"\n\
         url = \"https://example.invalid/mcp\"\nenabled = true\n\
         [server.agents]\nmain = [\"read\"]\n",
    )
    .unwrap();
    // Run the daemon's real startup path: it builds the runtime from
    // `mcp.toml` before serving, which is where a hand edit must be refused.
    let config = kernel_core::Config::load_or_create(&kernel_core::config_path(&home)).unwrap();
    let sandbox = aux_engine::shell_sandbox(&config.shell);
    let runtime = auxd::mcp::start(&home, &config.web, &sandbox).await;
    let mcp = std::sync::Arc::new(std::sync::RwLock::new(runtime));
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            mcp: Some(mcp),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    let listed = listed.json();
    let server = &listed["servers"][0];
    assert_eq!(server["enabled"], true);
    assert_eq!(server["state"], "needs_approval");
    assert_eq!(server["reason"], "approval_required");
    assert!(server["tools"].as_array().unwrap().is_empty());
    assert_eq!(
        aux_runtime::extensions::ledger::count(&home, "mcp.approve"),
        0
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_install_routes_are_owner_only_and_not_agent_tools() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, _token) = write_home(dir.path());
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    // Without the daemon's bearer token neither install route is reachable.
    for (method, path, body) in [
        ("POST", "/v1/mcp/servers", Some("{}".to_owned())),
        (
            "POST",
            "/v1/mcp/servers/x/approve",
            Some("{\"hash\":\"x\",\"agent\":\"main\"}".to_owned()),
        ),
    ] {
        let response =
            tokio::task::spawn_blocking(move || http(addr, method, path, None, body.as_deref()))
                .await
                .unwrap();
        assert_eq!(response.status, 401, "{}", response.body);
    }

    // A model sees only the registered tool surface. Installing is an owner
    // action, never a tool a turn can call.
    let mut registry = kernel_broker::ToolRegistry::new();
    let sandbox = kernel_broker::ShellSandbox::new(false, false, true);
    aux_runtime::tools::register_builtins(
        &mut registry,
        sandbox,
        kernel_core::WebConfig::default(),
    );
    for name in registry.names() {
        assert!(
            !matches!(
                name,
                "add_server" | "approve_server" | "mcp_add" | "mcp_approve"
            ),
            "install route exposed as a model tool: {name}"
        );
    }
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_swapped_catalog_binary_is_refused_at_approve_and_never_spawns() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, token) = write_home(dir.path());
    let reports = dir.path().join("reports");
    std::fs::create_dir(&reports).unwrap();
    let _tmp = EnvVar::set("TMPDIR", &reports);
    let script = dir.path().join("catalog-server.sh");
    fixture_script(&script);
    let sha256 = kernel_mcp::binary_sha256(&script);
    let catalog = dir.path().join("catalog.toml");
    std::fs::write(
        &catalog,
        format!(
            "catalog_version = \"test-1\"\n{}",
            catalog_entry("catalog-fixture", &script, &sha256)
        ),
    )
    .unwrap();
    // The seam exists only in a `test-util` build, which this target enables.
    let _catalog = EnvVar::set("AUXESIS_MCP_CATALOG", &catalog);
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    let added = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers",
        Some(
            serde_json::json!({"id":"catalog-fixture","catalog_id":"catalog-fixture"}).to_string(),
        ),
    )
    .await;
    assert_eq!(added.status, 200, "{}", added.body);
    let added = added.json();
    let hash = added["hash"].as_str().unwrap().to_owned();
    assert_eq!(added["catalog_pin"].as_str().map(str::len), Some(64));
    assert_eq!(added["tools"][0]["risk"], "low");
    assert_eq!(spawn_count(&reports), 0, "no child before approve");

    // The migration preview route agrees with the add response.
    let preview = call(
        addr,
        token,
        "GET",
        "/v1/mcp/servers/catalog-fixture/approval",
        None,
    )
    .await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    assert_eq!(preview.json()["hash"], hash.as_str());

    let approved = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/catalog-fixture/approve",
        Some(serde_json::json!({"hash": hash, "agent": "main"}).to_string()),
    )
    .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    wait_for("the approved catalog child to spawn", || {
        spawn_count(&reports) == 1
    })
    .await;

    // Disable: the child is reaped with its sandbox temp dir (and marker).
    let disabled = call(
        addr,
        token,
        "PUT",
        "/v1/mcp/servers/catalog-fixture",
        Some("{\"enabled\":false}".into()),
    )
    .await;
    assert_eq!(disabled.status, 200, "{}", disabled.body);
    wait_for("the reaped child marker", || spawn_count(&reports) == 0).await;

    // Swap the binary after approval; re-enable. The kernel re-hashes the file
    // at spawn, so the confirmed catalog SHA no longer matches and nothing runs.
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&script)
            .unwrap();
        file.write_all(b"\n# swapped\n").unwrap();
    }
    let enabled = call(
        addr,
        token,
        "PUT",
        "/v1/mcp/servers/catalog-fixture",
        Some("{\"enabled\":true}".into()),
    )
    .await;
    assert_eq!(enabled.status, 200, "{}", enabled.body);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        spawn_count(&reports),
        0,
        "a swapped catalog binary must never spawn"
    );
    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let listed = listed.json();
    let server = &listed["servers"][0];
    assert_eq!(server["state"], "failed");
    // `confirmation_missing` folds into the kernel's stable `command_refused`
    // kind; the no-spawn marker below is the proof the child never ran.
    assert_eq!(server["reason"], "command_refused");

    // Approve re-runs the catalog checks: the pinned SHA now mismatches, and
    // the call is a 400, not a confirmation.
    let refused = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/catalog-fixture/approve",
        Some(serde_json::json!({"hash": hash, "agent": "main"}).to_string()),
    )
    .await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(
        refused.body.contains("checksum_mismatch"),
        "{}",
        refused.body
    );
    assert_eq!(
        aux_runtime::extensions::ledger::count(&home, "mcp.approve"),
        1,
        "only the successful approval is recorded"
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_catalog_stdio_entry_is_only_confirmable_through_approve() {
    // Review P2: the legacy confirm/preview routes re-read whatever bytes sit
    // at `command`. A catalog stdio entry must be refused there (409
    // `use_approve`) and go through `/approve`, which binds the published SHA.
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, token) = write_home(dir.path());
    let reports = dir.path().join("reports");
    std::fs::create_dir(&reports).unwrap();
    let _tmp = EnvVar::set("TMPDIR", &reports);
    let script = dir.path().join("catalog-confirm.sh");
    fixture_script(&script);
    let sha256 = kernel_mcp::binary_sha256(&script);
    let catalog = dir.path().join("catalog.toml");
    std::fs::write(
        &catalog,
        format!(
            "catalog_version = \"test-1\"\n{}",
            catalog_entry("catalog-confirm", &script, &sha256)
        ),
    )
    .unwrap();
    let _catalog = EnvVar::set("AUXESIS_MCP_CATALOG", &catalog);
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    let added = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers",
        Some(
            serde_json::json!({"id":"catalog-confirm","catalog_id":"catalog-confirm"}).to_string(),
        ),
    )
    .await;
    assert_eq!(added.status, 200, "{}", added.body);
    let hash = added
        .json()
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .expect("add returns the approval binding")
        .to_owned();
    let before = std::fs::read_to_string(home.join("mcp.toml")).unwrap();

    let preview = call(
        addr,
        token,
        "GET",
        "/v1/mcp/servers/catalog-confirm/confirmation",
        None,
    )
    .await;
    assert_eq!(preview.status, 409, "{}", preview.body);
    assert!(preview.body.contains("use_approve"), "{}", preview.body);

    let confirmed = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/catalog-confirm/confirm",
        Some(serde_json::json!({"hash": hash}).to_string()),
    )
    .await;
    assert_eq!(confirmed.status, 409, "{}", confirmed.body);
    assert!(confirmed.body.contains("use_approve"), "{}", confirmed.body);

    // Neither refusal wrote a confirmation or started a child.
    assert_eq!(
        std::fs::read_to_string(home.join("mcp.toml")).unwrap(),
        before,
        "a refused legacy confirm must not rewrite mcp.toml"
    );
    assert_eq!(spawn_count(&reports), 0);

    // The pinned route still installs the same entry with one approval.
    let approved = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/catalog-confirm/approve",
        Some(serde_json::json!({"hash": hash, "agent": "main"}).to_string()),
    )
    .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    wait_for("the approved catalog child to spawn", || {
        spawn_count(&reports) == 1
    })
    .await;
    assert_eq!(
        aux_runtime::extensions::ledger::count(&home, "mcp.approve"),
        1
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_approval_ledger_write_enables_nothing() {
    // Review P3: the `mcp.approve` row must be written before the enable. A
    // store that cannot be opened returns 500 and leaves mcp.toml untouched,
    // so no server is enabled and no child starts.
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, token) = write_home(dir.path());
    let reports = dir.path().join("reports");
    std::fs::create_dir(&reports).unwrap();
    let _tmp = EnvVar::set("TMPDIR", &reports);
    let script = dir.path().join("ledger-fixture.sh");
    fixture_script(&script);
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    let added = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers",
        Some(
            serde_json::json!({
                "id": "ledger-fixture",
                "transport": "stdio",
                "command": script,
                "args": [reports],
                "agent": "main",
                "tools": ["FAKE_TOOL"],
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(added.status, 200, "{}", added.body);
    let hash = added.json()["hash"].as_str().unwrap().to_owned();
    let before = std::fs::read_to_string(home.join("mcp.toml")).unwrap();
    assert!(!before.contains("approval ="));

    // A directory where the store file must be: `Store::open` fails before the
    // audit row, so the commit never happens.
    let db = home.join("store.db");
    let _ = std::fs::remove_file(&db);
    std::fs::create_dir(&db).unwrap();

    let approved = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/ledger-fixture/approve",
        Some(serde_json::json!({"hash": hash, "agent": "main"}).to_string()),
    )
    .await;
    assert_eq!(approved.status, 500, "{}", approved.body);
    assert!(approved.body.contains("ledger_failed"), "{}", approved.body);

    assert_eq!(
        std::fs::read_to_string(home.join("mcp.toml")).unwrap(),
        before,
        "a failed ledger write must not enable or approve anything"
    );
    assert_eq!(
        spawn_count(&reports),
        0,
        "nothing may start without the row"
    );
    api.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pack_never_approves_an_existing_server_outside_its_read_only_tools() {
    // Review P2: a pack may only approve an existing server whose whole
    // allowlist is inside the pack's curated read-only tools. A hand-edited
    // matching server with an extra write tool stays `needs_approval`; a clean
    // one is still approved.
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, token) = write_home(dir.path());
    let endpoint = "https://127.0.0.1:9/mcp";
    let catalog = dir.path().join("catalog.toml");
    std::fs::write(
        &catalog,
        format!(
            "catalog_version = \"test-1\"\n\
             [[server]]\nid = \"datagouv-mcp\"\ndata_class = \"public\"\n\
             name = \"datagouv-mcp\"\nregion = \"fr\"\ncategory = \"gov-data\"\n\
             status = \"community\"\ntransport = \"http\"\nendpoint = \"{endpoint}\"\n\
             auth = \"none\"\naccess = \"read-only\"\ntier = \"recommended\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        home.join("mcp.toml"),
        format!(
            "[[server]]\nid = \"datagouv-mcp\"\ncatalog_id = \"datagouv-mcp\"\n\
             data_class = \"public\"\ntransport = \"http\"\nurl = \"{endpoint}\"\n\
             enabled = true\n\n[server.agents]\n\
             main = [\"curated_read\", \"write_extra\"]\n"
        ),
    )
    .unwrap();
    let _catalog = EnvVar::set("AUXESIS_MCP_CATALOG", &catalog);
    // Run the daemon's real startup path so the pending server has a status.
    let config = kernel_core::Config::load_or_create(&kernel_core::config_path(&home)).unwrap();
    let sandbox = aux_engine::shell_sandbox(&config.shell);
    let runtime = auxd::mcp::start(&home, &config.web, &sandbox).await;
    let mcp = std::sync::Arc::new(std::sync::RwLock::new(runtime));
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            mcp: Some(mcp),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    let pack = call(
        addr,
        token,
        "POST",
        "/v1/mcp/packs/public-data/enable",
        Some("{\"agent\":\"main\"}".into()),
    )
    .await;
    assert_eq!(pack.status, 400, "{}", pack.body);
    assert!(pack.body.contains("pack_no_tools_enabled"), "{}", pack.body);
    let text = std::fs::read_to_string(home.join("mcp.toml")).unwrap();
    assert!(
        !text.contains("approval ="),
        "a pack must not approve an over-broad allowlist: {text}"
    );
    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let listed = listed.json();
    let server = &listed["servers"][0];
    assert_eq!(server["enabled"], true);
    assert_eq!(server["state"], "needs_approval");
    assert_eq!(server["reason"], "approval_required");

    // Remove the extra tool: the pack may now approve the clean entry.
    std::fs::write(
        home.join("mcp.toml"),
        format!(
            "[[server]]\nid = \"datagouv-mcp\"\ncatalog_id = \"datagouv-mcp\"\n\
             data_class = \"public\"\ntransport = \"http\"\nurl = \"{endpoint}\"\n\
             enabled = false\n"
        ),
    )
    .unwrap();
    let pack = call(
        addr,
        token,
        "POST",
        "/v1/mcp/packs/public-data/enable",
        Some("{\"agent\":\"main\"}".into()),
    )
    .await;
    // No tool is discovered in the sandbox, so the pack rolls the enable back,
    // but the approval it minted is the proof the clean server was approved.
    assert_eq!(pack.status, 400, "{}", pack.body);
    assert!(pack.body.contains("pack_no_tools_enabled"), "{}", pack.body);
    let text = std::fs::read_to_string(home.join("mcp.toml")).unwrap();
    assert!(
        text.contains("approval = \""),
        "the pack must approve a curated read-only allowlist: {text}"
    );
    api.shutdown();
}

/// M6-3 (#524 P3): a new catalog release is a changed pin, so the approval
/// preview hash moves and the old approval no longer matches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_catalog_version_moves_the_approval_hash() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(temp_base()).unwrap();
    let (home, token) = write_home(dir.path());
    let script = dir.path().join("catalog-server.sh");
    fixture_script(&script);
    let sha256 = kernel_mcp::binary_sha256(&script);
    let catalog = dir.path().join("catalog.toml");
    let write_catalog = |version: &str| {
        std::fs::write(
            &catalog,
            format!(
                "catalog_version = \"{version}\"\n{}",
                catalog_entry("catalog-fixture", &script, &sha256)
            ),
        )
        .unwrap();
    };
    write_catalog("test-1");
    let _catalog = EnvVar::set("AUXESIS_MCP_CATALOG", &catalog);
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();
    let add = serde_json::json!({"id":"catalog-fixture","catalog_id":"catalog-fixture"});
    let added = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers",
        Some(add.to_string()),
    )
    .await;
    assert_eq!(added.status, 200, "{}", added.body);
    let first_pin = added.json()["hash"].as_str().unwrap().to_owned();

    write_catalog("test-2");
    let approval_path = "/v1/mcp/servers/catalog-fixture/approval";
    let moved = call(addr, token, "GET", approval_path, None).await;
    assert_eq!(moved.status, 200, "{}", moved.body);
    assert_ne!(moved.json()["hash"], first_pin.as_str());
    api.shutdown();
}
