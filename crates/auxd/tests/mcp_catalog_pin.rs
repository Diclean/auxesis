//! The catalog stdio pin through the management API: a complete entry installs
//! only when the binary at `command` matches its published `sha256`; a mismatch
//! is 400 `checksum_mismatch` with no write and no child. The fixture catalogue
//! comes from the `test-util`-only `AUXESIS_MCP_CATALOG` seam, so no real MCP
//! server is downloaded or run.

mod common;
use auxd::api::{self, ApiOptions};
use common::{http, HttpResponse};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::Path;

async fn call(a: SocketAddr, t: &str, m: &str, p: &str, b: Option<String>) -> HttpResponse {
    let (a, t, m, p) = (a, t.to_owned(), m.to_owned(), p.to_owned());
    tokio::task::spawn_blocking(move || http(a, &m, &p, Some(&t), b.as_deref()))
        .await
        .unwrap()
}

fn entry(id: &str, script: &Path, sha256: &str) -> String {
    let (command, hash) = (script.display(), sha256);
    format!(
        "[[server]]\nid = \"{id}\"\ndata_class = \"public\"\nname = \"{id}\"\nregion = \"fr\"\n\
         category = \"other\"\nstatus = \"community\"\ntransport = \"stdio\"\nauth = \"none\"\n\
         access = \"read-only\"\ntier = \"candidate\"\nversion = \"1.0.0\"\nsha256 = \"{hash}\"\n\
         command = \"{command}\"\nargs = [\"--stdio\"]\n\
         permissions = {{ tools = [\"echo\"], network = false, env = [] }}\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_catalog_artefact_is_refused_before_any_write_or_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".auxesis");
    std::fs::create_dir_all(home.join("agents/main")).unwrap();
    let config = "version=1\nprivacy.mode=\"open\"\ndefault_agent=\"main\"\n";
    std::fs::write(home.join("config.toml"), config).unwrap();
    let script = dir.path().join("echo-server.sh");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp/echo-server.sh");
    std::fs::copy(fixture, &script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let marker = dir.path().join("child-started");
    let sha256 = kernel_mcp::binary_sha256(&script);
    assert_eq!(sha256.len(), 64, "the fixture must be hashable");
    // Same bytes and checksum, but other users may rewrite the file: refused.
    let writable = dir.path().join("writable-server.sh");
    std::fs::copy(&script, &writable).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o775)).unwrap();
    }
    let catalog = dir.path().join("catalog.toml");
    std::fs::write(
        &catalog,
        format!(
            "catalog_version = \"2026.11.02-1\"\n{}{}{}",
            entry("fixture-stdio", &script, &sha256),
            entry("fixture-tampered", &script, &sha256),
            entry("fixture-writable", &writable, &sha256),
        ),
    )
    .unwrap();
    // The seam exists only in a `test-util` build, which this target enables.
    std::env::set_var("AUXESIS_MCP_CATALOG", &catalog);
    let token = "mcp-catalog-pin-token-0123456789";
    std::fs::write(api::token_path(&home), token).unwrap();
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();
    let add = |id: &str| {
        let body = format!("{{\"id\":\"{id}\",\"catalog_id\":\"{id}\"}}");
        call(addr, token, "POST", "/v1/mcp/servers", Some(body))
    };

    let before = std::fs::read(home.join("mcp.toml")).ok();
    let mutable = add("fixture-writable").await;
    assert_eq!(mutable.status, 400, "{}", mutable.body);
    assert!(
        mutable.body.contains("binary_path_mutable"),
        "{}",
        mutable.body
    );
    assert_eq!(
        std::fs::read(home.join("mcp.toml")).ok(),
        before,
        "no write"
    );

    let added = add("fixture-stdio").await;
    assert_eq!(added.status, 200, "{}", added.body);
    assert!(!marker.exists(), "installing must never start a child");
    let written = std::fs::read(home.join("mcp.toml")).unwrap();
    let text = String::from_utf8_lossy(&written);
    assert!(text.contains("catalog_id = \"fixture-stdio\"") && text.contains("enabled = false"));

    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let listed: serde_json::Value = serde_json::from_str(&listed.body).unwrap();
    let pinned = listed["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "fixture-stdio")
        .unwrap();
    assert_eq!(
        (pinned["state"].as_str(), pinned["enabled"].as_bool()),
        (Some("pinned"), Some(false))
    );

    // The pinned hash now lies: the install is refused before any write/spawn.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&script)
        .unwrap()
        .write_all(b"\n# tampered\n")
        .unwrap();
    let refused = add("fixture-tampered").await;
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert!(
        refused.body.contains("checksum_mismatch"),
        "{}",
        refused.body
    );
    assert_eq!(std::fs::read(home.join("mcp.toml")).unwrap(), written);
    assert!(!marker.exists(), "a refused install must not start a child");
}
