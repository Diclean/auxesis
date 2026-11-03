//! A slow MCP reload must never resurrect a server the owner disabled while it
//! was discovering, and the replaced stdio server must be reaped (security review P2 on
//! #139: mutations are serialized under one MCP lock with a generation check).

mod common;
use auxd::api::{self, ApiOptions};
use common::{http, HttpResponse};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

/// `name` written by the stdio child, either directly in `dir` (no sandbox)
/// or in one of its subdirectories: the sandboxed child on macOS writes into
/// its own `aux-mcp-*` temp dir under `$TMPDIR`.
fn child_file(dir: &Path, name: &str) -> Option<PathBuf> {
    let subdirs = std::fs::read_dir(dir).into_iter().flatten().flatten();
    std::iter::once(dir.to_path_buf())
        .chain(subdirs.map(|e| e.path()))
        .map(|d| d.join(name))
        .find(|p| p.exists())
}

async fn call(a: SocketAddr, t: &str, m: &str, p: &str, b: Option<String>) -> HttpResponse {
    let (a, t, m, p) = (a, t.to_owned(), m.to_owned(), p.to_owned());
    tokio::task::spawn_blocking(move || http(a, &m, &p, Some(&t), b.as_deref()))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serialized_mcp_replacement_wins_and_reaps_stdio() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join(".auxesis");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version=1\nprivacy.mode=\"open\"\ndefault_agent=\"main\"\n",
    )
    .unwrap();
    let token = "mcp-review-token-0123456789";
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
    // The stdio child is sandboxed on macOS and may write only its own temp
    // dir, which the launcher names in `$TMPDIR` (see `StdioSandbox`). Point the
    // daemon's `$TMPDIR` at a directory the test owns, so the child's temp dir
    // is findable; a file written anywhere else in the test dir is EPERM there.
    let report_dir = d.path().join("tmp");
    std::fs::create_dir(&report_dir).unwrap();
    std::env::set_var("TMPDIR", &report_dir);
    // A script MCP server whose tools/list takes 0.6 s and drops a marker file
    // when discovery starts, so the test can disable it mid-discovery. It writes
    // into `$TMPDIR` when the launcher set it (macOS), else into its argument
    // (no sandbox, cleared environment).
    //
    // Item 2 refuses a shell as `argv[0]`, so the fixture is a shebang script
    // executed directly instead of `sh -c <script>`: the policy checks the
    // launcher, not the interpreter a shebang later names.
    let script = r#"dir="${TMPDIR:-$1}"; echo $$ > "$dir/pid"; while IFS= read -r line; do id=$(printf '%s' "$line"|/usr/bin/sed -n 's/.*"id":[ ]*\([0-9][0-9]*\).*/\1/p'); case "$line" in *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id";; *tools/list*) : > "$dir/discovering"; sleep 0.6; printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"FAKE_TOOL","inputSchema":{"type":"object"}}],"nextCursor":null}}\n' "$id";; esac; done"#;
    let script_path = d.path().join("server.sh");
    std::fs::write(&script_path, format!("#!/bin/sh\n{script}\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cfg = serde_json::json!({
        "id": "slow",
        "transport": "stdio",
        "command": script_path,
        "stdio_confirmed": true,
        "args": [report_dir],
    });
    assert_eq!(
        call(
            addr,
            token,
            "POST",
            "/v1/mcp/servers",
            Some(cfg.to_string())
        )
        .await
        .status,
        200
    );

    // Confirmation is bound to the exact launch hash: fetch the preview and
    // confirm it, so the server may actually spawn.
    let preview = call(
        addr,
        token,
        "GET",
        "/v1/mcp/servers/slow/confirmation",
        None,
    )
    .await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    let hash = preview.json()["hash"].as_str().unwrap().to_owned();
    let confirm = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/slow/confirm",
        Some(format!("{{\"hash\":\"{hash}\"}}")),
    )
    .await;
    assert_eq!(confirm.status, 200, "{}", confirm.body);

    let (a, t) = (addr, token.to_owned());
    let enable = tokio::spawn(async move {
        call(
            a,
            &t,
            "PUT",
            "/v1/mcp/servers/slow",
            Some("{\"enabled\":true}".into()),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while child_file(&report_dir, "discovering").is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Read the pid before disabling: the child's temp dir, pid file included,
    // is removed when the server is reaped.
    let pid: i32 = std::fs::read_to_string(child_file(&report_dir, "pid").unwrap())
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let disable = tokio::spawn(async move {
        call(
            addr,
            token,
            "PUT",
            "/v1/mcp/servers/slow",
            Some("{\"enabled\":false}".into()),
        )
        .await
    });
    assert_eq!(enable.await.unwrap().status, 200);
    assert_eq!(disable.await.unwrap().status, 200);

    let view = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    assert_eq!(view.status, 200);
    assert_eq!(view.json()["servers"][0]["enabled"], false);
    assert!(view.json()["servers"][0]["tools"]
        .as_array()
        .unwrap()
        .is_empty());

    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let rc = unsafe { libc::kill(pid, 0) };
            if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                break;
            }
            assert_eq!(rc, 0, "unexpected kill(pid, 0) error");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    api.shutdown();
}
