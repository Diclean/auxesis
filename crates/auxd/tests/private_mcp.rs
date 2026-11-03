//! TOK-7: MCP servers work in a private chat, masked. A stdio server is mounted
//! and offered; the call keeps the session token (the server never sees the
//! value); the reply reaches the provider only through the session gate. An
//! open → private switch restarts every running child.
//!
//! The server is a shell script (no network, no real service). On macOS the
//! launcher sandboxes it and names its own temp dir in `$TMPDIR`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod common;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use auxd::api::{self, ApiOptions, EngineTurnRunner, TurnRunner};
use common::http;
use kernel_privacy::ContactIndex;

const IBAN: &str = "FR7630006000011234567890189";
const MESSAGE: &str =
    "Écris à Camille Exemple, camille@exemple.fr, IBAN FR7630006000011234567890189.";
const REPLY_EMAIL: &str = "dupont.reply@exemple.fr";
const REPLY_IBAN: &str = "DE89370400440532013000";

/// The children write into `$TMPDIR`, which is process-wide: one test at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SCRIPT: &str = r#"dir="${TMPDIR:-$1}"; echo $$ > "$dir/pid"; while IFS= read -r line; do id=$(printf '%s' "$line"|/usr/bin/sed -n 's/.*"id":[ ]*\([0-9][0-9]*\).*/\1/p'); case "$line" in *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id";; *tools/list*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"CRM_LOOKUP","inputSchema":{"type":"object","additionalProperties":true}}],"nextCursor":null}}\n' "$id";; *tools/call*) printf '%s\n' "$line" >> "$dir/calls"; printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"Reply from dupont.reply@exemple.fr, account DE89370400440532013000"}],"isError":false}}\n' "$id";; esac; done"#;

/// A home in `mode` with one confirmed stdio server `fake` (tool `CRM_LOOKUP`) and
/// an allow rule for it. Returns the temp dir, the home and the tmp the child
/// writes into.
fn home_with_server(mode: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    // `tempdir()` reads `$TMPDIR`, which an earlier test pointed at its own dir.
    let dir = tempfile::tempdir_in(test_base()).unwrap();
    let home = dir.path().join("home");
    kernel_core::ensure_home(&home).unwrap();
    let tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    std::env::set_var("TMPDIR", &tmp);
    let script = dir.path().join("server.sh");
    std::fs::write(&script, format!("#!/bin/sh\n{SCRIPT}\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let token = "private-mcp-token-0123456789";
    std::fs::write(auxd::api::token_path(&home), token).unwrap();
    let server = format!(
        "[[server]]\nid = \"fake\"\ntransport = \"stdio\"\ncommand = \"{}\"\nargs = [\"{}\"]\n\
         enabled = true\n[server.agents]\nmain = [\"CRM_LOOKUP\"]\n",
        script.display(),
        tmp.display()
    );
    let parsed = kernel_mcp::McpConfig::parse("mcp.toml", &server).unwrap();
    let hash = parsed.server[0]
        .confirmation_binding(token.as_bytes())
        .unwrap();
    std::fs::write(
        home.join("mcp.toml"),
        server.replace(
            "enabled = true",
            &format!("enabled = true\nstdio_confirmed = true\nstdio_confirmation = \"{hash}\""),
        ),
    )
    .unwrap();
    write_mode(&home, mode);
    (dir, home, tmp)
}

fn write_mode(home: &Path, mode: &str) {
    std::fs::write(
        kernel_core::config_path(home),
        format!(
            "version = 1\n\n[privacy]\nmode = \"{mode}\"\n\n[[rules]]\ndot = \"main\"\n\
             tool = \"mcp__fake__CRM_LOOKUP\"\naction = \"allow\"\n"
        ),
    )
    .unwrap();
}

/// Every `name` a child wrote, in `dir` or in its own `aux-mcp-*` subdirectory.
fn child_files(dir: &Path, name: &str) -> Vec<PathBuf> {
    let subdirs = std::fs::read_dir(dir).into_iter().flatten().flatten();
    std::iter::once(dir.to_path_buf())
        .chain(subdirs.map(|e| e.path()))
        .map(|d| d.join(name))
        .filter(|p| p.exists())
        .collect()
}

fn child_pids(tmp: &Path) -> Vec<i32> {
    child_files(tmp, "pid")
        .iter()
        .filter_map(|file| std::fs::read_to_string(file).ok()?.trim().parse().ok())
        .collect()
}

fn alive(pid: i32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Calls the MCP tool once with the first IBAN token of the owner's message.
struct Caller {
    requests: Mutex<Vec<ChatRequest>>,
}

#[async_trait::async_trait]
impl ChatProvider for Caller {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(req.clone());
        if requests.len() > 1 {
            return Ok(ChatResponse::assistant("done"));
        }
        let first = serde_json::to_string(&requests[0].messages).unwrap();
        let start = first.find("⟦IBAN_").expect("an IBAN token");
        let end = first[start..].find('⟧').unwrap() + start + '⟧'.len_utf8();
        let args = serde_json::json!({"query": &first[start..end]});
        Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
            "",
            vec![ToolCall::new("call_0", "mcp__fake__CRM_LOOKUP", args)],
        )))
    }

    fn name(&self) -> &str {
        "caller"
    }
}

#[test]
fn a_private_mcp_call_sends_the_token_and_gets_the_reply_tokenised() {
    let _serial = SERIAL.blocking_lock();
    let (_dir, home, tmp) = home_with_server("private");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let web = kernel_core::WebConfig::default();
    let sandbox = kernel_broker::ShellSandbox::new(false, false, true);
    let mcp = rt.block_on(auxd::mcp::start(&home, &web, &sandbox));
    assert_eq!(mcp.tool_count(), 1, "the server runs in private mode");

    let provider = Arc::new(Caller {
        requests: Mutex::new(Vec::new()),
    });
    let mut contacts = ContactIndex::new();
    contacts
        .add_from_header("Camille Exemple", "camille@exemple.fr")
        .unwrap();
    let runner = EngineTurnRunner::new(&home)
        .with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>)
        .with_contacts(Arc::new(contacts))
        .with_mcp(mcp);

    runner.run_turn("main", None, MESSAGE, None).unwrap();

    let bodies: Vec<String> = provider
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| serde_json::to_string(&request.messages).unwrap())
        .collect();
    assert_eq!(bodies.len(), 2, "the call ran, then the tool result");
    let seen = std::fs::read_to_string(
        child_files(&tmp, "calls")
            .first()
            .unwrap_or_else(|| panic!("no call: {bodies:?}")),
    )
    .unwrap();
    assert!(seen.contains("⟦IBAN_"), "the server got the token: {seen}");
    assert!(
        !seen.contains("⟦⟦"),
        "the session's token was escaped: {seen}"
    );
    assert!(!seen.contains(IBAN), "the server got the value: {seen}");
    assert!(
        bodies[1].contains("Reply from"),
        "the reply came back: {}",
        bodies[1]
    );
    for body in &bodies {
        for raw in [IBAN, "camille@exemple.fr", REPLY_EMAIL, REPLY_IBAN] {
            assert!(!body.contains(raw), "{raw} reached the provider: {body}");
        }
    }
    assert!(bodies[1].contains("⟦EMAIL_"), "{}", bodies[1]);
    assert!(bodies[1].contains("⟦IBAN_"), "{}", bodies[1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_to_private_switch_restarts_the_children_once() {
    let _serial = SERIAL.lock().await;
    let (_dir, home, tmp) = home_with_server("open");
    let web = kernel_core::WebConfig::default();
    let sandbox = kernel_broker::ShellSandbox::new(false, false, true);
    let runtime = auxd::mcp::start(&home, &web, &sandbox).await;
    assert_eq!(runtime.tool_count(), 1);
    let before = child_pids(&tmp)[0];
    let slot: auxd::mcp::McpSlot = Arc::new(std::sync::RwLock::new(runtime));
    let watch = auxd::mcp::spawn_privacy_watch(
        home.clone(),
        Arc::clone(&slot),
        auxd::mcp::McpOrdering::new(),
    );
    let first = auxd::mcp::current(&slot);
    // The watch reads its starting mode on its first tick: a switch written
    // before that tick is read as the start, never as a switch.
    tokio::time::sleep(auxd::privacy_wiring::WATCH_INTERVAL * 2).await;

    eprintln!(
        "mode before: {:?}",
        auxd::privacy_wiring::current_mode(&home)
    );
    write_mode(&home, "private");
    eprintln!(
        "mode after: {:?}",
        auxd::privacy_wiring::current_mode(&home)
    );
    // The rebuild starts a new child and runs its discovery: on a loaded CI
    // runner that took over 15 s (FLAKY-PROBE-2). 60 s still fails a hang.
    tokio::time::timeout(Duration::from_secs(60), async {
        while Arc::ptr_eq(&first, &auxd::mcp::current(&slot)) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the runtime was rebuilt");
    let rebuilt = auxd::mcp::current(&slot);
    assert_eq!(rebuilt.tool_count(), 1, "the server runs again, in private");
    assert!(!alive(before), "the open-mode child is gone");
    let after: Vec<i32> = child_pids(&tmp)
        .into_iter()
        .filter(|pid| alive(*pid))
        .collect();
    assert_eq!(after.len(), 1, "one live child: {after:?}");
    assert_ne!(before, after[0]);

    // A plain private → private tick does nothing.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(Arc::ptr_eq(&rebuilt, &auxd::mcp::current(&slot)));
    assert!(alive(after[0]));
    watch.abort();
}

/// A base dir captured before any test points `TMPDIR` elsewhere.
fn test_base() -> PathBuf {
    static BASE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BASE.get_or_init(std::env::temp_dir).clone()
}

/// P3 (Break-It M6): a privacy-mode rebuild must not resurrect a server the
/// owner revokes while the rebuild is discovering.
///
/// The rebuild takes the same lock as every MCP mutation, so the revoke either
/// lands before the config read or waits until the rebuilt runtime is in
/// place. Without that ordering the revoke installs an empty runtime and the
/// stale rebuild then installs the pre-revoke one over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_rebuild_cannot_resurrect_a_server_revoked_mid_discovery() {
    let _serial = SERIAL.lock().await;
    let dir = tempfile::tempdir_in(test_base()).unwrap();
    let home = dir.path().join("home");
    kernel_core::ensure_home(&home).unwrap();
    let tmp = dir.path().join("tmp");
    std::fs::create_dir_all(&tmp).unwrap();
    std::env::set_var("TMPDIR", &tmp);
    // Discovery takes 2 s, and the child drops a `discovering` marker as it
    // enters tools/list, so the revoke can be issued inside that window.
    let script = r#"dir="${TMPDIR:-$1}"; echo $$ > "$dir/pid"; while IFS= read -r line; do id=$(printf '%s' "$line"|/usr/bin/sed -n 's/.*"id":[ ]*\([0-9][0-9]*\).*/\1/p'); case "$line" in *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"fixture","version":"1"}}}\n' "$id";; *tools/list*) : > "$dir/discovering"; sleep 2; printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"FAKE_TOOL","inputSchema":{"type":"object"}}],"nextCursor":null}}\n' "$id";; esac; done"#;
    let script_path = dir.path().join("slow-server.sh");
    std::fs::write(&script_path, format!("#!/bin/sh\n{script}\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let token = "private-mcp-token-0123456789";
    std::fs::write(api::token_path(&home), token).unwrap();
    let server = format!(
        "[[server]]\nid = \"slow\"\ntransport = \"stdio\"\ncommand = \"{}\"\n\
         args = [\"{}\"]\nenabled = true\n[server.agents]\nmain = [\"FAKE_TOOL\"]\n",
        script_path.display(),
        tmp.display()
    );
    let parsed = kernel_mcp::McpConfig::parse("mcp.toml", &server).unwrap();
    let confirmation = parsed.server[0]
        .confirmation_binding(token.as_bytes())
        .unwrap();
    std::fs::write(
        home.join("mcp.toml"),
        server.replace(
            "enabled = true",
            &format!(
                "enabled = true\nstdio_confirmed = true\nstdio_confirmation = \"{confirmation}\""
            ),
        ),
    )
    .unwrap();
    write_mode(&home, "open");

    let web = kernel_core::WebConfig::default();
    let sandbox = kernel_broker::ShellSandbox::new(false, false, true);
    let runtime = auxd::mcp::start(&home, &web, &sandbox).await;
    assert_eq!(runtime.tool_count(), 1, "the approved server runs");
    let initial_pid = child_pids(&tmp)
        .into_iter()
        .find(|pid| alive(*pid))
        .expect("the first child wrote its pid");
    let slot: auxd::mcp::McpSlot = Arc::new(std::sync::RwLock::new(runtime));
    let ordering = auxd::mcp::McpOrdering::new();
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            mcp: Some(Arc::clone(&slot)),
            mcp_ordering: ordering.clone(),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();
    let watch = auxd::mcp::spawn_privacy_watch(home.clone(), Arc::clone(&slot), ordering);
    // The watch reads its starting mode on the first tick: let it see `open`.
    tokio::time::sleep(auxd::privacy_wiring::WATCH_INTERVAL * 2).await;

    // Drop the first child's discovery marker so the next one is the rebuild's.
    for marker in child_files(&tmp, "discovering") {
        let _ = std::fs::remove_file(marker);
    }
    write_mode(&home, "private");

    // Wait until the rebuild is inside discovery, then revoke the server while
    // it is running. On the fixed build the revoke waits for the rebuild; on
    // the old build it slips through and the stale runtime is installed last.
    tokio::time::timeout(Duration::from_secs(15), async {
        while child_files(&tmp, "discovering").is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the rebuild started discovery");
    let rebuild_pid = child_pids(&tmp)
        .into_iter()
        .find(|pid| *pid != initial_pid && alive(*pid))
        .expect("the rebuild child wrote its pid");

    let addr_call = addr;
    let token = token.to_owned();
    let revoke = tokio::task::spawn_blocking(move || {
        http(
            addr_call,
            "DELETE",
            "/v1/mcp/servers/slow",
            Some(&token),
            None,
        )
    });
    let revoked = tokio::time::timeout(Duration::from_secs(30), revoke)
        .await
        .expect("the revoke returned")
        .unwrap();
    assert_eq!(revoked.status, 200, "{}", revoked.body);

    // Give any stale rebuild time to land after the revoke, then require the
    // server to be gone for good: no mounted server and no live child.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(
        auxd::mcp::current(&slot).tool_count(),
        0,
        "a privacy rebuild must not resurrect a revoked server"
    );
    assert!(
        !alive(rebuild_pid),
        "the revoked server's child must be reaped"
    );
    assert!(
        !home.join("mcp.toml").exists() || {
            let text = std::fs::read_to_string(home.join("mcp.toml")).unwrap();
            !text.contains("id = \"slow\"")
        }
    );
    watch.abort();
    api.shutdown();
}
