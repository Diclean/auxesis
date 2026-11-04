//! Acceptance: `aux mcp` never contacts a server the daemon would
//! refuse for lack of the owner's one approval.
//!
//! The endpoint is a loopback fake that counts every TCP connection. The CLI
//! runs in the CLAUDE.md sandbox: temp HOME/AUXESIS_HOME, `AUXESIS_SANDBOX=1`,
//! `AUXESIS_API_PORT=0`.

mod common;
use common::sandbox_command;
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

/// A fake HTTP endpoint that counts accepted connections and closes them.
fn fake_endpoint() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}/mcp", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (address, hits)
}

fn home_with_endpoint(dir: &std::path::Path, endpoint: &str) -> std::path::PathBuf {
    let home = dir.join(".auxesis");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("api.token"), "mcp-cli-approval-token-0123456789").unwrap();
    std::fs::write(
        home.join("mcp.toml"),
        format!(
            "[[server]]\nid = \"hand-edited\"\ntransport = \"http\"\n\
             url = \"{endpoint}\"\nenabled = true\n\
             [server.agents]\nmain = [\"HTTP_TOOL\"]\n"
        ),
    )
    .unwrap();
    home
}

fn run(dir: &std::path::Path, home: &std::path::Path, args: &[&str]) -> String {
    let output = sandbox_command(aux_bin(), dir, home)
        .args(args)
        .env("AUXESIS_LANG", "en")
        .output()
        .expect("run aux mcp");
    assert!(
        output.status.success(),
        "aux mcp failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn an_unapproved_http_server_is_never_contacted_and_lists_needs_approval() {
    let dir = tempdir().unwrap();
    let (endpoint, hits) = fake_endpoint();
    let home = home_with_endpoint(dir.path(), &endpoint);

    let stdout = run(dir.path(), &home, &["mcp", "list"]);
    assert!(stdout.contains("needs approval"), "{stdout}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no contact before approval");

    // `tools` discovers every enabled server too, so it must not contact it.
    let _ = run(dir.path(), &home, &["mcp", "tools", "hand-edited"]);
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no contact from `tools`");

    // Approve exactly the preview the daemon would approve: the same keyed
    // binding, computed with the daemon token and no catalog pin (this entry
    // is hand-written, not catalogued).
    let mut config = kernel_mcp::McpConfig::load_from_path(&home.join("mcp.toml")).unwrap();
    let hash = config.server[0]
        .approval_binding(b"mcp-cli-approval-token-0123456789", None)
        .expect("approval binding");
    config.server[0].approval = Some(hash);
    std::fs::write(home.join("mcp.toml"), config.to_toml_string().unwrap()).unwrap();

    // The approval gate releases the server to the transport. The loopback
    // origin is then refused by the existing SSRF guard, so the state is
    // `failed`, never `needs approval`.
    let stdout = run(dir.path(), &home, &["mcp", "list"]);
    assert!(!stdout.contains("needs approval"), "{stdout}");
    assert!(stdout.contains("failed"), "{stdout}");
}
