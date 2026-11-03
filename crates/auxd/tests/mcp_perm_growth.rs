//! M6-3 acceptance: a permission growth needs a new approval.
//!
//! The fixture is a tiny loopback HTTP MCP server (fake tools only). The
//! daemon runs in a temp home. The first runtime is built here with the
//! loopback-only `network_guard: false` so the server is ready; every reload
//! after an API write uses the daemon's own start path.

mod common;
use auxd::api::{self, ApiOptions};
use common::{http, HttpResponse};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const TOKEN: &str = "mcp-growth-token-0123456789";

async fn call(a: SocketAddr, m: &str, p: &str, b: Option<String>) -> HttpResponse {
    let (m, p) = (m.to_owned(), p.to_owned());
    tokio::task::spawn_blocking(move || http(a, &m, &p, Some(TOKEN), b.as_deref()))
        .await
        .unwrap()
}

/// A loopback MCP server answering JSON (no SSE) with two fake tools.
fn spawn_fixture() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let _ = serve_one(stream);
            });
        }
    });
    addr
}

fn serve_one(stream: std::net::TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut stream = stream;
    loop {
        let mut length = 0usize;
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        loop {
            let mut header = String::new();
            reader.read_line(&mut header)?;
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body)?;
        let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let id = request.get("id").cloned();
        let result = match request["method"].as_str() {
            Some("initialize") => serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "fixture", "version": "1"}
            }),
            Some("tools/list") => serde_json::json!({
                "tools": [
                    {"name": "LOOKUP", "inputSchema": {"type": "object"}},
                    {"name": "WRITE_NOTE", "inputSchema": {"type": "object"}}
                ]
            }),
            _ => serde_json::Value::Null,
        };
        let reply = match id {
            Some(id) if !id.is_null() => {
                serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
            }
            _ => String::new(),
        };
        let status = if reply.is_empty() {
            "202 Accepted"
        } else {
            "200 OK"
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{reply}",
            reply.len()
        )?;
        stream.flush()?;
    }
}

fn write_home(dir: &Path, fixture: SocketAddr) -> PathBuf {
    let home = dir.join(".auxesis");
    std::fs::create_dir_all(home.join("agents/main")).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version=1\nprivacy.mode=\"open\"\ndefault_agent=\"main\"\n",
    )
    .unwrap();
    std::fs::write(api::token_path(&home), TOKEN).unwrap();
    let mut server = kernel_mcp::McpServerConfig {
        id: "notes".to_owned(),
        catalog_id: None,
        data_class: kernel_mcp::McpDataClass::Sensitive,
        stdio_confirmed: false,
        stdio_confirmation: None,
        approval: None,
        network: false,
        transport: kernel_mcp::McpTransport::Http,
        url: Some(format!("http://{fixture}/mcp")),
        command: None,
        args: vec![],
        env: vec![],
        enabled: true,
        agents: [("main".to_owned(), vec!["LOOKUP".to_owned()])].into(),
    };
    // The owner approved `main = [LOOKUP]` once (the daemon key is the token).
    let approval = server.approval_binding(TOKEN.as_bytes(), None).unwrap();
    std::fs::write(
        home.join("mcp.toml"),
        format!(
            "[[server]]\nid = \"notes\"\ntransport = \"http\"\nurl = \"{}\"\n\
             enabled = true\napproval = \"{approval}\"\n[server.agents]\nmain = [\"LOOKUP\"]\n",
            server.url.take().unwrap()
        ),
    )
    .unwrap();
    home
}

/// Build a runtime from `mcp.toml` that may reach the loopback fixture, with
/// the same approval rule the daemon applies.
async fn loopback_runtime(home: &Path) -> kernel_mcp::McpRuntime {
    let config = kernel_mcp::McpConfig::load_from_path(&home.join("mcp.toml")).unwrap();
    let options = kernel_mcp::McpStartOptions {
        network_guard: false,
        confirmation_secret: Some(TOKEN.as_bytes().to_vec()),
    };
    kernel_mcp::McpRuntime::start_with(config, &Default::default(), options, &|server| {
        if server.is_approved_with(TOKEN.as_bytes(), None) {
            Ok(())
        } else {
            Err(kernel_mcp::McpServerRefusal::needs_approval(
                "approval_required",
            ))
        }
    })
    .await
}

fn mounted(slot: &RwLock<Arc<kernel_mcp::McpRuntime>>) -> usize {
    let runtime = slot.read().unwrap().clone();
    runtime.register_for_agent("main", &mut kernel_broker::ToolRegistry::new())
}

fn approved_on_disk(home: &Path) -> bool {
    let config = kernel_mcp::McpConfig::load_from_path(&home.join("mcp.toml")).unwrap();
    config.server[0].is_approved_with(TOKEN.as_bytes(), None)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn widening_http_tools_needs_approval_and_a_shrink_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = spawn_fixture();
    let home = write_home(dir.path(), fixture);
    let slot = Arc::new(RwLock::new(Arc::new(loopback_runtime(&home).await)));
    assert_eq!(mounted(&slot), 1, "the approved LOOKUP mounts");
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            mcp: Some(Arc::clone(&slot)),
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    // Growth: adding the write tool is refused with 409 and staged.
    let grow = serde_json::json!({"tools": ["LOOKUP", "WRITE_NOTE"]}).to_string();
    let grown = call(addr, "PUT", "/v1/mcp/servers/notes/agents/main", Some(grow)).await;
    assert_eq!(grown.status, 409, "{}", grown.body);
    assert!(grown.body.contains("approval_required"), "{}", grown.body);
    assert!(
        !approved_on_disk(&home),
        "the old approval no longer matches"
    );
    let listed = call(addr, "GET", "/v1/mcp/servers", None).await.json();
    assert_eq!(listed["servers"][0]["state"], "needs_approval");
    assert_eq!(listed["servers"][0]["reason"], "approval_required");
    assert_eq!(mounted(&slot), 0, "no tool of the server mounts any more");

    // Approving the new preview records the new digest.
    let preview = call(addr, "GET", "/v1/mcp/servers/notes/approval", None).await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    let preview = preview.json();
    let names: Vec<&str> = preview["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(names, ["LOOKUP", "WRITE_NOTE"]);
    let hash = preview["hash"].as_str().unwrap().to_owned();
    let approve = serde_json::json!({"hash": hash, "agent": "main"}).to_string();
    let approved = call(addr, "POST", "/v1/mcp/servers/notes/approve", Some(approve)).await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    assert!(approved_on_disk(&home));
    let listed = call(addr, "GET", "/v1/mcp/servers", None).await.json();
    assert_ne!(listed["servers"][0]["state"], "needs_approval");
    // The daemon's own reload refuses loopback HTTP; the same approved file
    // on a loopback runtime mounts both tools again.
    *slot.write().unwrap() = Arc::new(loopback_runtime(&home).await);
    assert_eq!(mounted(&slot), 2, "approval restores the tools");

    // Shrink: removing the write tool needs no approval.
    let shrink = serde_json::json!({"tools": ["LOOKUP"]}).to_string();
    let shrunk = call(
        addr,
        "PUT",
        "/v1/mcp/servers/notes/agents/main",
        Some(shrink),
    )
    .await;
    assert_eq!(shrunk.status, 200, "{}", shrunk.body);
    assert!(
        approved_on_disk(&home),
        "a shrink keeps the server approved"
    );
    let listed = call(addr, "GET", "/v1/mcp/servers", None).await.json();
    assert_ne!(listed["servers"][0]["state"], "needs_approval");
    *slot.write().unwrap() = Arc::new(loopback_runtime(&home).await);
    assert_eq!(mounted(&slot), 1);

    // A new agent is growth too, even for a tool another agent already has.
    let other = serde_json::json!({"tools": ["LOOKUP"]}).to_string();
    let added = call(
        addr,
        "PUT",
        "/v1/mcp/servers/notes/agents/mail",
        Some(other),
    )
    .await;
    assert_eq!(added.status, 409, "{}", added.body);
    assert!(!approved_on_disk(&home));
    api.shutdown();
}
