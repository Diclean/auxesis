//! Hero acceptance test: the invite skill end to end, rewired for MA4 to
//! **fake SMTP plus the fake EventKit bridge**. Every GIVEN / WHEN / THEN of
//! the flow is an assertion below.
//!
//! The brain is picked by `AUX_HERO_BRAIN=fake|cloud|ollama-cloud` (default
//! `fake`):
//!
//! * `fake`: a scripted OpenAI-compatible endpoint. CI runs this.
//! * `cloud`: `AUX_HERO_CLOUD_URL`, `AUX_HERO_CLOUD_KEY`, `AUX_HERO_CLOUD_MODEL`.
//! * `ollama-cloud`: the same hosted path with `AUX_HERO_OLLAMA_CLOUD_URL`,
//!   `AUX_HERO_OLLAMA_CLOUD_KEY` and `AUX_HERO_OLLAMA_CLOUD_MODEL`. Optional leg.
//!
//! Every brain sits behind the same loopback recorder, and the engine talks to
//! it through the real `OpenAiCompat` adapter. The provider-side assertions
//! read the exact HTTP bodies the brain received. `cloud` and `ollama-cloud`
//! skip when their env is missing. The assertions are the same for every
//! brain; only the exact wording of the reply and the mail body depend on the
//! scripted brain.
//!
//! A test that does not run its assertions records `skipped`, never `passed`,
//! in the file named by `AUX_HERO_REPORT` (phase1.md §6). The nightly summary
//! reads that file.
//!
//! The invite path is native: the model calls `calendar.create_event` (answered
//! by the fake EventKit bridge) and `mail.send` (delivered to the fake SMTP
//! server). The `.ics` the runtime builds carries the **real** recipient and no
//! token delimiter anywhere.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use aux_engine::{ChatError, ChatSession, ChatSetup};
use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security, SmtpSettings};
use aux_mail::dial::Dialer;
use aux_mail::imap_read::Credentials;
use aux_mail::limits::Limits;
use aux_mail::{MailService, MailToolset};
use aux_providers::{OpenAiCompat, ProviderConfig, ProviderKind};
use aux_store::{Store, StoreHandle};
use auxd::bridge::{Bridge, BridgeAnswer};
use auxd::skill_executor::{attach_skill_runtime, register_eventkit_tools, SkillConnectors};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use kernel_broker::{ApprovalRequest, Approver, ApproverError, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::PrivacyMode;
use kernel_core::ContextConfig;
use kernel_privacy::ContactIndex;
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SEND_INVITE: &str =
    include_str!("../../crates/aux-runtime/src/skills/fixtures/skills/send-invite.md");

const AGENT: &str = "---
name: assistant
brain: cloud
default_mode: private
channels: [mac]
tools:
  - calendar.create_event
  - mail.send
recipients:
  policy: known-contacts
  allowlist: []
---
Hero acceptance assistant.
";

const OWNER_MESSAGE: &str = "/invite Camille Exemple camille@exemple.fr tomorrow 10:00";
const PLAIN_MESSAGE: &str = "Send camille@exemple.fr a short hello by mail.";
const SKILL_TOOL: &str = "skill__send-invite";
const MAIL_SEND_TOOL: &str = "mail_send";
const EVENTKIT_TOOL: &str = "apple_calendar_create_event";
/// The substrings the provider must never receive in Private mode.
/// What a private provider never receives; names pass (NAMES-OFF, 2026-10-19).
const PRIVATE_VALUES: [&str; 1] = ["camille@exemple.fr"];

// ---------------------------------------------------------------------------
// Brains
// ---------------------------------------------------------------------------

/// Where the recorder sends a completion request.
#[derive(Clone)]
enum Upstream {
    /// The scripted brain answers in process.
    Scripted,
    /// A real OpenAI-compatible API root (`…/v1`). The key, when any, is added
    /// here by the recorder: the engine's adapter never holds it.
    Forward {
        base_url: String,
        key: Option<String>,
    },
}

/// The brain chosen by `AUX_HERO_BRAIN`.
struct Brain {
    label: &'static str,
    upstream: Upstream,
    model: String,
    /// Send DeepSeek's thinking toggle: thinking mode refuses a forced tool.
    disable_thinking: bool,
}

impl Brain {
    fn scripted(&self) -> bool {
        matches!(self.upstream, Upstream::Scripted)
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// The brain for this run, or the reason it cannot run.
fn brain_from_env() -> Result<Brain, String> {
    let choice = env("AUX_HERO_BRAIN").unwrap_or_else(|| "fake".to_string());
    match choice.as_str() {
        "fake" => Ok(Brain {
            label: "fake",
            upstream: Upstream::Scripted,
            model: "hero-fake".to_string(),
            disable_thinking: false,
        }),
        // The nightly sets this for DeepSeek: thinking mode refuses a forced
        // tool_choice, so the toggle is off for the cloud leg only.
        "cloud" => hosted_brain(
            "cloud",
            "AUX_HERO_CLOUD",
            env("AUX_HERO_CLOUD_DISABLE_THINKING")
                .is_some_and(|value| matches!(value.trim(), "1" | "true")),
        ),
        "ollama-cloud" => hosted_brain("ollama-cloud", "AUX_HERO_OLLAMA_CLOUD", false),
        other => panic!("AUX_HERO_BRAIN must be fake, cloud or ollama-cloud, not `{other}`"),
    }
}

/// An OpenAI-compatible hosted brain, read from `<prefix>_URL`, `<prefix>_KEY`
/// and `<prefix>_MODEL`. The cloud and Ollama cloud legs share this path.
fn hosted_brain(
    label: &'static str,
    prefix: &str,
    disable_thinking: bool,
) -> Result<Brain, String> {
    let (Some(base_url), Some(key), Some(model)) = (
        env(&format!("{prefix}_URL")),
        env(&format!("{prefix}_KEY")),
        env(&format!("{prefix}_MODEL")),
    ) else {
        return Err(format!("set {prefix}_URL, {prefix}_KEY and {prefix}_MODEL"));
    };
    Ok(Brain {
        label,
        upstream: Upstream::Forward {
            base_url,
            key: Some(key),
        },
        model,
        disable_thinking,
    })
}

/// The brain for this run. When it cannot run, the test records a skip and
/// returns `None`, so a skipped test never reads as a pass.
fn brain_or_skip(test: &str) -> Option<Brain> {
    match brain_from_env() {
        Ok(brain) => Some(brain),
        Err(reason) => {
            let label = env("AUX_HERO_BRAIN").unwrap_or_else(|| "fake".to_string());
            eprintln!("SKIP {test} ({label}): {reason}");
            record(test, &label, Some(reason.as_str()));
            None
        }
    }
}

/// Appends `passed <test> <brain>`, or `skipped <test> <brain> <reason>` when
/// `skip` is set, to the file named by `AUX_HERO_REPORT`. Without the env var
/// this does nothing. One write per line keeps parallel tests from mixing.
fn record(test: &str, brain: &str, skip: Option<&str>) {
    let Some(path) = env("AUX_HERO_REPORT") else {
        return;
    };
    append_report(&path, &report_line(test, brain, skip));
}

/// The report line for one test: `passed <test> <brain>`, or
/// `skipped <test> <brain> <reason>` when `skip` is set.
fn report_line(test: &str, brain: &str, skip: Option<&str>) -> String {
    match skip {
        None => format!("passed {test} {brain}\n"),
        Some(reason) => format!("skipped {test} {brain} {reason}\n"),
    }
}

/// Appends one line in a single write, so parallel tests never interleave.
fn append_report(path: &str, line: &str) {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|err| panic!("AUX_HERO_REPORT {path}: {err}"));
    file.write_all(line.as_bytes())
        .expect("write AUX_HERO_REPORT");
}

/// What the scripted brain does on its first round.
#[derive(Clone, Copy, PartialEq)]
enum Script {
    /// Fill `send-invite` from the owner's message.
    Hero,
    /// Fill `send-invite` on every round, even after a result: a model that
    /// keeps retrying the skill (F2).
    AlwaysInvite,
    /// Call `mail.send` directly from a plain conversation.
    PlainSend,
    /// Fill `send-invite` with the calendar call only, as the cloud leg did.
    /// After the runtime's refusal it retries with both calls.
    DropsMail,
}

#[derive(Clone)]
struct RecorderState {
    upstream: Upstream,
    script: Script,
    bodies: Arc<StdMutex<Vec<String>>>,
    responses: Arc<StdMutex<Vec<String>>>,
    client: reqwest::Client,
}

/// The loopback endpoint the engine's adapter calls. It keeps every request
/// body verbatim, then answers from the script or forwards upstream.
struct Recorder {
    base_url: String,
    bodies: Arc<StdMutex<Vec<String>>>,
    responses: Arc<StdMutex<Vec<String>>>,
    server: tokio::task::JoinHandle<()>,
}

impl Recorder {
    async fn start(upstream: Upstream, script: Script) -> Recorder {
        let bodies = Arc::new(StdMutex::new(Vec::new()));
        let responses = Arc::new(StdMutex::new(Vec::new()));
        let state = RecorderState {
            upstream,
            script,
            bodies: Arc::clone(&bodies),
            responses: Arc::clone(&responses),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .unwrap(),
        };
        let app = axum::Router::new()
            .route("/v1/chat/completions", axum::routing::post(completions))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Recorder {
            base_url: format!("http://{addr}/v1"),
            bodies,
            responses,
            server,
        }
    }

    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }

    fn responses(&self) -> Vec<String> {
        self.responses.lock().unwrap().clone()
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn completions(
    axum::extract::State(state): axum::extract::State<RecorderState>,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    state.bodies.lock().unwrap().push(body.clone());
    match &state.upstream {
        Upstream::Scripted => {
            let reply = scripted_reply(state.script, &body);
            state.responses.lock().unwrap().push(reply.to_string());
            axum::Json(reply).into_response()
        }
        Upstream::Forward { base_url, key } => {
            let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
            let mut request = state
                .client
                .post(url)
                .header("content-type", "application/json")
                .body(body);
            if let Some(key) = key {
                request = request.bearer_auth(key);
            }
            match request.send().await {
                Ok(upstream) => {
                    let status = axum::http::StatusCode::from_u16(upstream.status().as_u16())
                        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
                    let content_type = upstream
                        .headers()
                        .get("content-type")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("application/json")
                        .to_string();
                    let bytes = upstream.bytes().await.unwrap_or_default();
                    state
                        .responses
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&bytes).into_owned());
                    (status, [("content-type", content_type)], bytes.to_vec()).into_response()
                }
                Err(_) => (
                    axum::http::StatusCode::BAD_GATEWAY,
                    "hero recorder: upstream unreachable",
                )
                    .into_response(),
            }
        }
    }
}

/// The text of a wire message's `content` (a string or a list of parts).
fn content_text(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The first `⟦<kind>…⟧` token in `text`, delimiters included.
fn token(text: &str, kind: &str) -> Option<String> {
    let start = text.find(&format!("⟦{kind}"))?;
    let end = text[start..].find('⟧')? + start + '⟧'.len_utf8();
    Some(text[start..end].to_string())
}

/// The scripted brain. Round one: the script's tool call. Once a tool result
/// is in the conversation: a plain-text reply.
fn scripted_reply(script: Script, body: &str) -> Value {
    let request: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let messages = request["messages"].as_array().cloned().unwrap_or_default();
    let last_tool = messages
        .iter()
        .rev()
        .find(|message| message["role"] == "tool")
        .map(content_text);
    // Only the refusal of a dropped call makes DropsMail fill again.
    let refused = last_tool
        .as_deref()
        .is_some_and(|text| text.contains("exactly these calls"));
    if script != Script::AlwaysInvite
        && last_tool.is_some()
        && !(script == Script::DropsMail && refused)
    {
        return text_reply("Invitation envoyée.");
    }
    match script {
        Script::Hero | Script::AlwaysInvite | Script::DropsMail => {
            let owner = messages
                .iter()
                .rev()
                .find(|message| message["role"] == "user")
                .map(content_text)
                .unwrap_or_default();
            // Tokens when the kernel masked the owner's values (Private), the
            // owner's own text otherwise (Open). `email` is derived from
            // `person`, so the model invents an address in every recipient
            // field and the runtime replaces each with the contact's.
            let person = token(&owner, "PERSON_").unwrap_or_else(|| "Camille Exemple".to_string());
            let mut arguments = json!({
                "slots": {
                    "person": person,
                    "when": "2026-10-11T10:00:00+02:00",
                    "duration": "PT30M",
                },
                "calls": [
                    {
                        "tool": EVENTKIT_TOOL,
                        "arguments": {
                            "title": format!("Meeting with {person}"),
                            "start": "2026-10-11T10:00:00+02:00",
                            "end": "2026-10-11T10:30:00+02:00",
                            "notes": format!("Invitation pour {person}"),
                        },
                    },
                    {
                        "tool": MAIL_SEND_TOOL,
                        "arguments": {
                            "to": ["billing@invented.example"],
                            "subject": "Invitation",
                            "body": format!("Bonjour, invitation confirmée avec {person}."),
                            "ics": "event",
                        },
                    },
                ],
            });
            if script == Script::DropsMail && !refused {
                arguments["calls"].as_array_mut().unwrap().truncate(1);
            }
            tool_call_reply(SKILL_TOOL, &arguments)
        }
        Script::PlainSend => tool_call_reply(
            MAIL_SEND_TOOL,
            &json!({
                "to": ["camille@exemple.fr"],
                "subject": "Hello",
                "body": "Hello.",
            }),
        ),
    }
}

fn tool_call_reply(name: &str, arguments: &Value) -> Value {
    json!({
        "id": "chatcmpl-hero",
        "object": "chat.completion",
        "model": "hero-fake",
        "choices": [{
            "index": 0,
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "call-1",
                    "type": "function",
                    "function": { "name": name, "arguments": arguments.to_string() },
                }],
            },
        }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20 },
    })
}

fn text_reply(text: &str) -> Value {
    json!({
        "id": "chatcmpl-hero",
        "object": "chat.completion",
        "model": "hero-fake",
        "choices": [{
            "index": 0,
            "finish_reason": "stop",
            "message": { "role": "assistant", "content": text },
        }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 },
    })
}

/// The tool names offered in one recorded request body.
fn offered_tools(body: &str) -> Vec<String> {
    let request: Value = serde_json::from_str(body).unwrap();
    request["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["function"]["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Owner approval channels
// ---------------------------------------------------------------------------

/// The owner's channel: records each card and answers `allow`.
#[derive(Default)]
struct CardRecord {
    cards: Vec<ApprovalRequest>,
}

struct ApprovingOwner {
    record: Arc<StdMutex<CardRecord>>,
}

#[async_trait]
impl Approver for ApprovingOwner {
    async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
        self.record.lock().unwrap().cards.push(request.clone());
        Ok(true)
    }
}

/// How long the silent owner's card stayed open: tokio (virtual) time and
/// wall-clock time.
#[derive(Default)]
struct Silence {
    cards: usize,
    virtual_wait: Option<Duration>,
    real_wait: Option<Duration>,
}

/// Resumes tokio time when the pending answer is dropped (the executor's
/// clock won the race), and records how long the card stayed open.
struct ResumeOnDrop {
    silence: Arc<StdMutex<Silence>>,
    virtual_start: tokio::time::Instant,
    real_start: std::time::Instant,
}

impl Drop for ResumeOnDrop {
    fn drop(&mut self) {
        let mut silence = self.silence.lock().unwrap();
        silence.virtual_wait = Some(self.virtual_start.elapsed());
        silence.real_wait = Some(self.real_start.elapsed());
        drop(silence);
        tokio::time::resume();
    }
}

/// The owner who never answers. When the card arrives it pauses tokio time,
/// so the executor's 600 s clock fires without a real 600 s sleep.
struct SilentOwner {
    silence: Arc<StdMutex<Silence>>,
}

#[async_trait]
impl Approver for SilentOwner {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        self.silence.lock().unwrap().cards += 1;
        tokio::time::pause();
        let _guard = ResumeOnDrop {
            silence: Arc::clone(&self.silence),
            virtual_start: tokio::time::Instant::now(),
            real_start: std::time::Instant::now(),
        };
        std::future::pending().await
    }
}

/// An owner who must never be asked.
struct NeverAsked(Arc<StdMutex<usize>>);

#[async_trait]
impl Approver for NeverAsked {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        *self.0.lock().unwrap() += 1;
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// The fake SMTP server (plaintext, no credential) and the fake bridge
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SmtpState {
    commands: StdMutex<Vec<String>>,
    accepted: StdMutex<Vec<String>>,
}

/// A tiny hand-rolled SMTP server bound to loopback. It relays for anyone and
/// records every command and every accepted `DATA` body.
struct FakeSmtp {
    port: u16,
    state: Arc<SmtpState>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeSmtp {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(SmtpState::default());
        let server_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&server_state);
                tokio::spawn(serve_smtp(stream, state));
            }
        });
        Self { port, state, task }
    }

    fn mail_from_count(&self) -> usize {
        self.state
            .commands
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.to_ascii_uppercase().starts_with("MAIL FROM"))
            .count()
    }

    fn accepted(&self) -> Vec<String> {
        self.state.accepted.lock().unwrap().clone()
    }
}

impl Drop for FakeSmtp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_smtp(mut stream: tokio::net::TcpStream, state: Arc<SmtpState>) {
    let _ = stream.write_all(b"220 aux hero fake ESMTP\r\n").await;
    let mut line = Vec::new();
    let mut in_data = false;
    let mut data = String::new();
    loop {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            line.clear();
            if in_data {
                if text == "." {
                    state
                        .accepted
                        .lock()
                        .unwrap()
                        .push(std::mem::take(&mut data));
                    in_data = false;
                    let _ = stream.write_all(b"250 2.0.0 Ok: queued\r\n").await;
                } else {
                    data.push_str(&text);
                    data.push_str("\r\n");
                }
                continue;
            }
            state.commands.lock().unwrap().push(text.clone());
            let upper = text.to_ascii_uppercase();
            let reply: &[u8] = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                b"250-aux hero fake\r\n250 8BITMIME\r\n"
            } else if upper.starts_with("DATA") {
                in_data = true;
                data.clear();
                b"354 End data with <CR><LF>.<CR><LF>\r\n"
            } else if upper.starts_with("QUIT") {
                let _ = stream.write_all(b"221 2.0.0 Bye\r\n").await;
                return;
            } else {
                b"250 2.0.0 Ok\r\n"
            };
            let _ = stream.write_all(reply).await;
        } else {
            line.push(byte[0]);
        }
    }
}

/// A fake Mac app: it answers every `eventkit.create_event` request and records
/// the (rehydrated) argument object.
struct FakeBridge {
    bridge: Arc<Bridge>,
    frames: Arc<StdMutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeBridge {
    fn start(home: &Path) -> Self {
        let (events, mut receiver) = tokio::sync::broadcast::channel(64);
        let bridge = Arc::new(Bridge::new(home.to_path_buf(), events));
        let frames = Arc::new(StdMutex::new(Vec::new()));
        let recorded = Arc::clone(&frames);
        let answering = Arc::clone(&bridge);
        let task = tokio::spawn(async move {
            while let Ok(text) = receiver.recv().await {
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                if value["type"] != "bridge.request" || value["op"] != "eventkit.create_event" {
                    continue;
                }
                recorded.lock().unwrap().push(value["args"].clone());
                if let Some(id) = value["id"].as_str() {
                    answering.answer(
                        id,
                        BridgeAnswer::Result(json!({"event_id": "evt-1", "calendar": "Home"})),
                    );
                }
            }
        });
        Self {
            bridge,
            frames,
            task,
        }
    }

    fn frames(&self) -> Vec<Value> {
        self.frames.lock().unwrap().clone()
    }
}

impl Drop for FakeBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

/// A mail credential source with no password: the plaintext fake relays
/// without authentication.
struct NoCredentials;

impl Credentials for NoCredentials {
    fn password(&self, _account: &str) -> Option<String> {
        None
    }
}

/// One run's home (agent + skill), store, fake SMTP and fake bridge.
struct Rig {
    _dir: TempDir,
    home: PathBuf,
    workspace: PathBuf,
    store: Arc<StdMutex<Store>>,
    smtp: FakeSmtp,
    bridge: FakeBridge,
}

async fn rig() -> Rig {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let agent_dir = home.join("agents").join("assistant");
    std::fs::create_dir_all(agent_dir.join("skills")).unwrap();
    std::fs::write(agent_dir.join("agent.md"), AGENT).unwrap();
    std::fs::write(agent_dir.join("skills").join("send-invite.md"), SEND_INVITE).unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let smtp = FakeSmtp::start().await;
    let bridge = FakeBridge::start(&home);
    Rig {
        _dir: dir,
        home,
        workspace,
        store: Arc::new(StdMutex::new(Store::open_in_memory().unwrap())),
        smtp,
        bridge,
    }
}

/// The mail service over the fake SMTP, with the account configured for an
/// explicit plaintext relay (no credential, so nothing can leak).
fn mail_toolset(rig: &Rig) -> MailToolset {
    let account = MailAccount {
        id: "personal".to_string(),
        email: "me@example.org".to_string(),
        display: None,
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: 1,
            security: Security::Tls,
            username: None,
            ca_file: None,
        },
        smtp: Some(SmtpSettings {
            host: "127.0.0.1".to_string(),
            port: rig.smtp.port,
            security: Security::Plain,
            username: None,
            ca_file: None,
        }),
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    };
    let service = MailService::new(
        Dialer::new(Duration::from_secs(5)),
        Limits::default(),
        vec![account],
        Arc::new(NoCredentials),
    );
    MailToolset::new(Arc::new(service), None)
}

/// The contacts index: "Camille Exemple <camille@exemple.fr>".
fn contacts() -> Arc<ContactIndex> {
    let mut index = ContactIndex::new();
    assert!(
        index
            .add_from_header("Camille Exemple", "camille@exemple.fr")
            .is_some(),
        "the contact is indexed"
    );
    Arc::new(index)
}

/// Run one owner turn through the daemon's attach helper, with `brain` behind
/// the recorder. Returns the turn's result and every body the brain received.
async fn drive(
    rig: &Rig,
    brain: &Brain,
    script: Script,
    mode: PrivacyMode,
    approver: Arc<dyn Approver>,
    message: &str,
) -> (Result<String, ChatError>, Vec<String>, String) {
    let recorder = Recorder::start(brain.upstream.clone(), script).await;
    let provider = OpenAiCompat::with_key_and_timeout(
        &ProviderConfig {
            disable_thinking: brain.disable_thinking,
            id: "hero".to_string(),
            base_url: recorder.base_url.clone(),
            model: brain.model.clone(),
            key_user: None,
            kind: ProviderKind::OpenAiCompat,
        },
        None,
        Duration::from_secs(300),
    )
    .unwrap();
    let mut registry = ToolRegistry::with_defaults();
    let toolset = mail_toolset(rig);
    for tool in toolset.tools() {
        registry.register_native(tool);
    }
    register_eventkit_tools(Arc::clone(&rig.bridge.bridge), &mut registry);
    let registry = Arc::new(RwLock::new(registry));
    let budgets = Budgets::default();
    let prices = PriceTable::default();
    let mode_fn: kernel_core::privacy::ModeFn = Arc::new(move || mode);
    let contacts = contacts();
    let session = ChatSession::start(ChatSetup {
        mode: mode_fn,
        contacts: Arc::clone(&contacts),
        store: StoreHandle::Shared(Arc::clone(&rig.store)),
        provider: &provider,
        registry,
        rules: Vec::new(),
        approver,
        agent: "assistant".to_string(),
        home: rig.home.clone(),
        skills: Vec::new(),
        budgets: &budgets,
        prices: &prices,
        context: ContextConfig::default(),
        title: None,
        stop: None,
        cancel: None,
        session_id: None,
        events: None,
        run_id: Some("hero-run".to_string()),
    })
    .unwrap();
    let mut session = attach_skill_runtime(
        session,
        SkillConnectors {
            mail: Some(toolset),
            bridge: Some(Arc::clone(&rig.bridge.bridge)),
            owner_email: Some("me@example.org".to_string()),
            mode: Some(Arc::new(move || mode)),
            #[cfg(feature = "google")]
            google: None,
            ..Default::default()
        },
        "assistant",
        rig.workspace.clone(),
        Some("hero-run".to_string()),
        contacts,
    );
    let session_id = session.session().id;
    let outcome = session.send(message).await.map(|out| out.text);
    drop(session);
    let messages = rig
        .store
        .lock()
        .unwrap()
        .list_messages(session_id)
        .unwrap_or_default();
    let bodies = recorder.bodies();
    let mut diagnosis = diagnose(&outcome, &bodies, &recorder.responses(), &messages);
    for kind in [
        "skill.approval",
        "skill.action",
        "skill.action.error",
        "skill.run",
        "skill.load_error",
    ] {
        for row in rows(&rig.store, kind) {
            diagnosis.push_str(&format!(
                "\n[diagnosis] ledger {kind}: {}",
                clip(&row.to_string(), 300)
            ));
        }
    }
    (outcome, bodies, diagnosis)
}

/// Clip to `max` characters, marking a cut.
fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max).collect();
    format!("{head}…")
}

/// What a run left behind, for the log when a card count is wrong.
fn diagnose(
    outcome: &Result<String, ChatError>,
    bodies: &[String],
    responses: &[String],
    messages: &[aux_store::Message],
) -> String {
    let mut lines = vec!["[diagnosis] hero run".to_string()];
    match outcome {
        Ok(text) => lines.push(format!("[diagnosis] final text: {:?}", clip(text, 400))),
        Err(err) => lines.push(format!("[diagnosis] outcome error: {err}")),
    }
    for (index, body) in bodies.iter().enumerate() {
        let request: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        let tools: Vec<&str> = request["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool["function"]["name"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        let choice = request
            .get("tool_choice")
            .map_or("absent".to_string(), Value::to_string);
        lines.push(format!(
            "[diagnosis] request {index}: tool_choice={choice} tools={tools:?}"
        ));
        if let Some(raw) = responses.get(index) {
            lines.push(format!("[diagnosis] reply {index}: {}", clip(raw, 300)));
        }
    }
    for message in messages.iter().filter(|message| message.role == "tool") {
        lines.push(format!(
            "[diagnosis] tool row: {}",
            clip(&message.content, 300)
        ));
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Mail decoding
// ---------------------------------------------------------------------------

/// A decoded SMTP message: the top headers plus the plain and calendar parts.
struct DecodedMail {
    to: String,
    subject: String,
    body: String,
    ics: Option<String>,
}

fn decode_base64(text: &str) -> String {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD
        .decode(compact)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

fn decode_mail(raw: &str) -> DecodedMail {
    let normalised = raw.replace("\r\n", "\n");
    let (head, body) = normalised
        .split_once("\n\n")
        .expect("headers, blank line, body");
    let header = |name: &str| -> String {
        head.split('\n')
            .find_map(|line| {
                let (key, value) = line.split_once(": ")?;
                key.eq_ignore_ascii_case(name).then(|| value.to_string())
            })
            .unwrap_or_default()
    };
    let content_type = header("Content-Type");
    let Some(boundary) = boundary_of(&content_type) else {
        return DecodedMail {
            to: header("To"),
            subject: header("Subject"),
            body: decode_base64(body),
            ics: None,
        };
    };
    let mut plain = String::new();
    let mut ics = None;
    for part in body.split(&format!("--{boundary}")) {
        let part = part.trim_start_matches('\n');
        let Some((part_head, part_body)) = part.split_once("\n\n") else {
            continue;
        };
        let kind = part_head
            .split('\n')
            .find_map(|line| line.split_once(": "))
            .filter(|(key, _)| key.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, value)| value.to_ascii_lowercase())
            .unwrap_or_default();
        if kind.starts_with("text/calendar") {
            ics = Some(decode_base64(part_body));
        } else if kind.starts_with("text/plain") {
            plain = decode_base64(part_body);
        }
    }
    DecodedMail {
        to: header("To"),
        subject: header("Subject"),
        body: plain,
        ics,
    }
}

fn boundary_of(content_type: &str) -> Option<String> {
    let rest = content_type.split("boundary=\"").nth(1)?;
    Some(rest.split('"').next()?.to_string())
}

// ---------------------------------------------------------------------------
// Ledger helpers
// ---------------------------------------------------------------------------

fn rows(store: &Arc<StdMutex<Store>>, kind: &str) -> Vec<Value> {
    store
        .lock()
        .unwrap()
        .event_payloads(kind)
        .unwrap()
        .iter()
        .map(|payload| serde_json::from_str(payload).unwrap())
        .collect()
}

/// The hash the loader gives send-invite v1: blake3 of the file's bytes.
fn send_invite_hash() -> String {
    blake3::hash(SEND_INVITE.as_bytes()).to_hex().to_string()
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// GIVEN / WHEN / THEN, blocks 1 and 2.
async fn invite_is_approved_and_sent(brain: &Brain, mode: PrivacyMode) {
    invite_is_approved_and_sent_as(brain, mode, Script::Hero).await;
}

async fn invite_is_approved_and_sent_as(brain: &Brain, mode: PrivacyMode, script: Script) {
    let rig = rig().await;
    let record = Arc::new(StdMutex::new(CardRecord::default()));
    let owner = Arc::new(ApprovingOwner {
        record: Arc::clone(&record),
    });
    let (outcome, bodies, diagnosis) = drive(&rig, brain, script, mode, owner, OWNER_MESSAGE).await;
    let reply = outcome.expect("the hero turn completes");
    if brain.scripted() {
        assert_eq!(reply, "Invitation envoyée.");
    }

    // THEN the provider never receives "camille@exemple.fr".
    assert!(!bodies.is_empty(), "the brain received the turn");
    if script == Script::DropsMail {
        assert!(bodies.len() >= 2, "the brain retried after the refusal");
        assert!(
            bodies[1].contains("exactly these calls"),
            "[{}] the refusal reaches the model",
            brain.label
        );
    }
    let wire = bodies.join("\n");
    if mode == PrivacyMode::Private {
        for value in PRIVATE_VALUES {
            assert!(
                !wire.contains(value),
                "[{}] the provider received {value:?}",
                brain.label
            );
        }
    } else {
        assert!(wire.contains("camille@exemple.fr"), "recorder saw the turn");
    }
    let first: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(
        first["tool_choice"],
        json!({ "type": "function", "function": { "name": SKILL_TOOL } }),
        "[{}] the first round forces the skill",
        brain.label
    );
    for body in &bodies {
        assert_eq!(
            offered_tools(body),
            [SKILL_TOOL],
            "forced turn offers one tool"
        );
    }

    // AND exactly one approval is requested, listing both writes.
    let cards = record.lock().unwrap().cards.clone();
    if cards.len() != 1 {
        eprintln!("{diagnosis}");
    }
    assert_eq!(cards.len(), 1, "exactly one approval card");
    let card = &cards[0];
    assert_eq!(card.tool, SKILL_TOOL);
    assert_eq!(card.arguments["skill_hash"], send_invite_hash());
    let mut listed: Vec<&str> = card.arguments["calls"]
        .as_array()
        .expect("the card lists the run's calls")
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    listed.sort_unstable();
    if listed != [EVENTKIT_TOOL, MAIL_SEND_TOOL] {
        eprintln!("{diagnosis}");
    }
    assert_eq!(
        listed,
        [EVENTKIT_TOOL, MAIL_SEND_TOOL],
        "the card lists the calendar create and the mail send"
    );
    let approvals = rows(&rig.store, "skill.approval");
    assert_eq!(approvals.len(), 1, "one skill.approval row");
    assert_eq!(approvals[0]["decision"], "approved");
    assert_eq!(approvals[0]["level"], "each_run");

    // WHEN the owner approves THEN one EventKit create with the real title.
    // The bridge is local to the owner's Mac, so it sees the rehydrated value;
    // only the provider must never have.
    let frames = rig.bridge.frames();
    if frames.len() != 1 {
        eprintln!("{diagnosis}");
    }
    assert_eq!(frames.len(), 1, "one eventkit.create_event frame");
    let title = frames[0]["title"].as_str().unwrap_or_default();
    assert!(!title.contains('⟦') && !title.contains('⟧'));
    if brain.scripted() {
        assert!(title.contains("Camille Exemple"), "{title:?}");
    }

    // AND one SMTP message with the real recipient and no token delimiters.
    assert_eq!(rig.smtp.mail_from_count(), 1, "exactly one MAIL FROM");
    let accepted = rig.smtp.accepted();
    assert_eq!(accepted.len(), 1, "exactly one message");
    let mail = decode_mail(&accepted[0]);
    assert_eq!(mail.to, "camille@exemple.fr", "the real recipient");
    assert!(!mail.subject.contains('⟦') && !mail.subject.contains('⟧'));
    assert!(!mail.body.contains('⟦') && !mail.body.contains('⟧'));
    if brain.scripted() {
        assert!(mail.body.contains("Camille Exemple"), "{:?}", mail.body);
    }

    // AND the .ics is a METHOD:REQUEST with the real attendee and no tokens.
    // Unfold the continuation lines before checking the property values.
    let ics = mail.ics.expect("the invite carries a text/calendar part");
    let unfolded = ics.replace("\r\n ", "");
    assert!(unfolded.contains("METHOD:REQUEST"), "{unfolded}");
    assert!(
        unfolded.contains("mailto:camille@exemple.fr"),
        "the real attendee: {unfolded}"
    );
    assert!(
        !ics.contains('⟦') && !ics.contains('⟧'),
        "no token delimiter in the .ics"
    );
    if brain.scripted() {
        assert!(
            unfolded.contains("SUMMARY:Meeting with Camille Exemple"),
            "{unfolded}"
        );
    }

    // AND the Ledger has two rows carrying skill_hash of send-invite v1.
    let actions = rows(&rig.store, "skill.action");
    assert_eq!(actions.len(), 2, "two skill.action rows");
    for row in &actions {
        assert_eq!(row["skill_name"], "send-invite");
        assert_eq!(row["skill_version"], "1");
        assert_eq!(row["skill_hash"], send_invite_hash());
        assert_eq!(row["outcome"], "ok", "{row}");
    }
    // AND exactly one `mail.call` row, with safe metadata and no values.
    let mail_calls = rows(&rig.store, "mail.call");
    assert_eq!(mail_calls.len(), 1, "one mail.call row per send");
    assert_eq!(mail_calls[0]["outcome"], "sent");
    assert_eq!(mail_calls[0]["ics"], true);
    assert_eq!(mail_calls[0]["reply_class"], "2xx");
    let row_text = mail_calls[0].to_string();
    assert!(!row_text.contains('@'), "no address in the row: {row_text}");
    for value in ["Camille", "Invitation", "Bonjour", "camille@exemple.fr"] {
        assert!(!row_text.contains(value), "the row carried {value:?}");
    }
}

/// Block 3: the replay, with the approval left unanswered for 600 s.
async fn unanswered_approval_sends_nothing(brain: &Brain, mode: PrivacyMode) {
    let rig = rig().await;
    let silence = Arc::new(StdMutex::new(Silence::default()));
    let owner = Arc::new(SilentOwner {
        silence: Arc::clone(&silence),
    });
    let (outcome, _bodies, diagnosis) =
        drive(&rig, brain, Script::Hero, mode, owner, OWNER_MESSAGE).await;
    outcome.expect("the turn ends normally after the timeout");

    let silence = std::mem::take(&mut *silence.lock().unwrap());
    if silence.cards != 1 {
        eprintln!("{diagnosis}");
    }
    assert_eq!(silence.cards, 1, "the replay asked once");
    let virtual_wait = silence.virtual_wait.expect("the card was dropped");
    assert!(
        virtual_wait >= Duration::from_secs(600),
        "the card stayed open 600 s of tokio time: {virtual_wait:?}"
    );
    assert!(
        silence.real_wait.unwrap() < Duration::from_secs(30),
        "no real 600 s sleep"
    );

    // THEN nothing reaches the bridge or the SMTP server.
    assert!(rig.bridge.frames().is_empty(), "no EventKit create");
    assert_eq!(rig.smtp.mail_from_count(), 0, "no MAIL FROM");
    let approvals = rows(&rig.store, "skill.approval");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0]["decision"], "timeout");
    let runs = rows(&rig.store, "skill.run");
    assert_eq!(runs.len(), 1, "one skill.run row");
    assert_eq!(runs[0]["outcome"], "timeout");
    assert_eq!(runs[0]["skill_hash"], send_invite_hash());
    assert!(rows(&rig.store, "skill.action").is_empty(), "no action ran");
    assert!(
        rows(&rig.store, "mail.call").is_empty(),
        "silence never reaches SMTP, so no mail.call row"
    );
}

/// Block 4: `mail.send` from a plain conversation. The scripted brain
/// calls it whatever `AUX_HERO_BRAIN` says: a real model is never offered the
/// tool, so only a script can force the worst case.
async fn plain_mail_send_is_refused_by_the_broker(mode: PrivacyMode) {
    let brain = Brain {
        label: "fake",
        upstream: Upstream::Scripted,
        model: "hero-fake".to_string(),
        disable_thinking: false,
    };
    let rig = rig().await;
    let asked = Arc::new(StdMutex::new(0_usize));
    let owner = Arc::new(NeverAsked(Arc::clone(&asked)));
    let (outcome, bodies, _diagnosis) =
        drive(&rig, &brain, Script::PlainSend, mode, owner, PLAIN_MESSAGE).await;
    outcome.expect("the plain turn completes");

    // The skill-only write is never offered to a plain conversation.
    for body in &bodies {
        assert!(
            !offered_tools(body).contains(&MAIL_SEND_TOOL.to_string()),
            "mail.send offered outside a skill"
        );
    }
    // THEN the broker refuses before any socket opens.
    let decisions = rows(&rig.store, "tool.decision");
    let send = decisions
        .iter()
        .find(|row| row["tool"] == MAIL_SEND_TOOL)
        .expect("the broker decided on mail.send");
    assert_eq!(send["action"], "deny", "{send}");
    assert_eq!(send["outcome"], "denied", "{send}");
    assert_eq!(send["reason"], "skill-only tool", "{send}");
    assert_eq!(*asked.lock().unwrap(), 0, "the owner is never asked");
    assert_eq!(rig.smtp.mail_from_count(), 0, "no MAIL FROM");
    assert!(rig.smtp.accepted().is_empty(), "no SMTP socket");
    assert!(rows(&rig.store, "skill.action").is_empty());
    assert!(rows(&rig.store, "skill.run").is_empty());
    assert!(
        rows(&rig.store, "mail.call").is_empty(),
        "a plain call is refused before any SMTP attempt"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// F2: a forced `/invite` runs its skill at most once per turn.
async fn invite_runs_at_most_once_per_turn(brain: &Brain, mode: PrivacyMode) {
    let rig = rig().await;
    let record = Arc::new(StdMutex::new(CardRecord::default()));
    let owner = Arc::new(ApprovingOwner {
        record: Arc::clone(&record),
    });
    let (outcome, _bodies, diagnosis) = drive(
        &rig,
        brain,
        Script::AlwaysInvite,
        mode,
        owner,
        OWNER_MESSAGE,
    )
    .await;
    outcome.expect("the turn completes, capped or not");
    let cards = record.lock().unwrap().cards.len();
    if cards != 1 {
        eprintln!("{diagnosis}");
    }
    assert_eq!(
        cards, 1,
        "[{}] one card per turn: the model called the skill again",
        brain.label
    );
    assert_eq!(
        rows(&rig.store, "skill.run").len(),
        1,
        "[{}] one run per turn",
        brain.label
    );
}

#[tokio::test]
async fn hero_forced_invite_runs_at_most_once_per_turn() {
    let Some(brain) = brain_or_skip("hero_forced_invite_runs_at_most_once_per_turn") else {
        return;
    };
    invite_runs_at_most_once_per_turn(&brain, PrivacyMode::Private).await;
    invite_runs_at_most_once_per_turn(&brain, PrivacyMode::Open).await;
    record(
        "hero_forced_invite_runs_at_most_once_per_turn",
        brain.label,
        None,
    );
}

#[tokio::test]
async fn hero_private_send_invite() {
    let Some(brain) = brain_or_skip("hero_private_send_invite") else {
        return;
    };
    invite_is_approved_and_sent(&brain, PrivacyMode::Private).await;
    unanswered_approval_sends_nothing(&brain, PrivacyMode::Private).await;
    plain_mail_send_is_refused_by_the_broker(PrivacyMode::Private).await;
    record("hero_private_send_invite", brain.label, None);
}

/// The model drops the mail call: the fill is refused with no card, then the
/// retry in the same turn sends both calls under one approval. Only the scripted
/// brain drops a call on purpose; a real brain is not steered into it.
#[tokio::test]
async fn hero_dropped_call_is_refused_then_retried() {
    let Some(brain) = brain_or_skip("hero_dropped_call_is_refused_then_retried") else {
        return;
    };
    if !brain.scripted() {
        let reason = "only the scripted brain drops a call";
        record(
            "hero_dropped_call_is_refused_then_retried",
            brain.label,
            Some(reason),
        );
        return;
    }
    invite_is_approved_and_sent_as(&brain, PrivacyMode::Private, Script::DropsMail).await;
    invite_is_approved_and_sent_as(&brain, PrivacyMode::Open, Script::DropsMail).await;
    record(
        "hero_dropped_call_is_refused_then_retried",
        brain.label,
        None,
    );
}

#[tokio::test]
async fn hero_open_invite_is_approved_and_sent() {
    let Some(brain) = brain_or_skip("hero_open_invite_is_approved_and_sent") else {
        return;
    };
    invite_is_approved_and_sent(&brain, PrivacyMode::Open).await;
    record("hero_open_invite_is_approved_and_sent", brain.label, None);
}

/// Security-review regression: the offline request the model reads for `send-invite`
/// must mark the contact slot as a name and keep the derived address hidden.
/// The live cloud model filled the slot with an address (then invented a name)
/// when it did not.
#[tokio::test]
async fn send_invite_request_shape_marks_the_contact_slot_a_name() {
    let brain = Brain {
        label: "fake",
        upstream: Upstream::Scripted,
        model: "hero-fake".to_string(),
        disable_thinking: false,
    };
    let rig = rig().await;
    let owner = Arc::new(ApprovingOwner {
        record: Arc::new(StdMutex::new(CardRecord::default())),
    });
    let (_outcome, bodies, _diagnosis) = drive(
        &rig,
        &brain,
        Script::Hero,
        PrivacyMode::Private,
        owner,
        OWNER_MESSAGE,
    )
    .await;
    let first: Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(
        first["tool_choice"],
        json!({ "type": "function", "function": { "name": SKILL_TOOL } }),
        "the first round forces the skill"
    );
    assert_eq!(
        offered_tools(&bodies[0]),
        [SKILL_TOOL],
        "forced turn offers one tool"
    );
    let slots = &first["tools"][0]["function"]["parameters"]["properties"]["slots"];
    assert!(
        slots["properties"].get("email").is_none(),
        "the derived address stays hidden: {slots}"
    );
    assert_eq!(slots["properties"]["person"]["type"], "string");
    let description = slots["properties"]["person"]["description"]
        .as_str()
        .unwrap_or_default();
    assert!(description.contains("contact's name"), "{description}");
    assert!(
        description.contains("never an email address"),
        "{description}"
    );
    assert_eq!(slots["required"], json!(["person", "when"]));
}

/// Open mode: the replay with 600 s of silence sends nothing and is refused.
#[tokio::test]
async fn hero_open_unanswered_approval_sends_nothing() {
    let Some(brain) = brain_or_skip("hero_open_unanswered_approval_sends_nothing") else {
        return;
    };
    unanswered_approval_sends_nothing(&brain, PrivacyMode::Open).await;
    record(
        "hero_open_unanswered_approval_sends_nothing",
        brain.label,
        None,
    );
}

/// Open mode: `mail.send` outside a skill is refused by the broker.
#[tokio::test]
async fn hero_open_plain_mail_send_is_refused() {
    let Some(brain) = brain_or_skip("hero_open_plain_mail_send_is_refused") else {
        return;
    };
    plain_mail_send_is_refused_by_the_broker(PrivacyMode::Open).await;
    // The broker refuses before any model runs, so this pass proves nothing
    // about the leg's brain; record the leg's own label all the same.
    record("hero_open_plain_mail_send_is_refused", brain.label, None);
}

// ---------------------------------------------------------------------------
// Harness checks (no brain, no network)
// ---------------------------------------------------------------------------

#[test]
fn report_lines_mark_passes_and_skips() {
    assert_eq!(
        report_line("hero_private_send_invite", "fake", None),
        "passed hero_private_send_invite fake\n"
    );
    assert_eq!(
        report_line(
            "hero_dropped_call_is_refused_then_retried",
            "cloud",
            Some("only the scripted brain drops a call"),
        ),
        "skipped hero_dropped_call_is_refused_then_retried cloud only the scripted brain drops a call\n"
    );
}

#[test]
fn report_file_gets_one_line_per_test() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("hero.report");
    let path = path.to_str().expect("utf-8 path");
    append_report(path, &report_line("hero_private_send_invite", "fake", None));
    append_report(
        path,
        &report_line(
            "hero_open_invite_is_approved_and_sent",
            "fake",
            Some("no key"),
        ),
    );
    assert_eq!(
        std::fs::read_to_string(path).expect("report"),
        "passed hero_private_send_invite fake\n\
         skipped hero_open_invite_is_approved_and_sent fake no key\n"
    );
}

#[test]
fn hosted_brain_without_env_names_what_to_set() {
    let Err(reason) = hosted_brain("cloud", "AUX_HERO_TEST_UNSET_PREFIX", false) else {
        panic!("an unset prefix must not make a brain");
    };
    assert_eq!(
        reason,
        "set AUX_HERO_TEST_UNSET_PREFIX_URL, AUX_HERO_TEST_UNSET_PREFIX_KEY \
         and AUX_HERO_TEST_UNSET_PREFIX_MODEL"
    );
}
