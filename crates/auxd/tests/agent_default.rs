//! A fresh install chats with Aux, the chief, which
//! is offered `delegate`; Mail is offered the mail reads, Calendar the calendar
//! read, and the chief neither. An existing config keeps the agent it
//! names: nothing is migrated.
//!
//! A delegated agent runs at least as private as its caller,
//! so a Private Aux never lets the owner's contact leave in clear, whatever
//! Mail's own or the global mode.
//!
//! The handoff takes the mode the chief's turn runs under,
//! so a switch to Open while its card waits still sends nothing clear.
//!
//! A real server on a loopback port, a provider that records every request and
//! a fictional mailbox that is never dialled. No network, Keychain or real home.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use aux_store::Store;
use auxd::api::{self, ApiHandle, ApiOptions, ToolRegistryHook};
use common::{get, post};
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::{config_path, store_path};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A fake brain and a fictional mailbox on a port nothing listens on.
const EXTRA: &str = "\n[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
model = \"fake-model\"\nkind = \"fake\"\n\n[connectors.mail]\n\n[[connectors.mail.accounts]]\n\
id = \"sim\"\nemail = \"owner@mailsim.test\"\n\n[connectors.mail.accounts.imap]\n\
host = \"127.0.0.1\"\nport = 9\nsecurity = \"tls\"\n";

/// The owner's fictional contact: never in clear in a Private body or row.
/// Her address; her name passes as written.
const CAMILLE: [&str; 1] = ["camille@exemple.fr"];

/// Records each request's text and offered tools; answers "ok", or what the
/// delegation script says when `delegating`.
#[derive(Default)]
struct Recording {
    calls: StdMutex<Vec<(String, Vec<String>)>>,
    delegating: bool,
}

#[async_trait]
impl ChatProvider for Recording {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let offered: Vec<String> = request
            .tools
            .iter()
            .map(|t| t.name().as_str().to_string())
            .collect();
        let body: Vec<&str> = request
            .messages
            .iter()
            .map(|m| m.content().as_str())
            .collect();
        self.calls
            .lock()
            .unwrap()
            .push((body.join("\n"), offered.clone()));
        if !self.delegating {
            return Ok(ChatResponse::assistant("ok"));
        }
        // The chief delegates once; Mail lists once; each answers what it read.
        let call = |name: &str, args: serde_json::Value| {
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new("call-1", name, args)],
            ))
        };
        let read = request
            .messages
            .iter()
            .rev()
            .find(|m| m.tool_call_id().is_some());
        Ok(
            match (offered.iter().any(|name| name == "delegate"), read) {
                (true, None) => call(
                    "delegate",
                    serde_json::json!({ "agent": "mail", "task": "Summarise the newest mail." }),
                ),
                (false, None) => call("mail_list", serde_json::json!({})),
                (_, Some(read)) => {
                    ChatResponse::assistant(format!("Newest: {}", read.content().as_str()))
                }
            },
        )
    }

    fn name(&self) -> &str {
        "recording"
    }
}

/// Mail's list tool: its output holds the contact.
struct FakeMailList;

#[async_trait]
impl Tool for FakeMailList {
    fn name(&self) -> &str {
        "mail_list"
    }
    fn schema(&self) -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": {}})
    }
    async fn run(&self, _: &serde_json::Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(
            "uid 12 · Invoice · from: Camille Exemple <camille@exemple.fr>",
        ))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B19
    }
    fn class(&self) -> ToolClass {
        ToolClass::default()
    }
}

fn assert_masked(texts: &[String], what: &str) {
    for text in texts {
        for value in CAMILLE {
            assert!(!text.contains(value), "{what} holds `{value}`: {text}");
        }
    }
}

struct Rig {
    dir: tempfile::TempDir,
    home: PathBuf,
    provider: Arc<Recording>,
    handle: ApiHandle,
}

impl Rig {
    /// `config` is written before the first start; `None` writes the kernel's
    /// own defaults, as a daemon did before the app named `main` the chief: an
    /// older install, whose chief is `aux`.
    fn start(config: Option<&str>, provider: Recording, tools: Option<ToolRegistryHook>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        if let Some(config) = config {
            std::fs::write(config_path(&home), format!("version = 1\n{config}\n")).unwrap();
        }
        #[allow(clippy::disallowed_methods)]
        kernel_core::Config::load_or_create(&config_path(&home)).unwrap();
        let text = std::fs::read_to_string(config_path(&home)).unwrap() + EXTRA;
        std::fs::write(config_path(&home), text).unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        let provider = Arc::new(provider);
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(Arc::clone(&provider) as Arc<dyn ChatProvider>),
            approval_timeout: Some(Duration::from_secs(30)),
            tools,
            ..ApiOptions::default()
        };
        let handle = api::spawn(&home, options).unwrap();
        Self {
            dir,
            home,
            provider,
            handle,
        }
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.provider.calls.lock().unwrap().clone()
    }

    /// The tools one app turn of `agent` is offered.
    fn offered_to(&self, agent: &str) -> Vec<String> {
        let path = format!("/v1/threads/{agent}/messages");
        let response = post(
            self.handle.addr(),
            &path,
            Some(TOKEN),
            r#"{"content":"hi"}"#,
        );
        assert_eq!(response.status, 200, "{agent}: {}", response.body);
        self.calls().pop().unwrap().1
    }

    /// One owner text on the iMessage path: the agent it ran.
    fn text(&self, content: &str) -> String {
        let agent = auxd::agent::default_chat_agent(&self.home);
        let session = Store::open(&store_path(&self.home))
            .unwrap()
            .create_session_of_kind(&agent, Some("iMessage"), "chat")
            .unwrap();
        let _ = self.handle.channel_access().run_turn(session.id, content);
        agent
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_install_chats_with_aux_and_its_team_reads_mail_and_calendar() {
    let rig = Rig::start(None, Recording::default(), None);
    assert_eq!(auxd::agent::default_chat_agent(&rig.home), "aux");
    tokio::task::block_in_place(|| {
        let chief = rig.offered_to("aux");
        assert!(chief.iter().any(|name| name == "delegate"), "{chief:?}");
        // Refused for the chief on every call (D33), so not offered.
        let raw = |name: &String| name.starts_with("mail_") || name.starts_with("apple_calendar");
        assert!(!chief.iter().any(raw), "{chief:?}");
        let mail = rig.offered_to("mail");
        for tool in ["mail_list", "mail_search", "mail_thread", "mail_read"] {
            assert!(mail.iter().any(|name| name == tool), "{mail:?}");
        }
        let calendar = rig.offered_to("calendar");
        assert!(calendar
            .iter()
            .any(|name| name == "apple_calendar_list_events"));
    });
}

/// A domain agent is not offered `shell` by default, so Mail
/// reads mail with its mail tools and never hunts the disk. An agent.md that
/// lists `shell` asks for it explicitly and gets it; the chief is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn domain_agents_are_not_offered_the_shell_by_default() {
    let rig = Rig::start(None, Recording::default(), None);
    tokio::task::block_in_place(|| {
        let chief = rig.offered_to("aux");
        assert!(chief.iter().any(|name| name == "shell"), "{chief:?}");
        for agent in ["mail", "calendar", "clients", "documents"] {
            let offered = rig.offered_to(agent);
            assert!(
                !offered.iter().any(|name| name == "shell"),
                "{agent}: {offered:?}"
            );
        }
        let mail = rig.offered_to("mail");
        for tool in ["mail_list", "mail_search", "mail_read"] {
            assert!(mail.iter().any(|name| name == tool), "{mail:?}");
        }
        // The explicit ask: agent.md lists `shell` next to the mail reads.
        let dir = rig.home.join("agents").join("mail");
        std::fs::create_dir_all(&dir).unwrap();
        let md = "---\nname: mail\ntools: [shell, mail_list]\n---\nAgent.\n";
        std::fs::write(dir.join("agent.md"), md).unwrap();
        let asked = rig.offered_to("mail");
        assert!(asked.iter().any(|name| name == "shell"), "{asked:?}");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_naming_main_runs_the_main_chief() {
    let rig = Rig::start(Some("default_dot = \"main\""), Recording::default(), None);
    assert_eq!(tokio::task::block_in_place(|| rig.text("hello")), "main");
    assert!(rig.calls()[0].1.iter().any(|name| name == "delegate"));
}

/// Aux asks Mail for the newest mail under the global `mode`, with `layers`
/// (agent, default_mode) as agent.md files. Every request of either agent,
/// every stored row and the delegation row hold tokens only. With
/// `open_on_card`, Aux's delegate asks; the owner turns the config Open while
/// the card waits, then allows it.
fn assert_delegation_masked(mode: &str, layers: &[(&str, &str)], open_on_card: bool) {
    let tools: ToolRegistryHook = Arc::new(|registry| {
        registry.register(Box::new(FakeMailList));
        registry.mark_read_only("mail_list");
    });
    // The owner lets Aux delegate without a card (agents.rs does the same).
    let rule = "\n\n[[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"";
    // The card case asks: an explicit `ask` rule wins over the default `auto`.
    let ask = rule.replace("\"allow\"", "\"ask\"");
    let rule = if open_on_card { ask.as_str() } else { rule };
    let config = format!("default_agent = \"aux\"\n\n[privacy]\nmode = \"{mode}\"{rule}");
    let provider = Recording {
        delegating: true,
        ..Recording::default()
    };
    let rig = Rig::start(Some(&config), provider, Some(tools));
    for (agent, layer) in layers {
        let dir = rig.home.join("agents").join(agent);
        std::fs::create_dir_all(&dir).unwrap();
        let md = format!("---\nname: {agent}\ndefault_mode: {layer}\ntools: []\n---\nAgent.\n");
        std::fs::write(dir.join("agent.md"), md).unwrap();
    }
    let card = rig.dir.path().join("camille.vcf");
    let vcard =
        "BEGIN:VCARD\nVERSION:3.0\nFN:Camille Exemple\nEMAIL:camille@exemple.fr\nEND:VCARD\n";
    std::fs::write(&card, vcard).unwrap();
    let body = serde_json::json!({ "path": card, "dry_run": false }).to_string();
    let imported = post(rig.handle.addr(), "/v1/contacts/import", Some(TOKEN), &body);
    assert_eq!(imported.status, 200, "{}", imported.body);
    let owner = open_on_card.then(|| {
        let (addr, path) = (rig.handle.addr(), config_path(&rig.home));
        std::thread::spawn(move || {
            let card = loop {
                let pending = get(addr, "/v1/approvals?state=pending", Some(TOKEN)).json();
                if let Some(card) = pending.as_array().and_then(|list| list.first()) {
                    break card["id"].as_str().unwrap().to_string();
                }
                std::thread::sleep(Duration::from_millis(25));
            };
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(text.contains("mode = \"private\""), "{text}");
            std::fs::write(&path, text.replace("mode = \"private\"", "mode = \"open\"")).unwrap();
            let allow = r#"{"decision":"allow_once"}"#;
            let path = format!("/v1/approvals/{card}");
            assert_eq!(post(addr, &path, Some(TOKEN), allow).status, 200);
        })
    });
    assert_eq!(rig.text("What is my newest mail?"), "aux");
    if let Some(owner) = owner {
        owner.join().unwrap();
        // The switch stops the chief's turn and, with it, Mail's:
        // the record is closed, and whatever Mail sent first is still masked.
        let store = Store::open(&store_path(&rig.home)).unwrap();
        let states = || -> Vec<String> {
            let rows = store.list_delegations(None).unwrap();
            rows.iter()
                .map(|row| row.state.as_str().to_string())
                .collect()
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let closed = |states: Vec<String>| states == ["stopped"] || states == ["failed"];
        while !closed(states()) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            closed(states()),
            "the delegation stayed open: {:?}",
            states()
        );
        let calls = rig.calls();
        let asked = calls
            .iter()
            .filter(|(_, tools)| tools.iter().any(|t| t == "delegate"));
        assert_eq!(asked.count(), 1, "the chief read nothing after the switch");
        let bodies: Vec<String> = calls.into_iter().map(|(body, _)| body).collect();
        assert_masked(&bodies, "a request");
        return;
    }

    // Aux asks, Mail lists and answers, Aux reads the result. Mail is never
    // offered `delegate`, so a delegation cannot chain.
    let calls = rig.calls();
    let chief: Vec<bool> = calls
        .iter()
        .map(|(_, tools)| tools.iter().any(|t| t == "delegate"))
        .collect();
    assert_eq!(chief, [true, false, false, true], "{calls:#?}");
    let bodies: Vec<String> = calls.into_iter().map(|(body, _)| body).collect();
    assert_masked(&bodies, "a request");
    assert!(bodies[2].contains('⟦'), "Mail reads tokens: {}", bodies[2]);
    // Mail's tool-output tokens are not in its display table yet,
    // so the chief reads them escaped; the delegation unit test pins the resolve.
    let chief_read = &bodies[3];
    assert!(
        chief_read.contains("Newest: uid 12 · Invoice · from: Camille Exemple <⟦"),
        "{chief_read}"
    );

    let store = Store::open(&store_path(&rig.home)).unwrap();
    let mut rows: Vec<String> = Vec::new();
    for session in store.list_sessions().unwrap() {
        rows.extend(
            store
                .list_messages(session.id)
                .unwrap()
                .into_iter()
                .map(|m| m.content),
        );
    }
    for delegation in store.list_delegations(None).unwrap() {
        rows.push(delegation.task);
        rows.extend(delegation.result);
    }
    assert!(
        rows.iter().any(|row| row.starts_with("Newest:")),
        "{rows:#?}"
    );
    assert_masked(&rows, "a stored row");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_private_delegation_never_sends_the_agents_names_in_clear() {
    tokio::task::block_in_place(|| assert_delegation_masked("private", &[], false));
}

/// Under global Open, a Private Aux makes an Open Mail agent run
/// Private: its provider sees tokens, never the contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_private_chief_makes_an_open_mail_agent_private() {
    let layers = [("aux", "private"), ("mail", "open")];
    tokio::task::block_in_place(|| assert_delegation_masked("open", &layers, false));
}

/// The chief's turn runs Private and its delegate card waits; the
/// owner switches to Open, then allows it. Mail still runs Private: its
/// provider never sees the contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_switch_to_open_while_the_card_waits_keeps_the_delegation_private() {
    tokio::task::block_in_place(|| assert_delegation_masked("private", &[], true));
}
