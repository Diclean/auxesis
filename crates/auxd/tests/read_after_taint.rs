//! READ-AFTER-TAINT acceptance: once outside content has tainted an agent's
//! workspace, that agent's OWN read-only domain tools (Mail's `mail_list`,
//! Calendar's `apple_calendar_list_events`) still run without a card. Sends,
//! writes, reads outside the agent's domain and an explicit owner `ask` rule
//! still ask, on the agent's own thread and through the chief's `delegate`.
//! A tainted chief's `delegate` runs without a card, and the agent it starts
//! inherits the taint, so the agent's own effectful calls still ask.
//!
//! A real server on a loopback port, a scripted fake brain, a temp home. No
//! network, Keychain or real home.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{ChatMessage, ChatProvider, ChatResponse, FakeProvider, ToolCall};
use aux_runtime::grants::ToolOrigin;
use auxd::api::{self, ApiHandle, ApiOptions, ToolRegistryHook};
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The connector stand-ins, and which of them are read-only by construction
/// (as `turn.rs` and `apple_eventkit.rs` declare the real ones).
const TOOLS: [(&str, bool); 7] = [
    ("mail_list", true),
    ("mail_read", true),
    ("mail_send", false),
    ("apple_calendar_list_events", true),
    ("apple_calendar_create_event", false),
    ("calendar_update_event", false),
    ("web_page", true),
];

/// A tool that answers "ok"; its output is untrusted, so it taints the turn.
struct Stub(&'static str);

#[async_trait]
impl Tool for Stub {
    fn name(&self) -> &str {
        self.0
    }
    fn schema(&self) -> Value {
        json!({"type": "object"})
    }
    async fn run(&self, _: &Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok("ok"))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B1
    }
    fn class(&self) -> ToolClass {
        // Like aux-mail's real tools: a wildcard `allow` never covers them.
        ToolClass {
            requires_explicit_rule: self.0.starts_with("mail_"),
            ..ToolClass::default()
        }
    }
}

fn call(name: &str) -> ChatResponse {
    let call = ToolCall::new("call-1", name, json!({}));
    ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![call]))
}

fn say(text: &str) -> ChatResponse {
    ChatResponse::assistant(text)
}

fn delegate(agent: &str) -> ChatResponse {
    let task = json!({ "agent": agent, "task": "Who wrote to me last?" });
    let call = ToolCall::new("call-1", "delegate", task);
    ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![call]))
}

struct Rig {
    dir: tempfile::TempDir,
    handle: ApiHandle,
}

impl Rig {
    /// A server whose config holds `head` and whose brain plays `script`.
    fn start(head: &str, script: Vec<ChatResponse>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let provider = "[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
                        model = \"fake-model\"\nkind = \"fake\"\n";
        let config = format!("version = 1\nprivacy.mode = \"open\"\n{head}\n\n{provider}");
        std::fs::write(config_path(&home), config).unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        let tools: ToolRegistryHook = Arc::new(|registry| {
            for (name, read_only) in TOOLS {
                registry.register(Box::new(Stub(name)));
                if read_only {
                    registry.mark_read_only(name);
                }
            }
        });
        let origin = |name: &str| match name {
            "web_page" => (name.to_string(), ToolOrigin::Builtin),
            _ => (name.to_string(), ToolOrigin::Connector),
        };
        let fake: Arc<dyn ChatProvider> = Arc::new(FakeProvider::scripted("fakey", script));
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(fake),
            approval_timeout: Some(Duration::from_secs(1)),
            tools: Some(tools),
            tool_origins: TOOLS.iter().map(|(name, _)| origin(name)).collect(),
            ..ApiOptions::default()
        };
        Self {
            handle: api::spawn(&home, options).unwrap(),
            dir,
        }
    }

    fn send(&self, agent: &str) {
        let path = format!("/v1/threads/{agent}/messages");
        let body = r#"{"content":"go"}"#;
        let response = tokio::task::block_in_place(|| {
            common::post(self.handle.addr(), &path, Some(TOKEN), body)
        });
        assert_eq!(response.status, 200, "{}", response.body);
    }

    fn rows(&self, kind: &str) -> Vec<Value> {
        let home = self.dir.path().join("home");
        let conn = aux_store::open_keyed_readonly(&store_path(&home)).unwrap();
        let sql = "SELECT payload FROM events WHERE kind = ?1 ORDER BY id";
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt
            .query_map([kind], |row| row.get::<_, String>(0))
            .unwrap();
        rows.map(|raw| serde_json::from_str(&raw.unwrap()).unwrap())
            .collect()
    }

    /// The tools that got an approval card.
    fn cards(&self) -> Vec<String> {
        let rows = self.rows("approval.pending");
        rows.iter()
            .map(|row| row["tool"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// `(outcome, tainted)` of the broker's decision for each call of `tool`.
    fn decisions(&self, tool: &str) -> Vec<(String, bool)> {
        let rows = self.rows("tool.decision").into_iter();
        rows.filter(|row| row["tool"] == tool)
            .map(|row| {
                let outcome = row["outcome"].as_str().unwrap_or_default().to_string();
                (outcome, row["tainted"] == true)
            })
            .collect()
    }
}

fn allowed(tainted: bool) -> (String, bool) {
    ("allowed".to_string(), tainted)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_a_tainted_mail_agent_lists_mail_again_without_a_card() {
    // Two owner questions on Mail's thread: the first read taints the
    // workspace, and the second question's read still runs.
    let script = vec![
        call("mail_list"),
        say("Two unread."),
        call("mail_list"),
        call("mail_read"),
        say("Ann wrote last."),
    ];
    let rig = Rig::start("default_agent = \"aux\"", script);
    rig.send("mail");
    rig.send("mail");
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(
        rig.decisions("mail_list"),
        [allowed(false), allowed(true)],
        "the second read ran while tainted"
    );
    assert_eq!(rig.decisions("mail_read"), [allowed(true)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_a_tainted_mail_agent_still_asks_to_send_or_read_the_web() {
    let script = vec![
        call("mail_list"),
        call("web_page"),
        call("mail_send"),
        say("done"),
    ];
    let rig = Rig::start("default_agent = \"aux\"", script);
    rig.send("mail");
    assert_eq!(rig.cards(), ["web_page", "mail_send"]);
    assert_eq!(rig.decisions("mail_list"), [allowed(false)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_a_tainted_calendar_agent_lists_freely_and_never_writes_unasked() {
    // `apple_calendar_create_event` is skill-only: plain chat refuses it
    // outright (no card, never runs). A plain calendar write asks.
    let script = vec![
        call("apple_calendar_list_events"),
        call("apple_calendar_list_events"),
        call("apple_calendar_create_event"),
        call("calendar_update_event"),
        say("done"),
    ];
    let rig = Rig::start("default_agent = \"aux\"", script);
    rig.send("calendar");
    assert_eq!(rig.cards(), ["calendar_update_event"]);
    assert_eq!(
        rig.decisions("apple_calendar_list_events"),
        [allowed(false), allowed(true)]
    );
    let refused = ("denied".to_string(), true);
    assert_eq!(rig.decisions("apple_calendar_create_event"), [refused]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_an_owner_ask_rule_on_mail_read_wins_clean_and_tainted() {
    let head = "default_agent = \"aux\"\n\n[[rules]]\nagent = \"mail\"\ntool = \"mail_read\"\n\
                action = \"ask\"";
    let script = vec![
        call("mail_read"),
        call("mail_list"),
        call("mail_read"),
        say("done"),
    ];
    let rig = Rig::start(head, script);
    rig.send("mail");
    assert_eq!(rig.cards(), ["mail_read", "mail_read"]);
    assert_eq!(rig.decisions("mail_list"), [allowed(false)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5_the_delegated_mail_agent_reads_after_taint_and_asks_to_send() {
    // Aux → Mail twice. Mail's result taints Aux, so the second delegate is
    // a tainted call: it runs without a card, and Mail's turn starts tainted.
    let script = vec![
        delegate("mail"),
        call("mail_list"),
        say("Two unread."),
        say("You have two unread mails."),
        delegate("mail"),
        call("mail_list"),
        call("mail_send"),
        say("Ann wrote last; the reply waits."),
        say("Ann wrote last."),
    ];
    let rig = Rig::start("default_agent = \"aux\"", script);
    rig.send("aux");
    rig.send("aux");
    assert_eq!(rig.cards(), ["mail_send"]);
    assert_eq!(rig.decisions("delegate"), [allowed(false), allowed(true)]);
    assert_eq!(rig.decisions("mail_list"), [allowed(false), allowed(true)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r6_a_tainted_delegate_result_taints_the_chiefs_next_call() {
    // Mail's own read runs free; its result carries taint back to Aux, so
    // Aux's local write afterwards runs tainted (free under ACT-FREE).
    let write = ToolCall::new(
        "call-1",
        "write_file",
        json!({ "path": "note.txt", "content": "x" }),
    );
    let script = vec![
        delegate("mail"),
        call("mail_list"),
        say("Ann wrote last."),
        ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![write])),
        say("done"),
    ];
    let rig = Rig::start("default_agent = \"aux\"", script);
    rig.send("aux");
    assert_eq!(rig.decisions("mail_list"), [allowed(false)]);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(rig.decisions("write_file"), [allowed(true)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r7_a_tainted_chief_cannot_launder_through_a_clean_agent() {
    // Aux reads an owner-allowed page (tainted), then hands Calendar a task.
    // The delegate runs without a card; Calendar's workspace was clean, but
    // it inherits Aux's taint, so its write runs tainted.
    let write = ToolCall::new(
        "call-1",
        "write_file",
        json!({ "path": "note.txt", "content": "x" }),
    );
    let script = vec![
        call("web_page"),
        delegate("calendar"),
        ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![write])),
        say("Noted."),
        say("done"),
    ];
    let head = "default_agent = \"aux\"\n\n[[rules]]\nagent = \"aux\"\ntool = \"web_page\"\n\
                action = \"allow\"";
    let rig = Rig::start(head, script);
    rig.send("aux");
    assert_eq!(rig.decisions("delegate"), [allowed(true)]);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(rig.decisions("write_file"), [allowed(true)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r8_a_later_wildcard_allow_never_hides_the_owners_delegate_ask() {
    // `aux/delegate=ask` then `aux/*=allow`. The broker never lets
    // the wildcard cover `delegate`, so a tainted hand-off still gets a card.
    let head = "default_agent = \"aux\"\n\n[[rules]]\nagent = \"aux\"\ntool = \"delegate\"\n\
                action = \"ask\"\n\n[[rules]]\nagent = \"aux\"\ntool = \"*\"\naction = \"allow\"";
    let script = vec![call("web_page"), delegate("mail"), say("done")];
    let rig = Rig::start(head, script);
    rig.send("aux");
    assert_eq!(rig.cards(), ["delegate"]);
    assert_eq!(rig.decisions("web_page"), [allowed(false)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r9_an_owner_wildcard_ask_on_mail_keeps_the_card_for_its_reads() {
    let head = "default_agent = \"aux\"\n\n[[rules]]\nagent = \"mail\"\ntool = \"*\"\n\
                action = \"ask\"";
    let rig = Rig::start(head, vec![call("mail_list"), say("done")]);
    rig.send("mail");
    assert_eq!(rig.cards(), ["mail_list"]);
}
