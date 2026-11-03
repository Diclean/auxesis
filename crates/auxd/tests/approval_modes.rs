//! APPROVAL-MODES acceptance: `approvals = "auto"` (the default) runs the
//! chief's `delegate` and local writes without a card, tainted or not, marked
//! `policy` in the audit trail with their class (ACT-FREE). After a tainted
//! mail read, reads, memory, workspace writes and an own event still run free;
//! sends, invites, deletes, unknown tools, an IBAN-carrying fetch, the shell
//! and owner ask rules keep the card, and `approvals = "ask"` cards every ask.
//!
//! A real server on a loopback port, a scripted fake brain, a temp home. No
//! network, Keychain or real home.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_providers::{ChatMessage, ChatProvider, ChatResponse, FakeProvider, ToolCall};
use aux_runtime::grants::ToolOrigin;
use auxd::api::{self, ApiHandle, ApiOptions, ToolRegistryHook};
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Connector stand-ins with the real tools' classes: `(name, read-only)`.
const CONNECTORS: [(&str, bool); 5] = [
    ("mail_list", true),
    ("mail_read", true),
    ("mail_delete", false),
    ("apple_calendar_list_events", true),
    ("google_calendar_create_event", false),
];

/// A tool that answers "ok"; its output is untrusted, so it taints the turn.
/// Mail tools require an explicit rule like aux-mail's.
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
        ToolClass {
            requires_explicit_rule: self.0.starts_with("mail_"),
            ..ToolClass::default()
        }
    }
}

fn call(name: &str, args: Value) -> ChatResponse {
    let call = ToolCall::new("call-1", name, args);
    ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![call]))
}

fn ls() -> ChatResponse {
    call("shell", json!({ "command": "ls" }))
}

fn note() -> ChatResponse {
    call("write_file", json!({ "path": "note.txt", "content": "x" }))
}

fn done() -> ChatResponse {
    ChatResponse::assistant("done")
}

/// Aux delegates once; Mail answers; Aux replies.
fn delegation() -> Vec<ChatResponse> {
    let task = json!({ "agent": "mail", "task": "Say the agreed status line." });
    let answer = ChatResponse::assistant("Three unread.");
    vec![call("delegate", task), answer, done()]
}

struct Rig {
    dir: tempfile::TempDir,
    handle: ApiHandle,
    brain: Arc<FakeProvider>,
}

impl Rig {
    /// A server whose config holds `head` (top-level keys, `[[rules]]`) and
    /// whose brain plays `script`; one owner message to `agent` has run.
    fn run(head: &str, agent: &str, script: Vec<ChatResponse>) -> Self {
        Self::seeded(head, agent, script, |_, _| {})
    }

    /// [`Rig::run`] over a store `seed` filled before the server starts.
    fn seeded(
        head: &str,
        agent: &str,
        script: Vec<ChatResponse>,
        seed: impl FnOnce(&aux_store::Store, &std::path::Path),
    ) -> Self {
        Self::with_timeout(head, agent, script, seed, Duration::from_secs(1))
    }

    fn with_timeout(
        head: &str,
        agent: &str,
        script: Vec<ChatResponse>,
        seed: impl FnOnce(&aux_store::Store, &std::path::Path),
        timeout: Duration,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        seed(&aux_store::Store::open(&store_path(&home)).unwrap(), &home);
        let provider = "[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
                        model = \"fake-model\"\nkind = \"fake\"\n";
        let config = format!("version = 1\nprivacy.mode = \"open\"\n{head}\n\n{provider}");
        std::fs::write(config_path(&home), config).unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        let tools: ToolRegistryHook = Arc::new(|registry| {
            registry.register(Box::new(Stub("imessage_send")));
            registry.register(Box::new(Stub("brand_new_tool")));
            registry.register(Box::new(Stub("web_page")));
            registry.mark_read_only("web_page");
            for (name, read_only) in CONNECTORS {
                registry.register(Box::new(Stub(name)));
                if read_only {
                    registry.mark_read_only(name);
                }
            }
        });
        let brain = Arc::new(FakeProvider::scripted("fakey", script));
        let fake: Arc<dyn ChatProvider> = brain.clone();
        let builtin = |name: &str| (name.to_string(), ToolOrigin::Builtin);
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(fake),
            approval_timeout: Some(timeout),
            tools: Some(tools),
            tool_origins: ["imessage_send", "brand_new_tool", "web_page"]
                .map(builtin)
                .into_iter()
                .chain(CONNECTORS.map(|(name, _)| (name.to_string(), ToolOrigin::Connector)))
                .collect(),
            ..ApiOptions::default()
        };
        let rig = Self {
            handle: api::spawn(&home, options).unwrap(),
            dir,
            brain,
        };
        rig.send(agent);
        rig
    }

    /// Everything the brain was sent, as one JSON text.
    fn sent(&self) -> String {
        serde_json::to_string(&self.brain.requests()).unwrap()
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn send(&self, agent: &str) {
        let (response, _) = self.try_send(agent, "go");
        assert_eq!(response.status, 200, "{}", response.body);
    }

    fn try_send(&self, agent: &str, content: &str) -> (common::HttpResponse, Duration) {
        let path = format!("/v1/threads/{agent}/messages");
        let body = serde_json::json!({ "content": content }).to_string();
        let started = Instant::now();
        let response = tokio::task::block_in_place(|| {
            common::post(self.handle.addr(), &path, Some(TOKEN), &body)
        });
        (response, started.elapsed())
    }

    fn approvals(&self) -> Vec<Value> {
        let response = common::get(self.handle.addr(), "/v1/approvals", Some(TOKEN));
        serde_json::from_str(&response.body).unwrap_or_default()
    }

    fn rows(&self, kind: &str) -> Vec<Value> {
        let conn = aux_store::open_keyed_readonly(&store_path(&self.home())).unwrap();
        let sql = "SELECT payload FROM events WHERE kind = ?1 ORDER BY id";
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt
            .query_map([kind], |row| row.get::<_, String>(0))
            .unwrap();
        rows.map(|raw| serde_json::from_str(&raw.unwrap()).unwrap())
            .collect()
    }

    /// `field` of each `kind` row that `keep` accepts, in order.
    fn column(&self, kind: &str, field: &str, keep: impl Fn(&Value) -> bool) -> Vec<String> {
        let rows = self.rows(kind).into_iter().filter(|row| keep(row));
        rows.map(|row| row[field].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// The tools that got an approval card.
    fn cards(&self) -> Vec<String> {
        self.column("approval.pending", "tool", |_| true)
    }

    /// The tools the `auto` mode's policy approved.
    fn auto(&self) -> Vec<String> {
        self.column("approval.answered", "tool", |row| row["by"] == "policy")
    }

    /// The broker's outcome for each call of `tool`.
    fn outcomes(&self, tool: &str) -> Vec<String> {
        self.column("tool.decision", "outcome", |row| row["tool"] == tool)
    }

    fn delegated(&self) -> Vec<Option<String>> {
        let store = aux_store::Store::open(&store_path(&self.home())).unwrap();
        let rows = store.list_delegations(None).unwrap();
        rows.into_iter().map(|row| row.result).collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t1_auto_runs_the_chiefs_delegation_without_a_card() {
    let rig = Rig::run("default_agent = \"aux\"", "aux", delegation());
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(rig.auto(), ["delegate"]);
    assert_eq!(rig.delegated(), [Some("Three unread.".to_string())]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t2_auto_runs_a_clean_sandboxed_write_without_a_card() {
    let rig = Rig::run("default_agent = \"main\"", "main", vec![note(), done()]);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(rig.outcomes("write_file"), ["allowed"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t3_auto_still_shows_a_card_for_a_send() {
    let send = call("imessage_send", json!({ "to": "owner", "text": "hi" }));
    let rig = Rig::run(
        "default_agent = \"main\"",
        "main",
        vec![send, note(), done()],
    );
    // The send waits for the owner (and times out here); the clean write runs.
    assert_eq!(rig.cards(), ["imessage_send"]);
    assert_eq!(rig.outcomes("imessage_send"), ["denied"]);
    assert_eq!(rig.auto(), ["write_file"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t4_a_tainted_local_write_runs_free_and_keeps_its_taint() {
    // An owner-allowed web page brings outside content into the turn; the
    // next write still runs without a card (ACT-FREE), audited as tainted.
    let head = "default_agent = \"main\"\n\n[[rules]]\nagent = \"main\"\ntool = \"web_page\"\n\
                action = \"allow\"";
    let script = vec![note(), call("web_page", json!({})), note(), done()];
    let rig = Rig::run(head, "main", script);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(rig.auto(), ["write_file", "write_file"]);
    let last = rig.rows("tool.decision").pop().unwrap();
    assert_eq!(
        (&last["tool"], &last["tainted"]),
        (&json!("write_file"), &json!(true))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t5_ask_keeps_the_delegation_card_and_auto_drops_it() {
    let mut script = delegation();
    script.truncate(1);
    script.push(ChatResponse::assistant("I could not ask Mail."));
    let ask = Rig::run(
        "default_agent = \"aux\"\napprovals = \"ask\"",
        "aux",
        script,
    );
    assert_eq!(ask.cards(), ["delegate"]);
    assert!(ask.auto().is_empty());
    assert!(ask.delegated().iter().all(Option::is_none));

    // The same delegation with the key absent: the default is auto. (A fresh
    // home: the refused delegate keeps its untrusted class in the history.)
    let auto = Rig::run("default_agent = \"aux\"", "aux", delegation());
    assert!(auto.cards().is_empty(), "{:?}", auto.cards());
    assert_eq!(auto.auto(), ["delegate"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t6_an_explicit_deny_rule_beats_auto() {
    let head = "default_agent = \"main\"\n\n[[rules]]\nagent = \"main\"\ntool = \"shell\"\n\
                action = \"deny\"";
    let write = call("write_file", json!({ "path": "note.txt", "content": "x" }));
    let rig = Rig::run(head, "main", vec![ls(), write, done()]);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(rig.outcomes("shell"), ["denied"]);
    assert_eq!(rig.auto(), ["write_file"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t7_the_audit_marks_an_auto_approved_call_as_auto() {
    let rig = Rig::run("default_agent = \"main\"", "main", vec![note(), done()]);
    let answered = rig.rows("approval.answered");
    assert_eq!(answered.len(), 1, "{answered:?}");
    let row = &answered[0];
    assert_eq!(
        (row["by"].as_str(), row["decision"].as_str()),
        (Some("policy"), Some("allow"))
    );
    assert_eq!(
        (row["agent"].as_str(), row["tool"].as_str()),
        (Some("main"), Some("write_file"))
    );
    assert_eq!(row["class"], "local_write");
    assert!(
        row["run_id"].as_str().is_some_and(|id| !id.is_empty()),
        "{row}"
    );
    // The broker's own row records the approved ask, as for a card.
    let decisions = rig.rows("tool.decision");
    let write = decisions
        .iter()
        .find(|row| row["tool"] == "write_file")
        .unwrap();
    assert_eq!(
        (write["action"].as_str(), write["approved"].as_bool()),
        (Some("ask"), Some(true))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shell_always_asks_even_for_a_plain_read() {
    // `auto` alone never runs the shell; the judge (SHELL-JUDGE) is off here.
    let rm = call("shell", json!({ "command": "rm -rf notes" }));
    let redirect = call("shell", json!({ "command": "cat x > y" }));
    let rig = Rig::run(
        "default_agent = \"main\"\n\n[approval]\nshell_judge = false",
        "main",
        vec![rm, redirect, ls(), done()],
    );
    assert_eq!(rig.cards(), ["shell", "shell", "shell"]);
    assert_eq!(rig.outcomes("shell"), ["denied", "denied", "denied"]);
    assert!(rig.auto().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shell_with_its_network_on_always_asks() {
    let head = "default_agent = \"main\"\n\n[shell]\nnetwork = true";
    let rig = Rig::run(head, "main", vec![ls(), done()]);
    assert_eq!(rig.cards(), ["shell"]);
    assert!(rig.auto().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegated_result_taints_the_chiefs_next_write() {
    let mut script = delegation();
    script.pop();
    script.push(call(
        "write_file",
        json!({ "path": "note.txt", "content": "x" }),
    ));
    script.push(done());
    let rig = Rig::run("default_agent = \"aux\"", "aux", script);
    // The write runs free (ACT-FREE) but the delegate's result tainted it.
    assert_eq!(rig.auto(), ["delegate", "write_file"]);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(rig.rows("tool.decision").last().unwrap()["tainted"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ask_rule_for_delegate_beats_a_later_wildcard_allow() {
    // The broker never lets `aux/*=allow` cover `delegate`, so `ask` decides;
    // auto must read the same rule and keep the card.
    let head = "default_agent = \"aux\"\n\n[[rules]]\nagent = \"aux\"\ntool = \"delegate\"\n\
                action = \"ask\"\n\n[[rules]]\nagent = \"aux\"\ntool = \"*\"\naction = \"allow\"";
    let rig = Rig::run(head, "aux", vec![delegation().remove(0), done()]);
    assert_eq!(rig.cards(), ["delegate"]);
    assert!(rig.auto().is_empty());
}

fn bare(name: &str) -> ChatResponse {
    call(name, json!({}))
}

const AUX: &str = "default_agent = \"aux\"";

/// CAL-BLANK-CREATE: the calendar agent definition the one-call skill needs.
const CREATE_ONLY_AGENT: &str = "---
name: calendar
tools: [calendar.create_event]
---
Create test agent.
";

/// CAL-BLANK-CREATE: a one-call create skill, so `auto` answers the run card
/// by the create's own class.
const CREATE_ONLY_SKILL: &str = "---
name: create-focus
version: 1
trigger:
  manual: true
tools: [calendar.create_event]
approval: each_run
---
Create the one event the owner asked for.
";

/// A create-only skill run, its `calendar` field absent or set to `calendar`.
fn create_focus(calendar: Option<&str>) -> Vec<ChatResponse> {
    let mut event = json!({
        "title": "Focus",
        "start": "2026-10-20T09:00:00+02:00",
        "end": "2026-10-20T09:30:00+02:00",
    });
    if let Some(calendar) = calendar {
        event["calendar"] = json!(calendar);
    }
    let fill = json!({
        "slots": {},
        "calls": [{ "tool": "apple_calendar_create_event", "arguments": event }],
    });
    vec![call("skill__create-focus", fill), done()]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a1_reads_memory_and_workspace_writes_run_free_after_a_tainted_mail_read() {
    let remember = json!({ "text": "Ann wrote about the invoice." });
    let script = vec![
        bare("mail_list"),
        bare("mail_read"),
        call("recall", json!({ "query": "Ann" })),
        call("remember", remember),
        note(),
        done(),
    ];
    let rig = Rig::run(AUX, "mail", script);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert_eq!(
        rig.auto(),
        ["mail_read", "recall", "remember", "write_file"]
    );
    let classes = rig.column("approval.answered", "class", |row| row["by"] == "policy");
    assert_eq!(classes, ["read", "read", "local_write", "local_write"]);
    assert_eq!(rig.rows("tool.decision").last().unwrap()["tainted"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2_an_own_event_runs_free_and_an_invite_or_a_named_calendar_asks() {
    let event = json!({ "title": "Focus", "start": "2026-10-20T09:00:00Z" });
    let invite = json!({ "title": "Call", "attendees": ["ann@example.test"] });
    let shared = json!({ "title": "Focus", "calendar": "Team" });
    let create = "google_calendar_create_event";
    let script = vec![
        bare("apple_calendar_list_events"),
        call(create, event),
        call(create, invite),
        call(create, shared),
        done(),
    ];
    let rig = Rig::run(AUX, "calendar", script);
    assert_eq!(rig.cards(), [create, create]);
    assert_eq!(rig.auto(), [create]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2b_an_owner_deny_beats_the_generated_calendar_write_ask() {
    let rule = "\n\n[[rules]]\nagent = \"calendar\"\ntool = \"google_calendar_create_event\"\n\
                action = \"deny\"";
    let event = json!({ "title": "Focus", "start": "2026-10-20T09:00:00Z" });
    let script = vec![call("google_calendar_create_event", event), done()];
    let rig = Rig::run(&format!("{AUX}{rule}"), "calendar", script);
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    assert!(rig.auto().is_empty(), "{:?}", rig.auto());
    assert_eq!(rig.outcomes("google_calendar_create_event"), ["denied"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2c_a_blank_calendar_on_a_create_is_the_default_and_stays_card_free() {
    // CAL-BLANK-CREATE: the Calendar create is skill-only, so the run card is
    // the one `auto` answers by the create's class. An absent or blank
    // `calendar` means the default; a named calendar keeps the card.
    let run = |calendar: Option<&str>| {
        Rig::seeded(AUX, "calendar", create_focus(calendar), |_, home| {
            let agent = home.join("agents/calendar");
            let skills = agent.join("skills");
            std::fs::create_dir_all(&skills).unwrap();
            std::fs::write(agent.join("agent.md"), CREATE_ONLY_AGENT).unwrap();
            std::fs::write(skills.join("create-focus.md"), CREATE_ONLY_SKILL).unwrap();
        })
    };
    for calendar in [None, Some(""), Some("   ")] {
        let rig = run(calendar);
        assert!(
            rig.cards().is_empty(),
            "calendar {calendar:?}: {:?}",
            rig.cards()
        );
        assert!(
            rig.auto().iter().any(|tool| tool == "skill__create-focus"),
            "calendar {calendar:?}: cards={:?} auto={:?}",
            rig.cards(),
            rig.auto()
        );
    }
    let rig = run(Some("Work"));
    assert_eq!(rig.cards(), ["skill__create-focus"]);
    assert!(rig.auto().is_empty(), "{:?}", rig.auto());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a3_a_send_a_delete_an_unknown_tool_and_an_iban_fetch_still_ask() {
    let url = "https://example.com/lookup?iban=FR7630006000011234567890189";
    let script = vec![
        bare("mail_list"),
        call("imessage_send", json!({ "to": "owner", "text": "hi" })),
        bare("mail_delete"),
        bare("brand_new_tool"),
        call("http_fetch", json!({ "url": url })),
        done(),
    ];
    let rig = Rig::run(AUX, "mail", script);
    let asked = [
        "imessage_send",
        "mail_delete",
        "brand_new_tool",
        "http_fetch",
    ];
    assert_eq!(rig.cards(), asked);
    assert!(rig.auto().is_empty(), "{:?}", rig.auto());
    assert_eq!(rig.outcomes("http_fetch"), ["denied"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a4_an_owner_ask_rule_and_ask_mode_keep_the_card_for_a_read() {
    let rule = "\n\n[[rules]]\nagent = \"mail\"\ntool = \"mail_read\"\naction = \"ask\"";
    let script = vec![bare("mail_read"), done()];
    let rig = Rig::run(&format!("{AUX}{rule}"), "mail", script);
    assert_eq!(rig.cards(), ["mail_read"]);
    let ask = format!("{AUX}\napprovals = \"ask\"");
    let script = vec![bare("mail_list"), bare("mail_read"), done()];
    let rig = Rig::run(&ask, "mail", script);
    assert_eq!(rig.cards(), ["mail_read"]);
    assert!(rig.auto().is_empty(), "{:?}", rig.auto());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a5_logging_a_call_runs_free_after_outside_content_and_a_send_still_asks() {
    let log = json!({
        "party": "Mira Fictive",
        "kind": "call",
        "at": "2026-10-18",
        "source_ref": "{}",
        "summary": "Talked about the spring catalogue.",
    });
    let send = json!({ "to": "mira@fictive.test", "text": "Thanks" });
    let script = vec![
        bare("web_page"),
        call("crm_log_interaction", log),
        call("imessage_send", send),
        done(),
    ];
    let mut party = 0;
    let head =
        format!("{AUX}\n\n[[rules]]\nagent = \"clients\"\ntool = \"web_page\"\naction = \"allow\"");
    let rig = Rig::seeded(&head, "clients", script, |store, _| {
        let mira = aux_crm::NewParty {
            kind: aux_crm::PartyKind::Person,
            display_name: "Mira Fictive".to_string(),
            emails: vec!["mira@fictive.test".to_string()],
            origin: "owner".to_string(),
            ..aux_crm::NewParty::default()
        };
        party = aux_crm::Crm::new(store).create(mira).unwrap().id;
    });
    // The page (outside content, like a mail) tainted the turn before the log.
    assert_eq!(rig.outcomes("web_page"), ["allowed"]);
    let decisions = rig.rows("tool.decision");
    let decided = decisions
        .iter()
        .find(|row| row["tool"] == "crm_log_interaction")
        .unwrap_or_else(|| panic!("no decision: {decisions:?}"));
    assert_eq!(decided["tainted"], true, "{decided}");
    // The CRM log runs without a card; the send keeps its card.
    assert_eq!(rig.cards(), ["imessage_send"]);
    assert_eq!(rig.outcomes("crm_log_interaction"), ["allowed"]);
    let answered = rig.rows("approval.answered");
    let logged = answered
        .iter()
        .find(|row| row["tool"] == "crm_log_interaction")
        .unwrap_or_else(|| panic!("no policy answer: {answered:?}"));
    assert_eq!(
        (&logged["by"], &logged["class"]),
        (&json!("policy"), &json!("local_write"))
    );
    // The audit says the write ran in a tainted turn, and from what.
    assert_eq!(logged["tainted"], true, "{logged}");
    assert!(
        logged["taint_source"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "{logged}"
    );
    // The entry is on the client's timeline.
    let store = aux_store::Store::open(&store_path(&rig.home())).unwrap();
    let rows = store.interactions_for_party(party).unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].kind, "call");
    assert!(rows[0].summary.contains("spring catalogue"), "{rows:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_the_chief_reads_a_local_file_without_a_card() {
    // ACT-FREE-REGRESS-1: "Aux may read a file — allow…" on 2026-10-28.
    let read = call("read_file", json!({ "path": "note.txt" }));
    let rig = Rig::seeded(AUX, "aux", vec![read, done()], |_, home| {
        let workspace = aux_engine::soul::workspace_dir(home, "aux");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "Fictional note: buy stamps.").unwrap();
    });
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    // The broker allows it outright: no ask, so no approver is consulted.
    assert_eq!(rig.outcomes("read_file"), ["allowed"]);
    assert!(rig.auto().is_empty(), "{:?}", rig.auto());
    assert!(rig.sent().contains("buy stamps"), "the read must have run");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_a_read_of_the_daemon_home_is_refused_without_a_card() {
    // Refused is not a card: a read outside the workspace (the daemon's own
    // home, a key file) fails closed and its text never reaches the brain.
    let script = vec![
        call("read_file", json!({ "path": "../../../.env" })),
        call("read_file", json!({ "path": "../../../config.toml" })),
        done(),
    ];
    let rig = Rig::seeded(AUX, "aux", script, |_, home| {
        std::fs::write(home.join(".env"), "FICTIVE_KEY=zz-not-a-real-key-41").unwrap();
    });
    assert!(rig.cards().is_empty(), "{:?}", rig.cards());
    let sent = rig.sent();
    assert!(
        !sent.contains("zz-not-a-real-key-41"),
        "a key file reached the brain"
    );
    assert!(!sent.contains("fakey"), "the config reached the brain");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_reads_stay_free_while_a_send_a_delete_and_an_unknown_tool_ask() {
    let read = call("read_file", json!({ "path": "note.txt" }));
    let script = vec![
        read,
        call("imessage_send", json!({ "to": "owner", "text": "hi" })),
        bare("mail_delete"),
        bare("brand_new_tool"),
        done(),
    ];
    let rig = Rig::seeded(AUX, "mail", script, |_, home| {
        let workspace = aux_engine::soul::workspace_dir(home, "mail");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("note.txt"), "Fictional note.").unwrap();
    });
    assert_eq!(
        rig.cards(),
        ["imessage_send", "mail_delete", "brand_new_tool"]
    );
    assert_eq!(rig.outcomes("read_file"), ["allowed"]);
}

fn card_turn() -> Arc<Rig> {
    let script = vec![
        ChatResponse::assistant("Hello."),
        call("imessage_send", json!({ "to": "owner", "text": "hi" })),
        ChatResponse::assistant("Noted."),
        ChatResponse::assistant("Noted."),
    ];
    Arc::new(Rig::with_timeout(
        AUX,
        "aux",
        script,
        |_, _| {},
        Duration::from_secs(60),
    ))
}

fn cancel_at_card(message: &str, refuses: bool) {
    let rig = card_turn();
    // The card turn in the background: it parks until the card is answered.
    let addr = rig.handle.addr();
    let path = "/v1/threads/aux/messages".to_string();
    let body = serde_json::json!({ "content": "reply camille ok" }).to_string();
    let first = std::thread::spawn(move || {
        common::http_with_read_timeout(
            addr,
            "POST",
            &path,
            Some(TOKEN),
            Some(&body),
            common::LOADED_RUNNER_WAIT,
        )
    });
    let started = Instant::now();
    let card = loop {
        if let Some(card) = rig.approvals().into_iter().next() {
            break card;
        }
        assert!(
            started.elapsed() < common::LOADED_RUNNER_WAIT,
            "no card came"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    let (response, took) = rig.try_send("aux", message);
    assert!(took < Duration::from_secs(2), "{message}: took {took:?}");
    if refuses {
        assert_eq!(response.status, 200, "{message}: {}", response.body);
        assert!(
            rig.approvals().is_empty(),
            "{message}: the card still waits"
        );
        assert!(
            response.body.contains("Cancelled — nothing was sent."),
            "{message}: no plain cancellation: {}",
            response.body
        );
        let answers = rig.rows("approval.answered");
        assert_eq!(answers.len(), 1, "{message}: {answers:?}");
        assert_eq!(answers[0]["id"], card["id"], "{message}: not denied");
        assert_eq!(answers[0]["decision"], "deny", "{message}: {answers:?}");
    } else {
        // CARD-NEVER-BLOCKS: anything else is a normal turn beside the card.
        assert_eq!(response.status, 200, "{message}: {}", response.body);
        assert!(
            response.body.contains("Noted."),
            "{message}: {}",
            response.body
        );
        assert_eq!(rig.approvals().len(), 1, "{message}: the card was touched");
        assert!(
            rig.rows("approval.answered").is_empty(),
            "{message}: answered"
        );
        let path = format!("/v1/approvals/{}", card["id"].as_str().unwrap());
        let denied = tokio::task::block_in_place(|| {
            common::post(
                rig.handle.addr(),
                &path,
                Some(TOKEN),
                r#"{"decision":"deny"}"#,
            )
        });
        assert_eq!(denied.status, 200, "{message}: {}", denied.body);
    }
    assert_eq!(first.join().unwrap().status, 200, "{message}: turn 1");
    assert_eq!(
        rig.outcomes("imessage_send"),
        ["denied"],
        "{message}: send ran"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_at_card_withdraws_the_waiting_card_at_once() {
    for word in ["cancel", "nah cancel that", "annule"] {
        cancel_at_card(word, true);
    }
    cancel_at_card("don't", true);
    cancel_at_card("laisse tomber", true);
    cancel_at_card("Laisse Tomber", true);
    cancel_at_card("Annulé !", true);
    cancel_at_card("ANNULÉ", true);
    cancel_at_card("NON MERCI", true);
    cancel_at_card("en fait non, cancel that", true);
    for word in [
        "wait no",
        "never mind",
        "forget it",
        "non attends",
        "oublie",
    ] {
        cancel_at_card(word, true);
    }
    cancel_at_card("cancel the 3pm meeting and email bob", false);
    cancel_at_card("yes", false);
    cancel_at_card("send it", false);
}

/// CARD-NEVER-BLOCKS: a Calendar thread whose skill run waits on its card
/// ("Work" keeps the card), then `after` for the turns that follow.
fn skill_card(after: Vec<ChatResponse>) -> (Arc<Rig>, std::thread::JoinHandle<u16>, Value) {
    let mut script = vec![ChatResponse::assistant("Hello.")];
    script.extend(create_focus(Some("Work")).into_iter().take(1));
    script.extend(after);
    let rig = Arc::new(Rig::with_timeout(
        AUX,
        "calendar",
        script,
        |_, home| {
            let agent = home.join("agents/calendar");
            std::fs::create_dir_all(agent.join("skills")).unwrap();
            std::fs::write(agent.join("agent.md"), CREATE_ONLY_AGENT).unwrap();
            std::fs::write(agent.join("skills/create-focus.md"), CREATE_ONLY_SKILL).unwrap();
        },
        Duration::from_secs(60),
    ));
    let (addr, body) = (rig.handle.addr(), r#"{"content":"focus at 9 in Work"}"#);
    let first = std::thread::spawn(move || {
        let path = "/v1/threads/calendar/messages";
        let wait = common::LOADED_RUNNER_WAIT;
        common::http_with_read_timeout(addr, "POST", path, Some(TOKEN), Some(body), wait).status
    });
    let started = Instant::now();
    let card = loop {
        // The skill card is in the state the app and the harness read.
        if let Some(card) = rig.approvals().into_iter().next() {
            break card;
        }
        assert!(started.elapsed() < common::LOADED_RUNNER_WAIT, "no card");
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(card["scope_tool"], "skill__create-focus", "{card}");
    (rig, first, card)
}

impl Rig {
    fn answer(&self, card: &Value, decision: &str) -> u16 {
        let path = format!("/v1/approvals/{}", card["id"].as_str().unwrap());
        let body = format!(r#"{{"decision":"{decision}"}}"#);
        let addr = self.handle.addr();
        tokio::task::block_in_place(|| common::post(addr, &path, Some(TOKEN), &body)).status
    }

    fn skill_decisions(&self) -> Vec<String> {
        self.column("skill.approval", "decision", |_| true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiting_skill_card_never_blocks_the_chat_and_sends_once() {
    let after = vec![ChatResponse::assistant("Friday is free."), done()];
    let (rig, first, card) = skill_card(after);
    let (response, took) = rig.try_send("calendar", "what's on fri");
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(took < Duration::from_secs(5), "took {took:?}");
    assert!(
        response.body.contains("Friday is free."),
        "{}",
        response.body
    );
    assert_eq!(rig.approvals().len(), 1, "the card still waits");
    // Send, while nothing else runs: one run; a second Send is refused.
    assert_eq!(rig.answer(&card, "allow_once"), 200);
    assert_ne!(rig.answer(&card, "allow_once"), 200, "answered twice");
    assert_eq!(first.join().unwrap(), 200);
    assert_eq!(rig.skill_decisions(), ["approved"], "executed once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_no_withdraws_a_skill_card_and_a_later_send_is_refused() {
    let (rig, first, card) = skill_card(vec![done()]);
    let (response, took) = rig.try_send("calendar", "wait no");
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(took < Duration::from_secs(2), "took {took:?}");
    assert!(
        response.body.contains("Cancelled — nothing was sent."),
        "{}",
        response.body
    );
    assert!(rig.approvals().is_empty(), "the card still waits");
    assert_ne!(
        rig.answer(&card, "allow_once"),
        200,
        "Send after a withdraw"
    );
    assert_eq!(first.join().unwrap(), 200);
    assert!(!rig.skill_decisions().contains(&"approved".to_string()));
    assert!(rig.rows("skill.action").is_empty(), "something ran");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aux_delegates_to_an_agent_whose_own_card_waits() {
    let task = json!({ "agent": "calendar", "task": "Say what is on Friday." });
    let after = vec![
        call("delegate", task),
        ChatResponse::assistant("Friday is free."),
        ChatResponse::assistant("Calendar says Friday is free."),
        done(),
    ];
    let (rig, first, card) = skill_card(after);
    let (response, took) = rig.try_send("aux", "ask calendar about friday");
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(took < Duration::from_secs(10), "took {took:?}");
    assert_eq!(rig.delegated(), [Some("Friday is free.".to_string())]);
    assert_eq!(rig.approvals().len(), 1, "the card still waits");
    assert_eq!(rig.answer(&card, "deny"), 200);
    assert_eq!(first.join().unwrap(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_withdraws_only_the_newest_of_two_waiting_cards() {
    // Turn 1 parks on card A; turn 2 runs beside it and parks on card B.
    let mut after = create_focus(Some("Work"));
    after.truncate(1);
    after.extend([done(), done()]);
    let (rig, first, older) = skill_card(after);
    let (addr, body) = (rig.handle.addr(), r#"{"content":"and one at 10 in Work"}"#);
    let second = std::thread::spawn(move || {
        let path = "/v1/threads/calendar/messages";
        let wait = common::LOADED_RUNNER_WAIT;
        common::http_with_read_timeout(addr, "POST", path, Some(TOKEN), Some(body), wait).status
    });
    let started = Instant::now();
    while rig.approvals().len() < 2 {
        assert!(
            started.elapsed() < common::LOADED_RUNNER_WAIT,
            "no second card"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let (response, _) = rig.try_send("calendar", "no");
    assert_eq!(response.status, 200, "{}", response.body);
    let expected = "Withdrawn: create-focus. 1 other request still waits for you.";
    assert!(response.body.contains(expected), "{}", response.body);
    let left = rig.approvals();
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0]["id"], older["id"], "the newest card was withdrawn");
    assert_eq!(second.join().unwrap(), 200);
    assert_eq!(rig.answer(&older, "allow_once"), 200);
    assert_eq!(first.join().unwrap(), 200);
    let approved = rig
        .skill_decisions()
        .into_iter()
        .filter(|d| d == "approved");
    assert_eq!(approved.count(), 1, "the older card ran once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_turn_audits_its_card_as_abandoned_in_the_receipt() {
    let rig = card_turn();
    let addr = rig.handle.addr();
    let first = std::thread::spawn(move || {
        let (path, body) = (
            "/v1/threads/aux/messages",
            r#"{"content":"tell the owner hi"}"#,
        );
        let wait = common::LOADED_RUNNER_WAIT;
        common::http_with_read_timeout(addr, "POST", path, Some(TOKEN), Some(body), wait).status
    });
    let started = Instant::now();
    let card = loop {
        if let Some(card) = rig.approvals().into_iter().next() {
            break card;
        }
        assert!(
            started.elapsed() < common::LOADED_RUNNER_WAIT,
            "no card came"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    let paused = tokio::task::block_in_place(|| {
        common::post(addr, "/v1/agents/aux/pause", Some(TOKEN), "{}")
    });
    assert_eq!(paused.status, 200, "{}", paused.body);
    let _ = first.join().unwrap();
    assert!(rig.approvals().is_empty(), "the card still waits");
    let answers = rig.rows("approval.answered");
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert_eq!(answers[0]["id"], card["id"]);
    assert_eq!(answers[0]["decision"], "abandoned", "{answers:?}");
    let receipts = common::get(addr, "/v1/receipts?agent=aux&limit=10", Some(TOKEN));
    assert!(
        receipts.body.contains("imessage_send: abandoned"),
        "{}",
        receipts.body
    );
}
