//! SHELL-JUDGE acceptance: under `approvals = "auto"`, a clean, sandboxed
//! `shell` ask goes to a judge on the agent's own provider. The judge sees
//! only the owner's messages, the workspace root and the command; its `allow`
//! runs the call with an `approval.answered` row `by: "judge"`. With the
//! shell's network on, the judge is never asked and the card stays.
//!
//! A real server on a loopback port, a scripted fake brain that also plays the
//! judge, a temp home. No network, Keychain or real home.

mod common;

use std::sync::Arc;
use std::time::Duration;

use aux_providers::{ChatMessage, ChatProvider, ChatResponse, FakeProvider, ToolCall};
use auxd::api::{self, ApiHandle, ApiOptions};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const OWNER: &str = "list the files in your workspace";

/// The assistant says `text` and calls `name` once.
fn call(text: &str, name: &str, args: Value) -> ChatResponse {
    let call = ToolCall::new(format!("call-{name}"), name, args);
    ChatResponse::new(ChatMessage::assistant_with_tool_calls(text, vec![call]))
}

struct Rig {
    dir: tempfile::TempDir,
    handle: ApiHandle,
    brain: Arc<FakeProvider>,
}

impl Rig {
    /// A server whose config holds `head` and whose brain plays `script`; one
    /// owner message to `main` has run.
    fn run(head: &str, script: Vec<ChatResponse>) -> Self {
        Self::run_as(head, "main", script)
    }

    /// [`Self::run`], the owner message going to `agent`.
    fn run_as(head: &str, agent: &str, script: Vec<ChatResponse>) -> Self {
        Self::run_as_with(head, agent, script, |_| {})
    }

    /// [`Self::run_as`], `seed` writing files under the home first.
    fn run_as_with(
        head: &str,
        agent: &str,
        script: Vec<ChatResponse>,
        seed: impl FnOnce(&std::path::Path),
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let provider = "[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
                        model = \"fake-model\"\nkind = \"fake\"\n";
        let config = format!("version = 1\nprivacy.mode = \"open\"\n{head}\n\n{provider}");
        std::fs::write(config_path(&home), config).unwrap();
        std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
        seed(&home);
        let brain = Arc::new(FakeProvider::scripted("fakey", script));
        let options = ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            provider: Some(Arc::clone(&brain) as Arc<dyn ChatProvider>),
            approval_timeout: Some(Duration::from_secs(1)),
            ..ApiOptions::default()
        };
        let rig = Self {
            handle: api::spawn(&home, options).unwrap(),
            dir,
            brain,
        };
        let body = json!({ "content": OWNER }).to_string();
        let response = tokio::task::block_in_place(|| {
            let path = format!("/v1/threads/{agent}/messages");
            common::post(rig.handle.addr(), &path, Some(TOKEN), &body)
        });
        assert_eq!(response.status, 200, "{}", response.body);
        rig
    }

    fn rows(&self, kind: &str) -> Vec<Value> {
        let store = store_path(&self.dir.path().join("home"));
        let conn = aux_store::open_keyed_readonly(&store).unwrap();
        let sql = "SELECT payload FROM events WHERE kind = ?1 ORDER BY id";
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt
            .query_map([kind], |row| row.get::<_, String>(0))
            .unwrap();
        rows.map(|raw| serde_json::from_str(&raw.unwrap()).unwrap())
            .collect()
    }

    /// Each recorded request, as the JSON it would put on the wire.
    fn requests(&self) -> Vec<Value> {
        let requests = self.brain.requests();
        requests
            .iter()
            .map(|request| serde_json::to_value(request).unwrap())
            .collect()
    }
}

/// True for a judge request (its fixed prompt).
fn is_judge(request: &Value) -> bool {
    request["messages"][0]["content"]
        .as_str()
        .is_some_and(|prompt| prompt.starts_with("You review one shell command"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_ls_runs_on_the_judges_allow_and_the_judge_sees_only_the_owner() {
    let allow = r#"{"decision":"allow","reason":"reads the workspace"}"#;
    let rig = Rig::run(
        "",
        vec![
            call("ASSISTANT_SAYS_RUN_IT", "shell", json!({ "command": "ls" })),
            ChatResponse::assistant(allow),
            ChatResponse::assistant("done"),
        ],
    );
    assert!(rig.rows("approval.pending").is_empty(), "no card");
    let answered = rig.rows("approval.answered");
    assert_eq!(answered.len(), 1, "{answered:?}");
    assert_eq!(answered[0]["by"], "judge");
    assert_eq!(answered[0]["tool"], "shell");
    assert_eq!(answered[0]["reason"], "reads the workspace");

    let requests = rig.requests();
    assert_eq!(requests.len(), 3, "turn, judge, turn");
    let judge = &requests[1];
    assert!(is_judge(judge), "{judge}");
    let messages = judge["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2, "{judge}");
    let input = messages[1]["content"].as_str().unwrap();
    assert!(
        input.contains(OWNER) && input.contains(r#""proposed_command":"ls""#),
        "{input}"
    );
    // The assistant's text and the turn's own prompt never reach the judge.
    let wire = judge.to_string();
    assert!(!wire.contains("ASSISTANT_SAYS_RUN_IT"), "{wire}");
    assert!(judge
        .get("tools")
        .is_none_or(|t| t.as_array().is_some_and(Vec::is_empty)));
    // The turn after the judge got the command's output as its tool result.
    let after = requests[2]["messages"].as_array().unwrap();
    assert_eq!(after.last().unwrap()["role"], "tool", "{}", requests[2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_shell_network_on_the_judge_is_never_asked() {
    let rig = Rig::run(
        "[shell]\nnetwork = true",
        vec![
            call("", "shell", json!({ "command": "ls" })),
            ChatResponse::assistant("done"),
        ],
    );
    let cards = rig.rows("approval.pending");
    assert_eq!(cards.len(), 1, "a card: {cards:?}");
    assert_eq!(cards[0]["tool"], "shell");
    assert!(!rig.requests().iter().any(is_judge), "the judge was asked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_judge_off_the_card_stays() {
    let rig = Rig::run(
        "[approval]\nshell_judge = false",
        vec![
            call("", "shell", json!({ "command": "ls" })),
            ChatResponse::assistant("done"),
        ],
    );
    assert_eq!(rig.rows("approval.pending").len(), 1);
    assert!(!rig.requests().iter().any(is_judge), "the judge was asked");
}

/// A delegated child runs a task the chief wrote, not the owner's words, so
/// its shell call keeps the card and the judge is never asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delegated_childs_shell_call_never_reaches_the_judge() {
    let task = json!({ "agent": "mail", "task": "List the files in your workspace." });
    // Mail asks for the shell in its agent.md; it is not offered otherwise.
    let seed = |home: &std::path::Path| {
        let dir = home.join("agents").join("mail");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("agent.md"),
            "---\nname: mail\ntools: [shell]\n---\nMail.\n",
        )
        .unwrap();
    };
    let rig = Rig::run_as_with(
        "default_agent = \"aux\"",
        "aux",
        vec![
            call("", "delegate", task),
            call("", "shell", json!({ "command": "ls" })),
            ChatResponse::assistant("child done"),
            ChatResponse::assistant("done"),
        ],
        seed,
    );
    let cards = rig.rows("approval.pending");
    assert_eq!(cards.len(), 1, "a card: {cards:?}");
    assert_eq!(cards[0]["tool"], "shell");
    assert_eq!(cards[0]["agent"], "mail");
    assert!(!rig.requests().iter().any(is_judge), "the judge was asked");
}

/// Under a global `allow shell`, a domain agent with no `tools` opt-in is not
/// offered the shell, and a forced call is denied before it runs: on its own
/// thread and as a delegated child. The chief keeps the shell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_domain_agents_forced_shell_call_is_denied_under_a_global_allow() {
    let head =
        "default_agent = \"aux\"\n[[rules]]\nagent = \"*\"\ntool = \"shell\"\naction = \"allow\"";
    let shell = || call("", "shell", json!({ "command": "echo ran" }));
    let offered = |request: &Value| request["tools"].to_string().contains("\"shell\"");
    let shell_outcomes = |rig: &Rig| -> Vec<(String, String)> {
        rig.rows("tool.decision")
            .iter()
            .filter(|row| row["tool"] == "shell")
            .map(|row| (row["agent"].to_string(), row["outcome"].to_string()))
            .collect()
    };
    let denied = vec![("\"mail\"".to_string(), "\"denied\"".to_string())];

    let own = Rig::run_as(head, "mail", vec![shell(), ChatResponse::assistant("done")]);
    assert!(!offered(&own.requests()[0]), "{}", own.requests()[0]);
    assert_eq!(shell_outcomes(&own), denied);
    assert!(own.rows("approval.pending").is_empty(), "no card");

    let task = json!({ "agent": "mail", "task": "List the files in your workspace." });
    let delegated = Rig::run_as(
        head,
        "aux",
        vec![
            call("", "delegate", task),
            shell(),
            ChatResponse::assistant("child done"),
            ChatResponse::assistant("done"),
        ],
    );
    let requests = delegated.requests();
    assert!(offered(&requests[0]), "the chief keeps the shell");
    assert!(!offered(&requests[1]), "{}", requests[1]);
    assert_eq!(shell_outcomes(&delegated), denied);
}
