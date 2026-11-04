//! `aux chat` goes through `auxd` when it answers (a real API on a
//! loopback port, scripted fake brain, sandboxed `aux`), else says so and runs alone.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use aux_providers::{ChatMessage, ChatResponse, FakeProvider, ToolCall};
use auxd::api::{self, ApiOptions};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};

fn call(name: &str, args: Value) -> ChatResponse {
    let call = ToolCall::new("call-1", name, args);
    ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![call]))
}

fn write_config(home: &std::path::Path, agent: &str) {
    std::fs::create_dir_all(home).unwrap();
    let fake = "base_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"";
    let config = format!("version = 1\ndefault_agent = \"{agent}\"\n[privacy]\nmode = \"open\"\n");
    let provider = format!("[[providers]]\nid = \"fakey\"\n{fake}\n");
    std::fs::write(config_path(home), config + &provider).unwrap();
}

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Rig {
    dir: tempfile::TempDir,
    runtime: tokio::runtime::Runtime,
    port: u16,
}

impl Rig {
    fn start(script: Vec<ChatResponse>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        write_config(&home, "aux");
        let token = api::token_path(&home);
        std::fs::write(&token, TOKEN).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let options = ApiOptions {
            port: 0,
            provider: Some(Arc::new(FakeProvider::scripted("fakey", script))),
            approval_timeout: Some(Duration::from_secs(30)),
            ..ApiOptions::default()
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let port = runtime
            .block_on(async { api::spawn(&home, options).unwrap() })
            .addr()
            .port();
        Self { dir, runtime, port }
    }

    fn aux(&self, args: &[&str], stdin: &str) -> Output {
        run_aux(self.dir.path(), self.port, args, stdin)
    }

    fn store(&self) -> aux_store::Store {
        aux_store::Store::open(&store_path(&self.dir.path().join("home"))).unwrap()
    }
}

/// `aux` in the sandbox under `dir` (home = `dir/home`), talking to loopback `port`.
fn spawn_aux(dir: &std::path::Path, port: u16, args: &[&str], stdin: &str) -> Child {
    std::fs::write(dir.join("stdin.txt"), stdin).unwrap();
    Command::new(env!("CARGO_BIN_EXE_aux"))
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", dir.join("home"))
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", port.to_string())
        .env("AUXESIS_UI_LANG", "en")
        .stdin(Stdio::from(
            std::fs::File::open(dir.join("stdin.txt")).unwrap(),
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run aux chat")
}

fn run_aux(dir: &std::path::Path, port: u16, args: &[&str], stdin: &str) -> Output {
    spawn_aux(dir, port, args, stdin)
        .wait_with_output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn a_turn_goes_through_auxd_and_can_delegate_to_the_mail_agent() {
    let task = json!({ "agent": "mail", "task": "Who wrote last?" });
    let rig = Rig::start(vec![
        call("delegate", task),
        ChatResponse::assistant("Camille Exemple wrote last."),
        ChatResponse::assistant("Camille Exemple wrote to you last."),
    ]);

    let output = rig.aux(&["chat", "who wrote to me last?"], "");

    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert_eq!(
        text(&output.stdout).trim(),
        "Camille Exemple wrote to you last."
    );
    let delegated = rig.store().list_delegations(None).unwrap();
    assert_eq!(
        delegated[0].result.as_deref(),
        Some("Camille Exemple wrote last.")
    );
}

#[test]
fn the_repl_keeps_one_thread_across_lines() {
    let rig = Rig::start(vec![
        ChatResponse::assistant("1"),
        ChatResponse::assistant("2"),
    ]);

    let output = rig.aux(&["chat", "--agent", "aux"], "one\ntwo\nexit\n");

    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout).lines().collect::<Vec<_>>(), ["1", "2"]);
    let sessions = rig.store().list_sessions().unwrap();
    assert_eq!(sessions.len(), 1, "both lines belong to one thread");
}

#[test]
fn new_starts_a_fresh_thread_and_keeps_the_old_one() {
    let rig = Rig::start(["1", "2", "3"].map(ChatResponse::assistant).to_vec());
    for args in [
        vec!["chat", "one"],
        vec!["chat", "two"],
        vec!["chat", "--new", "three"],
    ] {
        let output = rig.aux(&args, "");
        assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    }
    let store = rig.store();
    let sessions = store.list_sessions().unwrap();
    assert_eq!(sessions.len(), 2, "old thread kept, one new: {sessions:?}");
    let owner_rows = |id| {
        store
            .list_messages(id)
            .unwrap()
            .iter()
            .filter(|r| r.role == "user")
            .count()
    };
    // Newest first: the new thread holds only `three`, the old one both lines.
    assert_eq!(owner_rows(sessions[0].id), 1);
    assert_eq!(owner_rows(sessions[1].id), 2);
}

#[test]
fn a_card_keeps_the_turn_open_until_the_owner_approves_it_in_the_app() {
    let ls = call("shell", json!({ "command": "ls" }));
    // The shell judge reads the second reply, cannot parse it, and leaves the card.
    let rig = Rig::start(vec![
        ls,
        ChatResponse::assistant("?"),
        ChatResponse::assistant("ran it"),
    ]);
    let mut child = spawn_aux(rig.dir.path(), rig.port, &["chat", "list my files"], "");

    // The CLI says it waits; only then does the owner answer, in the app.
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    while !line.contains("waiting for your approval in the app") {
        line.clear();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "the CLI never said it waits"
        );
    }
    let base = format!("http://127.0.0.1:{}/v1/approvals", rig.port);
    rig.runtime.block_on(async {
        let client = reqwest::Client::new();
        let cards = client.get(&base).bearer_auth(TOKEN).send().await.unwrap();
        let cards: Value = serde_json::from_str(&cards.text().await.unwrap()).unwrap();
        let id = cards[0]["id"]
            .as_str()
            .expect("the card is still pending")
            .to_string();
        let decision = client
            .post(format!("{base}/{id}"))
            .bearer_auth(TOKEN)
            .header("content-type", "application/json")
            .body(r#"{"decision":"allow_once"}"#)
            .send()
            .await
            .unwrap();
        assert!(decision.status().is_success(), "{}", decision.status());
    });

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(text(&output.stdout).trim(), "ran it");
}

#[test]
fn flags_the_daemon_cannot_honour_are_refused_not_ignored() {
    let rig = Rig::start(vec![ChatResponse::assistant("never")]);

    for (args, flag) in [
        (["chat", "--auto-approve", "hi"], "--auto-approve"),
        (["chat", "--provider=fakey", "hi"], "--provider"),
    ] {
        let output = rig.aux(&args, "");
        assert!(!output.status.success(), "{args:?}");
        assert!(text(&output.stderr).contains(&format!("{flag} does not exist with auxd")));
        assert!(output.stdout.is_empty());
    }
    assert!(rig.store().list_sessions().unwrap().is_empty());
}

#[test]
fn chat_help_hides_auto_approve_when_auxd_is_available() {
    let rig = Rig::start(vec![]);
    let output = rig.aux(&["chat", "--help"], "");
    assert!(output.status.success());
    let help = text(&output.stdout);
    assert!(!help.contains("--auto-approve"), "help:\n{help}");
    assert!(help.contains("--provider"), "help:\n{help}");
}

#[test]
fn a_live_auxd_that_refuses_the_token_fails_closed_never_falls_back() {
    let rig = Rig::start(vec![ChatResponse::assistant("never")]);
    let token = api::token_path(&rig.dir.path().join("home"));
    std::fs::write(&token, "f".repeat(64)).unwrap();

    let output = rig.aux(&["chat", "--auto-approve", "hi"], "");

    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(
        stderr.contains("auxd is running but refused this CLI"),
        "{stderr}"
    );
    assert!(!stderr.contains("auxd is not running"), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn without_auxd_it_says_so_and_chats_in_process() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(&home, "main");
    // A closed loopback port: bind, learn the port, drop the listener.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let output = run_aux(dir.path(), port, &["chat", "hello"], "");

    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    let line = "auxd is not running: this chat has no mail, calendar or client tools.";
    assert_eq!(stderr.lines().next(), Some(line));
    assert!(text(&output.stdout).contains("[fake:fakey] hello"));
}
