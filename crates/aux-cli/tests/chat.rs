//! End-to-end tests of `aux chat` in a throwaway Auxesis home.
//!
//! The provider is `kind = "fake"` throughout, so nothing touches the network
//! and no key or secret is involved.

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

mod common;
use common::sandbox_command;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

const FAKE_PROVIDER: &str = r#"
[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;

fn write_config(home: &std::path::Path, extra: &str) {
    std::fs::create_dir_all(home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        format!("version = 1\nprivacy.mode = \"open\"\nlog_level = \"info\"\ndefault_agent = \"main\"\n{extra}"),
    )
    .unwrap();
}

#[test]
fn single_shot_echoes_and_persists_the_session() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(
        &home,
        &format!(
            "{FAKE_PROVIDER}\n\
             [[rules]]\n\
             agent = \"main\"\n\
             tool = \"read_file\"\n\
             action = \"allow\"\n"
        ),
    );

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--agent", "main", "hello"])
        .output()
        .expect("run aux chat");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "chat failed:\n{stdout}");
    assert!(
        stdout.contains("[fake:fakey] hello"),
        "unexpected output:\n{stdout}"
    );

    // The agent layout was created.
    assert!(
        home.join("agents/main/soul.md").exists(),
        "soul was created"
    );
    assert!(
        home.join("agents/main/workspace").is_dir(),
        "workspace was created"
    );

    // Every message of the run is persisted under one session.
    let store = aux_store::Store::open(&home.join("store.db")).unwrap();
    let sessions = store.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].agent, "main");
    let messages = store.list_messages(sessions[0].id).unwrap();
    let roles: Vec<&str> = messages
        .iter()
        .map(|message| message.role.as_str())
        .collect();
    assert_eq!(roles, vec!["system", "user", "assistant"]);
    assert!(messages[0].content.contains("You are main"));
    assert_eq!(messages[1].content, "hello");
    assert_eq!(messages[2].content, "[fake:fakey] hello");
}

#[test]
fn repl_reads_messages_until_exit() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(&home, FAKE_PROVIDER);

    let mut child = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--agent", "main"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aux chat");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"first\nsecond\nexit\n")
        .unwrap();
    let output = child.wait_with_output().expect("wait for aux chat");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "chat failed:\n{stdout}");
    assert!(stdout.contains("[fake:fakey] first"), "stdout:\n{stdout}");
    assert!(stdout.contains("[fake:fakey] second"), "stdout:\n{stdout}");

    let store = aux_store::Store::open(&home.join("store.db")).unwrap();
    let sessions = store.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    let roles: Vec<String> = store
        .list_messages(sessions[0].id)
        .unwrap()
        .into_iter()
        .map(|message| message.role)
        .collect();
    assert_eq!(
        roles,
        vec!["system", "user", "assistant", "user", "assistant"]
    );
}

#[test]
fn fails_cleanly_without_configured_providers() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(&home, "");

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "hello"])
        .output()
        .expect("run aux chat");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "chat should fail:\n{stderr}");
    assert!(
        stderr.contains("no providers are configured"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn requires_the_provider_flag_when_several_are_configured() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let two = format!(
        "{FAKE_PROVIDER}\n\
         [[providers]]\n\
         id = \"other\"\n\
         base_url = \"http://127.0.0.1:9/v1\"\n\
         model = \"fake-model\"\n\
         kind = \"fake\"\n"
    );
    write_config(&home, &two);

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "hello"])
        .output()
        .expect("run aux chat");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("several providers"), "stderr:\n{stderr}");

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--provider", "other", "hello"])
        .output()
        .expect("run aux chat");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stderr:\n{stderr}");
    assert!(stdout.contains("[fake:other] hello"), "stdout:\n{stdout}");
}

#[test]
fn rejects_unsafe_agent_names() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(&home, FAKE_PROVIDER);

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--agent", "../evil", "hello"])
        .output()
        .expect("run aux chat");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("invalid agent name"), "stderr:\n{stderr}");
    assert!(
        !dir.path().join("evil").exists(),
        "path traversal must not create directories"
    );
}

#[test]
fn auto_approve_flag_is_honoured_and_announced() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(&home, FAKE_PROVIDER);

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "--auto-approve", "hello"])
        .output()
        .expect("run aux chat");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("--auto-approve"), "stderr:\n{stderr}");
}

#[test]
fn invalid_rules_config_is_reported() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    write_config(
        &home,
        &format!(
            "{FAKE_PROVIDER}\n\
             [[rules]]\n\
             agent = \"main\"\n\
             tool = \"shell\"\n\
             action = \"maybe\"\n"
        ),
    );

    let output = sandbox_command(aux_bin(), dir.path(), &home)
        .args(["chat", "hello"])
        .output()
        .expect("run aux chat");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("parsing [[rules]]"), "stderr:\n{stderr}");
}

/// Private mode, the fake echo provider, a sandboxed home. The
/// echo answers with exactly what the provider received, so the output shows
/// what left the Mac; the owner's own questions are not touched, and an e-mail
/// address that was tokenised is restored for display, never shown raw.
fn private_chat(args: &[&str], stdin: Option<&str>) -> String {
    let dir = tempdir().unwrap();
    let home = dir.path().join(".auxesis");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        format!(
            "version = 1\nprivacy.mode = \"private\"\nlog_level = \"info\"\ndefault_agent = \"main\"\n{FAKE_PROVIDER}"
        ),
    )
    .unwrap();
    let mut child = Command::new(aux_bin())
        .args(["chat", "--agent", "main"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", dir.path())
        .env("AUXESIS_HOME", &home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aux chat");
    if let Some(input) = stdin {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().expect("wait for aux chat");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "chat failed:\n{stdout}\n{stderr}");
    stdout
}

#[test]
fn private_single_shot_keeps_the_question_intact_and_shows_no_token() {
    let question = "How many unread mails do I have, and who sent the newest one?";
    let stdout = private_chat(&[question], None);
    assert!(
        stdout.contains(&format!("[fake:fakey] {question}")),
        "the question was altered on its way to the provider:\n{stdout}"
    );
    assert!(!stdout.contains('⟦'), "a raw token was shown:\n{stdout}");

    let stdout = private_chat(&["How many unread mails do I have, Aux?"], None);
    assert!(
        stdout.contains("[fake:fakey] How many unread mails do I have, Aux?"),
        "Aux was tokenised:\n{stdout}"
    );

    // A tokenised address is restored for display.
    let stdout = private_chat(&["Write to camille@exemple.fr about the invoice."], None);
    assert!(
        stdout.contains("[fake:fakey] Write to camille@exemple.fr about the invoice."),
        "the address was not restored for display:\n{stdout}"
    );
    assert!(!stdout.contains('⟦'), "a raw token was shown:\n{stdout}");
}

#[test]
fn private_repl_shows_restored_values_too() {
    let stdout = private_chat(
        &[],
        Some("What is on my calendar tomorrow?\nWrite to camille@exemple.fr.\nexit\n"),
    );
    assert!(
        stdout.contains("[fake:fakey] What is on my calendar tomorrow?"),
        "{stdout}"
    );
    assert!(
        stdout.contains("[fake:fakey] Write to camille@exemple.fr."),
        "{stdout}"
    );
    assert!(!stdout.contains('⟦'), "a raw token was shown:\n{stdout}");
}
