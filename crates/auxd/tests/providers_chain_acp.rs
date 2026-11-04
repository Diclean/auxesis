//! A4 P1: an `acp` provider selected by `providers.toml` runs through the
//! daemon's ACP turn path, read-only skills only.
//!
//! The agent is the `aux-acp` fake agent binary (scenario `happy`): no real
//! OpenCode, no login, no network.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Once};

use auxd::api::{EngineTurnRunner, TurnError, TurnRunner};
use kernel_privacy::ContactIndex;

/// A fictional owner contact, so the session gate has a name detector mounted.
fn contacts() -> aux_runtime::known_names::Contacts {
    let mut index = ContactIndex::new();
    assert!(index
        .add_from_header("Test Person", "test@example.invalid")
        .is_some());
    Arc::new(index)
}

fn runner(home: &Path) -> EngineTurnRunner {
    EngineTurnRunner::new(home).with_contacts(contacts())
}

/// The `aux-acp` fake agent, next to the test binary.
///
/// `cargo test -p auxd` does not build another package's binary targets, so
/// when the agent is missing it is built once here, into this test's own
/// target directory. `cargo test --workspace` (CI) has already built it.
fn fake_agent() -> PathBuf {
    static BUILT: Once = Once::new();
    let mut profile_dir = std::env::current_exe().expect("the test binary path");
    profile_dir.pop(); // deps/
    profile_dir.pop(); // debug/
    let path = profile_dir.join("acp-fake-agent");
    BUILT.call_once(|| {
        if path.exists() {
            return;
        }
        let target_dir = profile_dir.parent().expect("a target directory");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut build = Command::new(cargo);
        // Offline: aux-acp is already a dependency, nothing to fetch.
        build.args([
            "build",
            "-p",
            "aux-acp",
            "--bin",
            "acp-fake-agent",
            "--locked",
            "--offline",
        ]);
        // Build into the profile this test binary runs under.
        if profile_dir
            .file_name()
            .is_some_and(|name| name == "release")
        {
            build.arg("--release");
        }
        let status = build
            .env("CARGO_TARGET_DIR", target_dir)
            .status()
            .expect("run cargo to build the fake agent");
        assert!(status.success(), "building the fake agent failed");
    });
    assert!(
        path.exists(),
        "the fake agent is missing after the build: {}",
        path.display()
    );
    path
}

const AGENT_MD: &str = "---\nname: main\nbrain: cloud\ndefault_mode: open\ntools:\n  - google.calendar.list_events\n  - google.gmail.send\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nBody.\n";

const READ_SKILL: &str = r#"---
name: list-events
version: 1
command: listevents
brain: cloud
trigger:
  manual: true
tools: [google.calendar.list_events]
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
List.
"#;

const WRITE_SKILL: &str = r#"---
name: send-mail
version: 1
command: sendmail
brain: cloud
trigger:
  manual: true
tools: [google.gmail.send]
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Send.
"#;

fn home(dir: &Path) -> PathBuf {
    let home = dir.join("home");
    let agent = home.join("agents/main");
    std::fs::create_dir_all(agent.join("skills")).unwrap();
    std::fs::write(agent.join("agent.md"), AGENT_MD).unwrap();
    std::fs::write(agent.join("skills/list-events.md"), READ_SKILL).unwrap();
    std::fs::write(agent.join("skills/send-mail.md"), WRITE_SKILL).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        format!(
            "version = 1\n\n[privacy]\nmode = \"open\"\n\n[acp]\nenabled = true\n\n\
             [acp.agents.opencode]\ncommand = \"{}\"\nargs = [\"happy\"]\n\
             provider_id = \"opencode\"\n\n[shell]\nsandbox = false\nallow_unsandboxed = true\n",
            fake_agent().display()
        ),
    )
    .unwrap();
    std::fs::write(
        home.join("providers.toml"),
        "[[provider]]\nid = \"opencode\"\nkind = \"acp\"\nagent = \"opencode\"\n\n\
         [brain]\ndefault = \"opencode\"\n",
    )
    .unwrap();
    home
}

#[test]
fn an_acp_default_brain_answers_a_read_only_skill() {
    let dir = tempfile::tempdir().unwrap();
    let home = home(dir.path());

    let turn = runner(&home)
        .run_turn("main", None, "/listevents", None)
        .expect("the ACP brain answers a read-only skill");

    let reply = turn.messages.last().expect("a reply");
    assert_eq!(reply.role, "assistant");
    assert!(
        reply.content.contains("hello world"),
        "reply: {:?}",
        reply.content
    );
}

#[test]
fn a_write_skill_on_an_acp_brain_is_refused_with_chat_only() {
    let dir = tempfile::tempdir().unwrap();
    let home = home(dir.path());

    let err = runner(&home)
        .run_turn("main", None, "/sendmail", None)
        .expect_err("a write skill is refused");

    let debug = format!("{err:?}");
    assert!(debug.contains("chat only"), "got {debug}");
    assert!(
        matches!(err, TurnError::ProviderConfig { .. }),
        "got {debug}"
    );
}

const READ_ONLY_AGENT_MD: &str = "---\nname: main\nbrain: cloud\ndefault_mode: open\ntools: []\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nBody.\n";

const NOOP_SKILL: &str = r#"---
name: noop
version: 1
command: noop
brain: cloud
trigger:
  manual: true
tools: []
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Noop.
"#;

/// A home whose only skill declares no tools, with the ACP fake agent given
/// `scenario` and one marker path argument.
fn read_only_home(dir: &Path, scenario: &str, marker: &Path) -> PathBuf {
    let home = dir.join("home");
    let agent = home.join("agents/main");
    std::fs::create_dir_all(agent.join("skills")).unwrap();
    std::fs::write(agent.join("agent.md"), READ_ONLY_AGENT_MD).unwrap();
    std::fs::write(agent.join("skills/noop.md"), NOOP_SKILL).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        format!(
            "version = 1\n\n[privacy]\nmode = \"open\"\n\n[acp]\nenabled = true\n\n\
             [acp.agents.opencode]\ncommand = \"{}\"\nargs = [\"{scenario}\", \"{}\"]\n\
             provider_id = \"opencode\"\n\n[shell]\nsandbox = false\nallow_unsandboxed = true\n",
            fake_agent().display(),
            marker.display()
        ),
    )
    .unwrap();
    std::fs::write(
        home.join("providers.toml"),
        "[[provider]]\nid = \"opencode\"\nkind = \"acp\"\nagent = \"opencode\"\n\n\
         [brain]\ndefault = \"opencode\"\n",
    )
    .unwrap();
    home
}

/// An empty-tools skill on an ACP brain cannot drive the
/// agent's own terminal.
#[test]
fn an_acp_read_only_brain_refuses_the_agents_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("home/agents/main/acp-workspace/marker");
    let home = read_only_home(dir.path(), "terminal-marker", &marker);

    let turn = runner(&home)
        .run_turn("main", None, "/noop", None)
        .expect("the ACP turn completes");

    let reply = turn.messages.last().unwrap().content.clone();
    assert!(reply.contains("terminal-error"), "reply: {reply}");
    assert!(!marker.exists(), "the read-only brain ran a terminal");
}

/// The same brain cannot write a file either.
#[test]
fn an_acp_read_only_brain_refuses_the_agents_fs_write() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir
        .path()
        .join("home/agents/main/acp-workspace/fs-written.txt");
    let home = read_only_home(dir.path(), "fs-write", &marker);

    let turn = runner(&home)
        .run_turn("main", None, "/noop", None)
        .expect("the ACP turn completes");

    let reply = turn.messages.last().unwrap().content.clone();
    assert!(reply.contains("write-error"), "reply: {reply}");
    assert!(!marker.exists(), "the read-only brain wrote a file");
}
