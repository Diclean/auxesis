//! An ACP turn in private mode. The agent is the `aux-acp` fake agent
//! (scenario `private-probe`): it records what it was sent, reads a workspace file
//! through the host and answers with both. Nothing here touches the network.
//!
//! The prompt carries a contact (Camille Exemple), her e-mail, an IBAN and an
//! E.164 phone. The agent must see tokens only; the owner's screen (the stored
//! rows rehydrated with the session's tokens) shows the values.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Once};

use auxd::api::{EngineTurnRunner, TurnRunner};
use kernel_privacy::ContactIndex;

const NAME: &str = "Camille Exemple";
const EMAIL: &str = "camille@exemple.fr";
const IBAN: &str = "FR1420041010050500013M02606";
const PHONE: &str = "+33612345678";

fn contacts() -> aux_runtime::known_names::Contacts {
    let mut index = ContactIndex::new();
    assert!(index.add_from_header(NAME, EMAIL).is_some());
    Arc::new(index)
}

/// The `aux-acp` fake agent, next to the test binary (built once when missing).
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
        build.args([
            "build",
            "-p",
            "aux-acp",
            "--bin",
            "acp-fake-agent",
            "--locked",
            "--offline",
        ]);
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
    assert!(path.exists(), "missing fake agent: {}", path.display());
    path
}

const AGENT_MD: &str = "---\nname: main\nbrain: cloud\ndefault_mode: open\ntools: []\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nBody.\n";

/// A home on an ACP brain in `mode`, with a note the agent reads from its workspace.
fn home(dir: &Path, mode: &str, note: &Path) -> PathBuf {
    let home = dir.join("home");
    let agent = home.join("agents/main");
    std::fs::create_dir_all(agent.join("skills")).unwrap();
    std::fs::write(agent.join("agent.md"), AGENT_MD).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        format!(
            "version = 1\n\n[privacy]\nmode = \"{mode}\"\n\n[acp]\nenabled = true\n\n\
             [acp.agents.opencode]\ncommand = \"{}\"\nargs = [\"private-probe\", \"{}\"]\n\
             provider_id = \"opencode\"\n\
             env_passthrough = [\"ACP_PROBE_NOTE\", \"ACP_PROBE_API_KEY\"]\n\n[shell]\nsandbox = false\nallow_unsandboxed = true\n",
            fake_agent().display(),
            note.display()
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

struct Run {
    /// Keeps the sandbox home alive for the store checks.
    _dir: tempfile::TempDir,
    home: PathBuf,
    /// What the agent recorded it received (prompt, file, permission answer).
    received: String,
    /// The stored user row and assistant row.
    stored: Vec<String>,
    thread_id: i64,
}

fn run(mode: &str) -> Run {
    // Values the agent's environment would carry: a note and its own API key.
    std::env::set_var("ACP_PROBE_NOTE", format!("{NAME} {IBAN}"));
    std::env::set_var("ACP_PROBE_API_KEY", "fake-key-for-the-test");
    let dir = tempfile::tempdir().unwrap();
    let note = dir.path().join("home/agents/main/acp-workspace/note.txt");
    let home = home(dir.path(), mode, &note);
    std::fs::create_dir_all(note.parent().unwrap()).unwrap();
    std::fs::write(&note, format!("Compte de {NAME}: {IBAN}")).unwrap();
    let runner = EngineTurnRunner::new(&home).with_contacts(contacts());
    let message = format!("Vire 10 EUR à {NAME} ({EMAIL}, {PHONE}), IBAN {IBAN}.");
    let turn = runner
        .run_turn("main", None, &message, None)
        .expect("an ACP turn completes in this mode");
    let received = std::fs::read_to_string(note.with_extension("received"))
        .expect("the agent recorded what it received");
    Run {
        home,
        _dir: dir,
        received,
        stored: turn.messages.iter().map(|m| m.content.clone()).collect(),
        thread_id: turn.thread.id,
    }
}

#[test]
fn a_private_acp_turn_shows_the_agent_tokens_and_the_owner_the_values() {
    let run = run("private");

    // D1 and D2: the agent was sent no raw value, in the prompt or in the file.
    // A name is not a hidden value.
    assert!(run.received.contains(NAME), "{}", run.received);
    for value in [EMAIL, IBAN, PHONE] {
        assert!(
            !run.received.contains(value),
            "the agent received {value}: {}",
            run.received
        );
    }
    assert!(
        run.received.contains('⟦'),
        "tokens expected: {}",
        run.received
    );
    let file_line = run
        .received
        .lines()
        .find(|line| line.starts_with("file="))
        .expect("a file line");
    assert!(
        file_line.contains('⟦'),
        "the file was tokenised: {file_line}"
    );
    // The same value is the same token in the prompt and in the file (one map).
    let token_of = |text: &str, class: &str| {
        let start = text.find(&format!("⟦{class}_")).expect("a token");
        let end = text[start..].find('⟧').unwrap() + start;
        text[start..end].to_string()
    };
    let prompt_line = run.received.lines().next().unwrap();
    assert_eq!(token_of(prompt_line, "IBAN"), token_of(file_line, "IBAN"));

    // Rows hold the gated copy (G1); the owner's screen resolves it locally.
    assert!(
        run.stored
            .iter()
            .all(|row| !row.contains(IBAN) && !row.contains(EMAIL)),
        "a stored row holds a raw value: {:?}",
        run.stored
    );
    let shown =
        auxd::privacy_wiring::rehydrate_local(run.thread_id, run.stored.last().expect("an answer"));
    for value in [EMAIL, IBAN, PHONE] {
        assert!(
            shown.contains(value),
            "the owner does not see {value}: {shown}"
        );
    }
}

#[test]
fn an_open_acp_turn_is_unchanged() {
    let run = run("open");
    assert!(
        run.received.contains(IBAN),
        "open mode sends the text: {}",
        run.received
    );
    assert!(run.received.contains(EMAIL), "{}", run.received);
    assert!(
        !run.received.contains('⟦'),
        "no tokens in open mode: {}",
        run.received
    );
    assert!(
        run.stored[0].contains(IBAN),
        "the user row is raw in open mode"
    );
}

#[test]
fn a_private_acp_turn_keeps_the_agent_in_an_empty_directory_and_stores_no_message() {
    let run = run("private");

    // The agent's cwd is a neutral scratch under the Aux tmp, not the workspace,
    // and the scratch is gone with the turn.
    let cwd = run
        .received
        .lines()
        .find_map(|line| line.strip_prefix("cwd="))
        .expect("a cwd line");
    assert!(cwd.contains("/tmp/acp-"), "cwd: {cwd}");
    assert!(!cwd.contains("acp-workspace"), "cwd: {cwd}");
    let left: Vec<_> = std::fs::read_dir(run.home.join("tmp"))
        .map(|dir| dir.flatten().map(|entry| entry.file_name()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "the scratch directory stayed: {left:?}");

    // Only the agent's own credential crosses; the note with the values does not.
    assert!(run.received.contains("note_env=unset"), "{}", run.received);
    assert!(
        run.received.contains("key_env=fake-key-for-the-test"),
        "{}",
        run.received
    );

    // G1: the session exists, with no title and no message row.
    let store = aux_store::Store::open(&kernel_core::store_path(&run.home)).unwrap();
    assert_eq!(
        store.list_messages(run.thread_id).unwrap().len(),
        0,
        "a private ACP turn stored a message"
    );
    let session = store.session(run.thread_id).unwrap().expect("the session");
    assert!(session.title.is_none(), "title: {:?}", session.title);
}

#[test]
fn an_open_acp_turn_keeps_its_environment_and_stores_its_rows() {
    let run = run("open");
    assert!(run.received.contains(IBAN), "{}", run.received);
    let store = aux_store::Store::open(&kernel_core::store_path(&run.home)).unwrap();
    assert_eq!(store.list_messages(run.thread_id).unwrap().len(), 2);
}
