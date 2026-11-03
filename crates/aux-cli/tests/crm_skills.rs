//! CRM acceptance from the CLI: the three CRM skills run from the real `aux`
//! binary over fixtures, under the mandated sandbox — a fresh temp `HOME` and
//! `AUXESIS_HOME`, `AUXESIS_SANDBOX=1` and an ephemeral API port. The people
//! are fictional, their phones are E.164, and the temp dir goes away with the
//! `TempDir` guard.
//!
//! `client-brief` reads the seeded party, `log-interaction` writes one
//! interaction and its party-linked memory with `skill:log-interaction`
//! provenance, and `brief` reads the CRM section beside the empty `docs.queue`
//! hook.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CLIENT_BRIEF: &str =
    include_str!("../../aux-runtime/src/skills/fixtures/skills/client-brief.md");
const LOG_INTERACTION: &str =
    include_str!("../../aux-runtime/src/skills/fixtures/skills/log-interaction.md");
const BRIEF: &str = include_str!("../../aux-runtime/src/skills/fixtures/skills/brief.md");
const VCARD: &str = include_str!("fixtures/crm-seed.vcf");

/// The `main` agent the CLI runs the skills as. Open mode keeps the fixture
/// readable; every CRM read and the write are local either way.
const AGENT: &str = "---
name: main
brain: cloud
default_mode: open
channels: [mac]
tools:
  - crm.search
  - crm.get
  - crm.today
  - crm.create_followup
  - crm.log_interaction
  - docs.queue
recipients:
  policy: known-contacts
  allowlist: []
---
CRM skills assistant.
";

/// Run `aux <args>` in the literal sandbox environment the project mandates.
fn aux(dir: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aux"))
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .expect("run aux")
}

/// Run `aux <args>` in the sandbox and answer the run-level card with `input`.
/// An `each_run` skill (here `log-interaction`) reads the owner's `y`/`n` from
/// the terminal, which the test supplies on the child's stdin.
fn aux_with_stdin(dir: &Path, home: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aux"))
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aux");
    child
        .stdin
        .take()
        .expect("the child's stdin")
        .write_all(input)
        .expect("write the approval answer");
    child.wait_with_output().expect("run aux")
}

fn text(output: &[u8]) -> String {
    String::from_utf8_lossy(output).into_owned()
}

/// A temp dir, the `.auxesis` home under it, the three skills on `main`, and one
/// seeded fictional party (Camille Exemple) with an E.164 phone.
fn sandbox() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".auxesis");
    let agent = home.join("agents/main");
    std::fs::create_dir_all(agent.join("skills")).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    std::fs::write(agent.join("agent.md"), AGENT).unwrap();
    std::fs::write(agent.join("skills/client-brief.md"), CLIENT_BRIEF).unwrap();
    std::fs::write(agent.join("skills/log-interaction.md"), LOG_INTERACTION).unwrap();
    std::fs::write(agent.join("skills/brief.md"), BRIEF).unwrap();

    let vcf = dir.path().join("crm-seed.vcf");
    std::fs::write(&vcf, VCARD).unwrap();
    let seeded = aux(
        dir.path(),
        &home,
        &[
            "contacts",
            "import",
            vcf.to_str().unwrap(),
            "--country",
            "FR",
        ],
    );
    assert!(
        seeded.status.success(),
        "seeding the fixture failed: {}",
        text(&seeded.stderr)
    );
    (dir, home)
}

/// Assert the run succeeded and served exactly `actions` calls.
fn ran(output: &Output, actions: usize) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        text(&output.stdout),
        text(&output.stderr)
    );
    let stdout = text(&output.stdout);
    assert!(
        stdout.contains(&format!("ran {actions} action(s)")),
        "unexpected output: {stdout}"
    );
}

#[test]
fn the_crm_skills_run_from_the_cli_on_fixtures() {
    let (dir, home) = sandbox();
    let dir = dir.path();

    // client-brief: one read of the seeded party.
    let client_fill = concat!(
        r#"{"slots":{"name":"Camille Exemple"},"calls":[{"tool":"crm_get","#,
        r#""arguments":{"name":"Camille Exemple","timeline":5,"memory":20}}]}"#
    );
    let briefed = aux(dir, &home, &["skill", "run", "client-brief", client_fill]);
    ran(&briefed, 1);

    // log-interaction: one write carrying the party and its provenance.
    let log_fill = concat!(
        r#"{"slots":{"party":"Camille Exemple","note":"Appel de suivi"},"calls":[{"tool":"crm_log_interaction","#,
        r#""arguments":{"party":"Camille Exemple","kind":"note","at":"2026-10-06T10:00:00Z","#,
        r#""source_ref":"{\"owner\":true}","summary":"Appel de suivi avec Camille Exemple","#,
        r#""memory":[{"kind":"fact","title":"Appel de suivi","body":"Rappeler la semaine prochaine."}]}}]}"#
    );
    let logged = aux_with_stdin(
        dir,
        &home,
        &["skill", "run", "log-interaction", log_fill],
        b"y\n",
    );
    ran(&logged, 1);

    // brief: the CRM section (who today, follow-ups due) and the empty
    // documents-queue hook.
    let brief_fill = concat!(
        r#"{"slots":{"focus":"aujourd'hui"},"calls":["#,
        r#"{"tool":"crm_today","arguments":{}},{"tool":"docs_queue","arguments":{}}]}"#
    );
    let brief = aux(dir, &home, &["skill", "run", "brief", brief_fill]);
    ran(&brief, 2);

    // The write landed on the party: one interaction and one memory row, both
    // provenanced as the skill.
    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
    let party = aux_crm::Crm::new(&store)
        .search("Camille", 10)
        .expect("search the seeded party")
        .into_iter()
        .find(|matched| matched.display_name == "Camille Exemple")
        .expect("the seeded party")
        .id;

    let interactions = store.interactions_for_party(party).unwrap();
    assert_eq!(interactions.len(), 1, "one logged interaction");
    assert_eq!(interactions[0].kind, "note");
    assert_eq!(interactions[0].provenance, "skill:log-interaction");

    let memory = store.memory_items_for_party("main", party, 10).unwrap();
    assert_eq!(memory.len(), 1, "one party-linked memory row");
    assert_eq!(memory[0].source, "skill:log-interaction");
    assert_eq!(memory[0].kind, "fact");
    assert_eq!(memory[0].title, "Appel de suivi");
}
