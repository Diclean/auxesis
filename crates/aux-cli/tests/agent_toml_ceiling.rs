//! A bad `agent.toml` fails `aux skill run` closed, from the real `aux`
//! binary, under the mandated sandbox (a fresh temp `HOME` and `AUXESIS_HOME`,
//! `AUXESIS_SANDBOX=1`, an ephemeral API port). The run is refused before any
//! call, and the error names the file that failed.

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

const BRIEF: &str = include_str!("../../aux-runtime/src/skills/fixtures/skills/brief.md");
const AGENT: &str = "---\nname: main\nbrain: cloud\ndefault_mode: open\nchannels: [mac]\n\
tools:\n  - crm.today\n  - docs.queue\n---\nBrief assistant.\n";
const FILL: &str = concat!(
    r#"{"slots":{"focus":"today"},"calls":["#,
    r#"{"tool":"crm_today","arguments":{}},{"tool":"docs_queue","arguments":{}}]}"#
);

fn run_brief(dir: &Path, home: &Path) -> Output {
    common::sandbox_command(env!("CARGO_BIN_EXE_aux"), dir, home)
        .args(["skill", "run", "brief", FILL])
        .output()
        .expect("run aux")
}

fn sandbox() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".auxesis");
    let agent = home.join("agents/main");
    std::fs::create_dir_all(agent.join("skills")).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version = 1\ndefault_agent = \"main\"\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    std::fs::write(agent.join("agent.md"), AGENT).unwrap();
    std::fs::write(agent.join("skills/brief.md"), BRIEF).unwrap();
    (dir, home)
}

fn refused(output: &Output, toml: &Path) {
    assert!(!output.status.success(), "the run must fail closed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("ran "), "no action ran: {stdout}");
    assert!(stderr.contains("unreadable"), "{stderr}");
    assert!(
        stderr.contains(&toml.display().to_string()),
        "the error names {}: {stderr}",
        toml.display()
    );
}

#[test]
fn a_skill_run_fails_closed_on_a_bad_agent_toml_and_names_the_file() {
    let (dir, home) = sandbox();
    let toml = home.join("agents/main/agent.toml");

    // Control: the same run succeeds with no `agent.toml`.
    let ok = run_brief(dir.path(), &home);
    assert!(
        ok.status.success(),
        "control run: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    std::fs::write(&toml, "not = [toml").unwrap();
    refused(&run_brief(dir.path(), &home), &toml);

    std::fs::remove_file(&toml).unwrap();
    std::fs::create_dir(&toml).unwrap();
    refused(&run_brief(dir.path(), &home), &toml);
}
