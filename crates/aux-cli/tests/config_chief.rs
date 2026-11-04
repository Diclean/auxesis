//! Every CLI path that can create `config.toml` names `main` as the chief. A
//! new home is never read as an older install, whose chief is `aux`, with the
//! four domain agents and their shipped grants. An existing config keeps what
//! it has: an explicit `aux` stays, and an older file without the key never
//! gains one.

mod common;

use common::sandbox_command;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

/// The CLI paths that write a config, with what each reads on stdin.
/// `{workspace}` is the main agent's workspace.
const PATHS: [(&[&str], &str); 3] = [
    // A preset domain: discovery needs no network.
    (
        &["mail", "add", "camille@gmail.com"],
        "1\nmon-mot-de-passe\n",
    ),
    (&["notify", "--test"], ""),
    (&["workspace", "trust", "{workspace}"], ""),
];

/// A sandbox home for `args`: an agent workspace when the path needs one.
fn home_for(dir: &Path, args: &[&str]) -> std::path::PathBuf {
    let home = dir.join(".auxesis");
    std::fs::create_dir_all(&home).unwrap();
    if args.contains(&"{workspace}") {
        std::fs::create_dir_all(home.join("agents/main/workspace")).unwrap();
    }
    home
}

/// Run one path. Most fail here (no daemon, no code): only the config counts.
fn run(dir: &Path, home: &Path, args: &[&str], stdin: &str) {
    let workspace = home.join("agents/main/workspace");
    let args: Vec<String> = args
        .iter()
        .map(|arg| arg.replace("{workspace}", &workspace.to_string_lossy()))
        .collect();
    let mut child = sandbox_command(env!("CARGO_BIN_EXE_aux"), dir, home)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aux");
    let mut input = child.stdin.take().expect("piped stdin");
    input.write_all(stdin.as_bytes()).unwrap();
    drop(input);
    child.wait_with_output().expect("wait for aux");
}

fn agent_ids(home: &Path) -> Vec<String> {
    let agents = auxd::agents::registry(home).unwrap();
    agents.into_iter().map(|agent| agent.id).collect()
}

#[test]
fn a_cli_path_that_creates_the_config_names_main_the_chief() {
    for (args, stdin) in PATHS {
        let dir = tempfile::tempdir().unwrap();
        let home = home_for(dir.path(), args);
        run(dir.path(), &home, args, stdin);
        let config = std::fs::read_to_string(home.join("config.toml")).unwrap();
        assert!(
            config.contains("default_agent = \"main\""),
            "{args:?}: {config}"
        );
        assert_eq!(auxd::agents::chief_id(&home), "main", "{args:?}");
        assert_eq!(agent_ids(&home), ["main"], "{args:?}");
    }
}

#[test]
fn a_cli_path_keeps_the_chief_an_existing_config_has() {
    // An explicit `aux`, and an older install's file without the key.
    let existing = [
        "version = 1\ndefault_agent = \"aux\"\n",
        "version = 1\n\n[privacy]\nmode = \"private\"\n",
    ];
    for before in existing {
        for (args, stdin) in PATHS {
            let dir = tempfile::tempdir().unwrap();
            let home = home_for(dir.path(), args);
            std::fs::write(home.join("config.toml"), before).unwrap();
            run(dir.path(), &home, args, stdin);
            let after = std::fs::read_to_string(home.join("config.toml")).unwrap();
            assert!(after.starts_with(before), "{args:?}: {after}");
            let raw: toml::Table = toml::from_str(&after).unwrap();
            let named = raw.get("default_agent").and_then(|value| value.as_str());
            let expected = before.contains("default_agent").then_some("aux");
            assert_eq!(named, expected, "{args:?}: {after}");
            assert_eq!(auxd::agents::chief_id(&home), "aux", "{args:?}");
            let ids = agent_ids(&home);
            assert!(ids.iter().any(|id| id == "aux"), "{args:?}: {ids:?}");
        }
    }
}
