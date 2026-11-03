//! Regression tests for BAPIV2-02: `append_rule` must be concurrency-safe
//! (no lost updates, no torn `config.toml`) and must refuse to append to a
//! file that is already broken.
//!
//! This file compiles against the pre-fix code on purpose: it is the
//! isolated reproduction for the release blocker (see the fix report).

use std::sync::{Arc, Barrier};
use std::time::Duration;

use aux_engine::{append_rule, load_rules};
use kernel_broker::{Action, Rule};

/// 8 threads released by one barrier, all appending to the same file: every
/// rule must survive and the file must still parse (pre-fix: 2 of 8 survived
/// and a torn file was observed).
#[test]
fn concurrent_appends_never_lose_or_corrupt_a_rule() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "version = 1\ndefault_agent = \"main\"\n\n[[providers]]\nid = \"fakey\"\n\
         base_url = \"http://127.0.0.1:9/v1\"\nmodel = \"fake-model\"\nkind = \"fake\"\n",
    )
    .unwrap();

    let threads = 8usize;
    let barrier = Arc::new(Barrier::new(threads));
    let mut handles = Vec::new();
    for index in 0..threads {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            append_rule(
                &path,
                &Rule::new("main", format!("tool_{index}"), Action::Allow),
            )
            .unwrap();
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    let rules = load_rules(&path).unwrap_or_else(|err| {
        panic!("concurrent appends corrupted config.toml: {err}");
    });
    let appended = rules
        .iter()
        .filter(|rule| rule.tool.starts_with("tool_"))
        .count();
    assert_eq!(
        appended, threads,
        "every concurrent append must survive; got {appended} of {threads} in {rules:?}"
    );
}

/// A reader racing the writers must only ever observe a parseable file (the
/// pre-fix truncating `fs::write` exposes half-written content).
#[test]
fn a_reader_racing_appends_never_sees_a_torn_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "version = 1\n").unwrap();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_path = path.clone();
    let reader_stop = Arc::clone(&stop);
    let reader = std::thread::spawn(move || {
        let mut reads = 0usize;
        while !reader_stop.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(text) = std::fs::read_to_string(&reader_path) {
                if !text.trim().is_empty() {
                    toml::from_str::<toml::Value>(&text)
                        .unwrap_or_else(|err| panic!("torn read ({err}): {text:?}"));
                }
                reads += 1;
            }
        }
        reads
    });

    for index in 0..32 {
        append_rule(
            &path,
            &Rule::new("main", format!("tool_{index}"), Action::Allow),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let reads = reader.join().unwrap();

    assert!(reads > 0, "the reader never observed the file");
    assert_eq!(load_rules(&path).unwrap().len(), 32);
}

/// An already-broken file is refused with a parse error and stays untouched.
#[test]
fn a_corrupt_config_is_refused_not_appended_to() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let broken = "[[rules]]\ndot = \"main\"\ntool = \"ow\"\n";
    std::fs::write(&path, broken).unwrap();

    let err = append_rule(&path, &Rule::new("main", "shell", Action::Allow)).unwrap_err();
    assert!(
        err.to_string().contains("parsing [[rules]]"),
        "a broken file reports the parse error: {err}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), broken);
}
