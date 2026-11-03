//! Regression for K-REGISTRY-PERF r1 (NO SEAL P2).
//!
//! The thread-local `NormalizedText` cache introduced on `wo/k-registry-perf`
//! was reached through `LocalKey::with`. A scan that ran while a non-main
//! thread was tearing down its thread-locals — for example, from another
//! thread-local's `Drop` — called into `SHARED` after the storage was gone
//! and aborted with `AccessError`. The fix replaced every cache touch with
//! `try_with` and a fresh-build fallback whose output is byte-identical to
//! the cached view (so speed and recognition output are unchanged for normal
//! scans).
//!
//! We cannot reproduce the panic inside `cargo test` itself: the first panic
//! from a thread-local `Drop` marks the test runner as failed and pins the
//! stack on a builtin PANIC, so the panic never clears during the test. The
//! repro therefore lives in `examples/repro_shared_drop.rs` and this test
//! spawns it as a fresh subprocess via `cargo run`. On `1391d639` the
//! subprocess aborts before printing `ok`, and this test fails on a non-zero
//! exit. After the fix the subprocess prints `ok` and exits 0.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = "repro_shared_drop";

/// Run the example in a fresh subprocess, capture stdout, return (status, log).
fn run_repro() -> (i32, String) {
    // The crate's own manifest: cargo finds the enclosing workspace from it,
    // so this works whether the crate sits under a workspace root or in a
    // checkout that carries its own.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let cargo = env!("CARGO");
    let output = Command::new(cargo)
        .arg("run")
        .arg("--quiet")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("-p")
        .arg(env!("CARGO_PKG_NAME"))
        .arg("--example")
        .arg(BIN)
        .output()
        .unwrap_or_else(|err| panic!("spawn `{cargo}` for `{BIN}`: {err}"));
    let log = format!(
        "---- stdout ----\n{}\n---- stderr ----\n{}---- end ----",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    (output.status.code().unwrap_or(-1), log)
}

/// K-REGISTRY-PERF r1: a scan inside another thread-local's `Drop`, on a
/// non-main thread, must not panic and must produce the same byte-identical
/// output as a scan on a thread that has free access to the cache. The
/// subprocess prints `ok` and exits 0 only when both call sites are safe.
#[test]
fn a_scan_inside_a_thread_local_drop_does_not_abort() {
    let (code, log) = run_repro();
    assert_eq!(code, 0, "repro `{BIN}` exited {code} (expected 0)\n{log}");
    assert!(
        log.contains("ok"),
        "repro `{BIN}` did not print `ok`\n{log}"
    );
}
