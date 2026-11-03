//! Concurrent first `Store::open` must never observe SQLCipher half-initialised.
//!
//! SQLCipher's bundled amalgamation sets SQLite's `isInit` flag *before* it
//! runs `SQLITE_EXTRA_INIT` (`sqlcipher_extra_init`), and it runs that extra
//! init outside the init mutex. A second thread that opens a store inside that
//! window returns from `sqlite3_initialize` at once, then `PRAGMA key` sees
//! `sqlcipher_init == 0` and fails. `Store::open` surfaces that as an error, and
//! callers such as the daemon's `TestApi::start_with` panic on it.
//!
//! That window is open only for the first SQLCipher use in a process. This is a
//! dedicated test binary whose only test is the batch below, so that batch is
//! the process's first SQLCipher use: `cargo test --test concurrent_open`, the
//! whole-workspace `cargo test`, and one-process-per-test cargo-nextest all run
//! it in a fresh process. Repetition across fresh processes is the caller's: run
//! this binary once per round (`for i in $(seq 20); do cargo test ...; done`).
//!
//! The window is timing-dependent and not always reachable on an idle host: with
//! the guard removed, a single batch can still pass, so this is a guard over
//! repeated fresh-process batches, not a reliable reproduction. Run it repeated.
//!
//! Do not fold a re-exec loop back in. Twenty in-process child rounds of
//! [`OPENERS`] first opens took ~130 s locally and over 200 s on the CI runner,
//! which nextest's 180 s per-test termination killed. That timeout, not a
//! deadlock, was the "hang". One batch is the same race at a tenth of the cost,
//! and every extra run of the binary is another fresh process.
//!
//! Each store has its own temp dir and its own file-based `master.key`: no
//! macOS Keychain, no shared path, no network.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

/// Concurrent first opens per process: a saturated parallel test run.
const OPENERS: usize = 16;

#[test]
fn concurrent_open_never_sees_sqlcipher_uninitialised() {
    run_batch();
}

/// Open [`OPENERS`] stores from threads released together. Any error or panic
/// fails the test.
fn run_batch() {
    let homes: Vec<tempfile::TempDir> = (0..OPENERS)
        .map(|_| tempfile::tempdir().expect("a temp store home"))
        .collect();
    let paths: Vec<PathBuf> = homes
        .iter()
        .enumerate()
        .map(|(index, home)| {
            write_master_key(home.path(), index as u8);
            home.path().join("store.db")
        })
        .collect();

    // Keep one path to prove, after the batch, that its key still opens it and
    // that SQLCipher is the cipher in use.
    let verify_path = paths[0].clone();

    let barrier = Arc::new(Barrier::new(OPENERS));
    let handles: Vec<_> = paths
        .into_iter()
        .map(|path| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                match aux_store::Store::open(&path) {
                    Ok(store) => {
                        drop(store);
                        Ok(())
                    }
                    Err(err) => Err(format!("{}: {err}", path.display())),
                }
            })
        })
        .collect();

    let mut failures = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => failures.push(err),
            Err(_) => failures.push("an opener thread panicked".to_string()),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {OPENERS} concurrent Store::open calls failed: {failures:#?}",
        failures.len()
    );

    verify_keyed_read(&verify_path);
}

/// Reopen one store with its file key: SQLCipher must be active, and a keyed
/// read must see the migrated schema. A plaintext fallback would let an
/// unapplied key hide here.
fn verify_keyed_read(path: &Path) {
    let conn = aux_store::open_keyed(path).expect("reopen an opened store with its key");
    let version: String = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .expect("PRAGMA cipher_version");
    assert!(
        !version.trim().is_empty(),
        "SQLCipher reported an empty cipher_version"
    );
    let tables: i64 = conn
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .expect("a keyed read of the opened store");
    assert!(tables > 0, "the keyed store has no schema to read");
}

/// A 32-byte file-based key shaped like `master.key`: owner-only, one name.
fn write_master_key(home: &Path, seed: u8) {
    let mut key = [0u8; 32];
    key[0] = seed;
    key[31] = 0x5a;

    let path = home.join("master.key");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).expect("create master.key");
    file.write_all(&key).expect("write master.key");
    file.sync_all().expect("sync master.key");
}
