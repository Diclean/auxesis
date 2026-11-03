//! Shared helper for the `aux` CLI integration tests.
//!
//! Every test that spawns `aux` goes through [`sandbox_command`], so no child
//! ever inherits the owner's HOME, the real API port (2893) or a live daemon.

#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Stdio};

/// Build a `Command` for a spawned `aux` binary inside a test sandbox.
///
/// It runs with a cleared environment and pins `HOME` to the temp `dir` and
/// `AUXESIS_HOME` to `home`, marks the child as sandboxed
/// (`AUXESIS_SANDBOX=1`) and sets `AUXESIS_API_PORT=0`, so the child can never
/// reach the real daemon. The assert keeps `home` literally under `dir`, so a
/// `$HOME` expansion mistake cannot point a child at the real `~/.auxesis`.
pub fn sandbox_command(binary: &str, dir: &Path, home: &Path) -> Command {
    assert!(
        home.starts_with(dir),
        "refusing to spawn {binary}: AUXESIS_HOME {} is not under the temp dir {}",
        home.display(),
        dir.display()
    );
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("HOME", dir)
        .env("AUXESIS_HOME", home)
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null());
    command
}
