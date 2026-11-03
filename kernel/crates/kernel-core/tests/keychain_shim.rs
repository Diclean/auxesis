//! The in-tree shim-only Keychain checks: a recording `security` first in
//! `PATH` must stay untouched while `run_security` is refused.
//!
//! Two phases (KC-01):
//!
//! 1. the sandbox guard is active (`AUXESIS_SANDBOX=1`) — refused;
//! 2. **unflagged** (no `AUXESIS_*` variable, a scratch `HOME`) — default
//!    deny: the Keychain is touched only with `AUXESIS_ALLOW_KEYCHAIN=1`, so
//!    a plain `cargo test` run can never reach the owner's real Keychain.
//!
//! The tests do not set the opt-in themselves: that is the condition under
//! test. `PATH` is process-global; this binary has a single test.

use std::path::PathBuf;

fn shim_dir(dir: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let marker = dir.path().join("invoked");
    let shim = bin.join("security");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\necho \"invoked: $*\" >> \"{}\"\nexit 44\n",
            marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (bin, marker)
}

#[test]
fn run_security_never_invokes_the_shim_without_the_explicit_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let (bin, marker) = shim_dir(&dir);

    // PATH is process-global; this binary has a single test.
    let previous_path = std::env::var_os("PATH");
    let mut paths: Vec<PathBuf> = vec![bin];
    if let Some(path) = &previous_path {
        paths.extend(std::env::split_paths(path));
    }
    std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
    let previous_sandbox = std::env::var_os("AUXESIS_SANDBOX");
    let previous_opt_in = std::env::var_os("AUXESIS_ALLOW_KEYCHAIN");
    let previous_home = std::env::var_os("HOME");
    let scratch_home = dir.path().join("home");
    std::fs::create_dir_all(&scratch_home).unwrap();

    let call = || {
        kernel_core::keychain::run_security(&[
            "find-generic-password",
            "-s",
            "auxesis",
            "-a",
            "nobody",
        ])
    };

    // Phase 1: the sandbox guard is active.
    std::env::set_var("AUXESIS_SANDBOX", "1");
    std::env::remove_var("AUXESIS_ALLOW_KEYCHAIN");
    let error = call().expect_err("the sandbox guard must refuse");
    assert!(error.contains("not queried"), "{error}");
    assert!(
        !marker.exists(),
        "the security shim was invoked despite the sandbox guard"
    );

    // Phase 2: unflagged, scratch HOME — default deny without the opt-in.
    std::env::remove_var("AUXESIS_SANDBOX");
    std::env::set_var("HOME", &scratch_home);
    let error = call().expect_err("default deny must refuse without the opt-in");
    assert!(error.contains("not queried"), "{error}");
    assert!(
        !marker.exists(),
        "the security shim was invoked without AUXESIS_ALLOW_KEYCHAIN=1"
    );

    match previous_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    match previous_opt_in {
        Some(value) => std::env::set_var("AUXESIS_ALLOW_KEYCHAIN", value),
        None => std::env::remove_var("AUXESIS_ALLOW_KEYCHAIN"),
    }
    match previous_sandbox {
        Some(value) => std::env::set_var("AUXESIS_SANDBOX", value),
        None => std::env::remove_var("AUXESIS_SANDBOX"),
    }
    match previous_path {
        Some(path) => std::env::set_var("PATH", path),
        None => std::env::remove_var("PATH"),
    }
}
