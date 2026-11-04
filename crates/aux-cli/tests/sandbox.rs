//! The sandbox guard, end to end against the real `aux` binary.
//!
//! With `AUXESIS_SANDBOX=1` — or with `$HOME` unset, empty, relative, or
//! overridden away from the OS user database home — `aux` refuses a home
//! that resolves to or under the real `~/.auxesis`, and accepts the
//! recommended literal sandbox invocation. Every run uses a temp dir; the
//! refusal cases pass the real path only as `AUXESIS_HOME`, and the guard
//! refuses before any file is opened (`aux --version` never touches a home).

use std::path::Path;
use std::process::{Command, Output};

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

/// Run `aux <args>` with a controlled environment.
fn run(
    args: &[&str],
    dir: Option<&Path>,
    home: Option<&Path>,
    sandbox: bool,
    api_port: Option<&str>,
) -> Output {
    let mut command = Command::new(aux_bin());
    command.args(args).env_clear();
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    if let Some(dir) = dir {
        command.env("HOME", dir);
    }
    if let Some(home) = home {
        command.env("AUXESIS_HOME", home);
    }
    if sandbox {
        command.env("AUXESIS_SANDBOX", "1");
    }
    if let Some(port) = api_port {
        command.env("AUXESIS_API_PORT", port);
    }
    command.output().expect("run aux")
}

fn version(
    dir: Option<&Path>,
    home: Option<&Path>,
    sandbox: bool,
    api_port: Option<&str>,
) -> Output {
    run(&["--version"], dir, home, sandbox, api_port)
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The OS user database home — never the overridden `$HOME`.
fn os_home() -> Option<std::path::PathBuf> {
    kernel_core::real_user_home()
}

fn assert_refused(output: &Output) {
    assert!(
        !output.status.success(),
        "aux must refuse: {}",
        text(output)
    );
    assert!(
        text(output).contains("refus de sandbox"),
        "{}",
        text(output)
    );
}

/// The invocation its own error message recommends, with the sandbox flag and
/// an explicit ephemeral port, must run.
#[test]
fn recommended_sandbox_command_runs() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox_home = dir.path().join("mktemp-like").join(".auxesis");
    let output = version(Some(dir.path()), Some(&sandbox_home), true, Some("0"));
    assert!(output.status.success(), "{}", text(&output));
}

/// The 2026-10-05 incident: `HOME=<tmp>` while `AUXESIS_HOME` expanded to the
/// real `~/.auxesis`. The guard must refuse before opening anything.
#[test]
fn sandbox_refuses_the_incident_spelling() {
    let Some(real_home) = os_home() else { return };
    let dir = tempfile::tempdir().unwrap();
    let output = version(
        Some(dir.path()),
        Some(&real_home.join(".auxesis")),
        true,
        Some("0"),
    );
    assert_refused(&output);
}

/// A sandboxed process with the real `$HOME` still may not use the real home.
#[test]
fn sandbox_refuses_the_real_home_even_with_the_real_home_env() {
    let Some(real_home) = os_home() else { return };
    let output = version(
        Some(&real_home),
        Some(&real_home.join(".auxesis")),
        true,
        Some("0"),
    );
    assert_refused(&output);
}

/// An overridden `$HOME` alone (no sandbox flag) is already a sandbox signal.
#[test]
fn home_override_alone_refuses_the_real_home() {
    let Some(real_home) = os_home() else { return };
    let dir = tempfile::tempdir().unwrap();
    let output = version(
        Some(dir.path()),
        Some(&real_home.join(".auxesis")),
        false,
        None,
    );
    assert_refused(&output);
}

/// Unset, empty and relative `$HOME` are violations too.
#[test]
fn invalid_home_refuses_the_real_home() {
    let Some(real_home) = os_home() else { return };
    let real_aux = real_home.join(".auxesis");
    // Unset HOME (dir = None), sandbox flag absent: the guard is still armed.
    assert_refused(&version(None, Some(&real_aux), false, None));
    // Empty HOME.
    assert_refused(&version(Some(Path::new("")), Some(&real_aux), false, None));
    // Relative HOME.
    assert_refused(&version(
        Some(Path::new("relative/home")),
        Some(&real_aux),
        false,
        None,
    ));
}

/// With neither `AUXESIS_HOME` nor a usable `$HOME`, refuse — never
/// fall back to the CWD.
#[test]
fn no_home_at_all_refuses_instead_of_a_cwd_fallback() {
    let output = version(None, None, true, Some("0"));
    assert_refused(&output);
    assert!(
        text(&output).contains("AUXESIS_HOME"),
        "the refusal must name the missing variable: {}",
        text(&output)
    );
}

/// The case-insensitive spelling of the real `.auxesis` is refused.
#[test]
fn sandbox_refuses_a_case_variant_of_the_real_home() {
    let Some(real_home) = os_home() else { return };
    let dir = tempfile::tempdir().unwrap();
    let output = version(
        Some(dir.path()),
        Some(&real_home.join(".AUXESIS")),
        true,
        Some("0"),
    );
    assert_refused(&output);
}

/// A symlink to the real `~/.auxesis` (even a dangling one) is refused.
#[test]
#[cfg(unix)]
fn sandbox_refuses_a_symlink_to_the_real_home() {
    let Some(real_home) = os_home() else { return };
    let dir = tempfile::tempdir().unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(real_home.join(".auxesis"), &alias).unwrap();
    let output = version(Some(dir.path()), Some(&alias), true, Some("0"));
    assert_refused(&output);
}

/// A literal sandbox home is accepted with and without the flag.
#[test]
fn a_literal_sandbox_home_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox_home = dir.path().join("mktemp-like").join(".auxesis");
    let output = version(Some(dir.path()), Some(&sandbox_home), false, None);
    assert!(output.status.success(), "{}", text(&output));
    let output = version(Some(dir.path()), Some(&sandbox_home), true, Some("0"));
    assert!(output.status.success(), "{}", text(&output));
}

/// `AUXESIS_API_PORT=0` means "no endpoint" for a client — doctor
/// reports that instead of probing the real daemon on 2893.
#[test]
fn doctor_honours_port_zero_as_no_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox_home = dir.path().join(".auxesis");
    let output = run(
        &["doctor"],
        Some(dir.path()),
        Some(&sandbox_home),
        true,
        Some("0"),
    );
    let output_text = text(&output);
    assert!(
        output_text.contains("AUXESIS_API_PORT=0"),
        "doctor must report the no-endpoint convention: {output_text}"
    );
    assert!(
        !output_text.contains("2893"),
        "doctor must not touch the real daemon port: {output_text}"
    );
}
