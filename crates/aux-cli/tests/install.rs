//! End-to-end tests of the `aux install` sandbox refusal.
//!
//! macOS-only: launchd and `~/Library/LaunchAgents` do not exist on Linux, so
//! this whole integration file is compiled away on other platforms (CI runs
//! on Linux; these tests run locally on macOS).
//!
//! A sandboxed `aux install` used to resolve the *real*
//! `~/Library/LaunchAgents` through `$HOME` and bootstrap a real agent. Now
//! install/uninstall/status refuse while the guard is active. Every test uses
//! a fake `$HOME` plus a fake `AUXESIS_LAUNCHCTL` and asserts the refusal
//! happens **before any plist write and before any launchctl call**, so the
//! real agent can never be touched by a test.

#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::tempdir;

const PLIST: &str = "dev.auxesis.auxd.plist";

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

fn make_executable(path: &Path) -> PathBuf {
    fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    path.to_path_buf()
}

struct Sandbox {
    #[allow(dead_code)]
    tmp: tempfile::TempDir,
    /// `$HOME` — owns `Library/LaunchAgents`.
    user_home: PathBuf,
    /// `$AUXESIS_HOME`.
    aux_home: PathBuf,
    auxd: PathBuf,
    launchctl: PathBuf,
    calls: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempdir().unwrap();
        let user_home = tmp.path().join("user");
        let aux_home = tmp.path().join("auxesis");
        let auxd = make_executable(&tmp.path().join("auxd"));
        let launchctl = make_executable(&tmp.path().join("fake-launchctl"));
        let calls = tmp.path().join("launchctl.calls");
        Self {
            tmp,
            user_home,
            aux_home,
            auxd,
            launchctl,
            calls,
        }
    }

    fn plist(&self) -> PathBuf {
        self.user_home
            .join("Library")
            .join("LaunchAgents")
            .join(PLIST)
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(aux_bin());
        cmd.args(args)
            .env("HOME", &self.user_home)
            .env("AUXESIS_HOME", &self.aux_home)
            .env("AUXESIS_AUXD", &self.auxd)
            .env("AUXESIS_LAUNCHCTL", &self.launchctl)
            .env("AUXESIS_SANDBOX", "1")
            .env("AUXESIS_API_PORT", "0");
        cmd.output().expect("run aux")
    }

    fn assert_refused_and_untouched(&self, output: &Output) {
        assert!(
            !output.status.success(),
            "the command must fail: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("refus de sandbox"), "{stderr}");
        assert!(
            !self.plist().exists(),
            "no plist may be written under a fake HOME"
        );
        assert!(
            !self.calls.exists(),
            "launchctl must never be called under the guard"
        );
    }
}

#[test]
fn install_refuses_under_the_guard_without_touching_the_launch_agent() {
    let sandbox = Sandbox::new();
    sandbox.assert_refused_and_untouched(&sandbox.run(&["install"]));
}

#[test]
fn uninstall_refuses_under_the_guard() {
    let sandbox = Sandbox::new();
    sandbox.assert_refused_and_untouched(&sandbox.run(&["uninstall"]));
}

#[test]
fn status_refuses_under_the_guard() {
    let sandbox = Sandbox::new();
    sandbox.assert_refused_and_untouched(&sandbox.run(&["status"]));
}
