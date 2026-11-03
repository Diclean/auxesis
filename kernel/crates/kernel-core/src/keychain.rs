//! The one place that may spawn the macOS `security` binary.
//!
//! **Default deny (KC-01).** The Keychain is touched only when the operator
//! explicitly opts in with `AUXESIS_ALLOW_KEYCHAIN=1`, and even then only
//! outside a sandbox guard (`AUXESIS_SANDBOX=1` or a `HOME` that is not the
//! OS account's home) and outside a crate's own tests. Nothing else enables
//! it: not a real `HOME`, not a release build, not the absence of the sandbox
//! flag. The production service plist does not set the opt-in, so keys come
//! from `~/.auxesis/.env`; tests, builders and breakers never set it, so a
//! `cargo test` run can never reach the owner's real Keychain (a unit test
//! that resolves a key with `key_user` set used to spawn `security` against
//! the real Keychain because `cfg!(test)` is false when kernel-core is compiled
//! as a dependency). Every caller checks [`keychain_allowed`] before
//! spawning, and [`run_security`] refuses to spawn when it is false. This
//! module is the single allowlisted spawner (see
//! `tests/keychain_single_spawn.rs` in this crate).

use std::path::{Path, PathBuf};

/// Whether this process may query the macOS Keychain.
///
/// **Default deny:** true only when `AUXESIS_ALLOW_KEYCHAIN=1` is set
/// explicitly, the sandbox guard is not active (`AUXESIS_SANDBOX` is not `1`
/// and `HOME` is the OS account's home), and this is not a crate's own test.
pub fn keychain_allowed() -> bool {
    if cfg!(test) {
        return false;
    }
    if std::env::var("AUXESIS_ALLOW_KEYCHAIN").as_deref() != Ok("1") {
        // No explicit opt-in: never touch the Keychain (KC-01).
        return false;
    }
    if std::env::var("AUXESIS_SANDBOX")
        .map(|value| value == "1")
        .unwrap_or(false)
    {
        return false;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    match os_home() {
        Some(os_home) => Path::new(&home) == os_home,
        None => false,
    }
}

/// The OS account's home directory from the passwd database (never `$HOME`).
fn os_home() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::ffi::{CStr, OsStr};
        use std::os::unix::ffi::OsStrExt;

        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd`, `buf` and `result` are valid for the call and
        // `getpwuid_r` fills them on success.
        let rc = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: `pw_dir` is a NUL-terminated string owned by the entry.
        let dir = unsafe { CStr::from_ptr(pwd.pw_dir) };
        Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())))
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// The test seam for the single spawn site (security review r11).
///
/// A `PATH` shim cannot observe an absolute `/usr/bin/security` launch, so
/// tests inject a launcher here and assert the spawn site is never reached
/// without the explicit opt-in. Production never installs one, and the
/// launcher is only consulted after [`keychain_allowed`] returns true.
#[doc(hidden)]
pub type SecurityTestLauncher =
    Box<dyn Fn(&[&str]) -> Result<std::process::Output, String> + Send + Sync>;

static SECURITY_TEST_LAUNCHER: std::sync::Mutex<Option<SecurityTestLauncher>> =
    std::sync::Mutex::new(None);

/// Install (or clear, with `None`) the process-wide test launcher. The
/// default-deny check still runs first, so a clean environment never reaches
/// it; tests use this instead of executing `/usr/bin/security`.
#[doc(hidden)]
pub fn set_security_test_launcher(launcher: Option<SecurityTestLauncher>) {
    *SECURITY_TEST_LAUNCHER
        .lock()
        .unwrap_or_else(|err| err.into_inner()) = launcher;
}

/// Run `security` with a hard 5-second timeout, unless the Keychain is not
/// allowed in this context — then nothing is spawned and the error says so.
///
/// The default-deny check gates the single spawn site: with a clean
/// environment (no `AUXESIS_ALLOW_KEYCHAIN=1`) control never reaches
/// `Command::new("security")`, whatever `PATH` says (an absolute
/// `/usr/bin/security` launch is impossible in-process, not merely shadowed
/// by a shim). Production resolves the binary through the daemon's minimal
/// `PATH`.
pub fn run_security(args: &[&str]) -> Result<std::process::Output, String> {
    if !keychain_allowed() {
        return Err("the Keychain is not queried in this context".to_string());
    }
    if let Some(result) = SECURITY_TEST_LAUNCHER
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .as_ref()
        .map(|launcher| launcher(args))
    {
        return result;
    }
    spawn_security(args)
}

/// The single spawn site. Only [`run_security`] reaches it, and only after
/// [`keychain_allowed`] returned true.
fn spawn_security(args: &[&str]) -> Result<std::process::Output, String> {
    use std::time::{Duration, Instant};

    let mut child = std::process::Command::new("security")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| format!("running `security`: {err}"))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("`security` timed out after 5s".to_string());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("waiting for `security`: {err}"));
            }
        }
    }

    child
        .wait_with_output()
        .map_err(|err| format!("collecting `security` output: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn keychain_is_never_allowed_in_tests() {
        // `cfg!(test)` alone must refuse, whatever HOME says.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        assert!(!keychain_allowed());
    }

    #[test]
    fn sandbox_and_foreign_home_are_refused() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let previous_sandbox = std::env::var_os("AUXESIS_SANDBOX");
        let previous_home = std::env::var_os("HOME");
        let previous_opt_in = std::env::var_os("AUXESIS_ALLOW_KEYCHAIN");
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AUXESIS_SANDBOX", "1");
        std::env::set_var("HOME", dir.path());
        assert!(!keychain_allowed());
        std::env::remove_var("AUXESIS_SANDBOX");
        assert!(!keychain_allowed(), "a foreign HOME must be refused");
        // Default deny (KC-01): without the explicit opt-in even a
        // real-home-like environment is refused.
        std::env::remove_var("AUXESIS_ALLOW_KEYCHAIN");
        if let Some(home) = previous_home.as_ref() {
            std::env::set_var("HOME", home);
        }
        assert!(
            !keychain_allowed(),
            "the Keychain is default-deny without AUXESIS_ALLOW_KEYCHAIN=1"
        );
        // The opt-in cannot override `cfg!(test)` in this crate's tests.
        std::env::set_var("AUXESIS_ALLOW_KEYCHAIN", "1");
        assert!(!keychain_allowed());
        std::env::remove_var("AUXESIS_ALLOW_KEYCHAIN");
        if let Some(home) = previous_home {
            std::env::set_var("HOME", home);
        }
        if let Some(sandbox) = previous_sandbox {
            std::env::set_var("AUXESIS_SANDBOX", sandbox);
        }
        if let Some(opt_in) = previous_opt_in {
            std::env::set_var("AUXESIS_ALLOW_KEYCHAIN", opt_in);
        }
        assert!(!keychain_allowed());
    }

    #[test]
    fn run_security_never_spawns_when_refused() {
        // The shim would be at /usr/bin/security on a developer machine; the
        // guard must short-circuit before any spawn. A successful call is
        // impossible in a test (cfg!(test)), so only the error path runs.
        let error = run_security(&["find-generic-password", "-s", "auxesis", "-a", "nobody"])
            .expect_err("a test must never spawn security");
        assert!(error.contains("not queried"), "{error}");
    }
}
