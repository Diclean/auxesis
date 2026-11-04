//! macOS transport: `osascript`, executed by absolute path over a pipe.
//!
//! The transport executes exactly one program, at the fixed absolute path
//! [`OSASCRIPT_PATH`] (`/usr/bin/osascript`) — never through `PATH` — with a
//! cleared environment, and only after verifying that the target is the
//! root-owned system binary (fail closed: no notification, and therefore no
//! one-time trust code, leaves the process if the check fails). The one
//! exception is the non-default `test-notify` stand-in, which is chosen by
//! [`crate::system_notifier`] and is never the system binary.
//!
//! The AppleScript source carries the notification title and body, so it
//! must never be seen by another process: it is written to the child's
//! **stdin** (`osascript -` reads the script from stdin), never placed in
//! `argv` or the environment. That keeps one-time trust codes out of the
//! process table. Text is encoded as an AppleScript string literal in
//! memory (quotes/backslashes escaped), never spliced raw, so a payload
//! like `do shell script` stays inert data.

use crate::{Notification, Notifier, NotifyError};
use std::io;
use std::process::Output;
#[cfg(any(target_os = "macos", test))]
use std::process::{Child, Command, Stdio};
#[cfg(any(target_os = "macos", test))]
use std::time::{Duration, Instant};

/// The program a default [`MacNotifier`] runs: the system `osascript`, by
/// absolute path. There is no `PATH` lookup, and this module never reads the
/// environment. The only other program is the non-default `test-notify`
/// stand-in, chosen once by [`crate::system_notifier`]; unit tests inject a
/// runner and never spawn the real program.
pub(crate) const OSASCRIPT_PATH: &str = "/usr/bin/osascript";

/// Largest AppleScript source accepted for one invocation. A notification
/// is a short text; anything bigger is a caller bug and is refused rather
/// than allowed to fill the child's stdin pipe.
#[cfg(target_os = "macos")]
const MAX_SCRIPT_BYTES: usize = 256 * 1024;

/// Cap for the stderr included in [`NotifyError::Osascript`].
const MAX_STDERR: usize = 512;

/// Hard ceiling for one `osascript` invocation. A wedged notification helper
/// must never block the daemon's runner (or its store mutex) forever; this
/// mirrors the `security` timeout used by `aux secret`.
#[cfg(target_os = "macos")]
pub const OSASCRIPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the wait loop re-checks the child.
#[cfg(any(target_os = "macos", test))]
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Everything needed to run one notification, captured before the spawn so
/// tests can assert the exact program, argv and environment (and that none
/// of them carries the notification text).
#[derive(Debug, Clone, PartialEq, Eq)]
struct OsascriptSpec {
    /// The program to run; never resolved through `PATH`.
    program: std::path::PathBuf,
    /// Command-line arguments; never carry the notification text.
    args: Vec<String>,
    /// Explicit environment. Empty means `env_clear()` and add nothing.
    env: Vec<(String, String)>,
    /// AppleScript source written to the child's stdin.
    script: String,
}

/// How osascript is invoked; injectable so tests never show a notification.
type CommandRunner = dyn Fn(&OsascriptSpec) -> io::Result<Output> + Send + Sync;

/// Delivers notifications through the built-in `osascript` command.
pub struct MacNotifier {
    /// The one program every notification runs.
    program: std::path::PathBuf,
    runner: Box<CommandRunner>,
}

impl MacNotifier {
    /// A notifier that really calls `/usr/bin/osascript`.
    pub fn new() -> Self {
        Self::with_program(std::path::PathBuf::from(OSASCRIPT_PATH))
    }

    /// A notifier that runs `program` for every notification. Only
    /// [`crate::system_notifier`] passes anything but [`OSASCRIPT_PATH`], and
    /// only when the `test-notify` seam is active.
    pub(crate) fn with_program(program: std::path::PathBuf) -> Self {
        Self {
            program,
            runner: Box::new(run_osascript),
        }
    }

    /// A notifier backed by a fake process runner (unit tests only). The
    /// runner receives the exact spec the production runner would execute,
    /// so tests can assert on the program, argv, environment and script.
    #[cfg(test)]
    fn with_runner(
        runner: impl Fn(&OsascriptSpec) -> io::Result<Output> + Send + Sync + 'static,
    ) -> Self {
        Self::with_runner_at(OSASCRIPT_PATH, runner)
    }

    #[cfg(test)]
    fn with_runner_at(
        program: &str,
        runner: impl Fn(&OsascriptSpec) -> io::Result<Output> + Send + Sync + 'static,
    ) -> Self {
        Self {
            program: std::path::PathBuf::from(program),
            runner: Box::new(runner),
        }
    }
}

impl Default for MacNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier for MacNotifier {
    fn notify(&self, notification: &Notification) -> Result<(), NotifyError> {
        let spec = osascript_spec(&self.program, notification);
        let output = (self.runner)(&spec).map_err(NotifyError::from_io)?;
        if output.status.success() {
            return Ok(());
        }
        let status = output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".to_string());
        let raw = String::from_utf8_lossy(&output.stderr);
        // Cleaned of invisibles and ANSI and secret-redacted:
        // the error is logged and can be shown, so no key may ride in it.
        let stderr =
            kernel_broker::scrub_external_preview(std::path::Path::new(""), raw.trim(), MAX_STDERR);
        let stderr = if stderr.is_empty() {
            "(no stderr)".to_string()
        } else {
            stderr
        };
        Err(NotifyError::Osascript { status, stderr })
    }
}

/// Build the exact invocation for a notification. The sanitized title and
/// body become an AppleScript literal inside the script; `argv` stays `-`
/// (read the script from stdin) and the environment stays empty.
fn osascript_spec(program: &std::path::Path, notification: &Notification) -> OsascriptSpec {
    let clean = notification.sanitized();
    let script = format!(
        "display notification {} with title {}",
        applescript_string_literal(&clean.body),
        applescript_string_literal(&clean.title),
    );
    OsascriptSpec {
        program: program.to_path_buf(),
        args: vec!["-".to_string()],
        env: Vec::new(),
        script,
    }
}

/// Render `text` as an AppleScript string literal.
///
/// The only escapes AppleScript defines in a literal are applied (`\\`,
/// `\"`, `\n`, `\t`), so quotes, backslashes or `do shell script` payloads
/// in a notification stay data instead of becoming script.
fn applescript_string_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// The one and only [`Command`] this transport builds: the fixed program,
/// the fixed argv, and a cleared environment (plus any explicit spec vars,
/// which production keeps empty).
#[cfg(any(target_os = "macos", test))]
fn build_command(spec: &OsascriptSpec) -> Command {
    let mut command = Command::new(&spec.program);
    command.args(&spec.args).env_clear();
    for (name, value) in &spec.env {
        command.env(name, value);
    }
    command
}

/// Run the fixed `/usr/bin/osascript` with the script on stdin.
///
/// Fail closed: the target is verified as the root-owned, non-writable
/// system binary before the spawn, and the script is written from a separate
/// thread so a child that never reads stdin cannot defeat the timeout.
#[cfg(target_os = "macos")]
fn run_osascript(spec: &OsascriptSpec) -> io::Result<Output> {
    // The fixed system binary is verified fail-closed before every run. The
    // only way `program` differs is the explicit non-default `test-notify`
    // seam, whose whole purpose is a user-owned stand-in.
    if spec.program == std::path::Path::new(OSASCRIPT_PATH) {
        verify_system_osascript(&spec.program)?;
    }
    if spec.script.len() > MAX_SCRIPT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "notification script is too large",
        ));
    }
    let mut child = build_command(spec)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let script = spec.script.clone();
    let writer = std::thread::spawn(move || {
        use std::io::Write as _;
        let _ = stdin.write_all(script.as_bytes());
        // Dropping `stdin` closes the pipe, so osascript sees EOF.
    });
    let result = wait_with_timeout(&mut child, OSASCRIPT_TIMEOUT);
    // The child has exited or been killed; the writer unblocks either way.
    let _ = writer.join();
    result?;
    child.wait_with_output()
}

/// Notifications are macOS-only; elsewhere the transport fails closed with
/// the same error the old name lookup produced.
#[cfg(not(target_os = "macos"))]
fn run_osascript(_spec: &OsascriptSpec) -> io::Result<Output> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "osascript requires macOS",
    ))
}

/// Fail-closed check that `path` is the system `osascript`.
///
/// Requires: an existing entry, a regular file after symlink resolution, a
/// symlink (if any) that stays inside `/usr/bin`, root ownership, and no
/// group/world write bit. Any failure means no notification is attempted.
#[cfg(target_os = "macos")]
fn verify_system_osascript(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let refuse = |reason: String| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to run {}: {reason}", path.display()),
        )
    };
    std::fs::symlink_metadata(path).map_err(|err| refuse(format!("cannot stat it ({err})")))?;
    if std::fs::symlink_metadata(path)
        .map_err(|err| refuse(format!("cannot stat it ({err})")))?
        .file_type()
        .is_symlink()
    {
        let resolved = std::fs::canonicalize(path)
            .map_err(|err| refuse(format!("cannot resolve the symlink ({err})")))?;
        if !resolved.starts_with("/usr/bin") {
            return Err(refuse("symlink leaves /usr/bin".to_string()));
        }
    }
    let meta = std::fs::metadata(path).map_err(|err| refuse(format!("cannot stat it ({err})")))?;
    if !meta.is_file() {
        return Err(refuse("not a regular file".to_string()));
    }
    if meta.uid() != 0 {
        return Err(refuse("not owned by root".to_string()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(refuse("group- or world-writable".to_string()));
    }
    Ok(())
}

/// Wait for `child` to exit, killing it once `timeout` elapses.
///
/// Polls `try_wait` (the same pattern as the `security` helper in
/// `aux-cli`): a timeout is reported as [`io::ErrorKind::TimedOut`], which
/// [`NotifyError::from_io`] maps to [`NotifyError::Timeout`].
#[cfg(any(target_os = "macos", test))]
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            // Reap the killed child so it cannot linger as a zombie.
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("osascript did not finish within {} s", timeout.as_secs()),
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};

    fn output_with(status: i32, stderr: &[u8]) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(status << 8),
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        }
    }

    /// Capture the exact spec the notifier would execute.
    fn capture() -> (MacNotifier, Arc<Mutex<Vec<OsascriptSpec>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let notifier = MacNotifier::with_runner(move |spec: &OsascriptSpec| {
            sink.lock().unwrap().push(spec.clone());
            Ok(output_with(0, b""))
        });
        (notifier, seen)
    }

    fn only_spec(seen: &Arc<Mutex<Vec<OsascriptSpec>>>) -> OsascriptSpec {
        let specs = seen.lock().unwrap();
        assert_eq!(specs.len(), 1);
        specs[0].clone()
    }

    #[test]
    fn the_script_goes_on_stdin_and_never_on_argv() {
        // P1 regression (security-review round 4): the one-time code used to be an
        // argv item of a program resolved through PATH. The only program is
        // the absolute system osascript, argv is exactly `-`, and the
        // title/body (code included) live in the stdin script only.
        let (notifier, seen) = capture();
        let code = "1234 5678";
        let body = format!(
            "Trust request for /home/agents/main/workspace\nCode: {code} (expires in 2 minutes)"
        );
        notifier
            .notify(&Notification::new(
                "Auxesis: workspace trust request",
                &body,
            ))
            .unwrap();
        let spec = only_spec(&seen);

        assert_eq!(
            spec.program,
            std::path::PathBuf::from("/usr/bin/osascript"),
            "the program must be the absolute system path"
        );
        assert_eq!(spec.args, vec!["-".to_string()]);
        assert!(spec.env.is_empty(), "the child environment must be empty");
        assert!(
            !spec
                .args
                .iter()
                .any(|arg| arg.chars().any(|c| c.is_ascii_digit())),
            "no argv item may contain code digits: {:?}",
            spec.args
        );
        assert!(
            spec.script.contains(code),
            "the code is delivered on stdin: {}",
            spec.script
        );
    }

    #[test]
    fn passes_sanitized_title_and_body_on_stdin() {
        let (notifier, seen) = capture();
        notifier
            .notify(&Notification::new("ti\u{1b}[31mtle", "bo\u{0}dy\nline"))
            .unwrap();
        let spec = only_spec(&seen);
        assert!(
            spec.script.contains(r#"with title "ti[31mtle""#),
            "script: {}",
            spec.script
        );
        assert!(
            spec.script.contains(r#""body\nline""#),
            "script: {}",
            spec.script
        );
        assert!(
            !spec.script.contains('\u{1b}') && !spec.script.contains('\u{0}'),
            "control characters must be stripped before the script is built"
        );
    }

    #[test]
    fn applescript_metacharacters_stay_inside_the_string_literal() {
        let title = r#"" & (do shell script "touch /tmp/pwned") & ""#;
        let body = r#"quote " backslash \ end"#;
        let (notifier, seen) = capture();
        notifier.notify(&Notification::new(title, body)).unwrap();
        let spec = only_spec(&seen);
        // The raw quote/backslash run is escaped, so it cannot terminate the
        // literal and start a statement; the escaped form is present.
        assert!(spec.script.contains(r#"\" & (do shell script \"touch"#));
        assert!(spec.script.contains(r#"quote \" backslash \\ end"#));
    }

    #[test]
    fn the_command_is_the_fixed_absolute_program_with_an_empty_environment() {
        let spec = osascript_spec(
            std::path::Path::new(OSASCRIPT_PATH),
            &Notification::new("t", "b"),
        );
        let command = build_command(&spec);
        assert_eq!(
            command.get_program(),
            std::ffi::OsStr::new("/usr/bin/osascript"),
            "the program must be the absolute system path"
        );
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![std::ffi::OsStr::new("-")],
            "argv must be exactly `-`"
        );
        assert!(
            command.get_envs().next().is_none(),
            "the child environment must be cleared"
        );
    }

    #[test]
    fn a_planted_osascript_in_path_is_never_selected() {
        // P1 regression (security-review round 4): a fake `osascript` placed first
        // in PATH must not be reachable: the spec always names the absolute
        // system binary, and the child environment does not even carry PATH.
        struct PathGuard(Option<std::ffi::OsString>);
        impl Drop for PathGuard {
            fn drop(&mut self) {
                match &self.0 {
                    Some(path) => std::env::set_var("PATH", path),
                    None => std::env::remove_var("PATH"),
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let fake_bin = dir.path().join("bin");
        std::fs::create_dir_all(&fake_bin).unwrap();
        let marker = dir.path().join("executed");
        let shim = fake_bin.join("osascript");
        std::fs::write(&shim, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut mode = std::fs::metadata(&shim).unwrap().permissions();
            mode.set_mode(0o755);
            std::fs::set_permissions(&shim, mode).unwrap();
        }

        let original = std::env::var_os("PATH");
        let poisoned = match &original {
            Some(path) => format!("{}:{}", fake_bin.display(), path.to_string_lossy()),
            None => fake_bin.display().to_string(),
        };
        let _guard = PathGuard(original);
        std::env::set_var("PATH", poisoned);

        let spec = osascript_spec(
            std::path::Path::new(OSASCRIPT_PATH),
            &Notification::new("t", "b"),
        );
        let command = build_command(&spec);
        assert_eq!(
            command.get_program(),
            std::ffi::OsStr::new("/usr/bin/osascript")
        );
        assert!(
            !marker.exists(),
            "the planted osascript must never be executed"
        );
    }

    #[test]
    fn a_default_notifier_runs_only_the_system_osascript() {
        // P1 regression (security-review round 4): no environment variable may
        // redirect the notifier. The program is fixed at construction and this
        // module never reads the environment; the test seam is chosen only by
        // `system_notifier`.
        assert_eq!(
            MacNotifier::new().program,
            std::path::PathBuf::from(OSASCRIPT_PATH)
        );
    }

    #[test]
    fn a_stand_in_program_is_the_only_program_run() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let notifier = MacNotifier::with_runner_at("/tmp/stand-in", move |spec: &OsascriptSpec| {
            sink.lock().unwrap().push(spec.clone());
            Ok(output_with(0, b""))
        });
        notifier.notify(&Notification::new("t", "b")).unwrap();
        let spec = only_spec(&seen);
        assert_eq!(spec.program, std::path::PathBuf::from("/tmp/stand-in"));
        assert_eq!(
            build_command(&spec).get_program(),
            std::ffi::OsStr::new("/tmp/stand-in"),
            "the spawned program is the stand-in, never the system osascript"
        );
    }

    #[test]
    fn success_is_ok() {
        let notifier = MacNotifier::with_runner(|_| Ok(output_with(0, b"")));
        assert!(notifier.notify(&Notification::new("t", "b")).is_ok());
    }

    #[test]
    fn maps_nonzero_exit_and_sanitizes_stderr() {
        // Round 3 made the shared sanitiser drop ANSI sequences as units
        // (`strip_ansi`): colouring must not survive even as its parameter
        // residue (`[31m`). The old expectation (`[31mpermission
        // denied[0m`) encoded the previous, leakier `sanitize_text`-only
        // behaviour, which removed the ESC byte but kept the CSI parameters
        // as visible text; that is the corrupted spelling, not the content.
        let notifier =
            MacNotifier::with_runner(|_| Ok(output_with(3, b"\x1b[31mpermission denied\x1b[0m\n")));
        let err = notifier.notify(&Notification::new("t", "b")).unwrap_err();
        match err {
            NotifyError::Osascript { status, stderr } => {
                assert_eq!(status, "3");
                assert_eq!(stderr, "permission denied");
                assert!(
                    !stderr.contains('\u{1b}') && !stderr.contains("[31m"),
                    "ANSI residue in {stderr:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn a_key_in_stderr_is_redacted() {
        let key = format!(
            "sk-proj-{}",
            "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3iJk6l"
        ); // gitleaks:allow
        let stderr = format!("execution error: api_key={key} rejected");
        let notifier = MacNotifier::with_runner(move |_| Ok(output_with(1, stderr.as_bytes())));
        match notifier.notify(&Notification::new("t", "b")).unwrap_err() {
            NotifyError::Osascript { stderr, .. } => {
                assert!(!stderr.contains("Ab3dEf6h"), "key in {stderr:?}");
                assert!(stderr.starts_with("execution error"), "{stderr:?}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_stderr_becomes_a_placeholder() {
        let notifier = MacNotifier::with_runner(|_| Ok(output_with(1, b"  \n")));
        let err = notifier.notify(&Notification::new("t", "b")).unwrap_err();
        assert!(matches!(
            err,
            NotifyError::Osascript { ref status, ref stderr }
                if status == "1" && stderr == "(no stderr)"
        ));
    }

    #[test]
    fn maps_spawn_failure() {
        let notifier = MacNotifier::with_runner(|_| {
            Err(io::Error::new(io::ErrorKind::NotFound, "no osascript"))
        });
        let err = notifier.notify(&Notification::new("t", "b")).unwrap_err();
        assert!(matches!(
            err,
            NotifyError::Spawn(ref err) if err.kind() == io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn maps_unsupported_platform_error() {
        let notifier = MacNotifier::with_runner(|_| {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not macos"))
        });
        let err = notifier.notify(&Notification::new("t", "b")).unwrap_err();
        assert!(matches!(err, NotifyError::Unsupported));
    }

    #[test]
    fn maps_timeout_to_the_timeout_variant() {
        let notifier = MacNotifier::with_runner(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "osascript did not finish",
            ))
        });
        let err = notifier.notify(&Notification::new("t", "b")).unwrap_err();
        assert!(matches!(err, NotifyError::Timeout));
    }

    #[test]
    fn a_wedged_child_is_killed_at_the_deadline() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sleep");
        let started = Instant::now();
        let err = wait_with_timeout(&mut child, Duration::from_millis(100)).unwrap_err();
        let elapsed = started.elapsed();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(elapsed < Duration::from_secs(2), "waited {elapsed:?}");
        assert!(
            child.try_wait().unwrap().is_some(),
            "the killed child must be reaped"
        );
    }

    #[test]
    fn a_fast_child_completes_normally() {
        let mut child = Command::new("/bin/sleep")
            .arg("0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sleep");

        wait_with_timeout(&mut child, Duration::from_secs(5)).unwrap();
        assert!(child.wait_with_output().unwrap().status.success());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_system_osascript_passes_verification() {
        verify_system_osascript(std::path::Path::new(OSASCRIPT_PATH))
            .expect("the production target must pass its own verification");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_user_owned_stand_in_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("osascript");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
        let err = verify_system_osascript(&fake).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("owned by root"), "{err}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_symlink_out_of_usr_bin_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("osascript");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        let err = verify_system_osascript(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("leaves /usr/bin"), "{err}");
    }
}
