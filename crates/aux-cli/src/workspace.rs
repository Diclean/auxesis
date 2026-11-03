//! `aux workspace` — owner actions on workspace taint (WS-C).
//!
//! Dispatching an untrusted-class tool in a workspace marks it
//! `untrusted-touched`: every conversation that starts there is tainted
//! until the owner clears the mark. Nothing a tool or the model does clears
//! it, and there is no time decay.
//!
//! Since WS-C fix round 4 the clear is a **two-step owner-presence proof**
//! (`aux_engine::trust`): `aux workspace trust <path>` creates a pending
//! request and sends a one-time code through the owner's local notification
//! channel — never through stdout, stderr, the store, an audit row or the
//! API. A tool that can run this same CLI (the `shell` tool's whole
//! capability) never sees the code, and the code is rate-limited, expires
//! after 120 s, allows 3 attempts and is single-use. The owner token stays
//! required for the API path, and WS-D's sandbox is the second layer (see
//! `aux_engine::trust` for the full threat model — in particular that WS-C
//! alone provides no owner-presence guarantee).
//!
//! Round 5 moves the code off every command line and out of `PATH`:
//! re-running `aux workspace trust <path>` prompts for the code on the
//! terminal without echo, and `aux workspace trust <path> --code -` reads it
//! from stdin for pipes. `--code <code>` still works but warns: it leaks the
//! code into the shell history and the process list. The request step is
//! unchanged.
//!
//! It only accepts an existing agent workspace under the current Auxesis home
//! and audits the request/completion/failure as `workspace.trust_requested`,
//! `workspace.trusted` and `workspace.trust_failed` — never the code.
//!
//! WS-C round 7 refuses the whole action while the loaded `[shell]` config can
//! run the shell unsandboxed (`sandbox = false` + `allow_unsandboxed = true`,
//! or an unavailable sandbox with the opt-in): the mark would not constrain a
//! command-capable model, so the attempt is audited as
//! `workspace.trust_refused` and no code is issued or consumed.

use aux_notify::{system_notifier, Notifier};
use clap::Args;
use kernel_core::{auxesis_home, config_path, store_path};
use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// Cap for one error line the CLI echoes (characters), the same hygiene
/// budget the API applies to its `detail` fields.
const CLI_ERROR_MAX_CHARS: usize = 512;

/// `aux workspace` subcommands.
#[derive(Debug, Args)]
pub struct WorkspaceArgs {
    #[command(subcommand)]
    action: WorkspaceAction,
}

#[derive(Debug, clap::Subcommand)]
enum WorkspaceAction {
    /// Clear the untrusted-touched mark of an agent workspace.
    ///
    /// The first run sends a one-time code to your notifications. Re-run the
    /// same command to type the code at a hidden prompt, or pipe it with
    /// `--code -`. `--code <code>` is deprecated (it leaks the code into
    /// your shell history and this process's command line).
    Trust {
        /// Path of the agent workspace (e.g. ~/.auxesis/agents/main/workspace).
        path: PathBuf,
        /// `-` reads the code from stdin; a literal is the deprecated
        /// legacy form. Omit to request a code, or — with a pending request
        /// — to type it at a hidden prompt.
        #[arg(long, value_name = "CODE")]
        code: Option<String>,
    },
}

/// Run one `aux workspace` subcommand.
pub fn run(args: WorkspaceArgs) -> ExitCode {
    let home = auxesis_home();
    match args.action {
        WorkspaceAction::Trust { path, code } => {
            // Production delivery: a macOS notification. Tests call
            // `trust_entry_with` with a recording notifier and never show
            // anything.
            let notifier = system_notifier(kernel_core::sandbox_guard_active());
            match trust_entry(&home, &path, code.as_deref(), &notifier) {
                Ok(message) => {
                    let _ = writeln!(std::io::stdout(), "{message}");
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    // P2-4 (security-review round 4): the transport error may be
                    // attacker-influenced, so it gets the same scrub the API
                    // applies — control/invisible characters stripped, home
                    // replaced, key shapes redacted, collapsed to one line,
                    // capped — before it reaches the terminal.
                    let safe = error_line(&home, &message);
                    let _ = writeln!(std::io::stderr(), "aux workspace trust: {safe}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// The error line the CLI prints: one sanitized, capped line (never raw
/// transport output).
fn error_line(home: &Path, message: &str) -> String {
    kernel_broker::sanitize_error_detail(home, message, CLI_ERROR_MAX_CHARS)
}

/// Resolve the `--code` argument into a trust step.
///
/// `None` (no flag) requests a code when nothing usable is pending, and
/// otherwise prompts on the terminal without echo; `-` reads it from stdin;
/// any other literal is the deprecated legacy form (warned about, because it
/// leaks the code into shell history and the process list).
fn trust_entry(
    home: &Path,
    path: &Path,
    code: Option<&str>,
    notifier: &dyn Notifier,
) -> Result<String, String> {
    trust_entry_with(
        home,
        path,
        code,
        notifier,
        &read_code_from_stdin,
        &read_code_prompt,
    )
}

fn trust_entry_with(
    home: &Path,
    path: &Path,
    code: Option<&str>,
    notifier: &dyn Notifier,
    read_stdin: &dyn Fn() -> Result<String, String>,
    read_prompt: &dyn Fn() -> Result<String, String>,
) -> Result<String, String> {
    match code {
        // `--code -`: the code comes from stdin (a pipe, a password manager).
        Some("-") => {
            let code = read_stdin()?;
            trust(home, path, Some(&code), notifier)
        }
        // Legacy literal: works, but warns without ever echoing the code.
        Some(literal) => {
            legacy_code_warning();
            trust(home, path, Some(literal), notifier)
        }
        // No flag: prompt only when a request is pending, still fresh and
        // not spent by the attempt cap. Otherwise this is the request step.
        None => {
            let (workspace, store) = open_workspace(home, path)?;
            refuse_when_unsandboxed(home, &store, &workspace)?;
            let pending = store
                .trust_request(&workspace)
                .map_err(|err| format!("could not read the pending trust request: {err}"))?;
            if is_usable_pending(pending.as_ref()) {
                let code = read_prompt()?;
                complete_step(&store, &workspace, &code)
            } else {
                request_step(&store, &workspace, &path.to_string_lossy(), notifier)
            }
        }
    }
}

/// A pending request worth prompting for: inside its TTL and not spent by
/// the attempt cap. An expired or spent row goes back through the request
/// step, which respects the cooldown.
fn is_usable_pending(pending: Option<&aux_store::TrustRequest>) -> bool {
    let Some(pending) = pending else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    now - pending.created_at <= aux_engine::TRUST_CODE_TTL_SECS
        && pending.attempts < aux_engine::TRUST_MAX_ATTEMPTS
}

/// One explicit step of the owner trust action; returns the human success
/// message. `None` requests a code, `Some` completes with it. Tests drive
/// this directly; the CLI goes through [`trust_entry`].
///
/// The returned messages and errors never contain the code —
/// `aux_engine::trust` guarantees that, and this presentation layer adds no
/// code of its own.
fn trust(
    home: &Path,
    path: &Path,
    code: Option<&str>,
    notifier: &dyn Notifier,
) -> Result<String, String> {
    let (workspace, store) = open_workspace(home, path)?;
    refuse_when_unsandboxed(home, &store, &workspace)?;
    match code {
        None => request_step(&store, &workspace, &path.to_string_lossy(), notifier),
        Some(code) => complete_step(&store, &workspace, code),
    }
}

/// Refuse the trust action while the loaded `[shell]` config can run the
/// shell unsandboxed (WS-C round 7).
///
/// With the escape hatch on, clearing the mark would not constrain the shell,
/// so the owner action is refused and audited as `workspace.trust_refused`
/// (`aux_engine::refuse_when_unsandboxed_shell`). No code is issued or
/// consumed. A config that cannot be loaded fails closed too.
fn refuse_when_unsandboxed(
    home: &Path,
    store: &aux_store::Store,
    workspace: &str,
) -> Result<(), String> {
    let config = kernel_core::Config::load_or_create(&config_path(home))
        .map_err(|err| format!("could not read the config: {err}"))?;
    aux_engine::refuse_when_unsandboxed_shell(store, workspace, "owner-cli", &config.shell)
        .map_err(|err| err.to_string())
}

fn open_workspace(home: &Path, path: &Path) -> Result<(String, aux_store::Store), String> {
    let raw = path.to_string_lossy();
    let workspace =
        aux_engine::resolve_agent_workspace(home, &raw).map_err(|err| err.to_string())?;
    let store = aux_store::Store::open(&store_path(home))
        .map_err(|err| format!("could not open the store: {err}"))?;
    Ok((workspace, store))
}

fn request_step(
    store: &aux_store::Store,
    workspace: &str,
    raw: &str,
    notifier: &dyn Notifier,
) -> Result<String, String> {
    let requested = aux_engine::request_trust(store, workspace, "owner-cli", notifier)
        .map_err(|err| err.to_string())?;
    Ok(format!(
        "trust request sent for {workspace}\n\
         enter the one-time code from your notifications within 2 minutes — type it at a hidden prompt:\n  \
         aux workspace trust {raw}\n\
         or pipe it on stdin:\n  \
         aux workspace trust {raw} --code -\n\
         (request {})",
        requested.request_id
    ))
}

fn complete_step(store: &aux_store::Store, workspace: &str, code: &str) -> Result<String, String> {
    let completed = aux_engine::complete_trust(store, workspace, code, "owner-cli")
        .map_err(|err| err.to_string())?;
    Ok(format!(
        "workspace trusted: {workspace}{}",
        if completed.changed {
            ""
        } else {
            " (was not tainted)"
        }
    ))
}

/// Warn (never echoing the code) that the literal `--code` form leaks.
fn legacy_code_warning() {
    let _ = writeln!(
        std::io::stderr(),
        "warning: --code <code> is deprecated — the code lands in your shell history \
         and in this process's command line; re-run without --code to type it at a \
         hidden prompt, or use --code - to pipe it on stdin"
    );
}

/// Read one code line from stdin (the `--code -` form).
fn read_code_from_stdin() -> Result<String, String> {
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|err| format!("could not read the code from stdin: {err}"))?;
    let code = line.trim();
    if read == 0 || code.is_empty() {
        return Err("no code was entered".to_string());
    }
    Ok(code.to_string())
}

/// Prompt for the code on a terminal without echo.
///
/// With piped stdin there is no terminal to hide input on and no reliable
/// way to tell an intentional pipe from an empty one, so this refuses and
/// points at the explicit `--code -` form instead of consuming input.
fn read_code_prompt() -> Result<String, String> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(
            "no code was given and stdin is not a terminal; use `--code -` to read it from stdin"
                .to_string(),
        );
    }
    let _guard = EchoOff::new(stdin.as_raw_fd())
        .map_err(|err| format!("could not disable terminal echo: {err}"))?;
    eprint!("one-time code (hidden): ");
    let _ = std::io::stderr().flush();
    let code = read_code_from_stdin()?;
    eprintln!();
    Ok(code)
}

/// Disables terminal echo on `fd` until dropped (best-effort restore).
struct EchoOff {
    fd: i32,
    saved: libc::termios,
}

impl EchoOff {
    fn new(fd: i32) -> std::io::Result<Self> {
        // SAFETY: `tcgetattr`/`tcsetattr` only read and write the termios
        // attributes of an open fd; no memory is shared beyond this struct.
        unsafe {
            let mut current: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut current) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let saved = current;
            current.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(fd, libc::TCSANOW, &current) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self { fd, saved })
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: as in `new`; restores the attributes captured before the
        // echo bit was cleared.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_notify::FakeNotifier;
    use tempfile::TempDir;

    struct Sandbox {
        _dir: TempDir,
        home: PathBuf,
        ws: PathBuf,
        key: String,
        store: aux_store::Store,
    }

    fn sandbox() -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let ws = home.join("agents/main/workspace");
        std::fs::create_dir_all(&ws).unwrap();
        let store = aux_store::Store::open(&store_path(&home)).unwrap();
        let key = ws.canonicalize().unwrap().to_string_lossy().into_owned();
        store.mark_workspace_tainted(&key, "shell").unwrap();
        Sandbox {
            _dir: dir,
            home,
            ws,
            key,
            store,
        }
    }

    /// The code as delivered to the owner's notifications.
    fn notified_code(fake: &FakeNotifier) -> String {
        let body = fake.last().unwrap().body;
        let line = body
            .lines()
            .find(|line| line.starts_with("Code: "))
            .unwrap();
        let after = &line["Code: ".len()..];
        let end = after.find(" (expires").unwrap_or(after.len());
        let digits: String = after[..end]
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        assert_eq!(digits.len(), 8, "notification body: {body}");
        digits
    }

    fn store_bytes(home: &Path) -> Vec<u8> {
        std::fs::read(store_path(home)).unwrap()
    }

    fn event_payloads(home: &Path, kind: &str) -> Vec<String> {
        let conn = aux_store::open_keyed(&store_path(home)).unwrap();
        let mut stmt = conn
            .prepare("SELECT payload FROM events WHERE kind = ?1 ORDER BY id")
            .unwrap();
        let payloads = stmt
            .query_map([kind], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        payloads
    }

    fn backdate(home: &Path, workspace: &str, seconds: i64) {
        let conn = aux_store::open_keyed(&store_path(home)).unwrap();
        conn.execute(
            "UPDATE trust_requests SET created_at = created_at - ?1 WHERE workspace = ?2",
            rusqlite::params![seconds, workspace],
        )
        .unwrap();
    }

    #[test]
    fn a_tool_running_this_same_cli_cannot_complete_without_the_notified_code() {
        // P1 regression (security-review round 3): the shell tool runs ordinary
        // owner commands, so `aux workspace trust` must not clear anything by
        // itself. Without the code from the notification it only creates a
        // pending request; every tool-producible candidate fails and the mark
        // survives; only the notified code completes.
        let s = sandbox();
        let fake = FakeNotifier::new();

        let message = trust(&s.home, &s.ws, None, &fake).unwrap();
        assert!(
            s.store.workspace_taint(&s.key).unwrap().is_some(),
            "a bare trust invocation must not clear the mark"
        );
        assert!(
            s.store.trust_request(&s.key).unwrap().is_some(),
            "it must leave a pending request instead"
        );
        let code = notified_code(&fake);
        assert!(!message.contains(&code), "stdout must not carry the code");

        for guess in ["00000000", "11111111", code.as_str()] {
            if guess == code {
                continue; // the real code is tested below
            }
            let err = trust(&s.home, &s.ws, Some(guess), &fake).unwrap_err();
            assert!(!err.contains(&code), "errors must not carry the code");
            assert!(
                s.store.workspace_taint(&s.key).unwrap().is_some(),
                "a wrong code must not clear the mark"
            );
        }

        let done = trust(&s.home, &s.ws, Some(&code), &fake).unwrap();
        assert!(!done.contains(&code), "stdout must not carry the code");
        assert!(s.store.workspace_taint(&s.key).unwrap().is_none());
        assert_eq!(s.store.event_count("workspace.trusted").unwrap(), 1);
        assert_eq!(
            s.store.event_count("workspace.trust_failed").unwrap(),
            2,
            "each wrong guess must be audited"
        );
    }

    #[test]
    fn the_code_never_appears_in_cli_output_audits_or_the_store_file() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        let message = trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);
        let spaced = format!("{} {}", &code[..4], &code[4..]);

        // Everything a tool can read: the CLI's own output, the audit rows
        // and the raw store file (which holds the hash, never the code).
        assert!(!message.contains(&code) && !message.contains(&spaced));
        for kind in ["workspace.trust_requested", "workspace.trust_failed"] {
            for payload in event_payloads(&s.home, kind) {
                assert!(
                    !payload.contains(&code) && !payload.contains(&spaced),
                    "the code appeared in {kind}: {payload}"
                );
            }
        }
        let bytes = store_bytes(&s.home);
        assert!(
            !contains_bytes(&bytes, code.as_bytes()) && !contains_bytes(&bytes, spaced.as_bytes()),
            "the raw store file must not contain the code"
        );

        let done = trust(&s.home, &s.ws, Some(&code), &fake).unwrap();
        assert!(!done.contains(&code) && !done.contains(&spaced));
        for payload in event_payloads(&s.home, "workspace.trusted") {
            assert!(!payload.contains(&code) && !payload.contains(&spaced));
        }
        assert!(!contains_bytes(&store_bytes(&s.home), code.as_bytes()));
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn an_expired_code_is_refused_and_the_mark_survives() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);
        backdate(&s.home, &s.key, aux_engine::TRUST_CODE_TTL_SECS + 1);

        let err = trust(&s.home, &s.ws, Some(&code), &fake).unwrap_err();
        assert!(err.contains("expired"), "{err}");
        assert!(s.store.workspace_taint(&s.key).unwrap().is_some());
        assert!(s.store.trust_request(&s.key).unwrap().is_none());
        assert_eq!(s.store.event_count("workspace.trust_failed").unwrap(), 1);
    }

    #[test]
    fn the_attempt_cap_cancels_the_request_so_the_real_code_stops_working() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);
        let wrong = if code == "00000000" {
            "11111111"
        } else {
            "00000000"
        };

        assert!(trust(&s.home, &s.ws, Some(wrong), &fake).is_err());
        assert!(trust(&s.home, &s.ws, Some(wrong), &fake).is_err());
        let err = trust(&s.home, &s.ws, Some(wrong), &fake).unwrap_err();
        assert!(err.contains("too many wrong codes"), "{err}");
        // The spent row stays as the cooldown watermark (security-review round 4,
        // P2-1) instead of being deleted.
        assert_eq!(
            s.store.trust_request(&s.key).unwrap().unwrap().attempts,
            aux_engine::TRUST_MAX_ATTEMPTS
        );
        assert!(s.store.workspace_taint(&s.key).unwrap().is_some());

        // Even the notified code cannot revive the cancelled request.
        assert!(trust(&s.home, &s.ws, Some(&code), &fake).is_err());
        assert!(s.store.workspace_taint(&s.key).unwrap().is_some());
        assert_eq!(
            s.store.event_count("workspace.trust_failed").unwrap(),
            4,
            "three wrong codes plus the replay attempt"
        );
    }

    #[test]
    fn a_code_is_bound_to_the_workspace_that_requested_it() {
        let s = sandbox();
        let other = s.home.join("agents/other/workspace");
        std::fs::create_dir_all(&other).unwrap();
        let other_key = other.canonicalize().unwrap().to_string_lossy().into_owned();
        s.store.mark_workspace_tainted(&other_key, "shell").unwrap();

        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);

        assert!(trust(&s.home, &other, Some(&code), &fake).is_err());
        assert!(s.store.workspace_taint(&s.key).unwrap().is_some());
        assert!(s.store.workspace_taint(&other_key).unwrap().is_some());
        // The owning workspace still completes.
        assert!(trust(&s.home, &s.ws, Some(&code), &fake).is_ok());
        assert!(s.store.workspace_taint(&s.key).unwrap().is_none());
    }

    #[test]
    fn a_completed_code_cannot_be_replayed() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);

        assert!(trust(&s.home, &s.ws, Some(&code), &fake).is_ok());
        assert!(trust(&s.home, &s.ws, Some(&code), &fake).is_err());
        assert_eq!(s.store.event_count("workspace.trusted").unwrap(), 1);
    }

    #[test]
    fn a_second_request_inside_the_cooldown_is_refused_without_notifying() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let err = trust(&s.home, &s.ws, None, &fake).unwrap_err();
        assert!(err.contains("try again"), "{err}");
        assert_eq!(fake.count(), 1, "no second notification may be shown");
        assert!(s.store.workspace_taint(&s.key).unwrap().is_some());
    }

    #[test]
    fn a_failed_notification_leaves_no_pending_request() {
        let s = sandbox();
        let fake = FakeNotifier::failing("script editor said no");
        let err = trust(&s.home, &s.ws, None, &fake).unwrap_err();
        assert!(err.contains("could not be delivered"), "{err}");
        assert!(s.store.trust_request(&s.key).unwrap().is_none());
        assert!(s.store.workspace_taint(&s.key).unwrap().is_some());
        assert_eq!(s.store.event_count("workspace.trust_failed").unwrap(), 1);
    }

    /// A reader that must never be called (the code came from elsewhere).
    fn reader_panic() -> impl Fn() -> Result<String, String> {
        || panic!("this code reader must not be called")
    }

    #[test]
    fn no_code_with_a_pending_request_prompts_and_completes() {
        // P1 regression (security-review round 4): the no-flag completion path no
        // longer asks for the code as a command-line argument; it prompts
        // (without echo) and sends no second notification.
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);

        let prompt = || Ok(code.clone());
        let message =
            trust_entry_with(&s.home, &s.ws, None, &fake, &reader_panic(), &prompt).unwrap();
        assert!(message.contains("workspace trusted"), "{message}");
        assert!(!message.contains(&code), "stdout must not carry the code");
        assert_eq!(fake.count(), 1, "prompting must not notify again");
        assert!(s.store.workspace_taint(&s.key).unwrap().is_none());
    }

    #[test]
    fn the_dash_code_reads_stdin_and_completes() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);
        let calls = std::cell::Cell::new(0);

        let stdin_reader = || {
            calls.set(calls.get() + 1);
            Ok(code.clone())
        };
        let message = trust_entry_with(
            &s.home,
            &s.ws,
            Some("-"),
            &fake,
            &stdin_reader,
            &reader_panic(),
        )
        .unwrap();
        assert_eq!(calls.get(), 1, "--code - must read stdin exactly once");
        assert!(message.contains("workspace trusted"), "{message}");
        assert!(!message.contains(&code));
        assert!(s.store.workspace_taint(&s.key).unwrap().is_none());
    }

    #[test]
    fn a_spent_request_is_not_prompted_and_the_cooldown_refuses_the_next_one() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);
        let wrong = if code == "00000000" {
            "11111111"
        } else {
            "00000000"
        };
        for _ in 0..aux_engine::TRUST_MAX_ATTEMPTS {
            assert!(trust(&s.home, &s.ws, Some(wrong), &fake).is_err());
        }

        // A spent request must not prompt for a dead code; the request step
        // is rate-limited, so the owner cannot flood the notification either.
        let err = trust_entry_with(
            &s.home,
            &s.ws,
            None,
            &fake,
            &reader_panic(),
            &reader_panic(),
        )
        .unwrap_err();
        assert!(err.contains("try again"), "{err}");
        assert_eq!(fake.count(), 1, "no second notification may be shown");
        assert!(s.store.workspace_taint(&s.key).unwrap().is_some());
    }

    #[test]
    fn an_expired_pending_request_falls_back_to_the_request_step() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        backdate(&s.home, &s.key, aux_engine::TRUST_CODE_TTL_SECS + 1);

        let message = trust_entry_with(
            &s.home,
            &s.ws,
            None,
            &fake,
            &reader_panic(),
            &reader_panic(),
        )
        .unwrap();
        assert!(message.contains("trust request sent"), "{message}");
        assert_eq!(fake.count(), 2, "an expired request must be replaced");
    }

    #[test]
    fn the_legacy_literal_still_completes_without_leaking_it_to_stdout() {
        let s = sandbox();
        let fake = FakeNotifier::new();
        trust(&s.home, &s.ws, None, &fake).unwrap();
        let code = notified_code(&fake);

        let message = trust_entry_with(
            &s.home,
            &s.ws,
            Some(&code),
            &fake,
            &reader_panic(),
            &reader_panic(),
        )
        .unwrap();
        assert!(message.contains("workspace trusted"), "{message}");
        assert!(!message.contains(&code));
        assert!(s.store.workspace_taint(&s.key).unwrap().is_none());
    }

    #[test]
    fn a_hostile_notification_error_becomes_one_capped_safe_line() {
        // P2-4 regression (security-review round 4): the CLI used to print the
        // transport's stderr verbatim — multi-line, unbounded, with ANSI and
        // bidi characters. The printed line is now the API's scrub.
        let s = sandbox();
        let hostile = format!(
            "script editor said no\nsecond line\u{1b}[31m\u{202e} and {}",
            "x".repeat(10_000)
        );
        let fake = FakeNotifier::failing(hostile);
        let err = trust(&s.home, &s.ws, None, &fake).unwrap_err();
        let line = error_line(&s.home, &err);
        assert!(
            !line.contains('\n'),
            "the CLI error line must be single-line: {line:?}"
        );
        assert!(
            !line.contains('\u{1b}') && !line.contains('\u{202e}'),
            "invisible characters must be gone: {line:?}"
        );
        assert!(line.chars().count() <= CLI_ERROR_MAX_CHARS);
        assert!(line.contains("could not be delivered"), "{line}");
    }
}
