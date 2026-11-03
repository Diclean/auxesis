//! The `Sender` trait and the production AppleScript implementation (G2).
//!
//! The message text and the recipient are passed to `osascript` as positional
//! `on run argv` arguments — never interpolated into the script — so a message
//! containing quotes or AppleScript is inert. Three refusals happen before the
//! runner is ever called: an empty message, the agent's own handle (no
//! iMessage-to-self), and any recipient that is not a pinned owner handle. A
//! send is attempted once and never retried. A failure is classed from the
//! AppleScript error number alone; the raw `osascript` output is never kept.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use crate::config::{same_handle, Mode};

/// The result of one command, with no captured payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandOutput {
    /// Whether the process exited zero.
    pub success: bool,
    /// The AppleScript error number `osascript` printed last, if any. The
    /// only thing read from its output; the bytes themselves are dropped.
    pub error_number: Option<i32>,
}

/// Trailing `osascript` stderr bytes held in memory to read the error number.
const STDERR_TAIL: usize = 512;

/// The error number at the end of `osascript`'s last stderr line, as in
/// `0:91: execution error: Not authorized to send Apple events to Messages.
/// (-1743)`. Only the trailing `(<integer>)` of an `execution error:` line
/// counts: osascript always appends the real number after any text it
/// echoes, so a message text cannot choose the class.
pub fn trailing_error_number(stderr: &[u8]) -> Option<i32> {
    let text = String::from_utf8_lossy(stderr);
    let line = text.trim_end().rsplit('\n').next()?;
    if !line.contains("execution error: ") {
        return None;
    }
    let inner = line.strip_suffix(')')?;
    let number = &inner[inner.rfind('(')? + 1..];
    if number.len() > 7 {
        return None;
    }
    number.parse().ok()
}

/// The fixed system binary. Never resolved through `PATH`.
pub const OSASCRIPT_PATH: &str = "/usr/bin/osascript";

/// The one seam a test replaces: run a program with arguments.
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`, with no shell.
    fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput>;
}

/// Verify the fixed system `osascript` before running it: a regular file,
/// root-owned, and not group- or world-writable; a symlink must resolve under
/// `/usr/bin`. Fail closed otherwise.
#[cfg(unix)]
fn verify_system_osascript(path: &str) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let refuse = |reason: &str| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to run {path}: {reason}"),
        )
    };
    let link = std::fs::symlink_metadata(path).map_err(|_| refuse("cannot stat it"))?;
    if link.file_type().is_symlink() {
        let resolved = std::fs::canonicalize(path).map_err(|_| refuse("cannot resolve it"))?;
        if !resolved.starts_with("/usr/bin") {
            return Err(refuse("the symlink leaves /usr/bin"));
        }
    }
    let metadata = std::fs::metadata(path).map_err(|_| refuse("cannot stat it"))?;
    if !metadata.is_file() {
        return Err(refuse("not a regular file"));
    }
    if metadata.uid() != 0 {
        return Err(refuse("not owned by root"));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(refuse("group- or world-writable"));
    }
    Ok(())
}

/// Run a child process with a bounded wait, no shell and a cleared
/// environment.
///
/// Stdout is discarded. Stderr is drained on a thread that keeps only its
/// last [`STDERR_TAIL`] bytes, so a chatty child can never fill a pipe and
/// deadlock the wait; only the error number is read from them. The fixed
/// system `osascript` is verified root-owned and non-writable before every
/// spawn.
pub struct ProcessRunner {
    timeout: Duration,
}

impl ProcessRunner {
    /// A runner that kills a child after `timeout`.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for ProcessRunner {
    fn default() -> Self {
        Self::new(Duration::from_secs(20))
    }
}

impl CommandRunner for ProcessRunner {
    fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput> {
        #[cfg(unix)]
        if program == OSASCRIPT_PATH {
            verify_system_osascript(program)?;
        }
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let tail = child.stderr.take().map(drain_tail);
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                // The pipe closes when the child exits; bounded all the same.
                let tail = tail
                    .and_then(|rx| rx.recv_timeout(Duration::from_millis(500)).ok())
                    .unwrap_or_default();
                return Ok(CommandOutput {
                    success: status.success(),
                    error_number: trailing_error_number(&tail),
                });
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "osascript timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Read `pipe` to its end on a thread, keeping only the last
/// [`STDERR_TAIL`] bytes, and hand them over once.
fn drain_tail(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut tail = Vec::with_capacity(STDERR_TAIL * 2);
        let mut chunk = [0u8; 4096];
        while let Ok(read @ 1..) = pipe.read(&mut chunk) {
            tail.extend_from_slice(&chunk[..read]);
            if tail.len() > STDERR_TAIL {
                tail.drain(..tail.len() - STDERR_TAIL);
            }
        }
        let _ = tx.send(tail);
    });
    rx
}

/// Why a send was refused or failed. Carries no text, handle or token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The sender has no owner handle or no agent handle.
    #[error("the iMessage sender is not configured")]
    NotConfigured,
    /// The recipient is not one of the pinned owner handles.
    #[error("the recipient is not the pinned owner handle")]
    NotOwner,
    /// The recipient is the agent's own handle.
    #[error("refusing to send iMessage to the agent's own handle")]
    SelfSend,
    /// The message is empty.
    #[error("the message is empty")]
    Empty,
    /// `osascript` failed.
    #[error("the AppleScript transport failed")]
    Transport,
    /// `osascript` did not finish within the timeout, or Messages did not
    /// answer the Apple event in time (-1712).
    #[error("the AppleScript transport timed out")]
    Timeout,
    /// macOS refused the Apple event: Automation (Auxesis → Messages) is not
    /// allowed (-1743, or -1744 when it still needs the owner's consent).
    #[error("macOS does not allow Auxesis to control Messages")]
    NotAuthorized,
    /// Messages is not running, could not be reached, or has no such account
    /// or participant (-600, -609, -1719, -1728).
    #[error("Messages could not take the send")]
    MessagesUnavailable,
}

impl SendError {
    /// Class a failed `osascript` run from its AppleScript error number only.
    pub fn from_error_number(number: Option<i32>) -> Self {
        match number {
            Some(-1743 | -1744) => Self::NotAuthorized,
            Some(-600 | -609 | -1719 | -1728) => Self::MessagesUnavailable,
            Some(-1712) => Self::Timeout,
            _ => Self::Transport,
        }
    }
}

/// Send one text to one recipient. Object-safe for the gateway.
pub trait Sender: Send + Sync {
    /// Deliver `text` to `recipient`. No automatic retry.
    fn send_text(&self, recipient: &str, text: &str) -> Result<(), SendError>;
}

/// The production sender: AppleScript through `osascript`.
pub struct AppleScriptSender {
    runner: Arc<dyn CommandRunner>,
    service: &'static str,
    owner_handles: Vec<String>,
    agent_handle: String,
}

impl AppleScriptSender {
    /// Build a sender for `mode`, refusing a config with no pinned chat, no
    /// owner handle or no agent handle.
    pub fn new(
        runner: Arc<dyn CommandRunner>,
        mode: Mode,
        owner_handles: Vec<String>,
        agent_handle: String,
    ) -> Result<Self, SendError> {
        if owner_handles.is_empty() || agent_handle.trim().is_empty() {
            return Err(SendError::NotConfigured);
        }
        Ok(Self {
            runner,
            service: mode.service_type(),
            owner_handles,
            agent_handle,
        })
    }

    /// The fallback script: send to the participant handle of the signed-in
    /// account. Its `argv` is `[recipient, text]`.
    pub fn participant_script(&self) -> String {
        format!(
            "on run argv\n\
             \tset targetBuddy to item 1 of argv\n\
             \tset messageText to item 2 of argv\n\
             \ttell application \"Messages\"\n\
             \t\tset targetService to 1st account whose service type = {service}\n\
             \t\tset targetBuddyRef to participant targetBuddy of targetService\n\
             \t\tsend messageText to targetBuddyRef\n\
             \tend tell\n\
             end run\n",
            service = self.service
        )
    }

    /// The exact argv for a participant-bound send:
    /// `["-e", participant_script, recipient, text]`.
    pub fn participant_command(&self, recipient: &str, text: &str) -> Vec<String> {
        vec![
            "-e".to_string(),
            self.participant_script(),
            recipient.to_string(),
            text.to_string(),
        ]
    }

    fn is_owner(&self, recipient: &str) -> bool {
        self.owner_handles
            .iter()
            .any(|owner| same_handle(owner, recipient))
    }
}

impl Sender for AppleScriptSender {
    fn send_text(&self, recipient: &str, text: &str) -> Result<(), SendError> {
        if text.is_empty() {
            return Err(SendError::Empty);
        }
        if same_handle(recipient, &self.agent_handle) {
            return Err(SendError::SelfSend);
        }
        if !self.is_owner(recipient) {
            return Err(SendError::NotOwner);
        }
        let args = self.participant_command(recipient, text);
        match self.runner.run(OSASCRIPT_PATH, &args) {
            Ok(output) if output.success => Ok(()),
            Ok(output) => Err(SendError::from_error_number(output.error_number)),
            Err(err) if err.kind() == io::ErrorKind::TimedOut => Err(SendError::Timeout),
            Err(_) => Err(SendError::Transport),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Replies from a fixed queue; the queue runs out to `true`.
    struct FakeRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        replies: Mutex<VecDeque<bool>>,
    }

    impl FakeRunner {
        fn new(replies: impl IntoIterator<Item = bool>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                replies: Mutex::new(replies.into_iter().collect()),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            let success = self.replies.lock().unwrap().pop_front().unwrap_or(true);
            Ok(CommandOutput {
                success,
                error_number: None,
            })
        }
    }

    const OWNER: &str = "+33600000001";
    fn sender(runner: Arc<FakeRunner>, mode: Mode) -> AppleScriptSender {
        AppleScriptSender::new(
            runner,
            mode,
            vec![OWNER.to_string(), "owner@example.test".to_string()],
            "agent@example.test".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn the_text_travels_through_argv_not_the_script() {
        let runner = Arc::new(FakeRunner::new([true]));
        let sender = sender(runner.clone(), Mode::AppleId);
        let text = "Bonjour \" & do shell script \"id\" & \"";
        sender.send_text(OWNER, text).unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 1, "the approved participant is sent once");
        let (program, args) = &calls[0];
        assert_eq!(program, OSASCRIPT_PATH);
        assert_eq!(args[0], "-e");
        let script = &args[1];
        assert!(script.contains("on run argv"));
        assert!(script.contains("item 2 of argv"));
        assert!(script.contains("participant targetBuddy"));
        assert!(!script.contains(text), "the text is never in the script");
        assert_eq!(args[2], OWNER);
        assert_eq!(args[3], text);
    }

    #[test]
    fn the_recipient_is_bound_to_the_approved_participant() {
        let runner = Arc::new(FakeRunner::new([true]));
        let sender = sender(runner.clone(), Mode::AppleId);
        let text = "Bonjour depuis le fallback";
        sender.send_text(OWNER, text).unwrap();

        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        let (program, participant) = &calls[0];
        assert_eq!(program, OSASCRIPT_PATH);
        assert!(participant[1].contains("participant targetBuddy"));
        assert!(participant[1].contains("service type = iMessage"));
        assert!(
            !participant[1].contains(text),
            "the participant script never names the text"
        );
        assert_eq!(participant[2], OWNER);
        assert_eq!(participant[3], text);
    }

    #[test]
    fn a_participant_send_is_never_retried() {
        let runner = Arc::new(FakeRunner::new([true, true]));
        let sender = sender(runner.clone(), Mode::AppleId);
        sender.send_text(OWNER, "hello").unwrap();
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn the_participant_script_uses_the_fixed_program_and_argv_shape() {
        let runner = Arc::new(FakeRunner::new([true]));
        let sender = sender(runner.clone(), Mode::AppleId);
        sender.send_text(OWNER, "hello").unwrap();
        for (program, args) in runner.calls() {
            assert_eq!(program, OSASCRIPT_PATH);
            assert_eq!(args[0], "-e");
            assert_eq!(args.len(), 4);
            assert_eq!(args[3], "hello");
        }
    }

    #[test]
    fn the_rcs_fallback_targets_the_sms_service() {
        let runner = Arc::new(FakeRunner::new([true]));
        let sender = sender(runner, Mode::RcsFallback);
        let participant = sender.participant_script();
        assert!(participant.contains("service type = SMS"));
        assert!(!participant.contains("service type = iMessage"));
    }

    #[test]
    fn a_send_to_the_agents_own_handle_is_refused_before_osascript() {
        let runner = Arc::new(FakeRunner::new([true]));
        let sender = sender(runner.clone(), Mode::AppleId);
        assert_eq!(
            sender.send_text("agent@example.test", "hi"),
            Err(SendError::SelfSend)
        );
        assert_eq!(
            sender.send_text("AGENT@example.test", "hi"),
            Err(SendError::SelfSend),
            "email handles compare case-insensitively"
        );
        assert!(runner.calls().is_empty(), "osascript never ran");
    }

    #[test]
    fn a_send_to_anyone_but_the_owner_is_refused_before_osascript() {
        let runner = Arc::new(FakeRunner::new([true]));
        let sender = sender(runner.clone(), Mode::AppleId);
        assert_eq!(
            sender.send_text("+33600000002", "hi"),
            Err(SendError::NotOwner)
        );
        assert_eq!(sender.send_text("", "hi"), Err(SendError::NotOwner));
        assert!(runner.calls().is_empty(), "osascript never ran");
    }

    #[test]
    fn an_empty_message_is_refused() {
        let runner = Arc::new(FakeRunner::new([true]));
        let sender = sender(runner.clone(), Mode::AppleId);
        assert_eq!(sender.send_text(OWNER, ""), Err(SendError::Empty));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn a_failed_participant_send_is_not_retried() {
        let runner = Arc::new(FakeRunner::new([false]));
        let sender = sender(runner.clone(), Mode::AppleId);
        assert_eq!(sender.send_text(OWNER, "hi"), Err(SendError::Transport));
        assert_eq!(runner.calls().len(), 1);
    }

    #[test]
    fn a_failed_send_is_classed_by_its_error_number_only() {
        let class = |n| SendError::from_error_number(Some(n));
        assert_eq!(class(-1743), SendError::NotAuthorized);
        assert_eq!(class(-600), SendError::MessagesUnavailable);
        assert_eq!(class(-1712), SendError::Timeout);
        assert_eq!(class(-1700), SendError::Transport);
        assert_eq!(SendError::from_error_number(None), SendError::Transport);
    }

    #[test]
    fn only_a_trailing_execution_error_number_counts() {
        let n = |s: &str| trailing_error_number(s.as_bytes());
        assert_eq!(n("0:9: execution error: No. (-1743)\n"), Some(-1743));
        assert_eq!(n("0:9: execution error: a (-1743) b (-1700)"), Some(-1700));
        assert_eq!(n("syntax error: (-1743)"), None);
        assert_eq!(n("0:9: execution error: x (-17430000000)"), None);
        assert_eq!(n(""), None);
    }

    #[test]
    fn a_sender_with_no_owner_or_agent_handle_is_not_configured() {
        let runner = Arc::new(FakeRunner::new([true]));
        // No owner handle.
        assert_eq!(
            AppleScriptSender::new(
                runner.clone(),
                Mode::AppleId,
                vec![],
                "a@example.test".into()
            )
            .err(),
            Some(SendError::NotConfigured)
        );
        // No agent handle.
        assert_eq!(
            AppleScriptSender::new(runner, Mode::AppleId, vec![OWNER.into()], " ".into()).err(),
            Some(SendError::NotConfigured)
        );
    }
}
