//! Client-side ACP methods, answered through Auxesis' broker semantics.
//!
//! The agent never touches the host filesystem or runs host commands directly
//! through these methods:
//!
//! - `fs/read_text_file` and `fs/write_text_file` are confined to the
//!   per-agent scratch workspace with canonical-path and symlink checks, size
//!   caps, and an approval for writes (never auto-approved);
//! - `terminal/*` commands run through the same sandbox launcher as the
//!   `shell` tool (Seatbelt profile, private HOME/TMPDIR, process-group kill);
//! - `session/request_permission` opens an approval through the existing
//!   [`kernel_broker::Approver`] flow (the daemon passes its `ApiApprover`), with
//!   a fail-closed timeout, and answers `cancelled` for every pending ask when
//!   the turn is cancelled;
//! - every response is a JSON-RPC error instead of raw host access when the
//!   request is out of policy.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};

use kernel_broker::sandbox::{self, ShellSandbox};
use kernel_broker::{ApprovalRequest, Approver, Risk};

use crate::error::AcpError;
use crate::jsonrpc::{RequestHandler, RpcLimits};
use crate::protocol::{code, method, RpcError};

/// Default cap on one `fs/read_text_file` response.
pub const DEFAULT_MAX_READ_BYTES: usize = 256 * 1024;

/// Default cap on one `fs/write_text_file` body.
pub const DEFAULT_MAX_WRITE_BYTES: usize = 1024 * 1024;

/// Default cap on one `terminal/output` response.
pub const DEFAULT_MAX_TERMINAL_BYTES: usize = 256 * 1024;

/// Default cap on live terminals per turn: a third-party agent must not be
/// able to fan out host processes at will.
pub const DEFAULT_MAX_TERMINALS_PER_TURN: usize = 4;

/// Default wall-clock wait for `terminal/wait_for_exit`.
pub const DEFAULT_TERMINAL_WAIT: Duration = Duration::from_secs(300);

/// Which host text a [`HostGate`] is asked to tokenise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostText {
    /// A file the host reads for the agent (`fs/read_text_file`, D2).
    FileRead,
    /// Output of a host terminal (`terminal/output`, D3).
    TerminalOutput,
}

/// The session gate as the ACP host sees it (private mode). The agent talks to a
/// cloud model, so whatever the host serves back to it passes `tokenise` first;
/// `reveal` turns the agent's tokens back into values for the owner's screen
/// only and its result never goes back to the agent. Absent in open mode.
pub trait HostGate: std::fmt::Debug + Send + Sync {
    /// The tokenised copy of `text`, or why it cannot be sent: the host then
    /// answers the agent with an error and nothing leaves.
    fn tokenise(&self, kind: HostText, text: &str) -> Result<String, String>;
    /// `text` with the session's tokens replaced by their values.
    fn reveal(&self, text: &str) -> String;
}

/// `value` with every string run through `gate.reveal` (keys stay as they are).
fn reveal_value(gate: &dyn HostGate, value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(gate.reveal(text)),
        Value::Array(items) => Value::Array(items.iter().map(|v| reveal_value(gate, v)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, v)| (key.clone(), reveal_value(gate, v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Effective caps and policy for broker-backed handlers.
#[derive(Debug, Clone)]
pub struct HandlerLimits {
    /// The private-mode session gate for host text; `None` in open mode.
    pub host_gate: Option<Arc<dyn HostGate>>,
    /// Largest read answered.
    pub max_read_bytes: usize,
    /// Largest write accepted.
    pub max_write_bytes: usize,
    /// Largest terminal output chunk returned.
    pub max_terminal_bytes: usize,
    /// Largest number of terminals alive at once in one turn.
    pub max_terminals_per_turn: usize,
    /// Bounded wait for one permission answer.
    pub permission_timeout: Duration,
    /// Bounded wait for one terminal command.
    pub terminal_wait_timeout: Duration,
    /// Sandbox settings for `terminal/*` (network is irrelevant here; commands
    /// stay as configured).
    pub sandbox: ShellSandbox,
    /// Per-turn marker injected into terminal environments (`AUXESIS_ACP_TURN`),
    /// so the reaper's env sweep finds escaped terminal children.
    pub turn_marker: String,
    /// Start of the JSON-RPC caps, used for terminal handler bookkeeping.
    pub rpc: RpcLimits,
}

impl Default for HandlerLimits {
    fn default() -> Self {
        Self {
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
            max_write_bytes: DEFAULT_MAX_WRITE_BYTES,
            max_terminal_bytes: DEFAULT_MAX_TERMINAL_BYTES,
            max_terminals_per_turn: DEFAULT_MAX_TERMINALS_PER_TURN,
            permission_timeout: Duration::from_secs(120),
            terminal_wait_timeout: DEFAULT_TERMINAL_WAIT,
            sandbox: ShellSandbox::default(),
            turn_marker: String::new(),
            rpc: RpcLimits::default(),
            host_gate: None,
        }
    }
}

/// Shared turn state the handlers observe.
#[derive(Debug, Default)]
pub struct TurnState {
    /// Set as soon as any agent-originated text arrives: approvals become
    /// tainted (no "always allow"), exactly like web content.
    pub tainted: AtomicBool,
    /// Set when the turn is cancelled: every pending/next permission answers
    /// `cancelled`, and terminals refuse new work.
    pub cancelled: AtomicBool,
    /// Wakes a pending approval when the turn is cancelled.
    cancel_notify: tokio::sync::Notify,
}

impl TurnState {
    /// Mark the conversation tainted.
    pub fn mark_tainted(&self) {
        self.tainted.store(true, Ordering::SeqCst);
    }

    /// True when untrusted agent content entered the turn.
    pub fn is_tainted(&self) -> bool {
        self.tainted.load(Ordering::SeqCst)
    }

    /// Mark the turn cancelled and wake every waiter.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.cancel_notify.notify_waiters();
    }

    /// True when the turn was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Resolve when the turn is cancelled (immediately if it already is).
    pub async fn wait_cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.cancel_notify.notified();
        tokio::pin!(notified);
        // Register interest before the second check, so a cancel between the
        // first check and the await cannot be lost.
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

/// The broker-backed implementation of the ACP client methods.
pub struct BrokerHandlers {
    /// Canonical scratch workspace: the only writable surface.
    workspace: PathBuf,
    /// Agent the turn belongs to (approval cards).
    agent: String,
    /// Approval callback (daemon: `ApiApprover`; CLI: stdin; tests: canned).
    approver: Arc<dyn Approver>,
    /// Shared turn state.
    state: Arc<TurnState>,
    /// Caps and policy.
    limits: HandlerLimits,
    /// Read-only turn (an ACP brain): refuse every write or exec method, so a
    /// skill with no tools cannot drive the agent's own terminal or filesystem.
    read_only: bool,
    /// Live terminals keyed by id.
    terminals: Mutex<HashMap<String, TerminalEntry>>,
    /// Terminal id counter.
    next_terminal: AtomicU64,
}

impl BrokerHandlers {
    /// Build handlers confined to `workspace`.
    pub fn new(
        workspace: PathBuf,
        agent: String,
        approver: Arc<dyn Approver>,
        state: Arc<TurnState>,
        limits: HandlerLimits,
    ) -> Result<Self, AcpError> {
        let workspace = workspace.canonicalize().map_err(|err| {
            AcpError::Sandbox(format!(
                "workspace {} is not usable: {err}",
                workspace.display()
            ))
        })?;
        if !workspace.is_dir() {
            return Err(AcpError::Sandbox(format!(
                "workspace {} is not a directory",
                workspace.display()
            )));
        }
        Ok(Self {
            workspace,
            agent,
            approver,
            state,
            limits,
            read_only: false,
            terminals: Mutex::new(HashMap::new()),
            next_terminal: AtomicU64::new(1),
        })
    }

    /// Refuse every write or exec method for this turn (ACP-as-brain). The
    /// coding-agent mode keeps its current behaviour (`read_only = false`).
    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// The canonical workspace.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Kill every live terminal (also called on drop).
    pub fn kill_all_terminals(&self) {
        let mut terminals = lock_terminals(&self.terminals);
        for (_, entry) in terminals.drain() {
            drop(entry); // Drop kills the tree.
        }
    }

    // ---- fs/* ----

    /// Resolve an agent-provided absolute path to an existing file inside the
    /// workspace (canonical, symlink-safe).
    fn resolve_readable(&self, path: &Value) -> Result<PathBuf, RpcError> {
        let raw = path
            .as_str()
            .filter(|path| path.starts_with('/'))
            .ok_or_else(|| invalid_params("path must be an absolute string"))?;
        let canonical = PathBuf::from(raw)
            .canonicalize()
            .map_err(|_| invalid_params("path does not exist or cannot be resolved"))?;
        if !canonical.starts_with(&self.workspace) {
            return Err(outside_workspace());
        }
        if canonical == self.workspace {
            return Err(invalid_params("path names a directory"));
        }
        Ok(canonical)
    }

    /// Resolve an agent-provided absolute path for writing inside the
    /// workspace: create the parent only inside the workspace and refuse a
    /// final symlink that points outside it.
    fn resolve_writable(&self, path: &Value) -> Result<PathBuf, RpcError> {
        let raw = path
            .as_str()
            .filter(|path| path.starts_with('/'))
            .ok_or_else(|| invalid_params("path must be an absolute string"))?;
        let requested = PathBuf::from(raw);
        // No `..` components: the join below must not escape, and canonical
        // checks alone would allow a symlinked intermediate directory.
        if requested
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(outside_workspace());
        }
        let file_name = requested
            .file_name()
            .ok_or_else(|| invalid_params("path has no file name"))?;
        let parent = requested
            .parent()
            .ok_or_else(|| invalid_params("path has no parent"))?;
        // A parent outside the workspace is refused before anything is
        // created on disk. (`create_dir_all` follows symlinks, so canonical
        // checks come after: the parent must resolve inside the workspace.)
        if !parent.starts_with(&self.workspace) {
            return Err(outside_workspace());
        }
        std::fs::create_dir_all(parent)
            .map_err(|_| internal("could not create the parent directory"))?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| internal("the parent directory is unusable"))?;
        if !canonical_parent.starts_with(&self.workspace) {
            return Err(outside_workspace());
        }
        let target = canonical_parent.join(file_name);
        // Refuse writing through a final symlink that leaves the workspace
        // (an existing file resolved inside is fine).
        if let Ok(metadata) = std::fs::symlink_metadata(&target) {
            if metadata.file_type().is_symlink() {
                let resolved = target.canonicalize().map_err(|_| outside_workspace())?;
                if !resolved.starts_with(&self.workspace) {
                    return Err(outside_workspace());
                }
                return Ok(resolved);
            }
        }
        Ok(target)
    }

    fn read_text_file(&self, params: &Value) -> Result<Value, RpcError> {
        let path = self.resolve_readable(params.get("path").unwrap_or(&Value::Null))?;
        let file = std::fs::File::open(&path).map_err(|_| internal("could not open the file"))?;
        let mut bytes = Vec::new();
        file.take((self.limits.max_read_bytes + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| internal("could not read the file"))?;
        let mut truncated = false;
        if bytes.len() > self.limits.max_read_bytes {
            bytes.truncate(self.limits.max_read_bytes);
            truncated = true;
        }
        let mut content = String::from_utf8_lossy(&bytes).into_owned();
        // `line` is 1-based; `limit` is a maximum number of lines.
        let line = params
            .get("line")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1) as usize;
        if line > 1 || params.get("limit").is_some() {
            let taken: Vec<&str> = content
                .lines()
                .skip(line - 1)
                .take(
                    params
                        .get("limit")
                        .and_then(Value::as_u64)
                        .unwrap_or(u64::MAX) as usize,
                )
                .collect();
            content = taken.join("\n");
        }
        if let Some(gate) = &self.limits.host_gate {
            content = gate
                .tokenise(HostText::FileRead, &content)
                .map_err(|_| internal("the file cannot be shared in private mode"))?;
        }
        let mut result = json!({"content": content});
        if truncated {
            result["truncated"] = json!(true);
        }
        // The read cap is a raw-byte cap; JSON escaping (control bytes grow
        // ×6) can still push the frame past the outbound cap. Fit the
        // escaped frame before it is sent.
        fit_result_string(&mut result, "content", self.limits.rpc.max_frame_bytes);
        Ok(result)
    }

    async fn write_text_file(&self, params: &Value) -> Result<Value, RpcError> {
        if self.state.is_cancelled() {
            return Err(cancelled_error());
        }
        let content = params
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_params("content must be a string"))?;
        if content.len() > self.limits.max_write_bytes {
            return Err(invalid_params(format!(
                "content exceeds the {} byte cap",
                self.limits.max_write_bytes
            )));
        }
        let path = self.resolve_writable(params.get("path").unwrap_or(&Value::Null))?;
        // Writes are consequential: ask through the approval flow, never
        // auto-approve, fail closed on timeout or error.
        let request = ApprovalRequest {
            agent: self.agent.clone(),
            tool: "acp.fs.write".to_string(),
            risk: Risk::Medium,
            arguments: json!({
                "path": path.display().to_string(),
                "bytes": content.len(),
            }),
            tainted: self.state.is_tainted(),
            taint_source: self
                .state
                .is_tainted()
                .then(|| "acp agent output".to_string()),
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        if !self.ask(&request).await? {
            return Err(denied_error());
        }
        // The approval window is human-sized: the agent can swap any path
        // component for a symlink while the owner decides. Re-open under the
        // verified workspace root with no-follow semantics instead of using
        // the path resolved before the approval.
        let mut file = self.open_verified_write(&path)?;
        file.write_all(content.as_bytes())
            .map_err(|_| internal("could not write the file"))?;
        Ok(Value::Null)
    }

    /// Open an approved path for writing, re-verified *after* the approval.
    ///
    /// Opens the parent directory, checks the real path of that descriptor is
    /// inside the workspace, opens the final component relative to it with
    /// `O_CREAT|O_NOFOLLOW` (a swapped-in symlink is an error, not a
    /// redirect), then checks the real path of the opened file, too. Any
    /// mismatch fails closed.
    fn open_verified_write(&self, path: &Path) -> Result<std::fs::File, RpcError> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid_params("path has no parent"))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| invalid_params("path has no file name"))?;
        let parent_file = std::fs::File::open(parent)
            .map_err(|_| internal("could not open the parent directory"))?;
        let real_parent = fd_real_path(&parent_file)
            .map_err(|_| internal("could not verify the parent directory"))?;
        if !real_parent.starts_with(&self.workspace) {
            return Err(outside_workspace());
        }
        let opened = openat_nofollow(&parent_file, file_name)?;
        let real_target =
            fd_real_path(&opened).map_err(|_| internal("could not verify the written file"))?;
        if !real_target.starts_with(&self.workspace) {
            return Err(outside_workspace());
        }
        Ok(opened)
    }

    // ---- session/request_permission ----

    async fn request_permission(&self, params: &Value) -> Result<Value, RpcError> {
        if self.state.is_cancelled() {
            return Ok(cancelled_outcome());
        }
        // A hostile agent can ask before publishing any update; agent input is
        // untrusted by definition, so the ask is always tainted and the turn
        // state flips immediately (no "always allow" from here on).
        self.state.mark_tainted();
        let mut tool_call = params.get("toolCall").cloned().unwrap_or(Value::Null);
        // The agent only knows tokens; the owner's approval card shows the
        // values (it is local). The answer below carries an option id only.
        if let Some(gate) = &self.limits.host_gate {
            tool_call = reveal_value(gate.as_ref(), &tool_call);
        }
        let title = tool_call
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("(untitled tool call)");
        let kind = tool_call
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let request = ApprovalRequest {
            agent: self.agent.clone(),
            tool: "acp.permission".to_string(),
            risk: Risk::High,
            arguments: json!({
                "toolCallId": tool_call.get("toolCallId").cloned().unwrap_or(Value::Null),
                "title": title,
                "kind": kind,
                "rawInput": tool_call.get("rawInput").cloned().unwrap_or(Value::Null),
            }),
            tainted: true,
            taint_source: Some("acp agent request".to_string()),
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        let approved = self.ask(&request).await?;
        if self.state.is_cancelled() {
            return Ok(cancelled_outcome());
        }
        Ok(permission_outcome(params, approved))
    }

    /// One approval through the shared [`Approver`], fail closed on timeout or
    /// error, and cancelled the moment the turn is cancelled (never waits for
    /// the timeout to answer a cancelled turn).
    async fn ask(&self, request: &ApprovalRequest) -> Result<bool, RpcError> {
        if self.state.is_cancelled() {
            return Ok(false);
        }
        let timeout = self.limits.permission_timeout;
        let approval = tokio::time::timeout(timeout, self.approver.approve(request));
        tokio::pin!(approval);
        tokio::select! {
            biased;
            _ = self.state.wait_cancelled() => Ok(false),
            result = &mut approval => match result {
                Ok(Ok(approved)) => Ok(approved),
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "acp: approver failed; failing closed");
                    Ok(false)
                }
                Err(_) => {
                    tracing::warn!(
                        secs = timeout.as_secs(),
                        "acp: approval timed out; failing closed"
                    );
                    Ok(false)
                }
            },
        }
    }

    // ---- terminal/* ----

    fn terminal_create(&self, params: &Value) -> Result<Value, RpcError> {
        if self.state.is_cancelled() {
            return Err(cancelled_error());
        }
        // Terminals run host commands, and this broker never asks for an
        // approval for them: if Seatbelt is unavailable (or configured off),
        // fail closed instead of falling back to an unsandboxed run.
        if !self.limits.sandbox.enabled || !self.limits.sandbox.available() {
            return Err(internal(
                "terminal/create refused: the sandbox is unavailable; \
                 no unsandboxed terminal will run",
            ));
        }
        if lock_terminals(&self.terminals).len() >= self.limits.max_terminals_per_turn {
            return Err(internal(format!(
                "terminal/create refused: at most {} terminals may run per turn",
                self.limits.max_terminals_per_turn
            )));
        }
        let command = params
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_params("command must be a string"))?;
        let mut args: Vec<String> = params
            .get("args")
            .and_then(Value::as_array)
            .map(|args| {
                args.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let command_line = {
            let mut parts = vec![shell_quote(command)];
            parts.extend(args.drain(..).map(|arg| shell_quote(&arg)));
            parts.join(" ")
        };
        // `cwd` is optional and must stay inside the workspace.
        let mut command_line = command_line;
        if let Some(cwd) = params.get("cwd").and_then(Value::as_str) {
            let cwd_path = PathBuf::from(cwd);
            if !cwd_path.starts_with(&self.workspace) {
                return Err(outside_workspace());
            }
            let canonical = cwd_path
                .canonicalize()
                .map_err(|_| invalid_params("cwd does not exist"))?;
            if !canonical.starts_with(&self.workspace) {
                return Err(outside_workspace());
            }
            command_line = format!("cd -- {} && {}", shell_quote(cwd), command_line);
        }

        // Private mode: a command runs with the values the gate withheld from the
        // agent, so it runs with no network whatever `[shell]` says.
        let mut terminal_sandbox = self.limits.sandbox.clone();
        if self.limits.host_gate.is_some() {
            terminal_sandbox.network = false;
        }
        let launched = sandbox::launch_with_limits(
            &command_line,
            &self.workspace,
            &terminal_sandbox,
            Duration::from_secs(3600),
            // Capture files are the agent's output sink: cap every file the
            // terminal writes at the same 256 KiB the broker reads back, and
            // bound how many processes it can create.
            self.limits.max_terminal_bytes as u64,
            sandbox::MAX_EXTRA_PROCESSES,
        )
        .map_err(|err| match err {
            sandbox::LaunchError::Unavailable | sandbox::LaunchError::SandboxDisabled => {
                internal(err.to_string())
            }
            sandbox::LaunchError::UnsafeWorkspace(_)
            | sandbox::LaunchError::SensitiveWorkspace(_) => outside_workspace(),
            sandbox::LaunchError::Io(_) => internal("could not prepare the terminal"),
        })?;
        let sandbox::Launched {
            mut command,
            temp,
            stdout_capture,
            stderr_capture,
            marker_file,
        } = launched;
        // Every terminal carries the per-turn marker, so children that close
        // their descriptors are still found by the env sweep.
        if !self.limits.turn_marker.is_empty() {
            command.env(crate::reaper::TURN_MARKER_ENV, &self.limits.turn_marker);
        }
        // Agent-provided env vars are added after the launcher's `env_clear`,
        // and only names that could never carry our secrets.
        if let Some(env) = params.get("env").and_then(Value::as_array) {
            for entry in env {
                let (Some(name), Some(value)) = (
                    entry.get("name").and_then(Value::as_str),
                    entry.get("value").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if crate::config::env_name_forbidden(name) {
                    return Err(invalid_params(format!(
                        "environment variable `{name}` is refused"
                    )));
                }
                command.env(name, value);
            }
        }
        let child = command
            .spawn()
            .map_err(|_| internal("could not start the terminal command"))?;
        let pid = child.id().unwrap_or(0);
        // Record the terminal's start time: a later kill must never land on a
        // recycled pid (and the group sweep only ever signals the dedicated
        // session the launcher created).
        let start = (pid > 0)
            .then(|| crate::reaper::PidIdentity::of(pid as i32))
            .flatten()
            .map(|identity| identity.start);
        let marker = crate::reaper::Marker::from_file(&marker_file)
            .map_err(|_| internal("could not prepare the terminal marker"))?;
        let id = format!(
            "term-{}",
            self.next_terminal.fetch_add(1, Ordering::Relaxed)
        );
        let entry = TerminalEntry {
            child: Some(child),
            exit: None,
            temp,
            marker_file,
            marker,
            pid,
            start,
            stdout: stdout_capture,
            stderr: stderr_capture,
            killed: false,
        };
        lock_terminals(&self.terminals).insert(id.clone(), entry);
        Ok(json!({"terminalId": id}))
    }

    /// The exit status the agent is told. In private mode the command ran with
    /// real values the agent never saw, so its exit code and signal would be a
    /// yes/no channel about them (`test "$IBAN" = FR…`): the agent learns only
    /// that the command ended.
    fn shared_status(&self, exit: &std::process::ExitStatus) -> Value {
        if self.limits.host_gate.is_some() {
            return json!({"exitCode": null, "signal": null});
        }
        json!({
            "exitCode": exit.code().unwrap_or(126),
            "signal": exit_signal(exit),
        })
    }

    fn terminal_output(&self, params: &Value) -> Result<Value, RpcError> {
        let id = terminal_id(params)?;
        let mut terminals = lock_terminals(&self.terminals);
        let entry = terminals
            .get_mut(&id)
            .ok_or_else(|| invalid_params("unknown terminalId"))?;
        entry.poll_exit();
        let (mut output, truncated) = entry.read_output(self.limits.max_terminal_bytes);
        if let Some(gate) = &self.limits.host_gate {
            output = gate
                .tokenise(HostText::TerminalOutput, &output)
                .map_err(|_| internal("the output cannot be shared in private mode"))?;
        }
        let mut result = json!({"output": output, "truncated": truncated});
        if let Some(exit) = &entry.exit {
            result["exitStatus"] = self.shared_status(exit);
        }
        fit_result_string(&mut result, "output", self.limits.rpc.max_frame_bytes);
        Ok(result)
    }

    async fn terminal_wait_for_exit(&self, params: &Value) -> Result<Value, RpcError> {
        let id = terminal_id(params)?;
        let mut child = {
            let mut terminals = lock_terminals(&self.terminals);
            let entry = terminals
                .get_mut(&id)
                .ok_or_else(|| invalid_params("unknown terminalId"))?;
            if let Some(exit) = &entry.exit {
                return Ok(self.shared_status(exit));
            }
            entry
                .child
                .take()
                .ok_or_else(|| internal("another waiter already owns this terminal"))?
        };
        let waited = tokio::time::timeout(self.limits.terminal_wait_timeout, child.wait()).await;
        let mut terminals = lock_terminals(&self.terminals);
        let Some(entry) = terminals.get_mut(&id) else {
            return Ok(json!({"exitCode": null, "signal": null}));
        };
        match waited {
            Ok(Ok(status)) => {
                entry.exit = Some(status);
                // The child is reaped: re-arm the entry with its own status
                // only; nothing to kill later.
                entry.child = None;
                Ok(self.shared_status(&status))
            }
            Ok(Err(_)) => {
                entry.child = Some(child);
                Err(internal("waiting for the terminal failed"))
            }
            Err(_) => {
                entry.child = Some(child);
                Err(internal("timed out waiting for the terminal"))
            }
        }
    }

    fn terminal_kill(&self, params: &Value) -> Result<Value, RpcError> {
        let id = terminal_id(params)?;
        let mut terminals = lock_terminals(&self.terminals);
        let entry = terminals
            .get_mut(&id)
            .ok_or_else(|| invalid_params("unknown terminalId"))?;
        entry.kill();
        Ok(Value::Null)
    }

    fn terminal_release(&self, params: &Value) -> Result<Value, RpcError> {
        let id = terminal_id(params)?;
        let mut terminals = lock_terminals(&self.terminals);
        if let Some(entry) = terminals.remove(&id) {
            drop(entry); // Drop kills anything still running.
        }
        Ok(Value::Null)
    }
}

impl Drop for BrokerHandlers {
    fn drop(&mut self) {
        self.kill_all_terminals();
    }
}

#[async_trait]
impl RequestHandler for BrokerHandlers {
    async fn handle(&self, method_name: &str, params: &Value) -> Result<Value, RpcError> {
        if self.read_only && is_read_only_refused(method_name) {
            return Err(RpcError::new(
                code::INVALID_REQUEST,
                format!("method `{method_name}` is refused: this ACP turn is read-only"),
            ));
        }
        // Private mode: the agent names paths, commands and content by token.
        // What runs on this Mac for it runs with the values, right here, and
        // nothing of the result goes back except through the gate (D2, D3).
        let revealed;
        let params = match (&self.limits.host_gate, method_name) {
            (
                Some(gate),
                method::FS_READ_TEXT_FILE | method::FS_WRITE_TEXT_FILE | method::TERMINAL_CREATE,
            ) => {
                revealed = reveal_value(gate.as_ref(), params);
                &revealed
            }
            _ => params,
        };
        match method_name {
            method::FS_READ_TEXT_FILE => self.read_text_file(params),
            method::FS_WRITE_TEXT_FILE => self.write_text_file(params).await,
            method::SESSION_REQUEST_PERMISSION => self.request_permission(params).await,
            method::TERMINAL_CREATE => self.terminal_create(params),
            method::TERMINAL_OUTPUT => self.terminal_output(params),
            method::TERMINAL_WAIT_FOR_EXIT => self.terminal_wait_for_exit(params).await,
            method::TERMINAL_KILL => self.terminal_kill(params),
            method::TERMINAL_RELEASE => self.terminal_release(params),
            other => Err(RpcError::new(
                code::METHOD_NOT_FOUND,
                format!("method `{other}` is not supported by this client"),
            )),
        }
    }
}

fn lock_terminals(
    terminals: &Mutex<HashMap<String, TerminalEntry>>,
) -> std::sync::MutexGuard<'_, HashMap<String, TerminalEntry>> {
    terminals.lock().unwrap_or_else(|err| err.into_inner())
}

/// Methods an ACP-as-brain (read-only) turn refuses: every write, and every
/// terminal method (create/output/wait/kill/release, i.e. exec and its
/// lifecycle). Reads stay limited to the skill's read scope as before.
fn is_read_only_refused(method_name: &str) -> bool {
    matches!(
        method_name,
        method::FS_WRITE_TEXT_FILE
            | method::TERMINAL_CREATE
            | method::TERMINAL_OUTPUT
            | method::TERMINAL_WAIT_FOR_EXIT
            | method::TERMINAL_KILL
            | method::TERMINAL_RELEASE
    )
}

fn terminal_id(params: &Value) -> Result<String, RpcError> {
    params
        .get("terminalId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| invalid_params("terminalId must be a string"))
}

fn invalid_params(message: impl Into<String>) -> RpcError {
    RpcError::new(code::INVALID_PARAMS, message)
}

fn internal(message: impl Into<String>) -> RpcError {
    RpcError::new(code::INTERNAL_ERROR, message)
}

fn outside_workspace() -> RpcError {
    // Deliberately generic: never echo host paths back to the agent.
    RpcError::new(
        code::INVALID_PARAMS,
        "path is outside the session workspace",
    )
}

fn denied_error() -> RpcError {
    RpcError::new(code::INTERNAL_ERROR, "the owner denied this request")
}

fn cancelled_error() -> RpcError {
    RpcError::new(code::INTERNAL_ERROR, "the turn was cancelled")
}

/// The `session/request_permission` response for a cancelled turn (spec MUST).
fn cancelled_outcome() -> Value {
    json!({"outcome": {"outcome": "cancelled"}})
}

/// Pick the offered option matching the decision.
///
/// `allow_once` is the **only** allow ever selected: a permission request from
/// the agent is untrusted, so the standing `allow_always` option is never
/// offered or accepted back. If the agent offered no allow-once option, the
/// ask is answered `cancelled` (fail closed) rather than inventing an id or
/// upgrading to a persistent grant. Rejections prefer `reject_once`.
fn permission_outcome(params: &Value, approved: bool) -> Value {
    let options = params
        .get("options")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let wanted: &[&str] = if approved {
        &["allow_once"]
    } else {
        &["reject_once", "reject_always"]
    };
    for kind in wanted {
        if let Some(option_id) = options.iter().find_map(|option| {
            (option.get("kind").and_then(Value::as_str) == Some(*kind))
                .then(|| option.get("optionId").and_then(Value::as_str))
                .flatten()
        }) {
            return json!({
                "outcome": {"outcome": "selected", "optionId": option_id},
            });
        }
    }
    // No option matches: fail closed.
    cancelled_outcome()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The real path an open descriptor points at (macOS `F_GETPATH`; Linux
/// `/proc/self/fd`). Verification fails closed when the platform cannot
/// answer.
#[cfg(target_os = "macos")]
fn fd_real_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;

    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    Ok(PathBuf::from(
        String::from_utf8_lossy(&buffer[..end]).into_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn fd_real_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;

    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn fd_real_path(_file: &std::fs::File) -> std::io::Result<PathBuf> {
    Err(std::io::Error::other(
        "descriptor path verification is unavailable on this platform",
    ))
}

/// Open `name` below the already-verified directory descriptor, write-only,
/// creating the file and refusing a symlink in the final component.
#[cfg(unix)]
fn openat_nofollow(dir: &std::fs::File, name: &std::ffi::OsStr) -> Result<std::fs::File, RpcError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| invalid_params("file name is not usable"))?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(internal("could not open the file for writing"));
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn openat_nofollow(
    _dir: &std::fs::File,
    _name: &std::ffi::OsStr,
) -> Result<std::fs::File, RpcError> {
    Err(internal(
        "no-follow writes are unavailable on this platform",
    ))
}

/// The terminating signal of an exit status, when the platform reports one.
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

/// One live terminal command and everything keeping it alive.
struct TerminalEntry {
    child: Option<tokio::process::Child>,
    exit: Option<std::process::ExitStatus>,
    /// Keep the private temp dir (`HOME`/`TMPDIR`) alive while the command
    /// runs; dropping it removes the directory.
    #[allow(dead_code)]
    temp: tempfile::TempDir,
    /// Keep the read-only marker descriptor open for the reaper.
    #[allow(dead_code)]
    marker_file: std::fs::File,
    marker: crate::reaper::Marker,
    pid: u32,
    /// Start time of `pid` when the terminal was spawned; every kill is gated
    /// on this identity so a recycled pid is never signalled.
    start: Option<u64>,
    stdout: std::fs::File,
    stderr: std::fs::File,
    killed: bool,
}

impl TerminalEntry {
    fn poll_exit(&mut self) {
        if self.exit.is_none() {
            if let Some(child) = self.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    self.exit = Some(status);
                    self.child = None;
                }
            }
        }
    }

    /// Read the accumulated output (stdout then stderr), capped.
    fn read_output(&mut self, cap: usize) -> (String, bool) {
        let mut out = String::new();
        let mut truncated = false;
        for (label, file) in [("stdout", &mut self.stdout), ("stderr", &mut self.stderr)] {
            let (text, was_truncated) = read_capture(file, cap);
            if !text.is_empty() {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&format!("[terminal {label}]\n{text}"));
            }
            truncated |= was_truncated;
        }
        (out, truncated)
    }

    fn kill(&mut self) {
        if self.killed {
            return;
        }
        self.killed = true;
        if self
            .child
            .as_ref()
            .is_some_and(|child| child.id().is_some())
        {
            crate::reaper::terminate_group(self.pid, self.start);
            crate::reaper::kill_process_tree(Some(self.pid), self.start, &self.marker);
        } else {
            crate::reaper::kill_marker_holders(&self.marker);
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

impl Drop for TerminalEntry {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Fit one string field of a handler result so the whole response frame stays
/// under the connection's outbound cap **after JSON escaping**.
///
/// Control-heavy payloads grow up to ×6 (`\u0000`); the raw-byte read caps
/// are not frame caps. The kept head is truncated on a char boundary and
/// marked; `truncated` is set so the agent knows why.
fn fit_result_string(result: &mut Value, key: &str, frame_cap: usize) {
    const FRAME_OVERHEAD: usize = 256;
    let Ok(serialized) = serde_json::to_string(result) else {
        return;
    };
    let allowed = frame_cap.saturating_sub(FRAME_OVERHEAD);
    if serialized.len() <= allowed {
        return;
    }
    let Some(content) = result.get(key).and_then(Value::as_str).map(str::to_string) else {
        return;
    };
    let escaped_content = serde_json::to_string(&content)
        .map(|text| text.len())
        .unwrap_or(usize::MAX);
    let other_fields = serialized.len().saturating_sub(escaped_content);
    let allowed_content = allowed.saturating_sub(other_fields);
    let fitted = fit_json_string(&content, allowed_content);
    result[key] = Value::String(fitted);
    result["truncated"] = json!(true);
}

/// The largest char-boundary prefix of `content` (plus a truncation marker)
/// whose JSON-escaped form fits in `allowed_escaped` bytes.
fn fit_json_string(content: &str, allowed_escaped: usize) -> String {
    const MARKER: &str = "\n[response truncated]";
    let fits = |candidate: &str| {
        serde_json::to_string(candidate)
            .map(|text| text.len() <= allowed_escaped)
            .unwrap_or(false)
    };
    if fits(content) {
        return content.to_string();
    }
    // Halve the keep length until the marker-suffixed prefix fits; each step
    // strictly shrinks, so this always terminates.
    let mut keep = content.len();
    while keep > 0 {
        let mut end = keep;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }
        let candidate = format!("{}{MARKER}", &content[..end]);
        if fits(&candidate) {
            return candidate;
        }
        keep = end / 2;
    }
    MARKER.to_string()
}

/// Read a capture file from the start, bounded: head and tail, with an
/// explicit truncation marker between them.
fn read_capture(file: &mut std::fs::File, cap: usize) -> (String, bool) {
    if file.seek(SeekFrom::Start(0)).is_err() {
        return (String::new(), false);
    }
    let mut bytes = Vec::new();
    if file
        .take((cap.saturating_mul(2) + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return (String::new(), false);
    }
    let truncated = bytes.len() > cap;
    if truncated {
        let head = cap / 2;
        let tail = cap - head;
        let mut joined = bytes[..head].to_vec();
        joined.extend_from_slice(b"\n[output truncated]\n");
        joined.extend_from_slice(&bytes[bytes.len().saturating_sub(tail)..]);
        bytes = joined;
    }
    (String::from_utf8_lossy(&bytes).into_owned(), truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_broker::{Approver, ApproverError};
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    /// Canned approver: pops decisions in order, defaults to deny.
    #[derive(Default)]
    struct CannedApprover {
        decisions: StdMutex<VecDeque<bool>>,
        seen: StdMutex<Vec<ApprovalRequest>>,
    }

    impl CannedApprover {
        fn new(decisions: Vec<bool>) -> Self {
            Self {
                decisions: StdMutex::new(decisions.into()),
                seen: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Approver for CannedApprover {
        async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
            self.seen.lock().unwrap().push(request.clone());
            Ok(self.decisions.lock().unwrap().pop_front().unwrap_or(false))
        }
    }

    #[derive(Default)]
    struct FailingApprover;

    #[async_trait]
    impl Approver for FailingApprover {
        async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
            Err(ApproverError("boom".to_string()))
        }
    }

    struct Harness {
        #[allow(dead_code)]
        workspace: tempfile::TempDir,
        /// Canonical workspace path (macOS `/var` vs `/private/var`).
        root: PathBuf,
        handlers: BrokerHandlers,
    }

    fn harness(approver: Arc<dyn Approver>) -> Harness {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join("sub")).unwrap();
        let root = workspace.path().canonicalize().unwrap();
        let handlers = BrokerHandlers::new(
            root.clone(),
            "main".to_string(),
            approver,
            Arc::new(TurnState::default()),
            HandlerLimits::default(),
        )
        .unwrap();
        Harness {
            workspace,
            root,
            handlers,
        }
    }

    #[tokio::test]
    async fn fs_read_is_confined_to_the_workspace() {
        let h = harness(Arc::new(CannedApprover::default()));
        let inside = h.root.join("notes.txt");
        std::fs::write(&inside, "hello").unwrap();
        let result = h
            .handlers
            .handle(
                method::FS_READ_TEXT_FILE,
                &json!({"path": inside.display().to_string()}),
            )
            .await
            .unwrap();
        assert_eq!(result["content"], "hello");

        let outside = tempfile::NamedTempFile::new().unwrap();
        let err = h
            .handlers
            .handle(
                method::FS_READ_TEXT_FILE,
                &json!({"path": outside.path().display().to_string()}),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INVALID_PARAMS);

        // Relative paths are refused outright (ACP requires absolute).
        assert!(h
            .handlers
            .handle(method::FS_READ_TEXT_FILE, &json!({"path": "notes.txt"}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn fs_read_denies_a_symlink_escape() {
        let h = harness(Arc::new(CannedApprover::default()));
        let outside = tempfile::NamedTempFile::new().unwrap();
        let link = h.root.join("escape.txt");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let err = h
            .handlers
            .handle(
                method::FS_READ_TEXT_FILE,
                &json!({"path": link.display().to_string()}),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn fs_write_asks_and_never_writes_an_unapproved_file() {
        let approver: Arc<dyn Approver> = Arc::new(CannedApprover::new(vec![false]));
        let h = harness(approver);
        let target = h.root.join("denied.txt");
        let err = h
            .handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({"path": target.display().to_string(), "content": "nope"}),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INTERNAL_ERROR);
        assert!(!target.exists(), "a denied write must not touch the disk");

        // Approved writes land, and the approval saw the taint state.
        h.handlers.state.mark_tainted();
        let approver2: Arc<dyn Approver> = Arc::new(CannedApprover::new(vec![true]));
        let h2 = harness(approver2);
        h2.handlers.state.mark_tainted();
        let target = h2.root.join("sub/ok.txt");
        h2.handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({"path": target.display().to_string(), "content": "yes"}),
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "yes");
    }

    #[tokio::test]
    async fn fs_write_denies_escape_through_a_parent_directory_component() {
        let h = harness(Arc::new(CannedApprover::new(vec![true])));
        let escape = h.workspace.path().join("..").join("outside.txt");
        let err = h
            .handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({"path": escape.display().to_string(), "content": "x"}),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn approver_errors_fail_closed() {
        let h = harness(Arc::new(FailingApprover));
        let target = h.root.join("x.txt");
        let err = h
            .handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({"path": target.display().to_string(), "content": "x"}),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(err.code, code::INTERNAL_ERROR);
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn permission_maps_allow_and_reject_options() {
        let params = json!({
            "sessionId": "s",
            "toolCall": {"toolCallId": "t1", "title": "Run rm -rf", "kind": "execute"},
            "options": [
                {"optionId": "a1", "kind": "allow_once", "name": "Allow"},
                {"optionId": "a2", "kind": "allow_always", "name": "Always"},
                {"optionId": "r1", "kind": "reject_once", "name": "No"},
            ]
        });
        let h = harness(Arc::new(CannedApprover::new(vec![true])));
        let approved = h
            .handlers
            .handle(method::SESSION_REQUEST_PERMISSION, &params)
            .await
            .unwrap();
        assert_eq!(approved["outcome"]["outcome"], "selected");
        assert_eq!(approved["outcome"]["optionId"], "a1");

        let h = harness(Arc::new(CannedApprover::new(vec![false])));
        let denied = h
            .handlers
            .handle(method::SESSION_REQUEST_PERMISSION, &params)
            .await
            .unwrap();
        assert_eq!(denied["outcome"]["optionId"], "r1");

        // No matching option => cancelled (never invent an id).
        let weird = json!({"options": [{"optionId": "x", "kind": "other"}]});
        let h = harness(Arc::new(CannedApprover::new(vec![true])));
        let outcome = h
            .handlers
            .handle(method::SESSION_REQUEST_PERMISSION, &weird)
            .await
            .unwrap();
        assert_eq!(outcome["outcome"]["outcome"], "cancelled");
    }

    #[tokio::test]
    async fn permission_timeout_fails_closed() {
        struct SlowApprover;
        #[async_trait]
        impl Approver for SlowApprover {
            async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(true)
            }
        }
        let workspace = tempfile::tempdir().unwrap();
        let handlers = BrokerHandlers::new(
            workspace.path().to_path_buf(),
            "main".to_string(),
            Arc::new(SlowApprover),
            Arc::new(TurnState::default()),
            HandlerLimits {
                permission_timeout: Duration::from_millis(50),
                ..HandlerLimits::default()
            },
        )
        .unwrap();
        let params = json!({
            "toolCall": {"toolCallId": "t", "title": "x"},
            "options": [
                {"optionId": "a", "kind": "allow_once"},
                {"optionId": "r", "kind": "reject_once"}
            ]
        });
        let outcome = handlers
            .handle(method::SESSION_REQUEST_PERMISSION, &params)
            .await
            .unwrap();
        assert_eq!(outcome["outcome"]["optionId"], "r");
    }

    #[tokio::test]
    async fn cancelled_turn_answers_cancelled_immediately() {
        let h = harness(Arc::new(CannedApprover::new(vec![true])));
        h.handlers.state.cancel();
        let outcome = h
            .handlers
            .handle(
                method::SESSION_REQUEST_PERMISSION,
                &json!({"options": [{"optionId": "a", "kind": "allow_once"}]}),
            )
            .await
            .unwrap();
        assert_eq!(outcome["outcome"]["outcome"], "cancelled");
    }

    #[tokio::test]
    async fn unknown_methods_get_method_not_found() {
        let h = harness(Arc::new(CannedApprover::default()));
        let err = h
            .handlers
            .handle("future/method", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.code, code::METHOD_NOT_FOUND);
    }

    #[derive(Debug)]
    struct PassGate;

    impl HostGate for PassGate {
        fn tokenise(&self, _kind: HostText, text: &str) -> Result<String, String> {
            Ok(text.to_string())
        }

        fn reveal(&self, text: &str) -> String {
            text.to_string()
        }
    }

    /// Exit code of `sh -c "exit 3"` as the agent sees it, with or without a
    /// host gate (private mode).
    async fn exit_code_seen(gate: Option<Arc<dyn HostGate>>) -> Option<(Value, Value)> {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().canonicalize().unwrap();
        let handlers = BrokerHandlers::new(
            root,
            "main".to_string(),
            Arc::new(CannedApprover::new(vec![true, true])),
            Arc::new(TurnState::default()),
            HandlerLimits {
                host_gate: gate,
                ..HandlerLimits::default()
            },
        )
        .unwrap();
        if !handlers.limits.sandbox.available() {
            return None; // The sandboxed terminal path is macOS-only.
        }
        let created = handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({"command": "sh", "args": ["-c", "exit 3"]}),
            )
            .await
            .unwrap();
        let id = created["terminalId"].as_str().unwrap().to_string();
        let waited = handlers
            .handle(method::TERMINAL_WAIT_FOR_EXIT, &json!({"terminalId": id}))
            .await
            .unwrap();
        let output = handlers
            .handle(method::TERMINAL_OUTPUT, &json!({"terminalId": id}))
            .await
            .unwrap();
        Some((
            waited["exitCode"].clone(),
            output["exitStatus"]["exitCode"].clone(),
        ))
    }

    #[tokio::test]
    async fn a_private_terminal_hides_its_exit_code_from_the_agent() {
        let Some(open) = exit_code_seen(None).await else {
            return;
        };
        assert_eq!(open, (json!(3), json!(3)), "open mode reports the code");
        let private = exit_code_seen(Some(Arc::new(PassGate))).await.unwrap();
        assert_eq!(
            private,
            (Value::Null, Value::Null),
            "private: no yes/no channel about the real values"
        );
    }

    #[tokio::test]
    async fn terminal_create_output_wait_kill() {
        let h = harness(Arc::new(CannedApprover::default()));
        if !h.handlers.limits.sandbox.available() {
            return; // The sandboxed terminal path is macOS-only; CI Linux skips.
        }
        let created = h
            .handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({"command": "echo", "args": ["hello"]}),
            )
            .await
            .unwrap();
        let id = created["terminalId"].as_str().unwrap().to_string();
        let waited = h
            .handlers
            .handle(method::TERMINAL_WAIT_FOR_EXIT, &json!({"terminalId": id}))
            .await
            .unwrap();
        assert_eq!(waited["exitCode"], 0);
        let output = h
            .handlers
            .handle(method::TERMINAL_OUTPUT, &json!({"terminalId": id}))
            .await
            .unwrap();
        assert!(output["output"].as_str().unwrap().contains("hello"));
        h.handlers
            .handle(method::TERMINAL_RELEASE, &json!({"terminalId": id}))
            .await
            .unwrap();
        assert!(h
            .handlers
            .handle(method::TERMINAL_OUTPUT, &json!({"terminalId": id}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn terminal_kill_reaps_the_tree() {
        let h = harness(Arc::new(CannedApprover::default()));
        if !h.handlers.limits.sandbox.available() {
            return;
        }
        let created = h
            .handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({"command": "sh", "args": ["-c", "sleep 300 & echo $! > child.pid; wait"]}),
            )
            .await
            .unwrap();
        let id = created["terminalId"].as_str().unwrap().to_string();
        let mut child_pid = None;
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(h.root.join("child.pid")) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    child_pid = Some(pid);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let child_pid = child_pid.expect("terminal child pid");
        h.handlers
            .handle(method::TERMINAL_KILL, &json!({"terminalId": id}))
            .await
            .unwrap();
        let mut gone = false;
        for _ in 0..100 {
            if unsafe { libc::kill(child_pid, 0) } != 0 {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(gone, "terminal kill must reap the whole tree");
    }

    // ---- security-review 1 regressions ----

    /// The adversary: while the owner is deciding, swap the approved path for
    /// a symlink (final-component or parent-directory) pointing outside the
    /// workspace.
    enum Swap {
        FinalSymlink,
        ParentSymlink,
    }

    struct SwappingApprover {
        swap: Swap,
        target: PathBuf,
        replacement: PathBuf,
    }

    #[async_trait]
    impl Approver for SwappingApprover {
        async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
            match self.swap {
                Swap::FinalSymlink => {
                    let _ = std::fs::remove_file(&self.target);
                    std::os::unix::fs::symlink(&self.replacement, &self.target).unwrap();
                }
                Swap::ParentSymlink => {
                    let _ = std::fs::remove_dir_all(&self.target);
                    std::os::unix::fs::symlink(&self.replacement, &self.target).unwrap();
                }
            }
            Ok(true)
        }
    }

    fn harness_with(approver: Arc<dyn Approver>) -> Harness {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(workspace.path().join("sub")).unwrap();
        let root = workspace.path().canonicalize().unwrap();
        let handlers = BrokerHandlers::new(
            root.clone(),
            "main".to_string(),
            approver,
            Arc::new(TurnState::default()),
            HandlerLimits::default(),
        )
        .unwrap();
        Harness {
            workspace,
            root,
            handlers,
        }
    }

    #[tokio::test]
    async fn fs_write_rejects_a_final_symlink_swapped_during_approval() {
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("outside.txt");
        std::fs::write(&outside, "original").unwrap();
        let mut h = harness_with(Arc::new(CannedApprover::default()));
        let target = h.root.join("victim.txt");
        std::fs::write(&target, "original").unwrap();
        h.handlers = BrokerHandlers::new(
            h.root.clone(),
            "main".to_string(),
            Arc::new(SwappingApprover {
                swap: Swap::FinalSymlink,
                target: target.clone(),
                replacement: outside.clone(),
            }),
            Arc::new(TurnState::default()),
            HandlerLimits::default(),
        )
        .unwrap();
        let result = h
            .handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({"path": target.display().to_string(), "content": "PWNED-BY-AGENT"}),
            )
            .await;
        assert!(
            result.is_err(),
            "the write must fail when the path was swapped for a symlink"
        );
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "original",
            "the outside canary must never be written"
        );
    }

    #[tokio::test]
    async fn fs_write_rejects_a_parent_symlink_swapped_during_approval() {
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("outside.txt");
        std::fs::write(&outside, "original").unwrap();
        let mut h = harness_with(Arc::new(CannedApprover::default()));
        let parent = h.root.join("sub");
        let target = parent.join("victim.txt");
        std::fs::write(&target, "original").unwrap();
        h.handlers = BrokerHandlers::new(
            h.root.clone(),
            "main".to_string(),
            Arc::new(SwappingApprover {
                swap: Swap::ParentSymlink,
                target: parent.clone(),
                replacement: outside_dir.path().to_path_buf(),
            }),
            Arc::new(TurnState::default()),
            HandlerLimits::default(),
        )
        .unwrap();
        let result = h
            .handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({"path": target.display().to_string(), "content": "PWNED-BY-AGENT"}),
            )
            .await;
        assert!(
            result.is_err(),
            "the write must fail when an ancestor was swapped for a symlink"
        );
        assert_eq!(
            std::fs::read_to_string(&outside).unwrap(),
            "original",
            "the outside canary must never be written"
        );
    }

    #[tokio::test]
    async fn permission_before_any_update_is_tainted_and_never_allow_always() {
        let approver = Arc::new(CannedApprover::new(vec![true]));
        let h = harness_with(approver.clone());
        let params = json!({
            "toolCall": {"toolCallId": "t1", "title": "Delete", "kind": "edit"},
            "options": [{"optionId": "persistent", "kind": "allow_always"}]
        });
        let outcome = h
            .handlers
            .handle(method::SESSION_REQUEST_PERMISSION, &params)
            .await
            .unwrap();
        assert_eq!(
            outcome["outcome"]["outcome"], "cancelled",
            "an agent offering only allow_always must be answered cancelled"
        );
        let seen = approver.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].tainted,
            "a permission request before any update is untrusted"
        );
    }

    #[tokio::test]
    async fn terminal_create_refuses_the_unsandboxed_fallback() {
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("outside.txt");
        let missing_helper = "/nonexistent/sandbox-exec";
        for sandbox in [
            ShellSandbox::new(false, false, true).with_test_sandbox_exec(missing_helper),
            ShellSandbox::new(true, false, true).with_test_sandbox_exec(missing_helper),
        ] {
            let workspace = tempfile::tempdir().unwrap();
            let root = workspace.path().canonicalize().unwrap();
            let handlers = BrokerHandlers::new(
                root,
                "main".to_string(),
                Arc::new(CannedApprover::default()),
                Arc::new(TurnState::default()),
                HandlerLimits {
                    sandbox,
                    ..HandlerLimits::default()
                },
            )
            .unwrap();
            let err = handlers
                .handle(
                    method::TERMINAL_CREATE,
                    &json!({
                        "command": "sh",
                        "args": ["-c", format!("printf pwned > {}", shell_quote(&outside.display().to_string()))],
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, code::INTERNAL_ERROR, "{err:?}");
        }
        assert!(
            !outside.exists(),
            "no unsandboxed terminal may run without Seatbelt"
        );
    }

    #[tokio::test]
    async fn terminal_count_is_capped_per_turn() {
        let h = harness(Arc::new(CannedApprover::default()));
        if !h.handlers.limits.sandbox.available() {
            return;
        }
        for index in 0..4 {
            h.handlers
                .handle(
                    method::TERMINAL_CREATE,
                    &json!({"command": "sleep", "args": ["30"]}),
                )
                .await
                .unwrap_or_else(|err| panic!("terminal {index} must start: {err:?}"));
        }
        let err = h
            .handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({"command": "sleep", "args": ["30"]}),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INTERNAL_ERROR, "{err:?}");
        h.handlers.kill_all_terminals();
    }

    #[tokio::test]
    async fn terminal_capture_files_stay_under_the_read_cap() {
        let h = harness(Arc::new(CannedApprover::default()));
        if !h.handlers.limits.sandbox.available() {
            return;
        }
        let created = h
            .handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({"command": "head", "args": ["-c", "4194304", "/dev/zero"]}),
            )
            .await
            .unwrap();
        let id = created["terminalId"].as_str().unwrap().to_string();
        h.handlers
            .handle(method::TERMINAL_WAIT_FOR_EXIT, &json!({"terminalId": id}))
            .await
            .unwrap();
        let terminals = lock_terminals(&h.handlers.terminals);
        let entry = terminals.get(&id).expect("the terminal entry");
        let stdout_len = entry.stdout.metadata().unwrap().len();
        let stderr_len = entry.stderr.metadata().unwrap().len();
        drop(terminals);
        let cap = h.handlers.limits.max_terminal_bytes as u64;
        assert!(
            stdout_len <= cap && stderr_len <= cap,
            "capture files must stay under the {cap} byte cap: {stdout_len}/{stderr_len}"
        );
        h.handlers.kill_all_terminals();
    }

    fn frame_len(result: &Value) -> usize {
        serde_json::to_string(&json!({"jsonrpc": "2.0", "id": 1, "result": result}))
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn fs_read_control_heavy_result_fits_the_outbound_frame() {
        let h = harness(Arc::new(CannedApprover::default()));
        // 200 KiB of NULs: ~1.2 MiB once JSON-escaped.
        let binary = h.root.join("binary.bin");
        std::fs::write(&binary, vec![0u8; 200 * 1024]).unwrap();
        let result = h
            .handlers
            .handle(
                method::FS_READ_TEXT_FILE,
                &json!({"path": binary.display().to_string()}),
            )
            .await
            .unwrap();
        let cap = h.handlers.limits.rpc.max_frame_bytes;
        assert!(
            frame_len(&result) <= cap,
            "escaped frame {} exceeds the cap {cap}",
            frame_len(&result)
        );
        assert_eq!(result["truncated"], true);

        // Multibyte content: the truncation must land on a char boundary and
        // the frame must fit too. 600 KiB of 2-byte chars escapes to ~1.8 MB.
        let multibyte = h.root.join("multibyte.txt");
        let mut text = String::new();
        while text.len() < 600 * 1024 {
            text.push('é');
        }
        std::fs::write(&multibyte, text).unwrap();
        let result = h
            .handlers
            .handle(
                method::FS_READ_TEXT_FILE,
                &json!({"path": multibyte.display().to_string()}),
            )
            .await
            .unwrap();
        assert!(
            frame_len(&result) <= cap,
            "multibyte frame {} exceeds the cap {cap}",
            frame_len(&result)
        );
        let content = result["content"].as_str().unwrap();
        // The raw read cap (256 KiB) already bounds this content; whether the
        // frame needed the extra slice, no character may be split.
        assert!(
            content.chars().all(|ch| ch == 'é' || ch.is_ascii()),
            "truncation must not split a character"
        );
    }

    #[test]
    fn fit_json_string_keeps_char_boundaries_under_small_caps() {
        let multibyte = "é".repeat(1000);
        let fitted = fit_json_string(&multibyte, 100);
        assert!(fitted.contains("[response truncated]"), "{fitted}");
        assert!(
            serde_json::to_string(&fitted).unwrap().len() <= 100,
            "fitted string must stay under the escaped cap"
        );
        let control = "\0".repeat(1000);
        let fitted = fit_json_string(&control, 100);
        assert!(fitted.contains("[response truncated]"), "{fitted}");
        assert!(serde_json::to_string(&fitted).unwrap().len() <= 100);
        // A fitting string is returned unchanged.
        assert_eq!(fit_json_string("hello", 100), "hello");
    }

    #[tokio::test]
    async fn terminal_output_control_heavy_result_fits_the_outbound_frame() {
        let h = harness(Arc::new(CannedApprover::default()));
        if !h.handlers.limits.sandbox.available() {
            return;
        }
        let created = h
            .handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({"command": "head", "args": ["-c", "4194304", "/dev/zero"]}),
            )
            .await
            .unwrap();
        let id = created["terminalId"].as_str().unwrap().to_string();
        h.handlers
            .handle(method::TERMINAL_WAIT_FOR_EXIT, &json!({"terminalId": id}))
            .await
            .unwrap();
        let result = h
            .handlers
            .handle(method::TERMINAL_OUTPUT, &json!({"terminalId": id}))
            .await
            .unwrap();
        let cap = h.handlers.limits.rpc.max_frame_bytes;
        assert!(
            frame_len(&result) <= cap,
            "escaped frame {} exceeds the cap {cap}",
            frame_len(&result)
        );
        assert_eq!(result["truncated"], true);
        h.handlers.kill_all_terminals();
    }

    #[tokio::test]
    async fn terminal_env_carries_the_turn_marker() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().canonicalize().unwrap();
        let handlers = BrokerHandlers::new(
            root.clone(),
            "main".to_string(),
            Arc::new(CannedApprover::default()),
            Arc::new(TurnState::default()),
            HandlerLimits {
                turn_marker: "test-turn-marker-123".to_string(),
                ..HandlerLimits::default()
            },
        )
        .unwrap();
        if !handlers.limits.sandbox.available() {
            return;
        }
        handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({
                    "command": "sh",
                    "args": ["-c", "printf %s \"$AUXESIS_ACP_TURN\" > marker.txt"]
                }),
            )
            .await
            .unwrap();
        let mut marker = None;
        for _ in 0..100 {
            // The shell creates marker.txt before printf writes it: wait for content.
            if let Ok(text) = std::fs::read_to_string(root.join("marker.txt")) {
                if !text.is_empty() {
                    marker = Some(text);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            marker.as_deref(),
            Some("test-turn-marker-123"),
            "terminals must carry the per-turn marker"
        );
        handlers.kill_all_terminals();
    }

    /// Read-only handlers rooted at a fresh temp workspace.
    fn read_only_handlers() -> (tempfile::TempDir, PathBuf, BrokerHandlers) {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().canonicalize().unwrap();
        let handlers = BrokerHandlers::new(
            root.clone(),
            "main".to_string(),
            Arc::new(CannedApprover::new(vec![true])),
            Arc::new(TurnState::default()),
            HandlerLimits::default(),
        )
        .unwrap()
        .with_read_only(true);
        (workspace, root, handlers)
    }

    /// Security-review round 3, P1: a read-only ACP brain may not run a terminal,
    /// whatever the skill declares.
    #[tokio::test]
    async fn read_only_refuses_terminal_create_and_writes_no_marker() {
        let (_dir, root, handlers) = read_only_handlers();
        let marker = root.join("marker");
        let err = handlers
            .handle(
                method::TERMINAL_CREATE,
                &json!({
                    "sessionId": "s",
                    "command": "touch",
                    "args": [marker.display().to_string()],
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INVALID_REQUEST);
        assert!(err.message.contains("read-only"), "{}", err.message);
        assert!(!marker.exists(), "the terminal must not have run");
    }

    /// Security-review round 3, P1: a read-only ACP brain may not write a file.
    #[tokio::test]
    async fn read_only_refuses_fs_write_text_file() {
        let (_dir, root, handlers) = read_only_handlers();
        let target = root.join("written.txt");
        let err = handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({
                    "sessionId": "s",
                    "path": target.display().to_string(),
                    "content": "hello",
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, code::INVALID_REQUEST);
        assert!(err.message.contains("read-only"), "{}", err.message);
        assert!(!target.exists(), "the file must not have been written");
    }

    /// Read-only still allows a read inside the workspace.
    #[tokio::test]
    async fn read_only_still_allows_fs_read_text_file() {
        let (_dir, root, handlers) = read_only_handlers();
        std::fs::write(root.join("read.txt"), "hello").unwrap();
        let ok = handlers
            .handle(
                method::FS_READ_TEXT_FILE,
                &json!({
                    "sessionId": "s",
                    "path": root.join("read.txt").display().to_string(),
                }),
            )
            .await
            .unwrap();
        assert_eq!(ok["content"], "hello");
    }

    /// The coding-agent mode keeps its current behaviour: writes still work.
    #[tokio::test]
    async fn coding_mode_still_writes_a_file() {
        let h = harness(Arc::new(CannedApprover::new(vec![true])));
        let target = h.root.join("written.txt");
        h.handlers
            .handle(
                method::FS_WRITE_TEXT_FILE,
                &json!({
                    "sessionId": "s",
                    "path": target.display().to_string(),
                    "content": "hello",
                }),
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello");
    }
}
