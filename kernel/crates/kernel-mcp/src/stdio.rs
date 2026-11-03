//! stdio transport for a locally launched MCP server (M2.6 P1).
//!
//! Spawns one pinned command and speaks newline-delimited JSON-RPC 2.0 over
//! its stdin/stdout. A single bounded-channel writer owns stdin and completes
//! every accepted frame independently of caller cancellation. This is the
//! transport seam P1 adds; the broker and the
//! agent tools are deliberately **not** wired to it yet.
//!
//! # No shell, no inherited environment, no PATH lookup
//!
//! [`StdioCommand`] is the whole launch configuration: an **explicit** program
//! path, verbatim arguments and a small environment allowlist. The transport
//! never calls `sh -c`; it `execve`s the program directly, so an argument such
//! as `; rm -rf /` is passed as one literal byte string. A bare program name
//! (no path separator) is refused at construction, so nothing is resolved
//! through an implicit `PATH`. The child environment is `env_clear()`ed and
//! only allowlisted keys ([`ALLOWED_ENV_KEYS`]) are set from the spec: the
//! app's full environment, its API keys and its `AUXESIS_*` variables never
//! reach the child.
//!
//! # Bounds fail closed and stop the process
//!
//! Four bounds are enforced, and crossing any of them is terminal
//! ([`McpError::requires_connection_close`]) — the process is killed and
//! reaped, never resumed:
//!
//! * one frame (one newline-delimited line) is capped at
//!   [`StdioLimits::max_frame_bytes`];
//! * the accumulated stdout of the whole session is capped at
//!   [`StdioLimits::max_output_bytes`];
//! * a request has [`StdioLimits::request_timeout`] to answer;
//! * at most [`StdioLimits::max_inflight`] requests may be unanswered.
//!
//! # Lifecycle
//!
//! The process is spawned lazily on the first round trip, so `initialize` is
//! naturally the first frame. [`StdioTransport::shutdown`] closes stdin first
//! (EOF is the polite stop), then gives the child
//! [`StdioLimits::shutdown_grace`] to exit before it is killed; the reader
//! task always reaps the child. [`Drop`] closes stdin, wakes the reader and
//! lets it run the same terminal path, so no orphan and no zombie survives the
//! transport. Only the reader signals the process group, keeping the leader
//! unreaped across both signals so its pid/pgid cannot be recycled meanwhile.
//!
//! # Correlation is race-free
//!
//! A request's waiter is registered **before** its bytes are written and the
//! id is allocated monotonically and never reused, so a server that answers
//! immediately can never lose its response or have it delivered to another
//! caller. A response whose id matches no live waiter is rejected and counted.
//!
//! # Secrets never reach an error or a log
//!
//! Nothing here logs. [`StdioCommand`]'s `Debug` prints the program, the
//! **number** of arguments and the environment **keys** only — never an
//! argument value and never an environment value (a spec may carry a runtime
//! token). Server output is untrusted: callers mark it with
//! [`crate::tools::UNTRUSTED_MCP_TAG`] before it reaches a model.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Map, Value};
use std::os::unix::process::CommandExt;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, watch, Notify, Semaphore};

use crate::error::{McpError, INVALID_REQUEST, PARSE_ERROR};
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::limits::{
    check_limit, check_timeout, Limits, DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_INFLIGHT,
};
use crate::Transport;

/// The mandatory macOS Seatbelt wrapper for a stdio child.
///
/// Re-exported so a caller of [`StdioTransport::new`] can name the required
/// argument without depending on `kernel-broker` directly.
pub use kernel_broker::sandbox::StdioSandbox;

/// Largest accepted accumulated stdout for one session: 64 MiB.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
/// Largest accepted accumulated-output bound: 4 GiB.
pub const MAX_OUTPUT_BYTES_CEILING: usize = 4 * 1024 * 1024 * 1024;
/// Default per-request budget for a stdio round trip.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default time the child has to honour stdin EOF before it is killed.
pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
/// Largest accepted number of pinned arguments.
pub const MAX_ARGS: usize = 1024;
/// Largest accepted number of pinned environment entries.
pub const MAX_ENV_ENTRIES: usize = 64;
/// Absolute cap on unanswered calls, independent of caller-supplied limits.
pub const MAX_PENDING_REQUESTS: usize = 64;

/// The only environment keys a [`StdioCommand`] may set.
///
/// The list is closed on purpose: a config (or, later, a plugin manifest)
/// cannot smuggle `AUX_KEY_*`, `AUXESIS_*` or a session credential into a local
/// server by naming it. `PATH` is deliberately absent: it changes executable
/// resolution, so neither the inherited environment nor a config may set it
/// (see [`env_key_declared`]). `HOME` is deliberately absent too: the
/// child environment must never be pointed at the owner's home by this
/// transport, and the workspace invariant forbids naming it outside the
/// gateway.
pub const ALLOWED_ENV_KEYS: &[&str] = &["LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TMPDIR", "TZ"];

/// Whether `key` may be copied into a child environment.
pub fn env_key_allowed(key: &str) -> bool {
    ALLOWED_ENV_KEYS.contains(&key)
}

/// Environment prefixes a user-declared secret name may never use.
///
/// Those names belong to Auxesis' own credential store (`AUX_KEY_*` provider
/// keys, `AUX_TELEGRAM_BOT_TOKEN`, ...). A configured MCP server may ask for
/// its own vendor key (for example `DATAGOUV_KEY`) but never for one of ours.
pub const RESERVED_ENV_PREFIXES: [&str; 2] = ["AUX_", "AUXESIS_"];

/// Names that steer the loader, the shell, an interpreter at start-up, or the
/// container CLI itself. A configured server may never declare one: its value
/// would change what runs or which daemon/socket a container talks to.
pub const DENIED_ENV_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "TMPDIR",
    "NODE_OPTIONS",
    "NODE_PATH",
    "BASH_ENV",
    "ENV",
    "IFS",
    "SHELLOPTS",
    "BASHOPTS",
    "ZDOTDIR",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5OPT",
    "PERL5LIB",
    "JAVA_TOOL_OPTIONS",
    "JAVA_OPTS",
    "JDK_JAVA_OPTIONS",
    "LUA_INIT",
    "LUA_PATH",
    "LUA_CPATH",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_EXTERNAL_DIFF",
    // Build- and runtime-hook names: they run another program around the one
    // the owner reviewed (`rustc`, javac's JVM, the Python debugger) or change
    // glibc's charset conversion module search path.
    "RUSTC_WRAPPER",
    "GCONV_PATH",
    "PYTHONBREAKPOINT",
    // Container-CLI steering: these retarget the daemon, socket, config or
    // trust material a `docker`/`podman`/`nerdctl` launch talks to.
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "PODMAN_HOST",
    "CONTAINERS_CONF",
    "BUILDKIT_HOST",
];
/// Loader prefixes (`DYLD_*` on macOS, `LD_*` on Linux), the container-CLI
/// steering namespaces (`CONTAINERD_*`, `DOCKER_*`, `CONTAINER*_`, `PODMAN_*`,
/// `NERDCTL_*`, `BUILDKIT_*`, `REGISTRY_*`), the git config/transport
/// namespace (`GIT_CONFIG_*`) and the XDG user/base-dir controls a configured
/// server may never declare.
///
/// Every comparison in [`env_key_declared`] is case-insensitive, so
/// `docker_host` is refused exactly like `DOCKER_HOST`.
pub const DENIED_ENV_PREFIXES: &[&str] = &[
    "DYLD_",
    "LD_",
    "DOCKER_",
    "CONTAINER_",
    "CONTAINERS_",
    "CONTAINERD_",
    "PODMAN_",
    "NERDCTL_",
    "BUILDKIT_",
    "REGISTRY_",
    "GIT_CONFIG_",
    "XDG_",
];

/// Whether `key` is a syntactically valid user-declared env name that is not
/// reserved to Auxesis itself nor a loader, start-up or container-steering
/// control name.
///
/// The name syntax keeps its original case, but every reserved/denied
/// comparison folds case, so a lowercase spelling cannot slip past.
pub fn env_key_declared(key: &str) -> bool {
    let bytes = key.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    if !valid {
        return false;
    }
    let upper = key.to_ascii_uppercase();
    !RESERVED_ENV_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
        && !DENIED_ENV_NAMES.contains(&upper.as_str())
        && !DENIED_ENV_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
}

/// The pinned launch configuration: program, arguments, environment.
///
/// Built once and immutable during a session. Values may carry runtime secrets
/// (an injected token is the documented path for MCP auth), so the type's
/// `Debug` never prints an argument or an environment value.
#[derive(Clone)]
pub struct StdioCommand {
    program: PathBuf,
    args: Vec<OsString>,
    env: BTreeMap<&'static str, OsString>,
    /// User-declared secret names from `mcp.toml` (`env = [...]`), resolved
    /// from `~/.auxesis/.env` by the caller. Kept separate from the fixed
    /// allowlist so the reserved-prefix rule is a structural property, not a
    /// naming convention.
    declared_env: BTreeMap<String, OsString>,
}

impl StdioCommand {
    /// Pin `program` as the executable.
    ///
    /// `program` must name a path (absolute or containing a separator); a bare
    /// name is refused so the OS never resolves it through an implicit `PATH`.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, McpError> {
        let program = program.into();
        if !is_explicit_program(&program) {
            return Err(McpError::InvalidCommand {
                reason: "program must be an explicit path, not a bare name resolved through PATH",
            });
        }
        Ok(Self {
            program,
            args: Vec::new(),
            env: BTreeMap::new(),
            declared_env: BTreeMap::new(),
        })
    }

    /// Append one argument, passed to the child verbatim.
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append several arguments, passed to the child verbatim.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set one environment variable, but only from [`ALLOWED_ENV_KEYS`].
    ///
    /// A non-allowlisted key is refused with a secret-free error: the key and
    /// the value are never echoed.
    pub fn env(mut self, key: &str, value: impl Into<OsString>) -> Result<Self, McpError> {
        let Some(allowed) = ALLOWED_ENV_KEYS.iter().find(|allowed| **allowed == key) else {
            return Err(McpError::InvalidCommand {
                reason: "environment key is not in the allowlist",
            });
        };
        self.env.insert(allowed, value.into());
        Ok(self)
    }

    /// Set one **user-declared** secret variable resolved from
    /// `~/.auxesis/.env`.
    ///
    /// The name must be a valid shell identifier and must not use a reserved
    /// Auxesis prefix ([`RESERVED_ENV_PREFIXES`]). A refused key returns a
    /// secret-free error: neither the key nor the value is echoed past this
    /// point, and `Debug` still prints keys only.
    pub fn env_declared(mut self, key: &str, value: impl Into<OsString>) -> Result<Self, McpError> {
        if !env_key_declared(key) {
            return Err(McpError::InvalidCommand {
                reason: "declared environment key is invalid or reserved",
            });
        }
        self.declared_env.insert(key.to_owned(), value.into());
        Ok(self)
    }

    /// The pinned program path.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The pinned arguments (never logged).
    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }

    /// The pinned environment keys (never the values).
    pub fn env_keys(&self) -> impl Iterator<Item = &str> + '_ {
        self.env
            .keys()
            .copied()
            .chain(self.declared_env.keys().map(String::as_str))
    }

    /// Reject a configuration the OS would refuse or that crosses a cap.
    fn validate(&self) -> Result<(), McpError> {
        if !is_explicit_program(&self.program) {
            return Err(McpError::InvalidCommand {
                reason: "program must be an explicit path, not a bare name resolved through PATH",
            });
        }
        if self.args.len() > MAX_ARGS {
            return Err(McpError::InvalidCommand {
                reason: "too many pinned arguments",
            });
        }
        if self.env.len() + self.declared_env.len() > MAX_ENV_ENTRIES {
            return Err(McpError::InvalidCommand {
                reason: "too many pinned environment variables",
            });
        }
        if self.declared_env.keys().any(|key| !env_key_declared(key)) {
            return Err(McpError::InvalidCommand {
                reason: "declared environment key is invalid or reserved",
            });
        }
        if has_nul(self.program.as_os_str()) || self.args.iter().any(|arg| has_nul(arg)) {
            return Err(McpError::InvalidCommand {
                reason: "program or arguments contain a NUL byte",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for StdioCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the argument values (they may carry a token) and never the
        // environment values (an injected secret) — keys and counts only.
        f.debug_struct("StdioCommand")
            .field("program", &self.program)
            .field("arguments", &format_args!("<{} pinned>", self.args.len()))
            .field("env_keys", &self.env_keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Hard bounds and budgets for one stdio session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioLimits {
    /// Largest accepted single line (frame), in bytes.
    pub max_frame_bytes: usize,
    /// Largest accepted accumulated stdout over the whole session, in bytes.
    pub max_output_bytes: usize,
    /// Most requests that may be unanswered at once.
    pub max_inflight: usize,
    /// Budget for one request/notification frame write + answer.
    pub request_timeout: Duration,
    /// Time the child has to exit after stdin closes, before it is killed.
    pub shutdown_grace: Duration,
}

impl Default for StdioLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

impl StdioLimits {
    /// A deliberately tiny preset for tests.
    pub fn tiny() -> Self {
        Self {
            max_frame_bytes: 256,
            max_output_bytes: 4 * 1024,
            max_inflight: 1,
            request_timeout: Duration::from_millis(200),
            shutdown_grace: Duration::from_millis(500),
        }
    }

    /// Reject a zero or absurd bound before a process is ever spawned.
    pub fn validate(&self) -> Result<(), McpError> {
        check_limit(
            "max_frame_bytes",
            self.max_frame_bytes,
            Limits::MAX_FRAME_BYTES_CEILING,
        )?;
        check_limit(
            "max_output_bytes",
            self.max_output_bytes,
            MAX_OUTPUT_BYTES_CEILING,
        )?;
        check_limit(
            "max_inflight",
            self.max_inflight,
            Limits::MAX_INFLIGHT_CEILING,
        )?;
        check_timeout("request_timeout", self.request_timeout)?;
        check_timeout("shutdown_grace", self.shutdown_grace)?;
        Ok(())
    }
}

/// One complete, newline-terminated frame accepted by the sole stdin writer.
struct WriteFrame {
    bytes: Vec<u8>,
    budget: Duration,
    complete: oneshot::Sender<Result<(), McpError>>,
}

/// One running stdio session. The writer task exclusively owns child stdin.
struct Conn {
    writer: mpsc::Sender<WriteFrame>,
    writer_task: tokio::task::JoinHandle<()>,
    reader: tokio::task::JoinHandle<()>,
}

/// State shared between the transport and its reader task.
struct Shared {
    /// In-flight requests, keyed by their JSON-RPC id.
    ///
    /// The entry is installed **before** the request is written, so a server
    /// that answers immediately can never race ahead of the correlation table:
    /// the reader either finds the waiter or rejects the id as unknown, but a
    /// response can never be lost or handed to another caller.
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<JsonRpcResponse, McpError>>>>,
    next_id: AtomicU64,
    unsolicited: AtomicUsize,
    pgid: AtomicUsize,
    /// At most `max_inflight` unanswered requests.
    inflight: Semaphore,
    /// Set once the process is gone or a bound has failed the session.
    dead: AtomicBool,
    /// Total stdout bytes read over the session.
    output_bytes: AtomicUsize,
    /// Signals the reader to kill the child now.
    kill: Notify,
    /// The reaped exit state, sent once (see [`Exit`]).
    exit: watch::Sender<Exit>,
}

/// Removes a correlation entry on every exit path, including future drop.
struct PendingGuard {
    shared: Arc<Shared>,
    id: u64,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        lock(&self.shared.pending).remove(&self.id);
    }
}

/// How the reader task ended for the child process.
///
/// The watch channel starts at [`Exit::Running`], so a waiter can always tell
/// "not yet" from "the reap itself failed" without a second flag or a race.
#[derive(Debug, Clone)]
enum Exit {
    /// The child has not been reaped yet.
    Running,
    /// The reader killed the child but `wait` failed.
    Failed,
    /// The reaped status.
    Reaped(std::process::ExitStatus),
}

/// A stdio transport for one pinned local MCP server.
pub struct StdioTransport {
    command: StdioCommand,
    limits: StdioLimits,
    /// When set, the child is spawned under the macOS Seatbelt profile shared
    /// with the shell tool (item 3): `~/.auxesis` and the store are denied, and
    /// network is allowed only when the server declared it. [`StdioTransport::new`]
    /// always sets it; only the crate-private `new_unsandboxed` leaves it empty.
    sandbox: Option<StdioSandbox>,
    shared: Arc<Shared>,
    started: tokio::sync::Mutex<Option<Conn>>,
}

impl StdioTransport {
    /// Build a sandboxed transport over a validated pinned command.
    ///
    /// The Seatbelt wrapper is a **required** argument: no public constructor
    /// skips it, so another crate cannot reach the spawn path without a sandbox
    /// profile. On a host without Seatbelt the wrapper is inert, which is a
    /// platform property (`cfg(not(target_os = "macos"))`), never a caller
    /// switch; the daemon ships macOS only, and its launch path refuses a macOS
    /// spawn whose `sandbox-exec` is missing instead of dropping the profile.
    ///
    /// No process is spawned yet: the first [`Transport::round_trip`] starts it,
    /// so `initialize` is naturally the first frame on the wire.
    ///
    /// # The unsandboxed constructor is not public
    ///
    /// [`StdioTransport::new_unsandboxed`] is `pub(crate)`, so a downstream
    /// crate cannot call it:
    ///
    /// ```compile_fail
    /// # use kernel_mcp::{StdioCommand, StdioLimits, StdioTransport};
    /// let command = StdioCommand::new("/usr/bin/true").expect("absolute path");
    /// // error[E0624]: associated function `new_unsandboxed` is private
    /// let _ = StdioTransport::new_unsandboxed(command, StdioLimits::default());
    /// ```
    pub fn new(
        command: StdioCommand,
        limits: StdioLimits,
        sandbox: StdioSandbox,
    ) -> Result<Self, McpError> {
        let mut transport = Self::new_unsandboxed(command, limits)?;
        transport.sandbox = Some(sandbox);
        Ok(transport)
    }

    /// Build the raw transport with no sandbox profile.
    ///
    /// `pub(crate)` on purpose: this is the only unsandboxed constructor, and it
    /// must never be reachable from another crate. Integration tests outside
    /// this module use the `test-util`-gated [`StdioTransport::new_for_tests`]
    /// alias, which a production build (the app's daemon and CLI) never compiles.
    pub(crate) fn new_unsandboxed(
        command: StdioCommand,
        limits: StdioLimits,
    ) -> Result<Self, McpError> {
        command.validate()?;
        limits.validate()?;
        let (exit, _receiver) = watch::channel(Exit::Running);
        Ok(Self {
            command,
            limits,
            sandbox: None,
            shared: Arc::new(Shared {
                pending: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
                unsolicited: AtomicUsize::new(0),
                pgid: AtomicUsize::new(0),
                inflight: Semaphore::new(limits.max_inflight.min(MAX_PENDING_REQUESTS)),
                dead: AtomicBool::new(false),
                output_bytes: AtomicUsize::new(0),
                kill: Notify::new(),
                exit,
            }),
            started: tokio::sync::Mutex::new(None),
        })
    }

    /// Build an unsandboxed transport for this crate's own integration tests.
    ///
    /// Compiled only with the `test-util` feature, which kernel-mcp's own
    /// `[dev-dependencies]` enables and **no** production crate (the app's daemon and CLI)
    /// does. The public constructor [`StdioTransport::new`] still requires a
    /// [`StdioSandbox`] in every build.
    #[cfg(feature = "test-util")]
    pub fn new_for_tests(command: StdioCommand, limits: StdioLimits) -> Result<Self, McpError> {
        Self::new_unsandboxed(command, limits)
    }

    /// The pinned command.
    pub fn command(&self) -> &StdioCommand {
        &self.command
    }

    /// Test-only: whether this transport was built with a Seatbelt sandbox.
    ///
    /// Used by the spawn-path acceptance test; it is not part of the public API
    /// and never influences the spawn.
    #[cfg(test)]
    pub(crate) fn has_sandbox(&self) -> bool {
        self.sandbox.is_some()
    }

    /// The session bounds.
    pub fn limits(&self) -> &StdioLimits {
        &self.limits
    }

    /// Whether a bound has failed the session or the process has exited.
    pub fn is_dead(&self) -> bool {
        self.shared.dead.load(Ordering::SeqCst)
    }

    /// Spawn the child if it is not running yet.
    pub async fn start(&self) -> Result<(), McpError> {
        self.ensure_started().await
    }

    /// Wait until the reader has reaped the child.
    ///
    /// Returns [`McpError::Timeout`] if the child is still running after
    /// `timeout`; that is a test/diagnostic helper, not a normal path.
    pub async fn wait_exit(&self, timeout: Duration) -> Result<std::process::ExitStatus, McpError> {
        // Subscribe before the first read: a `watch` receiver sees every value
        // sent after it exists, so an exit landing between the reads is never
        // missed (unlike a one-shot `notify_waiters`, which has no permit).
        let mut exit = self.shared.exit.subscribe();
        match exit.borrow_and_update().clone() {
            Exit::Reaped(status) => return Ok(status),
            Exit::Failed => return Err(McpError::ProcessGone),
            Exit::Running => {}
        }
        tokio::time::timeout(timeout, exit.changed())
            .await
            .map_err(|_| McpError::Timeout)?
            .map_err(|_| McpError::ProcessGone)?;
        let state = exit.borrow_and_update().clone();
        match state {
            Exit::Reaped(status) => Ok(status),
            // A terminal state other than a status means the reap itself failed.
            Exit::Failed | Exit::Running => Err(McpError::ProcessGone),
        }
    }

    /// Stop the child: close stdin, then kill after the grace period.
    ///
    /// Idempotent. The reader task always reaps the child, so no zombie is
    /// left behind; a transport dropped without this call is killed by
    /// [`Drop`].
    pub async fn shutdown(&self) -> Result<(), McpError> {
        let conn = self.started.lock().await.take();
        let Some(conn) = conn else {
            return Ok(());
        };
        // Close the writer channel: it drains accepted complete frames, then
        // drops stdin so EOF is the polite stop.
        drop(conn.writer);
        if self.wait_exit(self.limits.shutdown_grace).await.is_err() {
            self.shared.kill.notify_one();
            let _ = self.wait_exit(self.limits.shutdown_grace).await;
        }
        let _ = tokio::time::timeout(self.limits.shutdown_grace, conn.writer_task).await;
        // Let the reader finish reaping; it owns the `Child`.
        let _ = tokio::time::timeout(self.limits.shutdown_grace, conn.reader).await;
        Ok(())
    }

    /// Spawn the pinned command exactly once.
    async fn ensure_started(&self) -> Result<(), McpError> {
        let mut guard = self.started.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        if self.shared.dead.load(Ordering::SeqCst) {
            return Err(McpError::ProcessGone);
        }
        let mut command = match &self.sandbox {
            Some(sandbox) => sandbox.command(self.command.program(), &self.command.args),
            None => {
                let mut command = Command::new(self.command.program());
                command.args(&self.command.args);
                command
            }
        };
        command
            // Protocol on stdin/stdout; stderr is discarded so a chatty server
            // can never leak a secret into an Auxesis log and can never
            // deadlock on a full stderr pipe.
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .env_clear()
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        if let Some(sandbox) = &self.sandbox {
            command
                .env("HOME", sandbox.temp_path())
                .env("TMPDIR", sandbox.temp_path());
        }
        for (key, value) in &self.command.env {
            command.env(key, value);
        }
        for (key, value) in &self.command.declared_env {
            command.env(key, value);
        }
        let mut child = command
            .spawn()
            .map_err(|err| McpError::Io { kind: err.kind() })?;
        if let Some(pid) = child.id() {
            self.shared.pgid.store(pid as usize, Ordering::SeqCst);
        }
        let stdin = child.stdin.take().ok_or(McpError::ProcessGone)?;
        let stdout = child.stdout.take().ok_or(McpError::ProcessGone)?;
        let shared = Arc::clone(&self.shared);
        let limits = self.limits;
        let reader = tokio::spawn(read_loop(child, stdout, shared, limits));
        let (writer, receiver) = mpsc::channel(self.limits.max_inflight.min(MAX_PENDING_REQUESTS));
        let writer_task = tokio::spawn(write_loop(stdin, receiver, Arc::clone(&self.shared)));
        *guard = Some(Conn {
            writer,
            writer_task,
            reader,
        });
        Ok(())
    }

    /// Submit one complete frame. After channel acceptance, the sole writer
    /// owns it until fully written or terminally failed, regardless of whether
    /// this caller is cancelled.
    async fn write_frame(&self, line: &[u8], budget: Duration) -> Result<(), McpError> {
        let writer = self
            .started
            .lock()
            .await
            .as_ref()
            .map(|conn| conn.writer.clone())
            .ok_or(McpError::ProcessGone)?;
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line);
        bytes.push(b'\n');
        let (complete, written) = oneshot::channel();
        match tokio::time::timeout(
            budget,
            writer.send(WriteFrame {
                bytes,
                budget,
                complete,
            }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(McpError::ProcessGone),
            Err(_) => {
                self.mark_dead_and_stop().await;
                return Err(McpError::Timeout);
            }
        }
        match tokio::time::timeout(budget, written).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(McpError::ProcessGone),
            Err(_) => {
                self.mark_dead_and_stop().await;
                Err(McpError::Timeout)
            }
        }
    }

    /// Mark the session dead, signal a kill and wait (bounded) for the reap.
    async fn mark_dead_and_stop(&self) {
        self.shared.dead.store(true, Ordering::SeqCst);
        self.shared.kill.notify_one();
        if matches!(*self.shared.exit.borrow(), Exit::Running) {
            let _ = self.wait_exit(self.limits.shutdown_grace).await;
        }
    }
}

/// Sole owner of stdin. Once it dequeues a frame, it either writes the whole
/// frame or kills the session; it never advances to a later frame after a
/// partial write.
async fn write_loop(
    mut stdin: ChildStdin,
    mut frames: mpsc::Receiver<WriteFrame>,
    shared: Arc<Shared>,
) {
    while let Some(frame) = frames.recv().await {
        let outcome = tokio::time::timeout(frame.budget, async {
            stdin.write_all(&frame.bytes).await?;
            stdin.flush().await
        })
        .await;
        let result = match outcome {
            Ok(Ok(())) => Ok(()),
            // EPIPE means the child closed stdin before the frame landed: the
            // request never reached the server. A deliberate stop (an in-flight
            // bound or a kill) races exactly here, so report the honest "the
            // process is gone" rather than an opaque io failure.
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                Err(McpError::ProcessGone)
            }
            Ok(Err(error)) => Err(McpError::Io { kind: error.kind() }),
            Err(_) => Err(McpError::Timeout),
        };
        if result.is_err() {
            shared.dead.store(true, Ordering::SeqCst);
            shared.kill.notify_one();
        }
        let failed = result.is_err();
        let _ = frame.complete.send(result);
        if failed {
            break;
        }
    }
    // `stdin` is dropped here. When the sender channel was closed this is EOF;
    // on failure the child is already on the reader's terminal kill path.
}

impl fmt::Debug for StdioTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The command's own `Debug` already redacts argument and env values.
        f.debug_struct("StdioTransport")
            .field("command", &self.command)
            .field("limits", &self.limits)
            .field("dead", &self.is_dead())
            .finish()
    }
}

#[async_trait]
impl Transport for StdioTransport {
    async fn stop(&self) {
        // Close stdin, then kill after the grace period; the reader reaps it.
        let _ = self.shutdown().await;
    }

    async fn round_trip(
        &self,
        req: JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, McpError> {
        // The effective budget never exceeds the configured one.
        let budget = timeout.min(self.limits.request_timeout);
        let deadline = tokio::time::Instant::now() + budget;
        self.ensure_started().await?;
        if self.shared.dead.load(Ordering::SeqCst) {
            return Err(McpError::ProcessGone);
        }

        let mut req = req;
        req.id = self
            .shared
            .next_id
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |id| id.checked_add(1))
            .map_err(|_| McpError::ProcessGone)?;
        let is_notification = req.method.starts_with("notifications/");
        let line = encode(&req, is_notification)?;
        if line.len() > self.limits.max_frame_bytes {
            // A frame bound is terminal: stop the process rather than leave a
            // half-used pipe the next caller could reason about.
            self.mark_dead_and_stop().await;
            return Err(McpError::FrameTooLarge {
                limit: self.limits.max_frame_bytes,
                seen: line.len(),
            });
        }

        if is_notification {
            // A notification has no answer: write it and report success.
            self.write_frame(
                &line,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await?;
            return Ok(JsonRpcResponse::success(req.id, Value::Null));
        }

        // Fail closed on the in-flight cap: queueing would let a caller build
        // an unbounded backlog against a stuck server.
        let permit = match self.shared.inflight.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                self.mark_dead_and_stop().await;
                return Err(McpError::TooManyInflight {
                    limit: self.limits.max_inflight.min(MAX_PENDING_REQUESTS),
                });
            }
        };

        let (tx, rx) = oneshot::channel();
        // Install the waiter *before* the request bytes leave, so an answer
        // that arrives while the write is still in flight (or immediately
        // after) always finds its correlation entry. Ids are monotonically
        // allocated and never reused, so an existing key here is a bug, not a
        // normal collision.
        let collision = {
            let mut pending = lock(&self.shared.pending);
            match pending.entry(req.id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(tx);
                    false
                }
                std::collections::hash_map::Entry::Occupied(_) => true,
            }
        };
        if collision {
            self.mark_dead_and_stop().await;
            drop(permit);
            return Err(McpError::ProcessGone);
        }
        let _pending = PendingGuard {
            shared: Arc::clone(&self.shared),
            id: req.id,
        };
        if let Err(err) = self
            .write_frame(
                &line,
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            )
            .await
        {
            // The frame never fully reached the server: drop the waiter so a
            // later response for this id is rejected as unknown.
            drop(permit);
            return Err(err);
        }

        let outcome = tokio::time::timeout_at(deadline, rx).await;
        drop(permit);
        match outcome {
            Ok(Ok(Ok(response))) => Ok(response),
            Ok(Ok(Err(err))) => Err(err),
            Ok(Err(_recv)) => Err(McpError::ProcessGone),
            Err(_) => {
                self.mark_dead_and_stop().await;
                Err(McpError::Timeout)
            }
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        // No orphan, ever. Flip the flag and wake the reader; the reader owns
        // the `Child` and is the only place that may signal the process group.
        // It keeps the leader unreaped across both signals; Drop never signals
        // by number because a reaped pid/pgid may already have been recycled.
        self.shared.dead.store(true, Ordering::SeqCst);
        self.shared.kill.notify_one();
        let conn = self
            .started
            .try_lock()
            .ok()
            .and_then(|mut guard| guard.take());
        if let Some(conn) = conn {
            // Closing stdin is the polite stop: EOF lets a cooperative server
            // exit on its own before the reader's grace period expires.
            drop(conn.writer);
            drop(conn.writer_task);
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                // Let the reader run its terminal path (ordered group kills,
                // then reap). The await is moved off `Drop` because `Drop`
                // cannot block.
                runtime.spawn(async move {
                    let _ = conn.reader.await;
                });
            } else {
                // Detach rather than abort: if the original runtime is still
                // driving tasks on another thread, the reader remains the sole
                // owner of the child and will signal/reap it there.
                drop(conn.reader);
            }
        }
    }
}

/// Encode one JSON-RPC envelope as a single line.
///
/// A notification omits the `id` member (JSON-RPC 2.0) and omits empty params.
fn encode(req: &JsonRpcRequest, is_notification: bool) -> Result<Vec<u8>, McpError> {
    if is_notification {
        let mut envelope = Map::new();
        envelope.insert("jsonrpc".to_owned(), Value::String(req.jsonrpc.to_owned()));
        envelope.insert("method".to_owned(), Value::String(req.method.clone()));
        if req
            .params
            .as_object()
            .is_none_or(|params| !params.is_empty())
        {
            envelope.insert("params".to_owned(), req.params.clone());
        }
        serde_json::to_vec(&Value::Object(envelope))
            .map_err(|_| McpError::protocol(INVALID_REQUEST, "could not encode request"))
    } else {
        serde_json::to_vec(req)
            .map_err(|_| McpError::protocol(INVALID_REQUEST, "could not encode request"))
    }
}

/// The reader task: bounded frames in, correlated answers out, child reaped.
async fn read_loop(child: Child, stdout: ChildStdout, shared: Arc<Shared>, limits: StdioLimits) {
    let mut child = child;
    let mut reader = BufReader::new(stdout);
    let failure = loop {
        tokio::select! {
            _ = shared.kill.notified() => break None,
            frame = read_frame(&mut reader, &limits, &shared) => match frame {
                Ok(Some(line)) => {
                    if let Err(err) = dispatch(&line, &shared) {
                        break Some(err);
                    }
                }
                Ok(None) => break None, // EOF: the server closed stdout
                Err(err) => break Some(err),
            },
        }
    };
    // Terminal for every exit path: stop and reap, then fail any waiter with
    // the precise reason (never let a caller hang on a dead pipe).
    //
    // Keep the leader unreaped across both group signals. A zombie pins its pid
    // (and therefore pgid), so the number cannot be recycled between SIGTERM
    // and SIGKILL. This task is the sole owner of the Child and its reap.
    let pgid = shared.pgid.load(Ordering::SeqCst);
    if pgid != 0 && child_is_unreaped(pgid as libc::pid_t) {
        signal_group(pgid as libc::pid_t, libc::SIGTERM);
        let still_owned = wait_for_leader_exit(pgid as libc::pid_t, limits.shutdown_grace).await;
        if still_owned {
            // Unconditional with respect to leader state: waitid used WNOWAIT,
            // so even an exited leader is still an unreaped zombie pinning pgid.
            signal_group(pgid as libc::pid_t, libc::SIGKILL);
        }
    }
    let status = child.wait().await.ok();
    shared.dead.store(true, Ordering::SeqCst);
    let err = failure.unwrap_or(McpError::ProcessGone);
    fail_pending(&shared, err);
    // `send_replace`, not `send`: the transport may hold the only sender and a
    // `send` with zero receivers would drop the terminal state, leaving a
    // later `wait_exit` waiting forever. `send_replace` always stores it.
    let _ = shared.exit.send_replace(match status {
        Some(status) => Exit::Reaped(status),
        None => Exit::Failed,
    });
}

/// Read one bounded, newline-terminated frame.
///
/// The aggregate counter advances on every byte **consumed** from the server,
/// so a server that answers with a stream of small valid lines is still stopped
/// and no byte is ever counted twice as it lingers in the read buffer.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    limits: &StdioLimits,
    shared: &Shared,
) -> Result<Option<Vec<u8>>, McpError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|err| McpError::Io { kind: err.kind() })?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Ok(Some(trim_eol(line)));
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(position) => {
                if line.len() + position > limits.max_frame_bytes {
                    return Err(McpError::FrameTooLarge {
                        limit: limits.max_frame_bytes,
                        seen: line.len() + position,
                    });
                }
                // Count the whole frame, terminator included, before consuming.
                check_output(shared, limits, position + 1)?;
                line.extend_from_slice(&available[..position]);
                reader.consume(position + 1);
                return Ok(Some(trim_eol(line)));
            }
            None => {
                let len = available.len();
                if line.len() + len > limits.max_frame_bytes {
                    return Err(McpError::FrameTooLarge {
                        limit: limits.max_frame_bytes,
                        seen: line.len() + len,
                    });
                }
                check_output(shared, limits, len)?;
                line.extend_from_slice(available);
                reader.consume(len);
            }
        }
    }
}

/// Advance the session's accumulated-output counter, refusing a crossing.
fn check_output(shared: &Shared, limits: &StdioLimits, consumed: usize) -> Result<(), McpError> {
    let seen = shared.output_bytes.fetch_add(consumed, Ordering::SeqCst) + consumed;
    if seen > limits.max_output_bytes {
        return Err(McpError::OutputTooLarge {
            limit: limits.max_output_bytes,
            seen,
        });
    }
    Ok(())
}

/// Route one decoded line to the waiter with the matching request id.
///
/// A line that is not valid JSON is terminal (a stdio server must never write
/// anything but protocol to stdout). A server notification or a server→client
/// request is ignored: this client advertises no capability to answer one, and
/// ignoring it can never misattribute an answer.
fn dispatch(line: &[u8], shared: &Shared) -> Result<(), McpError> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let value: Value = serde_json::from_slice(line)
        .map_err(|_| McpError::protocol(PARSE_ERROR, "invalid JSON from mcp server"))?;
    if value.get("method").is_some() {
        return Ok(());
    }
    let response: JsonRpcResponse = serde_json::from_value(value)
        .map_err(|_| McpError::protocol(PARSE_ERROR, "invalid JSON-RPC from mcp server"))?;
    let Some(id) = response.id.as_number() else {
        if shared.unsolicited.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
            return Err(McpError::protocol(
                INVALID_REQUEST,
                "too many unsolicited mcp responses",
            ));
        }
        return Ok(());
    };
    if let Some(sender) = lock(&shared.pending).remove(&id) {
        let _ = sender.send(Ok(response));
    } else if shared.unsolicited.fetch_add(1, Ordering::SeqCst) + 1 >= 3 {
        // An id that matches no waiter is rejected and counted, never handed
        // to another caller.
        return Err(McpError::protocol(
            INVALID_REQUEST,
            "too many unsolicited mcp responses",
        ));
    }
    Ok(())
}

/// Fail every unanswered request with `err` (dropping a sender does the same,
/// but this keeps the precise reason).
fn fail_pending(shared: &Shared, err: McpError) {
    let drained: Vec<_> = lock(&shared.pending).drain().map(|(_, tx)| tx).collect();
    for sender in drained {
        let _ = sender.send(Err(err.clone()));
    }
}

/// Strip one trailing CR from an already newline-stripped frame.
fn trim_eol(mut line: Vec<u8>) -> Vec<u8> {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    line
}

/// A program must name an explicit path; a bare name means an implicit PATH.
fn is_explicit_program(program: &Path) -> bool {
    let raw = program.as_os_str();
    if raw.is_empty() {
        return false;
    }
    program.is_absolute() || raw.to_string_lossy().contains(std::path::MAIN_SEPARATOR)
}

/// Whether an OS string contains a NUL (which `execve` cannot accept).
fn has_nul(value: &OsStr) -> bool {
    value.to_string_lossy().contains('\0')
}

/// Lock without letting a poisoned mutex poison the transport.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Probe exit without reaping the leader (`WNOWAIT` keeps its pid/pgid pinned).
/// `Some(true)` means exited but still waitable, `Some(false)` means running,
/// and `None` means ownership cannot be established (including ECHILD).
fn waitid_observation(pid: libc::pid_t) -> Option<bool> {
    loop {
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `info` is a valid writable siginfo_t, and waitid receives only
        // scalar identifiers/flags. WNOWAIT explicitly leaves the child waitable.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: si_pid is read only after waitid initialised `info`.
            return Some(unsafe { info.si_pid() != 0 });
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return None;
        }
    }
}

fn child_is_unreaped(pid: libc::pid_t) -> bool {
    waitid_observation(pid).is_some()
}

/// Return false only if another path has already reaped (or ownership cannot
/// safely be established); otherwise wait up to `grace` without consuming exit.
async fn wait_for_leader_exit(pid: libc::pid_t, grace: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        match waitid_observation(pid) {
            Some(true) => return true,
            Some(false) => {}
            None => return false,
        }
        if tokio::time::Instant::now() >= deadline {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Signal a process group whose leader is still owned and unreaped by the
/// reader. Its zombie pid prevents group-id recycling until the later wait.
fn signal_group(pgid: libc::pid_t, signal: i32) {
    // SAFETY: negative pid selects the pinned child process group; no pointers
    // are passed, and the sole Child owner does not reap until after SIGKILL.
    unsafe {
        libc::kill(-pgid, signal);
    }
}

#[cfg(test)]
mod correlation_tests {
    use super::*;

    fn test_shared() -> Shared {
        let (exit, _rx) = watch::channel(Exit::Running);
        Shared {
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            unsolicited: AtomicUsize::new(0),
            pgid: AtomicUsize::new(0),
            inflight: Semaphore::new(1),
            dead: AtomicBool::new(false),
            output_bytes: AtomicUsize::new(0),
            kill: Notify::new(),
            exit,
        }
    }

    #[test]
    fn a_delivered_response_reaches_only_its_registered_waiter() {
        let shared = test_shared();
        let (tx, mut rx) = oneshot::channel();
        lock(&shared.pending).insert(9, tx);
        let response = br#"{"jsonrpc":"2.0","id":9,"result":{"ok":true}}"#;
        assert!(dispatch(response, &shared).is_ok());
        let delivered = rx.try_recv().expect("waiter was not served");
        assert!(delivered.is_ok());
        assert_eq!(shared.unsolicited.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unknown_response_id_is_counted_and_never_delivered() {
        let shared = test_shared();
        let (tx, mut rx) = oneshot::channel();
        lock(&shared.pending).insert(9, tx);
        // A response for an id no one is waiting on must not go to id 9.
        let response = br#"{"jsonrpc":"2.0","id":10,"result":{}}"#;
        assert!(dispatch(response, &shared).is_ok());
        assert_eq!(shared.unsolicited.load(Ordering::SeqCst), 1);
        assert!(lock(&shared.pending).contains_key(&9));
        assert!(
            rx.try_recv().is_err(),
            "a foreign response was misdelivered"
        );
    }

    #[tokio::test]
    async fn waitid_keeps_the_group_leader_unreaped_until_signalling_finishes() {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sleep 30")
            .stdout(std::process::Stdio::null());
        command.as_std_mut().process_group(0);
        let mut child = command.spawn().expect("spawn probe child");
        let pgid = child.id().expect("pid") as usize;
        assert!(child_is_unreaped(pgid as libc::pid_t));
        signal_group(pgid as libc::pid_t, libc::SIGTERM);
        assert!(wait_for_leader_exit(pgid as libc::pid_t, Duration::from_secs(2)).await);
        assert!(
            child_is_unreaped(pgid as libc::pid_t),
            "leader was reaped early"
        );
        signal_group(pgid as libc::pid_t, libc::SIGKILL);
        let _ = child.wait().await;

        let mut exited = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn exiting child");
        let pgid = exited.id().expect("pid") as usize;
        assert!(child_is_unreaped(pgid as libc::pid_t));
        let status = exited.wait().await.expect("reap");
        assert!(status.success());
        // Once reaped, waitid reports ECHILD and no caller may signal the pgid.
        assert!(!child_is_unreaped(pgid as libc::pid_t));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ten_thousand_cancelled_calls_leave_no_pending_entries() {
        let command = StdioCommand::new("/bin/sh")
            .expect("explicit path")
            .args(["-c", "while IFS= read -r line; do :; done"]);
        let transport =
            Arc::new(StdioTransport::new_unsandboxed(command, StdioLimits::default()).unwrap());
        transport.start().await.expect("start silent server");

        for id in 0..10_000 {
            let task_transport = Arc::clone(&transport);
            let task = tokio::spawn(async move {
                task_transport
                    .round_trip(
                        JsonRpcRequest::new(0, "tools/list", Value::Null),
                        Duration::from_secs(30),
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while lock(&transport.shared.pending).is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("request {id} was never registered"));
            task.abort();
            let _ = task.await;
            assert!(
                lock(&transport.shared.pending).is_empty(),
                "pending entry leaked after cancellation {id}"
            );
        }
        transport.shutdown().await.expect("shutdown silent server");
    }
}
