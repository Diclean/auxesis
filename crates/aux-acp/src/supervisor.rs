//! The ACP agent process supervisor.
//!
//! Spawns the agent with:
//!
//! - a **scrubbed environment** (`env_clear` + a fixed allowlist): no
//!   `AUX_KEY_*`, no `AUXESIS_*`, no inherited keys or paths;
//! - a **private `HOME`/`TMPDIR`** inside the per-agent scratch workspace, the
//!   process cwd;
//! - a deny-by-default **Seatbelt profile** reusing
//!   [`kernel_broker::sandbox::seatbelt_profile`] (network on: the agent must
//!   reach its vendor API; everything else stays closed), optionally with one
//!   read-only vendor data dir so a CLI login works without us ever reading
//!   the credentials;
//! - **no stdin from the terminal**, `setsid()` (own session and process
//!   group) and a read-only marker descriptor so the reaper can find every
//!   descendant, including double-fork + `setsid()` orphans;
//! - **scrubbed stderr**: captured under a size cap and run through the shared
//!   scrubber before it is stored or logged.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kernel_broker::sandbox::{self, ShellSandbox, SANDBOX_PATH};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};

use crate::error::AcpError;
use crate::reaper::{self, Marker};

/// Default kill grace: how long SIGTERM gets before the tree is SIGKILLed.
pub const DEFAULT_KILL_GRACE: Duration = Duration::from_secs(5);

/// Default stderr capture budget per agent process.
pub const DEFAULT_STDERR_CAP_BYTES: usize = 64 * 1024;

/// Default stderr line budget.
pub const DEFAULT_STDERR_MAX_LINES: usize = 200;

/// How to spawn one ACP agent process.
#[derive(Debug, Clone)]
pub struct SupervisorSpec {
    /// Executable (name resolved on the sandbox PATH, or an absolute path).
    pub command: String,
    /// Arguments passed verbatim.
    pub args: Vec<String>,
    /// Per-agent scratch workspace (created if missing); the process cwd.
    pub workspace: PathBuf,
    /// Private mode: the real workspace the host serves the agent through its
    /// fs/terminal handlers. `workspace` is then a neutral, empty directory and
    /// the only place the agent's own sandbox lets it read or write.
    pub host_workspace: Option<PathBuf>,
    /// Read-only vendor data dir exposed to the child (validated and
    /// canonicalised here). `None` = the real home stays unreadable.
    pub vendor_data_read: Option<PathBuf>,
    /// Extra environment variables (name, value) copied into the child.
    pub env_passthrough: Vec<(String, String)>,
    /// Sandbox settings; ACP always runs with the network enabled (the agent
    /// must reach its vendor API).
    pub sandbox: ShellSandbox,
    /// Test seam: the "real home" whose sensitive paths the profile denies.
    /// `None` reads the process `$HOME`.
    pub sandbox_home: Option<PathBuf>,
    /// Per-turn random marker injected as `AUXESIS_ACP_TURN`: the anchor the
    /// reaper uses to find children that closed every fd and left the
    /// workspace (empty disables the sweep).
    pub turn_marker: String,
    /// `RLIMIT_CPU` seconds for the agent (0 = `kill_grace`-padded timeout is
    /// used by the caller).
    pub max_cpu_seconds: u64,
    /// `RLIMIT_FSIZE` for every file the agent writes.
    pub max_file_bytes: u64,
    /// `RLIMIT_NOFILE` for the agent.
    pub max_open_files: u64,
    /// Extra processes the agent may create above the current user count
    /// (`RLIMIT_NPROC` headroom; 0 disables the limit).
    pub max_processes: u64,
    /// Best-effort `RLIMIT_AS`/`RLIMIT_DATA` for the agent (0 disables).
    pub max_memory_bytes: u64,
    /// SIGTERM grace before SIGKILL.
    pub kill_grace: Duration,
    /// Stderr capture budget, in bytes.
    pub stderr_cap_bytes: usize,
    /// Stderr line budget.
    pub stderr_max_lines: usize,
}

impl SupervisorSpec {
    /// A spec with safe defaults for `command` in `workspace`.
    pub fn new(command: impl Into<String>, workspace: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            workspace: workspace.into(),
            host_workspace: None,
            vendor_data_read: None,
            env_passthrough: Vec::new(),
            sandbox: ShellSandbox::default(),
            sandbox_home: None,
            turn_marker: reaper::new_turn_marker(),
            max_cpu_seconds: 0,
            max_file_bytes: DEFAULT_AGENT_MAX_FILE_BYTES,
            max_open_files: DEFAULT_AGENT_MAX_OPEN_FILES,
            max_processes: DEFAULT_AGENT_MAX_PROCESSES,
            max_memory_bytes: DEFAULT_AGENT_MAX_MEMORY_BYTES,
            kill_grace: DEFAULT_KILL_GRACE,
            stderr_cap_bytes: DEFAULT_STDERR_CAP_BYTES,
            stderr_max_lines: DEFAULT_STDERR_MAX_LINES,
        }
    }
}

/// Default `RLIMIT_FSIZE` for the agent (same 1 GiB as the shell tool).
pub const DEFAULT_AGENT_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

/// Default `RLIMIT_NOFILE` for the agent.
pub const DEFAULT_AGENT_MAX_OPEN_FILES: u64 = 4096;

/// Default extra processes above the current user count (`RLIMIT_NPROC`).
pub const DEFAULT_AGENT_MAX_PROCESSES: u64 = 64;

/// Default best-effort memory cap for the agent (8 GiB).
pub const DEFAULT_AGENT_MAX_MEMORY_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Fallback CPU-seconds cap when the caller sets none (default turn timeout
/// plus a grace).
pub const DEFAULT_AGENT_CPU_SECONDS: u64 = 630;

/// Best-effort resource caps for the agent (and everything it forks).
#[cfg(unix)]
fn set_agent_limits(
    cpu_seconds: u64,
    max_file_bytes: u64,
    max_open_files: u64,
    nproc: u64,
    max_memory_bytes: u64,
) {
    let limit = |value: u64| libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_CPU, &limit(cpu_seconds));
        libc::setrlimit(libc::RLIMIT_FSIZE, &limit(max_file_bytes));
        libc::setrlimit(libc::RLIMIT_NOFILE, &limit(max_open_files));
        if nproc > 0 {
            libc::setrlimit(libc::RLIMIT_NPROC, &limit(nproc));
        }
        if max_memory_bytes > 0 {
            // Best effort: Linux enforces the address-space cap; macOS
            // rejects AS (EINVAL) and may accept DATA.
            libc::setrlimit(libc::RLIMIT_AS, &limit(max_memory_bytes));
            libc::setrlimit(libc::RLIMIT_DATA, &limit(max_memory_bytes));
        }
    }
}

/// A live agent process.
pub struct AgentProcess {
    child: Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<ChildStdout>,
    pid: u32,
    marker: Marker,
    marker_file: std::fs::File,
    /// The agent's start time, so no kill can land on a recycled pid.
    start: Option<u64>,
    /// The per-turn environment marker the agent (and its terminals) carry.
    turn_marker: String,
    /// Sampled descendants, so a reparented `setsid()` grandchild is still
    /// killed by pid.
    tracker: reaper::TreeTracker,
    stderr_log: Arc<Mutex<StderrLog>>,
    stderr_task: tokio::task::JoinHandle<()>,
    kill_grace: Duration,
    armed: bool,
}

/// Bounded, scrubbed stderr ring.
#[derive(Debug)]
struct StderrLog {
    lines: std::collections::VecDeque<String>,
    bytes: usize,
    max_bytes: usize,
    max_lines: usize,
    truncated: bool,
}

impl StderrLog {
    fn new(max_bytes: usize, max_lines: usize) -> Self {
        Self {
            lines: std::collections::VecDeque::new(),
            bytes: 0,
            max_bytes: max_bytes.max(1024),
            max_lines: max_lines.max(1),
            truncated: false,
        }
    }

    fn push(&mut self, line: String) {
        self.bytes = self.bytes.saturating_add(line.len());
        self.lines.push_back(line);
        while self.bytes > self.max_bytes || self.lines.len() > self.max_lines {
            match self.lines.pop_front() {
                Some(dropped) => {
                    self.bytes = self.bytes.saturating_sub(dropped.len());
                    self.truncated = true;
                }
                None => break,
            }
        }
    }
}

/// Scrub one stderr line through the shared scrubber before it is stored or
/// logged: pattern-based secrets first, then every registered known value.
fn scrub_stderr_line(line: &str) -> String {
    crate::scrub::scrub_agent_text(line)
}

impl AgentProcess {
    /// Spawn the agent under the sandbox with the private environment.
    pub async fn spawn(spec: &SupervisorSpec) -> Result<Self, AcpError> {
        if spec.command.trim().is_empty() {
            return Err(AcpError::Config("agent command is empty".to_string()));
        }
        // Fail closed: ACP never runs unsandboxed unless the caller explicitly
        // opted in (tests on platforms without `sandbox-exec`).
        let workspace = std::fs::canonicalize(&spec.workspace).map_err(|err| {
            AcpError::Sandbox(format!(
                "workspace {} is not usable: {err}",
                spec.workspace.display()
            ))
        })?;
        if workspace == Path::new("/") || !workspace.is_dir() {
            return Err(AcpError::Sandbox(format!(
                "workspace {} is not a directory",
                workspace.display()
            )));
        }
        let private_home = workspace.join(".acp-home");
        let private_tmp = workspace.join(".acp-tmp");
        for dir in [&private_home, &private_tmp] {
            std::fs::create_dir_all(dir)?;
            set_private_dir(dir)?;
        }

        let real_home = spec
            .sandbox_home
            .clone()
            .or_else(kernel_core::real_user_home);
        let real_home = real_home.and_then(|home| home.canonicalize().ok());
        let vendor = match &spec.vendor_data_read {
            Some(dir) => Some(validate_vendor_dir(dir, real_home.as_deref())?),
            None => None,
        };
        let command_dir = match command_directory(&spec.command)? {
            Some(dir) => Some(validate_read_dir(
                &dir,
                real_home.as_deref(),
                "agent program dir",
            )?),
            None => None,
        };

        // Private mode: the agent may only read the host workspace through the
        // gated fs handlers. A read grant (its program dir or vendor data) that
        // contains or sits inside that workspace would hand it the raw files.
        if let Some(host) = &spec.host_workspace {
            let host = host.canonicalize().unwrap_or_else(|_| host.clone());
            for granted in [command_dir.as_deref(), vendor.as_deref()]
                .into_iter()
                .flatten()
            {
                if host.starts_with(granted) || granted.starts_with(&host) {
                    return Err(AcpError::Config(format!(
                        "{} overlaps the workspace; private mode refuses to start the agent",
                        granted.display()
                    )));
                }
            }
        }

        let use_sandbox = if !spec.sandbox.enabled {
            if !spec.sandbox.allow_unsandboxed {
                return Err(AcpError::Sandbox(
                    "the ACP sandbox is disabled and unsandboxed runs are not opted in".to_string(),
                ));
            }
            tracing::error!(
                workspace = %workspace.display(),
                "acp: sandbox disabled; running the agent UNSANDBOXED (tests/opt-in only)"
            );
            false
        } else if spec.sandbox.available() {
            true
        } else if spec.sandbox.allow_unsandboxed {
            tracing::error!(
                workspace = %workspace.display(),
                "acp: sandbox-exec unavailable; running the agent UNSANDBOXED (opt-in)"
            );
            false
        } else {
            return Err(AcpError::Sandbox(
                "sandbox-exec is unavailable; refusing to run the ACP agent unsandboxed \
                 (set shell.allow_unsandboxed only if you accept the risk)"
                    .to_string(),
            ));
        };

        let marker_file = tempfile::tempfile_in(&private_tmp)?;
        let marker = Marker::from_file(&marker_file)?;

        let command_args: Vec<String> = spec.args.clone();
        let mut command = if use_sandbox {
            let profile = build_profile(
                &workspace,
                &private_home,
                real_home.as_deref(),
                vendor.as_deref(),
                command_dir.as_deref(),
            )?;
            let mut command = Command::new(spec.sandbox.sandbox_exec());
            command.arg("-p").arg(profile).arg(&spec.command);
            command
        } else {
            Command::new(&spec.command)
        };
        command
            .args(&command_args)
            .current_dir(&workspace)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        scrub_environment(&mut command, &private_home, &private_tmp, vendor.as_deref());
        for (name, value) in &spec.env_passthrough {
            if crate::config::env_name_forbidden(name) {
                return Err(AcpError::Config(format!(
                    "refusing to forward environment variable `{name}` to the agent"
                )));
            }
            command.env(name, value);
        }
        // Per-turn environment marker: the reaper's env-anchored sweep finds
        // descendants that closed every fd and left the workspace.
        command.env(reaper::TURN_MARKER_ENV, &spec.turn_marker);

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            use std::os::unix::process::CommandExt;
            let marker_fd = marker_file.as_raw_fd();
            let cpu_seconds = if spec.max_cpu_seconds > 0 {
                spec.max_cpu_seconds
            } else {
                DEFAULT_AGENT_CPU_SECONDS
            };
            let max_file_bytes = spec.max_file_bytes;
            let max_open_files = spec.max_open_files;
            // `RLIMIT_NPROC` is a per-user total on macOS: add the configured
            // headroom to the count observed now. Computed in the parent; the
            // child between fork and exec must stay allocation-free.
            let nproc = if spec.max_processes > 0 {
                reaper::user_process_count().saturating_add(spec.max_processes)
            } else {
                0
            };
            let max_memory_bytes = spec.max_memory_bytes;
            let std_cmd = command.as_std_mut();
            unsafe {
                std_cmd.pre_exec(move || {
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    reaper::mark_inherited_fds_close_on_exec(marker_fd);
                    set_agent_limits(
                        cpu_seconds,
                        max_file_bytes,
                        max_open_files,
                        nproc,
                        max_memory_bytes,
                    );
                    Ok(())
                });
            }
        }

        let mut child = command.spawn().map_err(AcpError::Spawn)?;
        let pid = child.id().ok_or_else(|| {
            AcpError::Spawn(std::io::Error::other(
                "the spawned agent has no pid (already reaped?)",
            ))
        })?;
        // Record the agent's start time: every later signal is gated on this
        // identity, so a pid the OS recycles can never be killed through it.
        let start = reaper::PidIdentity::of(pid as i32).map(|identity| identity.start);
        // Sample the tree while it exists: by kill time a reparented
        // grandchild may be unreachable by ppid/session/marker.
        let tracker = reaper::TreeTracker::start(pid);
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr_task = match child.stderr.take() {
            Some(stderr) => {
                let log = Arc::new(Mutex::new(StderrLog::new(
                    spec.stderr_cap_bytes,
                    spec.stderr_max_lines,
                )));
                let task = tokio::spawn(read_stderr(stderr, Arc::clone(&log)));
                (log, task)
            }
            None => (
                Arc::new(Mutex::new(StderrLog::new(
                    spec.stderr_cap_bytes,
                    spec.stderr_max_lines,
                ))),
                tokio::spawn(async {}),
            ),
        };
        Ok(Self {
            child,
            stdin,
            stdout,
            pid,
            marker,
            marker_file,
            start,
            turn_marker: spec.turn_marker.clone(),
            tracker,
            stderr_log: stderr_task.0,
            stderr_task: stderr_task.1,
            kill_grace: spec.kill_grace,
            armed: true,
        })
    }

    /// Take the stdio halves for the JSON-RPC connection.
    pub fn take_stdio(
        &mut self,
    ) -> Result<(tokio::process::ChildStdin, tokio::process::ChildStdout), AcpError> {
        match (self.stdin.take(), self.stdout.take()) {
            (Some(stdin), Some(stdout)) => Ok((stdin, stdout)),
            _ => Err(AcpError::Protocol(
                "agent stdio was already taken".to_string(),
            )),
        }
    }

    /// The agent's pid (also its process-group id: it calls `setsid()`).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// A snapshot of the scrubbed stderr ring (oldest first).
    pub fn stderr_lines(&self) -> Vec<String> {
        lock_log(&self.stderr_log).lines.iter().cloned().collect()
    }

    /// True when the direct child has not exited yet.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// SIGTERM the group, wait up to `grace`, then SIGKILL the whole tree.
    ///
    /// Always sweeps, even when the direct child already exited: an ACP turn
    /// is one-shot, so any process still holding the marker is a leak and
    /// must not outlive the turn (double-fork + `setsid()` orphans included).
    pub async fn shutdown(&mut self) {
        if self.is_running() {
            reaper::terminate_group(self.pid, self.start);
            let grace = self.kill_grace;
            let _ = tokio::time::timeout(grace, self.child.wait()).await;
        } else {
            // Let a just-exited child's orphans reparent before the sweep.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.kill_now();
        // Let the stderr reader drain the last bytes, bounded.
        let task = std::mem::replace(&mut self.stderr_task, tokio::spawn(async {}));
        let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
    }

    /// SIGKILL the whole process tree immediately.
    pub fn kill_now(&mut self) {
        if !self.armed {
            return;
        }
        // Enumerate what is still attached *before* killing, then add the
        // sampled identities (reparented `setsid()` orphans; each is
        // start-time checked again at kill), then the env-anchored sweep for
        // children that closed every fd and left the workspace. A child that
        // also scrubs its own environment is the documented residual (bounded
        // by RLIMIT_NPROC and the session/group sweeps).
        if self.child.id().is_some() {
            reaper::kill_process_tree(Some(self.pid), self.start, &self.marker);
        } else {
            // `try_wait`/`wait` reaped the root, so its former pgid may have
            // been reused. Only marker-owned processes remain safe to sweep.
            reaper::kill_marker_holders(&self.marker);
        }
        reaper::kill_tracked(&self.tracker.identities());
        reaper::kill_marked_processes(&self.turn_marker, self.start.unwrap_or(0));
        let _ = self.child.start_kill();
        self.armed = false;
    }

    /// Keep the marker file alive for the lifetime of the process guard.
    pub fn marker_file(&self) -> &std::fs::File {
        &self.marker_file
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        // A dropped supervisor (cancelled turn, error path) must not leave the
        // agent tree behind.
        self.kill_now();
        self.stderr_task.abort();
    }
}

fn lock_log(log: &Mutex<StderrLog>) -> std::sync::MutexGuard<'_, StderrLog> {
    log.lock().unwrap_or_else(|err| err.into_inner())
}

async fn read_stderr<R: tokio::io::AsyncRead + Unpin>(reader: R, log: Arc<Mutex<StderrLog>>) {
    let mut reader = BufReader::new(reader);
    let mut line: Vec<u8> = Vec::new();
    const MAX_LINE: usize = 64 * 1024;
    loop {
        line.clear();
        let mut too_long = false;
        let mut eof = false;
        // Bounded line read: never buffer more than MAX_LINE bytes, and skip
        // the rest of an over-long line without allocating for it.
        loop {
            let available = match reader.fill_buf().await {
                Ok(available) => available,
                Err(_) => return,
            };
            if available.is_empty() {
                eof = true;
                break;
            }
            match available.iter().position(|byte| *byte == b'\n') {
                Some(position) => {
                    if !too_long {
                        if line.len().saturating_add(position) <= MAX_LINE {
                            line.extend_from_slice(&available[..position]);
                        } else {
                            too_long = true;
                        }
                    }
                    reader.consume(position + 1);
                    break;
                }
                None => {
                    let length = available.len();
                    if !too_long {
                        if line.len().saturating_add(length) <= MAX_LINE {
                            line.extend_from_slice(available);
                        } else {
                            too_long = true;
                        }
                    }
                    reader.consume(length);
                }
            }
        }
        if eof && line.is_empty() && !too_long {
            return;
        }
        let text = String::from_utf8_lossy(&line);
        let scrubbed = scrub_stderr_line(text.trim_end_matches(['\n', '\r']));
        if !scrubbed.is_empty() {
            tracing::debug!(line = %scrubbed, "acp agent stderr");
            let stored = if too_long {
                format!("{scrubbed} [truncated]")
            } else {
                scrubbed
            };
            lock_log(&log).push(stored);
        }
        if eof {
            return;
        }
    }
}

fn set_private_dir(dir: &Path) -> Result<(), AcpError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let _ = dir;
    Ok(())
}

/// The minimal environment the agent runs with: never inherited.
fn scrub_environment(
    command: &mut Command,
    private_home: &Path,
    private_tmp: &Path,
    vendor: Option<&Path>,
) {
    command.env_clear();
    for key in ["LANG", "LC_ALL", "LC_CTYPE", "TERM"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("PATH", SANDBOX_PATH)
        .env("HOME", private_home)
        .env("TMPDIR", private_tmp)
        .env("SHELL", "/bin/sh");
    if let Some(vendor) = vendor {
        // Let the vendor CLI find its own data dir (login store) without
        // changing HOME; the dir is read-only in the profile.
        if let Some(parent) = vendor.parent() {
            command.env("XDG_DATA_HOME", parent);
        }
    }
}

/// Build the sandbox profile: shell-tool profile + optional read-only vendor
/// dir + the configured agent's own program directory (read + exec), then
/// always keep the network on (the agent must reach its vendor).
fn build_profile(
    workspace: &Path,
    private_home: &Path,
    real_home: Option<&Path>,
    vendor: Option<&Path>,
    command_dir: Option<&Path>,
) -> Result<String, AcpError> {
    let mut profile = sandbox::seatbelt_profile(workspace, private_home, real_home, true)
        .map_err(|err| AcpError::Sandbox(err.to_string()))?;
    if let Some(vendor) = vendor {
        let vendor = scheme_escape(vendor)?;
        profile.push_str(&format!("(allow file-read* (subpath \"{vendor}\"))\n"));
    }
    if let Some(dir) = command_dir {
        // The owner-configured agent CLI may be installed outside the system
        // trees (e.g. `~/.opencode/bin`); its own directory gets read + exec,
        // never write. Validated against protected locations before this.
        let dir = scheme_escape(dir)?;
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{dir}\"))\n\
             (allow process-exec* (subpath \"{dir}\"))\n"
        ));
    }
    Ok(profile)
}

/// Resolve the directory of an absolute agent command (symlinks followed) for
/// the read+exec allow.
fn command_directory(command: &str) -> Result<Option<PathBuf>, AcpError> {
    let path = Path::new(command);
    if !path.is_absolute() {
        // A bare name is resolved on the sandbox PATH; every directory there
        // is already allowed.
        return Ok(None);
    }
    let canonical = path
        .canonicalize()
        .map_err(|err| AcpError::Config(format!("agent command {command} is not usable: {err}")))?;
    if !canonical.is_file() {
        return Err(AcpError::Config(format!(
            "agent command {command} is not a file"
        )));
    }
    let parent = canonical
        .parent()
        .ok_or_else(|| AcpError::Config(format!("agent command {command} has no directory")))?;
    Ok(Some(parent.to_path_buf()))
}

/// Refuse a directory that overlaps a sensitive location, then canonicalise
/// it. Used for both the vendor data dir and the agent's program dir.
fn validate_read_dir(
    dir: &Path,
    real_home: Option<&Path>,
    what: &str,
) -> Result<PathBuf, AcpError> {
    let canonical = dir.canonicalize().map_err(|err| {
        AcpError::Config(format!("{what} {} is not usable: {err}", dir.display()))
    })?;
    if !canonical.is_dir() {
        return Err(AcpError::Config(format!(
            "{what} {} is not a directory",
            dir.display()
        )));
    }
    if canonical == Path::new("/") {
        return Err(AcpError::Config(format!(
            "{what} {} is the filesystem root",
            dir.display()
        )));
    }
    if let Some(home) = real_home {
        // Canonicalise so `/var` vs `/private/var` cannot defeat the overlap
        // check (macOS temp dirs hit exactly this).
        let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
        let sensitive = [
            home.join(".auxesis"),
            home.join(".ssh"),
            home.join(".aws"),
            home.join(".gnupg"),
            home.join(".docker"),
            home.join(".kube"),
        ];
        for protected in sensitive {
            if overlaps(&canonical, &protected) {
                return Err(AcpError::Config(format!(
                    "{what} {} overlaps the protected path {}",
                    canonical.display(),
                    protected.display()
                )));
            }
        }
    }
    Ok(canonical)
}

/// Refuse a vendor data dir that overlaps a sensitive location, then
/// canonicalise it.
fn validate_vendor_dir(dir: &Path, real_home: Option<&Path>) -> Result<PathBuf, AcpError> {
    validate_read_dir(dir, real_home, "vendor data dir")
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

/// Escape a path as a Scheme string for the Seatbelt profile; control
/// characters are refused.
fn scheme_escape(path: &Path) -> Result<String, AcpError> {
    let text = path
        .to_str()
        .ok_or_else(|| AcpError::Sandbox(format!("path {} is not UTF-8", path.display())))?;
    if text.chars().any(char::is_control) {
        return Err(AcpError::Sandbox(format!(
            "path {} contains control characters",
            path.display()
        )));
    }
    Ok(text.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn unsandboxed_spec(workspace: &Path) -> SupervisorSpec {
        let mut spec = SupervisorSpec::new("/bin/sh", workspace);
        spec.args = vec!["-c".to_string(), "cat >/dev/null".to_string()];
        spec.sandbox.enabled = false;
        spec.sandbox.allow_unsandboxed = true;
        spec.kill_grace = Duration::from_millis(200);
        // These tests do not exercise the process cap, and the cap is computed
        // from the *live* user process count plus a fixed headroom: when the
        // whole suite runs in parallel (and the host runs other builds) that
        // headroom is exhausted by unrelated processes, so the child shell
        // fails with "Cannot fork". The dedicated fork-bomb test below sets its
        // own cap explicitly.
        spec.max_processes = 0;
        spec
    }

    /// Positive process liveness check.
    ///
    /// `Ok(true)` means the process is dead — either gone entirely (`kill(pid,
    /// 0)` reports `ESRCH`, or the OS no longer knows the pid) or surviving only
    /// as a zombie pending an init reap. `Ok(false)` means it is positively
    /// still running. `Err` means liveness cannot be determined right now: a
    /// caller polling for death must keep polling on `Err` and fail loudly at
    /// its deadline rather than treat the uncertainty as "gone" and pass
    /// vacuously (e.g. under fork exhaustion, `ps` cannot even be spawned).
    fn process_is_gone(pid: i32) -> Result<bool, String> {
        if unsafe { libc::kill(pid, 0) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(true);
            }
            // EPERM (or anything else): the process exists and we merely may not
            // signal it. Fall through to the state probe instead of guessing.
        }
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => {
                    // The state is the field after the parenthesised command name.
                    match stat.rsplit_once(')') {
                        Some((_, rest)) => Ok(rest.trim_start().starts_with('Z')),
                        None => Err(format!("/proc/{pid}/stat is unparsable: {stat:?}")),
                    }
                }
                // Gone between `kill()` and the read: positively dead.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(true),
                Err(err) => Err(format!("could not read /proc/{pid}/stat: {err}")),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let output = std::process::Command::new("ps")
                .args(["-o", "state=", "-p", &pid.to_string()])
                .output()
                .map_err(|err| format!("could not spawn `ps` to check pid {pid}: {err}"))?;
            if !output.status.success() {
                // BSD `ps` exits non-zero when it does not know the pid, which is
                // the same positive "gone" signal as `kill` ESRCH.
                return Ok(true);
            }
            let state = String::from_utf8_lossy(&output.stdout);
            let state = state.trim_start();
            if state.is_empty() {
                return Err(format!(
                    "`ps -o state= -p {pid}` reported success with no state"
                ));
            }
            Ok(state.starts_with('Z'))
        }
    }

    #[tokio::test]
    async fn child_environment_is_scrubbed_of_aux_keys_and_private_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AUX_KEY_ACP_SUPERVISOR_TEST", "canary");
        let mut spec = unsandboxed_spec(dir.path());
        // `env` writes the snapshot; the shell appends a builtin sentinel so the
        // reader can tell the finished file from the empty one the redirection
        // creates before `env` runs. (No extra fork: children run under a tight
        // RLIMIT_NPROC when the whole suite runs in parallel.)
        spec.args = vec![
            "-c".to_string(),
            "env > env.txt 2>/dev/null; printf '%s\\n' __ENV_DONE__ >> env.txt; sleep 0.2"
                .to_string(),
        ];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        // Poll for the sentinel instead of sleeping a fixed amount: under load
        // the child may not have run `env` yet.
        let env_path = dir.path().join("env.txt");
        let mut env = None;
        for _ in 0..250 {
            if let Ok(text) = std::fs::read_to_string(&env_path) {
                if text.lines().any(|line| line == "__ENV_DONE__") {
                    env = Some(text);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let env = env.expect("the child environment snapshot must be written");
        process.shutdown().await;
        assert!(
            !env.contains("AUX_KEY_ACP_SUPERVISOR_TEST"),
            "child must not see AUX_KEY_* variables"
        );
        assert!(
            !env.contains("AUXESIS_HOME="),
            "child must not see AUXESIS_HOME"
        );
        assert!(
            !env.contains("AUXESIS_SANDBOX="),
            "child must not see AUXESIS_SANDBOX"
        );
        // The per-turn reaper marker is the only AUXESIS_* variable allowed.
        let marker_line = env
            .lines()
            .find(|line| line.starts_with("AUXESIS_ACP_TURN="))
            .unwrap_or_default();
        assert!(
            !marker_line.is_empty(),
            "the per-turn reaper marker must be present"
        );
        let home_line = env
            .lines()
            .find(|line| line.starts_with("HOME="))
            .unwrap_or_default();
        assert!(
            home_line.contains(".acp-home"),
            "HOME must be the private scratch home, got {home_line}"
        );
        let tmp_line = env
            .lines()
            .find(|line| line.starts_with("TMPDIR="))
            .unwrap_or_default();
        assert!(
            tmp_line.contains(".acp-tmp"),
            "TMPDIR must be the private scratch tmp, got {tmp_line}"
        );
        std::env::remove_var("AUX_KEY_ACP_SUPERVISOR_TEST");
    }

    #[tokio::test]
    async fn kill_now_reaps_the_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = unsandboxed_spec(dir.path());
        spec.args = vec![
            "-c".to_string(),
            "sleep 300 & echo $! > child.pid; wait".to_string(),
        ];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        // Wait (bounded) for the background child's pid to appear: a loaded
        // runner can take well over the old one-second budget to fork `sh` and
        // start `sleep`.
        let pid_path = dir.path().join("child.pid");
        let mut child_pid = None;
        for _ in 0..250 {
            if let Ok(text) = std::fs::read_to_string(&pid_path) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    child_pid = Some(pid);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let child_pid = child_pid.expect("the background child's pid");
        process.kill_now();
        // SIGKILL is asynchronous, and a killed grandchild may linger as a
        // zombie until init reaps it; poll (bounded) until it is gone. An
        // indeterminate probe (`Err`) is not evidence of death: keep polling,
        // and if the deadline arrives without a positive answer, fail loudly
        // with the last error instead of passing vacuously.
        let mut gone = false;
        let mut last_error: Option<String> = None;
        for _ in 0..250 {
            match process_is_gone(child_pid) {
                Ok(true) => {
                    gone = true;
                    break;
                }
                Ok(false) => last_error = None,
                Err(err) => last_error = Some(err),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if let Some(err) = last_error {
            assert!(
                gone,
                "could not determine whether the background child is gone: {err}"
            );
        }
        assert!(gone, "the background child must be killed with the tree");
    }

    #[tokio::test]
    async fn stderr_is_scrubbed_before_it_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = unsandboxed_spec(dir.path());
        let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
        spec.args = vec![
            "-c".to_string(),
            format!("echo 'token={secret}' >&2; sleep 0.1"),
        ];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        process.shutdown().await;
        let lines = process.stderr_lines();
        let joined = lines.join("\n");
        assert!(
            !joined.contains(secret),
            "the raw secret must never be stored: {joined}"
        );
        assert!(
            joined.contains("<redacted>"),
            "expected a redaction: {joined}"
        );
    }

    #[tokio::test]
    async fn stderr_capture_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = unsandboxed_spec(dir.path());
        spec.stderr_cap_bytes = 2048;
        spec.stderr_max_lines = 10;
        spec.args = vec![
            "-c".to_string(),
            "for i in $(seq 1 500); do echo line-$i >&2; done; sleep 0.1".to_string(),
        ];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        process.shutdown().await;
        let lines = process.stderr_lines();
        assert!(lines.len() <= 10, "line cap: {}", lines.len());
        let bytes: usize = lines.iter().map(String::len).sum();
        assert!(bytes <= 2048 + 32, "byte cap: {bytes}");
    }

    #[tokio::test]
    async fn vendor_dirs_that_overlap_protected_paths_are_refused() {
        let home = tempfile::tempdir().unwrap();
        let auxesis = home.path().join(".auxesis");
        std::fs::create_dir_all(&auxesis).unwrap();
        let err = validate_vendor_dir(&auxesis, Some(home.path())).unwrap_err();
        assert!(err.to_string().contains("protected"), "{err}");
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        assert!(validate_vendor_dir(&ssh, Some(home.path())).is_err());
        let ok = home.path().join(".local/share/opencode");
        std::fs::create_dir_all(&ok).unwrap();
        assert!(validate_vendor_dir(&ok, Some(home.path())).is_ok());
    }

    #[test]
    fn command_dirs_overlapping_protected_paths_are_refused() {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".auxesis/bin");
        std::fs::create_dir_all(&bin).unwrap();
        assert!(validate_read_dir(&bin, Some(home.path()), "agent program dir").is_err());
        let ok = home.path().join(".opencode/bin");
        std::fs::create_dir_all(&ok).unwrap();
        assert!(validate_read_dir(&ok, Some(home.path()), "agent program dir").is_ok());
        // A relative command has no directory allow (it resolves on the
        // sandbox PATH).
        assert!(command_directory("opencode").unwrap().is_none());
    }

    #[tokio::test]
    async fn sandbox_required_but_unavailable_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = SupervisorSpec::new("/bin/echo", dir.path());
        spec.sandbox = ShellSandbox::new(true, false, false)
            .with_test_sandbox_exec("/nonexistent/sandbox-exec");
        let err = match AgentProcess::spawn(&spec).await {
            Ok(_) => panic!("spawn must fail closed without sandbox-exec"),
            Err(err) => err,
        };
        assert!(matches!(err, AcpError::Sandbox(_)), "{err}");
    }

    #[test]
    fn stderr_lines_are_scrubbed_by_the_shared_scrubber() {
        let _guard = crate::known_secret_test_lock();
        kernel_broker::scrub::clear_known_secrets();
        kernel_broker::scrub::register_known_secret("super-secret-known-value-123456");
        let scrubbed = scrub_stderr_line("here: super-secret-known-value-123456 end");
        assert!(!scrubbed.contains("super-secret-known-value-123456"));
        kernel_broker::scrub::clear_known_secrets();
    }

    #[tokio::test]
    async fn spawn_creates_the_private_home_and_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let spec = unsandboxed_spec(dir.path());
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        assert!(dir.path().join(".acp-home").is_dir());
        assert!(dir.path().join(".acp-tmp").is_dir());
        process.kill_now();
        let mut marker = std::fs::File::create(dir.path().join("x")).unwrap();
        marker.write_all(b"ok").unwrap();
    }

    #[tokio::test]
    async fn an_unrelated_process_in_the_workspace_survives_the_reap() {
        // A cwd-based sweep kills collateral owner
        // processes; the env marker replaces it and must never touch them.
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().canonicalize().unwrap();
        let mut unrelated = std::process::Command::new("sleep")
            .arg("300")
            .current_dir(&workspace)
            .spawn()
            .unwrap();
        let spec = unsandboxed_spec(&workspace);
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        process.kill_now();
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            matches!(unrelated.try_wait(), Ok(None)),
            "an unrelated process whose cwd is the workspace must never be killed"
        );
        let _ = unrelated.kill();
        let _ = unrelated.wait();
    }

    #[tokio::test]
    async fn file_size_limit_stops_a_disk_fill() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = unsandboxed_spec(dir.path());
        spec.max_file_bytes = 4096;
        spec.args = vec![
            "-c".to_string(),
            "head -c 100000 /dev/zero > big; wc -c < big > size".to_string(),
        ];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        process.shutdown().await;
        let size: u64 = std::fs::read_to_string(dir.path().join("size"))
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(0);
        assert!(
            size <= 4096,
            "RLIMIT_FSIZE must stop the disk fill: wrote {size}"
        );
    }

    #[tokio::test]
    async fn open_file_limit_stops_an_fd_leak() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = unsandboxed_spec(dir.path());
        spec.max_open_files = 32;
        spec.args = vec![
            "-c".to_string(),
            "i=3; while [ $i -lt 200 ]; do eval \"exec $i>/dev/null\" 2>/dev/null || break; \
             i=$((i+1)); done; echo $i > fds"
                .to_string(),
        ];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        process.shutdown().await;
        let fds: u32 = std::fs::read_to_string(dir.path().join("fds"))
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(0);
        assert!(
            fds <= 32,
            "RLIMIT_NOFILE must stop the fd leak: reached {fds}"
        );
    }

    #[tokio::test]
    async fn process_limit_stops_a_fork_bomb() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = unsandboxed_spec(dir.path());
        // Headroom above the current user process count. Kept comfortably
        // above what the bomb can reach, so a parallel suite or a busy runner
        // cannot push the live count past the limit and make the spawn itself
        // fail with EAGAIN (which would fail this test for the wrong reason).
        // An unconstrained bomb spawns thousands in the window below, so a cap
        // of 32 is still what stops it.
        spec.max_processes = 32;
        spec.args = vec!["-c".to_string(), "while :; do sleep 60 & done".to_string()];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        let pid = process.pid();
        tokio::time::sleep(Duration::from_millis(700)).await;
        let children = std::process::Command::new("pgrep")
            .args(["-P", &pid.to_string()])
            .output()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
            })
            .unwrap_or(0);
        process.kill_now();
        assert!(
            children < 100,
            "RLIMIT_NPROC must stop the fork bomb: {children} children"
        );
    }

    #[tokio::test]
    async fn cpu_limit_stops_a_spin() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = unsandboxed_spec(dir.path());
        spec.max_cpu_seconds = 1;
        spec.args = vec!["-c".to_string(), "while :; do :; done".to_string()];
        let mut process = AgentProcess::spawn(&spec).await.unwrap();
        let mut exited = false;
        for _ in 0..200 {
            if !process.is_running() {
                exited = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(exited, "RLIMIT_CPU must stop the spin");
        process.kill_now();
    }
}
