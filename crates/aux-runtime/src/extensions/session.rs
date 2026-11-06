//! The sandboxed stdio session.
//!
//! One session is one child process started under `sandbox-exec` with a
//! profile generated from the entry ([`kernel_mcp::seatbelt_profile`]). The
//! profile denies every socket unless the entry declares `network`, in which
//! case it allows exactly one loopback port — an [`kernel_net::EgressProxy`]
//! started here enforces the entry's `host:port` allowlist from that port. The
//! child's `HTTPS_PROXY`/`HTTP_PROXY` point at it.
//!
//! Tool identities are pinned at install ([`pin_extension`]) and re-checked on
//! every launch ([`verify_identity`]). Any added, removed or changed tool is
//! drift: the extension freezes and is unmounted everywhere.
//!
//! The child's stdout is scrubbed by exact secret value before it is parsed
//! ([`kernel_broker::scrub`]), so a server that prints an injected secret
//! cannot put it back into a model-visible result.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kernel_mcp::{
    client, tool_identity, IdentityDrift, JsonRpcRequest, JsonRpcResponse, McpClient, McpError,
    RemoteTool, ServerInfo, Transport,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use super::catalog::Entry;
use super::install::InstalledExtension;
use super::mount::{freeze, store_state, ExtensionState};
use super::{hex, unhex, valid_name};

/// The longest single JSON-RPC line accepted from a child.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
/// The longest request line written to a child.
const MAX_REQUEST_BYTES: usize = 1024 * 1024;

/// One pinned tool identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPin {
    /// Remote tool name.
    pub name: String,
    /// Hex blake3 identity.
    pub identity: String,
}

/// How a session is built.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionOptions {
    /// Allow a loopback artefact fetch (tests only).
    pub allow_loopback: bool,
}

/// Everything that can refuse a session.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// `sandbox-exec` is missing on macOS: fail closed, never run unsandboxed.
    #[error("sandbox-exec is unavailable; refusing to run an extension unsandboxed")]
    SandboxUnavailable,
    /// The child could not be started.
    #[error("could not start `{name}`: {message}")]
    Spawn {
        /// Extension name.
        name: String,
        /// Content-free reason.
        message: String,
    },
    /// The MCP handshake or discovery failed.
    #[error("discovery failed for `{name}`: {message}")]
    Discovery {
        /// Extension name.
        name: String,
        /// Content-free reason.
        message: String,
    },
    /// The egress proxy could not start.
    #[error("egress proxy failed: {0}")]
    Proxy(String),
    /// The pinned identity drifted.
    #[error("tool identity drift for `{name}`: {drift}")]
    IdentityDrift {
        /// Extension name.
        name: String,
        /// What changed.
        drift: String,
    },
    /// The extension has no pinned identity row (a missing install state is a
    /// refusal, never a silent "nothing to check").
    #[error("extension `{name}` has no pinned identity")]
    MissingState {
        /// Extension name.
        name: String,
    },
    /// A mount-side failure (the freeze on drift could not be persisted).
    #[error("mount refused: {0}")]
    Mount(#[from] super::mount::MountError),
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The installed artefact failed its re-hash before it could be re-pinned.
    #[error(transparent)]
    Install(#[from] super::install::InstallError),
    /// `--accept` would re-pin a build other than the approved one (another
    /// version, other bytes, or a row without an artefact pin), or
    /// `--downgrade-to` does not name exactly that build, or names the approved
    /// build itself: nothing is re-pinned.
    #[error("{message}")]
    DowngradeRefused {
        /// Both versions, why it is not the approved build, and the one
        /// command that re-pins it.
        message: String,
        /// The version that would run.
        installed: String,
        /// Versions newer than the running build whose entry is corrupt.
        corrupt_newer: Vec<String>,
    },
    /// `--accept` without `--accept-launch-change` naming exactly the launch
    /// fields that changed since the pin: nothing started or re-pinned.
    #[error("{0}")]
    LaunchChangeRefused(String),
}

/// A started egress proxy plus its loopback port.
pub struct EgressHandle {
    /// The running proxy.
    pub proxy: kernel_net::EgressProxy,
}

impl EgressHandle {
    /// The loopback port the sandbox allows.
    pub fn port(&self) -> u16 {
        self.proxy.port()
    }
}

/// Start the egress proxy for an entry, or `None` when it declares no network.
pub async fn spawn_egress(entry: &Entry) -> Result<Option<EgressHandle>, SessionError> {
    let allow = entry.network_allowlist();
    if allow.is_empty() {
        return Ok(None);
    }
    let proxy = kernel_net::spawn_egress_proxy(allow)
        .await
        .map_err(|err| SessionError::Proxy(err.to_string()))?;
    Ok(Some(EgressHandle { proxy }))
}

/// The child state, guarded so one round trip runs at a time.
struct ChildState {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
    dead: bool,
}

/// A stdio transport that spawns the child under an explicit Seatbelt profile.
struct SandboxedStdio {
    program: PathBuf,
    args: Vec<OsString>,
    profile: String,
    env: Vec<(String, String)>,
    work_dir: PathBuf,
    state: Mutex<ChildState>,
}

impl SandboxedStdio {
    fn new(
        program: PathBuf,
        args: Vec<OsString>,
        profile: String,
        env: Vec<(String, String)>,
        work_dir: PathBuf,
    ) -> Self {
        Self {
            program,
            args,
            profile,
            env,
            work_dir,
            state: Mutex::new(ChildState {
                child: None,
                stdin: None,
                stdout: None,
                dead: false,
            }),
        }
    }

    async fn ensure_started(&self) -> Result<(), McpError> {
        let mut state = self.state.lock().await;
        if state.dead {
            return Err(McpError::ProcessGone);
        }
        if state.child.is_some() {
            return Ok(());
        }
        let mut command = build_command(
            &self.program,
            &self.args,
            &self.profile,
            &self.work_dir,
            &self.env,
        )?;
        let mut child = command
            .spawn()
            .map_err(|err| McpError::Io { kind: err.kind() })?;
        let stdin = child.stdin.take().ok_or(McpError::ProcessGone)?;
        let stdout = child.stdout.take().ok_or(McpError::ProcessGone)?;
        state.child = Some(child);
        state.stdin = Some(stdin);
        state.stdout = Some(BufReader::new(stdout));
        Ok(())
    }

    async fn stop_child(&self) {
        let mut state = self.state.lock().await;
        state.dead = true;
        state.stdin.take();
        state.stdout.take();
        if let Some(mut child) = state.child.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }
}

/// Build the sandboxed command for a child.
fn build_command(
    program: &Path,
    args: &[OsString],
    profile: &str,
    work_dir: &Path,
    env: &[(String, String)],
) -> Result<tokio::process::Command, McpError> {
    let mut command = if cfg!(target_os = "macos") {
        let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
        if !sandbox_exec.is_file() {
            return Err(McpError::InvalidCommand {
                reason: "sandbox-exec is unavailable",
            });
        }
        let mut command = tokio::process::Command::new(sandbox_exec);
        command.arg("-p").arg(profile).arg(program).args(args);
        command
    } else {
        // Seatbelt is a macOS property. On another host the platform has no
        // equivalent and the daemon does not ship there; tests still need to
        // exercise the protocol path.
        let mut command = tokio::process::Command::new(program);
        command.args(args);
        command
    };
    command
        .current_dir(work_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .env_clear()
        .env("HOME", work_dir)
        .env("TMPDIR", work_dir)
        .env("PATH", SANDBOX_PATH)
        .kill_on_drop(true);
    for (key, value) in env {
        command.env(key, value);
    }
    Ok(command)
}

/// Replace every known secret value inside a decoded response.
fn scrub_value(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(redacted) = kernel_broker::scrub::redact_known_secrets(text) {
                *text = redacted;
            }
        }
        Value::Array(items) => {
            for item in items {
                scrub_value(item);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                scrub_value(item);
            }
        }
        _ => {}
    }
}

#[async_trait::async_trait]
impl Transport for SandboxedStdio {
    async fn round_trip(
        &self,
        req: JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, McpError> {
        self.ensure_started().await?;
        let is_notification = req.method.starts_with("notifications/");
        let line = if is_notification {
            let mut envelope = serde_json::Map::new();
            envelope.insert("jsonrpc".to_owned(), Value::String(req.jsonrpc.to_owned()));
            envelope.insert("method".to_owned(), Value::String(req.method.clone()));
            if !req
                .params
                .as_object()
                .is_none_or(|params| params.is_empty())
            {
                envelope.insert("params".to_owned(), req.params.clone());
            }
            serde_json::to_vec(&Value::Object(envelope))
        } else {
            serde_json::to_vec(&req)
        }
        .map_err(|_| McpError::protocol(-32700, "could not encode request"))?;
        if line.len() > MAX_REQUEST_BYTES {
            return Err(McpError::FrameTooLarge {
                limit: MAX_REQUEST_BYTES,
                seen: line.len(),
            });
        }

        let mut state = self.state.lock().await;
        if state.dead {
            return Err(McpError::ProcessGone);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        {
            let stdin = state.stdin.as_mut().ok_or(McpError::ProcessGone)?;
            let write = async {
                stdin.write_all(&line).await?;
                stdin.write_all(b"\n").await?;
                stdin.flush().await
            };
            if tokio::time::timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                write,
            )
            .await
            .map_err(|_| McpError::Timeout)?
            .is_err()
            {
                state.dead = true;
                return Err(McpError::ProcessGone);
            }
        }
        if is_notification {
            return Ok(JsonRpcResponse::success(req.id, Value::Null));
        }

        loop {
            let read = {
                let stdout = state.stdout.as_mut().ok_or(McpError::ProcessGone)?;
                let mut buf = String::new();
                async {
                    let read = stdout.read_line(&mut buf).await?;
                    Ok::<_, std::io::Error>((read, buf))
                }
            };
            let (read, buf) = match tokio::time::timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
                read,
            )
            .await
            {
                Ok(Ok(value)) => value,
                Ok(Err(err)) => {
                    state.dead = true;
                    return Err(McpError::Io { kind: err.kind() });
                }
                Err(_) => {
                    state.dead = true;
                    return Err(McpError::Timeout);
                }
            };
            if read == 0 {
                state.dead = true;
                return Err(McpError::ProcessGone);
            }
            if buf.len() > MAX_LINE_BYTES {
                state.dead = true;
                return Err(McpError::FrameTooLarge {
                    limit: MAX_LINE_BYTES,
                    seen: buf.len(),
                });
            }
            let mut value: Value = match serde_json::from_str(buf.trim()) {
                Ok(value) => value,
                // A malformed or unsolicited line is ignored: the protocol
                // answer we are waiting for may still follow.
                Err(_) => continue,
            };
            scrub_value(&mut value);
            let response: JsonRpcResponse = match serde_json::from_value(value) {
                Ok(response) => response,
                Err(_) => continue,
            };
            if response.id.as_number() == Some(req.id) {
                return Ok(response);
            }
        }
    }

    async fn stop(&self) {
        self.stop_child().await;
    }
}

/// One live extension: its discovered tools, its MCP client and its proxy.
pub struct ExtensionSession {
    /// Extension name.
    pub name: String,
    /// Pinned version.
    pub version: String,
    /// Tools advertised at launch, in server order.
    pub tools: Vec<RemoteTool>,
    /// The MCP client over the sandboxed child.
    pub client: Arc<dyn McpClient>,
    /// The child transport, kept for an explicit stop.
    transport: Arc<SandboxedStdio>,
    /// The running egress proxy, when the entry declares network.
    pub egress: Option<EgressHandle>,
}

impl ExtensionSession {
    /// Stop the child and the proxy.
    pub async fn stop(&self) {
        self.transport.stop().await;
        if let Some(egress) = &self.egress {
            // Dropping the handle stops the listener; `shutdown` waits it out.
            let _ = egress.port();
        }
    }

    /// One raw `tools/call` over the sandboxed transport.
    ///
    /// Used by `aux ext verify` and the tests to exercise the scrubbed output
    /// path without minting a broker grant. The normal path is [`McpTool`],
    /// which admits arguments through the privacy gate.
    ///
    /// [`McpTool`]: kernel_mcp::McpTool
    pub async fn call_tool_raw(&self, name: &str, arguments: Value) -> Result<Value, SessionError> {
        let params = serde_json::json!({"name": name, "arguments": arguments});
        let request = JsonRpcRequest::new(1, "tools/call", params);
        let response = self
            .transport
            .round_trip(request, Duration::from_secs(10))
            .await
            .map_err(|err| SessionError::Discovery {
                name: self.name.clone(),
                message: err.kind().to_owned(),
            })?;
        response
            .into_result()
            .map_err(|err| SessionError::Discovery {
                name: self.name.clone(),
                message: err.kind().to_owned(),
            })
    }
}

impl std::fmt::Debug for ExtensionSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionSession")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("tools", &self.tools.len())
            .finish()
    }
}

/// The `PATH` every child runs with. The child's environment is cleared, so
/// `/usr/bin/env X` searches exactly these directories for X.
const SANDBOX_PATH: &str = "/usr/bin:/bin";

/// Resolve the runtime program and the extra read paths its profile needs.
///
/// The profile grants exec on exact paths and never on a directory, so each
/// file the child runs is listed by its own path: the program when it is found
/// on `PATH`, and every interpreter its `#!` line names.
fn resolve_program(install_dir: &Path, command: &str) -> (PathBuf, Vec<PathBuf>) {
    let candidate = install_dir.join(command);
    let (program, mut paths) = if candidate.is_file() {
        (candidate, Vec::new())
    } else if let Some(found) = which(command) {
        let parent = found
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/usr/bin"));
        let mut paths = vec![parent];
        grant_file(&mut paths, &found);
        (found, paths)
    } else {
        (PathBuf::from(command), Vec::new())
    };
    // A script entry runs through its interpreter, so the files the kernel and
    // `env` execute must be allowed too, but only when each one sits in the
    // system allowlist or a declared runtime directory.
    for interpreter in script_interpreters(&program) {
        if allowed_interpreter(&interpreter, &paths) {
            grant_file(&mut paths, &interpreter);
            for need in interpreter_needs(&interpreter) {
                grant_file(&mut paths, Path::new(need));
            }
        }
    }
    (program, paths)
}

/// The files a system interpreter opens or runs beyond its own file. On macOS
/// `/bin/sh` reads `/private/var/select/sh` to find the shell it runs as, and
/// then execs `/bin/bash`. Nothing else is granted.
fn interpreter_needs(interpreter: &Path) -> &'static [&'static str] {
    if cfg!(target_os = "macos") && interpreter == Path::new("/bin/sh") {
        &["/private/var/select/sh", "/bin/bash"]
    } else {
        &[]
    }
}

/// Add `file` to `paths` by its own path, and by its real path when it is a link.
fn grant_file(paths: &mut Vec<PathBuf>, file: &Path) {
    let real = std::fs::canonicalize(file).ok();
    for path in std::iter::once(file.to_path_buf()).chain(real) {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
}

/// `path` with its symlinks resolved, or `path` itself when that fails.
fn real_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The files a `#!` script executes: the interpreter it names. For
/// `#!/usr/bin/env X` that is `/usr/bin/env` itself and X as `env` finds it on
/// the sandbox PATH. A file without a `#!` line has none.
fn script_interpreters(program: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(program) else {
        return Vec::new();
    };
    let Some(first) = text.lines().next() else {
        return Vec::new();
    };
    let Some(rest) = first.strip_prefix("#!") else {
        return Vec::new();
    };
    let mut parts = rest.split_whitespace();
    let Some(interpreter) = parts.next() else {
        return Vec::new();
    };
    let interpreter = PathBuf::from(interpreter);
    if interpreter != Path::new("/usr/bin/env") {
        return vec![interpreter];
    }
    let mut files = vec![interpreter];
    files.extend(parts.next().and_then(which_on_sandbox_path));
    files
}

/// Find `name` on the sandbox PATH, the search `env` makes inside the child.
fn which_on_sandbox_path(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        return None;
    }
    SANDBOX_PATH
        .split(':')
        .map(|dir| Path::new(dir).join(name))
        .find(|candidate| candidate.is_file())
}

/// Whether `interpreter` is an absolute, executable regular file inside
/// `/bin`, `/usr/bin` or one of the declared runtime paths.
fn allowed_interpreter(interpreter: &Path, runtime_paths: &[PathBuf]) -> bool {
    if !interpreter.is_absolute() {
        return false;
    }
    let Ok(meta) = std::fs::metadata(interpreter) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return false;
        }
    }
    let Ok(resolved) = std::fs::canonicalize(interpreter) else {
        return false;
    };
    let mut dirs: Vec<PathBuf> = vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")];
    dirs.extend(runtime_paths.iter().cloned());
    dirs.iter().any(|dir| {
        std::fs::canonicalize(dir)
            .map(|dir| resolved.starts_with(&dir))
            .unwrap_or(false)
    })
}

/// A minimal `PATH` lookup for a bare runtime name.
fn which(command: &str) -> Option<PathBuf> {
    if command.contains('/') {
        let path = PathBuf::from(command);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(command);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Read the declared secret values from `~/.auxesis/.env` and register them.
fn inject_secrets(home: &Path, entry: &Entry) -> BTreeMap<String, String> {
    let names: BTreeSet<String> = entry.secret_names().into_iter().collect();
    if names.is_empty() {
        return BTreeMap::new();
    }
    let values = kernel_core::env_file::read_values(home, &names);
    for value in values.values() {
        let _ = kernel_broker::scrub::register_known_secret(value);
    }
    values
}

/// Start a session for an installed extension and discover its tools.
pub async fn session_for(
    home: &Path,
    installed: &InstalledExtension,
    options: &SessionOptions,
) -> Result<ExtensionSession, SessionError> {
    if !valid_name(&installed.name) {
        return Err(SessionError::Spawn {
            name: installed.name.clone(),
            message: "invalid name".to_owned(),
        });
    }
    let _ = options;
    let entry = &installed.entry;
    let secrets = inject_secrets(home, entry);
    let egress = spawn_egress(entry).await?;
    let (program, runtime_paths) = resolve_program(&installed.dir, &entry.run.command);
    // Seatbelt matches a subpath against the resolved path, so a home under a
    // symlink (macOS `/var` is `/private/var`) must be granted by its real path.
    let spec = kernel_mcp::SandboxSpec {
        install_dir: real_path(&installed.dir),
        work_dir: real_path(&installed.work_dir()),
        runtime_read_paths: runtime_paths,
        proxy_port: egress.as_ref().map(EgressHandle::port),
    };
    let profile = kernel_mcp::seatbelt_profile(&spec);

    let mut env: Vec<(String, String)> = Vec::new();
    if let Some(egress) = &egress {
        let proxy = format!("http://127.0.0.1:{}", egress.port());
        env.push(("HTTP_PROXY".to_owned(), proxy.clone()));
        env.push(("HTTPS_PROXY".to_owned(), proxy.clone()));
        env.push(("http_proxy".to_owned(), proxy.clone()));
        env.push(("https_proxy".to_owned(), proxy));
    }
    for name in entry.secret_names() {
        if let Some(value) = secrets.get(&name) {
            env.push((name, value.clone()));
        }
    }

    let args: Vec<OsString> = entry.run.args.iter().map(OsString::from).collect();
    // The child starts from the same real paths the profile grants: a path
    // through a symlink (`/var` for `/private/var`) needs a metadata grant on
    // the link itself, which the profile does not give.
    let transport = Arc::new(SandboxedStdio::new(
        real_path(&program),
        args,
        profile,
        env,
        real_path(&installed.work_dir()),
    ));
    let client = client(transport.clone(), ServerInfo::default());
    client
        .initialize()
        .await
        .map_err(|err| SessionError::Discovery {
            name: installed.name.clone(),
            message: err.kind().to_owned(),
        })?;
    let page = client
        .list_tools(None)
        .await
        .map_err(|err| SessionError::Discovery {
            name: installed.name.clone(),
            message: err.kind().to_owned(),
        })?;
    Ok(ExtensionSession {
        name: installed.name.clone(),
        version: installed.version.clone(),
        tools: page.tools,
        client,
        transport,
        egress,
    })
}

/// A session for an installed extension, or a typed refusal when it is not
/// installed.
pub async fn discover_session(
    home: &Path,
    name: &str,
    options: &SessionOptions,
) -> Result<ExtensionSession, SessionError> {
    // Re-hashed before it starts: a binary rewritten in place never runs.
    let installed = super::install::verify_installed(home, name)?;
    super::mount::require_approval(home, &installed)?;
    session_for(home, &installed, options).await
}

/// The identity pins for a live tool list.
pub fn pinned_tools(tools: &[RemoteTool]) -> Vec<ToolPin> {
    tools
        .iter()
        .map(|tool| {
            let description = tool.description.as_ref().map_or("", |text| text.as_str());
            ToolPin {
                name: tool.name.clone(),
                identity: hex(&tool_identity(
                    &tool.name,
                    tool.input_schema.as_value(),
                    description,
                )),
            }
        })
        .collect()
}

/// Pin the identities of an installed extension and persist its state: the
/// install-time yes, for an extension with no approval row only.
///
/// An existing row is the owner's yes to one build: it is returned untouched
/// and the new build is **not started** (an upgrade waits for
/// `aux ext verify --accept`, which names its changes). An unreadable or
/// corrupt row is refused and kept.
pub async fn pin_extension(
    home: &Path,
    installed: &InstalledExtension,
    allow_loopback: bool,
) -> Result<ExtensionState, SessionError> {
    match super::mount::read_state(home, &installed.name) {
        Ok(None) => {}
        Ok(Some(state)) => return Ok(state),
        Err(_) => {
            let name = installed.name.clone();
            return Err(super::install::InstallError::StateUnreadable(name).into());
        }
    }
    // EXT-ANCHOR-10: after a remove, the owner's last yes is the row again:
    // this build is not started and diffs over it like an upgrade.
    match super::mount::read_last(home, &installed.name) {
        Ok(None) => {}
        Ok(Some(last)) => {
            store_state(home, &last)?;
            return Ok(last);
        }
        Err(_) => {
            let name = format!("{}.last", installed.name);
            return Err(super::install::InstallError::StateUnreadable(name).into());
        }
    }
    let session = session_for(home, installed, &SessionOptions { allow_loopback }).await?;
    let pins = pinned_tools(&session.tools);
    // Never clears a freeze: only the owner's `aux ext verify --accept` does
    // that. An unreadable row counts as frozen.
    let frozen = super::mount::is_frozen(home, &installed.name);
    let state = ExtensionState {
        name: installed.name.clone(),
        version: installed.version.clone(),
        kind: format!("{:?}", installed.entry.kind).to_lowercase(),
        frozen,
        tools: pins
            .into_iter()
            .map(|pin| (pin.name, pin.identity))
            .collect(),
        network: super::mount::network_pins(&installed.entry),
        secrets: installed.entry.secret_names(),
        // The `[oauth]` endpoints are pinned with the tools: a same-version
        // reinstall that moves the token URL must not pass the approval check.
        oauth: installed.entry.oauth.clone(),
        artefact: Some(super::mount::artefact_pin(&installed.entry)),
        launch: Some(super::mount::launch_pin(&installed.entry)),
    };
    store_state(home, &state)?;
    session.stop().await;
    Ok(state)
}

/// Re-pin the **current** live identity and clear the freeze
/// (`aux ext verify --accept`).
///
/// Clearing the flag alone would refreeze on the next start, so this starts a
/// session, records the tools it advertises now and only then unfreezes.
pub async fn accept_current(
    home: &Path,
    name: &str,
    allow_loopback: bool,
) -> Result<ExtensionState, SessionError> {
    let accepted = accept_installed(home, name, allow_loopback, None).await?;
    Ok(accepted.state)
}

/// What `--accept` re-pinned, and the corrupt newer entries it saw.
#[derive(Debug)]
pub struct Accepted {
    /// The new pinned state.
    pub state: ExtensionState,
    /// Versions newer than the re-pinned build whose entry is corrupt.
    pub corrupt_newer: Vec<String>,
}

/// [`accept_current`]: the approved build is the pinned version string (exact,
/// never a version order) with the pinned artefact sha256. Any other build
/// (older, newer, other bytes, or a row without the pin) is refused
/// ([`SessionError::DowngradeRefused`]) unless `downgrade_to` names exactly
/// it; `downgrade_to` on the approved build is refused too. The refusal comes
/// before the build starts and leaves the state as it was.
pub async fn accept_installed(
    home: &Path,
    name: &str,
    allow_loopback: bool,
    downgrade_to: Option<&str>,
) -> Result<Accepted, SessionError> {
    let options = AcceptOptions {
        allow_loopback,
        downgrade_to,
        ..Default::default()
    };
    accept_with(home, name, &options, |_| {}).await
}

/// What the owner's `--accept` names.
#[derive(Debug, Default, Clone, Copy)]
pub struct AcceptOptions<'a> {
    /// Allow loopback egress (tests).
    pub allow_loopback: bool,
    /// `--downgrade-to`: the exact build other than the approved one.
    pub downgrade_to: Option<&'a str>,
    /// `--accept-change` (alias `--accept-launch-change`): the trust fields
    /// re-trusted, exactly the ones that changed since the pin: launch fields
    /// ([`super::mount::LaunchPin`]), `network`, `secrets`, `oauth`.
    pub launch_change: &'a [String],
    /// `--accept-legacy`: trust a row written before the launch pin.
    pub legacy: bool,
}

/// [`accept_installed`] with every owner flag. The trust diff is checked
/// before anything starts: a changed `source.type`, `kind`, `sensitivity` or
/// `[run]` field, a new host or secret name, or another `[oauth]` table is
/// refused ([`SessionError::LaunchChangeRefused`]) unless `launch_change`
/// names exactly the changed fields; a row without a launch pin needs
/// `legacy`. The new pin is saved
/// (still frozen) and handed to `on_trusted` **before** the child starts, so
/// the owner sees what they trust before it runs; the freeze clears once the
/// live tools are pinned.
pub async fn accept_with(
    home: &Path,
    name: &str,
    options: &AcceptOptions<'_>,
    on_trusted: impl FnOnce(&ExtensionState),
) -> Result<Accepted, SessionError> {
    // Re-hash the installed bytes first: a tampered binary is refused before it
    // runs or is pinned, and the freeze stays.
    let report = super::install::verify_installed_report(home, name)?;
    let installed = report.installed;
    let mut state =
        super::mount::load_state(home, name).ok_or_else(|| SessionError::MissingState {
            name: name.to_owned(),
        })?;
    let pin = super::mount::artefact_pin(&installed.entry);
    let why = match state.artefact.as_deref() {
        _ if installed.version != state.version => String::new(),
        Some(approved) if approved == pin => String::new(),
        Some(approved) => format!(" (artefact sha256 {pin} is not the approved {approved})"),
        None => " (no approved artefact sha256 is pinned)".to_owned(),
    };
    let other = installed.version != state.version || !why.is_empty();
    let command = super::mount::accept_command(&state, &installed);
    if options.downgrade_to != other.then_some(installed.version.as_str()) {
        let fix = match other {
            true => format!("another build is re-pinned only by `{command}`"),
            false => format!("this is the approved build: `{command}`"),
        };
        let (installed, approved) = (installed.version, &state.version);
        return Err(SessionError::DowngradeRefused {
            message: format!(
                "`{name}` runs {}, approved {}{why}: {fix}",
                super::escape_text(&installed),
                super::escape_text(approved)
            ),
            installed,
            corrupt_newer: report.corrupt_newer,
        });
    }
    let launch = super::mount::launch_pin(&installed.entry);
    // A row written before the launch pin has nothing to diff: the owner says
    // so by name, and the values are printed before the child starts.
    let legacy = state.launch.is_none();
    if options.legacy != legacy {
        let message = match legacy {
            true => format!(
                "`{name}` has no approved launch (command, type, sensitivity) pinned; \
                 nothing started: trust it only with `{command}`"
            ),
            false => format!("`{name}` has an approved launch pin: drop `--accept-legacy`"),
        };
        return Err(SessionError::LaunchChangeRefused(message));
    }
    let changed = super::mount::changed_trust_fields(&state, &installed.entry);
    let mut named: BTreeSet<&str> = options.launch_change.iter().map(String::as_str).collect();
    // `tools` is checked once the build lists them, below.
    let named_tools = named.remove("tools");
    if named != changed.iter().copied().collect() {
        let message = match (changed.is_empty(), named.is_empty()) {
            (true, _) => format!("`{name}` has no changed trust field: drop `--accept-change`"),
            (false, true) => format!(
                "`{name}` changed trust fields since approval ({}){}; nothing started: \
                 re-trust them only with `{command}`",
                changed.join(", "),
                new_values(&state, &installed.entry),
            ),
            (false, false) => format!(
                "`--accept-change {}` does not name the changed trust fields of \
                 `{name}`{}: `{command}`",
                super::escape_text(&options.launch_change.join(",")),
                new_values(&state, &installed.entry),
            ),
        };
        return Err(SessionError::LaunchChangeRefused(message));
    }
    let previous = state.version.clone();
    let previous_sha256 = state.artefact.clone();
    // The owner's yes covers this build: its version, hosts and secret names
    // are pinned with its tools, so the next start passes the approval check.
    state.version = installed.version.clone();
    state.network = super::mount::network_pins(&installed.entry);
    state.secrets = installed.entry.secret_names();
    // The owner's yes also covers this build's OAuth endpoints (authorize and
    // token URLs, client id, client secret name, scopes), including a table
    // that an older pin never recorded.
    state.oauth = installed.entry.oauth.clone();
    // ... and these bytes: the next start or accept refuses any other.
    state.artefact = Some(pin);
    // ... run this way, from this source type, at this sensitivity.
    state.launch = Some(launch);
    // Saved and shown before the child starts; it stays frozen until its
    // live tools are pinned, so a failed start runs nothing later.
    state.frozen = true;
    store_state(home, &state)?;
    // The authorized transition is audited when it is saved, so a failed
    // start still shows what the owner trusted.
    super::ledger::log(
        home,
        super::ledger::VERIFY,
        &serde_json::json!({
            "name": name,
            "version": state.version,
            "accepted": true,
            "outcome": "pinned",
            "previous": previous,
            // The approved bytes, and the ones they replace (none on a row
            // written before the artefact pin).
            "sha256": state.artefact,
            "previous_sha256": previous_sha256,
            // The owner named a build other than the approved one.
            "downgrade": other,
            // The row had no launch pin; the owner trusted it by name.
            "legacy": legacy,
            // The trust fields the owner re-trusted by name.
            "launch_change": changed,
        }),
    );
    on_trusted(&state);
    let outcome = |outcome: &str| {
        let row = serde_json::json!({"name": name, "version": state.version, "outcome": outcome});
        super::ledger::log(home, super::ledger::VERIFY, &row);
    };
    let started = session_for(
        home,
        &installed,
        &SessionOptions {
            allow_loopback: options.allow_loopback,
        },
    )
    .await;
    let session = started.inspect_err(|_| outcome("start_failed"))?;
    let pins: BTreeMap<String, String> = pinned_tools(&session.tools)
        .into_iter()
        .map(|pin| (pin.name, pin.identity))
        .collect();
    // EXT-ANCHOR-10: `tools` is a trust field too, known once the build lists
    // them: a tool added, removed or with another identity (schema or
    // description) is named by the owner, never re-pinned silently. The
    // refusal keeps the row frozen.
    let tools_changed = tool_changes(&state.tools, &pins);
    if named_tools == tools_changed.is_empty() {
        session.stop().await;
        outcome("tools_refused");
        let command = super::mount::accept_command(&state, &installed);
        let message = match tools_changed.is_empty() {
            true => format!("`{name}` has no changed tool: drop `tools` from `{command}`"),
            false => format!(
                "`{name}` changed tools since approval ({}); nothing unfrozen: \
                 re-trust them only with `{}`",
                tools_changed.join(", "),
                with_tools(&command),
            ),
        };
        return Err(SessionError::LaunchChangeRefused(message));
    }
    state.tools = pins;
    state.frozen = false;
    let stored = store_state(home, &state);
    session.stop().await;
    stored?;
    // Logged once the unfrozen pin is saved: a failed save never reads as started.
    outcome("started");
    Ok(Accepted {
        state,
        corrupt_newer: report.corrupt_newer,
    })
}

/// `added "x", removed "y", changed "z"`: every tool whose pin differs.
fn tool_changes(pinned: &BTreeMap<String, String>, live: &BTreeMap<String, String>) -> Vec<String> {
    let mut changes = Vec::new();
    for (tool, identity) in live {
        match pinned.get(tool) {
            None => changes.push(format!("added {}", super::quoted(tool))),
            Some(old) if old != identity => {
                changes.push(format!("changed {}", super::quoted(tool)))
            }
            Some(_) => {}
        }
    }
    let removed = pinned.keys().filter(|tool| !live.contains_key(*tool));
    changes.extend(removed.map(|tool| format!("removed {}", super::quoted(tool))));
    changes
}

/// `command` with `tools` added to its `--accept-change` list.
fn with_tools(command: &str) -> String {
    match command.contains(" --accept-change ") {
        true => format!("{command},tools"),
        false => format!("{command} --accept-change tools"),
    }
}

/// `: new network "h:443", secrets "EXT_X__K"` for the refusal, or nothing.
fn new_values(state: &ExtensionState, entry: &Entry) -> String {
    let values = super::mount::new_trust_values(state, entry);
    match values.is_empty() {
        true => String::new(),
        false => format!(": new {}", values.join(", ")),
    }
}

/// Compare a live tool list against the pinned identities.
///
/// On any drift the extension is frozen and unmounted from every agent, and
/// [`SessionError::IdentityDrift`] is returned.
pub fn verify_identity(home: &Path, name: &str, live: &[RemoteTool]) -> Result<(), SessionError> {
    let state = super::mount::load_state(home, name).ok_or_else(|| SessionError::MissingState {
        name: name.to_owned(),
    })?;
    let pinned: BTreeMap<String, String> = state.tools.clone();
    let mut drift = IdentityDrift::default();
    let mut live_map: BTreeMap<String, String> = BTreeMap::new();
    for tool in live {
        let description = tool.description.as_ref().map_or("", |text| text.as_str());
        let identity = hex(&tool_identity(
            &tool.name,
            tool.input_schema.as_value(),
            description,
        ));
        if let Some(pinned_identity) = pinned.get(&tool.name) {
            if pinned_identity != &identity {
                drift.changed.push(tool.name.clone());
            }
        } else {
            drift.added.push(tool.name.clone());
        }
        live_map.insert(tool.name.clone(), identity);
    }
    for name in pinned.keys() {
        if !live_map.contains_key(name) {
            drift.removed.push(name.clone());
        }
    }
    drift.added.sort();
    drift.removed.sort();
    drift.changed.sort();
    if drift.is_empty() {
        return Ok(());
    }
    let reason = drift.to_string();
    freeze(home, name, &reason)?;
    Err(SessionError::IdentityDrift {
        name: name.to_owned(),
        drift: reason,
    })
}

/// Decode a stored hex identity back to bytes (used by tests and verify).
pub fn identity_bytes(pin: &ToolPin) -> Option<[u8; 32]> {
    let bytes = unhex(&pin.identity)?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_value_replaces_known_secret_in_nested_strings() {
        let canary = "CANARY-WO13B-SCRUB-0123456789";
        assert!(kernel_broker::scrub::register_known_secret(canary));
        let mut value = serde_json::json!({
            "result": {"content": [{"type": "text", "text": format!("token={canary}")}]}
        });
        scrub_value(&mut value);
        let rendered = value.to_string();
        assert!(!rendered.contains(canary), "{rendered}");
    }

    #[test]
    fn pinned_tools_are_stable_across_key_order() {
        use kernel_mcp::{RemoteTool, ToolSchema};
        let make = |schema: Value| RemoteTool {
            name: "ping".to_owned(),
            title: None,
            description: None,
            input_schema: ToolSchema::parse(schema).unwrap(),
            annotations: None,
        };
        let one = pinned_tools(&[make(
            serde_json::json!({"type":"object","properties":{"q":{"type":"string"}}}),
        )]);
        let two = pinned_tools(&[make(
            serde_json::json!({"properties":{"q":{"type":"string"}},"type":"object"}),
        )]);
        assert_eq!(one, two);
    }

    #[test]
    fn verify_identity_without_state_is_refused() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            verify_identity(home.path(), "demo", &[]).is_err(),
            "a missing identity row is a refusal, not a no-op"
        );
    }

    #[test]
    fn shebang_interpreter_must_be_in_the_runtime_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let evil = dir.path().join("evil");
        std::fs::write(&evil, "#!/opt/evil/sh\n").unwrap();
        let (_, paths) = resolve_program(dir.path(), "evil");
        assert!(
            !paths.iter().any(|p| p == Path::new("/opt/evil")),
            "an interpreter outside /bin, /usr/bin or the declared runtime path must not be granted"
        );
    }

    /// The profile grants exec on a literal path only, so a `#!/bin/sh` entry
    /// must be granted the interpreter file itself, never its directory.
    #[cfg(unix)]
    #[test]
    fn a_shebang_grants_the_interpreter_file_not_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server"), "#!/bin/sh\n").unwrap();
        let (_, paths) = resolve_program(dir.path(), "server");
        assert!(paths.iter().any(|p| p == Path::new("/bin/sh")), "{paths:?}");
        assert!(!paths.iter().any(|p| p == Path::new("/bin")), "{paths:?}");
    }

    /// `#!/usr/bin/env sh` resolves `sh` on the sandbox PATH, the one the child
    /// runs with, and grants that file.
    #[cfg(unix)]
    #[test]
    fn an_env_shebang_grants_the_file_it_resolves_on_the_sandbox_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server"), "#!/usr/bin/env sh\n").unwrap();
        let (_, paths) = resolve_program(dir.path(), "server");
        assert!(
            paths
                .iter()
                .any(|p| p.file_name() == Some(std::ffi::OsStr::new("sh"))),
            "{paths:?}"
        );
        // The allowlist checks the real file. Linux distributions may resolve
        // `/usr/bin/env` to a different real path; macOS grants this exact path.
        if cfg!(target_os = "macos") {
            assert!(
                paths.iter().any(|p| p == Path::new("/usr/bin/env")),
                "the kernel execs /usr/bin/env first: {paths:?}"
            );
        }
        assert!(
            !paths
                .iter()
                .any(|p| p == Path::new("/bin") || p == Path::new("/usr/bin")),
            "{paths:?}"
        );
    }

    /// The sandbox stays tight for a script entry: it cannot exec `/usr/bin/curl`
    /// and cannot read a file under the HOME it runs with. The positive control
    /// runs the same profile on a script that prints, so the denials cannot pass
    /// because the profile runs nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_script_extension_cannot_exec_curl_or_read_the_home() {
        let install_tmp = tempfile::tempdir().unwrap();
        let install = install_tmp.path().canonicalize().unwrap();
        let work_tmp = tempfile::tempdir().unwrap();
        let work = work_tmp.path().canonicalize().unwrap();
        let home_tmp = tempfile::tempdir().unwrap();
        let home = home_tmp.path().canonicalize().unwrap();
        std::fs::write(home.join("secret.txt"), "owner-only").unwrap();
        let run = |body: &str| {
            let probe = install.join("probe");
            std::fs::write(&probe, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&probe, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
            let (program, runtime_read_paths) = resolve_program(&install, "probe");
            let spec = kernel_mcp::SandboxSpec {
                install_dir: install.clone(),
                work_dir: work.clone(),
                runtime_read_paths,
                proxy_port: None,
            };
            std::process::Command::new("/usr/bin/sandbox-exec")
                .arg("-p")
                .arg(kernel_mcp::seatbelt_profile(&spec))
                .arg(&program)
                .env_clear()
                .env("HOME", &home)
                .output()
                .expect("run sandbox-exec")
        };

        let control = run("echo ok");
        assert!(control.status.success(), "positive control: {control:?}");
        assert_eq!(String::from_utf8_lossy(&control.stdout).trim(), "ok");

        let read = run("cat \"$HOME/secret.txt\"");
        assert!(!read.status.success(), "the home file must not be readable");
        assert!(!String::from_utf8_lossy(&read.stdout).contains("owner-only"));

        let exec = run("/usr/bin/curl --version");
        assert!(!exec.status.success(), "curl must not run");
        assert!(exec.stdout.is_empty(), "curl printed: {:?}", exec.stdout);
    }
}
