//! P2 runtime: discover configured servers once, then mount one agent's tools.
//!
//! [`McpRuntime::start`] walks the enabled servers of an [`McpConfig`] and
//! discovers each one **in isolation**: a server that is unreachable, broken or
//! times out is logged by id and a content-free reason, and every other server
//! still comes up. Nothing about a failed server reaches a log as text — only
//! its id and a [`McpError::kind`] label.
//!
//! # Mounting
//!
//! [`McpRuntime::register_for_agent`] is the P4 gate. An agent sees exactly the
//! remote names its own `[server.agents]` entry lists **and** that discovery
//! actually produced; a listed-but-absent tool is a warning, never a fallback
//! to "everything". Selected tools are ordinary [`kernel_broker::Tool`] values, so
//! the existing broker, taint and audit paths apply unchanged:
//!
//! * risk comes from the server annotations only ([`McpToolDescriptor::risk`]);
//! * every MCP tool sets [`Tool::requires_explicit_rule`], so a wildcard
//!   `allow tool = "*"` can never authorize it (server annotations are not
//!   corroborated, so a `readOnlyHint` cannot widen that);
//! * output is untrusted (`mcp__…` plus an explicit registry mark), so running
//!   one taints the conversation exactly like `http_fetch` or mail.
//!
//! # Sandbox guarantee
//!
//! **stdio servers never run without an OS sandbox; platforms without one
//! refuse.** On macOS the launch path attaches the mandatory Seatbelt profile
//! (a missing `sandbox-exec` is `sandbox_unavailable`, never a bare spawn). A
//! host with no OS sandbox at all (non-macOS) is refused with
//! `sandbox_unavailable` too. The sole exception is a crate built with the
//! `test-util` feature: only test `[dev-dependencies]` enable it, so the
//! offline fixtures can still spawn on Linux, and no production build (the daemon,
//! the CLI) ever compiles that escape hatch.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kernel_broker::{
    ExecutionMode, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, ToolRegistry, Trust,
};
use kernel_privacy::Gate;
use reqwest::header::HeaderMap;
use serde_json::Value;
use tokio::time::Instant;

use crate::client::{client, McpClient, ServerInfo};
use crate::config::{McpConfig, McpServerConfig, McpTransport};
use crate::descriptor::McpToolDescriptor;
use crate::discovery::ToolCatalog;
use crate::http::HttpTransport;
use crate::limits::{Limits, CALL_TOOL_TIMEOUT};
use crate::naming::valid_wire_component;
use crate::stdio::{StdioCommand, StdioLimits, StdioTransport};
use crate::tools::RemoteTool;

/// Whole-server discovery budget at daemon startup (one server).
pub const STARTUP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Most `tools/list` resume rounds a startup discovery follows.
pub const MAX_DISCOVERY_ROUNDS: usize = 4;
/// Budget for one dotted tool call.
pub const MCP_CALL_TIMEOUT: Duration = CALL_TOOL_TIMEOUT;

/// Why one configured server did not start.
///
/// Every variant is content-free: only ids, environment **names** and fixed
/// labels, never a server-supplied string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpStartError {
    /// A declared `env` name had no value in `~/.auxesis/.env`.
    MissingSecret {
        /// The missing variable name.
        name: String,
    },
    /// The pinned launch command was refused.
    Command(&'static str),
    /// The transport could not be built.
    Transport(&'static str),
    /// `initialize` or `tools/list` failed.
    Discovery(&'static str),
    /// The mandatory macOS stdio sandbox is unavailable (item 8).
    SandboxUnavailable,
    /// The whole discovery crossed [`STARTUP_DISCOVERY_TIMEOUT`].
    Timeout,
}

impl McpStartError {
    /// A stable, content-free classification for status and logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::MissingSecret { .. } => "missing_secret",
            Self::Command(_) => "command_refused",
            Self::Transport(_) => "transport_unavailable",
            Self::Discovery(_) => "discovery_failed",
            Self::SandboxUnavailable => "sandbox_unavailable",
            Self::Timeout => "timeout",
        }
    }
}

impl fmt::Display for McpStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSecret { name } => write!(f, "missing secret `{name}`"),
            Self::Command(label) => write!(f, "invalid stdio command ({label})"),
            Self::Transport(kind) => write!(f, "transport unavailable ({kind})"),
            Self::Discovery(kind) => write!(f, "discovery failed ({kind})"),
            Self::SandboxUnavailable => f.write_str("stdio sandbox unavailable"),
            Self::Timeout => f.write_str("discovery timed out"),
        }
    }
}

/// Lifecycle state of one configured server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpServerState {
    /// Discovery completed.
    Ready,
    /// `enabled = false`.
    Disabled,
    /// An uncurated `stdio` server whose exact launch has not been confirmed by
    /// the owner. It is quarantined (never spawned) until it is.
    NeedsConfirmation,
    /// The entry is unusable (a hard-refused launch, a catalog mismatch, a
    /// legacy shape). It is quarantined one by one; other servers still load.
    Quarantined,
    /// Discovery failed (isolated; the daemon keeps running).
    Failed,
}

impl McpServerState {
    /// Stable lowercase label used by the CLI and audit rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Disabled => "disabled",
            Self::NeedsConfirmation => "needs_confirmation",
            Self::Quarantined => "quarantined",
            Self::Failed => "failed",
        }
    }
}

/// A refusal the caller's policy applies before any transport is built.
///
/// The `reason` is a fixed, content-free label (shown in the API and UI);
/// `state` distinguishes "needs the owner's confirmation" from "unusable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerRefusal {
    /// Lifecycle state to report for the refused server.
    pub state: McpServerState,
    /// Stable, content-free reason label.
    pub reason: &'static str,
}

impl McpServerRefusal {
    /// An uncurated `stdio` server that needs the owner's confirmation.
    pub fn needs_confirmation(reason: &'static str) -> Self {
        Self {
            state: McpServerState::NeedsConfirmation,
            reason,
        }
    }

    /// An unusable entry (catalog mismatch, hard refusal, legacy shape).
    pub fn quarantined(reason: &'static str) -> Self {
        Self {
            state: McpServerState::Quarantined,
            reason,
        }
    }

    /// A server the policy allowed but that failed before discovery (for
    /// example an egress refusal).
    pub fn failed(reason: &'static str) -> Self {
        Self {
            state: McpServerState::Failed,
            reason,
        }
    }
}

/// One server's status, with no tool content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerStatus {
    /// Configured id.
    pub id: String,
    /// `http` / `stdio`.
    pub transport: &'static str,
    /// Whether the file enabled it.
    pub enabled: bool,
    /// Lifecycle state.
    pub state: McpServerState,
    /// Tools discovery produced (0 for disabled/failed/quarantined).
    pub tool_count: usize,
    /// Stable, content-free reason for a non-ready state.
    pub reason: Option<&'static str>,
}

/// One tool an agent may call: an [`kernel_broker::Tool`] over one MCP connection.
pub struct McpTool {
    descriptor: McpToolDescriptor,
    client: Arc<dyn McpClient>,
    timeout: Duration,
    /// The privacy row of the server's transport (B13 HTTP, B14 stdio).
    path: kernel_core::privacy::PathId,
}

impl McpTool {
    /// Wrap `descriptor` over `client`. `path` is the privacy row for the
    /// server's transport (see [`transport_path`]).
    pub fn new(
        descriptor: McpToolDescriptor,
        client: Arc<dyn McpClient>,
        timeout: Duration,
        path: kernel_core::privacy::PathId,
    ) -> Self {
        Self {
            descriptor,
            client,
            timeout,
            path,
        }
    }

    /// The descriptor behind this tool.
    pub fn descriptor(&self) -> &McpToolDescriptor {
        &self.descriptor
    }
}

/// The privacy row for an MCP transport: HTTP is B13, a local `stdio` child
/// is B14.
pub fn transport_path(transport: McpTransport) -> kernel_core::privacy::PathId {
    match transport {
        McpTransport::Http => kernel_core::privacy::PathId::B13,
        McpTransport::Stdio => kernel_core::privacy::PathId::B14,
    }
}

impl fmt::Debug for McpTool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpTool")
            .field("wire_name", &self.descriptor.wire_name)
            .field("server", &self.descriptor.server)
            .field("risk", &self.risk())
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        &self.descriptor.wire_name
    }

    fn path_id(&self) -> kernel_core::privacy::PathId {
        self.path
    }

    fn schema(&self) -> Value {
        self.descriptor.schema.clone()
    }

    fn risk(&self) -> Risk {
        self.descriptor.risk()
    }

    /// The whole class, in one value:
    ///
    /// * no MCP tool can be allowed by a wildcard rule; only a rule naming
    ///   `mcp__<server>__<tool>` exactly may auto-run it. Its risk rests on the
    ///   server's own annotations (never corroborated), so a lying server that
    ///   marks `delete_everything` read-only must not ride an `allow *` rule;
    /// * every MCP result may carry owner data: the
    ///   class is declared, never inferred from the server;
    /// * MCP results are third-party content: data, never instructions;
    /// * MCP calls never run outside the sandbox dimension: they have none;
    /// * the arguments go to a third-party server: the engine screens them for
    ///   identifiers, and holds the call in a conversation that carries private
    ///   data (the arguments are a send, whatever the server says).
    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            risk_is_corroborated: false,
            output_trust: Trust::Untrusted,
            execution_mode: ExecutionMode::Sandboxed,
            returns_private_data: true,
            arguments_leave_machine: true,
            ..ToolClass::default()
        }
    }

    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        // Item 5: the arguments a server receives are built from the call's
        // grant. A call without one (a caller that skipped `gate_dispatch`)
        // fails closed instead of sending raw JSON. A stdio server with no
        // network is a local destination; the grant is minted by the engine's
        // gate either way, and this path never sends the raw `Value`.
        let refused = || ToolError::PrivacyDisabled {
            path: self.path.as_str(),
        };
        let grant = ctx.grant().ok_or_else(refused)?;
        // The grant must be this tool's own row: a grant minted for another
        // path carries another policy (mask or pass through), so running under
        // it would send arguments the caller never admitted for this server.
        // A caller that skipped `gate_dispatch` or wired the wrong row fails
        // closed here, before any argument is built or any client is called.
        if grant.path() != self.path {
            return Err(refused());
        }
        // Open mode sends the arguments as they are. Private mode: the model
        // wrote them from session tokens, so those stay (the server never gets
        // a value) and anything still in the clear is masked.
        let mut gate = match grant.policy() {
            kernel_core::privacy::GrantPolicy::Passthrough => Gate::for_passthrough(grant),
            kernel_core::privacy::GrantPolicy::Tokenised => {
                Gate::for_session_tokens(grant, ctx.session_tokens.clone().unwrap_or_default())
            }
        }
        .map_err(|_| refused())?;
        let (safe, report) = gate.value(args).map_err(|err| {
            ToolError::fetch(format!("MCP arguments refused by the privacy gate: {err}"))
        })?;
        if !report.is_empty() {
            // The report says what was (private) or would have been (open)
            // masked, logged without a value.
            tracing::debug!(
                tool = %self.descriptor.wire_name,
                report = %report,
                "MCP arguments admitted"
            );
        }
        let outcome = self
            .client
            .call_tool(&self.descriptor.remote_name, &safe, self.timeout)
            .await
            .map_err(|err| ToolError::fetch(format!("MCP call failed: {}", err.kind())))?;
        let text = outcome.untrusted_text();
        Ok(if outcome.is_error {
            ToolOutput::error(text)
        } else {
            ToolOutput::ok(text)
        })
    }
}

/// Every discovered server, ready to mount per agent.
pub struct McpRuntime {
    config: McpConfig,
    catalog: ToolCatalog,
    clients: BTreeMap<String, Arc<dyn McpClient>>,
    statuses: Vec<McpServerStatus>,
    call_timeout: Duration,
}

impl fmt::Debug for McpRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpRuntime")
            .field("servers", &self.statuses)
            .field("tools", &self.catalog.len())
            .finish()
    }
}

impl Default for McpRuntime {
    fn default() -> Self {
        Self {
            config: McpConfig::default(),
            catalog: ToolCatalog::new(),
            clients: BTreeMap::new(),
            statuses: Vec::new(),
            call_timeout: MCP_CALL_TIMEOUT,
        }
    }
}

impl McpRuntime {
    /// An empty runtime: no server, no tool, no client.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Discover every enabled server of `config`, isolating each failure.
    ///
    /// `secrets` holds the resolved `~/.auxesis/.env` values for the declared
    /// `env` names; a name without a value fails only that server and is
    /// logged by name, never by value.
    pub async fn start(config: McpConfig, secrets: &BTreeMap<String, String>) -> Self {
        Self::start_with(config, secrets, McpStartOptions::default(), &|_| Ok(())).await
    }

    /// Like [`McpRuntime::start`], with the daemon's per-server policy.
    ///
    /// `filter` runs before any transport is built. Returning `Err(refusal)`
    /// quarantines that server — it is reported with the refusal's state and
    /// reason — and every other server still comes up. This is where the
    /// daemon applies the catalog/confirmation policy and the existing `[web]`
    /// egress policy.
    pub async fn start_with(
        config: McpConfig,
        secrets: &BTreeMap<String, String>,
        options: McpStartOptions,
        filter: &(dyn Fn(&McpServerConfig) -> Result<(), McpServerRefusal> + Send + Sync),
    ) -> Self {
        let mut runtime = Self {
            config: config.clone(),
            ..Self::default()
        };
        // Item 6: entries that failed to deserialize are reported as
        // quarantined, so the API/CLI still lists them next to the valid ones.
        for quarantined in config.quarantined.iter().cloned() {
            runtime.statuses.push(McpServerStatus {
                id: quarantined.id,
                transport: quarantined
                    .transport
                    .map(McpTransport::as_str)
                    .unwrap_or("unknown"),
                enabled: false,
                state: McpServerState::Quarantined,
                tool_count: 0,
                reason: Some(quarantined.reason),
            });
        }
        for server in config.server.iter().cloned() {
            let status = |state, reason, tool_count| McpServerStatus {
                id: server.id.clone(),
                transport: server.transport.as_str(),
                enabled: server.enabled,
                state,
                tool_count,
                reason,
            };
            if !server.enabled {
                runtime
                    .statuses
                    .push(status(McpServerState::Disabled, None, 0));
                continue;
            }
            if server.transport == McpTransport::Http && !server.env.is_empty() {
                // The names are validated but only a stdio child receives
                // them; an HTTP endpoint gets no header from this file.
                tracing::warn!(
                    server = %server.id,
                    "declared env names are injected into stdio servers only"
                );
            }
            if let Err(refusal) = filter(&server) {
                tracing::warn!(
                    server = %server.id,
                    state = refusal.state.as_str(),
                    reason = refusal.reason,
                    "MCP server quarantined; continuing without it"
                );
                runtime
                    .statuses
                    .push(status(refusal.state, Some(refusal.reason), 0));
                continue;
            }
            let outcome = tokio::time::timeout(
                STARTUP_DISCOVERY_TIMEOUT,
                discover_server(&server, secrets, options.clone()),
            )
            .await;
            match outcome {
                Ok(Ok((client, tools))) => {
                    // The daemon quarantines a catalog id whose transport or
                    // endpoint does not match the catalog entry *before* this
                    // point, so only a verified catalog server can use its
                    // catalog id as a toolkit name. A `stdio` server never
                    // registers under a catalog toolkit name (item 7), even if
                    // a caller bypasses the daemon policy filter.
                    let toolkit = match server.transport {
                        McpTransport::Http => server.catalog_id.clone().unwrap_or_default(),
                        McpTransport::Stdio => String::new(),
                    };
                    let stats = runtime
                        .catalog
                        .replace_server_tools(&server.id, &toolkit, &tools);
                    runtime.clients.insert(server.id.clone(), client);
                    runtime
                        .statuses
                        .push(status(McpServerState::Ready, None, stats.registered));
                }
                Ok(Err(err)) => {
                    tracing::warn!(
                        server = %server.id,
                        reason = %err,
                        "MCP server unavailable; continuing without it"
                    );
                    // Item 8: a missing mandatory sandbox is a quarantine
                    // (the entry is unusable here), not a transient failure.
                    let state = if matches!(err, McpStartError::SandboxUnavailable) {
                        McpServerState::Quarantined
                    } else {
                        McpServerState::Failed
                    };
                    runtime.statuses.push(status(state, Some(err.kind()), 0));
                }
                Err(_) => {
                    tracing::warn!(
                        server = %server.id,
                        seconds = STARTUP_DISCOVERY_TIMEOUT.as_secs(),
                        "MCP server discovery timed out; continuing without it"
                    );
                    runtime
                        .statuses
                        .push(status(McpServerState::Failed, Some("timeout"), 0));
                }
            }
        }
        runtime
    }

    /// Stop the local process of every server in this runtime. Calls made
    /// afterwards through a tool that still holds the runtime fail; nothing
    /// is respawned by this method.
    pub async fn stop_child_processes(&self) {
        for client in self.clients.values() {
            client.stop().await;
        }
    }

    /// The parsed configuration this runtime was built from.
    pub fn config(&self) -> &McpConfig {
        &self.config
    }

    /// Every server's status, in file order.
    pub fn statuses(&self) -> &[McpServerStatus] {
        &self.statuses
    }

    /// Number of discovered descriptors across every server.
    pub fn tool_count(&self) -> usize {
        self.catalog.len()
    }

    /// The discovered descriptors of one server, in wire-name order.
    pub fn descriptors_for(&self, server_id: &str) -> Vec<&McpToolDescriptor> {
        self.catalog
            .descriptors()
            .filter(|descriptor| descriptor.server == server_id)
            .collect()
    }

    /// Mount `agent`'s explicitly listed tools on `registry`.
    ///
    /// Returns how many were registered. A name the agent lists but discovery
    /// never produced is a warning; a tool already registered under the same
    /// name (a native tool) is never overwritten.
    pub fn register_for_agent(&self, agent: &str, registry: &mut ToolRegistry) -> usize {
        let mut requested: Vec<String> = Vec::new();
        for server in &self.config.server {
            if !server.enabled {
                continue;
            }
            let Some(list) = server.agents.get(agent) else {
                continue;
            };
            for remote in list {
                if !valid_wire_component(remote) {
                    continue;
                }
                if let Some(wire) = self.catalog.wire_for(&server.id, remote) {
                    requested.push(wire.to_owned());
                }
            }
        }
        let selection = self.catalog.for_agent(&requested);
        for missing in &selection.missing {
            tracing::warn!(
                agent,
                wire = %missing,
                "MCP tool listed for this agent was not discovered"
            );
        }
        if selection.over_cap_total > 0 {
            tracing::warn!(
                agent,
                withheld = selection.over_cap_total,
                cap = crate::discovery::PER_AGENT_TOOL_CAP,
                "MCP tools withheld by the per-agent cap"
            );
        }
        let mut registered = 0usize;
        for descriptor in selection.tools {
            let Some(client) = self.clients.get(&descriptor.server) else {
                continue;
            };
            let name = descriptor.wire_name.clone();
            if registry.get(&name).is_some() {
                continue;
            }
            let path = self
                .config
                .server
                .iter()
                .find(|server| server.id == descriptor.server)
                .map_or(kernel_core::privacy::PathId::B14, |server| {
                    transport_path(server.transport)
                });
            registry.register(Box::new(McpTool::new(
                descriptor,
                Arc::clone(client),
                self.call_timeout,
                path,
            )));
            // `mcp__` already marks output untrusted on registration; the
            // explicit mark keeps the class even if the name hook changes.
            registry.mark_untrusted_output(name.clone());
            // Deliberately **not** `mark_read_only`: the read-only class means
            // "read-only by construction", and a server's own `readOnlyHint`
            // is untrusted (see `RiskBasis`). No wildcard `allow` applies to an
            // MCP tool either (`requires_explicit_rule`): with no exact-name
            // rule the broker asks.
            registered += 1;
        }
        registered
    }
}

/// Build the client for one server and run `initialize` + `tools/list`.
/// Daemon-owned hardening applied to every transport it builds.
///
/// There is deliberately **no** field that turns the `stdio` Seatbelt sandbox
/// off. Sandboxing is unconditional on macOS: the launch path attaches the
/// profile itself, and a host without `sandbox-exec` is refused rather than
/// executed unsandboxed (item 8, security review P2 seal). The only platform carve-out is
/// the `cfg(not(target_os = "macos"))` branch inside the *private* sandbox
/// builder, which no caller can reach through this struct.
///
/// # No public opt-out (compile-time tripwire)
///
/// The two fields below are exhaustive and the struct is not
/// `#[non_exhaustive]`, so this literal stops compiling the moment a
/// `sandbox_stdio`-style switch is added back:
///
/// ```compile_fail
/// # use kernel_mcp::McpStartOptions;
/// let _ = McpStartOptions {
///     network_guard: true,
///     confirmation_secret: None,
///     sandbox_stdio: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct McpStartOptions {
    /// Enforce the shared SSRF guard and pin the resolved address for runtime
    /// `http` connections (`false` for the loopback tests).
    pub network_guard: bool,
    /// The daemon-held confirmation key. A `stdio` server is always re-checked
    /// at spawn time against its stored confirmation, which also re-hashes the
    /// binary (item 4).
    ///
    /// `None` **refuses** every `stdio` launch (defence in depth, item 6): a
    /// caller with no key can never verify a confirmation, so it must not be a
    /// silent bypass. Tests that need to spawn the fixture supply a key and a
    /// matching `stdio_confirmation`.
    pub confirmation_secret: Option<Vec<u8>>,
}

impl Default for McpStartOptions {
    /// Fail closed (item 9): the SSRF guard is on, and an empty confirmation key
    /// means every `stdio` server is refused at spawn unless a caller supplies
    /// an explicit, non-empty key. The `stdio` sandbox is **not** an option
    /// here — the launch path always attaches it on macOS.
    fn default() -> Self {
        Self {
            network_guard: true,
            confirmation_secret: Some(Vec::new()),
        }
    }
}

async fn discover_server(
    server: &McpServerConfig,
    secrets: &BTreeMap<String, String>,
    options: McpStartOptions,
) -> Result<(Arc<dyn McpClient>, Vec<RemoteTool>), McpStartError> {
    let client = build_client(server, secrets, options).await?;
    client
        .initialize()
        .await
        .map_err(|err| McpStartError::Discovery(err.kind()))?;
    let deadline = Instant::now() + STARTUP_DISCOVERY_TIMEOUT;
    let mut tools = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_DISCOVERY_ROUNDS {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(McpStartError::Timeout);
        }
        let page = tokio::time::timeout(remaining, client.list_tools(cursor.as_deref()))
            .await
            .map_err(|_| McpStartError::Timeout)?
            .map_err(|err| McpStartError::Discovery(err.kind()))?;
        tools.extend(page.tools);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok((client, tools)),
        }
    }
    Ok((client, tools))
}

/// Build one transport/client pair from the validated server config.
async fn build_client(
    server: &McpServerConfig,
    secrets: &BTreeMap<String, String>,
    options: McpStartOptions,
) -> Result<Arc<dyn McpClient>, McpStartError> {
    match server.transport {
        McpTransport::Http => {
            let url = server
                .url
                .as_deref()
                .ok_or(McpStartError::Command("missing url"))?;
            let transport = if options.network_guard {
                HttpTransport::new_checked(url, HeaderMap::new(), Limits::default()).await
            } else {
                HttpTransport::new(url, HeaderMap::new(), Limits::default())
            }
            .map_err(|err| McpStartError::Transport(err.kind()))?;
            Ok(client(Arc::new(transport), ServerInfo::default()))
        }
        McpTransport::Stdio => {
            let transport =
                build_stdio_transport(server, secrets, options.confirmation_secret.as_deref())?;
            Ok(client(Arc::new(transport), ServerInfo::default()))
        }
    }
}

/// Build the pinned, confirmed `stdio` transport for one server.
///
/// This is the **single** spawn path: [`build_client`] calls it and the
/// acceptance test calls it, so "the sandbox is attached" is proven against the
/// very code that spawns. On macOS the Seatbelt profile is a required argument
/// to [`StdioTransport::new`] — there is no parameter, flag or option that skips
/// it, and the crate-private unsandboxed constructor is unreachable outside
/// kernel-mcp.
///
/// A missing `sandbox-exec` on macOS is [`McpStartError::SandboxUnavailable`]
/// (a quarantine), never a silent unsandboxed spawn. On a platform without an
/// OS sandbox the private [`stdio_sandbox`] returns `None` (`cfg` path) and the
/// launch path **refuses** with [`McpStartError::SandboxUnavailable`]: a caller
/// of the public API on Linux gets a quarantine, not an unsandboxed child. The
/// only escape hatch is a build with the `test-util` feature, which only test
/// `[dev-dependencies]` enable ([`unsandboxed_stdio_transport`]).
fn build_stdio_transport(
    server: &McpServerConfig,
    secrets: &BTreeMap<String, String>,
    confirmation_secret: Option<&[u8]>,
) -> Result<StdioTransport, McpStartError> {
    let command = server
        .command
        .as_deref()
        .ok_or(McpStartError::Command("missing command"))?;
    // Item 8: canonicalise once and use that exact path for the policy
    // re-check, the confirmation digest **and** the spawn, so a symlink
    // cannot be swapped between the check and `execve`.
    let canonical = canonical_stdio_program(command);
    let mut launch = server.clone();
    launch.command = Some(canonical.clone());
    // Re-run the policy at spawn time, not only at parse time: a
    // symlink retargeted after load is caught here.
    aux_crate_stdio_recheck(&launch)?;
    // Item 4: re-verify at spawn time. The digest includes the binary's
    // SHA-256, so a binary swapped after confirmation is refused here.
    // Item 6 (defence in depth): a missing key is not a bypass — with
    // no key nothing can be confirmed, so the spawn is refused.
    match confirmation_secret {
        Some(secret) if launch.stdio_is_confirmed_with(secret) => {}
        _ => return Err(McpStartError::Command("confirmation_missing")),
    }
    let mut pinned = StdioCommand::new(canonical.as_str())
        .map_err(|_| McpStartError::Command("invalid absolute command"))?
        .args(server.args.iter().cloned());
    for name in &server.env {
        let Some(value) = secrets.get(name) else {
            return Err(McpStartError::MissingSecret { name: name.clone() });
        };
        pinned = pinned
            .env_declared(name, value.clone())
            .map_err(|_| McpStartError::Command("declared env key refused"))?;
    }
    let limits = StdioLimits::default();
    // Item 8: the Seatbelt profile is a *required* constructor argument, never
    // an option attached afterwards. On macOS `stdio_sandbox` yields the
    // mandatory wrapper or refuses the spawn. A host with no OS sandbox at all
    // is refused too: only a `test-util` build (the test suites'
    // `[dev-dependencies]`) may build the raw crate-private transport.
    match stdio_sandbox(server)? {
        Some(sandbox) => StdioTransport::new(pinned, limits, sandbox)
            .map_err(|_| McpStartError::Command("invalid stdio limits")),
        None => unsandboxed_stdio_transport(pinned, limits, test_util_enabled()),
    }
}

/// Whether this build may run a `stdio` server with no OS sandbox attached.
///
/// `true` only with the `test-util` feature, which nothing but a
/// `[dev-dependencies]` entry enables (kernel-mcp's own and the daemon's integration
/// tests). Every production build (the app's daemon and CLI) answers `false`, so a host
/// without an OS sandbox refuses the spawn instead of running a bare child.
const fn test_util_enabled() -> bool {
    cfg!(feature = "test-util")
}

/// Build the transport for a host with no OS sandbox, or refuse.
///
/// `test_util` is [`test_util_enabled`] at the launch site; it is a parameter so
/// a unit test can drive the production answer (`false`) directly, without
/// needing a separate build that omits the feature. A refusal is
/// [`McpStartError::SandboxUnavailable`]: a server the platform cannot sandbox
/// is quarantined, never spawned raw.
fn unsandboxed_stdio_transport(
    pinned: StdioCommand,
    limits: StdioLimits,
    test_util: bool,
) -> Result<StdioTransport, McpStartError> {
    if !test_util {
        return Err(McpStartError::SandboxUnavailable);
    }
    test_only_stdio_transport(pinned, limits)
}

/// The `test-util`-gated escape hatch to the crate-private unsandboxed
/// constructor. A production build has no such path.
#[cfg(feature = "test-util")]
fn test_only_stdio_transport(
    pinned: StdioCommand,
    limits: StdioLimits,
) -> Result<StdioTransport, McpStartError> {
    StdioTransport::new_for_tests(pinned, limits)
        .map_err(|_| McpStartError::Command("invalid stdio limits"))
}

/// Without `test-util` there is no escape hatch. The launch site never asks for
/// one in this build: `test_util` comes from the very feature this branch is
/// compiled out of.
#[cfg(not(feature = "test-util"))]
fn test_only_stdio_transport(
    _pinned: StdioCommand,
    _limits: StdioLimits,
) -> Result<StdioTransport, McpStartError> {
    Err(McpStartError::SandboxUnavailable)
}

/// The canonical (symlink-resolved) program path when it exists, else the path
/// as written.
///
/// The policy re-check, the confirmation digest and the spawn all use this one
/// value, so the file that was checked is the file that is executed (item 8).
fn canonical_stdio_program(command: &str) -> String {
    std::fs::canonicalize(command)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| command.to_owned())
}

/// Re-run the stdio hard-refusal policy against the current filesystem.
fn aux_crate_stdio_recheck(server: &McpServerConfig) -> Result<(), McpStartError> {
    let Some(command) = server.command.as_deref() else {
        return Err(McpStartError::Command("missing command"));
    };
    crate::config::evaluate_stdio_policy(&server.id, command, &server.args, server.network)
        .map(|_| ())
        .map_err(|_| McpStartError::Command("policy refused at spawn time"))
}

/// Build the shared macOS Seatbelt wrapper, or `None` where unsupported.
///
/// The launch path calls this for **every** `stdio` server, with no option to
/// skip it. On macOS the wrapper is mandatory: if `sandbox-exec` is missing the
/// spawn is refused (`sandbox_unavailable`), never silently unsandboxed
/// (item 8). On a host with no Seatbelt at all the `cfg(not(target_os =
/// "macos"))` branch returns `None`; the launch path then refuses with
/// `sandbox_unavailable` ([`unsandboxed_stdio_transport`]), except in a
/// `test-util` build. That is a platform property, not a caller switch.
fn stdio_sandbox(
    server: &McpServerConfig,
) -> Result<Option<kernel_broker::sandbox::StdioSandbox>, McpStartError> {
    stdio_sandbox_at(
        server,
        std::path::Path::new(kernel_broker::sandbox::SANDBOX_EXEC),
    )
}

/// Testable core of [`stdio_sandbox`]: `sandbox_exec` is passed in so a test
/// can point it at a missing binary and exercise the refusal.
fn stdio_sandbox_at(
    server: &McpServerConfig,
    sandbox_exec: &std::path::Path,
) -> Result<Option<kernel_broker::sandbox::StdioSandbox>, McpStartError> {
    let Some(command) = server.command.as_deref() else {
        return Ok(None);
    };
    #[cfg(target_os = "macos")]
    {
        if !sandbox_exec.is_file() {
            return Err(McpStartError::SandboxUnavailable);
        }
        kernel_broker::sandbox::StdioSandbox::new(std::path::Path::new(command), server.network)
            .map(Some)
            .map_err(|_| McpStartError::SandboxUnavailable)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (command, sandbox_exec);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stdio_server(id: &str, command: &str) -> McpServerConfig {
        McpServerConfig {
            id: id.to_owned(),
            catalog_id: None,
            data_class: crate::McpDataClass::Sensitive,
            stdio_confirmed: false,
            stdio_confirmation: None,
            network: false,
            transport: McpTransport::Stdio,
            url: None,
            command: Some(command.to_owned()),
            args: Vec::new(),
            env: Vec::new(),
            enabled: true,
            agents: Default::default(),
        }
    }

    #[test]
    fn sandbox_unavailable_refuses_a_stdio_spawn_on_macos() {
        let server = stdio_server("s", "/usr/local/bin/tool");
        let missing = std::path::Path::new("/nonexistent/sandbox-exec");
        let outcome = stdio_sandbox_at(&server, missing);
        if cfg!(target_os = "macos") {
            let err = outcome.expect_err("a missing sandbox-exec must refuse, never degrade");
            assert_eq!(err.kind(), "sandbox_unavailable");
        } else {
            assert!(outcome.is_ok(), "non-macOS keeps the current behaviour");
        }
    }

    /// On a host with no OS sandbox and no `test-util`, the launch path must
    /// refuse, never spawn a bare child.
    ///
    /// [`unsandboxed_stdio_transport`] takes the decision as a parameter, so
    /// this drives the value a production build computes (`false`) directly. It
    /// therefore holds in this test build too, even though the self
    /// dev-dependency has `test-util` on. `true` is the documented escape hatch
    /// and is exercised by the spawn-path test above.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_stdio_without_test_util_is_refused() {
        let command = StdioCommand::new("/usr/bin/true").expect("absolute path");
        let err = unsandboxed_stdio_transport(command, StdioLimits::default(), false)
            .expect_err("a non-macOS host without `test-util` must refuse, never spawn");
        assert_eq!(err, McpStartError::SandboxUnavailable);
        assert_eq!(err.kind(), "sandbox_unavailable");
    }

    #[test]
    fn spawn_time_confirmation_rejects_a_swapped_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("server");
        std::fs::write(&bin, b"one").unwrap();
        let mut server = stdio_server("s", &bin.to_string_lossy());
        let secret = b"daemon-key";
        server.stdio_confirmed = true;
        server.stdio_confirmation = server.confirmation_binding(secret);
        assert!(server.stdio_is_confirmed_with(secret));
        std::fs::write(&bin, b"two").unwrap();
        assert!(
            !server.stdio_is_confirmed_with(secret),
            "a binary swapped after confirmation must fail the spawn-time digest"
        );
    }

    #[test]
    fn stdio_spawn_uses_the_canonical_path_that_was_hashed() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-tool");
        std::fs::write(&real, b"binary").unwrap();
        let link = dir.path().join("link-tool");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let canonical = canonical_stdio_program(&link.to_string_lossy());
        assert_eq!(
            canonical,
            std::fs::canonicalize(&real).unwrap().to_string_lossy(),
            "the spawn path must be the resolved target, not the symlink"
        );

        // The confirmation binds the canonical path: confirming the link and
        // then retargeting it invalidates the confirmation (item 8).
        let secret = b"daemon-key";
        let mut server = stdio_server("s", &link.to_string_lossy());
        server.stdio_confirmed = true;
        server.stdio_confirmation = server.confirmation_binding(secret);
        assert!(server.stdio_is_confirmed_with(secret));
        let other = dir.path().join("other-tool");
        std::fs::write(&other, b"binary").unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert!(
            !server.stdio_is_confirmed_with(secret),
            "retargeting the symlink must invalidate the confirmation"
        );
    }

    #[test]
    fn start_options_expose_no_sandbox_opt_out() {
        // Compile-time absence. `McpStartOptions` is a plain public struct (not
        // `#[non_exhaustive]`) and this literal names every field, so adding a
        // `sandbox_stdio`-style switch back breaks the build here. The struct's
        // `compile_fail` doctest is the same tripwire from a caller's view.
        let options = McpStartOptions {
            network_guard: true,
            confirmation_secret: None,
        };
        assert!(options.network_guard);
        assert!(options.confirmation_secret.is_none());
    }

    #[test]
    fn default_start_options_fail_closed() {
        let options = McpStartOptions::default();
        assert!(options.network_guard, "the SSRF guard is on by default");
        let secret = options
            .confirmation_secret
            .as_deref()
            .expect("a key is present so an unconfirmed stdio launch is refused");
        let mut server = stdio_server("s", "/usr/local/bin/tool");
        server.stdio_confirmed = true;
        assert!(
            !server.stdio_is_confirmed_with(secret),
            "an empty default key can never confirm a server"
        );
    }

    /// The one spawn path must attach the Seatbelt profile on macOS.
    ///
    /// [`build_stdio_transport`] is exactly what [`build_client`] calls for a
    /// `stdio` server, so this asserts against the code that spawns, not a
    /// stand-in. It takes no sandbox argument: on macOS the profile is always
    /// attached, and no key means the spawn is refused before the transport
    /// exists. On a host with no Seatbelt this test build has `test-util` on
    /// (the self dev-dependency), so the private `cfg(not(target_os = "macos"))`
    /// branch leaves `sandbox` empty — a platform property the public API
    /// cannot influence. A production build on that host refuses instead
    /// (`non_macos_stdio_without_test_util_is_refused`).
    #[test]
    fn stdio_spawn_path_has_no_public_sandbox_opt_out() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("server");
        std::fs::write(&bin, b"fake-server").unwrap();
        let secret = b"daemon-key";
        let mut server = stdio_server("s", &bin.to_string_lossy());
        server.stdio_confirmed = true;
        server.stdio_confirmation = server.confirmation_binding(secret);

        let transport = build_stdio_transport(&server, &BTreeMap::new(), Some(secret))
            .expect("a confirmed server builds its transport");
        if cfg!(target_os = "macos") {
            assert!(
                transport.has_sandbox(),
                "macOS must always attach the profile: the spawn path has no \
                 sandbox opt-out"
            );
        } else {
            assert!(
                !transport.has_sandbox(),
                "this host has no Seatbelt; the platform `cfg` branch is what \
                 leaves the transport bare, never a caller flag"
            );
        }

        // Defence in depth: no confirmation key still refuses the spawn, so
        // the missing sandbox can never be reached through a keyless caller.
        assert!(
            build_stdio_transport(&server, &BTreeMap::new(), None).is_err(),
            "a keyless caller must never reach the spawn path"
        );
    }

    #[tokio::test]
    async fn runtime_start_refuses_an_unconfirmed_stdio_server_by_default() {
        let runtime = McpRuntime::start(
            McpConfig::from_servers(vec![stdio_server("s", "/usr/local/bin/tool")]),
            &BTreeMap::new(),
        )
        .await;
        assert_eq!(runtime.statuses().len(), 1);
        assert_eq!(
            runtime.statuses()[0].state,
            McpServerState::Failed,
            "the default options must refuse an unconfirmed stdio spawn"
        );
        assert_eq!(runtime.statuses()[0].reason, Some("command_refused"));
        assert_eq!(runtime.tool_count(), 0);
    }

    /// A client that is never called: the privacy test only checks the registry.
    struct NoClient;

    #[async_trait]
    impl crate::client::McpClient for NoClient {
        async fn initialize(&self) -> Result<crate::client::ServerInfo, crate::McpError> {
            unreachable!("the privacy test never talks to the server")
        }
        async fn list_tools(
            &self,
            _cursor: Option<&str>,
        ) -> Result<crate::tools::ToolPage, crate::McpError> {
            unreachable!("the privacy test never talks to the server")
        }
        async fn call_tool(
            &self,
            _name: &str,
            _args: &kernel_privacy::SafeValue,
            _timeout: Duration,
        ) -> Result<crate::tools::CallOutcome, crate::McpError> {
            unreachable!("the privacy test never talks to the server")
        }
    }

    fn crm_tool(path: kernel_core::privacy::PathId) -> (String, McpTool) {
        let remote: RemoteTool = serde_json::from_value(serde_json::json!({
            "name": "lookup_contact",
            "inputSchema": {"type": "object"}
        }))
        .expect("remote tool");
        let wire = crate::naming::wire_name("crm", "lookup_contact");
        let descriptor =
            McpToolDescriptor::from_remote("crm", "", wire.clone(), &remote).expect("descriptor");
        let tool = McpTool::new(descriptor, Arc::new(NoClient), Duration::from_secs(5), path);
        (wire, tool)
    }

    #[test]
    fn a_sensitive_http_server_tool_stays_mounted_in_private_mode() {
        // The server's transport decides the row (B13 for HTTP). TOK-7: it is
        // Covered, so the tool stays registered and the model is offered it.
        let path = transport_path(McpTransport::Http);
        let (wire, tool) = crm_tool(path);
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(tool));

        let dropped = kernel_broker::retain_mountable(
            &mut registry,
            kernel_core::privacy::PrivacyMode::Private,
        );
        assert!(dropped.is_empty());
        assert!(registry.get(&wire).is_some());
    }

    #[test]
    fn the_same_tool_stays_registered_in_open_mode() {
        let (wire, tool) = crm_tool(transport_path(McpTransport::Stdio));
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(tool));

        assert!(kernel_broker::retain_mountable(
            &mut registry,
            kernel_core::privacy::PrivacyMode::Open
        )
        .is_empty());
        assert!(registry.get(&wire).is_some());
    }

    #[tokio::test]
    async fn a_grant_for_another_path_never_reaches_the_mcp_server() {
        // Seal P3-2: the tool runs only under its own row's grant. A grant
        // minted for a different path — a caller that skipped `gate_dispatch`,
        // or a wiring bug that swapped two servers' rows — is refused before
        // the arguments are built, so no payload reaches the server under a
        // policy nobody admitted for it. `NoClient` panics if it is called,
        // which is what proves the refusal happened first.
        let path = transport_path(McpTransport::Http);
        let (_wire, tool) = crm_tool(path);
        let grant = kernel_core::privacy::admit_call(
            kernel_core::privacy::PathId::C9,
            kernel_core::privacy::PrivacyMode::Open,
            kernel_core::privacy::Destination::LocalDisplay,
        )
        .expect("C9 is covered and allowed in open mode");
        assert_ne!(grant.path(), path, "the probe must use a foreign grant");
        let ctx = ToolCtx::new("main", std::env::temp_dir()).with_grant(grant);
        let args = serde_json::json!({});

        match tool.run(&args, &ctx).await {
            Err(ToolError::PrivacyDisabled { path: refused }) => {
                assert_eq!(refused, path.as_str())
            }
            other => panic!("expected privacy_disabled, got {other:?}"),
        }
    }
}
