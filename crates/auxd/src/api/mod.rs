//! The `auxd` local API (B-API v1): HTTP + WebSocket on **127.0.0.1 only**.
//!
//! This is the contract the desktop app (and later a phone on a private
//! network) talks to: it reaches only this server and never touches the store,
//! the engine or the Keychain.
//!
//! # Security model
//!
//! - The listener is created by [`bind_loopback`], which accepts a port and
//!   nothing else: binding to a non-loopback address is impossible by
//!   construction (there is no API that takes an address).
//! - Every route, health and the WebSocket upgrade included, requires
//!   `Authorization: Bearer <token>`; anything else is `401` with a JSON
//!   body. The token lives at `~/.auxesis/api.token` (`0600`), is generated
//!   on first run from `/dev/urandom`, and is never logged (it is redacted
//!   from `Debug`).
//! - No CORS headers are ever emitted: this server is for the native app.
//!
//! # Surface
//!
//! See [`routes`] for the endpoint table. Reads never write (every store
//! read is `SQLITE_OPEN_READ_ONLY`); `POST /v1/threads/{id}/messages` runs
//! one engine turn exactly like `aux chat` (budget reservations, STOP gate)
//! and appends to the agent's current session — creating it only on first use.
//! With the live channel wired, `ask` decisions become pending approvals
//! ([`approval::ApiApprover`]): the WS publishes `approval.new`, the turn
//! waits (bounded, fail-closed) for `POST /v1/approvals/{id}`, and every
//! persisted message / tool step / phase transition streams as a WS frame.
//! B-API v3 adds the write surface: providers read/test, agent create/update
//! and per-agent pause/resume/kill, stop-all, and a real `first_run` gate on
//! `GET /v1/health`. Mode, settings, screen, audit and provider writes still
//! answer `501` with a machine-readable body.
//!
//! # Fan-out mode
//!
//! `WS /v1/events` is **poll-based** for journal rows + agent snapshots (one
//! background task every [`ApiState::event_poll`]) and **push-based** for
//! live turn events (engine [`aux_engine::TurnEvents`] → [`events`] frames
//! through the same broadcast ring). See [`events`] for the message shape.

mod agents;
mod approval;
pub(crate) mod approval_preview;
mod auth;
pub mod brief;
#[cfg(test)]
pub(crate) mod canary;
mod clients;
mod contacts;
mod coverage;
mod deltas;
pub(crate) mod display;
mod docs_api;
mod docs_export;
pub(crate) mod error;
mod events;
mod extensions;
mod first_run;
#[cfg(feature = "google")]
mod google;
pub mod jobs;
pub(crate) mod mcp_plugins;
mod notify_test;
mod private_answers;
mod providers;
pub mod receipt;
mod refusal;
mod routes;
mod security;
mod skills;
pub(crate) mod snapshot;
#[cfg(test)]
mod surface_guard;
mod turn;
mod turn_cancels;
pub(crate) mod turn_events;
pub(crate) mod wire;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub use approval::{ApprovalRegistry, PendingApproval, Resolution, DEFAULT_APPROVAL_TIMEOUT};
pub use auth::{token_path, ApiToken};
pub use private_answers::{HeldAnswer, PrivateAnswers, MAX_HELD};
// The delta stream is an internal component, but its registry-pinning
// lifecycle needs a process-isolated integration test (R7-1); the type is
// hidden from the documented surface.
use crate::gateway::router::NotifyRouter;
use aux_brief::BriefSource;
use aux_notify::{system_notifier, Notifier};
use aux_providers::ChatProvider;
#[doc(hidden)]
pub use deltas::{DeltaStream, StreamSinks};
pub use snapshot::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, MESSAGE_MAX_BYTES};
use tokio::sync::broadcast;
#[cfg(any(test, feature = "test-util"))]
pub use turn::ToolRegistryHook;
pub use turn::{EngineTurnRunner, FailingTurnRunner, TurnError, TurnRecord, TurnRunner};
use turn_cancels::TurnCancels;

/// Port the local API listens on by default (T9 for `auxd`: 2-8-9-3).
pub const DEFAULT_API_PORT: u16 = 2893;

/// Environment override for the port (`0` = ephemeral, for tests).
pub const API_PORT_ENV: &str = "AUXESIS_API_PORT";

/// How often the WS broadcaster polls the store in production.
pub const DEFAULT_EVENT_POLL: Duration = Duration::from_secs(1);

/// Largest accepted request body (POST JSON).
pub const MAX_REQUEST_BODY_BYTES: usize = 128 * 1024;

/// Largest accepted `content` of a chat message (bytes).
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;

/// Shared state of the API server.
pub struct ApiState {
    /// Auxesis home the API serves.
    pub(crate) home: PathBuf,
    /// Store file (read-only guests open it directly).
    pub(crate) db_path: PathBuf,
    /// Bearer token expected on every request.
    pub(crate) token: ApiToken,
    /// Broadcast ring fed by the store poller.
    pub(crate) events: broadcast::Sender<String>,
    /// Poll interval of the WS broadcaster.
    pub(crate) event_poll: Duration,
    /// Runs chat turns (`POST /v1/threads/{id}/messages`).
    pub(crate) runner: Arc<dyn TurnRunner>,
    /// Hard cap on one API turn (E-14). On expiry the turn's cancellation
    /// token is fired and the client gets `504 turn_timeout`.
    pub(crate) turn_timeout: Duration,
    /// Pending approvals + their waiters (in-memory).
    pub(crate) approvals: Arc<ApprovalRegistry>,
    /// Cancellation tokens of in-flight turns, keyed by agent: pause/kill and
    /// stop-all fire them so the turn aborts now (B-API v3 × E-18).
    pub(crate) turn_cancels: Arc<TurnCancels>,
    /// Owner notification channel for trust requests: the one-time code is
    /// delivered here and nowhere else (osascript in production, a fake in
    /// tests).
    pub(crate) notifier: Arc<dyn Notifier>,
    /// The daemon's morning-brief source, shared with the scheduled job so
    /// `POST /v1/brief/run` reads the exact same calendar and mailbox.
    pub(crate) brief_source: Option<Arc<dyn BriefSource>>,
    /// The daemon's notify router, so an explicit run routes its counts-only
    /// notification exactly as the scheduled one does.
    pub(crate) notify_router: Option<Arc<NotifyRouter>>,
    /// When `POST /v1/notify/test` last ran: at most one send a minute.
    pub(crate) notify_test_last: std::sync::Mutex<Option<std::time::Instant>>,
    /// One owner-started Google consent flow at a time (G4). The browser opens
    /// only from `POST /v1/google/connect`, never here or in a background path.
    #[cfg(feature = "google")]
    pub(crate) google_flow: Arc<google::FlowGuard>,
    /// The one writer lock for `config.toml` (and the provider `.env`), shared
    /// by every route that reads, modifies and atomically replaces the file
    /// (settings, provider create/key, allow-always rule). A whole-file
    /// rewrite under this lock cannot silently drop a concurrent append.
    /// Guards are only ever taken inside `spawn_blocking`, never across an
    /// `.await`.
    pub(crate) config_write: Arc<std::sync::Mutex<()>>,
    /// Serializes MCP config writes and runtime replacement as one operation.
    pub(crate) mcp_mutation: Arc<tokio::sync::Mutex<()>>,
    /// Monotone generation of the persisted MCP configuration.
    pub(crate) mcp_generation: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) mcp: Arc<std::sync::RwLock<Arc<kernel_mcp::McpRuntime>>>,
    /// Request/answer channel to the bundled Mac app (`docs/phase1.md` §3).
    pub(crate) bridge: Arc<crate::bridge::Bridge>,
    /// D33: the delegation runner the `delegate` tool and resume use.
    pub(crate) delegations: Arc<dyn crate::delegation::DelegationExecutor>,
    /// D33: per-delegation cancel tokens a task Stop fires.
    pub(crate) delegation_cancels: Arc<crate::delegation::DelegationCancels>,
    /// Pending sends Stop all cancelled the last time it ran (`GET /v1/stop`).
    pub(crate) stop_cancelled: std::sync::atomic::AtomicUsize,
    /// Private-mode iMessage answers, in memory only (C12).
    pub(crate) private_answers: Arc<PrivateAnswers>,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiState")
            .field("home", &self.home)
            .field("db_path", &self.db_path)
            .field("event_poll", &self.event_poll)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Knobs of [`spawn`].
#[derive(Clone)]
pub struct ApiOptions {
    /// Port to bind (`0` = ephemeral, the actual port lands in
    /// [`ApiHandle::addr`]).
    pub port: u16,
    /// WS poll interval (tests shrink it; production uses 1 s).
    pub event_poll: Duration,
    /// Turn runner override (tests inject a failing runner; `None` uses the
    /// real engine).
    pub runner: Option<Arc<dyn TurnRunner>>,
    /// Chat provider override: tests inject a scripted fake; `None` builds
    /// the provider from the config on every turn.
    pub provider: Option<Arc<dyn ChatProvider>>,
    /// Tool-registry override: tests swap a host-bound tool (the sandboxed
    /// `shell` on hosts without one) for a deterministic stand-in; `None`
    /// keeps the config-built registry. Test-util only.
    #[cfg(any(test, feature = "test-util"))]
    pub tools: Option<ToolRegistryHook>,
    /// How long an API approval may wait before the fail-closed deny.
    ///
    /// `None` reads `[approval] timeout_secs` from `config.toml` (default
    /// 600 s, clamped strictly below the turn timeout). Tests pin one.
    pub approval_timeout: Option<Duration>,
    /// Hard cap on one API turn. `None` reads `turn_timeout_secs` from
    /// `config.toml` (default 1800 s).
    pub turn_timeout: Option<Duration>,
    /// Notification transport for owner trust requests. `None` uses the real
    /// macOS notifier; tests inject a recording fake so no notification is
    /// ever shown.
    pub notifier: Option<Arc<dyn Notifier>>,
    /// Local macOS sink for the fixed waiting-approval phrase when no gateway
    /// is paired (APPROVAL-NO-GATEWAY). `None` leaves it to the phone router.
    pub approval_local: Option<Arc<dyn Notifier>>,
    /// Morning-brief source shared with the scheduled job. `None` makes
    /// `POST /v1/brief/run` answer `source_unavailable`.
    pub brief_source: Option<Arc<dyn BriefSource>>,
    /// Notify router shared with the daemon. `None` makes
    /// `POST /v1/brief/run` answer `source_unavailable`.
    pub notify_router: Option<Arc<NotifyRouter>>,
    /// Discovered MCP runtime (P2/P4), shared with the job runner and the
    /// privacy watch. `None` starts with no MCP tool.
    pub mcp: Option<crate::mcp::McpSlot>,
    /// Mounted extensions (WO-13b). `None` starts with no extension tool.
    pub extensions: Option<crate::extensions::ExtSlot>,
    /// D33: the delegation runner. `None` runs the domain agent's own turn.
    pub delegations: Option<Arc<dyn crate::delegation::DelegationExecutor>>,
    /// D33: one delegated turn's deadline. `None` uses the built-in 120 s.
    pub delegation_timeout: Option<Duration>,
    /// Test seam: the real origin of tools a `ToolRegistryHook` registers.
    /// Test-util only.
    #[cfg(any(test, feature = "test-util"))]
    pub tool_origins: Vec<(String, aux_runtime::grants::ToolOrigin)>,
}

impl Default for ApiOptions {
    fn default() -> Self {
        Self {
            port: DEFAULT_API_PORT,
            event_poll: DEFAULT_EVENT_POLL,
            runner: None,
            provider: None,
            #[cfg(any(test, feature = "test-util"))]
            tools: None,
            approval_timeout: None,
            turn_timeout: None,
            notifier: None,
            approval_local: None,
            brief_source: None,
            notify_router: None,
            mcp: None,
            extensions: None,
            delegations: None,
            delegation_timeout: None,
            #[cfg(any(test, feature = "test-util"))]
            tool_origins: Vec::new(),
        }
    }
}

impl ApiOptions {
    /// Defaults with the port read from [`API_PORT_ENV`] (invalid values are
    /// ignored with a warning).
    pub fn from_env() -> Self {
        let mut options = Self::default();
        if let Ok(raw) = std::env::var(API_PORT_ENV) {
            match raw.trim().parse::<u16>() {
                Ok(port) => options.port = port,
                Err(_) => {
                    tracing::warn!(
                        value = %raw,
                        "ignoring invalid {API_PORT_ENV} (expected a port number)"
                    );
                }
            }
        }
        options
    }
}

/// A running API server.
pub struct ApiHandle {
    addr: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    state: Arc<ApiState>,
}

/// The configured turn timeout for a turn no HTTP route wraps (TOOL-HANG): the
/// token fires once `limit` passes, so a turn left waiting ends with
/// `cancelled` instead of holding its channel. Dropping the guard disarms it.
struct TurnDeadline {
    _disarm: std::sync::mpsc::Sender<()>,
}

impl TurnDeadline {
    fn start(token: Arc<aux_engine::TurnCancel>, limit: Duration) -> Self {
        let (disarm, armed) = std::sync::mpsc::channel::<()>();
        let _ = std::thread::Builder::new()
            .name("auxd-turn-deadline".into())
            .spawn(move || {
                if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = armed.recv_timeout(limit) {
                    token.cancel();
                }
            });
        Self { _disarm: disarm }
    }
}

/// Trusted in-process access used by the daemon-owned text channels. It shares the
/// daemon's runner and approval registry with app API requests.
#[derive(Clone)]
pub struct ChannelApiHandle {
    state: Arc<ApiState>,
}

impl ChannelApiHandle {
    /// The in-memory holder for Private-mode channel answers.
    pub fn private_answers(&self) -> Arc<PrivateAnswers> {
        Arc::clone(&self.state.private_answers)
    }

    pub fn run_turn(&self, session_id: i64, content: &str) -> Result<TurnRecord, TurnError> {
        let agent = crate::agent::default_chat_agent(&self.state.home);
        let registration = self.state.turn_cancels.register(&agent);
        let _deadline = TurnDeadline::start(registration.token(), self.state.turn_timeout);
        self.state.runner.run_turn(
            &agent,
            Some(session_id),
            content,
            Some(registration.token()),
        )
    }

    /// Like [`Self::run_turn`], with nothing published on `/v1/events`.
    pub fn run_turn_quiet(&self, session_id: i64, content: &str) -> Result<TurnRecord, TurnError> {
        let agent = crate::agent::default_chat_agent(&self.state.home);
        let registration = self.state.turn_cancels.register(&agent);
        let _deadline = TurnDeadline::start(registration.token(), self.state.turn_timeout);
        self.state.runner.run_turn_quiet(
            &agent,
            Some(session_id),
            content,
            Some(registration.token()),
        )
    }

    pub fn pending_approvals(&self) -> Vec<PendingApproval> {
        self.state.approvals.pending()
    }

    pub fn approval_timeout(&self) -> std::time::Duration {
        self.state.approvals.timeout()
    }

    pub async fn resolve_approval(&self, id: &str, allow: bool) -> bool {
        routes::resolve_telegram_approval(Arc::clone(&self.state), id, allow).await
    }

    /// Issue an opaque, single-use callback nonce bound to a pending approval.
    pub fn issue_approval_nonce(&self, id: &str) -> Option<String> {
        self.state.approvals.issue_callback_nonce(id)
    }

    /// Redeem a callback nonce to the approval it answers, once. A raw approval
    /// id, an unknown nonce or a replay all get `None`.
    pub fn redeem_approval_nonce(&self, nonce: &str) -> Option<String> {
        self.state.approvals.redeem_callback_nonce(nonce)
    }

    pub fn approval_nonce_target(&self, nonce: &str) -> Option<String> {
        self.state.approvals.callback_nonce_target(nonce)
    }
}

impl ApiHandle {
    /// Address actually bound (loopback).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The Mac bridge shared with the app's answer route. Public so the bridge
    /// integration test can drive one call end to end before a tool uses it.
    pub fn bridge(&self) -> Arc<crate::bridge::Bridge> {
        Arc::clone(&self.state.bridge)
    }

    /// Trusted in-process access for daemon-owned text channels. The name is
    /// deliberately channel-neutral: turns use the same runner and approval
    /// registry as the app.
    pub fn channel_access(&self) -> ChannelApiHandle {
        ChannelApiHandle {
            state: Arc::clone(&self.state),
        }
    }

    /// Stop the server and the broadcaster (aborts their tasks).
    pub fn shutdown(&self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Bind the API port on `127.0.0.1` — the only bind this module can produce.
///
/// There is intentionally no address parameter: an external (`0.0.0.0`) bind
/// cannot be requested through this API.
pub fn bind_loopback(port: u16) -> std::io::Result<std::net::TcpListener> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Load `config.toml` through the process's verified home when one exists
/// (production): the handle re-verifies identity and creates through the
/// fd-relative gateway, so a swapped home cannot plant or redirect the file
/// (J-02 round 4). The path fallback only serves unit tests that never ran
/// `ensure_home`.
pub fn load_config_verified(home: &Path) -> Result<kernel_core::Config, kernel_core::ConfigError> {
    // Fail closed: always verify (and register) the home, never a raw path.
    let handle = kernel_core::verified_home_or_verify(home)?;
    kernel_core::Config::load_or_create_verified(&handle)
}

/// Start the local API on `home`.
///
/// Loads (or creates) the API token, binds loopback, spawns the store
/// poller and the HTTP server. Must be called from within a tokio runtime.
pub fn spawn(home: &Path, options: ApiOptions) -> std::io::Result<ApiHandle> {
    // H-03 port tripwire (defense in depth for direct callers): a sandbox
    // never binds the real daemon port.
    if let Err(err) = kernel_core::ensure_sandbox_port(options.port) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            err,
        ));
    }
    kernel_core::ensure_home(home)?;
    let db_path = kernel_core::store_path(home);
    match aux_store::Store::open(&db_path) {
        Ok(store) => {
            if let Err(err) = aux_docs::recover_erased_evidence(&store, home) {
                tracing::warn!(error = %err, "could not finish erased document cleanup");
            }
        }
        Err(err) => tracing::warn!(error = %err, "could not check erased document cleanup"),
    }
    let token = ApiToken::load_or_create(home)?;
    let listener = bind_loopback(options.port)?;
    let addr = listener.local_addr()?;
    let listener = tokio::net::TcpListener::from_std(listener)?;

    let (sender, _receiver) = broadcast::channel(events::EVENT_CHANNEL_CAPACITY);
    // Both bounds come from `config.toml` unless a test pinned one (H-04:
    // `[approval] timeout_secs`, clamped strictly below the turn timeout).
    // A config that cannot be read falls back to the compiled-in defaults;
    // the approval deny stays fail-closed either way.
    let config = load_config_verified(home).ok();
    let turn_timeout = options.turn_timeout.unwrap_or_else(|| {
        config
            .as_ref()
            .map(|config| config.turn_timeout())
            .unwrap_or_else(|| Duration::from_secs(kernel_core::config::DEFAULT_TURN_TIMEOUT_SECS))
    });
    let approval_timeout = options.approval_timeout.unwrap_or_else(|| {
        config
            .as_ref()
            .map(|config| config.approval_timeout())
            .unwrap_or(DEFAULT_APPROVAL_TIMEOUT)
    });
    let approvals = ApprovalRegistry::new(approval_timeout);
    approvals.set_language(
        config
            .as_ref()
            .map(|config| config.ui.language)
            .unwrap_or_default(),
    );
    if let Some(local) = &options.approval_local {
        approvals.set_local_notifier(local.clone());
    }
    if let Some(router) = &options.notify_router {
        approvals.set_phone_notifier(router.clone());
    }
    let turn_cancels = Arc::new(TurnCancels::new());
    let mcp = options.mcp.clone().unwrap_or_else(|| {
        Arc::new(std::sync::RwLock::new(Arc::new(
            kernel_mcp::McpRuntime::empty(),
        )))
    });
    // The Mac bridge pushes on the same events broadcast (one frame per
    // request); the answer route wakes the matching pending call. It is built
    // before the runner and the delegations so the EventKit tools can hold it.
    let bridge = Arc::new(crate::bridge::Bridge::new(
        home.to_path_buf(),
        sender.clone(),
    ));
    let delegation_cancels = Arc::new(crate::delegation::DelegationCancels::new());
    let delegations: Arc<dyn crate::delegation::DelegationExecutor> =
        options.delegations.clone().unwrap_or_else(|| {
            let executor = crate::delegation::EngineDelegationExecutor::new(
                home.to_path_buf(),
                options.provider.clone(),
                Some(Arc::clone(&approvals)),
            )
            .with_bridge(Arc::clone(&bridge));
            let executor = match options.delegation_timeout {
                Some(deadline) => executor.with_deadline(deadline),
                None => executor,
            };
            #[cfg(any(test, feature = "test-util"))]
            let executor = match &options.tools {
                Some(tools) => executor.with_tools(Arc::clone(tools)),
                None => executor,
            };
            Arc::new(executor)
        });
    let runner = options.runner.clone().unwrap_or_else(|| {
        let mut runner = EngineTurnRunner::new(home)
            .with_events(sender.clone())
            .with_approvals(Arc::clone(&approvals))
            .with_delegations(Arc::clone(&delegations))
            .with_delegation_cancels(Arc::clone(&delegation_cancels))
            .with_bridge(Arc::clone(&bridge));
        #[cfg(any(test, feature = "test-util"))]
        {
            runner = runner.with_tool_origins(options.tool_origins.clone());
        }
        if let Some(provider) = &options.provider {
            runner = runner.with_provider(Arc::clone(provider));
        }
        #[cfg(any(test, feature = "test-util"))]
        {
            if let Some(tools) = &options.tools {
                runner = runner.with_tools(Arc::clone(tools));
            }
        }
        // P2/P4: the discovered MCP servers; each turn mounts only the caller
        // agent's explicitly listed tools.
        runner = runner.with_mcp_handle(Arc::clone(&mcp));
        // WO-13b: the mounted extensions, same per-dot rule.
        if let Some(extensions) = &options.extensions {
            runner = runner.with_extensions_handle(Arc::clone(extensions));
        }
        Arc::new(runner)
    });
    let state = Arc::new(ApiState {
        home: home.to_path_buf(),
        db_path: kernel_core::store_path(home),
        token,
        events: sender,
        event_poll: options.event_poll,
        runner,
        // E-14: the turn timeout comes from `[config]` unless a test pinned
        // one.
        turn_timeout,
        approvals,
        turn_cancels,
        notifier: options
            .notifier
            .clone()
            .unwrap_or_else(|| system_notifier(kernel_core::sandbox_guard_active())),
        brief_source: options.brief_source.clone(),
        notify_router: options.notify_router.clone(),
        notify_test_last: std::sync::Mutex::new(None),
        #[cfg(feature = "google")]
        google_flow: Arc::new(google::FlowGuard::default()),
        config_write: Arc::new(std::sync::Mutex::new(())),
        mcp_mutation: Arc::new(tokio::sync::Mutex::new(())),
        mcp_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        mcp,
        bridge,
        delegations,
        delegation_cancels,
        stop_cancelled: std::sync::atomic::AtomicUsize::new(0),
        private_answers: Arc::new(PrivateAnswers::default()),
    });

    // Orphaned pending approvals (in-memory, lost to a restart) get one
    // audit line each before the server accepts traffic.
    approval::recover_stale_pending(&state.db_path);
    if let Err(err) = crate::delegation::recover_interrupted(home) {
        tracing::warn!(error = %err, "could not recover interrupted delegations");
    }

    let broadcaster = events::start_broadcaster(Arc::clone(&state));
    let router = routes::router(Arc::clone(&state));
    let server = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router).await {
            tracing::error!(error = %err, "local API server stopped");
        }
    });

    Ok(ApiHandle {
        addr,
        tasks: vec![broadcaster, server],
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_is_loopback_only_by_construction() {
        let listener = bind_loopback(0).unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback(), "must bind 127.0.0.1, got {addr}");
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn default_options_parse_the_env_port() {
        let options = ApiOptions::default();
        assert_eq!(options.port, DEFAULT_API_PORT);
        assert_eq!(options.event_poll, DEFAULT_EVENT_POLL);
        assert!(options.runner.is_none());

        // The parsing rule used by `from_env`, without mutating the process
        // environment (tests run in parallel).
        assert_eq!("2893".trim().parse::<u16>().unwrap(), 2893);
        assert_eq!("0".trim().parse::<u16>().unwrap(), 0);
        assert!("not-a-port".trim().parse::<u16>().is_err());
    }

    #[test]
    fn api_state_debug_redacts_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let token = ApiToken::load_or_create(dir.path()).unwrap();
        let text = format!("{token:?}");
        assert_eq!(text, "ApiToken(<redacted>)");
    }
}
