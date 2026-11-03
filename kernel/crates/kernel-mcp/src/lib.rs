//! `kernel-mcp` — the generic JSON-RPC 2.0 / MCP protocol client for Auxesis.
//!
//! S0 ships the vendor-free skeleton: the envelope types, the bounded frame
//! readers, the typed error surface and the [`Transport`] seam. S1 adds the
//! network layer on top of that seam ([`HttpTransport`] plus the [`McpClient`]
//! operations), still without any vendor knowledge.
//!
//! # Why the bounds live here and not in the transport
//!
//! A response body that is parsed before it is bounded is an unbounded
//! allocation driven by a third party. [`limits::read_frame`] therefore stops
//! while streaming and reports [`McpError::FrameTooLarge`]; a caller can never
//! observe a truncated JSON error instead.
//!
//! # Completeness is the transport's duty (the S0/S1 boundary)
//!
//! [`limits::read_frame`] reads until the reader reports EOF, so at S0 it
//! cannot tell a complete body from a **truncated-but-valid prefix**: only the
//! transport (S1) knows whether a `Content-Length` was satisfied or an SSE
//! stream delivered its terminal event. Truncation detection therefore belongs
//! to the transport, not to this crate; `read_frame` alone never proves
//! completeness.
//!
//! [`McpError::FrameTooLarge`] is **terminal for the connection**. When it is
//! returned the reader has stopped at an unknown offset, so the connection
//! must be dropped and never resumed — resuming would parse the tail of an
//! oversized frame as if it were a fresh message (mirroring the app's ACP crate's
//! `Frame::TooLarge` contract). [`McpError::requires_connection_close`] makes
//! that rule callable, and [`limits::read_sse_line`] is subject to the same
//! rule: it cannot re-sync past an over-limit line.
//!
//! # Untrusted text
//!
//! Every server- or peer-supplied string is copied through [`Sanitized`] /
//! [`sanitize_untrusted`] before it reaches a `Display`/`Debug`: bounded to
//! [`MAX_UNTRUSTED_BYTES`] on a character boundary and stripped of control
//! characters, newlines and ANSI escapes. The sanitiser **is not a redactor**
//! — secrets survive it — so callers must never log a raw protocol body.
//!
//! # User-visible wording
//!
//! Nothing here is shown to the owner directly except the `Display` strings
//! of [`McpError`], which stay protocol-neutral on purpose.
//!
//! # S2: descriptors, naming and the discovery cache
//!
//! [`descriptor`] turns a remote [`RemoteTool`] into an Auxesis
//! [`McpToolDescriptor`] with a stable [`wire_name`], a [`McpTag`] set and a
//! sanitised description/schema. [`naming`] owns the deterministic name map;
//! [`discovery`] dedupes the list into a [`ToolCatalog`] and caches it in memory
//! with a TTL. Every name and description here is untrusted, model-visible
//! input: it is data, never an instruction.

// `test-util` widens this crate's constructors for dependents' tests (for
// example `StdioTransport::new_for_tests`, the only public unsandboxed
// constructor). A release build that turns it on would ship a test seam, so it
// is a hard error there: only a debug (test) profile may enable it, and only
// through a `[dev-dependencies]` edge. This is the same rule kernel-privacy and
// kernel-broker carry.
#[cfg(all(feature = "test-util", not(debug_assertions)))]
compile_error!("test-util is dev-only");

pub mod client;
pub mod config;
pub mod descriptor;
pub mod discovery;
pub mod error;
pub mod http;
pub mod identity;
pub mod jsonrpc;
pub mod limits;
pub mod naming;
pub mod runtime;
pub mod sandbox;
pub mod stdio;
pub mod tools;

use std::time::Duration;

pub use client::{client, McpClient, ServerInfo};
pub use config::{
    binary_sha256, evaluate_stdio_policy, is_loopback_host, looks_like_secret, stdio_risk_label,
    wrapper_launcher_label, McpConfig, McpConfigError, McpDataClass, McpServerConfig, McpTransport,
    QuarantinedServer, ServerRefusal, StdioPolicy, MAX_MCP_CONFIG_BYTES, MAX_MCP_SERVERS,
    MAX_MCP_URL_BYTES,
};
pub use descriptor::{
    risk_from_tags, sanitize_description, sanitize_schema, McpTag, McpToolDescriptor,
    ToolkitClassifier, ToolkitMap,
};
pub use discovery::{AgentTools, DiscoveryCache, DiscoveryStats, ToolCatalog, PER_AGENT_TOOL_CAP};
pub use error::{sanitize_untrusted, McpError, McpResult, Sanitized, MAX_UNTRUSTED_BYTES};
pub use http::HttpTransport;
pub use identity::{tool_identity, IdentityDrift, PinnedTools};
pub use jsonrpc::{
    IdGenerator, JsonRpcError, JsonRpcRequest, JsonRpcResponse, Method, ResponseId, JSONRPC_VERSION,
};
pub use limits::Limits;
pub use naming::{
    display_name, logical_name, sanitize_wire_component, wire_name, WireNames, MAX_WIRE_NAME_BYTES,
};
pub use runtime::{
    transport_path, McpRuntime, McpServerRefusal, McpServerState, McpServerStatus, McpStartError,
    McpStartOptions, McpTool, MCP_CALL_TIMEOUT, STARTUP_DISCOVERY_TIMEOUT,
};
pub use sandbox::{seatbelt_profile, SandboxSpec};
pub use stdio::{
    env_key_declared, StdioCommand, StdioLimits, StdioSandbox, StdioTransport, ALLOWED_ENV_KEYS,
    RESERVED_ENV_PREFIXES,
};
pub use tools::{
    CallOutcome, RemoteTool, ToolPage, ToolSchema, ToolSchemaError, UntrustedText,
    UNTRUSTED_MCP_TAG,
};

/// The MCP protocol revision this client opens with (S1 bumps it if the
/// server negotiates a different one).
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// The client name reported in `initialize` `clientInfo`.
pub const CLIENT_NAME: &str = "auxesis";
/// The client version reported in `initialize` `clientInfo`.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The seam every test uses: one bounded round trip.
///
/// Implementations must honour `timeout` themselves and must never retry a
/// `tools/call` (a retried mutation is a double send).
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Send one request and return the decoded response envelope.
    async fn round_trip(
        &self,
        req: JsonRpcRequest,
        timeout: Duration,
    ) -> Result<JsonRpcResponse, McpError>;

    /// Stop any local process this transport owns. A transport with no process
    /// (HTTP) has nothing to stop. Idempotent.
    async fn stop(&self) {}
}
