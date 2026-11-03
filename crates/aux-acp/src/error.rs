//! Errors of the ACP backend.

use thiserror::Error;

/// Anything that can go wrong spawning, driving or settling an ACP turn.
#[derive(Debug, Error)]
pub enum AcpError {
    /// The `[acp]` configuration is unusable (unknown agent, empty command,
    /// no provider entry, ...).
    #[error("acp config: {0}")]
    Config(String),
    /// The sandbox is required but unavailable, or the scratch workspace is
    /// unsafe to run in. Fail closed, never run unsandboxed implicitly.
    #[error("acp sandbox: {0}")]
    Sandbox(String),
    /// The agent process could not be spawned.
    #[error("spawning the acp agent: {0}")]
    Spawn(#[source] std::io::Error),
    /// The transport is gone: the agent exited, or its stdio closed.
    #[error("acp transport closed")]
    Disconnected,
    /// A malformed frame or an out-of-spec message.
    #[error("acp protocol: {0}")]
    Protocol(String),
    /// The agent sent a frame larger than the configured line cap.
    #[error("acp frame too large (cap {limit} bytes)")]
    FrameTooLarge {
        /// The configured cap.
        limit: usize,
    },
    /// The JSON-RPC peer answered a request with an error.
    #[error("acp request `{method}` failed ({code}): {message}")]
    Rpc {
        /// Method that failed.
        method: String,
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },
    /// A request did not complete within its bounded wait.
    #[error("acp request `{method}` timed out after {secs}s")]
    Timeout {
        /// Method that timed out.
        method: String,
        /// The bounded wait, in seconds.
        secs: u64,
    },
    /// The whole turn exceeded its wall-clock cap.
    #[error("acp turn exceeded its {limit_secs}s wall-clock cap")]
    TurnTimeout {
        /// The configured cap.
        limit_secs: u64,
    },
    /// Too many requests are already in flight.
    #[error("too many pending acp requests (cap {0})")]
    TooManyPending(usize),
    /// The outbound queue is full.
    #[error("acp request queue is full (cap {0})")]
    QueueFull(usize),
    /// The agent asked for a path outside its scratch workspace, or the path
    /// resolved outside it (symlink escape).
    #[error("acp path is outside the agent workspace: {0}")]
    PathEscape(String),
    /// A broker-backed request failed for a structural reason.
    #[error("acp broker: {0}")]
    Broker(String),
    /// The turn was cancelled.
    #[error("acp turn cancelled")]
    Cancelled,
    /// The daily budget denied the turn.
    #[error("budget denied: {reason}")]
    BudgetDenied {
        /// Human-readable reason.
        reason: String,
    },
    /// Store failure while persisting the turn.
    #[error(transparent)]
    Store(#[from] aux_store::StoreError),
    /// Filesystem or process I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
