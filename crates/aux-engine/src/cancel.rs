//! Cancellation token for one turn.
//!
//! The token type lives in `aux-tools` so tool implementations can observe it
//! through [`kernel_broker::ToolCtx::cancel`]: the engine fires it on client
//! disconnect or the configured turn timeout, and a long-running tool (for
//! example the `shell` tool's process tree) can then run its own cleanup
//! instead of relying on being dropped. Re-exported here under the engine's
//! historical name.
//!
//! Cancelling never rolls back persisted state — the write-ahead taint marks
//! written before an untrusted dispatch must survive exactly as they do for a
//! crash or a timeout.

pub use kernel_broker::CancelToken as TurnCancel;
