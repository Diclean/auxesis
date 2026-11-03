//! Tools and the permission broker for Auxesis.
//!
//! Slice C of M1. The interface contract moved out of this repository (see
//! `docs/README.md`).
//!
//! - [`Tool`] is the single interface every tool implements. Tools are
//!   registered in a [`ToolRegistry`] so the chat loop can look them up by
//!   name and hand their [`Tool::schema`] to the model.
//! - [`Broker`] decides whether a call may run: ordered `allow`/`ask`/`deny`
//!   rules per agent, last match wins (defaults first). `ask` consults an [`Approver`] callback,
//!   and **every** decision is audited to the store as a `tool.decision`
//!   event.
//!
//! v1 is intentionally not fully sandboxed: `shell` really runs a shell. The
//! broker and its audit trail are the wall for `shell`; file tools are
//! confined to the agent workspace, and text helpers strip invisible characters
//! from external content.

// `test-util` widens this crate's constructors for dependents' tests (for
// example `ShellSandbox::with_test_sandbox_exec`). A release build that turns
// it on would ship a test seam, so it is a hard error there: only a debug
// (test) profile may enable it, and only through a `[dev-dependencies]` edge.
#[cfg(all(feature = "test-util", not(debug_assertions)))]
compile_error!("test-util is dev-only");

pub mod argument_screen;
mod broker;
mod cancel;
mod error;
pub mod owner_ids;
mod panic_hook;
mod privacy_wiring;
mod registry;
pub mod sandbox;
pub mod scrub;
mod taint;
mod text;
mod tool;

#[cfg(any(test, feature = "test-util"))]
pub use broker::MemoryAuditSink;
pub use broker::{
    matching_rule, Action, ApprovalDecision, ApprovalRequest, Approver, ApproverError, AuditError,
    AuditSink, Authorization, AuthorizeRequest, Broker, BrokerError, ExecutionMode, Rule,
    SkillOnlyLookup, SkillRef, ANY, MAX_EDITED_ARGUMENTS_BYTES, SKILL_ONLY_REASON,
};
pub use cancel::CancelToken;
pub use error::ToolError;
pub use panic_hook::install_payload_free_panic_hook;
pub use privacy_wiring::{gate_dispatch, retain_mountable};
pub use registry::ToolRegistry;
pub use sandbox::{ShellSandbox, StdioSandbox};
pub use taint::{Taint, TaintSource, Trust};
pub use text::{
    classify_echo, guard_log_redaction, is_secret_shaped, redact_identifiers, redact_log_line,
    redact_log_line_guarded, redact_secrets, sanitize_error_detail, sanitize_external_text,
    sanitize_text, scrub_display_text, scrub_external_preview, scrub_json_value, scrub_title,
    EchoState,
};
pub use tool::{
    Declaration, NativeDecl, NativeTool, Risk, Tool, ToolClass, ToolClassExt, ToolCtx, ToolOutput,
};
