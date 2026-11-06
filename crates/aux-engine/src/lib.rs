//! The Auxesis engine: souls, system prompts, the chat/tool loop, and the
//! configuration plumbing every runner needs.
//!
//! This crate is the reusable core behind `aux chat` and the daemon's
//! scheduled jobs. The CLI keeps its presentation layer (REPL, arguments,
//! approver selection); the daemon keeps its scheduler. Both drive the same
//! [`ChatSession`] here:
//!
//! - [`soul`] loads (or creates) `<home>/agents/<agent>/soul.md`;
//! - [`prompt`] turns a soul and a tool registry into the system prompt;
//! - [`engine`] runs one turn: provider calls, permission broker, budgets,
//!   persistence, and an optional [`stop::StopCheck`] kill-switch gate;
//! - [`workspace`] keys the workspace-level taint mark: dispatching an
//!   untrusted-class tool touches the whole workspace, and only the owner
//!   clears it;
//! - [`trust`] is the owner-presence proof behind that clear: a one-time code
//!   delivered only through the owner's local notification, so no tool, model
//!   or command line can complete a trust request on its own;
//! - [`approver`] ships the non-interactive approval policies
//!   ([`DenyApprover`], [`AutoApproveApprover`]) and the interactive
//!   [`StdinApprover`];
//! - [`config`] selects a provider entry and loads `[[rules]]`.
//!
//! Everything stays deterministic and offline in tests: providers and
//! approvers are injected through the public setup types.

pub mod action;
pub mod approver;
pub mod cancel;
pub mod config;
pub mod engine;
pub mod events;
pub mod handoff;
pub mod judge;
pub mod layout;
mod outbound;
mod private;
pub mod prompt;
mod read_guard;
pub mod skill_runtime;
pub mod skills;
pub mod soul;
pub mod stop;
pub mod taint;
pub mod trust;
pub mod workspace;

pub use approver::{AutoApproveApprover, DenyApprover, StdinApprover};
pub use cancel::TurnCancel;
pub use config::{
    append_rule, load_rules, registry_from_config, select_provider, shell_sandbox,
    ProviderSelectError, RulesError,
};
pub use engine::{
    gated_audit_sink, gated_store_write, gated_usage_write, is_stop_refusal, stop_settle_worker,
    validate_agent, watch_held_reservations, ChatError, ChatSession, ChatSetup, HeldReservation,
    SettleStore, ToolGate, TurnOutcome, ESTIMATED_UNIT, MAX_TOOL_ROUNDS,
};
pub use events::{ToolEndOutcome, TurnEvents};
#[cfg(feature = "ner-gliner")]
pub use outbound::install_deep_detector;
pub use outbound::session_gate;
#[cfg(any(test, feature = "test-util"))]
pub use outbound::test_seam;
pub use prompt::build_system_prompt;
pub use skills::{load_active as load_active_skills, ActiveSkill, SkillInfo, SkillStatus};
pub use soul::{
    agent_dir, agents_dir, default_soul, load_or_create, soul_path, workspace_dir, Soul,
    SoulStatus, DEFAULT_SOUL, MAX_SOUL_BYTES,
};
pub use stop::{marker_engaged, MarkerStop, ModeChangeStop, StopCheck};
pub use trust::{
    complete_trust, refuse_when_unsandboxed_shell, request_trust, TrustCompleted, TrustError,
    TrustRequested, TRUST_CODE_TTL_SECS, TRUST_MAX_ATTEMPTS, TRUST_REQUEST_COOLDOWN_SECS,
};
pub use workspace::{resolve_agent_workspace, workspace_key, WorkspacePathError};

/// Remove `AUX_KEY_*` variables from this process environment.
///
/// Called after key material has been loaded (Keychain, `.env`, or process
/// env), so a child process reading our environment (`ps eww`, a shell tool
/// spawned by a scheduled job) can never see it.
pub fn scrub_process_key_env() {
    let keys: Vec<String> = std::env::vars()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with("AUX_KEY_"))
        .collect();
    for key in keys {
        std::env::remove_var(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_key_env_is_scrubbed() {
        std::env::set_var("AUX_KEY_ENGINE_SCRUB_TEST", "canary");
        scrub_process_key_env();
        assert!(std::env::var("AUX_KEY_ENGINE_SCRUB_TEST").is_err());
    }
}
