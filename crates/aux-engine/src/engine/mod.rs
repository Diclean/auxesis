//! The chat loop: provider calls, the tool loop, approvals, and persistence.
//!
//! One [`ChatSession`] is one run of `aux chat` and maps to one store
//! session. Every message — system, user, assistant and tool results — is
//! appended to the store as it happens, so a crash mid-run still leaves an
//! honest history behind.
//!
//! The loop is deliberately single-task: the [`Broker`] borrows the
//! (non-`Sync`) store, so its futures are not `Send` and must not be moved
//! into `tokio::spawn`.

mod approvals;
mod budget;
pub(crate) use budget::{
    admit, admitted, call_estimate, day_denied, request_model, usage_actual, usage_write,
};
pub use budget::{
    gated_usage_write, stop_settle_worker, watch_held_reservations, HeldReservation, SettleStore,
};
mod context;
mod privacy;
mod session;
mod taint;
#[cfg(test)]
mod testsupport;
mod tools;
mod turn;
mod web;

use crate::cancel::TurnCancel;
use crate::events::TurnEvents;
use crate::skill_runtime::SessionTokenStore;
use crate::soul::SoulStatus;
use crate::stop::StopCheck;
use aux_providers::{ChatProvider, ProviderError, SafeMessage, SafeToolSpec};
use aux_runtime::executor::{RecipientDirectory, SkillConnector};
use aux_store::{Session, StoreError, StoreHandle};
use kernel_broker::{Approver, AuditSink, Broker, Rule, Taint, ToolCtx, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::ModeFn;
use kernel_core::ContextConfig;
use kernel_net::{WebBudget, WebGate};
use kernel_privacy::safetext::{Gate, GateError};
use kernel_privacy::ContactIndex;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;

/// Maximum provider completions per user turn before the loop gives up.
pub const MAX_TOOL_ROUNDS: usize = 8;

/// Unit marker for usage amounts derived from text length instead of
/// provider-reported `usage` (providers that do not report usage).
pub use kernel_core::budget::ESTIMATED_UNIT;

/// Output tokens requested for one provider call when enforcing a daily cap.
///
/// The store clamps this "max-tokens-ish" request to the remaining output
/// headroom at admission, and the engine passes the clamped value to the
/// provider as `max_tokens`. With a provider that honors the cap and reports
/// usage honestly, settled output can therefore never exceed the daily cap —
/// under any number of concurrent turns, because each admitted reservation
/// fits under the cap and settles at most its own value. A provider that
/// ignores `max_tokens` can settle the calls already in flight above the cap;
/// the store then latches the day closed, so no further call starts. Input
/// usage remains bounded by the char-based estimate only.
pub const DEFAULT_OUTPUT_RESERVE: u64 = 4_096;

/// How long a cancelled turn waits for a cooperative tool to observe
/// [`ToolCtx::cancel`] and clean up before its future is dropped. The shell
/// tool's `Drop` reaper sweeps the process tree even when this grace expires,
/// so the bound only decides whether the tool gets its own orderly say.
pub const CANCEL_CLEANUP_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Errors that abort a chat run.
#[derive(Debug, Error)]
pub enum ChatError {
    /// Persistence failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The provider failed to complete.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Filesystem failure (agent layout, soul, workspace).
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The agent would exceed a daily cap from `[budgets]`.
    #[error("budget denied: {reason}")]
    BudgetDenied {
        /// Human-readable reason (also audited as `budget.denied`).
        reason: String,
    },
    /// The agent name would not be a safe single path segment.
    #[error("invalid agent name `{agent}`: {reason}")]
    InvalidAgent {
        /// The offending name.
        agent: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The kill switch was engaged between two steps of the turn.
    #[error("stopped by kill switch")]
    Stopped,
    /// The caller cancelled the turn (client disconnect or request timeout).
    #[error("turn cancelled")]
    Cancelled,
    /// [`ChatSetup::session_id`] named a session that does not exist.
    #[error("session {id} not found")]
    SessionMissing {
        /// The missing session id.
        id: i64,
    },
    /// The privacy gate would not issue an outbound value. The text stays
    /// local and nothing is sent for it.
    #[error("the privacy gate kept this text local: {0}")]
    Privacy(#[from] GateError),
    /// The turn's store is borrowed. The broker audits through a shared store
    /// only (its sink must be `Send + Sync`), so the turn cannot start.
    #[error("a chat turn needs a shared store: the broker audits through it")]
    SharedStoreRequired,
    /// A document this turn read was erased while the turn ran. The model
    /// may have echoed its text, so nothing more is sent (ERASE-ACTIVE-TURN).
    #[error("a document used in this reply was erased, so the reply stopped")]
    DocumentErased,
}

/// Everything needed to start one chat session.
pub struct ChatSetup<'a> {
    /// Store to read rules context from and persist to. `Borrowed` keeps the
    /// CLI/job path zero-cost; the daemon passes a shared handle.
    pub store: StoreHandle<'a>,
    /// Chat backend.
    pub provider: &'a dyn ChatProvider,
    /// Tools offered to the model.
    /// The tools, shared with the broker: its skill floor reads the live registry.
    pub registry: Arc<RwLock<ToolRegistry>>,
    /// Ordered permission rules (last match wins — defaults first, exceptions after; no match asks).
    pub rules: Vec<Rule>,
    /// Callback consulted for `ask` decisions.
    pub approver: Arc<dyn Approver>,
    /// Agent this session talks to.
    pub agent: String,
    /// Auxesis home (`$AUXESIS_HOME` or `~/.auxesis`).
    pub home: PathBuf,
    /// The privacy mode in force, read live. The turn's outbound gate runs
    /// under the provider path admitted in this mode.
    pub mode: ModeFn,
    /// The owner's contacts, read once at session start: their names are the
    /// gate's known-names dictionary. The skill run's `known-contacts` directory
    /// is the same index.
    pub contacts: Arc<ContactIndex>,
    /// Owner-selected, already validated instructions for this agent.
    pub skills: Vec<crate::skills::ActiveSkill>,
    /// Per-agent daily caps from `[budgets]` in `config.toml`.
    pub budgets: &'a Budgets,
    /// Per-model price table (`[prices]`), used to record `usd_cents` spend
    /// from token counts when the provider reports no cost.
    pub prices: &'a PriceTable,
    /// Bounded model-context window (`[context]`); see [`ContextConfig`].
    pub context: ContextConfig,
    /// Optional session title stored alongside the run.
    pub title: Option<String>,
    /// Optional kill-switch gate, checked between steps. `None` (interactive
    /// chat) runs to completion; scheduled work passes a
    /// [`MarkerStop`](crate::stop::MarkerStop).
    pub stop: Option<Arc<dyn StopCheck>>,
    /// Optional cancellation token: checked between steps and raced
    /// against provider/tool awaits. A cancelled turn returns
    /// [`ChatError::Cancelled`] and leaves every taint mark untouched.
    pub cancel: Option<Arc<TurnCancel>>,
    /// Append the turn to this existing session instead of creating a new
    /// one. The session must exist ([`ChatError::SessionMissing`] otherwise)
    /// and keeps its single system prompt.
    pub session_id: Option<i64>,
    /// Optional live-event sink (`None` = silent, the CLI and scheduled
    /// jobs).
    pub events: Option<Arc<dyn TurnEvents>>,
    /// Identity of this turn, stamped on every `usage` row it records so a
    /// receipt can attribute spend by identity rather than by a shared
    /// row-id window. `None` for callers that keep no per-turn receipt.
    pub run_id: Option<String>,
}

/// Result of one user turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnOutcome {
    /// Text of the final assistant message (empty when the cap was reached).
    pub text: String,
    /// True when the round cap stopped the loop before a final answer.
    pub capped: bool,
    /// Provider completions used by this turn (`>= 1`).
    pub rounds: usize,
}

/// A live yes/no check for one tool, read before each round offers it.
pub type ToolGate = Arc<dyn Fn() -> bool + Send + Sync>;

/// The state of one chat run: conversation, broker, and workspace.
pub struct ChatSession<'a> {
    agent: String,
    session: Session,
    /// Shared conversation buffer: every round's [`ChatRequest`] shares it
    /// (no per-round deep clone) and it is bounded by
    /// [`ContextConfig`]. Only gated messages live here; the raw text stays
    /// in the store.
    messages: Arc<Vec<SafeMessage>>,
    /// The session's public-input gate: it issues every outbound value.
    gate: Gate,
    tool_specs: Vec<SafeToolSpec>,
    provider: &'a dyn ChatProvider,
    store: StoreHandle<'a>,
    registry: Arc<RwLock<ToolRegistry>>,
    broker: Broker,
    /// Conversation taint state. Sticky once an untrusted-output tool
    /// has run; rebuilt from persisted history when a session is resumed, so
    /// a new turn can never launder earlier untrusted content.
    taint: Taint,
    /// The deterministic web egress policy (`[web]`): the same gate
    /// `http_fetch` holds, applied to the *decision* before the tool runs.
    web: WebGate,
    /// Fetch counters, reserved before the connect. Shared behind a mutex so
    /// a dispatch can also hand them to the fetcher: every redirect hop
    /// reserves its destination from the same counters.
    web_budget: Arc<Mutex<WebBudget>>,
    /// Origins (`scheme://host:port`) this conversation fetched and actually
    /// received a response from. Read only by the non-sensitive mode rules
    /// (`ask_once_per_site`, `smart`): a sensitive turn asks for every fetch,
    /// so this set can never buy a silent request once the turn is sensitive.
    web_seen_origins: BTreeSet<String>,
    /// True once the conversation read private owner data (mail, calendar,
    /// memory, notes). Sticky; reading is silent, but it changes the egress
    /// rule for every later fetch in this conversation.
    carries_private_data: bool,
    /// The privacy mode the session's gate was built under.
    gate_mode: kernel_core::privacy::PrivacyMode,
    /// Whether this conversation's text may reach the store and the event feed.
    /// False in private mode: the feed sees the gated copy (`crate::private`).
    raw_text: bool,
    /// Whether the local store keeps the rows (G1). True in private mode too:
    /// the stored copy holds the values, the feed and the model the tokens.
    keep_history: bool,
    /// The conversation's home, which keys its memory in `crate::private`.
    home: PathBuf,
    /// Messages kept in context, as many as the store window holds.
    window_limit: usize,
    /// Raw owner input for the active turn; used only for local contact binding.
    current_owner_input: Option<String>,
    /// The active turn's persisted input row, used to bound trusted history.
    current_owner_row_id: Option<i64>,
    /// Owner words inherited for one non-owner turn; never included in prompts.
    inherited_owner_words: Option<String>,
    /// Who wrote this turn's input (`delegation` for a task the chief handed
    /// to an agent). Stamped on the turn's own input row, so a reader tells a
    /// delegated ask from the owner's words.
    input_source: Option<String>,
    /// The last memory-only row id handed out. Negative, so it never meets a store id.
    local_rows: std::sync::atomic::AtomicI64,
    /// Canonical key of this agent's workspace. Dispatching an
    /// untrusted-class tool marks the workspace under this key, and every
    /// conversation that starts there is tainted; the owner clears it via
    /// `aux workspace trust`.
    workspace_key: String,
    ctx: ToolCtx,
    max_rounds: usize,
    soul_status: SoulStatus,
    budgets: &'a Budgets,
    prices: &'a PriceTable,
    stop: Option<Arc<dyn StopCheck>>,
    cancel: Option<Arc<TurnCancel>>,
    events: Option<Arc<dyn TurnEvents>>,
    /// Identity of this turn, stamped on every `usage` row it records.
    run_id: Option<String>,
    /// The agent's runtime skills, in loader order.
    runtime_skills: Vec<aux_runtime::skills::LoadedSkill>,
    /// One `skill__<name>` spec per runtime skill.
    skill_specs: Vec<SafeToolSpec>,
    /// The agent's `recipients.allowlist`.
    skill_allowlist: Vec<String>,
    /// The store's audit sink, shared with the executor's `skill.*` rows.
    sink: Arc<dyn AuditSink>,
    /// The broker a skill run uses: each inner call is pre-approved because the
    /// run-level card is the one human approval.
    skill_broker: Broker,
    /// The approval channel, reused for the run-level skill card.
    approver: Arc<dyn Approver>,
    /// Injected connector that runs a skill's write calls.
    skill_connector: Option<Arc<dyn SkillConnector>>,
    /// Set once a skill run has started in this turn. A turn runs its skill at
    /// most once: a later `skill__*` call is refused without a card (F2).
    skill_ran_this_turn: AtomicBool,
    /// CAL-NO-TOOL-GUESS: this turn's read nudge in `messages`, removed at turn end.
    read_nudge_at: Option<usize>,
    /// MEM-FORGET-HANG: this turn's save nudge in `messages`, removed at turn end.
    save_nudge_at: Option<usize>,
    /// Tools an owner setting can switch off mid-turn: a round offers one only
    /// while its check still says yes.
    tool_gates: Vec<(String, ToolGate)>,
    /// Approval cards of this turn that expired unanswered (auxd's approver
    /// counts them); the last one is named in the turn's reply.
    card_expiries: Option<Arc<AtomicUsize>>,
    card_expired: Option<String>,
    /// Injected directory for the `known-contacts` recipient policy.
    skill_recipients: Option<Arc<dyn RecipientDirectory>>,
    /// The session's minted `(token, value)` pairs, for local rehydration.
    skill_tokens: Arc<Mutex<SessionTokenStore>>,
    /// The task's tokens, kept whole, and this run's handoff.
    inherited: Option<Arc<std::collections::BTreeSet<String>>>,
    handoff: crate::handoff::Handoff,
    /// Test seam: when set, budget checks read the day from here instead of
    /// `Store::local_day`. Production always reads the store, so the day is
    /// recomputed at every check and a turn that crosses local midnight
    /// starts enforcing the new day immediately.
    #[cfg(test)]
    day_source: Option<Box<dyn Fn() -> Result<String, StoreError> + Send>>,
    /// Test seam: a budget of the test's own, whose stop the process-wide one
    /// must not take.
    #[cfg(test)]
    budget: Option<&'static budget::Budget>,
}

/// Reject agent names that could escape `<home>/agents/`.
///
/// An agent is one directory name: ASCII letters, digits, `-`, `_` and `.`,
/// at most 64 characters, and neither `.` nor `..`.
pub fn validate_agent(agent: &str) -> Result<(), ChatError> {
    let invalid = |reason: &str| {
        Err(ChatError::InvalidAgent {
            agent: agent.to_string(),
            reason: reason.to_string(),
        })
    };
    if agent.is_empty() {
        return invalid("agent name is empty");
    }
    if agent == "." || agent == ".." {
        return invalid("agent name must not be `.` or `..`");
    }
    if agent.chars().count() > 64 {
        return invalid("agent name is longer than 64 characters");
    }
    if !agent
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return invalid("only ASCII letters, digits, `-`, `_` and `.` are allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_agent_accepts_safe_single_segments() {
        for agent in ["main", "axis-2", "my.agent_1", "a"] {
            assert!(validate_agent(agent).is_ok(), "`{agent}` should be valid");
        }
    }

    #[test]
    fn validate_agent_rejects_path_traversal_and_junk() {
        for agent in ["", ".", "..", "a/b", "a\\b", "a b", "café", "../evil"] {
            assert!(
                matches!(validate_agent(agent), Err(ChatError::InvalidAgent { .. })),
                "`{agent}` should be rejected"
            );
        }
        assert!(validate_agent(&"a".repeat(65)).is_err());
    }
}
