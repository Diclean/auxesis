//! Delegations (D33, WO E0): the chief hands one task to one domain agent.
//!
//! This module is the runtime behind `delegate`: it creates the durable record,
//! streams `delegation.*` events, runs the agent through a
//! [`DelegationExecutor`] and hands the chief **only** the short result. Stop
//! is a store state the executor checks between steps, so a stopped task keeps
//! its partial steps and never blocks its siblings; Stop all stops every open
//! delegation at once.
//!
//! The executor is a seam: production runs the domain agent's own engine turn
//! ([`EngineDelegationExecutor`]); tests inject a scripted one so the event
//! stream is deterministic without a provider.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aux_engine::TurnCancel;
use aux_runtime::grants::DOMAIN_AGENTS;
use aux_store::{Delegation, DelegationState, DelegationStep, Store};
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kernel_broker::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, Trust};
use kernel_core::killswitch;
use kernel_core::privacy::ModeFn;
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::api::error;
use crate::api::ApiState;
use crate::api::EngineTurnRunner;
use crate::api::TurnRunner;

/// Marks the end of a child turn's frames on the delegation's own channel.
const DRAIN_END: &str = "delegation.drain_end";

/// Most steps one delegation keeps.
const MAX_STEPS: usize = 200;

/// Largest task/result/step text the API stores (bytes).
const MAX_DELEGATION_TEXT_BYTES: usize = 8 * 1024;

const DELEGATION_DEADLINE: Duration = Duration::from_secs(120);
const DELEGATION_STOP_GRACE: Duration = Duration::from_secs(5);

/// How often the deadline loop checks whether the child is parked on a card.
const DELEGATION_POLL: Duration = Duration::from_millis(100);

/// How long a pending "sending in 10 s" approval may be undone.
pub const APPROVAL_UNDO_WINDOW: Duration = Duration::from_secs(10);

static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

/// A fresh delegation id (`dl-<millis>-<seq>`).
pub fn new_id() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("dl-{millis}-{seq}")
}

/// In-flight delegation cancel tokens, keyed by delegation id.
///
/// A task Stop fires only that task's token; Stop all fires every one. The
/// token is handed to the child turn's `run_turn`, which checks it before
/// every tool call and on the provider stream, so a stopped task aborts its
/// in-flight work instead of running to completion.
#[derive(Debug, Default)]
pub struct DelegationCancels {
    inner: Mutex<HashMap<String, Vec<Arc<TurnCancel>>>>,
}

impl DelegationCancels {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep `token` reachable under `id` until the guard drops.
    pub fn register(self: &Arc<Self>, id: &str, token: Arc<TurnCancel>) -> DelegationRegistration {
        kernel_core::lock_recover(&self.inner)
            .entry(id.to_string())
            .or_default()
            .push(Arc::clone(&token));
        DelegationRegistration {
            registry: Arc::clone(self),
            id: id.to_string(),
            token,
        }
    }

    /// Fire one task's token.
    pub fn cancel(&self, id: &str) {
        let tokens: Vec<Arc<TurnCancel>> = kernel_core::lock_recover(&self.inner)
            .get(id)
            .cloned()
            .unwrap_or_default();
        for token in tokens {
            token.cancel();
        }
    }

    /// Fire every live task's token (Stop all).
    pub fn cancel_all(&self) {
        let tokens: Vec<Arc<TurnCancel>> = kernel_core::lock_recover(&self.inner)
            .values()
            .flatten()
            .cloned()
            .collect();
        for token in tokens {
            token.cancel();
        }
    }
}

/// One registered delegation: the guard keeps its token reachable and removes
/// it when the run ends.
pub struct DelegationRegistration {
    registry: Arc<DelegationCancels>,
    id: String,
    token: Arc<TurnCancel>,
}

impl DelegationRegistration {
    /// The run's cancel token.
    pub fn token(&self) -> Arc<TurnCancel> {
        Arc::clone(&self.token)
    }
}

impl Drop for DelegationRegistration {
    fn drop(&mut self) {
        let mut inner = kernel_core::lock_recover(&self.registry.inner);
        if let Some(tokens) = inner.get_mut(&self.id) {
            tokens.retain(|token| !Arc::ptr_eq(token, &self.token));
            if tokens.is_empty() {
                inner.remove(&self.id);
            }
        }
    }
}

/// One delegation run handed to an executor.
///
/// The executor calls [`DelegationRun::step`] as it works; the method appends
/// the step, streams it, and returns `false` once the owner stopped the task
/// (or Stop all), so the executor can abort and keep the partial work.
pub struct DelegationRun {
    /// Delegation id.
    pub id: String,
    /// Thread that asked (the chief's agent name).
    pub parent_thread: String,
    /// Domain agent doing the work.
    pub agent: String,
    /// The task text.
    pub task: String,
    /// Brain label, when known.
    pub brain: Option<String>,
    /// Home the agent directories and STOP marker live in.
    home: PathBuf,
    /// The store connection for this run.
    store: Arc<Mutex<Store>>,
    /// Live event channel, when one is attached.
    events: Option<broadcast::Sender<String>>,
    /// The task-scoped cancel token a Stop fires.
    cancel: Arc<TurnCancel>,
    /// The agent's own session, once its turn ran: its references resolve there.
    child_thread: Arc<std::sync::OnceLock<i64>>,
    /// The caller's mode at handoff, only ever tightened: the agent's turn runs
    /// at least this private.
    caller_mode: ModeFn,
    /// TOK-DELEGATE: this run's handoff; a resumed run has none.
    inherited: aux_engine::handoff::Handoff,
    /// The chief's session, stamped on the agent's cards (TURN2-HANG).
    parent_session: Option<i64>,
    /// Live owner words for local checks; absent after resuming a delegation.
    owner_words: Option<String>,
}

impl DelegationRun {
    /// Record the session the agent's turn ran in (AGENT-DEFAULT).
    pub fn set_child_thread(&self, session_id: i64) {
        let _ = self.child_thread.set(session_id);
    }

    /// Open the store and build a run for `delegation`.
    pub fn open(
        delegation: &Delegation,
        home: &std::path::Path,
        db_path: &std::path::Path,
        events: Option<broadcast::Sender<String>>,
        cancel: Arc<TurnCancel>,
    ) -> Result<Self, String> {
        let store = Store::open(db_path).map_err(|err| err.to_string())?;
        Ok(Self {
            id: delegation.id.clone(),
            parent_thread: delegation.parent_thread.clone(),
            agent: delegation.agent.clone(),
            task: delegation.task.clone(),
            brain: delegation.brain.clone(),
            home: home.to_path_buf(),
            store: Arc::new(Mutex::new(store)),
            events,
            cancel,
            child_thread: Arc::default(),
            // A resumed run: the mode stored at handoff is the floor (a row
            // with none reads Private); only the chief delegates, so its live
            // mode may still tighten an Open one.
            caller_mode: crate::privacy_wiring::pinned_mode_fn(
                delegation.caller_mode,
                crate::privacy_wiring::agent_mode_fn(home, aux_runtime::grants::CHIEF_AGENT),
            ),
            inherited: aux_engine::handoff::Handoff::default(),
            parent_session: None,
            owner_words: None,
        })
    }

    /// The task-scoped cancel token the child turn runs under.
    pub fn cancel_token(&self) -> Arc<TurnCancel> {
        Arc::clone(&self.cancel)
    }

    fn with_store<T>(&self, f: impl FnOnce(&Store) -> Result<T, String>) -> Result<T, String> {
        let guard = kernel_core::lock_recover(&self.store);
        f(&guard)
    }

    /// Append and stream one step. Returns `false` when the owner stopped this
    /// delegation or Stop all is engaged.
    pub fn step(&self, text: &str, state: &str) -> bool {
        self.append(text, state, None);
        !self.stopped()
    }

    /// Append one step with where it ran (`None` is unknown); its index,
    /// when it was stored.
    fn append(&self, text: &str, state: &str, place: Option<&str>) -> Option<usize> {
        if self.stopped() {
            return None;
        }
        let step = DelegationStep {
            text: error::scrub_preview(&self.home, text, MAX_DELEGATION_TEXT_BYTES),
            at: now_stamp(),
            state: state.to_string(),
            where_ran: place.map(str::to_string),
        };
        let appended = self.with_store(|store| {
            // Never let an executor grow the record past its bound.
            let current = store
                .delegation(&self.id)
                .map_err(|err| err.to_string())?
                .map(|delegation| delegation.steps.len())
                .unwrap_or(0);
            if current >= MAX_STEPS {
                return Ok(None);
            }
            store
                .append_delegation_step(&self.id, &step)
                .map_err(|err| err.to_string())?;
            Ok(Some(current))
        });
        if appended.is_err() {
            tracing::warn!(id = %self.id, "could not append a delegation step");
        }
        self.publish(delegation_step_frame(&self.id, &self.agent, &step, None));
        appended.ok().flatten()
    }

    /// Record where step `index` ran, once the egress record knows.
    fn set_step_where(&self, index: usize, place: &str) {
        let _ = self.with_store(|store| {
            store
                .set_delegation_step_where(&self.id, index, place)
                .map_err(|err| err.to_string())
        });
    }

    /// Record finished-step progress and stream it.
    pub fn progress(&self, n: i64, of: i64) {
        let _ = self.with_store(|store| {
            store
                .set_delegation_progress(&self.id, n, of)
                .map_err(|err| err.to_string())?;
            Ok(())
        });
    }

    /// Mark the run as waiting on an approval.
    pub fn waiting(&self, approval_id: &str) {
        let _ = self.with_store(|store| {
            store
                .set_delegation_approval(&self.id, approval_id)
                .map_err(|err| err.to_string())?;
            Ok(())
        });
    }

    fn publish(&self, value: serde_json::Value) {
        if let Some(events) = &self.events {
            let _ = crate::api::wire::send_bounded(events, &value);
        }
    }

    /// True when Stop all is engaged or this delegation is `stopped`.
    pub fn stopped(&self) -> bool {
        if self.cancel.is_cancelled() || killswitch::is_stopped(&self.home) {
            return true;
        }
        self.with_store(|store| {
            Ok(store
                .delegation(&self.id)
                .ok()
                .flatten()
                .is_some_and(|delegation| delegation.state == DelegationState::Stopped))
        })
        .unwrap_or(true)
    }

    /// Mark the delegation stopped and stream `delegation.stopped`.
    fn mark_stopped(&self) {
        let _ = self.with_store(|store| {
            store
                .set_delegation_state(&self.id, DelegationState::Stopped)
                .map_err(|err| err.to_string())?;
            Ok(())
        });
        self.publish(delegation_stopped_frame(&self.id, &self.agent, "stopped"));
    }
}

/// Runs one delegation and returns the short result the chief may see.
#[async_trait]
pub trait DelegationExecutor: Send + Sync {
    /// Run `run`; `Ok` is the short result, `Err` a sanitized reason.
    async fn execute(&self, run: DelegationRun) -> Result<String, String>;
}

/// VAGUE-ASK-1: a delegation that holds no result and recorded no step
/// attempted nothing: the task never started (the chief's turn was dropped,
/// or the daemon restarted before the agent ran). "Couldn't finish" would be
/// a lie the owner reads as a red chip, so such a row is stopped, not failed.
fn attempted_nothing(delegation: &Delegation) -> bool {
    delegation.result.is_none() && delegation.steps.is_empty()
}

/// The state a run that did not finish leaves behind: a task that attempted
/// something failed, a task that never started was stopped.
fn unfinished_state(delegation: Option<&Delegation>) -> DelegationState {
    match delegation {
        Some(row) if attempted_nothing(row) => DelegationState::Stopped,
        _ => DelegationState::Failed,
    }
}

/// A daemon restart drops every executor future, so no run can still own an
/// open delegation. Retire those rows before serving snapshots; otherwise
/// their last persisted step keeps showing as live forever.
pub(crate) fn recover_interrupted(home: &std::path::Path) -> anyhow::Result<usize> {
    let store = Store::open(&kernel_core::store_path(home))?;
    let open: Vec<_> = store
        .list_delegations(None)?
        .into_iter()
        .filter(|delegation| delegation.state.is_open())
        .collect();
    let mut recovered = 0;
    for delegation in open {
        let state = unfinished_state(Some(&delegation));
        if store.set_delegation_state(&delegation.id, state)? {
            recovered += 1;
        }
    }
    Ok(recovered)
}

/// Production executor: the domain agent's own engine turn.
pub struct EngineDelegationExecutor {
    home: PathBuf,
    provider: Option<Arc<dyn aux_providers::ChatProvider>>,
    approvals: Option<Arc<crate::api::ApprovalRegistry>>,
    /// The Mac bridge, so a delegated Calendar turn can write (CAL-UPDATE-1).
    bridge: Option<Arc<crate::bridge::Bridge>>,
    /// How long one delegated turn may run.
    deadline: Duration,
    /// Test seam: the tool hook the child turn runs with. Test-util only.
    #[cfg(any(test, feature = "test-util"))]
    tools: Option<crate::api::ToolRegistryHook>,
    #[cfg(test)]
    mail: Option<Arc<dyn aux_mail::MailApi>>,
}

impl EngineDelegationExecutor {
    /// Build the executor rooted at `home`.
    pub fn new(
        home: PathBuf,
        provider: Option<Arc<dyn aux_providers::ChatProvider>>,
        approvals: Option<Arc<crate::api::ApprovalRegistry>>,
    ) -> Self {
        Self {
            home,
            provider,
            approvals,
            bridge: None,
            deadline: DELEGATION_DEADLINE,
            #[cfg(any(test, feature = "test-util"))]
            tools: None,
            #[cfg(test)]
            mail: None,
        }
    }

    /// Give the child turn the daemon's Mac bridge.
    pub fn with_bridge(mut self, bridge: Arc<crate::bridge::Bridge>) -> Self {
        self.bridge = Some(bridge);
        self
    }

    /// Bound one delegated turn (tests shrink it).
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Test-util only: give the child turn the parent's tool hook.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_tools(mut self, tools: crate::api::ToolRegistryHook) -> Self {
        self.tools = Some(tools);
        self
    }
}

#[async_trait]
impl DelegationExecutor for EngineDelegationExecutor {
    async fn execute(&self, run: DelegationRun) -> Result<String, String> {
        let run = Arc::new(run);
        let asking = run.append("asking its brain", "working", None);
        if asking.is_none() || run.stopped() {
            run.mark_stopped();
            return Err("stopped".to_string());
        }
        // The child turn gets an isolated sink: its `message.*` and `tool.*`
        // frames never reach the chief's channel. A drain task maps them to
        // content-free `delegation.step` summaries (the tool name only).
        let (child_tx, mut child_rx) = broadcast::channel::<String>(256);
        let end_tx = child_tx.clone();
        let steps = Arc::clone(&run);
        // A delegated agent's cards must reach the owner's Waiting page: its
        // isolated channel never reaches the app, so approval frames are
        // forwarded to the chief's channel whole.
        let parent_events = run.events.clone();
        let drain = tokio::spawn(async move {
            // DELEG-WHERE-1: one `brain.where` per provider round. Round 1
            // fills "asking its brain", later rounds are their own steps, the
            // answer ran where its round did; tool steps stay unknown.
            // A lagged channel lost frames, so rounds no longer line up: every
            // later step stays unknown.
            let (mut rounds, mut lagged) = (0usize, false);
            let mut last: Option<&'static str> = None;
            loop {
                let text = match child_rx.recv().await {
                    Ok(text) => text,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        (lagged, last) = (true, None);
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                    continue;
                };
                if matches!(
                    value["type"].as_str(),
                    Some("approval.new" | "approval.resolved" | "approval.updated")
                ) {
                    if let Some(events) = &parent_events {
                        let _ = crate::api::wire::send_bounded(events, &value);
                    }
                }
                let tool = value["call"]["tool"].as_str();
                match value["type"].as_str().unwrap_or("") {
                    "tool.start" => {
                        if let Some(name) = tool {
                            steps.step(&format!("running {name}"), "working");
                        }
                    }
                    "tool.end" => {
                        if let Some(name) = tool {
                            steps.step(&format!("finished {name}"), "done");
                        }
                    }
                    crate::api::turn_events::BRAIN_WHERE => {
                        rounds += 1;
                        last = match value["where"].as_str() {
                            _ if lagged => None,
                            Some("local") => Some("local"),
                            Some("out") => Some("out"),
                            _ => None,
                        };
                        match (rounds, asking, last) {
                            (1, Some(index), Some(place)) => steps.set_step_where(index, place),
                            (1, _, _) => {}
                            _ => drop(steps.append("asked its brain again", "done", last)),
                        }
                    }
                    "message.done" => {
                        steps.append("wrote its answer", "done", last);
                    }
                    DRAIN_END => break,
                    _ => {}
                }
            }
        });
        let home = self.home.clone();
        let provider = self.provider.clone();
        let (approvals, bridge) = (self.approvals.clone(), self.bridge.clone());
        #[cfg(any(test, feature = "test-util"))]
        let tools = self.tools.clone();
        #[cfg(test)]
        let mail = self.mail.clone();
        let cancel = run.cancel_token();
        let agent = run.agent.clone();
        let task = run.task.clone();
        let caller_mode = Arc::clone(&run.caller_mode);
        let inherited = run.inherited.clone();
        let parent_session = run.parent_session;
        let owner_words = run.owner_words.clone();
        // AGENT-HISTORY-BLEED: the agent's thread is the chief thread's own,
        // never the agent's latest one.
        let thread = run.with_store(|store| {
            store
                .delegate_session(parent_session, &agent)
                .map_err(|err| err.to_string())
        })?;
        let mut record = tokio::task::spawn_blocking(move || {
            let mut runner = EngineTurnRunner::new(&home)
                .with_events(child_tx)
                .with_inherited_tokens(inherited)
                .with_root_thread(parent_session);
            #[cfg(any(test, feature = "test-util"))]
            {
                if let Some(tools) = tools {
                    runner = runner.with_tools(tools);
                }
            }
            if let Some(provider) = provider {
                runner = runner.with_provider(provider);
            }
            #[cfg(test)]
            if let Some(mail) = mail {
                runner = runner.with_mail(mail);
            }
            if let Some(approvals) = approvals {
                runner = runner.with_approvals(approvals);
            }
            if let Some(bridge) = bridge {
                runner = runner.with_bridge(bridge);
            }
            runner
                .with_brain_where()
                .with_mode_floor(caller_mode)
                .with_owner_words(owner_words)
                // DELEGATION-SOURCE-1: the ask's row says it is a delegation,
                // so the app never shows it as the owner's words.
                .with_source("delegation")
                .run_turn(&agent, Some(thread), &task, Some(cancel))
        });
        // CROSS-AGENT-RESOLVE: a turn that never finishes must not hold the
        // chief, but time parked on one of its cards is the owner's, not the
        // delegate's: the clock pauses while a card waits and no card is
        // retired by the deadline (#467).
        let mut remaining = self.deadline;
        let mut last = Instant::now();
        let record = loop {
            let carded = self
                .approvals
                .as_ref()
                .is_some_and(|approvals| approvals.cards_holding(thread) > 0);
            let step = if carded {
                DELEGATION_POLL
            } else {
                remaining.min(DELEGATION_POLL)
            };
            tokio::select! {
                joined = &mut record => break joined,
                _ = tokio::time::sleep(step) => {}
            }
            let now = Instant::now();
            if !carded {
                remaining = remaining.saturating_sub(now - last);
            }
            last = now;
            let parked = self
                .approvals
                .as_ref()
                .is_some_and(|approvals| approvals.cards_holding(thread) > 0);
            if !parked && remaining.is_zero() {
                run.cancel_token().cancel();
                let _ = tokio::time::timeout(DELEGATION_STOP_GRACE, &mut record).await;
                record.abort();
                drain.abort();
                tracing::warn!(id = %run.id, agent = %run.agent, "a delegated turn hit its deadline");
                return Err(format!(
                    "the {} task did not finish within {} s and was stopped. Tell the owner in \
                     one short line what is still pending, and to check its last step.",
                    run.agent,
                    self.deadline.as_secs()
                ));
            }
        };
        // Every child frame is queued: let the drain reach the end marker
        // (bounded) so the last steps land.
        let _ = crate::api::wire::send_bounded(&end_tx, &serde_json::json!({ "type": DRAIN_END }));
        let stop_drain = drain.abort_handle();
        let _ = tokio::time::timeout(Duration::from_secs(2), drain).await;
        stop_drain.abort();
        let record = record
            .map_err(|err| err.to_string())?
            .map_err(|err| err.to_string())?;
        run.set_child_thread(record.thread.id);
        if run.stopped() {
            run.mark_stopped();
            return Err("stopped".to_string());
        }
        let text = record
            .messages
            .iter()
            .rev()
            .find(|message| message.role == "assistant")
            .map(|message| message.content.clone())
            .unwrap_or_default();
        Ok(text)
    }
}

/// `delegate` tool: the chief's only way to reach a domain agent.
pub struct DelegateTool {
    home: PathBuf,
    events: Option<broadcast::Sender<String>>,
    executor: Arc<dyn DelegationExecutor>,
    cancels: Option<Arc<DelegationCancels>>,
}

impl DelegateTool {
    /// Build the tool rooted at `home`.
    pub fn new(
        home: PathBuf,
        events: Option<broadcast::Sender<String>>,
        executor: Arc<dyn DelegationExecutor>,
        cancels: Option<Arc<DelegationCancels>>,
    ) -> Self {
        Self {
            home,
            events,
            executor,
            cancels,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegateArgs {
    agent: String,
    task: String,
}

impl NativeTool for DelegateTool {
    fn native_name(&self) -> &'static str {
        "delegate"
    }

    fn native_description(&self) -> &'static str {
        "Hand one task to a domain agent (mail, calendar, clients, documents) and get its short result back. Anything about a client goes to clients: listing the clients, showing a client card, and logging a call, meeting or note with a client (not `remember`). A client card is the CRM record of a client party: name, company, e-mail, phone and notes. Show the result as it comes: before you read it, the kernel handled its protected values. If the record is returned, show it; never say it is missing. You only ever receive the result, never the agent's raw data."
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "agent": {
                        "type": "string",
                        "enum": DOMAIN_AGENTS,
                        "description": "Domain agent to hand the task to."
                    },
                    "task": {
                        "type": "string",
                        "description": "The task, in one or two sentences. The agent does the work and returns a short result."
                    }
                },
                "required": ["agent", "task"],
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for DelegateTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        // Local orchestration: the tool writes the local store and starts the
        // agent's own turn; that turn is admitted separately (A1).
        kernel_core::privacy::PathId::B1
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: DelegateArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let caller = aux_engine::handoff::Caller::current();
        // TOK-DELEGATE: one handoff per run, dropped when it ends.
        let handoff = caller
            .as_ref()
            .map(|caller| caller.handoff_for(&args.task))
            .unwrap_or_default();
        if !DOMAIN_AGENTS.contains(&args.agent.as_str()) {
            return Ok(ToolOutput::error(format!(
                "`{}` is not a domain agent; use one of {}",
                args.agent,
                DOMAIN_AGENTS.join(", ")
            )));
        }
        if args.task.trim().is_empty() {
            return Ok(ToolOutput::error("the task is empty"));
        }
        let db_path = kernel_core::store_path(&self.home);
        let store = Store::open(&db_path)
            .map_err(|err| ToolError::Io(std::io::Error::other(err.to_string())))?;
        // READ-AFTER-TAINT: a tainted caller's hand-off runs without a card,
        // so the agent inherits the taint before its turn starts: its
        // workspace is marked, and its own effectful calls still ask. A clean
        // agent can never launder the caller's taint. Fails closed.
        if ctx.tainted {
            inherit_taint(&self.home, &store, &ctx.agent, &args.agent)
                .map_err(|err| ToolError::Io(std::io::Error::other(err)))?;
        }
        let store = Arc::new(Mutex::new(store));
        let brain = crate::agents::definition(&self.home, &args.agent)
            .ok()
            .flatten()
            .and_then(|def| def.brain.label());
        let started = Instant::now();
        let id = new_id();
        let task = error::scrub_preview(&self.home, &args.task, MAX_DELEGATION_TEXT_BYTES);
        // The handoff: the mode the caller's turn runs under, never re-read
        // from config, pinned now and stored so a resume keeps it.
        let (at_handoff, caller_mode) = crate::privacy_wiring::handoff_mode_fn(
            ctx.turn_mode(),
            crate::privacy_wiring::agent_mode_fn(&self.home, &ctx.agent),
        );
        let delegation = {
            let guard = kernel_core::lock_recover(&store);
            guard
                .create_delegation(
                    &id,
                    &ctx.agent,
                    &args.agent,
                    &task,
                    brain.as_deref(),
                    at_handoff,
                )
                .map_err(|err| ToolError::Io(std::io::Error::other(err.to_string())))?
        };
        if let Some(events) = &self.events {
            let _ = crate::api::wire::send_bounded(
                events,
                &serde_json::json!({
                    "type": "delegation.new",
                    "at": now_stamp(),
                    "agent": &args.agent,
                    "delegation": delegation_json(&self.home, &delegation),
                }),
            );
        }
        let cancel = TurnCancel::new();
        let _registration = self
            .cancels
            .as_ref()
            .map(|cancels| cancels.register(&id, Arc::clone(&cancel)));
        let run = {
            let guard = kernel_core::lock_recover(&store);
            let _ = guard.set_delegation_state(&id, DelegationState::Working);
            DelegationRun {
                id: delegation.id.clone(),
                parent_thread: delegation.parent_thread.clone(),
                agent: delegation.agent.clone(),
                task: delegation.task.clone(),
                brain: delegation.brain.clone(),
                home: self.home.clone(),
                store: Arc::clone(&store),
                events: self.events.clone(),
                cancel: Arc::clone(&cancel),
                child_thread: Arc::default(),
                caller_mode,
                inherited: handoff.clone(),
                owner_words: caller
                    .as_ref()
                    .and_then(|caller| caller.owner_words().map(str::to_owned)),
                parent_session: ctx
                    .run_id
                    .as_deref()
                    .and_then(crate::api::receipt::run_thread),
            }
        };
        let child_thread = Arc::clone(&run.child_thread);
        // TOOL-HANG: the chief's turn can end first (client gone, turn
        // timeout, Stop). Its cancel reaches the agent's own turn, which then
        // stops at once and retires its pending card; a call dropped before
        // the agent answered closes the record instead of leaving it working.
        let mut orphan = OrphanGuard {
            cancel: Arc::clone(&cancel),
            store: Arc::clone(&store),
            events: self.events.clone(),
            id: id.clone(),
            agent: args.agent.clone(),
            armed: true,
        };
        let execute = self.executor.execute(run);
        tokio::pin!(execute);
        let outcome = match ctx.cancel.clone() {
            Some(parent) => tokio::select! {
                outcome = &mut execute => outcome,
                _ = parent.cancelled() => {
                    cancel.cancel();
                    execute.await
                }
            },
            None => execute.await,
        };
        orphan.armed = false;
        match outcome {
            Ok(result) => {
                // The result holds the agent's references. A private chief
                // adopts this run's pairs (TOK-DELEGATE), never re-detecting a
                // clear value; an open chief reads the values, in memory only.
                let shown = match (child_thread.get(), &caller) {
                    (Some(id), Some(caller)) if caller.private => {
                        let pairs = handoff.returned_pairs(*id, &result);
                        caller.adopt(&pairs);
                        crate::api::display::live_tokens().record(caller.session_id, &pairs);
                        result.clone()
                    }
                    (Some(id), _) => crate::api::display::rehydrate_text(&self.home, *id, &result),
                    (None, _) => result.clone(),
                };
                let took_ms = started.elapsed().as_millis() as i64;
                // Conditional completion: a Stop that landed while the
                // executor ran must never be overwritten with `done`.
                let applied = {
                    let guard = kernel_core::lock_recover(&store);
                    guard
                        .set_delegation_result(&id, &result, took_ms)
                        .unwrap_or(false)
                };
                if !applied {
                    if let Some(events) = &self.events {
                        let _ = crate::api::wire::send_bounded(
                            events,
                            &delegation_stopped_frame(&id, &args.agent, "stopped"),
                        );
                    }
                    return Ok(ToolOutput::error("the task was stopped"));
                }
                if let Some(events) = &self.events {
                    let _ = crate::api::wire::send_bounded(
                        events,
                        &delegation_result_frame(&id, &args.agent, &result, took_ms),
                    );
                }
                Ok(ToolOutput::ok(shown))
            }
            Err(reason) => {
                let row = {
                    let guard = kernel_core::lock_recover(&store);
                    guard.delegation(&id).ok().flatten()
                };
                let stopped = row
                    .as_ref()
                    .is_some_and(|delegation| delegation.state == DelegationState::Stopped);
                {
                    let guard = kernel_core::lock_recover(&store);
                    if !stopped {
                        // VAGUE-ASK-1: a run that attempted nothing never ran.
                        let _ = guard.set_delegation_state(&id, unfinished_state(row.as_ref()));
                    }
                }
                if let Some(events) = &self.events {
                    let _ = crate::api::wire::send_bounded(
                        events,
                        &delegation_stopped_frame(
                            &id,
                            &args.agent,
                            if stopped { "stopped" } else { &reason },
                        ),
                    );
                }
                Ok(ToolOutput::error(if stopped {
                    "the task was stopped".to_string()
                } else {
                    reason
                }))
            }
        }
    }

    fn risk(&self) -> Risk {
        Risk::Medium
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            // A delegation spends a provider call and can act; never auto-run
            // it from a broad `allow` rule.
            requires_explicit_rule: true,
            // The result is derived from what the agent read (mail, web,
            // documents): untrusted, so the chief's next effectful call asks
            // instead of laundering that content through a clean conversation.
            output_trust: Trust::Untrusted,
            ..ToolClass::default()
        }
    }
}

/// Closes a delegation whose `delegate` call was dropped before the agent
/// answered: the agent's turn is cancelled and a record still open is marked
/// failed, so neither runs nor shows "working" past the chief's turn.
struct OrphanGuard {
    cancel: Arc<TurnCancel>,
    store: Arc<Mutex<Store>>,
    events: Option<broadcast::Sender<String>>,
    id: String,
    agent: String,
    armed: bool,
}

impl Drop for OrphanGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancel.cancel();
        let closed = {
            let guard = kernel_core::lock_recover(&self.store);
            let row = guard.delegation(&self.id).ok().flatten();
            let open = row.as_ref().is_some_and(|row| {
                matches!(
                    row.state,
                    DelegationState::Queued | DelegationState::Working | DelegationState::Waiting
                )
            });
            // VAGUE-ASK-1: a row the cancelled turn never touched attempted
            // nothing: it is stopped, so the owner reads no "couldn't finish".
            open && guard
                .set_delegation_state(&self.id, unfinished_state(row.as_ref()))
                .unwrap_or(false)
        };
        if let (true, Some(events)) = (closed, &self.events) {
            let _ = crate::api::wire::send_bounded(
                events,
                &delegation_stopped_frame(&self.id, &self.agent, "the turn was cancelled"),
            );
        }
    }
}

/// Mark `agent`'s workspace tainted by `caller`'s hand-off, the same mark the
/// engine writes for an untrusted call there: every turn of `agent` starts
/// tainted (and re-reads it before each authorization) until the owner trusts
/// the workspace again. The directory is created through the home gateway
/// first, so the key is the canonical path the engine computes.
fn inherit_taint(
    home: &std::path::Path,
    store: &Store,
    caller: &str,
    agent: &str,
) -> Result<(), String> {
    let workspace = aux_engine::workspace_dir(home, agent);
    let rel = std::path::Path::new("agents").join(agent).join("workspace");
    kernel_core::SandboxHome::open_existing(home)
        .and_then(|sandbox| sandbox.create_dir_all(&rel))
        .map_err(|err| err.to_string())?;
    let key = aux_engine::workspace::workspace_key(&workspace);
    store
        .mark_workspace_tainted(&key, &format!("delegate: from {caller}"))
        .map_err(|err| err.to_string())
}

// ---------------------------------------------------------------------------
// JSON + event frames
// ---------------------------------------------------------------------------

/// One delegation as the API and the UI see it.
pub fn delegation_json(home: &std::path::Path, delegation: &Delegation) -> serde_json::Value {
    let steps: Vec<serde_json::Value> = delegation
        .steps
        .iter()
        .map(|step| {
            serde_json::json!({
                "text": error::scrub_preview(home, &step.text, MAX_DELEGATION_TEXT_BYTES),
                "at": step.at,
                "state": step.state,
                "where": where_label(step),
            })
        })
        .collect();
    let progress = match (delegation.progress_n, delegation.progress_of) {
        (Some(n), Some(of)) => serde_json::json!({ "n": n, "of": of }),
        _ => serde_json::Value::Null,
    };
    serde_json::json!({
        "id": delegation.id,
        "parent_thread": delegation.parent_thread,
        "agent": delegation.agent,
        "ask": error::scrub_preview(home, &delegation.task, MAX_DELEGATION_TEXT_BYTES),
        "at": delegation.created_at,
        "state": delegation.state.as_str(),
        "steps": steps,
        "progress": progress,
        "result": delegation.result.as_deref().map(|text| {
            error::scrub_preview(home, text, MAX_DELEGATION_TEXT_BYTES)
        }),
        "took_ms": delegation.took_ms,
        "brain": delegation.brain,
        "approval_id": delegation.approval_id,
        "updated_at": delegation.updated_at,
    })
}

/// `local` or `out` only as recorded; anything else (an older row, a
/// corrupt value) reads `unknown`.
fn where_label(step: &DelegationStep) -> &'static str {
    match step.where_ran.as_deref() {
        Some("local") => "local",
        Some("out") => "out",
        _ => "unknown",
    }
}

fn delegation_step_frame(
    id: &str,
    agent: &str,
    step: &DelegationStep,
    progress: Option<(i64, i64)>,
) -> serde_json::Value {
    serde_json::json!({
        "type": "delegation.step",
        "at": now_stamp(),
        "agent": agent,
        "delegation_id": id,
        "step": {
            "text": step.text,
            "at": step.at,
            "state": step.state,
            "where": where_label(step),
        },
        "progress": progress.map(|(n, of)| serde_json::json!({ "n": n, "of": of })),
    })
}

fn delegation_result_frame(id: &str, agent: &str, result: &str, took_ms: i64) -> serde_json::Value {
    serde_json::json!({
        "type": "delegation.result",
        "at": now_stamp(),
        "agent": agent,
        "delegation_id": id,
        "result": result,
        "took_ms": took_ms,
    })
}

fn delegation_stopped_frame(id: &str, agent: &str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "delegation.stopped",
        "at": now_stamp(),
        "agent": agent,
        "delegation_id": id,
        "reason": reason,
    })
}

/// `stop.changed` frame, shared with the Stop routes.
pub fn stop_changed_frame(
    stopped: bool,
    since: Option<&str>,
    cancelled_sends: usize,
) -> serde_json::Value {
    serde_json::json!({
        "type": "stop.changed",
        "at": now_stamp(),
        "stopped": stopped,
        "since": since,
        "cancelled_sends": cancelled_sends,
    })
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DelegationsQuery {
    thread: Option<String>,
}

/// `GET /v1/delegations?thread=`.
pub async fn list(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<DelegationsQuery>,
) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let thread = query.thread.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
        let store = Store::open(&db_path).map_err(|err| err.to_string())?;
        let delegations = store
            .list_delegations(thread.as_deref())
            .map_err(|err| err.to_string())?;
        let items: Vec<serde_json::Value> = delegations
            .iter()
            .map(|delegation| delegation_json(&home, delegation))
            .collect();
        Ok(serde_json::Value::Array(items))
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(detail)) => internal("listing delegations", &detail),
        Err(err) => internal("joining the delegation reader", &err.to_string()),
    }
}

/// `GET /v1/delegations/{id}`.
pub async fn show(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result =
        tokio::task::spawn_blocking(move || -> Result<Option<serde_json::Value>, String> {
            let store = Store::open(&db_path).map_err(|err| err.to_string())?;
            Ok(store
                .delegation(&id)
                .map_err(|err| err.to_string())?
                .map(|delegation| delegation_json(&home, &delegation)))
        })
        .await;
    match result {
        Ok(Ok(Some(value))) => Json(value).into_response(),
        Ok(Ok(None)) => not_found(),
        Ok(Err(detail)) => internal("reading a delegation", &detail),
        Err(err) => internal("joining the delegation reader", &err.to_string()),
    }
}

/// `POST /v1/delegations/{id}/stop`.
pub async fn stop(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    set_state(state, id, DelegationState::Stopped).await
}

/// `POST /v1/delegations/{id}/resume`.
pub async fn resume(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let id_for_read = id.clone();
    let read = tokio::task::spawn_blocking(move || -> Result<Option<Delegation>, String> {
        let store = Store::open(&db_path).map_err(|err| err.to_string())?;
        store
            .delegation(&id_for_read)
            .map_err(|err| err.to_string())
    })
    .await;
    let delegation = match read {
        Ok(Ok(Some(delegation))) => delegation,
        Ok(Ok(None)) => return not_found(),
        Ok(Err(detail)) => return internal("reading a delegation", &detail),
        Err(err) => return internal("joining the delegation reader", &err.to_string()),
    };
    if delegation.state != DelegationState::Stopped {
        return error::error_response(
            axum::http::StatusCode::CONFLICT,
            "delegation_not_stopped",
            "only a stopped delegation can resume",
            None,
        );
    }
    let db_path = state.db_path.clone();
    let delegation_id = delegation.id.clone();
    let reset = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let store = Store::open(&db_path).map_err(|err| err.to_string())?;
        store
            .set_delegation_state(&delegation_id, DelegationState::Queued)
            .map_err(|err| err.to_string())?;
        Ok(())
    })
    .await;
    match reset {
        Ok(Ok(())) => {}
        Ok(Err(detail)) => return internal("resuming a delegation", &detail),
        Err(err) => return internal("joining the delegation writer", &err.to_string()),
    }
    if let Some(events) = Some(state.events.clone()) {
        let _ = crate::api::wire::send_bounded(
            &events,
            &serde_json::json!({
                "type": "delegation.new",
                "at": now_stamp(),
                "agent": delegation.agent,
                "delegation": delegation_json(&home, &Delegation { state: DelegationState::Queued, ..delegation.clone() }),
            }),
        );
    }
    spawn_run(Arc::clone(&state), delegation);
    Json(serde_json::json!({ "state": "queued" })).into_response()
}

async fn set_state(state: Arc<ApiState>, id: String, target: DelegationState) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Option<Delegation>, String> {
        let store = Store::open(&db_path).map_err(|err| err.to_string())?;
        let Some(delegation) = store.delegation(&id).map_err(|err| err.to_string())? else {
            return Ok(None);
        };
        store
            .set_delegation_state(&id, target)
            .map_err(|err| err.to_string())?;
        Ok(Some(delegation))
    })
    .await;
    match result {
        Ok(Ok(Some(delegation))) => {
            if target == DelegationState::Stopped {
                // Abort the child turn now: the token reaches the running
                // tool call and the provider stream.
                state.delegation_cancels.cancel(&delegation.id);
                let _ = crate::api::wire::send_bounded(
                    &state.events,
                    &delegation_stopped_frame(&delegation.id, &delegation.agent, "stopped"),
                );
            }
            let mut updated = delegation;
            updated.state = target;
            Json(delegation_json(&home, &updated)).into_response()
        }
        Ok(Ok(None)) => not_found(),
        Ok(Err(detail)) => internal("updating a delegation", &detail),
        Err(err) => internal("joining the delegation writer", &err.to_string()),
    }
}

/// Run one delegation in the background through the configured executor.
pub fn spawn_run(state: Arc<ApiState>, delegation: Delegation) {
    tokio::spawn(async move {
        let home = state.home.clone();
        let db_path = state.db_path.clone();
        let open_path = db_path.clone();
        let events = Some(state.events.clone());
        let id = delegation.id.clone();
        let agent = delegation.agent.clone();
        let cancel = TurnCancel::new();
        let _registration = state.delegation_cancels.register(&id, Arc::clone(&cancel));
        let run = match tokio::task::spawn_blocking(move || {
            DelegationRun::open(&delegation, &home, &open_path, events, Arc::clone(&cancel))
        })
        .await
        {
            Ok(Ok(run)) => run,
            Ok(Err(detail)) => {
                tracing::warn!(error = %detail, "could not resume a delegation");
                return;
            }
            Err(err) => {
                tracing::warn!(error = %err, "joining the delegation opener");
                return;
            }
        };
        // The row is live again before the executor takes its first step.
        if let Ok(store) = Store::open(&db_path) {
            let _ = store.set_delegation_state(&id, DelegationState::Working);
        }
        match state.delegations.execute(run).await {
            Ok(result) => {
                let applied = Store::open(&db_path)
                    .ok()
                    .and_then(|store| store.set_delegation_result(&id, &result, 0).ok())
                    .unwrap_or(false);
                if !applied {
                    let _ = crate::api::wire::send_bounded(
                        &state.events,
                        &delegation_stopped_frame(&id, &agent, "stopped"),
                    );
                    return;
                }
                let _ = crate::api::wire::send_bounded(
                    &state.events,
                    &delegation_result_frame(&id, &agent, &result, 0),
                );
            }
            Err(reason) => {
                let row = Store::open(&db_path)
                    .ok()
                    .and_then(|store| store.delegation(&id).ok().flatten());
                let stopped = row
                    .as_ref()
                    .is_some_and(|delegation| delegation.state == DelegationState::Stopped);
                if !stopped {
                    if let Ok(store) = Store::open(&db_path) {
                        // VAGUE-ASK-1: nothing attempted is stopped, not failed.
                        let _ = store.set_delegation_state(&id, unfinished_state(row.as_ref()));
                    }
                }
                let _ = crate::api::wire::send_bounded(
                    &state.events,
                    &delegation_stopped_frame(
                        &id,
                        &agent,
                        if stopped { "stopped" } else { &reason },
                    ),
                );
            }
        }
    });
}

/// `GET /v1/stop` → `{stopped, since, cancelled_sends}`.
pub async fn stop_status(State(state): State<Arc<ApiState>>) -> Response {
    let home = state.home.clone();
    let cancelled = state
        .stop_cancelled
        .load(std::sync::atomic::Ordering::Relaxed);
    let result = tokio::task::spawn_blocking(move || -> (bool, Option<String>) {
        let stopped = killswitch::is_stopped(&home);
        let since = if stopped {
            std::fs::metadata(home.join("STOP"))
                .ok()
                .and_then(|meta| meta.modified().ok())
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|duration| {
                    chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)
                        .map(|at| at.format("%Y-%m-%d %H:%M:%S").to_string())
                })
        } else {
            None
        };
        (stopped, since)
    })
    .await;
    match result {
        Ok((stopped, since)) => Json(serde_json::json!({
            "stopped": stopped,
            "since": since,
            "cancelled_sends": cancelled,
        }))
        .into_response(),
        Err(err) => internal("reading the stop state", &err.to_string()),
    }
}

/// `POST /v1/threads/{id}/read`.
pub async fn thread_read(State(state): State<Arc<ApiState>>, Path(id): Path<String>) -> Response {
    let home = state.home.clone();
    let db_path = state.db_path.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(), String> {
        let thread_id: i64 = if id.chars().all(|c| c.is_ascii_digit()) {
            id.parse().map_err(|_| "invalid thread id".to_string())?
        } else {
            crate::api::snapshot::latest_session_for_agent(&home, &id)
                .map_err(|err| err.to_string())?
                .map(|session| session.id)
                .ok_or_else(|| "no such thread".to_string())?
        };
        let store = Store::open(&db_path).map_err(|err| err.to_string())?;
        store
            .mark_thread_read(thread_id)
            .map_err(|err| err.to_string())
    })
    .await;
    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(Err(detail)) if detail == "no such thread" => not_found(),
        Ok(Err(detail)) => error::error_response(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_thread",
            &detail,
            None,
        ),
        Err(err) => internal("marking a thread read", &err.to_string()),
    }
}

fn not_found() -> Response {
    error::error_response(
        axum::http::StatusCode::NOT_FOUND,
        "delegation_not_found",
        "no such delegation",
        None,
    )
}

fn internal(what: &str, detail: &str) -> Response {
    tracing::warn!(detail = %detail, "delegation API: {what} failed");
    error::error_response(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "delegation_error",
        "the delegation could not be read or updated",
        None,
    )
}

fn now_stamp() -> String {
    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::privacy::PrivacyMode;
    use tokio::sync::Notify;

    #[derive(Clone)]
    struct FixedOutcome(Result<String, String>);

    #[async_trait]
    impl DelegationExecutor for FixedOutcome {
        async fn execute(&self, _run: DelegationRun) -> Result<String, String> {
            self.0.clone()
        }
    }

    struct Stalled {
        started: Arc<Notify>,
    }

    #[async_trait]
    impl DelegationExecutor for Stalled {
        async fn execute(&self, _run: DelegationRun) -> Result<String, String> {
            self.started.notify_one();
            std::future::pending().await
        }
    }

    fn assert_no_live_line(home: &std::path::Path, agent: &str) {
        let agents = crate::api::snapshot::agents_snapshot(home).unwrap();
        assert_eq!(
            agents
                .iter()
                .find(|row| row.name == agent)
                .and_then(|row| row.live_line.as_deref()),
            None
        );
    }

    /// Mail's turn ran in session 4242 and answered with one of its references.
    struct TokenisedMail;

    #[async_trait]
    impl DelegationExecutor for TokenisedMail {
        async fn execute(&self, run: DelegationRun) -> Result<String, String> {
            run.set_child_thread(4242);
            Ok("Newest mail from ⟦PERSON_4D2EBF5616CF⟧.".to_string())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_chief_gets_the_agents_result_without_its_references() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let _ = Store::open(&kernel_core::store_path(&home)).unwrap();
        crate::api::display::live_tokens().record(
            4242,
            &[(
                "PERSON_4D2EBF5616CF".to_string(),
                "Jonas Sample".to_string(),
            )],
        );
        let tool = DelegateTool::new(home.clone(), None, Arc::new(TokenisedMail), None);
        let ctx = ToolCtx::new("aux", home.clone());
        let args = serde_json::json!({ "agent": "mail", "task": "newest mail" });
        let output = tool.run(&args, &ctx).await.unwrap();
        assert_eq!(output.content, "Newest mail from Jonas Sample.");
        // At rest the result keeps the agent's reference, never the name.
        let stored = Store::open(&kernel_core::store_path(&home))
            .unwrap()
            .list_delegations(None)
            .unwrap();
        assert_eq!(
            stored[0].result.as_deref(),
            Some("Newest mail from ⟦PERSON_4D2EBF5616CF⟧.")
        );
        assert_no_live_line(&home, "mail");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_erroring_delegation_clears_its_live_line() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let tool = DelegateTool::new(
            home.to_path_buf(),
            None,
            Arc::new(FixedOutcome(Err("provider failed".into()))),
            None,
        );
        let _ = tool
            .run(
                &serde_json::json!({ "agent": "mail", "task": "newest mail" }),
                &ToolCtx::new("aux", home.to_path_buf()),
            )
            .await
            .unwrap();
        assert_no_live_line(home, "mail");
    }

    /// A home with a fake brain, as the delegation's own tests use.
    fn fake_home() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        // SANDBOX-GATEWAY-EXEMPT: cfg(test)-only fake-home fixture.
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            kernel_core::config_path(&home),
            "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"aux\"\n\n[[providers]]\n\
             id = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n",
        )
        .unwrap();
        (dir, home)
    }

    /// VAGUE-ASK-1: the "couldn't finish" chip must not fire on a delegation
    /// that attempted nothing: no result and no step, because the task never
    /// started. The owner sees a stopped task, not a red failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delegation_that_attempted_nothing_is_not_a_failure() {
        let (dir, home) = fake_home();
        let _ = dir;
        // The chief's turn was dropped before the agent started: the executor
        // never touched the run, so the row holds no step and no result.
        let tool = DelegateTool::new(
            home.clone(),
            None,
            Arc::new(FixedOutcome(Err("the turn was cancelled".into()))),
            None,
        );
        let _ = tool
            .run(
                &serde_json::json!({ "agent": "mail", "task": "newest mail" }),
                &ToolCtx::new("aux", home.clone()),
            )
            .await
            .unwrap();
        let rows = Store::open(&kernel_core::store_path(&home))
            .unwrap()
            .list_delegations(None)
            .unwrap();
        assert_eq!(
            rows[0].state,
            DelegationState::Stopped,
            "a task that never ran is not a failure"
        );
        assert!(rows[0].steps.is_empty(), "{rows:?}");
        assert!(rows[0].result.is_none(), "{rows:?}");
    }

    /// VAGUE-ASK-1: the chip still fires when the task ran and failed: the
    /// agent asked its brain and the brain had no answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delegation_that_attempted_something_still_fails() {
        let (dir, home) = fake_home();
        let _ = dir;
        // The fake brain has no answer to give: the task ran and could not
        // finish.
        let brain = Arc::new(aux_providers::FakeProvider::scripted("b", Vec::new()));
        let executor = Arc::new(EngineDelegationExecutor::new(
            home.clone(),
            Some(brain),
            None,
        ));
        let tool = DelegateTool::new(home.clone(), None, executor, None);
        let _ = tool
            .run(
                &serde_json::json!({ "agent": "mail", "task": "newest mail" }),
                &ToolCtx::new("aux", home.clone()),
            )
            .await
            .unwrap();
        let rows = Store::open(&kernel_core::store_path(&home))
            .unwrap()
            .list_delegations(None)
            .unwrap();
        assert_eq!(
            rows[0].state,
            DelegationState::Failed,
            "a task that ran and failed still reads as a failure"
        );
        assert!(!rows[0].steps.is_empty(), "{rows:?}");
        assert!(rows[0].result.is_none(), "{rows:?}");
    }

    /// VAGUE-ASK-1: a daemon restart that catches a task before it started
    /// leaves a stopped row, not a failure: nothing was attempted.
    #[test]
    fn a_restart_before_the_task_started_stops_it_rather_than_failing_it() {
        let (dir, home) = fake_home();
        let _ = dir;
        let store = Store::open(&kernel_core::store_path(&home)).unwrap();
        let row = store
            .create_delegation(
                "dl-1",
                "aux",
                "calendar",
                "look at what's pending",
                None,
                PrivacyMode::Open,
            )
            .unwrap();
        drop(store);
        assert_eq!(recover_interrupted(&home).unwrap(), 1);
        let rows = Store::open(&kernel_core::store_path(&home))
            .unwrap()
            .list_delegations(None)
            .unwrap();
        assert_eq!(rows[0].state, DelegationState::Stopped, "{rows:?}");
        assert_eq!(rows[0].id, row.id);
    }

    async fn stalled_delegation_task(
        home: std::path::PathBuf,
    ) -> (tokio::task::JoinHandle<()>, Arc<Notify>) {
        let started = Arc::new(Notify::new());
        let tool = DelegateTool::new(
            home.clone(),
            None,
            Arc::new(Stalled {
                started: Arc::clone(&started),
            }),
            None,
        );
        let task = tokio::spawn(async move {
            let _ = tool
                .run(
                    &serde_json::json!({ "agent": "mail", "task": "newest mail" }),
                    &ToolCtx::new("aux", home),
                )
                .await;
        });
        (task, started)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_delegation_clears_its_live_line() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let (mut task, started) = stalled_delegation_task(home.clone()).await;
        started.notified().await;
        assert!(tokio::time::timeout(std::time::Duration::ZERO, &mut task)
            .await
            .is_err());
        task.abort();
        let _ = task.await;
        assert_no_live_line(&home, "mail");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_delegation_clears_its_live_line() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let (task, started) = stalled_delegation_task(home.clone()).await;
        started.notified().await;
        task.abort();
        let _ = task.await;
        assert_no_live_line(&home, "mail");
    }

    #[test]
    fn restart_retires_persisted_live_delegations() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let store = Store::open(&kernel_core::store_path(home)).unwrap();
        let row = store
            .create_delegation(
                "dl-stale",
                "aux",
                "calendar",
                "check the next event",
                None,
                PrivacyMode::Open,
            )
            .unwrap();
        store
            .set_delegation_state(&row.id, DelegationState::Working)
            .unwrap();
        store
            .append_delegation_step(
                &row.id,
                &aux_store::DelegationStep {
                    text: "running apple_calendar_list_events".into(),
                    at: "2026-10-24 17:40:00".into(),
                    state: "working".into(),
                    where_ran: None,
                },
            )
            .unwrap();
        drop(store);

        assert_eq!(recover_interrupted(home).unwrap(), 1);
        assert_no_live_line(home, "calendar");
        let rows = Store::open(&kernel_core::store_path(home))
            .unwrap()
            .list_delegations(None)
            .unwrap();
        assert_eq!(rows[0].state, DelegationState::Failed);
        assert_eq!(rows[0].steps[0].text, "running apple_calendar_list_events");
    }

    /// Keeps the floor the child turn would run under, and answers at once.
    #[derive(Default)]
    struct Floor(std::sync::OnceLock<ModeFn>);

    #[async_trait]
    impl DelegationExecutor for Floor {
        async fn execute(&self, run: DelegationRun) -> Result<String, String> {
            let _ = self.0.set(Arc::clone(&run.caller_mode));
            Ok("done".to_string())
        }
    }

    fn set_mode(home: &std::path::Path, mode: &str) {
        let config = format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n");
        std::fs::write(kernel_core::config_path(home), config).unwrap();
    }

    /// Delegate once under `config` from a turn running under `turn`: the
    /// child's floor and the stored row.
    async fn delegate(home: &std::path::Path, config: &str, turn: ModeFn) -> (ModeFn, Delegation) {
        set_mode(home, config);
        let floor = Arc::new(Floor::default());
        let tool = DelegateTool::new(home.to_path_buf(), None, floor.clone(), None);
        let ctx = ToolCtx::new("aux", home.to_path_buf()).with_turn_mode(turn);
        let args = serde_json::json!({ "agent": "mail", "task": "newest mail" });
        tool.run(&args, &ctx).await.unwrap();
        let rows = Store::open(&kernel_core::store_path(home))
            .unwrap()
            .list_delegations(None)
            .unwrap();
        (floor.0.get().unwrap().clone(), rows[0].clone())
    }

    fn resume(home: &std::path::Path, row: &Delegation) -> PrivacyMode {
        let db = kernel_core::store_path(home);
        let run = DelegationRun::open(row, home, &db, None, TurnCancel::new()).unwrap();
        (run.caller_mode)()
    }

    /// Seal P1-a: a turn Private only through its own mode handle (a Private
    /// caller or channel) hands a Private floor over, under an Open config.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_private_caller_turn_hands_over_private_under_an_open_config() {
        let dir = tempfile::tempdir().unwrap();
        let (floor, row) = delegate(dir.path(), "public", Arc::new(|| PrivacyMode::Private)).await;
        assert_eq!(
            (floor(), row.caller_mode),
            (PrivacyMode::Private, PrivacyMode::Private)
        );
    }

    /// Open at handoff keeps following the caller's turn: a later switch of it
    /// to Private tightens the child.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_handoff_still_tightens_to_private() {
        let dir = tempfile::tempdir().unwrap();
        let private = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&private);
        let turn: ModeFn = Arc::new(move || match flag.load(Ordering::SeqCst) {
            true => PrivacyMode::Private,
            false => PrivacyMode::Open,
        });
        let (floor, row) = delegate(dir.path(), "public", turn).await;
        assert_eq!(
            (floor(), row.caller_mode),
            (PrivacyMode::Open, PrivacyMode::Open)
        );
        private.store(true, Ordering::SeqCst);
        assert_eq!(floor(), PrivacyMode::Private);
    }

    /// Seal P1-b: a delegation made under Private resumes Private after the
    /// chief turned Open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_private_delegation_resumes_private_after_a_switch_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let live = crate::privacy_wiring::live_mode_fn(home);
        let (_, row) = delegate(home, "private", live).await;
        set_mode(home, "public");
        assert_eq!(resume(home, &row), PrivacyMode::Private);
    }

    /// A row from before the stored mode resumes Private, whatever the config.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_legacy_row_with_no_stored_mode_resumes_private() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let (_, row) = delegate(home, "public", Arc::new(|| PrivacyMode::Open)).await;
        assert_eq!(resume(home, &row), PrivacyMode::Open);
        let db = kernel_core::store_path(home);
        aux_store::open_keyed(&db)
            .unwrap()
            .execute("UPDATE delegations SET caller_mode = NULL", [])
            .unwrap();
        let row = Store::open(&db)
            .unwrap()
            .delegation(&row.id)
            .unwrap()
            .unwrap();
        assert_eq!(resume(home, &row), PrivacyMode::Private);
    }

    #[test]
    fn ids_are_unique_and_prefixed() {
        let a = new_id();
        let b = new_id();
        assert!(a.starts_with("dl-"));
        assert_ne!(a, b);
    }
}

#[cfg(test)]
mod source_tests;
#[cfg(test)]
mod where_tests;
