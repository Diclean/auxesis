//! The skill executor.
//!
//! A skill run is: a model fills the `skill__<name>` tool with **tokens only**
//! (validated by [`crate::skills::validate_fill`]); the executor rehydrates the
//! real values locally, checks the recipient policy per value, asks the owner
//! **once per run** (`each_run`) or once per action (`each_action`), then runs
//! each approved call through the broker and the connector. No retry, ever:
//! the first failure stops the run (`on_failure: stop`).
//!
//! Real values never leave this module except into a connector call. The
//! approval card renders them locally; the Ledger rows and the tool result
//! returned to the model carry tokens only.
//!
//! The executor is deliberately dependency-light so it can be tested without a
//! network, a provider or a real clock:
//!
//! * [`SkillApprover`] — the run-level approval card (one per run, or one per
//!   action). A refusal or a 600 s silence stops the run.
//! * [`Clock`] — the timeout is driven by an injected clock, so a test can make
//!   silence happen with no real sleep.
//! * [`SkillConnector`] — the connector call, given the real arguments and the
//!   [`SkillContext`] proof.
//! * [`RecipientDirectory`] — the `known-contacts` check.
//! * [`kernel_privacy::TokenMap`] — the session's token ↔ value map, read from
//!   the vault ([`session_token_map`]).

use std::time::Duration;

use async_trait::async_trait;
use kernel_broker::{AuditSink, AuthorizeRequest, Broker, ExecutionMode, Risk, SkillRef, Taint};
use kernel_privacy::{LinkGuard, TokenMap, Vault, VaultError, PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
use serde_json::{json, Map, Value};

use crate::skills::fill::{
    log_rejected_fill, overwrite_derived_recipients, recipients_are_runtime_owned,
    substitute_derived_recipients, RunContext, ValidatedFill,
};
use crate::skills::{event_time, free_times, tool_map};
use crate::skills::{Approval, LoadedSkill};

mod mailbox;
pub use mailbox::{senders_named, MailboxScan, MailboxSender, QUOTES_MAILBOX, SENDER_SCAN_LIMIT};

/// Silence is no: an approval unanswered for this long is a refusal, nothing
/// executes, and `skill.run` records `timeout`.
pub const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 600;

/// The default approval timeout as a [`Duration`].
pub fn default_approval_timeout() -> Duration {
    Duration::from_secs(DEFAULT_APPROVAL_TIMEOUT_SECS)
}

/// The identity of the loaded skill a connector call runs under
/// (`name`, `version`, `hash`).
///
/// This is the executor's own context; the Google connector's
/// `aux_google::SkillContext` is the same three identity fields and is built
/// from this at the wiring layer (the turn's taint stays here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillContext {
    /// Loaded skill name (the file stem).
    pub name: String,
    /// Owner-bumped version.
    pub version: u32,
    /// blake3 of the skill file bytes, hex.
    pub hash: String,
    /// Whether the conversation had read outside content when the run started.
    /// A connector that writes durable memory keeps its rows quarantined under
    /// this flag, exactly like `remember` (CRM-NOTE-P3).
    pub tainted: bool,
}

impl SkillContext {
    /// The context of a loaded skill.
    pub fn from_loaded(skill: &LoadedSkill) -> Self {
        SkillContext {
            name: skill.name.clone(),
            version: skill.version,
            hash: skill.hash.clone(),
            tainted: false,
        }
    }

    /// The broker's skill reference for this exact file.
    pub fn skill_ref(&self) -> SkillRef {
        SkillRef {
            name: self.name.clone(),
            version: self.version.to_string(),
            hash: self.hash.clone(),
        }
    }
}

/// One call as it appears on the approval card.
#[derive(Debug, Clone, PartialEq)]
pub struct CardCall {
    /// Wire name the provider used.
    pub tool: String,
    /// Canonical logical name.
    pub logical: String,
    /// Real values, rendered locally (Mac only).
    pub real_arguments: Value,
    /// What the model saw: the tokenised arguments.
    pub token_arguments: Value,
}

/// The approval card: one per run (`each_run`) or one per action
/// (`each_action`). Fields are ordered as described below.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalCard {
    /// Skill name.
    pub skill_name: String,
    /// Skill version.
    pub skill_version: u32,
    /// Skill file hash.
    pub skill_hash: String,
    /// Approval level that produced this card.
    pub level: Approval,
    /// Why the owner is being asked (level + the calls' tools).
    pub reason: String,
    /// Seconds before silence is a refusal.
    pub countdown_secs: u64,
    /// The call(s) this card covers.
    pub calls: Vec<CardCall>,
    /// `{address, label}` of a recipient read from the mailbox, for the `To` line.
    pub recipient_source: Option<Value>,
}

/// What the owner answered for a card.
#[derive(Debug, Clone, PartialEq)]
pub enum RunDecision {
    /// Approved. `edits`, when non-empty, is aligned with the card's calls and
    /// carries a replacement argument object for a call the owner edited (the
    /// email body is rehydrated and editable). An empty list means "run the
    /// requested arguments unchanged".
    Approved {
        /// Per-call replacement arguments, aligned with `card.calls`.
        edits: Vec<Option<Value>>,
    },
    /// The owner refused.
    Refused,
    /// No answer before the timeout.
    Timeout,
}

impl RunDecision {
    /// Approve with no edits.
    pub fn approved() -> Self {
        RunDecision::Approved { edits: Vec::new() }
    }

    /// Approve with per-call edits.
    pub fn edited(edits: Vec<Option<Value>>) -> Self {
        RunDecision::Approved { edits }
    }

    /// The replacement for call `index`, when the owner supplied one.
    pub fn edit_for(&self, index: usize) -> Option<&Value> {
        match self {
            RunDecision::Approved { edits } => edits.get(index).and_then(Option::as_ref),
            _ => None,
        }
    }
}

/// The run-level approval card. One implementation per surface (Mac, Telegram,
/// CLI, tests).
#[async_trait]
pub trait SkillApprover: Send + Sync {
    /// Show `card` and return the owner's answer. A failure to reach the owner
    /// is a refusal: return [`RunDecision::Refused`].
    async fn decide(&self, card: &ApprovalCard) -> RunDecision;
}

/// The clock the approval timeout is measured against.
#[async_trait]
pub trait Clock: Send + Sync {
    /// Resolve after `duration`. A test clock can resolve without sleeping.
    async fn sleep(&self, duration: Duration);
}

/// The real clock: `tokio::time::sleep`.
#[derive(Debug, Default)]
pub struct RealClock;

#[async_trait]
impl Clock for RealClock {
    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// The run's stop check: the kill switch (STOP) or a cancelled turn. The
/// executor consults it after approval and before each connector call, so a
/// STOP between two calls sends nothing more.
pub trait RunStop: Send + Sync {
    /// True when the run must not send another call.
    fn is_stopped(&self) -> bool;
}

/// A run that is never stopped: tests and the CLI.
#[derive(Debug, Default)]
pub struct NeverStopped;

impl RunStop for NeverStopped {
    fn is_stopped(&self) -> bool {
        false
    }
}

/// The `known-contacts` directory.
pub trait RecipientDirectory: Send + Sync {
    /// True when `value` (an email or an E.164 phone) is a known contact.
    fn is_known(&self, value: &str) -> bool;

    /// The e-mail addresses of the known contact whose whole name matches
    /// `name` (case-insensitive), for an input derived with
    /// `from: contact(<slot>)` (`docs/phase1.md` §7). The default is empty, so
    /// a directory that does not model names refuses the derivation.
    fn addresses_for_name(&self, name: &str) -> Vec<String> {
        let _ = name;
        Vec::new()
    }

    /// Every known spelling that can identify a recipient, including aliases.
    fn name_groups(&self) -> Vec<Vec<String>> {
        Vec::new()
    }

    /// The IANA time zone stored on the client card of `address`, when the
    /// directory carries one. The default is none, so a directory that does not
    /// model zones keeps the model's `attendee_time_zone`.
    fn time_zone_for(&self, address: &str) -> Option<String> {
        let _ = address;
        None
    }

    /// The mailbox sender this run's directory added, shown on the card.
    fn mailbox_sender(&self) -> Option<&MailboxSender> {
        None
    }
}

/// The kernel's contact index is the production directory: a value is known
/// when it equals one of a person's emails or E.164 phone numbers.
impl RecipientDirectory for kernel_privacy::ContactIndex {
    fn is_known(&self, value: &str) -> bool {
        let needle = value.trim();
        self.people().any(|person| {
            person
                .emails
                .iter()
                .any(|email| email.as_str().eq_ignore_ascii_case(needle))
                || person.phones.iter().any(|phone| phone.as_str() == needle)
        })
    }

    fn addresses_for_name(&self, name: &str) -> Vec<String> {
        let needle = normalize_contact_name(name);
        if needle.is_empty() {
            return Vec::new();
        }
        let mut addresses: Vec<String> = Vec::new();
        for person in self.people() {
            if !whole_name_matches(person, &needle) {
                continue;
            }
            for email in &person.emails {
                let email = email.as_str();
                if !addresses
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(email))
                {
                    addresses.push(email.to_string());
                }
            }
        }
        addresses
    }

    fn name_groups(&self) -> Vec<Vec<String>> {
        self.people()
            .map(|person| {
                let mut names = Vec::new();
                if let Some(display) = &person.display_name {
                    names.push(display.to_string());
                }
                let given = person
                    .given
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let family = person
                    .family
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                match (given.is_empty(), family.is_empty()) {
                    (false, false) => {
                        names.push(format!("{given} {family}"));
                        names.push(format!("{family} {given}"));
                    }
                    (false, true) => names.push(given),
                    (true, false) => names.push(family),
                    (true, true) => {}
                }
                names.extend(
                    person
                        .nicknames
                        .iter()
                        .map(|name| name.as_str().to_string()),
                );
                names
            })
            .collect()
    }
}

/// Whether `person`'s whole name equals `needle` (already lower-cased). A
/// display name, `given family` and `family given` all count; a partial name
/// does not.
fn whole_name_matches(person: &kernel_privacy::Person, needle: &str) -> bool {
    let mut spellings: Vec<String> = Vec::new();
    if let Some(display) = &person.display_name {
        spellings.push(display.to_string());
    }
    let given = person
        .given
        .iter()
        .map(|word| word.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let family = person
        .family
        .iter()
        .map(|word| word.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    match (given.is_empty(), family.is_empty()) {
        (false, false) => {
            spellings.push(format!("{given} {family}"));
            spellings.push(format!("{family} {given}"));
        }
        (false, true) => spellings.push(given),
        (true, false) => spellings.push(family),
        (true, true) => {}
    }
    spellings.extend(
        person
            .nicknames
            .iter()
            .map(|name| name.as_str().to_string()),
    );
    spellings
        .iter()
        .any(|spelling| normalize_contact_name(spelling) == needle)
}

/// A connector failure. The message must never carry a real value
/// (`skill.action.error` has "no real values").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorError {
    /// Safe, value-free reason.
    pub message: String,
    /// Safe, value-free metadata for a connector-specific Ledger row (the mail
    /// send's `mail.call`). Never owner content: no address, subject or body.
    pub ledger: Value,
    /// True when the owner must decide before the call may go out again
    /// (CAL-DEFAULT-ID r1): the connector refused because the facts it
    /// checked no longer hold. The connector wrote nothing, so the owner may
    /// still say yes.
    pub needs_approval: bool,
}

impl ConnectorError {
    /// Build a value-free connector error.
    pub fn new(message: impl Into<String>) -> Self {
        ConnectorError {
            message: message.into(),
            ledger: Value::Null,
            needs_approval: false,
        }
    }

    /// Attach safe Ledger metadata (a typed kind and reply class).
    pub fn with_ledger(mut self, ledger: Value) -> Self {
        self.ledger = ledger;
        self
    }

    /// Mark the error as one the owner must answer before the call is tried
    /// again (CAL-DEFAULT-ID r1).
    pub fn with_approval(mut self) -> Self {
        self.needs_approval = true;
        self
    }
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConnectorError {}

/// The `send-draft` skill's body marker: the call arguments are empty and the
/// runtime loads the stored draft named by the skill's `draft_id` slot.
pub const DRAFT_MARKER: &str = "{draft}";

/// The slot the `send-draft` skill fills with the stored draft id.
pub const DRAFT_INPUT: &str = "draft_id";

/// The one line the owner sees when a send may have reached the server and the
/// draft can no longer be sent as it is.
pub const UNCERTAIN_DRAFT: &str = "This mail may have been sent: check your Sent folder \
    before sending again; to send again, write a new draft.";

/// One stored `mail.draft`, loaded before the send card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDraft {
    /// The resolved recipient addresses.
    pub to: Vec<String>,
    /// One human line per address, for the card and the journal.
    pub to_display: Vec<String>,
    pub subject: String,
    pub body: String,
}

/// The connector call, with the real arguments and the [`SkillContext`] proof.
#[async_trait]
pub trait SkillConnector: Send + Sync {
    /// Run one logical tool with real `arguments` inside `skill`'s context.
    /// Exactly one attempt is made; the executor never retries.
    async fn call(
        &self,
        skill: &SkillContext,
        logical: &str,
        arguments: &Value,
    ) -> Result<Value, ConnectorError>;

    /// The configured account slugs behind this connector, for the `mail.call`
    /// row. A connector that names no account returns the default empty list,
    /// so the executor logs `unknown` rather than a raw argument.
    fn account_ids(&self) -> Vec<String> {
        Vec::new()
    }

    /// The `(id, guest count, calendar)` of the event a
    /// `calendar.update_event` names, found before its card (an error refuses
    /// the run). `None` when this connector cannot tell, and a `None` count
    /// when the guests are unknown: the update then keeps its card.
    fn find_event(&self, _arguments: &Value) -> FoundEvent {
        Ok(None)
    }

    /// The `From` of the newest INBOX mails, newest first. `None` means this
    /// connector has no mailbox configured; `Some` with an empty list means a
    /// mailbox was read and held no mail.
    async fn received_senders(&self) -> Option<MailboxScan> {
        None
    }

    /// The stored draft `id`, when it exists and can still be sent. Loaded
    /// before the card, so an unknown, already-sent or uncertain draft refuses
    /// with no card. `Err` carries the one owner-facing line for an uncertain
    /// draft.
    fn mail_draft(&self, _id: i64) -> Result<Option<StoredDraft>, String> {
        Ok(None)
    }
}

/// What [`SkillConnector::find_event`] found about the event an update names.
///
/// `in_default_calendar` is set only when the event was found **by its id**
/// and the copy says, by id, that it sits on the owner's default calendar: a
/// title match names the event, not the calendar it sits on (CAL-DEFAULT-ID).
/// `calendar_id` is then the id the write must find again (CAL-DEFAULT-ID r1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundEventFacts {
    /// The event's own id, as the calendar copy holds it.
    pub id: String,
    /// The guest count, when the copy is fresh and lists them; `None` = unknown.
    pub guests: Option<usize>,
    /// The title of the calendar the event sits on.
    pub calendar: String,
    /// The id of that calendar, when the copy holds it.
    pub calendar_id: Option<String>,
    /// True when the copy proves the event sits on the default calendar.
    pub in_default_calendar: bool,
}

/// What [`SkillConnector::find_event`] found.
pub type FoundEvent = Result<Option<FoundEventFacts>, String>;

/// The mailbox a call names, from the configured slugs and what the caller
/// named.
///
/// The model is never told the account slugs, so a call that names one may
/// name a mailbox this Mac does not have: with one configured account the
/// call goes to it, with several it is refused and the owner is asked which
/// mailbox to use. The first account is never picked.
pub fn resolve_account(ids: &[String], named: Option<&str>) -> Result<String, String> {
    let named = named.map(str::trim).filter(|named| !named.is_empty());
    if let Some(named) = named.as_ref() {
        if ids.iter().any(|id| id == named) {
            return Ok(named.to_string());
        }
    }
    match ids {
        [only] => Ok(only.clone()),
        [] => match named {
            // No account is known here: the name is used as it is, and the
            // mail service refuses it when this Mac has no such mailbox.
            Some(named) => Ok(named.to_string()),
            None => Err("no mailbox is configured".to_string()),
        },
        _ => Err(match named {
            Some(named) => format!("no mailbox `{named}`; configured: {}", ids.join(", ")),
            None => format!("an account is required; configured: {}", ids.join(", ")),
        }),
    }
}

/// The run-level card, rendered as the arguments of one approval request.
///
/// `real` values stay on the owner's channel; `model_saw` is the token form the
/// provider filled.
pub fn card_arguments(card: &ApprovalCard) -> Value {
    let mut arguments = json!({
        "skill": card.skill_name,
        "skill_version": card.skill_version,
        "skill_hash": card.skill_hash,
        "level": card.level.as_str(),
        "reason": card.reason,
        "countdown_secs": card.countdown_secs,
        "calls": card
            .calls
            .iter()
            .map(|call| {
                json!({
                    "tool": call.tool,
                    "real": call.real_arguments,
                    "model_saw": call.token_arguments,
                })
            })
            .collect::<Vec<_>>(),
    });
    if let Some(source) = &card.recipient_source {
        arguments["recipient_source"] = source.clone();
    }
    arguments
}

/// One call of a run card, as it runs: its wire tool and its arguments.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RunCall<'a> {
    /// The wire tool name.
    pub tool: &'a str,
    /// The arguments it runs with: the call's `real` object.
    pub real: &'a Value,
}

/// The calls of a run card, or of the owner's edit of one, as they run
/// (SEND-REAL-ARGS-1).
///
/// The approval card and the executor both read a run through this one
/// function, so the card shows what runs. Each call names its wire `tool` and
/// carries its arguments as the object `real`; every other key (`model_saw`,
/// `arguments`, a field beside `real`, a field beside `calls`) is ignored by
/// both. A run that cannot be read this way is refused, never guessed: no
/// calls, a call that is not an object, without a tool, or without an object
/// `real`.
pub fn run_calls(value: &Value) -> Result<Vec<RunCall<'_>>, String> {
    let calls = value
        .get("calls")
        .and_then(Value::as_array)
        .ok_or("the run has no `calls` list")?;
    if calls.is_empty() {
        return Err("the run has no calls".to_string());
    }
    calls
        .iter()
        .enumerate()
        .map(|(index, call)| {
            let number = index + 1;
            let tool = call
                .get("tool")
                .and_then(Value::as_str)
                .filter(|tool| !tool.is_empty())
                .ok_or_else(|| format!("call {number} names no `tool`"))?;
            let real = call
                .get("real")
                .filter(|real| real.is_object())
                .ok_or_else(|| format!("call {number} has no `real` arguments object"))?;
            Ok(RunCall { tool, real })
        })
        .collect()
}

/// Map an edited whole-run payload back to the executor's per-call edits.
///
/// An answer that does not parse as an edit is an **error**, never an empty
/// edit: a caller must refuse the run, never fall back to the arguments the
/// run asked for.
pub fn edits_from_card(value: &Value, card: &ApprovalCard) -> Result<Vec<Option<Value>>, String> {
    edits_from_answer(value, card)
}

/// Parse an edited answer strictly with [`run_calls`]: one call per call of
/// the card, each with the card's tool. `Err` when it does not parse, so the
/// answer refuses instead of running the original or a guess.
pub fn edits_from_answer(value: &Value, card: &ApprovalCard) -> Result<Vec<Option<Value>>, String> {
    let calls = run_calls(value)?;
    if calls.len() != card.calls.len() {
        return Err(format!(
            "the edit has {} calls, the run has {}",
            calls.len(),
            card.calls.len()
        ));
    }
    for (number, (edited, call)) in calls.iter().zip(&card.calls).enumerate() {
        if edited.tool != call.tool {
            return Err(format!(
                "call {} must stay `{}`, the edit names `{}`",
                number + 1,
                call.tool,
                edited.tool
            ));
        }
    }
    Ok(calls
        .iter()
        .map(|edited| Some(edited.real.clone()))
        .collect())
}

/// Bridges the executor's [`SkillApprover`] onto the daemon's [`Approver`]:
/// one card for the whole run, answered through the existing approval channel.
pub struct BrokerCardApprover {
    inner: std::sync::Arc<dyn kernel_broker::Approver>,
    agent: String,
    tainted: bool,
    taint_source: Option<String>,
}

impl BrokerCardApprover {
    /// A card approver that publishes through `inner` for `agent`.
    pub fn new(
        inner: std::sync::Arc<dyn kernel_broker::Approver>,
        agent: impl Into<String>,
    ) -> Self {
        BrokerCardApprover {
            inner,
            agent: agent.into(),
            tainted: false,
            taint_source: None,
        }
    }

    /// Carry the conversation's taint onto the card.
    pub fn tainted(mut self, source: Option<String>) -> Self {
        self.tainted = source.is_some();
        self.taint_source = source;
        self
    }
}

#[async_trait]
impl SkillApprover for BrokerCardApprover {
    async fn decide(&self, card: &ApprovalCard) -> RunDecision {
        let request = kernel_broker::ApprovalRequest {
            agent: self.agent.clone(),
            tool: format!("skill__{}", card.skill_name),
            // One card covers the whole run: the highest risk of its calls.
            risk: Risk::High,
            arguments: card_arguments(card),
            tainted: self.tainted,
            taint_source: self.taint_source.clone(),
            web_approval: None,
            unsandboxed: false,
            networked: false,
        };
        // The registry denies when the owner's countdown runs out. An answer
        // that arrives that late is a timeout, not an owner refusal (F4). The
        // executor's own clock still bounds the wait for a silent registry.
        let started = tokio::time::Instant::now();
        let answer = self.inner.decide(&request).await;
        if started.elapsed() >= Duration::from_secs(card.countdown_secs) {
            return RunDecision::Timeout;
        }
        match answer {
            Ok(decision) if decision.allow => match decision.arguments {
                // An edit that does not parse refuses the run (F5): the
                // requested arguments never run in its place.
                Some(value) => match edits_from_answer(&value, card) {
                    Ok(edits) => RunDecision::Approved { edits },
                    Err(_) => RunDecision::Refused,
                },
                None => RunDecision::approved(),
            },
            // A refused ask and a broken channel are both a refusal.
            _ => RunDecision::Refused,
        }
    }
}

/// One call's model-facing result, re-tokenised before it re-enters the
/// conversation.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionResult {
    /// Wire name.
    pub tool: String,
    /// Canonical logical name.
    pub logical: String,
    /// The connector's reply with every real value replaced by its token.
    pub content: Value,
}

/// The end of a run.
#[derive(Debug, Clone, PartialEq)]
pub enum RunOutcome {
    /// Every approved call ran; `actions` holds their re-tokenised results.
    Done {
        /// One entry per executed call, in order.
        actions: Vec<ActionResult>,
    },
    /// The owner refused, or policy refused a call.
    Refused {
        /// Value-free reason.
        reason: String,
        /// True when the reason quotes mailbox `From` names: the engine then
        /// marks the conversation tainted.
        tainted: bool,
    },
    /// The approval was unanswered for the timeout.
    Timeout,
    /// A call failed, or rehydration failed. The run stopped.
    Failed {
        /// Value-free reason.
        error: String,
    },
}

impl RunOutcome {
    /// The `skill.run` outcome string.
    pub fn ledger_outcome(&self) -> &'static str {
        match self {
            RunOutcome::Done { .. } => "done",
            RunOutcome::Refused { .. } => "refused",
            RunOutcome::Timeout => "timeout",
            RunOutcome::Failed { .. } => "failed",
        }
    }
}

/// Read the session's token map from the vault (the executor's vault read
/// path). A session with no record yields an empty map.
pub fn session_token_map(vault: &Vault, session_id: &str) -> Result<TokenMap, VaultError> {
    vault.lookup(session_id)
}

/// One call after local rehydration.
#[derive(Debug, Clone)]
struct ExecCall {
    tool: String,
    logical: String,
    token_arguments: Value,
    real_arguments: Value,
}

/// The per-run state threaded through approval and execution.
struct RunState<'a, 'r> {
    skill: &'a LoadedSkill,
    run: &'a RunContext<'r>,
    taint: &'a Taint,
    context: &'a SkillContext,
    tokens: &'a dyn TokenResolver,
}

/// Why a single call could not run.
enum CallFailure {
    /// A policy refused it (recipient or broker).
    Refused(String),
    /// The connector or broker failed.
    Failed(String),
}

/// The skill executor. Every dependency is borrowed for the duration of one
/// run; nothing here is global.
pub struct Executor<'a> {
    /// The broker that authorizes each call with the skill reference.
    pub broker: &'a Broker,
    /// Ledger sink for the `skill.*` rows.
    pub sink: &'a dyn AuditSink,
    /// The run-level approval card.
    pub approver: &'a dyn SkillApprover,
    /// The connector.
    pub connector: &'a dyn SkillConnector,
    /// The `known-contacts` directory.
    pub directory: &'a dyn RecipientDirectory,
    /// The agent's `recipients.allowlist`, used by the `allowlist` policy.
    pub allowlist: &'a [String],
    /// The approval timeout clock.
    pub clock: &'a dyn Clock,
    /// STOP or cancellation, consulted before each connector call.
    pub stop: &'a dyn RunStop,
    /// How long silence is tolerated before it is a refusal.
    pub approval_timeout: Duration,
}

impl Executor<'_> {
    /// Run an already-validated skill fill. `tokens` is the session's vault
    /// map; `taint` is the conversation's taint state at the time of the run.
    pub async fn execute(
        &self,
        skill: &LoadedSkill,
        fill: &ValidatedFill,
        run: &RunContext<'_>,
        tokens: &dyn TokenResolver,
        taint: &Taint,
    ) -> RunOutcome {
        match self.mailbox_recipient(skill, fill, run, tokens).await {
            Ok(None) => self.execute_resolved(skill, fill, run, tokens, taint).await,
            Ok(Some((said, sender))) => {
                let directory = mailbox::WithMailboxSender {
                    inner: self.directory,
                    said,
                    sender,
                };
                Executor {
                    directory: &directory,
                    ..*self
                }
                .execute_resolved(skill, fill, run, tokens, taint)
                .await
            }
            Err(outcome) => outcome,
        }
    }

    /// For an unambiguous follow-up send, bind the contact to the immediately
    /// preceding owner turn. The caller must provide only locally stored,
    /// owner-authored text from this same thread; no other history is trusted.
    pub async fn execute_with_previous_owner(
        &self,
        skill: &LoadedSkill,
        fill: &ValidatedFill,
        run: &RunContext<'_>,
        tokens: &dyn TokenResolver,
        taint: &Taint,
        previous_owner: Option<&str>,
    ) -> RunOutcome {
        let current = run.owner_input.unwrap_or_default();
        // A short, fixed list of bare follow-ups in the owner's two languages.
        // Anything longer is a new ask and keeps the current-message rule.
        let follow_up = current
            .trim()
            .trim_end_matches(['.', '!', '?'])
            .trim()
            .to_lowercase();
        let is_send_it = matches!(
            follow_up.as_str(),
            "send it"
                | "send"
                | "ok send it"
                | "ok, send it"
                | "yes send it"
                | "yes, send it"
                | "envoie"
                | "envoie-le"
                | "envoie le"
                | "envoie-la"
                | "envoie la"
                | "ok envoie"
                | "ok, envoie"
                | "vas-y envoie"
                | "vas-y, envoie"
        );
        let single_mail = skill.effective_tools.len() == 1
            && skill.effective_tools.iter().any(|tool| tool == "mail.send")
            && skill
                .inputs
                .iter()
                .filter(|input| input.from.is_some())
                .count()
                == 1;
        let current_names = maximal_contact_name_matches(current, &self.directory.name_groups());
        let source_in_current = skill
            .inputs
            .iter()
            .filter_map(|input| input.from.as_ref())
            .filter_map(|source| fill.slots.iter().find(|(name, _)| name == source))
            .filter_map(|(_, value)| restore_value(&Value::String(value.clone()), tokens).ok())
            .filter_map(|value| value.as_str().map(str::to_owned))
            .any(|name| contains_ascii_case_insensitive_name(current, &name));
        let owner_input =
            if is_send_it && single_mail && current_names.is_empty() && !source_in_current {
                previous_owner.or(run.owner_input)
            } else {
                run.owner_input
            };
        let run = RunContext {
            owner_input,
            ..*run
        };
        self.execute(skill, fill, &run, tokens, taint).await
    }

    /// MAIL-UNKNOWN-CONTACT-1: a contact the owner typed that Clients cannot
    /// resolve is looked up among received senders. One is used and shown on
    /// the card; none or several refuse with one short question.
    async fn mailbox_recipient(
        &self,
        skill: &LoadedSkill,
        fill: &ValidatedFill,
        run: &RunContext<'_>,
        tokens: &dyn TokenResolver,
    ) -> Result<Option<(String, MailboxSender)>, RunOutcome> {
        let mut sources = skill.inputs.iter().filter_map(|input| input.from.as_ref());
        let (Some(source), None) = (sources.next(), sources.next()) else {
            return Ok(None);
        };
        let Some(owner_input) = run.owner_input else {
            return Ok(None);
        };
        let Some((_, value)) = fill.slots.iter().find(|(name, _)| name == source) else {
            return Ok(None);
        };
        let Ok(Value::String(name)) = restore_value(&Value::String(value.clone()), tokens) else {
            return Ok(None);
        };
        let directory = self.directory;
        if !contains_ascii_case_insensitive_name(owner_input, &name)
            || !directory.addresses_for_name(&name).is_empty()
            || directory.is_known(&name)
            || !maximal_contact_name_matches(owner_input, &directory.name_groups()).is_empty()
        {
            return Ok(None);
        }
        // No mailbox keeps the contacts-only path. An empty or partial scan
        // still asks: the owner may name the address, or a lone match may not
        // be unique.
        let Some(scan) = self.connector.received_senders().await else {
            return Ok(None);
        };
        let senders = senders_named(&scan.senders, &name);
        if scan.complete {
            if let [one] = senders.as_slice() {
                // A display name and its address are attacker text: the
                // mailbox may only pick an address the owner already wrote to
                // (or, with no Sent folder, one that wrote on two days).
                if let Some(reason) = mailbox::trust_refusal(value, one, &scan) {
                    log_rejected_fill(Some(self.sink), skill, run, None, &reason);
                    return Err(self.finish_refused(skill, run, &reason));
                }
                return Ok(Some((name, one.clone())));
            }
        }
        let reason = mailbox::question(value, &senders, scan.complete);
        log_rejected_fill(Some(self.sink), skill, run, None, &reason);
        if senders.is_empty() {
            Err(self.finish_refused(skill, run, &reason))
        } else {
            Err(self.finish_refused_tainted(skill, run, &reason))
        }
    }

    /// [`Executor::execute`] once the recipient directory is settled.
    async fn execute_resolved(
        &self,
        skill: &LoadedSkill,
        fill: &ValidatedFill,
        run: &RunContext<'_>,
        tokens: &dyn TokenResolver,
        taint: &Taint,
    ) -> RunOutcome {
        let mut context = SkillContext::from_loaded(skill);
        context.tainted = taint.forces_ask();

        // Resolve every `from: contact(<slot>)` input from the owner's contacts
        // before the card: the address the model never supplies
        // (`docs/phase1.md` §7).
        let derived = match self.resolve_derived_slots(skill, fill, run, tokens) {
            Ok(derived) => derived,
            Err(outcome) => return outcome,
        };
        // One derived contact means the runtime owns every recipient field:
        // the model's recipient values are replaced, not merely substituted.
        let runtime_owned = recipients_are_runtime_owned(skill);
        // CLIENT-TZ-FIELD: a known client's own zone decides the invite's
        // attendee zone, not the model's guess.
        let client_zone = self.attendee_time_zone(fill, tokens, &derived);

        // Rehydrate every call locally first: the card renders real values, and
        // any unknown/forged token refuses the whole run before an approval is
        // even requested.
        let mut calls = Vec::with_capacity(fill.calls.len());
        for call in &fill.calls {
            if !skill.effective_tools.contains(&call.logical) {
                return self.finish_failed(
                    skill,
                    run,
                    "tool is not in the skill's effective tools",
                );
            }
            // With one derived contact the resolved address overwrites every
            // recipient field the model wrote and is inserted where the tool
            // requires one; with several, a call that references a derived slot
            // gets the resolved value only where it carried the source value,
            // and the rest of the arguments keep the model's token so a name in
            // the body still rehydrates.
            let token_arguments = if runtime_owned {
                let address = derived
                    .first()
                    .map(|(_, token)| token.as_str())
                    .unwrap_or_default();
                overwrite_derived_recipients(&call.logical, &call.arguments, address)
            } else {
                substitute_derived_recipients(&call.logical, &call.arguments, &derived)
            };
            let real = match restore_value(&token_arguments, tokens) {
                Ok(real) => real,
                Err(err) => {
                    return self.finish_failed(skill, run, &err);
                }
            };
            // M4-2: an event's time is resolved in its zone before the card,
            // so the card shows the exact instant the `.ics` carries.
            let real = match resolve_times(&call.logical, &real, client_zone.as_deref()) {
                Ok(real) => real,
                Err(reason) => return self.finish_refused(skill, run, &reason),
            };
            let real = match with_found_event(self.connector, &call.logical, real) {
                Ok(real) => real,
                Err(reason) => return self.finish_refused(skill, run, &reason),
            };
            // M4-3b: the owner's free times are computed here from the local
            // calendar, never by the model, so the card shows the exact times sent.
            let real = match self
                .with_free_times(skill, fill, &context, &call.logical, real)
                .await
            {
                Ok(real) => real,
                Err(reason) => return self.finish_refused(skill, run, &reason),
            };
            // `send-draft` owns every message field: the stored draft is
            // loaded here, before the card, and the model's empty call is
            // replaced with exactly what was saved.
            let real = match self.resolve_draft_send(skill, fill, tokens, &call.logical, real) {
                Ok(real) => real,
                Err(reason) => return self.finish_refused(skill, run, &reason),
            };
            // A send goes out of one named mailbox. The account is resolved
            // here, before the card, so the card and the action name the same
            // mailbox: with several mailboxes and no name, the run is refused
            // rather than picking one.
            let real = match self.resolve_send_account(&call.logical, &real) {
                Ok(real) => real,
                Err(reason) => return self.finish_refused(skill, run, &reason),
            };
            calls.push(ExecCall {
                tool: call.tool.clone(),
                logical: call.logical.clone(),
                token_arguments,
                real_arguments: real,
            });
        }

        let state = RunState {
            skill,
            run,
            taint,
            context: &context,
            tokens,
        };
        match skill.approval {
            Approval::EachRun => self.run_each_run(&state, calls).await,
            Approval::EachAction => self.run_each_action(&state, calls).await,
            Approval::None => self.run_none(&state, calls).await,
        }
    }

    /// Replace a `send-draft` run's empty call with the stored draft: `to`,
    /// `subject` and `body` come from the journal row, never the model. The
    /// id is carried into the approved arguments so the connector claims the
    /// same row. Any other call argument refuses the run before the card.
    fn resolve_draft_send(
        &self,
        skill: &LoadedSkill,
        fill: &ValidatedFill,
        tokens: &dyn TokenResolver,
        logical: &str,
        real: Value,
    ) -> Result<Value, String> {
        if logical != "mail.send" || !skill.body.contains(DRAFT_MARKER) {
            return Ok(real);
        }
        let Some((_, value)) = fill.slots.iter().find(|(name, _)| name == DRAFT_INPUT) else {
            return Err("send-draft needs the saved draft's id; nothing was sent".to_string());
        };
        let id = match restore_value(&Value::String(value.clone()), tokens)? {
            Value::String(text) => text.trim().parse::<i64>().map_err(|_| {
                "send-draft needs the saved draft's id; nothing was sent".to_string()
            })?,
            _ => return Err("send-draft needs the saved draft's id; nothing was sent".to_string()),
        };
        let draft = match self.connector.mail_draft(id) {
            Ok(Some(draft)) => draft,
            Ok(None) => {
                return Err(
                    "no saved draft with that id (or it was already sent); nothing was sent"
                        .to_string(),
                );
            }
            Err(reason) => return Err(reason),
        };
        if real.as_object().is_none_or(|fields| !fields.is_empty()) {
            return Err("send-draft takes only a draft_id; nothing was sent".to_string());
        }
        if draft.to.is_empty() {
            return Err(
                "the saved draft has no recipient; ask the owner who to send it to".to_string(),
            );
        }
        let real = json!({
            "to": draft.to,
            "subject": draft.subject,
            "body": draft.body,
            "draft_id": id,
        });
        // The stored recipient must still pass the skill's policy before the
        // owner sees a card for it (a contact may have been removed).
        check_recipients(skill, logical, &real, self.directory, self.allowlist)?;
        Ok(real)
    }

    /// The account a `mail.send` goes out of, resolved **before** the card, so
    /// the card the owner approves and the action that follows name the same
    /// mailbox.
    fn resolve_send_account(&self, logical: &str, arguments: &Value) -> Result<Value, String> {
        if logical != "mail.send" {
            return Ok(arguments.clone());
        }
        let named = arguments.get("account").and_then(Value::as_str);
        let account = resolve_account(&self.connector.account_ids(), named)?;
        let mut arguments = arguments.clone();
        if let Some(object) = arguments.as_object_mut() {
            object.insert("account".to_string(), Value::String(account));
        }
        Ok(arguments)
    }

    /// Replace [`free_times::MARKER`] in a `mail.send` body with the owner's
    /// free windows, for a skill whose body names it; other calls as is. A mail
    /// that might state a time of its own is refused (subject too). The
    /// calendar read is local: its events never reach the model.
    async fn with_free_times(
        &self,
        skill: &LoadedSkill,
        fill: &ValidatedFill,
        context: &SkillContext,
        logical: &str,
        mut real: Value,
    ) -> Result<Value, String> {
        if logical != "mail.send" || !skill.body.contains(free_times::MARKER) {
            return Ok(real);
        }
        let zone = event_time::owner_time_zone()
            .and_then(|name| name.parse::<chrono_tz::Tz>().ok())
            .ok_or("the owner's time zone is unknown, so no free time is proposed")?;
        let length = fill
            .slots
            .iter()
            .find(|(name, _)| name == "duration")
            .map_or(Ok(chrono::Duration::minutes(30)), |(_, text)| {
                free_times::parse_length(text)
            })?;
        // Read exactly the searched days; the connector refuses a calendar it
        // cannot read in full, so no time is ever computed from part of one.
        let now = chrono::Utc::now();
        let (from, to) = free_times::search_span(now, zone)
            .ok_or("the days to search are unknown, so no free time is proposed")?;
        let span = json!({ "from": from.to_rfc3339(), "to": to.to_rfc3339() });
        let events = self
            .connector
            .call(context, free_times::CALENDAR_READ, &span)
            .await
            .map_err(|_| "the calendar is not readable in full, so no free time is proposed")?;
        let instant = |event: &Value, field: &str| {
            let text = event.get(field).and_then(Value::as_str)?;
            Some(
                chrono::DateTime::parse_from_rfc3339(text)
                    .ok()?
                    .with_timezone(&chrono::Utc),
            )
        };
        let busy = events
            .as_array()
            .ok_or("the calendar answer is not a list of events")?
            .iter()
            .map(|event| instant(event, "start").zip(instant(event, "end")))
            .collect::<Option<Vec<_>>>()
            .ok_or("a calendar event has no readable start or end")?;
        let windows = free_times::free_windows(&busy, now, zone, length);
        free_times::fill_mail(&mut real, &free_times::render(&windows, zone))?;
        Ok(real)
    }

    /// Resolve each input declared `from: contact(<slot>)` (`docs/phase1.md`
    /// §7): rehydrate the source slot, find the contact by whole name in the
    /// owner's directory, and return `(fill-time value, token form)` pairs for
    /// [`substitute_derived_recipients`].
    ///
    /// Zero addresses refuses with `no address for <value>`; several refuses
    /// with `several addresses for <value>; say which one` (the token, never a
    /// value). Both refuse the run before the card and write one
    /// `skill.rejected_fill` row.
    /// The stored IANA zone of the run's one attendee, when it is a known
    /// client that carries one (CLIENT-TZ-FIELD). A derived contact names the
    /// attendee when the skill has a `from: contact(...)` input; otherwise the
    /// calls' recipients do, but only when they name exactly one address.
    /// Several addresses are never guessed, and a directory without zones
    /// returns `None`, so the model's argument stays.
    fn attendee_time_zone(
        &self,
        fill: &ValidatedFill,
        tokens: &dyn TokenResolver,
        derived: &[(String, String)],
    ) -> Option<String> {
        let mut addresses: Vec<String> = Vec::new();
        if derived.is_empty() {
            for call in &fill.calls {
                let Ok(real) = restore_value(&call.arguments, tokens) else {
                    continue;
                };
                for address in invite_addresses(&real) {
                    if !addresses
                        .iter()
                        .any(|known| known.eq_ignore_ascii_case(&address))
                    {
                        addresses.push(address);
                    }
                }
            }
        } else if let [(_, token)] = derived {
            if let Ok(Value::String(address)) = restore_value(&Value::String(token.clone()), tokens)
            {
                addresses.push(address);
            }
        }
        let [address] = addresses.as_slice() else {
            return None;
        };
        self.directory.time_zone_for(address)
    }

    fn resolve_derived_slots(
        &self,
        skill: &LoadedSkill,
        fill: &ValidatedFill,
        run: &RunContext<'_>,
        tokens: &dyn TokenResolver,
    ) -> Result<Vec<(String, String)>, RunOutcome> {
        let mut derived = Vec::new();
        for input in &skill.inputs {
            let Some(source) = &input.from else {
                continue;
            };
            let Some((_, value)) = fill.slots.iter().find(|(name, _)| name == source) else {
                return Err(self.finish_failed(
                    skill,
                    run,
                    "a derived slot's contact source was not filled",
                ));
            };
            let name = match restore_value(&Value::String(value.clone()), tokens) {
                Ok(Value::String(name)) => name,
                Ok(_) => unreachable!("restoring a string yields a string"),
                Err(err) => return Err(self.finish_failed(skill, run, &err)),
            };
            let Some(owner_input) = run.owner_input else {
                let reason = "a contact recipient must be selected in the owner's message";
                log_rejected_fill(Some(self.sink), skill, run, None, reason);
                return Err(self.finish_refused(skill, run, reason));
            };
            let maximal = maximal_contact_name_matches(owner_input, &self.directory.name_groups());
            let selected = normalize_contact_name(&name);
            if maximal.len() > 1 {
                let reason = format!("several addresses for {value}; say which one");
                log_rejected_fill(Some(self.sink), skill, run, None, &reason);
                return Err(self.finish_refused(skill, run, &reason));
            }
            let owner_typed_known_address = maximal.len() == 1
                && self.directory.is_known(&name)
                && contains_ascii_case_insensitive_name(owner_input, &name);
            if maximal.len() == 1 && !maximal[0].contains(&selected) && !owner_typed_known_address {
                let reason = "the selected contact does not match the owner's message";
                log_rejected_fill(Some(self.sink), skill, run, None, reason);
                return Err(self.finish_refused(skill, run, reason));
            }
            if maximal.is_empty() {
                let owner_typed_known_address = self.directory.is_known(&name)
                    && contains_ascii_case_insensitive_name(owner_input, &name);
                if !owner_typed_known_address {
                    if contains_ascii_case_insensitive_name(owner_input, &name)
                        && self.directory.addresses_for_name(&name).is_empty()
                    {
                        let reason = format!("no address for {value}");
                        log_rejected_fill(Some(self.sink), skill, run, None, &reason);
                        return Err(self.finish_refused(skill, run, &reason));
                    }
                    let reason = "the contact recipient does not match the owner's message";
                    log_rejected_fill(Some(self.sink), skill, run, None, reason);
                    return Err(self.finish_refused(skill, run, reason));
                }
            }
            let addresses = self.directory.addresses_for_name(&name);
            // Address-form selection is valid only when the owner supplied
            // that exact known address in this turn's trusted message.
            let addresses = if addresses.is_empty() && self.directory.is_known(&name) {
                vec![name.clone()]
            } else {
                addresses
            };
            match addresses.as_slice() {
                [address] => {
                    // What the model saw on the card: the session's token for
                    // the address, or the address itself when nothing masked it.
                    // The map keys are bare; the card shows the delimited form.
                    let token = tokens
                        .pairs()
                        .into_iter()
                        .find(|(_, known)| known.eq_ignore_ascii_case(address))
                        .map(|(token, _)| format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"))
                        .unwrap_or_else(|| address.clone());
                    derived.push((value.clone(), token));
                }
                [] => {
                    let reason = format!("no address for {value}");
                    log_rejected_fill(Some(self.sink), skill, run, None, &reason);
                    return Err(self.finish_refused(skill, run, &reason));
                }
                _ => {
                    let reason = format!("several addresses for {value}; say which one");
                    log_rejected_fill(Some(self.sink), skill, run, None, &reason);
                    return Err(self.finish_refused(skill, run, &reason));
                }
            }
        }
        Ok(derived)
    }

    async fn run_each_run(&self, state: &RunState<'_, '_>, calls: Vec<ExecCall>) -> RunOutcome {
        let skill = state.skill;
        let run = state.run;
        let card = self.card(skill, Approval::EachRun, &calls);
        let decision = self.ask(&card).await;
        match decision {
            RunDecision::Approved { ref edits } => {
                let edited = edits.iter().any(Option::is_some);
                self.log_approval(
                    skill,
                    run,
                    Approval::EachRun,
                    &tool_names(&calls),
                    if edited { "edited" } else { "approved" },
                );
                // P2-1: every call is checked and authorized before the first
                // connector call. A refusal on call 2 must not leave call 1
                // already sent.
                let mut authorized = Vec::with_capacity(calls.len());
                for (index, call) in calls.iter().enumerate() {
                    let arguments = decision
                        .edit_for(index)
                        .cloned()
                        .unwrap_or_else(|| call.real_arguments.clone());
                    match self.authorize_call(state, call, &arguments).await {
                        Ok(executed) => authorized.push((call, executed)),
                        Err(failure) => {
                            self.log_mail_refusal(state, call, &failure);
                            return self.finish_failure(skill, run, failure);
                        }
                    }
                }
                let mut actions = Vec::with_capacity(authorized.len());
                for (call, executed) in &authorized {
                    if let Err(failure) = self.check_stop() {
                        return self.finish_failure(skill, run, failure);
                    }
                    match self.send_call(state, call, executed).await {
                        Ok(action) => actions.push(action),
                        Err(failure) => return self.finish_failure(skill, run, failure),
                    }
                    if let Err(failure) = self.check_stop_after_send() {
                        return self.finish_failure(skill, run, failure);
                    }
                }
                self.finish_done(skill, run, actions)
            }
            RunDecision::Refused => {
                self.log_approval(
                    skill,
                    run,
                    Approval::EachRun,
                    &tool_names(&calls),
                    "refused",
                );
                self.finish_refused(skill, run, "the owner refused the run")
            }
            RunDecision::Timeout => {
                self.log_approval(
                    skill,
                    run,
                    Approval::EachRun,
                    &tool_names(&calls),
                    "timeout",
                );
                self.finish_timeout(skill, run)
            }
        }
    }

    /// A read-only skill with `approval: none`: no card is shown, but every
    /// call is still authorized before the first connector call, and the STOP
    /// checks are the same as any other run. The loader only allows `none` when
    /// every tool is a read or the local `docs.ingest`, so this path can write
    /// nothing but that local append.
    async fn run_none(&self, state: &RunState<'_, '_>, calls: Vec<ExecCall>) -> RunOutcome {
        let skill = state.skill;
        let run = state.run;
        let mut authorized = Vec::with_capacity(calls.len());
        for call in &calls {
            match self.authorize_call(state, call, &call.real_arguments).await {
                Ok(executed) => authorized.push((call, executed)),
                Err(failure) => return self.finish_failure(skill, run, failure),
            }
        }
        let mut actions = Vec::with_capacity(authorized.len());
        for (call, executed) in &authorized {
            if let Err(failure) = self.check_stop() {
                return self.finish_failure(skill, run, failure);
            }
            match self.send_call(state, call, executed).await {
                Ok(action) => actions.push(action),
                Err(failure) => return self.finish_failure(skill, run, failure),
            }
            if let Err(failure) = self.check_stop_after_send() {
                return self.finish_failure(skill, run, failure);
            }
        }
        self.finish_done(skill, run, actions)
    }

    async fn run_each_action(&self, state: &RunState<'_, '_>, calls: Vec<ExecCall>) -> RunOutcome {
        let skill = state.skill;
        let run = state.run;
        let mut actions = Vec::with_capacity(calls.len());
        for call in &calls {
            let card = self.card(skill, Approval::EachAction, std::slice::from_ref(call));
            let decision = self.ask(&card).await;
            let arguments = match decision {
                RunDecision::Approved { edits } => {
                    let edited = edits.iter().any(Option::is_some);
                    self.log_approval(
                        skill,
                        run,
                        Approval::EachAction,
                        std::slice::from_ref(&call.tool),
                        if edited { "edited" } else { "approved" },
                    );
                    edits
                        .into_iter()
                        .next()
                        .flatten()
                        .unwrap_or_else(|| call.real_arguments.clone())
                }
                RunDecision::Refused => {
                    self.log_approval(
                        skill,
                        run,
                        Approval::EachAction,
                        std::slice::from_ref(&call.tool),
                        "refused",
                    );
                    return self.finish_refused(skill, run, "the owner refused the action");
                }
                RunDecision::Timeout => {
                    self.log_approval(
                        skill,
                        run,
                        Approval::EachAction,
                        std::slice::from_ref(&call.tool),
                        "timeout",
                    );
                    return self.finish_timeout(skill, run);
                }
            };
            let executed = match self.authorize_call(state, call, &arguments).await {
                Ok(executed) => executed,
                Err(failure) => {
                    self.log_mail_refusal(state, call, &failure);
                    return self.finish_failure(skill, run, failure);
                }
            };
            if let Err(failure) = self.check_stop() {
                return self.finish_failure(skill, run, failure);
            }
            match self.send_call(state, call, &executed).await {
                Ok(action) => actions.push(action),
                Err(failure) => return self.finish_failure(skill, run, failure),
            }
            if let Err(failure) = self.check_stop_after_send() {
                return self.finish_failure(skill, run, failure);
            }
        }
        self.finish_done(skill, run, actions)
    }

    /// Everything that must pass before a call may be sent: the argument checks,
    /// the recipient policy per value, and `Broker::authorize` with the skill
    /// reference. Sends nothing. Returns the arguments that will be sent.
    async fn authorize_call(
        &self,
        state: &RunState<'_, '_>,
        call: &ExecCall,
        arguments: &Value,
    ) -> Result<Value, CallFailure> {
        // Owner edits are not trusted to be well formed: they get the same
        // checks the model's fill gets, the time resolution included (a no-op
        // on the card's own arguments).
        let arguments =
            &resolve_times(&call.logical, arguments, None).map_err(CallFailure::Refused)?;
        if let Err(reason) = check_arguments(&call.logical, arguments) {
            return Err(CallFailure::Refused(reason));
        }
        // Recipient policy, per value, after rehydration.
        if let Err(reason) = check_recipients(
            state.skill,
            &call.logical,
            arguments,
            self.directory,
            self.allowlist,
        ) {
            return Err(CallFailure::Refused(reason));
        }

        // Every call goes through the broker with the skill reference.
        let info = tool_map::lookup(&call.logical);
        let read_only = info.as_ref().is_some_and(|info| info.is_read_only());
        let skill_only = info.as_ref().is_some_and(|info| info.skill_only);
        let skill_ref = state.context.skill_ref();
        let authorization = self
            .broker
            .authorize(AuthorizeRequest {
                agent: state.run.agent,
                tool: &call.tool,
                risk: risk_for(read_only, skill_only),
                arguments: arguments.clone(),
                taint: state.taint,
                read_only,
                mode: ExecutionMode::Sandboxed,
                requires_explicit_rule: false,
                skill: Some(&skill_ref),
                skill_only,
            })
            .await;
        let executed = match authorization {
            Ok(auth) if auth.is_allowed() => auth
                .arguments()
                .cloned()
                .unwrap_or_else(|| arguments.clone()),
            Ok(auth) => return Err(CallFailure::Refused(auth.reason().to_string())),
            Err(err) => return Err(CallFailure::Failed(err.to_string())),
        };
        // A substituted argument object gets the same checks as the original.
        if executed != *arguments {
            if let Err(reason) = check_arguments(&call.logical, &executed) {
                return Err(CallFailure::Refused(reason));
            }
            if let Err(reason) = check_recipients(
                state.skill,
                &call.logical,
                &executed,
                self.directory,
                self.allowlist,
            ) {
                return Err(CallFailure::Refused(reason));
            }
        }
        Ok(executed)
    }

    /// One connector attempt for an authorized call: no blind retry, ever
    /// (`on_failure: stop`).
    ///
    /// CAL-DEFAULT-ID (r1): a write whose preconditions the live calendar no
    /// longer holds comes back asking for the owner. That is not a silent
    /// retry: the connector wrote nothing, so the owner decides with the
    /// normal card and the write goes out once, without Auxesis's stale proof.
    async fn send_call(
        &self,
        state: &RunState<'_, '_>,
        call: &ExecCall,
        executed: &Value,
    ) -> Result<ActionResult, CallFailure> {
        let mut arguments = executed.clone();
        let mut escalated = false;
        loop {
            match self
                .connector
                .call(state.context, &call.logical, &arguments)
                .await
            {
                Ok(output) => {
                    self.log_action(state.skill, state.run, &call.tool, "ok", None);
                    let content = if call.logical == "mail.send" {
                        self.log_mail_call(state, &arguments, "sent", Some(&output), None);
                        strip_mail_call(&output)
                    } else {
                        output
                    };
                    return Ok(ActionResult {
                        tool: call.tool.clone(),
                        logical: call.logical.clone(),
                        content: retokenize_value(&content, state.tokens),
                    });
                }
                Err(err) if err.needs_approval && !escalated => {
                    // The facts the copy held are stale: the owner decides.
                    self.log_action(
                        state.skill,
                        state.run,
                        &call.tool,
                        "facts_changed",
                        Some(&err.message),
                    );
                    escalated = true;
                    match self
                        .ask_after_changed_facts(state, call, &arguments, &err)
                        .await
                    {
                        Ok(next) => arguments = next,
                        Err(failure) => return Err(failure),
                    }
                }
                Err(err) => {
                    self.log_action(
                        state.skill,
                        state.run,
                        &call.tool,
                        "error",
                        Some(&err.message),
                    );
                    if call.logical == "mail.send" {
                        // A connector that refused before the socket (the B20 gate,
                        // a leftover token) names its own outcome; everything else
                        // is the typed error kind.
                        let outcome = err
                            .ledger
                            .get("outcome")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                            .or_else(|| {
                                err.ledger
                                    .get("kind")
                                    .and_then(Value::as_str)
                                    .map(|kind| format!("error:{kind}"))
                            })
                            .unwrap_or_else(|| "error:connector".to_string());
                        self.log_mail_call(state, &arguments, &outcome, None, Some(&err.ledger));
                    }
                    return Err(CallFailure::Failed(err.message));
                }
            }
        }
    }

    /// The owner's answer to a write whose preconditions changed.
    ///
    /// The card is the normal one, without Auxesis's proof: the approver then
    /// treats the call as a consequential action and asks the owner. On an
    /// approval the write goes out once more, without the stale facts, and it
    /// is authorized again like any other call.
    async fn ask_after_changed_facts(
        &self,
        state: &RunState<'_, '_>,
        call: &ExecCall,
        executed: &Value,
        err: &ConnectorError,
    ) -> Result<Value, CallFailure> {
        let skill = state.skill;
        let run = state.run;
        if skill.approval == Approval::None {
            // No card can be shown: the write is refused, never done.
            return Err(CallFailure::Failed(err.message.clone()));
        }
        let mut arguments = executed.clone();
        if let Some(map) = arguments.as_object_mut() {
            // Auxesis's proof is stale: the card must not carry it.
            map.remove("event_default_calendar");
        }
        let retry = ExecCall {
            tool: call.tool.clone(),
            logical: call.logical.clone(),
            token_arguments: call.token_arguments.clone(),
            real_arguments: arguments.clone(),
        };
        let card = self.card(skill, skill.approval, std::slice::from_ref(&retry));
        let decision = self.ask(&card).await;
        let outcome = match &decision {
            RunDecision::Approved { .. } => "approved",
            RunDecision::Refused => "refused",
            RunDecision::Timeout => "timeout",
        };
        self.log_approval(
            skill,
            run,
            skill.approval,
            std::slice::from_ref(&call.tool),
            outcome,
        );
        match decision {
            RunDecision::Approved { edits } => {
                let approved = edits.into_iter().next().flatten().unwrap_or(arguments);
                // The owner's edit is not trusted to be well formed: it is
                // authorized again, exactly like the first attempt.
                self.authorize_call(state, call, &approved).await
            }
            RunDecision::Refused => Err(CallFailure::Refused(
                "the owner refused the update: the event's calendar or its guests changed"
                    .to_string(),
            )),
            RunDecision::Timeout => Err(CallFailure::Failed(
                "the approval timed out: the event's calendar or its guests changed".to_string(),
            )),
        }
    }

    /// One `mail.call` Ledger row per SMTP send attempt, on success and on
    /// failure (`docs/mail.md` §5). Account slug, outcome, recipient **count**,
    /// message size, whether an `.ics` rode along, the reply class and the
    /// skill identity only: never an address, subject, body or attendee.
    fn log_mail_call(
        &self,
        state: &RunState<'_, '_>,
        arguments: &Value,
        outcome: &str,
        output: Option<&Value>,
        error_ledger: Option<&Value>,
    ) {
        let metadata = output.and_then(|value| value.get("mail_call"));
        // The connector resolves the account to a validated, configured slug
        // (or `unknown`); a refusal never reaches it, so fall back to the
        // format check. Never the raw argument.
        let account = metadata
            .and_then(|value| value.get("account"))
            .and_then(Value::as_str)
            .or_else(|| {
                error_ledger
                    .and_then(|value| value.get("account"))
                    .and_then(Value::as_str)
            })
            .map(str::to_string)
            .unwrap_or_else(|| {
                safe_account(
                    arguments.get("account").and_then(Value::as_str),
                    &self.connector.account_ids(),
                )
            });
        let recipients = recipient_values("mail.send", arguments)
            .map(|values| values.len())
            .unwrap_or(0);
        let ics = arguments.get("ics").is_some();
        let bytes = metadata
            .and_then(|value| value.get("bytes"))
            .and_then(Value::as_u64)
            .or_else(|| {
                error_ledger
                    .and_then(|value| value.get("bytes"))
                    .and_then(Value::as_u64)
            })
            .unwrap_or(0);
        let reply_class = metadata
            .and_then(|value| value.get("reply_class"))
            .and_then(Value::as_str)
            .or_else(|| {
                error_ledger
                    .and_then(|value| value.get("reply_class"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("none");
        let payload = json!({
            "agent": state.run.agent,
            "skill_name": state.skill.name,
            "skill_version": state.skill.version.to_string(),
            "skill_hash": state.skill.hash,
            "run_id": state.run.run_id,
            "account": account,
            "outcome": outcome,
            "recipients": recipients,
            "bytes": bytes,
            "ics": ics,
            "reply_class": reply_class,
        });
        let _ = self.sink.log_event("mail.call", &payload);
    }

    /// A `mail.send` refused **before** the SMTP socket (policy or broker): one
    /// `mail.call` row with outcome `refused` or `error:broker`.
    fn log_mail_refusal(&self, state: &RunState<'_, '_>, call: &ExecCall, failure: &CallFailure) {
        if call.logical != "mail.send" {
            return;
        }
        let outcome = match failure {
            CallFailure::Refused(_) => "refused",
            CallFailure::Failed(_) => "error:broker",
        };
        self.log_mail_call(state, &call.real_arguments, outcome, None, None);
    }

    /// The STOP / cancel check, consulted after approval and before each call.
    fn check_stop(&self) -> Result<(), CallFailure> {
        if self.stop.is_stopped() {
            Err(CallFailure::Refused(
                "the run was stopped before this call".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Read after a call has gone out. A STOP or cancel that landed during the
    /// call ends the run as `refused`, with the sent call on the Ledger and the
    /// rest unsent. A run stopped during its last call is recorded `refused`
    /// too: it was cancelled, not completed.
    fn check_stop_after_send(&self) -> Result<(), CallFailure> {
        if self.stop.is_stopped() {
            Err(CallFailure::Refused(
                "the run was stopped during a call".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn finish_failure(
        &self,
        skill: &LoadedSkill,
        run: &RunContext<'_>,
        failure: CallFailure,
    ) -> RunOutcome {
        match failure {
            CallFailure::Refused(reason) => self.finish_refused(skill, run, &reason),
            CallFailure::Failed(error) => self.finish_failed(skill, run, &error),
        }
    }

    fn card(&self, skill: &LoadedSkill, level: Approval, calls: &[ExecCall]) -> ApprovalCard {
        ApprovalCard {
            skill_name: skill.name.clone(),
            skill_version: skill.version,
            skill_hash: skill.hash.clone(),
            level,
            reason: format!(
                "skill `{}` v{} requests {} action(s) at approval level `{}`",
                skill.name,
                skill.version,
                calls.len(),
                level.as_str()
            ),
            countdown_secs: self.approval_timeout.as_secs(),
            calls: calls
                .iter()
                .map(|call| CardCall {
                    tool: call.tool.clone(),
                    logical: call.logical.clone(),
                    real_arguments: call.real_arguments.clone(),
                    token_arguments: call.token_arguments.clone(),
                })
                .collect(),
            recipient_source: self.directory.mailbox_sender().map(mailbox::card_source),
        }
    }

    /// Ask the owner, racing the answer against the clock. Silence is no.
    async fn ask(&self, card: &ApprovalCard) -> RunDecision {
        tokio::select! {
            biased;
            decision = self.approver.decide(card) => decision,
            _ = self.clock.sleep(self.approval_timeout) => RunDecision::Timeout,
        }
    }

    fn finish_done(
        &self,
        skill: &LoadedSkill,
        run: &RunContext<'_>,
        actions: Vec<ActionResult>,
    ) -> RunOutcome {
        self.log_run(skill, run, "done");
        RunOutcome::Done { actions }
    }

    fn finish_refused(
        &self,
        skill: &LoadedSkill,
        run: &RunContext<'_>,
        reason: &str,
    ) -> RunOutcome {
        self.finish_refused_with(skill, run, reason, false)
    }

    /// A refusal that quotes mailbox `From` names: the engine taints it.
    fn finish_refused_tainted(
        &self,
        skill: &LoadedSkill,
        run: &RunContext<'_>,
        reason: &str,
    ) -> RunOutcome {
        self.finish_refused_with(skill, run, reason, true)
    }

    fn finish_refused_with(
        &self,
        skill: &LoadedSkill,
        run: &RunContext<'_>,
        reason: &str,
        tainted: bool,
    ) -> RunOutcome {
        self.log_run(skill, run, "refused");
        RunOutcome::Refused {
            reason: reason.to_string(),
            tainted,
        }
    }

    fn finish_timeout(&self, skill: &LoadedSkill, run: &RunContext<'_>) -> RunOutcome {
        self.log_run(skill, run, "timeout");
        RunOutcome::Timeout
    }

    fn finish_failed(&self, skill: &LoadedSkill, run: &RunContext<'_>, error: &str) -> RunOutcome {
        self.log_run(skill, run, "failed");
        RunOutcome::Failed {
            error: error.to_string(),
        }
    }

    fn log_approval(
        &self,
        skill: &LoadedSkill,
        run: &RunContext<'_>,
        level: Approval,
        calls: &[String],
        decision: &str,
    ) {
        let payload = json!({
            "agent": run.agent,
            "skill_name": skill.name,
            "skill_version": skill.version.to_string(),
            "skill_hash": skill.hash,
            "run_id": run.run_id,
            "calls": calls,
            "level": level.as_str(),
            "decision": decision,
        });
        let _ = self.sink.log_event("skill.approval", &payload);
    }

    fn log_action(
        &self,
        skill: &LoadedSkill,
        run: &RunContext<'_>,
        tool: &str,
        outcome: &str,
        error: Option<&str>,
    ) {
        let payload = json!({
            "agent": run.agent,
            "skill_name": skill.name,
            "skill_version": skill.version.to_string(),
            "skill_hash": skill.hash,
            "run_id": run.run_id,
            "tool": tool,
            "outcome": outcome,
            "error": error,
        });
        let _ = self.sink.log_event("skill.action", &payload);
    }

    fn log_run(&self, skill: &LoadedSkill, run: &RunContext<'_>, outcome: &str) {
        let payload = json!({
            "agent": run.agent,
            "skill_name": skill.name,
            "skill_version": skill.version.to_string(),
            "skill_hash": skill.hash,
            "run_id": run.run_id,
            "outcome": outcome,
        });
        let _ = self.sink.log_event("skill.run", &payload);
    }
}

/// Names are matched with ASCII case folding only. This intentionally rejects
/// Unicode lookalikes while allowing casing and surrounding whitespace.
fn contains_ascii_case_insensitive_name(input: &str, name: &str) -> bool {
    let input = normalize_contact_name(input);
    let name = normalize_contact_name(name);
    if name.is_empty() {
        return false;
    }
    input.match_indices(&name).any(|(start, matched)| {
        (start == 0
            || !input[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric))
            && (start + matched.len() == input.len()
                || !input[start + matched.len()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric))
    })
}

fn normalize_contact_name(value: &str) -> String {
    use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};
    value
        .nfkc()
        .filter(|ch| !is_combining_mark(*ch) && !is_format_character(*ch))
        .flat_map(|ch| match ch {
            'ß' | 'ẞ' => "ss".chars().collect::<Vec<_>>(),
            'ς' => vec!['σ'],
            other => other.to_lowercase().collect(),
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn is_format_character(ch: char) -> bool {
    matches!(ch as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 |
        0x08E2 | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 |
        0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD |
        0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A |
        0xE0001 | 0xE0020..=0xE007F)
}

fn maximal_contact_name_matches(input: &str, groups: &[Vec<String>]) -> Vec<Vec<String>> {
    let mut candidates = Vec::new();
    for (contact, names) in groups.iter().enumerate() {
        for name in names {
            let normalized = normalize_contact_name(name);
            if !normalized.is_empty() && contains_ascii_case_insensitive_name(input, &normalized) {
                candidates.push((contact, normalized));
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    let all = candidates.clone();
    candidates.retain(|(contact, candidate)| {
        !all.iter().any(|(other_contact, other)| {
            (contact != other_contact || candidate != other)
                && contains_ascii_case_insensitive_name(other, candidate)
                && other != candidate
        })
    });
    let mut result = vec![Vec::new(); groups.len()];
    for (contact, name) in candidates {
        result[contact].push(name);
    }
    result
        .into_iter()
        .filter(|matches| !matches.is_empty())
        .collect()
}

/// The session's token ↔ value view, as the executor needs it.
///
/// The session tokens are memory-only per session today (the gate's key is a
/// process-lifetime root), so the executor takes this interface rather than a
/// [`TokenMap`], whose constructors the kernel keeps private. A resolver answers
/// only for its own session: a token minted elsewhere resolves to `None`, and
/// the run is refused.
pub trait TokenResolver: Send + Sync {
    /// The value `token` stands for, or `None` when it is unknown here.
    fn resolve(&self, token: &str) -> Option<String>;

    /// Every `(token, value)` pair known here, for re-tokenising a result.
    fn pairs(&self) -> Vec<(String, String)>;
}

/// A vault map is a resolver for exactly one session.
impl TokenResolver for TokenMap {
    fn resolve(&self, token: &str) -> Option<String> {
        self.iter()
            .find(|(known, _)| known == token)
            .map(|(_, value)| value.clone())
    }

    fn pairs(&self) -> Vec<(String, String)> {
        self.iter().cloned().collect()
    }
}

/// Restore every token in a JSON value, refusing the whole run on any token
/// that does not resolve.
///
/// The unknown policy is the kernel's strictest: an unresolved token becomes
/// `[unknown reference]`, never the token in the clear, and the run is refused.
/// A value that still contains `⟦`/`⟧` after restore is refused too.
pub fn restore_value(value: &Value, tokens: &dyn TokenResolver) -> Result<Value, String> {
    match value {
        Value::String(text) => Ok(Value::String(restore_text(text, tokens)?)),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(restore_value(item, tokens)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            // Keys are restored too: a token smuggled into a key is refused the
            // same way one in a value is.
            let mut out = Map::with_capacity(map.len());
            for (key, item) in map {
                out.insert(restore_text(key, tokens)?, restore_value(item, tokens)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other.clone()),
    }
}

/// Restore one string, mirroring the kernel's parser: `⟦⟦` is a literal
/// opener, `⟦⟧` is kept, a missing closer makes every later `⟦` ordinary text,
/// and an unresolved token is counted and refused.
fn restore_text(text: &str, tokens: &dyn TokenResolver) -> Result<String, String> {
    let mut restored = String::with_capacity(text.len());
    let mut unknown = 0usize;
    let mut cursor = 0usize;
    let mut no_close = false;
    let mut links = LinkGuard::default();
    while cursor < text.len() {
        let ch = text[cursor..]
            .chars()
            .next()
            .expect("cursor is a char boundary");
        if ch == PLACEHOLDER_OPEN
            && text[cursor + PLACEHOLDER_OPEN.len_utf8()..].starts_with(PLACEHOLDER_OPEN)
        {
            // `⟦⟦` is the literal opener `anonymize` wrote doubled.
            links.append_to(&mut restored, "⟦");
            cursor += 2 * PLACEHOLDER_OPEN.len_utf8();
        } else if ch == PLACEHOLDER_OPEN {
            let inner_start = cursor + PLACEHOLDER_OPEN.len_utf8();
            let close = if no_close {
                None
            } else {
                text[inner_start..]
                    .find(PLACEHOLDER_CLOSE)
                    .map(|offset| inner_start + offset)
            };
            match close {
                Some(inner_end) => {
                    let token = &text[inner_start..inner_end];
                    if token.is_empty() {
                        // `⟦⟧` is not one of our placeholders: keep it.
                        links.append_to(
                            &mut restored,
                            &text[cursor..inner_end + PLACEHOLDER_CLOSE.len_utf8()],
                        );
                    } else if let Some(value) = tokens.resolve(token) {
                        if !links
                            .append_token_value(
                                &mut restored,
                                token,
                                &value,
                                &text[inner_end + PLACEHOLDER_CLOSE.len_utf8()..],
                                true,
                            )
                            .unwrap_or(true)
                        {
                            links.append_to(&mut restored, &value);
                        }
                    } else {
                        unknown += 1;
                        links.append_to(&mut restored, kernel_privacy::UNKNOWN_REFERENCE);
                    }
                    cursor = inner_end + PLACEHOLDER_CLOSE.len_utf8();
                }
                None => {
                    no_close = true;
                    links.append_to(&mut restored, "⟦");
                    cursor = inner_start;
                }
            }
        } else {
            links.append_to(&mut restored, &text[cursor..cursor + ch.len_utf8()]);
            cursor += ch.len_utf8();
        }
    }
    links.finish(&mut restored);
    let kept_in_link = links.take_redactions();
    if kept_in_link > 0 {
        tracing::info!(kept_in_link, "link values kept hidden");
    }
    if unknown > 0 {
        // The model reads this: say the tool works and what to send instead,
        // so it retries the same tool rather than hunting the data elsewhere.
        return Err(format!(
            "the call did not run and wrote nothing: {unknown} name token(s) in the arguments \
             did not resolve in this conversation. The tool itself works: retry with the token \
             copied exactly as the owner wrote it, or with a plain word"
        ));
    }
    if restored.contains(PLACEHOLDER_OPEN) || restored.contains(PLACEHOLDER_CLOSE) {
        return Err(
            "the call did not run: a value still contains a ⟦…⟧ delimiter; \
                    retry with plain text. The tool itself works"
                .to_string(),
        );
    }
    Ok(restored)
}

/// Remove the connector's private `mail_call` Ledger metadata from a result
/// before the model sees it. The object is consumed by [`Executor::log_mail_call`].
fn strip_mail_call(output: &Value) -> Value {
    let mut value = output.clone();
    if let Some(map) = value.as_object_mut() {
        map.remove("mail_call");
    }
    value
}

/// A `mail.call` account value that is safe to log: a canonical slug that the
/// connector reports as a **configured** account, or the literal `unknown`.
/// Never the raw argument, so an unconfigured slug or an address can never
/// appear.
fn safe_account(account: Option<&str>, configured: &[String]) -> String {
    match account {
        Some(account) if is_account_slug(account) && configured.iter().any(|id| id == account) => {
            account.to_string()
        }
        _ => "unknown".to_string(),
    }
}

/// The account-slug shape (`docs/mail.md` §2): `[a-z0-9][a-z0-9_-]{0,31}`.
fn is_account_slug(id: &str) -> bool {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && id.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Replace every real value in a connector result with its token, so the result
/// can re-enter the model conversation.
pub fn retokenize_value(value: &Value, tokens: &dyn TokenResolver) -> Value {
    match value {
        Value::String(text) => Value::String(retokenize_text(text, tokens)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| retokenize_value(item, tokens))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), retokenize_value(item, tokens)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Replace every real value in `text` with `⟦token⟧`. Longest values first, so
/// a value that contains another is still replaced whole.
fn retokenize_text(text: &str, tokens: &dyn TokenResolver) -> String {
    let mut pairs: Vec<(String, String)> = tokens.pairs();
    pairs.sort_by_key(|(_, value)| std::cmp::Reverse(value.len()));
    let mut out = text.to_string();
    for (token, value) in pairs {
        if value.is_empty() {
            continue;
        }
        out = out.replace(
            &value,
            &format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"),
        );
    }
    out
}

/// The recipient fields of one logical tool, as `(field, value)` pairs, after
/// the tool's own list syntax is applied: a Gmail `to`/`cc`/`bcc` is split on
/// commas, the way the Gmail parser splits it, and every calendar attendee is
/// one value.
///
/// Fails closed: a recipient that is not a string (or an attendee object
/// without a string `email`) is an error, not a value to skip.
pub fn recipient_values(logical: &str, arguments: &Value) -> Result<Vec<(String, String)>, String> {
    let mut fields = Vec::new();
    match logical {
        "google.gmail.send" => {
            for field in ["to", "cc", "bcc"] {
                push_recipient_list(&mut fields, field, arguments.get(field))?;
            }
        }
        "google.gmail.create_draft" => {
            push_recipient_list(&mut fields, "to", arguments.get("to"))?;
        }
        // MA4: the SMTP send carries arrays of addresses.
        "mail.send" => {
            for field in ["to", "cc"] {
                let Some(values) = arguments.get(field) else {
                    continue;
                };
                let values = values
                    .as_array()
                    .ok_or_else(|| format!("recipient `{field}` must be a list"))?;
                for (index, value) in values.iter().enumerate() {
                    let address = value.as_str().ok_or_else(|| {
                        format!("recipient `{field}[{index}]` must be an address")
                    })?;
                    let address = address.trim();
                    if address.is_empty() {
                        return Err(format!("recipient `{field}[{index}]` is empty"));
                    }
                    fields.push((format!("{field}[{index}]"), address.to_string()));
                }
            }
        }
        "google.calendar.create_event" => {
            if let Some(attendees) = arguments.get("attendees") {
                let attendees = attendees
                    .as_array()
                    .ok_or_else(|| "`attendees` must be a list".to_string())?;
                for (index, attendee) in attendees.iter().enumerate() {
                    let address = match attendee {
                        Value::String(address) => Some(address.as_str()),
                        Value::Object(_) => attendee.get("email").and_then(Value::as_str),
                        _ => None,
                    };
                    let Some(address) = address else {
                        return Err(format!("recipient `attendees[{index}]` must be an address"));
                    };
                    fields.push((format!("attendees[{index}]"), address.to_string()));
                }
            }
        }
        _ => {}
    }
    Ok(fields)
}

/// One Gmail recipient field: a string of comma-separated addresses.
fn push_recipient_list(
    fields: &mut Vec<(String, String)>,
    name: &str,
    value: Option<&Value>,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let text = value
        .as_str()
        .ok_or_else(|| format!("recipient `{name}` must be a string"))?;
    for part in text.split(',') {
        let address = part.trim();
        if address.is_empty() {
            return Err(format!("recipient `{name}` has an empty entry"));
        }
        fields.push((name.to_string(), address.to_string()));
    }
    Ok(())
}

/// Resolve a calendar create's or update's times in its zone (M4-2); other
/// calls as is. A create uses the known client's stored zone when one is given
/// (CLIENT-TZ-FIELD), and an owner's edit keeps the card's resolved zone.
fn resolve_times(
    logical: &str,
    arguments: &Value,
    client_zone: Option<&str>,
) -> Result<Value, String> {
    let zone = || event_time::owner_time_zone();
    match logical {
        event_time::EVENT_CREATE => {
            event_time::resolve_event_times_for_client(arguments, zone().as_deref(), client_zone)
        }
        event_time::EVENT_UPDATE => event_time::resolve_update_times(arguments, zone().as_deref()),
        _ => Ok(arguments.clone()),
    }
}

/// The addresses a call invites: a mail `to`, or a calendar `attendees`
/// address. The attendee is that one address, never a cc or a bcc.
fn invite_addresses(arguments: &Value) -> Vec<String> {
    let mut found = Vec::new();
    for field in ["to", "attendees"] {
        match arguments.get(field) {
            Some(Value::String(address)) => found.push(address.clone()),
            Some(Value::Array(items)) => {
                for item in items {
                    match item {
                        Value::String(address) => found.push(address.clone()),
                        Value::Object(fields) => {
                            if let Some(address) = fields.get("email").and_then(Value::as_str) {
                                found.push(address.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    found
        .into_iter()
        .map(|address| address.trim().to_string())
        .filter(|address| address.contains('@'))
        .collect()
}

/// CAL-UPDATE-1: the connector finds an update's event before the card and
/// Auxesis sets `guests`, never the model: an update is free only when the
/// event is known to have none (`aux_engine::action`).
///
/// CAL-DEFAULT-ID: Auxesis also sets `event_default_calendar` and
/// `event_calendar_id`, and only when it found the event by id on the owner's
/// default calendar. The model cannot name them: the fields are dropped
/// before the facts are set.
pub fn with_found_event(
    connector: &dyn SkillConnector,
    logical: &str,
    mut real: Value,
) -> Result<Value, String> {
    if logical != event_time::EVENT_UPDATE {
        return Ok(real);
    }
    let map = real
        .as_object_mut()
        .ok_or("the event arguments are not an object")?;
    map.remove("guests");
    map.remove("event_calendar");
    map.remove("event_calendar_id");
    map.remove("event_default_calendar");
    if let Some(found) = connector.find_event(&Value::Object(map.clone()))? {
        map.insert("event_id".into(), Value::String(found.id));
        map.insert("event_calendar".into(), Value::String(found.calendar));
        if let Some(guests) = found.guests {
            map.insert("guests".into(), Value::from(guests));
        }
        if found.in_default_calendar {
            map.insert("event_default_calendar".into(), Value::Bool(true));
            // The id the write must find again (CAL-DEFAULT-ID r1).
            if let Some(calendar_id) = found.calendar_id {
                map.insert("event_calendar_id".into(), Value::String(calendar_id));
            }
        }
    }
    match map.get("event_id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => Ok(real),
        _ => Err("name the event to change: its id, or its title and time".to_string()),
    }
}

/// Every argument check a call needs once its values are real: the tool's
/// pinned schema, C0 controls, and no `⟦`/`⟧` left in any string or key. The
/// same rules the model's fill passes ([`crate::skills::fill::check_arguments`]).
fn check_arguments(logical: &str, arguments: &Value) -> Result<(), String> {
    crate::skills::fill::check_arguments(logical, arguments)
}

/// Enforce the skill's effective recipient policy for every recipient value.
fn check_recipients(
    skill: &LoadedSkill,
    logical: &str,
    arguments: &Value,
    directory: &dyn RecipientDirectory,
    allowlist: &[String],
) -> Result<(), String> {
    use crate::skills::RecipientPolicy;
    for (field, value) in recipient_values(logical, arguments)? {
        let allowed = match skill.recipients_policy {
            RecipientPolicy::Allowlist => allowlist
                .iter()
                .any(|entry| entry.trim().eq_ignore_ascii_case(value.trim())),
            RecipientPolicy::KnownContacts => directory.is_known(&value),
            RecipientPolicy::AnyWithApproval => true,
        };
        if !allowed {
            // The field name and policy are safe; the value is not logged.
            return Err(format!(
                "recipient `{field}` is not allowed by the `{}` policy",
                skill.recipients_policy.as_str()
            ));
        }
    }
    Ok(())
}

/// The broker risk for a tool: reads are low, the two skill-only writes high,
/// everything else medium.
fn risk_for(read_only: bool, skill_only: bool) -> Risk {
    if read_only {
        Risk::Low
    } else if skill_only {
        Risk::High
    } else {
        Risk::Medium
    }
}

fn tool_names(calls: &[ExecCall]) -> Vec<String> {
    calls.iter().map(|call| call.tool.clone()).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn contact_name_matching_trims_and_folds_ascii_only() {
        assert!(super::contains_ascii_case_insensitive_name(
            "Invite ALICE Example today",
            "  Alice Example  "
        ));
        assert!(!super::contains_ascii_case_insensitive_name(
            "Invite Аlice Example today",
            "Alice Example"
        ));
        assert!(!super::contains_ascii_case_insensitive_name(
            "Invite Malice Example today",
            "Alice Example"
        ));
        let names = vec![
            vec!["Alice Example".into()],
            vec!["Alice Example Jr".into()],
        ];
        assert_eq!(
            super::maximal_contact_name_matches("Alice Example Jr", &names),
            vec![vec!["alice example jr"]]
        );
        assert_eq!(
            super::maximal_contact_name_matches(
                "Alice Example and Bob Jones",
                &[vec!["Alice Example".into()], vec!["Bob Jones".into()]]
            )
            .len(),
            2
        );
        assert!(super::contains_ascii_case_insensitive_name(
            "Ali\u{200b}ce E\u{0301}xample",
            "Alice Éxample"
        ));
        assert!(!super::contains_ascii_case_insensitive_name(
            "Аlice Example",
            "Alice Example"
        ));
    }
    use super::*;
    use kernel_privacy::Anonymizer;
    use std::sync::{Arc, Mutex};

    use kernel_broker::{
        Action, ApprovalRequest, Approver, ApproverError, MemoryAuditSink, Rule, SkillOnlyLookup,
    };
    use kernel_privacy::{ContactIndex, EntityKind, Span};

    use crate::skills::agent::{AgentMode, AgentSource, Brain, LoadedAgent};
    use crate::skills::fill::{validate_fill, RunContext};
    use crate::skills::skill::parse_skill;
    use crate::skills::RecipientPolicy;

    fn agent() -> LoadedAgent {
        LoadedAgent {
            name: "assistant".to_string(),
            brain: Brain::Cloud,
            default_mode: AgentMode::Private,
            budget: None,
            channels: Vec::new(),
            tools: vec![
                "google.calendar.create_event".to_string(),
                "google.gmail.send".to_string(),
            ],
            recipients_policy: RecipientPolicy::KnownContacts,
            recipients_allowlist: Vec::new(),
            body: String::new(),
            source: AgentSource::AgentMd,
            dir: std::path::PathBuf::from("/tmp/assistant"),
        }
    }

    /// The executor's own hero-style skill. The contact derivation is covered
    /// by the fixture and `recipient_from_contacts.rs`; here the model still
    /// fills `email` directly, so the existing executor rules are unchanged.
    fn skill() -> LoadedSkill {
        let text = b"---\nname: send-invite\nversion: 1\ntools: [google.calendar.create_event, google.gmail.send]\ninputs:\n  person: { tier: H }\n  email: { type: email }\n  when: { type: datetime }\n  duration: { type: duration, default: 30m }\napproval: each_run\n---\nBody.\n";
        parse_skill(text, "send-invite.md", "send-invite", &agent()).unwrap()
    }

    /// A masked session: the vault map plus the bare person/email tokens.
    fn session() -> (TokenMap, String, String) {
        let text = "Camille Exemple camille@exemple.fr";
        let spans = vec![
            span(text, "Camille Exemple", EntityKind::Person),
            span(text, "camille@exemple.fr", EntityKind::Email),
        ];
        let (_, map) = Anonymizer::new([7u8; 32]).anonymize(text, &spans);
        let person = map
            .iter()
            .find(|(token, _)| token.starts_with("PERSON_"))
            .map(|(token, _)| token.clone())
            .expect("a PERSON token");
        let email = map
            .iter()
            .find(|(token, _)| token.starts_with("EMAIL_"))
            .map(|(token, _)| token.clone())
            .expect("an EMAIL token");
        (map, person, email)
    }

    fn span(text: &str, needle: &str, kind: EntityKind) -> Span {
        let start = text.find(needle).unwrap();
        Span {
            kind,
            start,
            end: start + needle.len(),
            score: 1.0,
            recognizer: "test",
            person_id: None,
        }
    }

    fn delimited(token: &str) -> String {
        format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}")
    }

    fn fill_via_validator(person: &str, email: &str) -> ValidatedFill {
        let value = json!({
            "slots": {
                "person": person,
                "email": email,
                "when": "2026-10-06T10:00:00+02:00"
            },
            "calls": [
                {
                    "tool": "google_calendar_create_event",
                    "arguments": {
                        "summary": format!("Meeting with {person}"),
                        "start": "2026-10-06T10:00:00+02:00",
                        "attendees": [{ "email": email }]
                    }
                },
                {
                    "tool": "google_gmail_send",
                    "arguments": { "to": email, "body": format!("See you, {person}.") }
                }
            ]
        });
        let context = RunContext {
            agent: "assistant",
            run_id: "run-1",
            schemas: None,
            owner_input: None,
        };
        validate_fill(&skill(), &value, &context, None).unwrap()
    }

    fn run_context() -> RunContext<'static> {
        RunContext {
            agent: "assistant",
            run_id: "run-1",
            schemas: None,
            owner_input: None,
        }
    }

    /// The MA4 agent: the EventKit create and the SMTP send.
    fn mail_agent() -> LoadedAgent {
        let mut agent = agent();
        agent.tools = vec!["calendar.create_event".to_string(), "mail.send".to_string()];
        agent
    }

    /// The calendar agent: one event move (CAL-UPDATE-1).
    fn update_agent() -> LoadedAgent {
        let mut agent = agent();
        agent.tools = vec!["calendar.update_event".to_string()];
        agent
    }

    fn update_skill() -> LoadedSkill {
        let text = b"---\nname: move-event\nversion: 1\ntools: [calendar.update_event]\napproval: each_run\n---\nBody.\n";
        parse_skill(text, "move-event.md", "move-event", &update_agent()).unwrap()
    }

    /// A move of one event, by its id.
    fn update_fill() -> ValidatedFill {
        let value = json!({
            "slots": {},
            "calls": [{
                "tool": "apple_calendar_update_event",
                "arguments": { "event_id": "evt-1", "title": "Focus" }
            }]
        });
        validate_fill(&update_skill(), &value, &run_context(), None).unwrap()
    }

    fn mail_skill() -> LoadedSkill {
        let text = b"---\nname: send-invite\nversion: 1\ntools: [calendar.create_event, mail.send]\ninputs:\n  email: { type: email }\napproval: each_run\n---\nBody.\n";
        parse_skill(text, "send-invite.md", "send-invite", &mail_agent()).unwrap()
    }

    /// An invite fill with sentinel subject/body values that must never reach a
    /// `mail.call` row.
    fn mail_fill(email: &str) -> ValidatedFill {
        mail_fill_for(email, None)
    }

    /// As [`mail_fill`], with an optional raw `account` argument.
    fn mail_fill_for(email: &str, account: Option<&str>) -> ValidatedFill {
        let mut arguments = json!({
            "to": [email],
            "subject": "SUBJECT-SENTINEL",
            "body": "BODY-SENTINEL",
            "ics": "event"
        });
        if let Some(account) = account {
            arguments["account"] = json!(account);
        }
        let value = json!({
            "slots": { "email": email },
            "calls": [
                {
                    "tool": "apple_calendar_create_event",
                    "arguments": {
                        "title": "Meeting",
                        "start": "2026-10-06T10:00:00+02:00",
                        "end": "2026-10-06T10:30:00+02:00"
                    }
                },
                {
                    "tool": "mail_send",
                    "arguments": arguments,
                }
            ]
        });
        validate_fill(&mail_skill(), &value, &run_context(), None).unwrap()
    }

    /// A connector that returns the mail send's safe metadata on success and the
    /// typed `rate_limited` ledger on failure. `account`, when set, is the
    /// resolved account the connector would put in its metadata. `mailboxes`
    /// are the configured accounts; the default is the one mailbox `personal`.
    #[derive(Default)]
    struct MailRowConnector {
        calls: Mutex<Vec<String>>,
        sent: Mutex<Vec<Value>>,
        fail: bool,
        account: Option<&'static str>,
        mailboxes: Vec<String>,
    }

    impl MailRowConnector {
        fn failing() -> Self {
            Self {
                fail: true,
                ..Default::default()
            }
        }

        fn resolving(account: &'static str) -> Self {
            Self {
                account: Some(account),
                ..Default::default()
            }
        }

        /// A connector with several configured mailboxes.
        fn with_mailboxes(mailboxes: &[&str]) -> Self {
            Self {
                mailboxes: mailboxes.iter().map(|name| name.to_string()).collect(),
                ..Default::default()
            }
        }

        /// The arguments every call was given, in order.
        fn sent(&self) -> Vec<Value> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SkillConnector for MailRowConnector {
        async fn call(
            &self,
            _skill: &SkillContext,
            logical: &str,
            arguments: &Value,
        ) -> Result<Value, ConnectorError> {
            self.calls.lock().unwrap().push(logical.to_string());
            self.sent.lock().unwrap().push(arguments.clone());
            if logical == "mail.send" {
                if self.fail {
                    let mut ledger = json!({"kind": "rate_limited", "reply_class": "4xx"});
                    if let Some(account) = self.account {
                        ledger["account"] = json!(account);
                    }
                    return Err(
                        ConnectorError::new("The provider is throttling us").with_ledger(ledger)
                    );
                }
                let mut mail_call = json!({
                    "accepted": 1,
                    "bytes": 4096,
                    "reply_class": "2xx",
                    "ics": true,
                });
                if let Some(account) = self.account {
                    mail_call["account"] = json!(account);
                }
                return Ok(json!({
                    "content": json!({"sent": true, "accepted": 1}).to_string(),
                    "mail_call": mail_call,
                }));
            }
            Ok(json!({ "ok": true }))
        }

        fn account_ids(&self) -> Vec<String> {
            if self.mailboxes.is_empty() {
                vec!["personal".to_string()]
            } else {
                self.mailboxes.clone()
            }
        }
    }

    struct SkillOnly;
    impl SkillOnlyLookup for SkillOnly {
        fn is_skill_only(&self, tool: &str) -> bool {
            matches!(
                tool,
                "google_gmail_send"
                    | "google_calendar_create_event"
                    | "mail_send"
                    | "apple_calendar_create_event"
            )
        }
    }

    /// The broker-level approver for a skill run: the owner already approved the
    /// whole run at the executor level, so the per-call ask is pre-approved.
    struct PreApproved;
    #[async_trait]
    impl Approver for PreApproved {
        async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
            Ok(true)
        }
    }

    fn broker(sink: &Arc<MemoryAuditSink>) -> Broker {
        broker_with_rules(sink, Vec::new())
    }

    fn broker_with_rules(sink: &Arc<MemoryAuditSink>, rules: Vec<Rule>) -> Broker {
        let concrete = Arc::clone(sink);
        let sink: Arc<dyn AuditSink> = concrete;
        Broker::new(sink, rules, Arc::new(PreApproved), Arc::new(SkillOnly))
    }

    static NEVER_STOPPED: NeverStopped = NeverStopped;

    #[derive(Default)]
    struct RecordingApprover {
        cards: Mutex<Vec<ApprovalCard>>,
        decision: Mutex<Option<RunDecision>>,
    }

    impl RecordingApprover {
        fn approving() -> Self {
            RecordingApprover {
                cards: Mutex::new(Vec::new()),
                decision: Mutex::new(Some(RunDecision::approved())),
            }
        }

        fn answering(decision: RunDecision) -> Self {
            RecordingApprover {
                cards: Mutex::new(Vec::new()),
                decision: Mutex::new(Some(decision)),
            }
        }

        fn card_count(&self) -> usize {
            self.cards.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl SkillApprover for RecordingApprover {
        async fn decide(&self, card: &ApprovalCard) -> RunDecision {
            self.cards.lock().unwrap().push(card.clone());
            self.decision
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(RunDecision::Refused)
        }
    }

    struct PendingApprover;
    #[async_trait]
    impl SkillApprover for PendingApprover {
        async fn decide(&self, _card: &ApprovalCard) -> RunDecision {
            std::future::pending().await
        }
    }

    #[derive(Default)]
    struct ImmediateClock;
    #[async_trait]
    impl Clock for ImmediateClock {
        async fn sleep(&self, _duration: Duration) {}
    }

    #[derive(Default)]
    struct PendingClock;
    #[async_trait]
    impl Clock for PendingClock {
        async fn sleep(&self, _duration: Duration) {
            std::future::pending().await
        }
    }

    #[derive(Default)]
    struct RecordingConnector {
        calls: Mutex<Vec<(String, Value)>>,
        fail_at: Option<usize>,
    }

    impl RecordingConnector {
        fn failing_at(index: usize) -> Self {
            RecordingConnector {
                calls: Mutex::new(Vec::new()),
                fail_at: Some(index),
            }
        }

        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SkillConnector for RecordingConnector {
        async fn call(
            &self,
            _skill: &SkillContext,
            logical: &str,
            arguments: &Value,
        ) -> Result<Value, ConnectorError> {
            let mut calls = self.calls.lock().unwrap();
            let index = calls.len();
            calls.push((logical.to_string(), arguments.clone()));
            if self.fail_at == Some(index) {
                return Err(ConnectorError::new("connector refused"));
            }
            Ok(json!({ "ok": true, "seen": arguments }))
        }
    }

    struct Known(Vec<&'static str>);
    impl RecipientDirectory for Known {
        fn is_known(&self, value: &str) -> bool {
            self.0.iter().any(|known| known.eq_ignore_ascii_case(value))
        }
    }

    /// A connector that finds the event Auxesis's way, then refuses the first
    /// write because the live calendar no longer matches (CAL-DEFAULT-ID r1).
    struct FactsChangedConnector {
        calls: Mutex<Vec<Value>>,
    }

    #[async_trait]
    impl SkillConnector for FactsChangedConnector {
        async fn call(
            &self,
            _skill: &SkillContext,
            _logical: &str,
            arguments: &Value,
        ) -> Result<Value, ConnectorError> {
            let mut calls = self.calls.lock().unwrap();
            calls.push(arguments.clone());
            if calls.len() == 1 {
                return Err(
                    ConnectorError::new("the event's calendar or its guests changed")
                        .with_approval(),
                );
            }
            Ok(json!({ "ok": true }))
        }

        fn find_event(&self, _arguments: &Value) -> FoundEvent {
            Ok(Some(FoundEventFacts {
                id: "evt-1".to_string(),
                guests: Some(0),
                calendar: "Home".to_string(),
                calendar_id: Some("cal-1".to_string()),
                in_default_calendar: true,
            }))
        }
    }

    fn executor<'a>(
        broker: &'a Broker,
        sink: &'a Arc<MemoryAuditSink>,
        approver: &'a dyn SkillApprover,
        connector: &'a dyn SkillConnector,
        directory: &'a dyn RecipientDirectory,
        clock: &'a dyn Clock,
        allowlist: &'a [String],
    ) -> Executor<'a> {
        Executor {
            broker,
            sink: sink.as_ref(),
            approver,
            connector,
            directory,
            allowlist,
            clock,
            stop: &NEVER_STOPPED,
            approval_timeout: default_approval_timeout(),
        }
    }

    /// `each_run` produces exactly one approval listing every call.
    #[tokio::test]
    async fn each_run_produces_exactly_one_card_listing_every_call() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { ref actions } if actions.len() == 2));
        assert_eq!(approver.card_count(), 1, "one card for the whole run");
        let card = &approver.cards.lock().unwrap()[0];
        assert_eq!(card.level, Approval::EachRun);
        assert_eq!(card.calls.len(), 2);
        assert_eq!(card.calls[0].tool, "google_calendar_create_event");
        assert_eq!(card.calls[1].tool, "google_gmail_send");
        assert_eq!(sink.count("skill.approval"), 1);
        assert_eq!(sink.payloads("skill.approval")[0]["decision"], "approved");
        assert_eq!(sink.count("skill.action"), 2);
        assert_eq!(sink.count("skill.run"), 1);
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "done");
    }

    /// CAL-DEFAULT-ID (r1): a write whose facts the live calendar no longer
    /// holds is put to the owner: the normal card, without Auxesis's stale
    /// proof, and the write goes out once the owner says yes.
    #[tokio::test]
    async fn a_changed_calendar_asks_the_owner_and_writes_once_approved() {
        let (tokens, _person, _email) = session();
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = FactsChangedConnector {
            calls: Mutex::new(Vec::new()),
        };
        let directory = Known(vec![]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(
                &update_skill(),
                &update_fill(),
                &run_context(),
                &tokens,
                &Taint::Clean,
            )
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
        // The run's card, then the card the changed facts asked for.
        assert_eq!(approver.card_count(), 2);
        {
            let cards = approver.cards.lock().unwrap();
            assert_eq!(
                cards[0].calls[0]
                    .real_arguments
                    .get("event_default_calendar"),
                Some(&Value::Bool(true))
            );
            // The second card carries no proof: the approver treats it as a
            // consequential action, so the owner is the one who decides.
            assert!(cards[1].calls[0]
                .real_arguments
                .get("event_default_calendar")
                .is_none());
        }
        // The write went out once more, without the stale proof.
        let calls = connector.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[1].get("event_default_calendar").is_none());
    }

    /// MA4 `docs/mail.md` §5: a successful send writes exactly one `mail.call`
    /// row, and the row carries counts and sizes only — never the address,
    /// subject or body.
    #[tokio::test]
    async fn a_successful_send_writes_one_value_free_mail_call_row() {
        let (tokens, _person, email) = session();
        let fill = mail_fill(&delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = MailRowConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
        assert_eq!(sink.count("mail.call"), 1, "one row per send");
        let row = &sink.payloads("mail.call")[0];
        assert_eq!(row["outcome"], "sent");
        // The runtime resolved the account before the card, so the row names
        // the mailbox the send went out of.
        assert_eq!(row["account"], "personal");
        assert_eq!(row["recipients"], 1);
        assert_eq!(row["bytes"], 4096);
        assert_eq!(row["reply_class"], "2xx");
        assert_eq!(row["ics"], true);
        let text = row.to_string();
        assert!(!text.contains('@'), "no address in the row: {text}");
        assert!(
            !text.contains("SUBJECT-SENTINEL") && !text.contains("BODY-SENTINEL"),
            "no subject or body in the row: {text}"
        );
    }

    /// MA4: a refused send writes one `mail.call` row with `error:<kind>` and
    /// still calls the connector once (no retry).
    #[tokio::test]
    async fn a_throttled_send_writes_one_error_mail_call_row() {
        let (tokens, _person, email) = session();
        let fill = mail_fill(&delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = MailRowConnector::failing();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Failed { .. }), "{outcome:?}");
        assert_eq!(sink.count("mail.call"), 1, "one row per send attempt");
        let row = &sink.payloads("mail.call")[0];
        assert_eq!(row["outcome"], "error:rate_limited");
        assert_eq!(row["reply_class"], "4xx");
        assert_eq!(
            connector
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|logical| logical.as_str() == "mail.send")
                .count(),
            1,
            "the send is never retried"
        );
        let text = row.to_string();
        assert!(!text.contains('@'), "no address in the row: {text}");
        assert!(
            !text.contains("SUBJECT-SENTINEL") && !text.contains("BODY-SENTINEL"),
            "no subject or body in the row: {text}"
        );
    }

    /// MA4 fix 2, DOC-COLLECT-1: a raw `account` value that is not a
    /// configured slug is never copied into the row; the resolved mailbox is
    /// logged instead, without any address.
    #[tokio::test]
    async fn a_bad_account_is_replaced_by_the_resolved_mailbox() {
        let (tokens, _person, email) = session();
        let fill = mail_fill_for(&delimited(&email), Some("camille@exemple.test"));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        // The connector resolves no account field, so the executor's own
        // resolution must sanitize the raw argument.
        let connector = MailRowConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
        assert_eq!(sink.count("mail.call"), 1);
        let row = &sink.payloads("mail.call")[0];
        assert_eq!(row["account"], "personal", "the resolved mailbox is logged");
        assert!(
            !row.to_string().contains('@'),
            "the raw account leaked: {row}"
        );
    }

    /// MA4 fix 2: a validated, configured slug is logged as-is.
    #[tokio::test]
    async fn a_configured_account_slug_is_logged_as_is() {
        let (tokens, _person, email) = session();
        let fill = mail_fill_for(&delimited(&email), Some("personal"));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = MailRowConnector::resolving("personal");
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
        assert_eq!(sink.payloads("mail.call")[0]["account"], "personal");
    }

    /// DOC-COLLECT-1: a send with two mailboxes and no name is refused before
    /// any card: the first mailbox is never picked.
    #[tokio::test]
    async fn a_send_with_two_mailboxes_and_no_name_is_refused_before_the_card() {
        let (tokens, _person, email) = session();
        let fill = mail_fill(&delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = MailRowConnector::with_mailboxes(&["personal", "work"]);
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert_eq!(approver.card_count(), 0, "no card for a nameless send");
        assert_eq!(sink.count("mail.call"), 0, "nothing went out");
    }

    /// DOC-COLLECT-1: with one mailbox, the card names it and the action uses
    /// the very arguments the owner approved.
    #[tokio::test]
    async fn the_card_and_the_action_name_the_same_mailbox() {
        let (tokens, _person, email) = session();
        let fill = mail_fill(&delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = MailRowConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
        let card = approver.cards.lock().unwrap()[0].clone();
        let approved = card.calls[1].real_arguments.clone();
        assert_eq!(
            approved["account"], "personal",
            "the card names the mailbox"
        );
        assert_eq!(
            connector.sent()[1],
            approved,
            "the action uses the approved arguments"
        );
    }

    /// MA4 fix 2: the refused path also logs a safe account value.
    #[tokio::test]
    async fn a_refused_send_logs_the_resolved_mailbox_for_a_bad_account() {
        let (tokens, _person, email) = session();
        let fill = mail_fill_for(&delimited(&email), Some("camille@exemple.test"));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = MailRowConnector::default();
        // An empty directory refuses the recipient before the connector.
        let directory = Known(vec![]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert_eq!(sink.count("mail.call"), 1, "the refusal writes one row");
        let row = &sink.payloads("mail.call")[0];
        assert_eq!(row["outcome"], "refused");
        assert_eq!(row["account"], "personal", "the resolved mailbox is logged");
        assert!(
            !row.to_string().contains('@'),
            "the raw account leaked: {row}"
        );
    }

    /// MA4 fix 2: the refused path keeps a safe, format-valid slug.
    #[tokio::test]
    async fn a_refused_send_logs_a_safe_slug() {
        let (tokens, _person, email) = session();
        let fill = mail_fill_for(&delimited(&email), Some("personal"));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = MailRowConnector::default();
        let directory = Known(vec![]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert_eq!(sink.payloads("mail.call")[0]["account"], "personal");
    }

    /// MA4 round 3 P2, DOC-COLLECT-1: a slug-shaped account that is **not**
    /// configured must not be copied into the row; the refused path logs the
    /// mailbox the runtime resolved.
    #[tokio::test]
    async fn an_unconfigured_slug_is_replaced_on_the_refused_path() {
        let (tokens, _person, email) = session();
        let fill = mail_fill_for(&delimited(&email), Some("camille"));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        // This connector reports `personal` as its only configured account.
        let connector = MailRowConnector::default();
        let directory = Known(vec![]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&mail_skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert_eq!(
            sink.payloads("mail.call")[0]["account"],
            "personal",
            "an unconfigured slug must not reach the row"
        );
    }

    /// 600 s of silence is a refusal, with no real sleep.
    #[tokio::test]
    async fn approval_left_unanswered_refuses_without_touching_the_connector() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = PendingApprover;
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = ImmediateClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert_eq!(outcome, RunOutcome::Timeout);
        assert!(
            connector.calls().is_empty(),
            "nothing reaches the connector"
        );
        assert_eq!(sink.count("skill.approval"), 1);
        assert_eq!(sink.payloads("skill.approval")[0]["decision"], "timeout");
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "timeout");
        assert_eq!(sink.count("skill.action"), 0);
    }

    /// Rehydration + recipient policy; the connector sees real values,
    /// the model saw tokens.
    #[tokio::test]
    async fn rehydration_and_recipient_policy_send_real_values_to_the_connector() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        // What the model filled carries tokens only.
        assert!(fill.calls[0]
            .arguments
            .to_string()
            .contains(PLACEHOLDER_OPEN));
        assert!(!fill.calls[0].arguments.to_string().contains("Camille"));
        assert!(!fill.calls[1]
            .arguments
            .to_string()
            .contains("camille@exemple.fr"));

        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }));
        let calls = connector.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].1.to_string().contains("Camille Exemple"));
        assert_eq!(calls[1].1["to"], "camille@exemple.fr");
        assert_eq!(calls[1].1["body"], "See you, Camille Exemple.");
        // The card renders real values locally, and "what the model saw" tokens.
        let card = &approver.cards.lock().unwrap()[0];
        assert!(card.calls[0].real_arguments.to_string().contains("Camille"));
        assert!(card.calls[1]
            .token_arguments
            .to_string()
            .contains(PLACEHOLDER_OPEN));
        // The re-tokenised result the model gets carries no real value.
        if let RunOutcome::Done { actions } = &outcome {
            let joined = actions
                .iter()
                .map(|action| action.content.to_string())
                .collect::<String>();
            assert!(!joined.contains("Camille"));
            assert!(!joined.contains("camille@exemple.fr"));
        }
    }

    /// A forged/unknown token refuses the whole run, before any approval or
    /// connector call.
    #[tokio::test]
    async fn forged_token_refuses_the_whole_run() {
        let (tokens, person, email) = session();
        let mut fill = fill_via_validator(&delimited(&person), &delimited(&email));
        // Smuggle an invented token that is not in the session map.
        fill.calls[1].arguments["body"] = json!("cc ⟦EMAIL_DEADBEEF⟧");
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Failed { .. }), "{outcome:?}");
        assert_eq!(approver.card_count(), 0, "no card for a forged token");
        assert!(connector.calls().is_empty(), "nothing was sent");
        assert_eq!(sink.count("skill.action"), 0);
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "failed");
    }

    /// A recipient outside `known-contacts` stops the run before any connector
    /// call.
    #[tokio::test]
    async fn recipient_not_allowed_is_refused_before_any_connector_call() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::default();
        // The real recipient is deliberately not a known contact.
        let directory = Known(vec!["someone-else@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert!(connector.calls().is_empty());
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "refused");
        assert_eq!(sink.count("skill.action"), 0);
    }

    /// No retry: a second call failing stops the run and the first is recorded.
    #[tokio::test]
    async fn a_second_call_failing_does_not_retry_and_the_first_is_recorded() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::failing_at(1);
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Failed { .. }), "{outcome:?}");
        assert_eq!(connector.calls().len(), 2, "no retry: one attempt per call");
        let actions = sink.payloads("skill.action");
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0]["tool"], "google_calendar_create_event");
        assert_eq!(actions[0]["outcome"], "ok");
        assert_eq!(actions[1]["tool"], "google_gmail_send");
        assert_eq!(actions[1]["outcome"], "error");
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "failed");
    }

    /// `each_action`: one card per call, in order.
    #[tokio::test]
    async fn each_action_asks_once_per_call_in_order() {
        let text = b"---\nname: send-invite\nversion: 1\ntools: [google.calendar.create_event, google.gmail.send]\ninputs:\n  person: { tier: H }\n  email: { type: email }\n  when: { type: datetime }\n  duration: { type: duration, default: 30m }\napproval: each_action\n---\nBody.\n";
        let skill = parse_skill(text, "send-invite.md", "send-invite", &agent()).unwrap();
        let (tokens, person, email) = session();
        let value = json!({
            "slots": { "person": delimited(&person), "email": delimited(&email), "when": "2026-10-06T10:00:00+02:00" },
            "calls": [
                { "tool": "google_calendar_create_event", "arguments": { "summary": "M", "start": "2026-10-06T10:00:00+02:00", "attendees": [{ "email": delimited(&email) }] } },
                { "tool": "google_gmail_send", "arguments": { "to": delimited(&email), "body": "hi" } }
            ]
        });
        let fill = validate_fill(&skill, &value, &run_context(), None).unwrap();
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill, &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { ref actions } if actions.len() == 2));
        assert_eq!(approver.card_count(), 2, "one card per action");
        let cards = approver.cards.lock().unwrap();
        assert_eq!(cards[0].level, Approval::EachAction);
        assert_eq!(cards[0].calls[0].tool, "google_calendar_create_event");
        assert_eq!(cards[1].calls[0].tool, "google_gmail_send");
        assert_eq!(sink.count("skill.approval"), 2);
    }

    /// The owner may edit one call's arguments; the edit is what runs.
    #[tokio::test]
    async fn an_edited_body_replaces_that_calls_arguments() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        // An edit replaces the whole argument object, so it carries every
        // required field the schema asks for.
        let edited_body = json!({
            "to": "camille@exemple.fr",
            "subject": "Invitation",
            "body": "Edited by the owner."
        });
        let approver = RecordingApprover::answering(RunDecision::edited(vec![
            None,
            Some(edited_body.clone()),
        ]));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }));
        assert_eq!(connector.calls()[1].1, edited_body);
        assert_eq!(sink.payloads("skill.approval")[0]["decision"], "edited");
    }

    /// The vault read path: `session_token_map` returns what was recorded.
    #[test]
    fn vault_read_path_returns_the_recorded_session_map() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let (map, _, _) = session();
        vault.record("session-1", &map).unwrap();
        let loaded = session_token_map(&vault, "session-1").unwrap();
        assert_eq!(loaded.len(), map.len());
        // An unknown session is an empty map, never a guess.
        assert!(session_token_map(&vault, "session-2").unwrap().is_empty());
    }

    /// MAIL-NO-SHELL: the refusal the model reads says the tool works and what
    /// to send, so it does not read a refused search as "no mail tool".
    #[test]
    fn an_unknown_token_error_tells_the_model_the_tool_works() {
        let (map, _, _) = session();
        let err = restore_value(&json!({"query": "⟦PERSON_1⟧"}), &map).unwrap_err();
        assert!(err.contains("did not run"), "{err}");
        assert!(err.contains("did not resolve"), "{err}");
        assert!(err.contains("tool itself works"), "{err}");
        assert!(err.contains("plain word"), "{err}");
        assert!(!err.contains("refusing the run"), "{err}");
        let stray = restore_value(&json!("a ⟦⟦ b"), &map).unwrap_err();
        assert!(stray.contains("tool itself works"), "{stray}");
    }

    #[test]
    fn restore_value_refuses_unknown_tokens_and_leftover_delimiters() {
        let (map, _, _) = session();
        assert!(restore_value(&json!("camille@exemple.fr"), &map).is_ok());
        assert!(restore_value(&json!("⟦EMAIL_DEADBEEF⟧"), &map).is_err());
        // A literal delimiter left after restore is refused.
        assert!(restore_value(&json!("a ⟦⟦ b"), &map).is_err());
    }

    #[test]
    fn mail_draft_restoration_hides_values_inside_link_targets() {
        let (map, _, email) = session();
        let restored = restore_value(
            &json!({"body": format!("https://evil.invalid/?q=⟦{email}⟧ prose ⟦{email}⟧")}),
            &map,
        )
        .unwrap();
        assert_eq!(
            restored["body"],
            "https://evil.invalid/?q=[hidden] prose camille@exemple.fr"
        );
    }

    #[test]
    fn restore_value_hides_tokens_in_bare_host_labels() {
        let card = "4111111111111111";
        let spans = vec![span(card, card, EntityKind::CreditCard)];
        let (_, map) = Anonymizer::new([7u8; 32]).anonymize(card, &spans);
        let token = map
            .iter()
            .find(|(token, _)| token.starts_with("CREDIT_CARD_"))
            .map(|(token, _)| token.clone())
            .expect("a credit card token");
        let restored = restore_value(&json!(format!("⟦{token}⟧.evil.invalid/path")), &map).unwrap();
        assert_eq!(restored, "[hidden].evil.invalid/path");
    }

    #[test]
    fn mail_draft_restoration_hides_srcset_candidates_and_style_urls() {
        let (map, _, email) = session();
        let restored = restore_value(
            &json!({
                "body": format!(
                    "<img srcset=\"https://x.invalid/1?q=⟦{email}⟧ 1x, https://y.invalid/2?q=⟦{email}⟧ 2x\" style='background:url(https://z.invalid/?q=⟦{email}⟧)'>"
                )
            }),
            &map,
        )
        .unwrap();
        assert_eq!(
            restored["body"],
            "<img srcset=\"https://x.invalid/1?q=[hidden] 1x, https://y.invalid/2?q=[hidden] 2x\" style='background:url(https://z.invalid/?q=[hidden])'>"
        );
    }

    #[test]
    fn retokenize_replaces_real_values_with_tokens() {
        let (map, _, _) = session();
        let value = json!({ "to": "camille@exemple.fr", "note": "Camille Exemple" });
        let masked = retokenize_value(&value, &map);
        let text = masked.to_string();
        assert!(!text.contains("camille@exemple.fr"));
        assert!(!text.contains("Camille Exemple"));
        assert!(text.contains(PLACEHOLDER_OPEN));
    }

    #[test]
    fn recipient_values_cover_mail_and_calendar() {
        let args = json!({
            "to": "a@b.fr", "cc": "c@d.fr", "bcc": "e@f.fr"
        });
        assert_eq!(
            recipient_values("google.gmail.send", &args).unwrap().len(),
            3
        );
        let args = json!({ "attendees": [{ "email": "a@b.fr" }, { "email": "c@d.fr" }] });
        assert_eq!(
            recipient_values("google.calendar.create_event", &args)
                .unwrap()
                .len(),
            2
        );
        // A comma list is one value per address, like the Gmail parser.
        let args = json!({ "to": "a@b.fr, c@d.fr" });
        assert_eq!(
            recipient_values("google.gmail.send", &args).unwrap().len(),
            2
        );
    }

    /// A recipient that is not a string fails closed: it is never skipped.
    #[test]
    fn non_string_recipients_fail_closed() {
        assert!(recipient_values("google.gmail.send", &json!({ "to": 5 })).is_err());
        assert!(recipient_values("google.gmail.send", &json!({ "to": ["a@b.fr"] })).is_err());
        assert!(recipient_values("google.gmail.send", &json!({ "to": "a@b.fr,," })).is_err());
        let args = json!({ "attendees": [{ "email": 7 }] });
        assert!(recipient_values("google.calendar.create_event", &args).is_err());
        let args = json!({ "attendees": [5] });
        assert!(recipient_values("google.calendar.create_event", &args).is_err());
    }

    /// `restore_value` checks object keys too: a token in a key is refused.
    #[test]
    fn restore_refuses_a_token_smuggled_into_a_key() {
        let (map, _, _) = session();
        assert!(restore_value(&json!({ "⟦EMAIL_DEADBEEF⟧": "x" }), &map).is_err());
        assert!(restore_value(&json!({ "to": "x" }), &map).is_ok());
    }

    #[test]
    fn contact_index_is_a_recipient_directory() {
        let mut index = ContactIndex::new();
        index.add_from_header("Camille Exemple", "camille@exemple.fr");
        assert!(index.is_known("camille@exemple.fr"));
        assert!(index.is_known("CAMILLE@EXEMPLE.FR"));
        assert!(!index.is_known("other@exemple.fr"));
    }

    #[test]
    fn contact_aliases_are_owner_matchable_and_resolvable() {
        let mut index = ContactIndex::new();
        index.add_person(kernel_privacy::PersonDraft {
            display_name: Some("Alexandra Stone".to_string().into()),
            given: vec!["Alexandra".to_string().into()],
            family: vec!["Stone".to_string().into()],
            nicknames: vec!["Sasha".to_string().into()],
            emails: vec!["sasha@example.invalid".to_string().into()],
            ..Default::default()
        });
        assert_eq!(
            super::maximal_contact_name_matches("Please email Sasha", &index.name_groups()),
            vec![vec!["sasha"]]
        );
        assert_eq!(
            index.addresses_for_name("Sasha"),
            vec!["sasha@example.invalid"]
        );
    }

    #[test]
    fn phone_recipients_must_be_owner_typed_and_known() {
        let mut index = ContactIndex::new();
        index.add_person(kernel_privacy::PersonDraft {
            phones: vec!["+33612345678".to_string().into()],
            ..Default::default()
        });
        assert!(index.is_known("+33612345678"));
        assert!(!index.is_known("+33687654321"));
        assert!(super::check_recipients(
            &mail_skill(),
            "mail.send",
            &json!({"to": ["+33612345678"]}),
            &index,
            &[]
        )
        .is_ok());
        assert!(super::check_recipients(
            &mail_skill(),
            "mail.send",
            &json!({"to": ["+33687654321"]}),
            &index,
            &[]
        )
        .is_err());
    }

    struct WiremockConnector {
        url: String,
        client: reqwest::Client,
    }

    #[async_trait]
    impl SkillConnector for WiremockConnector {
        async fn call(
            &self,
            _skill: &SkillContext,
            _logical: &str,
            arguments: &Value,
        ) -> Result<Value, ConnectorError> {
            let body = serde_json::to_vec(arguments)
                .map_err(|err| ConnectorError::new(err.to_string()))?;
            let response = self
                .client
                .post(&self.url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|err| ConnectorError::new(err.to_string()))?;
            if !response.status().is_success() {
                return Err(ConnectorError::new(format!(
                    "connector status {}",
                    response.status()
                )));
            }
            Ok(json!({ "sent": true }))
        }
    }

    /// The Google mock receives real values only after approval, and zero
    /// requests before it; the sent body carries no `⟦`/`⟧`.
    #[tokio::test]
    async fn google_wiremock_receives_real_values_only_after_approval() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
            .mount(&server)
            .await;

        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let directory = Known(vec!["camille@exemple.fr"]);
        let connector = WiremockConnector {
            url: server.uri(),
            client: reqwest::Client::new(),
        };
        let clock = PendingClock;

        // Refused: zero requests reach the mock.
        let refused = RecordingApprover::answering(RunDecision::Refused);
        let exec = executor(
            &broker,
            &sink,
            &refused,
            &connector,
            &directory,
            &clock,
            &[],
        );
        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            0,
            "no request before approval"
        );

        // Approved: the connector sees real values, no delimiter in the body.
        let approved = RecordingApprover::approving();
        let exec = executor(
            &broker,
            &sink,
            &approved,
            &connector,
            &directory,
            &clock,
            &[],
        );
        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
        let requests = server.received_requests().await.unwrap_or_default();
        assert_eq!(requests.len(), 2);
        let bodies: String = requests
            .iter()
            .map(|request| String::from_utf8_lossy(&request.body).into_owned())
            .collect();
        assert!(bodies.contains("camille@exemple.fr"), "{bodies}");
        assert!(bodies.contains("Camille Exemple"), "{bodies}");
        assert!(!bodies.contains(PLACEHOLDER_OPEN), "{bodies}");
        assert!(!bodies.contains(PLACEHOLDER_CLOSE), "{bodies}");
    }

    /// No model-facing surface — the fill, the card's token form, or any Ledger
    /// row — carries a real value.
    #[tokio::test]
    async fn no_model_facing_surface_carries_a_real_value() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );
        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Done { .. }));

        let mut surfaces = String::new();
        for call in &fill.calls {
            surfaces.push_str(&call.arguments.to_string());
        }
        for call in &approver.cards.lock().unwrap()[0].calls {
            surfaces.push_str(&call.token_arguments.to_string());
        }
        for kind in ["skill.approval", "skill.action", "skill.run"] {
            for payload in sink.payloads(kind) {
                surfaces.push_str(&payload.to_string());
            }
        }
        assert!(!surfaces.contains("Camille"), "{surfaces}");
        assert!(!surfaces.contains("camille@exemple.fr"), "{surfaces}");
    }

    /// P2-1: a Deny on call 2 happens before call 1 is sent. The owner approved
    /// the run, but the broker refuses `google_gmail_send`: the calendar insert
    /// must not go out either.
    #[tokio::test]
    async fn operator_deny_on_a_later_call_sends_nothing() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let rules = vec![Rule::new("assistant", "google_gmail_send", Action::Deny)];
        let broker = broker_with_rules(&sink, rules);
        let approver = RecordingApprover::approving();
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert!(
            connector.calls().is_empty(),
            "no call is sent before all pass"
        );
        assert_eq!(sink.count("skill.action"), 0);
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "refused");
    }

    /// P2-1 with an owner edit: an edit that breaks the recipient policy on
    /// call 2 refuses the run before call 1 is sent.
    #[tokio::test]
    async fn edit_that_breaks_the_recipient_policy_sends_nothing() {
        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let edited = json!({ "to": "stranger@exemple.fr", "body": "Edited." });
        let approver = RecordingApprover::answering(RunDecision::edited(vec![None, Some(edited)]));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let connector = RecordingConnector::default();
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let exec = executor(
            &broker,
            &sink,
            &approver,
            &connector,
            &directory,
            &clock,
            &[],
        );

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert!(
            connector.calls().is_empty(),
            "nothing reaches the connector"
        );
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "refused");
    }

    /// P3: an owner edit gets the fill's checks: a delimiter, a header break,
    /// a non-string recipient, or a comma list with one unknown address all
    /// refuse the run with no connector call.
    #[tokio::test]
    async fn owner_edits_get_the_fill_checks() {
        let cases = [
            json!({ "to": "camille@exemple.fr", "body": "cc ⟦EMAIL_1⟧" }),
            json!({ "to": "camille@exemple.fr", "subject": "Hi\r\nBcc: x@y.fr", "body": "x" }),
            json!({ "to": 5, "body": "x" }),
            json!({ "to": "camille@exemple.fr, stranger@exemple.fr", "body": "x" }),
            // N4: a C1 control or a Unicode line separator in a header.
            json!({ "to": "camille@exemple.fr", "subject": "Hi\u{0085}Bcc: x", "body": "x" }),
            json!({ "to": "camille@exemple.fr", "subject": "Hi\u{2028}x", "body": "x" }),
        ];
        for edited in cases {
            let (tokens, person, email) = session();
            let fill = fill_via_validator(&delimited(&person), &delimited(&email));
            let approver =
                RecordingApprover::answering(RunDecision::edited(vec![None, Some(edited.clone())]));
            let sink = Arc::new(MemoryAuditSink::new());
            let broker = broker(&sink);
            let connector = RecordingConnector::default();
            let directory = Known(vec!["camille@exemple.fr"]);
            let clock = PendingClock;
            let exec = executor(
                &broker,
                &sink,
                &approver,
                &connector,
                &directory,
                &clock,
                &[],
            );

            let outcome = exec
                .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
                .await;
            assert!(
                matches!(outcome, RunOutcome::Refused { .. }),
                "{edited}: {outcome:?}"
            );
            assert!(connector.calls().is_empty(), "{edited}: nothing sent");
        }
    }

    /// P2-3: STOP engaged after call 1 means call 2 is not sent, and the run
    /// is recorded as refused.
    #[tokio::test]
    async fn stop_after_the_first_call_stops_the_second() {
        struct StopAfterFirst(Arc<std::sync::atomic::AtomicBool>);
        impl RunStop for StopAfterFirst {
            fn is_stopped(&self) -> bool {
                self.0.load(std::sync::atomic::Ordering::SeqCst)
            }
        }
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        struct StopOnFirstSend(Arc<std::sync::atomic::AtomicBool>, RecordingConnector);
        #[async_trait]
        impl SkillConnector for StopOnFirstSend {
            async fn call(
                &self,
                skill: &SkillContext,
                logical: &str,
                arguments: &Value,
            ) -> Result<Value, ConnectorError> {
                let out = self.1.call(skill, logical, arguments).await;
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                out
            }
        }

        let (tokens, person, email) = session();
        let fill = fill_via_validator(&delimited(&person), &delimited(&email));
        let sink = Arc::new(MemoryAuditSink::new());
        let broker = broker(&sink);
        let approver = RecordingApprover::approving();
        let connector = StopOnFirstSend(Arc::clone(&flag), RecordingConnector::default());
        let directory = Known(vec!["camille@exemple.fr"]);
        let clock = PendingClock;
        let stop = StopAfterFirst(Arc::clone(&flag));
        let exec = Executor {
            broker: &broker,
            sink: sink.as_ref(),
            approver: &approver,
            connector: &connector,
            directory: &directory,
            allowlist: &[],
            clock: &clock,
            stop: &stop,
            approval_timeout: default_approval_timeout(),
        };

        let outcome = exec
            .execute(&skill(), &fill, &run_context(), &tokens, &Taint::Clean)
            .await;
        assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
        assert_eq!(connector.1.calls().len(), 1, "call 2 is not sent");
        assert_eq!(sink.payloads("skill.run")[0]["outcome"], "refused");
    }
}
