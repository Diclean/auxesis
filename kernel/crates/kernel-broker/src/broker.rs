//! The permission broker: ordered rules, an approval callback, and an audit
//! trail for every decision.
//!
//! Rules are evaluated in the order they are given and the **last match
//! wins** — put your default first and exceptions after it (the same idea as
//! firewalls and OpenCode policies). A [`Rule`] may scope an agent and/or a tool
//! with the [`ANY`] wildcard.
//! When no rule matches, the broker asks — except for a tool the caller
//! declares **read-only by construction** (H-02): a declared read-only tool
//! with no matching deny rule runs with a `tool.decision` audit row and no
//! approval card. Reads are the daily-use path; the effectful default stays
//! conservative.
//!
//! **Taint (WS-C):** when the conversation holds untrusted content, the
//! broker raises the bar: every consequential call asks even if an `allow`
//! rule matches, and the [`ApprovalRequest`] tells the approver it is tainted
//! (so "always allow" can be refused). `deny` rules still win, tools the
//! caller declares **read-only by construction** keep their rule, and an
//! unknown taint state fails closed. [`Risk`] is informational: it is shown
//! and audited but never exempts a call, because a side-effecting tool that
//! under-reports its risk must not slip past the taint raise.
//!
//! Every decision — allow, deny, and both `ask` outcomes, including approver
//! failures — is written to the store as a `tool.decision` event whose payload
//! is JSON.
//!
//! **Execution mode (WS-C round 7):** a call that will run **unsandboxed** is
//! never auto-run by an `allow` rule. An `allow` rule is raised to `ask`
//! exactly as taint does (deny rules still win; a `read_only` declaration does
//! not exempt an unsandboxed call). The [`ApprovalRequest`] carries
//! `unsandboxed: true`, and the audit row records `mode = "unsandboxed"`.
//! The CLI's `--auto-approve` approver denies these asks; an interactive
//! approver may still explicitly approve them. This holds for the **first**
//! call in a clean workspace: it is a property of how the tool is built, not
//! of any prior taint mark. The caller passes [`ExecutionMode::Sandboxed`] as
//! the default; an unknown mode fails closed (unsandboxed).
//!
//! **Network-enabled shell (SHELL-NETWORK-ASK):** a sandboxed `shell` call
//! whose profile has `network = true` reports [`ExecutionMode::Networked`]. It
//! gets the same bar: no `allow` rule — and no persisted "always allow" — may
//! auto-run it, the [`ApprovalRequest`] carries `networked: true`, and the
//! audit row records `mode = "networked"`. A call that owns neither a sandbox
//! escape nor all sockets is still `Sandboxed` and keeps its allow-rule
//! behaviour.
//!
//! **Edited drafts:** an [`Approver`] may answer an ask with an
//! [`ApprovalDecision`] that substitutes the argument payload — the app's
//! `edit` decision. The broker then authorizes the *substituted* arguments:
//! they run under the same rule set, taint and execution mode as the ask
//! (a deny rule can never be edited around), they are held to the same
//! [`MAX_EDITED_ARGUMENTS_BYTES`] cap, and the `tool.decision` row carries
//! the SHA-256 of both the requested and the executed payload. Argument-
//! dependent gates that live in the caller (the web egress policy) must be
//! re-run on the substituted payload by that caller before it runs; the
//! broker never treats an approved edit as a fresh allowance of a different
//! resource.

use crate::{Risk, Taint};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

/// Wildcard that matches any agent or tool in a [`Rule`].
pub const ANY: &str = "*";

/// Cap on an approver-substituted draft (the `edit` decision), in bytes.
///
/// Identical to the 4 KiB tool-preview cap the API already applies
/// (`the daemon's api::wire::MAX_TOOL_ARGS_BYTES`): an edit can shrink a call but
/// never grow it past what the approval card could display.
pub const MAX_EDITED_ARGUMENTS_BYTES: usize = 4 * 1024;

/// How a tool call will execute for authorization purposes.
///
/// The `shell` tool is the only tool with an execution dimension, so
/// [`ToolRegistry`] reports one of the non-default variants for exactly its two
/// dangerous configurations: `Unsandboxed` for the explicit
/// `[shell] allow_unsandboxed` escape hatch, `Networked` for a sandbox that
/// allows **all** sockets (`[shell] network = true`). The broker treats both as
/// an unconditional bar: `allow` rules and persisted "always allow" answers
/// never apply to them. Unknown provenance fails closed:
/// [`crate::ToolRegistry::execution_mode`] answers `Unsandboxed` for a name it
/// cannot classify, and the default of this enum is `Sandboxed` only so callers
/// that already hold a concrete tool profile (and non-shell tools) can use it.
///
/// [`ToolRegistry`]: crate::ToolRegistry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    /// The call runs in its sandbox (or has no sandbox dimension at all).
    #[default]
    Sandboxed,
    /// The call will run without its sandbox: every ask is forced and no
    /// persistent allow may be written for it.
    Unsandboxed,
    /// The call runs sandboxed, but its sandbox has every socket open
    /// (`[shell] network = true`): every ask is forced and no persistent allow
    /// may be written for it, exactly as for [`ExecutionMode::Unsandboxed`].
    Networked,
}

impl ExecutionMode {
    /// True for [`ExecutionMode::Unsandboxed`].
    pub fn is_unsandboxed(self) -> bool {
        matches!(self, ExecutionMode::Unsandboxed)
    }

    /// True for [`ExecutionMode::Networked`].
    pub fn is_networked(self) -> bool {
        matches!(self, ExecutionMode::Networked)
    }

    /// True when no `allow` rule may auto-run the call: it either escapes its
    /// sandbox or has all sockets open. Deny rules and taint are unaffected.
    pub fn forces_ask(self) -> bool {
        !matches!(self, ExecutionMode::Sandboxed)
    }

    /// Lowercase label used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionMode::Sandboxed => "sandboxed",
            ExecutionMode::Unsandboxed => "unsandboxed",
            ExecutionMode::Networked => "networked",
        }
    }
}

impl std::fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a matching rule says to do with a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Run without asking.
    Allow,
    /// Ask the [`Approver`] callback.
    Ask,
    /// Refuse; the approver is not consulted.
    Deny,
}

impl Action {
    /// Lowercase label used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Ask => "ask",
            Action::Deny => "deny",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One ordered permission rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Agent this rule applies to, or [`ANY`]. Read from the legacy `dot` key too.
    #[serde(alias = "dot")]
    pub agent: String,
    /// Tool this rule applies to, or [`ANY`].
    pub tool: String,
    /// What to do when the rule matches.
    pub action: Action,
}

impl Rule {
    /// Build a rule.
    pub fn new(agent: impl Into<String>, tool: impl Into<String>, action: Action) -> Self {
        Self {
            agent: agent.into(),
            tool: tool.into(),
            action,
        }
    }

    /// True when this rule covers the given agent and tool.
    pub fn matches(&self, agent: &str, tool: &str) -> bool {
        (self.agent == ANY || self.agent == agent) && (self.tool == ANY || self.tool == tool)
    }
}

/// A tool call waiting for a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalRequest {
    /// Agent that wants to run the tool.
    pub agent: String,
    /// Name of the tool.
    pub tool: String,
    /// Risk classification of the tool.
    pub risk: Risk,
    /// Arguments the tool would run with. Shown to the approver; deliberately
    /// never written to the audit log.
    pub arguments: serde_json::Value,
    /// True when the conversation is tainted (or its taint state is unknown,
    /// which fails closed): "always allow" must not be offered or accepted.
    pub tainted: bool,
    /// Summary of what introduced the untrusted content, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_source: Option<String>,
    /// True when the call will run unsandboxed (the `[shell]` escape hatch):
    /// the card must say so and "always allow" must not be offered or
    /// accepted, exactly as for a tainted ask.
    pub unsandboxed: bool,
    /// True when the shell runs sandboxed with every socket open
    /// (`[shell] network = true`): the card must say so and "always allow"
    /// must not be offered or accepted, exactly as for an unsandboxed ask.
    pub networked: bool,
}

/// What an [`Approver`] decided for one ask.
///
/// A plain approve/deny is [`ApprovalDecision::new`] with no substitution.
/// An `edit` answer carries the substituted payload: the broker authorizes
/// **these** arguments instead of the requested ones, so the caller must run
/// them (and re-run any argument-dependent gate of its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    /// True when the ask may run.
    pub allow: bool,
    /// Arguments the approver substituted for the ask, or `None` to run the
    /// requested ones unchanged.
    pub arguments: Option<serde_json::Value>,
}

impl ApprovalDecision {
    /// An approve/deny with no argument substitution.
    pub fn new(allow: bool) -> Self {
        Self {
            allow,
            arguments: None,
        }
    }

    /// Approve the ask with `arguments` substituted for the requested ones
    /// (the app's `edit` decision).
    pub fn edited(arguments: serde_json::Value) -> Self {
        Self {
            allow: true,
            arguments: Some(arguments),
        }
    }
}

/// Callback consulted when a rule (or the default) says `ask`.
///
/// Implementations can prompt a human, consult another policy engine, or
/// auto-approve in tests. Returning an error is treated as a denial.
///
/// The broker calls [`Self::decide`]; the default defers to [`Self::approve`]
/// with no substitution, so an approver that never edits only implements
/// `approve`.
#[async_trait]
pub trait Approver: Send + Sync {
    /// Return `Ok(true)` to approve and `Ok(false)` to deny.
    async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError>;

    /// Decide an ask, optionally substituting an edited draft.
    ///
    /// Defaults to [`Self::approve`] with no substitution. An interactive
    /// approver that supports the `edit` decision overrides this and returns
    /// [`ApprovalDecision::edited`].
    async fn decide(&self, request: &ApprovalRequest) -> Result<ApprovalDecision, ApproverError> {
        Ok(ApprovalDecision::new(self.approve(request).await?))
    }
}

/// Error returned by an [`Approver`]; the broker fails closed and denies.
#[derive(Debug, Error)]
#[error("approver failed: {0}")]
pub struct ApproverError(pub String);

/// The fixed denial reason for a skill-only tool requested outside a skill.
/// Callers and tests match this exact string.
pub const SKILL_ONLY_REASON: &str = "skill-only tool";

/// The skill context of one broker call.
///
/// The broker receives it as an `Option<SkillRef>`: `Some` means the call runs
/// inside `skill__<name>`, `None` means the model asked for the tool directly.
/// A skill-only tool is denied without it, and asks at minimum with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRef {
    /// Skill name (the file stem).
    pub name: String,
    /// Skill version, as declared in the skill file.
    pub version: String,
    /// Content hash of the skill file, so a trace can name the exact bytes the
    /// approval was granted against.
    pub hash: String,
}

/// Outcome of a broker decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// The call may run.
    Allowed {
        /// Human-readable justification (matched rule or approval).
        reason: String,
        /// The arguments authorized to run: the requested ones, or the
        /// approver's edited draft when it substituted them.
        arguments: serde_json::Value,
        /// True when the approver explicitly substituted an edited draft,
        /// including when its value happens to equal the requested payload.
        edited: bool,
    },
    /// The call must not run.
    Denied {
        /// Human-readable justification.
        reason: String,
    },
}

impl Authorization {
    /// True for [`Authorization::Allowed`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, Authorization::Allowed { .. })
    }

    /// Human-readable justification for the decision.
    pub fn reason(&self) -> &str {
        match self {
            Authorization::Allowed { reason, .. } | Authorization::Denied { reason } => reason,
        }
    }

    /// The arguments authorized to run, when the call is allowed.
    ///
    /// For an allowed call this is always present: the edited draft when the
    /// approver substituted one, else the requested arguments.
    pub fn arguments(&self) -> Option<&serde_json::Value> {
        match self {
            Authorization::Allowed { arguments, .. } => Some(arguments),
            Authorization::Denied { .. } => None,
        }
    }

    /// Whether an allowed call was authorized with an approver-substituted
    /// draft.
    pub fn arguments_were_edited(&self) -> bool {
        matches!(self, Authorization::Allowed { edited: true, .. })
    }
}

/// Errors returned by an [`AuditSink`].
#[derive(Debug, Error)]
pub enum AuditError {
    /// The sink could not record the event.
    #[error("audit sink failed: {0}")]
    Backend(String),
}

impl AuditError {
    /// Wrap a backend's own error message.
    pub fn backend(message: impl Into<String>) -> Self {
        Self::Backend(message.into())
    }
}

/// The audit trail behind the broker: one event per decision.
///
/// The kernel does not own a store. The app implements this trait over its
/// SQLite `events` table; [`MemoryAuditSink`] is the in-process test double.
/// Every decision the broker makes — allow, deny, both ask outcomes, approver
/// failures and edit substitutions — is logged as a `tool.decision` event
/// carrying the metadata-only JSON payload. The returned id is the new row.
pub trait AuditSink: Send + Sync {
    /// Record `payload` under `kind` and return the row id.
    fn log_event(&self, kind: &str, payload: &serde_json::Value) -> Result<i64, AuditError>;
}

/// In-memory [`AuditSink`] for tests: records every event, in order.
#[cfg(any(test, feature = "test-util"))]
#[derive(Default)]
pub struct MemoryAuditSink {
    events: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
}

#[cfg(any(test, feature = "test-util"))]
impl MemoryAuditSink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every `(kind, payload)` recorded, in order.
    pub fn events(&self) -> Vec<(String, serde_json::Value)> {
        self.events.lock().unwrap().clone()
    }

    /// Payloads recorded for `kind`, in order.
    pub fn payloads(&self, kind: &str) -> Vec<serde_json::Value> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(recorded, _)| recorded == kind)
            .map(|(_, payload)| payload.clone())
            .collect()
    }

    /// How many events of `kind` were recorded.
    pub fn count(&self, kind: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(recorded, _)| recorded == kind)
            .count()
    }
}

#[cfg(any(test, feature = "test-util"))]
impl AuditSink for MemoryAuditSink {
    fn log_event(&self, kind: &str, payload: &serde_json::Value) -> Result<i64, AuditError> {
        let mut events = self.events.lock().unwrap();
        events.push((kind.to_string(), payload.clone()));
        Ok(events.len() as i64)
    }
}

/// Errors returned by the broker itself.
#[derive(Debug, Error)]
pub enum BrokerError {
    /// Writing the audit record failed.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// The audit record could not be serialized.
    #[error("serializing audit record: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Serialize)]
struct AuditRecord {
    agent: String,
    tool: String,
    risk: Risk,
    action: &'static str,
    outcome: &'static str,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Conversation taint state at decision time.
    tainted: bool,
    /// What introduced the untrusted content, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    taint_source: Option<String>,
    /// How the call will execute (`sandboxed` / `unsandboxed` / `networked`).
    mode: &'static str,
    /// SHA-256 (hex) of the arguments the caller requested, present only when
    /// an approver substituted an edited draft.
    #[serde(skip_serializing_if = "Option::is_none")]
    original_args_sha256: Option<String>,
    /// SHA-256 (hex) of the arguments that were authorized to run (the edited
    /// draft), present only when an approver substituted one.
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_args_sha256: Option<String>,
}

/// SHA-256 of the canonical JSON encoding of a tool-argument payload, hex.
///
/// The audit never stores arguments (they can hold secrets); the hashes let a
/// reader tie the requested and the executed call to the same decision row
/// without leaking either payload.
fn arguments_sha256(arguments: &serde_json::Value) -> String {
    let mut encoded = String::new();
    append_canonical_json(arguments, &mut encoded);
    let digest = Sha256::digest(&encoded);
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Append a deterministic JSON encoding: object keys are sorted at every
/// depth, and numbers use normalized scientific notation. The latter makes
/// equivalent JSON spellings such as `1.0`, `1e0`, and `10e-1` hash alike,
/// despite `arbitrary_precision` retaining the source number lexeme.
fn append_canonical_json(value: &serde_json::Value, output: &mut String) {
    match value {
        serde_json::Value::Null => output.push_str("null"),
        serde_json::Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        serde_json::Value::Number(number) => {
            output.push_str(&canonical_number(&number.to_string()))
        }
        serde_json::Value::String(value) => output.push_str(
            &serde_json::to_string(value).expect("serializing a JSON string cannot fail"),
        ),
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                append_canonical_json(value, output);
            }
            output.push(']');
        }
        serde_json::Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_unstable_by_key(|(key, _)| *key);
            output.push('{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("serializing a JSON key cannot fail"),
                );
                output.push(':');
                append_canonical_json(value, output);
            }
            output.push('}');
        }
    }
}

/// Normalize one JSON number into a signed coefficient and a base-ten
/// exponent. The exponent arithmetic is decimal-string based so very large
/// valid JSON exponents remain deterministic without overflow.
fn canonical_number(raw: &str) -> String {
    let (negative, unsigned) = raw
        .strip_prefix('-')
        .map_or((false, raw), |unsigned| (true, unsigned));
    let exponent_at = unsigned.find(['e', 'E']);
    let (mantissa, exponent) = exponent_at
        .map(|index| (&unsigned[..index], &unsigned[index + 1..]))
        .unwrap_or((unsigned, "0"));
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = String::with_capacity(integer.len() + fraction.len());
    digits.push_str(integer);
    digits.push_str(fraction);
    let significant = digits.trim_start_matches('0');
    if significant.is_empty() {
        return "0".to_string();
    }
    let trailing_zeroes = significant.len() - significant.trim_end_matches('0').len();
    let coefficient = &significant[..significant.len() - trailing_zeroes];
    let adjustment = i64::try_from(trailing_zeroes).expect("number length fits in i64")
        + i64::try_from(coefficient.len() - 1).expect("number length fits in i64")
        - i64::try_from(fraction.len()).expect("number length fits in i64");
    let exponent = add_decimal_integer(exponent, adjustment);
    let mut output = String::with_capacity(coefficient.len() + exponent.len() + 4);
    if negative {
        output.push('-');
    }
    output.push(coefficient.as_bytes()[0] as char);
    if coefficient.len() > 1 {
        output.push('.');
        output.push_str(&coefficient[1..]);
    }
    output.push('e');
    output.push_str(&exponent);
    output
}

fn add_decimal_integer(value: &str, adjustment: i64) -> String {
    let (value_negative, value_digits) = normalized_signed_digits(value);
    let adjustment = adjustment.to_string();
    let (adjustment_negative, adjustment_digits) = normalized_signed_digits(&adjustment);
    let value_is_zero = value_digits == "0";
    let adjustment_is_zero = adjustment_digits == "0";
    if value_is_zero {
        return signed_digits(adjustment_negative, &adjustment_digits);
    }
    if adjustment_is_zero {
        return signed_digits(value_negative, &value_digits);
    }
    if value_negative == adjustment_negative {
        return signed_digits(
            value_negative,
            &add_magnitudes(&value_digits, &adjustment_digits),
        );
    }
    match compare_magnitudes(&value_digits, &adjustment_digits) {
        std::cmp::Ordering::Greater => signed_digits(
            value_negative,
            &subtract_magnitudes(&value_digits, &adjustment_digits),
        ),
        std::cmp::Ordering::Less => signed_digits(
            adjustment_negative,
            &subtract_magnitudes(&adjustment_digits, &value_digits),
        ),
        std::cmp::Ordering::Equal => "0".to_string(),
    }
}

fn normalized_signed_digits(value: &str) -> (bool, String) {
    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        (false, "0".to_string())
    } else {
        (negative, digits.to_string())
    }
}

fn signed_digits(negative: bool, digits: &str) -> String {
    if negative && digits != "0" {
        format!("-{digits}")
    } else {
        digits.to_string()
    }
}

fn compare_magnitudes(left: &str, right: &str) -> std::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn add_magnitudes(left: &str, right: &str) -> String {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut digits = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut carry = 0u8;
    for index in 0..left.len().max(right.len()) {
        let a = left
            .get(left.len().wrapping_sub(index + 1))
            .map_or(0, |digit| digit - b'0');
        let b = right
            .get(right.len().wrapping_sub(index + 1))
            .map_or(0, |digit| digit - b'0');
        let sum = a + b + carry;
        digits.push(b'0' + sum % 10);
        carry = sum / 10;
    }
    if carry != 0 {
        digits.push(b'0' + carry);
    }
    digits.reverse();
    String::from_utf8(digits).expect("decimal digits are valid UTF-8")
}

/// Subtract decimal magnitudes where `left >= right`.
fn subtract_magnitudes(left: &str, right: &str) -> String {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut digits = Vec::with_capacity(left.len());
    let mut borrow = 0i16;
    for index in 0..left.len() {
        let a = i16::from(left[left.len() - index - 1] - b'0') - borrow;
        let b = right
            .get(right.len().wrapping_sub(index + 1))
            .map_or(0, |digit| i16::from(digit - b'0'));
        if a < b {
            digits.push((a + 10 - b) as u8 + b'0');
            borrow = 1;
        } else {
            digits.push((a - b) as u8 + b'0');
            borrow = 0;
        }
    }
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
    }
    digits.reverse();
    String::from_utf8(digits).expect("decimal digits are valid UTF-8")
}

/// The inputs of one authorization call, all required.
///
/// Every bar the broker applies is named here: there is no `Default` and no
/// shorthand constructor, so a caller cannot omit taint, read-only, execution
/// mode, explicit-rule, skill context or the skill-only declaration by
/// accident. `skill_only: false` never lowers a tool the broker's live
/// [`SkillOnlyLookup`] reports as skill-only: the broker raises the floor by
/// name regardless of this field.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest<'a> {
    /// Agent that wants to run the tool.
    pub agent: &'a str,
    /// Name of the tool.
    pub tool: &'a str,
    /// Risk classification of the tool.
    pub risk: Risk,
    /// Arguments the tool would run with. Shown to the approver; never written
    /// to the audit record.
    pub arguments: serde_json::Value,
    /// Taint state of the conversation. An unknown state behaves as tainted.
    pub taint: &'a Taint,
    /// True when the caller declares the tool read-only by construction: it
    /// observes local state and produces no side effects.
    pub read_only: bool,
    /// How the call will execute ([`ExecutionMode::forces_ask`] refuses every
    /// persistent allow).
    pub mode: ExecutionMode,
    /// True when a wildcard `allow` rule must not authorize this tool.
    pub requires_explicit_rule: bool,
    /// The skill context of the call, when it runs inside a skill.
    pub skill: Option<&'a SkillRef>,
    /// True when the tool declares [`crate::Tool::skill_only`].
    pub skill_only: bool,
}

/// The live answer to "is this tool skill-only?".
///
/// The broker's hardline skill floor is a property of the **tool**, not of a
/// caller's bookkeeping, so the broker asks this on every
/// [`Broker::authorize`] call instead of copying a name set at build time.
/// [`crate::ToolRegistry`] implements it by reading the class of the tool
/// registered under that name *right now*; hold the registry behind an
/// `Arc<RwLock<_>>` so a tool registered after the broker was built is still
/// covered.
pub trait SkillOnlyLookup: Send + Sync {
    /// True when `tool` declares [`crate::Tool::skill_only`] right now.
    fn is_skill_only(&self, tool: &str) -> bool;
}

/// The rule that decides `tool` for `agent`, with its index: the last match
/// wins, and a wildcard `allow` never covers a tool that requires an explicit
/// rule. [`Broker::authorize`] decides with it; an approver that must agree
/// with the broker on which rule applies calls it too.
pub fn matching_rule<'a>(
    rules: &'a [Rule],
    agent: &str,
    tool: &str,
    requires_explicit_rule: bool,
) -> Option<(usize, &'a Rule)> {
    rules.iter().enumerate().rfind(|(_, rule)| {
        rule.matches(agent, tool)
            && !(requires_explicit_rule && rule.tool == ANY && rule.action == Action::Allow)
    })
}

/// Decides whether an agent may run a tool, with an audit record for each call.
pub struct Broker {
    rules: Vec<Rule>,
    sink: Arc<dyn AuditSink>,
    approver: Arc<dyn Approver>,
    /// The live skill floor, consulted on every [`Self::authorize`] call. A
    /// mandatory constructor argument: no `Default`, no `Option`, no builder
    /// that skips it, and no method that replaces or clears it.
    skill_only: Arc<dyn SkillOnlyLookup>,
}

impl Broker {
    /// Build a broker for `rules`, auditing to `sink`, asking `approver` when
    /// needed, and taking the skill floor from `skill_only`.
    ///
    /// All four arguments are mandatory. A broker cannot be built without an
    /// answer to "is this tool skill-only?", and the round-1 optional
    /// `with_skill_only_tools` is gone: there is no method to replace or clear
    /// the lookup after the fact. The seal's probe does not compile — three
    /// arguments are not enough:
    ///
    /// ```compile_fail,E0061
    /// fn _probe(
    ///     sink: std::sync::Arc<dyn kernel_broker::AuditSink>,
    ///     rules: Vec<kernel_broker::Rule>,
    ///     approver: std::sync::Arc<dyn kernel_broker::Approver>,
    /// ) {
    ///     let _ = kernel_broker::Broker::new(sink, rules, approver);
    /// }
    /// ```
    ///
    /// and neither is a setter. The probe takes the broker **by value**, so
    /// before this fix it compiled (the method existed) and now it fails with
    /// `E0599`:
    ///
    /// ```compile_fail,E0599
    /// fn _probe(broker: kernel_broker::Broker) {
    ///     let _ = broker.with_skill_only_tools(["gmail_send"]);
    /// }
    /// ```
    pub fn new(
        sink: Arc<dyn AuditSink>,
        rules: Vec<Rule>,
        approver: Arc<dyn Approver>,
        skill_only: Arc<dyn SkillOnlyLookup>,
    ) -> Self {
        Self {
            rules,
            sink,
            approver,
            skill_only,
        }
    }

    /// The configured rules, in evaluation order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The one authorization entry point.
    ///
    /// Evaluation is ordered: the last matching rule wins (defaults first,
    /// exceptions after). With no match the broker asks, and a missing
    /// approver answer (error) is a denial. A tainted conversation raises
    /// every consequential `allow` to `ask`; an unsandboxed call is raised
    /// regardless of taint; and a skill-only tool (by the request's
    /// declaration or the live [`SkillOnlyLookup`]) is **denied** with
    /// [`SKILL_ONLY_REASON`] when `skill` is `None`, or held to at least `ask`
    /// when it is `Some` — all before the approver is consulted for the
    /// denial. `deny` rules still win everywhere.
    pub async fn authorize(&self, req: AuthorizeRequest<'_>) -> Result<Authorization, BrokerError> {
        // The hardline floor is a property of the tool, not of the caller's
        // bookkeeping: a name the live lookup reports as skill-only is
        // skill-only whatever the request says. The lookup is consulted here,
        // at authorization time, so a tool registered after this broker was
        // built is covered.
        let skill_only = req.skill_only || self.skill_only.is_skill_only(req.tool);
        self.authorize_inner(req, skill_only).await
    }

    /// The authorization body, with the skill floor already resolved.
    async fn authorize_inner(
        &self,
        req: AuthorizeRequest<'_>,
        skill_only: bool,
    ) -> Result<Authorization, BrokerError> {
        let AuthorizeRequest {
            agent,
            tool,
            risk,
            arguments,
            taint,
            read_only,
            mode,
            requires_explicit_rule,
            skill,
            skill_only: _,
        } = req;
        let tainted = taint.forces_ask();
        let taint_source = taint.summary();
        let unsandboxed = mode.is_unsandboxed();
        let networked = mode.is_networked();

        // Hardline floor (soul rule 1): a skill-only tool
        // requested without a skill context is refused here, before any rule
        // match and before the approver is asked anything.
        if skill_only && skill.is_none() {
            let reason = SKILL_ONLY_REASON.to_string();
            self.audit(AuditRecord {
                agent: agent.to_string(),
                tool: tool.to_string(),
                risk,
                action: Action::Deny.as_str(),
                outcome: "denied",
                reason: reason.clone(),
                rule: None,
                approved: None,
                error: None,
                tainted,
                taint_source,
                mode: mode.as_str(),
                original_args_sha256: None,
                executed_args_sha256: None,
            })?;
            return Ok(Authorization::Denied { reason });
        }

        // Last matching rule wins: defaults first, exceptions after.
        let matched = matching_rule(&self.rules, agent, tool, requires_explicit_rule);
        // H-02 (calibration): the no-rule default for a tool the caller
        // declares read-only is **allow** — an audit row, no approval card.
        // Reads are the daily-use path and a read-only tool cannot move data
        // or run anything. The two existing bars stay exactly as before:
        // taint still asks, and an unsandboxed or network-enabled call still
        // asks (a matching rule still wins in both directions).
        let read_only_default = matched.is_none() && read_only && !tainted && !mode.forces_ask();
        let (rule_index, rule_action) = match matched {
            Some((index, rule)) => (Some(index), rule.action),
            None if read_only_default => (None, Action::Allow),
            None => (None, Action::Ask),
        };
        // Three independent bars can raise an `allow` rule to `ask`:
        // - taint: untrusted content is in the conversation, so a
        //   consequential call must be approved (an explicit read-only
        //   declaration is the only exemption);
        // - unsandboxed: the call will escape its sandbox, so no `allow`
        //   rule — and no persisted "always allow" — may auto-run it, ever;
        // - networked: the sandbox has every socket open, so the same bar
        //   applies even though the filesystem is still confined.
        // `Risk` is deliberately not consulted for either: a tool that
        // under-reports its risk must still ask.
        //
        // The skill floor is the fourth: a skill-only tool running inside a
        // skill asks at minimum, so an `allow` rule cannot lift it either.
        let skill_floor = skill_only && skill.is_some();
        let forced_reason = if skill_floor {
            Some(format!(
                "`{tool}` is skill-only and may run only inside a skill"
            ))
        } else if unsandboxed {
            Some(if tainted {
                format!(
                    "`{tool}` runs unsandboxed and the conversation is tainted ({})",
                    taint_source.as_deref().unwrap_or("unknown")
                )
            } else {
                format!("`{tool}` runs unsandboxed")
            })
        } else if networked {
            Some(if tainted {
                format!(
                    "`{tool}` runs with the network enabled and the conversation is tainted ({})",
                    taint_source.as_deref().unwrap_or("unknown")
                )
            } else {
                format!("`{tool}` runs with the network enabled (all sockets open)")
            })
        } else if tainted && !read_only {
            Some(format!(
                "the conversation is tainted ({}) and `{tool}` is consequential",
                taint_source.as_deref().unwrap_or("unknown")
            ))
        } else {
            None
        };
        let forced = rule_action == Action::Allow && forced_reason.is_some();
        let action = if forced { Action::Ask } else { rule_action };
        let label = match (rule_index, forced) {
            (Some(index), true) => format!(
                "rule {index} matched, but {}",
                forced_reason
                    .as_deref()
                    .unwrap_or("the call must be approved")
            ),
            (Some(index), false) => format!("rule {index} matched"),
            (None, true) => format!(
                "no matching rule, but {}",
                forced_reason
                    .as_deref()
                    .unwrap_or("the call must be approved")
            ),
            (None, _) if read_only_default => {
                "no matching rule (read-only tool, default allow)".to_string()
            }
            (None, _) => "no matching rule (default ask)".to_string(),
        };

        match action {
            Action::Allow | Action::Deny => {
                let outcome = if action == Action::Allow {
                    "allowed"
                } else {
                    "denied"
                };
                let reason = format!("{label}: {action}");
                self.audit(AuditRecord {
                    agent: agent.to_string(),
                    tool: tool.to_string(),
                    risk,
                    action: action.as_str(),
                    outcome,
                    reason: reason.clone(),
                    rule: rule_index,
                    approved: None,
                    error: None,
                    tainted,
                    taint_source,
                    mode: mode.as_str(),
                    original_args_sha256: None,
                    executed_args_sha256: None,
                })?;
                Ok(if action == Action::Allow {
                    Authorization::Allowed {
                        reason,
                        arguments,
                        edited: false,
                    }
                } else {
                    Authorization::Denied { reason }
                })
            }
            Action::Ask => {
                let requested = arguments;
                let request = ApprovalRequest {
                    agent: agent.to_string(),
                    tool: tool.to_string(),
                    risk,
                    arguments: requested.clone(),
                    tainted,
                    taint_source: taint_source.clone(),
                    unsandboxed,
                    networked,
                };
                match self.approver.decide(&request).await {
                    Ok(decision) if decision.allow => {
                        // An edited draft is what runs; a plain approve keeps
                        // the request. The rule set, taint and mode are the
                        // same ones the ask was decided under, so an edit can
                        // never widen them. The 4 KiB preview cap is re-applied
                        // to the substituted payload as a hard floor.
                        let (executed, edited, original_args_sha256, executed_args_sha256) =
                            match decision.arguments {
                                Some(edited) => {
                                    let too_large = serde_json::to_vec(&edited)
                                        .map(|encoded| encoded.len() > MAX_EDITED_ARGUMENTS_BYTES)
                                        .unwrap_or(true);
                                    if too_large {
                                        let reason = format!(
                                            "{label}: ask, approved, but the edited draft exceeds the {MAX_EDITED_ARGUMENTS_BYTES} byte cap, denied"
                                        );
                                        self.audit(AuditRecord {
                                            agent: agent.to_string(),
                                            tool: tool.to_string(),
                                            risk,
                                            action: Action::Ask.as_str(),
                                            outcome: "denied",
                                            reason: reason.clone(),
                                            rule: rule_index,
                                            approved: Some(true),
                                            error: Some("edited_arguments_too_large".to_string()),
                                            tainted,
                                            taint_source,
                                            mode: mode.as_str(),
                                            original_args_sha256: Some(arguments_sha256(
                                                &requested,
                                            )),
                                            executed_args_sha256: Some(arguments_sha256(&edited)),
                                        })?;
                                        return Ok(Authorization::Denied { reason });
                                    }
                                    (
                                        edited.clone(),
                                        true,
                                        Some(arguments_sha256(&requested)),
                                        Some(arguments_sha256(&edited)),
                                    )
                                }
                                None => (requested, false, None, None),
                            };
                        let reason = format!("{label}: ask, approved");
                        self.audit(AuditRecord {
                            agent: agent.to_string(),
                            tool: tool.to_string(),
                            risk,
                            action: Action::Ask.as_str(),
                            outcome: "allowed",
                            reason: reason.clone(),
                            rule: rule_index,
                            approved: Some(true),
                            error: None,
                            tainted,
                            taint_source,
                            mode: mode.as_str(),
                            original_args_sha256,
                            executed_args_sha256,
                        })?;
                        Ok(Authorization::Allowed {
                            reason,
                            arguments: executed,
                            edited,
                        })
                    }
                    Ok(_) => {
                        let reason = format!("{label}: ask, denied");
                        self.audit(AuditRecord {
                            agent: agent.to_string(),
                            tool: tool.to_string(),
                            risk,
                            action: Action::Ask.as_str(),
                            outcome: "denied",
                            reason: reason.clone(),
                            rule: rule_index,
                            approved: Some(false),
                            error: None,
                            tainted,
                            taint_source,
                            mode: mode.as_str(),
                            original_args_sha256: None,
                            executed_args_sha256: None,
                        })?;
                        Ok(Authorization::Denied { reason })
                    }
                    Err(err) => {
                        // Fail closed: a broken approval channel is a denial.
                        let reason =
                            format!("{label}: ask, approver failed, denied (fail closed): {err}");
                        self.audit(AuditRecord {
                            agent: agent.to_string(),
                            tool: tool.to_string(),
                            risk,
                            action: Action::Ask.as_str(),
                            outcome: "denied",
                            reason: reason.clone(),
                            rule: rule_index,
                            approved: Some(false),
                            error: Some(err.to_string()),
                            tainted,
                            taint_source,
                            mode: mode.as_str(),
                            original_args_sha256: None,
                            executed_args_sha256: None,
                        })?;
                        Ok(Authorization::Denied { reason })
                    }
                }
            }
        }
    }

    fn audit(&self, record: AuditRecord) -> Result<(), BrokerError> {
        let payload = serde_json::to_value(&record)?;
        self.sink.log_event("tool.decision", &payload)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaintSource;
    use std::sync::{Mutex, RwLock};

    /// The lookup the tests that do not exercise the floor pass: no tool is
    /// skill-only, so only the request's own `skill_only` declaration counts.
    struct NoSkillOnlyTools;

    impl SkillOnlyLookup for NoSkillOnlyTools {
        fn is_skill_only(&self, _tool: &str) -> bool {
            false
        }
    }

    /// The mandatory [`Broker::new`] argument for those tests.
    fn no_skill_only() -> Arc<dyn SkillOnlyLookup> {
        Arc::new(NoSkillOnlyTools)
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        Approve,
        Deny,
        Fail,
    }

    struct ScriptedApprover {
        calls: Mutex<Vec<ApprovalRequest>>,
        outcome: Outcome,
    }

    impl ScriptedApprover {
        fn new(outcome: Outcome) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                outcome,
            })
        }

        fn calls(&self) -> Vec<ApprovalRequest> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Approver for ScriptedApprover {
        async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
            self.calls.lock().unwrap().push(request.clone());
            match self.outcome {
                Outcome::Approve => Ok(true),
                Outcome::Deny => Ok(false),
                Outcome::Fail => Err(ApproverError("no approval UI attached".to_string())),
            }
        }
    }

    fn sink() -> Arc<MemoryAuditSink> {
        Arc::new(MemoryAuditSink::new())
    }

    /// A clean taint state with a `'static` lifetime, so the request helpers
    /// below can borrow it.
    static CLEAN: Taint = Taint::Clean;

    /// A clean, sandboxed request with no explicit-rule or skill context.
    fn request<'a>(
        agent: &'a str,
        tool: &'a str,
        risk: Risk,
        arguments: serde_json::Value,
    ) -> AuthorizeRequest<'a> {
        request_with(
            agent,
            tool,
            risk,
            arguments,
            &CLEAN,
            false,
            ExecutionMode::Sandboxed,
            false,
            false,
            None,
        )
    }

    /// The full request, in the order the old entry points took their
    /// arguments, so a test names every bar the broker applies.
    #[allow(clippy::too_many_arguments)]
    fn request_with<'a>(
        agent: &'a str,
        tool: &'a str,
        risk: Risk,
        arguments: serde_json::Value,
        taint: &'a Taint,
        read_only: bool,
        mode: ExecutionMode,
        requires_explicit_rule: bool,
        skill_only: bool,
        skill: Option<&'a SkillRef>,
    ) -> AuthorizeRequest<'a> {
        AuthorizeRequest {
            agent,
            tool,
            risk,
            arguments,
            taint,
            read_only,
            mode,
            requires_explicit_rule,
            skill,
            skill_only,
        }
    }

    fn skill(name: &str) -> SkillRef {
        SkillRef {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            hash: "sha256:abc123".to_string(),
        }
    }

    /// The argument list every skill-floor test uses, so the two cases differ
    /// only by the skill context.
    #[allow(clippy::too_many_arguments)]
    async fn authorize_skill_only(
        broker: &Broker,
        skill_only: bool,
        skill: Option<&SkillRef>,
    ) -> Authorization {
        broker
            .authorize(request_with(
                "main",
                "google_gmail_send",
                Risk::High,
                serde_json::json!({"to": "owner@example.test"}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                true,
                skill_only,
                skill,
            ))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_skill_only_tool_without_a_skill_is_denied_before_the_approver() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        // Even the strongest rule cannot reach the approver: the hardline
        // floor runs before any rule match and before the approver is asked.
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "google_gmail_send", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );
        match authorize_skill_only(&broker, true, None).await {
            Authorization::Denied { reason } => assert_eq!(reason, SKILL_ONLY_REASON),
            other => panic!("expected Denied, got {other:?}"),
        }
        assert!(
            approver.calls().is_empty(),
            "the approver must never be consulted for a skill-only denial"
        );
        let payloads = sink.payloads("tool.decision");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["action"], "deny");
        assert_eq!(payloads[0]["reason"], SKILL_ONLY_REASON);
    }

    #[tokio::test]
    async fn a_skill_only_tool_inside_a_skill_still_asks_under_an_allow_rule() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        // An exact allow rule is the strongest thing that can match a
        // skill-only tool (a wildcard never does): it must still ask.
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "google_gmail_send", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );
        let context = skill("gmail_send");
        let auth = authorize_skill_only(&broker, true, Some(&context)).await;
        assert!(auth.is_allowed());
        assert_eq!(
            approver.calls().len(),
            1,
            "an allow rule cannot lift the skill floor: the call must ask"
        );
        assert!(
            auth.reason().contains("skill-only"),
            "the audit must name the floor: {}",
            auth.reason()
        );

        // A deny rule still wins over the skill floor.
        let denying = Broker::new(
            sink,
            vec![Rule::new(ANY, "google_gmail_send", Action::Deny)],
            ScriptedApprover::new(Outcome::Approve),
            no_skill_only(),
        );
        assert!(matches!(
            authorize_skill_only(&denying, true, Some(&context)).await,
            Authorization::Denied { .. }
        ));
    }

    #[tokio::test]
    async fn a_tool_that_is_not_skill_only_is_unaffected_by_the_context() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink,
            vec![Rule::new(ANY, "google_gmail_send", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );
        // Not skill-only, no context: the allow rule runs it without an ask.
        let auth = authorize_skill_only(&broker, false, None).await;
        assert!(auth.is_allowed());
        assert!(approver.calls().is_empty());
        // Not skill-only, with a context: the context never weakens anything.
        let context = skill("gmail_send");
        let auth = authorize_skill_only(&broker, false, Some(&context)).await;
        assert!(auth.is_allowed());
        assert!(approver.calls().is_empty());
    }

    /// A tool that declares the hardline skill floor in its own class.
    struct GmailSend;

    #[async_trait]
    impl crate::Tool for GmailSend {
        fn name(&self) -> &str {
            "gmail_send"
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &crate::ToolCtx,
        ) -> Result<crate::ToolOutput, crate::ToolError> {
            Ok(crate::ToolOutput::ok(""))
        }

        fn risk(&self) -> Risk {
            Risk::High
        }

        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B8
        }

        fn class(&self) -> crate::ToolClass {
            crate::ToolClass {
                skill_only: true,
                ..crate::ToolClass::default()
            }
        }
    }

    #[tokio::test]
    async fn a_tool_registered_after_the_broker_was_built_is_denied_without_a_skill() {
        // Seal probe_e: the floor is **live**, not a snapshot. The broker is
        // built first, holding a handle on the shared registry; `gmail_send`
        // is registered skill-only only afterwards. The request says
        // `skill_only: false` and an exact `allow` rule matches — the call must
        // still be denied with SKILL_ONLY_REASON, before the approver is
        // consulted.
        let registry = Arc::new(RwLock::new(crate::ToolRegistry::new()));
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "gmail_send", Action::Allow)],
            approver.clone(),
            registry.clone(),
        );

        // Nothing is skill-only yet: the live lookup answers `false`.
        assert!(!SkillOnlyLookup::is_skill_only(
            &*registry.read().unwrap(),
            "gmail_send"
        ));

        // The registration happens after the broker exists.
        registry.write().unwrap().register(Box::new(GmailSend));
        assert_eq!(registry.read().unwrap().skill_only_tools(), ["gmail_send"]);

        let auth = broker
            .authorize(request(
                "main",
                "gmail_send",
                Risk::High,
                serde_json::json!({"to": "owner@example.test"}),
            ))
            .await
            .unwrap();
        match auth {
            Authorization::Denied { reason } => assert_eq!(reason, SKILL_ONLY_REASON),
            other => panic!("expected Denied, got {other:?}"),
        }
        assert!(
            approver.calls().is_empty(),
            "the approver must never be consulted for a skill-only denial"
        );
        let payloads = sink.payloads("tool.decision");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["action"], "deny");
        assert_eq!(payloads[0]["reason"], SKILL_ONLY_REASON);
    }

    #[tokio::test]
    async fn ask_approver_receives_arguments() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let arguments = serde_json::json!({"command": "echo hi"});
        let auth = broker
            .authorize(request("main", "shell", Risk::High, arguments.clone()))
            .await
            .unwrap();
        assert!(auth.is_allowed());

        let calls = approver.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments, arguments);

        // The wrapper without arguments attaches `null`, never stale data.
        let bare = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(sink.clone(), vec![], bare.clone(), no_skill_only());
        broker
            .authorize(request(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(bare.calls()[0].arguments, serde_json::Value::Null);
    }

    #[tokio::test]
    async fn explicit_rule_tools_ignore_wildcard_allows_but_keep_exact_allows() {
        let sink = sink();
        let wildcard_approver = ScriptedApprover::new(Outcome::Approve);
        let wildcard = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, ANY, Action::Allow)],
            wildcard_approver.clone(),
            no_skill_only(),
        );
        let result = wildcard
            .authorize(request_with(
                "main",
                "google_gmail_create_draft",
                Risk::Medium,
                serde_json::json!({"to":"owner@example.test"}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                true,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(result.is_allowed());
        assert_eq!(
            wildcard_approver.calls().len(),
            1,
            "wildcard allow must ask"
        );

        let exact_approver = ScriptedApprover::new(Outcome::Approve);
        let exact = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, "google_gmail_create_draft", Action::Allow)],
            exact_approver.clone(),
            no_skill_only(),
        );
        let result = exact
            .authorize(request_with(
                "main",
                "google_gmail_create_draft",
                Risk::Medium,
                serde_json::json!({"to":"owner@example.test"}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                true,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(result.is_allowed());
        assert!(exact_approver.calls().is_empty(), "exact allow is retained");

        let ordinary_approver = ScriptedApprover::new(Outcome::Approve);
        let ordinary = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, ANY, Action::Allow)],
            ordinary_approver.clone(),
            no_skill_only(),
        );
        let result = ordinary
            .authorize(request_with(
                "main",
                "ordinary_tool",
                Risk::Medium,
                serde_json::json!({}),
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(result.is_allowed());
        assert!(ordinary_approver.calls().is_empty());
    }

    #[tokio::test]
    async fn explicit_rule_tools_always_ask_in_tainted_conversations() {
        let sink = sink();
        for rule in [
            Rule::new(ANY, ANY, Action::Allow),
            Rule::new(ANY, "google_gmail_create_draft", Action::Allow),
        ] {
            let approver = ScriptedApprover::new(Outcome::Approve);
            let broker = Broker::new(
                sink.clone(),
                vec![rule.clone()],
                approver.clone(),
                no_skill_only(),
            );
            let result = broker
                .authorize(request_with(
                    "main",
                    "google_gmail_create_draft",
                    Risk::Medium,
                    serde_json::json!({"to":"owner@example.test"}),
                    &Taint::Tainted(TaintSource::new("test", None)),
                    false,
                    ExecutionMode::Sandboxed,
                    true,
                    false,
                    None,
                ))
                .await
                .unwrap();
            assert!(result.is_allowed());
            assert_eq!(approver.calls().len(), 1, "taint must ask for {rule:?}");
        }
    }

    #[tokio::test]
    async fn allow_rule_allows_without_asking() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert!(approver.calls().is_empty(), "allow must not ask");
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn deny_rule_denies_without_asking() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed());
        assert!(approver.calls().is_empty(), "deny must not ask");
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn ask_rule_approved_allows() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "write_file", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert_eq!(
            approver.calls(),
            vec![ApprovalRequest {
                agent: "main".to_string(),
                tool: "write_file".to_string(),
                risk: Risk::Medium,
                arguments: serde_json::Value::Null,
                tainted: false,
                taint_source: None,
                unsandboxed: false,
                networked: false,
            }]
        );
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn ask_rule_denied_denies() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "write_file", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed());
        assert_eq!(approver.calls().len(), 1);
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn failing_approver_fails_closed() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Fail);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "approver failure must deny");
        assert!(auth.reason().contains("fail closed"), "{}", auth.reason());
        assert_eq!(sink.count("tool.decision"), 1);
    }

    #[tokio::test]
    async fn last_match_wins_deny_after_allow() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Allow),
                Rule::new("main", "shell", Action::Deny),
            ],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "the later deny rule wins");
        assert!(approver.calls().is_empty());
    }

    #[tokio::test]
    async fn last_match_wins_allow_after_deny() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Deny),
                Rule::new("main", "shell", Action::Allow),
            ],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "the later allow rule wins");
        assert!(approver.calls().is_empty());
    }

    #[tokio::test]
    async fn wildcard_rule_matches_any_tool_and_agent() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new(ANY, ANY, Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );

        let first = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        let second = broker
            .authorize(request(
                "work",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!first.is_allowed());
        assert!(!second.is_allowed());
        assert!(approver.calls().is_empty());
        assert_eq!(sink.count("tool.decision"), 2);
    }

    #[tokio::test]
    async fn rules_are_scoped_per_agent() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Allow),
                Rule::new("work", "shell", Action::Deny),
            ],
            approver.clone(),
            no_skill_only(),
        );

        assert!(broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null
            ))
            .await
            .unwrap()
            .is_allowed());
        assert!(!broker
            .authorize(request(
                "work",
                "shell",
                Risk::High,
                serde_json::Value::Null
            ))
            .await
            .unwrap()
            .is_allowed());
        assert_eq!(sink.count("tool.decision"), 2);
    }

    #[tokio::test]
    async fn no_matching_rule_asks_by_default() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed());
        assert_eq!(
            approver.calls(),
            vec![ApprovalRequest {
                agent: "main".to_string(),
                tool: "shell".to_string(),
                risk: Risk::High,
                arguments: serde_json::Value::Null,
                tainted: false,
                taint_source: None,
                unsandboxed: false,
                networked: false,
            }]
        );
    }

    #[tokio::test]
    async fn no_matching_rule_can_be_approved() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert_eq!(approver.calls().len(), 1);
    }

    #[tokio::test]
    async fn every_decision_is_audited_once() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", ANY, Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );

        broker
            .authorize(request(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        broker
            .authorize(request(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        // An agent with no matching rule still goes through the default ask.
        broker
            .authorize(request(
                "work",
                "shell",
                Risk::High,
                serde_json::Value::Null,
            ))
            .await
            .unwrap();

        assert_eq!(sink.count("tool.decision"), 3);
    }

    #[test]
    fn rule_matching_supports_wildcards() {
        let specific = Rule::new("main", "shell", Action::Allow);
        assert!(specific.matches("main", "shell"));
        assert!(!specific.matches("main", "read_file"));
        assert!(!specific.matches("work", "shell"));

        let any_tool = Rule::new("main", ANY, Action::Deny);
        assert!(any_tool.matches("main", "shell"));
        assert!(any_tool.matches("main", "read_file"));
        assert!(!any_tool.matches("work", "shell"));

        let any_agent = Rule::new(ANY, "shell", Action::Ask);
        assert!(any_agent.matches("main", "shell"));
        assert!(any_agent.matches("work", "shell"));
        assert!(!any_agent.matches("main", "read_file"));

        let catch_all = Rule::new(ANY, ANY, Action::Deny);
        assert!(catch_all.matches("main", "shell"));
        assert!(catch_all.matches("work", "read_file"));
    }

    #[test]
    fn action_labels_are_lowercase() {
        assert_eq!(Action::Allow.as_str(), "allow");
        assert_eq!(Action::Ask.to_string(), "ask");
        assert_eq!(
            serde_json::to_value(Action::Deny).unwrap(),
            serde_json::json!("deny")
        );
    }

    #[test]
    fn rules_accessor_keeps_order() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", ANY, Action::Allow),
                Rule::new(ANY, "shell", Action::Deny),
            ],
            approver,
            no_skill_only(),
        );

        assert_eq!(broker.rules().len(), 2);
        assert_eq!(broker.rules()[0].tool, ANY);
        assert_eq!(broker.rules()[1].action, Action::Deny);
    }

    fn tainted() -> Taint {
        Taint::Tainted(TaintSource::new(
            "http_fetch",
            Some("https://evil.example/page".to_string()),
        ))
    }

    #[tokio::test]
    async fn a_read_only_tool_with_no_rule_is_allowed_and_audited() {
        // H-02 (calibration): the no-rule default for a declared read-only
        // tool is allow — audit-logged, no approval card. The old default
        // (every unmatched call asks) made every read a prompt.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "a read-only default must not ask");
        assert!(
            auth.reason().contains("read-only tool, default allow"),
            "reason: {}",
            auth.reason()
        );
        assert!(
            approver.calls().is_empty(),
            "a read-only default must not raise a card"
        );
        assert_eq!(
            sink.count("tool.decision"),
            1,
            "the allowance is audit-logged"
        );
    }

    #[tokio::test]
    async fn a_read_only_default_never_beats_a_deny_or_explicit_ask_rule() {
        // H-02: the default only fills the **no match** case. A deny rule
        // still wins (non-negotiable #4), and an explicit `ask` rule on a
        // read-only tool still asks.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "read_file", Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );
        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(!auth.is_allowed(), "deny still wins over the read default");
        assert!(approver.calls().is_empty(), "deny never asks");

        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "read_file", Action::Ask)],
            approver.clone(),
            no_skill_only(),
        );
        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(auth.is_allowed());
        assert_eq!(approver.calls().len(), 1, "an explicit ask still asks");
    }

    #[tokio::test]
    async fn a_non_read_only_tool_with_no_rule_still_asks_and_a_tainted_read_still_asks() {
        // H-02: everything that is not a declared read-only tool behaves
        // exactly as before. And a tainted conversation forces the read-only
        // tool to ask too (taint is never weakened by the new default).
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(!auth.is_allowed(), "a consequential default still asks");
        assert_eq!(approver.calls().len(), 1);

        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &tainted(),
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(!auth.is_allowed(), "a tainted read still asks");
        let calls = approver.calls();
        assert_eq!(calls.len(), 2, "the tainted read raised a card");
        assert!(calls[1].tainted);
        assert!(
            calls[1]
                .taint_source
                .as_deref()
                .unwrap()
                .contains("http_fetch"),
            "the card names the source: {:?}",
            calls[1].taint_source
        );
    }

    #[tokio::test]
    async fn a_read_only_default_is_not_an_exemption_for_an_unsandboxed_call() {
        // H-02: the unsandboxed bar is independent and still wins: a
        // read-only call that will escape its sandbox is raised to ask.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "read_only_shellish",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Unsandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(!auth.is_allowed(), "an unsandboxed read must still ask");
        let calls = approver.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].unsandboxed);
    }

    #[tokio::test]
    async fn a_tainted_turn_forces_ask_for_a_declared_read_only_tool_with_no_rule() {
        // H-02 invariant: the read-only no-rule default is strictly for clean
        // turns. Taint is a one-way ratchet: once untrusted content is in the
        // conversation, a declared read-only tool with no matching rule still
        // raises a card (the default requires `!tainted`). The engine must not
        // seed an allow rule for read-only tools, or this guard is dead.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &tainted(),
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "a tainted read must ask");
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the tainted read raised a card");
        assert!(calls[0].tainted);
        assert!(
            calls[0]
                .taint_source
                .as_deref()
                .unwrap()
                .contains("http_fetch"),
            "the card names the taint source"
        );
    }

    #[tokio::test]
    async fn http_fetch_is_never_auto_allowed() {
        // WEB-01: `http_fetch` is egress, not a local read, so the registry
        // never declares it read-only and the H-02 read default cannot fire
        // for it. With no rule it asks like any other effectful tool, clean
        // or tainted; it is never silently auto-run.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(sink.clone(), vec![], approver.clone(), no_skill_only());

        let auth = broker
            .authorize(request_with(
                "main",
                "http_fetch",
                Risk::Medium,
                serde_json::Value::Null,
                &Taint::Clean, // The registry does not mark `http_fetch` read-only (tested in
                // `registry::tests::only_explicitly_declared_read_only_tools_are_exempt`).
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(
            !auth.is_allowed(),
            "an unknown fetch must ask, never auto-run"
        );
        assert_eq!(approver.calls().len(), 1);
    }

    #[tokio::test]
    async fn tainted_conversation_forces_ask_over_an_allow_rule() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Allow),
                Rule::new("main", "read_file", Action::Allow),
            ],
            approver.clone(),
            no_skill_only(),
        );

        // The allow rule is ignored: the human is asked.
        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &tainted(),
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "an approved call may still run");
        assert!(
            auth.reason().contains("tainted"),
            "reason: {}",
            auth.reason()
        );
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the allow rule must not skip the ask");
        assert!(calls[0].tainted);
        assert_eq!(
            calls[0].taint_source.as_deref(),
            Some("http_fetch: https://evil.example/page")
        );
        assert_eq!(sink.count("tool.decision"), 1);

        // A declared read-only tool keeps its configured rule: no ask for a
        // low-risk allow even while tainted.
        let auth = broker
            .authorize(request_with(
                "main",
                "read_file",
                Risk::Low,
                serde_json::Value::Null,
                &tainted(),
                true,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(auth.is_allowed());
        assert_eq!(approver.calls().len(), 1, "reads stay as configured");
    }

    #[tokio::test]
    async fn a_low_risk_side_effect_tool_is_not_exempt_from_the_taint_raise() {
        // `Risk` is informational: a side-effecting tool that self-reports
        // `low` must still ask while tainted. Only the explicit read-only
        // marker exempts a call.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "side_effect_writer", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "side_effect_writer",
                Risk::Low,
                serde_json::Value::Null,
                &tainted(),
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed(), "an approved call may still run");
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "a low-risk side effect must not slip past");
        assert!(calls[0].tainted);
    }

    #[tokio::test]
    async fn a_deny_rule_still_wins_and_unknown_state_fails_closed() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![
                Rule::new("main", "shell", Action::Deny),
                Rule::new("main", "write_file", Action::Allow),
            ],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &tainted(),
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(!auth.is_allowed(), "deny still wins");
        assert!(approver.calls().is_empty(), "deny never asks");

        // Unknown provenance acts like taint: the allow is raised to ask.
        let auth = broker
            .authorize(request_with(
                "main",
                "write_file",
                Risk::Medium,
                serde_json::Value::Null,
                &Taint::Unknown,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();
        assert!(auth.is_allowed());
        let calls = approver.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].tainted);
        assert!(calls[0]
            .taint_source
            .as_deref()
            .unwrap()
            .contains("fail closed"));
    }

    #[tokio::test]
    async fn an_unsandboxed_call_forces_ask_over_an_allow_rule() {
        // The first call in a clean workspace, no taint involved: the mode
        // alone must raise the allow rule to an ask and mark the request.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Unsandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "the denied ask must not run");
        assert!(
            auth.reason().contains("unsandboxed"),
            "reason: {}",
            auth.reason()
        );
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the allow rule must not skip the ask");
        assert!(calls[0].unsandboxed, "the card must say it is unsandboxed");
        assert!(!calls[0].tainted);
    }

    #[tokio::test]
    async fn a_networked_call_forces_ask_over_an_allow_rule() {
        // SHELL-NETWORK-ASK: `[shell] network = true` leaves every socket
        // open. A stored allow rule must not auto-run the command: the first
        // call asks, the card names the network, and a deny means nothing runs.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Networked,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "the denied ask must not run");
        assert!(
            auth.reason().contains("network"),
            "reason: {}",
            auth.reason()
        );
        let calls = approver.calls();
        assert_eq!(calls.len(), 1, "the allow rule must not skip the ask");
        assert!(calls[0].networked, "the card must say the network is on");
        assert!(!calls[0].unsandboxed, "the filesystem sandbox is still on");
        assert!(!calls[0].tainted);
        let payloads = sink.payloads("tool.decision");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["mode"], "networked", "{}", payloads[0]);
    }

    #[tokio::test]
    async fn an_unsandboxed_read_only_tool_is_not_exempted() {
        // The read-only declaration exempts a call from the taint raise only;
        // it says nothing about the sandbox escape hatch.
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "read_only_shellish", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "read_only_shellish",
                Risk::Low,
                serde_json::Value::Null,
                &Taint::Clean,
                true,
                ExecutionMode::Unsandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "an unsandboxed read must still ask");
        assert_eq!(approver.calls().len(), 1);
    }

    #[tokio::test]
    async fn a_deny_rule_still_wins_for_an_unsandboxed_call() {
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Approve);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Deny)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Unsandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(!auth.is_allowed(), "deny still wins");
        assert!(approver.calls().is_empty(), "deny never asks");
    }

    #[tokio::test]
    async fn a_sandboxed_call_keeps_its_allow_rule() {
        // No over-asking: with the mode explicitly sandboxed, a clean
        // conversation and an allow rule run without an approver call (the
        // behaviour before the unsandboxed bar existed).
        let sink = sink();
        let approver = ScriptedApprover::new(Outcome::Deny);
        let broker = Broker::new(
            sink.clone(),
            vec![Rule::new("main", "shell", Action::Allow)],
            approver.clone(),
            no_skill_only(),
        );

        let auth = broker
            .authorize(request_with(
                "main",
                "shell",
                Risk::High,
                serde_json::Value::Null,
                &Taint::Clean,
                false,
                ExecutionMode::Sandboxed,
                false,
                false,
                None,
            ))
            .await
            .unwrap();

        assert!(auth.is_allowed());
        assert!(
            approver.calls().is_empty(),
            "a sandboxed allow must not ask"
        );
        assert_eq!(sink.count("tool.decision"), 1);
    }
}
