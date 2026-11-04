//! The typed-fill tool.
//!
//! When a skill runs, the model is offered exactly one tool, `skill__<name>`,
//! whose arguments are `{ slots, calls }`. This module builds that tool's JSON
//! schema and validates a fill **before** the broker: slot values are
//! type-checked, each call's `arguments` are checked against the tool's schema,
//! every `⟦…⟧` token must come from a slot, and recipient fields must equal an
//! `email` slot. `calls` must be exactly the skill's declared calls, each once,
//! in any order (they run in declared order). A call naming a tool outside the
//! skill's effective tools is rejected with `skill.rejected_tool`; the other
//! violations write `skill.rejected_fill`. Either way the run stops.

use std::fmt;

use chrono::{DateTime, Local, NaiveDateTime, NaiveTime};
use kernel_broker::AuditSink;
use serde_json::{json, Map, Value};

use super::skill::{LoadedSkill, ValueType};
use super::tool_map;

/// Prefix of the one tool a skill offers the model.
pub const SKILL_TOOL_PREFIX: &str = "skill__";

/// The tool name the runtime forces for a skill (`skill__<name>`).
pub fn skill_tool_name(name: &str) -> String {
    format!("{SKILL_TOOL_PREFIX}{name}")
}

/// The skill name inside a `skill__<name>` tool, when the name has the prefix.
pub fn is_skill_tool(name: &str) -> Option<&str> {
    name.strip_prefix(SKILL_TOOL_PREFIX)
}

/// The wire names of a skill's effective tools, in order.
pub fn wire_tools(skill: &LoadedSkill) -> Vec<String> {
    skill
        .effective_tools
        .iter()
        .filter_map(|tool| tool_map::lookup(tool).map(|info| info.wire))
        .collect()
}

/// What each of the skill's tools takes as `arguments`, written out for the
/// model: its argument names and types, the same schema the validator enforces.
fn arguments_help(skill: &LoadedSkill) -> String {
    if skill.body.contains(crate::executor::DRAFT_MARKER) {
        return "Arguments: leave `mail_send` as an empty object; Auxesis fills the \
                stored draft itself."
            .to_string();
    }
    let parts: Vec<String> = skill
        .effective_tools
        .iter()
        .filter_map(|tool| {
            let info = tool_map::lookup(tool)?;
            let schema = tool_map::arguments_schema(&info.logical)?;
            Some(format!("{} takes {}", info.wire, schema))
        })
        .collect();
    if parts.is_empty() {
        "the tool's arguments as a JSON object".to_string()
    } else {
        format!("Arguments, by tool: {}.", parts.join("; "))
    }
}

/// The JSON schema of `skill__<name>`.
pub fn tool_schema(skill: &LoadedSkill) -> Value {
    // A `from: contact(<slot>)` input derives its value from that slot, so the
    // slot must read as a contact name to the model — never an address.
    let contact_slots: Vec<&str> = skill
        .inputs
        .iter()
        .filter_map(|input| input.from.as_deref())
        .collect();
    let mut slot_properties = Map::new();
    let mut slot_required = Vec::new();
    for input in &skill.inputs {
        // A derived slot is never the model's to fill (`docs/phase1.md` §7):
        // the runtime resolves it from its contact source after the fill.
        if input.from.is_some() {
            continue;
        }
        let schema = if contact_slots.contains(&input.name.as_str()) {
            contact_slot_schema(input.value_type)
        } else {
            slot_schema(input.value_type)
        };
        slot_properties.insert(input.name.clone(), schema);
        if input.default.is_none() {
            slot_required.push(Value::String(input.name.clone()));
        }
    }
    let wires = wire_tools(skill);
    // A skill whose one derived input is the contact address owns every
    // recipient field, so the model is told it may leave them out
    // (`docs/phase1.md` §7).
    let derived_note = if recipients_are_runtime_owned(skill) {
        " Recipient addresses are filled by Auxesis from the owner's contacts; leave recipient fields empty."
    } else {
        ""
    };
    // Position `i` of `calls` must be the skill's `i`-th declared tool.
    let pinned: Vec<Value> = wires
        .iter()
        .map(|wire| json!({ "properties": { "tool": { "const": wire } }, "required": ["tool"] }))
        .collect();
    json!({
        "type": "object",
        "properties": {
            "slots": {
                "type": "object",
                "properties": slot_properties,
                "required": slot_required,
                "additionalProperties": false
            },
            "calls": {
                "type": "array",
                "description": format!(
                    "Exactly these calls, each once, in this order: {}.{derived_note}",
                    wires.join(", ")
                ),
                "minItems": wires.len(),
                "maxItems": wires.len(),
                "prefixItems": pinned,
                "items": {
                    "type": "object",
                    "properties": {
                        "tool": { "type": "string", "enum": wires },
                        "arguments": { "type": "object", "description": arguments_help(skill) }
                    },
                    "required": ["tool", "arguments"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["slots", "calls"],
        "additionalProperties": false
    })
}

/// The advertised JSON schema for one slot.
fn slot_schema(value_type: ValueType) -> Value {
    match value_type {
        ValueType::String => json!({ "type": "string" }),
        ValueType::Email => json!({
            "type": "string",
            "format": "email",
            "description": "a valid address or a single ⟦EMAIL_…⟧ token"
        }),
        ValueType::DateTime => json!({
            "type": "string",
            "format": "date-time",
            "description": "local time (2026-10-26T10:00:00), RFC 3339, or `tomorrow HH:MM`"
        }),
        ValueType::Duration => json!({
            "type": "string",
            "format": "duration",
            "description": "ISO 8601 (e.g. PT30M) or `30m` / `1h`"
        }),
    }
}

/// The advertised schema for a slot a derived contact input reads.
///
/// The model copies the contact's name from the owner's message; the runtime
/// resolves the address itself, so the slot must read as a name and never as an
/// address or a token.
fn contact_slot_schema(value_type: ValueType) -> Value {
    let mut schema = slot_schema(value_type);
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "description".to_string(),
            json!(
                "the contact's name exactly as it appears in the owner's message; \
                 never an email address (Auxesis resolves the address from the \
                 owner's contacts)"
            ),
        );
    }
    schema
}

/// Supplies a pinned JSON schema for a tool's `arguments`.
///
/// Phase 0 supplies none, so an `mcp.*` tool in a skill is refused at fill
/// time. The executor can pass a real source later.
pub trait ToolSchemaSource {
    /// The tool's `arguments` schema, when one is pinned.
    fn arguments_schema(&self, logical: &str) -> Option<Value>;
}

/// Who is running the skill, for the Ledger rows.
#[derive(Clone, Copy)]
pub struct RunContext<'a> {
    /// Agent the run belongs to.
    pub agent: &'a str,
    /// Run identifier shared by the run's Ledger rows.
    pub run_id: &'a str,
    /// Pinned per-tool argument schemas. `None` in Phase 0.
    pub schemas: Option<&'a dyn ToolSchemaSource>,
    /// Raw owner message for this turn, retained locally to bind model-filled
    /// contact slots to names the owner actually supplied.
    pub owner_input: Option<&'a str>,
}

/// One validated tool call, still in wire form and still tokenised.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedCall {
    /// Wire name the provider used.
    pub tool: String,
    /// Canonical logical name.
    pub logical: String,
    /// Arguments as the model filled them (tokens only).
    pub arguments: Value,
}

/// A fill that passed validation.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedFill {
    /// Slot values in declared order, defaults filled and type-checked.
    pub slots: Vec<(String, String)>,
    /// Ordered, non-empty calls.
    pub calls: Vec<ValidatedCall>,
}

/// Why a fill was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillError {
    /// The model returned free text instead of `{ slots, calls }`.
    NotFilled,
    /// A declared slot without a default was omitted.
    MissingSlot(String),
    /// The fill carried a slot the skill does not declare.
    UnknownSlot(String),
    /// The fill carried a slot the runtime derives from a contact
    /// (`docs/phase1.md` §7). The model must never fill it.
    DerivedSlot(String),
    /// The `slots` object was malformed.
    BadSlots(String),
    /// A slot value did not match its declared type.
    BadSlotValue {
        /// Slot name.
        slot: String,
        /// Why the value was rejected.
        reason: String,
    },
    /// A call was malformed.
    BadCall(String),
    /// `calls` was empty.
    EmptyCalls,
    /// A call named a tool outside the skill's effective tools.
    RejectedTool(String),
    /// `calls` was not exactly the skill's declared calls, each once.
    WrongCalls {
        /// Skill name.
        skill: String,
        /// Wire names of the declared calls, in declared order.
        expected: Vec<String>,
    },
    /// A call's arguments did not match the tool's schema.
    BadArguments {
        /// Wire tool name.
        tool: String,
        /// Why the arguments were rejected.
        reason: String,
    },
    /// A `⟦…⟧` token in the arguments did not come from a slot value.
    TokenNotInSlots {
        /// Wire tool name.
        tool: String,
        /// The token that was not found.
        token: String,
    },
    /// A recipient field did not equal an `email`-typed slot value.
    RecipientNotFromSlot {
        /// Wire tool name.
        tool: String,
        /// Field that failed, e.g. `to` or `attendees[0].email`.
        field: String,
    },
}

impl fmt::Display for FillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FillError::NotFilled => write!(f, "model did not fill the skill"),
            FillError::MissingSlot(name) => write!(f, "missing slot `{name}`"),
            FillError::UnknownSlot(name) => write!(f, "unknown slot `{name}`"),
            FillError::DerivedSlot(_) => write!(f, "derived slot"),
            FillError::BadSlots(reason) => write!(f, "invalid slots: {reason}"),
            FillError::BadSlotValue { slot, reason } => {
                write!(f, "slot `{slot}`: {reason}")
            }
            FillError::BadCall(reason) => write!(f, "invalid call: {reason}"),
            FillError::EmptyCalls => write!(f, "calls must not be empty"),
            FillError::RejectedTool(tool) => {
                write!(f, "tool `{tool}` is not in the skill's tools")
            }
            FillError::WrongCalls { skill, expected } => write!(
                f,
                "{skill} needs exactly these calls: {}",
                expected.join(", ")
            ),
            FillError::BadArguments { tool, reason } => {
                write!(f, "arguments for `{tool}`: {reason}")
            }
            FillError::TokenNotInSlots { token, .. } => {
                write!(f, "token `{token}` does not appear in any slot")
            }
            FillError::RecipientNotFromSlot { tool, field } => {
                write!(f, "`{field}` on `{tool}` must equal an email slot")
            }
        }
    }
}

impl std::error::Error for FillError {}

/// Validate a `skill__<name>` fill against the skill, before the broker.
///
/// Every rejection writes exactly one Ledger row: `skill.rejected_tool` for a
/// tool outside the skill's effective tools, `skill.rejected_fill` for every
/// other class.
pub fn validate_fill(
    skill: &LoadedSkill,
    value: &Value,
    context: &RunContext<'_>,
    sink: Option<&dyn AuditSink>,
) -> Result<ValidatedFill, FillError> {
    match validate_fill_inner(skill, value, context) {
        Ok(fill) => Ok(fill),
        Err(err) => {
            if let FillError::RejectedTool(tool) = &err {
                log_rejected_tool(sink, skill, context, tool);
            } else {
                log_rejected_fill(sink, skill, context, error_tool(&err), &err.to_string());
            }
            Err(err)
        }
    }
}

/// The tool named by a rejection, when it carries one.
fn error_tool(err: &FillError) -> Option<&str> {
    match err {
        FillError::RejectedTool(tool) => Some(tool),
        FillError::BadArguments { tool, .. } => Some(tool),
        FillError::TokenNotInSlots { tool, .. } => Some(tool),
        FillError::RecipientNotFromSlot { tool, .. } => Some(tool),
        _ => None,
    }
}

fn validate_fill_inner(
    skill: &LoadedSkill,
    value: &Value,
    context: &RunContext<'_>,
) -> Result<ValidatedFill, FillError> {
    let object = value.as_object().ok_or(FillError::NotFilled)?;
    let slots = object.get("slots").ok_or(FillError::NotFilled)?;
    let calls = object.get("calls").ok_or(FillError::NotFilled)?;

    let slots = slots
        .as_object()
        .ok_or_else(|| FillError::BadSlots("`slots` must be an object".to_string()))?;

    // A skill with exactly one derived contact owns every recipient field of
    // every call; with several it cannot know which address goes where, so the
    // fill-time rule stays.
    let runtime_owned = recipients_are_runtime_owned(skill);

    // The model's own slots. A derived input is skipped here: the runtime fills
    // it from the contact source after the fill (`docs/phase1.md` §7).
    let mut slot_values: Vec<(String, String)> = Vec::new();
    for input in &skill.inputs {
        if input.from.is_some() {
            continue;
        }
        let raw = match slots.get(&input.name) {
            Some(Value::String(text)) => text.clone(),
            Some(_) => {
                return Err(FillError::BadSlotValue {
                    slot: input.name.clone(),
                    reason: "must be a string".to_string(),
                });
            }
            None => match &input.default {
                Some(default) => default.clone(),
                None => return Err(FillError::MissingSlot(input.name.clone())),
            },
        };
        let canonical = validate_slot_value(input.value_type, &raw).map_err(|reason| {
            FillError::BadSlotValue {
                slot: input.name.clone(),
                reason,
            }
        })?;
        slot_values.push((input.name.clone(), canonical));
    }
    // A model-supplied derived slot is rejected before an unknown one: it has a
    // name the skill declares, but the model must never fill it.
    for name in slots.keys() {
        if skill
            .inputs
            .iter()
            .any(|input| input.from.is_some() && &input.name == name)
        {
            return Err(FillError::DerivedSlot(name.clone()));
        }
    }
    for name in slots.keys() {
        if !skill.inputs.iter().any(|input| &input.name == name) {
            return Err(FillError::UnknownSlot(name.clone()));
        }
    }
    // A derived slot's value is its source slot's value. A call references the
    // derived slot through it; the executor replaces it with the contact's
    // address before the card. Kept in declared order.
    let mut validated_slots = Vec::new();
    for input in &skill.inputs {
        let source = input.from.as_deref().unwrap_or(&input.name);
        let value = slot_values
            .iter()
            .find(|(name, _)| name == source)
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        validated_slots.push((input.name.clone(), value));
    }

    // The one derived slot's fill-time value stands in for a required
    // recipient the model left out, so the tool schema sees the key; the
    // executor overwrites it with the resolved address (`docs/phase1.md` §7).
    let runtime_recipient: Option<&str> = if runtime_owned {
        skill
            .inputs
            .iter()
            .find(|input| input.from.is_some())
            .and_then(|input| {
                validated_slots
                    .iter()
                    .find(|(name, _)| name == &input.name)
                    .map(|(_, value)| value.as_str())
            })
    } else {
        None
    };

    let calls = calls
        .as_array()
        .ok_or_else(|| FillError::BadCall("`calls` must be an array".to_string()))?;
    if calls.is_empty() {
        return Err(FillError::EmptyCalls);
    }

    let allowed: Vec<(String, String)> = skill
        .effective_tools
        .iter()
        .filter_map(|tool| tool_map::lookup(tool).map(|info| (info.wire, info.logical)))
        .collect();

    let email_slots: Vec<String> = skill
        .inputs
        .iter()
        .filter(|input| input.value_type == ValueType::Email)
        .filter_map(|input| {
            validated_slots
                .iter()
                .find(|(name, _)| name == &input.name)
                .map(|(_, value)| value.clone())
        })
        .collect();

    let declared = wire_tools(skill);
    let mut validated_calls = Vec::new();
    for call in calls {
        let call = call
            .as_object()
            .ok_or_else(|| FillError::BadCall("each call must be an object".to_string()))?;
        let tool = call
            .get("tool")
            .and_then(Value::as_str)
            .ok_or_else(|| FillError::BadCall("call.tool must be a string".to_string()))?;
        let arguments = call
            .get("arguments")
            .cloned()
            .ok_or_else(|| FillError::BadCall("call.arguments is required".to_string()))?;
        if !arguments.is_object() {
            return Err(FillError::BadCall(
                "call.arguments must be an object".to_string(),
            ));
        }
        let Some((_, logical)) = allowed.iter().find(|(wire, _)| wire == tool) else {
            return Err(FillError::RejectedTool(tool.to_string()));
        };

        // A pinned schema is required: the Google tools have a built-in one,
        // and an `mcp.*` tool needs the runtime to supply one. Phase 0 supplies
        // none, so an `mcp.*` call is refused here.
        let schema = context
            .schemas
            .and_then(|source| source.arguments_schema(logical))
            .or_else(|| tool_map::arguments_schema(logical));
        let Some(schema) = schema else {
            return Err(FillError::BadArguments {
                tool: tool.to_string(),
                reason: format!("no pinned JSON schema for `{logical}`"),
            });
        };
        // The runtime owns every recipient field, so a required recipient the
        // model omitted is supplied here for the schema check only; the
        // executor inserts the resolved address (`docs/phase1.md` §7).
        // A `send-draft` call is empty on purpose: the runtime loads the
        // stored draft before the card. The schema check sees placeholders for
        // the three required fields only; the call itself stays empty.
        let draft_placeholder;
        let placeholder;
        let checked_arguments =
            if skill.body.contains(crate::executor::DRAFT_MARKER) && logical == "mail.send" {
                draft_placeholder = with_draft_placeholder(&arguments);
                &draft_placeholder
            } else {
                match runtime_recipient {
                    Some(value) => {
                        placeholder = with_runtime_recipient(logical, &arguments, value);
                        &placeholder
                    }
                    None => &arguments,
                }
            };
        if let Err(reason) = validate_arguments(checked_arguments, &schema, "") {
            return Err(FillError::BadArguments {
                tool: tool.to_string(),
                reason,
            });
        }
        if let Err(reason) = check_control_characters(&arguments, None) {
            return Err(FillError::BadArguments {
                tool: tool.to_string(),
                reason,
            });
        }

        let mut tokens = Vec::new();
        collect_tokens(&arguments, &mut tokens);
        for token in tokens {
            if !validated_slots
                .iter()
                .any(|(_, slot_value)| slot_value.contains(&token))
            {
                return Err(FillError::TokenNotInSlots {
                    tool: tool.to_string(),
                    token,
                });
            }
        }

        if !runtime_owned {
            // With several derived inputs (or none) the fill-time rule stays:
            // a recipient field must carry an email slot's value.
            for (field, recipient) in recipient_fields(logical, &arguments) {
                if !email_slots.contains(&recipient) {
                    return Err(FillError::RecipientNotFromSlot {
                        tool: tool.to_string(),
                        field,
                    });
                }
            }
        }

        validated_calls.push(ValidatedCall {
            tool: tool.to_string(),
            logical: logical.clone(),
            arguments,
        });
    }

    // The declared calls, each exactly once. Checked after the per-call rules, so
    // a tool outside the skill keeps its own refusal.
    let mut provided: Vec<&str> = validated_calls
        .iter()
        .map(|call| call.tool.as_str())
        .collect();
    let mut expected: Vec<&str> = declared.iter().map(String::as_str).collect();
    provided.sort_unstable();
    expected.sort_unstable();
    if provided != expected {
        return Err(FillError::WrongCalls {
            skill: skill.name.clone(),
            expected: declared,
        });
    }
    validated_calls.sort_by_key(|call| declared.iter().position(|wire| *wire == call.tool));

    Ok(ValidatedFill {
        slots: validated_slots,
        calls: validated_calls,
    })
}

/// Type-check and canonicalise one slot value.
fn validate_slot_value(value_type: ValueType, raw: &str) -> Result<String, String> {
    match value_type {
        ValueType::String => Ok(raw.to_string()),
        ValueType::Email => {
            if is_token(raw, "EMAIL") {
                return Ok(raw.to_string());
            }
            if is_email_address(raw) {
                return Ok(raw.to_string());
            }
            Err("must be a valid address or a single ⟦EMAIL_…⟧ token".to_string())
        }
        ValueType::DateTime => validate_datetime(raw),
        ValueType::Duration => {
            if is_iso8601_duration(raw) || is_short_duration(raw) {
                Ok(raw.to_string())
            } else {
                Err("must be ISO 8601 (e.g. PT30M) or `30m` / `1h`".to_string())
            }
        }
    }
}

/// A `⟦[A-Z]+_[A-Z0-9_]+⟧` token of the requested kind.
fn is_token(value: &str, kind: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('⟦')
        .and_then(|rest| rest.strip_suffix('⟧'))
    else {
        return false;
    };
    let Some((prefix, suffix)) = inner.split_once('_') else {
        return false;
    };
    prefix == kind
        && !prefix.is_empty()
        && prefix.chars().all(|ch| ch.is_ascii_uppercase())
        && !suffix.is_empty()
        && suffix
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

/// A pragmatic address check: one `@`, non-empty local and dotted domain.
fn is_email_address(value: &str) -> bool {
    if value.is_empty() || value.contains(char::is_whitespace) {
        return false;
    }
    if value.contains('⟦') || value.contains('⟧') {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty() || local.contains('@') || domain.contains('@') {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    })
}

/// RFC 3339, a wall time, or `today HH:MM` / `tomorrow HH:MM` (dated here, zoned by the event).
fn validate_datetime(value: &str) -> Result<String, String> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(parsed.to_rfc3339());
    }
    // A wall time stays a wall time: its zone is known only to the event it
    // lands in, which reads it there and refuses a skipped or repeated hour
    // (`event_time`). Reading it in the system zone here refused valid times
    // in another zone and gave the model an offset that zone does not have.
    if let Ok(naive) = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S") {
        return Ok(naive.format("%Y-%m-%dT%H:%M:%S").to_string());
    }
    let mut parts = value.split_whitespace();
    let day = parts.next().unwrap_or_default();
    let time = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err("must be RFC 3339 or `today HH:MM` / `tomorrow HH:MM`".to_string());
    }
    let offset_days = match day {
        "today" => 0,
        "tomorrow" => 1,
        _ => return Err("must be RFC 3339 or `today HH:MM` / `tomorrow HH:MM`".to_string()),
    };
    let time = NaiveTime::parse_from_str(time, "%H:%M")
        .or_else(|_| NaiveTime::parse_from_str(time, "%H:%M:%S"))
        .map_err(|_| "time must be HH:MM".to_string())?;
    let date = Local::now().date_naive() + chrono::Duration::days(offset_days);
    Ok(date.and_time(time).format("%Y-%m-%dT%H:%M:%S").to_string())
}

/// ISO 8601 duration, e.g. `PT30M`, `P1D`, `PT1H30M`.
fn is_iso8601_duration(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('P') else {
        return false;
    };
    let (date_part, time_part) = match rest.split_once('T') {
        Some((date, time)) => (date, Some(time)),
        None => (rest, None),
    };
    let mut any = duration_components(date_part, "YMWD");
    if let Some(time_part) = time_part {
        any |= duration_components(time_part, "HMS");
    }
    any
}

/// True when `text` is a non-empty run of `<digits><unit>` components.
fn duration_components(mut text: &str, units: &str) -> bool {
    let mut any = false;
    while !text.is_empty() {
        let digits_len = text.chars().take_while(|ch| ch.is_ascii_digit()).count();
        if digits_len == 0 {
            return false;
        }
        let (_, rest) = text.split_at(digits_len);
        let Some(designator) = rest.chars().next() else {
            return false;
        };
        if !units.contains(designator) {
            return false;
        }
        text = &rest[designator.len_utf8()..];
        any = true;
    }
    any
}

/// `30m` / `1h`.
fn is_short_duration(value: &str) -> bool {
    let Some(unit) = value.chars().last() else {
        return false;
    };
    if unit != 'm' && unit != 'h' {
        return false;
    }
    let digits = &value[..value.len() - unit.len_utf8()];
    !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
}

/// Validate `arguments` against a small JSON-schema subset.
fn validate_arguments(value: &Value, schema: &Value, path: &str) -> Result<(), String> {
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => {
            let object = value
                .as_object()
                .ok_or_else(|| format!("`{path}` must be an object"))?;
            let properties = schema.get("properties").and_then(Value::as_object);
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                if let Some(properties) = properties {
                    for key in object.keys() {
                        if !properties.contains_key(key) {
                            return Err(format!("unknown argument `{path}{key}`"));
                        }
                    }
                }
            }
            if let Some(properties) = properties {
                for (key, property) in properties {
                    let child = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    match object.get(key) {
                        Some(child_value) => validate_arguments(child_value, property, &child)?,
                        None => {
                            let required = schema
                                .get("required")
                                .and_then(Value::as_array)
                                .map(|required| {
                                    required.iter().any(|name| name.as_str() == Some(key))
                                })
                                .unwrap_or(false);
                            if required {
                                return Err(format!("missing required argument `{child}`"));
                            }
                        }
                    }
                }
            }
        }
        Some("array") => {
            let items = value
                .as_array()
                .ok_or_else(|| format!("`{path}` must be an array"))?;
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate_arguments(item, item_schema, &format!("{path}[{index}]"))?;
                }
            }
        }
        Some("string") => {
            let text = value
                .as_str()
                .ok_or_else(|| format!("`{path}` must be a string"))?;
            // A call's date-time is RFC 3339 (the connector takes no other form).
            // Slots keep their own rule in `validate_datetime`.
            if schema.get("format").and_then(Value::as_str) == Some("date-time")
                && DateTime::parse_from_rfc3339(text).is_err()
            {
                return Err(format!(
                    "`{path}` must be an RFC 3339 date-time, such as 2026-10-11T10:00:00+02:00"
                ));
            }
        }
        Some("integer") => {
            value
                .as_i64()
                .ok_or_else(|| format!("`{path}` must be an integer"))?;
        }
        Some("number") => {
            value
                .as_f64()
                .ok_or_else(|| format!("`{path}` must be a number"))?;
        }
        Some("boolean") => {
            value
                .as_bool()
                .ok_or_else(|| format!("`{path}` must be a boolean"))?;
        }
        _ => {}
    }
    Ok(())
}

/// Reject header-injection controls in string arguments.
///
/// Header-like fields (`to`/`cc`/`bcc`/`subject`, calendar `summary`/
/// `location`, `attendees[].email`) reject every C0 control except TAB. The
/// body-like fields `body` and `description` allow `\n` and TAB but still
/// reject NUL and the other C0 controls.
fn check_control_characters(value: &Value, key: Option<&str>) -> Result<(), String> {
    match value {
        Value::String(text) => {
            let allow_newline = key.is_some_and(|key| matches!(key, "body" | "description"));
            if let Some(ch) = text.chars().find(|ch| {
                let code = *ch as u32;
                if allow_newline {
                    code < 0x20 && *ch != '\t' && *ch != '\n'
                } else {
                    // Header fields also refuse C1 controls and the Unicode
                    // line and paragraph separators, as the Gmail header
                    // check does (`aux-google` `validate_message`).
                    ((code < 0x20 || (0x7f..=0x9f).contains(&code)) && *ch != '\t')
                        || matches!(ch, '\u{2028}' | '\u{2029}')
                }
            }) {
                return Err(format!(
                    "`{}` contains control character U+{:04X}",
                    key.unwrap_or("argument"),
                    ch as u32
                ));
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                check_control_characters(item, key)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (name, item) in map {
                check_control_characters(item, Some(name))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The argument checks a call needs once its values are real: the tool's pinned
/// schema, the header and body control rules, and no `⟦`/`⟧` left in any string
/// or key. The executor runs it on every call after rehydration and on every
/// owner edit, so an edit gets the fill's checks.
pub fn check_arguments(logical: &str, arguments: &Value) -> Result<(), String> {
    let schema = tool_map::arguments_schema(logical)
        .ok_or_else(|| format!("no pinned JSON schema for `{logical}`"))?;
    validate_arguments(arguments, &schema, "")?;
    check_control_characters(arguments, None)?;
    if contains_delimiter(arguments) {
        return Err("a value still contains a ⟦…⟧ delimiter".to_string());
    }
    Ok(())
}

/// True when any string or key in `value` contains a token delimiter.
fn contains_delimiter(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains('⟦') || text.contains('⟧'),
        Value::Array(items) => items.iter().any(contains_delimiter),
        Value::Object(map) => map
            .iter()
            .any(|(key, item)| key.contains('⟦') || key.contains('⟧') || contains_delimiter(item)),
        _ => false,
    }
}

/// Collect every `⟦…⟧` token appearing in `value`'s strings.
fn collect_tokens(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            let mut rest = text.as_str();
            while let Some(start) = rest.find('⟦') {
                let after = &rest[start + '⟦'.len_utf8()..];
                let Some(end) = after.find('⟧') else {
                    break;
                };
                out.push(rest[start..start + '⟦'.len_utf8() + end + '⟧'.len_utf8()].to_string());
                rest = &after[end + '⟧'.len_utf8()..];
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_tokens(item, out);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_tokens(item, out);
            }
        }
        _ => {}
    }
}

/// True when the skill declares exactly one derived email input, so the runtime
/// owns every recipient field of every call (`docs/phase1.md` §7).
///
/// With two or more derived inputs the runtime cannot know which address goes
/// in which field, so the fill-time rule stays: a recipient field must carry
/// one of the source slot's values.
pub fn recipients_are_runtime_owned(skill: &LoadedSkill) -> bool {
    skill
        .inputs
        .iter()
        .filter(|input| input.from.is_some())
        .count()
        == 1
}

/// The recipient fields a tool carries, as `(field, value)` pairs.
fn recipient_fields(logical: &str, arguments: &Value) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let mut push = |name: &str, value: &Value| {
        if let Some(value) = value.as_str() {
            fields.push((name.to_string(), value.to_string()));
        }
    };
    match logical {
        "google.gmail.send" => {
            for field in ["to", "cc", "bcc"] {
                if let Some(value) = arguments.get(field) {
                    push(field, value);
                }
            }
        }
        "google.gmail.create_draft" => {
            if let Some(value) = arguments.get("to") {
                push("to", value);
            }
        }
        "google.calendar.create_event" => {
            if let Some(attendees) = arguments.get("attendees").and_then(Value::as_array) {
                for (index, attendee) in attendees.iter().enumerate() {
                    if let Some(value) = attendee.get("email") {
                        push(&format!("attendees[{index}].email"), value);
                    }
                }
            }
        }
        // MA4: the SMTP send takes arrays of addresses.
        "mail.send" => {
            for field in ["to", "cc"] {
                if let Some(values) = arguments.get(field).and_then(Value::as_array) {
                    for (index, value) in values.iter().enumerate() {
                        if let Some(value) = value.as_str() {
                            fields.push((format!("{field}[{index}]"), value.to_string()));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    fields
}

/// Rewrite the recipient fields of `arguments` that equal a derived slot's
/// fill-time value into the resolved value the executor looked up
/// (`docs/phase1.md` §7). Only recipient fields are rewritten: the same value
/// in a `summary` or `body` is the person's name and stays as it was.
pub fn substitute_derived_recipients(
    logical: &str,
    arguments: &Value,
    derived: &[(String, String)],
) -> Value {
    let mut value = arguments.clone();
    if derived.is_empty() {
        return value;
    }
    for (field, current) in recipient_fields(logical, &value) {
        let Some((_, resolved)) = derived.iter().find(|(from, _)| from == &current) else {
            continue;
        };
        set_recipient_field(&mut value, logical, &field, resolved);
    }
    value
}

/// Replace one recipient field named by [`recipient_fields`].
fn set_recipient_field(arguments: &mut Value, logical: &str, field: &str, value: &str) {
    match logical {
        "google.gmail.send" | "google.gmail.create_draft" => {
            if let Some(map) = arguments.as_object_mut() {
                if map.contains_key(field) {
                    map.insert(field.to_string(), Value::String(value.to_string()));
                }
            }
        }
        "mail.send" => {
            let Some((name, index)) = field.split_once('[') else {
                return;
            };
            let Some(index) = index
                .strip_suffix(']')
                .and_then(|index| index.parse::<usize>().ok())
            else {
                return;
            };
            if let Some(slot) = arguments
                .get_mut(name)
                .and_then(Value::as_array_mut)
                .and_then(|values| values.get_mut(index))
            {
                if slot.is_string() {
                    *slot = Value::String(value.to_string());
                }
            }
        }
        "google.calendar.create_event" => {
            let Some(rest) = field.strip_prefix("attendees[") else {
                return;
            };
            let Some((index, tail)) = rest.split_once(']') else {
                return;
            };
            if tail != ".email" {
                return;
            }
            let Ok(index) = index.parse::<usize>() else {
                return;
            };
            if let Some(attendee) = arguments
                .get_mut("attendees")
                .and_then(Value::as_array_mut)
                .and_then(|attendees| attendees.get_mut(index))
                .and_then(Value::as_object_mut)
            {
                attendee.insert("email".to_string(), Value::String(value.to_string()));
            }
        }
        _ => {}
    }
}

/// The three fields a `send-draft` call does not carry: the runtime loads them
/// from the stored draft before the card. They are here for the schema check
/// only and never become part of the validated call.
fn with_draft_placeholder(arguments: &Value) -> Value {
    let mut value = arguments.clone();
    if let Some(map) = value.as_object_mut() {
        map.insert("to".to_string(), json!(["draft@invalid.example"]));
        map.insert("subject".to_string(), json!("draft"));
        map.insert("body".to_string(), json!("draft"));
    }
    value
}

/// A copy of `arguments` with the required recipient field the runtime will
/// fill, so the tool schema's required-key check passes when the model left it
/// out (`docs/phase1.md` §7). `placeholder` is a slot value; the executor
/// overwrites the field with the resolved address before the card.
fn with_runtime_recipient(logical: &str, arguments: &Value, placeholder: &str) -> Value {
    let mut value = arguments.clone();
    if let Some(map) = value.as_object_mut() {
        if logical == "google.gmail.send" && !map.contains_key("to") {
            map.insert("to".to_string(), Value::String(placeholder.to_string()));
        }
        if logical == "mail.send" && !map.contains_key("to") {
            map.insert(
                "to".to_string(),
                Value::Array(vec![Value::String(placeholder.to_string())]),
            );
        }
    }
    value
}

/// Overwrite every recipient field of a call with the one resolved contact
/// address and insert a required recipient the model left out
/// (`docs/phase1.md` §7).
///
/// The skill derives exactly one email input, so the runtime owns the
/// recipients: whatever the model wrote in `to`/`cc`/`bcc`/`attendees[].email`
/// — the source value, a token, an invented address or an empty string — never
/// reaches the connector. A Gmail `to` the model omitted is inserted; a
/// calendar event with no `attendees` array gets exactly one attendee. The
/// per-value recipient policy runs on the overwritten values, unchanged.
pub fn overwrite_derived_recipients(logical: &str, arguments: &Value, address: &str) -> Value {
    let mut value = arguments.clone();
    if let Some(map) = value.as_object_mut() {
        match logical {
            "google.gmail.send" | "google.gmail.create_draft" => {
                for field in ["to", "cc", "bcc"] {
                    // `to` is required by `gmail.send`; a `cc`/`bcc` and a
                    // draft's `to` are overwritten only when the model carried
                    // them.
                    let required = logical == "google.gmail.send" && field == "to";
                    if map.contains_key(field) || required {
                        map.insert(field.to_string(), Value::String(address.to_string()));
                    }
                }
            }
            "google.calendar.create_event" => {
                if map.contains_key("attendees") {
                    if let Some(Value::Array(attendees)) = map.get_mut("attendees") {
                        for attendee in attendees.iter_mut() {
                            if let Some(attendee) = attendee.as_object_mut() {
                                attendee.insert(
                                    "email".to_string(),
                                    Value::String(address.to_string()),
                                );
                            }
                        }
                    }
                } else {
                    map.insert(
                        "attendees".to_string(),
                        Value::Array(vec![json!({ "email": address })]),
                    );
                }
            }
            // MA4: `mail.send` takes arrays; `to` is required, `cc` only when
            // the model carried it.
            "mail.send" => {
                map.insert(
                    "to".to_string(),
                    Value::Array(vec![Value::String(address.to_string())]),
                );
                if map.contains_key("cc") {
                    map.insert(
                        "cc".to_string(),
                        Value::Array(vec![Value::String(address.to_string())]),
                    );
                }
            }
            _ => {}
        }
    }
    value
}

fn log_rejected_tool(
    sink: Option<&dyn AuditSink>,
    skill: &LoadedSkill,
    context: &RunContext<'_>,
    tool: &str,
) {
    let Some(sink) = sink else {
        return;
    };
    let payload = json!({
        "agent": context.agent,
        "skill_name": skill.name,
        "skill_version": skill.version.to_string(),
        "skill_hash": skill.hash,
        "run_id": context.run_id,
        "tool": tool,
    });
    let _ = sink.log_event("skill.rejected_tool", &payload);
}

/// Write the one `skill.rejected_fill` row a rejection owes the Ledger
/// `reason` must carry no real value.
pub fn log_rejected_fill(
    sink: Option<&dyn AuditSink>,
    skill: &LoadedSkill,
    context: &RunContext<'_>,
    tool: Option<&str>,
    reason: &str,
) {
    let Some(sink) = sink else {
        return;
    };
    let payload = json!({
        "agent": context.agent,
        "skill_name": skill.name,
        "skill_version": skill.version.to_string(),
        "skill_hash": skill.hash,
        "run_id": context.run_id,
        "tool": tool,
        "reason": reason,
    });
    let _ = sink.log_event("skill.rejected_fill", &payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::agent::{AgentMode, AgentSource, Brain, LoadedAgent};
    use crate::skills::skill::{parse_skill, Approval};
    use crate::skills::RecipientPolicy;
    use std::path::PathBuf;

    fn agent() -> LoadedAgent {
        LoadedAgent {
            name: "assistant".to_string(),
            brain: Brain::Cloud,
            default_mode: AgentMode::Private,
            channels: Vec::new(),
            tools: vec![
                "google.calendar.create_event".to_string(),
                "google.gmail.send".to_string(),
            ],
            recipients_policy: RecipientPolicy::KnownContacts,
            recipients_allowlist: Vec::new(),
            body: String::new(),
            source: AgentSource::AgentMd,
            dir: PathBuf::from("/tmp/assistant"),
        }
    }

    fn skill() -> LoadedSkill {
        let text = b"---\nname: send-invite\nversion: 1\ntools: [google.calendar.create_event, google.gmail.send]\ninputs:\n  person: { tier: H }\n  email: { type: email }\n  when: { type: datetime }\n  duration: { type: duration, default: 30m }\napproval: each_run\n---\nBody.\n";
        parse_skill(text, "send-invite.md", "send-invite", &agent()).unwrap()
    }

    fn context() -> RunContext<'static> {
        RunContext {
            agent: "assistant",
            run_id: "run-1",
            schemas: None,
            owner_input: None,
        }
    }

    /// The same skill with `email` derived from the `person` contact.
    fn derived_skill() -> LoadedSkill {
        let text = b"---\nname: send-invite\nversion: 1\ntools: [google.calendar.create_event, google.gmail.send]\ninputs:\n  person: { tier: H }\n  email: { type: email, from: contact(person) }\n  when: { type: datetime }\n  duration: { type: duration, default: 30m }\napproval: each_run\n---\nBody.\n";
        parse_skill(text, "send-invite.md", "send-invite", &agent()).unwrap()
    }

    /// Two derived contacts: the runtime cannot know which address goes in
    /// which field, so the fill-time rule stays.
    fn two_derived_skill() -> LoadedSkill {
        let text = b"---\nname: send-invite\nversion: 1\ntools: [google.calendar.create_event, google.gmail.send]\ninputs:\n  person: { tier: H }\n  backup: { tier: H }\n  email: { type: email, from: contact(person) }\n  alt: { type: email, from: contact(backup) }\n  when: { type: datetime }\napproval: each_run\n---\nBody.\n";
        parse_skill(text, "send-invite.md", "send-invite", &agent()).unwrap()
    }

    fn good_fill() -> Value {
        json!({
            "slots": {
                "person": "⟦PERSON_1⟧",
                "email": "camille@exemple.fr",
                "when": "2026-10-06T10:00:00+02:00"
            },
            "calls": [
                {
                    "tool": "google_calendar_create_event",
                    "arguments": {
                        "summary": "Meeting with ⟦PERSON_1⟧",
                        "start": "2026-10-06T10:00:00+02:00",
                        "attendees": [{ "email": "camille@exemple.fr" }]
                    }
                },
                {
                    "tool": "google_gmail_send",
                    "arguments": { "to": "camille@exemple.fr", "body": "See you." }
                }
            ]
        })
    }

    #[test]
    fn schema_advertises_slot_formats_and_wire_tools() {
        let schema = tool_schema(&skill());
        assert_eq!(skill_tool_name("send-invite"), "skill__send-invite");
        let wires = wire_tools(&skill());
        assert_eq!(
            wires,
            vec!["google_calendar_create_event", "google_gmail_send"]
        );
        assert_eq!(
            schema["properties"]["calls"]["items"]["properties"]["tool"]["enum"],
            json!(wires)
        );
        assert_eq!(
            schema["properties"]["slots"]["properties"]["email"]["format"],
            "email"
        );
        assert_eq!(
            schema["properties"]["slots"]["properties"]["when"]["format"],
            "date-time"
        );
        assert_eq!(
            schema["properties"]["slots"]["properties"]["duration"]["format"],
            "duration"
        );
        assert_eq!(
            schema["properties"]["slots"]["required"],
            json!(["person", "email", "when"])
        );
    }

    #[test]
    fn a_derived_slot_is_not_advertised_to_the_model() {
        let schema = tool_schema(&derived_skill());
        let slots = &schema["properties"]["slots"];
        assert!(slots["properties"].get("email").is_none(), "{slots}");
        assert_eq!(slots["required"], json!(["person", "when"]));
        // The slot the address derives from must read as a contact name, so the
        // model never fills it with an address (the live cloud model did).
        let description = slots["properties"]["person"]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(description.contains("contact's name"), "{description}");
        assert!(
            description.contains("never an email address"),
            "{description}"
        );
    }

    #[test]
    fn a_model_supplied_derived_slot_is_rejected() {
        let sink = kernel_broker::MemoryAuditSink::new();
        let err =
            validate_fill(&derived_skill(), &good_fill(), &context(), Some(&sink)).unwrap_err();
        assert_eq!(err, FillError::DerivedSlot("email".to_string()));
        assert_eq!(err.to_string(), "derived slot");
        assert_eq!(sink.count("skill.rejected_fill"), 1);
        assert_eq!(
            sink.payloads("skill.rejected_fill")[0]["reason"],
            "derived slot"
        );
    }

    #[test]
    fn a_call_references_the_derived_slot_through_its_source_value() {
        let mut value = good_fill();
        value["slots"].as_object_mut().unwrap().remove("email");
        value["calls"][0]["arguments"]["attendees"][0]["email"] = json!("⟦PERSON_1⟧");
        value["calls"][1]["arguments"]["to"] = json!("⟦PERSON_1⟧");
        let fill = validate_fill(&derived_skill(), &value, &context(), None).unwrap();
        assert!(fill
            .slots
            .iter()
            .any(|(name, value)| name == "email" && value == "⟦PERSON_1⟧"));
    }

    #[test]
    fn derived_recipients_are_rewritten_but_the_body_is_not() {
        let send = json!({ "to": "⟦PERSON_1⟧", "body": "See you, ⟦PERSON_1⟧." });
        let derived = [("⟦PERSON_1⟧".to_string(), "camille@exemple.fr".to_string())];
        let rewritten = substitute_derived_recipients("google.gmail.send", &send, &derived);
        assert_eq!(rewritten["to"], "camille@exemple.fr");
        assert_eq!(rewritten["body"], "See you, ⟦PERSON_1⟧.");

        let event = json!({
            "summary": "Meeting with ⟦PERSON_1⟧",
            "attendees": [{ "email": "⟦PERSON_1⟧" }]
        });
        let rewritten =
            substitute_derived_recipients("google.calendar.create_event", &event, &derived);
        assert_eq!(rewritten["attendees"][0]["email"], "camille@exemple.fr");
        assert_eq!(rewritten["summary"], "Meeting with ⟦PERSON_1⟧");
    }

    #[test]
    fn one_derived_input_owns_every_recipient_field() {
        assert!(recipients_are_runtime_owned(&derived_skill()));
        let value = json!({
            "slots": { "person": "⟦PERSON_1⟧", "when": "2026-10-06T10:00:00+02:00" },
            "calls": [
                {
                    "tool": "google_calendar_create_event",
                    "arguments": {
                        "summary": "Meeting with ⟦PERSON_1⟧",
                        "start": "2026-10-06T10:00:00+02:00",
                        "attendees": [{ "email": "x@invented.example" }]
                    }
                },
                {
                    "tool": "google_gmail_send",
                    "arguments": { "to": "billing@invented.example", "body": "See you." }
                }
            ]
        });
        // The invented addresses pass the fill: the executor overwrites every
        // recipient field with the resolved contact address.
        let fill = validate_fill(&derived_skill(), &value, &context(), None).unwrap();
        assert_eq!(fill.calls[1].arguments["to"], "billing@invented.example");
    }

    #[test]
    fn a_required_to_the_model_left_out_is_accepted() {
        let value = json!({
            "slots": { "person": "⟦PERSON_1⟧", "when": "2026-10-06T10:00:00+02:00" },
            "calls": [
                {
                    "tool": "google_calendar_create_event",
                    "arguments": {
                        "summary": "Meeting with ⟦PERSON_1⟧",
                        "start": "2026-10-06T10:00:00+02:00"
                    }
                },
                {
                    "tool": "google_gmail_send",
                    "arguments": { "subject": "Invitation", "body": "See you." }
                }
            ]
        });
        // The runtime inserts `to` after resolution, so the fill accepts its
        // absence even though the tool schema requires it.
        let fill = validate_fill(&derived_skill(), &value, &context(), None).unwrap();
        assert!(fill.calls[1].arguments.get("to").is_none());
    }

    #[test]
    fn several_derived_inputs_still_refuse_an_invented_recipient() {
        let skill = two_derived_skill();
        assert!(!recipients_are_runtime_owned(&skill));
        let value = json!({
            "slots": {
                "person": "⟦PERSON_1⟧",
                "backup": "⟦PERSON_2⟧",
                "when": "2026-10-06T10:00:00+02:00"
            },
            "calls": [
                {
                    "tool": "google_calendar_create_event",
                    "arguments": {
                        "summary": "Meeting with ⟦PERSON_1⟧",
                        "start": "2026-10-06T10:00:00+02:00",
                        "attendees": [{ "email": "⟦PERSON_1⟧" }]
                    }
                },
                {
                    "tool": "google_gmail_send",
                    "arguments": { "to": "billing@invented.example", "body": "See you." }
                }
            ]
        });
        let err = validate_fill(&skill, &value, &context(), None).unwrap_err();
        assert_eq!(
            err,
            FillError::RecipientNotFromSlot {
                tool: "google_gmail_send".to_string(),
                field: "to".to_string()
            }
        );
    }

    #[test]
    fn overwrite_derived_recipients_replaces_every_field_and_inserts_required_ones() {
        let address = "camille@exemple.fr";

        let send = json!({
            "to": "billing@invented.example",
            "cc": "",
            "subject": "Invitation",
            "body": "See you."
        });
        let rewritten = overwrite_derived_recipients("google.gmail.send", &send, address);
        assert_eq!(rewritten["to"], address);
        assert_eq!(rewritten["cc"], address);
        assert_eq!(rewritten["body"], "See you.");

        // No `to`: the required field is inserted.
        let send = json!({ "subject": "Invitation", "body": "See you." });
        let rewritten = overwrite_derived_recipients("google.gmail.send", &send, address);
        assert_eq!(rewritten["to"], address);

        // An existing attendees array is overwritten in place.
        let event = json!({
            "summary": "Meeting with ⟦PERSON_1⟧",
            "start": "2026-10-06T10:00:00+02:00",
            "attendees": [{ "email": "x@invented.example" }]
        });
        let rewritten =
            overwrite_derived_recipients("google.calendar.create_event", &event, address);
        assert_eq!(rewritten["attendees"][0]["email"], address);
        assert_eq!(rewritten["summary"], "Meeting with ⟦PERSON_1⟧");

        // No attendees array: one attendee is inserted.
        let event = json!({ "summary": "Meeting", "start": "2026-10-06T10:00:00+02:00" });
        let rewritten =
            overwrite_derived_recipients("google.calendar.create_event", &event, address);
        assert_eq!(rewritten["attendees"][0]["email"], address);

        // A draft has no required recipient: no `to` is invented for it.
        let draft = json!({ "subject": "Hi", "body": "Hello." });
        let rewritten = overwrite_derived_recipients("google.gmail.create_draft", &draft, address);
        assert!(rewritten.get("to").is_none());
    }

    #[test]
    fn the_derived_schema_says_the_runtime_fills_recipients() {
        let schema = tool_schema(&derived_skill());
        let described = schema["properties"]["calls"]["description"]
            .as_str()
            .expect("calls carries a description");
        assert!(described.contains("Auxesis"), "{described}");
        assert!(described.contains("contacts"), "{described}");
        assert!(
            described.contains("leave recipient fields empty"),
            "{described}"
        );

        let plain = tool_schema(&skill());
        let described = plain["properties"]["calls"]["description"]
            .as_str()
            .expect("calls carries a description");
        assert!(!described.contains("contacts"), "{described}");
    }

    #[test]
    fn fills_defaults_and_validates_calls() {
        let fill = validate_fill(&skill(), &good_fill(), &context(), None).unwrap();
        assert_eq!(fill.slots.len(), 4);
        assert_eq!(fill.slots[3], ("duration".to_string(), "30m".to_string()));
        assert_eq!(fill.calls.len(), 2);
        assert_eq!(fill.calls[1].logical, "google.gmail.send");
    }

    #[test]
    fn slot_types_are_checked_and_relative_datetimes_resolve() {
        let mut value = good_fill();
        value["slots"]["when"] = json!("tomorrow 09:30");
        let fill = validate_fill(&skill(), &value, &context(), None).unwrap();
        let when = &fill
            .slots
            .iter()
            .find(|(name, _)| name == "when")
            .unwrap()
            .1;
        let tomorrow = Local::now().date_naive() + chrono::Duration::days(1);
        assert_eq!(
            when,
            &format!("{tomorrow}T09:30:00"),
            "a wall time, zoned by the event"
        );

        // A wall time skipped in the system zone may exist in
        // the event's zone, so the slot keeps it as is; `event_time` decides.
        let mut value = good_fill();
        value["slots"]["when"] = json!("2026-03-29T02:30:00");
        let fill = validate_fill(&skill(), &value, &context(), None).unwrap();
        assert!(fill
            .slots
            .contains(&("when".to_string(), "2026-03-29T02:30:00".to_string())));

        let mut value = good_fill();
        value["slots"]["email"] = json!("⟦EMAIL_7⟧");
        value["calls"][0]["arguments"]["attendees"][0]["email"] = json!("⟦EMAIL_7⟧");
        value["calls"][1]["arguments"]["to"] = json!("⟦EMAIL_7⟧");
        assert!(validate_fill(&skill(), &value, &context(), None).is_ok());

        let mut value = good_fill();
        value["slots"]["email"] = json!("not an email");
        assert!(matches!(
            validate_fill(&skill(), &value, &context(), None),
            Err(FillError::BadSlotValue { .. })
        ));

        let mut value = good_fill();
        value["slots"]["duration"] = json!("PT45M");
        assert!(validate_fill(&skill(), &value, &context(), None).is_ok());
        value["slots"]["duration"] = json!("2h");
        assert!(validate_fill(&skill(), &value, &context(), None).is_ok());
        value["slots"]["duration"] = json!("soon");
        assert!(matches!(
            validate_fill(&skill(), &value, &context(), None),
            Err(FillError::BadSlotValue { .. })
        ));
    }

    #[test]
    fn call_arguments_must_match_the_tool_schema() {
        let mut value = good_fill();
        value["calls"][1]["arguments"] = json!({ "to": "camille@exemple.fr" });
        let err = validate_fill(&skill(), &value, &context(), None).unwrap_err();
        assert!(matches!(err, FillError::BadArguments { .. }), "{err:?}");

        let mut value = good_fill();
        value["calls"][1]["arguments"] = json!({
            "to": "camille@exemple.fr", "body": "x", "bogus": true
        });
        let err = validate_fill(&skill(), &value, &context(), None).unwrap_err();
        assert!(matches!(err, FillError::BadArguments { .. }), "{err:?}");
    }

    #[test]
    fn smuggled_tokens_are_rejected_and_logged() {
        let sink = kernel_broker::MemoryAuditSink::new();
        let mut value = good_fill();
        value["calls"][1]["arguments"]["body"] = json!("cc ⟦PERSON_9⟧");
        let err = validate_fill(&skill(), &value, &context(), Some(&sink)).unwrap_err();
        assert_eq!(
            err,
            FillError::TokenNotInSlots {
                tool: "google_gmail_send".to_string(),
                token: "⟦PERSON_9⟧".to_string()
            }
        );
        assert_eq!(sink.count("skill.rejected_fill"), 1);
        assert_eq!(
            sink.payloads("skill.rejected_fill")[0]["tool"],
            "google_gmail_send"
        );
    }

    #[test]
    fn recipients_must_equal_an_email_slot() {
        let sink = kernel_broker::MemoryAuditSink::new();
        let mut value = good_fill();
        value["calls"][1]["arguments"]["to"] = json!("someone@elsewhere.fr");
        let err = validate_fill(&skill(), &value, &context(), Some(&sink)).unwrap_err();
        assert_eq!(
            err,
            FillError::RecipientNotFromSlot {
                tool: "google_gmail_send".to_string(),
                field: "to".to_string()
            }
        );
        assert_eq!(sink.count("skill.rejected_fill"), 1);
    }

    #[test]
    fn free_text_is_not_filled() {
        assert_eq!(
            validate_fill(&skill(), &json!("just do it"), &context(), None),
            Err(FillError::NotFilled)
        );
    }

    /// The skill declares its calls, so a fill carries each one exactly once. The
    /// cloud leg sent only the calendar event: the run went out and the invite
    /// was never mailed. The refusal is a tool error the model can retry.
    #[test]
    fn a_fill_that_drops_a_declared_call_is_refused() {
        let mut value = good_fill();
        value["calls"].as_array_mut().unwrap().pop();
        let sink = kernel_broker::MemoryAuditSink::new();
        let err = validate_fill(&skill(), &value, &context(), Some(&sink)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "send-invite needs exactly these calls: google_calendar_create_event, google_gmail_send"
        );
        assert_eq!(sink.count("skill.rejected_fill"), 1);
    }

    /// A repeated call is not one of the declared calls: the fill is refused.
    #[test]
    fn a_fill_that_adds_a_call_is_refused() {
        let mut value = good_fill();
        let extra = value["calls"][1].clone();
        value["calls"].as_array_mut().unwrap().push(extra);
        let err = validate_fill(&skill(), &value, &context(), None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "send-invite needs exactly these calls: google_calendar_create_event, google_gmail_send"
        );
    }

    /// Each declared call once, in any order: the validated calls come back in
    /// the skill's declared order.
    #[test]
    fn reordered_calls_are_accepted_in_declared_order() {
        let mut value = good_fill();
        let calls = value["calls"].as_array_mut().unwrap();
        calls.reverse();
        let fill = validate_fill(&skill(), &value, &context(), None).unwrap();
        let order: Vec<&str> = fill.calls.iter().map(|call| call.tool.as_str()).collect();
        assert_eq!(order, ["google_calendar_create_event", "google_gmail_send"]);
    }

    /// The schema pins `calls` to the declared list: its length and each
    /// position's tool name, so the model is guided before it is refused.
    #[test]
    fn schema_pins_calls_to_the_declared_list() {
        let schema = tool_schema(&skill());
        let calls = &schema["properties"]["calls"];
        assert_eq!(calls["minItems"], 2);
        assert_eq!(calls["maxItems"], 2);
        assert_eq!(
            calls["prefixItems"][0]["properties"]["tool"]["const"],
            "google_calendar_create_event"
        );
        assert_eq!(
            calls["prefixItems"][1]["properties"]["tool"]["const"],
            "google_gmail_send"
        );
    }

    #[test]
    fn missing_slot_without_default_is_rejected() {
        let mut value = good_fill();
        value["slots"].as_object_mut().unwrap().remove("email");
        assert_eq!(
            validate_fill(&skill(), &value, &context(), None),
            Err(FillError::MissingSlot("email".to_string()))
        );
    }

    #[test]
    fn tool_outside_the_skill_is_rejected_and_logged() {
        let sink = kernel_broker::MemoryAuditSink::new();
        let value = json!({
            "slots": {
                "person": "⟦PERSON_1⟧",
                "email": "camille@exemple.fr",
                "when": "2026-10-06T10:00:00+02:00"
            },
            "calls": [{ "tool": "google_gmail_search", "arguments": {} }]
        });
        let err = validate_fill(&skill(), &value, &context(), Some(&sink)).unwrap_err();
        assert_eq!(
            err,
            FillError::RejectedTool("google_gmail_search".to_string())
        );
        assert_eq!(sink.count("skill.rejected_tool"), 1);
        let payload = &sink.payloads("skill.rejected_tool")[0];
        assert_eq!(payload["tool"], "google_gmail_search");
        assert_eq!(payload["skill_name"], "send-invite");
        assert_eq!(payload["skill_hash"], skill().hash);
    }

    #[test]
    fn empty_calls_and_unknown_slots_are_rejected() {
        let mut value = good_fill();
        value["slots"]["extra"] = json!("z");
        assert_eq!(
            validate_fill(&skill(), &value, &context(), None),
            Err(FillError::UnknownSlot("extra".to_string()))
        );

        let mut value = good_fill();
        value["calls"] = json!([]);
        assert_eq!(
            validate_fill(&skill(), &value, &context(), None),
            Err(FillError::EmptyCalls)
        );
    }

    #[test]
    fn approval_and_tools_are_parsed() {
        let skill = skill();
        assert_eq!(skill.approval, Approval::EachRun);
        assert_eq!(skill.effective_tools.len(), 2);
    }

    #[test]
    fn every_rejection_writes_exactly_one_row() {
        let skill = skill();
        let sink = kernel_broker::MemoryAuditSink::new();

        let mut cases: Vec<Value> = Vec::new();
        cases.push(json!("free text"));
        cases.push(json!({ "slots": 1, "calls": [] }));
        let mut value = good_fill();
        value["slots"]["email"] = json!("nope");
        cases.push(value);
        let mut value = good_fill();
        value["slots"].as_object_mut().unwrap().remove("email");
        cases.push(value);
        let mut value = good_fill();
        value["slots"]["extra"] = json!("x");
        cases.push(value);
        let mut value = good_fill();
        value["calls"] = json!([]);
        cases.push(value);
        let mut value = good_fill();
        value["calls"] = json!("x");
        cases.push(value);
        let mut value = good_fill();
        value["calls"][1]["arguments"] = json!({ "to": "camille@exemple.fr" });
        cases.push(value);
        let mut value = good_fill();
        value["calls"][1]["arguments"]["body"] = json!("⟦PERSON_9⟧");
        cases.push(value);
        let mut value = good_fill();
        value["calls"][1]["arguments"]["to"] = json!("x@y.fr");
        cases.push(value);

        for (index, case) in cases.iter().enumerate() {
            assert!(
                validate_fill(&skill, case, &context(), Some(&sink)).is_err(),
                "case {index} must fail"
            );
            assert_eq!(
                sink.count("skill.rejected_fill"),
                index + 1,
                "case {index} must add one row"
            );
        }

        // A tool outside the skill is the one distinct kind.
        let value = json!({
            "slots": {
                "person": "⟦PERSON_1⟧",
                "email": "camille@exemple.fr",
                "when": "2026-10-06T10:00:00+02:00"
            },
            "calls": [{ "tool": "google_gmail_search", "arguments": { "query": "x" } }]
        });
        assert!(validate_fill(&skill, &value, &context(), Some(&sink)).is_err());
        assert_eq!(sink.count("skill.rejected_tool"), 1);
        assert_eq!(sink.count("skill.rejected_fill"), cases.len());
    }

    #[test]
    fn mcp_tools_need_a_pinned_schema() {
        struct Schemas;
        impl ToolSchemaSource for Schemas {
            fn arguments_schema(&self, logical: &str) -> Option<Value> {
                (logical == "mcp.github.search_issues").then(|| {
                    json!({
                        "type": "object",
                        "properties": { "query": { "type": "string" } },
                        "required": ["query"],
                        "additionalProperties": false
                    })
                })
            }
        }

        let mut agent = agent();
        agent.tools.push("mcp.github.search_issues".to_string());
        let text = b"---\nname: gh\nversion: 1\ntools: [mcp.github.search_issues]\napproval: each_run\n---\n";
        let skill = parse_skill(text, "gh.md", "gh", &agent).unwrap();
        let value = json!({
            "slots": {},
            "calls": [{ "tool": "mcp__github__search_issues", "arguments": {} }]
        });

        let sink = kernel_broker::MemoryAuditSink::new();
        let err = validate_fill(&skill, &value, &context(), Some(&sink)).unwrap_err();
        assert!(matches!(err, FillError::BadArguments { .. }), "{err:?}");
        assert!(err.to_string().contains("no pinned JSON schema"), "{err}");
        assert_eq!(sink.count("skill.rejected_fill"), 1);

        // With a pinned schema the same call validates.
        let context = RunContext {
            agent: "assistant",
            run_id: "run-1",
            schemas: Some(&Schemas),
            owner_input: None,
        };
        let value = json!({
            "slots": {},
            "calls": [{ "tool": "mcp__github__search_issues", "arguments": { "query": "x" } }]
        });
        assert!(validate_fill(&skill, &value, &context, None).is_ok());
    }

    /// N4: header fields refuse C1 controls and the Unicode line and paragraph
    /// separators in the check phase, so the run is refused before any call.
    /// The body keeps its own rule.
    #[test]
    fn header_fields_refuse_c1_and_unicode_line_separators() {
        for bad in [
            "Hi\u{0085}Bcc: x@y",
            "Hi\u{2028}Bcc: x@y",
            "Hi\u{2029}x",
            "Hi\u{009f}x",
        ] {
            let mut value = good_fill();
            value["calls"][1]["arguments"]["subject"] = json!(bad);
            let err = validate_fill(&skill(), &value, &context(), None).unwrap_err();
            assert!(
                matches!(err, FillError::BadArguments { .. }),
                "{bad:?}: {err:?}"
            );
            assert!(
                check_arguments("google.gmail.send", &value["calls"][1]["arguments"]).is_err(),
                "{bad:?} must fail the check phase too"
            );
        }
        let mut value = good_fill();
        value["calls"][1]["arguments"]["body"] = json!("a\u{2028}b");
        assert!(validate_fill(&skill(), &value, &context(), None).is_ok());
    }

    #[test]
    fn header_injection_is_rejected_and_logged() {
        let sink = kernel_broker::MemoryAuditSink::new();
        let mut value = good_fill();
        value["calls"][1]["arguments"]["subject"] = json!("Hi\r\nBcc: x@y");
        let err = validate_fill(&skill(), &value, &context(), Some(&sink)).unwrap_err();
        assert!(matches!(err, FillError::BadArguments { .. }), "{err:?}");
        assert!(err.to_string().contains("control character"), "{err}");
        assert_eq!(sink.count("skill.rejected_fill"), 1);

        let mut value = good_fill();
        value["calls"][1]["arguments"]["body"] = json!("line one\nline two");
        assert!(validate_fill(&skill(), &value, &context(), None).is_ok());
        value["calls"][1]["arguments"]["body"] = json!("line\u{0}two");
        assert!(matches!(
            validate_fill(&skill(), &value, &context(), None),
            Err(FillError::BadArguments { .. })
        ));
    }

    #[test]
    fn email_tokens_must_match_the_token_grammar() {
        assert!(is_token("⟦EMAIL_1⟧", "EMAIL"));
        assert!(is_token("⟦EMAIL_ABC_9⟧", "EMAIL"));
        assert!(!is_token("⟦EMAIL_⟧", "EMAIL"));
        assert!(!is_token("⟦email_1⟧", "EMAIL"));
        assert!(!is_token("⟦EMAIL-1⟧", "EMAIL"));
        assert!(!is_token("⟦PERSON_1⟧", "EMAIL"));
        assert!(!is_token("⟦EMAIL_1⟧extra", "EMAIL"));
    }

    /// The model fills `calls` from what it is shown. The skill schema must name
    /// each tool's argument names and types, not leave `arguments` an open object:
    /// the cloud leg guessed `title` for a calendar event and was refused.
    #[test]
    fn tool_schema_shows_each_calls_argument_schema() {
        let schema = tool_schema(&skill());
        let described = schema["properties"]["calls"]["items"]["properties"]["arguments"]
            ["description"]
            .as_str()
            .expect("the arguments carry a description");
        assert!(
            described.contains("google_calendar_create_event"),
            "{described}"
        );
        assert!(described.contains("\"summary\""), "{described}");
        assert!(described.contains("google_gmail_send"), "{described}");
        assert!(described.contains("\"to\""), "{described}");
    }

    /// The connector takes calendar `start` and `end` only as RFC 3339, so the
    /// schema the model is shown says so.
    #[test]
    fn calendar_times_are_advertised_as_rfc_3339() {
        let schema = tool_map::arguments_schema("google.calendar.create_event")
            .expect("the calendar tool has a schema");
        assert_eq!(schema["properties"]["start"]["format"], "date-time");
        assert_eq!(schema["properties"]["end"]["format"], "date-time");
    }

    /// The cloud leg sent `start: "tomorrow 10:00"` (the slot's own wording). It
    /// must be refused before any card is shown, with the format named.
    #[test]
    fn a_calendar_start_that_is_not_rfc_3339_is_refused_before_any_card() {
        let arguments = |start: &str| {
            json!({
                "summary": "Meeting with Camille Exemple",
                "start": start,
                "end": "2026-10-11T10:30:00+02:00",
                "attendees": [{ "email": "camille@exemple.fr" }]
            })
        };
        assert!(check_arguments(
            "google.calendar.create_event",
            &arguments("2026-10-11T10:00:00+02:00")
        )
        .is_ok());
        let err = check_arguments("google.calendar.create_event", &arguments("tomorrow 10:00"))
            .expect_err("a non-RFC 3339 start is refused");
        assert!(err.contains("RFC 3339"), "{err}");
    }
}
