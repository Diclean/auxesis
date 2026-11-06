//! Daemon wiring for the CRM: the timeline builders and the follow-up tool.
//!
//! Three pieces live here:
//!
//! * [`collect_threads`] / [`attach`] — the timeline refresh. Mail comes from
//!   the same [`aux_mail::MailApi`] the mail tools use, and it is reduced to
//!   headers before a row is written; EventKit events come from the snapshot
//!   the Mac app published. No body and no event notes are ever read or stored.
//! * [`CrmFollowupTool`] — `crm_create_followup`, registered `skill_only`, so
//!   the broker's floor refuses a plain conversation and the engine never
//!   offers it to a model outside a skill.
//! * [`CrmSkillConnector`] — serves `crm.create_followup` to the skill executor,
//!   stamping the loaded skill as the author.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aux_crm::timeline::valid_message_id;
use aux_crm::{
    CalendarEvent, Crm, CrmError, CrmToday, InteractionDraft, MailThread, MemoryDraft, PartyBrief,
    PartyKind, PartyMatch,
};
use aux_mail::{EnvelopeItem, MailApi, MAX_HEADER_SCAN};
use aux_store::Store;
use kernel_broker::{
    NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, ToolRegistry, Trust,
};
use kernel_core::privacy::{ModeFn, PathId, PrivacyMode};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::apple_eventkit::{self, EventKitSnapshot};
use crate::turn_runtime::block_on;

/// Why a refresh stops before any socket in Private mode. Both the scheduled
/// job and `aux crm timeline refresh` surface this same sentence.
pub const PRIVATE_REFUSAL: &str = "the CRM timeline refresh is not available in private mode";

/// What one timeline refresh wrote.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RefreshReport {
    /// New `mail` interaction rows.
    pub mail: usize,
    /// New `meeting` interaction rows.
    pub meetings: usize,
    /// Items skipped because they failed to attach.
    pub skipped: usize,
}

/// The `crm_create_followup` tool's arguments (`docs/phase1.md` §5).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateFollowupArgs {
    party_id: i64,
    due: String,
    note: String,
}

/// Create a follow-up on a CRM party. Skill only: the registry marks it
/// `skill_only`, so the broker refuses a call that carries no skill context.
pub struct CrmFollowupTool {
    store: Arc<Mutex<Store>>,
}

impl CrmFollowupTool {
    /// A tool over `store`.
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }
}

impl NativeTool for CrmFollowupTool {
    fn native_name(&self) -> &'static str {
        "crm_create_followup"
    }

    fn native_description(&self) -> &'static str {
        "Create a follow-up on a CRM party (skill only)."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
            json!({
                "type": "object",
                "properties": {
                    "party_id": {"type": "integer", "minimum": 1},
                    "due": {"type": "string", "maxLength": 40},
                    "note": {"type": "string", "maxLength": 2000}
                },
                "required": ["party_id", "due", "note"],
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for CrmFollowupTool {
    fn path_id(&self) -> PathId {
        // The CRM/memory storage row of the privacy matrix (`docs/phase1.md` §2).
        PathId::G3
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: CreateFollowupArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let followup = Crm::new(&store)
            .create_followup(args.party_id, &args.due, &args.note, "skill")
            .map_err(|err| ToolError::invalid_args(self.name(), err.to_string()))?;
        Ok(ToolOutput::ok(
            json!({
                "id": followup.id,
                "party_id": followup.party_id,
                "due": followup.due,
                "status": followup.status
            })
            .to_string(),
        ))
    }

    fn risk(&self) -> Risk {
        Risk::Medium
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            // A local write; the result is only the new row's id and status.
            returns_private_data: false,
            output_trust: Trust::Trusted,
            skill_only: true,
            ..ToolClass::default()
        }
    }
}

/// The `crm_search` arguments.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    #[serde(default)]
    limit: Option<usize>,
}

/// The `crm_list` arguments.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

/// Most rows one `crm_list` call returns.
const MAX_LIST: usize = 50;

/// The `crm_get` arguments. A call names the party by id or by name; a name
/// that matches several parties returns them so the skill can ask the owner.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    #[serde(default)]
    party_id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    timeline: Option<usize>,
    #[serde(default)]
    memory: Option<usize>,
}

/// The `crm_today` arguments; `day` defaults to the local date.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TodayArgs {
    #[serde(default)]
    day: Option<String>,
}

/// One memory item in a `crm_log_interaction` call.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryArg {
    kind: String,
    title: String,
    body: String,
}

/// The `crm_log_interaction` arguments. The party is named by id or by name.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogInteractionArgs {
    #[serde(default)]
    party_id: Option<i64>,
    #[serde(default)]
    party: Option<String>,
    kind: String,
    at: String,
    source_ref: String,
    summary: String,
    #[serde(default)]
    memory: Vec<MemoryArg>,
}

/// The result of resolving a party reference.
enum Resolved {
    /// Exactly one party.
    One(i64),
    /// None or several matches, for the caller to list.
    Many(Vec<PartyMatch>),
}

/// Resolve a `party_id` or a name against the live parties. An id wins; a name
/// with no exact single match returns the candidate list.
fn resolve_party(
    store: &Store,
    party_id: Option<i64>,
    name: Option<&str>,
) -> Result<Resolved, String> {
    if let Some(id) = party_id {
        return Ok(Resolved::One(id));
    }
    let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
        return Err("a CRM read needs `party_id` or `name`".to_string());
    };
    let matches = Crm::new(store)
        .search(name, 10)
        .map_err(|err| err.to_string())?;
    match matches.len() {
        0 => Ok(Resolved::Many(Vec::new())),
        1 => Ok(Resolved::One(matches[0].id)),
        _ => Ok(Resolved::Many(matches)),
    }
}

/// The candidate list a refusal shows the owner: `Name (id N), …`.
fn choices(matches: &[PartyMatch]) -> String {
    matches
        .iter()
        .map(|party| format!("{} (id {})", party.display_name, party.id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolve a party reference to exactly one live party, for a write. A name is
/// its whole name or whole address, never a substring.
fn resolve_one_party(
    store: &Store,
    party_id: Option<i64>,
    name: Option<&str>,
) -> Result<i64, String> {
    if let Some(id) = party_id {
        return Ok(id);
    }
    let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) else {
        return Err("a CRM write needs `party_id` or `name`".to_string());
    };
    let matches = Crm::new(store)
        .resolve_exact(name)
        .map_err(|err| err.to_string())?;
    match matches.len() {
        0 => Err(format!("no client matches `{name}`; find the client first")),
        1 => Ok(matches[0].id),
        _ => Err(format!(
            "several clients match `{name}` ({}); ask the owner which one",
            choices(&matches)
        )),
    }
}

/// The pinned schema of a logical tool, shared with the fill validator.
fn schema_for(logical: &str) -> Value {
    aux_runtime::skills::tool_map::arguments_schema(logical)
        .unwrap_or_else(|| panic!("no schema for `{logical}`"))
}

/// One search match as JSON.
fn match_json(party: &PartyMatch) -> Value {
    json!({
        "id": party.id,
        "kind": party.kind.as_str(),
        "display_name": party.display_name,
        "emails": party.emails,
        // More addresses than shown: the agent says "+N more".
        "email_count": party.email_count,
    })
}

/// What the model is told about a timeline row written from outside content.
/// No model-controlled field of the row is sent, only the kind, the time and
/// this fixed marker.
const TAINTED_SUMMARY: &str = "[quarantined: from untrusted content]";

/// One party brief as JSON.
fn brief_json(store: &Store, brief: &PartyBrief) -> Value {
    json!({
        "client_card": {
            "id": brief.party.id,
            "kind": brief.party.kind.as_str(),
            "display_name": brief.party.display_name,
            "emails": brief.party.emails,
            "phones": brief.party.phones,
            "tags": brief.party.tags,
        },
        "last_contact_at": brief
            .last_contact_at
            .as_deref()
            .map(|at| aux_crm::safe_interaction_at(store, at)),
        "timeline": brief
            .interactions
            .iter()
            .map(|row| {
                // `at` predates validation on old rows: a non-time becomes the
                // store's clock, never model text.
                let at = aux_crm::safe_interaction_at(store, &row.at);
                if row.tainted {
                    // A tainted row's id, source reference, provenance, direction
                    // and summary are all model-controlled: keep none of them.
                    json!({
                        "kind": row.kind,
                        "at": at,
                        "summary": TAINTED_SUMMARY,
                        "tainted": true,
                    })
                } else {
                    json!({
                        "id": row.id,
                        "kind": row.kind,
                        "at": at,
                        "source_ref": row.source_ref,
                        "summary": row.summary,
                        "tainted": false,
                        "provenance": row.provenance,
                        "direction": row.direction,
                    })
                }
            })
            .collect::<Vec<_>>(),
        "followups": brief
            .followups
            .iter()
            .map(|followup| json!({
                "id": followup.id,
                "due": followup.due,
                "reason": followup.reason,
                "status": followup.status,
            }))
            .collect::<Vec<_>>(),
        "memory": brief
            .memory
            .iter()
            .map(|item| json!({
                "id": item.id,
                "kind": item.kind,
                "title": item.title,
                "body": item.body,
                "source": item.source,
            }))
            .collect::<Vec<_>>(),
    })
}

/// The brief's CRM section as JSON.
/// A day read from a stale calendar copy says so.
fn with_calendar_note(mut today: Value, home: &Path, snapshot: Option<&EventKitSnapshot>) -> Value {
    let note = snapshot.and_then(|snapshot| apple_eventkit::stale_note(home, snapshot));
    if let (Some(note), Some(map)) = (note, today.as_object_mut()) {
        map.insert("calendar_note".into(), Value::String(note));
    }
    today
}

fn today_json(today: &CrmToday) -> Value {
    json!({
        "parties": today.parties.iter().map(match_json).collect::<Vec<_>>(),
        "due_followups": today
            .due_followups
            .iter()
            .map(|due| json!({
                "party_id": due.party_id,
                "party": due.party,
                "due": due.due,
                "reason": due.reason,
            }))
            .collect::<Vec<_>>(),
    })
}

/// One `crm_list` page as JSON: id, name, kind and last interaction only.
fn list_json(store: &Store, args: &ListArgs) -> Result<Value, String> {
    let kind = match args.kind.as_deref() {
        None => None,
        Some(raw) => Some(
            PartyKind::parse(raw).ok_or_else(|| "`kind` is `person` or `company`".to_string())?,
        ),
    };
    let offset = args.offset.unwrap_or(0);
    let limit = args.limit.unwrap_or(MAX_LIST).clamp(1, MAX_LIST);
    let page = Crm::new(store)
        .recent(kind, offset, limit)
        .map_err(|err| err.to_string())?;
    let end = offset.saturating_add(page.rows.len());
    let parties: Vec<Value> = page
        .rows
        .iter()
        .map(|row| {
            json!({
                "id": row.party.id,
                "display_name": row.party.display_name,
                "kind": row.party.kind.as_str(),
                "last_interaction_at": row
                    .last_interaction_at
                    .as_deref()
                    .map(|at| aux_crm::safe_interaction_at(store, at)),
            })
        })
        .collect();
    Ok(json!({
        "parties": parties,
        "total": page.total,
        "offset": offset,
        "next_offset": (end < page.total).then_some(end),
    }))
}

/// The local day (`YYYY-MM-DD`) the brief runs for.
fn local_day() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

/// `crm_search`: resolve a party name for `client-brief`.
pub struct CrmSearchTool {
    store: Arc<Mutex<Store>>,
}

impl CrmSearchTool {
    /// A search over `store`.
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }
}

impl NativeTool for CrmSearchTool {
    fn native_name(&self) -> &'static str {
        "crm_search"
    }

    fn native_description(&self) -> &'static str {
        "Resolve a CRM party by name, name variant or address."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| schema_for("crm.search"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for CrmSearchTool {
    fn path_id(&self) -> PathId {
        PathId::G3
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: SearchArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = Crm::new(&store)
            .search(&args.query, args.limit.unwrap_or(10))
            .map_err(|err| ToolError::invalid_args(self.name(), err.to_string()))?;
        let matches: Vec<Value> = matches.iter().map(match_json).collect();
        Ok(ToolOutput::ok(json!({ "matches": matches }).to_string()))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            output_trust: Trust::Untrusted,
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

/// `crm_list`: the live parties, newest activity first. Names only: the
/// addresses and numbers stay behind `crm_get`.
pub struct CrmListTool {
    store: Arc<Mutex<Store>>,
}

impl CrmListTool {
    /// A list over `store`.
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }
}

impl NativeTool for CrmListTool {
    fn native_name(&self) -> &'static str {
        "crm_list"
    }

    fn native_description(&self) -> &'static str {
        "List the owner's clients (CRM parties), newest activity first: id, name, kind \
         and last interaction date, at most 50 per page. Use it for \"list/show my clients\"; \
         read one with crm_get."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| schema_for("crm.list"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for CrmListTool {
    fn path_id(&self) -> PathId {
        PathId::G3
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: ListArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let page =
            list_json(&store, &args).map_err(|err| ToolError::invalid_args(self.name(), err))?;
        Ok(ToolOutput::ok(page.to_string()))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            output_trust: Trust::Untrusted,
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

/// `crm_get`: one party's identity, timeline, follow-ups and memory.
pub struct CrmGetTool {
    store: Arc<Mutex<Store>>,
}

impl CrmGetTool {
    /// A read over `store`.
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }
}

impl NativeTool for CrmGetTool {
    fn native_name(&self) -> &'static str {
        "crm_get"
    }

    fn native_description(&self) -> &'static str {
        "Read one client card: the CRM record of a client party (identity, e-mail, phone, tags, the recent timeline, the open follow-ups and the memory items). Show the record as it comes; if the record is returned, show it and never say it is missing. Before you read it, the kernel handled its protected values."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| schema_for("crm.get"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for CrmGetTool {
    fn path_id(&self) -> PathId {
        PathId::G3
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: GetArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let value = match resolve_party(&store, args.party_id, args.name.as_deref())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?
        {
            Resolved::One(id) => {
                let brief = Crm::new(&store)
                    .brief(
                        &_ctx.agent,
                        id,
                        args.timeline.unwrap_or(20),
                        args.memory.unwrap_or(20),
                    )
                    .map_err(|err| ToolError::invalid_args(self.name(), err.to_string()))?;
                match brief {
                    Some(brief) => brief_json(&store, &brief),
                    None => {
                        return Err(ToolError::invalid_args(
                            self.name(),
                            format!("party {id} not found"),
                        ))
                    }
                }
            }
            Resolved::Many(matches) => json!({
                "matches": matches.iter().map(match_json).collect::<Vec<_>>(),
            }),
        };
        Ok(ToolOutput::ok(value.to_string()))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            output_trust: Trust::Untrusted,
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

/// `crm_today`: the `brief` skill's CRM section (who today, follow-ups due).
pub struct CrmTodayTool {
    home: PathBuf,
    store: Arc<Mutex<Store>>,
}

impl CrmTodayTool {
    /// A read over `home`'s EventKit snapshot and `store`.
    pub fn new(home: impl Into<PathBuf>, store: Arc<Mutex<Store>>) -> Self {
        Self {
            home: home.into(),
            store,
        }
    }
}

impl NativeTool for CrmTodayTool {
    fn native_name(&self) -> &'static str {
        "crm_today"
    }

    fn native_description(&self) -> &'static str {
        "The parties in a day's events and the follow-ups due on or before it."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| schema_for("crm.today"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for CrmTodayTool {
    fn path_id(&self) -> PathId {
        PathId::G3
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: TodayArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let day = args.day.unwrap_or_else(local_day);
        let snapshot = apple_eventkit::read_snapshot(&self.home);
        let events = calendar_events(snapshot.as_ref());
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let today = Crm::new(&store)
            .today(&day, &events, 20)
            .map_err(|err| ToolError::invalid_args(self.name(), err.to_string()))?;
        Ok(ToolOutput::ok(
            with_calendar_note(today_json(&today), &self.home, snapshot.as_ref()).to_string(),
        ))
    }

    fn risk(&self) -> Risk {
        Risk::Low
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            output_trust: Trust::Untrusted,
            returns_private_data: true,
            ..ToolClass::default()
        }
    }
}

/// `crm_log_interaction`: one interaction plus its memory items (skill only).
pub struct CrmLogInteractionTool {
    store: Arc<Mutex<Store>>,
}

impl CrmLogInteractionTool {
    /// A write over `store`.
    pub fn new(store: Arc<Mutex<Store>>) -> Self {
        Self { store }
    }
}

impl NativeTool for CrmLogInteractionTool {
    fn native_name(&self) -> &'static str {
        "crm_log_interaction"
    }

    fn native_description(&self) -> &'static str {
        "Log one interaction (call, meeting or note) and its memory on a CRM party's timeline, when the owner says what happened with a client. Log what the owner said as it is; do not ask for more detail first."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| schema_for("crm.log_interaction"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for CrmLogInteractionTool {
    fn path_id(&self) -> PathId {
        PathId::G3
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: LogInteractionArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let logged = log_interaction(&store, &ctx.agent, &args, ctx.tainted)
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        Ok(ToolOutput::ok(
            json!({
                "interaction_id": logged.interaction_id,
                "memory_ids": logged.memory_ids,
            })
            .to_string(),
        ))
    }

    fn risk(&self) -> Risk {
        Risk::Medium
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            returns_private_data: false,
            output_trust: Trust::Trusted,
            // Not skill-only: the owner saying "I called X" in chat has the
            // same trust as `remember`; the row is local, additive and shown
            // on the client card.
            ..ToolClass::default()
        }
    }
}

/// Run the CRM `log-interaction` write for `agent`, resolving the party name
/// when no id was given. Every memory row carries the party and the
/// `skill:log-interaction` provenance; a tainted turn's rows are quarantined.
fn log_interaction(
    store: &Store,
    agent: &str,
    args: &LogInteractionArgs,
    tainted: bool,
) -> Result<aux_crm::LoggedInteraction, String> {
    let party_id = resolve_one_party(store, args.party_id, args.party.as_deref())?;
    let memory: Vec<MemoryDraft<'_>> = args
        .memory
        .iter()
        .map(|item| MemoryDraft {
            kind: &item.kind,
            title: &item.title,
            body: &item.body,
        })
        .collect();
    let draft = InteractionDraft {
        party_id,
        kind: &args.kind,
        at: &args.at,
        source_ref: &args.source_ref,
        summary: &args.summary,
        tainted,
    };
    Crm::new(store)
        .log_interaction(agent, &draft, &memory)
        .map_err(|err| err.to_string())
}

/// The `crm_add_note` arguments: the client by id or by name, and the note
/// the owner asked to keep.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddNoteArgs {
    #[serde(default)]
    party_id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
    note: String,
}

/// The longest note one call may keep.
const MAX_NOTE_CHARS: usize = 2000;

/// The store-local counter behind a note's readable, collision-free id.
const NOTE_COUNTER: &str = "crm.note";

/// Keep one note on a client's card, through the CRM's own write: one
/// timeline row (the card's Timeline) and one memory item (the card's Memory).
/// A tainted turn's item is quarantined, exactly like `remember`.
fn add_note(
    store: &Store,
    agent: &str,
    args: &AddNoteArgs,
    tainted: bool,
    at: &str,
) -> Result<Value, String> {
    let party_id = resolve_one_party(store, args.party_id, args.name.as_deref())?;
    let note = args.note.trim();
    if note.is_empty() {
        return Err("a note needs some text".to_string());
    }
    if note.chars().count() > MAX_NOTE_CHARS {
        return Err(format!("a note is at most {MAX_NOTE_CHARS} characters"));
    }
    let body = kernel_broker::sanitize_external_text(note, MAX_NOTE_CHARS * 4);
    // The counter lives in the store, so two notes in the same second across
    // a restart are still two rows.
    let seq = store
        .next_counter(NOTE_COUNTER)
        .map_err(|err| err.to_string())?;
    let source_ref = json!({"note": at, "seq": seq}).to_string();
    let logged = Crm::new(store)
        .log_interaction(
            agent,
            &InteractionDraft {
                party_id,
                kind: "note",
                at,
                source_ref: &source_ref,
                summary: &body,
                tainted,
            },
            &[MemoryDraft {
                kind: "note",
                title: "Note",
                body: &body,
            }],
        )
        .map_err(|err| err.to_string())?;
    Ok(json!({
        "party_id": party_id,
        "interaction_id": logged.interaction_id,
        "memory_ids": logged.memory_ids,
    }))
}

/// `crm_add_note`: keep a note on an existing client's card. A local write:
/// the note lands in the client's memory and its timeline on this Mac. It needs
/// no card: a note is not a send, a payment, a delete or an account change.
pub struct CrmAddNoteTool {
    store: Arc<Mutex<Store>>,
}

impl NativeTool for CrmAddNoteTool {
    fn native_name(&self) -> &'static str {
        "crm_add_note"
    }

    fn native_description(&self) -> &'static str {
        "Keep one note on an existing client's card, when the owner asks to remember \
         something about a client (for example \"add a note to Camille's card: prefers \
         mornings\"). The note is kept on this Mac, in the client's memory and its timeline; \
         nothing is sent anywhere. Name the client by its id or by its name: a name that \
         matches no client, or several clients, is refused and nothing is written."
    }

    fn native_schema(&self) -> &'static Value {
        static SCHEMA: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| schema_for("crm.add_note"));
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for CrmAddNoteTool {
    fn path_id(&self) -> PathId {
        PathId::G3
    }

    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: AddNoteArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let written = add_note(&store, &ctx.agent, &args, ctx.tainted, &at)
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;
        Ok(ToolOutput::ok(written.to_string()))
    }

    fn risk(&self) -> Risk {
        Risk::Medium
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            // A local write; the result holds ids only.
            returns_private_data: false,
            output_trust: Trust::Trusted,
            // Not skill-only: the owner asking for a note in a conversation is
            // the same trust as `remember`; the rows stay on this Mac.
            ..ToolClass::default()
        }
    }
}

/// Register the CRM tools on a turn's registry. The reads are ordinary tools;
/// `crm_create_followup` stays skill-only; `crm_log_interaction` is a plain tool too,
/// so a chat turn can log what the owner says happened.
pub fn register_tools(home: &Path, store: Arc<Mutex<Store>>, registry: &mut ToolRegistry) {
    registry.register_native(Box::new(CrmFollowupTool::new(Arc::clone(&store))));
    registry.register_native(Box::new(CrmSearchTool::new(Arc::clone(&store))));
    registry.register_native(Box::new(CrmGetTool::new(Arc::clone(&store))));
    registry.register_native(Box::new(CrmListTool::new(Arc::clone(&store))));
    registry.register_native(Box::new(CrmTodayTool::new(home, Arc::clone(&store))));
    registry.register_native(Box::new(CrmAddNoteTool {
        store: Arc::clone(&store),
    }));
    registry.register_native(Box::new(CrmLogInteractionTool::new(store)));
    for name in ["crm_search", "crm_get", "crm_list", "crm_today"] {
        registry.mark_read_only(name);
        registry.mark_untrusted_output(name);
        registry.mark_private_data(name);
    }
}

/// The executor's connector for the CRM reads and the `log-interaction`
/// write. Unlike the network connectors it is always mountable: every call is
/// local, and the broker's skill floor still refuses a skill-only write from a
/// plain conversation.
///
/// Results are raw stored rows. The executor only re-tokenises values it knows;
/// the privacy boundary for the rest is the engine's session `Gate`, which
/// issues every message that follows (tool results included) as `SafeText`
/// before a provider sees it (`crates/auxd/tests/crm_skills.rs` pins this for
/// IBAN, card, secret and health text).
pub struct CrmSkillConnector {
    home: PathBuf,
    agent: String,
    store: Arc<Mutex<Store>>,
}

impl CrmSkillConnector {
    /// Serve the CRM tools for `agent` over `home`'s EventKit snapshot and
    /// `store`.
    pub fn new(
        home: impl Into<PathBuf>,
        agent: impl Into<String>,
        store: Arc<Mutex<Store>>,
    ) -> Self {
        Self {
            home: home.into(),
            agent: agent.into(),
            store,
        }
    }

    /// The connector's one error shape.
    fn error(message: impl Into<String>) -> aux_runtime::executor::ConnectorError {
        aux_runtime::executor::ConnectorError::new(message)
    }
}

#[async_trait]
impl aux_runtime::executor::SkillConnector for CrmSkillConnector {
    async fn call(
        &self,
        skill: &aux_runtime::executor::SkillContext,
        logical: &str,
        arguments: &Value,
    ) -> Result<Value, aux_runtime::executor::ConnectorError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match logical {
            "crm.create_followup" => {
                let args: CreateFollowupArgs =
                    serde_json::from_value(arguments.clone()).map_err(|err| {
                        Self::error(format!("crm.create_followup arguments are invalid: {err}"))
                    })?;
                let created_by = format!("skill:{}@{}", skill.name, skill.version);
                let followup = Crm::new(&store)
                    .create_followup(args.party_id, &args.due, &args.note, &created_by)
                    .map_err(|err| Self::error(err.to_string()))?;
                Ok(json!({
                    "id": followup.id,
                    "party_id": followup.party_id,
                    "due": followup.due,
                    "status": followup.status
                }))
            }
            "crm.search" => {
                let args: SearchArgs =
                    serde_json::from_value(arguments.clone()).map_err(|err| {
                        Self::error(format!("crm.search arguments are invalid: {err}"))
                    })?;
                let matches = Crm::new(&store)
                    .search(&args.query, args.limit.unwrap_or(10))
                    .map_err(|err| Self::error(err.to_string()))?;
                let matches: Vec<Value> = matches.iter().map(match_json).collect();
                Ok(json!({ "matches": matches }))
            }
            "crm.list" => {
                let args: ListArgs = serde_json::from_value(arguments.clone())
                    .map_err(|err| Self::error(format!("crm.list arguments are invalid: {err}")))?;
                list_json(&store, &args).map_err(Self::error)
            }
            "crm.get" => {
                let args: GetArgs = serde_json::from_value(arguments.clone())
                    .map_err(|err| Self::error(format!("crm.get arguments are invalid: {err}")))?;
                match resolve_party(&store, args.party_id, args.name.as_deref())
                    .map_err(Self::error)?
                {
                    Resolved::One(id) => {
                        let brief = Crm::new(&store)
                            .brief(
                                &self.agent,
                                id,
                                args.timeline.unwrap_or(20),
                                args.memory.unwrap_or(20),
                            )
                            .map_err(|err| Self::error(err.to_string()))?;
                        match brief {
                            Some(brief) => Ok(brief_json(&store, &brief)),
                            None => Err(Self::error(format!("party {id} not found"))),
                        }
                    }
                    Resolved::Many(matches) => Ok(json!({
                        "matches": matches.iter().map(match_json).collect::<Vec<_>>(),
                    })),
                }
            }
            "crm.today" => {
                let args: TodayArgs = serde_json::from_value(arguments.clone()).map_err(|err| {
                    Self::error(format!("crm.today arguments are invalid: {err}"))
                })?;
                let day = args.day.unwrap_or_else(local_day);
                let snapshot = apple_eventkit::read_snapshot(&self.home);
                let events = calendar_events(snapshot.as_ref());
                let today = Crm::new(&store)
                    .today(&day, &events, 20)
                    .map_err(|err| Self::error(err.to_string()))?;
                Ok(with_calendar_note(
                    today_json(&today),
                    &self.home,
                    snapshot.as_ref(),
                ))
            }
            "crm.add_note" => {
                let args: AddNoteArgs =
                    serde_json::from_value(arguments.clone()).map_err(|err| {
                        Self::error(format!("crm.add_note arguments are invalid: {err}"))
                    })?;
                let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                add_note(&store, &self.agent, &args, skill.tainted, &at).map_err(Self::error)
            }
            "crm.log_interaction" => {
                let args: LogInteractionArgs =
                    serde_json::from_value(arguments.clone()).map_err(|err| {
                        Self::error(format!("crm.log_interaction arguments are invalid: {err}"))
                    })?;
                let logged = log_interaction(&store, &self.agent, &args, skill.tainted)
                    .map_err(Self::error)?;
                Ok(json!({
                    "interaction_id": logged.interaction_id,
                    "memory_ids": logged.memory_ids,
                }))
            }
            _ => Err(Self::error(format!("no connector for `{logical}`"))),
        }
    }
}

/// The timeline inputs from one EventKit snapshot. An event with no id cannot
/// be de-duplicated, so it is skipped rather than stored twice.
pub fn calendar_events(snapshot: Option<&EventKitSnapshot>) -> Vec<CalendarEvent> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    snapshot
        .events
        .iter()
        .filter_map(|event| {
            let id = event.id.clone()?;
            Some(CalendarEvent {
                id,
                title: event.title.clone(),
                start: event.start.clone(),
                attendees: event.attendees.clone().unwrap_or_default(),
            })
        })
        .collect()
}

/// Turn one grouped thread's headers into a builder input. Addresses
/// accumulate across the thread; the builder normalises and de-duplicates.
///
/// A message whose `Date` the parser does not trust is skipped, and a thread
/// with no trusted date at all is dropped: the store's `at` column orders the
/// timeline, so a guess would order it wrongly. A root `Message-ID` that cannot
/// be stored drops the whole thread. The newest message sets the direction.
fn thread_input(
    account: &str,
    owner: &[String],
    root: &str,
    items: &[&(String, EnvelopeItem)],
) -> Option<MailThread> {
    if !valid_message_id(root) {
        return None;
    }
    let (mailbox, head) = items
        .iter()
        .find(|(_, item)| item.message_id == root)
        .or_else(|| items.iter().min_by_key(|(_, item)| item.uid))?;
    let mut from = Vec::new();
    let mut to = Vec::new();
    let mut cc = Vec::new();
    let mut dates = Vec::new();
    for (_, item) in items {
        let Some(date) = parse_date(&item.date) else {
            continue;
        };
        dates.push((date, item.from.clone()));
        from.push(item.from.clone());
        to.extend(item.to.clone());
        cc.extend(item.cc.clone());
    }
    let (at, last_from) = dates.into_iter().max()?;
    Some(MailThread {
        account: account.to_string(),
        mailbox: mailbox.clone(),
        uid: head.uid,
        message_id: root.to_string(),
        subject: head.subject.clone(),
        at,
        owner: owner.to_vec(),
        from,
        to,
        cc,
        last_from,
    })
}

/// RFC 3339 UTC for the store's `at` ordering column, or `None` when the server
/// date is neither RFC 2822 nor RFC 3339.
fn parse_date(raw: &str) -> Option<String> {
    let instant = chrono::DateTime::parse_from_rfc2822(raw)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(raw))
        .ok()?;
    Some(
        instant
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

/// Resolve every thread of one account into builder inputs: one header listing
/// of INBOX and one of its Sent folder, grouped by thread root. Bounded: at
/// most [`MAX_HEADER_SCAN`] headers per folder, no body read.
pub async fn collect_threads(
    mail: &dyn MailApi,
    account: &str,
    owner: &[String],
    sent: Option<&str>,
) -> Result<Vec<MailThread>, aux_mail::MailError> {
    let mut by_id: BTreeMap<String, (String, EnvelopeItem)> = BTreeMap::new();
    for folder in [None, sent.filter(|name| !name.is_empty())] {
        let headers = match mail.list_headers(account, folder, MAX_HEADER_SCAN).await {
            Ok(headers) => headers,
            // Only Sent may be skipped: missing on the server, or outside the
            // `only_folders` read allowlist, which this refresh never widens.
            Err(aux_mail::MailError::FolderUnavailable { .. }) if folder.is_some() => {
                warn_sent_folder_once(
                    "timeline refresh: the sent folder is missing or not allowed",
                );
                continue;
            }
            Err(error) => return Err(error),
        };
        if headers.len() >= MAX_HEADER_SCAN {
            tracing::warn!(
                headers = headers.len(),
                "timeline refresh hit the header cap"
            );
        }
        // One entry per Message-ID: a mail in both folders counts once.
        for item in headers
            .into_iter()
            .filter(|item| valid_message_id(&item.message_id))
        {
            let label = folder.unwrap_or("INBOX").to_string();
            by_id
                .entry(item.message_id.clone())
                .or_insert((label, item));
        }
    }
    // Follow In-Reply-To through the listed headers; past the oldest listed
    // one, its parent's id is the root, so a window that drops a thread's first
    // mail keeps its key. Bounded, so an In-Reply-To loop cannot hang it.
    // TODO: a window that drops two ancestors makes a new key.
    let mut threads: BTreeMap<String, Vec<&(String, EnvelopeItem)>> = BTreeMap::new();
    for pair in by_id.values() {
        let (mut item, mut root) = (&pair.1, None);
        for _ in 0..by_id.len() {
            match item.in_reply_to.as_deref().map(str::trim) {
                Some(up) if valid_message_id(up) => match by_id.get(up) {
                    Some((_, parent)) => item = parent,
                    None => {
                        root = Some(up.to_string());
                        break;
                    }
                },
                _ => break,
            }
        }
        let root = root.unwrap_or_else(|| item.message_id.clone());
        threads.entry(root).or_default().push(pair);
    }
    Ok(threads
        .iter()
        .filter_map(|(root, items)| thread_input(account, owner, root, items))
        .collect())
}

fn warn_sent_folder_once(message: &'static str) {
    static WARNED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<&'static str>>> =
        std::sync::OnceLock::new();
    let warned = WARNED.get_or_init(Default::default);
    if let Ok(mut warned) = warned.lock() {
        if warned.insert(message) {
            tracing::warn!("{message}");
        }
    }
}

fn discover_sent_folder(folders: &[aux_mail::Folder], configured: &str) -> Option<String> {
    folders
        .iter()
        .find(|folder| folder.selectable && folder.special_use == Some("sent"))
        .or_else(|| {
            folders
                .iter()
                .find(|folder| folder.selectable && folder.canonical == Some("sent"))
        })
        .map(|folder| folder.name.clone())
        .or_else(|| (!configured.trim().is_empty()).then(|| configured.to_string()))
}

/// Attach every thread and event to the CRM. Returns how many rows were new.
pub fn attach(
    store: &Store,
    threads: &[MailThread],
    events: &[CalendarEvent],
) -> Result<RefreshReport, CrmError> {
    let crm = Crm::new(store);
    let mut report = RefreshReport::default();
    // A single bad thread or event must not abort the whole refresh: the
    // timeline is best-effort, and one unparseable subject or refused
    // summary would otherwise make `aux crm timeline refresh` fail for every
    // party. Skip the failing item, count it, and log only the error kind.
    for thread in threads {
        match crm.attach_mail_thread(thread) {
            Ok(ids) => report.mail += ids.len(),
            Err(err) => {
                report.skipped += 1;
                tracing::warn!(kind = err_kind(&err), "timeline mail item skipped");
            }
        }
    }
    for event in events {
        match crm.attach_calendar_event(event) {
            Ok(ids) => report.meetings += ids.len(),
            Err(err) => {
                report.skipped += 1;
                tracing::warn!(kind = err_kind(&err), "timeline meeting item skipped");
            }
        }
    }
    Ok(report)
}

/// True when every item tried failed. Items already attached on an earlier run
/// add no new row but are not failures, so compare skips with attempts.
fn all_failed(report: &RefreshReport, attempts: usize) -> bool {
    attempts > 0 && report.skipped == attempts
}

/// The kind of a CRM error, without its payload: subjects, addresses and
/// client names must never be logged.
fn err_kind(err: &aux_crm::CrmError) -> &'static str {
    match err {
        aux_crm::CrmError::Store(_) => "Store",
        aux_crm::CrmError::InvalidMessageId => "InvalidMessageId",
        aux_crm::CrmError::SummaryRefused => "SummaryRefused",
        _ => "Other",
    }
}

/// The configured `[connectors.mail]` accounts, or `None` when there is none
/// or the config cannot be read safely (a FIFO, a symlink: at once, never a
/// wait) or does not parse. The private check and the dial share this one
/// parse, so they cannot disagree about the host.
pub(crate) fn mail_config(home: &Path) -> Option<aux_mail::MailConfig> {
    let home = kernel_core::SandboxHome::open_existing(home).ok()?;
    let text = aux_engine::config::read_config_text(&home).ok()?;
    let value: toml::Value = toml::from_str(&text).ok()?;
    let mail = value.get("connectors")?.get("mail")?;
    let text = toml::to_string(mail).ok()?;
    let config = aux_mail::MailConfig::from_toml(&text).ok()?;
    if config.accounts.is_empty() {
        return None;
    }
    Some(config)
}

/// The mail API over `config` and its `(account id, owner address)` pairs for
/// one refresh.
fn mail_service(
    home: &Path,
    mode: &ModeFn,
    config: &aux_mail::MailConfig,
) -> (aux_mail::MailService, Vec<(String, String, String)>) {
    let accounts: Vec<(String, String, String)> = config
        .accounts
        .iter()
        .map(|a| (a.id.clone(), a.email.clone(), a.folders.sent.clone()))
        .collect();
    // Only loopback accounts are local: if the mode turns private after the
    // job's check, every other account gets no password and is never dialled.
    let local: std::collections::HashSet<String> = config
        .accounts
        .iter()
        .filter(|account| aux_mail::tlsutil::is_loopback_host(&account.imap.host))
        .map(|account| account.id.clone())
        .collect();
    let limits = config.limits.limits();
    let dialer = aux_mail::Dialer::new(limits.connect_timeout);
    let service = aux_mail::MailService::new(
        dialer,
        limits,
        config.accounts.clone(),
        Arc::new(ModeGatedCredentials::new(
            Arc::new(aux_mail::EnvCredentials::new(home.to_path_buf())),
            Arc::clone(mode),
            local,
        )),
    );
    (service, accounts)
}

/// A credential source that re-reads the live privacy mode at the last moment
/// before a dial.
///
/// `aux-mail` asks for the password right before it opens the socket, with no
/// await in between, so a refusal here is a refusal of the dial itself: in
/// private mode only the accounts in `local` (loopback hosts) get a password,
/// every other account gets `None`, and the call ends in an auth error with no
/// connection made. A check made earlier by the caller can go stale if the
/// owner switches mode; this one cannot.
pub(crate) struct ModeGatedCredentials {
    inner: Arc<dyn aux_mail::Credentials>,
    mode: ModeFn,
    local: std::collections::HashSet<String>,
}

impl ModeGatedCredentials {
    pub(crate) fn new(
        inner: Arc<dyn aux_mail::Credentials>,
        mode: ModeFn,
        local: std::collections::HashSet<String>,
    ) -> Self {
        Self { inner, mode, local }
    }
}

impl aux_mail::Credentials for ModeGatedCredentials {
    fn password(&self, account: &str) -> Option<String> {
        if (self.mode)() == PrivacyMode::Private && !self.local.contains(account) {
            return None;
        }
        self.inner.password(account)
    }
}

/// Refresh the timeline once: every configured account's newest threads, then
/// the EventKit snapshot. A stop switch engaged before the run refuses it; the
/// scheduler also refuses to claim while stopped.
pub fn run_job(home: &Path, store: &Arc<Mutex<Store>>) -> Result<String, String> {
    run_job_with_mode(home, store, &crate::privacy_wiring::live_mode_fn(home))
}

/// [`run_job`] over an explicit live mode, so a test can flip it between the
/// check below and the dial. The same handle gates the dial itself.
pub fn run_job_with_mode(
    home: &Path,
    store: &Arc<Mutex<Store>>,
    mode: &ModeFn,
) -> Result<String, String> {
    // Same rule as the brief: Private runs the refresh only when every
    // IMAP host is loopback (the owner's mailbox on this Mac). A remote host,
    // or a config that does not parse, skips the whole refresh here, before
    // the kill switch and before any socket or DNS lookup for any account.
    let config = mail_config(home);
    if mode() == PrivacyMode::Private
        && !config
            .as_ref()
            .is_some_and(crate::local_brief::all_imap_hosts_loopback)
    {
        return Err(PRIVATE_REFUSAL.to_string());
    }
    if aux_engine::marker_engaged(home) {
        return Err("stopped by kill switch".to_string());
    }
    // The EventKit snapshot is local data at rest, read in both modes.
    let events = calendar_events(apple_eventkit::read_snapshot(home).as_ref());
    let threads = match config.map(|config| mail_service(home, mode, &config)) {
        Some((service, accounts)) => block_on(async move {
            let mut threads = Vec::new();
            for (account, owner, sent) in accounts {
                let discovered = service.folders(&account).await.ok();
                let sent = discovered
                    .as_deref()
                    .and_then(|folders| discover_sent_folder(folders, &sent));
                if sent.is_none() {
                    warn_sent_folder_once(
                        "timeline refresh: the sent folder is missing or not allowed",
                    );
                }
                let found = collect_threads(&service, &account, &[owner], sent.as_deref())
                    .await
                    .map_err(|err| err.to_string())?;
                threads.extend(found);
            }
            Ok::<Vec<MailThread>, String>(threads)
        })
        .map_err(|err| err.to_string())??,
        None => Vec::new(),
    };
    let store = store
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let report = attach(&store, &threads, &events).map_err(|err| err.to_string())?;
    if all_failed(&report, threads.len() + events.len()) {
        return Err(format!(
            "timeline refresh: {} mail, {} meetings, {} skipped",
            report.mail, report.meetings, report.skipped
        ));
    }
    Ok(format!(
        "timeline refresh: {} mail, {} meetings, {} skipped",
        report.mail, report.meetings, report.skipped
    ))
}

/// The job name the scheduler claims.
pub const TIMELINE_JOB: &str = "crm-timeline";
/// How often the timeline refreshes.
pub const TIMELINE_SCHEDULE: &str = "every 30m";
/// The JSON payload the timeline job carries.
pub const TIMELINE_PAYLOAD: &str = r#"{"kind":"crm-timeline","name":"crm-timeline"}"#;

/// Keep the timeline job in the `jobs` table. It is idempotent and always
/// enabled: the refresh is local reads plus a local write, and it does nothing
/// when no mailbox or snapshot exists.
pub fn sync_job(
    store: &Store,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), aux_store::StoreError> {
    let existing = store
        .list_jobs()?
        .into_iter()
        .find(|job| job.agent == "main" && job.name == TIMELINE_JOB);
    match existing {
        Some(mut job) => {
            let mut changed = false;
            if job.schedule != TIMELINE_SCHEDULE {
                job.schedule = TIMELINE_SCHEDULE.to_string();
                changed = true;
            }
            if job.payload != TIMELINE_PAYLOAD {
                job.payload = TIMELINE_PAYLOAD.to_string();
                changed = true;
            }
            if !job.enabled {
                job.enabled = true;
                changed = true;
            }
            if changed {
                store.update_job(&job)?;
            }
        }
        None => {
            let next = (now + chrono::Duration::minutes(1))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
            store.create_job(
                "main",
                TIMELINE_JOB,
                TIMELINE_SCHEDULE,
                TIMELINE_PAYLOAD,
                Some(&next),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_refresh_fails_only_when_every_item_failed() {
        let report = |skipped| RefreshReport {
            mail: 0,
            meetings: 0,
            skipped,
        };
        // Re-run: one item keeps failing, the others were attached before.
        assert!(!all_failed(&report(1), 3));
        assert!(all_failed(&report(3), 3));
        assert!(!all_failed(&report(0), 0));
    }

    use super::*;
    use async_trait::async_trait;
    use aux_runtime::executor::SkillConnector as _;
    use aux_store::{NewParty, PartyKind};

    #[test]
    fn sent_discovery_prefers_rfc6154_role_then_common_name() {
        let folders = vec![
            aux_mail::Folder {
                name: "Sent Messages".into(),
                canonical: Some("sent"),
                special_use: None,
                selectable: true,
            },
            aux_mail::Folder {
                name: "owner-outbox".into(),
                canonical: Some("sent"),
                special_use: Some("sent"),
                selectable: true,
            },
        ];
        assert_eq!(
            discover_sent_folder(&folders, "Sent"),
            Some("owner-outbox".into())
        );
        assert_eq!(
            discover_sent_folder(&folders[..1], "Sent"),
            Some("Sent Messages".into())
        );
    }

    fn store() -> (tempfile::TempDir, Arc<Mutex<Store>>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        (dir, Arc::new(Mutex::new(store)))
    }

    fn party() -> NewParty {
        NewParty {
            kind: PartyKind::Person,
            display_name: "Person Zero".to_string(),
            name_variants: vec!["Person Zero".to_string()],
            emails: vec!["person0@fixture.test".to_string()],
            phones: Vec::new(),
            addresses: Vec::new(),
            tags: Vec::new(),
            notes: String::new(),
            time_zone: None,
            origin: "owner".to_string(),
        }
    }

    #[test]
    fn the_followup_tool_is_skill_only_and_never_a_plain_tool() {
        let (_dir, store) = store();
        let dir = tempfile::tempdir().unwrap();
        let mut registry = ToolRegistry::new();
        register_tools(dir.path(), Arc::clone(&store), &mut registry);

        let tool = registry.get("crm_create_followup").expect("registered");
        assert!(tool.class().skill_only, "the broker floor must apply");
        let prompt = aux_engine::build_system_prompt("", &registry);
        assert!(
            !prompt.contains("crm_create_followup"),
            "a plain conversation is never offered the skill-only tool"
        );
    }

    #[tokio::test]
    async fn a_chat_turn_logs_an_interaction_that_shows_on_the_card() {
        let (_dir, store) = store();
        let party = {
            let guard = store.lock().unwrap();
            Crm::new(&guard).create(party()).unwrap()
        };
        let dir = tempfile::tempdir().unwrap();
        let mut registry = ToolRegistry::new();
        register_tools(dir.path(), Arc::clone(&store), &mut registry);
        let tool = registry.get("crm_log_interaction").expect("registered");
        assert!(
            !tool.class().skill_only,
            "a chat turn may log what the owner says"
        );
        assert!(
            registry
                .get("crm_create_followup")
                .unwrap()
                .class()
                .skill_only
        );
        let output = tool
            .run(
                &json!({"party": "Person Zero", "kind": "call", "at": "2026-10-17T09:00:00Z",
                    "source_ref": "{\"owner\":true}", "summary": "Called about the launch page"}),
                &ToolCtx::new("clients", std::path::Path::new("/tmp")),
            )
            .await
            .unwrap();
        assert!(!output.is_error, "{}", output.content);
        let guard = store.lock().unwrap();
        let rows = guard.interactions_for_party(party.id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "call");
        assert_eq!(rows[0].provenance, "skill:log-interaction");
    }

    #[test]
    fn the_card_the_agent_reads_holds_the_addresses_and_phones() {
        let (_dir, store) = store();
        let guard = store.lock().unwrap();
        let mut draft = party();
        draft.phones = vec!["+33612345678".to_string()];
        let created = Crm::new(&guard).create(draft).unwrap();
        guard
            .insert_interaction(
                created.id,
                "call",
                "2026-10-18T13:00:00Z",
                "fixture-call",
                "Called about the launch",
                "test",
            )
            .unwrap();
        let brief = Crm::new(&guard)
            .brief("clients", created.id, 20, 20)
            .unwrap()
            .unwrap();
        let card = brief_json(&guard, &brief);
        assert_eq!(
            card["client_card"]["emails"],
            json!(["person0@fixture.test"])
        );
        assert_eq!(card["client_card"]["phones"], json!(["+33612345678"]));
        assert_eq!(card["last_contact_at"], json!("2026-10-18T13:00:00Z"));
    }

    #[tokio::test]
    async fn the_tool_writes_an_open_followup() {
        let (_dir, store) = store();
        let party = {
            let guard = store.lock().unwrap();
            Crm::new(&guard).create(party()).unwrap()
        };
        let tool = CrmFollowupTool::new(Arc::clone(&store));
        let output = tool
            .run(
                &json!({"party_id": party.id, "due": "2025-10-10", "note": "Relancer"}),
                &ToolCtx::new("test", std::path::Path::new("/tmp")),
            )
            .await
            .unwrap();
        assert!(!output.is_error);
        let guard = store.lock().unwrap();
        let followups = guard.followups_for_party(party.id).unwrap();
        assert_eq!(followups.len(), 1);
        assert_eq!(followups[0].reason, "Relancer");
        assert_eq!(followups[0].status, "open");
    }

    #[tokio::test]
    async fn the_skill_connector_stamps_the_skill_as_author() {
        let (_dir, store) = store();
        let party = {
            let guard = store.lock().unwrap();
            Crm::new(&guard).create(party()).unwrap()
        };
        let connector = CrmSkillConnector::new("/tmp", "main", Arc::clone(&store));
        let skill = aux_runtime::executor::SkillContext {
            name: "log-interaction".to_string(),
            version: 2,
            hash: "abc".to_string(),
            tainted: false,
        };
        connector
            .call(
                &skill,
                "crm.create_followup",
                &json!({"party_id": party.id, "due": "2025-10-11", "note": "Envoyer le devis"}),
            )
            .await
            .unwrap();
        let guard = store.lock().unwrap();
        let followups = guard.followups_for_party(party.id).unwrap();
        assert_eq!(followups[0].created_by, "skill:log-interaction@2");
    }

    #[test]
    fn a_skill_only_tool_is_refused_by_the_broker_without_a_skill() {
        // The registry answers the broker's live skill floor by name.
        use kernel_broker::SkillOnlyLookup;
        let (_dir, store) = store();
        let mut registry = ToolRegistry::new();
        register_tools(std::path::Path::new("/tmp"), store, &mut registry);
        assert!(registry.is_skill_only("crm_create_followup"));
        assert!(!registry.is_skill_only("not_registered"));
    }

    #[test]
    fn events_without_an_id_are_skipped() {
        let snapshot = EventKitSnapshot {
            authorized: true,
            events: vec![
                apple_eventkit::EventItem {
                    id: Some("evt-1".to_string()),
                    title: "With id".to_string(),
                    start: "2025-10-05T10:00:00Z".to_string(),
                    end: "2025-10-05T11:00:00Z".to_string(),
                    all_day: None,
                    calendar: "Work".to_string(),
                    location: None,
                    attendees: Some(vec!["person0@fixture.test".to_string()]),
                    calendar_id: None,
                    recurring: None,
                },
                apple_eventkit::EventItem {
                    id: None,
                    title: "No id".to_string(),
                    start: "2025-10-06T10:00:00Z".to_string(),
                    end: "2025-10-06T11:00:00Z".to_string(),
                    all_day: None,
                    calendar: "Work".to_string(),
                    location: None,
                    attendees: Some(vec!["person0@fixture.test".to_string()]),
                    calendar_id: None,
                    recurring: None,
                },
            ],
            reminders: Vec::new(),
            ..Default::default()
        };
        let events = calendar_events(Some(&snapshot));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-1");
    }

    #[test]
    fn only_rfc2822_and_rfc3339_dates_are_trusted() {
        assert_eq!(
            parse_date("Mon, 6 Oct 2025 09:00:00 +0000").as_deref(),
            Some("2025-10-06T09:00:00Z")
        );
        assert_eq!(
            parse_date("2025-10-06T09:00:00+00:00").as_deref(),
            Some("2025-10-06T09:00:00Z")
        );
        assert_eq!(parse_date("not a date"), None);
    }

    fn envelope(uid: u32, message_id: &str, date: &str) -> EnvelopeItem {
        EnvelopeItem {
            uid,
            message_id: message_id.to_string(),
            subject: "Subject".to_string(),
            from: "person0@fixture.test".to_string(),
            to: vec!["owner@fixture.test".to_string()],
            cc: Vec::new(),
            date: date.to_string(),
            size: 1,
            unread: false,
            in_reply_to: None,
        }
    }

    #[test]
    fn a_thread_with_no_trusted_date_or_a_bad_root_id_is_dropped() {
        let owner = vec!["owner@fixture.test".to_string()];
        // The root date is junk, the reply is trusted: only the reply counts.
        let inbox = |item: EnvelopeItem| ("INBOX".to_string(), item);
        let root = "<root@fixture.test>";
        let mut reply = envelope(2, "<reply@fixture.test>", "Mon, 6 Oct 2025 10:00:00 +0000");
        reply.from = "owner@fixture.test".to_string();
        let items = [inbox(envelope(1, root, "not a date")), inbox(reply)];
        let thread = thread_input("personal", &owner, root, &items.iter().collect::<Vec<_>>())
            .expect("one trusted message");
        assert_eq!(thread.at, "2025-10-06T10:00:00Z");
        assert_eq!(thread.from, vec!["owner@fixture.test"]);
        assert_eq!(thread.last_from, "owner@fixture.test");
        assert_eq!(thread.message_id, root);

        // No trusted date at all: the thread is dropped, not stored with junk.
        let junk = [inbox(envelope(1, root, "not a date"))];
        assert!(thread_input("personal", &owner, root, &junk.iter().collect::<Vec<_>>()).is_none());

        // A root Message-ID with a control character drops the thread.
        let bad = "<root\u{0007}@fixture.test>";
        let bad_id = [inbox(envelope(1, bad, "Mon, 6 Oct 2025 09:00:00 +0000"))];
        assert!(
            thread_input("personal", &owner, bad, &bad_id.iter().collect::<Vec<_>>()).is_none()
        );
    }

    struct DenyApprover;

    /// The kernel's `MemoryAuditSink` is behind `test-util`; this test only
    /// needs a sink that accepts the denial row.
    struct NoAudit;

    impl kernel_broker::AuditSink for NoAudit {
        fn log_event(
            &self,
            _kind: &str,
            _payload: &serde_json::Value,
        ) -> Result<i64, kernel_broker::AuditError> {
            Ok(0)
        }
    }

    #[async_trait]
    impl kernel_broker::Approver for DenyApprover {
        async fn approve(
            &self,
            _request: &kernel_broker::ApprovalRequest,
        ) -> Result<bool, kernel_broker::ApproverError> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn the_broker_refuses_the_followup_tool_without_a_skill() {
        let (dir, store) = store();
        let mut registry = ToolRegistry::new();
        register_tools(dir.path(), Arc::clone(&store), &mut registry);
        let name = "crm_create_followup";
        let registry = Arc::new(registry);
        let broker = kernel_broker::Broker::new(
            Arc::new(NoAudit),
            Vec::new(),
            Arc::new(DenyApprover),
            Arc::clone(&registry) as Arc<dyn kernel_broker::SkillOnlyLookup>,
        );
        let authorization = broker
            .authorize(kernel_broker::AuthorizeRequest {
                agent: "main",
                tool: name,
                risk: registry.get(name).unwrap().risk(),
                arguments: json!({"party_id": 1, "due": "2025-10-10", "note": "x"}),
                taint: &kernel_broker::Taint::Clean,
                read_only: registry.is_read_only(name),
                mode: registry.execution_mode(name),
                requires_explicit_rule: false,
                skill: None,
                // The live lookup must catch it even when the request says false.
                skill_only: false,
            })
            .await
            .unwrap();
        match authorization {
            kernel_broker::Authorization::Denied { reason } => {
                assert!(
                    reason.contains(kernel_broker::SKILL_ONLY_REASON),
                    "{reason}"
                );
            }
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn the_job_is_created_once_and_refreshed_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        let now = chrono::Utc::now();
        sync_job(&store, now).unwrap();
        sync_job(&store, now).unwrap();
        let jobs = store.list_jobs().unwrap();
        let ours: Vec<_> = jobs.iter().filter(|job| job.name == TIMELINE_JOB).collect();
        assert_eq!(ours.len(), 1);
        assert!(ours[0].enabled);
        assert_eq!(ours[0].schedule, TIMELINE_SCHEDULE);
    }

    #[tokio::test]
    async fn tainted_writes_stay_off_the_card_and_are_quarantined() {
        let (_dir, store) = store();
        let party = {
            let guard = store.lock().unwrap();
            Crm::new(&guard).create(party()).unwrap()
        };
        let tainted = || ToolCtx::new("clients", std::path::Path::new("/tmp")).with_tainted(true);
        let note = CrmAddNoteTool {
            store: store.clone(),
        }
        .run(
            &json!({"party_id": party.id, "note": "prefers mornings"}),
            &tainted(),
        )
        .await
        .unwrap();
        let log = CrmLogInteractionTool::new(Arc::clone(&store))
            .run(
                &json!({
                    "party_id": party.id,
                    "kind": "note",
                    "at": "2026-10-17T09:00:00Z",
                    "source_ref": "{\"owner\":true}",
                    "summary": "Said on a call",
                    "memory": [{"kind": "note", "title": "Note", "body": "likes tea"}],
                }),
                &tainted(),
            )
            .await
            .unwrap();
        assert!(
            !note.is_error && !log.is_error,
            "{} {}",
            note.content,
            log.content
        );
        // The skill connector sees the same taint, so its write is quarantined.
        let skill = aux_runtime::executor::SkillContext {
            name: "log-interaction".to_string(),
            version: 1,
            hash: "abc".to_string(),
            tainted: true,
        };
        CrmSkillConnector::new("/tmp", "clients", Arc::clone(&store))
            .call(
                &skill,
                "crm.add_note",
                &json!({"party_id": party.id, "note": "from a skill"}),
            )
            .await
            .unwrap();
        let guard = store.lock().unwrap();
        // The card never shows either: a tainted write is not owner memory.
        assert!(guard
            .memory_items_for_party("clients", party.id, 10)
            .unwrap()
            .is_empty());
        assert!(guard
            .memory_items_for_party_card(party.id)
            .unwrap()
            .is_empty());
        let items = guard.memory_items_for_agent("clients", 10).unwrap();
        assert_eq!(items.len(), 3, "{items:?}");
        assert!(items
            .iter()
            .all(|item| item.state == "quarantined" && item.tainted && item.trust == "tainted"));
        let timeline = guard.interactions_for_party(party.id).unwrap();
        assert!(timeline.iter().all(|row| row.tainted), "{timeline:?}");
    }

    #[test]
    fn a_note_written_in_the_same_second_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let party_id = {
            let store = Store::open(&path).unwrap();
            Crm::new(&store).create(party()).unwrap().id
        };
        let mut n = 0;
        let mut write = || {
            n += 1;
            let args = AddNoteArgs {
                party_id: Some(party_id),
                name: None,
                note: format!("prefers mornings {n}"),
            };
            add_note(
                &Store::open(&path).unwrap(),
                "clients",
                &args,
                false,
                "2026-10-30T14:00:00Z",
            )
            .unwrap()
        };
        // Three separate opens: the in-memory counter would restart each time.
        let written = [write(), write(), write()];
        assert!(
            written.iter().all(|note| note["interaction_id"].is_i64()),
            "{written:?}"
        );
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.interactions_for_party(party_id).unwrap().len(),
            3,
            "same-second notes across restarts are three rows"
        );
    }
}
