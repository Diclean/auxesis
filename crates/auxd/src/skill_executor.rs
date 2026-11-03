//! Daemon wiring: the pieces that connect `aux_runtime::executor` to the real
//! connectors and the daemon's approval channel.
//!
//! The executor itself is transport-agnostic. This module supplies the
//! production connectors — the native mail send (SMTP), the EventKit create
//! through the Mac bridge, and, behind cargo feature `google`, the frozen
//! Google writes — and re-exports the approval bridge the executor and the
//! engine share:
//!
//! * [`CompositeSkillConnector`] — dispatches a skill call to the connector
//!   that serves its logical tool, exactly once.
//! * [`BrokerCardApprover`] — turns the executor's `ApprovalCard` into the
//!   daemon's existing `ApprovalRequest` so the Mac/Telegram channel shows one
//!   card for the run and its answer drives the executor.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aux_docs::{run_collect_receipts, CollectReport, StoreEvidence};
use aux_engine::ChatSession;
use aux_runtime::executor::{
    ConnectorError, FoundEvent, FoundEventFacts, MailboxScan, MailboxSender, RecipientDirectory,
    SkillConnector, SkillContext, StoredDraft, SENDER_SCAN_LIMIT, UNCERTAIN_DRAFT,
};
#[cfg(feature = "google")]
use aux_runtime::skills::tool_map;
use kernel_broker::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::privacy::{
    admit, Context as PrivacyContext, Decision, Destination, ModeFn, PathId, PrivacyMode,
};
use serde_json::{json, Value};

pub use aux_runtime::executor::{card_arguments, edits_from_card, BrokerCardApprover};

#[cfg(feature = "google")]
use aux_google::tools::{GoogleTools, SkillContext as GoogleSkillContext};
#[cfg(feature = "google")]
use aux_google::MacConnection;
use aux_store::Store;

use crate::crm::CrmSkillConnector;
#[cfg(feature = "google")]
use kernel_core::budget::Budgets;

/// The connectors a turn offers to the skill runtime.
#[derive(Default)]
pub struct SkillConnectors {
    /// The frozen Google writes, when this Mac is connected and the feature is on.
    #[cfg(feature = "google")]
    pub google: Option<GoogleTools>,
    /// The native mail tools (B19/B20/B22), when the home configures a mailbox.
    pub mail: Option<aux_mail::MailToolset>,
    /// The Mac bridge, for the EventKit create (B21).
    pub bridge: Option<Arc<crate::bridge::Bridge>>,
    /// The owner's account address, used as the invite `ORGANIZER`.
    pub owner_email: Option<String>,
    /// The live privacy mode, read at the mail send boundary (B20).
    pub mode: Option<ModeFn>,
    /// The local `docs.ingest` receipts collector (C1).
    pub docs: Option<DocsSkillConnector>,
    /// The local CRM follow-up write (B3).
    pub crm: Option<CrmSkillConnector>,
    /// The home whose EventKit snapshot the free-times read uses (M4-3b).
    pub calendar_home: Option<PathBuf>,
    /// The turn's store: the `mail.draft` rows a send-draft run claims.
    pub store: Option<Arc<Mutex<Store>>>,
}

/// The Google tools a skill connector runs on, when this Mac has Google
/// connected. `None` leaves the session without a Google connector: a skill
/// that writes then refuses with `skill_no_connector` (fail closed).
#[cfg(feature = "google")]
pub fn connected_google(
    home: &std::path::Path,
    store: Arc<Mutex<Store>>,
    budgets: Budgets,
) -> Option<GoogleTools> {
    let connection = MacConnection::at(home);
    if !connection.connected() {
        return None;
    }
    let client = connection.client().ok()?;
    GoogleTools::new(Arc::new(client), store, budgets).ok()
}

/// Attach the skill runtime to a chat session: the connector(s) for this turn
/// and the `known-contacts` directory. The daemon's turn path and the wiring
/// tests both come through here.
pub fn attach_skill_runtime<'a>(
    session: ChatSession<'a>,
    connectors: SkillConnectors,
    agent: &str,
    workspace: PathBuf,
    run_id: Option<String>,
    contacts: Arc<dyn RecipientDirectory>,
) -> ChatSession<'a> {
    let session = session.with_skill_recipients(contacts);
    let composite = build_connector(connectors, agent, workspace, run_id);
    match composite {
        Some(connector) => session.with_skill_connector(Arc::new(connector)),
        None => session,
    }
}

/// The known-contacts directory plus each client's stored IANA time zone
/// (CLIENT-TZ-FIELD).
///
/// The recipient policy is the kernel index's, unchanged; the zone map only
/// answers the invite's attendee. A directory built from a store with no zones
/// behaves exactly like the old one: the model's `attendee_time_zone` stays.
pub struct ContactsWithZones {
    contacts: aux_runtime::known_names::Contacts,
    zones: HashMap<String, String>,
}

impl ContactsWithZones {
    /// `zones` is `(address, IANA zone)` as [`aux_crm::Crm::client_time_zones`]
    /// reads it; an address is matched case-insensitively.
    pub fn new(contacts: aux_runtime::known_names::Contacts, zones: Vec<(String, String)>) -> Self {
        let zones = zones
            .into_iter()
            .map(|(address, zone)| (address.trim().to_ascii_lowercase(), zone))
            .collect();
        Self { contacts, zones }
    }

    /// The directory of `store`: every live client's stored zone. A store read
    /// that fails leaves no zones, so the model's argument is used, never a
    /// guess.
    pub fn from_store(contacts: aux_runtime::known_names::Contacts, store: &Store) -> Self {
        let zones = aux_crm::Crm::new(store)
            .client_time_zones()
            .unwrap_or_default();
        Self::new(contacts, zones)
    }
}

impl RecipientDirectory for ContactsWithZones {
    fn is_known(&self, value: &str) -> bool {
        self.contacts.is_known(value)
    }

    fn addresses_for_name(&self, name: &str) -> Vec<String> {
        self.contacts.addresses_for_name(name)
    }

    fn name_groups(&self) -> Vec<Vec<String>> {
        self.contacts.name_groups()
    }

    fn time_zone_for(&self, address: &str) -> Option<String> {
        self.zones
            .get(&address.trim().to_ascii_lowercase())
            .cloned()
    }
}

/// The local `docs.ingest` dispatch: run the deterministic receipts collector
/// over the skill's date window and return its counts. No model is involved.
pub struct DocsSkillConnector {
    home: PathBuf,
    store: Arc<Mutex<Store>>,
    mail: Arc<dyn aux_mail::MailApi>,
}

impl DocsSkillConnector {
    /// Serve `docs.ingest` for `home`'s evidence registry over `mail`.
    pub fn new(
        home: impl Into<PathBuf>,
        store: Arc<Mutex<Store>>,
        mail: Arc<dyn aux_mail::MailApi>,
    ) -> Self {
        Self {
            home: home.into(),
            store,
            mail,
        }
    }
}

#[async_trait]
impl SkillConnector for DocsSkillConnector {
    async fn call(
        &self,
        _skill: &SkillContext,
        logical: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, ConnectorError> {
        if logical != "docs.ingest" {
            return Err(ConnectorError::new(format!("no connector for `{logical}`")));
        }
        // The account is optional: the model never sees a slug, so a fill that
        // names one is a guess (DOC-COLLECT-1). A fill that names none reads
        // EVERY configured mailbox, one after another; a named account this
        // Mac does not have is still refused with the list.
        let ids = self.mail.account_ids();
        let named = arguments.get("account").and_then(serde_json::Value::as_str);
        let accounts: Vec<String> = match named {
            Some(named) => {
                vec![aux_mail::tools::resolve_account(&ids, Some(named))
                    .map_err(ConnectorError::new)?]
            }
            None if ids.is_empty() => return Err(ConnectorError::new("no mailbox is configured")),
            None => ids.clone(),
        };
        let folder = arguments
            .get("folder")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("INBOX");
        let days = arguments
            .get("days")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(30)
            .min(u64::from(u32::MAX)) as u32;
        let mut report = CollectReport::default();
        for account in &accounts {
            let evidence: Arc<dyn aux_mail::EvidenceSink> = Arc::new(StoreEvidence::new(
                self.home.clone(),
                Arc::clone(&self.store),
            ));
            let one = run_collect_receipts(Arc::clone(&self.mail), evidence, account, folder, days)
                .await
                .map_err(|err| ConnectorError::new(err.to_string()))?;
            report.messages += one.messages;
            report.new += one.new;
            report.deduplicated += one.deduplicated;
            report.skipped.extend(one.skipped);
        }
        serde_json::to_value(report).map_err(|err| ConnectorError::new(err.to_string()))
    }
}

/// Build the one connector the session uses, or `None` when no surface is
/// available.
fn build_connector(
    connectors: SkillConnectors,
    agent: &str,
    workspace: PathBuf,
    run_id: Option<String>,
) -> Option<CompositeSkillConnector> {
    let mode = connectors
        .mode
        .clone()
        .unwrap_or_else(|| Arc::new(|| PrivacyMode::Private));
    let draft_store = connectors.store.clone();
    let mail = connectors.mail.map(|mail| {
        let connector = MailSkillConnector::new(
            mail,
            connectors.bridge.clone(),
            connectors.owner_email.clone().unwrap_or_default(),
            Arc::clone(&mode),
        );
        match &draft_store {
            Some(store) => connector.with_store(Arc::clone(store)),
            None => connector,
        }
    });
    let docs = connectors.docs;
    let crm = connectors.crm;
    let calendar_home = connectors.calendar_home;
    #[cfg(not(feature = "google"))]
    {
        // Only the frozen Google connector needs the agent/workspace/run scope.
        let _ = (agent, workspace, run_id);
    }
    #[cfg(feature = "google")]
    let google = connectors
        .google
        .map(|google| GoogleSkillConnector::new(google, agent, workspace.clone(), run_id.clone()));
    #[cfg(feature = "google")]
    let has_google = google.is_some();
    #[cfg(not(feature = "google"))]
    let has_google = false;

    if mail.is_none() && docs.is_none() && crm.is_none() && !has_google {
        return None;
    }
    Some(CompositeSkillConnector {
        mail,
        docs,
        crm,
        calendar_home,
        #[cfg(feature = "google")]
        google,
    })
}

/// The vault directory below the verified home.
pub fn vault_dir(home: &std::path::Path) -> PathBuf {
    home.join("vault")
}

/// The Google tool's wire shape for a skill call's arguments.
///
/// The model-facing schema (`tool_map`) names each attendee `{ "email" }`, so
/// the recipient policy checks the address there. The Google tool takes plain
/// address strings, so the object form is flattened here, at the connector.
#[cfg(feature = "google")]
fn connector_arguments(logical: &str, arguments: &Value) -> Value {
    let mut value = arguments.clone();
    if logical == "google.calendar.create_event" {
        if let Some(attendees) = value.get_mut("attendees").and_then(|a| a.as_array_mut()) {
            for attendee in attendees.iter_mut() {
                if let Some(email) = attendee.get("email").cloned() {
                    *attendee = email;
                }
            }
        }
    }
    value
}

/// The one connector the session uses: mail send (SMTP), the EventKit create
/// through the bridge, and, behind the feature, the Google writes.
struct CompositeSkillConnector {
    mail: Option<MailSkillConnector>,
    docs: Option<DocsSkillConnector>,
    crm: Option<CrmSkillConnector>,
    calendar_home: Option<PathBuf>,
    #[cfg(feature = "google")]
    google: Option<GoogleSkillConnector>,
}

#[async_trait]
impl SkillConnector for CompositeSkillConnector {
    async fn call(
        &self,
        skill: &SkillContext,
        logical: &str,
        arguments: &Value,
    ) -> Result<Value, ConnectorError> {
        if logical == "docs.ingest" {
            let Some(docs) = &self.docs else {
                return Err(ConnectorError::new(
                    "this Mac has no receipts collector mounted",
                ));
            };
            return docs.call(skill, logical, arguments).await;
        }
        if logical.starts_with("crm.") {
            let Some(crm) = &self.crm else {
                return Err(ConnectorError::new(format!("no connector for `{logical}`")));
            };
            return crm.call(skill, logical, arguments).await;
        }
        if logical == "docs.queue" {
            // B4 leaves the documents queue as an empty read hook; C4 fills it
            // with the receipts waiting to be checked (`docs/phase1.md` §5).
            // Nothing is written here.
            return Ok(json!({ "items": [] }));
        }
        if logical == aux_runtime::skills::free_times::CALENDAR_READ {
            // M4-3b: the runtime's own read for the free times. Only each
            // event's start and end in `{from, to}` leave the snapshot; no
            // title, no attendee.
            let home = self
                .calendar_home
                .as_deref()
                .ok_or_else(|| ConnectorError::new("the calendar is not shared with Auxesis"))?;
            let snapshot = crate::apple_eventkit::read_snapshot(home)
                .filter(|snapshot| snapshot.authorized)
                .ok_or_else(|| ConnectorError::new("the calendar is not shared with Auxesis"))?;
            // The app publishes at most MAX_ITEMS events and now says when it
            // cut the list: either way a cut copy may have dropped a busy
            // event, so it is never read as complete.
            if snapshot.events_truncated
                || snapshot.events.len() >= crate::apple_eventkit::MAX_ITEMS
            {
                return Err(ConnectorError::new(
                    "the calendar is too full to read in full",
                ));
            }
            let instant = |value: Option<&Value>| {
                let text = value?.as_str()?;
                Some(chrono::DateTime::parse_from_rfc3339(text).ok()?.to_utc())
            };
            let (Some(from), Some(to)) =
                (instant(arguments.get("from")), instant(arguments.get("to")))
            else {
                return Err(ConnectorError::new(
                    "the calendar read needs a from and a to",
                ));
            };
            // Only the copy's own capture facts say what it
            // holds. A copy that is stale, from an older build, or whose
            // window misses any part of `{from, to}` may miss a busy event:
            // nothing is proposed. Never the file's mtime or zone math.
            let max_age = chrono::Duration::hours(crate::apple_eventkit::STALE_AFTER_HOURS);
            if !crate::apple_eventkit::snapshot_covers(
                &snapshot,
                from,
                to,
                chrono::Utc::now(),
                max_age,
            ) {
                return Err(ConnectorError::new(
                    "the calendar copy is out of date; open Auxesis so it refreshes",
                ));
            }
            // An event whose instants do not parse is kept: the runtime refuses it.
            let busy: Vec<Value> = snapshot
                .events
                .iter()
                .map(|event| json!({ "start": event.start, "end": event.end }))
                .filter(
                    |event| match (instant(event.get("start")), instant(event.get("end"))) {
                        (Some(start), Some(end)) => start < to && end > from,
                        _ => true,
                    },
                )
                .collect();
            return Ok(Value::Array(busy));
        }
        if logical == "mail.send" || logical.starts_with("calendar.") {
            if let Some(mail) = &self.mail {
                return mail.call(skill, logical, arguments).await;
            }
        }
        #[cfg(feature = "google")]
        if let Some(google) = &self.google {
            return google.call(skill, logical, arguments).await;
        }
        Err(ConnectorError::new(format!("no connector for `{logical}`")))
    }

    /// CAL-UPDATE-1: the event an update names, in the calendar copy: by id,
    /// else by a title matching exactly one; an unknown id alone keeps its card.
    /// Its guests are known only from a fresh copy that lists them (Seal B r1).
    /// CAL-DEFAULT-ID: only an event found **by id** can be proved to sit on
    /// the owner's default calendar, by comparing the calendar ids it holds.
    /// CAL-DEFAULT-ID (r2): a recurring event, or a detached occurrence of
    /// one, is never proved: EventKit's lookup can return the first
    /// occurrence, not the one the copy saw.
    fn find_event(&self, arguments: &Value) -> FoundEvent {
        use crate::apple_eventkit::EventItem;
        let home = self.calendar_home.as_deref();
        let snapshot = home.and_then(crate::apple_eventkit::read_snapshot);
        let snapshot = snapshot.filter(|snapshot| snapshot.authorized);
        let events = snapshot.as_ref().map_or(&[][..], |s| s.events.as_slice());
        let fresh = snapshot.as_ref().is_some_and(|snapshot| {
            crate::apple_eventkit::snapshot_age(snapshot, chrono::Utc::now()).fresh
        });
        let default_calendar_id = snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.default_calendar_id.as_deref());
        let found = |event: &EventItem, by_id: bool| FoundEventFacts {
            id: event.id.clone().unwrap_or_default(),
            guests: event.attendees.as_ref().filter(|_| fresh).map(Vec::len),
            calendar: event.calendar.clone(),
            calendar_id: event.calendar_id.clone(),
            in_default_calendar: by_id
                && !event.recurring.unwrap_or(false)
                && match (event.calendar_id.as_deref(), default_calendar_id) {
                    (Some(event_id), Some(default_id)) => event_id == default_id,
                    _ => false,
                },
        };
        let title = arguments.get("find_title").and_then(Value::as_str);
        if let Some(id) = arguments.get("event_id").and_then(Value::as_str) {
            // A named id is that event or none; it never falls back
            // to a title match on another event.
            let known = events.iter().find(|event| event.id.as_deref() == Some(id));
            return match (known, title) {
                (Some(known), _) => Ok(Some(found(known, true))),
                (None, Some(_)) => Err("calendar bridge: event_not_found".to_string()),
                (None, None) => Ok(None),
            };
        }
        let Some(title) = title else {
            return Ok(None);
        };
        // The exact title: case, spacing and apostrophes count.
        let same = |event: &&EventItem| event.id.is_some() && event.title == title.trim();
        match events.iter().filter(same).collect::<Vec<_>>().as_slice() {
            [one] => Ok(Some(found(one, false))),
            [] => Err("no event in the calendar has that title".to_string()),
            _ => Err("several events have that title: give the event's id".to_string()),
        }
    }

    fn account_ids(&self) -> Vec<String> {
        self.mail
            .as_ref()
            .map(|mail| mail.account_ids())
            .unwrap_or_default()
    }

    async fn received_senders(&self) -> Option<MailboxScan> {
        match &self.mail {
            Some(mail) => mail.received_senders().await,
            None => None,
        }
    }

    fn mail_draft(&self, id: i64) -> Result<Option<StoredDraft>, String> {
        match &self.mail {
            Some(mail) => mail.mail_draft(id),
            None => Ok(None),
        }
    }
}

/// The A2b write through the Mac bridge, as a native tool (B21).
///
/// `auxd` cannot call EventKit; this tool publishes one `eventkit.create_event`
/// frame and waits for the app's answer. The attribute is skill-only and the
/// broker's floor refuses a plain-conversation call before the bridge is
/// reached.
pub struct EventkitCreateTool {
    bridge: Arc<crate::bridge::Bridge>,
}

impl EventkitCreateTool {
    /// A tool over one bridge.
    pub fn new(bridge: Arc<crate::bridge::Bridge>) -> Self {
        Self { bridge }
    }
}

impl NativeTool for EventkitCreateTool {
    fn native_name(&self) -> &'static str {
        "apple_calendar_create_event"
    }
    fn native_description(&self) -> &'static str {
        "Create one event in the owner's Apple Calendar through the Auxesis app. \
         Skill-only: it can never run outside an approved skill."
    }
    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            json!({
                "type": "object",
                "properties": {
                    "calendar": { "type": "string" },
                    "title": { "type": "string" },
                    "start": { "type": "string" },
                    "end": { "type": "string" },
                    "location": { "type": "string" },
                    "notes": { "type": "string" },
                    "url": { "type": "string" }
                },
                "required": ["title", "start"],
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for EventkitCreateTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B21
    }
    fn name(&self) -> &str {
        self.native_name()
    }
    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }
    async fn run(&self, args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let result = self
            .bridge
            .call(crate::bridge::BridgeOp::EventkitCreateEvent, args.clone())
            .await
            .map_err(|err| ToolError::fetch(format!("calendar bridge: {}", err.code())))?;
        Ok(ToolOutput::ok(result.to_string()))
    }
    fn risk(&self) -> Risk {
        Risk::High
    }
    fn class(&self) -> ToolClass {
        ToolClass {
            skill_only: true,
            requires_explicit_rule: true,
            output_trust: kernel_broker::Trust::Trusted,
            // The acknowledgement carries only an opaque event id and calendar.
            returns_private_data: false,
            ..ToolClass::default()
        }
    }
}

/// Register the EventKit create tool on the turn's registry when a bridge is
/// present. The broker's floor then refuses a plain call to it.
pub fn register_eventkit_tools(
    bridge: Arc<crate::bridge::Bridge>,
    registry: &mut kernel_broker::ToolRegistry,
) {
    registry.register_native(Box::new(EventkitCreateTool::new(bridge)));
}

/// The bridge arguments of a calendar write: the fields the card shows (M4-2)
/// and the update's search fields stay out of the writer.
fn bridge_arguments(arguments: &Value) -> Value {
    let mut event = arguments.clone();
    if let Some(map) = event.as_object_mut() {
        let card = "time_zone attendee_time_zone attendee_time_zone_source attendee_start \
                    start_utc end_utc guests event_calendar event_calendar_id \
                    event_default_calendar find_title";
        for field in card.split_whitespace() {
            map.remove(field);
        }
    }
    event
}

/// The facts the write's approval rested on (CAL-DEFAULT-ID r1).
///
/// An approval-free move is free only while the event still sits on the
/// owner's default calendar and still has no guest. The copy that decided it
/// may be stale, so the facts travel with the write and the app checks them
/// against the live event before it saves. No proof, no expectations: a write
/// that already had the owner's card is not checked twice.
fn expected_facts(arguments: &Value) -> Option<(String, u64)> {
    let free_move = arguments.get("event_default_calendar") == Some(&Value::Bool(true))
        && arguments.get("guests").and_then(Value::as_u64) == Some(0);
    if !free_move {
        return None;
    }
    let calendar_id = arguments
        .get("event_calendar_id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())?;
    Some((calendar_id.to_string(), 0))
}

/// One `eventkit.update_event` (CAL-UPDATE-1), the card-only fields dropped.
/// An id the calendar does not hold is the typed `event_not_found`; every
/// other failure is the bridge's own code.
///
/// CAL-DEFAULT-ID (r1): the app answers `facts_changed` when the live event
/// no longer matches the facts the copy held. Nothing was written, so the
/// owner decides with the normal card instead of the run failing silently.
async fn update_event_through(
    bridge: &crate::bridge::Bridge,
    arguments: &Value,
) -> Result<Value, ConnectorError> {
    let op = crate::bridge::BridgeOp::EventkitUpdateEvent;
    let mut request = bridge_arguments(arguments);
    if let Some((calendar_id, attendees)) = expected_facts(arguments) {
        request["expected_calendar_id"] = json!(calendar_id);
        request["expected_attendees"] = json!(attendees);
    }
    let result = bridge.call(op, request).await;
    let result = result.map_err(|err| match err {
        crate::bridge::BridgeError::App { code, .. } if code == "not_found" => {
            ConnectorError::new("calendar bridge: event_not_found")
        }
        crate::bridge::BridgeError::App { code, .. } if code == "facts_changed" => {
            ConnectorError::new("the event's calendar or its guests changed").with_approval()
        }
        other => ConnectorError::new(format!("calendar bridge: {}", other.code())),
    })?;
    Ok(json!({ "content": result.to_string() }))
}

/// One created event, remembered between the calendar call and the mail call so
/// the runtime can build the invite from the **rehydrated** arguments.
struct StoredEvent {
    args: Value,
    event_id: String,
}

/// The mail/EventKit connector: `calendar.create_event` first, then `mail.send`
/// with the built `.ics`.
pub struct MailSkillConnector {
    mail: aux_mail::MailToolset,
    bridge: Option<Arc<crate::bridge::Bridge>>,
    owner_email: String,
    mode: ModeFn,
    /// The store holding `mail.draft` rows: absent in the tests that only send
    /// free-form skill mail, present whenever a send-draft run can reach here.
    store: Option<Arc<Mutex<Store>>>,
    event: Mutex<Option<StoredEvent>>,
}

impl MailSkillConnector {
    /// Serve the mail send and the EventKit create.
    pub fn new(
        mail: aux_mail::MailToolset,
        bridge: Option<Arc<crate::bridge::Bridge>>,
        owner_email: impl Into<String>,
        mode: ModeFn,
    ) -> Self {
        Self {
            mail,
            bridge,
            owner_email: owner_email.into(),
            mode,
            store: None,
            event: Mutex::new(None),
        }
    }

    /// Bind the local store a `send-draft` run claims from.
    pub fn with_store(mut self, store: Arc<Mutex<Store>>) -> Self {
        self.store = Some(store);
        self
    }

    /// Run one SMTP submission through the mail API.
    ///
    /// The typed `MailError` is kept here so the executor can write one
    /// `mail.call` row with a stable error kind, then the success path returns
    /// the safe outcome metadata beside the model-facing acknowledgement.
    async fn send_mail(&self, arguments: &Value) -> Result<Value, ConnectorError> {
        // The executor rehydrates every argument before the approval card; a
        // token here means a value never became real, so refuse before any
        // socket rather than mail a `⟦token⟧`.
        if contains_token(arguments) {
            return Err(
                ConnectorError::new("the mail still carries a token; refusing to send it")
                    .with_ledger(json!({"kind": "token", "outcome": "refused"})),
            );
        }
        let to = string_list(arguments.get("to"));
        let cc = string_list(arguments.get("cc"));
        let subject = arguments
            .get("subject")
            .and_then(Value::as_str)
            .ok_or_else(|| ConnectorError::new("the mail has no subject"))?;
        let body = arguments
            .get("body")
            .and_then(Value::as_str)
            .ok_or_else(|| ConnectorError::new("the mail has no body"))?;
        let ics = arguments
            .get("ics")
            .and_then(Value::as_str)
            .map(str::to_string);
        let account = self.resolve_account(arguments)?;

        // B20: the kernel gate runs before the socket, once per to and cc
        // recipient. In Private the row is `AskEachTime(FilteredRecipients)`:
        // the run card is the owner's approval and the executor already
        // filtered every recipient against the known-contacts directory, so an
        // `Ask` is satisfied here. One `Deny`, or no recipient at all, refuses
        // the whole send; the executor writes the `mail.call` row.
        if let Err(why) = admit_every_recipient(&to, &cc, |recipient| {
            admit(
                PathId::B20,
                (self.mode)(),
                &PrivacyContext {
                    destination: Destination::Recipient(recipient.to_string()),
                },
            )
        }) {
            return Err(ConnectorError::new(why).with_ledger(json!({
                "kind": "blocked",
                "outcome": "refused",
                "account": account,
            })));
        }

        // send-draft: claim the stored draft before the socket. The claim is
        // what makes a replay or a second approval impossible; a failed send
        // releases it so the draft stays retryable.
        let claimed = match arguments.get("draft_id").and_then(Value::as_i64) {
            Some(id) => {
                let Some(store) = &self.store else {
                    return Err(ConnectorError::new(
                        "send-draft needs the local draft store; nothing was sent",
                    )
                    .with_ledger(json!({"kind": "draft", "outcome": "refused"})));
                };
                let claim = kernel_core::lock_recover(store).claim_mail_draft(id);
                match claim {
                    Ok(Some(draft)) => Some((id, draft)),
                    Ok(None) => {
                        return Err(ConnectorError::new(
                            "no saved draft with that id (or it was already sent); nothing was sent",
                        )
                        .with_ledger(json!({"kind": "draft", "outcome": "refused"})));
                    }
                    Err(_) => {
                        return Err(ConnectorError::new(
                            "the local draft store could not be read; nothing was sent",
                        )
                        .with_ledger(json!({"kind": "draft", "outcome": "refused"})));
                    }
                }
            }
            None => None,
        };
        if let Some((id, draft)) = &claimed {
            let unchanged = draft.to == to
                && draft.subject == subject
                && draft.body == body
                && !draft.to.is_empty();
            if !unchanged {
                if let Some(store) = &self.store {
                    let _ = kernel_core::lock_recover(store).release_mail_draft(*id);
                }
                return Err(ConnectorError::new(
                    "the saved draft changed after the card; nothing was sent",
                )
                .with_ledger(json!({"kind": "draft", "outcome": "refused"})));
            }
        }

        let mail = aux_mail::OutgoingMail {
            // The service replaces this with the account's own address.
            from: String::new(),
            to,
            cc,
            subject: subject.to_string(),
            body: body.to_string(),
            ics,
        };
        let has_ics = mail.ics.is_some();
        let api = self.mail.api();
        match api.send(&account, &mail).await {
            Ok(outcome) => {
                if let (Some((id, _)), Some(store)) = (&claimed, &self.store) {
                    let _ = kernel_core::lock_recover(store).mark_mail_draft_sent(*id);
                }
                Ok(json!({
                    "content": json!({"sent": true, "accepted": outcome.accepted}).to_string(),
                    "mail_call": {
                        "account": account,
                        "accepted": outcome.accepted,
                        "bytes": outcome.bytes,
                        "reply_class": outcome.reply_class,
                        "ics": has_ics,
                    },
                }))
            }
            Err(error) => {
                // Post-DATA failures may have been accepted: keep the claim as
                // `uncertain` so no retry can send the same draft twice. Only a
                // definitive pre-DATA failure releases it for a retry.
                let uncertain = matches!(error, aux_mail::MailError::Uncertain);
                if let (Some((id, _)), Some(store)) = (&claimed, &self.store) {
                    let store = kernel_core::lock_recover(store);
                    let _ = if uncertain {
                        store.mark_mail_draft_uncertain(*id)
                    } else {
                        store.release_mail_draft(*id)
                    };
                }
                let detail = if uncertain {
                    UNCERTAIN_DRAFT.to_string()
                } else {
                    error.to_string()
                };
                Err(ConnectorError::new(detail).with_ledger(json!({
                    "kind": error.kind(),
                    "reply_class": error.reply_class(),
                    "account": account,
                })))
            }
        }
    }

    /// The validated, configured account slug a `mail.send` goes out of.
    ///
    /// The executor resolved the account before the card, so the arguments
    /// name the mailbox the owner approved. An account this Mac does not have
    /// is refused here: the first configured account is never picked, and the
    /// raw argument never reaches a Ledger row.
    fn resolve_account(&self, arguments: &Value) -> Result<String, ConnectorError> {
        let ids = self.mail.api().account_ids();
        let named = arguments
            .get("account")
            .and_then(Value::as_str)
            .filter(|account| !account.is_empty());
        let account = match named {
            Some(account)
                if aux_mail::is_account_slug(account) && ids.iter().any(|id| id == account) =>
            {
                Some(account.to_string())
            }
            // A name this Mac does not have is refused; a send that names none
            // is refused unless this Mac has exactly one mailbox. The first
            // configured account is never picked.
            Some(_) => None,
            None => match ids.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            },
        };
        match account {
            Some(account) => Ok(account),
            None => Err(
                ConnectorError::new("this send does not name a configured mailbox").with_ledger(
                    json!({
                        "kind": "invalid_field",
                        "reply_class": "none",
                        "account": "unknown",
                    }),
                ),
            ),
        }
    }

    /// Publish one `eventkit.create_event` through the bridge and remember it.
    async fn create_event(&self, arguments: &Value) -> Result<Value, ConnectorError> {
        let bridge = self
            .bridge
            .as_ref()
            .ok_or_else(|| ConnectorError::new("the calendar bridge is unavailable"))?;
        // M4-2: the card's zone fields stay for the `.ics`, not the bridge.
        let result = bridge
            .call(
                crate::bridge::BridgeOp::EventkitCreateEvent,
                bridge_arguments(arguments),
            )
            .await
            .map_err(|err| ConnectorError::new(format!("calendar bridge: {}", err.code())))?;
        let event_id = result
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ConnectorError::new("the calendar bridge returned no event id"))?
            .to_string();
        *self
            .event
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(StoredEvent {
            args: arguments.clone(),
            event_id,
        });
        Ok(json!({ "content": result.to_string() }))
    }

    /// Build the `.ics` from the stored event and the real mail arguments.
    fn build_invite(&self, arguments: &Value) -> Result<String, ConnectorError> {
        let event = self
            .event
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| ConnectorError::new("no event was created for this invite"))?;
        let recipient = arguments
            .get("to")
            .and_then(Value::as_array)
            .and_then(|to| to.first())
            .and_then(Value::as_str)
            .ok_or_else(|| ConnectorError::new("the invite has no recipient"))?;
        if self.owner_email.is_empty() {
            return Err(ConnectorError::new("the owner's mail account is unknown"));
        }
        let title = event
            .args
            .get("title")
            .and_then(Value::as_str)
            .ok_or_else(|| ConnectorError::new("the event has no title"))?;
        let invite = aux_mail::Invite {
            uid: format!("{}@auxesis.local", event.event_id),
            summary: title.to_string(),
            start_utc: shown_instant(&event.args, "start")?,
            end_utc: shown_instant(&event.args, "end")?,
            dtstamp_utc: chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
            organizer_email: self.owner_email.clone(),
            organizer_name: None,
            attendee_email: recipient.to_string(),
            attendee_name: None,
            location: event
                .args
                .get("location")
                .and_then(Value::as_str)
                .map(str::to_string),
            description: event
                .args
                .get("notes")
                .and_then(Value::as_str)
                .map(str::to_string),
        };
        aux_mail::build_request_ics(&invite)
            .map_err(|err| ConnectorError::new(format!("the invite could not be built: {err}")))
    }
}

/// Most Sent To/Cc addresses one trust lookup keeps; a truncated set only
/// ever narrows who is trusted.
const WRITTEN_TO_LIMIT: usize = 2000;

/// The address of a `Name <address>` header, or the whole trimmed value.
fn header_address(raw: &str) -> &str {
    let raw = raw.trim();
    raw.strip_suffix('>')
        .and_then(|rest| rest.rsplit_once('<'))
        .map_or(raw, |(_, address)| address.trim())
}

/// Compare owner addresses as one: lowercase, drop a `+tag`, and fold Gmail's
/// dots and `googlemail.com` alias. A mail sent to the owner is never a
/// recipient candidate.
fn owner_address_key(address: &str) -> String {
    let address = address.trim().to_ascii_lowercase();
    let Some((local, domain)) = address.split_once('@') else {
        return address;
    };
    let local = local.split_once('+').map_or(local, |(base, _)| base);
    let gmail = domain == "gmail.com" || domain == "googlemail.com";
    let local = if gmail {
        local.replace('.', "")
    } else {
        local.to_string()
    };
    let domain = if gmail { "gmail.com" } else { domain };
    format!("{local}@{domain}")
}

#[async_trait]
impl SkillConnector for MailSkillConnector {
    async fn call(
        &self,
        _skill: &SkillContext,
        logical: &str,
        arguments: &Value,
    ) -> Result<Value, ConnectorError> {
        match logical {
            "calendar.create_event" => self.create_event(arguments).await,
            "calendar.update_event" => match &self.bridge {
                Some(bridge) => update_event_through(bridge, arguments).await,
                None => Err(ConnectorError::new("the calendar bridge is unavailable")),
            },
            "mail.send" => {
                let mut arguments = arguments.clone();
                // The card names `invite.ics` only for a non-empty `ics`, so an
                // empty or non-text one is refused, never sent as an invite the
                // card did not show (SEND-REAL-ARGS-1).
                if let Some(marker) = arguments.get("ics") {
                    if !marker.as_str().is_some_and(|ics| !ics.is_empty()) {
                        return Err(ConnectorError::new(
                            "the invite marker is empty: refusing the send",
                        ));
                    }
                    let ics = self.build_invite(&arguments)?;
                    if let Some(map) = arguments.as_object_mut() {
                        map.insert("ics".to_string(), Value::String(ics));
                    }
                }
                self.send_mail(&arguments).await
            }
            other => Err(ConnectorError::new(format!("no connector for `{other}`"))),
        }
    }

    fn account_ids(&self) -> Vec<String> {
        self.mail.api().account_ids()
    }

    /// MAIL-UNKNOWN-CONTACT-1: the `From` of the newest INBOX mails, read
    /// locally (no body, nothing to a model). A capped scan or an unreadable
    /// mailbox marks the scan partial: a lone match then only asks. The To/Cc
    /// of a readable Sent folder give the trust bar its "owner wrote to them"
    /// set; a Sent folder outside `only_folders` is never opened, and a scan
    /// where any configured Sent folder is unreadable carries no set at all.
    ///
    /// The owner's own addresses are dropped before matching: a mail sent to
    /// themself is never a recipient candidate.
    async fn received_senders(&self) -> Option<MailboxScan> {
        let api = self.mail.api();
        let accounts = api.account_ids();
        if accounts.is_empty() {
            return None;
        }
        let mut complete = true;
        let mut senders = Vec::new();
        let mut written_to: Vec<String> = Vec::new();
        let mut sent_readable = 0usize;
        for account in &accounts {
            match api.list_headers(account, None, SENDER_SCAN_LIMIT).await {
                Ok(headers) => {
                    // A full page may be the whole INBOX or its first page;
                    // only the next page could tell, so it is never unique.
                    if headers.len() >= SENDER_SCAN_LIMIT {
                        complete = false;
                    }
                    senders.extend(headers.iter().map(|item| {
                        let from = item.from.trim();
                        let split = from
                            .strip_suffix('>')
                            .and_then(|rest| rest.rsplit_once('<'));
                        let (name, address) = split.unwrap_or(("", from));
                        let day = chrono::DateTime::parse_from_rfc2822(item.date.trim())
                            .map(|date| date.format("%-d %b").to_string())
                            .unwrap_or_default();
                        let name = name.trim().trim_matches('"').to_string();
                        MailboxSender {
                            name,
                            address: address.trim().to_string(),
                            day,
                        }
                    }));
                }
                Err(_) => complete = false,
            }
            let Some(folder) = api.sent_folder(account) else {
                continue;
            };
            // A Sent read that fails is no signal: the scan then carries no
            // set, so nothing mailbox-derived is trusted.
            if let Ok(headers) = api
                .list_headers(account, Some(&folder), SENDER_SCAN_LIMIT)
                .await
            {
                sent_readable += 1;
                for item in &headers {
                    for header in item.to.iter().chain(item.cc.iter()) {
                        let address = header_address(header);
                        if address.contains('@')
                            && !written_to
                                .iter()
                                .any(|known| known.eq_ignore_ascii_case(address))
                        {
                            written_to.push(address.to_string());
                            if written_to.len() >= WRITTEN_TO_LIMIT {
                                break;
                            }
                        }
                    }
                }
            }
        }
        let owner = owner_address_key(&self.owner_email);
        let own: Vec<String> = api
            .account_addresses()
            .iter()
            .map(|address| owner_address_key(address))
            .collect();
        senders.retain(|sender| {
            let sender = owner_address_key(&sender.address);
            sender != owner && !own.contains(&sender)
        });
        // The set is only present when every configured mailbox's Sent folder
        // was readable; `None` refuses every mailbox-derived recipient.
        let written_to = (sent_readable == accounts.len()).then_some(written_to);
        Some(MailboxScan {
            senders,
            complete,
            written_to,
        })
    }

    fn mail_draft(&self, id: i64) -> Result<Option<StoredDraft>, String> {
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        let store = kernel_core::lock_recover(store);
        match store.mail_draft_state(id) {
            Ok(Some(state)) if state == "uncertain" => Err(UNCERTAIN_DRAFT.to_string()),
            Err(_) => Ok(None),
            Ok(_) => Ok(store
                .mail_draft_for_send(id)
                .ok()
                .flatten()
                .map(|draft| StoredDraft {
                    to: draft.to,
                    to_display: draft.to_display,
                    subject: draft.subject,
                    body: draft.body,
                })),
        }
    }
}

/// The Google-only connector over the two skill-only writes, bound per call.
#[cfg(feature = "google")]
pub struct GoogleSkillConnector {
    google: GoogleTools,
    agent: String,
    workspace: PathBuf,
    run_id: Option<String>,
}

#[cfg(feature = "google")]
impl GoogleSkillConnector {
    /// Serve the Google skill-only writes for `agent` in `workspace`.
    pub fn new(
        google: GoogleTools,
        agent: impl Into<String>,
        workspace: impl Into<PathBuf>,
        run_id: Option<String>,
    ) -> Self {
        GoogleSkillConnector {
            google,
            agent: agent.into(),
            workspace: workspace.into(),
            run_id,
        }
    }
}

#[cfg(feature = "google")]
#[async_trait]
impl SkillConnector for GoogleSkillConnector {
    async fn call(
        &self,
        skill: &SkillContext,
        logical: &str,
        arguments: &Value,
    ) -> Result<Value, ConnectorError> {
        let wire = tool_map::wire_name(logical)
            .ok_or_else(|| ConnectorError::new(format!("unknown tool `{logical}`")))?;
        let bound = GoogleSkillContext {
            name: skill.name.clone(),
            version: skill.version,
            hash: skill.hash.clone(),
        };
        let tools = self.google.skill_tools_for(&bound);
        let tool = tools
            .iter()
            .find(|tool| tool.name() == wire)
            .ok_or_else(|| ConnectorError::new(format!("no connector for `{wire}`")))?;
        let mut ctx = ToolCtx::new(self.agent.clone(), self.workspace.clone());
        ctx.run_id = self.run_id.clone();
        let output = tool
            .as_ref()
            .run(&connector_arguments(logical, arguments), &ctx)
            .await
            .map_err(|err| ConnectorError::new(err.to_string()))?;
        if output.is_error {
            return Err(ConnectorError::new(output.content));
        }
        // The result is a local value; the executor re-tokenises it before it
        // re-enters the conversation.
        Ok(json!({ "content": output.content }))
    }
}

/// The string entries of an optional JSON array (mail recipients).
/// Run the B20 gate for every `to` and `cc` recipient. `Allow` and `Ask` pass
/// (the run card satisfies an `Ask`); the first `Deny` refuses the whole send,
/// and so does an empty `to` list.
fn admit_every_recipient(
    to: &[String],
    cc: &[String],
    mut gate: impl FnMut(&str) -> Decision,
) -> Result<(), String> {
    if to.is_empty() {
        return Err("the mail has no recipient; refusing to send it".to_string());
    }
    for recipient in to.iter().chain(cc) {
        if let Decision::Deny(reason) = gate(recipient) {
            return Err(format!(
                "the privacy gate refused the mail send ({reason:?})"
            ));
        }
    }
    Ok(())
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// True when any string in `value` still carries a `⟦…⟧` token. The executor
/// rehydrates before the card, so a token here means a value never became real
/// and the send must be refused rather than mailed.
fn contains_token(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains('\u{27e6}') || text.contains('\u{27e7}'),
        Value::Array(items) => items.iter().any(contains_token),
        Value::Object(map) => map.values().any(contains_token),
        _ => false,
    }
}

/// The `<field>_utc` instant the card showed (M4-2), checked against the
/// card's own `<field>`: the `.ics` carries exactly the instant shown, and a
/// pair that disagrees refuses the invite.
fn shown_instant(args: &Value, field: &str) -> Result<String, ConnectorError> {
    let local = args
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ConnectorError::new(format!("the event has no {field}")))?;
    let shown = args
        .get(format!("{field}_utc"))
        .and_then(Value::as_str)
        .ok_or_else(|| ConnectorError::new(format!("the event has no resolved {field}")))?;
    if to_utc_compact(local)? != shown {
        return Err(ConnectorError::new(format!(
            "the event {field} and its UTC instant disagree; refusing the invite"
        )));
    }
    Ok(shown.to_string())
}

/// Parse an RFC 3339 instant and render it as the RFC 5545 UTC `Z` form.
fn to_utc_compact(value: &str) -> Result<String, ConnectorError> {
    let instant = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|_| ConnectorError::new("the event time is not an RFC 3339 instant"))?;
    Ok(instant
        .with_timezone(&chrono::Utc)
        .format("%Y%m%dT%H%M%SZ")
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_runtime::executor::{ApprovalCard, CardCall, RunDecision, SkillApprover};
    use aux_runtime::skills::Approval;
    use kernel_broker::{ApprovalDecision, ApprovalRequest, Approver, ApproverError};
    use std::sync::Mutex;

    /// A fake Mac app holding one calendar; an unknown id is `not_found`.
    fn calendar_app(
        home: &std::path::Path,
    ) -> (Arc<crate::bridge::Bridge>, Arc<Mutex<Vec<Value>>>) {
        let (events, mut receiver) = tokio::sync::broadcast::channel(16);
        let bridge = Arc::new(crate::bridge::Bridge::new(home.to_path_buf(), events));
        let calendar = Arc::new(Mutex::new(Vec::<Value>::new()));
        let (app, held) = (Arc::clone(&bridge), Arc::clone(&calendar));
        tokio::spawn(async move {
            while let Ok(text) = receiver.recv().await {
                let frame: Value = serde_json::from_str(&text).unwrap_or_default();
                let (Some(id), args) = (frame["id"].as_str(), &frame["args"]) else {
                    continue;
                };
                use crate::bridge::BridgeAnswer;
                let mut events = held.lock().unwrap();
                let answer = if frame["op"] == "eventkit.create_event" {
                    let mut event = args.clone();
                    event["event_id"] = json!(format!("evt-{}", events.len() + 1));
                    events.push(event.clone());
                    BridgeAnswer::Result(event)
                } else if let Some(event) = events
                    .iter_mut()
                    .find(|e| e["event_id"] == args["event_id"])
                {
                    let fields = args.as_object().into_iter().flatten();
                    fields.for_each(|(key, value)| event[key] = value.clone());
                    BridgeAnswer::Result(event.clone())
                } else {
                    let (code, message) = ("not_found".into(), "no such event".into());
                    BridgeAnswer::Error { code, message }
                };
                drop(events);
                app.answer(id, answer);
            }
        });
        (bridge, calendar)
    }

    #[tokio::test]
    async fn an_update_moves_the_created_event_once_and_a_bad_id_is_a_typed_error() {
        let home = tempfile::tempdir().unwrap();
        let (bridge, calendar) = calendar_app(home.path());
        let create = json!({ "title": "Call with Camille", "start": "2026-10-31T10:00:00+01:00",
            "end": "2026-10-31T10:30:00+01:00" });
        let op = crate::bridge::BridgeOp::EventkitCreateEvent;
        let made = bridge.call(op, create).await.unwrap();
        let moved = json!({ "event_id": made["event_id"], "start": "2026-10-31T15:00:00+01:00",
            "end": "2026-10-31T15:30:00+01:00", "start_utc": "20261031T140000Z",
            "end_utc": "20261031T143000Z", "time_zone": "Europe/Paris", "guests": 0 });
        for _ in 0..2 {
            update_event_through(&bridge, &moved).await.unwrap();
        }
        let listed = calendar.lock().unwrap().clone();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0]["start"], "2026-10-31T15:00:00+01:00");
        assert_eq!(listed[0]["end"], "2026-10-31T15:30:00+01:00");
        let refused = |result: Result<Value, ConnectorError>| result.unwrap_err().message;
        let unknown = json!({ "event_id": "evt-404", "title": "Lost" });
        let backwards = json!({ "event_id": "evt-1", "start": "2026-10-31T16:00:00+01:00",
            "end": "2026-10-31T15:00:00+01:00" });
        for (args, reason) in [(unknown, "event_not_found"), (backwards, "invalid_args")] {
            let error = refused(update_event_through(&bridge, &args).await);
            assert_eq!(error, format!("calendar bridge: {reason}"));
        }
        let empty = refused(update_event_through(&bridge, &json!({ "event_id": "" })).await);
        assert_eq!(empty, "calendar bridge: invalid_args");
        assert_eq!(calendar.lock().unwrap().clone(), listed);
    }

    /// The class of one update `args` against a calendar copy holding `events`,
    /// captured now (`Some(true)`), five hours ago (`Some(false)`) or at no
    /// stated time (`None`). `default_calendar` is the copy's default calendar
    /// id; `None` is a copy from a build that published none.
    fn update_class(
        events: Value,
        fresh: Option<bool>,
        default_calendar: Option<&str>,
        args: Value,
    ) -> Result<String, String> {
        let dir = tempfile::tempdir().unwrap();
        aux_store::Store::open(&kernel_core::store_path(dir.path())).unwrap();
        let at = |hours: i64| (chrono::Utc::now() + chrono::Duration::hours(hours)).to_rfc3339();
        let mut snapshot = json!({ "authorized": true, "events": events, "reminders": [],
            "covers_from": at(-24), "covers_to": at(24 * 7) });
        if let Some(fresh) = fresh {
            snapshot["captured_at"] = json!(at(if fresh { 0 } else { -5 }));
        }
        if let Some(default_calendar) = default_calendar {
            snapshot["default_calendar_id"] = json!(default_calendar);
        }
        let snapshot = serde_json::from_value(snapshot).unwrap();
        crate::apple_eventkit::save_snapshot(dir.path(), &snapshot).unwrap();
        let connector = CompositeSkillConnector {
            mail: None,
            docs: None,
            crm: None,
            calendar_home: Some(dir.path().to_path_buf()),
            #[cfg(feature = "google")]
            google: None,
        };
        let real =
            aux_runtime::executor::with_found_event(&connector, "calendar.update_event", args)?;
        let calls = json!({ "calls": [{ "tool": "apple_calendar_update_event", "real": real }] });
        let class = aux_engine::action::classify("skill__move-event", &calls, None);
        Ok(format!("{class:?}"))
    }

    /// One event of the copy, tomorrow; `guests: None` leaves its list out.
    fn copy_event(id: &str, title: &str, calendar: &str, guests: Option<Value>) -> Value {
        let at = |hours: i64| (chrono::Utc::now() + chrono::Duration::hours(hours)).to_rfc3339();
        let mut event = json!({ "id": id, "title": title, "start": at(24), "end": at(25),
            "calendar": calendar, "location": null });
        if let Some(guests) = guests {
            event["attendees"] = guests;
        }
        event
    }

    /// One event of the copy, on the calendar `calendar` whose id is
    /// `calendar_id` (CAL-DEFAULT-ID).
    fn event_on(id: &str, title: &str, calendar: &str, calendar_id: &str, guests: Value) -> Value {
        let mut event = copy_event(id, title, calendar, Some(guests));
        event["calendar_id"] = json!(calendar_id);
        event
    }

    #[test]
    fn an_update_of_an_event_with_guests_is_a_send_and_any_other_keeps_its_card() {
        let events = json!([
            copy_event("evt-team", "Call", "", Some(json!(["c@x.test"]))),
            copy_event("evt-own", "Focus", "", Some(json!([]))),
        ]);
        let run = |args: Value| update_class(events.clone(), Some(true), None, args);
        let ok = |class: &str| Ok(class.to_string());
        assert_eq!(run(json!({ "event_id": "evt-team" })), ok("Send"));
        // The model cannot say an event has no guests: Auxesis sets it.
        assert_eq!(
            run(json!({ "event_id": "evt-team", "guests": 0 })),
            ok("Send")
        );
        // CAL-PRIMARY-1: a blank calendar title is not the default calendar.
        let own = json!({ "event_id": "evt-own", "start": "2026-10-31T15:00:00Z" });
        assert_eq!(run(own), ok("Unknown"));
        assert_eq!(run(json!({ "event_id": "evt-far" })), ok("Unknown"));
        assert_eq!(run(json!({ "find_title": " Call " })), ok("Send"));
        // An unknown id never falls back to a title; titles are exact.
        let far = run(json!({ "event_id": "evt-far", "find_title": "Call" }));
        assert_eq!(far, Err("calendar bridge: event_not_found".to_string()));
        assert!(run(json!({ "find_title": "call" })).is_err());
        assert!(run(json!({ "title": "No event named" })).is_err());
    }

    /// CAL-DEFAULT-ID: Auxesis lifts the card for a move only when it found
    /// the event **by id**, on the owner's default calendar, with no guest.
    /// The calendar is known by id: a title, `primary` included, never frees a
    /// move, and a copy from a build that published no id keeps the card.
    #[test]
    fn a_move_is_free_only_for_an_own_event_found_by_id_on_the_default_calendar() {
        let events = json!([
            event_on("evt-own", "Focus", "Home", "CAL-1", json!([])),
            event_on("evt-guest", "Call", "Home", "CAL-1", json!(["c@x.test"])),
            event_on("evt-shared", "Review", "primary", "CAL-2", json!([])),
        ]);
        let run = |args: Value| update_class(events.clone(), Some(true), Some("CAL-1"), args);
        let ok = |class: &str| Ok(class.to_string());
        // The owner's own event, no guest, on the default calendar: free.
        assert_eq!(run(json!({ "event_id": "evt-own" })), ok("LocalWrite"));
        // A guest is a send, on the default calendar too.
        assert_eq!(run(json!({ "event_id": "evt-guest" })), ok("Send"));
        // A calendar titled `primary` is not the default one: its id differs.
        assert_eq!(run(json!({ "event_id": "evt-shared" })), ok("Unknown"));
        // The model cannot name the calendar: Auxesis sets the proof.
        assert_eq!(
            run(json!({ "event_id": "evt-shared", "event_default_calendar": true })),
            ok("Unknown")
        );
        // A title names the event, not the calendar it sits on.
        assert_eq!(run(json!({ "find_title": "Focus" })), ok("Unknown"));
        // A copy from a build that published no id keeps the card.
        assert_eq!(
            update_class(
                events.clone(),
                Some(true),
                None,
                json!({ "event_id": "evt-own" })
            ),
            ok("Unknown")
        );
    }

    /// CAL-DEFAULT-ID (r2): a recurring event, or a detached occurrence of
    /// one, never takes the approval-free path. EventKit's lookup can return
    /// the first occurrence, not the one the copy saw, so the check and the
    /// save could land on another occurrence.
    #[test]
    fn a_recurring_event_keeps_its_card() {
        let mut event = event_on("evt-own", "Focus", "Home", "CAL-1", json!([]));
        event["recurring"] = json!(true);
        let events = json!([event]);
        let run = |args: Value| update_class(events.clone(), Some(true), Some("CAL-1"), args);
        let ok = |class: &str| Ok(class.to_string());
        assert_eq!(run(json!({ "event_id": "evt-own" })), ok("Unknown"));
        // The model cannot claim the event is a one-off.
        assert_eq!(
            run(json!({ "event_id": "evt-own", "event_default_calendar": true })),
            ok("Unknown")
        );
    }

    /// Seal B r1: a stale or partial copy keeps the card. CAL-PRIMARY-1: so
    /// does any calendar title, `primary` and blank included: only the copy's
    /// own ids prove the default calendar (CAL-DEFAULT-ID).
    #[test]
    fn an_update_keeps_its_card_on_a_stale_or_partial_copy_or_a_named_calendar() {
        let own = Some(json!([]));
        let cases = [
            (
                "a stale copy",
                Some(false),
                copy_event("evt", "F", "", own.clone()),
            ),
            (
                "no captured_at",
                None,
                copy_event("evt", "F", "", own.clone()),
            ),
            (
                "no guest list",
                Some(true),
                copy_event("evt", "F", "", None),
            ),
            (
                "a named calendar",
                Some(true),
                copy_event("evt", "F", "Team", own.clone()),
            ),
            (
                "a calendar titled primary",
                Some(true),
                copy_event("evt", "F", "primary", own.clone()),
            ),
            (
                "a blank calendar title",
                Some(true),
                copy_event("evt", "F", "", own),
            ),
        ];
        let classes: Vec<_> = cases
            .into_iter()
            .map(|(case, fresh, event)| {
                let class = update_class(json!([event]), fresh, None, json!({ "event_id": "evt" }));
                (case, class.unwrap())
            })
            .collect();
        let kept = classes
            .iter()
            .map(|(case, _)| (*case, "Unknown".to_string()));
        assert_eq!(classes, kept.collect::<Vec<_>>());
    }

    /// A fake app that refuses the write: the live event no longer matches
    /// the facts the copy held (CAL-DEFAULT-ID r1).
    fn facts_changed_app(
        home: &std::path::Path,
    ) -> (Arc<crate::bridge::Bridge>, Arc<Mutex<Vec<Value>>>) {
        let (events, mut receiver) = tokio::sync::broadcast::channel(16);
        let bridge = Arc::new(crate::bridge::Bridge::new(home.to_path_buf(), events));
        let sent = Arc::new(Mutex::new(Vec::<Value>::new()));
        let (app, held) = (Arc::clone(&bridge), Arc::clone(&sent));
        tokio::spawn(async move {
            while let Ok(text) = receiver.recv().await {
                let frame: Value = serde_json::from_str(&text).unwrap_or_default();
                let (Some(id), args) = (frame["id"].as_str(), &frame["args"]) else {
                    continue;
                };
                held.lock().unwrap().push(args.clone());
                use crate::bridge::BridgeAnswer;
                app.answer(
                    id,
                    BridgeAnswer::Error {
                        code: "facts_changed".into(),
                        message: "the event's calendar or its guests changed".into(),
                    },
                );
            }
        });
        (bridge, sent)
    }

    /// CAL-DEFAULT-ID (r1): the daemon sends the facts the write rested on, and
    /// the app's refusal is the owner's decision, never a silent failure.
    #[tokio::test]
    async fn a_write_carries_its_expected_facts_and_a_changed_calendar_asks_the_owner() {
        let home = tempfile::tempdir().unwrap();
        let (bridge, sent) = facts_changed_app(home.path());
        let args = json!({ "event_id": "evt-1", "guests": 0, "event_calendar_id": "cal-1",
            "event_default_calendar": true });
        let error = update_event_through(&bridge, &args).await.unwrap_err();
        {
            let sent = sent.lock().unwrap();
            assert_eq!(sent[0]["expected_calendar_id"], json!("cal-1"));
            assert_eq!(sent[0]["expected_attendees"], json!(0));
        }
        assert!(error.needs_approval, "the owner decides: {error}");
        // A write that already had the owner's card is not checked twice.
        let _ = update_event_through(&bridge, &json!({ "event_id": "evt-1", "guests": 1 })).await;
        let sent = sent.lock().unwrap();
        assert!(sent[1].get("expected_calendar_id").is_none());
    }

    fn card() -> ApprovalCard {
        ApprovalCard {
            skill_name: "send-invite".to_string(),
            skill_version: 1,
            skill_hash: "abc".to_string(),
            level: Approval::EachRun,
            reason: "skill `send-invite` v1 requests 2 action(s)".to_string(),
            countdown_secs: 600,
            recipient_source: None,
            calls: vec![
                CardCall {
                    tool: "apple_calendar_create_event".to_string(),
                    logical: "calendar.create_event".to_string(),
                    real_arguments: json!({ "title": "Meeting with Camille" }),
                    token_arguments: json!({ "title": "Meeting with ⟦PERSON_1⟧" }),
                },
                CardCall {
                    tool: "mail_send".to_string(),
                    logical: "mail.send".to_string(),
                    real_arguments: json!({ "to": ["camille@exemple.fr"], "body": "hi" }),
                    token_arguments: json!({ "to": ["⟦EMAIL_1⟧"], "body": "hi" }),
                },
            ],
        }
    }

    #[test]
    fn card_arguments_carry_real_values_and_the_token_form() {
        let value = card_arguments(&card());
        assert_eq!(value["skill"], "send-invite");
        assert_eq!(value["calls"][0]["tool"], "apple_calendar_create_event");
        assert!(value["calls"][0]["real"]["title"]
            .as_str()
            .unwrap()
            .contains("Camille"));
        assert!(value["calls"][0]["model_saw"]["title"]
            .as_str()
            .unwrap()
            .contains("⟦"));
    }

    #[cfg(feature = "google")]
    #[test]
    fn connector_flattens_attendee_objects_to_addresses() {
        let args = json!({ "summary": "M", "attendees": [{ "email": "camille@exemple.fr" }] });
        let wire = connector_arguments("google.calendar.create_event", &args);
        assert_eq!(wire["attendees"], json!(["camille@exemple.fr"]));
        // Other tools keep their arguments untouched.
        let mail = json!({ "to": ["camille@exemple.fr"] });
        assert_eq!(connector_arguments("google.gmail.send", &mail), mail);
    }

    #[test]
    fn edits_from_card_maps_the_edited_real_payload() {
        let value = json!({
            "calls": [
                { "tool": "apple_calendar_create_event", "real": { "title": "Edited" } },
                { "tool": "mail_send", "real": { "to": ["camille@exemple.fr"], "body": "edited" } }
            ]
        });
        let edits = edits_from_card(&value, &card()).expect("the edit maps");
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0], Some(json!({ "title": "Edited" })));
        assert_eq!(
            edits[1],
            Some(json!({ "to": ["camille@exemple.fr"], "body": "edited" }))
        );

        // A payload that is not an edit is an **error**, never an empty edit:
        // the caller must refuse the run, never fall back to the arguments the
        // run asked for.
        assert!(edits_from_card(&json!({}), &card()).is_err());
        assert!(edits_from_card(
            &json!({ "calls": [{ "tool": "mail_send", "real": { "to": ["c@exemple.fr"] } }] }),
            &card()
        )
        .is_err());
        assert!(edits_from_card(
            &json!({ "calls": [
                { "tool": "apple_calendar_create_event", "real": { "title": "Edited" } },
                { "tool": "notes_append", "real": { "to": ["c@exemple.fr"] } }
            ] }),
            &card()
        )
        .is_err());
    }

    #[test]
    fn the_utc_conversion_accepts_an_offset_and_rejects_junk() {
        assert_eq!(
            to_utc_compact("2026-10-11T10:00:00+02:00").unwrap(),
            "20261011T080000Z"
        );
        assert_eq!(
            to_utc_compact("2026-10-11T08:00:00Z").unwrap(),
            "20261011T080000Z"
        );
        assert!(to_utc_compact("tomorrow 10:00").is_err());
    }

    struct RecordingApprover {
        requests: Mutex<Vec<ApprovalRequest>>,
        decision: ApprovalDecision,
    }

    #[async_trait]
    impl Approver for RecordingApprover {
        async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
            Ok(self.decision.allow)
        }

        async fn decide(
            &self,
            request: &ApprovalRequest,
        ) -> Result<ApprovalDecision, ApproverError> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(self.decision.clone())
        }
    }

    #[test]
    fn mail_send_admits_every_recipient_and_refuses_on_one_deny() {
        use kernel_core::privacy::Reason;
        let to = vec!["known@exemple.fr".to_string()];
        let cc = vec![
            "stranger@exemple.fr".to_string(),
            "late@exemple.fr".to_string(),
        ];
        let mut seen = Vec::new();
        let result = admit_every_recipient(&to, &cc, |recipient| {
            seen.push(recipient.to_string());
            if recipient == "stranger@exemple.fr" {
                Decision::Deny(Reason::Disabled)
            } else {
                admit(
                    PathId::B20,
                    PrivacyMode::Private,
                    &PrivacyContext {
                        destination: Destination::Recipient(recipient.to_string()),
                    },
                )
            }
        });
        assert!(result.unwrap_err().contains("refused the mail send"));
        // `to` first, then the denied cc: the third recipient is never reached.
        assert_eq!(seen, ["known@exemple.fr", "stranger@exemple.fr"]);

        // Every recipient reaches the gate once when all pass, an Ask included.
        let mut count = 0;
        let ok = admit_every_recipient(&to, &cc, |recipient| {
            count += 1;
            admit(
                PathId::B20,
                PrivacyMode::Private,
                &PrivacyContext {
                    destination: Destination::Recipient(recipient.to_string()),
                },
            )
        });
        assert!(ok.is_ok());
        assert_eq!(count, 3);
    }

    #[test]
    fn mail_send_with_no_to_recipient_is_refused_before_the_gate() {
        let mut called = false;
        let result = admit_every_recipient(&[], &["cc@exemple.fr".to_string()], |_| {
            called = true;
            Decision::Deny(kernel_core::privacy::Reason::Disabled)
        });
        assert!(result.unwrap_err().contains("no recipient"));
        assert!(!called);
    }

    #[tokio::test]
    async fn bridge_publishes_one_card_and_maps_the_edit() {
        let inner = Arc::new(RecordingApprover {
            requests: Mutex::new(Vec::new()),
            decision: ApprovalDecision::edited(json!({
                "calls": [
                    { "tool": "apple_calendar_create_event", "real": { "title": "Edited" } },
                    { "tool": "mail_send", "real": { "to": ["camille@exemple.fr"], "body": "edited" } }
                ]
            })),
        });
        let bridge = BrokerCardApprover::new(inner.clone(), "assistant");
        let decision = bridge.decide(&card()).await;
        assert_eq!(decision.edit_for(0), Some(&json!({ "title": "Edited" })));
        let requests = inner.requests.lock().unwrap();
        assert_eq!(requests.len(), 1, "one request for the whole run");
        assert_eq!(requests[0].tool, "skill__send-invite");
        assert_eq!(requests[0].agent, "assistant");
        assert_eq!(requests[0].arguments["calls"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn bridge_refusal_is_a_refusal() {
        let inner = Arc::new(RecordingApprover {
            requests: Mutex::new(Vec::new()),
            decision: ApprovalDecision::new(false),
        });
        let bridge = BrokerCardApprover::new(inner, "assistant");
        assert_eq!(bridge.decide(&card()).await, RunDecision::Refused);
    }

    /// F5: an answer whose edit does not parse as one refuses the run. The
    /// requested arguments must not run in its place.
    #[tokio::test]
    async fn bridge_an_unparseable_edit_is_a_refusal() {
        let edits = [
            json!({}),
            json!({ "calls": [{ "real": { "title": "one call only" } }] }),
            json!({ "calls": [{ "real": "text" }, { "real": { "to": ["camille@exemple.fr"] } }] }),
        ];
        for edit in edits {
            let inner = Arc::new(RecordingApprover {
                requests: Mutex::new(Vec::new()),
                decision: ApprovalDecision::edited(edit.clone()),
            });
            let bridge = BrokerCardApprover::new(inner, "assistant");
            assert_eq!(bridge.decide(&card()).await, RunDecision::Refused, "{edit}");
        }
    }

    /// SEND-REAL-ARGS-1: whatever shape the owner's edit has, the card the
    /// edit route checks and the arguments the executor runs agree, or both
    /// refuse. An edited call runs by its `tool` and its `real` object; every
    /// other key is ignored by both.
    #[tokio::test]
    async fn an_edited_run_runs_exactly_what_its_card_shows() {
        let tool = "skill__send-invite";
        let event = json!({ "tool": "apple_calendar_create_event", "real": { "title": "T" } });
        let sent = json!({ "to": ["sent@exemple.fr"], "subject": "Hi", "body": "sent" });
        let edit = |second: Value| json!({ "calls": [event.clone(), second] });
        // (case, edit, runs): `runs` false = the route and the executor refuse.
        let cases = [
            (
                "real only",
                edit(json!({ "tool": "mail_send", "real": sent })),
                true,
            ),
            (
                "arguments only",
                edit(json!({ "tool": "mail_send", "arguments": sent })),
                false,
            ),
            (
                "arguments under a shown to",
                edit(json!({
                    "tool": "mail_send", "to": ["shown@exemple.fr"], "subject": "Hi",
                    "body": "shown", "arguments": sent
                })),
                false,
            ),
            (
                "real and arguments differ",
                edit(json!({
                    "tool": "mail_send", "real": sent,
                    "arguments": { "to": ["other@exemple.fr"], "subject": "Hi", "body": "x" }
                })),
                true,
            ),
            (
                "a to beside calls",
                json!({ "to": ["other@exemple.fr"], "calls": [event.clone(),
                    { "tool": "mail_send", "real": sent, "model_saw": {}, "extra": 1 }] }),
                true,
            ),
            ("no tool", edit(json!({ "real": sent })), false),
            (
                "another tool",
                edit(json!({ "tool": "notes_append", "real": sent })),
                false,
            ),
            (
                "real is text",
                edit(json!({ "tool": "mail_send", "real": "x" })),
                false,
            ),
            ("empty calls", json!({ "calls": [] }), false),
        ];
        let original = card_arguments(&card());
        let mut wrong = Vec::new();
        for (case, edited, runs) in cases {
            // What the edit route shows (routes.rs `edit`), then what runs.
            let shown = crate::api::approval_preview::build_edit_checked(
                tool,
                &original,
                &edited,
                &[],
                &|text| text.to_string(),
            );
            let inner = Arc::new(RecordingApprover {
                requests: Mutex::new(Vec::new()),
                decision: ApprovalDecision::edited(edited.clone()),
            });
            let decision = BrokerCardApprover::new(inner, "assistant")
                .decide(&card())
                .await;
            let ran = match &decision {
                RunDecision::Approved { edits } => {
                    let calls: Vec<Value> = card()
                        .calls
                        .iter()
                        .zip(edits)
                        .map(|(call, edit)| {
                            let real = edit.clone().unwrap_or(call.real_arguments.clone());
                            json!({ "tool": call.tool, "real": real })
                        })
                        .collect();
                    Some(json!({ "calls": calls }))
                }
                _ => None,
            };
            let ran_card = ran
                .as_ref()
                .map(|ran| crate::api::approval_preview::build(tool, ran, &[]));
            let agrees = match (&shown, &ran_card) {
                (Ok(shown), Some(Ok(ran))) => runs && shown == ran,
                (Err(_), None) => !runs,
                _ => false,
            };
            if !agrees {
                wrong.push(format!("{case}: card {shown:?} / runs {ran:?}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "card and send disagree:\n{}",
            wrong.join("\n")
        );
    }

    /// F4: the registry denies at the owner's countdown, which is the same
    /// moment the card expires. That silence is a timeout, not a refusal.
    struct SilentApprover;

    #[async_trait]
    impl Approver for SilentApprover {
        async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
            Ok(false)
        }

        async fn decide(
            &self,
            _request: &ApprovalRequest,
        ) -> Result<ApprovalDecision, ApproverError> {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            Ok(ApprovalDecision::new(false))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bridge_silence_past_the_countdown_is_a_timeout() {
        let bridge = BrokerCardApprover::new(Arc::new(SilentApprover), "assistant");
        assert_eq!(bridge.decide(&card()).await, RunDecision::Timeout);
    }

    /// A mail API that is never called: the composite test only loads a draft.
    struct NoMail;

    #[async_trait]
    impl aux_mail::MailApi for NoMail {
        async fn list(
            &self,
            _: &str,
            _: &aux_mail::ListQuery,
        ) -> Result<Vec<aux_mail::EnvelopeItem>, aux_mail::MailError> {
            Err(aux_mail::MailError::Protocol)
        }
        async fn search(
            &self,
            _: &str,
            _: &aux_mail::SearchQuery,
        ) -> Result<Vec<aux_mail::EnvelopeItem>, aux_mail::MailError> {
            Err(aux_mail::MailError::Protocol)
        }
        async fn thread(
            &self,
            _: &str,
            _: &str,
            _: usize,
        ) -> Result<Vec<aux_mail::EnvelopeItem>, aux_mail::MailError> {
            Err(aux_mail::MailError::Protocol)
        }
        async fn read(
            &self,
            _: &str,
            _: u32,
            _: &str,
            _: usize,
        ) -> Result<aux_mail::MailItem, aux_mail::MailError> {
            Err(aux_mail::MailError::Protocol)
        }
        async fn fetch_attachments(
            &self,
            _: &str,
            _: &str,
            _: u32,
        ) -> Result<aux_mail::FetchedAttachments, aux_mail::MailError> {
            Err(aux_mail::MailError::Protocol)
        }
        async fn send(
            &self,
            _: &str,
            _: &aux_mail::OutgoingMail,
        ) -> Result<aux_mail::SendOutcome, aux_mail::MailError> {
            Err(aux_mail::MailError::Protocol)
        }
        fn limits(&self) -> &aux_mail::Limits {
            static LIMITS: std::sync::LazyLock<aux_mail::Limits> =
                std::sync::LazyLock::new(aux_mail::Limits::default);
            std::sync::LazyLock::force(&LIMITS)
        }
    }

    /// The production connector is the composite; it must pass the stored
    /// draft through, or every send-draft run refuses before its card.
    #[test]
    fn the_composite_serves_the_stored_draft() {
        use kernel_core::privacy::PrivacyMode;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            Store::open(&dir.path().join("store.db")).unwrap(),
        ));
        let payload = json!({
            "to": ["camille@northwind.example"],
            "to_display": ["Northwind <camille@northwind.example>"],
            "subject": "Late",
            "body": "We're late.",
        })
        .to_string();
        let id = store
            .lock()
            .unwrap()
            .log_event_id("mail.draft", &payload)
            .unwrap();
        let mail = MailSkillConnector::new(
            aux_mail::MailToolset::new(Arc::new(NoMail), None),
            None,
            "me@example.org",
            Arc::new(|| PrivacyMode::Open),
        )
        .with_store(Arc::clone(&store));
        let composite = CompositeSkillConnector {
            mail: Some(mail),
            docs: None,
            crm: None,
            calendar_home: None,
            #[cfg(feature = "google")]
            google: None,
        };
        let draft = composite
            .mail_draft(id)
            .expect("the composite delegates")
            .expect("a sendable draft");
        assert_eq!(draft.to, ["camille@northwind.example"]);
        assert_eq!(draft.subject, "Late");
        assert!(composite.mail_draft(id + 1).unwrap().is_none());
    }

    /// CAL-COMPLETE-DEDUP: the app may have cut the event list at its cap. A
    /// copy that says so is never read for free times, even when it looks
    /// fresh and carries one event: the missing one may be busy.
    #[tokio::test]
    async fn a_truncated_calendar_copy_offers_no_free_times() {
        use crate::apple_eventkit::{save_snapshot, EventItem, EventKitSnapshot};
        let dir = tempfile::tempdir().unwrap();
        aux_store::Store::open(&kernel_core::store_path(dir.path())).unwrap();
        let now = chrono::Utc::now();
        let at = |hours: i64| (now + chrono::Duration::hours(hours)).to_rfc3339();
        let copy = |truncated: bool| EventKitSnapshot {
            authorized: true,
            events: vec![EventItem {
                id: Some("evt-busy".into()),
                title: "Busy".into(),
                start: at(24),
                end: at(25),
                all_day: Some(false),
                calendar: "Work".into(),
                location: None,
                attendees: None,
                calendar_id: None,
                recurring: None,
            }],
            reminders: Vec::new(),
            events_truncated: truncated,
            captured_at: Some(at(0)),
            covers_from: Some(at(-24)),
            covers_to: Some(at(24 * 10)),
            ..Default::default()
        };
        let connector = CompositeSkillConnector {
            mail: None,
            docs: None,
            crm: None,
            calendar_home: Some(dir.path().to_path_buf()),
            #[cfg(feature = "google")]
            google: None,
        };
        let skill = SkillContext {
            name: "reply-availability".into(),
            version: 1,
            hash: "hash".into(),
            tainted: false,
        };
        let span = json!({ "from": at(24), "to": at(48) });
        save_snapshot(dir.path(), &copy(true)).unwrap();
        let refused = connector
            .call(
                &skill,
                aux_runtime::skills::free_times::CALENDAR_READ,
                &span,
            )
            .await;
        assert!(
            refused.is_err(),
            "a truncated copy never proves the owner free"
        );
        // Without the flag the same copy reads: the refusal is the flag's.
        save_snapshot(dir.path(), &copy(false)).unwrap();
        let read = connector
            .call(
                &skill,
                aux_runtime::skills::free_times::CALENDAR_READ,
                &span,
            )
            .await
            .expect("a complete copy is read");
        assert_eq!(read.as_array().map(Vec::len), Some(1), "{read}");
    }
}
