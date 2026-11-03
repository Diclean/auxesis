//! The one logical-name ↔ wire-name table.
//!
//! Skill and agent files name tools logically (`<connector>.<area>.<verb>`);
//! providers see wire names (`google_gmail_send`). Every mapping lives here so
//! the loader, the fill validator and the executor agree on one table.

/// What a tool does, for the read-only and skill-only rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// Observes state and produces no side effects.
    Read,
    /// Changes state; never allowed on a scheduled skill.
    Write,
    /// A tool from an installed extension; treated as non-read-only.
    Extension,
}

/// One resolved tool name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInfo {
    /// Logical name used in skill and agent files.
    pub logical: String,
    /// Wire name the provider and connector see.
    pub wire: String,
    /// Read / write / extension classification.
    pub kind: ToolKind,
    /// True for the two write tools that may only run inside a skill.
    pub skill_only: bool,
}

impl ToolInfo {
    /// True when the tool is read-only by construction.
    pub fn is_read_only(&self) -> bool {
        matches!(self.kind, ToolKind::Read)
    }

    /// True when a skill may run the tool with no card: a read, or the one
    /// local ingest (`docs.ingest`, M5-5). That collector reads the owner's own
    /// mailbox and appends originals to this Mac's registry: nothing is sent,
    /// paid, deleted or changed on an account (owner rule 2026-10-16: cards are
    /// for those only). Every other write keeps its card.
    pub fn runs_without_card(&self) -> bool {
        self.is_read_only() || self.logical == "docs.ingest"
    }
}

const READ: ToolKind = ToolKind::Read;
const WRITE: ToolKind = ToolKind::Write;

/// The fixed half of the table.
const STATIC_TOOLS: &[(&str, &str, ToolKind, bool)] = &[
    ("google.gmail.search", "google_gmail_search", READ, false),
    (
        "google.gmail.read_message",
        "google_gmail_read_message",
        READ,
        false,
    ),
    (
        "google.gmail.create_draft",
        "google_gmail_create_draft",
        WRITE,
        false,
    ),
    ("google.gmail.send", "google_gmail_send", WRITE, true),
    (
        "google.calendar.list_events",
        "google_calendar_list_events",
        READ,
        false,
    ),
    (
        "google.calendar.get_event",
        "google_calendar_get_event",
        READ,
        false,
    ),
    (
        "google.calendar.create_event",
        "google_calendar_create_event",
        WRITE,
        true,
    ),
    // B19 reads and B22 local writes; neither leaves the Mac.
    ("mail.list", "mail_list", READ, false),
    ("mail.search", "mail_search", READ, false),
    ("mail.thread", "mail_thread", READ, false),
    ("mail.read", "mail_read", READ, false),
    (
        "mail.fetch_attachments",
        "mail_fetch_attachments",
        WRITE,
        false,
    ),
    // DRAFT-ONLY: local save, no card; a later send keeps `mail.send`'s card.
    ("mail.draft", "mail_draft", WRITE, false),
    // MA4: the one SMTP write (B20), skill-only exactly like the Gmail send it
    // replaces, and the EventKit create through the Mac bridge (B21), also
    // skill-only. `calendar.create_event` is the EventKit tool; the frozen
    // Google path keeps its own `google.calendar.create_event` row.
    ("mail.send", "mail_send", WRITE, true),
    (
        "calendar.create_event",
        "apple_calendar_create_event",
        WRITE,
        true,
    ),
    // CAL-UPDATE-1: move or edit one EventKit event, skill-only like the create.
    (
        "calendar.update_event",
        "apple_calendar_update_event",
        WRITE,
        true,
    ),
    // M4-0: the two EventKit reads (`apple_eventkit.rs`), so an agent file can
    // name them logically like every other registered connector tool.
    (
        "calendar.list_events",
        "apple_calendar_list_events",
        READ,
        false,
    ),
    ("reminders.list", "apple_reminders_list", READ, false),
    // `docs.ingest` (row C1): the deterministic receipts
    // collector's append into the local evidence registry. Local, append-only,
    // no model and no egress; it is not a provider tool, but the field and skill
    // loaders still name it logically like every other one.
    ("docs.ingest", "docs_ingest", WRITE, false),
    // B3 CRM follow-up: a local write, reachable only from a skill
    // (`docs/phase1.md` §5). The wire name is what the provider and connector see.
    ("crm.create_followup", "crm_create_followup", WRITE, true),
    // B4 CRM reads: `client-brief` resolves a party and reads its identity,
    // timeline, follow-ups and memory; `brief` reads the day's parties and the
    // follow-ups due. All three are ordinary local reads.
    ("crm.search", "crm_search", READ, false),
    ("crm.get", "crm_get", READ, false),
    ("crm.today", "crm_today", READ, false),
    // CRM-LIST: "list my clients", newest activity first, names only.
    ("crm.list", "crm_list", READ, false),
    // B4 `log-interaction`: one interaction plus its memory items. A local
    // write, reachable only from a skill (`docs/phase1.md` §5).
    ("crm.log_interaction", "crm_log_interaction", WRITE, true),
    // CRM-NOTE-CHAT-1: the note the owner asks for in a conversation. A local
    // write on an existing client's card, not skill-only.
    ("crm.add_note", "crm_add_note", WRITE, false),
    // B4 leaves the documents queue as a read hook the `brief` skill names;
    // C4 fills the queue behind it (`docs/phase1.md` §5).
    ("docs.queue", "docs_queue", READ, false),
];

/// Expand the brief's short forms to their canonical logical names.
fn canonical(name: &str) -> String {
    match name {
        "gmail.send" => "google.gmail.send".to_string(),
        other => other.to_string(),
    }
}

/// Resolve a logical name (short forms included) to its tool.
pub fn lookup(name: &str) -> Option<ToolInfo> {
    let name = canonical(name);
    if let Some((logical, wire, kind, skill_only)) =
        STATIC_TOOLS.iter().find(|(logical, ..)| *logical == name)
    {
        return Some(ToolInfo {
            logical: (*logical).to_string(),
            wire: (*wire).to_string(),
            kind: *kind,
            skill_only: *skill_only,
        });
    }
    let (server, tool) = parse_mcp(&name)?;
    Some(ToolInfo {
        logical: format!("mcp.{server}.{tool}"),
        wire: format!("mcp__{server}__{tool}"),
        kind: ToolKind::Extension,
        skill_only: false,
    })
}

/// Resolve a wire name back to its tool.
pub fn from_wire(wire: &str) -> Option<ToolInfo> {
    if let Some((logical, ..)) = STATIC_TOOLS.iter().find(|(_, name, ..)| *name == wire) {
        return lookup(logical);
    }
    let rest = wire.strip_prefix("mcp__")?;
    let (server, tool) = rest.split_once("__")?;
    if server.is_empty() || tool.is_empty() {
        return None;
    }
    // Round-trip so a segment that starts or ends with `_` cannot be
    // re-interpreted as a different server/tool pair.
    let info = lookup(&format!("mcp.{server}.{tool}"))?;
    if info.wire == wire {
        Some(info)
    } else {
        None
    }
}

/// The canonical logical name for `name`, when it is a known tool.
pub fn canonical_name(name: &str) -> Option<String> {
    lookup(name).map(|info| info.logical)
}

/// The wire name for `name`, when it is a known tool.
pub fn wire_name(name: &str) -> Option<String> {
    lookup(name).map(|info| info.wire)
}

/// The JSON schema of a tool's `arguments`, for the fill validator.
///
/// Phase 0 defines schemas for the Google tools only; extension (`mcp.*`)
/// tools have no local schema yet, so their arguments are not shape-checked.
pub fn arguments_schema(logical: &str) -> Option<serde_json::Value> {
    use serde_json::json;
    match logical {
        "google.gmail.search" => Some(json!({
            "type": "object",
            "properties": { "query": { "type": "string" }, "max_results": { "type": "integer" } },
            "required": ["query"],
            "additionalProperties": false
        })),
        "google.gmail.read_message" => Some(json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"],
            "additionalProperties": false
        })),
        "google.gmail.create_draft" => Some(json!({
            "type": "object",
            "properties": {
                "to": { "type": "string" },
                "subject": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["body"],
            "additionalProperties": false
        })),
        "google.gmail.send" => Some(json!({
            "type": "object",
            "properties": {
                "to": { "type": "string" },
                "cc": { "type": "string" },
                "bcc": { "type": "string" },
                "subject": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["to", "body"],
            "additionalProperties": false
        })),
        "google.calendar.list_events" => Some(json!({
            "type": "object",
            "properties": { "from": { "type": "string" }, "to": { "type": "string" } },
            "additionalProperties": false
        })),
        "google.calendar.get_event" => Some(json!({
            "type": "object",
            "properties": { "id": { "type": "string" } },
            "required": ["id"],
            "additionalProperties": false
        })),
        "google.calendar.create_event" => Some(json!({
            "type": "object",
            "properties": {
                "summary": { "type": "string" },
                "location": { "type": "string" },
                "start": {
                    "type": "string",
                    "format": "date-time",
                    "description": "RFC 3339 with an offset, e.g. 2026-10-11T10:00:00+02:00"
                },
                "end": {
                    "type": "string",
                    "format": "date-time",
                    "description": "RFC 3339 with an offset, e.g. 2026-10-11T10:30:00+02:00"
                },
                "description": { "type": "string" },
                "attendees": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": { "email": { "type": "string" } },
                        "required": ["email"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["summary", "start"],
            "additionalProperties": false
        })),
        "mail.list" => Some(json!({
            "type": "object",
            "properties": {
                "account": { "type": "string", "maxLength": 64 },
                "folder": { "type": "string", "maxLength": 256 },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                "unread": { "type": "boolean" },
                "days": { "type": "integer", "minimum": 1, "maximum": 90 }
            },
            "required": ["account"],
            "additionalProperties": false
        })),
        "mail.search" => Some(json!({
            "type": "object",
            "properties": {
                "account": { "type": "string", "maxLength": 64 },
                "query": { "type": "string", "maxLength": 512 },
                "folder": { "type": "string", "maxLength": 256 },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                "days": { "type": "integer", "minimum": 1, "maximum": 90 }
            },
            "required": ["account", "query"],
            "additionalProperties": false
        })),
        "mail.thread" => Some(json!({
            "type": "object",
            "properties": {
                "account": { "type": "string", "maxLength": 64 },
                "message_id": { "type": "string", "maxLength": 512 },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200 }
            },
            "required": ["account", "message_id"],
            "additionalProperties": false
        })),
        "mail.read" => Some(json!({
            "type": "object",
            "properties": {
                "account": { "type": "string", "maxLength": 64 },
                "uid": { "type": "integer", "minimum": 1 },
                "folder": { "type": "string", "maxLength": 256 },
                "max_chars": { "type": "integer", "minimum": 1 }
            },
            "required": ["account", "uid"],
            "additionalProperties": false
        })),
        "mail.fetch_attachments" => Some(json!({
            "type": "object",
            "properties": {
                "account": { "type": "string", "maxLength": 64 },
                "folder": { "type": "string", "maxLength": 256 },
                "uid": { "type": "integer", "minimum": 1 }
            },
            "required": ["account", "uid"],
            "additionalProperties": false
        })),
        "mail.send" => Some(json!({
            "type": "object",
            "properties": {
                "account": { "type": "string", "maxLength": 64 },
                "to": {
                    "type": "array",
                    "items": { "type": "string", "maxLength": 254 },
                    "minItems": 1,
                    "maxItems": 50
                },
                "cc": {
                    "type": "array",
                    "items": { "type": "string", "maxLength": 254 },
                    "maxItems": 50
                },
                "subject": { "type": "string", "maxLength": 998 },
                "body": { "type": "string", "maxLength": 102400 },
                "ics": { "type": "string", "description": "\"event\" to attach the invite for the event this skill creates" },
                "draft_id": { "type": "integer", "minimum": 1, "description": "set by Auxesis for send-draft" }
            },
            "required": ["to", "subject", "body"],
            "additionalProperties": false
        })),
        "calendar.create_event" => Some(json!({
            "type": "object",
            "properties": {
                "calendar": { "type": "string" },
                "title": { "type": "string" },
                "start": { "type": "string", "maxLength": 40,
                    "description": "local time as the owner said it, no offset, e.g. 2026-10-26T10:00:00" },
                "end": { "type": "string", "maxLength": 40,
                    "description": "local time, no offset" },
                "time_zone": { "type": "string", "maxLength": 64,
                    "description": "IANA zone of start/end, only when the owner names one; omit for the owner's own zone" },
                "attendee_time_zone": { "type": "string", "maxLength": 64,
                    "description": "the invitee's IANA zone, only when known" },
                "start_utc": { "type": "string", "maxLength": 16, "description": "set by Auxesis" },
                "end_utc": { "type": "string", "maxLength": 16, "description": "set by Auxesis" },
                "attendee_start": { "type": "string", "maxLength": 40, "description": "set by Auxesis" },
                "attendee_time_zone_source": { "type": "string", "maxLength": 160,
                    "description": "set by Auxesis: where the attendee's zone came from" },
                "location": { "type": "string" },
                "notes": { "type": "string" },
                "url": { "type": "string" }
            },
            "required": ["title", "start"],
            "additionalProperties": false
        })),
        "calendar.update_event" => Some(json!({
            "type": "object",
            "properties": {
                "event_id": { "type": "string", "maxLength": 512 },
                "find_title": { "type": "string", "description": "without an id: the exact title" },
                "calendar": { "type": "string" }, "title": { "type": "string" },
                "start": { "type": "string", "maxLength": 40, "description": "new local time, no offset" },
                "end": { "type": "string", "maxLength": 40, "description": "new local end, with the start" },
                "time_zone": { "type": "string", "maxLength": 64, "description": "IANA zone, only if named" },
                "start_utc": { "type": "string", "maxLength": 16, "description": "set by Auxesis" },
                "end_utc": { "type": "string", "maxLength": 16, "description": "set by Auxesis" },
                "guests": { "type": "integer", "minimum": 0, "description": "set by Auxesis" },
                "event_calendar": { "type": "string", "description": "set by Auxesis" },
                "event_calendar_id": { "type": "string", "description": "set by Auxesis" },
                "event_default_calendar": { "type": "boolean", "description": "set by Auxesis" },
                "location": { "type": "string" }, "notes": { "type": "string" }, "url": { "type": "string" }
            },
            "additionalProperties": false
        })),
        "docs.ingest" => Some(json!({
            "type": "object",
            "properties": {
                "account": { "type": "string", "maxLength": 64 },
                "folder": { "type": "string", "maxLength": 256 },
                "days": { "type": "integer", "minimum": 1, "maximum": 90 }
            },
            "additionalProperties": false
        })),
        "crm.create_followup" => Some(json!({
            "type": "object",
            "properties": {
                "party_id": { "type": "integer", "minimum": 1 },
                "due": { "type": "string", "maxLength": 40 },
                "note": { "type": "string", "maxLength": 2000 }
            },
            "required": ["party_id", "due", "note"],
            "additionalProperties": false
        })),
        "crm.search" => Some(json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "maxLength": 200 },
                "limit": { "type": "integer", "minimum": 1, "maximum": 20 }
            },
            "required": ["query"],
            "additionalProperties": false
        })),
        "crm.list" => Some(json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "enum": ["person", "company"] },
                "limit": { "type": "integer", "minimum": 1, "maximum": 50 },
                "offset": { "type": "integer", "minimum": 0, "maximum": 100000 }
            },
            "additionalProperties": false
        })),
        "crm.get" => Some(json!({
            "type": "object",
            "properties": {
                "party_id": { "type": "integer", "minimum": 1 },
                "name": { "type": "string", "maxLength": 200 },
                "timeline": { "type": "integer", "minimum": 1, "maximum": 20 },
                "memory": { "type": "integer", "minimum": 0, "maximum": 20 }
            },
            "additionalProperties": false
        })),
        "crm.today" => Some(json!({
            "type": "object",
            "properties": { "day": { "type": "string", "maxLength": 40 } },
            "additionalProperties": false
        })),
        "crm.log_interaction" => Some(json!({
            "type": "object",
            "properties": {
                "party_id": { "type": "integer", "minimum": 1 },
                "party": { "type": "string", "maxLength": 200 },
                "kind": { "type": "string", "maxLength": 16 },
                "at": { "type": "string", "maxLength": 40 },
                "source_ref": { "type": "string", "maxLength": 512 },
                "summary": { "type": "string", "maxLength": 2000 },
                "memory": {
                    "type": "array",
                    "maxItems": 8,
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": { "type": "string", "maxLength": 16 },
                            "title": { "type": "string", "maxLength": 200 },
                            "body": { "type": "string", "maxLength": 2000 }
                        },
                        "required": ["kind", "title", "body"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["kind", "at", "source_ref", "summary"],
            "additionalProperties": false
        })),
        "crm.add_note" => Some(json!({
            "type": "object",
            "properties": {
                "party_id": { "type": "integer", "minimum": 1 },
                "name": { "type": "string", "maxLength": 200 },
                "note": { "type": "string", "maxLength": 2000 }
            },
            "required": ["note"],
            "additionalProperties": false
        })),
        "docs.queue" => Some(json!({
            "type": "object",
            "properties": { "status": { "type": "string", "maxLength": 40 } },
            "additionalProperties": false
        })),
        _ => None,
    }
}

/// Split `mcp.<server>.<tool>` into its two variable segments.
fn parse_mcp(name: &str) -> Option<(String, String)> {
    let rest = name.strip_prefix("mcp.")?;
    let mut parts = rest.split('.');
    let server = parts.next()?;
    let tool = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && !segment.starts_with('_')
            && !segment.ends_with('_')
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    };
    if !valid_segment(server) || !valid_segment(tool) {
        return None;
    }
    Some((server.to_string(), tool.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_contract_row() {
        for (logical, wire, kind, skill_only) in STATIC_TOOLS {
            let info = lookup(logical).expect("known");
            assert_eq!(info.wire, *wire);
            assert_eq!(info.kind, *kind);
            assert_eq!(info.skill_only, *skill_only);
            assert_eq!(from_wire(wire).unwrap().logical, *logical);
        }
    }

    /// DOC-COLLECT-1: the collector's fill does not have to name an account:
    /// the model is never told the slug, so requiring one made it guess.
    #[test]
    fn the_collectors_schema_does_not_require_an_account() {
        let schema = arguments_schema("docs.ingest").expect("the pinned schema");
        assert!(schema["required"].is_null(), "{schema}");
    }

    #[test]
    fn short_forms_canonicalise() {
        assert_eq!(
            canonical_name("gmail.send").as_deref(),
            Some("google.gmail.send")
        );
        // The calendar short form is the EventKit tool, not the frozen Google one.
        assert_eq!(
            canonical_name("calendar.create_event").as_deref(),
            Some("calendar.create_event")
        );
        assert_eq!(
            wire_name("calendar.create_event").as_deref(),
            Some("apple_calendar_create_event")
        );
    }

    #[test]
    fn mcp_names_round_trip_and_unknown_names_fail() {
        let info = lookup("mcp.github.search_issues").unwrap();
        assert_eq!(info.wire, "mcp__github__search_issues");
        assert_eq!(info.kind, ToolKind::Extension);
        assert_eq!(
            from_wire("mcp__github__search_issues").unwrap().logical,
            "mcp.github.search_issues"
        );
        assert!(lookup("gmail.archive").is_none());
        assert!(lookup("mcp.github").is_none());
        assert!(from_wire("google_gmail_archive").is_none());
    }

    #[test]
    fn write_and_skill_only_flags_are_correct() {
        assert!(!lookup("google.gmail.send").unwrap().is_read_only());
        assert!(lookup("google.gmail.send").unwrap().skill_only);
        assert!(lookup("google.calendar.create_event").unwrap().skill_only);
        assert!(lookup("google.gmail.search").unwrap().is_read_only());
        assert!(!lookup("google.gmail.create_draft").unwrap().skill_only);
        assert!(lookup("mail.send").unwrap().skill_only);
        assert!(!lookup("mail.send").unwrap().is_read_only());
        assert!(!lookup("mail.draft").unwrap().skill_only);
        assert!(!lookup("mail.draft").unwrap().is_read_only());
        assert!(lookup("calendar.create_event").unwrap().skill_only);
        assert_eq!(
            from_wire("mail_send").unwrap().logical,
            "mail.send".to_string()
        );
        assert_eq!(
            from_wire("apple_calendar_create_event").unwrap().logical,
            "calendar.create_event".to_string()
        );
    }

    #[test]
    fn mail_tools_map_to_their_wire_names() {
        for (logical, wire, read_only) in [
            ("mail.list", "mail_list", true),
            ("mail.search", "mail_search", true),
            ("mail.thread", "mail_thread", true),
            ("mail.read", "mail_read", true),
            ("mail.fetch_attachments", "mail_fetch_attachments", false),
        ] {
            let info = lookup(logical).expect(logical);
            assert_eq!(info.wire, wire);
            assert_eq!(info.is_read_only(), read_only, "{logical}");
            assert!(!info.skill_only, "{logical} is not skill-only");
            assert_eq!(from_wire(wire).unwrap().logical, logical);
            assert!(arguments_schema(logical).is_some(), "{logical}");
        }
    }

    #[test]
    fn mcp_segments_that_start_or_end_with_underscore_are_rejected() {
        for name in [
            "mcp._github.search",
            "mcp.github_.search",
            "mcp.github.search_",
            "mcp._github_.search",
            "mcp.github._search",
        ] {
            assert!(lookup(name).is_none(), "{name} must be rejected");
        }
        assert!(from_wire("mcp__github___search").is_none());
        assert!(from_wire("mcp__github__search_").is_none());
    }

    #[test]
    fn argument_schemas_exist_for_the_google_tools() {
        let send = arguments_schema("google.gmail.send").unwrap();
        assert_eq!(send["required"], serde_json::json!(["to", "body"]));
        assert_eq!(send["additionalProperties"], serde_json::json!(false));
        let event = arguments_schema("google.calendar.create_event").unwrap();
        assert_eq!(event["required"], serde_json::json!(["summary", "start"]));
        assert!(arguments_schema("mcp.github.search_issues").is_none());

        // MA4: the SMTP send and the EventKit create each have a pinned schema.
        let mail = arguments_schema("mail.send").unwrap();
        assert_eq!(
            mail["required"],
            serde_json::json!(["to", "subject", "body"])
        );
        assert_eq!(mail["additionalProperties"], serde_json::json!(false));
        assert_eq!(mail["properties"]["to"]["type"], "array");
        assert_eq!(mail["properties"]["to"]["items"]["type"], "string");
        let event = arguments_schema("calendar.create_event").unwrap();
        assert_eq!(event["required"], serde_json::json!(["title", "start"]));
        assert_eq!(event["additionalProperties"], serde_json::json!(false));
    }

    #[test]
    fn b4_crm_and_docs_tools_map_to_their_wire_names() {
        for (logical, wire, read_only, skill_only) in [
            ("crm.search", "crm_search", true, false),
            ("crm.get", "crm_get", true, false),
            ("crm.today", "crm_today", true, false),
            ("crm.list", "crm_list", true, false),
            ("crm.log_interaction", "crm_log_interaction", false, true),
            ("crm.add_note", "crm_add_note", false, false),
            ("docs.queue", "docs_queue", true, false),
        ] {
            let info = lookup(logical).expect(logical);
            assert_eq!(info.wire, wire);
            assert_eq!(info.is_read_only(), read_only, "{logical}");
            assert_eq!(info.skill_only, skill_only, "{logical}");
            assert_eq!(from_wire(wire).unwrap().logical, logical);
            assert!(arguments_schema(logical).is_some(), "{logical} schema");
        }
        // `crm.log_interaction` is skill-only, so the broker floor can refuse it
        // from a plain conversation; `crm.search` is a plain read.
        assert!(!lookup("crm.search").unwrap().skill_only);
        assert!(lookup("crm.log_interaction").unwrap().skill_only);
    }
}
