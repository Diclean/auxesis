//! ACT-FREE: what one tool call does, as an action class, for
//! `approvals = "auto"`.
//!
//! The owner's order (2026-10-16): no card for anything but sending or paying.
//! Reads, local writes and the chief's `delegate` run without a card, tainted
//! or not; sends, payments, deletes, account changes and any tool this table
//! does not know keep the card (unknown = ask, like an unknown MCP server). A
//! web call runs without a card only when the privacy kernel can vet what
//! leaves (see [`web_vetted`]). The shell is not decided here.
//!
//! The table lifts cards only. Deny rules, grants, the skill-only floor, the
//! web gate and the privacy kernel run exactly as before.

use kernel_broker::{ApprovalRequest, ToolClass};
use serde_json::Value;

/// What a call does to the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// Reads and searches the owner's data.
    Read,
    /// Writes that stay on this Mac: memory, notes, CRM, the agent
    /// workspace, an event on the owner's default calendar with no attendees.
    LocalWrite,
    /// A draft in the owner's own mailbox: nothing is sent.
    Draft,
    /// The chief hands a task to a domain agent on this Mac.
    Delegate,
    /// A web request: the URL itself leaves the machine.
    Web,
    /// The sandboxed shell (judged elsewhere).
    Shell,
    /// Sends something to another person or service.
    Send,
    /// Moves money.
    Pay,
    /// Deletes or irreversibly changes owner data.
    Delete,
    /// Accounts, permissions, credentials, installs.
    Account,
    /// A tool this table does not know.
    Unknown,
}

impl ActionClass {
    /// Stable lowercase label for the audit row.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionClass::Read => "read",
            ActionClass::LocalWrite => "local_write",
            ActionClass::Draft => "draft",
            ActionClass::Delegate => "delegate",
            ActionClass::Web => "web",
            ActionClass::Shell => "shell",
            ActionClass::Send => "send",
            ActionClass::Pay => "pay",
            ActionClass::Delete => "delete",
            ActionClass::Account => "account",
            ActionClass::Unknown => "unknown",
        }
    }

    /// True for the classes that never need a card.
    pub fn is_free(self) -> bool {
        matches!(
            self,
            ActionClass::Read
                | ActionClass::LocalWrite
                | ActionClass::Draft
                | ActionClass::Delegate
        )
    }
}

/// The shipped tools that only read.
const READS: &str = "mail_list mail_search mail_thread mail_read mail_fetch_attachments \
    apple_calendar_list_events apple_reminders_list calendar_list_events calendar_get_event \
    gmail_list_threads gmail_read_message gmail_search crm_get crm_list crm_search crm_today recall \
    owner_profile privacy_record_summary read_file notes_read docs_ingest";

/// The shipped tools that write on this Mac only. `write_file` is confined
/// to the agent workspace. `crm_add_note` keeps a note on a client's card.
const LOCAL_WRITES: &str =
    "remember suggest_memory write_file crm_log_interaction crm_create_followup crm_add_note";

/// The shipped tools that create a calendar event (see [`own_event`]).
const EVENT_CREATES: &str = "apple_calendar_create_event google_calendar_create_event";

/// The shipped tools that change one calendar event (see [`own_update`]).
const EVENT_UPDATES: &str = "apple_calendar_update_event";

/// The vetted web reads: a URL or a query leaves, nothing else. Any other tool
/// that declares web egress, or one of these that does not, is unknown.
const WEB_READS: &str = "http_fetch web_page web_search weather_forecast weather_geocode";

/// Name words of each consequential class, checked before the table.
const WORDS: &[(ActionClass, &str)] = &[
    (
        ActionClass::Send,
        "send reply forward post publish share upload invite notify sms imessage whatsapp \
         telegram gateway email",
    ),
    (
        ActionClass::Pay,
        "pay payment purchase buy order checkout charge refund transfer subscribe",
    ),
    (
        ActionClass::Delete,
        "delete remove rm trash erase purge wipe destroy drop unlink forget move",
    ),
    (
        ActionClass::Account,
        "install uninstall extension credential credentials password permission permissions \
         grant login logout auth oauth account secret",
    ),
];

/// The class of one call to `tool` with `arguments`; `class` is the tool's
/// declared class when it is registered.
pub fn classify(tool: &str, arguments: &Value, class: Option<&ToolClass>) -> ActionClass {
    if tool == "delegate" {
        return ActionClass::Delegate;
    }
    if tool == "shell" {
        return ActionClass::Shell;
    }
    if let Some(skill) = tool.strip_prefix("skill__") {
        return classify_skill_run(skill, arguments);
    }
    let lower = tool.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    for (action, list) in WORDS {
        if list.split_whitespace().any(|word| words.contains(&word)) {
            return *action;
        }
    }
    // MCP and other third-party tools hand their arguments to someone else:
    // never free, whatever they are called.
    if lower.starts_with("mcp__") || class.is_some_and(|class| class.arguments_leave_machine) {
        return ActionClass::Unknown;
    }
    let listed = |list: &str| list.split_whitespace().any(|name| name == tool);
    if listed(EVENT_CREATES) {
        return own_event(tool, arguments, true);
    }
    if listed(EVENT_UPDATES) {
        return own_update(tool, arguments);
    }
    if listed(READS) {
        return ActionClass::Read;
    }
    if listed(LOCAL_WRITES) {
        return ActionClass::LocalWrite;
    }
    if tool == "google_gmail_create_draft" || tool == "mail_draft" {
        return ActionClass::Draft;
    }
    // The engine's web gate vets only a tool that declares its web egress.
    if listed(WEB_READS)
        && class.is_some_and(|class| class.performs_web_egress || class.egress_url_argument)
    {
        return ActionClass::Web;
    }
    ActionClass::Unknown
}

/// An event is a local write only with no attendees, on the owner's default
/// calendar (none named, Google's `primary`, or a blank name on a create):
/// a named calendar may be shared, and EventKit cannot prove it is not.
/// Anything set fails closed.
///
/// CAL-BLANK-CREATE: an empty or whitespace `calendar` on a create names no
/// calendar, exactly like the field being absent, so a plain create stays
/// free (ACT-FREE). The app then writes the owner's default calendar.
///
/// CAL-PRIMARY-1: `primary` is Google's id for the default. An
/// Apple calendar is found by its title, so `primary` is never taken for the
/// default; and a blank name is only the default on a create — on an update it
/// names a calendar and keeps the card (#397).
///
/// The calendar an *updated* event already sits on (`event_calendar`) is not a
/// target: it is a title, and a title never proves the default one
/// (CAL-DEFAULT-ID).
fn own_event(tool: &str, arguments: &Value, create: bool) -> ActionClass {
    let google = tool.starts_with("google_");
    let set = |key: &str| match arguments.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::Array(list)) => !list.is_empty(),
        Some(Value::String(name)) => {
            let blank = name.trim().is_empty();
            let blank_calendar = matches!(key, "calendar" | "calendar_id");
            let default =
                (google && (blank || name == "primary")) || (create && blank_calendar && blank);
            !default
        }
        Some(_) => true,
    };
    if set("attendees") {
        ActionClass::Send
    } else if set("calendar") || set("calendar_id") {
        ActionClass::Unknown
    } else {
        ActionClass::LocalWrite
    }
}

/// An update is a local write only as an [`own_event`] whose event has no
/// guests and sits on the owner's default calendar (`guests` and
/// `event_default_calendar`, set by Auxesis from a fresh calendar copy): a
/// change may notify guests, and an event Auxesis cannot see, or one it
/// cannot prove is on the default calendar, is unknown.
///
/// CAL-DEFAULT-ID: only the copy proves it, by id. A title, `primary`
/// included, or a copy with no id keeps the card.
fn own_update(tool: &str, arguments: &Value) -> ActionClass {
    match (
        own_event(tool, arguments, false),
        arguments.get("guests").map(Value::as_u64),
    ) {
        (ActionClass::LocalWrite, Some(Some(0))) if on_the_default_calendar(arguments) => {
            ActionClass::LocalWrite
        }
        // An event with guests is a send on any calendar.
        (_, Some(Some(1..))) => ActionClass::Send,
        (ActionClass::LocalWrite, _) => ActionClass::Unknown,
        (other, _) => other,
    }
}

/// True only when the calendar copy proved, by id, that the event sits on the
/// owner's default calendar. Auxesis sets it, never the model.
fn on_the_default_calendar(arguments: &Value) -> bool {
    arguments.get("event_default_calendar") == Some(&Value::Bool(true))
}

/// A skill run's card covers every call of the run: its class is the first
/// call that needs a card, else the run is free. No call is unknown.
fn classify_skill_run(_skill: &str, arguments: &Value) -> ActionClass {
    let Some(calls) = arguments.get("calls").and_then(Value::as_array) else {
        return ActionClass::Unknown;
    };
    if calls.is_empty() {
        return ActionClass::Unknown;
    }
    let null = Value::Null;
    calls
        .iter()
        .map(|call| match call.get("tool").and_then(Value::as_str) {
            Some(tool) if !tool.starts_with("skill__") => {
                classify(tool, call.get("real").unwrap_or(&null), None)
            }
            _ => ActionClass::Unknown,
        })
        .find(|class| !class.is_free())
        .unwrap_or(ActionClass::LocalWrite)
}

/// The prefix of a web gate ask raised only because the turn is sensitive
/// (taint or private owner data); its copy starts with the reason label.
pub(crate) const WEB_SENSITIVE_TURN: &str = "web: sensitive_turn";

/// A web call runs without a card when the privacy kernel can vet it: the
/// web gate asked only because the turn is sensitive (never for an owner web
/// mode, a missing judge or a private-data argument ask), and the kernel's
/// identifier screen finds no secret, ID, IBAN, card, phone or encoded data
/// in what would leave. Anything else keeps the card.
pub fn web_vetted(request: &ApprovalRequest) -> bool {
    let source = request.taint_source.as_deref().unwrap_or_default();
    let gate_ok = !request.tainted
        || source.starts_with(WEB_SENSITIVE_TURN)
        || !(source.starts_with("web") || source.starts_with("egress"));
    gate_ok && kernel_broker::argument_screen::identifier_in_arguments(&request.arguments).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_table_frees_reads_local_writes_and_delegate_only() {
        let web = ToolClass {
            performs_web_egress: true,
            egress_url_argument: true,
            ..ToolClass::default()
        };
        let mcp = ToolClass {
            arguments_leave_machine: true,
            ..ToolClass::default()
        };
        let none = json!({});
        for (tool, class, expected) in [
            ("mail_list", None, ActionClass::Read),
            ("recall", None, ActionClass::Read),
            ("privacy_record_summary", None, ActionClass::Read),
            ("crm_list", None, ActionClass::Read),
            ("remember", None, ActionClass::LocalWrite),
            ("suggest_memory", None, ActionClass::LocalWrite),
            ("write_file", None, ActionClass::LocalWrite),
            ("apple_calendar_create_event", None, ActionClass::LocalWrite),
            ("delegate", None, ActionClass::Delegate),
            ("http_fetch", Some(&web), ActionClass::Web),
            ("watch", Some(&web), ActionClass::Unknown),
            ("web_page", None, ActionClass::Unknown),
            ("google_gmail_create_draft", None, ActionClass::Draft),
            ("mail_draft", None, ActionClass::Draft),
            ("shell", None, ActionClass::Shell),
            ("mail_send", None, ActionClass::Send),
            ("google_gmail_send", None, ActionClass::Send),
            ("imessage_send", None, ActionClass::Send),
            ("forget", None, ActionClass::Delete),
            ("mail_delete", None, ActionClass::Delete),
            ("stripe_payment", None, ActionClass::Pay),
            ("install_extension", None, ActionClass::Account),
            ("mcp__crm__lookup", Some(&mcp), ActionClass::Unknown),
            ("mcp__notes__mail_list", None, ActionClass::Unknown),
            ("read_file", None, ActionClass::Read),
            ("mcp__files__read_file", None, ActionClass::Unknown),
            ("brand_new_tool", None, ActionClass::Unknown),
        ] {
            assert_eq!(classify(tool, &none, class), expected, "{tool}");
        }
        let invite = json!({ "attendees": ["ann@example.test"] });
        assert_eq!(
            classify("google_calendar_create_event", &invite, None),
            ActionClass::Send
        );
        assert_eq!(
            classify("google_calendar_create_event", &none, None),
            ActionClass::LocalWrite
        );
        let event = |calendar: &str| json!({ "title": "Focus", "calendar": calendar });
        let create = |args: &Value| classify("apple_calendar_create_event", args, None);
        assert_eq!(
            create(&json!({ "title": "Focus" })),
            ActionClass::LocalWrite
        );
        assert_eq!(create(&event("Team")), ActionClass::Unknown);
        let google = |args: &Value| classify("google_calendar_create_event", args, None);
        assert_eq!(google(&event("")), ActionClass::LocalWrite);
        assert_eq!(google(&event("primary")), ActionClass::LocalWrite);
        assert_eq!(
            create(&json!({ "attendees": "ann@example.test" })),
            ActionClass::Send
        );
        for update in [
            json!({ "guests": "0" }),
            json!({ "guests": 0, "calendar": "T" }),
            json!({ "guests": 0, "event_calendar": "Team" }),
        ] {
            let class = classify("apple_calendar_update_event", &update, None);
            assert_eq!(class, ActionClass::Unknown);
        }
    }

    /// CAL-BLANK-CREATE: an empty or whitespace `calendar` on a create means
    /// the default, exactly like an absent field, so a no-guest create stays
    /// free. Any guest, any other calendar, or a calendar titled `primary`
    /// keeps the card.
    #[test]
    fn a_blank_calendar_on_a_create_means_the_default() {
        let create = |args: &Value| classify("apple_calendar_create_event", args, None);
        for args in [
            json!({ "title": "Focus" }),
            json!({ "title": "Focus", "calendar": "" }),
            json!({ "title": "Focus", "calendar": "   " }),
            json!({ "title": "Focus", "calendar": "\t\n" }),
            json!({ "title": "Focus", "calendar_id": " " }),
        ] {
            assert_eq!(create(&args), ActionClass::LocalWrite, "{args}");
        }
        for args in [
            json!({ "title": "Focus", "calendar": "Work" }),
            json!({ "title": "Focus", "calendar": "primary" }),
        ] {
            assert_eq!(create(&args), ActionClass::Unknown, "{args}");
        }
        for calendar in ["", "   "] {
            let invite = json!({ "title": "Focus", "calendar": calendar, "attendees": ["ann@example.test"] });
            assert_eq!(create(&invite), ActionClass::Send, "{invite}");
        }
    }

    /// CAL-PRIMARY-1: an Apple calendar titled `primary` may be
    /// shared, so a create on it keeps the card. A blank name on an update
    /// still names a calendar: #397 kept that rule.
    #[test]
    fn an_apple_calendar_titled_primary_or_blank_keeps_its_card_on_an_update() {
        let create = json!({ "title": "Focus", "calendar": "primary" });
        assert_eq!(
            classify("apple_calendar_create_event", &create, None),
            ActionClass::Unknown
        );
        for update in [
            json!({ "event_id": "e", "guests": 0, "event_calendar": "primary" }),
            json!({ "event_id": "e", "guests": 0, "event_calendar": "" }),
            json!({ "event_id": "e", "guests": 0, "event_calendar": "   " }),
            json!({ "event_id": "e", "guests": 0, "calendar": "primary" }),
            json!({ "event_id": "e", "guests": 0, "calendar": "" }),
            json!({ "event_id": "e", "guests": 0, "calendar": "   " }),
        ] {
            let class = classify("apple_calendar_update_event", &update, None);
            assert_eq!(class, ActionClass::Unknown, "{update}");
        }
    }

    /// CAL-DEFAULT-ID: a move is free only when the calendar copy proved, by
    /// id, that the event sits on the owner's default calendar.
    #[test]
    fn a_move_is_free_only_on_the_default_calendar() {
        let move_of = |args: &Value| classify("apple_calendar_update_event", args, None);
        let own = json!({ "event_id": "e", "guests": 0, "event_calendar": "Home",
            "event_default_calendar": true });
        assert_eq!(move_of(&own), ActionClass::LocalWrite);
        // The proof is Auxesis's: without it, or with a false one, the card stays.
        for update in [
            json!({ "event_id": "e", "guests": 0, "event_calendar": "Home" }),
            json!({ "event_id": "e", "guests": 0, "event_default_calendar": false }),
        ] {
            assert_eq!(move_of(&update), ActionClass::Unknown);
        }
        // A guest is a send, on the default calendar too.
        let guest = json!({ "event_id": "e", "guests": 1, "event_default_calendar": true });
        assert_eq!(move_of(&guest), ActionClass::Send);
    }

    #[test]
    fn a_skill_run_is_free_only_when_every_call_is() {
        let run = |tools: &[&str]| {
            let calls: Vec<Value> = tools
                .iter()
                .map(|tool| json!({ "tool": tool, "real": {} }))
                .collect();
            classify("skill__x", &json!({ "calls": calls }), None)
        };
        assert_eq!(run(&["crm_log_interaction"]), ActionClass::LocalWrite);
        assert_eq!(
            run(&["apple_calendar_create_event"]),
            ActionClass::LocalWrite
        );
        assert_eq!(run(&["mail_search", "mail_send"]), ActionClass::Send);
        assert_eq!(run(&["mystery"]), ActionClass::Unknown);
        assert_eq!(run(&[]), ActionClass::Unknown);
        assert_eq!(classify("skill__x", &json!({}), None), ActionClass::Unknown);
    }

    #[test]
    fn a_web_call_is_vetted_only_after_a_sensitive_turn_ask_with_a_clean_screen() {
        let request = |source: Option<&str>, url: &str| ApprovalRequest {
            agent: "main".to_string(),
            tool: "http_fetch".to_string(),
            risk: kernel_broker::Risk::Medium,
            arguments: json!({ "url": url }),
            tainted: source.is_some(),
            taint_source: source.map(str::to_string),
            unsandboxed: false,
            networked: false,
        };
        let sensitive = Some("web: sensitive_turn — l'adresse …");
        let plain = "https://example.com/weather?city=Paris";
        assert!(web_vetted(&request(None, plain)));
        assert!(web_vetted(&request(sensitive, plain)));
        let iban = "https://example.com/?iban=FR7630006000011234567890189";
        assert!(!web_vetted(&request(sensitive, iban)));
        assert!(!web_vetted(&request(Some("web: mode_always_ask"), plain)));
        assert!(!web_vetted(&request(
            Some("egress: the conversation"),
            plain
        )));
    }

    #[test]
    fn a_web_call_with_a_deeply_encoded_address_is_not_vetted() {
        // FAKE: a fictional address, its `@` percent-encoded three times.
        let request = ApprovalRequest {
            agent: "main".to_string(),
            tool: "http_fetch".to_string(),
            risk: kernel_broker::Risk::Medium,
            arguments: json!({ "memo": "q7f3k9%252540example.com" }),
            tainted: true,
            taint_source: Some("web: sensitive_turn — l'adresse …".to_string()),
            unsandboxed: false,
            networked: false,
        };
        assert!(!web_vetted(&request));
    }
}
