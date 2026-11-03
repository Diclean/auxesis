//! The human approval card (APPROVAL-PREVIEW-1).
//!
//! Every ask the daemon publishes carries a card a person can read: a short
//! title, the fields of the action and the text it carries. The card shows
//! everything the action will do: the sender, every recipient, the subject,
//! the body and every attachment. A case that cannot be shown whole is
//! refused with a reason, never shortened.
//!
//! The preview is display-only: it never changes the payload the broker
//! authorizes, and it never drops what will leave the Mac.

use aux_runtime::executor::{run_calls, RunCall};
use serde_json::Value;

use super::wire::{MAX_MAIL_ARGS_BYTES, MAX_TOOL_ARGS_BYTES};

/// A card a person can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardPreview {
    /// The short title: "Send follow-up to camille@example.test".
    pub title: String,
    /// The text the action carries, verbatim: the mail body.
    pub body: String,
    /// The `label: value` lines: From, To, Cc, Bcc, Subject, the attachments.
    pub detail: Vec<String>,
}

/// The configured mail accounts, as `(id, address)`.
pub type Accounts = Vec<(String, String)>;

/// The wire tools that put a mail on the wire.
const SEND_TOOLS: [&str; 2] = ["mail_send", "google_gmail_send"];

/// The Google tools that put a message on the wire: the draft stays in the
/// owner's mailbox, the send leaves it.
const GOOGLE_TOOLS: [&str; 2] = ["google_gmail_send", "google_gmail_create_draft"];

/// The calendar tool that mails every attendee.
const CALENDAR_TOOLS: [&str; 1] = ["google_calendar_create_event"];

/// The sender a Google draft or send uses: the signed-in Google account, not
/// an SMTP mailbox (the two can be different people).
const GOOGLE_FROM: &str = "your Google account (signed in)";

/// The fields a tool never carries, per wire tool.
///
/// A card shows what leaves the Mac: a field the tool ignores is refused,
/// never shown. The owner would otherwise approve a recipient that never
/// receives the mail, or a location the invite does not carry
/// (SEND-REAL-ARGS-1).
///
/// The list is the connector's own truth: the composed SMTP message carries
/// `to` and `cc` only; the Gmail send and the Gmail draft carry a
/// recipient, a subject and a body; the Google event carries a summary, its
/// two instants, its zone and its attendees.
fn ignored_fields(tool: &str) -> Option<&'static [&'static str]> {
    match tool {
        // The SMTP send. There is no `bcc`: the message the service composes
        // carries `to` and `cc` only.
        "mail_send" => Some(&["bcc"]),
        // The Gmail send and the Gmail draft: a recipient, a subject, a body.
        "google_gmail_send" => Some(&["cc", "bcc"]),
        "google_gmail_create_draft" => Some(&["cc", "bcc"]),
        // The Google event: a summary, its two instants, its zone and its
        // attendees. The insert body carries no location and no description.
        "google_calendar_create_event" => Some(&["location", "description"]),
        _ => None,
    }
}

/// Refuse a call that carries a field its tool never sends.
///
/// The field and the tool are named, never a value: the reason goes back to
/// the model and onto the owner's screen. A field with nothing in it sends
/// nothing, so it is not a mismatch.
fn check_ignored_fields(tool: &str, arguments: &Value) -> Result<(), String> {
    let Some(ignored) = ignored_fields(tool) else {
        return Ok(());
    };
    let Some(fields) = arguments.as_object() else {
        return Ok(());
    };
    for (field, value) in fields {
        if ignored.contains(&field.as_str()) && !carries_nothing(value) {
            return Err(format!("{field} is not supported for {tool}"));
        }
    }
    Ok(())
}

/// True when a field carries nothing: a null, an empty string, an empty list
/// or an empty object.
fn carries_nothing(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        _ => false,
    }
}

/// The preview of one ask, or the reason it cannot be shown whole.
///
/// `tool` is the wire tool name, `arguments` what it was asked with and
/// `accounts` the mail accounts the sender can be named from.
pub fn build(
    tool: &str,
    arguments: &Value,
    accounts: &[(String, String)],
) -> Result<CardPreview, String> {
    if let Some(skill) = tool.strip_prefix("skill__") {
        return skill_card(skill, arguments, accounts);
    }
    if tool == "google_gmail_create_draft" {
        return draft_card(arguments);
    }
    if SEND_TOOLS.contains(&tool) {
        return send_card("mail", arguments, accounts, tool);
    }
    if CALENDAR_TOOLS.contains(&tool) {
        return event_card("invite", arguments);
    }
    let body = label_lines(arguments).join("\n");
    bounded(
        tool,
        CardPreview {
            title: humanize(tool),
            body,
            detail: Vec::new(),
        },
    )
}

/// The card of an ask, refused when a value that goes out would be shown
/// redacted.
///
/// The scrubber is the daemon's: the card shows scrubbed values, so a field
/// whose card differs from the payload is refused, never shown redacted
/// while the raw value leaves.
pub fn build_checked(
    tool: &str,
    arguments: &Value,
    accounts: &[(String, String)],
    scrub: &dyn Fn(&str) -> String,
) -> Result<CardPreview, String> {
    let card = build(tool, arguments, accounts)?;
    let mut parts = vec![card.title.as_str(), card.body.as_str()];
    parts.extend(card.detail.iter().map(String::as_str));
    for part in parts {
        if scrub(part) != part {
            return Err("a value that goes out would be shown redacted".to_string());
        }
    }
    Ok(card)
}

/// The card of the owner's edit of an ask whose arguments were `original`.
///
/// A skill run's edit must keep the run's calls, each with its tool: the
/// executor runs the card's tools with the edited `real` arguments and refuses
/// any other edit, so it is refused here too, with the reason, and the ask
/// stays pending (SEND-REAL-ARGS-1).
pub fn build_edit_checked(
    tool: &str,
    original: &Value,
    edited: &Value,
    accounts: &[(String, String)],
    scrub: &dyn Fn(&str) -> String,
) -> Result<CardPreview, String> {
    if tool.starts_with("skill__") {
        let asked = run_calls(original)?;
        let calls = run_calls(edited)?;
        if calls.len() != asked.len() {
            return Err(format!(
                "the edit has {} calls, the run has {}",
                calls.len(),
                asked.len()
            ));
        }
        for (number, (call, asked)) in calls.iter().zip(&asked).enumerate() {
            if call.tool != asked.tool {
                return Err(format!(
                    "call {} must stay `{}`, the edit names `{}`",
                    number + 1,
                    asked.tool,
                    call.tool
                ));
            }
        }
        // The card the owner approves shows what the run sends: a call that
        // carries a field its tool never sends is refused here, with the
        // reason, and the ask stays pending. The card builder refuses it too;
        // this check is the edit route's own (SEND-REAL-ARGS-1).
        for call in &calls {
            check_ignored_fields(call.tool, call.real)?;
        }
    }
    build_checked(tool, edited, accounts, scrub)
}

/// The card of a skill: the skill's name, and what its run will do.
///
/// The calls are read with the executor's own [`run_calls`], so the card
/// shows the arguments that run, and a run it cannot read is refused.
fn skill_card(
    skill: &str,
    arguments: &Value,
    accounts: &[(String, String)],
) -> Result<CardPreview, String> {
    let calls = run_calls(arguments)?;
    // Every call of the run must be showable: a call that carries a field its
    // tool never sends is refused, never shown (SEND-REAL-ARGS-1).
    for call in &calls {
        check_ignored_fields(call.tool, call.real)?;
    }
    let sends: Vec<usize> = calls
        .iter()
        .enumerate()
        .filter(|(_, call)| is_send(call))
        .map(|(index, _)| index)
        .collect();
    // One card holds one send: a run with two of them would hide a recipient
    // behind a repeated label, so the run is refused instead.
    if sends.len() > 1 {
        return Err(format!(
            "this run sends {} messages: one card cannot show them all, so it is not shown",
            sends.len()
        ));
    }
    // A run that sends shows the send: the recipients, the subject and the
    // text exactly as it leaves the Mac.
    if let Some(index) = sends.first() {
        let call = calls[*index];
        let mut card = if CALENDAR_TOOLS.contains(&call.tool) {
            event_card(skill, call.real)?
        } else {
            send_card(skill, call.real, accounts, call.tool)?
        };
        // MAIL-UNKNOWN-CONTACT-1: a `To` that is exactly an address read from
        // a received mail names its source; an edited recipient shows as is.
        let source = &arguments["recipient_source"];
        if let (Some(address), Some(label)) = (source["address"].as_str(), source["label"].as_str())
        {
            for line in &mut card.detail {
                if line.strip_prefix("To: ") == Some(address) {
                    *line = format!("To: {label}");
                }
            }
        }
        // The other calls of the same run are shown too: the owner approves
        // the whole run, not one call of it. Their labels carry the tool, so
        // they never overwrite a field of the send.
        let others: Vec<String> = calls
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != *index)
            .flat_map(|(_, call)| {
                label_lines(call.real)
                    .into_iter()
                    .map(|line| format!("{}. {line}", call.tool))
            })
            .collect();
        card.detail.extend(others);
        return Ok(card);
    }
    let lines = calls
        .iter()
        .flat_map(|call| label_lines(call.real))
        .collect::<Vec<_>>()
        .join("\n");
    bounded(
        "skill",
        CardPreview {
            title: skill.to_string(),
            body: lines,
            detail: Vec::new(),
        },
    )
}

/// The card of a send: the sender, every recipient, the subject, the body and
/// every attachment.
fn send_card(
    label: &str,
    arguments: &Value,
    accounts: &[(String, String)],
    tool: &str,
) -> Result<CardPreview, String> {
    // The card names the fields the send carries: a field the tool ignores
    // (a `bcc` on the SMTP path) is refused, never shown.
    check_ignored_fields(tool, arguments)?;
    let recipients = recipients(arguments);
    let mut detail = Vec::new();
    let mut sender_address = None;
    if GOOGLE_TOOLS.contains(&tool) {
        // The Google tools send as the signed-in account, never as an SMTP
        // mailbox: naming the wrong sender would be worse than naming none.
        detail.push(format!("From: {GOOGLE_FROM}"));
    } else {
        // The account the mail leaves from: the one the arguments name, else
        // the first. When no account is configured the card still asks — the
        // send would fail on its own — and the From stays unknown.
        if let Some((id, address)) = sender(arguments, accounts) {
            detail.push(format!("From: {address} (account {id})"));
            sender_address = Some(address);
        }
    }
    for (field, name) in [("to", "To"), ("cc", "Cc"), ("bcc", "Bcc")] {
        let value = list(arguments, field);
        if !value.is_empty() {
            detail.push(format!("{name}: {value}"));
        }
    }
    let subject = arguments
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !subject.is_empty() {
        detail.push(format!("Subject: {subject}"));
    }
    detail.extend(attachments(arguments, accounts, sender_address.as_deref())?);
    let title = if recipients.is_empty() {
        format!("Send {label}")
    } else {
        format!("Send {label} to {recipients}")
    };
    let body = arguments
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    bounded(
        tool,
        CardPreview {
            title,
            body,
            detail,
        },
    )
}

/// The card of a calendar event: Google mails every attendee as the signed-in
/// account, so the card names the organizer, every attendee and every field
/// of the event exactly as it is created. An event whose attendees cannot be
/// read is not shown.
fn event_card(label: &str, arguments: &Value) -> Result<CardPreview, String> {
    // The card names the fields the event carries: a field the insert body
    // ignores (a location, a description) is refused, never shown.
    check_ignored_fields("google_calendar_create_event", arguments)?;
    let has_attendees = arguments
        .get("attendees")
        .and_then(Value::as_array)
        .is_some_and(|attendees| !attendees.is_empty());
    // Each attendee by address; any other attendee field stays on its line.
    let attendees = match arguments.get("attendees") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item.get("email").and_then(Value::as_str) {
                Some(email) if item.as_object().is_some_and(|fields| fields.len() == 1) => {
                    email.to_string()
                }
                _ => readable(item),
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => list(arguments, "attendees"),
    };
    if has_attendees && attendees.trim().is_empty() {
        return Err("the event's attendees cannot be shown".to_string());
    }
    let mut detail = vec![format!("Organizer: {GOOGLE_FROM}")];
    if !attendees.is_empty() {
        detail.push(format!("Attendees (each gets an invite): {attendees}"));
    }
    detail.extend(
        arguments
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(field, _)| field.as_str() != "attendees" && field.as_str() != "description")
            .map(|(field, value)| format!("{field}: {}", readable(value))),
    );
    let summary = arguments
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let title = match (summary.is_empty(), attendees.is_empty()) {
        (false, false) => format!("Send {label} \u{201c}{summary}\u{201d} to {attendees}"),
        (true, false) => format!("Send {label} to {attendees}"),
        (false, true) => format!("Create event \u{201c}{summary}\u{201d}"),
        (true, true) => format!("Create event ({label})"),
    };
    let body = arguments
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    bounded(
        "google_calendar_create_event",
        CardPreview {
            title,
            body,
            detail,
        },
    )
}

/// The card of a Gmail draft: the recipients, the subject and the body, whole.
fn draft_card(arguments: &Value) -> Result<CardPreview, String> {
    // The draft carries a recipient, a subject and a body: a `cc` or a `bcc`
    // the draft never holds is refused, never shown.
    check_ignored_fields("google_gmail_create_draft", arguments)?;
    let recipients = recipients(arguments);
    if recipients.is_empty() {
        return Err("the draft has no readable recipient".to_string());
    }
    let mut detail = vec![format!("From: {GOOGLE_FROM}")];
    for (field, name) in [("to", "To"), ("cc", "Cc"), ("bcc", "Bcc")] {
        let value = list(arguments, field);
        if !value.is_empty() {
            detail.push(format!("{name}: {value}"));
        }
    }
    let subject = arguments
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !subject.is_empty() {
        detail.push(format!("Subject: {subject}"));
    }
    let body = arguments
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    bounded(
        "google_gmail_create_draft",
        CardPreview {
            title: format!("Draft to {recipients}"),
            body,
            detail,
        },
    )
}

/// True when the tool carries a mail: a send, a draft, or a skill run that
/// may send one.
pub fn carries_mail(tool: &str) -> bool {
    tool.starts_with("skill__") || SEND_TOOLS.contains(&tool) || GOOGLE_TOOLS.contains(&tool)
}

/// The card, refused when it does not fit: a card never shows less than the
/// action will do, so an action too big for a card is refused instead of
/// being shortened. A mail body is shown whole and scrolls in the app.
fn bounded(tool: &str, card: CardPreview) -> Result<CardPreview, String> {
    let limit = if carries_mail(tool) {
        MAX_MAIL_ARGS_BYTES
    } else {
        MAX_TOOL_ARGS_BYTES
    };
    let size = card.body.len() + card.detail.iter().map(String::len).sum::<usize>();
    if size > limit {
        return Err(format!(
            "too long to show for approval: {size} bytes, a card shows {limit}"
        ));
    }
    Ok(card)
}

/// True when one call of a run puts a message on the wire: a mail, or a
/// calendar event that mails its attendees.
fn is_send(call: &RunCall<'_>) -> bool {
    if SEND_TOOLS.contains(&call.tool) || GOOGLE_TOOLS.contains(&call.tool) {
        return true;
    }
    CALENDAR_TOOLS.contains(&call.tool)
        && !call
            .real
            .get("attendees")
            .and_then(Value::as_array)
            .map(Vec::is_empty)
            .unwrap_or(true)
}

/// The account a send goes out from, and the address it uses.
///
/// The mail tool picks the account the arguments name, else the first one; an
/// account it does not know has no address to show, so the card is refused.
fn sender(arguments: &Value, accounts: &[(String, String)]) -> Option<(String, String)> {
    match arguments.get("account").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => accounts.iter().find(|(account, _)| account == id).cloned(),
        _ => accounts.first().cloned(),
    }
}

/// The recipients of a send, every one of them, as they will be addressed.
pub fn recipients(arguments: &Value) -> String {
    list(arguments, "to")
}

/// One address list of the arguments, comma separated.
fn list(arguments: &Value, field: &str) -> String {
    match arguments.get(field) {
        Some(Value::Array(items)) => items.iter().map(readable).collect::<Vec<_>>().join(", "),
        Some(value) => readable(value),
        None => String::new(),
    }
}

/// The attachments a send carries, each by name.
///
/// The calendar invite leaves as an `invite.ics` part, so the card names it
/// and repeats what it says. The runtime builds that invite with the first
/// account as its organizer, so a send that leaves from another account would
/// show the wrong one: it is refused instead.
fn attachments(
    arguments: &Value,
    accounts: &[(String, String)],
    sender_address: Option<&str>,
) -> Result<Vec<String>, String> {
    let Some(ics) = arguments
        .get("ics")
        .and_then(Value::as_str)
        .filter(|ics| !ics.is_empty())
    else {
        return Ok(Vec::new());
    };
    let organizer = accounts
        .first()
        .map(|(_, email)| email.clone())
        .unwrap_or_default();
    if !organizer.is_empty() && Some(organizer.as_str()) != sender_address {
        return Err(
            "the calendar invite leaves with another account as its organizer: refusing"
                .to_string(),
        );
    }
    let mut line = "Attachment: invite.ics".to_string();
    let summary = ics_field(ics, "SUMMARY");
    let start = ics_field(ics, "DTSTART");
    match (summary, start) {
        (Some(summary), Some(start)) => {
            line.push_str(&format!(" (calendar invite: {summary}, {start}"))
        }
        (Some(summary), None) => line.push_str(&format!(" (calendar invite: {summary})")),
        (None, Some(start)) => line.push_str(&format!(" (calendar invite: {start})")),
        (None, None) => {}
    }
    if !organizer.is_empty() {
        line.push_str(&format!("; Organizer: {organizer})"));
    }
    Ok(vec![line])
}

/// One field of a calendar invite, unfolded.
fn ics_field(ics: &str, name: &str) -> Option<String> {
    let mut value: Option<String> = None;
    for line in ics.split("\r\n").flat_map(|line| line.split('\n')) {
        match (value.as_mut(), line.strip_prefix(' ')) {
            // A folded line continues the field before it.
            (Some(value), Some(rest)) => value.push_str(rest),
            (Some(_), None) => {}
            (None, Some(_)) => {}
            (None, None) => {
                if let Some(rest) = line.strip_prefix(&format!("{name}:")) {
                    value = Some(rest.to_string());
                }
            }
        }
    }
    value.filter(|value| !value.is_empty())
}

/// The `label: value` lines of one set of arguments.
fn label_lines(arguments: &Value) -> Vec<String> {
    match arguments.as_object() {
        Some(fields) => fields
            .iter()
            .map(|(label, value)| format!("{label}: {}", readable(value)))
            .collect(),
        None => Vec::new(),
    }
}

/// One value in the owner's words: no braces, no quotes, no JSON.
fn readable(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => String::new(),
        Value::Array(items) => items.iter().map(readable).collect::<Vec<_>>().join(", "),
        Value::Object(fields) => fields
            .iter()
            .map(|(label, value)| format!("{label}: {}", readable(value)))
            .collect::<Vec<_>>()
            .join("; "),
    }
}

/// A tool's name in the owner's words: "write_file" → "Write file".
fn humanize(tool: &str) -> String {
    let text = tool.replace(['_', '.'], " ");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// One configured mail account: the card names the address a mail leaves
    /// from.
    fn accounts() -> Accounts {
        vec![("work".to_string(), "owner@example.test".to_string())]
    }

    /// A skill run that sends one mail with a calendar invite.
    fn send_fill() -> Value {
        json!({
            "skill": "follow-up", "skill_version": 1, "skill_hash": "9f2c1d",
            "calls": [{
                "tool": "mail_send",
                "real": {
                    "account": "work",
                    "to": ["camille@example.test"],
                    "cc": ["lea@example.test"],
                    "subject": "Re: our last exchange",
                    "body": "Hi Camille,\n\nFollowing up on the quote.",
                    "ics": "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:evt-1@auxesis.local\r\nDTSTAMP:20261011T080000Z\r\nDTSTART:20261011T100000Z\r\nDTEND:20261011T103000Z\r\nSUMMARY:Design review\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
                },
                "model_saw": { "to": ["⟦EMAIL_1⟧"], "body": "Hi ⟦PERSON_1⟧" }
            }]
        })
    }

    /// MAIL-UNKNOWN-CONTACT-1: a recipient from a received mail's `From` shows
    /// its full address and source on the `To` line; an edited `To` as it is.
    #[test]
    fn a_recipient_from_the_mailbox_shows_its_full_address_and_source() {
        let mut fill = send_fill();
        let label = "Camille F <camille@example.test> (not in Clients: from their mail of 26 Sep)";
        fill["recipient_source"] = json!({ "address": "camille@example.test", "label": label });
        let card = build("skill__follow-up", &fill, &accounts()).expect("a card");
        assert!(card.detail.contains(&format!("To: {label}")));
        fill["calls"][0]["real"]["to"] = json!(["other@example.test"]);
        let card = build("skill__follow-up", &fill, &accounts()).expect("a card");
        assert!(card.detail.contains(&"To: other@example.test".to_string()));
    }

    /// CLIENT-TZ-FIELD: the invite card says the client card supplied the
    /// attendee's zone, on the calendar call's own line.
    #[test]
    fn a_client_card_zone_is_said_on_the_invite_card() {
        let fill = json!({
            "skill": "send-invite", "skill_version": 1, "skill_hash": "dd",
            "calls": [
                { "tool": "apple_calendar_create_event", "real": {
                    "title": "Meeting with Camille", "start": "2026-10-26T10:00:00+01:00",
                    "end": "2026-10-26T10:30:00+01:00", "time_zone": "Europe/Paris",
                    "attendee_time_zone": "Asia/Tokyo",
                    "attendee_time_zone_source": "client card (the model said America/New_York)",
                    "attendee_start": "2026-10-26T18:00:00+09:00" } },
                { "tool": "mail_send", "real": { "to": ["camille@example.test"],
                    "subject": "Invitation", "body": "Hello.", "ics": "event" } }
            ]
        });
        let card = build("skill__send-invite", &fill, &accounts()).expect("a card");
        for expected in [
            "apple_calendar_create_event. attendee_time_zone: Asia/Tokyo",
            "apple_calendar_create_event. attendee_time_zone_source: client card (the model said America/New_York)",
            "apple_calendar_create_event. attendee_start: 2026-10-26T18:00:00+09:00",
        ] {
            assert!(
                card.detail.iter().any(|line| line == expected),
                "missing {expected:?}: {:?}",
                card.detail
            );
        }
    }

    /// A Google draft never names an SMTP mailbox as its sender: it sends as
    /// the signed-in Google account.
    #[test]
    fn a_google_draft_names_the_signed_in_account_not_an_smtp_mailbox() {
        let card = build(
            "google_gmail_create_draft",
            &json!({ "to": "camille@example.test", "subject": "Invoice", "body": "Hello." }),
            &accounts(),
        )
        .expect("a card");
        assert!(
            card.detail
                .iter()
                .any(|line| line == "From: your Google account (signed in)"),
            "{:?}",
            card.detail
        );
        assert!(
            !card
                .detail
                .iter()
                .any(|line| line.contains("owner@example.test")),
            "the SMTP mailbox is not the Google sender: {:?}",
            card.detail
        );
    }

    /// A calendar event that mails its attendees is a send: a run with one
    /// beside a mail hides a second message, so it is refused.
    #[test]
    fn a_calendar_with_attendees_counts_as_a_send() {
        let fill = json!({
            "skill": "invite-and-mail", "skill_version": 1, "skill_hash": "bb",
            "calls": [
                { "tool": "google_calendar_create_event", "real": {
                    "summary": "Design review", "start": "2026-10-27T14:00:00+02:00",
                    "attendees": [{ "email": "camille@example.test" }] } },
                { "tool": "mail_send", "real": { "to": ["lea@example.test"], "body": "one" } }
            ]
        });
        let reason = build("skill__invite-and-mail", &fill, &accounts()).expect_err("two sends");
        assert!(reason.contains("sends 2 messages"), "{reason}");
    }

    /// A calendar invite shows the Google organizer, every attendee and the
    /// event, never a mail sender from SMTP.
    #[test]
    fn a_calendar_invite_shows_the_organizer_the_attendees_and_the_event() {
        let fill = json!({
            "skill": "invite", "skill_version": 1, "skill_hash": "cc",
            "calls": [
                { "tool": "google_calendar_create_event", "real": {
                    "summary": "Board review", "start": "2026-10-27T14:00:00+02:00",
                    "attendees": [{ "email": "board@example.test" }] } }
            ]
        });
        let card = build("skill__invite", &fill, &accounts()).expect("a card");

        assert_eq!(
            card.title,
            "Send invite \u{201c}Board review\u{201d} to board@example.test"
        );
        for expected in [
            "Organizer: your Google account (signed in)",
            "Attendees (each gets an invite): board@example.test",
            "start: 2026-10-27T14:00:00+02:00",
        ] {
            assert!(
                card.detail.iter().any(|line| line == expected),
                "missing {expected:?}: {:?}",
                card.detail
            );
        }
        assert!(
            !card
                .detail
                .iter()
                .any(|line| line.starts_with("From: owner@")),
            "{:?}",
            card.detail
        );
    }

    /// A card shows what leaves the Mac: a field the tool never sends is
    /// refused, never shown. The SMTP send has no `bcc`, so a send that names
    /// one is refused instead of a card that promises a hidden recipient.
    #[test]
    fn a_mail_send_card_never_shows_a_bcc_the_send_does_not_carry() {
        let reason = build(
            "mail_send",
            &json!({
                "to": ["to@example.test"], "bcc": ["hidden@example.test"],
                "subject": "S", "body": "B"
            }),
            &accounts(),
        )
        .expect_err("a bcc is not sent");
        assert!(
            reason.contains("bcc is not supported for mail_send"),
            "{reason}"
        );
        // An empty field sends nothing: it is not a mismatch.
        let card = build(
            "mail_send",
            &json!({ "to": ["to@example.test"], "bcc": [], "subject": "S", "body": "B" }),
            &accounts(),
        )
        .expect("a card");
        assert!(
            !card.detail.iter().any(|line| line.starts_with("Bcc:")),
            "{:?}",
            card.detail
        );
        // The card of a send shows the recipients it does send.
        let card = build(
            "mail_send",
            &json!({ "to": ["to@example.test"], "cc": ["cc@example.test"] }),
            &accounts(),
        )
        .expect("a card");
        assert!(
            card.detail.iter().any(|line| line == "Cc: cc@example.test"),
            "{:?}",
            card.detail
        );
    }

    /// The owner's edit is checked like the card: an edit that adds a `bcc` to
    /// a mail send is refused, with the reason, and the ask stays pending.
    #[test]
    fn an_edit_that_adds_a_bcc_to_a_mail_send_is_refused() {
        let original = json!({
            "skill": "follow-up", "skill_version": 1, "skill_hash": "9f2c1d",
            "calls": [{ "tool": "mail_send", "real": {
                "to": ["to@example.test"], "subject": "S", "body": "B" } }]
        });
        let edited = json!({
            "skill": "follow-up", "skill_version": 1, "skill_hash": "9f2c1d",
            "calls": [{ "tool": "mail_send", "real": {
                "to": ["to@example.test"], "bcc": ["hidden@example.test"],
                "subject": "S", "body": "B" } }]
        });
        let reason = build_edit_checked(
            "skill__follow-up",
            &original,
            &edited,
            &accounts(),
            &|text| text.to_string(),
        )
        .expect_err("a bcc is not sent");
        assert!(
            reason.contains("bcc is not supported for mail_send"),
            "{reason}"
        );
        // The same edit on the tool itself is refused the same way.
        let reason = build_edit_checked(
            "mail_send",
            &json!({ "to": ["to@example.test"] }),
            &json!({ "to": ["to@example.test"], "bcc": ["hidden@example.test"] }),
            &accounts(),
            &|text| text.to_string(),
        )
        .expect_err("a bcc is not sent");
        assert!(
            reason.contains("bcc is not supported for mail_send"),
            "{reason}"
        );
    }

    /// The Google event carries a summary, its instants, its zone and its
    /// attendees: a location or a description the insert body never holds is
    /// refused, never shown.
    #[test]
    fn a_calendar_invite_with_a_field_the_event_never_carries_is_refused() {
        for (field, why) in [
            (
                "location",
                "location is not supported for google_calendar_create_event",
            ),
            (
                "description",
                "description is not supported for google_calendar_create_event",
            ),
        ] {
            let mut arguments = json!({
                "summary": "Board review", "start": "2026-10-27T14:00:00+02:00",
                "attendees": [{ "email": "board@example.test" }]
            });
            arguments[field] = json!("Room 2");
            let reason =
                build("google_calendar_create_event", &arguments, &accounts()).expect_err(why);
            assert!(reason.contains(why), "{reason}");
        }
    }

    /// The Gmail send and the Gmail draft hold a recipient, a subject and a
    /// body: a `cc` or a `bcc` they never carry is refused, never shown.
    #[test]
    fn a_gmail_send_or_draft_with_a_cc_or_a_bcc_is_refused() {
        for tool in ["google_gmail_send", "google_gmail_create_draft"] {
            for field in ["cc", "bcc"] {
                let reason = build(
                    tool,
                    &json!({
                        "to": "to@example.test", field: "hidden@example.test",
                        "subject": "S", "body": "B"
                    }),
                    &accounts(),
                )
                .expect_err("a cc or a bcc is not sent");
                assert!(
                    reason.contains(&format!("{field} is not supported for {tool}")),
                    "{reason}"
                );
            }
        }
    }

    /// A send shows the sender, every recipient, the subject, the body and
    /// every attachment.
    #[test]
    fn a_send_shows_the_sender_the_recipients_the_subject_the_body_and_the_attachment() {
        let card = build("skill__follow-up", &send_fill(), &accounts()).expect("a card");

        assert_eq!(card.title, "Send follow-up to camille@example.test");
        assert_eq!(card.body, "Hi Camille,\n\nFollowing up on the quote.");
        for expected in [
            "From: owner@example.test (account work)",
            "To: camille@example.test",
            "Cc: lea@example.test",
            "Subject: Re: our last exchange",
            "Attachment: invite.ics (calendar invite: Design review, 20261011T100000Z; \
             Organizer: owner@example.test)",
        ] {
            assert!(
                card.detail.iter().any(|line| line == expected),
                "missing {expected:?}: {:?}",
                card.detail
            );
        }
        // Never the fill: no JSON, no internal marker, no token.
        for line in std::iter::once(&card.title)
            .chain(std::iter::once(&card.body))
            .chain(card.detail.iter())
        {
            assert!(!line.contains("{\""), "{line}");
            assert!(!line.contains("skill_hash"), "{line}");
            assert!(!line.contains('⟦'), "{line}");
        }
    }

    /// The runtime builds the invite with the first account as its organizer:
    /// a send that leaves from another account would show the wrong one.
    #[test]
    fn an_invite_whose_organizer_is_another_account_is_refused() {
        let mut fill = send_fill();
        fill["calls"][0]["real"]["account"] = json!("other");
        let mut accounts = accounts();
        accounts.push(("other".to_string(), "other@example.test".to_string()));
        let reason = build("skill__follow-up", &fill, &accounts).expect_err("another organizer");
        assert!(reason.contains("organizer"), "{reason}");
    }

    /// A send is asked even when no account is configured: the card shows
    /// what the owner must approve, and the send itself fails on its own.
    #[test]
    fn a_send_without_a_configured_account_is_still_asked() {
        let card = build("mail_send", &json!({ "to": ["a@example.test"] }), &[]).expect("a card");
        assert_eq!(card.title, "Send mail to a@example.test");
        assert!(
            !card.detail.iter().any(|line| line.starts_with("From:")),
            "no account, no sender: {:?}",
            card.detail
        );
    }

    /// A Gmail draft shows its body whole: the card never shows less than the
    /// draft will carry.
    #[test]
    fn a_gmail_draft_shows_its_body_whole() {
        let body = "A".repeat(20 * 1024) + "THE-END";
        let card = build(
            "google_gmail_create_draft",
            &json!({ "to": "camille@example.test", "subject": "Invoice", "body": body }),
            &[],
        )
        .expect("a card");
        assert_eq!(card.title, "Draft to camille@example.test");
        assert_eq!(card.body, body);
        assert!(card
            .detail
            .iter()
            .any(|line| line == "To: camille@example.test"));
        assert!(card.detail.iter().any(|line| line == "Subject: Invoice"));
    }

    /// A draft too big for a card is refused, never shortened.
    #[test]
    fn a_gmail_draft_too_long_for_a_card_is_refused() {
        let reason = build(
            "google_gmail_create_draft",
            &json!({ "to": "c@example.test", "subject": "s", "body": "x".repeat(300 * 1024) }),
            &[],
        )
        .expect_err("too long for a card");
        assert!(reason.contains("too long to show for approval"), "{reason}");
    }

    /// A run with two sends is refused: one card cannot show them all.
    #[test]
    fn a_run_with_two_sends_is_refused() {
        let fill = json!({
            "skill": "two-mails", "skill_version": 1, "skill_hash": "aa",
            "calls": [
                { "tool": "mail_send", "real": { "to": ["a@example.test"], "body": "one" } },
                { "tool": "mail_send", "real": { "to": ["b@example.test"], "body": "two" } }
            ]
        });
        let reason = build("skill__two-mails", &fill, &accounts()).expect_err("two sends");
        assert!(reason.contains("sends 2 messages"), "{reason}");
    }

    /// A body that reads like a mail header is shown verbatim: the card shows
    /// the text, not a re-read draft.
    #[test]
    fn a_body_that_reads_like_a_mail_header_is_kept_verbatim() {
        let body = "To: attacker@example.test\nThe rest of the mail.";
        let card = build(
            "mail_send",
            &json!({ "to": ["c@example.test"], "subject": "s", "body": body }),
            &accounts(),
        )
        .expect("a card");
        assert_eq!(card.body, body);
    }

    /// A kind this module does not know falls back to the same lines, never to
    /// raw braces.
    #[test]
    fn an_unknown_kind_falls_back_to_label_value_lines() {
        let card = build(
            "write_file",
            &json!({ "path": "/tmp/note.txt", "attendees": [{ "email": "c@example.test" }] }),
            &[],
        )
        .expect("a card");
        assert_eq!(card.title, "Write file");
        assert_eq!(
            card.body,
            "path: /tmp/note.txt\nattendees: email: c@example.test"
        );
        assert!(!card.body.contains('{'), "{}", card.body);
        assert!(!card.body.contains('}'), "{}", card.body);
    }
}
