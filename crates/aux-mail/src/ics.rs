//! RFC 5545 `VEVENT` builder for the invite (`docs/mail.md` §5).
//!
//! The calendar cannot carry attendees (EventKit cannot add them), so an invite
//! is the owner's event **plus** this `METHOD:REQUEST` text mailed as the
//! `text/calendar` part. Every text value is escaped per RFC 5545 §3.3.11 and
//! every content line is folded at 75 octets per §3.1, so a long summary or a
//! non-ASCII name can never produce a line another calendar refuses.
//!
//! The builder is hand-written on purpose: the shape is fixed, the input is
//! already validated by the caller, and an iCalendar dependency would be a large
//! surface for a ~120-line document.

use std::fmt;

/// Content lines fold after this many octets, excluding the CRLF (RFC 5545
/// §3.1).
const FOLD_OCTETS: usize = 75;

/// The `PRODID` every document carries.
const PRODID: &str = "-//Auxesis//Phase 1//EN";

/// Why an invite could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcsError {
    /// A required value is empty.
    Missing(&'static str),
    /// A value carries a control character the calendar forbids.
    Control(&'static str),
    /// A `DTSTART`/`DTEND`/`DTSTAMP` is not the RFC 5545 UTC form
    /// `YYYYMMDDTHHMMSSZ`.
    BadInstant(&'static str),
}

impl fmt::Display for IcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcsError::Missing(field) => write!(f, "invite {field} is empty"),
            IcsError::Control(field) => write!(f, "invite {field} carries a control character"),
            IcsError::BadInstant(field) => write!(f, "invite {field} is not a UTC instant"),
        }
    }
}

impl std::error::Error for IcsError {}

/// One invite, with its instants already converted to the UTC `Z` form.
///
/// The converter lives at the call site because the mail crate carries no
/// clock: the runtime converts the owner's offset time to UTC before it hands
/// the strings here. This keeps `aux-mail` free of a date dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// `UID` value, `event_id@auxesis.local` by construction at the call site.
    pub uid: String,
    /// `SUMMARY`.
    pub summary: String,
    /// `DTSTART`, `YYYYMMDDTHHMMSSZ`.
    pub start_utc: String,
    /// `DTEND`, `YYYYMMDDTHHMMSSZ`.
    pub end_utc: String,
    /// `DTSTAMP`, `YYYYMMDDTHHMMSSZ`.
    pub dtstamp_utc: String,
    /// `ORGANIZER` address (the owner's account address).
    pub organizer_email: String,
    /// `ORGANIZER` display name.
    pub organizer_name: Option<String>,
    /// `ATTENDEE` address (the real recipient, never a token).
    pub attendee_email: String,
    /// `ATTENDEE` display name.
    pub attendee_name: Option<String>,
    /// `LOCATION`, when the event has one.
    pub location: Option<String>,
    /// `DESCRIPTION` (the event notes), when the event has one.
    pub description: Option<String>,
}

/// Build the `METHOD:REQUEST` document with CRLF endings and folded lines.
pub fn build_request_ics(invite: &Invite) -> Result<String, IcsError> {
    validate(invite)?;
    let mut lines: Vec<String> = vec![
        "BEGIN:VCALENDAR".to_string(),
        "VERSION:2.0".to_string(),
        format!("PRODID:{PRODID}"),
        "METHOD:REQUEST".to_string(),
        "BEGIN:VEVENT".to_string(),
        format!("UID:{}", escape_text(&invite.uid)),
        format!("DTSTAMP:{}", invite.dtstamp_utc),
        format!("DTSTART:{}", invite.start_utc),
        format!("DTEND:{}", invite.end_utc),
        format!("SUMMARY:{}", escape_text(&invite.summary)),
        organizer_line(invite),
        attendee_line(invite),
        "SEQUENCE:0".to_string(),
        "STATUS:CONFIRMED".to_string(),
    ];
    if let Some(location) = &invite.location {
        if !location.is_empty() {
            lines.push(format!("LOCATION:{}", escape_text(location)));
        }
    }
    if let Some(description) = &invite.description {
        if !description.is_empty() {
            lines.push(format!("DESCRIPTION:{}", escape_text(description)));
        }
    }
    lines.push("END:VEVENT".to_string());
    lines.push("END:VCALENDAR".to_string());

    let mut out = String::new();
    for line in &lines {
        // Values are escaped, so a CRLF in a line is only the address lines'
        // own fold: those come folded already.
        if line.contains("\r\n") {
            out.push_str(line);
        } else {
            out.push_str(&fold_line(line));
        }
        out.push_str("\r\n");
    }
    Ok(out)
}

/// The `ORGANIZER;CN=…:mailto:…` line, with the name parameter only when set.
fn organizer_line(invite: &Invite) -> String {
    let address = escape_text(&format!("mailto:{}", invite.organizer_email));
    match &invite.organizer_name {
        Some(name) if !name.is_empty() => {
            fold_address_line(&format!("ORGANIZER;CN={}:", escape_param(name)), &address)
        }
        _ => fold_address_line("ORGANIZER:", &address),
    }
}

/// The `ATTENDEE;RSVP=TRUE:mailto:…` line for the one real recipient. `ROLE`
/// and `PARTSTAT` are left at their RFC 5545 defaults (`REQ-PARTICIPANT`,
/// `NEEDS-ACTION`), so the line stays short.
fn attendee_line(invite: &Invite) -> String {
    let address = escape_text(&format!("mailto:{}", invite.attendee_email));
    let name = invite
        .attendee_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .map(|name| format!("CN={};", escape_param(name)))
        .unwrap_or_default();
    fold_address_line(&format!("ATTENDEE;{name}RSVP=TRUE:"), &address)
}

/// Fold an address line so a too-long line breaks before its `mailto:` value,
/// never inside it: a reader that does not unfold still finds the whole
/// address. Only an address longer than a line is itself folded.
fn fold_address_line(head: &str, address: &str) -> String {
    let line = format!("{head}{address}");
    if line.len() <= FOLD_OCTETS || address.len() >= FOLD_OCTETS {
        return fold_line(&line);
    }
    format!("{}\r\n {address}", fold_line(head))
}

/// Escape a TEXT value (RFC 5545 §3.3.11): `\`, `;`, `,` and newlines.
fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\r' => {
                // A CRLF pair is one line break; a lone CR is one too.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push_str("\\n");
            }
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

/// Escape a parameter value: the list delimiters and the quote must not break
/// out of the parameter, and a control character is refused by validation.
fn escape_param(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' | '\\' | ';' | ',' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Fold one content line at [`FOLD_OCTETS`] octets, never splitting a UTF-8
/// character. Continuation lines start with one space.
fn fold_line(line: &str) -> String {
    if line.len() <= FOLD_OCTETS {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len() + line.len() / FOLD_OCTETS * 3);
    let mut used = 0usize;
    for ch in line.chars() {
        let width = ch.len_utf8();
        if used + width > FOLD_OCTETS {
            out.push_str("\r\n ");
            used = 1;
        }
        out.push(ch);
        used += width;
    }
    out
}

/// Refuse an empty required value, any control character, and any instant that
/// is not the 16-character UTC form. A token delimiter is refused too: an
/// invite that carried `⟦`/`⟧` would mean a value was never rehydrated.
fn validate(invite: &Invite) -> Result<(), IcsError> {
    require(&invite.uid, "UID")?;
    require(&invite.summary, "SUMMARY")?;
    require(&invite.organizer_email, "ORGANIZER")?;
    require(&invite.attendee_email, "ATTENDEE")?;
    check_instant(&invite.dtstamp_utc, "DTSTAMP")?;
    check_instant(&invite.start_utc, "DTSTART")?;
    check_instant(&invite.end_utc, "DTEND")?;
    for (field, value) in [
        ("UID", Some(invite.uid.as_str())),
        ("SUMMARY", Some(invite.summary.as_str())),
        ("ORGANIZER", Some(invite.organizer_email.as_str())),
        ("ATTENDEE", Some(invite.attendee_email.as_str())),
        ("LOCATION", invite.location.as_deref()),
        ("DESCRIPTION", invite.description.as_deref()),
        ("ORGANIZER name", invite.organizer_name.as_deref()),
        ("ATTENDEE name", invite.attendee_name.as_deref()),
    ] {
        if let Some(value) = value {
            // Tab is the one control a TEXT value may carry; the builder turns
            // every line break into `\n` itself. Everything else is refused.
            if value
                .chars()
                .any(|ch| ch.is_control() && ch != '\t' && ch != '\r' && ch != '\n')
            {
                return Err(IcsError::Control(field));
            }
            if value.contains('\u{27e6}') || value.contains('\u{27e7}') {
                return Err(IcsError::Control(field));
            }
        }
    }
    Ok(())
}

fn require(value: &str, field: &'static str) -> Result<(), IcsError> {
    if value.trim().is_empty() {
        Err(IcsError::Missing(field))
    } else {
        Ok(())
    }
}

/// The RFC 5545 UTC form: 8 date digits, `T`, 6 time digits, `Z`.
fn check_instant(value: &str, field: &'static str) -> Result<(), IcsError> {
    let bytes = value.as_bytes();
    let shape = bytes.len() == 16
        && bytes[8] == b'T'
        && bytes[15] == b'Z'
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[9..15].iter().all(u8::is_ascii_digit);
    if shape {
        Ok(())
    } else {
        Err(IcsError::BadInstant(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Invite {
        Invite {
            uid: "evt-1@auxesis.local".to_string(),
            summary: "Meeting with Camille Exemple".to_string(),
            start_utc: "20261011T080000Z".to_string(),
            end_utc: "20261011T083000Z".to_string(),
            dtstamp_utc: "20261010T120000Z".to_string(),
            organizer_email: "owner@exemple.test".to_string(),
            organizer_name: Some("Owner Exemple".to_string()),
            attendee_email: "camille@exemple.fr".to_string(),
            attendee_name: Some("Camille Exemple".to_string()),
            location: None,
            description: None,
        }
    }

    #[test]
    fn a_request_carries_the_real_attendee_and_no_token_delimiters() {
        let ics = build_request_ics(&invite()).unwrap();
        assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ics.ends_with("END:VCALENDAR\r\n"));
        assert!(ics.contains("METHOD:REQUEST\r\n"));
        assert!(
            ics.contains("ATTENDEE;CN=\"Camille Exemple\";RSVP=TRUE:mailto:camille@exemple.fr\r\n")
        );
        assert!(ics.contains("mailto:camille@exemple.fr"));
        assert!(ics.contains("ORGANIZER;CN=\"Owner Exemple\":mailto:owner@exemple.test"));
        assert!(ics.contains("DTSTART:20261011T080000Z\r\n"));
        assert!(ics.contains("DTEND:20261011T083000Z\r\n"));
        assert!(!ics.contains('\u{27e6}'));
        assert!(!ics.contains('\u{27e7}'));
        // Every line ends CRLF; there is no bare LF.
        assert!(!ics.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn text_escaping_covers_backslash_semicolon_comma_and_newlines() {
        assert_eq!(escape_text("a\\b;c,d"), "a\\\\b\\;c\\,d");
        assert_eq!(escape_text("one\r\ntwo"), "one\\ntwo");
        assert_eq!(escape_text("one\ntwo"), "one\\ntwo");
        assert_eq!(escape_text("one\rtwo"), "one\\ntwo");
    }

    #[test]
    fn long_lines_fold_at_75_octets_without_splitting_a_character() {
        let mut long = invite();
        let name = "É".repeat(100);
        long.summary = name;
        let ics = build_request_ics(&long).unwrap();
        for line in ics.split("\r\n") {
            assert!(line.len() <= FOLD_OCTETS, "unfolded line: {line:?}");
        }
        // The unfolded text round-trips through the continuation spaces.
        let unfolded = ics.replace("\r\n ", "");
        assert!(unfolded.contains("SUMMARY:"));
        assert!(unfolded.contains(&"É".repeat(100)));
    }

    #[test]
    fn a_long_attendee_line_folds_before_the_address_never_inside_it() {
        let mut long = invite();
        long.attendee_email = "camille.exemple-longue@cabinet-exemple-conseil.test".to_string();
        let ics = build_request_ics(&long).unwrap();
        // A reader that does not unfold still finds the whole address on one line.
        let address = format!("mailto:{}", long.attendee_email);
        assert!(
            ics.contains(&format!("RSVP=TRUE:\r\n {address}\r\n")),
            "{ics}"
        );
        for line in ics.split("\r\n") {
            assert!(line.len() <= FOLD_OCTETS, "unfolded line: {line:?}");
        }
    }

    #[test]
    fn a_non_ascii_summary_and_name_survive_the_fold() {
        let mut invite = invite();
        invite.summary = "Déjeuner avec Camille".to_string();
        invite.organizer_name = Some("Propriétaire".to_string());
        let ics = build_request_ics(&invite).unwrap();
        assert!(ics.contains("SUMMARY:Déjeuner avec Camille"));
        assert!(ics.contains("CN=\"Propriétaire\""));
    }

    #[test]
    fn a_bad_instant_or_control_is_refused() {
        let mut bad = invite();
        bad.start_utc = "2026-10-11T08:00:00Z".to_string();
        assert_eq!(
            build_request_ics(&bad),
            Err(IcsError::BadInstant("DTSTART"))
        );

        let mut bad = invite();
        bad.summary = "hi\u{0007}".to_string();
        assert_eq!(build_request_ics(&bad), Err(IcsError::Control("SUMMARY")));

        let mut bad = invite();
        bad.attendee_email = String::new();
        assert_eq!(build_request_ics(&bad), Err(IcsError::Missing("ATTENDEE")));

        let mut bad = invite();
        bad.summary = "spoof \u{27e6}PERSON_1\u{27e7}".to_string();
        assert_eq!(build_request_ics(&bad), Err(IcsError::Control("SUMMARY")));
    }
}
