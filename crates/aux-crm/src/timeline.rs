//! B3: attach mail threads and calendar events to parties, and create
//! follow-ups for them.
//!
//! The builders take neutral, already-bounded inputs. They never see a mail
//! body: [`MailThread`] carries headers only (subject, date, From/To/Cc), and
//! [`CalendarEvent`] carries a title, a start and the attendee addresses. A
//! match is an **exact, case-folded address match** against `party.emails`; the
//! stored row holds only the provider reference, the date, the direction and a
//! summary built locally from the subject (or title). The unique
//! `(party_id, kind, source_ref)` key makes a re-run idempotent.
//!
//! # The summary is minted through the kernel gate
//!
//! A subject is hostile text. [`summary_gate`] asks the kernel for the CRM
//! storage row ([`PathId::G3`]) and mints the summary through
//! [`Gate::for_passthrough`] — the constructor for a **local** destination: the
//! detectors run and the report is kept, but nothing is masked, so the value
//! stays real at rest (D24: storage is not egress). The mint fails closed, and
//! every read of the summary into a provider context passes `admit()` again
//! (`docs/phase1.md` §2). The result is then capped with the same sanitiser
//! the mail connector uses for headers.

use std::collections::BTreeSet;

use aux_store::Followup;
use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::safetext::Gate;

use crate::{Crm, CrmError};

/// Hard cap on a stored timeline summary, matching the store's own check.
const SUMMARY_BYTES: usize = aux_store::INTERACTION_SUMMARY_MAX_BYTES;

/// The kernel's truncation marker adds a head/tail note after the cap, so the
/// text is capped below the store's limit to leave room for it.
const SUMMARY_INPUT_BUDGET: usize = SUMMARY_BYTES - 96;

/// Longest stored thread reference (`msg-id` is capped at 998 bytes).
pub const MESSAGE_ID_MAX_BYTES: usize = 998;

/// One grouped mail thread, headers only.
///
/// `from`, `to`, `cc` and `owner` aggregate every address seen across the
/// thread, in any of the shapes IMAP gives (`Name <a@b>`, a bare address,
/// `mailto:a@b`). The builder extracts and normalises the mailbox from each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailThread {
    /// IMAP account id (`[connectors.mail.accounts]`).
    pub account: String,
    /// Mailbox the thread lives in (`INBOX`).
    pub mailbox: String,
    /// UID of the thread root message.
    pub uid: u32,
    /// `Message-ID` of the thread root; the stable thread reference.
    pub message_id: String,
    /// Thread subject, as the server wrote it.
    pub subject: String,
    /// Interaction timestamp (RFC 3339 UTC); the callers normalise it.
    pub at: String,
    /// The owner's own addresses on this account, so a thread the owner sent is
    /// distinguished from one a stranger copied a party on.
    pub owner: Vec<String>,
    /// Sender addresses across the thread.
    pub from: Vec<String>,
    /// `To` addresses across the thread.
    pub to: Vec<String>,
    /// `Cc` addresses across the thread.
    pub cc: Vec<String>,
    /// Sender of the newest message: the row's direction (`out` when it is
    /// one of the owner's addresses, otherwise `in`).
    pub last_from: String,
}

/// One EventKit event, reduced to what a timeline row needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CalendarEvent {
    /// EventKit event identifier; the stable reference.
    pub id: String,
    /// Event title, as the app published it.
    pub title: String,
    /// Start instant (RFC 3339 UTC).
    pub start: String,
    /// Attendee addresses (`mailto:` or plain).
    pub attendees: Vec<String>,
}

/// How a mail thread moved, from the owner's timeline point of view, for one
/// party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The newest message is not the owner's and the party sent one.
    Received,
    /// The owner sent the thread's newest message.
    Sent,
    /// The newest message is not the owner's and the party only got copies.
    Copied,
}

impl Direction {
    /// The word stored in the summary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Sent => "sent",
            Self::Copied => "copied",
        }
    }
}

impl Crm<'_> {
    /// Attach one mail thread to every party it addresses. Returns the ids of
    /// the rows actually inserted: a re-run inserts none (unique key).
    pub fn attach_mail_thread(&self, thread: &MailThread) -> Result<Vec<i64>, CrmError> {
        if !valid_message_id(&thread.message_id) {
            return Err(CrmError::InvalidMessageId);
        }
        let from = email_set(&thread.from);
        let mut recipients = email_set(&thread.to);
        recipients.extend(email_set(&thread.cc));
        if from.is_empty() && recipients.is_empty() {
            return Ok(Vec::new());
        }
        let owner = email_set(&thread.owner);
        let last_out = email_set(std::slice::from_ref(&thread.last_from))
            .iter()
            .any(|email| owner.contains(email));
        // One row per thread: the key is the root `Message-ID` alone, so the
        // same thread seen from another folder or UID is the same row.
        let source_ref =
            serde_json::json!({ "imap": { "message_id": thread.message_id } }).to_string();
        let matched: Vec<_> = self
            .store_ref()
            .parties()?
            .into_iter()
            .filter(|party| {
                party
                    .emails
                    .iter()
                    .any(|email| from.contains(email) || recipients.contains(email))
            })
            .collect();
        if matched.is_empty() {
            return Ok(Vec::new());
        }
        let mut gate = summary_gate().ok_or(CrmError::SummaryRefused)?;
        let mut inserted = Vec::new();
        for party in matched {
            let direction = if last_out {
                Direction::Sent
            } else if party.emails.iter().any(|email| from.contains(email)) {
                Direction::Received
            } else {
                Direction::Copied
            };
            let raw = format!("{}: {}", direction.as_str(), thread.subject);
            let summary = gated_summary(&mut gate, &raw).ok_or(CrmError::SummaryRefused)?;
            let column = if last_out { "out" } else { "in" };
            if let Some(id) = self.store_ref().upsert_mail_interaction(
                party.id,
                &thread.at,
                &source_ref,
                &summary,
                column,
            )? {
                inserted.push(id);
            }
        }
        Ok(inserted)
    }

    /// Attach one EventKit event to every party among its attendees. Returns the
    /// ids of the rows actually inserted: a re-run inserts none.
    pub fn attach_calendar_event(&self, event: &CalendarEvent) -> Result<Vec<i64>, CrmError> {
        let attendees = email_set(&event.attendees);
        if attendees.is_empty() {
            return Ok(Vec::new());
        }
        let source_ref = serde_json::json!({ "eventkit": { "id": event.id } }).to_string();
        let mut gate = summary_gate().ok_or(CrmError::SummaryRefused)?;
        let summary = gated_summary(&mut gate, &event.title).ok_or(CrmError::SummaryRefused)?;
        let mut inserted = Vec::new();
        for party in self.store_ref().parties()? {
            if !party.emails.iter().any(|email| attendees.contains(email)) {
                continue;
            }
            if let Some(id) = self.store_ref().insert_interaction(
                party.id,
                "meeting",
                &event.start,
                &source_ref,
                &summary,
                "timeline.eventkit",
            )? {
                inserted.push(id);
            }
        }
        Ok(inserted)
    }

    /// Create an open follow-up on a live party. `note` is hostile skill text:
    /// it is minted through the kernel gate and capped before it is stored, and
    /// an empty note is refused.
    pub fn create_followup(
        &self,
        party_id: i64,
        due: &str,
        note: &str,
        created_by: &str,
    ) -> Result<Followup, CrmError> {
        match self.store_ref().party(party_id)? {
            Some(party) if !party.archived => {}
            _ => return Err(CrmError::PartyNotFound { id: party_id }),
        }
        let due = due.trim();
        if !looks_like_due(due) {
            return Err(CrmError::InvalidDue {
                value: due.to_string(),
            });
        }
        let created_by = created_by.trim();
        if created_by.is_empty() {
            return Err(CrmError::EmptyCreatedBy);
        }
        let mut gate = summary_gate().ok_or(CrmError::SummaryRefused)?;
        let reason = gated_summary(&mut gate, note).ok_or(CrmError::SummaryRefused)?;
        if reason.is_empty() {
            return Err(CrmError::EmptyFollowupNote);
        }
        let id = self
            .store_ref()
            .insert_followup(party_id, due, &reason, created_by, "open")?;
        Ok(Followup {
            id,
            party_id,
            due: due.to_string(),
            reason,
            created_by: created_by.to_string(),
            status: "open".to_string(),
        })
    }
}

/// The mailbox of one address value, lower-cased, or `None` when it is not one.
///
/// Handles `Name <a@b>`, `mailto:a@b`, quotes and surrounding space. The check
/// is deliberately strict: one `@`, a non-empty local part and a dotted domain.
/// Only the mailbox inside the last angle pair is read, so a display name that
/// looks like an address cannot spoof it.
pub fn normalise_email(value: &str) -> Option<String> {
    let value = value.trim();
    let inner = match (value.find('<'), value.rfind('>')) {
        (Some(start), Some(end)) if end > start => &value[start + 1..end],
        _ => value,
    };
    let inner = inner.trim().trim_matches('"').trim();
    let inner = inner.strip_prefix("mailto:").unwrap_or(inner);
    let candidate = inner.trim().to_ascii_lowercase();
    if candidate.is_empty() || candidate.contains(char::is_whitespace) {
        return None;
    }
    let mut parts = candidate.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    (!local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.'))
    .then_some(candidate)
}

/// Whether `value` can be stored as a thread reference: non-empty, at most
/// [`MESSAGE_ID_MAX_BYTES`] bytes, and free of control characters.
pub fn valid_message_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MESSAGE_ID_MAX_BYTES && !value.chars().any(char::is_control)
}

/// The normalised mailboxes of `values`.
fn email_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter_map(|value| normalise_email(value))
        .collect()
}

/// Ask the kernel for the CRM storage row and build a passthrough gate for it.
///
/// `None` when the kernel does not allow the row: the caller stores nothing.
fn summary_gate() -> Option<Gate> {
    let ctx = Context {
        destination: Destination::LocalDisplay,
    };
    let Decision::Allow(grant) = admit(PathId::G3, PrivacyMode::Open, &ctx) else {
        return None;
    };
    Gate::for_passthrough(&grant).ok()
}

/// Sanitise and cap one summary with the kernel's existing hostile-text path.
pub(crate) fn safe_summary(raw: &str) -> String {
    let stripped = kernel_core::text::sanitize_text(raw);
    kernel_broker::sanitize_external_text(stripped.trim(), SUMMARY_INPUT_BUDGET)
}

/// Mint one summary through `gate` and cap it. `None` when the gate refuses.
fn gated_summary(gate: &mut Gate, raw: &str) -> Option<String> {
    let (safe, _report) = gate.text(raw).ok()?;
    Some(kernel_broker::sanitize_external_text(
        safe.as_str().trim(),
        SUMMARY_INPUT_BUDGET,
    ))
}

/// Whether `value` is exactly a calendar date (`YYYY-MM-DD`) or an RFC 3339
/// timestamp. The store keeps `due` as text; this rejects anything else.
fn looks_like_due(value: &str) -> bool {
    // `%Y` also reads a short year (`25-10-10`), so the exact shape is pinned
    // by the length before the parser sees it.
    (value.len() == 10 && chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok())
        || chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_store::{NewParty, PartyKind, Store};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        (dir, store)
    }

    fn party(name: &str, email: &str) -> NewParty {
        NewParty {
            kind: PartyKind::Person,
            display_name: name.to_string(),
            name_variants: vec![name.to_string()],
            emails: vec![email.to_string()],
            phones: Vec::new(),
            addresses: Vec::new(),
            tags: Vec::new(),
            notes: String::new(),
            time_zone: None,
            origin: "owner".to_string(),
        }
    }

    fn thread(
        message_id: &str,
        at: &str,
        subject: &str,
        from: &str,
        to: &[&str],
        cc: &[&str],
        owner: &[&str],
    ) -> MailThread {
        MailThread {
            account: "personal".to_string(),
            mailbox: "INBOX".to_string(),
            uid: 1,
            message_id: message_id.to_string(),
            subject: subject.to_string(),
            at: at.to_string(),
            owner: owner.iter().map(|value| value.to_string()).collect(),
            from: vec![from.to_string()],
            to: to.iter().map(|value| value.to_string()).collect(),
            cc: cc.iter().map(|value| value.to_string()).collect(),
            last_from: from.to_string(),
        }
    }

    #[test]
    fn a_body_is_never_in_the_summary_and_the_subject_is_sanitised() {
        let mut gate = summary_gate().expect("G3 is covered and allowed");
        // A bidi override and a zero-width char are stripped; the hard cap is
        // the store's own 500-byte limit.
        let long = "s".repeat(600);
        let summary = gated_summary(&mut gate, &format!("sent: a\u{202e}b\u{200b}{long}"))
            .expect("the gate issues it");
        assert!(!summary.contains('\u{202e}'));
        assert!(!summary.contains('\u{200b}'));
        assert!(summary.len() <= SUMMARY_BYTES);
        assert!(
            summary.contains("[truncated:"),
            "the kernel marks the truncation"
        );
    }

    #[test]
    fn addresses_are_normalised_and_display_names_are_dropped() {
        assert_eq!(
            normalise_email(" Person Zero <Person0@Example.ORG> "),
            Some("person0@example.org".to_string())
        );
        assert_eq!(
            normalise_email("mailto:Person0@Example.ORG"),
            Some("person0@example.org".to_string())
        );
        assert_eq!(
            normalise_email("\"a@b.test\""),
            Some("a@b.test".to_string())
        );
        assert_eq!(normalise_email("not an address"), None);
        assert_eq!(normalise_email("a@b"), None);
        assert_eq!(normalise_email(""), None);
    }

    #[test]
    fn a_display_name_cannot_spoof_the_mailbox() {
        // Only the last angle pair is read: the mailbox is the real one.
        assert_eq!(
            normalise_email("\"camille@example.org\" <evil@example.org>"),
            Some("evil@example.org".to_string())
        );
        assert_eq!(
            normalise_email("camille@example.org <evil@example.org>"),
            Some("evil@example.org".to_string())
        );
    }

    #[test]
    fn a_plus_tagged_sender_does_not_match_the_plain_party() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let p0 = crm
            .create(party("Person Zero", "person0@example.org"))
            .unwrap();
        let tagged = thread(
            "<t0@fixture.test>",
            "2025-10-01T09:00:00Z",
            "Thread zero",
            "Person Zero <person0+tag@example.org>",
            &["owner@example.org"],
            &[],
            &["owner@example.org"],
        );
        assert!(
            crm.attach_mail_thread(&tagged).unwrap().is_empty(),
            "plus addressing is a different address, never merged"
        );
        assert!(store.interactions_for_party(p0.id).unwrap().is_empty());
    }

    #[test]
    fn mail_attaches_by_from_to_and_cc_and_is_idempotent() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let p0 = crm
            .create(party("Person Zero", "person0@example.org"))
            .unwrap();
        let p1 = crm
            .create(party("Person One", "person1@example.org"))
            .unwrap();

        // Received by p0.
        let incoming = thread(
            "<t0@fixture.test>",
            "2025-10-01T09:00:00Z",
            "Thread zero",
            "Person Zero <person0@example.org>",
            &["owner@example.org"],
            &[],
            &["owner@example.org"],
        );
        // Sent by the owner to p1, p0 on Cc.
        let outgoing = thread(
            "<t1@fixture.test>",
            "2025-10-02T09:00:00Z",
            "Thread one",
            "owner@example.org",
            &["person1@example.org"],
            &["person0@example.org"],
            &["owner@example.org"],
        );

        assert_eq!(crm.attach_mail_thread(&incoming).unwrap().len(), 1);
        let outgoing_ids = crm.attach_mail_thread(&outgoing).unwrap();
        assert_eq!(outgoing_ids.len(), 2, "p1 is To, p0 is Cc");

        let p0_rows = store.interactions_for_party(p0.id).unwrap();
        assert_eq!(p0_rows.len(), 2);
        assert_eq!(p0_rows[0].kind, "mail");
        // Oldest first: the thread p0 sent, then the owner-sent copy it was
        // on. The owner sent it, so both parties' rows say `sent`.
        assert!(p0_rows[0].summary.starts_with("received: "));
        assert!(p0_rows[0].summary.contains("Thread zero"));
        assert!(p0_rows[1].summary.starts_with("sent: "));
        assert!(p0_rows[1].summary.contains("Thread one"));
        assert!(p0_rows[1].source_ref.contains("\"imap\""));
        assert!(p0_rows[1].source_ref.contains("<t1@fixture.test>"));
        assert_eq!(p0_rows[1].provenance, "timeline.imap");

        let p1_rows = store.interactions_for_party(p1.id).unwrap();
        assert_eq!(p1_rows.len(), 1);
        assert!(p1_rows[0].summary.starts_with("sent: "));

        // Re-running inserts nothing.
        assert!(crm.attach_mail_thread(&incoming).unwrap().is_empty());
        assert!(crm.attach_mail_thread(&outgoing).unwrap().is_empty());
        assert_eq!(store.interactions_for_party(p0.id).unwrap().len(), 2);
    }

    #[test]
    fn a_stranger_that_copies_a_party_marks_it_copied() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let p0 = crm
            .create(party("Person Zero", "person0@example.org"))
            .unwrap();
        // Stranger -> owner, party on Cc. The owner did not send it, and the
        // party did not either, so the party was copied.
        let copied = thread(
            "<t2@fixture.test>",
            "2025-10-03T09:00:00Z",
            "Thread two",
            "unknown@unknown.test",
            &["owner@example.org"],
            &["person0@example.org"],
            &["owner@example.org"],
        );
        assert_eq!(crm.attach_mail_thread(&copied).unwrap().len(), 1);
        let rows = store.interactions_for_party(p0.id).unwrap();
        assert_eq!(rows[0].summary, "copied: Thread two");
    }

    #[test]
    fn a_message_id_must_be_bounded_and_control_free() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let _p0 = crm
            .create(party("Person Zero", "person0@example.org"))
            .unwrap();
        let mut bad = thread(
            "<t0@fixture.test>",
            "2025-10-01T09:00:00Z",
            "Thread zero",
            "person0@example.org",
            &["owner@example.org"],
            &[],
            &["owner@example.org"],
        );
        bad.message_id = format!("<{}@fixture.test>", "x".repeat(MESSAGE_ID_MAX_BYTES));
        assert!(matches!(
            crm.attach_mail_thread(&bad),
            Err(CrmError::InvalidMessageId)
        ));
        bad.message_id = "<t0\u{0007}@fixture.test>".to_string();
        assert!(matches!(
            crm.attach_mail_thread(&bad),
            Err(CrmError::InvalidMessageId)
        ));
        bad.message_id = String::new();
        assert!(matches!(
            crm.attach_mail_thread(&bad),
            Err(CrmError::InvalidMessageId)
        ));
        assert!(valid_message_id("<ok@fixture.test>"));
        assert!(!valid_message_id(&"a".repeat(MESSAGE_ID_MAX_BYTES + 1)));
    }

    #[test]
    fn calendar_attaches_by_attendee_and_is_idempotent() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let p0 = crm
            .create(party("Person Zero", "person0@example.org"))
            .unwrap();
        let p1 = crm
            .create(party("Person One", "person1@example.org"))
            .unwrap();
        let event = CalendarEvent {
            id: "evt-1".to_string(),
            title: "Kick-off".to_string(),
            start: "2025-10-03T10:00:00Z".to_string(),
            attendees: vec![
                "mailto:person0@example.org".to_string(),
                "Person One <person1@example.org>".to_string(),
                "owner@example.org".to_string(),
            ],
        };
        assert_eq!(crm.attach_calendar_event(&event).unwrap().len(), 2);
        let p0_rows = store.interactions_for_party(p0.id).unwrap();
        assert_eq!(p0_rows.len(), 1);
        assert_eq!(p0_rows[0].kind, "meeting");
        assert_eq!(p0_rows[0].summary, "Kick-off");
        assert!(p0_rows[0].source_ref.contains("\"eventkit\""));
        assert!(p0_rows[0].source_ref.contains("evt-1"));
        assert_eq!(store.interactions_for_party(p1.id).unwrap().len(), 1);

        assert!(crm.attach_calendar_event(&event).unwrap().is_empty());
        assert_eq!(store.interactions_for_party(p0.id).unwrap().len(), 1);
    }

    #[test]
    fn an_unknown_sender_attaches_to_nobody() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let _p0 = crm
            .create(party("Person Zero", "person0@example.org"))
            .unwrap();
        let stranger = thread(
            "<t9@fixture.test>",
            "2025-10-01T09:00:00Z",
            "Spam",
            "unknown@unknown.test",
            &["owner@example.org"],
            &[],
            &["owner@example.org"],
        );
        assert!(crm.attach_mail_thread(&stranger).unwrap().is_empty());
    }

    #[test]
    fn a_followup_needs_a_live_party_a_date_and_a_note() {
        let (_dir, store) = store();
        let crm = Crm::new(&store);
        let p0 = crm
            .create(party("Person Zero", "person0@example.org"))
            .unwrap();

        let followup = crm
            .create_followup(
                p0.id,
                "2025-10-10",
                "  Relancer \u{200b} le devis  ",
                "skill",
            )
            .unwrap();
        assert_eq!(followup.due, "2025-10-10");
        assert_eq!(followup.reason, "Relancer  le devis");
        assert_eq!(followup.created_by, "skill");
        assert_eq!(followup.status, "open");
        assert_eq!(store.followups_for_party(p0.id).unwrap().len(), 1);

        assert!(matches!(
            crm.create_followup(999, "2025-10-10", "note", "skill"),
            Err(CrmError::PartyNotFound { .. })
        ));
        assert!(matches!(
            crm.create_followup(p0.id, "not-a-date", "note", "skill"),
            Err(CrmError::InvalidDue { .. })
        ));
        assert!(matches!(
            crm.create_followup(p0.id, "2025-10-10", "   ", "skill"),
            Err(CrmError::EmptyFollowupNote)
        ));
        assert!(matches!(
            crm.create_followup(p0.id, "2025-10-10", "note", "  "),
            Err(CrmError::EmptyCreatedBy)
        ));
    }

    #[test]
    fn due_dates_must_be_an_exact_date_or_rfc3339() {
        assert!(looks_like_due("2025-10-10"));
        assert!(looks_like_due("2025-10-10T09:00:00Z"));
        assert!(looks_like_due("2025-10-10T09:00:00+02:00"));
        assert!(!looks_like_due("2025-10-10junk"));
        assert!(!looks_like_due("2025-10-10 09:00"));
        assert!(!looks_like_due("2025-13-10"));
        assert!(!looks_like_due("25-10-10"));
        assert!(!looks_like_due("2025/10/10"));
    }
}
