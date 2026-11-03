//! Pure, offline helpers for the IMAP read path.
//!
//! Turning an `async-imap` [`Fetch`] into the typed [`EnvelopeItem`], grouping
//! envelopes into a thread, and building the server-side search window (the
//! quoted text plus the RFC 3501 date). Nothing here opens a socket, so all of
//! it is unit-testable; [`crate::imap_read::MailService`] owns the connection.

use std::collections::HashSet;

use async_imap::types::{Fetch, Flag};

use crate::imap_read::EnvelopeItem;

/// Turn one `FETCH` response into the typed header `list`/`search`/`thread`
/// return.
pub(crate) fn envelope_item(fetch: &Fetch) -> EnvelopeItem {
    let envelope = fetch.envelope();
    EnvelopeItem {
        uid: fetch.uid.unwrap_or(0),
        message_id: envelope
            .and_then(|envelope| envelope.message_id.as_deref())
            .map(text)
            .unwrap_or_default(),
        subject: envelope
            .and_then(|envelope| envelope.subject.as_deref())
            .map(text)
            .unwrap_or_default(),
        from: envelope
            .and_then(|envelope| envelope.from.as_deref())
            .and_then(|addresses| addresses.first())
            .map(format_address)
            .unwrap_or_default(),
        to: envelope
            .and_then(|envelope| envelope.to.as_deref())
            .map(format_addresses)
            .unwrap_or_default(),
        cc: envelope
            .and_then(|envelope| envelope.cc.as_deref())
            .map(format_addresses)
            .unwrap_or_default(),
        date: envelope
            .and_then(|envelope| envelope.date.as_deref())
            .map(text)
            .unwrap_or_default(),
        size: fetch.size.unwrap_or(0),
        unread: !fetch.flags().any(|flag| matches!(flag, Flag::Seen)),
        in_reply_to: envelope
            .and_then(|envelope| envelope.in_reply_to.as_deref())
            .map(text)
            .filter(|value| !value.is_empty()),
    }
}

fn format_addresses(addresses: &[imap_proto::Address<'_>]) -> Vec<String> {
    addresses.iter().map(format_address).collect()
}

fn format_address(address: &imap_proto::Address<'_>) -> String {
    let name = address.name.as_deref().map(text).unwrap_or_default();
    let mailbox = address.mailbox.as_deref().map(text).unwrap_or_default();
    let host = address.host.as_deref().map(text).unwrap_or_default();
    let email = if host.is_empty() {
        mailbox
    } else {
        format!("{mailbox}@{host}")
    };
    if name.is_empty() {
        email
    } else {
        format!("{name} <{email}>")
    }
}

/// Envelope text is untrusted header data: a control character (SOH, BEL, a
/// bare CR from a literal, ...) becomes a space so no listed header carries one.
/// This also applies to `Message-ID`/`In-Reply-To`, which are lookup keys: a
/// valid id (RFC 5322 `msg-id`) never holds a control, so a real id is returned
/// unchanged and threading still matches; only malformed ids are altered.
fn text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if !text.chars().any(char::is_control) {
        return text.into_owned();
    }
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Group `items` into the thread rooted at `root_id`: the `References`/
/// `In-Reply-To` chain. Subject equality is not proof of a relationship and
/// can join unrelated senders (or a stranger) into a CRM thread.
pub(crate) fn group_thread(items: &[EnvelopeItem], root_id: &str, max: usize) -> Vec<EnvelopeItem> {
    let Some(root) = items.iter().find(|item| item.message_id == root_id) else {
        return Vec::new();
    };
    let mut members: HashSet<String> = HashSet::new();
    members.insert(root.message_id.clone());
    loop {
        let mut added = false;
        for item in items {
            if members.contains(&item.message_id) {
                continue;
            }
            let by_reference = item
                .in_reply_to
                .as_deref()
                .is_some_and(|parent| members.contains(parent));
            if by_reference {
                members.insert(item.message_id.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    let mut thread: Vec<EnvelopeItem> = items
        .iter()
        .filter(|item| members.contains(&item.message_id))
        .cloned()
        .collect();
    thread.sort_by_key(|item| item.uid);
    thread.truncate(max);
    thread
}

/// Quote a search value so model text cannot inject another IMAP criterion.
pub(crate) fn imap_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            '\r' | '\n' => out.push(' '),
            _ => out.push(character),
        }
    }
    out.push('"');
    out
}

/// The month abbreviations IMAP dates use (RFC 3501 `date-month`).
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The IMAP `d-Mon-yyyy` date `days` before now (UTC).
pub fn days_ago_date(days: u32) -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    imap_date((seconds / 86_400) as i64 - i64::from(days))
}

/// The IMAP `d-Mon-yyyy` date `days` before the calendar day `day`
/// (`YYYY-MM-DD`, the caller's own day). `None` when `day` is not a date.
pub fn days_before_date(day: &str, days: u32) -> Option<String> {
    let mut parts = day.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day_of_month: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) {
        return None;
    }
    let day_number = days_from_civil(year, month, day_of_month)?;
    Some(imap_date(day_number - i64::from(days)))
}

/// `days` since 1970-01-01 as the IMAP `d-Mon-yyyy` date.
fn imap_date(days: i64) -> String {
    let (year, month, day_of_month) = civil_from_days(days);
    format!("{day_of_month}-{}-{year}", MONTHS[(month - 1) as usize])
}

/// Howard Hinnant's `days_from_civil`, checked: `(y, m, d)` → days since
/// 1970-01-01, or `None` when `d` is not a day of that month.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let (year, month, day) = (year, i64::from(month), i64::from(day));
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let longest = month_days[(month - 1) as usize] + i64::from(month == 2 && leap);
    if !(1..=longest).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let yoe = year - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → `(y, m, d)`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_text_replaces_control_characters_and_keeps_the_rest() {
        assert_eq!(text(b"Quote \x01for\x07 Camille"), "Quote  for  Camille");
        assert_eq!(text(b"split\rsubject\n"), "split subject");
        assert_eq!(
            text("Réunion \u{2014} café".as_bytes()),
            "Réunion \u{2014} café"
        );
    }

    #[test]
    fn civil_dates_match_known_epoch_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn unrelated_same_subject_message_is_not_joined_to_thread() {
        let item = |uid, message_id: &str, from: &str, in_reply_to: Option<&str>| EnvelopeItem {
            uid,
            message_id: message_id.into(),
            subject: "Invoice".into(),
            from: from.into(),
            to: vec![],
            cc: vec![],
            date: "Mon, 01 Jan 2024 00:00:00 +0000".into(),
            size: 1,
            unread: false,
            in_reply_to: in_reply_to.map(str::to_string),
        };
        let items = vec![
            item(1, "<root@example.org>", "owner@example.org", None),
            item(
                2,
                "<reply@example.org>",
                "party@example.org",
                Some("<root@example.org>"),
            ),
            item(3, "<stranger@example.net>", "stranger@example.net", None),
        ];
        let grouped = group_thread(&items, "<root@example.org>", 100);
        assert_eq!(grouped.len(), 2);
        assert!(!grouped
            .iter()
            .any(|message| message.message_id == "<stranger@example.net>"));
    }

    #[test]
    fn search_values_are_quoted_against_injection() {
        assert_eq!(imap_quote("plain"), "\"plain\"");
        assert_eq!(imap_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(imap_quote("a\r\nb"), "\"a  b\"");
    }

    #[test]
    fn imap_dates_use_the_rfc3501_shape() {
        let date = days_ago_date(90);
        let mut parts = date.split('-');
        let day: u32 = parts.next().expect("day").parse().expect("numeric day");
        let month = parts.next().expect("month");
        let year: i64 = parts.next().expect("year").parse().expect("numeric year");
        assert!((1..=31).contains(&day));
        assert!(MONTHS.contains(&month));
        assert!(year >= 1970);
        assert!(parts.next().is_none());
    }

    #[test]
    fn the_window_counts_back_from_the_callers_day() {
        assert_eq!(
            days_before_date("2026-10-15", 1).as_deref(),
            Some("14-Oct-2026")
        );
        assert_eq!(
            days_before_date("2026-10-15", 0).as_deref(),
            Some("15-Oct-2026")
        );
        assert_eq!(
            days_before_date("2026-03-01", 1).as_deref(),
            Some("28-Feb-2026")
        );
        assert_eq!(
            days_before_date("2024-03-01", 1).as_deref(),
            Some("29-Feb-2024")
        );
        assert_eq!(
            days_before_date("2026-01-01", 1).as_deref(),
            Some("31-Dec-2025")
        );
    }

    #[test]
    fn a_day_that_is_not_a_date_is_refused() {
        assert_eq!(days_before_date("2026-02-29", 1), None);
        assert_eq!(days_before_date("2026-13-01", 1), None);
        assert_eq!(days_before_date("2026-10-15T21:30", 1), None);
        assert_eq!(days_before_date("yesterday", 1), None);
    }
}
