//! MAIL-UNKNOWN-CONTACT-1: someone the owner names who is not in Clients may
//! still have written to the owner. The address then comes from the `From` of
//! a received INBOX mail, never from a body, and the card says so. The card is
//! still asked and the recipient check still runs, for that one address only.
//!
//! MAILBOX-LOOKALIKE-HARDEN: that `From` is attacker text: only an address
//! the owner wrote to (else one that wrote on two days) may be picked.

use serde_json::{json, Value};

use super::{normalize_contact_name, RecipientDirectory};

/// Most headers one unknown-contact lookup reads per folder and account; a
/// full page is never treated as the whole folder.
pub const SENDER_SCAN_LIMIT: usize = 500;

/// The `From` of one mail the owner received. Header data: untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxSender {
    /// The display name, possibly empty.
    pub name: String,
    /// The address.
    pub address: String,
    /// The day it arrived, as "26 Sep".
    pub day: String,
}

/// The senders read from the owner's mailboxes, whether every configured
/// mailbox reached the end of its INBOX, and the addresses the owner has
/// already written to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxScan {
    pub senders: Vec<MailboxSender>,
    /// False when a cap was hit or a mailbox could not be read.
    pub complete: bool,
    /// To/Cc addresses of the owner's Sent mail. `None` when no configured
    /// mailbox had a readable Sent folder: the bar then falls back to two
    /// arrival days.
    pub written_to: Option<Vec<String>>,
}

/// Marks a refusal that quotes `From` names: the engine taints it.
pub const QUOTES_MAILBOX: &str = "wrote to the owner:";

/// The sender's whole display name or local part, as normalized words.
fn name_words(text: &str) -> Vec<String> {
    normalize_contact_name(text)
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_string)
        .collect()
}

/// Role inboxes: a whole local part equal to one of these never identifies a
/// person by itself. A whole display name still does.
const GENERIC_LOCAL_PARTS: &[&str] = &[
    "support", "info", "contact", "hello", "team", "admin", "noreply", "no-reply", "sales",
    "billing",
];

fn generic_local_part(local: &str) -> bool {
    GENERIC_LOCAL_PARTS.contains(&normalize_contact_name(local).as_str())
}

/// The distinct senders whose whole address, whole display name or whole
/// non-generic local part equals `said`, case-insensitive. A token inside a
/// longer name or local part never counts: a common word must match the whole
/// thing.
pub fn senders_named(senders: &[MailboxSender], said: &str) -> Vec<MailboxSender> {
    let said = normalize_contact_name(said);
    let needle = name_words(&said);
    if needle.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<MailboxSender> = Vec::new();
    for sender in senders {
        let address = &sender.address;
        let plausible = address.matches('@').count() == 1
            && !address.starts_with('@')
            && !address.contains(|ch: char| "<>,;\" ".contains(ch) || ch.is_control());
        if !plausible {
            continue;
        }
        let local = address.split_once('@').map_or("", |(local, _)| local);
        let matches = address.eq_ignore_ascii_case(&said)
            || name_words(&sender.name) == needle
            || (!generic_local_part(local) && name_words(local) == needle);
        if matches
            && found
                .iter()
                .all(|f| !f.address.eq_ignore_ascii_case(address))
        {
            found.push(sender.clone());
        }
    }
    found
}

/// A header display name as plain words (letters, `-`, `'`), four at most.
/// Dots and every other address-looking mark are separators, never kept, so
/// the shown name cannot imitate a second address.
fn plain_name(name: &str) -> String {
    let kept = name.replace(|ch: char| !ch.is_alphabetic() && !"-'".contains(ch), " ");
    kept.split_whitespace()
        .take(4)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Most characters of a display name the card shows. Long enough for a full
/// name, short enough that the address always stays on the row.
const CARD_NAME_MAX_CHARS: usize = 40;

/// Cap a card display name on a character boundary and mark the cut with an
/// ellipsis. The address is never capped.
fn card_name(name: &str) -> String {
    if name.chars().count() <= CARD_NAME_MAX_CHARS {
        return name.to_string();
    }
    let mut capped: String = name.chars().take(CARD_NAME_MAX_CHARS - 1).collect();
    capped.push('…');
    capped
}

/// The card's `To` label: the warning comes first, then the name and the full
/// address, never a name alone.
pub(super) fn card_source(sender: &MailboxSender) -> Value {
    let name = card_name(&plain_name(&sender.name));
    let who = if name.is_empty() {
        sender.address.clone()
    } else {
        format!("{name} <{}>", sender.address)
    };
    let label = format!("Not in Clients — from their mail of {}: {who}", sender.day);
    json!({ "address": sender.address, "label": label })
}

/// True when `address` is a To/Cc of one of the owner's Sent mails.
fn written_to(written_to: &[String], address: &str) -> bool {
    written_to
        .iter()
        .any(|known| known.eq_ignore_ascii_case(address))
}

/// How many different arrival days `address` has in the scan. An empty day
/// proves nothing and is never counted.
fn arrival_days(senders: &[MailboxSender], address: &str) -> usize {
    let mut days: Vec<&str> = Vec::new();
    for sender in senders {
        if !sender.address.eq_ignore_ascii_case(address) {
            continue;
        }
        let day = sender.day.trim();
        if day.is_empty() {
            continue;
        }
        if !days.iter().any(|known| known.eq_ignore_ascii_case(day)) {
            days.push(day);
        }
    }
    days.len()
}

/// The trust bar for the one sender a mailbox lookup resolved. `None` lets the
/// send go to the card; `Some(reason)` refuses it before any card.
///
/// When a Sent folder is readable, only an address the owner has already
/// written to may be picked. When none is reachable, a sender who wrote on two
/// different days is trusted instead.
pub(super) fn trust_refusal(
    value: &str,
    sender: &MailboxSender,
    scan: &MailboxScan,
) -> Option<String> {
    if let Some(known) = &scan.written_to {
        if written_to(known, &sender.address) {
            return None;
        }
        return Some(format!(
            "not sending to {value}: not in Clients and not an address the owner has written to \
             before. Add {value} in Clients, or type the address, then ask again"
        ));
    }
    if arrival_days(&scan.senders, &sender.address) >= 2 {
        return None;
    }
    Some(format!(
        "not sending to {value}: not in Clients and that address has written to the owner on \
         fewer than two different days. Add {value} in Clients, or type the address, then ask \
         again"
    ))
}

/// The one short question for none, several, or a partial scan; names and days
/// only, never an address.
pub(super) fn question(value: &str, senders: &[MailboxSender], complete: bool) -> String {
    if senders.is_empty() {
        let cut = if complete {
            ""
        } else {
            "the mailbox scan stopped before the end and "
        };
        return format!(
            "no address for {value}: not in Clients and {cut}no mail the owner received is from \
             {value}. Ask the owner one short question: {value}'s full name or address as on a \
             mail they sent, or to add {value} in Clients first"
        );
    }
    let listed: Vec<String> = senders
        .iter()
        .take(5)
        .map(|sender| match plain_name(&sender.name) {
            name if name.is_empty() => format!("{value} (mail of {})", sender.day),
            name => format!("{name} (mail of {})", sender.day),
        })
        .collect();
    if !complete {
        return format!(
            "the mailbox scan stopped before the end, so a match is not unique: {value} \
             {QUOTES_MAILBOX} {}. Ask the owner one short question: which address?",
            listed.join(", ")
        );
    }
    format!(
        "several people named {value} {QUOTES_MAILBOX} {}. Ask the owner one short question: \
         which one? Their full name or address picks one",
        listed.join(", ")
    )
}

/// The owner's contacts plus the one mailbox sender this run resolved.
pub(super) struct WithMailboxSender<'a> {
    pub(super) inner: &'a dyn RecipientDirectory,
    /// The name as the owner said it.
    pub(super) said: String,
    pub(super) sender: MailboxSender,
}

impl RecipientDirectory for WithMailboxSender<'_> {
    fn is_known(&self, value: &str) -> bool {
        self.inner.is_known(value) || value.trim().eq_ignore_ascii_case(&self.sender.address)
    }

    fn addresses_for_name(&self, name: &str) -> Vec<String> {
        let found = self.inner.addresses_for_name(name);
        if found.is_empty() && normalize_contact_name(name) == normalize_contact_name(&self.said) {
            return vec![self.sender.address.clone()];
        }
        found
    }

    fn name_groups(&self) -> Vec<Vec<String>> {
        let mut groups = self.inner.name_groups();
        groups.push(vec![self.said.clone()]);
        groups
    }

    fn time_zone_for(&self, address: &str) -> Option<String> {
        self.inner.time_zone_for(address)
    }

    fn mailbox_sender(&self) -> Option<&MailboxSender> {
        Some(&self.sender)
    }
}
