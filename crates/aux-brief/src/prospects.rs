//! "Possible new clients": a deterministic, offline read of inbound mail.
//!
//! No model, no network. A hit carries a reason code, never text from the mail;
//! nothing is created from it until the owner adds the sender.

use aux_store::{Store, StoreError};
use serde::{Deserialize, Serialize};

/// Hits kept per brief.
pub const MAX_PROSPECTS: usize = 5;
/// Bytes of the plain body the classifier reads.
pub const BODY_WINDOW: usize = 2_048;

/// Why a sender looks like a new client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Quote,
    Availability,
    Referral,
}

/// One suggestion, as the brief and the app show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prospect {
    /// The mail account the sender wrote to (the party's origin).
    pub account: String,
    pub name: String,
    pub email: String,
    pub reason: Reason,
    pub date: String,
}

/// One inbound mail, already read by the source.
pub struct Inbound<'a> {
    pub account: &'a str,
    /// The `From` header, `Name <address>`.
    pub from: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub date: &'a str,
    /// The raw message bytes, for the list and auto-reply headers.
    pub raw: &'a [u8],
}

const REFERRAL: &[&str] = &[
    "recommended you",
    "recommended your",
    "referred by",
    "referred me",
    "got your name from",
    "told me about you",
    "suggested i contact you",
];
const QUOTE: &[&str] = &[
    "quote",
    "quotation",
    "pricing",
    "proposal",
    "your price",
    "your prices",
    "your rate",
    "your rates",
    "how much do you charge",
    "what do you charge",
];
const AVAILABILITY: &[&str] = &[
    "availability",
    "are you available",
    "are you free",
    "book you",
    "book a call",
    "booking",
];
const AUTOMATED_LOCALS: &[&str] = &[
    "notifications",
    "notification",
    "mailer-daemon",
    "postmaster",
];

/// Classify one mail, or `None` when it is not a lead. `owner` holds the
/// owner's own addresses.
pub fn classify(mail: &Inbound<'_>, owner: &[String]) -> Option<Prospect> {
    let (name, email) = split_sender(mail.from)?;
    let local = email.split('@').next().unwrap_or_default();
    if owner.iter().any(|own| own.eq_ignore_ascii_case(&email))
        || local.starts_with("noreply")
        || local.starts_with("no-reply")
        || AUTOMATED_LOCALS.contains(&local)
        || automated_headers(mail.raw)
    {
        return None;
    }
    let body_end = (0..=BODY_WINDOW.min(mail.body.len()))
        .rev()
        .find(|&end| mail.body.is_char_boundary(end))
        .unwrap_or(0);
    let text = words(&format!("{} {}", mail.subject, &mail.body[..body_end]));
    let has = |phrases: &[&str]| phrases.iter().any(|p| text.contains(&format!(" {p} ")));
    let reason = if has(REFERRAL) {
        Reason::Referral
    } else if has(QUOTE) {
        Reason::Quote
    } else if has(AVAILABILITY) {
        Reason::Availability
    } else {
        return None;
    };
    Some(Prospect {
        account: mail.account.to_string(),
        name: super::clean(&name, 64),
        email,
        reason,
        date: super::clean(mail.date, 40),
    })
}

/// Lower-case words separated by single spaces, padded so a phrase matches whole words.
fn words(raw: &str) -> String {
    let flat: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect();
    format!(
        " {} ",
        flat.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

/// `(display name, lower-case address)` from `Name <address>` or a bare address.
fn split_sender(from: &str) -> Option<(String, String)> {
    let (name, address) = match (from.rfind('<'), from.rfind('>')) {
        (Some(open), Some(close)) if open < close => (
            from[..open].trim().trim_matches('"'),
            &from[open + 1..close],
        ),
        _ => ("", from),
    };
    let address = address.trim().to_ascii_lowercase();
    let (local, domain) = address.split_once('@')?;
    let valid = !local.is_empty() && domain.contains('.') && !address.contains(char::is_whitespace);
    valid.then(|| (name.to_string(), address.clone()))
}

/// List mail and auto-replies: `List-Unsubscribe`, `List-Id`, `Auto-Submitted`
/// other than `no`, and bulk `Precedence`.
fn automated_headers(raw: &[u8]) -> bool {
    let head = &raw[..raw.len().min(16 * 1024)];
    let head = String::from_utf8_lossy(head);
    let head = head.split("\r\n\r\n").next().unwrap_or_default();
    head.lines().any(|line| {
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        let value = value.trim().to_ascii_lowercase();
        match key.to_ascii_lowercase().as_str() {
            "list-unsubscribe" | "list-id" => true,
            "auto-submitted" => value != "no",
            "precedence" => ["bulk", "list", "junk"].contains(&value.as_str()),
            _ => false,
        }
    })
}

/// Keep only senders that are not a live party and not ignored; one per
/// address, at most [`MAX_PROSPECTS`].
pub fn unknown_senders(store: &Store, found: Vec<Prospect>) -> Result<Vec<Prospect>, StoreError> {
    let known: Vec<String> = store
        .parties()?
        .into_iter()
        .flat_map(|p| p.emails)
        .collect();
    let ignored = store.ignored_senders()?;
    let mut kept: Vec<Prospect> = Vec::new();
    for hit in found {
        let listed = |list: &[String]| list.iter().any(|e| e.eq_ignore_ascii_case(&hit.email));
        if !listed(&known)
            && !ignored.contains(&hit.email)
            && !kept.iter().any(|k| k.email == hit.email)
        {
            kept.push(hit);
        }
    }
    kept.truncate(MAX_PROSPECTS);
    Ok(kept)
}

/// The count-only line for the notification; never a name or an address.
pub fn count_line(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 possible new client".to_string()),
        n => Some(format!("{n} possible new clients")),
    }
}
