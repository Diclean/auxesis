//! The built-in mailbox: FICTIONAL DATA, safe to commit and safe to read.
//!
//! Twelve English messages from five invented clients. Every domain is
//! `*.example` or `*.test`; every person and company name is obviously
//! invented. The dates are relative to "today" so the morning-brief window
//! always has fresh mail. One message is a meeting request, one is an invoice.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::fixtures::RawMessage;

/// One mailbox message, as stored in `<dir>/mailbox.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredMail {
    /// IMAP UID.
    pub uid: u32,
    /// `Message-ID` header.
    #[serde(default)]
    pub message_id: String,
    /// `Subject` header.
    pub subject: String,
    /// `From` header.
    pub from: String,
    /// `To` header values.
    #[serde(default)]
    pub to: Vec<String>,
    /// `Cc` header values.
    #[serde(default)]
    pub cc: Vec<String>,
    /// `Date` header.
    #[serde(default)]
    pub date: String,
    /// The whole RFC822 message.
    pub body: String,
    /// IMAP flags (`\Seen` for a read message).
    #[serde(default)]
    pub flags: Vec<String>,
    /// `In-Reply-To` header, when present.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// IMAP `BODYSTRUCTURE` of a multipart message; absent means one text part.
    #[serde(default)]
    pub bodystructure: Option<String>,
    /// `(part, bytes)` pairs served by `BODY.PEEK[part]` (attachments).
    #[serde(default)]
    pub parts: Vec<(String, String)>,
    /// Free-form tags describing which demo situation this mail covers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// IMAP folder the simulator serves it from; absent means `INBOX`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
}

impl StoredMail {
    /// Convert to the fake's wire fixture, leaking the owned strings.
    ///
    /// The process loads the mailbox once, so one bounded leak per message is
    /// fine (the same pattern `fixtures.rs` uses for its oversized case).
    pub fn into_raw(self) -> RawMessage {
        RawMessage {
            uid: self.uid,
            message_id: self.message_id,
            subject: self.subject,
            from: self.from,
            to: self.to,
            cc: self.cc,
            date: self.date,
            body: Box::leak(self.body.into_boxed_str()),
            flags: self
                .flags
                .into_iter()
                .map(|flag| &*Box::leak(flag.into_boxed_str()))
                .collect(),
            bodystructure: self
                .bodystructure
                .map(|text| &*Box::leak(text.into_boxed_str())),
            parts: self
                .parts
                .into_iter()
                .map(|(part, bytes)| {
                    (
                        &*Box::leak(part.into_boxed_str()),
                        &*Box::leak(bytes.into_boxed_str()),
                    )
                })
                .collect(),
            in_reply_to: self.in_reply_to,
        }
    }
}

/// The built-in fictional mailbox: twelve messages, five invented clients.
pub fn default_mailbox() -> Vec<StoredMail> {
    const SEEN: &str = "\\Seen";
    let clients = [
        "Camille Example <camille@northwind.example>",
        "Jonas Sample <jonas@brightpath.test>",
        "Mira Fictive <mira@lumenworks.example>",
        "Owen Placeholder <owen@quaystone.test>",
        "Priya Testman <priya@verdant.example>",
    ];
    let subjects = [
        "Invoice NW-2041 for October",
        "Meeting request: Q4 planning, Thursday 10:00",
        "Draft copy for the launch page",
        "Signed contract, countersigned copy attached",
        "Quick question about the delivery window",
        "Your subscription renews next week",
        "Notes from the onboarding call",
        "Budget figures you asked for",
        "Re: Meeting request: Q4 planning, Thursday 10:00",
        "Reminder: expense report due Friday",
        "New office address",
        "Thanks for the quick turnaround",
    ];
    // Unread (no `\Seen`) at indices 1, 4, 5, 9, 10: five unread, seven read.
    let unread = [1usize, 4, 5, 9, 10];
    (0..12)
        .map(|index| {
            let uid = index as u32 + 1;
            let client = index % clients.len();
            let from = clients[client].to_string();
            let subject = subjects[index].to_string();
            let date = rfc2822_days_ago(index as i64, 9 + (index as u32 % 5));
            let meeting = index == 1;
            let invoice = index == 0;
            let mut body = format!(
                "From: {from}\r\n\
                 To: Owner <owner@mailsim.test>\r\n\
                 Subject: {subject}\r\n\
                 Date: {date}\r\n\
                 Message-ID: <sim-{uid}@mailsim.test>\r\n\
                 MIME-Version: 1.0\r\n\
                 Content-Type: text/plain; charset=UTF-8\r\n\
                 \r\n"
            );
            if meeting {
                body.push_str(
                    "Hello,\r\n\r\nCould we meet on Thursday at 10:00 to plan Q4?\r\n\
                     I will send a calendar note. Thanks!\r\n",
                );
            } else if invoice {
                body.push_str(
                    "Hello,\r\n\r\nPlease find invoice NW-2041 for October attached.\r\n\
                     Payment is due in 30 days. Thank you for your business.\r\n",
                );
            } else {
                body.push_str(&format!(
                    "Hello,\r\n\r\nThis is a fictional message about: {subject}.\r\n\
                     Nothing here is real and no action is needed.\r\n"
                ));
            }
            StoredMail {
                uid,
                message_id: format!("<sim-{uid}@mailsim.test>"),
                subject,
                from,
                to: vec!["Owner <owner@mailsim.test>".to_string()],
                cc: Vec::new(),
                date,
                body,
                flags: if unread.contains(&index) {
                    Vec::new()
                } else {
                    vec![SEEN.to_string()]
                },
                in_reply_to: (index == 8).then(|| "<sim-2@mailsim.test>".to_string()),
                ..StoredMail::default()
            }
        })
        .collect()
}

/// One fresh unread fictional mail for the UTC day `day` (days since 1970-01-01),
/// dated today: `--daily-mail` adds one a day so a long-running simulator always has
/// something new for the morning brief.
pub fn daily_mail(day: i64) -> StoredMail {
    let (year, month, date) = civil_from_days(day);
    let (from, date_header) = ("Priya Testman <priya@verdant.test>", rfc2822_days_ago(0, 6));
    let subject = format!("Fictional daily note {year}-{month:02}-{date:02}");
    let message_id = format!("<sim-daily-{day}@mailsim.test>");
    let body = format!(
        "From: {from}\r\nTo: Owner <owner@mailsim.test>\r\nSubject: {subject}\r\n\
         Date: {date_header}\r\nMessage-ID: {message_id}\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=UTF-8\r\n\r\nA fictional message. Nothing here is real.\r\n"
    );
    StoredMail {
        uid: day as u32,
        message_id,
        subject,
        from: from.to_string(),
        to: vec!["Owner <owner@mailsim.test>".to_string()],
        cc: Vec::new(),
        date: date_header,
        body,
        flags: Vec::new(),
        in_reply_to: None,
        ..StoredMail::default()
    }
}

/// The current UTC day number (days since 1970-01-01).
pub fn today() -> i64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH);
    now.map(|elapsed| (elapsed.as_secs() / 86_400) as i64)
        .unwrap_or(0)
}

/// A UTC RFC 2822 date `days` before now, at `hour`.
fn rfc2822_days_ago(days: i64, hour: u32) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let date_days = (now - days * 86_400).div_euclid(86_400);
    let (year, month, day) = civil_from_days(date_days);
    let weekday =
        ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][((date_days + 4).rem_euclid(7)) as usize];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{weekday}, {day} {} {year} {hour:02}:00:00 +0000",
        months[(month - 1) as usize]
    )
}

/// Days since 1970-01-01 to a proleptic-Gregorian `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, valid for every day this simulator can
/// see; avoids a calendar dependency.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_mail_is_unread_fictional_and_unique_per_day() {
        let (first, next) = (daily_mail(today()), daily_mail(today() + 1));
        assert!(first.flags.is_empty() && first.from.ends_with("@verdant.test>"));
        assert_ne!((first.uid, &first.message_id), (next.uid, &next.message_id));
    }
}
