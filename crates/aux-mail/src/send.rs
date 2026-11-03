//! Composing and sending one message (RFC 5322 + MIME), `docs/mail.md` §5.
//!
//! The sender builds a 7-bit-safe message: the body is base64, the invite (when
//! present) is a `multipart/alternative` `text/calendar` part beside the plain
//! text, and every header value is checked for CR/LF before it can become a
//! header. The `.ics` text was built by the runtime from rehydrated values; the
//! model never supplies it, and this module never re-tokenises it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::b64;
use crate::error::MailError;

/// Most recipients one message may address (matching the Gmail path).
pub const MAX_RECIPIENTS: usize = 50;

/// Longest subject, in Unicode scalar values.
pub const MAX_SUBJECT_CHARS: usize = 998;

/// Longest plain-text body, in bytes.
pub const MAX_BODY_BYTES: usize = 100 * 1024;

/// Longest single `local@domain` mailbox.
const MAX_ADDRESS_BYTES: usize = 254;

/// RFC 5322's line limit, excluding the CRLF.
const MAX_LINE_BYTES: usize = 998;

/// The preferred folded header length.
const PREFERRED_HEADER_BYTES: usize = 78;

/// Base64 line width for a body part.
const BASE64_LINE_BYTES: usize = 76;

/// One message ready to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMail {
    /// `From` address (the account's own address).
    pub from: String,
    /// Primary recipients.
    pub to: Vec<String>,
    /// Carbon-copy recipients.
    pub cc: Vec<String>,
    /// `Subject`; RFC 2047 encoded when non-ASCII.
    pub subject: String,
    /// Plain-text body.
    pub body: String,
    /// The RFC 5545 `METHOD:REQUEST` text, when this is an invite.
    pub ics: Option<String>,
}

/// What a successful submission confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOutcome {
    /// Recipients the server accepted on `RCPT TO`.
    pub accepted: usize,
    /// Bytes of the composed message `DATA` carried.
    pub bytes: usize,
    /// The `DATA` reply's class: `2xx`, `4xx`, `5xx` or `none`.
    pub reply_class: &'static str,
}

impl SendOutcome {
    /// Build the safe outcome the tool and the `mail.call` row report.
    pub(crate) fn new(accepted: usize, code: u16, bytes: usize) -> Self {
        Self {
            accepted,
            bytes,
            reply_class: reply_class(code),
        }
    }
}

/// The class of an SMTP reply code, as the Ledger records it.
pub(crate) fn reply_class(code: u16) -> &'static str {
    match code {
        200..=299 => "2xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "none",
    }
}

/// Refuse a malformed message **before** any socket opens.
pub fn validate(mail: &OutgoingMail) -> Result<(), MailError> {
    validate_address(&mail.from, "from")?;
    for address in mail.to.iter().chain(mail.cc.iter()) {
        validate_address(address, "to")?;
    }
    if mail.to.is_empty() && mail.cc.is_empty() {
        return Err(MailError::InvalidField("to"));
    }
    if mail.to.len() + mail.cc.len() > MAX_RECIPIENTS {
        return Err(MailError::InvalidField("to"));
    }
    if mail.subject.chars().count() > MAX_SUBJECT_CHARS {
        return Err(MailError::InvalidField("subject"));
    }
    // Any control in a header value would let a value start a new header.
    if mail
        .subject
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}'))
    {
        return Err(MailError::InvalidField("subject"));
    }
    if mail.body.len() > MAX_BODY_BYTES {
        return Err(MailError::InvalidField("body"));
    }
    if mail.body.contains('\0') {
        return Err(MailError::InvalidField("body"));
    }
    if let Some(ics) = &mail.ics {
        if !ics.contains("BEGIN:VCALENDAR") || !ics.contains("METHOD:REQUEST") {
            return Err(MailError::InvalidField("ics"));
        }
        if ics.contains('\0') {
            return Err(MailError::InvalidField("ics"));
        }
    }
    Ok(())
}

/// A single bare `local@domain` mailbox, with no header-injection surface.
pub fn validate_address(address: &str, field: &'static str) -> Result<(), MailError> {
    if address.len() > MAX_ADDRESS_BYTES {
        return Err(MailError::InvalidField(field));
    }
    if address.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(MailError::InvalidField(field));
    }
    if address.chars().any(|c| {
        matches!(
            c,
            '<' | '>' | ';' | ':' | '"' | '(' | ')' | '[' | ']' | '\\' | ','
        )
    }) {
        return Err(MailError::InvalidField(field));
    }
    let mut pieces = address.split('@');
    let local = pieces.next().unwrap_or_default();
    let domain = pieces.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || pieces.next().is_some() {
        return Err(MailError::InvalidField(field));
    }
    if domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(MailError::InvalidField(field));
    }
    Ok(())
}

/// Build the RFC 5322 bytes `DATA` will carry, CRLF endings and all.
pub fn compose(mail: &OutgoingMail) -> Result<Vec<u8>, MailError> {
    validate(mail)?;
    let body = normalise_crlf(&mail.body);
    let to_header = fold_header("To", &mail.to.join(", "));
    let mut head = String::new();
    head.push_str(&fold_header("From", &mail.from));
    head.push_str("\r\n");
    head.push_str(&to_header);
    head.push('\n');
    if !mail.cc.is_empty() {
        head.push_str(&fold_header("Cc", &mail.cc.join(", ")));
        head.push('\n');
    }
    let subject = if mail.subject.is_ascii() {
        fold_header("Subject", &mail.subject)
    } else {
        format!("Subject: {}", encode_header_value(&mail.subject))
    };
    head.push_str(&subject);
    head.push_str("\r\nMIME-Version: 1.0\r\n");
    // Every push above used `\n` as a separator; normalise the lot to CRLF.
    head = normalise_crlf(&head);

    let mut message = head.into_bytes();
    match &mail.ics {
        Some(ics) => {
            let boundary = unique_boundary(&[body.as_bytes(), ics.as_bytes()]);
            message.extend_from_slice(
                format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n")
                    .as_bytes(),
            );
            message.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            message.extend_from_slice(
                b"Content-Type: text/plain; charset=\"UTF-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
            );
            message.extend_from_slice(
                b64::encode_lines(body.as_bytes(), BASE64_LINE_BYTES).as_bytes(),
            );
            message.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            message.extend_from_slice(
                b"Content-Type: text/calendar; method=REQUEST; charset=\"UTF-8\"\r\n\
                  Content-Transfer-Encoding: base64\r\n\
                  Content-Disposition: inline; filename=\"invite.ics\"\r\n\r\n",
            );
            message
                .extend_from_slice(b64::encode_lines(ics.as_bytes(), BASE64_LINE_BYTES).as_bytes());
            message.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        }
        None => {
            message.extend_from_slice(
                b"Content-Type: text/plain; charset=\"UTF-8\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
            );
            message.extend_from_slice(
                b64::encode_lines(body.as_bytes(), BASE64_LINE_BYTES).as_bytes(),
            );
        }
    }
    Ok(message)
}

/// Normalise every line ending to CRLF.
fn normalise_crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                if bytes.get(index + 1) == Some(&b'\n') {
                    index += 2;
                } else {
                    index += 1;
                }
                out.push_str("\r\n");
            }
            b'\n' => {
                index += 1;
                out.push_str("\r\n");
            }
            _ => {
                let start = index;
                while index < bytes.len() && bytes[index] != b'\r' && bytes[index] != b'\n' {
                    index += 1;
                }
                out.push_str(&text[start..index]);
            }
        }
    }
    out
}

/// Fold one `name: value` header into RFC 5322 lines.
fn fold_header(name: &str, value: &str) -> String {
    let mut output = String::with_capacity(value.len() + name.len() + 16);
    output.push_str(name);
    output.push_str(": ");
    let mut line_len = name.len() + 2;
    let mut first = true;
    for token in value.split(' ') {
        if !first {
            if line_len + 1 + token.len() <= PREFERRED_HEADER_BYTES {
                output.push(' ');
                line_len += 1;
            } else {
                output.push_str("\r\n ");
                line_len = 1;
            }
        }
        first = false;
        let mut remaining = token;
        while !remaining.is_empty() {
            let room = MAX_LINE_BYTES.saturating_sub(line_len);
            if room == 0 {
                output.push_str("\r\n ");
                line_len = 1;
                continue;
            }
            if remaining.len() <= room {
                output.push_str(remaining);
                line_len += remaining.len();
                break;
            }
            let mut take = room;
            while take > 0 && !remaining.is_char_boundary(take) {
                take -= 1;
            }
            if take == 0 {
                take = remaining.chars().next().map_or(1, char::len_utf8);
            }
            let (head, tail) = remaining.split_at(take);
            output.push_str(head);
            output.push_str("\r\n ");
            line_len = 1;
            remaining = tail;
        }
    }
    output
}

/// RFC 2047 `=?UTF-8?B?…?=` encoding for a non-ASCII header value.
fn encode_header_value(value: &str) -> String {
    // 45 input bytes encode to 60 base64 characters; `=?UTF-8?B?` and `?=`
    // add 12, for 72 <= 75.
    const MAX_WORD_BYTES: usize = 45;
    let mut words = Vec::new();
    let mut start = 0;
    while start < value.len() {
        let mut end = (start + MAX_WORD_BYTES).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = start + value[start..].chars().next().map_or(1, char::len_utf8);
        }
        words.push(format!(
            "=?UTF-8?B?{}?=",
            b64::encode(&value.as_bytes()[start..end])
        ));
        start = end;
    }
    words.join(" ")
}

/// A boundary that appears in none of `parts`.
fn unique_boundary(parts: &[&[u8]]) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    loop {
        let candidate = format!(
            "=_aux_{nanos:x}_{:x}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let needle = candidate.as_bytes();
        if !parts
            .iter()
            .any(|part| part.windows(needle.len()).any(|window| window == needle))
        {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail() -> OutgoingMail {
        OutgoingMail {
            from: "owner@exemple.test".to_string(),
            to: vec!["camille@exemple.fr".to_string()],
            cc: Vec::new(),
            subject: "Invitation".to_string(),
            body: "Bonjour, invitation confirmée.".to_string(),
            ics: None,
        }
    }

    #[test]
    fn a_plain_message_is_a_7bit_base64_text_part() {
        let message = compose(&mail()).unwrap();
        let text = String::from_utf8(message).unwrap();
        assert!(text.starts_with("From: owner@exemple.test\r\n"));
        assert!(text.contains("To: camille@exemple.fr\r\n"));
        assert!(text.contains("Subject: Invitation\r\n"));
        assert!(text.contains("Content-Type: text/plain; charset=\"UTF-8\"\r\n"));
        assert!(text.contains("Content-Transfer-Encoding: base64\r\n"));
        // The base64 body decodes back to the CRLF body.
        let body = text.split("\r\n\r\n").nth(1).unwrap();
        let decoded = decode_base64(body);
        assert_eq!(decoded, "Bonjour, invitation confirmée.");
    }

    #[test]
    fn an_invite_is_a_multipart_alternative_with_the_calendar_part() {
        let mut invite = mail();
        invite.ics = Some(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n".to_string(),
        );
        let message = compose(&invite).unwrap();
        let text = String::from_utf8(message).unwrap();
        assert!(text.contains("Content-Type: multipart/alternative; boundary=\""));
        assert!(text.contains("Content-Type: text/calendar; method=REQUEST; charset=\"UTF-8\""));
        assert!(text.contains("filename=\"invite.ics\""));
        // No token delimiter anywhere in the composed message.
        assert!(!text.contains('\u{27e6}'));
        assert!(!text.contains('\u{27e7}'));
        // The calendar part decodes back to the ICS.
        let (_, after) = text.split_once("filename=\"invite.ics\"\r\n\r\n").unwrap();
        let body = after.split("\r\n--").next().unwrap();
        assert_eq!(
            decode_base64(body),
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n"
        );
    }

    #[test]
    fn header_injection_is_refused_before_composition() {
        let mut bad = mail();
        bad.subject = "hi\r\nBcc: leak@exemple.fr".to_string();
        assert_eq!(compose(&bad), Err(MailError::InvalidField("subject")));

        let mut bad = mail();
        bad.to = vec!["camille@exemple.fr\r\nBcc: leak@exemple.fr".to_string()];
        assert_eq!(compose(&bad), Err(MailError::InvalidField("to")));

        let mut bad = mail();
        bad.body = "hi\0there".to_string();
        assert_eq!(compose(&bad), Err(MailError::InvalidField("body")));

        let mut bad = mail();
        bad.ics = Some("not a calendar".to_string());
        assert_eq!(compose(&bad), Err(MailError::InvalidField("ics")));
    }

    #[test]
    fn a_non_ascii_subject_is_rfc_2047_encoded() {
        let mut mail = mail();
        mail.subject = "Déjeuner".to_string();
        let text = String::from_utf8(compose(&mail).unwrap()).unwrap();
        assert!(text.contains("Subject: =?UTF-8?B?"), "{text}");
        assert!(!text.contains("Déjeuner"));
    }

    #[test]
    fn too_many_recipients_is_refused() {
        let mut mail = mail();
        mail.to = (0..MAX_RECIPIENTS + 1)
            .map(|index| format!("person{index}@exemple.fr"))
            .collect();
        assert_eq!(compose(&mail), Err(MailError::InvalidField("to")));
    }

    /// A tiny standard-alphabet base64 decoder for the tests only.
    fn decode_base64(text: &str) -> String {
        let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let value = |byte: u8| -> u32 {
            match byte {
                b'A'..=b'Z' => (byte - b'A') as u32,
                b'a'..=b'z' => (byte - b'a' + 26) as u32,
                b'0'..=b'9' => (byte - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                _ => 0,
            }
        };
        let bytes = compact.as_bytes();
        let mut out = Vec::new();
        for chunk in bytes.chunks(4) {
            let mut triple = 0u32;
            for (index, &byte) in chunk.iter().enumerate() {
                triple |= value(byte) << (18 - 6 * index);
            }
            out.push((triple >> 16) as u8);
            if chunk.len() > 2 && chunk[2] != b'=' {
                out.push((triple >> 8) as u8);
            }
            if chunk.len() > 3 && chunk[3] != b'=' {
                out.push(triple as u8);
            }
        }
        String::from_utf8(out).unwrap()
    }
}
