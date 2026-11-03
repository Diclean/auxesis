//! M4: RFC822 bytes become a decoded [`MailItem`].
//!
//! `mail-parser` (built with `full_encoding`) owns MIME walking and charset
//! decoding. `text/plain` is always preferred; an HTML-only message goes
//! through the runtime's readability extractor
//! ([`aux_runtime::fetch::extract_readable`]), which replaces the old
//! `aux-fetch` crate (`docs/phase1.md` §2).
//!
//! Attachments are **metadata only** — name, MIME type, decoded size and IMAP
//! part id — and no part body is ever fetched. Phase 1 drops the attachment
//! quarantine; downloading into the registry is slice MA3.
//!
//! Nothing here renders to a model: the parsed strings are still hostile and
//! must pass through [`crate::sanitize::render_untrusted`].

use mail_parser::{MessageParser, MimeHeaders};

use crate::error::MailError;
use crate::imap_read::RawMail;

/// The metadata of one attachment part. Never its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    /// The `filename`/`name` the sender declared, or empty.
    pub file_name: String,
    /// The declared `type/subtype`, or `application/octet-stream`.
    pub mime: String,
    /// The decoded part length in bytes.
    pub size: u32,
    /// The IMAP part specifier (`2`, `2.1`, …) the download in MA3 uses.
    pub part_id: String,
}

/// A parsed message, ready for [`crate::sanitize::render_untrusted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailItem {
    /// The `Message-ID` header, when the message has one.
    pub message_id: String,
    /// The `Subject` header.
    pub subject: String,
    /// The `From` header, formatted `Name <address>`.
    pub from: String,
    /// The `To` header, one entry per address.
    pub to: Vec<String>,
    /// The `Date` header, RFC 5322 form.
    pub date: String,
    /// The body text: the plain part, or the readability extractor's output.
    pub text: String,
    /// Attachment metadata only; no bytes.
    pub attachments: Vec<AttachmentMeta>,
    /// The folder the message was read from.
    pub folder: String,
    /// The message size in bytes (what was fetched, not `RFC822.SIZE`).
    pub size: u32,
}

/// Parse one raw message.
///
/// Never panics on hostile bytes: a message `mail-parser` refuses is a typed
/// [`MailError::Protocol`].
pub fn parse_message(raw: &RawMail) -> Result<MailItem, MailError> {
    let message = MessageParser::default()
        .parse(raw.bytes.as_slice())
        .ok_or(MailError::Protocol)?;

    let text = if let Some(plain) = message.body_text(0) {
        plain.into_owned()
    } else if let Some(html) = message.body_html(0) {
        aux_runtime::fetch::extract_readable(html.as_bytes()).text
    } else {
        String::new()
    };

    let attachments = attachment_meta(&message)?;

    Ok(MailItem {
        message_id: message.message_id().unwrap_or_default().to_string(),
        subject: message.subject().unwrap_or_default().to_string(),
        from: message
            .from()
            .map(format_address)
            .and_then(|addresses| addresses.into_iter().next())
            .unwrap_or_default(),
        to: message.to().map(format_address).unwrap_or_default(),
        date: message
            .date()
            .map(|date| date.to_rfc822())
            .unwrap_or_default(),
        text,
        attachments,
        folder: raw.folder.clone(),
        size: raw.bytes.len() as u32,
    })
}

fn attachment_meta(message: &mail_parser::Message<'_>) -> Result<Vec<AttachmentMeta>, MailError> {
    let numbering = part_ids(message)?;
    let mut attachments = Vec::with_capacity(message.attachments.len().min(MAX_PARTS));
    for id in &message.attachments {
        let Some(part) = message.part(*id) else {
            continue;
        };
        let mime = part
            .content_type()
            .map(|content_type| match content_type.subtype() {
                Some(subtype) => format!("{}/{}", content_type.ctype(), subtype),
                None => content_type.ctype().to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        attachments.push(AttachmentMeta {
            file_name: part.attachment_name().unwrap_or_default().to_string(),
            mime,
            size: part.len() as u32,
            part_id: numbering
                .iter()
                .find(|(index, _)| *index == *id as usize)
                .map(|(_, part_id)| part_id.clone())
                .unwrap_or_default(),
        });
    }
    Ok(attachments)
}

/// Deepest MIME nesting we will number before refusing the message.
const MAX_PART_DEPTH: u32 = 32;

/// Most MIME parts we will number before refusing the message.
const MAX_PARTS: usize = 500;

/// Map every MIME part index to its IMAP part specifier.
///
/// RFC 3501 numbers the children of a multipart from 1, dotted by nesting. The
/// walk is **iterative**: a hostile message can nest thousands of multiparts,
/// and a recursive walk would exhaust the stack before `mail-parser` (which
/// itself walks multiparts with an explicit state stack) returns. It refuses
/// past [`MAX_PART_DEPTH`] or [`MAX_PARTS`] with a typed error, never a panic.
/// A `message/rfc822` part has no `sub_parts`, so it is a leaf and is **not**
/// recursed into (the nested-message rule).
fn part_ids(message: &mail_parser::Message<'_>) -> Result<Vec<(usize, String)>, MailError> {
    let mut ids = Vec::new();
    let mut parts = 0usize;
    // (part index, dotted prefix, depth of the parent)
    let mut stack = vec![(0usize, String::new(), 0u32)];
    while let Some((index, prefix, depth)) = stack.pop() {
        let Some(children) = message.parts.get(index).and_then(|part| part.sub_parts()) else {
            continue;
        };
        if depth >= MAX_PART_DEPTH {
            return Err(MailError::Protocol);
        }
        for (position, child) in children.iter().enumerate() {
            parts += 1;
            if parts > MAX_PARTS {
                return Err(MailError::Protocol);
            }
            let id = if prefix.is_empty() {
                format!("{}", position + 1)
            } else {
                format!("{prefix}.{}", position + 1)
            };
            let child = *child as usize;
            ids.push((child, id.clone()));
            stack.push((child, id, depth + 1));
        }
    }
    Ok(ids)
}

fn format_address(address: &mail_parser::Address<'_>) -> Vec<String> {
    match address {
        mail_parser::Address::List(list) => list.iter().map(format_addr).collect(),
        mail_parser::Address::Group(groups) => groups
            .iter()
            .flat_map(|group| group.addresses.iter().map(format_addr))
            .collect(),
    }
}

fn format_addr(addr: &mail_parser::Addr<'_>) -> String {
    match (addr.name.as_deref(), addr.address.as_deref()) {
        (Some(name), Some(address)) => format!("{name} <{address}>"),
        (None, Some(address)) => address.to_string(),
        (Some(name), None) => name.to_string(),
        (None, None) => String::new(),
    }
}
