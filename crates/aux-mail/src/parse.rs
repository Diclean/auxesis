//! RFC822 bytes become a decoded [`MailItem`].
//!
//! `mail-parser` (built with `full_encoding`) owns MIME walking and charset
//! decoding. `text/plain` is always preferred; an HTML-only message goes
//! through the runtime's readability extractor over the whole body
//! ([`aux_runtime::fetch::extract_body_text`]), which replaces the old
//! `aux-fetch` crate (`docs/phase1.md` §2).
//!
//! Attachments are **metadata only** — name, MIME type, decoded size and IMAP
//! part id — and no part body is ever fetched. Phase 1 drops the attachment
//! quarantine; downloading into the registry is slice MA3.
//!
//! Nothing here renders to a model: the parsed strings are still hostile and
//! must pass through [`crate::sanitize::render_untrusted`].

use mail_parser::{Mailbox, Message, MessageParser, MessagePart, PartId, PartKind, PartRole};

use crate::error::MailError;
use crate::imap_read::RawMail;

/// The metadata of one attachment part. Never its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    /// The `filename`/`name` the sender declared, or empty.
    pub file_name: String,
    /// The declared `type/subtype`, or `application/octet-stream`.
    pub mime: String,
    /// The decoded part length in bytes; a text part counts its UTF-8 text.
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

    // The first text-body part (plain when there is one), else the first HTML one.
    let text = message
        .text_body()
        .next()
        .and_then(body_part_text)
        .or_else(|| message.html_body().next().and_then(body_part_text))
        .unwrap_or_default();

    let attachments = attachment_meta(&message)?;

    Ok(MailItem {
        message_id: message.message_id().unwrap_or_default().to_string(),
        subject: message.subject().unwrap_or_default().to_string(),
        from: message
            .from()
            .and_then(|addresses| addresses.mailboxes().next())
            .map(format_mailbox)
            .unwrap_or_default(),
        to: message
            .to()
            .map(|addresses| addresses.mailboxes().map(format_mailbox).collect())
            .unwrap_or_default(),
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

/// The text of one body part: a text part as decoded, an HTML part through
/// the runtime's extractor, which drops `noscript`, `iframe` and the other
/// elements a reader never sees (`mail-parser`'s own conversion keeps them).
/// `None` for inline media.
fn body_part_text(part: MessagePart<'_>) -> Option<String> {
    match part.kind() {
        PartKind::Text => part.text().map(|text| text.into_owned()),
        PartKind::Html => part
            .text()
            .map(|html| aux_runtime::fetch::extract_body_text(html.as_bytes()).text),
        _ => None,
    }
}

/// The attachments of the top-level message, in document order.
///
/// `mail-parser`'s own list follows RFC 8621, which leaves out an image, audio
/// or video part shown inline in the body. Such a part is still a file the
/// sender attached (a photo pasted into a mail), so it is listed too.
fn attachment_meta(message: &Message<'_>) -> Result<Vec<AttachmentMeta>, MailError> {
    let numbering = part_ids(message)?;
    let mut attachments = Vec::new();
    let listed = message
        .root()
        .parts()
        .filter(|part| part.is_attachment() || part.role() == PartRole::MediaBody);
    for part in listed {
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
            size: part_size(part),
            part_id: numbering
                .iter()
                .find(|(id, _)| *id == part.id())
                .map(|(_, part_id)| part_id.clone())
                .unwrap_or_default(),
        });
    }
    Ok(attachments)
}

/// The decoded length: the UTF-8 text of a text part, else the
/// transfer-decoded bytes.
fn part_size(part: MessagePart<'_>) -> u32 {
    let len = match part.text() {
        Some(text) => text.len(),
        None => part.decoded_len(),
    };
    len as u32
}

/// Deepest MIME nesting we will number before refusing the message.
const MAX_PART_DEPTH: u32 = 32;

/// Most MIME parts we will number before refusing the message.
const MAX_PARTS: usize = 500;

/// Map every MIME part id to its IMAP part specifier.
///
/// RFC 3501 numbers the children of a multipart from 1, dotted by nesting. The
/// walk is **iterative**: a hostile message can nest thousands of multiparts,
/// and a recursive walk would exhaust the stack before `mail-parser` (which
/// itself walks multiparts with an explicit state stack) returns. It refuses
/// past [`MAX_PART_DEPTH`] or [`MAX_PARTS`] with a typed error, never a panic.
/// A `message/rfc822` part has no `children()`, so it is a leaf and is **not**
/// recursed into (the nested-message rule).
fn part_ids(message: &Message<'_>) -> Result<Vec<(PartId, String)>, MailError> {
    let mut ids = Vec::new();
    let mut parts = 0usize;
    // (part, dotted prefix, depth of the parent)
    let mut stack = vec![(message.root_part(), String::new(), 0u32)];
    while let Some((part, prefix, depth)) = stack.pop() {
        if !part.is_multipart() {
            continue;
        }
        if depth >= MAX_PART_DEPTH {
            return Err(MailError::Protocol);
        }
        for (position, child) in part.children().enumerate() {
            parts += 1;
            if parts > MAX_PARTS {
                return Err(MailError::Protocol);
            }
            let id = if prefix.is_empty() {
                format!("{}", position + 1)
            } else {
                format!("{prefix}.{}", position + 1)
            };
            ids.push((child.id(), id.clone()));
            stack.push((child, id, depth + 1));
        }
    }
    Ok(ids)
}

fn format_mailbox(mailbox: Mailbox<'_>) -> String {
    match (mailbox.name(), mailbox.address()) {
        (Some(name), Some(address)) => format!("{name} <{address}>"),
        (None, Some(address)) => address.to_string(),
        (Some(name), None) => name.to_string(),
        (None, None) => String::new(),
    }
}
