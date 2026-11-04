//! Command handlers for the fake IMAP server.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::fake_imap::{Behavior, Shared, Stream};
use super::fixtures::RawMessage;

/// The messages of `folder`, cloned so the lock is never held across an await.
fn folder_messages(shared: &Shared, folder: &str) -> Vec<RawMessage> {
    shared
        .folders
        .lock()
        .expect("folders lock")
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(folder))
        .map(|(_, messages)| messages.clone())
        .unwrap_or_default()
}

pub(super) async fn handle_uid(
    stream: &mut Stream,
    tag: &str,
    rest: &str,
    shared: &Shared,
    folder: &str,
) {
    // `rest` still carries the `UID` verb: "UID FETCH 42 BODYSTRUCTURE".
    let mut parts = rest.splitn(3, char::is_whitespace);
    let _uid = parts.next();
    let command = parts.next().unwrap_or("").to_ascii_uppercase();
    let args = parts.next().unwrap_or("").trim();
    match command.as_str() {
        "SEARCH" => {
            let Some(filter) = SearchFilter::parse(args) else {
                let reply = format!("{tag} BAD invalid SINCE date\r\n");
                let _ = write(stream, reply.as_bytes()).await;
                return;
            };
            let uids: Vec<String> = folder_messages(shared, folder)
                .iter()
                .filter(|message| filter.matches(message))
                .map(|message| message.uid.to_string())
                .collect();
            let reply = format!(
                "* SEARCH {}\r\n{tag} OK SEARCH completed\r\n",
                uids.join(" ")
            );
            let _ = write(stream, reply.as_bytes()).await;
        }
        "FETCH" => handle_fetch(stream, tag, args, shared, folder).await,
        _ => {
            let reply = format!("{tag} BAD unknown UID command\r\n");
            let _ = write(stream, reply.as_bytes()).await;
        }
    }
}

/// A calendar day as (year, month, day), ordered the way days are.
type Day = (u32, u32, u32);

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// The day of an IMAP date (`8-Oct-2025`, optionally quoted).
fn parse_imap_day(text: &str) -> Option<Day> {
    let mut parts = text.trim_matches('"').split('-');
    let day: u32 = parts.next()?.parse().ok()?;
    let month = month_number(parts.next()?)?;
    let year: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

fn month_number(name: &str) -> Option<u32> {
    let name = name.to_ascii_lowercase();
    MONTHS.iter().position(|m| *m == name).map(|i| i as u32 + 1)
}

/// The day a `Date:` header is written on, its timezone ignored
/// ("Tue, 7 Oct 2025 00:01:00 +0900" is 7 Oct). A simplification: RFC 3501
/// compares `SINCE` with the INTERNALDATE, the fake uses the `Date` header.
fn day_of(header: &str) -> Option<Day> {
    let mut words = header.split_whitespace();
    let mut first = words.next()?;
    if first.ends_with(',') {
        first = words.next()?;
    }
    let day: u32 = first.parse().ok()?;
    let month = month_number(words.next()?)?;
    let year: u32 = words.next()?.parse().ok()?;
    Some((year, month, day))
}

/// Split search criteria on whitespace outside double quotes; a quoted
/// string stays one token, quotes included.
fn criteria_tokens(criteria: &str) -> Vec<&str> {
    let (mut tokens, mut start, mut quoted, mut escaped) = (Vec::new(), None, false, false);
    for (i, c) in criteria.char_indices() {
        if quoted {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => quoted = false,
                _ => {}
            }
        } else if c.is_whitespace() {
            if let Some(from) = start.take() {
                tokens.push(&criteria[from..i]);
            }
        } else {
            start.get_or_insert(i);
            quoted = c == '"';
        }
    }
    if let Some(from) = start {
        tokens.push(&criteria[from..]);
    }
    tokens
}

/// The search a `UID SEARCH` names. Every criterion must match, as on a real
/// server: SINCE bounds the date, UNSEEN skips read mail, and TEXT, BODY,
/// SUBJECT, FROM, TO, CC and HEADER each filter on their own field. A
/// criterion the fake does not model is accepted and ignored, as before.
struct SearchFilter {
    since: Option<Day>,
    unseen: bool,
    terms: Vec<(SearchField, String)>,
}

enum SearchField {
    Text,
    Body,
    Subject,
    From,
    To,
    Cc,
    Header(String),
}

impl SearchFilter {
    /// `None` when the SINCE date is missing or malformed (the caller answers
    /// BAD), so a broken query never silently matches the whole folder.
    fn parse(criteria: &str) -> Option<Self> {
        let mut tokens = criteria_tokens(criteria).into_iter();
        let mut filter = Self {
            since: None,
            unseen: false,
            terms: Vec::new(),
        };
        while let Some(token) = tokens.next() {
            match token.to_ascii_uppercase().as_str() {
                "SINCE" => filter.since = Some(parse_imap_day(tokens.next()?)?),
                "UNSEEN" => filter.unseen = true,
                "TEXT" => filter
                    .terms
                    .push((SearchField::Text, value(tokens.next()?))),
                "BODY" => filter
                    .terms
                    .push((SearchField::Body, value(tokens.next()?))),
                "SUBJECT" => filter
                    .terms
                    .push((SearchField::Subject, value(tokens.next()?))),
                "FROM" => filter
                    .terms
                    .push((SearchField::From, value(tokens.next()?))),
                "TO" => filter.terms.push((SearchField::To, value(tokens.next()?))),
                "CC" => filter.terms.push((SearchField::Cc, value(tokens.next()?))),
                "HEADER" => {
                    let name = value(tokens.next()?);
                    let needle = value(tokens.next()?);
                    filter.terms.push((SearchField::Header(name), needle));
                }
                "KEYWORD" | "UNKEYWORD" | "BCC" => {
                    tokens.next();
                }
                _ => {}
            }
        }
        Some(filter)
    }

    fn matches(&self, message: &RawMessage) -> bool {
        if let Some(since) = self.since {
            if day_of(&message.date).is_some_and(|day| day < since) {
                return false;
            }
        }
        if self.unseen
            && message
                .flags
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
        {
            return false;
        }
        self.terms
            .iter()
            .all(|(field, needle)| field.matches(message, needle))
    }
}

impl SearchField {
    fn matches(&self, message: &RawMessage, needle: &str) -> bool {
        let haystack = match self {
            Self::Text => message.body.to_string(),
            Self::Body => message
                .body
                .split_once("\r\n\r\n")
                .map_or(message.body, |(_, body)| body)
                .to_string(),
            Self::Subject => message.subject.clone(),
            Self::From => message.from.clone(),
            Self::To => message.to.join(", "),
            Self::Cc => message.cc.join(", "),
            Self::Header(name) => header_value(message.body, name).unwrap_or_default(),
        };
        haystack.to_lowercase().contains(needle)
    }
}

/// A SEARCH value: unquoted and unescaped, lower-cased for a case-insensitive
/// substring match.
fn value(token: &str) -> String {
    let mut out = String::with_capacity(token.len());
    let mut escaped = false;
    for c in token.trim_matches('"').chars() {
        match (escaped, c) {
            (true, _) => {
                out.push(c);
                escaped = false;
            }
            (false, '\\') => escaped = true,
            (false, _) => out.push(c),
        }
    }
    out.to_lowercase()
}

/// One header's value (`Subject: ...`), before the blank line that ends the
/// header block. `None` when the message does not carry it.
fn header_value(body: &str, name: &str) -> Option<String> {
    let wanted = format!("{}:", name.to_lowercase());
    body.lines()
        .take_while(|line| !line.is_empty())
        .find(|line| line.to_lowercase().starts_with(&wanted))
        .map(|line| line[wanted.len()..].trim().to_string())
}

pub(super) async fn handle_append(stream: &mut Stream, tag: &str, rest: &str, shared: &Shared) {
    let Some(open) = rest.rfind('{') else {
        let reply = format!("{tag} BAD APPEND needs a literal\r\n");
        let _ = write(stream, reply.as_bytes()).await;
        return;
    };
    let Some(close) = rest[open..].find('}') else {
        let reply = format!("{tag} BAD malformed literal\r\n");
        let _ = write(stream, reply.as_bytes()).await;
        return;
    };
    let length: usize = rest[open + 1..open + close].parse().unwrap_or(0);
    let _ = write(stream, b"+ Ready for literal data\r\n").await;
    let mut bytes = vec![0u8; length];
    if read_exact(stream, &mut bytes).await.is_err() {
        return;
    }
    shared
        .appended
        .lock()
        .expect("appended lock")
        .push(String::from_utf8_lossy(&bytes).into_owned());
    let _ = read_line(stream).await;
    let reply = format!("{tag} OK [APPENDUID 1 900] APPEND completed\r\n");
    let _ = write(stream, reply.as_bytes()).await;
}

async fn handle_fetch(stream: &mut Stream, tag: &str, args: &str, shared: &Shared, folder: &str) {
    let (set, items) = split_set_items(args);
    for (index, message) in folder_messages(shared, folder).iter().enumerate() {
        if !in_set(message.uid, &set) {
            continue;
        }
        let seq = index + 1;
        let mut meta = String::new();
        if items.contains("FLAGS") {
            meta.push_str(&format!(" FLAGS ({})", message.flags.join(" ")));
        }
        if items.contains("RFC822.SIZE") {
            meta.push_str(&format!(" RFC822.SIZE {}", message.body.len()));
        }
        if items.contains("ENVELOPE") {
            meta.push_str(&format!(" ENVELOPE {}", envelope(message)));
        }
        if items.contains("BODYSTRUCTURE") {
            meta.push_str(&format!(" BODYSTRUCTURE {}", bodystructure(message)));
        }

        let part = requested_part(&items);
        if part.is_some() || requests_full_body(&items) {
            let (label, bytes) = match part {
                Some(part) => {
                    let Some((_, bytes)) = message.parts.iter().find(|(name, _)| *name == part)
                    else {
                        // A real server refuses a part it does not have; it
                        // never answers an empty one. The client must see the
                        // refusal, not a 0-byte part.
                        let reply = format!("{tag} NO [NONEXISTENT] unknown part\r\n");
                        let _ = write(stream, reply.as_bytes()).await;
                        return;
                    };
                    (part.to_string(), *bytes)
                }
                None => (String::new(), message.body),
            };
            // An honest server truncates to the `<0.N>` partial it was asked
            // for; `IgnorePartial` serves the whole literal instead, so the
            // connection guard has to refuse it.
            let bytes = if shared.behavior == Behavior::IgnorePartial {
                bytes
            } else if let Some(limit) = partial_len(&items) {
                &bytes[..bytes.len().min(limit)]
            } else {
                bytes
            };
            let head = format!(
                "* {seq} FETCH (UID {}{meta} BODY[{label}] {{{}}}\r\n",
                message.uid,
                bytes.len()
            );
            let _ = write(stream, head.as_bytes()).await;
            let _ = write(stream, bytes.as_bytes()).await;
            let _ = write(stream, b")\r\n").await;
        } else {
            let reply = format!("* {seq} FETCH (UID {}{meta})\r\n", message.uid);
            let _ = write(stream, reply.as_bytes()).await;
        }
    }
    let reply = format!("{tag} OK FETCH completed\r\n");
    let _ = write(stream, reply.as_bytes()).await;
}

async fn write(stream: &mut Stream, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}

async fn read_line(stream: &mut Stream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => {
                return if buffer.is_empty() {
                    None
                } else {
                    Some(String::from_utf8_lossy(&buffer).into_owned())
                }
            }
            Ok(_) => {}
            Err(_) => return None,
        }
        if byte[0] == b'\n' {
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
            return Some(String::from_utf8_lossy(&buffer).into_owned());
        }
        buffer.push(byte[0]);
        if buffer.len() > 8 * 1024 {
            return None;
        }
    }
}

async fn read_exact(stream: &mut Stream, buffer: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = stream.read(&mut buffer[filled..]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "literal ended early",
            ));
        }
        filled += read;
    }
    Ok(())
}

fn split_set_items(args: &str) -> (String, String) {
    let trimmed = args.trim();
    match trimmed.split_once(char::is_whitespace) {
        Some((set, items)) => (set.to_string(), items.trim().to_string()),
        None => (trimmed.to_string(), String::new()),
    }
}

fn in_set(uid: u32, set: &str) -> bool {
    let set = set.trim();
    if set.is_empty() || set == "1:*" || set == "*" {
        return true;
    }
    set.split(',').any(|piece| {
        let piece = piece.trim();
        if let Some((start, end)) = piece.split_once(':') {
            let start = start.parse::<u32>().unwrap_or(0);
            let end = if end == "*" {
                u32::MAX
            } else {
                end.parse::<u32>().unwrap_or(0)
            };
            uid >= start && uid <= end
        } else {
            piece.parse::<u32>() == Ok(uid)
        }
    })
}

fn requests_full_body(items: &str) -> bool {
    items.contains("BODY.PEEK[]") || items.contains("BODY[]")
}

fn requested_part(items: &str) -> Option<&str> {
    for marker in ["BODY.PEEK[", "BODY["] {
        if let Some(start) = items.find(marker) {
            let rest = &items[start + marker.len()..];
            if let Some(end) = rest.find(']') {
                let part = &rest[..end];
                if !part.is_empty() {
                    return Some(part);
                }
            }
        }
    }
    None
}

/// The byte count in a `BODY[…]<0.N>` partial, when the request carries one.
fn partial_len(items: &str) -> Option<usize> {
    let start = items.find('<')?;
    let rest = &items[start + 1..];
    let end = rest.find('>')?;
    let (offset, length) = rest[..end].split_once('.')?;
    if offset != "0" {
        return None;
    }
    length.parse::<usize>().ok()
}

fn envelope(message: &RawMessage) -> String {
    let from = address_list(std::slice::from_ref(&message.from));
    let to = address_list(&message.to);
    let cc = address_list(&message.cc);
    let in_reply_to = message
        .in_reply_to
        .as_deref()
        .map(quoted)
        .unwrap_or_else(|| "NIL".to_string());
    format!(
        "({} {} {} {} {} {} {} NIL {} {})",
        quoted(&message.date),
        quoted(&message.subject),
        from,
        from,
        from,
        to,
        cc,
        in_reply_to,
        quoted(&message.message_id),
    )
}

fn bodystructure(message: &RawMessage) -> String {
    message
        .bodystructure
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
            "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" {} 1 NIL NIL NIL NIL)",
            message.body.len()
        )
        })
}

fn address_list(values: &[String]) -> String {
    let items: Vec<String> = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| address_item(value))
        .collect();
    if items.is_empty() {
        "NIL".to_string()
    } else {
        format!("({})", items.join(""))
    }
}

fn address_item(raw: &str) -> String {
    let raw = raw.trim();
    let (name, address) = match raw.find('<') {
        Some(start) => {
            let end = raw[start..]
                .find('>')
                .map(|offset| start + offset)
                .unwrap_or(raw.len());
            (
                raw[..start].trim().trim_matches('"').trim(),
                raw[start + 1..end].trim(),
            )
        }
        None => ("", raw),
    };
    let (mailbox, host) = address.split_once('@').unwrap_or((address, ""));
    let name = if name.is_empty() {
        "NIL".to_string()
    } else {
        quoted(name)
    };
    let mailbox = if mailbox.is_empty() {
        "NIL".to_string()
    } else {
        quoted(mailbox)
    };
    let host = if host.is_empty() {
        "NIL".to_string()
    } else {
        quoted(host)
    };
    format!("({name} NIL {mailbox} {host})")
}

/// An IMAP string: quoted, or a literal when it holds CR or LF, which a quoted
/// string may never carry (RFC 3501 §4.3).
fn quoted(value: &str) -> String {
    if value.contains(['\r', '\n']) {
        return format!("{{{}}}\r\n{value}", value.len());
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
