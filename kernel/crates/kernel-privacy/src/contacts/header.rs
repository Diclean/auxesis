//! Reading people out of mail: RFC 5322 mailboxes, RFC 2047 encoded words,
//! header-like lines in six languages, `<Name> <address>` pairs and attribution
//! lines ("… a écrit :", "… wrote:").
//!
//! This is the seeding half of the contact index: it runs on a message before
//! detection, so the index already knows the people the message names. Nothing
//! here reads a gold label; it only reads what a mail client shows.

use zeroize::Zeroizing;

use super::fold::folded_text;
use super::variants::GENERIC_WORDS;
use super::{ContactIndex, Insert, PersonDraft};
use crate::recognizer::Recognizer;
use crate::recognizers::email::EmailRecognizer;

/// Header labels that introduce a sender, lower-cased: English, Dutch, German,
/// Russian, Hungarian and Arabic forms.
const SENDER_LABELS: &[&str] = &["from", "de", "van", "von", "от", "feladó", "من"];

/// Header labels that introduce recipients, lower-cased, in the same languages.
const RECIPIENT_LABELS: &[&str] = &[
    "to",
    "à",
    "aan",
    "кому",
    "címzett",
    "إلى",
    "cc",
    "copie",
    "kopie",
    "másolat",
    "копия",
    "نسخة",
    "bcc",
];

/// Verbs that open an attribution line ("Marie a écrit :"), in six languages.
const ATTRIBUTION_VERBS: &[&str] = &[
    "a écrit",
    "wrote",
    "het geskryf",
    "schreef",
    "írta",
    "написал",
    "написала",
    "написали",
    "كتب",
    "قال",
];

/// Words that end a name run in an attribution line: weekdays, months, times.
const ATTRIBUTION_STOP: &[&str] = &[
    "am",
    "pm",
    "at",
    "à",
    "le",
    "on",
    "the",
    "het",
    "op",
    "om",
    "um",
    "de",
    "mon",
    "tue",
    "wed",
    "thu",
    "fri",
    "sat",
    "sun",
    "lun",
    "mar",
    "mer",
    "jeu",
    "ven",
    "sam",
    "dim",
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "sept",
    "oct",
    "nov",
    "dec",
    "janv",
    "févr",
    "avr",
    "juil",
    "août",
    "déc",
    "mrt",
    "mei",
    "okt",
    "des",
    "január",
    "február",
    "március",
    "április",
    "május",
    "június",
    "július",
    "augusztus",
    "szeptember",
    "október",
    "november",
    "december",
    "января",
    "февраля",
    "марта",
    "апреля",
    "мая",
    "июня",
    "июля",
    "августа",
    "сентября",
    "октября",
    "ноября",
    "декабря",
];

/// Greetings and sign-offs that open a line in six languages. Folded, they are
/// never part of a name before an address.
const GREETINGS: &[&str] = &[
    "hi",
    "hello",
    "hey",
    "dear",
    "cher",
    "chere",
    "chers",
    "cheres",
    "bonjour",
    "bonsoir",
    "salut",
    "merci",
    "hallo",
    "hej",
    "beste",
    "goeie",
    "hoi",
    "hola",
    "szia",
    "sziasztok",
    "helo",
    "привет",
    "здравствуйте",
    "здравствуй",
    "thanks",
    "thank",
    "regards",
    "cordialement",
    "best",
    "sincerely",
    "greetings",
    "dag",
    "مرحبا",
    "أهلا",
    "عزيزي",
    "عزيزتي",
];

/// Words that mark a display name as an organisation, not a person.
const ORG_WORDS: &[&str] = &[
    "ltd",
    "limited",
    "llc",
    "inc",
    "corp",
    "co",
    "gmbh",
    "sarl",
    "sas",
    "sasu",
    "srl",
    "spa",
    "bv",
    "nv",
    "kft",
    "zrt",
    "ooo",
    "pty",
    "plc",
    "sa",
    "asbl",
    "studio",
    "team",
    "support",
    "service",
    "services",
    "group",
    "bank",
    "company",
    "agency",
    "office",
    "department",
    "ministry",
    "ministère",
    "préfecture",
    "mairie",
    "université",
    "university",
    "association",
    "hotel",
    "hôtel",
    "shop",
    "store",
    "newsletter",
    "noreply",
    "admin",
    "info",
    "contact",
    "sales",
    "billing",
    "reply",
    "mailer",
    "notifications",
    "news",
    "webmaster",
    "bureau",
    "direction",
];

/// Titles and forms of address, dropped from a name.
const TITLE_WORDS: &[&str] = &[
    "dr", "mr", "mrs", "ms", "mme", "mlle", "m", "mx", "prof", "me", "ing", "dipl", "herr", "frau",
    "sir", "madam", "monsieur", "madame", "mijnheer", "mevrou", "mnr", "mev", "dhr", "hr",
];

/// Particles that may begin a family name.
const PARTICLES: &[&str] = &[
    "de", "du", "des", "der", "den", "van", "von", "di", "da", "dos", "das", "del", "della", "le",
    "la", "les", "el", "al", "bin", "ibn", "ben", "ter", "ten", "het", "zu", "op", "ap", "abu",
];

/// Longest display name, in words, that is taken as a person's name.
const MAX_NAME_WORDS: usize = 6;

/// A display name split into given and family names. Empty when the text is
/// not a plausible name (an organisation, a sentence, a role).
#[derive(Default)]
pub(crate) struct ParsedName {
    pub(crate) given: Vec<String>,
    pub(crate) family: Vec<String>,
}

impl ContactIndex {
    /// Seed the index from the text of one message: header lines (`From`,
    /// `To`, `Cc` and their translations), `<Name> <address>` pairs,
    /// attribution lines and bare addresses. Returns how many entries were
    /// added or merged. Nothing is read from the text except what a mail
    /// client shows.
    pub fn seed_from_text(&mut self, text: &str) -> usize {
        let text = self.clip(text);
        let decoded = decode_words(text);
        let mut mailboxes: Vec<(String, String)> = Vec::new();
        for line in decoded.lines() {
            let unquoted = line.trim_start_matches(|c: char| c == '>' || c.is_whitespace());
            if let Some(value) = header_value(unquoted) {
                mailboxes.extend(split_mailboxes(value));
                continue;
            }
            angle_pairs(line, &mut mailboxes);
            if let Some(name) = attribution_name(line) {
                mailboxes.push((name, String::new()));
            }
        }

        // Bare addresses last, so that they merge into the people named above.
        for found in EmailRecognizer::new().analyze(&decoded) {
            if let Some(address) = decoded.get(found.start..found.end) {
                mailboxes.push((String::new(), address.to_string()));
            }
        }
        self.add_mailboxes(&mailboxes).0
    }

    /// The part of `text` that seeding reads: at most `max_text_bytes`, cut back
    /// to a character boundary. A cut counts as one refusal.
    pub(super) fn clip<'a>(&mut self, text: &'a str) -> &'a str {
        let limit = self.limits.max_text_bytes;
        if text.len() <= limit {
            return text;
        }
        self.refused += 1;
        let mut end = limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    }
}

/// The value of a header-like line, when its label is a known one.
fn header_value(line: &str) -> Option<&str> {
    let (label, value) = line.split_once(':').or_else(|| line.split_once('：'))?;
    let label = label.trim().to_lowercase();
    let known =
        SENDER_LABELS.contains(&label.as_str()) || RECIPIENT_LABELS.contains(&label.as_str());
    known.then_some(value)
}

/// Whether `prefix`, the text of a line before a match, is a known header label
/// and its colon ("From: ", "Cc: Paul, "): the match is then a name in a header.
pub(super) fn is_header_value(prefix: &str) -> bool {
    header_value(prefix.trim_start_matches(|c: char| c == '>' || c.is_whitespace())).is_some()
}

/// Split a header value into `(display name, address)` mailboxes.
///
/// Commas and semicolons separate mailboxes, except inside quotes, angle
/// brackets and parentheses. A part without an address is a name fragment:
/// it joins the next mailbox, so `Dupont, Marie <m@…>` is one person.
pub(crate) fn split_mailboxes(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut pending: Option<String> = None;
    for segment in top_level_segments(value) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if let (Some(open), Some(close)) = (segment.find('<'), segment.rfind('>')) {
            if open < close {
                let address = segment[open + 1..close].trim().to_string();
                let own = strip_comments(&segment[..open]);
                let name = match pending.take() {
                    Some(earlier) if own.is_empty() => earlier,
                    Some(earlier) => format!("{earlier}, {own}"),
                    None => own,
                };
                out.push((name, address));
                continue;
            }
        }
        if segment.contains('@') {
            if let Some(name) = pending.take() {
                out.push((name, String::new()));
            }
            out.push((String::new(), segment.to_string()));
            continue;
        }
        pending = Some(match pending.take() {
            Some(earlier) => format!("{earlier}, {segment}"),
            None => segment.to_string(),
        });
    }
    if let Some(name) = pending {
        out.push((name, String::new()));
    }
    out
}

/// The parts of `value` between top-level separators.
fn top_level_segments(value: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut angle = 0i32;
    let mut paren = 0i32;
    let mut quoted = false;
    let mut start = 0;
    for (index, c) in value.char_indices() {
        match c {
            '"' => quoted = !quoted,
            _ if quoted => {}
            '<' => angle += 1,
            '>' => angle = (angle - 1).max(0),
            '(' => paren += 1,
            ')' => paren = (paren - 1).max(0),
            ',' | ';' | '،' if angle == 0 && paren == 0 => {
                segments.push(&value[start..index]);
                start = index + c.len_utf8();
            }
            _ => {}
        }
    }
    segments.push(&value[start..]);
    segments
}

/// Pairs `<address>` with the name written just before it on the same line.
fn angle_pairs(line: &str, out: &mut Vec<(String, String)>) {
    let mut cursor = 0;
    while let Some(relative) = line[cursor..].find('<') {
        let open = cursor + relative;
        let Some(relative_close) = line[open..].find('>') else {
            break;
        };
        let close = open + relative_close;
        let inner = line[open + 1..close].trim();
        if inner.contains('@') && !inner.contains(char::is_whitespace) {
            out.push((name_before(&line[cursor..open]), inner.to_string()));
        }
        cursor = close + 1;
    }
}

/// The name run at the end of `prefix`: the words after the last separator,
/// at most four, without a leading lower-case word or greeting. "contact the
/// team at Marie Dupont" gives "Marie Dupont"; "Hi, Thomas" gives "Thomas".
fn name_before(prefix: &str) -> String {
    let cut = prefix
        .rfind([',', ';', '(', '[', '{', '|'])
        .map_or(0, |index| index + 1);
    let cleaned = strip_comments(&prefix[cut..]);
    let mut words: Vec<&str> = cleaned.split_whitespace().collect();
    let keep_from = words.len().saturating_sub(4);
    words.drain(..keep_from);
    while words.first().is_some_and(|word| {
        word.chars().next().is_some_and(char::is_lowercase)
            || GREETINGS.contains(&folded_text(word).as_str())
    }) {
        words.remove(0);
    }
    words.join(" ")
}

/// The name in an attribution line ("Le 5 oct. 2026, Marie Dupont a écrit :"),
/// when the line ends with the verb.
fn attribution_name(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    if lower.len() != line.len() {
        return None;
    }
    let (at, verb) = ATTRIBUTION_VERBS
        .iter()
        .filter_map(|verb| lower.find(verb).map(|at| (at, *verb)))
        .min()?;
    if !line.is_char_boundary(at) {
        return None;
    }
    // The verb must end the attribution: only punctuation or "(a)" may follow.
    let rest = line.get(at + verb.len()..)?;
    if !rest
        .trim_matches(|c: char| matches!(c, ' ' | ':' | '(' | ')' | 'a' | 'а' | '\u{a0}'))
        .is_empty()
    {
        return None;
    }
    let prefix = &line[..at];
    let segment = prefix.rsplit([',', '،']).next().unwrap_or(prefix);
    let mut words: Vec<&str> = Vec::new();
    for word in segment.split_whitespace().rev() {
        let bare = word.trim_matches(|c: char| !c.is_alphabetic());
        if words.len() == 3
            || bare.is_empty()
            || bare.chars().next().is_some_and(char::is_lowercase)
            || ATTRIBUTION_STOP.contains(&folded_text(bare).as_str())
        {
            break;
        }
        words.push(bare);
    }
    if words.is_empty() {
        return None;
    }
    words.reverse();
    let name = words.join(" ");
    (name.chars().count() >= 2).then_some(name)
}

impl ContactIndex {
    /// Add one mailbox: a display name and an address, either possibly empty.
    /// Reports [`Insert::Unusable`] when neither is usable.
    pub(crate) fn add_mailbox(&mut self, display_name: &str, address: &str) -> Insert {
        let parsed = parse_name(display_name);
        let email = clean_address(address);
        if parsed.given.is_empty() && parsed.family.is_empty() && email.is_none() {
            return Insert::Unusable;
        }
        let display = decode_words(display_name).trim().to_string();
        self.insert(PersonDraft {
            display_name: (!display.is_empty()).then(|| Zeroizing::new(display)),
            given: parsed.given.into_iter().map(Zeroizing::new).collect(),
            family: parsed.family.into_iter().map(Zeroizing::new).collect(),
            emails: email.into_iter().map(Zeroizing::new).collect(),
            ..PersonDraft::default()
        })
    }
}

/// Split a display name into given and family names. `Last, First` order is
/// honoured; a single word is a given name. Organisations, titles, role words
/// and lower-case sentences give an empty result.
pub(crate) fn parse_name(raw: &str) -> ParsedName {
    let decoded = decode_words(raw);
    let cleaned: String = decoded
        .chars()
        .filter(|c| !matches!(c, '"' | '“' | '”' | '«' | '»'))
        .collect();
    let (given, family) = if let Some((family, rest)) = cleaned.split_once(',') {
        let given_part = rest.split(',').next().unwrap_or("");
        (name_words(given_part), name_words(family))
    } else {
        let mut words = name_words(&cleaned);
        if words.is_empty() {
            return ParsedName::default();
        }
        let given = vec![words.remove(0)];
        (given, words)
    };
    let names_only: Vec<&String> = given.iter().chain(&family).collect();
    if names_only.is_empty() || names_only.iter().any(|word| is_org_word(word)) {
        return ParsedName::default();
    }
    if given.is_empty() {
        return ParsedName::default();
    }
    ParsedName { given, family }
}

/// The plausible name words of `text`. Empty when the text has too many words
/// or a word is a digit, a mail token, or an unexpected lower-case word.
fn name_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    for raw in text.split_whitespace() {
        let word =
            raw.trim_matches(|c: char| !c.is_alphabetic() && c != '-' && c != '\'' && c != '’');
        if word.is_empty()
            || word
                .chars()
                .any(|c| c.is_ascii_digit() || c == '@' || c == '<' || c == '>')
        {
            return Vec::new();
        }
        let folded = folded_text(word);
        if TITLE_WORDS.contains(&folded.as_str()) {
            continue;
        }
        let starts_lower = word.chars().next().is_some_and(char::is_lowercase);
        if starts_lower && !PARTICLES.contains(&folded.as_str()) {
            return Vec::new();
        }
        words.push(word.to_string());
    }
    if words.len() > MAX_NAME_WORDS {
        return Vec::new();
    }
    words
}

/// Whether a name word marks an organisation or a mailbox role.
fn is_org_word(word: &str) -> bool {
    let folded = folded_text(word);
    ORG_WORDS.contains(&folded.as_str()) || GENERIC_WORDS.contains(&folded.as_str())
}

/// The address as lower-case `local@domain`, or `None` when it is not one.
pub(crate) fn clean_address(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    let lower = trimmed.to_lowercase();
    let address = lower
        .strip_prefix("mailto:")
        .unwrap_or(lower.as_str())
        .trim();
    let (local, domain) = address.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || address.contains(char::is_whitespace) {
        return None;
    }
    Some(address.to_string())
}

/// Remove parenthesised comments and quote characters from `text`.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0usize;
    for c in text.chars() {
        match c {
            '(' => depth += 1,
            ')' if depth > 0 => depth -= 1,
            '"' | '“' | '”' | '«' | '»' => {}
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out.trim().to_string()
}

/// Replace RFC 2047 encoded words (`=?charset?B|Q?text?=`) with their text.
/// Whitespace between two adjacent encoded words is dropped, as the RFC says.
pub(crate) fn decode_words(input: &str) -> String {
    if !input.contains("=?") {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    let mut after_word = false;
    while let Some(at) = rest.find("=?") {
        let (before, encoded) = rest.split_at(at);
        let blank = before.trim().is_empty();
        if !(after_word && blank) {
            out.push_str(before);
        }
        after_word = false;
        match decode_word(encoded) {
            Some((decoded, used)) => {
                out.push_str(&decoded);
                rest = &encoded[used..];
                after_word = true;
            }
            None => {
                out.push_str("=?");
                rest = &encoded[2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Decode one encoded word at the start of `text`; returns the text and the
/// number of bytes it spans.
fn decode_word(text: &str) -> Option<(String, usize)> {
    let body = text.strip_prefix("=?")?;
    let charset_end = body.find('?')?;
    let charset = &body[..charset_end];
    let after_charset = &body[charset_end + 1..];
    let encoding_end = after_charset.find('?')?;
    let encoding = &after_charset[..encoding_end];
    let after_encoding = &after_charset[encoding_end + 1..];
    let payload_end = after_encoding.find("?=")?;
    let payload = &after_encoding[..payload_end];
    let used = 2 + charset_end + 1 + encoding_end + 1 + payload_end + 2;
    let bytes = match encoding {
        "B" | "b" => base64_decode(payload),
        "Q" | "q" => quoted_printable_decode(payload),
        _ => return None,
    };
    let charset = charset.split('*').next().unwrap_or("").to_ascii_lowercase();
    Some((bytes_to_text(&charset, &bytes), used))
}

/// The text of `bytes` in `charset`. Latin-1 and Windows-1252 map byte for
/// byte; anything else is read as UTF-8, lossily.
fn bytes_to_text(charset: &str, bytes: &[u8]) -> String {
    match charset {
        "iso-8859-1" | "iso8859-1" | "latin1" | "windows-1252" | "cp1252" | "iso-8859-15" => {
            bytes.iter().map(|&byte| byte as char).collect()
        }
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Lenient base64: skips anything outside the alphabet, padding included.
fn base64_decode(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xFF) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    out
}

/// Quoted-printable as used in encoded words: `_` is a space and `=XX` a byte.
fn quoted_printable_decode(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'_' => out.push(b' '),
            b'=' if index + 2 < bytes.len() => {
                if let (Some(high), Some(low)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                {
                    out.push(high * 16 + low);
                    index += 3;
                    continue;
                }
                out.push(b'=');
            }
            other => out.push(other),
        }
        index += 1;
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_both_encodings_and_drops_space_between_words() {
        assert_eq!(decode_words("=?UTF-8?Q?Marie_Dupont?="), "Marie Dupont");
        // "Bálint Kovács" in UTF-8, base64.
        assert_eq!(
            decode_words("=?UTF-8?B?QsOhbGludCBLb3bDoWNz?="),
            "Bálint Kovács"
        );
        assert_eq!(
            decode_words("=?UTF-8?Q?Marie?= =?UTF-8?Q?_Dupont?="),
            "Marie Dupont"
        );
        assert_eq!(
            decode_words("plain =?bogus?x?y?= text"),
            "plain =?bogus?x?y?= text"
        );
    }

    #[test]
    fn mailboxes_handle_quotes_last_first_and_lists() {
        let value = r#""Dupont, Marie" <marie.dupont83@example.invalid>; Thomas Vidal <t.vidal@example.invalid>"#;
        let boxes = split_mailboxes(value);
        assert_eq!(boxes.len(), 2);
        assert_eq!(boxes[0].0, "Dupont, Marie");
        assert_eq!(boxes[0].1, "marie.dupont83@example.invalid");
        assert_eq!(boxes[1].0, "Thomas Vidal");
    }

    #[test]
    fn a_bare_last_first_pair_joins_the_next_mailbox() {
        let boxes = split_mailboxes("Dupont, Marie <m@example.invalid>, Ben <b@example.invalid>");
        assert_eq!(boxes[0].0, "Dupont, Marie");
        assert_eq!(boxes[1].0, "Ben");
    }

    #[test]
    fn names_parse_in_both_orders_and_refuse_organisations() {
        let parsed = parse_name("Dupont, Marie");
        assert_eq!(parsed.family, vec!["Dupont".to_string()]);
        assert_eq!(parsed.given, vec!["Marie".to_string()]);
        let parsed = parse_name("Dr. Jean-Marc Van der Berg");
        assert_eq!(parsed.given, vec!["Jean-Marc".to_string()]);
        assert_eq!(parsed.family.len(), 3);
        assert!(parse_name("Tallowmere Ltd").given.is_empty());
        assert!(parse_name("Quillfeather Studio").given.is_empty());
        assert!(parse_name("the team").given.is_empty());
    }

    #[test]
    fn header_labels_work_in_six_languages() {
        assert_eq!(
            header_value("De : Marie <m@example.invalid>"),
            Some(" Marie <m@example.invalid>")
        );
        assert_eq!(
            header_value("Кому: Анна <a@example.invalid>"),
            Some(" Анна <a@example.invalid>")
        );
        assert_eq!(
            header_value("Címzett: Anna <a@example.invalid>"),
            Some(" Anna <a@example.invalid>")
        );
        assert_eq!(header_value("Note: nothing here"), None);
    }

    #[test]
    fn attribution_lines_yield_the_writer() {
        assert_eq!(
            attribution_name("Le lun. 5 oct. 2026 à 09:12, Marie Dupont a écrit :").as_deref(),
            Some("Marie Dupont")
        );
        assert_eq!(
            attribution_name("On Mon, Oct 5, 2026 at 9:12 AM Marie Dupont wrote:").as_deref(),
            Some("Marie Dupont")
        );
        assert_eq!(
            attribution_name("5 окт. 2026 г., в 9:12, Анна Смирнова написал(а):").as_deref(),
            Some("Анна Смирнова")
        );
        assert_eq!(attribution_name("Marie wrote a letter to the board"), None);
    }

    #[test]
    fn angle_pairs_take_the_name_on_the_same_line() {
        let mut out = Vec::new();
        angle_pairs(
            "Please contact the team at Marie Dupont <marie.dupont83@example.invalid> today",
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "Marie Dupont");
    }

    #[test]
    fn seeding_reads_headers_pairs_and_addresses() {
        let mut index = ContactIndex::new();
        let text = "From: Mateo Lindqvist <mateo.lindqvist@example.invalid>\n\
                    To: Freya Halloran <freya.halloran@example.invalid>\n\
                    Cc: ops@example.invalid\n\n\
                    Hi, Thomas Vidal <t.vidal@example.invalid> is cc'd.";
        let touched = index.seed_from_text(text);
        assert!(touched >= 4);
        assert_eq!(index.len(), 4);
        let mateo = index
            .people()
            .find(|person| person.emails.iter().any(|e| e.starts_with("mateo")))
            .expect("mateo seeded");
        assert_eq!(mateo.given[0].as_str(), "Mateo");
        assert_eq!(mateo.family[0].as_str(), "Lindqvist");
    }

    #[test]
    fn envelope_seeding_counts_entries() {
        let mut index = ContactIndex::new();
        let added = index.seed_from_envelope(&[
            ("Marie Dupont", "marie@example.invalid"),
            ("Support", "support@example.invalid"),
            ("", ""),
        ]);
        assert_eq!(added, 2);
        assert_eq!(index.len(), 2);
    }
}
