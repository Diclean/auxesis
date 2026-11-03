//! Deterministic screen over the arguments a tool sends off the machine.
//!
//! An MCP call hands its arguments to a third-party server. Before such a call
//! runs, the engine asks [`identifier_in_arguments`]: a high-confidence
//! identifier in the arguments forces an approval whatever the allow rule says.
//! The screen runs the `kernel-privacy` registry (its public API, thresholds
//! included) over these views of the arguments:
//!
//! * the reconstructed view: every string and number value in document order,
//!   joined by [`VIEW_SEPARATOR`], so an identifier split over several fields is
//!   whole without two neighbouring values reading as one grouped number;
//! * the in-order view: every key and value in document order, joined the same
//!   way;
//! * the digits-and-letters view: each leaf that is mostly digits or shaped like
//!   an IBAN, reduced to its letters and digits and joined with no separator, so
//!   an IBAN or phone split across fields with unrelated text between them is
//!   whole again;
//! * every string, object key and number leaf, one leaf at a time. The
//!   serialized JSON is not scanned: a newline inside a JSON string serializes
//!   as the two characters `\n`, which would hide a wrapped value;
//! * the decoded views of each string leaf: percent-decoding, JSON `\uXXXX`
//!   escapes, and whole-leaf hex or base64 (standard or URL-safe). Each
//!   decoder runs up to two rounds deep, and a decoded view is kept only when
//!   it is valid UTF-8 (percent and JSON escapes are kept lossily, so the ASCII
//!   around a stray byte still scans).
//!
//! A leaf whose decoding stops while it still looks encoded forces the ask too: a
//! hex run, a base64 run that decodes to text, a percent-escape share above 20 %,
//! or a `\u` escape left over. A base64 run that decodes to bytes that are not
//! text is an opaque identifier, not hidden data, and does not force it. Neither
//! does a UUID, a git SHA, a SHA-256 or SHA-512 hex digest, a ULID, a Calendar
//! event ID or a Drive file ID. The
//! screen does not decode past its depth, so a third layer is caught by that rule
//! rather than read: at the depth cap, a leaf that any decoder would still change
//! asks, whatever its share of escapes (a lone `%40` left in an address).
//!
//! The views are bounded. A base64 or hex leaf whose decoded size would exceed
//! [`MAX_DECODED_PER_LEAF`], a call whose decoded views exceed
//! [`MAX_DECODED_PER_CALL`] in all, or a call whose leaves hold more than
//! [`MAX_SCREENED_TEXT`] bytes cannot be screened in full. Such a call forces the
//! ask as well: fail toward masking, never a truncated scan that passes.
//! Malformed encodings are ignored, never an error.
//!
//! A bare number, or an all-digit string, of 10 to 15 digits that opens with a
//! country code or a national trunk `0` is a phone candidate. The phone
//! recogniser rejects such a run without separators, so the screen asks. An epoch
//! timestamp (ten digits, or thirteen in milliseconds, opening with `1`) is not a
//! phone candidate: no national US number opens with `1`. A phone span made only
//! of epoch timestamps is not a hit either.
//!
//! Only the kind of identifier is returned, never the value, and no decoded
//! value is ever logged.

use std::sync::OnceLock;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use kernel_privacy::recognizers::iban::{valid_iban, valid_iban_unknown};
use kernel_privacy::{EntityKind, Registry, Span};
use serde_json::Value;

/// What the joined views put between two values. A phone run cannot cross it, so
/// a value ending in digits (a UUID) does not read as one grouped number with the
/// digits that open the next value (a ULID).
const VIEW_SEPARATOR: &str = " ; ";

/// The shortest leaf that may be a whole-leaf hex or base64 encoding.
const MIN_ENCODED_LEN: usize = 16;

/// The shortest base64 run, without padding, that still looks encoded.
const MIN_BASE64_RUN: usize = 24;

/// The shortest hex run that still looks encoded.
const MIN_HEX_RUN: usize = 32;

/// The least Shannon entropy, in bits per character, a base64 run needs to look
/// encoded.
const MIN_BASE64_ENTROPY: f64 = 4.0;

/// The fewest character classes (upper case, lower case, digits, `+/=-_`) a
/// base64 run needs to look encoded.
const MIN_BASE64_CLASSES: usize = 3;

/// The longest word of a snake_case or kebab-case key or label.
const MAX_DICTIONARY_WORD: usize = 12;

/// The largest share of percent escapes, in per cent, a text may carry once its
/// decoding has stopped.
const MAX_ESCAPE_PERCENT: usize = 20;

/// The largest decoded size of one encoded leaf the screen will read.
const MAX_DECODED_PER_LEAF: usize = 64 * 1024;

/// The largest total of decoded views one call may produce.
const MAX_DECODED_PER_CALL: usize = 1024 * 1024;

/// The largest total text, in bytes, of one call's leaves the screen will read.
const MAX_SCREENED_TEXT: usize = 256 * 1024;

/// How many decoding rounds stack: percent of percent, base64 of hex, and so on.
const MAX_DECODE_ROUNDS: usize = 2;

/// The plain-language label of a leaf the screen could not decode in full.
const UNSCREENED_LABEL: &str = "an encoded block too large to check";

/// The plain-language label of a leaf that still looks encoded once decoding
/// stopped.
const RESIDUE_LABEL: &str = "encoded content could not be fully checked";

/// The country calling codes of E.164, one, two or three digits each.
const COUNTRY_CODES: &str = "1 7 20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 \
    51 52 53 54 55 56 57 58 60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98 \
    211 212 213 216 218 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 \
    235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 \
    255 256 257 258 260 261 262 263 264 265 266 267 268 269 290 291 297 298 299 \
    350 351 352 353 354 355 356 357 358 359 370 371 372 373 374 375 376 377 378 \
    380 381 382 383 385 386 387 389 420 421 423 500 501 502 503 504 505 506 507 \
    508 509 590 591 592 593 594 595 596 597 598 599 670 672 673 674 675 676 677 \
    678 679 680 681 682 683 685 686 687 688 689 690 691 692 800 808 850 852 853 \
    855 856 880 881 882 883 886 888 960 961 962 963 964 965 966 967 968 970 971 \
    972 973 974 975 976 977 979 992 993 994 995 996 998";

/// A decoded view the screen could not produce within its caps.
struct Unscreened;

/// The plain-language label of the first identifier in `arguments`, or `None`.
///
/// IP addresses and URLs are not identifiers here: a fetch-style call carries a
/// URL on almost every run, so counting it would ask on routine calls.
pub fn identifier_in_arguments(arguments: &Value) -> Option<&'static str> {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    let registry = REGISTRY.get_or_init(Registry::new);
    let mut leaves = Vec::new();
    let mut values = Vec::new();
    collect_leaves(arguments, &mut leaves, &mut values);
    if leaves.iter().map(String::len).sum::<usize>() > MAX_SCREENED_TEXT {
        return Some(UNSCREENED_LABEL);
    }
    // The concatenated views go through the same screen as one more leaf, so
    // their own encoded forms are decoded too. Only a single leaf carries the
    // residue rule: a join of several fields is not a value that must decode
    // on its own.
    let reconstructed = values.join(VIEW_SEPARATOR);
    let in_order = leaves.join(VIEW_SEPARATOR);
    let digits = digits_and_letters(&leaves);
    let mut budget = MAX_DECODED_PER_CALL;
    // The digits view comes first: a split IBAN is named for what it is, not for a
    // grouped run the joined text happens to contain.
    let views = [digits.as_str(), reconstructed.as_str(), in_order.as_str()];
    let hit = views
        .into_iter()
        .find_map(|view| screen_text_and_views(registry, view, &mut budget, false))
        .or_else(|| phone_shaped_digits(&digits).then_some(label(EntityKind::Phone)));
    hit.or_else(|| {
        leaves.iter().find_map(|leaf| {
            phone_shaped_digits(leaf)
                .then_some(label(EntityKind::Phone))
                .or_else(|| screen_text_and_views(registry, leaf, &mut budget, true))
        })
    })
}

/// The label of the first hit in `text` or in one of its decoded views. A decode
/// that runs out of room asks. With `residue`, a decoding chain that stops while
/// its text still looks encoded asks too.
fn screen_text_and_views(
    registry: &Registry,
    text: &str,
    budget: &mut usize,
    residue: bool,
) -> Option<&'static str> {
    if let Some(label) = screen_text(registry, text) {
        return Some(label);
    }
    let mut views = Vec::new();
    let Ok(still_encoded) = collect_views(text, 0, budget, &mut views) else {
        return Some(UNSCREENED_LABEL);
    };
    views
        .iter()
        .find_map(|view| screen_text(registry, view))
        .or((residue && still_encoded).then_some(RESIDUE_LABEL))
}

/// The label of the first identifier in `text`, IP addresses and URLs aside, that
/// is not a false hit (see [`is_false_hit`]).
fn screen_text(registry: &Registry, text: &str) -> Option<&'static str> {
    let hits: Vec<Span> = registry
        .analyze(text)
        .into_iter()
        .filter(|span| !matches!(span.kind, EntityKind::IpV4 | EntityKind::Url))
        .filter(|span| !is_false_hit(text, span))
        .collect();
    // The e-mail layer reads a name off an address's local part, so a name hit
    // sits on top of the address: the address names the hit when both match.
    hits.iter()
        .find(|span| span.kind != EntityKind::Person)
        .or(hits.first())
        .map(|span| label(span.kind))
}

/// Whether a span is a false hit that an opaque identifier or an epoch timestamp
/// causes:
///
/// * epoch timestamps, alone or side by side, are never a phone;
/// * a phone inside one UUID, git SHA or SHA-256/512 digest token is not one: the
///   dashes of a UUID group its last twelve digits into a grouped number;
/// * an IBAN inside a Calendar event ID, Drive file ID, ULID, UUID, SHA or digest
///   token is not one unless its checksum holds: a random run carries a
///   two-letter, two-digit anchor that the shape-only fallback reads as an IBAN.
fn is_false_hit(text: &str, span: &Span) -> bool {
    let raw = &text[span.start..span.end];
    let token = enclosing_token(text, span.start, span.end);
    match span.kind {
        EntityKind::Phone => only_epoch_numbers(raw) || is_uuid_or_sha(token),
        EntityKind::Iban => is_opaque_token(token) && !(valid_iban(raw) || valid_iban_unknown(raw)),
        _ => false,
    }
}

/// Whether `raw` is one or more whitespace-separated epoch timestamps.
fn only_epoch_numbers(raw: &str) -> bool {
    raw.split_whitespace().next().is_some() && raw.split_whitespace().all(is_epoch_shaped)
}

/// Whether `token` has the shape of an opaque identifier: a UUID, a git SHA, a
/// ULID, a Calendar event ID or a Drive file ID.
fn is_opaque_token(token: &str) -> bool {
    is_uuid_or_sha(token)
        || is_calendar_event_id(token)
        || is_ulid(token)
        || is_drive_file_id(token)
}

/// The whitespace- or `;`-delimited token of `text` that holds `start..end`.
fn enclosing_token(text: &str, start: usize, end: usize) -> &str {
    let is_break = |ch: char| ch.is_whitespace() || ch == ';';
    let begin = text[..start]
        .char_indices()
        .rev()
        .find(|(_, ch)| is_break(*ch))
        .map_or(0, |(at, ch)| at + ch.len_utf8());
    let finish = text[end..]
        .char_indices()
        .find(|(_, ch)| is_break(*ch))
        .map_or(text.len(), |(at, _)| end + at);
    &text[begin..finish]
}

/// Whether `token` is a UUID, a git SHA-1 or a SHA-256/SHA-512 hex digest:
/// fixed-shape identifiers whose digits are never a phone, and whose random hex
/// reads as an IBAN shape by chance.
fn is_uuid_or_sha(token: &str) -> bool {
    is_uuid_shape(token) || is_git_sha(token) || is_hash_hex(token)
}

/// Push every decoded view of `text` and of those views, up to
/// [`MAX_DECODE_ROUNDS`] rounds deep, charging each view's bytes to `budget`.
///
/// Returns whether the end of a decoding chain still looks encoded: a view at the
/// depth cap that looks encoded or that a decoder would still change (fail
/// closed: the layer the cap leaves is never read), or one that nothing decodes
/// any further and that looks encoded.
fn collect_views(
    text: &str,
    round: usize,
    budget: &mut usize,
    views: &mut Vec<String>,
) -> Result<bool, Unscreened> {
    if round == MAX_DECODE_ROUNDS {
        return Ok(looks_encoded(text) || !decode_once(text)?.is_empty());
    }
    let decoded = decode_once(text)?;
    if decoded.is_empty() {
        return Ok(looks_encoded(text));
    }
    let mut still_encoded = false;
    for view in decoded {
        *budget = budget.checked_sub(view.len()).ok_or(Unscreened)?;
        still_encoded |= collect_views(&view, round + 1, budget, views)?;
        views.push(view);
    }
    Ok(still_encoded)
}

/// The views `text` decodes to in one round: each decoder that changes it.
fn decode_once(text: &str) -> Result<Vec<String>, Unscreened> {
    let mut views = Vec::new();
    if text.contains('%') {
        views.push(percent_decode(text));
    }
    if text.contains("\\u") {
        views.push(json_unicode(text));
    }
    views.extend(whole_leaf_views(text)?);
    views.retain(|view| view != text);
    Ok(views)
}

/// The UTF-8 text `text` reads as when the whole leaf is hex or base64.
///
/// A leaf whose shape fits but whose decoded size is over
/// [`MAX_DECODED_PER_LEAF`] is `Err`: its bytes cannot be read in full. A
/// malformed encoding yields nothing.
fn whole_leaf_views(text: &str) -> Result<Vec<String>, Unscreened> {
    let mut views = Vec::new();
    if text.len() < MIN_ENCODED_LEN {
        return Ok(views);
    }
    let bytes = text.as_bytes();
    if bytes.len().is_multiple_of(2) && bytes.iter().all(u8::is_ascii_hexdigit) {
        if bytes.len() / 2 > MAX_DECODED_PER_LEAF {
            return Err(Unscreened);
        }
        if let Some(view) = hex_decode(bytes).and_then(utf8) {
            views.push(view);
        }
    }
    let body = text.trim_end_matches('=');
    if body.len() % 4 != 1 && body.bytes().all(is_base64_byte) {
        if body.len() * 3 / 4 > MAX_DECODED_PER_LEAF {
            return Err(Unscreened);
        }
        if let Some(view) = decode_base64(body).and_then(utf8) {
            views.push(view);
        }
    }
    Ok(views)
}

/// The bytes of an unpadded base64 run. The alphabet is picked by the characters
/// present; the other one fails to decode, so a mixed run is ignored rather than
/// guessed.
fn decode_base64(body: &str) -> Option<Vec<u8>> {
    if body.contains(['-', '_']) {
        URL_SAFE_NO_PAD.decode(body).ok()
    } else {
        STANDARD_NO_PAD.decode(body).ok()
    }
}

/// Whether an unpadded base64 run decodes to plain text.
fn decodes_to_text(body: &str) -> bool {
    decode_base64(body).is_some_and(|bytes| is_text(&bytes))
}

/// Whether `bytes` read as plain text: valid UTF-8 with no control character other
/// than whitespace.
fn is_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars()
            .all(|ch| !ch.is_control() || ch.is_whitespace())
    })
}

/// Whether a byte belongs to either base64 alphabet.
fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

/// The bytes of an even-length hex string, or `None` on any other byte.
fn hex_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Some((hex_value(pair[0])? << 4) | hex_value(pair[1])?))
        .collect()
}

/// The value of one hex digit.
fn hex_value(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

/// The text of `bytes` when they are valid UTF-8.
fn utf8(bytes: Vec<u8>) -> Option<String> {
    String::from_utf8(bytes).ok()
}

/// `%XX` escapes decoded. A malformed escape is kept as written.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = bytes
            .get(index + 1..index + 3)
            .filter(|_| byte == b'%')
            .and_then(hex_pair);
        match escaped {
            Some(value) => {
                decoded.push(value);
                index += 3;
            }
            None => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// The byte of two hex digits.
fn hex_pair(pair: &[u8]) -> Option<u8> {
    match pair {
        [high, low] => Some((hex_value(*high)? << 4) | hex_value(*low)?),
        _ => None,
    }
}

/// `\uXXXX` escapes decoded, a surrogate pair combined. A lone surrogate becomes
/// U+FFFD, and a malformed escape is kept as written.
fn json_unicode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("\\u") {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(unit) = unicode_escape(rest) else {
            out.push_str("\\u");
            rest = &rest[2..];
            continue;
        };
        rest = &rest[6..];
        let code = match unit {
            0xD800..=0xDBFF => match unicode_escape(rest) {
                Some(low @ 0xDC00..=0xDFFF) => {
                    rest = &rest[6..];
                    0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                }
                _ => 0xFFFD,
            },
            0xDC00..=0xDFFF => 0xFFFD,
            other => other,
        };
        out.push(char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    out.push_str(rest);
    out
}

/// The code unit of a `\uXXXX` escape at the start of `text`.
fn unicode_escape(text: &str) -> Option<u32> {
    let digits = text.strip_prefix("\\u")?.as_bytes().get(..4)?;
    digits.iter().try_fold(0u32, |code, &byte| {
        Some((code << 4) | u32::from(hex_value(byte)?))
    })
}

/// Whether `text`, with decoding stopped, still reads as encoded: a `\u` escape
/// left over, a percent-escape share above [`MAX_ESCAPE_PERCENT`], or a
/// whitespace-separated token that is a hex or base64 run.
fn looks_encoded(text: &str) -> bool {
    text.contains("\\u")
        || percent_escapes_over_limit(text)
        || text.split_whitespace().any(looks_encoded_token)
}

/// Whether the valid `%XX` escapes of `text` take up more than
/// [`MAX_ESCAPE_PERCENT`] per cent of its bytes.
fn percent_escapes_over_limit(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut escaped = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && bytes.get(index + 1..index + 3).and_then(hex_pair).is_some() {
            escaped += 3;
            index += 3;
        } else {
            index += 1;
        }
    }
    escaped * 100 > text.len() * MAX_ESCAPE_PERCENT
}

/// Whether one whitespace-separated token is a hex run of at least
/// [`MIN_HEX_RUN`] digits, or a base64 run that looks encoded and decodes to text.
/// Opaque identifier shapes are never encoded data: a UUID, a git SHA and a bare
/// SHA-256 or SHA-512 hex digest are exempt, a ULID or a Calendar event ID is
/// exempt by shape, and a Drive file ID is exempt unless its base64 decoding is
/// text.
fn looks_encoded_token(token: &str) -> bool {
    if is_uuid_or_sha(token) {
        return false;
    }
    let body = token.trim_end_matches('=');
    let padding = token.len() - body.len();
    if token.len() >= MIN_HEX_RUN && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return true;
    }
    if is_calendar_event_id(token) || is_ulid(token) || is_drive_file_id(token) {
        return false;
    }
    let mixes_alphabets = body.bytes().any(|byte| matches!(byte, b'+' | b'/'))
        && body.bytes().any(|byte| matches!(byte, b'-' | b'_'));
    let base64 = body.len() >= MIN_BASE64_RUN
        && padding <= 2
        && (padding == 0 || token.len().is_multiple_of(4))
        && body.len() % 4 != 1
        && !mixes_alphabets
        && body.bytes().all(is_base64_byte)
        && character_classes(token) >= MIN_BASE64_CLASSES
        && shannon_entropy(token) >= MIN_BASE64_ENTROPY
        && !dictionary_like(token);
    base64 && decodes_to_text(body)
}

/// Whether `token` is a git SHA-1: forty hex digits.
fn is_git_sha(token: &str) -> bool {
    token.len() == 40 && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `token` is a bare SHA-256 or SHA-512 digest: 64 or 128 hex digits. It
/// is an opaque ID like a git SHA, so [`is_false_hit`] drops its shape-only
/// IBAN and phone reads; a checksum-valid IBAN inside it still counts.
fn is_hash_hex(token: &str) -> bool {
    matches!(token.len(), 64 | 128) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `token` is a Google Calendar event ID: base32hex, lowercase, at least
/// 26 characters, no padding. A run of only digits and `a`-`f` is hex and stays
/// with the hex rule, so it needs a letter from `g` to `v`.
fn is_calendar_event_id(token: &str) -> bool {
    token.len() >= 26
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'v').contains(&byte))
        && token.bytes().any(|byte| (b'g'..=b'v').contains(&byte))
}

/// Whether `token` is a ULID: 26 characters of Crockford base32 in capitals, which
/// never use `I`, `L`, `O` or `U`.
fn is_ulid(token: &str) -> bool {
    token.len() == 26
        && token.bytes().all(|byte| {
            byte.is_ascii_digit()
                || (byte.is_ascii_uppercase() && !matches!(byte, b'I' | b'L' | b'O' | b'U'))
        })
}

/// Whether `token` is a Google Drive file ID: 25 to 44 characters of the base64url
/// alphabet that do not decode to text. Such a run is an opaque ID, not hidden
/// data.
fn is_drive_file_id(token: &str) -> bool {
    (25..=44).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && !decodes_to_text(token)
}

/// How many of the four character classes `token` uses: upper case, lower case,
/// digits, and `+/=-_`.
fn character_classes(token: &str) -> usize {
    [
        token.bytes().any(|byte| byte.is_ascii_uppercase()),
        token.bytes().any(|byte| byte.is_ascii_lowercase()),
        token.bytes().any(|byte| byte.is_ascii_digit()),
        token
            .bytes()
            .any(|byte| matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')),
    ]
    .into_iter()
    .filter(|&present| present)
    .count()
}

/// The Shannon entropy of `text`, in bits per byte.
fn shannon_entropy(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for byte in text.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let total = text.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

/// Whether `token` is dictionary-like words joined by `_` or `-`: every part is
/// alphabetic and at most [`MAX_DICTIONARY_WORD`] characters. Such a run is a
/// snake_case or kebab-case key or label, not encoded data.
fn dictionary_like(token: &str) -> bool {
    token.contains(['_', '-'])
        && token.split(['_', '-']).all(|part| {
            part.len() <= MAX_DICTIONARY_WORD && part.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
}

/// Whether `token` has the shape of a UUID: 36 characters with dashes, or the 32
/// hex digits of one written without dashes.
fn is_uuid_shape(token: &str) -> bool {
    let bytes = token.as_bytes();
    match bytes.len() {
        32 => bytes.iter().all(u8::is_ascii_hexdigit),
        36 => bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        }),
        _ => false,
    }
}

/// The digits-and-letters view: each leaf that is mostly digits or shaped like
/// an IBAN, reduced to its ASCII letters and digits and joined with no
/// separator. Every other leaf is skipped, so unrelated text between the fields
/// of a split identifier does not break it.
///
/// A whole opaque ID (a UUID, a git SHA or a SHA-256/512 digest) is left out: it
/// is not a piece of a split identifier, and its hex letters would glue to a
/// neighbour's digits into a false IBAN shape.
///
/// Known residual, kept on purpose: the join has no separator, so an epoch next
/// to a small number (`ts: 1700000000` beside `n: 12`) reads as the 12-digit run
/// `170000000012`, which opens with `1` and is a phone candidate. The epoch rule
/// only sees a whole leaf, and a false ask is the cheaper error here.
fn digits_and_letters(leaves: &[String]) -> String {
    leaves
        .iter()
        .filter(|leaf| !is_uuid_or_sha(leaf))
        .filter(|leaf| mostly_digits(leaf) || iban_shaped(leaf))
        .flat_map(|leaf| leaf.chars().filter(char::is_ascii_alphanumeric))
        .collect()
}

/// Whether a leaf holds more digits than other non-space characters.
fn mostly_digits(leaf: &str) -> bool {
    let (digits, others) = leaf.chars().filter(|ch| !ch.is_whitespace()).fold(
        (0usize, 0usize),
        |(digits, others), ch| {
            if ch.is_ascii_digit() {
                (digits + 1, others)
            } else {
                (digits, others + 1)
            }
        },
    );
    digits > 0 && digits > others
}

/// Whether a leaf is shaped like the opening of an IBAN: two letters, then two
/// check digits. A two-letter leaf on its own, a split country code, counts too.
fn iban_shaped(leaf: &str) -> bool {
    let bytes = leaf.as_bytes();
    if !(2..=34).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    match bytes {
        [country, code] => country.is_ascii_alphabetic() && code.is_ascii_alphabetic(),
        [country, code, check, digit, ..] => {
            country.is_ascii_alphabetic()
                && code.is_ascii_alphabetic()
                && check.is_ascii_digit()
                && digit.is_ascii_digit()
        }
        _ => false,
    }
}

/// Whether an all-digit text is shaped like a phone number: 10 to 15 digits that
/// open with a country code, or a national trunk `0` followed by 9 or 10 digits.
/// An epoch timestamp is never one.
fn phone_shaped_digits(text: &str) -> bool {
    let len = text.len();
    if !(10..=15).contains(&len) || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if is_epoch_shaped(text) {
        return false;
    }
    (text.starts_with('0') && len <= 11) || starts_with_country_code(text)
}

/// Whether `text` is an epoch timestamp: all digits, ten long in seconds or
/// thirteen in milliseconds, opening with `1`. No national US number opens with
/// `1`, so such a value is not a phone.
fn is_epoch_shaped(text: &str) -> bool {
    matches!(text.len(), 10 | 13)
        && text.starts_with('1')
        && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `digits` opens with a calling code from [`COUNTRY_CODES`].
fn starts_with_country_code(digits: &str) -> bool {
    (1..=3).any(|len| {
        digits
            .get(..len)
            .is_some_and(|prefix| COUNTRY_CODES.split_whitespace().any(|code| code == prefix))
    })
}

/// Plain-language label for a kind. Never the value.
fn label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Email => "an e-mail address",
        EntityKind::Phone => "a phone number",
        EntityKind::Iban => "an IBAN",
        EntityKind::CreditCard => "a payment card number",
        _ => "a national identifier",
    }
}

/// Every string, object key and number in `value` as text, in document order.
/// `leaves` gets all of them; `values` gets only the string and number values,
/// which the reconstructed view joins.
fn collect_leaves(value: &Value, leaves: &mut Vec<String>, values: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            leaves.push(text.clone());
            values.push(text.clone());
        }
        Value::Number(number) => {
            leaves.push(number.to_string());
            values.push(number.to_string());
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_leaves(item, leaves, values)),
        Value::Object(map) => map.iter().for_each(|(key, item)| {
            leaves.push(key.clone());
            collect_leaves(item, leaves, values);
        }),
        Value::Null | Value::Bool(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;

    /// Lowercase hex of `text`, one byte at a time.
    fn hex(text: &str) -> String {
        text.bytes().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn a_fake_iban_in_a_nested_argument_is_found() {
        // FAKE: the checksum-valid specimen FR IBAN used across the tests.
        let arguments = json!({
            "query": "virement",
            "payee": { "memo": "FR76 3000 6000 0112 3456 7890 189" }
        });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn an_iban_wrapped_over_a_json_newline_is_found() {
        // The newline is a real character in the value; the screen scans the
        // value, not its `\n` escape.
        let arguments = json!({ "memo": "FR76 3000 6000 0112 3456\n7890 189" });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn ordinary_arguments_and_urls_are_not_identifiers() {
        let arguments = json!({
            "query": "weather in Paris",
            "limit": 5,
            "url": "https://example.com/page",
            "host": "10.0.0.5"
        });
        assert_eq!(identifier_in_arguments(&arguments), None);
    }

    #[test]
    fn a_percent_encoded_iban_is_found() {
        // FAKE: the specimen FR IBAN, every space percent-encoded.
        let arguments = json!({ "memo": "FR76%203000%206000%200112%203456%207890%20189" });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn a_twice_percent_encoded_iban_is_found() {
        // FAKE: the same specimen, its spaces encoded twice.
        let arguments =
            json!({ "memo": "FR76%25203000%25206000%25200112%25203456%25207890%2520189" });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn a_base64_encoded_email_is_found() {
        // FAKE: a fictional address, base64-encoded.
        let email = "jean.dupont@example.com";
        let arguments = json!({ "body": STANDARD.encode(email) });
        assert_eq!(
            identifier_in_arguments(&arguments),
            Some("an e-mail address")
        );
    }

    #[test]
    fn a_url_safe_base64_encoded_email_is_found() {
        // FAKE: the payload's standard base64 has a `/`, so its URL-safe form
        // carries a `_` and only the URL-safe decoder reads it back.
        let payload = "jean.dupont@example.com ???";
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        assert!(encoded.contains('_'), "{encoded}");
        let arguments = json!({ "body": encoded });
        assert_eq!(
            identifier_in_arguments(&arguments),
            Some("an e-mail address")
        );
    }

    #[test]
    fn a_hex_encoded_iban_is_found() {
        // FAKE: the specimen FR IBAN, hex-encoded.
        let arguments = json!({ "blob": hex("FR76 3000 6000 0112 3456 7890 189") });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn a_json_unicode_escaped_iban_is_found() {
        // FAKE: the specimen FR IBAN, its `F` carried as a literal JSON escape.
        let arguments = json!({ "memo": r"FR76 3000 6000 0112 3456 7890 189" });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn an_iban_split_over_two_fields_is_found() {
        // FAKE: the specimen FR IBAN, split over two sibling fields.
        let arguments = json!({ "a": "FR76 3000", "b": "6000 0112 3456 7890 189" });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn an_iban_split_across_nested_arrays_and_objects_is_found() {
        // FAKE: the specimen FR IBAN, split across two nested branches.
        let arguments = json!({
            "items": [
                { "p": "FR76 3000" },
                { "q": { "r": ["6000 0112 3456 7890 189"] } }
            ]
        });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn a_clean_encoded_call_is_still_allowed() {
        // Each encoded field on its own, so a hit names the field that trips it.
        for field in [
            STANDARD.encode("weather in Paris"),
            "weather%20in%20Paris".to_string(),
            hex("fox jumps"),
            r"weather in Paris".to_string(),
        ] {
            assert_eq!(identifier_in_arguments(&json!(field)), None, "{field}");
        }
        let arguments = json!({
            "query": STANDARD.encode("weather in Paris"),
            "memo": "weather%20in%20Paris",
            "blob": hex("fox jumps"),
            "page": r"weather in Paris"
        });
        assert_eq!(identifier_in_arguments(&arguments), None);
    }

    #[test]
    fn malformed_encodings_are_ignored() {
        let arguments = json!({
            "percent": "%zz%4",
            "padding": "================",
            "symbols": "@@@@@@@@@@@@@@@@@@@@",
            "bytes": "%E9%FF%C3",
            "base64": "ABCDEFGHIJKLMNOPQRS=",
            "hex": "zzzzzzzzzzzzzzzzzzzz"
        });
        assert_eq!(identifier_in_arguments(&arguments), None);
    }

    #[test]
    fn a_huge_base64_blob_stays_within_the_cap_and_asks() {
        // About 200 KB of text: its decoded size is over the per-leaf cap, so
        // the screen cannot read it in full and must ask, without decoding it.
        let blob = STANDARD.encode("weather ".repeat(25_000));
        assert_eq!(
            identifier_in_arguments(&json!({ "blob": blob })),
            Some(UNSCREENED_LABEL)
        );
    }

    #[test]
    fn a_clean_base64_blob_under_the_cap_is_allowed() {
        let blob = STANDARD.encode("weather in Paris ".repeat(1_000));
        assert_eq!(identifier_in_arguments(&json!({ "blob": blob })), None);
    }

    #[test]
    fn decoded_views_past_the_call_budget_ask() {
        // Twenty leaves of 80 KB of base64 each: over the text cap, so the call
        // asks before any decoding.
        let leaf = STANDARD.encode("a".repeat(60_000));
        let arguments = Value::Array(vec![json!(leaf); 20]);
        assert_eq!(identifier_in_arguments(&arguments), Some(UNSCREENED_LABEL));
    }

    #[test]
    fn nested_arrays_and_objects_are_walked() {
        // FAKE: the specimen FR IBAN buried in arrays and objects.
        let arguments = json!({
            "items": [ { "deep": { "list": ["FR76 3000 6000 0112 3456 7890 189"] } } ]
        });
        assert_eq!(identifier_in_arguments(&arguments), Some("an IBAN"));
    }

    #[test]
    fn a_triply_encoded_email_asks() {
        // FAKE: a fictional address, base64-encoded three times over.
        let email = "jean.dupont@example.com";
        let triple = STANDARD.encode(STANDARD.encode(STANDARD.encode(email)));
        assert_eq!(
            identifier_in_arguments(&json!({ "body": triple })),
            Some(RESIDUE_LABEL)
        );
    }

    #[test]
    fn a_triply_percent_encoded_text_asks_on_residue() {
        // Plain text, every space percent-encoded three times: no recogniser
        // fires, so the residue rule is what asks.
        let triple = "weather in Paris".replace(' ', "%252520");
        assert_eq!(
            identifier_in_arguments(&json!({ "memo": triple })),
            Some(RESIDUE_LABEL)
        );
    }

    #[test]
    fn a_triply_percent_encoded_iban_asks() {
        // FAKE: the specimen FR IBAN, every space percent-encoded three times.
        // Another hit may name it first; the call must still ask.
        let triple = "FR76 3000 6000 0112 3456 7890 189".replace(' ', "%252520");
        assert!(identifier_in_arguments(&json!({ "memo": triple })).is_some());
    }

    #[test]
    fn an_encoded_token_inside_a_sentence_asks() {
        // A base64 token inside a sentence is never decoded, so it asks.
        let arguments = json!({ "memo": "voici SGVsbG8gV29ybGQgdGhpcyBpcyBiYXNlNjQ= merci" });
        assert!(identifier_in_arguments(&arguments).is_some());
    }

    #[test]
    fn a_uuid_shape_is_never_a_residue() {
        assert!(!looks_encoded_token("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!looks_encoded_token("550e8400e29b41d4a716446655440000"));
        assert!(looks_encoded_token("550e8400e29b41d4a716446655440001ff"));
    }

    #[test]
    fn a_sha256_or_sha512_digest_is_never_a_residue() {
        // FAKE: a real SHA-256 digest (of the empty input), and a 128-digit run
        // of its doubled hex in the SHA-512 shape.
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sha512 = format!("{sha256}{sha256}");
        assert!(!looks_encoded_token(sha256));
        assert!(!looks_encoded_token(&sha512));
        // One digit past the shape is no digest: an ordinary hex run, so it asks.
        assert!(looks_encoded_token(&format!("{sha512}f")));
    }

    #[test]
    fn a_stray_json_unicode_escape_asks() {
        // The malformed escape is left as written after decoding, so it asks.
        let arguments = json!({ "escape": "\\uD83D\\u00" });
        assert_eq!(identifier_in_arguments(&arguments), Some(RESIDUE_LABEL));
    }

    #[test]
    fn ordinary_text_urls_uuids_and_short_hashes_do_not_ask() {
        // FAKE: a real SHA-256 digest (of the empty input) and its doubled hex.
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let sha512 = format!("{sha256}{sha256}");
        // Each value alone, collecting every hit.
        let mut asked = Vec::new();
        for value in [
            "weather in Paris",
            "https://example.com/docs/getting-started/installation-guide",
            "9f86d081884c7d65",
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400e29b41d4a716446655440000",
            sha256,
            sha512.as_str(),
        ] {
            if let Some(label) = identifier_in_arguments(&json!(value)) {
                asked.push(format!("{value}: {label}"));
            }
        }
        assert!(asked.is_empty(), "{asked:?}");
        let arguments = json!({
            "query": "weather in Paris",
            "url": "https://example.com/docs/getting-started/installation-guide",
            "hash": "9f86d081884c7d65",
            "digest": sha256,
            "limit": 5
        });
        assert_eq!(identifier_in_arguments(&arguments), None);
    }

    #[test]
    fn an_iban_split_across_three_fields_with_text_between_asks() {
        // FAKE: the specimen FR IBAN, split over three fields, a text field between.
        let arguments = json!({
            "a": "FR76 3000",
            "b": "Virement loyer",
            "c": "6000 0112 3456 7890 189"
        });
        // Another recogniser may name it first (grouped digits read as a phone);
        // the call must still ask.
        assert!(identifier_in_arguments(&arguments).is_some());
    }

    #[test]
    fn the_digits_view_joins_the_split_fields_and_skips_the_text() {
        // FAKE: the specimen FR IBAN, split with a text field between.
        let leaves = vec![
            "FR76 3000".to_string(),
            "Virement loyer".to_string(),
            "6000 0112 3456 7890 189".to_string(),
        ];
        assert_eq!(digits_and_letters(&leaves), "FR7630006000011234567890189");
    }

    #[test]
    fn a_phone_split_across_an_array_with_text_between_asks() {
        // FAKE: a phone number split over an array, a text item between its parts.
        let arguments = json!({ "numbers": ["33", "Bonjour", "612345678"] });
        assert!(identifier_in_arguments(&arguments).is_some());
    }

    #[test]
    fn bare_numbers_shaped_like_phones_ask() {
        // FAKE: phone shapes written as bare digits, none a real line.
        assert!(phone_shaped_digits("12025550142"));
        assert!(phone_shaped_digits("33612345678"));
        assert!(phone_shaped_digits("0612345678"));
        assert!(!phone_shaped_digits("2026"));
        assert!(!phone_shaped_digits("1234567"));
        for arguments in [
            json!(12025550142u64),
            json!("33612345678"),
            json!("0612345678"),
        ] {
            assert_eq!(
                identifier_in_arguments(&arguments),
                Some("a phone number"),
                "{arguments}"
            );
        }
    }

    #[test]
    fn years_and_short_ids_do_not_ask() {
        for arguments in [json!(2026), json!(1234567), json!({ "page": 2 })] {
            assert_eq!(identifier_in_arguments(&arguments), None, "{arguments}");
        }
    }

    #[test]
    fn a_call_over_the_text_cap_asks() {
        let arguments = json!({ "body": "weather in Paris ".repeat(20_000) });
        assert_eq!(identifier_in_arguments(&arguments), Some(UNSCREENED_LABEL));
    }

    #[test]
    fn opaque_identifiers_do_not_ask() {
        // FAKE: opaque IDs of each known shape. A Calendar event ID, a Drive file
        // ID (its base64 decoding is not text), a UUID, a ULID and a git SHA.
        let shapes = [
            "3pr8bd9ti1b2g0s6ch5o6r1s7k",
            "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms",
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400e29b41d4a716446655440000",
            "01HZX3K5M8T2W9YQ4N6P7R8S9V",
            "0a80bacac0aff8cdc04c4d3bc56378b7cacc5998",
        ];
        for value in shapes {
            assert_eq!(identifier_in_arguments(&json!(value)), None, "{value}");
        }
        // All of them in one call, a UUID directly followed by a ULID included.
        let arguments = json!({
            "eventId": shapes[0],
            "fileId": shapes[1],
            "requestId": shapes[2],
            "bareRequestId": shapes[3],
            "ulid": shapes[4],
            "commit": shapes[5],
            "keys": [shapes[2], shapes[4]],
            "shaKey": { "0a80bacac0aff8cdc04c4d3bc56378b7cacc5998": 1 }
        });
        assert_eq!(identifier_in_arguments(&arguments), None);
    }

    #[test]
    fn epoch_timestamps_do_not_ask() {
        for arguments in [
            json!({ "created_at": 1760000000 }),
            json!({ "created_at_ms": 1760000000000u64 }),
            json!({ "created_at": 1760000000, "created_at_ms": 1760000000000u64 }),
            json!(["1760000000", "1760000001"]),
            json!({ "since": "1760000000 1760000000000" }),
        ] {
            assert_eq!(identifier_in_arguments(&arguments), None, "{arguments}");
        }
    }

    #[test]
    fn long_snake_case_keys_do_not_ask() {
        let arguments = json!({
            "calendar_event_attendee_response_status": "accepted",
            "calendar_event_organizer_display_name_fallback": "Équipe produit",
            "max_results": 10
        });
        assert_eq!(identifier_in_arguments(&arguments), None);
        assert_eq!(
            identifier_in_arguments(&json!("calendar_event_attendee_response_status")),
            None
        );
    }

    #[test]
    fn near_misses_of_the_opaque_shapes_still_ask() {
        // Encoded text is still encoded, whatever its shape.
        let email = STANDARD.encode("jean.dupont@example.com");
        assert!(looks_encoded_token(&email));
        assert!(identifier_in_arguments(&json!({ "blob": email })).is_some());
        // A UUID is exempt as a whole token only: a phone glued to one still asks.
        assert_eq!(
            identifier_in_arguments(&json!("0612345678-550e8400-e29b-41d4-a716-446655440000")),
            Some("a phone number")
        );
        // A UK number split with a leading one: the epoch rule covers one value,
        // not the join of two.
        assert_eq!(
            identifier_in_arguments(&json!({ "numbers": ["44", "1234567890"] })),
            Some("a phone number")
        );
        // A US national number opens with 2, never 1, and stays a phone.
        assert_eq!(
            identifier_in_arguments(&json!("2125550142")),
            Some("a phone number")
        );
        // A valid IBAN is never a false hit, bare or glued to a letter, even though
        // its token has the shape of a Drive file ID.
        // FAKE: the checksum-valid specimen FR IBAN, compact.
        assert_eq!(
            identifier_in_arguments(&json!("FR7630006000011234567890189")),
            Some("an IBAN")
        );
        assert!(identifier_in_arguments(&json!("xFR7630006000011234567890189")).is_some());
    }

    /// `text` percent-encoded `layers` times: every byte but a letter or a digit
    /// in the first layer, so each later layer escapes only the `%` signs.
    fn percent_layers(text: &str, layers: usize) -> String {
        (0..layers).fold(text.to_string(), |text, _| {
            text.bytes()
                .map(|byte| match byte {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => char::from(byte).to_string(),
                    _ => format!("%{byte:02X}"),
                })
                .collect()
        })
    }

    #[test]
    fn a_triply_encoded_at_sign_under_the_escape_share_asks() {
        // FAKE: a fictional address, its `@` percent-encoded three times. After
        // the two rounds the screen reads, one `%40` is left: 3 of 20 bytes.
        let arguments = json!({ "memo": "q7f3k9%252540example.com" });
        assert_eq!(identifier_in_arguments(&arguments), Some(RESIDUE_LABEL));
    }

    #[test]
    fn deeply_encoded_emails_and_phones_ask() {
        // FAKE: a fictional address and a fictional French mobile number.
        for layers in [4, 6] {
            for value in [
                percent_layers("q7f3k9@example.com", layers),
                percent_layers("+33 6 12 34 56 78", layers),
                format!("{}33612345678", percent_layers("+", layers)),
                format!("q7f3k9{}example.com", percent_layers("@", layers)),
            ] {
                assert!(
                    identifier_in_arguments(&json!({ "memo": value })).is_some(),
                    "{layers} layers: {value}"
                );
            }
        }
    }

    #[test]
    fn a_short_hex_layer_left_at_the_cap_asks() {
        // FAKE: a fictional address, hex-encoded three times. The layer left at
        // the cap is 18 hex digits: shorter than a hex run, but it still decodes.
        let triple = hex(&hex(&hex("q7@ex.com")));
        assert_eq!(
            identifier_in_arguments(&json!({ "blob": triple })),
            Some(RESIDUE_LABEL)
        );
    }

    #[test]
    fn plain_urls_with_ordinary_escapes_still_pass() {
        for url in [
            "https://example.com/search?q=weather%20in%20Paris",
            "https://example.com/search?q=weather%2520in%2520Paris",
            "https://example.com/a%2Fb?city=Saint-%C3%89tienne&n=5",
        ] {
            assert_eq!(
                identifier_in_arguments(&json!({ "url": url })),
                None,
                "{url}"
            );
        }
    }

    #[test]
    fn adversarial_encoded_values_finish_within_the_bar() {
        // A 1 MB value, and one just under the text cap, both nested escapes.
        let bar = std::time::Duration::from_secs(10);
        for value in [
            "%25".repeat(350_000),
            "q7f3k9%25252540example.com ".repeat(9_000),
        ] {
            let started = std::time::Instant::now();
            assert!(identifier_in_arguments(&json!({ "memo": value })).is_some());
            let elapsed = started.elapsed();
            assert!(elapsed < bar, "{} bytes took {elapsed:?}", value.len());
        }
    }
}
