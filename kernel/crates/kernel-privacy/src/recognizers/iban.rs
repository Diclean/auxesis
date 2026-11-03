//! IBAN recogniser: ISO 13616 mod-97 plus a per-country length table.

use std::collections::HashSet;

use crate::checksum::{iban_country_length, iban_mod97, iban_mod97_loose};
use crate::normalize::{consume_alnum, NormalizedText};
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Checksum-valid IBANs of a known country score 1.0 (Presidio's IBAN
/// pattern does the same).
pub const SCORE: f32 = 1.0;
/// An unknown country code with a valid mod-97 check and a plausible length
/// scores lower, but still clears the default threshold so it is masked.
pub const UNKNOWN_SCORE: f32 = 0.6;
/// A checksum-invalid but IBAN-shaped value is still masked, at a lower score
/// (fail toward masking, P2-8).
pub const SHAPE_SCORE: f32 = 0.55;

/// Finds valid IBANs, grouped or ungrouped.
#[derive(Clone, Copy, Debug, Default)]
pub struct IbanRecognizer;

impl IbanRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for IbanRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Iban]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let identity = |start: usize, end: usize| {
            (start < end && text.is_char_boundary(start) && text.is_char_boundary(end))
                .then_some((start, end))
        };
        self.analyze_with_source(text, text, &identity)
    }

    fn analyze_with_source(
        &self,
        text: &str,
        original: &str,
        source_bounds: &dyn Fn(usize, usize) -> Option<(usize, usize)>,
    ) -> Vec<Span> {
        // IBANs carry meaningful letters (country code, and letters inside some
        // BBANs), so the OCR confusable fold is off for this recogniser; the
        // Unicode-digit, separator and fullwidth-letter folds still apply.
        let normalized = NormalizedText::new(text, false);
        let ids = uuid_tokens(original);
        let skippable = |start, end| {
            normalized
                .to_original(start, end)
                .and_then(|(start, end)| source_bounds(start, end))
                .is_some_and(|(start, end)| inside_uuid(&ids, start, end))
        };
        let mut found = candidates(normalized.text(), &skippable);
        // Keep old guesses and find verified IBANs starting inside them.
        let mut extra = Vec::new();
        for &(start, end, _) in &found {
            for at in start + 1..end {
                if let Some((past, score)) = known_match_at(normalized.text(), at) {
                    extra.push((at, past, score));
                }
            }
        }
        let mut seen: HashSet<_> = found.iter().map(|&(start, end, _)| (start, end)).collect();
        extra.extend(spaced_anchor_candidates(normalized.text()));
        extra.extend(context_shapes(normalized.text(), &skippable));
        extra.retain(|&(start, end, _)| !skippable(start, end));
        for candidate in column_gap_candidates(normalized.text())
            .into_iter()
            .chain(extra)
        {
            if seen.insert((candidate.0, candidate.1)) {
                found.push(candidate);
            }
        }
        found
            .into_iter()
            .filter_map(|(start, end, score)| {
                normalized
                    .to_original(start, end)
                    .map(|(start, end)| Span::new(EntityKind::Iban, start, end, score, "iban"))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "iban"
    }
}

/// A line or group break may also fall inside the country/check-digit prefix.
fn spaced_anchor_candidates(text: &str) -> Vec<(usize, usize, f32)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for start in 0..bytes.len() {
        if !bytes[start].is_ascii_alphabetic() {
            continue;
        }
        let ambiguous = start > 0
            && bytes[start - 1].is_ascii_alphabetic()
            && bytes.get(start + 1).is_some_and(u8::is_ascii_alphabetic)
            && !(bytes[start - 1].is_ascii_lowercase() && bytes[start].is_ascii_uppercase())
            && !bank_cue(&bytes[start.saturating_sub(64)..start])
            && !bytes[start.saturating_sub(3)..start].eq_ignore_ascii_case(b"ref")
            && !bytes[start.saturating_sub(4)..start].eq_ignore_ascii_case(b"code");
        let prefix_end = consume_alnum(text, start, 4);
        if prefix_end <= start + 4 {
            continue;
        }
        let mut prefix = bytes[start..prefix_end]
            .iter()
            .copied()
            .filter(u8::is_ascii_alphanumeric);
        let (Some(a), Some(b), Some(c), Some(d)) =
            (prefix.next(), prefix.next(), prefix.next(), prefix.next())
        else {
            continue;
        };
        if !a.is_ascii_alphabetic()
            || !b.is_ascii_alphabetic()
            || !c.is_ascii_digit()
            || !d.is_ascii_digit()
        {
            continue;
        }
        let code = [a, b];
        let Ok(code) = std::str::from_utf8(&code) else {
            continue;
        };
        let Some(expected) = iban_country_length(code) else {
            continue;
        };
        let end = consume_alnum(text, start, expected);
        if valid_iban(&text[start..end])
            && (!ambiguous || !bytes.get(end).is_some_and(u8::is_ascii_alphanumeric))
        {
            out.push((start, end, SCORE));
        }
    }
    out
}

/// Only registered-country, checksum-valid matches are added inside a guess.
fn known_match_at(text: &str, start: usize) -> Option<(usize, f32)> {
    let bytes = text.as_bytes();
    if start + 4 > bytes.len()
        || !bytes[start..start + 2].iter().all(u8::is_ascii_alphabetic)
        || !bytes[start + 2..start + 4].iter().all(u8::is_ascii_digit)
        || iban_country_length(&text[start..start + 2]).is_none()
    {
        return None;
    }
    match_at(text, start).filter(|&(end, _)| valid_iban(&text[start..end]))
}

/// A known-country shape of at least 11 characters behind an IBAN or bank cue
/// is sensitive even when its check digits fail or the value is incomplete.
/// The lookback and the value are bounded, including on a long input.
fn context_shapes(
    text: &str,
    skippable: &dyn Fn(usize, usize) -> bool,
) -> Vec<(usize, usize, f32)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for start in 0..bytes.len().saturating_sub(3) {
        if !bytes[start..start + 2].iter().all(u8::is_ascii_alphabetic)
            || !bytes[start + 2..start + 4].iter().all(u8::is_ascii_digit)
        {
            continue;
        }
        let Some(expected) = iban_country_length(&text[start..start + 2]) else {
            continue;
        };
        if !bank_cue(&bytes[start.saturating_sub(64)..start]) {
            continue;
        }
        let (mut end, mut count, mut group) = (start, 0, 0);
        while end < bytes.len() && count < expected {
            if bytes[end].is_ascii_alphanumeric() {
                count += 1;
                group += 1;
                end += 1;
            } else if matches!(bytes[end], b' ' | b'-') && group == 4 {
                let next = &bytes[end + 1..];
                let len = next
                    .iter()
                    .take(5)
                    .take_while(|b| b.is_ascii_alphanumeric())
                    .count();
                if len == 0 || len > 4 {
                    break;
                }
                group = 0;
                end += 1;
            } else {
                break;
            }
        }
        if count >= 11 && !skippable(start, end) {
            out.push((start, end, SHAPE_SCORE));
        }
    }
    out
}

fn bank_cue(before: &[u8]) -> bool {
    // One pass over the bytes: the first letter picks the one cue that can
    // start here, so each byte is read once instead of once per cue. A cue is
    // a whole word: no ASCII alphanumeric directly before or after it.
    for (at, &byte) in before.iter().enumerate() {
        let cue: &[u8] = match byte.to_ascii_lowercase() {
            b'i' => b"iban",
            b'b' => b"bank",
            b'a' => b"account",
            b'c' => b"compte",
            b'r' => b"rib",
            _ => continue,
        };
        let end = at + cue.len();
        if (at == 0 || !before[at - 1].is_ascii_alphanumeric())
            && end <= before.len()
            && before[at..end].eq_ignore_ascii_case(cue)
            && (end == before.len() || !before[end].is_ascii_alphanumeric())
        {
            return true;
        }
    }
    false
}

/// Scan for `LLdd…` anchors: a known country consumes exactly its registered
/// length; an unknown one is accepted when a plausible prefix (15–34 chars)
/// passes mod-97, or masked lower when only the IBAN shape matches. A guess
/// inside a UUID-shaped candidate is skipped only when `skippable` confirms its
/// mapped range lies inside an original-text UUID token.
fn candidates(text: &str, skippable: &dyn Fn(usize, usize) -> bool) -> Vec<(usize, usize, f32)> {
    let mut found = Vec::new();
    let (ids, mut next) = (uuid_tokens(text), 0);
    let mut index = 0;
    while index + 4 <= text.len() {
        let Some((end, score)) = match_at(text, index) else {
            index += 1;
            continue;
        };
        let start = index;
        index = end.max(start + 1);
        match id_end(&ids, &mut next, start) {
            // A guess wholly inside a source-confirmed UUID is a piece of the
            // id: drop it, then read anchors that may run past the token again.
            Some(id_end) if end <= id_end && score < SCORE && skippable(start, end) => found
                .extend((start + 1..end).filter_map(|at| {
                    match_at(text, at)
                        .filter(|&(past, _)| past > id_end)
                        .map(|(past, score)| (at, past, score))
                })),
            _ => found.push((start, end, score)),
        }
    }
    found
}

/// The IBAN that starts at `start`, if any: its end and its score.
fn match_at(text: &str, start: usize) -> Option<(usize, f32)> {
    let bytes = text.as_bytes();
    if start + 4 > bytes.len() {
        return None;
    }
    let anchor = bytes[start].is_ascii_alphabetic()
        && bytes[start + 1].is_ascii_alphabetic()
        && bytes[start + 2].is_ascii_digit()
        && bytes[start + 3].is_ascii_digit();
    if !anchor {
        return None;
    }
    match iban_country_length(&text[start..start + 2]) {
        Some(expected) => {
            let end = consume_alnum(text, start, expected);
            (count_alnum(&text[start..end]) == expected
                && (valid_iban(&text[start..end]) || valid_iban_ocr(&text[start..end])))
            .then_some((end, SCORE))
        }
        None => unknown_country_candidate(text, start)
            .map(|(end, valid)| (end, if valid { UNKNOWN_SCORE } else { SHAPE_SCORE })),
    }
}

/// IBANs of a known country whose groups a PDF table split with a column gap
/// (`BE68 5390   0754 7034`): up to 24 spaces between groups, exact country
/// length and a valid mod-97 only (K-BANK-STATEMENT-1).
fn column_gap_candidates(text: &str) -> Vec<(usize, usize, f32)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for start in 0..text.len().saturating_sub(3) {
        let anchor = bytes[start..start + 2].iter().all(u8::is_ascii_alphabetic)
            && bytes[start + 2..start + 4].iter().all(u8::is_ascii_digit)
            && (start == 0 || !bytes[start - 1].is_ascii_alphanumeric());
        let Some(expected) = anchor
            .then(|| iban_country_length(&text[start..start + 2]))
            .flatten()
        else {
            continue;
        };
        let (mut end, mut count) = (start, 0);
        while count < expected {
            let gap = bytes[end..]
                .iter()
                .take(25)
                .take_while(|&&b| b == b' ' || b == b'-')
                .count();
            if (count > 0 && gap > 24)
                || !bytes.get(end + gap).is_some_and(u8::is_ascii_alphanumeric)
            {
                break;
            }
            end += gap + 1;
            count += 1;
        }
        let tail_free = !bytes.get(end).is_some_and(u8::is_ascii_alphanumeric);
        if count == expected && tail_free && valid_iban(&text[start..end]) {
            found.push((start, end, SCORE));
        }
    }
    found
}

/// The whole UUID tokens of `text` in order: `8-4-4-4-12` hex digits, either
/// case, nothing alphanumeric glued on either side (IBAN-UUID-OVERMASK). A
/// guess wholly inside one (unknown country, or shape only) is a piece of an id
/// (`sandbox-<uuid>`, EventKit `<uuid>:<uuid>`); a checksum-valid IBAN of a
/// registered country is masked in any shape. Each start is tried once
/// against 36 bytes.
pub fn uuid_tokens(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    // Fail closed: a non-ASCII neighbour (a UTF-8 letter byte) is never a
    // delimiter, so the run is not a whole id and stays scanned as on main.
    let free = |byte: Option<&u8>| byte.is_none_or(|b| b.is_ascii() && !b.is_ascii_alphanumeric());
    let (mut found, mut start) = (Vec::new(), 0);
    while start + 36 <= bytes.len() {
        let whole = (start == 0 || free(bytes.get(start - 1)))
            && free(bytes.get(start + 36))
            && (bytes[start..start + 36].iter().enumerate()).all(|(at, byte)| match at {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            });
        if whole {
            found.push((start, start + 36));
        }
        start += if whole { 36 } else { 1 };
    }
    found
}

/// The end of the token of `ids` that holds byte `at`. `next` is a cursor, so
/// `at` must never go back.
fn id_end(ids: &[(usize, usize)], next: &mut usize, at: usize) -> Option<usize> {
    while ids.get(*next).is_some_and(|&(_, end)| end <= at) {
        *next += 1;
    }
    ids.get(*next)
        .filter(|&&(start, _)| start <= at)
        .map(|&(_, end)| end)
}

/// Whether a byte range lies wholly inside one of the sorted, non-overlapping
/// UUID tokens returned by `uuid_tokens`.
fn inside_uuid(ids: &[(usize, usize)], start: usize, end: usize) -> bool {
    let index = ids.partition_point(|&(_, uuid_end)| uuid_end <= start);
    ids.get(index)
        .is_some_and(|&(uuid_start, uuid_end)| uuid_start <= start && end <= uuid_end)
}

fn count_alnum(value: &str) -> usize {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .count()
}

/// Longest plausible prefix for an unknown country code, with a flag for
/// whether it passed mod-97.
///
/// Every alphanumeric group up to the ISO 13616 maximum of 34 is considered, so
/// a letter group inside the account (`ZZ85 ABCD …`) is never left in clear and
/// the leading country code is part of the span. A valid mod-97 prefix wins; if
/// none is valid but the value still has the `LLdd` + 11–30 alphanumeric IBAN
/// shape, it is returned as a shape-only match (P2-8). The check is computed
/// without building a `String` per length (P3-5).
fn unknown_country_candidate(text: &str, start: usize) -> Option<(usize, bool)> {
    if !text.as_bytes()[start..start + 2]
        .iter()
        .all(u8::is_ascii_uppercase)
    {
        return None;
    }
    let text = &text[..unknown_bound(text, start)];
    let max_end = consume_alnum(text, start, 34);
    let total = count_alnum(&text[start..max_end]);
    if total < 11 {
        return None;
    }
    for length in (15..=total.min(34)).rev() {
        let end = consume_alnum(text, start, length);
        if count_alnum(&text[start..end]) != length {
            continue;
        }
        if valid_iban_unknown_loose(&text[start..end]) {
            return Some((end, true));
        }
    }
    let shape_len = total.min(30);
    if shape_len < 11 {
        return None;
    }
    let end = consume_alnum(text, start, shape_len);
    if !iban_shape_ok(&text[start..end]) {
        return None;
    }
    Some((end, false))
}

/// Where an unknown-country guess must stop (TOK-FP): before the first group
/// holding a lower-case letter, and at a `/` or `.`. An IBAN is printed in
/// upper case with spaces or hyphens; a path or a sentence is not, and the
/// guess must never run into it (a temp dir `…xm0000gn/T/tmp…` was masked with
/// the words after it). A last group of letters only is a word after it
/// (`ZZ84 ABCD 123 OK`), not an account group.
fn unknown_bound(text: &str, start: usize) -> usize {
    let max_end = consume_alnum(text, start, 34);
    let mut kept = start;
    let mut bound = max_end;
    for (at, byte) in text.bytes().enumerate().take(max_end).skip(start) {
        match byte {
            b'a'..=b'z' => {
                bound = kept;
                break;
            }
            b'/' | b'.' => {
                bound = at;
                break;
            }
            b' ' | b'-' => kept = at,
            _ => {}
        }
    }
    while let Some(at) = text[start..bound].rfind([' ', '-']) {
        let last = &text[start + at + 1..bound];
        if !last.bytes().all(|b| b.is_ascii_uppercase()) {
            break;
        }
        bound = start + at;
    }
    bound
}

/// Whether a raw candidate starts with `LLdd` and holds 11–30 alphanumerics.
///
/// The anchor guarantees the `LLdd` prefix; this only bounds the length.
fn iban_shape_ok(raw: &str) -> bool {
    let length = count_alnum(raw);
    (11..=30).contains(&length)
}

/// Whether a raw candidate (spaces allowed) is a valid IBAN of a known country.
pub fn valid_iban(raw: &str) -> bool {
    let compact = compact(raw);
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    if !compact.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return false;
    }
    let code = &compact[0..2];
    let Some(expected) = iban_country_length(code) else {
        return false;
    };
    if compact.len() != expected {
        return false;
    }
    if !compact[2..4].chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    iban_mod97(&compact)
}

/// Whether a raw candidate is a valid IBAN once the letters an OCR engine swaps
/// for digits (`O` for 0, `I` and `l` for 1) are read back as digits after the
/// check digits. Only a corrected form that passes the country length and
/// mod-97 counts, so a real bank code with an `O` in it is left to
/// [`valid_iban`].
fn valid_iban_ocr(raw: &str) -> bool {
    let fixed: String = compact(raw)
        .chars()
        .enumerate()
        .map(|(index, ch)| match ch {
            'O' if index >= 4 => '0',
            'I' | 'L' if index >= 4 => '1',
            _ => ch,
        })
        .collect();
    valid_iban(&fixed)
}

/// Whether a raw candidate is a plausible IBAN for an *unknown* country code.
pub fn valid_iban_unknown(raw: &str) -> bool {
    valid_iban_unknown_loose(raw)
}

/// Allocation-free variant of [`valid_iban_unknown`].
fn valid_iban_unknown_loose(raw: &str) -> bool {
    let length = count_alnum(raw);
    if !(15..=34).contains(&length) {
        return false;
    }
    let bytes = raw.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic)
        || !bytes.get(1).is_some_and(u8::is_ascii_alphabetic)
        || !bytes.get(2).is_some_and(u8::is_ascii_digit)
        || !bytes.get(3).is_some_and(u8::is_ascii_digit)
    {
        return false;
    }
    if iban_country_length(&raw[0..2]).is_some() {
        return false;
    }
    iban_mod97_loose(raw) == Some(true)
}

fn compact(raw: &str) -> String {
    raw.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        IbanRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn accepts_valid_ibans() {
        assert_eq!(
            hits("IBAN FR7630006000011234567890189 ok"),
            vec!["FR7630006000011234567890189"]
        );
        assert_eq!(
            hits("HU42117730161111101800000000"),
            vec!["HU42117730161111101800000000"]
        );
    }

    #[test]
    fn accepts_grouped_ibans() {
        assert_eq!(
            hits("compte FR76 3000 6000 0112 3456 7890 189"),
            vec!["FR76 3000 6000 0112 3456 7890 189"]
        );
        // Dashes and non-breaking spaces are separators too (normalisation).
        assert_eq!(
            hits("compte FR76\u{2010}3000\u{00A0}6000 0112 3456 7890 189"),
            vec!["FR76\u{2010}3000\u{00A0}6000 0112 3456 7890 189"]
        );
    }

    #[test]
    fn accepts_the_corpus_za_and_ma_lengths() {
        assert_eq!(
            hits("ZA33 9999 0000 0112 3456 7890 12"),
            vec!["ZA33 9999 0000 0112 3456 7890 12"]
        );
        assert_eq!(
            hits("MA27 9990 0112 3456 7890 1234 5678"),
            vec!["MA27 9990 0112 3456 7890 1234 5678"]
        );
    }

    #[test]
    fn accepts_a_value_glued_to_a_letter() {
        assert_eq!(
            hits("xFR7630006000011234567890189"),
            vec!["FR7630006000011234567890189"]
        );
    }

    #[test]
    fn unknown_country_with_a_valid_check_is_masked_lower() {
        let text = "ZZ6630006000011234567890189";
        let spans = IbanRecognizer::new().analyze(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].score, UNKNOWN_SCORE);
    }

    #[test]
    fn unknown_country_includes_every_group_up_to_the_length() {
        // `ZZ85 ABCD …` is a valid mod-97 unknown-country IBAN; the whole
        // grouped value, country code and letter group included, must mask.
        let text = "ZZ85 ABCD 1234 5678 9012 3456";
        assert_eq!(hits(text), vec![text]);
        assert_eq!(IbanRecognizer::new().analyze(text)[0].score, UNKNOWN_SCORE);
    }

    #[test]
    fn an_invalid_unknown_country_value_with_the_shape_is_masked_lower() {
        // Same shape, broken check digit: it must still mask, at a lower score.
        let text = "ZZ84 ABCD 1234 5678 9012 3456";
        let spans = IbanRecognizer::new().analyze(text);
        assert_eq!(spans.len(), 1, "shape-only IBAN not masked: {spans:?}");
        assert_eq!(spans[0].score, SHAPE_SCORE);
        assert_eq!(&text[spans[0].start..spans[0].end], text);
    }

    #[test]
    fn unknown_country_does_not_swallow_following_words() {
        let text = "cpte ZZ6630006000011234567890189 merci beaucoup";
        assert_eq!(
            hits(text),
            vec!["ZZ6630006000011234567890189"],
            "unknown-country IBAN swallowed prose"
        );
    }

    #[test]
    fn an_unknown_country_guess_never_runs_into_a_path_or_prose() {
        // TOK-FP: `xm0000gn` in a macOS temp dir read as an unknown-country
        // IBAN shape, and the mask ran over the words after the path (the
        // directory names here are made up, with the same shape).
        let path = "/tmp/zq/plokij415_5uhyt7gtr13svxm0000gn/T/tmp.mTRfRr6UCj";
        assert!(hits(&format!("{path} Proposed command: ls")).is_empty());
        assert_eq!(
            hits("ZZ84 ABCD 1234 5678 Proposed command"),
            vec!["ZZ84 ABCD 1234 5678"]
        );
        assert!(hits("zz84 abcd 1234 5678 9012 3456").is_empty());
        // Upper-case prose after the guess stays in clear; a letter group
        // inside it is still masked.
        assert_eq!(hits("ZZ84 ABCD 123 OK"), vec!["ZZ84 ABCD 123"]);
        assert_eq!(
            hits("IBAN ZZ84 ABCD 1234 5678 OK THANKS"),
            vec!["ZZ84 ABCD 1234 5678"]
        );
        // A real IBAN keeps every printed form, lower case included.
        for text in [
            "FR76 3000 6000 0112 3456 7890 189",
            "FR7630006000011234567890189",
            "fr76 3000 6000 0112 3456 7890 189",
            "fr7630006000011234567890189",
            "FR76-3000-6000-0112-3456-7890-189",
        ] {
            assert_eq!(hits(&format!("IBAN {text} Proposed")), vec![text]);
        }
    }

    #[test]
    fn rejects_bad_check_digits_and_lengths() {
        assert!(hits("FR7630006000011234567890188").is_empty());
        assert!(hits("FR76300060000112345678901").is_empty());
    }

    #[test]
    fn lowercase_iban_is_accepted_and_reported_in_place() {
        assert_eq!(
            hits("fr7630006000011234567890189"),
            vec!["fr7630006000011234567890189"]
        );
    }

    #[test]
    fn ocr_letters_read_as_digits_when_the_check_then_passes() {
        let text = "IBAN FR76 3OOO 6OOO 0112 3456 7890 189";
        assert_eq!(hits(text), vec!["FR76 3OOO 6OOO 0112 3456 7890 189"]);
        assert_eq!(
            hits("fr76 3000 6000 O1l2 3456 7890 189"),
            vec!["fr76 3000 6000 O1l2 3456 7890 189"]
        );
        // A letter that is not a confusable, or a corrected form that fails the
        // check, is still rejected.
        assert!(hits("FR76 3OOO 6OOO 0112 3456 7890 188").is_empty());
        assert!(hits("FR76 3XOO 6OOO 0112 3456 7890 189").is_empty());
    }

    #[test]
    fn validity_vectors() {
        assert!(valid_iban("FR7630006000011234567890189"));
        assert!(!valid_iban("FR7630006000011234567890188"));
        assert!(valid_iban("MA27999001123456789012345678"));
    }

    #[test]
    fn only_a_whole_uuid_token_is_an_id() {
        let text = "a EB23A270-1C4F-4D6A-9E2B-5A7C3D0F121B:0f3d7c5a-b2e9-4a6d-8f4c-07282ab3e1c4 b";
        assert_eq!(uuid_tokens(text), [(2, 38), (39, 75)]);
        assert!(hits(text).is_empty());
        // Glued to a letter or grouped otherwise, the anchor is read as before.
        assert!(!hits("XEB23A270-1C4F-4D6A-9E2B-5A7C3D0F121B").is_empty());
        assert!(!hits("EB23A270-1C4F4D6A-9E2B-5A7C3D0F121B").is_empty());
        assert!(!hits("EB23A270-1C4F-4D6A-9E2B-5A7C3D0F121BC").is_empty());
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = IbanRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::Iban]);
        assert_eq!(recognizer.name(), "iban");
        assert!(recognizer.verified());
    }

    /// The old five-window scan, kept as the oracle for the one-pass cue.
    fn bank_cue_reference(before: &[u8]) -> bool {
        [b"iban".as_slice(), b"bank", b"account", b"compte", b"rib"]
            .iter()
            .any(|cue| {
                before.windows(cue.len()).enumerate().any(|(at, word)| {
                    word.eq_ignore_ascii_case(cue)
                        && (at == 0 || !before[at - 1].is_ascii_alphanumeric())
                        && (at + cue.len() == before.len()
                            || !before[at + cue.len()].is_ascii_alphanumeric())
                })
            })
    }

    #[test]
    fn bank_cue_reads_whole_words_and_case() {
        for (before, expected) in [
            (b"IBAN ".as_slice(), true),
            (b"xiban", false),
            (b"banque", false),
            (b"bank account", true),
            (b"compte", true),
            (b"RIB", true),
            (b"foo-rib", true),
            (b"rib_", true),
            (b"", false),
            (b"iban\n", true),
            (b"\xc3\x89RIB", true),
        ] {
            assert_eq!(bank_cue(before), expected, "{before:?}");
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn bank_cue_matches_the_five_window_scan(
            bytes in proptest::collection::vec(bank_cue_byte(), 0..160),
        ) {
            proptest::prop_assert_eq!(bank_cue(&bytes), bank_cue_reference(&bytes), "{:?}", bytes);
        }
    }

    /// Bytes biased to the cue words, so random cases actually hit them, plus
    /// case, separators, digits and non-ASCII bytes.
    fn bank_cue_byte() -> impl proptest::strategy::Strategy<Value = u8> {
        proptest::prop_oneof![
            proptest::sample::select(b"iIbBaAcCrRnkKouUtmMpeExX01- _\n".to_vec()),
            proptest::prelude::any::<u8>(),
        ]
    }
}
