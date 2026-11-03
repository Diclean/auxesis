//! Telephone recogniser.
//!
//! International (`+` and `00`) and national forms, with any of the usual
//! separators and grouped digits. The scanner runs over the shared normalised
//! view (Unicode digits, exotic spaces and dashes, OCR confusables), uses a
//! digit-run boundary so a letter glued to the number (`x0612345678`) does not
//! hide it, and never caps the upper length: a phone-like run longer than the
//! national maximum is masked whole (P1-2).

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Base score for a structurally plausible number.
pub const SCORE: f32 = 0.5;

const MIN_INTERNATIONAL_DIGITS: usize = 8;
const MIN_NATIONAL_DIGITS: usize = 9;
/// At most this many separator-separated groups may be a single digit before a
/// run stops looking like a phone. `1 2 3 … 20` is a list, not a number.
const MAX_SINGLE_DIGIT_GROUPS: usize = 4;

/// Finds plausible phone numbers.
#[derive(Clone, Copy, Debug, Default)]
pub struct PhoneRecognizer;

impl PhoneRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for PhoneRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Phone]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        let body = normalized.text();
        candidates(body)
            .into_iter()
            .filter(|(start, end)| valid_number(&body[*start..*end]))
            .filter(|(start, end)| {
                !price_context(body, *start, *end) && !iso_context(body, *start, *end)
            })
            .filter_map(|(start, end)| normalized.to_original(start, end))
            .map(|(start, end)| Span::new(EntityKind::Phone, start, end, SCORE, "phone"))
            .collect()
    }

    fn name(&self) -> &'static str {
        "phone"
    }
}

fn is_allowed(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b' ' | b'-' | b'.' | b'(' | b')' | b'/')
}

/// Maximal runs of digits and separators, starting only at a digit-run
/// boundary so `x0612345678` is one run but `0612345678` inside a longer
/// digit run is not split.
fn candidates(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let starts_here = byte.is_ascii_digit() || byte == b'+' || byte == b'(';
        if !starts_here {
            index += 1;
            continue;
        }
        if byte != b'+' && index > 0 && bytes[index - 1].is_ascii_digit() {
            index += 1;
            continue;
        }
        if byte == b'+' && index > 0 && bytes[index - 1].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut cursor = index;
        let mut last_digit_end: Option<usize> = None;
        while cursor < bytes.len() {
            let candidate = bytes[cursor];
            let allowed = is_allowed(candidate) || (cursor == start && candidate == b'+');
            if !allowed {
                break;
            }
            if candidate.is_ascii_digit() {
                last_digit_end = Some(cursor + 1);
            }
            cursor += 1;
        }
        if let Some(end) = last_digit_end {
            found.push((start, end));
            index = cursor.max(index + 1);
            continue;
        }
        // No digit in the whole scanned run, so no start inside it can form a
        // phone: skip to the end of the run instead of rescanning from the next
        // byte (that rescan was the quadratic path on `((((…`).
        index = cursor.max(index + 1);
    }
    found
}

/// Whether a run is a full, valid date and possibly a time rather than a phone.
///
/// Only a complete date triplet with a four-digit year (`12/03/2026`,
/// `2026-12-03`) joined by a real date separator (`/`, `-`, `.`) counts, and
/// only a valid `hh`, `hh:mm` may follow. A run with any further or oversized
/// digit group (`06/12/1234 56 78`, `06-12-1234-56-78`, `+2026/1/3 12345678`)
/// is not a date and stays masked (P2-6). A French phone written
/// `06.12.34.56.78` is not matched either: its third group is a two-digit year,
/// not four.
fn looks_like_datetime(raw: &str) -> bool {
    let (groups, separators) = split_groups(raw);
    if groups.len() < 3 {
        return false;
    }
    if !matches!(separators[1], '/' | '-' | '.') || !matches!(separators[2], '/' | '-' | '.') {
        return false;
    }
    if !date_triplet(groups[0], groups[1], groups[2]) {
        return false;
    }
    let clock = &groups[3..];
    match clock.len() {
        0 => true,
        1 => valid_clock(clock[0], 23),
        2 => valid_clock(clock[0], 23) && valid_clock(clock[1], 59),
        // `dd.mm.yyyy hh.mm.ss` / `dd.mm.yyyy hh mm ss` (P3): a full clock with
        // seconds is a datetime, not a phone.
        3 => valid_clock(clock[0], 23) && valid_clock(clock[1], 59) && valid_clock(clock[2], 59),
        _ => false,
    }
}

/// A one- or two-digit clock group at or below `max`.
fn valid_clock(group: &str, max: u32) -> bool {
    group.len() <= 2 && group.parse::<u32>().is_ok_and(|value| value <= max)
}

/// Whether three digit groups form a plausible `dd/mm/yyyy` or `yyyy/mm/dd`.
fn date_triplet(first: &str, second: &str, third: &str) -> bool {
    let (day, month) = if first.len() == 4 && second.len() <= 2 && third.len() <= 2 {
        (third, second)
    } else if third.len() == 4 && first.len() <= 2 && second.len() <= 2 {
        (first, second)
    } else {
        return false;
    };
    let (Ok(day), Ok(month)) = (day.parse::<u32>(), month.parse::<u32>()) else {
        return false;
    };
    (1..=31).contains(&day) && (1..=12).contains(&month)
}

/// The digit groups of a run plus the last non-digit before each group.
fn split_groups(raw: &str) -> (Vec<&str>, Vec<char>) {
    let bytes = raw.as_bytes();
    let mut groups: Vec<&str> = Vec::new();
    // `separators[i]` is the last non-digit before `groups[i]`; the first is
    // unused because no group precedes `groups[0]`.
    let mut separators: Vec<char> = Vec::new();
    let mut pending = '\0';
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            groups.push(&raw[start..index]);
            separators.push(pending);
        } else {
            pending = bytes[index] as char;
            index += 1;
        }
    }
    (groups, separators)
}

/// Whether a candidate run is a plausible phone number.
///
/// There is deliberately no upper bound on the digit count: a run longer than
/// a real phone stays masked rather than leaking its tail. Over-masking guards
/// reject the numbers that are not phones: a long list of digit groups
/// (`1 2 3 … 20`) and a full date with an optional time (`12/03/2026 14`).
/// A sequence of 9–12 *singly spaced* digits (the guard is evaluated per
/// candidate, P2-7) is a phone even though every group is one digit.
pub(crate) fn valid_number(raw: &str) -> bool {
    let digits: String = raw.chars().filter(|ch| ch.is_ascii_digit()).collect();
    let count = digits.len();
    if looks_like_datetime(raw) {
        return false;
    }
    if cn_mobile(raw, &digits) {
        return true;
    }
    let (groups, _) = split_groups(raw);
    let singles = groups.iter().filter(|group| group.len() == 1).count();
    let all_single = !groups.is_empty() && singles == groups.len();
    if all_single {
        if (9..=12).contains(&count) {
            return true;
        }
        if count > 12 {
            return false;
        }
    } else if singles > MAX_SINGLE_DIGIT_GROUPS {
        return false;
    }
    let international = raw.starts_with('+') || raw.starts_with("00");
    if international {
        return count >= MIN_INTERNATIONAL_DIGITS;
    }
    if count < MIN_NATIONAL_DIGITS {
        return false;
    }
    let grouped = raw.chars().any(|ch| !ch.is_ascii_digit());
    digits.starts_with('0') || grouped
}

/// Whether a run is a Chinese mobile number: eleven digits, `1[3-9]` first, written
/// bare (`13800138000`) or in the 3-4-4 form with spaces, hyphens or dots
/// (`138-0013-8000`). The `+86` form is an international run and already masked.
fn cn_mobile(raw: &str, digits: &str) -> bool {
    let bytes = digits.as_bytes();
    if bytes.len() != 11 || bytes[0] != b'1' || !(b'3'..=b'9').contains(&bytes[1]) {
        return false;
    }
    if raw
        .chars()
        .any(|ch| !(ch.is_ascii_digit() || matches!(ch, ' ' | '-' | '.')))
    {
        return false;
    }
    let (groups, _) = split_groups(raw);
    let lengths: Vec<usize> = groups.iter().map(|group| group.len()).collect();
    lengths == [11] || lengths == [3, 4, 4]
}

/// The currency symbols that turn a following number into a price, not a phone.
const CURRENCY_SYMBOLS: &[char] = &['€', '$', '£', '¥', '₹', '₽', '₺', '₩', '₪'];

/// A price guard exempts at most this many digits: a 9-digit number glued to a
/// currency symbol is masked (P3).
const PRICE_MAX_DIGITS: usize = 8;
/// The ISO guard keeps the older bound, so `ISO 27001 2022` stays clear.
const ISO_MAX_DIGITS: usize = 9;

/// Whether a currency symbol sits immediately before or after the run (P3-6);
/// a short number beside one is a price and must stay clear.
///
/// The guard only exempts a number of at most [`PRICE_MAX_DIGITS`] digits with
/// no leading `0`/`+` and no date separator: `06 12 34 56 78 €` is a phone with
/// a currency symbol beside it and must stay masked (P3), and so is a 9-digit
/// price-like run.
fn price_context(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start]
        .trim_end_matches(char::is_whitespace)
        .chars()
        .next_back();
    let after = text[end..]
        .trim_start_matches(char::is_whitespace)
        .chars()
        .next();
    let currency = [before, after]
        .into_iter()
        .flatten()
        .any(|ch| CURRENCY_SYMBOLS.contains(&ch));
    currency && guardable_as_non_phone(&text[start..end], PRICE_MAX_DIGITS)
}

/// Whether the token immediately before the run is `ISO` (P3-6); a standard
/// number such as `ISO 27001 2022` must stay clear.
///
/// As with the price guard, only a short undated number is exempt, so
/// `ISO 06 12 34 56 78` stays masked.
fn iso_context(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].trim_end_matches(char::is_whitespace);
    let is_iso = before
        .rsplit(|ch: char| !ch.is_alphanumeric())
        .next()
        .is_some_and(|token| token.eq_ignore_ascii_case("iso"));
    is_iso && guardable_as_non_phone(&text[start..end], ISO_MAX_DIGITS)
}

/// Whether a price/ISO context may exempt a run from being a phone.
///
/// Excluded only when the run is short (≤`max_digits` digits), has no leading
/// `0`/`+` and carries no date separator — the shapes of a price or a standard
/// number. A longer run, a leading zero or plus, or a date separator means it is
/// more likely a phone, so the guard leaves it masked (P3).
fn guardable_as_non_phone(raw: &str, max_digits: usize) -> bool {
    let mut digits = 0usize;
    let mut first_digit = None;
    let mut has_date_separator = false;
    for ch in raw.chars() {
        if ch.is_ascii_digit() {
            digits += 1;
            first_digit.get_or_insert(ch);
        } else if matches!(ch, '/' | '-' | '.') {
            has_date_separator = true;
        }
    }
    digits <= max_digits && first_digit != Some('0') && !raw.starts_with('+') && !has_date_separator
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        PhoneRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn accepts_international_forms() {
        assert_eq!(hits("appelez +33 6 12 34 56 78"), vec!["+33 6 12 34 56 78"]);
        assert_eq!(hits("call 0033 6 12 34 56 78"), vec!["0033 6 12 34 56 78"]);
        assert_eq!(hits("+1 (202) 555-0142"), vec!["+1 (202) 555-0142"]);
    }

    #[test]
    fn accepts_national_forms() {
        assert_eq!(hits("tél 06 12 34 56 78"), vec!["06 12 34 56 78"]);
        assert_eq!(hits("06.12.34.56.78"), vec!["06.12.34.56.78"]);
        assert_eq!(hits("06 12 34 56 78"), vec!["06 12 34 56 78"]);
        assert_eq!(hits("(01) 23 45 67 89"), vec!["(01) 23 45 67 89"]);
    }

    #[test]
    fn accepts_unicode_separators_and_digits() {
        assert_eq!(
            hits("tél 06\u{00A0}12\u{202F}34\u{2010}56\u{2212}78"),
            vec!["06\u{00A0}12\u{202F}34\u{2010}56\u{2212}78"]
        );
        assert_eq!(
            hits("０６ １２ ３４ ５６ ７８"),
            vec!["０６ １２ ３４ ５６ ７８"]
        );
    }

    #[test]
    fn accepts_ocr_confusables_inside_a_digit_run() {
        assert_eq!(hits("+33 l 99 OO 41 27"), vec!["+33 l 99 OO 41 27"]);
    }

    #[test]
    fn masks_runs_longer_than_the_national_maximum() {
        assert_eq!(hits("tel 06 12 34 56 78 123"), vec!["06 12 34 56 78 123"]);
        assert_eq!(hits("0612345678 2026"), vec!["0612345678 2026"]);
    }

    #[test]
    fn rejects_short_forms() {
        assert!(hits("12345").is_empty());
        assert!(hits("+33 6 12").is_empty());
        assert!(hits("2020.01.01").is_empty());
        assert!(hits("123456789").is_empty());
    }

    #[test]
    fn finds_a_value_glued_to_a_letter() {
        assert_eq!(hits("a0612345678"), vec!["0612345678"]);
        assert_eq!(hits("x+33612345678"), vec!["+33612345678"]);
    }

    #[test]
    fn validity_vectors() {
        assert!(valid_number("0612345678"));
        assert!(valid_number("+33612345678"));
        assert!(!valid_number("123456789"));
        assert!(valid_number("4111 1111 1111 1111"));
    }

    #[test]
    fn rejects_a_list_of_isolated_single_digits() {
        let list: Vec<String> = (1..=20).map(|n| n.to_string()).collect();
        let list = list.join(" ");
        assert!(hits(&list).is_empty(), "a 1..20 list became a phone");
        assert!(!valid_number("1 2 3 4 5"));
        assert!(!valid_number("1 2 3 4 5 6 7 8 9 10 11 12"));
    }

    #[test]
    fn rejects_dates_and_datetimes() {
        assert!(hits("le 12/03/2026 14 h").is_empty());
        assert!(!valid_number("12/03/2026 14"));
        assert!(!valid_number("2026-12-03 14"));
        assert!(!valid_number("12/03/2026"));
        // A dotted French phone must not be mistaken for a 2-digit-year date.
        assert!(valid_number("06.12.34.56.78"));
        assert!(valid_number("06 12 34 56 78"));
    }

    #[test]
    fn only_a_full_date_with_no_extra_groups_is_excluded() {
        for raw in [
            "06/12/1234 56 78",
            "06-12-1234-56-78",
            "06.12.2034.56.78",
            "+2026/1/3 12345678",
        ] {
            assert!(
                valid_number(raw),
                "a date with extra digit groups stayed excluded: {raw:?}"
            );
        }
        for raw in ["06/12/1234 56 78", "06-12-1234-56-78", "06.12.2034.56.78"] {
            assert!(!hits(raw).is_empty(), "not masked: {raw:?}");
        }
        assert!(!hits("+2026/1/3 12345678").is_empty());
    }

    #[test]
    fn singly_spaced_digits_are_a_phone() {
        assert_eq!(hits("tel 0 6 1 2 3 4 5 6 7 8"), vec!["0 6 1 2 3 4 5 6 7 8"]);
        assert_eq!(hits("0 6 1 2 3 4 5 6 7 8"), vec!["0 6 1 2 3 4 5 6 7 8"]);
        assert!(valid_number("0 6 1 2 3 4 5 6 7 8"));
        // The phone part of a run with a trailing list must be masked.
        assert!(!hits("06 12 34 56 78 / 1 / 2 / 3").is_empty());
        // Both the phone and the following address must be masked.
        let both = hits("+33 6 12 34 56 78  192.168.0.1");
        assert!(!both.is_empty());
        let registry = crate::Registry::new();
        let text = "+33 6 12 34 56 78  192.168.0.1";
        let masked = {
            let spans = registry.analyze(text);
            let mut anonymizer = crate::Anonymizer::new([0x66u8; 32]);
            anonymizer.anonymize(text, &spans).0
        };
        assert!(!masked.contains("6 12 34 56 78"));
        assert!(!masked.contains("192.168.0.1"));
    }

    #[test]
    fn prices_and_iso_standards_are_not_phones() {
        // A bare phone-like run stays masked.
        assert_eq!(hits("45 00 12 34 56"), vec!["45 00 12 34 56"]);
        assert_eq!(hits("0123456789012"), vec!["0123456789012"]);
        // A standard number stays clear under the ISO guard.
        assert!(hits("ISO 27001 2022").is_empty());
    }

    #[test]
    fn a_nine_digit_number_beside_a_currency_symbol_is_masked() {
        // P3: the price exemption stops at 8 digits, so a 9-digit phone-like run
        // glued to a currency symbol is no longer treated as a price.
        assert_eq!(hits("123 456 789 €"), vec!["123 456 789"]);
        assert_eq!(hits("123 456 789€"), vec!["123 456 789"]);
        assert_eq!(hits("€123 456 789"), vec!["123 456 789"]);
        // The ISO guard keeps its own, older bound.
        assert!(hits("ISO 27001 2022").is_empty());
    }

    #[test]
    fn price_and_iso_guards_do_not_hide_phones() {
        // A leading zero or a date separator means the run is a phone, not a
        // price or a standard number (P3).
        assert_eq!(hits("06 12 34 56 78 €"), vec!["06 12 34 56 78"]);
        assert_eq!(hits("ISO 06 12 34 56 78"), vec!["06 12 34 56 78"]);
        assert!(
            !hits("12/03/2026 06 12 34 56 78 €").is_empty(),
            "a dated phone run must stay masked next to a currency symbol"
        );
        assert!(valid_number("12/03/2026 06 12 34 56 78"));
    }

    #[test]
    fn russian_dotted_datetime_with_seconds_is_not_a_phone() {
        // P3: `dd.mm.yyyy` plus a dotted `hh.mm.ss` clock is a datetime, not a
        // number list that happens to be phone-shaped.
        assert!(!valid_number("12.03.2026 14.30.00"));
        assert!(hits("12.03.2026 14.30.00").is_empty());
        assert!(hits("12.03.2026 14 30 00").is_empty());
        // A dotted French phone (its third group is a two-digit year) stays a
        // phone.
        assert!(valid_number("06.12.34.56.78"));
    }

    #[test]
    fn rejects_a_run_of_separators_without_digits() {
        assert!(hits(&"(".repeat(64)).is_empty());
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = PhoneRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::Phone]);
        assert_eq!(recognizer.name(), "phone");
        assert!(recognizer.verified());
    }
}
