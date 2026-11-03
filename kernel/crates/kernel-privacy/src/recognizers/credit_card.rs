//! Payment-card recogniser: a digit-run pattern, a brand-prefix check and Luhn.

use crate::checksum::luhn_ok;
use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// A Luhn-valid branded number scores 0.6; the context word can raise it.
pub const SCORE: f32 = 0.6;

/// Finds Luhn-valid payment cards with a known brand prefix.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreditCardRecognizer;

impl CreditCardRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for CreditCardRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::CreditCard]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        let view = normalized.text();
        let mut found: Vec<(usize, usize)> = candidates(view)
            .into_iter()
            .filter(|(start, end)| valid_card(&view[*start..*end]))
            .collect();
        // FIN-6: a run with other separators adds only where no card above was
        // found. Those runs are sorted by start and disjoint, so a binary search
        // picks the only candidate; scanning them all was quadratic (r1).
        let old = found.len();
        for (start, end) in uniform_candidates(view) {
            let first = &found[..old];
            let before = first.partition_point(|&(s, _)| s < end);
            let overlaps = first[..before].last().is_some_and(|&(_, e)| e > start);
            if !overlaps && valid_card(&view[start..end]) {
                found.push((start, end));
            }
        }
        found
            .into_iter()
            .filter_map(|(start, end)| normalized.to_original(start, end))
            .map(|(start, end)| Span::new(EntityKind::CreditCard, start, end, SCORE, "credit_card"))
            .collect()
    }

    fn name(&self) -> &'static str {
        "credit_card"
    }
}

/// Maximal runs of digits grouped with a single space or hyphen.
fn candidates(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        if index > 0 && bytes[index - 1].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        let mut cursor = index;
        let mut last_digit_end = index;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if byte.is_ascii_digit() {
                last_digit_end = cursor + 1;
                cursor += 1;
            } else if matches!(byte, b' ' | b'-')
                && cursor + 1 < bytes.len()
                && bytes[cursor + 1].is_ascii_digit()
            {
                cursor += 1;
            } else {
                break;
            }
        }
        found.push((start, last_digit_end));
        index = cursor.max(index + 1);
    }
    found
}

/// FIN-6: maximal runs of digits grouped by one separator byte (space, hyphen,
/// `.` or `/`), repeated one to three times at each joint, the same byte all
/// along the run (`4539  1488  0343  6467`, `4539/1488/0343/6467`).
fn uniform_candidates(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() || (index > 0 && bytes[index - 1].is_ascii_digit()) {
            index += 1;
            continue;
        }
        let start = index;
        let mut sep: Option<u8> = None;
        let mut end = index;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        loop {
            let byte = bytes.get(end).copied();
            let Some(joint @ (b' ' | b'-' | b'.' | b'/')) = byte else {
                break;
            };
            if sep.is_some_and(|sep| sep != joint) {
                break;
            }
            let run = bytes[end..]
                .iter()
                .take(4)
                .take_while(|&&b| b == joint)
                .count();
            if run > 3 || !bytes.get(end + run).is_some_and(u8::is_ascii_digit) {
                break;
            }
            sep = Some(joint);
            end += run;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
        }
        found.push((start, end));
        index = end.max(index + 1);
    }
    found
}

/// Whether a raw run (spaces and hyphens allowed) is a branded Luhn-valid card.
pub(crate) fn valid_card(raw: &str) -> bool {
    let digits: String = raw.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    brand_ok(&digits) && luhn_ok(&digits)
}

/// The issuer identifiers of the major brands, from their public ranges.
pub(crate) fn brand_ok(digits: &str) -> bool {
    let len = digits.len();
    let prefix2 = digits.get(0..2).unwrap_or("");
    let prefix3 = digits.get(0..3).unwrap_or("");
    let prefix4 = digits.get(0..4).unwrap_or("");
    let prefix6 = digits.get(0..6).unwrap_or("");
    let n2: u32 = prefix2.parse().unwrap_or(0);
    let n3: u32 = prefix3.parse().unwrap_or(0);
    let n4: u32 = prefix4.parse().unwrap_or(0);
    let n6: u32 = prefix6.parse().unwrap_or(0);

    // Visa.
    if digits.starts_with('4') && matches!(len, 13 | 16 | 18 | 19) {
        return true;
    }
    // Mastercard.
    if len == 16 && ((51..=55).contains(&n2) || (2221..=2720).contains(&n4)) {
        return true;
    }
    // American Express.
    if len == 15 && matches!(prefix2, "34" | "37") {
        return true;
    }
    // Discover.
    if (16..=19).contains(&len)
        && (prefix4 == "6011"
            || (644..=649).contains(&n3)
            || (622126..=622925).contains(&n6)
            || prefix2 == "65")
    {
        return true;
    }
    // JCB.
    if (16..=19).contains(&len)
        && ((3528..=3589).contains(&n4)
            || (3088..=3094).contains(&n4)
            || (3096..=3102).contains(&n4)
            || (3112..=3120).contains(&n4)
            || (3158..=3159).contains(&n4)
            || (3337..=3349).contains(&n4))
    {
        return true;
    }
    // Diners Club.
    if (14..=19).contains(&len)
        && ((300..=305).contains(&n3) || prefix4 == "3095" || matches!(prefix2, "36" | "38" | "39"))
    {
        return true;
    }
    // UnionPay (62, and 8100-8171).
    if (16..=19).contains(&len) && (prefix2 == "62" || (8100..=8171).contains(&n4)) {
        return true;
    }
    // Maestro (seal #95): 50 and 56-69.
    if (12..=19).contains(&len) && (prefix2 == "50" || (56..=69).contains(&n2)) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        CreditCardRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn accepts_luhn_valid_fake_cards() {
        assert_eq!(
            hits("carte 4111 1111 1111 1111"),
            vec!["4111 1111 1111 1111"]
        );
        assert_eq!(hits("5500 0000 0000 0004"), vec!["5500 0000 0000 0004"]);
        assert_eq!(hits("378282246310005"), vec!["378282246310005"]);
        assert_eq!(
            hits("card 6440 0000 0000 0005"),
            vec!["6440 0000 0000 0005"]
        );
    }

    #[test]
    fn accepts_ocr_confusables_and_unicode_digits() {
        assert_eq!(
            hits("carte 4111 l111 1111 1111"),
            vec!["4111 l111 1111 1111"]
        );
        assert_eq!(
            hits("carte 4O12 8888 8888 1881"),
            vec!["4O12 8888 8888 1881"]
        );
        assert_eq!(
            hits("carte ４１１１ １１１１ １１１１ １１１１"),
            vec!["４１１１ １１１１ １１１１ １１１１"]
        );
    }

    #[test]
    fn finds_a_card_glued_to_a_letter() {
        assert_eq!(hits("x4111111111111111"), vec!["4111111111111111"]);
    }

    #[test]
    fn rejects_luhn_failures_and_unknown_brands() {
        assert!(hits("4111 1111 1111 1112").is_empty());
        assert!(hits("9999 9999 9999 9999").is_empty());
        assert!(hits("1234 5678 9012 3456").is_empty());
    }

    #[test]
    fn a_card_with_space_runs_slashes_or_dots_is_found() {
        assert_eq!(hits("4539--1488--0343--6467").len(), 1);
        assert!(hits("4539    1488    0343    6467").is_empty());
        assert!(hits("4539/1488.0343/6467").is_empty());
    }

    #[test]
    fn does_not_treat_a_short_phone_as_a_card() {
        assert!(hits("06 12 34 56 78").is_empty());
        assert!(hits("+33 6 12 34 56 78").is_empty());
    }

    #[test]
    fn brand_and_luhn_vectors() {
        assert!(brand_ok("4111111111111111"));
        assert!(brand_ok("5500000000000004"));
        // Discover 644-649 is a three-digit prefix (ORGANIC-1 audit).
        assert!(brand_ok("6440000000000005"));
        assert!(brand_ok("6011000000000004"));
        // Seal #95: UnionPay 81, Maestro, Diners 3095, JCB intervals, 18-digit Visa.
        for card in [
            "8171999927660000",
            "6304958000000009",
            "3095000000000000",
            "3088000000000009",
            "3089000000000008",
            "6331101234567892",
            "400000000000000002",
        ] {
            assert!(brand_ok(card) && luhn_ok(card), "{card}");
            assert_eq!(hits(&format!("card {card}")), vec![card.to_string()]);
        }
        assert!(!brand_ok("9999999999999999"));
        assert!(valid_card("4111 1111 1111 1111"));
        assert!(!valid_card("4111 1111 1111 1112"));
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = CreditCardRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::CreditCard]);
        assert_eq!(recognizer.name(), "credit_card");
        assert!(recognizer.verified());
    }
}
