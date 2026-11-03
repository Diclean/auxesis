//! Chinese resident identity card number recogniser (居民身份证号).
//!
//! The eighteen-character form is `AAAAAA YYYYMMDD SSS C`: a six-digit area
//! code, a real birth date from 1900 to the current year, a three-digit
//! sequence and a check character from ISO 7064 MOD 11-2. The legacy
//! fifteen-character form (`AAAAAA YYMMDD SSS`) has no check character. Digits
//! may be fullwidth, and the groups may be joined by spaces or dashes in `6-8-4`
//! or `6-4-4-4` (eighteen) and `6-6-3` (fifteen) grouping.
//!
//! A checksum-valid eighteen-character value masks on its own. Any other
//! candidate (a bad check character, or the legacy form) masks only next to a
//! cue word, so an order number that happens to look like an ID stays clear.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::normalize::{numeric_runs, NormalizedText};
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Score of a checksum-valid eighteen-character value.
pub const VERIFIED_SCORE: f32 = 1.0;

/// Score of a candidate that masks only because a cue sits next to it. Above
/// the default floor (`0.5`) and below a verified hit.
pub const CUED_SCORE: f32 = 0.6;

/// Words that name the card. Matched against the lowercased window.
const CUES: &[&str] = &[
    "身份证",
    "公民身份号码",
    "身份号码",
    "证件号",
    "id card",
    "carte d'identité",
    "carte d’identité",
];

/// Bytes read before and after a candidate when looking for a cue.
const CUE_BEFORE: usize = 24;
const CUE_AFTER: usize = 12;

/// Weights of the first seventeen digits in the MOD 11-2 check.
const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

/// Check character for each value of the weighted sum modulo 11.
const CHECK_CHARS: [char; 11] = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];

/// The Chinese resident identity card number, both the eighteen-character form
/// and the legacy fifteen-character form.
#[derive(Clone, Copy, Debug)]
pub struct CnResidentIdRecognizer {
    verified: bool,
}

impl CnResidentIdRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self { verified: true }
    }
}

impl Default for CnResidentIdRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

/// What a candidate proves on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proof {
    /// The eighteen-character check character matches.
    Checksum,
    /// Plausible shape, but only a cue can justify masking it.
    Cue,
}

impl Recognizer for CnResidentIdRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::NationalId]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        let folded = normalized.text();
        let this_year = current_year();
        numeric_runs(folded)
            .into_iter()
            .filter_map(|(start, end)| {
                let run = &folded[start..end];
                let digits: Vec<u32> = run
                    .bytes()
                    .filter(u8::is_ascii_digit)
                    .map(|byte| u32::from(byte - b'0'))
                    .collect();
                let check_x = check_follows(folded, end, digits.len());
                let groups = printed_groups(run, check_x);
                let proof = proof(&digits, check_x, &groups, this_year)?;
                let (start, end) = normalized.to_original(start, end + usize::from(check_x))?;
                let score = match proof {
                    Proof::Checksum => VERIFIED_SCORE,
                    Proof::Cue if has_cue(text, start, end) => CUED_SCORE,
                    Proof::Cue => return None,
                };
                Some(Span::new(
                    EntityKind::NationalId,
                    start,
                    end,
                    score,
                    "cn_resident_id",
                ))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "cn_resident_id"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// The proof a digit run carries, or `None` when it cannot be a card number.
fn proof(digits: &[u32], check_x: bool, groups: &[usize], this_year: u32) -> Option<Proof> {
    match groups {
        [18] | [6, 8, 4] | [6, 4, 4, 4] => {
            let year = number(&digits[6..10]);
            let date_ok = (1900..=this_year).contains(&year)
                && real_date(year, number(&digits[10..12]), number(&digits[12..14]));
            if !date_ok {
                return None;
            }
            let got = if check_x {
                'X'
            } else {
                char::from(b'0' + digits[17] as u8)
            };
            Some(if check_char(&digits[..17]) == got {
                Proof::Checksum
            } else {
                Proof::Cue
            })
        }
        [15] | [6, 6, 3] => {
            let year = 1900 + number(&digits[6..8]);
            real_date(year, number(&digits[8..10]), number(&digits[10..12])).then_some(Proof::Cue)
        }
        _ => None,
    }
}

/// Whether an `X` check character directly follows a seventeen-digit run and
/// is not glued to a letter or digit.
fn check_follows(folded: &str, end: usize, digits: usize) -> bool {
    digits == 17
        && matches!(folded[end..].chars().next(), Some('X' | 'x'))
        && !folded[end + 1..].starts_with(|ch: char| ch.is_ascii_alphanumeric())
}

/// The digit groups of a run as printed. The check character, when present,
/// counts in the last group.
fn printed_groups(run: &str, check_x: bool) -> Vec<usize> {
    let mut groups: Vec<usize> = run
        .split(|ch: char| !ch.is_ascii_digit())
        .map(str::len)
        .collect();
    if check_x {
        if let Some(last) = groups.last_mut() {
            *last += 1;
        }
    }
    groups
}

/// Whether a cue word sits within reach of the candidate, before or after it.
/// A cue preceded by an ASCII letter is part of a longer word and does not count.
fn has_cue(text: &str, start: usize, end: usize) -> bool {
    let mut from = start.saturating_sub(CUE_BEFORE);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    let mut to = (end + CUE_AFTER).min(text.len());
    while !text.is_char_boundary(to) {
        to += 1;
    }
    let window = text[from..to].to_lowercase();
    CUES.iter().any(|cue| {
        window
            .match_indices(cue)
            .any(|(at, _)| !window[..at].ends_with(|ch: char| ch.is_ascii_alphabetic()))
    })
}

/// ISO 7064 MOD 11-2 check character over the first seventeen digits.
fn check_char(body: &[u32]) -> char {
    let sum: u32 = body
        .iter()
        .zip(WEIGHTS)
        .map(|(digit, weight)| digit * weight)
        .sum();
    CHECK_CHARS[(sum % 11) as usize]
}

/// The value of a run of digits, most significant first.
fn number(digits: &[u32]) -> u32 {
    digits.iter().fold(0, |value, digit| value * 10 + digit)
}

/// Whether `year-month-day` is a date in the Gregorian calendar.
fn real_date(year: u32, month: u32, day: u32) -> bool {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// The current calendar year in UTC, from the system clock.
fn current_year() -> u32 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    civil_year((elapsed / 86_400) as i64)
}

/// The Gregorian year of a day count from 1970-01-01 (Howard Hinnant's
/// `civil_from_days`), so the birth-date bound needs no calendar crate.
fn civil_year(days: i64) -> u32 {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let year = year_of_era + era * 400;
    (if month_index >= 10 { year + 1 } else { year }) as u32
}

/// The 31 characters of a unified social credit code, in value order
/// (GB 32100-2015: digits, then capitals without I, O, S, V and Z).
const USCC_ALPHABET: &[u8; 31] = b"0123456789ABCDEFGHJKLMNPQRTUWXY";
/// Words that name a credit code, needed before an all-digit one.
const USCC_CUES: [&str; 4] = ["信用代码", "uscc", "credit code", "税号"];
const USCC_CUE_BYTES: usize = 40;

/// The Chinese unified social credit code (统一社会信用代码, GB 32100-2015,
/// K-PII-TRACE-GAPS-2): eighteen characters with a MOD 31 check character, one
/// ASCII run, or two wrapped over a line break or up to two spaces, masked
/// whole. An all-digit code masks only after a cue, so an order number stays
/// clear.
#[derive(Clone, Copy, Debug, Default)]
pub struct CnCreditCodeRecognizer;

impl Recognizer for CnCreditCodeRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::NationalId]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let mut runs = Vec::new();
        let mut chars = text.char_indices().peekable();
        while let Some((start, ch)) = chars.next() {
            if ch.is_ascii_alphanumeric() {
                let mut end = start + 1;
                while let Some((at, _)) = chars.next_if(|(_, ch)| ch.is_ascii_alphanumeric()) {
                    end = at + 1;
                }
                runs.push((start, end));
            }
        }
        let mut spans = Vec::new();
        for (index, &(start, end)) in runs.iter().enumerate() {
            let next = runs
                .get(index + 1)
                .filter(|&&(next, _)| matches!(&text[end..next], "\n" | "\r\n" | " " | "  "));
            let mut code = text[start..end].to_string();
            let mut stop = end;
            if code.len() < 18 {
                let Some(&(next, last)) = next else { continue };
                code.push_str(&text[next..last]);
                stop = last;
            }
            let digits = code.bytes().all(|byte| byte.is_ascii_digit());
            let cued = || {
                let from = text.ceil_char_boundary(start.saturating_sub(USCC_CUE_BYTES));
                let window = text[from..start].to_lowercase();
                USCC_CUES.iter().any(|cue| window.contains(cue))
            };
            if is_credit_code(code.as_bytes()) && (!digits || cued()) {
                spans.push(Span::new(
                    EntityKind::NationalId,
                    start,
                    stop,
                    VERIFIED_SCORE,
                    self.name(),
                ));
            }
        }
        spans
    }

    fn name(&self) -> &'static str {
        "cn_uscc"
    }
}

/// Whether `code` is a unified social credit code with a matching check character.
fn is_credit_code(code: &[u8]) -> bool {
    if code.len() != 18 || code[0] == b'0' || !code[2..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let (mut sum, mut weight) = (0u32, 1u32);
    for &ch in &code[..17] {
        let Some(value) = USCC_ALPHABET.iter().position(|&c| c == ch) else {
            return false;
        };
        sum += value as u32 * weight;
        weight = weight * 3 % 31;
    }
    USCC_ALPHABET[((31 - sum % 31) % 31) as usize] == code[17]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        CnResidentIdRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn check_character_follows_mod_11_2() {
        let body = [1, 1, 0, 1, 0, 5, 1, 9, 4, 9, 1, 2, 3, 1, 0, 0, 2];
        assert_eq!(check_char(&body), 'X');
    }

    #[test]
    fn a_checksum_valid_id_is_verified() {
        let spans = CnResidentIdRecognizer::new().analyze("11010519491231002X");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].kind, EntityKind::NationalId);
        assert_eq!(spans[0].score, VERIFIED_SCORE);
    }

    #[test]
    fn a_bad_check_character_needs_a_cue() {
        assert!(hits("110105194912310021").is_empty());
        assert_eq!(
            hits("身份证号：110105194912310021"),
            vec!["110105194912310021"]
        );
    }

    #[test]
    fn the_legacy_form_needs_a_cue() {
        assert!(hits("110105491231002").is_empty());
        assert_eq!(hits("身份证号：110105491231002"), vec!["110105491231002"]);
    }

    #[test]
    fn impossible_dates_are_rejected() {
        assert!(!real_date(1900, 2, 29));
        assert!(real_date(2000, 2, 29));
        assert!(!real_date(2026, 13, 1));
        assert!(!real_date(1949, 12, 32));
        // 1899 is before the window, and a date in the future is no birth date.
        assert!(hits("身份证号：110105189912310021").is_empty());
        assert!(hits("身份证号：110105209912310021").is_empty());
    }

    #[test]
    fn civil_year_matches_known_days() {
        assert_eq!(civil_year(0), 1970);
        assert_eq!(civil_year(18_992), 2021);
        assert_eq!(civil_year(18_993), 2022);
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = CnResidentIdRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::NationalId]);
        assert_eq!(recognizer.name(), "cn_resident_id");
        assert!(recognizer.verified());
    }
}
