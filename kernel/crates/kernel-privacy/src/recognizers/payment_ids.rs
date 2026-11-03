//! Payment and tax identifiers that follow a cue word, plus the French RIB.
//!
//! * a card security code (CVV, CVC, CSC): three or four digits after the cue,
//!   masked as `CREDIT_CARD`;
//! * a US social security number, ITIN or EIN: the dashed or spaced SSN shape
//!   stands alone when its area, group and serial are issuable; any other shape
//!   needs a cue (`SSN`, `EIN`, `tax id`);
//! * a US routing number (ABA), a bank account number of 6 to 17 digits and a UK
//!   sort code, each after its cue;
//! * a French RIB (`30006 00001 12345678901 89`), checked with its key;
//! * on a bank statement (K-BANK-STATEMENT-1): a German, Dutch or Spanish account
//!   cue, a RIB whose groups sit in table columns, a value glued to its label
//!   (`Account number55555555`), and a table value under its header line.
//! * a generic ID after a personal-identity label (`ID number`, `national ID`, `n° CNI`)
//!   or a bare `ID` at a sentence start or after `my`; business references (`order ID`,
//!   `customer ID`) stay clear (K-PUBLIC-MISSES).
//!
//! All of them are masked as `NATIONAL_ID`, a class open mode removes. The cue
//! may be followed by a label word (`no`, `number`, `n°`), a colon or an equals
//! sign. A cued value is masked even when its checksum fails: the masker fails
//! toward masking.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// The name echoed in [`Span::recognizer`].
const NAME: &str = "payment_ids";

const CVV_CUES: &[&str] = &[
    "cvv2",
    "cvv",
    "cvc2",
    "cvc",
    "csc",
    "cvn",
    "security code",
    "card verification value",
    "card verification code",
    "cryptogramme",
    "code de sécurité",
];
const TAX_CUES: &[&str] = &[
    "ssn",
    "ss#",
    "ss no",
    "social security",
    "soc sec",
    "itin",
    "ein",
    "fein",
    "tin",
    "tax id",
    "tax identification",
    "taxpayer id",
    "employer identification",
    "federal id",
];
const ROUTING_CUES: &[&str] = &["routing", "aba", "rtn"];
const ACCOUNT_CUES: &[&str] = &["account", "acct", "a/c", "compte"];
const SORT_CUES: &[&str] = &["sort code", "sortcode"];
/// Account cues of other statement languages (K-BANK-STATEMENT-1).
const ACCOUNT_CUES_INTL: &[&str] = &[
    "kontonummer",
    "konto-nr",
    "kontonr",
    "konto",
    "rekeningnummer",
    "rekeningnr",
    "kto.-nr",
    "kto-nr",
    "cuenta",
];
/// Words that may sit between a cue and its value.
const LABEL_WORDS: &[&str] = &["no", "number", "num", "nr", "n", "numéro", "id", "is"];

/// A digit group: its width and whether letters are allowed in it.
type Group = (usize, bool);

const DIGITS_9: &[Group] = &[(9, false)];
const EIN: &[Group] = &[(2, false), (7, false)];
const SSN: &[Group] = &[(3, false), (2, false), (4, false)];
const SORT_CODE: &[Group] = &[(2, false), (2, false), (2, false)];
const RIB: &[Group] = &[(5, false), (5, false), (11, true), (2, false)];

/// The recogniser for the cue-led payment and tax identifiers.
#[derive(Clone, Copy, Debug, Default)]
pub struct PaymentIdsRecognizer;

impl PaymentIdsRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for PaymentIdsRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::CreditCard, EntityKind::NationalId]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, false);
        let lower = normalized.text().to_ascii_lowercase();
        let bytes = lower.as_bytes();
        let mut found: Vec<(usize, usize, EntityKind, f32)> = Vec::new();
        let national = EntityKind::NationalId;

        for at in value_starts(&lower, CVV_CUES) {
            let end = at + digit_run(bytes, at);
            if (3..=4).contains(&(end - at)) && ends_value(&lower, end) {
                found.push((at, end, EntityKind::CreditCard, 1.0));
            }
        }
        for at in value_starts(&lower, TAX_CUES) {
            let shape = [DIGITS_9, EIN, SSN].into_iter().find_map(|shape| {
                groups(bytes, at, shape, false).filter(|&end| ends_value(&lower, end))
            });
            if let Some(end) = shape {
                found.push((at, end, national, 1.0));
            }
        }
        for at in value_starts(&lower, ROUTING_CUES) {
            if let Some(end) = groups(bytes, at, DIGITS_9, false).filter(|&e| ends_value(&lower, e))
            {
                let score = if aba_ok(&bytes[at..end]) { 1.0 } else { 0.6 };
                found.push((at, end, national, score));
            }
        }
        for at in value_starts(&lower, ACCOUNT_CUES) {
            let end = at + digit_run(bytes, at);
            if (6..=17).contains(&(end - at)) && ends_value(&lower, end) {
                found.push((at, end, national, 1.0));
            }
        }
        for at in value_starts(&lower, ACCOUNT_CUES_INTL) {
            let end = at + digit_run(bytes, at);
            if (6..=17).contains(&(end - at)) && ends_value(&lower, end) {
                found.push((at, end, national, 1.0));
            }
        }
        for captures in GLUED_ACCOUNT_RE
            .captures_iter(&lower)
            .chain(GLUED_SORT_RE.captures_iter(&lower))
        {
            if let Some(value) = captures.get(1) {
                found.push((value.start(), value.end(), national, 1.0));
            }
        }
        for rib in COLUMN_RIB_RE.find_iter(&lower) {
            if rib_key_ok(rib.as_str().as_bytes()) {
                found.push((rib.start(), rib.end(), national, 1.0));
            }
        }
        for at in value_starts(&lower, SORT_CUES) {
            if let Some(end) = groups(bytes, at, SORT_CODE, true).filter(|&e| ends_value(&lower, e))
            {
                found.push((at, end, national, 1.0));
            }
        }
        for (start, end) in id_label_values(&lower) {
            found.push((start, end, national, 1.0));
        }
        // Shapes that stand alone: an issuable dashed or spaced SSN, a RIB.
        for at in (0..bytes.len()).filter(|&at| starts_token(bytes, at)) {
            let ssn = groups(bytes, at, SSN, false)
                .filter(|&e| ends_value(&lower, e))
                .filter(|&e| !runs_on(at, e, bytes));
            if let Some(end) = ssn {
                if ssn_issuable(&bytes[at..end]) {
                    found.push((at, end, national, 1.0));
                }
            }
            if let Some(end) = groups(bytes, at, RIB, true).filter(|&e| ends_value(&lower, e)) {
                if rib_key_ok(&bytes[at..end]) {
                    found.push((at, end, national, 1.0));
                }
            }
        }
        found.sort_by_key(|&(start, end, ..)| (start, end));
        found.dedup_by_key(|&mut (start, end, kind, _)| (start, end, kind));
        let mut spans: Vec<Span> = found
            .into_iter()
            .filter_map(|(start, end, kind, score)| {
                let (start, end) = normalized.to_original(start, end)?;
                Some(Span::new(kind, start, end, score, NAME))
            })
            .collect();
        let known: HashSet<(usize, usize)> = spans.iter().map(|old| (old.start, old.end)).collect();
        for (start, end) in table_values(text) {
            if !known.contains(&(start, end)) {
                spans.push(Span::new(national, start, end, 1.0, NAME));
            }
        }
        spans
    }

    fn name(&self) -> &'static str {
        NAME
    }
}

/// An account or routing number glued to its cue or label word by PDF text
/// extraction (`Account number55555555`, `Acct No.12345678`); group 1 is the value.
static GLUED_ACCOUNT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:account|acct|routing|kontonummer|konto|kto\.?-nr|compte|rekeningnummer|rekeningnr)(?:\s*(?:number|num|no|nr))?\.?([0-9]{6,17})(?:[^0-9]|$)")
        .expect("glued account shape compiles")
});

/// A sort code glued to its cue (`Sort code20-20-15`); group 1 is the value.
static GLUED_SORT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bsort\s?code\.?([0-9]{2}[ -]?[0-9]{2}[ -]?[0-9]{2})(?:[^0-9-]|$)")
        .expect("glued sort code shape compiles")
});

/// A personal-identity label (`ID no.`, `identity card number`, `citizen ID`, `numéro
/// de carte d'identité`…) and the value after it (group 1), on the lowercased text. The
/// value may be written in groups (`1234 5678 9012`, `85.07.30-033.28`, `AB 123456`): each
/// later group starts with a digit, so a following word is never taken.
static ID_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:id(?:\s+card)?\s*(?:number\b|no\b\.?|#)|identity(?:\s+card)?\s+number\b|(?:national|personal|citizen)\s+id(?:entity)?\b(?:\s+card)?(?:\s*(?:number\b|no\b\.?|#))?|num[ée]ro\s+(?:de\s+carte\s+)?d['’]identit[ée]|n°\s*(?:d['’]identit[ée]|cni\b))(?:\s*(?:[:#=]|is\b|was\b))?\s*([a-z0-9]+(?:[ .-]?[0-9][a-z0-9]*)*)\b",
    )
    .expect("ID label shape compiles")
});

/// A bare `ID` and the value after it (group 1): `ID: …`, `ID …`, `my ID is …`.
static BARE_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bid\b(?:\s*[:#=]|\s+is\b)?\s*([a-z0-9]+(?:[ .-]?[0-9][a-z0-9]*)*)\b")
        .expect("bare ID shape compiles")
});

/// Words that make the `ID` after them a business reference (`order-line ID` too).
const BUSINESS_WORDS: &str =
    "order transaction invoice ticket booking tracking reference customer client account employee session request";

/// Words after which a bare `ID` is someone's own.
const POSSESSIVES: &[&str] = &["my", "his", "her", "their", "your"];

/// The generic IDs after a personal-identity label: 6 to 20 letters and digits with a
/// digit; after a bare `ID`, 9 or more, at a sentence start or after a possessive. A
/// business word right before `ID` (`order ID`, `customer ID number`) is no label.
fn id_label_values(lower: &str) -> Vec<(usize, usize)> {
    let labelled = ID_LABEL_RE
        .captures_iter(lower)
        .filter_map(|captures| Some((captures.get(0)?, captures.get(1)?)))
        .filter(|(label, value)| {
            !after_business_word(lower, *label) && id_value(value.as_str(), 6)
        });
    let bare = BARE_ID_RE
        .captures_iter(lower)
        .filter_map(|captures| Some((captures.get(0)?, captures.get(1)?)))
        .filter(|(label, value)| {
            bare_id_opens(lower, label.start()) && id_value(value.as_str(), 9)
        });
    // The caller sorts and dedups (a value both rules see is pushed twice).
    labelled
        .chain(bare)
        .map(|(_, v)| (v.start(), v.end()))
        .collect()
}

/// 6 (or `min`) to 20 letters and digits, a digit among them.
fn id_value(value: &str, min: usize) -> bool {
    let alnum = value.bytes().filter(u8::is_ascii_alphanumeric).count();
    (min..=20).contains(&alnum) && value.bytes().any(|b| b.is_ascii_digit())
}

/// The word right before `at`, without trailing spaces (`order-line` stays whole).
fn word_before(lower: &str, at: usize) -> &str {
    let head = lower[..at].trim_end_matches([' ', '\t']);
    let mut word = head.rsplit(|ch: char| !(ch.is_alphanumeric() || "-'".contains(ch)));
    word.next().unwrap_or_default()
}

/// Whether a business word stands right before a label that starts with `ID`.
fn after_business_word(lower: &str, label: regex::Match<'_>) -> bool {
    label.as_str().starts_with("id")
        && word_before(lower, label.start())
            .split(['-', '\''])
            .any(|part| BUSINESS_WORDS.split(' ').any(|word| word == part))
}

/// Whether a bare `ID` at `at` starts a sentence or follows a possessive.
fn bare_id_opens(lower: &str, at: usize) -> bool {
    let head = lower[..at].trim_end_matches([' ', '\t']);
    head.is_empty()
        || head.ends_with(['.', '!', '?', '\n', '\r'])
        || POSSESSIVES.contains(&word_before(lower, at))
}

/// Where the value after each whole-word cue starts: past the cue, a colon or
/// equals sign, and any label word.
fn value_starts(lower: &str, cues: &[&str]) -> Vec<usize> {
    let word_edge = |ch: Option<char>| ch.is_none_or(|ch| !ch.is_alphanumeric());
    let mut starts = Vec::new();
    for cue in cues {
        for (at, _) in lower.match_indices(cue) {
            let end = at + cue.len();
            if word_edge(lower[..at].chars().next_back()) && word_edge(lower[end..].chars().next())
            {
                starts.push(skip_labels(lower, end));
            }
        }
    }
    starts
}

/// Skip separators and label words (`no.`, `number`, `n°`) from `at`.
fn skip_labels(lower: &str, mut at: usize) -> usize {
    loop {
        let rest = &lower[at..];
        let trimmed = rest.trim_start_matches(|ch: char| {
            ch.is_whitespace() || matches!(ch, ':' | '=' | '#' | '.' | '°' | 'º' | '(' | ')')
        });
        at += rest.len() - trimmed.len();
        let word = trimmed
            .split(|ch: char| !ch.is_alphabetic())
            .next()
            .unwrap_or("");
        let glued = trimmed[word.len()..]
            .chars()
            .next()
            .is_some_and(char::is_alphanumeric);
        if word.is_empty() || glued || !LABEL_WORDS.contains(&word) {
            return at;
        }
        at += word.len();
    }
}

fn digit_run(bytes: &[u8], at: usize) -> usize {
    bytes[at..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count()
}

/// Whether a value ending at `end` stops at a word edge.
fn ends_value(lower: &str, end: usize) -> bool {
    lower[end..]
        .chars()
        .next()
        .is_none_or(|ch| !ch.is_alphanumeric())
}

/// Whether a stand-alone value may start at `at`: a digit that no letter, digit,
/// hyphen or slash precedes.
fn starts_token(bytes: &[u8], at: usize) -> bool {
    bytes[at].is_ascii_digit()
        && (at == 0
            || !(bytes[at - 1].is_ascii_alphanumeric() || matches!(bytes[at - 1], b'-' | b'/')))
}

/// Read `shape` at `start`: groups of exact widths, joined by one consistent
/// run of one to three spaces or `-`, `/` or `.` bytes (FIN-6 r1: an SSN written
/// `512  45  8873` joins like the slash and dot shapes do), or by nothing.
fn groups(bytes: &[u8], start: usize, shape: &[Group], glued: bool) -> Option<usize> {
    let mut at = start;
    let mut joint: Option<u8> = None;
    for (index, &(width, letters)) in shape.iter().enumerate() {
        if index > 0 {
            at += separator_run(bytes, at, &mut joint, glued)?;
        }
        for _ in 0..width {
            let byte = bytes.get(at)?;
            if !(byte.is_ascii_digit() || (letters && byte.is_ascii_alphabetic())) {
                return None;
            }
            at += 1;
        }
    }
    Some(at)
}

/// The joint at `at`: one to three of the same byte as the earlier joints. Zero
/// where a `glued` shape writes none, `None` where it must write one.
fn separator_run(bytes: &[u8], at: usize, joint: &mut Option<u8>, glued: bool) -> Option<usize> {
    let Some(&byte @ (b' ' | b'-' | b'.' | b'/')) = bytes.get(at) else {
        return glued.then_some(0);
    };
    if joint.is_some_and(|first| first != byte) {
        return glued.then_some(0);
    }
    *joint = Some(byte);
    let mut run = 0;
    while run < 3 && bytes.get(at + run) == Some(&byte) {
        run += 1;
    }
    Some(run)
}

/// FIN-6: a `/` or `.` joint must not run on into another group (`512/45/8873/1234`).
fn runs_on(at: usize, end: usize, bytes: &[u8]) -> bool {
    let Some(&joint @ (b'/' | b'.')) = bytes.get(at + 3) else {
        return false;
    };
    bytes.get(end) == Some(&joint) && bytes.get(end + 1).is_some_and(u8::is_ascii_digit)
}

/// A RIB whose four groups sit in table columns (`30004    00003    12345678901    43`).
static COLUMN_RIB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9]{5} {1,24}[0-9]{5} {1,24}[0-9a-z]{11} {1,24}[0-9]{2}\b")
        .expect("column RIB shape compiles")
});

/// A table cell: a run of words joined by single spaces or no-break spaces (a tab or
/// two spaces split cells).
static CELL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\S+(?:[ \x{a0}\x{202f}]\S+)*").expect("cell shape compiles"));

/// The cells read per table line: a statement has far fewer columns, and the cap
/// bounds the work per line pair.
const MAX_TABLE_CELLS: usize = 128;

/// The digit count a header cell announces for its column (a sort code, a routing
/// number, an account number), only when the cell is a label with no digit. Cues
/// match whole words only (`partner` holds no routing cue).
fn column_of(cell: &str) -> Option<(usize, usize)> {
    let lower = cell.to_lowercase();
    let has = |cues: &[&str]| !value_starts(&lower, cues).is_empty();
    if lower.bytes().any(|b| b.is_ascii_digit()) {
        None
    } else if has(SORT_CUES) {
        Some((6, 6))
    } else if has(ROUTING_CUES) {
        Some((9, 9))
    } else {
        (has(ACCOUNT_CUES) || has(ACCOUNT_CUES_INTL)).then_some((6, 17))
    }
}

/// Table values under a header line of at least two cells that names their column
/// (PDF text puts the header `Sort code   Account No.` on the line above
/// `20-20-15   55555555`; ruler and blank lines between them are skipped). The value
/// is the row cell in the same column when both lines have as many cells, else a row
/// cell sharing at least half of its or the header's character columns. An ISO date
/// is never a value. Each row cell is taken once. Offsets are original.
fn table_values(text: &str) -> Vec<(usize, usize)> {
    // (start, end, first column, end column): byte offsets in `text`, columns in chars.
    let cells = |line: &str| -> Vec<(usize, usize, usize, usize)> {
        let offset = line.as_ptr() as usize - text.as_ptr() as usize;
        let (mut seen, mut column) = (0, 0);
        let found = CELL_RE.find_iter(line).map(|cell| {
            let first = column + line[seen..cell.start()].chars().count();
            column = first + cell.as_str().chars().count();
            seen = cell.end();
            (offset + cell.start(), offset + cell.end(), first, column)
        });
        found.collect()
    };
    let ruler = |line: &str| {
        line.chars()
            .all(|ch| ch.is_whitespace() || "-=_+|─━═".contains(ch))
    };
    let lines: Vec<&str> = text.lines().filter(|line| !ruler(line)).collect();
    let mut found = Vec::new();
    for pair in lines.windows(2) {
        let (mut head, mut row) = (cells(pair[0]), cells(pair[1]));
        let same = head.len() == row.len();
        if head.len() < 2 {
            continue;
        }
        head.truncate(MAX_TABLE_CELLS);
        row.truncate(MAX_TABLE_CELLS);
        let mut taken = vec![false; row.len()];
        for (index, &(start, end, first, last)) in head.iter().enumerate() {
            let Some(digits) = column_of(&text[start..end]) else {
                continue;
            };
            let from = if same {
                index
            } else {
                row.partition_point(|cell| cell.3 <= first)
            };
            for (at, &(start, end, cell_first, cell_last)) in row.iter().enumerate().skip(from) {
                let shared = cell_last.min(last).saturating_sub(cell_first.max(first));
                let under = 2 * shared >= (cell_last - cell_first).min(last - first);
                if (same && at != index) || (!same && cell_first >= last) {
                    break;
                }
                if !same && !under {
                    continue;
                }
                let cell = &text.as_bytes()[start..end];
                let count = cell.iter().filter(|b| b.is_ascii_digit()).count();
                let iso_date = cell.len() == 10 && cell[4] == b'-' && cell[7] == b'-';
                if !taken[at]
                    && !iso_date
                    // PDF text groups digits with a no-break space too (`20\u{a0}20\u{a0}15`).
                    && text[start..end]
                        .chars()
                        .all(|ch| ch.is_ascii_digit() || matches!(ch, ' ' | '-' | '\u{a0}' | '\u{202f}'))
                    && cell[0].is_ascii_digit()
                    && cell[cell.len() - 1].is_ascii_digit()
                    && (digits.0..=digits.1).contains(&count)
                {
                    taken[at] = true;
                    found.push((start, end));
                }
            }
        }
    }
    found
}

/// The ABA routing checksum: weights 3-7-1 over nine digits, sum divisible by 10.
fn aba_ok(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .zip([3, 7, 1].into_iter().cycle())
        .map(|(digit, weight)| u32::from(digit - b'0') * weight)
        .sum();
    sum.is_multiple_of(10)
}

/// Whether an `AAA-GG-SSSS` value can be issued: area not 000, 666 or 9xx, group
/// not 00, serial not 0000.
fn ssn_issuable(value: &[u8]) -> bool {
    let digits: Vec<u8> = value
        .iter()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    let number = |part: &[u8]| part.iter().fold(0u32, |sum, d| sum * 10 + u32::from(*d));
    let (area, group, serial) = (
        number(&digits[..3]),
        number(&digits[3..5]),
        number(&digits[5..]),
    );
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// The French RIB key: `97 - (89 bank + 15 branch + 3 account) mod 97`, with the
/// letters of the account read as 1-9 (A-I, J-R) and 2-9 (S-Z).
fn rib_key_ok(value: &[u8]) -> bool {
    let compact: Vec<u8> = value
        .iter()
        .copied()
        .filter(u8::is_ascii_alphanumeric)
        .collect();
    let number = |part: &[u8]| {
        part.iter().fold(0u64, |sum, &byte| {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'i' => byte - b'a' + 1,
                b'j'..=b'r' => byte - b'j' + 1,
                _ => byte - b's' + 2,
            };
            sum * 10 + u64::from(digit)
        })
    };
    let (bank, branch) = (number(&compact[..5]), number(&compact[5..10]));
    let (account, key) = (number(&compact[10..21]), number(&compact[21..]));
    97 - (89 * bank + 15 * branch + 3 * account) % 97 == key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<&str> {
        PaymentIdsRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| &text[span.start..span.end])
            .collect()
    }

    #[test]
    fn a_card_security_code_after_its_cue() {
        assert_eq!(hits("Card 4111111111111111 CVV 737"), vec!["737"]);
        assert_eq!(hits("CVC: 4821"), vec!["4821"]);
        assert_eq!(hits("cvv2 = 318"), vec!["318"]);
        assert_eq!(hits("security code 905 on the back"), vec!["905"]);
        assert_eq!(hits("Card verification value: 123"), vec!["123"]);
        assert!(hits("CVV 12").is_empty());
        assert!(hits("CVV 12345").is_empty());
        assert!(hits("the cvv field").is_empty());
    }

    #[test]
    fn a_us_ssn_dashed_or_spaced_stands_alone() {
        assert_eq!(hits("SSN: 219-09-9999"), vec!["219-09-9999"]);
        assert_eq!(hits("number 219 09 9999."), vec!["219 09 9999"]);
        assert_eq!(hits("id 123-45-6789"), vec!["123-45-6789"]);
    }

    #[test]
    fn an_unissuable_or_misframed_ssn_is_left() {
        for text in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "123-00-3456",
            "123-45-0000",
            "Order 123-45-678 shipped",
            "2026-10-14",
            "1219-09-9999",
            "x219-09-9999",
            "219-09-99999",
        ] {
            assert!(hits(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn an_ssn_with_slashes_or_dots_is_masked() {
        assert_eq!(hits("SSN:512/45/8873"), vec!["512/45/8873"]);
        assert_eq!(hits("my SSN is 512.45.8873."), vec!["512.45.8873"]);
        assert_eq!(hits("| SSN | 512/45/8873 |"), vec!["512/45/8873"]);
        assert_eq!(hits("It was 512.45.8873."), vec!["512.45.8873"]);
        assert!(hits("SSN 512/45.8873").is_empty());
        assert!(hits("SSN 512/45/88731").is_empty());
        assert!(hits("see 000/45/8873 or 512/45/8873/12").is_empty());
    }

    #[test]
    fn a_plain_ssn_or_an_ein_needs_its_cue() {
        assert_eq!(hits("Social security 219099999"), vec!["219099999"]);
        assert_eq!(hits("SSN number: 219099999"), vec!["219099999"]);
        assert_eq!(hits("EIN 12-3456789"), vec!["12-3456789"]);
        assert_eq!(hits("Tax ID: 98-7654321"), vec!["98-7654321"]);
        assert_eq!(hits("TIN 987654321"), vec!["987654321"]);
        assert!(hits("Reference 219099999").is_empty());
        assert!(hits("a 12-3456789 b").is_empty());
        assert!(hits("being 12-3456789").is_empty());
    }

    #[test]
    fn a_routing_number_is_checked_and_cued_account_digits_are_masked() {
        let text = "Routing 021000021 Account 4567812345";
        assert_eq!(hits(text), vec!["021000021", "4567812345"]);
        let spans = PaymentIdsRecognizer::new().analyze("ABA 123456789");
        assert_eq!(spans.len(), 1);
        assert!(spans[0].score < 1.0);
        assert_eq!(
            hits("ABA 011401533 acct no. 123456789012"),
            vec!["011401533", "123456789012"]
        );
        assert_eq!(hits("Compte n° 00012345678"), vec!["00012345678"]);
        assert!(hits("Account 12345").is_empty());
        assert!(hits("Account 123456789012345678").is_empty());
        assert!(hits("Total 4567812345").is_empty());
    }

    #[test]
    fn a_uk_sort_code_after_its_cue() {
        assert_eq!(
            hits("Sort code 12-34-56, account 31926819"),
            vec!["12-34-56", "31926819"]
        );
        assert_eq!(hits("sortcode: 123456"), vec!["123456"]);
        assert_eq!(hits("Sort code 12 34 56"), vec!["12 34 56"]);
        assert!(hits("Due 12-34-56").is_empty());
    }

    #[test]
    fn a_french_rib_is_found_by_its_key() {
        assert_eq!(
            hits("RIB : 30006 00001 12345678901 89"),
            vec!["30006 00001 12345678901 89"]
        );
        assert_eq!(
            hits("30006-00001-12345678901-89"),
            vec!["30006-00001-12345678901-89"]
        );
        assert_eq!(
            hits("RIB 30006000011234567890189"),
            vec!["30006000011234567890189"]
        );
        assert!(hits("RIB : 30006 00001 12345678901 88").is_empty());
    }

    #[test]
    fn declared_name() {
        assert_eq!(PaymentIdsRecognizer::new().name(), "payment_ids");
    }
}
