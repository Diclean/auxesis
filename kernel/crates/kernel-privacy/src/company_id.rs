//! Context-keyword company and tax identifiers.
//!
//! A legal footer carries a registration number that no bare checksum rule can
//! justify on its own: a ZA registration (`Reg. No. 2019/123456/07`), a
//! Hungarian company number (`Cégjegyzékszám: 01-09-123456`) or tax number
//! (`Adószám: 12345678-2-42`), a RU ИНН/ОГРН, a UK Companies House number or a
//! GB VAT number, an AR commercial registration. Each rule is gated on the
//! keyword that names the format; where an official check exists (RU ИНН and
//! ОГРН, GB VAT) a candidate that fails it is not emitted, and where none
//! exists the keyword gate is the whole rule.
//!
//! Every hit is labelled [`EntityKind::NationalId`]: the specific register is
//! not a kind the kernel has, and the policy is to mask rather than to guess a
//! label. The module works on the normalised view, so a `&nbsp;` or a Unicode
//! dash inside a number does not hide it, and every span is mapped back to the
//! original bytes.

use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::NormalizedText;
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Score of a keyword-gated, format-valid company identifier.
pub const SCORE: f32 = 1.0;

/// How many characters before a candidate the keyword window looks.
const KEYWORD_WINDOW: usize = 48;

static ZA_REG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{4}/\d{6}/\d{2}").expect("za registration regex compiles"));
static HU_CEG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d{2}[\s.-]?\d{2}[\s.-]?\d{6}").expect("hu company regex compiles")
});
static HU_ADO_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{8}[\s.-]?\d[\s.-]?\d{2}").expect("hu tax regex compiles"));
static RU_INN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{12}\b|\b\d{10}\b").expect("ru inn regex compiles"));
static RU_OGRN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{15}\b|\b\d{13}\b").expect("ru ogrn regex compiles"));
static UK_COMPANY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z]{2}\d{6}\b|\b\d{8}\b").expect("uk company regex compiles")
});
static GB_VAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?i:GB)[ ./-]?(?:GD[ ./-]?\d{3}|HA[ ./-]?\d{3}|\d{3}[ ./-]?\d{4}[ ./-]?\d{2}[ ./-]?\d{3}|\d{3}[ ./-]?\d{4}[ ./-]?\d{2})\b",
    )
    .expect("gb vat regex compiles")
});
static BARE_VAT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{3}[ ./-]?\d{4}[ ./-]?\d{2}[ ./-]?\d{3}\b|\b\d{3}[ ./-]?\d{4}[ ./-]?\d{2}\b")
        .expect("bare vat regex compiles")
});
static GENERIC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{8,15}").expect("generic company regex compiles"));

/// Keywords, per rule, that name the register. Case-insensitive.
const ZA_KEYWORDS: &[&str] = &["reg", "verw", "registration", "company"];
const HU_CEG_KEYWORDS: &[&str] = &[
    "cégjegyzékszám",
    "cegjegyzekszam",
    "cégjegyzék",
    "cegjegyzek",
    "cégjegyzés",
    "company registration",
];
const HU_ADO_KEYWORDS: &[&str] = &["adószám", "adoszam", "tax number", "vat number"];
const RU_INN_KEYWORDS: &[&str] = &["инн", "inn"];
const RU_OGRN_KEYWORDS: &[&str] = &["огрн", "ogrn"];
const UK_COMPANY_KEYWORDS: &[&str] = &[
    "company no",
    "company number",
    "companies house",
    "registered in england",
    "company registration",
];
const GB_VAT_KEYWORDS: &[&str] = &["vat", "tva", "áfa"];
const GENERIC_KEYWORDS: &[&str] = &[
    "company ref",
    "company no",
    "company number",
    "companies house",
    "company registration",
    "matrícula",
    "matricula",
    "registro",
    "السجل التجاري",
];
static AR_REG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{4,12}").expect("ar registration regex compiles"));

/// A deterministic recogniser for keyword-gated company and tax identifiers.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompanyIdRecognizer;

impl CompanyIdRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for CompanyIdRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::NationalId]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        recognize(text)
    }

    fn name(&self) -> &'static str {
        "company_id"
    }
}

/// Find every keyword-gated company or tax identifier in `text`.
pub fn recognize(text: &str) -> Vec<Span> {
    let normalized = NormalizedText::new(text, false);
    let body = normalized.text();
    let mut spans = Vec::new();
    let mut push = |start: usize, end: usize| {
        if let Some((start, end)) = normalized.to_original(start, end) {
            spans.push(Span::new(
                EntityKind::NationalId,
                start,
                end,
                SCORE,
                "company_id",
            ));
        }
    };

    // ZA registration number, e.g. `Reg. No. 2018/501276/08`.
    for found in ZA_REG_RE.find_iter(body) {
        if keyword_before(body, found.start(), ZA_KEYWORDS) {
            push(found.start(), found.end());
        }
    }
    // Hungarian company number and tax number.
    for found in HU_CEG_RE.find_iter(body) {
        if keyword_before(body, found.start(), HU_CEG_KEYWORDS) {
            push(found.start(), found.end());
        }
    }
    for found in HU_ADO_RE.find_iter(body) {
        if keyword_before(body, found.start(), HU_ADO_KEYWORDS) {
            push(found.start(), found.end());
        }
    }
    // RU ИНН: 10 digits (legal entity) or 12 (individual), official checksum.
    for found in RU_INN_RE.find_iter(body) {
        if keyword_before(body, found.start(), RU_INN_KEYWORDS) && ru_inn_ok(found.as_str()) {
            push(found.start(), found.end());
        }
    }
    // RU ОГРН: 13 digits (organisation) or 15 (sole trader), official checksum.
    for found in RU_OGRN_RE.find_iter(body) {
        if keyword_before(body, found.start(), RU_OGRN_KEYWORDS) && ru_ogrn_ok(found.as_str()) {
            push(found.start(), found.end());
        }
    }
    // UK Companies House number: eight characters, keyword-gated.
    for found in UK_COMPANY_RE.find_iter(body) {
        if keyword_before(body, found.start(), UK_COMPANY_KEYWORDS) {
            push(found.start(), found.end());
        }
    }
    // GB VAT: grouped or compact `GB` numbers, plus the checksum-exempt GD/HA
    // government series. A branch suffix is part of the same VAT span.
    for found in GB_VAT_RE.find_iter(body) {
        let value = found.as_str();
        let compact: String = value.chars().filter(char::is_ascii_alphanumeric).collect();
        let special = compact.get(2..4).is_some_and(|prefix| {
            prefix.eq_ignore_ascii_case("GD") || prefix.eq_ignore_ascii_case("HA")
        });
        let digits: String = value.chars().filter(char::is_ascii_digit).collect();
        let labelled = keyword_before(body, found.start(), GB_VAT_KEYWORDS);
        if special || labelled || gb_vat_ok(&digits) {
            push(found.start(), found.end());
        }
    }
    // A bare VAT number behind its keyword (`VAT 123 4567 82`).
    for found in BARE_VAT_RE.find_iter(body) {
        if keyword_before(body, found.start(), GB_VAT_KEYWORDS) {
            push(found.start(), found.end());
        }
    }
    // AR commercial registration: keyword-gated digits only.
    for found in AR_REG_RE.find_iter(body) {
        if keyword_before(body, found.start(), GENERIC_KEYWORDS) {
            push(found.start(), found.end());
        }
    }
    // A generic keyword-gated company reference: `company ref 6413410477086`.
    for found in GENERIC_RE.find_iter(body) {
        if keyword_before(body, found.start(), GENERIC_KEYWORDS) {
            push(found.start(), found.end());
        }
    }
    // Overlapping rules (for example the HU tax shape and the generic rule) can
    // describe the same bytes; merge them so the recogniser's output is a clean,
    // non-overlapping set.
    crate::recognizer::resolve_overlaps(spans)
}

/// Whether any keyword appears as a word in the [`KEYWORD_WINDOW`] characters
/// before `start`.
fn keyword_before(body: &str, start: usize, keywords: &[&str]) -> bool {
    let begin = body[..start]
        .char_indices()
        .rev()
        .nth(KEYWORD_WINDOW)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let window = body[begin..start].to_lowercase();
    keywords
        .iter()
        .any(|keyword| contains_word(&window, keyword))
}

/// Find `needle` in `haystack` at a word boundary.
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut from = 0usize;
    while let Some(offset) = haystack[from..].find(needle) {
        let absolute = from + offset;
        let before_ok = haystack[..absolute]
            .chars()
            .next_back()
            .is_none_or(|ch| !ch.is_alphanumeric());
        let after = absolute + needle.len();
        let after_ok = haystack[after..]
            .chars()
            .next()
            .is_none_or(|ch| !ch.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        from = absolute + needle.len();
        if from >= haystack.len() {
            break;
        }
    }
    false
}

/// RU ИНН checksum: 11-mod-10 on the 10-digit weights, twice for 12 digits.
pub(crate) fn ru_inn_ok(digits: &str) -> bool {
    if digits.len() == 10 {
        return check_weighted(
            digits,
            &[2, 4, 10, 3, 5, 9, 4, 6, 8],
            digits.as_bytes()[9] - b'0',
        );
    }
    if digits.len() == 12 {
        let first = check_weighted(
            digits,
            &[7, 2, 4, 10, 3, 5, 9, 4, 6, 8],
            digits.as_bytes()[10] - b'0',
        );
        let second = check_weighted(
            digits,
            &[3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8],
            digits.as_bytes()[11] - b'0',
        );
        return first && second;
    }
    false
}

/// RU ОГРН checksum: the first `n - 1` digits mod 11, taken mod 10, is the last
/// digit.
pub(crate) fn ru_ogrn_ok(digits: &str) -> bool {
    if digits.len() != 13 && digits.len() != 15 {
        return false;
    }
    let Some(stem) = digits[..digits.len() - 1].parse::<u128>().ok() else {
        return false;
    };
    let expected = (stem % 11 % 10) as u8;
    digits.as_bytes()[digits.len() - 1] - b'0' == expected
}

/// GB VAT mod-97 / 9755: the first seven digits weighted 8..2 plus the two
/// check digits must be 0 modulo 97, or 42 modulo 97 for the parallel 9755
/// series. A 12-digit number checks its nine-digit stem.
pub(crate) fn gb_vat_ok(digits: &str) -> bool {
    if digits.len() != 9 && digits.len() != 12 {
        return false;
    }
    let stem = &digits[..9];
    let bytes = stem.as_bytes();
    let mut sum = 0u32;
    for (index, weight) in [8u32, 7, 6, 5, 4, 3, 2].iter().enumerate() {
        sum += (bytes[index] - b'0') as u32 * weight;
    }
    let tail = (bytes[7] - b'0') as u32 * 10 + (bytes[8] - b'0') as u32;
    matches!((sum + tail) % 97, 0 | 42)
}

/// Weighted sum mod 11 mod 10 equals `expected`.
fn check_weighted(digits: &str, weights: &[u32], expected: u8) -> bool {
    let bytes = digits.as_bytes();
    let sum: u32 = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| (bytes[index] - b'0') as u32 * weight)
        .sum();
    (sum % 11 % 10) as u8 == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        recognize(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn za_registration_is_found_behind_its_keyword() {
        assert_eq!(
            hits("Firm, Reg. No. 2019/123456/07."),
            vec!["2019/123456/07"]
        );
        assert_eq!(hits("(verw. 2009/694899/06)"), vec!["2009/694899/06"]);
        // No keyword, no mask.
        assert!(hits("number 2019/123456/07").is_empty());
    }

    #[test]
    fn hungarian_company_and_tax_numbers_are_found() {
        assert_eq!(
            hits("Csillagház Kft., Cégjegyzékszám: 41-07-612290, Adószám: 14409199-6-65."),
            vec!["41-07-612290", "14409199-6-65"]
        );
        assert!(hits("szám 41-07-612290").is_empty());
    }

    #[test]
    fn ru_inn_and_ogrn_checksums_gate_the_hit() {
        // Synthetic vectors generated from the official checksum rules; no real
        // entity is named.
        assert!(ru_inn_ok("1234567894"));
        assert!(!ru_inn_ok("1234567895"));
        assert_eq!(hits("ИНН 1234567894"), vec!["1234567894"]);
        assert!(hits("ИНН 1234567895").is_empty());
        // ОГРН: first 12 digits mod 11 mod 10 is the last digit.
        assert!(ru_ogrn_ok("1234567890127"));
        assert!(!ru_ogrn_ok("1234567890124"));
        assert_eq!(hits("ОГРН 1234567890127"), vec!["1234567890127"]);
    }

    #[test]
    fn gb_vat_mod97_and_uk_company_numbers() {
        assert!(gb_vat_ok("123456782"));
        assert!(!gb_vat_ok("123456783"));
        assert!(gb_vat_ok("123456727")); // Parallel 9755 series.
        assert!(!gb_vat_ok("123456789"));
        assert_eq!(hits("VAT GB123456782"), vec!["GB123456782"]);
        assert_eq!(hits("Company No. 12345678"), vec!["12345678"]);
        assert!(hits("reference 12345678").is_empty());
    }

    #[test]
    fn gb_vat_grouping_branches_and_special_prefixes() {
        for (text, expected) in [
            ("GB 123 4567 82", "GB 123 4567 82"),
            ("GB123 4567 82", "GB123 4567 82"),
            ("VAT reg no. 123 4567 82", "123 4567 82"),
            ("VAT: GB 123 4567 82 000", "GB 123 4567 82 000"),
            ("GB 123 4567 27 000", "GB 123 4567 27 000"),
            ("GBGD001", "GBGD001"),
            ("GBHA500", "GBHA500"),
        ] {
            assert_eq!(hits(text), vec![expected], "{text:?}");
        }
        let text = "VAT reg no. 123\u{00a0}4567\u{00a0}82";
        assert_eq!(hits(text), vec!["123\u{00a0}4567\u{00a0}82"]);
        let text = "GB\u{2009}123\u{2009}4567\u{2009}82";
        assert_eq!(hits(text), vec![text]);
        assert!(hits("GB 123 4567 89 is just prose").is_empty());
        assert_eq!(hits("gb 123 4567 82"), vec!["gb 123 4567 82"]);
        assert_eq!(hits("VAT reg no. 123 4567 89"), vec!["123 4567 89"]);
        assert_eq!(hits("TVA intracom.,123 4567 82"), vec!["123 4567 82"]);
        assert!(hits("123 4567 89").is_empty());
    }

    #[test]
    fn generic_company_reference_is_found() {
        assert_eq!(
            hits("in the name of Glenfallow Joinery (company ref 6413410477086)"),
            vec!["6413410477086"]
        );
    }

    #[test]
    fn normalised_view_maps_back_to_the_original_bytes() {
        // A NBSP inside the number is decoded by the normalisation layer.
        let text = "Adószám: 14409199\u{00A0}6\u{00A0}65";
        let spans = recognize(text);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            &text[spans[0].start..spans[0].end],
            "14409199\u{00A0}6\u{00A0}65"
        );
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = CompanyIdRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::NationalId]);
        assert_eq!(recognizer.name(), "company_id");
    }
}
