//! Public-term allowlist for NER output, loaded from a config file.
//!
//! GLiNER fires on public names — well-known brands, ministries, capital
//! cities — that the corpus labels as "never mask". The kernel keeps those out
//! of the mask with a configurable allowlist rather than a hard-coded table:
//! [`PublicTerms::from_path`] reads the `qa/privacy-eval/public-terms.json`
//! shape (an object of per-language arrays of strings), and
//! [`PublicTerms::from_json_str`] accepts the same text inline.
//!
//! A small built-in list of global brands and capital cities is always merged
//! in, so the built-in data cannot drift away from the config file's entries.
//! Matching is diacritic- and case-insensitive and ignores surrounding
//! whitespace. Only organisation and address spans consult the list; a person
//! is never dropped this way.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// A set of public terms that must not be masked.
#[derive(Clone, Debug, Default)]
pub struct PublicTerms {
    terms: HashSet<String>,
}

impl PublicTerms {
    /// The built-in list of global brands and capital cities.
    pub fn builtin() -> Self {
        let mut terms = HashSet::new();
        for term in BUILTIN_TERMS {
            terms.insert(fold(term));
        }
        Self { terms }
    }

    /// Load the allowlist from a JSON config file, merged with the built-ins.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, String> {
        let text = fs::read_to_string(path.as_ref())
            .map_err(|error| format!("public terms {}: {error}", path.as_ref().display()))?;
        Self::from_json_str(&text)
    }

    /// Parse the allowlist from JSON text, merged with the built-ins.
    pub fn from_json_str(text: &str) -> Result<Self, String> {
        let mut terms = Self::builtin().terms;
        terms.extend(parse_json_terms(text)?.into_iter().map(|term| fold(&term)));
        Ok(Self { terms })
    }

    /// The number of known terms.
    pub fn len(&self) -> usize {
        self.terms.len()
    }

    /// Whether the allowlist holds no term at all.
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// Whether `value` (trimmed) is exactly a public term.
    pub fn contains(&self, value: &str) -> bool {
        let folded = fold(value);
        !folded.is_empty() && self.terms.contains(&folded)
    }

    /// Whether `token` appears as a whole word of some public term.
    ///
    /// This stops a public phrase such as `Orbite-17` from seeding `orbite` as
    /// a name token during propagation.
    pub fn covers_word(&self, token: &str) -> bool {
        let folded = fold(token);
        if folded.is_empty() {
            return false;
        }
        self.terms.iter().any(|term| {
            term == &folded
                || term
                    .split(|ch: char| !ch.is_alphanumeric())
                    .any(|word| word == folded)
        })
    }

    /// Add one term.
    pub fn insert(&mut self, term: &str) {
        let folded = fold(term);
        if !folded.is_empty() {
            self.terms.insert(folded);
        }
    }
}

/// Fold a string for comparison: NFD, drop combining marks, lowercase, trim,
/// and collapse internal whitespace to one space.
pub fn fold(value: &str) -> String {
    // ASCII has no decomposition and its lowercasing is one byte for one
    // byte, so the Unicode path below is pure overhead there.
    if value.is_ascii() {
        return fold_ascii(value);
    }
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for ch in value.nfd() {
        if is_combining_mark(ch) {
            continue;
        }
        for lowered in ch.to_lowercase() {
            if lowered.is_whitespace() {
                pending_space = !out.is_empty();
                continue;
            }
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(lowered);
        }
    }
    out
}

/// [`fold`] for ASCII input: lowercase each byte and collapse whitespace,
/// which is exactly what NFD plus `char::to_lowercase` does to ASCII.
fn fold_ascii(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for &byte in value.as_bytes() {
        let ch = byte as char;
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// Extract every JSON string literal that is a value (not an object key) from
/// `text`.
///
/// The corpus file is a flat object of arrays of strings; a full JSON parser
/// would drag serde into a library that deliberately stays serde-free. The
/// scanner supports exactly that shape and is documented as such: a string
/// literal followed (after whitespace) by `:` is a key and is skipped; every
/// other literal is a term.
fn parse_json_terms(text: &str) -> Result<Vec<String>, String> {
    let bytes = text.as_bytes();
    let mut terms = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let (literal, next) = parse_json_string(text, index)?;
        let mut lookahead = next;
        while lookahead < bytes.len() && bytes[lookahead].is_ascii_whitespace() {
            lookahead += 1;
        }
        let is_key = lookahead < bytes.len() && bytes[lookahead] == b':';
        if !is_key {
            terms.push(literal);
        }
        index = next;
    }
    Ok(terms)
}

/// Parse one JSON string literal starting at the opening quote.
fn parse_json_string(text: &str, start: usize) -> Result<(String, usize), String> {
    let bytes = text.as_bytes();
    let mut out = String::new();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Ok((out, index + 1)),
            b'\\' => {
                index += 1;
                if index >= bytes.len() {
                    break;
                }
                let escaped = bytes[index];
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hex = text
                            .get(index + 1..index + 5)
                            .ok_or_else(|| "public terms: truncated \\u escape".to_string())?;
                        let code = u32::from_str_radix(hex, 16)
                            .map_err(|_| "public terms: bad \\u escape".to_string())?;
                        let ch = char::from_u32(code)
                            .ok_or_else(|| "public terms: bad code point".to_string())?;
                        out.push(ch);
                        index += 4;
                    }
                    other => out.push(other as char),
                }
                index += 1;
            }
            _ => {
                let ch = text[index..]
                    .chars()
                    .next()
                    .ok_or_else(|| "public terms: bad UTF-8".to_string())?;
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    Err("public terms: unterminated string".to_string())
}

/// Global brands and capital cities that the NER model reaches for, kept small
/// and reviewed. The corpus config file adds the per-language public terms.
const BUILTIN_TERMS: &[&str] = &[
    // Brands and platforms.
    "Auxesis",
    "Google",
    "Apple",
    "Microsoft",
    "Amazon",
    "Meta",
    "Facebook",
    "Instagram",
    "WhatsApp",
    "LinkedIn",
    "X",
    "Twitter",
    "Netflix",
    "Adobe",
    "Oracle",
    "IBM",
    "Intel",
    "Nvidia",
    "Samsung",
    "Siemens",
    "Bosch",
    "Toyota",
    "Volkswagen",
    "Mercedes-Benz",
    "Coca-Cola",
    "Nike",
    "Adidas",
    "Starbucks",
    "Vodafone",
    "Orange",
    "Spotify",
    "Airbnb",
    "Uber",
    "PayPal",
    // Capital cities.
    "Paris",
    "London",
    "Berlin",
    "Madrid",
    "Rome",
    "Brussels",
    "Amsterdam",
    "Lisbon",
    "Vienna",
    "Warsaw",
    "Budapest",
    "Bucharest",
    "Sofia",
    "Athens",
    "Prague",
    "Dublin",
    "Copenhagen",
    "Stockholm",
    "Oslo",
    "Helsinki",
    "Tallinn",
    "Riga",
    "Vilnius",
    "Moscow",
    "Kyiv",
    "Ankara",
    "Rabat",
    "Cairo",
    "Tunis",
    "Algiers",
    "Pretoria",
    "Cape Town",
    "Johannesburg",
    "Washington",
    "Ottawa",
    "Canberra",
    "Tokyo",
    "Beijing",
    "New Delhi",
    "Brasília",
    "Mexico City",
    "Buenos Aires",
    "Nairobi",
    "Dakar",
    "Abu Dhabi",
    "Riyadh",
    "Doha",
    "Amman",
    "Beirut",
    "Baghdad",
    "Tehran",
    "Islamabad",
];

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::strategy::Strategy as _;

    #[test]
    fn builtin_terms_match_case_and_diacritics_insensitively() {
        let terms = PublicTerms::builtin();
        assert!(terms.contains("Auxesis"));
        assert!(terms.contains("dublin"));
        assert!(terms.contains("  CAPE TOWN "));
        assert!(!terms.contains("Tallowmere Ltd"));
    }

    #[test]
    fn json_config_is_parsed_and_merged_with_builtins() {
        let json =
            r#"{"fr":["Lyon","préfecture du Rhône"],"en":["Ministry of Transit","Auxesis"]}"#;
        let terms = PublicTerms::from_json_str(json).expect("parses");
        assert!(terms.contains("Lyon"));
        assert!(terms.contains("PRÉFECTURE DU RHÔNE"));
        assert!(terms.contains("préfecture du rhone"));
        assert!(terms.contains("Ministry of Transit"));
        // The built-ins survive the merge.
        assert!(terms.contains("Dublin"));
        // A value that is not in the file is not a public term.
        assert!(!terms.contains("Tallowmere"));
    }

    #[test]
    fn covers_word_finds_a_token_inside_a_term() {
        let mut terms = PublicTerms::builtin();
        terms.insert("Orbite-17");
        assert!(terms.covers_word("orbite"));
        assert!(!terms.covers_word("tallowmere"));
    }

    #[test]
    fn fold_strips_marks_and_collapses_space() {
        assert_eq!(fold("Océane   MABILLE"), "oceane mabille");
        assert_eq!(fold("  Née le "), "nee le");
    }

    /// The full NFD/lowercase fold, kept as the oracle for the ASCII fast path.
    fn fold_reference(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        let mut pending_space = false;
        for ch in unicode_normalization::UnicodeNormalization::nfd(value) {
            if unicode_normalization::char::is_combining_mark(ch) {
                continue;
            }
            for lowered in ch.to_lowercase() {
                if lowered.is_whitespace() {
                    pending_space = !out.is_empty();
                    continue;
                }
                if pending_space {
                    out.push(' ');
                    pending_space = false;
                }
                out.push(lowered);
            }
        }
        out
    }

    #[test]
    fn fold_ascii_fast_path_matches_the_unicode_path_on_edges() {
        for value in [
            "",
            " \t\n\x0b\x0c\r",
            "  Mixed CASE  ",
            "Full\u{ff11}\u{ff12}",
            "zero\u{200b}width",
            "join\u{200d}er\u{feff}",
            "e\u{301}cole",
            "\u{130}stanbul",
            "\u{a0}nbsp\u{202f}",
            "\u{ff21}\u{ff22}\u{4e2d}",
        ] {
            assert_eq!(fold(value), fold_reference(value), "{value:?}");
        }
    }

    /// Every ASCII byte, alone and in short mixed strings: the fast branch is
    /// covered by enumeration, not by a proptest strategy.
    #[test]
    fn fold_ascii_fast_path_matches_every_byte() {
        for byte in 0x00u8..=0x7f {
            let ch = char::from(byte);
            for value in [
                ch.to_string(),
                format!("a{ch}Z 9"),
                format!("  {ch}\t"),
                format!("x{ch}y"),
            ] {
                assert_eq!(fold(&value), fold_reference(&value), "{value:?}");
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        #[test]
        fn fold_fast_path_matches_the_unicode_path(value in fold_text()) {
            proptest::prop_assert_eq!(fold(&value), fold_reference(&value), "{:?}", value);
        }
    }

    /// ASCII, mixed and non-ASCII text: marks, invisibles, full-width forms
    /// and the whitespace the fold treats specially.
    fn fold_text() -> impl proptest::strategy::Strategy<Value = String> {
        proptest::collection::vec(
            proptest::prop_oneof![
                proptest::prelude::any::<char>(),
                proptest::sample::select(vec![
                    ' ', '\t', '\n', '\u{0b}', '"', '\u{e9}', '\u{301}', '\u{200b}', '\u{200d}',
                    '\u{feff}', '\u{ff11}', '\u{ff21}', '\u{a0}',
                ]),
            ],
            0..40,
        )
        .prop_map(|chars| chars.into_iter().collect())
    }
}
