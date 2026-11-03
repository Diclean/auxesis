//! French identifier recognisers (Presidio has no French pack).
//!
//! Enablement follows slice 1c and the identifiers research doc: NIR and SIRET
//! stay `verified: false` (and so off by default) until their rules are
//! confirmed against an official source.
//! SIREN (Luhn) and numeric-key VAT are deterministic and enabled.
//!
//! Every recogniser scans the shared normalised view and uses digit-run
//! boundaries (P2-2), so a letter glued to a value or an OCR-confused digit
//! does not hide it.

use crate::checksum::{
    fr_nir_ok, fr_nir_shape_ok, fr_siren_ok, fr_siret_ok, fr_siret_shape_ok, fr_vat_ok,
};
use crate::normalize::{ascii_digits, consume_alnum, numeric_runs, NormalizedText};
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Score of a checksum-invalid value whose shape is still the identifier's.
/// For an unverified recogniser the registry clamps it to `NATIONAL_ID`, but
/// the span stays below a checksum-valid hit so the score records the doubt
/// (P2-3).
pub const INVALID_SCORE: f32 = 0.55;

/// NIR: thirteen digits or fifteen with the key (`97 - n mod 97`), Corsica
/// `2A`/`2B` handled. The structure must hold; the key only sets the score.
#[derive(Clone, Copy, Debug)]
pub struct FrNirRecognizer {
    verified: bool,
}

impl FrNirRecognizer {
    /// Build the recogniser (unverified, disabled by default).
    pub fn new() -> Self {
        Self { verified: false }
    }
}

impl Default for FrNirRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for FrNirRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::FrNir]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        let mut found = nir_candidates(normalized.text());
        // FIN-6: a NIR whose groups two or three spaces join is read on a view
        // where each such run is one space; it adds only where none was found.
        if normalized.text().contains("  ") {
            let (squeezed, at) = squeeze_spaces(normalized.text());
            let old = found.len();
            // FIN-6: the first-pass spans are sorted by start, so the furthest
            // end among those before a candidate answers the overlap test and a
            // binary search picks that prefix; scanning them all was quadratic.
            let mut far = Vec::with_capacity(old);
            let mut reach = 0;
            for &(_, end) in &found {
                reach = reach.max(end);
                far.push(reach);
            }
            for (start, end) in nir_candidates(&squeezed) {
                let (from, to) = (at[start], at[end - 1] + 1);
                let before = found[..old].partition_point(|&(s, _)| s < to);
                let overlap = before.checked_sub(1).map_or(0, |last| far[last]) > from;
                if !overlap {
                    found.push((from, to));
                }
            }
        }
        found
            .into_iter()
            .filter_map(|(start, end)| {
                let score = if fr_nir_ok(&normalized.text()[start..end]) {
                    1.0
                } else {
                    INVALID_SCORE
                };
                normalized
                    .to_original(start, end)
                    .map(|(start, end)| Span::new(EntityKind::FrNir, start, end, score, "fr_nir"))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "fr_nir"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// SIREN: nine digits, Luhn-valid.
#[derive(Clone, Copy, Debug)]
pub struct FrSirenRecognizer {
    verified: bool,
}

impl FrSirenRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self { verified: true }
    }
}

impl Default for FrSirenRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for FrSirenRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::FrSiren]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        digit_runs_with(normalized.text(), 9, fr_siren_ok)
            .into_iter()
            .filter_map(|(start, end)| normalized.to_original(start, end))
            .map(|(start, end)| Span::new(EntityKind::FrSiren, start, end, 1.0, "fr_siren"))
            .collect()
    }

    fn name(&self) -> &'static str {
        "fr_siren"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// SIRET: fourteen digits, Luhn with the La Poste digit-sum exception.
#[derive(Clone, Copy, Debug)]
pub struct FrSiretRecognizer {
    verified: bool,
}

impl FrSiretRecognizer {
    /// Build the recogniser (unverified, disabled by default).
    pub fn new() -> Self {
        Self { verified: false }
    }
}

impl Default for FrSiretRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for FrSiretRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::FrSiret]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        numeric_runs(normalized.text())
            .into_iter()
            .filter(|(start, end)| {
                let digits = ascii_digits(&normalized.text()[*start..*end]);
                digits.len() == 14
            })
            .filter_map(|(start, end)| {
                let digits = ascii_digits(&normalized.text()[start..end]);
                if !fr_siret_shape_ok(&digits) {
                    return None;
                }
                let score = if fr_siret_ok(&digits) {
                    1.0
                } else {
                    INVALID_SCORE
                };
                normalized.to_original(start, end).map(|(start, end)| {
                    Span::new(EntityKind::FrSiret, start, end, score, "fr_siret")
                })
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "fr_siret"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// French VAT, numeric-key form (`FR` + key + SIREN).
#[derive(Clone, Copy, Debug)]
pub struct FrVatRecognizer {
    verified: bool,
}

impl FrVatRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self { verified: true }
    }
}

impl Default for FrVatRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for FrVatRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::FrVat]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        vat_candidates(normalized.text())
            .into_iter()
            .filter_map(|(start, end)| normalized.to_original(start, end))
            .map(|(start, end)| Span::new(EntityKind::FrVat, start, end, 1.0, "fr_vat"))
            .collect()
    }

    fn name(&self) -> &'static str {
        "fr_vat"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// Every maximal digit run with exactly `length` digits that passes `check`.
fn digit_runs_with(text: &str, length: usize, check: fn(&str) -> bool) -> Vec<(usize, usize)> {
    numeric_runs(text)
        .into_iter()
        .filter(|(start, end)| {
            let digits = ascii_digits(&text[*start..*end]);
            digits.len() == length && check(&digits)
        })
        .collect()
}

/// Scan NIR candidates, spaced forms included (P0/P1 follow-up). A candidate
/// starts at a sex digit, is thirteen or fifteen digits (bar the Corsica
/// `2A`/`2B` department), and passes [`fr_nir_shape_ok`]. The key is optional:
/// a wrong or missing one still fires, at the lower [`INVALID_SCORE`] (fail
/// toward masking; the round-3 typo rule). The scan never starts inside a
/// digit run, and a candidate that ends inside a longer digit run is refused.
/// `text` with each run of two or three spaces between two ASCII letters or
/// digits read as one space, and the byte of `text` each byte of it comes from.
fn squeeze_spaces(text: &str) -> (String, Vec<usize>) {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut at = Vec::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let run = bytes[index..]
            .iter()
            .take(4)
            .take_while(|&&b| b == b' ')
            .count();
        let edges = index > 0
            && bytes[index - 1].is_ascii_alphanumeric()
            && bytes
                .get(index + run)
                .is_some_and(u8::is_ascii_alphanumeric);
        if (2..=3).contains(&run) && edges {
            out.push(' ');
            at.push(index);
            index += run;
            continue;
        }
        let len = text[index..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&text[index..index + len]);
        at.extend(index..index + len);
        index += len;
    }
    (out, at)
}

fn nir_candidates(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let runs = AlnumRuns::new(bytes);
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let sex_digit = matches!(bytes[index], b'1' | b'2' | b'3' | b'4' | b'7' | b'8');
        if !sex_digit {
            index += 1;
            continue;
        }
        if index == 0 || !bytes[index - 1].is_ascii_digit() {
            if let Some(end) = nir_end(text, &runs, index) {
                found.push((index, end));
                index = end;
                continue;
            }
        }
        if let Some(end) = hex_glued_nir_end(text, &runs, index) {
            found.push((index, end));
        }
        index += 1;
    }
    found
}

/// The end of a fifteen-character NIR with a valid key that starts at `start`
/// and is glued, on one side only, to a hex run holding a letter: a NIR pasted
/// against a hash (`1841276451089460f3a9…`, `…e9184127645108946`). The hex rule
/// of [`nir_end`] drops it; the key makes a chance hit at a hash's edge about
/// one in 10^5. Glued on both sides, it stays part of the hash.
fn hex_glued_nir_end(text: &str, runs: &AlnumRuns, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = consume_alnum(text, start, 15);
    let candidate = &text[start..end];
    if alnum_count(candidate) != 15 || !fr_nir_shape_ok(candidate) || !fr_nir_ok(candidate) {
        return None;
    }
    let alnum = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_alphanumeric);
    let glued = match (start > 0 && alnum(start - 1), alnum(end)) {
        (true, false) => {
            let begin = runs.left[start];
            // `0x` is the usual prefix for a hex literal, but the `x` itself
            // is not a hex digit and must not disqualify the run before NIR.
            let hex_begin = text
                .get(begin..begin + 2)
                .filter(|prefix| prefix.eq_ignore_ascii_case("0x"))
                .map_or(begin, |_| begin + 2);
            runs.hex_word(hex_begin, start)
        }
        (false, true) => runs.hex_word(end, runs.right[end]),
        _ => false,
    };
    glued.then_some(end)
}

/// The end of the NIR candidate that starts at `start`: the fifteen-character
/// form first, then the thirteen-character one. Each must pass the shape, end
/// before a digit, and sit outside an opaque token (a hex run or a Base64 one).
fn nir_end(text: &str, runs: &AlnumRuns, start: usize) -> Option<usize> {
    [15, 13].into_iter().find_map(|length| {
        let end = consume_alnum(text, start, length);
        let candidate = &text[start..end];
        let whole = alnum_count(candidate) == length
            && !text.as_bytes().get(end).is_some_and(u8::is_ascii_digit);
        let opaque =
            inside_hex_run(runs, start, end) || inside_base64_token(text, runs, start, end);
        (whole && fr_nir_shape_ok(candidate) && !opaque).then_some(end)
    })
}

/// The ASCII alphanumeric run bounds and a hex prefix count, built once per
/// text, so each candidate looks up its surrounding run in constant time
/// instead of rescanning it (the scan stays linear on one long glued run).
struct AlnumRuns {
    /// `left[i]`: the first byte of the alphanumeric run that ends at `i`.
    left: Vec<usize>,
    /// `right[i]`: the end of the alphanumeric run that starts at `i`.
    right: Vec<usize>,
    /// `non_hex[i]`: how many of the bytes before `i` are not hex digits.
    non_hex: Vec<usize>,
    /// `digits[i]`: how many of the bytes before `i` are ASCII digits.
    digits: Vec<usize>,
}

impl AlnumRuns {
    fn new(bytes: &[u8]) -> Self {
        let len = bytes.len();
        let mut left = vec![0; len + 1];
        let mut non_hex = vec![0; len + 1];
        let mut digits = vec![0; len + 1];
        for index in 0..len {
            digits[index + 1] = digits[index] + usize::from(bytes[index].is_ascii_digit());
            left[index + 1] = if bytes[index].is_ascii_alphanumeric() {
                left[index]
            } else {
                index + 1
            };
            non_hex[index + 1] = non_hex[index] + usize::from(!bytes[index].is_ascii_hexdigit());
        }
        let mut right = vec![len; len + 1];
        for index in (0..len).rev() {
            right[index] = if bytes[index].is_ascii_alphanumeric() {
                right[index + 1]
            } else {
                index
            };
        }
        Self {
            left,
            right,
            non_hex,
            digits,
        }
    }

    /// The alphanumeric run around `start..end`, extended from both ends.
    fn around(&self, start: usize, end: usize) -> (usize, usize) {
        (self.left[start], self.right[end])
    }

    fn all_hex(&self, begin: usize, finish: usize) -> bool {
        self.non_hex[finish] == self.non_hex[begin]
    }

    /// Whether `begin..finish` is a non-empty hex run with at least one letter.
    fn hex_word(&self, begin: usize, finish: usize) -> bool {
        begin < finish
            && self.all_hex(begin, finish)
            && self.digits[finish] - self.digits[begin] < finish - begin
    }
}

/// Whether the alphanumeric run around `start..end` is all hex digits and longer
/// than the candidate: a NIR inside a hash, a UUID or a git SHA written without
/// dashes. A letter glued to a value does not count (P2-2), and a spaced
/// candidate is never a hex run, since its spaces are not hex digits.
fn inside_hex_run(runs: &AlnumRuns, start: usize, end: usize) -> bool {
    let (begin, finish) = runs.around(start, end);
    finish - begin > end - start && runs.all_hex(begin, finish)
}

/// Shortest opaque token, `=` padding included, that a NIR candidate glued
/// directly to its letters or digits counts as part of.
const OPAQUE_TOKEN_MIN: usize = 20;

/// Whether the candidate at `start..end` is glued to a longer opaque token: the
/// run of ASCII letters and digits around it, with up to two `=` padding
/// characters at its end, is at least [`OPAQUE_TOKEN_MIN`] long, and a letter or
/// digit touches the candidate on at least one side. A separator (`/ ? & = # :
/// ; , . - _ +` or a space) or a boundary on both sides makes the candidate a
/// whole segment, which always fires, whatever the run around it: a URL path
/// part, a query value, a CSV or JSON field. A spaced, dotted or dashed
/// candidate is never a token.
fn inside_base64_token(text: &str, runs: &AlnumRuns, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    let alnum = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_alphanumeric);
    let glued = (start > 0 && alnum(start - 1)) || alnum(end);
    if !glued || !bytes[start..end].iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let (begin, finish) = runs.around(start, end);
    let padding = bytes[finish..]
        .iter()
        .take(2)
        .take_while(|byte| **byte == b'=')
        .count();
    finish - begin + padding >= OPAQUE_TOKEN_MIN
}

/// `FR` (any case) plus a two-character key and a SIREN, with any of the usual
/// separators (`FR 40303265045`, `FR 40 303 265 045`). Scans the shared
/// normalised view, so Unicode spaces and dashes are already ` ` / `-`.
fn vat_candidates(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index + 2 <= bytes.len() {
        let marker = bytes[index].eq_ignore_ascii_case(&b'F')
            && bytes[index + 1].eq_ignore_ascii_case(&b'R');
        let left_ok = index == 0 || !bytes[index - 1].is_ascii_alphanumeric();
        if !marker || !left_ok {
            index += 1;
            continue;
        }
        let end = consume_alnum(text, index, 13);
        let right_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if alnum_count(&text[index..end]) == 13 && right_ok && fr_vat_ok(&text[index..end]) {
            found.push((index, end));
            index = end;
            continue;
        }
        index += 1;
    }
    found
}

fn alnum_count(value: &str) -> usize {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits<R: Recognizer>(recognizer: &R, text: &str) -> Vec<String> {
        recognizer
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn nir_scan_is_linear_on_a_long_glued_letter_digit_run() {
        // K13 seal r2: every sex digit in one long alphanumeric run used to
        // rescan the whole run (zero-width chars fold away, so this is one run).
        let text = "AB1\u{200b}2".repeat(24 * 1024);
        let started = std::time::Instant::now();
        let _ = FrNirRecognizer::new().analyze(&text);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "fr_nir took {:?} on {} bytes",
            started.elapsed(),
            text.len()
        );
    }

    #[test]
    fn nir_valid_and_invalid_vectors() {
        let recognizer = FrNirRecognizer::new();
        assert_eq!(
            hits(&recognizer, "NIR 202022A01806376"),
            vec!["202022A01806376"]
        );
        assert_eq!(
            hits(&recognizer, "253072B07300470"),
            vec!["253072B07300470"]
        );
        // A wrong key still fires, at the lower score: the structure holds.
        let typo = recognizer.analyze("NIR 202022A01806377");
        assert_eq!(typo.len(), 1);
        assert_eq!(typo[0].score, INVALID_SCORE);
        assert!(!recognizer.verified());
        assert!(recognizer.enabled_by_default());
    }

    #[test]
    fn nir_with_double_or_triple_spaces_is_found() {
        let nir = "1   84  12  76  451  089  46";
        assert_eq!(FrNirRecognizer::new().analyze(nir)[0].score, 1.0);
        assert_eq!(squeeze_spaces("a  b    c").0, "a b    c");
    }

    #[test]
    fn nir_thirteen_digits_fire_without_a_key() {
        let recognizer = FrNirRecognizer::new();
        let spans = recognizer.analyze("NIR 1 84 03 00 999 001");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].score, INVALID_SCORE);
    }

    #[test]
    fn nir_rejects_structurally_impossible_values() {
        // Sex digit 9, month 13, department 96: none is a NIR shape.
        let recognizer = FrNirRecognizer::new();
        for text in ["9013015009070", "1841300999001", "1840396999001"] {
            assert!(recognizer.analyze(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn nir_never_starts_or_ends_inside_a_digit_run() {
        // Seventeen digits: no fifteen- or thirteen-digit window is whole.
        let recognizer = FrNirRecognizer::new();
        assert!(recognizer.analyze("18403009990012345").is_empty());
        assert!(recognizer.analyze("x 2840300999001234").is_empty());
    }

    #[test]
    fn nir_ignores_uuids_and_hex_hashes() {
        // FAKE: hex identifiers and hashes, none a NIR. Each has at most a short
        // digit run, so none is digit-only over fifteen characters.
        let recognizer = FrNirRecognizer::new();
        for text in [
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400e29b41d4a716446655440000",
            "9f86d081884c7d65",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ] {
            assert!(recognizer.analyze(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn nir_never_matches_inside_a_longer_hex_run() {
        // FAKE: a NIR-shaped run (1840300999001) inside a hex token, glued to
        // hex digits on both sides. The run is not a NIR; a hash is not a NIR.
        let recognizer = FrNirRecognizer::new();
        for text in [
            "1840300999001abcdef",
            "a1840300999001b2c3d4e5f6a7b8c9d0e1f2a3b4",
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ] {
            assert!(recognizer.analyze(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn nir_never_matches_inside_a_base64_token() {
        // FAKE: a Base64 token whose first thirteen characters are a NIR shape,
        // glued to letters and ending in `=` padding (44 characters in all).
        let recognizer = FrNirRecognizer::new();
        let token = format!("1840300999001Z{}=", "A".repeat(29));
        assert!(recognizer.analyze(&token).is_empty());
        assert!(recognizer
            .analyze(&format!("Le jeton est {token}, merci."))
            .is_empty());
        // A real-looking spaced NIR next to the token still fires.
        let text = format!("jeton {token} NIR 1 84 03 00 999 001 55");
        assert_eq!(hits(&recognizer, &text), vec!["1 84 03 00 999 001 55"]);
    }

    #[test]
    fn nir_delimited_on_both_sides_is_a_segment_and_fires() {
        // FAKE: a NIR between separators or boundaries: a URL path part, a query
        // value, a path, a key-value pair, a bare value. A whole segment fires
        // whatever the length of the text around it.
        let recognizer = FrNirRecognizer::new();
        for text in [
            "https://example.invalid/patients/184030099900123/file",
            "?id=184030099900123&x=1",
            "/184030099900123",
            "nir=184030099900123",
            "184030099900123",
        ] {
            assert_eq!(hits(&recognizer, text), vec!["184030099900123"], "{text}");
        }
        assert_eq!(
            hits(&recognizer, "1 84 03 00 999 001 23"),
            vec!["1 84 03 00 999 001 23"]
        );
    }

    #[test]
    fn nir_in_json_csv_and_markdown_fields_fires() {
        // FAKE: the NIR sits between quotes, commas, brackets or parentheses.
        let recognizer = FrNirRecognizer::new();
        for text in [
            r#"{"nir":"184030099900123"}"#,
            "nom,184030099900123,ville",
            "[dossier](https://example.invalid/184030099900123)",
            "[184030099900123](https://example.invalid/x)",
        ] {
            let found = hits(&recognizer, text);
            assert_eq!(found, vec!["184030099900123"], "{text}");
        }
    }

    #[test]
    fn nir_glued_to_letters_in_a_digest_or_blob_is_not_a_nir() {
        // FAKE: a 40-character hex digest with NIR-like digits glued to hex
        // letters, and a Base64 blob with the digits glued to letters on both
        // sides (a 44-character token with `=` padding).
        let recognizer = FrNirRecognizer::new();
        let digest = "7c1840300999001ab0d4e5f6a7b8c9d0e1f2a3b4";
        assert!(recognizer.analyze(digest).is_empty());
        let blob = "QUJDREVGR0hJ1840300999001SzFnaGlqa2xtbm8=";
        assert!(recognizer.analyze(blob).is_empty());
        let sentence = format!("Blob {blob}, fin.");
        assert!(recognizer.analyze(&sentence).is_empty());
    }

    #[test]
    fn nir_with_a_valid_key_glued_to_one_side_of_a_hex_run_fires() {
        // FAKE: 184127645108946 (key 46) pasted against a hash (FIN-4).
        let recognizer = FrNirRecognizer::new();
        for (text, value) in [
            ("1841276451089460f3a9b2c4d6e8", "184127645108946"),
            ("0f3a9b2c4d6e8e9184127645108946", "184127645108946"),
            ("x 184127645108946deadbeef", "184127645108946"),
            (
                "0f3a9b2c4d6e81 84 12 76 451 089 46.",
                "1 84 12 76 451 089 46",
            ),
        ] {
            assert_eq!(hits(&recognizer, text), vec![value], "{text}");
        }
        // A wrong key, a run glued on both sides, or digits only: no hit.
        for text in [
            "184127645108947f3a9b2c4d6e8",
            "a184127645108946f3a9b2c4d6e8",
            "18412764510894601234567",
        ] {
            assert!(recognizer.analyze(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn nir_wrapped_by_a_quoted_printable_soft_break_still_fires() {
        // FAKE: an e-mail body whose quoted-printable line ends in `=` before the
        // line break, so the number is split across two lines.
        let recognizer = FrNirRecognizer::new();
        let text = "NIR 184030099900=\r\n123 fin";
        assert_eq!(hits(&recognizer, text), vec!["184030099900=\r\n123"]);
    }

    #[test]
    fn nir_keeps_values_glued_to_short_runs_and_plain_values() {
        let recognizer = FrNirRecognizer::new();
        assert_eq!(
            hits(&recognizer, "NIR: 184030099900123"),
            vec!["184030099900123"]
        );
        assert_eq!(hits(&recognizer, "1840300999001"), vec!["1840300999001"]);
        // Glued on both sides, but the run is under the token minimum.
        assert_eq!(
            hits(&recognizer, "Zq1840300999001Yw="),
            vec!["1840300999001"]
        );
    }

    #[test]
    fn nir_accepts_spaced_forms() {
        let recognizer = FrNirRecognizer::new();
        assert_eq!(
            hits(&recognizer, "sécu 2 02 02 2A 018 063 76"),
            vec!["2 02 02 2A 018 063 76"]
        );
        assert_eq!(
            hits(&recognizer, "NIR 1 84 03 00 999 001 55"),
            vec!["1 84 03 00 999 001 55"]
        );
    }

    #[test]
    fn nir_finds_a_value_glued_to_a_letter() {
        let recognizer = FrNirRecognizer::new();
        assert_eq!(
            hits(&recognizer, "x202022A01806376"),
            vec!["202022A01806376"]
        );
    }

    #[test]
    fn siren_valid_and_invalid_vectors() {
        let recognizer = FrSirenRecognizer::new();
        assert_eq!(hits(&recognizer, "SIREN 732829320"), vec!["732829320"]);
        assert_eq!(hits(&recognizer, "404833048"), vec!["404833048"]);
        assert!(hits(&recognizer, "732829321").is_empty());
        assert!(recognizer.verified());
        assert!(recognizer.enabled_by_default());
    }

    #[test]
    fn siren_does_not_match_inside_a_siret() {
        let recognizer = FrSirenRecognizer::new();
        assert!(hits(&recognizer, "73282932000074").is_empty());
    }

    #[test]
    fn siret_valid_and_invalid_vectors() {
        let recognizer = FrSiretRecognizer::new();
        assert_eq!(hits(&recognizer, "73282932000074"), vec!["73282932000074"]);
        assert_eq!(hits(&recognizer, "35600000049837"), vec!["35600000049837"]);
        assert_eq!(hits(&recognizer, "35600000000048"), vec!["35600000000048"]);
        // A bad check digit with the fourteen-digit shape is still masked.
        let typo = recognizer.analyze("35600000049838");
        assert_eq!(typo.len(), 1);
        assert_eq!(typo[0].score, INVALID_SCORE);
        let typo = recognizer.analyze("73282932000079");
        assert_eq!(typo.len(), 1);
        assert_eq!(typo[0].score, INVALID_SCORE);
        assert!(!recognizer.verified());
        assert!(recognizer.enabled_by_default());
    }

    #[test]
    fn vat_valid_and_invalid_vectors() {
        let recognizer = FrVatRecognizer::new();
        assert_eq!(
            hits(&recognizer, "TVA FR83404833048"),
            vec!["FR83404833048"]
        );
        assert_eq!(hits(&recognizer, "FR27552032534"), vec!["FR27552032534"]);
        assert!(hits(&recognizer, "FR84404833048").is_empty());
        assert!(recognizer.verified());
    }

    #[test]
    fn vat_accepts_separators_between_groups() {
        let recognizer = FrVatRecognizer::new();
        assert_eq!(
            hits(&recognizer, "TVA FR 40303265045"),
            vec!["FR 40303265045"]
        );
        assert_eq!(
            hits(&recognizer, "TVA FR 40 303 265 045"),
            vec!["FR 40 303 265 045"]
        );
        assert_eq!(
            hits(&recognizer, "TVA FR-40-303-265-045"),
            vec!["FR-40-303-265-045"]
        );
    }

    #[test]
    fn vat_wins_over_the_siren_it_contains() {
        let registry = crate::Registry::builder()
            .with_recognizer(FrSirenRecognizer::new())
            .with_recognizer(FrVatRecognizer::new())
            .build();
        let spans = registry.analyze("TVA FR83404833048");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].kind, EntityKind::FrVat);
    }
}
