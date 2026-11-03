//! Hungarian identifier recognisers (official rules: 1996. évi XX. törvény).

use crate::checksum::{hu_taj_ok, hu_taxid_ok};
use crate::normalize::{ascii_digits, numeric_runs, NormalizedText};
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Score of a checksum-valid TAJ / tax ID with no cue in front: below the
/// default floor, so the registry relabels it `NATIONAL_ID` instead of
/// claiming the specific kind. A cue word raises it above the floor.
pub const AMBIGUOUS_SCORE: f32 = 0.4;

/// Score of a TAJ-shaped nine-digit run that follows a TAJ cue but fails its
/// check digit: well below every floor, so even after the context boost the
/// registry relabels it `NATIONAL_ID`. A typo in a real document is still
/// personal data, so the cue alone masks it.
pub const INVALID_TAJ_SCORE: f32 = 0.1;

/// Cue words that make a nine-digit run a TAJ candidate even when its check
/// digit fails. Mirrors the `HuTaj` cue list used by the context enhancer.
const TAJ_CUES: &[&str] = &["taj", "társadalombiztosítási"];
/// Characters inspected before a candidate for a TAJ cue.
const TAJ_CUE_WINDOW: usize = 40;

/// TAJ szám: nine digits, weighted mod-10 check digit.
///
/// The label depends only on a cue: without a cue the registry masks the value
/// as the generic `NATIONAL_ID` (never dropping a checksum-valid number);
/// with a cue (`TAJ`, `társadalombiztosítási`) it keeps `HU_TAJ`.
#[derive(Clone, Copy, Debug)]
pub struct HuTajRecognizer {
    verified: bool,
}

impl HuTajRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self { verified: true }
    }
}

impl Default for HuTajRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for HuTajRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::HuTaj]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        let body = normalized.text();
        numeric_runs(body)
            .into_iter()
            .filter_map(|(start, end)| {
                let digits = ascii_digits(&body[start..end]);
                if digits.len() != 9 {
                    return None;
                }
                // A valid check digit masks at the ambiguous score (the cue
                // decides the label); a cued but invalid one still masks, at a
                // score low enough that the registry labels it `NATIONAL_ID`.
                let score = if hu_taj_ok(&digits) {
                    AMBIGUOUS_SCORE
                } else if near_taj_cue(body, start) {
                    INVALID_TAJ_SCORE
                } else {
                    return None;
                };
                normalized
                    .to_original(start, end)
                    .map(|(start, end)| Span::new(EntityKind::HuTaj, start, end, score, "hu_taj"))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "hu_taj"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// Whether a TAJ cue appears within [`TAJ_CUE_WINDOW`] characters before
/// `start`. The window is measured in characters, so it is UTF-8 safe.
fn near_taj_cue(text: &str, start: usize) -> bool {
    let begin = text[..start]
        .char_indices()
        .rev()
        .nth(TAJ_CUE_WINDOW)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let window = text[begin..start].to_lowercase();
    TAJ_CUES.iter().any(|cue| window.contains(cue))
}

/// Adóazonosító jel: ten digits, first digit `8`, weighted mod-11 check digit.
///
/// As with TAJ, a cueless value is masked as `NATIONAL_ID`; only a cue
/// (`adóazonosító`, `adószám`, `tax`) keeps the specific `HU_TAX_ID` label.
#[derive(Clone, Copy, Debug)]
pub struct HuTaxIdRecognizer {
    verified: bool,
}

impl HuTaxIdRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self { verified: true }
    }
}

impl Default for HuTaxIdRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for HuTaxIdRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::HuTaxId]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        numeric_runs(normalized.text())
            .into_iter()
            .filter(|(start, end)| {
                let digits = ascii_digits(&normalized.text()[*start..*end]);
                digits.len() == 10 && hu_taxid_ok(&digits)
            })
            .filter_map(|(start, end)| {
                normalized.to_original(start, end).map(|(start, end)| {
                    Span::new(EntityKind::HuTaxId, start, end, AMBIGUOUS_SCORE, "hu_taxid")
                })
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "hu_taxid"
    }

    fn verified(&self) -> bool {
        self.verified
    }
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
    fn taj_valid_and_invalid_vectors() {
        let recognizer = HuTajRecognizer::new();
        assert_eq!(hits(&recognizer, "TAJ 123456788"), vec!["123456788"]);
        assert!(hits(&recognizer, "123456789").is_empty());
        assert!(recognizer.verified());
        assert!(recognizer.enabled_by_default());
    }

    #[test]
    fn cued_taj_with_a_bad_check_digit_is_still_masked() {
        let recognizer = HuTajRecognizer::new();
        // P3: a TAJ cue makes a nine-digit run a candidate even when its check
        // digit fails; the low score makes the registry relabel it NATIONAL_ID.
        assert_eq!(hits(&recognizer, "TAJ 123456789"), vec!["123456789"]);
        let cued = recognizer.analyze("TAJ 123456789");
        assert_eq!(cued.len(), 1);
        assert_eq!(cued[0].score, INVALID_TAJ_SCORE);
        // Without the cue an invalid nine-digit run is not a TAJ.
        assert!(hits(&recognizer, "szám 123456789").is_empty());
    }

    #[test]
    fn taj_is_masked_generically_without_a_cue() {
        let registry = crate::Registry::builder()
            .with_recognizer(HuTajRecognizer::new())
            .build();
        // Cueless (grouped or not): still masked, but labelled NATIONAL_ID.
        for text in ["szám 123 456 788", "szám 123456788"] {
            let spans = registry.analyze(text);
            assert_eq!(spans.len(), 1, "cueless TAJ not masked in {text:?}");
            assert_eq!(spans[0].kind, EntityKind::NationalId);
            assert!(spans[0].score >= registry.thresholds().get(EntityKind::NationalId));
        }
        // Cued: the specific kind survives.
        let cued = registry.analyze("TAJ 123456788");
        assert_eq!(cued.len(), 1);
        assert_eq!(cued[0].kind, EntityKind::HuTaj);
        assert!(cued[0].score >= registry.thresholds().get(EntityKind::HuTaj));
    }

    #[test]
    fn taxid_is_masked_generically_without_a_cue() {
        let registry = crate::Registry::builder()
            .with_recognizer(HuTaxIdRecognizer::new())
            .build();
        let bare = registry.analyze("szám 8123456786");
        assert_eq!(bare.len(), 1, "cueless tax id not masked");
        assert_eq!(bare[0].kind, EntityKind::NationalId);
        let cued = registry.analyze("adóazonosító 8123456786");
        assert_eq!(cued.len(), 1);
        assert_eq!(cued[0].kind, EntityKind::HuTaxId);
    }

    #[test]
    fn taxid_valid_and_invalid_vectors() {
        let recognizer = HuTaxIdRecognizer::new();
        assert_eq!(
            hits(&recognizer, "adóazonosító 8123456786"),
            vec!["8123456786"]
        );
        assert!(hits(&recognizer, "8123456787").is_empty());
        assert!(hits(&recognizer, "7123456786").is_empty());
        assert!(recognizer.verified());
    }

    #[test]
    fn taj_and_taxid_do_not_collide() {
        let recognizer = HuTajRecognizer::new();
        assert!(hits(&recognizer, "8123456786").is_empty());
    }

    #[test]
    fn declared_kinds_and_names() {
        assert_eq!(HuTajRecognizer::new().kinds(), &[EntityKind::HuTaj]);
        assert_eq!(HuTajRecognizer::new().name(), "hu_taj");
        assert_eq!(HuTaxIdRecognizer::new().kinds(), &[EntityKind::HuTaxId]);
        assert_eq!(HuTaxIdRecognizer::new().name(), "hu_taxid");
    }
}
