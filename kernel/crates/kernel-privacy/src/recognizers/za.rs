//! South African identity number recogniser (`YYMMDD SSSS C A Z`, Luhn).

use crate::checksum::{za_id_luhn_ok, za_id_shape_ok};
use crate::normalize::{ascii_digits, numeric_runs, NormalizedText};
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// Score of a Luhn-valid run whose date or citizenship field is odd, or of a
/// checksum-invalid run of the right shape. It sits below the `ZaId` floor even
/// after the `id` cue boost, so the registry always relabels it the generic
/// `NATIONAL_ID` instead of claiming a specific kind (P2-2). A typo in a real
/// document is still personal data.
pub const ODD_SCORE: f32 = 0.1;

/// Thirteen digits with a plausible date, citizenship digit and Luhn check.
#[derive(Clone, Copy, Debug)]
pub struct ZaIdRecognizer {
    verified: bool,
}

impl ZaIdRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self { verified: true }
    }
}

impl Default for ZaIdRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for ZaIdRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::ZaId]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let normalized = NormalizedText::new(text, true);
        numeric_runs(normalized.text())
            .into_iter()
            .filter_map(|(start, end)| {
                let digits = ascii_digits(&normalized.text()[start..end]);
                if digits.len() != 13 {
                    return None;
                }
                let luhn = za_id_luhn_ok(&digits);
                let shape = za_id_shape_ok(&digits);
                let score = if luhn && shape {
                    1.0
                } else if luhn || shape {
                    ODD_SCORE
                } else {
                    return None;
                };
                normalized
                    .to_original(start, end)
                    .map(|(start, end)| Span::new(EntityKind::ZaId, start, end, score, "za_id"))
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "za_id"
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(text: &str) -> Vec<String> {
        ZaIdRecognizer::new()
            .analyze(text)
            .into_iter()
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn valid_and_invalid_vectors() {
        assert_eq!(hits("ID 8001015009087"), vec!["8001015009087"]);
        // A typo (Luhn failure) of the right shape is still masked, lower.
        let typos = ZaIdRecognizer::new().analyze("ID 8001015009088");
        assert_eq!(typos.len(), 1);
        assert_eq!(typos[0].score, ODD_SCORE);
    }

    #[test]
    fn a_luhn_valid_run_with_an_odd_month_is_still_masked() {
        // Month 13 with a valid Luhn check: the shape is odd, so the value is
        // still masked but as the generic NATIONAL_ID (P2-2).
        let spans = ZaIdRecognizer::new().analyze("ID 8013015009082");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].score, ODD_SCORE);
        let registry = crate::Registry::builder()
            .with_recognizer(ZaIdRecognizer::new())
            .build();
        let masked = registry.analyze("ID 8013015009082");
        assert_eq!(masked.len(), 1);
        assert_eq!(masked[0].kind, EntityKind::NationalId);
    }

    #[test]
    fn rejects_implausible_dates_and_citizenship() {
        assert!(hits("8013015009087").is_empty());
        assert!(hits("8001015009287").is_empty());
    }

    #[test]
    fn finds_a_value_glued_to_a_letter() {
        assert_eq!(hits("x8001015009087"), vec!["8001015009087"]);
    }

    #[test]
    fn declared_kind_and_name() {
        let recognizer = ZaIdRecognizer::new();
        assert_eq!(recognizer.kinds(), &[EntityKind::ZaId]);
        assert_eq!(recognizer.name(), "za_id");
        assert!(recognizer.verified());
    }
}
