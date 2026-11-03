//! Regression tests for the PR #164 re-attack round, using the breaker's exact
//! inputs and the maintainer's fail-toward-masking policy. Fake data only.

use kernel_privacy::recognizer::MAX_SPAN_BYTES;
use kernel_privacy::{Anonymizer, EntityKind, NormalizedText, Registry, UnknownPolicy};

fn masked(registry: &Registry, text: &str) -> String {
    let spans = registry.analyze(text);
    let mut anonymizer = Anonymizer::new([0x31u8; 32]);
    anonymizer.anonymize(text, &spans).0
}

fn kinds(registry: &Registry, text: &str) -> Vec<EntityKind> {
    registry
        .analyze(text)
        .into_iter()
        .map(|span| span.kind)
        .collect()
}

// P1: FR VAT with separators.
#[test]
fn fr_vat_accepts_any_separator() {
    let registry = Registry::new();
    for text in ["TVA FR 40303265045", "TVA FR 40 303 265 045"] {
        let spans = registry.analyze(text);
        let vat = spans
            .iter()
            .find(|span| span.kind == EntityKind::FrVat)
            .unwrap_or_else(|| panic!("VAT not detected in {text:?}: {spans:?}"));
        let value = &text[vat.start..vat.end];
        assert!(
            !masked(&registry, text).contains(value),
            "VAT survived masking in {text:?}"
        );
    }
}

// P1: NIR / SIRET / MRZ are mounted; unverified rules mask as NATIONAL_ID.
#[test]
fn unverified_rules_are_mounted_and_label_generic() {
    let registry = Registry::new();
    for text in [
        "NIR 202022A01806376",
        "NIR 202022A01806376",        // ungrouped NIR
        "sécu 2 02 02 2A 018 063 76", // grouped NIR
        "siret 73282932000074",       // SIRET
        "passport L898902C36",        // passport MRZ
    ] {
        let spans = registry.analyze(text);
        let generic = spans
            .iter()
            .find(|span| span.kind == EntityKind::NationalId);
        assert!(generic.is_some(), "no NATIONAL_ID for {text:?}: {spans:?}");
        let span = generic.expect("checked above");
        assert!(
            span.score < 1.0,
            "unverified hit scored like a verified one"
        );
        assert!(span.score >= registry.thresholds().get(EntityKind::NationalId));
        let value = &text[span.start..span.end];
        assert!(!masked(&registry, text).contains(value), "leak in {text:?}");
    }
}

// P1: checksum-valid TAJ and HU tax ID are masked without a cue; the label is
// the generic NATIONAL_ID, and a cue keeps the specific kind.
#[test]
fn cueless_taj_and_taxid_are_masked_generically() {
    let registry = Registry::new();
    for text in ["szám 123456788", "szám 123 456 788", "szám 8123456786"] {
        let found = kinds(&registry, text);
        assert!(
            found.contains(&EntityKind::NationalId),
            "cueless identifier not masked in {text:?}: {found:?}"
        );
        assert!(
            !found.contains(&EntityKind::HuTaj) && !found.contains(&EntityKind::HuTaxId),
            "cueless identifier claimed a specific kind in {text:?}"
        );
    }
    assert_eq!(kinds(&registry, "TAJ 123456788"), vec![EntityKind::HuTaj]);
    assert_eq!(
        kinds(&registry, "adóazonosító 8123456786"),
        vec![EntityKind::HuTaxId]
    );
}

// P2: exact restore. A shared token covers two surface forms; each occurrence
// must come back byte for byte.
#[test]
fn every_occurrence_restores_its_exact_surface() {
    let registry = Registry::new();
    let text = "tel 0612345678 puis 06 12 34 56 78 fin";
    let spans = registry.analyze(text);
    let mut anonymizer = Anonymizer::new([0x32u8; 32]);
    let (mask, pairs) = anonymizer.anonymize(text, &spans);
    assert_eq!(pairs.len(), 1, "the two spellings must share a token");
    assert_eq!(mask.matches(&pairs[0].0).count(), 2);
    let report = Anonymizer::restore(&mask, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text);
    assert!(report.is_clean());
}

// P2/P3: invalid local parts fail closed.
#[test]
fn invalid_local_part_email_is_masked() {
    let registry = Registry::new();
    for text in [".N@example.invalid", "x .N@example.invalid"] {
        assert!(
            kinds(&registry, text).contains(&EntityKind::Email),
            "leading-dot email not masked in {text:?}"
        );
        assert!(!masked(&registry, text).contains("example.invalid"));
    }
}

// P3: over-masking guards.
#[test]
fn guards_reject_lists_and_datetimes() {
    let registry = Registry::new();
    let list: Vec<String> = (1..=20).map(|n| n.to_string()).collect();
    let list = list.join(" ");
    assert!(
        !kinds(&registry, &list).contains(&EntityKind::Phone),
        "a 1..20 list became a phone"
    );
    assert!(
        !kinds(&registry, "le 12/03/2026 14 h").contains(&EntityKind::Phone),
        "a date+time became a phone"
    );
    // A genuine dotted French phone stays a phone.
    assert!(kinds(&registry, "06.12.34.56.78").contains(&EntityKind::Phone));
}

#[test]
fn ocr_fold_only_touches_confusables_beside_digits() {
    // A confusable between two digits folds even with few digits (P3-4).
    let short = NormalizedText::new("1O2 3l4 5", true);
    assert_eq!(short.text(), "102 314 5");
    let long = NormalizedText::new("+33 l 99 OO 41 27", true);
    assert_eq!(long.text(), "+33 1 99 00 41 27");
    // A whole letter word is never folded.
    let words = NormalizedText::new("123456 Ilo om IBAN-ra", true);
    assert_eq!(words.text(), "123456 Ilo om IBAN-ra");
}

#[test]
fn unknown_iban_does_not_swallow_following_words() {
    let registry = Registry::new();
    let text = "cpte ZZ6630006000011234567890189 merci beaucoup";
    let spans = registry.analyze(text);
    let iban = spans
        .iter()
        .find(|span| span.kind == EntityKind::Iban)
        .expect("unknown-country IBAN detected");
    assert_eq!(&text[iban.start..iban.end], "ZZ6630006000011234567890189");
}

#[test]
fn spans_longer_than_the_cap_are_split() {
    let registry = Registry::new();
    let text = "06 ".repeat(60);
    let spans = registry.analyze(&text);
    assert!(!spans.is_empty(), "long phone run not masked");
    assert!(spans.iter().all(|span| span.len() <= MAX_SPAN_BYTES));
    assert_eq!(spans.first().map(|span| span.start), Some(0));
    assert_eq!(
        spans.last().map(|span| span.end),
        Some(text.trim_end().len())
    );
}
