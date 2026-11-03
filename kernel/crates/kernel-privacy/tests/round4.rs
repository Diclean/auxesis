//! Round-4 regression tests for the never-seen third split, replayed as fake
//! data. One test per fix item (P1–P3).
//!
//! Fake data only. No held-out corpus is copied into the repo.

use kernel_privacy::{Anonymizer, EntityKind, Registry};

fn masked(registry: &Registry, text: &str) -> String {
    let spans = registry.analyze(text);
    let mut anonymizer = Anonymizer::new([0x99u8; 32]);
    anonymizer.anonymize(text, &spans).0
}

fn kinds(registry: &Registry, text: &str) -> Vec<EntityKind> {
    registry
        .analyze(text)
        .into_iter()
        .map(|span| span.kind)
        .collect()
}

fn assert_no_leak(registry: &Registry, text: &str) {
    let spans = registry.analyze(text);
    assert!(!spans.is_empty(), "no span detected in {text:?}");
    let rendered = masked(registry, text);
    for span in spans {
        assert!(
            !rendered.contains(&text[span.start..span.end]),
            "value survived masking in {text:?}"
        );
    }
}

// P1: passport shapes with separators, case and non-ASCII digits.
#[test]
fn p1_passport_shapes_mask() {
    let registry = Registry::new();
    for text in [
        "Passport no QXZ 1234567",
        "جواز السفر QXZ١٢٣٤٥٦٧",
        "passeport qxz1234567",
        "paspoort QXZ-1234567",
        "passeport l898902c36",
    ] {
        assert_no_leak(&registry, text);
    }
}

// P2: fullwidth punctuation folds in the normalisation layer.
#[test]
fn p2_fullwidth_punctuation_masks() {
    let registry = Registry::new();
    for text in ["１９２．１６８．０．１", "jean＠example．com"] {
        assert_no_leak(&registry, text);
    }
    assert!(kinds(&registry, "１９２．１６８．０．１").contains(&EntityKind::IpV4));
    assert!(kinds(&registry, "jean＠example．com").contains(&EntityKind::Email));
}

// P3: the price/ISO guards exempt only a short, undated, non-leading-zero run.
#[test]
fn p3_price_and_iso_guards_do_not_hide_phones() {
    let registry = Registry::new();
    for text in [
        "06 12 34 56 78 €",
        "ISO 06 12 34 56 78",
        "12/03/2026 06 12 34 56 78 €",
    ] {
        assert!(
            !masked(&registry, text).contains("06 12 34 56 78"),
            "a phone was hidden by a price/ISO guard in {text:?}"
        );
    }
    // Round 5 lowered the price exemption to 8 digits, so this 9-digit run is
    // masked rather than exempted as a price.
    let text = "123 456 789 €";
    assert!(
        kinds(&registry, text).contains(&EntityKind::Phone),
        "a 9-digit price-like run was not masked in {text:?}"
    );
    assert!(
        kinds(&registry, "ISO 27001 2022").is_empty(),
        "an ISO standard number became a phone"
    );
}

// P3: a passport-shaped value keeps its origin over an IBAN candidate.
#[test]
fn p3_passport_label_wins_over_iban() {
    let registry = Registry::new();
    let text = "passport AB123456789";
    let spans = registry.analyze(text);
    assert_eq!(spans.len(), 1, "expected one merged span: {spans:?}");
    assert_eq!(spans[0].recognizer, "passport_mrz");
    assert_eq!(spans[0].kind, EntityKind::NationalId);
    assert_eq!(&text[spans[0].start..spans[0].end], "AB123456789");
}

// P3: a national-id-shaped value outranks a phone-shaped sub-run when an ID
// cue is present (the VAT/company case is covered by the registry unit test,
// which can build the overlap directly).
#[test]
fn p3_national_id_outranks_phone() {
    let registry = Registry::new();
    let found = kinds(&registry, "ID 1 84 03 00 999 001 55");
    assert!(
        found.contains(&EntityKind::NationalId),
        "national-id-shaped value did not win: {found:?}"
    );
    assert!(
        !found.contains(&EntityKind::Phone),
        "a phone outranked a national-id-shaped value: {found:?}"
    );
}

// P3: a Russian dotted datetime with seconds is not a phone.
#[test]
fn p3_russian_datetime_is_not_a_phone() {
    let registry = Registry::new();
    for text in ["12.03.2026 14.30.00", "12.03.2026 14 30 00"] {
        assert!(
            !kinds(&registry, text).contains(&EntityKind::Phone),
            "a dotted datetime became a phone in {text:?}"
        );
    }
}
