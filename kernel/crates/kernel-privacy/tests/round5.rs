//! Round-5 breaker regression tests: the open P2 and the two P3s, replayed as
//! fake data.
//!
//! Fake data only. No held-out corpus is copied into the repo.

use kernel_privacy::{Anonymizer, EntityKind, Registry};

fn masked(registry: &Registry, text: &str) -> String {
    let spans = registry.analyze(text);
    let mut anonymizer = Anonymizer::new([0x5Au8; 32]);
    anonymizer.anonymize(text, &spans).0
}

fn kinds(registry: &Registry, text: &str) -> Vec<EntityKind> {
    registry
        .analyze(text)
        .into_iter()
        .map(|span| span.kind)
        .collect()
}

// P2: a spaced passport with no cue at all must not leak.
#[test]
fn p2_spaced_passport_without_a_cue_masks() {
    let registry = Registry::new();
    // A bare OCR line.
    assert!(
        !masked(&registry, "QXZ 1234567").contains("QXZ 1234567"),
        "bare spaced passport leaked"
    );
    // A CSV cell.
    let csv = "\"name\";\"QXZ 1234567\"";
    assert!(
        !masked(&registry, csv).contains("QXZ 1234567"),
        "spaced passport in a CSV row leaked"
    );
    // A checksum-valid de-spaced value masks through the same rule.
    assert!(
        !masked(&registry, "L 123456781").contains("L 123456781"),
        "checksum-valid spaced passport leaked"
    );
}

// P2: the ISO prefix and the cued TAJ keep their own label and stay clear/typed.
#[test]
fn p2_iso_and_taj_prefixes_are_left_to_their_own_rules() {
    let registry = Registry::new();
    assert!(
        kinds(&registry, "ISO 123456").is_empty(),
        "ISO leaked as a passport"
    );
    assert_eq!(masked(&registry, "ISO 123456"), "ISO 123456");
    let found = kinds(&registry, "TAJ 123456788");
    assert!(
        found.contains(&EntityKind::HuTaj),
        "cued TAJ lost its label: {found:?}"
    );
    assert!(!found.contains(&EntityKind::PassportMrz));
}

// P3: the passport cue window looks after the value too.
#[test]
fn p3_cue_after_the_value_widens_the_shape() {
    let registry = Registry::new();
    let text = "A1B2C3D4E5 passeport";
    assert!(
        !masked(&registry, text).contains("A1B2C3D4E5"),
        "a value followed by a passport cue leaked"
    );
}

// P3: a 9-digit number glued to a currency symbol is masked.
#[test]
fn p3_nine_digit_price_is_masked() {
    let registry = Registry::new();
    for text in ["123 456 789 €", "123 456 789€", "€123 456 789"] {
        assert!(
            kinds(&registry, text).contains(&EntityKind::Phone),
            "a 9-digit price-like run was not masked in {text:?}"
        );
        assert!(
            !masked(&registry, text).contains("123 456 789"),
            "a 9-digit price-like run leaked in {text:?}"
        );
    }
    // A standard number is still exempt.
    assert!(kinds(&registry, "ISO 27001 2022").is_empty());
}

// P2 follow-up: the cue-less spaced passport masks for every 1–3 letter
// prefix, with only `ISO` and the business-reference denylist left clear.
#[test]
fn p2_spaced_passport_masks_for_every_prefix_length() {
    let registry = Registry::new();
    for text in ["E 12345678", "AB 1234567", "QXZ 1234567"] {
        assert!(
            !masked(&registry, text).contains(text),
            "spaced passport leaked in {text:?}"
        );
        assert!(
            kinds(&registry, text).contains(&EntityKind::NationalId),
            "spaced passport not labelled generic in {text:?}"
        );
    }
    // The two exceptions stay clear: an ISO prefix and a business prefix.
    assert!(kinds(&registry, "ISO 1234567").is_empty(), "ISO leaked");
    assert!(kinds(&registry, "REF 1234567").is_empty(), "REF leaked");
}

// P3: a TAJ that follows a cue but fails its check digit masks as NATIONAL_ID.
#[test]
fn p3_cued_taj_with_a_bad_check_digit_masks_generically() {
    let registry = Registry::new();
    let found = kinds(&registry, "TAJ 123456789");
    assert!(
        found.contains(&EntityKind::NationalId),
        "cued bad-check-digit TAJ not masked: {found:?}"
    );
    assert!(
        !found.contains(&EntityKind::HuTaj),
        "bad-check-digit TAJ claimed a specific kind: {found:?}"
    );
    assert!(
        !masked(&registry, "TAJ 123456789").contains("123456789"),
        "cued bad-check-digit TAJ leaked"
    );
}
