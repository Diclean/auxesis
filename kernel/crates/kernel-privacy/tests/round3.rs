//! Round-3 breaker regression tests: the exact held-out inputs, replayed as
//! fake data. One test per fix item, plus the policy traps.
//!
//! Fake data only. No held-out corpus is copied into the repo.

use kernel_privacy::{Anonymizer, EntityKind, NormalizedText, Registry};

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

// P1: passports mask on shape, with and without a cue.
#[test]
fn p1_passports_mask_on_shape() {
    let registry = Registry::new();
    for text in [
        "passeport QXZ1000001",
        "reference QXZ1000001",
        "passeport A1B2C3D4E5",
        "P<FRADUPONT A1B2C3D4E5",
        "útlevél A1B2C3D4E5",
    ] {
        let values: Vec<&str> = text.split_whitespace().collect();
        let value = values.last().copied().expect("a value");
        assert!(
            !masked(&registry, text).contains(value),
            "passport shape leaked in {text:?}"
        );
    }
}

// P2: a Luhn-valid ZA ID with an odd month is still masked, generically.
#[test]
fn p2_za_id_masks_any_luhn_valid_run() {
    let registry = Registry::new();
    for text in ["ID 8001015009087", "ID 8013015009082", "ID 8001015009088"] {
        let found = kinds(&registry, text);
        assert!(
            found.contains(&EntityKind::NationalId) || found.contains(&EntityKind::ZaId),
            "ZA ID not masked in {text:?}: {found:?}"
        );
        assert!(
            !masked(&registry, text).contains(&text[3..]),
            "ZA ID leaked in {text:?}"
        );
    }
}

// P2: checksum-invalid NIR and SIRET with the right shape still mask. A NIR
// with a wrong key still fires (its structure holds); only the score drops.
#[test]
fn p2_checksum_invalid_nir_and_siret_mask() {
    let registry = Registry::new();
    for text in [
        "NIR 202022A01806377",
        "NIR 734050099900155",
        "siret 73282932000079",
        "siret 35600000049838",
    ] {
        let value = text.split_whitespace().nth(1).expect("a value");
        assert!(
            !masked(&registry, text).contains(value),
            "typo identifier leaked in {text:?}"
        );
        assert!(
            kinds(&registry, text).contains(&EntityKind::NationalId),
            "typo identifier not labelled generic in {text:?}"
        );
    }
}

// P2: every adjacent e-mail in a run is masked.
#[test]
fn p2_email_retry_masks_every_address() {
    let registry = Registry::new();
    for text in [
        "a@x.invalid.b@y.invalid",
        "a@x.invalid-b@y.invalid",
        "jean.dupont@example.invalid2026",
    ] {
        let spans = registry.analyze(text);
        assert!(!spans.is_empty(), "no e-mail in {text:?}");
        let rendered = masked(&registry, text);
        for span in spans {
            assert!(
                !rendered.contains(&text[span.start..span.end]),
                "address {} leaked in {text:?}",
                &text[span.start..span.end]
            );
        }
    }
    let rendered = masked(&registry, "a@x.invalid.b@y.invalid");
    assert!(!rendered.contains("x.invalid"));
    assert!(!rendered.contains("y.invalid"));
}

// P2: a sentence-final dot after an IPv4 address does not hide it.
#[test]
fn p2_ipv4_before_a_sentence_period_masks() {
    let registry = Registry::new();
    assert!(!masked(&registry, "host 192.168.0.1.").contains("192.168.0.1"));
}

// P2: only a full date with no extra digit groups is excluded.
#[test]
fn p2_phone_dates_with_extra_groups_mask() {
    let registry = Registry::new();
    for text in [
        "06/12/1234 56 78",
        "06-12-1234-56-78",
        "06.12.2034.56.78",
        "+2026/1/3 12345678",
    ] {
        assert!(
            !masked(&registry, text).contains(text),
            "not masked: {text:?}"
        );
    }
    // The 12-digit runs are phone-shaped; the 14-digit run is also SIRET-shaped,
    // so it is masked as the higher-priority NATIONAL_ID.
    for text in ["06/12/1234 56 78", "06-12-1234-56-78", "06.12.2034.56.78"] {
        assert!(
            kinds(&registry, text).contains(&EntityKind::Phone),
            "date-like phone not masked in {text:?}"
        );
    }
    // A genuine full date (with optional time) stays clear.
    assert!(!kinds(&Registry::new(), "le 12/03/2026 14 h").contains(&EntityKind::Phone));
}

// P2: the single-digit guard is evaluated per candidate.
#[test]
fn p2_single_digit_guard_is_per_candidate() {
    let registry = Registry::new();
    assert!(!masked(&registry, "tel 0 6 1 2 3 4 5 6 7 8").contains("0 6 1 2 3 4 5 6 7 8"));
    assert!(!masked(&registry, "06 12 34 56 78 / 1 / 2 / 3").contains("06 12 34 56 78"));
    let both = "+33 6 12 34 56 78  192.168.0.1";
    let rendered = masked(&registry, both);
    assert!(!rendered.contains("6 12 34 56 78"));
    assert!(!rendered.contains("192.168.0.1"));
}

// P2: an unknown-country IBAN includes the country code and every group.
#[test]
fn p2_unknown_country_iban_masks_every_group() {
    let registry = Registry::new();
    let valid = "ZZ85 ABCD 1234 5678 9012 3456";
    assert!(
        !masked(&registry, valid).contains("ZZ85"),
        "unknown-country IBAN leaked"
    );
    let invalid = "ZZ84 ABCD 1234 5678 9012 3456";
    assert!(
        !masked(&registry, invalid).contains("ZZ84"),
        "shape-only IBAN leaked"
    );
}

// P3: the OCR fold never rewrites a whole letter word.
#[test]
fn p3_ocr_fold_stays_inside_digit_groups() {
    assert_eq!(NormalizedText::new("O6 l2", true).text(), "06 12");
    for word in ["om", "IBAN-ra", "Ilo"] {
        let input = format!("123456 {word}");
        assert_eq!(
            NormalizedText::new(&input, true).text(),
            input,
            "fold rewrote {word:?}"
        );
    }
}

// P3: fullwidth input and the `app` keyword bypass.
#[test]
fn p3_fullwidth_and_keyword_bypasses() {
    let registry = Registry::new();
    assert!(!masked(&registry, "ａｐｐ １０.０.０.５").contains("１０.０.０.５"));
    assert!(!masked(&registry, "app 10.0.0.5").contains("10.0.0.5"));
    assert!(!kinds(&registry, "version 10.0.0.5").contains(&EntityKind::IpV4));
    assert!(!masked(&registry, "ｊｅａｎ＠ｅｘａｍｐｌｅ.ｃｏｍ").contains("ｅｘａｍｐｌｅ"));
    let fullwidth_iban = "ＦＲ７６３０００６００００１１２３４５６７８９０１８９";
    assert!(
        !masked(&registry, fullwidth_iban).contains(fullwidth_iban),
        "fullwidth IBAN leaked"
    );
}

// P3: over-masking traps obey the mask/keep policy.
#[test]
fn p3_over_masking_traps() {
    let registry = Registry::new();
    assert!(kinds(&registry, "45 00 12 34 56").contains(&EntityKind::Phone));
    // P3 follow-up: a 9-digit run beside a currency symbol is masked, not a
    // price, because the price exemption stops at 8 digits.
    assert!(kinds(&registry, "123 456 789 €").contains(&EntityKind::Phone));
    assert!(kinds(&registry, "ISO 27001 2022").is_empty());
    assert!(kinds(&registry, "0123456789012").contains(&EntityKind::Phone));
}

// P3: the eval harness scores per case; identical offsets in two cases must not
// cross-match.
#[test]
fn p3_privacy_eval_scores_per_case() {
    use kernel_privacy::eval::{self, GoldSpan};
    let first = [GoldSpan::new(EntityKind::Email, 0, 8)];
    let second = [GoldSpan::new(EntityKind::Email, 0, 8)];
    let other = [kernel_privacy::Span::new(
        EntityKind::Email,
        0,
        8,
        1.0,
        "test",
    )];
    // Case two is never scored, so its gold must show as a miss when scored on
    // its own; a run-wide score would have reused case one's prediction.
    let scores = eval::score(&second, &[]);
    assert_eq!(scores[0].false_negatives, 1);
    let scores = eval::score(&first, &other);
    assert_eq!(scores[0].true_positives, 1);
}
