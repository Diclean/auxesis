//! One regression test per breaker finding (PR #164 re-attack), using the
//! breaker's exact inputs. Fake data only.

use kernel_privacy::recognizers::fr::FrNirRecognizer;
use kernel_privacy::{Anonymizer, EntityKind, Recognizer, Registry, UnknownPolicy};

fn mask(registry: &Registry, text: &str) -> (String, Vec<kernel_privacy::Span>) {
    let spans = registry.analyze(text);
    let mut anonymizer = Anonymizer::new([0x11u8; 32]);
    let (masked, _) = anonymizer.anonymize(text, &spans);
    (masked, spans)
}

// P1-1 / P2-5: never drop a span; mask the union.
#[test]
fn p1_1_partial_overlap_masks_the_whole_union() {
    let registry = Registry::new();
    for text in [
        "Appelez 06 12 34 56 78.john@ex.fr",
        "Voir https://ex.fr/x(06 12 34 56 78) merci",
    ] {
        let (masked, spans) = mask(&registry, text);
        assert!(!spans.is_empty(), "no span detected in {text:?}");
        for span in &spans {
            assert!(
                !masked.contains(&text[span.start..span.end]),
                "detected bytes survived in {text:?}"
            );
        }
    }
    let (masked, _) = mask(&registry, "Appelez 06 12 34 56 78.john@ex.fr");
    assert!(!masked.contains("06 12 34 56 78"));
    assert!(!masked.contains("john@ex.fr"));
    let (masked, _) = mask(&registry, "Voir https://ex.fr/x(06 12 34 56 78) merci");
    assert!(!masked.contains("06 12 34 56 78"));
    assert!(!masked.contains("https://ex.fr/x"));
}

// P1-2: long digit runs are masked whole.
#[test]
fn p1_2_long_digit_runs_are_masked_whole() {
    let registry = Registry::new();
    for text in [
        "tel 06 12 34 56 78 123",
        "0612345678 2026",
        "appel +33 6 12 34 56 78 123",
    ] {
        let (masked, spans) = mask(&registry, text);
        assert!(!spans.is_empty(), "no span detected in {text:?}");
        for span in &spans {
            assert!(!masked.contains(&text[span.start..span.end]));
        }
    }
    let (masked, _) = mask(&registry, "tel 06 12 34 56 78 123");
    assert!(!masked.contains("06 12 34 56 78 123"));
    assert!(!masked.contains("123"));
    let (masked, _) = mask(&registry, "0612345678 2026");
    assert!(!masked.contains("0612345678"));
}

// P1-3: the IBAN table covers the corpus codes and unknown codes with a valid
// mod-97 check are still masked, with a lower score.
#[test]
fn p1_3_iban_length_table_and_unknown_country_fallback() {
    let registry = Registry::new();
    for text in [
        "IBAN FR76 9999 9000 0112 3456 7890 152",
        "IBAN ZA33 9999 0000 0112 3456 7890 12",
        "IBAN MA27 9990 0112 3456 7890 1234 5678",
        "IBAN GB76 9999 0000 0112 3456 78",
    ] {
        let spans = registry.analyze(text);
        assert_eq!(
            spans.len(),
            1,
            "not exactly one IBAN in {text:?}: {spans:?}"
        );
        assert_eq!(spans[0].kind, EntityKind::Iban);
        assert_eq!(spans[0].score, 1.0);
    }
    let unknown = registry.analyze("ZZ6630006000011234567890189");
    assert_eq!(unknown.len(), 1, "unknown-country IBAN not detected");
    assert_eq!(unknown[0].kind, EntityKind::Iban);
    assert!(unknown[0].score < 1.0, "unknown country must score lower");
}

// P1-4: Unicode e-mail local parts and IDN domains.
#[test]
fn p1_4_unicode_emails() {
    let registry = Registry::new();
    for text in [
        "müller@example.com",
        "josé.dupont@example.invalid",
        "jean@exémple.fr",
        "jean@example.рф",
    ] {
        let spans = registry.analyze(text);
        // The email layer may add a separate PERSON span for the local part
        // (slice 1e); the e-mail itself must still be detected and cover the
        // whole value.
        let email = spans
            .iter()
            .find(|span| span.kind == EntityKind::Email)
            .unwrap_or_else(|| panic!("not detected: {text:?} -> {spans:?}"));
        assert_eq!(&text[email.start..email.end], text, "partial email span");
    }
}

// P2-1 / P2-3: the shared normalisation layer.
#[test]
fn p2_1_ocr_and_unicode_digits_are_found() {
    let registry = Registry::new();
    for text in [
        "+33 l 99 OO 41 27",
        "tél 06\u{00A0}12\u{202F}34\u{2010}56\u{2212}78",
        "０６ １２ ３４ ５６ ７８",
        "٠٦ ١٢ ٣٤ ٥٦ ٧٨",
    ] {
        let spans = registry.analyze(text);
        assert!(
            spans.iter().any(|span| span.kind == EntityKind::Phone),
            "phone not detected in {text:?}: {spans:?}"
        );
    }
}

// P2-2: digit-run boundaries, not word boundaries.
#[test]
fn p2_2_values_glued_to_a_letter_are_detected() {
    let registry = Registry::new();
    let iban = registry.analyze("xFR7630006000011234567890189");
    assert!(
        iban.iter().any(|span| span.kind == EntityKind::Iban),
        "glued IBAN missed: {iban:?}"
    );
    let phone = registry.analyze("x0612345678");
    assert!(
        phone.iter().any(|span| span.kind == EntityKind::Phone),
        "glued phone missed: {phone:?}"
    );
    let mail = registry.analyze("x.john@ex.fr");
    assert!(
        mail.iter().any(|span| span.kind == EntityKind::Email),
        "glued email missed: {mail:?}"
    );
}

// P2-6: TokenMap Debug redacts values.
#[test]
fn p2_6_token_map_debug_redacts_values() {
    let registry = Registry::new();
    let text = "mail john@ex.fr tel +33 6 12 34 56 78";
    let spans = registry.analyze(text);
    let mut anonymizer = Anonymizer::new([0x22u8; 32]);
    let (_, pairs) = anonymizer.anonymize(text, &spans);
    let rendered = format!("{pairs:?}");
    assert!(!rendered.contains("john@ex.fr"), "TokenMap leaked an email");
    assert!(
        !rendered.contains("+33 6 12 34 56 78"),
        "TokenMap leaked a phone"
    );
    assert!(rendered.contains("EMAIL_"));
    assert!(rendered.contains("PHONE_"));
}

// P3-1: the HMAC key must change the token.
#[test]
fn p3_1_two_keys_give_different_tokens() {
    let text = "mail john@ex.fr";
    let start = text.find("john@ex.fr").unwrap();
    let spans = vec![kernel_privacy::Span::new(
        EntityKind::Email,
        start,
        start + "john@ex.fr".len(),
        1.0,
        "test",
    )];
    let mut one = Anonymizer::new([0xA1u8; 32]);
    let mut two = Anonymizer::new([0xB2u8; 32]);
    let (masked_one, pairs_one) = one.anonymize(text, &spans);
    let (masked_two, pairs_two) = two.anonymize(text, &spans);
    assert_ne!(pairs_one[0].0, pairs_two[0].0);
    assert_ne!(masked_one, masked_two);
}

// P3-2: the kind is part of the digest and restore returns exact bytes.
#[test]
fn p3_2_digest_includes_kind_and_restore_is_exact() {
    let text = "tel +33 6 12 34 56 78 et mail john@ex.fr";
    let spans = Registry::new().analyze(text);
    let mut anonymizer = Anonymizer::new([0xC3u8; 32]);
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    assert!(pairs
        .iter()
        .any(|(_, original)| original == "+33 6 12 34 56 78"));
    assert_eq!(
        Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep).text,
        text
    );

    // Same digits, different kinds, must not share a token.
    let mut kinded = Anonymizer::new([0xC3u8; 32]);
    let (phone, _) = kinded.token_for(EntityKind::Phone, "123456789");
    let (siren, _) = kinded.token_for(EntityKind::FrSiren, "123456789");
    assert_ne!(phone, siren);
}

// P3-3: over-masking guards.
#[test]
fn p3_3_version_strings_are_not_ipv4() {
    let registry = Registry::new();
    for text in ["build 1.2.3.4", "version 10.12.0.1"] {
        let spans = registry.analyze(text);
        assert!(
            !spans.iter().any(|span| span.kind == EntityKind::IpV4),
            "version string became IPV4: {text:?} -> {spans:?}"
        );
    }
    assert!(registry
        .analyze("host 192.168.0.1")
        .iter()
        .any(|span| span.kind == EntityKind::IpV4));
}

#[test]
fn p3_3_taj_labels_follow_the_cue_fail_toward_masking() {
    let registry = Registry::new();
    // Cueless (bare or grouped) is still masked, but as generic NATIONAL_ID.
    for text in ["szám 123456788", "szám 123 456 788"] {
        let spans = registry.analyze(text);
        assert!(
            spans.iter().any(|span| span.kind == EntityKind::NationalId),
            "cueless TAJ not masked in {text:?}: {spans:?}"
        );
        assert!(
            !spans.iter().any(|span| span.kind == EntityKind::HuTaj),
            "cueless TAJ claimed a specific kind in {text:?}"
        );
    }
    assert!(
        registry
            .analyze("TAJ 123456788")
            .iter()
            .any(|span| span.kind == EntityKind::HuTaj),
        "cued TAJ missed"
    );
    assert!(
        registry
            .analyze("adóazonosító 8123456786")
            .iter()
            .any(|span| span.kind == EntityKind::HuTaxId),
        "cued tax id missed"
    );
}

// Follow-up: FR NIR accepts spaced forms and is mounted by default; the
// registry labels its hits NATIONAL_ID (unverified rule).
#[test]
fn fr_nir_accepts_spaced_forms() {
    let recognizer = FrNirRecognizer::new();
    assert!(recognizer.enabled_by_default());
    let spans = recognizer.analyze("sécu 2 02 02 2A 018 063 76");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].kind, EntityKind::FrNir);
    assert!(!recognizer.verified());
}
