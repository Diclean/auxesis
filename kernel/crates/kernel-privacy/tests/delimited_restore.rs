//! The final security-review seal, P2: placeholders are delimited, so token-like clear text can
//! never be mistaken for one of ours, and an unknown or cross-session token is
//! reported instead of restored. Fake data only.

use kernel_privacy::{Anonymizer, EntityKind, Registry, Span, UnknownPolicy};

fn phone_span(text: &str) -> Span {
    let start = text.find("0612345678").expect("the fake number is present");
    Span::new(EntityKind::Phone, start, start + 10, 1.0, "test")
}

// Clear text that contains a token-like string before and after a real
// placeholder must survive byte for byte; only the delimited placeholder is a
// placeholder. The span is supplied directly so the test pins the restore path
// rather than the recogniser's opinion of `PHONE_ab12cd`.
#[test]
fn token_like_clear_text_before_and_after_a_placeholder() {
    let mut anonymizer = Anonymizer::new([0x51u8; 32]);
    let text = "PHONE_ab12cd tel 0612345678 PHONE_ab12cd";
    let spans = vec![phone_span(text)];
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    // The undelimited lookalikes stay in the clear; only the real value is
    // replaced, and that replacement is delimited.
    assert_eq!(masked.matches("PHONE_ab12cd").count(), 2);
    assert!(masked.contains("⟦PHONE_"));
    let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text, "the lookalikes must not be swapped");
    assert!(report.is_clean());
}

// The strongest form: the clear text contains the session's *real* token, before
// and after the value it masks. The old scan-by-substring restore swapped the
// wrong occurrence; the delimited parse must not.
#[test]
fn clear_text_equal_to_the_real_token_is_never_swapped() {
    let registry = Registry::new();
    let mut anonymizer = Anonymizer::new([0x52u8; 32]);
    let (token, _) = anonymizer.token_for(EntityKind::Phone, "0612345678");
    let text = format!("{token} before 0612345678 after {token}");
    let spans = registry.analyze(&text);
    assert!(
        spans.iter().any(|span| span.kind == EntityKind::Phone),
        "the fake number must be detected: {spans:?}"
    );
    let (masked, pairs) = anonymizer.anonymize(&text, &spans);
    let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text);
    assert!(report.is_clean());
}

// Input that already contains the literal delimiters: they are escaped, so the
// masked text has exactly our one placeholder and restore is exact.
#[test]
fn literal_delimiters_in_the_input_are_escaped() {
    let registry = Registry::new();
    let mut anonymizer = Anonymizer::new([0x53u8; 32]);
    let text = "litteral ⟦ bracket ⟧ and tel 0612345678 fin";
    let mut spans = registry.analyze(text);
    spans.retain(|span| span.kind == EntityKind::Phone);
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    assert_eq!(
        masked.matches('⟦').count(),
        3,
        "the literal opener is doubled; ours is the third"
    );
    assert!(masked.contains("litteral ⟦⟦ bracket ⟧ and tel"));
    let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text);
    assert!(report.is_clean());
}

// An invented token inside delimiters is not restored: it is reported, kept
// visible on request, and replaced with the plan's marker on request.
#[test]
fn invented_token_is_reported_unknown_and_not_restored() {
    let registry = Registry::new();
    let mut anonymizer = Anonymizer::new([0x54u8; 32]);
    let text = "tel 0612345678 fin";
    let spans = registry.analyze(text);
    let (_, pairs) = anonymizer.anonymize(text, &spans);

    let cloud = "voici ⟦PHONE_zzzzzz⟧ merci";
    let kept = Anonymizer::restore(cloud, &pairs, UnknownPolicy::Keep);
    assert_eq!(kept.unknown, vec!["PHONE_zzzzzz".to_string()]);
    assert_eq!(kept.text, cloud, "an unknown token is never rehydrated");
    assert!(!kept.is_clean());

    let redacted = Anonymizer::restore(cloud, &pairs, UnknownPolicy::Redact);
    assert_eq!(redacted.text, "voici [unknown reference] merci");
    assert_eq!(redacted.unknown, vec!["PHONE_zzzzzz".to_string()]);
}

// A token minted under another session key (the same value, a different HMAC)
// is absent from this session's map, so it is reported unknown, not restored.
#[test]
fn forged_token_from_another_session_is_reported_unknown() {
    let registry = Registry::new();
    let mut session = Anonymizer::new([0x55u8; 32]);
    let text = "tel 0612345678";
    let spans = registry.analyze(text);
    let (_, pairs) = session.anonymize(text, &spans);

    let mut other = Anonymizer::new([0x56u8; 32]);
    let (forged, _) = other.token_for(EntityKind::Phone, "0612345678");
    assert!(
        pairs.iter().all(|(token, _)| token != &forged),
        "the forged token must differ from the session token"
    );

    let cloud = format!("valeur ⟦{forged}⟧");
    let report = Anonymizer::restore(&cloud, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.unknown, vec![forged]);
    assert_eq!(report.text, cloud);
}

// A real placeholder and undelimited token-like text in one pass: only the
// delimited one is restored, and the result is still exact.
#[test]
fn a_real_placeholder_next_to_token_like_text_restores_exactly() {
    let registry = Registry::new();
    let mut anonymizer = Anonymizer::new([0x57u8; 32]);
    let text = "garde PHONE_deadbe puis 0612345678 puis ⟦EMAIL_000000⟧";
    let mut spans = registry.analyze(text);
    spans.retain(|span| span.kind == EntityKind::Phone);
    let (masked, pairs) = anonymizer.anonymize(text, &spans);
    // The invented `EMAIL_000000` was already delimited in the clear text; it is
    // escaped and stays literal, and is not reported as an unknown token.
    let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
    assert_eq!(report.text, text);
    assert!(report.is_clean());
}

// Full pipeline over fake data: exact round-trip remains, escapes included.
#[test]
fn full_pipeline_round_trip_is_still_exact() {
    let registry = Registry::new();
    let mut anonymizer = Anonymizer::new([0x58u8; 32]);
    for text in [
        "tel 0612345678 puis 06 12 34 56 78 fin",
        "mail a@example.invalid et 192.168.0.1",
        "literal ⟦ et ⟧ with iban FR7630006000011234567890189",
        "reverse \\ and \\u27E6 text",
        "〚 white square brackets 〛",
        "no span at all, just ⟦PHONE_ab12cd⟧ and PHONE_ab12cd",
    ] {
        let spans = registry.analyze(text);
        let (masked, pairs) = anonymizer.anonymize(text, &spans);
        let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
        assert_eq!(report.text, text, "round-trip failed for {text:?}");
        assert!(report.is_clean(), "unexpected unknown token for {text:?}");
    }
}
