//! Deterministic fuzz round-trip: every masked occurrence must restore to its
//! exact original bytes. 50,000 generated documents, 0 mismatches required.
//!
//! The pool deliberately includes several surface spellings of the same
//! identifier, so a shared token covers different byte strings and the
//! per-occurrence restore path is exercised. Fake data only.

use kernel_privacy::{Anonymizer, Registry, UnknownPolicy};

/// The identifier fragments, with distinct surface spellings of shared values.
/// The last block is delimiter, escape and token-like noise: the masked text
/// must escape it and restore it byte for byte, and none of it may be read as
/// one of our placeholders.
const FRAGMENTS: &[&str] = &[
    "0612345678",
    "06 12 34 56 78",
    "06.12.34.56.78",
    "+33 6 12 34 56 78",
    "0033612345678",
    "a@example.invalid",
    "jean.dupont@example.invalid",
    "josé@example.invalid",
    "FR7630006000011234567890189",
    "FR76 3000 6000 0112 3456 7890 189",
    "202022A01806376",
    "2 02 02 2A 018 063 76",
    "73282932000074",
    "4111 1111 1111 1111",
    "192.168.0.1",
    "https://example.invalid/x",
    "hello",
    "le",
    "numéro",
    "merci",
    "x",
    "42",
    "build",
    "⟦",
    "⟧",
    "⟦PHONE_ab12cd⟧",
    "PHONE_ab12cd",
    "EMAIL_ab12cd",
    "\\",
    "\\u27E6",
    "〚",
    "〛",
];

/// A tiny reproducible PRNG (SplitMix64-shaped LCG).
fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

fn build(state: &mut u64) -> String {
    let mut text = String::new();
    let count = 1 + (next(state) % 3) as usize;
    for index in 0..count {
        if index > 0 {
            text.push(' ');
        }
        let fragment = FRAGMENTS[(next(state) as usize) % FRAGMENTS.len()];
        text.push_str(fragment);
    }
    text
}

#[test]
fn fifty_thousand_documents_round_trip_exactly() {
    let registry = Registry::new();
    let mut anonymizer = Anonymizer::new([0x77u8; 32]);
    let mut state = 0x1234_5678_9abc_def0u64;
    let mut mismatches = 0usize;
    let mut occurrences = 0usize;

    for _ in 0..50_000 {
        let text = build(&mut state);
        let spans = registry.analyze(&text);
        occurrences += spans.len();
        let (masked, pairs) = anonymizer.anonymize(&text, &spans);
        let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
        if report.text != text || !report.is_clean() {
            mismatches += 1;
        }
    }

    assert!(occurrences > 0, "fuzz generated no masked spans");
    assert_eq!(mismatches, 0, "{mismatches} round-trip mismatches");
}
