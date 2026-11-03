//! GATE-RESTORE-API: `kernel_privacy::restore` puts a gate's minted pairs back.
//!
//! The gate is the production path (`admit` -> `Gate::for_grant` -> `text` ->
//! `take_minted`), so the round-trip property runs on real minted token names and
//! real escaped text. All values are invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{restore, Gate, UnknownPolicy, UNKNOWN_REFERENCE};
use proptest::prelude::*;

const KEY: [u8; 32] = [0x3Au8; 32];
const EMAIL: &str = "alice@example.com";
const IBAN: &str = "GB82 WEST 1234 5698 7654 32";

/// A real Private grant: the gate mints tokens only under one.
fn grant() -> Grant {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, PrivacyMode::Private, &context) {
        Decision::Allow(grant) => grant,
        other => panic!("A1 must be allowed in Private mode: {other:?}"),
    }
}

/// The production path: the gate's text and the pairs it minted.
fn gate_text(text: &str) -> (String, Vec<(String, String)>) {
    let mut gate = Gate::for_grant(&grant(), KEY);
    let (safe, _report) = gate.text(text).expect("the gate issues");
    (safe.as_str().to_string(), gate.take_minted())
}

#[test]
fn known_tokens_restore_and_the_escape_reverses() {
    let minted = vec![
        ("EMAIL_AA".to_string(), EMAIL.to_string()),
        ("IBAN_BB".to_string(), IBAN.to_string()),
    ];
    let cases = [
        ("", ""),
        ("⟦EMAIL_AA⟧", EMAIL),
        (
            "Hi ⟦EMAIL_AA⟧, pay ⟦IBAN_BB⟧.",
            "Hi alice@example.com, pay GB82 WEST 1234 5698 7654 32.",
        ),
        // `⟦⟦` is the literal opener that the gate wrote doubled.
        ("⟦⟦EMAIL_AA⟧", "⟦EMAIL_AA⟧"),
        // An empty token and an unclosed marker are text, as in `restore`.
        ("⟦⟧", "⟦⟧"),
        ("⟦EMAIL_AA", "⟦EMAIL_AA"),
        // Every occurrence is restored, not only the first.
        (
            "⟦EMAIL_AA⟧ ⟦EMAIL_AA⟧",
            "alice@example.com alice@example.com",
        ),
        // Unknown delimited tokens under `Keep` stay visible.
        ("⟦EMAIL_AA⟧ ⟦EMAIL_CC⟧", "alice@example.com ⟦EMAIL_CC⟧"),
    ];
    for (input, expected) in cases {
        assert_eq!(
            restore(input, &minted, UnknownPolicy::Keep),
            expected,
            "restore({input:?})"
        );
    }
}

#[test]
fn unknown_tokens_follow_the_policy() {
    let minted = vec![("EMAIL_AA".to_string(), EMAIL.to_string())];
    let unknown = "a ⟦EMAIL_ZZ⟧ b";
    assert_eq!(restore(unknown, &minted, UnknownPolicy::Keep), unknown);
    assert_eq!(
        restore(unknown, &minted, UnknownPolicy::Redact),
        format!("a {UNKNOWN_REFERENCE} b")
    );

    // A malformed marker is not a delimited token: no policy invents an end for
    // it, so it passes through unchanged.
    for policy in [UnknownPolicy::Keep, UnknownPolicy::Redact] {
        assert_eq!(restore("a ⟦⟧ b", &minted, policy), "a ⟦⟧ b");
        assert_eq!(restore("a ⟦EMAIL_ZZ b", &minted, policy), "a ⟦EMAIL_ZZ b");
    }
}

/// Lowercase words and punctuation only: no second e-mail or IBAN can be built
/// inside the filler, so the fixed values are the only minted surfaces.
fn filler() -> impl Strategy<Value = String> {
    proptest::string::string_regex(r"[a-zàâäéèêëîïôöùûüç .,;:!?'’\n⟦⟧\\«»()_/-]{0,80}")
        .expect("the filler regex is valid")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `restore(gate.text(x), gate.take_minted()) == x` through the real gate.
    #[test]
    fn gate_round_trip_with_an_email_and_an_iban(before in filler(), after in filler()) {
        let text = format!("{before} Mail {EMAIL}, IBAN {IBAN}. {after}");
        let (safe, minted) = gate_text(&text);
        prop_assert!(!minted.is_empty(), "the gate minted no token for {text:?}");
        prop_assert_eq!(restore(&safe, &minted, UnknownPolicy::Keep), text);
    }

    /// Whatever the UTF-8, a lookup never panics; both policies read it.
    #[test]
    fn arbitrary_utf8_never_panics(
        text in any::<String>(),
        token in any::<String>(),
        value in any::<String>(),
    ) {
        let minted = vec![(token, value)];
        let _ = restore(&text, &minted, UnknownPolicy::Keep);
        let _ = restore(&text, &minted, UnknownPolicy::Redact);
    }
}

/// The helper walks the answer once. A 1 MiB answer with known tokens, unknown
/// tokens and escaped openers is the adversarial shape for the parser.
#[test]
fn one_mebibyte_restores_under_two_seconds_in_debug() {
    const SIZE: usize = 1024 * 1024;
    let minted: Vec<(String, String)> = (0..32)
        .map(|index| {
            (
                format!("EMAIL_{index:012X}"),
                format!("person{index}@example.invalid"),
            )
        })
        .collect();
    let units = [
        format!("Hi ⟦{}⟧, ", minted[0].0),
        "unknown ⟦TOKEN_000000000000⟧ ".to_string(),
        "literal ⟦⟦ opener, ".to_string(),
        "ordinary words and punctuation. ".to_string(),
    ];
    let unit_bytes: usize = units.iter().map(String::len).sum();

    let mut answer = String::with_capacity(SIZE);
    while answer.len() + unit_bytes <= SIZE {
        for unit in &units {
            answer.push_str(unit);
        }
    }
    answer.push_str(&" ".repeat(SIZE - answer.len()));
    assert_eq!(answer.len(), SIZE);

    let start = Instant::now();
    let restored = restore(&answer, &minted, UnknownPolicy::Keep);
    let elapsed = start.elapsed();
    std::hint::black_box(&restored);

    assert!(restored.contains("person0@example.invalid"));
    assert!(restored.contains("literal ⟦ opener"));
    assert!(
        elapsed < Duration::from_secs(2),
        "restore took {elapsed:?} on a 1 MiB input"
    );
}
