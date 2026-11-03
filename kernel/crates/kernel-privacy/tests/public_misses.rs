//! K-PUBLIC-MISSES: values the lab demo pass, EVAL-PUBLIC-1 (#121) and the #126 seal
//! saw leave raw (the maintainer's spec, 2026-10-19). Each MUST-MASK value is
//! gone in both modes (an e-mail or a phone is only reported in open mode);
//! each MUST-NOT-MASK sentence passes unchanged in both. Every rule here only
//! adds spans to main's.

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::recognizer::Recognizer;
use kernel_privacy::recognizers::payment_ids::PaymentIdsRecognizer;
use kernel_privacy::{EntityKind, Gate};

const KEY: [u8; 32] = [7u8; 32];

/// (text, the value in it that must not reach the model).
const MUST_MASK: &[(&str, &str)] = &[
    // 1. A generic ID right after an ID label (lab demo pass: raw nine times).
    ("My ID number is 123456789012", "123456789012"),
    ("ID: 123456789012", "123456789012"),
    ("my ID no. 123456789012", "123456789012"),
    ("ID card number 123456789012", "123456789012"),
    ("personal ID AB1234567", "AB1234567"),
    ("n° CNI 123456789012", "123456789012"),
    ("Their ID is 123456789012.", "123456789012"),
    ("numéro d'identité 123456789012", "123456789012"),
    ("my identity number is X1234567", "X1234567"),
    ("national ID: AB1234567", "AB1234567"),
    ("ID no 987654", "987654"),
    // 2. Ungrouped Luhn-valid cards with a known BIN and no cue.
    ("4991080457040835", "4991080457040835"),
    // TODO (backlog K-CARD-GLUE): 3592… (JCB outside 3528–3589) and cards glued to other
    // digits by a line break; the round-2 rules over-masked phone lists (#129 pre-review).
    ("see 2278012030709725.", "2278012030709725"),
    // 3. Dropbox-style short-lived token, no cue.
    (
        "use sl.jLIsDJ2dBqgbPjp8f9EZcZ3kTEcO for now",
        "jLIsDJ2dBqgbPjp8f9EZcZ3kTEcO",
    ),
    // 4. Phones (open mode reports them, see OPEN_REPORTS).
    ("call me on 06-12345678", "12345678"),
    ("my number is +52 1 55 1234 5678", "1234 5678"),
    // 5. #126 seal.
    (r#"the passwords are "A1xx" and "B2yy""#, "A1xx"),
    (r#"the passwords are "A1xx" and "B2yy""#, "B2yy"),
    // #129 pre-review: grouped ID values and a comma after a quoted list item.
    ("My ID number is 1234 5678 9012", "1234 5678 9012"),
    ("national ID 123 456 789", "123 456 789"),
    ("National ID: 85.07.30-033.28", "85.07.30-033.28"),
    ("ID no. AB 123456", "AB 123456"),
    ("the passwords are 'A1xx', 'B2yy'", "B2yy"),
    ("the door code is set to 4521", "4521"),
    ("the door code was changed to 4521", "4521"),
    // 6. EVAL-PUBLIC-1 e-mail misses (invented local parts, reserved domain).
    // Both handles are invented: same shape as the dataset miss they stand in
    // for (letters + dot + letters + digit, and letters + digits), same test.
    ("write to mira.quellen4@example.com", "mira.quellen4"),
    ("cc tobrenx82@example.com please", "tobrenx82"),
];

/// The probes open mode leaves in clear by design (an e-mail or a phone): it reports them.
const OPEN_REPORTS: &[&str] = &[
    "call me on 06-12345678",
    "write to mira.quellen4@example.com",
    "cc tobrenx82@example.com please",
];

const MUST_NOT_MASK: &[&str] = &[
    "room 4821",
    "order 55210",
    "ID card photo attached",
    "the ID is in the drawer",
    "the ID card is in the drawer",
    "order ID: 55210",
    // Business references stay readable (a customer ID too): Aux follows orders by them.
    "Transaction ID: 123456789",
    "invoice ID INV-2026-0042",
    "customer ID 88213",
    "customer ID number 123456789012",
    "client's ID number 123456789012",
    "the order-line ID #123456789",
    "employee id is MKT-6392",
    "see ID 123456789012",
];

/// Business references the ID-label rule leaves alone (main's `passport_mrz` and `iban`
/// rules still mask the first four, as before this change).
const BUSINESS_REFS: &[&str] = &[
    "Order ID 55210931",
    "ticket ID 4471923",
    "Booking ID: AB12345678",
    "tracking ID 1Z999AA10123456784",
    "reference ID 123456789012",
    "my session ID 123456789012",
];

/// An invalid SSN group with no cue gets no ID span (main's phone and `SSN` cue rules
/// still apply).
const NO_ID_SPAN: &[&str] = &["the reference 232-00-8506 is wrong"];

fn vendor() -> Context {
    Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    }
}

fn grant(mode: PrivacyMode) -> Grant {
    match admit(PathId::A1, mode, &vendor()) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow for A1 in {mode:?}, got {other:?}"),
    }
}

fn gate(mode: PrivacyMode) -> Gate {
    match mode {
        PrivacyMode::Open => Gate::for_grant(&grant(mode), KEY),
        PrivacyMode::Private => {
            Gate::for_grant_with_names(&grant(mode), KEY, ["Camille Exemple"]).expect("dictionary")
        }
    }
}

/// The parts of a value that could leak on their own (four characters or more).
fn fragments(value: &str) -> impl Iterator<Item = &str> {
    value.split([' ', '-']).filter(|part| part.len() >= 4)
}

#[test]
fn each_probe_value_is_masked_in_both_modes() {
    let mut leaks = Vec::new();
    for &(text, value) in MUST_MASK {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let mut gate = gate(mode);
            let (safe, report) = gate.text(text).expect("text");
            let out = safe.as_str();
            if mode == PrivacyMode::Open && OPEN_REPORTS.contains(&text) {
                if report.counts().all(|(_, count)| count == 0) {
                    leaks.push(format!("{mode:?} {text:?} not reported"));
                }
            } else if out.contains(value) || fragments(value).any(|part| out.contains(part)) {
                leaks.push(format!("{mode:?} {text:?} -> {out:?}"));
            }
        }
    }
    assert!(leaks.is_empty(), "leaked:\n{}", leaks.join("\n"));
}

#[test]
fn a_private_mode_probe_is_restored_for_the_owner() {
    for &(text, _) in MUST_MASK {
        let mut gate = gate(PrivacyMode::Private);
        let (safe, _) = gate.text(text).expect("text");
        let mut restored = safe.as_str().to_string();
        for (token, original) in gate.take_minted() {
            restored = restored.replace(&format!("⟦{token}⟧"), &original);
        }
        assert_eq!(restored, text, "private mode must restore {text:?}");
    }
}

#[test]
fn a_probe_with_no_sensitive_value_is_left_unchanged() {
    let mut masked = Vec::new();
    for &text in MUST_NOT_MASK {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let (safe, _) = gate(mode).text(text).expect("text");
            if safe.as_str() != text {
                masked.push(format!("{mode:?} {text:?} -> {:?}", safe.as_str()));
            }
        }
    }
    assert!(masked.is_empty(), "false positives:\n{}", masked.join("\n"));
}

#[test]
fn an_invalid_ssn_group_gets_no_id_span() {
    for &text in NO_ID_SPAN {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let (_, report) = gate(mode).text(text).expect("text");
            assert_eq!(
                report.count(EntityKind::NationalId),
                0,
                "{mode:?} {text:?} must get no ID span"
            );
        }
    }
}

#[test]
fn the_id_label_rule_leaves_business_references_alone() {
    for &text in MUST_NOT_MASK.iter().chain(BUSINESS_REFS) {
        let spans = PaymentIdsRecognizer::new().analyze(text);
        assert!(spans.is_empty(), "{text:?} -> {spans:?}");
    }
}

/// The eval scores the registry private mode runs: with names
/// dropped before the merge, a health word next to a name never yields a region that
/// covers a value private mode leaves in clear.
#[test]
fn the_eval_registry_drops_names_before_the_merge() {
    let text = "From: Cancer A1xx <sender@example.invalid>";
    let value = text.find("A1xx").unwrap();
    let covers = |spans: Vec<kernel_privacy::Span>| {
        spans
            .iter()
            .any(|span| span.start <= value && value + 4 <= span.end)
    };
    // With names kept, the name widens the health region over the value.
    assert!(covers(kernel_privacy::Registry::new().analyze(text)));
    let spans = kernel_privacy::Registry::new()
        .without_names()
        .analyze(text);
    assert!(
        !covers(
            kernel_privacy::Registry::new()
                .without_names()
                .analyze(text)
        ),
        "{spans:?}"
    );
}
