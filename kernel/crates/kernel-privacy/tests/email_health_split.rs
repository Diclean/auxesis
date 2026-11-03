//! E-mail spans keep their complete byte coverage when a higher-priority
//! detector also matches inside the local part.

#[path = "data/exact_mask.rs"]
mod exact;

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::recognizers::email::EmailRecognizer;
use kernel_privacy::{Gate, Recognizer, Registry};

const KEY: [u8; 32] = [0x43; 32];
const SENSITIVE_EMAILS: &[&str] = &[
    "ptsd@exemple.test",
    "diabetes@exemple.test",
    "hiv.clinic@exemple.test",
    "sk-test@exemple.test",
    "AB123456C@exemple.test",
    "owner@ptsd.exemple.test",
    "owner@diabetes.exemple.test",
    "owner@hiv.clinic.test",
    "owner@sk-test.exemple.test",
    "owner@AB123456C.exemple.test",
];

fn grant(mode: PrivacyMode) -> Grant {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &context) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow for A1 in {mode:?}, got {other:?}"),
    }
}

fn exact_mask_covers(
    mode: PrivacyMode,
    text: &str,
    needle: &str,
    output: &str,
    minted: &[(String, String)],
) {
    let start = text.find(needle).expect("needle is in input");
    let end = start + needle.len();
    let ranges = exact::exact_or_fail(mode, text, output, minted);
    assert!(
        ranges.iter().any(|&(from, to)| from <= start && end <= to),
        "{mode:?} did not mask all bytes of {needle:?}: {text:?} -> {output:?}; {ranges:?}"
    );
}

#[test]
fn registry_email_span_covers_sensitive_address_parts_whole() {
    let registry = Registry::new();
    let email_recognizer = EmailRecognizer::new();
    for email in SENSITIVE_EMAILS {
        let email_spans = email_recognizer.analyze(email);
        assert!(
            email_spans
                .iter()
                .any(|span| span.start == 0 && span.end == email.len()),
            "e-mail recognizer did not detect {email:?} whole: {email_spans:?}"
        );
        let spans = registry.analyze(email);
        assert!(
            spans
                .iter()
                .any(|span| span.start == 0 && span.end == email.len()),
            "no whole-value span for {email:?}: {spans:?}"
        );
    }
}

#[test]
fn private_gate_masks_each_sensitive_email_as_a_whole_value() {
    for email in SENSITIVE_EMAILS {
        let input = format!("Please reply to {email}.");
        let mut gate = Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Owner"])
            .expect("name dictionary");
        let (safe, _) = gate.text(&input).expect("private text is tokenised");
        let minted = gate.take_minted();
        exact_mask_covers(PrivacyMode::Private, &input, email, safe.as_str(), &minted);
    }
}

#[test]
fn open_gate_keeps_the_whole_email_inside_a_prohibited_health_region() {
    let mut gate = Gate::for_grant(&grant(PrivacyMode::Open), KEY);
    for email in [
        "ptsd@exemple.test",
        "diabetes@exemple.test",
        "hiv.clinic@exemple.test",
        "owner@ptsd.exemple.test",
        "owner@diabetes.exemple.test",
        "owner@hiv.clinic.test",
    ] {
        let input = format!("Please reply to {email}.");
        let (safe, _) = gate.text(&input).expect("open text passes through");
        exact_mask_covers(PrivacyMode::Open, &input, email, safe.as_str(), &[]);
    }
}

#[test]
fn exact_mask_alignment_holds_for_two_thousand_inputs_in_both_modes() {
    let mut private = Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Owner"])
        .expect("name dictionary");
    let mut open = Gate::for_grant(&grant(PrivacyMode::Open), KEY);

    for index in 0..2_000 {
        let base = SENSITIVE_EMAILS[index % SENSITIVE_EMAILS.len()];
        let (local, domain) = base.split_once('@').expect("address shape");
        let email = format!("{local}+{index}@{domain}");
        let input = format!("case {index}: please reply to {email}.");

        let (private_text, _) = private.text(&input).expect("private mode does not refuse");
        let private_minted = private.take_minted();
        exact_mask_covers(
            PrivacyMode::Private,
            &input,
            &email,
            private_text.as_str(),
            &private_minted,
        );

        let (open_text, _) = open.text(&input).expect("open mode does not refuse");
        let open_minted = open.take_minted();
        exact::exact_or_fail(PrivacyMode::Open, &input, open_text.as_str(), &open_minted);
    }
}
