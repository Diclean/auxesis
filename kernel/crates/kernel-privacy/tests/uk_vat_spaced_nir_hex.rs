//! Spaced UK VAT numbers and checksum-valid NIRs beside hex remain masked.

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::recognizers::fr::FrNirRecognizer;
use kernel_privacy::{company_id, Gate, Recognizer};

#[allow(dead_code)]
mod exact {
    include!("data/exact_mask.rs");
}

const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];

fn issue(mode: PrivacyMode, input: &str) -> (String, Vec<(String, String)>) {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
        panic!("A1 must be allowed in {mode:?}");
    };
    let mut gate = Gate::for_grant(&grant, [9u8; 32]);
    let output = gate
        .text(input)
        .expect("the gate accepts this input")
        .0
        .as_str()
        .to_string();
    (output, gate.take_minted())
}

fn ranges(mode: PrivacyMode, input: &str) -> Vec<(usize, usize)> {
    let (output, minted) = issue(mode, input);
    exact::exact_or_fail(mode, input, &output, &minted)
}

fn covered(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    (start..end).all(|byte| ranges.iter().any(|&(s, e)| s <= byte && byte < e))
}

#[test]
fn spaced_uk_vat_forms_match_compact_checksum_and_cue_rules() {
    // 123456782 passes the UK check; the VAT cue permits the labelled 89
    // example under the existing recognizer's cue rule.
    for (text, value) in [
        ("GB 123 4567 82", "GB 123 4567 82"),
        ("GB123 4567 82", "GB123 4567 82"),
        ("VAT reg no: 123 4567 89", "123 4567 89"),
        ("GB 123 4567 82 012", "GB 123 4567 82 012"),
    ] {
        let start = text.find(value).expect("value occurs in text");
        for mode in MODES {
            assert!(
                covered(&ranges(mode, text), start, start + value.len()),
                "{mode:?} left {value:?} clear in {text:?}"
            );
        }
    }

    // Do not broaden the recognizer to invalid unlabelled VAT shapes.
    for text in ["GB 123 4567 89", "GB123456789", "GB 123 4567 89 012"] {
        assert!(
            company_id::recognize(text).is_empty(),
            "VAT matched {text:?}"
        );
    }
}

#[test]
fn valid_nir_is_masked_next_to_hex_in_both_modes() {
    let cases = [
        ("ref:a3f9 1 85 05 78 006 084 91", "1 85 05 78 006 084 91"),
        ("0x1f2e185057800608491", "185057800608491"),
    ];
    for (text, value) in cases {
        let start = text.find(value).expect("NIR occurs in text");
        for mode in MODES {
            assert!(
                covered(&ranges(mode, text), start, start + value.len()),
                "{mode:?} left NIR {value:?} clear in {text:?}"
            );
        }
    }

    // The supplied `...436` ending has an invalid key for this stem. Only a
    // checksum-valid NIR may be admitted from an opaque hex token.
    let invalid_hex_nir = "0x1f2e185057800608436";
    assert!(
        FrNirRecognizer::new().analyze(invalid_hex_nir).is_empty(),
        "a hex-glued NIR with an invalid key must not match"
    );
}

#[test]
fn phone_and_uncued_order_number_are_not_uk_vat() {
    for text in ["020 7946 0958", "Order 123 4567 89"] {
        assert!(
            company_id::recognize(text).is_empty(),
            "UK VAT recognizer matched {text:?}"
        );
    }
}
