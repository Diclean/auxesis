//! Invented IBANs through the actual Private and Open gates.
#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, issue, masked, MODES};
use kernel_core::privacy::PrivacyMode;
use kernel_privacy::recognizers::iban::valid_iban;
fn iban(country: &str, bban: &str) -> String {
    let remainder = format!("{bban}{country}00").chars().fold(0, |r, c| {
        let n = c.to_digit(36).unwrap();
        (r * if n >= 10 { 100 } else { 10 } + n) % 97
    });
    let value = format!("{country}{:02}{bban}", 98 - remainder);
    assert!(valid_iban(&value), "invalid test specimen {value}");
    value
}
fn grouped(value: &str, separator: &str) -> String {
    value
        .as_bytes()
        .chunks(4)
        .map(|s| std::str::from_utf8(s).unwrap())
        .collect::<Vec<_>>()
        .join(separator)
}
#[test]
fn valid_ibans_are_wholly_hidden_in_both_modes() {
    let specimens = [
        iban("GB", "FAKE12345678901234"),
        iban("NL", "FAKE1234567890"),
        iban("IE", "FAKE12345678901234"),
        iban("FR", "1234567890ABC1234567890"),
        iban("MT", "FAKE12345123456789012ABCDEF"),
        iban("DE", "123456789012345678"),
    ];
    let mut misses = Vec::new();
    for compact in specimens {
        for value in [
            compact.clone(),
            grouped(&compact, " "),
            compact.to_lowercase(),
            grouped(&compact.to_lowercase(), " "),
            grouped(&compact, "\n  "),
            format!("{}\n{}", &compact[..1], &compact[1..]),
            format!("{}\n{}", &compact[..2], &compact[2..]).to_lowercase(),
            compact
                .chars()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        ] {
            for prefix in ["Pay to ", "IBAN", "code", "refXX12"] {
                let suffix = if prefix == "code" { "ok" } else { ", thanks." };
                let text = format!("{prefix}{value}{suffix}");
                for mode in MODES {
                    let ranges = masked(mode, &text).expect("gate allows");
                    if !covered(&ranges, prefix.len(), prefix.len() + value.len()) {
                        misses.push(format!("{mode:?} {text:?}: {ranges:?}"));
                    }
                }
            }
        }
    }
    assert!(
        misses.is_empty(),
        "uncovered valid IBANs:\n{}",
        misses.join("\n")
    );
}
#[test]
fn invalid_and_truncated_ibans_in_bank_context_are_hidden_in_private() {
    let valid = iban("GB", "FAKE12345678901234");
    let invalid = format!(
        "{}{}",
        &valid[..valid.len() - 1],
        if valid.ends_with('0') { '1' } else { '0' }
    );
    let truncated = &valid[..16];
    let mut misses = Vec::new();
    for value in [invalid, truncated.to_string()] {
        for prefix in ["IBAN: ", "IBAN", "Bank account: "] {
            let text = format!("{prefix}{value}, thanks.");
            let ranges = masked(PrivacyMode::Private, &text).expect("gate allows");
            if !covered(&ranges, prefix.len(), prefix.len() + value.len()) {
                misses.push(format!("{text:?}: {ranges:?}"));
            }
        }
    }
    for (prefix, value) in [
        ("IBAN: ", "GB46 FAKE 1234 5678"),
        ("bank: ", "gb46 fake 1234 5678"),
        ("compte: ", "FR121234567890ABC1234567890"),
    ] {
        let text = format!("{prefix}{value}, thanks.");
        let ranges = masked(PrivacyMode::Private, &text).expect("gate allows");
        if !covered(&ranges, prefix.len(), prefix.len() + value.len()) {
            misses.push(format!("{text:?}: {ranges:?}"));
        }
    }
    assert!(misses.is_empty(), "uncovered invalid IBANs: {misses:?}");
}
#[test]
fn ordinary_identifiers_keep_their_existing_output() {
    use kernel_privacy::{recognizers::iban::IbanRecognizer, Recognizer};
    assert!(IbanRecognizer::new()
        .analyze("Please send the parcel to 1 Lantern Road\n41395 Glenfallow before noon.")
        .is_empty());
    for text in [
        "Order number ORD-4827-1934 is ready.",
        "sandbox-EB23A270-1C4F-4D6A-9E2B-5A7C3D0F121B",
        "sha256 16e07db253f23a282d673668bd4b4656bf1f410962612fa4c7b4ddd87d893d77",
        "SWIFT/BIC: FAKEGB2LXXX.",
        "The spare part DE12AB34 is on the shelf.",
    ] {
        for mode in MODES {
            let (output, _) = issue(mode, text).expect("gate allows");
            assert_eq!(output, text, "{mode:?}: {text}");
        }
    }
}
#[test]
#[ignore = "release-mode timing: run with --release --ignored"]
fn dense_iban_anchors_scale_to_one_mib() {
    use kernel_privacy::{recognizers::iban::IbanRecognizer, Recognizer};
    use std::time::Instant;
    let run = |s: &str| {
        (0..3)
            .map(|_| {
                let start = Instant::now();
                std::hint::black_box(IbanRecognizer::new().analyze(s));
                start.elapsed()
            })
            .min()
            .unwrap()
    };
    for unit in [
        "bank DE12AB34 ".to_string(),
        format!("IBAN {} ", iban("GB", "FAKE12345678901234")),
    ] {
        let text = unit.repeat(1024 * 1024 / unit.len() + 1);
        let text = &text[..1024 * 1024];
        let small = run(&text[..text.len() / 4]);
        let large = run(text);
        let ratio = large.as_secs_f64() / small.as_secs_f64().max(0.001);
        eprintln!("IBAN {unit:?}: 256 KiB {small:?}; 1 MiB {large:?}; ratio {ratio:.2}");
        assert!(ratio < 9.0, "super-linear: {ratio:.2}");
    }
}
