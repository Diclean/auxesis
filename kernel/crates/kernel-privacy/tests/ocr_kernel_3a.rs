//! OCR-KERNEL-3a acceptance (re-cut of OCR-KERNEL-2, items 1 and 2).
//!
//! 1. A character whose lower case changes its byte length or its letters
//!    (`İ`, `ẞ`, `ﬃ`, the Kelvin sign) next to a greeting, a birth cue or a
//!    speech verb: the e-mail layer sliced the original line at a lowered
//!    offset and panicked, so the gate refused. Both modes now issue, and
//!    Private still hides the date after the cue.
//! 2. Prohibited labels on the mask regions are one sorted sweep, so a text
//!    dense with prohibited values is no longer quadratic, and every byte of
//!    them is still removed.
//!
//! 3. Glued joiner runs: #295 read a run (`__`, `\_`, `‐`, `−`) as one only in
//!    its new birth-label rule, which is not in this cut. On main a joiner run
//!    before a secret label still reads the label, and that stays: the value
//!    is removed in both modes.
//!
//! Every value is invented; the FR IBAN is the public specimen.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{issue, MODES};

/// Characters whose lower case is longer, shorter or another letter.
const ODD: [&str; 10] = ["İ", "ı", "ß", "ẞ", "ǅ", "ﬃ", "Σ", "ΑΣ", "İİ", "\u{212A}"];

/// A greeting, a cue, a verb or a header key with `{}` where an odd character goes.
const FRAMES: [&str; 15] = [
    "H{} Alice",
    "Hi{} Alice",
    "{}Hi Alice",
    "Hİ{}, Alice",
    "Bonjour{} Élise,",
    "Dear{} Alice",
    "> H{} Alice",
    "{}DOB{} 14/03/1985",
    "born{} 14/03/1985 {}",
    "{} сказала X {}",
    "P.S.{} Alice",
    "N{}B Alice",
    "Le 5 oct. 2026, {} Alice a écrit{} :",
    "From{}: Alice <alice@example.invalid>",
    "Subject{}: hi {} Alice",
];

/// Every frame with every odd character issues in both modes.
#[test]
fn case_changing_characters_never_refuse() {
    let mut wrong = Vec::new();
    for frame in FRAMES {
        for ch in ODD {
            let text = frame.replace("{}", ch);
            for mode in MODES {
                if issue(mode, &text).is_none() {
                    wrong.push(format!("{mode:?} refused {text:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A length-changing letter before a birth cue: both modes issue and Private
/// still hides the date. The plain cue is the positive control.
#[test]
fn length_changing_lowercase_still_hides_the_date() {
    for (text, date) in [
        ("DOB 14/03/1985", Some("14/03/1985")),
        ("İDOBé 14/03/1985", Some("14/03/1985")),
        ("ẞİ born 14/03/1985", Some("14/03/1985")),
        ("İ сказала X ẞ", None),
    ] {
        for mode in MODES {
            let Some((output, _)) = issue(mode, text) else {
                panic!("{mode:?} refused {text:?}");
            };
            if let (PrivacyMode::Private, Some(date)) = (mode, date) {
                assert!(!output.contains(date), "{text:?} -> {output:?}");
            }
        }
    }
}

/// Negative control: plain prose with odd characters and no value comes back
/// whole in Open mode.
#[test]
fn odd_characters_in_plain_prose_stay_in_open() {
    for text in [
        "Die Straße ist lang.",
        "İstanbul is far, ﬃ is a ligature.",
        "Water boils at 373 \u{212A}.",
    ] {
        let (output, _) = issue(PrivacyMode::Open, text).expect("issued");
        assert_eq!(output, text);
    }
}

/// A secret label glued on by a joiner run still hides its value in both
/// modes; a single joiner inside an identifier is no label (main's
/// `inside_word`), and plain prose with a joiner run stays whole in Open.
#[test]
fn a_joiner_run_never_frees_a_secret() {
    for (text, value) in [
        ("my__password: G9rP2zT7x", "G9rP2zT7x"),
        ("invoice__pin: 4821-77", "4821-77"),
        ("x--pin: 719836", "719836"),
        (
            // Split so the repo secret scan does not read the fake key.
            concat!("api\\_key: sk-", "proj-abcdefghijklmnopqrstuvwx"),
            "abcdefghijklmnopqrstuvwx",
        ),
    ] {
        for mode in MODES {
            let (output, _) = issue(mode, text).expect("issued");
            assert!(!output.contains(value), "{mode:?} {text:?} -> {output:?}");
        }
    }
    let prose = "Run the build__fast target, then the re\u{2010}\u{2010}test step.";
    let (output, _) = issue(PrivacyMode::Open, prose).expect("issued");
    assert_eq!(output, prose);
}

/// Prohibited values that overlap or touch, in any order: no byte of any of
/// them is left in Open or Private output.
#[test]
fn touching_prohibited_values_leave_no_byte() {
    let iban = "FR7630006000011234567890189";
    let card = "4111111111111111";
    for text in [
        format!("{iban} {card} and {card} {iban}"),
        format!("IBAN {iban} card {card} IBAN {iban}"),
        format!("I have diabetes, IBAN {iban}, HIV and card {card}."),
    ] {
        for mode in MODES {
            let (output, _) = issue(mode, &text).expect("issued");
            for value in [iban, card, "diabetes", "HIV"] {
                assert!(!output.contains(value), "{mode:?} {text:?} -> {output:?}");
            }
        }
    }
}

/// Release only: a token and text dense with prohibited values, 128 KiB to
/// 1 MiB, in Private mode; each 2x step at most 2.5x.
#[test]
#[ignore = "release timing: cargo test --release --test ocr_kernel_3a -- --ignored --nocapture"]
fn dense_prohibited_values_scale_linearly() {
    let time = |bytes: usize| {
        let unit = "IBAN FR7630006000011234567890189, I have diabetes. ";
        // A token makes the gate keep session tokens (`mask_keeping`).
        let text = format!("⟦PERSON_ABCDEF123456⟧\n{}", unit.repeat(bytes / unit.len()));
        (0..3)
            .map(|_| {
                let start = Instant::now();
                assert!(issue(PrivacyMode::Private, &text).is_some());
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let times: Vec<Duration> = [128, 256, 512, 1024].map(|k| time(k * 1024)).to_vec();
    eprintln!("dense prohibited 128 KiB..1 MiB: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) <= 2.5,
            "{times:?}"
        );
    }
}
