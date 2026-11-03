//! K-SECRET-TAIL-4: a secret's value is masked to its paragraph end,
//! or in an unambiguous config paragraph to its logical line end, through `Gate` in
//! Open and Private mode.

use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::recognizers::secrets::SecretRecognizer;
use kernel_privacy::{Gate, GateError, Recognizer};
use proptest::prelude::*;

include!("data/secret_tail4_cases.rs");

fn gate(mode: PrivacyMode, text: &str) -> Result<String, GateError> {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
        panic!("A1 {mode:?}")
    };
    let (safe, _) = Gate::for_grant(&grant, [7u8; 32]).text(text)?;
    Ok(safe.as_str().to_string())
}

#[test]
fn unicode_line_separators_do_not_leave_secret_or_identifier_tails_clear() {
    for separator in ["\u{2028}", "\u{2029}", "\u{85}"] {
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let input = format!(
                "\u{73}k-proj-FAKEKEY0123456789{separator}abcdefGHIJKL\nIBAN: HU42 1177 3016 1111{separator}1018 0000 0000\nCard: 4242 4242 4242{separator}4242"
            );
            let out = gate(mode, &input).unwrap();
            for tail in ["abcdefGHIJKL", "1018 0000 0000", "4242 4242 4242"] {
                assert!(!out.contains(tail), "{mode:?}: {out:?}");
            }
        }
    }
}

/// The gate output with its tokens and removal marks taken out.
fn clear_of(out: &str) -> String {
    let out = out.replace("[secret removed]", " ");
    out.split('⟦')
        .map(|part| part.split_once('⟧').map_or(part, |(_, rest)| rest))
        .collect()
}

/// Whether every non-whitespace byte of `text[range]` is under a secret span.
fn masked(text: &str, range: std::ops::Range<usize>) -> bool {
    let spans = SecretRecognizer::new().analyze(text);
    text[range.clone()].char_indices().all(|(at, ch)| {
        let at = range.start + at;
        ch.is_whitespace() || spans.iter().any(|span| span.start <= at && at < span.end)
    })
}

/// Hide and clear through Open and Private; R1: Private with `Ref: ` and `\n` is Ok.
fn check(id: &str, text: &str, hide: &[&str], clear: &[&str]) -> Vec<String> {
    let mut wrong = Vec::new();
    for value in hide {
        let at = text
            .rfind(value)
            .unwrap_or_else(|| panic!("{id}: {value:?} not in input"));
        if !masked(text, at..at + value.len()) {
            wrong.push(format!("{id}: {value:?} not masked"));
        }
    }
    for (mode, input) in [
        (PrivacyMode::Open, text.to_owned()),
        (PrivacyMode::Private, text.to_owned()),
    ] {
        match gate(mode, &input) {
            Ok(out) => {
                let left = clear_of(&out);
                wrong.extend(
                    hide.iter()
                        .filter(|value| value.len() > 2 && left.contains(*value))
                        .map(|value| format!("{id} {mode:?}: {value:?} in {out:?}")),
                );
                wrong.extend(
                    clear
                        .iter()
                        .filter(|value| !out.contains(*value))
                        .map(|value| format!("{id} {mode:?}: {value:?} not clear in {out:?}")),
                );
            }
            Err(error) => wrong.push(format!("{id} {mode:?}: refused {error:?}")),
        }
    }
    if let Err(error) = gate(PrivacyMode::Private, &format!("Ref: {text}\n")) {
        wrong.push(format!("{id} R1: refused {error:?}"));
    }
    wrong
}

#[test]
fn prose_password_masks_a_quoted_fragment_past_a_newline() {
    let text = "Ref: password is a0A0 \" 0\nAaa:";
    let wrong = check("quoted fragment", text, &["a0A0", "Aaa:"], &[]);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn prose_password_in_a_reference_masks_a_wrapped_entry_shaped_tail() {
    let text = "Ref: password is a0A0 \\\" 0\nAaa:";
    assert!(masked(text, 17..31), "the entire passphrase must be masked");
    let wrong = check("wrapped reference", text, &["a0A0", "Aaa:"], &[]);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn reference_password_masks_a_sentence_shaped_passphrase_continuation() {
    let text = "Ref: password is a0A0 0\nAaa: correct horse battery staple.";
    let wrong = check(
        "sentence-shaped passphrase",
        text,
        &["a0A0", "Aaa: correct horse battery staple."],
        &[],
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let clear = clear_of(&gate(mode, text).unwrap());
        for word in ["correct", "horse", "battery", "staple"] {
            assert!(!clear.contains(word), "{mode:?}: {word:?} in {clear:?}");
        }
    }
}

#[test]
fn reference_secret_token_and_pin_mask_wrapped_values_in_both_modes() {
    let mut wrong = Vec::new();
    for (cue, link) in [
        ("secret", "is"),
        ("token", "is"),
        ("PIN", "is"),
        ("secret", "est"),
        ("jeton", "est"),
        ("code PIN", "est"),
    ] {
        let text = format!("Ref: {cue} {link} a0A0 \\\" 0\nAaa:");
        wrong.extend(check(cue, &text, &["a0A0", "Aaa:"], &[]));
        let start = text.find("a0A0").unwrap();
        assert!(masked(&text, start..text.len()), "{cue}: incomplete span");
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let clear = clear_of(&gate(mode, &text).unwrap());
            assert!(
                !clear.contains('0') && !clear.contains("\\\"") && !clear.contains("Aaa"),
                "{cue} {mode:?}: {clear:?}"
            );
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn reference_password_deliberately_masks_ambiguous_following_notes() {
    // A sentence can be a passphrase continuation, so masking a note is deliberate.
    let text = "Ref: password is a0A0 \\\" 0\nNext: Please rotate it before launch.";
    let wrong = check(
        "sentence",
        text,
        &["a0A0 \\\" 0", "Please rotate it before launch."],
        &[],
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    let text = "Ref: password is a0A0 0\nAaa:\nNext: Please rotate it before launch.\nLater: leave this note alone!";
    let wrong = check(
        "sentence after tail",
        text,
        &[
            "a0A0",
            "Aaa:",
            "Please rotate it before launch.",
            "leave this note alone!",
        ],
        &[],
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    let text = "Ref: password is a0A0 0\nNext: rotate 47 before launch.\n\nClear afterward";
    let wrong = check(
        "ambiguous token",
        text,
        &["a0A0", "rotate 47 before launch."],
        &["Clear afterward"],
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    let text = "password is a0A0 0\nPlease rotate it before launch.";
    let wrong = check(
        "old prose rule",
        text,
        &["a0A0", "Please rotate it before launch."],
        &[],
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_reference_password_conservatively_masks_following_config_like_lines() {
    let text = "Ref: password is a0A0 0\nNext: ordinary text\n\nClear afterward";
    let wrong = check(
        "ambiguous reference",
        text,
        &["a0A0", "ordinary text"],
        &["Clear afterward"],
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    let config = "password: a0A0\nNext: ordinary text";
    let wrong = check("direct config", config, &["a0A0"], &["Next: ordinary text"]);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn every_pr1a_case_masks_its_value_and_passes_both_gates() {
    let mut wrong: Vec<String> = CASES
        .iter()
        .flat_map(|&(id, text, hide, clear)| check(id, text, hide, clear))
        .collect();
    for (id, text, hide, clear) in built_cases() {
        let hide: Vec<&str> = hide.iter().map(String::as_str).collect();
        let clear: Vec<&str> = clear.iter().map(String::as_str).collect();
        wrong.extend(check(&id, &text, &hide, &clear));
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn every_pr1b_case_masks_its_value_and_passes_both_gates() {
    let wrong: Vec<String> = PR1B_CASES
        .iter()
        .flat_map(|&(id, text, hide, clear)| check(id, text, hide, clear))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn every_pr2_case_masks_its_cell_and_passes_both_gates() {
    let same = PR2_SAME.iter().map(|&text| (text, text, &[][..], &[][..]));
    let wrong: Vec<String> = PR2_CASES
        .iter()
        .copied()
        .chain(same)
        .flat_map(|(id, text, hide, clear)| check(id, text, hide, clear))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// P2-2: the owned lines under a key cell that opens a region are masked too, so the
/// residue view never reads them as rows; both gates pass.
#[test]
fn an_owned_region_opened_in_a_key_cell_is_masked_and_passes_both_gates() {
    let wrong: Vec<String> = owned_cells()
        .iter()
        .flat_map(|(text, hide)| check(text, text, hide, &[]))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// K-REFUSALS: masking turns a neighbour of a clear quote into a stand-in and a line
/// break, so the residue view can own more than the text did. The gate masks a secret
/// it reads there instead of refusing: both gates pass, every secret byte masked.
#[test]
fn a_secret_the_residue_view_reads_is_masked_not_refused() {
    let script = include_str!("../../../qa/privacy-eval/scripts/fetch-external.py");
    let mut wrong: Vec<String> = refusal_cases()
        .iter()
        .flat_map(|(id, text, hide, clear)| check(id, text, hide, clear))
        .collect();
    wrong.extend(check(
        "KR4 fetch-external.py",
        script,
        &[],
        &["def main():"],
    ));
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// R3 (F1): an e-mail in a table header cell, a key column after it. Ok or a
/// `Residue` refusal, never a clear secret; the result is recorded.
#[test]
fn r3_an_email_in_a_table_header_is_recorded() {
    let mut seen = Vec::new();
    for head in [
        "a.user@example.invalid",
        "a.user@example.invalid x",
        "x a.user@example.invalid",
    ] {
        let text = format!("| {head} | password |\n|---|---|\n| bank | hunter2 horse |");
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let result = gate(mode, &text);
            if let Ok(out) = &result {
                assert!(!clear_of(out).contains("hunter2"), "{mode:?}: {out:?}");
            }
            seen.push(result.map(|_| "Ok").map_err(|error| format!("{error:?}")));
        }
    }
    assert_eq!(seen, vec![Ok("Ok"); 6], "the recorded results changed");
}

/// Q15 and the F2 fixtures: the result is recorded so a later change shows up; never a
/// clear secret. Q15 stays refused in Private because `value_too_long` must not change
/// (D-2 bar). F2a and F2b were the known false refusal: the gate now masks the
/// residue value instead (K-REFUSALS). F2c is the #164 variant, which the quote
/// ownership admits.
#[test]
fn recorded_results_never_leave_a_secret_clear() {
    let block = "Fk3jQ9xZ2m".repeat(900);
    let q15 = format!("token: |\n  {block}\n");
    // The PEM armour is built at run time so the repo's secret scan never sees it.
    let pem = |edge: &str| format!("-----{edge} PRIVATE KEY-----");
    let f2b = format!(
        "My password is {}\nMIIBVQ\n\nMIIBVR\n{} Bye",
        pem("BEGIN"),
        pem("END")
    );
    let f2a = format!(
        "“{}\nMIIBVQ”\n{}\n\nMy password is hunter2\n\nBye",
        pem("BEGIN"),
        pem("END")
    );
    let f2c = "| field | DB_PASSWORD := \"red horse\n\nbattery staple\" | tail |\n|---|---|---|";
    let mut seen = Vec::new();
    for (text, secret) in [
        (q15.as_str(), "Fk3jQ9xZ2m"),
        (f2a.as_str(), "hunter2"),
        (f2b.as_str(), "MIIBV"),
        (f2c, "battery"),
    ] {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let result = gate(mode, text);
            if let Ok(out) = &result {
                assert!(
                    !clear_of(out).contains(secret),
                    "{mode:?}: {secret} clear in {out:?}"
                );
            }
            seen.push(result.map(|_| "Ok").map_err(|error| format!("{error:?}")));
        }
    }
    let refused = Err("Detect(TooLong)".to_owned());
    assert_eq!(
        seen,
        [
            Ok("Ok"),
            refused,
            Ok("Ok"),
            Ok("Ok"),
            Ok("Ok"),
            Ok("Ok"),
            Ok("Ok"),
            Ok("Ok")
        ],
        "the recorded results changed"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::default())]

    /// P2: every byte of a planted passphrase is masked.
    #[test]
    fn p2_a_planted_passphrase_is_masked((text, range, _) in planted()) {
        prop_assert!(masked(&text, range.clone()), "{text:?} {range:?}");
    }

    /// P3: the gate passes the P2 texts in both modes with no passphrase word clear.
    #[test]
    fn p3_the_gate_passes_a_planted_passphrase((text, _, words) in planted()) {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let out = gate(mode, &text).map_err(|error| TestCaseError::fail(format!("{mode:?} {error:?}: {text:?}")))?;
            let left = clear_of(&out);
            for word in words.iter().filter(|word| word.len() >= 4 && text.matches(word.as_str()).count() == 1) {
                prop_assert!(!left.contains(word.as_str()), "{mode:?}: {word:?} in {out:?}");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::default())]

    /// P8 (and P3 on its generator): every owned passphrase byte, every opener whose
    /// closer is masked when text follows, and an unclosed tail are masked; both gates
    /// pass with no passphrase word clear.
    #[test]
    fn p8_an_owned_passphrase_is_masked_and_passes_both_gates((text, hide, words) in owned()) {
        for range in &hide {
            prop_assert!(masked(&text, range.clone()), "{text:?} {range:?} {:?}", &text[range.clone()]);
        }
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let out = gate(mode, &text).map_err(|error| TestCaseError::fail(format!("{mode:?} {error:?}: {text:?}")))?;
            let left = clear_of(&out);
            for word in words.iter().filter(|word| text.matches(word.as_str()).count() == 1) {
                prop_assert!(!left.contains(word.as_str()), "{mode:?}: {word:?} in {out:?}");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::default())]

    /// P4: each data cell of ≥ 4 chars under a key header of a valid table outside a
    /// fence is masked, and both gates pass.
    #[test]
    fn p4_a_key_column_cell_is_masked_and_passes_both_gates((text, hide) in tables()) {
        for range in &hide {
            prop_assert!(masked(&text, range.clone()), "{text:?} {:?}", &text[range.clone()]);
        }
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let out = gate(mode, &text).map_err(|error| TestCaseError::fail(format!("{mode:?} {error:?}: {text:?}")))?;
            let left = clear_of(&out);
            for range in &hide {
                prop_assert!(!left.contains(&text[range.clone()]), "{mode:?}: {:?} in {out:?}", &text[range.clone()]);
            }
        }
    }
}

/// PR2 bar: a 1 MB table (10,000 key columns, short rows): `analyze` under 1 s and
/// the gate under 5 s, in both modes.
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn a_megabyte_of_wide_tables_passes_the_release_gate_within_five_seconds() {
    let text = "|".to_owned()
        + &"password|".repeat(10_000)
        + "\n|"
        + &"---|".repeat(10_000)
        + "\n"
        + &"| hunter2 |\n".repeat(75_000);
    let start = Instant::now();
    let spans = SecretRecognizer::new().analyze(&text);
    let analyzed = start.elapsed();
    assert!(spans.len() >= 75_000, "{}", spans.len());
    assert!(analyzed < Duration::from_secs(1), "analyze: {analyzed:?}");
    for mode in [PrivacyMode::Open, PrivacyMode::Private] {
        let start = Instant::now();
        let out = gate(mode, &text).unwrap_or_else(|error| panic!("{mode:?}: {error:?}"));
        assert!(!clear_of(&out).contains("hunter2"), "{mode:?}");
        let elapsed = start.elapsed();
        eprintln!("PR2 bar {mode:?}: analyze {analyzed:?}, gate {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{mode:?}: {elapsed:?}");
    }
}

/// S2 and T4 through the release gate, in both modes, under 2 s.
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn s2_and_t4_pass_the_release_gate_within_two_seconds() {
    let n = 20_000;
    let s2 = " ".repeat(12_000) + &"password is \"x\" ".repeat(12_000);
    let t4 = "|".to_owned()
        + &"password|".repeat(n / 3)
        + "\n|"
        + &"---|".repeat(n / 3)
        + "\n"
        + &"x\n".repeat(n * 3);
    for text in [s2, t4] {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let start = Instant::now();
            let _ = gate(mode, &text);
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "{mode:?}: {:?}",
                start.elapsed()
            );
        }
    }
}

/// Many residue hits on one line before a long blank tail must
/// not trim that tail once per hit. Four times the text takes about four times as long
/// in Private (it took 8.5x when each hit re-trimmed the tail).
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn residue_hits_on_one_line_scale_linearly_in_private() {
    let text = |n: usize| {
        "| site | password |\n|---|---|\n| \"foo | red horse | ".to_owned()
            + &"a@fixture.invalid | ".repeat(n)
            + &" ".repeat(100 * n)
    };
    let time = |n: usize| {
        let text = text(n);
        let start = Instant::now();
        let _ = gate(PrivacyMode::Private, &text);
        start.elapsed()
    };
    let (small, large) = (time(4_000), time(16_000));
    eprintln!("residue scaling: n=4000 {small:?}, n=16000 {large:?}");
    assert!(large < small * 6, "{small:?} -> {large:?}");
    assert!(large < Duration::from_secs(5), "{large:?}");
}
