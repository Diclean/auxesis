//! SECRET-RECALL-3: same-length lowercase recovery-code groups remain hidden
//! in both privacy modes, with prose and long-input boundaries preserved.

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

/// A positive with braces around exactly the values the gate should mask.
fn unmark(marked: &str) -> (String, Vec<(usize, usize)>) {
    let (mut text, mut ranges, mut start) = (String::new(), Vec::new(), 0);
    for ch in marked.chars() {
        match ch {
            '{' => start = text.len(),
            '}' => ranges.push((start, text.len())),
            _ => text.push(ch),
        }
    }
    (text, ranges)
}

fn assert_exact_in_both_modes(marked: &str) {
    let (text, wanted) = unmark(marked);
    for mode in MODES {
        let got = masked(mode, &text).unwrap_or_else(|| panic!("refused in {mode:?}"));
        for (at, ch) in text.char_indices() {
            if ch.is_whitespace() {
                continue;
            }
            let end = at + ch.len_utf8();
            assert_eq!(
                covered(&got, at, end),
                covered(&wanted, at, end),
                "wrong mask in {mode:?} for {text:?} at {at}; got {got:?}, wanted {wanted:?}"
            );
        }
    }
}

/// Check that marked values are hidden while allowing the surrounding cue to
/// join a secret span when the gate coalesces adjacent recovery-code regions.
fn assert_values_masked_in_both_modes(marked: &str) {
    let (text, wanted) = unmark(marked);
    for mode in MODES {
        let got = masked(mode, &text).unwrap_or_else(|| panic!("refused in {mode:?}"));
        for (start, end) in &wanted {
            assert!(
                (*start..*end).all(|byte| covered(&got, byte, byte + 1)),
                "expected value {start}..{end} hidden in {mode:?} for {text:?}; got {got:?}"
            );
        }
    }
}

#[test]
fn mixed_case_recovery_code_groups_are_fully_masked() {
    assert_exact_in_both_modes("Recovery codes: {7KQ2} {wxyz} {k9m2} {p4q8}");
    assert_exact_in_both_modes("Recovery codes: {7KQ2} {WXYZ} {k9m2} {p4q8}");
}

#[test]
fn lowercase_recovery_code_groups_of_four_and_five_are_masked() {
    // These group sizes occur in lowercase defaults such as java-totp's
    // four-character groups and renox_2fa's five-character groups.
    assert_exact_in_both_modes("Recovery codes: {7kq2} {wxyz} {9bdf} {pqrs}");
    assert_exact_in_both_modes("Backup codes: {k7mqp} {abcde} {x2ndr} {fghij}");
}

#[test]
fn three_same_length_letters_only_groups_after_a_cue_are_masked() {
    assert_exact_in_both_modes("Recovery codes: {abcd} {efgh} {ijkl} {mnop}");
    assert_exact_in_both_modes("Recovery codes: abcd efgh");
    assert_exact_in_both_modes("Recovery codes: abcd efgh garden");
    assert_exact_in_both_modes("Recovery codes: keep them safe");
}

#[test]
fn lowercase_groups_keep_their_context_across_lists_and_comma_cells() {
    assert_exact_in_both_modes("Recovery codes:\n- {7KQ2}\n- {wxyz}\n- {k9m2}\n- {p4q8}");
    assert_values_masked_in_both_modes("Recovery codes: {7KQ2}, {wxyz}, {k9m2}, {p4q8}");
    assert_exact_in_both_modes("Recovery codes:\n1. {abcd}\n2. {efgh}\n3. {ijkl}\n4. {mnop}");
}

#[test]
fn ordinary_prose_after_a_recovery_cue_stays_clear() {
    assert_exact_in_both_modes("Recovery codes: keep them safe");
    assert_exact_in_both_modes("Recovery codes: {7KQ2} {wxyz}. Then keep them safe.");
    assert_exact_in_both_modes("Recovery codes: {7KQ2} {wxyz} merci");
}

#[test]
fn long_lowercase_recovery_run_does_not_panic_or_exceed_time_bound() {
    let text = format!("Recovery codes: 7kq2 {}", "wxyz ".repeat(20_000));
    let started = std::time::Instant::now();
    for mode in MODES {
        let got = masked(mode, &text).unwrap_or_else(|| panic!("refused in {mode:?}"));
        for (index, (at, _)) in text.match_indices("wxyz").enumerate() {
            for byte in at..at + 4 {
                assert_eq!(
                    covered(&got, byte, byte + 1),
                    index < 15,
                    "recovery group cap changed in {mode:?} at {at}"
                );
            }
        }
    }
    assert!(
        started.elapsed() < linear_budget(),
        "long recovery run was slow"
    );
}

/// The linear-time bar: 10 s in release; the debug profile is slower, so it
/// gets 30 s. What is checked does not change (see secret_recall_1.rs).
fn linear_budget() -> std::time::Duration {
    if cfg!(debug_assertions) {
        std::time::Duration::from_secs(30)
    } else {
        std::time::Duration::from_secs(10)
    }
}
