//! SECRET-LEAK-294B: two Open-mode repros from the late review of #294, through
//! the gate. A password `secret` on a letter row under `username,password,note`
//! is hidden; a password after 10,000 divider rows is hidden. Look-alike
//! columns and prose stay clear. Every value is invented.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

/// Each mode that leaves `text[start..end]` clear, or refuses `text`.
fn clear_in(text: &str, start: usize, end: usize) -> Vec<String> {
    MODES
        .into_iter()
        .filter(|&mode| masked(mode, text).is_none_or(|r| !covered(&r, start, end)))
        .map(|mode| format!("{mode:?}"))
        .collect()
}

#[test]
fn secret_named_password_on_a_letter_row_is_hidden() {
    let text = "username,password,note\nalice,secret,token";
    let at = text.find(",secret,").expect("value") + 1;
    assert_eq!(
        clear_in(text, at, at + "secret".len()),
        Vec::<String>::new()
    );
}

#[test]
fn password_after_ten_thousand_divider_rows_is_hidden() {
    let mut wrong = Vec::new();
    for (filler, unit) in [9_999, 10_000, 10_001, 20_000]
        .into_iter()
        .flat_map(|n| [(n, "---,---,---\n"), (n, "8,,Oslo\n")])
    {
        let text = format!(
            "id,password,city\n{}7,Tr0ub4dor&3x,Paris",
            unit.repeat(filler)
        );
        let at = text.rfind("Tr0ub4dor&3x").expect("value");
        for mode in clear_in(&text, at, at + "Tr0ub4dor&3x".len()) {
            wrong.push(format!("{filler} rows of {unit:?}: clear in {mode}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Columns that only look like a secret column, and prose, mask in Open only
/// what main masks (main's older key rule reads `hint,city` and
/// `reset_count,city` as values).
#[test]
fn lookalike_columns_and_prose_match_main_in_open() {
    let mut wrong = Vec::new();
    for (text, main) in [
        (
            "id,password_hint,city\n1,42,Paris\n2,17,Oslo",
            &[(12, 21)][..],
        ),
        (
            "id,passwords_reset_count,city\n1,3,Paris\n2,0,Oslo",
            &[(13, 29)],
        ),
        ("username,city,note\nalice,Paris,ok\nbob,Oslo,ready", &[]),
        (
            "We changed the password policy last week; reset counts are in the sheet.",
            &[],
        ),
    ] {
        let ranges = masked(PrivacyMode::Open, text).expect("Open allows");
        if ranges != main {
            wrong.push(format!("{text:?}: main {main:?} now {ranges:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// 1 MiB of filler rows under a secret header costs about ten times 100 KiB.
#[test]
fn filler_rows_scan_in_linear_time() {
    for unit in ["---,---,---\n", "8,Cherry6!,Oslo\n"] {
        linear(unit);
    }
}

fn linear(unit: &str) {
    use std::time::{Duration, Instant};
    let text = |bytes: usize| {
        format!(
            "id,password,city\n{}7,Tr0ub4dor&3x,Paris",
            unit.repeat(bytes / unit.len())
        )
    };
    let best = |t: &str| {
        (0..3)
            .map(|_| {
                let start = Instant::now();
                let _ = masked(PrivacyMode::Open, t);
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let (small, large) = (best(&text(104_858)), best(&text(1_048_576)));
    assert!(
        large <= small * 20 + Duration::from_millis(50),
        "{unit:?}: 100 KiB {small:?}, 1 MiB {large:?}"
    );
}
