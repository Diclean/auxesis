//! SECRET-RECALL-2: recovery codes in lists and tables, and a letters-only
//! Wi-Fi key after its cue, are hidden in both modes; a code run stops at a
//! sentence start. `data/secret_recall_2_main.txt` is frozen from main before
//! SECRET-RECALL-1, a56263ab (`-- --ignored freeze --nocapture`). All values
//! are invented.

use kernel_core::privacy::PrivacyMode;
use serde_json::Value;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};

const FIXTURE: &str = include_str!("data/secret_recall_2_main.txt");

/// The gate masks exactly the values in braces, and nothing else.
const CASES: &[&str] = &[
    "Recovery codes:\n- {7KQ2-9XZ1}\n- {M4P8-R6T3}\nThanks",
    "Backup codes:\n• {7KQ2 9XZ1}\n• {M4P8 R6T3}",
    "Backup codes:\n1. {7KQ2-9XZ1}\n2. {M4P8-R6T3}\n\nKeep them safe.",
    "Your recovery codes:\n1) {7KQ2-9XZ1}\n2) {M4P8-R6T3}",
    "**Recovery codes**\n* {5HJD82KM}\n* {QW3E7TY9}",
    "Codes de secours :\n- {7KQ2-9XZ1}\n- {M4P8-R6T3}",
    "| Recovery codes | {7KQ2-9XZ1} |",
    "Backup codes:\n| codes | {7KQ2-9XZ1} |\n| codes | {M4P8-R6T3} |",
    "Recovery codes\n| # | code |\n|---|---|\n| 1 | {7KQ2-9XZ1} |\n| 2 | {M4P8-R6T3} |",
    "| Service | Backup codes |\n|---|---|\n| Forge | {7KQ2-9XZ1} |\n| Vault | {M4P8-R6T3} |",
    "Recovery codes | {7KQ2-9XZ1}",
    "Backup codes:\nForge\t{7KQ2-9XZ1}",
    "Wi-Fi key: {blueotterriver}",
    "clé Wi-Fi : {soleilrouge}",
    "WPA password: {correcthorsebattery}",
    "Guest Wi-Fi / key: \"{lanternmoss}\" (case sensitive)",
    "mot de passe Wi-Fi :\n{ventdusud}",
    // A run stops at a sentence start with no period.
    "Recovery codes: {7KQ2-9XZ1 M4P8-R6T3} Thanks for the help",
    "Recovery codes: {7KQ2-9XZ1} Then contact support.",
    "Backup codes:\n- {7KQ2-9XZ1} Merci pour tout",
    "Recovery codes: {Alpha7 Bravo} thanks for your help",
    "Recovery codes: {7KQ2 Wxyz k9m2 p4q8}",
    "Backup codes:\n- {7KQ2 Wxyz k9m2 p4q8}",
    "Recovery codes:\n- [x] {7KQ2-9XZ1}\n- [ ] {M4P8-R6T3}",
    "Recovery codes:\n\n{7KQ2-9XZ1}",
    // The gate joins the two cells across their comma.
    "Recovery codes,{7KQ2-9XZ1,M4P8-R6T3}",
    "Wi-Fi key is {blueotterriver}",
    "Wi-Fi key: {blueotterriver} guest network",
    "Wi-Fi key: {Summer2024} Please",
    // Lookalikes: nothing is hidden.
    "Recovery codes are in the safe",
    "Recovery codes are in the safe\n- buy milk\n- call Anna",
    "Wi-Fi key holders: Anna",
    "Wi-Fi key holders: Christopher and Ben",
    "- buy milk",
    "1. Agenda",
    "Backup codes:\n- buy milk\n1. Agenda\n| Owner | Anna |",
    "Recovery codes\n| # | status |\n|---|---|\n| 1 | used |",
    "Wi-Fi: the key point is coverage on floor 3.",
    "Wi-Fi key: available at reception",
    "Wi-Fi key: see Anna",
    "WPA password reset needed",
    "Wi-Fi key: required",
    "Wi-Fi key: ask Anna",
    "Wi-Fi key is changing tomorrow",
];

/// A positive without its braces, and the ranges of its values.
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

/// Every case in both modes: no refusal, the masked bytes are the value bytes,
/// and Private restores the text exactly.
#[test]
fn listed_codes_and_letter_wifi_keys_are_hidden_exactly_in_both_modes() {
    let mut wrong = Vec::new();
    for marked in CASES {
        let (text, wanted) = unmark(marked);
        for mode in MODES {
            let Some(now) = masked(mode, &text) else {
                wrong.push(format!("{mode:?} {text:?}: refused"));
                continue;
            };
            let within = |inner: &[(usize, usize)], outer: &[(usize, usize)]| {
                text.char_indices()
                    .filter(|(at, ch)| !ch.is_whitespace() && covered(inner, *at, at + 1))
                    .all(|(at, ch)| covered(outer, at, at + ch.len_utf8()))
            };
            if !within(&wanted, &now) || !within(&now, &wanted) {
                wrong.push(format!("{mode:?} {text:?}: {now:?}, want {wanted:?}"));
            }
        }
        let (mut out, minted) = issue(PrivacyMode::Private, &text).expect("issued");
        for (token, surface) in minted {
            out = out.replace(&format!("⟦{token}⟧"), &surface);
        }
        assert_eq!(out, text, "Private restores exactly");
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Long lists, long tables, glued cells and repeated cues stay linear.
#[test]
fn long_code_lists_and_tables_stay_linear() {
    for text in [
        format!("Recovery codes:\n{}", "- 7KQ2-9XZ1\n".repeat(40_000)),
        format!("Backup codes:\n{}", "| 1 | 7KQ2-9XZ1 |\n".repeat(40_000)),
        format!("Backup codes:\n| {}", "7KQ2|".repeat(100_000)),
        "| Recovery codes | 7KQ2 ".repeat(20_000),
        "Recovery codes:\n".repeat(30_000),
        "Wi-Fi key: ".repeat(30_000),
        "clé Wi-Fi : blueotterriver ".repeat(20_000),
    ] {
        let started = std::time::Instant::now();
        for mode in MODES {
            assert!(issue(mode, &text).is_some(), "refused");
        }
        assert!(
            started.elapsed() < linear_budget(),
            "{:?} is slow",
            &text[..24]
        );
    }
}

/// This pass's texts, then every in-repo eval case and prose line.
fn inputs() -> Vec<String> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    let mut out: Vec<String> = CASES.iter().map(|t| unmark(t).0).collect();
    let read = |path: &std::path::Path| std::fs::read_to_string(path).unwrap();
    let dir = std::fs::read_dir(format!("{root}/cases")).unwrap();
    let mut files: Vec<_> = dir.map(|entry| entry.unwrap().path()).collect();
    files.sort();
    for file in files {
        let text = read(&file);
        let cases = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok());
        out.extend(cases.map(|case| case["text"].as_str().unwrap().to_string()));
    }
    for lang in ["af", "hu", "sl"] {
        let prose = read(format!("{root}/prose/{lang}.txt").as_ref());
        let lines = prose.lines().filter(|l| !l.trim().is_empty());
        out.extend(lines.map(String::from));
    }
    out
}

/// The input count, then one record per input, 200 to a line: Private and Open
/// ranges joined by `|`, `!` for a refusal.
fn fixture_text(inputs: &[String]) -> String {
    let ranges = |r: Vec<(usize, usize)>| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    let record = |r: Option<_>| r.map_or("!".to_string(), ranges);
    let line = |text: &String| MODES.map(|mode| record(masked(mode, text))).join("|");
    let records: Vec<String> = inputs.iter().map(line).collect();
    let lines: Vec<String> = records.chunks(200).map(|c| c.join(";") + ";").collect();
    format!("{}\n{}", inputs.len(), lines.join("\n"))
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    println!("FIXTURE-BEGIN\n{}\nFIXTURE-END", fixture_text(&inputs()));
}

/// No byte main masked goes clear, in either mode; nothing new is refused, and
/// no in-repo eval or prose text gains a mask (over-mask).
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let (count, body) = FIXTURE.split_once('\n').unwrap_or((FIXTURE.trim(), ""));
    assert_eq!(count, inputs.len().to_string(), "inputs changed: refreeze");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len(), "fixture records");
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    let (mut wrong, mut grown) = (Vec::new(), 0);
    let own = CASES.len();
    for (index, (text, record)) in inputs.iter().zip(records).enumerate() {
        for (mode, main) in MODES.into_iter().zip(record.split('|')) {
            let main: Vec<(usize, usize)> = main.split(',').filter_map(range).collect();
            let Some(now) = masked(mode, text) else {
                wrong.push(format!("{mode:?} {text:?}: refused"));
                continue;
            };
            grown += usize::from(index >= own && now != main);
            if main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .any(|b| !covered(&now, b, b + 1))
            {
                wrong.push(format!("{mode:?} {text:?}: main {main:?} now {now:?}"));
            }
        }
    }
    eprintln!(
        "{} inputs, corpus texts with a new mask: {grown}",
        inputs.len()
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert_eq!(grown, 0, "over-mask on the in-repo corpus");
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
