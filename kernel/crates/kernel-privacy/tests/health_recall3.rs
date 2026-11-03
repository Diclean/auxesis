//! HEALTH-RECALL-3 baseline and acceptance cases. All values are invented.
//! The in-repo measurement reads only the named case corpora below; it never
//! opens the held-out files or invokes the privacy-eval binary.

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, exact_ranges, issue, masked, MODES};
use serde_json::Value;
use std::time::{Duration, Instant};

fn byte_offset(text: &str, characters: usize) -> usize {
    text.char_indices()
        .nth(characters)
        .map_or(text.len(), |(byte, _)| byte)
}

const IN_REPO: &[(&str, &str)] = &[
    (
        "af.jsonl",
        include_str!("../../../qa/privacy-eval/cases/af.jsonl"),
    ),
    (
        "ar.jsonl",
        include_str!("../../../qa/privacy-eval/cases/ar.jsonl"),
    ),
    (
        "en.jsonl",
        include_str!("../../../qa/privacy-eval/cases/en.jsonl"),
    ),
    (
        "fr.jsonl",
        include_str!("../../../qa/privacy-eval/cases/fr.jsonl"),
    ),
    (
        "hu.jsonl",
        include_str!("../../../qa/privacy-eval/cases/hu.jsonl"),
    ),
    (
        "ru.jsonl",
        include_str!("../../../qa/privacy-eval/cases/ru.jsonl"),
    ),
    (
        "zh.jsonl",
        include_str!("../../../qa/privacy-eval/cases/zh.jsonl"),
    ),
    (
        "emails-af.jsonl",
        include_str!("../../../qa/privacy-eval/cases/emails-af.jsonl"),
    ),
    (
        "emails-ar.jsonl",
        include_str!("../../../qa/privacy-eval/cases/emails-ar.jsonl"),
    ),
    (
        "emails-en.jsonl",
        include_str!("../../../qa/privacy-eval/cases/emails-en.jsonl"),
    ),
    (
        "emails-fr.jsonl",
        include_str!("../../../qa/privacy-eval/cases/emails-fr.jsonl"),
    ),
    (
        "emails-hu.jsonl",
        include_str!("../../../qa/privacy-eval/cases/emails-hu.jsonl"),
    ),
    (
        "emails-ru.jsonl",
        include_str!("../../../qa/privacy-eval/cases/emails-ru.jsonl"),
    ),
    (
        "emails-zh.jsonl",
        include_str!("../../../qa/privacy-eval/cases/emails-zh.jsonl"),
    ),
    (
        "k10-sensitive.jsonl",
        include_str!("../../../qa/privacy-eval/cases/k10-sensitive.jsonl"),
    ),
];

#[test]
fn in_repo_health_cases_keep_only_out_of_scope_misses() {
    let mut total = 0usize;
    let mut hits = 0usize;
    let mut misses = Vec::new();
    for (file, corpus) in IN_REPO {
        for line in corpus.lines().filter(|line| !line.trim().is_empty()) {
            let case: Value = serde_json::from_str(line).expect("valid in-repo case");
            let text = case["text"].as_str().expect("case text");
            let id = case["id"].as_str().unwrap_or("unknown");
            for span in case["spans"].as_array().into_iter().flatten() {
                if span["type"]
                    .as_str()
                    .is_none_or(|kind| !kind.eq_ignore_ascii_case("health"))
                {
                    continue;
                }
                total += 1;
                let start = byte_offset(text, span["start"].as_u64().expect("span start") as usize);
                let end = byte_offset(text, span["end"].as_u64().expect("span end") as usize);
                let hidden = MODES.iter().all(|&mode| {
                    masked(mode, text).is_some_and(|ranges| covered(&ranges, start, end))
                });
                if hidden {
                    hits += 1;
                } else {
                    misses.push(format!("{file}:{id}: {:?}", &text[start..end]));
                }
            }
        }
    }
    eprintln!(
        "in-repo health after change {hits}/{total}; misses:\n{}",
        misses.join("\n")
    );
    assert_eq!(total, 64);
    assert_eq!(hits, 54);
}

const POSITIVES: &str = include_str!("data/health_recall3_positive.txt");
const NEGATIVES: &str = include_str!("data/health_recall3_negative.txt");

fn canonical_output(mode: kernel_core::privacy::PrivacyMode, text: &str) -> String {
    let (mut output, minted) = issue(mode, text).expect("health statement is allowed");
    for (token, _) in minted {
        output = output.replace(&format!("⟦{token}⟧"), "[health removed]");
    }
    output
}

#[test]
fn synthetic_120_health_values_are_exactly_masked_in_both_modes() {
    let cases: Vec<_> = POSITIVES
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(cases.len(), 120);
    for line in cases {
        let (before, rest) = line.split_once('[').expect("bracketed value");
        let (value, after) = rest.split_once(']').expect("closing bracket");
        let input = format!("{before}{value}{after}");
        let expected = format!("{before}[health removed]{after}");
        for mode in MODES {
            let (output, minted) = issue(mode, &input).expect("allowed");
            let ranges =
                exact_ranges(mode, &input, &output, &minted).expect("output has one exact reading");
            let start = before.len();
            assert!(
                covered(&ranges, start, start + value.len()),
                "{mode:?}: {line}"
            );
            let actual = canonical_output(mode, &input);
            assert_eq!(actual, expected, "{mode:?}: {line}");
        }
    }
}

#[test]
fn synthetic_60_hard_negatives_keep_exact_output_in_both_modes() {
    let cases: Vec<_> = NEGATIVES
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert!(cases.len() >= 60, "got {} negatives", cases.len());
    for line in cases {
        for mode in MODES {
            assert_eq!(canonical_output(mode, line), *line, "{mode:?}: {line}");
        }
    }
}

#[test]
fn report_existing_no_pii_prose_overmask_by_mode() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval/prose");
    let mut lines: Vec<String> = Vec::new();
    for lang in ["af", "hu", "sl"] {
        let path = format!("{root}/{lang}.txt");
        lines.extend(
            std::fs::read_to_string(path)
                .expect("in-repo prose corpus")
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned),
        );
    }
    lines.extend(
        norm1::ZH_PROSE
            .iter()
            .chain(norm1::CYRILLIC_PROSE)
            .map(|line| (*line).into()),
    );
    for mode in MODES {
        let masked_count = lines
            .iter()
            .filter(|line| {
                issue(mode, line).is_some_and(|(output, minted)| match mode {
                    kernel_core::privacy::PrivacyMode::Private => {
                        minted.iter().any(|(token, _)| token.starts_with("HEALTH_"))
                    }
                    kernel_core::privacy::PrivacyMode::Open => output.contains("[health removed]"),
                })
            })
            .count();
        eprintln!(
            "no-PII prose {mode:?}: {masked_count}/{} lines",
            lines.len()
        );
    }
}

#[test]
#[ignore = "release timing probe; run foreground with --release --ignored"]
fn medication_dose_extension_scales_linearly() {
    for mode in MODES {
        let mut previous: Option<Duration> = None;
        for size in [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024] {
            let sentence = "Refill metformin 500 mg tomorrow. ";
            let input = sentence.repeat(size / sentence.len() + 1);
            let start = Instant::now();
            let (output, _) = issue(mode, &input).expect("large allowed health text");
            let elapsed = start.elapsed();
            if let Some(prior) = previous {
                let ratio = elapsed.as_secs_f64() / prior.as_secs_f64();
                eprintln!(
                    "dose workload {mode:?} {} bytes: {elapsed:?}; step={ratio:.2}x",
                    input.len()
                );
                assert!(ratio <= 6.0, "{mode:?} 4x step took {ratio:.2}x");
            } else {
                eprintln!("dose workload {mode:?} {} bytes: {elapsed:?}", input.len());
            }
            assert!(output.contains("health removed") || output.contains("⟦HEALTH_"));
            previous = Some(elapsed);
        }
    }
}
