//! LABEL-VALUE-1a: the frozen-main differential for the label-value rule.
//! A sensitive label followed by its value may only add masks: nothing main
//! hides is lost, no text is newly refused, no text without a value changes.
//!
//! `data/label_value_main.txt` was frozen from `origin/main` by
//! `freeze_main_fixture`: for every privacy-eval case, prose line, secret_tail4
//! case, repro and trap, the bytes main's Private gate tokenises and main's Open
//! gate removes, or `R` for a refusal. This branch must cover each of those
//! bytes, refuse no new text, and mask nothing new in a text with no value.
//!
//! Refreeze on main only: `LV_FREEZE=<path> cargo test --test label_value_differential -- --ignored freeze`.
//! The 4,000 public texts are not in the repo: `public_corpus_differential`
//! freezes main to `LV_PUBLIC_MAIN` when `LV_PUBLIC_FREEZE=1`, and compares otherwise.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, NameDictionary, Registry};

#[allow(dead_code)]
mod tail4 {
    include!("data/secret_tail4_cases.rs");

    /// Every secret_tail4 input, built cases included.
    pub fn inputs() -> Vec<String> {
        let fixed = CASES.iter().chain(PR1B_CASES).chain(PR2_CASES);
        let mut out: Vec<String> = fixed.map(|case| case.1.to_string()).collect();
        out.extend(PR2_SAME.iter().map(|text| text.to_string()));
        out.extend(built_cases().into_iter().map(|case| case.1));
        out.extend(owned_cells().into_iter().map(|case| case.0));
        out
    }
}

include!("data/label_value_cases.rs");
include!("data/exact_mask.rs");

/// The texts with no value whose output must not gain a mask.
const NO_VALUE: &str = "no-value";

/// Private first, then Open, in every record this file writes or reads.
const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];

fn gate(mode: PrivacyMode) -> Gate {
    let ctx = Context {
        destination: Destination::Vendor("label-value".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be admitted");
    };
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).expect("dictionary"));
    Gate::for_grant_with_dictionary(&grant, [7; 32], names)
}

/// `(source, line, text, tag)` for every in-repo text, in a fixed order.
fn texts() -> Vec<(String, usize, String, &'static str)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../qa/privacy-eval");
    let mut out = Vec::new();
    for dir in ["cases", "prose"] {
        let mut paths: Vec<PathBuf> = fs::read_dir(root.join(dir))
            .expect("privacy-eval is readable")
            .map(|entry| entry.expect("entry").path())
            .collect();
        paths.sort();
        for path in paths {
            let name = format!("{dir}/{}", path.file_name().unwrap().to_string_lossy());
            let raw = fs::read_to_string(&path).expect("readable");
            for (line, raw) in raw.lines().enumerate() {
                if raw.trim().is_empty() {
                    continue;
                }
                if dir == "prose" {
                    out.push((name.clone(), line, raw.to_string(), NO_VALUE));
                    continue;
                }
                let case: serde_json::Value = serde_json::from_str(raw).expect("JSON");
                let spans = case["spans"].as_array().is_some_and(|s| !s.is_empty());
                let text = case["text"].as_str().expect("text").to_string();
                out.push((name.clone(), line, text, if spans { "" } else { NO_VALUE }));
            }
        }
    }
    for (line, text) in tail4::inputs().into_iter().enumerate() {
        out.push(("secret_tail4".into(), line, text, ""));
    }
    for (line, (text, _)) in REPROS.iter().enumerate() {
        out.push(("repros".into(), line, text.to_string(), ""));
    }
    for (line, text) in TRAPS.iter().enumerate() {
        out.push(("traps".into(), line, text.to_string(), NO_VALUE));
    }
    out
}

/// The exact byte ranges of `input` a gate in `mode` does not issue in clear, or
/// `None` for a refusal.
///
/// One alignment, never a second reading (TEST-FITS-EXACT): in Private each
/// token stands for the surface the gate minted for it, in Open each
/// `[<class> removed]` marker stands for the detector's own removed range. A
/// text the output does not read back onto panics here.
fn hidden(mode: PrivacyMode, input: &str) -> Option<Vec<(usize, usize)>> {
    let (output, minted) = run(mode, input)?;
    Some(exact_or_fail(mode, input, &output, &minted))
}

/// A gate output and the tokens it minted, or `None` for a refusal.
type Run = Option<(String, Vec<(String, String)>)>;

/// The gate output for `input` and the tokens it minted.
fn run(mode: PrivacyMode, input: &str) -> Run {
    let mut gate = gate(mode);
    let output = gate.text(input).ok()?.0.as_str().to_string();
    Some((output, gate.take_minted()))
}

/// The exact ranges of `input` an output masks, read from the minted tokens
/// (Private) or the detector's own removed ranges (Open).
type Ranges = Option<Vec<(usize, usize)>>;

fn format_modes(modes: &[Ranges; 2]) -> String {
    let one = |ranges: &Ranges| match ranges {
        None => "R".to_string(),
        Some(ranges) => {
            let parts: Vec<String> = ranges.iter().map(|(a, b)| format!("{a}-{b}")).collect();
            parts.join(",")
        }
    };
    format!("{}/{}", one(&modes[0]), one(&modes[1]))
}

fn parse_modes(field: &str) -> [Ranges; 2] {
    let one = |field: &str| {
        if field == "R" {
            return None;
        }
        let parse = |part: &str| {
            let (a, b) = part.split_once('-').expect("a-b");
            (a.parse().expect("start"), b.parse().expect("end"))
        };
        Some(
            field
                .split(',')
                .filter(|p| !p.is_empty())
                .map(parse)
                .collect(),
        )
    };
    let (private, open) = field.split_once('/').expect("private/open");
    [one(private), one(open)]
}

fn both_modes(text: &str) -> [Ranges; 2] {
    MODES.map(|mode| hidden(mode, text))
}

fn bytes(ranges: &[(usize, usize)]) -> Vec<usize> {
    ranges.iter().flat_map(|&(a, b)| a..b).collect()
}

/// What one text did against main: bytes lost, a new refusal, bytes gained.
#[derive(Default)]
struct Delta {
    lost: usize,
    refused: bool,
    gained: usize,
}

fn delta(main: &[Ranges; 2], ours: &[Ranges; 2]) -> Delta {
    let mut out = Delta::default();
    for (main, ours) in main.iter().zip(ours) {
        let (Some(main), Some(ours)) = (main, ours) else {
            out.refused |= ours.is_none() && main.is_some();
            continue;
        };
        let (main, ours) = (bytes(main), bytes(ours));
        out.lost += main.iter().filter(|b| !ours.contains(b)).count();
        out.gained += ours.iter().filter(|b| !main.contains(b)).count();
    }
    out
}

/// `(source, line)` -> main's ranges. A text it does not list was issued
/// unchanged by main in both modes.
fn frozen() -> BTreeMap<(String, usize), [Ranges; 2]> {
    let raw = include_str!("data/label_value_main.txt");
    let mut out = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.starts_with('#')) {
        let (source, entries) = line.split_once('\t').expect("source<TAB>entries");
        for entry in entries.split(';') {
            let (at, modes) = entry.split_once(':').expect("line:modes");
            out.insert(
                (source.to_string(), at.parse().expect("line")),
                parse_modes(modes),
            );
        }
    }
    out
}

#[test]
#[ignore = "refreezes the fixture on main when LV_FREEZE is set"]
fn freeze_main_fixture() {
    let Ok(path) = std::env::var("LV_FREEZE") else {
        return;
    };
    let mut lines: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (source, line, text, _) in texts() {
        let modes = both_modes(&text);
        if modes.iter().all(|m| m.as_ref().is_some_and(Vec::is_empty)) {
            continue;
        }
        let entry = format!("{line}:{}", format_modes(&modes));
        lines.entry(source).or_default().push(entry);
    }
    let mut out = String::from("# Frozen from origin/main 0dff4fb5 by freeze_main_fixture.\n");
    for (source, entries) in lines {
        out.push_str(&format!("{source}\t{}\n", entries.join(";")));
    }
    fs::write(path, out).expect("fixture written");
}

/// Rule 1 and 4: no byte main hides is issued in clear, in either mode, and no
/// text is newly refused. Rule 2: no text without a value gains a mask (the
/// AF/HU/SL prose, the eval cases with no labelled span, the traps).
#[test]
fn nothing_main_hides_is_issued_in_clear() {
    let frozen = frozen();
    let all = texts();
    let (mut lost, mut refusals, mut new_masks, mut gained) =
        (Vec::new(), Vec::new(), Vec::new(), 0);
    for (source, line, text, tag) in &all {
        let empty = [Some(Vec::new()), Some(Vec::new())];
        let main = frozen.get(&(source.clone(), *line)).unwrap_or(&empty);
        let step = delta(main, &both_modes(text));
        let at = format!("{source}:{line} {text:.80?}");
        if step.lost > 0 {
            lost.push(format!("{at}: {} bytes", step.lost));
        }
        if step.refused {
            refusals.push(at.clone());
        }
        if step.gained > 0 && *tag == NO_VALUE {
            new_masks.push(at);
        }
        gained += step.gained;
    }
    eprintln!(
        "{} texts: lost {}, refusals {}, new masks on no-value texts {}, bytes newly hidden {gained}",
        all.len(),
        lost.len(),
        refusals.len(),
        new_masks.len()
    );
    assert!(all.len() > 900, "only {} texts", all.len());
    assert!(lost.is_empty(), "bytes lost: {lost:#?}");
    assert!(refusals.is_empty(), "new refusals: {refusals:#?}");
    assert!(new_masks.is_empty(), "new masks: {new_masks:#?}");
}

/// Rule 1 and 2 on the 4,000 public synthetic texts (Nemotron-PII + Gretel, not in
/// the repo). `LV_PUBLIC_DIR` holds the JSONL files; with `LV_PUBLIC_FREEZE=1`
/// main's outputs are written to `LV_PUBLIC_MAIN`, otherwise they are compared:
/// a text whose output is unchanged is skipped, any other is read into ranges.
#[test]
#[ignore = "public corpus: LV_PUBLIC_DIR=<dir> LV_PUBLIC_MAIN=<file> -- --ignored public"]
fn public_corpus_differential() {
    let (Ok(dir), Ok(main_path)) = (
        std::env::var("LV_PUBLIC_DIR"),
        std::env::var("LV_PUBLIC_MAIN"),
    ) else {
        return;
    };
    let mut cases = Vec::new();
    for name in ["gretel-pii.jsonl", "nemotron-pii.jsonl"] {
        let raw = fs::read_to_string(PathBuf::from(&dir).join(name)).expect("corpus");
        for line in raw.lines() {
            let case: serde_json::Value = serde_json::from_str(line).expect("JSON");
            let text = case["text"].as_str().expect("text").to_string();
            let hard = [
                "secret",
                "national_id",
                "passport",
                "health",
                "card",
                "iban",
            ];
            let spans = case["spans"].as_array().cloned().unwrap_or_default();
            let gold = spans
                .iter()
                .any(|s| hard.contains(&s["type"].as_str().unwrap_or("")));
            cases.push((text, gold));
        }
    }
    let outputs = |text: &str| MODES.map(|mode| run(mode, text));
    if std::env::var("LV_PUBLIC_FREEZE").is_ok() {
        let out: Vec<String> = cases
            .iter()
            .map(|(text, _)| serde_json::to_string(&outputs(text)).expect("JSON"))
            .collect();
        fs::write(&main_path, out.join("\n")).expect("frozen");
        return;
    }
    let raw = fs::read_to_string(&main_path).expect("frozen main");
    let main: Vec<[Run; 2]> = raw
        .lines()
        .map(|l| serde_json::from_str(l).expect("JSON"))
        .collect();
    assert_eq!(main.len(), cases.len());
    let (mut lost, mut refusals, mut clean, mut clean_new, mut changed) = (0, 0, 0, 0, 0);
    let mut unreadable = 0;
    // The reader's own alignment panics are caught and counted, not printed.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for (at, ((text, gold), main)) in cases.iter().zip(&main).enumerate() {
        clean += usize::from(!gold);
        let ours = outputs(text);
        if ours == *main {
            continue;
        }
        let ranges = |runs: &[Run; 2]| {
            std::panic::catch_unwind(|| {
                runs.iter()
                    .zip(MODES)
                    .map(|(run, mode)| {
                        run.as_ref().map(|(output, minted)| {
                            exact_ranges(mode, text, output, minted)
                                .unwrap_or_else(|| panic!("{mode:?} no exact reading"))
                        })
                    })
                    .collect::<Vec<Ranges>>()
            })
            .ok()
            .map(|ranges| [ranges[0].clone(), ranges[1].clone()])
        };
        let step = match (ranges(main), ranges(&ours)) {
            (Some(main), Some(ours)) => {
                if !gold {
                    for (main, ours) in main.iter().zip(&ours) {
                        let (Some(main), Some(ours)) = (main, ours) else {
                            continue;
                        };
                        let main = bytes(main);
                        for &(a, b) in ours
                            .iter()
                            .filter(|(a, b)| (*a..*b).any(|x| !main.contains(&x)))
                        {
                            let from = text.floor_char_boundary(a.saturating_sub(40));
                            eprintln!("NEWMASK {at}: {:?} [{}]", &text[from..a], &text[a..b]);
                        }
                    }
                }
                delta(&main, &ours)
            }
            _ => {
                unreadable += 1;
                word_delta(text, main, &ours)
            }
        };
        if step.lost > 0 {
            lost += 1;
            eprintln!("LOST {at} {} bytes {text:.160?}", step.lost);
        }
        refusals += usize::from(step.refused);
        changed += usize::from(step.gained > 0);
        clean_new += usize::from(!gold && step.gained > 0);
    }
    std::panic::set_hook(hook);
    let rise = 100.0 * clean_new as f64 / clean.max(1) as f64;
    eprintln!(
        "{} public texts: lost {lost}, refusals {refusals}, changed {changed}, \
         new masks on no-PII texts {clean_new}/{clean} ({rise:.2} pp), read by words {unreadable}",
        cases.len()
    );
    assert_eq!(lost, 0);
    assert_eq!(refusals, 0);
    // A text the exact reader cannot align is compared by words and fails here
    // (TEST-FITS-EXACT: an unreadable text is never a pass).
    assert_eq!(unreadable, 0, "{unreadable} texts with no exact reading");
    assert!(rise <= 1.0, "{rise:.2} pp");
}

/// The word fallback when the range reader cannot align an output: a word of
/// `text` main does not issue must not be issued by this branch either. It only
/// ever feeds the `unreadable` count, which fails the test above.
fn word_delta(text: &str, main: &[Run; 2], ours: &[Run; 2]) -> Delta {
    let mut out = Delta::default();
    for (main, ours) in main.iter().zip(ours) {
        let (Some((main, _)), Some((ours, _))) = (main, ours) else {
            out.refused |= ours.is_none() && main.is_some();
            continue;
        };
        let words = |output: &str| -> Vec<String> {
            output.split_whitespace().map(str::to_string).collect()
        };
        let (main, ours) = (words(main), words(ours));
        for word in text.split_whitespace().filter(|w| w.len() > 2) {
            let issued = |words: &[String]| words.iter().any(|w| w == word);
            out.lost += usize::from(!issued(&main) && issued(&ours));
            out.gained += usize::from(issued(&main) && !issued(&ours));
        }
    }
    out
}

/// Rule 3: 4x the input costs less than 6x the time (linear is 4x, quadratic 16x).
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn label_dense_text_scales_linearly() {
    let registry = Registry::new().without_names();
    let table = "| password | Tax ID | MRN | blood type |\n|---|---|---|---|\n\
                 | Hk7#pq2Lm | 12-3456789 | 448812 | O+ |\n";
    for unit in ["password: ", "Tax ID ", "the pin, 7198 ", table] {
        let time = |n: usize| {
            let text = unit.repeat(n);
            let start = Instant::now();
            registry.analyze(&text);
            start.elapsed().as_secs_f64()
        };
        time(1_000);
        let (small, large) = (time(4_000), time(16_000));
        eprintln!(
            "{unit:?}: 4k {small:.3} s, 16k {large:.3} s, ratio {:.2}",
            large / small
        );
        assert!(
            large < small * 6.0,
            "{unit:?}: {small:.3} s -> {large:.3} s"
        );
    }
}
