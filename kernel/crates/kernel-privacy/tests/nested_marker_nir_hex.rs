//! FIN-4: a secret inside nested or unbalanced `⟦ ⟧` markers and a French NIR
//! glued to a hex run are masked in Private and Open, and nothing shipped
//! regresses.
//!
//! The differential runs every input through `Gate::for_grant` in both modes
//! against `data/fin4_main.txt`, frozen from origin/main: no byte main masks
//! may be left clear and no text may be refused. Refreeze on main only:
//! `cargo test -p kernel-privacy --test nested_marker_nir_hex -- --ignored
//! freeze --nocapture`. All values are invented; `sk~` reads `sk-` at run time.
//!
//! `fin4_main.txt` is a full refreeze from main with the exact reader
//! (TEST-FITS-EXACT), not a patch of 33 records: every record is re-read, and
//! 114 of them change against the fixture the greedy reader left behind — 32
//! with a byte given up, 1 that was `?` and is now ranges, 81 that gain only, 88
//! of the 114 eval records among them — for 2,564 bytes gained. The 94 bytes
//! given up are 30 single bytes that sit between two masks the gate writes
//! separately (`password is` and `red horse`; the gate leaves the one between
//! them in the clear) and 64 bytes of literal `⟦…⟧` marker text the gate emits
//! in the clear, escaped, which the old reader claimed as masked. No byte of a
//! value is given up.

use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, Registry};

#[allow(dead_code)]
mod tail4 {
    include!("data/secret_tail4_cases.rs");

    pub fn inputs() -> Vec<String> {
        let mut out: Vec<String> = [CASES, PR1B_CASES, PR2_CASES]
            .into_iter()
            .flatten()
            .map(|case| case.1.to_string())
            .collect();
        out.extend(built_cases().into_iter().map(|case| case.1));
        out.extend(refusal_cases().into_iter().map(|case| case.1));
        out
    }
}

const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];
const FIXTURE: &str = include_str!("data/fin4_main.txt");
const KEY: &str = "abcdefghijklmnopqrstuvwxyz";

#[allow(dead_code)]
mod exact {
    include!("data/exact_mask.rs");
}

/// The gate's output and the `(token, surface)` pairs it minted, or `None` for a
/// refusal.
fn run(mode: PrivacyMode, input: &str) -> Option<(String, Vec<(String, String)>)> {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be allowed in {mode:?}");
    };
    let mut gate = Gate::for_grant(&grant, [9u8; 32]);
    let output = gate.text(input).ok()?.0.as_str().to_string();
    Some((output, gate.take_minted()))
}

fn issue(mode: PrivacyMode, input: &str) -> Option<String> {
    run(mode, input).map(|(output, _)| output)
}

/// The byte ranges of `input` the gate replaced: `Ok(None)` for a refusal,
/// `Err(output)` when the output does not read back onto `input` exactly.
///
/// One alignment, never a second reading (TEST-FITS-EXACT, `exact_mask.rs`):
/// in Private each `⟦NAME⟧` stands for the surface the gate minted for it —
/// including the `⟦⟦` the gate writes for a literal `⟦` of this file's marker
/// texts — and in Open each `[<class> removed]` stands for the detector's own
/// removed range. The old reader dropped each clear piece at the first place it
/// appeared, which under-claimed a key written between nested markers.
type Masked = Result<Option<Vec<(usize, usize)>>, String>;

fn masked(mode: PrivacyMode, input: &str) -> Masked {
    let Some((output, minted)) = run(mode, input) else {
        return Ok(None);
    };
    exact::exact_ranges(mode, input, &output, &minted)
        .map(Some)
        .ok_or(output)
}

/// (text, the value it must fully mask in both modes).
fn repros() -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Nested, deeper, unbalanced and entity-written markers around a key.
    for dash in ["&#45;", "&#x2d;", "&#X2D;", "~"] {
        let key = format!("sk{dash}{KEY}").replace('~', "-");
        for shape in [
            "⟦1⟦{k}⟧ ⟧",
            "⟦1⟦2⟦{k}⟧ ⟧ ⟧",
            "⟦a⟦b⟦c⟦{k}⟧⟧⟧⟧",
            "⟦1⟦{k}",
            "⟦⟦⟦1⟦{k}",
            "1⟦{k} ⟧ ⟧",
            "⟦1⟦{k}⟧",
            "⟦x⟧1⟦{k}⟧ ⟧",
            "⟦1&#x27E6;{k}&#x27E7; ⟧",
        ] {
            let value = shape.replace("{k}", &key);
            out.push((format!("Can you check {value} now, please."), key.clone()));
        }
    }
    // A NIR (key 46) glued to a hex run on either side, plain and spaced.
    let hex = "0f3a9b2c4d6e8f0a1b3c5d7e9";
    for nir in ["184127645108946", "1 84 12 76 451 089 46"] {
        for (pre, post) in [("", hex), (hex, ""), ("", "deadbeef"), ("cafe", "")] {
            let text = format!("NIR {pre}{nir}{post} fin");
            out.push((text, nir.to_string()));
        }
    }
    out.push((
        format!("1841276451089460f3a9{hex}"),
        "184127645108946".into(),
    ));
    out
}

/// Look-alikes that carry no value: they must come out exactly as on main.
const TRAPS: [&str; 12] = [
    "⟦x + 1⟧ and ⟦⟦y⟧⟧ = z",
    "⟦1⟦2⟧ ⟧ items",
    "maths ⟦a⟦b⟧c⟧ and ⟦",
    "550e8400e29b41d4a716446655440000",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "1840300999001abcdef",
    "a1840300999001b2c3d4e5f6a7b8c9d0e1f2a3b4",
    "7c1840300999001ab0d4e5f6a7b8c9d0e1f2a3b4",
    "commit 184127645108947f3a9b2c4d6e8f0a1b",
    "commit a184127645108946f3a9b2c4d6e8f0a1b",
    "sha 1841276451089460123456789012345678901",
    "QUJDREVGR0hJ1840300999001SzFnaGlqa2xtbm8=",
];

/// Every input of the differential, in a fixed order.
fn inputs() -> Vec<(&'static str, String)> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    let read = |path: String| std::fs::read_to_string(path).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(format!("{root}/cases"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let mut out = Vec::new();
    for file in files {
        for line in read(file.display().to_string()).lines() {
            if let Ok(case) = serde_json::from_str::<serde_json::Value>(line) {
                out.push(("eval", case["text"].as_str().unwrap().to_string()));
            }
        }
    }
    for lang in ["af", "hu", "sl"] {
        let prose = read(format!("{root}/prose/{lang}.txt"));
        let lines = prose.lines().filter(|l| !l.trim().is_empty());
        out.extend(lines.map(|line| ("prose", line.to_string())));
    }
    out.extend(tail4::inputs().into_iter().map(|text| ("tail4", text)));
    out.extend(repros().into_iter().map(|(text, _)| ("repro", text)));
    out.extend(TRAPS.map(|text| ("trap", text.to_string())));
    out
}

/// One record per mode: `start-end` ranges joined by `,`, `!` for a refusal,
/// `?` plus a hash of the output when it does not align.
fn record(result: Masked) -> String {
    match result {
        Ok(None) => "!".into(),
        Ok(Some(ranges)) => {
            let ranges: Vec<String> = ranges.iter().map(|(s, e)| format!("{s}-{e}")).collect();
            ranges.join(",")
        }
        Err(output) => format!("?{}", fnv(output.bytes())),
    }
}

fn fnv(bytes: impl Iterator<Item = u8>) -> u64 {
    bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

fn parse(record: &str) -> Vec<(usize, usize)> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    record.split(',').filter_map(range).collect()
}

fn header(inputs: &[(&str, String)]) -> String {
    let bytes = inputs.iter().flat_map(|(_, text)| text.bytes().chain([0]));
    format!("{} {}", inputs.len(), fnv(bytes))
}

fn records(texts: &[(&str, String)]) -> Vec<String> {
    let record = |text: &String| MODES.map(|mode| record(masked(mode, text))).join("|");
    texts.iter().map(|(_, text)| record(text)).collect()
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = inputs();
    let lines: Vec<String> = records(&inputs)
        .chunks(100)
        .map(|c| c.join(";") + ";")
        .collect();
    let fixture = format!("{}\n{}", header(&inputs), lines.join("\n"));
    // A `?` record is an output this reader could not read back, and a frozen
    // one is a baseline that can never lose a byte: the differential counts
    // every `?` as a failure, so a fixture holding one would be red on the next
    // run with a red that says nothing. Refreeze instead.
    assert!(
        !fixture.contains('?'),
        "an unreadable output must never be frozen"
    );
    println!("FIXTURE-BEGIN\n{fixture}\nFIXTURE-END");
}

fn covered(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    (start..end).all(|byte| ranges.iter().any(|&(s, e)| s <= byte && byte < e))
}

/// Bytes main masked left clear per mode, refusals, unreadable outputs, and
/// changed outputs on `quiet` texts.
///
/// An unreadable output — a `?` record on either side — is a failure of its
/// own, not only when the two sides differ: an equal `?hash` used to add
/// nothing, so a text no gate output could be read back for was a silent pass
/// (TEST-FITS-EXACT). There is no such text in the fixture today, and `freeze`
/// refuses to write one.
fn differential(texts: &[(&str, String)], main: &[String]) -> ([usize; 2], usize, usize, usize) {
    let (mut lost, mut refused, mut unaligned, mut quiet) = ([0usize; 2], 0, 0, 0);
    for (((kind, text), main), now) in texts.iter().zip(main).zip(records(texts)) {
        for (index, (main, now)) in main.split('|').zip(now.split('|')).enumerate() {
            if now == "!" && main != "!" {
                refused += 1;
            } else if now.starts_with('?') || main.starts_with('?') {
                unaligned += 1;
                eprintln!("UNREADABLE {:?} {text:?}: {main} -> {now}", MODES[index]);
            } else {
                let now = parse(now);
                let gone = parse(main)
                    .iter()
                    .flat_map(|&(s, e)| s..e)
                    .filter(|&b| !covered(&now, b, b + 1))
                    .count();
                lost[index] += gone;
                if gone > 0 {
                    eprintln!("LOST {:?} {text:?}", MODES[index]);
                }
            }
            if matches!(*kind, "prose" | "trap") && now != main {
                quiet += 1;
                eprintln!("CHANGED {:?} {text:?}: {main} -> {now}", MODES[index]);
            }
        }
    }
    (lost, refused, unaligned, quiet)
}

/// A strict byte superset of main in both modes, no new refusal, and no change
/// on a prose line or a trap.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let main: Vec<String> = body
        .trim()
        .split_terminator(';')
        .map(|r| r.trim().to_string())
        .collect();
    assert_eq!(differential(&inputs, &main), ([0, 0], 0, 0, 0));
}

/// The 4,000 public texts (not in the repo). `FIN4_PUBLIC_FREEZE=1` on main
/// writes main's records to `FIN4_PUBLIC_MAIN`; a later run compares. With
/// either variable unset the test is skipped.
#[test]
#[ignore = "public corpus: set FIN4_PUBLIC_DIR and FIN4_PUBLIC_MAIN"]
fn public_corpus_differential() {
    let (Ok(dir), Ok(path)) = (
        std::env::var("FIN4_PUBLIC_DIR"),
        std::env::var("FIN4_PUBLIC_MAIN"),
    ) else {
        eprintln!("public corpus skipped: FIN4_PUBLIC_DIR and FIN4_PUBLIC_MAIN unset");
        return;
    };
    let mut texts = Vec::new();
    for name in ["gretel-pii.jsonl", "nemotron-pii.jsonl"] {
        let file = std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
        for line in file.lines() {
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            texts.push(("public", case["text"].as_str().unwrap().to_string()));
        }
    }
    if std::env::var_os("FIN4_PUBLIC_FREEZE").is_some() {
        std::fs::write(&path, records(&texts).join("\n")).unwrap();
        return;
    }
    let main: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(main.len(), texts.len());
    let changed = records(&texts)
        .iter()
        .zip(&main)
        .filter(|(a, b)| a != b)
        .count();
    let result = differential(&texts, &main);
    eprintln!(
        "public: {} texts, {changed} changed, (lost, refused, unaligned, -) {result:?}",
        texts.len()
    );
    assert_eq!((result.0, result.1, result.2), ([0, 0], 0, 0));
}

/// Acceptance: no eight-character piece of a repro value (read without its
/// spaces, the key without its `sk` prefix) comes out in either mode. Range
/// alignment is no use here: the input itself holds `⟦ ⟧`.
#[test]
fn repros_are_fully_masked_in_both_modes() {
    let mut leaks = Vec::new();
    for (text, value) in repros() {
        let value: String = value.replace(' ', "").replace("sk", "");
        let value = value.replace(['&', '#', ';', '-'], "");
        for mode in MODES {
            let output = issue(mode, &text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            let compact = output.replace(' ', "");
            let piece = |at: usize| &value[at..at + 8];
            if (0..=value.len() - 8).any(|at| compact.contains(piece(at))) {
                leaks.push(format!("{mode:?} {text:?} -> {output:?}"));
            }
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// The best of three registry runs over `text`.
fn timed(text: &str) -> Duration {
    let registry = Registry::new();
    let run = || {
        let start = Instant::now();
        std::hint::black_box(registry.analyze(text));
        start.elapsed()
    };
    (0..3).map(|_| run()).min().unwrap()
}

type Shape = (&'static str, fn(usize) -> String);

/// Linear time: 4x the input costs well under 6x the time.
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn markers_and_hex_runs_scale_linearly() {
    let shapes: [Shape; 5] = [
        ("open brackets", |n| "⟦".repeat(n)),
        ("nested opens", |n| "⟦1⟦".repeat(n)),
        ("nested pairs", |n| "⟦1⟦sk&#45;ab⟧ ⟧".repeat(n)),
        ("hex run", |n| "184127645108946f".repeat(n)),
        ("spaced hex", |n| "1 84 12 76 451 089 46ab".repeat(n)),
    ];
    for (name, shape) in shapes {
        let (small, large) = (timed(&shape(4_000)), timed(&shape(16_000)));
        let ratio = large.as_secs_f64() / small.max(Duration::from_millis(1)).as_secs_f64();
        eprintln!("scaling {name}: 4k {small:?} 16k {large:?} ratio {ratio:.2}");
        assert!(ratio < 6.0, "{name} is not linear: {ratio:.2}");
    }
}
