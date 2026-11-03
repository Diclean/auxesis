//! FIN-6 differential, as HEALTH-RECALL-1: every privacy-eval case, the 300
//! AF/HU/SL prose lines, every secret_tail4 input, the NORM-1 repros, the 1,692
//! leak-finder repros of 2026-10-22 and the FIN-6 probes and traps against
//! `data/fin6_main.txt`, frozen from origin/main (`-- --ignored freeze
//! --nocapture`). All values are invented.

use std::time::Instant;

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
#[allow(dead_code)]
mod tail4 {
    include!("data/secret_tail4_cases.rs");

    pub fn texts() -> Vec<String> {
        let fixed = [CASES, PR1B_CASES, PR2_CASES].into_iter().flatten();
        let fixed = fixed.map(|case| case.1.to_string());
        fixed
            .chain(built_cases().into_iter().map(|case| case.1))
            .collect()
    }
}
use cases::{covered, masked, repros, MODES};

const FIXTURE: &str = include_str!("data/fin6_main.txt");
const LEAK_REPROS: &str = include_str!("data/fin6_leak_repros.json");

/// The FIN-6 probes in a frame: what main already hides must stay hidden.
const PROBES: &[&str] = &[
    "my NI is PN/48/15/16/C, thanks",
    "PN  48  15  16  C",
    "PN.48.15.16.C is the one",
    "refPN 48 15 16 C",
    "PN 48 15 16 Cok",
    "please use QQ/12/34/56/A",
    "key akiaiosfodnn7example",
    "NIR 1  84  12  76  451  089  46",
    "card 4539  1488  0343  6467",
    "card 4539/1488/0343/6467",
    "card 4539.1488.0343.6467",
    "card 4539  1488  0343  6468",
    "SSN:512/45/8873",
];

/// Texts with no value: they must come out exactly as main.
const TRAPS: &[&str] = &[
    "12/34/56",
    "2026/10/22",
    "v1.48.15.16",
    "PN 48 pages",
    "Section 48.15.16",
    "ref 4539 1488",
    "akia",
    "internationalization",
    "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
];

/// Every input in its order, with its kind.
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
            if line.trim().is_empty() {
                continue;
            }
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            out.push(("eval", case["text"].as_str().unwrap().to_string()));
        }
    }
    for lang in ["af", "hu", "sl"] {
        let prose = read(format!("{root}/prose/{lang}.txt"));
        let lines = prose.lines().filter(|l| !l.trim().is_empty());
        out.extend(lines.map(|l| ("prose", l.into())));
    }
    out.extend(tail4::texts().into_iter().map(|text| ("tail4", text)));
    out.extend(repros().into_iter().map(|(text, _, _)| ("repro", text)));
    let leaks: Vec<String> = serde_json::from_str(LEAK_REPROS).unwrap();
    out.extend(leaks.into_iter().map(|text| ("leak", text)));
    out.extend(PROBES.iter().map(|t| ("repro", t.to_string())));
    out.extend(TRAPS.iter().map(|t| ("prose", t.to_string())));
    out
}

/// One record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    let join = |r: Vec<(usize, usize)>| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.map_or("!".into(), join)
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[(&str, String)]) -> String {
    let bytes = inputs.iter().flat_map(|(_, text)| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = inputs();
    let record = |text: &String| MODES.map(|mode| record(masked(mode, text))).join("|");
    let records: Vec<String> = inputs.iter().map(|(_, text)| record(text)).collect();
    let lines: Vec<String> = records.chunks(100).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// A strict byte superset of main in both modes, no new refusal, and no new
/// mask on a prose line or a trap.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut prose, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    let mut hidden = [0usize; 2];
    for ((kind, text), record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let now = masked(MODES[index], text);
            if now.is_none() && main.is_some() {
                refused += 1;
            }
            let (Some(now), Some(main)) = (now, main) else {
                continue;
            };
            let gone = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            lost[index] += gone;
            // The bytes the branch hides and main left in clear.
            hidden[index] += now
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&main, b, b + 1))
                .count();
            grew[index] += usize::from(now != main);
            let new = *kind == "prose" && now != main;
            prose += usize::from(new);
            if gone > 0 || new {
                eprintln!(
                    "{kind} {:?} {text:?}: main {main:?} now {now:?}",
                    MODES[index]
                );
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; bytes hidden Private/Open {hidden:?}; \
         refusals {refused}; prose or trap lines changed {prose}; texts whose masks changed \
         Private/Open {grew:?}",
        inputs.len()
    );
    assert_eq!((lost, refused, prose), ([0, 0], 0, 0));
}

/// Release only: each FIN-6 shape at 4k and 16k repeats through both gates,
/// best of three; the time ratio stays under 6 (linear).
#[test]
#[ignore = "release timing: -- --ignored --nocapture scales"]
fn fin6_shapes_scale_linearly() {
    for unit in ["PN/48/", "4539  ", "PN  48  15  16  C ", "akia"] {
        let once = |text: &str| {
            let start = Instant::now();
            for mode in MODES {
                let _ = masked(mode, text);
            }
            start.elapsed().as_secs_f64()
        };
        let time = |n: usize| {
            let text = unit.repeat(n);
            (0..3).map(|_| once(&text)).fold(f64::MAX, f64::min)
        };
        let (small, large) = (time(4096), time(16384));
        eprintln!(
            "{unit:?}: 4k {small:.3}s 16k {large:.3}s ratio {:.2}",
            large / small
        );
        assert!(large / small < 6.0, "{unit:?} scales {:.2}", large / small);
    }
}
