//! ID-LABEL-2 acceptance (seal A2 on #290): the labelled IDs main still leaves
//! in clear in both modes — a licence label with a short parenthesised aside
//! before its value, and a UK National Insurance number after an explicit NI
//! label with padding or one line break, compact or partly compact with a
//! glued suffix, or with uneven blanks between its pairs.
//!
//! Traps keep exactly main's masks, and the head is a strict byte superset of
//! main on a seeded differential frozen from origin/main in
//! `data/ids_after_label_2_main.txt` (`-- --ignored freeze --nocapture`, on
//! main only). Every value is invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};

/// Masked byte ranges, `start..end`.
type Ranges = Vec<(usize, usize)>;

const FIXTURE: &str = include_str!("data/ids_after_label_2_main.txt");

/// Seal A2's repros, `(text, value)`, plus near variants.
const REPROS: &[(&str, &str)] = &[
    (
        "Driving licence number (if applicable): MORGA753116SM9IJ",
        "MORGA753116SM9IJ",
    ),
    (
        "Driving licence number (if applicable): 48263471",
        "48263471",
    ),
    ("Driver's licence number (if any): 72BD41385", "72BD41385"),
    (
        "driving licence (optional) = MORGA753116SM9IJ",
        "MORGA753116SM9IJ",
    ),
    ("NI number:\nQq 28 46 15 bok", "Qq 28 46 15 b"),
    ("NI number:\r\nQq 28 46 15 bok", "Qq 28 46 15 b"),
    ("NI number:    Qq 28 46 15 bok", "Qq 28 46 15 b"),
    (
        "National Insurance number:\n  Qq 28 46 15 bok",
        "Qq 28 46 15 b",
    ),
    ("NI number:\nAB 12 34 56 C", "AB 12 34 56 C"),
    ("NI number:      AB123456C", "AB123456C"),
    ("NI number: AB123456Cok", "AB123456C"),
    ("NI number: Qq284615bok", "Qq284615b"),
    ("NI number: Qq 28 46 15bok", "Qq 28 46 15b"),
    ("NINO AB 123456C", "AB 123456C"),
    ("NINO: AB 123456Cok", "AB 123456C"),
    ("NI no: AB  12 34   56 C", "AB  12 34   56 C"),
    ("NI number: Qq  28 46 15 bok", "Qq  28 46 15 b"),
    ("NI no.\tQq 28  46 15 bok", "Qq 28  46 15 b"),
    // Round 1.
    (
        "Driving licence number (as applicable): 48263471",
        "48263471",
    ),
    (
        "Driving licence number (as available): 72BD41385",
        "72BD41385",
    ),
    ("TIN (if applicable): 7284635190", "7284635190"),
    ("Ausweis (falls vorhanden): L01X00T47", "L01X00T47"),
    ("NI number (if applicable): Qq284615bok", "Qq284615b"),
    (
        "National Insurance number (if applicable): Qq  28 46 15 bok",
        "Qq  28 46 15 b",
    ),
    ("NI number: Qq    28 46 15 bok", "Qq    28 46 15 b"),
    ("NI number: Qq\t28 46 15 bok", "Qq\t28 46 15 b"),
    ("NI no: Qq\t28\t46\t15\tbok", "Qq\t28\t46\t15\tb"),
    // Round 1 (a security review, NO-SEAL 1c1b0de2).
    ("NI number, Qq28 46 15 bok", "Qq28 46 15 b"),
    ("NI number, Qq284615bok", "Qq284615b"),
];

/// A secret label inside the aside: every byte main masks stays masked in both
/// modes (round 1 P2, the Open regression), checked by the differential.
const SUPERSET: &[&str] = &[
    "Driving licence number (password/alpha): 48263471",
    "Driving licence number (password): 48263471",
    "Driving licence number (PIN/alpha): 48263471",
    "Driving licence number (pin): 48263471",
    "Driving licence number (API key/old): 48263471",
    "Licence number (passcode): 72BD41385",
    "TIN (password): 7284635190",
];

/// Lines that keep exactly main's masks in both modes.
const TRAPS: &[&str] = &[
    "ANI number: at 12 34 56 cok",
    "ANI number:\nQq 28 46 15 bok",
    "ANI number: Qq284615bok",
    "NI number list at 12 34 56 cok",
    "NI number:\n\nQq 28 46 15 bok",
    "Qq 28 46 15 bok",
    "Qq  28 46 15 bok",
    "Qq284615bok",
    "at 10 20 30 cats",
    "Flight BA 12 34 56 dispatched",
    "Flight BA 12  34 56 dispatched",
    "Order ID 55210931",
    "Version 12AB34567",
    "Licence number: 12-11-08",
    "Licence number: 31-02-98",
    "Licence number (business): 72BD41385",
    "the driving licence (if applicable) is attached",
    "Driving licence (expired 2019) renewed in May",
    "MIT license (see LICENSE) applies",
    "NI number: see the letter from HMRC",
    "TIN (if applicable) 7284635190",
    "Ausweis (falls vorhanden) L01X00T47",
    "(if applicable): Qq284615bok",
    "Ref (if applicable): Qq284615bok",
    "Qq    28 46 15 bok",
    "Qq\t28 46 15 bok",
    "Code:\tQq\t28 46 15 bok",
    "Ref, Qq284615bok",
    "Driving licence number (corporate): 72BD41385",
    "Licence number (commercial): 72BD41385",
    "Driving licence number (organisation): 48263471",
    "Licence number (organization): 72BD41385",
    "driving licence (if any) - 12-11-08",
    "the corporate licence number 84730249",
];

/// A tiny seeded generator (xorshift64), so the differential is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a, T>(&mut self, list: &'a [T]) -> &'a T {
        &list[(self.next() % list.len() as u64) as usize]
    }
}

const SEED: u64 = 0x1D1A_BE12_2026_1027;
const LETTERS: &[u8] = b"ABCEGHJKLMNPRSTWXYZQ";
const NI_LEADS: &[&str] = &[
    "NI number:",
    "NI number:\n",
    "NI number:\r\n",
    "NI number:      ",
    "NI no: ",
    "NI no.\t",
    "NINO ",
    "NINO:\n  ",
    "National Insurance number: ",
    "ANI number: ",
    "NI number list ",
    "NI number:\n\n",
    "",
    "Ref ",
    "Flight ",
    "code: ",
    "NI number (if applicable): ",
    "National Insurance number (as applicable):\n",
    "NI no (password): ",
    "Ref (if applicable): ",
    "Code:\t",
    "NI number, ",
    "Ref, ",
];
const BLANKS: &[&str] = &[
    "", " ", " ", "  ", "   ", "\u{a0}", "-", "    ", "\t", "      ", " \t",
];
const TAILS: &[&str] = &["", "ok", "ay", " ", "\n", "7", "Dog", " dispatched", "."];
const ASIDES: &[&str] = &[
    "if applicable",
    "if any",
    "optional",
    "business",
    "UK",
    "see note",
    "expired 2019",
    "this one is a much longer aside than thirty",
    "as applicable",
    "as available",
    "password/alpha",
    "pin",
    "api key",
    "falls vorhanden",
    "corporate",
    "commercial",
    "organisation",
];
const LICENCE_LABELS: &[&str] = &[
    "Driving licence number",
    "Driver's licence number",
    "driving licence",
    "Licence number",
    "driver license",
    "the licence",
    "TIN",
    "Ausweis",
];
const LINKS: &[&str] = &[": ", " ", " = ", "\n", ") ", " is attached, value ", " - "];
const LICENCE_VALUES: &[&str] = &["MORGA753116SM9IJ", "48263471", "72BD41385", "12-11-08"];

/// One seeded NI or licence text.
fn seeded(rng: &mut Rng) -> String {
    if rng.next().is_multiple_of(3) {
        let label = rng.pick(LICENCE_LABELS);
        let aside = rng.pick(ASIDES);
        let link = rng.pick(LINKS);
        let value = rng.pick(LICENCE_VALUES);
        return format!("{label} ({aside}){link}{value}");
    }
    let letter = |rng: &mut Rng| {
        let b = *rng.pick(LETTERS);
        if rng.next().is_multiple_of(2) {
            b
        } else {
            b.to_ascii_lowercase()
        }
    };
    let (a, b) = (letter(rng), letter(rng));
    let c = *rng.pick(b"ABCDabcd");
    let mut text = rng.pick(NI_LEADS).to_string();
    text.push(a as char);
    text.push(b as char);
    for _ in 0..3 {
        text.push_str(rng.pick(BLANKS));
        text.push_str(&format!("{:02}", rng.next() % 100));
    }
    text.push_str(rng.pick(BLANKS));
    text.push(c as char);
    text.push_str(rng.pick(TAILS));
    text
}

/// The differential inputs: repros, traps and 900 seeded texts.
fn inputs() -> Vec<(String, Ranges)> {
    let mut out: Vec<(String, Ranges)> = REPROS
        .iter()
        .map(|&(t, v)| {
            let start = t.find(v).expect("value");
            (t.to_string(), vec![(start, start + v.len())])
        })
        .collect();
    out.extend(TRAPS.iter().map(|&t| (t.to_string(), Vec::new())));
    out.extend(SUPERSET.iter().map(|&t| (t.to_string(), Vec::new())));
    let mut rng = Rng(SEED);
    out.extend((0..900).map(|_| (seeded(&mut rng), Vec::new())));
    out
}

/// Each repro hidden in both modes, and restored exactly by Private.
#[test]
fn seal_a2_repros_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for &(text, value) in REPROS {
        let start = text.find(value).expect("the value is in its text");
        for mode in MODES {
            let Some((output, minted)) = issue(mode, text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            let ranges = masked(mode, text).expect("issued once already");
            if !covered(&ranges, start, start + value.len()) {
                wrong.push(format!("{mode:?} {text:?} -> {output:?}"));
            }
            if mode == PrivacyMode::Private {
                let mut restored = output.clone();
                for (token, surface) in &minted {
                    restored = restored.replace(&format!("⟦{token}⟧"), surface);
                }
                if restored != text {
                    wrong.push(format!("restore {text:?} -> {output:?}"));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// One record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Ranges>) -> String {
    let join = |r: Ranges| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.map_or("!".into(), join)
}

fn parse(record: &str) -> Option<Ranges> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[(String, Ranges)]) -> String {
    let bytes = inputs.iter().flat_map(|(text, _)| text.bytes().chain([0]));
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
    let records: Vec<String> = inputs.iter().map(|(text, _)| record(text)).collect();
    let lines: Vec<String> = records.chunks(100).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// The frozen main records, one `[private, open]` pair per input.
fn main_records(inputs: &[(String, Ranges)]) -> Vec<[Option<Ranges>; 2]> {
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    records
        .iter()
        .map(|record| {
            let mut modes = record.split('|').map(parse);
            [modes.next().expect("private"), modes.next().expect("open")]
        })
        .collect()
}

/// Traps: in both modes the exact masks equal main's.
#[test]
fn traps_keep_main_masks() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let mut wrong = Vec::new();
    for ((text, _), main) in inputs.iter().zip(&main) {
        if !TRAPS.contains(&text.as_str()) {
            continue;
        }
        for (index, mode) in MODES.into_iter().enumerate() {
            if masked(mode, text) != main[index] {
                let output = issue(mode, text).map(|(o, _)| o);
                wrong.push(format!(
                    "{mode:?} {text:?}: main {:?} -> {output:?}",
                    main[index]
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} changed:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A strict byte superset of main in both modes, no new refusal, and every
/// repro value hidden in both modes.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let (mut lost, mut refused, mut gained, mut missed) = ([0usize; 2], 0, [0usize; 2], 0);
    for ((text, values), main) in inputs.iter().zip(main) {
        for (index, main) in main.into_iter().enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += usize::from(main.is_some());
                continue;
            };
            let main = main.unwrap_or_default();
            let gone = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                eprintln!("{:?} {text:?}: main {main:?} -> {now:?}", MODES[index]);
            }
            lost[index] += gone;
            gained[index] += usize::from(now != main);
            if values.iter().any(|&(s, e)| !covered(&now, s, e)) {
                missed += 1;
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; texts with \
         new masks Private/Open {gained:?}; values missed {missed}",
        inputs.len()
    );
    assert_eq!((lost, refused, missed), ([0, 0], 0, 0));
}

/// Release only: dense labelled NI and licence text at 16 KiB to 1 MiB. Bar:
/// each 4x step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test ids_after_label_2 -- --ignored timing"]
fn timing_scales_linearly() {
    let unit = "NI number:\nQq 28 46 15 bok NI no: AB  12 34   56 C NI number: Qq284615bok \
        Driving licence number (if applicable): 48263471 ((((( NI number:       \
        Licence number (business): 72BD41385 Flight BA 12 34 56 dispatched TIN (if applicable): 7284635190 NI number (if applicable):\tQq\t28    46 15 bok (if (if (if\r\n";
    let time = |bytes: usize| {
        let text = unit.repeat(bytes / unit.len());
        (0..3)
            .map(|_| {
                let start = Instant::now();
                let _ = issue(PrivacyMode::Private, &text);
                let _ = issue(PrivacyMode::Open, &text);
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let times: Vec<Duration> = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
        .map(time)
        .to_vec();
    eprintln!("ids after label 2: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
