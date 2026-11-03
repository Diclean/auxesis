//! NINO-GLUED-NEXT: a suffix letter glued to the next word keeps that word's
//! value masked.
//!
//! NINO-NEWLINE-SUFFIX (#208) cut every suffix glued to a following letter at
//! the line break, so `AB 12 34 56\nCblood type A+` masked the digits, left
//! `Cblood` in clear, and the label no longer matched: `A+` came out clear.
//! 20165ae6 masked the suffix with the number, the word was a word again and
//! its value stayed masked. The cut is now only where it has to be: another
//! number starts at that letter, whose own digits the residue round must read
//! whole (FIN-6, kept by `the_fin6_repro_stays_fully_masked_in_private`).
//! Everywhere else the suffix is masked with the number, and a digit on the
//! next line is no part of it: `AB 12 34 56\nC4`, which neither base masked.
//!
//! Below: the cases over all eight line breaks, a seeded 1,600-document
//! differential against outputs frozen from origin/main (161e0381) and from
//! 20165ae6, and the release timing. The ranges come from `data/exact_mask.rs`,
//! the one shared reader (TEST-FITS-EXACT-2). Every value is invented.
//!
//! Round 1: the pass A repros (F1, a suffix that took the first letter of a
//! slashed, dotted or multi-spaced number; F2, a compact span that dropped an
//! older separated one) over the eight breaks, and a second differential of
//! 4,184 texts, two numbers in every pair of shapes, frozen from 4034659f.

use std::time::Instant;

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, exact_ranges, issue, masked, MODES};
use kernel_privacy::{EntityKind, Registry};

/// Frozen from origin/main (161e0381) and from 20165ae6 (HEALTH-LABEL, the
/// commit before NINO-NEWLINE-SUFFIX) on the corpus of [`texts`].
const MAIN: &str = include_str!("data/nino_glued_main.txt");
const HEALTH: &str = include_str!("data/nino_glued_health.txt");

/// The eight line breaks the normaliser folds into one separator, CRLF among
/// them (LF, CRLF, CR, VT, FF, NEL, U+2028, U+2029).
const BREAKS: &[&str] = &[
    "\n", "\r\n", "\r", "\u{b}", "\u{c}", "\u{85}", "\u{2028}", "\u{2029}",
];

/// A suffix letter, what it opens on the next line, and the value behind that
/// line's label. `C4` carries no label: there the number itself sat in clear on
/// both bases, which is the leak this fixes.
const GLUED: &[(&str, &str, &str)] = &[
    ("C", "blood type A+", "A+"),
    ("A", "blood group AB+", "AB+"),
    ("C", "health plan number 7KL2-QW9-PX41", "7KL2-QW9-PX41"),
    ("C", "MRN 00482913", "00482913"),
    ("C", "4", ""),
];

/// RED on 161e0381 and on 20165ae6: the suffix is masked with the number, so
/// the next line is a word again and the value behind its label stays masked.
/// Open keeps a health value in clear by design (it has no residue round), so
/// the value is required in private only; both modes must read back exactly.
#[test]
fn a_glued_suffix_keeps_the_next_words_value_masked() {
    let mut bad = Vec::new();
    for break_is in BREAKS {
        for (suffix, line, value) in GLUED {
            let text = format!("AB 12 34 56{break_is}{suffix}{line}");
            let number = format!("AB 12 34 56{break_is}{suffix}");
            match Registry::new()
                .analyze(&text)
                .iter()
                .find(|span| span.kind == EntityKind::UkNino)
            {
                None => bad.push(format!("{text:?}: no number is masked")),
                Some(span) if text[span.start..span.end] != number => bad.push(format!(
                    "{text:?}: {:?} is masked, not {number:?}",
                    &text[span.start..span.end]
                )),
                Some(_) => {}
            }
            for &mode in &MODES {
                // `masked` panics on an output that does not align exactly.
                match masked(mode, &text) {
                    None => bad.push(format!("{mode:?} refused {text:?}")),
                    Some(ranges) if !value.is_empty() && mode == MODES[0] => {
                        let at = text.find(value).unwrap();
                        if !covered(&ranges, at, at + value.len()) {
                            bad.push(format!("{mode:?} {text:?}: {value} is in clear"));
                        }
                    }
                    Some(_) => {}
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}\n{}", bad.len(), bad.join("\n"));
}

/// `|`-separated lists, so every table of the corpus is one line.
const CORPUS_BREAKS: &str = "\n|\r\n|\r|\u{b}|\u{c}|\u{85}|\u{2028}|\u{2029}|\n  |\r\n\t";
const LABELS: &str = "NI number|NINO|blood type|blood group|health plan number|MRN|\
     medical record number|card|SSN|NIR|Account|Total due|";
const PROSE: &str = "Dear customer,|thank you for your payment.|see attached.|42.00|";
const ITEMS: &str = "AB 12 34 56 C|AB123456C|QQ  12  34  56  A|PN/48/15/16/C|ce 12 34 56 d|\
     AB 12 34 56C|QQ123456C|4111 1111 1111 1111|4539  1488  0343  6467|\
     4539-1488-0343-6467|512-45-8873|512/45/8873|512  45  8873|\
     1 84 12 76 451 089 46|184127645108946|42.00|";
/// Numbers whose digits end a line, before the suffix letter that opens the
/// next one: spaced, double-spaced, slashed, compact and hyphenated.
const HEADS: &str = "AB 12 34 56|QQ  12  34  56|PN/48/15/16|AB 12 34 56|JG 12 34 56|\
     AB 123456|AB123456|AB-12-34-56|";
/// The suffix letter, then what it opens: a labelled value, a digit, another
/// number (FIN-6), a suffix letter of its own, or prose.
const SUFFIXES: &str = "C|A|D|B|";
const OPENERS: &str = "blood type A+|blood group AB+|health plan number 7KL2-QW9-PX41|\
     MRN 00482913|medical record number 771204|4|4111 1111 1111 1111|\
     B 12 34 56 A|-blood type O-|Card 4539 1488 0343 6467|see attached.|\
     Data protection officer|";

/// A xorshift64, so the corpus is the same text on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, list: &'a str) -> &'a str {
        let items = list.matches('|').count();
        list.split('|')
            .nth((self.next() % items as u64) as usize)
            .unwrap()
    }
}

/// A number whose digits end the line and whose suffix letter opens the next
/// one: the class this work order is about.
fn glued(rng: &mut Rng) -> String {
    format!(
        "{}{}{}{}",
        rng.pick(HEADS),
        rng.pick(CORPUS_BREAKS),
        rng.pick(SUFFIXES),
        rng.pick(OPENERS)
    )
}

/// The seeded corpus: 1,600 documents of one to five lines of National Insurance
/// numbers, cards, health values, social security and NIR numbers with prose,
/// joined by every break the normaliser folds. A value sits whole on its line,
/// wraps between two digit pairs, or is a suffix letter glued to the next line.
fn texts() -> Vec<String> {
    let mut rng = Rng(0x4e49_4f47_4c55_4544);
    let mut out = Vec::new();
    for _ in 0..1_600 {
        let mut doc = Vec::new();
        for _ in 0..1 + rng.next() % 5 {
            doc.push(match rng.next() % 6 {
                0 => rng.pick(PROSE).to_string(),
                1 => format!("{} {}", rng.pick(LABELS), rng.pick(ITEMS)),
                2 => format!("{} {}", rng.pick(ITEMS), rng.pick(ITEMS)),
                3 => glued(&mut rng),
                4 => {
                    let value = rng.pick(ITEMS);
                    let at = value.find(' ').unwrap_or(value.len());
                    format!(
                        "{} {} {}",
                        &value[..at],
                        rng.pick(CORPUS_BREAKS),
                        &value[at..]
                    )
                }
                _ => rng.pick(ITEMS).to_string(),
            });
        }
        out.push(doc.join(rng.pick(CORPUS_BREAKS)));
    }
    out
}

/// The exact ranges a gate masked, or `None` for a refusal or for an output the
/// shared reader cannot read back: a first-round span of one class that the
/// residue round then split into pieces of another (a card run that swallows a
/// number, `exact_mask.rs`). A baseline records `!` for those, so it claims
/// nothing there rather than reading them a second way.
fn read(
    mode: kernel_core::privacy::PrivacyMode,
    text: &str,
) -> Option<Option<Vec<(usize, usize)>>> {
    issue(mode, text).map(|(output, minted)| exact_ranges(mode, text, &output, &minted))
}

/// The `start-end` ranges of one masked text as a record, and back; `!` is a
/// refusal or an output the shared reader cannot read back.
fn record(ranges: &Option<Option<Vec<(usize, usize)>>>) -> String {
    let join = |r: Vec<(usize, usize)>| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.clone().flatten().map_or("!".into(), join)
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The text count and an FNV-1a hash of every text, so a refreeze is deliberate.
fn header(inputs: &[String]) -> String {
    let hash = inputs
        .iter()
        .flat_map(|t| t.bytes().chain([0]))
        .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        });
    format!("{} {hash}", inputs.len())
}

/// One fixture: the header, then the records of 128 texts per line.
fn fixture(inputs: &[String]) -> String {
    let each = |text: &String| MODES.map(|mode| record(&read(mode, text))).join("|");
    let lines: Vec<String> = inputs
        .chunks(128)
        .map(|chunk| chunk.iter().map(each).collect::<Vec<_>>().join(";") + ";")
        .collect();
    format!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(inputs),
        lines.join("\n")
    )
}

#[test]
#[ignore = "freezes a base fixture: run on the base only"]
fn freeze() {
    println!("{}", fixture(&texts()));
}

/// Every byte `fixture` (frozen on `base`) masked is still masked, in both
/// modes, with no new refusal and no claimed text the reader cannot read back.
fn assert_superset(base: &str, fixture: &str, inputs: &[String]) {
    let (head, body) = fixture.split_once('\n').unwrap();
    assert_eq!(
        head,
        header(inputs),
        "{base}: inputs changed: refreeze on {base}"
    );
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut unread, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    let mut lossy = Vec::new();
    for (text, record) in inputs.iter().zip(records) {
        for (index, was) in record.split('|').map(parse).enumerate() {
            let now = read(MODES[index], text);
            if now.is_none() && was.is_some() {
                refused += 1;
                lossy.push(format!("{:?} refused {text:?}", MODES[index]));
                continue;
            }
            let (Some(was), Some(now)) = (was, now) else {
                continue;
            };
            let Some(now) = now else {
                // The base claims these bytes, so this text is a finding, not
                // a text the reader skips.
                unread += 1;
                lossy.push(format!("{:?} unreadable {text:?}", MODES[index]));
                continue;
            };
            let gone = was
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                lossy.push(format!("{:?} lost {gone} in {text:?}", MODES[index]));
            }
            lost[index] += gone;
            grew[index] += usize::from(now != was);
        }
    }
    eprintln!(
        "{base}: {} texts: bytes lost Private/Open {lost:?}; refusals {refused}; \
         unreadable {unread}; masks changed {grew:?}",
        inputs.len()
    );
    lossy.truncate(40);
    assert_eq!(
        (lost, refused, unread),
        ([0, 0], 0, 0),
        "against {base}:\n{}",
        lossy.join("\n")
    );
}

/// A strict byte superset of origin/main and of 20165ae6, in both modes, with
/// no new refusal.
#[test]
fn the_seeded_differential_loses_no_byte_of_either_base() {
    let inputs = texts();
    for (base, fixture) in [("main 161e0381", MAIN), ("20165ae6", HEALTH)] {
        assert_superset(base, fixture, &inputs);
    }
}

/// Frozen from origin/main (4034659f) on the corpus of [`pairs`].
const PAIRS_MAIN: &str = include_str!("data/nino_glued_pairs_main.txt");

/// The number shapes the two passes read: spaced, compact, hyphenated,
/// slashed, dotted, two and three spaces, mixed spacing, lower case (spaced and
/// slashed), a spaced prefix before compact digits, and mixed hyphen/space.
/// `suffix` is the separator and letter that close a whole number; `None` is
/// the head alone, whose digits end a line. The digits are `12 34 56`, or
/// `65 43 21` for the second number: one value twice would be one token twice,
/// which no reader can place.
fn number(kind: usize, prefix: &str, second: bool, suffix: Option<char>) -> String {
    let (p, s) = if kind == 8 || kind == 9 {
        (
            prefix.to_ascii_lowercase(),
            suffix.map(|c| c.to_ascii_lowercase()),
        )
    } else {
        (prefix.to_string(), suffix)
    };
    let (body, sep) = match kind {
        0 | 8 => ("{p} {a} {b} {c}", " "),
        1 => ("{p}{a}{b}{c}", ""),
        2 => ("{p}-{a}-{b}-{c}", "-"),
        3 | 9 => ("{p}/{a}/{b}/{c}", "/"),
        4 => ("{p}.{a}.{b}.{c}", "."),
        5 => ("{p}  {a}  {b}  {c}", "  "),
        6 => ("{p}   {a}   {b}   {c}", "   "),
        7 => ("{p} {a}  {b} {c}", " "),
        10 => ("{p} {a}{b}{c}", ""),
        _ => ("{p}-{a} {b}-{c}", " "),
    };
    let [a, b, c] = if second {
        ["65", "43", "21"]
    } else {
        ["12", "34", "56"]
    };
    let head = body
        .replace("{p}", &p)
        .replace("{a}", a)
        .replace("{b}", b)
        .replace("{c}", c);
    s.map_or(head.clone(), |letter| format!("{head}{sep}{letter}"))
}

const KINDS: usize = 12;
const PAIR_BREAKS: &[&str] = &["\n", "\r\n", "\t", ""];
const PAIR_PREFIXES: &[&str] = &["CB", "AB", "CE", "JG"];
const LETTERS: [char; 4] = ['A', 'B', 'C', 'D'];

/// The pass A repros of round 1 (F1 and F2): a suffix letter that took the first
/// letter of the next number, and a compact span that hid an older separated
/// one. Each row is the text, then the bytes main masks that must stay masked.
fn repros() -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for br in BREAKS {
        for head in ["AB 12 34 56", "AB-12-34-56", "AB123456", "QQ  12  34  56"] {
            for next in [
                "CB/12/34/56/A",
                "CB  12  34  56  A",
                "CB   12   34   56   A",
                "CB.12.34.56.A",
                "CB 12  34 56 A",
                "cb/12/34/56/a",
                "CE/12/34/56/A",
                "AB/12/34/56/A",
            ] {
                out.push((format!("{head}{br}{next}"), vec![next.to_string()]));
            }
        }
        for (first, glued, keep) in [
            ("AB 12 34 56 AB123456", "cDog walk", "AB 12 34 56 AB123456"),
            ("AB 12 34 56 AB 12 34 56", "cDog", "AB 12 34 56 A"),
            (
                "JG 12 34 56 AB123456",
                "Cblood type A+",
                "JG 12 34 56 AB123456",
            ),
            ("AB 12 34 56 AB123456", "Cat sat", "AB 12 34 56 AB123456"),
            ("AB 12 34 56 AB123456", "cat sat", "AB 12 34 56 AB123456"),
        ] {
            out.push((format!("{first}{br}{glued}"), vec![keep.to_string()]));
        }
    }
    out
}

/// The second differential: two numbers in every pair of shapes across LF,
/// CRLF, tab and glue. A head whose suffix letter A to D is glued to the next
/// number, a head followed straight by the next number (whose first letter the
/// suffix may take), two whole numbers, then a separated number next to a
/// compact or spaced one whose suffix opens a word (FIN-6), and the repros.
fn pairs() -> Vec<String> {
    let mut out = Vec::new();
    for a in 0..KINDS {
        for b in 0..KINDS {
            let prefix = PAIR_PREFIXES[(a + b) % 4];
            let second = number(b, prefix, true, Some(LETTERS[b % 4]));
            for br in PAIR_BREAKS {
                for letter in LETTERS {
                    out.push(format!(
                        "{}{br}{letter}{second}",
                        number(a, "AB", false, None)
                    ));
                }
                out.push(format!("{}{br}{second}", number(a, "AB", false, None)));
                out.push(format!(
                    "{}{br}{second}",
                    number(a, "AB", false, Some(LETTERS[a % 4]))
                ));
            }
        }
    }
    for a in [0, 2, 3, 5, 7, 8] {
        for b in [0, 1, 10] {
            for br in PAIR_BREAKS {
                for letter in ['C', 'c', 'A'] {
                    for tail in ["Dog walk", "blood type A+"] {
                        out.push(format!(
                            "{} {}{br}{letter}{tail}",
                            number(a, "JG", false, Some('A')),
                            number(b, "AB", true, None)
                        ));
                    }
                }
            }
        }
    }
    out.extend(repros().into_iter().map(|(text, _)| text));
    out
}

#[test]
#[ignore = "freezes a base fixture: run on the base only"]
fn freeze_pairs() {
    println!("{}", fixture(&pairs()));
}

/// RED on 56fb66d3 (F1, F2): every number main masks stays masked, in both
/// modes, over the eight line breaks, read with the shared exact reader.
#[test]
fn the_round_one_repros_keep_every_number_masked() {
    let mut bad = Vec::new();
    for (text, keep) in repros() {
        for &mode in &MODES {
            let ranges = match read(mode, &text) {
                None => {
                    bad.push(format!("{mode:?} refused {text:?}"));
                    continue;
                }
                Some(None) => {
                    bad.push(format!("{mode:?} unreadable {text:?}"));
                    continue;
                }
                Some(Some(ranges)) => ranges,
            };
            for value in &keep {
                let at = text.find(value.as_str()).unwrap();
                if !covered(&ranges, at, at + value.len()) {
                    bad.push(format!("{mode:?} {text:?}: {value:?} is in clear"));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}\n{}", bad.len(), bad.join("\n"));
}

/// A strict byte superset of origin/main on every pair of shapes, in both
/// modes, with no new refusal.
#[test]
fn the_pairs_differential_loses_no_byte_of_main() {
    assert_superset("main 4034659f", PAIRS_MAIN, &pairs());
}

/// Release only: glued suffixes through both gates, best of three.
#[test]
#[ignore = "release timing: cargo test --release --test nino_glued_next -- --ignored scales"]
fn glued_dense_multiline_text_scales_linearly() {
    let mut last = 0.0;
    for size in [16_384usize, 65_536, 262_144, 1_048_576] {
        // Four numbers per unit: a suffix glued to a word, one glued to a card,
        // one glued to a slashed number (F1) and one next to a separated number
        // whose suffix opens a word (F2).
        let unit = "QQ  12  34  56\nCblood type A+\nAB 12 34 56\nC4111 1111 1111 1111\n\
                    AB 12 34 56\nCB/65/43/21/A\nJG 12 34 56 AB654321\ncDog walk\n"
            .repeat(size / 120);
        let mut best = f64::MAX;
        for _ in 0..3.min(1 + (262_144 / size)) {
            let start = Instant::now();
            for mode in MODES {
                let _ = masked(mode, &unit);
            }
            best = best.min(start.elapsed().as_secs_f64());
        }
        let ratio = if last == 0.0 { 0.0 } else { best / last };
        eprintln!("{size} bytes: {best:.3}s ratio {ratio:.2}");
        assert!(ratio < 6.0, "{size} bytes scales {ratio:.2}");
        last = best;
    }
}
