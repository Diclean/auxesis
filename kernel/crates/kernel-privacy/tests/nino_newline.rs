//! NINO-NEWLINE-SUFFIX: a UK National Insurance number reads a suffix letter
//! across a line break only when that letter is a letter of its own. FIN-6
//! (#204) folded a run of separators holding a break into one space, then let a
//! number end on the next line's first letter: `QQ  12  34  56\nCB 12 34 56 A…`
//! was read as the number `QQ  12  34  56\nC`, so the whole second line stayed
//! in clear. The cut is now only where it has to be: a suffix glued to a
//! following letter across a break is that word's first letter, so the shape
//! stops at the break and the next line is read from its own first letter. A
//! suffix of its own is no part of the next word and is read across the break,
//! so `AB 12 34 56\nC-blood type A+` masks the `C` and the health label still
//! matches — the narrowing that leaked `A+` on aa9b97ab. Below: the cases and
//! the bytes 2114f9e2 masked in them, a seeded differential against
//! `data/nino_newline_main.txt` (frozen from origin/main) and the release
//! timing. Every value is invented.
//!
//! The ranges come from [`cases::exact_ranges`], the one reader every superset
//! and differential test in this crate uses (TEST-FITS-EXACT,
//! TEST-FITS-EXACT-2). This file's own third copy of it is gone
//! (EXACT-READER-ADOPT), and each part of it had to go:
//!
//! * the Private fallback read a token the gate minted nothing for as `NAME⟧`
//!   bytes at the cursor **without reading the input**, so `card ⟦4111111111111⟧
//!   end` against `card 4111111111111111 end` covered thirteen digits of a card
//!   that sat in the output in clear. The shared reader reads a minted surface,
//!   then a whole detector span, then a piece of one, then the token as literal
//!   text — and only that;
//! * the Open reader placed each marker's end at the one place its following
//!   clear text appeared, and took any marker body, so `[health 4412 removed]`
//!   hid a value by spelling it. The shared reader takes the five fixed markers
//!   `safetext.rs` writes, the one belonging to that range's own class;
//! * neither handled the `⟦⟦` the gate writes for a literal `⟦` of the input,
//!   so an escaped marker text was "no exact reading".
//!
//! `nino_newline_main.txt` is refrozen with the shared reader; the audit of
//! what it gives up is [`the_fixture_claims_only_what_the_detector_reads`].

use std::time::Instant;

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, exact_ranges, issue, masked, MODES};
use kernel_privacy::safetext::Detector;
use kernel_privacy::{EntityKind, Registry, StandardDetector};

const FIXTURE: &str = include_str!("data/nino_newline_main.txt");

/// The regression and its variants: the text, then the bytes masked before
/// FIN-6 in private and in open mode, `|`-separated.
///
/// The `O-` rows are pinned to 20165ae6, which masks the blood type; 2114f9e2
/// leaves it in clear, so pinning to the older base would drop the row.
const REPROS: &[&str] = &[
    "QQ  12  34  56\nCB 12 34 56 A184127645108946|15-43|28-43",
    "QQ  12  34  56\r\nCB 12 34 56 A184127645108946|16-44|29-44",
    "QQ  12  34  56\u{2028}CB 12 34 56 A184127645108946|17-45|30-45",
    "QQ  12  34  56\u{2029}CB 12 34 56 A184127645108946|17-45|30-45",
    "QQ  12  34  56\u{b}CB 12 34 56 A184127645108946|15-43|28-43",
    "QQ  12  34  56\u{c}CB 12 34 56 A184127645108946|15-43|28-43",
    "QQ  12  34  56\u{85}CB 12 34 56 A184127645108946|16-44|29-44",
    "QQ  12  34  56\n  CB 12 34 56 A|17-30|17-30",
    "QQ  12  34  56\nCB 12 34 56 A|15-28|15-28",
    "AB 12 34 56 C\nCE 12 34 56 D|0-13,14-27|0-13,14-27",
    "QQ 12 34 56 C\n4111 1111 1111 1111|0-13,14-33|0-13,14-33",
    // The suffix is a letter of its own on the next line, not the first letter
    // of a following word: it is read across the break, so the label that
    // follows still matches and its value stays masked.
    "AB 12 34 56\nC-blood type A+|0-13,25-27|0-13",
    "AB 12 34 56\nD-blood group AB+|0-13,26-29|0-13",
    "AB 12 34 56\nB-blood type O-|0-13,25-27|0-13",
    "AB 12 34 56\nC|0-13|0-13",
    "AB 12 34 56\r\nC-blood type A+|0-14,26-28|0-14",
    "AB 12 34 56\r\nD-blood group AB+|0-14,27-30|0-14",
    "AB 12 34 56\r\nB-blood type O-|0-14,26-28|0-14",
    "AB 12 34 56\r\nC|0-14|0-14",
    "AB 12 34 56\rC-blood type A+|0-13,25-27|0-13",
    "AB 12 34 56\rD-blood group AB+|0-13,26-29|0-13",
    "AB 12 34 56\rB-blood type O-|0-13,25-27|0-13",
    "AB 12 34 56\rC|0-13|0-13",
    "AB 12 34 56\u{2028}C-blood type A+|0-15,27-29|0-15",
    "AB 12 34 56\u{2028}D-blood group AB+|0-15,28-31|0-15",
    "AB 12 34 56\u{2028}B-blood type O-|0-15,27-29|0-15",
    "AB 12 34 56\u{2028}C|0-15|0-15",
    "AB 12 34 56\u{b}C-blood type A+|0-13,25-27|0-13",
    "AB 12 34 56\u{b}D-blood group AB+|0-13,26-29|0-13",
    "AB 12 34 56\u{b}B-blood type O-|0-13,25-27|0-13",
    "AB 12 34 56\u{b}C|0-13|0-13",
    "AB 12 34 56\u{c}C-blood type A+|0-13,25-27|0-13",
    "AB 12 34 56\u{c}D-blood group AB+|0-13,26-29|0-13",
    "AB 12 34 56\u{c}B-blood type O-|0-13,25-27|0-13",
    "AB 12 34 56\u{c}C|0-13|0-13",
    "AB 12 34 56\u{85}C-blood type A+|0-14,26-28|0-14",
    "AB 12 34 56\u{85}D-blood group AB+|0-14,27-30|0-14",
    "AB 12 34 56\u{85}B-blood type O-|0-14,26-28|0-14",
    "AB 12 34 56\u{85}C|0-14|0-14",
    "AB 12 34 56\u{2029}C-blood type A+|0-15,27-29|0-15",
    "AB 12 34 56\u{2029}D-blood group AB+|0-15,28-31|0-15",
    "AB 12 34 56\u{2029}B-blood type O-|0-15,27-29|0-15",
    "AB 12 34 56\u{2029}C|0-15|0-15",
];

/// Every value a case carries: private must hide all of them. The blood types
/// are the values behind the labels; the lone `C` is checked by the span in
/// [`a_suffix_letter_of_its_own_is_read_across_a_break`], since a bare `C`
/// would match a letter anywhere.
const HIDDEN: &str = "CB 12 34 56 A|184127645108946|AB 12 34 56 C|CE 12 34 56 D|\
     QQ 12 34 56 C|4111 1111 1111 1111|QQ  12  34  56|A+|AB+|O-";

/// The seven line breaks the normaliser folds into one separator, CRLF among
/// them (VT, FF, NEL, U+2028, U+2029, CR, LF).
const SUFFIX_BREAKS: &[&str] = &[
    "\n", "\r\n", "\r", "\u{b}", "\u{c}", "\u{85}", "\u{2028}", "\u{2029}",
];

/// No National Insurance span holds a word's first letter across a break, no
/// byte masked before FIN-6 is clear again, and every value is masked in
/// private. A span may cross a break: only a suffix glued to a following letter
/// may not (NINO-NEWLINE-SUFFIX).
#[test]
fn a_nino_suffix_never_crosses_a_line_break() {
    let break_is = |c: char| {
        matches!(
            c,
            '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        )
    };
    let mut bad = Vec::new();
    for case in REPROS {
        let mut fields = case.split('|');
        let text = fields.next().unwrap();
        let spans = Registry::new().analyze(text);
        for span in spans.iter().filter(|s| s.kind == EntityKind::UkNino) {
            let value = &text[span.start..span.end];
            let tail = value.rsplit_once(break_is).map_or("", |(_, t)| t);
            if glued_letters(tail.as_bytes()) && !whole_number(tail) {
                bad.push(format!(
                    "{text:?}: {value:?} reads a suffix glued across a break"
                ));
            }
        }
        let private = masked(MODES[0], text).unwrap_or_default();
        for value in HIDDEN.split('|').filter(|v| text.contains(v)) {
            let at = text.find(value).unwrap();
            if !covered(&private, at, at + value.len()) {
                bad.push(format!("{text:?}: {value} is in clear"));
            }
        }
        for (mode, was) in MODES.into_iter().zip(fields) {
            let now = masked(mode, text).unwrap_or_default();
            for (start, end) in parse(was).unwrap() {
                if !covered(&now, start, end) {
                    bad.push(format!("{text:?} {mode:?}: {start}-{end} is in clear"));
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}\n{}", bad.len(), bad.join("\n"));
}

/// Whether the tail after the break is a whole National Insurance number and
/// not a word: the number before it reads the next line's number with itself
/// where that number's own suffix is glued to a value (NINO-CHAIN r1).
fn whole_number(tail: &str) -> bool {
    let bare: Vec<u8> = tail
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'-' | b'/' | b'.'))
        .collect();
    bare.len() == 9
        && bare[..2].iter().all(u8::is_ascii_alphabetic)
        && bare[2..8].iter().all(u8::is_ascii_digit)
        && matches!(bare[8], b'A'..=b'D' | b'a'..=b'd')
}

/// Whether `tail`, the bytes of a span after its last line break, open with a
/// letter glued to a following letter. One letter of its own is not a word.
fn glued_letters(tail: &[u8]) -> bool {
    tail.first().is_some_and(u8::is_ascii_alphabetic)
        && tail.get(1).is_some_and(u8::is_ascii_alphabetic)
}

/// A suffix letter that is a letter of its own is read across the break, so the
/// next line is read whole, its health label still matches and the value behind
/// it stays masked, as on main 20165ae6 and 2114f9e2.
///
/// RED on aa9b97ab, which cut at every break: the suffix stayed in clear glued
/// to the next word, `blood type` was no longer a word, and `A+`, `AB+` and
/// `O-` came out in clear. Open keeps a health value by design, so the value is
/// required in private only; both modes are required to read back exactly.
#[test]
fn a_suffix_letter_of_its_own_is_read_across_a_break() {
    // (the suffix letter, the next line, the value behind its label)
    let forms = [
        ('C', "C-blood type A+", "A+"),
        ('D', "D-blood group AB+", "AB+"),
        ('B', "B-blood type O-", "O-"),
        ('C', "C", "C"),
    ];
    let mut bad = Vec::new();
    for break_is in SUFFIX_BREAKS {
        for (suffix, line, hidden) in forms {
            let text = format!("AB 12 34 56{break_is}{line}");
            let number = format!("AB 12 34 56{break_is}{suffix}");
            let spans = Registry::new().analyze(&text);
            match spans.iter().find(|s| s.kind == EntityKind::UkNino) {
                None => bad.push(format!("{text:?}: no number is masked")),
                Some(span) => {
                    let masked = &text[span.start..span.end];
                    if masked != number {
                        bad.push(format!("{text:?}: {masked:?} is masked, not {number:?}"));
                    }
                }
            }
            for &mode in &MODES {
                let (output, minted) =
                    issue(mode, &text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
                let Some(ranges) = exact_ranges(mode, &text, &output, &minted) else {
                    bad.push(format!(
                        "{mode:?} {text:?} -> {output:?} does not read back"
                    ));
                    continue;
                };
                // Private only: open leaves a health value in clear by design.
                if mode == MODES[0] {
                    let at = text.find(hidden).unwrap();
                    if !covered(&ranges, at, at + hidden.len()) {
                        bad.push(format!("{mode:?} {text:?}: {hidden} is in clear"));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}\n{}", bad.len(), bad.join("\n"));
}

/// The FIN-6 repro over every break the suffix may cross: private masks the
/// whole text. The first pass masks `QQ  12  34  56{break}`, the residue round
/// then unglues the suffix and masks `CB 12 34 56 A` beside it.
#[test]
fn the_fin6_repro_stays_fully_masked_in_private() {
    let mut bad = Vec::new();
    for break_is in SUFFIX_BREAKS {
        let text = format!("QQ  12  34  56{break_is}CB 12 34 56 A184127645108946");
        let (output, minted) = issue(MODES[0], &text).expect("private must not refuse");
        let Some(ranges) = exact_ranges(MODES[0], &text, &output, &minted) else {
            bad.push(format!("{text:?} -> {output:?} does not read back"));
            continue;
        };
        if !covered(&ranges, 0, text.len()) {
            let clear: String = (0..text.len())
                .filter(|byte| !covered(&ranges, *byte, byte + 1))
                .map(|byte| text.as_bytes()[byte] as char)
                .collect();
            bad.push(format!("{text:?}: {clear:?} is in clear"));
        }
    }
    assert!(bad.is_empty(), "{}\n{}", bad.len(), bad.join("\n"));
}

/// `|`-separated lists, so every table of the corpus is one line.
const BREAKS: &str = "\n|\r\n|\u{2028}|\u{2029}|\n  |\r\n\t";
const LABELS: &str = "NI number|NINO|card|SSN|NIR|Account|Total due|";
const PROSE: &str = "Dear customer,|thank you for your payment.|see attached.|42.00|";
const ITEMS: &str = "AB 12 34 56 C|AB123456C|QQ  12  34  56  A|PN/48/15/16/C|ce 12 34 56 d|\
     AB 12 34 56C|QQ123456C|4111 1111 1111 1111|4539  1488  0343  6467|\
     4539-1488-0343-6467|512-45-8873|512/45/8873|512  45  8873|\
     1 84 12 76 451 089 46|184127645108946|42.00|";

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

/// The seeded corpus: 1,024 documents of one to five lines of National Insurance
/// numbers, cards, social security and NIR numbers with prose, joined by every
/// break the normaliser folds. A value sits whole on its line or is wrapped
/// between two digit pairs; one whose digits end a line is left out, since the
/// byte FIN-6 masked there is the suffix letter that starts the next one.
fn texts() -> Vec<String> {
    let mut rng = Rng(0x4e49_4e4f_5f10_2626);
    let mut out = Vec::new();
    for _ in 0..1_024 {
        let mut doc = Vec::new();
        for _ in 0..1 + rng.next() % 5 {
            doc.push(match rng.next() % 4 {
                0 => rng.pick(PROSE).to_string(),
                1 => format!("{} {}", rng.pick(LABELS), rng.pick(ITEMS)),
                2 => format!("{} {}", rng.pick(ITEMS), rng.pick(ITEMS)),
                _ => {
                    let value = rng.pick(ITEMS);
                    let at = value.find(' ').unwrap_or(value.len());
                    format!("{} {} {}", &value[..at], rng.pick(BREAKS), &value[at..])
                }
            });
        }
        out.push(doc.join(rng.pick(BREAKS)));
    }
    out
}

/// The `start-end` ranges of one masked text as a record, and back; `!` is no.
fn record(ranges: &Option<Vec<(usize, usize)>>) -> String {
    let join = |r: Vec<(usize, usize)>| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.clone().map_or("!".into(), join)
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

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let each = |text: &String| MODES.map(|mode| record(&masked(mode, text))).join("|");
    let inputs = texts();
    let lines: Vec<String> = inputs
        .chunks(128)
        .map(|chunk| chunk.iter().map(each).collect::<Vec<_>>().join(";") + ";")
        .collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// A strict byte superset of main in both modes, with no new refusal.
#[test]
fn the_seeded_differential_loses_no_byte_of_main() {
    let inputs = texts();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut grew) = ([0usize; 2], 0, [0usize; 2]);
    for (text, record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let now = masked(MODES[index], text);
            if now.is_none() && main.is_some() {
                refused += 1;
            }
            let (Some(now), Some(main)) = (now, main) else {
                continue;
            };
            lost[index] += main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            grew[index] += usize::from(now != main);
        }
    }
    eprintln!(
        "{} texts: bytes lost Private/Open {lost:?}; refusals {refused}; masks changed {grew:?}",
        inputs.len()
    );
    assert_eq!((lost, refused), ([0, 0], 0));
}

/// The audit of the refreeze (EXACT-READER-ADOPT), as a property of the frozen
/// fixture so it holds for whoever reads it next and not only for this freeze:
/// **every byte the baseline claims is a byte the detector reads** — in its own
/// reading view or in its residue view, the two the gate reads. A baseline can
/// then only ever claim less than the gate hides, never a byte it leaves in
/// clear.
///
/// The audit of the bytes the previous baseline gave up, record by record in
/// both modes: 954 dropped and 954 gained (480 Private, 474 Open each way).
/// 948 of the dropped bytes are a blank or a folded line break sitting between
/// two masks; 6 are the context label `SSN`, three bytes in each mode, which
/// the detector cued on and did not mask. **No byte of a value is given up.**
#[test]
fn the_fixture_claims_only_what_the_detector_reads() {
    let inputs = texts();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let mut bad = Vec::new();
    for (text, record) in inputs.iter().zip(records) {
        let detector = StandardDetector::new();
        let read = detector.detect(text).unwrap_or_default();
        let residue = detector.residue(text).unwrap_or_default();
        let read = |b: usize| read.iter().any(|span| span.start <= b && b < span.end);
        let residue = |b: usize| residue.iter().any(|span| span.start <= b && b < span.end);
        for (index, main) in record.split('|').filter_map(parse).enumerate() {
            for (start, end) in main {
                for b in start..end {
                    if !read(b) && !residue(b) {
                        bad.push(format!(
                            "{:?} {text:?} byte {b} = {:?} is claimed but no span reads it",
                            MODES[index],
                            text[b..].chars().next().unwrap_or('?')
                        ));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}\n{}", bad.len(), bad.join("\n"));
}

/// Release only: numbers on consecutive lines through both gates, best of three.
#[test]
#[ignore = "release timing: cargo test --release --test nino_newline -- --ignored scales"]
fn nino_dense_multiline_text_scales_linearly() {
    let mut last = 0.0;
    for size in [16_384usize, 65_536, 262_144, 1_048_576] {
        let unit = "QQ 12 34 56 A\nCE 12 34 56 B\n".repeat(size / 2);
        let mut best = f64::MAX;
        for _ in 0..3.min(1 + (262_144 / size)) {
            let start = Instant::now();
            for mode in MODES {
                let _ = masked(mode, &unit);
            }
            best = best.min(start.elapsed().as_secs_f64());
        }
        let ratio = if last == 0.0 { 0.0 } else { best / last };
        eprintln!("{size} lines: {best:.3}s ratio {ratio:.2}");
        assert!(ratio < 6.0, "{size} lines scales {ratio:.2}");
        last = best;
    }
}
