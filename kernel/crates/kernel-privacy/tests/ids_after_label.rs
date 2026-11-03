//! ID-LABEL-1 acceptance: the IDs main still leaves in clear in both modes — a
//! licence number after `licence number`/`licence no.`/`Nr`/`n°`, and four UK
//! National Insurance spellings (lower case with a glued suffix, zero-width
//! separators, doubled separators, Cyrillic or Greek look-alike capitals with
//! trailing punctuation). The work order's other repros (CNI, permis, DE, CN
//! passport, tax ID, file names) are hidden on main already and stay here as
//! regression guards.
//!
//! Lookalikes, traps and the in-repo prose keep exactly main's masks, and the
//! head is a strict byte superset of main on a seeded differential frozen from
//! origin/main in `data/ids_after_label_main.txt` (`-- --ignored freeze
//! --nocapture`, on main only). Every value is invented, most built at run
//! time by the seeded generator below.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
#[allow(dead_code)]
mod cases {
    include!("data/id_label_2_cases.rs");
}
use cases::{round1_text, seeded_text, ROUND1_TEXTS, SEED, SEEDED_TEXTS};
use norm1::{covered, issue, masked, CYRILLIC_PROSE, MODES, ZH_PROSE};

/// Masked byte ranges, `start..end`.
type Ranges = Vec<(usize, usize)>;

const FIXTURE: &str = include_str!("data/ids_after_label_main.txt");

/// The work order's repros, `(text, value)`, plus near variants.
const REPROS: &[(&str, &str)] = &[
    // Still in clear on main.
    ("pn 48 15 16 cok", "pn 48 15 16 c"),
    (
        "PN\u{200b}48\u{200b}15\u{200b}16\u{200b}Cok",
        "PN\u{200b}48\u{200b}15\u{200b}16\u{200b}C",
    ),
    ("PN..48..15..16..C", "PN..48..15..16..C"),
    ("РΝ 48 15 16 С).", "РΝ 48 15 16 С"),
    ("NI: pn 48 15 16 cok", "pn 48 15 16 c"),
    (
        "pn\u{200b}48\u{200b}15\u{200b}16\u{200b}cok",
        "pn\u{200b}48\u{200b}15\u{200b}16\u{200b}c",
    ),
    ("PN--48--15--16--C", "PN--48--15--16--C"),
    ("РΝ 48 15 16 С", "РΝ 48 15 16 С"),
    ("licence number 12AB34567", "12AB34567"),
    ("Licence No. 12AB34567", "12AB34567"),
    ("licence no: 12AB34567", "12AB34567"),
    ("license no 12AB34567", "12AB34567"),
    ("Licence Nr 12AB34567", "12AB34567"),
    ("licence n° 12AB34567", "12AB34567"),
    ("License Number: 12AB34567", "12AB34567"),
    // Hidden on main: regression guards.
    ("CNI : 123456789012", "123456789012"),
    ("Carte nationale d'identité : AB12CD34E", "AB12CD34E"),
    ("Permis de conduire : 12AB34567", "12AB34567"),
    ("Driving licence: MORGA753116SM9IJ", "MORGA753116SM9IJ"),
    ("Personalausweis Nr L01X00T47", "L01X00T47"),
    ("passport EA0000125", "EA0000125"),
    ("护照 EA0000125", "EA0000125"),
    ("Tax ID: 12AB34567", "12AB34567"),
    ("passport_12AB34567.pdf", "12AB34567"),
    ("cni_123456789012.pdf", "123456789012"),
    ("id_card_X4RTBT9M2.pdf", "X4RTBT9M2"),
    ("permis_12AB34567.pdf", "12AB34567"),
    ("ID card: X4RTBT9M2", "X4RTBT9M2"),
    ("identity card no X4RTBT9M2", "X4RTBT9M2"),
    ("passport no 20AB71234", "20AB71234"),
    ("Reisepass Nr. C01X00T47", "C01X00T47"),
    ("CNI n°123456789012", "123456789012"),
];

/// Lines that keep exactly main's masks in both modes.
const LOOKALIKES: &[&str] = &[
    "Order ID 55210931",
    "Version 12AB34567",
    "Order ID: 55210931 shipped",
    "Version 12AB34567 is out",
    "licence: 2024-10-01",
    "licence fee of 159 pounds",
    "licence number is on file",
    "the licence number field is empty",
    "licence nobody 12345",
    "licence notes 12AB34567",
    "MIT license, version 2.0",
    "license number of seats: 25",
    // Lower case with a glued suffix after a common short word: prose.
    "at 10 20 30 cats",
    "on 12 13 14 december",
    "be 10 11 12 able",
    "to 10 20 30 dogs",
    "an 11 22 33 average",
    // Dotted or dashed lower case glued: a host or a path.
    "ab.12.34.56.com",
    "ab-12-34-56-cd",
    "pn/48/15/16/cok",
    "PN//48//15//16//C",
    "PN/48.15/16/C",
    // Shapes that are no number.
    "pn481516cok",
    "PN 48 15 16 C7",
    "XPN 48 15 16 C",
    "7PN 48 15 16 C",
    "PN 48 15 16 E",
    "PN....48....15....16....C",
    "PN 48 15 16",
    "QD 48 15 16 C",
    // Look-alike letters in lower case, and Cyrillic and Greek words.
    "рn 48 15 16 с",
    "на 12 34 56 в",
    "Это 12 34 56 в доме",
    "και 12 34 56 βαθμοί",
];

/// Two-letter words a lower-case number glued to a word is read as prose after.
const SHORT_WORDS: &str = "AH AL AM AN AS AT AX AY BE BY CE EH EL EM EN ER ES ET EX HA HE HM JE \
    LA LE LO MA ME MY NE OH OK ON OR OW PA SA SE SO TA TE WE YA YE YO";
/// The NI prefixes the generator draws: issuable pairs that are no common word.
const LETTERS: &[u8] = b"ABCEGHJKLMNPRSTWXYZ";
/// Cyrillic and Greek capitals that look like a Latin capital.
const GLYPHS: &[(char, &[char])] = &[
    ('A', &['\u{0410}', '\u{0391}']),
    ('B', &['\u{0412}', '\u{0392}']),
    ('C', &['\u{0421}']),
    ('E', &['\u{0415}', '\u{0395}']),
    ('H', &['\u{041D}', '\u{0397}']),
    ('K', &['\u{041A}', '\u{039A}']),
    ('M', &['\u{041C}', '\u{039C}']),
    ('N', &['\u{039D}']),
    ('P', &['\u{0420}', '\u{03A1}']),
    ('T', &['\u{0422}', '\u{03A4}']),
    ('X', &['\u{0425}', '\u{03A7}']),
    ('Y', &['\u{03A5}']),
    ('Z', &['\u{0396}']),
];
const ZERO_WIDTH: &[char] = &['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'];
const NI_FRAMES: &[&str] = &[
    "{}",
    "NI number: {}",
    "my NI is {}.",
    "({})",
    "ref {} ok",
    "NI {}, thanks",
    "Name: Jo Pell\nNI: {}\n",
];
const GLUED: &[&str] = &["ok", "ay", "on", "ould", "xyz"];
const LICENCE_FRAMES: &[&str] = &[
    "licence number {}",
    "license number {}",
    "Licence No. {}",
    "license no: {}",
    "Licence Nr {}",
    "licence nr. {}",
    "licence n° {}",
    "License Number: {}",
    "his licence number is {}",
    "licence n°{}",
];

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn digits(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'0' + self.below(10) as u8))
            .collect()
    }
}

/// An issuable prefix that is no two-letter word.
fn prefix(rng: &mut Rng) -> [u8; 2] {
    loop {
        let pair = [rng.pick(LETTERS), rng.pick(LETTERS)];
        let refused = matches!(&pair, b"BG" | b"GB" | b"NK" | b"KN" | b"TN" | b"NT" | b"ZZ")
            || pair[1] == b'O';
        let word = SHORT_WORDS.split(' ').any(|w| w.as_bytes() == pair);
        if !refused && !word {
            return pair;
        }
    }
}

/// One NI number in one of the four new spellings: `(number)`.
fn ni_variant(rng: &mut Rng) -> String {
    let [first, second] = prefix(rng);
    let pairs = [rng.digits(2), rng.digits(2), rng.digits(2)];
    let suffix = b"ABCD"[rng.below(4)];
    let letters = [first, second, suffix].map(char::from);
    let join = |sep: &str, l: [char; 3]| {
        format!(
            "{}{}{sep}{}{sep}{}{sep}{}{sep}{}",
            l[0], l[1], pairs[0], pairs[1], pairs[2], l[2]
        )
    };
    match rng.below(4) {
        0 => join(" ", letters.map(|c| c.to_ascii_lowercase())),
        1 => {
            let zw = rng.pick(ZERO_WIDTH).to_string();
            let lower = rng.below(2) == 0;
            join(
                &zw,
                letters.map(|c| if lower { c.to_ascii_lowercase() } else { c }),
            )
        }
        2 => join(rng.pick(&["..", "--", "...", "  ", ". ", "- "]), letters),
        _ => {
            let mut glyphs = letters;
            for letter in &mut glyphs {
                if let Some((_, forms)) = GLYPHS.iter().find(|(l, _)| l == letter) {
                    if rng.below(3) > 0 {
                        *letter = rng.pick(forms);
                    }
                }
            }
            join(" ", glyphs)
        }
    }
}

/// A licence number value: 8–12 capitals and digits, 2+ digits.
fn licence_value(rng: &mut Rng) -> String {
    let len = 8 + rng.below(5);
    let mut value: String = (0..len)
        .map(|_| match rng.below(3) {
            0 => char::from(b'A' + rng.below(26) as u8),
            _ => char::from(b'0' + rng.below(10) as u8),
        })
        .collect();
    value.replace_range(0..2, &rng.digits(2));
    value
}

/// Every positive: `(text, value)`.
fn positives() -> Vec<(String, String)> {
    let mut rng = Rng(SEED ^ 0x1D1A_BE11);
    let mut out: Vec<(String, String)> = REPROS
        .iter()
        .map(|&(t, v)| (t.to_string(), v.to_string()))
        .collect();
    for _ in 0..240 {
        let value = ni_variant(&mut rng);
        let lower = value.chars().last().is_some_and(char::is_lowercase);
        let tail = if lower || rng.below(2) == 0 {
            rng.pick(GLUED)
        } else {
            rng.pick(&[").", ".", ",", ""])
        };
        let frame = rng.pick(NI_FRAMES);
        out.push((frame.replace("{}", &format!("{value}{tail}")), value));
    }
    for _ in 0..60 {
        let value = licence_value(&mut rng);
        out.push((rng.pick(LICENCE_FRAMES).replace("{}", &value), value));
    }
    out
}

/// Every positive hidden in both modes, and Private restores the text exactly.
#[test]
fn ids_after_a_label_are_hidden_in_both_modes() {
    let wrong = wrong_in_both_modes(positives());
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Seal A round 1 (outside the frozen differential's inputs, so the fixture
/// stays main's): a line break inside `licence number`, a business word in the
/// field before, a value shaped like an impossible date, and an NI number after
/// its explicit label in mixed case or after a short word, suffix glued.
const SEAL_A_REPROS: &[(&str, &str)] = &[
    ("licence\nnumber: 72BD41385", "72BD41385"),
    ("licence\r\nnumber: 72BD41385", "72BD41385"),
    ("Purpose: business\nLicence number: 72BD41385", "72BD41385"),
    ("Purpose: business; Licence number: 72BD41385", "72BD41385"),
    ("It is for business. Licence number: 72BD41385", "72BD41385"),
    ("Licence number: 99-99-99", "99-99-99"),
    ("Licence number: 12-34-56", "12-34-56"),
    ("licence no 31/13/2024", "31/13/2024"),
    ("Licence number: 2024-13-01", "2024-13-01"),
    ("NI number: at 12 34 56 cok", "at 12 34 56 c"),
    ("NI number: Rn 18 35 46 bok", "Rn 18 35 46 b"),
    (
        "National Insurance number: aT 12 34 56 Cat",
        "aT 12 34 56 C",
    ),
    ("NINO: on 12 34 56 dog", "on 12 34 56 d"),
];

/// Each seal A repro hidden in both modes.
#[test]
fn seal_a_repros_are_hidden_in_both_modes() {
    let cases = SEAL_A_REPROS
        .iter()
        .map(|&(t, v)| (t.to_string(), v.to_string()));
    let wrong = wrong_in_both_modes(cases.collect());
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The positives not hidden in a mode, or not restored exactly by Private.
fn wrong_in_both_modes(cases: Vec<(String, String)>) -> Vec<String> {
    let mut wrong = Vec::new();
    for (text, value) in cases {
        let start = text.find(value.as_str()).expect("the value is in its text");
        for mode in MODES {
            let Some((output, minted)) = issue(mode, &text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            let ranges = masked(mode, &text).expect("issued once already");
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
    wrong
}

/// The in-repo prose and the CN and Cyrillic prose lines: trap lines.
fn prose() -> Vec<String> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval/prose");
    let mut files: Vec<_> = std::fs::read_dir(root)
        .expect("privacy-eval prose is readable")
        .map(|entry| entry.expect("entry").path())
        .collect();
    files.sort();
    let mut out: Vec<String> = files
        .iter()
        .flat_map(|file| {
            let raw = std::fs::read_to_string(file).expect("readable");
            raw.lines()
                .filter(|l| !l.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    out.extend(ZH_PROSE.iter().chain(CYRILLIC_PROSE).map(|l| l.to_string()));
    out
}

/// The differential inputs: the ID-LABEL-2 seeded and round-1 texts, the
/// positives, the lookalikes, the prose lines and the in-repo privacy-eval
/// cases.
fn inputs() -> Vec<(String, Ranges)> {
    let mut rng = cases::Rng(SEED ^ 0x2ED1_AB2E);
    let mut out: Vec<_> = (0..SEEDED_TEXTS).map(|_| seeded_text(&mut rng)).collect();
    let mut round1 = cases::Rng(SEED ^ 0x0F1_F1F1_0001);
    out.extend((0..ROUND1_TEXTS).map(|_| round1_text(&mut round1)));
    out.extend(positives().into_iter().map(|(t, v)| {
        let start = t.find(&v).expect("value");
        (t.clone(), vec![(start, start + v.len())])
    }));
    out.extend(LOOKALIKES.iter().map(|&t| (t.to_string(), Vec::new())));
    out.extend(prose().into_iter().map(|t| (t, Vec::new())));
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval/cases");
    let mut files: Vec<_> = std::fs::read_dir(root)
        .expect("privacy-eval cases are readable")
        .map(|entry| entry.expect("entry").path())
        .collect();
    files.sort();
    for file in files {
        let raw = std::fs::read_to_string(file).expect("readable");
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            let case: serde_json::Value = serde_json::from_str(line).expect("JSON");
            out.push((case["text"].as_str().expect("text").to_string(), Vec::new()));
        }
    }
    out
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

/// Lookalikes, traps and prose lines: in both modes the exact masks equal
/// main's — no new mask, none lost, no refusal.
#[test]
fn lookalikes_and_prose_keep_main_masks() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let traps: Vec<String> = LOOKALIKES
        .iter()
        .map(|l| l.to_string())
        .chain(prose())
        .collect();
    let mut wrong = Vec::new();
    for ((text, _), main) in inputs.iter().zip(&main) {
        if !traps.contains(text) {
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
    assert!(traps.len() >= 60, "60+ trap lines");
    assert!(
        wrong.is_empty(),
        "{} changed:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A strict byte superset of main in both modes and no new refusal, with no
/// allowance; and every value hidden in both modes.
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
                eprintln!("missed {:?} in {text:?} -> {now:?}", MODES[index]);
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; texts with \
         new masks Private/Open {gained:?}; values missed {missed}",
        inputs.len()
    );
    assert!(inputs.len() >= 1600 + 600 + 300);
    assert_eq!((lost, refused, missed), ([0, 0], 0, 0));
}

/// Release only: dense NI and licence text at 16 KiB, 64 KiB, 256 KiB and
/// 1 MiB. Bar: each 4x step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test ids_after_label -- --ignored timing"]
fn timing_scales_linearly() {
    let mut unit = String::new();
    unit.push_str("pn 48 15 16 cok, PN\u{200b}48\u{200b}15\u{200b}16\u{200b}Cok; ");
    unit.push_str("PN..48..15..16..C РΝ 48 15 16 С). licence number 12AB34567, ");
    unit.push_str("Licence No. 12AB34567 at 10 20 30 cats ab.12.34.56.com PN 48 15 ");
    unit.push_str("licence: 2024-10-01 Order ID 55210931 Version 12AB34567\r\n");
    let unit = unit.as_str();
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
    eprintln!("ids after label: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
