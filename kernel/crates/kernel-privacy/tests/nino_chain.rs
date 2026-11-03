//! NINO-CHAIN: every number of a chain of National Insurance numbers stays
//! masked, in both modes.
//!
//! Three leaks on main 041c9c46, one root cause: a suffix letter A to D that
//! also opens the *next* number belongs to both, and each pass gave it to one
//! side only, then never looked back:
//!
//! ```text
//! AB 12 34 56\ncb123456a                  ->  AB 12 34 56\n⟦UK_NINO⟧
//! XY 12 34 56 AB 12 34 56 AB 12 34 56 C   ->  ⟦UK_NINO⟧B 12 34 56 ⟦UK_NINO⟧
//! AB 12 34 56\nBAB123456B                 ->  ⟦UK_NINO⟧AB123456B
//! ```
//!
//! * `nino_at` refused a number whose suffix letter opens another one, and the
//!   FIN-6 cut that should take over needs capitals: the head stayed in clear;
//! * the separated pass kept the letter on one line and went on past it: the
//!   middle number of a chain stayed in clear;
//! * a number that starts one letter *behind* the suffix letter is preceded by
//!   a letter, so the start rule never tried it.
//!
//! Now both passes keep the letter and read the next number from it as well;
//! the overlapping spans become one.
//!
//! Below: the three rows over every shape and break, chains of two to five
//! numbers in every shape combination, a seeded 1,800-document differential of
//! NI chains mixed with the other classes, a prose set that must not gain a
//! mask, and the release timing. Every range is read with the one shared reader
//! `tests/data/exact_mask.rs` (TEST-FITS-EXACT-2) — never `fits()`, never
//! `norm1::ranges`. Every number is built at run time from its own index, so no
//! two numbers in a text are the same value: one value twice is one token twice,
//! which the reader cannot place. Every value is invented.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, exact_ranges, issue, masked, MODES};

/// The line breaks and the glue the normaliser folds into one separator: LF,
/// CRLF, CR, tab, VT, NEL, U+2028, U+2029, a plain space, a break with an
/// indent, and no separator at all (two numbers written together). Glue is
/// last, so [`break_for`] can drop it by length alone.
const BREAKS: &[&str] = &[
    "\n", "\r\n", "\r", "\t", "\u{b}", "\u{85}", "\u{2028}", " ", "\n  ", "\r\n\t", "",
];

/// How many shapes of number this file builds, and the digits each one is built
/// from. A chain gives every number its own triple, so no two of them are the
/// same value.
const PAIRS: [[&str; 3]; 8] = [
    ["12", "34", "56"],
    ["65", "43", "21"],
    ["87", "16", "49"],
    ["23", "58", "90"],
    ["41", "72", "06"],
    ["95", "38", "14"],
    ["60", "29", "83"],
    ["74", "51", "36"],
];

/// The twelve shapes a number may take: compact, spaced, one to three spaces,
/// `-`, `/`, `.`, mixed spacing, a spaced prefix before compact digits, mixed
/// hyphen and space, and the lower-case form of spaced and slashed. Kind 7
/// (`{p} {a}  {b} {c}`) is the one shape neither pass reads, kept so a chain
/// that holds it asks for the same mask as one that does not.
const KINDS: usize = 12;

/// Every shape except the seventh, which no pass reads: three of its four
/// boundaries hold one separator and one holds two, and each pass wants one
/// separator count throughout. A chain that holds one is a near miss, so it is
/// generated as a neighbour and is never asked to mask.
const SHAPES: [usize; 11] = [0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11];

/// The one shape that is not a number when it is written straight onto a
/// letter: the lower-case separated one. FIN-6 ([`separated_nino_at`]) asks for
/// capitals where a letter touches a separated number, so no pass reads
/// `refab/65/43/21/b` on any base — there it is a near miss, not a leak, and a
/// chain that glues one must not be asked to mask it.
const GLUE_SAFE: [bool; KINDS] = [
    true, true, true, true, true, true, true, false, true, false, true, true,
];

/// The shapes only the separated pass reads. They need something that is not a
/// digit in front of them, which a number with a suffix letter of its own gives
/// them and a bare head does not.
const SEPARATED: [bool; KINDS] = [
    false, false, false, true, true, true, true, true, false, true, false, false,
];

/// The breaks a chain of these shapes may use: every one, glue included, where
/// the chain can carry glue (see [`GLUE_SAFE`], [`SEPARATED`] and `bare_head`),
/// and every one but the glue otherwise. Glue is last in [`BREAKS`], so a
/// prefix of the list is the same list without it.
fn breaks_for(kinds: &[usize], bare_head: bool) -> &'static [&'static str] {
    let carries = kinds.iter().all(|kind| GLUE_SAFE[*kind])
        && !(bare_head && kinds.iter().any(|kind| SEPARATED[*kind]));
    if carries {
        BREAKS
    } else {
        &BREAKS[..BREAKS.len() - 1]
    }
}

/// The prefix letters, all of them ones HMRC can issue.
const PREFIXES: [&str; 6] = ["AB", "CB", "CE", "JG", "PN", "XY"];

/// Heads that stand on their digits (shape, prefix): the letter behind one is
/// its suffix, so it needs a separator there and cannot carry glue at all.
const BARE_HEADS: [(usize, &str); 6] = [
    (0, "AB"),
    (5, "AB"),
    (2, "AB"),
    (1, "AB"),
    (5, "QQ"),
    (10, "AB"),
];

/// Heads that close with a suffix letter `C` of their own (shape, prefix), so a
/// letter glued behind them lands on that letter.
const WHOLE_HEADS: [(usize, &str); 6] = [
    (1, "AB"),
    (0, "AB"),
    (2, "AB"),
    (5, "QQ"),
    (3, "PN"),
    (4, "AB"),
];

/// The shapes a head with no suffix letter of its own may take: the ones the
/// compact pass reads, because the letter that follows such a head is its
/// suffix and has to sit behind a separator that pass accepts. A separated head
/// would need its own `/`, `.` or second space there instead.
const HEADS: [usize; 6] = [0, 1, 2, 8, 10, 11];

/// The prefixes of a chain that holds a head with no suffix letter: the letter
/// behind that head is its suffix, so the next number must open with A to D.
const HEAD_PREFIXES: [&str; 3] = ["AB", "CB", "CE"];

/// The suffix letters, A to D.
const LETTERS: [char; 4] = ['A', 'B', 'C', 'D'];

/// One number in shape `kind`, with the digits of `triple` and the suffix
/// `suffix` (no letter is a head whose digits end a line). Built from the index
/// every time, never written out as a literal.
fn number(kind: usize, prefix: &str, triple: usize, suffix: Option<char>) -> String {
    let (p, s) = match kind {
        8 | 9 => (
            prefix.to_ascii_lowercase(),
            suffix.map(|letter| letter.to_ascii_lowercase()),
        ),
        _ => (prefix.to_string(), suffix),
    };
    let [a, b, c] = PAIRS[triple % PAIRS.len()];
    let body = match kind {
        0 | 8 => format!("{p} {a} {b} {c}"),
        1 => format!("{p}{a}{b}{c}"),
        2 => format!("{p}-{a}-{b}-{c}"),
        3 | 9 => format!("{p}/{a}/{b}/{c}"),
        4 => format!("{p}.{a}.{b}.{c}"),
        5 => format!("{p}  {a}  {b}  {c}"),
        6 => format!("{p}   {a}   {b}   {c}"),
        7 => format!("{p} {a}  {b} {c}"),
        10 => format!("{p} {a}{b}{c}"),
        _ => format!("{p}-{a} {b}-{c}"),
    };
    let sep = match kind {
        1 | 10 => "",
        2 => "-",
        3 | 9 => "/",
        4 => ".",
        5 => "  ",
        6 => "   ",
        _ => " ",
    };
    s.map_or(body.clone(), |letter| format!("{body}{sep}{letter}"))
}

/// The three leaks, each over every shape of the number that follows, over
/// every break, with and without a suffix letter on the first number. Each row
/// is the text and the numbers in it that must be masked whole.
fn repros() -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for br in BREAKS {
        // Bug 1: a head with no suffix of its own before a number that opens
        // with its suffix letter, in lower case (which the FIN-6 cut cannot
        // see) and in capitals. Glue needs a head that ends on its digits.
        for (head_kind, prefix) in BARE_HEADS {
            for &kind in &SHAPES {
                if br.is_empty() && (SEPARATED[kind] || SEPARATED[head_kind]) {
                    continue;
                }
                for next_prefix in ["cb", "CB"] {
                    let head = number(head_kind, prefix, 0, None);
                    let next = number(kind, next_prefix, 1, Some('a'));
                    out.push((format!("{head}{br}{next}"), vec![head, next]));
                }
            }
        }
        // Bug 2: the middle number of a chain of three, in every pair of shapes.
        for &a in &SHAPES {
            for &b in &SHAPES {
                let last = (a + b) % KINDS;
                if br.is_empty() && !(GLUE_SAFE[a] && GLUE_SAFE[b] && GLUE_SAFE[last]) {
                    continue;
                }
                let first = number(a, "AB", 0, Some(LETTERS[a % 4]));
                let mid = number(b, "CE", 1, Some(LETTERS[(b + 1) % 4]));
                let last = number(last, "JG", 2, Some(LETTERS[(b + 2) % 4]));
                out.push((
                    format!("{first}{br}{mid}{br}{last}"),
                    vec![first.clone(), mid.clone(), last.clone()],
                ));
            }
        }
        // Bug 3: the number starts one letter behind the glued suffix. The head
        // may stand on its own digits ([`BARE_HEADS`]) or close with a suffix
        // letter of its own ([`WHOLE_HEADS`]). A slashed or dotted head that
        // stands on its digits cannot take a suffix across a break at all — its
        // fourth boundary has to be its own separator — on any base, so it is
        // not here; and it cannot take one under glue either, where there is no
        // boundary at all. The lower-case slashed shape is not here at all: the
        // letter this row glues in front of it makes it a word
        // (`Bab/65/43/21/b`), and a lower-case separated shape written onto a
        // letter is not a number on any base (see [`GLUE_SAFE`]).
        for &kind in &SHAPES {
            if !GLUE_SAFE[kind] {
                continue;
            }
            let bare = BARE_HEADS.map(|(kind, prefix)| number(kind, prefix, 0, None));
            let whole = WHOLE_HEADS.map(|(kind, prefix)| number(kind, prefix, 0, Some('C')));
            for (head, is_bare) in bare
                .into_iter()
                .zip([true; 6])
                .chain(whole.into_iter().zip([false; 6]))
            {
                if br.is_empty() && is_bare {
                    continue;
                }
                let next = number(kind, "AB", 1, Some('B'));
                let text = format!("{head}{br}B{next}");
                out.push((text, vec![head, next]));
            }
        }
    }
    out
}

/// Every number a gate must mask, checked with the shared exact reader: a
/// refusal or an output that does not read back exactly is a finding, as is a
/// value that sits in the clear.
fn check(out: &mut Vec<String>, text: &str, keep: &[String]) {
    for &mode in &MODES {
        let ranges = match masked(mode, text) {
            None => {
                out.push(format!("{mode:?} refused {text:?}"));
                continue;
            }
            Some(ranges) => ranges,
        };
        for value in keep {
            let at = match text.find(value.as_str()) {
                Some(at) => at,
                None => {
                    out.push(format!("{text:?}: {value:?} is not in the text"));
                    break;
                }
            };
            if !covered(&ranges, at, at + value.len()) {
                out.push(format!("{mode:?} {text:?}: {value:?} is in clear",));
            }
        }
    }
}

/// RED on main 041c9c46: the three leaks, over every shape and break, in both
/// modes. Every number of the chain is masked whole.
#[test]
fn every_number_of_a_chain_stays_masked() {
    let mut bad = Vec::new();
    for (text, keep) in repros() {
        check(&mut bad, &text, &keep);
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}

/// The values a next number's suffix is glued to in [`targeted`]: values the
/// first round masks whole, so only the residue round reads that number. The
/// IBANs are the public specimens; each key is built at run time.
fn tails() -> [String; 5] {
    let body: String = (0..36)
        .map(|at| (b'a' + (at * 7 % 26) as u8) as char)
        .collect();
    [
        "GB82WEST12345698765432".to_string(),
        "FR7630006000011234567890189".to_string(),
        format!("ghp_{body}"),
        format!("AKIA{}", body[..16].to_ascii_uppercase()),
        format!("glpat-{}", &body[..20]),
    ]
}

/// NINO-CHAIN r1 (pass A): a head, a break, a next number whose own suffix is
/// glued to a value only the residue round reads it past, then that value:
/// 4 heads x 7 breaks x 6 next numbers x 5 values = 840 texts, each with the
/// head and the next number (built from their digits) to mask whole.
fn targeted() -> Vec<(String, Vec<String>)> {
    let (a, b) = (["67", "18", "39"], ["05", "51", "39"]);
    let heads = [
        format!("ak {} {} {}", a[0], a[1], a[2]),
        format!("AK {} {} {}", a[0], a[1], a[2]),
        format!("ak{}{}{}", a[0], a[1], a[2]),
        format!("AK-{}-{}-{}", a[0], a[1], a[2]),
    ];
    let nexts = [
        format!("bl {} {} {} d", b[0], b[1], b[2]),
        format!("bl{}{}{}d", b[0], b[1], b[2]),
        format!("BL{}{}{}D", b[0], b[1], b[2]),
        format!("BL {} {} {} D", b[0], b[1], b[2]),
        format!("bl-{}-{}-{}-d", b[0], b[1], b[2]),
        format!("BL-{}-{}-{}-D", b[0], b[1], b[2]),
    ];
    let mut out = Vec::new();
    for head in &heads {
        for br in ["\r\n", "\n", " ", "", "\t", "\u{2028}", "\r"] {
            for next in &nexts {
                for tail in tails() {
                    let text = format!("{head}{br}{next}{tail}");
                    out.push((text, vec![head.clone(), next.clone()]));
                }
            }
        }
    }
    out
}

/// RED on c6f901ba (pass A): the head took the next number's first letter even
/// where no pass read that number in the first round, so the residue round
/// could not read it either and `l 05 51 39 d` stood in clear. Both numbers
/// are masked whole in both modes (Open removes a national ID too, and has no
/// residue round), and every text is read back exactly.
#[test]
fn a_next_number_read_only_in_the_residue_round_keeps_its_letter() {
    let cases = targeted();
    assert_eq!(cases.len(), 840);
    let mut bad = Vec::new();
    for (text, keep) in &cases {
        check(&mut bad, text, keep);
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}

/// Chains of two to five numbers, every shape combination for two, and a
/// deterministic walk of the shapes for three to five, in both modes.
#[test]
fn a_chain_of_two_to_five_numbers_masks_every_one() {
    let mut bad = Vec::new();
    let mut chains: Vec<(String, Vec<String>)> = Vec::new();
    for &a in &SHAPES {
        for &b in &SHAPES {
            for br in ["\n", " ", ""] {
                if br.is_empty() && !(GLUE_SAFE[a] && GLUE_SAFE[b]) {
                    continue;
                }
                let first = number(a, "AB", 0, Some(LETTERS[a % 4]));
                let second = number(b, "CE", 1, Some(LETTERS[(b + 1) % 4]));
                chains.push((format!("{first}{br}{second}"), vec![first, second]));
            }
        }
    }
    for len in 3..=5 {
        for step in 0..288 {
            for suffixless in [false, true] {
                // A head with no suffix letter of its own is only a number when
                // the letter behind it completes it, so it takes the shapes the
                // compact pass reads and the next number's prefix must open
                // with A to D — the letters a suffix may be.
                let pool: &[usize] = if suffixless { &HEADS } else { &SHAPES };
                let prefixes: &[&str] = if suffixless {
                    &HEAD_PREFIXES
                } else {
                    &PREFIXES
                };
                let kinds: Vec<usize> = (0..len)
                    .map(|at| pool[(step * 5 + at * 7 + at * at) % pool.len()])
                    .collect();
                let parts: Vec<String> = kinds
                    .iter()
                    .enumerate()
                    .map(|(at, &kind)| {
                        number(
                            kind,
                            prefixes[(step + at) % prefixes.len()],
                            (step + at) % PAIRS.len(),
                            match suffixless {
                                true if at % 2 == 1 && at + 1 < len => None,
                                _ => Some(LETTERS[(step + at) % 4]),
                            },
                        )
                    })
                    .collect();
                // A head with no suffix letter of its own needs a separator
                // behind it to be read at all, so glue is for whole numbers.
                let list = breaks_for(&kinds, suffixless);
                let text = parts.join(list[(step + 1) % list.len()]);
                chains.push((text, parts));
            }
        }
    }
    for (text, keep) in &chains {
        check(&mut bad, text, keep);
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}

/// NI-shaped prose: no new mask on it, so head must read exactly what main
/// reads, byte for byte, in both modes.
#[test]
fn ni_shaped_prose_keeps_the_mask_it_had_on_main() {
    let mut bad = Vec::new();
    let (head, body) = PROSE_MAIN.split_once('\n').unwrap();
    assert_eq!(
        head,
        header(&prose()),
        "inputs changed: refreeze the prose fixture"
    );
    let records: Vec<&str> = body.lines().collect();
    assert_eq!(records.len(), prose().len(), "refreeze the prose fixture");
    for (text, record) in prose().into_iter().zip(records) {
        for (index, &mode) in MODES.iter().enumerate() {
            let was = record.split('|').nth(index).unwrap();
            let got = record_of(&read(mode, &text));
            if got != was {
                bad.push(format!("{mode:?} {text:?}: main {was}, head {got}"));
            }
        }
    }
    let count = bad.len();
    bad.truncate(40);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}

/// NI-shaped prose that reads as a sentence: a flight number, an order line, a
/// part number, a table of figures. A number that opens a line or a word here
/// must keep reading as prose and not gain a second token.
fn prose() -> Vec<String> {
    let mut out = Vec::new();
    let spaced = |prefix| number(0, prefix, 0, None);
    let compact = number(1, "AB", 0, None);
    for br in ["\n", " ", "\r\n"] {
        let heads = [
            format!("Flight {}", spaced("BA")),
            format!("Order {compact}"),
            format!("Part no {}", number(2, "AB", 0, None)),
        ];
        for head in heads {
            for tail in [
                "Cat sat on it",
                "dispatched",
                "in stock",
                "Card payment taken",
                "Dog walk booked",
            ] {
                out.push(format!("{head}{br}{tail}"));
            }
        }
        for tail in [
            format!("ref {} ok", number(3, "CB", 0, Some('A'))),
            "total 42.00 due".to_string(),
            "see the table below".to_string(),
            format!("Item {} added", number(0, "AB", 0, Some('C'))),
        ] {
            out.push(format!("NI number {}{br}{tail}", spaced("AB")));
            out.push(format!("NINO {compact}{br}{tail}"));
        }
    }
    out
}

/// The seeded differential: 1,800 documents of a chain of two to five National
/// Insurance numbers in shapes of their own with digits of their own, mixed
/// with the other classes (IBAN, phone, e-mail, card, health value, NIR, key,
/// password, an address line) and prose, joined by every break the normaliser
/// folds.
fn documents() -> Vec<String> {
    let mut rng = Rng(0x4e49_4e4f_4348_4149);
    let mut out = Vec::new();
    for _ in 0..1_800 {
        let count = 2 + rng.next() % 4;
        // Each number of a document takes the next triple, so no two of its
        // numbers are the same value (five numbers, eight triples).
        let first = rng.next() as usize;
        let mut doc = String::new();
        for at in 0..count {
            if at > 0 {
                doc.push_str(rng.pick(BREAKS));
            }
            if at > 0 && rng.next().is_multiple_of(5) {
                doc.push_str(rng.pick(OTHERS));
                doc.push_str(rng.pick(BREAKS));
            }
            let suffix = match rng.next() % 3 {
                0 => None,
                _ => Some(LETTERS[(rng.next() % 4) as usize]),
            };
            doc.push_str(&number(
                (rng.next() % KINDS as u64) as usize,
                PREFIXES[(rng.next() % PREFIXES.len() as u64) as usize],
                (first + at as usize) % PAIRS.len(),
                suffix,
            ));
        }
        if rng.next().is_multiple_of(3) {
            doc.push_str(rng.pick(BREAKS));
            doc.push_str(rng.pick(OTHERS));
        }
        out.push(doc);
    }
    out
}

/// The other classes a chain sits next to, so the differential is not only a
/// chain of numbers.
const OTHERS: &[&str] = &[
    "IBAN GB29 NWBK 6016 1331 9268 19",
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "call +44 20 7946 0958 today",
    "mail alice.smith@example.org",
    "blood type A+",
    "health plan number 7KL2-QW9-PX41",
    "card 4111 1111 1111 1111",
    "NIR 1 84 12 76 451 089 46",
    "key AKIAIOSFODNN7EXAMPLE",
    "password: Sunflower2025",
    "Total due 42.00",
    "see attached.",
    "Dear customer,",
    "12 Baker Street",
    // Letters and digits a suffix letter may be glued to without opening a
    // number, so a chain that ends next to one keeps what main masked.
    "Cat sat",
    "Xray",
    "B7 ward",
    "dog",
];

/// A xorshift64, so the corpus is the same text on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, list: &'a [&'a str]) -> &'a str {
        list[(self.next() % list.len() as u64) as usize]
    }
}

/// The exact ranges a gate masked, or `None` for a refusal or for an output the
/// shared reader cannot read back (`exact_mask.rs`): a first-round span of one
/// class that the residue round then split into pieces of another. A baseline
/// records `!` for those, so it claims nothing there rather than reading them a
/// second way.
fn read(
    mode: kernel_core::privacy::PrivacyMode,
    text: &str,
) -> Option<Option<Vec<(usize, usize)>>> {
    issue(mode, text).map(|(output, minted)| exact_ranges(mode, text, &output, &minted))
}

/// The `start-end` ranges of one masked text as a record; `!` is a refusal or an
/// output the shared reader cannot read back.
fn record_of(ranges: &Option<Option<Vec<(usize, usize)>>>) -> String {
    ranges.clone().flatten().map_or("!".into(), |ranges| {
        ranges
            .iter()
            .map(|(start, end)| format!("{start}-{end},"))
            .collect()
    })
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

fn probe(text: &str, ranges: &[(usize, usize)]) -> Vec<String> {
    ranges
        .iter()
        .map(|&(s, e)| text.get(s..e).unwrap_or("<oob>").to_string())
        .collect()
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
    let each = |text: &String| MODES.map(|mode| record_of(&read(mode, text))).join("|");
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

/// Frozen from origin/main (0e6833e7) on the corpus of [`documents`].
const MAIN: &str = include_str!("data/nino_chain_main.txt");
/// Frozen from origin/main (0e6833e7) on the corpus of [`prose`]: the header
/// (count and hash, so an edit to `prose()` asks for a refreeze), then one
/// record per text.
const PROSE_MAIN: &str = include_str!("data/nino_chain_prose_main.txt");
/// Frozen from origin/main (0e6833e7) on the 840 texts of [`targeted`].
const TARGETED_MAIN: &str = include_str!("data/nino_chain_targeted_main.txt");

/// Frozen from origin/main (0e6833e7) on the texts of [`glued_runs`].
const GLUED_MAIN: &str = include_str!("data/nino_chain_glued_main.txt");

/// The texts of [`targeted`].
fn targeted_texts() -> Vec<String> {
    targeted().into_iter().map(|(text, _)| text).collect()
}

#[test]
#[ignore = "freezes a base fixture: run on the base only"]
fn freeze() {
    println!("{}", fixture(&documents()));
    println!("PROSE-BEGIN\n{}", header(&prose()));
    for text in prose() {
        let each = MODES.map(|mode| record_of(&read(mode, &text))).join("|");
        println!("{each}");
    }
    println!("PROSE-END\n{}", fixture(&targeted_texts()));
    println!("{}", fixture(&glued_texts()));
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
                let mode = MODES[index];
                lossy.push(format!("{:?} lost {gone} in {text:?}", mode));
                println!(
                    "DIAG {mode:?} {text:?}\n  main {:?}\n  head {:?}",
                    probe(text, &was),
                    probe(text, &now)
                );
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

/// A strict byte superset of origin/main (0e6833e7) on 1,800 documents of NI
/// chains mixed with the other classes, in both modes, with no new refusal.
#[test]
fn the_seeded_chain_differential_loses_no_byte_of_main() {
    let inputs = documents();
    assert!(inputs.len() >= 1_500, "only {} texts", inputs.len());
    assert_superset("main 0e6833e7", MAIN, &inputs);
}

/// A strict byte superset of origin/main (0e6833e7) on the 840 targeted texts
/// of pass A, in both modes, with no new refusal.
#[test]
fn the_targeted_differential_loses_no_byte_of_main() {
    assert_superset("main 0e6833e7", TARGETED_MAIN, &targeted_texts());
}

/// Release only: dense NI chains through both gates, best of three.
#[test]
#[ignore = "release timing: cargo test --release --test nino_chain -- --ignored scales"]
fn chain_dense_text_scales_linearly() {
    // Every shape and break in turn; a compact chain glued end to end, where
    // each number reopens one letter on; a one-line chain of bare heads, where
    // each scan steps back onto the shared letter.
    let mixed: String = (0..KINDS * 4)
        .map(|at| {
            let prefix = HEAD_PREFIXES[at % HEAD_PREFIXES.len()];
            let suffix = (!at.is_multiple_of(3)).then_some(LETTERS[at % 4]);
            number(at % KINDS, prefix, at, suffix) + BREAKS[at % BREAKS.len()]
        })
        .collect();
    let glued: String = (0..8).map(|at| number(1, "CB", at, Some('C'))).collect();
    let heads: String = (0..8).map(|at| number(0, "AB", at, None) + " ").collect();
    // A shared-letter chain whose last number is glued to a key, so every
    // number asks the read table about the next one (NINO-CHAIN r1).
    let shared: String = (0..8).map(|at| number(1, "CB", at, None)).collect();
    let [_, _, key, _, _] = tails();
    for unit in [
        mixed,
        glued + "\n",
        heads + "C\n",
        format!("{shared}D{key}\n"),
    ] {
        scales(&unit);
    }
}

fn scales(unit: &str) {
    let mut last = 0.0;
    for size in [16_384usize, 65_536, 262_144, 1_048_576] {
        let unit = unit.repeat(size / unit.len());
        let mut best = f64::MAX;
        for _ in 0..3.min(1 + (262_144 / size)) {
            let start = std::time::Instant::now();
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

/// The parts of one [`glued_runs`] text, as indices into its lists: head,
/// filler, break, next shape, value.
type Key = [usize; 5];

/// The byte ranges of the three values of one [`glued_runs`] text.
type Values = [(usize, usize); 3];

/// Zero to three filler bytes between the head's suffix and the break.
const GLUED_FILLERS: [&str; 4] = ["", "9", "X", "Xq"];

/// Glue, then the breaks the normaliser folds into one separator.
const GLUED_BREAKS: [&str; 6] = ["", " ", "\n", "\r\n", "\t", "\u{2028}"];

/// NINO-CHAIN r2 (pass B): a head with its own suffix, zero to three filler
/// bytes, a break, then a shape with no suffix (`BM085263`) or a whole number,
/// glued to a value the first round masks whole: 5 heads x 4 fillers x 6
/// breaks x 6 shapes x 4 values = 2,880 texts. Each comes with its parts and
/// the byte ranges of its three values (head, next, glued value); the filler
/// and the break are no value. Digits are built from their pairs at run time.
fn glued_runs() -> Vec<(String, Key, Values)> {
    let (a, b) = (["71", "28", "49"], ["08", "52", "63"]);
    let heads = [
        format!("ZK{}{}{}C", a[0], a[1], a[2]),
        format!("ZK {} {} {} C", a[0], a[1], a[2]),
        format!("ZK-{}-{}-{}-C", a[0], a[1], a[2]),
        format!("zk{}{}{}c", a[0], a[1], a[2]),
        format!("ZK/{}/{}/{}/C", a[0], a[1], a[2]),
    ];
    let nexts = [
        format!("BM{}{}{}", b[0], b[1], b[2]),
        format!("CM{}{}{}", b[0], b[1], b[2]),
        format!("bm{}{}{}", b[0], b[1], b[2]),
        format!("BM{}{}{}D", b[0], b[1], b[2]),
        format!("CM {} {} {} A", b[0], b[1], b[2]),
        format!("BM-{}-{}-{}-D", b[0], b[1], b[2]),
    ];
    let [iban, _, key, akia, _] = tails();
    let values = [key, akia, iban, format!("4111{}", "1".repeat(12))];
    let mut out = Vec::new();
    for (h, head) in heads.iter().enumerate() {
        for (f, filler) in GLUED_FILLERS.iter().enumerate() {
            for (r, br) in GLUED_BREAKS.iter().enumerate() {
                for (n, next) in nexts.iter().enumerate() {
                    for (t, value) in values.iter().enumerate() {
                        let text = format!("{head}{filler}{br}{next}{value}");
                        let at = head.len() + filler.len() + br.len();
                        let spans = [
                            (0, head.len()),
                            (at, at + next.len()),
                            (at + next.len(), text.len()),
                        ];
                        out.push((text, [h, f, r, n, t], spans));
                    }
                }
            }
        }
    }
    out
}

/// The texts of [`glued_runs`].
fn glued_texts() -> Vec<String> {
    glued_runs().into_iter().map(|(text, ..)| text).collect()
}

/// The accepted P3 of pass B r1 (TODO 1), closed: Private only, the parts of
/// the text, and the filler bytes main masked that head leaves in clear (a gap
/// letter, a stray digit, a break between two masked numbers). Main masked
/// them only by reading the whole glued run as one IBAN or ID. A loss not in
/// this list, and an entry that no longer happens, both fail the test. Empty:
/// on this corpus the r2 glue rule loses no filler byte either (699b949d lost
/// 20 here, `9`/`X` with their break, besides the two values).
const FILLER_ONLY: &[(Key, &str)] = &[];

/// RED on 699b949d: `ZK712849C9BM085263ghp_…` and `ZK712849C9CM085263ghp_…`
/// left `BM085263` / `CM085263` in clear in Private, where main masked the
/// whole run. Every value byte main masked stays masked in both modes, with no
/// new refusal and nothing unreadable; the only bytes head may leave that main
/// masked are the filler bytes of [`FILLER_ONLY`], exactly.
#[test]
fn a_glued_run_after_a_whole_head_loses_no_value_byte_of_main() {
    let runs = glued_runs();
    assert_eq!(runs.len(), 2_880);
    // Head 0, filler "9", glue, `BM…` / `CM…`, the `ghp_` key.
    assert!(runs[144].0.starts_with("ZK712849C9BM085263ghp_"));
    assert!(runs[148].0.starts_with("ZK712849C9CM085263ghp_"));
    let (head, body) = GLUED_MAIN.split_once('\n').unwrap();
    assert_eq!(head, header(&glued_texts()), "inputs changed: refreeze");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), runs.len());
    let (mut bad, mut filler) = (Vec::new(), Vec::new());
    for ((text, key, spans), record) in runs.iter().zip(records) {
        for (index, was) in record.split('|').map(parse).enumerate() {
            let mode = MODES[index];
            let Some(was) = was else { continue };
            let Some(Some(now)) = read(mode, text) else {
                bad.push(format!("{mode:?} refused or unreadable {text:?}"));
                continue;
            };
            let gone: Vec<usize> = was
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .collect();
            let value = gone
                .iter()
                .filter(|&&b| spans.iter().any(|&(s, e)| s <= b && b < e))
                .count();
            if value > 0 {
                bad.push(format!("{mode:?} lost {value} value bytes in {text:?}"));
            } else if !gone.is_empty() {
                let bytes: String = gone
                    .iter()
                    .map(|&b| std::ascii::escape_default(text.as_bytes()[b]).to_string())
                    .collect();
                if index == 0 {
                    filler.push((*key, bytes));
                } else {
                    bad.push(format!("{mode:?} lost filler {bytes:?} in {text:?}"));
                }
            }
        }
    }
    let listed: Vec<(Key, String)> = FILLER_ONLY
        .iter()
        .map(|(key, bytes)| (*key, (*bytes).to_string()))
        .collect();
    for entry in filler.iter().filter(|entry| !listed.contains(entry)) {
        bad.push(format!(
            "not in FILLER_ONLY: ({:?}, {:?}),",
            entry.0, entry.1
        ));
    }
    for entry in listed.iter().filter(|entry| !filler.contains(entry)) {
        bad.push(format!("FILLER_ONLY entry no longer happens: {entry:?}"));
    }
    eprintln!("{} texts: {} filler-only losses", runs.len(), filler.len());
    let count = bad.len();
    bad.truncate(80);
    assert!(bad.is_empty(), "{count}\n{}", bad.join("\n"));
}
