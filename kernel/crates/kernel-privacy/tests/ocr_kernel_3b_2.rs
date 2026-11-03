//! OCR-KERNEL-3b-2 acceptance: an OCR-damaged passport line is hidden in both
//! modes only when it has the exact length of its layout and every check digit
//! holds; every other run keeps main's masks.
//!
//! Failed checks (a `<` on a required check, a wrong document or composite
//! digit once OCR letters are read), runs one character short or long, and
//! prose keep exactly main's masks in Private and Open.
//! `data/ocr_kernel_3b_2_main.txt` freezes main's masks for every input;
//! refreeze on origin/main only (`-- --ignored freeze --nocapture`). Every
//! value is invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};

type Ranges = Vec<(usize, usize)>;

const FIXTURE: &str = include_str!("data/ocr_kernel_3b_2_main.txt");

/// The ICAO 9303 7-3-1 check digit of `field`.
fn check(field: &str) -> char {
    let value = |c: char| match c {
        '0'..='9' => c as u32 - '0' as u32,
        'A'..='Z' => c as u32 - 'A' as u32 + 10,
        _ => 0,
    };
    let sum: u32 = field
        .chars()
        .zip([7, 3, 1].iter().cycle())
        .map(|(c, w)| value(c) * w)
        .sum();
    char::from_digit(sum % 10, 10).expect("digit")
}

/// A TD3 (44) or TD2 (36) second line: document, nationality, birth, sex,
/// expiry and optional data, each with its check digit, then the composite.
fn line2(doc: &str, birth: &str, sex: char, expiry: &str, optional: &str) -> String {
    let field = |f: &str| format!("{f}{}", check(f));
    let mut line = format!("{}UTO{}{sex}{}", field(doc), field(birth), field(expiry));
    line.push_str(&if optional.len() == 14 {
        field(optional)
    } else {
        optional.into()
    });
    let composite: String = [&line[..10], &line[13..20], &line[21..]].concat();
    line.push(check(&composite));
    line
}

/// A TD1 second line (30): birth, sex, expiry, nationality, optional data.
fn td1_line2() -> String {
    let field = |f: &str| format!("{f}{}", check(f));
    format!("{}M{}UTO581041177364", field("870314"), field("310922"))
}

/// A TD1 first line (30) with the document number `R8M4K2T07` or `W3N7P0T52`.
fn td1_line1(doc: &str) -> String {
    format!("IDUTO{doc}{}395820174461823", check(doc))
}

/// `line` with the digits at `at` read as the letter OCR mistakes them for
/// (`0` as `o`/`O`, `1` as `l`/`I`, cycling), the line otherwise unchanged.
fn ocr(line: &str, at: &[usize]) -> String {
    let mut out: Vec<char> = line.chars().collect();
    for (n, &i) in at.iter().enumerate() {
        out[i] = match (out[i], n % 2) {
            ('0', 0) => 'o',
            ('0', _) => 'O',
            ('1', 0) => 'l',
            ('1', _) => 'I',
            (c, _) => panic!("{c} at {i} has no OCR letter in {line}"),
        };
    }
    out.into_iter().collect()
}

/// The valid lines the positives and the length variants are built on.
struct Lines {
    td3a: String,
    td3b: String,
    td2: String,
    td1a: String,
    td1b: String,
    td1_2: String,
}

fn lines() -> Lines {
    Lines {
        td3a: line2("X4R2T9M71", "870314", 'M', "310922", "58204117730941"),
        td3b: line2("KD7Q0P2Z8", "920105", 'F', "290611", "71039926458120"),
        td2: line2("QA81LM330", "750822", 'F', "300101", "4471028"),
        td1a: td1_line1("R8M4K2T07"),
        td1b: td1_line1("W3N7P0T52"),
        td1_2: td1_line2(),
    }
}

/// Every MRZ positive: `(text, lines that must be hidden)`.
fn mrz_positives() -> Vec<(String, Vec<String>)> {
    let Lines {
        td3a,
        td3b,
        td2,
        td1a,
        td1b,
        td1_2,
    } = lines();
    let name = |n: &str| {
        format!("P<UTO{n}")
            .chars()
            .chain(std::iter::repeat('<'))
            .take(44)
            .collect::<String>()
    };
    let one = |line: String| (line.clone(), vec![line]);
    let mut out = vec![
        (
            format!("{}\n{td3a}", name("VELMAR<<ANSEL")),
            vec![td3a.clone()],
        ),
        (format!("MRZ:\n{td3a}"), vec![td3a.clone()]),
        one(td3b.clone()),
        (
            format!("I<UTOQUILLAN<<BRET<<<<<<<<<\n{td2}"),
            vec![td2.clone()],
        ),
        (
            format!("{td1a}\n{td1_2}\nVELMAR<<ANSEL<<<<<<<<<<<<<<<<<"),
            vec![td1a.clone(), td1_2.clone()],
        ),
        // OCR letters on digits, every check digit valid once they are read.
        one(ocr(&td3a, &[15])),
        one(ocr(&td3a, &[15, 17, 22, 23])),
        one(ocr(&td3b, &[16, 25])),
        one(ocr(&td3b, &[9, 16])),
        one(ocr(&td2, &[22, 24])),
        one(ocr(&td1_2, &[2, 10])),
        one(ocr(&td1b, &[14])),
        (
            format!("{}\n{}", name("VELMAR<<ANSEL"), ocr(&td3a, &[15, 23])),
            vec![ocr(&td3a, &[15, 23])],
        ),
        // One lower-case letter OCR could not place.
        one(format!("x{}", &td3a[1..])),
        one(format!("i{}", &td1a[1..])),
    ];
    // Every layout, clean and damaged, bare, then under CRLF line ends (fix round 1).
    for (_, row) in specimens() {
        out.push(one(row.clone()));
        for variant in damaged(&row) {
            out.push(one(variant.clone()));
            out.push((
                format!("{}\r\n{variant}\r\n", name("VELMAR<<ANSEL")),
                vec![variant],
            ));
        }
    }
    // `K` and `C` read for a filler `<` of the optional data.
    let td3 = line2("X4R2T9M71", "870314", 'M', "310922", "58<04117<30941");
    out.push(one(td3.replace('<', "K")));
    out.push(one(td3.replace('<', "C")));
    // A row attached to text, one token longer than its layout: only the row is
    // hidden, the text around it is left (fix round 2).
    let attached = |row: &str| {
        let low = row.to_lowercase();
        [
            (format!("x{row}y"), row),
            (format!("{row}4"), row),
            (format!("{row}X"), row),
            (format!("ref{row}"), row),
            (
                format!("Example reference {row}X remains in the message."),
                row,
            ),
            (format!("x{low}y"), &low),
        ]
        .map(|(text, value)| (text, vec![value.to_string()]))
    };
    for row in valid_rows() {
        // A TD1 line 1 inside a longer token must show a filler `<`.
        if row.starts_with('I') && row.len() == 30 && !row.contains('<') {
            continue;
        }
        out.extend(attached(&row));
    }
    for (name, row) in specimens() {
        out.extend(attached(&row));
        // `K` and `C` for a filler `<` up to the last position of a visa row.
        if name.starts_with("MRV") {
            out.push(one(row.replace('<', "K")));
            out.push(one(row.replace('<', "C")));
        }
    }
    // Rows glued with no separator: each is hidden (fix round 2).
    let field = |f: &str| format!("{f}{}", check(f));
    let td2b = line2("KD7Q0P2Z8", "920105", 'F', "290611", "4471028");
    let td1_2b = format!("{}M{}UTO581041177364", field("920105"), field("290611"));
    for (a, b) in [
        (&td3a, &td3b),
        (&td2, &td2b),
        (&td1_2, &td1_2b),
        (&td3a.to_lowercase(), &td3b.to_lowercase()),
    ] {
        out.push((format!("{a}{b}"), vec![a.clone(), b.clone()]));
    }
    out
}

/// A specimen row of every layout, with isolated `<` fillers (no `<<`, which
/// main already masks whole): TD3, TD2, TD1 line 1, TD1 line 2, MRV-A, MRV-B.
fn specimens() -> Vec<(&'static str, String)> {
    let field = |f: &str| format!("{f}{}", check(f));
    let visa = |optional: &str| {
        format!(
            "{}UTO{}F{}{optional}",
            field("KD7Q0P2Z8"),
            field("920105"),
            field("290611")
        )
    };
    let td1_1 = format!("IDUTO{}39<5820<7446182", field("R8M4K2T07"));
    let td1_2 = format!("{}M{}UTO5810<4117734", field("870314"), field("310922"));
    vec![
        (
            "TD3",
            line2("X4R2T9M71", "870314", 'M', "310922", "58<04117<30941"),
        ),
        (
            "TD2",
            line2("QA81LM330", "750822", 'F', "300101", "44<1028"),
        ),
        ("TD1 line 1", td1_1),
        ("TD1 line 2", td1_2),
        ("MRV-A", visa("A<B<C<D<E<F<G<H<")),
        ("MRV-B", visa("A<B<C<D<")),
    ]
}

/// `row` with at most `n` of its `0` and `1` read as `O` and `I`/`l`.
fn swapped(row: &str, n: usize) -> String {
    let mut left = n;
    row.chars()
        .map(|c| match c {
            '0' | '1' if left > 0 => {
                left -= 1;
                match (c, left % 2) {
                    ('0', 0) => 'O',
                    ('0', _) => 'o',
                    (_, 0) => 'I',
                    _ => 'l',
                }
            }
            c => c,
        })
        .collect()
}

/// `row` with `gaps` inserted at the byte offsets `at`.
fn spaced(row: &str, at: &[usize], gap: &str) -> String {
    let mut out = String::new();
    let mut last = 0;
    for &i in at {
        out.push_str(&row[last..i]);
        out.push_str(gap);
        last = i;
    }
    out + &row[last..]
}

/// The OCR readings of a valid row that must still be hidden whole, spaces
/// included: lower case, five or more `O`/`I`/`l` for `0`/`1`, one blank, three
/// blanks (three gaps, and one gap of three), `«` for `<`, and a mix.
fn damaged(row: &str) -> Vec<String> {
    let mid = row.len() / 2;
    vec![
        row.to_lowercase(),
        swapped(row, 6),
        spaced(row, &[17], " "),
        spaced(row, &[8, mid, row.len() - 6], " "),
        spaced(row, &[17], "   "),
        row.replace('<', "«"),
        spaced(&swapped(&row.to_lowercase(), 5), &[12, 26], " "),
    ]
}

/// Seal repros: failed check digits and a `<` on a required check, at the exact
/// length of their layout. Main's masks stay.
const FAILED_CHECKS: &[&str] = &[
    // An ordinary 30-character code: marker, letters, six digits, no check (seal A, round 1).
    "AUXISREFNUMXYZ1ORDER2026123456",
    // A TD1 line 1 whose document check is 9, not the 7-3-1 digit 1 (seal B, round 1).
    "AZQVODDGMSGA3C9A<BYZ2N135VE7JH",
    "AB12345671UTO87O3042F30091521234567890123450",
    "AB1234567<UTO8703042F30091521234567890123458",
    // An OCR letter on a document check digit that is wrong once read.
    "X4R2T9M71oUTO8703145M31092255820411773094106",
    "X4R2T9M71OUTO8703145M31092255820411773094106",
    "IDUTOR8M4K2T07o395820174461823",
    "X4R2T9M716UTO87o3146M31092255820411773094106",
    "X4R2T9M716UTO87o3145M31092265820411773094106",
];

/// Prose and look-alikes that keep main's masks.
const PROSE: &[&str] = &[
    "Example reference 8703142M3109229UTO582041177364X remains in the message.",
    "3F2A9C41B07D58E6A1C3F2A9C41B07D58E6A1C3FA",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJ",
    "123456789012345678901234567890",
    "ORDER2024REF00001234567890ABCDEFXYZ",
    "SKU-AB12-CD34-EF56-GH78-IJ90-KL12",
    "BOOKINGREFOOOLIIOLOOIIOLOOIOLIOIOOLIOOLIOOLO",
    "HELLOWORLDUTOIOIOIIOMOIOIOIOIOIOIOIOIOIOIOIO",
];

/// Each valid line one character short, bare and inside prose, with and without
/// OCR letters: not a layout of 30, 36 or 44. Its first 36 characters can still
/// be a TD2 row (a shared document, birth and expiry, and a composite check
/// that holds one time in ten), so this is a superset check, not a look-alike.
/// One character long is a row with text attached: the row is hidden, see
/// `attached`.
fn partial_rows() -> Vec<String> {
    let mut out = Vec::new();
    for line in valid_rows() {
        let short = line[..line.len() - 1].to_string();
        out.push(format!("Example reference {short} remains in the message."));
        out.push(short);
    }
    out
}

/// Valid rows of every layout, with and without OCR letters.
fn valid_rows() -> Vec<String> {
    let l = lines();
    vec![
        l.td3a.clone(),
        l.td3b.clone(),
        l.td2.clone(),
        l.td1a.clone(),
        l.td1_2.clone(),
        ocr(&l.td3a, &[15, 23]),
        ocr(&l.td2, &[22, 24]),
        ocr(&l.td1_2, &[2, 10]),
    ]
}

/// Ordinary codes of a layout's length that no check digit backs: other
/// readings of the seal repros, a valid row with one digit changed (and so a
/// failed check) read in any damaged way, codes, part numbers, base32 and hex.
fn damaged_lookalikes() -> Vec<String> {
    let mut out = Vec::new();
    for repro in FAILED_CHECKS {
        out.push(repro.to_lowercase());
        out.push(spaced(repro, &[17], " "));
        out.push(swapped(repro, 6));
    }
    for (name, row) in specimens() {
        // A digit changed so its check digit no longer holds: the birth date
        // (TD2, TD3, visas), the expiry check (TD1 line 2). The TD1 document
        // check is `5` or, with an `O` for the `0`, `7`: it becomes `3`.
        let mut bad = row.clone().into_bytes();
        bad[14] = match name {
            "TD1 line 1" => b'3',
            _ if bad[14] == b'7' => b'6',
            _ => b'7',
        };
        let bad = String::from_utf8(bad).expect("ascii");
        // Clean, a shape with a failed check is main's too (fix round 2).
        out.push(bad.clone());
        out.extend(damaged(&bad));
    }
    // A valid row with its document check changed, clean and glued to another.
    let Lines { td3b, .. } = lines();
    let mut broken = td3b.clone();
    broken.replace_range(9..10, if &td3b[9..10] == "1" { "2" } else { "1" });
    out.push(format!("Zone lisible :\n{broken}\n"));
    out.extend(random_codes());
    out.extend(
        [
            "PROJECTALPHA2024REVISIONB0042CONTRACTNUMBERX",
            "projectalpha2024revisionb0042contractnumberx",
            "PN 4471 0028 AB 9921 7731 0094 ZX 5513 2208 8",
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK",
            "jbswy3dpehpk3pxpjbswy3dpehpk3pxpjbswy3dpehpk",
            "JBSWY3 DPEHPK 3PXPJB SWY3DP EHPK3P XPJBSWY3DP EHPK",
            "3F2A9C 41B07D 58E6A1 C3F2A9 C41B07 D58E6A",
            "3f2a9c41b07d58e6a1c3f2a9c41b07d58e6a",
            "870314 2M3109 229UTO 582041 177364",
            "8703142m3109229uto582041177364",
            "ORDER 2024 REF 00001234 567890 ABCDEF XYZ",
            "order2024ref00001234567890abcdefxyzorder2024",
            "BOOKING REF OOO LII OLOO IIOLOOIOLIOIOOLIOOLIOOLO",
        ]
        .map(String::from),
    );
    out
}

/// `n` characters of `set` from `next` at `at` in `code`.
fn put(next: &mut impl FnMut(usize) -> usize, code: &mut [char], at: usize, n: usize, set: &[u8]) {
    for c in &mut code[at..at + n] {
        *c = set[next(set.len())] as char;
    }
}

/// 2,000 codes of 30, 36 or 44 characters from a fixed seed, half of them laid
/// out as a data row (marker, nationality, digit fields), none of which passes
/// the check digits its layout carries, however its O/I/l are read: main's masks
/// stay (fix round 2).
fn random_codes() -> Vec<String> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = move |bound: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound as u64) as usize
    };
    let pick = |n: usize, set: &[u8]| set[n % set.len()] as char;
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    let read = |s: &str| -> String {
        s.chars()
            .map(|c| match c {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            })
            .collect()
    };
    let holds = |payload: &str, digit: char| {
        let digit = read(&digit.to_string());
        [payload.to_string(), read(payload)]
            .iter()
            .any(|p| check(p).to_string() == digit)
    };
    let mut out = Vec::new();
    while out.len() < 2000 {
        let width = [30, 36, 44][next(3)];
        let mut code: Vec<char> = (0..width)
            .map(|_| {
                if next(40) < 3 {
                    '<'
                } else {
                    pick(next(36), ALNUM)
                }
            })
            .collect();
        if next(2) == 0 {
            // Laid out as a data row.
            if width == 30 && next(2) == 0 {
                code[0] = ['I', 'A', 'C'][next(3)];
                put(&mut next, &mut code, 1, 4, UPPER);
                put(&mut next, &mut code, 14, 1, DIGITS);
                put(&mut next, &mut code, 15, 5, DIGITS);
            } else if width == 30 {
                put(&mut next, &mut code, 0, 7, DIGITS);
                code[7] = ['M', 'F', 'X'][next(3)];
                put(&mut next, &mut code, 8, 7, DIGITS);
                put(&mut next, &mut code, 15, 3, UPPER);
            } else {
                put(&mut next, &mut code, 9, 1, DIGITS);
                put(&mut next, &mut code, 10, 3, UPPER);
                put(&mut next, &mut code, 13, 7, DIGITS);
                code[20] = ['M', 'F', 'X'][next(3)];
                put(&mut next, &mut code, 21, 7, DIGITS);
            }
        }
        let code: String = code.into_iter().collect();
        // No window of the code, at any offset, passes the checks of a layout.
        let possible = [30, 36, 44].into_iter().filter(|&w| w <= width).any(|w| {
            (0..=width - w).any(|at| {
                let win = &code[at..at + w];
                let c = |a: usize, b: usize| win[a..b].to_string();
                let digit = |i: usize| win.as_bytes()[i] as char;
                if w == 30 {
                    let line1 = "IAC".contains(&win[..1]) && holds(&c(5, 14), digit(14));
                    let line2 = holds(&c(0, 6), digit(6)) && holds(&c(8, 14), digit(14));
                    line1 || line2
                } else {
                    holds(&c(0, 9), digit(9))
                        && holds(&c(13, 19), digit(19))
                        && holds(&c(21, 27), digit(27))
                }
            })
        });
        if !possible {
            out.push(code);
        }
    }
    out
}

/// Every look-alike: keeps main's masks in both modes.
fn lookalikes() -> Vec<String> {
    let strs = [FAILED_CHECKS, PROSE].concat();
    strs.into_iter()
        .map(String::from)
        .chain(damaged_lookalikes())
        .collect()
}

/// Every positive: `(text, value ranges)`.
fn positives() -> Vec<(String, Ranges)> {
    let at = |text: &str, value: &str| {
        let start = text.find(value).expect("the value is in its text");
        (start, start + value.len())
    };
    let out: Vec<(String, Ranges)> = mrz_positives()
        .into_iter()
        .map(|(t, lines)| {
            let ranges = lines.iter().map(|l| at(&t, l)).collect();
            (t, ranges)
        })
        .collect();
    out
}

/// The differential inputs: the positives, then every look-alike.
fn inputs() -> Vec<(String, Ranges)> {
    let mut out = positives();
    out.extend(lookalikes().into_iter().map(|t| (t, Vec::new())));
    out.extend(partial_rows().into_iter().map(|t| (t, Vec::new())));
    out
}

#[test]
fn ocr_damaged_passport_lines_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, values) in positives() {
        for mode in MODES {
            let Some(ranges) = masked(mode, &text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            if values.iter().any(|&(s, e)| !covered(&ranges, s, e)) {
                let output = issue(mode, &text).map(|(o, _)| o);
                wrong.push(format!("{mode:?} {text:?} -> {output:?}"));
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

/// Failed checks, off-length runs and prose: exactly main's
/// masks, Private and Open.
#[test]
fn lookalikes_keep_main_masks() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let look = lookalikes();
    let mut wrong = Vec::new();
    for ((text, _), main) in inputs.iter().zip(&main) {
        if !look.contains(text) {
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
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Random Base32 codes whose document field passes the TD1 line 1 check by
/// chance, but whose issuer is no ICAO code (seal of #303): no ID card line, so
/// exactly the masks of main before #303, frozen here, in both modes.
#[test]
fn random_base32_codes_are_no_id_card_line() {
    let pinned: &[(&str, Ranges)] = &[
        ("CUTOZ4W2VC652B73EM5KU7FQJJVRVP", vec![(8, 30)]),
        ("CQBGVBGJJQ3HC25L43IOSV2QCORUVP", vec![(11, 30)]),
        ("CMTEEA5UY6FGQG2Q7MY5TGPE2U5UCS", vec![]),
        ("IWBZG2QEZNMUT54RZT5GLWWAY3F66A", vec![(11, 30)]),
        ("CAGCXNQYDTUX4U44A5MHHYUCG6C3M4", vec![]),
        ("ISAPFTEQB6TGMU36V3KKHY725X6KGU", vec![]),
    ];
    let mut wrong = Vec::new();
    for (code, before) in pinned {
        for mode in MODES {
            if masked(mode, code).as_ref() != Some(before) {
                wrong.push(format!("{mode:?} {code}: {:?}", masked(mode, code)));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Every input: no byte main masks is left clear, and no new refusal.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let (mut lost, mut refused) = ([0usize; 2], 0);
    for ((text, _), main) in inputs.iter().zip(main) {
        for (index, main) in main.into_iter().enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += usize::from(main.is_some());
                continue;
            };
            let gone = main
                .unwrap_or_default()
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                eprintln!("{:?} {text:?} lost {gone}", MODES[index]);
            }
            lost[index] += gone;
        }
    }
    eprintln!(
        "{} inputs: bytes lost {lost:?}; refusals {refused}",
        inputs.len()
    );
    assert_eq!((lost, refused), ([0, 0], 0));
}

/// Release only: MRZ-like runs at 16 KiB to 1 MiB; each 4x
/// step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test ocr_kernel_3b_2 -- --ignored timing"]
fn timing_scales_linearly() {
    let mut unit = String::new();
    for text in lookalikes() {
        unit.push_str(&text);
        unit.push('\n');
    }
    for (text, _) in mrz_positives() {
        unit.push_str(&text);
        unit.push('\n');
    }
    unit.push_str(&"<<<<ABCD1234".repeat(8));
    // Windows of a layout's length that pass the shape, one line, many tokens.
    unit.push('\n');
    unit.push_str(&"870314 2M3109 229UTO 582041 177364 ".repeat(40));
    unit.push('\n');
    let time = |bytes: usize| {
        let text = unit.repeat(bytes / unit.len() + 1);
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
    eprintln!("ocr kernel 3b-2 text: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
    // One 100 KB token of valid rows end to end (main takes 20 s on 1 MiB of it:
    // the other detectors), and one 1 MiB token of look-alike windows.
    for giant in [
        "8703145M3109225UTO581041177364".repeat(3_500),
        "ID<UTO8703145M31092251234567890AB<".repeat(31_000),
    ] {
        let start = Instant::now();
        let _ = issue(PrivacyMode::Private, &giant);
        let _ = issue(PrivacyMode::Open, &giant);
        let took = start.elapsed();
        eprintln!("ocr kernel 3b-2 giant token: {took:?}");
        assert!(took < Duration::from_secs(30), "{took:?}");
    }
}
