//! NORM-GLYPH: a look-alike `x` in a hex escape folds, so the escape it opens
//! is decoded like the ASCII one. `＆#х73;k-proj-…` (U+0445), `＆#χ73;…` (U+03C7),
//! `＆#Х73;…` (U+0425) and `＆＃х73;…` (the full-width `#` too) all read as
//! `&#x73;k-proj-…`: every byte masked in Private and Open, Private restoring
//! the exact original bytes. Guards: the spellings that need no look-alike,
//! Chinese and Cyrillic prose unchanged, a 1,000-text seeded differential against
//! main frozen in `data/norm_glyph_main.txt` (no byte lost, no new refusal, every
//! plain ASCII text read exactly as main), and spaceless text dense with those
//! escapes linear. Values are invented; the FR IBAN and the `example.invalid`
//! address are the specimens this suite already uses.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, issue, masked, CYRILLIC_PROSE, MODES, ZH_PROSE};

const FIXTURE: &str = include_str!("data/norm_glyph_main.txt");

/// How one entity is written: the ampersand and the `#` plain or full-width, the
/// `x` of the hex form plain or a look-alike, whether the `;` is there. A `p` in
/// the `x` slot writes the letter in clear, no escape.
#[derive(Clone, Copy)]
struct Shape {
    amp: char,
    hash: char,
    x: char,
    semi: bool,
}

const PLAIN: Shape = Shape {
    amp: ' ',
    hash: ' ',
    x: 'p',
    semi: false,
};
const ASCII: Shape = Shape {
    amp: '&',
    hash: '#',
    x: 'x',
    semi: true,
};
/// The family this work order is about: the full-width `＆` (U+FF06), which folds
/// to `&` only when it opens an escape, an ASCII `#`, and a look-alike `x`. The
/// Greek `χ` and the uppercase Cyrillic `Х` (which reads as `X`, and HTML5 takes
/// for a hex reference like `x`) are the same family; `AMP_HASH` is full-width in
/// both characters and `AMP_PLAIN` holds an ASCII `x`.
const AMP: Shape = Shape {
    amp: '\u{FF06}',
    hash: '#',
    x: '\u{445}',
    semi: true,
};
const AMP_GREEK: Shape = Shape {
    amp: '\u{FF06}',
    hash: '#',
    x: '\u{3C7}',
    semi: true,
};
const AMP_UPPER: Shape = Shape {
    amp: '\u{FF06}',
    hash: '#',
    x: '\u{425}',
    semi: true,
};
const AMP_HASH: Shape = Shape {
    amp: '\u{FF06}',
    hash: '\u{FF03}',
    x: '\u{445}',
    semi: true,
};
const AMP_PLAIN: Shape = Shape {
    amp: '\u{FF06}',
    hash: '#',
    x: 'x',
    semi: true,
};

/// The spellings the corpus draws from: the four main reads, then the `＆` family
/// with every look-alike `x` and the full-width `＃`.
const SHAPES: &[Shape] = &[
    PLAIN,
    ASCII,
    Shape {
        amp: '&',
        hash: '#',
        x: 'x',
        semi: false,
    },
    Shape {
        amp: '&',
        hash: '#',
        x: 'х',
        semi: true,
    },
    AMP,
    AMP_GREEK,
    AMP_UPPER,
    AMP_HASH,
    Shape {
        amp: '\u{FF06}',
        hash: '\u{FF03}',
        x: 'χ',
        semi: true,
    },
    AMP_PLAIN,
];

/// The value with its first letter written as an entity in this shape: the
/// letter's code in hex behind the shape's `x`, then the rest of the value. `upper`
/// writes the code in caps (`&#X73;`). Built at run time: no file in the tree may
/// hold a key-shaped literal (`scripts/check-no-secrets.sh`).
fn spelled(shape: &Shape, code: u32, tail: &str, upper: bool) -> String {
    if shape.x == 'p' {
        return format!("{}{tail}", char::from_u32(code).expect("ASCII"));
    }
    let digits = if upper {
        format!("{code:02X}")
    } else {
        format!("{code:02x}")
    };
    let body = if shape.x == 'x' {
        format!("x{digits}")
    } else {
        format!("{}{digits}", shape.x)
    };
    let tail = if shape.semi {
        format!(";{tail}")
    } else {
        tail.to_string()
    };
    format!("{}{}{body}{tail}", shape.amp, shape.hash)
}

/// The body that follows a value's encoded letter: the entity stands for the `s`
/// of the key, so the tail starts at its `k`. Written without that `s` so no file
/// in the tree holds a key-shaped literal.
const KEY_TAIL: &str = "k-proj-abcdefghijklmnopqrstuvwx";
const IBAN_TAIL: &str = "R76 3000 6000 0112 3456 7890 189";

/// One value in one frame: the text, the value's bytes, and whether Open must
/// mask it too (Open leaves an e-mail address in clear by design,
/// `open_mode_prohibited.rs`, so that case is Private only).
struct Case {
    text: String,
    value: String,
    open: bool,
}

/// The work order's four repros first: the `s` of the key behind the Cyrillic `х`,
/// the Greek `χ`, the full-width `＃` beside the full-width `＆`, and the `d` of a
/// health word. Then the four variants: the uppercase Cyrillic `Х`, the `@` of an
/// address, the `F` of an IBAN, and a hex-digit position (built in [`repros`]).
/// The last four need no look-alike: they hold the fix to this family.
#[allow(clippy::type_complexity)]
const REPROS: &[(Shape, u32, &str, (&str, &str), bool)] = &[
    (AMP, 0x73, KEY_TAIL, ("key ", " end"), true),
    (AMP_GREEK, 0x73, KEY_TAIL, ("key ", " end"), true),
    (AMP_HASH, 0x73, KEY_TAIL, ("key ", " end"), true),
    (AMP, 0x64, "iabetes", ("I have ", ""), true),
    (AMP_UPPER, 0x73, KEY_TAIL, ("key ", " end"), true),
    (
        AMP,
        0x40,
        "example.invalid",
        ("mail freya.halloran", " now"),
        false,
    ),
    (AMP, 0x46, IBAN_TAIL, ("Virement sur ", " demain"), true),
    (ASCII, 0x73, KEY_TAIL, ("key ", " end"), true),
    (ASCII, 0x46, IBAN_TAIL, ("Virement sur ", " demain"), true),
    (PLAIN, 0x73, KEY_TAIL, ("key ", " end"), true),
    (AMP_PLAIN, 0x73, KEY_TAIL, ("key ", " end"), true),
];

fn repros() -> Vec<Case> {
    let build = |shape: &Shape, code: u32, tail: &str, frame: (&str, &str), open: bool| {
        let value = spelled(shape, code, tail, false);
        Case {
            text: format!("{}{value}{}", frame.0, frame.1),
            value,
            open,
        }
    };
    let mut out: Vec<Case> = REPROS
        .iter()
        .map(|&(shape, code, tail, frame, open)| build(&shape, code, tail, frame, open))
        .collect();
    // Two variants with a look-alike in a hex-digit position. In `＆#х6е;` the
    // Cyrillic `е` (U+0435) reads as the `e` of `6e`, the `n` of the key; the
    // letter before the escape folds the `＆` anyway, so this one guards the
    // hex-digit position rather than catching the bug. In `％6е` there is no
    // neighbour at all: the `％` folds only when both hex digits read as hex
    // digits, and it sits in a URL token, where the decoder reads it.
    let (head, tail) = KEY_TAIL.split_at(KEY_TAIL.len() - "opqrstuvwx".len());
    let entity = format!("s{head}{}#{}6{};{tail}", AMP.amp, AMP.x, '\u{435}');
    out.push(Case {
        text: format!("key {entity} end"),
        value: entity,
        open: true,
    });
    let percent = format!("s{head}％6{}{tail}", '\u{435}');
    out.push(Case {
        text: format!("https://example.invalid/?key={percent}"),
        value: percent,
        open: true,
    });
    out
}

#[test]
fn every_byte_of_each_value_is_masked_through_both_gates() {
    let mut leaks = Vec::new();
    for case in repros() {
        let at = case.text.find(&case.value).expect("value inside");
        for &mode in if case.open {
            &MODES[..]
        } else {
            &[PrivacyMode::Private][..]
        } {
            let Some(ranges) = masked(mode, &case.text) else {
                leaks.push(format!("{mode:?} refused {:?}", case.text));
                continue;
            };
            if !covered(&ranges, at, at + case.value.len()) {
                leaks.push(format!("{mode:?} {:?}: {ranges:?}", case.text));
            }
        }
        // An address is the one case Open keeps in clear by design: assert that it
        // stays exactly as clear as the ASCII spelling, so the glyph fold never
        // outruns the policy.
        if !case.open {
            let ascii = case.text.replace(
                &spelled(&AMP, 0x40, "", false),
                &spelled(&ASCII, 0x40, "", false),
            );
            assert_eq!(
                masked(PrivacyMode::Open, &case.text),
                masked(PrivacyMode::Open, &ascii)
            );
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// Private through the gate, with every minted token put back: the restore must
/// be the exact original bytes, escape and look-alike included.
#[test]
fn private_restores_the_exact_original_bytes() {
    for case in repros() {
        let (output, minted) = issue(PrivacyMode::Private, &case.text).expect("never refused");
        assert!(!minted.is_empty(), "{:?} -> {output:?}", case.text);
        let mut restored = output.clone();
        for (name, surface) in minted {
            restored = restored.replace(&format!("\u{27E6}{name}\u{27E7}"), &surface);
        }
        assert_eq!(restored, case.text, "{output:?}");
    }
}

/// The fold never reaches prose: no Chinese or Cyrillic line, and no line holding a
/// full-width `＆`, `＃` or `％` beside a look-alike, may gain a mask.
#[test]
fn prose_stays_unchanged() {
    let lines: Vec<&str> = ZH_PROSE
        .iter()
        .chain(CYRILLIC_PROSE)
        .copied()
        .chain([
            "Сегодня ＆＃х73; это не сущность, а просто текст.",
            "Η γραμμή ＆＃х73; είναι απλώς κείμενο.",
            "Цена: ％х4е и ＆＃х73; в тексте.",
            "今天有＆＃х73;这样的符号吗？",
        ])
        .collect();
    for text in lines {
        for mode in MODES {
            assert_eq!(masked(mode, text), Some(Vec::new()), "{mode:?} {text:?}");
        }
    }
}

/// xorshift64* over one fixed seed: the same corpus on every run and every
/// machine, so the frozen fixture stays comparable.
struct Rng(u64);

impl Rng {
    /// One draw: xorshift64* over the state, modulo `len`.
    fn below(&mut self, len: usize) -> usize {
        let mut x = self.0 | 1;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) % len as u64) as usize
    }
}

/// (prefix, suffix) around the value: prose in five languages, the shapes a mail
/// header takes, and the bare value with nothing around it.
const FRAMES: &[(&str, &str)] = &[
    ("key ", " end"),
    ("I have ", ""),
    ("", ""),
    ("IBAN ", " tomorrow"),
    ("mail ", " now"),
    ("le mot de passe est ", " ici"),
    ("Смотри ", " сюда"),
    ("密码是 ", " 谢谢"),
    ("uid 12 · key ", " · date: Thu, 15 Oct 2026"),
    ("", "\nThanks"),
];

/// (the code of the value's encoded letter, the rest of the value).
const VALUES: &[(u32, &str)] = &[
    (0x73, KEY_TAIL),
    (0x64, "iabetes"),
    (0x46, IBAN_TAIL),
    (0x40, "example.invalid"),
];

/// The 1,000 seeded texts: one value in one shape in one frame, a URL frame every
/// eighth time so the URL-token path runs too, and every sixteenth text carries a
/// percent escape whose second hex digit is a look-alike (`％4а`, the `J`).
fn corpus() -> Vec<String> {
    let mut rng = Rng(0x5EED_F013_2B1D_0001);
    (0..1000)
        .map(|index| {
            let shape = &SHAPES[rng.below(SHAPES.len())];
            let (code, tail) = VALUES[rng.below(VALUES.len())];
            let value = spelled(shape, code, tail, rng.below(2) == 0);
            let (prefix, suffix) = FRAMES[rng.below(FRAMES.len())];
            let value = if index % 16 == 0 {
                format!("％4\u{430}{value}")
            } else {
                value
            };
            if index % 8 == 0 {
                format!("https://example.invalid/?key={value} ")
            } else {
                format!("{prefix}{value}{suffix}")
            }
        })
        .collect()
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[String]) -> String {
    let bytes = inputs.iter().flat_map(|text| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

/// One record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    ranges.map_or("!".into(), |r| {
        r.iter()
            .map(|(s, e)| format!("{s}-{e}"))
            .collect::<Vec<_>>()
            .join(",")
    })
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = corpus();
    let records: Vec<String> = inputs
        .iter()
        .map(|text| MODES.map(|mode| record(masked(mode, text))).join("|"))
        .collect();
    let lines: Vec<String> = records.chunks(100).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// Rules: a strict byte superset of main in both modes, no new refusal, and every
/// plain ASCII text read exactly as main reads it. No allowlist: a lost byte means
/// the change dropped a value main kept, and the change is what must give.
#[test]
fn a_seeded_differential_is_a_strict_superset_of_main() {
    let inputs = corpus();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut gained, mut ascii, mut refused) = ([0usize; 2], [0usize; 2], 0, 0);
    for (text, record) in inputs.iter().zip(records) {
        let plain = text.is_ascii() && !text.contains(['&', '%']);
        for (index, main) in record.split('|').map(parse).enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += 1;
                continue;
            };
            let main = main.unwrap_or_default();
            let gone: usize = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            lost[index] += gone;
            gained[index] += usize::from(!now.iter().all(|r| main.contains(r)));
            if plain && now != main {
                ascii += 1;
            }
            if gone > 0 || (plain && now != main) {
                eprintln!("{:?} {text:?}: main {main:?} now {now:?}", MODES[index]);
            }
        }
    }
    eprintln!(
        "{} seeded texts: bytes lost Private/Open {lost:?}; refusals {refused}; masks gained \
         Private/Open {gained:?}; plain ASCII runs changed {ascii}",
        inputs.len()
    );
    assert_eq!((lost, ascii, refused), ([0, 0], 0, 0));
}

/// Release only: spaceless text dense with a look-alike `x` escape — the full-width
/// ampersand and hash too, so every branch of the escape rule runs at every
/// character — at 16 KiB, 64 KiB, 256 KiB and 1 MiB. Bar: each 4x step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test norm_glyph -- --ignored"]
fn glyph_x_text_scales_linearly() {
    let unit = "\u{FF06}\u{FF03}х73;k-proj-abcdefghijklmnopqrstuvwx\u{200B}";
    let time = |bytes: usize| {
        let text = unit.repeat(bytes / unit.len());
        assert!(
            !text.contains(char::is_whitespace),
            "the text must be spaceless"
        );
        (0..3)
            .map(|_| {
                let start = Instant::now();
                let _ = issue(PrivacyMode::Private, &text);
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let times: Vec<Duration> = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
        .map(time)
        .to_vec();
    eprintln!("spaceless glyph-x text: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
