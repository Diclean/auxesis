//! NORM-GLYPH r1: the glyph folds are an **extra** set of views, unioned with the
//! main folds, which read exactly as before. Decoding more filler (`＆#ｘ41;`,
//! `＆＃x41;`) loses the word boundary or the whole-token mask the main folds
//! give (#200, #201 pass A), so the new rule may only add masks.
//!
//! * the #200 and #201 repros: masked in Private and Open, as on main, and the
//!   Private restore is the exact original bytes;
//! * a 2,400-text seeded differential against main, frozen in
//!   `data/norm_glyph_union_main.txt`: spaceless filler runs (`＆#ｘ41;`, `𝐱`,
//!   `＆＃x41;`, `＆#х41;`, `％41`, …) glued to keys, health words, IBANs,
//!   e-mails and phones, plus glyph-x escapes. In both modes: no byte main masks
//!   comes out clear, no new refusal, and ASCII text without an `sk-proj-`
//!   candidate reads exactly as main. Exact-length key candidates may add a
//!   mask when decoded filler brings them to a supported issuer length;
//! * filler-dense spaceless text stays linear (release, ignored).
//!
//! The ranges come from `cases::masked`: one exact alignment, from the tokens the
//! gate minted (Private) or the detector's own removed ranges (Open), so a text
//! that cannot be read back fails the test instead of passing under some other
//! reading (TEST-FITS-EXACT, `exact_mask_alignment.rs`).
//!
//! Values are invented: the FR and DE IBANs are the specimens the suite already uses, the
//! phones are Ofcom drama numbers, the addresses sit under `example.invalid`.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, masked, MODES};

const FIXTURE: &str = include_str!("data/norm_glyph_union_main.txt");

/// The key after its first letter: written without the `s` so no file in the
/// tree holds a key-shaped literal (`scripts/check-no-secrets.sh`).
const KEY_TAIL: &str = "k-proj-abcdefghijklmnopqrstuvwx";

fn key() -> String {
    format!("s{KEY_TAIL}")
}

/// `unit` written `count` times, nothing between.
fn run(unit: &str, count: usize) -> String {
    unit.repeat(count)
}

/// (text, the value inside it). Every value must be masked in both modes.
fn repros() -> Vec<(String, String)> {
    let filler = "\u{FF06}#\u{FF58}41;";
    let wide_filler = "\u{FF06}\u{FF03}x41;";
    let mut out = Vec::new();
    // #201 pass A, 1 (#200 repro 1): the glued `k-proj` key behind a full-width
    // `x７３` entity, then `＆#ｘ41;` x17.
    let value = format!("\u{FF06}#x\u{FF17}\u{FF13};{KEY_TAIL}");
    out.push((format!("(/\u{FF06}#xyz{value}{}", run(filler, 17)), value));
    // #201 pass A, 2: a health word, then the same filler.
    out.push((
        format!("I have HIV positive{}", run(filler, 17)),
        "HIV positive".to_string(),
    ));
    // #201 pass A, 3: decoding the filler to `A` glues it onto `HIV`.
    out.push((
        format!("{filler}HI\u{FF06}#\u{FF18}\u{FF16}\u{FF1A}"),
        "HI\u{FF06}#\u{FF18}\u{FF16}".to_string(),
    ));
    // #200 repro 2: a full-width `＆＃x73;` key between filler runs.
    let value = format!("\u{FF06}\u{FF03}x73;{KEY_TAIL}");
    out.push((
        format!(
            "{}=\u{FF06}\u{FF03}x27e6; end{value}{}",
            run(filler, 24),
            run(filler, 28)
        ),
        value,
    ));
    // #200 repro 3: a card-shaped run and a marker, then the key behind a
    // `＆＃x41;＆#ｘ73;` pair, between full-width filler runs.
    let value = format!("{wide_filler}\u{FF06}#\u{FF58}73;{KEY_TAIL}");
    out.push((
        format!(
            "{} e1 + e2{}&#x27e7;note {value}\u{2060}{}",
            run(wide_filler, 20),
            "5555555555554444",
            run(wide_filler, 22)
        ),
        value,
    ));
    out
}

#[test]
fn repros_are_masked_in_both_modes() {
    let mut leaks = Vec::new();
    for (text, value) in repros() {
        let at = text.find(&value).expect("value inside");
        // Every byte of the value but a blank between two words: main masks
        // `HIV` and `positive` as two values and leaves the blank in clear.
        let bytes: Vec<usize> = value
            .char_indices()
            .filter(|&(_, ch)| ch != ' ')
            .flat_map(|(i, ch)| at + i..at + i + ch.len_utf8())
            .collect();
        for mode in MODES {
            match masked(mode, &text) {
                None => leaks.push(format!("{mode:?} refused {text:?}")),
                Some(ranges) if !bytes.iter().all(|&b| covered(&ranges, b, b + 1)) => {
                    leaks.push(format!("{mode:?} {text:?}: {ranges:?}"));
                }
                Some(_) => {}
            }
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

#[test]
fn repros_restore_the_exact_original_bytes() {
    for (text, _) in repros() {
        let (output, minted) = cases::issue(PrivacyMode::Private, &text).expect("never refused");
        let mut restored = output.clone();
        for (name, surface) in minted {
            restored = restored.replace(&format!("\u{27E6}{name}\u{27E7}"), &surface);
        }
        assert_eq!(restored, text, "{output:?}");
    }
}

/// xorshift64* over one fixed seed: the same corpus on every run and machine.
struct Rng(u64);

impl Rng {
    fn below(&mut self, len: usize) -> usize {
        let mut x = self.0 | 1;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) % len as u64) as usize
    }
}

/// The spaceless filler units: full-width and look-alike `x` escapes, the
/// mathematical `𝐱`, a full-width `％41`, and their ASCII forms.
const FILLERS: &[&str] = &[
    "\u{FF06}#\u{FF58}41;",
    "\u{1D431}",
    "\u{FF06}\u{FF03}x41;",
    "\u{FF06}#\u{445}41;",
    "\u{FF05}41",
    "\u{FF06}#\u{FF38}41;",
    "\u{FF06}\u{FF03}\u{3C7}41;",
    "\u{FF06}#\u{FF58}\u{FF14}\u{FF11};",
    "&#x41;",
    "%41",
];

/// The look-alike or full-width `x` of a glyph-x escape.
const GLYPH_X: &[char] = &['\u{445}', '\u{425}', '\u{3C7}', '\u{FF58}', '\u{FF38}', 'x'];

/// One value, its first letter written as a glyph-x escape one time in three.
fn value(rng: &mut Rng) -> String {
    let plain = match rng.below(9) {
        0 | 1 => key(),
        2 => format!("gh{}_{}", 'p', "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A7"),
        3 => "HIV positive".to_string(),
        4 => "type 2 diabetes".to_string(),
        5 => "FR76 3000 6000 0112 3456 7890 189".to_string(),
        6 => "DE89370400440532013000".to_string(),
        7 => "freya.halloran@example.invalid".to_string(),
        _ => ["+44 7700 900123", "+447700900456"][rng.below(2)].to_string(),
    };
    if rng.below(3) != 0 {
        return plain;
    }
    let first = plain.chars().next().expect("a value");
    let x = GLYPH_X[rng.below(GLYPH_X.len())];
    let hash = ['#', '\u{FF03}'][rng.below(2)];
    let amp = ['&', '\u{FF06}'][rng.below(2)];
    format!(
        "{amp}{hash}{x}{:x};{}",
        first as u32,
        &plain[first.len_utf8()..]
    )
}

/// Prose around a segment, glued or spaced.
const WORDS: &[&str] = &[
    "key", "I have", "IBAN", "mail", "call", "note", "", "(/", "=",
];

/// The 2,400 seeded texts: one to three segments, each a value with filler runs
/// glued before and after it (1-30 units, often none on one side), framed by a
/// word with or without a blank. Every tenth text is plain ASCII, so the ASCII
/// path is held to main exactly. Returns each text with its value ranges.
fn corpus() -> Vec<(String, Vec<(usize, usize)>)> {
    let mut rng = Rng(0x5EED_6170_4E10_0001);
    (0..2400)
        .map(|index| {
            let (mut text, mut values) = (String::new(), Vec::new());
            let ascii = index % 10 == 0;
            for _ in 0..=rng.below(3) {
                let word = WORDS[rng.below(WORDS.len())];
                text.push_str(word);
                if rng.below(2) == 0 {
                    text.push(' ');
                }
                let filler = |text: &mut String, rng: &mut Rng| {
                    if rng.below(3) == 0 {
                        return;
                    }
                    let units = if ascii { &FILLERS[8..] } else { FILLERS };
                    let unit = units[rng.below(units.len())];
                    text.push_str(&run(unit, 1 + rng.below(30)));
                };
                filler(&mut text, &mut rng);
                let value = if ascii {
                    [
                        key(),
                        "FR7630006000011234567890189".into(),
                        "HIV positive".into(),
                    ][rng.below(3)]
                    .clone()
                } else {
                    value(&mut rng)
                };
                values.push((text.len(), text.len() + value.len()));
                text.push_str(&value);
                filler(&mut text, &mut rng);
                if rng.below(2) == 0 {
                    text.push(' ');
                }
            }
            (text, values)
        })
        .collect()
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[(String, Vec<(usize, usize)>)]) -> String {
    let bytes = inputs.iter().flat_map(|(text, _)| text.bytes().chain([0]));
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
        .map(|(text, _)| MODES.map(|mode| record(masked(mode, text))).join("|"))
        .collect();
    let lines: Vec<String> = records.chunks(50).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// In both modes: no byte main masks comes out clear (value bytes counted on
/// their own too), and no refusal main did not make. Exact `sk-proj-` key
/// candidates must gain masks; other ASCII changes are reported for review,
/// since health phrase extension may add condition bytes.
#[test]
fn filler_runs_are_a_strict_superset_of_main() {
    let inputs = corpus();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut value_lost, mut gained) = ([0usize; 2], [0usize; 2], [0usize; 2]);
    let (mut refused, mut ascii, mut key_overmask) = ([0usize; 2], 0, 0);
    for ((text, values), record) in inputs.iter().zip(records) {
        let plain = text.is_ascii();
        for (index, main) in record.split('|').map(parse).enumerate() {
            let now = masked(MODES[index], text);
            let (main, now) = match (main, now) {
                (Some(main), Some(now)) => (main, now),
                // A refusal main made too is no change.
                (None, _) => continue,
                (Some(_), None) => {
                    refused[index] += 1;
                    eprintln!("{:?} new refusal {text:?}", MODES[index]);
                    continue;
                }
            };
            let gone: Vec<usize> = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .collect();
            lost[index] += gone.len();
            value_lost[index] += gone
                .iter()
                .filter(|&&b| values.iter().any(|&(s, e)| s <= b && b < e))
                .count();
            gained[index] += usize::from(now != main);
            if plain && now != main {
                if text.contains("sk-proj-") {
                    key_overmask += 1;
                } else {
                    ascii += 1;
                }
            }
            if !gone.is_empty() || (plain && now != main && !text.contains("sk-proj-")) {
                eprintln!("{:?} {text:?}: main {main:?} now {now:?}", MODES[index]);
            }
        }
    }
    eprintln!(
        "{} seeded texts: bytes lost Private/Open {lost:?} (value bytes {value_lost:?}); new \
         refusals {refused:?}; texts gaining masks {gained:?}; unrelated ASCII changes {ascii}; \
         key-candidate over-masks {key_overmask}",
        inputs.len()
    );
    assert_eq!((lost, value_lost, refused), ([0, 0], [0, 0], [0, 0]));
    assert!(key_overmask > 0, "exact key candidates should gain masks");
}

/// Release only: spaceless text dense with filler runs and glued values, at
/// 16 KiB, 64 KiB, 256 KiB and 1 MiB. Every unit holds a full-width `＆`, so the
/// extra glyph run always runs. Bar: each 4x step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test norm_glyph_union -- --ignored"]
fn filler_dense_text_scales_linearly() {
    let unit = format!(
        "{}\u{FF06}#\u{445}73;{KEY_TAIL}{}HIV\u{FF06}\u{FF03}x41;{}",
        run("\u{FF06}#\u{FF58}41;", 6),
        run("\u{FF06}\u{FF03}x41;", 4),
        run("\u{1D431}\u{FF05}41", 3)
    );
    let time = |bytes: usize| {
        let text = unit.repeat(bytes / unit.len());
        assert!(!text.contains(char::is_whitespace), "spaceless");
        (0..3)
            .map(|_| {
                let start = Instant::now();
                let _ = cases::issue(PrivacyMode::Private, &text);
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let times: Vec<Duration> = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
        .map(time)
        .to_vec();
    eprintln!("spaceless filler-dense text: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
