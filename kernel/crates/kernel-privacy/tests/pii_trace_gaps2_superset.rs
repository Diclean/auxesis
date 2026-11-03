//! K-PII-TRACE-GAPS-2: spelled-out e-mails, split cued codes and wrapped CN
//! credit codes are masked, and nothing shipped regresses.
//!
//! The differential runs every input through `Gate::for_grant` in Private and
//! Open against `data/pii_trace_gaps2_main.txt`, frozen from origin/main: no
//! byte main masks may be left clear and no text may be refused. Refreeze on
//! main only: `cargo test -p kernel-privacy --test pii_trace_gaps2_superset --
//! --ignored freeze --nocapture`. All values are invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, Registry};

#[allow(dead_code)]
mod cases {
    include!("data/exact_mask.rs");
}

#[allow(dead_code)]
mod tail4 {
    include!("data/secret_tail4_cases.rs");

    pub fn inputs() -> impl Iterator<Item = &'static str> {
        [CASES, PR1B_CASES, PR2_CASES]
            .into_iter()
            .flatten()
            .map(|case| case.1)
    }
}

const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];
const FIXTURE: &str = include_str!("data/pii_trace_gaps2_main.txt");

/// The gate output for `input` and the tokens it minted, or `None` for a
/// refusal.
fn issue(mode: PrivacyMode, input: &str) -> Option<(String, Vec<(String, String)>)> {
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

/// The exact byte ranges of `input` the gate replaced, or `None` for a refusal.
///
/// One alignment, never a second reading (TEST-FITS-EXACT): in Private each
/// token stands for the surface the gate minted for it, in Open each marker for
/// the detector's own removed range, so a text the output does not read back
/// onto fails here instead of coming back masked under some other reading.
fn masked(mode: PrivacyMode, input: &str) -> Option<Vec<(usize, usize)>> {
    let (output, minted) = issue(mode, input)?;
    Some(cases::exact_or_fail(mode, input, &output, &minted))
}

fn email_repros() -> Vec<String> {
    let chain = "a dot b dot c dot d dot e at example dot org";
    let quotes = ["''", "\"\"", "‘’", "“”", "’’", "``"].map(|q| q.chars().collect::<Vec<_>>());
    let mut out: Vec<String> = quotes
        .iter()
        .map(|q| format!("{}{chain}{}", q[0], q[1]))
        .collect();
    let (a, b, q) = ("a".repeat(32), "b".repeat(32), "q".repeat(63));
    out.extend([
        chain.to_string(),
        "jane [dot] doe [at] example [dot] org".into(),
        "jane (dot) doe (at) example (dot) org".into(),
        "jean point dupont arobase exemple point fr".into(),
        format!("{a} dot {b} at example dot org"),
        format!("x at {q} dot {q} dot {q} dot {q}"),
        format!("x at {q} dot {q} dot {q} dot {q} dot org"),
        format!("{} at example dot org", ["x"; 18].join(" dot ")),
        format!("x at {} dot org", ["d"; 16].join(" dot ")),
        "a dot b . c at example dot org".into(),
        "O'Neil dot r at example dot org".into(),
        "O’Neil dot r at example dot org".into(),
        "home at me dot com".into(),
        "z9fake at my dot com".into(),
        "alice at my dot com".into(),
        "bob77 at me dot com".into(),
        "a dot\r\nb at\texample dot\r\norg".into(),
        "jane\tdot\tdoe\r\nat\r\nexample\tdot\torg".into(),
        "Mail jane at example dot com today.".into(),
    ]);
    out
}

/// (text, the value it must have fully masked in Private).
fn code_repros() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = [
        ("PIN 1234  5678", "1234  5678"),
        ("OTP 12 34 56", "12 34 56"),
        ("Comparison code: 803-143-301", "803-143-301"),
        ("OTP 12 . 34 . 56", "12 . 34 . 56"),
        ("OTP 12. 34. 56", "12. 34. 56"),
        ("OTP 12.\r\n34.\t56", "12.\r\n34.\t56"),
        ("OTP 12 . 34. 56", "12 . 34. 56"),
        ("PIN 12-34 56.78", "12-34 56.78"),
        ("Your verification code is 4821 09", "4821 09"),
    ]
    .map(|(text, value)| (text.to_string(), value.to_string()))
    .to_vec();
    for gap in ["\n", "\r\n", "  ", " "] {
        let value = format!("91990505{gap}MD4E5F6G7Q");
        out.push((format!("统一社会信用代码：{value}"), value));
    }
    out
}

const HEALTH: [&str; 7] = [
    "diabetes at example dot org",
    "cancer at example dot org",
    "HIV at example dot org",
    "chimiothérapie at example dot org",
    "alice at diabetes dot org",
    "diabetes [at] example [dot] org",
    "I have diabetes at example dot org",
];

const TRAPS: [&str; 12] = [
    "meet me at home dot",
    "look at the dot com era",
    "we arrived at night",
    "Look at it dot by dot.",
    "the price is 12.50",
    "price 12 . 50 USD",
    "due 2026-10-21",
    "OTP sent on 2026-10-21",
    "PIN reset costs 12.50 EUR",
    "at that point we left",
    "the order code is 12.50",
    "follow me @ the conference",
];

/// Every input of the differential, in a fixed order: the privacy-eval cases
/// and prose, the secret-tail cases, then each repro, trap and mix in six frames.
fn inputs() -> Vec<(&'static str, String)> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    let read = |path| std::fs::read_to_string(path).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(format!("{root}/cases"))
        .unwrap()
        .collect();
    files.sort_by_key(|entry| entry.as_ref().unwrap().path());
    let mut out = Vec::new();
    for file in files {
        for line in read(file.unwrap().path())
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            out.push(("eval", case["text"].as_str().unwrap().to_string()));
        }
    }
    for lang in ["af", "hu", "sl"] {
        let prose = read(format!("{root}/prose/{lang}.txt").into());
        let lines = prose.lines().filter(|l| !l.trim().is_empty());
        out.extend(lines.map(|line| ("prose", line.to_string())));
    }
    out.extend(tail4::inputs().map(|text| ("tail4", text.to_string())));
    let mut bases: Vec<(&str, String)> = email_repros().into_iter().map(|t| ("repro", t)).collect();
    bases.extend(code_repros().into_iter().map(|(t, _)| ("repro", t)));
    bases.extend(HEALTH.map(|t| ("health", t.to_string())));
    bases.extend(TRAPS.map(|t| ("trap", t.to_string())));
    let mixes = [
        "OTP 120394; tel +33 6 12 34 56 78",
        "PIN 4821 then call 06 12 34 56 78",
        "code-code/code 123456",
    ];
    bases.extend(mixes.map(|t| ("mix", t.to_string())));
    let frames = [
        ("", ""),
        ("Contact: ", "."),
        ("Hi,\n", " thanks"),
        ("« ", " »\n"),
        ("x ", "\r\n"),
    ];
    for (kind, base) in &bases {
        out.extend(frames.map(|(pre, post)| (*kind, format!("{pre}{base}{post}"))));
        out.push((kind, base.to_uppercase()));
    }
    out
}

/// One fixture record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    let ranges = ranges.map(|r| {
        r.iter()
            .map(|(s, e)| format!("{s}-{e}"))
            .collect::<Vec<_>>()
    });
    ranges.map_or("!".into(), |r| r.join(","))
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The fixture header: the input count and an FNV-1a hash of every input.
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
    let fixture = format!("{}\n{}", header(&inputs), lines.join("\n"));
    println!("FIXTURE-BEGIN\n{fixture}\nFIXTURE-END");
}

fn covered(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    (start..end).all(|byte| ranges.iter().any(|&(s, e)| s <= byte && byte < e))
}

/// The differential over the health-overlap inputs (`health`) or every other
/// input: bytes main masked left clear per mode, refusals, and new masks on
/// prose lines and on traps.
fn differential(health: bool) -> ([usize; 2], usize, [usize; 2]) {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    // Bytes lost per mode, refusals, and new masks on prose lines and on traps.
    let (mut lost, mut refused, mut over) = ([0usize; 2], 0, [0usize; 2]);
    for ((kind, text), record) in inputs.iter().zip(records) {
        if (*kind == "health") != health {
            continue;
        }
        for (index, main) in record.split('|').map(parse).enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += 1;
                continue;
            };
            let main = main.unwrap_or_default();
            let lose = |&(s, e): &(usize, usize)| (s..e).filter(|&b| !covered(&now, b, b + 1));
            let gone: usize = main.iter().map(|range| lose(range).count()).sum();
            lost[index] += gone;
            let new = matches!(*kind, "prose" | "trap") && now != main;
            over[usize::from(*kind == "trap")] += usize::from(new);
            if gone > 0 || new {
                eprintln!("{:?} {text:?}: main {main:?} now {now:?}", MODES[index]);
            }
        }
    }
    eprintln!(
        "differential (health {health}): bytes lost Private/Open {lost:?}; refusals {refused}; \
         prose/trap over-mask {over:?}"
    );
    (lost, refused, over)
}

/// Rules 1, 4 and 5: a strict byte superset of main in both modes, no new
/// refusal, and no new mask on the prose lines or a precision trap.
#[test]
fn strict_superset_of_main_in_both_modes() {
    assert_eq!(differential(false), ([0, 0], 0, [0, 0]));
}

/// Rule 1 on the cued codes: a value that parses as a date or a decimal is not
/// a code, and neither is a shorter prefix of it. Each input comes out byte for
/// byte unchanged through `Gate::for_grant` in both modes.
#[test]
fn a_date_or_a_decimal_is_not_a_code_and_has_no_shorter_prefix() {
    let clear = [
        "OTP 2026-10-21",
        "OTP 1234.50",
        "OTP 2026.10.21",
        "OTP 21-10-2026",
        "code 2026-10-21",
    ];
    let mut leaks = Vec::new();
    for text in clear {
        for mode in MODES {
            let got = issue(mode, text).map(|(output, _)| output);
            if got.as_deref() != Some(text) {
                leaks.push(format!("{text:?} in {mode:?} -> {got:?}"));
            }
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// The one fallback the amount guard must keep: only the joined value of
/// `OTP 1234  56 USD` is an amount, so its first groups are still a code.
#[test]
fn an_amount_keeps_the_first_groups_of_the_code_masked() {
    let (text, value) = ("OTP 1234  56 USD", "1234");
    let at = text.find(value).unwrap();
    for mode in MODES {
        let ranges = masked(mode, text).expect("never refused");
        assert!(
            covered(&ranges, at, at + value.len()),
            "{text:?} in {mode:?}: {ranges:?}"
        );
    }
}

/// Every cued-code repro stays fully masked, whitespace aside, in both modes.
#[test]
fn the_cued_code_repros_stay_masked_in_both_modes() {
    let repros = [
        ("PIN 1234  5678", "1234  5678"),
        ("OTP 12 34 56", "12 34 56"),
        ("Comparison code: 803-143-301", "803-143-301"),
        ("OTP 12 . 34 . 56", "12 . 34 . 56"),
        ("OTP 12. 34. 56", "12. 34. 56"),
    ];
    for (text, value) in repros {
        let at = text.find(value).unwrap();
        for mode in MODES {
            let ranges = masked(mode, text).expect("never refused");
            let clear = (at..at + value.len()).filter(|&b| {
                !text.as_bytes()[b].is_ascii_whitespace() && !covered(&ranges, b, b + 1)
            });
            assert_eq!(
                clear.count(),
                0,
                "{text:?} leaves {value:?} clear in {mode:?}: {ranges:?}"
            );
        }
    }
}

/// Rule 2 inside the differential: the health-overlap inputs lose no byte
/// either. Open loses the health word until the shared overlap fix lands.
#[test]
fn strict_superset_of_main_on_health_overlaps() {
    assert_eq!(differential(true), ([0, 0], 0, [0, 0]));
}

/// Acceptance: every repro is fully masked in Private.
#[test]
fn acceptance_repros_are_fully_masked_in_private() {
    let quotes = |c: char| "'\"‘’“”`".contains(c);
    let value = |t: &str| {
        t.trim_matches(quotes)
            .replace("Mail ", "")
            .replace(" today.", "")
    };
    let mut texts: Vec<(String, String)> =
        email_repros().into_iter().map(|t| (value(&t), t)).collect();
    texts.extend(code_repros().into_iter().map(|(text, value)| (value, text)));
    // `OTP 1234  56 USD`: the joined value is an amount, but `1234` is still a code.
    texts.push(("1234".into(), "OTP 1234  56 USD".into()));
    let mut leaks = Vec::new();
    for (value, text) in &texts {
        let at = text.find(value.as_str()).unwrap();
        let ranges = masked(PrivacyMode::Private, text).expect("never refused");
        let clear = (at..at + value.len())
            .filter(|&b| !text.as_bytes()[b].is_ascii_whitespace() && !covered(&ranges, b, b + 1));
        if clear.count() > 0 {
            leaks.push(format!("{text:?} leaves {value:?} in part: {ranges:?}"));
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// Rule 2: an e-mail span never displaces a health hit. With K-SPAN-PRIORITY the
/// merged region takes the prohibited kind, so Open removes the whole region
/// (health word and spelled address together): fail closed, a superset of main.
/// Private masks the whole address.
#[test]
fn health_hits_are_never_displaced() {
    let open = |text: &str| issue(PrivacyMode::Open, text).unwrap().0;
    for text in HEALTH {
        let out = open(text);
        assert!(out.contains("[health removed]"), "{text} -> {out}");
        for word in ["diabetes", "cancer", "HIV", "chimiothérapie"] {
            assert!(!out.contains(word), "{text} -> {out}");
        }
        let ranges = masked(PrivacyMode::Private, text).unwrap();
        let start = if text.starts_with("I have ") { 7 } else { 0 };
        assert!(covered(&ranges, start, text.len()), "{text}: {ranges:?}");
    }
    assert_eq!(
        open("I have diabetes at example dot org"),
        "I have [health removed]"
    );
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

/// A named input shape, built at a given repetition count.
type Shape = (&'static str, fn(usize) -> String);

/// Rule 3: every new loop is linear: 4x the input costs well under 6x the time.
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn new_scans_scale_linearly() {
    let shapes: [Shape; 7] = [
        ("a dot", |n| "a dot ".repeat(n) + "b at example dot org"),
        ("x at", |n| "x at b dot ".repeat(n)),
        ("code-", |n| "code-".repeat(n)),
        ("code/code/", |n| "code/code/".repeat(n)),
        ("OTP 12", |n| "OTP ".to_string() + &"12 ".repeat(n)),
        ("codes x phones", |n| {
            "OTP 120394; tel +33 6 12 34 56 78; ".repeat(n)
        }),
        ("cn wraps", |n| {
            "统一社会信用代码：91990505\nMD4E5F6G7Q ".repeat(n)
        }),
    ];
    for (name, shape) in shapes {
        let (small, large) = (timed(&shape(4_000)), timed(&shape(16_000)));
        let ratio = large.as_secs_f64() / small.max(Duration::from_millis(1)).as_secs_f64();
        eprintln!("scaling {name}: 4k {small:?} 16k {large:?} ratio {ratio:.2}");
        assert!(ratio < 6.0, "{name} is not linear: {ratio:.2}");
    }
}
