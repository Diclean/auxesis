//! FIN-6-ADDR: the address rule only adds masks. `data/address_main.txt` was
//! frozen from `origin/main` (38d40a90) by `freeze_main_fixture`: for every
//! privacy-eval case, prose line, address fixture and review repro, the bytes
//! main's Private gate tokenises (`P`) and main's Open gate removes (`O`), or
//! `R` for a refusal. This branch must cover each of those bytes, refuse no new
//! text, and mask nothing new in a text with no value.
//!
//! Refreeze on main only: `ADDR_FREEZE=<path> cargo test --test address_differential`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
#[cfg(feature = "ner-gliner")]
use kernel_privacy::safetext::{DetectError, Detector};
#[cfg(feature = "ner-gliner")]
use kernel_privacy::{EntityKind, Span};
use kernel_privacy::{Gate, NameDictionary, Registry};

include!("data/address_cases.rs");

/// The review repros of ADDR-DET-1 and ADDR-DET-2, `|`-separated.
const REPROS: &str = "xKerkstraat\n12 Lanternlaan|xKerkstraat 12 Lanternlaan|P.O. Box 12 London|\
    Postfach 1234 Berlin|BP oil price 456|BP 456|42 maple rd.|42 maple RD.|42 Maple Rd|\
    rd. 3 of the race|st. 4 of the plan|12 Main St #4, Boston, MA 02110|12 rue des Lilas, 75011|\
    Our Dublin office is at 7 Merrion Square, Dublin 2, D02 X285.|\
    Apt 4, 14 High St, Bristol BS1 4DJ|Flat 3, 14 High St, Bristol BS1 4DJ|\
    Unit 2B, 18 Quill Row, Leeds LS1 4AP|room #4 is free|in 2026 12 people|\
    06123-45678 Diabetes Lane|Flat 3, Oncology Centre|12 Diabetes Lane@example.invalid|\
    She lives at 4 Cancer Road, 75011 Paris, IBAN FR76 3000 6000 0112 3456 7890 189.|\
    7 avenue des tilleuls, 31000 toulouse|ref7 avenue des Tilleuls, 31000 Toulouse|\
    7 avenue des\nTilleuls, 31000 Toulouse|7 avenue des\r\nTilleuls, 31000 Toulouse|\
    9 Willow Lane, Leeds LS6 2QTok|“7 avenue des tilleuls, 31000 toulouse”|\
    7 avenue des tilleuls, 31000 toulouseok|ref7 avenue des tilleuls, 31000 toulouse|\
    7 avenue des\r\ntilleuls, 31000 toulouse|１２ ａｖｅｎｕｅ ｄｅｓ ｔｉｌｌｅｕｌｓ, ３１０００ ｔｏｕｌｏｕｓｅ|\
    7&#32;avenue&#32;des&#32;till&#x65;uls&#44;&#32;31000&#32;toulouse|\
    12 rue|in 69003 cases";

const NO_VALUE_GUARDS: &[&str] = &["12 rue", "in 69003 cases"];
const NEW_NO_VALUE_GUARDS: &[&str] = &["1234 cases", "Main Street Capital"];

/// A prohibited value inside an address block (maintainer note on #184): an IBAN, a
/// health word, a national ID and a secret.
const PROHIBITED_INSIDE: &[(&str, &str, &str)] = &[
    (
        "12 Main St, IBAN FR76 3000 6000 0112 3456 7890 189, Boston",
        "FR76 3000 6000 0112 3456 7890 189",
        "[iban removed]",
    ),
    ("Flat 3, Oncology Centre", "Oncology", "[health removed]"),
    (
        "Flat 3, 14 High St, NINO AB 12 34 56 C, Bristol BS1 4DJ",
        "AB 12 34 56 C",
        "[id removed]",
    ),
    (
        "12 rue des Lilas, aws key AKIAIOSFODNN7EXAMPLE, 75011 Paris",
        "AKIAIOSFODNN7EXAMPLE",
        "[secret removed]",
    ),
];

/// The texts with no value whose Private output must not gain a mask: the
/// prose files and every eval case with no labelled span.
const NO_VALUE: &str = "no-value";

fn gate(mode: PrivacyMode) -> Gate {
    let ctx = Context {
        destination: Destination::Vendor("addr-diff".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be admitted");
    };
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).expect("dictionary"));
    Gate::for_grant_with_dictionary(&grant, [7; 32], names)
}

/// `(source, line, text, tag)` for every text, in a fixed order.
fn texts() -> Vec<(String, usize, String, &'static str)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../qa/privacy-eval");
    let mut out = Vec::new();
    for dir in ["cases", "prose"] {
        let mut paths: Vec<PathBuf> = fs::read_dir(root.join(dir))
            .expect("privacy-eval is readable")
            .map(|entry| entry.expect("entry").path())
            .collect();
        paths.sort();
        for path in paths {
            let name = format!("{dir}/{}", path.file_name().unwrap().to_string_lossy());
            let raw = fs::read_to_string(&path).expect("readable");
            for (line, raw) in raw.lines().enumerate() {
                if raw.trim().is_empty() {
                    continue;
                }
                if dir == "prose" {
                    out.push((name.clone(), line, raw.to_string(), NO_VALUE));
                    continue;
                }
                let case: serde_json::Value = serde_json::from_str(raw).expect("JSON");
                let spans = case["spans"].as_array().is_some_and(|s| !s.is_empty());
                let text = case["text"].as_str().expect("text").to_string();
                out.push((name.clone(), line, text, if spans { "" } else { NO_VALUE }));
            }
        }
    }
    let extra = CASES
        .iter()
        .map(|(text, _)| *text)
        .chain(CLEAR.iter().copied());
    let inside = PROHIBITED_INSIDE.iter().map(|(text, _, _)| *text);
    for (line, text) in extra
        .chain(REPROS.split('|'))
        .chain(inside)
        .chain(NEW_NO_VALUE_GUARDS.iter().copied())
        .enumerate()
    {
        let tag = if CLEAR.contains(&text)
            || NO_VALUE_GUARDS.contains(&text)
            || NEW_NO_VALUE_GUARDS.contains(&text)
        {
            NO_VALUE
        } else {
            ""
        };
        out.push(("extra".into(), line, text.to_string(), tag));
    }
    out
}

#[allow(dead_code)]
mod exact {
    include!("data/exact_mask.rs");
}

/// The byte ranges of `input` a gate in `mode` does not issue in clear, or
/// `None` for a refusal. A minted token stands for the surface the gate minted
/// for it and a `[<class> removed]` marker for the detector's own range: one
/// exact alignment, never a second reading (TEST-FITS-EXACT,
/// `data/exact_mask.rs`). The old reader let an unminted token or a marker of
/// any body stand for "the input up to the first `find(clear)`".
///
/// `Some(None)` is a text whose output does not read back onto `input` at all:
/// a failure of its own, never a refusal, and never a pass.
fn hidden(mode: PrivacyMode, input: &str) -> Option<Option<Vec<(usize, usize)>>> {
    let mut gate = gate(mode);
    let output = gate.text(input).ok()?.0.as_str().to_string();
    let minted = gate.take_minted();
    Some(exact::exact_ranges(mode, input, &output, &minted))
}

fn format_ranges(ranges: &Option<Option<Vec<(usize, usize)>>>) -> String {
    match ranges {
        None => "R".into(),
        Some(None) => "?".into(),
        Some(Some(ranges)) => {
            let parts: Vec<String> = ranges.iter().map(|(a, b)| format!("{a}-{b}")).collect();
            parts.join(",")
        }
    }
}

fn parse_ranges(field: &str) -> Option<Vec<(usize, usize)>> {
    if field == "R" {
        return None;
    }
    let parse = |part: &str| {
        let (a, b) = part.split_once('-').expect("a-b");
        (a.parse().expect("start"), b.parse().expect("end"))
    };
    Some(
        field
            .split(',')
            .filter(|p| !p.is_empty())
            .map(parse)
            .collect(),
    )
}

/// `(source, line)` -> `(private, open)` from the frozen fixture. A text it does
/// not list was issued unchanged by main in both modes.
type Frozen = BTreeMap<(String, usize), [Option<Vec<(usize, usize)>>; 2]>;

fn frozen() -> Frozen {
    let raw = include_str!("data/address_main.txt");
    let mut out = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.starts_with('#')) {
        let (source, entries) = line.split_once('\t').expect("source<TAB>entries");
        for entry in entries.split(';') {
            let (at, modes) = entry.split_once(':').expect("line:modes");
            let (private, open) = modes.split_once('/').expect("private/open");
            let key = (source.to_string(), at.parse().expect("line"));
            out.insert(key, [parse_ranges(private), parse_ranges(open)]);
        }
    }
    out
}

fn bytes(ranges: &[(usize, usize)]) -> Vec<usize> {
    ranges.iter().flat_map(|&(a, b)| a..b).collect()
}

#[test]
#[ignore = "refreezes the fixture on main when ADDR_FREEZE is set"]
fn freeze_main_fixture() {
    let Ok(path) = std::env::var("ADDR_FREEZE") else {
        return;
    };
    let mut lines: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unreadable = Vec::new();
    for (source, line, text, _) in texts() {
        let modes = [PrivacyMode::Private, PrivacyMode::Open].map(|mode| {
            let hidden = hidden(mode, &text);
            if hidden == Some(None) {
                unreadable.push(format!("{mode:?} {source}:{line} {text:?}"));
            }
            hidden
        });
        if modes.iter().all(|m| m.as_ref() == Some(&Some(Vec::new()))) {
            continue;
        }
        let entry = format!(
            "{line}:{}/{}",
            format_ranges(&modes[0]),
            format_ranges(&modes[1])
        );
        lines.entry(source).or_default().push(entry);
    }
    assert!(unreadable.is_empty(), "unaligned on main: {unreadable:#?}");
    let mut out = String::from("# Frozen from origin/main 38d40a90 by freeze_main_fixture.\n");
    for (source, entries) in lines {
        out.push_str(&format!("{source}\t{}\n", entries.join(";")));
    }
    fs::write(path, out).expect("fixture written");
}

/// No byte main hides is issued in clear, in either mode.
#[test]
fn nothing_main_hides_is_issued_in_clear() {
    let frozen = frozen();
    let all = texts();
    let (mut lost, mut refusals, mut unreadable, mut new_masks, mut gained) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), 0);
    for (source, line, text, tag) in &all {
        let main = frozen
            .get(&(source.clone(), *line))
            .cloned()
            .unwrap_or([Some(Vec::new()), Some(Vec::new())]);
        for (mode, main) in [PrivacyMode::Private, PrivacyMode::Open]
            .into_iter()
            .zip(main)
        {
            let ours = hidden(mode, text);
            let (main, ours) = match (main, ours) {
                // Main refused, or main has no record: nothing to compare.
                (None, _) => continue,
                (Some(_), None) => {
                    refusals.push(format!("{mode:?} {source}:{line} {text:?}"));
                    continue;
                }
                (Some(_), Some(None)) => {
                    unreadable.push(format!("{mode:?} {source}:{line} {text:?}"));
                    continue;
                }
                (Some(main), Some(Some(ours))) => (main, ours),
            };
            let ours = bytes(&ours);
            let missing = bytes(&main)
                .into_iter()
                .filter(|b| !ours.contains(b))
                .count();
            let report = format!("{mode:?} {source}:{line} {missing} bytes {text:?}");
            if missing > 0 {
                lost.push(report);
            }
            let main = bytes(&main);
            let added = ours.iter().filter(|b| !main.contains(b)).count();
            gained += added;
            if added > 0 && *tag == NO_VALUE {
                new_masks.push(format!("{mode:?} {source}:{line} {text:?}"));
            }
        }
    }
    eprintln!(
        "{} texts: lost {}, refusals {}, unreadable {}, new masks on no-value texts {}, \
         bytes newly hidden {gained}",
        all.len(),
        lost.len(),
        refusals.len(),
        unreadable.len(),
        new_masks.len()
    );
    assert!(all.len() > 900, "only {} texts", all.len());
    assert!(lost.is_empty(), "bytes lost: {lost:#?}");
    assert!(refusals.is_empty(), "new refusals: {refusals:#?}");
    assert!(
        unreadable.is_empty(),
        "outputs that do not read back exactly: {unreadable:#?}"
    );
    assert!(new_masks.is_empty(), "new masks: {new_masks:#?}");
}

/// A prohibited value inside an address is removed in Open mode and never
/// issued in Private mode. Its bytes are also in the main differential above.
#[test]
fn a_prohibited_value_inside_an_address_is_never_issued() {
    for (text, value, marker) in PROHIBITED_INSIDE {
        let (open, _) = gate(PrivacyMode::Open).text(text).expect("open issues");
        assert!(
            !open.as_str().contains(value),
            "{text:?} -> {:?}",
            open.as_str()
        );
        assert!(
            open.as_str().contains(marker),
            "{text:?} -> {:?}",
            open.as_str()
        );
        let (private, _) = gate(PrivacyMode::Private)
            .text(text)
            .expect("private issues");
        assert!(
            !private.as_str().contains(value),
            "{text:?} -> {:?}",
            private.as_str()
        );
    }
}

/// A megabyte of address-like lines through the Private registry takes about
/// the time it takes without the address rule (on the Mac, release, main and
/// this branch both take about 11 s here: main's own registry is slow on such
/// lines). The ratio is measured in one run, so the bar holds on any machine.
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn a_megabyte_of_address_lines_costs_about_what_main_costs() {
    let mixes = [
        "Flat 3, 14 High St, Bristol BS1 4DJ\n12 rue des Lilas, 75011 Paris\n\
         Kossuth Lajos utca 12., 1051 Budapest\nPO Box 12 the 3 of us 2 x Street\n",
        "Flat 3, 14 High St, Bristol BS1 4DJ\nxKerkstraat\n12 Lanternlaan, call \
         +44 20 7946 0123\nP.O. Box 12 London\n42 maple RD.\n",
    ];
    let with = Registry::new().without_names();
    let mut builder = Registry::builder();
    for recognizer in kernel_privacy::recognizers::default_recognizers() {
        if recognizer.name() != "address" {
            builder = builder.with_boxed_recognizer(recognizer);
        }
    }
    let without = builder.build().without_names();
    for line in mixes {
        let text = line.repeat(1024 * 1024 / line.len() + 1);
        let time = |registry: &Registry| {
            let start = Instant::now();
            registry.analyze(&text);
            start.elapsed().as_secs_f64()
        };
        let (main, ours) = (time(&without), time(&with));
        eprintln!(
            "{} bytes: {ours:.2} s, without the address rule {main:.2} s",
            text.len()
        );
        assert!(ours < main * 1.25, "{ours:.2} s against {main:.2} s");
    }
}

#[test]
#[ignore = "release-mode latency report"]
fn ten_kilobyte_standard_latency_stays_within_five_percent_of_main() {
    let unit = "Neutral discussion contains no location data or identifiers. ";
    let text = unit.repeat(10_000 / unit.len() + 1);
    let text = &text[..10_000];
    let with = Registry::new().without_names();
    let mut builder = Registry::builder();
    for recognizer in kernel_privacy::recognizers::default_recognizers() {
        if recognizer.name() != "address" {
            builder = builder.with_boxed_recognizer(recognizer);
        }
    }
    let without = builder.build().without_names();
    let time = |registry: &Registry| {
        (0..3)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..100 {
                    std::hint::black_box(registry.analyze(std::hint::black_box(text)));
                }
                start.elapsed().as_secs_f64() / 100.0
            })
            .fold(f64::INFINITY, f64::min)
    };
    let (main, ours) = (time(&without), time(&with));
    eprintln!(
        "Standard 10 kB: {ours:.6} s, main {main:.6} s, ratio {:.3}x",
        ours / main
    );
    assert!(ours <= main * 1.05, "{ours:.6} s against {main:.6} s");
}

#[cfg(feature = "ner-gliner")]
struct OverlappingAddresses(Vec<String>);

#[cfg(feature = "ner-gliner")]
impl Detector for OverlappingAddresses {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self
            .0
            .iter()
            .filter_map(|value| {
                let at = text.find(value)?;
                let (start, end) = if text.starts_with("18 Maple Road ") {
                    (0, 18)
                } else {
                    (at, at + 4)
                };
                Some(Span::new(EntityKind::Address, start, end, 1.0, "fake"))
            })
            .collect())
    }
}

#[cfg(feature = "ner-gliner")]
fn deep_output(
    mode: PrivacyMode,
    input: &str,
    values: Vec<String>,
) -> Option<(String, Vec<(String, String)>)> {
    let ctx = Context {
        destination: Destination::Vendor("addr-deep-diff".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        return None;
    };
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).ok()?);
    let mut gate = Gate::for_grant_with_deep_detector(
        &grant,
        [7; 32],
        names,
        Arc::new(OverlappingAddresses(values)),
    );
    let output = gate.text(input).ok()?.0.as_str().to_owned();
    Some((output, gate.take_minted()))
}

#[cfg(feature = "ner-gliner")]
#[test]
fn seeded_deep_address_overlaps_preserve_every_standard_mask_byte() {
    const IBAN: &str = "FR76 3000 6000 0112 3456 7890 189";
    const NINO: &str = "AB 12 34 56 C";
    const CARD: &str = "4111 1111 1111 1111";
    const HEALTH: &str = "Oncology";
    let repro = "18 Maple Road +12025550142";
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let (output, minted) = deep_output(mode, repro, vec!["+12025550142".into()])
            .expect("Deep issues the overlap repro");
        let ranges = if mode == PrivacyMode::Private {
            exact::exact_or_fail(mode, repro, &output, &minted)
        } else {
            assert_eq!(output, "[address removed]");
            vec![(0, repro.len())]
        };
        assert_eq!(ranges, vec![(0, repro.len())], "{mode:?}: {ranges:?}");
    }
    for seed in 0..24 {
        let values = [
            "+12025550142".to_string(),
            format!("contact{seed}@example.invalid"),
            IBAN.into(),
            NINO.into(),
            CARD.into(),
            HEALTH.into(),
        ];
        let text = format!(
            "seed {seed}: {} | {} | {IBAN} | {NINO} | {CARD} | {HEALTH}",
            values[0], values[1]
        );
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let main = hidden(mode, &text)
                .and_then(|result| result)
                .expect("Standard output reads back exactly");
            let (output, minted) =
                deep_output(mode, &text, values.to_vec()).expect("Deep issues the seeded text");
            let deep = if mode == PrivacyMode::Private {
                exact::exact_or_fail(mode, &text, &output, &minted)
            } else {
                let expected = text
                    .replace(&values[0], "[address removed]")
                    .replace(&values[1], "[address removed]")
                    .replace(IBAN, "[iban removed]")
                    .replace(NINO, "[id removed]")
                    .replace(CARD, "[card removed]")
                    .replace(HEALTH, "[health removed]");
                assert_eq!(output, expected, "Open, seed {seed}");
                values
                    .iter()
                    .map(|value| {
                        let start = text.find(value).unwrap();
                        (start, start + value.len())
                    })
                    .collect()
            };
            let (main, deep) = (bytes(&main), bytes(&deep));
            let lost: Vec<_> = main
                .into_iter()
                .filter(|byte| !deep.contains(byte))
                .collect();
            assert!(lost.is_empty(), "{mode:?}, seed {seed}: lost {lost:?}");
        }
    }
}
