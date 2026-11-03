//! K-OVERMASK-FIVE: the common words an abbreviation row inflects to are not
//! health data. `FIV` is `FIV`, never `five`; `HIV` is `HIV`, never `hive`.
//! Every value below is invented.
//!
//! The differential at the end runs a mixed corpus against main, frozen in
//! `data/k_overmask_five_main.txt`: only the excepted words lose a mask.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}

use kernel_core::privacy::PrivacyMode;
use kernel_privacy::{EntityKind, Registry, Span};

use cases::{covered, masked, MODES};

/// The common words the abbreviations must not mask.
const CLEAR: &[&str] = &["five", "fives", "hive", "hived", "hiving"];

/// The mixed corpus of the differential: prose, health terms, the abbreviations
/// and the forms they inflect to.
const CORPUS: &[&str] = &[
    "Say hello in five words.",
    "I have five minutes.",
    "Five stars on the shop.",
    "The hive is busy today.",
    "a bee hive near the road.",
    "He hived the bees last week.",
    "They are hiving the bees now.",
    "The hives are quiet in June.",
    "hives on my skin after the walk.",
    "FIV en cours. ma FIV a échoué.",
    "IVF treatment goes on next week. fiv",
    "She has AIDS and diabetes.",
    "Patient with MS and pain.",
    "The note says z aidsom, then aidsa and aidsu.",
    "AVCs, IVGs, VIHs and TDAHs in the file.",
    "HIV-om and l'AVC in the note.",
    "Ordinary prose with no health word at all.",
];

/// The bytes that may go: the excepted word, on the line that carries it.
const GIVEN_BACK: &[(&str, &str)] = &[
    ("Say hello in five words.", "five"),
    ("I have five minutes.", "five"),
    ("Five stars on the shop.", "Five"),
    ("The hive is busy today.", "hive"),
    ("a bee hive near the road.", "hive"),
    ("He hived the bees last week.", "hived"),
    ("They are hiving the bees now.", "hiving"),
];

/// The mask ranges of main, one line per corpus line: the Private ranges, then
/// the Open ones.
const FIXTURE: &str = include_str!("data/k_overmask_five_main.txt");

/// The spans the recogniser finds in `text`.
fn spans(registry: &Registry, text: &str) -> Vec<Span> {
    registry.analyze(text)
}

/// One record per mode: `start-end` ranges joined by `,`.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    ranges.map_or("!".into(), |r| {
        r.iter().map(|(s, e)| format!("{s}-{e},")).collect()
    })
}

/// The ranges of one record.
fn parse(record: &str) -> Vec<(usize, usize)> {
    record
        .split(',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (start, end) = part.split_once('-').expect("a range");
            (start.parse().unwrap(), end.parse().unwrap())
        })
        .collect()
}

/// The byte range of the one value given back on this line, when the line is
/// one of [`GIVEN_BACK`].
fn given_back(text: &str) -> Option<(usize, usize)> {
    let (context, value) = GIVEN_BACK
        .iter()
        .find(|(context, _)| text.contains(context))?;
    let start = text.find(context)? + context.find(value)?;
    Some((start, start + value.len()))
}

#[test]
fn the_common_words_an_abbreviation_infects_to_stay_clear() {
    let registry = Registry::new();
    for word in CLEAR {
        let text = format!("{word}.");
        assert!(
            !spans(&registry, &text)
                .iter()
                .any(|span| span.kind == EntityKind::Health),
            "{word} is masked: {text}"
        );
    }
}

#[test]
fn the_health_forms_of_an_abbreviation_stay_hidden() {
    let registry = Registry::new();
    for (text, word) in [
        ("FIV en cours.", "FIV"),
        ("ma FIV a échoué.", "FIV"),
        ("IVF treatment goes on.", "IVF"),
        ("fiv", "fiv"),
        ("I did two IVFs last year.", "IVFs"),
        ("His PTSDs came back in June.", "PTSDs"),
        ("Her OCDs and COPDs are documented.", "OCDs"),
        ("Her OCDs and COPDs are documented.", "COPDs"),
        ("The note says z aidsom, then aidsa and aidsu.", "aidsom"),
        ("The note says z aidsom, then aidsa and aidsu.", "aidsa"),
        ("The note says z aidsom, then aidsa and aidsu.", "aidsu"),
        ("The file keeps aidses in the record.", "aidses"),
        ("AVCs, IVGs, VIHs and TDAHs in the file.", "AVCs"),
        ("AVCs, IVGs, VIHs and TDAHs in the file.", "IVGs"),
        ("AVCs, IVGs, VIHs and TDAHs in the file.", "VIHs"),
        ("AVCs, IVGs, VIHs and TDAHs in the file.", "TDAHs"),
        ("The CGTs met on Tuesday.", "CGTs"),
        ("HIV-om and l'AVC in the note.", "HIV"),
        ("HIV-om and l'AVC in the note.", "AVC"),
        ("hives on my skin after the walk.", "hives"),
        ("The hives are quiet in June.", "hives"),
    ] {
        let start = text.find(word).expect("the word is in the text");
        assert!(
            spans(&registry, text)
                .iter()
                .any(|span| span.start <= start && start + word.len() <= span.end),
            "{word} left in clear: {text}"
        );
    }
}

#[test]
fn the_differential_against_main_loses_only_the_excepted_words() {
    let lines: Vec<&str> = FIXTURE.lines().collect();
    assert_eq!(lines.len(), CORPUS.len(), "the fixture is out of date");
    for (line, text) in lines.iter().zip(CORPUS) {
        let (private, open) = line.split_once('|').expect("two modes");
        for (record, mode) in [private, open].iter().zip(MODES) {
            let before = parse(record);
            let after =
                masked(mode, text).unwrap_or_else(|| panic!("{text:?} {mode:?}: a new refusal"));
            for &(start, end) in &after {
                assert!(
                    before.iter().any(|&(s, e)| s <= start && end <= e),
                    "{text:?} {mode:?}: a new mask {start}-{end}"
                );
            }
            let in_before = |byte: &usize| before.iter().any(|&(s, e)| *byte >= s && *byte < e);
            let gone: Vec<usize> = before
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&byte| !covered(&after, byte, byte + 1))
                .collect();
            let named: Vec<usize> = given_back(text)
                .map(|(start, end)| (start..end).filter(in_before).collect())
                .unwrap_or_default();
            assert_eq!(
                gone, named,
                "{text:?} {mode:?}: only the excepted word may go"
            );
        }
    }
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    for text in CORPUS {
        let one = |mode: PrivacyMode| record(masked(mode, text));
        println!(
            "FIXTURE-ROW|{}|{}",
            one(PrivacyMode::Private),
            one(PrivacyMode::Open)
        );
    }
}
