//! HEALTH-LABEL-1 acceptance: a blood type across a line break or glued to its
//! label, a health word glued to a short prefix or suffix or written with
//! look-alike letters, and a labelled record number are hidden in both modes.
//! All values are fictional.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, NameDictionary};

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

/// Main's hidden ranges for [`inputs`], frozen by [`freeze`] on origin/main.
const FIXTURE: &str = include_str!("data/health_label_1_main.txt");

fn gate(mode: PrivacyMode) -> Gate {
    let ctx = Context {
        destination: Destination::Vendor("health-label-1".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be admitted");
    };
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).expect("dictionary"));
    Gate::for_grant_with_dictionary(&grant, [7; 32], names)
}

/// The gate output with its tokens and removal marks taken out.
fn clear_of(out: &str) -> String {
    let out: String = out
        .split('⟦')
        .map(|part| part.split_once('⟧').map_or(part, |(_, rest)| rest))
        .collect();
    out.split('[')
        .map(|part| part.split_once(" removed]").map_or(part, |(_, rest)| rest))
        .collect()
}

/// Each `(text, pieces)`: no piece is left in clear (case-insensitive) in either mode.
fn wrong_cases(cases: &[(&str, &[&str])]) -> Vec<String> {
    let mut wrong = Vec::new();
    for (text, pieces) in cases {
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            match gate(mode).text(text) {
                Ok((out, _)) => {
                    let clear = clear_of(out.as_str()).to_lowercase();
                    for piece in *pieces {
                        if clear.contains(&piece.to_lowercase()) {
                            wrong.push(format!("{mode:?} {text:?} -> {:?}", out.as_str()));
                            break;
                        }
                    }
                }
                Err(error) => wrong.push(format!("{mode:?} {text:?} refused: {error:?}")),
            }
        }
    }
    wrong
}

fn assert_all_hidden(cases: &[(&str, &[&str])]) {
    let wrong = wrong_cases(cases);
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Scope 1: a blood type after a line break, glued to its label or to a suffix.
#[test]
fn a_blood_type_across_a_break_or_glued_is_hidden() {
    assert_all_hidden(BLOOD);
}

/// Scope 2: a health word glued to a short ASCII prefix or suffix.
#[test]
fn a_health_word_glued_to_a_short_prefix_or_suffix_is_hidden() {
    assert_all_hidden(GLUED);
}

/// Scope 3: Cyrillic or Greek look-alikes inside an otherwise Latin health word.
#[test]
fn a_health_word_with_look_alike_letters_is_hidden() {
    assert_all_hidden(LOOKALIKE);
}

/// Scope 4: a labelled record or plan number is hidden, value included.
#[test]
fn a_labelled_record_number_is_hidden() {
    assert_all_hidden(RECORDS);
}

/// Review round 1: the parenthesised plan label, quoted CSV cells, every blood
/// column of a header, a stem behind a tag and a short sign with a tag.
#[test]
fn review_round_one_forms_are_hidden() {
    assert_all_hidden(ROUND1);
}

/// A blood column is read down to its 10,000th row, each row once.
#[test]
fn a_blood_column_is_read_for_ten_thousand_rows() {
    let mut text = String::from("id,blood_type,city\n");
    for row in 1..=10_000 {
        text.push_str(&format!("{row},AB negative,Lyon\n"));
    }
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let (out, _) = gate(mode).text(&text).expect("issued");
        let clear = clear_of(out.as_str());
        assert!(!clear.contains("negative"), "{mode:?} left a row in clear");
    }
}

/// A sign word that is only the start of an adverb is not taken whole.
#[test]
fn an_adverb_after_a_blood_group_keeps_its_text() {
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let (out, _) = gate(mode)
            .text("Blood type: AB negatively affects nothing.")
            .expect("issued");
        assert!(
            out.as_str().contains("negatively affects"),
            "{mode:?} {out:?}"
        );
    }
}

const ROUND1: &[(&str, &[&str])] = &[
    ("health plan (beneficiary) number: 61850437", &["61850437"]),
    ("Health plan (beneficiary) number 61850437", &["61850437"]),
    (
        "id,blood_type,city\n\"fictional,subject\",AB negative,Tours",
        &["AB negative", "negative"],
    ),
    (
        "id,blood_type,city\n\"a \"\"b\"\", c\",\"O+\",Tours",
        &["O+"],
    ),
    (
        "id,blood_type,groupe_sanguin\n17,A+,O\u{2212}",
        &["A+", "O\u{2212}"],
    ),
    ("id;groupe_sanguin;blood_group\n17;B-;AB+", &["B-", "AB+"]),
    ("refdiabetic", &["diabet"]),
    ("id42depressive", &["depress"]),
    ("Blood type: B posok", &["posok"]),
    ("Blood type: A negok", &["negok"]),
];

const BLOOD: &[(&str, &[&str])] = &[
    ("Blood type\nAB\nnegative", &["AB", "negative"]),
    ("Blood type:AB\r\nnegative", &["AB", "negative"]),
    ("Blood typerefAB negative", &["AB negative", "negative"]),
    ("Blood type:AB negativeok", &["AB", "negative"]),
    ("Blood group\nO\npos", &["\nO", "pos"]),
    ("Groupe sanguin\r\nA\r\npositif", &["\r\nA", "positif"]),
    ("blood type\nB-", &["B-"]),
    ("Rh: O negative", &["O negative"]),
    (
        "id,blood_type,city\n17,AB negative,Lyon",
        &["AB negative", "negative"],
    ),
    (
        "id;groupe_sanguin;ville\n17;O positif;Lyon",
        &["O positif", "positif"],
    ),
];

const GLUED: &[(&str, &[&str])] = &[
    ("chimiothérapieok", &["chimioth"]),
    ("refchimiothérapie", &["chimioth"]),
    ("refCHIMIOTHÉRAPIE", &["chimioth"]),
    ("CHIMIOTHÉRAPIEok", &["chimioth"]),
    ("chemotherapyok", &["chemotherap"]),
    ("id42diabetes", &["diabet"]),
    ("diabetesID", &["diabet"]),
];

const LOOKALIKE: &[(&str, &[&str])] = &[
    (
        "DI\u{410}\u{412}\u{415}\u{422}\u{415}S",
        &["DI\u{410}\u{412}"],
    ),
    ("di\u{430}betes", &["di\u{430}bet"]),
    ("DI\u{391}BETES", &["DI\u{391}BET"]),
    ("chemoth\u{435}rapy", &["chemoth"]),
];

const RECORDS: &[(&str, &[&str])] = &[
    ("MRN: 00438291", &["00438291"]),
    ("MRN 00438291", &["00438291"]),
    ("medical record number: 55120934", &["55120934"]),
    ("Medical record number 55120934", &["55120934"]),
    ("patient ID: 7730215", &["7730215"]),
    ("health plan beneficiary number: 88210044", &["88210044"]),
    ("Health plan number 88210044", &["88210044"]),
    ("NHS number: 401 023 2137", &["401 023 2137", "2137"]),
    ("numéro de sécurité sociale : 9912345", &["9912345"]),
];

/// Ordinary words that hold a health word or a label, kept in clear.
const TRAPS: &[&str] = &[
    "The bloodstream test is next week.",
    "Type A personalities and B-movies are fine.",
    "Group A won, group B lost.",
    "Rhythm and blues at 8.",
    "Our record number of visitors was 5000 last year.",
    "The patient identified the problem.",
    "Rhode Island and the Rhine.",
    "A positive attitude and a negative test.",
    "Your blood type matters for donations.",
    "The cancellation fee applies.",
    "Pancreatic juice and the panorama.",
    "Biochemistry and therapy dogs.",
    "Blood type\nis checked at the first visit.",
    "Blood type\nAnd more questions follow.",
    "Rh\nOK",
    "The raids, braids and maids archive.",
    "Hospitality staff read chapter 3.",
    "id,blood_type,city\n17,,Lyon",
    "Rhubarb pie, a Rhône cruise and an Rh factor talk.",
];

/// Ordinary words that merely hold a health word, and prose that names a label
/// without a value, keep their text.
#[test]
fn ordinary_words_and_traps_stay_clear() {
    for text in TRAPS {
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let (out, _) = gate(mode).text(text).expect("issued");
            assert_eq!(out.as_str(), *text, "{mode:?} changed prose");
        }
    }
}

/// Linear time: 10x the input takes at most 20x the time.
#[test]
fn glued_and_broken_inputs_stay_linear() {
    let unit = "Blood type\nAB\nnegative refchimiothérapie DI\u{410}\u{412}\u{415}\u{422}\u{415}S MRN: 00438291 ";
    let time = |n: usize| {
        let text = unit.repeat(n);
        let mut gate = gate(PrivacyMode::Private);
        let started = Instant::now();
        gate.text(&text).expect("issued");
        started.elapsed()
    };
    let small = time(20).max(Duration::from_millis(1));
    let large = time(200);
    assert!(large <= small * 20, "10x input took {large:?} vs {small:?}");
}

/// The differential inputs: every case above, then the in-repo privacy-eval
/// cases and prose lines. `true` marks a text that must not change at all.
fn inputs() -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = [BLOOD, GLUED, LOOKALIKE, RECORDS, ROUND1]
        .iter()
        .flat_map(|cases| cases.iter().map(|(text, _)| (text.to_string(), false)))
        .collect();
    out.extend(TRAPS.iter().map(|text| (text.to_string(), true)));
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    for dir in ["cases", "prose"] {
        let mut files: Vec<_> = std::fs::read_dir(format!("{root}/{dir}"))
            .expect("privacy-eval is readable")
            .map(|entry| entry.expect("entry").path())
            .collect();
        files.sort();
        for file in files {
            let raw = std::fs::read_to_string(file).expect("readable");
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let text = if dir == "prose" {
                    line.to_string()
                } else {
                    let case: serde_json::Value = serde_json::from_str(line).expect("JSON");
                    case["text"].as_str().expect("text").to_string()
                };
                out.push((text, dir == "prose"));
            }
        }
    }
    out
}

/// One record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    let join = |r: Vec<(usize, usize)>| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.map_or("!".into(), join)
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[(String, bool)]) -> String {
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

/// A strict byte superset of main in both modes, no new refusal, and no prose
/// line or trap changed.
#[test]
fn strict_superset_of_main_and_prose_unchanged() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut prose, mut gained) = ([0usize; 2], 0, 0, [0usize; 2]);
    for ((text, fixed), record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let now = masked(MODES[index], text);
            if now.is_none() {
                refused += usize::from(main.is_some());
                continue;
            }
            let (now, main) = (now.unwrap_or_default(), main.unwrap_or_default());
            let gone = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            lost[index] += gone;
            if now != main {
                gained[index] += 1;
                prose += usize::from(*fixed);
                eprintln!("{:?} {text:.80?}: main {main:?} now {now:?}", MODES[index]);
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; prose or \
         trap changes {prose}; texts with new masks Private/Open {gained:?}",
        inputs.len()
    );
    assert!(inputs.len() >= 900, "only {} inputs", inputs.len());
    assert_eq!((lost, refused, prose), ([0, 0], 0, 0));
}
