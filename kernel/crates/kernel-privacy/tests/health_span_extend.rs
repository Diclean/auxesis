//! HEALTH-SPAN-EXTEND acceptance cases. All text is invented.
//! Baseline note: origin/main masks only its individual lexicon terms; it has
//! no mask for the added phrases, and leaves qualifiers outside existing terms.
#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};
const MAIN_NEGATIVE_OUTPUT: &str = include_str!("data/health_span_extend_main.txt");
// (condition, complete phrase). Four personal sentence frames produce 80 cases.
// Main leaves new terms clear and only masks the existing term in partial rows.
const TERMS: &[(&str, &str)] = &[
    ("ulcerative colitis", "ulcerative colitis"),
    (
        "early-onset multiple sclerosis",
        "early-onset multiple sclerosis",
    ),
    ("polycystic ovary syndrome", "polycystic ovary syndrome"),
    (
        "obsessive-compulsive disorder",
        "obsessive-compulsive disorder",
    ),
    ("anxiety and depression", "anxiety and depression"),
    ("chronic kidney disease", "chronic kidney disease"),
    ("type 2 diabetes", "type 2 diabetes"),
    ("idiopathic scoliosis", "idiopathic scoliosis"),
    ("stage 3 lung cancer", "stage 3 lung cancer"),
    ("post-viral fatigue", "post-viral fatigue"),
    (
        "right-sided chronic migraine",
        "right-sided chronic migraine",
    ),
    ("mild sleep apnea", "mild sleep apnea"),
    ("Crohn's disease", "Crohn's disease"),
    ("severe rheumatoid arthritis", "severe rheumatoid arthritis"),
    (
        "chronic obstructive pulmonary disease",
        "chronic obstructive pulmonary disease",
    ),
    ("traumatic brain injury", "traumatic brain injury"),
    ("severe bipolar disorder", "severe bipolar disorder"),
    ("scoliose idiopathique", "scoliose idiopathique"),
    ("maladie de Crohn chronique", "maladie de Crohn chronique"),
    ("diabète gestationnel", "diabète gestationnel"),
];
const NEGATIVE_EXPECTED: &[(&str, &str)] = &[
    (
        "The news covered chronic kidney disease in rural areas.",
        "The news covered [health removed] in rural areas.",
    ),
    (
        "News report: severe asthma cases rose this winter.",
        "News report: [health removed] cases rose this winter.",
    ),
    (
        "A product review mentions chronic migraine relief.",
        "A product review mentions [health removed] relief.",
    ),
    (
        "The company released a product named Type 2 Diabetes Care.",
        "The company released a product named Type 2 [health removed] Care.",
    ),
];
const NEGATIVE: &[&str] = &[
    "The newspaper covered ulcerative colitis research at the university.",
    "A history of multiple sclerosis appears in the 1910 archive.",
    "The Crohn's foundation opened a new office downtown.",
    "There is a depression in the road after the bridge.",
    "Economic depression affected the whole region for a decade.",
    "News: the clinic published a report on polycystic ovary syndrome.",
    "The word sclerosis appears in a linguistics textbook.",
    "The foundation for Crohn's research meets on Friday.",
    "A product called Bipolar Disorder is on sale.",
    "The economic forecast warns of a mild recession.",
    "This is a news article about anxiety and depression rates.",
    "The Crohn's Foundation annual report is available online.",
    "The phrase kidney disease appears in a translation guide.",
    "Road maintenance crews filled a depression in the lane.",
    "The economic depression is a chapter in the history book.",
    "A news story discusses polycystic ovary syndrome research.",
    "The documentary title is Multiple Sclerosis: A History.",
    "The lecture discussed obsessive-compulsive disorder in literature.",
    "The historical record says the king had bipolar disorder.",
    "The podcast discussed treatment-related neuropathy news.",
    "The city has a depression in the road near the station.",
    "The Crohn's Foundation is funding a research project.",
    "The news covered chronic kidney disease in rural areas.",
    "The word depression can describe a low area of land.",
    "A biography mentions the author's old diagnosis of epilepsy.",
    "News report: severe asthma cases rose this winter.",
    "The historical record lists ulcerative colitis in 1890.",
    "The lecture discusses Crohn's disease as a public health topic.",
    "The novel describes a fictional obsessive-compulsive disorder.",
    "A product review mentions chronic migraine relief.",
    "The phrase economic depression is often misunderstood.",
    "The city crew repaired a road depression after the storm.",
    "This newspaper article covers anxiety and panic disorder.",
    "The museum has a display on Parkinson's disease history.",
    "The phrase appears in an old medical history book.",
    "The company released a product named Type 2 Diabetes Care.",
    "The archive lists ulcerative colitis among rare terms.",
    "A catalog entry names polycystic ovary syndrome as a book title.",
    "The product called Ulcerative Colitis is fictional.",
    "A documentary title contains the words Polycystic Ovary Syndrome.",
    "The newspaper printed a crossword clue for ulcerative colitis.",
    "A company named its catalog PolyCystic Ovary Syndrome.",
    "The old index lists ulcerative colitis in a bibliography.",
    "The museum shop sells a poster called Traumatic Brain Injury.",
    "A history lecture quotes the phrase polycystic ovary syndrome.",
    "The archive catalog uses ulcerative colitis as a heading.",
    "I have diabetes, type 2 fonts are ugly.",
];
#[test]
fn personal_multword_conditions_are_covered_in_full_in_both_modes() {
    let frames = [
        "I've had {} since March.",
        "My daughter has {}.",
        "Je vis avec {}.",
        "Ek het {}.",
    ];
    let mut count = 0;
    for (condition, target) in TERMS {
        for frame in frames {
            let text = frame.replace("{}", condition);
            let start = text.find(target).expect("target in case");
            for mode in MODES {
                let (output, minted) = issue(mode, &text).expect("allowed");
                let mut actual = output;
                for (token, _) in minted {
                    actual = actual.replace(&format!("⟦{token}⟧"), "[health removed]");
                }
                assert_eq!(
                    actual,
                    text.replacen(target, "[health removed]", 1),
                    "{mode:?} {text:?}"
                );
                let ranges = masked(mode, &text).expect("allowed");
                assert!(
                    covered(&ranges, start, start + target.len()),
                    "{mode:?} {text:?}: {ranges:?}"
                );
            }
            count += 1;
        }
    }
    assert!(count >= 80);
    eprintln!("partial/none to full: {count}/{count} synthetic cases");
}
#[test]
fn negatives_keep_main_behavior_and_never_refuse() {
    assert!(NEGATIVE.len() >= 40);
    let expected: Vec<_> = MAIN_NEGATIVE_OUTPUT.lines().collect();
    assert_eq!(expected.len(), NEGATIVE.len());
    for (text, record) in NEGATIVE.iter().zip(expected) {
        let fields: Vec<_> = record.split('\t').collect();
        assert_eq!(fields.first().copied(), Some(*text));
        for (index, mode) in MODES.iter().enumerate() {
            let (mut output, minted) = issue(*mode, text).expect("allowed");
            for (token, _) in minted {
                output = output.replace(&format!("⟦{token}⟧"), "[health removed]");
            }
            let expected_output = NEGATIVE_EXPECTED
                .iter()
                .find(|(input, _)| input == text)
                .map_or(fields[index + 1], |(_, output)| *output);
            assert_eq!(output, expected_output, "{mode:?}: {text}");
        }
    }
    for text in NEGATIVE {
        for mode in MODES {
            assert!(masked(mode, text).is_some(), "refused {mode:?}: {text:?}");
        }
    }
}

#[test]
#[ignore = "freeze exact output from origin/main only"]
fn freeze_main_negative_outputs() {
    let mut records = Vec::new();
    for input in NEGATIVE {
        let outputs: Vec<String> = MODES
            .iter()
            .map(|&mode| {
                let (mut output, minted) = issue(mode, input).expect("main allows negative prose");
                for (token, _) in minted {
                    output = output.replace(&format!("⟦{token}⟧"), "[health removed]");
                }
                output
            })
            .collect();
        records.push(format!("{}\t{}\t{}", input, outputs[0], outputs[1]));
    }
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/health_span_extend_main.txt"
        ),
        records.join("\n") + "\n",
    )
    .expect("write main baseline fixture");
}

#[test]
fn localized_personal_conditions_are_covered() {
    const CASES: &[(&str, &str)] = &[
        (
            "Ma fille a une scoliose idiopathique.",
            "scoliose idiopathique",
        ),
        (
            "Je vis avec un trouble bipolaire de type II.",
            "trouble bipolaire de type II",
        ),
        ("Hy het ernstige depressie.", "ernstige depressie"),
        ("Nekem sclerosis multiplex van.", "sclerosis multiplex"),
        ("Jaz imam multiplo sklerozo.", "multiplo sklerozo"),
        ("Ek leef met Crohn se siekte.", "Crohn se siekte"),
        ("Ek het suikersiekte tipe 2.", "suikersiekte tipe 2"),
        ("Hul suikersiekte tipe 2.", "suikersiekte tipe 2"),
        ("Haar suikersiekte tipe 2.", "suikersiekte tipe 2"),
        ("我有多发性硬化症。", "多发性硬化症"),
        ("我女儿有特发性脊柱侧弯。", "特发性脊柱侧弯"),
        ("我有克罗恩病。", "克罗恩病"),
        ("我有慢性肾病。", "慢性肾病"),
        ("我有二型糖尿病。", "二型糖尿病"),
    ];
    for (text, target) in CASES {
        let start = text.find(target).expect("target in localized case");
        for mode in MODES {
            let (output, minted) = issue(mode, text).expect("allowed");
            let mut actual = output;
            for (token, _) in minted {
                actual = actual.replace(&format!("⟦{token}⟧"), "[health removed]");
            }
            assert_eq!(
                actual,
                text.replacen(target, "[health removed]", 1),
                "{mode:?}: {text}"
            );
            assert!(covered(
                &masked(mode, text).unwrap(),
                start,
                start + target.len()
            ));
        }
    }
}

#[test]
fn extension_stops_at_lines_sentences_and_six_tokens() {
    let cases = [
        (
            "I have chronic\nsevere asthma.",
            "I have chronic\n[health removed].",
        ),
        (
            "My chronic. Severe asthma.",
            "My chronic. [health removed].",
        ),
        (
            "I have early onset stage 2 left right bilateral chronic asthma.",
            "I have early onset stage [health removed].",
        ),
        ("I have ulcerative\ncolitis.", "I have ulcerative\ncolitis."),
        ("I have ulcerative-\ncolitis.", "I have [health removed]."),
    ];
    for (text, expected) in cases {
        for mode in MODES {
            let (mut output, minted) = issue(mode, text).expect("allowed");
            for (token, _) in minted {
                output = output.replace(&format!("⟦{token}⟧"), "[health removed]");
            }
            assert_eq!(output, expected, "{mode:?}: {text}");
        }
    }
}

#[test]
fn condition_qualifiers_cross_one_separator_without_crossing_sentence_context() {
    const POSITIVES: &[(&str, &str)] = &[
        ("I have diabetes, type 2.", "diabetes, type 2"),
        ("I have type 2\ndiabetes.", "type 2\ndiabetes"),
        ("I have type 2\r\ndiabetes.", "type 2\r\ndiabetes"),
        ("mijn tipe 2 suikersiekte.", "tipe 2 suikersiekte"),
        ("I have diabète, type 1.", "diabète, type 1"),
        ("Ek het suikersiekte, tipe 2.", "suikersiekte, tipe 2"),
        ("I have stage 3\nbreast cancer.", "stage 3\nbreast cancer"),
    ];
    for (text, target) in POSITIVES {
        let start = text.find(target).expect("target in positive case");
        for mode in MODES {
            let ranges = masked(mode, text).expect("allowed");
            assert!(
                covered(&ranges, start, start + target.len()),
                "{mode:?}: {text:?}: {ranges:?}"
            );
            let (mut output, minted) = issue(mode, text).expect("allowed");
            for (token, _) in minted {
                output = output.replace(&format!("⟦{token}⟧"), "[health removed]");
            }
            assert_eq!(
                output,
                text.replacen(target, "[health removed]", 1),
                "{mode:?}: {text:?}"
            );
        }
    }

    let text = "I have diabetes, type 2 fonts are ugly.";
    for text in [
        text,
        "I have diabetes,type 2.",
        "I have type 2\n\ndiabetes.",
        "I have type 2.\ndiabetes.",
    ] {
        for mode in MODES {
            let (mut output, minted) = issue(mode, text).expect("allowed");
            for (token, _) in minted {
                output = output.replace(&format!("⟦{token}⟧"), "[health removed]");
            }
            assert_eq!(
                output,
                text.replacen("diabetes", "[health removed]", 1),
                "{mode:?}: unrelated or sentence-separated classifier must remain clear: {text:?}"
            );
        }
    }
}

const DIFF_MAIN: &str = include_str!("data/health_span_extend_diff_main.txt");
const DIFF_TERMS: &[&str] = &[
    "ulcerative colitis",
    "polycystic ovary syndrome",
    "chronic kidney disease",
    "type 2 diabetes",
    "idiopathic scoliosis",
    "post viral fatigue",
    "chronic obstructive pulmonary disease",
    "traumatic brain injury",
    "rheumatoid arthritis",
    "maladie de Crohn",
    "insuffisance renale chronique",
    "veelvuldige sklerose",
    "Crohn se siekte",
    "krónikus veseelégtelenség",
    "multiplo sklerozo",
    "多发性硬化症",
];
const NEGATIVE_DIFF_TERMS: &[&str] = &[
    "ulcerative colitis",
    "polycystic ovary syndrome",
    "traumatic brain injury",
];

fn differential_inputs() -> Vec<(String, Option<(usize, usize)>)> {
    let mut cases = Vec::with_capacity(2_000);
    for index in 0..1_000 {
        let term = DIFF_TERMS[index % DIFF_TERMS.len()];
        let text = format!("I have {term}; invented note {index}.");
        let start = text.find(term).expect("condition in positive input");
        cases.push((text, Some((start, start + term.len()))));
    }
    for index in 0..1_000 {
        let term = NEGATIVE_DIFF_TERMS[index % NEGATIVE_DIFF_TERMS.len()];
        cases.push((format!("News archive entry {index} mentions {term}."), None));
    }
    cases
}

fn encoded_ranges(ranges: Option<Vec<(usize, usize)>>) -> String {
    ranges.map_or_else(
        || "!".to_string(),
        |ranges| {
            ranges
                .iter()
                .map(|(start, end)| format!("{start}-{end},"))
                .collect()
        },
    )
}

fn decoded_ranges(record: &str) -> Option<Vec<(usize, usize)>> {
    if record == "!" {
        return None;
    }
    Some(
        record
            .split(',')
            .filter_map(|range| {
                let (start, end) = range.split_once('-')?;
                Some((start.parse().ok()?, end.parse().ok()?))
            })
            .collect(),
    )
}

fn input_header(inputs: &[(String, Option<(usize, usize)>)]) -> String {
    let bytes = inputs.iter().flat_map(|(text, _)| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

#[test]
#[ignore = "freeze exact ranges from origin/main only"]
fn freeze_2000_input_differential_baseline() {
    let inputs = differential_inputs();
    let rows: Vec<String> = inputs
        .iter()
        .map(|(text, _)| {
            MODES
                .iter()
                .map(|&mode| encoded_ranges(masked(mode, text)))
                .collect::<Vec<_>>()
                .join("|")
        })
        .collect();
    let fixture = format!("{}\n{}\n", input_header(&inputs), rows.join("\n"));
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/health_span_extend_diff_main.txt"
        ),
        fixture,
    )
    .expect("write main differential fixture");
}

#[test]
fn strict_superset_of_main_on_2000_inputs_in_both_modes() {
    let inputs = differential_inputs();
    let (header, records) = DIFF_MAIN.split_once('\n').expect("baseline header");
    assert_eq!(
        header,
        input_header(&inputs),
        "inputs changed: refreeze on origin/main"
    );
    let records: Vec<_> = records.lines().collect();
    assert_eq!(records.len(), inputs.len());
    for ((text, target), record) in inputs.iter().zip(records) {
        let main: Vec<_> = record.split('|').map(decoded_ranges).collect();
        for (mode_index, mode) in MODES.iter().enumerate() {
            let now = masked(*mode, text).unwrap_or_else(|| panic!("refused {mode:?}: {text}"));
            let baseline = main[mode_index].as_deref().unwrap_or(&[]);
            for &(start, end) in baseline {
                for byte in start..end {
                    assert!(
                        covered(&now, byte, byte + 1),
                        "lost byte {byte} {mode:?}: {text}"
                    );
                }
            }
            if let Some((start, end)) = target {
                assert!(
                    covered(&now, *start, *end),
                    "partial condition {mode:?}: {text}"
                );
            } else {
                assert_eq!(
                    now, baseline,
                    "unframed news/history changed {mode:?}: {text}"
                );
            }
        }
    }
    eprintln!(
        "strict superset: {} differential inputs, both modes",
        inputs.len()
    );
}

#[test]
#[ignore = "release timing: run with --release --ignored extension_timing_scales_linearly"]
fn extension_timing_scales_linearly() {
    const SIZES: &[usize] = &[16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024];
    const UNITS: &[(&str, &str)] = &[
        ("and-chain", "I have anxiety and depression. "),
        (
            "prose",
            "News report: severe asthma cases rose this winter. ",
        ),
    ];
    for (name, unit) in UNITS {
        for mode in MODES {
            let mut samples = Vec::new();
            for &size in SIZES {
                let mut text = unit.repeat(size / unit.len() + 1);
                text.truncate(size);
                let mut best = std::time::Duration::MAX;
                for _ in 0..3 {
                    let started = std::time::Instant::now();
                    assert!(masked(mode, &text).is_some(), "refused {mode:?}");
                    best = best.min(started.elapsed());
                }
                samples.push(best);
            }
            let ratios: Vec<f64> = samples
                .windows(2)
                .map(|step| step[1].as_secs_f64() / step[0].as_secs_f64())
                .collect();
            eprintln!("{name} {mode:?}: {samples:?}; 4x ratios {ratios:?}");
            assert!(
                ratios.iter().all(|ratio| *ratio <= 6.0),
                "{name} {mode:?} 4x timing exceeded 6x: {ratios:?}"
            );
        }
    }
}
