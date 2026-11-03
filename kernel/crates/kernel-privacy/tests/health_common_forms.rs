//! HEALTH-RECALL-1 acceptance: the common health forms of a freelancer's mail
//! or notes are hidden in both modes, and near-miss words keep their text.
//! Every sentence is invented. In each case a `[value]` must be hidden.

use std::time::{Duration, Instant};

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};

/// Main's hidden ranges for [`inputs`], frozen by [`freeze`] on origin/main.
const FIXTURE: &str = include_str!("data/health_common_forms_main.txt");

const CASES: &[&str] = &[
    // Diagnoses and conditions, EN.
    "I was diagnosed with [type 1 diabetes] last spring, so lunches are tricky.",
    "Sorry for the slow reply, I have been fighting [depression] since the summer.",
    "My partner starts [chemotherapy] on Monday, so I will work half days.",
    "I am [HIV positive] and my [viral load] is undetectable now.",
    "I'm off for two weeks with [burn-out], back on the 12th.",
    "Good news, I'm [pregnant] and due in March.",
    "My son has [autism] and his school calls me often.",
    "I have [breast cancer] and start [radiotherapy] next week.",
    "My mum had a [stroke] last night, I'm at the hospital.",
    "I have [epilepsy], so I cannot drive to the client.",
    "I had a [panic attack] just before the pitch.",
    "Sorry, I'm in bed with [pneumonia] this week.",
    // Medications and doses, EN.
    "I take [sertraline 50 mg] every morning.",
    "Remind me to pick up my [metformin 500 mg] at the pharmacy.",
    "The doctor put me on [ibuprofen 400 mg] for my back.",
    "I'm on [antidepressants] again, so I may be slow.",
    // Treatments and appointments, EN.
    "I have a [therapy session] at 4 pm, can we move the call?",
    "Thursday I have an appointment with my [psychiatrist].",
    "I'm recovering from [knee surgery] and work from home.",
    "I see my [physiotherapist] twice a week for my shoulder.",
    "I have an [MRI scan] on Tuesday for my headaches.",
    // Sick leave and disability, EN.
    "I'm on [sick leave] for my back until Friday.",
    "I use a [wheelchair] since the accident, so the venue needs a ramp.",
    "I have a [disability], please book the accessible room.",
    // Lab results, EN.
    "My [HbA1c is 8.1 %], the nurse wants to see me again.",
    "My [blood test] came back and my [cholesterol] is too high.",
    // Diagnoses and conditions, FR.
    "On m'a diagnostiqué un [diabète de type 2] l'an dernier.",
    "Je suis en [dépression] depuis l'été, je réponds plus lentement.",
    "Je suis [enceinte] de quatre mois.",
    "Je suis [séropositif] depuis 2019.",
    "J'ai un [cancer de la prostate] et je vois l'[oncologue] mardi.",
    "Je fais un [burn-out], je reprends en janvier.",
    "Je suis [diabétique] et je dois manger à heure fixe.",
    // Medications and doses, FR.
    "Mon médecin m'a prescrit du [paracétamol 1 g] trois fois par jour.",
    "Je prends de la [lévothyroxine 75 µg] chaque matin.",
    // Treatments and appointments, FR.
    "J'ai rendez-vous chez le [psychiatre] jeudi à 10 h.",
    "Ma femme commence sa [chimiothérapie] lundi.",
    "J'ai une [séance de kiné] demain matin.",
    "J'ai une [IRM] lundi pour mon genou.",
    "Ma [séance de psychothérapie] est décalée à 18 h.",
    // Sick leave, disability, lab results, FR.
    "Je suis en [arrêt maladie] jusqu'au 15 novembre.",
    "Mon fils est [handicapé], il a besoin d'un accompagnant.",
    "Je suis en [mi-temps thérapeutique] jusqu'en mars.",
    "Ma [prise de sang] montre une [glycémie] trop haute.",
    // FR without accents.
    "Je suis en [arret maladie] cette semaine.",
    "Je commence la [chimiotherapie] lundi.",
    "Je suis en [depression] depuis mai.",
    "Rdv chez le [psychiatre] demain matin.",
    "Je fais un [burnout], je dois m'arreter.",
    "J'ai un [diabete de type 1] depuis l'enfance.",
    "Je suis [seropositive] et sous traitement.",
    "J'ai rendez-vous chez le [gynecologue] vendredi.",
];

/// Plain words next to health vocabulary, with no health value in them.
const NEAR_MISSES: &[&str] = &[
    "Please be patient, the invoice will arrive next week.",
    "I need a break from this project for a week.",
    "The back office is closed on Friday.",
    "Let's book an appointment with the accountant.",
    "The session starts at 10, see you there.",
    "Our team is on leave for the holidays.",
    "The test results for the website are green.",
    "The lab is open for the design workshop.",
    "Le rendez-vous avec le comptable est jeudi.",
    "Merci de votre patience, la facture arrive.",
    "Je suis en congé la semaine prochaine.",
    "La séance de travail commence à 9 h.",
    "Les résultats du trimestre sont bons.",
    "Le cabinet d'architecte a envoyé les plans.",
    "Le résultat de l'analyse de marché est prêt.",
];

/// The text without brackets and the byte ranges of its bracketed values.
fn parse_case(case: &str) -> (String, Vec<(usize, usize)>) {
    let (mut text, mut values, mut open) = (String::new(), Vec::new(), 0);
    for ch in case.chars() {
        match ch {
            '[' => open = text.len(),
            ']' => values.push((open, text.len())),
            _ => text.push(ch),
        }
    }
    (text, values)
}

/// Every value missed in a mode, as `mode text value`.
fn misses() -> (usize, Vec<String>) {
    let (mut total, mut missed) = (0, Vec::new());
    for case in CASES {
        let (text, values) = parse_case(case);
        for (start, end) in values {
            total += 1;
            for mode in MODES {
                let hidden = masked(mode, &text).is_some_and(|r| covered(&r, start, end));
                if !hidden {
                    missed.push(format!("{mode:?} {text:?} -> {:?}", &text[start..end]));
                }
            }
        }
    }
    (total, missed)
}

#[test]
fn common_health_forms_are_hidden_in_both_modes() {
    assert!(CASES.len() >= 40, "only {} cases", CASES.len());
    let (total, missed) = misses();
    eprintln!(
        "health values {total} x 2 modes, missed {}:\n{}",
        missed.len(),
        missed.join("\n")
    );
    assert!(missed.is_empty(), "{} misses", missed.len());
}

#[test]
fn near_misses_keep_their_text_in_both_modes() {
    assert!(NEAR_MISSES.len() >= 15);
    for text in NEAR_MISSES {
        for mode in MODES {
            let (out, _) = issue(mode, text).expect("allowed");
            assert_eq!(out, *text, "{mode:?} changed a near miss");
        }
    }
}

/// Linear time: 10x the input takes at most 20x the time.
#[test]
fn common_health_forms_stay_linear() {
    let unit: String = CASES.iter().map(|case| parse_case(case).0 + " ").collect();
    let time = |n: usize| {
        let text = unit.repeat(n);
        let started = Instant::now();
        issue(MODES[0], &text).expect("allowed");
        started.elapsed()
    };
    let small = time(2).max(Duration::from_millis(1));
    let large = time(20);
    assert!(large <= small * 20, "10x input took {large:?} vs {small:?}");
}

/// The differential inputs: the cases above, then the in-repo privacy-eval
/// cases and prose lines. `true` marks a text with no health value, whose new
/// masks count as over-masks.
fn inputs() -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = CASES.iter().map(|c| (parse_case(c).0, false)).collect();
    out.extend(NEAR_MISSES.iter().map(|text| (text.to_string(), true)));
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
                if dir == "prose" {
                    out.push((line.to_string(), true));
                    continue;
                }
                let case: serde_json::Value = serde_json::from_str(line).expect("JSON");
                let health = case["spans"].as_array().into_iter().flatten().any(|s| {
                    s["type"]
                        .as_str()
                        .is_some_and(|t| t.eq_ignore_ascii_case("health"))
                });
                out.push((case["text"].as_str().expect("text").to_string(), !health));
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

/// A strict byte superset of main in both modes, no new refusal; prints the
/// texts with no health value that gained a mask (the over-mask count).
#[test]
fn strict_superset_of_main_with_overmask_count() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut over, mut gained) = ([0usize; 2], 0, [0usize; 2], [0usize; 2]);
    for ((text, clean), record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let now = masked(MODES[index], text);
            if now.is_none() {
                refused += usize::from(main.is_some());
                continue;
            }
            let (now, main) = (now.unwrap_or_default(), main.unwrap_or_default());
            lost[index] += main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if now != main {
                gained[index] += 1;
                // A region main already masked may widen (GATE-REGISTRY-GAP-1:
                // Private hides the label Open removes); only a region that
                // overlaps none of main's is a new mask.
                let new_region = now
                    .iter()
                    .any(|&(s, e)| !main.iter().any(|&(ms, me)| ms < e && s < me));
                over[index] += usize::from(*clean && new_region);
                if *clean && new_region {
                    eprintln!("over-mask {:?} {text:.80?}: now {now:?}", MODES[index]);
                }
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; texts with \
         new masks {gained:?}; of them with a new region and no health value (over-mask) {over:?}",
        inputs.len()
    );
    assert!(inputs.len() >= 900, "only {} inputs", inputs.len());
    assert_eq!((lost, refused), ([0, 0], 0));
    assert_eq!(over, [0, 0], "new masks on texts with no health value");
}
