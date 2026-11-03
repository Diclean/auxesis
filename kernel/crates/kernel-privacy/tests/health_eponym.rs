//! HEALTH-EPONYM-1 acceptance: a condition named after a person is hidden in
//! both modes; the same surname as a person, firm or street keeps its text.
//! Every sentence is invented. A surname is part of a condition only when:
//! - a medical head follows it (`disease`, `syndrome`, `palsy`, `lymphoma`,
//!   `thyroiditis`, `chorea`, `sarcoma`), or a French head and `de` precede it
//!   (`maladie`, `syndrome`, `thyroïdite`, `lymphome`, `chorée`, `sarcome`),
//!   or it is a fixed name (`Lou Gehrig's disease`, `paralysie de Bell`…);
//! - its possessive stands alone (`I have Hashimoto's`): only a clause end or
//!   a linking word (`and`, `so`…) follows, and no honorific or place word
//!   (`Ms Hashimoto's.`, `at Hashimoto's`) precedes it.
//!
//! A bare surname never is. `Alzheimer`, `Parkinson` and `Crohn` were bare
//! terms before this pass and stay masked even as a surname (`Mr Parkinson`):
//! a privacy fix only adds.

use std::time::{Duration, Instant};

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};

/// Main's hidden ranges for [`inputs`], frozen by [`freeze`] on origin/main.
const FIXTURE: &str = include_str!("data/health_eponym_main.txt");

const CASES: &[&str] = &[
    // EN, a medical head after the surname.
    "I was diagnosed with [Hashimoto thyroiditis] last year, so I tire easily.",
    "My doctor confirmed [Hashimoto's thyroiditis] in May.",
    "My brother has [Crohn's disease] and misses some meetings.",
    "Our son has [Asperger syndrome] and prefers written briefs.",
    "He has [Tourette syndrome], the tics are harmless.",
    "I have [Raynaud's phenomenon], so cold rooms hurt my hands.",
    "She has [Graves' disease] and sees a specialist in June.",
    "He was diagnosed with [Addison's disease] in 2021.",
    "She has [Cushing's syndrome] and works part time.",
    "His mother died of [Huntington's disease] last year.",
    "Her aunt had [Huntington's chorea] for ten years.",
    "My uncle has [Lou Gehrig's disease] and works from home.",
    "Our daughter has [Down syndrome] and starts school in September.",
    "He is treated for [Hodgkin lymphoma] at the clinic.",
    "He had non-[Hodgkin lymphoma] two years ago.",
    "I woke up with [Bell's palsy] and cannot present today.",
    "I have [Ménière's disease], so I avoid flights.",
    "She is in remission from [Ewing's sarcoma].",
    // EN, a possessive used alone.
    "I have [Hashimoto]'s, so mornings are slow.",
    "My father has [Parkinson]'s and needs care on Tuesdays.",
    "My grandmother has [Alzheimer]'s, I visit her on Fridays.",
    "Our son has [Asperger]'s, so please send the agenda early.",
    "She has [Tourette]'s and may need short breaks.",
    "I have [Raynaud]'s and wear gloves in the office.",
    "He has [Addison]'s, so he carries his tablets.",
    "He tested positive for [Huntington]'s and is very quiet.",
    "He is in remission from [Hodgkin]'s, thanks for asking.",
    "My mother has [Cushing]'s since the spring.",
    "My dad lives with [Ménière]'s.",
    // FR.
    "Je suis suivie pour une [maladie de Crohn] depuis 2018.",
    "Ma mère a la [maladie d'Alzheimer], je pars plus tôt.",
    "Mon père a la [maladie de Parkinson] et je l'accompagne lundi.",
    "J'ai une [thyroïdite de Hashimoto], je suis souvent fatiguée.",
    "Mon fils a le [syndrome d'Asperger], merci d'envoyer l'ordre du jour.",
    "Il a le [syndrome de Gilles de la Tourette] depuis l'enfance.",
    "Elle a la [maladie de Basedow] et prend un traitement.",
    "J'ai une [paralysie de Bell] depuis lundi.",
    "Il est soigné pour un [lymphome de Hodgkin].",
    "Il a eu un [lymphome] non [hodgkinien] l'an dernier.",
    "Elle a la [maladie de Ménière] et évite l'avion.",
    "Il a la [maladie de Huntington], sa sœur aussi.",
    "Elle a une [chorée de Huntington] depuis 2020.",
    "Elle a un [syndrome de Cushing] et travaille à mi-temps.",
    "Il souffre de la [maladie d'Addison].",
    "J'ai le [syndrome de Raynaud] en hiver.",
];

/// The same surnames as people, firms, places and plain words: no health value.
const NEGATIVES: &[&str] = &[
    "Down the road there is a good cafe for the meeting.",
    "Our office moved to Graves Street last month.",
    "Graves and Partners sent the brief.",
    "Call Ms Hashimoto about the new logo.",
    "Ms Hashimoto's invoice is attached.",
    "The blue folder is Ms Hashimoto's.",
    "Kenji Hashimoto's team sent the slides.",
    "We had dinner at Hashimoto's last night.",
    "Bell's new shop opens on Monday.",
    "The Bell project is late again.",
    "Addison Lee will pick you up at 9.",
    "Addison's report is due on Friday.",
    "Lunch at Addison's, then the pitch.",
    "Hodgkin Ltd sent the quote this morning.",
    "Raynaud Consulting signed the contract.",
    "Tourette Avenue is closed for works.",
    "Huntington Beach is on the client list.",
    "Huntington's new office opens in May.",
    "The Cushing office needs new chairs.",
    "Thanks, Asperger GmbH paid the invoice.",
    "Mme Ménière arrive demain avec les plans.",
    "Rendez-vous chez Raynaud à 10 h.",
    "Le cabinet Basedow et Fils a envoyé la facture.",
    "La rue Hodgkin est fermée jeudi.",
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

#[test]
fn eponymous_conditions_are_hidden_in_both_modes() {
    let mut missed = Vec::new();
    for case in CASES {
        let (text, values) = parse_case(case);
        for (start, end) in values {
            for mode in MODES {
                if !masked(mode, &text).is_some_and(|r| covered(&r, start, end)) {
                    missed.push(format!("{mode:?} {text:?} -> {:?}", &text[start..end]));
                }
            }
        }
    }
    assert!(
        missed.is_empty(),
        "{} misses:\n{}",
        missed.len(),
        missed.join("\n")
    );
}

#[test]
fn surnames_without_a_condition_keep_their_text() {
    for text in NEGATIVES {
        for mode in MODES {
            let (out, _) = issue(mode, text).expect("allowed");
            assert_eq!(out, *text, "{mode:?} changed a plain surname");
        }
    }
}

/// Linear time: 10x the input takes at most 20x the time, on the cases and on
/// long runs of the shapes the rules walk (heads, `de`, possessives).
#[test]
fn eponym_rules_stay_linear() {
    let cases: String = CASES.iter().map(|case| parse_case(case).0 + " ").collect();
    let units = [
        cases,
        "Hashimoto's ".into(),
        "I have Hashimoto's, ".into(),
        "syndrome de Gilles de la ".into(),
        "Lou Gehrig's Bell's palsy-".into(),
    ];
    for unit in units {
        let time = |n: usize| {
            let text = unit.repeat(n);
            // The fastest of three runs: a loaded machine must not decide a bound.
            (0..3)
                .map(|_| {
                    let started = Instant::now();
                    issue(MODES[0], &text).expect("allowed");
                    started.elapsed()
                })
                .min()
                .unwrap_or_default()
        };
        let small = time(40).max(Duration::from_millis(1));
        let large = time(400);
        assert!(
            large <= small * 20,
            "{unit:.30?}: 10x took {large:?} vs {small:?}"
        );
    }
}

fn inputs() -> Vec<String> {
    let cases = CASES.iter().map(|case| parse_case(case).0);
    cases
        .chain(NEGATIVES.iter().map(|t| t.to_string()))
        .collect()
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

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let lines: Vec<String> = inputs()
        .iter()
        .map(|text| MODES.map(|mode| record(masked(mode, text))).join("|") + ";")
        .collect();
    println!("FIXTURE-BEGIN\n{}\nFIXTURE-END", lines.join("\n"));
}

/// A strict byte superset of main in both modes, with no new refusal.
#[test]
fn strict_superset_of_main() {
    let inputs = inputs();
    let records: Vec<&str> = FIXTURE
        .trim()
        .split_terminator(';')
        .map(str::trim)
        .collect();
    assert_eq!(
        records.len(),
        inputs.len(),
        "inputs changed: refreeze on main"
    );
    for (text, record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let now = masked(MODES[index], text);
            assert!(now.is_some() || main.is_none(), "new refusal {text:?}");
            let (now, main) = (now.unwrap_or_default(), main.unwrap_or_default());
            let lost = main.iter().flat_map(|&(s, e)| s..e);
            assert!(
                lost.clone().all(|b| covered(&now, b, b + 1)),
                "{:?} exposes main bytes in {text:?}: main {main:?} now {now:?}",
                MODES[index]
            );
        }
    }
}
