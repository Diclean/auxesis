//! NAMES-OFF round 2: a private gate hides no name, but a name can never take a
//! hard value with it, and the health values the name model used to hide by
//! chance are deterministic lexicon terms. All data is invented.

use std::sync::Arc;

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{ContactIndex, Gate, NameDictionary};

fn private_grant() -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("names-off-probe".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &ctx) else {
        panic!("a private grant must be admitted");
    };
    grant
}

/// The private SafeText of `input` with `name` as an imported contact.
fn with_contact(name: &str, input: &str) -> String {
    let mut contacts = ContactIndex::new();
    assert!(contacts
        .add_from_header(name, "fake@example.invalid")
        .is_some());
    let names: Vec<String> = contacts
        .people()
        .filter_map(|person| person.display_name.as_ref().map(|v| v.as_str().to_string()))
        .collect();
    let dictionary = Arc::new(NameDictionary::new(names).expect("dictionary"));
    let mut gate = Gate::for_grant_with_dictionary(&private_grant(), [91; 32], dictionary);
    gate.text(input)
        .expect("gate must issue")
        .0
        .as_str()
        .to_string()
}

/// The private SafeText of `input` with `name` in a names list.
fn with_names(name: &str, input: &str) -> String {
    let mut gate = Gate::for_grant_with_names(&private_grant(), [91; 32], [name]).expect("names");
    gate.text(input)
        .expect("gate must issue")
        .0
        .as_str()
        .to_string()
}

/// (contact name, input, a part of the hard value that must not survive).
/// Each name holds digits or an `@`, so the dictionary's span runs into the
/// hard value next to it.
const OVERLAPS: &[(&str, &str, &str)] = &[
    (
        "Camille Exemple 14",
        "DOB: Camille Exemple 14/03/1987",
        "03/1987",
    ),
    (
        "Camille Exemple 14/03/1987",
        "DOB: Camille Exemple 14/03/1987",
        "03/1987",
    ),
    (
        "Camille Exemple DOB: 14/03/1987",
        "Camille Exemple DOB: 14/03/1987",
        "03/1987",
    ),
    (
        "Camille Exemple born 14/03/1987",
        "Camille Exemple born 14/03/1987",
        "03/1987",
    ),
    (
        "Camille Exemple 4111",
        "Card: Camille Exemple 4111 1111 1111 1111",
        "1111 1111",
    ),
    (
        "Camille Exemple +33 6",
        "Call Camille Exemple +33 6 12 34 56 78",
        "12 34 56 78",
    ),
    (
        "Camille Exemple DE89",
        "IBAN: Camille Exemple DE89 3704 0044 0532 0130 00",
        "3704 0044",
    ),
    (
        "Camille Exemple camille@exemple",
        "Write to Camille Exemple camille@exemple.invalid",
        "@exemple",
    ),
    (
        "Camille Exemple QXZ12",
        "Passport: Camille Exemple QXZ1234567",
        "1234567",
    ),
];

#[test]
fn a_name_that_overlaps_a_hard_value_never_unmasks_it() {
    for &(name, input, value) in OVERLAPS {
        for out in [with_contact(name, input), with_names(name, input)] {
            assert!(
                !out.contains(value),
                "hard value left in clear: {input:?} -> {out:?}"
            );
        }
    }
}

#[test]
fn a_name_equal_to_or_holding_a_hard_value_never_unmasks_it() {
    for value in [
        "14/03/1987",
        "4111 1111 1111 1111",
        "+33612345678",
        "DE89 3704 0044 0532 0130 00",
        "probe@example.invalid",
        "219-09-9999",
    ] {
        let input = format!("DOB / card / phone / IBAN / mail / SSN: {value}");
        for name in [input.as_str(), value, &format!("Camille {value}")] {
            let out = with_names(name, &input);
            assert!(!out.contains(value), "{name:?}: {input:?} -> {out:?}");
        }
    }
}

#[test]
fn a_name_next_to_a_birth_date_stays_in_clear() {
    let out = with_contact("Camille Exemple", "DOB of Camille Exemple: 14/03/1987");
    assert!(out.contains("Camille Exemple"), "{out}");
    assert!(!out.contains("14/03/1987"), "{out}");
}

/// The 40 health probes of the c215879a seal review, plus the new medicines.
const HEALTH: &[(&str, &str)] = &[
    ("I have diabetes.", "diabetes"),
    ("My son has diabetes.", "diabetes"),
    ("I was diagnosed with diabetes.", "diabetes"),
    ("I have depression.", "depression"),
    ("My son has depression.", "depression"),
    ("I have anxiety.", "anxiety"),
    ("I was diagnosed with anxiety.", "anxiety"),
    ("I am HIV positive.", "HIV"),
    ("My son has cancer.", "cancer"),
    ("I am receiving chemotherapy.", "chemotherapy"),
    ("I am pregnant.", "pregnant"),
    ("I had a miscarriage.", "miscarriage"),
    ("My son has ADHD.", "ADHD"),
    ("I have bipolar disorder.", "bipolar disorder"),
    ("I am bipolar.", "bipolar"),
    ("My son has asthma.", "asthma"),
    ("I have epilepsy.", "epilepsy"),
    ("We are undergoing IVF.", "IVF"),
    ("I attend therapy sessions every week.", "therapy sessions"),
    ("I am in rehab.", "rehab"),
    ("I take metformin daily.", "metformin"),
    ("I was prescribed metformin.", "metformin"),
    ("I take insulin daily.", "insulin"),
    ("I take sertraline daily.", "sertraline"),
    ("I take Xanax at night.", "Xanax"),
    ("I was diagnosed with endometriosis.", "endometriosis"),
    ("My son has endometriosis.", "endometriosis"),
    ("I have fibromyalgia.", "fibromyalgia"),
    ("I was diagnosed with fibromyalgia.", "fibromyalgia"),
    ("My son has pneumonia.", "pneumonia"),
    ("I have COVID-19.", "COVID-19"),
    ("I have bronchitis.", "bronchitis"),
    ("I have lupus.", "lupus"),
    ("I have rheumatoid arthritis.", "rheumatoid arthritis"),
    ("I have hypertension.", "hypertension"),
    ("I take levothyroxine daily.", "levothyroxine"),
    ("I take amoxicillin daily.", "amoxicillin"),
    ("I take atorvastatin daily.", "atorvastatin"),
    ("My son has autism.", "autism"),
    ("I have PTSD.", "PTSD"),
];

const MEDICINES: &[&str] = &[
    "metformin",
    "amoxicillin",
    "levothyroxine",
    "atorvastatin",
    "ibuprofen",
    "paracetamol",
    "acetaminophen",
    "omeprazole",
    "pantoprazole",
    "lisinopril",
    "amlodipine",
    "losartan",
    "metoprolol",
    "salbutamol",
    "albuterol",
    "prednisone",
    "prednisolone",
    "warfarin",
    "apixaban",
    "clopidogrel",
    "simvastatin",
    "gabapentin",
    "tramadol",
    "morphine",
    "codeine",
    "oxycodone",
    "furosemide",
    "methotrexate",
    "insulin",
    "sertraline",
    "fluoxetine",
];

fn private_text(input: &str) -> String {
    let mut gate = Gate::for_grant(&private_grant(), [91; 32]);
    gate.text(input)
        .expect("gate must issue")
        .0
        .as_str()
        .to_string()
}

#[test]
fn every_health_probe_of_the_seal_review_is_masked_without_a_model() {
    let raw: Vec<String> = HEALTH
        .iter()
        .map(|&(input, value)| (private_text(input), value))
        .filter(|(out, value)| out.contains(value))
        .map(|(out, _)| out)
        .collect();
    assert!(
        raw.is_empty(),
        "{} of {} raw: {raw:?}",
        raw.len(),
        HEALTH.len()
    );
}

#[test]
fn common_medicines_are_masked_in_any_case() {
    for medicine in MEDICINES {
        let upper = medicine.to_uppercase();
        for input in [
            format!("I take {medicine} daily."),
            format!("I was prescribed {medicine}."),
            format!("Doctor said: {upper} twice a day."),
        ] {
            let out = private_text(&input);
            assert!(
                !out.to_lowercase().contains(medicine),
                "{input:?} -> {out:?}"
            );
        }
    }
}

#[test]
fn ordinary_words_near_the_new_terms_stay_clear() {
    for input in [
        "The training session starts at nine.",
        "The morning session ran long.",
        "I take the train daily.",
        "We morph the image before export.",
        "The code is in the main branch.",
        "Our warfare game ships in May.",
    ] {
        assert_eq!(private_text(input), input);
    }
}
