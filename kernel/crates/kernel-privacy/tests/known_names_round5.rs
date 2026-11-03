//! Round-5 known-names probes: the inflection and stem rules, checked under a
//! 200-name dictionary that holds the names the over-masking probes must not
//! hit.
//!
//! Fake names only.

use kernel_privacy::{NameDictionary, Recognizer};

/// A deterministic filler name that no probe contains.
fn filler(seed: usize) -> String {
    const LETTERS: &[u8] = b"bcdfgz";
    let mut rest = seed;
    let mut out = String::from("Qu");
    for _ in 0..4 {
        out.push(LETTERS[rest % LETTERS.len()] as char);
        rest /= LETTERS.len();
    }
    out
}

/// Two hundred names: twelve named ones and 188 fillers.
fn round5_dictionary() -> Vec<String> {
    let mut names: Vec<String> = [
        "Mercier", "Bonnet", "Leroy", "Laura", "Denis", "Simon", "Carter", "Isaac", "Andrew",
        "Moreau", "Young", "Camille",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect();
    names.extend((0..188).map(|index| format!("{} {}", filler(2 * index), filler(2 * index + 1))));
    assert_eq!(names.len(), 200);
    names
}

/// The text of every span `names` finds in `text`.
fn masked_words(names: &[&str], text: &str) -> Vec<String> {
    NameDictionary::new(names)
        .expect("dictionary")
        .analyze(text)
        .iter()
        .map(|span| text[span.start..span.end].to_string())
        .collect()
}

/// `text` must mask exactly the word `word`.
fn assert_masks(names: &[&str], text: &str, word: &str) {
    let masked = masked_words(names, text);
    assert!(
        masked.iter().any(|found| found == word),
        "{text:?} masked {masked:?}, expected {word:?}"
    );
}

#[test]
fn round5_unmasked_probes_stay_unmasked_under_200_names() {
    let dictionary = NameDictionary::new(round5_dictionary()).expect("dictionary");
    for probe in [
        "Merci de votre aide",
        "bonne journée",
        "car la voiture",
        "si la réunion de mardi",
        "Le dossier est prêt",
        "is and more you",
        "un camion",
        "une camisole",
        "Budi sudah",
        "I bought a camera in Cambridge",
    ] {
        let masked: Vec<&str> = dictionary
            .analyze(probe)
            .iter()
            .map(|span| &probe[span.start..span.end])
            .collect();
        assert!(masked.is_empty(), "{probe:?} masked {masked:?}");
    }
}

#[test]
fn indic_tails_are_masked() {
    let bengali = ["রাহুল দাস", "রবি সেন"];
    assert_masks(&bengali, "সেনকে", "সেনকে");
    assert_masks(&bengali, "রবিকে", "রবিকে");
    assert_masks(&bengali, "দাসকে", "দাসকে");
    let tamil = ["ரவி குமார்"];
    assert_masks(&tamil, "ரவிக்கு", "ரவிக்கு");
    assert_masks(&tamil, "ரவியிடம்", "ரவியிடம்");
    assert_masks(&["अनु शर्मा"], "अनुको", "अनुको");
}

#[test]
fn finnish_greek_and_polish_forms_are_masked() {
    let tom = ["Tom Virta", "Leo Laine"];
    assert_masks(&tom, "Tomin", "Tomin");
    assert_masks(&tom, "Leolle", "Leolle");
    let finns = ["Pekka Mäki", "Jukka Koski", "Antti Niemi", "Matti Salo"];
    for word in ["Pekan", "Jukan", "Antin", "Matin", "Matille"] {
        assert_masks(&finns, word, word);
    }
    assert_masks(&["Ζωή Παππά"], "της Ζωής", "Ζωής");
    assert_masks(&["Ewa Nowak"], "dla Ewy", "Ewy");
}

#[test]
fn stem_and_tail_forms_need_a_capital_in_cased_scripts() {
    let dictionary =
        NameDictionary::new(["Tom Virta", "Pekka Mäki", "Ewa Nowak"]).expect("dictionary");
    for probe in ["tomin", "pekan", "dla ewy"] {
        assert!(
            dictionary.analyze(probe).is_empty(),
            "{probe:?} matched a lower-case form"
        );
    }
}

#[test]
fn a_stem_is_never_a_standalone_match() {
    let dictionary = NameDictionary::new(["Ewa Nowak", "Pekka Mäki"]).expect("dictionary");
    for probe in ["Ew", "Pek", "Pe"] {
        assert!(
            dictionary.analyze(probe).is_empty(),
            "{probe:?} matched on its stem alone"
        );
    }
}
