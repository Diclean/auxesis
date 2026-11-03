//! Round-7 known-names probes: the Latin-homoglyph fold only inside words that
//! hold a Latin letter (F1), and the spellings a diacritic strip or a
//! transliteration derives need a capital (F2).
//!
//! Every case names a dictionary and a text, and says whether the text must
//! mask (`true`) or stay in clear (`false`). All failures are reported at once.
//!
//! Fake names only.

use kernel_privacy::{NameDictionary, Recognizer};

/// One probe: the names a caller seeds, the text, and whether it must mask.
struct Case {
    names: &'static [&'static str],
    text: &'static str,
    masked: bool,
}

const fn masked(names: &'static [&'static str], text: &'static str) -> Case {
    Case {
        names,
        text,
        masked: true,
    }
}

const fn clear(names: &'static [&'static str], text: &'static str) -> Case {
    Case {
        names,
        text,
        masked: false,
    }
}

/// The text of every span the dictionary finds in `text`.
fn masked_words(names: &[&str], text: &str) -> Vec<String> {
    NameDictionary::new(names)
        .expect("dictionary")
        .analyze(text)
        .iter()
        .map(|span| text[span.start..span.end].to_string())
        .collect()
}

/// Run every case and fail once, listing each probe that did not hold.
fn check(cases: &[Case]) {
    let mut failures = Vec::new();
    for case in cases {
        let found = masked_words(case.names, case.text);
        if found.is_empty() == case.masked {
            failures.push(format!(
                "{:?} with {:?}: masked {found:?}, expected masked={}",
                case.text, case.names, case.masked
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn f1_homoglyphs_fold_only_inside_a_word_with_a_latin_letter() {
    let contacts: &[&str] = &[
        "Kai", "Mia", "Eva", "Vai", "Meta", "Tote", "Nana", "Ham", "Mama",
    ];
    check(&[
        clear(contacts, "Θέλω και καφέ και πίτα"),
        clear(contacts, "μια μέρα"),
        clear(contacts, "ένα"),
        clear(contacts, "ΚΑΙ"),
        clear(contacts, "ναι"),
        clear(contacts, "μετά"),
        clear(contacts, "τότε"),
        clear(contacts, "папа и мама"),
        clear(contacts, "нам"),
        clear(contacts, "как так"),
        masked(&["Camille"], "Cаmille"),
        masked(&["Kai"], "Κai"),
        masked(&["Νίκος Παπαδόπουλος"], "Νίκος Παπαδόπουλος"),
        masked(&["Иван Петров"], "иван петров"),
    ]);
}

#[test]
fn f2_derived_spellings_need_a_capital_and_the_entry_keeps_its_rule() {
    let contacts: &[&str] = &[
        "Bäck", "Lück", "Löw", "Hård", "Schön", "Bär", "Hög", "Bøg", "Ståhl", "Mäki",
    ];
    check(&[
        clear(contacts, "I'll get back to you"),
        clear(contacts, "good luck"),
        clear(contacts, "the price is low"),
        clear(contacts, "hard work"),
        clear(contacts, "ich bin schon da"),
        clear(contacts, "at the bar"),
        clear(contacts, "hog"),
        clear(contacts, "bog"),
        clear(contacts, "stahl"),
        clear(contacts, "maki roll"),
        masked(contacts, "Back called"),
        masked(&["Schön"], "Herr Schon"),
        masked(&["José Müller"], "Muller"),
        masked(&["Åsa Öberg"], "Asa Oberg"),
        masked(&["José Müller"], "jose muller"),
        masked(&["Erik Bäck"], "erik back"),
        masked(&["Camille"], "camille"),
    ]);
}
