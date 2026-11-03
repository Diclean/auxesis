//! Round-6 known-names probes: diacritic spellings typed without accents (N1),
//! modifier-letter apostrophes (N2), and common words as name parts (N3).
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

/// The text must mask exactly the word `word`, not a fragment of it.
fn check_word(names: &[&str], text: &str, word: &str) {
    let found = masked_words(names, text);
    assert!(
        found.iter().any(|value| value == word),
        "{text:?} with {names:?} masked {found:?}, expected {word:?}"
    );
}

#[test]
fn n1_diacritic_names_match_their_plain_and_transliterated_spellings() {
    check(&[
        masked(&["José Müller"], "Muller"),
        masked(&["José Müller"], "muller"),
        masked(&["José Müller"], "MULLER"),
        masked(&["José Müller"], "Mueller"),
        masked(&["José Müller"], "Jose"),
        masked(&["Schröder"], "Schroder"),
        masked(&["Jäger"], "Jager"),
        masked(&["Bjørn"], "Bjorn"),
        masked(&["Søren"], "Soren"),
        masked(&["Åsa Öberg"], "Asa Oberg"),
        masked(&["Jose Muller"], "Müller"),
        masked(&["Jose Muller"], "José"),
    ]);
}

#[test]
fn n2_modifier_letter_apostrophes_fold_like_ascii_apostrophes() {
    check(&[
        masked(&["Camille Exemple"], "Camilleʼs file"),
        masked(&["Camille Exemple"], "CAMILLEʼS"),
        masked(&["Sinéad O'Connor"], "OʼConnor"),
        masked(&["Sinéad O'Connor"], "Sinéadʼs"),
        masked(&["Дарʼя Коваленко"], "Дар'я"),
        masked(&["Дарʼя Коваленко"], "Дар’я"),
        masked(&["Дар'я Коваленко"], "Дарʼя"),
        masked(&["Дар'я Коваленко"], "Дар’я"),
        masked(&["Мар'яна"], "Марʼяна"),
        masked(&["Мар'яна"], "Мар’яна"),
        masked(&["Gʻulom"], "G'ulom"),
        masked(&["Gʻulom"], "G‘ulom"),
        masked(&["G'ulom"], "Gʻulom"),
    ]);
    check_word(&["Дар'я Коваленко"], "Дарʼя", "Дарʼя");
    check_word(&["Дарʼя Коваленко"], "Дар'я", "Дар'я");
}

#[test]
fn n3_common_word_name_parts_need_a_capital() {
    let contacts: &[&str] = &[
        "Will", "May", "Young", "Hope", "Rose", "Pierre", "Petit", "Blanc", "Boucher", "Marchand",
        "Mark", "Jan",
    ];
    check(&[
        clear(contacts, "I will send it"),
        clear(contacts, "you may go"),
        clear(contacts, "a young man"),
        clear(contacts, "I hope so"),
        clear(contacts, "un petit souci, une rose"),
        clear(contacts, "vin blanc"),
        clear(contacts, "le boucher"),
        masked(contacts, "Will called"),
        masked(contacts, "Mme Rose"),
        masked(&["Will Smith"], "will smith"),
    ]);
}
