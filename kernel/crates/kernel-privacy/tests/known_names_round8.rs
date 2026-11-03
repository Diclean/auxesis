//! Round-8 known-names probes: a one-part entry with a diacritic keeps its own
//! spelling rule (N1), and a Latin look-alike in a Cyrillic or Greek word folds
//! toward that word's script (N2).
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
fn n1_a_one_part_diacritic_entry_keeps_its_own_spelling_rule() {
    let contacts: &[&str] = &[
        "Chloé",
        "Zoë",
        "Léa",
        "Björn",
        "Søren",
        "Hélène",
        "François",
        "Jérôme",
        "Renée",
        "Łukasz",
        "Mäki",
        "Bäck",
    ];
    check(&[
        masked(&["Chloé"], "dinner with chloé tonight"),
        masked(&["Zoë"], "zoë called"),
        masked(&["Léa"], "léa is here"),
        masked(&["Björn"], "björn wrote"),
        masked(&["Søren"], "søren wrote"),
        masked(&["Hélène"], "hélène wrote"),
        masked(&["François"], "françois wrote"),
        masked(&["Jérôme"], "jérôme wrote"),
        masked(&["Renée"], "renée wrote"),
        masked(&["Łukasz"], "łukasz wrote"),
        masked(&["Mäki"], "mäki wrote"),
        masked(&["Bäck"], "bäck wrote"),
        clear(contacts, "I'll get back to you"),
        clear(contacts, "good luck"),
        clear(contacts, "the price is low"),
        clear(contacts, "hard work"),
        clear(contacts, "ich bin schon da"),
    ]);
}

#[test]
#[ignore = "out of language scope (owner 2026-10-10)"]
fn n2_a_mixed_script_word_folds_toward_its_majority_script() {
    check(&[
        masked(&["Віталій"], "Вiталiй прийде завтра"),
        masked(&["Марія"], "Марiя"),
        masked(&["Ігор"], "Iгор"),
        masked(&["Олексій Петренко"], "Олексiй прийде"),
        masked(&["Марiя"], "Марія"),
        masked(&["Сергей"], "Cергей"),
        masked(&["Сергей"], "Сергeй"),
        masked(&["Νίκος"], "Νiκος"),
        masked(&["Камілла"], "Kамілла"),
        masked(&["Camille"], "Cаmille"),
    ]);
}

#[test]
#[ignore = "out of language scope (owner 2026-10-10)"]
fn n2_the_whole_mixed_script_name_is_one_span() {
    let name = "Вiталiй Коваленко";
    let text = format!("{name} пишет");
    let spans = NameDictionary::new([name])
        .expect("dictionary")
        .analyze(&text);
    assert!(
        spans
            .iter()
            .any(|span| span.start == 0 && span.end == name.len()),
        "{spans:?}"
    );
}
