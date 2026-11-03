//! Round-9 known-names probes (K07 seal r9).
//!
//! F1: NFD text is the same spelling as NFC. A combining mark belongs to the
//! letter it follows, so `chloe\u{301}` masks as one token, restores to its exact
//! bytes and erases. An NFD entry keeps the rule of its NFC spelling.
//!
//! F2: a Cyrillic word is read as it is written. Ukrainian і is not Russian и,
//! so a lower-case Ukrainian word never matches a Russian contact.
//!
//! Every case names a dictionary and the words that must mask, in order. All
//! failures are reported at once. Fake names only.

use std::sync::Arc;

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{Anonymizer, Gate, NameDictionary, Recognizer, UnknownPolicy, Vault};

/// The text of every span the dictionary finds in `text`.
fn masked_words(names: &[&str], text: &str) -> Vec<String> {
    NameDictionary::new(names)
        .expect("dictionary")
        .analyze(text)
        .iter()
        .map(|span| text[span.start..span.end].to_string())
        .collect()
}

/// Run every `(names, text, expected)` case and fail once, listing each probe
/// that does not hold. Each expected word must be masked as one span; a given or
/// family part of a name may mask on its own as well. An empty `expected` means
/// nothing masks.
fn check_words(cases: &[(&[&str], &str, &[&str])]) {
    let mut failures = Vec::new();
    for (names, text, expected) in cases {
        let found = masked_words(names, text);
        let holds = if expected.is_empty() {
            found.is_empty()
        } else {
            expected
                .iter()
                .all(|token| found.iter().any(|word| word.as_str() == *token))
        };
        if !holds {
            failures.push(format!(
                "{text:?} with {names:?}: masked {found:?}, expected {expected:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A Private A1 grant to a hosted model, the path a chat takes.
fn grant() -> Grant {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, PrivacyMode::Private, &context) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn f1_a_lowercase_nfd_one_word_contact_masks_as_one_word() {
    check_words(&[
        (
            &["Chloé"],
            "dinner with chloe\u{301} tonight",
            &["chloe\u{301}"],
        ),
        (&["José"], "jose\u{301} called", &["jose\u{301}"]),
        (&["André"], "andre\u{301} is here", &["andre\u{301}"]),
        (&["Noé"], "noe\u{301} wrote", &["noe\u{301}"]),
        (&["Zoë"], "zoe\u{308} called", &["zoe\u{308}"]),
    ]);
}

#[test]
fn f1_b_a_capitalised_nfd_word_masks_its_mark_with_it() {
    check_words(&[
        (&["Chloé"], "Chloe\u{301} called", &["Chloe\u{301}"]),
        (&["José"], "Jose\u{301} called", &["Jose\u{301}"]),
        (&["André"], "Andre\u{301} is here", &["Andre\u{301}"]),
        (&["Noé"], "Noe\u{301} wrote", &["Noe\u{301}"]),
        (&["Zoë"], "Zoe\u{308} called", &["Zoe\u{308}"]),
    ]);
}

#[test]
fn f1_c_an_nfd_entry_keeps_the_rule_of_its_nfc_spelling() {
    check_words(&[
        (&["Chloe\u{301}"], "dinner with chloé tonight", &["chloé"]),
        (
            &["Chloe\u{301}"],
            "dinner with chloe\u{301} tonight",
            &["chloe\u{301}"],
        ),
        (&["Chloe\u{301}"], "dinner with chloe tonight", &[]),
        (&["Chloé"], "dinner with chloe tonight", &[]),
    ]);
}

#[test]
fn f2_a_lowercase_ukrainian_word_is_not_a_russian_contact() {
    check_words(&[
        (&["Мира"], "яка міра відповідальності", &[]),
        (&["Мина"], "міна", &[]),
        (&["Вика"], "віка", &[]),
        (&["Лина"], "ліна", &[]),
        (&["Дина"], "діна", &[]),
        (&["Ира"], "іра", &[]),
    ]);
}

/// Private mode's languages (owner 2026-10-10): French, English, Afrikaans,
/// Hungarian, Slovenian and Chinese. Fictional names only.
#[test]
fn lang_fr_french_contacts_mask_in_lowercase_nfc_and_nfd() {
    check_words(&[
        (&["Chloé"], "chloé est là", &["chloé"]),
        (&["Chloé"], "chloe\u{301} est là", &["chloe\u{301}"]),
        (&["Hélène"], "hélène arrive", &["hélène"]),
        (
            &["Hélène"],
            "he\u{301}le\u{300}ne arrive",
            &["he\u{301}le\u{300}ne"],
        ),
        (&["François"], "françois arrive", &["françois"]),
        (
            &["François"],
            "franc\u{327}ois arrive",
            &["franc\u{327}ois"],
        ),
    ]);
}

#[test]
fn lang_hu_hungarian_contacts_mask_in_either_order_and_nfd() {
    check_words(&[
        (&["Kovács Anna"], "kovács anna holnap", &["kovács anna"]),
        (&["Kovács Anna"], "Anna Kovács holnap", &["Anna Kovács"]),
        (&["Anna Kovács"], "kovács anna holnap", &["kovács anna"]),
        (
            &["Kovács Anna"],
            "kova\u{301}cs anna holnap",
            &["kova\u{301}cs anna"],
        ),
        (&["Győző"], "győző jön", &["győző"]),
        (
            &["Győző"],
            "gyo\u{30B}zo\u{30B} jön",
            &["gyo\u{30B}zo\u{30B}"],
        ),
        (&["Szűcs"], "szűcs jön", &["szűcs"]),
        (&["Szűcs"], "szu\u{30B}cs jön", &["szu\u{30B}cs"]),
    ]);
}

#[test]
fn lang_sl_slovenian_contacts_mask_with_their_diacritics() {
    check_words(&[
        (&["Mojca Žagar"], "mojca žagar pride", &["mojca žagar"]),
        (&["Mojca Žagar"], "Mojca Zagar pride", &["Mojca Zagar"]),
        (
            &["Mojca Žagar"],
            "mojca za\u{30C}gar pride",
            &["mojca za\u{30C}gar"],
        ),
        (&["Tomaž Kranjc"], "tomaž kranjc pride", &["tomaž kranjc"]),
        (&["Anže"], "anže pride", &["anže"]),
        (&["Špela"], "špela pride", &["špela"]),
        (&["Špela"], "s\u{30C}pela pride", &["s\u{30C}pela"]),
    ]);
}

#[test]
fn lang_af_afrikaans_contacts_with_ê_ë_ï_ô_and_particles() {
    check_words(&[
        (&["Anél"], "anél kom", &["anél"]),
        (&["Anél"], "Ane\u{301}l kom", &["Ane\u{301}l"]),
        (&["Zoë Botha"], "zoë botha kom", &["zoë botha"]),
        (
            &["Zoë Botha"],
            "Zoe\u{308} Botha kom",
            &["Zoe\u{308} Botha"],
        ),
        (&["Liné"], "liné kom", &["liné"]),
        (&["Doïne"], "doïne kom", &["doïne"]),
        (&["Pôl"], "pôl kom", &["pôl"]),
        (
            &["Pieter van der Merwe"],
            "Pieter van der Merwe kom",
            &["Pieter van der Merwe"],
        ),
        (
            &["Johan du Plessis"],
            "Johan du Plessis kom",
            &["Johan du Plessis"],
        ),
        (&["Pieter van der Merwe"], "die boek van der tafel", &[]),
        (&["Johan du Plessis"], "ek sien du dorp", &[]),
    ]);
}

#[test]
fn lang_zh_han_names_match_inside_han_text_without_spaces() {
    check_words(&[
        (&["王小明"], "明天和王小明开会", &["王小明"]),
        (&["王小明"], "meeting with 王小明 tomorrow", &["王小明"]),
        (&["王小明"], "王小明的电话是多少", &["王小明"]),
        (
            &["Wang Xiaoming"],
            "Wang Xiaoming tomorrow",
            &["Wang Xiaoming"],
        ),
        (
            &["Wang Xiaoming"],
            "Xiaoming Wang tomorrow",
            &["Xiaoming Wang"],
        ),
        // A single Han character is not a name on its own.
        (&["王"], "明天和王小明开会", &[]),
    ]);
}

/// Common words that equal a short contact name stay clear in lower case. A
/// lower-case entry is spelled as the text must be, so it still masks.
#[test]
fn guard_common_words_stay_clear_in_lowercase() {
    check_words(&[
        (&["Rose"], "the rose is red", &[]),
        (&["Pierre"], "la pierre est lourde", &[]),
        (&["Mark"], "the mark is faint", &[]),
        (&["Dan"], "to je dan lep", &[]),
        (&["Bon"], "un bon repas", &[]),
        (&["Bäck"], "get back to you", &[]),
        (&["Luc"], "good luck", &[]),
        (&["Camille"], "Cаmille est là", &["Cаmille"]),
        (&["rose"], "the rose is red", &["rose"]),
        (&["pierre"], "la pierre est lourde", &["pierre"]),
    ]);
}

#[test]
fn f1_d_an_nfd_token_restores_byte_exact_and_erases() {
    for (name, text, token) in [
        ("Chloé", "dinner with chloe\u{301} tonight", "chloe\u{301}"),
        ("Chloé", "Chloe\u{301} called", "Chloe\u{301}"),
    ] {
        // NAMES-OFF (2026-10-19): a private gate keeps the name, bytes intact.
        let dictionary = Arc::new(NameDictionary::new([name]).expect("dictionary"));
        let grant = grant();
        let mut gate = Gate::for_grant_with_dictionary(&grant, [7u8; 32], dictionary);
        let (safe, _) = gate.text(text).expect("private chat is issued");
        assert_eq!(safe.as_str(), text);
        assert!(gate.take_minted().is_empty());

        // A dictionary token still holds the original bytes, and erasure finds it.
        let spans = NameDictionary::new([name])
            .expect("dictionary")
            .analyze(text);
        let mut anonymizer = Anonymizer::new([7u8; 32]);
        let (masked, map) = anonymizer.anonymize(text, &spans);
        assert!(!masked.contains('\u{301}'), "{masked}");
        let restored = Anonymizer::restore(&masked, &map, UnknownPolicy::Keep).text;
        assert_eq!(restored, text, "restore is not byte-exact");
        let home = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(home.path()).expect("vault");
        vault.record("f1-session", &map).expect("record");
        assert_eq!(vault.forget_value(token).expect("erase"), 1, "{token:?}");
    }
}
