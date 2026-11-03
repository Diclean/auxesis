//! ADDR-DET-1, ADDR-DET-2: Private mode tokenises a postal address (one
//! `ADDRESS` token per block) and restores it locally; Open mode removes it
//! under the owner's always-hidden rule. Every address here is invented.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::EntityKind::{self, Address, Organization, Person};
use kernel_privacy::{DecodedText, Gate, NameDictionary, Recognizer, Registry};
use proptest::prelude::*;

fn grant(mode: PrivacyMode) -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("addr-probe".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be admitted");
    };
    grant
}

/// The production gate auxd builds (`session_gate`): the dictionary form.
fn gate(mode: PrivacyMode) -> Gate {
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).expect("dictionary"));
    Gate::for_grant_with_dictionary(&grant(mode), [7; 32], names)
}

include!("data/address_cases.rs");

/// Whether every byte of `needle` (each occurrence) is covered by a span.
fn covered(text: &str, spans: &[kernel_privacy::Span], needle: &str) -> bool {
    let start = text.find(needle).expect("needle in text");
    let end = start + needle.len();
    (start..end).all(|at| spans.iter().any(|span| span.start <= at && at < span.end))
}

/// Each fixture is masked to its last byte in the registry, tokenised by the
/// Private gate, and restored locally.
#[test]
fn every_address_is_tokenised_whole_and_restored() {
    assert!(CASES.len() >= 40, "{} cases", CASES.len());
    let registry = Registry::new().without_names();
    for (input, needles) in CASES {
        let spans = registry.analyze(input);
        let mut gate = gate(PrivacyMode::Private);
        let (safe, report) = gate.text(input).expect("a private gate issues the text");
        let masked = safe.as_str();
        for needle in *needles {
            assert!(covered(input, &spans, needle), "{input:?} -> {needle:?}");
            assert!(!masked.contains(needle), "{needle:?} issued: {masked:?}");
        }
        assert!(report.counts().any(|(kind, _)| kind == EntityKind::Address));
        let mut restored = masked.to_string();
        for (token, value) in gate.take_minted() {
            restored = restored.replace(&format!("⟦{token}⟧"), &value);
        }
        assert_eq!(restored, *input, "the local answer restores the address");
    }
}

#[test]
fn a_name_above_the_address_stays_in_clear() {
    let mut gate = gate(PrivacyMode::Private);
    let (safe, _) = gate
        .text("Mara Ellison\n12 Lantern Gardens\nGlenfallow GL5 3QT")
        .expect("issued");
    assert!(
        safe.as_str().starts_with("Mara Ellison\n⟦ADDRESS_"),
        "{}",
        safe.as_str()
    );
}

#[test]
fn open_mode_removes_an_address_and_reports_it() {
    for (input, _) in CASES {
        let mut gate = gate(PrivacyMode::Open);
        let (safe, report) = gate.text(input).expect("an open gate issues the text");
        assert_ne!(safe.as_str(), *input);
        assert!(
            safe.as_str().contains("[address removed]"),
            "{input:?}: {:?}",
            safe.as_str()
        );
        // A name the address overlaps keeps its label in Open mode (the span
        // priority is K-SPAN-PRIORITY's); either way the text is counted.
        let counted = |kind| matches!(kind, Address | Person | Organization);
        assert!(
            report.counts().any(|(k, _)| counted(k)),
            "{input:?}: {report}"
        );
    }
}

fn mutate_address(mut text: String, mutation: &str) -> String {
    match mutation {
        "lower" => text = text.to_lowercase(),
        "glue-pre" => text = format!("ref{}", text.trim_start()),
        "glue-suf" => text.push_str("ok"),
        "lf" | "crlf" => {
            let (at, end) = text
                .match_indices(' ')
                .nth(text.matches(' ').count() / 2)
                .map(|(at, _)| (at, at + 1))
                .or_else(|| text.find("&#32;").map(|at| (at, at + "&#32;".len())))
                .expect("address has a space");
            let br = if mutation == "lf" { "\n" } else { "\r\n" };
            text.replace_range(at..end, br);
        }
        "quote-curly" => text = format!("“{text}”"),
        "fullwidth" => {
            text = text
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() {
                        char::from_u32(ch as u32 + 0xFEE0).unwrap_or(ch)
                    } else {
                        ch
                    }
                })
                .collect();
        }
        "entities" => {
            text = text
                .chars()
                .enumerate()
                .map(|(i, ch)| match ch {
                    _ if !ch.is_alphanumeric() => format!("&#{};", ch as u32),
                    _ if i % 3 == 2 => format!("&#x{:x};", ch as u32),
                    _ => ch.to_string(),
                })
                .collect();
        }
        _ => unreachable!("unknown address mutator"),
    }
    text
}

fn assert_address_hidden_in_both_modes(input: &str) {
    let spans = Registry::new().without_names().analyze(input);
    assert!(
        spans.iter().any(|span| span.kind == Address),
        "{input:?}: {spans:?}"
    );
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let mut gate = gate(mode);
        let (safe, report) = gate.text(input).expect("an address must be issued safely");
        assert!(
            report.counts().any(|(kind, _)| kind == Address),
            "{mode:?} {input:?}: {report}"
        );
        assert_ne!(safe.as_str(), input, "{mode:?} leaked {input:?}");
        assert!(
            !safe.as_str().contains("Willow"),
            "{mode:?}: {:?}",
            safe.as_str()
        );
        assert!(
            !safe.as_str().contains("tilleuls"),
            "{mode:?}: {:?}",
            safe.as_str()
        );
        let clear_skeleton = address_skeleton(safe.as_str());
        for private_part in ["toulouse", "31000", "leeds", "ls62qt", "tilleuls", "willow"] {
            assert!(
                !clear_skeleton.contains(private_part),
                "{mode:?} leaked {private_part:?}: {clear_skeleton:?}"
            );
        }
    }
}

fn address_skeleton(text: &str) -> String {
    DecodedText::new(text)
        .text()
        .chars()
        .map(|ch| match ch as u32 {
            0xFF01..=0xFF5E => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
            _ => ch,
        })
        .filter(char::is_ascii_alphanumeric)
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

#[test]
fn lower_case_and_mutated_postal_addresses_are_hidden_in_both_modes() {
    let fr = "7 avenue des Tilleuls, 31000 Toulouse";
    let en = "9 Willow Lane, Leeds LS6 2QT";
    let cells = [
        mutate_address(fr.into(), "lower"),
        mutate_address(fr.into(), "glue-pre"),
        mutate_address(fr.into(), "lf"),
        mutate_address(fr.into(), "crlf"),
        mutate_address(en.into(), "glue-suf"),
        mutate_address(mutate_address(fr.into(), "lower"), "quote-curly"),
        mutate_address(mutate_address(fr.into(), "lower"), "glue-suf"),
        mutate_address(mutate_address(fr.into(), "lower"), "entities"),
        mutate_address(mutate_address(fr.into(), "lower"), "glue-pre"),
        mutate_address(mutate_address(fr.into(), "crlf"), "lower"),
        mutate_address(mutate_address(fr.into(), "lower"), "fullwidth"),
    ];
    for input in cells {
        assert_address_hidden_in_both_modes(&input);
    }
    for input in [
        "42 willow crescent, leeds ls6 2qt",
        "(seeref12 rue des Lilas, 69003 Lyon)",
        "Kossuth Lajos utca\n12, 1055 Budapest",
        "prešernova cesta 10, 1000 ljubljana",
        "４２ ｗｉｌｌｏｗ ｃｒｅｓｃｅｎｔ, ｌｅｅｄｓ ｌｓ６ ２ｑｔ",
    ] {
        assert_address_hidden_in_both_modes(input);
    }
}

#[test]
fn round_two_address_repros_are_removed_whole_in_both_modes() {
    for input in [
        "1600 pennsylvania avenue nw, washington, dc 20500",
        "P.O. Box 12, London",
        "7 avenue des tilleuls 31000 toulouse",
        "42 maple\nroad",
    ] {
        assert_masked_exactly(input, &[input]);
        let (safe, report) = gate(PrivacyMode::Open)
            .text(input)
            .expect("an open gate issues the address");
        assert_eq!(safe.as_str(), "[address removed]", "{input:?}");
        assert!(report.counts().any(|(kind, _)| kind == Address));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn generated_address_mutator_sequences_stay_hidden(
        base in prop::sample::select(vec![
            "7 avenue des Tilleuls, 31000 Toulouse",
            "9 Willow Lane, Leeds LS6 2QT",
        ]),
        mutations in prop::collection::btree_set(
            prop::sample::select(vec!["lower", "glue-pre", "glue-suf", "lf", "crlf", "quote-curly", "fullwidth", "entities"]),
            1..=3,
        ),
    ) {
        let mut ordered: Vec<_> = mutations.into_iter().collect();
        ordered.sort_by_key(|mutation| match *mutation {
            "lower" => 0,
            "lf" | "crlf" => 1,
            "quote-curly" | "glue-pre" | "glue-suf" => 2,
            "fullwidth" => 3,
            "entities" => 4,
            _ => unreachable!(),
        });
        let input = ordered.iter().fold(base.to_string(), |text, mutation| mutate_address(text, mutation));
        assert_address_hidden_in_both_modes(&input);
    }
}

#[test]
fn ordinary_lower_case_number_prose_keeps_main_masking() {
    let address = kernel_privacy::recognizers::address::AddressRecognizer::new();
    for input in [
        "1234 cases",
        "12 rue",
        "in 69003 cases",
        "12 rue is the example",
        "we saw 69003 cases",
        "Main Street Capital",
    ] {
        assert!(
            address.analyze(input).is_empty(),
            "{input:?} got an address span"
        );
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let (safe, _) = gate(mode).text(input).expect("ordinary prose is issued");
            assert_eq!(safe.as_str(), input, "{mode:?} over-masked {input:?}");
        }
    }
}

#[test]
fn text_without_an_address_stays_clear() {
    let address = kernel_privacy::recognizers::address::AddressRecognizer::new();
    for input in CLEAR {
        let spans = address.analyze(input);
        assert!(spans.is_empty(), "{input:?} gave {spans:?}");
        let mut gate = gate(PrivacyMode::Private);
        let (safe, _) = gate.text(input).expect("issued");
        assert_eq!(safe.as_str(), *input);
    }
}

#[test]
fn an_address_never_crosses_a_bank_statement_column_gap() {
    let address = kernel_privacy::recognizers::address::AddressRecognizer::new();
    let statement = "12/03/2026  CB 12 RUE DE LA PAIX  75002 PARIS  -45,00\n\
                     13/03/2026\tVIR 4 HIGH ST\tLONDON SW1A 1AA\t-12,00";
    for span in address.analyze(statement) {
        let value = &statement[span.start..span.end];
        assert!(!value.contains("  ") && !value.contains('\t'), "{value:?}");
    }
}

#[test]
fn an_address_after_a_masked_value_never_refuses_the_text() {
    // Masking the e-mail puts a line end before the postcode line in the residue
    // view; an address read there must not refuse the turn.
    for input in [
        "mail jo@example.invalid 75011 Paris.",
        "+33 6 12 34 56 78\n75011 Paris",
        "jo@example.invalid, 12 rue des Lilas, 75011 Paris",
    ] {
        let mut gate = gate(PrivacyMode::Private);
        assert!(gate.text(input).is_ok(), "{input:?} was refused");
    }
}

/// The Private gate's output for `input`, which must be `input` with each of
/// `needles` replaced by one address token and nothing else changed.
fn assert_masked_exactly(input: &str, needles: &[&str]) {
    let mut gate = gate(PrivacyMode::Private);
    let (safe, _) = gate.text(input).expect("a private gate issues the text");
    let minted = gate.take_minted();
    let mut expected = input.to_string();
    for needle in needles {
        let (token, _) = minted
            .iter()
            .find(|(_, value)| value == needle)
            .unwrap_or_else(|| panic!("{needle:?} is not one token in {:?}", safe.as_str()));
        assert!(token.starts_with("ADDRESS_"), "{needle:?} took {token}");
        expected = expected.replacen(needle, &format!("⟦{token}⟧"), 1);
    }
    assert_eq!(safe.as_str(), expected, "{input:?}");
}

/// Texts the Private gate must issue unchanged.
fn assert_clear(inputs: &[&str]) {
    for input in inputs {
        let (safe, _) = gate(PrivacyMode::Private).text(input).expect("issued");
        assert_eq!(safe.as_str(), *input);
    }
}

/// ADDR-DET-2 item 1: a match glued to a word restarts at that word's end, so
/// an address on the next line or after a space is still found.
#[test]
fn an_address_after_a_glued_street_word_is_masked() {
    assert_masked_exactly("xKerkstraat\n12 Lanternlaan", &["12 Lanternlaan"]);
    assert_masked_exactly("xKerkstraat 12 Lanternlaan", &["12 Lanternlaan"]);
    assert_masked_exactly("xKerkstraat\n12 Lantern Lane", &["12 Lantern Lane"]);
    assert_masked_exactly("ab12 rue des Lilas 9 Hollin Close", &["9 Hollin Close"]);
}

/// ADDR-DET-2 item 1: a long word glued before a street word is skipped once,
/// so the scan stays linear (it was quadratic in ADDR-DET-1 round 0).
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn a_long_word_before_a_street_word_is_scanned_in_linear_time() {
    let address = kernel_privacy::recognizers::address::AddressRecognizer::new();
    let time = |n: usize| {
        let text = format!("x{}straat 12", "A".repeat(n));
        let start = Instant::now();
        assert!(address.analyze(&text).is_empty());
        start.elapsed()
    };
    time(1_000);
    let (small, large) = (time(4_000), time(16_000));
    eprintln!("glued scan: n=4000 {small:?}, n=16000 {large:?}");
    assert!(large < small * 6, "small={small:?} large={large:?}");
    assert!(large < Duration::from_secs(1), "large={large:?}");
}

/// ADDR-DET-2 item 2: a box that names itself keeps its number when a city
/// follows; a bare `BP`/`CS` box needs punctuation or the line end after it.
#[test]
fn boxes_are_masked_and_bp_in_prose_is_not() {
    assert_masked_exactly("P.O. Box 12 London", &["P.O. Box 12 London"]);
    assert_masked_exactly("Postfach 1234 Berlin", &["Postfach 1234 Berlin"]);
    assert_masked_exactly("BP 456", &["BP 456"]);
    assert_masked_exactly("Envoyez au CS 70001.", &["CS 70001"]);
    assert_clear(&["BP oil price 456", "BP 2023 results.", "I took CS 101."]);
}

/// ADDR-DET-2 item 3: an abbreviated street type matches in any case.
/// Round 1: a match that already consumed its trailing dot is closed even when
/// only a space (or a tab / NBSP) follows, so the address is masked in prose.
#[test]
fn abbreviated_street_types_match_in_any_case() {
    for input in "42 maple rd.|42 maple RD.|42 Maple Rd|42 maple Rd|14 elm St.".split('|') {
        assert_masked_exactly(input, &[input]);
    }
    // Round 1: the `segment(...)` regex anchors on the char after the optional
    // dot, but the dot itself ends the match. Treat the match as closed even
    // when the next char is just a space, a tab, or a NBSP.
    for tail in [" ", "\t", "\u{202f}", "\u{a0}"] {
        assert_masked_exactly(
            &format!("42 maple rd.{tail}Please send it."),
            &["42 maple rd."],
        );
        assert_masked_exactly(
            &format!("42 maple RD.{tail}Please send it."),
            &["42 maple RD."],
        );
        assert_masked_exactly(
            &format!("42 maple Rd.{tail}Please send it."),
            &["42 maple Rd."],
        );
        assert_masked_exactly(&format!("14 elm St.{tail}Please send it."), &["14 elm St."]);
    }
    assert_masked_exactly("My address is 42 maple rd.", &["42 maple rd."]);
    assert_masked_exactly(
        "To 18 maple Blvd, Austin, TX 78701",
        &["18 maple Blvd, Austin, TX 78701"],
    );
    assert_clear(&["rd. 3 of the race", "st. 4 of the plan", "RD. 3 of it"]);
    // Round 1: a `HOUSE` + `utca` prose and a bare `Utca` stay clear.
    assert_clear(&["I ran 3 km on the main rd. today", "Utca is a word"]);
}

/// ADDR-DET-2 round 1: Hungarian / Slovene street types match in every case
/// (lower, UPPER, Title) and in either order (`HOUSE` before or after), so a
/// mixed-case street line is masked in prose.
#[test]
fn hungarian_and_slovene_street_types_match_in_any_case_and_order() {
    let kinds = [
        "utca",
        "u.",
        "útja",
        "út",
        "tere",
        "tér",
        "körút",
        "krt.",
        "köz",
        "sor",
        "sétány",
        "rakpart",
        "fasor",
        "cesta",
        "ulica",
        "ul.",
        "trg",
        "nabrežje",
    ];
    let names = ["Lámpás", "Slovenska", "Prešernov", "Kossuth Lajos"];
    let cases = ["lower", "UPPER", "Title"];
    let registry = Registry::new().without_names();
    let mut total = 0;
    for kind in kinds {
        for case in cases {
            let spelled = match case {
                "lower" => kind.to_string(),
                "UPPER" => kind.to_uppercase(),
                _ => {
                    let mut chars = kind.chars();
                    let first = chars.next().unwrap().to_uppercase().to_string();
                    first + chars.as_str()
                }
            };
            for name in names {
                // `HOUSE` number first (`18 Lámpás UTCA`, etc.).
                let sentence_before = format!("Látogasson el 18 {name} {spelled}.");
                let needle_before = format!("18 {name} {spelled}");
                let spans = registry.analyze(&sentence_before);
                assert!(
                    covered(&sentence_before, &spans, &needle_before),
                    "{sentence_before:?} -> {spans:?}"
                );
                let mut g_before = gate(PrivacyMode::Private);
                let (safe, _) = g_before.text(&sentence_before).expect("issued");
                assert!(
                    !safe.as_str().contains(&needle_before),
                    "{needle_before:?} still in {safe:?}"
                );

                // `HOUSE` number last (`Slovenska CESTA 12`, etc.).
                let sentence_after = format!("Cím: {name} {spelled} 12.");
                let needle_after = format!("{name} {spelled} 12");
                let spans_after = registry.analyze(&sentence_after);
                assert!(
                    covered(&sentence_after, &spans_after, &needle_after),
                    "{sentence_after:?} -> {spans_after:?}"
                );
                let mut g_after = gate(PrivacyMode::Private);
                let (safe_after, _) = g_after.text(&sentence_after).expect("issued");
                assert!(
                    !safe_after.as_str().contains(&needle_after),
                    "{needle_after:?} still in {safe_after:?}"
                );
                total += 2;
            }
        }
    }
    // 18 kinds × 3 cases × 4 names × 2 orders = 432 cases (the spec asks for
    // the first two axes and the order axis; the four names include the
    // finding-cited examples `Lámpás utca`, `Slovenska cesta`, and the
    // multi-Cap `Kossuth Lajos`, exercising both segments).
    assert_eq!(total, 18 * 3 * 4 * 2, "{total} cases");
}

/// ADDR-DET-2 item 4: a unit, a trailing postcode, a district and an Eircode
/// join the block, to the last byte and no further.
#[test]
fn every_part_of_an_address_is_in_its_token() {
    for needle in [
        "12 Main St #4, Boston, MA 02110",
        "12 rue des Lilas, 75011",
        "7 Merrion Square, Dublin 2, D02 X285",
        "D02 X285",
        "Apt 4, 14 High St, Bristol BS1 4DJ",
        "Flat 3, 14 High St, Bristol BS1 4DJ",
        "Unit 2B, 18 Quill Row, Leeds LS1 4AP",
        "350 Fifth Avenue, Apt 4B, New York, NY 10118",
        "27 place du Marché, Flat 3, 44000 Nantes",
    ] {
        assert_masked_exactly(&format!("Send it to {needle}."), &[needle]);
    }
    assert_clear(&["room #4 is free", "in 2026 12 people", "Flat 3 is free."]);
}

/// ADDR-DET-2 item 5: Open mode removes a health word inside an address, as
/// main does. Main's region merge gives the union the phone or e-mail label.
#[test]
fn open_mode_removes_a_health_word_inside_an_address() {
    for input in ["06123-45678 Diabetes Lane", "12 Diabetes Lane@x.invalid"] {
        let (safe, _) = gate(PrivacyMode::Open).text(input).expect("issued");
        let safe = safe.as_str();
        assert!(safe.contains("[health removed]"), "{input:?} -> {safe:?}");
    }
}

/// Words of the generated addresses, `|`-separated.
const STREETS: &str = "Lantern|Quill|Maple|Hollin|Old Mill|St Anne's";
const EN_TYPES: &str = "Street|St|Road|Lane|Avenue|Close|Gardens|Drive";
const FR_TYPES: &str = "rue|avenue|boulevard|impasse|allée|chemin|quai";
const FR_NAMES: &str = "des Lilas|du Hérisson|de la Liberté|Victor Hugo|de l'Église";
const CITIES: &str = "Mistvale|Valbrume|Glenfallow|Saint-Malo";

fn pick(words: &'static str) -> prop::sample::Select<&'static str> {
    prop::sample::select(words.split('|').collect::<Vec<_>>())
}

/// An invented street line and an optional postcode line, in EN or FR.
fn address() -> impl Strategy<Value = String> {
    let letter = prop::option::of("[A-D]");
    let en = (1u32..9999, letter, pick(STREETS), pick(EN_TYPES))
        .prop_map(|(n, l, name, kind)| format!("{n}{} {name} {kind}", l.unwrap_or_default()));
    let fr = (1u32..999, pick(",|| bis"), pick(FR_TYPES), pick(FR_NAMES))
        .prop_map(|(n, glue, kind, name)| format!("{n}{glue} {kind} {name}"));
    let city = (10000u32..99999, pick(CITIES), pick(", |\n"))
        .prop_map(|(code, city, sep)| format!("{sep}{code} {city}"));
    (prop_oneof![en, fr], prop::option::of(city))
        .prop_map(|(street, city)| format!("{street}{}", city.unwrap_or_default()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every generated address is masked to its last byte, and the words around
    /// it are never masked.
    #[test]
    fn a_generated_address_is_masked_and_its_sentence_is_not(addr in address()) {
        let text = format!("Please send the parcel to {addr} before noon.");
        let spans = Registry::new().without_names().analyze(&text);
        prop_assert!(covered(&text, &spans, &addr), "{text:?} gave {spans:?}");
        let prefix = "Please send the parcel to ".len();
        let suffix = text.len() - " before noon.".len();
        // An address and the next words can, by chance, compact to a string
        // with a registered IBAN length and a valid mod-97 checksum (seen:
        // "St\n68905 Glenfallow before no" → ST, 25 chars, remainder 1). The
        // IBAN rule hides it on purpose: that over-mask errs on the safe side,
        // and narrowing it would also clear real bank-account text
        // (IBAN-EATS-ADDRESS, two attempts, binned). Only such an IBAN span
        // may reach past the address.
        prop_assert!(
            spans
                .iter()
                .all(|s| s.kind == EntityKind::Iban || (s.start >= prefix && s.end <= suffix)),
            "{text:?} {spans:?}"
        );
    }
}

/// Seal B round 3 on #258: forms main already hides must stay hidden (no
/// pre-filter may skip the segment passes).
#[test]
fn forms_main_hides_stay_hidden() {
    let address = kernel_privacy::recognizers::address::AddressRecognizer::new();
    for input in [
        "Send it to 18 2nd Avenue please.",
        "Livraison au 12 route de Nice.",
        "Rendez-vous 12 place des Lilas.",
        "Bureau au 12 cours Victor Hugo.",
        "Sydney NSW 2000",
    ] {
        assert!(
            !address.analyze(input).is_empty(),
            "{input:?} lost its address span"
        );
        let (safe, _) = gate(PrivacyMode::Private).text(input).expect("issued");
        assert_ne!(safe.as_str(), input, "Private left {input:?} clear");
    }
}
