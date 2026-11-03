//! EU-KERNEL-1a: the EU national and tax identifiers the privacy kernel
//! leaks today.
//!
//! * Germany: the Steuer-ID, eleven digits, ISO 7064 MOD 11,10;
//! * Spain: the DNI (eight digits and a letter) and the NIE (`X`, `Y` or `Z`,
//!   seven digits and a letter), the letter being the mod-23 check and
//!   standing after a hyphen, a space, a dot or a single line break;
//! * Italy: the codice fiscale, sixteen characters with the odd and even
//!   check character, which is a letter, the shape keeping the place of three
//!   digits and a digit of the omocodia standing for its letter;
//! * the Netherlands: the BSN, nine digits, the eleven-proof;
//! * Belgium: the national number, eleven digits or twelve with the century
//!   in front, as a birth after 2000 is written, the check then computed on
//!   the number with that century in front;
//! * EU-KERNEL-1b: the Polish PESEL, the Portuguese NIF (after a label
//!   only), the Austrian SV-Nr, the Irish PPSN and the Swedish personnummer;
//! * EU-KERNEL-1c: the Romanian CNP, the Czech and Slovak rodné číslo (the
//!   nine digits before 1954 after a label only), the Greek AFM (after a label
//!   only) and AMKA, and the Bulgarian EGN.
//!
//! Every value is hidden in Private mode and removed in Open mode, with a
//! label and without one. A value whose check digit fails stays in clear
//! unless a label names it. Every value is invented.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, issue, masked, wide, MODES};
use kernel_privacy::recognizers::eu_ids::{
    AtSvNrRecognizer, BeNationalNumberRecognizer, DeSteuerIdRecognizer, EsDniRecognizer,
    Eu1cRecognizer, IePpsnRecognizer, ItCodiceFiscaleRecognizer, NlBsnRecognizer,
    PlPeselRecognizer, PtNifRecognizer, SePersonnummerRecognizer,
};
use kernel_privacy::{EntityKind, Recognizer, Span};

/// Every spelling of every class: the text, the value inside it and the class
/// it belongs to. The spellings are the ones the leak-finder mutates: a
/// glued prefix and suffix, lower case, full-width digits and the four
/// separators a printed number may use.
const SPELLINGS: &[(&str, &str, &str)] = &[
    // Germany.
    ("de_steuer_id", "26954371827", "26954371827"),
    ("de_steuer_id", "26 954 371 827", "26 954 371 827"),
    ("de_steuer_id", "26.954.371.827", "26.954.371.827"),
    ("de_steuer_id", "26-954-371-827", "26-954-371-827"),
    ("de_steuer_id", "26/954/371/827", "26/954/371/827"),
    ("de_steuer_id", "ref26954371827ok", "26954371827"),
    (
        "de_steuer_id",
        "２６９５４３７１８２７",
        "２６９５４３７１８２７",
    ),
    // Spain: the DNI and the NIE.
    ("es_dni", "12345678Z", "12345678Z"),
    ("es_dni", "12.345.678Z", "12.345.678Z"),
    ("es_dni", "12345678z", "12345678z"),
    ("es_dni", "ref12345678Zok", "12345678Z"),
    ("es_dni", "X1234567L", "X1234567L"),
    ("es_dni", "x1234567l", "x1234567l"),
    ("es_dni", "refX1234567Lok", "X1234567L"),
    // Spain: the control letter after a separator, and the NIE with one.
    ("es_dni", "12345678-Z", "12345678-Z"),
    ("es_dni", "12345678 Z", "12345678 Z"),
    ("es_dni", "12345678\nZ", "12345678\nZ"),
    ("es_dni", "X-1234567-L", "X-1234567-L"),
    // Italy.
    ("it_codice_fiscale", "ZMRPKC73R12H780Z", "ZMRPKC73R12H780Z"),
    ("it_codice_fiscale", "zmrpkc73r12h780z", "zmrpkc73r12h780z"),
    (
        "it_codice_fiscale",
        "ZMRPKC７３R１２H７８０Z",
        "ZMRPKC７３R１２H７８０Z",
    ),
    (
        "it_codice_fiscale",
        "refZMRPKC73R12H780Zok",
        "ZMRPKC73R12H780Z",
    ),
    // Italy: the control character is a letter, the place keeps three digits
    // and a digit of the omocodia stands for its letter.
    ("it_codice_fiscale", "AAAAAA00A10H501B", "AAAAAA00A10H501B"),
    ("it_codice_fiscale", "ZMRPKC99R12H780J", "ZMRPKC99R12H780J"),
    ("it_codice_fiscale", "ZMRPKCV9R12H780J", "ZMRPKCV9R12H780J"),
    // The Netherlands: nine consecutive digits, never a grouped run.
    ("nl_bsn", "456789236", "456789236"),
    ("nl_bsn", "ref456789236ok", "456789236"),
    // Belgium: a birth before 2000 and a birth after it.
    ("be_national_number", "91.07.22-406.21", "91.07.22-406.21"),
    ("be_national_number", "91072240621", "91072240621"),
    ("be_national_number", "91 07 22 406 21", "91 07 22 406 21"),
    ("be_national_number", "291.07.22-406.21", "291.07.22-406.21"),
    ("be_national_number", "205.03.14-237.51", "205.03.14-237.51"),
    ("be_national_number", "87111523456", "87111523456"),
    // Belgium: the check of a birth after 2000 is computed on the number
    // with the century in front.
    ("be_national_number", "05031423780", "05031423780"),
    ("be_national_number", "99.03.14-237.17", "99.03.14-237.17"),
    ("be_national_number", "299.03.14-237.17", "299.03.14-237.17"),
    ("be_national_number", "05.03.14-237.80", "05.03.14-237.80"),
    // Poland: issued without a separator; a birth after 2000.
    ("pl_pesel", "92071314764", "92071314764"),
    ("pl_pesel", "ref92071314764tail", "92071314764"),
    ("pl_pesel", "02221503788", "02221503788"),
    (
        "pl_pesel",
        "９２０７１３１４７６４",
        "９２０７１３１４７６４",
    ),
    // Austria: whole or `NNNC DDMMYY`.
    ("at_sv_nr", "1230150885", "1230150885"),
    ("at_sv_nr", "1230 150885", "1230 150885"),
    ("at_sv_nr", "ref1230150885tail", "1230150885"),
    // Ireland: one or two letters, glued on one side, wrapped.
    ("ie_ppsn", "1234567T", "1234567T"),
    ("ie_ppsn", "7654321PA", "7654321PA"),
    ("ie_ppsn", "1234567t", "1234567t"),
    ("ie_ppsn", "ref1234567T", "1234567T"),
    ("ie_ppsn", "7654321PAtail", "7654321PA"),
    ("ie_ppsn", "1234567 . T", "1234567 . T"),
    ("ie_ppsn", "7654321  /  PA", "7654321  /  PA"),
    ("ie_ppsn", "7654321\nPA", "7654321\nPA"),
    // Sweden: ten or twelve digits, a dash or a plus.
    ("se_personnummer", "850709-3253", "850709-3253"),
    ("se_personnummer", "8507093253", "8507093253"),
    ("se_personnummer", "19850709-3253", "19850709-3253"),
    ("se_personnummer", "850709+3253", "850709+3253"),
    ("se_personnummer", "ref850709-3253tail", "850709-3253"),
    // Romania: thirteen digits, issued without a separator.
    ("ro_cnp", "1850709401231", "1850709401231"),
    ("ro_cnp", "2981215123455", "2981215123455"),
    ("ro_cnp", "ref1850709401231ok", "1850709401231"),
    (
        "ro_cnp",
        "１８５０７０９４０１２３１",
        "１８５０７０９４０１２３１",
    ),
    // Czechia and Slovakia: a woman (+50), a birth from 2004 (+70), the 10 -> 0
    // remainder, whole or with the slash.
    ("cz_sk_rodne_cislo", "855709/1235", "855709/1235"),
    ("cz_sk_rodne_cislo", "8557091235", "8557091235"),
    ("cz_sk_rodne_cislo", "850709/1241", "850709/1241"),
    ("cz_sk_rodne_cislo", "057715/1245", "057715/1245"),
    ("cz_sk_rodne_cislo", "052715/1230", "052715/1230"),
    ("cz_sk_rodne_cislo", "ref855709/1235tail", "855709/1235"),
    // Greece: the AMKA, issued without a separator.
    ("gr_amka", "09078512341", "09078512341"),
    ("gr_amka", "ref09078512341tail", "09078512341"),
    // Bulgaria: a birth in the 1900s and one in the 2000s (+40).
    ("bg_egn", "8507091237", "8507091237"),
    ("bg_egn", "0547151238", "0547151238"),
    ("bg_egn", "ref8507091237tail", "8507091237"),
    ("bg_egn", "８５０７０９１２３７", "８５０７０９１２３７"),
];

/// The labelled spelling of every class: a label names the value.
const LABELLED: &[(&str, &str, &str)] = &[
    ("de_steuer_id", "Steuer-ID 26954371827", "26954371827"),
    ("es_dni", "DNI 12345678Z", "12345678Z"),
    ("es_dni", "NIE X1234567L", "X1234567L"),
    (
        "it_codice_fiscale",
        "codice fiscale ZMRPKC73R12H780Z",
        "ZMRPKC73R12H780Z",
    ),
    ("nl_bsn", "BSN 456789236", "456789236"),
    (
        "be_national_number",
        "rijksregisternummer 91.07.22-406.21",
        "91.07.22-406.21",
    ),
    (
        "be_national_number",
        "rijksregisternummer 205.03.14-237.51",
        "205.03.14-237.51",
    ),
    (
        "be_national_number",
        "rijksregisternummer 299.03.14-237.17",
        "299.03.14-237.17",
    ),
    ("pl_pesel", "PESEL number 920 713 147 64", "920 713 147 64"),
    ("pt_nif", "NIF 234567899", "234567899"),
    (
        "pt_nif",
        "número de contribuinte: 162 738 498",
        "162 738 498",
    ),
    ("pt_nif", "tax number 234567899", "234567899"),
    ("at_sv_nr", "SV-Nr. 1230 150885", "1230 150885"),
    (
        "at_sv_nr",
        "social insurance number 1230-150885",
        "1230-150885",
    ),
    ("ie_ppsn", "PPSN: 1234567 T", "1234567 T"),
    ("ie_ppsn", "PPS number 7654321PA", "7654321PA"),
    ("ie_ppsn", "PPSN 1234567/T", "1234567/T"),
    ("ie_ppsn", "PPSN:1234567 / T", "1234567 / T"),
    ("ie_ppsn", "PPS No 1234567 - TW", "1234567 - TW"),
    ("ie_ppsn", "PPS number ref7654321PAtail", "7654321PA"),
    ("se_personnummer", "personnummer 850709-3253", "850709-3253"),
    (
        "se_personnummer",
        "personal identity number: 19850709 3253",
        "19850709 3253",
    ),
    ("ro_cnp", "CNP: 1850709401231", "1850709401231"),
    (
        "ro_cnp",
        "cod numeric personal 1 850709 401231",
        "1 850709 401231",
    ),
    (
        "ro_cnp",
        "personal numeric code 1850709401231",
        "1850709401231",
    ),
    (
        "cz_sk_rodne_cislo",
        "rodné číslo 855709/1235",
        "855709/1235",
    ),
    (
        "cz_sk_rodne_cislo",
        "rodne cislo: 855709 1235",
        "855709 1235",
    ),
    ("cz_sk_rodne_cislo", "RČ 450709/123", "450709/123"),
    ("cz_sk_rodne_cislo", "birth number 450709123", "450709123"),
    ("gr_afm", "AFM 123456783", "123456783"),
    ("gr_afm", "A.F.M.: 090 876 541", "090 876 541"),
    ("gr_amka", "AMKA 09078512341", "09078512341"),
    ("gr_amka", "AMKA: 090785 12341", "090785 12341"),
    (
        "gr_amka",
        "Greek social insurance number: 09078512341",
        "09078512341",
    ),
    ("gr_afm", "Greek tax number: 123456783", "123456783"),
    ("bg_egn", "EGN 8507091237", "8507091237"),
    ("bg_egn", "unified civil number 850709 1237", "850709 1237"),
];

/// A value whose check digit fails: it stays in clear while no label names
/// it, and a label names it.
///
/// The Italian value is the lower-case spelling: the bank rule reads the last
/// twelve characters of an upper-case codice fiscale as an IBAN guess, which
/// is main's business and not this rule's.
const FAILURES: &[(&str, &str, &str)] = &[
    ("de_steuer_id", "26954371828", "Steuer-ID 26954371828"),
    ("es_dni", "12345678A", "DNI 12345678A"),
    ("es_dni", "X1234567A", "NIE X1234567A"),
    (
        "it_codice_fiscale",
        "zmrpkc73r12h780y",
        "codice fiscale zmrpkc73r12h780y",
    ),
    ("nl_bsn", "456789237", "BSN 456789237"),
    (
        "be_national_number",
        "91.07.22-406.22",
        "rijksregisternummer 91.07.22-406.22",
    ),
    (
        "be_national_number",
        "205.03.14-237.52",
        "rijksregisternummer 205.03.14-237.52",
    ),
    (
        "be_national_number",
        "299.03.14-237.18",
        "rijksregisternummer 299.03.14-237.18",
    ),
    ("pl_pesel", "92071314765", "PESEL 92071314765"),
    ("at_sv_nr", "1231150885", "SV-Nr 1231150885"),
    ("ie_ppsn", "1234567A", "PPSN 1234567A"),
    ("ie_ppsn", "1234567/A", "PPSN 1234567/A"),
    ("ie_ppsn", "1234567 / A", "PPSN:1234567 / A"),
    ("ie_ppsn", "1234567 - AB", "PPS No 1234567 - AB"),
    ("ie_ppsn", "1234567 . A", "PPSN 1234567 . A"),
    // `850709-3254` is a valid rodné číslo: the failing value is another.
    ("se_personnummer", "850709-3255", "personnummer 850709-3255"),
    // A valid NIF stays in clear without a label: the rule reads labels only.
    ("pt_nif", "234567899", "NIF 234567899"),
    (
        "cz_sk_rodne_cislo",
        "855709/1236",
        "rodné číslo 855709/1236",
    ),
    ("gr_amka", "09078512342", "AMKA 09078512342"),
    // Seal A r1 (#348): the English label names a check-failing AMKA too.
    (
        "gr_amka",
        "09078512342",
        "Greek social insurance number: 09078512342",
    ),
    ("gr_afm", "123456783", "tax identification number 123456783"),
    ("bg_egn", "8507091238", "EGN 8507091238"),
    // A valid AFM and a rodné číslo of nine digits stay in clear without a
    // label: they carry no check that keeps a bare rule rare.
    ("gr_afm", "123456783", "AFM 123456783"),
    ("cz_sk_rodne_cislo", "450709/123", "RČ 450709/123"),
];

/// Every rule of the work order.
fn rules() -> Vec<Box<dyn Recognizer>> {
    vec![
        Box::new(DeSteuerIdRecognizer::new()),
        Box::new(EsDniRecognizer::new()),
        Box::new(ItCodiceFiscaleRecognizer::new()),
        Box::new(NlBsnRecognizer::new()),
        Box::new(BeNationalNumberRecognizer::new()),
        Box::new(PlPeselRecognizer::new()),
        Box::new(PtNifRecognizer::new()),
        Box::new(AtSvNrRecognizer::new()),
        Box::new(IePpsnRecognizer::new()),
        Box::new(SePersonnummerRecognizer::new()),
        Box::new(Eu1cRecognizer::new()),
    ]
}

/// The spans the rule of a class reads in `text`: every span names its rule.
fn spans_of(class: &str, text: &str) -> Vec<Span> {
    rules()
        .iter()
        .flat_map(|rule| rule.analyze(text))
        .filter(|span| span.recognizer == class)
        .collect()
}

/// Every spelling is hidden in both modes: the value never reaches the cloud.
#[test]
fn every_spelling_is_hidden_in_both_modes() {
    let mut missed = Vec::new();
    for (class, input, value) in SPELLINGS.iter().chain(LABELLED) {
        let start = input.find(value).expect("the value is in the text");
        let end = start + value.len();
        for mode in MODES {
            let (output, _) = issue(mode, input).expect("the gate issues the text");
            if output.contains(value) {
                missed.push(format!("{class} {mode:?} {input:?} kept {value:?}"));
                continue;
            }
            let ranges = masked(mode, input).expect("the gate issues the text");
            if !covered(&ranges, start, end) {
                missed.push(format!(
                    "{class} {mode:?} {input:?} did not cover {value:?}"
                ));
            }
        }
    }
    assert!(
        missed.is_empty(),
        "{} missed:\n{}",
        missed.len(),
        missed.join("\n")
    );
}

/// A value whose check digit fails stays in clear while no label names it.
#[test]
fn a_check_that_fails_stays_in_clear_without_a_label() {
    let mut missed = Vec::new();
    for (class, value, _) in FAILURES {
        let (output, _) = issue(MODES[1], value).expect("the gate issues the text");
        if !output.contains(value) {
            missed.push(format!("{class} {value:?} was removed in open mode"));
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

/// A label names the value, so a typo in a real document is still hidden.
#[test]
fn a_label_hides_a_value_whose_check_fails() {
    let mut missed = Vec::new();
    for (class, value, labelled) in FAILURES {
        for mode in MODES {
            let (output, _) = issue(mode, labelled).expect("the gate issues the text");
            if output.contains(value) {
                missed.push(format!("{class} {mode:?} {labelled:?} kept {value:?}"));
            }
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

/// EU-KERNEL-1c: a CNP whose check fails is not read without a label, and a
/// label hides it. Main's South African rule already removes a bare run of
/// thirteen digits in both modes, so the gate's output is main's business.
#[test]
fn a_romanian_cnp_whose_check_fails_needs_a_label() {
    assert!(spans_of("ro_cnp", "1850709401232").is_empty());
    assert!(!spans_of("ro_cnp", "CNP 1850709401232").is_empty());
    assert_value_hidden_in_both_modes("CNP 1850709401232", "1850709401232");
}

/// EU-KERNEL-1c: a value issued whole and wrapped at the end of a line is
/// still whole, in both modes and without a label.
#[test]
fn a_1c_value_wrapped_at_a_line_end_is_hidden() {
    for (text, value) in [
        ("CZ 855709/\n1235 ok", "855709/\n1235"),
        ("RO 1850709\r\n401231 ok", "1850709\r\n401231"),
        ("GR 090785\n12341 ok", "090785\n12341"),
        ("BG 850709-\n1237 ok", "850709-\n1237"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
    // A break that joins a valid value to more digits is a run more: the
    // value at its head is still read.
    assert_value_hidden_in_both_modes("8507091237-\n42", "8507091237");
}

/// The Italian control character is a letter: the remainder of the odd and
/// even tables stands for the letter `A` to `Z` and never for a digit.
#[test]
fn the_italian_control_character_is_always_a_letter() {
    let value = "AAAAAA00A10H501B";
    assert_hidden_in_both_modes(value);
    // A digit in the place of the control character is not a codice fiscale.
    assert!(
        ItCodiceFiscaleRecognizer::new()
            .analyze("AAAAAA00A10H5011")
            .is_empty(),
        "the rule read a value whose control character is a digit"
    );
}

/// The Italian shape is six letters, two digits, the letter of the month, two
/// digits, the letter of the place, three digits and the control letter; a
/// digit of the omocodia stands for its letter and the check follows.
#[test]
fn the_italian_shape_keeps_three_digits_of_the_place() {
    for value in ["ZMRPKC99R12H780J", "ZMRPKCV9R12H780J"] {
        assert_hidden_in_both_modes(value);
        let spans = ItCodiceFiscaleRecognizer::new().analyze(value);
        assert!(
            spans
                .iter()
                .any(|span| span.start == 0 && span.end == value.len()),
            "{value:?} -> {spans:?}"
        );
    }
}

/// The Spanish control letter stands after a hyphen, a space, a dot or a
/// single line break, and the NIE keeps its letter before the digits.
#[test]
fn the_spanish_control_letter_may_follow_a_separator() {
    for value in ["12345678-Z", "12345678 Z", "12345678\nZ", "X-1234567-L"] {
        assert_hidden_in_both_modes(value);
        let spans = EsDniRecognizer::new().analyze(value);
        assert!(
            spans
                .iter()
                .any(|span| span.start == 0 && span.end == value.len()),
            "{value:?} -> {spans:?}"
        );
    }
}

/// The Belgian check of a birth after 2000 is computed on the number with the
/// century in front.
#[test]
fn the_belgian_century_in_front_carries_its_own_check() {
    for value in ["05031423780", "99.03.14-237.17", "299.03.14-237.17"] {
        assert_hidden_in_both_modes(value);
        let spans = BeNationalNumberRecognizer::new().analyze(value);
        assert!(
            spans
                .iter()
                .any(|span| span.start == 0 && span.end == value.len()),
            "{value:?} -> {spans:?}"
        );
    }
}

/// A value that stands in prose is not part of an opaque token: the length of
/// a token counts its alphanumerics, never the punctuation of the value.
#[test]
fn a_value_glued_to_prose_is_not_an_opaque_token() {
    for (text, value) in [
        ("ref05.03.14-238.79tail", "05.03.14-238.79"),
        ("ref26.954.371.827tail", "26.954.371.827"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
}

/// A run of separators that holds a line break is one separator: a value
/// wrapped after a hyphen or a dot stays one value.
#[test]
fn a_value_wrapped_after_a_separator_stays_one_value() {
    for value in [
        "05.03.14-\n238.79",
        "05.03.14-\r\n238.79",
        "26.954.\n371.827",
        "26.954.\r\n371.827",
    ] {
        assert_hidden_in_both_modes(value);
    }
}

/// The siblings keep their own shape: the Spanish control letter stands after
/// a separator, and the Dutch BSN is nine consecutive digits.
#[test]
fn the_sibling_rules_keep_their_own_shape() {
    // Spain: the value glued to prose, and the value wrapped after a
    // separator: the control letter stands after the one separator, and the
    // NIE keeps its letter before the digits.
    assert_value_hidden_in_both_modes("ref12.345.678Ztail", "12.345.678Z");
    for value in ["12.345.678-\nZ", "12.345.678-\r\nZ", "X-\n1234567L"] {
        assert_hidden_in_both_modes(value);
    }
    // The Netherlands: a BSN glued to prose is still a BSN.
    assert_value_hidden_in_both_modes("ref456789236tail", "456789236");
    // The BSN is issued as nine consecutive digits: a grouped or a wrapped run
    // is a telephone number or a reference, not a BSN. The rule is unchanged.
    for value in ["456 789 236", "45678\n9236"] {
        assert!(
            NlBsnRecognizer::new().analyze(value).is_empty(),
            "{value:?} was read as a BSN"
        );
    }
    // A value that a line break follows keeps its own run: the joined run is a
    // run more, never a run less.
    assert_value_hidden_in_both_modes("26954371827-\n3", "26954371827");
}

/// The value never reaches the cloud: it is hidden in Private mode and
/// removed in Open mode, and the gate masks every byte of it.
fn assert_hidden_in_both_modes(value: &str) {
    for mode in MODES {
        let (output, _) = issue(mode, value).expect("the gate issues the text");
        assert!(!output.contains(value), "{mode:?} kept {value:?}");
        let ranges = masked(mode, value).expect("the gate issues the text");
        assert!(
            covered(&ranges, 0, value.len()),
            "{mode:?} did not cover {value:?}"
        );
    }
}

/// The value inside the text never reaches the cloud: it is hidden in Private
/// mode and removed in Open mode, and the gate masks every byte of it. The
/// prose around it stays in clear.
fn assert_value_hidden_in_both_modes(text: &str, value: &str) {
    let start = text.find(value).expect("the value is in the text");
    let end = start + value.len();
    for mode in MODES {
        let (output, _) = issue(mode, text).expect("the gate issues the text");
        assert!(!output.contains(value), "{mode:?} kept {value:?}");
        let ranges = masked(mode, text).expect("the gate issues the text");
        assert!(
            covered(&ranges, start, end),
            "{mode:?} did not cover {value:?}"
        );
    }
}

/// Every rule finds its own value and names itself, so the span says which
/// rule read it.
#[test]
fn every_rule_finds_its_own_value() {
    for (class, input, value) in SPELLINGS {
        let spans = spans_of(class, input);
        let start = input.find(value).expect("the value is in the text");
        let end = start + value.len();
        assert!(
            spans
                .iter()
                .any(|span| span.start <= start && span.end >= end),
            "{class} {input:?} -> {spans:?}"
        );
        assert!(spans.iter().all(|span| span.kind == EntityKind::NationalId));
    }
}

/// A rule reads nothing in a value whose check digit fails.
#[test]
fn a_rule_reads_nothing_in_a_value_whose_check_fails() {
    for (class, value, _) in FAILURES {
        assert!(
            spans_of(class, value).is_empty(),
            "{class} masked {value:?} without a label"
        );
    }
    // The upper-case codice fiscale is not read either: the bank rule's IBAN
    // guess over its last twelve characters is main's business.
    assert!(ItCodiceFiscaleRecognizer::new()
        .analyze("ZMRPKC73R12H780Y")
        .is_empty());
}

/// The rules scan in linear time: ten times the input costs ten times the
/// work, not a hundred. The bound and the floor are the ones of the H14
/// test.
#[test]
fn the_rules_scan_in_linear_time() {
    for unit in [
        "26954371827 ",
        "12345678Z ",
        "X1234567L ",
        "ZMRPKC73R12H780Z ",
        "456789236 ",
        "91.07.22-406.21 ",
        "05.03.14-\n238.79 ",
        "26.954.\n371.827 ",
        "92071314764 ",
        "NIF 234567899 ",
        "1230 150885 ",
        "1234567TA ",
        "850709+3253 ",
        "1850709401231 ",
        "855709/1235 ",
        "AFM 123456783 ",
        "09078512341 ",
        "8507091237 ",
    ] {
        let flood = |size: usize| unit.repeat(size / unit.len());
        let (small, big) = (fastest(&flood(1_000)), fastest(&flood(10_000)));
        println!(
            "{unit:?}: {small:?} -> {big:?} ({:.1}x)",
            big.as_secs_f64() / small.as_secs_f64().max(1e-9)
        );
        assert!(
            big.as_secs_f64() <= 20.0 * small.as_secs_f64().max(1e-5),
            "{unit:?}: {small:?} -> {big:?}"
        );
    }
}

/// The fastest of three runs of every rule over `text`: a loaded machine must
/// not decide a bound.
fn fastest(text: &str) -> std::time::Duration {
    let rules = rules();
    (0..3)
        .map(|_| {
            let started = std::time::Instant::now();
            for rule in &rules {
                let _ = rule.analyze(text);
            }
            started.elapsed()
        })
        .min()
        .unwrap_or_default()
}

/// The full-width spelling of a value reads like the plain one.
#[test]
fn a_full_width_value_reads_like_the_plain_one() {
    assert_eq!(wide("26954371827"), "２６９５４３７１８２７");
    let text = wide("26954371827");
    let spans = DeSteuerIdRecognizer::new().analyze(&text);
    assert_eq!(spans.len(), 1, "{spans:?}");
    assert_eq!(
        &text[spans[0].start..spans[0].end],
        "２６９５４３７１８２７"
    );
}

/// EU-KERNEL-1b-1: a hash is not a codice fiscale. A sixteen-character window
/// of an md5 digest that holds the shape and the check stays in clear in Open
/// mode: masking it corrupts the digest (a #284 over-mask).
#[test]
fn a_hex_digest_is_not_a_codice_fiscale() {
    let digest = "74059780218effbdd55a96c196d8ae89";
    let text = format!("md5 {digest} ok");
    let (output, _) = issue(MODES[1], &text).expect("the gate issues the text");
    assert!(
        output.contains(digest),
        "open mode masked the digest: {output:?}"
    );
    assert!(ItCodiceFiscaleRecognizer::new().analyze(&text).is_empty());
    // A codice fiscale glued to prose is still one.
    assert_value_hidden_in_both_modes("refZMRPKC73R12H780Zok", "ZMRPKC73R12H780Z");
}

/// EU-KERNEL-1b-1: the control letter of an omocodia codice fiscale is
/// computed over the letters as written.
#[test]
fn the_italian_omocodia_check_reads_the_written_letters() {
    for value in ["qrtnvs83d21f20rx", "QRTNVS83D21F20RX"] {
        assert_hidden_in_both_modes(value);
    }
}

/// EU-KERNEL-1b-1: a control letter after a separator, glued to a prose
/// suffix, is the control letter when the check holds.
#[test]
fn a_spanish_control_letter_glued_to_a_suffix_is_read() {
    for (text, value) in [
        ("ref31.415.926-Ltail", "31.415.926-L"),
        ("refY-2456789-Ntail", "Y-2456789-N"),
        ("ref31.415.926-\nLtail", "31.415.926-\nL"),
        ("refY-2456789.Ntail", "Y-2456789.N"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
    // A word after a space is a word: the number stays in clear without a
    // label, and a check that fails never reads a glued word.
    for text in ["invoice 31415926 Lisbon", "ref31.415.926-Mtail"] {
        assert!(EsDniRecognizer::new().analyze(text).is_empty(), "{text:?}");
    }
}

/// EU-KERNEL-1b-1: a chain of three runs a line break joins still hides the
/// wrapped value at its head.
#[test]
fn a_wrapped_value_followed_by_more_runs_is_hidden() {
    for (text, value) in [
        ("05.03.14-\n238.79-\n99", "05.03.14-\n238.79"),
        ("26.954.\n371.827-\n12-\n7", "26.954.\n371.827"),
        ("7-\n05.03.14-\n238.79", "05.03.14-\n238.79"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
}

/// EU-KERNEL-1b-1 (seal P3): a labelled BSN printed in groups is a BSN.
#[test]
fn a_labelled_bsn_in_groups_is_hidden() {
    for (text, value) in [
        ("BSN 456 789 236", "456 789 236"),
        ("burgerservicenummer: 456.789.236", "456.789.236"),
        ("citizen service number 456 789 236", "456 789 236"),
    ] {
        assert_value_hidden_in_both_modes(text, value);
    }
}

/// EU-KERNEL-1b: look-alikes in prose stay in clear: a telephone number, a
/// word after the digits, a letter that fails the check, a machine line.
#[test]
fn the_1b_rules_leave_look_alikes_alone() {
    for text in [
        "call 070-123 45 67 or 0701 234 567",
        "invoice 1234567 Tuesday",
        "1234567BAX was filed",
        "ref1234567Atail",
        "0953692M4359008FXT<K1",
        "ref7654321PAtail",
        "PPS number ref7654321PBtail",
        "1234567/Tuesday",
        "ticket 1234567 - Tuesday",
        "1234567   /   T",
        "Order 92071314765 shipped.",
    ] {
        let spans: Vec<_> = rules().iter().flat_map(|rule| rule.analyze(text)).collect();
        assert!(spans.is_empty(), "{text:?} -> {spans:?}");
    }
}

/// EU-KERNEL-1c: the over-mask of the bare rules on random numbers in prose,
/// with no label: nine to thirteen digits, compact or grouped with the four
/// separators. A rule that read more than its bound would hide too many order
/// numbers, references and timestamps; the AFM and the nine-digit rodné
/// číslo read labels only, so they read none.
#[test]
fn the_1c_rules_rarely_read_a_random_number() {
    const TEXTS: u32 = 50_000;
    let mut seed: u64 = 0x1c1c_2026;
    let mut next = |below: u64| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (seed >> 33) % below
    };
    let rule = Eu1cRecognizer::new();
    let mut hits = std::collections::BTreeMap::<&str, u32>::new();
    for _ in 0..TEXTS {
        let length = 9 + next(5) as usize;
        let digits: String = (0..length)
            .map(|_| char::from(b'0' + next(10) as u8))
            .collect();
        let separator = [' ', '-', '.', '/'][next(4) as usize];
        let number = match next(4) {
            0 | 1 => digits,
            2 => format!("{}{separator}{}", &digits[..6], &digits[6..]),
            _ => digits
                .as_bytes()
                .chunks(3)
                .map(|group| std::str::from_utf8(group).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(&separator.to_string()),
        };
        for span in rule.analyze(&format!("Order {number} is due.")) {
            *hits.entry(span.recognizer).or_default() += 1;
        }
    }
    let rate = |class: &str| f64::from(hits.get(class).copied().unwrap_or(0)) / f64::from(TEXTS);
    println!("over-mask on {TEXTS} random numbers: {hits:?}");
    for (class, bound) in [
        ("ro_cnp", 0.001),
        ("cz_sk_rodne_cislo", 0.003),
        ("gr_afm", 0.0),
        ("gr_amka", 0.001),
        ("bg_egn", 0.003),
    ] {
        assert!(
            rate(class) <= bound,
            "{class}: {:.4} > {bound}",
            rate(class)
        );
    }
}
