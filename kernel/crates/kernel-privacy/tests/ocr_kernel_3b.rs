//! OCR-KERNEL-3b-1 acceptance: a date of birth after an EN/FR label is hidden
//! in both modes, and nothing else moves.
//!
//! Impossible calendar dates, cue traps (`Adobe`, `Os-born`, `invoice_dob`) and
//! prose keep exactly main's masks in Private and Open.
//! `data/ocr_kernel_3b_main.txt` freezes main's masks for every input; refreeze
//! on origin/main only (`-- --ignored freeze --nocapture`). Every value is
//! invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};

type Ranges = Vec<(usize, usize)>;

const FIXTURE: &str = include_str!("data/ocr_kernel_3b_main.txt");

/// Label positives: `(text, value)`.
const LABELLED: &[(&str, &str)] = &[
    ("Date of birth : 14 March 1987", "14 March 1987"),
    ("DOB 03/14/1987", "03/14/1987"),
    ("born on 1987-03-14", "1987-03-14"),
    ("Date of Birth\n4 July 1979", "4 July 1979"),
    ("dob: March 14, 1987", "March 14, 1987"),
    ("DOB: Sept. 9, 1987", "Sept. 9, 1987"),
    ("D.O.B. 14/03/1985", "14/03/1985"),
    ("DOB-14/03/1985", "14/03/1985"),
    ("DOB: 29.02.2000", "29.02.2000"),
    ("DOB: 28 February 1987", "28 February 1987"),
    ("Date de naissance : 14/03/1987", "14/03/1987"),
    ("Né le 14/03/1987 à Lyon", "14/03/1987"),
    ("née le 3 mars 1987", "3 mars 1987"),
    ("Né le 14 févr. 1987", "14 févr. 1987"),
    ("Né le 14 fevr. 1987", "14 fevr. 1987"),
    ("Né le 14 FÉVR. 1987", "14 FÉVR. 1987"),
    ("né le 2 janv. 1990", "2 janv. 1990"),
    ("née le 1 janv 1990", "1 janv 1990"),
    ("née le 9 avr. 1991", "9 avr. 1991"),
    ("Né le 5 juil. 1985", "5 juil. 1985"),
    ("Date de naissance: 31 déc. 1999", "31 déc. 1999"),
    ("né le 31 dec. 1999", "31 dec. 1999"),
    ("né le 12 sept. 1982", "12 sept. 1982"),
    ("née le 3 oct. 1982", "3 oct. 1982"),
    ("née le 3 nov. 1982", "3 nov. 1982"),
    ("né le 1er août 1980", "1er août 1980"),
    ("né le 1 aout 1980", "1 aout 1980"),
    ("née le 7 mai 1980", "7 mai 1980"),
    ("née le 7 juin 1980", "7 juin 1980"),
    ("date de naissance : 29 février 2000", "29 février 2000"),
    // Fix round 1: blanks between the fields of a numeric date.
    ("DOB: 12 03 1987", "12 03 1987"),
    ("Date of birth 12 03 1987", "12 03 1987"),
    ("born on 1987 03 14", "1987 03 14"),
    ("Né le 12 03 1987", "12 03 1987"),
    ("née le 12  03  1987", "12  03  1987"),
    ("date de naissance : 12 03 87", "12 03 87"),
    // Repeated blanks inside a multiword label.
    ("Date   of birth: 14/03/1987", "14/03/1987"),
    ("Date of    birth : 14 March 1987", "14 March 1987"),
    ("Birth   date: 12/03/1987", "12/03/1987"),
    ("Date \t of\tbirth: 12/03/1987", "12/03/1987"),
    ("Né(e)  le 14/03/1987", "14/03/1987"),
    ("Date  de   naissance 14 mars 1987", "14 mars 1987"),
    ("Née   le 3 mars 1987", "3 mars 1987"),
    // A month-name date with a two-digit year.
    ("DOB: 12 March 87", "12 March 87"),
    ("DOB: March 12, 87", "March 12, 87"),
    ("Date of birth: 12 Mar 87", "12 Mar 87"),
    ("Né le 12 mars 87", "12 mars 87"),
    ("née le 12 févr. 87", "12 févr. 87"),
    ("date de naissance 1er août 87", "1er août 87"),
    // The value glued to its label.
    ("DOB12/03/1987", "12/03/1987"),
    ("dob12.03.1987", "12.03.1987"),
    ("DOB12 March 1987", "12 March 1987"),
    ("DOB1987-03-14", "1987-03-14"),
    ("Date of birth12/03/1987", "12/03/1987"),
    ("Date de naissance12/03/1987", "12/03/1987"),
    // Fix round 2: label aliases, JSON fields, form blanks, OCR noise, and the
    // blanks seal A tried by hand.
    ("D.O.B 12.3.87", "12.3.87"),
    ("D.O.B: 12/03/1987", "12/03/1987"),
    ("DDN: 12/03/1987", "12/03/1987"),
    ("ddn 12 mars 1987", "12 mars 1987"),
    ("DDN 12/03/87", "12/03/87"),
    ("{\"DOB\": \"12/03/1987\"}", "12/03/1987"),
    ("{\"dob\":\"12/03/1987\"}", "12/03/1987"),
    ("{\"date_of_birth\": \"1987-03-14\"}", "1987-03-14"),
    ("{\"dateOfBirth\": \"12 March 1987\"}", "12 March 1987"),
    ("{\"birthDate\": \"1987-03-14\"}", "1987-03-14"),
    ("{\"date_de_naissance\": \"12/03/1987\"}", "12/03/1987"),
    ("{'DOB': '12/03/1987'}", "12/03/1987"),
    ("{\"DDN\": \"12/03/1987\"}", "12/03/1987"),
    ("DOB: ____ 12/03/1987", "12/03/1987"),
    ("Date of birth: ________ 12 March 1987", "12 March 1987"),
    ("Né le: ____ 12/03/1987", "12/03/1987"),
    ("DOB: ____\n12/03/1987", "12/03/1987"),
    ("D0B: 12/03/1987", "12/03/1987"),
    ("d0b 12/03/1987", "12/03/1987"),
    ("DOB: I2/03/1987", "I2/03/1987"),
    ("DOB: 12/O3/1987", "12/O3/1987"),
    ("DOB: l2/03/l987", "l2/03/l987"),
    ("DOB: 12/031987", "12/031987"),
    ("DOB: 12.031987", "12.031987"),
    ("DOB:\u{a0}12/03/1987", "12/03/1987"),
    ("DOB:\t12/03/1987", "12/03/1987"),
    ("DOB: １２/０３/１９８７", "１２/０３/１９８７"),
];

/// Forms of fix round 1 that are no date of birth, or no real date, and keep
/// main's masks: a date with blanks or a short year and no birth label, and an
/// impossible date in each new form.
const MORE_LOOKALIKES: &[&str] = &[
    // Fix round 2: wrappers with no date, labels inside words, other dates.
    "{\"DOB\": \"\"}",
    "{\"DOB\": null}",
    "{\"dob\": \"n/a\"}",
    "{\"date_of_birth\": \"unknown\"}",
    "DOB: ____",
    "DOB: ____ unknown",
    "The DOB field is required.",
    "Please enter your DOB.",
    "D0B template",
    "D.O.B form",
    "DDN storage 12/03/2026",
    "ADDN 12/03/2026",
    "DDNS 12/03/2026",
    "Oddness 12/03/2026",
    "Due: 12/03/2026",
    "Payment due: 12 03 2026",
    "Date: 12/03/2026",
    "{\"due\": \"12/03/2026\"}",
    "{\"created_at\": \"2026-03-12\"}",
    "DDN: 31/02/1987",
    "D.O.B 13/13/1987",
    "{\"DOB\": \"31/04/1987\"}",
    "DOB: I3/I3/1987",
    "DOB: 13/131987",
    "D0B: OO/OO/OOOO",
    "DOB: ____ OO/OO/OOOO",
    "Order 12 03 1987 units",
    "Order 12 03 87 units",
    "version 12 March 87",
    "Order 12 mars 87 reçu",
    "12 03 1987",
    "12 March 87",
    "Invoice 12 03 1987",
    "ref 12 March 87",
    "Date   of invoice: 12/03/1987",
    "Date  de   facture 12 mars 87",
    "DOB: 31 02 1987",
    "DOB: 13 13 1987",
    "DOB: 31 April 87",
    "DOB: March 32, 87",
    "Né le 31 avr. 87",
    "Date   of birth: 31 02 1987",
    "DOB31/02/1987",
    "Adobe12/03/2024",
    "mydob12/03/1987",
    "Reborn12/03/2024",
    "dob12abc 12/03/1987",
    "DOB: 1987 13 14",
];

/// Impossible dates after a label (main leaves them as they are).
const IMPOSSIBLE_DATES: &[&str] = &[
    "DOB: 31.02.2000",
    "DOB: 31 February 1987",
    "DOB: 14/13/1987",
    "DOB: 29.02.1900",
    "DOB: February 30, 1987",
    "DOB: 1987-04-31",
    "Né le 31 févr. 1987",
    "Né le 29 févr. 1999",
    "née le 31 avr. 1987",
    "née le 31 juin 1987",
    "date de naissance : 32 janv. 1987",
    "né le 29 février 1900",
    "Né le 0 déc. 1987",
];

/// Prose and look-alikes that keep main's masks.
const PROSE: &[&str] = &[
    "Invoice date: 14/03/2024",
    "Date : 14.03.2024",
    "Date de facture : 14/03/2024",
    "Due 2024-03-14, total 59.99",
    "Meeting on 14 March 2024 at 10:00",
    "14/03/2024",
    "born in 1987",
    "Date of birth: unknown",
    "Je ne le sais pas.",
    "Il est né le jour de la fête.",
    "DOB: OO/OO/OOOO",
    "Adobe invoice 14/03/2024, total 59.99",
    "Osborne & Co paid us on 14/03/2024",
    "Mr Dobson signed on 2024-03-14",
    "Born to run tour 12/06/2025 tickets",
    "Dobby the elf on 01/02/2025",
    "Reborn 2024-05-06 release",
    "Os-born 14/03/2024",
    "invoice_dob: 14/03/2024",
    "re-born 14/03/2024",
    "x_DOB 14/03/2024",
    "dob_date 14/03/2024",
    "invoice__dob: 14/03/2024",
    "Os\u{2010}born 14/03/2024",
    "invoice\\_dob: 14/03/2024",
    "x\u{2212}dob 14/03/2024",
    "Os\u{2014}\u{2014}born 14/03/2024",
    "dob\\_date 14/03/2024",
    "Adobe 14 févr. 2024",
];

/// Every look-alike: keeps main's masks in both modes.
fn lookalikes() -> Vec<String> {
    [IMPOSSIBLE_DATES, MORE_LOOKALIKES, PROSE]
        .concat()
        .into_iter()
        .map(String::from)
        .collect()
}

/// Every positive: `(text, value ranges)`.
fn positives() -> Vec<(String, Ranges)> {
    let at = |text: &str, value: &str| {
        let start = text.find(value).expect("the value is in its text");
        (start, start + value.len())
    };
    LABELLED
        .iter()
        .map(|&(t, v)| (t.to_string(), vec![at(t, v)]))
        .collect()
}

/// The differential inputs: the positives, then every look-alike.
fn inputs() -> Vec<(String, Ranges)> {
    let mut out = positives();
    out.extend(lookalikes().into_iter().map(|t| (t, Vec::new())));
    out
}

#[test]
fn labelled_birth_dates_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, values) in positives() {
        for mode in MODES {
            let Some(ranges) = masked(mode, &text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            if values.iter().any(|&(s, e)| !covered(&ranges, s, e)) {
                let output = issue(mode, &text).map(|(o, _)| o);
                wrong.push(format!("{mode:?} {text:?} -> {output:?}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Open returns a cue trap byte for byte, as main did; a labelled date is removed.
#[test]
fn open_removes_a_labelled_date_and_keeps_the_cue_traps() {
    let traps = PROSE.iter().skip_while(|t| !t.starts_with("Adobe invoice"));
    for &text in traps {
        let output = issue(PrivacyMode::Open, text).map(|(o, _)| o);
        assert_eq!(output.as_deref(), Some(text));
    }
    for (text, date) in [
        ("Date of birth: 14/03/1985", "14/03/1985"),
        ("Né le 14 févr. 1987", "14 févr. 1987"),
        ("DOB: 29.02.2000", "29.02.2000"),
    ] {
        let (output, _) = issue(PrivacyMode::Open, text).expect("allowed");
        assert!(
            output.contains("[date of birth removed]") && !output.contains(date),
            "{text:?} -> {output:?}"
        );
    }
}

/// A zero-width character between the label and the date is no part of the
/// date: Open removes the date bytes only (main left these texts as they were).
#[test]
fn a_zero_width_character_before_the_date_is_not_removed() {
    for text in [
        "DOB:\u{200B}12/03/1987",
        "DOB:\u{200B} 12/03/1987",
        "Né le\u{200B}14 mars 1987",
        "Date of birth:\u{200B}\u{200B}12 03 1987",
        "née le \u{FEFF}12 mars 87",
    ] {
        let start = text.find(|c: char| c.is_ascii_digit()).expect("a date");
        let (open, _) = issue(PrivacyMode::Open, text).expect("allowed");
        assert_eq!(
            open,
            format!("{}[date of birth removed]", &text[..start]),
            "{text:?}"
        );
        let (private, _) = issue(PrivacyMode::Private, text).expect("allowed");
        assert!(!private.contains(&text[start..]), "{text:?} -> {private:?}");
    }
}

fn record(ranges: Option<Ranges>) -> String {
    let join = |r: Ranges| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.map_or("!".into(), join)
}

fn parse(record: &str) -> Option<Ranges> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[(String, Ranges)]) -> String {
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

fn main_records(inputs: &[(String, Ranges)]) -> Vec<[Option<Ranges>; 2]> {
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    records
        .iter()
        .map(|record| {
            let mut modes = record.split('|').map(parse);
            [modes.next().expect("private"), modes.next().expect("open")]
        })
        .collect()
}

/// Impossible dates and prose: exactly main's
/// masks, Private and Open.
#[test]
fn lookalikes_keep_main_masks() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let look = lookalikes();
    let mut wrong = Vec::new();
    for ((text, _), main) in inputs.iter().zip(&main) {
        if !look.contains(text) {
            continue;
        }
        for (index, mode) in MODES.into_iter().enumerate() {
            if masked(mode, text) != main[index] {
                let output = issue(mode, text).map(|(o, _)| o);
                wrong.push(format!(
                    "{mode:?} {text:?}: main {:?} -> {output:?}",
                    main[index]
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Every input: no byte main masks is left clear, and no new refusal.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let (mut lost, mut refused) = ([0usize; 2], 0);
    for ((text, _), main) in inputs.iter().zip(main) {
        for (index, main) in main.into_iter().enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += usize::from(main.is_some());
                continue;
            };
            let gone = main
                .unwrap_or_default()
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                eprintln!("{:?} {text:?} lost {gone}", MODES[index]);
            }
            lost[index] += gone;
        }
    }
    eprintln!(
        "{} inputs: bytes lost {lost:?}; refusals {refused}",
        inputs.len()
    );
    assert_eq!((lost, refused), ([0, 0], 0));
}

/// Release only: labels and dates at 16 KiB to 1 MiB; each 4x
/// step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test ocr_kernel_3b -- --ignored timing"]
fn timing_scales_linearly() {
    let mut unit: String = LABELLED.iter().map(|(t, _)| format!("{t}\n")).collect();
    for text in lookalikes() {
        unit.push_str(&text);
        unit.push('\n');
    }
    unit.push_str(&"<<<<ABCD1234".repeat(8));
    unit.push_str("\nDate of birth Date of birth Né le 14/03/2024 Invoice date 2024-03-14\n");
    let time = |bytes: usize| {
        let text = unit.repeat(bytes / unit.len() + 1);
        (0..3)
            .map(|_| {
                let start = Instant::now();
                let _ = issue(PrivacyMode::Private, &text);
                let _ = issue(PrivacyMode::Open, &text);
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let times: Vec<Duration> = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
        .map(time)
        .to_vec();
    eprintln!("ocr kernel 3b text: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
