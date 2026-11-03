//! OCR-KERNEL-3b-1-TODO acceptance: a `,` or `;` after a birth word in prose
//! links no date, so Open leaves the date as main before #300 did; CSV forms
//! (`dob,12/03/1987`, a quoted key, a key at a line start, a cell of a spaced
//! row `Name, DOB, 12/03/1987`) stay hidden. Every value is invented.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::issue;

const REMOVED: &str = "[date of birth removed]";

#[test]
fn a_comma_after_a_birth_word_in_prose_hides_no_date() {
    for (text, date) in [
        ("the DOB, 12/03/2026 deadline", "12/03/2026"),
        ("born, 2026-03-12T10:00", "2026-03-12"),
        (
            "Our startup was born, 12 March 2024, in Paris",
            "12 March 2024",
        ),
        ("The idea was born; 2024-03-12 …", "2024-03-12"),
        // A prose label at a bare line start, a label after a determiner:
        // intended, as `born,`.
        ("Born, 12/03/1987", "12/03/1987"),
        ("Né le, 12/03/1987", "12/03/1987"),
        ("Envoyez la DDN; 12/03/2026 au plus tard", "12/03/2026"),
    ] {
        let (open, _) = issue(PrivacyMode::Open, text).expect("allowed");
        assert!(
            !open.contains(REMOVED) && open.contains(date),
            "{text:?} -> {open:?}"
        );
    }
}

/// Every labelled date seal B found dropped on a721fcce, and the CSV forms:
/// hidden in both modes, as main hides them.
#[test]
fn a_csv_birth_date_is_still_hidden_in_both_modes() {
    for text in [
        "dob,12/03/1987",
        "\"dob\",\"12/03/1987\"",
        "\"dob\", \"12/03/1987\"",
        "DDN;12/03/1987",
        "dob, 12/03/1987",
        "Name: Alice\nDOB, 12/03/1987",
        "x,dob,12/03/1987",
        "x, dob, 12/03/1987",
        "Name, DOB, 12/03/1987",
        "Name; DDN; 12/03/1987",
        "| DOB ; 12/03/1987 |",
        "Name | DOB, 12/03/1987",
        "Name\tDOB, 12/03/1987",
        "Alice: DOB, 12/03/1987",
        "Alice — DOB, 12/03/1987",
        "Alice - DOB, 12/03/1987",
        "Alice / DOB, 12/03/1987",
        "Patient Alice (DOB, 12/03/1987)",
        "(DOB; 12/03/1987)",
        "Nom Alice Date de naissance ; 12/03/1987",
        "Nom Alice Né le ; 12/03/1987",
        "Name Alice Date of birth,\n12/03/1987",
        "Patient: Alice Smith DOB, 12/03/1987",
        "é DOB, 12/03/1987",
        "日本 DOB, 12/03/1987",
        // A possessive names the person: their own date, hidden (seal B r1).
        "Her date of birth, 12 March 1987, is on file.",
        "His date of birth, 12/03/1987, was confirmed.",
        "Please confirm your date of birth, 12/03/1987.",
        "Their DOB, 12/03/1987",
        "Votre date de naissance, 12/03/1987",
        "Sa date de naissance, 12/03/1987, figure au dossier.",
        "Patient Alice\u{a0}DOB, 12/03/1987",
        "Patient: Alice, born, 12/03/1987",
        "Alice (born, 12/03/1987)",
        "Alice\tborn; 12/03/1987",
        "Alice: née le, 12/03/1987",
    ] {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let (output, _) = issue(mode, text).expect("allowed");
            assert!(
                !output.contains("12/03/1987"),
                "{mode:?} {text:?} -> {output:?}"
            );
        }
    }
}
