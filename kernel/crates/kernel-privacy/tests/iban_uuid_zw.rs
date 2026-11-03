//! IBAN UUID skip eligibility comes only from original ASCII boundaries.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}

use cases::{covered, issue, masked, MODES};

const UUID: &str = "01234567-AB12-4CDE-8F23-456789ABCDEF";

#[test]
fn unicode_neighbours_retain_legacy_exact_ranges_in_both_modes() {
    let cases = [
        ("\u{200B}", vec![(25, 52)]),
        ("\u{FEFF}", vec![(25, 52)]),
        ("\u{00A0}", vec![(24, 51)]),
        ("\u{FF0D}", vec![(25, 52)]),
        ("é", vec![(24, 51)]),
    ];
    for (neighbour, expected) in cases {
        let text = format!("Calendar id: {neighbour}{UUID};");
        for mode in MODES {
            let ranges = masked(mode, &text).expect("the gate allows calendar text");
            assert_eq!(
                ranges, expected,
                "{mode:?} changed the exact legacy mask for neighbour {neighbour:?}"
            );
        }
    }
}

#[test]
fn plain_ascii_calendar_uuid_round_trips_in_both_modes() {
    let text = format!("Calendar id: {UUID};");
    for mode in MODES {
        let (output, _) = issue(mode, &text).expect("the gate allows calendar text");
        assert_eq!(output, text, "{mode:?} changed a complete UUID");
    }
}

#[test]
fn a_valid_iban_inside_uuid_shape_stays_masked() {
    let text = "BE685390-0754-7034-ABCD-EF0123456789";
    let value = "BE685390-0754-7034";
    for mode in MODES {
        let ranges = masked(mode, text).expect("the gate allows a valid IBAN");
        assert!(
            covered(&ranges, 0, value.len()),
            "{mode:?} left the valid IBAN unmasked: {ranges:?}"
        );
    }
}
