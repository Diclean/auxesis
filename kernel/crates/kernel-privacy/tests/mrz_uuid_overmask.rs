//! MRZ-UUID-OVERMASK: complete UUIDs in ordinary text are identifiers, while
//! passport values and machine-readable-zone data keep their existing masks.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}

use cases::{covered, issue, masked, MODES};
use kernel_core::privacy::PrivacyMode;

const UUID: &str = "EB238270-1B4C-4E2A-9F3D-0A1B2C3D4E5F";

#[test]
fn unicode_neighbours_keep_origin_main_exact_ranges_in_both_modes() {
    // Ranges captured from origin/main, kept as a floor. Only original ASCII token
    // boundaries can qualify a UUID; folded neighbours retain main's masks.
    let cases = [
        ("\u{200B}", vec![(0, 11)]),
        ("\u{FEFF}", vec![(0, 11)]),
        ("\u{00A0}", vec![(2, 10)]),
        ("\u{FF0D}", vec![(3, 11)]),
        ("é", vec![(2, 36)]),
    ];
    for (neighbour, expected) in cases {
        let text = format!("{neighbour}{UUID}");
        for mode in MODES {
            // Strict superset: later rules may mask more, never less.
            let ranges = masked(mode, &text).expect("the gate allows the text");
            for &(s, e) in &expected {
                assert!(
                    covered(&ranges, s, e),
                    "{mode:?} masks less than origin/main for {neighbour:?}: {ranges:?}"
                );
            }
        }
    }
}

#[test]
fn calendar_uuids_round_trip_in_private_and_open_modes() {
    for id in [UUID.to_string(), UUID.to_lowercase()] {
        let text = format!("Calendar event id: {id}; starts at 10:30.");
        for mode in MODES {
            let (output, _) = issue(mode, &text).expect("the gate allows calendar text");
            assert_eq!(output, text, "{mode:?} changed a complete UUID");
            let ranges = masked(mode, &text).expect("the gate allows calendar text");
            let start = text.find(&id).expect("UUID in calendar text");
            assert!(
                !ranges
                    .iter()
                    .any(|&(s, e)| s < start + id.len() && start < e),
                "{mode:?} still reports the UUID as a passport: {ranges:?}"
            );
        }
    }
}

#[test]
fn passport_values_near_keywords_remain_masked_in_both_modes() {
    for (text, value) in [
        ("passport no: AB123456", "AB123456"),
        ("passeport n°: L898902C3", "L898902C3"),
    ] {
        for mode in MODES {
            let ranges = masked(mode, text).expect("the gate allows passport text");
            let start = text.find(value).expect("passport value in text");
            assert!(
                covered(&ranges, start, start + value.len()),
                "{mode:?}: {text}"
            );
        }
    }
}

#[test]
fn an_mrz_line_containing_a_uuid_like_run_remains_masked() {
    let line = "P<UTO<<<<<<<<EB2382701B4C4E2A9F3D0A1B2C3D4E5F<<<<<<<<";
    let text = format!("MRZ:\n{line}");
    for mode in MODES {
        let ranges = masked(mode, &text).expect("the gate allows MRZ text");
        let start = text.find(line).expect("MRZ line in text");
        assert!(
            covered(&ranges, start, start + line.len()),
            "{mode:?}: {text}"
        );
    }
}

#[test]
fn non_ascii_glue_keeps_main_behavior() {
    let text = format!("é{UUID}");
    for mode in MODES {
        let ranges = masked(mode, &text).expect("the gate allows text");
        assert!(
            covered(&ranges, 2, text.len() - 2),
            "{mode:?} stopped masking the glued UUID-like run as on main: {ranges:?}"
        );
        assert!(
            !covered(&ranges, text.len() - 2, text.len()),
            "{mode:?} changed the clear suffix as on main: {ranges:?}"
        );
    }
}

#[test]
fn ordinary_passport_without_uuid_stays_masked_in_private_and_open_modes() {
    let text = "document passport: L898902C3";
    let value = "L898902C3";
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let ranges = masked(mode, text).expect("the gate allows passport text");
        let start = text.find(value).expect("passport value in text");
        assert!(
            covered(&ranges, start, start + value.len()),
            "{mode:?}: {text}"
        );
    }
}
