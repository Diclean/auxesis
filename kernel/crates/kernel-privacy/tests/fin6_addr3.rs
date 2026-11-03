//! FIN-6-ADDR-3: two address forms the privacy kernel leaks today.
//!
//! * a mixed-case English street name (`42 mApLe Road`): main's capitalised
//!   class wants an upper-case first letter and its lower-case class wants an
//!   all-lower word, so a word that mixes the two falls between the two rules;
//! * a postcode glued to its city (`31000toulouse`): the postcode-and-city
//!   rules need a space between the two.
//!
//! Both are hidden in Private and removed in Open, through the same public
//! API the other address tests use. The traps (a quantity, a version, a time,
//! a room) stay clear. Every value is invented.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, issue, masked, MODES};
use kernel_privacy::Recognizer;

/// The work order's probes, with the value each one must hide. The value is
/// the whole text but the `ref … ok` carrier, whose glue stays in the clear.
const PROBES: &[(&str, &str)] = &[
    (
        "42 mApLe Road, Leeds LS6 2QT",
        "42 mApLe Road, Leeds LS6 2QT",
    ),
    ("7 OAK street, York YO1 7HH", "7 OAK street, York YO1 7HH"),
    ("12 kInG's Avenue", "12 kInG's Avenue"),
    ("31000toulouse", "31000toulouse"),
    ("31000Toulouse", "31000Toulouse"),
    ("75011paris", "75011paris"),
    ("ref 31000toulouse ok", "31000toulouse"),
];

/// Texts that hold no address: the address rule must find nothing in them and
/// the gate must issue them unchanged.
const TRAPS: &[&str] = &[
    "order 31000 units",
    "version 12345abc",
    "call me at 15h30",
    "Room 42 Road Map",
];

/// Every probe is an address in both modes: the value never reaches the cloud.
#[test]
fn every_probe_is_hidden_in_both_modes() {
    let mut missed = Vec::new();
    for (input, value) in PROBES {
        let start = input.find(value).expect("the value is in the text");
        let end = start + value.len();
        for mode in MODES {
            let (output, _) = issue(mode, input).expect("the gate issues the text");
            if output.contains(value) {
                missed.push(format!("{mode:?} {input:?} kept {value:?} in {output:?}"));
                continue;
            }
            let ranges = masked(mode, input).expect("the gate issues the text");
            if !covered(&ranges, start, end) {
                missed.push(format!("{mode:?} {input:?} did not cover {value:?}"));
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

/// The traps stay clear: the address rule finds nothing and the gate issues
/// every one of them byte for byte.
#[test]
fn the_traps_stay_clear_in_both_modes() {
    let address = kernel_privacy::recognizers::address::AddressRecognizer::new();
    for trap in TRAPS {
        let spans = address.analyze(trap);
        assert!(spans.is_empty(), "{trap:?} got an address span: {spans:?}");
        for mode in MODES {
            let (output, _) = issue(mode, trap).expect("the gate issues the text");
            assert_eq!(output, *trap, "{mode:?} over-masked {trap:?}");
        }
    }
}
