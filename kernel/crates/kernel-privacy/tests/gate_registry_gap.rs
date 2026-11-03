//! GATE-REGISTRY-GAP-1: the gate hides every prohibited value its own
//! registry finds, in both modes.
//!
//! Two paths dropped bytes the registry (`Registry::new()`) masks:
//!
//! 1. Private mode drops person and organisation spans before the overlap
//!    merge. A name the merge joined to a prohibited value widened that
//!    value's region in the registry, and Open mode removes the whole region,
//!    but Private masked only the value's own span and left the rest clear.
//! 2. Open mode blanks every token-shaped string before detection, so the
//!    registry's fail-closed run for a token that splices a word never fired
//!    there: the run was returned in clear.
//!
//! Every value below is invented.

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{Gate, Registry};
use proptest::prelude::*;

fn grant(mode: PrivacyMode) -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow for A1 in {mode:?}, got {other:?}"),
    }
}

/// Letters and digits, lower-cased.
fn skeleton(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The issued text without its tokens and removal markers.
fn clear_of(out: &str) -> String {
    let (head, tokens) = out.split_once('⟦').unwrap_or((out, ""));
    let mut text = head.to_string();
    for part in tokens.split('⟦') {
        text.push_str(part.split_once('⟧').map_or("", |(_, rest)| rest));
    }
    while let Some(end) = text.find(" removed]") {
        let start = text[..end].rfind('[').unwrap_or(end);
        text.replace_range(start..end + " removed]".len(), " ");
    }
    text
}

/// The privacy-eval leak rule (LEAK-FINDER-1): the region's text, or a run of
/// 6 of its letters and digits the rest of the text does not hold, is still
/// readable in the issued text.
fn leaked(text: &str, start: usize, end: usize, issued: &str) -> bool {
    let value = &text[start..end];
    let rest = format!("{} {}", &text[..start], &text[end..]);
    if issued.contains(value) && !rest.contains(value) {
        return true;
    }
    let (seed, rest, out) = (
        skeleton(value),
        skeleton(&rest),
        skeleton(&clear_of(issued)),
    );
    let seed: Vec<char> = seed.chars().collect();
    let k = seed.len().min(6);
    k > 0
        && seed.windows(k).any(|run| {
            let run: String = run.iter().collect();
            out.contains(&run) && !rest.contains(&run)
        })
}

/// Every prohibited region the registry finds in `text` that a gate in `mode`
/// leaves readable, as `(mode, region text)`.
fn registry_regions_left_clear(text: &str) -> Vec<(PrivacyMode, String)> {
    let regions = Registry::new().analyze(text);
    let mut left = Vec::new();
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let mut gate = Gate::for_grant(&grant(mode), [7u8; 32]);
        let issued = match gate.text(text) {
            Ok((safe, _)) => safe.as_str().to_string(),
            Err(error) => panic!("{mode:?} refused {text:?}: {error}"),
        };
        for region in regions.iter().filter(|region| region.is_prohibited()) {
            if leaked(text, region.start, region.end, &issued) {
                left.push((mode, text[region.start..region.end].to_string()));
            }
        }
    }
    left
}

/// Path 1: a name merged into a prohibited region widened it in the registry
/// and in Open mode; Private masked only the value's own span. One case per
/// class where the merge reaches it.
const NAME_WIDENED: &[&str] = &[
    // health: the merge of a name with `Ms` reaches the names around it
    "Dear Dr Smith, Ms Valide has Parkinson Disease.",
    // IBAN: a statement line, the words before the guillemet
    "Transferencia a «ES60 0049 1500 0512 3456 7892»   -300,00",
    // national ID: the label before the passport number
    "Passport Number: X4RTBPFW4, Jean Valide",
    // secret: the key before a quoted password
    "password: \"Fk3j,Q9xZ2mAA\"",
    "{\n  \"username\": \"admin\",\n  \"password\": \"Fk3jQ9xZ2mAA\",\n  \"api_key\": \"Fk3jQ9xZ2mP7vB4n\"\n}",
    // address: a reference glued to the street number, a label before it
    "(seeref12 rue des Lilas, 69003 Lyon)",
    "Naslov: Slovenska cesta 12, 1000 Ljubljana",
];

/// Path 2: a token spliced into a word. The registry's marker run fails closed;
/// Open mode read only the blanked view and returned the run in clear. The
/// first case is the repro; the others pin variants main already hid.
const SPLICED_TOKEN: &[&str] = &[
    "mara@⟦EMAIL_0123456789AB⟧example.test",
    "note sk-proj⟦PERSON_0A1B2C3D4E5F⟧Xy7Qm2Lp9Rt4Vb8Nc3Kd here",
    "diagnosis diab⟦X_0A1B2C3D4E5F⟧etes type 2",
];

#[test]
fn a_name_merged_into_a_prohibited_region_is_hidden_in_both_modes() {
    for text in NAME_WIDENED {
        assert!(
            Registry::new()
                .analyze(text)
                .iter()
                .any(|region| region.is_prohibited()),
            "the registry finds no prohibited region in {text:?}"
        );
    }
    let left: Vec<_> = NAME_WIDENED
        .iter()
        .map(|text| (text, registry_regions_left_clear(text)))
        .filter(|(_, left)| !left.is_empty())
        .collect();
    assert!(left.is_empty(), "left clear: {left:#?}");
}

#[test]
fn a_token_spliced_into_a_word_is_hidden_in_both_modes() {
    let left: Vec<_> = SPLICED_TOKEN
        .iter()
        .map(|text| (text, registry_regions_left_clear(text)))
        .filter(|(_, left)| !left.is_empty())
        .collect();
    assert!(left.is_empty(), "left clear: {left:#?}");
}

#[test]
fn private_keeps_names_in_clear_when_no_prohibited_value_is_near() {
    // Only adds hiding next to a prohibited value: a name alone stays a name.
    let text = "Lunch with Jean Valide and Erika Muster on Friday.";
    let mut gate = Gate::for_grant(&grant(PrivacyMode::Private), [7u8; 32]);
    let (safe, _) = gate.text(text).expect("issued");
    assert_eq!(safe.as_str(), text);
}

/// One fictional value per class, each as the registry finds it; the key is
/// built at run time so no secret-shaped literal sits in the file.
fn values() -> Vec<String> {
    let key = ["ghp_", "auxesisCanary", "0123456789abcdef"].concat();
    [
        "FR76 3000 6000 0112 3456 7890 189",
        "ES60 0049 1500 0512 3456 7892",
        "4111 1111 1111 1111",
        "4539 1488 0343 6467",
        "X4RTBPFW4",
        "QQ 12 34 56 C",
        "1 84 12 76 451 089 46",
        "65929970489",
        "\"Fk3j,Q9xZ2mAA\"",
        "Parkinson Disease",
        "type 2 diabetes",
        &key,
    ]
    .map(String::from)
    .to_vec()
}

/// Frames that put names, labels, glue and tokens around the value.
const FRAMES: &[&str] = &[
    "{name} wrote: {value}",
    "Dear Dr {name}, Ms {name} sent {value}.",
    "Passport Number: {value}, {name}",
    "password: {value}",
    "Transferencia a «{value}»   -300,00",
    "Diagnosis: {value}, {name}",
    "ref{value} for {name}",
    "{name} <{value}>",
    "| {name} | {value} |",
    "see ⟦PERSON_0A1B2C3D4E5F⟧ {value}",
];

const NAMES: &[&str] = &[
    "Jean Valide",
    "Erika Muster",
    "Smith",
    "Camille Exemple",
    "Mara",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Whatever prohibited region the registry finds in a fictional text, the
    /// gate in either mode never leaves it readable.
    #[test]
    fn what_the_registry_finds_never_leaves_in_clear(
        value in 0..12usize,
        frame in 0..FRAMES.len(),
        name in 0..NAMES.len(),
    ) {
        let text = FRAMES[frame]
            .replace("{value}", &values()[value])
            .replace("{name}", NAMES[name]);
        let left = registry_regions_left_clear(&text);
        prop_assert!(left.is_empty(), "{:?}: left clear {:?}", text, left);
    }
}
