//! K12: a secret is dropped in every mode, and a JSON key gives its value
//! context.
//!
//! Open mode (`GrantPolicy::Passthrough`) leaves ordinary values in clear, but a
//! detected secret is replaced with `[secret removed]`, never returned. Private
//! mode (`GrantPolicy::Tokenised`) is unchanged for text; a JSON string value
//! whose key makes the detector read it as a secret becomes one restoreable
//! token. The existing secret recogniser decides what a secret is: these tests
//! add no key names.

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::safetext::DetectError;
use kernel_privacy::{DetectionReport, EntityKind, Gate, GateError};
use serde_json::{json, Map, Value};

const KEY: [u8; 32] = [7u8; 32];
const SECRET_REMOVED: &str = "[secret removed]";

/// The hosted-model destination, the shape a chat provider or MCP server uses.
fn vendor() -> Context {
    Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    }
}

/// A real grant for path A1 in `mode`, minted the way production does.
fn grant(mode: PrivacyMode) -> Grant {
    match admit(PathId::A1, mode, &vendor()) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow for A1 in {mode:?}, got {other:?}"),
    }
}

/// An open-mode gate: the detectors run, ordinary values pass, secrets do not.
fn open_gate() -> Gate {
    Gate::for_grant(&grant(PrivacyMode::Open), KEY)
}

/// A private-mode gate with the dictionary a chat path mounts, so masking needs
/// no GLiNER model.
fn private_gate() -> Gate {
    Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Camille Exemple"])
        .expect("dictionary")
}

/// The object `{ key: value }`, as a JSON value.
fn object(key: &str, value: &str) -> Value {
    let mut map = Map::new();
    map.insert(key.to_string(), Value::String(value.to_string()));
    Value::Object(map)
}

#[test]
fn open_json_drops_secret_values_and_counts_them() {
    // The first two need the key beside them; the third is key-shaped by its
    // name too. All three are gone in open mode.
    for (key, value) in [
        ("password", "hunter2-Very-Secret"),
        ("api_key", "sk-test-0000000000000000000000000000"),
        ("token", "ghp_auxesisCanary0123456789abcdef"),
    ] {
        let mut gate = open_gate();
        let (safe, report) = gate
            .value(&object(key, value))
            .expect("open value is issued");
        assert_eq!(
            safe.as_value().get(key).and_then(Value::as_str),
            Some(SECRET_REMOVED),
            "{key} was not removed: {}",
            safe.as_value()
        );
        let wire = serde_json::to_string(&safe).unwrap();
        assert!(!wire.contains(value), "{value} left in clear: {wire}");
        assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
        assert_eq!(report.count(EntityKind::Secret), 1, "{report}");
    }
}

#[test]
fn open_json_leaves_a_plain_value_in_clear() {
    let mut gate = open_gate();
    let input = object("city", "Paris");
    let (safe, report) = gate.value(&input).expect("open value is issued");
    assert_eq!(safe.as_value(), &input);
    assert!(report.is_empty(), "{report}");
}

#[test]
fn open_json_recurses_into_nested_objects_and_arrays() {
    let mut gate = open_gate();
    let input = json!({
        "db": { "password": "x9!Kq-22-Zz" },
        "clients": [
            { "api_key": "sk-test-0000000000000000000000000000" },
            { "city": "Paris" }
        ]
    });
    let (safe, report) = gate.value(&input).expect("open value is issued");
    assert_eq!(safe.as_value()["db"]["password"], json!(SECRET_REMOVED));
    assert_eq!(
        safe.as_value()["clients"][0]["api_key"],
        json!(SECRET_REMOVED)
    );
    assert_eq!(safe.as_value()["clients"][1]["city"], json!("Paris"));
    assert_eq!(report.count(EntityKind::Secret), 2, "{report}");
    let wire = serde_json::to_string(&safe).unwrap();
    assert!(!wire.contains("x9!Kq-22-Zz"), "{wire}");
    assert!(
        !wire.contains("sk-test-0000000000000000000000000000"),
        "{wire}"
    );
}

#[test]
fn private_json_makes_one_restoreable_secret_token() {
    for (key, value) in [
        ("password", "hunter2-Very-Secret"),
        ("api_key", "sk-test-0000000000000000000000000000"),
        ("db", "x9!Kq-22-Zz"),
    ] {
        let mut gate = private_gate();
        let input = if key == "db" {
            json!({ "db": { "password": value } })
        } else {
            object(key, value)
        };
        let (safe, report) = gate.value(&input).expect("private value is issued");
        let wire = serde_json::to_string(&safe).unwrap();
        assert!(!wire.contains(value), "{value} left in clear: {wire}");
        assert_eq!(report.count(EntityKind::Secret), 1, "{report}");
        // The whole value is exactly one token; the minted pair restores it.
        let minted = gate.take_minted();
        let (token, original) = minted
            .iter()
            .find(|(token, _)| token.starts_with("SECRET_"))
            .unwrap_or_else(|| panic!("no SECRET token in {minted:?}"));
        assert_eq!(original, value);
        assert_eq!(
            wire.matches(&format!("⟦{token}⟧")).count(),
            1,
            "{token} is not the whole value: {wire}"
        );
    }
}

#[test]
fn a_secret_over_the_read_cap_is_removed_in_open_mode() {
    // A block scalar past the 8 KB read cap: open mode replaces it whole, never
    // returns it, and private mode below fails closed on the same value.
    let value = format!("|\n  {}", "A".repeat(9000));
    let mut gate = open_gate();
    let (safe, report) = gate
        .value(&object("token", &value))
        .expect("open value is issued");
    assert_eq!(safe.as_value()["token"], json!(SECRET_REMOVED));
    assert_eq!(report.count(EntityKind::Secret), 1, "{report}");
}

#[test]
fn a_secret_over_the_read_cap_fails_closed_in_private_mode() {
    let value = format!("|\n  {}", "A".repeat(9000));
    let mut gate = private_gate();
    assert_eq!(
        gate.value(&object("token", &value)).unwrap_err(),
        GateError::Detect(DetectError::TooLong)
    );
}

#[test]
fn open_text_replaces_only_the_secret_part() {
    let mut gate = open_gate();
    let input = "my password is X9!kq-22-Zz";
    let (safe, report) = gate.text(input).expect("open text is issued");
    assert_eq!(safe.as_str(), "my password is [secret removed]");
    assert_eq!(report.count(EntityKind::Secret), 1, "{report}");
    assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
}

#[test]
fn open_text_still_passes_every_other_kind() {
    let mut gate = open_gate();
    let input = "mail elise.vautrin@example.invalid and call +33612345678";
    let (safe, report) = gate.text(input).expect("open text is issued");
    assert_eq!(safe.as_str(), input);
    assert!(report.count(EntityKind::Email) >= 1, "{report}");
    assert!(report.count(EntityKind::Phone) >= 1, "{report}");
}

#[test]
fn private_text_still_tokenises_the_secret() {
    let mut gate = private_gate();
    let input = "my password is X9!kq-22-Zz";
    let (safe, report) = gate.text(input).expect("private text is issued");
    assert!(!safe.as_str().contains("X9!kq-22-Zz"), "{}", safe.as_str());
    assert!(safe.as_str().contains("⟦SECRET_"), "{}", safe.as_str());
    assert_eq!(report.label(), DetectionReport::MASKED);
    assert_eq!(report.count(EntityKind::Secret), 1, "{report}");
}
