//! Open mode never returns a prohibited class.
//!
//! Open mode (`GrantPolicy::Passthrough`) leaves ordinary values, names
//! included, in clear. IBAN, payment cards, national IDs and passports, health
//! terms and secrets never leave in any mode: each is replaced with a fixed
//! `[<class> removed]` marker and counted in the report, never returned. All
//! values below are invented.

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{DetectionReport, EntityKind, Gate};
use serde_json::json;

const KEY: [u8; 32] = [7u8; 32];

fn grant(mode: PrivacyMode) -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow for A1 in {mode:?}, got {other:?}"),
    }
}

fn open_gate() -> Gate {
    Gate::for_grant(&grant(PrivacyMode::Open), KEY)
}

const IBAN: &str = "FR76 3000 6000 0112 3456 7890 189";
const CARD: &str = "4111 1111 1111 1111";
const NIR: &str = "1 84 12 76 451 089 46";
const MRZ: &str = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
// Built at run time so no secret-shaped literal sits in the file.
fn secret() -> String {
    ["ghp_", "auxesisCanary", "0123456789abcdef"].concat()
}

/// (text, raw value, marker, kind) for one prohibited class each.
fn cases() -> Vec<(String, String, &'static str, EntityKind)> {
    vec![
        (
            format!("Virement sur {IBAN} demain"),
            IBAN.into(),
            "[iban removed]",
            EntityKind::Iban,
        ),
        (
            format!("Carte {CARD} exp 12/29"),
            CARD.into(),
            "[card removed]",
            EntityKind::CreditCard,
        ),
        (
            format!("N° de sécurité sociale {NIR}"),
            NIR.into(),
            "[id removed]",
            EntityKind::NationalId,
        ),
        (
            format!("scan:\nP<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n{MRZ}"),
            MRZ.into(),
            "[id removed]",
            EntityKind::NationalId,
        ),
        (
            "Elle suit une chimiothérapie depuis mars.".into(),
            "chimiothérapie".into(),
            "[health removed]",
            EntityKind::Health,
        ),
        (
            "He has cancer and starts chemotherapy.".into(),
            "cancer".into(),
            "[health removed]",
            EntityKind::Health,
        ),
        (
            format!("token: {}", secret()),
            secret(),
            "[secret removed]",
            EntityKind::Secret,
        ),
    ]
}

#[test]
fn open_text_removes_every_prohibited_class() {
    for (text, raw, marker, kind) in cases() {
        let mut gate = open_gate();
        let (safe, report) = gate.text(&text).expect("open text is issued");
        assert!(
            !safe.as_str().contains(raw.as_str()),
            "{raw} left in clear: {}",
            safe.as_str()
        );
        assert!(
            safe.as_str().contains(marker),
            "no {marker}: {}",
            safe.as_str()
        );
        assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
        assert!(report.total() >= 1, "{report}");
        assert!(report.count(kind) >= 1, "{report}");
        assert!(!report.to_string().contains(raw.as_str()));
    }
}

#[test]
fn open_text_keeps_names_and_ordinary_text_around_a_removal() {
    let mut gate = open_gate();
    let text = format!("Camille Exemple (camille@example.invalid) vit à Lyon, IBAN {IBAN}, merci.");
    let (safe, report) = gate.text(&text).unwrap();
    assert_eq!(
        safe.as_str(),
        "Camille Exemple (camille@example.invalid) vit à Lyon, IBAN [iban removed], merci."
    );
    assert_eq!(report.count(EntityKind::Iban), 1);
}

#[test]
fn open_text_with_no_prohibited_class_is_unchanged() {
    let mut gate = open_gate();
    let text = "Camille Exemple écrit à camille@example.invalid, rendez-vous à Lyon le 4 mai.";
    let (safe, _) = gate.text(text).unwrap();
    assert_eq!(safe.as_str(), text);
}

#[test]
fn open_json_removes_prohibited_classes_in_values_and_keeps_the_rest() {
    let mut gate = open_gate();
    let input = json!({
        "from": "Camille Exemple",
        "notes": [format!("IBAN {IBAN}"), format!("carte {CARD}")],
        "nested": { "health": "Elle suit une chimiothérapie." },
        "count": 3
    });
    let (safe, report) = gate.value(&input).unwrap();
    let wire = serde_json::to_string(&safe).unwrap();
    for raw in [IBAN, CARD, "chimiothérapie"] {
        assert!(!wire.contains(raw), "{raw} left in clear: {wire}");
    }
    assert!(
        wire.contains("Camille Exemple") && wire.contains("\"count\":3"),
        "{wire}"
    );
    assert_eq!(report.count(EntityKind::Iban), 1);
    assert_eq!(report.count(EntityKind::CreditCard), 1);
}

#[test]
fn private_mode_still_tokenises_the_same_classes() {
    for (text, raw, _, _) in cases() {
        let mut gate =
            Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Camille Exemple"])
                .expect("dictionary");
        let (safe, _) = gate.text(&text).expect("private text is issued");
        assert!(
            !safe.as_str().contains(raw.as_str()),
            "{raw} left in clear: {}",
            safe.as_str()
        );
        assert!(safe.as_str().contains('⟦'), "{}", safe.as_str());
    }
}

#[test]
fn open_text_keeps_a_sha256_digest_intact() {
    // The IBAN recogniser guesses inside this digest; open mode cannot restore
    // a removed fragment, so the model would cite a corrupted hash.
    let digest = "16e07db253f23a282d673668bd4b4656bf1f410962612fa4c7b4ddd87d893d77";
    let text = format!("{{\"sha256\":\"{digest}\",\"file_name\":\"invoice.pdf\"}}");
    let mut gate = open_gate();
    let (safe, _) = gate.text(&text).unwrap();
    assert_eq!(safe.as_str(), text);
}
