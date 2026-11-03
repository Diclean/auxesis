//! K07: in Private mode the hosted chat paths are tokenised in the default
//! build, with no `ner-gliner` feature.
//!
//! Before this change `admit(Private, A1)` was `Deny(Disabled)` and a
//! tokenising gate refused without a name detector. These tests run on the
//! default feature set.

use kernel_core::privacy::{
    admit, Context, Decision, Destination, Grant, GrantPolicy, PathId, PrivacyMode,
};
use kernel_privacy::{DetectionReport, EntityKind, Gate, Registry};

/// The hero sentence: a full name, an e-mail and an E.164 phone.
const TEXT: &str = "Invite Camille Exemple camille@exemple.fr +33612345678";

/// The hosted-model destination: a vendor, the shape a chat provider uses.
fn vendor() -> Context {
    Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    }
}

/// Admit a chat path, or fail the test with the decision.
fn chat(path: PathId, mode: PrivacyMode) -> Grant {
    match admit(path, mode, &vendor()) {
        Decision::Allow(grant) => grant,
        other => panic!(
            "expected Allow for {} in {mode:?}, got {other:?}",
            path.as_str()
        ),
    }
}

/// How many `⟦<kind>…⟧` tokens the text holds.
fn count_token(text: &str, kind: &str) -> usize {
    text.matches(&format!("⟦{kind}")).count()
}

#[test]
fn private_chat_is_tokenised_in_the_default_build() {
    for path in [PathId::A1, PathId::A2] {
        let grant = chat(path, PrivacyMode::Private);
        assert_eq!(grant.path(), path);
        assert_eq!(grant.policy(), GrantPolicy::Tokenised);
    }
}

#[test]
fn private_chat_without_a_dictionary_still_tokenises_mail_and_phone() {
    // No dictionary and no name model: names are not checked, but the gate
    // still tokenises the mail and the phone and issues the text. The filter
    // tokenises; it does not refuse (owner, 2026-10-14).
    let grant = chat(PathId::A1, PrivacyMode::Private);
    let mut gate = Gate::for_grant(&grant, [7u8; 32]);
    let (safe, _) = gate.text(TEXT).unwrap();
    assert!(!safe.names_checked());
    assert!(
        !safe.as_str().contains("camille@exemple.fr"),
        "{}",
        safe.as_str()
    );
    assert!(!safe.as_str().contains("+33612345678"), "{}", safe.as_str());
}

/// NAMES-OFF (owner, 2026-10-19): a known name passes as written; the e-mail
/// and the phone are one token each and restore exactly.
#[test]
fn private_chat_with_known_names_keeps_the_name_and_masks_email_and_phone() {
    let grant = chat(PathId::A1, PrivacyMode::Private);
    let mut gate =
        Gate::for_grant_with_names(&grant, [7u8; 32], ["Camille Exemple"]).expect("dictionary");
    let (safe, report) = gate.text(TEXT).expect("private chat is issued");
    assert!(
        safe.as_str().starts_with("Invite Camille Exemple ⟦EMAIL_"),
        "{}",
        safe.as_str()
    );
    for secret in ["camille@exemple.fr", "612345678"] {
        assert!(
            !safe.as_str().contains(secret),
            "leaked {secret:?}: {}",
            safe.as_str()
        );
    }
    assert_eq!(
        count_token(safe.as_str(), "PERSON_"),
        0,
        "{}",
        safe.as_str()
    );
    assert_eq!(count_token(safe.as_str(), "EMAIL_"), 1, "{}", safe.as_str());
    assert_eq!(count_token(safe.as_str(), "PHONE_"), 1, "{}", safe.as_str());
    assert_eq!(report.label(), DetectionReport::MASKED);
    assert_eq!(report.count(EntityKind::Person), 0, "{report}");
    assert_eq!(report.count(EntityKind::Email), 1, "{report}");
    assert_eq!(report.count(EntityKind::Phone), 1, "{report}");

    // Each token restores to its own exact original.
    let minted = gate.take_minted();
    let restore = |kind: &str| {
        let (token, value) = minted
            .iter()
            .find(|(token, _)| token.starts_with(kind))
            .unwrap_or_else(|| panic!("no {kind} token in {minted:?}"));
        assert!(
            safe.as_str().contains(&format!("⟦{token}⟧")),
            "{token} not in {}",
            safe.as_str()
        );
        value.clone()
    };
    assert_eq!(restore("EMAIL_"), "camille@exemple.fr");
    assert_eq!(restore("PHONE_"), "+33612345678");
}

#[test]
fn no_partial_name_fragment_survives_with_or_without_a_dictionary() {
    // The seal string. A private gate keeps the name whole (NAMES-OFF) and
    // masks the address.
    let text = "/invite Camille Exemple camille@exemple.fr tomorrow 10:00";
    let grant = chat(PathId::A1, PrivacyMode::Private);
    let mut gate =
        Gate::for_grant_with_names(&grant, [7u8; 32], ["Camille Exemple"]).expect("dictionary");
    let (safe, _) = gate.text(text).expect("issued");
    assert!(
        safe.as_str().starts_with("/invite Camille Exemple ⟦EMAIL_"),
        "{}",
        safe.as_str()
    );
    assert!(!safe.as_str().contains("camille@"), "{}", safe.as_str());

    // Without the dictionary the detector still flags part of the name. The
    // region must grow over the adjacent capitalised token, so a detector-level
    // check sees the whole name covered.
    let spans = Registry::new().analyze(text);
    assert!(
        spans.iter().any(|span| {
            span.kind == EntityKind::Person && &text[span.start..span.end] == "Camille Exemple"
        }),
        "no full-name region: {spans:?}"
    );
}

#[test]
fn an_overlapping_name_in_an_email_local_part_yields_one_email_token() {
    // The dictionary's PERSON span sits inside the address: the overlap makes
    // one EMAIL region and leaves no name fragment in clear.
    let grant = chat(PathId::A1, PrivacyMode::Private);
    let mut gate =
        Gate::for_grant_with_names(&grant, [7u8; 32], ["Camille Exemple"]).expect("dictionary");
    let (safe, report) = gate.text("camille.exemple@x.fr").expect("issued");
    assert_eq!(count_token(safe.as_str(), "EMAIL_"), 1, "{}", safe.as_str());
    assert_eq!(
        count_token(safe.as_str(), "PERSON_"),
        0,
        "{}",
        safe.as_str()
    );
    assert!(!safe.as_str().contains("camille"), "{}", safe.as_str());
    assert!(!safe.as_str().contains("exemple"), "{}", safe.as_str());
    assert_eq!(report.count(EntityKind::Email), 1, "{report}");
    assert_eq!(report.count(EntityKind::Person), 0, "{report}");
}

#[test]
fn every_dictionary_variant_passes_as_written_in_private_text() {
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "Bonjour Camille,",
            "Camille Exemple",
            &["camille", "exemple"],
        ),
        ("Camille's file", "Camille Exemple", &["camille", "exemple"]),
        (
            "Camille a appelé",
            "Camille Exemple",
            &["camille", "exemple"],
        ),
        ("Merci Camille", "Camille Exemple", &["camille", "exemple"]),
        (
            "Mme Exemple a appelé",
            "Camille Exemple",
            &["camille", "exemple"],
        ),
        ("C. Exemple", "Camille Exemple", &["camille", "exemple"]),
        ("Camille E.", "Camille Exemple", &["camille", "exemple"]),
        (
            "Exemple Camille",
            "Camille Exemple",
            &["camille", "exemple"],
        ),
        (
            "Exemple, Camille",
            "Camille Exemple",
            &["camille", "exemple"],
        ),
        (
            "Camille\u{200B}Exemple",
            "Camille Exemple",
            &["camille", "exemple"],
        ),
        ("CamilleExemple", "Camille Exemple", &["camille", "exemple"]),
        (
            "JeanPierre Dupont",
            "Jean-Pierre Dupont",
            &["jean", "pierre", "dupont"],
        ),
    ];
    for (probe, entry, tokens) in cases {
        let grant = chat(PathId::A1, PrivacyMode::Private);
        let mut gate = Gate::for_grant_with_names(&grant, [7u8; 32], [*entry]).expect("dictionary");
        let (safe, _) = gate.text(probe).expect("issued");
        assert_eq!(safe.as_str(), *probe, "{entry:?} parts {tokens:?}");
    }
}

#[test]
fn a_display_name_glued_to_an_address_keeps_the_name_and_masks_the_address() {
    // '<', '>', '"' and '(' are never part of an email local part: the display
    // name stays as written and the address is one token.
    let text = "Camille Exemple<camille@exemple.fr> demain";
    let grant = chat(PathId::A1, PrivacyMode::Private);
    let mut gate =
        Gate::for_grant_with_names(&grant, [7u8; 32], ["Camille Exemple"]).expect("dictionary");
    let (safe, report) = gate.text(text).expect("issued");
    assert!(
        safe.as_str().starts_with("Camille Exemple<⟦EMAIL_"),
        "{}",
        safe.as_str()
    );
    assert_eq!(count_token(safe.as_str(), "EMAIL_"), 1, "{}", safe.as_str());
    assert!(!safe.as_str().contains("camille@"), "{}", safe.as_str());
    assert_eq!(report.count(EntityKind::Person), 0, "{report}");
    assert_eq!(report.count(EntityKind::Email), 1, "{report}");
}

#[test]
fn open_chat_passes_through_and_reports_what_private_would_mask() {
    let grant = chat(PathId::A1, PrivacyMode::Open);
    let mut gate = Gate::for_grant(&grant, [7u8; 32]);
    let (safe, report) = gate.text(TEXT).expect("open chat is issued");
    assert!(safe.as_str().contains("camille@exemple.fr"));
    assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
    assert!(report.count(EntityKind::Email) >= 1);
    assert!(report.count(EntityKind::Phone) >= 1);
    assert!(!report.to_string().contains("camille@exemple.fr"));
}

#[test]
fn a_name_beside_an_address_or_in_a_list_stays_as_written() {
    // `Camille@exemple.fr` carries an '@': the address is one token, the name
    // before it and a comma-separated list of names stay as written.
    let grant = chat(PathId::A1, PrivacyMode::Private);
    let mut gate =
        Gate::for_grant_with_names(&grant, [7u8; 32], ["Camille Exemple"]).expect("dictionary");
    let (safe, report) = gate
        .text("Camille Exemple Camille@exemple.fr")
        .expect("issued");
    assert!(
        safe.as_str().starts_with("Camille Exemple ⟦EMAIL_"),
        "{}",
        safe.as_str()
    );
    assert_eq!(count_token(safe.as_str(), "EMAIL_"), 1, "{}", safe.as_str());
    assert_eq!(report.count(EntityKind::Person), 0, "{report}");
    assert_eq!(report.count(EntityKind::Email), 1, "{report}");

    let list = "Camille Exemple, Camille Exemple, Camille";
    assert_eq!(gate.text(list).expect("issued").0.as_str(), list);
}
