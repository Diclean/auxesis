//! K-SECRET-PHRASE: a secret written in a natural sentence is masked in every mode.
//!
//! Fixed probes (the maintainer's spec, 2026-10-19): each MUST-MASK value is
//! gone from the text in open mode (`[secret removed]`) and in private mode
//! (one restoreable SECRET token); each MUST-NOT-MASK sentence passes
//! unchanged in both modes.

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{EntityKind, Gate};

const KEY: [u8; 32] = [7u8; 32];
const SECRET_REMOVED: &str = "[secret removed]";

/// (text, the secret value in it).
const MUST_MASK: &[(&str, &str)] = &[
    (
        "My password for the client portal is velvet-cactus-lantern",
        "velvet-cactus-lantern",
    ),
    ("the portal password: Tr0ub4dor&3", "Tr0ub4dor&3"),
    ("pw is hunter2-blue", "hunter2-blue"),
    (
        "login for the bank site is mira.f / pass Gx7#qq91",
        "Gx7#qq91",
    ),
    ("PIN is 4821", "4821"),
    ("my passcode for the alarm is 0917", "0917"),
    (
        "passphrase: correct horse battery staple",
        "correct horse battery staple",
    ),
    (
        "the API key for Stripe is sk_test_51Habc123XYZ", // gitleaks:allow
        "sk_test_51Habc123XYZ",                           // gitleaks:allow
    ),
    ("Wi-Fi password = BakeryGuest2026!", "BakeryGuest2026!"),
    ("here's the code to the shared drive: 77-AB-19", "77-AB-19"),
    (
        "password for the CRM is the same as before: Sunflower#88",
        "Sunflower#88",
    ),
    ("Portal\nuser: camille\npassword: Fj3!kd9", "Fj3!kd9"),
    ("my password is \"orange tree 42\"", "orange tree 42"),
    // Round 2 (#126).
    (
        "My password for the client portal at work is velvet-cactus-lantern",
        "velvet-cactus-lantern",
    ),
    (
        "the password for the shared Google Drive folder is velvet-cactus-lantern",
        "velvet-cactus-lantern",
    ),
    ("the PIN number is 4821", "4821"),
    ("my pin code is 4821", "4821"),
    ("the door code is 4521", "4521"),
    ("alarm code is 0917", "0917"),
    (
        "the wifi password is now BakeryGuest2026",
        "BakeryGuest2026",
    ),
    (
        "the new password is still velvet-cactus-lantern",
        "velvet-cactus-lantern",
    ),
    ("passwords for both accounts are Sunset77x", "Sunset77x"),
    (
        "my passphrase is correct horse battery staple",
        "correct horse battery staple",
    ),
    ("the token for the API is 7f3a9c2e1b8d", "7f3a9c2e1b8d"), // gitleaks:allow
    // A list after `passwords`: each value is checked on its own.
    ("the passwords are Sunset77x and Moon88y", "Sunset77x"),
    ("the passwords are Sunset77x and Moon88y", "Moon88y"),
    // Seal r1: a plain word right after the key stays a value, as on main.
    ("password letmein", "letmein"),
    ("the wifi password letmein works", "letmein"),
    // Seal r2: a quoted value is never read as prose.
    ("Use password 'login' to connect", "login"),
    ("passcode \"vault\"", "vault"),
    ("api key 'safe' for staging", "safe"),
];

const MUST_NOT_MASK: &[&str] = &[
    "I forgot my password",
    "password reset link sent",
    "PIN code required at checkout",
    "what is a strong password?",
    "the code is on GitHub",
    "the door code is on the fridge note",
    "the token for the event is free",
];

/// A plain word right after a key is masked, exactly as on main: any list of "prose"
/// words let real passwords through (`Use password vault to connect`, seal r3). These
/// sentences are over-masked on purpose; the owner still sees them restored.
const MASKED_AS_ON_MAIN: &[&str] = &[
    "change your password every 90 days",
    "the passcode screen froze",
    "password strength: Strong",
    "password policy: 12 characters",
    "Use password vault to connect",
    "Use pwd vault to connect",
    // K-SECRET-TAIL-4 over-mask: the words after the link are the value.
    "the password is in 1Password",
];

fn vendor() -> Context {
    Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    }
}

fn grant(mode: PrivacyMode) -> Grant {
    match admit(PathId::A1, mode, &vendor()) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow for A1 in {mode:?}, got {other:?}"),
    }
}

fn gate(mode: PrivacyMode) -> Gate {
    match mode {
        PrivacyMode::Open => Gate::for_grant(&grant(mode), KEY),
        PrivacyMode::Private => {
            Gate::for_grant_with_names(&grant(mode), KEY, ["Camille Exemple"]).expect("dictionary")
        }
    }
}

/// The words of a value that could leak on their own (three characters or more).
fn fragments(value: &str) -> impl Iterator<Item = &str> {
    value.split(' ').filter(|word| word.len() >= 3)
}

#[test]
fn a_secret_in_a_sentence_is_removed_in_open_mode() {
    let mut leaks = Vec::new();
    for &(text, value) in MUST_MASK {
        let (safe, report) = gate(PrivacyMode::Open).text(text).expect("open text");
        let out = safe.as_str();
        if fragments(value).any(|word| out.contains(word))
            || !out.contains(SECRET_REMOVED)
            || report.count(EntityKind::Secret) == 0
        {
            leaks.push(format!("{text:?} -> {out:?}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "leaked in open mode:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn a_secret_in_a_sentence_is_one_restoreable_token_in_private_mode() {
    let mut leaks = Vec::new();
    for &(text, value) in MUST_MASK {
        let mut gate = gate(PrivacyMode::Private);
        let (safe, report) = gate.text(text).expect("private text");
        let out = safe.as_str().to_string();
        let minted = gate.take_minted();
        // The whole value (its quotes aside) is inside one SECRET token, and that token
        // is in the text sent out. Since K-SECRET-TAIL-4 the token may hold the words
        // between the link and the value too (`is now X`).
        let token = minted.iter().find(|(token, original)| {
            token.starts_with("SECRET_")
                && original.trim_matches(['"', '\'']).contains(value)
                && out.contains(&format!("⟦{token}⟧"))
        });
        if fragments(value).any(|word| out.contains(word))
            || token.is_none()
            || report.count(EntityKind::Secret) == 0
        {
            leaks.push(format!("{text:?} -> {out:?} minted {minted:?}"));
        }
    }
    assert!(
        leaks.is_empty(),
        "leaked in private mode:\n{}",
        leaks.join("\n")
    );
}

#[test]
fn a_sentence_about_a_password_with_no_value_is_left_unchanged() {
    let mut masked = Vec::new();
    for &text in MUST_NOT_MASK {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let (safe, report) = gate(mode).text(text).expect("text");
            if safe.as_str() != text || report.count(EntityKind::Secret) != 0 {
                masked.push(format!("{mode:?} {text:?} -> {:?}", safe.as_str()));
            }
        }
    }
    assert!(masked.is_empty(), "false positives:\n{}", masked.join("\n"));
}

#[test]
fn a_plain_word_after_a_key_is_masked_as_on_main() {
    for &text in MASKED_AS_ON_MAIN {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let (_, report) = gate(mode).text(text).expect("text");
            assert!(
                report.count(EntityKind::Secret) > 0,
                "{mode:?} {text:?} must stay masked as on main"
            );
        }
    }
}
