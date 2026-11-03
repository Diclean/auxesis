//! SECRET-RECALL-1 acceptance: a password, PIN, recovery code, passphrase,
//! token, private key or connection string written the way people write it in
//! business mail and chat (EN + FR) is hidden in both modes, and the everyday
//! lookalikes stay readable. Values are invented; token prefixes are split so
//! no scanner reads the source as a live key.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

/// The linear-time bar of this file. Release keeps 10 s; the debug profile is
/// slower (the KPUB-2 dry run measured 12.46 s for the slowest cue on this Mac,
/// 2026-11-01), so it gets 30 s. The check itself is unchanged: two full passes
/// per cue.
fn linear_budget() -> Duration {
    if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(10)
    }
}

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, issue, masked, MODES};

/// `(text, value)`: every byte of `value` must be hidden.
fn positives() -> Vec<(String, String)> {
    let ghp = format!("gh{}_{}", "p", "Zq8WmR3tY6uP1sD4fG7hJ0kL2xC5vB9nM3aQ");
    let aws = format!("wJalr{}", "XUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY");
    let key_body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW";
    let pem = format!(
        "-----BEGIN OPENSSH {}-----\n{key_body}\nQyNTUxOQAAACBz1fake2key3body4\n-----END OPENSSH {}-----",
        "PRIVATE KEY", "PRIVATE KEY"
    );
    let split_tok = format!("gh{}_Yx7Kd2Lq9Wm4Rt6Np1Bv8\nCz3Hs5Fg0Jk", "p");
    let mut cases: Vec<(String, String)> = vec![
        (
            "Hi Tom, the password is Tr0ub4dor&3 for the shared drive.".into(),
            "Tr0ub4dor&3".into(),
        ),
        (
            "Bonjour, mdp : Soleil2024! pour le portail client.".into(),
            "Soleil2024!".into(),
        ),
        (
            "Bonjour, le mot de passe est Plage#88vent merci.".into(),
            "Plage#88vent".into(),
        ),
        (
            "Quick one: my pin is 4821, can you pay the courier?".into(),
            "4821".into(),
        ),
        (
            "Mon code PIN est 7390 si tu passes à la banque.".into(),
            "7390".into(),
        ),
        (
            "code de récupération: 7KQ2-9XZ1-M4P8-R6T3".into(),
            "7KQ2-9XZ1-M4P8-R6T3".into(),
        ),
        (
            "Recovery codes: 5HJD-82KM-QW3E".into(),
            "5HJD-82KM-QW3E".into(),
        ),
        ("login: alice / pass: hunter2".into(), "hunter2".into()),
        ("user=bob pwd=Qx7!mN2pzz".into(), "Qx7!mN2pzz".into()),
        (
            "passphrase: correct horse battery staple".into(),
            "correct horse battery staple".into(),
        ),
        (format!("here's the token {ghp} for the CI"), ghp.clone()),
        (format!("AWS secret {aws} (rotate after)"), aws.clone()),
        (
            "DB is postgres://appuser:Rq9vLm2x@db.internal.example/crm".into(),
            "Rq9vLm2x".into(),
        ),
        (
            "use mysql://report:S3cr3tPw@10.0.0.7:3306/sales".into(),
            "S3cr3tPw".into(),
        ),
        (format!("Key below:\n{pem}\nthanks"), pem.clone()),
        (format!("token: {split_tok}"), split_tok.clone()),
        (
            "the password is \"Vela9!Ktz\" ok".into(),
            "Vela9!Ktz".into(),
        ),
        ("password: `Mpq7#Zr2k`".into(), "Mpq7#Zr2k".into()),
        (
            "Wi-Fi: CafeNet / key: blue-otter-472".into(),
            "blue-otter-472".into(),
        ),
        (
            "WiFi: BureauLyon / clé : Lyon2025!wifi".into(),
            "Lyon2025!wifi".into(),
        ),
        (
            "Your OTP 482913 expires in 5 minutes.".into(),
            "482913".into(),
        ),
        ("code de vérification : 615204".into(), "615204".into()),
        ("2FA code is 993201".into(), "993201".into()),
        ("PW: Kestrel_77x".into(), "Kestrel_77x".into()),
        ("le code d'accès est 4417B".into(), "4417B".into()),
    ];
    cases.push(("pw is Lumen42?ok".into(), "Lumen42?ok".into()));
    // Grouped codes (seal A round 1): space groups, dash groups across a line
    // break, a key on the next line, ten codes one per line.
    let ten: Vec<String> = (0..10).map(|n| format!("k{n}x7q-{n}m4p2")).collect();
    let ten = ten.join("\n");
    cases.extend([
        (
            "Recovery codes: 7KQ2 9XZ1 M4P8 R6T3".into(),
            "7KQ2 9XZ1 M4P8 R6T3".into(),
        ),
        (
            "Recovery codes:\n7KQ2-9XZ1-\nM4P8-R6T3\nthanks".into(),
            "7KQ2-9XZ1-\nM4P8-R6T3".into(),
        ),
        (
            "codes de récupération :\n7KQ2-9XZ1\nM4P8-R6T3".into(),
            "7KQ2-9XZ1\nM4P8-R6T3".into(),
        ),
        ("Wi-Fi key:\nblue-otter-472".into(), "blue-otter-472".into()),
        (
            format!("Backup codes:\n{ten}\n\nKeep them safe."),
            ten.clone(),
        ),
    ]);
    cases
}

/// Lookalikes: the gate must hide nothing in them.
fn negatives() -> Vec<&'static str> {
    vec![
        "A password reset link was sent to the client this morning.",
        "Please fix the PIN pad at the front desk before Monday.",
        "A small token of appreciation for the team, see you Friday.",
        "Mot de passe oublié ? Cliquez sur le lien de réinitialisation.",
        "Order number 48213 ships on 2026-11-04.",
        "Invoice INV-2026-0042 is due on 12/11/2026.",
        "Your password must be at least 12 characters long.",
        "The meeting code of conduct is on page 4.",
        "Le code postal du bureau a changé, voir la facture F-2026-118.",
        "We need a recovery plan for the Q4 budget.",
        "The key point is the delivery date, 4 December.",
        "Merci de changer votre mot de passe tous les 90 jours.",
        "The Wi-Fi is down on the second floor again.",
        "Reference 7KQ2 is the box label, not a code.",
        "The recovery code process is in the wiki.",
        "Our AWS secret rotation policy changed in 2026.",
        "Wi-Fi: the key point is coverage on floor 3.",
        "Le code de vérification a expiré, merci de réessayer.",
        "Les codes de secours sont dans le coffre du bureau.",
        "Recovery codes are in the safe",
        "Wi-Fi key holders: Anna and Ben",
        "Backup codes:\n\nAsk the office for a new sheet.",
    ]
}

/// Every non-whitespace byte of `text[start..end]` is masked: a key split by a
/// line break keeps its line break.
fn hidden(ranges: &[(usize, usize)], text: &str, start: usize, end: usize) -> bool {
    text[start..end]
        .char_indices()
        .filter(|(_, ch)| !ch.is_whitespace())
        .all(|(at, ch)| covered(ranges, start + at, start + at + ch.len_utf8()))
}

fn misses() -> Vec<String> {
    let mut wrong = Vec::new();
    for (text, value) in positives() {
        let start = text.find(value.as_str()).expect("value in text");
        for mode in MODES {
            match masked(mode, &text) {
                Some(r) if hidden(&r, &text, start, start + value.len()) => {}
                other => wrong.push(format!("{mode:?} {text:?}: {other:?}")),
            }
        }
    }
    wrong
}

/// Every positive: each value byte hidden in both modes.
#[test]
fn everyday_secrets_are_hidden_in_both_modes() {
    let wrong = misses();
    assert!(
        wrong.is_empty(),
        "{} misses:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Every lookalike passes unmasked and unrefused in both modes.
#[test]
fn everyday_lookalikes_stay_readable() {
    let mut wrong = Vec::new();
    for text in negatives() {
        for mode in MODES {
            match issue(mode, text) {
                Some((out, _)) if out == text => {}
                other => wrong.push(format!("{mode:?} {text:?}: {other:?}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Private restores every positive exactly.
#[test]
fn private_restores_everyday_secrets() {
    for (text, _) in positives() {
        let (mut out, minted) = issue(PrivacyMode::Private, &text).expect("issued");
        for (token, surface) in minted {
            out = out.replace(&format!("⟦{token}⟧"), &surface);
        }
        assert_eq!(out, text);
    }
}

/// Long inputs built from the new cues stay linear.
#[test]
fn everyday_cues_stay_linear_on_long_input() {
    for unit in [
        "my pin is ",
        "OTP ",
        "pw is ",
        "key: ",
        "code de vérification : ",
        "2FA code is ",
        "Wi-Fi ",
        "Wi-Fi key: ",
        "AWS secret ",
        "recovery codes: ",
        "code de récupération ",
    ] {
        let text = unit.repeat(20_000);
        let started = Instant::now();
        for mode in MODES {
            let _ = issue(mode, &text);
        }
        let limit = linear_budget();
        assert!(
            started.elapsed() < limit,
            "{unit:?} took {:?}, limit {limit:?}",
            started.elapsed()
        );
    }
}

/// A long code run after one key, and many keys each before a run, stay linear.
#[test]
fn grouped_code_runs_stay_linear_on_long_input() {
    for text in [
        format!("Recovery codes: {}", "7KQ2 ".repeat(50_000)),
        format!("Recovery codes:\n{}", "7KQ2-\n".repeat(50_000)),
        "Wi-Fi key: 7KQ2 9XZ1 ".repeat(20_000),
        "Recovery codes ".repeat(20_000),
    ] {
        let started = Instant::now();
        for mode in MODES {
            let _ = issue(mode, &text);
        }
        assert!(
            started.elapsed() < linear_budget(),
            "took {:?}",
            started.elapsed()
        );
    }
}
