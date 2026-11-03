//! LABEL-VALUE-1 acceptance: every finish-line repro (a sensitive label followed
//! by its value) is tokenised in Private and removed in Open. The superset and
//! precision proof is `tests/label_value_differential.rs`.

use std::sync::Arc;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::recognizers::label_value::LabelValueRecognizer;
use kernel_privacy::{Gate, NameDictionary, Recognizer};

include!("data/label_value_cases.rs");

fn gate(mode: PrivacyMode) -> Gate {
    let ctx = Context {
        destination: Destination::Vendor("label-value".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be admitted");
    };
    let names = Arc::new(NameDictionary::new(Vec::<String>::new()).expect("dictionary"));
    Gate::for_grant_with_dictionary(&grant, [7; 32], names)
}

/// Spec rule 5: every finish-line repro is tokenised in Private and removed in Open.
#[test]
fn every_label_value_repro_is_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, value) in REPROS {
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            match gate(mode).text(text) {
                Ok((out, _)) if out.as_str().contains(value) => {
                    wrong.push(format!("{mode:?} {text:?} -> {:?}", out.as_str()));
                }
                Ok((out, _))
                    if mode == PrivacyMode::Open && !out.as_str().contains(" removed]") =>
                {
                    wrong.push(format!(
                        "Open kept no marker: {text:?} -> {:?}",
                        out.as_str()
                    ));
                }
                Ok(_) => {}
                Err(error) => wrong.push(format!("{mode:?} {text:?} refused: {error:?}")),
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Spec rule 2: a label with no value after it yields no span.
#[test]
fn a_trap_yields_no_label_value_span() {
    for text in TRAPS {
        let spans = LabelValueRecognizer::new().analyze(text);
        assert!(spans.is_empty(), "{text:?}: {spans:?}");
    }
}

/// The gate output with its tokens and removal marks taken out.
fn clear_of(out: &str) -> String {
    let out: String = out
        .split('⟦')
        .map(|part| part.split_once('⟧').map_or(part, |(_, rest)| rest))
        .collect();
    out.split('[')
        .map(|part| part.split_once(" removed]").map_or(part, |(_, rest)| rest))
        .collect()
}

/// Every byte of `text[at..at + value.len()]` is under a label-value span, both gates
/// issue the text, and no 3-character piece of the value (that the text holds
/// nowhere else) is left in clear. With
/// `alphabet`, no character of it is left in clear either (the text holds it only
/// in the value), so even a one-byte tail is caught.
fn assert_hidden(text: &str, value: &str, alphabet: &str) {
    let at = text.find(value).expect("value in text");
    let spans = LabelValueRecognizer::new().analyze(text);
    let missed = (at..at + value.len())
        .filter(|b| !spans.iter().any(|s| s.start <= *b && *b < s.end))
        .count();
    assert_eq!(missed, 0, "raw: {missed} value bytes clear in {text:.120?}");
    let chars: Vec<char> = value.chars().collect();
    let around = format!("{}\u{0}{}", &text[..at], &text[at + value.len()..]);
    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        let out = match gate(mode).text(text) {
            Ok((out, _)) => clear_of(out.as_str()),
            Err(error) => panic!("{mode:?} refused {text:.80?}: {error:?}"),
        };
        for piece in chars.windows(3.min(chars.len())) {
            let piece: String = piece.iter().collect();
            if around.contains(&piece) {
                continue;
            }
            assert!(
                !out.contains(&piece),
                "{mode:?}: {piece:?} clear in {out:.160?}"
            );
        }
        let left: Vec<char> = out.chars().filter(|c| alphabet.contains(*c)).collect();
        assert!(
            left.is_empty(),
            "{mode:?}: {} value chars clear",
            left.len()
        );
    }
}

/// Fix r1 P2-1: a Unicode blank before a cookie pair never panics or refuses.
#[test]
fn a_cookie_pair_after_a_unicode_blank_is_masked_without_refusal() {
    for blank in ["\u{a0}", "\u{2003}", "\u{202f}", "\u{3000}", " "] {
        let text = format!("x{blank}csrftoken=Ab12Cd34Ef; Path=/");
        assert_hidden(&text, "Ab12Cd34Ef", "");
    }
}

/// Fix r1 P2-2: an all-letter password or a passphrase after a prose link is masked
/// whole, with its clause.
#[test]
fn an_all_letter_password_or_passphrase_after_a_link_is_masked_whole() {
    for (text, value) in [
        (
            "the password might be correcthorsebattery",
            "correcthorsebattery",
        ),
        (
            "the password might be red9 horse battery",
            "red9 horse battery",
        ),
        ("the password, sunflowerfield, opens it", "sunflowerfield"),
        ("the password was set to bluemoonrising", "bluemoonrising"),
        ("my pin was changed to tangerine", "tangerine"),
        (
            "the passphrase will be correct horse battery staple",
            "correct horse battery staple",
        ),
        ("the password might be \"opensesame\" now", "opensesame"),
        (
            "the password might be 'red horse battery'",
            "red horse battery",
        ),
    ] {
        assert_hidden(text, value, "");
    }
}

/// `n` bytes from an alphabet the surrounding texts never use, multi-byte included.
fn long_value(n: usize) -> String {
    let mut out = String::new();
    for ch in "Qx7Zé密".chars().cycle() {
        if out.len() + ch.len_utf8() > n {
            break;
        }
        out.push(ch);
    }
    out.extend(std::iter::repeat_n('x', n - out.len()));
    out
}

/// Fix r1 P2-3: a cookie, token or quoted value is masked to its end, whatever its
/// length; the registry splits the span to its size limits.
#[test]
fn a_long_value_is_masked_to_its_last_byte() {
    for n in [511, 512, 513, 800] {
        let v = long_value(n);
        for text in [
            format!("Cookie: sid={v}"),
            format!("Set-Cookie: sid={v}; Path=/"),
            format!("the password might be {v}"),
            format!("api key, {v} ok"),
            format!("the password might be \"{v}\" ok"),
            format!("the password: \"{v}"),
            format!("the password might be '{v}"),
        ] {
            assert_hidden(&text, &v, "Qx7Zé密");
        }
    }
}

/// Fix r1 P2-4: an accented or blank-separated blood sign is masked with its group.
#[test]
fn an_accented_blood_sign_is_masked_with_its_group() {
    for (text, value) in [
        ("Groupe sanguin : O négatif", "O négatif"),
        ("Groupe sanguin : O ne\u{301}gatif", "O ne\u{301}gatif"),
        ("Groupe sanguin : AB négatif", "AB négatif"),
        ("Vércsoport: O pozitív", "O pozitív"),
        ("Vércsoport: O poziti\u{301}v", "O poziti\u{301}v"),
        ("blood group: O\u{a0}neg", "O\u{a0}neg"),
        ("Blood type: AB\u{2009}positive.", "AB\u{2009}positive"),
    ] {
        assert_hidden(text, value, "");
    }
}

/// Fix r1 P3: a prose word before a year is no ID, and a prose link brings no list,
/// verb or address as a password.
#[test]
fn an_id_card_renewal_year_stays_clear() {
    for text in [
        "ID card renewal 2026",
        "Reset your password, then log in",
        "Use strong passwords, two-factor authentication and locks.",
        "The link and passcode will be sent to you separately.",
        "send the password to bob tomorrow",
        "geslo je pozabljeno",
        "das Passwort ist vergessen",
    ] {
        let spans = LabelValueRecognizer::new().analyze(text);
        assert!(spans.is_empty(), "{text:?}: {spans:?}");
    }
}
