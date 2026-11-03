//! AGENT-REAL-1 (seal P2): a health term or a secret written with HTML entities
//! is masked in Private mode, whatever the words around it. The detectors read
//! the decoded text, so masking does not depend on the line-name rule.

use std::sync::Arc;

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{Gate, NameDictionary};

fn grant() -> Grant {
    grant_in(PrivacyMode::Private)
}

fn grant_in(mode: PrivacyMode) -> Grant {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &context) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow, got {other:?}"),
    }
}

fn sent(text: &str) -> String {
    sent_in(PrivacyMode::Private, text)
}

fn sent_in(mode: PrivacyMode, text: &str) -> String {
    let names = Arc::new(NameDictionary::new::<[&str; 0], &str>([]).expect("dictionary"));
    let mut gate = Gate::for_grant_with_dictionary(&grant_in(mode), [7u8; 32], names);
    let (safe, _) = gate.text(text).expect("text is issued");
    safe.as_str().to_string()
}

/// `text` goes out with `secret` gone from it, and with a token or a removal
/// marker in its place.
fn assert_masked(text: &str, secret: &str) {
    let out = sent(text);
    assert!(!out.contains(secret), "{text:?} -> {out:?}");
    assert!(
        out.contains('⟦') || out.contains("[secret removed]"),
        "{text:?} -> {out:?}"
    );
}

#[test]
fn the_plain_forms_are_masked() {
    assert_masked("Can you check chimiothérapie, please.", "chimiothérapie");
    // Built at run time: the scanner rejects a key-shaped literal in a file.
    let key = ["sk", "-abcdefghijklmnopqrstuvwxyz"].concat();
    assert_masked(&format!("Can you check {key}, please."), &key[3..]);
}

#[test]
fn an_entity_encoded_health_term_is_masked() {
    for (text, secret) in [
        ("Can you check chimioth&eacute;rapie, please.", "rapie"),
        ("Can you check Chimioth&eacute;rapie, please.", "rapie"),
        ("Can you check CHIMIOTH&Eacute;RAPIE, please.", "RAPIE"),
        ("Can you check chimioth&#233;rapie, please.", "rapie"),
        ("Can you check chimioth&#xe9;rapie, please.", "rapie"),
        ("Can you check chimioth&#XE9;rapie, please.", "rapie"),
        ("Can you check chimioth&amp;eacute;rapie, please.", "rapie"),
        (
            "Hello,\nthe chimioth&eacute;rapie starts on Monday.\nThanks",
            "rapie",
        ),
        (
            "uid 12 · Re: chimioth&eacute;rapie, results · date: Thu, 15 Oct 2026",
            "rapie",
        ),
    ] {
        assert_masked(text, secret);
    }
}

#[test]
fn octal_and_percent_unicode_health_terms_are_masked() {
    for text in [r"\143himiothérapie", "%u0063himiothérapie"] {
        assert_masked(text, "himiothérapie");
    }
}

#[test]
fn an_entity_encoded_secret_is_masked() {
    for text in [
        "Can you check sk&#45;abcdefghijklmnopqrstuvwxyz, please.",
        "Can you check sk&#x2d;abcdefghijklmnopqrstuvwxyz, please.",
        "Can you check sk&#X2D;abcdefghijklmnopqrstuvwxyz, please.",
        "Can you check sk&amp;#45;abcdefghijklmnopqrstuvwxyz, please.",
        "Hello,\nthe key is sk&#45;abcdefghijklmnopqrstuvwxyz for now.\nThanks",
        "uid 12 · key sk&#45;abcdefghijklmnopqrstuvwxyz, ok · date: Thu, 15 Oct 2026",
    ] {
        assert_masked(text, "abcdefghijklmnopqrstuvwxyz");
    }
}

#[test]
fn nested_and_entity_encoded_markers_cannot_hide_an_openai_key() {
    let key = format!("sk-proj-{}", "Ab9cD2eF7gH4iJ1kL8mN5pQ3rS6tU0vW9xY2zA4b");
    assert_eq!(key.strip_prefix("sk-proj-").unwrap().len(), 40);
    let (prefix, suffix) = key.split_at(24);
    let shapes = [
        format!("⟦X⟦{key}⟧Y⟧"),
        format!("⟦&#10214;X &#10215;{key}⟦A B AAA⟧Z⟧"),
        format!("&#10214;X &#10215;{key}&#10214;A B AAA&#10215;Z"),
        format!(
            "⟦&#10214;X &#10215;{prefix}⟦A B {}⟧{suffix}⟧",
            "A".repeat(60)
        ),
    ];

    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        for shape in &shapes {
            let text = format!("Can you check {shape}, please.");
            let out = sent_in(mode, &text);
            for read in [reader_view(&out, true), reader_view(&out, false)] {
                assert!(
                    !read.contains(&key),
                    "{mode:?}: {text:?} -> {out:?} reads {read:?}"
                );
            }
            assert!(!out.contains(&key), "{mode:?}: {text:?} -> {out:?}");
        }
    }
}

/// `Can you check <value>, please.` goes out with none of `parts` readable, even
/// after a reader decodes every entity and deletes every marker and invisible char.
fn assert_hidden(value: &str, parts: &[&str]) {
    let text = format!("Can you check {value}, please.");
    let out = sent(&text);
    for read in [reader_view(&out, true), reader_view(&out, false)] {
        for part in parts {
            assert!(!read.contains(part), "{text:?} -> {out:?} reads {read:?}");
        }
    }
}

/// What a reader rebuilds from the outbound text: entities decoded (numeric,
/// `;` optional; the named ones this file writes, any case) until nothing
/// changes, then `⟦…⟧` markers (`drop_bodies`, else only the brackets) and
/// invisible characters deleted. Written apart from the kernel's decoder, so
/// the property is not a tautology.
fn reader_view(out: &str, drop_bodies: bool) -> String {
    let entity = r"&(?:#[xX]([0-9a-fA-F]+)|#([0-9]+)|((?i)amp|eacute|shy);?|((?i)ccaron|scaron|zcaron|odblac|udblac|egrave|aacute|iacute|oacute|ouml|uuml);|(?i:zerowidthspace|zwj|nobreak|lrm|it);)";
    let entity = regex::Regex::new(entity);
    let entity = entity.expect("regex");
    let mut text = out.to_string();
    for _ in 0..64 {
        let next = entity.replace_all(&text, |c: &regex::Captures| {
            let code = match (c.get(1), c.get(2)) {
                (Some(hex), _) => u32::from_str_radix(hex.as_str(), 16).ok(),
                (_, Some(dec)) => dec.as_str().parse().ok(),
                _ => {
                    let name = c.get(3).or(c.get(4));
                    return [("amp", "&"), ("eacute", "é")]
                        .iter()
                        .chain(NAMED)
                        .find(|(entity, _)| {
                            name.is_some_and(|n| n.as_str().eq_ignore_ascii_case(entity))
                        })
                        .map_or("", |(_, value)| value)
                        .to_string();
                }
            };
            code.and_then(char::from_u32)
                .unwrap_or('\u{FFFD}')
                .to_string()
        });
        if next == text {
            break;
        }
        text = next.into_owned();
    }
    let hidden = if drop_bodies {
        "⟦[^⟧]*⟧|[⟦⟧\u{00AD}\u{200B}-\u{200F}\u{2060}\u{FEFF}]"
    } else {
        "[⟦⟧\u{00AD}\u{200B}-\u{200F}\u{2060}\u{FEFF}]"
    };
    let hidden = regex::Regex::new(hidden);
    hidden.expect("regex").replace_all(&text, "").into_owned()
}

/// The named entities this file writes past `&amp;` and `&eacute;`: the
/// Slovenian, Hungarian and French letters of the health terms below.
const NAMED: &[(&str, &str)] = &[
    ("ccaron", "č"),
    ("scaron", "š"),
    ("zcaron", "ž"),
    ("odblac", "ő"),
    ("udblac", "ű"),
    ("egrave", "è"),
    ("aacute", "á"),
    ("iacute", "í"),
    ("oacute", "ó"),
    ("ouml", "ö"),
    ("uuml", "ü"),
];

const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz";
const SPLIT_KEY: [&str; 2] = ["abcdefghij", "klmnopqrstuvwxyz"];

#[test]
fn seal_round_two_inputs_are_masked() {
    assert_hidden("sk&#45abcdefghijklmnopqrstuvwxyz", &[ALPHABET]);
    assert_hidden("chimioth&AMP;eacute;rapie", &["chimioth", "rapie"]);
    assert_hidden(
        "sk&#45;abcdefghij&#10214;PERSON_ABCDEFABCDEF&#10215;klmnopqrstuvwxyz",
        &SPLIT_KEY,
    );
}

#[test]
fn every_numeric_named_and_nested_form_is_masked() {
    let hyphens = "&#45 &#0045; &#000045 &#x2d &#X2D &#x002D; &#X02d &AMP;#45; &amp;amp;#x2d; &#38;#45; &#38;#38;#45; &amp;amp;amp;amp;amp;#45;";
    for hyphen in hyphens.split(' ') {
        assert_hidden(&format!("sk{hyphen}{ALPHABET}"), &[ALPHABET]);
    }
    let accents = "&EACUTE; &eAcUtE; &Eacute; &eacute &EACUTE &amp;eacute &AMP;AMP;eacute; &#233 &#x0E9 &#XE9;";
    for e in accents.split(' ') {
        assert_hidden(&format!("chimioth{e}rapie"), &["chimioth", "rapie"]);
    }
}

#[test]
fn a_marker_or_invisible_split_inside_a_value_is_masked() {
    let splits = "⟦PERSON_ABCDEFABCDEF⟧ ⟦⟦PERSON_ABCDEFABCDEF⟧ ⟦ &#x27E6;PERSON_ABCDEFABCDEF&#x27E7; &amp;#10214;EMAIL_0A1B2C3D4E5F&amp;#10215; \u{200B} \u{00AD} \u{2060} \u{FEFF} &shy; &#8203 &SHY";
    for split in splits.split(' ') {
        assert_hidden(
            &format!("sk&#45;abcdefghij{split}klmnopqrstuvwxyz"),
            &SPLIT_KEY,
        );
        assert_hidden(
            &format!("chimio{split}th&eacute;rapie"),
            &["chimio", "rapie"],
        );
    }
}

#[test]
fn seal_round_three_inputs_are_masked() {
    // Nested past the pass cap: the whole token fails closed.
    assert_hidden(
        &format!("sk&{}#45;{ALPHABET}", "amp;".repeat(16)),
        &[ALPHABET],
    );
    // A `⟦…⟧` pair of any content or length.
    assert_hidden("sk&#45;abcdefghij⟦A B⟧klmnopqrstuvwxyz", &SPLIT_KEY);
    assert_hidden(
        &format!("chimioth⟦{}⟧érapie", "A".repeat(65)),
        &["chimioth", "rapie"],
    );
    // `&shy` with no `;` before a long run of letters.
    let long_tail = "klmnopqrstuvwxyz".repeat(3);
    assert_hidden(
        &format!("sk&#45;abcdefghij&shy{long_tail}"),
        &["abcdefghij", &long_tail],
    );
    // Invisible named entities.
    for name in [
        "&ZeroWidthSpace;",
        "&zwnj;",
        "&ZWJ;",
        "&NoBreak;",
        "&InvisibleTimes;",
        "&lrm;",
        "&it;",
    ] {
        assert_hidden(
            &format!("sk&#45;abcdefghij{name}klmnopqrstuvwxyz"),
            &SPLIT_KEY,
        );
        assert_hidden(
            &format!("chimio{name}th&eacute;rapie"),
            &["chimio", "rapie"],
        );
    }
}

/// The K10 secret and health samples, as (sentence before, value, sentence after).
/// Already-encoded and multi-line samples are their own cases above.
fn k10_samples() -> Vec<(String, String, String)> {
    let cases = include_str!("../../../qa/privacy-eval/cases/k10-sensitive.jsonl");
    let mut samples = Vec::new();
    for case in cases
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("case"))
    {
        let chars: Vec<char> = case["text"].as_str().expect("text").chars().collect();
        let text = |from: usize, to: usize| chars[from..to].iter().collect::<String>();
        for span in case["spans"].as_array().expect("spans") {
            let at = |key: &str| span[key].as_u64().expect("offset") as usize;
            let value = text(at("start"), at("end"));
            if matches!(span["type"].as_str(), Some("HEALTH" | "SECRET"))
                && !value.contains(['&', '\n'])
            {
                samples.push((text(0, at("start")), value, text(at("end"), chars.len())));
            }
        }
    }
    assert!(samples.len() >= 30, "{} samples", samples.len());
    samples
}

/// Encode the first char of `value`, or insert a split before it.
fn transform(value: &str, kind: u8, zeros: usize) -> String {
    let mut chars = value.chars();
    let ch = chars.next().expect("a char");
    let next = chars.clone().next().unwrap_or(' ');
    let (z, code) = ("0".repeat(zeros), ch as u32);
    let semi = |digit: bool| if digit { ";" } else { "" };
    let encoded = match kind {
        0 => format!("&#{z}{code};"),
        1 => format!("&#{z}{code}{}", semi(next.is_ascii_digit())),
        2 => format!("&#x{z}{code:x};"),
        3 => format!("&#X{z}{code:X}{}", semi(next.is_ascii_hexdigit())),
        4 if ch == 'é' => "&EaCuTe".to_string(),
        4 => format!("&AMP;#{z}{code};"),
        5 => format!("&amp;amp;amp;#x{code:x};"),
        6 => format!("\u{200B}{ch}"),
        7 => format!("&shy;{ch}"),
        8 => format!("⟦PERSON_ABCDEFABCDEF⟧{ch}"),
        9 => format!("&#10214;PERSON_ABCDEFABCDEF&#10215;{ch}"),
        10 => format!("&{}#{code};", "amp;".repeat(16 + zeros)),
        11 => format!("⟦A B {}⟧{ch}", "A".repeat(60 + zeros * 10)),
        12 => format!("&shy{ch}"),
        // A named entity from the full HTML5 table, in any case.
        14 => match NAMED.iter().find(|(_, letter)| letter.starts_with(ch)) {
            Some((name, _)) if zeros % 2 == 1 => format!("&{};", name.to_ascii_uppercase()),
            Some((name, _)) => format!("&{name};"),
            None => format!("&#{code};"),
        },
        // A marker that is no token: inside, a lone opener, entity-written.
        15 => format!("⟦X⟧{ch}"),
        16 => format!("⟦{ch}"),
        17 => format!("&#10214;X{}&#10215;{ch}", " ".repeat(zeros)),
        _ => format!(
            "{}{ch}",
            ["&ZeroWidthSpace;", "&ZWJ;", "&NoBreak;", "&lrm;"][zeros]
        ),
    };
    encoded + chars.as_str()
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|cases| cases.parse().ok())
            .unwrap_or(512)
    ))]

    /// For every K10 secret or health sample and every encoding transform, the
    /// outbound text does not hold the raw value after a reader's decode and strip.
    #[test]
    fn encoded_k10_values_never_leave_readable(
        pick in 0usize..1000,
        steps in proptest::collection::vec((0usize..64, (0u8..18, 0usize..4)), 1..4),
        wrap in 0u8..3,
    ) {
        let samples = k10_samples();
        let (before, value, after) = &samples[pick % samples.len()];
        let len = value.chars().count();
        let mut encoded = value.clone();
        // Distinct positions, rightmost first, so each transform hits a raw char.
        let steps: std::collections::BTreeMap<_, _> =
            steps.into_iter().map(|(at, step)| (at % len, step)).collect();
        for (at, (kind, zeros)) in steps.into_iter().rev() {
            let prefix: String = value.chars().take(at).collect();
            encoded = format!("{prefix}{}", transform(&encoded[prefix.len()..], kind, zeros));
        }
        let text = format!("{before}{encoded}{after}");
        let text = match wrap {
            1 => text.replacen(&encoded, &format!("texte⟦{encoded}⟧"), 1),
            2 => text.replacen(&encoded, &format!("⟦{encoded} ⟧"), 1),
            _ => text,
        };
        let out = sent(&text);
        for read in [reader_view(&out, true), reader_view(&out, false)] {
            proptest::prop_assert!(!read.contains(value.as_str()), "{text:?} -> {out:?} reads {read:?}");
        }
    }
}

/// DECODE-HARDEN-2 (a): a health term written with any HTML5 named entity is
/// masked like its plain form. `parts` are pieces of the term that must not
/// be readable.
#[test]
fn health_terms_with_named_entities_are_masked() {
    for (encoded, plain, parts) in [
        ("plju&ccaron;ni rak", "pljučni rak", &["plju", "ni rak"][..]),
        ("PLJU&Ccaron;NI RAK", "PLJUČNI RAK", &["PLJU", "NI RAK"]),
        ("plju&CCARON;ni rak", "pljučni rak", &["plju", "ni rak"]),
        (
            "du&scaron;evna bolezen",
            "duševna bolezen",
            &["evna bolezen"],
        ),
        ("mo&zcaron;ganska kap", "možganska kap", &["ganska kap"]),
        (
            "bolezen &scaron;&ccaron;itnice",
            "bolezen ščitnice",
            &["itnice"],
        ),
        ("sr&ccaron;ni infarkt", "srčni infarkt", &["infarkt"]),
        (
            "rak debelega &ccaron;revesa",
            "rak debelega črevesa",
            &["debelega", "revesa"],
        ),
        (
            "t&uuml;d&odblac;gyullad&aacute;s",
            "tüdőgyulladás",
            &["gyullad"],
        ),
        (
            "k&aacute;b&iacute;t&oacute;szer-f&uuml;gg&odblac;s&eacute;g",
            "kábítószer-függőség",
            &["szer-f"],
        ),
        ("f&uuml;gg&odblac;s&eacute;g", "függőség", &["gg"]),
        ("kemoter&aacute;pia", "kemoterápia", &["kemoter"]),
        ("leuk&eacute;mia", "leukémia", &["leuk"]),
        ("diab&egrave;te", "diabète", &["diab"]),
        ("&Eacute;pilepsie", "Épilepsie", &["pilepsie"]),
        ("sant&eacute; mentale", "santé mentale", &["mentale"]),
        ("h&eacute;patite", "hépatite", &["patite"]),
    ] {
        let (plain_out, encoded_out) = (
            sent(&format!("Can you check {plain}, please.")),
            sent(&format!("Can you check {encoded}, please.")),
        );
        assert!(!plain_out.contains(plain), "{plain:?} -> {plain_out:?}");
        assert!(
            !encoded_out.contains(encoded),
            "{encoded:?} -> {encoded_out:?}"
        );
        assert_hidden(encoded, parts);
    }
}

/// DECODE-HARDEN-2 (b): a `⟦` or `⟧` that is no token this gate minted is
/// ambiguous, so its whole run is masked: around, inside and across a value.
#[test]
fn a_marker_around_inside_or_across_a_value_masks_its_run() {
    for value in [
        "texte⟦sk&#45;abcdefghijklmnopqrstuvwxyz⟧",
        "texte⟦sk~abcdefghijklmnopqrstuvwxyz⟧",
        "⟦sk~abcdefghijklmnopqrstuvwxyz⟧",
        "⟦sk&#45;abcdefghijklmnopqrstuvwxyz",
        "sk&#45;abcdefghijklmnopqrstuvwxyz⟧",
        "sk~abcdefghij⟦X⟧klmnopqrstuvwxyz",
        "sk~abcdefghij⟧klmnopqrstuvwxyz",
        "sk~abcdefghij⟦X klmnopqrstuvwxyz⟧",
        "⟦texte sk~abcdefghij⟧klmnopqrstuvwxyz",
        "texte&#x27E6;sk&#45;abcdefghijklmnopqrstuvwxyz&#x27E7;",
        "texte⟦PERSON_ABCDEFABCDEF⟧sk&#45;abcdefghijklmnopqrstuvwxyz",
    ] {
        // `sk~` reads `sk-` at run time: the scanner rejects a key-shaped literal.
        assert_hidden(&value.replace("sk~", "sk-"), &SPLIT_KEY);
    }
    for value in [
        "chimioth⟦X⟧éra⟦pie ⟧",
        "chimioth⟦X⟧érapie",
        "chimio⟦th⟧&eacute;rapie",
        "⟦chimioth&eacute;rapie⟧",
        "plju⟦X⟧&ccaron;ni rak",
    ] {
        assert_hidden(value, &["chimioth", "rapie", "plju"]);
    }
}

/// A session token the model passes back stays whole; a marker next to it
/// that the session never minted still masks its run.
#[test]
fn a_minted_session_token_stays_and_a_stray_marker_is_masked() {
    let token = "EMAIL_0A1B2C3D4E5F".to_string();
    let minted = Arc::new([token.clone()].into_iter().collect());
    let mut gate = Gate::for_session_tokens(&grant(), minted).expect("session gate");
    let text = format!("Mail ⟦{token}⟧ with texte⟦sk&#45;abcdefghijklmnopqrstuvwxyz⟧ now");
    let (safe, _) = gate.text(&text).expect("issued");
    let out = safe.as_str();
    assert!(
        out.starts_with(&format!("Mail ⟦{token}⟧ with ⟦")),
        "{out:?}"
    );
    assert!(out.ends_with(" now"), "{out:?}");
    for read in [reader_view(out, true), reader_view(out, false)] {
        assert!(!read.contains("abcdefghij"), "{out:?}");
    }
}

fn open_gate() -> Gate {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, PrivacyMode::Open, &context) {
        Decision::Allow(grant) => Gate::for_passthrough(&grant).expect("open gate"),
        other => panic!("expected Allow, got {other:?}"),
    }
}

/// Revision 1 (maintainer): a marker alone is no reason to mask. Maths and
/// markdown with `⟦ ⟧` read as before, in both modes; the original attacks stay
/// masked.
#[test]
fn a_marker_with_no_value_behind_it_stays_text() {
    for text in [
        "Please use ⟦x + 1⟧ in the formula.",
        "Semantics: ⟦e1 + e2⟧ρ = ⟦e1⟧ρ + ⟦e2⟧ρ, see the notes.",
        "- **Step 2:** write `⟦a, b⟧` for the closed range ⟦0, 10⟧.",
        "A lone ⟦ or ⟧ in a sentence stays.",
    ] {
        assert_eq!(sent(text), text.replace('⟦', "⟦⟦"), "Private: {text:?}");
        let (open, _) = open_gate().text(text).expect("open text");
        assert_eq!(open.as_str(), text, "Open: {text:?}");
    }
    for text in [
        "Can you check texte⟦sk&#45;abcdefghijklmnopqrstuvwxyz⟧, please.",
        "Can you check chimioth⟦X⟧éra⟦pie ⟧, please.",
    ] {
        let (open, _) = open_gate().text(text).expect("open text");
        for out in [sent(text), open.as_str().to_string()] {
            for read in [reader_view(&out, true), reader_view(&out, false)] {
                for part in ["abcdefghij", "chimioth", "rapie"] {
                    assert!(!read.contains(part), "{text:?} -> {out:?}");
                }
            }
        }
    }
}

/// Seal r1 P2-1: a secret-named JSON key masks the whole value, a marker in
/// it or not, in both modes.
#[test]
fn a_secret_named_key_masks_the_whole_value_with_a_marker_in_it() {
    let value = serde_json::json!({ "password": "⟦x⟧unusual-pass phrase remainder" });
    let names = Arc::new(NameDictionary::new::<[&str; 0], &str>([]).expect("dictionary"));
    let mut private = Gate::for_grant_with_dictionary(&grant(), [7u8; 32], names);
    let (masked, _) = private.value(&value).expect("private value");
    let (open, _) = open_gate().value(&value).expect("open value");
    for wire in [masked.as_value().to_string(), open.as_value().to_string()] {
        for part in ["unusual", "pass phrase", "remainder"] {
            assert!(!wire.contains(part), "{wire}");
        }
    }
}

/// Seal r1 P2-2: 1 MiB of forged tokens through the session-token gate stays
/// linear (31.3 s in debug at 79e312df, quadratic). One registry pass over
/// 1 MiB of blanks takes about 9 s in debug, so the bound is relative: 1 MiB
/// takes under 8 times what 256 KiB takes (linear is 4, quadratic 16), and
/// under 120 s debug, 15 s release.
#[test]
fn a_mebibyte_of_forged_tokens_is_linear() {
    let time = |copies: usize| {
        let text = "⟦EMAIL_FFFFFFFFFFFF⟧ ".repeat(copies);
        let minted = Arc::new(["EMAIL_0A1B2C3D4E5F".to_string()].into_iter().collect());
        let mut gate = Gate::for_session_tokens(&grant(), minted).expect("session gate");
        let start = std::time::Instant::now();
        let (safe, _) = gate.text(&text).expect("issued");
        assert!(safe.as_str().contains("⟦⟦EMAIL_FFFFFFFFFFFF⟧"));
        start.elapsed()
    };
    let (quarter, full) = (time(43_690 / 4), time(43_690));
    eprintln!("forged tokens: 256 KiB {quarter:?}, 1 MiB {full:?}");
    assert!(full < quarter * 8, "256 KiB {quarter:?}, 1 MiB {full:?}");
    let bound = if cfg!(debug_assertions) { 120 } else { 15 };
    assert!(
        full < std::time::Duration::from_secs(bound),
        "1 MiB took {full:?}"
    );
}
