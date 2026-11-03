//! Properties of the delimiter escape.
//!
//! The only rewrite is a literal opener `⟦`, written doubled. So ordinary
//! text round-trips byte for byte, paths and code pass the gate unchanged, and
//! a placeholder the user types is never restored as a real value.

use std::sync::OnceLock;

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::{Anonymizer, DetectionReport, Gate, Registry, TokenMap, UnknownPolicy};
use proptest::prelude::*;

const KEY: [u8; 32] = [0x5Au8; 32];

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::new)
}

/// A real open-mode grant: the gate can only be built from one.
fn open_grant() -> Grant {
    let ctx = Context {
        destination: Destination::LocalDisplay,
    };
    match admit(PathId::C9, PrivacyMode::Open, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow, got {other:?}"),
    }
}

fn restore_keep(text: &str, pairs: &TokenMap) -> String {
    Anonymizer::restore(text, pairs, UnknownPolicy::Keep).text
}

/// Text built from the characters that matter to the escape: both brackets,
/// backslashes, look-alike escapes, a value and an ordinary word.
fn fragment() -> impl Strategy<Value = String> {
    proptest::string::string_regex(r"[⟦⟧\\u0-9A-Za-z 'é〚〛\n@.+-]{0,48}").unwrap()
}

#[test]
fn ordinary_text_without_pii_is_issued_byte_identical() {
    let samples = [
        r"C:\Users\build\target\debug\aux.exe",
        r"\\serveur\partage\dossier\notes.txt",
        r"^\d{2,3}\s+[A-Za-z_]\w*\.(rs|toml)$",
        r"\frac{\alpha}{\beta} + \sum_{i=1}^{n} x_i \\ fin",
        r#"{"path":"C:\\Users\\build","pattern":"\\d+\\s","note":"tab\tnew\nline"}"#,
        "fn main() { println!(\"\\u{1F600}\\n\"); }",
        "chemin \\ seul et \\\\ double",
        "〚 crochets 〛 et 【 noirs 】",
    ];
    for sample in samples {
        let mut gate = Gate::for_grant(&open_grant(), KEY);
        let (safe, report) = gate.text(sample).unwrap();
        assert_eq!(safe.as_str(), sample, "the gate changed {sample:?}");
        assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
    }
}

#[test]
fn restore_inverts_gate_on_fixed_inputs() {
    let inputs = [
        "",
        "⟦",
        "⟦⟦",
        "⟧⟦",
        r"a\u27E6⟦⟦b",
        "〚⟦〛",
        "⟦EMAIL_abcdef⟧",
        "x ⟦PHONE_0A1B2C3D4E5F⟧ y",
        "⟦ elise.vautrin@example.invalid ⟦",
        "mail elise.vautrin@example.invalid et ⟦⟦EMAIL_0a1b2c⟧ fin",
    ];
    for input in inputs {
        let spans = registry().analyze(input);
        let (masked, pairs) = Anonymizer::new(KEY).anonymize(input, &spans);
        let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
        assert_eq!(report.text, input, "round trip failed for {input:?}");
        assert!(report.is_clean(), "unexpected unknown token for {input:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// `restore(anonymize(x)) == x` for any mix of brackets, backslashes and
    /// values, whether or not the registry found a span.
    #[test]
    fn restore_inverts_anonymize(text in fragment()) {
        let spans = registry().analyze(&text);
        let (masked, pairs) = Anonymizer::new(KEY).anonymize(&text, &spans);
        let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
        prop_assert_eq!(&report.text, &text);
        prop_assert!(report.is_clean());
    }

    /// A placeholder the user types is text: it is never restored and never
    /// reported as a real token, wherever it sits in the message.
    #[test]
    fn a_typed_placeholder_is_never_a_token(
        kind in "[A-Z]{3,8}",
        hex in "[0-9A-F]{6,12}",
        before in fragment(),
        after in fragment(),
    ) {
        let typed = format!("{before}⟦{kind}_{hex}⟧{after}");
        let (masked, pairs) = Anonymizer::new(KEY).anonymize(&typed, &[]);
        prop_assert_eq!(restore_keep(&masked, &pairs), typed.clone());
        let report = Anonymizer::restore(&masked, &pairs, UnknownPolicy::Keep);
        prop_assert!(report.unknown.is_empty(), "typed look-alike was parsed as a token");
    }

    /// Text with no detected value keeps every byte outside the literal
    /// openers: the escape never touches backslashes or the closer.
    #[test]
    fn only_literal_openers_change_in_masked_text(text in fragment()) {
        let (masked, _) = Anonymizer::new(KEY).anonymize(&text, &[]);
        prop_assert_eq!(masked, text.replace('⟦', "⟦⟦"));
    }
}
