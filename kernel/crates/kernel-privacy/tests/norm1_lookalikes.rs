//! NORM-1: look-alike, full-width, mathematical and invisible characters no
//! longer hide a value. Every byte of each value, the invisible ones inside it
//! included, is masked through `Gate::for_grant`; Private restores the exact
//! original bytes; Chinese and Cyrillic prose stay unchanged. All values are
//! invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{EntityKind, Gate, Recognizer, Registry, Span};

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, exact_or_fail, issue, masked, wide, CYRILLIC_PROSE, MODES, ZH_PROSE};

/// The ranges a Private output masks, read exactly from the tokens the gate
/// minted: a text the output does not read back onto fails here
/// (TEST-FITS-EXACT).
fn exact(text: &str, output: &str, minted: &[(String, String)]) -> Vec<(usize, usize)> {
    exact_or_fail(PrivacyMode::Private, text, output, minted)
}

/// The NORM-1a repros, then a look-alike behind an HTML entity: the
/// decoded views are folded too.
fn repros() -> Vec<(String, String, bool)> {
    let mut out = cases::repros();
    for (frame, value) in [
        ("key {}", "sk-pr\u{43E}j-abcdefgh&#105;jklmnopqrstuvwx"),
        ("I have {}", "di&#1072;betes"),
        ("I have {}", "dia&nbsp;betes"),
        ("key {}", "&#1109;k-proj-abcdefghijklmnopqrstuvwx"),
        ("key {}", "sk-proj-abcdefgh&nbsp;ijklmnopqrstuvwx"),
    ] {
        out.push((frame.replace("{}", value), value.to_string(), true));
    }
    out
}

#[test]
fn every_byte_of_each_value_is_masked_through_both_gates() {
    let mut leaks = Vec::new();
    for (text, value, open) in repros() {
        let at = text.find(&value).unwrap();
        let modes = if open { &MODES[..] } else { &MODES[..1] };
        for &mode in modes {
            let ranges = masked(mode, &text).expect("never refused");
            if !covered(&ranges, at, at + value.len()) {
                leaks.push(format!("{mode:?} {text:?}: {ranges:?}"));
            }
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

#[test]
fn private_restores_the_exact_original_bytes() {
    for (text, _, _) in repros() {
        let (output, minted) = issue(PrivacyMode::Private, &text).expect("never refused");
        assert!(!minted.is_empty(), "{text:?} -> {output:?}");
        let mut restored = output.clone();
        for (token, surface) in minted {
            restored = restored.replace(&format!("⟦{token}⟧"), &surface);
        }
        assert_eq!(restored, text, "{output:?}");
    }
}

/// A Private gate kept across calls, as a chat session keeps it.
fn private_gate() -> Gate {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &ctx) else {
        panic!("A1 must be allowed in Private");
    };
    Gate::for_grant(&grant, [9u8; 32])
}

/// Two spellings of one value (ASCII and look-alike) get two tokens,
/// so each restores to its own bytes, in either order, in one text or across
/// two calls of one gate. Both are masked in both modes.
#[test]
fn two_spellings_of_one_value_each_restore_exactly() {
    let plain = "ES91 2100 0418 4502 0005 1332";
    let styled = format!("{} 2100 0418 4502 0005 1332", cases::bold("ES91"));
    let others = [
        styled.clone(),
        wide(plain),
        "\u{415}S91 2100 0418 4502 0005 1332".to_string(),
        "ES91\u{A0}2100\u{200B}0418 4502 0005 1332".to_string(),
    ];
    for other in &others {
        for (first, second) in [(plain, other.as_str()), (other.as_str(), plain)] {
            let text = format!("IBAN {first} and {second}.");
            for mode in MODES {
                let got = masked(mode, &text).expect("never refused");
                for value in [first, second] {
                    let at = text.find(value).unwrap();
                    assert!(covered(&got, at, at + value.len()), "{mode:?} {text:?}");
                }
            }
            let mut gate = private_gate();
            let output = gate.text(&text).expect("issued").0.as_str().to_string();
            assert_eq!(restore(&output, &gate.take_minted()), text, "{output:?}");
            // The same two spellings across two calls of one gate, then again.
            let mut gate = private_gate();
            let mut minted = Vec::new();
            for value in [first, second, first, second] {
                let text = format!("IBAN {value}.");
                let output = gate.text(&text).expect("issued").0.as_str().to_string();
                let one = gate.take_minted();
                minted.extend(one.iter().cloned());
                // The cumulative `minted`, not `one`: a value the gate already
                // tokenised in an earlier call of this session reuses its token
                // and mints nothing, so this call's `take_minted` is empty while
                // the output still carries that token. The reader needs the name
                // to admit the detector span it falls back to (TEST-FITS-EXACT).
                assert_eq!(exact(&text, &output, &minted).len(), 1, "{output:?}");
                assert_eq!(restore(&output, &minted), text, "{output:?}");
            }
        }
    }
}

/// `output` with each minted token replaced by its surface.
fn restore(output: &str, minted: &[(String, String)]) -> String {
    let mut restored = output.to_string();
    for (token, surface) in minted {
        restored = restored.replace(&format!("⟦{token}⟧"), surface);
    }
    restored
}

/// A recogniser that knows only ASCII, like a label rule: `MRN: ` then digits.
struct AsciiMrn;

impl Recognizer for AsciiMrn {
    fn kinds(&self) -> &[EntityKind] {
        &[EntityKind::Health]
    }

    fn analyze(&self, text: &str) -> Vec<Span> {
        let Some(at) = text.find("MRN: ").map(|at| at + 5) else {
            return Vec::new();
        };
        let digits = text[at..].bytes().take_while(u8::is_ascii_digit).count();
        (digits >= 6)
            .then(|| Span::new(EntityKind::Health, at, at + digits, 1.0, "mrn"))
            .into_iter()
            .collect()
    }
}

/// Every recogniser reads the folded view, so an ASCII-only rule (the MRN label
/// rule of LABEL-VALUE-1 is one) sees full-width, bold and spaced digits.
#[test]
fn an_ascii_only_recogniser_sees_a_full_width_mrn() {
    let registry = Registry::builder()
        .with_recognizer(AsciiMrn)
        .without_email_layer()
        .build();
    for value in [wide("00438291"), cases::bold("00438291")] {
        for label in ["MRN: ", "ＭＲＮ： ", "MRN\u{FF1A}\u{A0}"] {
            let text = format!("{label}{value}.");
            let spans = registry.analyze(&text);
            let at = text.find(&value).unwrap();
            let ranges: Vec<_> = spans.iter().map(|s| (s.start, s.end)).collect();
            assert!(
                covered(&ranges, at, at + value.len()),
                "{text:?}: {spans:?}"
            );
        }
    }
}

/// Through the gate, a full-width MRN is masked wherever the ASCII one is.
#[test]
fn a_full_width_mrn_is_masked_wherever_the_ascii_one_is() {
    for mode in MODES {
        let ascii = masked(mode, "MRN: 00438291").expect("never refused");
        let text = format!("MRN: {}", wide("00438291"));
        let ranges = masked(mode, &text).expect("never refused");
        if covered(&ascii, 5, 13) {
            assert!(covered(&ranges, 5, text.len()), "{mode:?}: {ranges:?}");
        }
    }
}

#[test]
fn chinese_and_cyrillic_prose_stay_unchanged() {
    for text in ZH_PROSE.iter().chain(CYRILLIC_PROSE) {
        for mode in MODES {
            assert_eq!(masked(mode, text), Some(Vec::new()), "{mode:?} {text:?}");
        }
    }
}

/// Release only: text dense with zero-width, full-width, look-alike and
/// Unicode-space characters, at 4k, 16k and 64k repeats. Bar: each 4x step
/// costs under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test norm1_lookalikes -- --ignored"]
fn dense_folded_text_scales_linearly() {
    let units = [
        "a\u{200B}b\u{AD}c\u{2060}d\u{FEFF} ",
        "ｗｏｒｄ １２３４，",
        "p\u{430}ss\u{3BF} w\u{A0}x ",
        "𝐛𝐨𝐥𝐝 𝟏𝟐 ",
        "di&#1072;b&nbsp;x\u{200B}y ",
    ];
    for unit in units {
        let time = |reps: usize| {
            let text = unit.repeat(reps);
            (0..3)
                .map(|_| {
                    let start = Instant::now();
                    let _ = issue(PrivacyMode::Private, &text);
                    start.elapsed()
                })
                .min()
                .unwrap()
        };
        let times: Vec<Duration> = [4_000, 16_000, 64_000].map(time).to_vec();
        eprintln!("{unit:?}: {times:?}");
        for pair in times.windows(2) {
            let ratio = pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6);
            assert!(ratio < 6.0, "{unit:?}: {times:?}");
        }
    }
}
