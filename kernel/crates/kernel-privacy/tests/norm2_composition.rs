//! NORM-2: decoding and folding compose. A fold creates escapes of its own
//! (`&#65286;` reads as the full-width `＆`, which folds back to `&`), and what
//! that escape reads folds again (`о` reads as `o`). Every view of a round is
//! decoded again, each fold of it is scanned too, the composed map still covers
//! every source byte of the value, and the composition is bounded: at the pass
//! cap a spelling that deep stays masked rather than read. Through
//! `Gate::for_grant`, in Private and Open, with Private restoring the exact
//! original bytes. All values are invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
use cases::{covered, issue, masked, CYRILLIC_PROSE, MODES, ZH_PROSE};

/// Rounds of decode and fold the composition runs, the cap the tests hold it to.
const ROUNDS: usize = 3;

/// Private through the gate, with every minted token put back: the restore must
/// be the exact original bytes.
fn private_round_trip(text: &str) {
    let (output, minted) = issue(PrivacyMode::Private, text).expect("never refused");
    assert!(!minted.is_empty(), "{text:?} -> {output:?}");
    let mut restored = output.clone();
    for (name, surface) in minted {
        restored = restored.replace(&format!("\u{27E6}{name}\u{27E7}"), &surface);
    }
    assert_eq!(restored, text, "{output:?}");
}

/// The repros: an escape a fold created is decoded again, and what it
/// reads folds again. Every byte of the value is covered, in both modes.
fn repros() -> Vec<(String, String)> {
    let head = "sk-pr\u{43E}j-abcdefgh";
    let mut out = Vec::new();
    let mut add = |frame: &str, value: String| {
        let text = frame.replace("{}", &value);
        assert!(text.contains(&value), "{text:?}");
        out.push((text, value));
    };
    // `&#65286;` decodes to `＆`, which folds back to `&`, so `&#105;` reads as
    // the `i` of `sk-proj` only after the fold.
    add("key {}jklmnopqrstuvwx", format!("{head}&#65286;#105;"));
    add("I have {}", "di&#65286;#1072;betes".into());
    // The same escape with `＆` and `&nbsp;` written plainly.
    add("I have {}", "di\u{FF06}#1072;betes".into());
    add("I have {}", "dia\u{FF06}nbsp;betes".into());
    add("key {}jklmnopqrstuvwx", format!("{head}\u{FF06}#105;"));
    // A percent escape decodes to the full-width `％`, which folds back to `%`,
    // so `%D0%BE` reads as the Cyrillic `о` of `sk-proj`. Open left both URLs in
    // clear; Private masked them.
    let url = "https://example.invalid/?key=sk-pr";
    let tail = "j-abcdefghijklmnopqrstuvwx";
    add("{}", format!("{url}%EF%BC%85D0%EF%BC%85BE{tail}"));
    add("{}", format!("{url}\u{FF05}D0\u{FF05}BE{tail}"));
    out
}

#[test]
fn every_byte_of_each_value_is_masked_through_both_gates() {
    let mut leaks = Vec::new();
    for (text, value) in repros() {
        let at = text.find(&value).expect("value inside");
        for mode in MODES {
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
    for (text, _) in repros() {
        private_round_trip(&text);
    }
}

/// The round-1 repros of both reviewers, at gate level. Two leaks, both a
/// variant of this work order's own family, both in Private and Open:
///
/// * a bracket a fold created (`＆#10214;` folds to `&#10214;`, which reads as
///   `⟦`) was decoded in the default marker mode, where a `⟦…⟧` pair goes with
///   its content, so every deeper round dropped the value inside it;
/// * a full-width `＆` that opens an escape at the start of a token had no ASCII
///   letter or digit beside it, so `Fold::Punct` left it alone and the escape it
///   begins was never decoded.
///
/// With the value inside it and the prose around it that must stay clear.
fn round1_repros() -> Vec<(String, String, &'static [&'static str])> {
    [
        // P2-1: a `⟦…⟧` pair a fold created, around a key.
        (
            "key x\u{ff06}#10214;sk-pr\u{ff06}#111;j-abcdefghijklmnopqrstuvwx\u{ff06}#10215;y end",
            "sk-pr\u{ff06}#111;j-abcdefghijklmnopqrstuvwx",
            &["key ", " end"][..],
        ),
        // The same pair with a Cyrillic `о` (`&#1086;`) inside, and no prose.
        (
            "x\u{ff06}#10214;sk-pr\u{ff06}#1086;j-abcdefghijklmnopqrstuvwx\u{ff06}#10215;x",
            "sk-pr\u{ff06}#1086;j-abcdefghijklmnopqrstuvwx",
            &[][..],
        ),
        // The pair around an AWS key, with a Cyrillic `А` (`&#1040;`) inside.
        (
            "1\u{ff06}#10214;AKI\u{ff06}#1040;IOSFODNN7EXAMPLE\u{ff06}#10215;2",
            "AKI\u{ff06}#1040;IOSFODNN7EXAMPLE",
            &[][..],
        ),
        // One lone bracket: dropping it splices `texte` onto `sk-`, and the key
        // rule takes `sk-` only beside no letter or digit.
        (
            "texte\u{ff06}#10214;sk-pr\u{ff06}#111;j-abcdefghijklmnopqrstuvwx",
            "sk-pr\u{ff06}#111;j-abcdefghijklmnopqrstuvwx",
            &[][..],
        ),
        // P2-2: a full-width `＆` opening an escape at the start of a token.
        (
            "I have \u{ff06}#100;i\u{ff06}#1072;betes",
            "\u{ff06}#100;i\u{ff06}#1072;betes",
            &["I have "][..],
        ),
        (
            "key \u{ff06}#115;k-pr\u{43E}j-abcdefghijklmnopqrstuvwx",
            "\u{ff06}#115;k-pr\u{43E}j-abcdefghijklmnopqrstuvwx",
            &["key "][..],
        ),
        // Control for the same rule: a full-width `％` opening a percent escape
        // at the start of a URL path. It already folded (the first hex digit is
        // the ASCII digit beside it), and must keep folding. No prose to hold
        // clear: the URL rule masks the whole URL on its own.
        (
            "https://example.invalid/\u{ff05}73k-proj-abcdefghijklmnopqrstuvwx",
            "\u{ff05}73k-proj-abcdefghijklmnopqrstuvwx",
            &[][..],
        ),
    ]
    .map(|(text, value, clear)| (text.to_string(), value.to_string(), clear))
    .into()
}

/// Every byte of the value is masked through both gates, and the prose around
/// it is not: masking the whole line would pass a weaker test than this one.
#[test]
fn fold_created_brackets_and_leading_ampersands_never_hide_a_value() {
    let mut leaks = Vec::new();
    for (text, value, clear) in round1_repros() {
        let at = text.find(&value).expect("value inside");
        for mode in MODES {
            let ranges = masked(mode, &text).expect("never refused");
            if !covered(&ranges, at, at + value.len()) {
                leaks.push(format!("{mode:?} {text:?}: {ranges:?}"));
                continue;
            }
            for prose in clear {
                let at = text.find(prose).expect("clear prose inside");
                if covered(&ranges, at, at + prose.len()) {
                    leaks.push(format!("{mode:?} {text:?}: masked {prose:?}: {ranges:?}"));
                }
            }
        }
    }
    assert!(leaks.is_empty(), "{leaks:#?}");
}

/// Private puts every one of them back byte for byte.
#[test]
fn private_restores_every_round1_repro() {
    for (text, _, _) in round1_repros() {
        private_round_trip(&text);
    }
}

/// An escape nested `depth` levels deep: `&#65286;` decodes to `＆` and the fold
/// supplies the `&` the next body needs, so each round peels one level and the
/// value read is `sk-proj-…`.
fn nest(depth: usize) -> String {
    let mut out = String::from("&#65286;");
    for _ in 1..depth {
        out.push_str("#65286;");
    }
    out.push_str("#111;");
    out
}

/// A key whose escape is nested `depth` deep, and that key.
fn nested(depth: usize) -> (String, String) {
    let value = format!("sk-pr{}oj-abcdefghijklmnopqrstuvwx", nest(depth));
    (format!("key {value}"), value)
}

/// Nested past the pass cap, the value stays masked whole in both modes and
/// Private restores it: at the cap the composition fails closed.
#[test]
fn escapes_nested_past_the_pass_cap_stay_masked() {
    let (text, value) = nested(ROUNDS + 2);
    let at = text.find(&value).expect("value inside");
    for mode in MODES {
        let ranges = masked(mode, &text).expect("never refused");
        assert!(
            covered(&ranges, at, at + value.len()),
            "{mode:?} {text:?}: {ranges:?}"
        );
    }
    private_round_trip(&text);
}

/// The fastest of three gate runs over `unit` repeated `reps` times.
fn fastest(unit: &str, reps: usize) -> Duration {
    let text = unit.repeat(reps);
    (0..3)
        .map(|_| {
            let start = Instant::now();
            let _ = issue(PrivacyMode::Private, &text);
            start.elapsed()
        })
        .min()
        .expect("three runs")
}

/// The same nesting, one value per line at two sizes: the composition is a
/// fixed number of linear passes, so four times the text costs a small multiple
/// of four. A decode that rescanned its own output would make this quadratic.
#[test]
fn nested_escapes_stay_linear_in_the_text_size() {
    let (_, value) = nested(ROUNDS + 2);
    let (small, large) = (
        fastest(&format!("{value}\n"), 256),
        fastest(&format!("{value}\n"), 1_024),
    );
    let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-6);
    eprintln!("nested escapes, 256 -> 1024 values: {small:?} -> {large:?} ({ratio:.2}x)");
    assert!(ratio < 10.0, "{small:?} -> {large:?}");
}

/// Release only: text dense with entities a fold creates escapes from, at 4k,
/// 16k and 64k repeats. Bar: each 4x step costs under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test norm2_composition -- --ignored"]
fn dense_nested_escapes_scale_linearly() {
    let units = [
        format!("key sk-pr{}jklmnopqrstuvwx ", nest(3)),
        format!("I have di{}betes ", nest(4)),
        "di&#65286;#1072;b x\u{200B}y ".to_string(),
        "url https://example.invalid/?key=sk-pr\u{FF05}D0\u{FF05}BEj-abcdefghijklmnopqrstuvwx "
            .to_string(),
        // Round 1: a bracket a fold created, masked whole by the marker rule.
        "key x\u{FF06}#10214;sk-pr\u{FF06}#111;jklmnopqrstuvwx\u{FF06}#10215;y ".to_string(),
    ];
    for unit in units {
        let times: Vec<Duration> = [4_000, 16_000, 64_000]
            .map(|reps| fastest(&unit, reps))
            .to_vec();
        eprintln!("{unit:?}: {times:?}");
        for pair in times.windows(2) {
            let ratio = pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6);
            assert!(ratio < 6.0, "{unit:?}: {times:?}");
        }
    }
}

/// A fold composed into a decode must not reach prose: a Chinese or Cyrillic
/// line holds no value, so no byte of it may be masked.
#[test]
fn chinese_and_cyrillic_prose_stay_unchanged() {
    for text in ZH_PROSE
        .iter()
        .chain(CYRILLIC_PROSE)
        .chain(WIDE_AMPERSAND_PROSE)
    {
        for mode in MODES {
            assert_eq!(masked(mode, text), Some(Vec::new()), "{mode:?} {text:?}");
        }
    }
}

/// Chinese prose holding a full-width `＆` or `％` that opens no escape. The
/// round-1 fold reads `＆` and `％` as ASCII wherever they sit, and this is the
/// line that keeps it from reaching ordinary punctuation: the NORM-1
/// differential's "new Chinese masks 0" must stay 0.
const WIDE_AMPERSAND_PROSE: &[&str] = &[
    "预算增加１５％，库存＆物流都正常。",
    "会议改到下午３点，Ａ＆Ｂ两组都参加。",
    "ＣＰＵ占用率是８５％，内存还剩２ＧＢ。",
    "他说：“明天见！”然后就走了，＆其它人无关。",
];
