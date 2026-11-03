//! Linear-time guards: three 1 MiB adversarial inputs must finish quickly.
//!
//! The bound is 2 s in release and a generous 30 s in the debug test profile,
//! so a quadratic path still fails the gate without making CI flaky on a slow
//! shared machine.

use std::time::{Duration, Instant};

use kernel_privacy::{Anonymizer, Registry};

const MIB: usize = 1024 * 1024;

fn limit() -> Duration {
    if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(2)
    }
}

fn run(label: &str, text: &str) -> usize {
    let registry = Registry::new();
    let start = Instant::now();
    let spans = registry.analyze(text);
    let mut anonymizer = Anonymizer::new([0x44u8; 32]);
    let (_masked, _pairs) = anonymizer.anonymize(text, &spans);
    let elapsed = start.elapsed();
    assert!(
        elapsed < limit(),
        "{label}: took {elapsed:?}, limit {:?}",
        limit()
    );
    spans.len()
}

#[test]
fn unique_emails_scan_and_mask_linearly() {
    let mut text = String::with_capacity(MIB + 32);
    let mut index = 0usize;
    while text.len() < MIB {
        text.push_str(&format!("user{index}@example.invalid "));
        index += 1;
    }
    let spans = run("unique emails", &text);
    assert!(spans > 10_000, "only {spans} email spans found");
}

#[test]
fn long_alnum_run_before_ipv4_is_linear() {
    let mut text = "x".repeat(MIB);
    text.push_str(" 192.168.0.1");
    let spans = run("alnum run before ipv4", &text);
    assert!(spans >= 1, "no span found");
}

#[test]
fn repeated_parens_are_linear() {
    let text = "(".repeat(MIB);
    let spans = run("repeated parens", &text);
    assert_eq!(spans, 0, "a run of parens produced a span");
}

#[test]
fn adversarial_email_retry_is_linear() {
    // A long `a.` local-part run whose only candidate is rejected by the
    // trailing `¼` must be skipped whole, not one character at a time (P2-4).
    let mut text = "a.".repeat(200_000);
    text.push_str("a@example.com¼");
    let bound = if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(1)
    };
    let registry = Registry::new();
    let start = Instant::now();
    let _spans = registry.analyze(&text);
    let elapsed = start.elapsed();
    assert!(
        elapsed < bound,
        "adversarial email: took {elapsed:?}, limit {bound:?}"
    );
}

#[test]
fn adversarial_email_left_boundary_is_linear() {
    // Every address after the first is glued to the previous one by a `-`, so
    // its regex match starts on that separator, immediately after an
    // alphanumeric: the left boundary rejects it and only the retry finds it.
    // The old input (`-a` repeated then one `@x.invalid`) was accepted whole at
    // the left edge, so it never entered this path (P3 follow-up). Bound: 1 s
    // in release.
    let mut text = String::from("a");
    text.push_str(&"-a@x.invalid".repeat(100_000));
    let bound = if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(1)
    };
    let registry = Registry::new();
    let start = Instant::now();
    let spans = registry.analyze(&text);
    let elapsed = start.elapsed();
    assert!(
        elapsed < bound,
        "adversarial email left boundary: took {elapsed:?}, limit {bound:?}"
    );
    // The retry must find every address, so the path was actually driven.
    assert!(
        spans.len() >= 100_000,
        "left-boundary retry found only {} spans",
        spans.len()
    );
}

/// K-QUAD-RUN: repeated glued UK NI-number chains must stay linear in both
/// gate modes. Release only; best-of-three keeps scheduler noise out of ratios.
#[test]
#[ignore = "release-mode timing: run with --release --ignored"]
fn glued_uk_nino_chains_scale_linearly_in_both_modes() {
    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
    use kernel_privacy::Gate;

    fn input(unit: &str, bytes: usize) -> String {
        let mut text = String::with_capacity(bytes);
        while text.len() < bytes {
            text.push_str(unit);
        }
        text.truncate(bytes);
        text
    }

    fn gate(mode: PrivacyMode, text: &str) {
        let context = Context {
            destination: Destination::Vendor("hosted-model".to_string()),
        };
        let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
            panic!("chat is admitted in {mode:?}");
        };
        let _safe = Gate::for_grant(&grant, [0x44u8; 32])
            .text(text)
            .expect("issued");
    }

    let shapes = [
        ("NINO+next NINO", "ZK712849C9BM085263"),
        ("NINO+letter+NINO", "ZK712849CBM085263D9"),
        (
            "NINO+IBAN-ish tail",
            "ZK712849CM085263GB82WEST12345698765432",
        ),
    ];
    let sizes = [16 * 1024, 64 * 1024, 256 * 1024, MIB];
    for mode in [PrivacyMode::Open, PrivacyMode::Private] {
        for (label, unit) in shapes {
            let mut times = Vec::new();
            for size in sizes {
                let text = input(unit, size);
                let elapsed = (0..3)
                    .map(|_| {
                        let start = Instant::now();
                        gate(mode, &text);
                        start.elapsed()
                    })
                    .min()
                    .expect("three runs");
                println!("K-QUAD {label} {mode:?} {} KiB: {elapsed:?}", size / 1024);
                times.push(elapsed);
            }
            for pair in times.windows(2) {
                let ratio =
                    pair[1].as_secs_f64() / pair[0].max(Duration::from_micros(1)).as_secs_f64();
                assert!(
                    ratio <= 6.0,
                    "{label} {mode:?} grows super-linearly: x{ratio:.2} per x4 input"
                );
            }
        }
    }
}

/// A named input shape, built at a given repetition count.
type Shape = (&'static str, fn(usize) -> String);

/// The best of three registry runs over `text`.
fn best_of_three(text: &str) -> Duration {
    let registry = Registry::new();
    let run = || {
        let start = Instant::now();
        std::hint::black_box(registry.analyze(text));
        start.elapsed()
    };
    (0..3).map(|_| run()).min().unwrap()
}

/// FIN-6 r1: a list of hits must not make a second pass quadratic. Every new hit
/// used to check itself against every first-pass span with a linear scan, so 4x
/// the units cost up to 16x the time. The step starts at 16k units: at 4k a card
/// or NIR hit costs ten times more linearly, so only the NI list reads steep.
#[test]
#[ignore = "release perf bar: cargo test --release -- --ignored"]
fn fin6_hit_dense_lists_scale_linearly() {
    let mut steep = Vec::new();
    let shapes: [Shape; 3] = [
        ("nino list", |n| "AB 12 34 56 C, ".repeat(n)),
        ("card list", |n| "4539 1488 0343 6467, ".repeat(n)),
        // The one `"a  b"` is what turns the squeezed second pass on for the
        // whole text, so every NIR in the list pays the overlap check.
        ("nir list", |n| {
            format!("a  b{}", "1 84 12 76 451 089 46, ".repeat(n))
        }),
    ];
    for (name, shape) in shapes {
        let hits = Registry::new().analyze(&shape(64)).len();
        assert!(hits >= 64, "{name} is not hit-dense");
        let (small, large) = (best_of_three(&shape(16_000)), best_of_three(&shape(64_000)));
        let ratio = large.as_secs_f64() / small.max(Duration::from_millis(1)).as_secs_f64();
        eprintln!("scaling {name}: 16k {small:?} 64k {large:?} ratio {ratio:.2}");
        steep.extend((ratio >= 6.0).then_some(format!("{name} {ratio:.2}")));
    }
    assert!(steep.is_empty(), "not linear: {}", steep.join(", "));
}

/// The Standard dictionary with ten thousand known names: scanning one message
/// must stay under the brief's p95 bar (150 ms). Release only, like the other
/// timing guards.
#[test]
#[ignore = "release-mode timing: run with --release --ignored"]
fn ten_thousand_known_names_meet_the_p95_bar() {
    use kernel_privacy::{NameDictionary, Recognizer};

    let names: Vec<String> = (0..10_000)
        .map(|index| format!("Name{index} Surname{index}"))
        .collect();
    let dictionary = NameDictionary::new(&names).expect("dictionary");
    let text = "Bonjour Name42 Surname42, Name7 Surname7 et Name9999 Surname9999.";
    let mut samples = Vec::with_capacity(100);
    for _ in 0..100 {
        let start = Instant::now();
        let spans = dictionary.analyze(text);
        samples.push(start.elapsed());
        assert!(!spans.is_empty());
    }
    samples.sort();
    let p95 = samples[samples.len() * 95 / 100];
    assert!(
        p95 <= Duration::from_millis(150),
        "p95 over 10k names: {p95:?}"
    );
}

/// A gate per message over one 10k-name dictionary: a hundred gates must cost
/// under 50 ms in total, so the dictionary is compiled once, not per gate.
/// Release only.
#[test]
#[ignore = "release-mode timing: run with --release --ignored"]
fn hundred_gates_over_ten_thousand_names_stay_under_50_ms() {
    use std::sync::Arc;

    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
    use kernel_privacy::{Gate, NameDictionary};

    let names: Vec<String> = (0..10_000)
        .map(|index| format!("Name{index} Surname{index}"))
        .collect();
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &context) else {
        panic!("private chat is admitted");
    };
    let dictionary = Arc::new(NameDictionary::new(&names).expect("dictionary"));
    let start = Instant::now();
    for _ in 0..100 {
        let gate = Gate::for_grant_with_dictionary(&grant, [7u8; 32], Arc::clone(&dictionary));
        drop(gate);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed <= Duration::from_millis(50),
        "100 gates over 10k names: {elapsed:?}"
    );
}
