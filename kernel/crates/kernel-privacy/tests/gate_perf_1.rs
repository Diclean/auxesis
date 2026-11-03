//! GATE-PERF-1: the full gate stays linear on odd secret-table shapes.
//! Release only, like the other timing tests in `perf.rs`.

use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, Registry};

const KIB: usize = 1024;

/// The adversarial shapes: a fictional header, then one repeated unit.
const SHAPES: &[(&str, &str, &str)] = &[
    ("blank+row", "id,password,note\n", "\n17,Cherry6!,x\n"),
    ("header per line", "", "id,password,note\n"),
    ("blank+header", "", "\nid,password,note\n"),
    (
        "quoted break",
        "id,password,note\n",
        "17,\"ordered\nagain\",x\n",
    ),
    (
        "blank+prose",
        "id,password,note\n",
        "\nThe meeting moved to Tuesday.\n",
    ),
    ("trailing comma", "id,password,note\n", "17,Cherry6!,\n,,\n"),
    // The #319 seal B repro: 2x the blocks cost 3.5x the time on main.
    (
        "blank+name row",
        "id,password,city\n",
        "\nalice,hunter,oslo\n",
    ),
];

fn input(head: &str, unit: &str, bytes: usize) -> String {
    let mut text = String::with_capacity(bytes + unit.len());
    text.push_str(head);
    while text.len() < bytes {
        text.push_str(unit);
    }
    text
}

fn gate(mode: PrivacyMode, text: &str) -> String {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
        panic!("chat is admitted in {mode:?}");
    };
    let (safe, _report) = Gate::for_grant(&grant, [0x44u8; 32])
        .text(text)
        .expect("issued");
    safe.as_str().to_string()
}

fn best_of_three(run: impl Fn()) -> Duration {
    (0..3)
        .map(|_| {
            let start = Instant::now();
            run();
            start.elapsed()
        })
        .min()
        .expect("three runs")
}

/// Prints the stage times: the registry alone, then the gate in each mode.
#[test]
#[ignore = "release-mode timing: run with --release --ignored"]
fn bench_gate_secret_table_shapes() {
    let registry = Registry::new();
    for (label, head, unit) in SHAPES {
        for size in [64 * KIB, 128 * KIB, 256 * KIB, 512 * KIB] {
            let text = input(head, unit, size);
            let analyze = best_of_three(|| {
                std::hint::black_box(registry.analyze(&text));
            });
            let open = best_of_three(|| {
                std::hint::black_box(gate(PrivacyMode::Open, &text));
            });
            let private = best_of_three(|| {
                std::hint::black_box(gate(PrivacyMode::Private, &text));
            });
            println!(
                "GATE-PERF {label} {} KiB: analyze {analyze:?} open {open:?} private {private:?}",
                size / KIB
            );
        }
    }
}

/// The guard: 8x the input costs at most 12x the time, on every shape and in
/// both modes. On main the e-mail layer split the whole text once per line, so
/// 8x the bytes cost about 50x.
#[test]
#[ignore = "release-mode timing: run with --release --ignored"]
fn gate_scales_linearly_on_secret_table_shapes() {
    let mut steep = Vec::new();
    for mode in [PrivacyMode::Open, PrivacyMode::Private] {
        for (label, head, unit) in SHAPES {
            let small = input(head, unit, 64 * KIB);
            let large = input(head, unit, 512 * KIB);
            let small_time = best_of_three(|| {
                std::hint::black_box(gate(mode, &small));
            });
            let large_time = best_of_three(|| {
                std::hint::black_box(gate(mode, &large));
            });
            let ratio =
                large_time.as_secs_f64() / small_time.max(Duration::from_millis(1)).as_secs_f64();
            println!("GATE-PERF {label} {mode:?}: 64 KiB {small_time:?} 512 KiB {large_time:?} x{ratio:.2}");
            if ratio > 12.0 {
                steep.push(format!("{label} {mode:?} x{ratio:.2}"));
            }
        }
    }
    assert!(steep.is_empty(), "super-linear per x8 input: {steep:?}");
}
