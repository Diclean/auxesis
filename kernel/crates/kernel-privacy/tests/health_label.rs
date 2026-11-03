//! HEALTH-LABEL acceptance: a labelled health number (`MRN`, `medical record
//! number`, `health plan beneficiary number`, `patient ID`, `NHS number`, a
//! `member ID` by a health word, `numéro de dossier médical`) and a labelled
//! blood group (`blood type AB-`, `groupe sanguin O Rh+`) are HEALTH in both
//! modes; lookalikes stay clear; and the head is a strict byte superset of main
//! on a seeded differential, frozen from origin/main in
//! `data/health_label_main.txt` (`-- --ignored freeze --nocapture`, on main only).
//! All values are invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;
use kernel_privacy::recognizers::label_value::LabelValueRecognizer;
use kernel_privacy::{EntityKind, Recognizer};

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
#[allow(dead_code)]
mod cases {
    include!("data/health_label_cases.rs");
}
use cases::*;
use norm1::{covered, issue, masked, MODES};

const FIXTURE: &str = include_str!("data/health_label_main.txt");

/// `output` with each minted token replaced by its surface.
fn restore(output: &str, minted: &[(String, String)]) -> String {
    let mut restored = output.to_string();
    for (token, surface) in minted {
        restored = restored.replace(&format!("⟦{token}⟧"), surface);
    }
    restored
}

/// Every positive: each value byte hidden in both modes, and Private restores
/// the text exactly. Open removes only prohibited classes, so a value it hides
/// is HEALTH, or an ID when an ID rule on main already claimed it (that kind is
/// kept: the label rule adds masks, it never relabels).
#[test]
fn labelled_health_values_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, value) in POSITIVES {
        let start = text.find(value).expect("the value is in its text");
        for mode in MODES {
            let Some((output, minted)) = issue(mode, text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            let ranges = match norm1::exact_ranges(mode, text, &output, &minted) {
                Some(ranges) => ranges,
                None => {
                    wrong.push(format!("{mode:?} {text:?} -> {output:?}: no exact reading"));
                    continue;
                }
            };
            let marker = match mode {
                PrivacyMode::Private => ["⟦HEALTH_", "⟦NATIONAL_ID_", "⟦UK_NINO_"],
                _ => ["[health removed]", "[id removed]", "[id removed]"],
            };
            let hidden = covered(&ranges, start, start + value.len());
            if !hidden || !marker.iter().any(|m| output.contains(m)) {
                wrong.push(format!("{mode:?} {text:?} -> {output:?}"));
            }
            if mode == PrivacyMode::Private && restore(&output, &minted) != *text {
                wrong.push(format!("restore {text:?} -> {output:?}"));
            }
        }
    }
    assert!(POSITIVES.len() >= 30, "30+ positives");
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// `n° de sécurité sociale` and its forms: hidden in both modes and never
/// relabelled HEALTH (the ID kind stays).
#[test]
fn french_social_security_labels_keep_the_id_kind() {
    for (text, value) in FR_SOCIAL {
        let start = text.find(value).expect("the value is in its text");
        for mode in MODES {
            let (output, minted) = issue(mode, text).expect("issued");
            let ranges = norm1::exact_ranges(mode, text, &output, &minted)
                .unwrap_or_else(|| panic!("{mode:?} {text:?} -> {output:?}: no exact reading"));
            assert!(
                covered(&ranges, start, start + value.len()),
                "{mode:?} {text:?} -> {output:?}"
            );
            assert!(
                !output.contains("HEALTH") && !output.contains("health"),
                "{output:?}"
            );
            if mode == PrivacyMode::Private {
                assert_eq!(restore(&output, &minted), *text, "{output:?}");
            }
        }
    }
}

/// Lookalikes: no health marker in Open, no health token in Private, and no
/// HEALTH span from the label rule.
#[test]
fn lookalikes_stay_clear() {
    let mut wrong = Vec::new();
    for text in NEGATIVES {
        let open = issue(PrivacyMode::Open, text).map(|(o, _)| o);
        let private = issue(PrivacyMode::Private, text).map(|(o, _)| o);
        let health = LabelValueRecognizer::new()
            .analyze(text)
            .iter()
            .any(|span| span.kind == EntityKind::Health);
        if open
            .as_deref()
            .is_none_or(|o| o.contains("[health removed]"))
            || private.as_deref().is_none_or(|p| p.contains("HEALTH"))
            || health
        {
            wrong.push(format!("{text:?}: open {open:?} private {private:?}"));
        }
    }
    assert!(NEGATIVES.len() >= 30, "30+ negatives");
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The differential inputs: the seeded texts, then every case above, then the
/// in-repo privacy-eval cases and prose lines.
fn inputs() -> Vec<(String, Vec<(usize, usize)>)> {
    let mut rng = Rng(SEED);
    let mut out: Vec<_> = (0..DIFFERENTIAL_TEXTS)
        .map(|_| differential_text(&mut rng))
        .collect();
    let at = |text: &str, value: &str| {
        let start = text.find(value).expect("value");
        vec![(start, start + value.len())]
    };
    out.extend(POSITIVES.iter().map(|(t, v)| (t.to_string(), at(t, v))));
    out.extend(FR_SOCIAL.iter().map(|(t, v)| (t.to_string(), at(t, v))));
    out.extend(NEGATIVES.iter().map(|t| (t.to_string(), Vec::new())));
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    for dir in ["cases", "prose"] {
        let mut files: Vec<_> = std::fs::read_dir(format!("{root}/{dir}"))
            .expect("privacy-eval is readable")
            .map(|entry| entry.expect("entry").path())
            .collect();
        files.sort();
        for file in files {
            let raw = std::fs::read_to_string(file).expect("readable");
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                let text = if dir == "prose" {
                    line.to_string()
                } else {
                    let case: serde_json::Value = serde_json::from_str(line).expect("JSON");
                    case["text"].as_str().expect("text").to_string()
                };
                out.push((text, Vec::new()));
            }
        }
    }
    out
}

/// One record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    let join = |r: Vec<(usize, usize)>| r.iter().map(|(s, e)| format!("{s}-{e},")).collect();
    ranges.map_or("!".into(), join)
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[(String, Vec<(usize, usize)>)]) -> String {
    let bytes = inputs.iter().flat_map(|(text, _)| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = inputs();
    let record = |text: &String| MODES.map(|mode| record(masked(mode, text))).join("|");
    let records: Vec<String> = inputs.iter().map(|(text, _)| record(text)).collect();
    let lines: Vec<String> = records.chunks(100).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// A strict byte superset of main in both modes and no new refusal, with no
/// allowance; and every seeded health value hidden in both modes.
///
/// The ranges are the exact alignment (`norm1::exact_ranges`): every token
/// stands for the surface the gate minted, every Open marker for the detector's
/// own removed range, so there is one reading per text and a text that has none
/// fails here (TEST-FITS-EXACT; the leaks the old any-reading helper passed are
/// pinned in `exact_mask_alignment.rs`).
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut gained, mut missed) = ([0usize; 2], 0, [0usize; 2], 0);
    for ((text, values), record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let Some((output, minted)) = issue(MODES[index], text) else {
                refused += usize::from(main.is_some());
                eprintln!("refused {:?} {text:?}", MODES[index]);
                continue;
            };
            let Some(now) = norm1::exact_ranges(MODES[index], text, &output, &minted) else {
                panic!(
                    "{:?} {text:?} -> {output:?}: no exact reading",
                    MODES[index]
                );
            };
            let main = main.unwrap_or_default();
            let gone = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                eprintln!("{:?} {text:?}: main {main:?} now {now:?}", MODES[index]);
            }
            lost[index] += gone;
            gained[index] += usize::from(now != main);
            let missing = values.iter().filter(|&&(s, e)| !covered(&now, s, e));
            if missing.count() > 0 {
                missed += 1;
                eprintln!("missed {:?} in {text:?} -> {output:?}", MODES[index]);
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; texts with \
         new masks Private/Open {gained:?}; health values missed {missed}",
        inputs.len()
    );
    assert!(inputs.len() >= 1500 + 30);
    assert_eq!((lost, refused, missed), ([0, 0], 0, 0));
}

/// Release only: dense label text (every label class, values and lookalikes)
/// at 16 KiB, 64 KiB, 256 KiB and 1 MiB. Bar: each 4x step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test health_label -- --ignored timing"]
fn timing_scales_linearly() {
    let unit = "MRN: 7730-41925. Blood type: AB-. a blood type of O+, member ID 88412-0093 \
                at the clinic; gym member ID 4412; numéro de dossier médical DM-2024-77812\n";
    let time = |bytes: usize| {
        let text = unit.repeat(bytes / unit.len());
        (0..3)
            .map(|_| {
                let start = Instant::now();
                let _ = issue(PrivacyMode::Private, &text);
                let _ = issue(PrivacyMode::Open, &text);
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let times: Vec<Duration> = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
        .map(time)
        .to_vec();
    eprintln!("health label text: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
