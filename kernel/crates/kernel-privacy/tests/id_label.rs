//! ID-LABEL acceptance: national IDs are `NATIONAL_ID` in both modes — the FR
//! carte nationale d'identité and permis de conduire after their labels, a UK
//! driving licence by its structure, a DE Personalausweis, a CN passport, a tax
//! number after `Tax ID` / `TIN` / `numéro fiscal`, and an ID inside a file name
//! (`scan_passport_L898902C3.pdf`). Lookalikes keep exactly main's masks, and
//! the head is a strict byte superset of main on a seeded differential frozen
//! from origin/main in `data/id_label_main.txt` (`-- --ignored freeze
//! --nocapture`, on main only).
//!
//! Every mask is read with the exact reader of `data/exact_mask.rs`: a token
//! covers the surface the gate minted for it, a marker the range the Open
//! detector removed, and an output that does not read back exactly fails. All
//! values are invented.

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
#[allow(dead_code)]
mod exact {
    include!("data/exact_mask.rs");
}
#[allow(dead_code)]
mod cases {
    include!("data/id_label_cases.rs");
}
use cases::*;
use norm1::{covered, issue, MODES};

/// Masked byte ranges, `start..end`.
type Ranges = Vec<(usize, usize)>;

const FIXTURE: &str = include_str!("data/id_label_main.txt");

/// The exact ranges the gate masks in `text`, or `None` for a refusal. An
/// output that does not align exactly panics: it never passes.
fn masked(mode: PrivacyMode, text: &str) -> Option<Vec<(usize, usize)>> {
    let (output, minted) = issue(mode, text)?;
    Some(exact::exact_or_fail(mode, text, &output, &minted))
}

/// `output` with each minted token replaced by its surface.
fn restore(output: &str, minted: &[(String, String)]) -> String {
    let mut restored = output.to_string();
    for (token, surface) in minted {
        restored = restored.replace(&format!("⟦{token}⟧"), surface);
    }
    restored
}

/// Every positive: each value byte hidden in both modes as an ID (Open writes
/// `[id removed]`, Private an ID token; an IBAN marker where an IBAN candidate
/// inside the value outranks it), and Private restores the text exactly.
#[test]
fn labelled_ids_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, value) in POSITIVES {
        let start = text.find(value).expect("the value is in its text");
        for mode in MODES {
            let Some((output, minted)) = issue(mode, text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            let Some(ranges) = exact::exact_ranges(mode, text, &output, &minted) else {
                wrong.push(format!("{mode:?} unaligned {text:?} -> {output:?}"));
                continue;
            };
            // An IBAN candidate inside a licence outranks the ID when they merge
            // (`mask_priority`): the whole value is still one masked region.
            let markers = match mode {
                PrivacyMode::Private => ["⟦NATIONAL_ID_", "⟦IBAN_"],
                _ => ["[id removed]", "[iban removed]"],
            };
            let marked = markers.iter().any(|m| output.contains(m));
            if !covered(&ranges, start, start + value.len()) || !marked {
                wrong.push(format!("{mode:?} {text:?} -> {output:?}"));
            }
            if mode == PrivacyMode::Private && restore(&output, &minted) != *text {
                wrong.push(format!("restore {text:?} -> {output:?}"));
            }
        }
    }
    assert!(POSITIVES.len() >= 40, "40+ positives");
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

/// The frozen main records, one `[private, open]` pair per input.
fn main_records(inputs: &[(String, Ranges)]) -> Vec<[Option<Ranges>; 2]> {
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    records
        .iter()
        .map(|record| {
            let mut modes = record.split('|').map(parse);
            [modes.next().expect("private"), modes.next().expect("open")]
        })
        .collect()
}

/// Lookalikes: in both modes the exact masks equal main's — no new mask, none
/// lost, no refusal.
#[test]
fn lookalikes_keep_main_masks() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let mut wrong = Vec::new();
    for ((text, _), main) in inputs.iter().zip(&main) {
        if !NEGATIVES.contains(&text.as_str()) {
            continue;
        }
        for (index, mode) in MODES.into_iter().enumerate() {
            let now = masked(mode, text);
            // Postal addresses are now prohibited in Open mode as well. These
            // two existing ID negatives already classify as addresses in
            // Private mode; their matching Open address spans are intentional.
            let address_negative = match text.as_str() {
                "75008 Paris, France" => Some(vec![(0, 11)]),
                "Postcode SW1A 1AA, London" => Some(vec![(0, 17)]),
                _ => None,
            };
            let expected = if mode == PrivacyMode::Open {
                address_negative.or_else(|| main[index].clone())
            } else {
                main[index].clone()
            };
            if now != expected {
                let output = issue(mode, text).map(|(o, _)| o);
                wrong.push(format!(
                    "{mode:?} {text:?}: main {:?} -> {output:?}",
                    expected
                ));
            }
        }
    }
    assert!(NEGATIVES.len() >= 40, "40+ negatives");
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A strict byte superset of main in both modes and no new refusal, with no
/// allowance; and every seeded ID hidden in both modes.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let main = main_records(&inputs);
    let (mut lost, mut refused, mut gained, mut missed) = ([0usize; 2], 0, [0usize; 2], 0);
    for ((text, values), main) in inputs.iter().zip(main) {
        for (index, main) in main.into_iter().enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += usize::from(main.is_some());
                eprintln!("refused {:?} {text:?}", MODES[index]);
                continue;
            };
            let main = main.unwrap_or_default();
            let gone = main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&b| !covered(&now, b, b + 1))
                .count();
            if gone > 0 {
                eprintln!("{:?} {text:?}: main {main:?} -> {now:?}", MODES[index]);
            }
            lost[index] += gone;
            gained[index] += usize::from(now != main);
            if values.iter().any(|&(s, e)| !covered(&now, s, e)) {
                missed += 1;
                eprintln!("missed {:?} in {text:?} -> {now:?}", MODES[index]);
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; texts with \
         new masks Private/Open {gained:?}; ID values missed {missed}",
        inputs.len()
    );
    assert!(inputs.len() >= 1500 + 80);
    assert_eq!((lost, refused, missed), ([0, 0], 0, 0));
}

/// Release only: dense ID text (labels, licences, file names and lookalikes) at
/// 16 KiB, 64 KiB, 256 KiB and 1 MiB. Bar: each 4x step under 6x.
#[test]
#[ignore = "release timing: cargo test --release --test id_label -- --ignored timing"]
fn timing_scales_linearly() {
    let unit = "CNI : X4RTBT9M2, permis n° 12AB34567; licence MORGA753116SM9IJ SKU \
                SMITH802115J99RT scan_passport_L898902C3.pdf passport_20240301.pdf \
                a tax ID of 98-2316704 Ausweis-Nr. T220001293 order_A7K29Q4M1.pdf\n";
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
    eprintln!("id label text: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
