//! NORM-1 differential: every input runs through `Gate::for_grant` in Private
//! and Open against `data/norm1_main.txt`, frozen from origin/main. No byte main
//! masks may be left clear, no text may be refused, and no prose line (AF, HU,
//! SL, Chinese, Cyrillic) may gain a mask. New masks on the Chinese eval cases
//! are printed for review. Refreeze on main only: `cargo test -p kernel-privacy
//! --test norm1_superset -- --ignored freeze --nocapture`. The 4,000 public
//! texts are not in the repo: `public_corpus_differential` freezes main to
//! `NORM1_PUBLIC_MAIN` when `NORM1_PUBLIC_FREEZE=1`, and compares otherwise.
//! All values are invented.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}
#[allow(dead_code)]
mod tail4 {
    include!("data/secret_tail4_cases.rs");

    pub fn texts() -> Vec<String> {
        let fixed = [CASES, PR1B_CASES, PR2_CASES].into_iter().flatten();
        let fixed = fixed.map(|case| case.1.to_string());
        fixed
            .chain(built_cases().into_iter().map(|case| case.1))
            .collect()
    }
}
use cases::{covered, exact_ranges, issue, masked, repros, CYRILLIC_PROSE, MODES, ZH_PROSE};
use kernel_privacy::EntityKind;

const FIXTURE: &str = include_str!("data/norm1_main.txt");

/// Every input, in a fixed order, with its kind: the privacy-eval cases (`zh`
/// for the Chinese ones), the AF/HU/SL prose, the secret-tail cases, the NORM-1
/// repros in three frames and the Chinese and Cyrillic prose.
fn inputs() -> Vec<(&'static str, String)> {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    let read = |path: String| std::fs::read_to_string(path).unwrap();
    let mut files: Vec<_> = std::fs::read_dir(format!("{root}/cases"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let kind = if file.to_string_lossy().ends_with("zh.jsonl") {
            "zh"
        } else {
            "eval"
        };
        for line in read(file.display().to_string())
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            out.push((kind, case["text"].as_str().unwrap().to_string()));
        }
    }
    for lang in ["af", "hu", "sl"] {
        let prose = read(format!("{root}/prose/{lang}.txt"));
        out.extend(
            prose
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| ("prose", l.into())),
        );
    }
    out.extend(tail4::texts().into_iter().map(|text| ("tail4", text)));
    for (text, _, _) in repros() {
        for (pre, post) in [("", ""), ("Hi,\n", " thanks."), ("« ", " »\r\n")] {
            out.push(("repro", format!("{pre}{text}{post}")));
        }
    }
    out.extend(
        ZH_PROSE
            .iter()
            .chain(CYRILLIC_PROSE)
            .map(|t| ("prose", t.to_string())),
    );
    out
}

/// One record per mode: `start-end` ranges joined by `,`; `!` is a refusal.
fn record(ranges: Option<Vec<(usize, usize)>>) -> String {
    ranges.map_or("!".into(), |r| {
        r.iter()
            .map(|(s, e)| format!("{s}-{e}"))
            .collect::<Vec<_>>()
            .join(",")
    })
}

fn parse(record: &str) -> Option<Vec<(usize, usize)>> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    (record != "!").then(|| record.split(',').filter_map(range).collect())
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[(&str, String)]) -> String {
    let bytes = inputs.iter().flat_map(|(_, text)| text.bytes().chain([0]));
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
    let records: Vec<String> = inputs.iter().map(|(_, text)| record(text)).collect();
    let lines: Vec<String> = records.chunks(100).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// Bytes `now` leaves clear that `main` masked.
fn lost(main: &[(usize, usize)], now: &[(usize, usize)]) -> usize {
    main.iter()
        .flat_map(|&(s, e)| s..e)
        .filter(|&b| !covered(now, b, b + 1))
        .count()
}

/// Bytes `now` masks that `main` left clear.
fn gained(main: &[(usize, usize)], now: &[(usize, usize)]) -> usize {
    now.iter()
        .flat_map(|&(s, e)| s..e)
        .filter(|&b| !covered(main, b, b + 1))
        .count()
}

/// Rules: a strict byte superset of main in both modes, no new refusal, no new
/// mask on a prose line; new masks on the Chinese cases are printed.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut bytes_lost, mut refused, mut prose, mut zh) = ([0usize; 2], 0, 0, [0usize; 2]);
    for ((kind, text), record) in inputs.iter().zip(records) {
        for (index, main) in record.split('|').map(parse).enumerate() {
            let Some(now) = masked(MODES[index], text) else {
                refused += 1;
                continue;
            };
            let main = main.unwrap_or_default();
            let (gone, new) = (lost(&main, &now), gained(&main, &now));
            bytes_lost[index] += gone;
            prose += usize::from(*kind == "prose" && new > 0);
            zh[index] += usize::from(*kind == "zh" && new > 0);
            if gone > 0 || (new > 0 && matches!(*kind, "prose" | "zh")) {
                eprintln!(
                    "{kind} {:?} {text:?}: main {main:?} now {now:?}",
                    MODES[index]
                );
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {bytes_lost:?}; refusals {refused}; prose lines \
         changed {prose}; zh cases with a new mask Private/Open {zh:?}",
        inputs.len()
    );
    assert_eq!((bytes_lost, refused, prose), ([0, 0], 0, 0));
}

/// Plain ASCII carrying no escape: only a new address or health-term range
/// may join main; all other ranges and token identities stay fixed.
#[test]
fn plain_ascii_inputs_read_exactly_as_main() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').unwrap();
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    let mut compared = 0;
    let mut changed = Vec::new();
    for ((_, text), record) in inputs.iter().zip(records) {
        if !text.is_ascii() || text.contains(['&', '%']) {
            continue;
        }
        for (index, main) in record.split('|').map(parse).enumerate() {
            compared += 1;
            let now = masked(MODES[index], text);
            let retained = main.is_none() == now.is_none()
                && main
                    .as_ref()
                    .zip(now.as_ref())
                    .is_none_or(|(main, now)| only_new_address_or_health(text, main, now));
            if !retained {
                changed.push(format!(
                    "{:?} {text:?}: main {main:?} now {now:?}",
                    MODES[index]
                ));
            }
        }
    }
    eprintln!(
        "{compared} plain ASCII runs, {} not exactly as main",
        changed.len()
    );
    assert!(changed.is_empty(), "{changed:#?}");
}

/// Whether now retains main and adds bytes only inside an address, health or
/// labelled date-of-birth span (OCR-KERNEL-1).
fn only_new_address_or_health(text: &str, main: &[(usize, usize)], now: &[(usize, usize)]) -> bool {
    let allowed: Vec<_> =
        kernel_privacy::safetext::Detector::detect(&kernel_privacy::StandardDetector::new(), text)
            .unwrap()
            .into_iter()
            .filter(|span| {
                matches!(
                    span.kind,
                    EntityKind::Address | EntityKind::Health | EntityKind::DateOfBirth
                )
            })
            .collect();
    let covered = |byte: usize, ranges: &[(usize, usize)]| {
        ranges
            .iter()
            .any(|&(start, end)| start <= byte && byte < end)
    };
    let keeps_main = main
        .iter()
        .flat_map(|&(start, end)| start..end)
        .all(|byte| covered(byte, now));
    let added_allowed = now
        .iter()
        .flat_map(|&(start, end)| start..end)
        .filter(|&byte| !covered(byte, main))
        .all(|byte| {
            allowed
                .iter()
                .any(|span| span.start <= byte && byte < span.end)
        });
    keeps_main && added_allowed
}

/// The same rules on the 4,000 public synthetic texts (Nemotron-PII + Gretel,
/// not in the repo). `NORM1_PUBLIC_DIR` holds the JSONL files; with
/// `NORM1_PUBLIC_FREEZE=1` main's outputs go to `NORM1_PUBLIC_MAIN`, otherwise
/// they are compared.
///
/// Both sides are read exactly (`data/exact_mask.rs`): ours from the tokens this
/// run minted, main's from the tokens this run minted too — main's own minted
/// pairs are not in the frozen file, and a token name is one value, so a reading
/// that restores main's output onto the input is the only one there is. A text
/// with no exact reading on either side fails the test, counted as `unreadable`
/// (TEST-FITS-EXACT: an unreadable text is never a pass).
///
/// So reading main's output with *this* run's `minted` is not a second reading
/// and not a pass by default: when a token name differs from the one main minted,
/// the Private side has no minted surface for it and this gate minted no such
/// name, so the detector-span fallback does not apply either and the reader
/// gives `None`. `unreadable` is asserted to be 0, so that case is a red, never
/// a silent skip.
#[test]
#[ignore = "public corpus: NORM1_PUBLIC_DIR=<dir> NORM1_PUBLIC_MAIN=<file> -- --ignored public"]
fn public_corpus_differential() {
    let (Ok(dir), Ok(main_path)) = (
        std::env::var("NORM1_PUBLIC_DIR"),
        std::env::var("NORM1_PUBLIC_MAIN"),
    ) else {
        return;
    };
    let mut texts = Vec::new();
    for name in ["gretel-pii.jsonl", "nemotron-pii.jsonl"] {
        for line in std::fs::read_to_string(format!("{dir}/{name}"))
            .unwrap()
            .lines()
        {
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            texts.push(case["text"].as_str().unwrap().to_string());
        }
    }
    let run = |text: &str| MODES.map(|mode| issue(mode, text));
    if std::env::var("NORM1_PUBLIC_FREEZE").is_ok() {
        let out: Vec<String> = texts
            .iter()
            .map(|t| {
                let run = run(t);
                let outputs: Vec<Option<&str>> = run
                    .iter()
                    .map(|run| run.as_ref().map(|(out, _)| out.as_str()))
                    .collect();
                serde_json::to_string(&outputs).unwrap()
            })
            .collect();
        std::fs::write(&main_path, out.join("\n")).unwrap();
        return;
    }
    let raw = std::fs::read_to_string(&main_path).unwrap();
    let main: Vec<[Option<String>; 2]> = raw
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(main.len(), texts.len());
    let (mut bytes_lost, mut refused, mut changed, mut unreadable) = (0, 0, 0, 0);
    for (text, main) in texts.iter().zip(&main) {
        let ours = run(text);
        let same = main
            .iter()
            .zip(&ours)
            .all(|(main, ours)| ours.as_ref().map(|(out, _)| out) == main.as_ref());
        if same {
            continue;
        }
        changed += 1;
        for (index, (main, ours)) in main.iter().zip(&ours).enumerate() {
            let (Some(main), Some((ours, minted))) = (main, ours) else {
                refused += usize::from(ours.is_none());
                continue;
            };
            let mode = MODES[index];
            match (
                exact_ranges(mode, text, ours, minted),
                exact_ranges(mode, text, main, minted),
            ) {
                (Some(ours), Some(main)) => bytes_lost += lost(&main, &ours),
                _ => {
                    unreadable += 1;
                    eprintln!("unreadable {:?} {text:.80?}", mode);
                }
            }
        }
    }
    eprintln!(
        "{} public texts: changed {changed}, bytes lost {bytes_lost}, refusals {refused}, \
         unreadable {unreadable}",
        texts.len()
    );
    assert_eq!((bytes_lost, refused, unreadable), (0, 0, 0));
}
