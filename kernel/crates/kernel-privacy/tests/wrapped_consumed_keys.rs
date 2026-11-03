//! K-WRAP-CONSUMED: a key body wrapped across lines after an earlier consumed
//! glued run stays masked over its complete original byte span in both modes.

use std::time::Instant;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, exact_ranges, issue, MODES};

fn cases() -> Vec<(String, String)> {
    let deepseek_body = ["c144b535780a43", "2f0aab98a3", "d3d161dc"].concat();
    let openrouter_body = [
        "69ca4cc8deddc2",
        "f903d6b03040e",
        "01507b5519b4740a",
        "d5e77cdcc584584c",
        "88119",
    ]
    .concat();
    let deepseek = format!("sk-{deepseek_body}");
    let openrouter = format!("sk-or-v1-{openrouter_body}");
    let mut out = Vec::new();
    for key in [&deepseek, &openrouter] {
        for br in ["\n", "\r\n"] {
            for at in [3, 8, key.len() / 2, key.len() - 3] {
                let text = format!("high-risk-{br}note{}{br}{}!", &key[..at], &key[at..]);
                out.push((text, key.clone()));
            }
        }
    }
    out.push((
        format!(
            "high-risk-\nnotesk-{}\n{}!",
            &deepseek_body[..14],
            &deepseek_body[14..]
        ),
        deepseek,
    ));
    out.push((
        format!(
            "high-risk-\nnotesk-or-v1-{}\n{}!",
            &openrouter_body[..29],
            &openrouter_body[29..]
        ),
        openrouter,
    ));
    let adjacent = out
        .iter()
        .take(2)
        .map(|(text, key)| (format!("🙂{text}界"), key.clone()))
        .collect::<Vec<_>>();
    out.extend(adjacent);
    out
}

#[test]
fn wrapped_keys_after_consumed_runs_are_fully_masked_in_both_modes() {
    for (text, key) in cases() {
        let start = text.find("notesk").expect("glued run") + "note".len();
        // Include the physical line break(s) within the key's original span.
        let end = start + key.len() + if text.contains("\r\n") { 2 } else { 1 };
        for mode in MODES {
            let (output, minted) = issue(mode, &text).expect("gate must not refuse");
            let ranges = exact_ranges(mode, &text, &output, &minted).expect("exact alignment");
            assert!(
                covered(&ranges, start, end),
                "{mode:?} did not cover {start}..{end}: {text:?} -> {ranges:?}"
            );
        }
    }
}

/// Release only: each 4x input-size step must take no more than 6x as long.
#[test]
#[ignore = "release timing: cargo test --release --test wrapped_consumed_keys -- --ignored scales --nocapture"]
fn wrapped_consumed_scales_linearly() {
    let unit = "high-risk-\nnotesk-c144b535780a43\n2f0aab98a3d3d161dc!\n";
    let mut previous = [0u128; 2];
    for size in [16 * 1024, 64 * 1024, 256 * 1024] {
        let text = unit.repeat(size / unit.len());
        let mut elapsed = [0u128; 2];
        for (index, mode) in MODES.into_iter().enumerate() {
            let mut best = u128::MAX;
            for _ in 0..3 {
                let start = Instant::now();
                let (output, minted) = issue(mode, &text).expect("gate must not refuse");
                assert!(exact_ranges(mode, &text, &output, &minted).is_some());
                best = best.min(start.elapsed().as_micros());
            }
            elapsed[index] = best;
            if previous[index] > 0 {
                assert!(
                    best <= previous[index] * 6,
                    "{mode:?} {size} bytes: {best}us after {}us",
                    previous[index]
                );
            }
        }
        eprintln!("{size} bytes: Private/Open {elapsed:?} us");
        previous = elapsed;
    }
}
