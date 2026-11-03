//! UK VAT grouping and chained NINO acceptance, with an exact main baseline.

use kernel_core::privacy::PrivacyMode;
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod exact {
    include!("data/exact_mask.rs");
}

#[allow(dead_code)]
mod helpers {
    include!("data/norm1_cases.rs");
}

use helpers::{covered, issue, MODES};

const FIXTURE: &str = include_str!("data/uk_id_gaps_main.txt");
const POSITIVES: &[(&str, &str)] = &[
    ("GB 123 4567 82", "GB 123 4567 82"),
    ("GB123 4567 82", "GB123 4567 82"),
    ("VAT reg no. 123 4567 82", "123 4567 82"),
    ("VAT: GB 123 4567 82 000", "GB 123 4567 82 000"),
    ("VAT: GB 123 4567 82 001", "GB 123 4567 82 001"),
    ("GBGD001", "GBGD001"),
    ("GBHA500", "GBHA500"),
    (
        "VAT reg no. 123\u{00a0}4567\u{00a0}82",
        "123\u{00a0}4567\u{00a0}82",
    ),
    (
        "GB\u{2009}123\u{2009}4567\u{2009}82",
        "GB\u{2009}123\u{2009}4567\u{2009}82",
    ),
    ("AB 12 34 56\nBAB123456B", "AB 12 34 56\nBAB123456B"),
];

const LABELLED_POSITIVES: &[(&str, &str)] = &[
    ("VAT reg no.: GB 123 4567 89", "GB 123 4567 89"),
    ("gb 123 4567 82", "gb 123 4567 82"),
    ("TVA intracom.,123 4567 82", "123 4567 82"),
    ("n° TVA 123 4567 89", "123 4567 89"),
    ("VAT no. 123 4567 89", "123 4567 89"),
    ("VAT number 123 4567 89", "123 4567 89"),
];

/// K-VAT-DASH and K-VAT-GBSPACE acceptance cases. Each expected value is the
/// exact source range to replace; wrappers exercise punctuation and line edges.
const NEW_POSITIVES: &[(&str, &str)] = &[
    ("VAT 123-4567-89", "123-4567-89"),
    ("vAt No: 123-4567-89", "123-4567-89"),
    ("VAT NUMBER: 123-4567-89", "123-4567-89"),
    ("tVa: 123-4567-89", "123-4567-89"),
    ("TVA intracom.: 123-4567-89", "123-4567-89"),
    ("N° TVA: 123-4567-89", "123-4567-89"),
    ("VAT: GB 123-4567-89", "GB 123-4567-89"),
    ("VAT no: gb123-4567-89", "gb123-4567-89"),
    ("GB GD001", "GB GD001"),
    ("GB HA500", "GB HA500"),
    ("VAT GB GD 001", "GB GD 001"),
    ("!VAT 123-4567-89?", "123-4567-89"),
    ("\nVAT 123-4567-89\n", "123-4567-89"),
    ("!VAT: GB 123-4567-89?", "GB 123-4567-89"),
    ("\nVAT: GB 123-4567-89\n", "GB 123-4567-89"),
    ("!VAT no: gb123-4567-89?", "gb123-4567-89"),
    ("\nVAT no: gb123-4567-89\n", "gb123-4567-89"),
    ("!GB GD001?", "GB GD001"),
    ("\nGB GD001\n", "GB GD001"),
    ("!GB HA500?", "GB HA500"),
    ("\nGB HA500\n", "GB HA500"),
    ("!VAT GB GD 001?", "GB GD 001"),
    ("\nVAT GB GD 001\n", "GB GD 001"),
];

/// Dot and slash grouping are accepted only when a VAT label supplies context.
/// Every item checks the exact replaced source range in Open and Private modes.
const DOTTED_POSITIVES: &[(&str, &str)] = &[
    ("TVA intracom.\n123.4567.89", "123.4567.89"),
    ("VAT 123.4567.89", "123.4567.89"),
    ("VAT\n123.4567.89", "123.4567.89"),
    ("VAT no. 123.4567.89", "123.4567.89"),
    ("VAT no.\n123.4567.89", "123.4567.89"),
    ("TVA 123.4567.89", "123.4567.89"),
    ("TVA\n123.4567.89", "123.4567.89"),
    ("n° TVA 123.4567.89", "123.4567.89"),
    ("n° TVA\n123.4567.89", "123.4567.89"),
    ("TVA intracom. 123.4567.89", "123.4567.89"),
    ("VAT 123.4567-89", "123.4567-89"),
    ("VAT GB 123.4567.89", "GB 123.4567.89"),
    ("TVA 123/4567/89", "123/4567/89"),
];

const DOTTED_NEGATIVES: &[&str] = &["12.04.2026", "1.2.3"];

const DASHED_NEGATIVES: &[&str] = &["123-4567-89", "date 12-34-56-78", "order 123-4567-89"];
const LABELLED_LOOKALIKE: &str = "VAT 123 4567 89";
const UNLABELLED_LOOKALIKES: &[&str] = &[
    "123 4567 89",
    "GB 123 4567 89",
    "IBAN fragment: 123 4567 89",
];

const LOOKALIKES: &[&str] = &[
    "GB 123 4567 89 is just prose",
    "order 123 4567 89",
    "phone +44 123 4567 890",
    "date 12 34 56 78, price 123.45 GBP",
    "VAT 123 4567 89",
    "GBGD0010",
    "XGB 123 4567 82",
];

fn ranges(mode: PrivacyMode, text: &str) -> Option<Vec<(usize, usize)>> {
    let (output, minted) = issue(mode, text)?;
    Some(exact::exact_or_fail(mode, text, &output, &minted))
}

#[test]
fn uk_vat_and_repeated_nino_are_fully_masked_in_both_modes() {
    for &(text, value) in POSITIVES {
        let at = text.find(value).expect("positive value appears in text");
        for mode in MODES {
            let masked = ranges(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            assert!(
                covered(&masked, at, at + value.len()),
                "{mode:?} partial {text:?}: {masked:?}"
            );
        }
    }
}

#[test]
fn labelled_vat_evidence_masks_failed_checksums_and_french_labels_in_both_modes() {
    for &(text, value) in LABELLED_POSITIVES {
        let at = text.find(value).expect("positive value appears in text");
        for mode in MODES {
            let masked = ranges(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            assert!(
                covered(&masked, at, at + value.len()),
                "{mode:?} partial {text:?}: {masked:?}"
            );
        }
    }
    for &text in UNLABELLED_LOOKALIKES {
        for mode in MODES {
            let masked = ranges(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            assert!(
                kernel_privacy::company_id::recognize(text).is_empty(),
                "VAT recognizer masked unlabelled lookalike {text:?}"
            );
            if mode == PrivacyMode::Open {
                assert!(masked.is_empty(), "{mode:?} masked {text:?}: {masked:?}");
            }
        }
    }
}

#[test]
fn dashed_and_spaced_gb_vat_forms_have_exact_outputs_in_both_modes() {
    for &(text, value) in NEW_POSITIVES {
        let start = text.find(value).expect("expected value appears in input");
        let end = start + value.len();
        for mode in MODES {
            let (output, minted) =
                issue(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            let mask = exact::exact_or_fail(mode, text, &output, &minted);
            assert!(
                covered(&mask, start, end),
                "{mode:?} partial {text:?}: {mask:?}"
            );
            let expected = match mode {
                PrivacyMode::Open => format!("{}[id removed]{}", &text[..start], &text[end..]),
                PrivacyMode::Private => {
                    let token = minted
                        .iter()
                        .find(|(_, surface)| surface == value)
                        .map(|(token, _)| token.as_str())
                        .unwrap_or_else(|| panic!("no exact token for {value:?} in {text:?}"));
                    format!("{}⟦{}⟧{}", &text[..start], token, &text[end..])
                }
            };
            assert_eq!(output, expected, "{mode:?} output for {text:?}");
        }
    }
}

#[test]
fn dot_and_slash_grouped_vat_forms_have_exact_outputs_in_both_modes() {
    for &(text, value) in DOTTED_POSITIVES {
        let start = text.find(value).expect("expected value appears in input");
        let end = start + value.len();
        for mode in MODES {
            let (output, minted) =
                issue(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            let mask = exact::exact_or_fail(mode, text, &output, &minted);
            assert!(
                covered(&mask, start, end),
                "{mode:?} partial {text:?}: {mask:?}"
            );
            let expected = match mode {
                PrivacyMode::Open => format!("{}[id removed]{}", &text[..start], &text[end..]),
                PrivacyMode::Private => {
                    let token = minted
                        .iter()
                        .find(|(_, surface)| surface == value)
                        .map(|(token, _)| token.as_str())
                        .unwrap_or_else(|| panic!("no exact token for {value:?} in {text:?}"));
                    format!("{}⟦{}⟧{}", &text[..start], token, &text[end..])
                }
            };
            assert_eq!(output, expected, "{mode:?} output for {text:?}");
        }
    }
}

#[test]
fn unlabelled_dotted_dates_and_versions_keep_main_output() {
    for &text in DOTTED_NEGATIVES {
        assert!(kernel_privacy::company_id::recognize(text).is_empty());
        for mode in MODES {
            let (output, minted) =
                issue(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            assert!(
                minted.is_empty(),
                "{mode:?} minted for {text:?}: {minted:?}"
            );
            assert_eq!(output, text, "{mode:?} changed main's output for {text:?}");
        }
    }
}

#[test]
fn unlabelled_dashed_numbers_remain_clear() {
    let inputs = generated();
    let (_, frozen) = FIXTURE.split_once('\n').expect("main fixture header");
    let frozen: Vec<&str> = frozen.trim().split_terminator(';').collect();
    for &text in DASHED_NEGATIVES {
        assert!(
            kernel_privacy::company_id::recognize(text).is_empty(),
            "recognizer masked {text:?}"
        );
        let index = inputs
            .iter()
            .position(|(candidate, _)| candidate == text)
            .expect("negative is in the differential corpus");
        let mut old_modes = frozen[index].split('|');
        for mode in MODES {
            let (output, minted) =
                issue(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            let masks = exact::exact_or_fail(mode, text, &output, &minted);
            let old = parse(old_modes.next().expect("both frozen modes"))
                .expect("origin/main allowed the negative");
            for byte in 0..text.len() {
                assert_eq!(
                    covered(&masks, byte, byte + 1),
                    covered(&old, byte, byte + 1),
                    "{mode:?} changed byte {byte} of unlabelled negative {text:?}"
                );
            }
            if mode == PrivacyMode::Open {
                assert!(
                    masks.is_empty(),
                    "Open masked dashed negative {text:?}: {output:?}"
                );
            }
        }
    }
}

#[test]
fn uk_vat_lookalikes_stay_clear_in_both_modes() {
    for &text in LOOKALIKES {
        for mode in MODES {
            let masked = ranges(mode, text).unwrap_or_else(|| panic!("{mode:?} refused {text:?}"));
            if text == LABELLED_LOOKALIKE {
                let at = text.find("123 4567 89").expect("labelled VAT value");
                assert!(covered(&masked, at, at + "123 4567 89".len()));
                continue;
            }
            assert!(
                kernel_privacy::company_id::recognize(text).is_empty(),
                "VAT recognizer masked {text:?}"
            );
            if mode == PrivacyMode::Open {
                assert!(
                    masked.is_empty(),
                    "{mode:?} masked lookalike {text:?}: {masked:?}"
                );
            } else {
                let (output, minted) = issue(mode, text).expect("Private issues output");
                assert!(
                    !minted
                        .iter()
                        .any(|(token, _)| token.starts_with("NATIONAL_ID_")),
                    "invalid VAT became an ID: {text:?} -> {output:?}"
                );
            }
        }
    }
}

const SEED: u64 = 0xA51D_0A95_C012_2026;
const COUNT: usize = 2_400;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a>(&mut self, choices: &'a [&'a str]) -> &'a str {
        choices[(self.next() as usize) % choices.len()]
    }
    fn digits(&mut self, count: usize) -> String {
        (0..count)
            .map(|_| char::from(b'0' + (self.next() % 10) as u8))
            .collect()
    }
}

fn generated() -> Vec<(String, Vec<(usize, usize)>)> {
    let mut rng = Rng(SEED);
    let mut out = Vec::with_capacity(
        COUNT + POSITIVES.len() + NEW_POSITIVES.len() + LOOKALIKES.len() + DASHED_NEGATIVES.len(),
    );
    for index in 0..COUNT {
        let text = match index % 6 {
            0 => format!("GB {} {} {}", rng.digits(3), rng.digits(4), rng.digits(2)),
            1 => format!(
                "VAT reg no. {} {} {}",
                rng.digits(3),
                rng.digits(4),
                rng.digits(2)
            ),
            2 => format!(
                "{}GB {} {} {}{}",
                rng.pick(&["invoice ", "ref ", "note: "]),
                rng.digits(3),
                rng.digits(4),
                rng.digits(2),
                rng.digits(3)
            ),
            3 => format!(
                "{}{}",
                rng.pick(&["AB 12 34 56\nB", "XY-12-34-56\nC", "QQ 12 34 56\nB"]),
                rng.digits(6)
            ),
            4 => format!(
                "{} {}",
                rng.pick(&["order", "phone", "date", "price"]),
                rng.digits(9)
            ),
            _ => format!(
                "VAT: GB {} {} {}",
                rng.digits(3),
                rng.digits(4),
                rng.digits(2)
            ),
        };
        out.push((text, Vec::new()));
    }
    for &(text, value) in POSITIVES {
        let at = text.find(value).expect("value");
        out.push((text.to_owned(), vec![(at, at + value.len())]));
    }
    for &(text, value) in NEW_POSITIVES {
        let at = text.find(value).expect("new VAT value");
        out.push((text.to_owned(), vec![(at, at + value.len())]));
    }
    out.extend(LOOKALIKES.iter().map(|&text| (text.to_owned(), Vec::new())));
    out.extend(
        DASHED_NEGATIVES
            .iter()
            .map(|&text| (text.to_owned(), Vec::new())),
    );
    out
}

fn record(value: Option<Vec<(usize, usize)>>) -> String {
    value.map_or_else(
        || "!".into(),
        |ranges| ranges.iter().map(|(s, e)| format!("{s}-{e},")).collect(),
    )
}

fn header(inputs: &[(String, Vec<(usize, usize)>)]) -> String {
    let hash = inputs
        .iter()
        .flat_map(|(text, _)| text.bytes().chain([0]))
        .fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        });
    format!("{} {hash}", inputs.len())
}

fn parse(value: &str) -> Option<Vec<(usize, usize)>> {
    (value != "!").then(|| {
        value
            .split(',')
            .filter_map(|part| {
                let (start, end) = part.split_once('-')?;
                Some((start.parse().ok()?, end.parse().ok()?))
            })
            .collect()
    })
}

#[test]
#[ignore = "freeze baseline on origin/main only"]
fn freeze_main() {
    let inputs = generated();
    let records: Vec<String> = inputs
        .iter()
        .map(|(text, _)| MODES.map(|m| record(ranges(m, text))).join("|"))
        .collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        records.join(";")
    );
}

#[test]
fn strict_byte_superset_of_main_in_both_modes() {
    let inputs = generated();
    assert!(inputs.len() >= 2_000);
    let (head, body) = FIXTURE.split_once('\n').expect("main fixture header");
    assert_eq!(
        head,
        header(&inputs),
        "input set changed; refreeze on origin/main"
    );
    let baseline: Vec<&str> = body.trim().split_terminator(';').collect();
    assert_eq!(baseline.len(), inputs.len());
    let mut lost = [0usize; 2];
    let mut refused = 0usize;
    for (index, (text, positives)) in inputs.iter().enumerate() {
        let mut old = baseline[index].split('|');
        for (slot, mode) in MODES.into_iter().enumerate() {
            let main = parse(old.next().expect("two modes")).expect("main allowed");
            let Some(now) = ranges(mode, text) else {
                refused += 1;
                continue;
            };
            lost[slot] += main
                .iter()
                .flat_map(|&(s, e)| s..e)
                .filter(|&byte| !covered(&now, byte, byte + 1))
                .count();
            for &(start, end) in positives {
                assert!(covered(&now, start, end), "{mode:?} missed {text:?}");
            }
        }
    }
    assert_eq!(lost, [0, 0]);
    assert_eq!(refused, 0);
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}",
        inputs.len()
    );
}

#[test]
#[ignore = "release timing: cargo test --release --test uk_id_gaps -- --ignored timing_scales_linearly"]
fn timing_scales_linearly() {
    let unit = "GB 123 4567 82; VAT reg no. 123 4567 82; GB 123 4567 82 001; VAT 123-4567-89; VAT: GB 123-4567-89; GB GD001; GB HA500; VAT GB GD 001; AB 12 34 56\nBAB123456B; order 123 4567 89; phone +44 123 4567 890; ";
    let time = |size: usize| {
        let text = unit.repeat(size / unit.len());
        (0..3)
            .map(|_| {
                let start = Instant::now();
                for mode in MODES {
                    let _ = ranges(mode, &text);
                }
                start.elapsed()
            })
            .min()
            .unwrap_or(Duration::ZERO)
    };
    let times: Vec<_> = [16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024]
        .map(time)
        .into();
    eprintln!("UK ID gaps text: {times:?}");
    for pair in times.windows(2) {
        assert!(
            pair[1].as_secs_f64() / pair[0].as_secs_f64().max(1e-6) < 6.0,
            "{times:?}"
        );
    }
}
