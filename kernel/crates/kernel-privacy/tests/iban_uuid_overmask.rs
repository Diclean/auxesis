//! IBAN-UUID-OVERMASK: an IBAN guess wholly inside a whole UUID id is dropped
//! (`sandbox-<uuid>` came back as `sandbox-[iban removed]1B`), but every
//! checksum-valid IBAN of the 27 EU countries plus GB, CH and NO stays masked:
//! compact or grouped, alone, next to a UUID, running past one or in UUID shape.
//! Every UUID and IBAN below is generated from a fixed seed or invented.

#[allow(dead_code)]
mod cases {
    include!("data/norm1_cases.rs");
}

use cases::{covered, issue, masked, wide, MODES};
use kernel_privacy::recognizers::iban::{uuid_tokens, SCORE};
use kernel_privacy::{EntityKind, Registry};

/// The 27 EU countries plus GB, CH and NO: code and length, then the letters
/// some banks put at the head of the BBAN (a bank code or an Italian CIN).
const COUNTRIES: &str = "AT20 BE16 BG22BNBG HR21 CY28 CZ24 DK18 EE20 FI18 FR27 DE22 GR27 \
    HU28 IE22AIBK IT27X LV21BANK LT20 LU20 MT31MALT NL18ABNA PL28 PT25 RO24AAAA SK24 SI19 \
    ES24 SE24 GB22NWBK CH21 NO15";

/// Each row of [`COUNTRIES`]: code, length, BBAN head letters.
fn countries() -> impl Iterator<Item = (&'static str, usize, &'static str)> {
    COUNTRIES.split_whitespace().map(|row| {
        let length = row[2..4].parse().expect("a length");
        (&row[..2], length, &row[4..])
    })
}

/// SplitMix64: a fixed, dependency-free stream of test values.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A random v4 UUID, upper case.
fn uuid(rng: &mut Rng) -> String {
    let hex = b"0123456789ABCDEF";
    let mut out = String::with_capacity(36);
    for at in 0..36 {
        let ch = match at {
            8 | 13 | 18 | 23 => '-',
            14 => '4',
            19 => hex[8 + rng.below(4) as usize] as char,
            _ => hex[rng.below(16) as usize] as char,
        };
        out.push(ch);
    }
    out
}

/// A checksum-valid compact IBAN for `code`.
fn iban(rng: &mut Rng, code: &str, length: usize, letters: &str) -> String {
    let mut bban = letters.to_string();
    while bban.len() < length - 4 {
        bban.push(char::from(b'0' + rng.below(10) as u8));
    }
    let remainder = format!("{bban}{code}00")
        .chars()
        .map(|ch| ch.to_digit(36).expect("alphanumeric"))
        .fold(0, |acc, value| {
            (acc * if value >= 10 { 100 } else { 10 } + value) % 97
        });
    format!("{code}{:02}{bban}", 98 - remainder)
}

/// `compact` in groups of four joined by `separator`.
fn grouped(compact: &str, separator: &str) -> String {
    compact
        .as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).expect("ascii"))
        .collect::<Vec<_>>()
        .join(separator)
}

/// One IBAN per country in each printed form.
fn iban_corpus() -> Vec<String> {
    let mut rng = Rng(0x1BA4_0001);
    let mut corpus = Vec::new();
    for (code, length, letters) in countries() {
        let compact = iban(&mut rng, code, length, letters);
        corpus.push(grouped(&compact, " "));
        corpus.push(grouped(&compact, "-"));
        corpus.push(compact);
    }
    corpus
}

/// Whether the gate hides every byte of `value` at `at` in `text`, both modes.
fn hidden_in_both_modes(text: &str, at: usize, value: &str) -> bool {
    MODES.iter().all(|&mode| {
        masked(mode, text).is_some_and(|ranges| covered(&ranges, at, at + value.len()))
    })
}

#[test]
fn a_sandbox_event_id_comes_back_unchanged() {
    // The reported shape: the id opens on an `LLdd` anchor (`EB23…`, unknown
    // country) and main masked all of it but the last `1B`.
    let id = "sandbox-EB23A270-1C4F-4D6A-9E2B-5A7C3D0F121B";
    let pair = "EB23A270-1C4F-4D6A-9E2B-5A7C3D0F121B:0F3D7C5A-B2E9-4A6D-8F4C-07282AB3E1C4";
    for text in [id, pair]
        .into_iter()
        .flat_map(|t| [t.to_string(), t.to_lowercase()])
    {
        for mode in MODES {
            let (output, _) = issue(mode, &text).expect("the gate allows an id");
            assert_eq!(output, text, "{mode:?} changed an event id");
        }
    }
}

#[test]
fn every_iban_form_of_every_country_is_masked() {
    for value in iban_corpus() {
        let text = format!("Pay to {value} please.");
        assert!(hidden_in_both_modes(&text, 7, &value), "{value} not masked");
    }
}

#[test]
fn an_iban_next_to_a_uuid_is_masked() {
    let mut rng = Rng(0x0BAD_CAFE);
    for value in iban_corpus() {
        let one = uuid(&mut rng);
        let lower = uuid(&mut rng).to_lowercase();
        let texts = [
            format!("{one} {value}"),
            format!("{value} {one}"),
            format!("{one}:{value}"),
            format!("{one}-{value}"),
            format!("{value}-{lower}"),
            format!("{lower}\n{value}"),
            format!("{{\"id\":\"{one}\",\"iban\":\"{value}\"}}"),
            format!("sandbox-{one} {value} {lower}"),
        ];
        for text in texts {
            let at = text.find(&value).expect("value in text");
            assert!(hidden_in_both_modes(&text, at, &value), "{text:?}");
        }
    }
}

#[test]
fn an_iban_that_runs_past_a_uuid_is_masked() {
    // The seal's repros: the IBAN starts inside a whole UUID token and runs
    // past its end, so its bytes outside the id stay masked.
    for text in [
        "ref 0f3d7c5a-b2e9-4a6d-8f4c-07282ab3DE89 3704 0044 0532 0130 00",
        "0f3d7c5a-b2e9-4a6d-8f4c-07282ab3DE89-3704-0044-0532-0130-00",
        "0f3d7c5a-b2e9-4a6d-8f4c-DE8937040044 0532 0130 00",
    ] {
        let at = text.find("DE89").expect("the IBAN");
        let value = &text[at..];
        assert!(hidden_in_both_modes(text, at, value), "{text:?} leaks");
    }
    // Every country, every form, glued on the last 4 or 12 hex of a UUID. The
    // texts where the IBAN starts inside a whole UUID token are the sweep;
    // the others glue it onto a run that is no UUID, as main reads it.
    let mut rng = Rng(0x7A11_0001);
    let (mut cases, mut clear) = (0usize, 0usize);
    for (code, length, letters) in countries() {
        let compact = iban(&mut rng, code, length, letters);
        let forms = [
            grouped(&compact, " "),
            grouped(&compact, "-"),
            format!("{} {}", &compact[..12], grouped(&compact[12..], " ")),
            compact,
        ];
        for value in forms {
            let one = uuid(&mut rng);
            for head in [&one[..32], &one[..24]] {
                for head in [head.to_string(), head.to_lowercase()] {
                    let text = format!("ref {head}{value} ok");
                    if !uuid_tokens(&text).iter().any(|&(start, _)| start == 4) {
                        continue;
                    }
                    cases += 1;
                    for mode in MODES {
                        let ranges = masked(mode, &text).expect("the gate allows it");
                        let at = 4 + head.len();
                        clear += (at..at + value.len())
                            .filter(|&b| !covered(&ranges, b, b + 1))
                            .count();
                    }
                }
            }
        }
    }
    // BE, DE and EE open on hex: 3 forms x 2 heads-or-cases each, at least.
    assert!(cases >= 18, "only {cases} IBANs start inside a UUID");
    assert_eq!(clear, 0, "IBAN bytes left clear past a UUID");
}

#[test]
fn a_valid_iban_in_uuid_shape_is_masked() {
    // UUID-shaped ids holding the checksum-valid Belgian IBAN `BE68539007547034`
    // at the head or mid-group, where only the main scan reads
    // it: a real account is masked in any shape, also after the Unicode dash
    // and full-width folds. `skip` letters and digits come before the IBAN.
    for (id, skip) in [
        ("BE685390-0754-7034-ABCD-EF0123456789", 0),
        ("0123BE68-5390-0754-7034-0123456789AB", 4),
    ] {
        for (text, skip) in [
            (id.to_string(), skip),
            (id.to_lowercase(), skip),
            (format!("ref {}", id.replace('-', "\u{2010}")), skip + 3),
            (format!("ref {}", wide(id)), skip + 3),
        ] {
            let alnum: Vec<(usize, char)> = (text.char_indices())
                .filter(|(_, ch)| ch.is_alphanumeric())
                .collect();
            let (start, (last, ch)) = (alnum[skip].0, alnum[skip + 15]);
            let value = &text[start..last + ch.len_utf8()];
            assert!(hidden_in_both_modes(&text, start, value), "{text:?} leaks");
        }
    }
}

#[test]
fn ten_thousand_random_uuids_keep_only_valid_ibans() {
    let registry = Registry::new();
    let mut rng = Rng(0x00C0_FFEE);
    // Upper, lower, `sandbox-` upper and lower, `A:B` upper and lower.
    let mut hits = [0usize; 6];
    for _ in 0..10_000 {
        let (one, two) = (uuid(&mut rng), uuid(&mut rng));
        let texts = [
            one.clone(),
            one.to_lowercase(),
            format!("sandbox-{one}"),
            format!("sandbox-{one}").to_lowercase(),
            format!("{one}:{two}"),
            format!("{one}:{two}").to_lowercase(),
        ];
        for (index, text) in texts.iter().enumerate() {
            let ibans: Vec<_> = (registry.analyze(text).into_iter())
                .filter(|span| span.kind == EntityKind::Iban)
                .collect();
            // Only a checksum-valid IBAN of a registered country is left.
            assert!(ibans.iter().all(|span| span.score >= SCORE), "{text}");
            hits[index] += usize::from(!ibans.is_empty());
        }
    }
    // Main: 3421, 4, 3421, 4, 5670, 11.
    assert_eq!(hits, [4, 4, 4, 4, 11, 11], "UUIDs read as IBANs, of 10,000");
}

/// Seal A r2 repro: a UTF-8 letter glued before the run must not make it a
/// whole id, so the IBAN inside stays masked as on main.
#[test]
fn a_letter_glued_before_a_uuid_keeps_the_iban_masked() {
    for text in [
        "éAAAAAAAA-DE89-3704-0044-053201300000",
        "AAAAAAAA-DE89-3704-0044-053201300000é",
        "ßAAAAAAAA-DE89-3704-0044-053201300000 x",
    ] {
        let ids = kernel_privacy::recognizers::iban::uuid_tokens(text);
        assert!(ids.is_empty(), "{text:?} read as a whole id: {ids:?}");
    }
    let text = "éAAAAAAAA-DE89-3704-0044-053201300000";
    let value = "DE89-3704-0044-0532013000";
    let at = text.find(value).expect("value in text");
    assert!(
        hidden_in_both_modes(text, at, value),
        "{value} not masked in {text:?}"
    );
}
