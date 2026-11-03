//! SECRET-PROSE acceptance: a password, API key, PIN or cookie whose value
//! follows a prose link, an escaped key (`api\_key`) or a cookie header is a
//! secret in both modes; lookalikes gain no mask; and the head is a strict byte
//! superset of main on a seeded differential frozen from origin/main in
//! `data/secret_prose_main.txt` (`-- --ignored freeze --nocapture`, on main only).
//! Every mask is read with the shared exact reader of `data/exact_mask.rs`
//! (TEST-FITS-EXACT-2), the one every superset and differential test in this
//! crate uses: an output that does not read back onto its input in exactly one
//! way fails. This file's own second copy of that reader is gone; it read an
//! Open marker of any one-word body, so `[hunter2x9 removed]` covered the value
//! it spelled, and the two shapes are pinned in
//! [`an_output_that_spell_a_value_reads_as_nothing`] below. All values are
//! invented and built at runtime.

use std::time::Instant;

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
#[allow(dead_code)]
mod cases {
    include!("data/secret_prose_cases.rs");
}
use cases::{key, negatives, positives, pw, tok, word_pw};
use norm1::{covered, exact_ranges, issue, MODES};

/// What one mode did to one input.
#[derive(Debug)]
enum Mask {
    /// The gate refused the text.
    Refused,
    /// The output does not read back onto the input exactly.
    Unaligned(String),
    /// The exact masked byte ranges, merged.
    Ranges(Vec<(usize, usize)>),
}

/// The exact mask of `input` in `mode`, read by the shared reader. Only this
/// file's own wrapper: the reading is [`exact_ranges`]'s, one way only.
fn exact(mode: PrivacyMode, input: &str) -> Mask {
    let Some((output, minted)) = issue(mode, input) else {
        return Mask::Refused;
    };
    exact_ranges(mode, input, &output, &minted).map_or(Mask::Unaligned(output), Mask::Ranges)
}

const FIXTURE: &str = include_str!("data/secret_prose_main.txt");

/// `output` with each minted token replaced by its surface.
fn restore(output: &str, minted: &[(String, String)]) -> String {
    let mut restored = output.to_string();
    for (token, surface) in minted {
        restored = restored.replace(&format!("⟦{token}⟧"), surface);
    }
    restored
}

/// Every positive: each value byte hidden in both modes (exact reading), and
/// Private restores the text exactly.
#[test]
fn prose_secrets_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    let all = positives();
    for (text, value) in &all {
        let start = text
            .rfind(value.as_str())
            .expect("the value is in its text");
        for mode in MODES {
            match exact(mode, text) {
                Mask::Ranges(r) if covered(&r, start, start + value.len()) => {}
                other => wrong.push(format!("{mode:?} {text:?}: {other:?}")),
            }
        }
        let (output, minted) = issue(PrivacyMode::Private, text).expect("issued");
        if restore(&output, &minted) != *text {
            wrong.push(format!("restore {text:?} -> {output:?}"));
        }
    }
    assert!(all.len() >= 40, "40+ positives");
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Lookalikes gain no mask over main in either mode, and the 40+ that main
/// leaves clear stay clear, byte for byte.
#[test]
fn lookalikes_gain_no_mask() {
    let main = frozen();
    let mut wrong = Vec::new();
    let mut clear = 0;
    for text in negatives() {
        let records = main
            .iter()
            .find(|(input, _)| *input == text)
            .map(|(_, records)| records.clone())
            .expect("every negative is frozen");
        if records.iter().all(String::is_empty) {
            clear += 1;
        }
        for (index, mode) in MODES.into_iter().enumerate() {
            let now = record(&exact(mode, &text));
            if now != records[index] {
                wrong.push(format!(
                    "{mode:?} {text:?}: main {} now {now}",
                    records[index]
                ));
            }
        }
    }
    assert!(clear >= 40, "40+ negatives clear on main: {clear}");
    assert!(
        wrong.is_empty(),
        "{} wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// One output the gate must never write: what it is, the text it came from, the
/// mode, the output itself, and the `(token, surface)` pairs `take_minted`
/// reported for it.
struct Leak {
    what: &'static str,
    mode: PrivacyMode,
    input: String,
    output: String,
    minted: Vec<(String, String)>,
}

/// The leaking outputs of pass B, against this PR's **own** reader, which is gone.
/// That reader took a Private token by its minted surface and an Open marker of
/// any one-word body, so the first two of these read back as a mask over the
/// value they spell; the shared reader rejects all of them, and that is pinned.
///
/// The first two are written the way the gate would have to write them: the text
/// is run through the gate, and only the **output** is mutated to spell the value
/// where its own token name or its own marker body stood. `take_minted` is the
/// gate's own, and `Anonymizer::make_token` writes `KIND_<12 hex>`, never the
/// value, so a name that spells a value is a name the gate did not mint; an Open
/// marker is one of the five fixed strings `safetext.rs` writes, so one with the
/// value inside is no marker at all. The rest are literal: outputs the gate could
/// have written and must not, so the reader is the thing under test.
fn leaking_outputs() -> Vec<Leak> {
    const VALUE: &str = "hunter2x9";
    let text = format!("pw {VALUE} end");
    let out = vec![
        // The gate's own output for `pw hunter2x9 end`, with its token name and
        // its marker body replaced by the value they stand for. Minted is the
        // gate's own list, read back here so the case cannot drift from it.
        Leak {
            what: "a Private token name that spells the value",
            mode: PrivacyMode::Private,
            input: text.clone(),
            output: gate_output(PrivacyMode::Private, &text, VALUE),
            minted: gate_minted(PrivacyMode::Private, &text),
        },
        Leak {
            what: "an Open marker body that spells the value",
            mode: PrivacyMode::Open,
            input: text.clone(),
            output: gate_output(PrivacyMode::Open, &text, VALUE),
            minted: gate_minted(PrivacyMode::Open, &text),
        },
        Leak {
            what: "a Private token with the value glued to it",
            mode: PrivacyMode::Private,
            input: "pw 1hunter2x9 end".into(),
            output: "\u{27E6}SECRET_1\u{27E7}hunter2x9 end".into(),
            minted: vec![("SECRET_1".into(), "1".into())],
        },
        Leak {
            what: "an Open marker with the value glued to it",
            mode: PrivacyMode::Open,
            input: "pw 1hunter2x9 end".into(),
            output: "[secret removed]hunter2x9 end".into(),
            minted: vec![],
        },
        Leak {
            what: "a Private token name no gate ever minted",
            mode: PrivacyMode::Private,
            input: text.clone(),
            output: "pw \u{27E6}SECRET_7\u{27E7} end".into(),
            minted: vec![],
        },
        Leak {
            what: "a Private token covering half the value",
            mode: PrivacyMode::Private,
            input: text.clone(),
            output: "pw \u{27E6}SECRET_1\u{27E7}2x9 end".into(),
            minted: vec![("SECRET_1".into(), "hunter2".into())],
        },
        Leak {
            what: "an Open marker covering half the value",
            mode: PrivacyMode::Open,
            input: text.clone(),
            output: "pw [secret removed]2x9 end".into(),
            minted: vec![],
        },
    ];
    out
}

/// The gate's own output for `text`, with `value` standing where its token name
/// (Private) or its marker body (Open) was. The gate does mask `hunter2x9` in
/// `pw hunter2x9 end` — that is what makes the mutation a leak and not a
/// refusal — so the honest output is required, and the test fails if the gate
/// stops masking this text. Open writes no token (`take_minted` is empty), which
/// is why the marker is what stands for the value there.
fn gate_output(mode: PrivacyMode, text: &str, value: &str) -> String {
    let (output, minted) = issue(mode, text).expect("the gate issues");
    let marker = if mode == PrivacyMode::Open {
        assert!(
            output.contains("[secret removed]"),
            "the gate must mask {value:?} in {text:?}, else this case is not a leak: \
             {output:?}"
        );
        "[secret removed]"
    } else {
        assert!(
            minted.iter().any(|(_, surface)| surface == value),
            "the gate must mask {value:?} in {text:?}, else this case is not a leak: \
             {output:?}"
        );
        &minted
            .iter()
            .find(|(_, surface)| surface == value)
            .expect("checked")
            .0
    };
    let out = output.replace(
        marker,
        &if mode == PrivacyMode::Open {
            format!("[{value} removed]")
        } else {
            format!("\u{27E6}SECRET_{value}\u{27E7}")
        },
    );
    assert!(
        out.contains(value),
        "the mutated output spells {value:?}: {out:?}"
    );
    out
}

/// The `(token, surface)` pairs `take_minted` reported for `text`.
fn gate_minted(mode: PrivacyMode, text: &str) -> Vec<(String, String)> {
    issue(mode, text).expect("the gate issues").1
}

/// Every output that spells a value reads back as nothing, or as a reading that
/// leaves the value in the clear. The two that this PR's own reader accepted —
/// a token name and an Open marker body holding the value — are the first two.
#[test]
fn an_output_that_spell_a_value_reads_as_nothing() {
    let mut passed = Vec::new();
    for leak in leaking_outputs() {
        let value = "hunter2x9";
        let start = leak.input.find(value).expect("the value is in its input");
        let end = start + value.len();
        let ranges = exact_ranges(leak.mode, &leak.input, &leak.output, &leak.minted);
        let hidden = ranges.as_ref().is_some_and(|r| covered(r, start, end));
        assert!(
            !hidden,
            "{}: {:?} reads back as {ranges:?} and still calls {value:?} masked",
            leak.what, leak.output
        );
        passed.push((leak.what, ranges));
    }
    assert_eq!(passed.len(), 7, "all seven leaking outputs");
}

/// A xorshift64, so the corpus is the same text on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, list: &[&'a str]) -> &'a str {
        list[(self.next() % list.len() as u64) as usize]
    }
}

/// Values of the other hidden classes: public specimens and invented numbers.
const OTHERS: &[&str] = &[
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "pay to GB82 WEST 1234 5698 7654 32 today",
    "card 4111 1111 1111 1111 exp 09/29",
    "Mastercard 5555 5555 5555 4444",
    "NIR 1 84 12 76 451 089 46",
    "NI number QQ 12 34 56 C",
    "SSN 512-45-8873",
    "she has type 2 diabetes",
    "MRN: 7730-41925",
    "blood type AB-",
    "mail lena.ortiz@example.org",
    "call +44 20 7946 0958",
    "or +33 6 12 34 56 78",
    "see https://example.test/login",
];

/// Prose around the values, with lookalike links.
const PROSE: &[&str] = &[
    "Thanks for the update.",
    "The password is required for this step.",
    "set it to default",
    "use the default",
    "Path=/",
    "The key is to listen.",
    "Our cookie policy changed.",
    "Kind regards,",
    "See you on Monday at 10:30.",
    "Order 55210931 shipped.",
];

/// One secret sentence, its value built from `i`.
fn secret(rng: &mut Rng, i: usize) -> String {
    let p = pw(i);
    let w = word_pw(i);
    let k = key("sk_", 16 + i % 8);
    let t = tok(i);
    let pin = format!("{}", 4100 + (rng.next() % 5_000_000) as usize);
    match rng.next() % 16 {
        0 => format!("the password might be {p}"),
        1 => format!("the password, {w}, works"),
        2 => format!("Our API key, {k}, expires soon"),
        3 => format!("I changed my pin to {pin} yesterday"),
        4 => format!("I changed the router password to {p} today"),
        5 => format!("For the vault password, set it to {p} now"),
        6 => format!("For the API key use {k} instead"),
        7 => format!("Please enter your PIN, which is {pin}, below"),
        8 => format!("api\\_key: {k}"),
        9 => format!("Cookie: sid={t}; lang=en"),
        10 => format!("Set-Cookie: user_session={t}; Path=/; HttpOnly"),
        11 => format!("x_session={t}; Path=/; Secure"),
        12 => format!("the http cookie sess={t} is set"),
        13 => format!("He listed his password as {w}."),
        14 => format!("Le mot de passe sera {p} lundi"),
        _ => format!("use {p} as the password"),
    }
}

/// The seeded corpus: 1,600 documents of two to five distinct parts (a secret
/// sentence, another class's value, or prose), joined by a sentence end, a line
/// break or a blank line. A part never repeats in its document and two values
/// never touch: main's output for those can be read back more than one way.
fn seeded() -> Vec<String> {
    let mut rng = Rng(0x5345_4352_4554_5052);
    let mut out = Vec::new();
    for i in 0..1_600 {
        let mut parts = Vec::new();
        for _ in 0..2 + rng.next() % 4 {
            let part = match rng.next() % 3 {
                0 => secret(&mut rng, i),
                1 => rng.pick(OTHERS).to_string(),
                _ => rng.pick(PROSE).to_string(),
            };
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
        let joint = rng.pick(&["\n", "\n\n", ". "]);
        out.push(parts.join(joint));
    }
    out
}

/// The differential inputs: the seeded texts, every case above, then the in-repo
/// privacy-eval cases and prose lines. The Russian files are left out: Cyrillic
/// is out of scope, and two of their mails mint one token for two surfaces, so
/// main's output does not read back exactly.
fn inputs() -> Vec<String> {
    let mut out = seeded();
    out.extend(positives().into_iter().map(|(text, _)| text));
    out.extend(negatives());
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval");
    for dir in ["cases", "prose"] {
        let mut files: Vec<_> = std::fs::read_dir(format!("{root}/{dir}"))
            .expect("privacy-eval is readable")
            .map(|entry| entry.expect("entry").path())
            .collect();
        files.sort();
        files.retain(|file| !file.to_string_lossy().ends_with("ru.jsonl"));
        for file in files {
            let raw = std::fs::read_to_string(file).expect("readable");
            for line in raw.lines().filter(|l| !l.trim().is_empty()) {
                out.push(if dir == "prose" {
                    line.to_string()
                } else {
                    let case: serde_json::Value = serde_json::from_str(line).expect("JSON");
                    case["text"].as_str().expect("text").to_string()
                });
            }
        }
    }
    out
}

/// One mode's record: `start-end,` ranges; `!` a refusal; `?` an output that
/// does not read back exactly.
fn record(mask: &Mask) -> String {
    match mask {
        Mask::Refused => "!".into(),
        Mask::Unaligned(_) => "?".into(),
        Mask::Ranges(r) => r.iter().map(|(s, e)| format!("{s}-{e},")).collect(),
    }
}

fn parse(record: &str) -> Vec<(usize, usize)> {
    record
        .split(',')
        .filter_map(|r| r.split_once('-'))
        .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
        .collect()
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[String]) -> String {
    let bytes = inputs.iter().flat_map(|text| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

/// Every input with its frozen main records, one per mode.
fn frozen() -> Vec<(String, Vec<String>)> {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let split = |r: &str| r.split('|').map(String::from).collect();
    inputs
        .into_iter()
        .zip(records.into_iter().map(split))
        .collect()
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = inputs();
    let each = |text: &String| MODES.map(|mode| record(&exact(mode, text))).join("|");
    let records: Vec<String> = inputs.iter().map(each).collect();
    let lines: Vec<String> = records.chunks(64).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// A strict byte superset of main in both modes: no byte main masked is clear,
/// no new refusal, and every output reads back exactly, on main and on the head.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let main = frozen();
    let (mut lost, mut refused, mut unaligned, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    for (text, records) in &main {
        for (index, mode) in MODES.into_iter().enumerate() {
            let before = records[index].as_str();
            let now = exact(mode, text);
            match (&now, before) {
                (Mask::Unaligned(output), _) => {
                    unaligned += 1;
                    eprintln!("unaligned {mode:?} {text:?}: main {before} now {output:?}");
                }
                (_, "?") => {
                    unaligned += 1;
                    eprintln!("unaligned {mode:?} {text:?}: main {before} now {now:?}");
                }
                (Mask::Refused, "!") => {}
                (Mask::Refused, _) => {
                    refused += 1;
                    eprintln!("refused {mode:?} {text:?}");
                }
                (Mask::Ranges(_), "!") => grew[index] += 1,
                (Mask::Ranges(r), _) => {
                    let gone = parse(before)
                        .iter()
                        .flat_map(|&(s, e)| s..e)
                        .filter(|&b| !covered(r, b, b + 1))
                        .count();
                    if gone > 0 {
                        eprintln!("lost {gone} {mode:?} {text:?}: main {before} now {r:?}");
                    }
                    lost[index] += gone;
                    grew[index] += usize::from(record(&now) != before);
                }
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; unaligned \
         {unaligned}; texts with new masks Private/Open {grew:?}",
        main.len()
    );
    assert!(main.len() >= 1_500 + 80);
    assert_eq!((lost, refused, unaligned), ([0, 0], 0, 0));
}

/// Release only: link-dense, cookie-dense and key-dense text through both gates
/// at 16 KiB, 64 KiB, 256 KiB and 1 MiB, best of three. Bar: each 4x step under
/// 6x.
///
/// The third unit is the one pass B timed at 11.8 s against main's 2.2 s on
/// 1 MiB: a 1 KiB word of `pin-pin-…-pin`, so 256 keys sit in every KiB and each
/// of them used to read ten whole words of 1 KiB. `MAX_WORD` is 257 bytes now, so
/// a key reads 257 bytes and a word it cannot hold ends the search.
#[test]
#[ignore = "release timing: cargo test --release --test secret_prose -- --ignored --nocapture"]
fn dense_text_scales_linearly() {
    let links = format!(
        "the password might be {}, the pin, 719406, and the API key, {}; set it to \
         default, use the default. password password key is to listen, ",
        pw(3),
        key("pk_", 20)
    );
    let cookies = format!(
        "Cookie: sid={}; lang=en\nSet-Cookie: s={}; Path=/; HttpOnly; Secure\n\
         a=b; Path=/; c=d; Path=/ the http cookie x={} is set ",
        tok(1),
        tok(2),
        tok(3)
    );
    let keys = format!("{} ", "pin-".repeat(255) + "pin");
    for unit in [links, cookies, keys] {
        let mut last = 0.0;
        for size in [16_384usize, 65_536, 262_144, 1_048_576] {
            let text = unit.repeat(size / unit.len() + 1);
            let mut best = f64::MAX;
            for _ in 0..3 {
                let start = Instant::now();
                for mode in MODES {
                    let _ = issue(mode, &text);
                }
                best = best.min(start.elapsed().as_secs_f64());
            }
            let ratio = if last == 0.0 { 0.0 } else { best / last };
            eprintln!("{size} bytes: {best:.3}s ratio {ratio:.2}");
            assert!(ratio < 6.0, "{size} bytes scales {ratio:.2}");
            last = best;
        }
    }
}
