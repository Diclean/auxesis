//! K-SKPROJ-GLUE acceptance: a prefixed key glued after a letter, a digit or `_`
//! (`notesk-proj-…`, `2024ghp_…`, `my_AKIA…`) is hidden whole in both modes, at
//! line start, mid-line and after a break, for every prefix of the family:
//! `sk-`, `sk-proj-`, `sk-ant-`, `ghp_`, `gho_`, `ghs_`, `github_pat_`, `xoxb-`,
//! `xoxp-`, `AKIA`, `ASIA`, `AIza`, `GOCSPX-`, `ya29.`, `sk_live_`, `rk_live_`,
//! `glpat-`, `npm_`, `sl.` and the JWT `eyJ`. Words that only hold a prefix
//! (`desk-top`, `risk-free`, `Asia`, `eyJustice`) gain no mask, and the head is a
//! strict byte superset of main on a seeded differential frozen from origin/main
//! in `data/prefix_key_glue_main.txt` (`-- --ignored freeze --nocapture`, on main
//! only). Every mask is read with the shared exact reader `data/exact_mask.rs`.
//! Round 1: each issuer format of the `sk-` / `sl.` family (OpenAI legacy 48,
//! DeepSeek 32 hex, OpenRouter `sk-or-v1-` 64 hex, `sk-proj-`, `sk-svcacct-`,
//! `sk-admin-`, `sk-ant-api03-`, `sk-ant-admin01-`, `sl.`, `sl.u.`) glued after
//! letters and digits has 0 misses in both modes, from a fixed seed (20,000 per
//! format in the ignored `glued_exact_formats_20k`). Round 2: the same keys
//! followed by `-`, `_`, `-prod` or `_old`, and on the line after a glued `sk-`
//! run (`high-risk-\n<key>`).
//! Every key is invented and built at runtime from parts.

use std::time::Instant;

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use kernel_privacy::recognizers::iban::uuid_tokens;
use norm1::{covered, exact_ranges, issue, MODES};

const FIXTURE: &str = include_str!("data/prefix_key_glue_main.txt");

/// One mode's record of `input`, read by the shared exact reader:
/// `start-end,` ranges; `!` a refusal; `?` an output that does not read back.
fn exact(mode: PrivacyMode, input: &str) -> String {
    let Some((output, minted)) = issue(mode, input) else {
        return "!".into();
    };
    exact_ranges(mode, input, &output, &minted).map_or("?".into(), |r| {
        r.iter().map(|(s, e)| format!("{s}-{e},")).collect()
    })
}

fn parse(record: &str) -> Vec<(usize, usize)> {
    record
        .split(',')
        .filter_map(|r| r.split_once('-'))
        .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
        .collect()
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

/// `n` invented key characters, `_` and `-` included, seeded by `seed`.
fn body(seed: u64, n: usize) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    (0..n)
        .map(|_| char::from(alphabet[(rng.next() % 64) as usize]))
        .collect()
}

/// `n` invented ASCII letters and digits, with a `7Q` in the middle.
fn alnum(seed: u64, n: usize) -> String {
    let mut out: String = body(seed, n * 4)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .chain("x9K".chars().cycle())
        .take(n - 2)
        .collect();
    out.insert_str(n / 2 - 1, "7Q");
    out
}

/// One invented key per prefix of the family: `(prefix, key)`.
fn keys(i: u64) -> Vec<(&'static str, String)> {
    let digits = format!("{:010}", i.wrapping_mul(0x2545_F491) % 10_000_000_000);
    let slack = |kind: &str, n| format!("xox{kind}-1{digits}-2{digits}-{}", alnum(i, n));
    vec![
        ("sk-", format!("s{}-{}", "k", alnum(i, 48))),
        ("sk-proj-", format!("sk-{}-{}", "proj", alnum(i + 1, 64))),
        ("sk-proj-", format!("sk-{}-{}A1b", "proj", body(i + 2, 120))),
        (
            "sk-ant-",
            format!("sk-{}-api03-{}AA", "ant", alnum(i + 3, 93)),
        ),
        ("ghp_", format!("gh{}_{}", "p", alnum(i + 4, 36))),
        ("gho_", format!("gh{}_{}", "o", alnum(i + 5, 36))),
        ("ghs_", format!("gh{}_{}", "s", alnum(i + 6, 36))),
        (
            "github_pat_",
            format!("github{}_{}_{}", "_pat", alnum(i + 7, 22), alnum(i + 8, 59)),
        ),
        ("xoxb-", slack("b", 24)),
        ("xoxp-", slack("p", 32)),
        (
            "AKIA",
            format!("AK{}{}", "IA", alnum(i + 9, 16).to_uppercase()),
        ),
        (
            "ASIA",
            format!("AS{}{}", "IA", alnum(i + 10, 16).to_uppercase()),
        ),
        ("AIza", format!("AI{}Sy{}", "za", alnum(i + 11, 33))),
        ("GOCSPX-", format!("GOC{}-{}", "SPX", alnum(i + 12, 28))),
        ("ya29.", format!("ya{}.a0{}", "29", alnum(i + 13, 60))),
        ("sk_live_", format!("sk{}_{}", "_live", alnum(i + 14, 24))),
        ("rk_live_", format!("rk{}_{}", "_live", alnum(i + 15, 24))),
        ("glpat-", format!("glp{}-{}", "at", alnum(i + 16, 20))),
        ("npm_", format!("np{}_{}", "m", alnum(i + 17, 36))),
        ("sl.", format!("s{}.{}", "l", alnum(i + 18, 130))),
        (
            "eyJ",
            format!(
                "ey{}{}.ey{}{}.{}",
                "J",
                alnum(i + 19, 30),
                "J",
                alnum(i + 20, 40),
                alnum(i + 21, 43)
            ),
        ),
    ]
}

/// `n` characters drawn uniformly from `alphabet`.
fn draw(rng: &mut Rng, alphabet: &[u8], n: usize) -> String {
    (0..n)
        .map(|_| char::from(alphabet[(rng.next() % alphabet.len() as u64) as usize]))
        .collect()
}

const BASE62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const HEX: &[u8] = b"0123456789abcdef";

/// The issuers' exact formats of the `sk-` and `sl.` family: a name, and an
/// invented key in that format, uniformly random, built at runtime.
const FORMATS: &[&str] = &[
    "openai-legacy-48",
    "openai-legacy-marker",
    "deepseek-32hex",
    "openrouter-64hex",
    "openai-proj",
    "openai-svcacct",
    "openai-admin",
    "anthropic-api03",
    "anthropic-admin01",
    "dropbox-sl",
    "dropbox-sl-u",
];

fn format_key(format: &str, rng: &mut Rng) -> String {
    let marker = ["T3Blbk", "FJ"].concat();
    let sk = |rest: String| format!("s{}-{rest}", "k");
    let long = |rng: &mut Rng, sub: &str| {
        let n = 140 + (rng.next() % 40) as usize;
        let mut tail = draw(rng, BASE64URL, n);
        tail.insert_str(n / 2, &marker);
        sk(format!("{sub}-{tail}"))
    };
    match format {
        "openai-legacy-48" => sk(draw(rng, BASE62, 48)),
        "openai-legacy-marker" => sk(draw(rng, BASE62, 20) + &marker + &draw(rng, BASE62, 20)),
        "deepseek-32hex" => sk(draw(rng, HEX, 32)),
        "openrouter-64hex" => sk(format!("or-{}-{}", "v1", draw(rng, HEX, 64))),
        "openai-proj" => long(rng, "proj"),
        "openai-svcacct" => long(rng, "svcacct"),
        "openai-admin" => long(rng, "admin"),
        "anthropic-api03" => sk(format!("ant-{}-{}AA", "api03", draw(rng, BASE64URL, 93))),
        "anthropic-admin01" => sk(format!("ant-{}-{}AA", "admin01", draw(rng, BASE64URL, 93))),
        "dropbox-sl" => format!("s{}.{}", "l", draw(rng, BASE64URL, 135)),
        _ => format!("s{}.u.{}", "l", draw(rng, BASE64URL, 140)),
    }
}

/// What a format key is glued after: letters and digits only.
const FORMAT_GLUES: &[&str] = &[
    "note", "key", "x", "Token", "2024", "7", "A", "z9", "apiKey", "OPENAI", "id0",
];

/// Where a format key sits.
const FORMAT_FRAMES: &[&str] = &[
    "cfg: {}",
    "The key is {} for prod.",
    "first line\n{}\nnext line",
    "{}",
    "cfg: {}-",
    "cfg: {}_",
    "The key is {}-prod here.",
    "The key is {}_old here.",
    "high-risk-\n{} ok",
];

/// `(format, text, key start, key end)`: `per` keys of every format, each glued
/// after a letter or digit, in a frame, from a fixed seed.
fn format_positives(per: usize, seed: u64) -> Vec<(&'static str, String, usize, usize)> {
    let mut rng = Rng(seed | 1);
    let mut out = Vec::new();
    for format in FORMATS {
        for i in 0..per {
            let key = format_key(format, &mut rng);
            let glue = FORMAT_GLUES[i % FORMAT_GLUES.len()];
            let frame = FORMAT_FRAMES[(i / FORMAT_GLUES.len()) % FORMAT_FRAMES.len()];
            let (head, tail) = frame.split_once("{}").expect("frame");
            let start = head.len() + glue.len();
            out.push((
                *format,
                format!("{head}{glue}{key}{tail}"),
                start,
                start + key.len(),
            ));
        }
    }
    out
}

/// Misses per format and mode `[Private, Open]`, read by the exact reader.
fn format_misses(per: usize, seed: u64) -> Vec<(&'static str, [usize; 2], String)> {
    let mut out: Vec<(&'static str, [usize; 2], String)> = FORMATS
        .iter()
        .map(|f| (*f, [0, 0], String::new()))
        .collect();
    for (format, text, start, end) in format_positives(per, seed) {
        let row = out.iter_mut().find(|row| row.0 == format).expect("format");
        for (index, mode) in MODES.into_iter().enumerate() {
            let now = exact(mode, &text);
            if !covered(&parse(&now), start, end) {
                row.1[index] += 1;
                if row.2.is_empty() {
                    row.2 = format!("{mode:?} {text:?}: {now}");
                }
            }
        }
    }
    out
}

fn assert_no_format_misses(per: usize, seed: u64) {
    let rows = format_misses(per, seed);
    for (format, misses, first) in &rows {
        eprintln!("{format}: {per} keys, misses Private/Open {misses:?} {first}");
    }
    let missed: Vec<_> = rows.iter().filter(|row| row.1 != [0, 0]).collect();
    assert!(missed.is_empty(), "{missed:#?}");
}

/// Every exact format, glued after letters and digits: 0 misses in both modes.
#[test]
fn glued_exact_formats_are_hidden_in_both_modes() {
    assert_no_format_misses(220, 0x464F_524D_4154_5331);
}

/// The 20,000-keys-per-format run (release).
#[test]
#[ignore = "slow: cargo test --release --test prefix_key_glue -- --ignored formats_20k --nocapture"]
fn glued_exact_formats_20k() {
    assert_no_format_misses(20_000, 0x3230_4B5F_4B45_5953);
}

/// The repros (round 1), keys invented and built at runtime.
#[test]
fn pass_a_repros_are_hidden_in_both_modes() {
    let sk = |rest: &str| format!("s{}-{rest}", "k");
    let marker = ["T3Blbk", "FJ"].concat();
    let cases = [
        (
            "cfg: key",
            sk("jUBwx48Yl1z2zsQNpa8WqelGdIc5Dl69QisaqTsFhAkVtBnv"),
            "",
        ),
        (
            "The key is 7",
            sk("NuFuI6mfg9SoqdZ7n4ozEiNaLivAo0nFpqlEqCpDxDji2tor"),
            " for prod.",
        ),
        (
            "first line\napiKey",
            sk(&format!("xcgKuaZv3jWzLzUym1Li{marker}ukeKqwo811bw4zWtfVas")),
            "\nnext line",
        ),
        (
            "cfg: z9",
            sk(&format!("aks9wxdUz98SghzRqpOf{marker}bmHaLv5nXj2kmFhGf361")),
            "",
        ),
        ("note", sk("5acc6fab1b3d993596e3bcd1df39067a"), ""),
        (
            "note",
            sk(&format!(
                "or-{}-{}",
                "v1", "79bece22ff98e1753abe9cd1944d9e6a61489c30c95100eb4c6a71c1e30b63a5"
            )),
            "",
        ),
    ];
    for (head, key, tail) in cases {
        let text = format!("{head}{key}{tail}");
        for mode in MODES {
            let now = exact(mode, &text);
            assert!(
                covered(&parse(&now), head.len(), head.len() + key.len()),
                "{mode:?} {text:?}: {now}"
            );
        }
    }
}

/// An accepted over-mask (security review, round 1): a random 32-hex or
/// 48-character ID glued after `sk-` (`task-<hex>`, `disk-<id>`) reads as a
/// DeepSeek or OpenAI legacy key. Round 2: the same 32 or 48 characters
/// followed by `-` or `_` and more (`task-<hex>-v2`, `disk-<id>_old`) are the
/// same over-mask.
fn accepted_overmask(text: &str) -> bool {
    text.match_indices("sk-").any(|(at, _)| {
        let run: String = text[at + 3..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
            .collect();
        let cut = |n: usize| {
            (run.len() == n || (run.len() > n && matches!(run.as_bytes()[n], b'-' | b'_')))
                .then(|| &run[..n])
        };
        cut(32).is_some_and(|head| head.bytes().all(|b| HEX.contains(&b)))
            || run
                .get(..48)
                .is_some_and(|head| head.bytes().all(|b| b.is_ascii_alphanumeric()))
    })
}

/// What a key is glued after: letters, digits and `_`.
const GLUES: &[&str] = &["note", "Key", "x", "token", "2024", "7", "_", "my_", "Ab1_"];

/// Where the glued key sits: line start, mid-line, after a break.
const FRAMES: &[&str] = &[
    "{}",
    "{} is the key",
    "Use {} now.",
    "first line\n{} x",
    "first line\r\n  {}",
    "a: {}, b",
];

/// `(text, key start, key end)` for every prefix, glue and frame.
fn positives() -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for (n, glue) in GLUES.iter().enumerate() {
        for (f, frame) in FRAMES.iter().enumerate() {
            for (_, key) in keys((n * 31 + f) as u64) {
                let (head, tail) = frame.split_once("{}").expect("frame");
                let start = head.len() + glue.len();
                out.push((format!("{head}{glue}{key}{tail}"), start, start + key.len()));
            }
        }
    }
    out
}

/// `output` with each minted token replaced by its surface.
fn restore(output: &str, minted: &[(String, String)]) -> String {
    let mut restored = output.to_string();
    for (token, surface) in minted {
        restored = restored.replace(&format!("⟦{token}⟧"), surface);
    }
    restored
}

#[test]
fn glued_prefixed_keys_are_hidden_in_both_modes() {
    let all = positives();
    let mut wrong = Vec::new();
    for (text, start, end) in &all {
        for mode in MODES {
            let now = exact(mode, text);
            if !covered(&parse(&now), *start, *end) {
                wrong.push(format!("{mode:?} {text:?}: {now}"));
            }
        }
        let (output, minted) = issue(PrivacyMode::Private, text).expect("issued");
        if restore(&output, &minted) != *text {
            wrong.push(format!("restore {text:?} -> {output:?}"));
        }
    }
    assert!(all.len() >= 1_000, "1,000+ positives: {}", all.len());
    let shown: Vec<&String> = wrong.iter().take(30).collect();
    assert!(wrong.is_empty(), "{} wrong:\n{shown:#?}", wrong.len());
}

/// K-SK-TAIL: seeded key shapes with random alphanumeric glue and the
/// punctuation/alphanumeric/end boundaries that previously changed the
/// recognizer's match length. Every format has 10,000 invented samples, and
/// the shared exact reader must show the entire key body hidden in both modes.
#[test]
fn glued_openai_key_tails_are_hidden_in_both_modes() {
    const CASES: usize = 100_000;
    let shapes = [("sk-", 48), ("sk-proj-", 48), ("sk-proj-", 64)];
    let letters = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let digits = b"0123456789";
    let mut rng = Rng(0x4B53_4B54_4149_4C31);
    let mut misses = [[0usize; 2]; 3];
    for (shape_index, (prefix, len)) in shapes.into_iter().enumerate() {
        for case in 0..CASES {
            let before = char::from(BASE62[(rng.next() % BASE62.len() as u64) as usize]);
            let mut key_body = draw(&mut rng, BASE62, len);
            // Exercise marked and unmarked tails without changing the exact
            // issuer body length.
            if case % 2 == 0 {
                key_body.replace_range(0..8, "T3BlbkFJ");
            }
            let suffix = match case % 6 {
                0 => "_".to_string(),
                1 => "-".to_string(),
                2 => ".".to_string(),
                3 => char::from(letters[(rng.next() % letters.len() as u64) as usize]).to_string(),
                4 => char::from(digits[(rng.next() % digits.len() as u64) as usize]).to_string(),
                _ => String::new(),
            };
            let text = format!("{before}{prefix}{key_body}{suffix}");
            let start = 1 + prefix.len();
            let end = start + key_body.len();
            for (mode_index, mode) in MODES.into_iter().enumerate() {
                let now = exact(mode, &text);
                misses[shape_index][mode_index] += usize::from(!covered(&parse(&now), start, end));
            }
        }
    }
    assert_eq!(
        misses, [[0; 2]; 3],
        "per-shape Private/Open misses: {misses:?}"
    );
}

/// Round-one regressions: exact-length runs with too little segmentation are
/// secrets in both modes, while the two #231 segmented identifier examples stay
/// clear. Wrapped key offsets include the inserted LF/CRLF bytes exactly.
#[test]
fn glued_exact_lengths_require_segmented_words_and_wrapped_ranges_are_exact() {
    let repeated = "banana".repeat(8);
    let false_clears = [
        format!("notesk-{repeated}"),
        format!("notesk-proj-{repeated}"),
        "xsk-QuarterlyFinancialReportForEuropeanTeamsRiskTo20!".to_string(),
    ];
    for text in &false_clears {
        let key_start = text.find("sk-").unwrap();
        let key_end = text.find('!').unwrap_or(text.len());
        for mode in MODES {
            assert_eq!(
                exact(mode, text),
                format!("{key_start}-{key_end},"),
                "{text}"
            );
        }
    }

    for text in [
        "task-calculateTotalAmountForUserAccountBalanceInEuros2024",
        "risk-assessmentForQuarterlyReportGenerationAndReview2025",
    ] {
        for mode in MODES {
            assert_eq!(exact(mode, text), "", "{mode:?}: {text}");
        }
    }

    for (prefix, body_len) in [("sk-", 48), ("sk-proj-", 48), ("sk-proj-", 64)] {
        for newline in ["\n", "\r\n"] {
            for split in [1, 7, 24, body_len / 2, body_len - 1] {
                let body = format!("{}{}", "A7b".repeat(body_len / 3), "Q".repeat(body_len % 3));
                let key = format!("{prefix}{body}");
                let wrapped = format!(
                    "{}{}{}",
                    &key[..prefix.len() + split],
                    newline,
                    &key[prefix.len() + split..]
                );
                let text = format!("x{wrapped}_word");
                let end = 1 + key.len() + newline.len();
                for mode in MODES {
                    assert_eq!(
                        exact(mode, &text),
                        format!("1-{end},"),
                        "{mode:?}, {prefix}, {newline:?}, split {split}"
                    );
                }
            }
        }
    }

    // The reported byte-25 LF repro, including its clear identifier suffix.
    let body = "A7b".repeat(16);
    let wrapped = format!("{}\n{}", &body[..21], &body[21..]);
    let text = format!("xsk-{wrapped}_word");
    for mode in MODES {
        assert_eq!(exact(mode, &text), "1-53,", "{mode:?}");
    }
}

/// Words that hold a prefix, `¦`-separated: none is a key. `{camel}`, `{uuid}`,
/// `{UUID}` and `{hex}` are filled at runtime by [`lookalikes`].
const LOOKALIKES: &str = "desk-top¦risk-free¦task-force¦kiosk-mode¦whisk-in¦Ask-me¦\
    desk-Booking-System-v12-Release-Notes-2024¦risk-assessment-framework-2024-Q3-report¦\
    task-{camel}¦flask-SQLAlchemy-extension-v3¦\
    disk-{uuid}¦task-{hex}¦disk-{id48}¦task-{camel48}¦desk-{camel48}-v2¦\
    ta{sk}-proj-quarterly-planning-review-for-the-sales-team-and-the-board-2024-final-v3¦\
    ri{sk}-admin-escalation-matrix-for-regional-offices-and-partners-2024-q3-draft¦\
    Basel.u.Office¦consul.a.b¦tasksl.u.v2¦ri{sk}-or-v1-review¦\
    risk-{UUID}¦Asia¦ASIA-Pacific¦Southeast Asia¦Slovakia¦\
    eyJustice¦eyJ¦heyJude¦Aizawa¦AIzawa¦ya29 model¦npm_install¦ghost_town¦ghp_ prefix¦\
    sk_live_ docs¦glpat- token¦GOCSPX- secret¦xoxb- tokens¦AKIA prefix¦Russl.Co¦tasksl.v2¦\
    basket-of-goods¦brisk-walk¦obelisk-tower";

/// Business sentences the look-alikes sit in, `¦`-separated.
const SENTENCES: &str = "Please book a {} for the Monday meeting.¦The {} plan was approved.¦\
    See ticket {} before Friday.¦Our {} budget is 12,500 EUR.¦{} — notes from the call.¦\
    Revenue in {} grew 8% this quarter.¦Attach the {} file to the invoice.¦\
    The team moved {} to the next sprint.¦Kind regards, {} team";

/// 1,000+ business and prose texts with prefix-like words, no key.
fn lookalikes() -> String {
    let uuid = ["3fa85f64", "5717", "4562", "b3fc", "2c963f66afa6"].join("-");
    let camel = [
        "calculate",
        "Total",
        "Amount",
        "For",
        "User",
        "Account",
        "Balance",
        "In",
        "Euros",
        "2024",
    ]
    .concat();
    let camel48 = camel.trim_end_matches("2024");
    assert_eq!(camel48.len(), 48);
    LOOKALIKES
        .replace("{sk}", "sk")
        .replace("{camel48}", camel48)
        .replace("{id48}", &["Xq7", "Lm2", "Rt9", "Kd4"].concat().repeat(4))
        .replace("{camel}", &camel)
        .replace("{uuid}", &uuid)
        .replace("{UUID}", &uuid.to_uppercase())
        .replace(
            "{hex}",
            &["7f3a9c1e", "2b4d6f80", "a1b2c3d4", "e5f60718"].concat(),
        )
}

fn negatives() -> Vec<String> {
    let all = lookalikes();
    let words: Vec<&str> = all.split('¦').collect();
    let sentences: Vec<&str> = SENTENCES.split('¦').collect();
    let mut rng = Rng(0x4C4F_4F4B_414C_494B);
    let mut out = Vec::new();
    for word in &words {
        for sentence in &sentences {
            out.push(sentence.replace("{}", word));
        }
    }
    while out.len() < 1_250 {
        let glue = rng.pick(&["", "", " ", "\n", "-", "_"]);
        let text = format!(
            "{} {}{glue}{}",
            rng.pick(&sentences).replace("{}", rng.pick(&words)),
            rng.pick(&["Re:", "Note", "Q3", "item7", ""]),
            rng.pick(&words)
        );
        out.push(text);
    }
    out
}

/// Values of the other classes and prose, `¦`-separated.
const OTHERS: &str = "IBAN FR76 3000 6000 0112 3456 7890 189¦GB82 WEST 1234 5698 7654 32¦\
    card 4111 1111 1111 1111 exp 09/29¦NI number QQ 12 34 56 C¦AB123456C¦SSN 512-45-8873¦\
    she has type 2 diabetes¦lena.ortiz@example.org¦call +44 20 7946 0958¦\
    see https://example.test/login¦Thanks for the update.¦risk-free desk-top¦Asia trip¦\
    api_key: ¦password=";

/// The seeded corpus: 1,600 documents of two to five parts (a key glued or not,
/// another class's value, or prose), joined by a break, glue or a sentence end.
fn seeded() -> Vec<String> {
    let mut rng = Rng(0x534B_5052_4F4A_474C);
    let others: Vec<&str> = OTHERS.split('¦').collect();
    let glues = [
        "note", "Key", "x", "2024", "7", "_", "my_", "", " ", "-", "\n", "日本",
    ];
    let mut out = Vec::new();
    for i in 0..1_600u64 {
        let mut parts: Vec<String> = Vec::new();
        for _ in 0..2 + rng.next() % 4 {
            let part = match rng.next() % 3 {
                0 => {
                    let all = keys(i * 7 + rng.next() % 5);
                    let key = &all[(rng.next() % all.len() as u64) as usize].1;
                    let frame = FRAMES[(rng.next() % FRAMES.len() as u64) as usize];
                    frame.replace("{}", &format!("{}{key}", rng.pick(&glues)))
                }
                1 => rng.pick(&others).to_string(),
                _ => rng
                    .pick(&["Hello", "Notes:", "x", "task-force", "eyJustice"])
                    .to_string(),
            };
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
        let joint = rng.pick(&["\n", "\r\n", "\t", " ", "", ". "]);
        out.push(parts.join(joint));
    }
    out
}

fn inputs() -> Vec<String> {
    let mut out = seeded();
    out.extend(negatives());
    out.extend(positives().into_iter().map(|(text, _, _)| text));
    // 99 = 11 glues x 9 frames: every frame of every format.
    out.extend(
        format_positives(99, 0x4449_4646_4552_454E)
            .into_iter()
            .map(|(_, text, _, _)| text),
    );
    out
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[String]) -> String {
    let bytes = inputs.iter().flat_map(|text| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

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
    let each = |text: &String| MODES.map(|mode| exact(mode, text)).join("|");
    let records: Vec<String> = inputs.iter().map(each).collect();
    let lines: Vec<String> = records.chunks(64).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// The UUID bytes main masked as an IBAN in the look-alikes and the head gives
/// back, Private and Open (IBAN-UUID-OVERMASK).
const GIVEN_BACK_PRIVATE: usize = 1144;
const GIVEN_BACK_OPEN: usize = 1768;

/// A strict byte superset of main in both modes: no byte main masked is clear,
/// no new refusal, every output reads back exactly, and no look-alike text
/// gains a mask, except the accepted over-mask of [`accepted_overmask`], which
/// is counted and printed.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let main = frozen();
    let negatives = negatives();
    let (mut lost, mut refused, mut unaligned, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    let (mut lookalikes, mut accepted) = (0, [0usize; 2]);
    let mut given_back = [0usize; 2];
    for (text, records) in &main {
        for (index, mode) in MODES.into_iter().enumerate() {
            let before = records[index].as_str();
            let now = exact(mode, text);
            if now == "?" || before == "?" {
                unaligned += 1;
                eprintln!("unaligned {mode:?} {text:?}: main {before} now {now}");
            } else if now == "!" {
                refused += usize::from(before != "!");
            } else {
                let (r, ids) = (parse(&now), uuid_tokens(text));
                let (back, gone): (Vec<usize>, Vec<usize>) = parse(before)
                    .iter()
                    .flat_map(|&(s, e)| s..e)
                    .filter(|&b| !covered(&r, b, b + 1))
                    .partition(|&b| negatives.contains(text) && covered(&ids, b, b + 1));
                let only_back = !back.is_empty() && gone.is_empty() && {
                    let old = parse(before);
                    r.iter().all(|&(s, e)| covered(&old, s, e))
                };
                given_back[index] += back.len();
                let gone = gone.len();
                let changed = now != before && negatives.contains(text);
                let allowed = changed && (accepted_overmask(text) || only_back);
                accepted[index] += usize::from(allowed);
                let lookalike = changed && !allowed;
                if gone > 0 || changed {
                    eprintln!("{mode:?} {text:?}: main {before} now {now}");
                }
                lost[index] += gone;
                grew[index] += usize::from(now != before);
                lookalikes += usize::from(lookalike);
            }
        }
    }
    eprintln!(
        "{} inputs ({} negatives): bytes lost Private/Open {lost:?}; new refusals {refused}; \
         unaligned {unaligned}; texts with new masks Private/Open {grew:?}; look-alikes \
         changed {lookalikes}; accepted over-masks Private/Open {accepted:?}; UUID bytes \
         given back Private/Open {given_back:?}",
        main.len(),
        negatives.len()
    );
    assert!(main.len() >= 1_500 + 1_000 && negatives.len() >= 1_200);
    assert_eq!((lost, refused, unaligned, lookalikes), ([0, 0], 0, 0, 0));
    // Only the look-alike UUIDs main read as IBANs go back, and only them: a
    // new loss on a UUID-shaped value moves this count.
    assert_eq!(given_back, [GIVEN_BACK_PRIVATE, GIVEN_BACK_OPEN]);
}

/// Release only: dense glued keys and near-misses through both gates at 16 KiB,
/// 64 KiB, 256 KiB and 1 MiB, best of three. Bar: each 4x step at most 6x.
#[test]
#[ignore = "release timing: cargo test --release --test prefix_key_glue -- --ignored dense --nocapture"]
fn dense_glued_keys_scale_linearly() {
    if cfg!(debug_assertions) {
        return;
    }
    let glued: String = keys(1)
        .iter()
        .map(|(_, key)| format!("note{key} "))
        .collect();
    let units = [
        glued,
        format!("x{} ", keys(2)[1].1),
        "task-desk-risk-ask-".to_string(),
        "asksk-sk-sk-".to_string(),
        format!("asksk-{}\n", alnum(3, 31)),
        "risk-free desk-top eyJustice Asia ".to_string(),
        format!("ask-{}\nk", "aB1".repeat(20)),
        format_positives(1, 7)
            .into_iter()
            .map(|(_, text, _, _)| text + " ")
            .collect(),
        format!("tasksk-{}-", "a1".repeat(16)),
        "asksl.u.sl.u.sk-or-v1-".to_string(),
        format!("notesk-{}-prod ", "0123456789abcdef".repeat(2)),
        format!("high-risk-\nnotesk-{}_ ", "fedcba9876543210".repeat(2)),
    ];
    for unit in units {
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
            assert!(ratio <= 6.0, "{size} bytes scales {ratio:.2}");
            last = best;
        }
    }
}
