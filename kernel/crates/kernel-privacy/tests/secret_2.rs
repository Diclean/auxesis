//! SECRET-2 acceptance: the follow-ups to SECRET-1 (#288). A sentence
//! on the line after a secret label is its value; a quoted CSV cell may span
//! lines; a long password made of rule bytes is no divider; an all-letter
//! lower-case AWS id with five vowels is an id; `Passphrase: words!` on one line
//! is hidden; a password that reads `secret` on a row that names columns is
//! hidden. Prose and traps stay clear, and the result is a strict byte superset
//! of the main fixture in both modes. Every value is invented.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

/// `(text, values that must be hidden, clear words that must stay)`.
fn positives() -> Vec<(String, Vec<String>, Vec<&'static str>)> {
    let rule = "=:-".repeat(104);
    let own = |t: &str, v: &[&str], k: &[&'static str]| {
        (
            t.to_string(),
            v.iter().map(|s| (*s).to_string()).collect(),
            k.to_vec(),
        )
    };
    vec![
        // 2. A sentence after its label is still the value.
        own("Password\nMy dog Rex.", &["My dog Rex."], &["Password"]),
        own("Passphrase\nMy dog Rex.", &["My dog Rex."], &["Passphrase"]),
        own(
            "- Passphrase\nChoose one you can remember.",
            &["Choose one you can remember."],
            &["Passphrase"],
        ),
        own("PIN\r\nThe year we met.", &["The year we met."], &["PIN"]),
        own("Password\nPIN\n4821", &["PIN", "4821"], &["Password"]),
        // 3. A quoted cell across lines keeps the record whole.
        own(
            "id,password,note\n8,Cherry6!,\"ordered\nagain\"\n9,Forest6!,ready",
            &["Cherry6!", "Forest6!"],
            &["id,password,", "ordered", "ready"],
        ),
        own(
            "id,password,note\n8,\"Cher\nry6!\",ok\n9,Forest6!,ready",
            &["Cher\nry6!", "Forest6!"],
            &["id,password,", "ready"],
        ),
        // 4. A long password of rule bytes is no separator row.
        (
            format!("id,password,city\n1,{rule},Oslo"),
            vec![rule.clone()],
            vec!["Oslo", "id,password,"],
        ),
        own(
            "| id | password |\n|----|----------|\n| 1 | Tr0ub4dor&3x |\n| 2 | ---- |",
            &["Tr0ub4dor&3x", "| ---- |"],
            &["|----|----------|"],
        ),
        // 5. All-letter AWS ids, five vowels at most.
        own("asiabcdfghjklmnpqrstsuffix", &["asiabcdfghjklmnpqrst"], &[]),
        own("akiabcadfegihjoklpumsuffix", &["akiabcadfegihjoklpum"], &[]),
        // 6. Same-line passphrase with `!`/`?`; a secret-named password cell.
        own("Passphrase: words!", &["words!"], &["Passphrase"]),
        own(
            "Passphrase: cedar valley ink orbit?",
            &["cedar valley ink orbit?"],
            &["Passphrase"],
        ),
        own(
            "id,password,note\n1,secret,token",
            &["secret"],
            &["id,password,"],
        ),
        own("id,password,note\n2,pin,ready", &["pin"], &["id,password,"]),
    ]
}

/// The `| ---- |` value above is the cell between its bars.
fn find_value(text: &str, value: &str) -> (usize, usize) {
    let at = text.rfind(value).expect("value in text");
    match value.strip_prefix("| ").and_then(|v| v.strip_suffix(" |")) {
        Some(inner) => (at + 2, at + 2 + inner.len()),
        None => (at, at + value.len()),
    }
}

#[test]
fn secret_2_repros_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, values, keep) in positives() {
        for mode in MODES {
            let Some(ranges) = masked(mode, &text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            for value in &values {
                let (start, end) = find_value(&text, value);
                if !covered(&ranges, start, end) {
                    wrong.push(format!("{mode:?} {text:?}: {value:?} clear {ranges:?}"));
                }
            }
            for word in &keep {
                let at = text.find(word).expect("kept word in text");
                if ranges.iter().any(|&(s, e)| s < at + word.len() && at < e) {
                    wrong.push(format!("{mode:?} {text:?}: {word:?} masked {ranges:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Prose and traps that must stay exactly as main leaves them in both modes
/// (main's older key rule already masks a few words of three of them).
const NEGATIVES: &[&str] = &[
    "the session was long",
    "password reset email",
    "PIN code required",
    "Password\n\nThe meeting moved to Tuesday.",
    "Password\nChange it every month and never share it with anyone at all.",
    "Passphrase: pick four random words and keep them safe.",
    "Passphrase protection is on for every account.",
    "| token | count |\n|---|---|\n| | 3 |",
    "id,token,count\n,,3\n---,---,---",
    "akiapolaaubirdwatchers",
    "akiakeepsmovingforward",
    "the akiakamaainalandscapes tour",
    "asiaticmonsoonpatterns",
    "asianfusionrestaurants",
];

#[test]
fn secret_2_lookalikes_match_main() {
    let body = FIXTURE.split_once('\n').expect("fixture header").1;
    let main: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    let mut wrong = Vec::new();
    // Round 1: a value line after a label holds up to sixteen words now.
    let value_now = "Password\nChange it every month and never share it with anyone at all.";
    for (text, main) in NEGATIVES.iter().zip(main) {
        if *text == value_now {
            continue;
        }
        let now = MODES.map(|mode| record(mode, text)).join("|");
        if now != main {
            wrong.push(format!("{text:?}: main {main} now {now}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
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

const PROSE: &[&str] = &[
    "the session was long",
    "password reset email",
    "PIN code required",
    "My password is Tr0ub4dor&3x, keep it.",
    "Call +33 6 12 34 56 78 about the invoice.",
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "ana@example.invalid wrote back.",
    "Passphrase: words!",
    "Passphrase: pick four random words and keep them safe.",
    "Cookie: theme=dark; sid=7f3a9c2e4b1d8f60",
    "",
];
const LABELS: &[&str] = &[
    "Passphrase",
    "Password",
    "- PIN",
    "Secret",
    "API key:",
    "Notes",
];
const LINES: &[&str] = &[
    "My dog Rex.",
    "Tr0ub4dor&3x",
    "4821",
    "PIN",
    "Change it every month.",
    "Change it every month and never share it with anyone at all.",
    "",
    "Password:",
];
const HEADERS: &[&str] = &[
    "id,password,note",
    "id,name,city",
    "id\ttoken\tcity",
    "| id | token | city |",
    "user;pin;city",
];
const CELLS: &[&str] = &[
    "17",
    "Cherry6!",
    "\"ordered\nagain\"",
    "\"a,b\"",
    "\"open",
    "=:-=:-=:-",
    "---",
    "secret",
    "token",
    "",
    "Lyon",
];
const AWS: &[&str] = &[
    "asiabcdfghjklmnpqrstsuffix",
    "akiabcadfegihjoklpumsuffix",
    "akiapolaaubirdwatchers",
    "asiaticmonsoonpatterns",
    "AKIAIOSFODNN7EXAMPLE",
    "xasiabcdfghjklmnpqrst",
];

/// One seeded input: a few lines drawn from every form, prose between them.
fn seeded(seed: u64) -> String {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut text = String::new();
    for _ in 0..(1 + rng.next() % 3) {
        match rng.next() % 4 {
            0 => text.push_str(rng.pick(PROSE)),
            1 => {
                let eol = if rng.next().is_multiple_of(2) {
                    "\n"
                } else {
                    "\r\n"
                };
                text.push_str(&format!("{}{eol}{}", rng.pick(LABELS), rng.pick(LINES)));
            }
            2 => {
                let header = rng.pick(HEADERS);
                let delim = [",", "\t", ";", "|"]
                    .into_iter()
                    .find(|d| header.contains(d))
                    .expect("a delimiter");
                text.push_str(header);
                for _ in 0..(1 + rng.next() % 3) {
                    let row: Vec<&str> = (0..header.split(delim).count())
                        .map(|_| rng.pick(CELLS))
                        .collect();
                    text.push('\n');
                    text.push_str(&row.join(delim));
                }
            }
            _ => text.push_str(rng.pick(AWS)),
        }
        text.push_str(rng.pick(&["\n", " ", "\n\n", ". "]));
    }
    text
}

/// Round 1 of the seals on 82fcb3ef (a security review): `(text, values hidden)`.
fn round_1() -> Vec<(String, Vec<String>)> {
    let mut all: Vec<(String, Vec<String>)> = Vec::new();
    let own = |t: String, v: &[&str]| (t, v.iter().map(|s| (*s).to_string()).collect());
    // 1-2. Label lines: long passphrases, colon ends, nine words.
    let long = |a: usize, b: usize| format!("{} {}", "q".repeat(a), "z".repeat(b));
    for label in ["Passphrase", "Phrase secrète", "Password", "- Passphrase"] {
        for value in [long(63, 64), long(64, 64), long(100, 200)] {
            all.push(own(format!("{label}\n{value}"), &[&value]));
        }
    }
    for label in ["Password", "Passphrase", "Secret", "PIN"] {
        for value in [
            "My dog Rex:",
            "one two three four five six seven eight nine",
            "My dog Rex is nine and he loves the park.",
        ] {
            all.push(own(format!("{label}\n{value}"), &[value]));
        }
    }
    // 3. Long quoted records, then a later row.
    for lines in [15, 16, 17, 40] {
        let note = format!("{}done", "part\n".repeat(lines));
        all.push(own(
            format!("id,password,note\n8,Cherry6!,\"{note}\"\n9,Forest6!,ready"),
            &["Cherry6!", "Forest6!"],
        ));
    }
    for bytes in [4_090, 4_100, 9_000] {
        let note = format!("{}\nend", "p".repeat(bytes));
        all.push(own(
            format!("id,password,note\n8,Cherry6!,\"{note}\"\n9,Forest6!,ready"),
            &["Cherry6!", "Forest6!"],
        ));
    }
    // 4. Literal secret names as passwords, on letter and number rows.
    for header in [
        "id,password,note",
        "user,password,note",
        "user\tpassword\tnote",
    ] {
        let delim = if header.contains('\t') { "\t" } else { "," };
        for user in ["alice", "admin", "17"] {
            for value in ["secret", "token", "pin"] {
                for note in ["token", "ready"] {
                    let row = [user, value, note].join(delim);
                    let at = header.len() + 1 + user.len() + 1;
                    let text = format!("{header}\n{row}");
                    all.push((text, vec![format!("@{at}:{value}")]));
                }
            }
        }
    }
    // 5. All-letter AWS ids with many vowels.
    for key in ["asiabcadfegihjoklpua", "akiabcadfegihjoklpua"] {
        all.push(own(format!("{key}suffix"), &[key]));
        all.push(own(format!("key {key} here"), &[key]));
    }
    all
}

/// Inputs from the generators that only feed the main differential.
fn generated() -> Vec<String> {
    let mut all = Vec::new();
    for columns in [3, 50, 400] {
        all.push(format!(
            "id,{}note\n1,{}token",
            "password,".repeat(columns),
            "secret,".repeat(columns)
        ));
        all.push(format!(
            "id,{}note\nalice,{}ok",
            "password,".repeat(columns),
            "Pw9x!,".repeat(columns)
        ));
    }
    for lines in [1, 3, 16, 17] {
        for cell in ["\"open", "\"a\nb\"", "x"] {
            all.push(format!(
                "id,token,note\n1,{cell},{}\n2,Forest6!,ok\n3,\"Pine\n7!\",ok",
                "l\n".repeat(lines)
            ));
        }
    }
    for body in [
        "polaaubirdwatchers",
        "keepsmovingforward",
        "ticmonsoonpatterns",
    ] {
        all.push(format!("akia{body}"));
        all.push(format!("asia{body}"));
    }
    all
}

fn inputs() -> Vec<String> {
    let mut all: Vec<String> = NEGATIVES.iter().map(|s| (*s).to_string()).collect();
    all.extend(positives().into_iter().map(|(text, _, _)| text));
    all.extend((0..2_000).map(seeded));
    all.extend(round_1().into_iter().map(|(text, _)| text));
    all.extend(generated());
    all
}

/// A value is found by its text, or at `@at:` when the same word is earlier.
fn value_range(text: &str, value: &str) -> (usize, usize) {
    match value.strip_prefix('@').and_then(|v| v.split_once(':')) {
        Some((at, word)) => {
            let at: usize = at.parse().expect("offset");
            assert_eq!(&text[at..at + word.len()], word, "{text:?}");
            (at, at + word.len())
        }
        None => {
            let at = text.rfind(value).expect("value in text");
            (at, at + value.len())
        }
    }
}

#[test]
fn round_1_repros_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, values) in round_1() {
        for mode in MODES {
            let Some(ranges) = masked(mode, &text) else {
                wrong.push(format!("{mode:?} refused {text:.80?}"));
                continue;
            };
            for value in &values {
                let (start, end) = value_range(&text, value);
                if !covered(&ranges, start, end) {
                    wrong.push(format!("{mode:?} {text:.80?}: {value:.40?} clear"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// One mode's record of `input`: `start-end,` ranges; `!` a refusal; `?` an
/// output that does not read back.
fn record(mode: PrivacyMode, input: &str) -> String {
    let Some((output, minted)) = norm1::issue(mode, input) else {
        return "!".into();
    };
    norm1::exact_ranges(mode, input, &output, &minted).map_or("?".into(), |r| {
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

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[String]) -> String {
    let bytes = inputs.iter().flat_map(|text| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

const FIXTURE: &str = include_str!("data/secret_2_main.txt");

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    dump(&inputs());
}

#[test]
#[ignore = "freezes the table fixture: run on origin/main only"]
fn freeze_tables() {
    dump(&tables());
}

fn dump(inputs: &[String]) {
    let each = |text: &String| MODES.map(|mode| record(mode, text)).join("|");
    let records: Vec<String> = inputs.iter().map(each).collect();
    let lines: Vec<String> = records.chunks(64).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(inputs),
        lines.join("\n")
    );
}

/// A strict byte superset of main in both modes: no byte main masked is clear,
/// no new refusal, and every output reads back exactly.
#[test]
fn strict_superset_of_main_in_both_modes() {
    superset(&inputs(), FIXTURE);
}

/// The same on the SECRET-TABLE generator (round 2).
#[test]
fn strict_superset_of_main_on_secret_tables() {
    superset(&tables(), TABLES_FIXTURE);
}

const TABLES_FIXTURE: &str = include_str!("data/secret_2_tables_main.txt");

fn superset(inputs: &[String], fixture: &str) {
    let (head, body) = fixture.split_once('\n').expect("fixture header");
    assert_eq!(head, header(inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused, mut unaligned, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    for (text, main) in inputs.iter().zip(records) {
        let main: Vec<&str> = main.split('|').collect();
        for (index, mode) in MODES.into_iter().enumerate() {
            let (before, now) = (main[index], record(mode, text));
            if now == "?" || before == "?" {
                unaligned += 1;
                eprintln!("unaligned {mode:?} {text:?}: main {before} now {now}");
            } else if now == "!" {
                if before != "!" {
                    refused += 1;
                    eprintln!("refused {mode:?} {text:?}: main {before}");
                }
            } else {
                let r = parse(&now);
                let gone = parse(before)
                    .iter()
                    .flat_map(|&(s, e)| s..e)
                    .filter(|&b| !covered(&r, b, b + 1))
                    .count();
                if gone > 0 {
                    eprintln!("{mode:?} {text:?}: main {before} now {now}");
                }
                lost[index] += gone;
                grew[index] += usize::from(now != before);
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; unaligned \
         {unaligned}; texts with new masks Private/Open {grew:?}",
        inputs.len()
    );
    assert_eq!((lost, refused, unaligned), ([0, 0], 0, 0));
}

/// The tail shape: `columns` password columns, then one row of `secret`s.
fn tail(columns: usize) -> String {
    format!(
        "id,{}note\n1,{}token",
        "password,".repeat(columns),
        "secret,".repeat(columns)
    )
}

/// The whole gate on 1 MiB costs at most 20× what it costs on 1/10 of it.
#[test]
fn the_gate_scales_linearly_on_a_wide_secret_table() {
    use std::time::{Duration, Instant};
    let time = |text: &str| {
        let start = Instant::now();
        let _ = masked(PrivacyMode::Open, text).expect("issued");
        start.elapsed()
    };
    let (small, large) = (tail(6_554), tail(65_536));
    assert!(large.len() >= 1 << 20);
    let (s, l) = (time(&small), time(&large));
    assert!(
        l <= s * 20 + Duration::from_millis(200),
        "100 KB {s:?}, 1 MiB {l:?}"
    );
}

/// SECRET-TABLE (round 2): tab, comma and semicolon tables with secret
/// columns, broken and unclosed quotes, header-like rows and secret names as
/// cells, after a cookie or prose or alone.
fn tables() -> Vec<String> {
    const NAMES: &[&str] = &[
        "password", "api key", "pwd", "pin", "token", "secret", "id", "name", "count", "note",
    ];
    const CELLS: &[&str] = &[
        "Cherry6!",
        "Tr0ub4dor&3x",
        "9f8e7d6c5b4a",
        "346",
        "Hunter2x",
        "secret",
        "token",
        "pin",
        "password",
        "alice",
        "",
        "---",
        "\"open",
        "\"a,b\"",
        "\"9f8e\t\"x",
        "\"x\ny\"",
        "346\"",
    ];
    const LEADS: &[&str] = &["", "PHPSESSID=fkqw9zjx1nwmsor4equmtq7k67a3 ", "Notes: "];
    let mut all = Vec::new();
    for seed in 0..3_000u64 {
        let mut rng = Rng(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
        let delim = ["\t", ",", ";"][(rng.next() % 3) as usize];
        let width = 2 + (rng.next() % 4) as usize;
        let mut text = rng.pick(LEADS).to_string();
        let head: Vec<&str> = (0..width).map(|_| rng.pick(NAMES)).collect();
        text.push_str(&head.join(delim));
        for _ in 0..(1 + rng.next() % 4) {
            let row: Vec<&str> = if rng.next().is_multiple_of(5) {
                (0..width).map(|_| rng.pick(NAMES)).collect()
            } else {
                (0..width).map(|_| rng.pick(CELLS)).collect()
            };
            text.push('\n');
            text.push_str(&row.join(delim));
        }
        if rng.next().is_multiple_of(3) {
            text.push_str(rng.pick(&["\n", "\n\nThe end.", "\nCall +33 6 12 34 56 78."]));
        }
        all.push(text);
    }
    all
}

/// A quoted row that breaks a secret table, and a
/// secret name beside a password: `(text, value)`, both modes.
#[test]
fn round_2_rows_are_hidden_in_both_modes() {
    let cookie = "PHPSESSID=fkqw9zjx1nwmsor4equmtq7k67a3 ";
    let cases = [
        (
            "password\tapi key\nCherry6!\tpin\n\"9f8e7d6c5b4a\t\"Tr0ub4dor&3x".to_string(),
            "Tr0ub4dor&3x",
        ),
        (
            "password,api key\nCherry6!,pin\n\"9f8e7d6c5b4a,\"Tr0ub4dor&3x".to_string(),
            "Tr0ub4dor&3x",
        ),
        (
            format!("{cookie}secret;name;secret;pwd\nCherry6!;and;secret;\"Tr0ub4dor&3x\n346\""),
            "Cherry6!",
        ),
        (
            format!("{cookie}pwd,api key,id\nS3cret!,token,token\n"),
            "S3cret!",
        ),
        (
            "pwd\tcount\tcount\tpwd\tapi key\nHunter2x\t\"346\t916\t9f8e7d6c5b4a\tsecret"
                .to_string(),
            "9f8e7d6c5b4a",
        ),
        (
            "pwd,count,count,pwd,api key\nHunter2x,\"346,916,9f8e7d6c5b4a,secret".to_string(),
            "9f8e7d6c5b4a",
        ),
    ];
    let mut wrong = Vec::new();
    for (text, value) in cases {
        let at = text.rfind(value).expect("value");
        for mode in MODES {
            match masked(mode, &text) {
                Some(r) if covered(&r, at, at + value.len()) => {}
                other => wrong.push(format!("{mode:?} {text:?}: {value} {other:?}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
