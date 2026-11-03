//! SECRET-1 acceptance: a cookie value, a secret on the line after its label, a
//! value in a CSV/TSV column whose header names a secret, and a lower-case AWS
//! key id glued to a word are hidden in both modes; their names, labels and
//! headers stay clear; lookalike prose and tables gain no mask; and the CSV
//! column scan is linear. Every mask is read with the shared exact reader
//! (`data/exact_mask.rs`). All values are invented (the leak-finder's fictional
//! strings; the AWS key is the AWS documentation example).

use std::time::{Duration, Instant};

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

/// `(text, value that must be hidden, clear words that must stay)`.
fn positives() -> Vec<(&'static str, &'static str, &'static [&'static str])> {
    vec![
        // 1. Cookies.
        (
            "sessionid=7f3a9c2e4b1d8f60a5c3e9b2",
            "7f3a9c2e4b1d8f60a5c3e9b2",
            &["sessionid"],
        ),
        (
            "Cookie: sessionid=7f3a9c2e4b1d8f60a5c3e9b2",
            "7f3a9c2e4b1d8f60a5c3e9b2",
            &[],
        ),
        (
            "Set-Cookie: user_session=Qm9vay1zaGVsZi0yMDI2; Path=/",
            "Qm9vay1zaGVsZi0yMDI2",
            &[],
        ),
        (
            "prefs=k2Lp9xQe7Rv3Wm8T; Path=/; HttpOnly",
            "k2Lp9xQe7Rv3Wm8T",
            &[],
        ),
        (
            "Your cookie is PHPSESSID=a8c3e9b27f3a9c2e4b1d and it expires soon.",
            "a8c3e9b27f3a9c2e4b1d",
            &["expires"],
        ),
        (
            "JSESSIONID=9C2E4B1D8F60A5C3E9B27F3A",
            "9C2E4B1D8F60A5C3E9B27F3A",
            &["JSESSIONID"],
        ),
        (
            "connect.sid=s%3Ab1d8f60a5c3e9b2.7f3a9c2e",
            "s%3Ab1d8f60a5c3e9b2.7f3a9c2e",
            &["connect.sid"],
        ),
        (
            "csrftoken=Zx81mNq02LpWv7Ks",
            "Zx81mNq02LpWv7Ks",
            &["csrftoken"],
        ),
        (
            "Cookie: theme=dark; remember_token=e4b1d8f60a5c3e9b", // gitleaks:allow
            "e4b1d8f60a5c3e9b",
            &[],
        ),
        // 2. A label on its own line, the value on the next.
        (
            "Passphrase\nviolet tractor humming seventy",
            "violet tractor humming seventy",
            &["Passphrase"],
        ),
        (
            "Passphrase\r\nviolet tractor humming seventy",
            "violet tractor humming seventy",
            &["Passphrase"],
        ),
        ("Password\nTr0ub4dor&3x", "Tr0ub4dor&3x", &["Password"]),
        ("PIN\n4821", "4821", &["PIN"]),
        (
            "API key\n3f9a1c7e5b2d8f40a6c4e2b9d1f7a3c5",
            "3f9a1c7e5b2d8f40a6c4e2b9d1f7a3c5",
            &["API key"],
        ),
        ("Secret\nb4nana-Sl1de-77", "b4nana-Sl1de-77", &["Secret"]),
        (
            "Mot de passe\nCh4teau!Blanc",
            "Ch4teau!Blanc",
            &["Mot de passe"],
        ),
        (
            "Phrase secrète\ncerise lune papier vingt",
            "cerise lune papier vingt",
            &["Phrase secrète"],
        ),
        // 3. CSV/TSV columns named by a secret header.
        (
            "id,password,city\n17,Tr0ub4dor&3x,Lyon",
            "Tr0ub4dor&3x",
            &["password", "Lyon"],
        ),
        (
            "id,api_key,city\n17,3f9a1c7e5b2d8f40a6c4e2b9d1f7a3c5,Lyon",
            "3f9a1c7e5b2d8f40a6c4e2b9d1f7a3c5",
            &["api_key", "Lyon"],
        ),
        (
            "id,Password,city\n17,Tr0ub4dor&3x,Lyon\n18,plainword,Nice",
            "plainword",
            &["Password", "Nice"],
        ),
        (
            "id\tAPI-Key\tcity\n17\tk2Lp9xQe7Rv3Wm8T\tLyon",
            "k2Lp9xQe7Rv3Wm8T",
            &["API-Key", "Lyon"],
        ),
        ("user;pin;city\nana;4821;Lyon", "4821", &["pin", "Lyon"]),
        (
            "name,Private Key,note\nbox,MIIEvQIBADANBgkqhkiG9w0B,ok",
            "MIIEvQIBADANBgkqhkiG9w0B",
            &["Private Key"],
        ),
        // 4. A lower-case AWS key id glued to a word suffix.
        ("akiaiosfodnn7exampleok", "akiaiosfodnn7example", &[]),
        (
            "key akiaiosfodnn7example in the log",
            "akiaiosfodnn7example",
            &["log"],
        ),
        ("ASIAIOSFODNN7EXAMPLEok", "ASIAIOSFODNN7EXAMPLE", &[]),
    ]
}

/// Texts that must stay exactly as they are in both modes.
const NEGATIVES: &[&str] = &[
    "the session was long",
    "password reset email",
    "PIN code required",
    "id,name,city\n17,Ana,Lyon\n18,Bo,Nice",
    "Password\n",
    "Password\n\nThe meeting moved to Tuesday.",
    "theme=dark",
    "size=12; color=blue",
    "sessionid=short",
    "akiaiosfodnn7exampl",
    "token,count\n,3",
];

#[test]
fn secret_1_repros_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, value, keep) in positives() {
        let start = text.find(value).expect("value in text");
        for mode in MODES {
            let Some(ranges) = masked(mode, text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            if !covered(&ranges, start, start + value.len()) {
                wrong.push(format!("{mode:?} {text:?}: value not hidden {ranges:?}"));
            }
            for word in keep {
                let at = text.find(word).expect("kept word in text");
                if ranges.iter().any(|&(s, e)| s < at + word.len() && at < e) {
                    wrong.push(format!("{mode:?} {text:?}: {word:?} masked {ranges:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Round 1 of the seal: `(text, value, clear words)`.
fn round_1() -> Vec<(String, String, Vec<&'static str>)> {
    let phrase = "cedar valley ink orbit";
    let long = |n: usize| "birch7willow".repeat(27)[..n].to_string();
    let mut all: Vec<(String, String, Vec<&'static str>)> = Vec::new();
    // 1. A bullet or a number before the label; punctuation in the value.
    for label in [
        "- Passphrase",
        "* Passphrase",
        "• Passphrase",
        "1. Passphrase",
        "2) Passphrase",
    ] {
        all.push((
            format!("{label}\n{phrase}"),
            phrase.into(),
            vec!["Passphrase"],
        ));
    }
    all.push((
        "- Password\nTr0ub4dor&3x".into(),
        "Tr0ub4dor&3x".into(),
        vec!["Password"],
    ));
    for value in [
        "cedar valley ink orbit!",
        "cedar valley ink orbit?",
        "cedar @valley #ink orbit",
        "cedar valley ink orbit.",
    ] {
        all.push((
            format!("Passphrase\n{value}"),
            value.into(),
            vec!["Passphrase"],
        ));
    }
    // 2. A quoted delimiter in the header; a second table under the first.
    all.push((
        "id\t\"last, first\"\tpassword\n17\tfield\tcobalt-moon-lake".into(),
        "cobalt-moon-lake".into(),
        vec!["password", "last, first", "field"],
    ));
    all.push((
        "id,password,city\n17,cobalt-moon-lake,Lyon\npassword,city,id\namber-fox-trail,Nice,18"
            .into(),
        "amber-fox-trail".into(),
        vec![],
    ));
    // 3. Values at and over 256 bytes.
    for n in [256, 257, 312] {
        all.push((
            format!("laravel_session={}", long(n)),
            long(n),
            vec!["laravel_session"],
        ));
        all.push((
            format!("Cookie: sid={}; Path=/", long(n)),
            long(n),
            vec!["Cookie"],
        ));
        all.push((
            format!("id\tpassword\n17\t{}", long(n)),
            long(n),
            vec!["id"],
        ));
        all.push((format!("Password\n{}", long(n)), long(n), vec!["Password"]));
    }
    // 4. An all-letter AWS id body glued to a suffix.
    all.push((
        "akiamnbvcxzlkjhgfdsaok".into(),
        "akiamnbvcxzlkjhgfdsa".into(),
        vec![],
    ));
    all.push((
        "key akiamnbvcxzlkjhgfdsa.".into(),
        "akiamnbvcxzlkjhgfdsa".into(),
        vec!["key"],
    ));
    // 5. Header names and delimiters stay; only cell values go.
    // Main's older key rule already masks the `city` after `passphrase`;
    // a strict superset keeps that mask.
    all.push((
        "id,passphrase,city\n17,cedar valley ink orbit,Lyon".into(),
        phrase.into(),
        vec!["id,passphrase,", "Lyon"],
    ));
    all.push((
        "id\tpassphrase\tcity\n17\tcedar valley ink orbit\tLyon".into(),
        phrase.into(),
        vec!["id\tpassphrase\t", "Lyon"],
    ));
    all
}

#[test]
fn round_1_values_are_hidden_and_labels_kept_in_both_modes() {
    let mut wrong = Vec::new();
    for (text, value, keep) in round_1() {
        let start = text.rfind(value.as_str()).expect("value in text");
        for mode in MODES {
            let Some(ranges) = masked(mode, &text) else {
                wrong.push(format!("{mode:?} refused {text:?}"));
                continue;
            };
            if !covered(&ranges, start, start + value.len()) {
                wrong.push(format!("{mode:?} {text:?}: value not hidden {ranges:?}"));
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

/// Prose and words that start like an AWS id, and bullet prose, stay clear.
const ROUND_1_NEGATIVES: &[&str] = &[
    "akiapolaaubirdwatchers",
    "akiakeepsmovingforward",
    "the akiakamaainalandscapes tour",
    "asiaticmonsoonpatterns",
    "- Passphrase\nChoose one you can remember.",
    "1. Password\n",
];

/// A secret header alone: main masks `city` (bytes 14..18) and nothing else, and
/// so must the branch: the delimiters and the other names stay.
const HEADER_ONLY: &str = "id,passphrase,city";

#[test]
fn a_header_line_gains_no_mask_over_main() {
    for mode in MODES {
        assert_eq!(masked(mode, HEADER_ONLY), Some(vec![(14, 18)]), "{mode:?}");
    }
}

#[test]
fn round_1_lookalikes_stay_clear() {
    let mut wrong = Vec::new();
    // SECRET-2: the line after a label is its value, a sentence too.
    let value_now = "- Passphrase\nChoose one you can remember.";
    for text in ROUND_1_NEGATIVES.iter().filter(|t| **t != value_now) {
        for mode in MODES {
            match masked(mode, text) {
                Some(r) if r.is_empty() => {}
                other => wrong.push(format!("{mode:?} {text:?}: {other:?}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The leak-finder's remaining passphrase form: the words in brackets after
/// the key, on the same line. Kept out of [`positives`], whose texts are frozen.
#[test]
fn a_bracketed_passphrase_is_hidden_in_both_modes() {
    let text = "Re: your Passphrase (violet tractor humming seventy)";
    let start = text.find("violet").expect("value");
    for mode in MODES {
        let ranges = masked(mode, text).expect("issued");
        assert!(
            covered(&ranges, start, text.len() - 1),
            "{mode:?} {ranges:?}"
        );
        assert!(
            !ranges.iter().any(|&(s, _)| s < start - 1),
            "{mode:?} {ranges:?}"
        );
    }
}

#[test]
fn secret_1_lookalikes_stay_clear() {
    let mut wrong = Vec::new();
    for text in NEGATIVES {
        for mode in MODES {
            match masked(mode, text) {
                Some(r) if r.is_empty() => {}
                other => wrong.push(format!("{mode:?} {text:?}: {other:?}")),
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Every value row of a secret column is hidden, and the other columns stay.
#[test]
fn every_row_of_a_secret_column_is_hidden() {
    let mut text = String::from("id,passwd,city\n");
    let mut values = Vec::new();
    for i in 0..50 {
        let value = format!("Pw{i:03}x{}", i * 7);
        text.push_str(&format!("{i},{value},Town{i}\n"));
        values.push(value);
    }
    for mode in MODES {
        let ranges = masked(mode, &text).expect("issued");
        for value in &values {
            let at = text.find(&format!(",{value},")).expect("row") + 1;
            assert!(covered(&ranges, at, at + value.len()), "{mode:?} {value}");
        }
        let town = text.find("Town7").expect("town");
        assert!(!ranges.iter().any(|&(s, e)| s < town + 5 && town < e));
    }
}

fn table(rows: usize) -> String {
    let mut text = String::from("id,token,city\n");
    for i in 0..rows {
        text.push_str(&format!("{i},t{i:08}q,Lyon\n"));
    }
    text
}

fn time(text: &str) -> Duration {
    let start = Instant::now();
    let _ = masked(PrivacyMode::Private, text).expect("issued");
    start.elapsed()
}

/// 10× the rows costs at most 20× the time (best of three).
#[test]
fn secret_column_scan_is_linear() {
    let small = table(1_000);
    let large = table(10_000);
    let best = |t: &str| (0..3).map(|_| time(t)).min().expect("three runs");
    let (s, l) = (best(&small), best(&large));
    assert!(
        l <= s * 20 + Duration::from_millis(50),
        "1k rows {s:?}, 10k rows {l:?}"
    );
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
    "Send the secret santa list to Ana.",
    "My password is Tr0ub4dor&3x, keep it.",
    "api_key=3f9a1c7e5b2d8f40a6c4e2b9d1f7a3c5", // gitleaks:allow
    "The token expired at noon.",
    "Call +33 6 12 34 56 78 about the invoice.",
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "ana@example.invalid wrote back.",
    "",
];
const PAIRS: &[&str] = &[
    "sessionid=7f3a9c2e4b1d8f60a5c3e9b2",
    "Cookie: sessionid=7f3a9c2e4b1d8f60a5c3e9b2",
    "Set-Cookie: user_session=Qm9vay1zaGVsZi0yMDI2; Path=/",
    "theme=dark; Path=/; HttpOnly",
    "sid=12345678",
    "token=abc",
    "session=afternoon tea",
    "Cookie: lang=fr; csrftoken=Zx81mNq02LpWv7Ks",
];
const LABELS: &[&str] = &[
    "Passphrase",
    "Password",
    "PIN",
    "API key",
    "Secret",
    "Mot de passe",
    "Phrase secrète",
    "Notes",
    "Password:",
];
const LINES: &[&str] = &[
    "violet tractor humming seventy",
    "Tr0ub4dor&3x",
    "4821",
    "Change it every month.",
    "",
    "see the vault",
];
const HEADERS: &[&str] = &[
    "id,password,city",
    "id,api_key,city",
    "id,name,city",
    "id\ttoken\tcity",
    "user;pin;city",
    "id,Secret,note",
    "id,count,total",
    "| id | token | city |",
];
const CELLS: &[&str] = &[
    "17",
    "Tr0ub4dor&3x",
    "Lyon",
    "",
    "4821",
    "k2Lp9xQe7Rv3Wm8T",
    "Ana",
];
const AWS: &[&str] = &[
    "akiaiosfodnn7exampleok",
    "AKIAIOSFODNN7EXAMPLE",
    "asiaiosfodnn7example",
    "asianfusionrestaurants",
    "xakiaiosfodnn7example",
];

/// One seeded input: a few lines drawn from every form, prose between them.
fn seeded(seed: u64) -> String {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut text = String::new();
    for _ in 0..(1 + rng.next() % 3) {
        match rng.next() % 5 {
            0 => text.push_str(rng.pick(PROSE)),
            1 => text.push_str(rng.pick(PAIRS)),
            2 => {
                let label = rng.pick(LABELS);
                let eol = if rng.next().is_multiple_of(2) {
                    "\n"
                } else {
                    "\r\n"
                };
                text.push_str(&format!("{label}{eol}{}", rng.pick(LINES)));
            }
            3 => {
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

fn inputs() -> Vec<String> {
    let mut all: Vec<String> = NEGATIVES.iter().map(|s| (*s).to_string()).collect();
    all.extend(positives().into_iter().map(|(text, _, _)| text.to_string()));
    all.extend(round_1().into_iter().map(|(text, _, _)| text));
    all.extend(ROUND_1_NEGATIVES.iter().map(|s| (*s).to_string()));
    all.push(HEADER_ONLY.to_string());
    all.extend((0..2_000).map(seeded));
    all
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

const FIXTURE: &str = include_str!("data/secret_1_main.txt");

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = inputs();
    let each = |text: &String| MODES.map(|mode| record(mode, text)).join("|");
    let records: Vec<String> = inputs.iter().map(each).collect();
    let lines: Vec<String> = records.chunks(64).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// A strict byte superset of main in both modes: no byte main masked is clear,
/// no new refusal, and every output reads back exactly.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
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
                refused += usize::from(before != "!");
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
