//! SECRET-LEAK-294B, the whole column: every value under a password-named
//! header is hidden in Private and Open, however the table is laid out (header
//! names, quotes, `,` `;` tab `|` separators, markdown, JSON objects, column
//! order, empty cells, a repeated header, CRLF) or however long it is. Look-alike
//! columns and prose stay clear. Every value is invented.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

/// Values a password column holds, short dictionary words included.
const VALUES: [&str; 5] = ["Tr0ub4dor&3x", "secret", "sunshine", "hunter2", "4821"];

/// Header names of a password-like column.
const HEADERS: [&str; 16] = [
    "password",
    "Password",
    "PASSWORD",
    "passwd",
    "pwd",
    "pass",
    "Pass",
    "mot de passe",
    "mdp",
    "secret",
    "PIN",
    "token",
    "api key",
    "API Key",
    "api_key",
    "apikey",
];

/// Each `(case, mode)` where the last `value` of `text` stays clear or the gate
/// refuses.
fn leaks(text: &str, value: &str) -> Vec<String> {
    let at = text.rfind(value).expect("value");
    let short: String = text.chars().take(70).collect();
    MODES
        .into_iter()
        .filter(|&mode| masked(mode, text).is_none_or(|r| !covered(&r, at, at + value.len())))
        .map(|mode| format!("{short:?} [{value}]: clear in {mode:?}"))
        .collect()
}

fn check(cases: impl IntoIterator<Item = (String, &'static str)>) {
    let wrong: Vec<String> = cases
        .into_iter()
        .flat_map(|(text, value)| leaks(&text, value))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} leaks:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// `cells` with `name` at `column`, joined by `delim`, each quoted or not.
fn row(cells: [&str; 2], name: &str, column: usize, delim: &str, quote: bool) -> String {
    let mut out: Vec<String> = cells.iter().map(|c| c.to_string()).collect();
    out.insert(column, name.to_string());
    out.iter()
        .map(|c| if quote { format!("\"{c}\"") } else { c.clone() })
        .collect::<Vec<_>>()
        .join(delim)
}

#[test]
fn every_header_separator_quote_and_column_order_hides_the_value() {
    let mut cases = Vec::new();
    for name in HEADERS {
        for value in VALUES {
            for (delim, nl) in [(",", "\n"), (";", "\n"), ("\t", "\n"), (",", "\r\n")] {
                for column in 0..3 {
                    for quote in [false, true] {
                        let line = |a: &str, v: &str, b: &str| row([a, b], v, column, delim, quote);
                        cases.push((
                            format!(
                                "{}{nl}{}{nl}{}{nl}{}",
                                line("username", name, "city"),
                                line("bob", "x9Kq2", "Oslo"),
                                line("carol", "Zebra77", "Rome"),
                                line("alice", value, "Paris"),
                            ),
                            value,
                        ));
                    }
                }
            }
        }
    }
    check(cases);
}

#[test]
fn markdown_and_json_tables_hide_the_value() {
    let mut cases = Vec::new();
    for name in HEADERS {
        for value in VALUES {
            cases.push((
                format!(
                    "| username | {name} | city |\n|---|---|---|\n| bob | x9Kq2 | Oslo |\n| alice | {value} | Paris |"
                ),
                value,
            ));
            cases.push((
                format!("| {name} | username |\n| :-- | :-- |\n| {value} | alice |"),
                value,
            ));
            cases.push((
                format!(
                    "[{{\"username\": \"bob\", \"{name}\": \"x9Kq2\"}}, {{\"username\": \"alice\", \"{name}\": \"{value}\", \"city\": \"Paris\"}}]"
                ),
                value,
            ));
            cases.push((
                format!(
                    "[\n  {{\n    \"username\": \"alice\",\n    \"{name}\": \"{value}\"\n  }}\n]"
                ),
                value,
            ));
        }
    }
    check(cases);
}

#[test]
fn empty_cells_repeated_headers_and_letter_rows_hide_the_value() {
    let mut cases = Vec::new();
    for value in VALUES {
        for (head, nl) in [
            ("username,password,note", "\n"),
            ("username,password,note", "\r\n"),
        ] {
            // The seal repro: a letter row right under the header.
            cases.push((format!("{head}{nl}alice,{value},token"), value));
            cases.push((format!("{head}{nl}alice,{value},note"), value));
            cases.push((format!("{head}{nl}bob,,Oslo{nl}alice,{value},"), value));
            cases.push((format!("{head}{nl},,{nl},,{nl}alice,{value},Paris"), value));
            cases.push((
                format!("{head}{nl}bob,x9Kq2,Oslo{nl}{head}{nl}alice,{value},Paris"),
                value,
            ));
            cases.push((
                format!(
                    "{head}{nl}bob,x9Kq2,Oslo{nl}password,username,note{nl}{value},alice,Paris"
                ),
                value,
            ));
            cases.push((
                format!("{head}{nl}bob,token,secret{nl}alice,{value},Paris"),
                value,
            ));
        }
    }
    check(cases);
}

/// Password manager exports (Chrome, Firefox, 1Password, Bitwarden, LastPass,
/// KeePass header shapes, fictional rows).
#[test]
fn password_manager_exports_hide_the_value() {
    let pw = "Tr0ub4dor&3x";
    check(
        [
            format!("name,url,username,password,note\nshop,https://shop.example,alice,{pw},"),
            format!("\"url\",\"username\",\"password\",\"httpRealm\"\n\"https://a.example\",\"alice\",\"{pw}\",\"\""),
            format!("Title,Url,Username,Password,OTPAuth,Notes\nShop,https://shop.example,alice,{pw},,"),
            format!("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,Shop,,,0,https://shop.example,alice,{pw},"),
            format!("url,username,password,totp,extra,name,grouping,fav\nhttps://shop.example,alice,{pw},,,Shop,,0"),
            format!("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Shop\",\"alice\",\"{pw}\",\"https://shop.example\",\"\""),
        ]
        .map(|text| (text, "Tr0ub4dor&3x")),
    );
}

/// A one-time code seed in a TOTP column, and a real password under a bare
/// `pass` column beside pass/fail verdicts.
#[test]
fn totp_seeds_and_pass_values_are_hidden() {
    check([
        (
            "name,login_totp\nShop,JBSWY3DPEHPK3PXP".to_string(),
            "JBSWY3DPEHPK3PXP",
        ),
        (
            "url,username,password,totp\nhttps://a.example,alice,x,KRSXG5CTMVRXEZLU".to_string(),
            "KRSXG5CTMVRXEZLU",
        ),
        ("user,pass\nbob,yes\nalice,secret".to_string(), "secret"),
        ("room;pass\n12;4821".to_string(), "4821"),
    ]);
}

/// Rows past the old 10,000-row cap, divider, empty or letter filler, then a
/// last row: its password is still hidden.
#[test]
fn a_long_table_never_stops_hiding_the_column() {
    let mut cases = Vec::new();
    for filler in ["---,---,---\n", "8,,Oslo\n", "y,abc,Rome\n", ",,\n"] {
        for n in [10_000, 10_001, 25_000] {
            for value in ["Tr0ub4dor&3x", "secret"] {
                cases.push((
                    format!("id,password,city\n{}x,{value},Paris", filler.repeat(n)),
                    value,
                ));
            }
        }
    }
    check(cases);
}

/// Open masks nothing in columns or prose that only mention a password.
#[test]
fn lookalikes_stay_clear_in_open() {
    let mut wrong = Vec::new();
    for (text, clear) in [
        (
            "id,password_reset_count,city\n1,3,Paris\n2,0,Oslo",
            "3,Paris",
        ),
        ("name,passport_country,city\nalice,FR,Paris", "FR,Paris"),
        (
            "the password field is required",
            "the password field is required",
        ),
        (
            "Note: the password field is required, see the form.",
            "the password field is required",
        ),
        (
            "username,city,note\nalice,Paris,secret",
            "alice,Paris,secret",
        ),
        ("student,score,passed\nbob,12,yes", "bob,12,yes"),
        (
            "student,score,pass\nbob,12,yes\ncarol,9,FAIL\ndan,15,\"✓\"",
            "bob,12,yes\ncarol,9,FAIL\ndan,15,\"✓\"",
        ),
        (
            "test\tpass\nlogin\ttrue\nexport\tn/a",
            "login\ttrue\nexport\tn/a",
        ),
    ] {
        let at = text.find(clear).expect("clear part");
        let ranges = masked(PrivacyMode::Open, text).expect("Open allows");
        if ranges.iter().any(|&(s, e)| s < at + clear.len() && at < e) {
            wrong.push(format!("{text:?}: masked {ranges:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A 1 MiB ragged table under a password header (rows of 1 to 6 cells, blank
/// lines, quotes) costs about ten times 100 KiB, in both modes: an export
/// header runs the gate's second residue rounds in Private.
#[test]
fn ragged_tables_scan_in_linear_time() {
    use std::time::{Duration, Instant};
    let unit = "1,Cherry6!,Oslo\n2,x\n\n3,\"a,b\",c,d,e,f\n4,pw,Rome,\n---,---,---\n5\n";
    for head in [
        "id,password,city\n",
        "id;mot de passe;city\n",
        "| id | pwd | city |\n",
        "id,pass,city\n",
        "name,login_password,city\n",
    ] {
        let text = |bytes: usize| {
            format!(
                "{head}{}x,Tr0ub4dor&3x,Paris",
                unit.repeat(bytes / unit.len())
            )
        };
        // Main's headers keep main's Private path: Open is enough there.
        let modes = match head.contains("pass,") || head.contains("login_") {
            true => &MODES[..],
            false => &MODES[1..],
        };
        for &mode in modes {
            let best = |t: &str| {
                (0..3)
                    .map(|_| {
                        let start = Instant::now();
                        let _ = masked(mode, t);
                        start.elapsed()
                    })
                    .min()
                    .expect("three runs")
            };
            let (small, large) = (best(&text(104_858)), best(&text(1_048_576)));
            eprintln!("{mode:?} {head:?}: 100 KiB {small:?}, 1 MiB {large:?}");
            assert!(
                large <= small * 20 + Duration::from_micros(10),
                "{mode:?} {head:?}: 100 KiB {small:?}, 1 MiB {large:?}"
            );
        }
    }
}

/// The smallest inputs where adding the export columns to main's first pass
/// lost bytes main hid in its residue round, or refused (seal A, round 1),
/// minimised from 30,000 ragged tables, plus three quoted rows: each still
/// hides every byte main hides, in both modes, and is never refused. Each
/// fixture line is main's Private ranges, its Open ranges, and the text.
#[test]
fn minimised_tables_keep_every_byte_main_hides() {
    let fixture = include_str!("data/secret_table_column_minimal.tsv");
    let unescape = |text: &str| {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            out.push(match (ch, ch == '\\') {
                (_, true) => match chars.next() {
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('t') => '\t',
                    _ => '\\',
                },
                (ch, false) => ch,
            });
        }
        out
    };
    let mut wrong = Vec::new();
    for line in fixture.lines() {
        let mut fields = line.splitn(3, '\t');
        let main = [fields.next(), fields.next()].map(|f| parse(f.expect("ranges")));
        let text = unescape(fields.next().expect("text"));
        for (mode, main) in MODES.into_iter().zip(main) {
            let Some(now) = masked(mode, &text) else {
                wrong.push(format!("{mode:?} {text:?}: refused"));
                continue;
            };
            if !main.iter().all(|&(s, e)| covered(&now, s, e)) {
                wrong.push(format!("{mode:?} {text:?}: main hid {main:?}, now {now:?}"));
            }
        }
    }
    assert_eq!(fixture.lines().count(), 15);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// `start-end,` ranges.
fn parse(record: &str) -> Vec<(usize, usize)> {
    let range = |r: &str| {
        r.split_once('-')
            .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
    };
    record.split(',').filter_map(range).collect()
}

/// Seeded tables with a password-like column among plain ones: every
/// separator, markdown, blank lines, CRLF, quoted cells, verdicts and prose.
fn tables() -> Vec<String> {
    let heads = [
        "id", "name", "user", "url", "city", "note", "status", "result", "test", "date",
    ];
    let secret = [
        "pass",
        "Pass",
        "PASS",
        "login_password",
        "login_totp",
        "totp",
        "otpauth",
        "OTPAuth",
        "password",
        "pin",
        "mdp",
    ];
    let values = [
        "yes",
        "no",
        "fail",
        "pass",
        "12",
        "4821",
        "Tr0ub4dor&3x",
        "alice",
        "Paris",
        "",
        "x9Kq2",
        "n/a",
        "✓",
        "true",
        "1",
        "0",
        "\"q,u\"",
        "see you at noon",
        "https://shop.example",
        "JBSWY3DPEHPK3PXP",
        "2026-10-29",
        "ok",
    ];
    let prose = [
        "Thanks, see you, Bob",
        "Here is the export:",
        "the password field is required",
    ];
    let mut seed = 0xD1B5_4A32_D192_ED03_u64;
    let mut next = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    let mut out = Vec::new();
    for _ in 0..1_500 {
        let delim = [",", ";", "\t", "|"][next(4)];
        let md = delim == "|" && next(2) == 0;
        let nl = ["\n", "\n", "\r\n"][next(3)];
        let width = 2 + next(4);
        let mut head: Vec<&str> = (0..width).map(|_| heads[next(heads.len())]).collect();
        head[next(width)] = secret[next(secret.len())];
        let line = |cells: Vec<&str>| match md {
            true => format!("| {} |", cells.join(" | ")),
            false => cells.join(delim),
        };
        let mut lines = Vec::new();
        if next(3) == 0 {
            lines.push(prose[next(prose.len())].to_string());
        }
        lines.push(line(head));
        if md {
            lines.push(line(vec!["---"; width]));
        }
        for _ in 0..1 + next(6) {
            if next(8) == 0 {
                lines.push(String::new());
            }
            lines.push(line(
                (0..width).map(|_| values[next(values.len())]).collect(),
            ));
        }
        out.push(lines.join(nl));
    }
    out
}

/// One mode's record of `input`: `start-end,` ranges, or `!` for a refusal.
fn record(mode: PrivacyMode, input: &str) -> String {
    masked(mode, input).map_or("!".into(), |r| {
        r.iter().map(|(s, e)| format!("{s}-{e},")).collect()
    })
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[String]) -> String {
    let bytes = inputs.iter().flat_map(|text| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = tables();
    let each = |text: &String| MODES.map(|mode| record(mode, text)).join("|");
    let records: Vec<String> = inputs.iter().map(each).collect();
    let lines: Vec<String> = records.chunks(64).map(|c| c.join(";") + ";").collect();
    let body = lines.join("\n");
    println!("FIXTURE-BEGIN\n{}\n{body}\nFIXTURE-END", header(&inputs));
}

/// A strict byte superset of main in both modes on the seeded tables: no byte
/// main masked is clear and no new refusal.
#[test]
fn strict_superset_of_main_on_seeded_tables() {
    let inputs = tables();
    let fixture = include_str!("data/secret_table_column_main.txt");
    let (head, body) = fixture.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let (mut lost, mut refused) = ([0usize; 2], 0);
    for (text, main) in inputs.iter().zip(records) {
        for (index, (mode, before)) in MODES.into_iter().zip(main.split('|')).enumerate() {
            let now = record(mode, text);
            if now == "!" {
                refused += usize::from(before != "!");
                continue;
            }
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
        }
    }
    assert_eq!(
        (lost, refused),
        ([0, 0], 0),
        "bytes lost Private/Open; new refusals"
    );
}
