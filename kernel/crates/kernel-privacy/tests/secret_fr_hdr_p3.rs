//! SECRET-FR-HDR-P3: six leftovers from seal B of #319, through the gate. A
//! trailing delimiter, a value row that names a secret, a passphrase row that
//! ends like a sentence, an NFD `Clé privée`, a `Mot de passe :` header cell:
//! each keeps the secret hidden. So does a header with a trailing delimiter.
//! Case 6 (a log line read as a header) is dropped: SECRET-LOG-OVERMASK-1.
//! Every value is invented.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

const PW: &str = "Tr0ub4dor&3x";

/// Each `(mode, value)` of `values` that some mode leaves clear in `text`, or
/// `text` refused.
fn leaks(text: &str, values: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for mode in MODES {
        let Some(ranges) = masked(mode, text) else {
            out.push(format!("{mode:?}: refused"));
            continue;
        };
        for value in values {
            for (at, _) in text.match_indices(value) {
                if !covered(&ranges, at, at + value.len()) {
                    out.push(format!("{mode:?}: {value:?} at {at} clear"));
                }
            }
        }
    }
    out
}

fn check(cases: impl IntoIterator<Item = (String, Vec<&'static str>)>) {
    let wrong: Vec<String> = cases
        .into_iter()
        .flat_map(|(text, values)| {
            let short: String = text.chars().take(70).collect();
            leaks(&text, &values)
                .into_iter()
                .map(move |leak| format!("{short:?}: {leak}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The bytes of `values` in `text` that Open masks (none expected).
fn open_masks(text: &str, values: &[&str]) -> Vec<String> {
    let ranges = masked(PrivacyMode::Open, text).expect("Open allows");
    values
        .iter()
        .flat_map(|value| text.match_indices(value).map(|(at, _)| (at, *value)))
        .filter(|&(at, value)| {
            (at..at + value.len()).any(|b| ranges.iter().any(|&(s, e)| s <= b && b < e))
        })
        .map(|(at, value)| format!("{text:?}: {value:?} at {at} masked"))
        .collect()
}

#[test]
fn a_trailing_delimiter_keeps_the_table() {
    let mut cases = Vec::new();
    for header in ["id,password,city", "id,mot de passe,city"] {
        for blank in ["", "\n", "\n \n"] {
            cases.push((
                format!("{header}\n1,a,Oslo\n{blank}7,{PW},Paris,\n8,Zq9!pw77,Rome"),
                vec![PW, "Zq9!pw77"],
            ));
            cases.push((
                format!("{header}\n1,a,Oslo,\n{blank}7,{PW},Paris"),
                vec![PW],
            ));
        }
        let tsv = header.replace(',', "\t");
        cases.push((
            format!("{tsv}\r\n1\ta\tOslo\r\n\r\n7\t{PW}\tParis\t\r\n8\tZq9!pw77\tRome"),
            vec![PW, "Zq9!pw77"],
        ));
    }
    check(cases);
}

#[test]
fn a_value_row_that_names_a_secret_is_no_header() {
    let mut cases = Vec::new();
    for header in ["id,password,city", "id,mot de passe,city"] {
        for blank in ["\n", "\n\n", "\t\n"] {
            cases.push((
                format!("{header}\n1,a,Oslo\n{blank}7,token,Paris\n8,{PW},Rome"),
                vec!["token", PW],
            ));
            cases.push((
                format!("{header}\n1,a,Oslo\n{blank}7,Paris,token\n8,{PW},Rome"),
                vec![PW],
            ));
        }
    }
    check(cases);
    // The city of the row under it stays clear.
    let text = format!("id,password,city\n1,a,Oslo\n\n7,token,Paris\n8,{PW},Rome");
    assert_eq!(open_masks(&text, &["Rome"]), Vec::<String>::new());
}

#[test]
fn a_passphrase_row_that_ends_like_a_sentence_is_hidden() {
    let mut cases = Vec::new();
    for value in [
        "violet tractor humming seventy.",
        "red fox jumps high!",
        "who ate my blue lamp?",
    ] {
        for (header, row) in [
            ("id,passphrase", format!("2,{value}")),
            ("id,city,passphrase", format!("2,Paris,{value}")),
            ("id;mot de passe", format!("2;{value}")),
        ] {
            let first = row.replacen(value, "a b", 1);
            cases.push((format!("{header}\n{first}\n\n{row}"), vec![value]));
            let next = row.replacen(value, PW, 1);
            cases.push((
                format!("{header}\n{first}\n \n{row}\n{next}"),
                vec![value, PW],
            ));
        }
    }
    check(cases);
}

#[test]
fn nfd_accents_name_the_secret() {
    let mut cases = Vec::new();
    for name in [
        "Cle\u{301} prive\u{301}e",
        "cle\u{301}_prive\u{301}e",
        "CLE\u{301} PRIVE\u{301}E",
        "Clé privée",
    ] {
        cases.push((format!("id,{name},city\n1,{PW},Oslo"), vec![PW]));
        cases.push((format!("id;{name};city\n1;{PW};Oslo"), vec![PW]));
    }
    let words = "violet tractor humming seventy";
    for label in ["Phrase secre\u{300}te", "phrase secre\u{300}te"] {
        cases.push((format!("{label} :\n{words}"), vec![words]));
        cases.push((format!("{label} : {words}"), vec![words]));
    }
    check(cases);
}

#[test]
fn a_colon_after_a_header_name_keeps_the_column() {
    let mut cases = Vec::new();
    for name in [
        "Mot de passe :",
        "Mot de passe\u{a0}:",
        "Mot de passe\u{202f}:",
        "mot de passe:",
        "Password :",
        "MDP :",
    ] {
        for delim in [",", ";", "\t", "|"] {
            let row = |cells: [&str; 3]| cells.join(delim);
            cases.push((
                format!(
                    "{}\n{}\n{}",
                    row(["id", name, "city"]),
                    row(["1", PW, "Oslo"]),
                    row(["2", "Zq9!pw77", "Rome"])
                ),
                vec![PW, "Zq9!pw77"],
            ));
        }
    }
    check(cases);
}

#[test]
fn spaced_compound_headers_keep_their_column() {
    // Seal B r1 on 0918f92f: a lead cell with a number still heads a table.
    check([
        (
            "S3 bucket,access token\nmy-bucket,bluehorse77\nother,greenfox88".to_string(),
            vec!["bluehorse77", "greenfox88"],
        ),
        (
            "Env 1\tAccess Token\nprod\tbluehorse77".to_string(),
            vec!["bluehorse77"],
        ),
        (format!("app,client secret\nbilling,{PW}"), vec![PW]),
    ]);
}

#[test]
fn a_trailing_delimiter_on_the_header_keeps_the_table() {
    let mut cases = Vec::new();
    for header in [
        "id,password,city,",
        "id;mot de passe;city;",
        "id\tpassword\tcity\t",
    ] {
        let delim = &header[header.len() - 1..];
        let row = |cells: [&str; 3]| cells.join(delim);
        cases.push((
            format!(
                "{header}\n{}\n{}{delim}\n{}",
                row(["7", PW, "Paris"]),
                row(["8", "Zq9!pw77", "Rome"]),
                row(["9", "Kx4?mm21", "Lyon"])
            ),
            vec![PW, "Zq9!pw77", "Kx4?mm21"],
        ));
    }
    check(cases);
}

#[test]
fn lookalikes_stay_clear_in_open() {
    let mut wrong = Vec::new();
    for (text, clear) in [
        ("Mot de passe oublié ?", &["Mot de passe oublié ?"][..]),
        (
            "Your access token expired, so sign in again today.",
            &["access token expired", "sign in again today"],
        ),
        (
            "id,name,city\n1,Ann,Oslo,\n\n2,Bob,Rome\n\n3,Cy,Paris.",
            &["Ann", "Oslo", "Bob", "Rome", "Cy", "Paris"],
        ),
        (
            "id,note\n1,see the token page\n\n2,check the docs today.",
            &["see the token page", "check the docs today."],
        ),
    ] {
        wrong.extend(open_masks(text, clear));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// 1 MiB of blank-split rows on each new path costs about ten times 100 KiB.
#[test]
fn the_new_paths_scan_in_linear_time() {
    use std::time::{Duration, Instant};
    for (head, unit) in [
        ("id,password,city\n", "8,Cherry6!,Oslo,\n\n"),
        ("id,password,city\n", "7,token,Paris\n\n"),
        ("id,passphrase\n", "2,red fox jumps high!\n \n"),
        ("id,Cle\u{301} prive\u{301}e :,city\n", "1,x,Oslo\n\n"),
    ] {
        let text = |bytes: usize| format!("{head}{}", unit.repeat(bytes / unit.len()));
        let best = |t: &str| {
            (0..3)
                .map(|_| {
                    let start = Instant::now();
                    let _ = masked(PrivacyMode::Open, t);
                    start.elapsed()
                })
                .min()
                .expect("three runs")
        };
        let (small, large) = (best(&text(104_858)), best(&text(1_048_576)));
        assert!(
            large <= small * 20 + Duration::from_millis(50),
            "{unit:?}: 100 KiB {small:?}, 1 MiB {large:?}"
        );
    }
}

/// A very wide secret header with blank rows after gaps scans in linear
/// time: each cell's column lookup must not walk every secret column (seal B r3).
#[test]
fn a_wide_secret_header_with_sentence_rows_scans_in_linear_time() {
    use std::time::{Duration, Instant};
    let text = |columns: usize| {
        let head = vec!["pin"; columns].join(",");
        let row = ",".repeat(columns - 1);
        format!("{head}\n{row}{}", format!("\n\n{row}").repeat(4))
    };
    let best = |t: &str| {
        (0..3)
            .map(|_| {
                let start = Instant::now();
                let _ = masked(PrivacyMode::Private, t);
                start.elapsed()
            })
            .min()
            .expect("three runs")
    };
    let (small, large) = (best(&text(6_000)), best(&text(60_000)));
    assert!(
        large <= small * 20 + Duration::from_millis(50),
        "6k columns {small:?}, 60k columns {large:?}"
    );
}
