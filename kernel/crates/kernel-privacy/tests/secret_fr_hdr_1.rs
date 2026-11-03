//! SECRET-FR-HDR-1: two repros from seal A of #315, through the gate. A French
//! `mot de passe` column is hidden like `password`; a blank line inside a
//! table keeps its header when the next line has the same shape. Prose after
//! a table, and columns that only look like a secret, mask what main masks.
//! Every value is invented.

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, masked, MODES};

const PW: &str = "Tr0ub4dor&3x";

/// Each mode that leaves the last `PW` of `text` clear, or refuses `text`.
fn leaks(text: &str) -> Vec<String> {
    let at = text.rfind(PW).expect("value");
    MODES
        .into_iter()
        .filter(|&mode| masked(mode, text).is_none_or(|r| !covered(&r, at, at + PW.len())))
        .map(|mode| format!("{mode:?}"))
        .collect()
}

fn check(cases: impl IntoIterator<Item = String>) {
    let wrong: Vec<String> = cases
        .into_iter()
        .flat_map(|text| {
            let short: String = text.chars().take(60).collect();
            leaks(&text)
                .into_iter()
                .map(move |mode| format!("{short:?}: clear in {mode}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn french_password_headers_are_hidden() {
    let mut cases = Vec::new();
    for name in [
        "mot de passe",
        "Mot de passe",
        "MOT DE PASSE",
        "mot_de_passe",
        "mot-de-passe",
        "motdepasse",
        "\"mot de passe\"",
        "mdp",
        "MDP",
        "code secret",
        "code_secret",
    ] {
        for filler in [0, 3, 10_002] {
            for (delim, nl) in [(",", "\n"), (";", "\n"), ("\t", "\r\n"), ("|", "\n")] {
                let row = |cells: [&str; 3]| cells.join(delim) + nl;
                cases.push(format!(
                    "{}{}{}",
                    row(["id", name, "city"]),
                    row(["---", "---", "---"]).repeat(filler),
                    row(["7", PW, "Paris"]).trim_end()
                ));
            }
        }
    }
    check(cases);
}

#[test]
fn english_header_gaps_are_hidden() {
    check(
        [
            "passcode",
            "secret_key",
            "client_secret",
            "api_secret",
            "access_token",
            "auth_token",
        ]
        .map(|name| format!("id,{name},city\n1,x,Oslo\n7,{PW},Paris")),
    );
}

#[test]
fn blank_lines_keep_the_table_header() {
    let mut cases = Vec::new();
    for blank in ["\n", "\n\n", "\n\n\n", "\r\n", "   \n", "\t\n \n"] {
        for header in ["id,password,city", "id,mot de passe,city"] {
            let nl = if blank.contains('\r') { "\r\n" } else { "\n" };
            let rows = |n: usize| format!("---,---,---{nl}").repeat(n);
            cases.push(format!(
                "{header}{nl}{}{blank}{}7,{PW},Paris",
                rows(5_000),
                rows(5_001)
            ));
            cases.push(format!("{header}{nl}1,a,Oslo{nl}{blank}7,{PW},Paris"));
            let spaced = |n: usize| format!("8,,Oslo{nl}{blank}").repeat(n);
            cases.push(format!("{header}{nl}{}7,{PW},Paris", spaced(3)));
            cases.push(format!("{header}{nl}{}7,{PW},Paris", spaced(10_001)));
            cases.push(format!(
                "{header}{nl}1,a,Oslo{nl}{blank}2,b,Rome{nl}{blank}7,{PW},Paris"
            ));
        }
    }
    check(cases);
}

/// What Open masks on main for each look-alike (the older key rule reads
/// `hint,city`, `reset_count,city` and `secret,` in prose as values).
#[test]
fn lookalikes_match_main_in_open() {
    let mut wrong = Vec::new();
    for (text, main) in [
        (
            "id,password,city\n1,a,Oslo\n\nThe secret, as always, is 42 more steps.",
            &[(12, 16), (19, 20)][..],
        ),
        (
            "id,password,city\n1,a,Oslo\n\nWe met at 10, then 11, and left at 12.",
            &[(12, 16), (19, 20)],
        ),
        (
            "id,password,city\n1,a,Oslo\n\nid,name\n4,Bob",
            &[(12, 16), (19, 20)],
        ),
        (
            "id,password,city\n1,a,Oslo\n\nThanks, see you, Bob",
            &[(12, 16), (19, 20)],
        ),
        ("id,name,city\n1,Ann,Oslo\n\n2,Bob,Rome\n\n3,Cy,Paris", &[]),
        ("id,note,city\n1,secret,Oslo\n \n2,42,Rome", &[]),
        (
            "id,password,city\n1,Tr0ub4dor&3x,Oslo\n\nid,name,city\n2,notsecret,Paris",
            &[(12, 16), (19, 31)],
        ),
        (
            "id;password;city\n1;Tr0ub4dor&3x;Oslo\n\nID;Name;City\n2;notsecret;Paris",
            &[(11, 16), (19, 31)],
        ),
        (
            "id,password,city\n1,Tr0ub4dor&3x,Oslo\n\nUser,Email Kind,Role\n2,notsecret,admin",
            &[(12, 16), (19, 31)],
        ),
        (
            "id,password,city\n1,Tr0ub4dor&3x,Oslo\n \nid,label,city\n2,notsecret,Paris\n\n3,x,Rome",
            &[(12, 16), (19, 31)],
        ),
        ("id,mot,city\n1,abc,Oslo\n2,def,Rome", &[]),
        ("id,passeport,city\n1,abc,Oslo", &[]),
        ("id,code postal,city\n1,75011,Paris\n2,10115,Berlin", &[]),
        ("id,code,city\n1,4821,Paris", &[]),
        (
            "id,password_reset_count,city\n1,3,Paris\n\n2,0,Oslo",
            &[(12, 28)],
        ),
        ("Le mot de passe a changé, merci de vérifier.", &[]),
    ] {
        let ranges = masked(PrivacyMode::Open, text).expect("Open allows");
        if ranges != main {
            wrong.push(format!("{text:?}: main {main:?} now {ranges:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// 1 MiB of rows split by blank lines under a French header costs about ten
/// times 100 KiB.
#[test]
fn blank_split_rows_scan_in_linear_time() {
    use std::time::{Duration, Instant};
    for unit in ["---,---,---\n\n", "8,Cherry6!,Oslo\n \n", "\n"] {
        let text = |bytes: usize| {
            format!(
                "id,mot de passe,city\n{}7,{PW},Paris",
                unit.repeat(bytes / unit.len())
            )
        };
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

/// A wide table: a row after a blank line is matched against the header in one
/// pass, so 16,000 columns cost about ten times 1,600 (seal r1, fictional).
#[test]
fn a_wide_row_after_a_blank_line_scans_in_linear_time() {
    use std::time::{Duration, Instant};
    let text = |columns: usize| {
        let head: Vec<String> = (0..columns)
            .map(|i| {
                if i == 1 {
                    "password".into()
                } else {
                    format!("c{i}")
                }
            })
            .collect();
        let row: Vec<String> = (0..columns).map(|i| format!("v{i}x")).collect();
        let other: Vec<String> = (0..columns).map(|i| format!("w{i}y")).collect();
        format!(
            "{}\n{}\n\n{}\n",
            head.join(","),
            row.join(","),
            other.join(",")
        )
    };
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
    let (small, large) = (best(&text(1_600)), best(&text(16_000)));
    assert!(
        large <= small * 20 + Duration::from_millis(50),
        "1,600 columns {small:?}, 16,000 columns {large:?}"
    );
}
