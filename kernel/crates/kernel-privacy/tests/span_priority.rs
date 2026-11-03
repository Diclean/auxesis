//! K-SPAN-PRIORITY: a merged region that holds any prohibited member (health,
//! IBAN, card, national ID or passport, secret) keeps a prohibited label, so
//! Open mode removes it and Private mode tokenises it under that label.
//! All values are invented.

use std::collections::HashMap;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::recognizer::resolve_overlaps;
use kernel_privacy::{EntityKind, Gate, Span};

mod tail4 {
    #![allow(dead_code)]
    include!("data/secret_tail4_cases.rs");

    pub fn texts() -> Vec<(String, String)> {
        let mut out = Vec::new();
        for set in [CASES, PR1B_CASES, PR2_CASES] {
            for (id, text, _, _) in set {
                out.push((format!("tail4-{id}"), text.to_string()));
            }
        }
        for (id, text, _, _) in built_cases() {
            out.push((format!("tail4-{id}"), text));
        }
        for (id, text, _, _) in refusal_cases() {
            out.push((format!("tail4-{id}"), text));
        }
        out
    }
}

type Member = (EntityKind, usize, usize); // kind, start, end

/// The kind of the one region `spans` merge into, and its end.
fn region(spans: &[Span]) -> (EntityKind, usize) {
    let regions = resolve_overlaps(spans.to_vec());
    assert_eq!(regions.len(), 1, "{regions:?}");
    (regions[0].kind, regions[0].end)
}

#[test]
fn a_region_with_a_prohibited_member_keeps_a_prohibited_label() {
    use EntityKind::{Address, Email, Health, Iban, IpV4, Phone, Secret, Url};
    #[rustfmt::skip]
    let cases: &[(&str, &[Member], EntityKind, usize)] = &[
        ("health inside email", &[(Email, 0, 20), (Health, 0, 8)], Health, 20),
        ("phone+address+health", &[(Phone, 0, 11), (Address, 0, 25), (Health, 12, 20)], Health, 25),
        ("iban inside address", &[(Address, 0, 60), (Iban, 10, 37)], Iban, 60),
        ("secret inside email", &[(Email, 0, 40), (Secret, 5, 30)], Secret, 40),
        ("nested url>email>health", &[(Url, 0, 40), (Email, 5, 30), (Health, 5, 13)], Health, 40),
        ("chained", &[(Email, 0, 10), (Health, 8, 14), (Phone, 12, 24)], Health, 24),
        ("health first", &[(Health, 0, 8), (Email, 4, 20)], Health, 20),
        ("equal start, health short", &[(Phone, 0, 20), (Health, 0, 8)], Health, 20),
        ("equal start, health long", &[(Url, 0, 8), (Health, 0, 20)], Health, 20),
        ("equal start, ipv4", &[(IpV4, 0, 8), (Health, 0, 8)], Health, 8),
        ("strongest prohibited wins", &[(Health, 0, 30), (Email, 0, 20), (Iban, 2, 29)], Iban, 30),
        ("two ordinary kinds", &[(Url, 0, 30), (Email, 5, 20)], Email, 30),
    ];
    for (name, members, kind, end) in cases {
        let spans: Vec<Span> = members
            .iter()
            .map(|&(kind, start, end)| Span::new(kind, start, end, 0.9, "test"))
            .collect();
        assert_eq!(region(&spans), (*kind, *end), "{name}");
    }
    // Passport over IBAN stays as it was (P3, kind labels).
    let passport = Span::new(EntityKind::NationalId, 0, 44, 0.9, "passport_mrz");
    let iban = Span::new(EntityKind::Iban, 0, 30, 0.9, "iban");
    assert_eq!(
        resolve_overlaps(vec![iban, passport])[0].recognizer,
        "passport_mrz"
    );
}

fn grant(mode: PrivacyMode) -> kernel_core::privacy::Grant {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("A1 {mode:?}: {other:?}"),
    }
}

fn gate(mode: PrivacyMode, text: &str) -> Option<String> {
    let (safe, _) = Gate::for_grant(&grant(mode), [7u8; 32]).text(text).ok()?;
    Some(safe.as_str().to_string())
}

/// Shipped overlaps on main: `sensitive_terms` finds the health word inside an
/// e-mail or URL region.
const SHIPPED: &[(&str, &str)] = &[
    ("mail diabetes@example.org now", "mail [health removed] now"),
    (
        "write to diabetes.clinic@example.org",
        "write to [health removed]",
    ),
    (
        "see https://example.org/diabetes/info now",
        "see [health removed] now",
    ),
];

#[test]
fn open_mode_removes_a_region_with_a_health_word() {
    for (text, want) in SHIPPED {
        assert_eq!(
            gate(PrivacyMode::Open, text).as_deref(),
            Some(*want),
            "{text}"
        );
    }
}

#[test]
fn private_mode_tokenises_the_region_as_health() {
    for (text, _) in SHIPPED {
        let out = gate(PrivacyMode::Private, text).expect("private gate");
        assert!(!out.contains("diabetes"), "{out}");
        assert!(out.contains("⟦HEALTH_"), "{out}");
    }
}

/// The clear text of a gate output: removal markers and tokens taken out.
fn clear_of(out: &str) -> String {
    let mut out = out.to_string();
    for class in ["secret", "iban", "card", "health", "id"] {
        out = out.replace(&format!("[{class} removed]"), "\u{1}");
    }
    out.split('⟦')
        .map(|part| part.split_once('⟧').map_or(part, |(_, rest)| rest))
        .collect::<String>()
        .replace('\u{1}', "")
}

/// Bytes of `after` that are not a subsequence of `before`: clear in the new
/// output but not in the old one.
fn lost_bytes(before: &str, after: &str) -> usize {
    let mut old = before.chars();
    after
        .chars()
        .filter(|ch| !old.by_ref().any(|o| o == *ch))
        .map(char::len_utf8)
        .sum()
}

fn fixtures() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../qa/privacy-eval/cases");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("privacy-eval cases")
        .map(|entry| entry.expect("entry").path())
        .collect();
    files.sort();
    for file in files {
        for line in std::fs::read_to_string(&file).expect("read").lines() {
            let case: serde_json::Value = serde_json::from_str(line).expect("jsonl");
            out.push((
                case["id"].as_str().expect("id").to_string(),
                case["text"].as_str().expect("text").to_string(),
            ));
        }
    }
    out.extend(tail4::texts());
    for (at, (text, _)) in SHIPPED.iter().enumerate() {
        out.push((format!("shipped-{at}"), text.to_string()));
    }
    out
}

/// The differential against main. `SPAN_PRIORITY_OUT=<file>` writes every
/// fixture's Open and Private output; `SPAN_PRIORITY_BASE=<file>` (written on
/// main) compares: no byte clear on main is lost, and the bytes newly removed
/// are printed.
#[test]
#[ignore = "differential: run with SPAN_PRIORITY_OUT or SPAN_PRIORITY_BASE"]
fn differential_against_main() {
    let mut now = HashMap::new();
    for (id, text) in fixtures() {
        for mode in [PrivacyMode::Open, PrivacyMode::Private] {
            let out = gate(mode, &text).unwrap_or_else(|| "\u{0}refused".into());
            now.insert(format!("{mode:?}\t{id}"), out);
        }
    }
    if let Ok(path) = std::env::var("SPAN_PRIORITY_OUT") {
        let body = serde_json::to_string(&now).expect("json");
        std::fs::write(path, body).expect("write");
    }
    let Ok(path) = std::env::var("SPAN_PRIORITY_BASE") else {
        return;
    };
    let base: HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("base")).expect("json");
    let (mut lost, mut removed, mut changed) = (0, 0, 0);
    for (key, before) in &base {
        let after = &now[key];
        if before == after {
            continue;
        }
        changed += 1;
        let (old, new) = (clear_of(before), clear_of(after));
        lost += lost_bytes(&old, &new);
        removed += old.len().saturating_sub(new.len());
        println!("{key}\n  main: {before:?}\n  now:  {after:?}");
    }
    println!(
        "outputs {} changed {changed} lost {lost} removed {removed}",
        base.len()
    );
    assert_eq!(base.len(), now.len());
    assert_eq!(lost, 0, "bytes clear now that main masked");
}
