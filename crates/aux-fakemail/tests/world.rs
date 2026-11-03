use std::process::Command;

use aux_fakemail::world_mailbox;

const NOW: i64 = 1_792_000_000;

fn rfc2822_to_epoch(s: &str) -> i64 {
    let parts: Vec<&str> = s.split_whitespace().collect();
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => panic!("bad month"),
    };
    let year: i64 = parts[3].parse().unwrap();
    let t: Vec<&str> = parts[4].split(':').collect();
    let hh: i64 = t[0].parse().unwrap();
    let mm: i64 = t[1].parse().unwrap();
    let ss: i64 = t[2].parse().unwrap();
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m as i64 + 2) / 5 + 365 * yoe + yoe / 4 - yoe / 100;
    let doe = era * 146097 + doy - 719468;
    doe * 86400 + hh * 3600 + mm * 60 + ss
}

#[test]
fn world_is_deterministic() {
    let a = world_mailbox(NOW);
    let b = world_mailbox(NOW);
    let ja = serde_json::to_string(&a).unwrap();
    let jb = serde_json::to_string(&b).unwrap();
    assert_eq!(ja, jb);
}

#[test]
fn world_has_enough_clients_and_no_future_dates() {
    let mails = world_mailbox(NOW);
    assert!(mails.len() >= 100);
    let mut domains = std::collections::BTreeSet::new();
    for m in &mails {
        if let Some(start) = m.from.find('@') {
            if let Some(end) = m.from[start..].find('>') {
                domains.insert(m.from[start + 1..start + end].to_string());
            }
        }
    }
    assert!(domains.len() >= 15, "domains={}", domains.len());
    for m in &mails {
        let epoch = rfc2822_to_epoch(&m.date);
        assert!(epoch <= NOW, "future date: {} ({})", m.date, m.subject);
    }
}

#[test]
fn world_covers_situations() {
    let mails = world_mailbox(NOW);
    let tags: Vec<&str> = mails
        .iter()
        .flat_map(|m| m.tags.iter().map(String::as_str))
        .collect();
    for needed in [
        "waiting-on-you",
        "waiting-on-them",
        "quote-request",
        "invoice",
        "newsletter",
        "meeting-invite",
        "late-payment",
        "scope-creep",
    ] {
        assert!(
            tags.iter().any(|t| t.contains(needed) || *t == needed),
            "missing {}",
            needed
        );
    }
    assert!(tags.iter().any(|t| t.contains("sensitive-bait")));
}

#[test]
fn world_addresses_end_in_example_or_test() {
    let mails = world_mailbox(NOW);
    for m in &mails {
        assert!(
            m.from.ends_with(".example>") || m.from.ends_with(".test>"),
            "bad from: {}",
            m.from
        );
        for t in &m.to {
            assert!(
                t.ends_with(".example>") || t.ends_with(".test>"),
                "bad to: {}",
                t
            );
        }
    }
}

#[test]
fn world_invoices_have_xml_attachments() {
    let mails = world_mailbox(NOW);
    let inv: Vec<_> = mails
        .iter()
        .filter(|m| m.tags.iter().any(|t| t.contains("invoice")))
        .collect();
    assert!(inv.len() >= 2);
    for m in inv {
        assert!(m.parts.len() >= 2, "invoice missing attachment");
    }
}

#[test]
fn world_refuses_overwrite_without_force() {
    let dir = std::env::temp_dir().join(format!("aux-fakemail-world-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let status = sandboxed(&dir)
        .args(["demo", "--world", "--dir", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let status = sandboxed(&dir)
        .args(["demo", "--world", "--dir", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
    let status = sandboxed(&dir)
        .args(["demo", "--world", "--force", "--dir", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The simulator under the sandbox line the repo rules set: no real HOME, no
/// daemon port.
fn sandboxed(dir: &std::path::Path) -> Command {
    let home = dir.join("home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_aux-fakemail"));
    command
        .env_clear()
        .env("HOME", &home)
        .env("AUXESIS_HOME", home.join(".auxesis"))
        .env("AUXESIS_SANDBOX", "1")
        .env("AUXESIS_API_PORT", "0");
    command
}
