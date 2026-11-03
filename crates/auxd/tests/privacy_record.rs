//! AUX-EGRESS-TOOL acceptance: Aux answers "how many requests left the Mac
//! today?" from the record the sidebar footer counts. A private turn calls
//! `privacy_record_summary` with no card; the brain receives the tool's
//! answer byte for byte, its count matches `GET /v1/receipts`, and it holds
//! no string from the record but provider ids and class names.
//!
//! A real server on a loopback port, a scripted fake brain, a temp home.

mod common;

use std::sync::Arc;
use std::time::Duration;

use aux_providers::{ChatMessage, ChatProvider, ChatResponse, FakeProvider, ToolCall};
use auxd::api::receipt::{build_receipt, persist_receipt, ReceiptEvent, ReceiptStatus};
use auxd::api::{self, ApiOptions};
use auxd::privacy_record::{is_loopback, provider_hosts, PrivacyRecordTool, CLASSES};
use kernel_core::{config_path, store_path};
use serde_json::{json, Value};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Strings in the record that must never reach the brain.
const SENTINELS: [&str; 8] = [
    "turn-sentinel-run",
    "sentinel-agent",
    "client-dupont-sentinel.example",
    "Sentinel-Contract.pdf",
    "ann.sentinel@example.test",
    "sentinel-skill",
    "sentinel reason",
    "zz_sentinel_kind",
];

/// One receipt `days_ago` (none: no start time) with `hosts`, token kinds and `more`.
fn seed(
    db: &std::path::Path,
    days_ago: Option<u64>,
    hosts: &[&str],
    kinds: &[(&str, u32)],
    more: Vec<ReceiptEvent>,
) {
    let today = chrono::Local::now().date_naive();
    let started = days_ago.map(|n| format!("{} 09:00:00", today - chrono::Days::new(n)));
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let run = ReceiptEvent::Run {
        run_id: format!("turn-sentinel-run-{n}"),
        agent: "sentinel-agent".into(),
        started,
        finished: None,
    };
    let hosts = hosts
        .iter()
        .map(|h| ReceiptEvent::HostContacted(h.to_string()));
    let kinds = (kinds.iter()).map(|(kind, count)| ReceiptEvent::Replaced {
        kind: kind.to_string(),
        count: *count,
    });
    let events: Vec<ReceiptEvent> = std::iter::once(run)
        .chain(hosts)
        .chain(kinds)
        .chain(more)
        .collect();
    persist_receipt(db, &build_receipt(&events)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aux_answers_from_the_sidebar_record_with_counts_only_and_no_card() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let entry = |id: &str, url: &str| {
        format!(
            "[[providers]]\nid = \"{id}\"\nbase_url = \"{url}\"\nmodel = \"m\"\nkind = \"fake\"\n"
        )
    };
    let config = format!(
        "version = 1\nprivacy.mode = \"private\"\ndefault_agent = \"aux\"\n\n{}\n{}",
        entry("fakey", "http://127.0.0.1:9/v1"),
        entry("deepseek", "https://api.deepseek.com/v1")
    );
    std::fs::write(config_path(&home), config).unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let db = store_path(&home);
    let _store = aux_store::Store::open(&db).unwrap();

    let skill = ReceiptEvent::Skill("sentinel-skill".into());
    seed(
        &db,
        Some(0),
        &["api.deepseek.com"],
        &[("email", 2), ("credit_card", 1), ("person", 3)],
        vec![skill],
    );
    let kinds = [
        ("iban", 1),
        ("national_id", 1),
        ("secret", 1),
        ("address", 1),
        ("health", 1),
        ("phone", 1),
    ];
    let more = vec![
        ReceiptEvent::Replaced {
            kind: "zz_sentinel_kind".into(),
            count: 4,
        },
        ReceiptEvent::FileTouched("Sentinel-Contract.pdf".into()),
        ReceiptEvent::MessageSent("ann.sentinel@example.test".into()),
        ReceiptEvent::CouldNotVerify("mail_send returned denied (grant_not_granted)".into()),
    ];
    seed(
        &db,
        Some(0),
        &[
            "https://api.deepseek.com/v1",
            "client-dupont-sentinel.example",
        ],
        &kinds,
        more,
    );
    seed(&db, Some(0), &["127.0.0.1"], &[], vec![]);
    seed(&db, Some(0), &["[::1]"], &[], vec![]);
    let failed = vec![
        ReceiptEvent::Status(ReceiptStatus::Failed),
        ReceiptEvent::CouldNotVerify("sentinel reason".into()),
    ];
    seed(&db, Some(0), &[], &[], failed);
    seed(&db, Some(40), &["api.deepseek.com"], &[], vec![]);
    seed(&db, None, &["api.deepseek.com"], &[], vec![]);

    let call = ToolCall::new("call-1", "privacy_record_summary", json!({}));
    let fake = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![call])),
            ChatResponse::assistant("Two requests left the Mac today."),
        ],
    ));
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::clone(&fake) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(1)),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    let addr = handle.addr();

    // The sidebar: `GET /v1/receipts` at the app's limit, the footer's rule.
    let sidebar =
        tokio::task::block_in_place(|| common::get(addr, "/v1/receipts?limit=100", Some(TOKEN)));
    assert_eq!(sidebar.status, 200, "{}", sidebar.body);
    let today = chrono::Local::now().date_naive();
    let day = today.format("%Y-%m-%d").to_string();
    let outside = |r: &Value| {
        r["hosts_contacted"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| !is_loopback(h.as_str().unwrap()))
    };
    let footer = (sidebar.json().as_array().unwrap().iter())
        .filter(|r| r["started"].as_str().is_some_and(|s| s.starts_with(&day)) && outside(r))
        .count();
    assert_eq!(footer, 2);

    let expected = PrivacyRecordTool::new(db.clone(), provider_hosts(&home))
        .answer(&json!({}), today)
        .unwrap();
    assert_eq!(
        expected["requests_left_the_mac"], footer as u64,
        "{expected}"
    );
    let providers =
        json!([{"provider": "deepseek", "requests": 2}, {"provider": "web", "requests": 1}]);
    assert_eq!(expected["left_the_mac_by_provider"], providers);
    let hidden: Vec<Value> = (CLASSES.iter())
        .map(|class| json!({"class": class, "count": if *class == "email" { 2 } else { 1 }}))
        .collect();
    assert_eq!(expected["items_hidden_by_class"], json!(hidden));
    assert_eq!(
        expected["items_hidden_other"], 7,
        "person 3 + unknown kind 4"
    );
    assert_eq!(expected["items_tokenised"], 16);
    assert_eq!(expected["runs_that_stayed_on_this_mac"], 3);
    assert_eq!(expected["complete"], true);

    // Retention: a `since` 200 days back starts at the oldest kept day, so the
    // 100-day-old run is outside and the 40-day-old one is in.
    seed(&db, Some(100), &["api.deepseek.com"], &[], vec![]);
    let tool = PrivacyRecordTool::new(db.clone(), provider_hosts(&home));
    let far = (today - chrono::Days::new(200))
        .format("%Y-%m-%d")
        .to_string();
    let kept = (today - chrono::Days::new(90))
        .format("%Y-%m-%d")
        .to_string();
    let since = tool.answer(&json!({ "since": far }), today).unwrap();
    assert_eq!(since["kept_since"], kept.as_str(), "{since}");
    assert_eq!(since["from"], kept.as_str());
    assert_eq!(since["requests_left_the_mac"], 3, "today 2 + 40 days ago 1");
    // The cap: the newest rows read stop inside the period, so minimums.
    let capped = tool
        .with_cap(3)
        .answer(&json!({ "since": far }), today)
        .unwrap();
    assert_eq!(capped["complete"], false, "{capped}");
    assert_eq!(capped["counts_are_minimums"], true);
    assert_eq!(expected["runs_blocked_or_refused"], 1);
    assert_eq!(expected["tool_calls_refused"], 1);

    let body = json!({ "content": "how many requests left the Mac today?" }).to_string();
    let turn = tokio::task::block_in_place(|| {
        common::post(addr, "/v1/threads/aux/messages", Some(TOKEN), &body)
    });
    assert_eq!(turn.status, 200, "{}", turn.body);

    // The brain got the tool's answer unchanged by the kernel: counts only.
    let requests = fake.requests();
    assert_eq!(requests.len(), 2, "one tool round, then the answer");
    let result = (requests[1].messages.iter())
        .find(|m| m.tool_call_id().map(|id| id.as_str()) == Some("call-1"))
        .expect("the tool result reached the brain");
    assert_eq!(result.content().as_str(), expected.to_string());
    // Every string value is a provider id, a class name, the period or the unit line.
    let mut allowed: Vec<String> = [
        "deepseek",
        "web",
        "today",
        &day,
        expected["unit"].as_str().unwrap(),
    ]
    .map(String::from)
    .to_vec();
    allowed.extend(CLASSES.map(String::from));
    fn values(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::String(text) => out.push(text.clone()),
            Value::Array(items) => items.iter().for_each(|item| values(item, out)),
            Value::Object(map) => map.values().for_each(|item| values(item, out)),
            _ => {}
        }
    }
    let mut seen = Vec::new();
    values(&expected, &mut seen);
    assert!(seen.iter().all(|text| allowed.contains(text)), "{seen:?}");
    let wire = serde_json::to_string(&requests[1]).unwrap();
    for sentinel in SENTINELS {
        assert!(!wire.contains(sentinel), "{sentinel} reached the brain");
    }

    // A local read: no approval card was created.
    let conn = aux_store::open_keyed_readonly(&db).unwrap();
    let sql = "SELECT COUNT(*) FROM events WHERE kind = 'approval.pending'";
    let cards: i64 = conn.query_row(sql, [], |r| r.get(0)).unwrap();
    assert_eq!(cards, 0);
    handle.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_home_with_no_record_is_never_answered_with_a_number() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config =
        "version = 1\nprivacy.mode = \"private\"\ndefault_agent = \"aux\"\n\n[[providers]]\n\
        id = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n";
    std::fs::write(config_path(&home), config).unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    // No store file yet: the tool says so, with no count field.
    let db = store_path(&home);
    assert!(!db.exists());
    let today = chrono::Local::now().date_naive();
    let tool = PrivacyRecordTool::new(db.clone(), Vec::new());
    let none = tool.answer(&json!({}), today).unwrap();
    assert_eq!(none["record"], "none_yet", "{none}");
    assert!(none.get("requests_left_the_mac").is_none(), "{none}");

    let call = ToolCall::new("call-1", "privacy_record_summary", json!({}));
    let fake = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls("", vec![call])),
            ChatResponse::assistant("No request is in the record yet."),
        ],
    ));
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::clone(&fake) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(1)),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    let body = json!({ "content": "how many requests left the Mac today?" }).to_string();
    let turn = tokio::task::block_in_place(|| {
        common::post(
            handle.addr(),
            "/v1/threads/aux/messages",
            Some(TOKEN),
            &body,
        )
    });
    assert_eq!(turn.status, 200, "{}", turn.body);
    let requests = fake.requests();
    let prompt = serde_json::to_string(&requests[0]).unwrap();
    for rule in ["no privacy record yet, say exactly that", "for every count"] {
        assert!(prompt.contains(rule), "{rule:?} is in the prompt");
    }
    let result = (requests[1].messages.iter())
        .find(|m| m.tool_call_id().map(|id| id.as_str()) == Some("call-1"))
        .expect("the tool result reached the brain");
    // The turn opens the store before any tool runs, so the tool reads a real,
    // empty record: true zeros, marked complete, and the unit line says the
    // asking run is counted only once it ends. Never a zero from a missing store.
    let result: Value = serde_json::from_str(result.content().as_str()).unwrap();
    assert!(db.exists(), "the turn opened the store");
    assert!(result.get("record").is_none(), "{result}");
    assert_eq!(result["requests_left_the_mac"], 0, "{result}");
    assert_eq!(result["complete"], true);
    assert!(result["unit"].as_str().unwrap().contains("once it ends"));
    handle.shutdown();
}
