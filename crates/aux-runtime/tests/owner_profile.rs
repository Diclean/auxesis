//! ASK-1: `owner_profile` hands the agents what the Mac already knows about
//! the owner, and lists what is still missing.

use std::sync::{Arc, Mutex};

use aux_runtime::tools::OwnerProfileTool;
use aux_store::{ContactRecord, NewMemoryItem, Store};
use kernel_broker::{Tool, ToolCtx};
use serde_json::{json, Value};

fn open_store(dir: &tempfile::TempDir) -> Arc<Mutex<Store>> {
    Arc::new(Mutex::new(
        Store::open(&dir.path().join("store.db")).unwrap(),
    ))
}

async fn profile(store: &Arc<Mutex<Store>>, language: Option<&str>) -> Value {
    let tool = OwnerProfileTool::new(Arc::clone(store), language.map(str::to_string));
    let out = tool
        .run(&json!({}), &ToolCtx::new("main", "."))
        .await
        .unwrap();
    serde_json::from_str(&out.content).unwrap()
}

fn owner_contact() -> ContactRecord {
    ContactRecord {
        source: "owner".to_string(),
        display_name: Some("Alex Exemple".to_string()),
        given: vec!["Alex".to_string()],
        family: vec!["Exemple".to_string()],
        emails: vec!["alex@exemple.test".to_string()],
        phones: vec!["+33612345678".to_string()],
        ..ContactRecord::default()
    }
}

#[tokio::test]
async fn an_owner_contact_gives_name_email_phone_and_lists_the_address_as_missing() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    store
        .lock()
        .unwrap()
        .replace_source_contacts("owner", &[owner_contact()])
        .unwrap();
    let value = profile(&store, None).await;
    assert_eq!(value["known"]["name"], "Alex Exemple");
    assert_eq!(value["known"]["emails"], json!(["alex@exemple.test"]));
    assert_eq!(value["known"]["phones"], json!(["+33612345678"]));
    let missing: Vec<&str> = value["missing"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(missing.contains(&"address"), "{missing:?}");
    assert!(!missing.contains(&"name") && !missing.contains(&"email"));
    assert!(value["known"].get("address").is_none(), "only known fields");
}

#[tokio::test]
async fn facts_and_the_language_fill_gaps_but_a_tainted_or_local_number_never_does() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir);
    let fact = |key: &'static str, body: &'static str, tainted: bool| NewMemoryItem {
        kind: "fact",
        title: key,
        body,
        fact_key: Some(key),
        confidence: None,
        source: "chat",
        trust: if tainted { "tainted" } else { "owner" },
        tainted,
        state: if tainted { "quarantined" } else { "active" },
        supersedes_id: None,
        valid_from: None,
        valid_to: None,
    };
    {
        let guard = store.lock().unwrap();
        for item in [
            fact("owner.company", "Exemple SARL", false),
            fact("owner.time_zone", "Europe/Paris", false),
            fact("owner.address", "1 rue Fictive, 75000 Paris", true),
            fact("owner.phone", "06 12 34 56 78", false),
        ] {
            guard.create_memory_item("main", &item).unwrap();
        }
    }
    let value = profile(&store, Some("fr")).await;
    assert_eq!(value["known"]["company"], "Exemple SARL");
    assert_eq!(value["known"]["time_zone"], "Europe/Paris");
    assert_eq!(value["known"]["language"], "fr");
    assert!(value["known"].get("address").is_none(), "tainted fact used");
    assert!(
        value["known"].get("phones").is_none(),
        "a country was guessed"
    );
    let missing = value["missing"].to_string();
    assert!(missing.contains("address") && missing.contains("phone"));
}
