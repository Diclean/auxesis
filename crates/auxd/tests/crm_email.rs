//! CRM-EMAIL: a client's email survives the search and the read.

use std::path::PathBuf;
use std::sync::Arc;

use aux_crm::{Crm, NewParty, PartyKind};
use aux_providers::{ChatMessage, ChatProvider, ChatResponse, FakeProvider, ToolCall};
use auxd::api::{EngineTurnRunner, TurnRunner};
use serde_json::{json, Value};

fn home(mode: &str, emails: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n"),
    )
    .unwrap();
    let store = aux_store::Store::open(&kernel_core::store_path(&home)).unwrap();
    let crm = Crm::new(&store);
    crm.create(NewParty {
        kind: PartyKind::Person,
        display_name: "Jonas Weber".to_string(),
        name_variants: vec!["Jonas".to_string()],
        emails: emails.iter().map(|e| e.to_string()).collect(),
        origin: "owner".to_string(),
        ..NewParty::default()
    })
    .unwrap();
    (dir, home)
}

fn call(tool: &str, args: Value) -> ChatResponse {
    ChatResponse::new(ChatMessage::assistant_with_tool_calls(
        "",
        vec![ToolCall::new("call_1", tool, args)],
    ))
}

fn run(mode: &str, emails: &[&str], script: Vec<ChatResponse>) -> Vec<aux_providers::ChatRequest> {
    let (_dir, home) = home(mode, emails);
    let provider = Arc::new(FakeProvider::scripted("fake", script));
    let runner =
        EngineTurnRunner::new(&home).with_provider(Arc::clone(&provider) as Arc<dyn ChatProvider>);
    runner
        .run_turn("clients", None, "What is Jonas Weber's email?", None)
        .unwrap();
    provider.requests()
}

fn tool_results(requests: &[aux_providers::ChatRequest]) -> Vec<String> {
    let mut out = Vec::new();
    for r in requests {
        for m in r.messages.iter() {
            if m.tool_call_id().is_some() {
                out.push(m.content().as_str().to_string());
            }
        }
    }
    out
}

#[test]
fn search_carries_the_email_in_open_mode() {
    let emails = ["jonas@weber.test"];
    let requests = run(
        "open",
        &emails,
        vec![
            call("crm_search", json!({"query": "Jonas Weber"})),
            call("crm_get", json!({"party_id": 1})),
            ChatResponse::assistant("done"),
        ],
    );
    let results = tool_results(&requests);
    let search = results.iter().find(|r| r.contains("\"matches\"")).unwrap();
    assert!(
        search.contains("jonas@weber.test"),
        "search lost the email: {search}"
    );
    let get = results
        .iter()
        .find(|r| r.contains("\"client_card\""))
        .unwrap();
    assert!(get.contains("jonas@weber.test"), "{get}");
}

#[test]
fn search_is_case_insensitive_and_first_name() {
    for q in ["jonas weber", "Jonas", "JONAS"] {
        let requests = run(
            "open",
            &["jonas@weber.test"],
            vec![
                call("crm_search", json!({"query": q})),
                ChatResponse::assistant("done"),
            ],
        );
        let results = tool_results(&requests);
        let search = results.iter().find(|r| r.contains("\"matches\"")).unwrap();
        assert!(search.contains("jonas@weber.test"), "query {q}: {search}");
    }
}

#[test]
fn a_party_with_two_emails_returns_both() {
    let emails = ["jonas@weber.test", "jw@weber.test"];
    let requests = run(
        "open",
        &emails,
        vec![
            call("crm_get", json!({"party_id": 1})),
            ChatResponse::assistant("done"),
        ],
    );
    let results = tool_results(&requests);
    let get = results
        .iter()
        .find(|r| r.contains("\"client_card\""))
        .unwrap();
    assert!(get.contains("jonas@weber.test"), "{get}");
    assert!(get.contains("jw@weber.test"), "{get}");
}

#[test]
fn private_mode_masks_email_in_provider_request() {
    let emails = ["jonas@weber.test"];
    let requests = run(
        "private",
        &emails,
        vec![
            call("crm_search", json!({"query": "Jonas Weber"})),
            call("crm_get", json!({"party_id": 1})),
            ChatResponse::assistant("done"),
        ],
    );
    let sent = serde_json::to_string(&requests).unwrap();
    assert!(
        !sent.contains("jonas@weber.test"),
        "cleartext email reached the provider"
    );
    assert!(sent.contains("⟦EMAIL_"), "email not tokenised");
    let results = tool_results(&requests);
    assert!(
        results.iter().any(|r| r.contains("⟦EMAIL_")),
        "no email token in tool result: {results:?}"
    );
}
