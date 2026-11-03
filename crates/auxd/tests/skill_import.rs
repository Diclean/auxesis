//! Local, owner-only import: a sandboxed daemon and a scripted fake model.
mod common;
use aux_providers::{ChatMessage, ChatResponse, FakeProvider, ToolCall};
use auxd::api::{self, ApiOptions};
use serde_json::{json, Value};
use std::{fs, sync::Arc};

const TOKEN: &str = "fictional-import-token";
const AGENT: &str = "---\nname: mail\nbrain: cloud\ndefault_mode: open\ntools: [mail.read, mail.send]\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nFictional assistant.\n";
fn skill(tools: &str) -> String {
    format!("---\nname: parcel\nversion: 1\ntools: [{tools}]\ntrigger:\n  manual: true\napproval: each_action\n---\nReview a fictional parcel.\n```sh\ntouch NEVER_EXECUTED\n```\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_import_waits_for_owner_and_rejects_invalid_or_model_actions() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(home.join("agents/mail")).unwrap();
    fs::write(home.join("agents/mail/agent.md"), AGENT).unwrap();
    fs::write(home.join("config.toml"), "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"mail\"\n[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"fake-model\"\nkind = \"fake\"\n").unwrap();
    fs::write(api::token_path(&home), TOKEN).unwrap();
    let other = skill("mail.read").replace("name: parcel", "name: extra");
    let hash = blake3::hash(skill("mail.read").as_bytes())
        .to_hex()
        .to_string();
    let calls = vec![
        ToolCall::new(
            "one",
            "skill_import",
            json!({"agent":"mail", "filename":"extra.md", "text":other}),
        ),
        ToolCall::new(
            "two",
            "skill_approve",
            json!({"agent":"mail", "name":"parcel", "hash":hash}),
        ),
    ];
    let provider = Arc::new(FakeProvider::scripted(
        "fakey",
        vec![
            ChatResponse::new(ChatMessage::assistant_with_tool_calls("", calls)),
            ChatResponse::assistant("No changes."),
            ChatResponse::assistant("Hello."),
        ],
    ));
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            provider: Some(provider.clone()),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let file = dir.path().join("sensitive.md");
    fs::write(&file, "fictional local file that must not be returned").unwrap();
    let post = |path: &str, body: Value, token: Option<&str>| {
        tokio::task::block_in_place(|| common::post(handle.addr(), path, token, &body.to_string()))
    };
    let import = |text: &str| {
        post(
            "/v1/skills/import",
            json!({"filename":"parcel.md","text":text,"agent":"mail"}),
            Some(TOKEN),
        )
    };
    let active = || aux_engine::skill_runtime::load_runtime_skills(&home, "mail", None).skills;
    let approve = |hash: &Value| {
        post(
            "/v1/skills/parcel/approve",
            json!({"agent":"mail","hash":hash}),
            Some(TOKEN),
        )
    };
    let turn = || {
        let r = post(
            "/v1/threads/mail/messages",
            json!({"content":"Hello."}),
            Some(TOKEN),
        );
        assert_eq!(r.status, 200, "{}", r.body);
    };

    let path_request = post(
        "/v1/skills/import",
        json!({"path":file,"agent":"mail"}),
        Some(TOKEN),
    );
    assert_eq!(path_request.status, 422);
    assert!(!path_request.body.contains("fictional local file"));
    assert_eq!(
        post(
            "/v1/skills/import",
            json!({"path":file,"filename":"parcel.md","text":skill("mail.read")}),
            Some(TOKEN)
        )
        .status,
        422
    );
    assert_eq!(
        post(
            "/v1/skills/import",
            json!({"filename":"../parcel.md","text":skill("mail.read")}),
            Some(TOKEN)
        )
        .status,
        400
    );
    let invalid = import(&skill("not.a.tool"));
    assert_eq!(invalid.status, 400, "{}", invalid.body);
    assert!(invalid.body.contains("unknown tool"));
    assert_eq!(import(&"x".repeat(65537)).status, 400);
    let mut maximal = skill("mail.read");
    maximal.push_str(&"\n".repeat(65536 - maximal.len()));
    assert_eq!(import(&maximal).status, 200);
    let builtin = post(
        "/v1/skills/import",
        json!({
            "filename": "follow-up.md",
            "text": skill("mail.read").replace("name: parcel", "name: follow-up"),
            "agent": "mail"
        }),
        Some(TOKEN),
    );
    assert_eq!(builtin.status, 400, "{}", builtin.body);
    assert!(builtin.body.contains("built-in skill"), "{}", builtin.body);
    assert!(!home
        .join("skill-imports/pending/mail/follow-up.md")
        .exists());
    assert!(!home.join("agents/mail/skills/follow-up.md").exists());
    // JSON cannot carry invalid UTF-8; invalid byte input is rejected by the CLI.
    let original = skill("mail.read");
    assert_eq!(
        post("/v1/skills/import", json!({"path":file}), None).status,
        401
    );
    let response = import(&original);
    assert_eq!(response.status, 200, "{}", response.body);
    let preview = response.json();
    assert_eq!(preview["text"], original);
    assert_eq!(preview["name"], "parcel");
    assert_eq!(preview["agent"], "mail");
    assert!(preview["description"]
        .as_str()
        .unwrap()
        .contains("fictional parcel"));
    assert!(preview["read"].to_string().contains("mail.read"));
    assert!(preview["contact"].to_string().contains("mail"));
    assert_eq!(approve(&json!("wrong")).status, 400);
    assert_eq!(
        post("/v1/skills/parcel/approve", json!({}), None).status,
        401
    );
    assert!(active().is_empty());
    assert!(!std::path::Path::new("NEVER_EXECUTED").exists());
    turn();
    let offered = serde_json::to_string(&provider.requests()[0].tools).unwrap();
    for name in ["skill__parcel", "skill_import", "skill_approve"] {
        assert!(!offered.contains(name));
    }
    assert!(active().is_empty());
    assert!(!home.join("skill-imports/pending/mail/extra.md").exists());
    let result = approve(&preview["hash"]);
    assert_eq!(result.status, 200, "{}", result.body);
    assert_eq!(active()[0].effective_tools, ["mail.read"]);
    turn();
    assert!(serde_json::to_string(&provider.requests()[2].tools)
        .unwrap()
        .contains("skill__parcel"));
    let update = import(&skill("mail.read, mail.send"));
    assert_eq!(update.status, 200, "{}", update.body);
    assert!(update.json()["write"].to_string().contains("mail.send"));
    assert_eq!(active()[0].effective_tools, ["mail.read"]);
    assert_eq!(approve(&preview["hash"]).status, 400);
    assert_eq!(active()[0].effective_tools, ["mail.read"]);
    let result = approve(&update.json()["hash"]);
    assert_eq!(result.status, 200, "{}", result.body);
    assert_eq!(active()[0].effective_tools, ["mail.read", "mail.send"]);
}
