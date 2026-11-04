//! In private mode a person's or a
//! company's name reaches the model as written. Cards, IBANs, IDs, secrets,
//! health terms, e-mail addresses and phone numbers are still masked.
//!
//! The owner's contacts hold the person, and a stand-in for the local name
//! model tags the company, the `delegate` tool and "clients agent" as names,
//! as the local model did. A real server on a loopback port and a
//! scripted brain that records every request. No network, Keychain or real home.

mod common;

use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, ProviderError, ToolCall,
};
use auxd::api::{self, ApiOptions};
use common::post;
use kernel_core::config_path;
use kernel_privacy::safetext::{DetectError, NameSpotter};
use kernel_privacy::{EntityKind, Span};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EXTRA: &str = "\n[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
model = \"fake-model\"\nkind = \"fake\"\n\n[ui]\nlanguage = \"en\"\n";
const ASK: &str = "Call Camille Exemple at Northwind about the quote";

/// What the local name model tagged.
struct ModelStandIn;

impl NameSpotter for ModelStandIn {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let tags = [
            ("Northwind", EntityKind::Organization),
            ("delegate", EntityKind::Person),
            ("clients agent", EntityKind::Person),
        ];
        Ok(tags
            .iter()
            .flat_map(|(word, kind)| {
                text.match_indices(word)
                    .map(|(at, _)| Span::new(*kind, at, at + word.len(), 0.99, "stand-in"))
            })
            .collect())
    }
}

/// One recorded request: chief or not, its serialised messages, the names of
/// the tool calls it replays.
type Body = (bool, String, Vec<String>);

/// The chief delegates the owner's words to Clients, Clients answers, and the
/// chief tells the owner what it read in the owner's message.
#[derive(Default)]
struct Script {
    bodies: StdMutex<Vec<Body>>,
}

#[async_trait]
impl ChatProvider for Script {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let messages = &request.messages;
        let chief = request
            .tools
            .iter()
            .any(|t| t.name().as_str() == "delegate");
        let calls = messages
            .iter()
            .flat_map(|m| m.tool_calls().iter().map(|c| c.name().as_str().to_string()))
            .collect();
        let json = serde_json::to_string(messages).unwrap();
        self.bodies.lock().unwrap().push((chief, json, calls));
        let at = messages.iter().rposition(|m| m.role() == ChatRole::User);
        let user = at.map_or(String::new(), |at| messages[at].content().as_str().into());
        let answered = messages[at.map_or(0, |at| at + 1)..]
            .iter()
            .any(|m| m.role() == ChatRole::Tool);
        Ok(match (chief, answered) {
            (true, false) => ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new(
                    "call-1",
                    "delegate",
                    serde_json::json!({ "agent": "clients", "task": user }),
                )],
            )),
            (true, true) => ChatResponse::assistant(format!("On it: {user}")),
            (false, _) => ChatResponse::assistant(format!("Noted: {user}")),
        })
    }

    fn name(&self) -> &str {
        "script"
    }
}

/// One private turn on a fresh home with Camille Exemple in the contacts:
/// every request and the answer as the app shows it.
fn turn(content: &str) -> (Vec<Body>, String) {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        kernel_privacy::safetext::install_name_spotter(Arc::new(ModelStandIn));
    });
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let config = "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"private\"\n\n\
                  [[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"\n";
    std::fs::write(config_path(&home), config).unwrap();
    aux_engine::config::load_or_create(&config_path(&home)).unwrap();
    let text = std::fs::read_to_string(config_path(&home)).unwrap() + EXTRA;
    std::fs::write(config_path(&home), text).unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let brain = Arc::new(Script::default());
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::clone(&brain) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(30)),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    let vcf = dir.path().join("contacts.vcf");
    let card = "BEGIN:VCARD\nVERSION:3.0\nFN:Camille Exemple\nORG:Northwind\n\
                EMAIL:camille@exemple.fr\nEND:VCARD\n";
    std::fs::write(&vcf, card).unwrap();
    let body = serde_json::json!({ "path": vcf, "dry_run": false }).to_string();
    let imported = post(handle.addr(), "/v1/contacts/import", Some(TOKEN), &body);
    assert_eq!(imported.status, 200, "{}", imported.body);
    let body = serde_json::json!({ "content": content }).to_string();
    let response = post(
        handle.addr(),
        "/v1/threads/aux/messages",
        Some(TOKEN),
        &body,
    );
    assert_eq!(response.status, 200, "{}", response.body);
    let json: serde_json::Value = response.json();
    let last = json["messages"].as_array().unwrap().last().unwrap();
    let answer = last["content"].as_str().unwrap_or_default().to_string();
    let bodies = brain.bodies.lock().unwrap().clone();
    assert!(bodies.len() >= 3, "chief, Clients, chief: {bodies:#?}");
    handle.shutdown();
    drop(dir);
    (bodies, answer)
}

/// Lower-case letters and digits of `text`, every `⟦…⟧` dropped.
fn compact(text: &str) -> String {
    let (mut out, mut inside) = (String::new(), false);
    for c in text.chars() {
        match c {
            '⟦' => inside = true,
            '⟧' => inside = false,
            c if !inside && c.is_alphanumeric() => out.extend(c.to_lowercase()),
            _ => {}
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n1_a_contact_and_a_company_reach_the_model_as_written() {
    let (bodies, _) = tokio::task::block_in_place(|| turn(ASK));
    for (_, json, _) in &bodies {
        assert!(json.contains(ASK), "the owner's words, as written: {json}");
        assert!(
            !json.contains("⟦PERSON") && !json.contains("⟦ORGANIZATION"),
            "{json}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n2_a_replayed_delegate_call_keeps_its_tool_name() {
    let (bodies, _) = tokio::task::block_in_place(|| turn(ASK));
    let replay = bodies
        .iter()
        .rfind(|(chief, _, calls)| *chief && !calls.is_empty());
    let (_, json, calls) = replay.expect("the chief's second request replays its call");
    assert_eq!(calls, &["delegate"], "{json}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n3_clients_agent_stays_as_written() {
    let ask = "Ask the clients agent for Camille Exemple's card";
    let (bodies, answer) = tokio::task::block_in_place(|| turn(ask));
    for (_, json, _) in &bodies {
        assert!(json.contains(ask), "{json}");
    }
    assert_eq!(answer, format!("On it: {ask}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n4_n6_hard_classes_masked_names_verbatim_answer_whole() {
    let card = "4111 1111 1111 1111";
    let iban = "FR76 3000 6000 0112 3456 7890 189";
    let (mail, phone) = ("camille@exemple.fr", "+33 6 12 34 56 78");
    let ask = format!("{ASK}: card {card}, IBAN {iban}, mail {mail}, phone {phone}.");
    let (bodies, answer) = tokio::task::block_in_place(|| turn(&ask));
    for (_, json, _) in &bodies {
        assert!(json.contains(ASK), "names as written: {json}");
        for value in [card, iban, mail, phone] {
            let raw = compact(value);
            assert!(!compact(json).contains(&raw), "{value:?} left raw: {json}");
        }
        for kind in ["CREDIT_CARD_", "IBAN_", "EMAIL_", "PHONE_"] {
            assert!(json.contains(&format!("⟦{kind}")), "{kind} masked: {json}");
        }
    }
    assert_eq!(answer, format!("On it: {ask}"), "the owner reads it whole");
    assert!(!answer.contains('⟦'), "{answer}");
}
