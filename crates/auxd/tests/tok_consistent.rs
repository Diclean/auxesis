//! One value is one placeholder (every turn, chief and Clients)
//! and no `⟦…⟧` reaches the owner. Names
//! pass as written; addresses are the values.

mod common;

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ChatRole, ProviderError, ToolCall,
};
use auxd::api::{self, ApiOptions, ToolRegistryHook};
use common::{http_with_read_timeout, post};
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::config_path;
use serde_json::json;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FORGED: &str = "⟦PERSON_0123456789AB⟧"; // well-formed, never minted
const CARD_MIRA: &str = "party 1 · Mira Fictive · mira@lumenworks.test · contact: Jonas Sample";
const CARD_JONAS: &str = "party 2 · Jonas Sample · jonas@brightpath.test · cc mira@lumenworks.test";
const CARD_KEY: &str = "party 3 · Api Key · api key: Zq7Lm2Xr";
const CONFIG: &str = "version = 1\ndefault_agent = \"aux\"\n\n[privacy]\nmode = \"private\"\n\n\
[[rules]]\nagent = \"aux\"\ntool = \"delegate\"\naction = \"allow\"\n\n\
[[rules]]\nagent = \"clients\"\ntool = \"crm_get\"\naction = \"allow\"\n\n\
[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"fake-model\"\n\
kind = \"fake\"\n\n[ui]\nlanguage = \"en\"\n";

fn tokens(text: &str, kind: &str) -> Vec<String> {
    text.split('⟦')
        .skip(1)
        .filter(|rest| rest.starts_with(kind))
        .filter_map(|rest| rest.split_once('⟧').map(|(inner, _)| format!("⟦{inner}⟧")))
        .collect()
}

type Body = (bool, Vec<(ChatRole, String)>);

fn last(body: &Body, role: ChatRole) -> String {
    let found = body.1.iter().rfind(|(r, _)| *r == role);
    found.map(|(_, text)| text.clone()).unwrap_or_default()
}

/// The parties the script looks for, by name.
const PEOPLE: [&str; 3] = ["Mira Fictive", "Jonas Sample", "Api Key"];

/// Chief: delegate the owner's first person, then repeat Clients with a forged
/// token. Clients: read the card, answer it, recall its first task's person;
/// with `echo`, also echo and look up the chief's last address.
#[derive(Default)]
struct Script {
    bodies: StdMutex<Vec<Body>>,
    first_task: StdMutex<Option<String>>,
    echo: bool,
}

#[async_trait]
impl ChatProvider for Script {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let chief = request
            .tools
            .iter()
            .any(|t| t.name().as_str() == "delegate");
        let messages: Vec<(ChatRole, String)> = request
            .messages
            .iter()
            .map(|m| (m.role(), m.content().as_str().to_string()))
            .collect();
        let mut bodies = self.bodies.lock().unwrap();
        let echo = bodies.iter().rfind(|b| b.0 && self.echo && !chief);
        let echo = echo.map_or(String::new(), |b| {
            tokens(&last(b, ChatRole::User), "EMAIL_").concat()
        });
        bodies.push((chief, messages.clone()));
        drop(bodies);
        let at = messages
            .iter()
            .rposition(|(r, _)| *r == ChatRole::User)
            .unwrap();
        let named = PEOPLE
            .iter()
            .filter_map(|p| messages[at].1.find(p).map(|i| (i, *p)));
        let who = named.min().map_or(String::new(), |(_, p)| p.to_string());
        let tool: Vec<&str> = messages[at + 1..]
            .iter()
            .filter(|(r, _)| *r == ChatRole::Tool)
            .map(|(_, text)| text.as_str())
            .collect();
        let call = |name: &str, args| {
            let mut calls = vec![ToolCall::new("call-1", name, args)];
            if !echo.is_empty() {
                calls.push(ToolCall::new("call-2", name, json!({ "name": echo })));
            }
            ChatResponse::new(ChatMessage::assistant_with_tool_calls(echo.clone(), calls))
        };
        Ok(match (chief, tool.first()) {
            (true, None) => call(
                "delegate",
                json!({ "agent": "clients", "task": format!("Show the card of {who}.") }),
            ),
            (false, None) => call("crm_get", json!({ "name": who })),
            (false, Some(card)) => {
                let mut first = self.first_task.lock().unwrap();
                let answer = match first.as_ref() {
                    Some(earlier) if *earlier != who => {
                        format!("Card: {card} (earlier: {earlier})")
                    }
                    _ => format!("Card: {card}"),
                };
                first.get_or_insert(who);
                ChatResponse::assistant(answer)
            }
            (true, Some(said)) => ChatResponse::assistant(format!("Clients: {said} ref {FORGED}")),
        })
    }

    fn name(&self) -> &str {
        "script"
    }
}

/// The card tool: answers by the real name the executor restored.
struct FakeCard;

#[async_trait]
impl Tool for FakeCard {
    fn name(&self) -> &str {
        "crm_get"
    }
    fn schema(&self) -> serde_json::Value {
        json!({"type": "object", "properties": {"name": {"type": "string"}}})
    }
    async fn run(&self, args: &serde_json::Value, _: &ToolCtx) -> Result<ToolOutput, ToolError> {
        Ok(ToolOutput::ok(match args["name"].as_str() {
            Some("Mira Fictive") => CARD_MIRA,
            Some("Jonas Sample") => CARD_JONAS,
            Some("Api Key") => CARD_KEY,
            Some(other) if other.contains('@') => "raw address received",
            _ => "no such party",
        }))
    }
    fn risk(&self) -> Risk {
        Risk::Low
    }
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::G3
    }
    fn class(&self) -> ToolClass {
        ToolClass::default()
    }
}

/// The daemon on `brain`, with the contacts `names` imported.
fn start(brain: &Arc<Script>, names: &[&str]) -> (tempfile::TempDir, api::ApiHandle) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().to_path_buf();
    std::fs::write(config_path(&home), CONFIG).unwrap();
    std::fs::write(api::token_path(&home), format!("{TOKEN}\n")).unwrap();
    let tools: ToolRegistryHook = Arc::new(|registry| {
        registry.register(Box::new(FakeCard));
        registry.mark_read_only("crm_get");
    });
    let options = ApiOptions {
        port: 0,
        event_poll: Duration::from_millis(25),
        provider: Some(Arc::clone(brain) as Arc<dyn ChatProvider>),
        approval_timeout: Some(Duration::from_secs(30)),
        tools: Some(tools),
        ..ApiOptions::default()
    };
    let handle = api::spawn(&home, options).unwrap();
    let vcf = dir.path().join("contacts.vcf");
    let cards: String = names
        .iter()
        .map(|n| format!("BEGIN:VCARD\nVERSION:3.0\nFN:{n}\nEND:VCARD\n"))
        .collect();
    std::fs::write(&vcf, cards).unwrap();
    let body = json!({ "path": vcf, "dry_run": false }).to_string();
    let imported = post(handle.addr(), "/v1/contacts/import", Some(TOKEN), &body);
    assert_eq!(imported.status, 200, "{}", imported.body);
    (dir, handle)
}

/// The owner asks on the chief's current thread: each answer as shown.
fn ask(handle: &api::ApiHandle, turns: &[&str]) -> Vec<String> {
    let one = |content: &str| {
        let body = json!({ "content": content }).to_string();
        let (path, wait) = ("/v1/threads/aux/messages", Duration::from_secs(90));
        let response =
            http_with_read_timeout(handle.addr(), "POST", path, Some(TOKEN), Some(&body), wait);
        assert_eq!(response.status, 200, "{}", response.body);
        let json: serde_json::Value = response.json();
        let last = json["messages"].as_array().unwrap().last().cloned();
        last.unwrap()["content"].as_str().unwrap().to_string()
    };
    let answers = turns.iter().map(|q| tokio::task::block_in_place(|| one(q)));
    answers.collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_value_is_one_placeholder_across_turns_and_agents() {
    let brain = Arc::new(Script::default());
    let (_dir, handle) = start(&brain, &["Mira Fictive", "Jonas Sample"]);
    let answers = ask(
        &handle,
        &[
            "Show me the client card for Mira Fictive.",
            "Does Jonas Sample write from mira@lumenworks.test?",
            "Show Mira Fictive's timeline.",
        ],
    );
    let bodies = brain.bodies.lock().unwrap().clone();
    // Per turn: chief, Clients, Clients, chief; no value leaves.
    assert_eq!(bodies.len(), 12, "{bodies:#?}");
    for (_, text) in bodies.iter().flat_map(|(_, messages)| messages) {
        for value in ["@lumenworks", "@brightpath", "⟦PERSON_"] {
            assert!(!text.contains(value), "{value:?} left the Mac: {text}");
        }
    }
    let (t1, t2, t3) = (&bodies[0..4], &bodies[4..8], &bodies[8..12]);
    assert!(t1[0].0 && !t1[1].0 && !t1[2].0 && t1[3].0, "{bodies:#?}");

    // H5: an agent's name is never tokenised (`Clients` is no person).
    let h5 = last(&t2[0], ChatRole::Assistant);
    assert!(h5.starts_with("Clients: Card: "), "{h5}");
    // Turn 1: Clients' card as the chief reads it back, names as written.
    let card = last(&t1[3], ChatRole::Tool);
    assert!(
        card.contains("Mira Fictive") && card.contains("Jonas Sample"),
        "{card}"
    );
    let mira_email = tokens(&card, "EMAIL_")[0].clone();

    // F4: the owner's turn 2 names Mira's address with the token the chief met
    // through Clients in turn 1.
    let owner2 = last(&t2[0], ChatRole::User);
    assert!(owner2.contains("Jonas Sample"), "F1: {owner2}");
    let email2 = tokens(&owner2, "EMAIL_");
    assert_eq!(email2, [mira_email.as_str()], "F4: {owner2}");
    // F2 + F4: Clients reads the chief's token in its turn-2 card.
    let card2 = last(&t2[2], ChatRole::Tool);
    assert_eq!(tokens(&card2, "EMAIL_")[1], mira_email, "F4: {card2}");

    // F3: the possessive stays as written.
    let owner3 = last(&t3[0], ChatRole::User);
    assert!(owner3.contains("Mira Fictive's timeline"), "F3: {owner3}");

    // F5: no marker on screen; the person Clients recalls from turn 1 shows
    // its value; the forged token shows the neutral marker.
    for answer in &answers {
        assert!(!answer.contains(['⟦', '⟧']), "F5: {answer}");
        assert!(answer.ends_with("ref [name hidden]"), "F5: {answer}");
    }
    let recalled = &answers[1];
    assert!(
        recalled.contains("(earlier: Mira Fictive)"),
        "F5: {recalled}"
    );
}

/// Detection reads the text as written (owner text and tool result), names stay
/// as written, and a token the model only echoes never resolves for a tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_carried_token_never_hides_a_secret_or_resolves_an_echo_and_names_stay() {
    let brain = Arc::new(Script {
        echo: true,
        ..Script::default()
    });
    let names = ["Api Key", "Anna Bell", "Ann Abell", "Jo Silva", "Josil Va"];
    let (_dir, handle) = start(&brain, &names);
    ask(
        &handle,
        &[
            "Show me the client card for Api Key, hidden@fiction.test; cc Anna Bell, Jo Silva.",
            "cc Ann Abell, Josil Va. api key: Zq7Lm2Xr",
        ],
    );
    let bodies = brain.bodies.lock().unwrap().clone();
    let mut failed = Vec::new();
    for (_, text) in bodies.iter().flat_map(|(_, messages)| messages) {
        let leaks = ["Zq7Lm2Xr", "raw address received", "@fiction"];
        let leaks = leaks.into_iter().filter(|value| text.contains(value));
        failed.extend(leaks.map(|value| format!("{value:?} left the Mac: {text}")));
    }
    let chief = bodies
        .iter()
        .filter(|b| b.0)
        .map(|b| last(b, ChatRole::User));
    let mut asked: Vec<String> = chief.collect();
    asked.dedup();
    if !asked[0].contains("cc Anna Bell, Jo Silva.")
        || !asked[1].starts_with("cc Ann Abell, Josil Va.")
    {
        failed.push(format!("P2a: {asked:?}"));
    }
    assert!(failed.is_empty(), "{failed:#?}");
}
