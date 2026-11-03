//! Memory is storage (D24): the memory tools run in Private, a recalled real
//! name reaches the provider only as a `⟦…⟧` token, and the owner's screen
//! rehydrates it. The store keeps the real values, and a foreign token is
//! refused before any write.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aux_engine::{ChatSession, ChatSetup, ToolEndOutcome, TurnEvents};
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use aux_runtime::tools::{MemoryTools, OwnerProfileTool, RecallTool};
use aux_store::{ContactRecord, Message, NewMemoryItem, Store, StoreHandle};
use kernel_broker::{Action, Rule, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::{ModeFn, PrivacyMode};
use kernel_core::ContextConfig;
use kernel_privacy::ContactIndex;
use serde_json::json;
use tempfile::TempDir;

/// The owner's one known contact: a fictional person.
fn camille() -> Arc<ContactIndex> {
    let mut contacts = ContactIndex::new();
    assert!(contacts
        .add_from_header("Camille Exemple", "camille@exemple.fr")
        .is_some());
    Arc::new(contacts)
}

const OWNER_EMAIL: &str = "alex.exemple@exemple.test";
const OWNER_PHONE: &str = "+33612345678";

/// A temp home and a store seeded with one memory item holding a real name.
struct Harness {
    _dir: TempDir,
    home: PathBuf,
    store: Arc<Mutex<Store>>,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        store
            .lock()
            .unwrap()
            .create_memory_item(
                "main",
                &NewMemoryItem {
                    kind: "fact",
                    title: "Camille prefers Tuesday",
                    body: "Camille Exemple (camille@exemple.fr) prefers Tuesday meetings",
                    fact_key: None,
                    confidence: None,
                    source: "chat",
                    trust: "owner",
                    tainted: false,
                    state: "active",
                    supersedes_id: None,
                    valid_from: None,
                    valid_to: None,
                },
            )
            .unwrap();
        store
            .lock()
            .unwrap()
            .replace_source_contacts(
                "owner",
                &[ContactRecord {
                    source: "owner".to_string(),
                    display_name: Some("Alex Exemple".to_string()),
                    emails: vec![OWNER_EMAIL.to_string()],
                    phones: vec![OWNER_PHONE.to_string()],
                    ..ContactRecord::default()
                }],
            )
            .unwrap();
        Self {
            _dir: dir,
            home,
            store,
        }
    }

    fn registry(&self) -> Arc<std::sync::RwLock<ToolRegistry>> {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(MemoryTools::new(Arc::clone(&self.store))));
        registry.register(Box::new(RecallTool::new(Arc::clone(&self.store))));
        registry.mark_read_only("recall");
        registry.register(Box::new(OwnerProfileTool::new(
            Arc::clone(&self.store),
            None,
        )));
        registry.mark_read_only("owner_profile");
        Arc::new(std::sync::RwLock::new(registry))
    }
}

/// What the fake model is scripted to do with the memory tools.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Asked {
    Recall,
    OwnerProfile,
    Remember,
    RememberForeign,
}

/// Records every request body and the tool results the provider was shown, and
/// calls the memory tool the scenario asks for. In Private the second answer
/// echoes the token from the recall result, so the owner's screen has to
/// rehydrate it.
struct Recorder {
    asked: Asked,
    requests: Mutex<Vec<String>>,
    tool_results: Mutex<Vec<String>>,
    rounds: Mutex<usize>,
}

impl Recorder {
    fn new(asked: Asked) -> Self {
        Self {
            asked,
            requests: Mutex::new(Vec::new()),
            tool_results: Mutex::new(Vec::new()),
            rounds: Mutex::new(0),
        }
    }

    /// The first `⟦…⟧` token in `text`, delimiters included; the private
    /// prompt's note on the brackets is not one.
    fn first_token(text: &str) -> Option<String> {
        let text = text.replace("⟦ and ⟧", "");
        let start = text.find('⟦')?;
        let end = text[start..].find('⟧')? + start + '⟧'.len_utf8();
        Some(text[start..end].to_string())
    }
}

#[async_trait]
impl ChatProvider for Recorder {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let mut round = self.rounds.lock().unwrap();
        *round += 1;
        let number = *round;
        let mut body = String::new();
        let mut results = String::new();
        for message in req.messages.iter() {
            let text = message.content().as_str().to_string();
            if message.tool_call_id().is_some() {
                results.push_str(&text);
                results.push('\n');
            }
            body.push_str(&text);
            body.push('\n');
        }
        self.requests.lock().unwrap().push(body.clone());
        self.tool_results.lock().unwrap().push(results);
        if number == 1 {
            let call = match self.asked {
                Asked::Recall => {
                    ToolCall::new("call-1", "recall", json!({"query": "Camille", "limit": 8}))
                }
                Asked::OwnerProfile => ToolCall::new("call-1", "owner_profile", json!({})),
                Asked::Remember => {
                    let token =
                        Self::first_token(&body).expect("the private gate tokenised the address");
                    ToolCall::new(
                        "call-1",
                        "remember",
                        json!({"kind": "fact", "text": format!("{token} prefers Wednesday standups")}),
                    )
                }
                Asked::RememberForeign => ToolCall::new(
                    "call-1",
                    "remember",
                    json!({"kind": "fact",
                           "text": "⟦PERSON_DEADBEEF012345⟧ prefers Wednesday standups"}),
                ),
            };
            return Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![call],
            )));
        }
        let reply = match self.asked {
            Asked::Recall => match Self::first_token(
                self.tool_results
                    .lock()
                    .unwrap()
                    .last()
                    .map(String::as_str)
                    .unwrap_or_default(),
            ) {
                Some(token) => format!("C'est noté pour {token}."),
                None => "C'est noté.".to_string(),
            },
            _ => "Mémorisé.".to_string(),
        };
        Ok(ChatResponse::assistant(reply))
    }

    fn name(&self) -> &str {
        "memory-recorder"
    }
}

/// An approver that always says yes. `recall` is untrusted output, so the
/// broker asks; the test is about gating, not about the approval card.
struct ApproveAll;

#[async_trait]
impl kernel_broker::Approver for ApproveAll {
    async fn approve(
        &self,
        _request: &kernel_broker::ApprovalRequest,
    ) -> Result<bool, kernel_broker::ApproverError> {
        Ok(true)
    }
}

/// The `(token, value)` pairs the turn's gate minted, as the local display
/// side keeps them.
#[derive(Default)]
struct Tokens {
    pairs: Mutex<Vec<(String, String)>>,
}

impl TurnEvents for Tokens {
    fn message(&self, _message: &Message) {}
    fn tool_start(&self, _session: i64, _message: i64, _index: usize, _call: &ToolCall) {}
    fn tool_end(
        &self,
        _session: i64,
        _message: i64,
        _index: usize,
        _call: &ToolCall,
        _outcome: ToolEndOutcome<'_>,
    ) {
    }
    fn done(&self, _session: i64, _message: i64) {}
    fn session_tokens(&self, _session: i64, pairs: &[(String, String)]) {
        self.pairs.lock().unwrap().extend_from_slice(pairs);
    }
}

/// Replace `⟦token⟧` with its value, the way the loopback display does.
fn rehydrate(text: &str, pairs: &[(String, String)]) -> String {
    let mut out = text.to_string();
    for (token, value) in pairs {
        out = out.replace(&format!("⟦{token}⟧"), value);
    }
    out
}

fn message_for(asked: Asked) -> &'static str {
    match asked {
        Asked::Recall => "Qu'est-ce que tu sais ?",
        Asked::OwnerProfile => "Quelles sont mes coordonnées ?",
        Asked::Remember => "Souviens-toi que camille@exemple.fr aime les réunions.",
        Asked::RememberForeign => "Souviens-toi de quelque chose.",
    }
}

/// Drive one turn. Returns the owner-facing reply, every provider request body,
/// the tool results the provider was shown (empty between calls), and the
/// session's minted pairs.
async fn run(
    harness: &Harness,
    private: bool,
    asked: Asked,
) -> (String, Vec<String>, Vec<String>, Vec<(String, String)>) {
    let provider = Recorder::new(asked);
    let mode: ModeFn = if private {
        Arc::new(|| PrivacyMode::Private)
    } else {
        Arc::new(|| PrivacyMode::Open)
    };
    let budgets = Budgets::default();
    let prices = PriceTable::default();
    let events = Arc::new(Tokens::default());
    let mut session = ChatSession::start(ChatSetup {
        store: StoreHandle::Shared(Arc::clone(&harness.store)),
        provider: &provider,
        registry: harness.registry(),
        rules: vec![
            Rule::new("main", "remember", Action::Allow),
            Rule::new("main", "owner_profile", Action::Allow),
        ],
        approver: Arc::new(ApproveAll),
        agent: "main".to_string(),
        home: harness.home.clone(),
        mode,
        contacts: camille(),
        skills: Vec::new(),
        budgets: &budgets,
        prices: &prices,
        context: ContextConfig::default(),
        title: Some("memory test".to_string()),
        stop: None,
        cancel: None,
        session_id: None,
        events: Some(events.clone() as Arc<dyn TurnEvents>),
        run_id: None,
    })
    .unwrap();

    let reply = session.send(message_for(asked)).await.unwrap().text;
    let requests = provider.requests.lock().unwrap().clone();
    let tool_results = provider.tool_results.lock().unwrap().clone();
    let pairs = events.pairs.lock().unwrap().clone();
    (reply, requests, tool_results, pairs)
}

#[tokio::test]
async fn a_private_recall_result_reaches_the_provider_as_a_token_and_the_reply_rehydrates() {
    let harness = Harness::new();
    let (reply, requests, tool_results, pairs) = run(&harness, true, Asked::Recall).await;

    assert_eq!(requests.len(), 2, "one recall round, one answer round");
    let carrying = &requests[1];
    assert!(
        carrying.contains('⟦'),
        "the recall result was not tokenised: {carrying}"
    );
    // NAMES-OFF (owner, 2026-10-19): the name passes, the address does not.
    assert!(carrying.contains("Camille Exemple"), "{carrying}");
    assert!(
        !carrying.contains("camille@exemple.fr"),
        "the real address reached the provider: {carrying}"
    );
    assert!(
        !tool_results[1].contains("camille@exemple.fr"),
        "the tool result carried the real address: {}",
        tool_results[1]
    );

    // The reply echoed the tool result's token; the owner's table rehydrates it.
    let owner = rehydrate(&reply, &pairs);
    assert!(
        owner.contains("camille@exemple.fr"),
        "the owner-facing reply was not rehydrated: {owner}"
    );
}

#[tokio::test]
async fn a_private_remember_stores_the_real_address_not_the_token() {
    let harness = Harness::new();
    run(&harness, true, Asked::Remember).await;

    let guard = harness.store.lock().unwrap();
    let items = guard.search_memory("main", "Wednesday", 8).unwrap();
    assert_eq!(items.len(), 1, "one write: {items:?}");
    assert!(
        items[0].body.contains("camille@exemple.fr"),
        "the store kept the token: {}",
        items[0].body
    );
    assert!(
        !items[0].body.contains('⟦'),
        "a token reached the store: {}",
        items[0].body
    );
}

#[tokio::test]
async fn a_private_remember_refuses_a_foreign_token_and_writes_nothing() {
    let harness = Harness::new();
    let (_reply, _requests, tool_results, _pairs) =
        run(&harness, true, Asked::RememberForeign).await;

    assert!(
        tool_results[1].contains("did not resolve"),
        "the model got no clear refusal: {}",
        tool_results[1]
    );
    assert!(
        harness
            .store
            .lock()
            .unwrap()
            .search_memory("main", "Wednesday", 8)
            .unwrap()
            .is_empty(),
        "a foreign token was written"
    );
}

#[tokio::test]
async fn an_open_recall_result_reaches_the_provider_in_clear() {
    let harness = Harness::new();
    let (_reply, requests, tool_results, _pairs) = run(&harness, false, Asked::Recall).await;

    assert!(
        requests[1].contains("Camille Exemple"),
        "Open mode must stay in clear: {}",
        requests[1]
    );
    assert!(
        tool_results[1].contains("Camille Exemple"),
        "the Open tool result lost the name: {}",
        tool_results[1]
    );
    assert!(
        !tool_results[1].contains('⟦'),
        "Open mode tokenised a value: {}",
        tool_results[1]
    );
}

#[tokio::test]
async fn a_private_owner_profile_reaches_the_provider_as_tokens() {
    let harness = Harness::new();
    let (_reply, requests, _results, _pairs) = run(&harness, true, Asked::OwnerProfile).await;

    assert_eq!(requests.len(), 2);
    for body in &requests {
        assert!(
            !body.contains(OWNER_EMAIL),
            "raw email reached the provider: {body}"
        );
        assert!(
            !body.contains(OWNER_PHONE),
            "raw phone reached the provider: {body}"
        );
    }
    assert!(requests[1].contains('⟦'), "not tokenised: {}", requests[1]);
}
