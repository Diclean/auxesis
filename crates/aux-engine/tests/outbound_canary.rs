//! Canary harness for the outbound gate (`docs/phase1.md` §2).
//!
//! Synthetic PII goes through a real engine turn into an OpenAI-compatible
//! adapter. The wiremock server records the HTTP body that left the process:
//! no canary may appear there raw, and the tokens that replace it must.
//! Covered paths: the first request, a tool result in the follow-up, a provider
//! error followed by the next turn, and the streaming fallback. The ACP, voice
//! and WhatsApp text paths capture their own sinks (see their test files).
//!
//! Every canary is FAKE. The values come from `qa/privacy-eval/canaries.json`,
//! invented data that only follows the public check algorithms. The turns run
//! in private mode with one known contact (canary-06, a full name), so the
//! names dictionary is on the real path: a private gate with no names refuses.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aux_engine::{AutoApproveApprover, ChatSession, ChatSetup};
use aux_providers::config::{ProviderConfig, ProviderKind};
use aux_providers::{ChatProvider, OpenAiCompat};
use aux_store::{Store, StoreHandle};
use kernel_broker::ToolRegistry;
use kernel_core::budget::{Budgets, ModelPrice, PriceTable};

/// The money cap refuses an unpriced model, so the test brain carries a price.
fn canary_prices() -> PriceTable {
    let mut prices = PriceTable::default();
    prices.models.insert(
        "canary-model".to_string(),
        ModelPrice {
            input_cents_per_million: 1,
            output_cents_per_million: 1,
        },
    );
    prices
}
use kernel_core::ContextConfig;
use serde_json::{json, Value};
use std::sync::{Mutex, RwLock};
use tempfile::{tempdir, TempDir};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CANARIES: &str = include_str!("../../../qa/privacy-eval/canaries.json");

/// The FAKE canary value with this id in `qa/privacy-eval/canaries.json`.
fn canary(id: &str) -> String {
    let file: Value = serde_json::from_str(CANARIES).unwrap();
    file["canaries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .and_then(|entry| entry["value"].as_str())
        .unwrap_or_else(|| panic!("canary {id} is missing"))
        .to_string()
}

struct Harness {
    _dir: TempDir,
    home: PathBuf,
    store: Arc<Mutex<Store>>,
    registry: Arc<RwLock<ToolRegistry>>,
    budgets: Budgets,
    prices: PriceTable,
}

impl Harness {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        Self {
            _dir: dir,
            home,
            store: Arc::new(Mutex::new(Store::open_in_memory().unwrap())),
            registry: Arc::new(RwLock::new(ToolRegistry::with_defaults())),
            budgets: Budgets::default(),
            prices: canary_prices(),
        }
    }

    fn start<'a>(&'a self, provider: &'a dyn ChatProvider) -> ChatSession<'a> {
        ChatSession::start(ChatSetup {
            mode: std::sync::Arc::new(|| kernel_core::privacy::PrivacyMode::Private),
            contacts: known_contacts(),
            store: StoreHandle::Shared(Arc::clone(&self.store)),
            provider,
            registry: Arc::clone(&self.registry),
            rules: Vec::new(),
            approver: Arc::new(AutoApproveApprover),
            agent: "main".to_string(),
            home: self.home.clone(),
            skills: Vec::new(),
            budgets: &self.budgets,
            prices: &self.prices,
            context: ContextConfig::default(),
            title: None,
            stop: None,
            cancel: None,
            session_id: None,
            events: None,
            run_id: None,
        })
        .unwrap()
    }
}

/// A chat provider pointed at the mock server, as a deployment would be.
fn provider(server: &MockServer) -> OpenAiCompat {
    let config = ProviderConfig {
        disable_thinking: false,
        id: "canary".to_string(),
        base_url: format!("{}/v1", server.uri()),
        model: "canary-model".to_string(),
        key_user: None,
        kind: ProviderKind::OpenAiCompat,
    };
    OpenAiCompat::with_key(&config, Some("fake-test-key".to_string())).unwrap()
}

async fn mount_reply(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "choices": [{ "message": { "content": "Bien reçu." } }] })),
        )
        .mount(server)
        .await;
}

/// The owner's contacts for these turns: the FAKE canary-06 person, whose name
/// is a known contact in private mode.
fn known_contacts() -> aux_runtime::known_names::Contacts {
    let mut contacts = kernel_privacy::ContactIndex::new();
    contacts.add_from_header(&canary("canary-06"), &canary("canary-07"));
    Arc::new(contacts)
}

/// Every chat-completion body the mock server received, in order.
///
/// Only `POST /v1/chat/completions` counts: the mock listens on a local port,
/// and a process outside the test may probe it (the test host sends
/// `GET /` from node to every port a thread's process opens). Such a request
/// is not provider egress and must neither add a body nor shift the order.
/// Only a bare `GET /` (no query, no body: it carries no text) is skipped;
/// any other request is egress the test did not expect, and fails it.
async fn wire_bodies(server: &MockServer) -> Vec<String> {
    let mut bodies = Vec::new();
    for request in server.received_requests().await.unwrap() {
        let (method, url) = (request.method.as_str(), &request.url);
        if method == "POST" && url.path() == "/v1/chat/completions" {
            bodies.push(String::from_utf8(request.body).unwrap());
        } else if !(method == "GET" && url.path() == "/" && url.query().is_none())
            || !request.body.is_empty()
        {
            panic!(
                "unexpected request to the provider: {method} {}",
                url.path()
            );
        }
    }
    bodies
}

/// The first `⟦KIND_…⟧` token of a kind in a wire body.
fn token_of(body: &str, kind: &str) -> String {
    let start = body
        .find(&format!("⟦{kind}_"))
        .unwrap_or_else(|| panic!("no {kind} token in the wire body"));
    let end = body[start..].find('⟧').unwrap() + start + '⟧'.len_utf8();
    body[start..end].to_string()
}

#[tokio::test]
async fn canary_pii_never_reaches_the_provider_wire_raw() {
    let values = [
        canary("canary-02"),
        canary("canary-03"),
        canary("canary-04"),
        canary("canary-05"),
        canary("canary-07"),
        canary("canary-08"),
    ];
    let message = format!(
        "Mon e-mail : {}. Tél : {}. IBAN : {}. NIR : {}. Contact EN : {}, {}.",
        values[0], values[1], values[2], values[3], values[4], values[5]
    );

    let server = MockServer::start().await;
    mount_reply(&server).await;
    let provider = provider(&server);
    let harness = Harness::new();
    let mut session = harness.start(&provider);

    let outcome = session.send(&message).await.unwrap();
    assert_eq!(outcome.text, "Bien reçu.");

    let bodies = wire_bodies(&server).await;
    assert!(!bodies.is_empty(), "the turn sent no provider request");
    for body in &bodies {
        for value in &values {
            assert!(
                !body.contains(value.as_str()),
                "raw canary reached the provider wire"
            );
        }
        assert!(body.contains("⟦EMAIL_"), "e-mail was not tokenised");
        assert!(body.contains("⟦PHONE_"), "phone was not tokenised");
        assert!(body.contains("⟦IBAN_"), "IBAN was not tokenised");
    }
}

#[tokio::test]
async fn public_chat_reaches_the_provider_unchanged() {
    let server = MockServer::start().await;
    mount_reply(&server).await;
    let provider = provider(&server);
    let harness = Harness::new();
    let mut session = harness.start(&provider);

    session
        .send("Bonjour, quelle heure est-il à Lyon ?")
        .await
        .unwrap();

    let bodies = wire_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    // The user's own message is the last one; the system prompt may carry
    // tokens of its own (the tool list is masked too), so only this is checked.
    let wire: Value = serde_json::from_str(&bodies[0]).unwrap();
    let messages = wire["messages"].as_array().unwrap();
    assert_eq!(
        messages.last().unwrap()["content"],
        "Bonjour, quelle heure est-il à Lyon ?",
        "public text must reach the provider unchanged"
    );
}

#[tokio::test]
async fn one_session_keeps_a_value_token_across_turns() {
    let email = canary("canary-02");
    let server = MockServer::start().await;
    mount_reply(&server).await;
    let provider = provider(&server);
    let harness = Harness::new();
    let mut session = harness.start(&provider);

    session.send(&format!("Écris à {email}.")).await.unwrap();
    session.send("Relance-le demain.").await.unwrap();

    let bodies = wire_bodies(&server).await;
    assert_eq!(bodies.len(), 2);
    let first = token_of(&bodies[0], "EMAIL");
    assert!(
        bodies[1].contains(&first),
        "the second turn lost the token of the first"
    );
}

/// A chat reply in which the model asks for one tool call.
fn tool_call_reply(name: &str, arguments: &str) -> Value {
    json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": name, "arguments": arguments }
                }]
            }
        }]
    })
}

#[tokio::test]
#[ignore = "read_file is Disabled in private mode (path row B3): the tool does not run, so its result is never tokenised; the raw-value check passes in private"]
async fn canary_in_a_tool_result_never_reaches_the_follow_up_raw() {
    let values = [canary("canary-02"), canary("canary-03")];
    let harness = Harness::new();
    // The note holds the canaries; `read_file` returns it to the follow-up.
    let workspace = aux_engine::workspace_dir(&harness.home, "main");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(
        workspace.join("note.txt"),
        format!("Mon e-mail : {}. Tél : {}.", values[0], values[1]),
    )
    .unwrap();

    let server = MockServer::start().await;
    // Registered first: only the follow-up carries the tool result.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_string_contains("\"role\":\"tool\""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "choices": [{ "message": { "content": "Bien reçu." } }] })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(tool_call_reply("read_file", r#"{"path":"note.txt"}"#)),
        )
        .mount(&server)
        .await;
    let provider = provider(&server);
    let mut session = harness.start(&provider);

    let outcome = session.send("Lis la note.").await.unwrap();
    assert_eq!(outcome.text, "Bien reçu.");

    let bodies = wire_bodies(&server).await;
    assert_eq!(bodies.len(), 2, "one tool round trip: request, follow-up");
    for body in &bodies {
        for value in &values {
            assert!(!body.contains(value.as_str()), "raw canary in a body");
        }
    }
    assert!(
        bodies[1].contains("⟦EMAIL_"),
        "the tool result was not tokenised"
    );
}

#[tokio::test]
async fn canary_survives_a_provider_error_and_the_next_turn() {
    let email = canary("canary-02");
    let server = MockServer::start().await;
    // The first completion fails; the mock behind it answers the next turn.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream unavailable"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_reply(&server).await;
    let provider = provider(&server);
    let harness = Harness::new();
    let mut session = harness.start(&provider);

    assert!(
        session.send(&format!("Écris à {email}.")).await.is_err(),
        "the 500 must surface as an error"
    );
    session.send("Relance-le demain.").await.unwrap();

    let bodies = wire_bodies(&server).await;
    assert_eq!(bodies.len(), 2, "the failed request and the next turn");
    for body in &bodies {
        assert!(!body.contains(email.as_str()), "raw canary after an error");
    }
    assert!(bodies[1].contains("⟦EMAIL_"), "the retry lost the token");
}

#[tokio::test]
async fn canary_survives_the_streaming_fallback() {
    let email = canary("canary-02");
    let server = MockServer::start().await;
    // A refused stream is re-sent as a plain completion: both bodies are checked.
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_string_contains("\"stream\":true"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({ "error": { "message": "stream not supported" } })),
        )
        .mount(&server)
        .await;
    mount_reply(&server).await;
    let provider = provider(&server);
    let harness = Harness::new();
    let mut session = harness.start(&provider);

    let outcome = session.send(&format!("Écris à {email}.")).await.unwrap();
    assert_eq!(outcome.text, "Bien reçu.");

    let bodies = wire_bodies(&server).await;
    assert_eq!(bodies.len(), 2, "one refused stream, one plain fallback");
    for body in &bodies {
        assert!(!body.contains(email.as_str()), "raw canary in a fallback");
        assert!(body.contains("⟦EMAIL_"), "the fallback was not tokenised");
    }
}

#[tokio::test]
async fn a_known_contact_name_reaches_the_provider_wire_as_written() {
    // The name canary is in the owner's contacts; private mode hides no name.
    let name = canary("canary-06");
    let server = MockServer::start().await;
    mount_reply(&server).await;
    let provider = provider(&server);
    let harness = Harness::new();
    let mut session = harness.start(&provider);

    session
        .send(&format!("Dis bonjour à {name}."))
        .await
        .unwrap();

    let bodies = wire_bodies(&server).await;
    assert!(!bodies.is_empty(), "the turn sent no provider request");
    for body in &bodies {
        assert!(
            body.contains(name.as_str()),
            "the name was not sent as written"
        );
        assert!(!body.contains("⟦PERSON_"), "the name was tokenised");
    }
}

/// The owner's contacts for the repro: Camille Exemple, with one e-mail address.
fn camille_contacts() -> aux_runtime::known_names::Contacts {
    let mut contacts = kernel_privacy::ContactIndex::new();
    contacts.add_from_header("Camille Exemple", "camille@exemple.fr");
    Arc::new(contacts)
}

/// A private chat session over the file-backed store at `home`, resuming
/// `session_id` when given. The title is the message, as the daemon passes it.
#[allow(clippy::too_many_arguments)]
fn private_session<'a>(
    provider: &'a dyn ChatProvider,
    store: &Arc<Mutex<Store>>,
    home: &Path,
    budgets: &'a Budgets,
    prices: &'a PriceTable,
    session_id: Option<i64>,
    title: &str,
) -> ChatSession<'a> {
    ChatSession::start(ChatSetup {
        mode: std::sync::Arc::new(|| kernel_core::privacy::PrivacyMode::Private),
        contacts: camille_contacts(),
        store: StoreHandle::Shared(Arc::clone(store)),
        provider,
        registry: Arc::new(RwLock::new(ToolRegistry::with_defaults())),
        rules: Vec::new(),
        approver: Arc::new(AutoApproveApprover),
        agent: "main".to_string(),
        home: home.to_path_buf(),
        skills: Vec::new(),
        budgets,
        prices,
        context: ContextConfig::default(),
        title: Some(title.to_string()),
        stop: None,
        cancel: None,
        session_id,
        events: None,
        run_id: None,
    })
    .unwrap()
}

/// Every text or blob value, in every table of the encrypted store at `db`,
/// that holds one of `needles`. The store is SQLCipher over the whole file, so
/// the rows are read through its key, not by scanning bytes.
fn stored_text_containing(db: &Path, needles: &[&str]) -> Vec<String> {
    let conn = aux_store::open_keyed_readonly(db).unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut hits = Vec::new();
    for table in tables {
        let mut statement = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let columns = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for index in 0..columns {
                let text = match row.get_ref(index).unwrap() {
                    rusqlite::types::ValueRef::Text(bytes)
                    | rusqlite::types::ValueRef::Blob(bytes) => {
                        String::from_utf8_lossy(bytes).into_owned()
                    }
                    _ => continue,
                };
                if needles.iter().any(|needle| text.contains(needle)) {
                    hits.push(format!("{table}: {text}"));
                }
            }
        }
    }
    hits
}

#[tokio::test]
async fn a_private_turn_keeps_its_text_only_in_the_chat_history_and_the_next_turn_still_sees_it() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let db = home.join("store.db");
    let store = Arc::new(Mutex::new(Store::open(&db).unwrap()));
    let server = MockServer::start().await;
    mount_reply(&server).await;
    let provider = provider(&server);
    let budgets = Budgets::default();
    let prices = canary_prices();
    let repro = "Dis bonjour à Camille Exemple, camille@exemple.fr.";

    let mut first = private_session(&provider, &store, &home, &budgets, &prices, None, repro);
    first.send(repro).await.unwrap();
    let session_id = first.session().id;
    drop(first);

    // A new session object resumes the same conversation.
    let mut second = private_session(
        &provider,
        &store,
        &home,
        &budgets,
        &prices,
        Some(session_id),
        "Et demain ?",
    );
    second.send("Et demain ?").await.unwrap();
    drop(second);

    // The rows hold tokens; a value sits only in the session's token table,
    // never in messages, audit, events or usage. Names are not hidden, so only
    // the e-mail is a hidden value.
    let hits = stored_text_containing(&db, &["camille@exemple.fr"]);
    assert!(
        !hits.is_empty(),
        "the private turn's token table was not kept"
    );
    let elsewhere: Vec<_> = hits
        .iter()
        .filter(|hit| !hit.starts_with("session_tokens: "))
        .collect();
    assert!(
        elsewhere.is_empty(),
        "raw text reached the store: {elsewhere:?}"
    );

    let bodies = wire_bodies(&server).await;
    assert_eq!(bodies.len(), 2, "one provider call per turn");
    let email = token_of(&bodies[0], "EMAIL");
    assert!(
        bodies[1].contains(&email),
        "the second turn lost the first turn's token"
    );
}
