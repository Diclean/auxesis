//! CRM acceptance: the CRM skills run through the daemon's skill dispatch.
//!
//! The fake provider is the "fake brain": it forces `skill__client-brief`,
//! `skill__log-interaction` or `skill__brief` once, with the tokens it was
//! shown. The daemon's own [`attach_skill_runtime`] hands the executor the CRM
//! connector, so the reads and the write are the real ones over a temp home's
//! store.
//!
//! What the tests prove:
//! * `client-brief` in Private mode: the provider's next request carries the
//!   party's token, never the cleartext name.
//! * `log-interaction` writes one interaction and its party-linked memory with
//!   the `skill:log-interaction` provenance.
//! * stored CRM text (timeline, follow-up reasons, memory) that holds an IBAN,
//!   a card, a secret or a health term never reaches the provider in Private
//!   mode, for `client-brief` and for the `log-interaction` echo.
//! * a denied card writes nothing.
//! * `brief` reads the due follow-ups (and the parties) from the store.

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, RwLock};

use async_trait::async_trait;
use aux_crm::{Crm, NewParty, PartyKind};
use aux_engine::{ChatSession, ChatSetup};
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use aux_store::{Store, StoreHandle};
use auxd::skill_executor::{attach_skill_runtime, SkillConnectors};
use kernel_broker::{ApprovalRequest, Approver, ApproverError, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::PrivacyMode;
use kernel_core::ContextConfig;
use kernel_privacy::ContactIndex;
use serde_json::{json, Value};
use tempfile::TempDir;

const CLIENT_BRIEF: &str =
    include_str!("../../aux-runtime/src/skills/fixtures/skills/client-brief.md");
const LOG_INTERACTION: &str =
    include_str!("../../aux-runtime/src/skills/fixtures/skills/log-interaction.md");
const BRIEF: &str = include_str!("../../aux-runtime/src/skills/fixtures/skills/brief.md");

const AGENT: &str = "---
name: assistant
brain: cloud
default_mode: open
channels: [mac]
tools:
  - crm.search
  - crm.get
  - crm.today
  - crm.create_followup
  - crm.log_interaction
  - docs.queue
recipients:
  policy: known-contacts
  allowlist: []
---
CRM skills assistant.
";

/// A temp home with the three B4 skills, one party and an optional due
/// follow-up.
struct Rig {
    _dir: TempDir,
    home: PathBuf,
    store: Arc<StdMutex<Store>>,
    workspace: PathBuf,
    contacts: Arc<ContactIndex>,
    party_id: i64,
}

impl Rig {
    fn new(mode: &str, due: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let agent_dir = home.join("agents").join("assistant");
        std::fs::create_dir_all(agent_dir.join("skills")).unwrap();
        std::fs::write(agent_dir.join("agent.md"), AGENT).unwrap();
        std::fs::write(
            agent_dir.join("skills").join("client-brief.md"),
            CLIENT_BRIEF,
        )
        .unwrap();
        std::fs::write(
            agent_dir.join("skills").join("log-interaction.md"),
            LOG_INTERACTION,
        )
        .unwrap();
        std::fs::write(agent_dir.join("skills").join("brief.md"), BRIEF).unwrap();
        std::fs::write(
            kernel_core::config_path(&home),
            format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n"),
        )
        .unwrap();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();

        let store = Arc::new(StdMutex::new(
            Store::open(&kernel_core::store_path(&home)).unwrap(),
        ));
        let party = {
            let guard = store.lock().unwrap();
            Crm::new(&guard)
                .create(NewParty {
                    kind: PartyKind::Person,
                    display_name: "Camille Exemple".to_string(),
                    name_variants: vec!["Camille".to_string()],
                    emails: vec!["camille@exemple.test".to_string()],
                    origin: "owner".to_string(),
                    ..NewParty::default()
                })
                .unwrap()
        };
        if let Some(due) = due {
            store
                .lock()
                .unwrap()
                .insert_followup(party.id, due, "Envoyer le devis", "owner", "open")
                .unwrap();
        }
        let mut contacts = ContactIndex::new();
        contacts.add_from_header("Camille Exemple", "camille@exemple.test");
        Rig {
            _dir: dir,
            home,
            store,
            workspace,
            contacts: Arc::new(contacts),
            party_id: party.id,
        }
    }
}

/// Stored values that must never reach a model in the clear.
const IBAN: &str = "FR76 3000 6000 0112 3456 7890 189";
const CARD: &str = "4111 1111 1111 1111";
const SECRET: &str = concat!("sk-", "proj-AbCdEf1234567890abcdef1234567890");
const HEALTH: &str = "chimiothérapie";

/// Store free text that carries each prohibited class, on the rig's party.
fn seed_sensitive(rig: &Rig) {
    let guard = rig.store.lock().unwrap();
    guard
        .insert_interaction(
            rig.party_id,
            "note",
            "2026-10-05T09:00:00Z",
            "{\"owner\":true}",
            &format!("Virement sur {IBAN}, carte {CARD}"),
            "owner",
        )
        .unwrap();
    guard
        .insert_followup(
            rig.party_id,
            "2026-10-06",
            &format!("Rappeler pour la {HEALTH}"),
            "owner",
            "open",
        )
        .unwrap();
    guard
        .create_memory_item_for_party(
            "assistant",
            &aux_store::NewMemoryItem {
                kind: "fact",
                title: "Accès",
                body: &format!("Clé API {SECRET} ; IBAN {IBAN}"),
                fact_key: None,
                confidence: None,
                source: "owner",
                trust: "owner",
                tainted: false,
                state: "active",
                supersedes_id: None,
                valid_from: None,
                valid_to: None,
            },
            rig.party_id,
        )
        .unwrap();
}

/// The raw value, and its spaceless form, must be absent from `seen`.
fn assert_withheld(seen: &str, raw: &str) {
    let compact: String = raw.split_whitespace().collect();
    assert!(!seen.contains(raw), "`{raw}` reached the provider: {seen}");
    assert!(
        !seen.contains(&compact),
        "`{compact}` reached the provider: {seen}"
    );
}

/// The stored rows reached the model, each prohibited class as a kernel token.
fn assert_tokenised(seen: &str) {
    for kind in ["IBAN", "CREDIT_CARD", "SECRET", "HEALTH"] {
        assert!(
            seen.contains(&format!("⟦{kind}_")),
            "no {kind} token in the model's request: {seen}"
        );
    }
}

/// Which skill the fake brain forces.
#[derive(Clone, Copy)]
enum Case {
    ClientBrief,
    LogInteraction,
    /// `log-interaction` whose model-written summary repeats prohibited values.
    LogSensitive,
    Brief,
}

/// The fake brain: its first answer forces the skill's fill; every later answer
/// is plain text. Every request's text and offered tools are kept.
struct CrmProvider {
    case: Case,
    calls: StdMutex<usize>,
    seen: StdMutex<Vec<String>>,
    offered: StdMutex<Vec<Vec<String>>>,
}

impl CrmProvider {
    fn new(case: Case) -> Self {
        Self {
            case,
            calls: StdMutex::new(0),
            seen: StdMutex::new(Vec::new()),
            offered: StdMutex::new(Vec::new()),
        }
    }

    /// The first `⟦PERSON_…⟧` token in `text`, or the literal name.
    fn person(text: &str) -> String {
        if let Some(start) = text.find("⟦PERSON_") {
            if let Some(end) = text[start..].find('⟧') {
                return text[start..start + end + '⟧'.len_utf8()].to_string();
            }
        }
        "Camille Exemple".to_string()
    }

    fn skill(&self) -> &'static str {
        match self.case {
            Case::ClientBrief => "skill__client-brief",
            Case::LogInteraction | Case::LogSensitive => "skill__log-interaction",
            Case::Brief => "skill__brief",
        }
    }

    fn fill(&self, text: &str) -> Value {
        let person = Self::person(text);
        match self.case {
            Case::ClientBrief => json!({
                "slots": { "name": person },
                "calls": [{
                    "tool": "crm_get",
                    "arguments": { "name": person, "timeline": 5, "memory": 20 },
                }],
            }),
            Case::LogInteraction | Case::LogSensitive => json!({
                "slots": { "party": person, "note": "Appel de suivi" },
                "calls": [{
                    "tool": "crm_log_interaction",
                    "arguments": {
                        "party": person,
                        "kind": "note",
                        "at": "2026-10-06T10:00:00Z",
                        "source_ref": "{\"owner\":true}",
                        "summary": if matches!(self.case, Case::LogSensitive) {
                            format!("{person}: {IBAN}, {CARD}, {SECRET}, {HEALTH}")
                        } else {
                            format!("Appel de suivi avec {person}")
                        },
                        "memory": [{
                            "kind": "fact",
                            "title": "Appel de suivi",
                            "body": "Rappeler la semaine prochaine.",
                        }],
                    },
                }],
            }),
            Case::Brief => json!({
                "slots": { "focus": "aujourd'hui" },
                "calls": [
                    { "tool": "crm_today", "arguments": {} },
                    { "tool": "docs_queue", "arguments": {} },
                ],
            }),
        }
    }
}

#[async_trait]
impl ChatProvider for CrmProvider {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let text = request
            .messages
            .iter()
            .map(|message| message.content().as_str().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        self.seen.lock().unwrap().push(text.clone());
        self.offered.lock().unwrap().push(
            request
                .tools
                .iter()
                .map(|tool| tool.name().as_str().to_string())
                .collect(),
        );
        let mut calls = self.calls.lock().unwrap();
        *calls += 1;
        if *calls == 1 {
            return Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new("call-1", self.skill(), self.fill(&text))],
            )));
        }
        Ok(ChatResponse::assistant("Fait."))
    }

    fn name(&self) -> &str {
        "crm-fake"
    }
}

/// The owner's approval channel.
struct Answer(bool);

#[async_trait]
impl Approver for Answer {
    async fn approve(&self, _: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(self.0)
    }
}

/// Drive one forced-skill turn through the daemon's attach helper.
/// Returns whether the turn ended tainted.
async fn drive(
    rig: &Rig,
    provider: &CrmProvider,
    private: bool,
    allow: bool,
    message: &str,
) -> bool {
    let budgets = Budgets::default();
    let prices = PriceTable::default();
    let contacts = Arc::clone(&rig.contacts);
    let mode: kernel_core::privacy::ModeFn = if private {
        Arc::new(|| PrivacyMode::Private)
    } else {
        Arc::new(|| PrivacyMode::Open)
    };
    let session = ChatSession::start(ChatSetup {
        mode,
        contacts: Arc::clone(&contacts),
        store: StoreHandle::Shared(Arc::clone(&rig.store)),
        provider,
        registry: Arc::new(RwLock::new(ToolRegistry::with_defaults())),
        rules: Vec::new(),
        approver: Arc::new(Answer(allow)),
        agent: "assistant".to_string(),
        home: rig.home.clone(),
        skills: Vec::new(),
        budgets: &budgets,
        prices: &prices,
        context: ContextConfig::default(),
        title: None,
        stop: None,
        cancel: None,
        session_id: None,
        events: None,
        run_id: Some("crm-run".to_string()),
    })
    .unwrap();
    let crm = auxd::crm::CrmSkillConnector::new(&rig.home, "assistant", Arc::clone(&rig.store));
    let connectors = SkillConnectors {
        crm: Some(crm),
        ..Default::default()
    };
    let mut session = attach_skill_runtime(
        session,
        connectors,
        "assistant",
        rig.workspace.clone(),
        Some("crm-run".to_string()),
        contacts,
    );
    let outcome = session.send(message).await.expect("the turn completes");
    assert_eq!(outcome.text, "Fait.");
    session.taint().forces_ask()
}

/// A skill's connector replies are untrusted, so a clean turn
/// that ran one is tainted before the model sees them; a CRM write the model
/// makes next keeps its card.
#[tokio::test]
async fn a_skill_run_taints_the_turn() {
    let rig = Rig::new("taint", None);
    let provider = CrmProvider::new(Case::ClientBrief);
    assert!(drive(&rig, &provider, false, true, "brief Camille Exemple").await);
}

#[tokio::test]
async fn client_brief_in_private_mode_sends_the_name_and_a_token_for_the_address() {
    let rig = Rig::new("private", None);
    let provider = CrmProvider::new(Case::ClientBrief);
    drive(&rig, &provider, true, true, "brief Camille Exemple").await;

    // The skill was offered, and the read ran inside it.
    let offered = provider.offered.lock().unwrap().clone();
    assert!(
        offered[0].iter().any(|tool| tool == "skill__client-brief"),
        "the skill is offered: {offered:?}"
    );
    let seen = provider.seen.lock().unwrap().join("\n");
    // The party's name passes as written.
    assert!(seen.contains("Camille Exemple"), "{seen}");
    assert!(
        !seen.contains("camille@exemple.test"),
        "a cleartext address reached the provider: {seen}"
    );
    assert!(!seen.contains("⟦PERSON_"), "{seen}");
    // The read itself ran: the executor logged one `crm_get` action.
    let actions = rig
        .store
        .lock()
        .unwrap()
        .event_payloads("skill.action")
        .unwrap();
    let actions: Vec<Value> = actions
        .iter()
        .map(|payload| serde_json::from_str(payload).unwrap())
        .collect();
    assert!(
        actions
            .iter()
            .any(|action| action["tool"] == "crm_get" && action["outcome"] == "ok"),
        "the crm_get read ran: {actions:?}"
    );
}

#[tokio::test]
async fn log_interaction_writes_memory_with_party_id_and_provenance() {
    let rig = Rig::new("open", None);
    let provider = CrmProvider::new(Case::LogInteraction);
    drive(
        &rig,
        &provider,
        false,
        true,
        "log an interaction with Camille Exemple",
    )
    .await;

    let guard = rig.store.lock().unwrap();
    let interactions = guard.interactions_for_party(rig.party_id).unwrap();
    assert_eq!(interactions.len(), 1);
    assert_eq!(interactions[0].kind, "note");
    assert_eq!(interactions[0].provenance, "skill:log-interaction");
    assert!(interactions[0].summary.contains("Camille Exemple"));

    let memory = guard
        .memory_items_for_party("assistant", rig.party_id, 10)
        .unwrap();
    assert_eq!(memory.len(), 1, "one memory row with party_id");
    assert_eq!(memory[0].source, "skill:log-interaction");
    assert_eq!(memory[0].kind, "fact");
    assert_eq!(memory[0].title, "Appel de suivi");
}

#[tokio::test]
async fn a_denied_card_writes_nothing() {
    let rig = Rig::new("open", None);
    let provider = CrmProvider::new(Case::LogInteraction);
    drive(
        &rig,
        &provider,
        false,
        false,
        "log an interaction with Camille Exemple",
    )
    .await;

    let guard = rig.store.lock().unwrap();
    assert!(guard
        .interactions_for_party(rig.party_id)
        .unwrap()
        .is_empty());
    assert!(guard
        .memory_items_for_party("assistant", rig.party_id, 10)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn brief_lists_today_parties_and_due_followups() {
    // The party is among today's event attendees (the aux-crm fixture test
    // proves the attendee match); here the store holds the due follow-up the
    // brief must list.
    let rig = Rig::new("open", Some("2026-10-06"));
    let provider = CrmProvider::new(Case::Brief);
    drive(&rig, &provider, false, true, "brief me").await;

    let offered = provider.offered.lock().unwrap().clone();
    assert!(
        offered[0].iter().any(|tool| tool == "skill__brief"),
        "the brief skill is offered: {offered:?}"
    );
    let seen = provider.seen.lock().unwrap().join("\n");
    assert!(
        seen.contains("Envoyer le devis"),
        "the due reason is listed: {seen}"
    );
    assert!(
        seen.contains("Camille Exemple"),
        "the party is listed: {seen}"
    );
    assert!(
        seen.contains("due_followups"),
        "the CRM section is present: {seen}"
    );
}

#[tokio::test]
async fn client_brief_withholds_prohibited_classes_from_stored_text() {
    let rig = Rig::new("private", None);
    seed_sensitive(&rig);
    let provider = CrmProvider::new(Case::ClientBrief);
    drive(&rig, &provider, true, true, "brief Camille Exemple").await;

    // The read ran and returned the stored rows to the executor.
    let actions = rig
        .store
        .lock()
        .unwrap()
        .event_payloads("skill.action")
        .unwrap();
    assert!(
        actions.iter().any(|payload| payload.contains("crm_get")),
        "the crm_get read ran: {actions:?}"
    );
    // The follow-up to the model carries the CRM result: it must hold tokens,
    // never the stored IBAN, card, secret or health term.
    let seen = provider.seen.lock().unwrap().clone();
    assert!(seen.len() >= 2, "the result reached a second request");
    let seen = seen.join("\n");
    for raw in [IBAN, CARD, SECRET, HEALTH] {
        assert_withheld(&seen, raw);
    }
    assert_tokenised(&seen);
    assert!(
        seen.contains("Camille Exemple") && !seen.contains("⟦PERSON_"),
        "the client name passes as written: {seen}"
    );
}

#[tokio::test]
async fn log_interaction_echo_withholds_prohibited_classes() {
    let rig = Rig::new("private", None);
    let provider = CrmProvider::new(Case::LogSensitive);
    drive(
        &rig,
        &provider,
        true,
        true,
        "log an interaction with Camille Exemple",
    )
    .await;

    // The write ran, and the second request (the echo) is clean.
    let guard = rig.store.lock().unwrap();
    assert_eq!(guard.interactions_for_party(rig.party_id).unwrap().len(), 1);
    drop(guard);
    let seen = provider.seen.lock().unwrap().clone();
    assert!(seen.len() >= 2, "the result reached a second request");
    let seen = seen.join("\n");
    for raw in [IBAN, CARD, SECRET, HEALTH] {
        assert_withheld(&seen, raw);
    }
    // The echo is ids only: no stored text rides back to the model.
    assert!(
        seen.contains(r#""result":{"interaction_id":1,"memory_ids":[1]}"#),
        "the echo is ids only: {seen}"
    );
}
