//! Hero test for the invite skill (`docs/mail.md` §5).
//!
//! An owner's `/invite` message drives the `send-invite` skill end to end with
//! the fake provider. The provider fills the skill with tokens only (Private)
//! or with the owner's values (Open). Exactly one approval card covers the run.
//! Google receives nothing before the owner approves; after approval it gets
//! one calendar insert and one Gmail send, both with the real recipient and no
//! token delimiters left in the body.
//!
//! The Private variant runs on kernel-0.0.2 (K07): private-mode chat (A1/A2) is
//! covered, and the owner's contact supplies the names the gate masks. The
//! session and the skill run read the same contacts index.

// MA4: the frozen Google writes only exist when the `google` feature is on.
#![cfg(feature = "google")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, RwLock};

use async_trait::async_trait;
use aux_engine::{ChatError, ChatSession, ChatSetup, StopCheck, TurnCancel};
use aux_google::tools::{GoogleTools, StaticAuth};
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use aux_store::{Store, StoreHandle};
use auxd::skill_executor::attach_skill_runtime;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kernel_broker::{ApprovalRequest, Approver, ApproverError, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::PrivacyMode;
use kernel_core::ContextConfig;
use kernel_privacy::ContactIndex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::{tempdir, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

// MA4: this Google-only test keeps its own Google skill text; the shared
// fixture now points at the EventKit create and the SMTP send.
const SEND_INVITE: &str = "---
name: send-invite
version: 1
command: invite
trigger:
  manual: true
  schedule: null
  on: null
tools: [google.calendar.create_event, google.gmail.send]
inputs:
  person:   { tier: H }
  email:    { type: email, tier: C, from: contact(person) }
  when:     { type: datetime }
  duration: { type: duration, default: 30m }
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Create a {duration} calendar event titled \"Meeting with {person}\" at {when} and
invite {email}. Then send a short, polite confirmation email in the language of
the conversation. Do not add anyone else. Do not change the time.
";

const AGENT: &str = "---
name: assistant
brain: cloud
default_mode: private
channels: [mac]
tools:
  - google.calendar.create_event
  - google.gmail.send
recipients:
  policy: known-contacts
  allowlist: []
---
Hero test assistant.
";

const OWNER_MESSAGE: &str = "/invite Camille Exemple camille@exemple.fr tomorrow 10:00";
const CALENDAR_PATH: &str = "/calendar/v3/calendars/primary/events";
const GMAIL_PATH: &str = "/gmail/v1/users/me/messages/send";

/// What the owner's approval channel saw, and how many Google requests had
/// already arrived when it answered.
#[derive(Default)]
struct CardRecord {
    cards: Vec<ApprovalRequest>,
    google_before_answer: Vec<usize>,
}

/// The owner's approval channel: records one card per run and answers `allow`.
struct OwnerApprover {
    google: Arc<MockServer>,
    record: Arc<StdMutex<CardRecord>>,
}

#[async_trait]
impl Approver for OwnerApprover {
    async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
        let seen = self
            .google
            .received_requests()
            .await
            .map_or(0, |requests| requests.len());
        let mut record = self.record.lock().unwrap();
        record.cards.push(request.clone());
        record.google_before_answer.push(seen);
        Ok(true)
    }
}

/// The fake provider. Its first answer calls `skill__send-invite` with the
/// values it was shown: tokens in Private mode, the owner's text in Open mode.
/// Its second answer is plain text. Every request's text is kept for the
/// masking assertions.
struct HeroProvider {
    private: bool,
    seen: StdMutex<Vec<String>>,
    answered: StdMutex<usize>,
    tool_results: StdMutex<Vec<String>>,
    /// The tool names offered in each round, in order.
    offered: StdMutex<Vec<Vec<String>>>,
}

impl HeroProvider {
    fn new(private: bool) -> Self {
        HeroProvider {
            private,
            seen: StdMutex::new(Vec::new()),
            answered: StdMutex::new(0),
            tool_results: StdMutex::new(Vec::new()),
            offered: StdMutex::new(Vec::new()),
        }
    }

    /// The first `⟦<kind>…⟧` token in `text`, delimiters included.
    fn token(text: &str, kind: &str) -> Option<String> {
        let start = text.find(&format!("⟦{kind}"))?;
        let end = text[start..].find('⟧')? + start + '⟧'.len_utf8();
        Some(text[start..end].to_string())
    }

    fn skill_call(&self, text: &str) -> ChatResponse {
        // `email` is derived from `person`: the model invents an address in
        // every recipient field, and the runtime replaces each with the
        // contact's address (`docs/phase1.md` §7).
        let person = if self.private {
            Self::token(text, "PERSON_").expect("the owner's name is tokenised")
        } else {
            "Camille Exemple".to_string()
        };
        let arguments = json!({
            "slots": {
                "person": person,
                "when": "tomorrow 10:00",
                "duration": "PT30M",
            },
            "calls": [
                {
                    "tool": "google_calendar_create_event",
                    "arguments": {
                        "summary": format!("Meeting with {person}"),
                        "start": "2026-10-11T10:00:00+02:00",
                        "end": "2026-10-11T10:30:00+02:00",
                        "attendees": [{ "email": "x@invented.example" }],
                    },
                },
                {
                    "tool": "google_gmail_send",
                    "arguments": {
                        "to": "billing@invented.example",
                        "subject": "Invitation",
                        "body": format!("Bonjour, invitation confirmée avec {person}."),
                    },
                },
            ],
        });
        ChatResponse {
            message: ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new("call-1", "skill__send-invite", arguments)],
            ),
            usage: None,
        }
    }
}

#[async_trait]
impl ChatProvider for HeroProvider {
    async fn complete(&self, req: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        let texts: Vec<String> = req
            .messages
            .iter()
            .map(|message| message.content().as_str().to_string())
            .collect();
        self.seen.lock().unwrap().extend(texts.iter().cloned());
        self.tool_results.lock().unwrap().extend(
            req.messages
                .iter()
                .filter(|message| message.tool_call_id().is_some())
                .map(|message| message.content().as_str().to_string()),
        );
        self.offered.lock().unwrap().push(
            req.tools
                .iter()
                .map(|tool| tool.name().as_str().to_string())
                .collect(),
        );
        let mut answered = self.answered.lock().unwrap();
        *answered += 1;
        if *answered == 1 {
            let owner = texts.last().cloned().unwrap_or_default();
            return Ok(self.skill_call(&owner));
        }
        Ok(ChatResponse::assistant("Invitation envoyée."))
    }

    fn name(&self) -> &str {
        "hero-fake"
    }
}

/// Mount the two Google writes the skill makes.
async fn mount_google(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(CALENDAR_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "evt-1" })))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(GMAIL_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "msg-1" })))
        .expect(1)
        .mount(server)
        .await;
}

/// Every `skill.action` payload, parsed.
fn action_rows(store: &Arc<StdMutex<Store>>) -> Vec<Value> {
    store
        .lock()
        .unwrap()
        .event_payloads("skill.action")
        .unwrap()
        .iter()
        .map(|payload| serde_json::from_str(payload).unwrap())
        .collect()
}

/// The `raw` RFC 822 message of a Gmail send, decoded.
fn decoded_mail(body: &Value) -> String {
    let raw = body["raw"]
        .as_str()
        .expect("gmail send carries a raw message");
    String::from_utf8(URL_SAFE_NO_PAD.decode(raw).unwrap()).unwrap()
}

/// A fresh home, workspace, store and Google fake for one hero-style run.
struct Rig {
    _dir: TempDir,
    home: PathBuf,
    workspace: PathBuf,
    store: Arc<StdMutex<Store>>,
    google_server: Arc<MockServer>,
}

async fn rig() -> Rig {
    let dir: TempDir = tempdir().unwrap();
    let home: PathBuf = dir.path().join("home");
    let agent_dir = home.join("agents").join("assistant");
    std::fs::create_dir_all(agent_dir.join("skills")).unwrap();
    std::fs::write(agent_dir.join("agent.md"), AGENT).unwrap();
    std::fs::write(agent_dir.join("skills").join("send-invite.md"), SEND_INVITE).unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let google_server = Arc::new(MockServer::start().await);
    mount_google(&google_server).await;
    let store = Arc::new(StdMutex::new(Store::open_in_memory().unwrap()));
    Rig {
        _dir: dir,
        home,
        workspace,
        store,
        google_server,
    }
}

/// The Google tools bound to the fake server, as the daemon builds them.
fn google_for(rig: &Rig) -> GoogleTools {
    GoogleTools::new_with_bases_for_tests(
        Arc::new(StaticAuth("hero-token".to_string())),
        Arc::clone(&rig.store),
        Budgets::default(),
        &format!("{}/gmail/v1/users/me/", rig.google_server.uri()),
        &format!("{}/calendar/v3/", rig.google_server.uri()),
    )
    .unwrap()
}

/// The owner's one known contact, as a directory.
fn known_contact() -> Arc<ContactIndex> {
    let mut contacts = ContactIndex::new();
    assert!(
        contacts
            .add_from_header("Camille Exemple", "camille@exemple.fr")
            .is_some(),
        "the owner's contact is known"
    );
    Arc::new(contacts)
}

/// What the provider was shown, once the turn is over.
struct Seen {
    texts: String,
    tool_results: String,
    offered: Vec<Vec<String>>,
}

/// Drive the owner's `/invite` through the daemon's attach helper. Returns the
/// turn's result and what the provider saw.
async fn drive(
    rig: &Rig,
    private: bool,
    approver: Arc<dyn Approver>,
    stop: Option<Arc<dyn StopCheck>>,
    cancel: Option<Arc<TurnCancel>>,
) -> (Result<String, ChatError>, Seen) {
    drive_with(rig, private, approver, stop, cancel, known_contact()).await
}

/// [`drive`] over the owner's `contacts`: the session's names and the skill run's
/// `known-contacts` directory are both read from this one index.
async fn drive_with(
    rig: &Rig,
    private: bool,
    approver: Arc<dyn Approver>,
    stop: Option<Arc<dyn StopCheck>>,
    cancel: Option<Arc<TurnCancel>>,
    contacts: Arc<ContactIndex>,
) -> (Result<String, ChatError>, Seen) {
    let mut registry = ToolRegistry::with_defaults();
    let google = google_for(rig);
    google.register_into(&mut registry);
    for tool in google.skill_tools() {
        registry.register_native(tool);
    }
    let registry = Arc::new(RwLock::new(registry));
    let provider = HeroProvider::new(private);
    let budgets = Budgets::default();
    let prices = PriceTable::default();
    let mode: kernel_core::privacy::ModeFn = if private {
        Arc::new(|| PrivacyMode::Private)
    } else {
        Arc::new(|| PrivacyMode::Open)
    };
    let session = ChatSession::start(ChatSetup {
        mode,
        contacts: Arc::clone(&contacts),
        store: StoreHandle::Shared(Arc::clone(&rig.store)),
        provider: &provider,
        registry,
        rules: Vec::new(),
        approver,
        agent: "assistant".to_string(),
        home: rig.home.clone(),
        skills: Vec::new(),
        budgets: &budgets,
        prices: &prices,
        context: ContextConfig::default(),
        title: None,
        stop,
        cancel,
        session_id: None,
        events: None,
        run_id: Some("hero-run".to_string()),
    })
    .unwrap();
    // The same attach the daemon's turn path runs.
    let mut session = attach_skill_runtime(
        session,
        auxd::skill_executor::SkillConnectors {
            google: Some(google),
            ..Default::default()
        },
        "assistant",
        rig.workspace.clone(),
        Some("hero-run".to_string()),
        contacts,
    );
    let outcome = session.send(OWNER_MESSAGE).await.map(|out| out.text);
    drop(session);
    let seen = Seen {
        texts: provider.seen.lock().unwrap().join("\n"),
        tool_results: provider.tool_results.lock().unwrap().join("\n"),
        offered: provider.offered.lock().unwrap().clone(),
    };
    (outcome, seen)
}

async fn run_hero(private: bool) {
    let rig = rig().await;
    let record = Arc::new(StdMutex::new(CardRecord::default()));
    let approver = Arc::new(OwnerApprover {
        google: Arc::clone(&rig.google_server),
        record: Arc::clone(&record),
    });
    let (outcome, seen) = drive(&rig, private, approver, None, None).await;
    assert_eq!(outcome.unwrap(), "Invitation envoyée.");

    // The owner's `/invite` forces its skill: that skill is the only tool
    // offered, in every round of the turn.
    assert_eq!(
        seen.offered.len(),
        2,
        "two rounds: the fill, then the reply"
    );
    for round in &seen.offered {
        assert_eq!(
            round,
            &["skill__send-invite"],
            "forced turn offers one tool"
        );
    }

    // The provider never saw the owner's name or address in Private mode.
    if private {
        assert!(!seen.texts.contains("Camille"), "provider saw the name");
        assert!(
            !seen.texts.contains("camille@exemple.fr"),
            "provider saw the address"
        );
    }
    // The tool result it got back is tokenised: the real values never return.
    assert!(
        seen.tool_results.contains("done"),
        "the run reports done: {}",
        seen.tool_results
    );
    if private {
        assert!(
            !seen.tool_results.contains("camille@exemple.fr"),
            "result carries the address"
        );
    }

    // One approval card covers the whole run, listing both writes.
    let (cards, google_before_answer) = {
        let record = record.lock().unwrap();
        (record.cards.clone(), record.google_before_answer.clone())
    };
    assert_eq!(cards.len(), 1, "exactly one approval card");
    let card = &cards[0];
    assert_eq!(card.tool, "skill__send-invite");
    let tools: Vec<&str> = card.arguments["calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert_eq!(tools, ["google_calendar_create_event", "google_gmail_send"]);
    // Google saw nothing before the owner answered.
    assert_eq!(
        google_before_answer,
        [0_usize],
        "no Google request before approval"
    );

    // After approval: one insert with the real attendee, one send to the real
    // recipient, and no token delimiter in the mail body.
    let requests = rig.google_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2, "one calendar insert and one Gmail send");
    // The model's invented address never reached Google, in any request.
    for request in &requests {
        let body = String::from_utf8_lossy(&request.body);
        assert!(
            !body.contains("invented.example"),
            "the invented address reached Google: {body}"
        );
    }
    let insert = requests
        .iter()
        .find(|request| request.url.path() == CALENDAR_PATH)
        .expect("calendar insert");
    let insert_body: Value = serde_json::from_slice(&insert.body).unwrap();
    assert_eq!(insert_body["attendees"][0]["email"], "camille@exemple.fr");
    let send = requests
        .iter()
        .find(|request| request.url.path() == GMAIL_PATH)
        .expect("gmail send");
    let mail = decoded_mail(&serde_json::from_slice(&send.body).unwrap());
    assert!(
        mail.contains("camille@exemple.fr"),
        "mail goes to the real recipient"
    );
    assert!(
        !mail.contains('⟦') && !mail.contains('⟧'),
        "no token delimiter in the mail"
    );

    // The Ledger: two `skill.action` rows, both under the same skill hash.
    let actions = action_rows(&rig.store);
    assert_eq!(actions.len(), 2, "one skill.action row per executed call");
    let hash = actions[0]["skill_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64, "the skill hash is blake3 hex");
    assert!(actions.iter().all(|row| row["skill_hash"] == hash));
}

#[tokio::test]
async fn hero_open_mode_runs_the_send_invite_skill_end_to_end() {
    run_hero(false).await;
}

#[tokio::test]
async fn hero_private_mode_masks_the_names_end_to_end() {
    run_hero(true).await;
}

/// The derivation holds in private mode too. The owner's contacts do not hold
/// the invitee, so the derived address cannot be resolved and the run stops
/// before any Google request: no approval for an unknown recipient reaches
/// Google, and no action row is written.
#[tokio::test]
async fn hero_private_mode_refuses_a_recipient_outside_the_known_contacts() {
    let rig = rig().await;
    // Nothing may be sent: drop the default write expectations, as the cancel test does.
    rig.google_server.reset().await;
    let mut others = ContactIndex::new();
    assert!(
        others
            .add_from_header("Jordan Exemple", "jordan@exemple.fr")
            .is_some(),
        "the other contact is known"
    );
    let record = Arc::new(StdMutex::new(CardRecord::default()));
    let approver = Arc::new(OwnerApprover {
        google: Arc::clone(&rig.google_server),
        record,
    });
    let (outcome, seen) = drive_with(&rig, true, approver, None, None, Arc::new(others)).await;
    outcome.expect("the turn completes with the refusal as its tool result");

    // The refusal reason reaches the provider, and the run is recorded as refused.
    assert!(
        seen.tool_results.contains("no address for"),
        "the tool result did not carry the refusal: {}",
        seen.tool_results
    );
    let runs: Vec<Value> = rig
        .store
        .lock()
        .unwrap()
        .event_payloads("skill.run")
        .unwrap()
        .iter()
        .map(|payload| serde_json::from_str(payload).unwrap())
        .collect();
    assert_eq!(runs.len(), 1, "one skill.run row: {runs:?}");
    assert_eq!(runs[0]["outcome"], "refused", "{runs:?}");

    let requests = rig.google_server.received_requests().await.unwrap();
    assert!(
        requests.is_empty(),
        "no Google request for an unknown recipient"
    );
    assert!(action_rows(&rig.store).is_empty(), "no skill.action row");
}

/// An owner who never answers. The approval stays pending until the turn is
/// cancelled.
struct NeverAnswers;

#[async_trait]
impl Approver for NeverAnswers {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        std::future::pending().await
    }
}

/// P2-3: a cancel while the card is pending ends the turn, and Google sees
/// nothing and the run writes no `skill.run` row.
#[tokio::test]
async fn hero_cancel_while_approval_is_pending_sends_nothing() {
    let rig = rig().await;
    // Nothing may be sent, so the default write expectations are dropped: any
    // request would now be recorded and fail the assertion below.
    rig.google_server.reset().await;
    let cancel = TurnCancel::new();
    let canceller = Arc::clone(&cancel);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        canceller.cancel();
    });
    let (outcome, _seen) = drive(
        &rig,
        false,
        Arc::new(NeverAnswers),
        None,
        Some(Arc::clone(&cancel)),
    )
    .await;
    assert!(
        matches!(outcome, Err(ChatError::Cancelled)),
        "the turn is cancelled: {outcome:?}"
    );
    let requests = rig.google_server.received_requests().await.unwrap();
    assert!(requests.is_empty(), "no Google request after a cancel");
    assert!(action_rows(&rig.store).is_empty(), "no skill.action row");
}

/// Google's calendar fake that also raises the STOP flag, as the owner's kill
/// switch would once the first write has landed.
struct StopAfterCalendar(Arc<AtomicBool>);

impl Respond for StopAfterCalendar {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.0.store(true, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(json!({ "id": "evt-1" }))
    }
}

/// STOP engaged after call 1: the calendar insert went out, the Gmail send
/// does not, and the run is recorded as refused.
#[tokio::test]
async fn hero_stop_after_the_first_call_sends_no_more() {
    let rig = rig().await;
    let stopped = Arc::new(AtomicBool::new(false));
    // Replace the calendar fake: the STOP flag rises on its one request.
    rig.google_server.reset().await;
    Mock::given(method("POST"))
        .and(path(CALENDAR_PATH))
        .respond_with(StopAfterCalendar(Arc::clone(&stopped)))
        .expect(1)
        .mount(&rig.google_server)
        .await;
    struct Flag(Arc<AtomicBool>);
    impl StopCheck for Flag {
        fn is_stopped(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }
    let record = Arc::new(StdMutex::new(CardRecord::default()));
    let approver = Arc::new(OwnerApprover {
        google: Arc::clone(&rig.google_server),
        record,
    });
    let (outcome, _seen) = drive(
        &rig,
        false,
        approver,
        Some(Arc::new(Flag(Arc::clone(&stopped)))),
        None,
    )
    .await;
    // The engine's own STOP check ends the turn at its next step.
    assert!(matches!(outcome, Err(ChatError::Stopped)), "{outcome:?}");
    let requests = rig.google_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "only the calendar insert was sent");
    assert!(requests[0].url.path() == CALENDAR_PATH);
    assert_eq!(action_rows(&rig.store).len(), 1, "one skill.action row");
    let runs = rig
        .store
        .lock()
        .unwrap()
        .event_payloads("skill.run")
        .unwrap();
    let outcome: Value = serde_json::from_str(&runs[0]).unwrap();
    assert_eq!(outcome["outcome"], "refused");
}

/// The owner cancels while the Gmail send is in flight: the cancel lands in
/// the server's handler, and the response is delayed. The send completes and
/// is recorded; the run ends refused and nothing else is sent.
struct CancelDuringSend(Arc<TurnCancel>);

impl Respond for CancelDuringSend {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.0.cancel();
        ResponseTemplate::new(200)
            .set_delay(std::time::Duration::from_millis(200))
            .set_body_json(json!({ "id": "msg-1" }))
    }
}

/// N2: a cancel during an in-flight connector call keeps the call's Ledger
/// rows, and the run is recorded `refused`.
#[tokio::test]
async fn hero_cancel_during_an_in_flight_send_keeps_its_ledger_rows() {
    let rig = rig().await;
    rig.google_server.reset().await;
    let cancel = TurnCancel::new();
    Mock::given(method("POST"))
        .and(path(CALENDAR_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "evt-1" })))
        .expect(1)
        .mount(&rig.google_server)
        .await;
    Mock::given(method("POST"))
        .and(path(GMAIL_PATH))
        .respond_with(CancelDuringSend(Arc::clone(&cancel)))
        .expect(1)
        .mount(&rig.google_server)
        .await;
    let record = Arc::new(StdMutex::new(CardRecord::default()));
    let approver = Arc::new(OwnerApprover {
        google: Arc::clone(&rig.google_server),
        record,
    });
    let (outcome, _seen) = drive(&rig, false, approver, None, Some(Arc::clone(&cancel))).await;
    assert!(
        matches!(outcome, Err(ChatError::Cancelled)),
        "the turn ends cancelled: {outcome:?}"
    );

    let requests = rig.google_server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        2,
        "the send in flight completed, nothing after it"
    );

    let actions = action_rows(&rig.store);
    assert_eq!(actions.len(), 2, "both sent calls have a skill.action row");
    assert_eq!(actions[1]["tool"], "google_gmail_send");
    assert_eq!(actions[1]["outcome"], "ok");

    let connector_calls = rig
        .store
        .lock()
        .unwrap()
        .event_payloads("google.connector_call")
        .unwrap();
    assert_eq!(
        connector_calls.len(),
        2,
        "each sent call left a connector row"
    );

    let runs = rig
        .store
        .lock()
        .unwrap()
        .event_payloads("skill.run")
        .unwrap();
    let run: Value = serde_json::from_str(&runs[0]).unwrap();
    assert_eq!(run["outcome"], "refused");
}
