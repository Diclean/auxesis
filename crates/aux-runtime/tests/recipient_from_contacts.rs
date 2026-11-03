//! A1-C3: the recipient is resolved from the owner's contacts, never from the
//! model (`docs/phase1.md` §7).
//!
//! An `email` input declared `from: contact(<slot>)` is filled by the runtime:
//! after the fill and before the approval card it rehydrates the source slot,
//! looks the whole name up in the `ContactIndex`, and uses exactly one address.
//! Zero or several addresses refuse the run before the card and before any
//! connector call, each with one `skill.rejected_fill` row.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_runtime::executor::{
    default_approval_timeout, ApprovalCard, Clock, ConnectorError, Executor, NeverStopped,
    RunDecision, RunOutcome, SkillApprover, SkillConnector, SkillContext,
};
use aux_runtime::skills::agent::{AgentMode, AgentSource, Brain};
use aux_runtime::skills::skill::parse_skill;
use aux_runtime::skills::{
    tool_schema, validate_fill, LoadedAgent, LoadedSkill, RecipientPolicy, RunContext,
    ValidatedFill,
};
use kernel_broker::{
    ApprovalRequest, Approver, ApproverError, Broker, MemoryAuditSink, Rule, SkillOnlyLookup, Taint,
};
use kernel_privacy::{Anonymizer, ContactIndex, EntityKind, Span};
use serde_json::{json, Value};

const SEND_INVITE: &str = include_str!("../src/skills/fixtures/skills/send-invite.md");

fn agent() -> LoadedAgent {
    LoadedAgent {
        name: "assistant".to_string(),
        brain: Brain::Cloud,
        default_mode: AgentMode::Private,
        budget: None,
        channels: Vec::new(),
        tools: vec![
            "google.calendar.create_event".to_string(),
            "google.gmail.send".to_string(),
            // MA4: the fixture now declares the EventKit create and SMTP send.
            "calendar.create_event".to_string(),
            "mail.send".to_string(),
        ],
        recipients_policy: RecipientPolicy::KnownContacts,
        recipients_allowlist: Vec::new(),
        body: String::new(),
        source: AgentSource::AgentMd,
        dir: std::path::PathBuf::from("/tmp/assistant"),
    }
}

fn skill() -> LoadedSkill {
    let text = b"---\nname: send-invite\nversion: 1\ntools: [google.calendar.create_event, google.gmail.send]\ninputs:\n  person: { tier: H }\n  email: { type: email, from: contact(person) }\n  when: { type: datetime }\n  duration: { type: duration, default: 30m }\napproval: each_run\n---\nBody.\n";
    parse_skill(text, "send-invite.md", "send-invite", &agent()).unwrap()
}

fn context() -> RunContext<'static> {
    context_with_owner("Please invite Camille Exemple, camille@exemple.fr.")
}

fn context_with_owner(owner_input: &'static str) -> RunContext<'static> {
    RunContext {
        agent: "assistant",
        run_id: "run-1",
        schemas: None,
        owner_input: Some(owner_input),
    }
}

struct NoTokens;

impl aux_runtime::executor::TokenResolver for NoTokens {
    fn resolve(&self, _token: &str) -> Option<String> {
        None
    }
    fn pairs(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

/// The same tool set with two derived contacts: no single address owns the
/// recipient fields, so the fill-time rule stays.
fn two_derived_skill() -> LoadedSkill {
    let text = b"---\nname: send-invite\nversion: 1\ntools: [google.calendar.create_event, google.gmail.send]\ninputs:\n  person: { tier: H }\n  backup: { tier: H }\n  email: { type: email, from: contact(person) }\n  alt: { type: email, from: contact(backup) }\n  when: { type: datetime }\napproval: each_run\n---\nBody.\n";
    parse_skill(text, "send-invite.md", "send-invite", &agent()).unwrap()
}

fn span(text: &str, needle: &str, kind: EntityKind) -> Span {
    let start = text.find(needle).unwrap();
    Span {
        kind,
        start,
        end: start + needle.len(),
        score: 1.0,
        recognizer: "test",
        person_id: None,
    }
}

fn delimited(token: &str) -> String {
    format!("⟦{token}⟧")
}

/// The session with the owner's name and address masked: the token map, and the
/// bare PERSON/EMAIL tokens.
fn session() -> (kernel_privacy::TokenMap, String, String) {
    let text = "Camille Exemple camille@exemple.fr";
    let spans = vec![
        span(text, "Camille Exemple", EntityKind::Person),
        span(text, "camille@exemple.fr", EntityKind::Email),
    ];
    let (_, map) = Anonymizer::new([7u8; 32]).anonymize(text, &spans);
    let person = map
        .iter()
        .find(|(token, _)| token.starts_with("PERSON_"))
        .map(|(token, _)| token.clone())
        .expect("a PERSON token");
    let email = map
        .iter()
        .find(|(token, _)| token.starts_with("EMAIL_"))
        .map(|(token, _)| token.clone())
        .expect("an EMAIL token");
    (map, person, email)
}

/// A fill that references the derived `email` slot through its source value
/// (`person`) in every recipient field, and carries an invented address in a
/// non-recipient field.
fn fill(person: &str, invented: &str) -> ValidatedFill {
    let value = json!({
        "slots": {
            "person": person,
            "when": "2026-10-06T10:00:00+02:00"
        },
        "calls": [
            {
                "tool": "google_calendar_create_event",
                "arguments": {
                    "summary": format!("Meeting with {person}"),
                    "start": "2026-10-06T10:00:00+02:00",
                    "end": "2026-10-06T10:30:00+02:00",
                    "attendees": [{ "email": person }]
                }
            },
            {
                "tool": "google_gmail_send",
                "arguments": {
                    "to": person,
                    "subject": "Invitation",
                    "body": format!("Bonjour, facturez {invented} pour le détail.")
                }
            }
        ]
    });
    validate_fill(&skill(), &value, &context(), None).unwrap()
}

/// The failure this work order exists to fix: the model puts an invented
/// address in every recipient field, and nothing else names it.
fn invented_recipient_fill(person: &str) -> ValidatedFill {
    let value = json!({
        "slots": {
            "person": person,
            "when": "2026-10-06T10:00:00+02:00"
        },
        "calls": [
            {
                "tool": "google_calendar_create_event",
                "arguments": {
                    "summary": format!("Meeting with {person}"),
                    "start": "2026-10-06T10:00:00+02:00",
                    "end": "2026-10-06T10:30:00+02:00",
                    "attendees": [{ "email": "x@invented.example" }]
                }
            },
            {
                "tool": "google_gmail_send",
                "arguments": {
                    "to": "billing@invented.example",
                    "subject": "Invitation",
                    "body": "Bonjour, au plaisir de vous voir."
                }
            }
        ]
    });
    validate_fill(&skill(), &value, &context(), None).unwrap()
}

/// The model leaves every recipient field empty.
fn empty_recipient_fill(person: &str) -> ValidatedFill {
    let value = json!({
        "slots": {
            "person": person,
            "when": "2026-10-06T10:00:00+02:00"
        },
        "calls": [
            {
                "tool": "google_calendar_create_event",
                "arguments": {
                    "summary": format!("Meeting with {person}"),
                    "start": "2026-10-06T10:00:00+02:00",
                    "end": "2026-10-06T10:30:00+02:00",
                    "attendees": [{ "email": "" }]
                }
            },
            {
                "tool": "google_gmail_send",
                "arguments": {
                    "to": "",
                    "subject": "Invitation",
                    "body": "Bonjour, au plaisir de vous voir."
                }
            }
        ]
    });
    validate_fill(&skill(), &value, &context(), None).unwrap()
}

/// The Gmail call carries no `to` key at all: the runtime inserts it.
fn missing_to_fill(person: &str) -> ValidatedFill {
    let value = json!({
        "slots": {
            "person": person,
            "when": "2026-10-06T10:00:00+02:00"
        },
        "calls": [
            {
                "tool": "google_calendar_create_event",
                "arguments": {
                    "summary": format!("Meeting with {person}"),
                    "start": "2026-10-06T10:00:00+02:00",
                    "end": "2026-10-06T10:30:00+02:00",
                    "attendees": [{ "email": person }]
                }
            },
            {
                "tool": "google_gmail_send",
                "arguments": {
                    "subject": "Invitation",
                    "body": "Bonjour, au plaisir de vous voir."
                }
            }
        ]
    });
    validate_fill(&skill(), &value, &context(), None).unwrap()
}

struct NoClock;

#[async_trait]
impl Clock for NoClock {
    async fn sleep(&self, _duration: Duration) {}
}

#[derive(Default)]
struct RecordingApprover {
    cards: Mutex<Vec<ApprovalCard>>,
}

impl RecordingApprover {
    fn cards(&self) -> Vec<ApprovalCard> {
        self.cards.lock().unwrap().clone()
    }
}

#[async_trait]
impl SkillApprover for RecordingApprover {
    async fn decide(&self, card: &ApprovalCard) -> RunDecision {
        self.cards.lock().unwrap().push(card.clone());
        RunDecision::approved()
    }
}

#[derive(Default)]
struct RecordingConnector {
    calls: Mutex<Vec<(String, Value)>>,
}

impl RecordingConnector {
    fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl SkillConnector for RecordingConnector {
    async fn call(
        &self,
        _skill: &SkillContext,
        logical: &str,
        arguments: &Value,
    ) -> Result<Value, ConnectorError> {
        self.calls
            .lock()
            .unwrap()
            .push((logical.to_string(), arguments.clone()));
        Ok(json!({ "ok": true }))
    }
}

struct PreApproved;

#[async_trait]
impl Approver for PreApproved {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }
}

struct SkillOnly;

impl SkillOnlyLookup for SkillOnly {
    fn is_skill_only(&self, tool: &str) -> bool {
        matches!(tool, "google_gmail_send" | "google_calendar_create_event")
    }
}

/// The owner's contacts, as a directory. Each pair is `(whole name, address)`.
fn contacts(entries: &[(&str, &str)]) -> Arc<ContactIndex> {
    let mut index = ContactIndex::new();
    for (name, address) in entries {
        assert!(
            index.add_from_header(name, address).is_some(),
            "the contact is known"
        );
    }
    Arc::new(index)
}

/// Run one fill through the executor over `directory`.
async fn run(
    directory: &ContactIndex,
    fill: &ValidatedFill,
    tokens: &dyn aux_runtime::executor::TokenResolver,
    sink: &MemoryAuditSink,
    approver: &RecordingApprover,
    connector: &RecordingConnector,
) -> RunOutcome {
    run_for_owner(
        directory,
        fill,
        tokens,
        sink,
        approver,
        connector,
        "Please invite Camille Exemple, camille@exemple.fr.",
    )
    .await
}

async fn run_for_owner(
    directory: &ContactIndex,
    fill: &ValidatedFill,
    tokens: &dyn aux_runtime::executor::TokenResolver,
    sink: &MemoryAuditSink,
    approver: &RecordingApprover,
    connector: &RecordingConnector,
    owner_input: &'static str,
) -> RunOutcome {
    let broker = Broker::new(
        Arc::new(MemoryAuditSink::new()),
        Vec::<Rule>::new(),
        Arc::new(PreApproved),
        Arc::new(SkillOnly),
    );
    let executor = Executor {
        broker: &broker,
        sink,
        approver,
        connector,
        directory,
        allowlist: &[],
        clock: &NoClock,
        stop: &NeverStopped,
        approval_timeout: default_approval_timeout(),
    };
    executor
        .execute(
            &skill(),
            fill,
            &context_with_owner(owner_input),
            tokens,
            &Taint::Clean,
        )
        .await
}

/// The fixture declares the derivation, and the model's schema drops it.
#[test]
fn the_fixture_derives_email_from_person() {
    let skill = parse_skill(
        SEND_INVITE.as_bytes(),
        "send-invite.md",
        "send-invite",
        &agent(),
    )
    .unwrap();
    let email = skill
        .inputs
        .iter()
        .find(|input| input.name == "email")
        .unwrap();
    assert_eq!(email.from.as_deref(), Some("person"));
    let schema = tool_schema(&skill);
    assert!(schema["properties"]["slots"]["properties"]
        .get("email")
        .is_none());
    assert_eq!(
        schema["properties"]["slots"]["required"],
        json!(["person", "when"])
    );
}

/// One contact: the run sends to that address, even though the model's call
/// text carries an invented address in a non-recipient field.
#[tokio::test]
async fn one_contact_resolves_the_recipient() {
    let (tokens, person, email) = session();
    let directory = contacts(&[("Camille Exemple", "camille@exemple.fr")]);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = fill(&delimited(&person), "billing@evil.example");

    let outcome = run(&directory, &fill, &tokens, &sink, &approver, &connector).await;
    let actions = match outcome {
        RunOutcome::Done { actions } => actions,
        other => panic!("the run completes: {other:?}"),
    };
    assert_eq!(actions.len(), 2, "both approved calls ran");

    // The card shows the resolved address locally and its token form to the model.
    let cards = approver.cards();
    assert_eq!(cards.len(), 1, "one card for the run");
    let send = cards[0]
        .calls
        .iter()
        .find(|call| call.logical == "google.gmail.send")
        .unwrap();
    assert_eq!(send.real_arguments["to"], "camille@exemple.fr");
    assert_eq!(send.token_arguments["to"], delimited(&email));

    // The connector got the contact's address, not the invented one, in every
    // recipient field.
    let calls = connector.calls();
    assert_eq!(calls.len(), 2, "one connector call per approved call");
    let gmail = calls
        .iter()
        .find(|(logical, _)| logical == "google.gmail.send")
        .unwrap();
    assert_eq!(gmail.1["to"], "camille@exemple.fr");
    assert!(
        gmail.1["body"]
            .as_str()
            .unwrap()
            .contains("billing@evil.example"),
        "the invented address stays in the body, it is not the recipient"
    );
    let calendar = calls
        .iter()
        .find(|(logical, _)| logical == "google.calendar.create_event")
        .unwrap();
    assert_eq!(calendar.1["attendees"][0]["email"], "camille@exemple.fr");
}

/// Prompt injection selects Bob although the trusted owner message selected Alice.
#[tokio::test]
async fn injected_other_known_contact_is_refused() {
    let (tokens, _person, _) = session();
    let directory = contacts(&[
        ("Alice Example", "alice@example.test"),
        ("Bob Example", "bob@example.test"),
    ]);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = fill("Bob Example", "irrelevant@example.test");

    let outcome = run_for_owner(
        &directory,
        &fill,
        &tokens,
        &sink,
        &approver,
        &connector,
        "Please send the invite to Alice Example.",
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
    assert!(approver.cards().is_empty());
    assert!(connector.calls().is_empty());
}

/// Public mode keeps owner text readable locally; the selected contact works.
#[tokio::test]
async fn owner_named_contact_works_in_public_mode() {
    let directory = contacts(&[("Alice Example", "alice@example.test")]);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = fill("Alice Example", "irrelevant@example.test");
    let outcome = run_for_owner(
        &directory,
        &fill,
        &NoTokens,
        &sink,
        &approver,
        &connector,
        "Please send the invite to Alice Example.",
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert_eq!(
        connector.calls()[0].1["attendees"][0]["email"],
        "alice@example.test"
    );
}

/// The model fills the contact slot with the address instead of the name. When
/// the value is a known contact address, the runtime derives from it rather
/// than refusing (the live cloud model does this).
#[tokio::test]
async fn a_known_address_in_the_contact_slot_resolves() {
    let (tokens, _person, email) = session();
    let directory = contacts(&[("Camille Exemple", "camille@exemple.fr")]);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = fill(&delimited(&email), "billing@evil.example");

    let outcome = run(&directory, &fill, &tokens, &sink, &approver, &connector).await;
    let actions = match outcome {
        RunOutcome::Done { actions } => actions,
        other => panic!("the run completes: {other:?}"),
    };
    assert_eq!(actions.len(), 2, "both approved calls ran");
    let calls = connector.calls();
    let gmail = calls
        .iter()
        .find(|(logical, _)| logical == "google.gmail.send")
        .unwrap();
    assert_eq!(gmail.1["to"], "camille@exemple.fr");
}

/// The model invents the address in every recipient field. The card and the
/// connector must see only the contact's real address, and the invented string
/// must not appear anywhere the connector received.
#[tokio::test]
async fn an_invented_recipient_address_is_replaced_everywhere() {
    let (tokens, person, email) = session();
    let directory = contacts(&[("Camille Exemple", "camille@exemple.fr")]);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = invented_recipient_fill(&delimited(&person));

    let outcome = run(&directory, &fill, &tokens, &sink, &approver, &connector).await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");

    let cards = approver.cards();
    assert_eq!(cards.len(), 1, "one card for the run");
    let send = cards[0]
        .calls
        .iter()
        .find(|call| call.logical == "google.gmail.send")
        .unwrap();
    assert_eq!(send.real_arguments["to"], "camille@exemple.fr");
    assert_eq!(send.token_arguments["to"], delimited(&email));
    let calendar = cards[0]
        .calls
        .iter()
        .find(|call| call.logical == "google.calendar.create_event")
        .unwrap();
    assert_eq!(
        calendar.real_arguments["attendees"][0]["email"],
        "camille@exemple.fr"
    );

    let received = serde_json::to_string(&connector.calls()).unwrap();
    assert!(!received.contains("invented.example"), "{received}");
    assert_eq!(connector.calls().len(), 2, "one connector call per action");
    let gmail = connector
        .calls()
        .iter()
        .find(|(logical, _)| logical == "google.gmail.send")
        .cloned()
        .unwrap();
    assert_eq!(gmail.1["to"], "camille@exemple.fr");
    let calendar = connector
        .calls()
        .iter()
        .find(|(logical, _)| logical == "google.calendar.create_event")
        .cloned()
        .unwrap();
    assert_eq!(calendar.1["attendees"][0]["email"], "camille@exemple.fr");
}

/// The model leaves every recipient field empty. The runtime still fills them.
#[tokio::test]
async fn empty_recipient_fields_get_the_contact() {
    let (tokens, person, _email) = session();
    let directory = contacts(&[("Camille Exemple", "camille@exemple.fr")]);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = empty_recipient_fill(&delimited(&person));

    let outcome = run(&directory, &fill, &tokens, &sink, &approver, &connector).await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");

    let calls = connector.calls();
    let gmail = calls
        .iter()
        .find(|(logical, _)| logical == "google.gmail.send")
        .cloned()
        .unwrap();
    assert_eq!(gmail.1["to"], "camille@exemple.fr");
    let calendar = calls
        .iter()
        .find(|(logical, _)| logical == "google.calendar.create_event")
        .cloned()
        .unwrap();
    assert_eq!(calendar.1["attendees"][0]["email"], "camille@exemple.fr");
    let received = serde_json::to_string(&calls).unwrap();
    assert!(!received.contains("\"to\":\"\""), "{received}");
    assert!(!received.contains("\"email\":\"\""), "{received}");
}

/// The Gmail call carries no `to` key: the required field is inserted with the
/// resolved address.
#[tokio::test]
async fn a_gmail_call_without_to_gets_the_contact_inserted() {
    let (tokens, person, _email) = session();
    let directory = contacts(&[("Camille Exemple", "camille@exemple.fr")]);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = missing_to_fill(&delimited(&person));

    let outcome = run(&directory, &fill, &tokens, &sink, &approver, &connector).await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");

    let gmail = connector
        .calls()
        .iter()
        .find(|(logical, _)| logical == "google.gmail.send")
        .cloned()
        .unwrap();
    assert_eq!(gmail.1["to"], "camille@exemple.fr");
}

/// Two derived contacts: the runtime cannot know which address goes in which
/// field, so an invented address in a recipient field is still a fill
/// rejection, before any card.
#[test]
fn two_derived_inputs_still_refuse_an_invented_recipient() {
    let value = json!({
        "slots": {
            "person": "⟦PERSON_1⟧",
            "backup": "⟦PERSON_2⟧",
            "when": "2026-10-06T10:00:00+02:00"
        },
        "calls": [
            {
                "tool": "google_calendar_create_event",
                "arguments": {
                    "summary": "Meeting with ⟦PERSON_1⟧",
                    "start": "2026-10-06T10:00:00+02:00",
                    "attendees": [{ "email": "⟦PERSON_1⟧" }]
                }
            },
            {
                "tool": "google_gmail_send",
                "arguments": { "to": "billing@invented.example", "body": "See you." }
            }
        ]
    });
    let sink = MemoryAuditSink::new();
    let err = validate_fill(&two_derived_skill(), &value, &context(), Some(&sink)).unwrap_err();
    assert_eq!(
        err,
        aux_runtime::skills::FillError::RecipientNotFromSlot {
            tool: "google_gmail_send".to_string(),
            field: "to".to_string()
        }
    );
    assert_eq!(sink.count("skill.rejected_fill"), 1);
}

/// No contact matches the whole name: refuse before the card, before the
/// connector, with one `skill.rejected_fill` row.
#[tokio::test]
async fn no_address_refuses_before_the_card() {
    assert_refused(
        |token| format!("no address for {token}"),
        &[("Jordan Exemple", "jordan@exemple.fr")],
    )
    .await;
}

/// Several contacts match the whole name: refuse before the card too, and the
/// reason names the token, never a value.
#[tokio::test]
async fn several_addresses_refuse_before_the_card() {
    assert_refused(
        |token| format!("several addresses for {token}; say which one"),
        &[
            ("Camille Exemple", "camille@exemple.fr"),
            ("Camille Exemple", "camille@autre.example"),
        ],
    )
    .await;
}

async fn assert_refused(expected: impl Fn(&str) -> String, entries: &[(&str, &str)]) {
    let (tokens, person, _email) = session();
    let directory = contacts(entries);
    let sink = MemoryAuditSink::new();
    let approver = RecordingApprover::default();
    let connector = RecordingConnector::default();
    let fill = fill(&delimited(&person), "billing@evil.example");
    let reason = expected(&delimited(&person));

    let outcome = run(&directory, &fill, &tokens, &sink, &approver, &connector).await;
    assert_eq!(
        outcome,
        RunOutcome::Refused {
            reason: reason.clone(),
            tainted: false,
        },
        "the run is refused with the contract reason"
    );
    assert!(approver.cards().is_empty(), "no card before the refusal");
    assert!(connector.calls().is_empty(), "no connector call");
    assert_eq!(sink.count("skill.rejected_fill"), 1);
    let rejected = &sink.payloads("skill.rejected_fill")[0];
    assert_eq!(rejected["reason"], reason);
    assert_eq!(rejected["tool"], Value::Null);
    assert_eq!(sink.count("skill.run"), 1);
    let run = &sink.payloads("skill.run")[0];
    assert_eq!(run["outcome"], "refused");
}
