//! MA4: the skill connector's invite path, offline.
//!
//! The mail API is a recorder (no socket), and the Mac app is a fake bridge on
//! a loopback broadcast. The test proves the connection between the two:
//! `calendar.create_event` runs first, then `mail.send` builds the `.ics` from
//! the **rehydrated** event arguments and the real recipient.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security, SmtpSettings};
use aux_mail::dial::Dialer;
use aux_mail::imap_read::Credentials;
use aux_mail::limits::Limits;
use aux_mail::{
    EnvelopeItem, FetchedAttachments, ListQuery, MailApi, MailError, MailItem, MailService,
    MailToolset, OutgoingMail, SearchQuery, SendOutcome,
};
use aux_runtime::executor::{
    default_approval_timeout, Executor, NeverStopped, RealClock, RecipientDirectory, RunDecision,
    RunOutcome, SkillApprover, SkillConnector, SkillContext, UNCERTAIN_DRAFT,
};
use aux_runtime::skills::agent::{AgentMode, AgentSource, Brain, LoadedAgent};
use aux_runtime::skills::skill::parse_skill;
use aux_runtime::skills::{validate_fill, LoadedSkill, RecipientPolicy, RunContext, ValidatedFill};
use aux_store::{ContactRecord, NewParty, Store};
use auxd::bridge::{Bridge, BridgeAnswer};
use auxd::skill_executor::{BrokerCardApprover, ContactsWithZones, MailSkillConnector};
use kernel_broker::{
    ApprovalDecision, ApprovalRequest, Approver, ApproverError, AuditSink, Broker, SkillOnlyLookup,
    Taint,
};
use kernel_core::privacy::{ModeFn, PrivacyMode};
use kernel_privacy::TokenMap;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A mail API that records the one outgoing message; a listing is `inbox`.
#[derive(Default)]
struct RecordingMail {
    sent: Mutex<Vec<OutgoingMail>>,
    inbox: Vec<EnvelopeItem>,
    /// Headers of the owner's Sent folder; `None` = no readable Sent folder.
    sent_mail: Option<Vec<EnvelopeItem>>,
    owner_addresses: Vec<String>,
    /// Fail the next send once, with this typed error.
    next_error: Mutex<Option<MailError>>,
}

#[async_trait]
impl MailApi for RecordingMail {
    async fn list(&self, _: &str, query: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
        match query.folder.as_deref() {
            Some(_) => Ok(self.sent_mail.clone().unwrap_or_default()),
            None => Ok(self.inbox.clone()),
        }
    }
    async fn search(&self, _: &str, _: &SearchQuery) -> Result<Vec<EnvelopeItem>, MailError> {
        Ok(Vec::new())
    }
    async fn thread(&self, _: &str, _: &str, _: usize) -> Result<Vec<EnvelopeItem>, MailError> {
        Ok(Vec::new())
    }
    async fn read(&self, _: &str, _: u32, _: &str, _: usize) -> Result<MailItem, MailError> {
        Err(MailError::Protocol)
    }
    async fn fetch_attachments(
        &self,
        _: &str,
        _: &str,
        _: u32,
    ) -> Result<FetchedAttachments, MailError> {
        Err(MailError::Protocol)
    }
    async fn send(&self, _: &str, mail: &OutgoingMail) -> Result<SendOutcome, MailError> {
        if let Some(error) = self.next_error.lock().unwrap().take() {
            return Err(error);
        }
        self.sent.lock().unwrap().push(mail.clone());
        Ok(SendOutcome {
            accepted: mail.to.len(),
            bytes: 128,
            reply_class: "2xx",
        })
    }
    fn account_ids(&self) -> Vec<String> {
        vec!["personal".to_string()]
    }
    fn account_addresses(&self) -> Vec<String> {
        self.owner_addresses.clone()
    }
    fn sent_folder(&self, _: &str) -> Option<String> {
        self.sent_mail.as_ref().map(|_| "Sent".to_string())
    }
    fn limits(&self) -> &aux_mail::Limits {
        static LIMITS: std::sync::LazyLock<aux_mail::Limits> =
            std::sync::LazyLock::new(aux_mail::Limits::default);
        std::sync::LazyLock::force(&LIMITS)
    }
}

/// A fake Mac app answering `eventkit.create_event`.
fn fake_bridge(home: PathBuf) -> Arc<Bridge> {
    let (events, mut receiver) = tokio::sync::broadcast::channel(16);
    let bridge = Arc::new(Bridge::new(home, events));
    let answering = Arc::clone(&bridge);
    tokio::spawn(async move {
        while let Ok(text) = receiver.recv().await {
            let Ok(value) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            if value["type"] != "bridge.request" || value["op"] != "eventkit.create_event" {
                continue;
            }
            if let Some(id) = value["id"].as_str() {
                answering.answer(
                    id,
                    BridgeAnswer::Result(json!({"event_id": "evt-1", "calendar": "Home"})),
                );
            }
        }
    });
    bridge
}

fn open_mode() -> ModeFn {
    Arc::new(|| PrivacyMode::Open)
}

fn private_mode() -> ModeFn {
    Arc::new(|| PrivacyMode::Private)
}

fn connector(mail: Arc<dyn MailApi>, bridge: Arc<Bridge>) -> MailSkillConnector {
    MailSkillConnector::new(
        MailToolset::new(mail, None),
        Some(bridge),
        "me@example.org",
        open_mode(),
    )
}

fn context() -> SkillContext {
    SkillContext {
        name: "send-invite".to_string(),
        version: 1,
        hash: "abc".to_string(),
        tainted: false,
    }
}

#[tokio::test]
async fn the_invite_is_built_from_the_rehydrated_event_and_the_real_recipient() {
    let mail = Arc::new(RecordingMail::default());
    let bridge =
        fake_bridge(std::env::temp_dir().join(format!("aux-mail-send-{}", std::process::id())));
    let connector = connector(mail.clone(), bridge);
    let skill = context();

    connector
        .call(
            &skill,
            "calendar.create_event",
            &json!({
                "title": "Meeting with Camille Exemple",
                "start": "2026-10-11T10:00:00+02:00",
                "end": "2026-10-11T10:30:00+02:00",
                "start_utc": "20261011T080000Z",
                "end_utc": "20261011T083000Z",
                "notes": "Invitation pour Camille Exemple",
            }),
        )
        .await
        .expect("the event is created");

    let result = connector
        .call(
            &skill,
            "mail.send",
            &json!({
                "to": ["camille@exemple.fr"],
                "subject": "Invitation",
                "body": "Bonjour, invitation confirmée.",
                "ics": "event",
            }),
        )
        .await
        .expect("the mail is sent");
    // The connector resolves the default account to a configured slug, never
    // a raw argument, so the Ledger value is safe.
    assert_eq!(result["mail_call"]["account"], "personal");

    let sent = mail.sent.lock().unwrap();
    assert_eq!(sent.len(), 1, "one send");
    let ics = sent[0].ics.as_deref().expect("an .ics was attached");
    assert!(ics.contains("METHOD:REQUEST"));
    assert!(ics.contains("UID:evt-1@auxesis.local"));
    // The attendee may be folded across lines; unfold before checking.
    let unfolded = ics.replace("\r\n ", "");
    assert!(
        unfolded.contains("mailto:camille@exemple.fr"),
        "the real attendee: {unfolded}"
    );
    assert!(unfolded.contains("ORGANIZER:mailto:me@example.org"));
    assert!(unfolded.contains("DTSTART:20261011T080000Z"));
    assert!(!ics.contains('⟦') && !ics.contains('⟧'));
}

#[tokio::test]
async fn an_empty_invite_marker_is_refused_never_sent_as_an_invite() {
    let mail = Arc::new(RecordingMail::default());
    let bridge = fake_bridge(
        std::env::temp_dir().join(format!("aux-mail-send-empty-{}", std::process::id())),
    );
    let connector = connector(mail.clone(), bridge);
    let skill = context();
    connector
        .call(
            &skill,
            "calendar.create_event",
            &json!({
                "title": "Meeting with Camille Exemple",
                "start": "2026-10-11T10:00:00+02:00",
                "end": "2026-10-11T10:30:00+02:00",
                "start_utc": "20261011T080000Z",
                "end_utc": "20261011T083000Z",
            }),
        )
        .await
        .expect("the event is created");
    for marker in [json!(""), json!(null), json!(true)] {
        let error = connector
            .call(
                &skill,
                "mail.send",
                &json!({
                    "to": ["camille@exemple.fr"],
                    "subject": "Invitation",
                    "body": "Bonjour.",
                    "ics": marker,
                }),
            )
            .await
            .expect_err("an empty marker shows no attachment, so it is refused");
        assert!(error.message.contains("invite marker"), "{}", error.message);
    }
    assert!(mail.sent.lock().unwrap().is_empty(), "nothing was sent");
}

#[tokio::test]
async fn a_mail_that_names_an_invite_before_the_event_is_refused() {
    let mail = Arc::new(RecordingMail::default());
    let bridge = fake_bridge(
        std::env::temp_dir().join(format!("aux-mail-send-none-{}", std::process::id())),
    );
    let connector = connector(mail.clone(), bridge);

    let error = connector
        .call(
            &context(),
            "mail.send",
            &json!({
                "to": ["camille@exemple.fr"],
                "subject": "Invitation",
                "body": "Bonjour.",
                "ics": "event",
            }),
        )
        .await
        .expect_err("no event was created");
    assert!(error.message.contains("no event"), "{}", error.message);
    assert!(mail.sent.lock().unwrap().is_empty(), "nothing was sent");
}

// ---------------------------------------------------------------------------
// The real SMTP 421: one MAIL FROM, one typed `rate_limited` error.
// ---------------------------------------------------------------------------

/// A mail credential source with no password (the plaintext fake relays).
struct NoCredentials;

impl Credentials for NoCredentials {
    fn password(&self, _account: &str) -> Option<String> {
        None
    }
}

/// A plaintext SMTP server that answers the first `MAIL FROM` with `421`.
struct FakeSmtp421 {
    port: u16,
    mail_from: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeSmtp421 {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mail_from = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&mail_from);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let _ = stream.write_all(b"220 aux fake ESMTP\r\n").await;
                    let mut line = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        if byte[0] != b'\n' {
                            line.push(byte[0]);
                            continue;
                        }
                        if line.last() == Some(&b'\r') {
                            line.pop();
                        }
                        let text = String::from_utf8_lossy(&line).to_ascii_uppercase();
                        line.clear();
                        if text.starts_with("MAIL FROM") {
                            counter.fetch_add(1, Ordering::SeqCst);
                            let _ = stream.write_all(b"421 4.7.0 Try again later\r\n").await;
                        } else if text.starts_with("EHLO") || text.starts_with("HELO") {
                            let _ = stream.write_all(b"250-aux fake\r\n250 8BITMIME\r\n").await;
                        } else if text.starts_with("QUIT") {
                            let _ = stream.write_all(b"221 2.0.0 Bye\r\n").await;
                            return;
                        } else {
                            let _ = stream.write_all(b"250 2.0.0 Ok\r\n").await;
                        }
                    }
                });
            }
        });
        Self {
            port,
            mail_from,
            task,
        }
    }

    fn mail_from_count(&self) -> usize {
        self.mail_from.load(Ordering::SeqCst)
    }
}

impl Drop for FakeSmtp421 {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn a_421_writes_one_typed_error_with_one_mail_from() {
    let smtp = FakeSmtp421::start().await;
    let account = MailAccount {
        id: "personal".to_string(),
        email: "me@example.org".to_string(),
        display: None,
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: 1,
            security: Security::Tls,
            username: None,
            ca_file: None,
        },
        smtp: Some(SmtpSettings {
            host: "127.0.0.1".to_string(),
            port: smtp.port,
            security: Security::Plain,
            username: None,
            ca_file: None,
        }),
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    };
    let service = MailService::new(
        Dialer::new(Duration::from_secs(5)),
        Limits::default(),
        vec![account],
        Arc::new(NoCredentials),
    );
    let connector = MailSkillConnector::new(
        MailToolset::new(Arc::new(service), None),
        None,
        "me@example.org",
        open_mode(),
    );

    let error = connector
        .call(
            &context(),
            "mail.send",
            &json!({
                "to": ["camille@exemple.fr"],
                "subject": "Invitation",
                "body": "Bonjour.",
            }),
        )
        .await
        .expect_err("the server throttled the send");
    assert_eq!(error.ledger["kind"], "rate_limited", "{error:?}");
    assert_eq!(error.ledger["reply_class"], "4xx", "{error:?}");
    assert_eq!(error.ledger["account"], "personal", "a configured slug");
    assert_eq!(smtp.mail_from_count(), 1, "the 421 is never retried");
    let text = error.ledger.to_string();
    assert!(!text.contains('@'), "no address in the ledger metadata");
}

/// MA4 fix 2: an `account` that is not a configured slug is refused before any
/// socket, and the ledger carries only `unknown`.
#[tokio::test]
async fn a_bad_account_is_refused_before_any_socket() {
    let smtp = FakeSmtp421::start().await;
    let account = MailAccount {
        id: "personal".to_string(),
        email: "me@example.org".to_string(),
        display: None,
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: 1,
            security: Security::Tls,
            username: None,
            ca_file: None,
        },
        smtp: Some(SmtpSettings {
            host: "127.0.0.1".to_string(),
            port: smtp.port,
            security: Security::Plain,
            username: None,
            ca_file: None,
        }),
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    };
    let service = MailService::new(
        Dialer::new(Duration::from_secs(5)),
        Limits::default(),
        vec![account],
        Arc::new(NoCredentials),
    );
    let connector = MailSkillConnector::new(
        MailToolset::new(Arc::new(service), None),
        None,
        "me@example.org",
        open_mode(),
    );

    let error = connector
        .call(
            &context(),
            "mail.send",
            &json!({
                "account": "camille@exemple.test",
                "to": ["camille@exemple.fr"],
                "subject": "Invitation",
                "body": "Bonjour.",
            }),
        )
        .await
        .expect_err("a raw account is refused");
    assert_eq!(error.ledger["kind"], "invalid_field", "{error:?}");
    assert_eq!(error.ledger["account"], "unknown", "{error:?}");
    assert!(!error.ledger.to_string().contains('@'), "{error:?}");
    assert_eq!(smtp.mail_from_count(), 0, "no socket, no MAIL FROM");
}

/// P1: the executor rehydrates before the card, so a token left in the
/// arguments means a value never became real; the connector refuses rather
/// than mail a `⟦token⟧`.
#[tokio::test]
async fn a_token_left_in_the_arguments_is_refused() {
    let mail = Arc::new(RecordingMail::default());
    let bridge = fake_bridge(
        std::env::temp_dir().join(format!("aux-mail-send-token-{}", std::process::id())),
    );
    let connector = connector(mail.clone(), bridge);

    let error = connector
        .call(
            &context(),
            "mail.send",
            &json!({
                "to": ["camille@exemple.fr"],
                "subject": "Invitation",
                "body": "Bonjour ⟦PERSON_1⟧.",
            }),
        )
        .await
        .expect_err("a token is refused");
    assert_eq!(error.ledger["kind"], "token", "{error:?}");
    assert_eq!(error.ledger["outcome"], "refused", "{error:?}");
    assert!(mail.sent.lock().unwrap().is_empty(), "nothing was sent");
}

// ---------------------------------------------------------------------------
// The executor path in Private mode: the recipient filter and the B20 gate
// ---------------------------------------------------------------------------

/// An SMTP server that accepts one message and records every `DATA` body.
struct FakeSmtpAccept {
    port: u16,
    connections: Arc<AtomicUsize>,
    accepted: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeSmtpAccept {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let conns = Arc::clone(&connections);
        let acc = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                conns.fetch_add(1, Ordering::SeqCst);
                let acc = Arc::clone(&acc);
                tokio::spawn(async move {
                    serve_accept(stream, acc).await;
                });
            }
        });
        Self {
            port,
            connections,
            accepted,
            task,
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn accepted(&self) -> Vec<String> {
        self.accepted.lock().unwrap().clone()
    }
}

impl Drop for FakeSmtpAccept {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_accept(mut stream: tokio::net::TcpStream, accepted: Arc<Mutex<Vec<String>>>) {
    let _ = stream.write_all(b"220 aux fake ESMTP\r\n").await;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    let mut in_data = false;
    let mut data = String::new();
    loop {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            return;
        }
        if byte[0] != b'\n' {
            line.push(byte[0]);
            continue;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        line.clear();
        if in_data {
            if text == "." {
                accepted.lock().unwrap().push(std::mem::take(&mut data));
                in_data = false;
                let _ = stream.write_all(b"250 2.0.0 Ok: queued\r\n").await;
            } else {
                data.push_str(&text);
                data.push_str("\r\n");
            }
            continue;
        }
        let upper = text.to_ascii_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let _ = stream.write_all(b"250-aux fake\r\n250 8BITMIME\r\n").await;
        } else if upper.starts_with("DATA") {
            in_data = true;
            data.clear();
            let _ = stream
                .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                .await;
        } else if upper.starts_with("QUIT") {
            let _ = stream.write_all(b"221 2.0.0 Bye\r\n").await;
            return;
        } else {
            let _ = stream.write_all(b"250 2.0.0 Ok\r\n").await;
        }
    }
}

fn plaintext_account(port: u16) -> MailAccount {
    MailAccount {
        id: "personal".to_string(),
        email: "me@example.org".to_string(),
        display: None,
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: 1,
            security: Security::Tls,
            username: None,
            ca_file: None,
        },
        smtp: Some(SmtpSettings {
            host: "127.0.0.1".to_string(),
            port,
            security: Security::Plain,
            username: None,
            ca_file: None,
        }),
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    }
}

#[derive(Default)]
struct RecordingSink {
    rows: Mutex<Vec<(String, Value)>>,
}

impl RecordingSink {
    fn rows(&self, kind: &str) -> Vec<Value> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| name == kind)
            .map(|(_, payload)| payload.clone())
            .collect()
    }
}

impl AuditSink for RecordingSink {
    fn log_event(&self, kind: &str, payload: &Value) -> Result<i64, kernel_broker::AuditError> {
        let mut rows = self.rows.lock().unwrap();
        rows.push((kind.to_string(), payload.clone()));
        Ok(rows.len() as i64)
    }
}

struct Approves;

#[async_trait]
impl SkillApprover for Approves {
    async fn decide(&self, _card: &aux_runtime::executor::ApprovalCard) -> RunDecision {
        RunDecision::approved()
    }
}

struct PreApproved;

#[async_trait]
impl Approver for PreApproved {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }
}

struct MailSendOnly;

impl SkillOnlyLookup for MailSendOnly {
    fn is_skill_only(&self, tool: &str) -> bool {
        tool == "mail_send"
    }
}

struct Known(Vec<&'static str>);

impl RecipientDirectory for Known {
    fn is_known(&self, value: &str) -> bool {
        self.0.iter().any(|known| known.eq_ignore_ascii_case(value))
    }
}

/// One named person, as Clients resolves a name the owner typed.
struct NamedKnown(&'static str, &'static str);

impl RecipientDirectory for NamedKnown {
    fn is_known(&self, value: &str) -> bool {
        self.1.eq_ignore_ascii_case(value)
    }

    fn addresses_for_name(&self, name: &str) -> Vec<String> {
        self.0
            .eq_ignore_ascii_case(name.trim())
            .then(|| self.1.to_string())
            .into_iter()
            .collect()
    }

    fn name_groups(&self) -> Vec<Vec<String>> {
        vec![vec![self.0.to_string()]]
    }
}

fn mail_exec_agent() -> LoadedAgent {
    LoadedAgent {
        name: "assistant".to_string(),
        brain: Brain::Cloud,
        default_mode: AgentMode::Private,
        budget: None,
        channels: Vec::new(),
        tools: vec!["mail.send".to_string()],
        recipients_policy: RecipientPolicy::KnownContacts,
        recipients_allowlist: Vec::new(),
        body: String::new(),
        source: AgentSource::AgentMd,
        dir: PathBuf::from("/tmp/assistant"),
    }
}

fn mail_exec_skill() -> LoadedSkill {
    let text = b"---\nname: send-invite\nversion: 1\ntools: [mail.send]\ninputs:\n  email: { type: email }\nrecipients:\n  policy: known-contacts\napproval: each_run\n---\nBody.\n";
    parse_skill(text, "send-invite.md", "send-invite", &mail_exec_agent()).unwrap()
}

fn mail_exec_context() -> RunContext<'static> {
    RunContext {
        agent: "assistant",
        run_id: "run-1",
        schemas: None,
        owner_input: None,
    }
}

fn mail_exec_fill(email: &str) -> ValidatedFill {
    let value = json!({
        "slots": { "email": email },
        "calls": [{
            "tool": "mail_send",
            "arguments": {
                "to": [email],
                "subject": "Invitation",
                "body": "Bonjour Camille Exemple."
            }
        }]
    });
    validate_fill(&mail_exec_skill(), &value, &mail_exec_context(), None).unwrap()
}

async fn run_executor(
    connector: Arc<dyn SkillConnector>,
    directory: Arc<dyn RecipientDirectory>,
) -> (RunOutcome, Arc<RecordingSink>) {
    run_executor_with(connector, directory, &Approves).await
}

async fn run_executor_with(
    connector: Arc<dyn SkillConnector>,
    directory: Arc<dyn RecipientDirectory>,
    approver: &dyn SkillApprover,
) -> (RunOutcome, Arc<RecordingSink>) {
    run_executor_fill(
        &mail_exec_skill(),
        mail_exec_fill("camille@exemple.fr"),
        connector,
        directory,
        approver,
    )
    .await
}

async fn run_executor_fill(
    skill: &LoadedSkill,
    fill: ValidatedFill,
    connector: Arc<dyn SkillConnector>,
    directory: Arc<dyn RecipientDirectory>,
    approver: &dyn SkillApprover,
) -> (RunOutcome, Arc<RecordingSink>) {
    let sink = Arc::new(RecordingSink::default());
    let broker = Broker::new(
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        Vec::new(),
        Arc::new(PreApproved),
        Arc::new(MailSendOnly),
    );
    let clock = RealClock;
    let exec = Executor {
        broker: &broker,
        sink: sink.as_ref(),
        approver,
        connector: connector.as_ref(),
        directory: directory.as_ref(),
        allowlist: &[],
        clock: &clock,
        stop: &NeverStopped,
        approval_timeout: default_approval_timeout(),
    };
    let outcome = exec
        .execute(
            skill,
            &fill,
            &mail_exec_context(),
            &TokenMap::default(),
            &Taint::Clean,
        )
        .await;
    (outcome, sink)
}

fn private_connector(port: u16) -> Arc<dyn SkillConnector> {
    let service = MailService::new(
        Dialer::new(Duration::from_secs(5)),
        Limits::default(),
        vec![plaintext_account(port)],
        Arc::new(NoCredentials),
    );
    Arc::new(MailSkillConnector::new(
        MailToolset::new(Arc::new(service), None),
        None,
        "me@example.org",
        private_mode(),
    ))
}

/// P1: an unknown recipient in Private mode is refused by the executor's
/// known-contacts filter before the connector, so no SMTP socket opens.
#[tokio::test]
async fn private_unknown_recipient_opens_no_smtp_socket() {
    let smtp = FakeSmtpAccept::start().await;
    let connector = private_connector(smtp.port);
    let directory: Arc<dyn RecipientDirectory> = Arc::new(Known(vec![]));
    let (outcome, sink) = run_executor(connector, directory).await;
    assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
    assert_eq!(
        smtp.connections(),
        0,
        "an unknown recipient must not open a socket"
    );
    // The refusal is recorded, and the row names the mailbox the send would
    // have gone out of (DOC-COLLECT-1).
    let rows = sink.rows("mail.call");
    assert_eq!(rows.len(), 1, "one refusal row");
    assert_eq!(rows[0]["outcome"], "refused");
    assert_eq!(rows[0]["account"], "personal");
    assert!(!rows[0].to_string().contains('@'));
}

/// P1: a known contact in Private mode is admitted by the B20 gate and the
/// real values reach the fake SMTP server.
#[tokio::test]
async fn private_known_contact_reaches_smtp_with_real_values() {
    let smtp = FakeSmtpAccept::start().await;
    let connector = private_connector(smtp.port);
    let directory: Arc<dyn RecipientDirectory> = Arc::new(Known(vec!["camille@exemple.fr"]));
    let (outcome, sink) = run_executor(connector, directory).await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert_eq!(smtp.connections(), 1, "one SMTP connection");
    let accepted = smtp.accepted();
    assert_eq!(accepted.len(), 1, "one message");
    assert!(
        accepted[0].contains("camille@exemple.fr"),
        "the real recipient reaches SMTP: {}",
        accepted[0]
    );
    assert!(
        !accepted[0].contains('\u{27e6}') && !accepted[0].contains('\u{27e7}'),
        "no token reaches SMTP"
    );
    assert_eq!(sink.rows("mail.call")[0]["outcome"], "sent");
    assert_eq!(sink.rows("mail.call")[0]["account"], "personal");
}

/// The owner's answer on the daemon's channel: an edit of the run card.
struct EditsTo(Value);

#[async_trait]
impl Approver for EditsTo {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }

    async fn decide(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision, ApproverError> {
        Ok(ApprovalDecision::edited(self.0.clone()))
    }
}

/// SEND-REAL-ARGS-1: an edited call runs its `real` object, the one the card
/// shows; a call that carries only `arguments` (the card shows no recipient)
/// opens no SMTP socket.
#[tokio::test]
async fn an_edited_send_reaches_smtp_only_through_its_real_arguments() {
    let edited = json!({ "to": ["sent@exemple.fr"], "subject": "Invitation", "body": "Edited." });
    for (key, sends) in [("arguments", false), ("real", true)] {
        let smtp = FakeSmtpAccept::start().await;
        let directory: Arc<dyn RecipientDirectory> =
            Arc::new(Known(vec!["camille@exemple.fr", "sent@exemple.fr"]));
        let answer = json!({ "calls": [{ "tool": "mail_send", key: edited }] });
        let approver = BrokerCardApprover::new(Arc::new(EditsTo(answer)), "assistant");
        let (outcome, _) =
            run_executor_with(private_connector(smtp.port), directory, &approver).await;
        if sends {
            assert!(
                matches!(outcome, RunOutcome::Done { .. }),
                "{key}: {outcome:?}"
            );
            let accepted = smtp.accepted();
            assert_eq!(accepted.len(), 1, "{key}: one message");
            assert!(
                accepted[0].contains("sent@exemple.fr"),
                "{key}: {}",
                accepted[0]
            );
            assert!(
                !accepted[0].contains("camille@exemple.fr"),
                "{key}: the edit wins"
            );
        } else {
            assert!(
                matches!(outcome, RunOutcome::Refused { .. }),
                "{key}: {outcome:?}"
            );
            assert_eq!(smtp.connections(), 0, "{key}: no SMTP socket");
        }
    }
}

/// The model cannot propose a `bcc` in the first place: the `mail.send`
/// schema has no such field, so the fill is refused before any card. Only the
/// owner's edit could add one, and that edit is refused too.
#[test]
fn a_model_cannot_propose_a_bcc_in_a_mail_send() {
    let value = json!({
        "slots": { "email": "camille@exemple.fr" },
        "calls": [{
            "tool": "mail_send",
            "arguments": {
                "to": ["camille@exemple.fr"],
                "subject": "Invitation",
                "body": "Bonjour.",
                "bcc": ["hidden@exemple.fr"]
            }
        }]
    });
    let err = validate_fill(&mail_exec_skill(), &value, &mail_exec_context(), None)
        .expect_err("the model cannot add a bcc");
    assert!(format!("{err:?}").contains("bcc"), "{err:?}");
}

/// SEND-REAL-ARGS-1: a `bcc` the SMTP path never sends is refused before any
/// socket. The card would show a hidden recipient that no message carries, so
/// the run stops and the fake SMTP sees nothing at all.
#[tokio::test]
async fn an_edited_send_with_a_bcc_is_refused_and_opens_no_smtp_socket() {
    let smtp = FakeSmtpAccept::start().await;
    let directory: Arc<dyn RecipientDirectory> =
        Arc::new(Known(vec!["camille@exemple.fr", "hidden@exemple.fr"]));
    let answer = json!({ "calls": [{ "tool": "mail_send", "real": {
        "to": ["camille@exemple.fr"], "subject": "Invitation", "body": "Bonjour.",
        "bcc": ["hidden@exemple.fr"] } }] });
    let approver = BrokerCardApprover::new(Arc::new(EditsTo(answer)), "assistant");
    let (outcome, _) = run_executor_with(private_connector(smtp.port), directory, &approver).await;
    assert!(matches!(outcome, RunOutcome::Refused { .. }), "{outcome:?}");
    assert_eq!(smtp.connections(), 0, "no SMTP socket");
    assert!(smtp.accepted().is_empty(), "nothing was sent");
}

// M4-2: the `.ics` carries exactly the instant the card shows.

/// Remembers each run card exactly as the approval channel renders it.
#[derive(Default)]
struct CardRecorder(Mutex<Vec<Value>>);

#[async_trait]
impl SkillApprover for CardRecorder {
    async fn decide(&self, card: &aux_runtime::executor::ApprovalCard) -> RunDecision {
        let shown = aux_runtime::executor::card_arguments(card);
        self.0.lock().unwrap().push(shown);
        RunDecision::approved()
    }
}

struct InviteToolsSkillOnly;

impl SkillOnlyLookup for InviteToolsSkillOnly {
    fn is_skill_only(&self, tool: &str) -> bool {
        tool == "mail_send" || tool == "apple_calendar_create_event"
    }
}

/// Run the two-call invite with `event` as the model's calendar arguments;
/// returns the outcome, the cards shown and the mails sent.
async fn run_invite(event: Value) -> (RunOutcome, Vec<Value>, Vec<OutgoingMail>) {
    run_invite_with(event, &Known(vec!["camille@exemple.fr"])).await
}

/// [`run_invite`] with this run's known-contacts directory: a directory that
/// carries a stored client zone changes the invite's attendee zone.
async fn run_invite_with(
    event: Value,
    directory: &dyn RecipientDirectory,
) -> (RunOutcome, Vec<Value>, Vec<OutgoingMail>) {
    let mut agent = mail_exec_agent();
    agent.tools = vec!["calendar.create_event".into(), "mail.send".into()];
    let text = b"---\nname: send-invite\nversion: 1\ntools: [calendar.create_event, mail.send]\ninputs:\n  email: { type: email }\nrecipients:\n  policy: known-contacts\napproval: each_run\n---\nBody.\n";
    let skill = parse_skill(text, "send-invite.md", "send-invite", &agent).unwrap();
    let fill = json!({ "slots": { "email": "camille@exemple.fr" }, "calls": [
        { "tool": "apple_calendar_create_event", "arguments": event },
        { "tool": "mail_send", "arguments": { "to": ["camille@exemple.fr"],
            "subject": "Invitation", "body": "Bonjour.", "ics": "event" } },
    ]});
    let fill = validate_fill(&skill, &fill, &mail_exec_context(), None).expect("a valid fill");
    let mail = Arc::new(RecordingMail::default());
    let home = std::env::temp_dir().join(format!("aux-invite-tz-{}", std::process::id()));
    let connector = connector(mail.clone(), fake_bridge(home));
    let sink = Arc::new(RecordingSink::default());
    let skill_only = Arc::new(InviteToolsSkillOnly);
    let broker = Broker::new(sink.clone(), Vec::new(), Arc::new(PreApproved), skill_only);
    let approver = CardRecorder::default();
    let exec = Executor {
        broker: &broker,
        sink: sink.as_ref(),
        approver: &approver,
        connector: &connector,
        directory,
        allowlist: &[],
        clock: &RealClock,
        stop: &NeverStopped,
        approval_timeout: default_approval_timeout(),
    };
    let (tokens, context) = (TokenMap::default(), mail_exec_context());
    let outcome = exec
        .execute(&skill, &fill, &context, &tokens, &Taint::Clean)
        .await;
    let cards = approver.0.lock().unwrap().clone();
    let sent = mail.sent.lock().unwrap().clone();
    (outcome, cards, sent)
}

/// "10:00" in Paris on 2026-10-26, the day after the clocks went back, is
/// 09:00 UTC, not the 08:00 today's +02:00 gave. The card shows the zone, the
/// client's local time and the exact UTC instants; the `.ics` carries them.
#[tokio::test]
async fn an_invite_at_ten_paris_after_the_dst_change_lands_at_ten_paris() {
    let (outcome, cards, sent) = run_invite(json!({
        "title": "Meeting with Camille Exemple", "start": "2026-10-26T10:00:00",
        "end": "2026-10-26T10:30:00", "time_zone": "Europe/Paris",
        "attendee_time_zone": "America/New_York",
    }))
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    let shown = &cards[0]["calls"][0]["real"];
    assert_eq!(shown["start"], "2026-10-26T10:00:00+01:00", "{shown}");
    assert_eq!(shown["time_zone"], "Europe/Paris");
    assert_eq!(shown["attendee_start"], "2026-10-26T05:00:00-04:00");
    assert!(
        shown.get("attendee_time_zone_source").is_none(),
        "no stored client zone: the model's argument stays, with no note"
    );
    assert_eq!(shown["start_utc"], "20261026T090000Z");
    assert_eq!(sent.len(), 1, "one invite");
    let ics = sent[0]
        .ics
        .as_deref()
        .expect("an .ics")
        .replace("\r\n ", "");
    for (field, line) in [("start_utc", "DTSTART:"), ("end_utc", "DTEND:")] {
        let instant = shown[field].as_str().expect("shown on the card");
        assert!(ics.contains(&format!("{line}{instant}\r\n")), "{ics}");
    }
}

/// CLIENT-TZ-FIELD: the client card's stored zone wins over the model's
/// `attendee_time_zone`, and the card says where the zone came from.
#[tokio::test]
async fn a_stored_client_zone_wins_over_the_models_zone() {
    let store = Store::open_in_memory().unwrap();
    aux_crm::Crm::new(&store)
        .create(NewParty {
            kind: aux_store::PartyKind::Person,
            display_name: "Camille Exemple".to_string(),
            emails: vec!["camille@exemple.fr".to_string()],
            origin: "contacts:file:vcard".to_string(),
            time_zone: Some("Asia/Tokyo".to_string()),
            ..NewParty::default()
        })
        .unwrap();
    // The directory the daemon builds: the contacts index and the store's zones.
    let index = aux_runtime::known_names::contacts_index(&[ContactRecord {
        source: "file:vcard".to_string(),
        display_name: Some("Camille Exemple".to_string()),
        emails: vec!["camille@exemple.fr".to_string()],
        ..ContactRecord::default()
    }]);
    let directory = ContactsWithZones::from_store(Arc::new(index), &store);

    let (outcome, cards, sent) = run_invite_with(
        json!({
            "title": "Meeting with Camille Exemple", "start": "2026-10-26T10:00:00",
            "end": "2026-10-26T10:30:00", "time_zone": "Europe/Paris",
            // The model's guess: the stored zone replaces it.
            "attendee_time_zone": "America/New_York",
        }),
        &directory,
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    let shown = &cards[0]["calls"][0]["real"];
    assert_eq!(shown["attendee_time_zone"], "Asia/Tokyo");
    // 10:00 in Paris is 09:00 UTC, 18:00 in Tokyo.
    assert_eq!(shown["attendee_start"], "2026-10-26T18:00:00+09:00");
    let source = shown["attendee_time_zone_source"]
        .as_str()
        .expect("the card says where the zone came from");
    assert!(
        source.contains("client card") && source.contains("America/New_York"),
        "{source}"
    );
    assert_eq!(sent.len(), 1, "one invite");
    // The write itself never carries the card-only source field.
    let ics = sent[0].ics.as_deref().expect("an .ics");
    assert!(ics.contains("DTSTART:20261026T090000Z"), "{ics}");
    assert!(!ics.contains("attendee_time_zone_source"), "{ics}");
}

/// CLIENT-TZ-FIELD acceptance: a client imported from a vCard carrying
/// `TZ:America/New_York`, then an invite whose model guessed `Europe/Paris`.
/// The card's zone wins before the approval card, and the `.ics` carries the
/// instant that is 10:00 in Paris and 05:00 in New York. A `TZ:` that is not an
/// IANA name (`Mars/Base`) is ignored on import, never guessed, and the import
/// report says so.
#[tokio::test]
async fn an_imported_vcard_zone_reaches_the_invite_and_beats_the_models_guess() {
    let dir = tempfile::tempdir().expect("a temp store");
    let store = Store::open(&dir.path().join("store.db")).expect("a store");
    let file = dir.path().join("contacts.vcf");
    std::fs::write(
        &file,
        "BEGIN:VCARD\nVERSION:4.0\nFN:Camille Exemple\nEMAIL:camille@exemple.fr\n\
         TZ:America/New_York\nEND:VCARD\n\
         BEGIN:VCARD\nVERSION:4.0\nFN:Jonas Weber\nEMAIL:jonas@exemple.fr\n\
         TZ:Mars/Base\nEND:VCARD\n",
    )
    .expect("a vCard");
    let summary = aux_runtime::contacts_import::import_file(&store, &file, None, Some("client"))
        .expect("an import");
    assert_eq!(summary.time_zone_ignored, 1, "Mars/Base is not a zone");
    assert!(
        summary.to_string().contains("not an IANA name"),
        "the report must say the invalid zone was ignored: {summary}"
    );
    let parties = aux_crm::Crm::new(&store).list().expect("the cards");
    let zone_of = |email: &str| {
        parties
            .iter()
            .find(|party| party.emails.iter().any(|known| known == email))
            .and_then(|party| party.time_zone.as_deref())
    };
    assert_eq!(zone_of("camille@exemple.fr"), Some("America/New_York"));
    assert_eq!(
        zone_of("jonas@exemple.fr"),
        None,
        "an invalid zone is ignored"
    );

    let index = aux_runtime::known_names::contacts_index(&store.contacts().expect("contacts"));
    let directory = ContactsWithZones::from_store(Arc::new(index), &store);
    let (outcome, cards, sent) = run_invite_with(
        json!({
            "title": "Meeting with Camille Exemple",
            "start": "2026-10-26T10:00:00",
            "end": "2026-10-26T10:30:00",
            "time_zone": "Europe/Paris",
            // The model's guess: the card's New York zone replaces it.
            "attendee_time_zone": "Europe/Paris",
        }),
        &directory,
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    let shown = &cards[0]["calls"][0]["real"];
    assert_eq!(shown["attendee_time_zone"], "America/New_York");
    // 10:00 in Paris is 09:00 UTC, 05:00 in New York.
    assert_eq!(shown["attendee_start"], "2026-10-26T05:00:00-04:00");
    let source = shown["attendee_time_zone_source"]
        .as_str()
        .expect("the card says where the zone came from");
    assert!(
        source.contains("client card") && source.contains("Europe/Paris"),
        "{source}"
    );
    assert_eq!(sent.len(), 1, "one invite");
    let ics = sent[0].ics.as_deref().expect("an .ics");
    assert!(ics.contains("DTSTART:20261026T090000Z"), "{ics}");
}

/// Refused before any card, nothing sent, no zone assumed: today's `+02:00` on
/// a `+01:00` day, an unknown zone, a time the clocks skip.
#[tokio::test]
async fn a_wrong_offset_an_unknown_zone_or_a_skipped_time_sends_nothing() {
    for (start, zone, why) in [
        ("2026-10-26T10:00:00+02:00", "Europe/Paris", "+01:00"),
        ("2026-10-26T10:00:00", "Europe/Pariss", "unknown time zone"),
        ("2026-03-29T02:30:00", "Europe/Paris", "does not exist"),
    ] {
        let (outcome, cards, sent) = run_invite(json!({
            "title": "Meeting", "start": start, "end": "2026-10-26T11:00:00", "time_zone": zone,
        }))
        .await;
        let reason = format!("{outcome:?}");
        let refused = matches!(outcome, RunOutcome::Refused { .. });
        assert!(refused && reason.contains(why), "{reason}");
        assert_eq!((cards.len(), sent.len()), (0, 0), "{start} {zone}");
    }
}

/// The `.ics` takes the card's `start_utc` only while it agrees with the card's
/// `start`: a pair that disagrees refuses the invite and sends nothing.
#[tokio::test]
async fn an_event_whose_utc_disagrees_with_its_start_sends_no_invite() {
    let mail = Arc::new(RecordingMail::default());
    let home = std::env::temp_dir().join(format!("aux-tz-{}", std::process::id()));
    let connector = connector(mail.clone(), fake_bridge(home));
    let event = json!({"title": "M", "start": "2026-10-26T10:00:00+01:00",
        "end": "2026-10-26T10:30:00+01:00", "start_utc": "20261026T080000Z",
        "end_utc": "20261026T093000Z"});
    let ctx = context();
    connector
        .call(&ctx, "calendar.create_event", &event)
        .await
        .expect("created");
    let invite = json!({"to": ["camille@exemple.fr"], "subject": "I", "body": "B", "ics": "x"});
    let err = connector.call(&ctx, "mail.send", &invite).await;
    let err = err.expect_err("a disagreeing instant is refused");
    assert!(err.message.contains("disagree"), "{}", err.message);
    assert!(mail.sent.lock().unwrap().is_empty(), "nothing is sent");
}

// INVITE-ATTENDEE-1: the invite that reaches SMTP names its real recipient.

/// The `.ics` part of one SMTP message, base64-decoded and unfolded.
fn smtp_ics(data: &str) -> String {
    use base64::Engine as _;
    let part = data
        .split("Content-Type: text/calendar")
        .nth(1)
        .expect("a calendar part");
    let body = part.split("\r\n\r\n").nth(1).expect("the part's body");
    let encoded: String = body
        .lines()
        .take_while(|line| !line.starts_with("--"))
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .expect("a base64 calendar part");
    String::from_utf8(bytes)
        .expect("UTF-8")
        .replace("\r\n ", "")
}

/// A Private invite whose recipient the model saw only as a token: approved,
/// it reaches the fake SMTP server with the real `To` address as the `.ics`
/// `ATTENDEE`, and no token anywhere in the message.
#[tokio::test]
async fn an_approved_private_invite_names_the_real_to_address_as_its_attendee() {
    use kernel_privacy::{Anonymizer, EntityKind, Span};
    // Long enough that the attendee line needs a fold.
    let real = "camille.exemple-longue@cabinet-exemple.test";
    let span = Span {
        kind: EntityKind::Email,
        start: 0,
        end: real.len(),
        score: 1.0,
        recognizer: "test",
        person_id: None,
    };
    let (_, tokens) = Anonymizer::new([7u8; 32]).anonymize(real, &[span]);
    let token = tokens
        .iter()
        .map(|(token, _)| format!("⟦{token}⟧"))
        .next()
        .expect("an EMAIL token");

    let mut agent = mail_exec_agent();
    agent.tools = vec!["calendar.create_event".into(), "mail.send".into()];
    let text = b"---\nname: send-invite\nversion: 1\ntools: [calendar.create_event, mail.send]\ninputs:\n  email: { type: email }\nrecipients:\n  policy: known-contacts\napproval: each_run\n---\nBody.\n";
    let skill = parse_skill(text, "send-invite.md", "send-invite", &agent).unwrap();
    let fill = json!({ "slots": { "email": token }, "calls": [
        { "tool": "apple_calendar_create_event", "arguments": {
            "title": "Meeting", "start": "2026-11-03T10:00:00",
            "end": "2026-11-03T10:30:00", "time_zone": "Europe/Paris" } },
        { "tool": "mail_send", "arguments": { "to": [token],
            "subject": "Invitation", "body": "Bonjour.", "ics": "event" } },
    ]});
    let fill = validate_fill(&skill, &fill, &mail_exec_context(), None).expect("a valid fill");

    let smtp = FakeSmtpAccept::start().await;
    let service = MailService::new(
        Dialer::new(Duration::from_secs(5)),
        Limits::default(),
        vec![plaintext_account(smtp.port)],
        Arc::new(NoCredentials),
    );
    let home = tempfile::tempdir().expect("a temp home");
    let connector = MailSkillConnector::new(
        MailToolset::new(Arc::new(service), None),
        Some(fake_bridge(home.path().to_path_buf())),
        "me@example.org",
        private_mode(),
    );
    let sink = Arc::new(RecordingSink::default());
    let broker = Broker::new(
        sink.clone(),
        Vec::new(),
        Arc::new(PreApproved),
        Arc::new(InviteToolsSkillOnly),
    );
    let approver = CardRecorder::default();
    let exec = Executor {
        broker: &broker,
        sink: sink.as_ref(),
        approver: &approver,
        connector: &connector,
        directory: &Known(vec![real]),
        allowlist: &[],
        clock: &RealClock,
        stop: &NeverStopped,
        approval_timeout: default_approval_timeout(),
    };
    let outcome = exec
        .execute(&skill, &fill, &mail_exec_context(), &tokens, &Taint::Clean)
        .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");

    let accepted = smtp.accepted();
    assert_eq!(accepted.len(), 1, "one message");
    let data = &accepted[0];
    assert!(
        !data.contains('⟦') && !data.contains('⟧'),
        "no token in the mail"
    );
    let to = data
        .lines()
        .find_map(|line| line.strip_prefix("To: "))
        .expect("a To header");
    assert_eq!(to, real, "the mail goes to the real recipient");
    let ics = smtp_ics(data);
    let attendee = ics
        .lines()
        .find(|line| line.starts_with("ATTENDEE"))
        .expect("an ATTENDEE line");
    assert_eq!(attendee, format!("ATTENDEE;RSVP=TRUE:mailto:{to}"), "{ics}");
    for line in ["METHOD:REQUEST", "UID:", "DTSTART:", "DTEND:"] {
        assert!(ics.lines().any(|l| l.starts_with(line)), "{line} in {ics}");
    }
    assert!(
        !ics.contains('⟦') && !ics.contains('⟧'),
        "no token in the invite"
    );
}

fn envelope(from: &str, day: &str) -> EnvelopeItem {
    EnvelopeItem {
        uid: 1,
        message_id: "<m@example.test>".to_string(),
        subject: "Re: Invoice 100".to_string(),
        from: from.to_string(),
        to: vec!["me@example.org".to_string()],
        cc: Vec::new(),
        date: format!("{day} 2026 10:00:00 +0000"),
        size: 100,
        unread: false,
        in_reply_to: None,
    }
}

/// One mail of the owner's Sent folder, to `recipient`.
fn sent_to(recipient: &str) -> EnvelopeItem {
    EnvelopeItem {
        from: "me@example.org".to_string(),
        to: vec![recipient.to_string()],
        ..envelope("me@example.org", "20 Sep")
    }
}

/// Records each card and approves it.
#[derive(Default)]
struct RecordsCards(Mutex<Vec<aux_runtime::executor::ApprovalCard>>);

#[async_trait]
impl SkillApprover for RecordsCards {
    async fn decide(&self, card: &aux_runtime::executor::ApprovalCard) -> RunDecision {
        self.0.lock().unwrap().push(card.clone());
        RunDecision::approved()
    }
}

/// A mail that forwards another Lea in its subject (its body is never read).
fn forwarded() -> EnvelopeItem {
    let subject = "Fwd: Lea <evil@x.example> about invoice 100".to_string();
    EnvelopeItem {
        subject,
        ..envelope("Bob Fictive <bob@verdant.example>", "27 Sep")
    }
}

/// MAIL-UNKNOWN-CONTACT-1: the owner says "reply to Lea" and the shipped
/// `follow-up` skill runs with no contact at all.
type Ran = (
    RunOutcome,
    Vec<aux_runtime::executor::ApprovalCard>,
    Vec<OutgoingMail>,
);

async fn reply_to_lea(inbox: Vec<EnvelopeItem>) -> Ran {
    reply_to_named(
        "Lea",
        "réponds au dernier mail de lea, dis lui que c'est ok pour jeudi",
        inbox,
    )
    .await
}

async fn reply_to_named(said: &str, owner_input: &str, inbox: Vec<EnvelopeItem>) -> Ran {
    reply_to_named_with(said, owner_input, inbox, Vec::new()).await
}

async fn reply_to_named_with(
    said: &str,
    owner_input: &str,
    inbox: Vec<EnvelopeItem>,
    owner_addresses: Vec<String>,
) -> Ran {
    reply_to_named_full(
        said,
        owner_input,
        inbox,
        None,
        owner_addresses,
        Arc::new(Known(vec![])),
    )
    .await
}

/// The same run over a Sent folder the owner may read and an explicit
/// directory, for the mailbox trust bar and the Clients path.
async fn reply_to_named_full(
    said: &str,
    owner_input: &str,
    inbox: Vec<EnvelopeItem>,
    sent_mail: Option<Vec<EnvelopeItem>>,
    owner_addresses: Vec<String>,
    directory: Arc<dyn RecipientDirectory>,
) -> Ran {
    let mail = Arc::new(RecordingMail {
        inbox,
        sent_mail,
        owner_addresses,
        ..RecordingMail::default()
    });
    let api = Arc::clone(&mail) as Arc<dyn MailApi>;
    let connector = MailSkillConnector::new(
        MailToolset::new(api, None),
        None,
        "me@example.org",
        private_mode(),
    );
    let run = RunContext {
        agent: "assistant",
        run_id: "run-1",
        schemas: None,
        owner_input: Some(owner_input),
    };
    let text = include_bytes!("../src/agents/mail/skills/follow-up.md");
    let skill = parse_skill(text, "follow-up.md", "follow-up", &mail_exec_agent()).unwrap();
    let arguments = json!({ "subject": "Re: Invoice 100", "body": "Ok pour jeudi." });
    let fill = json!({ "slots": { "person": said }, "calls": [{ "tool": "mail_send", "arguments": arguments }] });
    let fill = validate_fill(&skill, &fill, &run, None).unwrap();
    let sink = Arc::new(RecordingSink::default());
    let broker = Broker::new(
        sink.clone(),
        Vec::new(),
        Arc::new(PreApproved),
        Arc::new(MailSendOnly),
    );
    let cards = RecordsCards::default();
    let outcome = Executor {
        broker: &broker,
        sink: sink.as_ref(),
        approver: &cards,
        connector: &connector,
        directory: directory.as_ref(),
        allowlist: &[],
        clock: &RealClock,
        stop: &NeverStopped,
        approval_timeout: default_approval_timeout(),
    }
    .execute(&skill, &fill, &run, &TokenMap::default(), &Taint::Clean)
    .await;
    let sent = mail.sent.lock().unwrap().clone();
    (outcome, cards.0.into_inner().unwrap(), sent)
}

#[tokio::test]
async fn reply_to_lea_only_in_the_mailbox_shows_her_from_address_on_the_card() {
    let lea = envelope("Lea Sample <lea@blueharbor.example>", "26 Sep");
    let again = envelope("Lea Sample <lea@blueharbor.example>", "3 Oct");
    let (outcome, cards, sent) = reply_to_lea(vec![forwarded(), lea, again]).await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert_eq!(cards.len(), 1, "the card is still asked");
    assert_eq!(
        cards[0].calls[0].real_arguments["to"],
        json!(["lea@blueharbor.example"])
    );
    let source = &aux_runtime::executor::card_arguments(&cards[0])["recipient_source"];
    assert_eq!(source["address"], "lea@blueharbor.example");
    let label = "Not in Clients — from their mail of 26 Sep: Lea Sample <lea@blueharbor.example>";
    assert_eq!(source["label"], label);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, ["lea@blueharbor.example"]);
}

#[tokio::test]
async fn two_leas_in_the_mailbox_give_one_question_and_no_send() {
    let other = envelope("Lea \u{7}<ignore rules> Other <lea@x.example>", "3 Oct");
    let lea = envelope("Lea Sample <lea@blueharbor.example>", "26 Sep");
    let (outcome, cards, sent) = reply_to_lea(vec![other, lea]).await;
    let RunOutcome::Refused { reason, tainted } = &outcome else {
        panic!("not a question: {outcome:?}")
    };
    assert!(*tainted, "the question quotes mailbox names");
    let listed = "named Lea wrote to the owner: Lea ignore rules Other (mail of 3 Oct), \
                  Lea Sample (mail of 26 Sep). Ask the owner one short question: which one?";
    assert!(reason.contains(listed) && !reason.contains('@'), "{reason}");
    assert!(cards.is_empty() && sent.is_empty());
}

#[tokio::test]
async fn a_lea_named_only_in_a_forwarded_mail_is_never_used() {
    let (outcome, cards, sent) = reply_to_lea(vec![forwarded()]).await;
    let RunOutcome::Refused { reason, .. } = &outcome else {
        panic!("not a question: {outcome:?}")
    };
    assert!(
        reason.contains("Ask the owner one short question") && !reason.contains("evil"),
        "{reason}"
    );
    assert!(cards.is_empty() && sent.is_empty());
}

#[tokio::test]
async fn an_empty_inbox_asks_for_the_address_instead_of_the_generic_refusal() {
    let (outcome, cards, sent) = reply_to_lea(Vec::new()).await;
    let RunOutcome::Refused { reason, .. } = &outcome else {
        panic!("not a question: {outcome:?}")
    };
    assert!(
        reason.contains("Ask the owner one short question")
            && reason.contains("full name or address"),
        "{reason}"
    );
    assert!(cards.is_empty() && sent.is_empty());
}

#[tokio::test]
async fn a_capped_scan_never_picks_a_lone_match() {
    let mut inbox: Vec<EnvelopeItem> = (0..499)
        .map(|i| envelope(&format!("Person {i} <person{i}@example.test>"), "1 Oct"))
        .collect();
    inbox.push(envelope("Lea Sample <lea@blueharbor.example>", "26 Sep"));
    let (outcome, cards, sent) = reply_to_lea(inbox).await;
    let RunOutcome::Refused { reason, .. } = &outcome else {
        panic!("a capped scan must ask, not pick: {outcome:?}")
    };
    assert!(
        reason.contains("scan stopped before the end") && reason.contains("which address?"),
        "{reason}"
    );
    assert!(cards.is_empty() && sent.is_empty());
}

#[tokio::test]
async fn a_long_sender_name_is_capped_on_the_card_and_the_address_stays_whole() {
    let display = format!("Lea {} <lea@blueharbor.example>", "é".repeat(80));
    let again = envelope(&display, "3 Oct");
    let (outcome, cards, _sent) = reply_to_lea(vec![envelope(&display, "26 Sep"), again]).await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    let source = &aux_runtime::executor::card_arguments(&cards[0])["recipient_source"];
    let label = source["label"].as_str().expect("a card label");
    let prefix = "Not in Clients — from their mail of 26 Sep: ";
    let shown = label
        .strip_prefix(prefix)
        .expect("the warning comes first")
        .split(" <")
        .next()
        .expect("a display name");
    assert!(shown.chars().count() <= 40, "capped: {shown:?}");
    assert!(shown.ends_with('…'), "the cap is marked: {shown:?}");
    assert!(
        label.ends_with("<lea@blueharbor.example>"),
        "the address is whole: {label}"
    );
}

/// MAILBOX-LOOKALIKE-HARDEN: one mail from a lookalike name is not enough for
/// the mailbox to pick the recipient: no card, no send, one plain line.
#[tokio::test]
async fn a_one_day_lookalike_sender_from_the_mailbox_is_refused_without_a_card() {
    let attacker = envelope("Camille Northwind <q7f3k9@evil.example>", "26 Sep");
    let (outcome, cards, sent) = reply_to_named(
        "Camille Northwind",
        "send Camille Northwind the new IBAN",
        vec![attacker],
    )
    .await;
    let RunOutcome::Refused { reason, tainted } = &outcome else {
        panic!("a one-day lookalike must be refused: {outcome:?}")
    };
    assert!(!tainted, "the refusal quotes no mailbox name: {reason}");
    assert!(
        reason.contains("Clients") && reason.contains("type the address"),
        "{reason}"
    );
    assert!(cards.is_empty() && sent.is_empty());
}

/// A correspondent the owner already wrote to clears the bar on one received
/// mail; the warning now comes first on the row.
#[tokio::test]
async fn a_correspondent_the_owner_wrote_to_before_is_picked_with_the_warning_first() {
    let camille = envelope("Camille Northwind <camille@northwind.example>", "26 Sep");
    let sent_mail = Some(vec![sent_to(
        "Camille Northwind <camille@northwind.example>",
    )]);
    let (outcome, cards, sent) = reply_to_named_full(
        "Camille Northwind",
        "send Camille Northwind the new IBAN",
        vec![camille],
        sent_mail,
        Vec::new(),
        Arc::new(Known(vec![])),
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert_eq!(cards.len(), 1);
    let source = &aux_runtime::executor::card_arguments(&cards[0])["recipient_source"];
    assert_eq!(
        source["label"],
        "Not in Clients — from their mail of 26 Sep: Camille Northwind \
         <camille@northwind.example>"
    );
    assert_eq!(sent[0].to, ["camille@northwind.example"]);
}

/// A dotted display name must not read like another address beside the real
/// one: the card shows words only, and the warning stays first.
#[tokio::test]
async fn a_dotted_display_name_cannot_imitate_an_address_on_the_card() {
    let sender = envelope(
        "camille.northwind.example <camille@northwind.example>",
        "26 Sep",
    );
    let sent_mail = Some(vec![sent_to("camille@northwind.example")]);
    let (outcome, cards, _sent) = reply_to_named_full(
        "camille.northwind.example",
        "send camille.northwind.example the IBAN",
        vec![sender],
        sent_mail,
        Vec::new(),
        Arc::new(Known(vec![])),
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    let source = &aux_runtime::executor::card_arguments(&cards[0])["recipient_source"];
    assert_eq!(
        source["label"],
        "Not in Clients — from their mail of 26 Sep: camille northwind example \
         <camille@northwind.example>"
    );
}

/// No readable Sent folder: two different arrival days are the bar.
#[tokio::test]
async fn two_arrival_days_are_enough_when_no_sent_folder_is_readable() {
    let first = envelope("Camille Northwind <camille@northwind.example>", "26 Sep");
    let second = envelope("Camille Northwind <camille@northwind.example>", "3 Oct");
    let (outcome, cards, sent) = reply_to_named_full(
        "Camille Northwind",
        "send Camille Northwind the new IBAN",
        vec![first, second],
        None,
        Vec::new(),
        Arc::new(Known(vec![])),
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert_eq!(cards.len(), 1);
    assert_eq!(sent[0].to, ["camille@northwind.example"]);
}

/// A readable Sent folder is the stricter rule: two days are not enough.
#[tokio::test]
async fn a_readable_sent_folder_overrides_two_arrival_days() {
    let first = envelope("Camille Northwind <camille@northwind.example>", "26 Sep");
    let second = envelope("Camille Northwind <camille@northwind.example>", "3 Oct");
    let (outcome, cards, sent) = reply_to_named_full(
        "Camille Northwind",
        "send Camille Northwind the new IBAN",
        vec![first, second],
        Some(Vec::new()),
        Vec::new(),
        Arc::new(Known(vec![])),
    )
    .await;
    let RunOutcome::Refused { reason, .. } = &outcome else {
        panic!("the written-to bar must win: {outcome:?}")
    };
    assert!(reason.contains("written to"), "{reason}");
    assert!(cards.is_empty() && sent.is_empty());
}

/// A person in Clients never reaches the mailbox lookup: the client address
/// wins even while a lookalike sits in the INBOX.
#[tokio::test]
async fn a_clients_contact_is_unaffected_by_a_lookalike_in_the_mailbox() {
    let lookalike = envelope("Camille <q7f3k9@evil.example>", "26 Sep");
    let directory = Arc::new(NamedKnown("Camille", "camille@northwind.example"));
    let (outcome, cards, sent) = reply_to_named_full(
        "Camille",
        "send Camille the new IBAN",
        vec![lookalike],
        None,
        Vec::new(),
        directory,
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert_eq!(cards.len(), 1);
    assert_eq!(
        cards[0].calls[0].real_arguments["to"],
        json!(["camille@northwind.example"])
    );
    assert_eq!(
        aux_runtime::executor::card_arguments(&cards[0])["recipient_source"],
        Value::Null,
        "a Clients contact has no mailbox source"
    );
    assert_eq!(sent[0].to, ["camille@northwind.example"]);
}

#[tokio::test]
async fn the_owners_own_addresses_are_never_picked_as_the_recipient() {
    for (owner, sender) in [
        ("me@example.org", "me@example.org"),
        ("alias@example.org", "alias@example.org"),
        ("me@example.com", "me+news@example.com"),
        ("me@gmail.com", "m.e+news@googlemail.com"),
    ] {
        let own = envelope(&format!("Lea <{sender}>"), "26 Sep");
        let (outcome, cards, sent) = reply_to_named_with(
            "Lea",
            "réponds au dernier mail de lea, dis lui que c'est ok pour jeudi",
            vec![own],
            vec![owner.to_string()],
        )
        .await;
        let RunOutcome::Refused { reason, .. } = &outcome else {
            panic!("the owner's own address must not be picked: {owner} -> {outcome:?}")
        };
        assert!(
            reason.contains("Ask the owner one short question"),
            "{reason}"
        );
        assert!(cards.is_empty() && sent.is_empty());
    }
}

#[tokio::test]
async fn generic_role_local_parts_do_not_resolve_by_local_part_alone() {
    for word in [
        "support", "info", "contact", "hello", "team", "admin", "noreply", "no-reply", "sales",
        "billing",
    ] {
        let sender = envelope(&format!("Vendor Desk <{word}@vendor.example>"), "26 Sep");
        let owner_input = format!("réponds à {word}, dis lui que c'est ok pour jeudi");
        let (outcome, cards, sent) = reply_to_named(word, &owner_input, vec![sender]).await;
        let RunOutcome::Refused { reason, .. } = &outcome else {
            panic!("a role address must not resolve by local part: {word} -> {outcome:?}")
        };
        assert!(
            reason.contains("Ask the owner one short question"),
            "{reason}"
        );
        assert!(cards.is_empty() && sent.is_empty(), "{word}");
    }

    // A whole display name still identifies the sender.
    let sender = envelope("Support <support@vendor.example>", "26 Sep");
    let again = envelope("Support <support@vendor.example>", "3 Oct");
    let owner_input = "réponds à support, dis lui que c'est ok pour jeudi";
    let (outcome, cards, sent) = reply_to_named("support", owner_input, vec![sender, again]).await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert_eq!(cards.len(), 1);
    assert_eq!(sent.len(), 1);
}

#[tokio::test]
async fn common_words_only_match_a_whole_display_name_or_local_part() {
    for (word, from) in [
        ("team", "Team Support <team.support@x.example>"),
        ("support", "Support Team <support.team@x.example>"),
        ("hello", "Hello There <hello.there@x.example>"),
    ] {
        let owner_input = format!("réponds à {word}, dis lui que c'est ok pour jeudi");
        let (outcome, cards, sent) =
            reply_to_named(word, &owner_input, vec![envelope(from, "26 Sep")]).await;
        let RunOutcome::Refused { reason, .. } = &outcome else {
            panic!("a partial name must ask: {word} -> {outcome:?}")
        };
        assert!(
            reason.contains("Ask the owner one short question"),
            "{reason}"
        );
        assert!(cards.is_empty() && sent.is_empty(), "{word}");
    }
}

/// The `send-draft` skill as shipped, filled the only way it takes: a slot
/// with the stored draft id and an empty `mail.send` call.
fn send_draft_skill() -> LoadedSkill {
    parse_skill(
        include_bytes!("../src/agents/mail/skills/send-draft.md"),
        "send-draft.md",
        "send-draft",
        &mail_exec_agent(),
    )
    .unwrap()
}

fn send_draft_fill(id: i64, arguments: Value) -> ValidatedFill {
    let value = json!({
        "slots": { "draft_id": id.to_string() },
        "calls": [{ "tool": "mail_send", "arguments": arguments }]
    });
    validate_fill(&send_draft_skill(), &value, &mail_exec_context(), None).unwrap()
}

fn draft_store() -> (tempfile::TempDir, Arc<Mutex<Store>>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("store.db")).unwrap();
    (dir, Arc::new(Mutex::new(store)))
}

fn insert_draft(store: &Arc<Mutex<Store>>, body: &str) -> i64 {
    let payload = json!({
        "to": ["camille@northwind.example"],
        "to_display": ["Northwind <camille@northwind.example>"],
        "subject": "Late",
        "body": body,
    })
    .to_string();
    store
        .lock()
        .unwrap()
        .log_event_id("mail.draft", &payload)
        .unwrap()
}

fn draft_connector(store: Arc<Mutex<Store>>, mail: Arc<RecordingMail>) -> Arc<dyn SkillConnector> {
    Arc::new(
        MailSkillConnector::new(
            MailToolset::new(mail as Arc<dyn MailApi>, None),
            None,
            "me@example.org",
            open_mode(),
        )
        .with_store(store),
    )
}

fn known_draft() -> Arc<dyn RecipientDirectory> {
    Arc::new(Known(vec!["camille@northwind.example"]))
}

#[tokio::test]
async fn a_saved_draft_raises_the_card_with_its_stored_fields_and_one_mail() {
    let (_dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    let mail = Arc::new(RecordingMail::default());
    let cards = RecordsCards::default();
    let (outcome, _) = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &cards,
    )
    .await;
    assert!(matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    let cards = cards.0.lock().unwrap();
    assert_eq!(cards.len(), 1, "one card");
    let args = &cards[0].calls[0].real_arguments;
    assert_eq!(args["to"], json!(["camille@northwind.example"]));
    assert_eq!(args["subject"], json!("Late"));
    assert_eq!(args["body"], json!("We're late."));
    assert_eq!(mail.sent.lock().unwrap().len(), 1);
    assert_eq!(
        store
            .lock()
            .unwrap()
            .mail_draft_state(id)
            .unwrap()
            .as_deref(),
        Some("sent")
    );
}

#[tokio::test]
async fn sending_without_a_saved_draft_is_refused_before_a_card() {
    let (_dir, store) = draft_store();
    let mail = Arc::new(RecordingMail::default());
    let cards = RecordsCards::default();
    let (outcome, _) = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(99, json!({})),
        draft_connector(store, Arc::clone(&mail)),
        known_draft(),
        &cards,
    )
    .await;
    let RunOutcome::Refused { reason, .. } = &outcome else {
        panic!("not refused: {outcome:?}")
    };
    assert!(reason.contains("no saved draft"), "{reason}");
    assert!(cards.0.lock().unwrap().is_empty(), "no card");
    assert!(mail.sent.lock().unwrap().is_empty(), "no mail");
}

#[tokio::test]
async fn free_form_fields_are_refused_before_a_card() {
    let (_dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    let mail = Arc::new(RecordingMail::default());
    let cards = RecordsCards::default();
    let (outcome, _) = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({"account": "personal"})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &cards,
    )
    .await;
    let RunOutcome::Refused { reason, .. } = &outcome else {
        panic!("not refused: {outcome:?}")
    };
    assert!(reason.contains("only a draft_id"), "{reason}");
    assert!(cards.0.lock().unwrap().is_empty(), "no card");
    assert!(mail.sent.lock().unwrap().is_empty(), "no mail");

    // A slot the skill does not declare is refused by the fill itself.
    let value = json!({
        "slots": { "draft_id": id.to_string(), "to": "x@invented.example" },
        "calls": [{ "tool": "mail_send", "arguments": {} }]
    });
    assert!(validate_fill(&send_draft_skill(), &value, &mail_exec_context(), None).is_err());
}

#[tokio::test]
async fn the_same_draft_sends_once() {
    let (_dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    let mail = Arc::new(RecordingMail::default());
    let cards = RecordsCards::default();
    for _ in 0..2 {
        let _ = run_executor_fill(
            &send_draft_skill(),
            send_draft_fill(id, json!({})),
            draft_connector(Arc::clone(&store), Arc::clone(&mail)),
            known_draft(),
            &cards,
        )
        .await;
    }
    assert_eq!(mail.sent.lock().unwrap().len(), 1, "one mail");
    assert_eq!(
        cards.0.lock().unwrap().len(),
        1,
        "one card: the replay has none"
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .mail_draft_state(id)
            .unwrap()
            .as_deref(),
        Some("sent")
    );
}

/// We pick "approve is refused": an approved payload that no longer matches
/// the stored draft sends nothing.
struct EditCard(Value);
#[async_trait]
impl SkillApprover for EditCard {
    async fn decide(&self, _card: &aux_runtime::executor::ApprovalCard) -> RunDecision {
        RunDecision::edited(vec![Some(self.0.clone())])
    }
}

#[tokio::test]
async fn an_approval_that_changed_the_draft_is_refused() {
    let (_dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    let mail = Arc::new(RecordingMail::default());
    let edited = json!({
        "to": ["camille@northwind.example"], "subject": "Late",
        "body": "A different body.", "draft_id": id,
    });
    let (outcome, _) = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &EditCard(edited),
    )
    .await;
    assert!(!matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert!(mail.sent.lock().unwrap().is_empty(), "nothing was sent");
    assert_eq!(
        store.lock().unwrap().mail_draft_state(id).unwrap(),
        None,
        "released"
    );
}

/// The stored row changes after the card was shown, before the approve: the
/// approve is refused and the claimed row is released.
#[cfg(debug_assertions)]
struct ChangesDraftThenApproves {
    store: Arc<Mutex<Store>>,
    id: i64,
}

#[cfg(debug_assertions)]
#[async_trait]
impl SkillApprover for ChangesDraftThenApproves {
    async fn decide(&self, _card: &aux_runtime::executor::ApprovalCard) -> RunDecision {
        let payload = json!({
            "to": ["camille@northwind.example"],
            "to_display": ["Northwind <camille@northwind.example>"],
            "subject": "Late",
            "body": "The row changed after the card.",
        })
        .to_string();
        self.store
            .lock()
            .unwrap()
            .rewrite_mail_draft_for_test(self.id, &payload)
            .unwrap();
        RunDecision::approved()
    }
}

#[cfg(debug_assertions)]
#[tokio::test]
async fn a_draft_changed_between_the_card_and_the_approve_is_refused() {
    let (_dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    let mail = Arc::new(RecordingMail::default());
    let (outcome, _) = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &ChangesDraftThenApproves {
            store: Arc::clone(&store),
            id,
        },
    )
    .await;
    assert!(!matches!(outcome, RunOutcome::Done { .. }), "{outcome:?}");
    assert!(mail.sent.lock().unwrap().is_empty(), "nothing was sent");
    assert_eq!(
        store.lock().unwrap().mail_draft_state(id).unwrap(),
        None,
        "the claim is released for a retry with the new row"
    );
}

#[tokio::test]
async fn an_error_after_data_marks_the_draft_uncertain_and_blocks_a_retry() {
    let (_dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    let mail = Arc::new(RecordingMail::default());
    *mail.next_error.lock().unwrap() = Some(MailError::Uncertain);
    let cards = RecordsCards::default();
    let first = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &cards,
    )
    .await
    .0;
    let RunOutcome::Failed { error } = &first else {
        panic!("not failed: {first:?}")
    };
    assert!(error.contains(UNCERTAIN_DRAFT), "{error}");
    assert_eq!(
        store
            .lock()
            .unwrap()
            .mail_draft_state(id)
            .unwrap()
            .as_deref(),
        Some("uncertain")
    );
    assert!(mail.sent.lock().unwrap().is_empty(), "nothing was sent");

    // The same row can never be sent again; a fresh draft is the only way.
    let second = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &cards,
    )
    .await
    .0;
    let RunOutcome::Refused { reason, .. } = &second else {
        panic!("not refused: {second:?}")
    };
    assert!(reason.contains(UNCERTAIN_DRAFT), "{reason}");
    assert_eq!(cards.0.lock().unwrap().len(), 1, "the retry has no card");
}

#[tokio::test]
async fn a_restart_marks_a_claimed_draft_uncertain() {
    let (dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    store.lock().unwrap().claim_mail_draft(id).unwrap().unwrap();
    drop(store);

    // The daemon opens the store again and adopts the dead claim before it
    // serves a turn; this is `main`'s startup call.
    let reopened = Store::open(&dir.path().join("store.db")).unwrap();
    assert_eq!(
        reopened.mail_draft_state(id).unwrap().as_deref(),
        Some("claimed")
    );
    reopened.recover_mail_draft_claims().unwrap();
    assert_eq!(
        reopened.mail_draft_state(id).unwrap().as_deref(),
        Some("uncertain")
    );
    assert!(reopened.mail_draft_for_send(id).unwrap().is_none());
}

#[tokio::test]
async fn a_failed_send_leaves_the_draft_retryable() {
    let (_dir, store) = draft_store();
    let id = insert_draft(&store, "We're late.");
    let mail = Arc::new(RecordingMail::default());
    *mail.next_error.lock().unwrap() = Some(MailError::Connect {
        host: "smtp.example".to_string(),
        port: 465,
    });
    let cards = RecordsCards::default();
    let failed = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &cards,
    )
    .await
    .0;
    assert!(!matches!(failed, RunOutcome::Done { .. }), "{failed:?}");
    assert_eq!(
        store.lock().unwrap().mail_draft_state(id).unwrap(),
        None,
        "released"
    );
    let done = run_executor_fill(
        &send_draft_skill(),
        send_draft_fill(id, json!({})),
        draft_connector(Arc::clone(&store), Arc::clone(&mail)),
        known_draft(),
        &cards,
    )
    .await
    .0;
    assert!(matches!(done, RunOutcome::Done { .. }), "{done:?}");
    assert_eq!(mail.sent.lock().unwrap().len(), 1, "one mail on the retry");
}

// SEND-IT-FOLLOWUP: drive the real chat/skill/approval path with a scripted
// brain and an offline mailbox. The first assistant response represents the
// draft shown in chat; the second calls the shipped follow-up send skill.
mod followup_owner_history {
    use super::*;
    use aux_engine::{ChatSession, ChatSetup};
    use aux_providers::{ChatMessage, ChatResponse, FakeProvider, ToolCall};
    use aux_store::StoreHandle;
    use kernel_broker::ToolRegistry;
    use kernel_core::{
        budget::{Budgets, PriceTable},
        ContextConfig,
    };
    use kernel_privacy::ContactIndex;
    use std::sync::RwLock;

    const NAME: &str = "Ana Ferreira";
    const ADDRESS: &str = "ana.ferreira@example.test";
    const AGENT: &str = "---\nname: assistant\nbrain: cloud\ndefault_mode: open\nchannels: [mac]\ntools:\n  - mail.send\nrecipients:\n  policy: known-contacts\n  allowlist: []\n---\nMail assistant.\n";

    #[derive(Default)]
    struct Cards(Mutex<Vec<ApprovalRequest>>);
    #[async_trait]
    impl Approver for Cards {
        async fn approve(&self, request: &ApprovalRequest) -> Result<bool, ApproverError> {
            self.0.lock().unwrap().push(request.clone());
            Ok(false) // Observe the card without sending mail.
        }
    }

    async fn scenario(
        first: &str,
        assistant: &str,
        extra: &[(&str, &str, Option<&str>)],
        other_thread: bool,
        private: bool,
    ) -> Vec<ApprovalRequest> {
        scenario_with(first, assistant, extra, other_thread, private, "send it").await
    }

    async fn scenario_with(
        first: &str,
        assistant: &str,
        extra: &[(&str, &str, Option<&str>)],
        other_thread: bool,
        private: bool,
        follow_up: &str,
    ) -> Vec<ApprovalRequest> {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let agent = home.join("agents/assistant");
        std::fs::create_dir_all(agent.join("skills")).unwrap();
        std::fs::write(agent.join("agent.md"), AGENT).unwrap();
        std::fs::write(
            agent.join("skills/follow-up.md"),
            include_str!("../src/agents/mail/skills/follow-up.md"),
        )
        .unwrap();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let mail = Arc::new(RecordingMail::default());
        let mail_tools = MailToolset::new(mail.clone(), None);
        let mut registry = ToolRegistry::with_defaults();
        for tool in mail_tools.tools() {
            registry.register_native(tool);
        }
        let registry = Arc::new(RwLock::new(registry));
        let mut index = ContactIndex::new();
        index.add_from_header(NAME, ADDRESS).unwrap();
        let contacts = Arc::new(index);
        let cards = Arc::new(Cards::default());
        let budgets = Budgets::default();
        let prices = PriceTable::default();
        let make_session = |provider, session_id| {
            ChatSession::start(ChatSetup {
                mode: if private { private_mode() } else { open_mode() },
                contacts: contacts.clone(),
                store: StoreHandle::Shared(store.clone()),
                provider,
                registry: registry.clone(),
                rules: vec![],
                approver: cards.clone(),
                agent: "assistant".into(),
                home: home.clone(),
                skills: vec![],
                budgets: &budgets,
                prices: &prices,
                context: ContextConfig::default(),
                title: None,
                stop: None,
                cancel: None,
                session_id,
                events: None,
                run_id: None,
            })
            .unwrap()
            .with_skill_connector(Arc::new(MailSkillConnector::new(
                MailToolset::new(mail.clone(), None),
                None,
                "owner@example.test",
                open_mode(),
            )))
            .with_skill_recipients(contacts.clone())
        };

        let first_brain = FakeProvider::scripted("fake", vec![ChatResponse::assistant(assistant)]);
        let mut first_session = make_session(&first_brain, None);
        let first_id = first_session.session().id;
        first_session.send(first).await.unwrap();
        drop(first_session);
        for (role, content, meta) in extra {
            store
                .lock()
                .unwrap()
                .append_message(first_id, role, content, *meta)
                .unwrap();
        }
        let send_id = if other_thread {
            store
                .lock()
                .unwrap()
                .create_session("assistant", None)
                .unwrap()
                .id
        } else {
            first_id
        };
        let send_brain = FakeProvider::scripted(
            "fake",
            vec![
                ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                    "",
                    vec![ToolCall::new(
                        "send",
                        "skill__follow-up",
                        json!({"slots": {"person": if private { ADDRESS } else { NAME }, "topic": "the quote"},
                "calls": [{"tool": "mail_send", "arguments": {"to": [], "subject": "Re: Quote", "body": "Thank you."}}]}),
                    )],
                )),
                ChatResponse::assistant("Done."),
            ],
        );
        let mut sending = make_session(&send_brain, Some(send_id));
        sending.send(follow_up).await.unwrap();
        drop(sending);
        assert!(mail.sent.lock().unwrap().is_empty());
        let result = cards.0.lock().unwrap().clone();
        if result.is_empty() {
            let messages = store.lock().unwrap().list_messages(send_id).unwrap();
            assert!(
                messages
                    .iter()
                    .any(|m| m.role == "tool"
                        && m.content.contains("contact recipient does not match")),
                "{messages:?}"
            );
        }
        result
    }

    #[tokio::test]
    async fn owner_named_recipient_in_previous_turn_reaches_send_card() {
        let cards = scenario(
            "draft a reply to Ana Ferreira about the quote",
            "Draft: thank you for the quote.",
            &[],
            false,
            false,
        )
        .await;
        assert_eq!(cards.len(), 1, "{cards:?}");
        assert_eq!(cards[0].tool, "skill__follow-up");
        assert_eq!(
            cards[0].arguments["calls"][0]["real"]["to"],
            json!([ADDRESS])
        );
    }

    #[tokio::test]
    async fn a_french_follow_up_after_a_named_draft_reaches_send_card() {
        let cards = scenario_with(
            "prépare une réponse à Ana Ferreira pour le devis",
            "Brouillon prêt.",
            &[],
            false,
            false,
            "Envoie-le !",
        )
        .await;
        assert_eq!(cards.len(), 1, "{cards:?}");
        assert_eq!(
            cards[0].arguments["calls"][0]["real"]["to"],
            json!([ADDRESS])
        );
    }

    #[tokio::test]
    async fn a_longer_follow_up_is_a_new_ask_and_is_refused() {
        let cards = scenario_with(
            "draft a reply to Ana Ferreira about the quote",
            "Draft ready.",
            &[],
            false,
            false,
            "send it to the usual person",
        )
        .await;
        assert!(cards.is_empty(), "{cards:?}");
    }

    /// Review round #509 P2: a labelled row right before "send it" stops the
    /// look-back instead of being skipped for an older owner row.
    #[tokio::test]
    async fn a_labelled_last_row_never_binds_send_it() {
        let cards = scenario(
            "draft a reply to Ana Ferreira about the quote",
            "Draft ready.",
            &[(
                "user",
                "check the quote",
                Some("{\"source\":\"delegation\"}"),
            )],
            false,
            false,
        )
        .await;
        assert!(cards.is_empty(), "{cards:?}");
    }

    #[tokio::test]
    async fn recipient_only_in_untrusted_mail_result_is_refused() {
        let cards = scenario(
            "draft a reply about the quote",
            "Draft ready.",
            &[(
                "tool",
                "From: Ana Ferreira <ana.ferreira@example.test>",
                Some("{\"tool\":\"mail_read\"}"),
            )],
            false,
            false,
        )
        .await;
        assert!(cards.is_empty(), "{cards:?}");
    }

    #[tokio::test]
    async fn recipient_only_in_assistant_message_is_refused() {
        let cards = scenario(
            "draft a reply about the quote",
            "Draft to Ana Ferreira <ana.ferreira@example.test>.",
            &[],
            false,
            false,
        )
        .await;
        assert!(cards.is_empty(), "{cards:?}");
    }

    #[tokio::test]
    async fn private_owner_address_is_restored_locally_for_the_card() {
        let cards = scenario(
            "draft a reply to ana.ferreira@example.test about the quote",
            "Draft ready.",
            &[],
            false,
            true,
        )
        .await;
        assert_eq!(cards.len(), 1, "{cards:?}");
        assert_eq!(
            cards[0].arguments["calls"][0]["real"]["to"],
            json!([ADDRESS])
        );
    }

    #[tokio::test]
    async fn recipient_only_in_delegated_user_turn_is_refused() {
        let cards = scenario(
            "draft a reply about the quote",
            "Draft ready.",
            &[(
                "user",
                "send to Ana Ferreira",
                Some("{\"source\":\"delegation\"}"),
            )],
            false,
            false,
        )
        .await;
        assert!(cards.is_empty(), "{cards:?}");
    }

    #[tokio::test]
    async fn recipient_outside_recent_owner_turns_or_in_another_thread_is_refused() {
        let extra = [("user", "another topic", None)];
        let cards = scenario(
            "draft a reply to Ana Ferreira about the quote",
            "Draft ready.",
            &extra,
            false,
            false,
        )
        .await;
        assert!(cards.is_empty(), "{cards:?}");
        let cards = scenario(
            "draft a reply to Ana Ferreira about the quote",
            "Draft ready.",
            &[],
            true,
            false,
        )
        .await;
        assert!(cards.is_empty(), "{cards:?}");
    }
}
