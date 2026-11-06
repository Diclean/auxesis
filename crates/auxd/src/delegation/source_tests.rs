//! The delegated ask's row says who wrote it. The app
//! matches on that field, never on the ask's words.

use super::*;
use aux_providers::{ChatResponse, FakeProvider};
use kernel_core::privacy::PrivacyMode;

/// A home with a fake brain, like the delegation's own tests.
fn fake_home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    // SANDBOX-GATEWAY-EXEMPT: cfg(test)-only fake-home fixture.
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"aux\"\n\n[[providers]]\n\
         id = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n",
    )
    .unwrap();
    (dir, home)
}

/// Run one delegation and return the ask's row, in the agent's own thread.
async fn delegated_ask(home: PathBuf, task: &str) -> (PathBuf, aux_store::Message) {
    let db = kernel_core::store_path(&home);
    let id = new_id();
    let store = Store::open(&db).unwrap();
    let row = store
        .create_delegation(&id, "aux", "mail", task, None, PrivacyMode::Open)
        .unwrap();
    let run = DelegationRun::open(&row, &home, &db, None, TurnCancel::new()).unwrap();
    let provider = FakeProvider::scripted("b", vec![ChatResponse::assistant("Two requests.")]);
    let executor = EngineDelegationExecutor::new(home.clone(), Some(Arc::new(provider)), None);
    let _ = executor.execute(run).await;
    let thread = store
        .list_sessions()
        .unwrap()
        .into_iter()
        .find(|session| session.agent == "mail")
        .expect("the delegated agent's thread");
    let ask = store
        .list_messages(thread.id)
        .unwrap()
        .into_iter()
        .find(|message| message.role == "user")
        .expect("the ask's row");
    (home, ask)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delegated_ask_stores_its_source_and_serves_it() {
    let task = "List the quote requests in the inbox.";
    let (home, ask) = delegated_ask(fake_home().1, task).await;
    assert_eq!(ask.content, task, "the row holds the ask");
    let meta: serde_json::Value =
        serde_json::from_str(ask.meta.as_deref().expect("the row has metadata")).unwrap();
    assert_eq!(meta["source"], "delegation", "the row names who wrote it");
    // The API serves the same field, so the app never matches on the words.
    let json =
        serde_json::to_value(crate::api::snapshot::message_json_scrubbed(&home, &ask)).unwrap();
    assert_eq!(json["source"], "delegation");
    assert_eq!(json["role"], "user", "the role never changes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owners_own_words_carry_no_source() {
    let (home, ask) = delegated_ask(fake_home().1, "Read the newest mail.").await;
    let owner = aux_store::Message {
        id: ask.id + 1000,
        session_id: ask.session_id,
        role: "user".to_string(),
        content: "And the weather?".to_string(),
        created_at: ask.created_at.clone(),
        meta: None,
    };
    let json =
        serde_json::to_value(crate::api::snapshot::message_json_scrubbed(&home, &owner)).unwrap();
    assert!(
        json["source"].is_null(),
        "an owner's row names no source: {json}"
    );
}

#[derive(Default)]
struct FakeMail(std::sync::Mutex<Vec<aux_mail::OutgoingMail>>);

#[async_trait]
impl aux_mail::MailApi for FakeMail {
    async fn list(
        &self,
        _: &str,
        _: &aux_mail::ListQuery,
    ) -> Result<Vec<aux_mail::EnvelopeItem>, aux_mail::MailError> {
        Ok(Vec::new())
    }
    async fn search(
        &self,
        _: &str,
        _: &aux_mail::SearchQuery,
    ) -> Result<Vec<aux_mail::EnvelopeItem>, aux_mail::MailError> {
        Ok(Vec::new())
    }
    async fn thread(
        &self,
        _: &str,
        _: &str,
        _: usize,
    ) -> Result<Vec<aux_mail::EnvelopeItem>, aux_mail::MailError> {
        Ok(Vec::new())
    }
    async fn read(
        &self,
        _: &str,
        _: u32,
        _: &str,
        _: usize,
    ) -> Result<aux_mail::MailItem, aux_mail::MailError> {
        Err(aux_mail::MailError::Protocol)
    }
    async fn fetch_attachments(
        &self,
        _: &str,
        _: &str,
        _: u32,
    ) -> Result<aux_mail::FetchedAttachments, aux_mail::MailError> {
        Err(aux_mail::MailError::Protocol)
    }
    async fn send(
        &self,
        _: &str,
        mail: &aux_mail::OutgoingMail,
    ) -> Result<aux_mail::SendOutcome, aux_mail::MailError> {
        self.0.lock().unwrap().push(mail.clone());
        Ok(aux_mail::SendOutcome {
            accepted: mail.to.len(),
            bytes: 0,
            reply_class: "2xx",
        })
    }
    fn account_ids(&self) -> Vec<String> {
        vec!["personal".into()]
    }
    fn limits(&self) -> &aux_mail::Limits {
        static LIMITS: std::sync::LazyLock<aux_mail::Limits> =
            std::sync::LazyLock::new(aux_mail::Limits::default);
        &LIMITS
    }
}

fn tool_call(name: &str, arguments: serde_json::Value) -> ChatResponse {
    ChatResponse::new(aux_providers::ChatMessage::assistant_with_tool_calls(
        "",
        vec![aux_providers::ToolCall::new("call-1", name, arguments)],
    ))
}

// Runs the real chief -> DelegateTool -> EngineDelegationExecutor -> Mail
// skill path, or a resumed delegation which has no live owner turn.
async fn contact_delegation(
    owner: Option<&str>,
    scheduled: bool,
) -> (Vec<serde_json::Value>, String) {
    let (_dir, home) = fake_home();
    std::fs::write(kernel_core::config_path(&home),
        "version = 1\nprivacy.mode = \"open\"\ndefault_agent = \"aux\"\n\n[[providers]]\nid = \"fakey\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\nkind = \"fake\"\n\n[connectors.mail]\n\n[[connectors.mail.accounts]]\nid = \"personal\"\nemail = \"owner@example.invalid\"\n\n[connectors.mail.accounts.imap]\nhost = \"127.0.0.1\"\nport = 9\nsecurity = \"tls\"\n").unwrap();
    let mail_dir = aux_engine::agent_dir(&home, "mail");
    std::fs::create_dir_all(&mail_dir).unwrap();
    std::fs::write(mail_dir.join("soul.md"), "Mail.\n").unwrap();
    crate::agents::install_shipped_files(&home).unwrap();
    let db = kernel_core::store_path(&home);
    let store = Store::open(&db).unwrap();
    store
        .replace_contacts(&[aux_store::ContactRecord {
            source: "file:test.vcf".into(),
            display_name: Some("Ana Ferreira".into()),
            given: vec!["Ana".into()],
            family: vec!["Ferreira".into()],
            emails: vec!["ana@fiction.example".into()],
            ..Default::default()
        }])
        .unwrap();
    let task = "Reply to Ana Ferreira about the quote.";
    let mut script = Vec::new();
    if owner.is_some() {
        script.push(tool_call(
            "delegate",
            serde_json::json!({"agent": "mail", "task": task}),
        ));
    }
    script.push(tool_call(
        "skill__follow-up",
        serde_json::json!({
            "slots": {"person": "Ana Ferreira", "topic": "the quote"},
            "calls": [{"tool": "mail_send", "arguments": {
                "to": ["other@fiction.example"], "subject": "Quote", "body": "Thank you."
            }}]
        }),
    ));
    script.push(ChatResponse::assistant("Done."));
    if owner.is_some() {
        script.push(ChatResponse::assistant("Done."));
    }
    let provider = Arc::new(FakeProvider::scripted("fake", script));
    let approvals = crate::api::ApprovalRegistry::new(Duration::from_secs(10));
    let (events, mut frames) = broadcast::channel(1024);
    let mail = Arc::new(FakeMail::default());
    let mut executor = EngineDelegationExecutor::new(
        home.clone(),
        Some(provider.clone()),
        Some(approvals.clone()),
    );
    executor.mail = Some(mail.clone());
    let executor = Arc::new(executor);
    let work = if let Some(owner) = owner {
        let mut runner = EngineTurnRunner::new(&home)
            .with_provider(provider.clone())
            .with_approvals(approvals.clone())
            .with_events(events.clone())
            .with_delegations(executor, Arc::default());
        if scheduled {
            runner = runner.with_source("schedule");
        }
        let owner = owner.to_string();
        tokio::task::spawn_blocking(move || {
            runner.run_turn("aux", None, &owner, None).unwrap();
        })
    } else {
        let id = new_id();
        let row = store
            .create_delegation(&id, "aux", "mail", task, None, PrivacyMode::Open)
            .unwrap();
        let run =
            DelegationRun::open(&row, &home, &db, Some(events.clone()), TurnCancel::new()).unwrap();
        tokio::spawn(async move {
            executor.execute(run).await.unwrap();
        })
    };
    tokio::pin!(work);
    let mut cards = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                biased;
                frame = frames.recv() => {
                    let value: serde_json::Value = serde_json::from_str(&frame.unwrap()).unwrap();
                    if value["type"] == "approval.new" {
                        let id = value["approval"]["id"].as_str().unwrap();
                        approvals.resolve(id, crate::api::Resolution::deny());
                        cards.push(value);
                    }
                }
                result = &mut work => { result.unwrap(); break; }
            }
        }
    })
    .await
    .expect("delegation did not finish");
    assert!(
        mail.0.lock().unwrap().is_empty(),
        "no send without approval"
    );
    let requests = provider.requests();
    for request in &requests {
        if request
            .tools
            .iter()
            .any(|tool| tool.name().as_str() == "skill__follow-up")
        {
            assert!(
                !request
                    .messages
                    .iter()
                    .any(|message| message.content().as_str().contains("owner-only-marker")),
                "the owner's extra words must not reach the delegate's model"
            );
        }
    }
    let text = requests
        .iter()
        .flat_map(|r| r.messages.iter())
        .filter(|m| m.role() == aux_providers::ChatRole::Tool)
        .map(|m| m.content().as_str().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    (cards, text)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegated_contact_send_requires_the_chief_turns_owner_words() {
    let (cards, _) = contact_delegation(
        Some("ask Mail to reply to Ana Ferreira about the quote; owner-only-marker"),
        false,
    )
    .await;
    assert_eq!(cards.len(), 1, "the owner named Ana: {cards:?}");
    assert!(
        cards[0].to_string().contains("ana@fiction.example"),
        "the card addresses Ana: {cards:?}"
    );

    let (cards, result) =
        contact_delegation(Some("ask Mail to reply about the quote"), false).await;
    assert!(
        cards.is_empty(),
        "a model-named recipient must not produce a card: {cards:?}"
    );
    assert!(
        result.contains("contact recipient does not match the owner's message"),
        "{result}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumed_delegation_has_no_owner_words_and_refuses_contact_send() {
    let (cards, result) = contact_delegation(None, false).await;
    assert!(
        cards.is_empty(),
        "an ownerless delegation must not produce a card: {cards:?}"
    );
    assert!(
        result.contains("contact recipient must be selected in the owner's message"),
        "{result}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scheduled_caller_cannot_lend_its_prompt_as_owner_words() {
    let (cards, result) = contact_delegation(
        Some("ask Mail to reply to Ana Ferreira about the quote"),
        true,
    )
    .await;
    assert!(
        cards.is_empty(),
        "scheduled text is not owner input: {cards:?}"
    );
    assert!(
        result.contains("contact recipient must be selected in the owner's message"),
        "{result}"
    );
}
