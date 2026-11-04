//! `collect-receipts` runs through the daemon's skill dispatch.
//!
//! The fake provider forces the skill once; the daemon's own
//! [`attach_skill_runtime`] hands the executor the `docs.ingest` connector, and
//! the deterministic collector writes the evidence registry. No model is asked
//! to read a document, and the fake mail API is the only mailbox.
//!
//! The end-to-end acceptance: the fictional demo mailbox
//! (the receipt for VF-2210 with its PDF) → the collect → the Documents list.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, RwLock};

use async_trait::async_trait;
use aux_engine::{ChatSession, ChatSetup};
use aux_mail::{
    DownloadedAttachment, EnvelopeItem, FetchedAttachments, Limits, ListQuery, MailApi, MailError,
    MailItem, SearchQuery, SkippedAttachment,
};
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use aux_runtime::executor::{SkillConnector, SkillContext};
use aux_store::{Store, StoreHandle};
use auxd::skill_executor::{attach_skill_runtime, DocsSkillConnector};
use kernel_broker::{ApprovalRequest, Approver, ApproverError, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::PrivacyMode;
use kernel_core::ContextConfig;
use kernel_privacy::ContactIndex;
use serde_json::json;
use tempfile::tempdir;

const PDF_BYTES: &[u8] = b"%PDF-1.4 docs daemon fixture\r\n";
const PDF_SHA256: &str = "931c581e12b5952e4fa3e4ac6dd4507c138c9bc23a99a37fb8c090b4475f2c90";
/// The second mailbox's receipt: its own bytes, so the two are two documents.
const WORK_PDF_BYTES: &[u8] = b"%PDF-1.4 docs daemon work receipt\r\n";
const WORK_PDF_SHA256: &str = "11623cd83d077da47139a8a09c372279447c4170024c9ac29399283f321bbe81";

const AGENT: &str = "---
name: assistant
brain: cloud
default_mode: open
channels: [mac]
tools:
  - mail.fetch_attachments
  - docs.ingest
recipients:
  policy: known-contacts
  allowlist: []
---
Docs dispatch assistant.
";

/// The Phase 0 loadable form of the skill: no `on:` trigger here.
const COLLECT_RECEIPTS: &str = "---
name: collect-receipts
version: 1
command: collect-receipts
brain: none
trigger:
  manual: true
tools: [docs.ingest]
recipients:
  policy: known-contacts
approval: each_run
on_failure: stop
---
Collect the local receipts.
";

/// One message with one allowed PDF and one refused ZIP.
struct CollectMail;

#[async_trait]
impl MailApi for CollectMail {
    async fn list(&self, _: &str, _: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
        Ok(vec![EnvelopeItem {
            uid: 1,
            message_id: "<docs@northwind.test>".to_string(),
            subject: "Receipt".to_string(),
            from: "Northwind Studio <billing@northwind.test>".to_string(),
            to: Vec::new(),
            cc: Vec::new(),
            date: "Mon, 6 Oct 2025 09:00:00 +0000".to_string(),
            size: 128,
            unread: true,
            in_reply_to: None,
        }])
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
        account: &str,
        _: &str,
        _: u32,
    ) -> Result<FetchedAttachments, MailError> {
        // One receipt per mailbox, so a collect that names no account files
        // both of them.
        let (bytes, sha256) = if account == "work" {
            (WORK_PDF_BYTES, WORK_PDF_SHA256)
        } else {
            (PDF_BYTES, PDF_SHA256)
        };
        Ok(FetchedAttachments {
            message_id: format!("<{account}@northwind.test>"),
            downloaded: vec![DownloadedAttachment {
                part: "2".to_string(),
                file_name: format!("invoice-{account}.pdf"),
                mime: "application/pdf".to_string(),
                size: bytes.len(),
                sha256: sha256.to_string(),
                bytes: bytes.to_vec(),
            }],
            skipped: vec![SkippedAttachment {
                part: "3".to_string(),
                file_name: "archive.zip".to_string(),
                mime: "application/zip".to_string(),
                reason: "mime type not allowed: application/zip".to_string(),
            }],
        })
    }

    async fn send(
        &self,
        _: &str,
        _: &aux_mail::OutgoingMail,
    ) -> Result<aux_mail::SendOutcome, MailError> {
        Err(MailError::Protocol)
    }

    fn account_ids(&self) -> Vec<String> {
        vec!["personal".to_string(), "work".to_string()]
    }

    fn limits(&self) -> &Limits {
        static LIMITS: std::sync::LazyLock<Limits> = std::sync::LazyLock::new(Limits::default);
        std::sync::LazyLock::force(&LIMITS)
    }
}

/// The fake provider: fill `collect-receipts` once, then answer in text.
struct DocsProvider {
    seen: StdMutex<Vec<String>>,
    offered: StdMutex<Vec<Vec<String>>>,
}

#[async_trait]
impl ChatProvider for DocsProvider {
    async fn complete(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        self.seen.lock().unwrap().extend(
            request
                .messages
                .iter()
                .map(|message| message.content().as_str().to_string()),
        );
        self.offered.lock().unwrap().push(
            request
                .tools
                .iter()
                .map(|tool| tool.name().as_str().to_string())
                .collect(),
        );
        if self.offered.lock().unwrap().len() == 1 {
            // The fill names no account: the model is never told the slug, and
            // the collector reads the only configured mailbox.
            let arguments = json!({
                "slots": {},
                "calls": [{
                    "tool": "docs_ingest",
                    "arguments": { "folder": "INBOX", "days": 30 },
                }],
            });
            return Ok(ChatResponse::new(ChatMessage::assistant_with_tool_calls(
                "",
                vec![ToolCall::new(
                    "call-1",
                    "skill__collect-receipts",
                    arguments,
                )],
            )));
        }
        Ok(ChatResponse::assistant("Reçus collectés."))
    }

    fn name(&self) -> &str {
        "docs-fake"
    }
}

/// The owner's approval channel answers `allow`.
struct AllowApprover;

#[async_trait]
impl Approver for AllowApprover {
    async fn approve(&self, _: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }
}

fn count(home: &std::path::Path, table: &str) -> i64 {
    let conn = aux_store::open_keyed_readonly(&kernel_core::store_path(home)).unwrap();
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

#[tokio::test]
async fn collect_receipts_dispatches_docs_ingest_and_writes_the_registry() {
    let dir = tempdir().unwrap();
    let home: PathBuf = dir.path().join("home");
    let agent_dir = home.join("agents").join("assistant");
    std::fs::create_dir_all(agent_dir.join("skills")).unwrap();
    std::fs::write(agent_dir.join("agent.md"), AGENT).unwrap();
    std::fs::write(
        agent_dir.join("skills").join("collect-receipts.md"),
        COLLECT_RECEIPTS,
    )
    .unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let store = Arc::new(StdMutex::new(
        Store::open(&kernel_core::store_path(&home)).unwrap(),
    ));

    let provider = DocsProvider {
        seen: StdMutex::new(Vec::new()),
        offered: StdMutex::new(Vec::new()),
    };
    let budgets = Budgets::default();
    let prices = PriceTable::default();
    let contacts = Arc::new(ContactIndex::new());
    let mode: kernel_core::privacy::ModeFn = Arc::new(|| PrivacyMode::Open);
    let session = ChatSession::start(ChatSetup {
        mode,
        contacts: Arc::clone(&contacts),
        store: StoreHandle::Shared(Arc::clone(&store)),
        provider: &provider,
        registry: Arc::new(RwLock::new(ToolRegistry::with_defaults())),
        rules: Vec::new(),
        approver: Arc::new(AllowApprover),
        agent: "assistant".to_string(),
        home: home.clone(),
        skills: Vec::new(),
        budgets: &budgets,
        prices: &prices,
        context: ContextConfig::default(),
        title: None,
        stop: None,
        cancel: None,
        session_id: None,
        events: None,
        run_id: Some("docs-run".to_string()),
    })
    .unwrap();
    let docs = DocsSkillConnector::new(home.clone(), Arc::clone(&store), Arc::new(CollectMail));
    let mut session = attach_skill_runtime(
        session,
        auxd::skill_executor::SkillConnectors {
            docs: Some(docs),
            ..Default::default()
        },
        "assistant",
        workspace,
        Some("docs-run".to_string()),
        contacts,
    );

    let outcome = session
        .send("/collect-receipts")
        .await
        .expect("the collect-receipts turn completes");
    drop(session);
    assert_eq!(outcome.text, "Reçus collectés.");

    // The forced command offered exactly the one skill tool.
    let offered = provider.offered.lock().unwrap().clone();
    assert_eq!(offered[0], vec!["skill__collect-receipts".to_string()]);

    // The connector ran the real registry write, over both mailboxes: a
    // collect that names no account reads every configured one.
    assert_eq!(count(&home, "documents"), 2, "one document per mailbox");
    assert_eq!(count(&home, "evidence_source"), 2, "one source per mailbox");
    assert_eq!(open_blob(&home, PDF_SHA256), PDF_BYTES);
    assert_eq!(open_blob(&home, WORK_PDF_SHA256), WORK_PDF_BYTES);
    assert_eq!(document_mailboxes(&home), ["personal", "work"]);

    // The dispatch left one skill.action Ledger row for `docs_ingest`.
    let actions = store
        .lock()
        .unwrap()
        .event_payloads("skill.action")
        .unwrap()
        .iter()
        .map(|payload| serde_json::from_str::<serde_json::Value>(payload).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 1, "one action row: {actions:?}");
    assert_eq!(actions[0]["tool"], "docs_ingest", "{actions:?}");
    assert_eq!(actions[0]["outcome"], "ok", "{actions:?}");

    // The report reaches the conversation; the skipped zip carries its reason.
    let seen = provider.seen.lock().unwrap().join("\n");
    assert!(seen.contains("\"new\":2"), "the counts reach the model");
    assert!(
        seen.contains("application/zip"),
        "the skip reason is reported"
    );
}

/// The mailbox every filed document came from, in the order they were filed.
fn document_mailboxes(home: &std::path::Path) -> Vec<String> {
    let conn = aux_store::open_keyed_readonly(&kernel_core::store_path(home)).unwrap();
    let mut stmt = conn
        .prepare("SELECT account_id FROM documents ORDER BY id")
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// The original bytes of a sealed evidence blob, opened as the registry does.
fn open_blob(home: &std::path::Path, sha256: &str) -> Vec<u8> {
    let key = aux_store::evidence_key(home).unwrap();
    let raw = std::fs::read(home.join("evidence").join(sha256)).unwrap();
    aux_store::open_evidence(&key, sha256, &raw).expect("the blob opens")
}

/// A fresh home, as the daemon starts it: the shipped files are in, the
/// only configured model is unreachable (`providers.toml` when `providers`).
fn owner_home(mode: &str, providers: bool) -> (tempfile::TempDir, PathBuf) {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n"),
    )
    .unwrap();
    if providers {
        std::fs::write(
            home.join("providers.toml"),
            "[[provider]]\nid = \"primary\"\nkind = \"openai\"\nbase_url = \"http://127.0.0.1:9/v1\"\n\
             models = [\"m\"]\n\n[brain]\ndefault = \"primary/m\"\n",
        )
        .unwrap();
    }
    auxd::agents::install_shipped_files(&home).unwrap();
    (dir, home)
}

/// One chat `/collect-receipts` with the Documents agent; the reply and
/// whether an approval card was ever raised.
fn chat_collect(home: &std::path::Path, mail: bool) -> (String, bool) {
    use auxd::api::{ApprovalRegistry, EngineTurnRunner, TurnRunner};
    let approvals = ApprovalRegistry::new(std::time::Duration::from_secs(2));
    let (events, _) = tokio::sync::broadcast::channel(64);
    let mut runner = EngineTurnRunner::new(home)
        .with_events(events)
        .with_approvals(Arc::clone(&approvals));
    if mail {
        runner = runner.with_mail(Arc::new(CollectMail));
    }
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watch = {
        let (approvals, done) = (Arc::clone(&approvals), Arc::clone(&done));
        std::thread::spawn(move || {
            let mut seen = false;
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                seen |= !approvals.list_pending().is_empty();
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            seen
        })
    };
    let record = runner.run_turn("documents", None, "/collect-receipts", None);
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let carded = watch.join().unwrap();
    let record = record.expect("the collect turn completes with no model");
    let reply = record
        .messages
        .iter()
        .rev()
        .find(|message| message.role == "assistant")
        .map(|message| message.content.clone())
        .unwrap_or_default();
    (reply, carded)
}

fn run_outcomes(home: &std::path::Path) -> Vec<String> {
    let store = Store::open(&kernel_core::store_path(home)).unwrap();
    assert!(store.event_payloads("skill.approval").unwrap().is_empty());
    store
        .event_payloads("skill.run")
        .unwrap()
        .iter()
        .map(|payload| serde_json::from_str::<serde_json::Value>(payload).unwrap())
        .map(|row| format!("{}:{}", row["agent"], row["outcome"]).replace('"', ""))
        .collect()
}

#[test]
fn owner_collects_receipts_from_chat_with_no_model_and_no_card() {
    for mode in ["open", "private"] {
        let (_dir, home) = owner_home(mode, true);
        let (first, carded) = chat_collect(&home, true);
        assert!(!carded, "{mode}: a local collect raises no card");
        assert!(first.contains("2 new"), "{mode}: {first}");
        let (second, carded) = chat_collect(&home, true);
        assert!(!carded, "{mode}");
        assert!(
            second.contains("0 new, 2 already stored"),
            "{mode}: {second}"
        );
        assert_eq!(count(&home, "documents"), 2, "{mode}: no duplicate");
        assert_eq!(
            run_outcomes(&home),
            ["documents:done", "documents:done"],
            "{mode}: each run is in the ledger"
        );
    }
}

#[test]
fn with_no_mailbox_and_no_model_the_collect_says_so_and_chat_still_needs_one() {
    let (_dir, home) = owner_home("open", false);
    let (reply, carded) = chat_collect(&home, false);
    assert!(!carded);
    assert!(reply.contains("No mailbox is configured"), "{reply}");
    assert_eq!(count(&home, "documents"), 0);
    use auxd::api::{EngineTurnRunner, TurnError, TurnRunner};
    let plain = EngineTurnRunner::new(&home).run_turn("documents", None, "hello", None);
    assert!(
        matches!(plain, Err(TurnError::NoProvider { .. })),
        "{plain:?}"
    );
}

/// A receipt with a PDF attachment reaches the Documents list.
///
/// The fictional demo mailbox holds the receipt for invoice VF-2210 with its
/// PDF attachment. The collect runs through the daemon's own `docs.ingest`
/// connector — the path the `collect-receipts` skill takes — with the account
/// the model guessed, and the document lands in the Documents list API.

#[tokio::test(flavor = "multi_thread")]
async fn a_receipt_with_a_pdf_attachment_reaches_the_documents_list() {
    let dir = tempdir().unwrap();
    let home: PathBuf = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    aux_fakemail::write_demo(dir.path(), false).expect("the demo mailbox");
    let server = aux_fakemail::serve(aux_fakemail::SimConfig {
        dir: dir.path().to_path_buf(),
        imap_port: 0,
        smtp_port: 0,
    })
    .await
    .expect("the fake mailbox");
    let ca = server.ca_file.to_string_lossy().into_owned();
    // The mailbox the owner configured, and the service over it.
    let mail = aux_mail::config::MailConfig::from_toml(&format!(
        "[[accounts]]\nid = \"sim\"\nemail = \"owner@mailsim.test\"\n\n\
         [accounts.imap]\nhost = \"127.0.0.1\"\nport = {}\nsecurity = \"tls\"\nca_file = \"{ca}\"\n",
        server.imap_port
    ))
    .unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    let limits = Limits::default();
    let service = aux_mail::MailService::new(
        aux_mail::Dialer::new(limits.connect_timeout),
        limits,
        mail.accounts.clone(),
        Arc::new(aux_fakemail::StaticCredentials::new("sim", "any-password")),
    );
    let store = Arc::new(StdMutex::new(
        Store::open(&kernel_core::store_path(&home)).unwrap(),
    ));
    let docs = DocsSkillConnector::new(home.clone(), Arc::clone(&store), Arc::new(service));
    let context = SkillContext {
        name: "collect-receipts".to_string(),
        version: 1,
        hash: "0".repeat(64),
        tainted: false,
    };

    // The model names an account this Mac does not have: the collect still
    // runs, on the only configured mailbox.
    let report = docs
        .call(
            &context,
            "docs.ingest",
            &json!({"account": "personal", "days": 30}),
        )
        .await
        .expect("the collect runs");
    assert_eq!(report["new"], 1, "the receipt is filed: {report}");
    assert_eq!(report["messages"], 12, "every demo mail is read: {report}");
    assert_eq!(count(&home, "documents"), 1, "one document row");

    // The local API: the document is in the list, and its fields follow the
    // text the Mac bridge posts back.
    let handle = auxd::api::spawn(
        &home,
        auxd::api::ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .expect("the local API");
    let addr = handle.addr();
    let token = std::fs::read_to_string(auxd::api::token_path(&home)).unwrap();
    let token = token.trim().to_string();
    let get = |path: &str| common::http(addr, "GET", path, Some(&token), None);
    let post = |path: &str, body: &str| common::http(addr, "POST", path, Some(&token), Some(body));
    let listed = get("/v1/docs");
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_eq!(listed.json()[0]["status"], "waiting for reading");

    let pending = get("/v1/docs/extract/pending?limit=8");
    let hash = pending.json()[0]["hash"]
        .as_str()
        .expect("a document")
        .to_string();
    let text = json!({
        "extractor": "pdf_text",
        "text": "fictional receipt VF-2210\nInvoice VF-2210\nTotal 120.00 EUR\n"
    })
    .to_string();
    let posted = post(&format!("/v1/docs/{hash}/extraction"), &text);
    assert_eq!(posted.status, 200, "{}", posted.body);

    let listed = get("/v1/docs");
    assert_eq!(listed.status, 200, "{}", listed.body);
    let row = &listed.json()[0];
    assert_eq!(row["number"], "VF-2210", "{row}");
    assert_eq!(row["total"], "120.00 EUR", "{row}");
    assert_eq!(row["status"], "read", "{row}");
    // The local API stops with the test, so no port stays bound.
    handle.shutdown();
}
