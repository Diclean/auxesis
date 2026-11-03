//! DOC-REEXTRACT-1 live acceptance: the owner's receipt question, from the
//! OLD state, in a sandbox.
//!
//! The state is the one the owner was in after #275: the demo mailbox still
//! holds the old receipt attachment (a `%PDF` header followed by plain text),
//! the registry holds that attachment as one `other` document with no fields,
//! and the Documents agent's `collect-receipts` skill is the version shipped
//! before DOC-COLLECT-2. The question is the owner's own: "Find the receipt
//! for invoice VF-2210 and tell me the amount". The answer must name 120.00
//! EUR in one turn, with no approval card: `collect-receipts` is local
//! (`approval: none`), so the agent runs it itself instead of asking. The
//! PDF is read by the Mac's own extractor (PDFKit), through the app's own
//! queue: `qa/acceptance/pdf_bridge.swift` is that half. The same question
//! through the chief (`aux`, which hands the work out) is timed: the owner's
//! own turn took over 280 s.
//!
//! Skips cleanly unless the AUX_HERO_CLOUD_* env is set: source
//! a test key file you provide (see CONTRIBUTING.md), use the sandbox env
//! it gives (`env -i HOME=<tmp> AUXESIS_HOME=<tmp>/.auxesis AUXESIS_SANDBOX=1
//! AUXESIS_API_PORT=0`), then `cargo test -p auxd --test receipt -- --nocapture`.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aux_mail::EvidenceSink;
use aux_store::Store;
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};

/// The question the owner asked, and the agent that owns the documents scope.
const QUESTION: &str = "Find the receipt for invoice VF-2210 and tell me the amount";
const AGENT: &str = "documents";
/// The chief: the agent the owner talks to, which hands the work out.
const CHIEF: &str = "aux";
/// The receipt attachment as the demo mailbox held it before DOC-COLLECT-2: a
/// `%PDF` header followed by plain text, which PDFKit refuses, so the
/// document stayed empty ("other, no total").
const OLD_RECEIPT: &str =
    "%PDF-1.4 fictional receipt VF-2210\r\nInvoice VF-2210\r\nTotal 120.00 EUR\r\n";
/// The SHA-256 of [`OLD_RECEIPT`]: the document the owner's registry held.
const OLD_RECEIPT_SHA256: &str = "852c878830bd40c3293bb6753fe3478c174bdd6e5cc4a2a19bf18f2debf88462";
/// The `collect-receipts` skill as it shipped before DOC-COLLECT-2.
const OLD_SKILL: &str = include_str!("../../crates/auxd/tests/data/collect-receipts-pre-275.md");
/// The skill as it ships now.
const CURRENT_SKILL: &str =
    include_str!("../../crates/aux-runtime/src/skills/fixtures/skills/collect-receipts.md");

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// The Mac's own extractor, headless: it claims one pending document, reads
/// its bytes, extracts the text with PDFKit and posts it back. `None` when
/// this Mac has no `swiftc`: the acceptance skips.
/// The bridge process, killed and reaped when dropped: a failed `expect`
/// mid-turn never leaves its polling loop running.
struct Bridge(Child);

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_pdf_bridge(dir: &TempDir, addr: std::net::SocketAddr, token: &str) -> Option<Child> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../qa/acceptance/pdf_bridge.swift");
    let binary = dir.path().join("pdf_bridge");
    let compiled = Command::new("swiftc")
        .arg("-O")
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .ok()?;
    if !compiled.status.success() {
        eprintln!("SKIP receipt: the PDFKit bridge did not compile");
        return None;
    }
    Command::new(&binary)
        .arg(format!("http://{addr}"))
        // The token never goes on the command line: an argument shows up in
        // the process list.
        .env("AUX_BRIDGE_TOKEN", token)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_asks_for_a_receipt_and_gets_the_amount() {
    let (Some(url), Some(key), Some(model)) = (
        env("AUX_HERO_CLOUD_URL"),
        env("AUX_HERO_CLOUD_KEY"),
        env("AUX_HERO_CLOUD_MODEL"),
    ) else {
        eprintln!(
            "SKIP receipt: set AUX_HERO_CLOUD_URL, AUX_HERO_CLOUD_KEY and AUX_HERO_CLOUD_MODEL"
        );
        return;
    };
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let sim_dir = dir.path().join("sim");
    // The mailbox in the OLD state: the demo's own messages, with the receipt
    // attachment as it shipped before DOC-COLLECT-2.
    aux_fakemail::write_demo(&sim_dir, false).expect("the demo mailbox");
    let mailbox = sim_dir.join("mailbox.json");
    let mut mails: Vec<aux_fakemail::StoredMail> =
        serde_json::from_str(&std::fs::read_to_string(&mailbox).unwrap()).unwrap();
    let receipt = mails
        .iter_mut()
        .find(|mail| mail.uid == 5)
        .expect("the demo receipt");
    receipt.parts[1].1 = OLD_RECEIPT.to_string();
    std::fs::write(&mailbox, serde_json::to_vec_pretty(&mails).unwrap()).unwrap();
    let sim = aux_fakemail::serve(aux_fakemail::SimConfig {
        dir: sim_dir,
        imap_port: 0,
        smtp_port: 0,
    })
    .await
    .expect("the fake mailbox");
    // The demo's own messages are re-seeded: the receipt is the real PDF now.
    let served: Vec<aux_fakemail::StoredMail> =
        serde_json::from_str(&std::fs::read_to_string(&mailbox).unwrap()).unwrap();
    let receipt = served
        .iter()
        .find(|mail| mail.uid == 5)
        .expect("the receipt");
    assert!(
        receipt.parts[1].1.contains("(Total 120.00 EUR) Tj"),
        "the demo receipt is the real PDF now"
    );
    std::fs::write(
        kernel_core::config_path(&home),
        format!(
            "version = 1\ndefault_agent = \"{AGENT}\"\n\n[privacy]\nmode = \"open\"\n\n\
             [connectors.mail]\n\n[[connectors.mail.accounts]]\nid = \"sim\"\n\
             email = \"owner@mailsim.test\"\n\n[connectors.mail.accounts.imap]\n\
             host = \"127.0.0.1\"\nport = {}\nsecurity = \"tls\"\nca_file = \"{}\"\n",
            sim.imap_port,
            sim.ca_file.to_string_lossy()
        ),
    )
    .unwrap();
    // The simulator takes any password.
    std::fs::write(home.join(".env"), "AUX_MAIL_SIM=fictional-password\n").unwrap();
    // The registry in the OLD state: the old attachment, one `other` document
    // with no fields (the sweep gives it its first row, as the daemon does).
    {
        let store = Store::open(&kernel_core::store_path(&home)).expect("the store");
        let sink =
            aux_docs::StoreEvidence::new(&home, std::sync::Arc::new(std::sync::Mutex::new(store)));
        let reference = sink
            .append(aux_mail::EvidenceAttachment {
                sha256: OLD_RECEIPT_SHA256.to_string(),
                file_name: "receipt-VF-2210.pdf".to_string(),
                mime: "application/pdf".to_string(),
                size: OLD_RECEIPT.len(),
                bytes: OLD_RECEIPT.as_bytes().to_vec(),
                account: "sim".to_string(),
                folder: "INBOX".to_string(),
                uid: 5,
                message_id: "<demo-5@mailsim.test>".to_string(),
                part: "2".to_string(),
            })
            .expect("the old attachment is registered");
        assert!(!reference.duplicate);
    }
    {
        let store = Store::open(&kernel_core::store_path(&home)).expect("the store");
        let document_id = store
            .evidence_document_id(OLD_RECEIPT_SHA256)
            .expect("the document")
            .expect("the document");
        store
            .insert_document_fields(&aux_store::NewDocumentFields {
                document_id,
                kind: "other",
                extractor: "none",
                status: "to_check",
                updated_at: "2026-10-27T00:00:00Z",
                extract_state: "done",
                ..Default::default()
            })
            .expect("the empty fields row");
    }
    // The shipped agent files, with the `collect-receipts` skill as it
    // shipped before DOC-COLLECT-2: the owner's copy.
    auxd::agents::install_shipped_files(&home).unwrap();
    let skill = home.join("agents/documents/skills/collect-receipts.md");
    std::fs::write(&skill, OLD_SKILL).unwrap();
    // The chief, as the app writes it: it hands the work out.
    let chief = home.join("agents/aux");
    std::fs::create_dir_all(&chief).unwrap();
    std::fs::write(
        chief.join("agent.md"),
        "---\nname: aux\nbrain: cloud\ndefault_mode: open\nchannels: [mac]\ntools:\n  \
         - delegate\n---\nYou are Aux, the chief. Hand every task to the domain agent \
         that owns it.\n",
    )
    .unwrap();
    // The daemon starts: the old shipped skill is the current one now.
    auxd::agents::install_shipped_files(&home).unwrap();
    assert_eq!(
        std::fs::read_to_string(&skill).unwrap(),
        CURRENT_SKILL,
        "an old shipped file is updated, not kept"
    );

    // The daemon, on an ephemeral port, on the temp home. The hosted brain
    // is built with the key the caller holds: it never reaches a file or a
    // log line.
    Store::open(&kernel_core::store_path(&home)).expect("the store");
    let brain = aux_providers::OpenAiCompat::with_key_and_timeout(
        &aux_providers::ProviderConfig {
            disable_thinking: env("AUX_HERO_CLOUD_DISABLE_THINKING")
                .is_some_and(|value| matches!(value.trim(), "1" | "true")),
            id: "live".to_string(),
            base_url: url,
            model,
            key_user: None,
            kind: aux_providers::ProviderKind::OpenAiCompat,
        },
        Some(key),
        Duration::from_secs(300),
    )
    .expect("the hosted brain");
    let handle = auxd::api::spawn(
        &home,
        auxd::api::ApiOptions {
            port: 0,
            provider: Some(std::sync::Arc::new(brain)),
            // A card, if one were raised, is refused after two seconds.
            approval_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        },
    )
    .expect("the local API");
    let addr = handle.addr();
    let token = std::fs::read_to_string(auxd::api::token_path(&home))
        .expect("the api token")
        .trim()
        .to_string();
    let Some(bridge) = start_pdf_bridge(&dir, addr, &token).map(Bridge) else {
        handle.shutdown();
        return;
    };

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let (reply, seconds) = ask(&client, &base, &token, AGENT).await;
    eprintln!("LIVE reply ({seconds:.1}s): {reply}");

    // A local collect asks nobody: no approval card was raised.
    let store = Store::open(&kernel_core::store_path(&home)).expect("the store");
    assert!(
        store.event_payloads("skill.approval").unwrap().is_empty(),
        "the local collect raised an approval card"
    );
    // The model ran the collect itself, and the collector filed the receipt.
    let actions = store.event_payloads("skill.action").unwrap();
    assert!(
        actions
            .iter()
            .any(|row| row.contains("collect-receipts") && row.contains("\"ok\"")),
        "the agent ran the local collect: {actions:?}"
    );
    // And the answer names the amount the receipt carries.
    assert!(
        reply.contains("120"),
        "the answer names the amount: {reply}"
    );
    assert!(
        reply.contains("EUR") || reply.contains('€'),
        "the answer names the currency: {reply}"
    );

    // The answer names the receipt: the amount came out of the extracted PDF.
    assert!(
        reply.contains("VF-2210"),
        "the answer names the receipt: {reply}"
    );

    // The same question through the chief, which hands the work out: the
    // owner's own turn took over 280 s.
    let (chief, chief_seconds) = ask(&client, &base, &token, CHIEF).await;
    eprintln!("LIVE chief reply ({chief_seconds:.1}s): {chief}");
    assert!(!chief.is_empty(), "the chief answered");
    handle.shutdown();
    // The bridge is killed and reaped here: a failed turn never leaves it
    // running.
    drop(bridge);
}

/// One question, one turn, and the seconds it took.
async fn ask(client: &reqwest::Client, base: &str, token: &str, agent: &str) -> (String, f64) {
    let session: i64 = client
        .post(format!("{base}/v1/threads/{agent}/new"))
        .bearer_auth(token)
        .send()
        .await
        .expect("the thread starts")
        .json::<Value>()
        .await
        .expect("a session")["id"]
        .as_i64()
        .expect("a session id");
    let started = Instant::now();
    let body: Value = client
        .post(format!("{base}/v1/threads/{session}/messages"))
        .bearer_auth(token)
        .json(&json!({ "content": QUESTION }))
        .send()
        .await
        .expect("the turn")
        .json()
        .await
        .expect("the turn body");
    let seconds = started.elapsed().as_secs_f64();
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let reply = messages
        .iter()
        .rev()
        .find(|message| message["role"] == "assistant")
        .and_then(|message| message["content"].as_str())
        .unwrap_or_default()
        .to_string();
    (reply, seconds)
}
