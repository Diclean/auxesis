//! CLOSURE-4: the daemon reads a document that lands in the registry, with no
//! app request and no app process.
//!
//! Before this test, the extractor chain ran only when the Mac app polled
//! `GET /v1/docs/extract/pending` (or the owner opened the Documents page,
//! which runs the same sweep): a document that arrived while the app was
//! closed stayed `[unread]` forever. The real `auxd` binary is spawned in a
//! sandbox home, a canary proves the startup sweep ran, then a UBL invoice
//! lands *after* the daemon is ready and the test only reads the store back.
//! Nothing here calls the API, so a passing test can only mean a later tick
//! of the daemon's own sweep read it.
//!
//! No network, no Keychain, no real home: an ephemeral API port and a fake
//! provider are enough.

mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use aux_store::{NewEvidenceDocument, Store};
use common::KillOnDrop;
use kernel_core::{config_path, store_path};

const CONFIG: &str = r#"
version = 1
default_agent = "main"

[privacy]
mode = "open"

[[providers]]
id = "fakey"
base_url = "http://127.0.0.1:9/v1"
model = "fake-model"
kind = "fake"
"#;

/// Lowercase 64-hex keys; the store never re-hashes the bytes.
const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000c4d";
/// The invoice already waiting when the daemon starts: it proves the startup
/// sweep ran, so the second document can only be read by a later tick.
const CANARY_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000c4c";

/// A fictional UBL invoice: the owner's "how much was the Northwind receipt?"
/// shape, read by the Rust XML leg (no PDFKit, no OCR, no app).
const UBL: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2">
  <cbc:ID>FAC-2025-0042</cbc:ID>
  <cbc:IssueDate>2025-09-12</cbc:IssueDate>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cac:AccountingSupplierParty><cac:Party>
    <cac:PartyName><cbc:Name>Nordwind Studio SARL</cbc:Name></cac:PartyName>
    <cac:PartyTaxScheme><cbc:CompanyID>FR12345678901</cbc:CompanyID>
      <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>
    <cac:PartyLegalEntity><cbc:CompanyID>123456789</cbc:CompanyID></cac:PartyLegalEntity>
  </cac:Party></cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty><cac:Party>
    <cac:PartyName><cbc:Name>Camille Exemple</cbc:Name></cac:PartyName>
    <cac:PartyLegalEntity><cbc:CompanyID>987654321</cbc:CompanyID></cac:PartyLegalEntity>
  </cac:Party></cac:AccountingCustomerParty>
  <cac:TaxTotal><cbc:TaxAmount>20.00</cbc:TaxAmount>
    <cac:TaxSubtotal><cbc:TaxableAmount>100.00</cbc:TaxableAmount>
      <cbc:TaxAmount>20.00</cbc:TaxAmount><cbc:Percent>20</cbc:Percent>
    </cac:TaxSubtotal></cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:TaxExclusiveAmount>100.00</cbc:TaxExclusiveAmount>
    <cbc:PayableAmount>120.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
  <cac:InvoiceLine>
    <cbc:ID>1</cbc:ID><cbc:InvoicedQuantity>1</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount>100.00</cbc:LineExtensionAmount>
    <cac:Item><cbc:Description>Design</cbc:Description>
      <cac:ClassifiedTaxCategory><cbc:Percent>20</cbc:Percent>
        <cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price><cbc:PriceAmount>100.00</cbc:PriceAmount></cac:Price>
  </cac:InvoiceLine>
</Invoice>"#;

/// One extracted field row, or `None` while the document has no row yet.
#[derive(Debug, PartialEq, Eq)]
struct Row {
    state: String,
    extractor: String,
    issuer: Option<String>,
    number: Option<String>,
    total_minor: Option<i64>,
}

fn field_row(home: &Path, hash: &str) -> Option<Row> {
    let conn = aux_store::open_keyed_readonly(&store_path(home)).ok()?;
    conn.query_row(
        "SELECT f.extract_state, f.extractor, f.issuer, f.number, f.total_minor
           FROM document_fields AS f
           JOIN documents AS d ON d.id = f.document_id
          WHERE d.content_hash = ?1",
        [hash],
        |row| {
            Ok(Row {
                state: row.get(0)?,
                extractor: row.get(1)?,
                issuer: row.get(2)?,
                number: row.get(3)?,
                total_minor: row.get(4)?,
            })
        },
    )
    .ok()
}

/// Register the invoice's sealed blob exactly as a mail attachment would be:
/// the daemon's own evidence path, not a test-only shortcut in the extractor.
fn drop_document_in_the_registry(home: &Path, hash: &str, bytes: &[u8], name: &str) {
    let store = Store::open(&store_path(home)).unwrap();
    let storage_path = format!("evidence/{hash}");
    std::fs::create_dir_all(home.join("evidence")).unwrap();
    let key = aux_store::evidence_key(home).unwrap();
    let sealed = aux_store::seal_evidence(&key, hash, bytes).unwrap();
    std::fs::write(home.join(&storage_path), sealed).unwrap();
    store
        .append_evidence(
            &NewEvidenceDocument {
                content_hash: hash,
                storage_path: &storage_path,
                size_bytes: bytes.len() as i64,
                mime_type: "application/xml",
                original_name: name,
                account_id: "personal",
                captured_at: "2025-10-01T00:00:00Z",
            },
            "{\"owner\":{\"file_name\":\"fixture\"}}",
            "2025-10-01T00:00:00Z",
        )
        .unwrap();
}

/// Poll the store until `hash` is `done`; a `failed` row fails at once with
/// its reason instead of waiting out the budget. No API is involved.
fn wait_for_read(home: &Path, hash: &str, what: &str) -> Row {
    let started = Instant::now();
    let deadline = started + common::LOADED_RUNNER_WAIT;
    loop {
        if let Some(row) = field_row(home, hash) {
            match row.state.as_str() {
                "done" => return row,
                "failed" => panic!("{what}: the sweep filed it failed: {row:?}"),
                _ => {}
            }
        }
        assert!(
            Instant::now() < deadline,
            "{what} within {:?} (last row: {:?})",
            started.elapsed(),
            field_row(home, hash)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Spawn the real daemon and wait for its `auxd ready` line.
fn start_daemon(dir: &Path, home: &Path) -> KillOnDrop {
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir, home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut daemon = KillOnDrop::new(child);
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    let deadline = Instant::now() + common::LOADED_RUNNER_WAIT;
    loop {
        assert!(Instant::now() < deadline, "the daemon announces ready");
        assert!(daemon.try_wait().unwrap().is_none(), "the daemon exited");
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(line) if line.contains("auxd ready") => break,
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("the daemon's stdout closed before ready")
            }
        }
    }
    daemon
}

#[test]
fn a_document_that_lands_in_the_registry_is_read_without_the_app() {
    let dir = tempfile::tempdir().unwrap();
    let home: PathBuf = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), CONFIG).unwrap();
    let _ = Store::open(&store_path(&home)).unwrap();

    // The canary is already registered when the daemon starts: reading it
    // proves the startup sweep has run, so the second invoice below can only
    // be read by a later tick.
    let canary = String::from_utf8(UBL.to_vec())
        .unwrap()
        .replace("FAC-2025-0042", "FAC-2025-0041")
        .into_bytes();
    drop_document_in_the_registry(&home, CANARY_HASH, &canary, "canary.xml");
    let _daemon = start_daemon(dir.path(), &home);
    let read_at_startup = wait_for_read(&home, CANARY_HASH, "the startup sweep reads the canary");
    assert_eq!(read_at_startup.extractor, "xml");

    // A document lands with the daemon up and no app running. No HTTP call is
    // made anywhere in this test: only a background tick can read it.
    drop_document_in_the_registry(&home, HASH, UBL, "nordwind-receipt.xml");

    let row = wait_for_read(&home, HASH, "the daemon reads a new invoice on its own");
    assert_eq!(
        row,
        Row {
            state: "done".into(),
            extractor: "xml".into(),
            issuer: Some("Nordwind Studio SARL".into()),
            number: Some("FAC-2025-0042".into()),
            total_minor: Some(12_000),
        }
    );
}
