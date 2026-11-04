//! C2b acceptance: the document extractor chain and the local bridge API.
//! Everything runs in-process on an ephemeral loopback port and a temp home:
//! no network, no real `~/.auxesis`, no Keychain. The bridge is the test
//! itself, speaking HTTP with the daemon's bearer token.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use aux_engine::{ChatSession, ChatSetup};
use aux_mail::{
    DownloadedAttachment, EnvelopeItem, FetchedAttachments, Limits, ListQuery, MailApi, MailError,
    MailItem, SearchQuery,
};
use aux_providers::{
    ChatMessage, ChatProvider, ChatRequest, ChatResponse, ProviderError, ToolCall,
};
use aux_store::{
    open_keyed, open_keyed_readonly, NewEvidenceDocument, NewParty, PartyKind, Store, StoreHandle,
};
use auxd::api::{self, ApiHandle, ApiOptions};
use auxd::skill_executor::{attach_skill_runtime, DocsSkillConnector};
use kernel_broker::{ApprovalRequest, Approver, ApproverError, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::PrivacyMode;
use kernel_core::{config_path, store_path, ContextConfig};
use kernel_privacy::ContactIndex;
use tempfile::tempdir;

use common::HttpResponse;

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FAKE_CONFIG: &str = "version = 1\n\n[privacy]\nmode = \"open\"\n";
const PRIVATE_CONFIG: &str = "version = 1\n\n[privacy]\nmode = \"private\"\n";

// ---------------------------------------------------------------------------
// fixtures (fictional companies and people)
// ---------------------------------------------------------------------------

fn ubl_invoice() -> Vec<u8> {
    br#"<?xml version="1.0" encoding="UTF-8"?>
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
</Invoice>"#
        .to_vec()
}

fn cii_invoice(gross: &str) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<rsm:CrossIndustryInvoice
    xmlns:rsm="urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"
    xmlns:ram="urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100"
    xmlns:udt="urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100">
  <rsm:ExchangedDocument>
    <ram:ID>REC-2025-0007</ram:ID>
    <ram:IssueDateTime><udt:DateTimeString format="102">20250930</udt:DateTimeString></ram:IssueDateTime>
  </rsm:ExchangedDocument>
  <rsm:SupplyChainTradeTransaction>
    <ram:IncludedSupplyChainTradeLineItem>
      <ram:SpecifiedTradeProduct><ram:Name>Conseil</ram:Name></ram:SpecifiedTradeProduct>
      <ram:SpecifiedLineTradeAgreement>
        <ram:NetPriceProductTradePrice><ram:ChargeAmount>50.00</ram:ChargeAmount></ram:NetPriceProductTradePrice>
      </ram:SpecifiedLineTradeAgreement>
      <ram:SpecifiedLineTradeDelivery><ram:BilledQuantity>2</ram:BilledQuantity></ram:SpecifiedLineTradeDelivery>
      <ram:SpecifiedLineTradeSettlement>
        <ram:ApplicableTradeTax><ram:RateApplicablePercent>20</ram:RateApplicablePercent></ram:ApplicableTradeTax>
        <ram:SpecifiedTradeSettlementLineMonetarySummation><ram:LineTotalAmount>100.00</ram:LineTotalAmount></ram:SpecifiedTradeSettlementLineMonetarySummation>
      </ram:SpecifiedLineTradeSettlement>
    </ram:IncludedSupplyChainTradeLineItem>
    <ram:ApplicableHeaderTradeAgreement>
      <ram:SellerTradeParty>
        <ram:Name>Atelier Cobalt</ram:Name>
        <ram:SpecifiedTaxRegistration><ram:ID schemeID="VA">FR99999999999</ram:ID></ram:SpecifiedTaxRegistration>
      </ram:SellerTradeParty>
      <ram:BuyerTradeParty><ram:Name>Camille Exemple</ram:Name></ram:BuyerTradeParty>
    </ram:ApplicableHeaderTradeAgreement>
    <ram:ApplicableHeaderTradeSettlement>
      <ram:InvoiceCurrencyCode>EUR</ram:InvoiceCurrencyCode>
      <ram:ApplicableTradeTax>
        <ram:RateApplicablePercent>20</ram:RateApplicablePercent>
        <ram:BasisAmount>100.00</ram:BasisAmount>
        <ram:CalculatedAmount>20.00</ram:CalculatedAmount>
      </ram:ApplicableTradeTax>
      <ram:SpecifiedTradeSettlementHeaderMonetarySummation>
        <ram:TaxBasisTotalAmount>100.00</ram:TaxBasisTotalAmount>
        <ram:GrandTotalAmount>{gross}</ram:GrandTotalAmount>
      </ram:SpecifiedTradeSettlementHeaderMonetarySummation>
    </ram:ApplicableHeaderTradeSettlement>
  </rsm:SupplyChainTradeTransaction>
</rsm:CrossIndustryInvoice>"#
    )
    .into_bytes()
}

const FRENCH_RECEIPT: &str = "Boulangerie Exemple\n\
    12 rue des Lilas\n\
    Ticket N° 2025-0042\n\
    Date 12/09/2025\n\
    Sous-total 10,00\n\
    Total TTC 12,34 €\n\
    TVA 20% 2,34\n";

const ENGLISH_INVOICE: &str = "Northwind Studio\n\
    Invoice # INV-2025-0009\n\
    Issued 2025-10-01\n\
    Subtotal 100.00 USD\n\
    VAT 20.00\n\
    Total due 120.00\n";

// ---------------------------------------------------------------------------
// daemon + registry helpers
// ---------------------------------------------------------------------------

struct TestApi {
    _dir: tempfile::TempDir,
    home: PathBuf,
    addr: SocketAddr,
    token: String,
    /// Kept alive for the test: dropping it detaches nothing that the test
    /// needs, but the server tasks live as long as the runtime.
    _handle: Option<ApiHandle>,
}

impl TestApi {
    fn start() -> Self {
        Self::start_with(FAKE_CONFIG)
    }

    /// Start the in-process daemon with `config` written to the temp home.
    fn start_with(config: &str) -> Self {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(config_path(&home), config).unwrap();
        let _ = Store::open(&store_path(&home)).unwrap();
        std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
        Self::start_existing(dir, home)
    }

    fn start_existing(dir: tempfile::TempDir, home: PathBuf) -> Self {
        let handle = api::spawn(
            &home,
            ApiOptions {
                port: 0,
                event_poll: Duration::from_millis(25),
                ..ApiOptions::default()
            },
        )
        .unwrap();
        let addr = handle.addr();
        let token = std::fs::read_to_string(api::token_path(&home))
            .unwrap()
            .trim()
            .to_string();
        Self {
            _dir: dir,
            home,
            addr,
            token,
            _handle: Some(handle),
        }
    }

    fn store(&self) -> Store {
        Store::open(&store_path(&self.home)).unwrap()
    }
}

async fn call(
    t: &TestApi,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> HttpResponse {
    call_at(t.addr, method, path, token, body).await
}

async fn call_at(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> HttpResponse {
    let method = method.to_string();
    let path = path.to_string();
    let token = token.map(str::to_string);
    let body = body.map(str::to_string);
    tokio::task::spawn_blocking(move || {
        common::http(addr, &method, &path, token.as_deref(), body.as_deref())
    })
    .await
    .unwrap()
}

/// A deterministic 64-hex key for a fixture. The store never re-hashes the
/// bytes: the key is the blob path, so a fixture can be given a distinct key
/// without changing its content.
fn fixture_hash(tag: u8) -> String {
    format!("{tag:02x}").repeat(32)
}

/// A distinct 64-hex key for a bulk fixture (left-padded hex).
fn fixture_hash_n(n: u32) -> String {
    format!("{n:064x}")
}

fn seed(store: &Store, home: &Path, tag: u8, bytes: &[u8], name: &str, mime: &str) -> String {
    let hash = fixture_hash(tag);
    seed_hash(store, home, &hash, bytes, name, mime);
    hash
}

/// Register an original under `hash` and write its sealed blob. The store never
/// re-hashes the bytes, so the key is the blob path.
fn seed_hash(store: &Store, home: &Path, hash: &str, bytes: &[u8], name: &str, mime: &str) {
    let storage_path = format!("evidence/{hash}");
    std::fs::create_dir_all(home.join("evidence")).unwrap();
    // Blobs are sealed at rest; the blob route opens them.
    let key = aux_store::evidence_key(home).unwrap();
    let sealed = aux_store::seal_evidence(&key, hash, bytes).unwrap();
    std::fs::write(home.join(&storage_path), sealed).unwrap();
    store
        .append_evidence(
            &NewEvidenceDocument {
                content_hash: hash,
                storage_path: &storage_path,
                size_bytes: bytes.len() as i64,
                mime_type: mime,
                original_name: name,
                account_id: "personal",
                captured_at: "2025-10-01T00:00:00Z",
            },
            "{\"owner\":{\"file_name\":\"fixture\"}}",
            "2025-10-01T00:00:00Z",
        )
        .unwrap();
}

/// Register an original without writing its blob: the sweep must still file it
/// and leave the queue moving.
fn seed_without_blob(store: &Store, hash: &str, name: &str, mime: &str) {
    store
        .append_evidence(
            &NewEvidenceDocument {
                content_hash: hash,
                storage_path: &format!("evidence/{hash}"),
                size_bytes: 4,
                mime_type: mime,
                original_name: name,
                account_id: "personal",
                captured_at: "2025-10-01T00:00:00Z",
            },
            "{\"owner\":{\"file_name\":\"fixture\"}}",
            "2025-10-01T00:00:00Z",
        )
        .unwrap();
}

#[derive(Debug, Clone)]
struct FieldRow {
    extract_state: String,
    kind: String,
    extractor: String,
    issuer: Option<String>,
    number: Option<String>,
    total_minor: Option<i64>,
    vat_minor: Option<i64>,
    checks: serde_json::Value,
    party_id: Option<i64>,
    attempts: i64,
    status: String,
}

fn field_row(home: &Path, hash: &str) -> FieldRow {
    let conn = open_keyed_readonly(&store_path(home)).unwrap();
    conn.query_row(
        "SELECT f.extract_state, f.kind, f.extractor, f.issuer, f.number, f.total_minor,
                f.vat_minor, f.checks_json, f.party_id, f.attempts, f.status
           FROM document_fields AS f
           JOIN documents AS d ON d.id = f.document_id
          WHERE d.content_hash = ?1",
        [hash],
        |row| {
            let checks: String = row.get(7)?;
            Ok(FieldRow {
                extract_state: row.get(0)?,
                kind: row.get(1)?,
                extractor: row.get(2)?,
                issuer: row.get(3)?,
                number: row.get(4)?,
                total_minor: row.get(5)?,
                vat_minor: row.get(6)?,
                checks: serde_json::from_str(&checks).unwrap_or(serde_json::Value::Null),
                party_id: row.get(8)?,
                attempts: row.get(9)?,
                status: row.get(10)?,
            })
        },
    )
    .unwrap()
}

fn check_state(row: &FieldRow, name: &str) -> String {
    row.checks
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["name"] == name)
                .and_then(|check| check["state"].as_str())
        })
        .unwrap_or("missing")
        .to_string()
}

/// The raw `fields_json` of a stored row.
fn fields_json_of(home: &Path, hash: &str) -> String {
    open_keyed_readonly(&store_path(home))
        .unwrap()
        .query_row(
            "SELECT f.fields_json FROM document_fields AS f
               JOIN documents AS d ON d.id = f.document_id
              WHERE d.content_hash = ?1",
            [hash],
            |row| row.get(0),
        )
        .unwrap()
}

fn set_claimed_at(home: &Path, hash: &str, when: &str) {
    let conn = open_keyed(&store_path(home)).unwrap();
    conn.execute(
        "UPDATE document_fields SET claimed_at = ?1
          WHERE document_id = (SELECT id FROM documents WHERE content_hash = ?2)",
        rusqlite::params![when, hash],
    )
    .unwrap();
}

fn pending_hashes(response: &HttpResponse) -> Vec<String> {
    response
        .json()
        .as_array()
        .expect("an array of pending documents")
        .iter()
        .map(|doc| doc["hash"].as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// XML leg
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xml_invoices_extract_in_rust_with_checks() {
    let t = TestApi::start();
    let store = t.store();
    let ubl = seed(
        &store,
        &t.home,
        1,
        &ubl_invoice(),
        "ubl.xml",
        "application/xml",
    );
    let cii = seed(
        &store,
        &t.home,
        2,
        &cii_invoice("120.00"),
        "cii.xml",
        "application/xml",
    );
    let cent = seed(
        &store,
        &t.home,
        3,
        &cii_invoice("120.01"),
        "cent.xml",
        "application/xml",
    );

    let response = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=5",
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert!(
        pending_hashes(&response).is_empty(),
        "XML is extracted in Rust, never queued: {}",
        response.body
    );

    let ubl_row = field_row(&t.home, &ubl);
    assert_eq!(ubl_row.extract_state, "done");
    assert_eq!(ubl_row.kind, "invoice");
    assert_eq!(ubl_row.extractor, "xml");
    assert_eq!(ubl_row.issuer.as_deref(), Some("Nordwind Studio SARL"));
    assert_eq!(ubl_row.number.as_deref(), Some("FAC-2025-0042"));
    assert_eq!(ubl_row.total_minor, Some(12_000));
    assert_eq!(ubl_row.vat_minor, Some(2_000));
    assert_eq!(check_state(&ubl_row, "totals"), "pass");
    assert_eq!(check_state(&ubl_row, "vat"), "pass");

    let cii_row = field_row(&t.home, &cii);
    assert_eq!(cii_row.issuer.as_deref(), Some("Atelier Cobalt"));
    assert_eq!(cii_row.total_minor, Some(12_000));
    assert_eq!(check_state(&cii_row, "totals"), "pass");

    let cent_row = field_row(&t.home, &cent);
    assert_eq!(check_state(&cent_row, "totals"), "fail");
    assert_eq!(cent_row.total_minor, Some(12_001));

    // No route ever returned a name or a body: the queue was empty.
    assert!(!response.body.contains("Nordwind"), "{}", response.body);
}

// ---------------------------------------------------------------------------
// bridge leg
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_bridge_claims_pdfs_and_images_and_posts_text() {
    let t = TestApi::start();
    let store = t.store();
    let mut pdfs = Vec::new();
    for tag in 10..14u8 {
        let bytes = format!("%PDF-1.4 docs-fixture-pdf-{tag}\r\n").into_bytes();
        pdfs.push(seed(
            &store,
            &t.home,
            tag,
            &bytes,
            &format!("receipt-{tag}.pdf"),
            "application/pdf",
        ));
    }
    let mut images = Vec::new();
    for tag in 20..23u8 {
        let mut bytes = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
        bytes.extend_from_slice(format!("docs-fixture-image-{tag}").as_bytes());
        images.push(seed(
            &store,
            &t.home,
            tag,
            &bytes,
            &format!("scan-{tag}.png"),
            "image/png",
        ));
    }

    // First poll: the four PDFs, in document order.
    let first = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=4",
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(first.status, 200, "{}", first.body);
    let claimed = pending_hashes(&first);
    assert_eq!(claimed.len(), 4, "{}", first.body);
    for (index, hash) in claimed.iter().enumerate() {
        assert_eq!(*hash, pdfs[index]);
        let blob = call(
            &t,
            "GET",
            &format!("/v1/docs/{hash}/blob"),
            Some(&t.token),
            None,
        )
        .await;
        assert_eq!(blob.status, 200, "{}", blob.body);
        assert!(blob.body.contains("docs-fixture-pdf"), "{}", blob.body);
        let text = if index == 0 {
            FRENCH_RECEIPT
        } else if index == 1 {
            ENGLISH_INVOICE
        } else {
            "Atelier Cobalt\nFacture N° F-0001\nDate 2025-08-01\nTotal 42,00 €\nTVA 20% 7,00\n"
        };
        post_extraction(&t, hash, "pdf_text", text).await;
    }

    // Second poll: the three images.
    let second = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=4",
        Some(&t.token),
        None,
    )
    .await;
    let claimed = pending_hashes(&second);
    assert_eq!(claimed, images, "{}", second.body);
    for hash in &claimed {
        let blob = call(
            &t,
            "GET",
            &format!("/v1/docs/{hash}/blob"),
            Some(&t.token),
            None,
        )
        .await;
        assert!(blob.body.contains("docs-fixture-image"), "{}", blob.body);
        post_extraction(&t, hash, "ocr", FRENCH_RECEIPT).await;
    }

    // A third poll claims nothing: the bridge drained the queue.
    let third = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=4",
        Some(&t.token),
        None,
    )
    .await;
    assert!(pending_hashes(&third).is_empty(), "{}", third.body);

    // The canned French receipt produced the expected fields.
    let french = field_row(&t.home, &pdfs[0]);
    assert_eq!(french.extract_state, "done");
    assert_eq!(french.extractor, "pdf_text");
    assert_eq!(french.kind, "receipt");
    assert_eq!(french.issuer.as_deref(), Some("Boulangerie Exemple"));
    assert_eq!(french.number.as_deref(), Some("2025-0042"));
    assert_eq!(french.total_minor, Some(1_234));
    assert_eq!(french.vat_minor, Some(234));
    assert_eq!(check_state(&french, "totals"), "unknown");

    // The English invoice.
    let english = field_row(&t.home, &pdfs[1]);
    assert_eq!(english.kind, "invoice");
    assert_eq!(english.number.as_deref(), Some("INV-2025-0009"));
    assert_eq!(english.total_minor, Some(12_000));
    assert_eq!(english.vat_minor, Some(2_000));

    // OCR images are `ocr`, not `pdf_text`.
    let scanned = field_row(&t.home, &images[0]);
    assert_eq!(scanned.extractor, "ocr");
    assert_eq!(scanned.total_minor, Some(1_234));
}

async fn post_extraction(t: &TestApi, hash: &str, extractor: &str, text: &str) {
    let body = serde_json::json!({ "extractor": extractor, "text": text, "pages": 1 }).to_string();
    let response = call(
        t,
        "POST",
        &format!("/v1/docs/{hash}/extraction"),
        Some(&t.token),
        Some(&body),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.body);
}

// ---------------------------------------------------------------------------
// auth, claim gating, queue policy
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_token_is_required_and_an_unclaimed_blob_is_not_served() {
    let t = TestApi::start();
    let store = t.store();
    seed(
        &store,
        &t.home,
        30,
        b"%PDF-1.4 first",
        "first.pdf",
        "application/pdf",
    );
    let second = seed(
        &store,
        &t.home,
        31,
        b"%PDF-1.4 second",
        "second.pdf",
        "application/pdf",
    );

    let unauthorized = call(&t, "GET", "/v1/docs/extract/pending?limit=1", None, None).await;
    assert_eq!(unauthorized.status, 401, "{}", unauthorized.body);

    let first = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=1",
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(pending_hashes(&first).len(), 1);

    // The second document is registered but not claimed: its blob is a 404.
    let unclaimed = call(
        &t,
        "GET",
        &format!("/v1/docs/{second}/blob"),
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(unclaimed.status, 404, "{}", unclaimed.body);

    // An unknown (but well-formed) hash is a 404 too.
    let unknown = call(
        &t,
        "GET",
        &format!("/v1/docs/{}/blob", "f".repeat(64)),
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(unknown.status, 404, "{}", unknown.body);

    // The claimed document is served.
    let claimed = pending_hashes(&first)[0].clone();
    let served = call(
        &t,
        "GET",
        &format!("/v1/docs/{claimed}/blob"),
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(served.status, 200, "{}", served.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_claim_is_requeued_then_fails_after_three_attempts() {
    let t = TestApi::start();
    let store = t.store();
    let hash = seed(
        &store,
        &t.home,
        40,
        b"%PDF-1.4 expired",
        "expired.pdf",
        "application/pdf",
    );

    let first = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=1",
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(pending_hashes(&first), vec![hash.clone()]);
    let row = field_row(&t.home, &hash);
    assert_eq!(row.extract_state, "claimed");
    assert_eq!(row.attempts, 1);

    // Attempt 2 and 3: each stale claim is re-queued and re-claimed.
    for expected in [2, 3] {
        set_claimed_at(&t.home, &hash, "2000-01-01T00:00:00Z");
        let next = call(
            &t,
            "GET",
            "/v1/docs/extract/pending?limit=1",
            Some(&t.token),
            None,
        )
        .await;
        assert_eq!(
            pending_hashes(&next),
            vec![hash.clone()],
            "attempt {expected}"
        );
        assert_eq!(field_row(&t.home, &hash).attempts, expected);
    }

    // The fourth stale claim is the cap: failed, to_check, empty fields, and
    // never re-claimed.
    set_claimed_at(&t.home, &hash, "2000-01-01T00:00:00Z");
    let cap = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=1",
        Some(&t.token),
        None,
    )
    .await;
    assert!(pending_hashes(&cap).is_empty(), "{}", cap.body);
    let row = field_row(&t.home, &hash);
    assert_eq!(row.extract_state, "failed");
    assert_eq!(row.status, "to_check");
    assert_eq!(row.attempts, 3);
    assert_eq!(row.total_minor, None);

    let again = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=1",
        Some(&t.token),
        None,
    )
    .await;
    assert!(pending_hashes(&again).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_a_megabyte_of_text_is_refused() {
    let t = TestApi::start();
    let store = t.store();
    let hash = seed(
        &store,
        &t.home,
        50,
        b"%PDF-1.4 big",
        "big.pdf",
        "application/pdf",
    );
    let claimed = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=1",
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(pending_hashes(&claimed), vec![hash.clone()]);

    let body = serde_json::json!({
        "extractor": "pdf_text",
        "text": "a".repeat(1024 * 1024 + 1),
    })
    .to_string();
    let response = call(
        &t,
        "POST",
        &format!("/v1/docs/{hash}/extraction"),
        Some(&t.token),
        Some(&body),
    )
    .await;
    assert_eq!(response.status, 413, "{}", response.body);
    assert_eq!(field_row(&t.home, &hash).extract_state, "claimed");
}

// ---------------------------------------------------------------------------
// duplicate and party checks against the registry
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_issuer_and_number_is_detected() {
    let t = TestApi::start();
    let store = t.store();
    let first = seed(
        &store,
        &t.home,
        60,
        &cii_invoice("120.00"),
        "one.xml",
        "application/xml",
    );
    let second = seed(
        &store,
        &t.home,
        61,
        &cii_invoice("120.00"),
        "two.xml",
        "application/xml",
    );
    let response = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=5",
        Some(&t.token),
        None,
    )
    .await;
    assert!(pending_hashes(&response).is_empty());

    assert_eq!(
        check_state(&field_row(&t.home, &first), "duplicate"),
        "pass"
    );
    assert_eq!(
        check_state(&field_row(&t.home, &second), "duplicate"),
        "fail"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_party_match_links_the_document_to_the_crm() {
    let t = TestApi::start();
    let store = t.store();
    let party = aux_crm::Crm::new(&store)
        .create(NewParty {
            kind: PartyKind::Company,
            display_name: "Nordwind Studio SARL".to_string(),
            origin: "owner".to_string(),
            ..NewParty::default()
        })
        .unwrap();
    let hash = seed(
        &store,
        &t.home,
        70,
        &ubl_invoice(),
        "party.xml",
        "application/xml",
    );
    let response = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=5",
        Some(&t.token),
        None,
    )
    .await;
    assert!(pending_hashes(&response).is_empty());

    let row = field_row(&t.home, &hash);
    assert_eq!(row.party_id, Some(party.id));
    assert_eq!(check_state(&row, "party_match"), "pass");
}

async fn get(t: &TestApi, path: &str) -> HttpResponse {
    call(t, "GET", path, Some(&t.token), None).await
}

async fn post(t: &TestApi, path: &str) -> HttpResponse {
    call(t, "POST", path, Some(&t.token), None).await
}

fn company(store: &Store, name: &str) -> aux_store::Party {
    aux_crm::Crm::new(store)
        .create(NewParty {
            kind: PartyKind::Company,
            display_name: name.to_string(),
            origin: "owner".to_string(),
            ..NewParty::default()
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_docs_list_shows_each_document_with_its_current_client() {
    let t = TestApi::start();
    let store = t.store();
    let party = company(&store, "Nordwind Studio SARL");
    // Two parties share the other issuer's name: that one is never guessed.
    company(&store, "Atelier Cobalt");
    company(&store, "atelier  cobalt");
    let put = |tag, bytes: &[u8]| seed(&store, &t.home, tag, bytes, "secret-name", "text/xml");
    let linked = put(72, &ubl_invoice());
    let other = put(73, &cii_invoice("120.00"));
    let waiting = seed(&store, &t.home, 74, b"%PDF-1.4", "x.pdf", "application/pdf");
    let row = |rows: &serde_json::Value, hash: &str| -> serde_json::Value {
        let rows = rows.as_array().unwrap();
        let found = rows.iter().find(|r| r["hash"] == hash[..12]);
        found.cloned().unwrap_or_default()
    };

    // The list reads unread XML itself: no Mac bridge needed.
    let response = get(&t, "/v1/docs").await;
    assert_eq!(response.status, 200, "{}", response.body);
    for absent in ["secret-name", "Camille", "Design", "x.pdf"] {
        assert!(!response.body.contains(absent), "{}", response.body);
    }
    let rows = response.json();
    let first = row(&rows, &linked);
    assert_eq!(first["client"]["id"], party.id);
    assert_eq!(first["client"]["name"], "Nordwind Studio SARL");
    assert_eq!(
        (&first["total"], &first["vat"]),
        (&"120.00 EUR".into(), &"20.00 EUR".into())
    );
    assert_eq!(
        (&first["number"], &first["status"]),
        (&"FAC-2025-0042".into(), &"read".into())
    );
    assert!(row(&rows, &other)["client"].is_null());
    assert_eq!(
        check_state(&field_row(&t.home, &other), "party_match"),
        "unknown"
    );
    assert_eq!(row(&rows, &waiting)["status"], "waiting for reading");

    // A renamed client shows its current name; an archived one says so.
    let crm = aux_crm::Crm::new(&store);
    let current = crm.get(party.id).unwrap().unwrap();
    let renamed = NewParty {
        display_name: "Nordwind Atelier".to_string(),
        ..NewParty::from(&current)
    };
    crm.update(party.id, renamed).unwrap();
    let rows = get(&t, "/v1/docs").await.json();
    assert_eq!(row(&rows, &linked)["client"]["name"], "Nordwind Atelier");
    crm.archive(party.id).unwrap();
    let rows = get(&t, "/v1/docs").await.json();
    assert_eq!(row(&rows, &linked)["client"]["archived"], true);

    // Filters and the bound.
    let count = |rows: serde_json::Value| rows.as_array().map_or(0, Vec::len);
    let by_client = get(&t, &format!("/v1/docs?client={}", party.id)).await;
    assert_eq!(count(by_client.json()), 1);
    assert_eq!(count(get(&t, "/v1/docs?unlinked=true").await.json()), 2);
    assert_eq!(count(get(&t, "/v1/docs?limit=1").await.json()), 1);
    assert_eq!(get(&t, "/v1/docs?client=1&unlinked=true").await.status, 400);
    assert_eq!(call(&t, "GET", "/v1/docs", None, None).await.status, 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_links_and_unlinks_a_document_by_hash_prefix() {
    let t = TestApi::start();
    let store = t.store();
    let hash = seed(
        &store,
        &t.home,
        75,
        &cii_invoice("120.00"),
        "a.xml",
        "application/xml",
    );
    let pdf = seed(
        &store,
        &t.home,
        76,
        b"%PDF-1.4 x",
        "scan.pdf",
        "application/pdf",
    );
    for n in [1, 2] {
        seed_without_blob(&store, &fixture_hash_n(n), "twin.pdf", "application/pdf");
    }
    assert_eq!(
        call(&t, "GET", "/v1/docs", Some(&t.token), None)
            .await
            .status,
        200
    );
    let party = company(&store, "Atelier Lumen");
    let archived = company(&store, "Old Client");
    aux_crm::Crm::new(&store).archive(archived.id).unwrap();
    let prefix = &hash[..8];

    // Every refusal is clear and writes nothing.
    let refusals = [
        (
            format!("/v1/docs/{prefix}/party?party={}", archived.id),
            404,
        ),
        (format!("/v1/docs/{prefix}/party?party=9999"), 404),
        (format!("/v1/docs/ffffffff/party?party={}", party.id), 404),
        (
            format!("/v1/docs/{}/party?party={}", &hash[..7], party.id),
            400,
        ),
        (format!("/v1/docs/00000000/party?party={}", party.id), 409),
        (
            format!("/v1/docs/{}/party?party={}", &pdf[..8], party.id),
            409,
        ),
    ];
    for (path, status) in refusals {
        let response = post(&t, &path).await;
        assert_eq!(response.status, status, "{path}: {}", response.body);
        assert!(response.json()["error"]["message"].is_string());
    }
    assert_eq!(field_row(&t.home, &hash).party_id, None);

    let linked = post(&t, &format!("/v1/docs/{prefix}/party?party={}", party.id)).await;
    assert_eq!(linked.status, 200, "{}", linked.body);
    let row = field_row(&t.home, &hash);
    assert_eq!(row.party_id, Some(party.id));
    assert_eq!(check_state(&row, "party_match"), "pass");

    let unlinked = post(&t, &format!("/v1/docs/{prefix}/party?party=none")).await;
    assert_eq!(unlinked.status, 200, "{}", unlinked.body);
    let row = field_row(&t.home, &hash);
    assert_eq!(row.party_id, None);
    assert_eq!(check_state(&row, "party_match"), "unknown");
    let path = format!("/v1/docs/{prefix}/party?party=none");
    assert_eq!(call(&t, "POST", &path, None, None).await.status, 401);
}

/// DOCS-RELINK: a receipt read before its client existed is linked once the
/// client is created, by the extraction rule; two matching clients link
/// nothing, and the owner's own unlink stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receipt_read_before_its_client_is_linked_once_the_client_exists() {
    let t = TestApi::start();
    let store = t.store();
    let put = |tag, bytes: &[u8]| seed(&store, &t.home, tag, bytes, "r.xml", "application/xml");
    let nordwind = put(77, &ubl_invoice());
    let kept = put(78, &ubl_invoice());
    let cobalt = put(79, &cii_invoice("120.00"));
    assert_eq!(get(&t, "/v1/docs").await.status, 200);
    let unlink = format!("/v1/docs/{}/party?party=none", &kept[..8]);
    assert_eq!(post(&t, &unlink).await.status, 200);

    let party = company(&store, "Nordwind Studio SARL");
    company(&store, "Atelier Cobalt");
    company(&store, "atelier  cobalt");
    assert_eq!(get(&t, "/v1/docs").await.status, 200);

    let row = field_row(&t.home, &nordwind);
    assert_eq!(row.party_id, Some(party.id));
    assert_eq!(check_state(&row, "party_match"), "pass");
    assert_eq!(
        field_row(&t.home, &kept).party_id,
        None,
        "the owner's unlink stands"
    );
    let row = field_row(&t.home, &cobalt);
    assert_eq!(row.party_id, None, "two matching clients link nothing");
    assert_eq!(check_state(&row, "party_match"), "unknown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_erase_removes_the_registry_rows_and_the_sealed_blob() {
    let t = TestApi::start();
    let store = t.store();
    let hash = seed(
        &store,
        &t.home,
        81,
        &ubl_invoice(),
        "erase.xml",
        "application/xml",
    );
    assert_eq!(get(&t, "/v1/docs").await.status, 200);
    let path = t.home.join("evidence").join(&hash);
    assert!(path.exists());

    let erased = call(
        &t,
        "DELETE",
        &format!("/v1/docs/{}", &hash[..12]),
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(erased.status, 200, "{}", erased.body);
    assert!(
        !path.exists(),
        "owner erase retained the sealed source blob"
    );
    assert!(
        t.store()
            .documents_by_hash_prefix(&hash)
            .unwrap()
            .is_empty(),
        "owner erase retained the documents row"
    );
    assert!(t.store().recent_document_texts().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erase_tombstone_clears_when_blob_is_already_missing_after_restart() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();
    std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
    let store = Store::open(&store_path(&home)).unwrap();
    let hash = seed(
        &store,
        &home,
        82,
        &ubl_invoice(),
        "crash.xml",
        "application/xml",
    );
    let document_id = store.documents_by_hash_prefix(&hash).unwrap()[0].document_id;
    store
        .insert_document_fields(&aux_store::NewDocumentFields {
            document_id,
            kind: "invoice",
            extractor: "xml",
            issuer: Some("Northwind"),
            recipient: None,
            issued_on: None,
            currency: Some("EUR"),
            total_minor: Some(12_000),
            vat_minor: None,
            number: Some("NW-ERASE-82"),
            fields_json: "{\"number\":\"NW-ERASE-82\"}",
            extracted_text: "source OCR that must be erased",
            checks_json: "[]",
            party_id: None,
            tags: "[]",
            status: "filed",
            updated_at: "2026-10-26T00:00:00Z",
            extract_state: "done",
            claimed_at: None,
            attempts: 1,
        })
        .unwrap();

    assert_eq!(
        store.erase_document_by_hash_prefix(&hash[..12]).unwrap(),
        aux_store::DocumentEraseResult::Erased(hash.clone())
    );
    let blob = home.join("evidence").join(&hash);
    assert!(
        blob.exists(),
        "test must stop after commit, before blob deletion"
    );
    drop(store);
    std::fs::remove_file(&blob).unwrap();

    let restarted = TestApi::start_existing(dir, home);
    assert!(!blob.exists(), "startup did not sweep the erase tombstone");
    let pending = restarted.store().pending_evidence_erases().unwrap();
    assert!(pending.is_empty(), "startup left erase tombstones");
    assert!(restarted
        .store()
        .documents_by_hash_prefix(&hash)
        .unwrap()
        .is_empty());
}

// ---------------------------------------------------------------------------
// a bad document cannot starve the queue
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreadable_documents_do_not_starve_the_queue() {
    let t = TestApi::start();
    let store = t.store();

    // A malformed hash inserted under the store's validation guard, followed
    // by 300 valid rows whose blob is missing.
    open_keyed(&store_path(&t.home))
        .unwrap()
        .execute(
            "INSERT INTO documents(content_hash, storage_path, size_bytes, mime_type, source, state)
             VALUES ('not-a-hash', 'evidence/not-a-hash', 4, 'application/pdf', 'imap', 'unverified')",
            [],
        )
        .unwrap();
    for n in 0..300u32 {
        seed_without_blob(&store, &fixture_hash_n(n), "missing.pdf", "application/pdf");
    }
    let good = seed(
        &store,
        &t.home,
        200,
        &cii_invoice("120.00"),
        "good.xml",
        "application/xml",
    );

    // One sweep handles 256 unprocessed rows. Two polls must reach the good
    // document behind the 301 bad ones.
    for _ in 0..2 {
        let response = call(
            &t,
            "GET",
            "/v1/docs/extract/pending?limit=1",
            Some(&t.token),
            None,
        )
        .await;
        assert_eq!(response.status, 200, "{}", response.body);
    }

    let good_row = field_row(&t.home, &good);
    assert_eq!(good_row.extract_state, "done");
    assert_eq!(good_row.number.as_deref(), Some("REC-2025-0007"));

    // A bad row is filed failed and `to_check`, not left unprocessed.
    let missing = field_row(&t.home, &fixture_hash_n(0));
    assert_eq!(missing.extract_state, "failed");
    assert_eq!(missing.status, "to_check");
    let malformed = field_row(&t.home, "not-a-hash");
    assert_eq!(malformed.extract_state, "failed");
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_mode_keeps_reduced_document_metadata() {
    let t = TestApi::start_with(PRIVATE_CONFIG);
    let store = t.store();
    // A CRM party and an invoice whose issuer matches it: the name may stay.
    let party = aux_crm::Crm::new(&store)
        .create(NewParty {
            kind: PartyKind::Company,
            display_name: "Nordwind Studio SARL".to_string(),
            origin: "owner".to_string(),
            ..NewParty::default()
        })
        .unwrap();
    let matched = seed(
        &store,
        &t.home,
        80,
        &ubl_invoice(),
        "matched.xml",
        "application/xml",
    );
    // An invoice with no CRM party: its free-text issuer must not be stored.
    let unmatched = seed(
        &store,
        &t.home,
        81,
        &cii_invoice("120.00"),
        "unmatched.xml",
        "application/xml",
    );
    let scanned = seed(
        &store,
        &t.home,
        82,
        b"%PDF-1.4 private",
        "scan.pdf",
        "application/pdf",
    );

    let first = call(
        &t,
        "GET",
        "/v1/docs/extract/pending?limit=4",
        Some(&t.token),
        None,
    )
    .await;
    assert_eq!(pending_hashes(&first), vec![scanned.clone()]);
    post_extraction(&t, &scanned, "ocr", FRENCH_RECEIPT).await;

    let matched_row = field_row(&t.home, &matched);
    assert_eq!(matched_row.party_id, Some(party.id));
    // Metadata only: even a matched party leaves no free-text issuer.
    assert_eq!(matched_row.issuer, None);
    assert_eq!(matched_row.number.as_deref(), Some("FAC-2025-0042"));
    assert_eq!(matched_row.total_minor, Some(12_000));
    assert!(!fields_json_of(&t.home, &matched).contains("Nordwind"));

    let unmatched_row = field_row(&t.home, &unmatched);
    assert_eq!(unmatched_row.party_id, None);
    assert_eq!(
        unmatched_row.issuer, None,
        "free-text issuer is dropped in private mode"
    );
    assert_eq!(unmatched_row.number.as_deref(), Some("REC-2025-0007"));
    assert_eq!(unmatched_row.total_minor, Some(12_000));
    assert!(!fields_json_of(&t.home, &unmatched).contains("Atelier Cobalt"));

    let scanned_row = field_row(&t.home, &scanned);
    assert_eq!(scanned_row.issuer, None);
    assert_eq!(scanned_row.total_minor, Some(1_234));
    assert!(!fields_json_of(&t.home, &scanned).contains("Boulangerie"));
}

// ---------------------------------------------------------------------------
// privacy: a real collector turn and the real extraction route never carry a
// document canary
// ---------------------------------------------------------------------------

/// The real `collect-receipts` skill agent, so the turn exercises the
/// deterministic collector path rather than an empty conversation.
const CANARY_AGENT: &str =
    "---\nname: assistant\nbrain: cloud\ndefault_mode: open\nchannels: [mac]\n\
     tools:\n  - mail.fetch_attachments\n  - docs.ingest\n\
     recipients:\n  policy: known-contacts\n  allowlist: []\n---\nCanary agent.\n";

const CANARY_SKILL: &str = "---\nname: collect-receipts\nversion: 1\ncommand: collect-receipts\n\
     brain: none\ntrigger:\n  manual: true\ntools: [docs.ingest]\n\
     recipients:\n  policy: known-contacts\napproval: each_run\non_failure: stop\n---\n\
     Collect the local receipts.\n";

/// A fake mailbox whose one stored attachment carries the canary bytes.
struct CanaryMail {
    bytes: Vec<u8>,
    sha256: String,
}

#[async_trait]
impl MailApi for CanaryMail {
    async fn list(&self, _: &str, _: &ListQuery) -> Result<Vec<EnvelopeItem>, MailError> {
        Ok(vec![EnvelopeItem {
            uid: 1,
            message_id: "<canary@example.test>".to_string(),
            subject: "Receipt".to_string(),
            from: "Nordwind Studio <billing@nordwind.test>".to_string(),
            to: Vec::new(),
            cc: Vec::new(),
            date: "Mon, 6 Oct 2025 09:00:00 +0000".to_string(),
            size: 64,
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
        _: &str,
        _: &str,
        _: u32,
    ) -> Result<FetchedAttachments, MailError> {
        Ok(FetchedAttachments {
            message_id: "<canary@example.test>".to_string(),
            downloaded: vec![DownloadedAttachment {
                part: "2".to_string(),
                file_name: "invoice.pdf".to_string(),
                mime: "application/pdf".to_string(),
                size: self.bytes.len(),
                sha256: self.sha256.clone(),
                bytes: self.bytes.clone(),
            }],
            skipped: Vec::new(),
        })
    }

    async fn send(
        &self,
        _: &str,
        _: &aux_mail::OutgoingMail,
    ) -> Result<aux_mail::SendOutcome, MailError> {
        Err(MailError::Protocol)
    }

    fn limits(&self) -> &Limits {
        static LIMITS: std::sync::LazyLock<Limits> = std::sync::LazyLock::new(Limits::default);
        std::sync::LazyLock::force(&LIMITS)
    }
}

/// The fake provider: force the `collect-receipts` skill once, then answer.
#[derive(Default)]
struct DocsProvider {
    seen: Mutex<Vec<String>>,
    offered: Mutex<Vec<Vec<String>>>,
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
            let arguments = serde_json::json!({
                "slots": {},
                "calls": [{
                    "tool": "docs_ingest",
                    "arguments": { "account": "personal", "folder": "INBOX", "days": 30 },
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
        Ok(ChatResponse::assistant("ok"))
    }

    fn name(&self) -> &str {
        "canary"
    }
}

struct AllowApprover;

#[async_trait]
impl Approver for AllowApprover {
    async fn approve(&self, _: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn document_canaries_never_reach_a_provider() {
    const CANARY_BYTES: &str = "CANARY-DOCUMENT-BYTES";
    const CANARY_OCR: &str = "CANARY-OCR-TEXT";

    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    let agent_dir = home.join("agents").join("assistant");
    std::fs::create_dir_all(agent_dir.join("skills")).unwrap();
    std::fs::write(config_path(&home), FAKE_CONFIG).unwrap();
    std::fs::write(agent_dir.join("agent.md"), CANARY_AGENT).unwrap();
    std::fs::write(
        agent_dir.join("skills").join("collect-receipts.md"),
        CANARY_SKILL,
    )
    .unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let store = Arc::new(Mutex::new(Store::open(&store_path(&home)).unwrap()));

    // Real path 1: the deterministic `collect-receipts` skill ingests a mail
    // attachment whose stored bytes carry the canary. The skill's report is a
    // real tool result fed back to the provider.
    let hash = fixture_hash(91);
    let provider = DocsProvider::default();
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
        run_id: Some("canary-run".to_string()),
    })
    .unwrap();
    let docs = DocsSkillConnector::new(
        home.clone(),
        Arc::clone(&store),
        Arc::new(CanaryMail {
            bytes: format!("%PDF-1.4 {CANARY_BYTES}").into_bytes(),
            sha256: hash.clone(),
        }),
    );
    let mut session = attach_skill_runtime(
        session,
        auxd::skill_executor::SkillConnectors {
            docs: Some(docs),
            ..Default::default()
        },
        "assistant",
        workspace,
        Some("canary-run".to_string()),
        contacts,
    );
    let outcome = session.send("/collect-receipts").await.unwrap();
    assert_eq!(outcome.text, "ok");
    drop(session);

    // The provider saw the real collector report, and it carried no document
    // byte.
    let seen_after_collect = provider.seen.lock().unwrap().join("\n");
    assert!(
        seen_after_collect.contains("\"new\":1")
            || seen_after_collect.contains("\"new\": 1"),
        "the collector report must reach the provider, or the test is vacuous: {seen_after_collect}"
    );
    assert!(
        !seen_after_collect.contains(CANARY_BYTES),
        "the document bytes reached a provider: {seen_after_collect}"
    );

    // Real path 2: the daemon's authenticated extraction route, on the same
    // registry, with the OCR text bearing a second canary.
    std::fs::write(api::token_path(&home), TEST_TOKEN).unwrap();
    let handle = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            event_poll: Duration::from_millis(25),
            ..ApiOptions::default()
        },
    )
    .unwrap();
    let addr = handle.addr();
    let pending = call_at(
        addr,
        "GET",
        "/v1/docs/extract/pending?limit=1",
        Some(TEST_TOKEN),
        None,
    )
    .await;
    assert_eq!(pending.status, 200, "{}", pending.body);
    assert_eq!(
        pending_hashes(&pending),
        vec![hash.clone()],
        "{}",
        pending.body
    );
    let text = format!("Boulangerie Exemple\nTotal TTC 12,34 €\n{CANARY_OCR}\n");
    let body = serde_json::json!({ "extractor": "ocr", "text": text, "pages": 1 }).to_string();
    let posted = call_at(
        addr,
        "POST",
        &format!("/v1/docs/{hash}/extraction"),
        Some(TEST_TOKEN),
        Some(&body),
    )
    .await;
    assert_eq!(posted.status, 200, "{}", posted.body);
    handle.shutdown();

    assert!(
        !fields_json_of(&home, &hash).contains(CANARY_OCR),
        "the OCR text must not be copied into metadata"
    );
    assert_eq!(field_row(&home, &hash).total_minor, Some(1_234));
    let seen = provider.seen.lock().unwrap().join("\n");
    assert!(
        !seen.contains(CANARY_OCR),
        "the OCR canary reached a provider: {seen}"
    );
    assert!(!seen.contains(CANARY_BYTES), "{seen}");
}
