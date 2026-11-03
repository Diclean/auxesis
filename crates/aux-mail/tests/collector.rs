//! C1 acceptance: fixture mail lands in the evidence registry (fake IMAP).
//!
//! Lives in aux-mail's own tests so the offline TLS seam may be named by this
//! crate's dev-dependency self-reference (`scripts/check-egress.sh`). The fake
//! binds `127.0.0.1:0` and the store lives under a temp home; no socket leaves
//! the machine. The people and companies are fictional.

use std::path::Path;
use std::sync::{Arc, Mutex};

use aux_docs::{ReceiptCollector, StoreEvidence};
use aux_fakemail::{FakeImap, RawMessage, StaticCredentials};
use aux_mail::config::{FolderMap, ImapSettings, MailAccount, Security};
use aux_mail::dial::Dialer;
use aux_mail::imap_read::MailService;
use aux_mail::limits::Limits;
use aux_mail::{EvidenceSink, MailApi};

/// A body canary planted in every message's text part. It must never reach the
/// registry: only attachment bytes are stored.
const BODY_CANARY: &str = "CANARY-BODY-NORTHWIND";

const PDF_BYTES: &str = "%PDF-1.4 receipt fixture - Northwind Studio\r\n";
const XML_BYTES: &str = "<Invoice><Seller>Northwind Studio</Seller></Invoice>\r\n";
const JPG_BYTES: &str = "JPEG fake scan - Northwind Studio\r\n";
const ZIP_BYTES: &str = "PK\u{3}\u{4}fakezip";

const TEXT_PDF: &str = "CANARY-BODY-NORTHWIND invoice body\r\n";
const TEXT_XML: &str = "CANARY-BODY-NORTHWIND xml body\r\n";
const TEXT_SCAN: &str = "CANARY-BODY-NORTHWIND scan body\r\n";

const BODY_INVOICE: &str = "From: Northwind Studio <billing@northwind.test>\r\n\
    To: me@example.org\r\n\
    Subject: Invoice 2025-001\r\n\
    MIME-Version: 1.0\r\n\
    Content-Type: multipart/mixed; boundary=\"aux-receipts\"\r\n\
    \r\n\
    --aux-receipts\r\n\
    Content-Type: text/plain; charset=UTF-8\r\n\
    \r\n\
    CANARY-BODY-NORTHWIND invoice body\r\n\
    --aux-receipts\r\n\
    Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
    Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
    Content-Transfer-Encoding: 7bit\r\n\
    \r\n\
    %PDF-1.4 receipt fixture - Northwind Studio\r\n\
    --aux-receipts\r\n\
    Content-Type: application/pdf; name=\"invoice-copy.pdf\"\r\n\
    Content-Disposition: attachment; filename=\"invoice-copy.pdf\"\r\n\
    Content-Transfer-Encoding: 7bit\r\n\
    \r\n\
    %PDF-1.4 receipt fixture - Northwind Studio\r\n\
    --aux-receipts--\r\n";

const BODY_XML: &str = "From: Northwind Studio <billing@northwind.test>\r\n\
    To: me@example.org\r\n\
    Subject: Factur-X 2025-002\r\n\
    MIME-Version: 1.0\r\n\
    Content-Type: multipart/mixed; boundary=\"aux-receipts\"\r\n\
    \r\n\
    --aux-receipts\r\n\
    Content-Type: text/plain; charset=UTF-8\r\n\
    \r\n\
    CANARY-BODY-NORTHWIND xml body\r\n\
    --aux-receipts\r\n\
    Content-Type: application/xml; name=\"factur-x.xml\"\r\n\
    Content-Disposition: attachment; filename=\"factur-x.xml\"\r\n\
    Content-Transfer-Encoding: 7bit\r\n\
    \r\n\
    <Invoice><Seller>Northwind Studio</Seller></Invoice>\r\n\
    --aux-receipts--\r\n";

const BODY_SCAN: &str = "From: Northwind Studio <billing@northwind.test>\r\n\
    To: me@example.org\r\n\
    Subject: Scan 2025-003\r\n\
    MIME-Version: 1.0\r\n\
    Content-Type: multipart/mixed; boundary=\"aux-receipts\"\r\n\
    \r\n\
    --aux-receipts\r\n\
    Content-Type: text/plain; charset=UTF-8\r\n\
    \r\n\
    CANARY-BODY-NORTHWIND scan body\r\n\
    --aux-receipts\r\n\
    Content-Type: image/jpeg; name=\"scan.jpg\"\r\n\
    Content-Disposition: attachment; filename=\"scan.jpg\"\r\n\
    Content-Transfer-Encoding: 7bit\r\n\
    \r\n\
    JPEG fake scan - Northwind Studio\r\n\
    --aux-receipts\r\n\
    Content-Type: application/zip; name=\"archive.zip\"\r\n\
    Content-Disposition: attachment; filename=\"archive.zip\"\r\n\
    Content-Transfer-Encoding: 7bit\r\n\
    \r\n\
    PK\u{3}\u{4}fakezip\r\n\
    --aux-receipts--\r\n";

const BS_INVOICE: &str = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 64 1)\
 (\"APPLICATION\" \"PDF\" (\"NAME\" \"invoice.pdf\") NIL NIL \"7BIT\" 64 NIL (\"ATTACHMENT\" (\"FILENAME\" \"invoice.pdf\")) NIL)\
 (\"APPLICATION\" \"PDF\" (\"NAME\" \"invoice-copy.pdf\") NIL NIL \"7BIT\" 64 NIL (\"ATTACHMENT\" (\"FILENAME\" \"invoice-copy.pdf\")) NIL) \
 \"MIXED\" (\"BOUNDARY\" \"aux-receipts\") NIL NIL)";

const BS_XML: &str = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 64 1)\
 (\"APPLICATION\" \"XML\" (\"NAME\" \"factur-x.xml\") NIL NIL \"7BIT\" 64 NIL (\"ATTACHMENT\" (\"FILENAME\" \"factur-x.xml\")) NIL) \
 \"MIXED\" (\"BOUNDARY\" \"aux-receipts\") NIL NIL)";

const BS_SCAN: &str = "((\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 64 1)\
 (\"IMAGE\" \"JPEG\" (\"NAME\" \"scan.jpg\") NIL NIL \"7BIT\" 64 NIL (\"ATTACHMENT\" (\"FILENAME\" \"scan.jpg\")) NIL)\
 (\"APPLICATION\" \"ZIP\" (\"NAME\" \"archive.zip\") NIL NIL \"7BIT\" 64 NIL (\"ATTACHMENT\" (\"FILENAME\" \"archive.zip\")) NIL) \
 \"MIXED\" (\"BOUNDARY\" \"aux-receipts\") NIL NIL)";

fn message(
    uid: u32,
    message_id: &str,
    subject: &str,
    body: &'static str,
    bodystructure: &'static str,
    parts: Vec<(&'static str, &'static str)>,
) -> RawMessage {
    RawMessage {
        uid,
        message_id: message_id.to_string(),
        subject: subject.to_string(),
        from: "Northwind Studio <billing@northwind.test>".to_string(),
        to: vec!["me@example.org".to_string()],
        cc: Vec::new(),
        date: aux_fakemail::fixture_date(),
        body,
        flags: Vec::new(),
        bodystructure: Some(bodystructure),
        parts,
        in_reply_to: None,
    }
}

/// Three mails: a PDF with an identical duplicate part, an XML, an image plus
/// one disallowed type.
fn fixtures() -> Vec<RawMessage> {
    vec![
        message(
            1,
            "<invoice@northwind.test>",
            "Invoice 2025-001",
            BODY_INVOICE,
            BS_INVOICE,
            vec![("1", TEXT_PDF), ("2", PDF_BYTES), ("3", PDF_BYTES)],
        ),
        message(
            2,
            "<facturx@northwind.test>",
            "Factur-X 2025-002",
            BODY_XML,
            BS_XML,
            vec![("1", TEXT_XML), ("2", XML_BYTES)],
        ),
        message(
            3,
            "<scan@northwind.test>",
            "Scan 2025-003",
            BODY_SCAN,
            BS_SCAN,
            vec![("1", TEXT_SCAN), ("2", JPG_BYTES), ("3", ZIP_BYTES)],
        ),
    ]
}

fn account(fake: &FakeImap) -> MailAccount {
    MailAccount {
        id: "personal".to_string(),
        email: "me@example.org".to_string(),
        display: None,
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: fake.port,
            security: Security::Tls,
            username: None,
            ca_file: None,
        },
        smtp: None,
        folders: FolderMap::default(),
        only_folders: vec!["INBOX".to_string()],
    }
}

fn service(fake: &FakeImap) -> MailService {
    let cert = fake.cert().expect("the TLS fake has a cert");
    let limits = Limits::default();
    MailService::new(
        Dialer::with_client_config(cert.client_config(), limits.connect_timeout),
        limits,
        vec![account(fake)],
        Arc::new(StaticCredentials::new("personal", "secret")),
    )
}

fn home_with_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    (dir, home)
}

fn count(home: &Path, table: &str) -> i64 {
    let conn = aux_store::open_keyed_readonly(&kernel_core::store_path(home)).unwrap();
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn sources(home: &Path) -> Vec<String> {
    let conn = aux_store::open_keyed_readonly(&kernel_core::store_path(home)).unwrap();
    let mut stmt = conn
        .prepare("SELECT source FROM evidence_source ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows
}

/// Every text column of the two registry tables, for the canary check.
fn store_text(home: &Path) -> String {
    let conn = aux_store::open_keyed_readonly(&kernel_core::store_path(home)).unwrap();
    let mut out = String::new();
    for table in ["documents", "evidence_source"] {
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let columns = stmt.column_count();
        let rows = stmt
            .query_map([], |row| {
                let mut line = String::new();
                for index in 0..columns {
                    if let Ok(text) = row.get::<_, String>(index) {
                        line.push_str(&text);
                    }
                }
                Ok(line)
            })
            .unwrap();
        for row in rows {
            out.push_str(&row.unwrap());
        }
    }
    out
}

fn blob_bytes(home: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(home.join("evidence")).unwrap() {
        out.push(std::fs::read(entry.unwrap().path()).unwrap());
    }
    out
}

#[tokio::test]
async fn fixture_receipts_land_in_the_registry_once_each_with_source_refs() {
    let fake = FakeImap::spawn_tls(fixtures()).await;
    let (_dir, home) = home_with_config();
    let store = Arc::new(Mutex::new(
        aux_store::Store::open(&kernel_core::store_path(&home)).unwrap(),
    ));
    let evidence: Arc<dyn EvidenceSink> = Arc::new(StoreEvidence::new(home.clone(), store));
    let mail: Arc<dyn MailApi> = Arc::new(service(&fake));
    let collector = ReceiptCollector::new(mail, evidence);

    let report = collector
        .collect("personal", "INBOX", 30, 0)
        .await
        .expect("collect");

    assert_eq!(report.messages, 3, "three fixture mails");
    assert_eq!(report.new, 3, "pdf, xml and jpg are new");
    assert_eq!(
        report.deduplicated, 1,
        "the identical PDF part is a duplicate"
    );
    assert_eq!(report.skipped.len(), 1, "the zip is refused");
    assert_eq!(report.skipped[0].mime, "application/zip");
    assert!(report.skipped[0].reason.contains("not allowed"));
    assert!(report.to_json().contains("\"new\":3"));

    assert_eq!(count(&home, "documents"), 3, "one document per hash");
    assert_eq!(
        count(&home, "evidence_source"),
        4,
        "the duplicate keeps its own source"
    );

    let sources = sources(&home);
    assert!(sources.iter().any(|source| {
        source.contains("\"account\":\"personal\"")
            && source.contains("\"folder\":\"INBOX\"")
            && source.contains("\"uid\":1")
            && source.contains("\"part\":\"2\"")
            && source.contains("\"file_name\":\"invoice.pdf\"")
            && source.contains("\"message_id\":\"<invoice@northwind.test>\"")
    }));
    assert!(sources
        .iter()
        .any(|source| source.contains("\"part\":\"3\"") && source.contains("invoice-copy.pdf")));
    assert!(sources
        .iter()
        .any(|source| source.contains("factur-x.xml") && source.contains("\"uid\":2")));
    assert!(sources
        .iter()
        .any(|source| source.contains("scan.jpg") && source.contains("\"uid\":3")));

    // No body byte reaches the registry: neither a stored blob nor a row.
    let blobs = blob_bytes(&home);
    assert_eq!(blobs.len(), 3, "one blob per document");
    assert!(
        !blobs
            .iter()
            .any(|bytes| String::from_utf8_lossy(bytes).contains(BODY_CANARY)),
        "a body canary reached a blob"
    );
    assert!(
        !store_text(&home).contains(BODY_CANARY),
        "a body canary reached a registry row"
    );
}

#[tokio::test]
async fn a_second_run_is_idempotent() {
    let fake = FakeImap::spawn_tls(fixtures()).await;
    let (_dir, home) = home_with_config();
    let store = Arc::new(Mutex::new(
        aux_store::Store::open(&kernel_core::store_path(&home)).unwrap(),
    ));
    let evidence: Arc<dyn EvidenceSink> = Arc::new(StoreEvidence::new(home.clone(), store));
    let mail: Arc<dyn MailApi> = Arc::new(service(&fake));
    let collector = ReceiptCollector::new(mail, evidence);

    collector
        .collect("personal", "INBOX", 30, 0)
        .await
        .expect("first run");
    let second = collector
        .collect("personal", "INBOX", 30, 0)
        .await
        .expect("second run");

    assert_eq!(second.messages, 3);
    assert_eq!(second.new, 0, "nothing new on the second run");
    assert_eq!(second.deduplicated, 4, "every part is already known");
    assert_eq!(second.skipped.len(), 1);
    assert_eq!(count(&home, "documents"), 3, "still one document per hash");
    assert_eq!(
        count(&home, "evidence_source"),
        4,
        "the same provenance is not appended twice"
    );
}
