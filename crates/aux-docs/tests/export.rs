//! M5-2 acceptance: a fixture XML receipt in the registry exports to a CSV row
//! and a byte-identical original, for an accountant. Fictional data only.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aux_docs::export::{export_receipts, ExportError, ExportOutcome, ExportRequest};
use aux_mail::{EvidenceAttachment, EvidenceSink};
use aux_store::{NewParty, PartyKind, Store};

const UBL: &str = r#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2">
<cbc:ID>FAC/2025/0042</cbc:ID><cbc:IssueDate>2025-09-12</cbc:IssueDate><cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
<cac:AccountingSupplierParty><cac:Party><cac:PartyName><cbc:Name>=Nordwind, "Studio"</cbc:Name></cac:PartyName></cac:Party></cac:AccountingSupplierParty>
<cac:AccountingCustomerParty><cac:Party><cac:PartyName><cbc:Name>Camille Exemple</cbc:Name></cac:PartyName></cac:Party></cac:AccountingCustomerParty>
<cac:TaxTotal><cbc:TaxAmount>20.05</cbc:TaxAmount><cac:TaxSubtotal><cbc:TaxableAmount>100.25</cbc:TaxableAmount><cbc:TaxAmount>20.05</cbc:TaxAmount><cbc:Percent>20</cbc:Percent></cac:TaxSubtotal></cac:TaxTotal>
<cac:LegalMonetaryTotal><cbc:TaxExclusiveAmount>100.25</cbc:TaxExclusiveAmount><cbc:PayableAmount>120.30</cbc:PayableAmount></cac:LegalMonetaryTotal>
<cac:InvoiceLine><cbc:ID>1</cbc:ID><cbc:InvoicedQuantity>1</cbc:InvoicedQuantity><cbc:LineExtensionAmount>100.25</cbc:LineExtensionAmount><cac:Item><cbc:Description>Design</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>20</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>100.25</cbc:PriceAmount></cac:Price></cac:InvoiceLine>
</Invoice>"#;

/// A temp home whose registry holds the fixture receipt, linked to a party.
struct World(tempfile::TempDir, Arc<Mutex<Store>>, i64, String);

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(dir.path().join("out")).unwrap();
        let store = Store::open(&kernel_core::store_path(&home)).unwrap();
        let name = "Camille Exemple".to_string();
        let new = NewParty {
            kind: PartyKind::Company,
            display_name: name,
            origin: "owner".into(),
            ..NewParty::default()
        };
        let party = store.insert_party(&new).unwrap();
        let store = Arc::new(Mutex::new(store));
        let bytes = UBL.as_bytes().to_vec();
        let sha256 = aux_invoices::sha256_hex(&bytes);
        let attachment = EvidenceAttachment {
            sha256: sha256.clone(),
            file_name: "facture.XML".into(),
            mime: "application/xml".into(),
            size: bytes.len(),
            bytes,
            account: "personal".into(),
            folder: "INBOX".into(),
            uid: 1,
            message_id: "<1@fixture.test>".into(),
            part: "2".into(),
        };
        aux_docs::StoreEvidence::new(&home, Arc::clone(&store))
            .append(attachment)
            .unwrap();
        let (now, cutoff) = ("2026-10-20T10:00:00Z", "2026-10-20T09:50:00Z");
        let window = aux_docs::ExtractWindow {
            now,
            cutoff,
            private: false,
        };
        aux_docs::sweep_unprocessed(&store.lock().unwrap(), &home, window).unwrap();
        World(dir, store, party, sha256)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.path().join(name)
    }

    fn export(
        &self,
        from: &str,
        to: &str,
        client: Option<i64>,
        out: &Path,
    ) -> Result<ExportOutcome, ExportError> {
        let request = ExportRequest {
            from,
            to,
            client,
            out,
        };
        export_receipts(&self.1.lock().unwrap(), &self.path("home"), &request)
    }
}

#[test]
fn a_receipt_exports_to_a_csv_row_and_its_identical_original() {
    let world = World::new();
    let out = world.path("out");
    let outcome = world
        .export("2025-09-01", "2025-09-30", Some(world.2), &out)
        .unwrap();
    let folder = out
        .canonicalize()
        .unwrap()
        .join("auxesis-receipts-2025-09-01-2025-09-30");
    assert_eq!(
        outcome,
        ExportOutcome::Written {
            folder: folder.clone(),
            rows: 1,
            missing: 0
        }
    );
    let csv = std::fs::read_to_string(folder.join("receipts.csv")).unwrap();
    assert_eq!(
        csv,
        "date,number,issuer,client,currency,total,vat,checks,file\r\n\
         2025-09-12,FAC/2025/0042,\"'=Nordwind, \"\"Studio\"\"\",Camille Exemple,EUR,120.30,20.05,\
         \"passed: totals, vat, duplicate, party_match\",originals/2025-09-12_FAC-2025-0042.xml\r\n"
    );
    let original = std::fs::read(folder.join("originals/2025-09-12_FAC-2025-0042.xml")).unwrap();
    assert_eq!(original, UBL.as_bytes());
    assert_eq!(aux_invoices::sha256_hex(&original), world.3);

    // A second run never overwrites, and the error names the folder.
    let again = world
        .export("2025-09-01", "2025-09-30", None, &out)
        .unwrap_err();
    assert!(matches!(again, ExportError::Exists(_)));
    assert!(
        again
            .to_string()
            .contains("auxesis-receipts-2025-09-01-2025-09-30"),
        "{again}"
    );
}

#[test]
fn an_empty_period_reports_nothing_exported_and_writes_nothing() {
    let world = World::new();
    let out = world.path("out");
    let outcome = world
        .export("2025-10-01", "2025-10-31", None, &out)
        .unwrap();
    let message = "No documents between 2025-10-01 and 2025-10-31; nothing exported.".to_string();
    assert_eq!(outcome, ExportOutcome::Empty { message });
    assert!(
        std::fs::read_dir(&out).unwrap().next().is_none(),
        "an empty period writes no folder and no header-only CSV"
    );
}

#[test]
fn an_existing_empty_export_folder_is_reused() {
    let world = World::new();
    let out = world.path("out");
    let name = "auxesis-receipts-2025-09-01-2025-09-30";
    let folder = out.join(name);
    std::fs::create_dir(&folder).unwrap();
    let outcome = world
        .export("2025-09-01", "2025-09-30", None, &out)
        .unwrap();
    assert_eq!(
        outcome,
        ExportOutcome::Written {
            folder: out.canonicalize().unwrap().join(name),
            rows: 1,
            missing: 0
        }
    );
    assert!(folder.join("receipts.csv").is_file());
    assert!(folder.join("originals").is_dir());
}

#[test]
fn an_existing_non_empty_export_folder_is_refused_and_left_alone() {
    let world = World::new();
    let out = world.path("out");
    let name = "auxesis-receipts-2025-09-01-2025-09-30";
    let folder = out.join(name);
    std::fs::create_dir(&folder).unwrap();
    let owner_file = folder.join("owner-notes.txt");
    std::fs::write(&owner_file, b"do not touch").unwrap();
    let err = world
        .export("2025-09-01", "2025-09-30", None, &out)
        .unwrap_err();
    let ExportError::Exists(path) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(path, &folder.canonicalize().unwrap());
    let message = err.to_string();
    assert!(message.contains(name), "{message}");
    assert!(message.contains("new --out folder"), "{message}");
    assert_eq!(std::fs::read(&owner_file).unwrap(), b"do not touch");
    assert!(!folder.join("receipts.csv").exists());
    assert!(!folder.join("originals").exists());
}

#[test]
fn edge_cases_refuse_without_writing() {
    let world = World::new();
    let out = world.path("out");
    std::os::unix::fs::symlink(&out, world.path("link")).unwrap();
    let refusals = [
        (
            "2025-09-30",
            "2025-09-01",
            None,
            out.clone(),
            "start date is after",
        ),
        ("2025-9-1", "2025-09-30", None, out.clone(), "YYYY-MM-DD"),
        (
            "2025-09-01",
            "2025-09-30",
            Some(world.2 + 99),
            out.clone(),
            "no client with id",
        ),
        (
            "2025-09-01",
            "2025-09-30",
            None,
            PathBuf::from("out"),
            "absolute directory",
        ),
        (
            "2025-09-01",
            "2025-09-30",
            None,
            world.path("link"),
            "not a link",
        ),
        (
            "2025-09-01",
            "2025-09-30",
            None,
            world.path("home"),
            "outside the Auxesis home",
        ),
    ];
    for (from, to, client, dir, why) in refusals {
        let err = world.export(from, to, client, &dir).unwrap_err();
        assert!(
            matches!(&err, ExportError::Refused(text) if text.contains(why)),
            "{err}"
        );
    }
    assert!(
        std::fs::read_dir(&out).unwrap().next().is_none(),
        "nothing was written"
    );
}

#[test]
fn a_missing_original_keeps_its_row_and_is_counted() {
    let world = World::new();
    std::fs::remove_file(world.path("home/evidence").join(&world.3)).unwrap();
    let outcome = world
        .export("2025-09-12", "2025-09-12", None, &world.path("out"))
        .unwrap();
    let ExportOutcome::Written {
        folder,
        rows: 1,
        missing: 1,
    } = outcome
    else {
        panic!("{outcome:?}");
    };
    let csv = std::fs::read_to_string(folder.join("receipts.csv")).unwrap();
    assert!(csv.ends_with(",(missing)\r\n"), "{csv}");
}
