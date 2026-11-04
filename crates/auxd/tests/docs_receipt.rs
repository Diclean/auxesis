//! The demo receipt is a real PDF, and the extractor reads it.
//!
//! The demo mailbox used to attach a `%PDF-1.4` header followed by plain
//! text: not a PDF at all, so the Mac bridge (PDFKit) refused it and the
//! document stayed empty ("other, no total"). The receipt's text layer now
//! parses into the fields the owner asks about — 120.00 EUR, invoice VF-2210,
//! dated 2026-10-14 — with the daemon's own extractor. The Mac's own PDFKit
//! reads the same bytes: the live acceptance in `qa/acceptance/receipt.rs`.

use aux_docs::{extract_text, DocKind, Extractor};

fn receipt_pdf() -> String {
    let receipt = aux_fakemail::demo_mailbox(1_800_000_000)
        .into_iter()
        .find(|mail| mail.subject.contains("VF-2210"))
        .expect("the demo mailbox holds the receipt for VF-2210");
    receipt
        .parts
        .iter()
        .find(|(part, _)| part == "2")
        .map(|(_, bytes)| bytes.clone())
        .expect("the receipt carries a PDF part")
}

/// The text layer of the demo PDF: the strings its content stream shows.
/// A reader for this fixture only; PDFKit on the Mac is the real extractor.
fn pdf_text_layer(pdf: &str) -> String {
    let stream = pdf
        .split_once("stream\r\n")
        .expect("the PDF has a content stream")
        .1
        .split_once("endstream")
        .expect("the content stream ends")
        .0;
    stream
        .split(") Tj")
        .filter_map(|chunk| chunk.rfind('(').map(|start| chunk[start + 1..].to_string()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The receipt's own fields, read by the daemon's extractor.
#[test]
fn the_demo_receipt_is_extracted_with_its_amount_number_and_date() {
    let text = pdf_text_layer(&receipt_pdf());
    assert_eq!(
        text, "Verdant Billing\nInvoice VF-2210 - 2026-10-14\nDate 14 Oct 2026\nTotal 120.00 EUR",
        "the text layer of the demo receipt"
    );
    let fields = extract_text(&text, Some(1), Extractor::PdfText).fields;
    assert_eq!(fields.kind, DocKind::Invoice);
    assert_eq!(fields.issuer.as_deref(), Some("Verdant Billing"));
    assert_eq!(fields.number.as_deref(), Some("VF-2210"));
    assert_eq!(fields.issued_on.as_deref(), Some("2026-10-14"));
    assert_eq!(fields.currency.as_deref(), Some("EUR"));
    assert_eq!(
        fields.total_minor,
        Some(12_000),
        "120.00 EUR in minor units"
    );
}
