//! Documents: the receipts collector, the extractor chain and the evidence registry.
//!
//! The collector walks recent mail through the existing `aux-mail`
//! read path, keeps the MIME types the mail download allows, and appends each
//! part to the local evidence registry. The extractor chain ([`extract`]) and
//! its durable bridge queue ([`queue`]) parse XML in Rust through
//! `aux-invoices`, and anything else waits for the Mac bridge, which posts
//! PDFKit text or Vision OCR back over the authenticated local API. There is no
//! in-process PDF parser.
//!

pub mod collector;
pub mod evidence;
pub mod export;
pub mod extract;
pub mod queue;

pub use collector::{
    run_collect_receipts, CollectError, CollectReport, ReceiptCollector, SkippedReceipt,
};
pub use evidence::{
    erase_document, migrate_blobs, recover_erased_evidence, EraseError, StoreEvidence,
};
pub use extract::{
    decimal_string_to_minor, extract_text, extract_xml, is_lowercase_sha256, is_xml, party_match,
    sensitive_kind, Check, CheckState, DocKind, ExtractError, Extracted, Extractor, Fields,
    PartyMatch, PartyRef,
};
pub use queue::{
    claim_cutoff, claimed_blob, link_document, store_text_extraction, sweep_and_claim,
    sweep_unprocessed, ClaimedBlob, ExtractWindow, LinkError, PendingDocument, QueueError,
    StoredExtraction, MAX_TEXT_BYTES,
};
