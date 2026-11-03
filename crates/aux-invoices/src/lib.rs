//! Invoice e-invoice parsing and deterministic totals checks.
//!
//! This crate is a pure library for the invoices product. It turns the bytes of
//! a Factur-X/ZUGFeRD CII or UBL XML document into a typed [`EInvoice`],
//! reconciles its totals and VAT with exact decimal arithmetic, and classifies
//! bytes by signature. It does no I/O, opens no file, makes no network call and
//! keeps no state. The evidence registry (originals, deduplication, provenance)
//! lives in the Auxesis app, which passes this crate bytes and reads back typed
//! results.
//!
//! Guarantees:
//!
//! * **Every input is tainted.** Each byte and string given to this crate is
//!   document content. The parser bounds size, depth and element count, checks
//!   the encoding, and refuses DOCTYPE declarations, so no entity is expanded.
//! * **Checks report, they never correct.** A totals or VAT mismatch is a
//!   [`ValidationIssue`] carrying the declared and calculated amounts. No
//!   source value is changed.
//! * **Deterministic.** The same bytes always give the same result: no clock,
//!   no randomness, no locale.
//! * **Silent.** The crate logs nothing and performs no I/O.

use sha2::{Digest, Sha256};

mod einvoice;
pub use einvoice::{
    parse_einvoice_xml, EInvoice, EInvoiceError, InvoiceLine, Party, TaxTotal, ValidationCheck,
    ValidationIssue, ValidationIssueKind,
};

/// Coarse capture ceiling for a document, in bytes.
///
/// This crate does not read it: the caller applies it before it reads a file
/// into memory. The e-invoice XML limit is enforced by the parser separately.
pub const MAX_ORIGINAL_BYTES: u64 = 32 * 1024 * 1024;

/// Length of a canonical lower-case SHA-256 hex digest.
const SHA256_HEX_LEN: usize = 64;

/// Lower-case SHA-256 hex of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(SHA256_HEX_LEN);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble is a hex digit"));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble is a hex digit"));
    }
    hex
}

/// `true` for the canonical lower-case SHA-256 hex shape.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Detect a MIME type from the bytes' **signature**, never the extension.
///
/// A `.txt` extension on `%PDF-` bytes is still `application/pdf`; the
/// caller's filename is metadata only and is never trusted for dispatch.
pub fn detect_mime(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"%PDF-") {
        return "application/pdf";
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "image/png";
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return "image/jpeg";
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return "image/gif";
    }
    if bytes.starts_with(b"II\x2a\x00") || bytes.starts_with(b"MM\x00\x2a") {
        return "image/tiff";
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP".as_slice() {
        return "image/webp";
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp".as_slice() {
        let brand = &bytes[8..12];
        if brand == b"heic".as_slice()
            || brand == b"heix".as_slice()
            || brand == b"hevc".as_slice()
            || brand == b"mif1".as_slice()
        {
            return "image/heic";
        }
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return "application/zip";
    }
    if looks_like_xml(bytes) {
        return "application/xml";
    }
    if !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok() {
        return "text/plain";
    }
    "application/octet-stream"
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    let body = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let body = trim_ascii_start(body);
    if body.starts_with(b"<?xml") {
        return true;
    }
    // A bare element: `<` followed by an XML name-start character.
    matches!(body.first(), Some(b'<'))
        && matches!(
            body.get(1),
            Some(byte) if byte.is_ascii_alphabetic() || *byte == b'_' || *byte == b':'
        )
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    &bytes[start..]
}

/// The totals and VAT reconciliation issues of a parsed invoice.
///
/// This is the single entry point for totals checks. [`parse_einvoice_xml`]
/// already runs them in exact decimal arithmetic and stores the result in
/// [`EInvoice::validation`], so this returns that result rather than
/// computing it a second time. The totals checks are `lines_equal_net` (the
/// line net amounts plus document allowances and charges equal the net
/// total), `gross_equals_net_plus_vat`, and `vat_by_rate` (each tax amount
/// equals rate × taxable amount, rounded half-up to 2 dp). The list also
/// carries the VAT-breakdown and line-arithmetic issues. An empty list means
/// the invoice reconciles.
///
/// The issues describe the document as it was parsed. Editing an `EInvoice`
/// afterwards does not re-run the checks.
pub fn check_totals(inv: &EInvoice) -> Vec<ValidationIssue> {
    inv.validation.issues.clone()
}
