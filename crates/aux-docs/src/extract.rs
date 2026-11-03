//! The extractor chain and the checks (Wave C / C2b).
//!
//! The chain is deterministic and local: **XML in Rust** through
//! `aux-invoices` (Factur-X/ZUGFeRD CII and UBL e-invoices), then the **Mac
//! bridge** (`pdf_text` first, `ocr` second) over the authenticated local API,
//! then **none**. There is deliberately no in-process PDF parser: hostile mail
//! PDFs are parsed by PDFKit on the Mac, never by a Rust crate (D25/D26).
//!
//! Everything here is pure: bytes or text in, typed fields and checks out. No
//! model is ever asked to read a document. Amounts are integer minor units,
//! converted from `rust_decimal`'s exact decimal string, never floats.

use serde::{Deserialize, Serialize};

use aux_invoices::{check_totals, EInvoice, EInvoiceError, TaxTotal};

/// Which extractor produced a field set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Extractor {
    /// XML through `aux-invoices`.
    Xml,
    /// Native PDF text from the Mac bridge (PDFKit).
    PdfText,
    /// OCR text from the Mac bridge (Vision).
    Ocr,
    /// No extractor; the fields are empty.
    #[default]
    None,
}

impl Extractor {
    /// The stored spelling (`xml` | `pdf_text` | `ocr` | `none`).
    pub fn as_str(self) -> &'static str {
        match self {
            Extractor::Xml => "xml",
            Extractor::PdfText => "pdf_text",
            Extractor::Ocr => "ocr",
            Extractor::None => "none",
        }
    }

    /// Parse a stored spelling.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "xml" => Some(Extractor::Xml),
            "pdf_text" => Some(Extractor::PdfText),
            "ocr" => Some(Extractor::Ocr),
            "none" => Some(Extractor::None),
            _ => None,
        }
    }
}

/// What kind of document the fields describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocKind {
    /// An invoice (XML e-invoice, or a text that calls itself one).
    Invoice,
    /// A receipt or till slip.
    Receipt,
    /// Not classified.
    #[default]
    Other,
    /// An ID card, passport (MRZ) or driving licence (DOC-SAFE-1).
    IdDocument,
    /// A bank or account statement (DOC-SAFE-1).
    BankStatement,
    /// A medical document: report, prescription, sick note (DOC-SAFE-1).
    Health,
}

impl DocKind {
    /// The stored spelling (`invoice` | `receipt` | `other`).
    pub fn as_str(self) -> &'static str {
        match self {
            DocKind::Invoice => "invoice",
            DocKind::Receipt => "receipt",
            DocKind::Other => "other",
            DocKind::IdDocument => "id_document",
            DocKind::BankStatement => "bank_statement",
            DocKind::Health => "health",
        }
    }

    /// The `document_fields.kind` column value. The v23 column takes only
    /// `invoice` | `receipt` | `other`, so a sensitive class is stored as
    /// `other` and kept exactly in `fields_json`.
    pub fn stored(self) -> &'static str {
        match self {
            DocKind::Invoice | DocKind::Receipt => self.as_str(),
            _ => "other",
        }
    }
}

/// Classify text by local rules only. A class wins on one strong signal (an
/// MRZ line, or a heading that opens one of the first three lines, even under
/// an invoice or receipt title) or on two
/// different whole-word phrases of its list anywhere, so one stray word such as
/// "patient" or "passeport" on an invoice classes nothing. `None` when the text
/// is not a sensitive class. ID wins over health, health over bank.
pub fn sensitive_kind(text: &str) -> Option<DocKind> {
    let normalized = normalize_text(text);
    let heads: Vec<String> = normalized
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(3)
        .map(words)
        .collect();
    let wins = |titles: &str, list: &str| {
        let mut titles = titles.split('|').map(words);
        titles.any(|t| heads.iter().any(|h| h.starts_with(&t)))
            || list
                .split('|')
                .filter(|p| contains_word(&normalized, p))
                .count()
                >= 2
    };
    let mrz = text.lines().map(str::trim).any(|line| {
        matches!(line.len(), 30 | 36 | 44)
            && line.contains("<<")
            && line
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'<')
    });
    if mrz || wins(ID_WORDS, ID_WORDS) {
        Some(DocKind::IdDocument)
    } else if wins(HEALTH_TITLES, HEALTH_WORDS) {
        Some(DocKind::Health)
    } else if wins(BANK_TITLES, BANK_WORDS) {
        Some(DocKind::BankStatement)
    } else {
        None
    }
}

/// `text` lowercased as ` word word `: one space around each alphanumeric run,
/// so a phrase matches whole words only ("patient" never inside "impatient").
fn words(text: &str) -> String {
    let lower = text.to_lowercase();
    let mut out = String::from(" ");
    for token in lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
    {
        out.push_str(token);
        out.push(' ');
    }
    out
}

// Lowercase phrases, `|`-separated, matched as whole words. A title opens a
// line; any ID phrase is also a title.
const ID_WORDS: &str =
    "passport|passeport|identity card|carte d'identité|carte nationale d'identité|\
    driving licence|driver's license|driver license|permis de conduire";
const HEALTH_WORDS: &str = "medical report|compte rendu médical|patient|diagnosis|\
    prescription|ordonnance|sick note|arrêt de travail|carte vitale";
const HEALTH_TITLES: &str = "medical report|compte rendu médical|prescription|ordonnance|\
    sick note|arrêt de travail";
const BANK_TITLES: &str =
    "bank statement|account statement|relevé de compte|relevé bancaire|kontoauszug";
const BANK_WORDS: &str = "bank statement|account statement|relevé de compte|relevé bancaire|\
    kontoauszug|opening balance|closing balance|ancien solde|nouveau solde";

/// The tri-state result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckState {
    /// The check ran and reconciled.
    Pass,
    /// The check ran and found a problem.
    Fail,
    /// The check could not run (no data, or no comparison basis).
    Unknown,
}

/// One check, with a short reason that never carries a document body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// `totals` | `vat` | `duplicate` | `party_match`.
    pub name: String,
    /// `pass` | `fail` | `unknown`.
    pub state: CheckState,
    /// A short, deterministic reason.
    pub reason: String,
}

impl Check {
    fn new(name: &str, state: CheckState, reason: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            state,
            reason: reason.into(),
        }
    }
}

/// The fields of one extracted document, matching the `document_fields`
/// columns plus the JSON-only extras.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Fields {
    /// The document kind.
    pub kind: DocKind,
    /// The extractor that produced the fields.
    pub extractor: Extractor,
    /// Seller/issuer name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Buyer/recipient name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// ISO `YYYY-MM-DD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_on: Option<String>,
    /// ISO 4217 code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Total including VAT, in minor units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_minor: Option<i64>,
    /// VAT amount, in minor units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vat_minor: Option<i64>,
    /// Human invoice/receipt number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    /// Total excluding VAT, in minor units (XML only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_minor: Option<i64>,
    /// `UBL` or `CII` (XML only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Seller VAT identifier (XML only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seller_vat_id: Option<String>,
    /// Buyer VAT identifier (XML only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_vat_id: Option<String>,
    /// Number of pages the bridge reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages: Option<u32>,
}

impl Fields {
    /// The field set to persist in Private mode (privacy row G5): metadata
    /// only. Amounts, dates, number and the matched party id survive; every
    /// free-text field — issuer, recipient and VAT identifiers — is dropped.
    pub fn metadata_only(&self) -> Fields {
        let mut sanitized = self.clone();
        sanitized.issuer = None;
        sanitized.recipient = None;
        sanitized.seller_vat_id = None;
        sanitized.buyer_vat_id = None;
        sanitized
    }
}

/// One extraction: the fields and the checks that ran on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// The fields.
    pub fields: Fields,
    /// The checks (`totals` and `vat`; `duplicate` and `party_match` are added
    /// by the store-backed stage).
    pub checks: Vec<Check>,
}

/// A failure of the pure extractor.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtractError {
    /// The XML is not a supported e-invoice.
    #[error("not a supported e-invoice: {0}")]
    Xml(#[from] EInvoiceError),
}

/// True when the bytes look like XML by signature, never by extension.
pub fn is_xml(bytes: &[u8]) -> bool {
    aux_invoices::detect_mime(bytes) == "application/xml"
}

/// `true` for a canonical lower-case SHA-256 hex digest.
pub fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The XML leg of the chain: parse an e-invoice and map it to fields and the
/// totals/VAT checks. Party and duplicate checks are added later, against the
/// CRM and the store.
pub fn extract_xml(bytes: &[u8]) -> Result<Extracted, ExtractError> {
    let invoice = aux_invoices::parse_einvoice_xml(bytes)?;
    Ok(extracted_from_einvoice(&invoice))
}

fn extracted_from_einvoice(invoice: &EInvoice) -> Extracted {
    let total_minor = decimal_string_to_minor(&invoice.gross_total.to_string());
    let net_minor = decimal_string_to_minor(&invoice.net_total.to_string());
    let (vat_minor, vat_conversion_failed) = sum_vat_minor(&invoice.tax_totals);
    let fields = Fields {
        kind: DocKind::Invoice,
        extractor: Extractor::Xml,
        issuer: non_empty(&invoice.seller.name),
        recipient: non_empty(&invoice.buyer.name),
        issued_on: non_empty(&invoice.invoice_date),
        currency: non_empty(&invoice.currency),
        total_minor,
        vat_minor,
        number: non_empty(&invoice.invoice_number),
        net_minor,
        format: non_empty(&invoice.format),
        seller_vat_id: invoice.seller.vat_id.clone(),
        buyer_vat_id: invoice.buyer.vat_id.clone(),
        pages: None,
    };
    let issues = check_totals(invoice);
    let totals_issue = issues.iter().find(|issue| {
        matches!(
            issue.check,
            "lines_equal_net" | "gross_equals_net_plus_vat" | "line_quantity_times_unit_price"
        )
    });
    let totals = match totals_issue {
        Some(issue) => Check::new(
            "totals",
            CheckState::Fail,
            format!(
                "{}: declared {}, calculated {}",
                issue.check, issue.declared, issue.calculated
            ),
        ),
        None => Check::new("totals", CheckState::Pass, "totals reconcile"),
    };
    let vat_issue = issues.iter().find(|issue| {
        !matches!(
            issue.check,
            "lines_equal_net" | "gross_equals_net_plus_vat" | "line_quantity_times_unit_price"
        )
    });
    let vat = if vat_conversion_failed {
        Check::new(
            "vat",
            CheckState::Unknown,
            "a declared VAT amount could not be converted exactly",
        )
    } else {
        match vat_issue {
            Some(issue) => Check::new(
                "vat",
                CheckState::Fail,
                format!(
                    "{}: declared {}, calculated {}",
                    issue.check, issue.declared, issue.calculated
                ),
            ),
            None => Check::new("vat", CheckState::Pass, "VAT reconciles"),
        }
    };
    Extracted {
        fields,
        checks: vec![totals, vat],
    }
}

/// Sum the declared VAT amounts in exact minor units. `(None, true)` when any
/// declared amount cannot be converted: VAT is then unknown, never a silently
/// dropped value.
fn sum_vat_minor(tax_totals: &[TaxTotal]) -> (Option<i64>, bool) {
    if tax_totals.is_empty() {
        return (None, false);
    }
    let converted = tax_totals
        .iter()
        .map(|tax| decimal_string_to_minor(&tax.tax_amount.to_string()));
    match checked_sum(converted) {
        Some(total) => (Some(total), false),
        None => (None, true),
    }
}

/// Sum optional minor amounts with checked addition. A missing value (a failed
/// conversion) or an overflow makes the whole sum unknown.
fn checked_sum(values: impl IntoIterator<Item = Option<i64>>) -> Option<i64> {
    let mut total = 0i64;
    for value in values {
        total = total.checked_add(value?)?;
    }
    Some(total)
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Convert `rust_decimal`'s exact decimal string to integer minor units
/// (half-up on the third fractional digit). Integer arithmetic only, so an
/// amount can never drift through a float.
pub fn decimal_string_to_minor(raw: &str) -> Option<i64> {
    let value = raw.trim();
    let (negative, value) = match value.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let (integer, fraction) = value.split_once('.').unwrap_or((value, ""));
    if integer.is_empty()
        || !integer.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 6
    {
        return None;
    }
    let whole: i128 = integer.parse().ok()?;
    let mut cents: i128 = whole.checked_mul(100)?;
    let digits: Vec<u8> = fraction.bytes().map(|b| b - b'0').collect();
    cents = cents.checked_add(i128::from(*digits.first().unwrap_or(&0)) * 10)?;
    cents = cents.checked_add(i128::from(*digits.get(1).unwrap_or(&0)))?;
    if digits.get(2).is_some_and(|digit| *digit >= 5) {
        cents = cents.checked_add(1)?;
    }
    if negative {
        cents = -cents;
    }
    i64::try_from(cents).ok()
}

/// A CRM party as the matcher sees it: its names and e-mail addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyRef {
    /// `party.id`.
    pub id: i64,
    /// `display_name` plus every `name_variants` entry.
    pub names: Vec<String>,
    /// `emails`.
    pub emails: Vec<String>,
}

/// The `party_match` check and the matched `party_id`, when one matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyMatch {
    /// The check.
    pub check: Check,
    /// The matched party, when the check passes.
    pub party_id: Option<i64>,
}

/// Match the issuer or recipient against the CRM parties' names and e-mails
/// (the B1 `party` rows). Exact, case-insensitive and whitespace-normalised:
/// a fuzzy match would file a document against the wrong party. Several
/// matching parties link none (`unknown`, ambiguous).
pub fn party_match(fields: &Fields, parties: &[PartyRef]) -> PartyMatch {
    let candidates: Vec<String> = [fields.issuer.as_deref(), fields.recipient.as_deref()]
        .into_iter()
        .flatten()
        .map(normalize_name)
        .filter(|name| !name.is_empty())
        .collect();
    if candidates.is_empty() {
        return PartyMatch {
            check: Check::new("party_match", CheckState::Unknown, "no issuer or recipient"),
            party_id: None,
        };
    }
    if parties.is_empty() {
        return PartyMatch {
            check: Check::new("party_match", CheckState::Unknown, "no CRM parties"),
            party_id: None,
        };
    }
    let mut matched = None;
    for party in parties {
        let names = party
            .names
            .iter()
            .map(|name| normalize_name(name))
            .chain(party.emails.iter().map(|email| normalize_name(email)));
        for name in names {
            if !name.is_empty() && candidates.contains(&name) {
                if matched.is_some_and(|id| id != party.id) {
                    // Several parties match: never guess, the owner links by hand.
                    let reason = "ambiguous: several CRM parties match";
                    return PartyMatch {
                        check: Check::new("party_match", CheckState::Unknown, reason),
                        party_id: None,
                    };
                }
                matched = Some(party.id);
            }
        }
    }
    if let Some(id) = matched {
        return PartyMatch {
            check: Check::new(
                "party_match",
                CheckState::Pass,
                format!("matched CRM party {id}"),
            ),
            party_id: Some(id),
        };
    }
    PartyMatch {
        check: Check::new("party_match", CheckState::Fail, "no CRM party matches"),
        party_id: None,
    }
}

fn normalize_name(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The bridge leg of the chain: parse fields from text deterministically.
///
/// The parser is regex-free by design (no new dependency): it normalises the
/// text, splits it into lines, and applies label and layout rules for French
/// and English receipts. It never calls a model.
pub fn extract_text(text: &str, pages: Option<u32>, extractor: Extractor) -> Extracted {
    let normalized = normalize_text(text);
    let lines: Vec<&str> = normalized
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if let Some(kind) = sensitive_kind(text) {
        // DOC-SAFE-1: no value of an ID, health or bank document is parsed
        // into the invoice fields, not even the amounts of a bill for one: a
        // "Total" or "VAT" line can carry an ID or secret as digits. Only the
        // class and the page count stay.
        let fields = Fields {
            kind,
            extractor,
            pages,
            ..Fields::default()
        };
        let reason = "a sensitive document: no fields are extracted";
        let checks = vec![
            Check::new("totals", CheckState::Unknown, reason),
            Check::new("vat", CheckState::Unknown, reason),
        ];
        return Extracted { fields, checks };
    }
    let kind = if contains_word(&normalized, "facture") || contains_word(&normalized, "invoice") {
        DocKind::Invoice
    } else {
        DocKind::Receipt
    };
    let fields = Fields {
        kind,
        extractor,
        issuer: lines.first().map(|line| (*line).to_string()),
        recipient: None,
        issued_on: find_date(&lines),
        currency: find_currency(&normalized),
        total_minor: find_total(&lines),
        vat_minor: find_vat(&lines),
        number: find_number(&lines),
        net_minor: None,
        format: None,
        seller_vat_id: None,
        buyer_vat_id: None,
        pages,
    };
    let checks = vec![
        Check::new(
            "totals",
            CheckState::Unknown,
            "no line items in the extracted text",
        ),
        Check::new(
            "vat",
            CheckState::Unknown,
            "no VAT breakdown in the extracted text",
        ),
    ];
    Extracted { fields, checks }
}

/// Replace the non-breaking spaces French receipts use with plain spaces, drop
/// carriage returns, and glue a thousands separator back to its digits.
fn normalize_text(text: &str) -> String {
    let spaced = text
        .replace(['\u{00a0}', '\u{202f}'], " ")
        .replace('\r', "");
    collapse_digit_spaces(&spaced)
}

fn collapse_digit_spaces(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        out.push(current);
        if current.is_ascii_digit() {
            let mut next = index + 1;
            while next < chars.len() && chars[next] == ' ' {
                next += 1;
            }
            // Glue only a real thousands group: exactly three digits followed
            // by a separator, a space, a currency sign or the end. A 1-2 digit
            // run that is a rate (after TVA/VAT/Tax or before `%`) must keep its
            // space, or "TVA 20 100,00" would become "TVA 20100,00".
            if next > index + 1
                && next + 3 <= chars.len()
                && chars[next].is_ascii_digit()
                && chars[next + 1].is_ascii_digit()
                && chars[next + 2].is_ascii_digit()
                && (next + 3 == chars.len() || is_group_terminator(chars[next + 3]))
                && !is_rate_run(&chars, index)
            {
                // Drop the spaces and continue on the first digit of the group.
                index = next;
                continue;
            }
        }
        index += 1;
    }
    out
}

/// True when the digits ending at `end` are a 1-2 digit rate: preceded by a VAT
/// keyword, or by a `%`.
fn is_rate_run(chars: &[char], end: usize) -> bool {
    let mut start = end;
    while start > 0 && chars[start - 1].is_ascii_digit() {
        start -= 1;
    }
    if end - start + 1 > 2 {
        return false;
    }
    let mut before = start;
    while before > 0 && chars[before - 1] == ' ' {
        before -= 1;
    }
    if before > 0 && chars[before - 1] == '%' {
        return true;
    }
    let mut word_start = before;
    while word_start > 0
        && (chars[word_start - 1].is_alphanumeric() || chars[word_start - 1] == '.')
    {
        word_start -= 1;
    }
    let word: String = chars[word_start..before].iter().collect();
    matches!(
        word.to_lowercase().as_str(),
        "tva" | "vat" | "tax" | "taux" | "rate"
    )
}

/// The character that may follow a three-digit thousands group for the group
/// to be glued to the digits before it.
fn is_group_terminator(c: char) -> bool {
    matches!(c, '.' | ',' | ' ' | '€' | '$' | '£')
}

/// True when `word` (one word or a phrase) appears in `text` as whole words.
fn contains_word(text: &str, word: &str) -> bool {
    words(text).contains(&words(word))
}

fn find_date(lines: &[&str]) -> Option<String> {
    for line in lines {
        for token in date_tokens(line) {
            if let Some(date) = parse_date_token(token) {
                return Some(date);
            }
        }
    }
    None
}

fn date_tokens(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let is_date_char = |b: u8| b.is_ascii_digit() || matches!(b, b'-' | b'/' | b'.');
        if !is_date_char(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_date_char(bytes[index]) {
            index += 1;
        }
        tokens.push(&line[start..index]);
    }
    tokens
}

fn parse_date_token(token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split(['-', '/', '.']).collect();
    match parts.as_slice() {
        [year, month, day] if year.len() == 4 => ymd(year, month, day),
        [day, month, year] if year.len() == 4 => ymd(year, month, day),
        [day, month, year] if year.len() == 2 => ymd(&format!("20{year}"), month, day),
        _ => None,
    }
}

fn ymd(year: &str, month: &str, day: &str) -> Option<String> {
    let year: u32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    let day: u32 = day.parse().ok()?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days).contains(&day) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

fn find_currency(text: &str) -> Option<String> {
    if text.contains('€') {
        return Some("EUR".to_string());
    }
    if text.contains('£') {
        return Some("GBP".to_string());
    }
    if text.contains('$') {
        return Some("USD".to_string());
    }
    for code in ["EUR", "USD", "GBP", "CHF"] {
        if contains_word(text, code) {
            return Some(code.to_string());
        }
    }
    None
}

fn find_number(lines: &[&str]) -> Option<String> {
    const MARKERS: &[&str] = &[
        "facture", "invoice", "receipt", "reçu", "recu", "n°", "no.", "no", "#", "numéro",
        "numero", "number", "ref",
    ];
    for line in lines {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (index, token) in tokens.iter().enumerate() {
            let lower = token.to_lowercase();
            if MARKERS.iter().any(|marker| lower == *marker) {
                if let Some(next) = tokens.get(index + 1) {
                    if let Some(id) = clean_id(next) {
                        return Some(id);
                    }
                }
            }
            for marker in ["n°", "no.", "#"] {
                if let Some(rest) = lower.strip_prefix(marker) {
                    if !rest.is_empty() {
                        if let Some(clean) = clean_id(&token[marker.len()..]) {
                            return Some(clean);
                        }
                    }
                }
            }
        }
    }
    None
}

fn clean_id(token: &str) -> Option<String> {
    let cleaned = token
        .trim_matches(|c: char| matches!(c, '#' | ':' | ',' | '.' | ';' | '(' | ')' | '"' | '\''));
    if cleaned.len() < 3 || !cleaned.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    if !cleaned
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/'))
    {
        return None;
    }
    Some(cleaned.to_string())
}

fn find_total(lines: &[&str]) -> Option<i64> {
    let mut best = None;
    for line in lines {
        let lower = line.to_lowercase();
        // On French invoices "net à payer" (with or without "Total") is the
        // final payable amount, so it labels the line by itself.
        let net_a_payer = lower.contains("net à payer") || lower.contains("net a payer");
        let labelled = lower.contains("total")
            || lower.contains("montant")
            || lower.contains("amount due")
            || lower.contains("balance due")
            || net_a_payer;
        if !labelled {
            continue;
        }
        // Exclude a total *before* tax, the sub-totals, a bare net total and a
        // pure VAT line, but keep a total that says it *includes* VAT or is the
        // final "net à payer": "Total incl. VAT", "Total TTC (TVA incluse)" and
        // "Total net à payer" are the amounts we want.
        let mentions_vat = lower.contains("tva") || lower.contains("vat") || lower.contains("tax");
        let includes_vat = lower.contains("incl") || contains_word(&lower, "ttc");
        let excluded = lower.contains("sous-total")
            || lower.contains("subtotal")
            || lower.contains("sub total")
            || lower.contains("total ht")
            || lower.contains("total h.t")
            || lower.contains("hors taxe")
            || contains_word(&lower, "ht")
            || (contains_word(&lower, "net") && !net_a_payer)
            || (mentions_vat && !includes_vat)
            || lower.contains("avant")
            || lower.contains("excl")
            || lower.contains("before tax");
        if excluded {
            continue;
        }
        if let Some(value) = last_amount(line) {
            best = Some(value);
        }
    }
    best
}

fn find_vat(lines: &[&str]) -> Option<i64> {
    for line in lines {
        let lower = line.to_lowercase();
        if lower.contains("tva") || lower.contains("vat") || lower.contains("tax") {
            if let Some(value) = last_amount(line) {
                return Some(value);
            }
        }
    }
    None
}

fn last_amount(line: &str) -> Option<i64> {
    amounts_in(line).into_iter().last().map(|(_, value)| value)
}

/// Every money-shaped token on `line`, in order. A token immediately followed
/// by `%` is a rate, not an amount, and is skipped.
fn amounts_in(line: &str) -> Vec<(usize, i64)> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        if index > 0 && bytes[index - 1].is_ascii_alphanumeric() {
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            continue;
        }
        let start = index;
        while index < bytes.len()
            && (bytes[index].is_ascii_digit() || matches!(bytes[index], b'.' | b',' | b'\''))
        {
            index += 1;
        }
        let token = line[start..index].trim_end_matches(['.', ',', '\'']);
        if token.is_empty() {
            continue;
        }
        let after = line[start + token.len()..].trim_start();
        if after.starts_with('%') {
            continue;
        }
        if let Some(value) = parse_amount_token(token) {
            out.push((start, value));
        }
    }
    out
}

/// Parse a money token into minor units. The last `.`/`,` with one or two
/// digits after it is the decimal separator; a longer run of digits after the
/// last separator is a thousands group. A token carrying any other character
/// is refused, and every step is checked, so malformed text can never panic.
fn parse_amount_token(token: &str) -> Option<i64> {
    if token.is_empty() || token.len() > 32 {
        return None;
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b',' | b'\''))
    {
        return None;
    }
    let last_separator = token.rfind(['.', ',']);
    let (integer, fraction) = match last_separator {
        Some(position) => {
            let after = &token[position + 1..];
            if after.is_empty() || !after.bytes().all(|byte| byte.is_ascii_digit()) {
                // A non-digit in the fraction part is malformed ("12.3'4").
                return None;
            }
            if after.len() <= 2 {
                (&token[..position], after)
            } else {
                // Three or more digits is a thousands group, not a fraction.
                (token, "")
            }
        }
        None => (token, ""),
    };
    if !valid_integer_groups(integer) {
        // "1.2.3" has a separator that is not a three-digit thousands group.
        return None;
    }
    let mut whole: i64 = 0;
    let mut digits = 0usize;
    for byte in integer.bytes() {
        if !byte.is_ascii_digit() {
            continue;
        }
        whole = whole.checked_mul(10)?.checked_add(i64::from(byte - b'0'))?;
        digits += 1;
        if digits > 15 {
            return None;
        }
    }
    if digits == 0 {
        return None;
    }
    let mut cents = whole.checked_mul(100)?;
    for (index, byte) in fraction.bytes().enumerate() {
        let digit = i64::from(byte - b'0');
        if index == 0 {
            cents = cents.checked_add(digit.checked_mul(10)?)?;
        } else {
            cents = cents.checked_add(digit)?;
        }
    }
    Some(cents)
}

/// True when the separator groups in an integer part are well formed: no
/// separator means any digit run; with separators the first group holds 1-3
/// digits and every later group exactly three. This refuses "1.2.3".
fn valid_integer_groups(integer: &str) -> bool {
    if !integer.contains(['.', ',', '\'']) {
        return !integer.is_empty() && integer.bytes().all(|byte| byte.is_ascii_digit());
    }
    let groups: Vec<&str> = integer.split(['.', ',', '\'']).collect();
    let Some((first, rest)) = groups.split_first() else {
        return false;
    };
    if first.is_empty() || first.len() > 3 || !first.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    !rest.is_empty()
        && rest
            .iter()
            .all(|group| group.len() == 3 && group.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const UBL_INVOICE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
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

    fn nordwind() -> PartyRef {
        PartyRef {
            id: 7,
            names: vec!["Nordwind Studio SARL".to_string()],
            emails: vec!["billing@nordwind.test".to_string()],
        }
    }

    #[test]
    fn ubl_invoice_maps_to_fields_and_passing_checks() {
        let extracted = extract_xml(UBL_INVOICE).expect("UBL parses");
        assert_eq!(extracted.fields.kind, DocKind::Invoice);
        assert_eq!(extracted.fields.extractor, Extractor::Xml);
        assert_eq!(extracted.fields.format.as_deref(), Some("UBL"));
        assert_eq!(extracted.fields.number.as_deref(), Some("FAC-2025-0042"));
        assert_eq!(extracted.fields.issued_on.as_deref(), Some("2025-09-12"));
        assert_eq!(extracted.fields.currency.as_deref(), Some("EUR"));
        assert_eq!(
            extracted.fields.issuer.as_deref(),
            Some("Nordwind Studio SARL")
        );
        assert_eq!(
            extracted.fields.recipient.as_deref(),
            Some("Camille Exemple")
        );
        assert_eq!(extracted.fields.net_minor, Some(10_000));
        assert_eq!(extracted.fields.vat_minor, Some(2_000));
        assert_eq!(extracted.fields.total_minor, Some(12_000));
        assert_eq!(
            extracted.fields.seller_vat_id.as_deref(),
            Some("FR12345678901")
        );
        for check in &extracted.checks {
            assert_eq!(check.state, CheckState::Pass, "{check:?}");
        }
        let matched = party_match(&extracted.fields, &[nordwind()]);
        assert_eq!(matched.check.state, CheckState::Pass);
        assert_eq!(matched.party_id, Some(7));
    }

    #[test]
    fn cii_invoice_maps_to_fields() {
        let extracted = extract_xml(&cii_invoice("120.00")).expect("CII parses");
        assert_eq!(extracted.fields.format.as_deref(), Some("CII"));
        assert_eq!(extracted.fields.number.as_deref(), Some("REC-2025-0007"));
        assert_eq!(extracted.fields.issued_on.as_deref(), Some("2025-09-30"));
        assert_eq!(extracted.fields.issuer.as_deref(), Some("Atelier Cobalt"));
        assert_eq!(extracted.fields.total_minor, Some(12_000));
        assert_eq!(extracted.fields.vat_minor, Some(2_000));
        for check in &extracted.checks {
            assert_eq!(check.state, CheckState::Pass, "{check:?}");
        }
    }

    #[test]
    fn a_one_cent_error_fails_the_totals_check() {
        let extracted = extract_xml(&cii_invoice("120.01")).expect("CII parses");
        let totals = extracted
            .checks
            .iter()
            .find(|check| check.name == "totals")
            .expect("a totals check");
        assert_eq!(totals.state, CheckState::Fail, "{totals:?}");
        // The VAT leg still reconciles: the injected error is in the gross total.
        let vat = extracted
            .checks
            .iter()
            .find(|check| check.name == "vat")
            .expect("a vat check");
        assert_eq!(vat.state, CheckState::Pass, "{vat:?}");
    }

    #[test]
    fn a_non_xml_blob_is_not_xml() {
        assert!(is_xml(UBL_INVOICE));
        assert!(!is_xml(b"%PDF-1.4 fake"));
        assert!(!is_xml(b"\x89PNG\r\n\x1a\n"));
        assert!(extract_xml(b"hello").is_err());
    }

    #[test]
    fn decimal_strings_convert_exactly_and_round_half_up() {
        assert_eq!(decimal_string_to_minor("120.00"), Some(12_000));
        assert_eq!(decimal_string_to_minor("0.01"), Some(1));
        assert_eq!(decimal_string_to_minor("-0.01"), Some(-1));
        assert_eq!(decimal_string_to_minor("1"), Some(100));
        assert_eq!(decimal_string_to_minor("1.005"), Some(101));
        assert_eq!(decimal_string_to_minor("1.004"), Some(100));
        assert_eq!(decimal_string_to_minor(""), None);
        assert_eq!(decimal_string_to_minor("abc"), None);
    }

    #[test]
    fn a_french_receipt_text_yields_fields() {
        let text = "Boulangerie Exemple\n\
                    12 rue des Lilas\n\
                    Ticket N° 2025-0042\n\
                    Date 12/09/2025\n\
                    Sous-total 10,00\n\
                    Total TTC 12,34 €\n\
                    TVA 20% 2,34\n\
                    Merci !\n";
        let extracted = extract_text(text, Some(1), Extractor::Ocr);
        assert_eq!(extracted.fields.kind, DocKind::Receipt);
        assert_eq!(extracted.fields.extractor, Extractor::Ocr);
        assert_eq!(
            extracted.fields.issuer.as_deref(),
            Some("Boulangerie Exemple")
        );
        assert_eq!(extracted.fields.number.as_deref(), Some("2025-0042"));
        assert_eq!(extracted.fields.issued_on.as_deref(), Some("2025-09-12"));
        assert_eq!(extracted.fields.currency.as_deref(), Some("EUR"));
        assert_eq!(extracted.fields.total_minor, Some(1_234));
        assert_eq!(extracted.fields.vat_minor, Some(234));
        assert_eq!(extracted.fields.pages, Some(1));
        let names: Vec<&str> = extracted.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["totals", "vat"]);
    }

    #[test]
    fn an_english_invoice_text_yields_fields() {
        let text = "Northwind Studio\n\
                    Invoice # INV-2025-0009\n\
                    Issued 2025-10-01\n\
                    Subtotal 100.00 USD\n\
                    VAT 20.00\n\
                    Total due 120.00\n";
        let extracted = extract_text(text, None, Extractor::PdfText);
        assert_eq!(extracted.fields.kind, DocKind::Invoice);
        assert_eq!(extracted.fields.number.as_deref(), Some("INV-2025-0009"));
        assert_eq!(extracted.fields.issued_on.as_deref(), Some("2025-10-01"));
        assert_eq!(extracted.fields.currency.as_deref(), Some("USD"));
        assert_eq!(extracted.fields.total_minor, Some(12_000));
        assert_eq!(extracted.fields.vat_minor, Some(2_000));
    }

    #[test]
    fn a_thousands_separator_is_not_a_decimal_point() {
        assert_eq!(parse_amount_token("1.234,56"), Some(123_456));
        assert_eq!(parse_amount_token("1,234.56"), Some(123_456));
        assert_eq!(parse_amount_token("1,234"), Some(123_400));
        assert_eq!(parse_amount_token("1.234"), Some(123_400));
        assert_eq!(parse_amount_token("12,3"), Some(1_230));
    }

    #[test]
    fn malformed_money_tokens_are_refused_not_panicking() {
        // `12.3'4` used to underflow on `b'\'' - b'0'`.
        assert_eq!(parse_amount_token("12.3'4"), None);
        assert_eq!(parse_amount_token("12,34'56"), None);
        assert_eq!(parse_amount_token("12a"), None);
        assert_eq!(parse_amount_token(","), None);
        assert_eq!(parse_amount_token(""), None);
        assert_eq!(parse_amount_token(&"9".repeat(20)), None);
        // A separator that is not a three-digit thousands group is malformed.
        assert_eq!(parse_amount_token("1.2.3"), None);
        assert_eq!(parse_amount_token("1,23,456"), None);
    }

    #[test]
    fn thousands_groups_glue_but_a_rate_and_an_amount_do_not() {
        assert_eq!(collapse_digit_spaces("1 234,56"), "1234,56");
        assert_eq!(collapse_digit_spaces("1 234 567,89"), "1234567,89");
        assert_eq!(collapse_digit_spaces("1 234"), "1234");
        // A rate and the amount after it must stay apart.
        assert_eq!(collapse_digit_spaces("TVA 20 2,34"), "TVA 20 2,34");
        assert_eq!(collapse_digit_spaces("TVA 20 100,00"), "TVA 20 100,00");
        assert_eq!(collapse_digit_spaces("2 10,00"), "2 10,00");
        assert_eq!(find_vat(&["TVA 20 2,34"]), Some(234));
        assert_eq!(find_vat(&["TVA 20 100,00"]), Some(10_000));
    }

    #[test]
    fn a_total_that_mentions_vat_is_still_a_total() {
        assert_eq!(find_total(&["Total incl. VAT 120.00"]), Some(12_000));
        assert_eq!(find_total(&["Total TTC (TVA incluse) 12,34"]), Some(1_234));
        assert_eq!(find_total(&["Total HT 100.00"]), None);
        assert_eq!(find_total(&["Sous-total 10,00"]), None);
        assert_eq!(find_total(&["Total before tax 100.00"]), None);
        // A bare net total and a pure VAT line are not the amount due.
        assert_eq!(find_total(&["Total net 35,10"]), None);
        assert_eq!(find_total(&["Total TVA 3,90"]), None);
        // "net à payer" is the French payable line, with or without "Total".
        assert_eq!(find_total(&["Total net à payer 42,00"]), Some(4_200));
        assert_eq!(find_total(&["NET A PAYER 42,00"]), Some(4_200));
        assert_eq!(find_total(&["Net à payer 42,00"]), Some(4_200));
    }

    #[test]
    fn metadata_only_drops_every_free_text_field() {
        let fields = Fields {
            issuer: Some("Nordwind Studio SARL".to_string()),
            recipient: Some("Camille Exemple".to_string()),
            seller_vat_id: Some("FR12345678901".to_string()),
            buyer_vat_id: Some("FR99999999999".to_string()),
            total_minor: Some(12_000),
            number: Some("FAC-2025-0042".to_string()),
            issued_on: Some("2025-09-12".to_string()),
            ..Fields::default()
        };
        let sanitized = fields.metadata_only();
        assert_eq!(sanitized.issuer, None);
        assert_eq!(sanitized.recipient, None);
        assert_eq!(sanitized.seller_vat_id, None);
        assert_eq!(sanitized.buyer_vat_id, None);
        assert_eq!(sanitized.total_minor, Some(12_000));
        assert_eq!(sanitized.number.as_deref(), Some("FAC-2025-0042"));
        assert_eq!(sanitized.issued_on.as_deref(), Some("2025-09-12"));
    }

    #[test]
    fn one_stray_keyword_does_not_class_an_invoice_sensitive() {
        for text in [
            "Thank you for being a patient customer, total 120 EUR",
            "Facture F-12\nfrais de passeport\nTotal 86 EUR",
            "Invoice INV-7\nNorthwind Supplies\nTotal 130 EUR\nClosing balance 130 EUR",
            "Receipt\nan impatient courier, total 9 EUR",
        ] {
            assert_eq!(sensitive_kind(text), None, "{text}");
            assert!(extract_text(text, None, Extractor::PdfText)
                .fields
                .total_minor
                .is_some());
        }
    }

    #[test]
    fn a_bill_for_a_sensitive_item_stays_sensitive_and_keeps_no_value() {
        for (text, kind) in [
            (
                "Invoice INV-7\nPassport renewal fee 86 EUR\nTotal 86 EUR",
                DocKind::IdDocument,
            ),
            (
                "Invoice INV-8\nPrescription glasses 120 EUR\nTotal 120 EUR",
                DocKind::Health,
            ),
            (
                "Receipt\nBank statement\nTax portal password: 12345678",
                DocKind::BankStatement,
            ),
            (
                "Receipt\nBank statement\nTax identification number: 123456789",
                DocKind::BankStatement,
            ),
            (
                "Receipt\nBank statement\nTotal 86 EUR Account number 12345678",
                DocKind::BankStatement,
            ),
        ] {
            assert_eq!(sensitive_kind(text), Some(kind), "{text}");
            let fields = extract_text(text, None, Extractor::PdfText).fields;
            assert_eq!(fields.kind, kind, "{text}");
            assert_eq!(
                (
                    fields.total_minor,
                    fields.vat_minor,
                    fields.issued_on.is_none()
                ),
                (None, None, true),
                "{text}"
            );
            assert_eq!((fields.issuer, fields.number), (None, None), "{text}");
        }
    }

    #[test]
    fn a_sensitive_heading_under_a_receipt_title_still_classes_the_text() {
        for (text, kind) in [
            (
                "Receipt\nMedical report 120 EUR\nClinical observation: persistent fatigue",
                DocKind::Health,
            ),
            (
                "Receipt\nBank statement\nTransactions: Fictive Cafe 12 EUR",
                DocKind::BankStatement,
            ),
            (
                "Receipt\nMedical report 120EUR\nClinical observation: persistent fatigue",
                DocKind::Health,
            ),
            (
                "Receipt\nMedical report follow-up March 2026\nClinical observation: none",
                DocKind::Health,
            ),
            (
                "Receipt\nMedical report copy\nClinical observation: persistent fatigue",
                DocKind::Health,
            ),
            ("Receipt\nPassport copy\nNo X1234567", DocKind::IdDocument),
            (
                "Facture\nRelevé de compte frais bancaires\nSolde 12 EUR",
                DocKind::BankStatement,
            ),
        ] {
            assert_eq!(sensitive_kind(text), Some(kind), "{text}");
        }
    }

    #[test]
    fn real_sensitive_documents_keep_their_class() {
        let mrz = "Utopia\nP<UTOFICTIVE<<MIRA<ANNA<<<<<<<<<<<<<<<<<<<<<\n";
        let cases = [
            (mrz, DocKind::IdDocument),
            (
                "REPUBLIQUE\nCARTE NATIONALE D'IDENTITÉ\nNom: Fictive",
                DocKind::IdDocument,
            ),
            ("Utopia\nPASSPORT\nNo X1234567", DocKind::IdDocument),
            ("Medical report\nPatient: Mira Fictive", DocKind::Health),
            (
                "Note\nPatient Mira Fictive\nDiagnosis: flu",
                DocKind::Health,
            ),
            (
                "RELEVÉ DE COMPTE\nNouveau solde 1 200,00",
                DocKind::BankStatement,
            ),
            (
                "October\nOpening balance 10\nClosing balance 20",
                DocKind::BankStatement,
            ),
        ];
        for (text, kind) in cases {
            assert_eq!(sensitive_kind(text), Some(kind), "{text}");
        }
    }

    #[test]
    fn a_failed_vat_conversion_makes_the_sum_unknown() {
        assert_eq!(checked_sum([Some(1), Some(2), Some(3)]), Some(6));
        assert_eq!(checked_sum([Some(1), None, Some(3)]), None);
        assert_eq!(checked_sum([Some(i64::MAX), Some(1)]), None);
        assert_eq!(checked_sum(std::iter::empty::<Option<i64>>()), Some(0));
    }

    proptest! {
        /// Arbitrary bytes never panic the money parser.
        #[test]
        fn parse_amount_token_never_panics(token in ".{0,32}") {
            let _ = parse_amount_token(&token);
        }

        /// Arbitrary bytes never panic the exact-decimal reader.
        #[test]
        fn decimal_string_to_minor_never_panics(value in ".{0,40}") {
            let _ = decimal_string_to_minor(&value);
        }

        /// Arbitrary receipt text never panics the whole deterministic parser.
        #[test]
        fn extract_text_never_panics(text in ".{0,200}") {
            let _ = extract_text(&text, Some(1), Extractor::Ocr);
        }
    }

    #[test]
    fn party_match_is_exact_and_tri_state() {
        let mut fields = Fields {
            issuer: Some("camille   exemple".to_string()),
            ..Fields::default()
        };
        let parties = vec![PartyRef {
            id: 3,
            names: vec!["Camille Exemple".to_string()],
            emails: vec![],
        }];
        assert_eq!(party_match(&fields, &parties).party_id, Some(3));
        // No parties at all is unknown, not a failure.
        assert_eq!(party_match(&fields, &[]).check.state, CheckState::Unknown);
        // A populated CRM with no match is a failure.
        let other = vec![PartyRef {
            id: 4,
            names: vec!["Atelier Cobalt".to_string()],
            emails: vec![],
        }];
        assert_eq!(party_match(&fields, &other).check.state, CheckState::Fail);
        // No issuer or recipient is unknown.
        fields.issuer = None;
        assert_eq!(
            party_match(&fields, &parties).check.state,
            CheckState::Unknown
        );
    }

    #[test]
    fn an_email_matches_a_party() {
        let fields = Fields {
            issuer: Some("billing@nordwind.test".to_string()),
            ..Fields::default()
        };
        let matched = party_match(&fields, &[nordwind()]);
        assert_eq!(matched.party_id, Some(7));
    }

    #[test]
    fn two_matching_parties_link_nothing() {
        let cobalt = PartyRef {
            id: 2,
            names: vec!["Atelier Cobalt".to_string()],
            emails: vec![],
        };
        let mut fields = Fields {
            issuer: Some("Nordwind Studio SARL".to_string()),
            recipient: Some("Atelier Cobalt".to_string()),
            ..Fields::default()
        };
        // Issuer and recipient each match a different party: never guess.
        let matched = party_match(&fields, &[nordwind(), cobalt]);
        assert_eq!(matched.party_id, None);
        assert_eq!(matched.check.state, CheckState::Unknown);
        // One party matched by its name and its e-mail is still one party.
        fields.recipient = Some("billing@nordwind.test".to_string());
        assert_eq!(party_match(&fields, &[nordwind()]).party_id, Some(7));
    }
}
