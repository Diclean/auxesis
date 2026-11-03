//! Bounded, offline readers for Factur-X/ZUGFeRD CII and UBL e-invoices.
//! No schema validation is implied: this produces parsed values and explicit
//! deterministic arithmetic checks only.
use quick_xml::{events::Event, NsReader};
use rust_decimal::Decimal;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use thiserror::Error;

pub const MAX_XML_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_XML_DEPTH: usize = 128;
pub const MAX_XML_ELEMENTS: usize = 100_000;
const MAX_TEXT: usize = 1024;
const MAX_LINES: usize = 10_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EInvoiceError {
    #[error("XML exceeds the 10 MiB limit")]
    TooLarge,
    #[error("XML encoding is invalid or unsupported")]
    Encoding,
    #[error("DOCTYPE declarations are forbidden")]
    Doctype,
    #[error("malformed XML: {0}")]
    Malformed(String),
    #[error("XML nesting exceeds the limit")]
    TooDeep,
    #[error("XML element count exceeds the limit")]
    TooManyElements,
    #[error("required invoice field is missing: {0}")]
    Missing(&'static str),
    #[error("invalid decimal in {0}")]
    InvalidDecimal(&'static str),
    #[error("duplicate invoice field: {0}")]
    Duplicate(&'static str),
    #[error("decimal amount overflow")]
    AmountOverflow,
    #[error("amount or quantity is outside supported bounds")]
    AmountOutOfRange,
    #[error("unsupported invoice XML vocabulary")]
    UnsupportedFormat,
    #[error("XML contains more than one root element")]
    MultipleRoots,
    #[error("party identifier exceeds 64 characters")]
    IdentifierTooLong,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Party {
    pub name: String,
    pub vat_id: Option<String>,
    pub registration_id: Option<String>,
    pub fiscal_id: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceLine {
    pub description: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub vat_rate: Decimal,
    pub net_amount: Decimal,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxTotal {
    pub rate: Decimal,
    pub taxable_amount: Decimal,
    pub tax_amount: Decimal,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub check: &'static str,
    pub kind: Option<ValidationIssueKind>,
    pub declared: Decimal,
    pub calculated: Decimal,
    pub difference: Decimal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationIssueKind {
    IncompleteTaxBreakdown,
    MissingTaxBreakdown,
    /// A VAT rate present on a line is absent from the header breakdown, or a
    /// rate declared in the breakdown has no matching line (a negative rate is
    /// always a mismatch: a credit note carries negative amounts, never a
    /// negative rate).
    VatRateMismatch,
    /// A rate matches on both sides but the breakdown's taxable amount differs
    /// from the expected basis at that rate: the sum of the *declared* line
    /// net amounts at that rate, minus the document-level allowances at that
    /// rate, plus the document-level charges at that rate.
    VatBasisMismatch,
    /// A document-level allowance or charge has no VAT rate or no readable
    /// indicator, so the per-rate basis cannot be checked: reported instead of
    /// silently skipping the check (declared = breakdown total, calculated =
    /// expected basis from the lines and the attributable adjustments).
    UnverifiableVatBasis,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationCheck {
    pub issues: Vec<ValidationIssue>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EInvoice {
    pub format: String,
    pub seller: Party,
    pub buyer: Party,
    pub invoice_number: String,
    pub invoice_date: String,
    pub currency: String,
    pub lines: Vec<InvoiceLine>,
    pub net_total: Decimal,
    pub tax_totals: Vec<TaxTotal>,
    pub gross_total: Decimal,
    pub validation: ValidationCheck,
}

#[derive(Debug, Default)]
struct Node {
    name: String,
    namespace: String,
    text: String,
    scheme_id: Option<String>,
    children: Vec<Node>,
}
impl Node {
    fn at_path<'a>(&'a self, path: &[&str], cii: bool) -> Vec<&'a Node> {
        fn matches(node: &Node, part: &str, cii: bool) -> bool {
            let (prefix, name) = part.split_once(':').unwrap_or(("root", part));
            if prefix == "self" && name == "*" {
                return true;
            }
            if !(prefix == "root" && name == "root") && node.name != name {
                return false;
            }
            let ns = match (cii, prefix) {
                (_, "self") => return true,
                (true, "root" | "rsm") => "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100",
                (true, "ram") => "urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100",
                (true, "udt") => "urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100",
                (false, "root") => return node.namespace.starts_with("urn:oasis:names:specification:ubl:schema:xsd:") && (node.namespace.ends_with("Invoice-2") || node.namespace.ends_with("CreditNote-2")),
                (false, "cbc") => "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
                (false, "cac") => "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
                _ => return false,
            };
            node.namespace == ns
        }
        fn walk<'a>(nodes: &'a [Node], path: &[&str], cii: bool, out: &mut Vec<&'a Node>) {
            if path.is_empty() {
                return;
            }
            for node in nodes {
                if matches(node, path[0], cii) {
                    if path.len() == 1 {
                        out.push(node);
                    } else {
                        walk(&node.children, &path[1..], cii, out);
                    }
                }
            }
        }
        let mut result = Vec::new();
        if path
            .first()
            .is_some_and(|p| p.starts_with("root:") || p.starts_with("rsm:") || *p == "root")
        {
            walk(std::slice::from_ref(self), path, cii, &mut result);
        } else {
            let mut relative = Vec::with_capacity(path.len() + 1);
            relative.push("self:*");
            relative.extend_from_slice(path);
            // Relative paths are matched against children; the synthetic first
            // component anchors extraction to this line or aggregate node.
            walk(std::slice::from_ref(self), &relative, cii, &mut result);
        }
        result
    }
    fn exact_value(
        &self,
        path: &[&str],
        cii: bool,
        field: &'static str,
    ) -> Result<Option<String>, EInvoiceError> {
        let matches = self.at_path(path, cii);
        if matches.len() > 1 {
            return Err(EInvoiceError::Duplicate(field));
        }
        Ok(matches
            .first()
            .and_then(|n| clean_text(&n.text))
            .filter(|s| !s.is_empty()))
    }
}

/// Parse CII (Factur-X/ZUGFeRD) or UBL (Peppol BIS 3/XRechnung) XML.
/// Decimal differences are reported, never applied to the source values.
pub fn parse_einvoice_xml(bytes: &[u8]) -> Result<EInvoice, EInvoiceError> {
    if bytes.len() > MAX_XML_BYTES {
        return Err(EInvoiceError::TooLarge);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| EInvoiceError::Encoding)?;
    check_xml_encoding(source)?;
    // Quick rejection also catches declarations in comments/CDATA; rejecting
    // harmless occurrences is intentionally conservative for this boundary.
    if source.to_ascii_uppercase().contains("<!DOCTYPE")
        || source.to_ascii_uppercase().contains("<!ENTITY")
    {
        return Err(EInvoiceError::Doctype);
    }
    let mut reader = NsReader::from_str(source);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Node> = vec![Node {
        name: "#document".into(),
        ..Node::default()
    }];
    let mut count = 0usize;
    let mut root_namespace: Option<String> = None;
    let mut root_closed = false;
    loop {
        let decoder = reader.decoder();
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|e| EInvoiceError::Malformed(e.to_string()))?;
        match event {
            Event::Start(e) => {
                if root_closed || (stack.len() == 1 && count > 0) {
                    return Err(EInvoiceError::MultipleRoots);
                }
                count += 1;
                if count > MAX_XML_ELEMENTS {
                    return Err(EInvoiceError::TooManyElements);
                }
                if stack.len() > MAX_XML_DEPTH {
                    return Err(EInvoiceError::TooDeep);
                }
                if count == 1 {
                    let qname = e.name();
                    let qname =
                        std::str::from_utf8(qname.as_ref()).map_err(|_| EInvoiceError::Encoding)?;
                    let prefix = qname.split_once(':').map(|(p, _)| p.to_string());
                    for attr in e.attributes().with_checks(true) {
                        let attr = attr.map_err(|e| EInvoiceError::Malformed(e.to_string()))?;
                        let key = std::str::from_utf8(attr.key.as_ref())
                            .map_err(|_| EInvoiceError::Encoding)?;
                        let declares_root_namespace = match prefix.as_deref() {
                            Some(prefix) => key == format!("xmlns:{prefix}"),
                            None => key == "xmlns",
                        };
                        if declares_root_namespace {
                            let uri = attr
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    decoder,
                                )
                                .map_err(|e| EInvoiceError::Malformed(e.to_string()))?
                                .into_owned();
                            if uri == "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
                                || uri == "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2"
                                || uri == "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"
                            { root_namespace = Some(uri); }
                        }
                    }
                }
                let q = e.local_name();
                let q = std::str::from_utf8(q.as_ref())
                    .map_err(|_| EInvoiceError::Encoding)?
                    .to_string();
                let namespace = match resolved {
                    quick_xml::name::ResolveResult::Bound(ns) => std::str::from_utf8(ns.as_ref())
                        .map_err(|_| EInvoiceError::Encoding)?
                        .to_string(),
                    quick_xml::name::ResolveResult::Unbound => String::new(),
                    quick_xml::name::ResolveResult::Unknown(_) => {
                        return Err(EInvoiceError::Malformed("unresolved namespace".into()))
                    }
                };
                // Attribute errors (a malformed value or a duplicated name,
                // checked by quick-xml) are propagated exactly like on the
                // root element: an unreadable attribute is never silently
                // dropped.
                let mut scheme_id: Option<String> = None;
                for attr in e.attributes().with_checks(true) {
                    let attr = attr.map_err(|err| EInvoiceError::Malformed(err.to_string()))?;
                    if attr.key.local_name().as_ref() != b"schemeID" {
                        continue;
                    }
                    if scheme_id.is_some() {
                        return Err(EInvoiceError::Duplicate("schemeID"));
                    }
                    scheme_id = Some(
                        attr.decoded_and_normalized_value(
                            quick_xml::XmlVersion::Implicit1_0,
                            decoder,
                        )
                        .map_err(|err| EInvoiceError::Malformed(err.to_string()))?
                        .into_owned(),
                    );
                }
                stack.push(Node {
                    name: q,
                    namespace,
                    scheme_id,
                    ..Node::default()
                });
            }
            Event::Empty(e) => {
                if root_closed || (stack.len() == 1 && count > 0) {
                    return Err(EInvoiceError::MultipleRoots);
                }
                count += 1;
                if count > MAX_XML_ELEMENTS {
                    return Err(EInvoiceError::TooManyElements);
                }
                if stack.len() > MAX_XML_DEPTH {
                    return Err(EInvoiceError::TooDeep);
                }
                let q = e.local_name();
                let q = std::str::from_utf8(q.as_ref())
                    .map_err(|_| EInvoiceError::Encoding)?
                    .to_string();
                stack
                    .last_mut()
                    .ok_or_else(|| EInvoiceError::Malformed("missing document root".into()))?
                    .children
                    .push(Node {
                        name: q,
                        namespace: match resolved {
                            quick_xml::name::ResolveResult::Bound(ns) => {
                                std::str::from_utf8(ns.as_ref())
                                    .map_err(|_| EInvoiceError::Encoding)?
                                    .to_string()
                            }
                            quick_xml::name::ResolveResult::Unbound => String::new(),
                            quick_xml::name::ResolveResult::Unknown(_) => {
                                return Err(EInvoiceError::Malformed("unresolved namespace".into()))
                            }
                        },
                        ..Node::default()
                    });
                if stack.len() == 1 {
                    root_closed = true;
                }
            }
            Event::Text(e) => {
                let decoded = e
                    .decode()
                    .map_err(|e| EInvoiceError::Malformed(e.to_string()))?;
                let text = quick_xml::escape::unescape(&decoded)
                    .map_err(|e| EInvoiceError::Malformed(e.to_string()))?;
                let node = stack
                    .last_mut()
                    .ok_or_else(|| EInvoiceError::Malformed("missing document root".into()))?;
                if node.text.len().saturating_add(text.len()) > MAX_TEXT {
                    return Err(EInvoiceError::Malformed(
                        "element text exceeds 1024 bytes".into(),
                    ));
                }
                node.text.push_str(&text);
            }
            Event::CData(e) => {
                let text = std::str::from_utf8(e.as_ref()).map_err(|_| EInvoiceError::Encoding)?;
                let node = stack
                    .last_mut()
                    .ok_or_else(|| EInvoiceError::Malformed("missing document root".into()))?;
                if node.text.len().saturating_add(text.len()) > MAX_TEXT {
                    return Err(EInvoiceError::Malformed(
                        "element text exceeds 1024 bytes".into(),
                    ));
                }
                node.text.push_str(text);
            }
            Event::End(_) => {
                if stack.len() <= 1 {
                    return Err(EInvoiceError::Malformed(
                        "unexpected closing element".into(),
                    ));
                }
                let node = stack
                    .pop()
                    .ok_or_else(|| EInvoiceError::Malformed("unexpected closing element".into()))?;
                stack
                    .last_mut()
                    .ok_or_else(|| EInvoiceError::Malformed("missing document root".into()))?
                    .children
                    .push(node);
                if stack.len() == 1 {
                    root_closed = true;
                }
            }
            Event::DocType(_) => return Err(EInvoiceError::Doctype),
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
            Event::GeneralRef(_) => {
                return Err(EInvoiceError::Malformed(
                    "entity reference is forbidden".into(),
                ))
            }
        }
    }
    if stack.len() != 1 {
        return Err(EInvoiceError::Malformed("unclosed element".into()));
    }
    let mut root = stack.pop().ok_or(EInvoiceError::UnsupportedFormat)?;
    let root_element = root
        .children
        .first()
        .ok_or(EInvoiceError::UnsupportedFormat)?;
    let ns = root_namespace
        .as_deref()
        .ok_or(EInvoiceError::UnsupportedFormat)?;
    let namespace_ok = match root_element.name.as_str() {
        "Invoice" => ns == "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
        "CreditNote" => ns == "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
        "CrossIndustryInvoice" => {
            ns == "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100"
        }
        _ => false,
    };
    if !namespace_ok {
        return Err(EInvoiceError::UnsupportedFormat);
    }
    // The vocabulary is decided by the root element's namespace URI alone. A
    // descendant named `ExchangedDocument` living in an extension block (for
    // example `ext:UBLExtensions`) must never reclassify a UBL document, and
    // no descendant of a CII root can turn it into UBL.
    let cii = ns == "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100";
    fn prune(node: &mut Node, allowed: &[&str], is_document: bool) {
        node.children
            .retain(|n| is_document || allowed.contains(&n.namespace.as_str()));
        for child in &mut node.children {
            prune(child, allowed, false);
        }
    }
    let allowed: &[&str] = if cii {
        &[
            "urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100",
            "urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100",
            "urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100",
        ]
    } else {
        &[
            "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
            "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
            "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
        ]
    };
    prune(&mut root, allowed, true);
    let invoice_root = root
        .children
        .first()
        .ok_or(EInvoiceError::UnsupportedFormat)?;
    parse_tree(invoice_root, cii)
}

fn parse_tree(root: &Node, cii: bool) -> Result<EInvoice, EInvoiceError> {
    // These are the only selectable locations in the two vocabularies. Each
    // path begins at the document element and includes every namespace-bearing
    // ancestor, so same-named extension elements can never shadow data.
    let root_name = root.name.as_str();
    let ubl_root = if root_name == "CreditNote" {
        "CreditNote"
    } else {
        "Invoice"
    };
    let (
        number_path,
        date_path,
        currency_path,
        net_path,
        gross_path,
        line_path,
        seller_path,
        buyer_path,
    ) = if cii {
        (
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:ExchangedDocument",
                "ram:ID",
            ][..],
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:ExchangedDocument",
                "ram:IssueDateTime",
                "udt:DateTimeString",
            ][..],
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:SupplyChainTradeTransaction",
                "ram:ApplicableHeaderTradeSettlement",
                "ram:InvoiceCurrencyCode",
            ][..],
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:SupplyChainTradeTransaction",
                "ram:ApplicableHeaderTradeSettlement",
                "ram:SpecifiedTradeSettlementHeaderMonetarySummation",
                "ram:TaxBasisTotalAmount",
            ][..],
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:SupplyChainTradeTransaction",
                "ram:ApplicableHeaderTradeSettlement",
                "ram:SpecifiedTradeSettlementHeaderMonetarySummation",
                "ram:GrandTotalAmount",
            ][..],
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:SupplyChainTradeTransaction",
                "ram:IncludedSupplyChainTradeLineItem",
            ][..],
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:SupplyChainTradeTransaction",
                "ram:ApplicableHeaderTradeAgreement",
                "ram:SellerTradeParty",
            ][..],
            &[
                "rsm:CrossIndustryInvoice",
                "rsm:SupplyChainTradeTransaction",
                "ram:ApplicableHeaderTradeAgreement",
                "ram:BuyerTradeParty",
            ][..],
        )
    } else {
        let root_segment = if ubl_root == "CreditNote" {
            "root:CreditNote"
        } else {
            "root:Invoice"
        };
        let line_container = if ubl_root == "CreditNote" {
            "cac:CreditNoteLine"
        } else {
            "cac:InvoiceLine"
        };
        (
            &[root_segment, "cbc:ID"][..],
            &[root_segment, "cbc:IssueDate"][..],
            &[root_segment, "cbc:DocumentCurrencyCode"][..],
            &[
                root_segment,
                "cac:LegalMonetaryTotal",
                "cbc:TaxExclusiveAmount",
            ][..],
            &[root_segment, "cac:LegalMonetaryTotal", "cbc:PayableAmount"][..],
            &[root_segment, line_container][..],
            &[root_segment, "cac:AccountingSupplierParty", "cac:Party"][..],
            &[root_segment, "cac:AccountingCustomerParty", "cac:Party"][..],
        )
    };
    let field = |path: &[&str], key| root.exact_value(path, cii, key);
    let number =
        field(number_path, "invoice number")?.ok_or(EInvoiceError::Missing("invoice number"))?;
    let mut date =
        field(date_path, "invoice date")?.ok_or(EInvoiceError::Missing("invoice date"))?;
    if cii && date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()) {
        date = format!("{}-{}-{}", &date[0..4], &date[4..6], &date[6..8]);
    }
    if !is_iso_date(&date) {
        return Err(EInvoiceError::Malformed(
            "invoice date is not ISO YYYY-MM-DD".into(),
        ));
    }
    let currency = field(currency_path, "currency")?.ok_or(EInvoiceError::Missing("currency"))?;
    let net_s = field(net_path, "net total")?.ok_or(EInvoiceError::Missing("net total"))?;
    let gross_s = field(gross_path, "gross total")?.ok_or(EInvoiceError::Missing("gross total"))?;
    let net = parse_dec(net_s, "net total")?;
    let gross = parse_dec(gross_s, "gross total")?;

    let line_nodes = root.at_path(line_path, cii);
    if line_nodes.len() > MAX_LINES {
        return Err(EInvoiceError::Malformed("too many invoice lines".into()));
    }
    let mut lines = Vec::new();
    for item in line_nodes {
        let (desc_path, qty_path, price_path, rate_path, amount_path) = if cii {
            (
                &["ram:SpecifiedTradeProduct", "ram:Name"][..],
                &["ram:SpecifiedLineTradeDelivery", "ram:BilledQuantity"][..],
                &[
                    "ram:SpecifiedLineTradeAgreement",
                    "ram:NetPriceProductTradePrice",
                    "ram:ChargeAmount",
                ][..],
                &[
                    "ram:SpecifiedLineTradeSettlement",
                    "ram:ApplicableTradeTax",
                    "ram:RateApplicablePercent",
                ][..],
                &[
                    "ram:SpecifiedLineTradeSettlement",
                    "ram:SpecifiedTradeSettlementLineMonetarySummation",
                    "ram:LineTotalAmount",
                ][..],
            )
        } else {
            (
                &["cac:Item", "cbc:Description"][..],
                if ubl_root == "CreditNote" {
                    &["cbc:CreditedQuantity"][..]
                } else {
                    &["cbc:InvoicedQuantity"][..]
                },
                &["cac:Price", "cbc:PriceAmount"][..],
                &["cac:Item", "cac:ClassifiedTaxCategory", "cbc:Percent"][..],
                &["cbc:LineExtensionAmount"][..],
            )
        };
        let get = |path, key| item.exact_value(path, cii, key);
        let description = get(desc_path, "line description")?
            .ok_or(EInvoiceError::Missing("line description"))?;
        let quantity = get(qty_path, "quantity")?.ok_or(EInvoiceError::Missing("quantity"))?;
        let price = get(price_path, "unit price")?.ok_or(EInvoiceError::Missing("unit price"))?;
        let rate = get(rate_path, "VAT rate")?.ok_or(EInvoiceError::Missing("VAT rate"))?;
        let amount = get(amount_path, "line net amount")?
            .ok_or(EInvoiceError::Missing("line net amount"))?;
        lines.push(InvoiceLine {
            description,
            quantity: parse_dec(quantity, "quantity")?,
            unit_price: parse_dec(price, "unit price")?,
            vat_rate: parse_dec(rate, "VAT rate")?,
            net_amount: parse_dec(amount, "line amount")?,
        });
    }
    let tax_path: &[&str] = if cii {
        &[
            "rsm:CrossIndustryInvoice",
            "rsm:SupplyChainTradeTransaction",
            "ram:ApplicableHeaderTradeSettlement",
            "ram:ApplicableTradeTax",
        ]
    } else {
        &["root", "cac:TaxTotal", "cac:TaxSubtotal"]
    };
    let mut tax_totals = Vec::new();
    let mut incomplete_tax = false;
    for tax in root.at_path(tax_path, cii) {
        let (rate_path, basis_path, amount_path) = if cii {
            (
                &["ram:RateApplicablePercent"][..],
                &["ram:BasisAmount"][..],
                &["ram:CalculatedAmount"][..],
            )
        } else {
            (
                &["cbc:Percent"][..],
                &["cbc:TaxableAmount"][..],
                &["cbc:TaxAmount"][..],
            )
        };
        let values = (
            tax.exact_value(rate_path, cii, "VAT rate")?,
            tax.exact_value(basis_path, cii, "taxable amount")?,
            tax.exact_value(amount_path, cii, "tax amount")?,
        );
        if let (Some(rate), Some(basis), Some(amount)) = values {
            tax_totals.push(TaxTotal {
                rate: parse_dec(rate, "VAT rate")?,
                taxable_amount: parse_dec(basis, "taxable amount")?,
                tax_amount: parse_dec(amount, "tax amount")?,
            });
        } else {
            incomplete_tax = true;
        }
    }
    let parse_exact_party = |path: &[&str], seller: bool| -> Result<Party, EInvoiceError> {
        let parties = root.at_path(path, cii);
        if parties.len() > 1 {
            return Err(EInvoiceError::Duplicate(if seller {
                "seller"
            } else {
                "buyer"
            }));
        }
        let n = parties.first().ok_or(EInvoiceError::Missing(if seller {
            "seller"
        } else {
            "buyer"
        }))?;
        let (name_path, reg_path) = if cii {
            (
                &["ram:Name"][..],
                &["ram:SpecifiedLegalOrganization", "ram:ID"][..],
            )
        } else {
            (
                &["cac:PartyName", "cbc:Name"][..],
                &["cac:PartyLegalEntity", "cbc:CompanyID"][..],
            )
        };
        let name = n
            .exact_value(name_path, cii, "party name")?
            .ok_or(EInvoiceError::Missing(if seller {
                "seller name"
            } else {
                "buyer name"
            }))?;
        let (vat_id, fiscal_id) = if cii {
            let regs = n.at_path(&["ram:SpecifiedTaxRegistration"], true);
            let ids: Vec<_> = regs
                .iter()
                .flat_map(|x| x.at_path(&["ram:ID"], true))
                .collect();
            let vals: Vec<_> = ids
                .iter()
                .filter(|id| id.scheme_id.as_deref() == Some("VA"))
                .filter_map(|id| clean_text(&id.text))
                .collect();
            let fiscal: Vec<_> = ids
                .iter()
                .filter(|id| id.scheme_id.as_deref() == Some("FC"))
                .filter_map(|id| clean_text(&id.text))
                .collect();
            if vals.len() > 1 || fiscal.len() > 1 {
                return Err(EInvoiceError::Duplicate("party VAT ID"));
            }
            (vals.into_iter().next(), fiscal.into_iter().next())
        } else {
            let schemes = n.at_path(&["cac:PartyTaxScheme"], false);
            let mut values = Vec::new();
            for scheme in schemes {
                if scheme
                    .exact_value(&["cac:TaxScheme", "cbc:ID"], false, "tax scheme")?
                    .as_deref()
                    == Some("VAT")
                {
                    if let Some(v) =
                        scheme.exact_value(&["cbc:CompanyID"], false, "party VAT ID")?
                    {
                        values.push(v);
                    }
                }
            }
            if values.len() > 1 {
                return Err(EInvoiceError::Duplicate("party VAT ID"));
            }
            (values.into_iter().next(), None)
        };
        let registration_id = n.exact_value(reg_path, cii, "party registration ID")?;
        if vat_id.as_ref().is_some_and(|s| s.len() > 64)
            || registration_id.as_ref().is_some_and(|s| s.len() > 64)
            || fiscal_id.as_ref().is_some_and(|s| s.len() > 64)
        {
            return Err(EInvoiceError::IdentifierTooLong);
        }
        Ok(Party {
            name,
            vat_id,
            registration_id,
            fiscal_id,
        })
    };
    let seller = parse_exact_party(seller_path, true)?;
    let buyer = parse_exact_party(buyer_path, false)?;
    let mut issues = Vec::new();
    if incomplete_tax {
        issues.push(ValidationIssue {
            check: "incomplete_tax_breakdown",
            kind: Some(ValidationIssueKind::IncompleteTaxBreakdown),
            declared: Decimal::ZERO,
            calculated: Decimal::ZERO,
            difference: Decimal::ZERO,
        });
    }
    if tax_totals.is_empty() && !lines.is_empty() {
        issues.push(ValidationIssue {
            check: "missing_tax_breakdown",
            kind: Some(ValidationIssueKind::MissingTaxBreakdown),
            declared: Decimal::ZERO,
            calculated: Decimal::ZERO,
            difference: Decimal::ZERO,
        });
    }
    // Document-level allowances and charges (BT-107/BT-108) belong to the
    // header, not to a line. They are already part of the declared breakdown
    // and of the invoice total without VAT, so the checks below must take them
    // into account exactly like EN 16931 (BR-CO-13, BR-S-08/BR-Z-08/BR-E-08)
    // does: a discount reduces the taxable basis and the total, a charge adds
    // to both.
    let document_adjustments: &[&str] = if cii {
        &[
            "rsm:CrossIndustryInvoice",
            "rsm:SupplyChainTradeTransaction",
            "ram:ApplicableHeaderTradeSettlement",
            "ram:SpecifiedTradeAllowanceCharge",
        ]
    } else if ubl_root == "CreditNote" {
        &["root:CreditNote", "cac:AllowanceCharge"]
    } else {
        &["root:Invoice", "cac:AllowanceCharge"]
    };
    let mut adjustment_basis: BTreeMap<Decimal, Decimal> = BTreeMap::new();
    let mut adjustment_total = Decimal::ZERO;
    // A nonzero adjustment whose amount cannot be attributed to a rate leaves
    // the expected per-rate basis unknown; its sign cannot be read at all when
    // the indicator is missing. Both cases make the corresponding comparison
    // unsound, so it is skipped there instead of risking a false alert.
    let mut unattributed_adjustment = false;
    let mut unreadable_adjustment = false;
    for adjustment in root.at_path(document_adjustments, cii) {
        let (amount_path, rate_path, indicator_path) = if cii {
            (
                &["ram:ActualAmount"][..],
                &["ram:CategoryTradeTax", "ram:RateApplicablePercent"][..],
                &["ram:ChargeIndicator", "udt:Indicator"][..],
            )
        } else {
            (
                &["cbc:Amount"][..],
                &["cac:TaxCategory", "cbc:Percent"][..],
                &["cbc:ChargeIndicator"][..],
            )
        };
        let amount =
            adjustment.exact_value(amount_path, cii, "document allowance or charge amount")?;
        let Some(amount) = amount else {
            continue;
        };
        let amount = parse_dec(amount, "document allowance or charge amount")?;
        let indicator = adjustment.exact_value(
            indicator_path,
            cii,
            "document allowance or charge indicator",
        )?;
        // A charge adds to the taxable basis, an allowance subtracts from it.
        let signed = match indicator.as_deref().map(str::trim) {
            Some("true") | Some("1") => amount,
            Some("false") | Some("0") => Decimal::ZERO
                .checked_sub(amount)
                .ok_or(EInvoiceError::AmountOverflow)?,
            _ => {
                if amount != Decimal::ZERO {
                    unreadable_adjustment = true;
                }
                continue;
            }
        };
        adjustment_total = adjustment_total
            .checked_add(signed)
            .ok_or(EInvoiceError::AmountOverflow)?;
        let rate =
            adjustment.exact_value(rate_path, cii, "document allowance or charge VAT rate")?;
        match rate {
            Some(rate) => {
                let entry = adjustment_basis
                    .entry(parse_dec(rate, "document allowance or charge VAT rate")?)
                    .or_insert(Decimal::ZERO);
                *entry = entry
                    .checked_add(signed)
                    .ok_or(EInvoiceError::AmountOverflow)?;
            }
            None => {
                if amount != Decimal::ZERO {
                    unattributed_adjustment = true;
                }
            }
        }
    }
    // Reconcile the declared VAT breakdown against the lines, rate by rate.
    // Every rate is compared whatever its sign: a zero-rated invoice still
    // declares its 0 % group, and a credit note carries negative *amounts*,
    // never a negative rate, so a negative rate is always reported. The check
    // runs only when a breakdown exists; an absent breakdown is already
    // reported above. The expected basis uses the *declared* line net amounts
    // (already rounded to the cent), never a value recomputed from unrounded
    // quantities and prices.
    if !tax_totals.is_empty() {
        let mut expected_basis: BTreeMap<Decimal, Decimal> = BTreeMap::new();
        for line in &lines {
            let entry = expected_basis.entry(line.vat_rate).or_insert(Decimal::ZERO);
            *entry = entry
                .checked_add(line.net_amount)
                .ok_or(EInvoiceError::AmountOverflow)?;
        }
        for (rate, amount) in adjustment_basis {
            let entry = expected_basis.entry(rate).or_insert(Decimal::ZERO);
            *entry = entry
                .checked_add(amount)
                .ok_or(EInvoiceError::AmountOverflow)?;
        }
        let mut declared_basis: BTreeMap<Decimal, Decimal> = BTreeMap::new();
        for tax in &tax_totals {
            let entry = declared_basis.entry(tax.rate).or_insert(Decimal::ZERO);
            *entry = entry
                .checked_add(tax.taxable_amount)
                .ok_or(EInvoiceError::AmountOverflow)?;
        }
        let mut rates: BTreeSet<Decimal> = expected_basis.keys().copied().collect();
        rates.extend(declared_basis.keys().copied());
        for rate in rates {
            let expected = expected_basis.get(&rate).copied();
            let declared = declared_basis.get(&rate).copied();
            let expected_sum = expected.unwrap_or(Decimal::ZERO);
            let declared_sum = declared.unwrap_or(Decimal::ZERO);
            if rate < Decimal::ZERO || expected.is_some() != declared.is_some() {
                push_issue(
                    &mut issues,
                    "vat_rate_mismatch",
                    ValidationIssueKind::VatRateMismatch,
                    declared_sum,
                    expected_sum,
                )?;
            } else if declared_sum != expected_sum
                && !unattributed_adjustment
                && !unreadable_adjustment
            {
                push_issue(
                    &mut issues,
                    "vat_basis_mismatch",
                    ValidationIssueKind::VatBasisMismatch,
                    declared_sum,
                    expected_sum,
                )?;
            }
        }
        if unattributed_adjustment || unreadable_adjustment {
            let mut declared_total = Decimal::ZERO;
            for amount in declared_basis.values() {
                declared_total = declared_total
                    .checked_add(*amount)
                    .ok_or(EInvoiceError::AmountOverflow)?;
            }
            let mut expected_total = Decimal::ZERO;
            for amount in expected_basis.values() {
                expected_total = expected_total
                    .checked_add(*amount)
                    .ok_or(EInvoiceError::AmountOverflow)?;
            }
            push_issue(
                &mut issues,
                "vat_basis_unverifiable",
                ValidationIssueKind::UnverifiableVatBasis,
                declared_total,
                expected_total,
            )?;
        }
    }
    for line in &lines {
        let calculated = line
            .quantity
            .checked_mul(line.unit_price)
            .ok_or(EInvoiceError::AmountOverflow)?
            .round_dp_with_strategy(2, rust_decimal::RoundingStrategy::MidpointAwayFromZero);
        // Both amounts are declared rounded to the cent, so a one-cent
        // disagreement per line is a rounding artefact, not a data error.
        issue_within(
            &mut issues,
            "line_quantity_times_unit_price",
            line.net_amount,
            calculated,
            Decimal::new(1, 2),
        )?;
    }
    let line_sum = lines.iter().try_fold(Decimal::ZERO, |sum, l| {
        sum.checked_add(l.net_amount)
            .ok_or(EInvoiceError::AmountOverflow)
    })?;
    // When an adjustment's indicator is missing its sign — and therefore the
    // total of all the adjustments — is unknown; comparing the declared total
    // without VAT would then be a guess that could raise a false alert.
    if !unreadable_adjustment {
        issue(
            &mut issues,
            "lines_equal_net",
            net,
            line_sum
                .checked_add(adjustment_total)
                .ok_or(EInvoiceError::AmountOverflow)?,
        )?;
    }
    for tax in &tax_totals {
        issue(
            &mut issues,
            "vat_by_rate",
            tax.tax_amount,
            (tax.taxable_amount
                .checked_mul(tax.rate)
                .ok_or(EInvoiceError::AmountOverflow)?
                .checked_div(Decimal::from(100))
                .ok_or(EInvoiceError::AmountOverflow)?)
            .round_dp_with_strategy(2, rust_decimal::RoundingStrategy::MidpointAwayFromZero),
        )?;
    }
    let tax_sum = tax_totals.iter().try_fold(Decimal::ZERO, |sum, t| {
        sum.checked_add(t.tax_amount)
            .ok_or(EInvoiceError::AmountOverflow)
    })?;
    issue(
        &mut issues,
        "gross_equals_net_plus_vat",
        gross,
        net.checked_add(tax_sum)
            .ok_or(EInvoiceError::AmountOverflow)?,
    )?;
    Ok(EInvoice {
        format: if cii { "CII" } else { "UBL" }.into(),
        seller,
        buyer,
        invoice_number: clean_required(number, "invoice number")?,
        invoice_date: date,
        currency: clean_required(currency, "currency")?,
        lines,
        net_total: net,
        tax_totals,
        gross_total: gross,
        validation: ValidationCheck { issues },
    })
}

fn is_iso_date(date: &str) -> bool {
    if date.len() != 10
        || date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
        || !date
            .chars()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return false;
    }
    let year = date[0..4].parse::<u32>().unwrap_or(0);
    let month = date[5..7].parse::<u32>().unwrap_or(0);
    let day = date[8..10].parse::<u32>().unwrap_or(0);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

fn check_xml_encoding(source: &str) -> Result<(), EInvoiceError> {
    let trimmed = source.trim_start_matches(char::is_whitespace);
    let declaration_start = if trimmed.starts_with("<?xml") {
        Some(source.len() - trimmed.len())
    } else {
        source.find("<?xml")
    };
    let Some(start) = declaration_start else {
        return Ok(());
    };
    let tail = &source[start..];
    let Some(end) = tail.find("?>") else {
        return Err(EInvoiceError::Encoding);
    };
    let declaration = tail[..end].to_ascii_lowercase();
    let Some((_, value)) = declaration.split_once("encoding") else {
        return Ok(());
    };
    let Some((_, value)) = value.split_once('=') else {
        return Err(EInvoiceError::Encoding);
    };
    let quote = value
        .trim_start()
        .chars()
        .next()
        .ok_or(EInvoiceError::Encoding)?;
    if quote != '\'' && quote != '"' {
        return Err(EInvoiceError::Encoding);
    }
    let encoding = value
        .trim_start()
        .strip_prefix(quote)
        .ok_or(EInvoiceError::Encoding)?
        .split(quote)
        .next()
        .ok_or(EInvoiceError::Encoding)?;
    if matches!(encoding, "utf-8" | "utf8") {
        Ok(())
    } else {
        Err(EInvoiceError::Encoding)
    }
}

fn parse_dec(s: String, field: &'static str) -> Result<Decimal, EInvoiceError> {
    let value = Decimal::from_str(s.trim()).map_err(|_| EInvoiceError::InvalidDecimal(field))?;
    if value.abs() > Decimal::from(1_000_000_000_000i64) || value.scale() > 6 {
        return Err(EInvoiceError::AmountOutOfRange);
    }
    Ok(value)
}
fn clean_required(s: String, key: &'static str) -> Result<String, EInvoiceError> {
    clean_text(&s)
        .filter(|x| !x.is_empty())
        .ok_or(EInvoiceError::Missing(key))
}
fn clean_text(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    let trimmed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    Some(trimmed.chars().take(MAX_TEXT).collect())
}
fn issue(
    issues: &mut Vec<ValidationIssue>,
    check: &'static str,
    declared: Decimal,
    calculated: Decimal,
) -> Result<(), EInvoiceError> {
    if declared != calculated {
        let difference = calculated
            .checked_sub(declared)
            .ok_or(EInvoiceError::AmountOverflow)?;
        issues.push(ValidationIssue {
            check,
            kind: None,
            declared,
            calculated,
            difference,
        });
    }
    Ok(())
}

/// Report a difference only when it exceeds `tolerance`. Declared e-invoice
/// amounts are already rounded to the cent, so a smaller disagreement is a
/// rounding artefact and must not raise an alert.
fn issue_within(
    issues: &mut Vec<ValidationIssue>,
    check: &'static str,
    declared: Decimal,
    calculated: Decimal,
    tolerance: Decimal,
) -> Result<(), EInvoiceError> {
    let difference = calculated
        .checked_sub(declared)
        .ok_or(EInvoiceError::AmountOverflow)?;
    if difference.abs() > tolerance {
        issues.push(ValidationIssue {
            check,
            kind: None,
            declared,
            calculated,
            difference,
        });
    }
    Ok(())
}

/// Push a typed issue unconditionally: some problems (a rate that appears on
/// one side only, a negative rate) must be reported even when the declared and
/// calculated amounts happen to be equal.
fn push_issue(
    issues: &mut Vec<ValidationIssue>,
    check: &'static str,
    kind: ValidationIssueKind,
    declared: Decimal,
    calculated: Decimal,
) -> Result<(), EInvoiceError> {
    let difference = calculated
        .checked_sub(declared)
        .ok_or(EInvoiceError::AmountOverflow)?;
    issues.push(ValidationIssue {
        check,
        kind: Some(kind),
        declared,
        calculated,
        difference,
    });
    Ok(())
}
