use aux_invoices::{check_totals, parse_einvoice_xml, EInvoiceError};
use rust_decimal::Decimal;

const CII: &str = r#"<rsm:CrossIndustryInvoice xmlns:rsm="urn:un:unece:uncefact:data:standard:CrossIndustryInvoice:100" xmlns:ram="urn:un:unece:uncefact:data:standard:ReusableAggregateBusinessInformationEntity:100" xmlns:udt="urn:un:unece:uncefact:data:standard:UnqualifiedDataType:100"><rsm:ExchangedDocument><ram:ID>FX-2026-01</ram:ID><ram:IssueDateTime><udt:DateTimeString>20261001</udt:DateTimeString></ram:IssueDateTime></rsm:ExchangedDocument><rsm:SupplyChainTradeTransaction><ram:IncludedSupplyChainTradeLineItem><ram:SpecifiedTradeProduct><ram:Name>Fictitious service</ram:Name></ram:SpecifiedTradeProduct><ram:SpecifiedLineTradeAgreement><ram:NetPriceProductTradePrice><ram:ChargeAmount>100.00</ram:ChargeAmount></ram:NetPriceProductTradePrice></ram:SpecifiedLineTradeAgreement><ram:SpecifiedLineTradeDelivery><ram:BilledQuantity>1</ram:BilledQuantity></ram:SpecifiedLineTradeDelivery><ram:SpecifiedLineTradeSettlement><ram:ApplicableTradeTax><ram:RateApplicablePercent>20</ram:RateApplicablePercent></ram:ApplicableTradeTax><ram:SpecifiedTradeSettlementLineMonetarySummation><ram:LineTotalAmount>100.00</ram:LineTotalAmount></ram:SpecifiedTradeSettlementLineMonetarySummation></ram:SpecifiedLineTradeSettlement></ram:IncludedSupplyChainTradeLineItem><ram:ApplicableHeaderTradeSettlement><ram:InvoiceCurrencyCode>EUR</ram:InvoiceCurrencyCode><ram:ApplicableTradeTax><ram:BasisAmount>100.00</ram:BasisAmount><ram:CalculatedAmount>20.00</ram:CalculatedAmount><ram:RateApplicablePercent>20</ram:RateApplicablePercent></ram:ApplicableTradeTax><ram:SpecifiedTradeSettlementHeaderMonetarySummation><ram:TaxBasisTotalAmount>100.00</ram:TaxBasisTotalAmount><ram:GrandTotalAmount>120.00</ram:GrandTotalAmount></ram:SpecifiedTradeSettlementHeaderMonetarySummation></ram:ApplicableHeaderTradeSettlement><ram:ApplicableHeaderTradeAgreement><ram:SellerTradeParty><ram:Name>Fiction SARL</ram:Name><ram:SpecifiedTaxRegistration><ram:ID>FR00000000000</ram:ID></ram:SpecifiedTaxRegistration></ram:SellerTradeParty><ram:BuyerTradeParty><ram:Name>Example SAS</ram:Name></ram:BuyerTradeParty></ram:ApplicableHeaderTradeAgreement></rsm:SupplyChainTradeTransaction></rsm:CrossIndustryInvoice>"#;
const UBL: &str = r#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"><cbc:ID>UBL-2026-01</cbc:ID><cbc:IssueDate>2026-10-02</cbc:IssueDate><cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode><cac:AccountingSupplierParty><cac:Party><cac:PartyName><cbc:Name>Fiction GmbH</cbc:Name></cac:PartyName><cac:PartyTaxScheme><cbc:CompanyID>DE000000000</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme></cac:Party></cac:AccountingSupplierParty><cac:AccountingCustomerParty><cac:Party><cac:PartyName><cbc:Name>Example BV</cbc:Name></cac:PartyName></cac:Party></cac:AccountingCustomerParty><cac:TaxTotal><cac:TaxSubtotal><cbc:TaxableAmount>100.00</cbc:TaxableAmount><cbc:TaxAmount>21.00</cbc:TaxAmount><cbc:Percent>21</cbc:Percent></cac:TaxSubtotal></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:LineExtensionAmount>100.00</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount>100.00</cbc:TaxExclusiveAmount><cbc:TaxInclusiveAmount>121.00</cbc:TaxInclusiveAmount><cbc:PayableAmount>121.00</cbc:PayableAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:ID>1</cbc:ID><cbc:InvoicedQuantity>2</cbc:InvoicedQuantity><cbc:LineExtensionAmount>100.00</cbc:LineExtensionAmount><cac:Item><cbc:Description>Fictitious goods</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>21</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>50.00</cbc:PriceAmount></cac:Price></cac:InvoiceLine></Invoice>"#;

#[test]
fn parses_cii_and_normalizes_date() {
    let invoice = parse_einvoice_xml(CII.as_bytes()).unwrap();
    assert_eq!(invoice.format, "CII");
    assert_eq!(invoice.invoice_date, "2026-10-01");
    assert_eq!(invoice.seller.name, "Fiction SARL");
    assert_eq!(invoice.lines[0].net_amount, Decimal::new(100, 0));
    assert!(invoice.validation.issues.is_empty());
}

#[test]
fn parses_ubl_and_reconciles_totals() {
    let invoice = parse_einvoice_xml(UBL.as_bytes()).unwrap();
    assert_eq!(invoice.format, "UBL");
    assert_eq!(invoice.buyer.name, "Example BV");
    assert!(invoice.validation.issues.is_empty());
}

#[test]
fn reports_rounding_difference_without_correction() {
    let xml = UBL
        .replace(
            "<cbc:TaxAmount>21.00</cbc:TaxAmount>",
            "<cbc:TaxAmount>21.01</cbc:TaxAmount>",
        )
        .replace(
            "<cbc:TaxInclusiveAmount>121.00</cbc:TaxInclusiveAmount>",
            "<cbc:TaxInclusiveAmount>121.01</cbc:TaxInclusiveAmount>",
        )
        .replace(
            "<cbc:PayableAmount>121.00</cbc:PayableAmount>",
            "<cbc:PayableAmount>121.01</cbc:PayableAmount>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert_eq!(invoice.tax_totals[0].tax_amount, Decimal::new(2101, 2));
    assert_eq!(invoice.validation.issues[0].check, "vat_by_rate");
    assert_eq!(invoice.validation.issues[0].difference, Decimal::new(-1, 2));
}

#[test]
fn reports_false_total() {
    let xml = UBL
        .replace(
            "<cbc:TaxInclusiveAmount>121.00</cbc:TaxInclusiveAmount>",
            "<cbc:TaxInclusiveAmount>122.00</cbc:TaxInclusiveAmount>",
        )
        .replace(
            "<cbc:PayableAmount>121.00</cbc:PayableAmount>",
            "<cbc:PayableAmount>122.00</cbc:PayableAmount>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(invoice
        .validation
        .issues
        .iter()
        .any(|i| i.check == "gross_equals_net_plus_vat" && i.difference == -Decimal::ONE));
}

#[test]
fn checks_quantity_times_unit_price_and_validates_calendar_date() {
    let bad_line = UBL.replace(
        "<cbc:PriceAmount>50.00</cbc:PriceAmount>",
        "<cbc:PriceAmount>49.00</cbc:PriceAmount>",
    );
    let invoice = parse_einvoice_xml(bad_line.as_bytes()).unwrap();
    assert!(invoice
        .validation
        .issues
        .iter()
        .any(|issue| issue.check == "line_quantity_times_unit_price"));
    let invalid_date = UBL.replace("2026-10-02", "2026-02-30");
    assert!(matches!(
        parse_einvoice_xml(invalid_date.as_bytes()),
        Err(EInvoiceError::Malformed(_))
    ));
}

#[test]
fn refuses_doctype_xxe_and_billion_laughs() {
    for xml in [
        "<!DOCTYPE x><Invoice/>",
        "<!DOCTYPE x [<!ENTITY ext SYSTEM 'file:///etc/passwd'>]><Invoice>&ext;</Invoice>",
        "<!DOCTYPE lolz [<!ENTITY lol 'ha'><!ENTITY lol2 '&lol;&lol;'>]><Invoice>&lol2;</Invoice>",
    ] {
        assert_eq!(
            parse_einvoice_xml(xml.as_bytes()),
            Err(EInvoiceError::Doctype)
        );
    }
}

#[test]
fn bounds_depth_size_and_rejects_invalid_encoding_and_namespace_trap() {
    let deep = format!("{}{}", "<a>".repeat(10_000), "</a>".repeat(10_000));
    assert_eq!(
        parse_einvoice_xml(deep.as_bytes()),
        Err(EInvoiceError::TooDeep)
    );
    assert_eq!(
        parse_einvoice_xml(&vec![b' '; 50 * 1024 * 1024]),
        Err(EInvoiceError::TooLarge)
    );
    assert_eq!(
        parse_einvoice_xml(&[0xff, 0xfe, 0xfd]),
        Err(EInvoiceError::Encoding)
    );
    assert_eq!(
        parse_einvoice_xml(b"<?xml version='1.0' encoding='ISO-8859-1'?><Invoice/>"),
        Err(EInvoiceError::Encoding)
    );
    assert_eq!(
        parse_einvoice_xml(b"<fake:Invoice xmlns:legit='urn:oasis:names:specification:ubl:schema:xsd:Invoice-2' xmlns:fake='urn:attacker' xmlns:cbc='urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2'><cbc:ID>x</cbc:ID></fake:Invoice>"),
        Err(EInvoiceError::UnsupportedFormat)
    );
}

#[test]
fn ignores_foreign_namespace_ids_and_rejects_real_duplicate() {
    let ubl = UBL.replace(
        "<cbc:ID>UBL-2026-01</cbc:ID>",
        "<e:ID xmlns:e=\"urn:attacker\">FORGED</e:ID><cbc:ID>UBL-2026-01</cbc:ID>",
    );
    assert_eq!(
        parse_einvoice_xml(ubl.as_bytes()).unwrap().invoice_number,
        "UBL-2026-01"
    );
    let duplicate = UBL.replace(
        "<cbc:ID>UBL-2026-01</cbc:ID>",
        "<cbc:ID>FORGED</cbc:ID><cbc:ID>UBL-2026-01</cbc:ID>",
    );
    assert_eq!(
        parse_einvoice_xml(duplicate.as_bytes()),
        Err(EInvoiceError::Duplicate("invoice number"))
    );

    let cii = CII.replace(
        "<ram:ID>FX-2026-01</ram:ID>",
        "<e:ID xmlns:e=\"urn:attacker\">FORGED</e:ID><ram:ID>FX-2026-01</ram:ID>",
    );
    assert_eq!(
        parse_einvoice_xml(cii.as_bytes()).unwrap().invoice_number,
        "FX-2026-01"
    );
}

#[test]
fn ignores_ubl_values_outside_their_exact_paths() {
    let xml = UBL.replace(
        "<Invoice xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\">",
        "<Invoice xmlns=\"urn:oasis:names:specification:ubl:schema:xsd:Invoice-2\"><ext:UBLExtensions xmlns:ext=\"urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2\" xmlns:cbc=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\"><ext:UBLExtension><ext:ExtensionContent><cbc:ID>FORGED</cbc:ID><cbc:IssueDate>1900-01-01</cbc:IssueDate><cbc:CompanyID>FORGED</cbc:CompanyID><cbc:TaxExclusiveAmount>999</cbc:TaxExclusiveAmount></ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions><cac:AdditionalDocumentReference xmlns:cac=\"urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2\" xmlns:cbc=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\"><cbc:ID>ALSO-FORGED</cbc:ID><cbc:IssueDate>1901-01-01</cbc:IssueDate><cbc:CompanyID>WRONG</cbc:CompanyID><cbc:TaxExclusiveAmount>998</cbc:TaxExclusiveAmount></cac:AdditionalDocumentReference>",
    )
    .replace(
        "<cac:InvoiceLine>",
        "<cac:InvoiceLine><cbc:ID>LINE-ID-MUST-NOT-BECOME-INVOICE-ID</cbc:ID><cbc:IssueDate>1902-01-01</cbc:IssueDate><cbc:CompanyID>LINE-VAT-MUST-NOT-BECOME-SELLER-VAT</cbc:CompanyID><cbc:TaxExclusiveAmount>997</cbc:TaxExclusiveAmount>",
    );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert_eq!(invoice.invoice_number, "UBL-2026-01");
    assert_eq!(invoice.invoice_date, "2026-10-02");
    assert_eq!(invoice.seller.vat_id.as_deref(), Some("DE000000000"));
    assert_eq!(invoice.net_total, Decimal::new(100, 0));
}

#[test]
fn duplicate_exact_issue_date_is_a_typed_error() {
    let xml = UBL.replace(
        "<cbc:IssueDate>2026-10-02</cbc:IssueDate>",
        "<cbc:IssueDate>2026-10-02</cbc:IssueDate><cbc:IssueDate xmlns:cbc=\"urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2\">2026-10-03</cbc:IssueDate>",
    );
    assert_eq!(
        parse_einvoice_xml(xml.as_bytes()),
        Err(EInvoiceError::Duplicate("invoice date"))
    );
}

#[test]
fn ignores_cii_values_in_notes_and_trade_products() {
    let xml = CII.replace(
        "<rsm:ExchangedDocument>",
        "<rsm:ExchangedDocument><ram:IncludedNote><ram:ID>FORGED</ram:ID><ram:IssueDateTime><udt:DateTimeString>19000101</udt:DateTimeString></ram:IssueDateTime><ram:TaxBasisTotalAmount>999</ram:TaxBasisTotalAmount></ram:IncludedNote>",
    ).replace(
        "<ram:SpecifiedTradeProduct>",
        "<ram:SpecifiedTradeProduct><ram:CompanyID>FORGED</ram:CompanyID>",
    );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert_eq!(invoice.invoice_number, "FX-2026-01");
    assert_eq!(invoice.invoice_date, "2026-10-01");
    assert_eq!(invoice.net_total, Decimal::new(100, 0));
}

#[test]
fn rejects_out_of_range_decimals_without_panicking() {
    for amount in ["10000000000000", "79228162514264337593543950335"] {
        let xml = UBL.replace(
            "<cbc:PriceAmount>50.00</cbc:PriceAmount>",
            &format!("<cbc:PriceAmount>{amount}</cbc:PriceAmount>"),
        );
        let outcome = std::panic::catch_unwind(|| parse_einvoice_xml(xml.as_bytes()));
        assert!(matches!(outcome, Ok(Err(EInvoiceError::AmountOutOfRange))));
    }
}

proptest::proptest! {
    #[test]
    fn sum_of_decimal_line_values_is_stable(values in proptest::collection::vec(0u32..100_000, 1..100)) {
        let sum: Decimal = values.iter().map(|v| Decimal::new(i64::from(*v), 2)).sum();
        let reverse: Decimal = values.iter().rev().map(|v| Decimal::new(i64::from(*v), 2)).sum();
        proptest::prop_assert_eq!(sum, reverse);
    }
}

#[test]
fn identifies_registration_and_tax_ids_by_scheme() {
    let ubl = UBL.replace("<cac:PartyTaxScheme><cbc:CompanyID>DE000000000</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>", "<cac:PartyTaxScheme><cbc:CompanyID>FRVAT</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme><cac:PartyLegalEntity><cbc:CompanyID>FR-REG</cbc:CompanyID></cac:PartyLegalEntity>");
    let invoice = parse_einvoice_xml(ubl.as_bytes()).unwrap();
    assert_eq!(invoice.seller.vat_id.as_deref(), Some("FRVAT"));
    assert_eq!(invoice.seller.registration_id.as_deref(), Some("FR-REG"));
    let cii = CII.replace("<ram:SpecifiedTaxRegistration><ram:ID>FR00000000000</ram:ID></ram:SpecifiedTaxRegistration>", "<ram:SpecifiedTaxRegistration><ram:ID schemeID=\"VA\">FRVAT</ram:ID></ram:SpecifiedTaxRegistration><ram:SpecifiedTaxRegistration><ram:ID schemeID=\"FC\">FISCAL</ram:ID></ram:SpecifiedTaxRegistration><ram:SpecifiedLegalOrganization><ram:ID>FR-REG</ram:ID></ram:SpecifiedLegalOrganization>");
    let invoice = parse_einvoice_xml(cii.as_bytes()).unwrap();
    assert_eq!(invoice.seller.vat_id.as_deref(), Some("FRVAT"));
    assert_eq!(invoice.seller.registration_id.as_deref(), Some("FR-REG"));
    assert_eq!(invoice.seller.fiscal_id.as_deref(), Some("FISCAL"));
}

#[test]
fn rejects_multiple_roots_and_long_identifiers() {
    assert_eq!(
        parse_einvoice_xml(format!("{UBL}<Invoice/>").as_bytes()),
        Err(EInvoiceError::MultipleRoots)
    );
    let long = "x".repeat(65);
    let xml = UBL.replace("</cac:PartyName>", &format!("</cac:PartyName><cac:PartyLegalEntity><cbc:CompanyID>{long}</cbc:CompanyID></cac:PartyLegalEntity>"));
    assert_eq!(
        parse_einvoice_xml(xml.as_bytes()),
        Err(EInvoiceError::IdentifierTooLong)
    );
}

#[test]
fn incomplete_and_missing_tax_breakdowns_are_reported() {
    let incomplete = UBL.replace("<cbc:TaxableAmount>100.00</cbc:TaxableAmount>", "");
    let invoice = parse_einvoice_xml(incomplete.as_bytes()).unwrap();
    assert!(invoice
        .validation
        .issues
        .iter()
        .any(|i| i.kind == Some(aux_invoices::ValidationIssueKind::IncompleteTaxBreakdown)));
    let missing = UBL.replace("<cac:TaxTotal><cac:TaxSubtotal><cbc:TaxableAmount>100.00</cbc:TaxableAmount><cbc:TaxAmount>21.00</cbc:TaxAmount><cbc:Percent>21</cbc:Percent></cac:TaxSubtotal></cac:TaxTotal>", "");
    let invoice = parse_einvoice_xml(missing.as_bytes()).unwrap();
    assert!(invoice
        .validation
        .issues
        .iter()
        .any(|i| i.kind == Some(aux_invoices::ValidationIssueKind::MissingTaxBreakdown)));
}

#[test]
fn utf8_encoding_declaration_after_comment_is_checked() {
    let xml = format!("<!-- preface --><?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>{UBL}");
    assert_eq!(
        parse_einvoice_xml(xml.as_bytes()),
        Err(EInvoiceError::Encoding)
    );
}

#[test]
fn zero_rated_lines_with_a_taxed_recap_are_a_rate_mismatch() {
    // The line says 0 %, the header still declares a 20 % group. Both sides of
    // the disagreement must be reported, amounts included.
    let xml = CII.replace(
        "<ram:SpecifiedLineTradeSettlement><ram:ApplicableTradeTax><ram:RateApplicablePercent>20</ram:RateApplicablePercent>",
        "<ram:SpecifiedLineTradeSettlement><ram:ApplicableTradeTax><ram:RateApplicablePercent>0</ram:RateApplicablePercent>",
    );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    let mismatches: Vec<_> = invoice
        .validation
        .issues
        .iter()
        .filter(|i| i.kind == Some(aux_invoices::ValidationIssueKind::VatRateMismatch))
        .collect();
    assert_eq!(mismatches.len(), 2);
    assert!(mismatches
        .iter()
        .any(|i| i.declared == Decimal::ZERO && i.calculated == Decimal::new(100, 0)));
    assert!(mismatches
        .iter()
        .any(|i| i.declared == Decimal::new(100, 0) && i.calculated == Decimal::ZERO));
}

#[test]
fn a_rate_missing_from_the_recap_is_a_rate_mismatch() {
    // A second line at 10 % has no matching subtotal in the header.
    let xml = UBL.replace(
        "</cac:InvoiceLine>",
        "</cac:InvoiceLine><cac:InvoiceLine><cbc:ID>2</cbc:ID><cbc:InvoicedQuantity>1</cbc:InvoicedQuantity><cbc:LineExtensionAmount>50.00</cbc:LineExtensionAmount><cac:Item><cbc:Description>Second line</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>10</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>50.00</cbc:PriceAmount></cac:Price></cac:InvoiceLine>",
    );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(invoice.validation.issues.iter().any(|i| {
        i.kind == Some(aux_invoices::ValidationIssueKind::VatRateMismatch)
            && i.declared == Decimal::ZERO
            && i.calculated == Decimal::new(50, 0)
    }));
}

#[test]
fn a_matching_rate_with_a_different_basis_is_a_basis_mismatch() {
    let xml = CII
        .replace(
            "<ram:ChargeAmount>100.00</ram:ChargeAmount>",
            "<ram:ChargeAmount>90.00</ram:ChargeAmount>",
        )
        .replace(
            "<ram:LineTotalAmount>100.00</ram:LineTotalAmount>",
            "<ram:LineTotalAmount>90.00</ram:LineTotalAmount>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(invoice.validation.issues.iter().any(|i| {
        i.kind == Some(aux_invoices::ValidationIssueKind::VatBasisMismatch)
            && i.declared == Decimal::new(100, 0)
            && i.calculated == Decimal::new(90, 0)
            && i.difference == -Decimal::new(10, 0)
    }));
}

#[test]
fn declared_rounded_line_amounts_drive_the_per_rate_basis() {
    // Two lines of 0.05 € at 20 % declare a 0.10 € basis: the check must use
    // the declared, already-rounded line amounts, never a value recomputed
    // from unrounded quantities and prices (BR-CO-10/13).
    let xml = r#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"><cbc:ID>UBL-CENT</cbc:ID><cbc:IssueDate>2026-10-02</cbc:IssueDate><cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode><cac:AccountingSupplierParty><cac:Party><cac:PartyName><cbc:Name>Fiction GmbH</cbc:Name></cac:PartyName></cac:Party></cac:AccountingSupplierParty><cac:AccountingCustomerParty><cac:Party><cac:PartyName><cbc:Name>Example BV</cbc:Name></cac:PartyName></cac:Party></cac:AccountingCustomerParty><cac:TaxTotal><cac:TaxSubtotal><cbc:TaxableAmount>0.10</cbc:TaxableAmount><cbc:TaxAmount>0.02</cbc:TaxAmount><cbc:Percent>20</cbc:Percent></cac:TaxSubtotal></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:LineExtensionAmount>0.10</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount>0.10</cbc:TaxExclusiveAmount><cbc:PayableAmount>0.12</cbc:PayableAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:ID>1</cbc:ID><cbc:InvoicedQuantity>1</cbc:InvoicedQuantity><cbc:LineExtensionAmount>0.05</cbc:LineExtensionAmount><cac:Item><cbc:Description>A</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>20</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>0.05</cbc:PriceAmount></cac:Price></cac:InvoiceLine><cac:InvoiceLine><cbc:ID>2</cbc:ID><cbc:InvoicedQuantity>1</cbc:InvoicedQuantity><cbc:LineExtensionAmount>0.05</cbc:LineExtensionAmount><cac:Item><cbc:Description>B</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>20</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>0.05</cbc:PriceAmount></cac:Price></cac:InvoiceLine></Invoice>"#;
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(
        invoice.validation.issues.is_empty(),
        "{:?}",
        invoice.validation.issues
    );
}

#[test]
fn unrounded_unit_prices_do_not_fake_a_basis_mismatch() {
    // 3 × 0.333333 = 0.999999 €, declared rounded to 1.00 € per line. Summing
    // the unrounded products at 20 % would find 1.999998 € against the
    // declared 2.00 € and wrongly alert.
    let xml = r#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"><cbc:ID>UBL-UNROUNDED</cbc:ID><cbc:IssueDate>2026-10-02</cbc:IssueDate><cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode><cac:AccountingSupplierParty><cac:Party><cac:PartyName><cbc:Name>Fiction GmbH</cbc:Name></cac:PartyName></cac:Party></cac:AccountingSupplierParty><cac:AccountingCustomerParty><cac:Party><cac:PartyName><cbc:Name>Example BV</cbc:Name></cac:PartyName></cac:Party></cac:AccountingCustomerParty><cac:TaxTotal><cac:TaxSubtotal><cbc:TaxableAmount>2.00</cbc:TaxableAmount><cbc:TaxAmount>0.40</cbc:TaxAmount><cbc:Percent>20</cbc:Percent></cac:TaxSubtotal></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:LineExtensionAmount>2.00</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount>2.00</cbc:TaxExclusiveAmount><cbc:PayableAmount>2.40</cbc:PayableAmount></cac:LegalMonetaryTotal><cac:InvoiceLine><cbc:ID>1</cbc:ID><cbc:InvoicedQuantity>3</cbc:InvoicedQuantity><cbc:LineExtensionAmount>1.00</cbc:LineExtensionAmount><cac:Item><cbc:Description>A</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>20</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>0.333333</cbc:PriceAmount></cac:Price></cac:InvoiceLine><cac:InvoiceLine><cbc:ID>2</cbc:ID><cbc:InvoicedQuantity>3</cbc:InvoicedQuantity><cbc:LineExtensionAmount>1.00</cbc:LineExtensionAmount><cac:Item><cbc:Description>B</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>20</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>0.333333</cbc:PriceAmount></cac:Price></cac:InvoiceLine></Invoice>"#;
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(
        invoice.validation.issues.is_empty(),
        "{:?}",
        invoice.validation.issues
    );
}

#[test]
fn a_document_allowance_is_part_of_the_expected_basis() {
    // A 10 € document allowance at 20 % brings the declared 100 € basis down
    // to 90 €. When the breakdown accounts for it, nothing is reported; when
    // it does not, the basis mismatch is reported (BR-S-08).
    let accounted = UBL
        .replace("<cbc:Percent>21</cbc:Percent>", "<cbc:Percent>20</cbc:Percent>")
        .replace(
            "<cbc:TaxableAmount>100.00</cbc:TaxableAmount>",
            "<cbc:TaxableAmount>90.00</cbc:TaxableAmount>",
        )
        .replace(
            "<cbc:TaxAmount>21.00</cbc:TaxAmount>",
            "<cbc:TaxAmount>18.00</cbc:TaxAmount>",
        )
        .replace(
            "<cbc:TaxExclusiveAmount>100.00</cbc:TaxExclusiveAmount>",
            "<cbc:TaxExclusiveAmount>90.00</cbc:TaxExclusiveAmount>",
        )
        .replace(
            "<cbc:PayableAmount>121.00</cbc:PayableAmount>",
            "<cbc:PayableAmount>108.00</cbc:PayableAmount>",
        )
        .replace(
            "</Invoice>",
            "<cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:Amount>10.00</cbc:Amount><cac:TaxCategory><cbc:Percent>20</cbc:Percent></cac:TaxCategory></cac:AllowanceCharge></Invoice>",
        );
    let invoice = parse_einvoice_xml(accounted.as_bytes()).unwrap();
    assert!(
        invoice.validation.issues.is_empty(),
        "{:?}",
        invoice.validation.issues
    );

    let unaccounted = accounted.replace(
        "<cbc:TaxableAmount>90.00</cbc:TaxableAmount>",
        "<cbc:TaxableAmount>100.00</cbc:TaxableAmount>",
    );
    let invoice = parse_einvoice_xml(unaccounted.as_bytes()).unwrap();
    assert!(invoice.validation.issues.iter().any(|i| {
        i.kind == Some(aux_invoices::ValidationIssueKind::VatBasisMismatch)
            && i.declared == Decimal::new(100, 0)
            && i.calculated == Decimal::new(90, 0)
            && i.difference == -Decimal::new(10, 0)
    }));
}

#[test]
fn an_allowance_without_a_vat_rate_is_reported_as_unverifiable() {
    // A 10 € document allowance with no tax category: the per-rate basis can
    // no longer be checked, so the reader says so instead of staying silent.
    let doc = UBL.replace(
        "</Invoice>",
        "<cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:Amount>10.00</cbc:Amount></cac:AllowanceCharge></Invoice>",
    );
    let invoice = parse_einvoice_xml(doc.as_bytes()).unwrap();
    assert!(
        invoice
            .validation
            .issues
            .iter()
            .any(|i| i.kind == Some(aux_invoices::ValidationIssueKind::UnverifiableVatBasis)),
        "{:?}",
        invoice.validation.issues
    );
}

#[test]
fn a_cii_allowance_without_a_vat_rate_is_reported_as_unverifiable() {
    // The CII shape of the UBL case above. A 10 € document allowance
    // with no `CategoryTradeTax` rate cannot be attributed to a rate group, so
    // the per-rate basis can no longer be checked: the reader must say so
    // rather than stay silent.
    let doc = CII.replace(
        "</ram:ApplicableHeaderTradeSettlement>",
        "<ram:SpecifiedTradeAllowanceCharge><ram:ChargeIndicator><udt:Indicator>false</udt:Indicator></ram:ChargeIndicator><ram:ActualAmount>10.00</ram:ActualAmount></ram:SpecifiedTradeAllowanceCharge></ram:ApplicableHeaderTradeSettlement>",
    );
    let invoice = parse_einvoice_xml(doc.as_bytes()).unwrap();
    assert!(
        invoice
            .validation
            .issues
            .iter()
            .any(|i| i.kind == Some(aux_invoices::ValidationIssueKind::UnverifiableVatBasis)),
        "{:?}",
        invoice.validation.issues
    );
}

#[test]
fn a_cii_document_allowance_is_part_of_the_expected_basis() {
    let accounted = CII
        .replace(
            "<ram:BasisAmount>100.00</ram:BasisAmount>",
            "<ram:BasisAmount>90.00</ram:BasisAmount>",
        )
        .replace(
            "<ram:CalculatedAmount>20.00</ram:CalculatedAmount>",
            "<ram:CalculatedAmount>18.00</ram:CalculatedAmount>",
        )
        .replace(
            "<ram:TaxBasisTotalAmount>100.00</ram:TaxBasisTotalAmount>",
            "<ram:TaxBasisTotalAmount>90.00</ram:TaxBasisTotalAmount>",
        )
        .replace(
            "<ram:GrandTotalAmount>120.00</ram:GrandTotalAmount>",
            "<ram:GrandTotalAmount>108.00</ram:GrandTotalAmount>",
        )
        .replace(
            "</ram:ApplicableHeaderTradeSettlement>",
            "<ram:SpecifiedTradeAllowanceCharge><ram:ChargeIndicator><udt:Indicator>false</udt:Indicator></ram:ChargeIndicator><ram:ActualAmount>10.00</ram:ActualAmount><ram:CategoryTradeTax><ram:RateApplicablePercent>20</ram:RateApplicablePercent></ram:CategoryTradeTax></ram:SpecifiedTradeAllowanceCharge></ram:ApplicableHeaderTradeSettlement>",
        );
    let invoice = parse_einvoice_xml(accounted.as_bytes()).unwrap();
    assert!(
        invoice.validation.issues.is_empty(),
        "{:?}",
        invoice.validation.issues
    );

    let unaccounted = accounted.replace(
        "<ram:BasisAmount>90.00</ram:BasisAmount>",
        "<ram:BasisAmount>100.00</ram:BasisAmount>",
    );
    let invoice = parse_einvoice_xml(unaccounted.as_bytes()).unwrap();
    assert!(invoice.validation.issues.iter().any(|i| {
        i.kind == Some(aux_invoices::ValidationIssueKind::VatBasisMismatch)
            && i.declared == Decimal::new(100, 0)
            && i.calculated == Decimal::new(90, 0)
    }));
}

#[test]
fn a_document_charge_raises_the_expected_basis() {
    // Shipping charged at the document level at 20 % (BR-S-08): the declared
    // basis and total already include it.
    let xml = UBL
        .replace("<cbc:Percent>21</cbc:Percent>", "<cbc:Percent>20</cbc:Percent>")
        .replace(
            "<cbc:TaxableAmount>100.00</cbc:TaxableAmount>",
            "<cbc:TaxableAmount>110.00</cbc:TaxableAmount>",
        )
        .replace(
            "<cbc:TaxAmount>21.00</cbc:TaxAmount>",
            "<cbc:TaxAmount>22.00</cbc:TaxAmount>",
        )
        .replace(
            "<cbc:TaxExclusiveAmount>100.00</cbc:TaxExclusiveAmount>",
            "<cbc:TaxExclusiveAmount>110.00</cbc:TaxExclusiveAmount>",
        )
        .replace(
            "<cbc:PayableAmount>121.00</cbc:PayableAmount>",
            "<cbc:PayableAmount>132.00</cbc:PayableAmount>",
        )
        .replace(
            "</Invoice>",
            "<cac:AllowanceCharge><cbc:ChargeIndicator>true</cbc:ChargeIndicator><cbc:Amount>10.00</cbc:Amount><cac:TaxCategory><cbc:Percent>20</cbc:Percent></cac:TaxCategory></cac:AllowanceCharge></Invoice>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(
        invoice.validation.issues.is_empty(),
        "{:?}",
        invoice.validation.issues
    );
}

#[test]
fn a_credit_note_with_a_document_allowance_reconciles_the_basis() {
    let xml = r#"<CreditNote xmlns="urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"><cbc:ID>UBL-CN</cbc:ID><cbc:IssueDate>2026-10-02</cbc:IssueDate><cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode><cac:AccountingSupplierParty><cac:Party><cac:PartyName><cbc:Name>Fiction GmbH</cbc:Name></cac:PartyName></cac:Party></cac:AccountingSupplierParty><cac:AccountingCustomerParty><cac:Party><cac:PartyName><cbc:Name>Example BV</cbc:Name></cac:PartyName></cac:Party></cac:AccountingCustomerParty><cac:TaxTotal><cac:TaxSubtotal><cbc:TaxableAmount>95.00</cbc:TaxableAmount><cbc:TaxAmount>19.00</cbc:TaxAmount><cbc:Percent>20</cbc:Percent></cac:TaxSubtotal></cac:TaxTotal><cac:LegalMonetaryTotal><cbc:TaxExclusiveAmount>95.00</cbc:TaxExclusiveAmount><cbc:PayableAmount>114.00</cbc:PayableAmount></cac:LegalMonetaryTotal><cac:CreditNoteLine><cbc:ID>1</cbc:ID><cbc:CreditedQuantity>1</cbc:CreditedQuantity><cbc:LineExtensionAmount>100.00</cbc:LineExtensionAmount><cac:Item><cbc:Description>Returned goods</cbc:Description><cac:ClassifiedTaxCategory><cbc:Percent>20</cbc:Percent></cac:ClassifiedTaxCategory></cac:Item><cac:Price><cbc:PriceAmount>100.00</cbc:PriceAmount></cac:Price></cac:CreditNoteLine><cac:AllowanceCharge><cbc:ChargeIndicator>false</cbc:ChargeIndicator><cbc:Amount>5.00</cbc:Amount><cac:TaxCategory><cbc:Percent>20</cbc:Percent></cac:TaxCategory></cac:AllowanceCharge></CreditNote>"#;
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert_eq!(invoice.format, "UBL");
    assert!(
        invoice.validation.issues.is_empty(),
        "{:?}",
        invoice.validation.issues
    );
}

#[test]
fn a_credit_note_with_negative_amounts_is_not_a_vat_mismatch() {
    // A credit note carries negative amounts at a positive rate; only negative
    // *rates* are a data error.
    let xml = CII
        .replace(
            "<ram:BilledQuantity>1</ram:BilledQuantity>",
            "<ram:BilledQuantity>-1</ram:BilledQuantity>",
        )
        .replace(
            "<ram:LineTotalAmount>100.00</ram:LineTotalAmount>",
            "<ram:LineTotalAmount>-100.00</ram:LineTotalAmount>",
        )
        .replace(
            "<ram:TaxBasisTotalAmount>100.00</ram:TaxBasisTotalAmount>",
            "<ram:TaxBasisTotalAmount>-100.00</ram:TaxBasisTotalAmount>",
        )
        .replace(
            "<ram:GrandTotalAmount>120.00</ram:GrandTotalAmount>",
            "<ram:GrandTotalAmount>-120.00</ram:GrandTotalAmount>",
        )
        .replace(
            "<ram:BasisAmount>100.00</ram:BasisAmount>",
            "<ram:BasisAmount>-100.00</ram:BasisAmount>",
        )
        .replace(
            "<ram:CalculatedAmount>20.00</ram:CalculatedAmount>",
            "<ram:CalculatedAmount>-20.00</ram:CalculatedAmount>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(!invoice.validation.issues.iter().any(|i| {
        i.kind == Some(aux_invoices::ValidationIssueKind::VatRateMismatch)
            || i.kind == Some(aux_invoices::ValidationIssueKind::VatBasisMismatch)
    }));
}

#[test]
fn a_negative_vat_rate_is_always_reported() {
    // A negative rate on both sides is still a data error, never silently kept.
    let xml = CII
        .replace(
            "<ram:SpecifiedLineTradeSettlement><ram:ApplicableTradeTax><ram:RateApplicablePercent>20</ram:RateApplicablePercent>",
            "<ram:SpecifiedLineTradeSettlement><ram:ApplicableTradeTax><ram:RateApplicablePercent>-20</ram:RateApplicablePercent>",
        )
        .replace(
            "<ram:RateApplicablePercent>20</ram:RateApplicablePercent></ram:ApplicableTradeTax><ram:SpecifiedTradeSettlementHeaderMonetarySummation>",
            "<ram:RateApplicablePercent>-20</ram:RateApplicablePercent></ram:ApplicableTradeTax><ram:SpecifiedTradeSettlementHeaderMonetarySummation>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert!(invoice
        .validation
        .issues
        .iter()
        .any(|i| i.kind == Some(aux_invoices::ValidationIssueKind::VatRateMismatch)));
}

#[test]
fn duplicate_scheme_id_and_invalid_attribute_entity_are_typed_errors() {
    let duplicate = CII.replace(
        "<ram:ID>FR00000000000</ram:ID>",
        "<ram:ID schemeID=\"VA\" schemeID=\"FC\">FRVAT</ram:ID>",
    );
    assert!(matches!(
        parse_einvoice_xml(duplicate.as_bytes()),
        Err(EInvoiceError::Malformed(_))
    ));
    let bad_entity = CII.replace(
        "<ram:ID>FR00000000000</ram:ID>",
        "<ram:ID schemeID=\"VA&bogus;\">FRVAT</ram:ID>",
    );
    assert!(matches!(
        parse_einvoice_xml(bad_entity.as_bytes()),
        Err(EInvoiceError::Malformed(_))
    ));
}

#[test]
fn ubl_with_an_exchanged_document_extension_stays_ubl() {
    // The vocabulary comes from the root element's namespace, never from a
    // descendant named `ExchangedDocument` hidden in an extension block.
    let xml = UBL.replace(
        "<cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>",
        "<cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode><ext:UBLExtensions xmlns:ext=\"urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2\"><ext:UBLExtension><ext:ExtensionContent><ExchangedDocument xmlns=\"urn:example:ext\">ignored</ExchangedDocument></ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions>",
    );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    assert_eq!(invoice.format, "UBL");
    assert_eq!(invoice.invoice_number, "UBL-2026-01");
    assert!(invoice.validation.issues.is_empty());
}

#[test]
fn check_totals_is_empty_for_a_balanced_invoice() {
    let invoice = parse_einvoice_xml(UBL.as_bytes()).unwrap();
    assert!(check_totals(&invoice).is_empty());
}

#[test]
fn check_totals_reports_one_cent_off_in_a_tax_amount_only() {
    // The tax line is one cent high and the gross follows it, so only the
    // per-rate check (rate × base = 21.00) disagrees.
    let xml = UBL
        .replace(
            "<cbc:TaxAmount>21.00</cbc:TaxAmount>",
            "<cbc:TaxAmount>21.01</cbc:TaxAmount>",
        )
        .replace(
            "<cbc:TaxInclusiveAmount>121.00</cbc:TaxInclusiveAmount>",
            "<cbc:TaxInclusiveAmount>121.01</cbc:TaxInclusiveAmount>",
        )
        .replace(
            "<cbc:PayableAmount>121.00</cbc:PayableAmount>",
            "<cbc:PayableAmount>121.01</cbc:PayableAmount>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    let issues = check_totals(&invoice);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "vat_by_rate");
    assert_eq!(issues[0].declared, Decimal::new(2101, 2));
    assert_eq!(issues[0].calculated, Decimal::new(2100, 2));
    assert_eq!(issues[0].difference, Decimal::new(-1, 2));
}

#[test]
fn check_totals_reports_one_cent_off_in_the_gross_only() {
    // The taxes agree with the lines; only the declared gross is one cent high.
    let xml = UBL
        .replace(
            "<cbc:TaxInclusiveAmount>121.00</cbc:TaxInclusiveAmount>",
            "<cbc:TaxInclusiveAmount>121.01</cbc:TaxInclusiveAmount>",
        )
        .replace(
            "<cbc:PayableAmount>121.00</cbc:PayableAmount>",
            "<cbc:PayableAmount>121.01</cbc:PayableAmount>",
        );
    let invoice = parse_einvoice_xml(xml.as_bytes()).unwrap();
    let issues = check_totals(&invoice);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "gross_equals_net_plus_vat");
    assert_eq!(issues[0].declared, Decimal::new(12101, 2));
    assert_eq!(issues[0].calculated, Decimal::new(12100, 2));
}
