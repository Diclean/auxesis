//! Crucial values in invoice / OCR-shaped text never leave, in any mode.
//!
//! IBAN, cards (with their security code), national IDs, bank account numbers
//! and health terms must be gone from the output of a private gate and of an
//! open gate alike. The cases come from the 2026-10-14 probe; every value is
//! invented. BIC, date of birth, VAT and label over-masking are out of scope.

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::Gate;

const KEY: [u8; 32] = [7u8; 32];

fn grant(mode: PrivacyMode) -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    match admit(PathId::A1, mode, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("expected Allow in {mode:?}, got {other:?}"),
    }
}

fn open_gate() -> Gate {
    Gate::for_grant(&grant(PrivacyMode::Open), KEY)
}

fn private_gate() -> Gate {
    Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Camille Exemple"])
        .expect("dictionary")
}

fn norm(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_uppercase()
}

/// (label, text, the crucial value that must not survive).
const CASES: &[(&str, &str, &str)] = &[
    ("iban plain", "IBAN: FR7630006000011234567890189", "FR7630006000011234567890189"),
    ("iban spaced", "IBAN FR76 3000 6000 0112 3456 7890 189", "FR7630006000011234567890189"),
    ("iban line break", "IBAN: FR76 3000 6000 0112\n3456 7890 189", "FR7630006000011234567890189"),
    ("iban lowercase", "iban fr76 3000 6000 0112 3456 7890 189", "FR7630006000011234567890189"),
    ("iban OCR O-for-0", "IBAN FR76 3OOO 6OOO 0112 3456 7890 189", "01123456789"),
    ("iban OCR l-for-1", "IBAN FR76 3000 6000 O1l2 3456 7890 189", "34567890189"),
    ("iban GB", "IBAN: GB82 WEST 1234 5698 7654 32", "GB82WEST12345698765432"),
    ("iban DE dashes", "DE89-3704-0044-0532-0130-00", "DE89370400440532013000"),
    ("RIB fr", "RIB : 30006 00001 12345678901 89", "30006000011234567890189"),
    ("RIB compte", "Compte 30006 00001 12345678901 89", "12345678901"),
    ("card spaced", "Card 4111 1111 1111 1111 exp 12/27", "4111111111111111"),
    ("card dashes", "Paid with 5555-5555-5555-4444", "5555555555554444"),
    ("card amex", "Amex 3782 822463 10005", "378282246310005"),
    ("card OCR l-for-1", "Card 4111 1111 1111 111l", "411111111111111"),
    ("card + cvv", "Card 4111111111111111 CVV 737", "CVV737"),
    ("cvc colon", "Visa 4111 1111 1111 1111, CVC: 4821", "4821"),
    ("security code", "security code 905 on the back", "905"),
    ("cvv2", "cvv2 = 318", "318"),
    ("US SSN", "SSN: 219-09-9999", "219099999"),
    ("US SSN spaced", "SSN 219 09 9999", "219099999"),
    ("US SSN no dash", "Social security 219099999", "219099999"),
    ("US SSN no dash cue", "SSN 219099999", "219099999"),
    ("US EIN", "EIN 12-3456789", "123456789"),
    ("US TIN", "Tax ID: 98-7654321", "987654321"),
    ("US routing+acct", "Routing 021000021 Account 4567812345", "4567812345"),
    ("US ABA", "ABA 011401533 acct no. 123456789012", "123456789012"),
    ("UK NINO", "NI number QQ 12 34 56 C", "QQ123456C"),
    ("UK sort+acct", "Sort code 12-34-56, account 31926819", "31926819"),
    ("UK sort code", "Sort code 12-34-56, account 31926819", "123456"),
    ("FR SIRET", "SIRET 732 829 320 00074", "73282932000074"),
    ("DE VAT", "VAT ID DE136695976", "DE136695976"),
    ("FR NIR", "N° sécu 1 85 05 78 006 084 91", "185057800608491"),
    ("passport MRZ", "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10", "L898902C3"),
    ("passport no", "Passport no. 18AB34567", "18AB34567"),
    ("AWS key", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("password", "Login: anna / Password: Hunter2!Blue", "HUNTER2BLUE"),
    ("health multi-word", "Diagnosis: type 2 diabetes, insulin daily", "DIABETES"),
    ("health insulin", "Diagnosis: type 2 diabetes, insulin daily", "INSULIN"),
    ("invoice OCR block", "INVOICE #2026-114\nBill to: Northwind Ltd\nIBAN GB82 WEST 1234 5698 7654 32\nBIC WESTGB2L\nVAT GB123456789\nTotal due: 1,250.00 GBP", "GB82WEST12345698765432"),
];

/// The cases, plus a token built at run time so no secret-shaped literal sits
/// in the file.
fn cases() -> Vec<(&'static str, String, String)> {
    let token = ["ghp_", "1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R8"].concat();
    CASES
        .iter()
        .map(|(label, text, value)| (*label, text.to_string(), value.to_string()))
        .chain([("GitHub token", format!("token {token}"), token)])
        .collect()
}

fn leaks(mut gate: Gate) -> Vec<&'static str> {
    cases()
        .into_iter()
        .filter(|(_, text, value)| {
            // A refused text leaks nothing.
            let Ok((safe, _)) = gate.text(text) else {
                return false;
            };
            norm(safe.as_str()).contains(&norm(value))
        })
        .map(|(label, _, _)| label)
        .collect()
}

#[test]
fn private_gate_leaks_no_crucial_value() {
    assert_eq!(leaks(private_gate()), Vec::<&str>::new());
}

#[test]
fn open_gate_leaks_no_crucial_value() {
    assert_eq!(leaks(open_gate()), Vec::<&str>::new());
}

#[test]
fn open_gate_keeps_ordinary_invoice_text() {
    for text in [
        "Total due: 1,250.00 GBP",
        "Invoice #2026-114",
        "Due date 2026-10-14",
        "Quantity 12, unit price 34.50, line total 414.00",
        "Order 123-45-678 shipped; ref 1234-5678",
        "Room 305, floor 4, code of conduct section 12",
    ] {
        let (safe, _) = open_gate().text(text).expect("open text is issued");
        assert_eq!(safe.as_str(), text);
    }
}
