//! Recogniser modules and the built-in recogniser sets.
//!
//! Since the masker fails toward masking, every deterministic rule is mounted
//! by default, including the unverified ones (NIR, SIRET, passport MRZ). The
//! registry relabels an unverified hit `NATIONAL_ID` at a lower score instead
//! of dropping it.

pub mod address;
pub mod cn_id;
pub mod credit_card;
pub mod dob_label;
pub mod email;
pub mod eu_ids;
pub mod fr;
pub mod hu;
pub mod iban;
pub mod id_label;
pub mod ip;
pub mod label_value;
pub mod mrz;
pub mod payment_ids;
pub mod phone;
mod secret_lines;
pub(crate) use secret_lines::export_scan;
mod secret_link;
mod secret_prose;
pub mod secrets;
pub mod sensitive_terms;
pub mod uk_nino;
pub mod url;
pub mod za;

use crate::recognizer::Recognizer;

/// Every recogniser, in run order.
pub fn default_recognizers() -> Vec<Box<dyn Recognizer>> {
    vec![
        Box::new(email::EmailRecognizer::new()),
        Box::new(phone::PhoneRecognizer::new()),
        Box::new(address::AddressRecognizer::new()),
        Box::new(sensitive_terms::SensitiveTermsRecognizer::new()),
        Box::new(secrets::SecretRecognizer::new()),
        Box::new(iban::IbanRecognizer::new()),
        Box::new(credit_card::CreditCardRecognizer::new()),
        Box::new(ip::IpV4Recognizer::new()),
        Box::new(url::UrlRecognizer::new()),
        Box::new(fr::FrNirRecognizer::new()),
        Box::new(fr::FrSirenRecognizer::new()),
        Box::new(fr::FrSiretRecognizer::new()),
        Box::new(fr::FrVatRecognizer::new()),
        Box::new(hu::HuTajRecognizer::new()),
        Box::new(hu::HuTaxIdRecognizer::new()),
        Box::new(za::ZaIdRecognizer::new()),
        Box::new(uk_nino::UkNinoRecognizer::new()),
        Box::new(eu_ids::DeSteuerIdRecognizer::new()),
        Box::new(eu_ids::EsDniRecognizer::new()),
        Box::new(eu_ids::ItCodiceFiscaleRecognizer::new()),
        Box::new(eu_ids::NlBsnRecognizer::new()),
        Box::new(eu_ids::BeNationalNumberRecognizer::new()),
        Box::new(eu_ids::PlPeselRecognizer::new()),
        Box::new(eu_ids::PtNifRecognizer::new()),
        Box::new(eu_ids::AtSvNrRecognizer::new()),
        Box::new(eu_ids::IePpsnRecognizer::new()),
        Box::new(eu_ids::SePersonnummerRecognizer::new()),
        Box::new(eu_ids::Eu1cRecognizer::new()),
        Box::new(cn_id::CnResidentIdRecognizer::new()),
        Box::new(cn_id::CnCreditCodeRecognizer),
        Box::new(email::SpelledEmailRecognizer),
        Box::new(secrets::CuedCodeRecognizer),
        Box::new(mrz::PassportMrzRecognizer::new()),
        Box::new(payment_ids::PaymentIdsRecognizer::new()),
        Box::new(label_value::LabelValueRecognizer::new()),
        Box::new(id_label::IdLabelRecognizer::new()),
        Box::new(dob_label::DobLabelRecognizer::new()),
    ]
}

/// Every recogniser in the crate. Kept as a named set for callers that want the
/// full registry explicitly; it equals [`default_recognizers`].
pub fn all_recognizers() -> Vec<Box<dyn Recognizer>> {
    default_recognizers()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_set_mounts_every_rule() {
        let default: Vec<&'static str> = default_recognizers()
            .iter()
            .map(|recognizer| recognizer.name())
            .collect();
        for name in [
            "email",
            "phone",
            "address",
            "iban",
            "fr_nir",
            "fr_siren",
            "fr_siret",
            "fr_vat",
            "hu_taj",
            "hu_taxid",
            "za_id",
            "uk_nino",
            "de_steuer_id",
            "es_dni",
            "it_codice_fiscale",
            "nl_bsn",
            "be_national_number",
            "passport_mrz",
            "payment_ids",
            "label_value",
            "id_label",
        ] {
            assert!(default.contains(&name), "default registry misses {name}");
        }
        assert!(default_recognizers()
            .iter()
            .any(|recognizer| !recognizer.verified()));
    }

    #[test]
    fn all_set_equals_the_default_set() {
        let default: Vec<&'static str> = default_recognizers()
            .iter()
            .map(|recognizer| recognizer.name())
            .collect();
        let all: Vec<&'static str> = all_recognizers()
            .iter()
            .map(|recognizer| recognizer.name())
            .collect();
        assert_eq!(all, default);
    }
}
