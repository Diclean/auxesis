//! Deterministic guard on owner identifiers in outbound channel text.
//!
//! An IBAN or a phone number is an owner identifier. A channel send may carry
//! one only to the owner's own chat (`owner_self`); any other recipient gets a
//! hold before the text leaves the machine. The check runs the `kernel-privacy`
//! recognisers directly, so it reuses their checksums (IBAN mod-97 for known
//! countries) and shapes, and adds no regex, model or network call. It skips
//! the registry's thresholds on purpose: a low-confidence phone-shaped value
//! is held too, which is the fail-toward-masking side.
//!
//! A hold names the kind only, never the value.

use std::sync::OnceLock;

use kernel_privacy::recognizers::{iban::IbanRecognizer, phone::PhoneRecognizer};
use kernel_privacy::Recognizer;

/// The owner identifier kinds the guard holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerIdentifier {
    /// An IBAN the recogniser accepts (mod-97 for known countries).
    Iban,
    /// A phone number.
    Phone,
}

impl OwnerIdentifier {
    /// Plain-language label for logs and refusal text. Never the value.
    pub fn label(self) -> &'static str {
        match self {
            Self::Iban => "IBAN",
            Self::Phone => "phone number",
        }
    }
}

struct Guard {
    iban: IbanRecognizer,
    phone: PhoneRecognizer,
}

/// The first owner identifier in `text` (IBAN before phone), or `None`.
pub fn owner_identifier_in(text: &str) -> Option<OwnerIdentifier> {
    static GUARD: OnceLock<Guard> = OnceLock::new();
    let guard = GUARD.get_or_init(|| Guard {
        iban: IbanRecognizer::new(),
        phone: PhoneRecognizer::new(),
    });
    if !guard.iban.analyze(text).is_empty() {
        Some(OwnerIdentifier::Iban)
    } else if !guard.phone.analyze(text).is_empty() {
        Some(OwnerIdentifier::Phone)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FAKE: the checksum-valid specimen FR IBAN from the kernel-privacy tests.
    const IBAN: &str = "FR76 3000 6000 0112 3456 7890 189";
    // FAKE: a number in the 555 fiction range (kernel-privacy phone vector).
    const PHONE: &str = "+1 (202) 555-0142";

    #[test]
    fn a_valid_iban_is_an_owner_identifier() {
        assert_eq!(
            owner_identifier_in(&format!("voici {IBAN} merci")),
            Some(OwnerIdentifier::Iban)
        );
    }

    #[test]
    fn a_wrapped_owner_iban_is_held() {
        // A messy email wraps the IBAN over a newline, or over CRLF plus
        // indentation: the holds see one identifier, not two fragments.
        assert_eq!(
            owner_identifier_in("voici FR76 3000 6000 0112 3456\n7890 189 merci"),
            Some(OwnerIdentifier::Iban)
        );
        assert_eq!(
            owner_identifier_in("IBAN FR76 3000 6000 0112\r\n   3456 7890 189"),
            Some(OwnerIdentifier::Iban)
        );
    }

    #[test]
    fn a_wrapped_owner_phone_is_held() {
        assert_eq!(
            owner_identifier_in("appelle +1 (202)\r\n555-0142"),
            Some(OwnerIdentifier::Phone)
        );
    }

    #[test]
    fn a_phone_number_is_an_owner_identifier() {
        assert_eq!(
            owner_identifier_in(&format!("appelle {PHONE}")),
            Some(OwnerIdentifier::Phone)
        );
    }

    #[test]
    fn an_iban_of_a_known_country_needs_a_valid_checksum() {
        // The last digit changed, so mod-97 fails and the IBAN recogniser does
        // not accept it. The grouped digits still read as a phone-shaped run,
        // so the guard holds it as a phone: fail toward masking, not an IBAN.
        let broken = "FR76 3000 6000 0112 3456 7890 180";
        assert!(!kernel_privacy::recognizers::iban::valid_iban(broken));
        assert_ne!(
            owner_identifier_in(broken),
            Some(OwnerIdentifier::Iban),
            "a checksum-failing value is not an IBAN"
        );
    }

    #[test]
    fn plain_text_and_dates_are_not_held() {
        assert_eq!(
            owner_identifier_in("Rendez-vous le 12/03/2026 à 14 h."),
            None
        );
        assert_eq!(owner_identifier_in("Bonjour, tout va bien."), None);
    }

    #[test]
    fn labels_never_carry_a_value() {
        assert_eq!(OwnerIdentifier::Iban.label(), "IBAN");
        assert_eq!(OwnerIdentifier::Phone.label(), "phone number");
    }
}
