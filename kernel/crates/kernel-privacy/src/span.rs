//! Span and entity-kind types shared by every recogniser.
//!
//! A [`Span`] carries byte offsets into the original text, never the value
//! itself, so it is safe to log; the [`Span`] `Debug` impl is nonetheless
//! written by hand to make that guarantee explicit.

use std::fmt;

/// The kinds of personal data a deterministic recogniser can find.
///
/// `as_str` is the placeholder prefix issued by the anonymizer (`EMAIL`,
/// `PHONE`, …), written inside the `⟦…⟧` delimiters; `ALL` is the closed set the
/// registry and the eval harness agree on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityKind {
    /// E-mail address.
    Email,
    /// Telephone number, international or national.
    Phone,
    /// International Bank Account Number (ISO 13616).
    Iban,
    /// Payment card number (Luhn plus a brand prefix).
    CreditCard,
    /// IPv4 address.
    IpV4,
    /// Absolute URL with a scheme and a dotted host.
    Url,
    /// French NIR / sécurité sociale number (unverified: masked as
    /// `NATIONAL_ID`).
    FrNir,
    /// French SIREN company identifier.
    FrSiren,
    /// French SIRET establishment identifier (unverified: masked as
    /// `NATIONAL_ID`).
    FrSiret,
    /// French VAT number, numeric key form.
    FrVat,
    /// Hungarian TAJ social-security number.
    HuTaj,
    /// Hungarian adóazonosító jel tax identifier.
    HuTaxId,
    /// South African identity number.
    ZaId,
    /// UK National Insurance number: two letters, six digits and a suffix letter
    /// (no checksum, so it is masked as its own kind, K13).
    UkNino,
    /// ICAO 9303 passport number plus its 7-3-1 check digit (unverified:
    /// masked as `NATIONAL_ID`).
    PassportMrz,
    /// A checksum-valid national identifier whose specific kind is not known
    /// (an unverified recogniser, or a cueless ambiguous identifier). Masking
    /// must never depend on the specific label, so this generic kind is the
    /// fail-toward-masking fallback.
    NationalId,
    /// A person's name (GLiNER, slice 1d).
    Person,
    /// An organisation name (GLiNER, slice 1d).
    Organization,
    /// A postal address or place name (GLiNER, slice 1d). The model's
    /// `location` label is folded into this kind when it names a place.
    Address,
    /// A date of birth (GLiNER, slice 1d).
    DateOfBirth,
    /// A health condition (GLiNER, slice 1d).
    Health,
    /// A religion or faith (GLiNER, slice 1d).
    Religion,
    /// Sexual orientation or sex life, GDPR Art. 9 (deterministic lexicon, K10).
    SexualOrientation,
    /// Trade-union membership, GDPR Art. 9 (deterministic lexicon, K10).
    Union,
    /// Ethnic or racial origin, GDPR Art. 9 (deterministic lexicon, K10).
    Ethnicity,
    /// An API key or token, masked whole with its prefix (K10). Never a secret
    /// that an IBAN or a phone shape relabels.
    Secret,
}

impl EntityKind {
    /// Every kind, in a stable order.
    pub const ALL: [EntityKind; 26] = [
        EntityKind::Email,
        EntityKind::Phone,
        EntityKind::Iban,
        EntityKind::CreditCard,
        EntityKind::IpV4,
        EntityKind::Url,
        EntityKind::FrNir,
        EntityKind::FrSiren,
        EntityKind::FrSiret,
        EntityKind::FrVat,
        EntityKind::HuTaj,
        EntityKind::HuTaxId,
        EntityKind::ZaId,
        EntityKind::UkNino,
        EntityKind::PassportMrz,
        EntityKind::NationalId,
        EntityKind::Person,
        EntityKind::Organization,
        EntityKind::Address,
        EntityKind::DateOfBirth,
        EntityKind::Health,
        EntityKind::Religion,
        EntityKind::SexualOrientation,
        EntityKind::Union,
        EntityKind::Ethnicity,
        EntityKind::Secret,
    ];

    /// The stable token prefix for this kind (`EMAIL_0001`, `PHONE_0002`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            EntityKind::Email => "EMAIL",
            EntityKind::Phone => "PHONE",
            EntityKind::Iban => "IBAN",
            EntityKind::CreditCard => "CREDIT_CARD",
            EntityKind::IpV4 => "IPV4",
            EntityKind::Url => "URL",
            EntityKind::FrNir => "FR_NIR",
            EntityKind::FrSiren => "FR_SIREN",
            EntityKind::FrSiret => "FR_SIRET",
            EntityKind::FrVat => "FR_VAT",
            EntityKind::HuTaj => "HU_TAJ",
            EntityKind::HuTaxId => "HU_TAX_ID",
            EntityKind::ZaId => "ZA_ID",
            EntityKind::UkNino => "UK_NINO",
            EntityKind::PassportMrz => "PASSPORT_MRZ",
            EntityKind::NationalId => "NATIONAL_ID",
            EntityKind::Person => "PERSON",
            EntityKind::Organization => "ORGANIZATION",
            EntityKind::Address => "ADDRESS",
            EntityKind::DateOfBirth => "DATE_OF_BIRTH",
            EntityKind::Health => "HEALTH",
            EntityKind::Religion => "RELIGION",
            EntityKind::SexualOrientation => "SEXUAL_ORIENTATION",
            EntityKind::Union => "TRADE_UNION",
            EntityKind::Ethnicity => "ETHNIC_ORIGIN",
            EntityKind::Secret => "SECRET",
        }
    }

    /// Parse an eval-corpus `type` label, tolerating common aliases.
    pub fn parse(label: &str) -> Option<Self> {
        let upper = label.trim().to_ascii_uppercase();
        Some(match upper.as_str() {
            "EMAIL" | "EMAIL_ADDRESS" | "E-MAIL" | "MAIL" | "COURRIEL" => EntityKind::Email,
            "PHONE" | "PHONE_NUMBER" | "TELEPHONE" | "TEL" => EntityKind::Phone,
            "IBAN" | "IBAN_CODE" => EntityKind::Iban,
            "CREDIT_CARD" | "CARD" | "CC" | "PAYMENT_CARD" => EntityKind::CreditCard,
            "IPV4" | "IP" | "IP_ADDRESS" => EntityKind::IpV4,
            "URL" | "LINK" => EntityKind::Url,
            "FR_NIR" | "NIR" => EntityKind::FrNir,
            "FR_SIREN" | "SIREN" => EntityKind::FrSiren,
            "FR_SIRET" | "SIRET" => EntityKind::FrSiret,
            "FR_VAT" | "VAT" => EntityKind::FrVat,
            "HU_TAJ" | "TAJ" => EntityKind::HuTaj,
            "HU_TAX_ID" | "TAX_ID" | "TAXID" | "ADO" => EntityKind::HuTaxId,
            "ZA_ID" | "SA_ID" | "SOUTH_AFRICAN_ID" => EntityKind::ZaId,
            "UK_NINO" | "NINO" => EntityKind::UkNino,
            "PASSPORT_MRZ" | "MRZ" | "PASSPORT" | "PASSEPORT" => EntityKind::PassportMrz,
            "NATIONAL_ID" | "NATIONALID" | "NAT_ID" | "NATID" => EntityKind::NationalId,
            "PERSON" | "PER" | "NAME" => EntityKind::Person,
            "ORGANIZATION" | "ORG" | "COMPANY" | "ORGANISATION" => EntityKind::Organization,
            // The GLiNER benchmark label for a place is `location`; the corpus
            // counts it as `address`.
            "ADDRESS" | "LOCATION" | "PLACE" | "GPE" => EntityKind::Address,
            "DATE_OF_BIRTH" | "DATEOFBIRTH" | "DOB" | "BIRTHDATE" => EntityKind::DateOfBirth,
            "HEALTH" | "HEALTH_CONDITION" | "MEDICAL_CONDITION" => EntityKind::Health,
            "RELIGION" | "FAITH" => EntityKind::Religion,
            "SEXUAL_ORIENTATION" | "SEXUALITY" => EntityKind::SexualOrientation,
            "TRADE_UNION" | "UNION" => EntityKind::Union,
            "ETHNIC_ORIGIN" | "ETHNICITY" | "ETHNIC" => EntityKind::Ethnicity,
            "SECRET" | "API_KEY" | "CREDENTIAL" => EntityKind::Secret,
            _ => return None,
        })
    }

    /// Identifier kinds are normalized by stripping separators and folding
    /// case before being HMAC'd; textual kinds keep their exact spelling.
    pub fn is_identifier(self) -> bool {
        matches!(
            self,
            EntityKind::Phone
                | EntityKind::Iban
                | EntityKind::CreditCard
                | EntityKind::FrNir
                | EntityKind::FrSiren
                | EntityKind::FrSiret
                | EntityKind::FrVat
                | EntityKind::HuTaj
                | EntityKind::HuTaxId
                | EntityKind::ZaId
                | EntityKind::UkNino
                | EntityKind::PassportMrz
                | EntityKind::NationalId
        )
    }

    /// Whether a value of this kind never leaves the Mac in any mode: Open
    /// mode replaces it with a `[<class> removed]` marker (IBAN, payment card,
    /// national ID or passport, health term, secret, postal address). Every
    /// other kind is one Open mode leaves in clear. A date of birth after its
    /// label is prohibited as a span: see [`Span::is_prohibited`].
    pub fn is_prohibited(self) -> bool {
        matches!(
            self,
            EntityKind::Secret
                | EntityKind::Iban
                | EntityKind::CreditCard
                | EntityKind::Health
                | EntityKind::Address
                | EntityKind::FrNir
                | EntityKind::HuTaj
                | EntityKind::HuTaxId
                | EntityKind::ZaId
                | EntityKind::UkNino
                | EntityKind::PassportMrz
                | EntityKind::NationalId
        )
    }

    /// Mask priority when spans merge: the lowest value wins.
    ///
    /// The order is the one the privacy kernel fixes: `passport > iban >
    /// card > national_id > phone > email > url > ipv4`. A secret shares the top
    /// rank with a passport, so an API key is never relabelled an IBAN, a card
    /// or a phone (K10). A passport-shaped
    /// value must keep its specific label when it overlaps an IBAN candidate
    /// (P3, kind labels). Company identifiers (SIREN/SIRET/VAT) sit with the
    /// national identifiers, below phone, so a company number always wins over
    /// a phone-shaped sub-run.
    ///
    /// Passport hits are relabelled `NATIONAL_ID` by the registry (unverified
    /// rule), so [`crate::recognizer::resolve_overlaps`] also consults the
    /// span's originating recogniser to apply the `passport > iban` rule; see
    /// `wins_over`.
    pub fn mask_priority(self) -> u8 {
        match self {
            EntityKind::PassportMrz | EntityKind::Secret => 0,
            EntityKind::Iban => 1,
            EntityKind::CreditCard => 2,
            EntityKind::FrNir
            | EntityKind::ZaId
            | EntityKind::UkNino
            | EntityKind::HuTaj
            | EntityKind::HuTaxId
            | EntityKind::NationalId => 3,
            EntityKind::FrSiren | EntityKind::FrSiret | EntityKind::FrVat => 4,
            EntityKind::Phone => 5,
            EntityKind::Email => 6,
            EntityKind::Url => 7,
            EntityKind::IpV4 => 8,
            // Model-emitted textual kinds (slice 1d) sit below every
            // deterministic rule: when a GLiNER span overlaps a checksum-valid
            // identifier the deterministic label and its end offset win, so a
            // model over-reach can never shrink a deterministic mask.
            //
            // A special-category term outranks a name: a name region that
            // swallows `type 2 diabetes` must keep the `HEALTH` label, the one
            // open mode removes.
            EntityKind::Health
            | EntityKind::Religion
            | EntityKind::SexualOrientation
            | EntityKind::Union
            | EntityKind::Ethnicity => 9,
            EntityKind::Person
            | EntityKind::Organization
            | EntityKind::Address
            | EntityKind::DateOfBirth => 10,
        }
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A detected value: byte offsets into the original UTF-8 text, a score in
/// `0.0..=1.0`, and the name of the recogniser that produced it.
///
/// The span never stores the matched text, so `Debug` cannot leak a value.
#[derive(Clone, Copy, PartialEq)]
pub struct Span {
    /// The kind of value found.
    pub kind: EntityKind,
    /// Byte offset of the first byte of the value.
    pub start: usize,
    /// Byte offset one past the last byte of the value.
    pub end: usize,
    /// Confidence in `0.0..=1.0`.
    pub score: f32,
    /// The recogniser that produced the span.
    pub recognizer: &'static str,
    /// The known person this span names, when a contact index produced it
    /// (slice 1f). Every variant of one person carries the same id, so an
    /// anonymizer can give them one token. `None` for every other span, and for
    /// a merged region whose members name different people.
    pub person_id: Option<crate::contacts::PersonId>,
}

impl Span {
    /// Build a span.
    pub fn new(
        kind: EntityKind,
        start: usize,
        end: usize,
        score: f32,
        recognizer: &'static str,
    ) -> Self {
        Self {
            kind,
            start,
            end,
            score,
            recognizer,
            person_id: None,
        }
    }

    /// The same span, naming the known person `person`.
    pub fn with_person(mut self, person: crate::contacts::PersonId) -> Self {
        self.person_id = Some(person);
        self
    }

    /// The span length in bytes.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no bytes.
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Whether this span never leaves the Mac in any mode: its kind is
    /// prohibited, or it is a date of birth the birth-label rule read
    /// (OCR-KERNEL-3b). The e-mail layer's cue-gated and a model's dates of
    /// birth stay ordinary, so Open leaves them in clear as before.
    pub fn is_prohibited(&self) -> bool {
        self.kind.is_prohibited()
            || self.kind == EntityKind::DateOfBirth
                && self.recognizer == crate::recognizers::dob_label::NAME
    }

    /// Whether two spans share at least one byte.
    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Span")
            .field("kind", &self.kind)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("score", &self.score)
            .field("recognizer", &self.recognizer)
            .field("person_id", &self.person_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_labels_round_trip() {
        for kind in EntityKind::ALL {
            assert_eq!(EntityKind::parse(kind.as_str()), Some(kind));
            assert_eq!(EntityKind::parse(&kind.as_str().to_lowercase()), Some(kind));
        }
        assert_eq!(EntityKind::parse("EMAIL_ADDRESS"), Some(EntityKind::Email));
        assert_eq!(EntityKind::parse("nope"), None);
    }

    #[test]
    fn span_debug_hides_no_value_because_it_holds_none() {
        let span = Span::new(EntityKind::Iban, 3, 30, 1.0, "iban");
        let rendered = format!("{span:?}");
        assert!(rendered.contains("Iban"));
        assert!(rendered.contains("start: 3"));
        assert!(!rendered.contains("FR76"));
    }

    #[test]
    fn a_special_category_term_outranks_a_name_it_overlaps() {
        let spans = vec![
            Span::new(EntityKind::Person, 0, 26, 1.0, "test"),
            Span::new(EntityKind::Health, 18, 26, 1.0, "test"),
        ];
        let regions = crate::recognizer::resolve_overlaps(spans);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].kind, EntityKind::Health);
    }

    #[test]
    fn overlap_and_length() {
        let a = Span::new(EntityKind::Email, 0, 10, 1.0, "email");
        let b = Span::new(EntityKind::Email, 5, 12, 1.0, "email");
        let c = Span::new(EntityKind::Email, 10, 20, 1.0, "email");
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
        assert_eq!(a.len(), 10);
        assert!(!a.is_empty());
    }
}
