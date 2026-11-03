//! Deterministic PII detection and anonymisation for the Auxesis privacy
//! kernel (slice 1b).
//!
//! The crate ports the deterministic half of Microsoft Presidio's
//! architecture to Rust:
//!
//! * a [`Recognizer`] trait and a [`Registry`] that runs every enabled
//!   recogniser, validates byte offsets, applies the [`ContextEnhancer`] and
//!   per-kind [`Thresholds`], and merges overlapping or adjacent spans into a
//!   single masked union (highest-priority kind wins);
//! * the priority-1 recognisers (e-mail, phone, IBAN, payment card, IPv4,
//!   URL) plus the FR/HU/ZA/MRZ pack whose rules the source docs test;
//! * an [`Anonymizer`] that replaces spans with stable, delimited
//!   `⟦KIND_<fingerprint>⟧` placeholders keyed by a per-session HMAC-SHA-256 of
//!   the kind and normalised value; the delimiters let [`Anonymizer::restore`]
//!   tell a placeholder from token-like clear text, and an unknown or
//!   cross-session token is reported instead of restored.
//!
//! The [`safetext`] module is the provider boundary: [`safetext::SafeText`] has
//! private fields and is issued only by [`safetext::Gate`], which runs the
//! registry plus the anonymizer and fails closed on detection errors.
//!
//! It never runs a model, opens a socket, touches the Keychain or logs a
//! value. The unverified rules (FR NIR, FR SIRET, passport MRZ) are mounted
//! too: since this crate is a masker, an unverified checksum-valid value is
//! still masked, labelled `NATIONAL_ID` at a lower score.

#![forbid(unsafe_code)]

// `test-util` widens this crate's constructors for dependents' tests (for
// example `Gate::for_tests`). A release build that turns it on would ship a
// test seam, so it is a hard error there: only a debug (test) profile may
// enable it, and only through a `[dev-dependencies]` edge.
#[cfg(all(feature = "test-util", not(debug_assertions)))]
compile_error!("test-util is dev-only");

pub mod anonymize;
pub mod checksum;
pub mod company_id;
pub mod contacts;
pub mod context;
pub mod decode;
pub mod email_layer;
pub mod eval;
pub mod known_names;
pub mod link_guard;
pub mod name_lexicon;
#[cfg(feature = "ner-gliner")]
pub mod ner;
pub mod normalize;
pub mod public_terms;
pub mod recognizer;
pub mod recognizers;
pub mod safetext;
pub mod span;
pub mod threshold;
pub mod vault;

pub use anonymize::{
    restore, Anonymizer, RestoreReport, TokenMap, UnknownPolicy, PLACEHOLDER_CLOSE,
    PLACEHOLDER_OPEN, UNKNOWN_REFERENCE,
};
pub use company_id::CompanyIdRecognizer;
pub use contacts::{
    ContactIndex, ContactRecognizer, ContactStore, MemoryContactStore, Person, PersonDraft,
    PersonId, SeedLimits,
};
pub use context::ContextEnhancer;
pub use decode::DecodedText;
pub use email_layer::{EmailLayer, MASK_FIRST_NAMES_CONFIG_KEY};
pub use known_names::NameDictionary;
pub use link_guard::LinkGuard;
#[cfg(feature = "ner-gliner")]
pub use ner::{load_vetted_local_model, GlinerConfig, GlinerError, GlinerRecognizer, GlinerReport};
pub use normalize::NormalizedText;
pub use public_terms::PublicTerms;
pub use recognizer::{Recognizer, Registry, RegistryBuilder};
pub use safetext::{
    DetectionReport, Gate, GateError, NameCoverage, SafeText, SafeValue, StandardDetector,
};
pub use span::{EntityKind, Span};
pub use threshold::Thresholds;
pub use vault::{Vault, VaultError};
