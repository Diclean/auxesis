//! The `SafeText` boundary.
//!
//! [`SafeText`] is the only text a chat provider may receive. Its fields are
//! private and it has no public constructor, no `From<String>` and no
//! `Deserialize`, so it can be issued only by a [`Gate`], and a gate exists
//! only for a [`Grant`](kernel_core::privacy::Grant) minted by
//! `kernel_core::privacy::admit`. The gate runs the deterministic recognisers
//! (with the e-mail layer) and follows the grant's policy:
//!
//! * `GrantPolicy::Tokenised` (private mode): every detected value is replaced
//!   with a keyed `⟦KIND_…⟧` token, and the masked output is checked again. It
//!   fails closed: when detection errors, or the masked output still holds a
//!   detectable value, nothing is issued and the caller keeps the text local.
//! * `GrantPolicy::Passthrough` (open mode): the detectors still run, ordinary
//!   values are left in clear, and the [`DetectionReport`] returned next to the
//!   text names the kinds and counts private mode would have masked. The
//!   prohibited classes are the exception: a detected IBAN, payment card,
//!   national ID or passport, health term or secret is replaced with a fixed
//!   `[<class> removed]` marker (`[secret removed]` for a secret) rather than
//!   returned, because those classes never leave in any mode. No value is ever
//!   in the report.
//!
//! A production private gate hides no person's or company's name (owner,
//! 2026-10-19): it drops every `PERSON` and `ORGANIZATION` span and runs no name
//! model. The name sources (the known-names dictionary
//! [`crate::known_names::NameDictionary`], the e-mail layer's cues, GLiNER under
//! feature `ner-gliner`) still serve open mode's report and the eval.
//!
//! ```
//! use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
//! use kernel_privacy::safetext::Gate;
//!
//! let ctx = Context { destination: Destination::LocalDisplay };
//! let Decision::Allow(grant) = admit(PathId::C9, PrivacyMode::Open, &ctx) else {
//!     unreachable!("C9 is covered and allowed in open mode");
//! };
//! let mut gate = Gate::for_grant(&grant, [7u8; 32]);
//! let (safe, report) = gate.text("Bonjour, quelle heure est-il ?").unwrap();
//! assert_eq!(safe.as_str(), "Bonjour, quelle heure est-il ?");
//! assert_eq!(report.label(), "would have masked");
//! ```
//!
//! A raw string cannot become a [`SafeText`] outside this crate:
//!
//! ```compile_fail
//! let _ = kernel_privacy::safetext::SafeText::from(String::from("Élise Vautrin"));
//! ```
//!
//! ```compile_fail
//! let _ = kernel_privacy::safetext::SafeText("Élise Vautrin".to_string());
//! ```
//!
//! The round-1 literal path is gone as well. There is no hidden constructor
//! that takes a string — `&'static str` is exactly what `Box::leak`,
//! `OnceLock` and `LazyLock` produce — and no macro that reaches one:
//!
//! ```compile_fail,E0599
//! let _ = kernel_privacy::safetext::SafeText::__from_literal("[auxesis]");
//! ```
//!
//! ```compile_fail
//! let _ = kernel_privacy::safe_text_literal!("[auxesis]");
//! ```
//!
//! The only grantless path left is the crate-private `KernelMarker` enum: a
//! closed set of fixed strings written in this file, which no crate outside
//! `kernel-privacy` can name.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};

use kernel_core::privacy::{Grant, GrantPolicy};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::anonymize::{Anonymizer, PLACEHOLDER_CLOSE, PLACEHOLDER_OPEN};
#[cfg(feature = "ner-gliner")]
use crate::email_layer::EmailLayer;
use crate::known_names::{NameDictionary, NameDictionaryError};
#[cfg(feature = "ner-gliner")]
use crate::ner::GlinerRecognizer;
#[cfg(feature = "ner-gliner")]
use crate::recognizer::extend_hyphenated_persons;
#[cfg(feature = "ner-gliner")]
use crate::recognizer::split_long_spans;
use crate::recognizer::{
    resolve_overlaps, span_is_well_formed, Registry, RegistryBuilder, MARKER_RUN, NAME_WIDENED,
};
use crate::recognizers::dob_label::trim_invisible;
use crate::span::{EntityKind, Span};

/// The fixed text a passthrough gate writes in place of a detected secret. Open
/// mode leaves ordinary kinds in clear and only reports; a prohibited class is
/// never returned, only counted.
const SECRET_REMOVED: &str = "[secret removed]";

/// The fixed text a passthrough gate writes in place of a detected value of a
/// class that never leaves the Mac in any mode (IBAN, payment card, national
/// ID or passport, health, secret, postal address), or `None` for an ordinary
/// kind that open mode leaves in clear.
fn removal_text(kind: EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::Secret => Some(SECRET_REMOVED),
        EntityKind::Iban => Some("[iban removed]"),
        EntityKind::CreditCard => Some("[card removed]"),
        EntityKind::Health => Some("[health removed]"),
        EntityKind::Address => Some("[address removed]"),
        EntityKind::DateOfBirth => Some("[date of birth removed]"),
        EntityKind::FrNir
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino
        | EntityKind::PassportMrz
        | EntityKind::NationalId => Some("[id removed]"),
        _ => None,
    }
}

/// Whether the gate's detection covered person and organisation names.
///
/// The deterministic recognisers find a name only through the e-mail layer's
/// cues (a greeting, a sign-off, a header). A full name in running prose needs
/// a name detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCoverage {
    /// A name detector ran on the text.
    Checked,
    /// No name detector was mounted: names may be unmasked in this text.
    NotChecked,
    /// Written by the application itself, never by a user, a tool result or a
    /// memory row: no detector runs on it, and none is needed.
    AppAuthored,
}

impl NameCoverage {
    /// The coverage of text built from `parts`: any unchecked part leaves the
    /// whole unchecked, and application text alone is app-authored.
    fn of_parts(parts: impl IntoIterator<Item = NameCoverage>) -> Self {
        parts
            .into_iter()
            .fold(Self::AppAuthored, |acc, part| match (acc, part) {
                (Self::NotChecked, _) | (_, Self::NotChecked) => Self::NotChecked,
                (Self::Checked, _) | (_, Self::Checked) => Self::Checked,
                _ => Self::AppAuthored,
            })
    }
}

/// Text that may leave the device: every detected value has been replaced by
/// a token. Issued by [`Gate::text`], the only public constructor.
///
/// There is no public grantless mint. The old `trusted_static` accepted
/// `Box::leak`, `OnceLock` and `LazyLock` runtime data; the round-1
/// `safe_text_literal!`/`__from_literal` pair reopened the same hole, because
/// a `&'static str` is what `Box::leak` returns. Both are gone:
///
/// ```compile_fail,E0599
/// let leaked: &'static str = Box::leak(String::from("Élise Vautrin").into_boxed_str());
/// let _ = kernel_privacy::safetext::SafeText::trusted_static(leaked);
/// ```
///
/// ```compile_fail,E0599
/// let _ = kernel_privacy::safetext::SafeText::__from_literal("[auxesis]");
/// ```
///
/// Fixed kernel-authored markers do not need a grant: they go through the
/// crate-private `KernelMarker` enum, whose variants are constants written in
/// this file and which nothing outside `kernel-privacy` can name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SafeText {
    text: String,
    #[serde(skip)]
    names: NameCoverage,
}

/// A fixed, kernel-authored string that may be issued as a [`SafeText`]
/// without a grant.
///
/// The enum is `pub(crate)` and every variant maps to a constant written in
/// this file ([`Self::as_str`]), so nothing outside `kernel-privacy` can name
/// a variant and no variant carries caller data. This is the **only** grantless
/// path left: a refusal placeholder, or another fixed marker kernel code shows
/// in place of a value it refused to send. Dynamic text always goes through
/// [`Gate::text`], which needs a [`Grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum KernelMarker {
    /// Shown in place of a value the gate refused to issue.
    RefusalPlaceholder,
}

#[cfg(test)]
impl KernelMarker {
    /// The fixed text of this marker, written here and nowhere else.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RefusalPlaceholder => "[auxesis: withheld]",
        }
    }
}

impl SafeText {
    /// Mint the fixed text of a `KernelMarker`.
    ///
    /// `pub(crate)`: reachable only from `kernel-privacy` source, and only with
    /// a `KernelMarker` value, whose every variant is a constant written in
    /// this file. No variant takes a caller string, so this cannot mint runtime
    /// data — `Box::leak` has nothing to leak into. A `&Grant` is deliberately
    /// not required, because no caller-supplied byte reaches the text.
    #[cfg(test)]
    pub(crate) fn from_marker(marker: KernelMarker) -> Self {
        Self {
            text: marker.as_str().to_string(),
            names: NameCoverage::AppAuthored,
        }
    }

    /// The parts, in order, as one text. Each part was checked on its own when
    /// it was issued; the join does not scan across the seams, so a caller
    /// joins only whole, self-contained parts.
    pub fn join(parts: impl IntoIterator<Item = SafeText>) -> Self {
        let mut text = String::new();
        let mut names = Vec::new();
        for part in parts {
            text.push_str(&part.text);
            names.push(part.names);
        }
        Self {
            text,
            names: NameCoverage::of_parts(names),
        }
    }

    /// The masked text, read-only.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether no name in this text can be unmasked: a name detector checked
    /// it, or the application wrote it. `false` means person and organisation
    /// names may still be in it, unmasked.
    pub fn names_checked(&self) -> bool {
        self.names != NameCoverage::NotChecked
    }
}

/// A JSON value (tool schema, tool-call arguments) whose every string, key
/// and value, has been masked. Issued by [`Gate::value`].
///
/// There is deliberately no literal path: no caller in the tree declares a
/// static JSON value, so [`Gate::value`] is the only constructor. The removed
/// `trusted_static` accepted a leaked `&'static Value`; the seal's probe no
/// longer compiles:
///
/// ```compile_fail
/// let leaked: &'static serde_json::Value =
///     Box::leak(Box::new(serde_json::json!({ "to": "Élise Vautrin" })));
/// let _ = kernel_privacy::safetext::SafeValue::trusted_static(leaked);
/// ```
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SafeValue {
    value: Value,
    #[serde(skip)]
    names: NameCoverage,
}

impl SafeValue {
    /// The masked value, read-only.
    pub fn as_value(&self) -> &Value {
        &self.value
    }

    /// Whether every string of this value is covered: checked by a name
    /// detector, or written by the application.
    pub fn names_checked(&self) -> bool {
        self.names != NameCoverage::NotChecked
    }
}

type Detection = (Vec<Span>, bool);
type DetectionPair = (Detection, Detection);

/// The local detection step, injected so the fail-closed path can be tested.
/// The default is the deterministic [`Registry`].
pub trait Detector: Send + Sync {
    /// Find every detectable value in `text`, or fail.
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError>;

    /// Whether this detector finds person and organisation names. The default
    /// is no: the deterministic registry finds a name only through the e-mail
    /// layer's cues.
    fn checks_names(&self) -> bool {
        false
    }

    /// [`Detector::detect`] plus whether names were covered on this very text.
    /// The default is the detector's standing claim; a two-pass detector whose
    /// second pass failed on this text says `false`.
    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        Ok((self.detect(text)?, self.checks_names()))
    }

    /// Detect both token views. Composite detectors with expensive shared passes
    /// can override this to reuse one result across the pair.
    fn detect_pair_covered(&self, first: &str, second: &str) -> Result<DetectionPair, DetectError> {
        Ok((self.detect_covered(first)?, self.detect_covered(second)?))
    }

    /// Pattern values only, for a caller that does not need names (the JSON
    /// key-context probe). The default is [`Detector::detect`].
    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.detect(text)
    }

    /// The values still detectable in the clear text of a masked string: the
    /// residue scan. It reads context-free values only by default; a detector
    /// whose name cues depend on context must not refuse text on them, since
    /// masking changes that context.
    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.detect(text)
    }
}

impl Detector for Registry {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        // A panic inside a recogniser is a detection error, never a clean pass.
        panic::catch_unwind(AssertUnwindSafe(|| self.analyze(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.analyze_values(text)))
            .map_err(|_| DetectError::Panicked)
    }
}

/// The deterministic half shared by the Standard and Deep stacks: every
/// recogniser plus the caller's known-names dictionary, with the e-mail layer
/// left to the caller. Standard mounts the layer directly; Deep applies it once
/// with its model's `PERSON` spans as extra seeds. Both use this builder, so
/// Deep never detects less than Standard.
fn standard_builder<I, S>(names: I) -> Result<(RegistryBuilder, bool), NameDictionaryError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Ok(dictionary_builder(Arc::new(NameDictionary::new(names)?)))
}

/// [`standard_builder`] over a dictionary that is already compiled.
fn dictionary_builder(dictionary: Arc<NameDictionary>) -> (RegistryBuilder, bool) {
    let mounted = !dictionary.is_empty();
    let mut builder = Registry::builder().with_all();
    if mounted {
        builder = builder.with_recognizer(dictionary);
    }
    (builder, mounted)
}

/// The Standard detection set (D7): the deterministic recognisers with the
/// e-mail-aware layer, plus the caller's known-names dictionary when one is
/// supplied.
///
/// The dictionary is the only Tier H source in this build, so the detector
/// claims name coverage exactly when one is mounted. Without it a private gate
/// masks the pattern values and issues names-not-checked; Deep detection (feature
/// `ner-gliner`) adds its model on top.
pub struct StandardDetector {
    registry: Registry,
    /// Whether a name source is mounted.
    names: bool,
}

impl StandardDetector {
    /// Standard with no known-names dictionary: the deterministic recognisers
    /// and the e-mail layer, but no Tier H coverage.
    pub fn new() -> Self {
        Self {
            registry: Registry::builder().with_all().build(),
            names: false,
        }
    }

    /// Standard plus the caller's known names (Tier H). The dictionary is the
    /// only name source in this build, so its absence is what
    /// [`Detector::checks_names`] reports.
    pub fn with_names<I, S>(names: I) -> Result<Self, NameDictionaryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let (builder, names) = standard_builder(names)?;
        Ok(Self {
            registry: builder.build(),
            names,
        })
    }

    /// Standard plus a dictionary compiled once by the caller, shared rather
    /// than recompiled: the same matcher serves every detector built from it.
    pub fn with_dictionary(dictionary: Arc<NameDictionary>) -> Self {
        let (builder, names) = dictionary_builder(dictionary);
        Self {
            registry: builder.build(),
            names,
        }
    }
}

impl StandardDetector {
    /// This detector with no person or organisation span, dropped before the
    /// registry's overlap merge (see [`Registry::without_names`]).
    fn without_names(self) -> Self {
        Self {
            registry: self.registry.without_names(),
            names: self.names,
        }
    }
}

impl Default for StandardDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for StandardDetector {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.registry.analyze_tagged(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.registry.analyze(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.registry.analyze_values(text)))
            .map_err(|_| DetectError::Panicked)
    }

    fn checks_names(&self) -> bool {
        self.names
    }
}

/// The assistant's own names, never a person: the product and its chief.
pub const ASSISTANT_NAMES: &[&str] = &["Aux", "Auxesis"];

/// A detector that drops the person spans naming the assistant itself. The
/// owner's own contacts always win: a span the known-names dictionary produced
/// stays masked, whatever the terms say.
struct NonPersonTerms {
    inner: Arc<dyn Detector>,
    /// Folded terms.
    terms: BTreeSet<String>,
}

impl NonPersonTerms {
    fn filter(&self, text: &str, mut spans: Vec<Span>) -> Vec<Span> {
        spans.retain(|span| {
            span.kind != EntityKind::Person
                || span.recognizer == crate::known_names::KNOWN_NAMES
                || !text
                    .get(span.start..span.end)
                    .is_some_and(|value| self.terms.contains(&crate::public_terms::fold(value)))
        });
        spans
    }
}

impl Detector for NonPersonTerms {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self.filter(text, self.inner.detect(text)?))
    }

    fn checks_names(&self) -> bool {
        self.inner.checks_names()
    }

    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        let (spans, covered) = self.inner.detect_covered(text)?;
        Ok((self.filter(text, spans), covered))
    }

    fn detect_pair_covered(&self, first: &str, second: &str) -> Result<DetectionPair, DetectError> {
        let ((first_spans, first_covered), (second_spans, second_covered)) =
            self.inner.detect_pair_covered(first, second)?;
        Ok((
            (self.filter(first, first_spans), first_covered),
            (self.filter(second, second_spans), second_covered),
        ))
    }

    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self.filter(text, self.inner.detect_patterns(text)?))
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self.filter(text, self.inner.residue(text)?))
    }
}

/// Why detection could not produce a verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    /// A recogniser panicked.
    #[error("a recogniser failed")]
    Panicked,
    /// The name detector could not run (its model is missing or failed).
    #[error("the name detector failed")]
    Names,
    /// A secret-class block scalar is longer than the gate reads (8 KB). The gate
    /// refuses the text rather than mask part of the block; a longer value on its
    /// line is masked whole and never refused.
    #[error("a secret-class block is longer than the gate reads")]
    TooLong,
}

/// Why the gate refused to issue a [`SafeText`] or [`SafeValue`]. Messages
/// never contain the refused text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// Local detection failed; the text stays local.
    #[error("local detection failed: {0}")]
    Detect(#[from] DetectError),
    /// The masked output still holds a detectable value; the text stays local.
    #[error("masked text still holds a detectable value")]
    Residue,
    /// No pseudonym key could be made; nothing is issued.
    #[error("no key for the outbound pseudonyms")]
    Key,
    /// The known-names dictionary could not be compiled; nothing is issued.
    #[error("the known-names dictionary could not be compiled")]
    Dictionary(#[from] NameDictionaryError),
}

/// What one gate call detected: the kinds and counts, never a value.
///
/// In open mode the report is what private mode **would have masked**, so the
/// caller can log `"would have masked"` and offer the upgrade; in private mode
/// it is what was masked (`"masked"`). Only [`EntityKind`] labels and counts
/// are held, so a report can be logged, audited or serialized without ever
/// carrying a raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionReport {
    label: &'static str,
    counts: BTreeMap<EntityKind, usize>,
}

impl DetectionReport {
    /// The audit label for a tokenising gate: values were replaced.
    pub const MASKED: &'static str = "masked";
    /// The audit label for a passthrough gate: values were left in clear.
    pub const WOULD_HAVE_MASKED: &'static str = "would have masked";

    fn empty(policy: GrantPolicy) -> Self {
        Self {
            label: label_for(policy),
            counts: BTreeMap::new(),
        }
    }

    fn of(policy: GrantPolicy, spans: &[Span]) -> Self {
        let mut report = Self::empty(policy);
        for span in spans {
            *report.counts.entry(span.kind).or_insert(0) += 1;
        }
        report
    }

    fn merge(&mut self, other: Self) {
        for (kind, count) in other.counts {
            *self.counts.entry(kind).or_insert(0) += count;
        }
    }

    /// `"masked"` for a tokenising gate, `"would have masked"` for a
    /// passthrough one. This is the exact string the caller logs.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// True when nothing detectable was found.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Total number of detected spans.
    pub fn total(&self) -> usize {
        self.counts.values().sum()
    }

    /// How many spans of `kind` were detected.
    pub fn count(&self, kind: EntityKind) -> usize {
        self.counts.get(&kind).copied().unwrap_or(0)
    }

    /// The `(kind, count)` pairs, in the kind's stable order.
    pub fn counts(&self) -> impl Iterator<Item = (EntityKind, usize)> + '_ {
        self.counts.iter().map(|(kind, count)| (*kind, *count))
    }
}

impl fmt::Display for DetectionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label)?;
        if self.is_empty() {
            return write!(f, ": nothing detected");
        }
        write!(f, ":")?;
        for (kind, count) in self.counts() {
            write!(f, " {}={count}", kind.as_str())?;
        }
        Ok(())
    }
}

fn label_for(policy: GrantPolicy) -> &'static str {
    match policy {
        GrantPolicy::Passthrough => DetectionReport::WOULD_HAVE_MASKED,
        GrantPolicy::Tokenised => DetectionReport::MASKED,
    }
}

/// Whether `span` is an IBAN-shaped guess (not a checksum-valid IBAN of a known
/// country) inside a hex token of 32 or more characters, which is a digest. The
/// recogniser fails toward masking, so private mode tokenises such a guess and
/// restores it locally; open mode cannot restore, and would hand the model a
/// corrupted hash it must cite. A real IBAN starts with letters outside `a`-`f`
/// (or is checksum-valid), so it never qualifies.
fn is_hash_fragment(text: &str, span: &Span) -> bool {
    if span.kind != EntityKind::Iban || span.score >= crate::recognizers::iban::SCORE {
        return false;
    }
    // A low-confidence IBAN span can occur at every offset in an unbroken
    // alphanumeric run. Scanning the full run for each span made Open mode
    // quadratic on glued identifiers. Only exempt bounded digest-like runs;
    // when the boundary is beyond this window, fail closed and mask the span.
    const MAX_HASH_FRAGMENT_BYTES: usize = 256;
    let bytes = text.as_bytes();
    let alnum = |index: usize| bytes[index].is_ascii_alphanumeric();
    let mut start = span.start;
    let mut scanned = 0;
    while start > 0 && alnum(start - 1) && scanned < MAX_HASH_FRAGMENT_BYTES {
        start -= 1;
        scanned += 1;
    }
    if start > 0 && alnum(start - 1) {
        return false;
    }
    let mut end = span.end;
    scanned = 0;
    while end < bytes.len() && alnum(end) && scanned < MAX_HASH_FRAGMENT_BYTES {
        end += 1;
        scanned += 1;
    }
    if end < bytes.len() && alnum(end) {
        return false;
    }
    end - start >= 32 && bytes[start..end].iter().all(u8::is_ascii_hexdigit)
}

/// Keep each full overlap union and its best prohibited label, so masking or
/// removal cannot leave the tail of a prohibited-containing region clear.
/// The ranges the gate hides as secrets on top of its detector's spans, in
/// both modes: the export columns of a table (SECRET-LEAK-294B). Public for the
/// tests' exact reader of an Open output.
#[doc(hidden)]
pub fn export_column_ranges(text: &str) -> Vec<(usize, usize)> {
    crate::recognizers::export_scan(text)
}

/// [`export_column_ranges`] as secret spans.
fn export_spans(text: &str) -> Vec<Span> {
    export_column_ranges(text)
        .into_iter()
        .map(|(start, end)| Span::new(EntityKind::Secret, start, end, 1.0, "secret-export"))
        .collect()
}

/// Remove and return the [`NAME_WIDENED`] regions of `spans`: the gate masks
/// them once its main rounds have settled, as `extra`, so they never change
/// what those rounds hide (SECRET-LEAK-294B, GATE-REGISTRY-GAP-1).
fn take_widened(spans: &mut Vec<Span>) -> Vec<Span> {
    let (widened, rest) = std::mem::take(spans)
        .into_iter()
        .partition(|span| span.recognizer == NAME_WIDENED);
    *spans = rest;
    widened
}

/// The report of `spans`, plus each `extra` region no span of `spans` holds.
fn report_of(policy: GrantPolicy, spans: &[Span], extra: &[Span]) -> DetectionReport {
    if extra.is_empty() {
        return DetectionReport::of(policy, spans);
    }
    let all: Vec<Span> = spans.iter().chain(extra).copied().collect();
    DetectionReport::of(policy, &consolidate_mask_spans(all))
}

fn consolidate_mask_spans(spans: Vec<Span>) -> Vec<Span> {
    let mut resolved = resolve_overlaps(spans.clone());
    crate::recognizer::label_prohibited(&mut resolved, &spans);
    resolved
}

/// Replace every well-formed prohibited-class span of `text` (see
/// [`removal_text`]) with its fixed marker, for the passthrough policy.
///
/// Overlapping and adjacent prohibited spans merge into one maximal range and
/// are replaced once, so no byte of a prohibited value survives and no range is
/// written twice; a merged range takes the marker of its highest-priority kind
/// (a secret over an ID over a health term). Every other span, and every byte
/// no prohibited span covers, is returned exactly as it was.
fn remove_prohibited(text: &str, spans: &[Span]) -> String {
    let mut ranges: Vec<(usize, usize, EntityKind)> = spans
        .iter()
        .filter(|span| {
            span.is_prohibited() && span_is_well_formed(text, span) && !is_hash_fragment(text, span)
        })
        .map(|span| match span.kind {
            // Not the invisible characters the fold read in front of the date.
            EntityKind::DateOfBirth => {
                let (start, end) = trim_invisible(text, span.start, span.end);
                (start, end, span.kind)
            }
            _ => (span.start, span.end, span.kind),
        })
        .filter(|&(start, end, _)| start < end)
        .collect();
    if ranges.is_empty() {
        return text.to_string();
    }
    ranges.sort_by_key(|&(start, end, kind)| (start, end, kind.mask_priority()));
    let mut merged: Vec<(usize, usize, EntityKind)> = Vec::with_capacity(ranges.len());
    for (start, end, kind) in ranges {
        match merged.last_mut() {
            Some((_, last_end, last_kind)) if start <= *last_end => {
                *last_end = (*last_end).max(end);
                if kind.mask_priority() < last_kind.mask_priority() {
                    *last_kind = kind;
                }
            }
            _ => merged.push((start, end, kind)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for (start, end, kind) in merged {
        out.push_str(&text[cursor..start]);
        out.push_str(removal_text(kind).unwrap_or(SECRET_REMOVED));
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// The gate that issues [`SafeText`] and [`SafeValue`] for one [`Grant`].
///
/// A gate is built **from a grant**, so its policy (mask or pass through) is
/// the one `admit` decided, never a second switch a caller could flip. One
/// gate serves one session: its anonymizer keeps the session's value→token
/// table, so the same value gets the same token for as long as the key lasts.
///
/// There is no keyless or grantless constructor:
///
/// ```compile_fail,E0599
/// let _ = kernel_privacy::safetext::Gate::new([0u8; 32]);
/// ```
///
/// and the grant cannot be faked with a key or a mode:
///
/// ```compile_fail,E0308
/// let _ = kernel_privacy::safetext::Gate::for_grant(&[0u8; 32], [0u8; 32]);
/// ```
#[cfg_attr(
    not(feature = "test-util"),
    doc = "Without `test-util` no caller can inject a detector that approves everything:\n\n\
    ```compile_fail\n\
    struct Allow;\n\
    impl kernel_privacy::safetext::Detector for Allow {\n\
    fn detect(&self, _text: &str) -> Result<Vec<kernel_privacy::Span>, kernel_privacy::safetext::DetectError> {\n\
    Ok(Vec::new())\n\
    }\n\
    }\n\
    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};\n\
    let ctx = Context { destination: Destination::LocalDisplay };\n\
    let Decision::Allow(grant) = admit(PathId::C9, PrivacyMode::Open, &ctx) else { unreachable!() };\n\
    let _ = kernel_privacy::safetext::Gate::for_tests(&grant, [0u8; 32], std::sync::Arc::new(Allow));\n\
    ```"
)]
pub struct Gate {
    detector: Arc<dyn Detector>,
    policy: GrantPolicy,
    /// The keyed pseudonyms. Present only when the policy masks; a passthrough
    /// gate needs no key and mints no token.
    anonymizer: Option<Anonymizer>,
    /// `(token, value)` pairs minted since the last [`Gate::take_minted`].
    /// They leave the gate only through that method, for the local display
    /// side; `Debug` never prints them.
    minted: Vec<(String, String)>,
    /// Whether names were covered on every string of the call in progress;
    /// `None` until a string is read (then the detector's standing claim holds).
    names_run: Option<bool>,
    /// Set by [`Gate::for_session_tokens`]: the tokens (`KIND_<hex>`, no
    /// delimiters) this session minted. The input already carries some of
    /// them; those pass through whole. Any other token-shaped text is ordinary
    /// text.
    session_tokens: Option<Arc<BTreeSet<String>>>,
}

/// A person's `span` without a trailing `'s`: a token is keyed by its surface, so
/// `Mira Fictive's` would be a second person (TOK-CONSISTENT-1).
fn without_possessive(text: &str, span: Span) -> Span {
    if span.kind != EntityKind::Person {
        return span;
    }
    let name = text
        .get(span.start..span.end)
        .unwrap_or_default()
        .strip_suffix(['s', 'S'])
        .and_then(|head| head.strip_suffix(['\'', '’', 'ʼ']));
    match name {
        Some(name) if name.ends_with(char::is_alphabetic) => Span {
            end: span.start + name.len(),
            ..span
        },
        _ => span,
    }
}

static DEFAULT_DETECTOR: OnceLock<Arc<StandardDetector>> = OnceLock::new();
static PRIVATE_DETECTOR: OnceLock<Arc<dyn Detector>> = OnceLock::new();

impl Gate {
    /// The one production constructor: the grant fixes the policy and `key`
    /// seeds the per-session pseudonyms.
    ///
    /// `GrantPolicy::Passthrough` runs the detectors and leaves ordinary values
    /// in clear (a prohibited class is replaced with its marker, never returned);
    /// `GrantPolicy::Tokenised` replaces every detected value with a keyed
    /// token.
    pub fn for_grant(grant: &Grant, key: [u8; 32]) -> Self {
        let detector = match grant.policy() {
            GrantPolicy::Tokenised => PRIVATE_DETECTOR
                .get_or_init(|| without_names(StandardDetector::new()))
                .clone(),
            GrantPolicy::Passthrough => default_detector(),
        };
        Self::with_detector_for_grant(grant, key, detector)
    }

    /// [`Gate::for_grant`] with the caller's known names (the contacts index)
    /// added to the Standard detector set. A name matches exactly: case- and
    /// accent-insensitive, whole-word, multi-token.
    pub fn for_grant_with_names<I, S>(
        grant: &Grant,
        key: [u8; 32],
        names: I,
    ) -> Result<Self, GateError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let detector = StandardDetector::with_names(names)?;
        let detector = egress_detector(grant, detector);
        Ok(Self::with_detector_for_grant(grant, key, detector))
    }

    /// [`Gate::for_grant_with_names`] over a dictionary the caller compiled
    /// once with [`NameDictionary::new`]. A service that gates many messages
    /// builds the dictionary at start-up and passes a clone of the `Arc` per
    /// gate; no gate recompiles the names.
    pub fn for_grant_with_dictionary(
        grant: &Grant,
        key: [u8; 32],
        dictionary: Arc<NameDictionary>,
    ) -> Self {
        let detector = egress_detector(grant, StandardDetector::with_dictionary(dictionary));
        Self::with_detector_for_grant(grant, key, detector).with_non_person_terms(ASSISTANT_NAMES)
    }

    /// Never tokenise `terms` (the assistant's own names, the configured agent
    /// ids) as a person. A name from the known-names dictionary still masks.
    #[must_use]
    pub fn with_non_person_terms<I, S>(mut self, terms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut folded = BTreeSet::new();
        for term in terms {
            let term = crate::public_terms::fold(term.as_ref());
            if !term.is_empty() {
                folded.insert(term);
            }
        }
        if !folded.is_empty() {
            self.detector = Arc::new(NonPersonTerms {
                inner: self.detector,
                terms: folded,
            });
        }
        self
    }

    /// Add Deep model spans of prohibited Tier C kinds to the Standard gate.
    /// Model names and locations are deliberately ignored. A failed or slow
    /// model pass returns the Standard result unchanged.
    #[cfg(feature = "ner-gliner")]
    pub fn for_grant_with_deep_detector(
        grant: &Grant,
        key: [u8; 32],
        dictionary: Arc<NameDictionary>,
        deep: Arc<dyn Detector>,
    ) -> Self {
        let standard = egress_detector(grant, StandardDetector::with_dictionary(dictionary));
        Self::with_detector_for_grant(grant, key, Arc::new(DeepAdder::new(standard, deep)))
            .with_non_person_terms(ASSISTANT_NAMES)
    }

    /// A gate for a grant that never masks, without a session key.
    ///
    /// This is the constructor for a local destination (an MCP stdio child, a
    /// local display): the detectors run and the report is kept, but no token
    /// is minted, so no key is needed. A tokenising grant is refused
    /// ([`GateError::Key`]): masking without the session key would mint
    /// pseudonyms nobody can resolve.
    pub fn for_passthrough(grant: &Grant) -> Result<Self, GateError> {
        if grant.policy() != GrantPolicy::Passthrough {
            return Err(GateError::Key);
        }
        Ok(Self::with_detector_for_grant(
            grant,
            [0u8; 32],
            default_detector(),
        ))
    }

    fn with_detector_for_grant(grant: &Grant, key: [u8; 32], detector: Arc<dyn Detector>) -> Self {
        let policy = grant.policy();
        Self {
            detector,
            policy,
            anonymizer: match policy {
                GrantPolicy::Passthrough => None,
                GrantPolicy::Tokenised => Some(Anonymizer::new(key)),
            },
            minted: Vec::new(),
            names_run: None,
            session_tokens: None,
        }
    }

    /// A tokenising gate for a value the model wrote after reading only the
    /// session's tokens (an MCP call): each `⟦KIND_<hex>⟧` in `minted` (the
    /// tokens this session issued) already in it stays as it is, so the server
    /// receives the token and never the value. A token-shaped string the
    /// session never minted is ordinary text. Any value still in the clear is
    /// masked under a one-call key nobody can resolve. A passthrough grant is
    /// refused ([`GateError::Key`]).
    pub fn for_session_tokens(
        grant: &Grant,
        minted: Arc<BTreeSet<String>>,
    ) -> Result<Self, GateError> {
        if grant.policy() != GrantPolicy::Tokenised {
            return Err(GateError::Key);
        }
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|_| GateError::Key)?;
        let mut gate = Self::for_grant(grant, key);
        gate.session_tokens = Some(minted);
        Ok(gate)
    }

    /// A gate over an injected detector, for tests and `test-util` dependents:
    /// a production gate always runs the fixed registry.
    #[cfg(any(test, feature = "test-util"))]
    pub fn for_tests(grant: &Grant, key: [u8; 32], detector: Arc<dyn Detector>) -> Self {
        Self::with_detector_for_grant(grant, key, detector)
    }

    /// A gate whose names come from the local GLiNER model, unioned with the
    /// deterministic recognisers and the e-mail layer: the eval's best
    /// configuration.
    #[cfg(feature = "ner-gliner")]
    pub fn for_grant_with_gliner(grant: &Grant, key: [u8; 32], model: GlinerRecognizer) -> Self {
        Self::with_detector_for_grant(grant, key, Arc::new(NameStack::new(model)))
    }

    /// [`Gate::for_grant_with_gliner`] with the caller's known names unioned in,
    /// so Deep detection never detects less than Standard.
    #[cfg(feature = "ner-gliner")]
    pub fn for_grant_with_gliner_and_names<I, S>(
        grant: &Grant,
        key: [u8; 32],
        model: GlinerRecognizer,
        names: I,
    ) -> Result<Self, GateError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let stack = NameStack::with_names(model, names)?;
        Ok(Self::with_detector_for_grant(grant, key, Arc::new(stack)))
    }

    /// The policy this gate follows, from its grant.
    pub fn policy(&self) -> GrantPolicy {
        self.policy
    }

    /// Issue the text under the grant's policy, with the detection report.
    ///
    /// `Passthrough` returns the text with every detected prohibited-class value
    /// replaced by its `[<class> removed]` marker and the report of what private mode would have masked.
    /// `Tokenised` returns the masked text and refuses (`GateError`) when it
    /// cannot prove the output is clean.
    pub fn text(&mut self, text: &str) -> Result<(SafeText, DetectionReport), GateError> {
        self.names_run = None;
        let (masked, report) = self.mask(text)?;
        let names = self.coverage();
        Ok((
            SafeText {
                text: masked,
                names,
            },
            report,
        ))
    }

    /// Keep `minted` (the tokens this session issued, `KIND_<hex>`) whole in
    /// what the gate issues next, as [`Gate::for_session_tokens`] does, but under
    /// this gate's own key: for text the model wrote after reading only the
    /// session's tokens. Its references then stay references, not literal text,
    /// and a value it wrote in clear is still masked. `None` goes back to
    /// reading every token-shaped string as text. A passthrough gate ignores it.
    pub fn keep_session_tokens(&mut self, minted: Option<Arc<BTreeSet<String>>>) {
        if self.policy == GrantPolicy::Tokenised {
            self.session_tokens = minted;
        }
    }

    /// The `(token, value)` pairs this gate minted since the last call, in mint
    /// order, and forgets them. This is the only way a value leaves the gate.
    pub fn take_minted(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.minted)
    }

    /// Issue a JSON value with every string key and string value masked under
    /// the grant's policy. Numbers, booleans and nulls pass unchanged. A string
    /// value whose key gives it a secret's context (the detector reads the pair
    /// `"<key>: <value>"`) is treated as one secret: a single token, or
    /// [`SECRET_REMOVED`] in open mode.
    pub fn value(&mut self, value: &Value) -> Result<(SafeValue, DetectionReport), GateError> {
        self.names_run = None;
        let (masked, report) = self.map_value(value)?;
        let names = self.coverage();
        Ok((
            SafeValue {
                value: masked,
                names,
            },
            report,
        ))
    }

    /// Whether this gate's output has names checked. Without a name detector
    /// both policies issue and mark it: a tokenising gate has still masked
    /// every pattern value (mail, phone, IBAN, card, ID, health, secret).
    fn coverage(&self) -> NameCoverage {
        if self
            .names_run
            .unwrap_or_else(|| self.detector.checks_names())
        {
            return NameCoverage::Checked;
        }
        NameCoverage::NotChecked
    }

    /// Detection runs on the input. A passthrough gate returns the text
    /// unchanged; a tokenising gate masks each span, then scans the clear parts
    /// of the masked output once more: they must hold no detectable value.
    fn mask(&mut self, text: &str) -> Result<(String, DetectionReport), GateError> {
        match self.session_tokens.clone() {
            Some(minted) => self.mask_keeping(text, &minted),
            // A tokenising gate reads a foreign token's text both ways too, so
            // a value it splits is still masked (TOK-FP).
            None if self.policy == GrantPolicy::Tokenised => {
                self.mask_keeping(text, &BTreeSet::new())
            }
            None => self.mask_clear(text),
        }
    }

    /// [`Gate::mask`] for a gate that keeps the session's tokens. Detection
    /// reads the **whole** text, in two views of it: with each minted token
    /// replaced by blanks of the same length (a token separates the values
    /// around it; any other token-shaped string is plain text, read as it is);
    /// and with every token-shaped string (minted or not) deleted, so a value a
    /// token splits (`mara@⟦…⟧example.test`) is read the way a server that
    /// deletes the token reads it. Every span found in either view is masked; a span
    /// that touches a token masks it too. Only a minted token no span touches
    /// stays, whole, and the text between kept tokens is masked.
    fn mask_keeping(
        &mut self,
        text: &str,
        minted: &BTreeSet<String>,
    ) -> Result<(String, DetectionReport), GateError> {
        let tokens = token_ranges(text, minted);
        if tokens.is_empty() {
            return self.mask_clear(text);
        }
        let blanked = blank_minted(text, &tokens);
        let (stripped, segments) = strip_tokens(text, &tokens);
        for view in [blanked.as_ref(), stripped.as_str()] {
            if crate::recognizers::secrets::value_too_long(view) {
                return Err(GateError::Detect(DetectError::TooLong));
            }
        }
        let ((mut spans, blanked_covered), (stripped_spans, stripped_covered)) =
            self.detector.detect_pair_covered(&blanked, &stripped)?;
        self.names_run =
            Some(self.names_run.unwrap_or(true) && blanked_covered && stripped_covered);
        let mut extra = export_spans(&blanked);
        spans.extend(stripped_spans.into_iter().filter_map(|span| {
            let start = segments.original(span.start, false)?;
            let end = segments.original(span.end, true)?;
            Some(Span { start, end, ..span })
        }));
        extra.extend(take_widened(&mut spans));
        // A span that touches a token takes all of it. Tokens and (after the
        // merge) spans are sorted and disjoint: binary searches and one
        // cursor keep this linear-log in their number.
        for span in &mut spans {
            let mut at = tokens.partition_point(|t| t.end <= span.start);
            while at < tokens.len() && tokens[at].start < span.end {
                span.start = span.start.min(tokens[at].start);
                span.end = span.end.max(tokens[at].end);
                at += 1;
            }
        }
        for span in &mut extra {
            let mut at = tokens.partition_point(|t| t.end <= span.start);
            while at < tokens.len() && tokens[at].start < span.end {
                span.start = span.start.min(tokens[at].start);
                span.end = span.end.max(tokens[at].end);
                at += 1;
            }
        }
        let spans = consolidate_mask_spans(spans);
        let report = report_of(self.policy, &spans, &extra);
        let mut out = String::with_capacity(text.len());
        let mut from = 0;
        let kept = tokens.iter().filter(|t| {
            let at = spans.partition_point(|s| s.end <= t.start);
            spans.get(at).is_none_or(|s| t.end <= s.start)
        });
        let mut next = 0;
        for token in kept.chain(std::iter::once(&TokenRange {
            start: text.len(),
            end: text.len(),
        })) {
            let first = next;
            while next < spans.len() && spans[next].end <= token.start {
                next += 1;
            }
            let piece: Vec<Span> = spans[first..next]
                .iter()
                .filter(|s| from <= s.start)
                .map(|s| Span {
                    start: s.start - from,
                    end: s.end - from,
                    ..*s
                })
                .collect();
            // An export span keeps to the piece: the tokens kept are main's.
            let added: Vec<Span> = extra
                .iter()
                .filter(|s| s.start < token.start && from < s.end)
                .map(|s| Span {
                    start: s.start.max(from) - from,
                    end: s.end.min(token.start) - from,
                    ..*s
                })
                .collect();
            out.push_str(&self.apply_spans(&text[from..token.start], &piece, &added)?);
            out.push_str(&text[token.start..token.end]);
            from = token.end;
        }
        Ok((out, report))
    }

    fn mask_clear(&mut self, text: &str) -> Result<(String, DetectionReport), GateError> {
        if text.is_empty() {
            return Ok((String::new(), DetectionReport::empty(self.policy)));
        }
        // This path has no issued-token context, so every marker is detector input.
        let view = blank_minted(text, &token_ranges(text, &BTreeSet::new()));
        let (mut spans, covered) = self.detector.detect_covered(&view)?;
        let mut extra = export_spans(&view);
        extra.extend(take_widened(&mut spans));
        if self.policy == GrantPolicy::Passthrough && view.as_ref() != text {
            // The blanked view holds no token, so it never sees one that splices
            // a word: that run fails closed on the text itself, as the registry
            // and the tokenising gate read it (GATE-REGISTRY-GAP-1).
            let raw = self.detector.residue(text)?;
            extra.extend(raw.into_iter().filter(|span| span.recognizer == MARKER_RUN));
        }
        self.names_run = Some(self.names_run.unwrap_or(true) && covered);
        let report = report_of(self.policy, &spans, &extra);
        if self.policy == GrantPolicy::Passthrough {
            // Open mode returns ordinary text unchanged, but a prohibited
            // class (IBAN, card, ID, health, secret, address) is replaced, never
            // returned. Each maximal merged range is written once; every
            // other span is left exactly as it was.
            spans.extend(extra);
            return Ok((remove_prohibited(text, &spans), report));
        }
        Ok((self.apply_spans(text, &spans, &extra)?, report))
    }

    /// Mask `spans` of `text` and scan what is left in clear, then mask
    /// `extra` on top of that.
    ///
    /// SECRET-LEAK-294B: the residue rounds re-read the masked view, and what
    /// they find depends on what was masked first, so a span added up front
    /// can make them hide less. `extra` is added only once main's rounds have
    /// settled: the rounds run again from main's final spans plus `extra`, and
    /// spans only grow, so every byte main hides stays hidden. Those rounds
    /// never refuse on residue: a hit they leave is in bytes main's own output
    /// left in clear, and their last masking is returned. A detector error in
    /// them fails closed, as it does in main's rounds: main's output is never
    /// returned in its place.
    fn apply_spans(
        &mut self,
        text: &str,
        spans: &[Span],
        extra: &[Span],
    ) -> Result<String, GateError> {
        if text.is_empty() {
            return Ok(String::new());
        }
        // Fail closed: a secret-class value past the read cap is refused before
        // anything is masked, never masked in part.
        if crate::recognizers::secrets::value_too_long(text) {
            return Err(GateError::Detect(DetectError::TooLong));
        }
        let mut spans: Vec<Span> = spans
            .iter()
            .map(|span| without_possessive(text, *span))
            .collect();
        let (masked, settled) = self.residue_rounds(text, &mut spans)?;
        if !settled {
            return Err(GateError::Residue);
        }
        if extra.is_empty() {
            return Ok(masked);
        }
        spans.extend_from_slice(extra);
        let (more, _) = self.residue_rounds(text, &mut spans)?;
        Ok(more)
    }

    /// Mask `spans` of `text`, then add what the residue view still reads in
    /// clear, at most [`RESIDUE_ROUNDS`] times: the last masking, and whether
    /// its residue view read nothing.
    fn residue_rounds(
        &mut self,
        text: &str,
        spans: &mut Vec<Span>,
    ) -> Result<(String, bool), GateError> {
        let anonymizer = self.anonymizer.as_mut().ok_or(GateError::Key)?;
        let mut round = 0;
        loop {
            let (masked, tokens) = anonymizer.anonymize(text, spans);
            // The values this call newly masked are kept until the caller takes
            // them, so the local screen can resolve the tokens. Nothing else keeps them.
            self.minted.extend(tokens.iter().cloned());
            let clear = clear_parts(&masked);
            let clear = blank_minted(&clear, &token_ranges(&clear, &BTreeSet::new()));
            if crate::recognizers::secrets::value_too_long(&clear) {
                return Err(GateError::Detect(DetectError::TooLong));
            }
            // A residue hit is a value left in clear, unless every character of it is a
            // masked token's stand-in: then it is that token's own place. An address
            // reads its line, and a stand-in starts a new line, so the residue view
            // can read one the text never held: it never refuses (ADDR-DET-1).
            let residue = self.detector.residue(&clear)?;
            let hits: Vec<&Span> = residue
                .iter()
                .filter(|span| {
                    span.kind != EntityKind::Address
                        && !is_stand_in_only(&clear[span.start..span.end])
                })
                .collect();
            if hits.is_empty() {
                return Ok((masked, true));
            }
            // K-REFUSALS: a value the residue view reads in clear is masked, never
            // refused (private = tokenise). Masking changes what a clear quote next
            // to a stand-in pairs with, so the view can own more than the text did;
            // and a stand-in's line break starts a line, so a number glued to a
            // masked value reads as a phone or an MRZ line there (FIN-5: bank
            // files). A hit still there after the last round refuses.
            if round == RESIDUE_ROUNDS {
                return Ok((masked, false));
            }
            let mut more = residue_in_text(text, &masked, tokens.occurrences(), &hits);
            let tails = url_tails(text, spans, &more);
            more.extend(tails);
            if more.is_empty() {
                return Ok((masked, false));
            }
            spans.extend(more);
            round += 1;
        }
    }

    fn map_value(&mut self, value: &Value) -> Result<(Value, DetectionReport), GateError> {
        Ok(match value {
            Value::String(text) => {
                let (masked, report) = self.mask(text)?;
                (Value::String(masked), report)
            }
            Value::Array(items) => {
                let mut report = DetectionReport::empty(self.policy);
                let mut masked = Vec::with_capacity(items.len());
                for item in items {
                    let (value, item_report) = self.map_value(item)?;
                    masked.push(value);
                    report.merge(item_report);
                }
                (Value::Array(masked), report)
            }
            Value::Object(fields) => {
                let mut report = DetectionReport::empty(self.policy);
                let mut masked = Map::new();
                for (key, field) in fields {
                    let (masked_key, key_report) = self.mask(key)?;
                    let (masked_field, field_report) = match field {
                        Value::String(value) => self.map_string_field(key, value)?,
                        _ => self.map_value(field)?,
                    };
                    report.merge(key_report);
                    report.merge(field_report);
                    masked.insert(masked_key, masked_field);
                }
                (Value::Object(masked), report)
            }
            other => (other.clone(), DetectionReport::empty(self.policy)),
        })
    }

    /// Mask one object entry's string value.
    ///
    /// The value is masked on its own, as any string leaf is, and the detector
    /// **also** reads the synthetic line `"<key>: <value>"`: a bare JSON value
    /// carries no key beside it, so the secret recogniser cannot tell what it
    /// is. When a `Secret` span in that line touches the value's bytes, the key
    /// gave the value a secret's context and the whole value is one secret: a
    /// single minted token under `Tokenised`, [`SECRET_REMOVED`] under
    /// `Passthrough`. A value over the secret read cap still fails closed in
    /// tokenised mode, exactly as the text path does.
    fn map_string_field(
        &mut self,
        key: &str,
        value: &str,
    ) -> Result<(Value, DetectionReport), GateError> {
        // The session's own tokens read as blanks, as in `mask_keeping`: a kept
        // token is no marker and gives the value no secret's context.
        let probe = match &self.session_tokens {
            Some(minted) => blank_minted(value, &token_ranges(value, minted)),
            None => blank_minted(value, &token_ranges(value, &BTreeSet::new())),
        };
        let synthetic = format!("{key}: {probe}");
        let value_start = key.len() + ": ".len();
        // TODO(DECODE-HARDEN-3): any Secret span touching the value promotes it,
        // so a marker-word span in a plain `body` masks the whole body; promote
        // only when the key itself gave the secret context.
        let secret = self
            .detector
            .detect_patterns(&synthetic)?
            .iter()
            .any(|span| {
                span.kind == EntityKind::Secret
                    && span.start < synthetic.len()
                    && value_start < span.end
            });
        if !secret {
            let (masked, report) = self.mask(value)?;
            return Ok((Value::String(masked), report));
        }
        // Fail closed on a secret-class value past the read cap, exactly as the
        // text path and the ordinary string path do; passthrough removes the
        // whole value below instead of returning it.
        if self.policy == GrantPolicy::Tokenised
            && (crate::recognizers::secrets::value_too_long(value)
                || crate::recognizers::secrets::value_too_long(&synthetic))
        {
            return Err(GateError::Detect(DetectError::TooLong));
        }
        let span = Span::new(EntityKind::Secret, 0, value.len(), 1.0, "json-key");
        let report = DetectionReport::of(self.policy, &[span]);
        let masked = match self.policy {
            GrantPolicy::Passthrough => Value::String(SECRET_REMOVED.to_string()),
            GrantPolicy::Tokenised => {
                let anonymizer = self.anonymizer.as_mut().ok_or(GateError::Key)?;
                let (token, is_new) = anonymizer.token_for(EntityKind::Secret, value);
                if is_new {
                    self.minted.push((token.clone(), value.to_string()));
                }
                Value::String(format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"))
            }
        };
        Ok((masked, report))
    }
}

/// The second pass of a private gate (owner, 2026-10-14: "first round the
/// dictionary, second round with what stays"): a local model that finds the
/// person, organisation and address names the patterns and the dictionary do
/// not know. It only ever adds spans; it can never remove one.
pub trait NameSpotter: Send + Sync {
    /// Name spans in `text`, or an error. The caller falls back to pass 1 alone
    /// on an error; an implementation must not put `text` in the error.
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError>;
}

static NAME_SPOTTER: OnceLock<Arc<dyn NameSpotter>> = OnceLock::new();

/// Install the process-wide second pass; the first install wins. Tokenising
/// gates built afterwards run it; open mode never does.
pub fn install_name_spotter(spotter: Arc<dyn NameSpotter>) -> bool {
    NAME_SPOTTER.set(spotter).is_ok()
}

/// Whether a second pass is installed in this process.
pub fn name_spotter_installed() -> bool {
    NAME_SPOTTER.get().is_some()
}

/// Directory under `$AUXESIS_HOME/models/` that holds the second-pass model.
pub const LOCAL_MODEL_DIR: &str = "gliner2-pii";

/// [`crate::ner::install_local_model`] when this build has the `ner-gliner`
/// feature; without it there is no second pass and this returns `false`.
pub fn install_local_name_model(root: &std::path::Path, model_dir: &std::path::Path) -> bool {
    #[cfg(feature = "ner-gliner")]
    {
        crate::ner::install_local_model(root, model_dir)
    }
    #[cfg(not(feature = "ner-gliner"))]
    {
        let _ = (root, model_dir);
        false
    }
}

/// A [`NameSpotter`] run on one dedicated worker thread, with an input cap and a
/// deadline, so a slow or huge text can never stall a turn.
///
/// A text over `max_bytes` is not read at all (checked before the inner spotter
/// sees it). The inner spotter runs on the worker; if it has not answered within
/// `deadline` the call returns an error and the gate keeps pass 1. While the
/// worker is still busy with a late text, later texts skip the second pass
/// instead of queueing behind it. Each cause logs one line, never the text.
pub struct BoundedSpotter {
    inner: Arc<dyn NameSpotter>,
    max_bytes: usize,
    deadline: std::time::Duration,
    busy: Arc<std::sync::atomic::AtomicBool>,
    worker: std::sync::Mutex<Option<std::sync::mpsc::Sender<SpotJob>>>,
    logged: [std::sync::atomic::AtomicBool; 3],
}

type SpotJob = (
    String,
    std::sync::mpsc::SyncSender<Result<Vec<Span>, DetectError>>,
);

impl BoundedSpotter {
    /// `inner` behind a `max_bytes` input cap and a `deadline` per text.
    pub fn new(
        inner: Arc<dyn NameSpotter>,
        max_bytes: usize,
        deadline: std::time::Duration,
    ) -> Self {
        Self {
            inner,
            max_bytes,
            deadline,
            busy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            worker: std::sync::Mutex::new(None),
            logged: Default::default(),
        }
    }

    fn skip(&self, cause: usize, line: &str) -> Result<Vec<Span>, DetectError> {
        if !self.logged[cause].swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("auxesis: private mode: {line}; that text is checked by pass 1 only");
        }
        Err(DetectError::Names)
    }

    fn sender(&self) -> Option<std::sync::mpsc::Sender<SpotJob>> {
        let mut worker = self.worker.lock().unwrap_or_else(|p| p.into_inner());
        if worker.is_none() {
            let (tx, rx) = std::sync::mpsc::channel::<SpotJob>();
            let inner = Arc::clone(&self.inner);
            let busy = Arc::clone(&self.busy);
            std::thread::Builder::new()
                .name("auxesis-name-spotter".into())
                .spawn(move || {
                    for (text, reply) in rx {
                        let result = panic::catch_unwind(AssertUnwindSafe(|| inner.spot(&text)))
                            .unwrap_or(Err(DetectError::Panicked));
                        busy.store(false, std::sync::atomic::Ordering::Release);
                        let _ = reply.send(result);
                    }
                })
                .ok()?;
            *worker = Some(tx);
        }
        worker.clone()
    }
}

impl NameSpotter for BoundedSpotter {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        use std::sync::atomic::Ordering;
        if text.len() > self.max_bytes {
            return self.skip(0, "a text is too long for the local name model");
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return self.skip(1, "the local name model is still busy with an earlier text");
        }
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        let sent = self
            .sender()
            .is_some_and(|tx| tx.send((text.to_string(), reply)).is_ok());
        if !sent {
            self.busy.store(false, Ordering::Release);
            *self.worker.lock().unwrap_or_else(|p| p.into_inner()) = None;
            return self.skip(1, "the local name model worker is not running");
        }
        match answer.recv_timeout(self.deadline) {
            Ok(result) => result,
            Err(_) => self.skip(2, "the local name model took too long"),
        }
    }
}

/// The detector of a production gate for `grant`. Private mode hides no
/// person's or company's name (owner, 2026-10-19): a tokenising gate drops every
/// name span, whatever found it (the known-names dictionary, the e-mail layer's
/// cues), and never runs the name model. The registry drops them before its
/// overlap merge, so a name that overlaps a card, an IBAN, an ID, a secret, a
/// health term, a birth date, an e-mail address or a phone number can neither
/// take that value's label nor remove its mask. Open mode is unchanged.
fn egress_detector(grant: &Grant, standard: StandardDetector) -> Arc<dyn Detector> {
    match grant.policy() {
        GrantPolicy::Tokenised => without_names(standard),
        GrantPolicy::Passthrough => Arc::new(standard),
    }
}

/// The private-mode form of `standard`: names dropped before the merge, and
/// [`WithoutNames`] behind it.
fn without_names(standard: StandardDetector) -> Arc<dyn Detector> {
    Arc::new(WithoutNames(Arc::new(standard.without_names())))
}

#[cfg(feature = "ner-gliner")]
struct DeepAdder {
    standard: Arc<dyn Detector>,
    deep: Arc<dyn Detector>,
}

#[cfg(feature = "ner-gliner")]
static DEEP_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "ner-gliner")]
impl DeepAdder {
    fn new(standard: Arc<dyn Detector>, deep: Arc<dyn Detector>) -> Self {
        Self { standard, deep }
    }

    fn run(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let standard = self.standard.detect(text)?;
        self.add_deep(text, standard)
    }

    fn add_deep(&self, text: &str, standard: Vec<Span>) -> Result<Vec<Span>, DetectError> {
        if text.len() > 64 * 1024 {
            return Ok(standard);
        }
        use std::sync::atomic::Ordering;
        if DEEP_BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(standard);
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let deep = Arc::clone(&self.deep);
        let input = text.to_owned();
        if std::thread::Builder::new()
            .name("auxesis-deep-detector".into())
            .spawn(move || {
                let result = panic::catch_unwind(AssertUnwindSafe(|| deep.detect(&input)))
                    .unwrap_or(Err(DetectError::Panicked));
                DEEP_BUSY.store(false, Ordering::Release);
                let _ = tx.send(result);
            })
            .is_err()
        {
            DEEP_BUSY.store(false, Ordering::Release);
            return Ok(standard);
        }
        let Ok(Ok(spans)) = rx.recv_timeout(std::time::Duration::from_secs(5)) else {
            return Ok(standard);
        };
        let mut added: Vec<Span> = spans
            .into_iter()
            .filter(|span| span.kind.is_prohibited() && span_is_well_formed(text, span))
            .collect();
        let mut standard = standard;
        let widened = take_widened(&mut standard);
        added.extend(standard);
        let mut out = crate::ner::consolidate(added);
        out.extend(widened);
        Ok(out)
    }
}

#[cfg(feature = "ner-gliner")]
impl Detector for DeepAdder {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.run(text)
    }
    fn checks_names(&self) -> bool {
        self.standard.checks_names()
    }
    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        Ok((self.run(text)?, self.standard.checks_names()))
    }
    fn detect_pair_covered(&self, first: &str, second: &str) -> Result<DetectionPair, DetectError> {
        let first_standard = self.standard.detect(first)?;
        let second_standard = self.standard.detect(second)?;
        let first_covered = self.standard.checks_names();
        let second_covered = first_covered;
        let first_result = (first_standard, first_covered);
        let second_result = (self.add_deep(second, second_standard)?, second_covered);
        Ok((first_result, second_result))
    }
    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.run(text)
    }
    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        // Deep spans are masked from the original text before residue checking.
        // Keep residue on the deterministic stack so each Gate::text operation
        // runs the bounded model once and retains its single deadline.
        self.standard.residue(text)
    }
}

/// `inner` without its person and organisation spans: a second guard behind
/// [`Registry::without_names`], for any span a wrapped detector adds after the
/// registry ran.
struct WithoutNames(Arc<dyn Detector>);

impl WithoutNames {
    fn keep(mut spans: Vec<Span>) -> Vec<Span> {
        spans.retain(|span| !matches!(span.kind, EntityKind::Person | EntityKind::Organization));
        spans
    }
}

impl Detector for WithoutNames {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(Self::keep(self.0.detect(text)?))
    }

    fn checks_names(&self) -> bool {
        self.0.checks_names()
    }

    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        let (spans, covered) = self.0.detect_covered(text)?;
        Ok((Self::keep(spans), covered))
    }

    fn detect_pair_covered(&self, first: &str, second: &str) -> Result<DetectionPair, DetectError> {
        let ((first_spans, first_covered), (second_spans, second_covered)) =
            self.0.detect_pair_covered(first, second)?;
        Ok((
            (Self::keep(first_spans), first_covered),
            (Self::keep(second_spans), second_covered),
        ))
    }

    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(Self::keep(self.0.detect_patterns(text)?))
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(Self::keep(self.0.residue(text)?))
    }
}

/// Pass 1 (`first`) plus the name spotter on the same text. Pass 1 wins every
/// overlap. When the spotter errors or panics the text keeps its pass-1 spans
/// and the call reports that names were not covered by the spotter: the turn
/// never blocks on the model.
pub struct TwoPassDetector {
    first: Arc<dyn Detector>,
    spotter: Arc<dyn NameSpotter>,
}

impl TwoPassDetector {
    /// Pass 1 `first`, pass 2 `spotter`.
    pub fn new(first: Arc<dyn Detector>, spotter: Arc<dyn NameSpotter>) -> Self {
        Self { first, spotter }
    }
}

impl Detector for TwoPassDetector {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self.detect_covered(text)?.0)
    }

    fn detect_covered(&self, text: &str) -> Result<(Vec<Span>, bool), DetectError> {
        let (mut spans, first_covered) = self.first.detect_covered(text)?;
        let spotted = panic::catch_unwind(AssertUnwindSafe(|| self.spotter.spot(text)));
        let Ok(Ok(found)) = spotted else {
            return Ok((spans, first_covered));
        };
        let extra: Vec<Span> = found
            .into_iter()
            .filter(|span| {
                matches!(
                    span.kind,
                    EntityKind::Person | EntityKind::Organization | EntityKind::Address
                ) && span_is_well_formed(text, span)
                    && !(span.kind != EntityKind::Address
                        && model_function_word(&text[span.start..span.end])
                        && !reads_as_name(text, span))
                    && !spans.iter().any(|kept| kept.overlaps(span))
            })
            .collect();
        spans.extend(extra);
        spans.sort_by_key(|span| (span.start, span.end));
        Ok((spans, true))
    }

    fn detect_patterns(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.first.detect_patterns(text)
    }

    fn checks_names(&self) -> bool {
        self.first.checks_names()
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.first.residue(text)
    }
}

/// Words the name model tags as a person or an organisation on their own at
/// its low name floor (TOK-FP: "Who wrote to me last?" lost its `Who`), beyond
/// the closed function words. These are real given names too, so only a
/// model span of the word alone is dropped: "May Smith" is still a name, and
/// the owner's contacts (pass 1) are never filtered this way.
const MODEL_NOT_NAMES: &str = "why how i can may will june";

/// Whether a model name span is one function word and nothing else.
fn model_function_word(value: &str) -> bool {
    let word =
        crate::contacts::fold::folded_text(value.trim_matches(|ch: char| !ch.is_alphanumeric()));
    !word.contains(char::is_whitespace)
        && (crate::contacts::stopwords::is_closed_word(&word)
            || MODEL_NOT_NAMES
                .split_whitespace()
                .any(|listed| listed == word))
}

/// Given names that are also words, and what greets or signs a name.
const WORD_NAMES: &str = "can may will june";
const GREETINGS: &str = "hi hey hello dear thanks cheers";

/// Whether context makes a [`WORD_NAMES`] span a name: a capitalised surname
/// follows (`May Smith`), or a greeting or a signature dash comes before it
/// (`Hi June,`, `— Will`).
fn reads_as_name(text: &str, span: &Span) -> bool {
    let folded = |word: &str| crate::contacts::fold::folded_text(word);
    let listed = |list: &str, word: &str| list.split_whitespace().any(|w| w == folded(word));
    if !listed(WORD_NAMES, text[span.start..span.end].trim()) {
        return false;
    }
    let next = text[span.end..]
        .trim_start_matches(' ')
        .split(|ch: char| !ch.is_alphanumeric())
        .next()
        .unwrap_or_default();
    let before = text[..span.start].trim_end_matches([' ', ',']);
    (next.starts_with(char::is_uppercase) && !model_function_word(next))
        || before.ends_with(['—', '–', '-'])
        || before
            .rsplit(|ch: char| !ch.is_alphanumeric())
            .next()
            .is_some_and(|word| listed(GREETINGS, word))
}

fn default_detector() -> Arc<dyn Detector> {
    DEFAULT_DETECTOR
        .get_or_init(|| Arc::new(StandardDetector::new()))
        .clone()
}

/// The best configuration the eval measures: deterministic candidates and
/// model spans go through the e-mail layer together, and the model's `PERSON`
/// spans seed name propagation.
#[cfg(feature = "ner-gliner")]
struct NameStack {
    deterministic: Registry,
    layer: EmailLayer,
    model: GlinerRecognizer,
}

#[cfg(feature = "ner-gliner")]
impl NameStack {
    fn new(model: GlinerRecognizer) -> Self {
        Self {
            deterministic: Registry::builder().with_all().without_email_layer().build(),
            layer: EmailLayer::new(),
            model,
        }
    }

    /// The Standard deterministic half plus the caller's known names. The
    /// e-mail layer runs once, below, with the model's spans in it.
    fn with_names<I, S>(model: GlinerRecognizer, names: I) -> Result<Self, NameDictionaryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let (builder, _) = standard_builder(names)?;
        Ok(Self {
            deterministic: builder.without_email_layer().build(),
            layer: EmailLayer::new(),
            model,
        })
    }

    fn run(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let mut candidates = self.deterministic.analyze(text);
        let predicted = self
            .model
            .analyze_report(text)
            .map_err(|_| DetectError::Names)?
            .spans;
        let seeds: Vec<Span> = predicted
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .copied()
            .collect();
        candidates.extend(predicted);
        let layered = self.layer.apply(text, candidates, &seeds);
        let layered = extend_hyphenated_persons(text, layered);
        Ok(split_long_spans(text, resolve_overlaps(layered)))
    }
}

#[cfg(feature = "ner-gliner")]
impl Detector for NameStack {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        panic::catch_unwind(AssertUnwindSafe(|| self.run(text)))
            .map_err(|_| DetectError::Panicked)?
    }

    fn checks_names(&self) -> bool {
        true
    }

    fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        // The deterministic half only: the model's name spans depend on their
        // context, as the e-mail layer's do (see `Detector::residue`).
        panic::catch_unwind(AssertUnwindSafe(|| self.deterministic.analyze(text)))
            .map_err(|_| DetectError::Panicked)
    }
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gate").finish_non_exhaustive()
    }
}

/// The stand-in for a masked token in the clear text of the residue scan. It is
/// one character that is not a blank, so a value rule reads the token's place as
/// a value's place: the blank it replaces let a rule's separator skip into the
/// next word (`password: ⟦…⟧ tous` read `tous` as a value). A hit that holds the
/// stand-in is the masked token's own value, never residue.
const MASKED_STAND_IN: char = '\u{E000}';

/// Rounds that mask a secret residue before the gate refuses the text.
const RESIDUE_ROUNDS: usize = 3;

/// The clear bytes of each residue `hits` (offsets in the clear text of `masked`),
/// as spans of `text` of the hit's class, the string `masked` was made from with the
/// per-token `occurrences`. A secret runs on to the end of its line in `text`: the
/// stand-in's line break may have cut it short there. Any other class is the hit's
/// own bytes: its rule read the whole value, and the next round scans again. A clear
/// byte has the same length in both texts (`⟦⟦` reads as `⟦`, a typed stand-in as
/// U+FFFD, a blanked token as blanks).
fn residue_in_text(
    text: &str,
    masked: &str,
    occurrences: &[(String, String)],
    hits: &[&Span],
) -> Vec<Span> {
    // Clear stretches: (offset in the clear text, offset in `text`, length).
    let (mut stretches, mut view, mut at) = (Vec::<(usize, usize, usize)>::new(), 0, 0);
    let mut surfaces = occurrences.iter().map(|(_, surface)| surface.len());
    let mut chars = masked.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == PLACEHOLDER_OPEN && chars.peek() != Some(&PLACEHOLDER_OPEN) {
            chars.by_ref().find(|&inner| inner == PLACEHOLDER_CLOSE);
            view += MASKED_STAND_IN.len_utf8() + 1;
            at += surfaces.next().unwrap_or(0);
            continue;
        }
        if ch == PLACEHOLDER_OPEN {
            chars.next();
        }
        match stretches.last_mut() {
            Some(last) if last.0 + last.2 == view && last.1 + last.2 == at => {
                last.2 += ch.len_utf8();
            }
            _ => stretches.push((view, at, ch.len_utf8())),
        }
        (view, at) = (view + ch.len_utf8(), at + ch.len_utf8());
    }
    let mut found = Vec::new();
    for hit in hits {
        // Stretches are sorted: a binary search, then only the ones the hit overlaps.
        let first = stretches.partition_point(|&(from, _, len)| from + len <= hit.start);
        for &(from, to, len) in stretches[first..].iter().take_while(|s| s.0 < hit.end) {
            let (start, end) = (hit.start.max(from), hit.end.min(from + len));
            if start < end && to + len <= text.len() {
                found.push((to + start - from, to + end - from, hit.kind));
            }
        }
    }
    let mut spans: Vec<Span> = found
        .extract_if(.., |(_, _, kind)| *kind != EntityKind::Secret)
        .map(|(start, end, kind)| Span::new(kind, start, end, 1.0, "residue"))
        .collect();
    // Each line end is searched from the furthest point reached, and each line's trimmed
    // end is found once, from its first hit: one pass over `text`. Hits are sorted, so a
    // later hit on the same line starts at or after that first one, and its trimmed end is
    // the larger of its start and the line's.
    found.sort_unstable_by_key(|&(start, end, _)| (start, end));
    let (mut reach, mut trimmed) = (0, (usize::MAX, 0));
    for (start, end, _) in found {
        let from = start.max(reach).min(text.len());
        let line = text[from..].find('\n').map_or(text.len(), |n| from + n);
        if trimmed.0 != line {
            trimmed = (line, start + text[start..line].trim_end().len());
        }
        let end = end.max(start.max(trimmed.1));
        reach = reach.max(line);
        spans.push(Span::new(EntityKind::Secret, start, end, 1.0, "residue"));
    }
    spans
}

/// K-RESIDUE-URL: the rest of each residue URL in `more` that a masked secret
/// cut short. A secret's stand-in ends its line in the residue view, so a URL
/// read there stops at the secret, while the URL rule, reading the text itself,
/// runs on through it (`…?key=<secret>&alt=json`). Past each secret span the URL
/// is the run of URL characters up to a blank, a URL stop or the next masked
/// span; it runs on through every secret span it meets. These tails are only
/// added: no span is removed or narrowed.
fn url_tails(text: &str, spans: &[Span], more: &[Span]) -> Vec<Span> {
    let mut tails = Vec::new();
    if !more.iter().any(|span| span.kind == EntityKind::Url) {
        return tails;
    }
    // Secret spans merged into disjoint ranges, and every span's start, sorted.
    let mut secrets: Vec<(usize, usize)> = spans
        .iter()
        .filter(|span| span.kind == EntityKind::Secret)
        .map(|span| (span.start, span.end))
        .collect();
    secrets.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(secrets.len());
    for (start, end) in secrets {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut starts: Vec<usize> = spans.iter().map(|span| span.start).collect();
    starts.sort_unstable();
    let stop = |ch: char| ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'' | ')');
    let mut ends: Vec<usize> = more
        .iter()
        .filter(|span| span.kind == EntityKind::Url)
        .map(|span| span.end)
        .collect();
    ends.sort_unstable();
    // A walk covers every URL end it passes: each byte is walked once (linear).
    let mut reach = 0;
    for mut at in ends {
        if at < reach {
            continue;
        }
        // Each step moves past one merged secret range, so this ends.
        while let Some(&(_, end)) = merged
            .get(merged.partition_point(|&(_, end)| end <= at))
            .filter(|&&(start, _)| start <= at)
        {
            at = end.min(text.len());
            let next = starts
                .get(starts.partition_point(|&s| s < at))
                .map_or(text.len(), |&s| s.min(text.len()));
            let run = text.get(at..next).unwrap_or("");
            // The URL rule reads through a Unicode space between two ASCII letters
            // or digits (the folded view drops it), so the tail does too.
            let glued = |i: usize, ch: char| {
                crate::normalize::is_unicode_space(ch)
                    && text[..at + i]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric())
                    && text[at + i + ch.len_utf8()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric())
            };
            let found = run
                .char_indices()
                .find(|&(i, ch)| stop(ch) && !glued(i, ch));
            let found = found.map(|(i, _)| i);
            let Some(cut) = found.or((next == text.len()).then_some(run.len())) else {
                // The run reaches the next masked span: the URL may go on past it.
                if next > at {
                    tails.push(Span::new(EntityKind::Url, at, next, 1.0, "residue"));
                }
                at = next;
                continue;
            };
            // The URL ends here: the URL rule's trailing punctuation stays out.
            let cut = run[..cut]
                .trim_end_matches(['.', ',', ';', ':', '!', '?'])
                .len();
            if cut > 0 {
                tails.push(Span::new(EntityKind::Url, at, at + cut, 1.0, "residue"));
            }
            break;
        }
        reach = at;
    }
    tails
}

/// Whether a residue hit is only stand-ins: every character is a masked token's
/// stand-in, so the hit is that token's own place. A hit with any other character,
/// even one next to a stand-in, is a value left in clear.
fn is_stand_in_only(hit: &str) -> bool {
    !hit.is_empty() && hit.chars().all(|ch| ch == MASKED_STAND_IN)
}

/// The clear text of a masked string, read the way [`Anonymizer::restore`]
/// reads it: a doubled opener is one literal `⟦`, and each placeholder becomes
/// [`MASKED_STAND_IN`], so its hex fingerprint never reads as a value in the
/// residue scan.
///
/// Not a line break: a line break starts a new line for the e-mail layer's line
/// heuristics, which then read the words that follow a token as names
/// (`…⟦TOKEN⟧): Find places matching a name` gave `name` as a person) and refused
/// text the first pass had already masked correctly.
fn clear_parts(masked: &str) -> Cow<'_, str> {
    if !masked.contains(MASKED_STAND_IN) && !masked.contains(PLACEHOLDER_OPEN) {
        return Cow::Borrowed(masked);
    }
    let mut clear = String::with_capacity(masked.len());
    let mut chars = masked.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == MASKED_STAND_IN {
            // Typed text, not a token: it keeps a character that is no stand-in.
            clear.push('\u{FFFD}');
        } else if ch != PLACEHOLDER_OPEN {
            clear.push(ch);
        } else if chars.peek() == Some(&PLACEHOLDER_OPEN) {
            chars.next();
            clear.push(PLACEHOLDER_OPEN);
        } else {
            // The stand-in ends its line in the clear text. A masked value ran to
            // the end of its line, and a merged span may have eaten the line break:
            // the residue scan must not read the next line as that value.
            clear.push(MASKED_STAND_IN);
            clear.push('\n');
            for inner in chars.by_ref() {
                if inner == PLACEHOLDER_CLOSE {
                    break;
                }
            }
        }
    }
    Cow::Owned(clear)
}

/// A standalone token marker issued by this session.
struct TokenRange {
    start: usize,
    end: usize,
}

/// Every standalone, well-formed known token marker in `text` that this session
/// issued. All foreign, nested, entity-encoded, or unresolved marker text stays
/// ordinary detector input.
fn token_ranges(text: &str, minted: &BTreeSet<String>) -> Vec<TokenRange> {
    if minted.is_empty() {
        return Vec::new();
    }
    let issued: HashSet<&str> = minted.iter().map(String::as_str).collect();
    let (mut candidates, mut at) = (Vec::new(), 0);
    while let Some(offset) = text[at..].find(PLACEHOLDER_OPEN) {
        let start = at + offset;
        match session_token_len(&text[start..]) {
            Some(len) => {
                let (open, close) = (PLACEHOLDER_OPEN.len_utf8(), PLACEHOLDER_CLOSE.len_utf8());
                let end = start + len;
                let body = &text[start + open..start + len - close];
                if issued.contains(body) {
                    candidates.push(TokenRange { start, end });
                }
                at = end;
            }
            None => {
                at = start + PLACEHOLDER_OPEN.len_utf8();
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    // Walk the decoded marker spans and candidates together. The old code
    // searched all spans for exact, enclosing and unresolved matches per token
    // (`contains`/`any`), which made repeated issued tokens quadratic.
    let decoded = crate::decode::DecodedText::new(text);
    let markers = decoded.markers();
    let unresolved = decoded.unresolved();
    let mut found = Vec::with_capacity(candidates.len());
    let (mut marker_at, mut unresolved_at, mut outer_end) = (0, 0, 0);
    for candidate in candidates {
        while marker_at < markers.len() && markers[marker_at].0 < candidate.start {
            outer_end = outer_end.max(markers[marker_at].1);
            marker_at += 1;
        }
        let nested = outer_end >= candidate.end;

        let mut group_end = marker_at;
        let mut exact = false;
        let mut group_end_max = outer_end;
        while group_end < markers.len() && markers[group_end].0 == candidate.start {
            let (_, end) = markers[group_end];
            exact |= end == candidate.end;
            group_end_max = group_end_max.max(end);
            group_end += 1;
        }
        if group_end > marker_at {
            // These spans are prior context for the next candidate, but their
            // shared start cannot make this candidate nested in itself.
            marker_at = group_end;
            outer_end = group_end_max;
        }

        while unresolved_at < unresolved.len() && unresolved[unresolved_at].1 <= candidate.start {
            unresolved_at += 1;
        }
        let overlaps_unresolved = unresolved
            .get(unresolved_at)
            .is_some_and(|&(from, _)| from < candidate.end);
        if exact && !nested && !overlaps_unresolved {
            found.push(candidate);
        }
    }
    found
}

/// `text` with every issued token replaced by blanks of the same byte length;
/// with no token it is borrowed, since the clear text already is the view.
fn blank_minted<'a>(text: &'a str, tokens: &[TokenRange]) -> Cow<'a, str> {
    if tokens.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    for token in tokens {
        let close = token.end - PLACEHOLDER_CLOSE.len_utf8();
        let blank = token.start;
        out.push_str(&text[from..blank]);
        out.extend(std::iter::repeat_n(' ', close - blank));
        out.extend(std::iter::repeat_n(' ', token.end - close));
        from = token.end;
    }
    out.push_str(&text[from..]);
    Cow::Owned(out)
}

/// The kept stretches of a stripped text: `(offset in the view, offset in the
/// original, length)`.
struct Segments(Vec<(usize, usize, usize)>);

impl Segments {
    /// The original offset of view offset `at`; `ending` reads it as the end of
    /// a span, so a span that stops where a token was ends before the token.
    fn original(&self, at: usize, ending: bool) -> Option<usize> {
        // Stretches are sorted by view offset: a binary search, not a scan.
        let index = self.0.partition_point(|&(view, _, len)| {
            if ending {
                view + len < at
            } else {
                view + len <= at
            }
        });
        let &(view, original, len) = self.0.get(index)?;
        let inside = if ending {
            view < at && at <= view + len
        } else {
            view <= at && at < view + len
        };
        inside.then(|| original + (at - view))
    }
}

/// `text` with every token deleted, and how to map its offsets back.
fn strip_tokens(text: &str, tokens: &[TokenRange]) -> (String, Segments) {
    let (mut out, mut segments, mut from) = (String::with_capacity(text.len()), Vec::new(), 0);
    let ends = tokens
        .iter()
        .map(|t| (t.start, t.end))
        .chain(std::iter::once((text.len(), text.len())));
    for (start, end) in ends {
        if start > from {
            segments.push((out.len(), from, start - from));
            out.push_str(&text[from..start]);
        }
        from = end;
    }
    (out, Segments(segments))
}

/// Longest token body (the bytes between `⟦` and `⟧`) read as a session token.
/// A real one is a kind, `_`, 12 hex digits and an optional `_N`, far below this.
const MAX_SESSION_TOKEN_BYTES: usize = 64;

/// Byte length of the session token that starts `text` (`⟦`, a known kernel
/// kind, `_`, 12 uppercase hex digits, an optional `_<n>`, `⟧`), or `None`.
fn session_token_len(text: &str) -> Option<usize> {
    let body = text.strip_prefix(PLACEHOLDER_OPEN)?;
    // Look for the closer only within the longest token: text of a million
    // openers and no closer must not rescan the rest at each opener.
    let mut window = body
        .len()
        .min(MAX_SESSION_TOKEN_BYTES + PLACEHOLDER_CLOSE.len_utf8());
    while !body.is_char_boundary(window) {
        window -= 1;
    }
    let close = body[..window].find(PLACEHOLDER_CLOSE)?;
    let body = &body[..close];
    let is_hex = |s: &str| {
        s.len() == 12
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    };
    let kind = EntityKind::ALL.into_iter().find(|kind| {
        body.strip_prefix(kind.as_str())
            .is_some_and(|rest| rest.starts_with('_'))
    })?;
    let fingerprint = body.strip_prefix(kind.as_str())?.strip_prefix('_')?;
    let valid = if let Some((hex, number)) = fingerprint.rsplit_once('_') {
        is_hex(hex) && (1..=3).contains(&number.len()) && number.bytes().all(|b| b.is_ascii_digit())
    } else {
        is_hex(fingerprint)
    };
    valid.then(|| PLACEHOLDER_OPEN.len_utf8() + close + PLACEHOLDER_CLOSE.len_utf8())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::{EntityKind, Span};
    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const KEY: [u8; 32] = [9u8; 32];

    #[test]
    fn hash_fragment_exclusion_is_bounded_and_masks_overlong_runs() {
        let text = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let span = Span::new(
            EntityKind::Iban,
            0,
            15,
            crate::recognizers::iban::SHAPE_SCORE,
            "iban",
        );
        assert!(is_hash_fragment(text, &span));

        let long = "a".repeat(1024);
        let span = Span::new(
            EntityKind::Iban,
            400,
            415,
            crate::recognizers::iban::SHAPE_SCORE,
            "iban",
        );
        assert!(!is_hash_fragment(&long, &span));
    }

    /// A real grant, minted the way production does. C9 is covered and allowed
    /// in both modes, so a test can pick the policy it exercises.
    fn grant(mode: PrivacyMode) -> Grant {
        let ctx = Context {
            destination: Destination::LocalDisplay,
        };
        match admit(PathId::C9, mode, &ctx) {
            Decision::Allow(grant) => grant,
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    /// An open-mode gate: the detectors run, nothing is masked.
    fn passthrough_gate() -> Gate {
        Gate::for_grant(&grant(PrivacyMode::Open), KEY)
    }

    /// A passthrough gate over a detector with no name coverage at all: the
    /// pre-Standard view, kept to test [`NameCoverage::NotChecked`].
    fn passthrough_gate_without_names() -> Gate {
        Gate::for_tests(&grant(PrivacyMode::Open), KEY, Arc::new(Registry::new()))
    }

    /// A private-mode gate over an injected detector: masking needs a name
    /// detector, so tests inject one.
    fn tokenising_gate(key: [u8; 32], detector: Arc<dyn Detector>) -> Gate {
        Gate::for_tests(&grant(PrivacyMode::Private), key, detector)
    }

    /// The default deterministic registry, claiming name coverage, so the
    /// tokenising path can be exercised without GLiNER.
    struct NamesClaimed(Registry);

    impl NamesClaimed {
        fn new() -> Self {
            Self(Registry::new())
        }
    }

    impl Detector for NamesClaimed {
        fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            self.0.detect(text)
        }

        fn checks_names(&self) -> bool {
            true
        }

        fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            self.0.residue(text)
        }
    }

    fn masking_gate() -> Gate {
        tokenising_gate(KEY, Arc::new(NamesClaimed::new()))
    }

    /// A detector that always fails, to exercise the fail-closed path.
    struct Broken;

    impl Detector for Broken {
        fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
            Err(DetectError::Panicked)
        }

        /// A tokenising gate refuses before detection when names are
        /// unchecked; these probes stand in for the full stack.
        fn checks_names(&self) -> bool {
            true
        }
    }

    /// Detects like [`NamesClaimed`], but its residue view fails from the
    /// second call on: the rounds that add export columns.
    struct FailsLate(NamesClaimed, std::sync::atomic::AtomicUsize);

    impl Detector for FailsLate {
        fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            self.0.detect(text)
        }

        fn checks_names(&self) -> bool {
            true
        }

        fn residue(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            if self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                return Err(DetectError::Panicked);
            }
            self.0.residue(text)
        }
    }

    #[test]
    fn a_detector_error_after_the_export_mask_fails_closed() {
        let detector = FailsLate(NamesClaimed::new(), std::sync::atomic::AtomicUsize::new(0));
        let mut gate = tokenising_gate(KEY, Arc::new(detector));
        let result = gate.text("user,login_password,note\nalice,hunter2,x");
        assert!(
            result.is_err(),
            "{:?}",
            result.map(|(safe, _)| safe.as_str().to_owned())
        );
    }

    #[test]
    fn open_text_is_issued_unchanged_with_a_would_have_masked_report() {
        let mut gate = passthrough_gate();
        let (safe, report) = gate.text("Bonjour, quelle heure est-il ?").unwrap();
        assert_eq!(safe.as_str(), "Bonjour, quelle heure est-il ?");
        assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
        assert!(report.is_empty());
        assert_eq!(gate.policy(), GrantPolicy::Passthrough);
    }

    #[test]
    fn passthrough_reports_what_private_would_have_masked_without_a_value() {
        let raw = "elise.vautrin@example.invalid";
        let mut gate = passthrough_gate();
        let (safe, report) = gate.text(&format!("Écris à {raw} demain")).unwrap();
        // Open mode masks nothing…
        assert!(safe.as_str().contains(raw));
        // …but the report names the kind and the count, never the value.
        assert_eq!(report.label(), DetectionReport::WOULD_HAVE_MASKED);
        assert_eq!(report.count(EntityKind::Email), 1);
        assert_eq!(report.total(), 1);
        assert!(!format!("{report:?}").contains(raw));
        assert!(!report.to_string().contains(raw));
        assert!(report.to_string().contains("EMAIL=1"), "{report}");
    }

    #[test]
    fn detected_values_never_reach_the_masked_text() {
        let mut gate = masking_gate();
        let (safe, report) = gate
            .text("Écris à elise.vautrin@example.invalid demain")
            .unwrap();
        assert!(!safe.as_str().contains("elise.vautrin"));
        assert!(safe.as_str().contains("⟦EMAIL_"));
        assert_eq!(report.label(), DetectionReport::MASKED);
        assert_eq!(report.count(EntityKind::Email), 1);
        assert!(!report.to_string().contains("elise.vautrin"));
        assert_eq!(gate.policy(), GrantPolicy::Tokenised);
    }

    #[test]
    fn a_value_report_counts_every_string_leaf_without_a_value() {
        let mut gate = masking_gate();
        let raw = "elise.vautrin@example.invalid";
        let (safe, report) = gate
            .value(&serde_json::json!({ "to": raw, "note": raw }))
            .unwrap();
        assert_eq!(report.count(EntityKind::Email), 2);
        assert!(!format!("{report:?}").contains("elise.vautrin"));
        assert!(!serde_json::to_string(&safe).unwrap().contains(raw));
    }

    #[test]
    fn a_passthrough_gate_refuses_a_tokenising_grant() {
        assert_eq!(
            Gate::for_passthrough(&grant(PrivacyMode::Private)).unwrap_err(),
            GateError::Key
        );
        assert!(Gate::for_passthrough(&grant(PrivacyMode::Open)).is_ok());
    }

    #[test]
    fn the_same_value_gets_the_same_token_within_a_gate() {
        let mut gate = masking_gate();
        let (first, _) = gate.text("mail elise.vautrin@example.invalid").unwrap();
        let (second, _) = gate.text("encore elise.vautrin@example.invalid").unwrap();
        let token = |text: &str| {
            text.split('⟦')
                .nth(1)
                .unwrap()
                .split('⟧')
                .next()
                .unwrap()
                .to_string()
        };
        assert_eq!(token(first.as_str()), token(second.as_str()));
    }

    #[test]
    fn a_new_key_gives_a_new_token() {
        let value = "mail elise.vautrin@example.invalid";
        let mut a = tokenising_gate([1u8; 32], Arc::new(NamesClaimed::new()));
        let mut b = tokenising_gate([2u8; 32], Arc::new(NamesClaimed::new()));
        let a = a.text(value).unwrap().0;
        let b = b.text(value).unwrap().0;
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn a_detection_error_issues_nothing() {
        let mut gate = tokenising_gate(KEY, Arc::new(Broken));
        let err = gate.text("anything").unwrap_err();
        assert_eq!(err, GateError::Detect(DetectError::Panicked));
    }

    /// Finds the word `secret` on the first pass, then reads the first clear
    /// character of every residue view as a value of its class.
    struct Leaky(EntityKind, AtomicUsize);

    impl Leaky {
        fn new(kind: EntityKind) -> Arc<Self> {
            Arc::new(Self(kind, AtomicUsize::new(0)))
        }
    }

    impl Detector for Leaky {
        fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            let first = self.1.fetch_add(1, Ordering::SeqCst) == 0;
            let found = if first {
                text.find("secret").map(|at| (at, at + "secret".len()))
            } else {
                let at = text.find(|ch: char| !ch.is_whitespace() && ch != MASKED_STAND_IN);
                at.map(|at| (at, at + 1))
            };
            Ok(found
                .map(|(start, end)| vec![Span::new(self.0, start, end, 1.0, "leaky")])
                .unwrap_or_default())
        }

        fn checks_names(&self) -> bool {
            true
        }
    }

    #[test]
    fn a_residue_still_in_clear_after_the_last_round_is_refused() {
        for kind in [EntityKind::NationalId, EntityKind::Phone] {
            let mut gate = tokenising_gate(KEY, Leaky::new(kind));
            let err = gate.text("a b c d secret").unwrap_err();
            assert_eq!(err, GateError::Residue, "{kind:?}");
        }
    }

    /// FIN-5: a residue of any class is masked, never refused. Any class but a
    /// secret is masked as its own bytes, as its own class.
    #[test]
    fn a_residue_of_any_class_is_masked_not_refused() {
        for kind in [EntityKind::NationalId, EntityKind::Phone, EntityKind::Iban] {
            let mut gate = tokenising_gate(KEY, Leaky::new(kind));
            let (safe, _) = gate.text("a secret").unwrap();
            let clear = clear_parts(safe.as_str());
            assert!(
                clear
                    .chars()
                    .all(|ch| ch == MASKED_STAND_IN || ch.is_whitespace()),
                "{kind:?}: {}",
                safe.as_str()
            );
        }
    }

    #[test]
    fn a_secret_residue_is_masked_to_its_line_end_not_refused() {
        let mut gate = tokenising_gate(KEY, Leaky::new(EntityKind::Secret));
        let (safe, _) = gate.text("a b secret\nnext").unwrap();
        assert!(safe.as_str().starts_with('⟦'), "{}", safe.as_str());
        assert!(!safe.as_str().contains("a b"), "{}", safe.as_str());
        // Each round masks one more line; past the last round the gate refuses.
        let mut gate = tokenising_gate(KEY, Leaky::new(EntityKind::Secret));
        let text = "a\nb\nc\nd\nsecret";
        assert_eq!(gate.text(text).unwrap_err(), GateError::Residue);
    }

    #[test]
    fn session_tokens_pass_whole_and_clear_values_are_masked() {
        let mut gate = Gate::for_session_tokens(&grant(PrivacyMode::Private), minted()).unwrap();
        let input = serde_json::json!({
            "to": "⟦EMAIL_0A1B2C3D4E5F⟧",
            "note": "iban ⟦IBAN_0A1B2C3D4E5F_2⟧ or elise.vautrin@example.invalid",
            "forged": "⟦FR7630006000011234567890189⟧"
        });
        let (safe, _) = gate.value(&input).unwrap();
        let wire = serde_json::to_string(&safe).unwrap();
        assert!(wire.contains("\"⟦EMAIL_0A1B2C3D4E5F⟧\""), "{wire}");
        assert!(wire.contains("⟦IBAN_0A1B2C3D4E5F_2⟧"), "{wire}");
        assert!(!wire.contains("elise.vautrin"), "{wire}");
        assert!(!wire.contains("FR7630006000011234567890189"), "{wire}");
    }

    /// A kept session token can leave detection with nothing, but the residue
    /// pass still reads the password label after it: the next line is masked.
    #[test]
    fn a_minted_token_before_a_password_label_does_not_skip_the_residue_pass() {
        let mut gate = Gate::for_session_tokens(&grant(PrivacyMode::Private), minted()).unwrap();
        let (safe, _) = gate
            .text("prefix ⟦EMAIL_0A1B2C3D4E5F⟧password\nordinaryword")
            .expect("the residue pass masks the value");
        assert!(!safe.as_str().contains("ordinaryword"), "{}", safe.as_str());
    }

    /// The tokens this test's session minted.
    fn minted() -> Arc<BTreeSet<String>> {
        Arc::new(
            [
                "EMAIL_0A1B2C3D4E5F",
                "IBAN_0A1B2C3D4E5F_2",
                "PERSON_0A1B2C3D4E5F",
            ]
            .map(String::from)
            .into(),
        )
    }

    fn session_gate_wire(input: &str) -> String {
        let mut gate = Gate::for_session_tokens(&grant(PrivacyMode::Private), minted()).unwrap();
        let (safe, _) = gate.value(&serde_json::json!({ "v": input })).unwrap();
        serde_json::to_string(&safe).unwrap()
    }

    #[test]
    fn a_kept_session_token_stays_a_reference_and_clear_values_are_still_masked() {
        let mut gate = Gate::for_grant(&grant(PrivacyMode::Private), [3u8; 32]);
        let (first, _) = gate.text("Write to anne@example.org").unwrap();
        let minted = gate.take_minted();
        let token = minted[0].0.clone();
        assert!(first.as_str().contains(&format!("⟦{token}⟧")));
        let reply = format!("Mail from ⟦{token}⟧, cc bob@example.org.");

        // By default a token-shaped string the model wrote is literal text.
        let (plain, _) = gate.text(&reply).unwrap();
        assert!(
            plain.as_str().contains(&format!("⟦⟦{token}⟧")),
            "{}",
            plain.as_str()
        );
        gate.take_minted();

        gate.keep_session_tokens(Some(Arc::new([token.clone()].into())));
        let (kept, _) = gate.text(&reply.replace("bob", "carol")).unwrap();
        assert!(kept
            .as_str()
            .starts_with(&format!("Mail from ⟦{token}⟧, cc ⟦EMAIL_")));
        assert!(!kept.as_str().contains("carol@example.org"));
        let new = gate.take_minted();
        assert_eq!(
            new.len(),
            1,
            "the clear value is minted under the session key"
        );
        assert_eq!(new[0].1, "carol@example.org");

        gate.keep_session_tokens(None);
        assert!(gate.text(&reply).unwrap().0.as_str().contains("⟦⟦"));

        // Open mode: a passthrough gate ignores it and keeps the text.
        let mut open = Gate::for_passthrough(&grant(PrivacyMode::Open)).unwrap();
        open.keep_session_tokens(Some(Arc::new([token.clone()].into())));
        assert_eq!(open.text(&reply).unwrap().0.as_str(), reply);
    }

    #[test]
    fn kept_tokens_are_found_in_linear_time_on_openers_with_no_closer() {
        // A model reply of `⟦x` repeated: 1 MiB and no closer. A closer search
        // to the end of the text at each opener took 8 s in release; one pass is
        // milliseconds (7 ms release). The bound is generous for a debug build.
        let text = "⟦x".repeat(1024 * 1024 / 4);
        let started = std::time::Instant::now();
        assert!(token_ranges(&text, &minted()).is_empty());
        let scan = started.elapsed();
        assert!(scan < std::time::Duration::from_secs(2), "{scan:?}");
        // A closer past the longest token is not read as one.
        let far = format!("⟦{}_0A1B2C3D4E5F⟧", "K".repeat(MAX_SESSION_TOKEN_BYTES));
        assert_eq!(session_token_len(&far), None);
        assert!(session_token_len("⟦EMAIL_0A1B2C3D4E5F⟧ rest").is_some());
    }

    #[test]
    fn only_standalone_known_issued_tokens_are_kept() {
        let token = "EMAIL_0A1B2C3D4E5F";
        let issued: Arc<BTreeSet<String>> = Arc::new([token.to_string()].into());
        let malformed_contexts = [
            format!("⟦X⟦{token}⟧Y⟧"),
            format!("&#10214;X ⟦{token}⟧Y&#10215;"),
        ];
        for text in malformed_contexts {
            assert!(
                token_ranges(&text, &issued).is_empty(),
                "nested or encoded marker was treated as issued: {text:?}"
            );
        }

        let unknown: Arc<BTreeSet<String>> = Arc::new(["UNKNOWN_0A1B2C3D4E5F".to_string()].into());
        assert!(
            token_ranges("⟦UNKNOWN_0A1B2C3D4E5F⟧", &unknown).is_empty(),
            "an unknown label is not a kernel token"
        );
        let standalone = token_ranges(&format!("⟦{token}⟧"), &issued);
        assert_eq!(standalone.len(), 1);
    }

    #[test]
    fn many_mixed_issued_markers_are_scanned_within_a_linear_bound() {
        const TARGET_BYTES: usize = 1024 * 1024;
        let token = "EMAIL_0A1B2C3D4E5F";
        let issued_marker = format!("⟦{token}⟧");
        let unknown_marker = "⟦EMAIL_FFFFFFFFFFFF⟧";
        let nested_marker = format!("⟦X{issued_marker}Y⟧");
        let mut text = String::with_capacity(TARGET_BYTES);
        let mut expected = 0;
        while text.len() < TARGET_BYTES {
            for _ in 0..16 {
                text.push_str(&issued_marker);
                text.push(' ');
                expected += 1;
            }
            text.push_str(unknown_marker);
            text.push(' ');
            text.push_str(&nested_marker);
            text.push(' ');
        }
        let issued: BTreeSet<String> = [token.to_string()].into();

        let started = std::time::Instant::now();
        let ranges = token_ranges(&text, &issued);
        let elapsed = started.elapsed();

        assert_eq!(
            ranges.len(),
            expected,
            "only standalone issued markers pass"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "1 MiB with {expected} issued markers took {elapsed:?}"
        );
    }

    #[test]
    fn standalone_issued_tokens_still_rehydrate() {
        let key = format!("sk-proj-{}", "Ab9cD2eF7gH4iJ1kL8mN5pQ3rS6tU0vW9xY2zA4b");
        let mut anonymizer = Anonymizer::new(KEY);
        let span = Span::new(EntityKind::Secret, 0, key.len(), 1.0, "test");
        let (issued, pairs) = anonymizer.anonymize(&key, &[span]);
        let token = issued
            .strip_prefix(PLACEHOLDER_OPEN)
            .and_then(|body| body.strip_suffix(PLACEHOLDER_CLOSE))
            .expect("one token marker")
            .to_string();
        let mut gate =
            Gate::for_session_tokens(&grant(PrivacyMode::Private), Arc::new([token].into()))
                .unwrap();
        let (safe, _) = gate.text(&issued).unwrap();
        assert_eq!(safe.as_str(), issued);
        assert_eq!(
            Anonymizer::restore(safe.as_str(), &pairs, crate::anonymize::UnknownPolicy::Keep).text,
            key
        );
    }

    #[test]
    fn a_forged_token_cannot_split_an_email_out_of_detection() {
        let wire = session_gate_wire("mara@⟦EMAIL_0123456789AB⟧example.test");
        assert!(!wire.contains("mara@"), "{wire}");
        assert!(!wire.contains("example.test"), "{wire}");
        // Deleting the forged token must not give the server the address.
        let stripped = wire.replace("⟦EMAIL_0123456789AB⟧", "");
        assert!(!stripped.contains("mara@example.test"), "{stripped}");
    }

    #[test]
    fn a_forged_token_next_to_an_iban_does_not_hide_it() {
        let wire = session_gate_wire("⟦IBAN_0123456789AB⟧FR7630006000011234567890189");
        assert!(!wire.contains("FR7630006000011234567890189"), "{wire}");
        let wire = session_gate_wire("FR76300060⟦IBAN_0123456789AB⟧00011234567890189");
        assert!(!wire.contains("00011234567890189"), "{wire}");
        assert!(!wire.contains("FR76300060"), "{wire}");
    }

    #[test]
    fn a_real_session_token_beside_a_raw_value_stays_and_the_value_is_masked() {
        let wire = session_gate_wire("⟦PERSON_0A1B2C3D4E5F⟧mara@example.test");
        assert!(wire.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{wire}");
        assert!(!wire.contains("mara@example.test"), "{wire}");
        let wire = session_gate_wire("mara@example.test⟦PERSON_0A1B2C3D4E5F⟧");
        assert!(wire.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{wire}");
        assert!(!wire.contains("mara@example.test"), "{wire}");
    }

    #[test]
    fn look_alike_brackets_are_not_tokens() {
        for (open, close) in [("〚", "〛"), ("［", "］"), ("❬", "❭"), ("⟦\u{200B}", "⟧")]
        {
            let token = format!("{open}PERSON_0A1B2C3D4E5F{close}");
            let wire = session_gate_wire(&format!("{token}mara@example.test"));
            assert!(!wire.contains("mara@"), "{token}: {wire}");
            let wire = session_gate_wire(&format!("{token}FR7630006000011234567890189"));
            assert!(
                !wire.contains("FR7630006000011234567890189"),
                "{token}: {wire}"
            );
        }
        // A token spelled with look-alike brackets is not the session's: the
        // text around it is masked exactly as if it were absent.
        let wire = session_gate_wire("〚PERSON_0A1B2C3D4E5F〛");
        assert!(!wire.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{wire}");
    }

    #[test]
    fn a_token_the_session_never_minted_is_masked_like_text() {
        let wire = session_gate_wire("⟦EMAIL_FFFFFFFFFFFF⟧ and ⟦EMAIL_0A1B2C3D4E5F⟧");
        assert!(wire.contains(" ⟦EMAIL_0A1B2C3D4E5F⟧"), "{wire}");
        // Plain text: its opener is escaped, as for any typed `⟦`.
        assert!(wire.contains("⟦⟦EMAIL_FFFFFFFFFFFF⟧"), "{wire}");
        // An escaped opener is a literal one, never a token.
        let wire = session_gate_wire("⟦⟦EMAIL_0A1B2C3D4E5F⟧");
        assert!(wire.contains("⟦⟦⟦⟦EMAIL_0A1B2C3D4E5F⟧"), "{wire}");
    }

    #[test]
    fn foreign_token_text_is_scanned_but_minted_tokens_are_kept() {
        // `AB12…` has an IBAN anchor. A foreign marker is plain text and can
        // be masked; only a marker in this session's issued set stays opaque.
        let mut private = Gate::for_grant(&grant(PrivacyMode::Private), KEY);
        let mut open = Gate::for_passthrough(&grant(PrivacyMode::Open)).unwrap();
        for token in ["PERSON_AB12CDEFABCD", "PERSON_AB12CDEFABCD_2"] {
            for text in [
                format!("find mail from ⟦{token}⟧"),
                format!("find mail from ⟦⟦{token}⟧"),
            ] {
                let wire = session_gate_wire(&text);
                let (plain, _) = private.text(&text).unwrap();
                let (shown, _) = open.text(&text).unwrap();
                for out in [wire.as_str(), plain.as_str(), shown.as_str()] {
                    assert!(!out.contains(token), "foreign marker escaped: {out}");
                }
            }
        }
        let issued = session_gate_wire("find mail from ⟦PERSON_0A1B2C3D4E5F⟧");
        assert!(issued.contains("⟦PERSON_0A1B2C3D4E5F⟧"), "{issued}");
        assert!(!issued.contains("IBAN"), "{issued}");
        // A value a foreign token splits is still read whole.
        let (plain, _) = private
            .text("FR76300060⟦IBAN_0123456789AB⟧00011234567890189")
            .unwrap();
        assert!(
            !plain.as_str().contains("00011234567890189"),
            "{}",
            plain.as_str()
        );
    }

    #[test]
    fn a_card_or_id_hidden_in_a_fake_token_suffix_is_still_masked() {
        let mut private = Gate::for_grant(&grant(PrivacyMode::Private), KEY);
        for text in [
            "pay with ⟦CARD_AAAAAAAAAAAA_4111111111111111⟧ now",
            "pay with ⟦⟦CARD_AAAAAAAAAAAA_4111111111111111⟧ now",
            "iban ⟦PERSON_AB12CDEFABCD_FR7630006000011234567890189⟧ ok",
        ] {
            let (plain, _) = private.text(text).unwrap();
            assert!(
                !plain.as_str().contains("4111111111111111"),
                "{}",
                plain.as_str()
            );
            assert!(
                !plain.as_str().contains("30006000011234567890189"),
                "{}",
                plain.as_str()
            );
        }
    }

    #[test]
    fn a_span_that_touches_a_real_token_masks_the_token_whole() {
        let wire = session_gate_wire("mara@⟦EMAIL_0A1B2C3D4E5F⟧example.test");
        assert!(!wire.contains("EMAIL_0A1B2C3D4E5F"), "{wire}");
        assert!(!wire.contains("example.test"), "{wire}");
    }

    #[test]
    fn a_passthrough_grant_cannot_build_a_session_token_gate() {
        assert!(Gate::for_session_tokens(&grant(PrivacyMode::Open), minted()).is_err());
    }

    #[test]
    fn values_mask_every_string_leaf_and_keep_scalars() {
        let mut gate = masking_gate();
        let input = serde_json::json!({
            "to": "elise.vautrin@example.invalid",
            "count": 3,
            "tags": ["plain", true, null]
        });
        let (safe, _) = gate.value(&input).unwrap();
        let wire = serde_json::to_string(&safe).unwrap();
        assert!(!wire.contains("elise.vautrin"));
        assert!(wire.contains("\"count\":3"));
        assert!(wire.contains("\"plain\""));
        assert!(wire.contains("true"));
    }

    #[test]
    fn overlapping_and_adjacent_secret_spans_merge_into_one_removal() {
        let text = "abcdefghij";
        let spans = [
            Span::new(EntityKind::Secret, 0, 4, 1.0, "t"),
            Span::new(EntityKind::Secret, 4, 7, 1.0, "t"),
            Span::new(EntityKind::Secret, 6, 10, 1.0, "t"),
        ];
        assert_eq!(remove_prohibited(text, &spans), SECRET_REMOVED);
        // Only a prohibited class is replaced: another kind's span leaves the
        // text alone.
        let email = [Span::new(EntityKind::Email, 0, 4, 1.0, "t")];
        assert_eq!(remove_prohibited(text, &email), text);
        // Overlapping spans of two classes become one range, marked by the
        // higher-priority kind.
        let mixed = [
            Span::new(EntityKind::Health, 0, 6, 1.0, "t"),
            Span::new(EntityKind::Secret, 4, 10, 1.0, "t"),
        ];
        assert_eq!(remove_prohibited(text, &mixed), SECRET_REMOVED);
        let ids = [
            Span::new(EntityKind::Iban, 0, 3, 1.0, "t"),
            Span::new(EntityKind::Person, 3, 6, 1.0, "t"),
        ];
        assert_eq!(remove_prohibited(text, &ids), "[iban removed]defghij");
        // An IBAN-shaped guess inside a 64-hex digest stays; a checksum-valid
        // IBAN score or a short token does not.
        let digest = "sha 16e07db253f23a282d673668bd4b4656bf1f410962612fa4c7b4ddd87d893d77";
        let at = digest.find("db25").unwrap();
        let guess = [Span::new(EntityKind::Iban, at, at + 28, 0.55, "t")];
        assert_eq!(remove_prohibited(digest, &guess), digest);
        let valid = [Span::new(EntityKind::Iban, at, at + 28, 1.0, "t")];
        assert_ne!(remove_prohibited(digest, &valid), digest);
        let short = "ref ab12cd34ef56";
        let guess = [Span::new(EntityKind::Iban, 4, 16, 0.55, "t")];
        assert_ne!(remove_prohibited(short, &guess), short);
    }

    #[test]
    fn a_removal_marker_exists_for_exactly_the_prohibited_kinds() {
        for kind in EntityKind::ALL {
            // A date of birth is prohibited only as a labelled span.
            let labelled = kind == EntityKind::DateOfBirth;
            assert_eq!(
                removal_text(kind).is_some(),
                kind.is_prohibited() || labelled
            );
        }
    }

    #[test]
    fn a_typed_placeholder_look_alike_is_masked_as_clear_text() {
        let mut gate = masking_gate();
        let (safe, _) = gate.text("tel ⟦EMAIL_abcdef⟧ fin").unwrap();
        assert_eq!(safe.as_str(), "tel ⟦⟦EMAIL_abcdef⟧ fin");
    }

    #[test]
    fn safe_text_serializes_as_a_plain_string() {
        let mut gate = passthrough_gate();
        let (safe, _) = gate.text("salut").unwrap();
        assert_eq!(serde_json::to_string(&safe).unwrap(), "\"salut\"");
    }

    /// The full name every name test uses. The deterministic recognisers do not
    /// find it in running prose.
    const NAME: &str = "Mara Ellison";

    /// Stands in for a name detector (GLiNER): it finds the full name and says
    /// so through `checks_names`.
    struct NameAware;

    impl Detector for NameAware {
        fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            Ok(text
                .find(NAME)
                .map(|start| {
                    vec![Span::new(
                        EntityKind::Person,
                        start,
                        start + NAME.len(),
                        0.9,
                        "name",
                    )]
                })
                .unwrap_or_default())
        }

        fn checks_names(&self) -> bool {
            true
        }
    }

    #[test]
    fn a_full_name_is_masked_when_a_name_detector_runs() {
        let mut gate = tokenising_gate(KEY, Arc::new(NameAware));
        let (safe, report) = gate.text("Le dossier de Mara Ellison est prêt.").unwrap();
        assert!(!safe.as_str().contains(NAME));
        assert!(safe.as_str().contains("⟦PERSON_"));
        assert!(safe.names_checked());
        assert_eq!(report.count(EntityKind::Person), 1);
        assert!(!report.to_string().contains(NAME));
    }

    #[test]
    fn an_open_gate_without_a_name_detector_marks_names_unchecked() {
        let (safe, _) = passthrough_gate_without_names()
            .text("Le dossier est prêt.")
            .unwrap();
        assert!(!safe.names_checked());
    }

    #[test]
    fn a_private_gate_with_no_name_coverage_still_masks_pattern_values() {
        // A detector that does not check names: the private gate tokenises
        // what it finds and issues the text marked names-not-checked; it does
        // not refuse (owner, 2026-10-14).
        let mut gate =
            Gate::for_tests(&grant(PrivacyMode::Private), KEY, Arc::new(Registry::new()));
        let text = "Écris à camille@exemple.fr, IBAN FR7630006000011234567890189.";
        let (safe, _) = gate.text(text).unwrap();
        assert!(!safe.names_checked());
        assert!(
            !safe.as_str().contains("camille@exemple.fr"),
            "{}",
            safe.as_str()
        );
        assert!(
            !safe.as_str().contains("FR7630006000011234567890189"),
            "{}",
            safe.as_str()
        );
        let (value, _) = gate.value(&serde_json::json!({ "to": text })).unwrap();
        assert!(!value.names_checked());
        assert!(!value.as_value().to_string().contains("camille@exemple.fr"));
    }

    #[test]
    fn the_deep_stack_deterministic_half_includes_the_dictionary() {
        // `NameStack` (Deep) builds its deterministic half with
        // `standard_builder`; this pins that the dictionary is in it, so Deep
        // never detects less than Standard.
        let registry = standard_builder(["Mara Ellison"])
            .expect("dictionary")
            .0
            .without_email_layer()
            .build();
        let text = "Le dossier de Mara Ellison est prêt.";
        let found = registry.analyze(text);
        assert!(found
            .iter()
            .any(|span| span.kind == EntityKind::Person && &text[span.start..span.end] == NAME));
    }

    #[test]
    fn a_private_default_gate_without_a_dictionary_issues_and_masks_patterns() {
        // The default Standard detector mounts no dictionary: names are not
        // checked, but a phone number is still tokenised and the text issued.
        let mut gate = Gate::for_grant(&grant(PrivacyMode::Private), KEY);
        let text = "Le dossier de Mara Ellison est prêt, rappelle au +33612345678.";
        let (safe, _) = gate.text(text).unwrap();
        assert!(!safe.names_checked());
        assert!(!safe.as_str().contains("+33612345678"), "{}", safe.as_str());
        assert!(safe.as_str().contains('⟦'), "{}", safe.as_str());
    }

    /// NAMES-OFF (owner, 2026-10-19): a known name passes; the phone does not.
    #[test]
    fn a_private_standard_gate_keeps_a_known_name_and_masks_a_phone() {
        let mut gate =
            Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Mara Ellison"])
                .expect("dictionary");
        let text = "Le dossier de Mara Ellison est prêt, rappelle au +33612345678.";
        let (safe, _) = gate.text(text).unwrap();
        assert!(safe.as_str().contains(NAME), "{}", safe.as_str());
        assert!(!safe.as_str().contains("⟦PERSON_"), "{}", safe.as_str());
        assert!(!safe.as_str().contains("+33612345678"), "{}", safe.as_str());
    }

    /// TOK-CONSISTENT-1 F3: never `Mira Fictive's's` on screen.
    #[test]
    fn a_possessive_keeps_the_token_of_the_bare_name() {
        let names = ["Mira Fictive"];
        let mut gate =
            Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, names).unwrap();
        let bare = gate.text("Mira Fictive").unwrap().0.as_str().to_string();
        for apostrophe in ['\'', '’'] {
            let (safe, _) = gate
                .text(&format!("Show Mira Fictive{apostrophe}s card."))
                .unwrap();
            assert_eq!(safe.as_str(), format!("Show {bare}{apostrophe}s card."));
        }
    }

    #[test]
    fn a_private_gate_keeps_a_hyphenated_name_whole() {
        let mut gate = Gate::for_grant_with_names(&grant(PrivacyMode::Private), KEY, ["Vosloo"])
            .expect("dictionary");
        let text = "Hi Smit-Vosloo, thanks for the file.";
        assert_eq!(gate.text(text).unwrap().0.as_str(), text);
    }

    #[test]
    fn a_private_gate_with_a_name_detector_masks_the_name() {
        let mut gate = tokenising_gate(KEY, Arc::new(NameAware));
        let (safe, _) = gate.text("Le dossier de Mara Ellison est prêt.").unwrap();
        assert!(!safe.as_str().contains(NAME));
        assert!(safe.names_checked());
    }

    #[test]
    fn a_value_is_marked_like_its_gate() {
        let mut gate = tokenising_gate(KEY, Arc::new(NameAware));
        let (safe, _) = gate
            .value(&serde_json::json!({ "to": "Mara Ellison" }))
            .unwrap();
        assert!(safe.names_checked());
        let wire = serde_json::to_string(&safe).unwrap();
        assert!(!wire.contains(NAME));
    }

    #[test]
    fn a_name_that_only_the_context_suggests_does_not_refuse_the_text() {
        // The e-mail layer reads "a name" after a comma as a person, but that
        // cue depends on the words around it, which masking changes. The residue
        // scan reads values only, so the text is issued, not withheld.
        let text = "- `read_file` (risk: low): Find places matching a name, from Open-Meteo.";
        assert!(masking_gate().text(text).is_ok());
        assert!(Registry::new()
            .analyze_values(text)
            .iter()
            .all(|span| span.kind != EntityKind::Person));
    }

    #[test]
    fn a_joined_text_is_as_covered_as_its_least_covered_part() {
        // The former literal path is the closed `KernelMarker` enum now: the
        // app-authored part is a fixed kernel constant, not a token a caller
        // writes.
        let app = SafeText::from_marker(KernelMarker::RefusalPlaceholder);
        assert_eq!(app.as_str(), "[auxesis: withheld]");
        assert!(app.names_checked());
        let open = passthrough_gate_without_names().text("Bonjour").unwrap().0;
        assert!(SafeText::join([app.clone(), app.clone()]).names_checked());
        assert!(!SafeText::join([app.clone(), open]).names_checked());
        assert_eq!(
            SafeText::join([app.clone(), app]).as_str(),
            "[auxesis: withheld][auxesis: withheld]"
        );
    }

    #[test]
    fn a_gated_text_and_a_fixed_marker_join_without_a_literal_path() {
        // The former `safe_text_literal!("# Tools\n\n")` caller takes the
        // grant-bound path; a fixed marker comes from the closed enum.
        let (head, _) = passthrough_gate().text("# Tools\n\n").unwrap();
        let marker = SafeText::from_marker(KernelMarker::RefusalPlaceholder);
        assert_eq!(
            SafeText::join([head, marker]).as_str(),
            "# Tools\n\n[auxesis: withheld]"
        );
    }

    #[test]
    fn minted_pairs_are_handed_out_once_and_match_the_masked_text() {
        let mut gate = masking_gate();
        let (safe, _) = gate
            .text("écrire à anne.dupont@example.org demain")
            .unwrap();
        let minted = gate.take_minted();
        assert_eq!(minted.len(), 1, "one distinct value, one pair");
        let (token, value) = &minted[0];
        assert_eq!(value, "anne.dupont@example.org");
        assert!(token.starts_with("EMAIL_"));
        assert!(safe
            .as_str()
            .contains(&format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}")));
        assert!(gate.take_minted().is_empty(), "taking forgets the pairs");
    }
}

#[cfg(test)]
mod stand_in_tests {
    use super::*;

    #[test]
    fn a_typed_stand_in_is_not_read_as_a_masked_token() {
        // Only a placeholder becomes the stand-in. A U+E000 in the input keeps a
        // different character, so the rescan reads it as text, not as a token.
        assert_eq!(clear_parts("a\u{E000}b"), "a\u{FFFD}b");
        // A stand-in ends its line in the clear text.
        assert_eq!(
            clear_parts("a⟦SECRET_1⟧b"),
            format!("a{MASKED_STAND_IN}\nb")
        );
    }
}

#[cfg(test)]
mod second_pass_tests {
    use super::*;
    use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
    #[cfg(feature = "ner-gliner")]
    const KEY: [u8; 32] = [9; 32];

    const TEXT: &str = "Please call Camille Exemple at Exemple Conseil SARL";

    fn private_grant() -> Grant {
        let ctx = Context {
            destination: Destination::Vendor("hosted-model".to_string()),
        };
        match admit(PathId::A1, PrivacyMode::Private, &ctx) {
            Decision::Allow(grant) => grant,
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[cfg(feature = "ner-gliner")]
    fn grant(mode: PrivacyMode) -> Grant {
        let ctx = Context {
            destination: Destination::Vendor("hosted-model".to_string()),
        };
        match admit(PathId::A1, mode, &ctx) {
            Decision::Allow(grant) => grant,
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    /// Finds each needle as a span of the given kind, like a model would.
    struct Finds(Vec<(&'static str, EntityKind)>);

    impl NameSpotter for Finds {
        fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            Ok(self
                .0
                .iter()
                .filter_map(|(needle, kind)| {
                    let start = text.find(needle)?;
                    Some(Span::new(*kind, start, start + needle.len(), 0.9, "fake"))
                })
                .collect())
        }
    }

    struct Fails;

    impl NameSpotter for Fails {
        fn spot(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
            Err(DetectError::Names)
        }
    }

    struct Panics;

    impl NameSpotter for Panics {
        fn spot(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
            panic!("the model blew up");
        }
    }

    fn gate_with(spotter: impl NameSpotter + 'static) -> Gate {
        let detector = TwoPassDetector::new(Arc::new(StandardDetector::new()), Arc::new(spotter));
        Gate::for_tests(&private_grant(), [9u8; 32], Arc::new(detector))
    }

    #[test]
    fn mask_consolidation_keeps_pre_250_ordinary_overlaps() {
        let cases = [
            vec![
                Span::new(EntityKind::Person, 0, 12, 0.9, "fake"),
                Span::new(EntityKind::Health, 5, 12, 0.95, "fake"),
            ],
            vec![
                Span::new(EntityKind::Person, 0, 12, 0.9, "fake"),
                Span::new(EntityKind::Organization, 5, 14, 0.9, "fake"),
            ],
            vec![
                Span::new(EntityKind::Person, 0, 20, 0.8, "fake"),
                Span::new(EntityKind::Address, 4, 16, 0.9, "fake"),
                Span::new(EntityKind::Organization, 7, 12, 0.7, "fake"),
            ],
            vec![
                Span::new(EntityKind::Person, 0, 8, 0.9, "fake"),
                Span::new(EntityKind::Organization, 0, 8, 0.9, "fake"),
            ],
        ];
        for spans in cases {
            let expected: Vec<_> = resolve_overlaps(spans.clone())
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            let actual: Vec<_> = consolidate_mask_spans(spans)
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            assert_eq!(actual, expected);
        }

        for input in 0..2_000 {
            let shift = input % 7;
            let score = [0.6, 0.7, 0.8, 0.9][input % 4];
            let spans = vec![
                Span::new(EntityKind::Person, shift, shift + 12, score, "fake-deep"),
                Span::new(
                    EntityKind::Organization,
                    shift + input % 3,
                    shift + 10,
                    score,
                    "fake-deep",
                ),
                Span::new(
                    EntityKind::Address,
                    shift + 4,
                    shift + 15,
                    0.85,
                    "fake-deep",
                ),
                Span::new(EntityKind::Health, shift + 2, shift + 13, 0.95, "fake-deep"),
                Span::new(
                    EntityKind::NationalId,
                    shift + 8,
                    shift + 11,
                    0.95,
                    "fake-deep",
                ),
            ];
            let expected: Vec<_> = resolve_overlaps(spans.clone())
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            let actual: Vec<_> = consolidate_mask_spans(spans)
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            assert_eq!(actual, expected, "fake-Deep input {input}");
        }
    }

    fn rehydrate(masked: &str, minted: &[(String, String)]) -> String {
        minted
            .iter()
            .fold(masked.to_string(), |text, (token, value)| {
                text.replace(
                    &format!("{PLACEHOLDER_OPEN}{token}{PLACEHOLDER_CLOSE}"),
                    value,
                )
            })
    }

    #[test]
    fn spotted_names_are_tokenised_and_rehydrate_exactly() {
        let mut gate = gate_with(Finds(vec![
            ("Camille Exemple", EntityKind::Person),
            ("Exemple Conseil SARL", EntityKind::Organization),
        ]));
        let (safe, report) = gate.text(TEXT).unwrap();
        assert!(!safe.as_str().contains("Camille"), "{}", safe.as_str());
        assert!(!safe.as_str().contains("Conseil"), "{}", safe.as_str());
        assert_eq!(report.count(EntityKind::Person), 1);
        assert_eq!(report.count(EntityKind::Organization), 1);
        assert!(safe.names_checked());
        assert_eq!(rehydrate(safe.as_str(), &gate.take_minted()), TEXT);
    }

    #[test]
    fn a_function_word_the_model_calls_a_name_stays_in_clear() {
        // TOK-FP: at its low name floor the model tagged "Who" in "Who wrote to
        // me last?" as a person, so the question reached the agents broken.
        let words = ["Who", "What", "You", "When", "Can", "May", "Will", "June"];
        let found = words.iter().map(|word| (*word, EntityKind::Person));
        let mut gate = gate_with(Finds(
            found.chain([("May Smith", EntityKind::Person)]).collect(),
        ));
        for text in [
            "Who wrote to me last?",
            "What is on today?",
            "You there?",
            "When can I call? Will June work?",
        ] {
            let (safe, report) = gate.text(text).unwrap();
            assert_eq!(safe.as_str(), text, "{report}");
        }
        let (safe, _) = gate.text("Ask May Smith").unwrap();
        assert!(!safe.as_str().contains("Smith"), "{}", safe.as_str());
    }

    #[test]
    fn a_word_name_stays_a_name_where_context_says_so() {
        let words = ["Can", "May", "Will", "June"];
        let mut gate = gate_with(Finds(
            words
                .iter()
                .map(|word| (*word, EntityKind::Person))
                .collect(),
        ));
        for (text, name) in [
            ("June Carter called", "June"),
            ("Hi June, see you soon", "June"),
            ("Thanks for that.\n— Will", "Will"),
            ("Dear May,", "May"),
        ] {
            let (safe, _) = gate.text(text).unwrap();
            assert!(!safe.as_str().contains(name), "{}", safe.as_str());
        }
    }

    #[test]
    fn no_text_after_a_match_is_ever_removed() {
        let path = "/tmp/zq/plokij415_5uhyt7gtr13svxm0000gn/T/tmp.mTRfRr6UCj";
        let text = format!("workspace {path}\nProposed command: ls {path} now");
        let mut gate = gate_with(Finds(Vec::new()));
        assert_eq!(gate.text(&text).unwrap().0.as_str(), text);
        let (safe, _) = gate
            .text("IBAN FR76 3000 6000 0112 3456 7890 189 Proposed command")
            .unwrap();
        let rest = safe.as_str().split_once('⟧').map(|(_, rest)| rest);
        assert_eq!(rest, Some(" Proposed command"), "{}", safe.as_str());
    }

    #[test]
    fn a_failing_or_panicking_second_pass_falls_back_to_pass_one() {
        let text = "Call +33612345678 and ask for Camille Exemple";
        let mut gates = [gate_with(Fails), gate_with(Panics)];
        for gate in &mut gates {
            let (safe, _) = gate.text(text).expect("the turn is never blocked");
            assert!(!safe.as_str().contains("+33612345678"));
            assert!(safe.as_str().contains("Camille Exemple"), "pass 1 only");
            assert!(!safe.names_checked(), "names were not covered");
        }
    }

    #[test]
    fn pass_one_wins_overlaps_and_the_second_pass_adds_only_names() {
        let mut gate = gate_with(Finds(vec![
            ("camille@exemple.fr", EntityKind::Person),
            ("Please", EntityKind::Phone),
        ]));
        let (safe, report) = gate.text("Please write camille@exemple.fr").unwrap();
        assert_eq!(report.count(EntityKind::Email), 1);
        assert_eq!(report.count(EntityKind::Person), 0);
        assert_eq!(report.count(EntityKind::Phone), 0);
        assert!(safe.as_str().contains("Please"));
    }

    #[test]
    fn an_absent_model_mounts_no_second_pass() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!install_local_name_model(dir.path(), dir.path()));
        assert!(!name_spotter_installed());
        let mut gate = Gate::for_grant(&private_grant(), [9u8; 32]);
        let (safe, _) = gate.text("Call +33612345678 now").unwrap();
        assert!(!safe.as_str().contains("+33612345678"));
        assert!(!safe.names_checked());
    }

    /// Sleeps on its first text only, then answers at once.
    struct Slow(std::time::Duration, std::sync::atomic::AtomicBool);

    impl NameSpotter for Slow {
        fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            if !self.1.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(self.0);
            }
            Finds(vec![("Camille Exemple", EntityKind::Person)]).spot(text)
        }
    }

    fn bounded(inner: impl NameSpotter + 'static, max: usize, ms: u64) -> Arc<BoundedSpotter> {
        Arc::new(BoundedSpotter::new(
            Arc::new(inner),
            max,
            std::time::Duration::from_millis(ms),
        ))
    }

    struct Shared(Arc<BoundedSpotter>);

    impl NameSpotter for Shared {
        fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            self.0.spot(text)
        }
    }

    #[test]
    fn a_slow_second_pass_times_out_and_later_texts_skip_it_instead_of_queueing() {
        let text = "Call +33612345678 and ask for Camille Exemple";
        let slow = bounded(
            Slow(std::time::Duration::from_millis(700), false.into()),
            1024,
            100,
        );
        let mut gate = gate_with(Shared(Arc::clone(&slow)));
        let started = std::time::Instant::now();
        let (safe, _) = gate.text(text).expect("the turn is never blocked");
        assert!(started.elapsed() < std::time::Duration::from_millis(600));
        assert!(!safe.as_str().contains("+33612345678"));
        assert!(safe.as_str().contains("Camille Exemple"), "pass 1 only");
        assert!(!safe.names_checked());
        // The worker is still sleeping: the next text skips pass 2 at once.
        let started = std::time::Instant::now();
        let (safe, _) = gate.text(text).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_millis(300));
        assert!(!safe.names_checked());
        // Once the worker is free again the second pass answers.
        std::thread::sleep(std::time::Duration::from_millis(800));
        let spans = slow.spot(text).expect("the worker recovered");
        assert_eq!(spans.len(), 1);
    }

    #[test]
    fn an_oversize_text_never_reaches_the_second_pass() {
        let spotter = bounded(Finds(vec![("Camille", EntityKind::Person)]), 64, 2000);
        let mut gate = gate_with(Shared(spotter));
        let text = format!("Call +33612345678 for Camille Exemple {}", "x ".repeat(64));
        let (safe, _) = gate.text(&text).expect("the turn is never blocked");
        assert!(!safe.as_str().contains("+33612345678"));
        assert!(safe.as_str().contains("Camille Exemple"), "pass 1 only");
        assert!(!safe.names_checked());
    }

    #[test]
    fn a_text_under_the_cap_in_time_is_spotted_on_the_worker() {
        let spotter = bounded(
            Finds(vec![("Camille Exemple", EntityKind::Person)]),
            1024,
            2000,
        );
        let mut gate = gate_with(Shared(spotter));
        let (safe, _) = gate.text(TEXT).unwrap();
        assert!(!safe.as_str().contains("Camille"));
        assert!(safe.names_checked());
    }

    #[cfg(feature = "ner-gliner")]
    struct FixedDeep(Result<Vec<Span>, DetectError>);

    #[cfg(feature = "ner-gliner")]
    impl Detector for FixedDeep {
        fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
            self.0.clone()
        }
    }

    #[cfg(feature = "ner-gliner")]
    struct GeneratedDeep;

    #[cfg(feature = "ner-gliner")]
    impl Detector for GeneratedDeep {
        fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            let start = text.find("ordinarytag").ok_or(DetectError::Names)?;
            // Deliberately adversarial: a full health span, a short equal-score
            // ID at its start, and a non-prohibited label over the same bytes.
            Ok(vec![
                Span::new(EntityKind::Health, start, text.len(), 0.9, "fake"),
                Span::new(EntityKind::NationalId, start, start + 3, 0.9, "fake"),
                Span::new(EntityKind::Person, start, text.len(), 1.0, "fake"),
            ])
        }
    }

    #[cfg(feature = "ner-gliner")]
    struct BlockedDeep {
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        finished: std::sync::mpsc::SyncSender<()>,
    }

    #[cfg(feature = "ner-gliner")]
    static DEEP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(feature = "ner-gliner")]
    impl Detector for BlockedDeep {
        fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
            self.release
                .lock()
                .unwrap()
                .recv()
                .map_err(|_| DetectError::Names)?;
            let _ = self.finished.send(());
            Ok(Vec::new())
        }
    }

    #[cfg(feature = "ner-gliner")]
    fn deep_gate(mode: PrivacyMode, spans: Result<Vec<Span>, DetectError>) -> Gate {
        Gate::for_grant_with_deep_detector(
            &grant(mode),
            KEY,
            Arc::new(NameDictionary::new(std::iter::empty::<&str>()).expect("empty dictionary")),
            Arc::new(FixedDeep(spans)),
        )
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_adds_only_prohibited_tier_c_and_standard_wins_overlap() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let text = "Asterian health and +33612345678";
        let health = Span::new(EntityKind::Health, 16, 19, 1.0, "fake");
        let person = Span::new(EntityKind::Person, 0, 8, 1.0, "fake");
        let phone_overlap = Span::new(EntityKind::Secret, 22, text.len(), 1.0, "fake");
        let mut deep = deep_gate(PrivacyMode::Open, Ok(vec![health, person, phone_overlap]));
        let (safe, _) = deep.text(text).unwrap();
        assert!(safe.as_str().contains("[health removed]"));
        assert!(safe.as_str().contains("Asterian"));
        assert!(safe.as_str().contains("[secret removed]"));
        let mut names_only = deep_gate(
            PrivacyMode::Open,
            Ok(vec![Span::new(EntityKind::Person, 0, 8, 1.0, "fake")]),
        );
        assert_eq!(names_only.text("Asterian").unwrap().0.as_str(), "Asterian");
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_non_prohibited_overlaps_cannot_suppress_health_or_secret() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let text = "QZXHEALTHTOKEN / QZXSECRETTOKEN";
        let health = text.find("QZXHEALTHTOKEN").unwrap();
        let secret = text.find("QZXSECRETTOKEN").unwrap();
        let spans = vec![
            Span::new(EntityKind::Person, health, health + 14, 0.99, "fake"),
            Span::new(EntityKind::Health, health, health + 14, 0.6, "fake"),
            Span::new(EntityKind::Address, secret, secret + 14, 0.99, "fake"),
            Span::new(EntityKind::Secret, secret, secret + 14, 0.6, "fake"),
        ];
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let mut gate = deep_gate(mode, Ok(spans.clone()));
            let safe = gate.text(text).unwrap().0;
            assert!(!safe.as_str().contains("QZXHEALTHTOKEN"));
            assert!(!safe.as_str().contains("QZXSECRETTOKEN"));
        }
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_prohibited_overlaps_are_unioned_in_both_modes() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let text = "QZX health value and secret tail marker";
        let health = Span::new(EntityKind::Health, 0, 27, 0.9, "fake");
        let id = Span::new(EntityKind::NationalId, 0, 3, 0.9, "fake");
        let secret = Span::new(EntityKind::Secret, 20, 39, 0.8, "fake");
        let short_health = Span::new(EntityKind::Health, 24, 28, 0.8, "fake");
        let spans = vec![health, id, secret, short_health];
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let mut gate = deep_gate(mode, Ok(spans.clone()));
            let output = gate.text(text).unwrap().0;
            assert!(
                !output.as_str().contains("QZX health"),
                "{mode:?}: {}",
                output.as_str()
            );
            assert!(
                !output.as_str().contains("secret tail"),
                "{mode:?}: {}",
                output.as_str()
            );
        }
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_failure_and_empty_output_match_standard_and_private_tokens_repeat() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let text = "Ordinary prose; Asterian";
        let names = Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap());
        let mut standard =
            Gate::for_grant_with_dictionary(&grant(PrivacyMode::Private), KEY, Arc::clone(&names));
        let mut failed = deep_gate(PrivacyMode::Private, Err(DetectError::Names));
        let mut empty = deep_gate(PrivacyMode::Private, Ok(Vec::new()));
        let base = standard.text(text).unwrap().0.as_str().to_owned();
        assert_eq!(failed.text(text).unwrap().0.as_str(), base);
        assert_eq!(
            empty.text("No private values here.").unwrap().0.as_str(),
            "No private values here."
        );
        let health = Span::new(EntityKind::Health, 17, text.len(), 1.0, "fake");
        let mut deep = deep_gate(PrivacyMode::Private, Ok(vec![health]));
        let first = deep.text(text).unwrap().0.as_str().to_owned();
        let second = deep.text(text).unwrap().0.as_str().to_owned();
        assert_eq!(first, second);
        assert_ne!(first, base);
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_is_a_strict_superset_of_standard_on_generated_corpus() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for mode in [PrivacyMode::Private, PrivacyMode::Open] {
            let names = Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap());
            let mut standard =
                Gate::for_grant_with_dictionary(&grant(mode), KEY, Arc::clone(&names));
            let mut deep = Gate::for_grant_with_deep_detector(
                &grant(mode),
                KEY,
                names,
                Arc::new(GeneratedDeep),
            );
            for i in 0..2_000 {
                let email = format!("canary{i}@example.test");
                let text = format!("Asterian contact {email}; ordinarytag{i}");
                let base = standard.text(&text).expect("Standard issues text").0;
                let added = deep
                    .text(&text)
                    .expect("Deep fallback gate never refuses")
                    .0;
                assert!(base.as_str().contains("ordinarytag"));
                assert!(!added.as_str().contains("ordinarytag"));
                assert!(
                    added.as_str().contains("Asterian"),
                    "names never added in {mode:?}"
                );
                assert_eq!(
                    added.as_str().contains(&email),
                    base.as_str().contains(&email),
                    "Deep preserves Standard email handling in {mode:?}"
                );
            }
        }
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_timeout_returns_standard_output_byte_for_byte() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
        let detector = Arc::new(BlockedDeep {
            release: std::sync::Mutex::new(release_rx),
            finished: finished_tx,
        });
        let empty = || Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap());
        let mut deep = Gate::for_grant_with_deep_detector(
            &grant(PrivacyMode::Private),
            KEY,
            empty(),
            detector,
        );
        let mut standard =
            Gate::for_grant_with_dictionary(&grant(PrivacyMode::Private), KEY, empty());
        let text = "No private values in this sentence.";
        let expected = standard.text(text).unwrap().0.as_str().to_owned();
        assert_eq!(deep.text(text).unwrap().0.as_str(), expected);
        release_tx.send(()).unwrap();
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
    }

    #[cfg(feature = "ner-gliner")]
    struct SleepingDeep {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        delay: std::time::Duration,
    }

    #[cfg(feature = "ner-gliner")]
    impl Detector for SleepingDeep {
        fn detect(&self, _text: &str) -> Result<Vec<Span>, DetectError> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::thread::sleep(self.delay);
            Ok(Vec::new())
        }
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_deadline_covers_the_whole_text_operation_and_falls_back_to_standard() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut gate = Gate::for_grant_with_deep_detector(
            &grant(PrivacyMode::Private),
            KEY,
            Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap()),
            Arc::new(SleepingDeep {
                calls: Arc::clone(&calls),
                delay: std::time::Duration::from_secs(4),
            }),
        );
        let mut standard = Gate::for_grant_with_dictionary(
            &grant(PrivacyMode::Private),
            KEY,
            Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap()),
        );
        let text = "kept ⟦PERSON_AAAAAAAAAAAA⟧";
        let expected = standard.text(text).unwrap().0.as_str().to_owned();
        let start = std::time::Instant::now();
        let actual = gate.text(text).unwrap().0.as_str().to_owned();
        let elapsed = start.elapsed();
        eprintln!("4 s Deep operation: {elapsed:?}");
        assert!(elapsed <= std::time::Duration::from_millis(5_200));
        assert_eq!(actual, expected);
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[cfg(feature = "ner-gliner")]
    #[test]
    fn deep_detector_runs_once_for_plain_token_and_residue_paths() {
        let _serial = DEEP_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut gate = Gate::for_grant_with_deep_detector(
            &grant(PrivacyMode::Private),
            KEY,
            Arc::new(NameDictionary::new(std::iter::empty::<&str>()).unwrap()),
            Arc::new(SleepingDeep {
                calls: Arc::clone(&calls),
                delay: std::time::Duration::from_millis(1),
            }),
        );
        gate.text("A short ordinary sentence.").unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        gate.text("kept ⟦PERSON_AAAAAAAAAAAA⟧").unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 2);
        // Email masking enters the residue scan; that scan must stay on pass 1.
        gate.text("probe@example.test").unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 3);
    }
}
