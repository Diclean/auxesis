//! Local GLiNER2-PII NER recogniser, behind the `ner-gliner` feature.
//!
//! GLiNER2 is a zero-shot span tagger: the caller supplies the entity labels in
//! the prompt and the model returns byte spans and probabilities for them. It
//! is the span engine the deterministic [`crate::Registry`] cannot provide.
//! The runner is the reusable `gliner2-rs` crate (`crates/gliner2`); this
//! module maps its entities onto the kernel's [`EntityKind`]s, keeps the
//! fail-closed rules, and exposes the recogniser the registry and the gate
//! use.
//!
//! Properties the kernel relies on:
//!
//! * **No Python at runtime and no network.** The ONNX graph, the fast
//!   tokenizer and the ONNX Runtime dylib are local files under a
//!   user-configured directory; nothing is bundled in the repository.
//! * **Byte-accurate spans.** Every span is checked against the source bytes
//!   by the runner; a mismatch is dropped and counted, never guessed.
//! * **Long text is chunked, never truncated.** The runner splits a long text
//!   into overlapping token windows and shifts the spans back into the text.
//! * **Fail closed.** [`GlinerRecognizer::load`] and
//!   [`GlinerRecognizer::analyze_report`] return a [`GlinerError`] on a missing
//!   model, a bad tokenizer or an inference failure. Nothing returns "no
//!   entities" on error.
//!
//! The [`Recognizer`] trait cannot carry an error. Its adapter
//! ([`GlinerRecognizer::analyze`]) therefore fails toward masking: on error it
//! returns one span covering the whole text and records the error, which
//! [`GlinerRecognizer::take_error`] hands back to the caller. Code that can
//! propagate the failure should call [`GlinerRecognizer::analyze_report`].

use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use gliner2_rs::{Gliner2, Options};

use crate::recognizer::Recognizer;
use crate::safetext::{
    install_name_spotter, name_spotter_installed, BoundedSpotter, DetectError, NameSpotter,
};
use crate::span::{EntityKind, Span};

/// The GLiNER2-PII labels the runner sends, in the order of the exported graph's
/// fields. Native labels come first; `health condition` and `religion` are
/// zero-shot. The same list is in `scripts/gliner2-parity.py`.
pub const GLINER_PII_LABELS: [&str; 12] = [
    "person",
    "address",
    "phone_number",
    "email",
    "iban",
    "payment_card",
    "passport_number",
    "national_id_number",
    "date_of_birth",
    "organization",
    "health condition",
    "religion",
];

/// Default score floor for every label without its own entry in
/// [`LABEL_THRESHOLDS`]. An internal EN bench picked 0.5 for the native labels.
pub const DEFAULT_THRESHOLD: f32 = 0.5;

/// Score floor for the labels only the model can see: names, organisations and
/// addresses (NER-THRESH, 2026-10-14). Private mode tokenises and never
/// refuses, so an extra mask is cheap while a missed name leaks. On the EN
/// messy-email split, name recall rises from 0.85 to 0.91 (bare first names
/// 0.68 to 0.82) for a precision drop from 0.83 to 0.79; clean EN recall is
/// unchanged at 0.98. The pattern-backed labels keep the default.
pub const NAME_THRESHOLD: f32 = 0.15;

/// Per-label score floors. `health condition` is zero-shot and recalls its
/// five EN health spans at 0.3 to 0.4 (0.8 at 0.5), so it runs at 0.4.
pub const LABEL_THRESHOLDS: [(&str, f32); 4] = [
    ("person", NAME_THRESHOLD),
    ("organization", NAME_THRESHOLD),
    ("address", NAME_THRESHOLD),
    ("health condition", 0.4),
];

/// The graph's `max_width` (`config.json` of the checkpoint): spans run at most
/// this many words.
pub const DEFAULT_MAX_WIDTH: usize = 8;

/// Token window used for a long text (benchmark: 300 tokens).
pub const DEFAULT_CHUNK_TOKENS: usize = 300;

/// Token overlap between two windows (benchmark: 50 tokens).
pub const DEFAULT_CHUNK_OVERLAP: usize = 50;

/// Why a [`GlinerRecognizer`] could not load or could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlinerError {
    /// The configuration points at a directory or file that does not exist.
    MissingFile(String),
    /// The ONNX graph or its tokenizer could not be opened.
    Model(String),
    /// Tokenisation of a text failed.
    Tokenizer(String),
    /// The model ran but returned an error, or was given invalid input.
    Inference(String),
    /// A configuration value is invalid.
    Config(String),
}

impl fmt::Display for GlinerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlinerError::MissingFile(path) => write!(f, "gliner: missing file: {path}"),
            GlinerError::Model(message) => write!(f, "gliner: model error: {message}"),
            GlinerError::Tokenizer(message) => write!(f, "gliner: tokenizer error: {message}"),
            GlinerError::Inference(message) => write!(f, "gliner: inference error: {message}"),
            GlinerError::Config(message) => write!(f, "gliner: config error: {message}"),
        }
    }
}

impl std::error::Error for GlinerError {}

impl From<gliner2_rs::Error> for GlinerError {
    fn from(error: gliner2_rs::Error) -> Self {
        match error {
            gliner2_rs::Error::MissingFile(path) => {
                GlinerError::MissingFile(path.display().to_string())
            }
            gliner2_rs::Error::Model(message) => GlinerError::Model(message),
            gliner2_rs::Error::Tokenizer(message) => GlinerError::Tokenizer(message),
            gliner2_rs::Error::Inference(message) => GlinerError::Inference(message),
            gliner2_rs::Error::InvalidOptions(message) => GlinerError::Config(message),
        }
    }
}

/// Everything [`GlinerRecognizer::load`] needs.
#[derive(Clone, Debug)]
pub struct GlinerConfig {
    /// Directory holding the ONNX graphs and the fast tokenizer.
    pub model_dir: PathBuf,
    /// ONNX graph inside `model_dir` (fp32 `model.onnx` by default).
    pub onnx_file: String,
    /// Fast tokenizer inside `model_dir`.
    pub tokenizer_file: String,
    /// Score floor for labels without an entry in `label_thresholds`; default
    /// [`DEFAULT_THRESHOLD`].
    pub threshold: f32,
    /// Per-label score floors; default [`LABEL_THRESHOLDS`].
    pub label_thresholds: Vec<(&'static str, f32)>,
    /// Entity labels sent in the prompt; default [`GLINER_PII_LABELS`].
    pub labels: Vec<&'static str>,
    /// ONNX Runtime shared library. When set and `ORT_DYLIB_PATH` is unset, it
    /// is exported for the process before the first session is created.
    pub ort_dylib: Option<PathBuf>,
    /// Maximum span width in words (checkpoint value).
    pub max_width: usize,
    /// Token window for a long text.
    pub chunk_tokens: usize,
    /// Token overlap between two windows.
    pub chunk_overlap: usize,
}

impl GlinerConfig {
    /// A config for one exported model directory, with the GLiNER2-PII labels,
    /// the default thresholds and the window sizes of the benchmark.
    pub fn new(model_dir: impl Into<PathBuf>) -> Self {
        Self {
            model_dir: model_dir.into(),
            onnx_file: "model.onnx".to_string(),
            tokenizer_file: "tokenizer.json".to_string(),
            threshold: DEFAULT_THRESHOLD,
            label_thresholds: LABEL_THRESHOLDS.to_vec(),
            labels: GLINER_PII_LABELS.to_vec(),
            ort_dylib: None,
            max_width: DEFAULT_MAX_WIDTH,
            chunk_tokens: DEFAULT_CHUNK_TOKENS,
            chunk_overlap: DEFAULT_CHUNK_OVERLAP,
        }
    }

    /// Override the default score floor. Labels with their own entry in
    /// `label_thresholds` keep it.
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Use the int8 dynamic-quantised graph instead of the fp32 one.
    pub fn with_int8(mut self) -> Self {
        self.onnx_file = "model_int8.onnx".to_string();
        self
    }

    /// Point at the ONNX Runtime shared library.
    pub fn with_ort_dylib(mut self, path: impl Into<PathBuf>) -> Self {
        self.ort_dylib = Some(path.into());
        self
    }

    /// Replace the entity labels.
    pub fn with_labels(mut self, labels: Vec<&'static str>) -> Self {
        self.labels = labels;
        self
    }

    /// The score floor for one label: its own entry, else the default.
    pub fn threshold_for(&self, label: &str) -> f32 {
        self.label_thresholds
            .iter()
            .find(|(name, _)| *name == label)
            .map(|(_, threshold)| *threshold)
            .unwrap_or(self.threshold)
    }
}

/// Map a GLiNER2-PII label to the crate's [`EntityKind`].
///
/// `payment_card` is a card number, `passport_number` is masked as an
/// unverified passport, and `national_id_number` as the generic national
/// identifier (fail toward masking). An unknown label is ignored.
pub fn label_kind(label: &str) -> Option<EntityKind> {
    Some(match label {
        "person" => EntityKind::Person,
        "organization" => EntityKind::Organization,
        "address" => EntityKind::Address,
        "phone_number" => EntityKind::Phone,
        "email" => EntityKind::Email,
        "iban" => EntityKind::Iban,
        "payment_card" => EntityKind::CreditCard,
        "passport_number" => EntityKind::PassportMrz,
        "national_id_number" => EntityKind::NationalId,
        "date_of_birth" => EntityKind::DateOfBirth,
        "health condition" => EntityKind::Health,
        "religion" => EntityKind::Religion,
        _ => return None,
    })
}

/// What one [`GlinerRecognizer::analyze_report`] call produced.
#[derive(Clone, Debug, Default)]
pub struct GlinerReport {
    /// The model's spans, ordered by start offset and never overlapping.
    pub spans: Vec<Span>,
    /// Spans the model returned whose bytes did not match the source text.
    pub dropped: usize,
    /// Number of token windows the text was split into (`1` when it fit).
    pub chunks: usize,
}

/// A local GLiNER2-PII recogniser.
pub struct GlinerRecognizer {
    model: Gliner2,
    config: GlinerConfig,
    kinds: Vec<EntityKind>,
    failure: Mutex<Option<GlinerError>>,
}

impl GlinerRecognizer {
    /// Load the ONNX graph and the fast tokenizer from `config.model_dir`.
    ///
    /// A missing file, a bad graph or a bad tokenizer is a [`GlinerError`]; the
    /// recogniser is never built in a state that would answer "no entities".
    pub fn load(config: GlinerConfig) -> Result<Self, GlinerError> {
        if config.threshold <= 0.0 || config.threshold > 1.0 {
            return Err(GlinerError::Config(format!(
                "threshold {} is outside 0.0..=1.0",
                config.threshold
            )));
        }
        if config.labels.is_empty() {
            return Err(GlinerError::Config("no entity labels".to_string()));
        }

        let options = Options {
            label_thresholds: config
                .label_thresholds
                .iter()
                .map(|(label, threshold)| (label.to_string(), *threshold))
                .collect(),
            max_width: config.max_width,
            chunk_tokens: config.chunk_tokens,
            chunk_overlap: config.chunk_overlap,
            ort_dylib: config.ort_dylib.clone(),
        };
        let model = Gliner2::load_paths(
            config.model_dir.join(&config.onnx_file),
            config.model_dir.join(&config.tokenizer_file),
            &options,
        )?;

        let mut kinds: Vec<EntityKind> = Vec::new();
        for label in &config.labels {
            if let Some(kind) = label_kind(label) {
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
            }
        }

        Ok(Self {
            model,
            config,
            kinds,
            failure: Mutex::new(None),
        })
    }

    /// The configuration this recogniser was built with.
    pub fn config(&self) -> &GlinerConfig {
        &self.config
    }

    /// The error recorded by the infallible [`Recognizer::analyze`] adapter, if
    /// any, clearing it. `analyze_report` does not record anything.
    pub fn take_error(&self) -> Option<GlinerError> {
        self.failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    /// Run the model over `text`, chunking it when it does not fit one window.
    ///
    /// Returns the verified, non-overlapping spans plus the number of model
    /// spans dropped for not matching the source bytes. Any load, tokenisation
    /// or inference failure is a [`GlinerError`].
    pub fn analyze_report(&self, text: &str) -> Result<GlinerReport, GlinerError> {
        let labels: Vec<&str> = self.config.labels.clone();
        let extraction = self
            .model
            .extract_report(text, &labels, self.config.threshold)?;
        let spans: Vec<Span> = extraction
            .entities
            .into_iter()
            .filter_map(|entity| {
                let kind = label_kind(&entity.label)?;
                Some(Span::new(
                    kind,
                    entity.start,
                    entity.end,
                    entity.score,
                    "gliner",
                ))
            })
            .collect();
        Ok(GlinerReport {
            spans: consolidate(spans),
            dropped: extraction.dropped,
            chunks: extraction.chunks,
        })
    }

    /// [`Self::analyze_report`] with only the spans.
    pub fn recognize(&self, text: &str) -> Result<Vec<Span>, GlinerError> {
        Ok(self.analyze_report(text)?.spans)
    }
}

impl Recognizer for GlinerRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &self.kinds
    }

    /// The infallible trait adapter: fail toward masking.
    ///
    /// On any [`GlinerError`] this masks the whole text as one `NATIONAL_ID`
    /// span (which the registry then splits) and stores the error, retrievable
    /// with [`GlinerRecognizer::take_error`]. It never reports "no entities" on
    /// error. Prefer [`GlinerRecognizer::analyze_report`] where the error can
    /// be propagated.
    fn analyze(&self, text: &str) -> Vec<Span> {
        match self.analyze_report(text) {
            Ok(report) => report.spans,
            Err(error) => {
                *self
                    .failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
                vec![Span::new(
                    EntityKind::NationalId,
                    0,
                    text.len(),
                    1.0,
                    "gliner",
                )]
            }
        }
    }

    fn name(&self) -> &'static str {
        "gliner"
    }

    /// A model is not a checksum rule, but its scores are already calibrated
    /// probabilities, so the registry must not relabel every span it emits.
    fn verified(&self) -> bool {
        true
    }

    /// A model is opt-in: the default registry stays deterministic and offline.
    fn enabled_by_default(&self) -> bool {
        false
    }
}

/// As an egress-gate detector the model only adds prohibited kinds; names and
/// other ordinary labels stay with the registry and CRM callers of
/// [`GlinerRecognizer::recognize`], which need them.
impl crate::safetext::Detector for GlinerRecognizer {
    fn detect(&self, text: &str) -> Result<Vec<Span>, crate::safetext::DetectError> {
        self.recognize(text)
            .map(|spans| {
                spans
                    .into_iter()
                    .filter(|span| span.kind.is_prohibited())
                    .collect()
            })
            .map_err(|_| crate::safetext::DetectError::Names)
    }
}

/// The ONNX Runtime library the product looks for next to the model.
const LOCAL_ORT_DYLIB: &str = "libonnxruntime.dylib";

/// Longest text the second pass reads. Above it a text keeps pass 1 only.
pub const MAX_SPOT_BYTES: usize = 64 * 1024;

/// How long the second pass may take on one text before the gate moves on.
pub const SPOT_DEADLINE: Duration = Duration::from_secs(5);

/// Why the model directory is not mounted.
#[derive(Debug, PartialEq, Eq)]
enum Vetting {
    /// No model files: nothing to mount, checked again next time.
    Absent,
    /// Files exist but a path leaves the model directory, or is a symlink.
    Refused,
}

/// The config for the model under `model_dir`, only if every path stays inside
/// it and `model_dir` stays inside `root` (the home): no symlink at the
/// directory or at a file, each canonical path under its parent's canonical
/// path. `ORT_DYLIB_PATH` is honoured only when it resolves inside `model_dir`
/// (or in this crate's own tests); the dir's own dylib is used otherwise.
fn vet_model_dir(root: &Path, model_dir: &Path) -> Result<GlinerConfig, Vetting> {
    let regular = |path: &Path| {
        std::fs::symlink_metadata(path)
            .map(|meta| meta.is_file())
            .unwrap_or(false)
    };
    let onnx = ["model.onnx", "model_int8.onnx"]
        .into_iter()
        .find(|file| model_dir.join(file).symlink_metadata().is_ok());
    let (Some(onnx), true) = (
        onnx,
        model_dir.join("tokenizer.json").symlink_metadata().is_ok(),
    ) else {
        return Err(Vetting::Absent);
    };
    let dir_is_plain = std::fs::symlink_metadata(model_dir)
        .map(|meta| meta.is_dir())
        .unwrap_or(false);
    let (Ok(root), Ok(dir)) = (root.canonicalize(), model_dir.canonicalize()) else {
        return Err(Vetting::Refused);
    };
    if !dir_is_plain || !dir.starts_with(&root) {
        return Err(Vetting::Refused);
    }
    let inside = |path: &Path| {
        path.canonicalize()
            .is_ok_and(|real| real.parent() == Some(&dir))
    };
    for file in [onnx, "tokenizer.json"] {
        let path = model_dir.join(file);
        if !regular(&path) || !inside(&path) {
            return Err(Vetting::Refused);
        }
    }
    let mut config = GlinerConfig::new(model_dir);
    config.onnx_file = onnx.to_string();
    let dylib = model_dir.join(LOCAL_ORT_DYLIB);
    match std::env::var_os("ORT_DYLIB_PATH") {
        Some(env) => {
            let real = PathBuf::from(env).canonicalize().ok();
            let in_dir = real.as_ref().is_some_and(|real| real.starts_with(&dir));
            if !in_dir && !cfg!(test) {
                return Err(Vetting::Refused);
            }
        }
        None if regular(&dylib) && inside(&dylib) => config = config.with_ort_dylib(dylib),
        None => {}
    }
    Ok(config)
}

/// Load the validated local model for the egress gate. Returns `None` when
/// absent or refused; callers should log a single path-free info message.
pub fn load_vetted_local_model(root: &Path, model_dir: &Path) -> Option<GlinerRecognizer> {
    let config = vet_model_dir(root, model_dir).ok()?;
    panic::catch_unwind(AssertUnwindSafe(|| GlinerRecognizer::load(config)))
        .ok()?
        .ok()
}

/// The product's second pass: the GLiNER2 model under one local directory,
/// loaded once on first use and shared. A load or inference failure is one log
/// line (never the text) and a [`DetectError::Names`]: the gate then keeps its
/// pass-1 spans. The directory is vetted again at load time.
struct LocalGliner {
    root: PathBuf,
    model_dir: PathBuf,
    model: OnceLock<Option<GlinerRecognizer>>,
    inference_logged: AtomicBool,
}

impl LocalGliner {
    fn model(&self) -> Option<&GlinerRecognizer> {
        self.model
            .get_or_init(|| {
                let loaded = vet_model_dir(&self.root, &self.model_dir)
                    .ok()
                    .and_then(|config| {
                        panic::catch_unwind(AssertUnwindSafe(|| GlinerRecognizer::load(config)))
                            .ok()
                    });
                match loaded {
                    Some(Ok(model)) => Some(model),
                    _ => {
                        eprintln!("auxesis: private mode: the local name model did not load; names are checked by pass 1 only");
                        None
                    }
                }
            })
            .as_ref()
    }
}

impl NameSpotter for LocalGliner {
    fn spot(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let model = self.model().ok_or(DetectError::Names)?;
        match model.recognize(text) {
            Ok(spans) => Ok(spans),
            Err(_) => {
                if !self.inference_logged.swap(true, Ordering::Relaxed) {
                    eprintln!("auxesis: private mode: the local name model failed on a text; that text is checked by pass 1 only");
                }
                Err(DetectError::Names)
            }
        }
    }
}

/// Mount the second pass from `model_dir` (`model.onnx` or `model_int8.onnx`,
/// `tokenizer.json`, and `libonnxruntime.dylib` unless `ORT_DYLIB_PATH` points
/// inside it), which must stay inside `root` with no symlink on the way.
/// Nothing is loaded here and nothing is downloaded: the model loads on the
/// first tokenised text, on the bounded worker. Returns whether a second pass is
/// mounted. A directory without the model files, or one that fails the vetting,
/// mounts nothing and is checked again on the next call.
pub fn install_local_model(root: &Path, model_dir: &Path) -> bool {
    static ABSENT_LOGGED: AtomicBool = AtomicBool::new(false);
    static REFUSED_LOGGED: AtomicBool = AtomicBool::new(false);
    if name_spotter_installed() {
        return true;
    }
    match vet_model_dir(root, model_dir) {
        Ok(_) => {}
        Err(Vetting::Absent) => {
            if !ABSENT_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "auxesis: private mode: no local name model; names are checked by pass 1 only"
                );
            }
            return false;
        }
        Err(Vetting::Refused) => {
            if !REFUSED_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!("auxesis: private mode: the local name model path was refused (symlink or outside the home); names are checked by pass 1 only");
            }
            return false;
        }
    }
    let local = LocalGliner {
        root: root.to_path_buf(),
        model_dir: model_dir.to_path_buf(),
        model: OnceLock::new(),
        inference_logged: AtomicBool::new(false),
    };
    install_name_spotter(Arc::new(BoundedSpotter::new(
        Arc::new(local),
        MAX_SPOT_BYTES,
        SPOT_DEADLINE,
    )));
    true
}

/// Union every overlap that contains a prohibited span, keeping its full range
/// even when a higher-scoring ordinary label overlaps it.
pub fn consolidate(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|span| !span.is_empty());
    let mut regions = crate::recognizer::resolve_overlaps(spans.clone());
    let held = crate::recognizer::label_prohibited(&mut regions, &spans);
    let protected = regions
        .into_iter()
        .zip(held)
        .filter_map(|(region, held)| held.then_some(region));
    let ordinary = consolidate_flat(spans)
        .into_iter()
        .filter(|span| !span.is_prohibited())
        .collect::<Vec<_>>();
    let mut kept: Vec<Span> = protected.collect();
    kept.extend(ordinary);
    // Preserve the old stable start/end ordering, including tie order.
    kept.sort_by_key(|span| (span.start, span.end));
    kept
}

/// The flat score and overlap rule used before Tier C spans were unioned.
/// Keep this comparator and stable ordering unchanged for non-Tier-C labels.
fn consolidate_flat(mut spans: Vec<Span>) -> Vec<Span> {
    spans.retain(|span| !span.is_empty());
    spans.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.end.cmp(&right.end))
    });
    // Kept spans are disjoint and non-empty, so a new span overlaps one of
    // them exactly when it overlaps the kept span with the greatest start
    // before its end: O(n log n) instead of a scan of every kept span.
    let mut starts: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        let overlaps = starts
            .range(..span.end)
            .next_back()
            .is_some_and(|(_, &end)| span.start < end);
        if !overlaps {
            starts.insert(span.start, span.end);
            kept.push(span);
        }
    }
    kept.sort_by_key(|span| (span.start, span.end));
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interval lookup keeps exactly what the old scan of every kept
    /// span kept, ties and order included.
    #[test]
    fn consolidate_flat_matches_the_quadratic_scan() {
        fn naive(mut spans: Vec<Span>) -> Vec<Span> {
            spans.retain(|span| !span.is_empty());
            spans.sort_by(|left, right| {
                right
                    .score
                    .partial_cmp(&left.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| left.start.cmp(&right.start))
                    .then_with(|| left.end.cmp(&right.end))
            });
            let mut kept: Vec<Span> = Vec::new();
            for span in spans {
                if !kept.iter().any(|kept| kept.overlaps(&span)) {
                    kept.push(span);
                }
            }
            kept.sort_by_key(|span| (span.start, span.end));
            kept
        }
        let kinds = [
            EntityKind::Person,
            EntityKind::Organization,
            EntityKind::Health,
            EntityKind::Email,
        ];
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for _ in 0..2_000 {
            let count = next(24) as usize;
            let spans: Vec<Span> = (0..count)
                .map(|_| {
                    let start = next(60) as usize;
                    let end = start + next(12) as usize;
                    let score = next(5) as f32 / 4.0;
                    Span::new(kinds[next(4) as usize], start, end, score, "gliner")
                })
                .collect();
            assert_eq!(consolidate_flat(spans.clone()), naive(spans));
        }
    }

    #[test]
    fn native_labels_map_to_kinds() {
        assert_eq!(label_kind("person"), Some(EntityKind::Person));
        assert_eq!(label_kind("organization"), Some(EntityKind::Organization));
        assert_eq!(label_kind("address"), Some(EntityKind::Address));
        assert_eq!(label_kind("phone_number"), Some(EntityKind::Phone));
        assert_eq!(label_kind("email"), Some(EntityKind::Email));
        assert_eq!(label_kind("iban"), Some(EntityKind::Iban));
        assert_eq!(label_kind("payment_card"), Some(EntityKind::CreditCard));
        assert_eq!(label_kind("passport_number"), Some(EntityKind::PassportMrz));
        assert_eq!(
            label_kind("national_id_number"),
            Some(EntityKind::NationalId)
        );
        assert_eq!(label_kind("date_of_birth"), Some(EntityKind::DateOfBirth));
        assert_eq!(label_kind("health condition"), Some(EntityKind::Health));
        assert_eq!(label_kind("religion"), Some(EntityKind::Religion));
        // The GLiNER v1 names are gone with the v1 model.
        assert_eq!(label_kind("IBAN"), None);
        assert_eq!(label_kind("phone number"), None);
        // Every default label is recognised.
        assert!(GLINER_PII_LABELS
            .iter()
            .all(|label| label_kind(label).is_some()));
    }

    #[test]
    fn health_and_religion_thresholds_are_per_label() {
        let config = GlinerConfig::new("/models/gliner2");
        assert_eq!(config.threshold, 0.5);
        // NER-THRESH: only the model-only labels run at the low floor.
        for label in ["person", "organization", "address"] {
            assert_eq!(config.threshold_for(label), NAME_THRESHOLD, "{label}");
        }
        assert_eq!(config.threshold_for("health condition"), 0.4);
        for label in ["religion", "email", "iban", "payment_card", "phone_number"] {
            assert_eq!(config.threshold_for(label), 0.5, "{label}");
        }
        // Moving the default floor moves every label without its own override.
        let lowered = config.with_threshold(0.3);
        assert_eq!(lowered.threshold_for("religion"), 0.3);
        assert_eq!(lowered.threshold_for("person"), NAME_THRESHOLD);
        assert_eq!(lowered.threshold_for("health condition"), 0.4);
    }

    #[test]
    fn consolidate_keeps_the_higher_score_and_orders_by_start() {
        let spans = vec![
            Span::new(EntityKind::Person, 0, 12, 0.9, "gliner"),
            Span::new(EntityKind::Person, 5, 12, 0.5, "gliner"),
            Span::new(EntityKind::Organization, 20, 30, 0.7, "gliner"),
        ];
        let kept = consolidate(spans);
        assert_eq!(kept.len(), 2);
        assert_eq!((kept[0].start, kept[0].end), (0, 12));
        assert_eq!(kept[0].score, 0.9);
        assert_eq!((kept[1].start, kept[1].end), (20, 30));
    }

    #[test]
    fn consolidate_keeps_adjacent_spans_apart() {
        let spans = vec![
            Span::new(EntityKind::Person, 0, 4, 0.9, "gliner"),
            Span::new(EntityKind::Person, 4, 8, 0.9, "gliner"),
        ];
        let kept = consolidate(spans);
        assert_eq!(kept.len(), 2);
    }

    fn pre_250_consolidate(mut spans: Vec<Span>) -> Vec<Span> {
        spans.retain(|span| !span.is_empty());
        spans.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.start.cmp(&right.start))
                .then_with(|| left.end.cmp(&right.end))
        });
        let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
        for span in spans {
            if kept.iter().any(|kept| kept.overlaps(&span)) {
                continue;
            }
            kept.push(span);
        }
        kept.sort_by_key(|span| (span.start, span.end));
        kept
    }

    #[test]
    fn non_prohibited_spans_match_pre_250_for_overlaps_and_2000_fake_deep_cases() {
        let cases = [
            vec![
                Span::new(EntityKind::Person, 0, 12, 0.9, "fake-deep"),
                Span::new(EntityKind::Health, 5, 12, 0.95, "fake-deep"),
            ],
            vec![
                Span::new(EntityKind::Person, 0, 12, 0.9, "fake-deep"),
                Span::new(EntityKind::Organization, 5, 14, 0.9, "fake-deep"),
            ],
            vec![
                Span::new(EntityKind::Person, 0, 20, 0.8, "fake-deep"),
                Span::new(EntityKind::Address, 4, 16, 0.9, "fake-deep"),
                Span::new(EntityKind::Organization, 7, 12, 0.7, "fake-deep"),
            ],
            vec![
                Span::new(EntityKind::Person, 0, 8, 0.9, "fake-deep"),
                Span::new(EntityKind::Organization, 0, 8, 0.9, "fake-deep"),
            ],
        ];
        for spans in cases {
            let expected: Vec<_> = pre_250_consolidate(spans.clone())
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            let actual: Vec<_> = consolidate(spans)
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            assert_eq!(actual, expected);
        }

        // Deterministic, invented fake-Deep output: ties, nested names, and
        // Tier C overlaps vary across inputs while ordinary selections must
        // remain byte-for-byte equal to the pre-#250 flat pass.
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
            let expected: Vec<_> = pre_250_consolidate(spans.clone())
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            let actual: Vec<_> = consolidate(spans)
                .into_iter()
                .filter(|span| !span.kind.is_prohibited())
                .collect();
            assert_eq!(actual, expected, "fake-Deep input {input}");
        }
    }

    #[test]
    fn consolidate_unions_prohibited_overlap_chains_and_ignores_other_labels() {
        let kept = consolidate(vec![
            Span::new(EntityKind::Health, 0, 27, 0.9, "fake"),
            Span::new(EntityKind::NationalId, 0, 3, 0.9, "fake"),
            Span::new(EntityKind::Secret, 5, 40, 0.8, "fake"),
            Span::new(EntityKind::Health, 10, 15, 0.8, "fake"),
            Span::new(EntityKind::Iban, 38, 50, 0.7, "fake"),
            Span::new(EntityKind::Person, 0, 50, 1.0, "fake"),
        ]);
        let sensitive: Vec<_> = kept
            .iter()
            .filter(|span| span.kind.is_prohibited())
            .collect();
        assert_eq!(sensitive.len(), 1);
        assert_eq!(
            (sensitive[0].start, sensitive[0].end, sensitive[0].kind),
            (0, 50, EntityKind::Secret)
        );
        assert!(kept.iter().any(|span| span.kind == EntityKind::Person));
    }

    #[test]
    fn consolidate_keeps_touching_prohibited_ranges_separate_and_ties_are_stable() {
        let kept = consolidate(vec![
            Span::new(EntityKind::Health, 0, 27, 0.9, "fake"),
            Span::new(EntityKind::NationalId, 0, 3, 0.9, "fake"),
            Span::new(EntityKind::Secret, 27, 40, 0.9, "fake"),
        ]);
        assert_eq!(kept.len(), 2);
        assert_eq!(
            (kept[0].start, kept[0].end, kept[0].kind),
            (0, 27, EntityKind::NationalId)
        );
        assert_eq!(
            (kept[1].start, kept[1].end, kept[1].kind),
            (27, 40, EntityKind::Secret)
        );
    }

    #[test]
    fn config_defaults_are_the_benchmark_values() {
        let config = GlinerConfig::new("/models/gliner2");
        assert_eq!(config.threshold, 0.5);
        assert_eq!(config.labels, GLINER_PII_LABELS.to_vec());
        assert_eq!(config.onnx_file, "model.onnx");
        assert_eq!(config.chunk_tokens, 300);
        assert_eq!(config.chunk_overlap, 50);
        assert_eq!(
            GlinerConfig::new("/x").with_int8().onnx_file,
            "model_int8.onnx"
        );
    }

    #[test]
    fn a_symlinked_model_file_is_refused_and_mounts_nothing() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("models").join("gliner2-pii");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(home.path().join("elsewhere.onnx"), b"x").unwrap();
        std::os::unix::fs::symlink(home.path().join("elsewhere.onnx"), dir.join("model.onnx"))
            .unwrap();
        std::fs::write(dir.join("tokenizer.json"), b"{}").unwrap();
        assert_eq!(
            vet_model_dir(home.path(), &dir).unwrap_err(),
            Vetting::Refused
        );
        assert!(!install_local_model(home.path(), &dir));
        assert!(!name_spotter_installed());
    }

    #[test]
    fn a_model_dir_outside_the_home_or_behind_a_symlink_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        for file in ["model.onnx", "tokenizer.json"] {
            std::fs::write(elsewhere.path().join(file), b"x").unwrap();
        }
        assert_eq!(
            vet_model_dir(home.path(), elsewhere.path()).unwrap_err(),
            Vetting::Refused
        );
        std::fs::create_dir_all(home.path().join("models")).unwrap();
        let link = home.path().join("models").join("gliner2-pii");
        std::os::unix::fs::symlink(elsewhere.path(), &link).unwrap();
        assert_eq!(
            vet_model_dir(home.path(), &link).unwrap_err(),
            Vetting::Refused
        );
    }

    #[test]
    fn plain_files_inside_the_home_are_accepted_and_missing_files_are_absent() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("models").join("gliner2-pii");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            vet_model_dir(home.path(), &dir).unwrap_err(),
            Vetting::Absent
        );
        std::fs::write(dir.join("model_int8.onnx"), b"x").unwrap();
        std::fs::write(dir.join("tokenizer.json"), b"{}").unwrap();
        let config = vet_model_dir(home.path(), &dir).unwrap();
        assert_eq!(config.onnx_file, "model_int8.onnx");
    }
}
