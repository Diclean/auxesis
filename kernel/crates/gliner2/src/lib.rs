//! GLiNER2 zero-shot span extraction over ONNX Runtime.
//!
//! The caller names the entity labels and gets back the spans of the text that
//! match them, with byte offsets into the text. The model is an exported
//! GLiNER2 graph (see the README for the export and its licence). The prompt,
//! the word split, the decode and the windowing follow the gliner2 library, and
//! `tests/parity.rs` checks the spans against it.
//!
//! ```no_run
//! use gliner2_rs::{Gliner2, Options};
//!
//! # fn main() -> Result<(), gliner2_rs::Error> {
//! let model = Gliner2::load("models/gliner2-privacy-filter-PII-multi", &Options::default())?;
//! for entity in model.extract("Mara Ellison, mara@example.com", &["person", "email"], 0.5)? {
//!     println!("{} {}..{} {:.2}", entity.label, entity.start, entity.end, entity.score);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! This crate has no `unsafe` code of its own. ONNX Runtime is loaded at run
//! time from the shared library named by [`Options::ort_dylib`] or
//! `ORT_DYLIB_PATH`, so building it needs no network access.

use std::fmt;
use std::path::{Path, PathBuf};

mod decode;
mod schema;
mod session;
mod text;

/// Why a model could not be loaded, or could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A model or tokenizer file does not exist.
    MissingFile(PathBuf),
    /// The ONNX graph could not be opened.
    Model(String),
    /// The tokenizer could not be opened, or could not encode a text.
    Tokenizer(String),
    /// The graph ran and failed, or returned a tensor of an unexpected shape.
    Inference(String),
    /// An option or an argument is invalid.
    InvalidOptions(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingFile(path) => write!(f, "gliner2: missing file: {}", path.display()),
            Error::Model(message) => write!(f, "gliner2: model error: {message}"),
            Error::Tokenizer(message) => write!(f, "gliner2: tokenizer error: {message}"),
            Error::Inference(message) => write!(f, "gliner2: inference error: {message}"),
            Error::InvalidOptions(message) => write!(f, "gliner2: invalid options: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// Settings for [`Gliner2::load`] and [`Gliner2::load_paths`].
#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    /// Score floors for labels that have no entry in `label_thresholds`; the
    /// `threshold` argument of [`Gliner2::extract`] is used for those labels.
    pub label_thresholds: Vec<(String, f32)>,
    /// Maximum span width in words. It must match the exported graph.
    pub max_width: usize,
    /// Tokens per window for a long text.
    pub chunk_tokens: usize,
    /// Tokens shared by two neighbouring windows.
    pub chunk_overlap: usize,
    /// ONNX Runtime 1.20 shared library. When set and `ORT_DYLIB_PATH` is
    /// unset, it is exported for the process before the first session starts.
    pub ort_dylib: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            label_thresholds: Vec::new(),
            max_width: 8,
            chunk_tokens: 300,
            chunk_overlap: 50,
            ort_dylib: None,
        }
    }
}

impl Options {
    /// Give one label its own score floor.
    pub fn with_label_threshold(mut self, label: &str, threshold: f32) -> Self {
        self.label_thresholds.push((label.to_string(), threshold));
        self
    }
}

/// One span the model found: byte offsets into the text, the label, and the score.
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub score: f32,
}

/// What [`Gliner2::extract_report`] found, with the bookkeeping behind it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Extraction {
    /// The spans, ordered by start offset, never overlapping.
    pub entities: Vec<Entity>,
    /// Spans the model proposed whose bytes did not match the text.
    pub dropped: usize,
    /// Number of windows the text was split into (`1` when it fit).
    pub chunks: usize,
}

/// A loaded GLiNER2 graph and its tokenizer.
pub struct Gliner2 {
    runner: session::Runner,
    tokenizer: tokenizers::Tokenizer,
    max_width: usize,
    chunk_tokens: usize,
    chunk_overlap: usize,
    label_thresholds: Vec<(String, f32)>,
}

impl Gliner2 {
    /// Load `model.onnx` and `tokenizer.json` from `model_dir`.
    pub fn load(model_dir: impl AsRef<Path>, options: &Options) -> Result<Self, Error> {
        let dir = model_dir.as_ref();
        Self::load_paths(dir.join("model.onnx"), dir.join("tokenizer.json"), options)
    }

    /// Load the graph and the tokenizer from explicit paths.
    pub fn load_paths(
        model: impl AsRef<Path>,
        tokenizer: impl AsRef<Path>,
        options: &Options,
    ) -> Result<Self, Error> {
        validate_options(options)?;
        let (model, tokenizer) = (model.as_ref(), tokenizer.as_ref());
        for path in [model, tokenizer] {
            if !path.is_file() {
                return Err(Error::MissingFile(path.to_path_buf()));
            }
        }
        if let Some(dylib) = &options.ort_dylib {
            if std::env::var_os("ORT_DYLIB_PATH").is_none() {
                std::env::set_var("ORT_DYLIB_PATH", dylib);
            }
        }
        let runner = session::Runner::load(model)?;
        let tokenizer = tokenizers::Tokenizer::from_file(tokenizer)
            .map_err(|error| Error::Tokenizer(error.to_string()))?;
        Ok(Self {
            runner,
            tokenizer,
            max_width: options.max_width,
            chunk_tokens: options.chunk_tokens,
            chunk_overlap: options.chunk_overlap,
            label_thresholds: options.label_thresholds.clone(),
        })
    }

    /// The spans of `text` for `labels`, at `threshold` for every label without
    /// its own floor. Byte offsets index `text`.
    pub fn extract(
        &self,
        text: &str,
        labels: &[&str],
        threshold: f32,
    ) -> Result<Vec<Entity>, Error> {
        self.extract_report(text, labels, threshold)
            .map(|extraction| extraction.entities)
    }

    /// [`Self::extract`] with the dropped-span count and the number of windows.
    pub fn extract_report(
        &self,
        text: &str,
        labels: &[&str],
        threshold: f32,
    ) -> Result<Extraction, Error> {
        if labels.is_empty() {
            return Err(Error::InvalidOptions("no entity labels".to_string()));
        }
        check_threshold("threshold", threshold)?;
        if text.is_empty() {
            return Ok(Extraction::default());
        }

        let encoding = self
            .tokenizer
            .encode(text, false)
            .map_err(|error| Error::Tokenizer(error.to_string()))?;
        let offsets: Vec<(usize, usize)> = encoding.get_offsets().to_vec();
        if offsets.is_empty() {
            return Err(Error::Tokenizer(
                "the tokenizer produced no token for a non-empty text".to_string(),
            ));
        }
        let windows = text::windows(&offsets, text.len(), self.chunk_tokens, self.chunk_overlap);

        let mut candidates: Vec<Entity> = Vec::new();
        let mut dropped = 0usize;
        for &(window_start, window_end) in &windows {
            let window = &text[window_start..window_end];
            let encoded = schema::encode(&self.tokenizer, window, labels)?;
            let output = self.runner.run(&encoded)?;

            let words = encoded.word_first.len();
            let expected = [labels.len() as i64, words as i64, self.max_width as i64];
            if output.shape != expected {
                return Err(Error::Inference(format!(
                    "span_probs has shape {:?}, expected {expected:?}",
                    output.shape
                )));
            }
            decode::check_outputs(&output.probs, &output.counts).map_err(Error::Inference)?;
            // The count head decides whether the window has any instance at all.
            if decode::argmax(&output.counts) == 0 {
                continue;
            }

            let field_len = words * self.max_width;
            for (field, label) in labels.iter().enumerate() {
                let floor = self.threshold_for(label, threshold);
                let probs = &output.probs[field * field_len..(field + 1) * field_len];
                let kept = decode::finalize_label(decode::field_candidates(
                    probs,
                    self.max_width,
                    floor,
                    words,
                ));
                for (score, first, end) in kept {
                    let (char_start, char_end) =
                        (encoded.word_starts[first], encoded.word_ends[end - 1]);
                    // A span running into the full stop appended to the window is not in it.
                    if char_end > window.len() {
                        continue;
                    }
                    let value = encoded.normalized[char_start..char_end].trim();
                    if value.is_empty() {
                        continue;
                    }
                    let (start, stop) = (window_start + char_start, window_start + char_end);
                    if !decode::span_matches_source(text, start, stop, value) {
                        dropped += 1;
                        continue;
                    }
                    candidates.push(Entity {
                        start,
                        end: stop,
                        label: (*label).to_string(),
                        score,
                    });
                }
            }
        }

        Ok(Extraction {
            entities: consolidate(candidates),
            dropped,
            chunks: windows.len(),
        })
    }

    fn threshold_for(&self, label: &str, default: f32) -> f32 {
        self.label_thresholds
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, threshold)| *threshold)
            .unwrap_or(default)
    }
}

fn validate_options(options: &Options) -> Result<(), Error> {
    for (label, threshold) in &options.label_thresholds {
        check_threshold(label, *threshold)?;
    }
    if options.max_width == 0 {
        return Err(Error::InvalidOptions(
            "max_width must be at least 1".to_string(),
        ));
    }
    if options.chunk_tokens == 0 || options.chunk_overlap >= options.chunk_tokens {
        return Err(Error::InvalidOptions(
            "chunk_overlap must be smaller than chunk_tokens".to_string(),
        ));
    }
    Ok(())
}

fn check_threshold(name: &str, threshold: f32) -> Result<(), Error> {
    if threshold > 0.0 && threshold <= 1.0 {
        Ok(())
    } else {
        Err(Error::InvalidOptions(format!(
            "{name} {threshold} is outside 0.0..=1.0"
        )))
    }
}

/// Keep the highest-scoring span of every overlapping same-label group, then
/// order by start offset. Cross-label overlaps must survive for policy filtering.
fn consolidate(mut entities: Vec<Entity>) -> Vec<Entity> {
    entities.retain(|entity| entity.end > entity.start);
    entities.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.end.cmp(&right.end))
    });
    let mut kept: Vec<Entity> = Vec::with_capacity(entities.len());
    for entity in entities {
        if kept.iter().any(|existing| {
            existing.label == entity.label
                && entity.start < existing.end
                && existing.start < entity.end
        }) {
            continue;
        }
        kept.push(entity);
    }
    kept.sort_by_key(|entity| (entity.start, entity.end));
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(start: usize, end: usize, score: f32) -> Entity {
        Entity {
            start,
            end,
            label: "person".to_string(),
            score,
        }
    }

    #[test]
    fn consolidate_keeps_the_higher_score_and_orders_by_start() {
        let kept = consolidate(vec![
            entity(0, 12, 0.9),
            entity(5, 12, 0.5),
            entity(20, 30, 0.7),
        ]);
        assert_eq!(kept, vec![entity(0, 12, 0.9), entity(20, 30, 0.7)]);
    }

    #[test]
    fn consolidate_keeps_adjacent_spans_apart() {
        let kept = consolidate(vec![entity(0, 4, 0.9), entity(4, 8, 0.9)]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn consolidate_preserves_overlapping_different_labels_for_policy_filtering() {
        let mut person = entity(9, 13, 0.99);
        let mut health = entity(9, 26, 0.6);
        health.label = "health".to_string();
        person.label = "person".to_string();
        assert_eq!(
            consolidate(vec![person.clone(), health.clone()]),
            vec![person, health]
        );
    }

    #[test]
    fn invalid_options_are_refused_before_a_model_is_opened() {
        assert!(validate_options(&Options::default()).is_ok());
        assert!(validate_options(&Options::default().with_label_threshold("x", 0.0)).is_err());
        let overlap = Options {
            chunk_overlap: Options::default().chunk_tokens,
            ..Options::default()
        };
        assert!(validate_options(&overlap).is_err());
        let width = Options {
            max_width: 0,
            ..Options::default()
        };
        assert!(validate_options(&width).is_err());
    }
}
