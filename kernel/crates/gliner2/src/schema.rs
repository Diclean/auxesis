//! The input gliner2 builds for one window: the schema
//! `( [P] entities ( [E] label ... ) )`, then `[SEP_TEXT]`, then the words.

use crate::text::{normalize_text, split_words};
use crate::Error;

/// The encoding of one window, ready for the graph.
pub(crate) struct Encoded {
    pub(crate) input_ids: Vec<i64>,
    /// Byte offsets of each word in `normalized`.
    pub(crate) word_starts: Vec<usize>,
    pub(crate) word_ends: Vec<usize>,
    /// Subword position of the first subword of each word.
    pub(crate) word_first: Vec<i64>,
    /// Subword positions of `[P]`, then of each `[E]`.
    pub(crate) schema_special: Vec<i64>,
    /// The window with a closing full stop when it had none; word offsets index into it.
    pub(crate) normalized: String,
}

/// Encode one window for the entity labels.
pub(crate) fn encode(
    tokenizer: &tokenizers::Tokenizer,
    window: &str,
    labels: &[&str],
) -> Result<Encoded, Error> {
    let normalized = normalize_text(window);
    let words = split_words(&normalized);

    let mut schema: Vec<&str> = vec!["(", "[P]", "entities", "("];
    for label in labels {
        schema.push("[E]");
        schema.push(*label);
    }
    schema.extend([")", ")"]);

    let mut input_ids: Vec<i64> = Vec::new();
    let mut schema_special: Vec<i64> = Vec::with_capacity(labels.len() + 1);
    let schema_len = schema.len();
    for (index, token) in schema.iter().enumerate() {
        // The `[P]` token, then every `[E]` marker (even indices from 4 on).
        if index == 1 || (index >= 4 && index % 2 == 0 && index < schema_len - 2) {
            schema_special.push(input_ids.len() as i64);
        }
        input_ids.extend(subword_ids(tokenizer, token)?);
    }
    input_ids.extend(subword_ids(tokenizer, "[SEP_TEXT]")?);

    let mut word_starts = Vec::with_capacity(words.len());
    let mut word_ends = Vec::with_capacity(words.len());
    let mut word_first = Vec::with_capacity(words.len());
    for (word, start, end) in &words {
        word_starts.push(*start);
        word_ends.push(*end);
        word_first.push(input_ids.len() as i64);
        input_ids.extend(subword_ids(tokenizer, word)?);
    }

    Ok(Encoded {
        input_ids,
        word_starts,
        word_ends,
        word_first,
        schema_special,
        normalized,
    })
}

/// Subword ids of one token, without special tokens.
fn subword_ids(tokenizer: &tokenizers::Tokenizer, token: &str) -> Result<Vec<i64>, Error> {
    let encoding = tokenizer
        .encode(token, false)
        .map_err(|error| Error::Tokenizer(error.to_string()))?;
    Ok(encoding.get_ids().iter().map(|id| i64::from(*id)).collect())
}
