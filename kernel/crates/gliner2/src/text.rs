//! Word splitting, text normalisation and token windows.

use std::sync::OnceLock;

use regex::Regex;

/// gliner2's `WhitespaceTokenSplitter`: each word, lower-cased, with its byte range.
///
/// URLs, e-mail addresses and `@handles` stay whole. Words may join with a
/// hyphen or an underscore, and any other non-space character is a word of its own.
pub(crate) fn split_words(text: &str) -> Vec<(String, usize, usize)> {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = PATTERN.get_or_init(|| {
        let word = r"[\p{L}\p{M}\p{N}_\x{200c}\x{200d}]";
        Regex::new(&format!(
            r"(?i)https?://\S+|www\.\S+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{{2,}}|@[a-z0-9_]+|{word}+(?:[-_]{word}+)*|\S"
        ))
        .expect("the word pattern is valid")
    });
    pattern
        .find_iter(text)
        .map(|found| (found.as_str().to_lowercase(), found.start(), found.end()))
        .collect()
}

/// The text as gliner2 feeds it to the model: a text without closing sentence
/// punctuation gets a full stop.
pub(crate) fn normalize_text(text: &str) -> String {
    if text.is_empty() {
        return ".".to_string();
    }
    if matches!(text.chars().last(), Some('.' | '!' | '?')) {
        text.to_string()
    } else {
        format!("{text}.")
    }
}

/// Byte ranges of the windows that cover a text: `chunk_tokens` tokens each,
/// with `overlap` tokens shared by two neighbours. A text that fits one window
/// is one window over the whole text. `offsets` are the byte ranges of the
/// tokens of the whole text, in order.
pub(crate) fn windows(
    offsets: &[(usize, usize)],
    text_len: usize,
    chunk_tokens: usize,
    overlap: usize,
) -> Vec<(usize, usize)> {
    if offsets.len() <= chunk_tokens {
        return vec![(0, text_len)];
    }
    let step = chunk_tokens - overlap;
    let mut out = Vec::new();
    let mut start = 0usize;
    loop {
        let end = (start + chunk_tokens).min(offsets.len());
        out.push((offsets[start].0, offsets[end - 1].1));
        if end >= offsets.len() {
            break;
        }
        start += step;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_splitter_matches_the_gliner2_reference() {
        // Expected values are the output of gliner2 2.1.0's WhitespaceTokenSplitter
        // (lower=True), ASCII so that character and byte offsets agree.
        let words = split_words("Mara.Ellison-x mara.ellison@example.invalid, IBAN DE89-3704");
        let got: Vec<(&str, usize, usize)> = words
            .iter()
            .map(|(word, start, end)| (word.as_str(), *start, *end))
            .collect();
        assert_eq!(
            got,
            vec![
                ("mara", 0, 4),
                (".", 4, 5),
                ("ellison-x", 5, 14),
                ("mara.ellison@example.invalid", 15, 43),
                (",", 43, 44),
                ("iban", 45, 49),
                ("de89-3704", 50, 59),
            ]
        );
        let words: Vec<String> = split_words("1,000.50 ok? +33 X1234567!")
            .into_iter()
            .map(|(word, _, _)| word)
            .collect();
        assert_eq!(
            words,
            vec!["1", ",", "000", ".", "50", "ok", "?", "+", "33", "x1234567", "!"]
        );
    }

    #[test]
    fn text_without_closing_punctuation_gets_a_full_stop() {
        assert_eq!(normalize_text("Mara Ellison"), "Mara Ellison.");
        assert_eq!(normalize_text("Mara Ellison?"), "Mara Ellison?");
        assert_eq!(normalize_text("ok!"), "ok!");
    }

    #[test]
    fn windows_overlap_by_the_configured_tokens() {
        // Ten contiguous tokens of two bytes each.
        let offsets: Vec<(usize, usize)> = (0..10).map(|i| (2 * i, 2 * i + 2)).collect();
        // Windows of four tokens with one token of overlap: [0,4), [3,7), [6,10).
        assert_eq!(windows(&offsets, 20, 4, 1), vec![(0, 8), (6, 14), (12, 20)]);
        // A text that fits one window is one window over the whole text.
        assert_eq!(windows(&offsets[..3], 6, 4, 1), vec![(0, 6)]);
    }
}
