//! Span decoding: per-field candidates, greedy selection and source verification.

/// A candidate span of one field, as word indices `[start, end)`, with its score.
pub(crate) type Candidate = (f32, usize, usize);

/// The candidates of one field at or above `floor`. `probs` holds one field of
/// the graph output, row-major `[word][width]`; a span whose end runs past the
/// last word is never a candidate.
pub(crate) fn field_candidates(
    probs: &[f32],
    width: usize,
    floor: f32,
    words: usize,
) -> Vec<Candidate> {
    let mut found = Vec::new();
    for start in 0..words {
        for offset in 0..width {
            let score = probs[start * width + offset];
            let end = start + offset + 1;
            if score >= floor && end <= words {
                found.push((score, start, end));
            }
        }
    }
    found
}

/// Greedy selection within one label: highest score first, and a candidate is
/// dropped when it shares a word with one already kept.
pub(crate) fn finalize_label(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|left, right| right.0.total_cmp(&left.0));
    let mut kept: Vec<Candidate> = Vec::new();
    for candidate in candidates {
        if kept
            .iter()
            .any(|existing| candidate.1 < existing.2 && existing.1 < candidate.2)
        {
            continue;
        }
        kept.push(candidate);
    }
    kept
}

/// The model's outputs must be usable: a NaN or infinite value, or an empty
/// count head, is an inference error, never "no entities" (fail closed).
pub(crate) fn check_outputs(probs: &[f32], counts: &[f32]) -> Result<(), String> {
    if counts.is_empty() {
        return Err("count_logits is empty".to_string());
    }
    if !counts.iter().all(|value| value.is_finite()) {
        return Err("count_logits has a non-finite value".to_string());
    }
    if !probs.iter().all(|value| value.is_finite()) {
        return Err("span_probs has a non-finite value".to_string());
    }
    Ok(())
}

/// Index of the largest value (the first one on a tie).
pub(crate) fn argmax(values: &[f32]) -> usize {
    let mut best = 0usize;
    for (index, value) in values.iter().enumerate() {
        if *value > values[best] {
            best = index;
        }
    }
    best
}

/// The byte range must lie on char boundaries and its bytes must equal the
/// model's own value: a span the source does not confirm is dropped.
pub(crate) fn span_matches_source(text: &str, start: usize, end: usize, value: &str) -> bool {
    if start >= end || end > text.len() {
        return false;
    }
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return false;
    }
    text[start..end] == *value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_keeps_candidates_at_or_above_the_floor_in_word_order() {
        // Two words, width two. Row-major: [start][width].
        // Span (0,0) = 0.9, span (0,1) = 0.2, span (1,0) = 0.6, span (1,1) runs past the text.
        let probs = [0.9, 0.2, 0.6, 0.99];
        let found = field_candidates(&probs, 2, 0.5, 2);
        assert_eq!(found, vec![(0.9, 0, 1), (0.6, 1, 2)]);
    }

    #[test]
    fn a_label_keeps_its_best_non_overlapping_spans() {
        let kept = finalize_label(vec![(0.6, 0, 4), (0.9, 2, 7), (0.7, 7, 9)]);
        assert_eq!(kept, vec![(0.9, 2, 7), (0.7, 7, 9)]);
    }

    #[test]
    fn the_count_head_argmax_picks_the_first_largest() {
        assert_eq!(argmax(&[0.1, 2.0, 2.0, -1.0]), 1);
        assert_eq!(argmax(&[3.0, -1.0]), 0);
    }

    #[test]
    fn spans_are_verified_against_source_bytes() {
        let text = "Mara Ellison";
        assert!(span_matches_source(text, 0, 4, "Mara"));
        assert!(!span_matches_source(text, 0, 4, "Mara "));
        assert!(!span_matches_source(text, 0, 99, "Mara"));
        // Byte 2 is inside `é`, so it is not a boundary.
        let text = "héllo";
        assert!(span_matches_source(text, 1, 3, "é"));
        assert!(!span_matches_source(text, 2, 3, "é"));
    }

    #[test]
    fn non_finite_or_empty_outputs_are_refused() {
        assert!(check_outputs(&[0.1, 0.9], &[0.0, 2.0]).is_ok());
        assert!(check_outputs(&[0.1, f32::NAN], &[0.0, 2.0]).is_err());
        assert!(check_outputs(&[0.1, 0.9], &[f32::NAN, 9.0]).is_err());
        assert!(check_outputs(&[f32::INFINITY], &[0.0, 2.0]).is_err());
        assert!(check_outputs(&[0.1], &[f32::NEG_INFINITY, 1.0]).is_err());
        assert!(check_outputs(&[0.1], &[]).is_err());
    }
}
