//! Recall and precision scoring for the `qa/privacy-eval` benchmark.
//!
//! The library stays serde-free; the `qa/privacy-eval` runner parses
//! the JSONL corpus and feeds [`GoldSpan`] pairs here. A predicted span counts
//! as a true positive only when its kind and both byte offsets match a gold
//! span exactly (the contract pins offsets, so near misses are misses).

use crate::span::{EntityKind, Span};

/// One labelled span from the corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldSpan {
    /// Expected kind.
    pub kind: EntityKind,
    /// Expected start byte offset.
    pub start: usize,
    /// Expected end byte offset.
    pub end: usize,
}

impl GoldSpan {
    /// Build a gold span.
    pub fn new(kind: EntityKind, start: usize, end: usize) -> Self {
        Self { kind, start, end }
    }
}

/// Per-kind counts and rates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KindScore {
    /// The scored kind.
    pub kind: EntityKind,
    /// Predicted spans matching a gold span.
    pub true_positives: usize,
    /// Predicted spans with no matching gold span.
    pub false_positives: usize,
    /// Gold spans no prediction matched.
    pub false_negatives: usize,
    /// `tp / (tp + fp)`, `1.0` when nothing was predicted.
    pub precision: f32,
    /// `tp / (tp + fn)`, `1.0` when nothing was expected.
    pub recall: f32,
}

/// Score predictions against gold spans, one entry per kind that appears in
/// either side, ordered by [`EntityKind::ALL`].
pub fn score(gold: &[GoldSpan], predicted: &[Span]) -> Vec<KindScore> {
    let mut scores = Vec::new();
    for kind in EntityKind::ALL {
        let expected: Vec<&GoldSpan> = gold.iter().filter(|span| span.kind == kind).collect();
        let got: Vec<&Span> = predicted.iter().filter(|span| span.kind == kind).collect();
        if expected.is_empty() && got.is_empty() {
            continue;
        }
        let mut matched = vec![false; expected.len()];
        let mut true_positives = 0usize;
        for prediction in &got {
            let hit = expected.iter().enumerate().find(|(index, candidate)| {
                !matched[*index]
                    && candidate.start == prediction.start
                    && candidate.end == prediction.end
            });
            if let Some((index, _)) = hit {
                matched[index] = true;
                true_positives += 1;
            }
        }
        let false_positives = got.len() - true_positives;
        let false_negatives = expected.len() - true_positives;
        scores.push(KindScore {
            kind,
            true_positives,
            false_positives,
            false_negatives,
            precision: ratio(true_positives, true_positives + false_positives),
            recall: ratio(true_positives, true_positives + false_negatives),
        });
    }
    scores
}

/// Micro-averaged totals over every kind.
pub fn overall(scores: &[KindScore]) -> (f32, f32) {
    let true_positives: usize = scores.iter().map(|score| score.true_positives).sum();
    let false_positives: usize = scores.iter().map(|score| score.false_positives).sum();
    let false_negatives: usize = scores.iter().map(|score| score.false_negatives).sum();
    (
        ratio(true_positives, true_positives + false_positives),
        ratio(true_positives, true_positives + false_negatives),
    )
}

fn ratio(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f32 / denominator as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn predicted(kind: EntityKind, start: usize, end: usize) -> Span {
        Span::new(kind, start, end, 1.0, "test")
    }

    #[test]
    fn perfect_match_scores_one() {
        let gold = [GoldSpan::new(EntityKind::Email, 0, 5)];
        let got = [predicted(EntityKind::Email, 0, 5)];
        let scores = score(&gold, &got);
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].precision, 1.0);
        assert_eq!(scores[0].recall, 1.0);
    }

    #[test]
    fn offsets_must_match_exactly() {
        let gold = [GoldSpan::new(EntityKind::Email, 0, 5)];
        let got = [predicted(EntityKind::Email, 0, 6)];
        let scores = score(&gold, &got);
        assert_eq!(scores[0].false_positives, 1);
        assert_eq!(scores[0].false_negatives, 1);
        assert_eq!(scores[0].precision, 0.0);
        assert_eq!(scores[0].recall, 0.0);
    }

    #[test]
    fn counts_false_positives_and_negatives_per_kind() {
        let gold = [
            GoldSpan::new(EntityKind::Phone, 0, 4),
            GoldSpan::new(EntityKind::Phone, 10, 14),
        ];
        let got = [
            predicted(EntityKind::Phone, 0, 4),
            predicted(EntityKind::Phone, 20, 24),
        ];
        let scores = score(&gold, &got);
        assert_eq!(scores[0].true_positives, 1);
        assert_eq!(scores[0].false_positives, 1);
        assert_eq!(scores[0].false_negatives, 1);
        assert_eq!(scores[0].precision, 0.5);
        assert_eq!(scores[0].recall, 0.5);
    }

    #[test]
    fn empty_sides_are_skipped_and_overall_averages() {
        assert!(score(&[], &[]).is_empty());
        let gold = [GoldSpan::new(EntityKind::Iban, 0, 4)];
        let got = [
            predicted(EntityKind::Iban, 0, 4),
            predicted(EntityKind::Phone, 5, 9),
        ];
        let scores = score(&gold, &got);
        let (_precision, recall) = overall(&scores);
        assert_eq!(recall, 1.0);
    }
}
