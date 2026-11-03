//! Per-kind score floors.
//!
//! A recogniser emits a score; the registry drops any span whose score is
//! below its kind's floor. Checksum-validated values score `1.0`, so the
//! default floor of `0.5` keeps them while still filtering bare low-confidence
//! patterns. The floors are a config knob, not a hidden constant.

use std::collections::HashMap;

use crate::span::EntityKind;

/// Number of [`EntityKind`] variants.
const KIND_COUNT: usize = EntityKind::ALL.len();

/// Minimum score a span of a given kind must reach to survive.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Thresholds {
    per_kind: [f32; KIND_COUNT],
}

impl Thresholds {
    /// The default floor (`0.5`) for every kind.
    pub fn new() -> Self {
        Self {
            per_kind: [0.5; KIND_COUNT],
        }
    }

    /// The floor for one kind.
    pub fn get(&self, kind: EntityKind) -> f32 {
        self.per_kind[index_of(kind)]
    }

    /// Override the floor for one kind.
    pub fn set(&mut self, kind: EntityKind, floor: f32) {
        self.per_kind[index_of(kind)] = floor;
    }

    /// A copy with one kind overridden (builder style).
    pub fn with(mut self, kind: EntityKind, floor: f32) -> Self {
        self.set(kind, floor);
        self
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self::new()
    }
}

fn index_of(kind: EntityKind) -> usize {
    EntityKind::ALL
        .iter()
        .position(|candidate| *candidate == kind)
        .expect("EntityKind::ALL is exhaustive")
}

/// A convenience view used by tests and the eval harness.
pub fn default_floors() -> HashMap<EntityKind, f32> {
    let thresholds = Thresholds::new();
    EntityKind::ALL
        .iter()
        .map(|kind| (*kind, thresholds.get(*kind)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_half_and_overrides_stick() {
        let mut thresholds = Thresholds::new();
        assert_eq!(thresholds.get(EntityKind::Email), 0.5);
        thresholds.set(EntityKind::Phone, 0.9);
        assert_eq!(thresholds.get(EntityKind::Phone), 0.9);
        assert_eq!(thresholds.get(EntityKind::Iban), 0.5);
        assert_eq!(
            Thresholds::new()
                .with(EntityKind::Url, 0.1)
                .get(EntityKind::Url),
            0.1
        );
        assert_eq!(default_floors().len(), EntityKind::ALL.len());
    }
}
