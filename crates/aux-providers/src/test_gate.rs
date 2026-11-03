//! Test-only name coverage for tokenising gates.
//!
//! A tokenising gate issues nothing without a detector that checks names, and
//! the default build has none: the GLiNER model is an opt-in feature. The tests
//! that hold a tokenising gate exercise tokenising, not names. [`names_checked`]
//! holds the deterministic registry and claims the coverage a name model would
//! give, so the gate issues and every value the tests use is still masked.

use std::sync::Arc;

use kernel_privacy::safetext::{DetectError, Detector};
use kernel_privacy::{Registry, Span};

/// The deterministic registry, claiming name coverage.
struct NamesChecked(Registry);

impl Detector for NamesChecked {
    fn detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Detector::detect(&self.0, text)
    }

    fn checks_names(&self) -> bool {
        true
    }
}

/// A detector a tokenising test gate can hold: the deterministic recognisers,
/// with name coverage claimed.
pub fn names_checked() -> Arc<dyn Detector> {
    Arc::new(NamesChecked(Registry::new()))
}

/// A detector that claims name coverage over `inner`, which keeps its own
/// detection and residue scan. For a test that injects a detector and still
/// needs a tokenising gate to issue.
struct Claimed(Arc<dyn Detector>);

impl Detector for Claimed {
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

/// `inner` with name coverage claimed; see [`Claimed`].
pub fn names_claimed(inner: Arc<dyn Detector>) -> Arc<dyn Detector> {
    Arc::new(Claimed(inner))
}
