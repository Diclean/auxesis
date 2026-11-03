#![cfg(feature = "ner-gliner")]
//! The second pass with the real local GLiNER2 model: a private gate with no
//! contacts tokenises an unknown person and organisation, and rehydrates exactly.
//!
//! Needs an exported model directory (`model.onnx` or `model_int8.onnx`,
//! `tokenizer.json`, `libonnxruntime.dylib`; no symlinks). Without `AUX_GLINER_MODEL_DIR`
//! the test prints why and passes, like the eval examples. Run it with:
//!
//! ```console
//! AUX_GLINER_MODEL_DIR=~/.auxesis/models/gliner2-pii \
//! cargo test -p kernel-privacy --features ner-gliner --test second_pass_model -- --nocapture
//! ```

use std::path::PathBuf;

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::ner::install_local_model;
use kernel_privacy::{EntityKind, Gate};

const TEXT: &str = "Please call Camille Exemple at Exemple Conseil SARL";

#[test]
fn an_unknown_person_and_organisation_are_tokenised_without_a_dictionary() {
    let Some(dir) = std::env::var_os("AUX_GLINER_MODEL_DIR").map(PathBuf::from) else {
        println!("skipped: AUX_GLINER_MODEL_DIR is not set (no local GLiNER2 model)");
        return;
    };
    assert!(
        install_local_model(&dir, &dir),
        "{} holds no model",
        dir.display()
    );
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &ctx) else {
        panic!("A1 is allowed in private mode");
    };
    let mut gate = Gate::for_grant(&grant, [5u8; 32]);
    let (safe, report) = gate.text(TEXT).expect("the gate issues the text");
    assert!(safe.names_checked(), "NER ran, so names are checked");
    assert!(report.count(EntityKind::Person) >= 1, "{report}");
    assert!(report.count(EntityKind::Organization) >= 1, "{report}");
    assert!(!safe.as_str().contains("Camille"), "{}", safe.as_str());
    assert!(!safe.as_str().contains("Conseil"), "{}", safe.as_str());
    let rehydrated = gate
        .take_minted()
        .iter()
        .fold(safe.as_str().to_string(), |text, (token, value)| {
            text.replace(&format!("⟦{token}⟧"), value)
        });
    assert_eq!(rehydrated, TEXT);
}
