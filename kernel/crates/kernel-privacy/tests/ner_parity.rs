#![cfg(feature = "ner-gliner")]
//! Parity gate: the Rust GLiNER2-PII runner against the reference spans of the
//! gliner2 library, on the first 50 FAKE `qa/privacy-eval` English cases.
//!
//! The reference is `crates/gliner2/tests/fixtures/gliner2_en50_reference.json`, written by
//! `scripts/gliner2-parity.py` from the library and checked there against the
//! PyTorch and ONNX graphs. The spans must match exactly: same label, same byte
//! offsets, same text, in every case.
//!
//! Ignored by default because it needs the exported model directory and the
//! ONNX Runtime 1.20 shared library. Run it with:
//!
//! ```console
//! AUX_GLINER_MODEL_DIR=/path/to/export/gliner2_privacy_pii_multi \
//! AUX_GLINER_ORT_DYLIB=/path/to/libonnxruntime.so.1.20.0 \
//! cargo test -p kernel-privacy --features ner-gliner --test ner_parity -- --ignored --nocapture
//! ```

use std::collections::BTreeSet;
use std::env;

use kernel_privacy::ner::label_kind;
use kernel_privacy::span::EntityKind;
use kernel_privacy::{GlinerConfig, GlinerRecognizer};
use serde_json::Value;

const REFERENCE: &str = include_str!("../../gliner2/tests/fixtures/gliner2_en50_reference.json");

#[test]
#[ignore = "needs AUX_GLINER_MODEL_DIR and AUX_GLINER_ORT_DYLIB (see the module docs)"]
fn rust_gliner2_matches_the_library_on_the_fake_en_cases() {
    let model_dir = env::var("AUX_GLINER_MODEL_DIR").expect("AUX_GLINER_MODEL_DIR");
    let reference: Value = serde_json::from_str(REFERENCE).expect("reference fixture");

    let mut config = GlinerConfig::new(&model_dir);
    if let Ok(dylib) = env::var("AUX_GLINER_ORT_DYLIB") {
        config = config.with_ort_dylib(dylib);
    }
    let recognizer = GlinerRecognizer::load(config).expect("load GLiNER2");

    let cases = reference["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 50, "the reference holds the first 50 EN cases");
    let mut mismatches = Vec::new();

    for case in cases {
        let id = case["id"].as_str().expect("id");
        let text = case["text"].as_str().expect("text");
        let want: BTreeSet<(EntityKind, usize, usize, String)> = case["spans"]
            .as_array()
            .expect("spans")
            .iter()
            .map(|span| {
                let label = span["label"].as_str().expect("label");
                (
                    label_kind(label).unwrap_or_else(|| panic!("{id}: label {label}")),
                    span["start"].as_u64().expect("start") as usize,
                    span["end"].as_u64().expect("end") as usize,
                    span["text"].as_str().expect("text").to_string(),
                )
            })
            .collect();

        let report = recognizer
            .analyze_report(text)
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        let got: BTreeSet<(EntityKind, usize, usize, String)> = report
            .spans
            .iter()
            .map(|span| {
                (
                    span.kind,
                    span.start,
                    span.end,
                    text[span.start..span.end].to_string(),
                )
            })
            .collect();

        if got != want {
            mismatches.push(format!(
                "{id}:\n  only in library: {:?}\n  only in rust:    {:?}",
                want.difference(&got).collect::<Vec<_>>(),
                got.difference(&want).collect::<Vec<_>>(),
            ));
        }
    }

    println!(
        "{} cases, {} with a mismatch",
        cases.len(),
        mismatches.len()
    );
    assert!(
        mismatches.is_empty(),
        "Rust/library spans differ:\n{}",
        mismatches.join("\n")
    );
}
