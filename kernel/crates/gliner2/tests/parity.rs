//! Parity with the gliner2 library on the first 50 FAKE English cases.
//!
//! The reference is `tests/fixtures/gliner2_en50_reference.json`, written by
//! `scripts/gliner2-parity.py`. Ignored by default: it needs the exported model
//! directory and the ONNX Runtime 1.20 shared library.
//!
//! ```console
//! AUX_GLINER2_MODEL_DIR=/path/to/export \
//! AUX_GLINER2_ORT_DYLIB=/path/to/libonnxruntime.so.1.20.0 \
//! cargo test -p gliner2-rs --test parity -- --ignored --nocapture
//! ```

use std::collections::BTreeSet;
use std::env;

use gliner2_rs::{Gliner2, Options};
use serde_json::Value;

const REFERENCE: &str = include_str!("fixtures/gliner2_en50_reference.json");

#[test]
#[ignore = "needs AUX_GLINER2_MODEL_DIR and AUX_GLINER2_ORT_DYLIB (see the module docs)"]
fn matches_the_library_on_the_fake_en_cases() {
    let model_dir = env::var("AUX_GLINER2_MODEL_DIR").expect("AUX_GLINER2_MODEL_DIR");
    let reference: Value = serde_json::from_str(REFERENCE).expect("reference fixture");
    let labels: Vec<String> = reference["labels"]
        .as_array()
        .expect("labels")
        .iter()
        .map(|label| label.as_str().expect("label").to_string())
        .collect();
    let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    let default = reference["default_threshold"].as_f64().expect("default") as f32;

    let mut options = Options::default();
    if let Some(overrides) = reference["thresholds"].as_object() {
        for (label, value) in overrides {
            let value = value.as_f64().expect("threshold") as f32;
            options = options.with_label_threshold(label, value);
        }
    }
    if let Ok(dylib) = env::var("AUX_GLINER2_ORT_DYLIB") {
        options.ort_dylib = Some(dylib.into());
    }
    let model = Gliner2::load(&model_dir, &options).expect("load GLiNER2");

    let mut mismatches = Vec::new();
    for case in reference["cases"].as_array().expect("cases") {
        let id = case["id"].as_str().expect("id");
        let text = case["text"].as_str().expect("text");
        let want: BTreeSet<(String, usize, usize)> = case["spans"]
            .as_array()
            .expect("spans")
            .iter()
            .map(|span| {
                (
                    span["label"].as_str().expect("label").to_string(),
                    span["start"].as_u64().expect("start") as usize,
                    span["end"].as_u64().expect("end") as usize,
                )
            })
            .collect();
        let got: BTreeSet<(String, usize, usize)> = model
            .extract(text, &label_refs, default)
            .expect("extract")
            .into_iter()
            .map(|entity| (entity.label, entity.start, entity.end))
            .collect();
        if got != want {
            mismatches.push(format!(
                "{id}: library-only {:?}, rust-only {:?}",
                want.difference(&got).collect::<Vec<_>>(),
                got.difference(&want).collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "spans differ:\n{}",
        mismatches.join("\n")
    );
}
