# gliner2-rs

Zero-shot entity extraction with [GLiNER2](https://github.com/fastino-ai/GLiNER2)
over ONNX Runtime. You name the labels; you get back the spans of the text that
match them, with byte offsets into that text, a label and a score.

```rust
use gliner2_rs::{Gliner2, Options};

let model = Gliner2::load("models/gliner2-privacy-filter-PII-multi", &Options::default())?;
for entity in model.extract("Mara Ellison, mara@example.com", &["person", "email"], 0.5)? {
    println!("{} {}..{} {:.2}", entity.label, entity.start, entity.end, entity.score);
}
```

- `Gliner2::load(dir, &options)` reads `model.onnx` and `tokenizer.json` from `dir`;
  `Gliner2::load_paths` takes the two files explicitly.
- `extract(text, labels, threshold)` returns the spans, ordered by start, never
  overlapping. `extract_report` also returns the number of dropped spans and
  of windows.
- `Options` sets per-label score floors, the maximum span width (8, the graph's
  value), the window size (300 tokens) and the overlap (50 tokens), and an optional
  ONNX Runtime library path.
- Errors are `gliner2_rs::Error`: a missing file, a model, tokenizer or inference
  failure, or an invalid option. Nothing is reported as "no entities" on error.

## Requirements

- ONNX Runtime **1.20.0**, as a shared library, found through `Options::ort_dylib`
  or `ORT_DYLIB_PATH`. The crate loads it at run time (`ort` with `load-dynamic`),
  so the build downloads nothing.
- A model exported from the pinned checkpoint below. The crate does not ship one.

## The model

The graph is an export of `fastino/gliner2-privacy-filter-PII-multi`:

- revision `1cb4166094dc58fa8d836429f060d6c95f62b495`;
- licence **Apache-2.0** (model card);
- `model.safetensors` sha256 `0280f6f39f6012da50b6640bad438d9b7e763a1b0102094115d1b710c4dd79b6`,
  `tokenizer.json` sha256 `f6df10ec83bea993035b2dd7c39345a3d4fcf23421c2adb6cb4ffc1e6d1bc4b5`.

The export is `scripts/export-gliner2-onnx.py` (opset 17, fp32). The parity
gate is `scripts/gliner2-parity.py`: it checks the ONNX graph against PyTorch
(within 1e-4) and the decoded spans against the gliner2 library. Its reference
for this crate is `tests/fixtures/gliner2_en50_reference.json`, 50 fake English
cases. The integration test `tests/parity.rs` checks the crate against that
reference; run it with `--ignored` and the two `AUX_GLINER2_*` variables named
in its module docs.

## Licence

Apache-2.0, the workspace licence. The model is a separate work under its own
licence (above).

## Safety

The crate has no `unsafe` code. The `unsafe` in the dependency tree is inside
`ort`, which loads the ONNX Runtime library and calls its C API.
