#!/usr/bin/env python3
"""Parity gate for the GLiNER2-PII ONNX export, and the reference spans for the Rust runner.

    venv-gliner2/bin/python -I scripts/gliner2-parity.py <model_dir> <model.onnx> <cases.jsonl> <fixture.json>

For the first 50 cases of `cases.jsonl` (fake data only), every 300-token window
is run four ways:

1. the gliner2 library (`extract_entities`), which is the reference;
2. the PyTorch span path from `export-gliner2-onnx.py`;
3. the ONNX graph, through ONNX Runtime;
4. a Python decode of the ONNX probabilities, written the way the Rust runner does it.

The gate fails unless ONNX and PyTorch agree within 1e-4 on every span probability
and count logit, the ONNX decode gives the same spans as the library, and the
spans the library returns are the same at every per-label threshold. The
fixture holds the reference spans (byte offsets) and the sha256 of each
window's input ids, so that the Rust test can locate any drift.
"""

import hashlib
import importlib.util
import json
import os
import struct
import sys

import numpy as np
import onnxruntime as ort
import torch
from gliner2 import GLiNER2
from tokenizers import Tokenizer

CHUNK_TOKENS = 300
CHUNK_OVERLAP = 50
CASES = 50
PROB_TOLERANCE = 1e-4
DEFAULT_THRESHOLD = 0.5
MIN_THRESHOLD = 0.4

# The native GLiNER2-PII labels, and the two zero-shot labels for health and religion.
# Map to EntityKind in crates/kernel-privacy/src/ner.rs; keep the two lists in step.
LABELS = [
    "person",
    "address",
    "phone_number",
    "email",
    "iban",
    "payment_card",
    "passport_number",
    "national_id_number",
    "date_of_birth",
    "organization",
    "health condition",
    "religion",
]
THRESHOLDS = {"health condition": 0.4}
INPUT_NAMES = ["input_ids", "attention_mask", "text_word_indices", "schema_special_indices"]

SCRIPTS = os.path.dirname(os.path.abspath(__file__))


def load_exporter():
    spec = importlib.util.spec_from_file_location(
        "export_gliner2_onnx", os.path.join(SCRIPTS, "export-gliner2-onnx.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def windows(tokenizer, text):
    """Character ranges of 300-token windows with 50 tokens of overlap (as ner_run.py)."""
    encoding = tokenizer.encode(text, add_special_tokens=False)
    offsets = encoding.offsets
    if len(offsets) <= CHUNK_TOKENS:
        return [(0, len(text))]
    step = CHUNK_TOKENS - CHUNK_OVERLAP
    out, start = [], 0
    while True:
        end = min(start + CHUNK_TOKENS, len(offsets))
        out.append((offsets[start][0], offsets[end - 1][1]))
        if end >= len(offsets):
            break
        start += step
    return out


def byte_offset(text, index):
    return len(text[:index].encode("utf-8"))


def input_ids_sha256(ids):
    return hashlib.sha256(b"".join(struct.pack("<q", int(i)) for i in ids)).hexdigest()


def decode(probs, start_map, end_map, chunk, threshold):
    """Per-label candidates above `threshold`, greedy by score, as finalize_spans does."""
    candidates = []
    count, width = probs.shape
    for start in range(count):
        for w in range(width):
            score = probs[start, w]
            end = start + w
            if score >= threshold and end < count:
                char_start, char_end = start_map[start], end_map[end]
                value = chunk[char_start:char_end].strip()
                if value:
                    candidates.append((float(score), char_start, char_end, value))
    ranked = sorted(candidates, key=lambda c: c[0], reverse=True)
    kept = []
    for candidate in ranked:
        if any(candidate[1] < k[2] and k[1] < candidate[2] for k in kept):
            continue
        kept.append(candidate)
    return kept


def consolidate(spans):
    """Global greedy by score, then ordered by start (as kernel-privacy's consolidate)."""
    ranked = sorted(spans, key=lambda s: (-s["score"], s["start"], s["end"]))
    kept = []
    for span in ranked:
        if any(span["start"] < k["end"] and k["start"] < span["end"] for k in kept):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: (s["start"], s["end"]))


def main(model_dir, onnx_path, cases_path, fixture_path):
    exporter = load_exporter()
    model = GLiNER2.from_pretrained(model_dir)
    wrapper = exporter.build_wrapper(model)
    session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    tokenizer = Tokenizer.from_file(os.path.join(model_dir, "tokenizer.json"))
    schema = model.create_schema().entities(LABELS).build()

    with open(cases_path, encoding="utf-8") as handle:
        cases = [json.loads(line) for line in handle][:CASES]

    failures = []
    worst_prob = 0.0
    worst_count = 0.0
    report = {"labels": LABELS, "thresholds": THRESHOLDS, "default_threshold": DEFAULT_THRESHOLD,
              "min_threshold": MIN_THRESHOLD, "chunk_tokens": CHUNK_TOKENS,
              "chunk_overlap": CHUNK_OVERLAP, "onnx_file_sha256": None, "cases": []}
    with open(onnx_path, "rb") as handle:
        report["onnx_file_sha256"] = hashlib.sha256(handle.read()).hexdigest()

    for case in cases:
        text = case["text"]
        entry = {"id": case["id"], "lang": case.get("lang", "en"), "text": text,
                 "windows": [], "spans": []}
        merged = []
        for ws, we in windows(tokenizer, text):
            chunk = text[ws:we]
            batch = model.processor.collate_fn_inference([(chunk, schema)], error_policy="raise")
            feeds = {
                "input_ids": batch.input_ids.numpy().astype(np.int64),
                "attention_mask": batch.attention_mask.numpy().astype(np.int64),
                "text_word_indices": batch.text_word_indices.numpy().astype(np.int64),
                "schema_special_indices": np.array(
                    [batch.schema_special_indices[0][0]], dtype=np.int64),
            }
            with torch.no_grad():
                torch_probs, torch_counts = wrapper(
                    *(torch.from_numpy(feeds[name]) for name in INPUT_NAMES))
            onnx_probs, onnx_counts = session.run(None, feeds)
            diff = np.abs(torch_probs.numpy() - onnx_probs).max()
            count_diff = np.abs(torch_counts.numpy() - onnx_counts).max()
            worst_prob = max(worst_prob, float(diff))
            worst_count = max(worst_count, float(count_diff))
            if diff > PROB_TOLERANCE or count_diff > PROB_TOLERANCE:
                failures.append(f"{case['id']}: onnx/torch diff {diff:.2e} counts {count_diff:.2e}")

            # Reference: the library's own spans for this window, at the lowest threshold.
            library = model.extract_entities(
                chunk, LABELS, threshold=MIN_THRESHOLD, include_confidence=True, include_spans=True)
            library_spans = {(label, s["start"], s["end"])
                             for label, items in library.get("entities", {}).items()
                             for s in items}

            # Decode the ONNX probabilities, the way the Rust runner does.
            start_map, end_map, normalized = word_offsets(tokenizer, chunk)
            ids = feeds["input_ids"][0]
            entry["windows"].append({"start": byte_offset(text, ws), "end": byte_offset(text, we),
                                     "ids_sha256": input_ids_sha256(ids)})
            decoded_spans = set()
            for index, label in enumerate(LABELS):
                kept = decode(onnx_probs[index], start_map, end_map, normalized, MIN_THRESHOLD)
                for score, char_start, char_end, value in kept:
                    decoded_spans.add((label, char_start, char_end))
                    # A span that runs into the appended "." is not in the source text.
                    if char_end <= len(chunk):
                        merged.append({"label": label, "score": score, "start": ws + char_start,
                                       "end": ws + char_end, "value": value})
            if decoded_spans != library_spans:
                failures.append(f"{case['id']}: decode {sorted(decoded_spans)} "
                                f"!= library {sorted(library_spans)}")

        final = []
        for span in merged:
            threshold = THRESHOLDS.get(span["label"], DEFAULT_THRESHOLD)
            if span["score"] < threshold:
                continue
            final.append({"label": span["label"], "score": span["score"],
                          "start": span["start"], "end": span["end"], "value": span["value"]})
        for span in consolidate(final):
            entry["spans"].append({"label": span["label"], "score": round(span["score"], 6),
                                   "start": byte_offset(text, span["start"]),
                                   "end": byte_offset(text, span["end"]),
                                   "text": span["value"]})
        report["cases"].append(entry)

    report["worst_prob_diff"] = worst_prob
    report["worst_count_diff"] = worst_count
    report["failures"] = failures
    with open(fixture_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=1, sort_keys=True)
        handle.write("\n")
    print(f"cases={len(cases)} spans={sum(len(c['spans']) for c in report['cases'])} "
          f"worst_prob_diff={worst_prob:.3e} worst_count_diff={worst_count:.3e} "
          f"failures={len(failures)}")
    for failure in failures[:20]:
        print("FAIL", failure)
    if failures or worst_prob > PROB_TOLERANCE:
        raise SystemExit(1)


def word_offsets(tokenizer, chunk):
    """Char offsets of each word, and the normalised text the model sees (as _normalize_text)."""
    from gliner2.processing.word_splitter import WhitespaceTokenSplitter

    normalized = chunk if chunk.endswith((".", "!", "?")) else chunk + "."
    starts, ends = [], []
    for _, start, end in WhitespaceTokenSplitter()(normalized, lower=True):
        starts.append(start)
        ends.append(end)
    return starts, ends, normalized


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    main(*sys.argv[1:])
