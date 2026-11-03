#!/usr/bin/env python3
"""Export the GLiNER2-PII span path to ONNX (fp32) for `kernel-privacy` (feature `ner-gliner`).

gliner2 2.1.0 ships no ONNX exporter, so this script writes one. It runs on the
build server, in the pinned venv, never on a laptop:

    venv-gliner2/bin/python -I scripts/export-gliner2-onnx.py <model_dir> <out_dir>

`model_dir` is the pinned `fastino/gliner2-privacy-filter-PII-multi` checkout
(revision 1cb4166094dc58fa8d836429f060d6c95f62b495). Both `model.safetensors`
and `tokenizer.json` are checked against their recorded sha256 before anything
is loaded. Output: `<out_dir>/model.onnx`, a copy of `tokenizer.json`, and
`MANIFEST.json` with the sha256 and the I/O signature of the graph.

The graph is the span path of `SpanExtractor` in eval mode: the DeBERTa-v2
encoder, the `[P]` count head, the count-aware field queries and the span
scorer. The decoder only reads count step 0, and the GRU is causal, so the
queries are built with a count of 1. Batch size is always 1.

Inputs (int64):
  input_ids               [1, S]      subword ids of "( [P] entities ( [E] f1 [E] f2 ... ) ) [SEP_TEXT] words"
  attention_mask          [1, S]      all ones
  text_word_indices       [1, N]      position of the first subword of each text word
  schema_special_indices  [1, 1 + F]  position of the [P] token, then one position per [E] token
Outputs (float32):
  span_probs              [F, N, W]   sigmoid span score; W = max_width; 0 for spans running past the text
  count_logits            [20]        count head; argmax 0 means no entity instance

The export is checked with `onnx.checker`. It must use an opset of at most 19,
so that it loads in ONNX Runtime 1.20, the version the Rust `ort` setup uses.
"""

import hashlib
import json
import os
import shutil
import sys

import onnx
import torch
import torch.nn.functional as F
from gliner2 import GLiNER2

OPSET = 17
MAX_OPSET = 19
MODEL_SHA256 = "0280f6f39f6012da50b6640bad438d9b7e763a1b0102094115d1b710c4dd79b6"
TOKENIZER_SHA256 = "f6df10ec83bea993035b2dd7c39345a3d4fcf23421c2adb6cb4ffc1e6d1bc4b5"  # gitleaks:allow
REVISION = "1cb4166094dc58fa8d836429f060d6c95f62b495"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class SpanPath(torch.nn.Module):
    """The span path of gliner2's SpanExtractor, with its gathers and masks made explicit."""

    def __init__(self, model):
        super().__init__()
        self.encoder = model.encoder
        self.count_pred = model.count_pred
        self.count_embed = model.count_embed
        self.span_marker = model.span_rep.span_rep_layer
        self.max_width = model.max_width

    def span_logits(self, words, queries):
        # Mirrors SpanMarkerV0.score_queries (eval mode), with the unfold replaced
        # by an explicit gather so that the graph exports.
        marker = self.span_marker
        first = marker.out_project[0]
        final = marker.out_project[3]
        hidden_size = words.shape[-1]
        start_rep = marker.project_start(words).relu()
        end_rep = marker.project_end(words).relu()
        start_hidden = F.linear(start_rep, first.weight[:, :hidden_size])
        end_hidden = F.linear(end_rep, first.weight[:, hidden_size:])
        count = words.shape[0]
        ends = torch.arange(count).unsqueeze(1) + torch.arange(self.max_width).unsqueeze(0)
        valid = ends < count
        end_windows = end_hidden[ends.clamp(max=count - 1)]
        hidden = (start_hidden.unsqueeze(1) + end_windows + first.bias).relu()
        folded = queries @ final.weight
        query_bias = queries @ final.bias
        logits = torch.einsum("nwk,fk->fnw", hidden, folded) + query_bias[:, None, None]
        return logits.masked_fill(~valid.unsqueeze(0), float("-inf"))

    def forward(self, input_ids, attention_mask, text_word_indices, schema_special_indices):
        hidden = self.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state[0]
        words = hidden.index_select(0, text_word_indices[0])
        schema = hidden.index_select(0, schema_special_indices[0])
        count_logits = self.count_pred(schema[:1])[0]
        queries = self.count_embed(schema[1:], 1)[0]
        return torch.sigmoid(self.span_logits(words, queries)), count_logits


def build_wrapper(model):
    model.eval()
    model.encoder.config._attn_implementation = "eager"
    wrapper = SpanPath(model).eval()
    return wrapper


def dummy_inputs(words=5, fields=2):
    # Ids are arbitrary: the trace depends on shapes, not on values.
    seq = 1 + 2 * (fields + 2) + words * 2
    input_ids = torch.arange(1, seq + 1, dtype=torch.long).unsqueeze(0) % 1000
    attention_mask = torch.ones_like(input_ids)
    text_word_indices = torch.arange(words, dtype=torch.long).unsqueeze(0) * 2 + 2 + 1
    schema_special_indices = torch.tensor([[0] + [2 * i + 2 for i in range(1, fields + 1)]], dtype=torch.long)
    return input_ids, attention_mask, text_word_indices, schema_special_indices


def export(model_dir, out_dir):
    model_path = os.path.join(model_dir, "model.safetensors")
    tokenizer_path = os.path.join(model_dir, "tokenizer.json")
    if sha256_file(model_path) != MODEL_SHA256:
        raise SystemExit(f"{model_path}: sha256 does not match the pinned revision {REVISION}")
    if sha256_file(tokenizer_path) != TOKENIZER_SHA256:
        raise SystemExit(f"{tokenizer_path}: sha256 does not match the pinned revision {REVISION}")

    os.makedirs(out_dir, exist_ok=True)
    model = GLiNER2.from_pretrained(model_dir)
    wrapper = build_wrapper(model)
    onnx_path = os.path.join(out_dir, "model.onnx")
    inputs = dummy_inputs()
    names = ["input_ids", "attention_mask", "text_word_indices", "schema_special_indices"]
    with torch.no_grad():
        torch.onnx.export(
            wrapper,
            inputs,
            onnx_path,
            input_names=names,
            output_names=["span_probs", "count_logits"],
            dynamic_axes={
                "input_ids": {1: "seq"},
                "attention_mask": {1: "seq"},
                "text_word_indices": {1: "words"},
                "schema_special_indices": {1: "schema_slots"},
                "span_probs": {0: "fields", 1: "words"},
            },
            opset_version=OPSET,
            dynamo=False,
            do_constant_folding=True,
        )

    graph = onnx.load(onnx_path)
    onnx.checker.check_model(graph)
    opsets = {imp.domain or "ai.onnx": imp.version for imp in graph.opset_import}
    if opsets.get("ai.onnx", 0) > MAX_OPSET:
        raise SystemExit(f"opset {opsets} is above {MAX_OPSET}: ONNX Runtime 1.20 cannot load it")

    shutil.copyfile(tokenizer_path, os.path.join(out_dir, "tokenizer.json"))
    manifest = {
        "model": "fastino/gliner2-privacy-filter-PII-multi",
        "revision": REVISION,
        "source_model_safetensors_sha256": MODEL_SHA256,
        "exporter": "scripts/export-gliner2-onnx.py",
        "opset": opsets,
        "torch": torch.__version__,
        "gliner2": "2.1.0",
        "max_width": model.max_width,
        "inputs": [
            {"name": name, "dtype": "int64", "shape": "see dynamic_axes"} for name in names
        ],
        "outputs": ["span_probs (float32 [F, N, W])", "count_logits (float32 [20])"],
        "files": {
            name: {"sha256": sha256_file(os.path.join(out_dir, name)),
                   "bytes": os.path.getsize(os.path.join(out_dir, name))}
            for name in ("model.onnx", "tokenizer.json")
        },
    }
    with open(os.path.join(out_dir, "MANIFEST.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(json.dumps(export(sys.argv[1], sys.argv[2]), indent=2, sort_keys=True))
