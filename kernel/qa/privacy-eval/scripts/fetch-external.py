#!/usr/bin/env python3
"""Fetch public PII datasets and convert them to privacy-eval case JSONL.

Stdlib only. Downloads via the Hugging Face datasets-server rows API (JSON
pages) so no parquet reader is required. Output goes to
~/.cache/auxesis/privacy-eval-external/ and is never committed.

Datasets:
  * NVIDIA Nemotron-PII (nvidia/Nemotron-PII) - English, synthetic, CC BY 4.0
  * Gretel synthetic_pii_finance_multilingual - English + French rows only,
    Apache-2.0

Usage:
    python3 kernel/qa/privacy-eval/scripts/fetch-external.py
    python3 kernel/qa/privacy-eval/scripts/fetch-external.py --sample-size 500
"""
import argparse
import ast
import json
import os
import random
import ssl
import sys
import time
from collections import Counter
import urllib.parse
import urllib.request
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "auxesis" / "privacy-eval-external"
HF_ROWS = "https://datasets-server.huggingface.co/rows"

# Mapping from each dataset's native label to our span type. Labels not present
# here are counted (see unmapped counts) and not scored.
NEMOTRON_MAP = {
    "first_name": "person",
    "last_name": "person",
    "company_name": "org",
    "email": "email",
    "phone_number": "phone",
    "fax_number": "phone",
    "street_address": "address",
    "county": "address",
    "coordinate": "address",
    "iban": "iban",
    "credit_debit_card": "card",
    "ssn": "national_id",
    "tax_id": "national_id",
    "passport_number": "passport",
    "passport": "passport",
    "blood_type": "health",
    "medical_record_number": "health",
    "health_plan_beneficiary_number": "health",
    "religious_belief": "religion",
    "race_ethnicity": "ethnicity",
    "sexuality": "sexual_orientation",
    "password": "secret",
    "api_key": "secret",
    "pin": "secret",
    "http_cookie": "secret",
    "url": "url",
    "ipv4": "ipv4",
    "cvv": "secret",
    "user_name": "person",
    "date_of_birth": "date_of_birth",
}
GRETEL_MAP = {
    "name": "person",
    "first_name": "person",
    "last_name": "person",
    "company": "org",
    "street_address": "address",
    "email": "email",
    "phone_number": "phone",
    "iban": "iban",
    "credit_card_number": "card",
    "credit_card_security_code": "secret",
    "passport_number": "passport",
    "ssn": "national_id",
    "ipv4": "ipv4",
    "api_key": "secret",
    "password": "secret",
    "driver_license_number": "national_id",
    "account_pin": "secret",
    "customer_id": "national_id",
    "employee_id": "national_id",
    "local_latlng": "address",
    "date_of_birth": "date_of_birth",
}


def ssl_context():
    if os.path.exists("/etc/ssl/cert.pem"):
        return ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    return ssl.create_default_context()


CTX = ssl_context()


def fetch_pages(dataset, config, split, needed, max_pages=2000):
    """Fetch rows until we have `needed` matching rows (caller filters)."""
    out = []
    offset = 0
    pages = 0
    while len(out) < needed and pages < max_pages:
        url = "{}?{}".format(HF_ROWS, urllib.parse.urlencode({
            "dataset": dataset, "config": config, "split": split,
            "offset": offset, "limit": 100,
        }))
        for attempt in range(5):
            try:
                with urllib.request.urlopen(url, context=CTX, timeout=60) as resp:
                    data = json.load(resp)
                break
            except Exception as exc:
                if attempt < 4:
                    time.sleep(15 * (attempt + 1))
                    continue
                # A silent prefix is not a random sample: fail the run.
                sys.exit(f"fetch error at offset {offset}: {exc}")
        rows = data.get("rows", [])
        if not rows:
            break
        out.extend(rows)
        offset += len(rows)
        pages += 1
        time.sleep(1.0)
    return out


def nemotron_cases(rows, sample_size, seed, unmapped_counter):
    rng = random.Random(seed)
    collected = []
    for r in rows:
        row = r["row"]
        text = row.get("text", "")
        if not text:
            continue
        spans_raw = row.get("spans", "")
        try:
            spans_list = ast.literal_eval(spans_raw) if isinstance(spans_raw, str) else spans_raw
        except (ValueError, SyntaxError):
            continue
        if not isinstance(spans_list, list):
            continue
        spans = []
        for s in spans_list:
            label = s.get("label")
            our = NEMOTRON_MAP.get(label)
            if our is None:
                unmapped_counter[label] += 1
                continue
            start = s.get("start")
            end = s.get("end")
            if not isinstance(start, int) or not isinstance(end, int):
                continue
            if not (0 <= start < end <= len(text)):
                continue
            spans.append({"type": our, "start": start, "end": end})
        collected.append({"lang": "en", "text": text, "spans": spans})
    rng.shuffle(collected)
    collected = collected[:sample_size]
    cases = []
    for i, c in enumerate(collected):
        c["id"] = "en-nemotron-{:04d}".format(i)
        cases.append(c)
    return cases


def gretel_cases(rows, sample_size, seed, unmapped_counter, lang_filter):
    rng = random.Random(seed)
    collected = []
    for r in rows:
        row = r["row"]
        language = row.get("language", "")
        if language not in lang_filter:
            continue
        lang = "en" if language == "English" else "fr"
        text = row.get("generated_text", "")
        if not text:
            continue
        spans_raw = row.get("pii_spans", [])
        try:
            spans_list = json.loads(spans_raw) if isinstance(spans_raw, str) else spans_raw
        except json.JSONDecodeError:
            continue
        if not isinstance(spans_list, list):
            continue
        spans = []
        for s in spans_list:
            label = s.get("label")
            our = GRETEL_MAP.get(label)
            if our is None:
                unmapped_counter[label] += 1
                continue
            start = s.get("start")
            end = s.get("end")
            if not isinstance(start, int) or not isinstance(end, int):
                continue
            if not (0 <= start < end <= len(text)):
                continue
            spans.append({"type": our, "start": start, "end": end})
        collected.append({"lang": lang, "text": text, "spans": spans})
    rng.shuffle(collected)
    collected = collected[:sample_size]
    cases = []
    for i, c in enumerate(collected):
        c["id"] = "{}-gretel-{:04d}".format(c["lang"], i)
        cases.append(c)
    return cases


def write_jsonl(path, cases):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-size", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", type=Path, default=CACHE_DIR)
    parser.add_argument("--datasets", default="all",
                        choices=["all", "nemotron", "gretel"])
    args = parser.parse_args()

    out_dir = args.output_dir

    def git_root(start):
        cur = start.resolve()
        while True:
            if (cur / ".git").exists():
                return cur
            if cur.parent == cur:
                return None
            cur = cur.parent

    # The repo is found from this script, not the caller's cwd.
    root = git_root(Path(__file__).resolve().parent)
    if root is not None:
        try:
            out_dir.resolve().relative_to(root)
        except ValueError:
            pass
        else:
            print("refusing --output-dir inside the git repo: {}".format(out_dir),
                  file=sys.stderr)
            return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.datasets in ("all", "nemotron"):
        print("Fetching Nemotron-PII ...", file=sys.stderr)
        rows = fetch_pages("nvidia/Nemotron-PII", "default", "train",
                           10 ** 9)
        unmapped = {}
        uc = Counter()
        cases = nemotron_cases(rows, args.sample_size, args.seed, uc)
        write_jsonl(out_dir / "nemotron-pii.jsonl", cases)
        print("Nemotron: {} cases -> {}".format(len(cases), out_dir / "nemotron-pii.jsonl"))
        if uc:
            print("Nemotron unmapped labels: " + ", ".join(
                "{}={}".format(k, v) for k, v in sorted(uc.items())), file=sys.stderr)

    if args.datasets in ("all", "gretel"):
        print("Fetching Gretel ...", file=sys.stderr)
        rows = fetch_pages("gretelai/synthetic_pii_finance_multilingual",
                           "default", "train", 10 ** 9)
        uc = Counter()
        cases = gretel_cases(rows, args.sample_size, args.seed, uc,
                             {"English", "France"})
        write_jsonl(out_dir / "gretel-pii.jsonl", cases)
        print("Gretel: {} cases -> {}".format(len(cases), out_dir / "gretel-pii.jsonl"))
        if uc:
            print("Gretel unmapped labels: " + ", ".join(
                "{}={}".format(k, v) for k, v in sorted(uc.items())), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())