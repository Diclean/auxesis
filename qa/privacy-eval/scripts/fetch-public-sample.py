#!/usr/bin/env python3
"""Fetch a deterministic sample of two public synthetic PII datasets.

Writes qa/privacy-eval-style JSONL case files (code-point spans) into the
directory given as the first argument. Stdlib only. Run with `python3 -I`.

Usage: python3 -I qa/privacy-eval/scripts/fetch-public-sample.py OUT_DIR
"""
import ast
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, OrderedDict

CA_CANDIDATES = [
    os.environ.get("SSL_CERT_FILE"),
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/System/Library/OpenSSL/certs/cert.pem",
]


def _ca_file():
    for c in CA_CANDIDATES:
        if c and os.path.isfile(c):
            return c
    return None


def _ssl_context():
    ca = _ca_file()
    if ca:
        return ssl.create_default_context(cafile=ca)
    # Never fall back to an unverified connection: use the system trust store or stop.
    return ssl.create_default_context()


CTX = _ssl_context()

BASE = "https://datasets-server.huggingface.co/rows"


def fetch_rows(dataset, config, split, offset, length, retries=5):
    url = "{}?dataset={}&config={}&split={}&offset={}&length={}".format(
        BASE, dataset, config, split, offset, length
    )
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, context=CTX, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 429:
                wait = 10 * (attempt + 1)
            else:
                wait = 2 ** attempt
            if attempt < retries - 1:
                time.sleep(wait)
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise RuntimeError("fetch failed {}: {}".format(url, last))


def nemotron_label_map():
    # Explicit mapping: label -> our kind or None (not scored, by design).
    return {
        "email": "email",
        "phone_number": "phone",
        "fax_number": "phone",
        "credit_debit_card": "card",
        "ssn": "national_id",
        "tax_id": "national_id",
        "password": "secret",
        "api_key": "secret",
        # Everything else is reported but not scored.
    }


def gretel_label_map():
    return {
        "email": "email",
        "phone_number": "phone",
        "iban": "iban",
        "credit_card_number": "card",
        "ssn": "national_id",
        "driver_license_number": "national_id",
        "passport_number": "national_id",
        "password": "secret",
        "api_key": "secret",
        "account_pin": "secret",
    }


NEMOTRON_ALL_LABELS = [
    "first_name", "date", "company_name", "last_name", "email", "phone_number",
    "street_address", "url", "country", "state", "city", "county", "date_of_birth",
    "time", "occupation", "biometric_identifier", "ssn", "customer_id",
    "certificate_license_number", "employment_status", "swift_bic", "pin",
    "credit_debit_card", "medical_record_number", "mac_address", "date_time",
    "bank_routing_number", "license_plate", "coordinate", "vehicle_identifier",
    "education_level", "health_plan_beneficiary_number", "account_number", "age",
    "political_view", "employee_id", "postcode", "blood_type",
    "religious_belief", "gender", "cvv", "device_identifier", "race_ethnicity",
    "sexuality", "user_name", "password", "fax_number", "http_cookie", "ipv4",
    "language",
]


def map_span(label, mapping):
    return mapping.get(label, None)  # None means not scored


def make_case(lang, text, spans, idx):
    return {
        "id": "{}-pub-{:04d}".format(lang, idx),
        "lang": lang,
        "kind": "scan_text",
        "text": text,
        "spans": spans,
        "expect_residue": False,
        "triage_label": "relevant",
        "notes": "public dataset",
    }


def fetch_nemotron(out_dir):
    mapping = nemotron_label_map()
    all_labels = Counter()
    cases = []
    idx = 0
    for batch in range(30):
        offset = batch * 100
        data = fetch_rows("nvidia/Nemotron-PII", "default", "train", offset, 100)
        time.sleep(0.1)
        for row in data["rows"]:
            r = row["row"]
            text = r["text"]
            # Nemotron spans is a Python repr string.
            try:
                raw_spans = ast.literal_eval(r["spans"])
            except Exception:
                raw_spans = []
            spans = []
            for s in raw_spans:
                label = s.get("label")
                all_labels[label] += 1
                kind = map_span(label, mapping)
                if kind is None:
                    continue
                spans.append({"type": kind, "start": s["start"], "end": s["end"]})
            # Nemotron is English.
            cases.append(make_case("en", text, spans, idx))
            idx += 1
    # write
    path = os.path.join(out_dir, "nemotron.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print("Nemotron: {} cases -> {}".format(len(cases), path))
    print("Nemotron label map (explicit):")
    seen = sorted(all_labels)
    for label in seen:
        kind = mapping.get(label, None)
        print("  {:32s} -> {}".format(label, kind if kind else "not scored (by design)"))
    print("Nemotron unmapped labels and counts:")
    for label, n in sorted((l for l in all_labels.items() if mapping.get(l[0]) is None)):
        print("  {:32s} {}".format(label, n))
    return all_labels


GRETEL_LANG = OrderedDict([
    ("English", "en"),
    ("France", "fr"),
    ("German", "de"),
    ("Dutch", "nl"),
    ("Spanish", "es"),
    ("Italian", "it"),
])


def fetch_gretel(out_dir):
    mapping = gretel_label_map()
    all_labels = Counter()
    counts = {lang: 0 for lang in GRETEL_LANG.values()}
    cases = []
    idx = {lang: 0 for lang in GRETEL_LANG.values()}
    offset = 0
    max_rows = 60000
    while any(counts[l] < 500 for l in counts) and offset < max_rows:
        try:
            data = fetch_rows("gretelai/synthetic_pii_finance_multilingual", "default", "train", offset, 100)
        except Exception as e:
            # A short sample is not the deterministic sample: fail instead of writing it.
            raise SystemExit("Gretel fetch error at offset {}: {}".format(offset, e))
        rows = data.get("rows", [])
        if not rows:
            break
        for row in rows:
            r = row["row"]
            lang_name = r.get("language")
            if lang_name not in GRETEL_LANG:
                continue
            lang = GRETEL_LANG[lang_name]
            if counts[lang] >= 500:
                continue
            text = r.get("generated_text", "")
            if not text:
                continue
            try:
                raw_spans = json.loads(r["pii_spans"])
            except Exception:
                raw_spans = []
            spans = []
            for s in raw_spans:
                label = s.get("label")
                all_labels[label] += 1
                kind = map_span(label, mapping)
                if kind is None:
                    continue
                spans.append({"type": kind, "start": s["start"], "end": s["end"]})
            case = make_case(lang, text, spans, idx[lang])
            cases.append(case)
            idx[lang] += 1
            counts[lang] += 1
        offset += len(rows)
        time.sleep(0.15)
        # progress
        if offset % 1000 == 0:
            print("Gretel offset {} counts {}".format(offset, dict(counts)), file=sys.stderr)
    path = os.path.join(out_dir, "gretel.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print("Gretel: {} cases -> {}".format(len(cases), path))
    print("Gretel counts per lang: {}".format(counts))
    print("Gretel label map (explicit):")
    for label in sorted(all_labels):
        kind = mapping.get(label, None)
        print("  {:32s} -> {}".format(label, kind if kind else "not scored (by design)"))
    print("Gretel unmapped labels and counts:")
    for label, n in sorted((l for l in all_labels.items() if mapping.get(l[0]) is None)):
        print("  {:32s} {}".format(label, n))
    return all_labels


def main():
    if len(sys.argv) != 2:
        print("usage: {} OUT_DIR".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    fetch_nemotron(out_dir)
    fetch_gretel(out_dir)
    print("done")


if __name__ == "__main__":
    main()
