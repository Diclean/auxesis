#!/usr/bin/env python3
"""Validate the FAKE privacy eval corpus in qa/privacy-eval/. Standard library only.

Run from the repository root:

    python3 -I qa/privacy-eval/scripts/check-privacy-eval.py

Checks:
  1. every case validates against schema.json (JSON Schema subset, see validate());
  2. spans: 0 <= start < end <= len(text), sorted, no overlap, offsets index text;
  3. checksums of identifier spans: IBAN mod-97 (known country lengths),
     national_id by length (15 digits = FR NIR key and department 00, 13 = ZA Luhn,
     9 = HU TAJ, 18 = CN resident ID or CN USCC), company IDs by check digit or format
     (see national_id_ok), card = UnionPay 62, 16 to 19 digits, Luhn,
     passport = zh: E + 8 digits, EA + 7 or G + 8, at least four zeros;
     other languages: three capitals and seven digits (passport_ok);
  4. phone-like and e-mail-like text is fictional: phones only in the allowlist
     below, e-mails only under the .invalid TLD. Identifier spans are masked
     before the text scan, so IBAN and ID digits do not trip it;
  5. public terms (public-terms.json) are never a span, and every public_trap
     case contains at least one;
  6. canaries: unique, script matches their letters, each appears as a span of
     its type in a case of its language;
  7. per-language minimum counts per kind, every entity type present in the
     corpus, the per-language core types present, >= 1 residue case per language,
     and a complete triage label set in triage cases;
  8. zh passports: at least half sit near a passport keyword (护照 or passport within
     PASSPORT_WINDOW characters), and at least one does not, so both paths are measured.
Exit status 0 on PASS, 1 on FAIL. Prints per-language counts and a corpus hash.
"""
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LANGS = ["fr", "en", "af", "hu", "ar", "ru", "zh"]
KINDS = {"short": 20, "thread": 4, "scan_text": 2, "triage": 10, "injection": 5, "public_trap": 10}
TYPES = ["person", "org", "address", "phone", "email", "iban", "passport",
         "national_id", "card", "health", "religion", "date_of_birth", "handle"]
CORE_TYPES = {"person", "org", "address", "phone", "email", "iban", "passport",
              "date_of_birth", "health", "religion"}
NATIONAL_ID_LANGS = {"fr", "en", "af", "hu", "zh"}
IDENT_TYPES = {"iban", "national_id", "passport", "card"}
PASSPORT_KEYWORDS = ("护照", "passport", "Passport")
PASSPORT_WINDOW = 40  # characters either side of a passport span
CN_UNALLOCATED_REGION = "99"  # GB/T 2260: no administrative division code starts with 99, so these are fictional
IBAN_LEN = {"FR": 27, "HU": 28, "RU": 33, "ZA": 26, "MA": 28, "GB": 22}
SCRIPTS = {"Latin": "LATIN", "Cyrillic": "CYRILLIC", "Arabic": "ARABIC"}
OCR = str.maketrans("OoIl", "0011")  # OCR confusions: O/o -> 0, I/l -> 1

D_CHARS = r"\dOoIl"  # digit, or an OCR-confusable letter inside a phone candidate
D = f"[{D_CHARS}]"
PHONE_CANDIDATES = [
    re.compile(rf"\+{D}[{D_CHARS} ().\-]*{D}"),
    re.compile(rf"(?<!\w)[0O]{D}(?:[ .\-]?{D}){{8,}}(?!\w)"),
    re.compile(rf"(?<!\w)\(?{D}{{3}}\)?[ .\-]{D}{{3}}[ .\-]{D}{{4}}(?!\w)"),
]
PHONE_ALLOWED = [  # fictional ranges only; digits after normalisation
    re.compile(r"3319900\d{4}"),        # FR +33 1 99 00 xx xx
    re.compile(r"0199\d{6}"),           # FR national 01 99 00 xx xx
    re.compile(r"1?\d{3}55501\d\d"),    # US 555-01xx (fictional block), with or without country code
    re.compile(r"447700900\d{3}"),      # UK 07700 900xxx (drama range)
    re.compile(r"(?:7|27|36|212)0{8}1"), # unallocated: CC 7, 27, 36, 212 then 00 000 0001 only
    re.compile(r"(?:0086|86)?1[3-9]\d0{4}\d{4}"),  # CN mobile 3-4-4, fictional middle block 0000 (owner review)
    re.compile(r"(?:0086|86|0)?100\d{7}"),         # CN Beijing 010, local number starts with 0 (unallocated)
]
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def validate(value, schema, path, errors):
    """Subset of JSON Schema 2020-12: type, enum, pattern, minLength, minimum,
    required, properties, additionalProperties (false), items."""
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in enum")
    kind = schema.get("type")
    if kind:
        py = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}[kind]
        if not isinstance(value, py) or (kind == "integer" and isinstance(value, bool)):
            errors.append(f"{path}: expected {kind}")
            return
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than minLength")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: pattern mismatch")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value):
            errors.append(f"{path}: below minimum")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{path}: unexpected key {key}")
        for key, sub in props.items():
            if key in value:
                validate(value[key], sub, f"{path}.{key}", errors)
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            validate(item, schema["items"], f"{path}[{i}]", errors)


def iban_ok(value):
    s = "".join(value.split())  # spans may wrap across lines in natural e-mails
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    if IBAN_LEN.get(s[:2]) != len(s):
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


def luhn_ok(d):
    total = 0
    for i, ch in enumerate(reversed(d)):
        v = int(ch)
        if i % 2 == 1:
            v *= 2
            v = v - 9 if v > 9 else v
        total += v
    return total % 10 == 0


def cn_resident_ok(d):
    """CN resident identity card (GB 11643-1999): 17 digits, then a MOD 11-2 check
    character (X = 10). The region code must be 99xxxx, which is unallocated."""
    if not re.fullmatch(r"\d{17}[\dX]", d):
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    total = sum(int(x) * w for x, w in zip(d[:17], weights))
    return "10X98765432"[total % 11] == d[17] and d[:2] == CN_UNALLOCATED_REGION


def cn_uscc_ok(d):
    """CN unified social credit code (GB 32100-2015): 18 characters from a 31-symbol
    set, the last one a check character over the first 17 (weights below). The
    registration-authority region (characters 3 and 4) must be 99, unallocated."""
    charset = "0123456789ABCDEFGHJKLMNPQRTUWXY"
    if len(d) != 18 or any(ch not in charset for ch in d):
        return False
    weights = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]
    total = sum(charset.index(ch) * w for ch, w in zip(d[:17], weights))
    return charset[(31 - total % 31) % 31] == d[17] and d[2:4] == CN_UNALLOCATED_REGION


def card_ok(value):
    """Payment card: UnionPay (62...), 16 to 19 digits, Luhn-valid. Spaces and
    hyphens are grouping, and full-width digits are folded before the check."""
    d = re.sub(r"[\s\-]", "", unicodedata.normalize("NFKC", value))
    return re.fullmatch(r"62\d{14,17}", d) is not None and luhn_ok(d)


def national_id_ok(value, lang=None):
    """Whether `value` checks out as a national or company identifier.

    `lang` selects the per-language company-ID rules (GB VAT, `en` Companies
    House, `ar` commercial register, `ru` INN/OGRN, `hu` TAJ) and the `zh` rules
    (CN resident ID and USCC, both 18 characters). It is optional so
    the older one-argument call keeps working for an external validator that
    imports this function: without it, only the checksum and format rules that do
    not need the language are applied.
    """
    d = unicodedata.normalize("NFKC", "".join(value.split()))
    if lang == "zh" and len(d) == 18:
        return cn_resident_ok(d) or cn_uscc_ok(d)
    # Company legal IDs are typed national_id (the kernel masks SIRET as NATIONAL_ID too).
    if re.fullmatch(r"FR\d{11}", d):  # FR VAT, numeric key: (12 + 3 x (SIREN mod 97)) mod 97
        return int(d[2:4]) == (12 + 3 * (int(d[4:]) % 97)) % 97
    if re.fullmatch(r"GB\d{9}", d):  # UK VAT: weights 8..2 over 7 digits + the 2 check digits, mod 97 = 0
        return (sum(int(x) * w for x, w in zip(d[2:9], range(8, 1, -1))) + int(d[9:11])) % 97 == 0
    if re.fullmatch(r"\d{4}/\d{6}/\d{2}|\d{2}-\d{2}-\d{6}|\d{8}-\d-\d{2}", d):
        return True  # ZA and HU registration numbers: format only, no check rule in this repo
    if lang == "en" and re.fullmatch(r"\d{8}", d):
        return True  # UK Companies House number (England and Wales): format only
    if lang == "ar" and re.fullmatch(r"\d{6}", d):
        return True  # AR commercial register number (Morocco): format only
    if lang == "ru" and re.fullmatch(r"\d{10}", d):  # RU INN (legal entity): weights mod 11 mod 10
        w = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        return sum(int(x) * y for x, y in zip(d[:9], w)) % 11 % 10 == int(d[9])
    if lang == "ru" and re.fullmatch(r"\d{13}", d):  # RU OGRN (legal entity): first 12 digits mod 11 mod 10
        return int(d[:12]) % 11 % 10 == int(d[12])
    if len(d) == 15 and d.isdigit():  # FR NIR: 13 digits + key; department (d[5:7]) is always 00
        return d[5:7] == "00" and 97 - int(d[:13]) % 97 == int(d[13:])
    if len(d) == 14 and d.isdigit():  # FR SIRET: Luhn over all 14 digits
        return luhn_ok(d)
    if len(d) == 13 and d.isdigit():  # ZA ID: Luhn over all 13 digits
        return luhn_ok(d)
    if len(d) == 9 and d.isdigit():
        if lang == "hu":  # HU TAJ: weights 3,7 over 8 digits, check = sum mod 10
            w = [3, 7, 3, 7, 3, 7, 3, 7]
            return sum(int(x) * y for x, y in zip(d[:8], w)) % 10 == int(d[8])
        return luhn_ok(d)  # FR SIREN: Luhn
    return False


def phone_findings(s):
    bad = []
    for rx in PHONE_CANDIDATES:
        for m in rx.finditer(s):
            digits = re.sub(r"\D", "", m.group(0).translate(OCR))
            if len(digits) < 8:
                continue
            if not any(p.fullmatch(digits) for p in PHONE_ALLOWED):
                bad.append(m.group(0))
    return bad


def email_findings(s):
    return [m.group(0) for m in EMAIL.finditer(s) if not m.group(0).endswith(".invalid")]


def masked(text, spans):
    chars = list(text)
    for sp in spans:
        if sp["type"] in IDENT_TYPES:
            for i in range(sp["start"], min(sp["end"], len(chars))):
                chars[i] = "X"
    return "".join(chars)


def passport_ok(value, lang):
    """zh: Chinese layouts (E + 8 digits, EA + 7, G + 8) with at least four zeros, so the
    number reads as fake. Other languages: the QXZ series, three capitals and seven digits."""
    if lang == "zh":
        return re.fullmatch(r"E\d{8}|EA\d{7}|G\d{8}", value) is not None and value.count("0") >= 4
    return re.fullmatch(r"[A-Z]{3}\d{7}", value) is not None


def script_ok(value, script):
    prefix = SCRIPTS[script]
    for ch in value:
        if ch.isalpha() and not unicodedata.name(ch, "").startswith(prefix):
            return False
    return True


def main():
    errors = []
    schema = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
    public = json.loads((ROOT / "public-terms.json").read_text(encoding="utf-8"))
    cases = []
    counts = {lang: Counter() for lang in LANGS}
    types_by_lang = {lang: set() for lang in LANGS}
    types_seen = Counter()
    residue = Counter()
    passport_near = {lang: [] for lang in LANGS}
    triage_labels = {lang: Counter() for lang in LANGS}
    spans_by_lang = {lang: set() for lang in LANGS}
    ids = set()

    # cases/<lang>.jsonl is required; cases/emails-<lang>.jsonl (natural messy e-mails) is optional.
    files = [(lang, f"{lang}.jsonl") for lang in LANGS] + [(lang, f"emails-{lang}.jsonl") for lang in LANGS]
    for lang, name in files:
        path = ROOT / "cases" / name
        if not path.exists():
            if not name.startswith("emails-"):
                errors.append(f"cases/{name}: missing")
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            where = f"cases/{name}:{n}"
            if not line.strip():
                errors.append(f"{where}: blank line")
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{where}: invalid JSON ({exc.msg})")
                continue
            before = len(errors)
            validate(case, schema, where, errors)
            if len(errors) > before:
                continue
            cases.append((where, case))
            if case["id"] in ids:
                errors.append(f"{where}: duplicate id {case['id']}")
            ids.add(case["id"])
            if case["lang"] != lang:
                errors.append(f"{where}: lang {case['lang']} in file for {lang}")
            text = case["text"]
            if case["kind"] == "short" and len(text) >= 120:
                errors.append(f"{where}: short case is {len(text)} characters, limit is under 120")
            counts[lang][case["kind"]] += 1
            triage_labels[lang][case["triage_label"]] += (case["kind"] == "triage")
            residue[lang] += case["expect_residue"]
            prev_end = -1
            for sp in sorted(case["spans"], key=lambda s: s["start"]):
                s, e, typ = sp["start"], sp["end"], sp["type"]
                value = text[s:e] if e <= len(text) else ""
                if not (0 <= s < e <= len(text)):
                    errors.append(f"{where}: span {typ} [{s},{e}) outside text")
                    continue
                if s < prev_end:
                    errors.append(f"{where}: span {typ} [{s},{e}) overlaps previous span")
                prev_end = e
                types_seen[typ] += 1
                types_by_lang[lang].add(typ)
                spans_by_lang[lang].add((typ, value))
                if typ == "iban" and not iban_ok(value):
                    errors.append(f"{where}: IBAN checksum or length fails: {value}")
                if typ == "national_id" and not national_id_ok(value, lang):
                    errors.append(f"{where}: national_id check fails: {value}")
                if typ == "card" and not card_ok(value):
                    errors.append(f"{where}: card check fails (UnionPay 62, Luhn): {value}")
                if typ == "passport":
                    if not passport_ok(value, lang):
                        errors.append(f"{where}: passport layout fails for {lang}: {value}")
                    window = text[max(0, s - PASSPORT_WINDOW):e + PASSPORT_WINDOW]
                    passport_near[lang].append(any(k in window for k in PASSPORT_KEYWORDS))
                if value.lower() in {t.lower() for t in public[lang]}:
                    errors.append(f"{where}: public term masked as {typ}: {value}")
            if case["kind"] == "public_trap" and not any(t in text for t in public[lang]):
                errors.append(f"{where}: public_trap without a public term")
            # NFKC folds full-width digits and signs (１３８, ＋８６) so the phone scan sees them.
            scan = unicodedata.normalize("NFKC", masked(text, case["spans"]) + "\n" + case["notes"])
            for bad in phone_findings(scan):
                errors.append(f"{where}: phone-like text outside fictional ranges: {bad}")
            for bad in email_findings(scan):
                errors.append(f"{where}: e-mail not under .invalid: {bad}")

    for lang in LANGS:
        for kind, minimum in KINDS.items():
            if counts[lang][kind] < minimum:
                errors.append(f"{lang}: {kind} has {counts[lang][kind]}, needs >= {minimum}")
        missing = CORE_TYPES | ({"national_id"} if lang in NATIONAL_ID_LANGS else set())
        for typ in sorted(missing - types_by_lang[lang]):
            errors.append(f"{lang}: no {typ} span")
        if residue[lang] < 1:
            errors.append(f"{lang}: no expect_residue case")
        for label in ["relevant", "spam", "phishing", "irrelevant"]:
            if triage_labels[lang][label] < 1:
                errors.append(f"{lang}: no triage case labelled {label}")
    near = passport_near["zh"]
    if not near or sum(near) * 2 < len(near) or all(near):
        errors.append(f"zh: passport keyword mix is {sum(near)} of {len(near)} near a keyword; "
                      "need at least half, and at least one without")
    for typ in TYPES:
        if types_seen[typ] == 0:
            errors.append(f"corpus: no {typ} span anywhere")

    canary_file = ROOT / "canaries.json"
    canaries = json.loads(canary_file.read_text(encoding="utf-8"))["canaries"]
    values = Counter()
    for c in canaries:
        where = f"canaries.json:{c['id']}"
        if c["lang"] not in LANGS or c["type"] not in TYPES or c["script"] not in SCRIPTS:
            errors.append(f"{where}: bad lang, type or script")
            continue
        values[c["value"]] += 1
        if not script_ok(c["value"], c["script"]):
            errors.append(f"{where}: letters are not all {c['script']}")
        if (c["type"], c["value"]) not in spans_by_lang[c["lang"]]:
            errors.append(f"{where}: no {c['type']} span with this value in cases/{c['lang']}.jsonl")
        if c["value"] in public[c["lang"]]:
            errors.append(f"{where}: canary is a public term")
        scan = "X" * len(c["value"]) if c["type"] in IDENT_TYPES else c["value"]
        for bad in phone_findings(scan):
            errors.append(f"{where}: phone-like text outside fictional ranges: {bad}")
        for bad in email_findings(scan):
            errors.append(f"{where}: e-mail not under .invalid: {bad}")
    for value, n in values.items():
        if n > 1:
            errors.append(f"canaries.json: duplicate canary value {value!r}")
    if len(canaries) < 25:
        errors.append(f"canaries.json: {len(canaries)} canaries, expected about 30")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for bad in phone_findings(readme):
        errors.append(f"README.md: phone-like text outside fictional ranges: {bad}")
    for bad in email_findings(readme):
        errors.append(f"README.md: e-mail not under .invalid: {bad}")

    digest = hashlib.sha256()
    for path in sorted((ROOT / "cases").glob("*.jsonl")) + [ROOT / "canaries.json", ROOT / "public-terms.json"]:
        digest.update(path.name.encode() + b"\0" + path.read_bytes())

    header = ["lang"] + list(KINDS) + ["total"]
    print("  ".join(f"{h:>11}" for h in header))
    for lang in LANGS:
        row = [lang] + [str(counts[lang][k]) for k in KINDS] + [str(sum(counts[lang].values()))]
        print("  ".join(f"{v:>11}" for v in row))
    print(f"cases: {len(cases)}  canaries: {len(canaries)}  spans: {sum(types_seen.values())}")
    print("span types: " + ", ".join(f"{t}={types_seen[t]}" for t in TYPES))
    print(f"corpus sha256: {digest.hexdigest()}")
    if errors:
        for line in errors[:60]:
            print(f"FAIL {line}", file=sys.stderr)
        if len(errors) > 60:
            print(f"FAIL ... {len(errors) - 60} more", file=sys.stderr)
        print(f"FAIL: {len(errors)} problem(s)")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
