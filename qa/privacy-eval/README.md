# Privacy eval corpus (`qa/privacy-eval/`)

A labelled, **FAKE** multilingual corpus (fr, en, af, hu, ar, ru, zh). It gates every detector and
threshold in the privacy kernel. The runner that scores against it comes later; for now this
directory ships the data, its schema and its validator.

Nothing here is real. Names, companies, addresses, documents and numbers are invented, and each
identifier only follows the public check algorithm of its format.

## Files

| Path | What it is |
|---|---|
| `cases/<lang>.jsonl` | One JSON case per line, one file per language |
| `cases/emails-<lang>.jsonl` | Natural, messy e-mails (signatures, banners, threads), optional, same schema. See below |
| `schema.json` | JSON Schema (draft 2020-12) for one case |
| `canaries.json` | 30 unique canary strings. Any canary in a cloud payload is a hard fail |
| `public-terms.json` | Public terms per language (cities, ministries, préfectures, products, "Auxesis"). Never masked |
| `scripts/check-privacy-eval.py` | Stdlib-only validator. Run from the repo root: `python3 -I qa/privacy-eval/scripts/check-privacy-eval.py` |

## Case format

```json
{"id": "en-short-99", "lang": "en", "kind": "short", "text": "Hi, I am Mara Ellison.",
 "spans": [{"type": "person", "start": 9, "end": 21}],
 "expect_residue": false, "triage_label": "relevant", "notes": "types: person"}
```

- `id`: `<lang>-<short|thread|scan|triage|injection|trap>-<NN>`, unique across the corpus.
- `kind`: `short`, `thread`, `scan_text`, `triage`, `injection` or `public_trap`.
- `spans`: `start` and `end` are Unicode code point indexes into `text` (Python `str` indexes),
  `end` exclusive. The detector emits UTF-8 byte offsets, so the runner converts before comparing.
- `expect_residue`, `triage_label`, `notes`: see the labelling rules below.

## Kinds and minimum per language

| kind | What it tests | Min per language |
|---|---|---|
| `short` | A message, usually under 120 characters | 20 |
| `thread` | Quoted replies, header blocks, signatures | 4 |
| `scan_text` | OCR-style text as printed (l/1 and O/0 confusions, split names) | 2 |
| `triage` | Message with a triage label; all four labels must appear | 10 |
| `injection` | Prompt-injection attempt inside a message | 5 |
| `public_trap` | Public terms that must not be masked. May also hold a PERSON or private ORG span that must still be masked | 10 |

## Entity types and formats

| type | Format in this corpus |
|---|---|
| `person` | Invented full name, transliterated where the script differs |
| `org` | Invented company. Public bodies are never `org` spans |
| `address` | Invented street, postcode `00000`, invented town |
| `phone` | Only fictional forms: FR `+33 1 99 00 xx xx` (national `01 99 00 xx xx`); US `555-01xx` block; UK `07700 900xxx`; unallocated "country code then 00 000 0001" forms for country codes 7, 27, 36 and 212 only: `+27 00 000 0001`, `+7 (00) 000-0001`, `+36 00 000 0001`, `+212 00 000 0001`. CN (zh): mobile `1[3-9]`, one digit, `0000`, four digits (3-4-4), and Beijing `010` then `0` and seven digits; both take an optional `+86` or `0086`. The `0000` middle block of the mobile form is an allowlisted fictional form for test data only (deliberate choice, see Known limits). Anything else fails |
| `email` | Only under the `.invalid` top-level domain. Messaging handles are never `email`; see `handle` |
| `handle` | Messaging or social handle: WeChat ID, Telegram `@user`, X/Twitter, LINE. Not an e-mail, so the e-mail recogniser ignores it. It identifies a person, so tier HIGH. Not a golden-covered kind (`covered_kind` in `golden.rs` does not list it) |
| `card` | Payment card: UnionPay `62` prefix, 16 to 19 digits, Luhn-valid. Spaces and hyphens are grouping, not part of the value |
| `iban` | Passes mod-97 and the known length for FR (27), HU (28), RU (33), ZA (26), MA (28), GB (22). Bank codes start with 9 (fictional) |
| `passport` | zh: Chinese layouts, `E` + 8 digits, `EA` + 7 digits, or `G` + 8 digits, nine characters (the MRZ size), with at least four zeros so the number reads as fake. About half the zh passport spans sit within 40 characters of a passport keyword (护照 or "passport"), the rest do not. Other languages: one invented series `QXZ`, three capital letters and seven digits (ten characters). ICAO Doc 9303 gives a passport number nine characters in the machine-readable zone, so no machine-readable passport can carry ten. MRZ check digits are not checked yet |
| `national_id` | FR NIR: 15 digits, key = 97 minus (first 13 digits mod 97), department 00. INSEE issues no department 00, so these NIRs are structurally impossible, not merely fictional. ZA ID: 13 digits, Luhn. HU TAJ: 9 digits, weights 3,7,3,7,3,7,3,7 over the first eight, check digit = sum mod 10. CN (zh): resident ID (18 characters, MOD 11-2 check, X allowed) and USCC (18 characters, GB 32100-2015 check character); both use region code `99`, which is unallocated, so they are fictional |
| `health` | Invented condition names (for example "Mist Fever"). Special category, masked |
| `religion` | Invented faiths (for example "Solism"). Special category, masked |
| `date_of_birth` | Date of birth in the local format, after a birth cue word. Masked |

The checker enforces the checksums (NIR key and department 00 included), the passport layout, and the
phone and e-mail rules. It does not check bank codes or passport check digits; reviewers do.

## Labelling rules

1. Mark every occurrence, including repeats inside quoted replies and signatures. The thread map
   must return one token for one person.
2. Mark the surface form as written, OCR noise included. Checksum-validated IDs stay clean.
3. Do not mark pronouns, roles or titles on their own ("elle", "he", "the director"). They are
   residue (rule 5), not spans.
4. Do not mark public terms. A public term never equals a span value, and every `public_trap` case
   contains at least one (`public-terms.json`).
5. `expect_residue` is `true` when the text still identifies someone after every span is masked: a
   unique role plus an organisation plus a city, or a coreference chain that masking cannot break.
   A residue judge is expected to answer `possible` or `likely` on those cases only.
6. `triage_label`: `relevant` (the owner should act or read), `spam` (unsolicited bulk offer),
   `phishing` (a lure to click, pay, log in or send an identifier), `irrelevant` (no action).
   Injection cases are labelled `phishing` because they try to steer the assistant. The injection
   flag belongs to the triage contract; here it is `kind = injection`.
7. Spans never overlap and are sorted by `start`.
8. `notes` holds free text: types, the residue reason, coreference links, or the public terms in a
   trap.

## Natural e-mails (`cases/emails-<lang>.jsonl`)

Real mail is messy, and the cases above are short and clean. These files hold realistic e-mails:
20 per language, in the same schema and checked by the same validator. Each file is optional.

- Kinds: `thread` 11, `triage` 4, `injection` 2, `public_trap` 3 per language. Ids continue the
  per-kind numbering of `<lang>.jsonl` (for example `fr-thread-05`). Each `notes` field names the
  features of its e-mail.
- Features mixed across the set: Outlook and Gmail header blocks, quoted replies with `>` and `>>`,
  forwarded messages, top-posting, HTML-to-text artifacts (`&nbsp;`, `*bold*`, flattened tables,
  line wraps inside names, IBANs and phones), tracking links carrying a name or an encoded e-mail,
  `mailto:` links, unsubscribe footers, signatures with direct and mobile lines, office addresses,
  legal footers, logo alt text, social icons as text, lowercase SMS style, initials, nicknames, emoji,
  and two languages in one mail.

### Labelling policy for natural e-mails

- **Person:** any personal name, including greetings (`Bonjour Hugo`, `Dear Dr S. K.`), signatures,
  `a écrit` and `wrote` lines, first names on their own, lowercase names (`joss`, `павла`),
  nicknames and initials that identify someone (`JM`, `Dr. K.`). Titles alone are not spans. A first
  name that sits before a date of birth is a `person` span too.
- **Name inside an address:** the `email` span covers the whole address, because spans never
  overlap. The sender's display name still gets its own `person` span.
- **Phone:** personal and direct lines, and the company switchboard (fail toward masking).
- **Org:** the sender's company in a signature or footer, and a private company named in a body.
- **Company legal IDs:** `national_id`, the type the kernel uses for SIRET. SIREN (9 digits) and
  SIRET (14 digits) use the Luhn check, and FR VAT uses the numeric key. UK VAT (`GB` + 9 digits)
  uses the mod-97 check, RU INN (10 digits) and RU OGRN (13 digits) use their check digits. ZA
  registration numbers, HU company and tax numbers, the UK Companies House number (8 digits) and the
  AR commercial register number (6 digits) are format checks only.
- **Footers:** en, ar and ru each have at least two legal footers (company, registration or VAT
  number). Ids in them are `national_id` like the fr, af and hu ones.
- **Client and case numbers:** the schema has no span type for them. They stay as plain text,
  unlabelled. Open item.
- **Health, religion, passports, IBANs, dates of birth:** labelled wherever they appear, including
  inside quotes and tracking links.
- **Not labelled:** generic brands, public bodies, cities, holidays and generic street names in the
  body. They are entries in `public-terms.json`. A `public_trap` case can also hold a private span
  that must still be masked.
- **Split identifiers:** an IBAN or phone broken over a line is one span that contains the break.
- **Handles:** WeChat IDs, Telegram `@user`, X/Twitter and LINE handles are `handle` spans, never `email`.

### Checker changes for this set

- The checker reads `cases/emails-<lang>.jsonl` as well as `cases/<lang>.jsonl`. It is optional, and
  the existing files are unchanged.
- The IBAN and `national_id` checks ignore all whitespace, so split identifiers validate.
- `national_id_ok` takes the language and checks the company-ID formats above (`GB` VAT, `en` 8-digit,
  `ar` 6-digit, `ru` INN and OGRN).
- The schema gained one span type, `handle`, for messaging handles. No new kind. `public-terms.json` gained public terms for each language.

### Phone forms in this set

Only the allowlisted forms pass. Outside the France and US/UK ranges, each country code has one
fictional number, so the same number recurs across cases. Do not add a form without a review.

### Limits

- Draft. A native speaker of af, hu, ar and ru should review these files before the gate is
  trusted.
- The company-ID format checks do not prove that a number is fictional.

## Adding a case

1. Pick the language file and the next free number for the kind.
2. Write the text. Keep `short` cases under 120 characters.
3. Compute each span: `start = text.index(value)`, `end = start + len(value)`. Check that
   `text[start:end] == value`.
4. Append one JSON object per line, written with `json.dumps(obj, ensure_ascii=False)`.
5. Run the checker. It must print `PASS`.
6. A new canary needs a matching span (same type, same value) in a case of its language.

The checker prints a corpus sha256 over the case, canary and public-term files. Any change to the
corpus changes it, and results on the old hash are no longer valid.

## Canaries

`canaries.json` lists 30 unique values across eleven types and three scripts (Latin, Cyrillic,
Arabic). Each one appears as a span of its type in a case of its language, and the checker enforces
that. Canary values are unique across the file and none is a public term.

## Fake data only: checklist

Tick these in review before a change is merged. The checker covers the mechanical items.

- [ ] Names are invented or transliterated invented names; none is a known public figure.
- [ ] Companies, addresses and products are fictional; the postcode is `00000`.
- [ ] Every e-mail address ends in `.invalid`. (checker)
- [ ] Every phone number is one of the fictional forms above. (checker)
- [ ] Every IBAN passes mod-97 and uses a fictional bank code starting with 9. (checker: mod-97; reviewer: bank code)
- [ ] Every national ID uses the public check and a fictional issuer block (NIR department 00, structurally impossible). (checker)
- [ ] Passport numbers use the QXZ series (seven digits, ten characters) outside zh, and the zh layouts (E + 8 digits, EA + 7, G + 8, at least four zeros) in zh. (checker: layout; reviewer: series)
- [ ] URLs use `.invalid` domains only.
- [ ] No real person, real message, key, token or account detail is copied from anywhere.
- [ ] Public terms are real public place and body names, or the product name, nothing private.
- [ ] Run the checker and the repository's personal-data and secret scans before committing.

## Public datasets

Two public synthetic PII datasets are measured by
[`public_eval.rs`](https://github.com/Diclean/auxesis-privacy-kernel/blob/v0.1.1/crates/kernel-privacy/examples/public_eval.rs)
together with `qa/privacy-eval/scripts/fetch-public-sample.py`. The sample is fetched into a
directory **outside** the repo (never committed).

- **nvidia/Nemotron-PII** (https://huggingface.co/datasets/nvidia/Nemotron-PII) — CC BY 4.0, English,
  100K-1M rows. Synthetic.
  Attribution (CC BY 4.0): "Nemotron-PII by NVIDIA, licensed under CC BY 4.0
  (https://creativecommons.org/licenses/by/4.0/). Changes: a sampled subset; labels mapped to Auxesis classes."
- **gretelai/synthetic_pii_finance_multilingual** (https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual)
  — Apache-2.0, en/fr/de/nl/es/it, 10K-100K rows. Synthetic.
  Attribution (Apache-2.0): "synthetic_pii_finance_multilingual by Gretel, licensed under the
  Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0). Changes: a sampled
  subset; labels mapped to Auxesis classes."

Scored classes only: IBAN/bank account, card, national ID/passport/SSN/tax id, secrets (API keys,
passwords), e-mail, phone. Health is **not measured** on these sets (no label maps to it), so its
numbers are null. Person and company names are **not scored (by design)**.

TODO: report `placeholder` and `invalid_checksum` separately, with recall on invalid-checksum cards
and IBANs as its own row; map Nemotron's
`medical_record_number`/`health_plan_beneficiary_number`; remove about 150 duplicated lines; make the
example's unit test run under `cargo test`; drop excluded-gold hits from the FP samples (public_eval.rs ~:404).

How to run:

    set -e
    T=$(mktemp -d)
    python3 -I qa/privacy-eval/scripts/fetch-public-sample.py "$T"   # fails on a short sample
    cargo build -p kernel-privacy --example public_eval --release
    AUX_PUBLIC_EVAL_DIR="$T" AUX_PUBLIC_EVAL_JSON=/tmp/public_eval.json \
      <cargo target dir>/release/examples/public_eval
    rm -rf "$T"

## Known limits

- The corpus is a first draft. A native speaker of af, hu, ar, ru and zh should review it before the
  gate is trusted.
- zh (`zh.jsonl`, `emails-zh.jsonl`): WeChat IDs are `handle` spans, not `email`. Handles are HIGH
  tier and are not a golden-covered kind, so the golden gate does not score them.
- zh mobile numbers use the `0000` middle block (for example `+86 130 0000 1234`). That form is
  allowlisted for test data only, a deliberate choice. The format does not prove the number is
  unallocated, so it is not a claim about real numbers. The Beijing landline form is allowlisted for
  now and needs the same review.
- zh passports use the Chinese layouts (E + 8, EA + 7, G + 8), with at least four zeros. Only the
  zh rules use them; other languages keep the QXZ series.
- The golden gate in
  [`golden.rs`](https://github.com/Diclean/auxesis-privacy-kernel/blob/v0.1.1/crates/kernel-privacy/tests/golden.rs)
  includes the zh files. The one
  gap is the 18-character zh national IDs (resident ID and USCC): the registry has no recogniser
  for them until the Chinese recogniser pack lands. Those spans are skipped by shape, and
  no other span is.
- `scan_text` cases are OCR-style text, not rendered images. Noise is limited to l/1, O/0 and split
  names.
- The ZA ID and HU TAJ examples are not structurally impossible: a real holder could share the number.
  Give them an impossible birth date or issuer block before the gate is trusted.
- The HU TAJ weighting is taken from the public rule as recalled. Confirm it against the official
  specification before relying on the checksum result. Passport numbers are not MRZ-checked.
- The corpus lives under `qa/privacy-eval/`. Moving it to `crates/aux-privacy/tests/corpus/` is a
  follow-up.
