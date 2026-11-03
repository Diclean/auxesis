# Privacy eval

The harness in `src/main.rs` prints the detection table; the JSONL corpora are in
`cases/`, the normal-prose corpora in `prose/`, and the reference list of sensitive
terms is `crates/kernel-privacy/data/sensitive-terms-reference.md`.

Coverage is promised for the reference list: every entry is masked in each language
where it has a form. A term outside that list is backlog, not a P2 defect.

## Languages in scope

The scored languages are FR, EN, AF, HU, SL and ZH — the owner's private-mode
languages. The `ar` and `ru` cases in `cases/` (including `emails-ar.jsonl` and
`emails-ru.jsonl`) are **out of scope**: they print on a `NOT SCORED` row and no
bar covers them. A miss there is not a defect and must not drive a fix. The
whole-corpus table is descriptive only, not a bar.

## What is scored (EVAL-NO-NAMES)

Person and company names are **not hidden by design** (2026-10-19), so they are
**unscored by design**: a gold name lowers no recall, a detected name is no
over-mask, neither reaches a precision or a tier bar, and a text whose only
labels are names counts as a no-PII text. Scored: e-mail, phone, address, IBAN,
card, IDs, secrets, health.

### Bar definitions, exactly as computed

| Row | Computed over | Bar |
| --- | --- | --- |
| **Tier C recall, held-out (prohibited)** | [`EntityKind::is_prohibited`]: IBAN, card, national ID or passport, health, secret | `>= 99.5 %` |
| **Tier H recall, held-out, Standard / Deep** | the model-emitted kinds that are not names: address, date of birth | `>= 95 %` / `>= 98 %` |

### Tier C scope and set (TIERC-HELDOUT-2, 2026-10-23)

- **Set**: `heldout-2.jsonl`, 250 invented Tier C values in FR/EN/AF/HU/SL/ZH
  carriers (mail, thread, chat, form, JSON, CSV, tables, OCR). Line 1 is
  `# sha256: <hex>` of the rest of the file; the harness refuses a mismatch.
  Builders of fixes must not read it or tune against it.
- **Location (PUB-2)**: `heldout-2.jsonl` and `heldout.txt` are not in the tree.
  They live in `$AUXESIS_EVAL_DIR` (default `~/.auxesis-eval/heldout/`) at
  `qa/privacy-eval/<file>`, pinned by whole-file SHA-256 in `HELDOUT-PINS.txt`.
  A missing file prints `held-out set absent, skipped` and nothing is measured;
  a hash mismatch refuses the run. Measured recall: `RECALL.md`.
- **Languages**: only the owner's private-mode languages (fr, en, af, hu, sl,
  zh) are scored. Other languages of the v1 split (`heldout.txt`: ar, ru) print
  on a `NOT SCORED` row.
- **Path**: the bar rows are the production gate (`Gate::for_grant`, A1) in
  Private and Open, i.e. what leaves the Mac. A value counts as hidden only when
  neither it nor any run of 6 of its letters and digits (all, when shorter)
  that the rest of the text did not hold is readable in the output (the
  LEAK-FINDER-1 rule): a partial mask is a miss, a gate refusal is a miss.
  The Registry row prints beside it with no bar.
- **Old row**: `Tier C, v1 all langs (old row), Registry` is the tally the
  table printed before (41 spans), with its bar. The bar is still 99.5 %.

Tier C calls `EntityKind::is_prohibited` at runtime, not a list copied here, so
a kind joining that set joins Tier C with no edit. Tier H keeps the bars above,
over the kinds left in it after the names. Both print as measured: short reads
`MISSED`, unmeasured reads `n/a (n = 0)`, never `100 %`.

The run ends with a per-class table over the **whole in-repo corpus, not the
held-out split** (the held-out bars above use the split): one row per scored
class, its gold count, the share hidden in Private and in Open, and the
over-mask rate on the texts holding no value of a scored class. A class the mode
never hides reads `n/a (kept by design)` — derived from the grant, since a
`Tokenised` grant masks every class it detects and a `Passthrough` one replaces
only the prohibited values — and a class with no gold in the corpus reads
`n/a (n = 0)` rather than disappearing.

## Fetching external corpora

Run `python3 kernel/qa/privacy-eval/scripts/fetch-external.py` (optional `--sample-size N`,
`--seed N`, `--datasets nemotron|gretel|all`). Output goes to `~/.cache/auxesis/privacy-eval-external/`
and is never committed. Refuses `--output-dir` inside the git repo.

Run the harness on fetched data with:
`cargo run -p privacy-eval --release -- ~/.cache/auxesis/privacy-eval-external/*.jsonl`
(add `--legacy` for the per-type before/after table).

## Licences

- NVIDIA Nemotron-PII (`nvidia/Nemotron-PII`): CC BY 4.0. Attribution: NVIDIA Corporation.
- Gretel synthetic_pii_finance_multilingual: Apache-2.0. Attribution: Gretel AI.

Data stays in `~/.cache` and is never committed.
