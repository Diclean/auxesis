# Measured recall on our held-out set (PUB-3)

Tier C values of held-out-2 (250 invented values, 184 cases, FR/EN/AF/HU/SL/ZH),
scored through the production gate (`Gate::for_grant`) in Private and Open. A value
counts as hidden only when no 6-character run of it is readable in the output; a
partial mask or a gate refusal is a miss. Aggregate counts only: the set itself is
not in the tree (`HELDOUT-PINS.txt`, `README.md`).

Run 2026-11-01 on base `ef2745c1`, Standard detection only
(`--no-default-features`; Deep not measured: GLiNER/ONNX Runtime not in this
build), held-out-2 content sha256 `8ed06af5…a64bef`, verified.

| class                       |   n | recall Private | recall Open |
| --------------------------- | --: | --------------: | -----------: |
| IBAN                        |  40 |       100.00 % |    100.00 % |
| ↳ previous run (2026-10-29) |  40 |       100.00 % |    100.00 % |
| card                        |  35 |       100.00 % |    100.00 % |
| ↳ previous run (2026-10-29) |  35 |       100.00 % |    100.00 % |
| ID                          |  70 |        95.71 % |     94.29 % |
| ↳ previous run (2026-10-29) |  70 |        95.71 % |     94.29 % |
| secret                      |  45 |        93.33 % |     93.33 % |
| ↳ previous run (2026-10-29) |  45 |        91.11 % |     91.11 % |
| health                      |  60 |        81.67 % |     81.67 % |
| ↳ previous run (2026-10-29) |  60 |        76.67 % |     76.67 % |
| all                         | 250 |        93.20 % |     92.80 % |
| ↳ previous run (2026-10-29) | 250 |        91.60 % |     91.20 % |

The Tier C bar is 99.5 %. Private misses it at 93.20 % and Open misses it at
92.80 % on this set. This is measured recall on our held-out set, not a guarantee
about other text. Reproduce with
`AUXESIS_EVAL_DIR=<dir> cargo run -p privacy-eval --locked --release --no-default-features`
from `kernel/`.
