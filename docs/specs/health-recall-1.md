# Health recall: health words and disease cues

Goal: health recall in Private at 90 % or more on the in-scope languages (fr, en,
hu, af, sl, zh), as `qa/privacy-eval` measures it. Baseline: 62.50 % (40/64)
in both modes; in scope 39/54 (72.2 %). Russian and Arabic are out of scope and
stay as they are: 9 spans.

## Missed gold spans on main (in scope)

| Case ids | Span | Why missed |
| --- | --- | --- |
| en-short-06, en-thread-04, en-scan-02 | `Mist Fever` | invented name; `fever` is no term |
| fr-short-06, fr-thread-04, fr-scan-02 | `maladie de Brume` | invented name; `maladie` is only a cue |
| hu-short-06, hu-thread-04, hu-scan-02 | `Köd-láz` | invented name; `láz` is no term |
| zh-short-06, zh-thread-04, zh-thread-08 | `晨雾热` | invented name, no word breaks |
| zh-thread-13 | `灰羽病` | invented name |
| af-thread-08 | `op siek verlof` | only the one-word `siekverlof` is a term |

Real words (chemo, cancer, HIV, VIH, kanker, 糖尿病, MS/SEP, Prozac…) and the other
leave phrases (on sick leave, en arrêt maladie, táppénzen) are already caught.

## Rules (`recognizers/sensitive_terms.rs`, `data/sensitive-terms-v1.tsv`)

1. Terms: `siek verlof`, `op siek verlof`, `met siek verlof`, `op siekverlof` (af).
2. Head cue: a name, then a disease word. The name is one to three
   hyphen-joined words, each capitalised and letters only, never an article or
   determiner (`This disease`, `No fever`, `Az`, `Die`). en: `fever`, `disease`,
   `syndrome` after a space or a hyphen, with the possessive `X's disease`. hu:
   `-láz`, `-betegség`, `-szindróma` with case endings (`Köd-lázról`), hyphen
   only. af: `-griep`, `-koors`, `-siekte`, hyphen only. The span is name plus word.
3. Lead cue (fr): `maladie`, `syndrome` or `fièvre`, then `de`, `d'` or `du`, then
   a capitalised name, hyphen parts included (`maladie de Creutzfeldt-Jakob`).
   Not after `assurance` (`caisse d'assurance maladie de Lyon`).
4. Han cue: two Han characters, then `热`, `病` or `症`, then a non-Han character
   or a particle (`的 了 和 与 及 等`). Neither character may be a degree word, a verb or
   a particle (`很热`, `生病`, `看病`, `毛病`). The hit is contextual: it stands
   only when a health term or a HEALTHCUE word (`治疗`, `病假`, `确诊`) shares
   its sentence, the same check as `?MS`.

## Names stay clear

A cue never fires on a name alone, nor after an honorific (`Dr`, `Mme`, `Mnr`…):
`Dr Brume has a fever`, `Dr Brume Fever` and `maladie de Mme X` stay clear.

## Over-masking

Each rule needs a disease word next to the name; lowercase heads never fire
(`the fever`); a capitalised word before one (`High fever`) is health anyway.
The Han rule, the riskiest, needs a health anchor in the sentence. The eval's
prose rows (HU, AF, SL), the over-mask guards, HU short cases and no-PII
over-mask (Private 11.60 %, Open 0.55 %) must not move. Guards in the test cover
names, insurance, an era (`Árpád-kor`), `Grys-familie` and Chinese weather.

## Proof

`tests/health_recall1_superset.rs` freezes main on the 1,132 baseline inputs plus
17 health repros and 11 guards: no byte lost in either mode, no refusal, no
prose or guard line changed, every repro hidden in both modes. Every rule is
linear: a constant amount of work per word or Han character.
