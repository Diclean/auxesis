//! Benchmark hook for the `qa/privacy-eval` JSONL corpus.
//!
//! Usage (from the repository root):
//!
//! * `cargo run -p privacy-eval --locked --release` prints the detection table:
//!   tier C and tier H recall on the held-out split, false positives on trap
//!   cases, p95 latency and, when the GLiNER feature and its model files are
//!   present, the Deep-detection rows. A missed bar prints `MISSED` and is
//!   never rounded up; an unavailable Deep row prints
//!   `NOT MEASURED`. Rows without a Standard/Deep qualifier use the detection
//!   level in force: Deep when the model is present, Standard otherwise.
//! * `cargo run -p privacy-eval --locked --release -- --legacy` prints the
//!   before/after table of the K04 runner (the pre-1e pipeline against the
//!   email-aware one).
//!
//! The table also prints a `Known contacts recall` row for the dictionary
//! recogniser over `qa/privacy-eval/known_contacts.jsonl`
//! (`{"id","dictionary","text","spans"}`, byte offsets). It has no bar; every
//! miss is printed, never hidden.
//!
//! ## What is scored (EVAL-NO-NAMES)
//!
//! Names are not hidden by design (2026-10-19): a gold name lowers no recall, a
//! detected name is no over-mask, neither reaches a bar or a precision. Tier C
//! is `EntityKind::is_prohibited` itself, and an empty tally prints
//! `n/a (n = 0)`, never `100 %`. `README.md` has the exact bar definitions.
//! A path argument is a `.jsonl` file or a directory of them. Every case is
//! `{"id","lang","text","spans":[{"type","start","end"}]}`.
//!
//! The held-out split is frozen in `qa/privacy-eval/heldout.txt` (one case id
//! per line, `#` comments allowed; it and `heldout-2.jsonl` live outside the
//! tree, see [`private_sets`]): the rule is FNV-1a 64 of the case id, held
//! out when `hash % 5 == 0` (~20 %), but the committed file is the source of
//! truth so the split never changes silently.
//!
//! ## Tier C (TIERC-HELDOUT-2)
//!
//! The Tier C bar is scored on `qa/privacy-eval/heldout-2.jsonl` (outside the
//! tree, in `$AUXESIS_EVAL_DIR`), a frozen set
//! of invented Tier C values whose line 1 is `# sha256: <hex>` of the rest of
//! the file; a mismatch refuses the run. It is scored through the production
//! gate (what leaves the Mac) in Private and Open, with the Registry beside it.
//! Only the owner's languages ([`IN_SCOPE_LANGS`]) are scored: the v1 split's
//! other languages print on an unscored row, and the old all-language row
//! still prints with its bar, so no number disappears.
//!
//! ## Legacy runner
//!
//! With `--legacy`, the binary scores two registries over the same corpus:
//!
//! * **before** — `Registry::builder().with_all().without_email_layer()`, the
//!   pre-1e pipeline;
//! * **after** — `Registry::new()`, with the email-aware layer mounted.
//!
//! Scores are per case (P3-8). Recall and precision use the same-kind partial
//! overlap rule of the Python benchmark (`examples/ner_eval.rs`): the registry
//! merges an overlap into one union, so an exact-offset rule would score a
//! nested value as a miss even when its bytes are masked. *Mask coverage* is the
//! fraction of gold spans whose bytes are fully covered by the predicted union,
//! which is the metric the fail-toward-masking policy cares about. *Trap FP*
//! counts a predicted span whose exact value is a public term from the config
//! file.
//!
//! Set `AUX_EVAL_FP=1` to print every same-kind false positive with its value,
//! which is how an over-masking round is diagnosed.
//!
//! Timing is the wall time of the analyse loop, so the difference is the
//! layer's overhead. It reads only the paths it is given and never touches a
//! network.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use kernel_core::privacy::{
    admit, Context, Decision, Destination, GrantPolicy, PathId, PrivacyMode,
};
use kernel_privacy::eval::GoldSpan;
use kernel_privacy::recognizers::sensitive_terms::SensitiveTermsRecognizer;
use kernel_privacy::{
    Anonymizer, EntityKind, Gate, NameDictionary, PublicTerms, Recognizer, Registry, Span,
};
use serde::Deserialize;

mod private_sets;
use private_sets::{HeldOut, HELDOUT_1, HELDOUT_2};

/// The known-contacts slice: dictionary, text and the names it must mask.
const KNOWN_CONTACTS: &str = "qa/privacy-eval/known_contacts.jsonl";

/// The bars of the table in `README.md`, in hundredths of a percent where a
/// rate is compared.
///
/// Tier C covers the prohibited classes and Tier H the model-emitted kinds that
/// are not names, so neither bar can be reached by averaging in a class the
/// product does not claim to hide. A bar with nothing behind it prints
/// `n/a (n = 0)`, never a pass.
const BAR_C_HUNDREDTHS: u64 = 9950; // >= 99.5 %, the prohibited classes
const BAR_H_STANDARD_HUNDREDTHS: u64 = 9500; // >= 95 %
const BAR_H_DEEP_HUNDREDTHS: u64 = 9800; // >= 98 %
const BAR_TRAP_FP: u64 = 40; // <= 40
const BAR_LATENCY_STANDARD_MS: u64 = 150; // <= 150 ms
const BAR_LATENCY_DEEP_MS: u64 = 400; // <= 400 ms
const BAR_PEAK_MEMORY_MB: u64 = 1024; // <= 1 GB

/// The owner's private-mode languages (2026-10-10). Tier C is scored on these
/// only; a case in any other language is printed on an unscored row.
const IN_SCOPE_LANGS: [&str; 6] = ["fr", "en", "af", "hu", "sl", "zh"];

/// Maintainer-approved SHA-256 of the frozen held-out-2 data lines (excluding
/// line 1).
const HELDOUT_2_SHA256: &str = "8ed06af51b9d6bcc030d21421bdd7a59bfbba6eb3b9c6d76e5fed24700a64bef";

/// Whether a case's language is one the owner declared.
fn in_scope(lang: &str) -> bool {
    IN_SCOPE_LANGS.contains(&lang)
}

/// Whether a kind belongs to Tier C: [`EntityKind::is_prohibited`] itself, not
/// a list mirrored here -- the five classes the owner requires hidden.
fn tier_c_kind(kind: EntityKind) -> bool {
    kind.is_prohibited()
}

#[derive(Deserialize)]
struct Case {
    id: String,
    lang: String,
    text: String,
    spans: Vec<Gold>,
}

#[derive(Deserialize)]
struct Gold {
    #[serde(rename = "type")]
    kind: String,
    start: usize,
    end: usize,
}

/// Sensitivity tier of a gold span.
///
/// The C/H split follows the kernel's own per-kind classification:
/// [`EntityKind::mask_priority`] (`crates/kernel-privacy/src/span.rs:184`)
/// puts every deterministic recogniser's kind below `9` and every model-emitted
/// kind at `9`. The C+9 (GDPR Art. 9) flag and the N (never leaves) tier come
/// from the sensitivity taxonomy: health and religion are special-category,
/// and no detected [`EntityKind`] is a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    /// CRITICAL: the prohibited classes, [`tier_c_kind`].
    C,
    /// C+9: special-category data (Art. 9); model-only today.
    C9,
    /// HIGH: the model-emitted kinds that are not names.
    H,
    /// NEVER: secrets, such as API keys and tokens (K10).
    N,
    /// A person or organisation name: not a scored class.
    Name,
}

fn tier_of(kind: EntityKind) -> Tier {
    match kind {
        EntityKind::Health
        | EntityKind::Religion
        | EntityKind::SexualOrientation
        | EntityKind::Union
        | EntityKind::Ethnicity => Tier::C9,
        EntityKind::Secret => Tier::N,
        EntityKind::Person | EntityKind::Organization => Tier::Name,
        EntityKind::Address | EntityKind::DateOfBirth => Tier::H,
        _ if kind.mask_priority() < 9 => Tier::C,
        _ => Tier::H,
    }
}

/// Whether a kind is a name: a person or an organisation.
fn is_name(kind: EntityKind) -> bool {
    tier_of(kind) == Tier::Name
}

/// The tier a gold span is scored under, or `None` when its kind is not: a
/// name never is, and neither is a kind that is not prohibited, which keeps
/// e-mail, phone, address and date of birth in the scored recall but off
/// every bar that is not theirs.
fn scored_tier(kind: EntityKind) -> Option<Tier> {
    match tier_of(kind) {
        Tier::Name => None,
        Tier::C | Tier::C9 | Tier::N => tier_c_kind(kind).then_some(Tier::C),
        tier => Some(tier),
    }
}

/// Convert a Unicode code-point index to a UTF-8 byte offset.
fn cp_to_byte(text: &str, cp: usize) -> usize {
    text.char_indices()
        .nth(cp)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

/// Gold spans of one case, with code-point offsets converted to bytes.
fn gold_spans(case: &Case) -> Vec<GoldSpan> {
    case.spans
        .iter()
        .filter_map(|labelled| {
            let kind = EntityKind::parse(&labelled.kind)?;
            Some(GoldSpan::new(
                kind,
                cp_to_byte(&case.text, labelled.start),
                cp_to_byte(&case.text, labelled.end),
            ))
        })
        .collect()
}

/// Whether one predicted region covers every byte of a gold span.
///
/// The registry returns the merged, non-overlapping regions the anonymiser
/// masks, so a token covers a gold span exactly when one region contains it.
fn covered(predicted: &[Span], gold: &GoldSpan) -> bool {
    predicted
        .iter()
        .any(|span| span.start <= gold.start && span.end >= gold.end)
}

/// One tier's held-out tally.
#[derive(Default)]
struct TierTally {
    caught: u64,
    total: u64,
}

impl TierTally {
    fn add(&mut self, hit: bool) {
        self.total += 1;
        if hit {
            self.caught += 1;
        }
    }

    /// The rate in hundredths of a percent, truncated (never rounded up), or
    /// `None` when nothing was measured.
    fn hundredths(&self) -> Option<u64> {
        hundredths(self.caught, self.total)
    }
}

/// The Standard-pipeline measurement over every case.
#[derive(Default)]
struct StandardMeasure {
    c: TierTally,
    h: TierTally,
    /// Every scored class, names excluded, and the names themselves.
    scored: TierTally,
    names: u64,
    trap_fp: u64,
    p95_ms: u64,
}

/// The Deep-pipeline measurement over every case.
#[derive(Default)]
struct DeepMeasure {
    c: TierTally,
    h: TierTally,
    scored: TierTally,
    names: u64,
    trap_fp: u64,
    p95_ms: u64,
    peak_mb: Option<u64>,
}

/// Fold one case's gold spans into the three tallies a measure carries: tier
/// C, tier H, the scored recall. A name is skipped in both directions -- not a
/// miss, not an over-mask, no bar; every other kind enters the scored recall.
fn tally_case(
    (c, h, scored): (&mut TierTally, &mut TierTally, &mut TierTally),
    gold: &[GoldSpan],
    predicted: &[Span],
) {
    for span in gold {
        if is_name(span.kind) {
            continue;
        }
        let hit = covered(predicted, span);
        scored.add(hit);
        match scored_tier(span.kind) {
            Some(Tier::C) => c.add(hit),
            Some(Tier::H) => h.add(hit),
            _ => {}
        }
    }
}

/// `caught / total` in hundredths of a percent, truncated, or `None` when the
/// tally is empty: it has no rate and used to read `100 %`.
fn hundredths(caught: u64, total: u64) -> Option<u64> {
    (total > 0).then(|| caught.saturating_mul(10000) / total)
}

/// What a cell shows when nothing was measured.
const NO_RATE: &str = "n/a (n = 0)";

/// `xx.xx %`, or [`NO_RATE`] when the tally is empty.
fn rate_cell(caught: u64, total: u64) -> String {
    hundredths(caught, total).map_or_else(|| NO_RATE.to_string(), pct)
}

/// Render hundredths of a percent as `xx.xx %` without rounding up.
fn pct(hundredths: u64) -> String {
    format!("{}.{:02} %", hundredths / 100, hundredths % 100)
}

/// `MET` when the measured rate reaches the bar, `MISSED` otherwise.
fn met(hundredths: u64, bar: u64) -> &'static str {
    if hundredths >= bar {
        "MET"
    } else {
        "MISSED"
    }
}

/// One table row, in the exact column shape of the table in `README.md`.
fn row_line(measure: &str, value: &str, bar: &str, status: &str) -> String {
    format!("{measure:<42}{value:<10}{bar:<11}{status}")
}

fn print_row(measure: &str, value: &str, bar: &str, status: &str) {
    println!("{}", row_line(measure, value, bar, status));
}

/// A measured row and its bar. The bar is decided only on a tally that holds
/// something: an empty one prints `n/a (n = 0)`, never a pass. The counts
/// always print, so a rate is never read without its denominator.
fn measured_line(measure: &str, tally: &TierTally, bar: Option<(&str, u64)>) -> String {
    let text = bar.map_or("no bar", |(t, _)| t);
    let Some(value) = tally.hundredths() else {
        return row_line(measure, NO_RATE, text, "NOT MEASURED");
    };
    let status = match bar {
        Some((_, at)) => met(value, at),
        None => "MEASURED",
    };
    let status = format!("{status} {}/{}", tally.caught, tally.total);
    row_line(measure, &pct(value), text, &status)
}

fn measured_row(measure: &str, tally: &TierTally, bar: Option<(&str, u64)>) {
    println!("{}", measured_line(measure, tally, bar));
}

/// The Tier C bar, as the rows print it.
const BAR_C: Option<(&str, u64)> = Some((">= 99.5 %", BAR_C_HUNDREDTHS));

/// Read the frozen held-out-2 set. Line 1 hashes every byte after it, and both
/// that digest and the maintainer-approved code pin must match before scoring.
/// Returns the verified hash and the cases.
fn parse_heldout_2(text: &str) -> Result<(String, Vec<Case>), String> {
    let (head, body) = text.split_once('\n').unwrap_or((text, ""));
    let want = head
        .strip_prefix("# sha256: ")
        .ok_or("held-out-2: line 1 is not `# sha256: <hex>`")?
        .trim();
    let got = sha256_hex(body.as_bytes());
    if want != got {
        return Err(format!(
            "held-out-2: content sha256 {got} != header {want}: the frozen set was edited"
        ));
    }
    if got != HELDOUT_2_SHA256 {
        return Err(format!(
            "held-out-2: content sha256 {got} != code pin {HELDOUT_2_SHA256}; re-baselining needs a lead decision"
        ));
    }
    let cases = body
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| serde_json::from_str(line).map_err(|e| format!("held-out-2: {e}")))
        .collect::<Result<Vec<Case>, String>>()?;
    Ok((got, cases))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_heldout_2_scope(cases: &[Case]) -> Result<(), String> {
    if let Some(case) = cases.iter().find(|case| !in_scope(&case.lang)) {
        return Err(format!(
            "held-out-2: out-of-scope case {} has language {}; re-baselining needs a lead decision",
            case.id, case.lang
        ));
    }
    Ok(())
}

/// Letters and digits of `text`, lower-cased.
fn skeleton(text: &str) -> String {
    text.chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The gate output without its tokens (`⟦…⟧`) and removal markers (`[… removed]`).
fn clear_of(out: &str) -> String {
    let (head, tokens) = out.split_once('⟦').unwrap_or((out, ""));
    let mut text = head.to_string();
    for part in tokens.split('⟦') {
        text.push_str(part.split_once('⟧').map_or("", |(_, rest)| rest));
    }
    while let Some(end) = text.find(" removed]") {
        let start = text[..end].rfind('[').unwrap_or(end);
        text.replace_range(start..end + " removed]".len(), " ");
    }
    text
}

/// Whether the gold value can still be read in what the gate issued: the value
/// itself, or a run of 6 of its letters and digits (all of them when shorter)
/// that the rest of the text did not already hold. This is the LEAK-FINDER-1
/// rule on Unicode letters, so a partial mask is a miss and a Han term counts.
fn leaked(text: &str, gold: &GoldSpan, issued: &str) -> bool {
    let value = text.get(gold.start..gold.end).unwrap_or("");
    if issued.contains(value) {
        return true;
    }
    let rest = format!("{} {}", &text[..gold.start], &text[gold.end..]);
    let (seed, rest, out) = (
        skeleton(value),
        skeleton(&rest),
        skeleton(&clear_of(issued)),
    );
    let seed: Vec<char> = seed.chars().collect();
    let k = seed.len().min(6);
    k > 0
        && seed.windows(k).any(|run| {
            let run: String = run.iter().collect();
            out.contains(&run) && !rest.contains(&run)
        })
}

fn gate_hides(text: &str, gold: &GoldSpan, issued: Option<&str>) -> bool {
    issued.is_some_and(|issued| !leaked(text, gold, issued))
}

/// Tier C over one set of cases, through the three paths.
#[derive(Default)]
struct TierCPaths {
    registry: TierTally,
    private: TierTally,
    open: TierTally,
    /// Class -> `[n, missed in Private, missed in Open]`.
    misses: BTreeMap<&'static str, [u64; 3]>,
    /// `(class, language) -> [Private hits, Private misses, Open hits, Open misses]`.
    by_class_language: BTreeMap<(&'static str, String), [u64; 4]>,
    /// (class, mode, feature, bucket) -> misses; keys contain no case data.
    miss_shape: BTreeMap<(&'static str, &'static str, &'static str, &'static str), u64>,
    /// E-mail, phone, address: always hidden in Private, kept in Open by design.
    contact: TierTally,
    langs: BTreeSet<String>,
    /// Class -> `[n, Standard registry, gate Private, gate Open, registry hit
    /// left clear in Private, in Open]` (GATE-REGISTRY-GAP-1). Counts only.
    gap: BTreeMap<&'static str, [u64; 6]>,
}

impl TierCPaths {
    fn add_gold(
        &mut self,
        kind: EntityKind,
        lang: &str,
        registry_hit: bool,
        private_hidden: bool,
        open_hidden: bool,
    ) {
        self.registry.add(registry_hit);
        self.private.add(private_hidden);
        self.open.add(open_hidden);
        if let Some(class) = report_class(kind) {
            let row = self.misses.entry(class).or_insert([0; 3]);
            row[0] += 1;
            row[1] += u64::from(!private_hidden);
            row[2] += u64::from(!open_hidden);
        }
        if let Some(class) = tier_c_class(kind) {
            let row = self
                .by_class_language
                .entry((class, lang.to_owned()))
                .or_insert([0; 4]);
            row[usize::from(!private_hidden)] += 1;
            row[2 + usize::from(!open_hidden)] += 1;
        }
    }
}

/// The five public Tier C categories, kept in display order.
const TIER_C_CLASSES: [&str; 5] = ["IBAN", "card", "national ID/passport", "health", "secret"];

fn tier_c_class(kind: EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::Iban => Some("IBAN"),
        EntityKind::CreditCard => Some("card"),
        EntityKind::NationalId
        | EntityKind::PassportMrz
        | EntityKind::FrNir
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino => Some("national ID/passport"),
        EntityKind::Health => Some("health"),
        EntityKind::Secret => Some("secret"),
        _ => None,
    }
}

fn tier_c_breakdown(paths: &TierCPaths) -> Vec<String> {
    let mut lines = vec![
        "| class | language | Private n | hit | miss | Open n | hit | miss |".to_owned(),
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |".to_owned(),
    ];
    for class in TIER_C_CLASSES {
        let mut totals = [0u64; 4];
        for lang in IN_SCOPE_LANGS {
            let [pm, p_miss, om, o_miss] = paths
                .by_class_language
                .get(&(class, lang.to_owned()))
                .copied()
                .unwrap_or([0; 4]);
            totals[0] += pm + p_miss;
            totals[1] += pm;
            totals[2] += om + o_miss;
            totals[3] += om;
            lines.push(format!(
                "| {class} | {lang} | {} | {pm} | {p_miss} | {} | {om} | {o_miss} |",
                pm + p_miss,
                om + o_miss,
            ));
        }
        lines.push(format!(
            "| {class} | TOTAL | {} | {} | {} | {} | {} | {} |",
            totals[0],
            totals[1],
            totals[0] - totals[1],
            totals[2],
            totals[3],
            totals[2] - totals[3]
        ));
    }
    lines
}

fn add_shape(
    paths: &mut TierCPaths,
    class: &'static str,
    mode: &'static str,
    feature: &'static str,
    bucket: &'static str,
) {
    *paths
        .miss_shape
        .entry((class, mode, feature, bucket))
        .or_default() += 1;
}

/// Structural characteristics only. The caller never stores the value or text.
fn miss_shape(
    paths: &mut TierCPaths,
    mode: &'static str,
    class: &'static str,
    case: &Case,
    gold: &GoldSpan,
    predicted: &[Span],
    issued: Option<&str>,
) {
    let value = case.text.get(gold.start..gold.end).unwrap_or("");
    let overlapping: Vec<&Span> = predicted
        .iter()
        .filter(|span| span.start < gold.end && gold.start < span.end)
        .collect();
    let failure = if issued.is_none() {
        "refusal"
    } else if overlapping.is_empty() {
        "no overlapping span"
    } else {
        let mut covered: Vec<(usize, usize)> = overlapping
            .iter()
            .map(|span| (span.start.max(gold.start), span.end.min(gold.end)))
            .collect();
        covered.sort_unstable();
        let bytes = covered
            .into_iter()
            .fold(Vec::<(usize, usize)>::new(), |mut acc, span| {
                if let Some(last) = acc.last_mut().filter(|last| span.0 <= last.1) {
                    last.1 = last.1.max(span.1);
                } else {
                    acc.push(span);
                }
                acc
            });
        let covered_len: usize = bytes.iter().map(|(start, end)| end - start).sum();
        if covered_len < value.len() {
            if covered_len > 0 {
                let before = bytes.first().is_some_and(|(start, _)| *start > gold.start);
                let after = bytes.last().is_some_and(|(_, end)| *end < gold.end);
                add_shape(
                    paths,
                    class,
                    mode,
                    "uncovered remainder",
                    match (before, after) {
                        (true, true) => "both sides",
                        (true, false) => "before",
                        (false, true) => "after",
                        (false, false) => "both sides",
                    },
                );
            }
            if covered_len * 2 < value.len() {
                "partial coverage <50%"
            } else {
                "partial coverage 50-99%"
            }
        } else if overlapping.iter().any(|span| !span.kind.is_prohibited()) {
            "fully covered, non-prohibited kind"
        } else {
            "fully covered, prohibited kind"
        }
    };
    add_shape(paths, class, mode, "failure mode", failure);

    let len = value.chars().count();
    add_shape(
        paths,
        class,
        mode,
        "value length",
        match len {
            1..=8 => "1-8 chars",
            9..=20 => "9-20 chars",
            21..=40 => "21-40 chars",
            _ => "41+ chars",
        },
    );
    let has_han = value.chars().any(is_han);
    let has_latin = value.chars().any(is_latin);
    add_shape(
        paths,
        class,
        mode,
        "script",
        if has_han {
            "Han"
        } else if has_latin {
            "Latin"
        } else {
            "other"
        },
    );
    add_shape(
        paths,
        class,
        mode,
        "label cue within 40 chars",
        if has_label_cue(&case.text, gold.start) {
            "yes"
        } else {
            "no"
        },
    );
    add_shape(
        paths,
        class,
        mode,
        "spans line break",
        if value.contains('\n') || value.contains('\r') {
            "yes"
        } else {
            "no"
        },
    );
    add_shape(
        paths,
        class,
        mode,
        "contains digits",
        if value.chars().any(|ch| ch.is_ascii_digit()) {
            "yes"
        } else {
            "no"
        },
    );
    if gold.kind == EntityKind::Health {
        add_shape(
            paths,
            class,
            mode,
            "health phrase",
            if value.split_whitespace().count() <= 1 {
                "single word"
            } else {
                "multi-word"
            },
        );
    }

    add_requested_miss_shapes(paths, class, mode, case, gold, value);
}

fn add_requested_miss_shapes(
    paths: &mut TierCPaths,
    class: &'static str,
    mode: &'static str,
    case: &Case,
    gold: &GoldSpan,
    value: &str,
) {
    let lexicon_hit = SensitiveTermsRecognizer::new()
        .analyze(value)
        .iter()
        .any(|span| span.kind == EntityKind::Health && span.start < value.len() && span.end > 0);
    add_shape(
        paths,
        class,
        mode,
        "any lexicon term",
        if lexicon_hit { "yes" } else { "no" },
    );

    let (sentence_start, sentence_end) = sentence_bounds(&case.text, gold.start, gold.end);
    let sentence = &case.text[sentence_start..sentence_end];
    add_shape(
        paths,
        class,
        mode,
        "personal frame",
        if has_personal_frame(sentence) {
            "yes"
        } else {
            "no"
        },
    );
    add_shape(paths, class, mode, "gold category", gold_category(value));
    let sentence_len = sentence.chars().count();
    add_shape(
        paths,
        class,
        mode,
        "sentence length",
        match sentence_len {
            0..=60 => "≤ 60 chars",
            61..=150 => "61–150 chars",
            _ => "> 150 chars",
        },
    );
    let chars_before = case.text[sentence_start..gold.start].chars().count();
    let chars_in = case.text[gold.start..gold.end].chars().count();
    let chars_after = sentence_len.saturating_sub(chars_before + chars_in);
    add_shape(
        paths,
        class,
        mode,
        "span position",
        if chars_before <= sentence_len / 3 {
            "start"
        } else if chars_after <= sentence_len / 3 {
            "end"
        } else {
            "middle"
        },
    );
}

fn sentence_bounds(text: &str, start: usize, end: usize) -> (usize, usize) {
    let before = &text[..start];
    let sentence_start = before
        .char_indices()
        .rev()
        .find(|(_, ch)| matches!(ch, '.' | '!' | '?' | '。' | '！' | '？' | '\n' | '\r'))
        .map_or(0, |(i, ch)| i + ch.len_utf8());
    let after = &text[end..];
    let sentence_end = after
        .char_indices()
        .find(|(_, ch)| matches!(ch, '.' | '!' | '?' | '。' | '！' | '？' | '\n' | '\r'))
        .map_or(text.len(), |(i, _)| end + i);
    (sentence_start, sentence_end)
}

fn has_personal_frame(sentence: &str) -> bool {
    const FRAMES: &[&str] = &[
        "i",
        "me",
        "my",
        "mine",
        "we",
        "us",
        "our",
        "ours",
        "you",
        "your",
        "yours",
        "he",
        "him",
        "his",
        "she",
        "her",
        "hers",
        "they",
        "them",
        "their",
        "theirs",
        "je",
        "me",
        "moi",
        "mon",
        "ma",
        "mes",
        "nous",
        "notre",
        "nos",
        "tu",
        "te",
        "toi",
        "ton",
        "ta",
        "tes",
        "vous",
        "votre",
        "vos",
        "il",
        "elle",
        "on",
        "ils",
        "elles",
        "leur",
        "leurs",
        "ek",
        "my",
        "ons",
        "onze",
        "jy",
        "jou",
        "julle",
        "hy",
        "sy",
        "hulle",
        "én",
        "engem",
        "enyém",
        "mi",
        "minket",
        "miénk",
        "te",
        "téged",
        "tiéd",
        "ő",
        "őt",
        "övé",
        "mi",
        "minket",
        "ők",
        "övék",
        "jaz",
        "me",
        "moj",
        "moja",
        "moje",
        "midva",
        "mi",
        "naš",
        "naša",
        "ti",
        "tebe",
        "tvoj",
        "tvoja",
        "on",
        "ona",
        "oni",
        "one",
        "njihov",
        "我",
        "我们",
        "我的",
        "我们的",
        "你",
        "你们",
        "你的",
        "你们的",
        "他",
        "她",
        "他们",
        "她们",
        "他的",
        "她的",
        "他们的",
    ];
    let folded = sentence.to_lowercase();
    folded
        .split(|ch: char| !ch.is_alphanumeric())
        .any(|word| FRAMES.contains(&word))
        || FRAMES
            .iter()
            .any(|frame| frame.chars().any(is_han) && folded.contains(frame))
}

fn gold_category(value: &str) -> &'static str {
    let s = value.to_lowercase();
    let has = |terms: &[&str]| terms.iter().any(|term| s.contains(term));
    if has(&[
        "mg",
        "mcg",
        "dose",
        "tablet",
        "pill",
        "medication",
        "medicine",
        "drug",
        "insulin",
        "metformin",
        "mg",
        "médicament",
        "dose",
        "dosis",
        "gyógyszer",
        "lek",
        "药",
        "药物",
    ]) {
        "medication/dose"
    } else if has(&[
        "surgery",
        "surgical",
        "procedure",
        "operation",
        "biopsy",
        "transplant",
        "chirurgie",
        "opération",
        "operacija",
        "műtét",
        "手术",
    ]) {
        "procedure/surgery"
    } else if has(&[
        "pain",
        "fever",
        "cough",
        "symptom",
        "nausea",
        "fatigue",
        "douleur",
        "fièvre",
        "toux",
        "symptôme",
        "tünet",
        "bolečina",
        "simptom",
        "症状",
    ]) {
        "symptom"
    } else if has(&[
        "diabetes",
        "cancer",
        "asthma",
        "disease",
        "diagnosis",
        "syndrome",
        "maladie",
        "diabète",
        "diagnostic",
        "betegség",
        "bolezen",
        "疾病",
        "糖尿病",
    ]) {
        "diagnosis/disease"
    } else if has(&[
        "depression",
        "anxiety",
        "bipolar",
        "schizophrenia",
        "mental",
        "dépression",
        "anxiété",
        "dušev",
        "精神",
        "抑郁",
    ]) {
        "mental health"
    } else if has(&[
        "disability",
        "disabled",
        "autism",
        "paralysis",
        "handicap",
        "invalid",
        "disability",
        "invalidit",
        "残疾",
    ]) {
        "disability"
    } else if has(&[
        "pregnan",
        "pregnancy",
        "menstru",
        "fertility",
        "reproductive",
        "enceinte",
        "grossesse",
        "terhess",
        "nosečnost",
        "怀孕",
    ]) {
        "pregnancy/reproductive"
    } else {
        "other"
    }
}

fn is_han(ch: char) -> bool {
    matches!(ch as u32, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x2FA1F)
}

fn is_latin(ch: char) -> bool {
    matches!(ch as u32, 0x0041..=0x024F | 0x1E00..=0x1EFF)
}

fn has_label_cue(text: &str, value_start: usize) -> bool {
    const CUES: &[&str] = &[
        "diagnosis",
        "diagnostic",
        "diagnostique",
        "allergie",
        "allergy",
        "medication",
        "médicament",
        "medicament",
        "maladie",
        "condition",
        "treatment",
        "traitement",
        "santé",
        "sante",
        "health",
    ];
    let prefix = &text[..value_start.min(text.len())];
    let start = prefix
        .char_indices()
        .rev()
        .nth(39)
        .map_or(0, |(index, _)| index);
    let folded = prefix[start..].to_lowercase();
    CUES.iter().any(|cue| folded.contains(cue))
}

fn tier_c_miss_shape(paths: &TierCPaths) -> Vec<String> {
    let mut lines = vec![
        "held-out-2 Tier C miss shape (counts only):".to_owned(),
        "| class | mode | feature | bucket | misses |".to_owned(),
        "| --- | --- | --- | --- | ---: |".to_owned(),
    ];
    for ((class, mode, feature, bucket), count) in &paths.miss_shape {
        if *count > 0 {
            lines.push(format!(
                "| {class} | {mode} | {feature} | {bucket} | {count} |"
            ));
        }
    }
    lines
}

fn record_tier_c_gold(
    paths: &mut TierCPaths,
    lang: &str,
    text: &str,
    gold: &GoldSpan,
    predicted: &[Span],
    private_issued: Option<&str>,
    open_issued: Option<&str>,
) {
    paths.add_gold(
        gold.kind,
        lang,
        covered(predicted, gold),
        gate_hides(text, gold, private_issued),
        gate_hides(text, gold, open_issued),
    );
}

/// Score `cases` through the Registry and the gate in both modes. A gate
/// refusal counts as a miss: Private tokenises, it never blocks.
fn measure_tier_c(registry: &Registry, cases: &[&Case]) -> Result<TierCPaths, String> {
    measure_tier_c_gated(registry, cases, None)
}

fn measure_tier_c_gated(
    registry: &Registry,
    cases: &[&Case],
    deep: Option<&Arc<Registry>>,
) -> Result<TierCPaths, String> {
    let context = Context {
        destination: Destination::Vendor("privacy-eval".into()),
    };
    let gate = |mode| {
        let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
            return Err(format!("the A1 {mode:?} grant was not admitted"));
        };
        #[cfg(feature = "ner-gliner")]
        if let Some(deep) = deep {
            return Ok(Gate::for_grant_with_deep_detector(
                &grant,
                [0x2Cu8; 32],
                Arc::new(
                    NameDictionary::new(std::iter::empty::<&str>()).map_err(|e| e.to_string())?,
                ),
                Arc::clone(deep) as Arc<dyn kernel_privacy::safetext::Detector>,
            ));
        }
        let _ = deep;
        Ok(Gate::for_grant(&grant, [0x2Cu8; 32]))
    };
    let (mut private, mut open) = (gate(PrivacyMode::Private)?, gate(PrivacyMode::Open)?);
    // The registry the Standard gate runs: `registry` is the Deep one when the
    // model is installed, so the gap line compares like with like.
    let standard = Registry::new();
    let mut out = TierCPaths::default();
    for case in cases {
        out.langs.insert(case.lang.clone());
        let predicted = registry.analyze(&case.text);
        let standard_predicted = standard.analyze(&case.text);
        let issued_p = private
            .text(&case.text)
            .ok()
            .map(|(s, _)| s.as_str().to_string());
        let issued_o = open
            .text(&case.text)
            .ok()
            .map(|(s, _)| s.as_str().to_string());
        for gold in gold_spans(case) {
            let hidden = |issued: &Option<String>| gate_hides(&case.text, &gold, issued.as_deref());
            if scored_tier(gold.kind) != Some(Tier::C) {
                if matches!(
                    gold.kind,
                    EntityKind::Email | EntityKind::Phone | EntityKind::Address
                ) {
                    out.contact.add(hidden(&issued_p));
                }
                continue;
            }
            record_tier_c_gold(
                &mut out,
                &case.lang,
                &case.text,
                &gold,
                &predicted,
                issued_p.as_deref(),
                issued_o.as_deref(),
            );
            if let Some(class) = tier_c_class(gold.kind) {
                let found = covered(&standard_predicted, &gold);
                let p = gate_hides(&case.text, &gold, issued_p.as_deref());
                let o = gate_hides(&case.text, &gold, issued_o.as_deref());
                let row = out.gap.entry(class).or_insert([0; 6]);
                for (cell, hit) in row
                    .iter_mut()
                    .zip([true, found, p, o, found && !p, found && !o])
                {
                    *cell += u64::from(hit);
                }
                if !p {
                    miss_shape(
                        &mut out,
                        "Private",
                        class,
                        case,
                        &gold,
                        &predicted,
                        issued_p.as_deref(),
                    );
                }
                if !o {
                    miss_shape(
                        &mut out,
                        "Open",
                        class,
                        case,
                        &gold,
                        &predicted,
                        issued_o.as_deref(),
                    );
                }
            }
        }
    }
    Ok(out)
}

/// The Tier C block. The bar rows are held-out-2 through the gate; then the
/// Registry; then the v1 split: its old all-language row (`old`, the tally the
/// table always printed), its in-scope rows, and its out-of-scope languages on
/// a row that is printed and never scored.
fn tier_c_rows(
    registry: &Registry,
    old: &TierTally,
    v1: &[&Case],
    v2: &[Case],
    deep: Option<&Arc<Registry>>,
) -> Result<Vec<String>, String> {
    validate_heldout_2_scope(v2)?;
    let v2: Vec<&Case> = v2.iter().collect();
    let (v1_in, v1_out): (Vec<&Case>, Vec<&Case>) =
        v1.iter().partition(|case| in_scope(&case.lang));
    let new = measure_tier_c(registry, &v2)?;
    let deep_new = deep
        .map(|detector| measure_tier_c_gated(registry, &v2, Some(detector)))
        .transpose()?;
    let inside = measure_tier_c(registry, &v1_in)?;
    let outside = measure_tier_c(registry, &v1_out)?;
    let per_class = new
        .misses
        .iter()
        .map(|(class, [n, p, o])| format!("{class} {p}/{o} of {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    let out_langs = outside.langs.iter().cloned().collect::<Vec<_>>().join(",");
    let independent = out_of_scope_independent_count(v1_out.iter().copied());
    let o = &outside.private;
    let mut rows = vec![
        measured_line("Tier C, held-out-2, gate Private", &new.private, BAR_C),
        measured_line("Tier C, held-out-2, gate Open", &new.open, BAR_C),
        measured_line("Tier C, held-out-2, Registry", &new.registry, None),
        format!("  held-out-2 misses (Private/Open of n): {per_class}"),
        measured_line("  e-mail/phone/address, h-o-2, Private", &new.contact, None),
    ];
    for class in TIER_C_CLASSES {
        let [n, found, p, o, lost_p, lost_o] = new.gap.get(class).copied().unwrap_or([0; 6]);
        rows.push(format!(
            "  held-out-2 {class}: registry {found} / gate {p} Private, {o} Open \
             (Standard, of {n}); registry-found left clear: {lost_p} Private, {lost_o} Open"
        ));
    }
    rows.push("held-out-2 Tier C gate breakdown (counts only):".to_owned());
    for (label, tally) in [
        (
            "Tier C, held-out-2, gate Private Deep",
            deep_new.as_ref().map(|m| &m.private),
        ),
        (
            "Tier C, held-out-2, gate Open Deep",
            deep_new.as_ref().map(|m| &m.open),
        ),
    ] {
        rows.push(tally.map_or_else(
            || format!("{label}: NOT MEASURED"),
            |t| measured_line(label, t, None),
        ));
    }
    rows.extend(tier_c_breakdown(&new));
    rows.extend(tier_c_miss_shape(&new));
    rows.extend([
        measured_line("Tier C, v1 all langs (old row), Registry", old, BAR_C),
        measured_line("Tier C, v1 in scope, gate Private", &inside.private, None),
        measured_line("Tier C, v1 in scope, gate Open", &inside.open, None),
        measured_line("Tier C, v1 in scope, Registry", &inside.registry, None),
        "v1 in-scope Tier C gate breakdown (counts only):".to_owned(),
    ]);
    rows.extend(tier_c_breakdown(&inside));
    rows.extend([
        row_line(
            &format!("Tier C, v1 out of scope [{out_langs}]"),
            &rate_cell(o.caught, o.total),
            "not scored",
            &format!("NOT SCORED gate {}/{}", o.caught, o.total),
        ),
        row_line(
            "Tier C, v1 RU/AR IBAN/card/ID/secret",
            &format!("{independent} values"),
            "not scored",
            "NOT SCORED",
        ),
    ]);
    Ok(rows)
}

fn out_of_scope_independent_count<'a>(cases: impl IntoIterator<Item = &'a Case>) -> usize {
    cases
        .into_iter()
        .filter(|case| matches!(case.lang.as_str(), "ru" | "ar"))
        .flat_map(gold_spans)
        .filter(|gold| {
            matches!(
                gold.kind,
                EntityKind::Iban
                    | EntityKind::CreditCard
                    | EntityKind::NationalId
                    | EntityKind::PassportMrz
                    | EntityKind::Secret
            )
        })
        .count()
}

/// Nearest-rank p95 of a per-case latency list, in milliseconds.
fn p95_ms(mut micros: Vec<u128>) -> u64 {
    if micros.is_empty() {
        return 0;
    }
    micros.sort_unstable();
    let len = micros.len();
    let rank = (len * 95).div_ceil(100).max(1) - 1;
    (micros[rank.min(len - 1)] / 1000) as u64
}

/// Peak resident set size of this process, in MB, from `/proc/self/status`.
///
/// `VmHWM` is the high-water mark, so reading it after the Deep pass is the
/// peak while Deep ran. `None` off Linux, where the table prints NOT MEASURED.
fn peak_rss_mb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// The commit under test, or `"unknown"`.
fn git_commit() -> String {
    if let Ok(value) = env::var("PRIVACY_EVAL_COMMIT") {
        let value = value.trim();
        if !value.is_empty() {
            return value.to_string();
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Read the frozen held-out case ids.
fn load_heldout(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Where the exported GLiNER checkpoint lives, when it is installed.
#[cfg(feature = "ner-gliner")]
fn find_gliner_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for key in [
        "PRIVACY_EVAL_GLINER_DIR",
        "AUX_GLINER_DIR",
        "GLINER_MODEL_DIR",
    ] {
        if let Some(value) = env::var_os(key) {
            candidates.push(PathBuf::from(value));
        }
    }
    if let Some(home) = env::var_os("AUXESIS_HOME") {
        candidates.push(PathBuf::from(home).join("models/gliner2-pii"));
    }
    // The model is never bundled in the repository.
    if let Some(home) = env::var_os("HOME") {
        candidates.push(PathBuf::from(&home).join("models/gliner2-pii"));
        candidates.push(PathBuf::from(&home).join(".auxesis/models/gliner2-pii"));
        candidates.push(PathBuf::from(home).join(".auxesis/models/gliner-multi-pii-v1"));
    }
    candidates.push(PathBuf::from("models/gliner-multi-pii-v1"));
    candidates.push(PathBuf::from("vendor/gliner-multi-pii-v1"));
    candidates.into_iter().find(|dir| {
        (dir.join("model.onnx").is_file() || dir.join("model_int8.onnx").is_file())
            && dir.join("tokenizer.json").is_file()
    })
}

/// The ONNX Runtime shared library, when one is installed.
#[cfg(feature = "ner-gliner")]
fn find_ort_dylib() -> Option<PathBuf> {
    if let Some(value) = env::var_os("ORT_DYLIB_PATH") {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    [
        "/usr/lib/libonnxruntime.so",
        "/usr/local/lib/libonnxruntime.so",
        "vendor/onnxruntime/lib/libonnxruntime.so",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
}

/// The Standard pipeline plus GLiNER, when the feature and the model exist.
#[cfg(feature = "ner-gliner")]
fn load_deep() -> Result<Arc<Registry>, String> {
    use kernel_privacy::{GlinerConfig, GlinerRecognizer};

    let model_dir = find_gliner_dir().ok_or_else(|| "no GLiNER model directory".to_string())?;
    let mut config = GlinerConfig::new(model_dir);
    if let Some(dylib) = find_ort_dylib() {
        config = config.with_ort_dylib(dylib);
    }
    let gliner = GlinerRecognizer::load(config).map_err(|error| error.to_string())?;
    Ok(Arc::new(
        Registry::builder()
            .with_all()
            .with_boxed_recognizer(Box::new(gliner))
            .build(),
    ))
}

/// Without the feature, Deep detection is never available.
#[cfg(not(feature = "ner-gliner"))]
fn load_deep() -> Result<Arc<Registry>, String> {
    Err("built without the ner-gliner feature".to_string())
}

/// Score the Standard pipeline: held-out tier recall, trap FPs, latency.
fn measure_standard(
    registry: &Registry,
    cases: &[Case],
    public: &PublicTerms,
    heldout: &HashSet<String>,
) -> StandardMeasure {
    let mut out = StandardMeasure::default();
    let mut latencies_us = Vec::with_capacity(cases.len());
    let mut anonymizer = Anonymizer::new([0x5Au8; 32]);
    for case in cases {
        let start = Instant::now();
        let predicted = registry.analyze(&case.text);
        let _ = anonymizer.anonymize(&case.text, &predicted);
        latencies_us.push(start.elapsed().as_micros());
        for span in &predicted {
            // A name is not a trap: names are clear by design, so a public term
            // read as a name is not a false alarm on the scored classes.
            if is_name(span.kind) || span.start >= span.end {
                continue;
            }
            if let Some(value) = case.text.get(span.start..span.end) {
                if public.contains(value) {
                    out.trap_fp += 1;
                }
            }
        }
        // Names are counted over the whole corpus, not just the held-out split:
        // the row says how many the harness saw, not how many it scored.
        let gold = gold_spans(case);
        out.names += gold.iter().filter(|s| is_name(s.kind)).count() as u64;
        if heldout.contains(&case.id) {
            tally_case((&mut out.c, &mut out.h, &mut out.scored), &gold, &predicted);
        }
    }
    out.p95_ms = p95_ms(latencies_us);
    out
}

/// Score the Deep pipeline: held-out tier recall, trap FPs, latency and memory.
fn measure_deep(
    registry: &Registry,
    cases: &[Case],
    public: &PublicTerms,
    heldout: &HashSet<String>,
) -> DeepMeasure {
    let mut out = DeepMeasure {
        peak_mb: None,
        ..DeepMeasure::default()
    };
    let mut latencies_us = Vec::with_capacity(cases.len());
    let mut anonymizer = Anonymizer::new([0x5Bu8; 32]);
    for case in cases {
        let start = Instant::now();
        let predicted = registry.analyze(&case.text);
        let _ = anonymizer.anonymize(&case.text, &predicted);
        latencies_us.push(start.elapsed().as_micros());
        for span in &predicted {
            if is_name(span.kind) || span.start >= span.end {
                continue;
            }
            if let Some(value) = case.text.get(span.start..span.end) {
                if public.contains(value) {
                    out.trap_fp += 1;
                }
            }
        }
        let gold = gold_spans(case);
        out.names += gold.iter().filter(|s| is_name(s.kind)).count() as u64;
        if heldout.contains(&case.id) {
            tally_case((&mut out.c, &mut out.h, &mut out.scored), &gold, &predicted);
        }
    }
    out.p95_ms = p95_ms(latencies_us);
    out.peak_mb = peak_rss_mb();
    out
}

/// The detection table: held-out tier recall, trap FPs, p95 latency and memory.
fn run_table(cases: &[Case], public: &PublicTerms) -> Result<ExitCode, String> {
    let dir = private_sets::eval_dir()?;
    let (held_1, held_2) = match (
        private_sets::load(&dir, HELDOUT_1)?,
        private_sets::load(&dir, HELDOUT_2)?,
    ) {
        (HeldOut::Present(one), HeldOut::Present(two)) => (one, two),
        (one, two) => {
            for set in [one, two] {
                if let HeldOut::Absent(path) = set {
                    println!(
                        "held-out set absent, skipped: {} (set AUXESIS_EVAL_DIR)",
                        path.display()
                    );
                }
            }
            println!("held-out table: SKIPPED, nothing was measured");
            return Ok(ExitCode::SUCCESS);
        }
    };
    let heldout = load_heldout(&held_1);
    let held_out_cases = cases
        .iter()
        .filter(|case| heldout.contains(&case.id))
        .count();

    let standard = Registry::new();
    let standard_measure = measure_standard(&standard, cases, public, &heldout);

    let deep = match load_deep() {
        Ok(registry) => Some(registry),
        Err(reason) => {
            if env::var("PRIVACY_EVAL_DEBUG").is_ok_and(|value| value != "0") {
                eprintln!("privacy-eval: deep detection not measured: {reason}");
            }
            None
        }
    };
    let deep_measure = deep
        .as_deref()
        .map(|registry| measure_deep(registry, cases, public, &heldout));

    // Rows without a Standard/Deep qualifier report the detection level in
    // force: the production pipeline (Standard plus Deep) when the model is
    // present, Standard alone otherwise.
    let registry = deep.as_deref().unwrap_or(&standard);
    let c = deep_measure
        .as_ref()
        .map_or(&standard_measure.c, |measure| &measure.c);
    let (hash_2, cases_2) = parse_heldout_2(&held_2)?;
    let v1: Vec<&Case> = cases
        .iter()
        .filter(|case| heldout.contains(&case.id))
        .collect();

    print_row("measure", "value", "bar", "status");
    for line in tier_c_rows(registry, c, &v1, &cases_2, deep.as_ref())? {
        println!("{line}");
    }
    let deep_score = deep_measure.as_ref().map(|m| (&m.scored, m.names));
    let (scored, names) = deep_score.unwrap_or((&standard_measure.scored, standard_measure.names));
    measured_row("Scored recall, held-out, names excluded", scored, None);
    measured_row(
        "Tier H recall, held-out, Standard",
        &standard_measure.h,
        Some((">= 95 %", BAR_H_STANDARD_HUNDREDTHS)),
    );
    match &deep_measure {
        Some(measure) => measured_row(
            "Tier H recall, held-out, Deep",
            &measure.h,
            Some((">= 98 %", BAR_H_DEEP_HUNDREDTHS)),
        ),
        None => print_row(
            "Tier H recall, held-out, Deep",
            "n/a",
            ">= 98 %",
            "NOT MEASURED",
        ),
    }
    // Names are reported and never scored (EVAL-NO-NAMES).
    let seen = names;
    print_row(
        "names (not hidden by design)",
        &seen.to_string(),
        "no bar",
        &format!("{seen} seen"),
    );
    let trap_fp = deep_measure
        .as_ref()
        .map_or(standard_measure.trap_fp, |measure| measure.trap_fp);
    print_row(
        "False positives on trap cases",
        &trap_fp.to_string(),
        "<= 40",
        if trap_fp <= BAR_TRAP_FP {
            "MET"
        } else {
            "MISSED"
        },
    );
    let standard_ms = standard_measure.p95_ms;
    print_row(
        "Latency p95, Standard",
        &format!("{standard_ms} ms"),
        "<= 150 ms",
        if standard_ms <= BAR_LATENCY_STANDARD_MS {
            "MET"
        } else {
            "MISSED"
        },
    );
    match &deep_measure {
        Some(measure) => {
            let deep_ms = measure.p95_ms;
            print_row(
                "Latency p95, Deep detection",
                &format!("{deep_ms} ms"),
                "<= 400 ms",
                if deep_ms <= BAR_LATENCY_DEEP_MS {
                    "MET"
                } else {
                    "MISSED"
                },
            );
            match measure.peak_mb {
                Some(mb) => print_row(
                    "Peak memory, Deep detection",
                    &format!("{mb} MB"),
                    "<= 1 GB",
                    if mb <= BAR_PEAK_MEMORY_MB {
                        "MET"
                    } else {
                        "MISSED"
                    },
                ),
                None => print_row(
                    "Peak memory, Deep detection",
                    "n/a",
                    "<= 1 GB",
                    "NOT MEASURED",
                ),
            }
        }
        None => {
            print_row(
                "Latency p95, Deep detection",
                "n/a",
                "<= 400 ms",
                "NOT MEASURED",
            );
            print_row(
                "Peak memory, Deep detection",
                "n/a",
                "<= 1 GB",
                "NOT MEASURED",
            );
        }
    }
    let private = measure_mode(cases, PrivacyMode::Private, "Private")?;
    let open = measure_mode(cases, PrivacyMode::Open, "Open")?;
    println!("\nper-class over the whole in-repo corpus (not the held-out split):");
    print!("{}", class_table(&private, &open));
    print_known_contacts(Path::new(KNOWN_CONTACTS));
    print_k10(cases);
    print_prose();
    print_hu_check(cases);
    let languages: BTreeSet<&str> = cases.iter().map(|case| case.lang.as_str()).collect();
    println!(
        "corpus: {} cases, held-out {} cases, langs [{}], commit {}",
        cases.len(),
        held_out_cases,
        languages.into_iter().collect::<Vec<_>>().join(","),
        git_commit()
    );
    println!(
        "held-out-2: {} cases, sha256 {hash_2} (verified), Tier C scored on [{}]",
        cases_2.len(),
        IN_SCOPE_LANGS.join(",")
    );
    Ok(ExitCode::SUCCESS)
}

/// The K10 rows: the Standard recall of the fictional `k10-` cases, grouped by
/// the four kinds K10 adds, and the spans the over-masking guards (`k10-neg-`)
/// produced. The rows have no bar and are not held-out: the counts print, and a
/// guard that masks anything prints `MISSED`.
fn print_k10(cases: &[Case]) {
    let registry = Registry::new();
    let mut groups: BTreeMap<&'static str, TierTally> = BTreeMap::new();
    let (mut guard_spans, mut guard_cases) = (0u64, 0u64);
    for case in cases.iter().filter(|case| case.id.starts_with("k10-")) {
        let predicted = registry.analyze(&case.text);
        if case.id.starts_with("k10-neg-") {
            guard_cases += 1;
            guard_spans += predicted.len() as u64;
            continue;
        }
        for gold in gold_spans(case) {
            let group = match gold.kind {
                EntityKind::Health => "K10 health terms",
                EntityKind::Religion
                | EntityKind::SexualOrientation
                | EntityKind::Union
                | EntityKind::Ethnicity => "K10 Art. 9 other categories",
                EntityKind::Phone => "K10 phone, Chinese mobile",
                EntityKind::Secret => "K10 API keys and tokens",
                _ => continue,
            };
            groups
                .entry(group)
                .or_default()
                .add(covered(&predicted, &gold));
        }
    }
    for (measure, tally) in &groups {
        print_row(
            measure,
            &rate_cell(tally.caught, tally.total),
            "no bar",
            &format!("MEASURED {}/{}", tally.caught, tally.total),
        );
    }
    let status = if guard_spans == 0 { "MET" } else { "MISSED" };
    print_row(
        "K10 over-mask guards",
        &format!("{guard_spans}"),
        "0 spans",
        &format!("{status}, {guard_cases} cases"),
    );
}

/// The Hungarian over-mask check: the share of the HU cases (e-mail threads and
/// short texts, ids `hu-…`) that hold a K10 span outside every gold span. Bar: at
/// most 0.5 %. A span counts as false when it overlaps no gold span.
fn print_hu_check(cases: &[Case]) {
    let registry = Registry::new();
    let (mut total, mut over) = (0u64, 0u64);
    for case in cases.iter().filter(|case| case.id.starts_with("hu-")) {
        total += 1;
        let golds = gold_spans(case);
        let false_k10 = registry.analyze(&case.text).iter().any(|span| {
            matches!(span.recognizer, "sensitive_terms" | "secrets")
                && !golds
                    .iter()
                    .any(|gold| span.start < gold.end && gold.start < span.end)
        });
        if false_k10 {
            over += 1;
        }
    }
    let status = if total == 0 {
        "NOT MEASURED"
    } else if over * 200 <= total {
        "MET"
    } else {
        "MISSED"
    };
    print_row(
        "Over-mask, HU e-mail and short cases",
        &rate_cell(over, total),
        "<= 0.5 %",
        &format!("{status} {over}/{total}"),
    );
}

/// The normal-prose rows: the share of prose lines the K10 recognisers mask (bar:
/// at most 1 %), and the share any recogniser masks. The second row includes the
/// e-mail layer's name heuristic, which predates K10 and has no bar.
fn print_prose() {
    let registry = Registry::new();
    for lang in ["hu", "af", "sl"] {
        let upper = lang.to_uppercase();
        let path = format!("qa/privacy-eval/prose/{lang}.txt");
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("privacy-eval: prose {path} not measured: {error}");
                print_row(
                    &format!("Over-mask, normal prose {upper}"),
                    "n/a",
                    "<= 1 %",
                    "NOT MEASURED",
                );
                continue;
            }
        };
        let (mut k10_lines, mut any_lines, mut total) = (0u64, 0u64, 0u64);
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let spans = registry.analyze(line);
            total += 1;
            if spans
                .iter()
                .any(|span| matches!(span.recognizer, "sensitive_terms" | "secrets"))
            {
                k10_lines += 1;
            }
            if !spans.is_empty() {
                any_lines += 1;
            }
        }
        let status = if total == 0 {
            "NOT MEASURED"
        } else if k10_lines * 100 <= total {
            "MET"
        } else {
            "MISSED"
        };
        print_row(
            &format!("Over-mask, normal prose {upper}"),
            &rate_cell(k10_lines, total),
            "<= 1 %",
            &format!("{status} {k10_lines}/{total}"),
        );
        print_row(
            &format!("Any span, prose {upper} (incl. e-mail)"),
            &rate_cell(any_lines, total),
            "no bar",
            &format!("MEASURED {any_lines}/{total}"),
        );
    }
}

// ---------------------------------------------------------------------------

/// The rows of the per-class table. Every name [`report_class`] can return must
/// appear here or that class is measured and never shown.
const CLASS_ORDER: [&str; 13] = [
    "e-mail",
    "phone",
    "IBAN",
    "card",
    "ID",
    "business ID",
    "secret",
    "health",
    "special category",
    "address",
    "date of birth",
    "IP",
    "URL",
];

/// The README class of a kind, or `None` for a name.
///
/// Identity documents and company identifiers are separate rows on purpose: the
/// national ID kinds are prohibited, the SIREN/SIRET/VAT kinds are not, so a
/// shared row would understate the prohibited ones in Open. A name has no
/// class because it is not hidden, so there is nothing to report.
fn report_class(kind: EntityKind) -> Option<&'static str> {
    if is_name(kind) {
        return None;
    }
    Some(match kind {
        EntityKind::Email => "e-mail",
        EntityKind::Phone => "phone",
        EntityKind::Iban => "IBAN",
        EntityKind::CreditCard => "card",
        EntityKind::Secret => "secret",
        EntityKind::Address => "address",
        EntityKind::DateOfBirth => "date of birth",
        EntityKind::IpV4 => "IP",
        EntityKind::Url => "URL",
        EntityKind::Health => "health",
        EntityKind::Religion
        | EntityKind::SexualOrientation
        | EntityKind::Union
        | EntityKind::Ethnicity => "special category",
        EntityKind::FrSiren | EntityKind::FrSiret | EntityKind::FrVat => "business ID",
        EntityKind::FrNir
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino
        | EntityKind::PassportMrz
        | EntityKind::NationalId => "ID",
        EntityKind::Person | EntityKind::Organization => return None,
    })
}

/// One mode's measurement of the whole corpus.
#[derive(Default)]
struct ModeTable {
    /// Class -> `[hidden, n]`, the shape `Totals::per_kind` already uses.
    classes: BTreeMap<&'static str, [u64; 2]>,
    /// Classes this mode keeps in clear by design; their cell prints `n/a`.
    kept: BTreeSet<&'static str>,
    /// Texts holding no value of a scored class: a name does not make a text
    /// one, which is what keeps a name from reading as an over-mask.
    plain: u64,
    /// Those texts the gate changed anyway.
    over: u64,
    /// Texts the gate refused: never scored, and printed so one cannot hide.
    refused: u64,
}

/// The classes `policy` keeps in clear by design, so a 0 % against them is a
/// design statement and not a miss.
///
/// Read from the grant, never from the observed numbers. `Tokenised` (Private)
/// masks every class it detects, so it keeps none; `Passthrough` (Open) runs
/// the detectors and replaces only [`EntityKind::is_prohibited`] values with a
/// `[<class> removed]` marker, so it keeps every class outside that set.
/// Names are kept by both, and have no class here at all.
fn kept_by_design(policy: GrantPolicy) -> BTreeSet<&'static str> {
    if policy != GrantPolicy::Passthrough {
        return BTreeSet::new();
    }
    EntityKind::ALL
        .iter()
        .filter_map(|kind| report_class(*kind))
        .filter(|class| {
            !EntityKind::ALL
                .iter()
                .any(|kind| report_class(*kind) == Some(*class) && kind.is_prohibited())
        })
        .collect()
}

impl ModeTable {
    /// Record one value of `class`: `n` grows, and `hidden` when it is gone
    /// from what the gate issued.
    fn add(&mut self, class: &'static str, hidden: bool) {
        let tally = self.classes.entry(class).or_insert([0, 0]);
        tally[1] += 1;
        if hidden {
            tally[0] += 1;
        }
    }
}

/// Run every case through a production gate for `mode`, labelled `label`.
fn measure_mode(cases: &[Case], mode: PrivacyMode, label: &str) -> Result<ModeTable, String> {
    let context = Context {
        destination: Destination::Vendor("privacy-eval".into()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
        return Err(format!("the A1 {label} grant was not admitted"));
    };
    let kept = kept_by_design(grant.policy());
    let mut gate = Gate::for_grant(&grant, [0x2Au8; 32]);
    let mut table = ModeTable::default();
    for case in cases {
        let (safe, _report) = match gate.text(&case.text) {
            Ok(issued) => issued,
            Err(error) => {
                table.refused += 1;
                eprintln!("privacy-eval: {label} refused {}: {error}", case.id);
                continue;
            }
        };
        let mut scored = 0u64;
        for gold in gold_spans(case) {
            let value = case.text.get(gold.start..gold.end).unwrap_or("");
            if let Some(class) = report_class(gold.kind) {
                scored += 1;
                table.add(class, !safe.as_str().contains(value));
            }
        }
        // Over-mask is what the reader sees: the issued text differs from the
        // input. A class the mode keeps in clear changes nothing, so it never
        // counts, whatever the detectors reported.
        if scored == 0 {
            table.plain += 1;
            if safe.as_str() != case.text {
                table.over += 1;
            }
        }
    }
    table.kept = kept;
    Ok(table)
}

/// The per-class Markdown block, a README pastes as is. Snapshot-tested: the
/// shape is a contract, so a column cannot move without a test failing.
fn class_table(private: &ModeTable, open: &ModeTable) -> String {
    // A class the mode never hides has nothing to report, so it reads as a
    // design statement; a class it does hide reads its rate, or n/a with no
    // value to read.
    let cell = |tally: Option<&[u64; 2]>, kept: bool| {
        if kept {
            "n/a (kept by design)".to_string()
        } else {
            tally.map_or_else(|| NO_RATE.to_string(), |t| rate_cell(t[0], t[1]))
        }
    };
    let mut out = String::from("| class | n | Private | Open |\n| --- | ---: | ---: | ---: |\n");
    for class in CLASS_ORDER {
        let n = private
            .classes
            .get(class)
            .or_else(|| open.classes.get(class))
            .map_or_else(|| NO_RATE.to_string(), |t| t[1].to_string());
        out.push_str(&format!(
            "| {class} | {n} | {} | {} |\n",
            cell(private.classes.get(class), private.kept.contains(class)),
            cell(open.classes.get(class), open.kept.contains(class)),
        ));
    }
    out.push_str(&format!(
        "over-mask on the no-PII texts: Private {}, Open {}\n",
        rate_cell(private.over, private.plain),
        rate_cell(open.over, open.plain)
    ));
    if private.refused + open.refused > 0 {
        out.push_str(&format!(
            "gate refusals, counted in neither: Private {}, Open {}\n",
            private.refused, open.refused
        ));
    }
    out
}

/// One known-contacts case: the dictionary a caller would seed, a text, and the
/// names the text must mask. Offsets are bytes.
#[derive(Deserialize)]
struct KnownCase {
    id: String,
    dictionary: Vec<String>,
    text: String,
    spans: Vec<Gold>,
}

/// Known-contacts recall: the share of gold names covered by one dictionary
/// match. Every miss is printed with its case id and value, never hidden.
fn known_contacts_recall(path: &Path) -> Result<(u64, u64), String> {
    let handle = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let (mut caught, mut total) = (0u64, 0u64);
    for (line_number, line) in BufReader::new(handle).lines().enumerate() {
        let line = line.map_err(|error| format!("{}: {error}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let case: KnownCase = serde_json::from_str(&line).map_err(|error| {
            format!(
                "{}:{}: malformed JSON: {error}",
                path.display(),
                line_number + 1
            )
        })?;
        let dictionary = NameDictionary::new(&case.dictionary)
            .map_err(|error| format!("{}: {error}", case.id))?;
        let found = dictionary.analyze(&case.text);
        for gold in &case.spans {
            total += 1;
            if found
                .iter()
                .any(|span| span.start <= gold.start && span.end >= gold.end)
            {
                caught += 1;
            } else {
                let value = case.text.get(gold.start..gold.end).unwrap_or("?");
                println!("  miss {}: {value:?} in {:?}", case.id, case.text);
            }
        }
    }
    Ok((caught, total))
}

/// The known-contacts row of the table. It has no bar: the slice reports the
/// recall and its misses, and a missing file prints `NOT MEASURED`.
fn print_known_contacts(path: &Path) {
    match known_contacts_recall(path) {
        Ok((caught, total)) => print_row(
            "Known contacts recall",
            &rate_cell(caught, total),
            "no bar",
            &format!("MEASURED {caught}/{total}"),
        ),
        Err(reason) => {
            eprintln!("privacy-eval: known contacts not measured: {reason}");
            print_row("Known contacts recall", "n/a", "no bar", "NOT MEASURED");
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy before/after runner (K04), behind `--legacy`.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Totals {
    per_kind: BTreeMap<EntityKind, [usize; 3]>,
    gold: usize,
    covered: usize,
    trap_fp: usize,
    /// Gold person and organisation names, counted and never scored: they are
    /// not hidden by design, so they are in no recall, precision or region.
    names: usize,
    /// Region precision: merged predicted regions against merged gold regions.
    region_tp: usize,
    region_fp: usize,
    region_gold: usize,
    region_hit: usize,
    /// Same-kind false positives, `(kind, recogniser, value)`, for the
    /// over-masking drill.
    fps: Vec<(&'static str, &'static str, String)>,
    /// Every predicted span, `(kind, recogniser, value)`, when `AUX_EVAL_SPANS`.
    spans: Vec<(&'static str, &'static str, String)>,
    nanos: u128,
}

impl Totals {
    fn region_precision(&self) -> Option<f32> {
        ratio(self.region_tp, self.region_tp + self.region_fp)
    }

    fn region_recall(&self) -> Option<f32> {
        ratio(self.region_hit, self.region_gold)
    }

    fn overall_recall(&self) -> Option<f32> {
        let (tp, fn_): (usize, usize) = self.per_kind.values().fold((0, 0), |(tp, fn_), counts| {
            (tp + counts[0], fn_ + counts[2])
        });
        ratio(tp, tp + fn_)
    }

    fn overall_precision(&self) -> Option<f32> {
        let (tp, fp): (usize, usize) = self
            .per_kind
            .values()
            .fold((0, 0), |(tp, fp), counts| (tp + counts[0], fp + counts[1]));
        ratio(tp, tp + fp)
    }

    fn coverage(&self) -> Option<f32> {
        ratio(self.covered, self.gold)
    }
}

/// Whether a predicted span and a gold span share at least one byte.
fn overlaps(pred: &Span, gold: &GoldSpan) -> bool {
    pred.start < gold.end && gold.start < pred.end
}

/// Merge overlapping or adjacent spans into the regions the masker covers.
fn merged_regions(spans: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut sorted: Vec<(usize, usize)> = spans
        .iter()
        .copied()
        .filter(|(start, end)| start < end)
        .collect();
    sorted.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
    for (start, end) in sorted {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn regions_overlap(left: &(usize, usize), right: &(usize, usize)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn ratio(numerator: usize, denominator: usize) -> Option<f32> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f32 / denominator as f32)
    }
}

fn fmt_ratio(value: Option<f32>) -> String {
    match value {
        Some(v) => format!("{:.3}", v),
        None => "n/a".to_string(),
    }
}

/// Score one registry over every case.
fn measure(registry: &Registry, cases: &[Case], public: &PublicTerms, dump_fp: bool) -> Totals {
    let mut totals = Totals::default();
    let dump_spans = env::var("AUX_EVAL_SPANS").is_ok_and(|value| value != "0");
    let start = Instant::now();
    for case in cases {
        let mut gold: Vec<GoldSpan> = Vec::new();
        for labelled in &case.spans {
            let start = cp_to_byte(&case.text, labelled.start);
            let end = cp_to_byte(&case.text, labelled.end);
            if let Some(kind) = EntityKind::parse(&labelled.kind) {
                gold.push(GoldSpan::new(kind, start, end));
            }
        }
        // Names are counted and dropped: a missed name is not a miss, a
        // detected name is not a false positive, and neither enters a recall,
        // a precision or a region.
        totals.names += gold.iter().filter(|span| is_name(span.kind)).count();
        gold.retain(|span| !is_name(span.kind));
        let predicted: Vec<Span> = registry
            .analyze(&case.text)
            .into_iter()
            .filter(|span| !is_name(span.kind))
            .collect();
        if dump_spans {
            for pred in &predicted {
                if pred.start < pred.end && pred.end <= case.text.len() {
                    totals.spans.push((
                        pred.kind.as_str(),
                        pred.recognizer,
                        case.text[pred.start..pred.end].to_string(),
                    ));
                }
            }
        }
        totals.gold += gold.len();
        // Same-kind partial overlap, the matching rule the Python benchmark and
        // `examples/ner_eval.rs` use; a merged union still counts its members.
        for gold_span in &gold {
            let hit = predicted
                .iter()
                .any(|pred| pred.kind == gold_span.kind && overlaps(pred, gold_span));
            let entry = totals.per_kind.entry(gold_span.kind).or_insert([0, 0, 0]);
            if hit {
                entry[0] += 1;
            } else {
                entry[2] += 1;
            }
        }
        for pred in &predicted {
            let hit = gold
                .iter()
                .any(|gold_span| gold_span.kind == pred.kind && overlaps(pred, gold_span));
            let entry = totals.per_kind.entry(pred.kind).or_insert([0, 0, 0]);
            if !hit {
                entry[1] += 1;
                if dump_fp && pred.start < pred.end && pred.end <= case.text.len() {
                    totals.fps.push((
                        pred.kind.as_str(),
                        pred.recognizer,
                        case.text[pred.start..pred.end].to_string(),
                    ));
                }
            }
        }
        // Region precision: merge both sides first, so a separate span inside an
        // EMAIL or URL region is absorbed instead of counted twice.
        let gold_regions = merged_regions(
            &gold
                .iter()
                .map(|span| (span.start, span.end))
                .collect::<Vec<_>>(),
        );
        let pred_regions = merged_regions(
            &predicted
                .iter()
                .map(|span| (span.start, span.end))
                .collect::<Vec<_>>(),
        );
        for region in &pred_regions {
            if gold_regions
                .iter()
                .any(|gold| regions_overlap(region, gold))
            {
                totals.region_tp += 1;
            } else {
                totals.region_fp += 1;
            }
        }
        for region in &gold_regions {
            totals.region_gold += 1;
            if pred_regions
                .iter()
                .any(|pred| regions_overlap(region, pred))
            {
                totals.region_hit += 1;
            }
        }
        for gold_span in &gold {
            if predicted
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                totals.covered += 1;
            }
        }
        for pred in &predicted {
            if pred.start >= pred.end {
                continue;
            }
            if public.contains(&case.text[pred.start..pred.end]) {
                totals.trap_fp += 1;
            }
        }
    }
    totals.nanos = start.elapsed().as_nanos();
    totals
}

fn read_cases(paths: &[PathBuf]) -> Result<Vec<Case>, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path.is_dir() {
            let entries =
                fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))?;
            let mut found: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|entry| entry.extension().is_some_and(|ext| ext == "jsonl"))
                .collect();
            found.sort();
            files.extend(found);
        } else {
            files.push(path.clone());
        }
    }
    let mut cases = Vec::new();
    for file in files {
        let handle = File::open(&file).map_err(|error| format!("{}: {error}", file.display()))?;
        for (line_number, line) in BufReader::new(handle).lines().enumerate() {
            let line = line.map_err(|error| format!("{}: {error}", file.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let case: Case = serde_json::from_str(&line).map_err(|error| {
                format!(
                    "{}:{}: malformed JSON: {error}",
                    file.display(),
                    line_number + 1
                )
            })?;
            cases.push(case);
        }
    }
    Ok(cases)
}

/// The K04 before/after table.
fn run_legacy(cases: &[Case], public: &PublicTerms) {
    let dump_fp = env::var("AUX_EVAL_FP").is_ok_and(|value| value != "0");

    let before = Registry::builder().with_all().without_email_layer().build();
    let after = Registry::new();
    let before = measure(&before, cases, public, dump_fp);
    let after = measure(&after, cases, public, dump_fp);

    let languages: BTreeSet<&str> = cases.iter().map(|case| case.lang.as_str()).collect();
    // Names get exactly one line here too: the corpus header. They are clear by
    // design, so there is no before/after to compare.
    println!(
        "corpus: {} cases [{}], {} gold spans, {} names not scored",
        cases.len(),
        languages.into_iter().collect::<Vec<_>>().join(","),
        before.gold,
        after.names
    );
    println!();
    println!("{:<22} {:>8} {:>8}", "metric", "before", "after");
    println!(
        "{:<22} {:>8} {:>8}",
        "overall recall",
        fmt_ratio(before.overall_recall()),
        fmt_ratio(after.overall_recall())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "span precision",
        fmt_ratio(before.overall_precision()),
        fmt_ratio(after.overall_precision())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "region precision",
        fmt_ratio(before.region_precision()),
        fmt_ratio(after.region_precision())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "region recall",
        fmt_ratio(before.region_recall()),
        fmt_ratio(after.region_recall())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "mask coverage",
        fmt_ratio(before.coverage()),
        fmt_ratio(after.coverage())
    );
    println!(
        "{:<22} {:>8} {:>8}",
        "trap FP", before.trap_fp, after.trap_fp
    );
    let overhead_ms = (after.nanos as f64 - before.nanos as f64) / 1e6;
    let per_case_us = (after.nanos as f64 - before.nanos as f64) / cases.len() as f64 / 1e3;
    println!(
        "layer overhead: {overhead_ms:.2} ms over {} cases ({per_case_us:.1} us/case)",
        cases.len()
    );
    println!();
    println!(
        "{:<16} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "kind", "rec B", "rec A", "prec B", "prec A", "fp B", "fp A"
    );
    for kind in EntityKind::ALL {
        let Some(before_counts) = before.per_kind.get(&kind) else {
            continue;
        };
        let after_counts = after.per_kind.get(&kind).copied().unwrap_or([0, 0, 0]);
        println!(
            "{:<16} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            kind.as_str(),
            fmt_ratio(ratio(before_counts[0], before_counts[0] + before_counts[2])),
            fmt_ratio(ratio(after_counts[0], after_counts[0] + after_counts[2])),
            fmt_ratio(ratio(before_counts[0], before_counts[0] + before_counts[1])),
            fmt_ratio(ratio(after_counts[0], after_counts[0] + after_counts[1])),
            before_counts[1],
            after_counts[1]
        );
    }
    if dump_fp {
        println!();
        println!("after false positives ({}):", after.fps.len());
        let mut counts: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
        for (kind, recognizer, value) in &after.fps {
            *counts
                .entry((kind, recognizer, value.as_str()))
                .or_default() += 1;
        }
        let mut sorted: Vec<((&str, &str, &str), usize)> = counts.into_iter().collect();
        sorted.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        for ((kind, recognizer, value), count) in sorted {
            println!("{count:>4}  {kind:<14} {recognizer:<24} {value:?}");
        }
    }
    if env::var("AUX_EVAL_SPANS").is_ok_and(|value| value != "0") {
        println!();
        for (kind, recognizer, value) in &after.spans {
            println!("SPAN\t{kind}\t{recognizer}\t{value}");
        }
    }
}

fn main() -> ExitCode {
    // Every binary target calls the shared guard before it reads anything
    // (`crates/kernel-core/tests/workspace_guard.rs`). This one reads only the
    // paths it is given, so the guard only verifies the home and refuses a
    // sandbox that points at the real one.
    if let Err(error) = kernel_core::ensure_sandbox_guard(None) {
        eprintln!("{error}");
        return ExitCode::from(2);
    }
    let mut legacy = false;
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in env::args().skip(1) {
        if arg == "--legacy" {
            legacy = true;
        } else {
            paths.push(PathBuf::from(arg));
        }
    }
    if paths.is_empty() {
        paths.push(PathBuf::from("qa/privacy-eval/cases"));
    }
    let cases = match read_cases(&paths) {
        Ok(cases) => cases,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    if cases.is_empty() {
        eprintln!("no cases");
        return ExitCode::from(2);
    }

    let public = Path::new("qa/privacy-eval/public-terms.json")
        .exists()
        .then(|| PublicTerms::from_path("qa/privacy-eval/public-terms.json").ok())
        .flatten()
        .unwrap_or_else(PublicTerms::builtin);

    if legacy {
        run_legacy(&cases, &public);
        return ExitCode::SUCCESS;
    }
    match run_table(&cases, &public) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_the_spec_shape() {
        assert_eq!(
            row_line("measure", "value", "bar", "status"),
            "measure                                   value     bar        status"
        );
    }

    #[test]
    fn a_missed_bar_prints_missed_and_is_never_rounded_up() {
        // 99.49 % is below the 99.5 % bar: it must print MISSED, not 99.50/MET.
        let value = hundredths(9949, 10000).expect("a non-empty tally has a rate");
        assert_eq!(value, 9949);
        assert_eq!(pct(value), "99.49 %");
        assert_eq!(met(value, BAR_C_HUNDREDTHS), "MISSED");
        let line = row_line(
            "Tier C recall, held-out",
            &pct(value),
            ">= 99.5 %",
            met(value, BAR_C_HUNDREDTHS),
        );
        assert!(line.contains("99.49 %"), "{line}");
        assert!(!line.contains("99.50"), "{line}");
        assert!(line.ends_with(">= 99.5 %  MISSED"), "{line}");
        let at = hundredths(9950, 10000).expect("a non-empty tally has a rate");
        assert_eq!(met(at, BAR_C_HUNDREDTHS), "MET");
    }

    /// An empty tally used to read `100.00 %` and pass its bar. A missed name
    /// costs no recall; a missed e-mail costs a point of it. The denominator is
    /// never empty: an e-mail hit beside a missed name reads 100 %, the same
    /// case with the e-mail missed reads 0 %, a name alone measures nothing.
    #[test]
    fn an_empty_tally_is_never_a_pass_and_a_name_costs_no_recall() {
        assert_eq!(hundredths(0, 0), None);
        assert_eq!(rate_cell(0, 0), NO_RATE);
        let line = row_line(
            "Tier C recall",
            &rate_cell(0, 0),
            ">= 99.5 %",
            "NOT MEASURED",
        );
        assert!(line.ends_with(">= 99.5 %  NOT MEASURED"), "{line}");
        assert!(!line.contains("MET"), "{line}");

        let name = GoldSpan::new(EntityKind::Person, 0, 9);
        let email = GoldSpan::new(EntityKind::Email, 11, 27);
        let hit = [Span::new(EntityKind::Email, 11, 27, 1.0, "test")];
        let clean = score(&[name, email], &hit, 1);
        assert_eq!(clean.names, 1, "the name is still reported");
        assert_eq!(
            clean.scored.hundredths(),
            Some(10000),
            "a name costs nothing"
        );
        assert_eq!(
            (clean.c.total, clean.h.total),
            (0, 0),
            "no bar takes a name"
        );
        assert_eq!(score(&[name, email], &[], 1).scored.hundredths(), Some(0));
        assert_eq!(score(&[name], &[], 1).scored.hundredths(), None);
    }

    /// Score one case's gold with these predictions, as `measure_standard` does.
    fn score(gold: &[GoldSpan], predicted: &[Span], names: u64) -> StandardMeasure {
        let mut out = StandardMeasure {
            names,
            ..StandardMeasure::default()
        };
        tally_case((&mut out.c, &mut out.h, &mut out.scored), gold, predicted);
        out
    }

    /// The same through the real Standard scorer over a real case, so the
    /// policy is not only proven against `tally_case`.
    #[test]
    fn a_name_alone_leaves_the_held_out_scored_tally_empty() {
        let json = r#"{"id":"n1","lang":"en","text":"Bob Smith wrote it.","spans":[{"type":"PERSON","start":0,"end":9}]}"#;
        let cases: Vec<Case> = vec![serde_json::from_str(json).expect("case parses")];
        let out = measure_standard(
            &Registry::new(),
            &cases,
            &PublicTerms::builtin(),
            &HashSet::from(["n1".to_string()]),
        );
        assert_eq!(out.names, 1);
        assert_eq!(out.scored.hundredths(), None, "nothing to score");
        assert_eq!(out.c.hundredths(), None, "Tier C has no denominator");
        assert_eq!(out.h.hundredths(), None, "Tier H has no denominator");
    }

    /// Tier C claims exactly the kernel's prohibited set -- the five classes
    /// the owner requires hidden -- Tier H the model-emitted non-names, and
    /// every other scored class reaches no bar.
    #[test]
    fn a_tier_bar_reaches_only_its_own_classes() {
        let want = |kind: EntityKind, tier: Option<Tier>| {
            assert_eq!(scored_tier(kind), tier, "{kind:?}");
        };
        for kind in [
            EntityKind::Iban,
            EntityKind::CreditCard,
            EntityKind::NationalId,
        ] {
            want(kind, Some(Tier::C));
        }
        for kind in [EntityKind::Address, EntityKind::DateOfBirth] {
            want(kind, Some(Tier::H));
        }
        for kind in [EntityKind::Email, EntityKind::Phone, EntityKind::Person] {
            want(kind, None);
        }
    }

    /// One mode's table for the snapshot: `plain` no-PII texts, `over` of them
    /// over-masked, and `(class, hidden, n)` per class.
    fn mode(kept: &[&'static str], rows: &[(&'static str, u64, u64)]) -> ModeTable {
        ModeTable {
            classes: rows.iter().map(|r| (r.0, [r.1, r.2])).collect(),
            kept: kept.iter().copied().collect(),
            ..ModeTable::default()
        }
    }

    /// Every kind lands on a printed row, and Open keeps that row only when no
    /// kind in it is prohibited. `business ID` exists so the non-prohibited
    /// SIREN/SIRET/VAT kinds cannot inflate the prohibited `ID` row.
    #[test]
    fn every_kind_maps_to_a_row_with_the_right_prohibited_status() {
        let kept = kept_by_design(GrantPolicy::Passthrough);
        for kind in EntityKind::ALL {
            let class = report_class(kind);
            assert_eq!(class.is_none(), is_name(kind), "{kind:?}");
            // Postal addresses never leave the Mac (owner rule 10-21) but are
            // not one of the Tier C 100 % classes, so they keep their own row.
            assert_eq!(
                tier_c_class(kind).is_some(),
                kind.is_prohibited() && kind != EntityKind::Address,
                "{kind:?}"
            );
            let Some(class) = class else { continue };
            assert!(CLASS_ORDER.contains(&class), "{class} has no row");
            let prohibited = EntityKind::ALL
                .iter()
                .any(|k| report_class(*k) == Some(class) && k.is_prohibited());
            assert_eq!(kept.contains(class), !prohibited, "{class}");
        }
        assert!(kept_by_design(GrantPolicy::Tokenised).is_empty());
        assert!(kept.contains("e-mail") && kept.contains("business ID"));
        assert!(!kept.contains("ID") && !kept.contains("health"));
        // Religion, union, orientation and ethnicity are not prohibited: Open
        // keeps them, so they must not dilute the health row.
        assert!(kept.contains("special category"));
    }

    /// The README block is a contract: a column cannot be renamed, dropped or
    /// reordered without this failing.
    #[test]
    fn the_class_table_matches_its_snapshot() {
        let rows = [("e-mail", 6, 7), ("IBAN", 42, 42), ("ID", 59, 64)];
        let open = [("e-mail", 7, 7), ("IBAN", 42, 42), ("ID", 55, 64)];
        let p = mode(&[], &rows);
        let kept = ["e-mail", "phone", "business ID", "address", "date of birth"];
        let o = mode(&kept, &open);
        assert_eq!(
            class_table(&p, &o),
            concat!(
                "| class | n | Private | Open |\n",
                "| --- | ---: | ---: | ---: |\n",
                "| e-mail | 7 | 85.71 % | n/a (kept by design) |\n",
                "| phone | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
                "| IBAN | 42 | 100.00 % | 100.00 % |\n",
                "| card | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
                "| ID | 64 | 92.18 % | 85.93 % |\n",
                "| business ID | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
                "| secret | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
                "| health | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
                "| special category | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
                "| address | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
                "| date of birth | n/a (n = 0) | n/a (n = 0) | n/a (kept by design) |\n",
                "| IP | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
                "| URL | n/a (n = 0) | n/a (n = 0) | n/a (n = 0) |\n",
                "over-mask on the no-PII texts: Private n/a (n = 0), Open n/a (n = 0)\n",
            )
        );
    }

    /// End to end through a real gate on real cases: an IBAN is hidden in both
    /// modes, and the e-mail beside it reads `n/a (kept by design)` in Open.
    #[test]
    fn a_real_gate_hides_an_iban_and_keeps_the_email_in_open() {
        let json = r#"{"id":"p1","lang":"en","text":"IBAN FR7630006000011234567890189, mail a@b.org",
            "spans":[{"type":"IBAN","start":5,"end":34},{"type":"EMAIL","start":41,"end":48}]}"#;
        let cases = vec![serde_json::from_str(json).expect("case parses")];
        let open = measure_mode(&cases, PrivacyMode::Open, "Open").expect("open grant");
        let private = measure_mode(&cases, PrivacyMode::Private, "Private").expect("private grant");
        let table = class_table(&private, &open);
        assert!(
            table.contains("| IBAN | 1 | 100.00 % | 100.00 % |"),
            "{table}"
        );
        assert!(
            table.contains("| e-mail | 1 | 100.00 % | n/a (kept by design) |"),
            "{table}"
        );
    }

    /// A Russian case sits on its own printed row and costs the scored rows
    /// nothing; the old all-language row still counts it, so nothing hides.
    #[test]
    fn the_out_of_scope_row_prints_and_leaves_the_score() {
        let lines = [
            r#"{"id":"e1","lang":"en","text":"IBAN FR7630006000011234567890189 please","spans":[{"type":"IBAN","start":5,"end":32}]}"#,
            r#"{"id":"r1","lang":"ru","text":"Сегодня погода хорошая.","spans":[{"type":"HEALTH","start":8,"end":14}]}"#,
        ];
        let cases: Vec<Case> = lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("case parses"))
            .collect();
        let ids = HashSet::from(["e1".to_string(), "r1".to_string()]);
        let registry = Registry::new();
        let old = measure_standard(&registry, &cases, &PublicTerms::builtin(), &ids).c;
        let v1: Vec<&Case> = cases.iter().collect();
        let rows = tier_c_rows(&registry, &old, &v1, &cases[..1], None).expect("rows");
        let row = |label: &str| {
            rows.iter()
                .find(|line| line.starts_with(label))
                .unwrap_or_else(|| panic!("no `{label}` row in {rows:#?}"))
                .clone()
        };
        assert!(row("Tier C, v1 out of scope [ru]").ends_with("not scored NOT SCORED gate 0/1"));
        assert!(row("Tier C, held-out-2, gate Private").ends_with("MET 1/1"));
        assert!(row("Tier C, held-out-2, gate Open").ends_with("MET 1/1"));
        assert!(row("Tier C, v1 in scope, gate Private").ends_with("MEASURED 1/1"));
        assert!(row("Tier C, v1 all langs (old row)").ends_with("MISSED 1/2"));
    }

    #[test]
    fn a_gate_refusal_is_a_miss() {
        let gold = GoldSpan::new(EntityKind::Secret, 0, 8);
        assert!(!gate_hides("password", &gold, None));
    }

    #[test]
    fn the_private_row_uses_gate_output_even_when_registry_covers() {
        let text = "FR763000";
        let gold = GoldSpan::new(EntityKind::Iban, 0, text.len());
        let predicted = [Span::new(EntityKind::Iban, 0, text.len(), 1.0, "synthetic")];
        let mut paths = TierCPaths::default();
        record_tier_c_gold(
            &mut paths,
            "en",
            text,
            &gold,
            &predicted,
            None,
            Some("⟦IBAN_1⟧"),
        );
        assert_eq!((paths.registry.caught, paths.registry.total), (1, 1));
        assert_eq!((paths.private.caught, paths.private.total), (0, 1));
        assert_eq!((paths.open.caught, paths.open.total), (1, 1));
    }

    #[test]
    fn heldout_2_out_of_scope_cases_are_rejected() {
        let case: Case =
            serde_json::from_str(r#"{"id":"synthetic-ru","lang":"ru","text":"пример","spans":[]}"#)
                .expect("synthetic case parses");
        let error = validate_heldout_2_scope(&[case]).expect_err("out-of-scope is rejected");
        assert!(
            error.contains("synthetic-ru") && error.contains("ru"),
            "{error}"
        );
    }

    #[test]
    fn tier_c_breakdown_counts_are_language_scoped_and_never_render_values() {
        let cases: Vec<Case> = include_str!("../tests/fixtures/tier-c-breakdown.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).expect("synthetic case parses"))
            .collect();
        let registry = Registry::new();
        let refs: Vec<&Case> = cases.iter().collect();
        let measured = measure_tier_c(&registry, &refs).expect("synthetic gate measurement");
        let output = tier_c_breakdown(&measured).join("\n");

        assert!(
            output.contains("| IBAN | fr | 1 | 0 | 1 | 1 | 0 | 1 |"),
            "{output}"
        );
        assert!(
            output.contains("| card | en | 1 | 0 | 1 | 1 | 0 | 1 |"),
            "{output}"
        );
        assert!(
            output.contains("| national ID/passport | af | 1 | 1 | 0 | 1 | 1 | 0 |"),
            "{output}"
        );
        assert!(
            output.contains("| health | hu | 1 | 0 | 1 | 1 | 0 | 1 |"),
            "{output}"
        );
        assert!(
            output.contains("| secret | sl | 1 | 1 | 0 | 1 | 1 | 0 |"),
            "{output}"
        );
        assert!(
            output.contains("| IBAN | TOTAL | 1 | 0 | 1 | 1 | 0 | 1 |"),
            "{output}"
        );
        for case in &cases {
            for gold in &case.spans {
                let value = &case.text[gold.start..gold.end];
                assert!(
                    !output.contains(value),
                    "breakdown rendered fixture value {value}"
                );
            }
            assert!(!output.contains(&case.id), "breakdown rendered fixture id");
            assert!(
                !output.contains(&case.text),
                "breakdown rendered fixture text"
            );
        }
    }

    #[test]
    fn tier_c_miss_shape_renders_only_aggregate_buckets() {
        let cases: Vec<Case> = include_str!("../tests/fixtures/tier-c-breakdown.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).expect("synthetic case parses"))
            .collect();
        let mut paths = TierCPaths::default();
        for case in &cases {
            for gold in gold_spans(case) {
                if let Some(class) = tier_c_class(gold.kind) {
                    // Synthetic clear output guarantees a miss. Only structural counts are kept.
                    for mode in ["Private", "Open"] {
                        miss_shape(&mut paths, mode, class, case, &gold, &[], Some(&case.text));
                    }
                }
            }
        }
        let output = tier_c_miss_shape(&paths).join("\n");
        assert!(output.contains("| health | Open | value length | 9-20 chars | 1 |"));
        assert!(output.contains("| health | Private | health phrase | single word | 1 |"));
        assert!(output.contains("| secret | Private | contains digits | yes | 1 |"));
        for case in &cases {
            for gold in &case.spans {
                let value = &case.text[gold.start..gold.end];
                assert!(!output.contains(value), "miss shape rendered fixture value");
            }
            assert!(!output.contains(&case.id), "miss shape rendered fixture id");
            assert!(
                !output.contains(&case.text),
                "miss shape rendered fixture text"
            );
        }
    }

    #[test]
    fn requested_miss_shape_buckets_use_synthetic_health_text() {
        let case = Case {
            id: "synthetic-only".into(),
            lang: "en".into(),
            text: "I take metformin daily for diabetes today.".into(),
            spans: vec![],
        };
        let gold = GoldSpan::new(EntityKind::Health, 7, 16);
        let partial = [Span::new(EntityKind::Health, 9, 13, 1.0, "synthetic")];
        let mut paths = TierCPaths::default();
        miss_shape(
            &mut paths,
            "Private",
            "health",
            &case,
            &gold,
            &partial,
            Some("clear"),
        );
        let rows = tier_c_miss_shape(&paths).join("\n");
        assert!(rows.contains("| health | Private | any lexicon term | yes | 1 |"));
        assert!(rows.contains("| health | Private | personal frame | yes | 1 |"));
        assert!(rows.contains("| health | Private | gold category | medication/dose | 1 |"));
        assert!(rows.contains("| health | Private | sentence length | ≤ 60 chars | 1 |"));
        assert!(rows.contains("| health | Private | span position | start | 1 |"));
        assert!(rows.contains("| health | Private | uncovered remainder | both sides | 1 |"));
        assert!(!rows.contains("synthetic-only") && !rows.contains("metformin"));
    }

    #[test]
    fn russian_and_arabic_language_independent_values_get_an_unscored_row() {
        let lines = [
            r#"{"id":"r1","lang":"ru","text":"IBAN FR7630006000011234567890189","spans":[{"type":"IBAN","start":5,"end":32}]}"#,
            r#"{"id":"a1","lang":"ar","text":"secret sk_live_1234567890123456789012345678901234567890","spans":[{"type":"SECRET","start":7,"end":55}]}"#, // gitleaks:allow
        ];
        let cases: Vec<Case> = lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("synthetic case parses"))
            .collect();
        let rows = tier_c_rows(
            &Registry::new(),
            &TierTally::default(),
            &cases.iter().collect::<Vec<_>>(),
            &[],
            None,
        )
        .expect("synthetic RU/AR v1 cases are reported");
        let row = rows
            .iter()
            .find(|line| line.contains("RU/AR"))
            .expect("RU/AR row");
        assert!(
            row.contains("2 values") && row.contains("NOT SCORED"),
            "{row}"
        );
    }

    /// A value is hidden only when no run of 6 of its letters and digits is
    /// left: a half-masked IBAN is a miss, a fully tokenised one is not.
    #[test]
    fn a_partial_mask_is_a_miss() {
        let text = "IBAN FR76 3000 6000 0112 3456 7890 189 ok";
        let gold = GoldSpan::new(EntityKind::Iban, 5, 38);
        assert!(leaked(text, &gold, "IBAN ⟦IBAN_1⟧ 7890 189 ok"));
        assert!(!leaked(text, &gold, "IBAN ⟦IBAN_1⟧ ok"));
        assert!(!leaked(text, &gold, "IBAN [IBAN removed] ok"));
    }

    /// The set is pinned to a code constant; a synthetically rehashed body
    /// cannot authorize re-baselining by changing only its data header.
    #[test]
    fn the_heldout_2_pin_rejects_a_rehashed_synthetic_body() {
        assert_eq!(
            HELDOUT_2_SHA256,
            "8ed06af51b9d6bcc030d21421bdd7a59bfbba6eb3b9c6d76e5fed24700a64bef"
        );
        let body = "{\"id\":\"synthetic\",\"lang\":\"en\",\"text\":\"sample\",\"spans\":[]}\n";
        let header = sha256_hex(body.as_bytes());
        let error = parse_heldout_2(&format!("# sha256: {header}\n{body}"))
            .err()
            .expect("a self-consistent but unapproved hash is rejected");
        assert!(error.contains("lead decision"), "{error}");
    }

    /// With the sets in `$AUXESIS_EVAL_DIR`, both pass their pins and the
    /// header check; without them, the test says it skipped.
    #[test]
    fn the_held_out_sets_verify_when_present() {
        let dir = private_sets::eval_dir().expect("eval dir");
        match private_sets::load(&dir, HELDOUT_1).expect("held-out split") {
            HeldOut::Present(text) => assert!(!load_heldout(&text).is_empty()),
            HeldOut::Absent(path) => eprintln!("held-out set absent, skipped: {}", path.display()),
        }
        match private_sets::load(&dir, HELDOUT_2).expect("held-out-2") {
            HeldOut::Present(text) => {
                let (_, cases) = parse_heldout_2(&text).expect("held-out-2 header and code pin");
                validate_heldout_2_scope(&cases).expect("held-out-2 scope");
            }
            HeldOut::Absent(path) => eprintln!("held-out set absent, skipped: {}", path.display()),
        }
    }

    #[test]
    fn external_fixture_parses() {
        let text = include_str!("../scripts/fixtures/sample-cases.jsonl");
        let mut count = 0usize;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let _: Case = serde_json::from_str(line).expect("fixture case parses");
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn tiers_follow_the_kernel_classification() {
        assert_eq!(tier_of(EntityKind::Email), Tier::C);
        assert_eq!(tier_of(EntityKind::Iban), Tier::C);
        assert_eq!(tier_of(EntityKind::NationalId), Tier::C);
        // Names are their own tier, and that tier is never scored.
        assert_eq!(tier_of(EntityKind::Organization), Tier::Name);
        assert_eq!(tier_of(EntityKind::Health), Tier::C9);
        assert_eq!(tier_of(EntityKind::Religion), Tier::C9);
        assert_eq!(tier_of(EntityKind::SexualOrientation), Tier::C9);
        assert_eq!(tier_of(EntityKind::Union), Tier::C9);
        assert_eq!(tier_of(EntityKind::Ethnicity), Tier::C9);
        assert_eq!(tier_of(EntityKind::Secret), Tier::N);
    }
}
