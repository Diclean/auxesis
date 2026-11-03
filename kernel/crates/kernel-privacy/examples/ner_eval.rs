//! Score the local GLiNER recogniser, alone and unioned with the deterministic
//! registry, on the FAKE `qa/privacy-eval` corpus.
//!
//! This is the slice-1d/1e gate harness. It runs the Rust recogniser over the
//! corpus, compares its byte spans with the gold spans with the same matching
//! rule the Python benchmark used (same kind and a partial overlap), reports
//! per-language name recall and overall recall/precision, times short messages
//! and synthetic long threads, reads the process peak RSS, and repeats
//! everything for the union with the deterministic `Registry::new()`.
//!
//! Slice 1e adds the messy-email dev split and the before/after comparison:
//! `AUX_GLINER_EMAILS` is a comma-separated list of extra JSONL files (the
//! `emails-<lang>.jsonl` split). For those cases the report gains, for both the
//! pre-1e registry (`without_email_layer`) and the 1e registry, the union
//! recall, name recall, mask coverage, public-term trap FP and per-pattern
//! person recall, plus the GLiNER-only precision.
//!
//! Run it with the feature on and a local model directory:
//!
//! ```console
//! AUX_GLINER_MODEL_DIR=/path/to/export \
//! AUX_GLINER_ORT_DYLIB=/path/to/libonnxruntime.so \
//! cargo run -p kernel-privacy --features ner-gliner --example ner_eval
//! ```
//!
//! Options: `AUX_GLINER_ONNX` (`fp32` | `int8`, default `fp32`),
//! `AUX_GLINER_THRESHOLD` (default `0.4`), `AUX_GLINER_JSON` (write the report
//! to this path as well as stdout), `AUX_GLINER_REPEAT` (timing repetitions,
//! default 3), `AUX_GLINER_EMAILS` (extra JSONL files).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use kernel_privacy::decode::url_ranges;
use kernel_privacy::eval::GoldSpan;
use kernel_privacy::span::EntityKind;
use kernel_privacy::{EmailLayer, GlinerConfig, GlinerRecognizer, PublicTerms, Registry};
use serde_json::{json, Value};

const LANGS: [&str; 6] = ["fr", "en", "af", "hu", "ar", "ru"];
const SEP: &str = "\n\n---\n\n";

#[derive(Clone, Debug)]
struct Case {
    id: String,
    lang: String,
    kind: String,
    text: String,
    gold: Vec<GoldSpan>,
}

/// Parse one corpus file.
fn read_cases_file(path: &Path) -> Vec<Case> {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let mut cases = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: Value = serde_json::from_str(line).expect("case JSON");
        let cases_text = value["text"].as_str().expect("text");
        // The corpus stores Unicode scalar indices (it is written by Python);
        // the recogniser emits byte offsets, so convert once here.
        let mut scalar_to_byte = Vec::with_capacity(cases_text.chars().count() + 1);
        for (byte, _) in cases_text.char_indices() {
            scalar_to_byte.push(byte);
        }
        scalar_to_byte.push(cases_text.len());
        let gold = value["spans"]
            .as_array()
            .expect("spans")
            .iter()
            .filter_map(|span| {
                let kind = EntityKind::parse(span["type"].as_str()?)?;
                let start = span["start"].as_u64()? as usize;
                let end = span["end"].as_u64()? as usize;
                Some(GoldSpan::new(
                    kind,
                    scalar_to_byte[start],
                    scalar_to_byte[end],
                ))
            })
            .collect();
        cases.push(Case {
            id: value["id"].as_str().expect("id").to_string(),
            lang: value["lang"].as_str().expect("lang").to_string(),
            kind: value["kind"].as_str().expect("kind").to_string(),
            text: cases_text.to_string(),
            gold,
        });
    }
    cases
}

fn read_cases(root: &Path) -> Vec<Case> {
    let mut cases = Vec::new();
    for lang in LANGS {
        cases.extend(read_cases_file(
            &root.join("cases").join(format!("{lang}.jsonl")),
        ));
    }
    cases
}

/// The Python benchmark's long-thread document: the four `thread` cases of one
/// language joined by a separator, gold spans shifted.
fn long_threads(cases: &[Case]) -> Vec<Case> {
    let mut docs = Vec::new();
    for lang in LANGS {
        let mut threads: Vec<&Case> = cases
            .iter()
            .filter(|case| case.lang == lang && case.kind == "thread")
            .collect();
        threads.sort_by(|left, right| left.id.cmp(&right.id));
        let mut text = String::new();
        let mut gold = Vec::new();
        let mut offset = 0usize;
        for (index, case) in threads.iter().enumerate() {
            if index > 0 {
                text.push_str(SEP);
                offset += SEP.len();
            }
            text.push_str(&case.text);
            gold.extend(
                case.gold
                    .iter()
                    .map(|span| GoldSpan::new(span.kind, span.start + offset, span.end + offset)),
            );
            offset += case.text.len();
        }
        docs.push(Case {
            id: format!("{lang}-longthread-synthetic"),
            lang: lang.to_string(),
            kind: "long_thread".to_string(),
            text,
            gold,
        });
    }
    docs
}

#[derive(Default)]
struct Score {
    gold: usize,
    recalled: usize,
    predicted: usize,
    matched: usize,
}

impl Score {
    fn recall(&self) -> f64 {
        if self.gold == 0 {
            1.0
        } else {
            self.recalled as f64 / self.gold as f64
        }
    }
    fn precision(&self) -> f64 {
        if self.predicted == 0 {
            1.0
        } else {
            self.matched as f64 / self.predicted as f64
        }
    }
    fn add(&mut self, other: &Score) {
        self.gold += other.gold;
        self.recalled += other.recalled;
        self.predicted += other.predicted;
        self.matched += other.matched;
    }
}

fn overlap(left: &GoldSpan, right: &GoldSpan) -> bool {
    left.start < right.end && right.start < left.end
}

fn score(gold: &[GoldSpan], predicted: &[GoldSpan], only_person: bool) -> Score {
    let mut score = Score::default();
    for gold_span in gold {
        if only_person && gold_span.kind != EntityKind::Person {
            continue;
        }
        score.gold += 1;
        if predicted
            .iter()
            .any(|pred| pred.kind == gold_span.kind && overlap(pred, gold_span))
        {
            score.recalled += 1;
        }
    }
    for pred in predicted {
        if only_person && pred.kind != EntityKind::Person {
            continue;
        }
        score.predicted += 1;
        if gold
            .iter()
            .any(|gold_span| gold_span.kind == pred.kind && overlap(gold_span, pred))
        {
            score.matched += 1;
        }
    }
    score
}

fn percentile(values: &mut [f64], fraction: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((values.len() - 1) as f64 * fraction).round() as usize;
    values[index]
}

/// Per-language `{recall, precision, name_recall}` for the recogniser alone.
fn lang_map(entries: &BTreeMap<String, (Score, Score)>) -> Value {
    let mut map = serde_json::Map::new();
    for (lang, (all, names)) in entries {
        map.insert(
            lang.clone(),
            json!({
                "recall": all.recall(),
                "precision": all.precision(),
                "name_recall": names.recall(),
            }),
        );
    }
    Value::Object(map)
}

fn peak_rss_kb() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn as_gold(spans: &[kernel_privacy::Span]) -> Vec<GoldSpan> {
    spans
        .iter()
        .map(|span| GoldSpan::new(span.kind, span.start, span.end))
        .collect()
}

fn union(
    deterministic: Vec<kernel_privacy::Span>,
    predicted: &[kernel_privacy::Span],
) -> Vec<GoldSpan> {
    let mut spans = deterministic;
    spans.extend_from_slice(predicted);
    as_gold(&kernel_privacy::recognizer::resolve_overlaps(spans))
}

/// Merge overlapping or adjacent spans into the regions the masker covers.
///
/// This is the non-overlapping union view (kind dropped), so a `PERSON` span
/// kept inside an `EMAIL` or `URL` region for the kind-aware audit is absorbed
/// instead of counted a second time.
fn merged_regions(spans: &[GoldSpan]) -> Vec<(usize, usize)> {
    let mut sorted: Vec<(usize, usize)> = spans
        .iter()
        .filter(|span| span.start < span.end)
        .map(|span| (span.start, span.end))
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

/// `(true positives, false positives, gold regions, recalled gold regions)`.
fn region_counts(gold: &[GoldSpan], predicted: &[GoldSpan]) -> (usize, usize, usize, usize) {
    let gold_regions = merged_regions(gold);
    let pred_regions = merged_regions(predicted);
    let mut true_positives = 0usize;
    for region in &pred_regions {
        if gold_regions
            .iter()
            .any(|gold| regions_overlap(region, gold))
        {
            true_positives += 1;
        }
    }
    let false_positives = pred_regions.len() - true_positives;
    let recalled = gold_regions
        .iter()
        .filter(|gold| pred_regions.iter().any(|pred| regions_overlap(gold, pred)))
        .count();
    (
        true_positives,
        false_positives,
        gold_regions.len(),
        recalled,
    )
}

/// Kind-agnostic name recall: any predicted kind may cover a gold `PERSON`.
fn agnostic_name_counts(gold: &[GoldSpan], predicted: &[GoldSpan]) -> (usize, usize) {
    let mut hit = 0usize;
    let mut total = 0usize;
    for gold_span in gold.iter().filter(|span| span.kind == EntityKind::Person) {
        total += 1;
        if predicted.iter().any(|pred| overlap(pred, gold_span)) {
            hit += 1;
        }
    }
    (hit, total)
}

fn region_precision(counts: (usize, usize, usize, usize)) -> f64 {
    let denominator = counts.0 + counts.1;
    if denominator == 0 {
        1.0
    } else {
        counts.0 as f64 / denominator as f64
    }
}

fn region_recall(counts: (usize, usize, usize, usize)) -> f64 {
    if counts.2 == 0 {
        1.0
    } else {
        counts.3 as f64 / counts.2 as f64
    }
}

fn agnostic_name_recall(counts: (usize, usize)) -> f64 {
    if counts.1 == 0 {
        1.0
    } else {
        counts.0 as f64 / counts.1 as f64
    }
}

/// The production pipeline with the model mounted: deterministic candidates and
/// model spans go through the email-aware layer together, so the public-term
/// allowlist sees the model's organisation and address spans.
fn after_union(
    layer: &EmailLayer,
    deterministic: Vec<kernel_privacy::Span>,
    predicted: &[kernel_privacy::Span],
    text: &str,
) -> Vec<GoldSpan> {
    let mut candidates = deterministic;
    let seeds: Vec<kernel_privacy::Span> = predicted
        .iter()
        .filter(|span| span.kind == EntityKind::Person)
        .copied()
        .collect();
    candidates.extend_from_slice(predicted);
    as_gold(&kernel_privacy::recognizer::resolve_overlaps(
        layer.apply(text, candidates, &seeds),
    ))
}

/// Greeting, closing and reply markers used to classify a missed person.
const GREETING_MARKERS: &[&str] = &[
    "bonjour",
    "salut",
    "coucou",
    "hello",
    "hi",
    "hey",
    "dear",
    "hallo",
    "beste",
    "liewe",
    "kedves",
    "szia",
    "привет",
    "مرحبا",
    "سلام",
];
const CLOSING_MARKERS: &[&str] = &[
    "cordialement",
    "bien à vous",
    "kind regards",
    "best regards",
    "thanks",
    "groete",
    "dankie",
    "üdvözlettel",
    "с уважением",
    "مع التحية",
    "شكرا",
];
const REPLY_MARKERS: &[&str] = &["wrote:", "a écrit", "geskryf", "írta", "написал", "كتب"];

/// Classify a gold person span by the messy pattern that hid it.
fn person_patterns(case: &Case, span: &GoldSpan) -> Vec<&'static str> {
    let text = &case.text;
    let value = &text[span.start..span.end];
    let mut patterns = Vec::new();
    if value.chars().count() <= 3 {
        patterns.push("short");
    }
    if !value.chars().any(char::is_whitespace) {
        patterns.push("bare_first");
    }
    if value.chars().next().is_some_and(|ch| ch.is_lowercase())
        && !value.chars().any(char::is_uppercase)
    {
        patterns.push("lowercase");
    }
    if url_ranges(text)
        .iter()
        .any(|(start, end)| span.start >= *start && span.end <= *end)
    {
        patterns.push("url");
    }
    let line_start = text[..span.start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let line = text[line_start..span.end].to_lowercase();
    if GREETING_MARKERS.iter().any(|marker| line.contains(marker)) {
        patterns.push("greeting");
    }
    if line.split_whitespace().count() <= 12
        && CLOSING_MARKERS.iter().any(|marker| line.contains(marker))
    {
        patterns.push("signoff");
    }
    let previous_start = text[..line_start]
        .trim_end_matches('\n')
        .rfind('\n')
        .map(|at| at + 1)
        .unwrap_or(0);
    let window = text[previous_start..span.end].to_lowercase();
    if window.contains("ps:") || window.contains("ps :") || window.contains("p.s.") {
        patterns.push("ps");
    }
    if REPLY_MARKERS.iter().any(|marker| line.contains(marker)) {
        patterns.push("wrote");
    }
    patterns
}

/// Count union spans whose exact value is a public term (never a person).
fn trap_fp(spans: &[GoldSpan], text: &str, public: &PublicTerms) -> usize {
    spans
        .iter()
        .filter(|span| span.kind != EntityKind::Person && span.start < span.end)
        .filter(|span| public.contains(&text[span.start..span.end]))
        .count()
}

#[derive(Default)]
struct PatternScore {
    gold: usize,
    recalled: usize,
}

/// The messy-email before/after comparison for both registries.
fn email_report(
    recognizer: &GlinerRecognizer,
    before: &Registry,
    deterministic: &Registry,
    layer: &EmailLayer,
    cases: &[Case],
    public: &PublicTerms,
) -> Value {
    let mut before_union = Score::default();
    let mut after_union_score = Score::default();
    let mut before_names = Score::default();
    let mut after_names = Score::default();
    let mut det_span = Score::default();
    let mut det_names = Score::default();
    let mut det_agnostic = (0usize, 0usize);
    let mut det_region = (0usize, 0usize, 0usize, 0usize);
    let mut det_covered = 0usize;
    let det_missed_enabled = std::env::var("AUX_GLINER_FN").is_ok_and(|value| value != "0");
    let mut det_missed: Vec<String> = Vec::new();
    let mut union_missed: Vec<String> = Vec::new();
    let mut det_trap = 0usize;
    let mut before_agnostic = (0usize, 0usize);
    let mut after_agnostic = (0usize, 0usize);
    let mut before_region = (0usize, 0usize, 0usize, 0usize);
    let mut after_region = (0usize, 0usize, 0usize, 0usize);
    let mut ner_precision = Score::default();
    let mut before_covered = 0usize;
    let mut after_covered = 0usize;
    let mut before_trap = 0usize;
    let mut after_trap = 0usize;
    let mut gold_total = 0usize;
    let mut patterns: BTreeMap<&'static str, PatternScore> = BTreeMap::new();
    let mut before_overhead = std::time::Duration::ZERO;
    let mut after_overhead = std::time::Duration::ZERO;

    for case in cases {
        let report = recognizer.analyze_report(&case.text).expect("recognize");
        let predicted = report.spans;
        let predicted_gold = as_gold(&predicted);
        ner_precision.add(&score(&case.gold, &predicted_gold, false));

        // Deterministic-only config: the production registry (email layer
        // mounted, no model), exactly what `privacy-eval` scores.
        let det_spans = as_gold(&deterministic.analyze(&case.text));
        det_span.add(&score(&case.gold, &det_spans, false));
        det_names.add(&score(&case.gold, &det_spans, true));
        let det_agnostic_score = agnostic_name_counts(&case.gold, &det_spans);
        det_agnostic.0 += det_agnostic_score.0;
        det_agnostic.1 += det_agnostic_score.1;
        let det_region_score = region_counts(&case.gold, &det_spans);
        det_region.0 += det_region_score.0;
        det_region.1 += det_region_score.1;
        det_region.2 += det_region_score.2;
        det_region.3 += det_region_score.3;
        for gold_span in &case.gold {
            if det_spans
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                det_covered += 1;
            }
            if det_missed_enabled
                && gold_span.kind == EntityKind::Person
                && !det_spans.iter().any(|pred| overlap(pred, gold_span))
            {
                det_missed.push(case.text[gold_span.start..gold_span.end].to_string());
            }
        }
        det_trap += trap_fp(&det_spans, &case.text, public);
        gold_total += case.gold.len();

        let start = Instant::now();
        let before_spans = before.analyze(&case.text);
        before_overhead += start.elapsed();
        let before_union_spans = union(before_spans.clone(), &predicted);
        let mut candidates = before_spans;
        candidates.extend_from_slice(&predicted);
        let seeds: Vec<kernel_privacy::Span> = predicted
            .iter()
            .filter(|span| span.kind == EntityKind::Person)
            .copied()
            .collect();
        let start = Instant::now();
        let layered = layer.apply(&case.text, candidates, &seeds);
        after_overhead += start.elapsed();
        let after_union_spans = as_gold(&kernel_privacy::recognizer::resolve_overlaps(layered));
        if det_missed_enabled {
            for gold_span in &case.gold {
                if gold_span.kind == EntityKind::Person
                    && !after_union_spans
                        .iter()
                        .any(|pred| overlap(pred, gold_span))
                {
                    union_missed.push(case.text[gold_span.start..gold_span.end].to_string());
                }
            }
        }
        let before_score = score(&case.gold, &before_union_spans, false);
        let after_score = score(&case.gold, &after_union_spans, false);
        before_union.add(&before_score);
        after_union_score.add(&after_score);
        before_names.add(&score(&case.gold, &before_union_spans, true));
        after_names.add(&score(&case.gold, &after_union_spans, true));
        let before_agnostic_score = agnostic_name_counts(&case.gold, &before_union_spans);
        before_agnostic.0 += before_agnostic_score.0;
        before_agnostic.1 += before_agnostic_score.1;
        let after_agnostic_score = agnostic_name_counts(&case.gold, &after_union_spans);
        after_agnostic.0 += after_agnostic_score.0;
        after_agnostic.1 += after_agnostic_score.1;
        let before_region_score = region_counts(&case.gold, &before_union_spans);
        before_region.0 += before_region_score.0;
        before_region.1 += before_region_score.1;
        before_region.2 += before_region_score.2;
        before_region.3 += before_region_score.3;
        let after_region_score = region_counts(&case.gold, &after_union_spans);
        after_region.0 += after_region_score.0;
        after_region.1 += after_region_score.1;
        after_region.2 += after_region_score.2;
        after_region.3 += after_region_score.3;

        for gold_span in &case.gold {
            if before_union_spans
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                before_covered += 1;
            }
            if after_union_spans
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                after_covered += 1;
            }
            if gold_span.kind == EntityKind::Person {
                let recalled = after_union_spans
                    .iter()
                    .any(|pred| pred.kind == EntityKind::Person && overlap(pred, gold_span));
                for pattern in person_patterns(case, gold_span) {
                    let entry = patterns.entry(pattern).or_default();
                    entry.gold += 1;
                    if recalled {
                        entry.recalled += 1;
                    }
                }
            }
        }
        for (spans, counter) in [
            (&before_union_spans, &mut before_trap),
            (&after_union_spans, &mut after_trap),
        ] {
            for pred in spans.iter() {
                if pred.kind == EntityKind::Person || pred.start >= pred.end {
                    continue;
                }
                if public.contains(&case.text[pred.start..pred.end]) {
                    *counter += 1;
                }
            }
        }
    }

    let mut pattern_map = serde_json::Map::new();
    for (pattern, entry) in &patterns {
        pattern_map.insert(
            (*pattern).to_string(),
            json!({
                "gold": entry.gold,
                "recalled": entry.recalled,
                "recall": if entry.gold == 0 { 1.0 } else { entry.recalled as f64 / entry.gold as f64 },
            }),
        );
    }

    json!({
        "cases": cases.len(),
        "gold": gold_total,
        "deterministic": {
            "span_precision": det_span.precision(),
            "span_recall": det_span.recall(),
            "name_recall": det_names.recall(),
            "name_recall_agnostic": agnostic_name_recall(det_agnostic),
            "region_precision": region_precision(det_region),
            "region_recall": region_recall(det_region),
            "mask_coverage": if gold_total == 0 { 1.0 } else { det_covered as f64 / gold_total as f64 },
            "trap_fp": det_trap,
        },
        "before": {
            "union_recall": before_union.recall(),
            "union_precision": before_union.precision(),
            "name_recall": before_names.recall(),
            "name_recall_agnostic": agnostic_name_recall(before_agnostic),
            "region_precision": region_precision(before_region),
            "region_recall": region_recall(before_region),
            "mask_coverage": if gold_total == 0 { 1.0 } else { before_covered as f64 / gold_total as f64 },
            "trap_fp": before_trap,
        },
        "after": {
            "union_recall": after_union_score.recall(),
            "union_precision": after_union_score.precision(),
            "name_recall": after_names.recall(),
            "name_recall_agnostic": agnostic_name_recall(after_agnostic),
            "region_precision": region_precision(after_region),
            "region_recall": region_recall(after_region),
            "mask_coverage": if gold_total == 0 { 1.0 } else { after_covered as f64 / gold_total as f64 },
            "trap_fp": after_trap,
        },
        "ner_precision": ner_precision.precision(),
        "deterministic_missed_persons": det_missed,
        "union_missed_persons": union_missed,
        "registry_ms_before": before_overhead.as_secs_f64() * 1000.0,
        "layer_ms": after_overhead.as_secs_f64() * 1000.0,
        "layer_us_per_case": after_overhead.as_secs_f64() * 1e6 / cases.len().max(1) as f64,
        "per_pattern": Value::Object(pattern_map),
    })
}

fn main() {
    let model_dir = std::env::var("AUX_GLINER_MODEL_DIR").expect("AUX_GLINER_MODEL_DIR");
    let int8 = std::env::var("AUX_GLINER_ONNX").as_deref() == Ok("int8");
    let threshold: f32 = std::env::var("AUX_GLINER_THRESHOLD")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.4);
    let repeat: usize = std::env::var("AUX_GLINER_REPEAT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);

    let repo_root = std::env::var("AUX_REPO_ROOT").unwrap_or_else(|_| ".".to_string());
    let corpus = PathBuf::from(repo_root).join("qa/privacy-eval");
    let cases = read_cases(&corpus);
    let long = long_threads(&cases);
    let public = PublicTerms::from_path(corpus.join("public-terms.json"))
        .unwrap_or_else(|_| PublicTerms::builtin());
    let email_cases: Vec<Case> = std::env::var("AUX_GLINER_EMAILS")
        .ok()
        .map(|list| {
            list.split(',')
                .filter(|path| !path.trim().is_empty())
                .flat_map(|path| read_cases_file(Path::new(path.trim())))
                .collect()
        })
        .unwrap_or_default();

    let mut config = GlinerConfig::new(&model_dir).with_threshold(threshold);
    if int8 {
        config = config.with_int8();
    }
    if let Ok(dylib) = std::env::var("AUX_GLINER_ORT_DYLIB") {
        config = config.with_ort_dylib(dylib);
    }

    let load_start = Instant::now();
    let recognizer = GlinerRecognizer::load(config).expect("load GLiNER");
    let load_s = load_start.elapsed().as_secs_f64();
    let rss_after_load_kb = peak_rss_kb();

    // Warm-up on three short cases, untimed.
    for case in cases.iter().take(3) {
        recognizer.recognize(&case.text).expect("warm-up");
    }

    // One registry with the layer off (pre-1e) and one with it on.
    let before_registry = Registry::builder().with_all().without_email_layer().build();
    let layer = EmailLayer::new();
    let mut per_lang: BTreeMap<String, (Score, Score)> = BTreeMap::new();
    let mut total = (Score::default(), Score::default());
    let mut union_before_total = (Score::default(), Score::default());
    let mut union_after_total = (Score::default(), Score::default());
    let mut long_latency = Vec::new();
    let mut short_latency = Vec::new();
    let mut dropped = 0usize;
    let mut chunks_max = 0usize;
    let mut clean_gold = 0usize;
    let mut union_before_covered = 0usize;
    let mut union_after_covered = 0usize;
    let mut trap_before = 0usize;
    let mut trap_after = 0usize;
    let mut union_before_region = (0usize, 0usize, 0usize, 0usize);
    let mut union_after_region = (0usize, 0usize, 0usize, 0usize);
    let mut union_before_agnostic = (0usize, 0usize);
    let mut union_after_agnostic = (0usize, 0usize);

    let mut long_recall = (Score::default(), Score::default());

    for case in &cases {
        if case.kind == "short" {
            let start = Instant::now();
            for _ in 0..repeat {
                recognizer.recognize(&case.text).expect("recognize");
            }
            short_latency.push(start.elapsed().as_secs_f64() * 1000.0 / repeat as f64);
        }

        let report = recognizer.analyze_report(&case.text).expect("recognize");
        dropped += report.dropped;
        chunks_max = chunks_max.max(report.chunks);
        let predicted = report.spans;
        let predicted_gold = as_gold(&predicted);

        let all = score(&case.gold, &predicted_gold, false);
        let names = score(&case.gold, &predicted_gold, true);
        let entry = per_lang.entry(case.lang.clone()).or_default();
        entry.0.add(&all);
        entry.1.add(&names);
        total.0.add(&all);
        total.1.add(&names);

        let union_before = union(before_registry.analyze(&case.text), &predicted);
        let union_after = after_union(
            &layer,
            before_registry.analyze(&case.text),
            &predicted,
            &case.text,
        );
        union_before_total
            .0
            .add(&score(&case.gold, &union_before, false));
        union_before_total
            .1
            .add(&score(&case.gold, &union_before, true));
        union_after_total
            .0
            .add(&score(&case.gold, &union_after, false));
        union_after_total
            .1
            .add(&score(&case.gold, &union_after, true));
        let before_region = region_counts(&case.gold, &union_before);
        union_before_region.0 += before_region.0;
        union_before_region.1 += before_region.1;
        union_before_region.2 += before_region.2;
        union_before_region.3 += before_region.3;
        let after_region = region_counts(&case.gold, &union_after);
        union_after_region.0 += after_region.0;
        union_after_region.1 += after_region.1;
        union_after_region.2 += after_region.2;
        union_after_region.3 += after_region.3;
        let before_agnostic = agnostic_name_counts(&case.gold, &union_before);
        union_before_agnostic.0 += before_agnostic.0;
        union_before_agnostic.1 += before_agnostic.1;
        let after_agnostic = agnostic_name_counts(&case.gold, &union_after);
        union_after_agnostic.0 += after_agnostic.0;
        union_after_agnostic.1 += after_agnostic.1;
        clean_gold += case.gold.len();
        for gold_span in &case.gold {
            if union_before
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                union_before_covered += 1;
            }
            if union_after
                .iter()
                .any(|pred| pred.start <= gold_span.start && pred.end >= gold_span.end)
            {
                union_after_covered += 1;
            }
        }
        trap_before += trap_fp(&union_before, &case.text, &public);
        trap_after += trap_fp(&union_after, &case.text, &public);
    }

    for case in &long {
        let start = Instant::now();
        for _ in 0..repeat {
            recognizer.recognize(&case.text).expect("recognize long");
        }
        long_latency.push(start.elapsed().as_secs_f64() * 1000.0 / repeat as f64);
        let report = recognizer
            .analyze_report(&case.text)
            .expect("recognize long");
        let predicted: Vec<GoldSpan> = report
            .spans
            .iter()
            .map(|span| GoldSpan::new(span.kind, span.start, span.end))
            .collect();
        let all = score(&case.gold, &predicted, false);
        long_recall.0.add(&all);
        let names = score(&case.gold, &predicted, true);
        long_recall.1.add(&names);
    }

    let emails = if email_cases.is_empty() {
        Value::Null
    } else {
        email_report(
            &recognizer,
            &before_registry,
            &Registry::new(),
            &layer,
            &email_cases,
            &public,
        )
    };

    let report = json!({
        "model_dir": model_dir,
        "onnx": if int8 { "model_int8.onnx" } else { "model.onnx" },
        "threshold": threshold,
        "load_s": load_s,
        "rss_after_load_kb": rss_after_load_kb,
        "peak_rss_kb": peak_rss_kb(),
        "dropped_spans": dropped,
        "max_chunks": chunks_max,
        "cases": cases.len(),
        "overall": {
            "recall": total.0.recall(),
            "precision": total.0.precision(),
            "name_recall": total.1.recall(),
            "gold": total.0.gold,
            "predicted": total.0.predicted,
        },
        "per_lang": lang_map(&per_lang),
        "union_before": {
            "recall": union_before_total.0.recall(),
            "precision": union_before_total.0.precision(),
            "name_recall": union_before_total.1.recall(),
            "name_recall_agnostic": agnostic_name_recall(union_before_agnostic),
            "region_precision": region_precision(union_before_region),
            "region_recall": region_recall(union_before_region),
            "mask_coverage": if clean_gold == 0 { 1.0 } else { union_before_covered as f64 / clean_gold as f64 },
            "trap_fp": trap_before,
        },
        "union_after": {
            "recall": union_after_total.0.recall(),
            "precision": union_after_total.0.precision(),
            "name_recall": union_after_total.1.recall(),
            "name_recall_agnostic": agnostic_name_recall(union_after_agnostic),
            "region_precision": region_precision(union_after_region),
            "region_recall": region_recall(union_after_region),
            "mask_coverage": if clean_gold == 0 { 1.0 } else { union_after_covered as f64 / clean_gold as f64 },
            "trap_fp": trap_after,
        },
        "latency_ms": {
            "short_p50": percentile(&mut short_latency.clone(), 0.5),
            "short_p95": percentile(&mut short_latency.clone(), 0.95),
            "long_p50": percentile(&mut long_latency.clone(), 0.5),
            "long_p95": percentile(&mut long_latency.clone(), 0.95),
        },
        "long_thread": {
            "recall": long_recall.0.recall(),
            "name_recall": long_recall.1.recall(),
        },
        "emails": emails,
    });

    let rendered = serde_json::to_string_pretty(&report).expect("serialize");
    if let Ok(path) = std::env::var("AUX_GLINER_JSON") {
        fs::write(path, &rendered).expect("write report");
    }
    println!("{rendered}");
}
