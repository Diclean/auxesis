//! Score the deterministic privacy registry ([`Registry::new()`]) on two public
//! synthetic PII datasets (Nemotron-PII, Gretel finance multilingual).
//!
//! This is the EVAL-PUBLIC-1 measurement harness. It uses ONLY the
//! deterministic [`Registry::new()`] path — the same recogniser set production
//! uses in private mode for text without GLiNER (StandardDetector::new() builds
//! `Registry::builder().with_all().build()`). The daemon's private turn calls
//! `Gate::text` (kernel-privacy/src/safetext.rs:903) under a grant obtained in
//! crates/auxd/src/api/turn.rs:746 (`session_gate.issue(PathId::D1, content)`);
//! that gate runs `detector.detect_covered` (StandardDetector/Registry) on the
//! text, so span-level scoring uses [`Registry::new().analyze()`]. No model is
//! loaded, no network is used by this binary.
//!
//! Input: `AUX_PUBLIC_EVAL_DIR` pointing at a directory of JSONL case files
//! (one case per line, code-point spans). Output: a summary on stdout and,
//! when `AUX_PUBLIC_EVAL_JSON` is set, a full JSON report.
//!
//! Run:
//! ```console
//! AUX_PUBLIC_EVAL_DIR=/tmp/pub AUX_PUBLIC_EVAL_JSON=/tmp/report.json \
//!   cargo run -p kernel-privacy --example public_eval --release
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use kernel_privacy::span::EntityKind;
use kernel_privacy::Registry;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Class {
    Iban,
    Card,
    Id,
    Secret,
    Health,
    Email,
    Phone,
}

impl Class {
    fn as_str(self) -> &'static str {
        match self {
            Class::Iban => "iban",
            Class::Card => "card",
            Class::Id => "id",
            Class::Secret => "secret",
            Class::Health => "health",
            Class::Email => "email",
            Class::Phone => "phone",
        }
    }

    const ALL: [Class; 7] = [
        Class::Iban,
        Class::Card,
        Class::Id,
        Class::Secret,
        Class::Health,
        Class::Email,
        Class::Phone,
    ];
}

struct Case {
    id: String,
    lang: String,
    text: String,
    gold: Vec<(Class, usize, usize)>,
}

#[derive(Default, Clone, Copy)]
struct Counts {
    gold: usize,
    caught: usize,
    predicted: usize,
    matched: usize,
    excluded: usize,
    /// Caught gold masked under another class's label (K-PUBLIC-MISSES).
    relabelled: usize,
}

impl Counts {
    fn recall(&self) -> f64 {
        // No gold: not measured (NaN serialises as JSON null), never a perfect score.
        if self.gold == 0 {
            f64::NAN
        } else {
            self.caught as f64 / self.gold as f64
        }
    }
    fn precision(&self) -> f64 {
        if self.predicted == 0 || self.gold == 0 {
            f64::NAN
        } else {
            self.matched as f64 / self.predicted as f64
        }
    }
    fn fp(&self) -> usize {
        self.predicted - self.matched
    }
}

struct Miss {
    dataset: String,
    lang: String,
    id: String,
    snippet: String,
}

fn codepoint_span_to_byte(text: &str, start: usize, end: usize) -> (usize, usize) {
    let mut scalar_to_byte = Vec::with_capacity(text.chars().count() + 1);
    for (byte, _) in text.char_indices() {
        scalar_to_byte.push(byte);
    }
    scalar_to_byte.push(text.len());
    (scalar_to_byte[start], scalar_to_byte[end])
}

fn class_of_type(label: &str) -> Option<Class> {
    match label {
        "iban" => Some(Class::Iban),
        "card" => Some(Class::Card),
        "national_id" => Some(Class::Id),
        "secret" => Some(Class::Secret),
        "health" => Some(Class::Health),
        "email" => Some(Class::Email),
        "phone" => Some(Class::Phone),
        _ => None,
    }
}

fn class_of_kind(kind: EntityKind) -> Option<Class> {
    match kind {
        EntityKind::Iban => Some(Class::Iban),
        EntityKind::CreditCard => Some(Class::Card),
        EntityKind::FrNir
        | EntityKind::FrSiren
        | EntityKind::FrSiret
        | EntityKind::FrVat
        | EntityKind::HuTaj
        | EntityKind::HuTaxId
        | EntityKind::ZaId
        | EntityKind::UkNino
        | EntityKind::PassportMrz
        | EntityKind::NationalId => Some(Class::Id),
        EntityKind::Secret => Some(Class::Secret),
        EntityKind::Health => Some(Class::Health),
        EntityKind::Email => Some(Class::Email),
        EntityKind::Phone => Some(Class::Phone),
        _ => None,
    }
}

fn is_placeholder(text: &str, class: Class) -> bool {
    let t = text.trim();
    // '(' is not a placeholder: real US phones are written "(555) 123-4567".
    if t.starts_with('[') || t.starts_with('<') || t.starts_with('{') {
        return true;
    }
    if t.contains("XXXX") || t.contains("xxxx") || t.contains("****") {
        return true;
    }
    match class {
        Class::Email => {
            let at = match t.find('@') {
                Some(i) => i,
                None => return true,
            };
            !t[at..].contains('.')
        }
        Class::Phone => t.chars().filter(|c| c.is_ascii_digit()).count() < 7,
        Class::Card => t.chars().filter(|c| c.is_ascii_digit()).count() < 12,
        Class::Iban => t.chars().filter(|c| c.is_ascii_alphanumeric()).count() < 10,
        _ => false,
    }
}

fn checksum_valid(text: &str, class: Class) -> bool {
    match class {
        Class::Card => {
            let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() < 12 {
                return false;
            }
            kernel_privacy::checksum::luhn_ok(&digits)
        }
        Class::Iban => kernel_privacy::checksum::iban_mod97_loose(text).unwrap_or(false),
        _ => true,
    }
}

fn overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

fn read_cases_file(path: &Path) -> Vec<Case> {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut cases = Vec::new();
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        let value: Value = serde_json::from_str(line).expect("case JSON");
        let text = value["text"].as_str().expect("text").to_string();
        let lang = value["lang"].as_str().expect("lang").to_string();
        let id = value["id"].as_str().unwrap_or("").to_string();
        let mut gold = Vec::new();
        if let Some(spans) = value["spans"].as_array() {
            for span in spans {
                let ty = match span["type"].as_str() {
                    Some(t) => t,
                    None => continue,
                };
                let class = match class_of_type(ty) {
                    Some(c) => c,
                    None => continue,
                };
                let start_cp = span["start"].as_u64().unwrap_or(0) as usize;
                let end_cp = span["end"].as_u64().unwrap_or(0) as usize;
                let (s, e) = codepoint_span_to_byte(&text, start_cp, end_cp);
                gold.push((class, s, e));
            }
        }
        cases.push(Case {
            id,
            lang,
            text,
            gold,
        });
    }
    cases
}

fn main() {
    let dir =
        PathBuf::from(std::env::var("AUX_PUBLIC_EVAL_DIR").expect("AUX_PUBLIC_EVAL_DIR not set"));
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("jsonl"))
        .collect();
    files.sort();

    // Private mode drops names before the merge: a name
    // must never widen a region over a value the eval then credits.
    let registry = Registry::new().without_names();

    // dataset -> lang -> class -> counts
    let mut by_dataset: BTreeMap<String, BTreeMap<String, BTreeMap<Class, Counts>>> =
        BTreeMap::new();
    let mut dataset_totals: BTreeMap<String, BTreeMap<Class, Counts>> = BTreeMap::new();
    let mut global: BTreeMap<Class, Counts> = BTreeMap::new();
    for c in Class::ALL {
        global.insert(c, Counts::default());
    }

    let mut misses: BTreeMap<Class, Vec<Miss>> = BTreeMap::new();
    for c in Class::ALL {
        misses.insert(c, Vec::new());
    }
    let mut fp_id_samples: Vec<(String, String, String, String)> = Vec::new();
    let mut fp_phone_samples: Vec<(String, String, String, String)> = Vec::new();

    let mut total_cases = 0usize;
    for file in &files {
        let dataset = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let cases = read_cases_file(file);
        for case in &cases {
            total_cases += 1;
            let predicted_raw = registry.analyze(&case.text);
            let mut predicted: Vec<(Class, usize, usize)> = Vec::new();
            for span in &predicted_raw {
                if let Some(cls) = class_of_kind(span.kind) {
                    predicted.push((cls, span.start, span.end));
                }
            }

            // validity + placeholder filtering for gold
            let mut gold_valid = vec![false; case.gold.len()];
            for (gi, (gcls, gs, ge)) in case.gold.iter().enumerate() {
                let txt = &case.text[*gs..*ge];
                if is_placeholder(txt, *gcls) {
                    continue;
                }
                if !checksum_valid(txt, *gcls) {
                    continue;
                }
                gold_valid[gi] = true;
            }

            // caught per gold (valid only). A value inside one merged region of
            // another class is masked too: the registry labels a merged region with
            // its top-priority kind (`EntityKind::mask_priority`), so an e-mail that
            // overlaps an ID-shaped span leaves as a `NATIONAL_ID` token. It counts
            // as caught and as relabelled.
            let mut gold_caught = vec![false; case.gold.len()];
            let mut gold_relabelled = vec![false; case.gold.len()];
            for (gi, (gcls, gs, ge)) in case.gold.iter().enumerate() {
                if !gold_valid[gi] {
                    continue;
                }
                let caught = predicted
                    .iter()
                    .any(|(pcls, ps, pe)| *pcls == *gcls && overlap(*ps, *pe, *gs, *ge));
                // Private mode only (this eval scores the private detector): names,
                // companies and addresses are not hidden there, so a region of
                // those kinds never counts (pre-review of #129).
                let inside = predicted_raw.iter().any(|span| {
                    !matches!(
                        span.kind,
                        EntityKind::Person | EntityKind::Organization | EntityKind::Address
                    ) && span.start <= *gs
                        && *ge <= span.end
                });
                if caught || inside {
                    gold_caught[gi] = true;
                    gold_relabelled[gi] = !caught;
                }
            }

            // matched per predicted (against valid gold only)
            let mut pred_matched = vec![false; predicted.len()];
            for (pi, (pcls, ps, pe)) in predicted.iter().enumerate() {
                let matched = case.gold.iter().enumerate().any(|(gi, (gcls, gs, ge))| {
                    gold_valid[gi] && *gcls == *pcls && overlap(*gs, *ge, *ps, *pe)
                });
                if matched {
                    pred_matched[pi] = true;
                }
            }

            // update aggregates
            // global + dataset + lang
            let lang_entry = by_dataset
                .entry(dataset.clone())
                .or_default()
                .entry(case.lang.clone())
                .or_default();
            let ds_total = dataset_totals.entry(dataset.clone()).or_default();
            for (gi, (class, _gs, _ge)) in case.gold.iter().enumerate() {
                let cls = *class;
                if !gold_valid[gi] {
                    // excluded: placeholder or invalid checksum
                    let g = global.get_mut(&cls).unwrap();
                    g.excluded += 1;
                    let l = lang_entry.entry(cls).or_default();
                    l.excluded += 1;
                    let d = ds_total.entry(cls).or_default();
                    d.excluded += 1;
                    continue;
                }
                let caught_flag = gold_caught[gi];
                // global
                let g = global.get_mut(&cls).unwrap();
                g.gold += 1;
                if caught_flag {
                    g.caught += 1;
                }
                if gold_relabelled[gi] {
                    g.relabelled += 1;
                }
                // lang
                let l = lang_entry.entry(cls).or_default();
                l.gold += 1;
                if caught_flag {
                    l.caught += 1;
                }
                // dataset total
                let d = ds_total.entry(cls).or_default();
                d.gold += 1;
                if caught_flag {
                    d.caught += 1;
                }
            }
            for (pi, (cls, ps, pe)) in predicted.iter().enumerate() {
                let matched = pred_matched[pi];
                // A hit on excluded gold (placeholder, invalid checksum) is neither a match nor a false positive.
                if !matched
                    && case.gold.iter().enumerate().any(|(gi, (gcls, gs, ge))| {
                        !gold_valid[gi] && gcls == cls && overlap(*gs, *ge, *ps, *pe)
                    })
                {
                    continue;
                }
                // global
                let g = global.get_mut(cls).unwrap();
                g.predicted += 1;
                if matched {
                    g.matched += 1;
                }
                // lang
                let l = lang_entry.entry(*cls).or_default();
                l.predicted += 1;
                if matched {
                    l.matched += 1;
                }
                // dataset total
                let d = ds_total.entry(*cls).or_default();
                d.predicted += 1;
                if matched {
                    d.matched += 1;
                }
            }

            // record misses (valid gold only)
            for (gi, (gcls, gs, ge)) in case.gold.iter().enumerate() {
                if !gold_valid[gi] || gold_caught[gi] {
                    continue;
                }
                let snippet_raw = &case.text[*gs..*ge];
                let snippet: String = snippet_raw.chars().take(120).collect();
                misses.get_mut(gcls).unwrap().push(Miss {
                    dataset: dataset.clone(),
                    lang: case.lang.clone(),
                    id: case.id.clone(),
                    snippet,
                });
            }

            // collect FP samples for id and phone (first 20 each)
            for (pi, (cls, ps, pe)) in predicted.iter().enumerate() {
                if pred_matched[pi] {
                    continue;
                }
                if *cls != Class::Id && *cls != Class::Phone {
                    continue;
                }
                let snippet: String = case.text[*ps..*pe].chars().take(120).collect();
                let bucket = if *cls == Class::Id {
                    &mut fp_id_samples
                } else {
                    &mut fp_phone_samples
                };
                if bucket.len() < 20 {
                    bucket.push((dataset.clone(), case.lang.clone(), case.id.clone(), snippet));
                }
            }
        }
    }

    // Build JSON report
    let mut datasets_json = serde_json::Map::new();
    for (ds, langs) in &by_dataset {
        let mut langs_json = serde_json::Map::new();
        for (lang, classes) in langs {
            let mut cls_json = serde_json::Map::new();
            for cls in Class::ALL {
                let c = classes.get(&cls).copied().unwrap_or_default();
                cls_json.insert(
                    cls.as_str().to_string(),
                    json!({
                        "gold": c.gold,
                        "caught": c.caught,
                        "recall": c.recall(),
                        "predicted": c.predicted,
                        "matched": c.matched,
                        "false_positives": c.fp(),
                        "precision": c.precision(),
                        "excluded_placeholders_or_invalid": c.excluded,
                    }),
                );
            }
            langs_json.insert(lang.clone(), json!({ "classes": cls_json }));
        }
        let mut tot_json = serde_json::Map::new();
        if let Some(tot) = dataset_totals.get(ds) {
            for cls in Class::ALL {
                let c = tot.get(&cls).copied().unwrap_or_default();
                tot_json.insert(
                    cls.as_str().to_string(),
                    json!({
                        "gold": c.gold,
                        "caught": c.caught,
                        "recall": c.recall(),
                        "predicted": c.predicted,
                        "matched": c.matched,
                        "false_positives": c.fp(),
                        "precision": c.precision(),
                        "excluded_placeholders_or_invalid": c.excluded,
                    }),
                );
            }
        }
        datasets_json.insert(
            ds.clone(),
            json!({ "languages": langs_json, "totals": { "classes": tot_json } }),
        );
    }

    let mut global_json = serde_json::Map::new();
    for cls in Class::ALL {
        let c = global.get(&cls).copied().unwrap_or_default();
        global_json.insert(
            cls.as_str().to_string(),
            json!({
                "gold": c.gold,
                "caught": c.caught,
                "relabelled": c.relabelled,
                "recall": c.recall(),
                "predicted": c.predicted,
                "matched": c.matched,
                "false_positives": c.fp(),
                "precision": c.precision(),
                "excluded_placeholders_or_invalid": c.excluded,
            }),
        );
    }

    let mut misses_json = serde_json::Map::new();
    for cls in Class::ALL {
        let list: Vec<Value> = misses
            .get(&cls)
            .unwrap()
            .iter()
            .take(20)
            .map(|m| {
                json!({
                    "dataset": m.dataset,
                    "lang": m.lang,
                    "id": m.id,
                    "snippet": m.snippet,
                })
            })
            .collect();
        misses_json.insert(cls.as_str().to_string(), Value::Array(list));
    }

    let fp_id_json: Vec<Value> = fp_id_samples
        .iter()
        .map(|(d, l, i, s)| json!({"dataset": d, "lang": l, "id": i, "snippet": s}))
        .collect();
    let fp_phone_json: Vec<Value> = fp_phone_samples
        .iter()
        .map(|(d, l, i, s)| json!({"dataset": d, "lang": l, "id": i, "snippet": s}))
        .collect();
    let report = json!({
        "cases": total_cases,
        "datasets": datasets_json,
        "overall": { "classes": global_json },
        "misses": misses_json,
        "fp_samples": { "id": fp_id_json, "phone": fp_phone_json },
    });

    let rendered = serde_json::to_string_pretty(&report).expect("serialize");
    if let Ok(path) = std::env::var("AUX_PUBLIC_EVAL_JSON") {
        fs::write(&path, &rendered).expect("write report");
    }

    // Console summary
    println!("cases: {total_cases}");
    println!(
        "{:<8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "class", "gold", "caught", "relabel", "recall", "fp", "precision"
    );
    for cls in Class::ALL {
        let c = global.get(&cls).copied().unwrap_or_default();
        if cls == Class::Health {
            println!(
                "{:<8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
                cls.as_str(),
                c.gold,
                c.caught,
                c.relabelled,
                "n/a",
                c.fp(),
                "n/a"
            );
        } else {
            println!(
                "{:<8} {:>8} {:>8} {:>8} {:>8.3} {:>8} {:>8.3}",
                cls.as_str(),
                c.gold,
                c.caught,
                c.relabelled,
                c.recall(),
                c.fp(),
                c.precision()
            );
        }
    }
    println!();
    for ds in by_dataset.keys() {
        println!("dataset: {ds}");
        if let Some(tot) = dataset_totals.get(ds) {
            for cls in Class::ALL {
                let c = tot.get(&cls).copied().unwrap_or_default();
                if c.gold == 0 && c.predicted == 0 {
                    continue;
                }
                println!(
                    "  {:<8} gold={} caught={} recall={:.3} fp={} prec={:.3}",
                    cls.as_str(),
                    c.gold,
                    c.caught,
                    c.recall(),
                    c.fp(),
                    c.precision()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codepoint_to_byte_conversion_accented_emoji() {
        let text = "café 😀 test";
        // emoji is one code point at index 5
        let (s, e) = codepoint_span_to_byte(text, 5, 6);
        assert_eq!(&text[s..e], "😀");
        // accented word "café" is 4 code points
        let (s, e) = codepoint_span_to_byte(text, 0, 4);
        assert_eq!(&text[s..e], "café");
        // boundary at end
        let (_, e) = codepoint_span_to_byte(text, 0, text.chars().count());
        assert_eq!(e, text.len());
    }
}
