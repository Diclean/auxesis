//! Score the local contact index (slice 1f) on the FAKE dev split A.
//!
//! Reads only `qa/privacy-eval/cases/emails-<lang>.jsonl` and
//! `qa/privacy-eval/public-terms.json`. Each mail seeds a fresh index from what
//! a mail client shows (header-like lines, `<Name> <address>` pairs, attribution
//! lines, and the addresses in the text). No gold label is read to seed.
//!
//! Per configuration it reports, over gold `person` spans:
//! * name recall: the name is overlapped by a masked span, of any kind;
//! * mask coverage: the name lies fully inside one masked span (the ship bar);
//! * both split by tier (HIGH: two or more tokens, or a name in a header line
//!   or signature block; LOW: one token elsewhere);
//! * trap false positives: a public term that a masked span overlaps while no
//!   gold span does.
//!
//! It then times the recogniser on 5,000 synthetic contacts (fake names,
//! `.invalid` addresses) against a 100 KB text made of the dev mails.
//!
//! ```console
//! AUX_REPO_ROOT=/path/to/checkout \
//! AUX_GLINER_MODEL_DIR=/path/to/export AUX_GLINER_ORT_DYLIB=/path/to/libonnxruntime.so \
//! cargo run --release -p kernel-privacy --features ner-gliner --example contacts_eval
//! ```
//!
//! Without `--features ner-gliner` the GLiNER rows are left out.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use kernel_privacy::contacts::{ContactIndex, PersonDraft};
use kernel_privacy::span::Span;
use kernel_privacy::{ContactRecognizer, Recognizer, Registry};
use serde_json::{json, Value};
use zeroize::Zeroizing;

#[cfg(feature = "ner-gliner")]
use kernel_privacy::recognizer::resolve_overlaps;
#[cfg(feature = "ner-gliner")]
use kernel_privacy::{GlinerConfig, GlinerRecognizer};

const LANGS: [&str; 6] = ["fr", "en", "af", "hu", "ar", "ru"];

/// Gold `person` spans, split by tier (see [`tier`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tier {
    High,
    Low,
}

/// One dev mail. Offsets are UTF-8 byte offsets.
struct Case {
    lang: String,
    text: String,
    /// Gold `person` spans and their tier.
    names: Vec<(usize, usize, Tier)>,
    /// Every gold span, any type.
    gold: Vec<(usize, usize)>,
}

/// Name counts of one tier.
#[derive(Default, Clone, Copy)]
struct TierTally {
    names: usize,
    touched: usize,
    masked: usize,
}

/// Counts for one configuration and one language.
#[derive(Default, Clone, Copy)]
struct Tally {
    high: TierTally,
    low: TierTally,
    traps: usize,
    spans: usize,
}

impl Tally {
    /// Both tiers added together.
    fn total(self) -> TierTally {
        TierTally {
            names: self.high.names + self.low.names,
            touched: self.high.touched + self.low.touched,
            masked: self.high.masked + self.low.masked,
        }
    }
}

/// Header labels (lower-case) that open a header line, in the six languages.
const HEADER_LABELS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "sent",
    "subject",
    "date",
    "de",
    "aan",
    "van",
    "kopie",
    "onderwerp",
    "gestuur",
    "objet",
    "envoyé",
    "à",
    "feladó",
    "címzett",
    "másolat",
    "tárgy",
    "dátum",
    "от",
    "кому",
    "копия",
    "тема",
    "дата",
    "من",
    "إلى",
    "نسخة",
    "الموضوع",
    "gesendet",
    "betreff",
    "an",
];

/// Words and marks that open or end a signature block (lower-case).
const SIGNATURE_MARKERS: &[&str] = &[
    "|",
    "·",
    "@",
    "www",
    "tel",
    "tél",
    "mob",
    "gsm",
    "vat",
    "ltd",
    "registered",
    "regards",
    "cordialement",
    "groet",
    "freundlichen",
    "уважением",
    "üdvözl",
    "التحية",
    "sincerely",
    "+",
];

/// HIGH: two or more tokens, or any name in a header line or a signature block.
/// LOW: a single-token name elsewhere. Heuristic, read from the text alone.
fn tier(text: &str, start: usize, end: usize) -> Tier {
    if text[start..end].split_whitespace().count() >= 2 {
        return Tier::High;
    }
    let line_start = text[..start].rfind('\n').map_or(0, |at| at + 1);
    let line_end = text[end..].find('\n').map_or(text.len(), |at| end + at);
    let line =
        text[line_start..line_end].trim_start_matches(|c: char| c == '>' || c.is_whitespace());
    let label = line
        .split_once(':')
        .map(|(label, _)| label.trim().to_lowercase());
    if label.is_some_and(|label| HEADER_LABELS.contains(&label.as_str())) {
        return Tier::High;
    }
    let block_start = text[..start].rfind("\n\n").map_or(0, |at| at + 2);
    let block_end = text[end..].find("\n\n").map_or(text.len(), |at| end + at);
    let block = text[block_start..block_end].to_lowercase();
    if SIGNATURE_MARKERS
        .iter()
        .any(|marker| block.contains(marker))
    {
        return Tier::High;
    }
    Tier::Low
}

fn read_cases(corpus: &Path) -> Vec<Case> {
    let mut cases = Vec::new();
    for lang in LANGS {
        let path = corpus.join("cases").join(format!("emails-{lang}.jsonl"));
        let raw =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        for line in raw.lines().filter(|line| !line.trim().is_empty()) {
            let value: Value = serde_json::from_str(line).expect("case JSON");
            let text = value["text"].as_str().expect("text").to_string();
            // The corpus counts code points; the recognisers emit byte offsets.
            let mut offsets: Vec<usize> = text.char_indices().map(|(at, _)| at).collect();
            offsets.push(text.len());
            let mut names = Vec::new();
            let mut gold = Vec::new();
            for span in value["spans"].as_array().expect("spans") {
                let start = span["start"].as_u64().expect("start") as usize;
                let end = span["end"].as_u64().expect("end") as usize;
                let bytes = (offsets[start], offsets[end]);
                gold.push(bytes);
                if span["type"].as_str() == Some("person") {
                    names.push((bytes.0, bytes.1, tier(&text, bytes.0, bytes.1)));
                }
            }
            cases.push(Case {
                lang: lang.to_string(),
                text,
                names,
                gold,
            });
        }
    }
    cases
}

fn read_terms(corpus: &Path) -> BTreeMap<String, Vec<String>> {
    let raw = fs::read_to_string(corpus.join("public-terms.json")).expect("public-terms.json");
    let value: Value = serde_json::from_str(&raw).expect("public-terms JSON");
    LANGS
        .iter()
        .map(|lang| {
            let terms = value[*lang]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            (lang.to_string(), terms)
        })
        .collect()
}

/// Add one case's scores to `tally`.
fn score(case: &Case, terms: &[String], predicted: &[Span], tally: &mut Tally) {
    for &(gold_start, gold_end, gold_tier) in &case.names {
        let counts = match gold_tier {
            Tier::High => &mut tally.high,
            Tier::Low => &mut tally.low,
        };
        counts.names += 1;
        if predicted
            .iter()
            .any(|span| span.start < gold_end && gold_start < span.end)
        {
            counts.touched += 1;
        }
        if predicted
            .iter()
            .any(|span| span.start <= gold_start && gold_end <= span.end)
        {
            counts.masked += 1;
        }
    }
    tally.spans += predicted.len();
    for term in terms {
        for (at, _) in case.text.match_indices(term.as_str()) {
            let stop = at + term.len();
            let masked = predicted
                .iter()
                .any(|span| span.start < stop && at < span.end);
            let gold = case
                .gold
                .iter()
                .any(|&(start, end)| start < stop && at < end);
            if masked && !gold {
                tally.traps += 1;
            }
        }
    }
}

fn pct(part: usize, whole: usize) -> String {
    if whole == 0 {
        "n/a".to_string()
    } else {
        format!("{:.1} %", 100.0 * part as f64 / whole as f64)
    }
}

/// Tallies of one configuration: the total under `"all"`, then per language.
type Rows = Vec<(&'static str, BTreeMap<String, Tally>)>;

fn record(
    rows: &mut Rows,
    name: &'static str,
    lang: &str,
    case: &Case,
    terms: &[String],
    spans: &[Span],
) {
    let index = match rows.iter().position(|(row, _)| *row == name) {
        Some(index) => index,
        None => {
            rows.push((name, BTreeMap::new()));
            rows.len() - 1
        }
    };
    let table = &mut rows[index].1;
    let mut one = Tally::default();
    score(case, terms, spans, &mut one);
    add(table.entry("all".to_string()).or_default(), one);
    add(table.entry(lang.to_string()).or_default(), one);
}

fn add(into: &mut Tally, from: Tally) {
    for (into, from) in [(&mut into.high, from.high), (&mut into.low, from.low)] {
        into.names += from.names;
        into.touched += from.touched;
        into.masked += from.masked;
    }
    into.traps += from.traps;
    into.spans += from.spans;
}

fn registry_with(recognizer: ContactRecognizer) -> Registry {
    Registry::builder()
        .with_all()
        .with_recognizer(recognizer)
        .build()
}

#[cfg(feature = "ner-gliner")]
fn load_gliner() -> GlinerRecognizer {
    let model_dir = std::env::var("AUX_GLINER_MODEL_DIR").expect("AUX_GLINER_MODEL_DIR");
    let mut config = GlinerConfig::new(model_dir).with_threshold(0.4);
    if let Ok(dylib) = std::env::var("AUX_GLINER_ORT_DYLIB") {
        config = config.with_ort_dylib(dylib);
    }
    GlinerRecognizer::load(config).expect("load GLiNER")
}

/// Fake syllables for the synthetic contacts of the timing run.
const SYLLABLES: [&str; 16] = [
    "ka", "ro", "mi", "tan", "vel", "sor", "bik", "dun", "fel", "gar", "hes", "jo", "lin", "mor",
    "nev", "pax",
];

fn synthetic_name(mut value: u64) -> String {
    let mut name = String::new();
    for _ in 0..3 {
        name.push_str(SYLLABLES[(value % 16) as usize]);
        value /= 16;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Time the contact recogniser (and the full registry) on 5,000 synthetic
/// contacts against a 100 KB text.
fn performance(cases: &[Case]) -> Value {
    let mut index = ContactIndex::new();
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for number in 0..5000 {
        let given = synthetic_name(next());
        let family = synthetic_name(next());
        index.add_person(PersonDraft {
            emails: vec![Zeroizing::new(format!(
                "{}.{}{number}@example.invalid",
                given.to_lowercase(),
                family.to_lowercase()
            ))],
            given: vec![Zeroizing::new(given)],
            family: vec![Zeroizing::new(family)],
            ..PersonDraft::default()
        });
    }

    let mut text = String::new();
    'fill: loop {
        for case in cases {
            text.push_str(&case.text);
            text.push_str("\n\n");
            if text.len() >= 100_000 {
                break 'fill;
            }
        }
    }

    let build_start = Instant::now();
    let contacts = index.recognizer().expect("build");
    let build_ms = build_start.elapsed().as_secs_f64() * 1000.0;
    let variants = contacts.pattern_count();
    let registry = registry_with(index.recognizer().expect("build"));

    for _ in 0..3 {
        std::hint::black_box(contacts.analyze(&text));
        std::hint::black_box(registry.analyze(&text));
    }
    let mut contact_ms = Vec::new();
    let mut registry_ms = Vec::new();
    let mut spans = 0;
    for _ in 0..20 {
        let start = Instant::now();
        let found = contacts.analyze(&text);
        contact_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        spans = found.len();
        std::hint::black_box(found);

        let start = Instant::now();
        std::hint::black_box(registry.analyze(&text));
        registry_ms.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    contact_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    registry_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    json!({
        "people": index.len(),
        "variants": variants,
        "text_bytes": text.len(),
        "contact_spans": spans,
        "build_ms": build_ms,
        "contacts_analyze_ms_min": contact_ms[0],
        "contacts_analyze_ms_median": contact_ms[contact_ms.len() / 2],
        "registry_analyze_ms_min": registry_ms[0],
        "registry_analyze_ms_median": registry_ms[registry_ms.len() / 2],
    })
}

fn main() {
    let repo = PathBuf::from(std::env::var("AUX_REPO_ROOT").unwrap_or_else(|_| ".".to_string()));
    let corpus = repo.join("qa/privacy-eval");
    let cases = read_cases(&corpus);
    let terms = read_terms(&corpus);

    let deterministic = Registry::new();
    // The index of every dev mail, as a mail client that has seen all of them.
    let mut shared = ContactIndex::new();
    for case in &cases {
        shared.seed_from_text(&case.text);
    }
    println!(
        "shared index: {} people, {} patterns, {} refused by a seed cap",
        shared.len(),
        shared.pattern_count(),
        shared.refused()
    );
    let shared_registry = registry_with(shared.recognizer().expect("shared index"));
    #[cfg(feature = "ner-gliner")]
    let gliner = load_gliner();

    let mut rows: Rows = Vec::new();
    for case in &cases {
        let lang = case.lang.as_str();
        let terms = terms.get(lang).map(Vec::as_slice).unwrap_or(&[]);
        let det = deterministic.analyze(&case.text);

        let mut per_mail = ContactIndex::new();
        per_mail.seed_from_text(&case.text);
        let per_mail_spans =
            registry_with(per_mail.recognizer().expect("per-mail index")).analyze(&case.text);
        let shared_spans = shared_registry.analyze(&case.text);

        record(&mut rows, "deterministic", lang, case, terms, &det);
        record(
            &mut rows,
            "det + contacts (index of this mail)",
            lang,
            case,
            terms,
            &per_mail_spans,
        );
        record(
            &mut rows,
            "det + contacts (index of all dev mails)",
            lang,
            case,
            terms,
            &shared_spans,
        );

        #[cfg(feature = "ner-gliner")]
        {
            let model = gliner.analyze_report(&case.text).expect("GLiNER").spans;
            let with_model = |base: &[Span]| {
                resolve_overlaps(base.iter().copied().chain(model.iter().copied()).collect())
            };
            record(
                &mut rows,
                "det + GLiNER fp32 @0.4",
                lang,
                case,
                terms,
                &with_model(&det),
            );
            record(
                &mut rows,
                "det + GLiNER + contacts (index of this mail)",
                lang,
                case,
                terms,
                &with_model(&per_mail_spans),
            );
            record(
                &mut rows,
                "det + GLiNER + contacts (index of all dev mails)",
                lang,
                case,
                terms,
                &with_model(&shared_spans),
            );
        }
    }

    println!(
        "dev split A: {} mails, {} gold person names",
        cases.len(),
        cases.iter().map(|case| case.names.len()).sum::<usize>()
    );
    println!("\n| configuration | names | name recall (any span) | mask coverage (fully masked) | trap FP |");
    println!("|---|---:|---:|---:|---:|");
    for (name, table) in &rows {
        let all = table["all"];
        println!(
            "| {name} | {} | {} | {} | {} |",
            all.total().names,
            pct(all.total().touched, all.total().names),
            pct(all.total().masked, all.total().names),
            all.traps
        );
    }
    println!("\nBy tier (HIGH = 2+ tokens, or any name in a header line or signature block; LOW = one token elsewhere):\n");
    println!("| configuration | HIGH names | HIGH recall | HIGH coverage | LOW names | LOW recall | LOW coverage |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for (name, table) in &rows {
        let all = table["all"];
        println!(
            "| {name} | {} | {} | {} | {} | {} | {} |",
            all.high.names,
            pct(all.high.touched, all.high.names),
            pct(all.high.masked, all.high.names),
            all.low.names,
            pct(all.low.touched, all.low.names),
            pct(all.low.masked, all.low.names),
        );
    }
    println!("\nMask coverage per language:\n");
    println!("| configuration | {} |", LANGS.join(" | "));
    println!("|---|{}|", LANGS.map(|_| "---:").join("|"));
    for (name, table) in &rows {
        let cells: Vec<String> = LANGS
            .iter()
            .map(|lang| {
                let tally = table.get(*lang).copied().unwrap_or_default();
                let total = tally.total();
                format!("{} ({})", pct(total.masked, total.names), total.names)
            })
            .collect();
        println!("| {name} | {} |", cells.join(" | "));
    }
    println!("\nName recall (any span) per language:\n");
    println!("| configuration | {} |", LANGS.join(" | "));
    println!("|---|{}|", LANGS.map(|_| "---:").join("|"));
    for (name, table) in &rows {
        let cells: Vec<String> = LANGS
            .iter()
            .map(|lang| {
                let tally = table.get(*lang).copied().unwrap_or_default();
                let total = tally.total();
                pct(total.touched, total.names)
            })
            .collect();
        println!("| {name} | {} |", cells.join(" | "));
    }

    let performance = performance(&cases);
    println!("\nPerformance: {performance}");
}
