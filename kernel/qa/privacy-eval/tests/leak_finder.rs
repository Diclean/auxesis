//! LEAK-FINDER-1: invented values of every always-hidden class, in short
//! carriers, changed by one mutator or a pair, go through `Gate::for_grant` in
//! Private and Open. A LEAK is a run of the seed's letters and digits (6, or
//! all when shorter) clear in the output and not already in the carrier: in
//! Private for every class, in Open for the prohibited ones. Refusals in
//! Private, panics and calls over 50 ms are recorded too. The whole case set
//! is planned from the seed and `cases` before any gate call, so `cells` is the
//! same on every machine; `max_secs` is only a safety abort, and it marks the
//! report `truncated` with the cells it did not run. The ignored `nightly`
//! test reads `leak-finder.conf` (+ an uncommitted `leak-finder.override`) and
//! prints the report; `scripts/leak-finder.sh` runs it on the Linux build host, and falls
//! back to this Mac when the build host is unreachable.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use kernel_core::privacy::{admit, Context, Decision, Destination, Grant, PathId, PrivacyMode};
use kernel_privacy::Gate;
use serde_json::{json, Value};

/// One invented value: class, label used by the carriers, value, prohibited in
/// Open, grouped (its spaces are separators the `sep-*` mutators swap), and
/// needs a cue (only carriers with the label before the value: nothing else
/// says a bare `Tr0ub4dor&3x` or `00482913` is a password or a record number).
struct Seed(&'static str, &'static str, &'static str, bool, bool, bool);

#[rustfmt::skip]
const SEEDS: &[Seed] = &[
    Seed("email", "Email", "mira.fictive@example-mail.org", false, false, false),
    Seed("phone", "Phone", "+33 6 12 34 56 78", false, true, false),
    Seed("phone", "Phone", "+44 7700 900123", false, true, false),
    Seed("phone", "Phone", "06 12 34 56 78", false, true, false),
    Seed("phone", "Phone", "07700 900123", false, true, false),
    Seed("phone", "Phone", "(415) 555 0132", false, true, false),
    Seed("phone", "Phone", "06 30 123 4567", false, true, false),
    Seed("phone", "Phone", "031 234 567", false, true, false),
    Seed("phone", "Phone", "082 123 4567", false, true, false),
    Seed("phone", "Phone", "138 0013 8000", false, true, false),
    Seed("address", "Address", "42 Willow Crescent, Leeds LS6 2QT", false, false, false),
    Seed("address", "Adresse", "12 rue des Lilas, 69003 Lyon", false, false, false),
    Seed("address", "Cím", "Kossuth Lajos utca 12, 1055 Budapest", false, false, false),
    Seed("address", "Naslov", "Prešernova cesta 10, 1000 Ljubljana", false, false, false),
    Seed("iban", "IBAN", "FR76 3000 6000 0112 3456 7890 189", true, true, false),
    Seed("card", "Card", "4539 1488 0343 6467", true, true, false),
    Seed("fr-nir", "NIR", "1 84 12 76 451 089 46", true, true, false),
    Seed("uk-ni", "NI number", "PN 48 15 16 C", true, true, false),
    Seed("us-ssn", "SSN", "512 45 8873", true, true, true),
    Seed("passport", "Passport no", "L898902C3", true, false, true),
    Seed("mrz", "MRZ", "L898902C36UTO7408122F1204159ZE184226B<<<<<10", true, false, false),
    Seed("aws-key", "AWS key", "AKIAIOSFODNN7EXAMPLE", true, false, false),
    Seed("api-key", "api_key", "3f9a1c7e5b2d8f40a6c4e2b9d1f7a3c5", true, false, true),  // gitleaks:allow
    Seed("password", "Password", "Tr0ub4dor&3x", true, false, true),
    Seed("passphrase", "Passphrase", "violet tractor humming seventy", true, true, true),
    Seed("health", "Diagnosis", "diabetes", true, false, false),
    Seed("health", "Traitement", "chimiothérapie", true, false, false),
    Seed("mrn", "MRN", "00482913", true, false, true),
    Seed("blood-type", "Blood type", "AB negative", true, false, true),
    Seed("cookie", "Cookie", "sessionid=7f3a9c2e4b1d8f60a5c3e9b2", true, false, false),
];

/// Carriers: `{l}` is the label, `{k}` its key form, `{v}` the value.
#[rustfmt::skip]
const TEMPLATES: &[&str] = &[
    "Here it is: {v} thanks", "{l}: {v}", "| {l} | {v} |", "{\"{k}\": \"{v}\"}",
    "He wrote \"{v}\" on the form", "(see {v})", "https://portal.example.net/find?q={v}&lang=en",
    "- {l}: {v}\n- next item", "My {l} is {v}.", "The {l} was {v}.", "The {l} might be {v}",
    "{l} set to {v}", "Best regards,\nMira\n{l}: {v}", "[10:42] client: {l} {v}",
    "id,{k},city\n17,{v},Lyon", "{l} = {v}", "{k}={v}", "<td>{v}</td>", "Please use {v} for this",
    "{v}", "Note to self — {l} {v} — do not share", "> {l}: {v}", "`{v}`", "Re: your {l} ({v})",
    "{l}\n{v}", "Updated {l} -> {v}", "Le {l} est {v}.", "* **{l}**: {v}", "{l}:{v}",
    "Can you check {v}? It is my {l}.",
];

/// The separators the `sep-*` mutators put between the groups of a value.
#[rustfmt::skip]
const SEPS: &[(&str, &str)] = &[
    ("sep-space", " "), ("sep-double", "  "), ("sep-dash", "-"), ("sep-dot", "."),
    ("sep-slash", "/"), ("sep-tab", "\t"), ("sep-nbsp", "\u{a0}"), ("sep-figure", "\u{2007}"),
    ("sep-zw", "\u{200b}"),
];

#[rustfmt::skip]
const OTHERS: &[&str] = &[
    "lf", "crlf", "upper", "lower", "fullwidth", "homoglyph", "entities", "quote-straight",
    "quote-curly", "md-label", "trailing-punct", "glue-pre", "glue-suf", "spelled",
];

/// Cyrillic and Greek look-alikes of Latin letters.
#[rustfmt::skip]
const HOMOGLYPHS: &[(char, char)] = &[
    ('a', 'а'), ('e', 'е'), ('o', 'о'), ('p', 'р'), ('c', 'с'), ('x', 'х'), ('y', 'у'),
    ('A', 'А'), ('B', 'В'), ('E', 'Е'), ('K', 'К'), ('M', 'М'), ('H', 'Н'), ('O', 'О'),
    ('P', 'Р'), ('C', 'С'), ('T', 'Т'), ('X', 'Х'), ('i', 'ι'), ('N', 'Ν'), ('Z', 'Ζ'),
];

const SLOW_MS: f64 = 50.0;

/// One generated text, in three parts so a mutator can edit the value alone.
struct Case {
    pre: String,
    v: String,
    post: String,
}

fn build(seed: &Seed, template: &str) -> Case {
    let key = seed.1.to_lowercase().replace(' ', "_");
    let t = template.replace("{l}", seed.1).replace("{k}", &key);
    let (pre, post) = t.split_once("{v}").unwrap_or((&t, ""));
    let (pre, v, post) = (pre.into(), seed.2.into(), post.into());
    Case { pre, v, post }
}

fn map_chars(s: &str, f: impl Fn(usize, char) -> String) -> String {
    s.chars().enumerate().map(|(i, ch)| f(i, ch)).collect()
}

fn fullwidth(_: usize, ch: char) -> String {
    let wide = ch
        .is_ascii_alphanumeric()
        .then(|| char::from_u32(ch as u32 + 0xFEE0));
    wide.flatten().unwrap_or(ch).to_string()
}

fn homoglyph(_: usize, ch: char) -> String {
    HOMOGLYPHS
        .iter()
        .find(|h| h.0 == ch)
        .map_or(ch, |h| h.1)
        .to_string()
}

fn entity(i: usize, ch: char) -> String {
    match ch {
        _ if !ch.is_alphanumeric() => format!("&#{};", ch as u32),
        _ if i % 3 == 2 => format!("&#x{:x};", ch as u32),
        _ => ch.to_string(),
    }
}

/// Applies mutator `m`; `false` when it does not apply to this seed or carrier.
fn mutate(m: &str, seed: &Seed, c: &mut Case) -> bool {
    let middle_space = c.v.match_indices(' ').map(|(i, _)| i).collect::<Vec<_>>();
    let middle_space = middle_space.get(middle_space.len() / 2).copied();
    let new_v = match m {
        _ if m.starts_with("sep-") => SEPS
            .iter()
            .find(|s| s.0 == m)
            .and_then(|s| seed.4.then(|| c.v.replace(' ', s.1))),
        "lf" | "crlf" => middle_space.map(|i| {
            let nl = if m == "lf" { "\n" } else { "\r\n" };
            format!("{}{nl}{}", &c.v[..i], &c.v[i + 1..])
        }),
        "upper" | "lower" => {
            for part in [&mut c.pre, &mut c.v, &mut c.post] {
                *part = if m == "upper" {
                    part.to_uppercase()
                } else {
                    part.to_lowercase()
                };
            }
            return true;
        }
        "fullwidth" => Some(map_chars(&c.v, fullwidth)),
        "homoglyph" => Some(map_chars(&c.v, homoglyph)).filter(|v| *v != c.v),
        "entities" => Some(map_chars(&c.v, entity)),
        "quote-straight" => Some(format!("\"{}\"", c.v)),
        "quote-curly" => Some(format!("“{}”", c.v)),
        "md-label" => {
            let bold = format!("**{}**", seed.1);
            let part = [&mut c.pre, &mut c.post]
                .into_iter()
                .find(|p| p.contains(seed.1) && !p.contains(&bold));
            return part.map(|p| *p = p.replacen(seed.1, &bold, 1)).is_some();
        }
        "trailing-punct" => Some(format!("{}).", c.v)),
        "glue-pre" => {
            c.pre = format!("{}ref", c.pre.trim_end());
            return true;
        }
        "glue-suf" => Some(format!("{}ok", c.v)),
        "spelled" => (seed.0 == "email").then(|| c.v.replace('@', " at ").replace('.', " dot ")),
        _ => None,
    };
    new_v.map(|v| c.v = v).is_some()
}

/// Lowercase ASCII letters and digits, after undoing what the mutators do to
/// characters: HTML entities, full-width forms and look-alikes.
fn skeleton(s: &str) -> String {
    let mut decoded = String::new();
    for (i, part) in s.split("&#").enumerate() {
        let entity = part
            .split_once(';')
            .filter(|_| i > 0)
            .and_then(|(n, rest)| {
                let code = match n.strip_prefix('x') {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => n.parse().ok(),
                };
                Some((char::from_u32(code?)?, rest))
            });
        match entity {
            Some((ch, rest)) => write!(decoded, "{ch}{rest}"),
            None if i > 0 => write!(decoded, "&#{part}"),
            None => write!(decoded, "{part}"),
        }
        .unwrap_or_default();
    }
    let latin = |ch: char| match ch as u32 {
        0xFF01..=0xFF5E => char::from_u32(ch as u32 - 0xFEE0).unwrap_or(ch),
        _ => HOMOGLYPHS.iter().find(|h| h.1 == ch).map_or(ch, |h| h.0),
    };
    let ascii = decoded
        .chars()
        .map(latin)
        .filter(char::is_ascii_alphanumeric);
    ascii.map(|ch| ch.to_ascii_lowercase()).collect()
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

/// Whether a run of the seed survives in `out` that the carrier did not hold.
fn leaks(seed: &str, carrier: &str, out: &str) -> bool {
    let (seed, carrier, out) = (skeleton(seed), skeleton(carrier), skeleton(&clear_of(out)));
    let k = seed.len().min(6);
    let fresh = |w: &str| out.contains(w) && !carrier.contains(w);
    k > 0 && (0..=seed.len() - k).any(|i| fresh(&seed[i..i + k]))
}

/// SplitMix64: small, seeded and the same on every platform.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        ((z ^ (z >> 31)) % n as u64) as usize
    }
}

/// Run settings and the allowlist: `(class, mutators, reason)`, `*` = any.
#[derive(Default)]
struct Config {
    set: BTreeMap<String, String>,
    allow: Vec<(String, Vec<String>, String)>,
}

impl Config {
    /// `leak-finder.conf`, then `extra` (`<key> <value>` and `allow` lines).
    fn load(extra: &str) -> Self {
        let conf = include_str!("../leak-finder.conf");
        let mut cfg = Config::default();
        let lines = conf.lines().chain(extra.lines()).map(str::trim);
        for line in lines.filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let mut words = line.splitn(4, ' ');
            let (key, a) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
            if key == "allow" {
                let ms = words
                    .next()
                    .unwrap_or("*")
                    .split(',')
                    .map(String::from)
                    .collect();
                cfg.allow
                    .push((a.into(), ms, words.next().unwrap_or("").into()));
            } else {
                cfg.set.insert(key.into(), a.into());
            }
        }
        cfg
    }

    fn n(&self, key: &str) -> u64 {
        self.set.get(key).and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    /// The reason a cell is allowed, or `None` when it is not. A pair (`a+b`)
    /// is allowed only when the pair itself is listed, or when EVERY half has
    /// a rule of that class: one allowed half would hide the leaks the other
    /// half causes (`card sep-dot+upper` is not covered by a `card sep-dot`
    /// rule), so an allowlist of single mutators says nothing about pairs.
    fn allowed(&self, class: &str, mutator: &str) -> Option<&str> {
        let hit = |p: &str, v: &str| p == "*" || p == v;
        let rule = |m: &str| {
            self.allow
                .iter()
                .find(|r| hit(&r.0, class) && r.1.iter().any(|p| hit(p, m)))
        };
        if let Some(r) = rule(mutator) {
            return Some(r.2.as_str());
        }
        let halves: Vec<&str> = mutator.split('+').collect();
        if halves.iter().all(|half| rule(half).is_some()) {
            // A pair of allowed halves: the reason of the first of them.
            return rule(halves[0]).map(|r| r.2.as_str());
        }
        None
    }
}

#[derive(Default)]
struct Cell {
    cases: u64,
    counts: BTreeMap<&'static str, u64>,
    /// The 5 shortest failing inputs: (length, kind, input, output).
    repros: Vec<(usize, &'static str, String, String)>,
}

fn grant(mode: PrivacyMode) -> Grant {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".into()),
    };
    match admit(PathId::A1, mode, &ctx) {
        Decision::Allow(grant) => grant,
        other => panic!("A1 {mode:?} is not allowed: {other:?}"),
    }
}

/// One gate call: `Ok(Some(text))`, `Ok(None)` on a refusal, `Err` on a panic.
fn gate(grant: &Grant, text: &str) -> (Result<Option<String>, ()>, f64) {
    let start = Instant::now();
    let out = catch_unwind(AssertUnwindSafe(|| {
        let out = Gate::for_grant(grant, [7u8; 32]).text(text).ok();
        out.map(|(safe, _)| safe.as_str().to_string())
    }));
    (out.map_err(drop), start.elapsed().as_secs_f64() * 1000.0)
}

/// Draws the next case: seed, its mutated text, carrier and mutator name.
fn draw(rng: &mut Rng) -> Option<(&'static Seed, Case, String)> {
    let seed = &SEEDS[rng.below(SEEDS.len())];
    let template = TEMPLATES[rng.below(TEMPLATES.len())];
    let pre = template.split_once("{v}").map_or("", |(pre, _)| pre);
    if seed.5 && !pre.contains("{l}") && !pre.contains("{k}") {
        return None;
    }
    let all: Vec<&str> = SEPS.iter().map(|s| s.0).chain(OTHERS.to_vec()).collect();
    // 40 % of the cases are unmutated or one mutator, the rest a pair.
    let names = match rng.below(10) {
        0 => vec![],
        1..=3 => vec![all[rng.below(all.len())]],
        _ => {
            let (a, b) = (rng.below(all.len()), rng.below(all.len()));
            (a != b).then(|| vec![all[a.min(b)], all[a.max(b)]])?
        }
    };
    let mut case = build(seed, template);
    names
        .iter()
        .all(|m| mutate(m, seed, &mut case))
        .then_some(())?;
    Some((
        seed,
        case,
        if names.is_empty() {
            "none".into()
        } else {
            names.join("+")
        },
    ))
}

/// The whole case set, decided before any gate call: the RNG state that
/// draws each case, in order. Planning costs no gate time, so the cells and
/// the case count are the same on every machine; `max_secs` can then only cut
/// the run short, never decide which cases were going to be made.
fn plan_cases(cfg: &Config) -> Vec<u64> {
    let mut rng = Rng(cfg.n("seed"));
    let mut states = Vec::new();
    while states.len() < cfg.n("cases") as usize {
        let state = rng.0;
        if draw(&mut rng).is_some() {
            states.push(state);
        }
    }
    states
}

/// Runs the probe and returns the JSON report.
fn run(cfg: &Config) -> Value {
    let (private, open) = (grant(PrivacyMode::Private), grant(PrivacyMode::Open));
    let plan = plan_cases(cfg);
    let started = Instant::now();
    let mut cells: BTreeMap<(&str, String), Cell> = BTreeMap::new();
    let mut slow: BTreeMap<String, u64> = BTreeMap::new();
    let mut run = 0;
    while run < plan.len() {
        if started.elapsed().as_secs() >= cfg.n("max_secs") {
            break;
        }
        // Replaying the recorded state redraws the case the plan chose.
        let Some((seed, case, mutator)) = draw(&mut Rng(plan[run])) else {
            break;
        };
        run += 1;
        let text = format!("{}{}{}", case.pre, case.v, case.post);
        let carrier = format!("{} {}", case.pre, case.post);
        let cell = cells.entry((seed.0, mutator.clone())).or_default();
        cell.cases += 1;
        for (mode, g, checked) in [("private", &private, true), ("open", &open, seed.3)] {
            let (out, ms) = gate(g, &text);
            if ms > SLOW_MS {
                *slow.entry(format!("{} {mutator}", seed.0)).or_default() += 1;
            }
            let private = mode == "private";
            let (kind, output) = match out {
                Err(()) if private => ("panic_private", String::new()),
                Err(()) => ("panic_open", String::new()),
                Ok(None) if private => ("refusal_private", String::new()),
                Ok(Some(o)) if checked && leaks(seed.2, &carrier, &o) => {
                    (if private { "leak_private" } else { "leak_open" }, o)
                }
                _ => continue,
            };
            *cell.counts.entry(kind).or_default() += 1;
            cell.repros
                .push((text.chars().count(), kind, text.clone(), output));
            cell.repros.sort_by_key(|r| r.0);
            cell.repros.truncate(5);
        }
    }
    // What the clock cut off: the plan says it, so a truncated run is never
    // silently a smaller one. Empty on a run that finished.
    let mut missed: BTreeMap<(&'static str, String), u64> = BTreeMap::new();
    for state in &plan[run..] {
        if let Some((seed, _, mutator)) = draw(&mut Rng(*state)) {
            *missed.entry((seed.0, mutator)).or_default() += 1;
        }
    }
    let mut totals: BTreeMap<&str, u64> = BTreeMap::new();
    let mut out = Vec::new();
    for ((class, mutator), cell) in &cells {
        let allowed = cfg.allowed(class, mutator);
        for (kind, n) in cell.counts.iter().filter(|_| allowed.is_none()) {
            *totals.entry(kind).or_default() += n;
        }
        let repros: Vec<Value> = cell
            .repros
            .iter()
            .map(|r| json!({"kind": r.1, "input": r.2, "output": r.3}))
            .collect();
        let failures: u64 = cell.counts.values().sum();
        out.push(
            json!({"class": class, "mutator": mutator, "cases": cell.cases,
            "counts": cell.counts, "failures": failures, "allowed": allowed, "repros": repros}),
        );
    }
    let secs = (started.elapsed().as_secs_f64() * 10.0).round() / 10.0;
    let not_run: Vec<Value> = missed
        .iter()
        .map(
            |((class, mutator), cases)| json!({"class": class, "mutator": mutator, "cases": cases}),
        )
        .collect();
    json!({"work_order": "LEAK-FINDER-1", "date": cfg.set.get("date"), "rev": cfg.set.get("rev"),
        "seed": cfg.n("seed"), "cases_requested": cfg.n("cases"), "cases_planned": plan.len(),
        "cases_run": run, "truncated": run < plan.len(),
        "cells_not_run": not_run,
        "totals_not_allowed": totals, "cells": out,
        "timing": {"elapsed_secs": secs, "slow_over_ms": SLOW_MS, "slow": slow}})
}

/// A short markdown summary: failing cells outside the allowlist, one repro
/// each, ranked by score: failures for an unmutated cell, failures beyond the
/// class's unmutated rate for a mutated one (what the mutator itself breaks).
fn summary(report: &Value, top: usize) -> String {
    let cells = report["cells"].as_array().cloned().unwrap_or_default();
    let num = |c: &Value, k: &str| c[k].as_u64().unwrap_or(0) as f64;
    let rate = |c: &Value| num(c, "failures") / num(c, "cases").max(1.0);
    let none = |c: &Value| c["mutator"] == "none";
    let base: BTreeMap<String, f64> = cells
        .iter()
        .filter(|c| none(c))
        .map(|c| (c["class"].to_string(), rate(c)))
        .collect();
    let score = |c: &Value| match none(c) {
        true => num(c, "failures"),
        false => {
            num(c, "failures") - num(c, "cases") * base.get(&c["class"].to_string()).unwrap_or(&0.0)
        }
    };
    let mut rows: Vec<(f64, &Value)> = cells.iter().map(|c| (score(c), c)).collect();
    rows.retain(|r| r.0 >= 1.0 && r.1["allowed"].is_null());
    rows.sort_by(|a, b| b.0.total_cmp(&a.0));
    let allowed = cells
        .iter()
        .filter(|c| !c["allowed"].is_null() && rate(c) > 0.0)
        .count();
    let cut = match report["truncated"].as_bool() {
        Some(true) => format!(
            " **TRUNCATED at `max_secs`: {} cells not run.**",
            report["cells_not_run"].as_array().map_or(0, Vec::len),
        ),
        _ => String::new(),
    };
    let mut md = format!(
        "# Leak finder {} (rev {})\n\nCases run: {} of {} planned (seed {}), {} s.{cut} \
         Failures outside the allowlist: {}. {} failing cells ({allowed} allowlisted cells \
         not shown).\n\n\
         | class | mutator | cases | score | counts | shortest repro |\n|---|---|---|---|---|---|\n",
        report["date"].as_str().unwrap_or(""), report["rev"].as_str().unwrap_or(""),
        report["cases_run"], report["cases_planned"], report["seed"], report["timing"]["elapsed_secs"],
        report["totals_not_allowed"], rows.len(),
    );
    for (score, c) in rows.iter().take(top) {
        let input = c["repros"][0]["input"]
            .as_str()
            .unwrap_or("")
            .escape_debug()
            .to_string();
        let input: String = input.replace('|', "\\|").chars().take(90).collect();
        let (class, mutator, cases, counts) =
            (&c["class"], &c["mutator"], &c["cases"], &c["counts"]);
        let line = format!("| {class} | {mutator} | {cases} | {score:.0} | {counts} |");
        let _ = writeln!(md, "{} `{input}` |", line.replace('"', ""));
    }
    md
}

#[test]
#[rustfmt::skip]
fn the_oracle_sees_a_clear_value_and_ignores_tokens_and_the_carrier() {
    for (seed, carrier, out, leak) in [
        ("06 12 34 56 78", "Phone: ", "Phone: 06 12 34 56 78", true),
        ("06 12 34 56 78", "Phone: ", "Phone: ０６&#49;2.34.56.78", true),
        ("mira.fictive@example-mail.org", "", "mira dot fictive at example-mail dot org", true),
        ("06 12 34 56 78", "Phone: ", "Phone: ⟦PHONE_1a2b⟧", false),
        ("diabetes", "", "[health removed] now", false),
        ("Tr0ub4dor&3x", "Password Tr0ub4", "Password Tr0ub4 ⟦SECRET_9f⟧", false),
    ] {
        assert_eq!(leaks(seed, carrier, out), leak, "{out}");
    }
}

#[test]
fn the_same_seed_gives_the_same_cells() {
    let cfg = Config::load("cases 150\nmax_secs 3600");
    let (a, b) = (run(&cfg), run(&cfg));
    assert_eq!(a["cases_run"], 150);
    assert_eq!(a["truncated"], json!(false));
    assert_eq!(a["cells_not_run"], json!([]));
    assert_eq!(a["cells"], b["cells"]);
    assert!(summary(&a, 5).contains("| class | mutator |"));
}

/// The cells a report covers, run or not, as `(class, mutator)`.
fn cells_of(report: &Value) -> Vec<String> {
    let key = |c: &Value| format!("{} {}", c["class"], c["mutator"]);
    let mut all = Vec::new();
    for list in ["cells", "cells_not_run"] {
        all.extend(report[list].as_array().into_iter().flatten().map(key));
    }
    all.sort();
    all.dedup();
    all
}

#[test]
fn the_cells_come_from_the_seed_and_the_count_not_from_the_clock() {
    let done = run(&Config::load("cases 150\nmax_secs 3600"));
    assert_eq!(done["cases_run"], done["cases_planned"]);
    assert_eq!(
        cells_of(&done),
        cells_of(&run(&Config::load("cases 150\nmax_secs 3600")))
    );

    // The clock can only cut a run short, and a cut run says so: the cells it
    // missed are the plan, so it is never quietly a smaller report.
    let cut = run(&Config::load("cases 150\nmax_secs 0"));
    assert_eq!(cut["truncated"], json!(true));
    assert_eq!(cut["cases_run"], 0);
    assert_eq!(cells_of(&cut), cells_of(&done));
    assert!(summary(&cut, 5).contains("TRUNCATED"));
}

/// A config whose only allowlist rules are `rules`: `(class, mutators, reason)`.
fn allow_only(rules: &[(&str, &str, &str)]) -> Config {
    Config {
        allow: rules
            .iter()
            .map(|(class, mutators, reason)| {
                (
                    class.to_string(),
                    mutators.split(',').map(String::from).collect(),
                    reason.to_string(),
                )
            })
            .collect(),
        ..Config::default()
    }
}

#[test]
fn the_allowlist_covers_cells_and_pairs() {
    let cfg = Config::load("");
    assert!(cfg.allowed("email", "homoglyph").is_some());
    assert!(cfg.allowed("card", "sep-dot+sep-slash").is_some());
    assert!(cfg.allowed("card", "none").is_none());
    assert!(cfg.allowed("iban", "sep-dot").is_none());
}

#[test]
fn a_pair_is_allowed_only_when_every_half_is() {
    let cfg = allow_only(&[("card", "lookalike", "parked")]);
    assert!(cfg.allowed("card", "lookalike").is_some());
    // Both halves parked: the pair is parked.
    assert!(cfg.allowed("card", "lookalike+lookalike").is_some());
    // One half parked is not a pair: the other half's leaks are not parked.
    assert!(cfg.allowed("card", "sep-dot+double-space").is_none());
    assert!(cfg.allowed("card", "lookalike+sep-dot").is_none());
    // The rule belongs to `card`, not to every class.
    assert!(cfg.allowed("email", "lookalike+lookalike").is_none());
    // A pair listed as a whole is allowed whatever its halves are.
    let whole = allow_only(&[("card", "sep-dot+double-space", "parked as a pair")]);
    assert!(whole.allowed("card", "sep-dot+double-space").is_some());
}

/// The nightly run: `scripts/leak-finder.sh` calls it on the Linux build host, and
/// on this Mac when the build host is unreachable.
#[test]
#[ignore = "nightly leak finder, about 20 minutes in release"]
fn nightly() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/leak-finder.override");
    let extra = std::fs::read_to_string(path).unwrap_or_default();
    let report = run(&Config::load(&extra));
    let json = serde_json::to_string_pretty(&report).unwrap_or_default();
    println!("LEAK-FINDER-JSON-BEGIN\n{json}\nLEAK-FINDER-JSON-END");
    println!(
        "LEAK-FINDER-MD-BEGIN\n{}LEAK-FINDER-MD-END",
        summary(&report, 20)
    );
}
