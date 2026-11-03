//! EU national and tax identifiers (EU-KERNEL-1a): Germany, Spain, Italy,
//! the Netherlands and Belgium; 1b: Poland, Portugal, Austria, Ireland, Sweden;
//! 1c: Romania, Czechia and Slovakia, Greece and Bulgaria, read over one body.
//!
//! Each rule follows the pattern of the French NIR and the UK National
//! Insurance number: a dedicated recogniser, a check digit that decides, and a
//! span that never carries the value itself. A value whose check digit holds
//! is hidden in Private mode and removed in Open mode, with a label and
//! without one; a value whose check digit fails stays in clear unless a label
//! names it, for a label is evidence and a typo is still personal data. The
//! value may carry spaces, dots, dashes or slashes between its groups, sit
//! glued to a prefix or a suffix, be in lower case, or hold full-width digits.
//! A run of separators that holds a line break is one separator, so a value
//! wrapped after a hyphen or a dot stays one value. A value that stands in
//! prose is not a fragment of an opaque token: the length of a token counts
//! its alphanumerics, never the punctuation of the value.
//! Every rule emits [`EntityKind::NationalId`], the kind the kernel removes in
//! Open mode, so a national identifier never leaves the Mac in any mode.

use crate::normalize::{ascii_digits, numeric_runs, NormalizedText};
use crate::recognizer::Recognizer;
use crate::span::{EntityKind, Span};

/// The kind every rule here emits: a national identifier.
const KIND: EntityKind = EntityKind::NationalId;

/// How far back a label is looked for, in characters.
const CUE_WINDOW: usize = 40;

/// The shortest opaque token a candidate can be part of: a hash, a UUID or a
/// Base64 blob. Masking a part of one would corrupt it.
const OPAQUE_TOKEN_MIN: usize = 20;

/// The length of the Italian codice fiscale, which never hides in a hash.
const IT_LENGTH: usize = 16;

/// The shortest hex digest: an md5. A run of hex digits this long is a digest,
/// and a window of it is not a codice fiscale.
const HEX_DIGEST_MIN: usize = 32;

/// The most digits a wrapped value holds: a sub-chain of break-joined runs is
/// read up to this many digits, so the scan stays linear.
const CHAIN_DIGITS_MAX: usize = 13;

/// The positions of the letters of a codice fiscale: the six of the name, the
/// letter of the month and the letter of the place.
const IT_LETTERS: [usize; 8] = [0, 1, 2, 3, 4, 5, 8, 11];

/// The positions of the digits of a codice fiscale: the year, the day and the
/// three digits of the place.
const IT_DIGITS: [usize; 7] = [6, 7, 9, 10, 12, 13, 14];

/// The position of the control letter of a codice fiscale.
const IT_CONTROL: usize = 15;

/// The score of a value whose check digit holds and a label names it.
const CUED_VALID_SCORE: f32 = 1.0;

/// The score of a value whose check digit holds and no label names it.
const BARE_SCORE: f32 = 0.6;

/// The score of a value a label names whose check digit fails: a typo in a
/// real document is still personal data, so it stays hidden.
const CUED_SCORE: f32 = 0.55;

/// The verdict of a check digit.
type Check = fn(&str) -> bool;

/// Whether a run is printed in the shape a value is issued in.
type Shape = fn(&str) -> bool;

/// The label words of one rule, each a sequence of words (`codice fiscale`).
type Cue = &'static [&'static str];

/// A candidate: its byte range and whether its check digit holds.
struct Candidate {
    start: usize,
    end: usize,
    ok: bool,
}

impl Candidate {
    /// A candidate over `start..end` whose check digit holds or not.
    fn new(start: usize, end: usize, ok: bool) -> Self {
        Self { start, end, ok }
    }
}

/// One country rule: the name, the label words and how candidates are found.
struct Rule(
    &'static str,
    &'static [Cue],
    fn(&Body<'_>) -> Vec<Candidate>,
);

/// The label words of the German Steuer-ID.
static DE_CUES: &[Cue] = &[
    &["steuer", "id"],
    &["steueridentifikationsnummer"],
    &["idnr"],
];
/// The label words of the Spanish DNI and NIE.
static ES_CUES: &[Cue] = &[
    &["dni"],
    &["d", "n", "i"],
    &["nie"],
    &["nif"],
    &["identidad"],
];
/// The label words of the Italian codice fiscale.
static IT_CUES: &[Cue] = &[&["codice", "fiscale"], &["cod", "fisc"], &["cf"]];
/// The label words of the Dutch BSN.
static NL_CUES: &[Cue] = &[
    &["bsn"],
    &["burgerservicenummer"],
    &["citizen", "service", "number"],
];
/// The label words of the Belgian national number.
static BE_CUES: &[Cue] = &[
    &["rijksregisternummer"],
    &["national", "number"],
    &["nationale", "nummer"],
    &["bisnummer"],
];
/// The label words of the Polish PESEL.
static PL_CUES: &[Cue] = &[&["pesel"]];
/// The label words of the Portuguese NIF, and the tax number in English.
static PT_CUES: &[Cue] = &[
    &["nif"],
    &["contribuinte"],
    &["tax", "number"],
    &["taxpayer", "number"],
    &["tax", "identification", "number"],
];
/// The label words of the Austrian social insurance number.
static AT_CUES: &[Cue] = &[
    &["sv", "nr"],
    &["svnr"],
    &["sozialversicherungsnummer"],
    &["versicherungsnummer"],
    &["social", "insurance", "number"],
];
/// The label words of the Irish PPSN.
static IE_CUES: &[Cue] = &[
    &["ppsn"],
    &["pps", "number"],
    &["pps", "no"],
    &["personal", "public", "service", "number"],
];
/// The label words of the Swedish personnummer.
static SE_CUES: &[Cue] = &[
    &["personnummer"],
    &["personnr"],
    &["samordningsnummer"],
    &["personal", "identity", "number"],
];

/// The label words of the Romanian CNP.
static RO_CUES: &[Cue] = &[
    &["cnp"],
    &["c", "n", "p"],
    &["cod", "numeric", "personal"],
    &["personal", "numeric", "code"],
];
/// The label words of the Czech and Slovak rodné číslo.
static CZ_CUES: &[Cue] = &[
    &["rodné", "číslo"],
    &["rodne", "cislo"],
    &["rč"],
    &["r", "č"],
    &["birth", "number"],
];
/// The label words of the Greek AFM, the tax number.
static GR_AFM_CUES: &[Cue] = &[
    &["afm"],
    &["a", "f", "m"],
    &["tax", "identification", "number"],
    &["tax", "number"],
];
/// The label words of the Greek AMKA, the social insurance number.
static GR_AMKA_CUES: &[Cue] = &[
    &["amka"],
    &["a", "m", "k", "a"],
    &["social", "insurance", "number"],
];
/// The label words of the Bulgarian EGN.
static BG_CUES: &[Cue] = &[
    &["egn"],
    &["e", "g", "n"],
    &["unified", "civil", "number"],
    &["civil", "number"],
];

/// Every country rule, in run order.
static RULES: [Rule; 10] = [
    Rule("de_steuer_id", DE_CUES, de_candidates),
    Rule("es_dni", ES_CUES, es_candidates),
    Rule("it_codice_fiscale", IT_CUES, it_candidates),
    Rule("nl_bsn", NL_CUES, nl_candidates),
    Rule("be_national_number", BE_CUES, be_candidates),
    Rule("pl_pesel", PL_CUES, pl_candidates),
    Rule("pt_nif", PT_CUES, pt_candidates),
    Rule("at_sv_nr", AT_CUES, at_candidates),
    Rule("ie_ppsn", IE_CUES, ie_candidates),
    Rule("se_personnummer", SE_CUES, se_candidates),
];

/// The rules of EU-KERNEL-1c: Romania, Czechia and Slovakia, Greece and
/// Bulgaria. One recogniser reads them over one body, so the text is grouped
/// into runs once for the five, not once each.
static RULES_1C: [Rule; 5] = [
    Rule("ro_cnp", RO_CUES, ro_candidates),
    Rule("cz_sk_rodne_cislo", CZ_CUES, cz_candidates),
    Rule("gr_afm", GR_AFM_CUES, gr_afm_candidates),
    Rule("gr_amka", GR_AMKA_CUES, gr_amka_candidates),
    Rule("bg_egn", BG_CUES, bg_candidates),
];

/// Every value of `rules` in `text`, with the score its label and its check
/// digit earn. The rules read one body.
fn spans_for(rules: &[Rule], text: &str) -> Vec<Span> {
    let normalized = NormalizedText::new(text, false);
    let body = Body::new(normalized.text(), text, &normalized);
    let mut spans = Vec::new();
    for rule in rules {
        spans.extend(
            (rule.2)(&body)
                .into_iter()
                .filter(|candidate| !in_opaque_token(body.text, candidate))
                .filter_map(|candidate| {
                    let cued = has_cue(body.text, candidate.start, rule.1);
                    let score = match (candidate.ok, cued) {
                        (true, true) => CUED_VALID_SCORE,
                        (true, false) => BARE_SCORE,
                        (false, true) => CUED_SCORE,
                        (false, false) => return None,
                    };
                    normalized
                        .to_original(candidate.start, candidate.end)
                        .map(|(start, end)| Span::new(KIND, start, end, score, rule.0))
                }),
        );
    }
    spans
}

/// What the rules read: the normalised body of the text, its digit runs, and
/// the original text, to see the line breaks the normaliser folded.
struct Body<'a> {
    /// The normalised text the rules read.
    text: &'a str,
    /// The original text the body came from.
    original: &'a str,
    /// The view that maps the body back to the original.
    view: &'a NormalizedText,
    /// The digit runs of the body, with the runs a line break separates joined
    /// into one run more.
    runs: Vec<(usize, usize)>,
}

impl<'a> Body<'a> {
    /// The body of the text: its digit runs, with the runs a line break
    /// separates joined into one run more.
    fn new(text: &'a str, original: &'a str, view: &'a NormalizedText) -> Self {
        let runs = grouped_runs(text, original, view);
        Self {
            text,
            original,
            view,
            runs,
        }
    }

    /// Whether the run of separators `from..to` of the body holds a line
    /// break: the original bytes of the run hold one.
    ///
    /// The normaliser folds a break to a space, so the body alone cannot tell
    /// a folded break from a space: only the original bytes can.
    fn holds_break(&self, from: usize, to: usize) -> bool {
        let Some((start, end)) = self.view.to_original(from, to) else {
            return false;
        };
        self.original
            .get(start..end)
            .is_some_and(|bytes| bytes.contains(['\n', '\r']))
    }
}

/// The digit runs of the body, with the runs a line break separates joined
/// into one run more.
///
/// A run of separators that holds a line break is one separator, so a value
/// wrapped after a hyphen or a dot stays one value. The joined run is a run
/// more: the runs it joins stay, so no value is ever lost.
fn grouped_runs(body: &str, original: &str, view: &NormalizedText) -> Vec<(usize, usize)> {
    let runs = numeric_runs(body);
    // The end of the chain of every run: the runs a break-holding run of
    // separators joins, and the ones that chain joins in turn. One pass, so
    // the scan stays linear.
    let mut chain_end = vec![0usize; runs.len()];
    for index in (0..runs.len()).rev() {
        chain_end[index] = if index + 1 < runs.len()
            && separated_by_break(body, original, view, runs[index].1, runs[index + 1].0)
        {
            chain_end[index + 1]
        } else {
            index
        };
    }
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(runs.len() * 2);
    for (index, &(start, end)) in runs.iter().enumerate() {
        out.push((start, end));
        // The chain of the run, when the run starts one: the runs a
        // break-holding run of separators joins are one value. One run per
        // chain, so the joined runs stay disjoint and the scan stays linear.
        let last = chain_end[index];
        let starts_chain = index == 0 || chain_end[index - 1] < index;
        if last > index && starts_chain {
            out.push((start, runs[last].1));
        }
        // The shorter chains from the run: a wrapped value followed by more
        // break-joined runs is one value too. Each run adds a digit at least,
        // so a run starts at most [`CHAIN_DIGITS_MAX`] chains.
        let mut digits = ascii_digit_count(&body[start..end]);
        for next in index + 1..=last {
            digits += ascii_digit_count(&body[runs[next].0..runs[next].1]);
            if digits > CHAIN_DIGITS_MAX {
                break;
            }
            // The whole chain is already in.
            if !(starts_chain && next == last) {
                out.push((start, runs[next].1));
            }
        }
    }
    out
}

/// The ASCII digits of `text`.
fn ascii_digit_count(text: &str) -> usize {
    text.bytes().filter(u8::is_ascii_digit).count()
}

/// Whether two runs are separated by a run of separators that holds a line
/// break: the gap holds nothing but separators, and the original bytes of the
/// gap hold a break.
fn separated_by_break(
    body: &str,
    original: &str,
    view: &NormalizedText,
    from: usize,
    to: usize,
) -> bool {
    if from >= to {
        return false;
    }
    let Some(gap) = body.get(from..to) else {
        return false;
    };
    if !gap
        .bytes()
        .all(|byte| matches!(byte, b' ' | b'-' | b'.' | b'/'))
    {
        return false;
    }
    let Some((start, end)) = view.to_original(from, to) else {
        return false;
    };
    original
        .get(start..end)
        .is_some_and(|bytes| bytes.contains(['\n', '\r']))
}

/// Whether the candidate sits in an opaque token: an alphanumeric run of
/// [`OPAQUE_TOKEN_MIN`] characters or more around it.
///
/// Only the alphanumerics count, on every side: the punctuation of a printed
/// number is not part of the token, so a value with separators that stands in
/// prose is not a fragment of a hash.
///
/// The run is read at most [`OPAQUE_TOKEN_MIN`] bytes on each side, so the
/// answer is exact and the scan stays linear.
fn in_opaque_token(text: &str, candidate: &Candidate) -> bool {
    let length = candidate.end - candidate.start;
    if length >= IT_LENGTH {
        return false;
    }
    let bytes = text.as_bytes();
    let left = alnum_run(&mut bytes[..candidate.start].iter().rev().copied());
    let right = alnum_run(&mut bytes[candidate.end..].iter().copied());
    let inner = bytes[candidate.start..candidate.end]
        .iter()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .count();
    left + inner + right >= OPAQUE_TOKEN_MIN
}

/// The alphanumeric bytes the iterator yields, at most [`OPAQUE_TOKEN_MIN`].
fn alnum_run(bytes: &mut impl Iterator<Item = u8>) -> usize {
    bytes
        .by_ref()
        .take(OPAQUE_TOKEN_MIN)
        .take_while(|byte| byte.is_ascii_alphanumeric())
        .count()
}

/// Whether a label stands within [`CUE_WINDOW`] characters before `start`: the
/// words of the window must hold the words of one cue, in order. The window is
/// read as words, so `Steuer-ID` and `steuer id` are one label.
fn has_cue(text: &str, start: usize, cues: &[Cue]) -> bool {
    let from = text[..start]
        .char_indices()
        .rev()
        .nth(CUE_WINDOW)
        .map_or(0, |(at, _)| at);
    let window = text[from..start].to_lowercase();
    let words: Vec<&str> = window
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    cues.iter()
        .any(|cue| cue.len() <= words.len() && words.windows(cue.len()).any(|pair| pair == *cue))
}

/// Every maximal digit run of `text` whose digits number one of `lens`, with
/// the verdict of `check`. The run keeps the separators a printed number may
/// use, so `26 954 371 827` is one run of eleven digits; a `compact` rule
/// reads a grouped run only when a label names it, as the BSN is issued
/// without a separator: its check counts as failed.
fn digit_runs(body: &Body, lens: &[usize], compact: bool, check: Check) -> Vec<Candidate> {
    body.runs
        .iter()
        .filter_map(|&(start, end)| {
            let digits = ascii_digits(&body.text[start..end]);
            let shape = lens.contains(&digits.len());
            let ok = check(&digits) && (!compact || end - start == digits.len());
            shape.then(|| Candidate::new(start, end, ok))
        })
        .collect()
}

/// The German Steuer-ID: eleven digits, ISO 7064 MOD 11,10.
fn de_candidates(body: &Body) -> Vec<Candidate> {
    digit_runs(body, &[11], false, de_steuer_id_ok)
}

/// The Dutch BSN: nine consecutive digits, the eleven-proof. A grouped run of
/// nine digits is a telephone number or a reference unless a label names it.
fn nl_candidates(body: &Body) -> Vec<Candidate> {
    digit_runs(body, &[9], true, nl_bsn_ok)
}

/// The Belgian national number: eleven digits (`YY MM DD XXX CC`) or twelve
/// with the century in front, as a birth after 2000 is written.
fn be_candidates(body: &Body) -> Vec<Candidate> {
    digit_runs(body, &[11, 12], false, be_national_ok)
}

/// Every digit run whose digits number one of `lens`, the check holding only
/// when the run is printed in the `bare` shape the value is issued in: another
/// grouping is a telephone number or a reference unless a label names it.
fn shaped_runs(body: &Body, lens: &[usize], bare: Shape, check: Check) -> Vec<Candidate> {
    body.runs
        .iter()
        .filter_map(|&(start, end)| {
            let raw = &body.text[start..end];
            let digits = ascii_digits(raw);
            let ok = check(&digits) && bare(raw);
            lens.contains(&digits.len())
                .then(|| Candidate::new(start, end, ok))
        })
        .collect()
}

/// Whether a run is printed without a separator.
fn compact(raw: &str) -> bool {
    raw.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether a run holds no break and its groups have the lengths `groups`.
fn grouped(raw: &str, groups: &[usize]) -> bool {
    let lengths: Vec<usize> = raw.split([' ', '-', '.', '/']).map(str::len).collect();
    lengths == groups
}

/// The Polish PESEL: eleven digits, issued without a separator.
fn pl_candidates(body: &Body) -> Vec<Candidate> {
    shaped_runs(body, &[11], compact, pl_pesel_ok)
}

/// The Portuguese NIF: nine digits, mod 11. Nine digits with a mod-11 check
/// match one number in eleven, so the rule reads a NIF only after a label.
fn pt_candidates(body: &Body) -> Vec<Candidate> {
    shaped_runs(body, &[9], |_| false, pt_nif_ok)
}

/// The Austrian SV-Nr: ten digits, `NNNC DDMMYY`, printed whole or in these
/// two groups.
fn at_candidates(body: &Body) -> Vec<Candidate> {
    shaped_runs(
        body,
        &[10],
        |raw| compact(raw) || grouped(raw, &[4, 6]),
        at_sv_ok,
    )
}

/// The Swedish personnummer: `YYMMDD-NNNC` or `YYYYMMDD-NNNC`, Luhn over the
/// last ten digits; a `+` stands for a person past a hundred.
fn se_candidates(body: &Body) -> Vec<Candidate> {
    let bare = |raw: &str| compact(raw) || grouped(raw, &[6, 4]) || grouped(raw, &[8, 4]);
    let mut found = shaped_runs(body, &[10, 12], bare, se_personnummer_ok);
    let bytes = body.text.as_bytes();
    for &(start, end) in &body.runs {
        let after = end + 5;
        let plus = end - start == 6 || end - start == 8;
        if !plus
            || bytes.get(end) != Some(&b'+')
            || !body.text.get(end + 1..after).is_some_and(compact)
            || bytes.get(after).is_some_and(u8::is_ascii_digit)
            || !compact(&body.text[start..end])
        {
            continue;
        }
        let digits = ascii_digits(&body.text[start..after]);
        found.push(Candidate::new(start, after, se_personnummer_ok(&digits)));
    }
    found
}

/// Every digit run whose digits number one of `lens`, read as
/// [`shaped_runs`] reads it, but the shape drops a run of separators that
/// holds a line break: a value issued whole and wrapped at the end of a line
/// is still whole.
fn wrapped_runs(body: &Body, lens: &[usize], bare: Shape, check: Check) -> Vec<Candidate> {
    body.runs
        .iter()
        .filter_map(|&(start, end)| {
            let digits = ascii_digits(&body.text[start..end]);
            lens.contains(&digits.len()).then(|| {
                let ok = check(&digits) && bare(&unwrapped(body, start, end));
                Candidate::new(start, end, ok)
            })
        })
        .collect()
}

/// The run `start..end` of the body without its runs of separators that hold
/// a line break. A run of the body is ASCII: digits and separators.
fn unwrapped(body: &Body, start: usize, end: usize) -> String {
    let bytes = body.text.as_bytes();
    let mut out = String::with_capacity(end - start);
    let mut at = start;
    while at < end {
        let gap = (at..end)
            .find(|&next| bytes[next].is_ascii_digit())
            .unwrap_or(end);
        if gap == at {
            out.push(char::from(bytes[at]));
            at += 1;
            continue;
        }
        if !body.holds_break(at, gap) {
            out.push_str(&body.text[at..gap]);
        }
        at = gap;
    }
    out
}

/// The Romanian CNP: thirteen digits, issued without a separator.
fn ro_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[13], compact, ro_cnp_ok)
}

/// The Czech and Slovak rodné číslo: `YYMMDD/SSSC`, whole or with the slash.
/// The nine digits of a birth before 1954 carry no check: a label names them.
fn cz_candidates(body: &Body) -> Vec<Candidate> {
    let bare = |raw: &str| compact(raw) || grouped(raw, &[6, 4]);
    wrapped_runs(body, &[9, 10], bare, cz_rodne_cislo_ok)
}

/// The Greek AFM: nine digits, mod 11. Nine digits with a mod-11 check match
/// one number in ten, so the rule reads an AFM only after a label.
fn gr_afm_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[9], |_| false, |_| false)
}

/// The Greek AMKA: eleven digits, `DDMMYY`, a serial and the Luhn check,
/// issued without a separator.
fn gr_amka_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[11], compact, gr_amka_ok)
}

/// The Bulgarian EGN: ten digits, issued without a separator.
fn bg_candidates(body: &Body) -> Vec<Candidate> {
    wrapped_runs(body, &[10], compact, bg_egn_ok)
}

/// The Irish PPSN: seven digits, the mod-23 check letter and an optional
/// second letter, which counts in the check.
fn ie_candidates(body: &Body) -> Vec<Candidate> {
    let bytes = body.text.as_bytes();
    let mut found = Vec::new();
    for &(start, end) in &body.runs {
        if end - start != 7 || !compact(&body.text[start..end]) {
            continue;
        }
        // The check letter stands after one separator, or after a loose gap:
        // up to two spaces, a slash, a dot or a dash, and up to two spaces.
        let (at, loose) = match letter_after(body, end) {
            Some(at) => (at, false),
            None => match ie_loose_letter(bytes, end) {
                Some(at) => (at, true),
                None => continue,
            },
        };
        let digits = &body.text[start..end];
        let check = bytes[at].to_ascii_uppercase();
        // Two letters when the check holds over the second, or when two
        // letters stand alone and neither reading holds; else one.
        let second = bytes.get(at + 1).copied().filter(u8::is_ascii_alphabetic);
        let single = ie_letter(digits, None) == check;
        let pair_alone = !bytes.get(at + 2).is_some_and(u8::is_ascii_alphabetic);
        let (stop, ok) = match second {
            Some(second) if ie_letter(digits, Some(second)) == check => (at + 2, true),
            Some(_) if !single && pair_alone => (at + 2, false),
            _ => (at + 1, single),
        };
        // Letters glued to more letters are a word, unless the check holds,
        // a hyphen, a dot or nothing stands before them, and nothing is glued
        // before the digits: a token glued on both sides is a machine line,
        // unless a label names it.
        let glued = bytes.get(stop).is_some_and(u8::is_ascii_alphabetic);
        let prefixed = start > 0
            && bytes[start - 1].is_ascii_alphanumeric()
            && !has_cue(body.text, start, IE_CUES);
        if glued && (!ok || prefixed || loose || at > end && spaced_only(bytes, end, at)) {
            continue;
        }
        found.push(Candidate::new(start, stop, ok));
    }
    found
}

/// The place of the PPSN letter after a loose gap from `end`: up to two
/// spaces or tabs, at most one slash, dot or dash, and up to two spaces or tabs.
fn ie_loose_letter(bytes: &[u8], end: usize) -> Option<usize> {
    let spaces = |from: usize| {
        let count = bytes[from.min(bytes.len())..]
            .iter()
            .take(3)
            .take_while(|byte| matches!(byte, b' ' | b'\t'))
            .count();
        (count <= 2).then_some(from + count)
    };
    let mut at = spaces(end)?;
    if bytes
        .get(at)
        .is_some_and(|byte| matches!(byte, b'/' | b'.' | b'-'))
    {
        at = spaces(at + 1)?;
    }
    (at > end && bytes.get(at).is_some_and(u8::is_ascii_alphabetic)).then_some(at)
}

/// The Irish check letter: the digits weighted 8 to 2, the second letter
/// weighted 9 (`W` counting 0), modulo 23; 0 is `W`.
fn ie_letter(digits: &str, second: Option<u8>) -> u8 {
    let mut sum: u32 = digits
        .bytes()
        .zip((2..=8).rev())
        .map(|(byte, weight)| u32::from(byte - b'0') * weight)
        .sum();
    if let Some(letter) = second.map(|byte| byte.to_ascii_uppercase()) {
        sum += 9 * if letter == b'W' {
            0
        } else {
            u32::from(letter - b'A' + 1)
        };
    }
    match sum % 23 {
        0 => b'W',
        rest => b'A' + rest as u8 - 1,
    }
}

/// The Spanish DNI (eight digits and a letter) and NIE (X, Y or Z, seven
/// digits and a letter), the letter being the mod-23 check.
///
/// The letter may stand after a separator: a hyphen, a space, a dot or a
/// single line break, the normaliser folding a break to a space. A run of
/// separators that holds a line break is one separator, so the letter may
/// stand after the whole run. The NIE keeps its letter before the digits, one
/// separator away.
fn es_candidates(body: &Body) -> Vec<Candidate> {
    let bytes = body.text.as_bytes();
    let mut found = Vec::new();
    for &(start, end) in &body.runs {
        let digits = ascii_digits(&body.text[start..end]);
        // The letter of a DNI or a NIE stands after the digits, or after one
        // separator.
        let Some((letter_at, glued)) = es_letter_at(body, end) else {
            continue;
        };
        let letter = bytes[letter_at].to_ascii_uppercase();
        // A DNI: eight digits and the letter. A NIE: the letter X, Y or Z
        // stands before the seven digits and stands for 0, 1 or 2.
        let (from, number) = match digits.len() {
            8 => (start, digits.parse::<u32>().unwrap_or(u32::MAX)),
            7 => {
                let Some(prefix_at) = es_nie_at(body, start) else {
                    continue;
                };
                let head = u32::from(bytes[prefix_at].to_ascii_uppercase() - b'X') * 10_000_000;
                (prefix_at, head + digits.parse::<u32>().unwrap_or(0))
            }
            _ => continue,
        };
        let ok = ES_LETTERS[(number % 23) as usize] == letter;
        if glued && !ok {
            continue;
        }
        found.push(Candidate::new(from, letter_at + 1, ok));
    }
    found
}

/// Whether the byte separates two parts of a printed identifier: a hyphen, a
/// space or a dot. A line break is a space here: the normaliser folds a
/// single break to one.
fn es_separator(byte: u8) -> bool {
    matches!(byte, b' ' | b'-' | b'.')
}

/// The end of the run of separators that starts at `at`: the separators a
/// printed identifier may use, one after the other.
fn es_separator_run_end(bytes: &[u8], at: usize) -> usize {
    let mut end = at;
    while end < bytes.len() && es_separator(bytes[end]) {
        end += 1;
    }
    end
}

/// The start of the run of separators that ends at `at`: the separators a
/// printed identifier may use, one after the other.
fn es_separator_run_start(bytes: &[u8], at: usize) -> usize {
    let mut start = at;
    while start > 0 && es_separator(bytes[start - 1]) {
        start -= 1;
    }
    start
}

/// The place of the control letter of a DNI or a NIE: right after the digits,
/// or after one separator.
///
/// A letter that stands alone is a control letter; a letter that starts the
/// next word is not, for the digits of a date are followed by a word. A run of
/// separators that holds a line break is one separator, so the letter may
/// stand after the whole run. A letter glued to a suffix after a hyphen or a
/// dot comes back `glued`: it is the control letter only when the check holds.
fn es_letter_at(body: &Body, end: usize) -> Option<(usize, bool)> {
    let bytes = body.text.as_bytes();
    let at = letter_after(body, end)?;
    if at == end {
        return Some((end, false));
    }
    let alone = !bytes
        .get(at + 1)
        .is_some_and(|after| after.is_ascii_alphabetic());
    if alone {
        return Some((at, false));
    }
    // A letter glued to a suffix after a hyphen or a dot may be the control
    // letter of a value glued to prose; after spaces alone it starts a word.
    (!spaced_only(bytes, end, at)).then_some((at, true))
}

/// Whether the separators `from..to` are spaces only: no hyphen and no dot.
fn spaced_only(bytes: &[u8], from: usize, to: usize) -> bool {
    !bytes[from..to]
        .iter()
        .any(|&byte| matches!(byte, b'-' | b'.'))
}

/// The place of the letter after the digits that end at `end`: right after
/// them, or after one separator; a run of separators that holds a line break
/// is one separator.
fn letter_after(body: &Body, end: usize) -> Option<usize> {
    let bytes = body.text.as_bytes();
    let byte = *bytes.get(end)?;
    if byte.is_ascii_alphabetic() {
        return Some(end);
    }
    if !es_separator(byte) {
        return None;
    }
    let run_end = es_separator_run_end(bytes, end);
    let at = if run_end > end + 1 {
        // The run holds more than one separator: it is one separator only when
        // it holds a line break.
        if !body.holds_break(end, run_end) {
            return None;
        }
        run_end
    } else {
        end + 1
    };
    bytes.get(at)?.is_ascii_alphabetic().then_some(at)
}

/// The place of the letter X, Y or Z of a NIE: right before the digits, or
/// before one separator. A run of separators that holds a line break is one
/// separator, so the letter may stand before the whole run.
fn es_nie_at(body: &Body, start: usize) -> Option<usize> {
    let bytes = body.text.as_bytes();
    let at = start.checked_sub(1)?;
    if matches!(bytes[at].to_ascii_uppercase(), b'X' | b'Y' | b'Z') {
        return Some(at);
    }
    if !es_separator(bytes[at]) {
        return None;
    }
    // The run of separators that ends at the digits: the letter stands before
    // it. A run of more than one separator is one separator only when it
    // holds a line break.
    let run_start = es_separator_run_start(bytes, at);
    if at > run_start && !body.holds_break(run_start, at + 1) {
        return None;
    }
    let before = run_start.checked_sub(1)?;
    matches!(bytes[before].to_ascii_uppercase(), b'X' | b'Y' | b'Z').then_some(before)
}

/// The Italian codice fiscale: sixteen characters — six letters, two digits, a
/// letter for the month, two digits, a letter for the place, three digits and
/// the control letter. A digit replaced by a letter of the omocodia keeps the
/// shape.
fn it_candidates(body: &Body) -> Vec<Candidate> {
    let bytes = body.text.as_bytes();
    let mut found = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphanumeric() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_alphanumeric() {
            index += 1;
        }
        // Every sixteen-character window of the run: a value glued to a prefix
        // or a suffix is one value too. A hex digest is not a codice fiscale:
        // masking a window of it corrupts the digest.
        if index - start < IT_LENGTH || is_hex_digest(&bytes[start..index]) {
            continue;
        }
        for at in start..=index - IT_LENGTH {
            if let Some(ok) = it_cf_check(&bytes[at..at + IT_LENGTH]) {
                found.push(Candidate::new(at, at + IT_LENGTH, ok));
            }
        }
    }
    found
}

/// Whether an alphanumeric run is a hex digest: [`HEX_DIGEST_MIN`] hex digits
/// or more, and nothing else.
fn is_hex_digest(run: &[u8]) -> bool {
    run.len() >= HEX_DIGEST_MIN && run.iter().all(u8::is_ascii_hexdigit)
}

/// The German Steuer-ID: eleven digits, the last one the ISO 7064 check.
fn de_steuer_id_ok(digits: &str) -> bool {
    if digits.len() != 11 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut product = 10u32;
    for byte in digits.as_bytes()[..10].iter() {
        let mut sum = (u32::from(byte - b'0') + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (2 * sum) % 11;
    }
    let expected = if 11 - product == 10 { 0 } else { 11 - product };
    expected == u32::from(digits.as_bytes()[10] - b'0')
}

/// The Dutch BSN: nine digits whose weighted sum is a multiple of eleven.
fn nl_bsn_ok(digits: &str) -> bool {
    if digits.len() != 9 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    const WEIGHTS: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i32 = digits
        .bytes()
        .zip(WEIGHTS)
        .map(|(byte, weight)| i32::from(byte - b'0') * weight)
        .sum();
    sum % 11 == 0
}

/// The Belgian national number: the control number is `97 - (prefix mod 97)`,
/// the date must hold, and the century may stand in front.
///
/// A birth after 2000 is written with the century in front, and its check is
/// computed on the number with that century in front. Either check may hold.
fn be_national_ok(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    let (prefix, control) = match bytes.len() {
        11 => (&digits[0..9], &digits[9..11]),
        12 if matches!(bytes[0], b'1' | b'2') => (&digits[1..10], &digits[10..12]),
        _ => return false,
    };
    // The date must hold: a month of the year and a day of that month.
    let month = prefix[2..4].parse::<u32>().unwrap_or(0);
    let day = prefix[4..6].parse::<u32>().unwrap_or(0);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    let Ok(number) = prefix.parse::<u64>() else {
        return false;
    };
    let Ok(got) = control.parse::<u64>() else {
        return false;
    };
    // The check of a birth after 2000 is computed on the number with the
    // century in front: a `2` and the nine digits.
    let with_century = number + 2 * 1_000_000_000;
    got == 97 - (number % 97) || got == 97 - (with_century % 97)
}

/// The digits of `digits` as numbers, when every byte is an ASCII digit.
fn digit_values(digits: &str, len: usize) -> Option<Vec<u32>> {
    (digits.len() == len && compact(digits))
        .then(|| digits.bytes().map(|byte| u32::from(byte - b'0')).collect())
}

/// The sum of the digits times their weights.
fn weighted(digits: &[u32], weights: &[u32]) -> u32 {
    digits
        .iter()
        .zip(weights)
        .map(|(digit, weight)| digit * weight)
        .sum()
}

/// Whether `DD MM` read from two digit pairs is a day of a month: the day may
/// carry `offset` (a Swedish coordination number adds 60).
fn day_month_ok(day: u32, month: u32, offset: u32) -> bool {
    (1..=12).contains(&month)
        && ((1..=31).contains(&day) || (offset > 0 && (1 + offset..=31 + offset).contains(&day)))
}

/// The Polish PESEL: `YYMMDD`, the month carrying the century (+80, +0, +20,
/// +40, +60), a serial, and the check over the weights 1 3 7 9.
fn pl_pesel_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 11) else {
        return false;
    };
    let sum = weighted(&d, &[1, 3, 7, 9, 1, 3, 7, 9, 1, 3]);
    let month = (d[2] * 10 + d[3]) % 20;
    let day = d[4] * 10 + d[5];
    day_month_ok(day, month, 0) && (10 - sum % 10) % 10 == d[10]
}

/// The Portuguese NIF: the first digit names the kind, the weights 9 to 2,
/// modulo 11; a remainder under two is a 0.
fn pt_nif_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 9) else {
        return false;
    };
    if d[0] == 0 || d[0] == 4 && d[1] != 5 || d[0] == 7 {
        return false;
    }
    let rest = weighted(&d, &[9, 8, 7, 6, 5, 4, 3, 2]) % 11;
    (if rest < 2 { 0 } else { 11 - rest }) == d[8]
}

/// The Austrian SV-Nr: a serial that never starts with 0, the check digit,
/// and the birth date `DDMMYY`; the weights 3 7 9 5 8 4 2 1 6, modulo 11, a
/// remainder of 10 never issued.
fn at_sv_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 10) else {
        return false;
    };
    let serial_and_date = [d[0], d[1], d[2], d[4], d[5], d[6], d[7], d[8], d[9]];
    let sum = weighted(&serial_and_date, &[3, 7, 9, 5, 8, 4, 2, 1, 6]);
    d[0] != 0 && day_month_ok(d[4] * 10 + d[5], d[6] * 10 + d[7], 0) && sum % 11 == d[3]
}

/// The Swedish personnummer: ten digits, or twelve with the century (`18`,
/// `19` or `20`) in front; the date holds, the day of a coordination number
/// carrying 60, and Luhn holds over the ten digits.
fn se_personnummer_ok(digits: &str) -> bool {
    let ten = match digits.len() {
        10 => digits,
        12 if matches!(&digits[..2], "18" | "19" | "20") => &digits[2..],
        _ => return false,
    };
    let Some(d) = digit_values(ten, 10) else {
        return false;
    };
    let luhn: u32 = d
        .iter()
        .enumerate()
        .map(|(at, &digit)| match (at % 2, digit * 2) {
            (0, doubled) if doubled > 9 => doubled - 9,
            (0, doubled) => doubled,
            _ => digit,
        })
        .sum();
    day_month_ok(d[4] * 10 + d[5], d[2] * 10 + d[3], 60) && luhn.is_multiple_of(10)
}

/// The Romanian CNP: the sex and century digit, `YYMMDD`, the county (01 to
/// 52, or 70), a serial and the check over the weights 2 7 9 1 4 6 3 5 8 2 7
/// 9, modulo 11, a remainder of 10 written 1.
fn ro_cnp_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 13) else {
        return false;
    };
    let rest = weighted(&d, &[2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]) % 11;
    let county = d[7] * 10 + d[8];
    d[0] != 0
        && day_month_ok(d[5] * 10 + d[6], d[3] * 10 + d[4], 0)
        && ((1..=52).contains(&county) || county == 70)
        && (if rest == 10 { 1 } else { rest }) == d[12]
}

/// The Czech and Slovak rodné číslo of ten digits: `YYMMDD`, the month of a
/// woman carrying 50 and, from 2004, either month 20 more; the number is a
/// multiple of eleven, or its first nine digits leave 10 and it ends with 0.
/// The nine digits of a birth before 1954 carry no check.
fn cz_rodne_cislo_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 10) else {
        return false;
    };
    let Ok(number) = digits.parse::<u64>() else {
        return false;
    };
    let month = (d[2] * 10 + d[3]) % 50;
    let month = if month > 20 { month - 20 } else { month };
    day_month_ok(d[4] * 10 + d[5], month, 0)
        && (number % 11 == 0 || (number / 10) % 11 == 10 && d[9] == 0)
}

/// The Greek AMKA: `DDMMYY`, a serial, and Luhn over the eleven digits.
fn gr_amka_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 11) else {
        return false;
    };
    day_month_ok(d[0] * 10 + d[1], d[2] * 10 + d[3], 0) && luhn(&d)
}

/// The Bulgarian EGN: `YYMMDD`, the month carrying 20 for the 1800s and 40
/// for the 2000s, a serial and the check over the weights 2 4 8 5 10 9 7 3 6,
/// modulo 11, a remainder of 10 written 0.
fn bg_egn_ok(digits: &str) -> bool {
    let Some(d) = digit_values(digits, 10) else {
        return false;
    };
    let month = d[2] * 10 + d[3];
    let month = if month > 40 { month - 40 } else { month % 20 };
    let rest = weighted(&d, &[2, 4, 8, 5, 10, 9, 7, 3, 6]) % 11;
    day_month_ok(d[4] * 10 + d[5], month, 0) && rest % 10 == d[9]
}

/// Whether Luhn holds: from the right, every second digit doubled.
fn luhn(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(at, &digit)| match (at % 2, digit * 2) {
            (1, doubled) if doubled > 9 => doubled - 9,
            (1, doubled) => doubled,
            _ => digit,
        })
        .sum();
    sum.is_multiple_of(10)
}

/// The letters a Spanish DNI or NIE number ends with.
const ES_LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";

/// The values of the odd positions of a codice fiscale, as letters.
const IT_ODD: &str = "BAFHJNPRTVBAFHJNPRTVCESULDGIMOQKWZYX";

/// The values of the even positions: a digit and a letter stand for themselves.
const IT_EVEN: &str = "ABCDEFGHIJABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// The letters of the omocodia: a digit of a codice fiscale replaced by its
/// letter, `0` to `9` in this order.
const IT_OMOCODIA: &[u8; 10] = b"LMNPQRSTUV";

/// The Italian control letter: the odd and even tables over the first fifteen
/// characters, modulo 26. The remainder stands for the letter `A` to `Z`: the
/// control letter is a letter, never a digit. `written` reads a letter of the
/// omocodia as the letter it is, as the official rule does; otherwise it
/// stands for the digit it replaced.
fn it_check_char(code: &[u8], written: bool) -> u8 {
    let mut sum = 0u32;
    for (index, &byte) in code.iter().enumerate() {
        let table = if index % 2 == 0 { IT_ODD } else { IT_EVEN };
        sum += (table.as_bytes()[it_table_index(index, byte, written)] - b'A') as u32;
    }
    b'A' + (sum % 26) as u8
}

/// The place of a character of a codice fiscale in the table of its position:
/// a digit stands for itself, a letter for its place in the alphabet plus
/// ten, and a letter of the omocodia for the digit it replaced unless it is
/// read as `written`.
fn it_table_index(at: usize, byte: u8, written: bool) -> usize {
    let byte = byte.to_ascii_uppercase();
    if byte.is_ascii_digit() {
        return usize::from(byte - b'0');
    }
    match it_omocodia(byte) {
        // A digit of the omocodia stands for the digit it replaced.
        Some(digit) if !written && IT_DIGITS.contains(&at) => digit,
        _ => (usize::from(byte.saturating_sub(b'A')) + 10).min(35),
    }
}

/// The digit a letter of the omocodia stands for.
fn it_omocodia(byte: u8) -> Option<usize> {
    let byte = byte.to_ascii_uppercase();
    IT_OMOCODIA.iter().position(|&letter| letter == byte)
}

/// The shape of an Italian codice fiscale and the verdict of its control
/// letter. `None` when the sixteen characters are not shaped like one.
///
/// The shape is six letters, two digits, the letter of the month, two digits,
/// the letter of the place, three digits and the control letter. A digit
/// replaced by a letter of the omocodia keeps the shape, and the control
/// letter is computed over the letters as written, the official rule; the
/// reading over the digit it replaced holds too.
fn it_cf_check(code: &[u8]) -> Option<bool> {
    if code.len() != IT_LENGTH {
        return None;
    }
    let upper = |at: usize| code[at].to_ascii_uppercase();
    if !IT_LETTERS.iter().all(|&at| upper(at).is_ascii_alphabetic()) {
        return None;
    }
    if !IT_DIGITS
        .iter()
        .all(|&at| upper(at).is_ascii_digit() || it_omocodia(upper(at)).is_some())
    {
        return None;
    }
    if !upper(IT_CONTROL).is_ascii_alphabetic() {
        return None;
    }
    let head = &code[..IT_CONTROL];
    let control = upper(IT_CONTROL);
    Some(control == it_check_char(head, true) || control == it_check_char(head, false))
}

/// Build one country recogniser: the same plumbing for every rule.
macro_rules! eu_recognizer {
    ($name:ident, $rule:expr) => {
        /// The recogniser of one EU identifier.
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;
        impl $name {
            /// Build the recognise.
            pub fn new() -> Self {
                Self
            }
        }
        impl Recognizer for $name {
            fn kinds(&self) -> &[EntityKind] {
                &[KIND]
            }
            fn analyze(&self, text: &str) -> Vec<Span> {
                spans_for(std::slice::from_ref($rule), text)
            }
            fn name(&self) -> &'static str {
                $rule.0
            }
        }
    };
}

eu_recognizer!(DeSteuerIdRecognizer, &RULES[0]);
eu_recognizer!(EsDniRecognizer, &RULES[1]);
eu_recognizer!(ItCodiceFiscaleRecognizer, &RULES[2]);
eu_recognizer!(NlBsnRecognizer, &RULES[3]);
eu_recognizer!(BeNationalNumberRecognizer, &RULES[4]);
eu_recognizer!(PlPeselRecognizer, &RULES[5]);
eu_recognizer!(PtNifRecognizer, &RULES[6]);
eu_recognizer!(AtSvNrRecognizer, &RULES[7]);
eu_recognizer!(IePpsnRecognizer, &RULES[8]);
eu_recognizer!(SePersonnummerRecognizer, &RULES[9]);

/// The recogniser of EU-KERNEL-1c: the Romanian CNP, the Czech and Slovak
/// rodné číslo, the Greek AFM and AMKA and the Bulgarian EGN, read over one
/// body. Every span names the rule that read it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Eu1cRecognizer;

impl Eu1cRecognizer {
    /// Build the recogniser.
    pub fn new() -> Self {
        Self
    }
}

impl Recognizer for Eu1cRecognizer {
    fn kinds(&self) -> &[EntityKind] {
        &[KIND]
    }
    fn analyze(&self, text: &str) -> Vec<Span> {
        spans_for(&RULES_1C, text)
    }
    fn name(&self) -> &'static str {
        "eu_ids_1c"
    }
}
